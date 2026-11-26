//! GraphQL detection, lightweight parsing, and per-operation endpoint keys.

use regex::Regex;
use std::sync::LazyLock;

use crate::types::api::{EndpointKey, HttpMethod};

/// A detected GraphQL operation.
#[derive(Debug, Clone)]
pub struct GraphQLOperation {
    pub operation_type: GraphQLOperationType,
    pub operation_name: Option<String>,
    pub raw_query: String,
    pub depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphQLOperationType {
    Query,
    Mutation,
    Subscription,
}

impl GraphQLOperationType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "QUERY",
            Self::Mutation => "MUTATION",
            Self::Subscription => "SUBSCRIPTION",
        }
    }
}

/// Detect a GraphQL request from URL + POST body.
/// Returns `Some(op)` if the request is a GraphQL operation.
pub fn detect_graphql_request(url: &str, post_data: Option<&str>) -> Option<GraphQLOperation> {
    // Must be a request to a /graphql endpoint.
    if !is_graphql_url(url) {
        return None;
    }

    // Try to extract query from POST body (JSON).
    if let Some(body) = post_data {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(query) = val.get("query").and_then(|q| q.as_str()) {
                return parse_graphql_operation(query);
            }
        }
    }

    // Try to extract query from URL query params (?query=...).
    if let Ok(parsed) = url::Url::parse(url) {
        for (key, value) in parsed.query_pairs() {
            if key == "query" {
                return parse_graphql_operation(&value);
            }
        }
    }

    None
}

/// Generate a per-operation endpoint key instead of a generic `POST /graphql`.
/// Format: `POST /graphql#QUERY users` or `POST /graphql#MUTATION createUser`.
pub fn graphql_endpoint_key(base_path: &str, op: &GraphQLOperation) -> EndpointKey {
    let suffix = match &op.operation_name {
        Some(name) => format!("{}#{} {}", base_path, op.operation_type.as_str(), name),
        None => format!("{}#{}", base_path, op.operation_type.as_str()),
    };
    EndpointKey {
        method: HttpMethod::Post,
        path_template: suffix,
    }
}

/// Write-guard check: may this request carry a GraphQL mutation?
///
/// Unlike [`detect_graphql_request`] this does not require a `/graphql` URL
/// for JSON bodies, handles batched (array) bodies and documents that start
/// with fragments, and is conservative: persisted/opaque operations (no query
/// text) and unreadable bodies on GraphQL-looking URLs count as possible
/// mutations. `body_unavailable` means the browser reported post data but did
/// not expose it.
pub fn request_may_be_mutation(url: &str, body: Option<&str>, body_unavailable: bool) -> bool {
    if let Ok(parsed) = url::Url::parse(url) {
        if parsed
            .query_pairs()
            .any(|(k, v)| k == "query" && document_has_mutation(&v))
        {
            return true;
        }
    }

    let graphql_url = is_graphql_url(url);
    let Some(body) = body.map(str::trim).filter(|b| !b.is_empty()) else {
        return body_unavailable && graphql_url;
    };

    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Array(ops)) => ops.iter().any(operation_may_mutate),
        Ok(v @ serde_json::Value::Object(_)) => operation_may_mutate(&v),
        // `application/graphql` bodies and multipart uploads on GraphQL URLs.
        _ => graphql_url && (document_has_mutation(body) || body.contains("mutation")),
    }
}

/// One JSON GraphQL request object (`{query, operationName, variables, ...}`).
fn operation_may_mutate(op: &serde_json::Value) -> bool {
    let Some(obj) = op.as_object() else {
        return false;
    };
    if let Some(query) = obj.get("query").and_then(|q| q.as_str()) {
        return document_has_mutation(query);
    }
    // Persisted / trusted documents carry only a hash or id: the operation
    // type is unknown, so treat it as a possible mutation.
    let persisted = obj
        .get("extensions")
        .and_then(|e| e.get("persistedQuery"))
        .is_some();
    let named_opaque = obj.contains_key("operationName")
        && ["id", "documentId", "queryId", "extensions"]
            .iter()
            .any(|k| obj.contains_key(*k));
    persisted || named_opaque
}

/// `true` when a GraphQL document defines a `mutation` operation at top level
/// (ignoring strings, comments, selection sets, and variable definitions).
pub fn document_has_mutation(doc: &str) -> bool {
    let bytes = doc.as_bytes();
    let mut i = 0usize;
    let mut braces = 0usize;
    let mut parens = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' => {
                if doc[i..].starts_with("\"\"\"") {
                    i += 3;
                    match doc[i..].find("\"\"\"") {
                        Some(end) => i += end + 2,
                        None => return false,
                    }
                } else {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
            }
            b'{' => braces += 1,
            b'}' => braces = braces.saturating_sub(1),
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            c if c == b'_' || c.is_ascii_alphabetic() => {
                let start = i;
                while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                let prefixed = start > 0 && matches!(bytes[start - 1], b'$' | b'@');
                if braces == 0
                    && parens == 0
                    && !prefixed
                    && &doc[start..i] == "mutation"
                    && doc[i..].contains('{')
                {
                    return true;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Check if a URL path looks like a GraphQL endpoint.
fn is_graphql_url(url: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)/graphql(?:\?|$|/)").unwrap());
    RE.is_match(url)
}

/// Parse a GraphQL query string to extract operation type, name, and depth.
fn parse_graphql_operation(query: &str) -> Option<GraphQLOperation> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (op_type, rest) = if trimmed.starts_with("mutation") {
        (GraphQLOperationType::Mutation, &trimmed["mutation".len()..])
    } else if trimmed.starts_with("subscription") {
        (
            GraphQLOperationType::Subscription,
            &trimmed["subscription".len()..],
        )
    } else if trimmed.starts_with("query") {
        (GraphQLOperationType::Query, &trimmed["query".len()..])
    } else if trimmed.starts_with('{') {
        // Anonymous query (shorthand).
        (GraphQLOperationType::Query, trimmed)
    } else {
        return None;
    };

    let op_name = extract_operation_name(rest);
    let depth = estimate_depth(query);

    Some(GraphQLOperation {
        operation_type: op_type,
        operation_name: op_name,
        raw_query: query.to_string(),
        depth,
    })
}

/// Extract the operation name from the text after the operation keyword.
fn extract_operation_name(rest: &str) -> Option<String> {
    static NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([A-Za-z_]\w*)").unwrap());
    NAME_RE.captures(rest).map(|c| c[1].to_string())
}

/// Estimate nesting depth by counting braces.
fn estimate_depth(query: &str) -> usize {
    let mut max_depth = 0usize;
    let mut current = 0usize;
    for ch in query.chars() {
        match ch {
            '{' => {
                current += 1;
                max_depth = max_depth.max(current);
            }
            '}' => {
                current = current.saturating_sub(1);
            }
            _ => {}
        }
    }
    max_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_post_query() {
        let body = r#"{"query":"query GetUser { user(id: 1) { name email } }"}"#;
        let op = detect_graphql_request("https://example.com/graphql", Some(body));
        assert!(op.is_some());
        let op = op.unwrap();
        assert_eq!(op.operation_type, GraphQLOperationType::Query);
        assert_eq!(op.operation_name.as_deref(), Some("GetUser"));
        assert_eq!(op.depth, 2);
    }

    #[test]
    fn test_detect_mutation() {
        let body = r#"{"query":"mutation CreateUser($input: UserInput!) { createUser(input: $input) { id } }"}"#;
        let op = detect_graphql_request("https://example.com/graphql", Some(body));
        assert!(op.is_some());
        let op = op.unwrap();
        assert_eq!(op.operation_type, GraphQLOperationType::Mutation);
        assert_eq!(op.operation_name.as_deref(), Some("CreateUser"));
    }

    #[test]
    fn test_detect_anonymous_query() {
        let body = r#"{"query":"{ users { id name } }"}"#;
        let op = detect_graphql_request("https://example.com/graphql", Some(body));
        assert!(op.is_some());
        let op = op.unwrap();
        assert_eq!(op.operation_type, GraphQLOperationType::Query);
        assert!(op.operation_name.is_none());
    }

    #[test]
    fn test_not_graphql_url() {
        let body = r#"{"query":"query { users { id } }"}"#;
        let op = detect_graphql_request("https://example.com/api/users", Some(body));
        assert!(op.is_none());
    }

    #[test]
    fn test_endpoint_key_named() {
        let op = GraphQLOperation {
            operation_type: GraphQLOperationType::Query,
            operation_name: Some("GetUser".to_string()),
            raw_query: String::new(),
            depth: 2,
        };
        let key = graphql_endpoint_key("/graphql", &op);
        assert_eq!(key.path_template, "/graphql#QUERY GetUser");
    }

    #[test]
    fn mutation_detection_for_write_guard() {
        let url = "https://example.com/graphql";
        let body = r#"{"query":"mutation RefundOrder { refund(id: 1) { ok } }"}"#;
        assert!(request_may_be_mutation(url, Some(body), false));
        // Fragments first, then the mutation.
        let body = r#"{"query":"fragment F on Order { id } mutation M { refund { ...F } }"}"#;
        assert!(request_may_be_mutation(url, Some(body), false));
        // Batched bodies.
        let body = r#"[{"query":"query A { a }"},{"query":"mutation B { b }"}]"#;
        assert!(request_may_be_mutation(url, Some(body), false));
        // Queries are reads, including ones mentioning "mutation" in strings,
        // comments, fields, or variable names.
        let body = r##"{"query":"# mutation note\nquery Q($mutation: Int) { search(q: \"mutation {\") { mutation } }"}"##;
        assert!(!request_may_be_mutation(url, Some(body), false));
        // JSON bodies are checked regardless of URL.
        let body = r#"{"query":"mutation { addItem(id: 1) { id } }"}"#;
        assert!(request_may_be_mutation(
            "https://example.com/api/gql",
            Some(body),
            false
        ));
        // Search APIs with a "query" field are not GraphQL mutations.
        assert!(!request_may_be_mutation(
            "https://example.com/api/search",
            Some(r#"{"query":"mutation testing"}"#),
            false
        ));
        // Mutation over GET.
        assert!(request_may_be_mutation(
            "https://example.com/graphql?query=mutation%20M%20%7B%20a%20%7D",
            None,
            false
        ));
        // Persisted operations and unreadable bodies are unknown -> guarded.
        let body = r#"{"operationName":"X","extensions":{"persistedQuery":{"version":1,"sha256Hash":"ab"}}}"#;
        assert!(request_may_be_mutation(url, Some(body), false));
        assert!(request_may_be_mutation(url, None, true));
        assert!(!request_may_be_mutation(
            "https://example.com/api/orders",
            None,
            true
        ));
    }

    #[test]
    fn test_depth_estimation() {
        assert_eq!(estimate_depth("{ a { b { c } } }"), 3);
        assert_eq!(estimate_depth("{ a }"), 1);
    }
}
