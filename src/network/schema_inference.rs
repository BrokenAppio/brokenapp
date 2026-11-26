use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::types::api::{JsonSchema, JsonSchemaType};

pub fn infer_schema(samples: &[serde_json::Value]) -> Option<JsonSchema> {
    if samples.is_empty() {
        return None;
    }
    Some(infer_schema_inner(samples))
}

fn infer_schema_inner(samples: &[serde_json::Value]) -> JsonSchema {
    // Nullability is tracked separately.
    let mut nullable = false;
    let non_null: Vec<&serde_json::Value> = samples
        .iter()
        .filter(|v| {
            if v.is_null() {
                nullable = true;
                false
            } else {
                true
            }
        })
        .collect();

    if non_null.is_empty() {
        return JsonSchema {
            schema_type: JsonSchemaType::Null,
            properties: BTreeMap::new(),
            required: Vec::new(),
            items: None,
            format: None,
            nullable: true,
        };
    }

    let schema_type = classify_union(&non_null);
    let mut schema = JsonSchema {
        schema_type,
        properties: BTreeMap::new(),
        required: Vec::new(),
        items: None,
        format: None,
        nullable,
    };

    match schema.schema_type {
        JsonSchemaType::Object => {
            let mut all_keys: BTreeSet<String> = BTreeSet::new();
            let mut required_keys: Option<BTreeSet<String>> = None;

            for v in &non_null {
                if let Some(obj) = v.as_object() {
                    let keys: BTreeSet<String> = obj.keys().cloned().collect();
                    all_keys.extend(keys.iter().cloned());
                    required_keys = Some(match required_keys {
                        None => keys,
                        Some(prev) => prev.intersection(&keys).cloned().collect(),
                    });
                }
            }

            for key in all_keys {
                let mut subs = Vec::new();
                for v in &non_null {
                    if let Some(obj) = v.as_object() {
                        if let Some(val) = obj.get(&key) {
                            subs.push(val.clone());
                        }
                    }
                }
                schema.properties.insert(key, infer_schema_inner(&subs));
            }

            if let Some(req) = required_keys {
                schema.required = req.into_iter().collect();
            }
        }
        JsonSchemaType::Array => {
            let mut items = Vec::new();
            for v in &non_null {
                if let Some(arr) = v.as_array() {
                    items.extend(arr.iter().cloned());
                }
            }
            if !items.is_empty() {
                schema.items = Some(Box::new(infer_schema_inner(&items)));
            }
        }
        JsonSchemaType::String => {
            let fmt = detect_string_format(&non_null);
            schema.format = fmt;
        }
        _ => {}
    }

    schema
}

fn classify_union(non_null: &[&serde_json::Value]) -> JsonSchemaType {
    let mut has_bool = false;
    let mut has_string = false;
    let mut has_number = false;
    let mut has_object = false;
    let mut has_array = false;

    let mut all_integers = true;

    for v in non_null {
        match v {
            serde_json::Value::Bool(_) => has_bool = true,
            serde_json::Value::String(_) => has_string = true,
            serde_json::Value::Number(n) => {
                has_number = true;
                if !(n.is_i64() || n.is_u64()) {
                    all_integers = false;
                }
            }
            serde_json::Value::Array(_) => has_array = true,
            serde_json::Value::Object(_) => has_object = true,
            serde_json::Value::Null => {}
        }
    }

    let kinds = [has_bool, has_string, has_number, has_object, has_array]
        .into_iter()
        .filter(|b| *b)
        .count();

    if kinds == 1 {
        if has_bool {
            JsonSchemaType::Boolean
        } else if has_string {
            JsonSchemaType::String
        } else if has_number {
            if all_integers {
                JsonSchemaType::Integer
            } else {
                JsonSchemaType::Number
            }
        } else if has_object {
            JsonSchemaType::Object
        } else if has_array {
            JsonSchemaType::Array
        } else {
            JsonSchemaType::Mixed
        }
    } else {
        JsonSchemaType::Mixed
    }
}

fn detect_string_format(non_null: &[&serde_json::Value]) -> Option<String> {
    let uuid_re = Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        .expect("uuid regex");
    let email_re = Regex::new(r"(?i)^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$").expect("email regex");
    let datetime_re =
        Regex::new(r"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}").expect("datetime regex");

    let mut all_uuid = true;
    let mut all_email = true;
    let mut all_datetime = true;

    for v in non_null {
        let Some(s) = v.as_str() else { continue };
        if !uuid_re.is_match(s) {
            all_uuid = false;
        }
        if !email_re.is_match(s) {
            all_email = false;
        }
        if !datetime_re.is_match(s) {
            all_datetime = false;
        }
    }

    if all_uuid {
        Some("uuid".to_string())
    } else if all_email {
        Some("email".to_string())
    } else if all_datetime {
        Some("date-time".to_string())
    } else {
        None
    }
}

/// Detected pagination shape in a response schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaginationPattern {
    /// `{ data: [...], has_more, cursor/next_cursor }`
    CursorBased,
    /// `{ items/data/results: [...], offset/page, total/total_pages }`
    OffsetBased,
    /// Top-level array with no pagination metadata (raw list).
    UnpaginatedList,
}

use serde::{Deserialize, Serialize};

static CURSOR_KEYS: &[&str] = &[
    "cursor",
    "next_cursor",
    "next_page_token",
    "starting_after",
    "ending_before",
    "continuation_token",
];

static OFFSET_KEYS: &[&str] = &[
    "offset",
    "page",
    "page_number",
    "current_page",
    "total_pages",
    "total_count",
    "total",
    "per_page",
    "page_size",
    "limit",
];

static ARRAY_KEYS: &[&str] = &[
    "data", "items", "results", "records", "entries", "rows", "list", "edges", "nodes", "content",
];

/// Inspect a response `JsonSchema` for common pagination patterns.
pub fn detect_pagination_pattern(schema: &JsonSchema) -> Option<PaginationPattern> {
    if schema.schema_type == JsonSchemaType::Array {
        return Some(PaginationPattern::UnpaginatedList);
    }
    if schema.schema_type != JsonSchemaType::Object {
        return None;
    }

    let keys: Vec<String> = schema
        .properties
        .keys()
        .map(|k| k.to_ascii_lowercase())
        .collect();

    let has_array_prop = keys.iter().any(|k| ARRAY_KEYS.contains(&k.as_str()))
        || schema
            .properties
            .values()
            .any(|v| v.schema_type == JsonSchemaType::Array);

    if !has_array_prop {
        return None;
    }

    let has_cursor = keys.iter().any(|k| CURSOR_KEYS.contains(&k.as_str()))
        || keys
            .iter()
            .any(|k| k.contains("cursor") || k.contains("next_page_token"));
    if has_cursor {
        return Some(PaginationPattern::CursorBased);
    }

    let has_offset = keys.iter().any(|k| OFFSET_KEYS.contains(&k.as_str()))
        || keys.contains(&"has_more".to_string())
        || keys.contains(&"hasmore".to_string());
    if has_offset {
        return Some(PaginationPattern::OffsetBased);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_pagination_cursor_based() {
        let schema = infer_schema(&[serde_json::json!({
            "data": [{"id": 1}],
            "next_cursor": "abc",
            "has_more": true
        })])
        .unwrap();
        assert_eq!(
            detect_pagination_pattern(&schema),
            Some(PaginationPattern::CursorBased)
        );
    }

    #[test]
    fn detect_pagination_offset_based() {
        let schema = infer_schema(&[serde_json::json!({
            "items": [{"id": 1}],
            "page": 1,
            "total_pages": 5
        })])
        .unwrap();
        assert_eq!(
            detect_pagination_pattern(&schema),
            Some(PaginationPattern::OffsetBased)
        );
    }

    #[test]
    fn detect_pagination_unpaginated_list() {
        let schema = infer_schema(&[serde_json::json!([{"id": 1}])]).unwrap();
        assert_eq!(
            detect_pagination_pattern(&schema),
            Some(PaginationPattern::UnpaginatedList)
        );
    }

    #[test]
    fn detect_pagination_none_for_simple_object() {
        let schema = infer_schema(&[serde_json::json!({"id": 1, "name": "a"})]).unwrap();
        assert_eq!(detect_pagination_pattern(&schema), None);
    }

    #[test]
    fn infer_object_required_fields() {
        let samples = vec![
            serde_json::json!({"id": 1, "name": "a"}),
            serde_json::json!({"id": 2, "name": "b", "opt": true}),
        ];
        let schema = infer_schema(&samples).unwrap();
        assert_eq!(schema.schema_type, JsonSchemaType::Object);
        assert!(schema.required.contains(&"id".to_string()));
        assert!(schema.required.contains(&"name".to_string()));
        assert!(!schema.required.contains(&"opt".to_string()));
    }
}
