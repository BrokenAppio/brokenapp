//! Form validation fuzzing via network replay (no DOM dependency).
//!
//! This pass replays captured same-origin requests (from `network.jsonl`) with
//! mutated payloads in request bodies. It uses the same response classification
//! as the DOM-based fuzzing helpers, but gets real HTTP status codes.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;

use crate::bugs::detector::BugDetector;
use crate::bugs::form_validation::ValidationResult;
use crate::network::path_parameterizer::path_to_template;
use crate::types::api::{EndpointKey, HttpMethod, TrafficEntry};
use crate::types::bugs::BugSeverity;
use crate::types::classifier::FormFieldType;

/// Safety caps to avoid request explosions on large apps.
const MAX_SEEDS: usize = 25;
const MAX_FIELDS_PER_SEED: usize = 12;
const MAX_REQUESTS_TOTAL: usize = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Json,
    FormUrlEncoded,
}

/// Headers that should never be replayed from captured traffic.
const STRIPPED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "x-requested-with",
    "content-length",
    "host",
];

#[derive(Debug, Clone, Default)]
pub struct ReplayFuzzSummary {
    pub seeds_considered: usize,
    pub seeds_fuzzed: usize,
    pub requests_sent: usize,
    pub findings_recorded: usize,
}

pub async fn run_form_fuzz_replay(
    network_log_path: &Path,
    base_url: &Url,
    form_submit_endpoints: &HashSet<EndpointKey>,
    cookie_override: Option<&str>,
    authorization_override: Option<&str>,
    max_payloads_per_field: usize,
    ignore_https_errors: bool,
    bug_detector: &std::sync::Arc<BugDetector>,
) -> Result<ReplayFuzzSummary> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(5));
    if ignore_https_errors {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder.build().context("build reqwest client")?;

    let file = tokio::fs::File::open(network_log_path)
        .await
        .with_context(|| format!("open {}", network_log_path.display()))?;
    let mut reader = BufReader::new(file).lines();

    let mut summary = ReplayFuzzSummary::default();
    let mut seeds_used = 0usize;

    while let Some(line) = reader.next_line().await? {
        if seeds_used >= MAX_SEEDS || summary.requests_sent >= MAX_REQUESTS_TOTAL {
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry: TrafficEntry = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        summary.seeds_considered += 1;

        // Only consider successful same-origin requests with bodies.
        let Some(post_data) = entry.request.post_data.as_deref() else {
            continue;
        };
        if post_data.trim().is_empty() {
            continue;
        }
        if !matches!(
            entry.request.method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
        ) {
            continue;
        }
        let Some(resp) = entry.response.as_ref() else {
            continue;
        };
        if resp.status >= 400 {
            continue;
        }

        let url = match Url::parse(&entry.request.url) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if !same_origin(base_url, &url) {
            continue;
        }

        // If we know the "form submit endpoints" set, only fuzz those.
        let endpoint_key = EndpointKey {
            method: entry.request.method,
            path_template: path_to_template(url.path()),
        };
        if !form_submit_endpoints.is_empty() && !form_submit_endpoints.contains(&endpoint_key) {
            continue;
        }

        // Skip auth/login-ish endpoints; fuzzing here is noisy and can lock accounts.
        if looks_like_auth_path(url.path()) {
            continue;
        }

        // Parse request body as JSON or form-urlencoded.
        let content_type = header_value(&entry.request.headers, "content-type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let body_kind = if is_json_body(&content_type, post_data) {
            BodyKind::Json
        } else if is_form_urlencoded_body(&content_type, post_data) {
            BodyKind::FormUrlEncoded
        } else {
            continue;
        };

        let trace_id = entry.trace.as_ref().map(|t| t.trace_id.clone());
        let view_id = entry.triggered_by.as_ref().map(|t| t.view.clone());

        let fields: Vec<String>;
        let baseline_json: Option<serde_json::Value>;
        let baseline_form: Option<Vec<(String, String)>>;

        if body_kind == BodyKind::Json {
            let v: serde_json::Value = match serde_json::from_str(post_data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(obj) = v.as_object() else {
                continue;
            };

            // If the body includes sensitive fields (except CSRF), skip.
            if obj
                .keys()
                .any(|k| is_sensitive_body_field(k) && !is_csrf_field(k))
            {
                continue;
            }

            fields = obj
                .iter()
                .filter_map(|(k, vv)| {
                    if is_sensitive_body_field(k) {
                        return None;
                    }
                    if vv.is_string() {
                        Some(k.clone())
                    } else {
                        None
                    }
                })
                .take(MAX_FIELDS_PER_SEED)
                .collect();

            let mut baseline = v.clone();
            normalize_json_body(&mut baseline, cookie_override);
            baseline_json = Some(baseline);
            baseline_form = None;
        } else {
            let pairs = url::form_urlencoded::parse(post_data.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect::<Vec<_>>();

            if pairs
                .iter()
                .any(|(k, _)| is_sensitive_body_field(k) && !is_csrf_field(k))
            {
                continue;
            }

            fields = pairs
                .iter()
                .filter_map(|(k, _)| {
                    if is_sensitive_body_field(k) {
                        None
                    } else {
                        Some(k.clone())
                    }
                })
                .take(MAX_FIELDS_PER_SEED)
                .collect();

            let baseline = normalize_form_body(&pairs, cookie_override);
            baseline_form = Some(baseline);
            baseline_json = None;
        }

        if fields.is_empty() {
            continue;
        }

        seeds_used += 1;
        summary.seeds_fuzzed += 1;

        for field in fields {
            if summary.requests_sent >= MAX_REQUESTS_TOTAL {
                break;
            }

            let field_type = guess_field_type(&field);
            let payloads = crate::bugs::form_validation::payloads_for_field_type(
                &field_type,
                max_payloads_per_field,
            );

            for payload in payloads {
                if summary.requests_sent >= MAX_REQUESTS_TOTAL {
                    break;
                }

                let mut headers = build_replay_headers(
                    &entry.request.headers,
                    cookie_override,
                    authorization_override,
                    match body_kind {
                        BodyKind::Json => "application/json",
                        BodyKind::FormUrlEncoded => "application/x-www-form-urlencoded",
                    },
                )?;

                // If the original request used a CSRF header (redacted), try to rehydrate from cookies.
                if needs_csrf_header(&entry.request.headers) {
                    if let Some(token) = csrf_token_from_cookie(cookie_override.unwrap_or("")) {
                        // Use the header name we observed if present.
                        let name =
                            csrf_header_name(&entry.request.headers).unwrap_or("x-csrf-token");
                        if let (Ok(hn), Ok(hv)) = (
                            HeaderName::from_bytes(name.as_bytes()),
                            HeaderValue::from_str(&token),
                        ) {
                            headers.insert(hn, hv);
                        }
                    }
                }

                let body = if let Some(baseline) = baseline_json.as_ref() {
                    let mut v = baseline.clone();
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert(
                            field.clone(),
                            serde_json::Value::String(payload.value.into()),
                        );
                    }
                    serde_json::to_string(&v).unwrap_or_default()
                } else if let Some(pairs) = baseline_form.as_ref() {
                    let s = render_form_with_mutation(pairs, &field, payload.value);
                    s
                } else {
                    continue;
                };

                let method = match entry.request.method {
                    HttpMethod::Post => reqwest::Method::POST,
                    HttpMethod::Put => reqwest::Method::PUT,
                    HttpMethod::Patch => reqwest::Method::PATCH,
                    _ => continue,
                };

                let req = client
                    .request(method, url.as_str())
                    .headers(headers)
                    .body(body.clone());

                summary.requests_sent += 1;
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let status = resp.status().as_u16();
                let body_bytes = resp.bytes().await.unwrap_or_default();
                let body_str = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(10_240)])
                    .to_string();

                let payload_reflected = !payload.value.is_empty()
                    && memchr::memmem::find(&body_bytes, payload.value.as_bytes()).is_some();
                let mut result = crate::bugs::form_validation::classify_response(
                    status,
                    Some(&body_str),
                    payload.value,
                );
                if (200..300).contains(&status) && payload_reflected {
                    result = crate::bugs::form_validation::ValidationResult::Reflected;
                }
                if result == ValidationResult::Rejected {
                    continue;
                }

                let severity =
                    crate::bugs::form_validation::severity_for_result(result, payload.category);
                if severity == BugSeverity::Info {
                    continue;
                }

                summary.findings_recorded += 1;

                bug_detector
                    .record_form_fuzz_finding(
                        payload.value.to_string(),
                        format!("{:?}", payload.category),
                        payload.description.to_string(),
                        format!("{:?}", result),
                        severity,
                        Some(field.clone()),
                        view_id.clone(),
                        Some(url.to_string()),
                        trace_id.clone(),
                    )
                    .await;

                // Avoid hammering the target.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    Ok(summary)
}

fn build_replay_headers(
    captured: &std::collections::BTreeMap<String, String>,
    cookie_override: Option<&str>,
    authorization_override: Option<&str>,
    content_type: &str,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();

    for (k, v) in captured {
        let key_lower = k.trim().to_ascii_lowercase();
        if STRIPPED_HEADERS.iter().any(|s| *s == key_lower) {
            continue;
        }
        if v.contains("<redacted>") {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }

    // Ensure content-type matches our encoding (reqwest won't infer it).
    if let Ok(ct) = HeaderValue::from_str(content_type) {
        headers.insert(reqwest::header::CONTENT_TYPE, ct);
    }

    if let Some(cookie) = cookie_override {
        if let Ok(val) = HeaderValue::from_str(cookie) {
            headers.insert(reqwest::header::COOKIE, val);
        }
    }

    if let Some(auth) = authorization_override {
        if let Ok(val) = HeaderValue::from_str(auth) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }

    Ok(headers)
}

fn header_value<'a>(
    headers: &'a std::collections::BTreeMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.as_str());
        }
    }
    None
}

fn same_origin(a: &Url, b: &Url) -> bool {
    crate::url_origin::same_origin(a, b)
}

fn looks_like_auth_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("login")
        || p.contains("signin")
        || p.contains("sign-in")
        || p.contains("logout")
        || p.contains("mfa")
        || p.contains("otp")
        || p.contains("password")
}

fn is_sensitive_body_field(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "password"
            | "pass"
            | "passwd"
            | "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "secret"
            | "client_secret"
            | "authorization"
            | "cookie"
            | "session"
            | "session_id"
            | "sessionid"
            | "otp"
            | "mfa"
            | "code"
            | "pin"
    )
}

fn is_csrf_field(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "csrf" | "csrf_token" | "xsrf" | "xsrf_token"
    )
}

fn csrf_token_from_cookie(cookie_header: &str) -> Option<String> {
    // Try common cookie names used by popular frameworks.
    let candidates = [
        "XSRF-TOKEN",
        "CSRF-TOKEN",
        "csrftoken",
        "csrf_token",
        "__Host-csrf",
    ];

    for part in cookie_header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=')?;
        for cand in candidates {
            if k.trim().eq_ignore_ascii_case(cand) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn needs_csrf_header(headers: &std::collections::BTreeMap<String, String>) -> bool {
    headers.keys().any(|k| {
        k.eq_ignore_ascii_case("x-csrf-token")
            || k.eq_ignore_ascii_case("x-xsrf-token")
            || k.eq_ignore_ascii_case("x-xcsrf-token")
    })
}

fn csrf_header_name(headers: &std::collections::BTreeMap<String, String>) -> Option<&'static str> {
    for k in headers.keys() {
        if k.eq_ignore_ascii_case("x-xsrf-token") {
            return Some("x-xsrf-token");
        }
        if k.eq_ignore_ascii_case("x-xcsrf-token") {
            return Some("x-xcsrf-token");
        }
        if k.eq_ignore_ascii_case("x-csrf-token") {
            return Some("x-csrf-token");
        }
    }
    None
}

fn synthetic_value_for_key(key: &str) -> String {
    let k = key.to_ascii_lowercase();
    if k.contains("email") {
        "test@example.com".to_string()
    } else if k.contains("phone") || k.contains("tel") {
        "5555555555".to_string()
    } else if k.contains("url") {
        "https://example.com".to_string()
    } else if k.contains("date") {
        "2000-01-01".to_string()
    } else if k.ends_with("id") || k == "id" {
        "1".to_string()
    } else if k.contains("name") {
        "test".to_string()
    } else {
        "test".to_string()
    }
}

fn normalize_json_body(v: &mut serde_json::Value, cookie_override: Option<&str>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, vv) in map.iter_mut() {
                if vv.is_string() && vv.as_str() == Some("<redacted>") {
                    if is_csrf_field(k) {
                        if let Some(t) = csrf_token_from_cookie(cookie_override.unwrap_or("")) {
                            *vv = serde_json::Value::String(t);
                        } else {
                            *vv = serde_json::Value::String(String::new());
                        }
                    } else {
                        *vv = serde_json::Value::String(synthetic_value_for_key(k));
                    }
                } else {
                    normalize_json_body(vv, cookie_override);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for vv in arr {
                normalize_json_body(vv, cookie_override);
            }
        }
        _ => {}
    }
}

fn normalize_form_body(
    pairs: &[(String, String)],
    cookie_override: Option<&str>,
) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| {
            let mut vv = v.clone();
            if vv == "<redacted>" || vv.is_empty() {
                if is_csrf_field(k) {
                    vv = csrf_token_from_cookie(cookie_override.unwrap_or("")).unwrap_or_default();
                } else {
                    vv = synthetic_value_for_key(k);
                }
            }
            (k.clone(), vv)
        })
        .collect()
}

fn render_form_with_mutation(pairs: &[(String, String)], field: &str, payload: &str) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        if k == field {
            ser.append_pair(k, payload);
        } else {
            ser.append_pair(k, v);
        }
    }
    ser.finish()
}

fn guess_field_type(name: &str) -> FormFieldType {
    let n = name.to_ascii_lowercase();
    if n.contains("email") {
        FormFieldType::Email
    } else if n.contains("pass") {
        FormFieldType::Password
    } else if n.contains("phone") || n.contains("tel") {
        FormFieldType::Tel
    } else if n.contains("url") || n.contains("website") {
        FormFieldType::Url
    } else if n.contains("date") {
        FormFieldType::Date
    } else if n.ends_with("id") || n == "id" || n.contains("count") || n.contains("num") {
        FormFieldType::Number
    } else {
        FormFieldType::Text
    }
}

fn is_json_body(content_type: &str, body: &str) -> bool {
    if content_type.contains("application/json") {
        return true;
    }
    let b = body.trim_start();
    b.starts_with('{') || b.starts_with('[')
}

fn is_form_urlencoded_body(content_type: &str, body: &str) -> bool {
    if content_type.contains("application/x-www-form-urlencoded") {
        return true;
    }
    // If a content-type was specified and it wasn't x-www-form-urlencoded, don't guess.
    if !content_type.trim().is_empty() {
        return false;
    }

    // Some environments omit content-type; use a conservative heuristic.
    let b = body.trim();
    if b.is_empty() {
        return false;
    }
    if b.contains('\n') || b.contains("\r\n") {
        return false;
    }
    if b.contains("----") {
        // Avoid multipart boundary false positives.
        return false;
    }
    b.contains('=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_values_cover_common_fields() {
        assert_eq!(synthetic_value_for_key("email"), "test@example.com");
        assert_eq!(synthetic_value_for_key("user_id"), "1");
        assert_eq!(synthetic_value_for_key("name"), "test");
    }

    #[test]
    fn csrf_cookie_extraction() {
        let c = "a=1; XSRF-TOKEN=abc123; b=2";
        assert_eq!(csrf_token_from_cookie(c).as_deref(), Some("abc123"));
    }

    #[test]
    fn render_form_mutates_one_field() {
        let pairs = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        let out = render_form_with_mutation(&pairs, "b", "PAYLOAD");
        assert!(out.contains("a=1"));
        assert!(out.contains("b=PAYLOAD"));
    }

    #[test]
    fn form_urlencoded_body_rejects_multipart() {
        let ct = "multipart/form-data; boundary=----abc";
        let body = "a=1";
        assert!(!is_form_urlencoded_body(ct, body));
    }

    #[test]
    fn replay_same_origin_allows_localhost_aliases() {
        let base = Url::parse("http://localhost:4102").unwrap();
        let loopback = Url::parse("http://127.0.0.1:4102/api/signup").unwrap();
        let ipv6 = Url::parse("http://[::1]:4102/api/signup").unwrap();

        assert!(same_origin(&base, &loopback));
        assert!(same_origin(&base, &ipv6));
    }

    #[test]
    fn replay_same_origin_stays_strict_for_non_local_changes() {
        let base = Url::parse("http://localhost:4102").unwrap();
        let different_port = Url::parse("http://127.0.0.1:4103/api/signup").unwrap();
        let external = Url::parse("http://example.com:4102/api/signup").unwrap();

        assert!(!same_origin(&base, &different_port));
        assert!(!same_origin(&base, &external));
    }
}
