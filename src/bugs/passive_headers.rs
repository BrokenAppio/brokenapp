use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use url::Url;

use crate::network::filters::looks_like_static_asset_path;
use crate::types::api::{HttpMethod, TrafficEntry};
use crate::types::bugs::{Bug, BugCategory, BugEvidence, BugLocation, BugSeverity};

struct PassiveHeaderRule {
    header: &'static str,
    title: &'static str,
    description: &'static str,
    remediation: &'static str,
    severity: BugSeverity,
    cwe: Option<&'static str>,
    owasp: Option<&'static str>,
    https_only: bool,
    allow_csp_frame_ancestors: bool,
    required_value: Option<&'static str>,
}

const PASSIVE_HEADER_RULES: &[PassiveHeaderRule] = &[
    PassiveHeaderRule {
        header: "content-security-policy",
        title: "Missing Content-Security-Policy header",
        description: "HTML responses are missing a Content-Security-Policy header.",
        remediation: "Add a Content-Security-Policy header with a least-privilege script, style, image, connect, object, and frame policy for this application.",
        severity: BugSeverity::Medium,
        cwe: Some("CWE-693"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        https_only: false,
        allow_csp_frame_ancestors: false,
        required_value: None,
    },
    PassiveHeaderRule {
        header: "x-frame-options",
        title: "Missing X-Frame-Options header",
        description: "HTML responses are missing clickjacking protection.",
        remediation: "Add X-Frame-Options: DENY or SAMEORIGIN, or enforce frame-ancestors in Content-Security-Policy.",
        severity: BugSeverity::Medium,
        cwe: Some("CWE-1021"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        https_only: false,
        allow_csp_frame_ancestors: true,
        required_value: None,
    },
    PassiveHeaderRule {
        header: "x-content-type-options",
        title: "Missing X-Content-Type-Options header",
        description: "HTML responses do not explicitly disable MIME sniffing.",
        remediation: "Add X-Content-Type-Options: nosniff to application responses.",
        severity: BugSeverity::Low,
        cwe: Some("CWE-16"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        https_only: false,
        allow_csp_frame_ancestors: false,
        required_value: Some("nosniff"),
    },
    PassiveHeaderRule {
        header: "referrer-policy",
        title: "Missing Referrer-Policy header",
        description: "HTML responses do not define a referrer policy.",
        remediation: "Add a Referrer-Policy header such as strict-origin-when-cross-origin or no-referrer.",
        severity: BugSeverity::Low,
        cwe: Some("CWE-200"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        https_only: false,
        allow_csp_frame_ancestors: false,
        required_value: None,
    },
    PassiveHeaderRule {
        header: "permissions-policy",
        title: "Missing Permissions-Policy header",
        description: "HTML responses do not restrict browser feature permissions.",
        remediation: "Add a Permissions-Policy header that disables unused sensitive browser features.",
        severity: BugSeverity::Low,
        cwe: Some("CWE-693"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        https_only: false,
        allow_csp_frame_ancestors: false,
        required_value: None,
    },
    PassiveHeaderRule {
        header: "strict-transport-security",
        title: "Missing Strict-Transport-Security header",
        description: "HTTPS HTML responses do not enforce HSTS.",
        remediation: "Add Strict-Transport-Security with an appropriate max-age after validating HTTPS is enforced across the domain.",
        severity: BugSeverity::Low,
        cwe: Some("CWE-319"),
        owasp: Some("A02:2021 Cryptographic Failures"),
        https_only: true,
        allow_csp_frame_ancestors: false,
        required_value: None,
    },
];

pub fn evaluate_passive_header_findings(
    entries: &[TrafficEntry],
    base_url: Option<&Url>,
) -> Vec<Bug> {
    let mut findings = Vec::new();
    let mut seen: HashSet<(String, &'static str)> = HashSet::new();
    let mut next_id = 1usize;

    for entry in entries {
        if !is_html_document_response(entry, base_url) {
            continue;
        }
        let Ok(url) = Url::parse(&entry.request.url) else {
            continue;
        };
        let Some(resp) = entry.response.as_ref() else {
            continue;
        };
        let origin = origin_key(&url);

        for rule in PASSIVE_HEADER_RULES {
            if rule.https_only && url.scheme() != "https" {
                continue;
            }
            if rule.header == "strict-transport-security" && is_loopback_or_localhost(&url) {
                continue;
            }
            if rule.allow_csp_frame_ancestors && has_csp_frame_ancestors(&resp.headers) {
                continue;
            }
            if header_satisfies(&resp.headers, rule.header, rule.required_value) {
                continue;
            }
            if !seen.insert((origin.clone(), rule.header)) {
                continue;
            }

            let is_local = is_loopback_or_localhost(&url);
            let severity = if is_local {
                BugSeverity::Info
            } else {
                rule.severity
            };
            let confidence = if is_local { Some(0.35) } else { Some(0.82) };
            let description = if is_local {
                format!(
                    "{} First observed on {} (local/dev server; verify headers against staging or production).",
                    rule.description, entry.request.url
                )
            } else {
                format!(
                    "{} First observed on {}.",
                    rule.description, entry.request.url
                )
            };

            let header_label = match rule.required_value {
                Some(value) => format!("{}: {}", canonical_header_name(rule.header), value),
                None => canonical_header_name(rule.header).to_string(),
            };
            findings.push(Bug {
                id: format!("PASSIVE-{next_id:04}"),
                severity,
                confidence,
                category: BugCategory::SecurityObservation {
                    description: format!("Missing or invalid response header {header_label}"),
                },
                title: rule.title.to_string(),
                description,
                remediation: Some(rule.remediation.to_string()),
                location: BugLocation {
                    view: None,
                    element: None,
                    url: Some(entry.request.url.clone()),
                },
                reproduction: vec![
                    format!("Request {}", entry.request.url),
                    format!("Inspect the response headers for {header_label}"),
                ],
                evidence: BugEvidence {
                    network_log: vec![entry.clone()],
                    ..BugEvidence::default()
                },
                discovered_at: chrono::Utc::now(),
                cwe: rule.cwe.map(str::to_string),
                owasp: rule.owasp.map(str::to_string),
            });
            next_id += 1;
        }
    }

    findings
}

pub fn evaluate_passive_header_findings_from_log(
    network_log_path: Option<&Path>,
    base_url: Option<&Url>,
) -> Vec<Bug> {
    let Some(path) = network_log_path else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let entries = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<TrafficEntry>(line).ok())
        .collect::<Vec<_>>();
    evaluate_passive_header_findings(&entries, base_url)
}

/// Returns true if `bug` is a passive HTTP security-header observation produced
/// by [`evaluate_passive_header_findings`] (e.g. "Missing Content-Security-Policy
/// header").
///
/// These describe missing defense-in-depth response headers — a security-posture
/// concern, not a functional defect. The store uses this to import them under
/// `finding_type = "posture"` so they are hidden from the default functional
/// finding list (and excluded from runtime counts), surfacing only with
/// `--include-posture`. This keeps a handful of boilerplate header warnings from
/// burying the real functional bugs on an otherwise small app.
pub fn is_passive_header_finding(bug: &Bug) -> bool {
    matches!(bug.category, BugCategory::SecurityObservation { .. })
        && bug.title.starts_with("Missing ")
        && bug.title.ends_with(" header")
}

fn is_html_document_response(entry: &TrafficEntry, base_url: Option<&Url>) -> bool {
    if !matches!(entry.request.method, HttpMethod::Get | HttpMethod::Head) {
        return false;
    }
    let Some(resp) = entry.response.as_ref() else {
        return false;
    };
    if !(200..400).contains(&resp.status) {
        return false;
    }
    let Ok(url) = Url::parse(&entry.request.url) else {
        return false;
    };
    if let Some(base) = base_url {
        if !same_origin(base, &url) {
            return false;
        }
    }
    if entry.is_api == Some(true) || looks_like_static_asset_path(url.path()) {
        return false;
    }
    resp.mime_type
        .as_deref()
        .map(|mime| mime.to_ascii_lowercase().contains("html"))
        .unwrap_or_else(|| {
            url.path().ends_with('/')
                || url
                    .path_segments()
                    .and_then(|mut segments| segments.next_back())
                    .map(|last| !last.contains('.'))
                    .unwrap_or(true)
        })
}

fn header_satisfies(
    headers: &BTreeMap<String, String>,
    name: &str,
    required_value: Option<&str>,
) -> bool {
    let Some(actual) = header_value_ci(headers, name) else {
        return false;
    };
    match required_value {
        Some(required) => actual
            .split(';')
            .next()
            .map(|part| part.trim().eq_ignore_ascii_case(required))
            .unwrap_or(false),
        None => !actual.trim().is_empty(),
    }
}

fn has_csp_frame_ancestors(headers: &BTreeMap<String, String>) -> bool {
    header_value_ci(headers, "content-security-policy")
        .map(|value| value.to_ascii_lowercase().contains("frame-ancestors"))
        .unwrap_or(false)
}

fn header_value_ci<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn origin_key(url: &Url) -> String {
    match url.port() {
        Some(port) => format!(
            "{}://{}:{port}",
            url.scheme(),
            url.host_str().unwrap_or_default()
        ),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    crate::url_origin::same_origin(a, b)
}

fn is_loopback_or_localhost(url: &Url) -> bool {
    url.host_str()
        .map(crate::url_origin::is_localhost_alias)
        .unwrap_or(false)
}

fn canonical_header_name(name: &str) -> &'static str {
    match name {
        "content-security-policy" => "Content-Security-Policy",
        "x-frame-options" => "X-Frame-Options",
        "x-content-type-options" => "X-Content-Type-Options",
        "referrer-policy" => "Referrer-Policy",
        "permissions-policy" => "Permissions-Policy",
        "strict-transport-security" => "Strict-Transport-Security",
        _ => "response header",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use url::Url;

    use crate::types::api::{HttpMethod, HttpRequestLog, HttpResponseLog, TrafficEntry};

    fn html_entry(url: &str, headers: &[(&str, &str)]) -> TrafficEntry {
        TrafficEntry {
            occurred_at: Utc::now(),
            trace: None,
            request: HttpRequestLog {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: BTreeMap::new(),
                post_data: None,
            },
            response: Some(HttpResponseLog {
                status: 200,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                mime_type: Some("text/html".to_string()),
                body_snippet: Some("<!doctype html><html></html>".to_string()),
            }),
            failure: None,
            triggered_by: None,
            is_api: Some(false),
            duration_ms: Some(1.0),
            attribution: None,
        }
    }

    #[test]
    fn reports_missing_passive_security_headers_once_per_origin() {
        let base = Url::parse("https://example.test").unwrap();
        let entries = vec![
            html_entry("https://example.test/", &[]),
            html_entry("https://example.test/account", &[]),
        ];

        let findings = super::evaluate_passive_header_findings(&entries, Some(&base));
        let titles: Vec<_> = findings.iter().map(|bug| bug.title.as_str()).collect();

        assert!(titles.contains(&"Missing Content-Security-Policy header"));
        assert!(titles.contains(&"Missing X-Frame-Options header"));
        assert_eq!(
            titles
                .iter()
                .filter(|title| **title == "Missing Content-Security-Policy header")
                .count(),
            1
        );
    }

    #[test]
    fn passive_security_header_findings_attach_request_response_proof() {
        let base = Url::parse("https://example.test").unwrap();
        let entries = vec![html_entry(
            "https://example.test/",
            &[("Server", "fixture")],
        )];

        let findings = super::evaluate_passive_header_findings(&entries, Some(&base));
        let csp = findings
            .iter()
            .find(|bug| bug.title == "Missing Content-Security-Policy header")
            .expect("missing CSP finding");
        assert_eq!(csp.evidence.network_log.len(), 1);
        assert_eq!(
            csp.evidence.network_log[0]
                .response
                .as_ref()
                .unwrap()
                .status,
            200
        );
    }

    #[test]
    fn ignores_static_assets_and_frame_ancestors_for_clickjacking() {
        let base = Url::parse("https://example.test").unwrap();
        let mut asset = html_entry("https://example.test/app.js", &[]);
        asset.response.as_mut().unwrap().mime_type = Some("application/javascript".to_string());
        let html = html_entry(
            "https://example.test/",
            &[(
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'none'",
            )],
        );

        let findings = super::evaluate_passive_header_findings(&[asset, html], Some(&base));
        let titles: Vec<_> = findings.iter().map(|bug| bug.title.as_str()).collect();

        assert!(!titles.contains(&"Missing Content-Security-Policy header"));
        assert!(!titles.contains(&"Missing X-Frame-Options header"));
    }

    #[test]
    fn passive_header_origin_filter_allows_localhost_aliases() {
        let base = Url::parse("http://localhost:4102").unwrap();
        let loopback = Url::parse("http://127.0.0.1:4102/dashboard").unwrap();
        let unspecified = Url::parse("http://0.0.0.0:4102/dashboard").unwrap();

        assert!(super::same_origin(&base, &loopback));
        assert!(super::same_origin(&base, &unspecified));
    }

    #[test]
    fn passive_header_origin_filter_rejects_different_local_ports() {
        let base = Url::parse("http://localhost:4102").unwrap();
        let other = Url::parse("http://127.0.0.1:4103/dashboard").unwrap();

        assert!(!super::same_origin(&base, &other));
    }

    #[test]
    fn generator_output_is_recognized_as_passive_header_findings() {
        let base = Url::parse("https://example.test").unwrap();
        let findings = super::evaluate_passive_header_findings(
            &[html_entry("https://example.test/", &[])],
            Some(&base),
        );
        assert!(
            !findings.is_empty(),
            "expected the generator to emit at least one missing-header finding"
        );
        for bug in &findings {
            assert!(
                super::is_passive_header_finding(bug),
                "generator output must be recognized as a passive header finding: {}",
                bug.title
            );
        }
    }

    #[test]
    fn functional_security_observation_is_not_a_passive_header_finding() {
        use crate::types::bugs::{Bug, BugCategory, BugEvidence, BugLocation, BugSeverity};

        // A form-fuzz style SecurityObservation is a functional finding, not a
        // missing-header posture observation, so it must NOT be reclassified.
        let bug = Bug {
            id: "FUZZ-0001".to_string(),
            severity: BugSeverity::Medium,
            confidence: Some(0.6),
            category: BugCategory::SecurityObservation {
                description: "Form fuzzing: sql payload accepted".to_string(),
            },
            title: "Form validation: sql — accepted".to_string(),
            description: "Payload accepted by the server.".to_string(),
            remediation: None,
            location: BugLocation {
                view: None,
                element: None,
                url: Some("https://example.test/login".to_string()),
            },
            reproduction: vec![],
            evidence: BugEvidence::default(),
            discovered_at: Utc::now(),
            cwe: None,
            owasp: None,
        };
        assert!(!super::is_passive_header_finding(&bug));
    }

    #[test]
    fn localhost_missing_headers_downgrade_to_info_with_low_confidence() {
        let base = Url::parse("http://localhost:5833").unwrap();
        let entries = vec![html_entry("http://localhost:5833/", &[])];

        let findings = super::evaluate_passive_header_findings(&entries, Some(&base));
        assert!(!findings.is_empty());
        for bug in &findings {
            assert_eq!(bug.severity, crate::types::bugs::BugSeverity::Info);
            assert_eq!(bug.confidence, Some(0.35));
            assert!(
                bug.description.contains("local/dev server"),
                "{}",
                bug.description
            );
        }
    }
}
