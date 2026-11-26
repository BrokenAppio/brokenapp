//! TOML-based custom rule engine.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::types::api::{ApiEndpoint, TrafficEntry};
use crate::types::bugs::{Bug, BugCategory, BugEvidence, BugLocation, BugSeverity};
use crate::types::graph::AppView;

/// A user-defined custom check rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    #[serde(rename = "match")]
    pub matcher: RuleMatcher,
}

fn default_severity() -> String {
    "medium".to_string()
}

/// Tagged matcher for different rule types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleMatcher {
    /// Match endpoints by API characteristics.
    Endpoint {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method_pattern: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_pattern: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_required: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status_code_pattern: Option<String>,
    },
    /// Check for missing response headers.
    MissingHeader {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_pattern: Option<String>,
        header_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_value: Option<String>,
    },
    /// Regex match on response bodies.
    ResponseBody {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_pattern: Option<String>,
        body_pattern: String,
    },
    /// Check for presence/absence of page elements.
    ViewElement {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route_pattern: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        required_element_selector: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        required_element_label: Option<String>,
        #[serde(default)]
        negate: bool,
    },
}

/// Result of evaluating custom rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleEvaluation {
    pub rules_evaluated: usize,
    pub findings: Vec<Bug>,
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    pattern == value
}

fn parse_severity(s: &str) -> BugSeverity {
    match s.to_lowercase().as_str() {
        "critical" => BugSeverity::Critical,
        "high" => BugSeverity::High,
        "medium" => BugSeverity::Medium,
        "low" => BugSeverity::Low,
        "info" => BugSeverity::Info,
        _ => BugSeverity::Medium,
    }
}

fn push_custom_finding(
    findings: &mut Vec<Bug>,
    bug_seq: &mut usize,
    rule: &CustomRule,
    description: String,
    url: Option<String>,
    reproduction: Vec<String>,
    confidence: f64,
) {
    *bug_seq += 1;
    findings.push(Bug {
        id: format!("CUSTOM-{:04}", *bug_seq),
        severity: parse_severity(&rule.severity),
        confidence: Some(confidence),
        category: BugCategory::SecurityObservation {
            description: description.clone(),
        },
        title: rule.name.clone(),
        description: rule.description.clone().unwrap_or(description),
        remediation: rule.remediation.clone(),
        location: BugLocation {
            view: None,
            element: None,
            url,
        },
        reproduction,
        evidence: BugEvidence::default(),
        discovered_at: chrono::Utc::now(),
        cwe: rule.cwe.clone(),
        owasp: rule.owasp.clone(),
    });
}

fn path_from_url(url: &str) -> String {
    if let Ok(parsed) = Url::parse(url) {
        return parsed.path().to_string();
    }
    url.split('?').next().unwrap_or(url).to_string()
}

fn header_value_ci<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.as_str());
        }
    }
    None
}

fn load_network_entries(network_log: Option<&Path>) -> Vec<TrafficEntry> {
    let Some(path) = network_log else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            serde_json::from_str::<TrafficEntry>(trimmed).ok()
        })
        .collect()
}

fn route_matches(pattern: Option<&str>, route_or_url: &str) -> bool {
    let Some(pattern) = pattern else {
        return true;
    };
    let path = path_from_url(route_or_url);
    glob_matches(pattern, route_or_url) || glob_matches(pattern, &path)
}

/// Evaluate custom rules against scan data.
pub fn evaluate_custom_rules(
    rules: &[CustomRule],
    endpoints: &[ApiEndpoint],
    network_log: Option<&Path>,
    views: &[AppView],
) -> CustomRuleEvaluation {
    let mut findings = Vec::new();
    let mut bug_seq = 0usize;
    let network_entries = load_network_entries(network_log);

    for rule in rules {
        match &rule.matcher {
            RuleMatcher::Endpoint {
                method_pattern,
                path_pattern,
                auth_required,
                status_code_pattern: _,
            } => {
                for ep in endpoints {
                    let method_ok = method_pattern
                        .as_ref()
                        .map(|p| glob_matches(p, ep.key.method.as_str()))
                        .unwrap_or(true);

                    let path_ok = path_pattern
                        .as_ref()
                        .map(|p| glob_matches(p, &ep.key.path_template))
                        .unwrap_or(true);

                    let auth_ok = auth_required
                        .map(|expected| ep.auth_required == expected)
                        .unwrap_or(true);

                    if method_ok && path_ok && auth_ok {
                        push_custom_finding(
                            &mut findings,
                            &mut bug_seq,
                            rule,
                            rule.description
                                .clone()
                                .unwrap_or_else(|| rule.name.clone()),
                            Some(ep.key.path_template.clone()),
                            vec![format!(
                                "{} {}",
                                ep.key.method.as_str(),
                                ep.key.path_template
                            )],
                            0.9,
                        );
                    }
                }
            }
            RuleMatcher::MissingHeader {
                path_pattern,
                header_name,
                expected_value,
            } => {
                if network_entries.is_empty() {
                    continue;
                }

                let mut seen = HashSet::new();
                for entry in &network_entries {
                    let Some(resp) = entry.response.as_ref() else {
                        continue;
                    };

                    let path = path_from_url(&entry.request.url);
                    if !path_pattern
                        .as_ref()
                        .map(|p| glob_matches(p, &path))
                        .unwrap_or(true)
                    {
                        continue;
                    }

                    let observed = header_value_ci(&resp.headers, header_name);
                    let header_ok = match (observed, expected_value.as_deref()) {
                        (None, _) => false,
                        (Some(_), None) => true,
                        (Some(actual), Some(expected)) => {
                            actual.trim().eq_ignore_ascii_case(expected.trim())
                        }
                    };

                    if header_ok {
                        continue;
                    }

                    let method = entry.request.method.as_str().to_string();
                    let dedupe_key = format!("{} {}", method, path);
                    if !seen.insert(dedupe_key.clone()) {
                        continue;
                    }

                    let expectation = expected_value
                        .as_ref()
                        .map(|v| format!("{}: {}", header_name, v))
                        .unwrap_or_else(|| header_name.clone());

                    push_custom_finding(
                        &mut findings,
                        &mut bug_seq,
                        rule,
                        format!(
                            "Missing or invalid response header '{}' on {}",
                            expectation, dedupe_key
                        ),
                        Some(path.clone()),
                        vec![dedupe_key],
                        0.85,
                    );
                }
            }
            RuleMatcher::ResponseBody {
                path_pattern,
                body_pattern,
            } => {
                if network_entries.is_empty() {
                    continue;
                }

                let Ok(body_re) = Regex::new(body_pattern) else {
                    continue;
                };

                let mut seen = HashSet::new();
                for entry in &network_entries {
                    let Some(resp) = entry.response.as_ref() else {
                        continue;
                    };
                    let Some(body) = resp.body_snippet.as_deref() else {
                        continue;
                    };

                    let path = path_from_url(&entry.request.url);
                    if !path_pattern
                        .as_ref()
                        .map(|p| glob_matches(p, &path))
                        .unwrap_or(true)
                    {
                        continue;
                    }

                    if !body_re.is_match(body) {
                        continue;
                    }

                    let method = entry.request.method.as_str().to_string();
                    let dedupe_key = format!("{} {}", method, path);
                    if !seen.insert(dedupe_key.clone()) {
                        continue;
                    }

                    push_custom_finding(
                        &mut findings,
                        &mut bug_seq,
                        rule,
                        format!("Response body pattern matched on {}", dedupe_key),
                        Some(path.clone()),
                        vec![dedupe_key],
                        0.8,
                    );
                }
            }
            RuleMatcher::ViewElement {
                route_pattern,
                required_element_selector,
                required_element_label,
                negate,
            } => {
                if required_element_selector.is_none() && required_element_label.is_none() {
                    continue;
                }

                let required_label_lc = required_element_label
                    .as_ref()
                    .map(|label| label.to_ascii_lowercase());

                for view in views {
                    if !route_matches(route_pattern.as_deref(), &view.url) {
                        continue;
                    }

                    let element_present = view.elements.iter().any(|el| {
                        let selector_ok = required_element_selector
                            .as_ref()
                            .map(|required| {
                                glob_matches(required, &el.selector)
                                    || el.selector.contains(required)
                            })
                            .unwrap_or(true);

                        let label_ok = required_label_lc
                            .as_ref()
                            .map(|needle| {
                                el.label
                                    .as_ref()
                                    .map(|label| label.to_ascii_lowercase().contains(needle))
                                    .unwrap_or(false)
                            })
                            .unwrap_or(true);

                        selector_ok && label_ok
                    });

                    let violation = if *negate {
                        element_present
                    } else {
                        !element_present
                    };

                    if !violation {
                        continue;
                    }

                    let expectation = match (required_element_selector, required_element_label) {
                        (Some(sel), Some(label)) => {
                            format!("selector '{}' and label '{}'", sel, label)
                        }
                        (Some(sel), None) => format!("selector '{}'", sel),
                        (None, Some(label)) => format!("label '{}'", label),
                        (None, None) => "element".to_string(),
                    };

                    let description = if *negate {
                        format!(
                            "Unexpected element with {} present on {}",
                            expectation, view.url
                        )
                    } else {
                        format!(
                            "Missing required element with {} on {}",
                            expectation, view.url
                        )
                    };

                    push_custom_finding(
                        &mut findings,
                        &mut bug_seq,
                        rule,
                        description,
                        Some(view.url.clone()),
                        vec![format!("Visit {}", view.url)],
                        0.8,
                    );
                }
            }
        }
    }

    CustomRuleEvaluation {
        rules_evaluated: rules.len(),
        findings,
    }
}
