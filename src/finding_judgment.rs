use serde::{Deserialize, Serialize};

use crate::types::bugs::{Bug, BugCategory, BugSeverity};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingJudgment {
    pub judgment: String,
    pub confidence_score: f64,
    pub confidence_label: String,
    pub confidence_reason: String,
    pub evidence_completeness: EvidenceCompleteness,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_kind: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceCompleteness {
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
}

pub fn judgment_for_bug(bug: &Bug) -> FindingJudgment {
    let mut proof_kind = Vec::new();
    if !bug.evidence.network_log.is_empty() {
        proof_kind.push("request_response".to_string());
    }
    if bug.location.element.is_some()
        || !bug.evidence.action_ids.is_empty()
        || matches!(bug.category, BugCategory::DeadButton { .. })
    {
        proof_kind.push("dom_action".to_string());
    }

    let mut missing = Vec::new();
    if bug.location.url.is_none() {
        missing.push("triggering route/action: route".to_string());
    }
    if requires_action_proof(bug)
        && bug.location.element.is_none()
        && bug.reproduction.is_empty()
        && bug.evidence.action_ids.is_empty()
    {
        missing.push("triggering route/action: action".to_string());
    }
    if requires_request_response_proof(bug) && bug.evidence.network_log.is_empty() {
        missing.push("request/response proof".to_string());
    }
    if bug.reproduction.is_empty() && !passive_or_static_observation(bug) {
        missing.push("reproducibility steps".to_string());
    }
    if let BugCategory::DeadButton {
        precondition_satisfied: Some(false),
        ..
    } = &bug.category
    {
        missing.push("precondition satisfied".to_string());
    }

    let confidence_score = bug
        .confidence
        .unwrap_or_else(|| inferred_confidence_score(bug, &missing))
        .clamp(0.0, 1.0);
    let confidence_score = (confidence_score * 100.0).round() / 100.0;
    let confidence_label = confidence_label(confidence_score).to_string();
    let judgment = judgment_label(bug, confidence_score, &missing).to_string();
    let confidence_reason = confidence_reason(bug, confidence_score, &confidence_label, &missing);

    FindingJudgment {
        judgment,
        confidence_score,
        confidence_label,
        confidence_reason,
        evidence_completeness: EvidenceCompleteness {
            complete: missing.is_empty(),
            missing,
        },
        proof_kind,
    }
}

pub fn confidence_label(score: f64) -> &'static str {
    if score >= 0.8 {
        "high"
    } else if score >= 0.6 {
        "medium"
    } else {
        "low"
    }
}

fn inferred_confidence_score(bug: &Bug, missing: &[String]) -> f64 {
    let mut score: f64 = match bug.severity {
        BugSeverity::Critical => 0.65,
        BugSeverity::High => 0.60,
        BugSeverity::Medium => 0.55,
        BugSeverity::Low => 0.50,
        BugSeverity::Info => 0.45,
    };
    if bug.location.url.is_some() {
        score += 0.10;
    }
    if bug.location.element.is_some() || !bug.evidence.action_ids.is_empty() {
        score += 0.10;
    }
    if !bug.evidence.network_log.is_empty() {
        score += 0.15;
    }
    if !bug.reproduction.is_empty() || passive_or_static_observation(bug) {
        score += 0.10;
    }
    if bug.evidence.screenshot.is_some() || bug.evidence.dom_snapshot.is_some() {
        score += 0.05;
    }
    if !bug.evidence.console_log.is_empty() {
        score += 0.05;
    }
    if !missing.is_empty() {
        score -= 0.05;
    }
    score.clamp(0.0, 1.0)
}

fn judgment_label(bug: &Bug, confidence_score: f64, missing: &[String]) -> &'static str {
    if let BugCategory::DeadButton {
        precondition_satisfied: Some(false),
        ..
    } = &bug.category
    {
        return "coverage_gap";
    }
    if confidence_score < 0.60 {
        return "suspected";
    }
    if !missing.is_empty() && confidence_score < 0.80 {
        return "suspected";
    }
    match &bug.category {
        BugCategory::SecurityObservation { .. }
        | BugCategory::ServerError { .. }
        | BugCategory::ApiError { .. }
        | BugCategory::NetworkRequestFailure { .. }
        | BugCategory::AssetLoadFailure { .. }
        | BugCategory::BrokenLink { .. } => {
            if !missing.iter().any(|m| m == "request/response proof") {
                "confirmed"
            } else {
                "suspected"
            }
        }
        BugCategory::DeadButton { .. } => {
            if confidence_score >= 0.80 {
                "confirmed"
            } else {
                "suspected"
            }
        }
        BugCategory::AccessibilityViolation { .. } => "confirmed",
        BugCategory::UiErrorToast { .. } | BugCategory::WebSocketError { .. } => {
            if confidence_score >= 0.80 && missing.is_empty() {
                "confirmed"
            } else {
                "suspected"
            }
        }
        _ => {
            if confidence_score >= 0.80 {
                "confirmed"
            } else {
                "suspected"
            }
        }
    }
}

fn confidence_reason(
    bug: &Bug,
    confidence_score: f64,
    confidence_label: &str,
    missing: &[String],
) -> String {
    if let Some(reason) = passive_header_reason(bug) {
        return reason;
    }
    if let BugCategory::DeadButton {
        label,
        pre_click_pattern,
        classification,
        ..
    } = &bug.category
    {
        let label_text = label.as_deref().unwrap_or("unlabeled control");
        return format!(
            "Dead-control detector scored this {confidence_score:.2} ({confidence_label}) for {label_text:?}; classification={} pattern={}. Treat as suspected unless source or UX intent proves the control should navigate or mutate state.",
            classification.as_deref().unwrap_or("unknown"),
            pre_click_pattern.as_deref().unwrap_or("unknown")
        );
    }
    if missing.is_empty() {
        format!(
            "BrokenApp has complete scanner evidence for this finding and assigned {confidence_label} confidence ({confidence_score:.2})."
        )
    } else {
        format!(
            "BrokenApp assigned {confidence_label} confidence ({confidence_score:.2}); missing evidence: {}.",
            missing.join(", ")
        )
    }
}

fn passive_header_reason(bug: &Bug) -> Option<String> {
    if !matches!(bug.category, BugCategory::SecurityObservation { .. }) {
        return None;
    }
    if !bug.title.to_ascii_lowercase().contains("header") {
        return None;
    }
    let entry = bug.evidence.network_log.first()?;
    let status = entry
        .response
        .as_ref()
        .map(|r| r.status)
        .unwrap_or_default();
    Some(format!(
        "Captured {} {} returned status {} with response headers; the required header was absent or invalid in that response.",
        format!("{:?}", entry.request.method).to_uppercase(),
        entry.request.url,
        status
    ))
}

fn requires_action_proof(bug: &Bug) -> bool {
    matches!(bug.category, BugCategory::DeadButton { .. })
}

fn requires_request_response_proof(bug: &Bug) -> bool {
    matches!(
        bug.category,
        BugCategory::SecurityObservation { .. }
            | BugCategory::ServerError { .. }
            | BugCategory::ApiError { .. }
            | BugCategory::NetworkRequestFailure { .. }
            | BugCategory::AssetLoadFailure { .. }
            | BugCategory::BrokenLink { .. }
    )
}

fn passive_or_static_observation(bug: &Bug) -> bool {
    matches!(bug.category, BugCategory::SecurityObservation { .. })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::types::bugs::{BugEvidence, BugLocation};

    #[test]
    fn respects_detector_confidence_for_dead_sidebar_button() {
        let bug = Bug {
            id: "BUG-1".to_string(),
            severity: BugSeverity::Medium,
            confidence: Some(0.50),
            category: BugCategory::DeadButton {
                selector: "button.sidebar-dashboard".to_string(),
                label: Some("⌂ Dashboard".to_string()),
                precondition_hint: None,
                precondition_satisfied: Some(true),
                pre_click_pattern: Some("unknown".to_string()),
                classification: Some("dead".to_string()),
            },
            title: "Unresponsive Dashboard sidebar button".to_string(),
            description: "Clicking the Dashboard sidebar button produced no observable effect."
                .to_string(),
            remediation: None,
            location: BugLocation {
                view: None,
                element: Some("button.sidebar-dashboard".to_string()),
                url: Some("http://localhost:9099/".to_string()),
            },
            reproduction: vec![],
            evidence: BugEvidence::default(),
            discovered_at: Utc::now(),
            cwe: None,
            owasp: None,
        };

        let judgment = judgment_for_bug(&bug);

        assert_eq!(judgment.confidence_score, 0.50);
        assert_eq!(judgment.confidence_label, "low");
        assert_eq!(judgment.judgment, "suspected");
        assert!(
            judgment.confidence_reason.contains("Dead-control detector"),
            "{}",
            judgment.confidence_reason
        );
    }
}
