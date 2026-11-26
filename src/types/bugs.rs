use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::api::TrafficEntry;
use crate::types::graph::ViewId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bug {
    pub id: String,
    pub severity: BugSeverity,
    /// Optional confidence score in [0.0, 1.0] for noisy/heuristic detections.
    /// Higher means "more likely a real issue".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub category: BugCategory,
    pub title: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    pub location: BugLocation,
    #[serde(default)]
    pub reproduction: Vec<String>,
    pub evidence: BugEvidence,
    pub discovered_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BugSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AccessibilityImpact {
    Critical,
    Serious,
    Moderate,
    Minor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BugCategory {
    BrokenLink {
        url: String,
        status: u16,
    },
    AssetLoadFailure {
        url: String,
        status: u16,
    },
    DeadButton {
        selector: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        precondition_hint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        precondition_satisfied: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pre_click_pattern: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        classification: Option<String>,
    },
    ServerError {
        endpoint: String,
        status: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response: Option<String>,
    },
    ApiError {
        endpoint: String,
        status: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response: Option<String>,
    },
    NetworkRequestFailure {
        endpoint: String,
        failure: String,
    },
    ConsoleError {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    CorsError {
        endpoint: String,
    },
    MixedContent {
        insecure_url: String,
    },
    InconsistentApiResponse {
        endpoint: String,
        description: String,
    },
    OrphanedRoute {
        url: String,
    },
    PerformanceIssue {
        metric: String,
        value: f64,
        threshold: f64,
    },
    AccessibilityViolation {
        /// Machine identifier for the rule/category (e.g. "missing_alt_text").
        category: String,
        /// WCAG criterion id (e.g. "1.1.1").
        wcag_criterion: String,
        impact: AccessibilityImpact,
    },
    SecurityObservation {
        description: String,
    },
    UnexpectedRedirect {
        requested_url: String,
        landed_url: String,
        redirect_kind: String,
    },
    UiErrorToast {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
    },
    #[serde(rename = "websocket_error")]
    WebSocketError {
        endpoint: String,
        message: String,
    },
    Other {
        description: String,
    },
}

impl BugCategory {
    /// Return the variant name as a string, ignoring inner fields.
    /// Used for grouping/counting categories in confidence adjustment.
    pub fn discriminant_name(&self) -> String {
        match self {
            Self::BrokenLink { .. } => "BrokenLink",
            Self::AssetLoadFailure { .. } => "AssetLoadFailure",
            Self::DeadButton { .. } => "DeadButton",
            Self::ServerError { .. } => "ServerError",
            Self::ApiError { .. } => "ApiError",
            Self::NetworkRequestFailure { .. } => "NetworkRequestFailure",
            Self::ConsoleError { .. } => "ConsoleError",
            Self::CorsError { .. } => "CorsError",
            Self::MixedContent { .. } => "MixedContent",
            Self::InconsistentApiResponse { .. } => "InconsistentApiResponse",
            Self::OrphanedRoute { .. } => "OrphanedRoute",
            Self::PerformanceIssue { .. } => "PerformanceIssue",
            Self::AccessibilityViolation { .. } => "AccessibilityViolation",
            Self::SecurityObservation { .. } => "SecurityObservation",
            Self::UnexpectedRedirect { .. } => "UnexpectedRedirect",
            Self::UiErrorToast { .. } => "UiErrorToast",
            Self::WebSocketError { .. } => "WebSocketError",
            Self::Other { .. } => "Other",
        }
        .to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<ViewId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub element: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteContext {
    pub tier: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BugEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_log: Vec<TrafficEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub console_log: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom_snapshot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_context: Option<RouteContext>,
}
