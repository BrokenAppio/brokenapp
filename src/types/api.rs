use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::dom::InteractionRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Ws,
}

impl HttpMethod {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "WS" | "WEBSOCKET" => Self::Ws,
            _ => Self::Get,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Ws => "WS",
        }
    }
}

/// Endpoint identity: method plus a path template.
///
/// `path_template` is the parameterized path (`/api/orders/:id`) for requests
/// to the scan's own origin. Cross-origin requests keep their origin as a
/// prefix (`https://x.supabase.co/rest/v1/cart`). GraphQL operations append
/// `#QUERY Name` / `#MUTATION Name`, and Next.js Server Action posts append
/// `#action:<id>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct EndpointKey {
    pub method: HttpMethod,
    pub path_template: String,
}

impl std::fmt::Display for EndpointKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.method.as_str(), self.path_template)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParam {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_samples: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub key: EndpointKey,
    pub url_pattern: String,
    #[serde(default)]
    pub path_params: Vec<String>,
    #[serde(default)]
    pub query_params: Vec<QueryParam>,

    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_schema: Option<JsonSchema>,

    #[serde(default)]
    pub response_status_codes: Vec<u16>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_schema: Option<JsonSchema>,

    #[serde(default)]
    pub auth_required: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,

    #[serde(default)]
    pub observed_count: u32,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub status_code_counts: BTreeMap<u16, u32>,

    #[serde(default)]
    pub error_responses: Vec<ErrorResponse>,

    #[serde(default)]
    pub avg_response_time_ms: f64,

    #[serde(default)]
    pub triggered_by: Vec<InteractionRef>,

    /// Internal: stored samples for schema inference.
    #[serde(default, skip_serializing)]
    pub request_body_samples: Vec<serde_json::Value>,
    #[serde(default, skip_serializing)]
    pub response_body_samples: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub occurred_at: DateTime<Utc>,
    /// Correlation metadata for this request/response pair (request id, initiator, action id, etc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<RequestTrace>,
    pub request: HttpRequestLog,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpResponseLog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<InteractionRef>,
    /// Derived tag so `network.jsonl` can be filtered without re-parsing the whole entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_api: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    /// Attribution tag: None or "active" for UI-triggered traffic, "passive" for
    /// imported traffic (HAR, proxy logs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<String>,
}

/// What the write guard did with a state-changing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteGuardAction {
    /// Failed in the browser (`net::ERR_BLOCKED_BY_CLIENT`); native form posts
    /// get an empty 204 so the page stays put. Nothing reached the server.
    Blocked,
    /// Answered locally with the configured stub response. Nothing reached
    /// the server.
    Stubbed,
}

impl WriteGuardAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Stubbed => "stubbed",
        }
    }
}

/// One line of `network.jsonl`: a [`TrafficEntry`] plus annotations that are
/// only meaningful in the log.
///
/// Readers that only need the traffic can keep deserializing lines as
/// [`TrafficEntry`]; the extra keys are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLogRecord {
    #[serde(flatten)]
    pub entry: TrafficEntry,
    /// Endpoint identity this request was aggregated under
    /// (`POST /api/orders`, `POST https://x.supabase.co/rest/v1/cart`,
    /// `POST /graphql#MUTATION Refund`, `POST /cart#action:<id>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_key: Option<String>,
    /// Set when the write guard stopped this request before it reached a
    /// server. Such rows carry no response and must not be treated as
    /// failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_guard: Option<WriteGuardAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTrace {
    /// UUID generated by BrokenApp for this traffic entry.
    pub trace_id: String,
    /// CDP Network.requestId for linking to low-level browser events.
    pub cdp_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_line_number: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_column_number: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_user_gesture: Option<bool>,
    /// Action id stamped by the injected action-probe (when same-origin).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestLog {
    pub method: HttpMethod,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseLog {
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_snippet: Option<String>,
}

/// A compact inferred schema representation (not full JSON Schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSchema {
    #[serde(rename = "type")]
    pub schema_type: JsonSchemaType,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, JsonSchema>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<JsonSchema>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    #[serde(default)]
    pub nullable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JsonSchemaType {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Array,
    Object,
    Mixed,
}
