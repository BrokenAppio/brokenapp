//! Lenient readers for the scan artifacts the inventory is built from.
//!
//! Every input is optional except `spec.json`: older scans have no
//! `interactions.jsonl`, scans without a network log have no
//! `network.jsonl`, and fields added by newer scanners (`write_guard`,
//! endpoint keys, source captures) are picked up when present. Malformed
//! lines and elements are skipped rather than failing the build.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::output::interactions::{InteractionRecord, read_interactions};
use crate::types::dom::InteractiveElement;

/// Everything read from one scan directory.
#[derive(Debug, Default)]
pub struct ScanArtifacts {
    pub target_url: String,
    pub views: Vec<SpecView>,
    pub endpoints: Vec<SpecEndpoint>,
    pub transitions: Vec<SpecTransition>,
    /// `interactions.jsonl` existed (even if empty).
    pub has_interactions: bool,
    pub interactions: Vec<InteractionRecord>,
    pub network: Vec<NetRow>,
    pub gaps: Vec<GapItem>,
    /// `(view, selector)` reported by the dead-button detector (`bugs.json`).
    pub dead_buttons: Vec<(Option<String>, String)>,
    /// `(url, message)` for pages the crawler failed to load (navigation
    /// timeouts and errors recorded in `checkpoint.json`).
    pub nav_failures: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct SpecView {
    pub id: String,
    pub route: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub elements: Vec<InteractiveElement>,
    pub on_load: Vec<String>,
}

#[derive(Debug, Default)]
pub struct SpecEndpoint {
    pub key: String,
    pub triggered_by: Vec<(String, String)>,
    pub statuses: Vec<u16>,
}

#[derive(Debug, Default)]
pub struct SpecTransition {
    pub from_view: String,
    pub to_view: String,
    pub trigger_view: String,
    pub trigger_selector: String,
    pub kind: String,
}

/// One coverage gap (`coverage-gaps.json`).
#[derive(Debug, Default, Clone)]
pub struct GapItem {
    pub kind: String,
    pub target: String,
    pub reason: String,
    /// View id parsed from `context` (`view_0001 label=...`).
    pub view: Option<String>,
}

/// Compact `network.jsonl` row.
#[derive(Debug, Default, Clone)]
pub struct NetRow {
    pub occurred_at: Option<DateTime<Utc>>,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub failure: Option<String>,
    /// `Sec-Fetch-Dest: document` (top-level navigation).
    pub is_document: bool,
    pub is_api: Option<bool>,
    pub mime: Option<String>,
    pub action_id: Option<String>,
    pub trigger: Option<(String, String)>,
    pub write_guard: Option<String>,
    /// Endpoint key recorded by the scanner, when present.
    pub endpoint: Option<String>,
    pub post_data: Option<String>,
    /// `Next-Action` request header (Next.js Server Actions).
    pub next_action: Option<String>,
    /// `Location` response header (redirects).
    pub location: Option<String>,
    /// CDP request id: a redirect chain shares it across its hops.
    pub request_id: Option<String>,
}

impl NetRow {
    /// Request fired by a page load rather than a control.
    pub fn is_page_load(&self) -> bool {
        match &self.trigger {
            Some((view, selector)) => selector == "__page_load__" || view.starts_with("__load_"),
            None => self.action_id.is_none(),
        }
    }

    pub fn is_guarded(&self) -> bool {
        self.write_guard
            .as_deref()
            .is_some_and(|g| !g.is_empty() && g != "off" && g != "allowed")
    }
}

pub fn load(scan_dir: &Path) -> Result<ScanArtifacts> {
    let spec_path = scan_dir.join("spec.json");
    let raw = std::fs::read_to_string(&spec_path)
        .with_context(|| format!("read {}", spec_path.display()))?;
    let spec: RawSpec =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", spec_path.display()))?;

    let mut art = ScanArtifacts {
        target_url: spec
            .meta
            .target_url
            .filter(|s| !s.is_empty())
            .or(spec.application.base_url)
            .unwrap_or_default(),
        ..Default::default()
    };

    for v in spec.views {
        let elements = v
            .elements
            .into_iter()
            .filter_map(|e| match serde_json::from_value::<InteractiveElement>(e) {
                Ok(el) => Some(el),
                Err(err) => {
                    tracing::debug!(view = %v.id, "skip unparseable element: {err}");
                    None
                }
            })
            .collect();
        art.views.push(SpecView {
            id: v.id,
            route: v.route,
            url: v.url,
            title: v.title.filter(|t| !t.trim().is_empty()),
            elements,
            on_load: v
                .on_load_api_calls
                .iter()
                .filter_map(RawKey::render)
                .collect(),
        });
    }

    for e in spec.api_surface.endpoints {
        let Some(key) = e.key.render() else { continue };
        let mut statuses = e.response_status_codes;
        statuses.extend(
            e.status_code_counts
                .keys()
                .filter_map(|k| k.parse::<u16>().ok()),
        );
        statuses.sort_unstable();
        statuses.dedup();
        art.endpoints.push(SpecEndpoint {
            key,
            triggered_by: e
                .triggered_by
                .into_iter()
                .map(|t| (t.view, t.selector))
                .collect(),
            statuses,
        });
    }

    for t in spec.state_machine.transitions {
        art.transitions.push(SpecTransition {
            from_view: t.from_view,
            to_view: t.to_view,
            trigger_view: t.trigger.view,
            trigger_selector: t.trigger.selector,
            kind: t.transition_type,
        });
    }

    art.has_interactions = scan_dir
        .join(crate::output::interactions::INTERACTIONS_FILE)
        .is_file();
    art.interactions = read_interactions(scan_dir)?;
    art.network = read_network(&scan_dir.join("network.jsonl"))?;
    art.gaps = read_gaps(&scan_dir.join("coverage-gaps.json"));
    art.dead_buttons = read_dead_buttons(&scan_dir.join("bugs.json"));
    art.nav_failures = read_nav_failures(&scan_dir.join("checkpoint.json"));
    Ok(art)
}

/// `Failed to navigate to <url>: <message>` findings from the crawler
/// checkpoint (they are not always promoted to `bugs.json`).
fn read_nav_failures(path: &Path) -> Vec<(String, String)> {
    #[derive(Deserialize, Default)]
    struct Checkpoint {
        #[serde(default)]
        bugs: Vec<Bug>,
    }
    #[derive(Deserialize, Default)]
    struct Bug {
        #[serde(default)]
        description: String,
    }
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(cp) = serde_json::from_str::<Checkpoint>(&raw) else {
        return Vec::new();
    };
    cp.bugs
        .iter()
        .filter_map(|b| {
            let rest = b.description.strip_prefix("Failed to navigate to ")?;
            let (url, msg) = rest.split_once(": ").unwrap_or((rest, "navigation failed"));
            Some((url.trim().to_string(), msg.trim().to_string()))
        })
        .collect()
}

fn read_network(path: &Path) -> Result<Vec<NetRow>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("read {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(row) = serde_json::from_str::<RawNetRow>(&line) else {
            continue;
        };
        out.push(row.into_row());
    }
    Ok(out)
}

fn read_gaps(path: &Path) -> Vec<GapItem> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(gaps) = serde_json::from_str::<RawGaps>(&raw) else {
        tracing::debug!("skip unparseable {}", path.display());
        return Vec::new();
    };
    gaps.items
        .into_iter()
        .map(|g| GapItem {
            view: g
                .context
                .as_deref()
                .and_then(|c| c.split_whitespace().next())
                .filter(|v| v.starts_with("view_") || v.starts_with("__"))
                .map(str::to_string),
            kind: g.kind,
            target: g.target,
            reason: g.reason,
        })
        .collect()
}

/// Dead-button findings. Collapsed `dead_button_group` findings only list
/// their selectors in the description (backticked bullet lines).
fn read_dead_buttons(path: &Path) -> Vec<(Option<String>, String)> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(report) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    let items = report
        .get("items")
        .or_else(|| report.get("bugs"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for item in items {
        let category = item.get("category");
        let kind = category
            .and_then(|c| c.get("kind"))
            .and_then(|k| k.as_str())
            .unwrap_or("");
        let view = item
            .pointer("/location/view")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if kind == "dead_button" {
            if let Some(sel) = category
                .and_then(|c| c.get("selector"))
                .and_then(|s| s.as_str())
            {
                out.push((view, sel.to_string()));
            }
            continue;
        }
        let is_group = category
            .and_then(|c| c.get("description"))
            .and_then(|d| d.as_str())
            == Some("dead_button_group");
        if is_group {
            let desc = item
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            for line in desc.lines() {
                let line = line.trim();
                if let Some(sel) = line
                    .strip_prefix("- `")
                    .and_then(|rest| rest.strip_suffix('`'))
                {
                    out.push((view.clone(), sel.to_string()));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Raw (lenient) shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct RawSpec {
    #[serde(default)]
    meta: RawMeta,
    #[serde(default)]
    application: RawApplication,
    #[serde(default)]
    views: Vec<RawView>,
    #[serde(default)]
    api_surface: RawApiSurface,
    #[serde(default)]
    state_machine: RawStateMachine,
}

#[derive(Debug, Default, Deserialize)]
struct RawMeta {
    #[serde(default)]
    target_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawApplication {
    #[serde(default)]
    base_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawView {
    #[serde(default)]
    id: String,
    #[serde(default)]
    route: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    elements: Vec<serde_json::Value>,
    #[serde(default)]
    on_load_api_calls: Vec<RawKey>,
}

#[derive(Debug, Default, Deserialize)]
struct RawKey {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path_template: String,
}

impl RawKey {
    fn render(&self) -> Option<String> {
        if self.path_template.is_empty() {
            return None;
        }
        let method = if self.method.is_empty() {
            "GET".to_string()
        } else {
            self.method.to_ascii_uppercase()
        };
        Some(format!("{method} {}", self.path_template))
    }
}

#[derive(Debug, Default, Deserialize)]
struct RawApiSurface {
    #[serde(default)]
    endpoints: Vec<RawEndpoint>,
}

#[derive(Debug, Default, Deserialize)]
struct RawEndpoint {
    #[serde(default)]
    key: RawKey,
    #[serde(default)]
    response_status_codes: Vec<u16>,
    #[serde(default)]
    status_code_counts: BTreeMap<String, u32>,
    #[serde(default)]
    triggered_by: Vec<RawRef>,
}

#[derive(Debug, Default, Deserialize)]
struct RawRef {
    #[serde(default)]
    view: String,
    #[serde(default)]
    selector: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawStateMachine {
    #[serde(default)]
    transitions: Vec<RawTransition>,
}

#[derive(Debug, Default, Deserialize)]
struct RawTransition {
    #[serde(default)]
    from_view: String,
    #[serde(default)]
    to_view: String,
    #[serde(default)]
    trigger: RawRef,
    #[serde(default)]
    transition_type: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawGaps {
    #[serde(default)]
    items: Vec<RawGap>,
}

#[derive(Debug, Default, Deserialize)]
struct RawGap {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    context: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawNetRow {
    #[serde(default)]
    occurred_at: Option<String>,
    #[serde(default)]
    trace: Option<RawTrace>,
    #[serde(default)]
    request: RawRequest,
    #[serde(default)]
    response: Option<RawResponse>,
    #[serde(default)]
    failure: Option<String>,
    #[serde(default)]
    triggered_by: Option<RawRef>,
    #[serde(default)]
    is_api: Option<bool>,
    #[serde(default)]
    write_guard: Option<serde_json::Value>,
    #[serde(default)]
    endpoint: Option<serde_json::Value>,
    #[serde(default)]
    endpoint_key: Option<serde_json::Value>,
    #[serde(default)]
    action_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawTrace {
    #[serde(default)]
    action_id: Option<String>,
    #[serde(default)]
    cdp_request_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawRequest {
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    post_data: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawResponse {
    #[serde(default)]
    status: u16,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

impl RawNetRow {
    fn into_row(self) -> NetRow {
        // CDP often omits Sec-Fetch-* on navigation requests; fall back to an
        // HTML response that the scanner did not tag as API traffic.
        let fetch_dest = self
            .request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("sec-fetch-dest"))
            .map(|(_, v)| v.to_ascii_lowercase());
        let html_response = self
            .response
            .as_ref()
            .and_then(|r| r.mime_type.as_deref())
            .is_some_and(|m| m.to_ascii_lowercase().starts_with("text/html"));
        let is_document = match fetch_dest.as_deref() {
            Some(dest) => dest == "document",
            None => {
                html_response
                    && self.is_api != Some(true)
                    && !url::Url::parse(&self.request.url).ok().is_some_and(|u| {
                        crate::network::filters::looks_like_static_asset_path(u.path())
                    })
            }
        };
        let endpoint = self
            .endpoint_key
            .as_ref()
            .and_then(render_endpoint_value)
            .or_else(|| self.endpoint.as_ref().and_then(render_endpoint_value));
        let write_guard = match self.write_guard {
            Some(serde_json::Value::String(s)) => Some(s),
            Some(serde_json::Value::Object(map)) => map
                .get("action")
                .or_else(|| map.get("mode"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            Some(serde_json::Value::Bool(true)) => Some("blocked".to_string()),
            _ => None,
        };
        let next_action = self
            .request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("next-action"))
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let trace = self.trace.unwrap_or_default();
        let location = self.response.as_ref().and_then(|r| {
            r.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.trim().to_string())
                .filter(|v| !v.is_empty())
        });
        NetRow {
            occurred_at: self
                .occurred_at
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            method: if self.request.method.is_empty() {
                "GET".to_string()
            } else {
                self.request.method.to_ascii_uppercase()
            },
            url: self.request.url,
            status: self.response.as_ref().map(|r| r.status).filter(|s| *s > 0),
            failure: self.failure,
            is_document,
            is_api: self.is_api,
            mime: self.response.and_then(|r| r.mime_type),
            action_id: trace.action_id.or(self.action_id),
            trigger: self
                .triggered_by
                .filter(|t| !t.view.is_empty() || !t.selector.is_empty())
                .map(|t| (t.view, t.selector)),
            write_guard,
            endpoint,
            post_data: self.request.post_data,
            next_action,
            location,
            request_id: trace.cdp_request_id.filter(|r| !r.is_empty()),
        }
    }
}

/// Endpoint key from a string (`POST /api/x`) or `{method, path_template}`.
fn render_endpoint_value(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if s.contains(' ') => Some(s.trim().to_string()),
        serde_json::Value::Object(map) => {
            let method = map.get("method").and_then(|m| m.as_str())?;
            let path = map
                .get("path_template")
                .or_else(|| map.get("path"))
                .and_then(|p| p.as_str())?;
            Some(format!("{} {}", method.to_ascii_uppercase(), path))
        }
        _ => None,
    }
}
