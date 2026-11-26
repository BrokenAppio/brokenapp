//! HAR 1.2 subset parser and traffic converter.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::api::{HttpMethod, HttpRequestLog, HttpResponseLog, TrafficEntry};

// ── HAR 1.2 Types ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct HarFile {
    pub log: HarLog,
}

#[derive(Debug, Deserialize)]
pub struct HarLog {
    #[serde(default)]
    pub entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
pub struct HarEntry {
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub request: HarRequest,
    pub response: HarResponse,
    #[serde(default)]
    pub time: f64,
}

#[derive(Debug, Deserialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<HarHeader>,
    #[serde(rename = "postData", default)]
    pub post_data: Option<HarPostData>,
}

#[derive(Debug, Deserialize)]
pub struct HarResponse {
    pub status: i32,
    #[serde(rename = "statusText", default)]
    pub status_text: String,
    #[serde(default)]
    pub headers: Vec<HarHeader>,
    pub content: Option<HarContent>,
}

#[derive(Debug, Deserialize)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct HarPostData {
    #[serde(rename = "mimeType", default)]
    pub mime_type: String,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HarContent {
    #[serde(rename = "mimeType", default)]
    pub mime_type: String,
    #[serde(default)]
    pub text: Option<String>,
}

// ── Import result ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HarImportResult {
    pub total_entries: usize,
    pub api_entries: usize,
    pub skipped: usize,
    pub new_endpoints: usize,
}

// ── Conversion ───────────────────────────────────────────────────────

fn har_headers_to_map(headers: &[HarHeader]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for h in headers {
        map.entry(h.name.to_lowercase())
            .or_insert_with(|| h.value.clone());
    }
    map
}

fn convert_har_entry(entry: &HarEntry) -> Option<TrafficEntry> {
    let occurred_at: DateTime<Utc> = entry
        .started_date_time
        .parse()
        .unwrap_or_else(|_| Utc::now());

    let method = HttpMethod::from_str_lossy(&entry.request.method);

    let request = HttpRequestLog {
        method,
        url: entry.request.url.clone(),
        headers: har_headers_to_map(&entry.request.headers),
        post_data: entry
            .request
            .post_data
            .as_ref()
            .and_then(|pd| pd.text.clone()),
    };

    let status = entry.response.status;
    if status <= 0 {
        return None; // Skip failed/aborted requests
    }

    let body_snippet = entry
        .response
        .content
        .as_ref()
        .and_then(|c| c.text.as_ref())
        .map(|t| {
            if t.len() > 512 {
                t[..512].to_string()
            } else {
                t.clone()
            }
        });

    let response = Some(HttpResponseLog {
        status: status as u16,
        headers: har_headers_to_map(&entry.response.headers),
        mime_type: entry.response.content.as_ref().map(|c| c.mime_type.clone()),
        body_snippet,
    });

    Some(TrafficEntry {
        occurred_at,
        trace: None,
        request,
        response,
        failure: None,
        triggered_by: None,
        is_api: None,
        duration_ms: if entry.time > 0.0 {
            Some(entry.time)
        } else {
            None
        },
        attribution: Some("passive".to_string()),
    })
}

/// Parse a HAR file and convert entries to BrokenApp TrafficEntry format.
pub fn parse_har_file(path: &Path) -> Result<Vec<TrafficEntry>> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("read HAR file {}", path.display()))?;
    let har: HarFile =
        serde_json::from_str(&data).with_context(|| format!("parse HAR {}", path.display()))?;

    let entries: Vec<TrafficEntry> = har
        .log
        .entries
        .iter()
        .filter_map(convert_har_entry)
        .collect();

    Ok(entries)
}

/// Import HAR entries into an existing scan directory by appending to network.jsonl.
pub async fn import_har_to_scan_dir(
    har_path: &Path,
    scan_dir: &Path,
    base_url: &url::Url,
) -> Result<HarImportResult> {
    let entries = parse_har_file(har_path)?;
    let total_entries = entries.len();

    // Filter to same-origin API requests
    let api_entries: Vec<&TrafficEntry> = entries
        .iter()
        .filter(|e| {
            if let Ok(u) = url::Url::parse(&e.request.url) {
                u.host() == base_url.host() && crate::network::filters::is_application_traffic(e)
            } else {
                false
            }
        })
        .collect();

    let api_count = api_entries.len();
    let skipped = total_entries - api_count;

    // Append to network.jsonl
    let network_path = scan_dir.join("network.jsonl");
    let mut lines = String::new();
    for entry in &api_entries {
        if let Ok(json) = serde_json::to_string(entry) {
            lines.push_str(&json);
            lines.push('\n');
        }
    }

    if !lines.is_empty() {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&network_path)
            .await
            .with_context(|| format!("open {} for append", network_path.display()))?;
        file.write_all(lines.as_bytes()).await?;
    }

    Ok(HarImportResult {
        total_entries,
        api_entries: api_count,
        skipped,
        new_endpoints: 0, // Could be computed by deduping against existing endpoints
    })
}
