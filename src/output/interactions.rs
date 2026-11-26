//! Per-control interaction outcome log (`interactions.jsonl`).
//!
//! One JSON line per control the crawler attempted to exercise *or* decided to
//! skip. This is the raw evidence the UI inventory (`crate::inventory`) is
//! built from: what each button/link/input did when used, what it called, or
//! why it was not exercised. Network requests are joined later from
//! `network.jsonl` by `action_id`, so this log only records what the
//! interaction pass itself observed.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const INTERACTIONS_FILE: &str = "interactions.jsonl";
pub const INTERACTION_RECORD_SCHEMA: &str = "brokenapp.interaction.v1";

/// What the interaction pass observed for one control.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InteractionOutcome {
    /// URL changed (full navigation, pushState, or hash change).
    Navigated,
    /// DOM changed (modal, menu, panel, toast, tab, inline edit...).
    DomChange,
    /// No navigation, no DOM change, no request observed in the page.
    NoEffect,
    /// The click/type itself failed, or the handler threw.
    Error,
    /// The control was not exercised (see `skipped_reason`).
    Skipped,
}

/// One row of `interactions.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InteractionRecord {
    #[serde(default = "default_schema")]
    pub schema: String,
    /// Per-interaction UUID; matches `trace.action_id` / `triggered_by` in
    /// `network.jsonl`. `None` for skipped controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    pub view_id: String,
    /// URL of the page the control was on when exercised (fragment kept).
    pub page_url: String,
    pub selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Element kind slug (`button`, `navigation_link`, `text_input`, ...).
    pub element_kind: String,
    /// `click`, `type`, `select`, `toggle`, `submit`, or `skip`.
    pub action: String,
    pub outcome: InteractionOutcome,
    /// URL after the interaction when it navigated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_url: Option<String>,
    /// Short description of the DOM change (`modal`, `menu`, `panel`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom_change: Option<String>,
    /// In-page fetch/XHR/beacon activity counter observed during the action.
    #[serde(default)]
    pub network_activity: bool,
    /// Console errors / uncaught exceptions raised during the action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub console_errors: Vec<String>,
    /// Runtime error toasts/alerts or WebSocket RPC errors triggered by the action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ui_errors: Vec<String>,
    /// Error message when `outcome == error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why the control was skipped (`interaction_limit`, `view_time_budget`,
    /// `dangerous_label`, `disabled`, `exercised_elsewhere`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
    /// Covering element selector/description when `skipped_reason == Some("obscured")`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obscured_by: Option<String>,
    /// When the control was exercised on another view with the same identity
    /// (shell/header controls), the view where it was exercised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exercised_on: Option<String>,
    /// Native JS dialog raised by the action (`confirm: Delete item?`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_dialog: Option<String>,
    /// The control was already in its active state (aria-pressed/selected/
    /// current, checked, or an `active` class) when clicked, so a no-op is expected.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub already_active: bool,
    /// Effects that are not DOM/network/navigation: `print`, `window_open`,
    /// `clipboard`, `scroll`, `download`, `file_chooser`, `form_validation`,
    /// `focus_moved`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<String>,
    /// Result of re-testing a no-effect control on a freshly loaded view:
    /// `confirmed_no_effect` or `effect_on_retest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retest: Option<String>,
    /// RFC3339 start time of the action.
    pub started_at: String,
    #[serde(default)]
    pub duration_ms: u64,
}

fn default_schema() -> String {
    INTERACTION_RECORD_SCHEMA.to_string()
}

impl InteractionRecord {
    pub fn new(view_id: &str, page_url: &str, selector: &str, element_kind: &str) -> Self {
        Self {
            schema: default_schema(),
            action_id: None,
            view_id: view_id.to_string(),
            page_url: page_url.to_string(),
            selector: selector.to_string(),
            label: None,
            element_kind: element_kind.to_string(),
            action: "click".to_string(),
            outcome: InteractionOutcome::NoEffect,
            after_url: None,
            dom_change: None,
            network_activity: false,
            console_errors: Vec::new(),
            ui_errors: Vec::new(),
            error: None,
            skipped_reason: None,
            obscured_by: None,
            exercised_on: None,
            native_dialog: None,
            already_active: false,
            side_effects: Vec::new(),
            retest: None,
            started_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: 0,
        }
    }
}

/// Append-only, thread-safe writer for `interactions.jsonl`.
pub struct InteractionLog {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl InteractionLog {
    pub fn create(output_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("create {}", output_dir.display()))?;
        let path = output_dir.join(INTERACTIONS_FILE);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, record: &InteractionRecord) -> Result<()> {
        let line = serde_json::to_string(record).context("serialize interaction record")?;
        let mut w = self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("interaction log lock poisoned"))?;
        w.write_all(line.as_bytes())
            .context("write interaction record")?;
        w.write_all(b"\n")
            .context("write interaction record newline")?;
        w.flush().context("flush interaction record")?;
        Ok(())
    }
}

/// Read all records from a scan directory's `interactions.jsonl`.
/// Missing file yields an empty list; malformed lines are skipped.
pub fn read_interactions(scan_dir: &Path) -> Result<Vec<InteractionRecord>> {
    let path = scan_dir.join(INTERACTIONS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("read {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<InteractionRecord>(&line) {
            out.push(rec);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_records() {
        let dir = tempfile::tempdir().unwrap();
        let log = InteractionLog::create(dir.path()).unwrap();
        let mut rec = InteractionRecord::new("view_0001", "http://x/#/a", "#buy", "button");
        rec.action_id = Some("a1".into());
        rec.outcome = InteractionOutcome::DomChange;
        rec.dom_change = Some("modal".into());
        log.append(&rec).unwrap();
        let mut skip = InteractionRecord::new("view_0001", "http://x/#/a", "#more", "button");
        skip.action = "skip".into();
        skip.outcome = InteractionOutcome::Skipped;
        skip.skipped_reason = Some("interaction_limit".into());
        log.append(&skip).unwrap();
        let back = read_interactions(dir.path()).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], rec);
        assert_eq!(back[1].skipped_reason.as_deref(), Some("interaction_limit"));
    }

    #[test]
    fn obscured_by_round_trips_and_omits_when_none() {
        let mut rec = InteractionRecord::new("view_0001", "http://x/", "#btn", "button");
        rec.action = "skip".into();
        rec.outcome = InteractionOutcome::Skipped;
        rec.skipped_reason = Some("obscured".into());
        let plain_json = serde_json::to_string(&rec).unwrap();
        assert!(!plain_json.contains("obscured_by"), "{plain_json}");
        let parsed_plain: InteractionRecord = serde_json::from_str(&plain_json).unwrap();
        assert_eq!(parsed_plain.obscured_by, None);

        rec.obscured_by = Some("div[data-radix-overlay]".into());
        let with_cover_json = serde_json::to_string(&rec).unwrap();
        assert!(
            with_cover_json.contains("\"obscured_by\":\"div[data-radix-overlay]\""),
            "{with_cover_json}"
        );
        let parsed_cover: InteractionRecord = serde_json::from_str(&with_cover_json).unwrap();
        assert_eq!(
            parsed_cover.obscured_by.as_deref(),
            Some("div[data-radix-overlay]")
        );
    }
}
