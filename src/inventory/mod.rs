//! UI inventory: what every route and control in the app does.
//!
//! Built from one scan directory (`spec.json`, `interactions.jsonl`,
//! `network.jsonl`, `coverage-gaps.json`) into a stable, diffable read model.
//! Controls get a stable identity across scans (route template + role + best
//! stable locator + ordinal), so `diff` can report element-level changes:
//! added/removed controls, controls that went dead, controls that now call a
//! different endpoint. Rendered into greppable map files under
//! `<project>/.brokenapp/map/`.
//!
//! Contract: field names and function signatures here are relied on by
//! `crate::front`. Implementations may add fields (with serde defaults) but
//! must not rename or remove existing ones.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::code_link::runtime_source::ResolvedSource;
use crate::route_discovery::DiscoveredRoute;

mod artifacts;
mod build;
mod diff;
pub mod evidence;
pub mod identity;
pub mod journey;
mod merge;
pub mod parity;
pub mod query;
pub mod render;
mod sources;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_attribution;
#[cfg(test)]
mod tests_coverage_reason;
#[cfg(test)]
mod tests_field_fixes;
#[cfg(test)]
mod tests_merge;
#[cfg(test)]
mod tests_state_entries;

pub use merge::{MergeOptions, Merged, merge_incremental};

pub const INVENTORY_SCHEMA: &str = "brokenapp.inventory.v1";

/// Version of the control-identity scheme behind the keys. Maps built with
/// different schemes are not diffed control by control (every key would
/// look added and removed); `diff` reports a re-baseline instead.
/// 1 (or absent): href-keyed links. 2: label + region identity, href is an
/// outcome; same-document anchors; date/number-folded labels.
pub const IDENTITY_VERSION: u32 = 2;

/// Full inventory for one scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Inventory {
    pub schema: String,
    /// Control-identity scheme ([`IDENTITY_VERSION`]); 0 = version 1.
    #[serde(default)]
    pub identity_version: u32,
    pub project: String,
    /// RFC3339 build time.
    pub generated_at: String,
    /// RFC3339 start of the `brokenapp map` run that crawled the app. Files
    /// modified after it are what `map --changed` re-crawls when git is not
    /// available. Absent in maps written before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Absolute path of the scan directory this was built from.
    pub scan_dir: String,
    pub target_url: String,
    /// The login role this map was crawled as (`[[roles]]` name); absent
    /// for the anonymous (logged-out) map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitInfo>,
    /// `block`, `stub`, or `off`.
    pub write_guard: String,
    pub coverage: CoverageSummary,
    pub routes: Vec<RouteEntry>,
    /// Sorted by (route, key). Shell/global controls use route `*`.
    pub controls: Vec<Control>,
    /// Reverse index: endpoint -> controls that call it.
    pub endpoints: Vec<EndpointEntry>,
    /// Per-route provenance once an incremental map (`map --changed`) has
    /// merged a re-crawl into this map: when each route was last crawled and
    /// by which scan. Empty for a whole-app map, whose routes all come from
    /// `scan_dir` at `started_at`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub route_scans: BTreeMap<String, RouteScan>,
    /// Set when this map merged an incremental re-crawl into the previous one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incremental: Option<IncrementalInfo>,
    /// Optional, hash-bound review annotations loaded separately by read commands.
    /// Never persisted into or trusted from the original inventory JSON.
    #[serde(skip)]
    pub evidence_annotations: Option<evidence::RouteEvidenceAnnotations>,
    /// Offline static relinking, with original owners retained separately.
    #[serde(skip)]
    pub source_reviews: Option<evidence::SourceReviews>,
}

/// When and by which scan one route was last crawled.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteScan {
    /// RFC3339 start of the map run that crawled the route.
    pub scanned_at: String,
    /// Scan directory the route's controls come from.
    pub scan_dir: String,
}

/// How an incremental map (`map --changed`) was produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncrementalInfo {
    /// `generated_at` of the map the re-crawl was merged into.
    pub base: String,
    /// Routes re-crawled; their controls, route entries and endpoint rows
    /// were replaced. Every other route is kept from the base map.
    pub routes: Vec<String>,
    /// Changed files (codebase-relative) that selected the routes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_files: Vec<String>,
    /// Routes selected for the re-crawl that the crawl did not reach; kept
    /// from the base map.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kept: Vec<String>,
    /// Routes dropped because the file defining them was deleted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitInfo {
    pub commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default)]
    pub dirty: bool,
}

/// Top covering element responsible for `obscured` skipped interactions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObscuredCover {
    pub cover: String,
    pub count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CoverageSummary {
    /// Routes known from source (route discovery) or links.
    pub routes_known: u32,
    pub routes_visited: u32,
    pub controls_total: u32,
    /// Exercised with a known result (`ok`, `dead`, `no_effect`, `broken`).
    pub controls_exercised: u32,
    /// Controls the crawler could exercise: total minus external links,
    /// disabled controls, and deliberately skipped ones. The fair
    /// denominator for `controls_exercised`.
    #[serde(default)]
    pub controls_exercisable: u32,
    #[serde(default)]
    pub controls_external: u32,
    #[serde(default)]
    pub controls_disabled: u32,
    #[serde(default)]
    pub controls_skipped: u32,
    /// Not-exercised controls by reason (`interaction_limit`, `dangerous_label`, ...).
    #[serde(default)]
    pub not_exercised_by_reason: std::collections::BTreeMap<String, u32>,
    /// Top elements covering controls that were skipped as `obscured`, sorted
    /// descending by count then alphabetically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obscured_top_covers: Vec<ObscuredCover>,
    /// Routes known from source but never reached by the crawler.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unvisited_routes: Vec<String>,
    /// Unvisited routes grouped by why: `redirects to login`, `navigation
    /// timeout`, `not linked or seeded`, ...
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unvisited_by_reason: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RouteEntry {
    /// Route template, e.g. `/`, `/products/:id`, `/#/admin`.
    pub route: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub visited: bool,
    /// HTTP status of the document when visited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Source file defining the route (from route discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Number of controls on the route (excluding global ones).
    pub controls: u32,
    /// Visited, but no route found in source matches it (an SPA "soft 404"
    /// or a page discovery could not see).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub not_in_source: bool,
    /// Why an unvisited route was not reached (`redirects to login`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unvisited_reason: Option<String>,
    /// Page variants visited: the query string (`?tab=history`) or, for
    /// dynamic routes, the concrete path (`/devices/3567?tab=x`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<String>,
}

/// Health of one control.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    /// Exercised and did something observable.
    Ok,
    /// Exercised; nothing happened (no navigation, request, or DOM change)
    /// and no handler evidence: high-confidence dead UI.
    Dead,
    /// Exercised; a handler exists (or the control was already active) but no
    /// observable effect: review it (already-selected filter, refresh with
    /// identical data, print/clipboard stubs are common benign causes).
    NoEffect,
    /// Exercised; errored (handler exception, 4xx/5xx, failed click) or a
    /// link to a missing page.
    Broken,
    /// Disabled when seen.
    Disabled,
    /// Points off-site; not followed.
    External,
    /// Deliberately not exercised (dangerous label, logout, file input...).
    Skipped,
    /// Not exercised because of budgets/coverage limits.
    #[default]
    NotExercised,
}

/// One observable effect of using a control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outcome {
    /// Navigates to a route (template) or same-origin URL.
    Navigates { to: String },
    /// Fires a request. `endpoint` is `METHOD /path/template` (host-prefixed
    /// when cross-origin). `blocked` = stopped by the write guard.
    Calls {
        endpoint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        #[serde(default)]
        blocked: bool,
    },
    /// Changes the page without navigating (`modal`, `menu`, `panel`, `toast`, `other`).
    DomChange { kind: String },
    /// Opens a native dialog (alert/confirm/prompt).
    Dialog { message: String },
    /// Starts a download.
    Download,
    /// Links off-site.
    External { url: String },
    /// Raised an error.
    Error { message: String },
    /// Same-document link: scrolls to `#fragment`, no navigation.
    Anchor { fragment: String },
    /// An effect outside the DOM/network: `print`, `window_open`,
    /// `clipboard`, `scroll`, `focus_moved`.
    SideEffect { kind: String },
}

/// One observed way to enter a control's state. Entries are alternatives,
/// not a cross-product of variants and openers. An absent list is legacy
/// provenance, not proof of an unrestricted initial-page observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControlStateEntry {
    /// Actual route context, including for controls promoted to `*`.
    pub route: String,
    /// Concrete record/query state; `None` means the plain route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(flatten)]
    pub kind: ControlStateEntryKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlStateEntryKind {
    /// Observed on the top-level page as loaded in this route/variant.
    Direct,
    /// Observed after this control opened a sub-view in this route/variant.
    Opened { opener: String },
    /// The page context or entry control could not be established.
    Unknown,
}

/// One UI control (button, link, input, select, ...), possibly grouped.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Control {
    /// Stable identity across scans: `<route>|<role>|<locator>[#n]`.
    pub key: String,
    /// Route template, or `*` for shell/global controls present on most routes.
    pub route: String,
    /// All routes the control appears on (for global/shared controls).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    /// `button`, `link`, `input`, `select`, `checkbox`, `form`, `tab`, `other`.
    pub role: String,
    pub label: String,
    /// Distinct labels of the grouped instances when they differ (searched
    /// by `ui --text` and `journey label:`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Page region: `header`, `nav`, `main`, `aside`, `footer`, `dialog`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// Link target signature (`/route`, `/route#frag`, `#frag`, off-site URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Keys of the controls whose interaction opened the sub-view (modal,
    /// panel, wizard step) this control was seen in. Empty when it is on the
    /// page as loaded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub opened_by: Vec<String>,
    /// Page variants (see [`RouteEntry::variants`]) the control was seen on,
    /// when it is specific to some of them (an expanded row, one record).
    /// Empty when it shows on every visited variant of its route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<String>,
    /// Observed state-entry alternatives. When present, these preserve the
    /// pairing lost by the legacy `variants` and `opened_by` summaries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_entries: Vec<ControlStateEntry>,
    /// Sample CSS selector (scan-local, not stable).
    pub selector: String,
    /// The stable locator used in `key` (`testid=…`, `id=…`, `aria=…`, `text=…`).
    pub locator: String,
    /// Identical controls grouped into this row (e.g. 16 "Add to cart").
    pub count: u32,
    pub status: ControlStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<Outcome>,
    /// Not-exercised/skip reason or error detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ResolvedSource>,
}

/// Reverse index entry: which controls call an endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EndpointEntry {
    /// `METHOD /path/template` (host-prefixed when cross-origin).
    pub endpoint: String,
    /// Control keys that call it.
    pub controls: Vec<String>,
    /// Routes where it is called on page load (not by a control).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub on_load: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<u16>,
    /// At least one call was stopped by the write guard.
    #[serde(default)]
    pub write: bool,
}

/// Options for [`build_from_scan_dir`].
#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    pub project: String,
    pub target_url: String,
    /// Codebase root for source linking and git info.
    pub codebase: Option<PathBuf>,
    /// Routes found in source (from `route_discovery`), used for coverage
    /// and route source files.
    pub discovered_routes: Vec<DiscoveredRoute>,
    /// Route prefixes omitted from coverage, including linked but unvisited
    /// targets. Their visible link controls remain explicitly skipped.
    pub exclude_routes: Vec<String>,
    /// Probe same-origin link targets with GET to detect dead links (dev server must be up).
    pub check_links: bool,
    /// Resolve element source locations (dev server must be up for runtime frames).
    pub resolve_sources: bool,
    pub write_guard: String,
    /// Keep shell controls on their routes instead of promoting the ones on
    /// most routes to `*`. An incremental re-crawl covers a few routes, so
    /// "most routes" is decided by the map it is merged into.
    pub keep_route_scope: bool,
    /// Concrete routes kept distinct from `:param` templates, instead of the
    /// run's `seed-routes.txt`. An incremental re-crawl seeds only a few
    /// routes but must name routes the way the whole-app map did.
    pub concrete_routes: Option<Vec<String>>,
}

/// Build the inventory for one scan directory.
///
/// Needs `spec.json`; `interactions.jsonl`, `network.jsonl`,
/// `coverage-gaps.json` and `bugs.json` are used when present (older scans
/// without `interactions.jsonl` fall back to transitions, snapshots, endpoint
/// triggers and dead-button findings).
pub async fn build_from_scan_dir(scan_dir: &Path, opts: &BuildOptions) -> Result<Inventory> {
    build::build(scan_dir, opts)
        .await
        .with_context(|| format!("build inventory from {}", scan_dir.display()))
}

pub fn load(path: &Path) -> Result<Inventory> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

pub fn save(inv: &Inventory, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(inv).context("serialize inventory")?;
    std::fs::write(path, raw).with_context(|| format!("write {}", path.display()))
}

/// One element-level change between two inventories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Change {
    /// `added`, `removed`, `now_dead`, `now_broken`, `fixed`, `rewired`
    /// (calls/navigation changed), `relabeled`, `moved` (source moved),
    /// `route_added`, `route_removed`, `endpoint_added`, `endpoint_removed`.
    pub kind: String,
    pub key: String,
    pub route: String,
    pub label: String,
    /// One human line, e.g. `NOW DEAD /checkout "Pay" (was calls POST /api/pay)`.
    pub line: String,
    /// Every route when the same change happened on several (one line for a
    /// shared component); `route` / `key` are then the first of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ChangeSet {
    /// `generated_at` / git commit of the previous inventory, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    pub to: String,
    pub changes: Vec<Change>,
    /// Count per change kind, plus the buckets that are *not* changes:
    /// `not_observed` (in the previous map, but its route or state was not
    /// reached this time, or it was never exercised), `newly_observed` (the
    /// reverse), and `shifted` (source lines moved by edits above them).
    #[serde(default)]
    pub summary: std::collections::BTreeMap<String, u32>,
    /// Human notes about what the diff left out and why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// `route role "label" (why)` for each control in the `not_observed` bucket.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_observed: Vec<String>,
}

/// Summary buckets that are not element-level changes.
pub const NON_CHANGE_BUCKETS: &[&str] = &["not_observed", "newly_observed", "shifted"];

/// Stable display/diff form of an endpoint key: Next.js Server Action ids
/// (`POST /cart#action:7f3a…`) change between builds, so they render and
/// diff as `POST /cart [server action]`.
pub fn stable_endpoint(key: &str) -> String {
    match key.split_once("#action:") {
        Some((head, _)) => format!("{head} [server action]"),
        None => key.to_string(),
    }
}

/// Element-level diff. `prev = None` means first scan (everything added is
/// summarized, not listed per control).
pub fn diff(prev: Option<&Inventory>, cur: &Inventory) -> ChangeSet {
    diff::diff(prev, cur)
}

/// Write greppable map files into `map_dir` (UI-MAP.md, ui-map.tsv,
/// endpoints.tsv, DEAD-UI.md). Returns the files written.
pub fn write_map(inv: &Inventory, map_dir: &Path) -> Result<Vec<PathBuf>> {
    render::write_map(inv, map_dir)
}

/// Append a dated entry for `changes` to `CHANGELOG.md` (newest first).
/// Scans with no element-level changes add nothing.
pub fn append_changelog(changes: &ChangeSet, cur: &Inventory, path: &Path) -> Result<()> {
    render::append_changelog(changes, cur, path)
}

impl ControlStatus {
    pub const ALL: [ControlStatus; 8] = [
        ControlStatus::Ok,
        ControlStatus::Dead,
        ControlStatus::NoEffect,
        ControlStatus::Broken,
        ControlStatus::Disabled,
        ControlStatus::External,
        ControlStatus::Skipped,
        ControlStatus::NotExercised,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            ControlStatus::Ok => "ok",
            ControlStatus::Dead => "dead",
            ControlStatus::NoEffect => "no_effect",
            ControlStatus::Broken => "broken",
            ControlStatus::Disabled => "disabled",
            ControlStatus::External => "external",
            ControlStatus::Skipped => "skipped",
            ControlStatus::NotExercised => "not_exercised",
        }
    }

    /// Parse `ok`, `dead`, `not-exercised`, ... (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        let norm = s.trim().to_ascii_lowercase().replace(['-', ' '], "_");
        Self::ALL.into_iter().find(|st| st.as_str() == norm)
    }

    /// Exercised by the crawler (or link probe) with a known result.
    pub fn is_exercised(&self) -> bool {
        matches!(
            self,
            ControlStatus::Ok
                | ControlStatus::Dead
                | ControlStatus::NoEffect
                | ControlStatus::Broken
        )
    }
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Inventory {
    /// When the map run behind this inventory started: `started_at`, else
    /// the run directory's timestamp (`scans/<YYYYmmddTHHMMSSZ>/scan`), else
    /// `generated_at`.
    pub fn run_started_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        let rfc = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc))
        };
        if let Some(at) = self.started_at.as_deref().and_then(rfc) {
            return Some(at);
        }
        let run_dir = Path::new(&self.scan_dir)
            .parent()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy().into_owned());
        if let Some(at) = run_dir.and_then(|name| {
            let stamp = name.split('-').next().unwrap_or(&name).to_string();
            chrono::NaiveDateTime::parse_from_str(&stamp, "%Y%m%dT%H%M%SZ")
                .ok()
                .map(|n| n.and_utc())
        }) {
            return Some(at);
        }
        rfc(&self.generated_at)
    }
}

impl Control {
    /// Endpoints this control calls.
    pub fn endpoints(&self) -> impl Iterator<Item = &str> {
        self.outcomes.iter().filter_map(|o| match o {
            Outcome::Calls { endpoint, .. } => Some(endpoint.as_str()),
            _ => None,
        })
    }

    /// Routes this control navigates to.
    pub fn navigates_to(&self) -> impl Iterator<Item = &str> {
        self.outcomes.iter().filter_map(|o| match o {
            Outcome::Navigates { to } => Some(to.as_str()),
            _ => None,
        })
    }

    /// Routes the control is present on (`routes` for shell controls).
    pub fn present_on(&self) -> Vec<&str> {
        if self.routes.is_empty() {
            vec![self.route.as_str()]
        } else {
            self.routes.iter().map(String::as_str).collect()
        }
    }

    /// Does `needle` (lowercase) occur in the label or any member label?
    pub fn label_contains(&self, needle: &str) -> bool {
        self.label.to_lowercase().contains(needle)
            || self
                .labels
                .iter()
                .any(|l| l.to_lowercase().contains(needle))
    }

    /// Human handle: label, else locator value, else `(no label) <selector tail>`.
    pub fn display_label(&self) -> String {
        if !self.label.trim().is_empty() {
            return self.label.clone();
        }
        match self.locator.split_once('=') {
            Some((_, v)) if !v.is_empty() => v.to_string(),
            _ => {
                let n = self.selector.chars().count();
                let tail: String = if n > 60 {
                    let rest: String = self.selector.chars().skip(n - 59).collect();
                    format!("…{rest}")
                } else {
                    self.selector.clone()
                };
                format!("(no label) {tail}")
            }
        }
    }
}
