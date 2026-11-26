//! Build an [`Inventory`] from one scan directory.
//!
//! Pipeline: one *instance* per element per view (plus controls that only
//! appear in `interactions.jsonl`) -> attach evidence (interaction records,
//! attributed requests, and for older scans transitions / snapshots /
//! dead-button findings / coverage gaps) -> group identical instances into
//! controls -> promote shell controls to route `*` -> apply the status rules.
//!
//! Identity: a control is (route, page region, role, label-based locator).
//! A link's href is what it *does*; instances are only grouped when their
//! targets agree too, and same-labelled links with different targets on one
//! route get the target in their key (`text=learn more->/pricing`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use regex::Regex;
use url::Url;

use super::artifacts::{self, NetRow, ScanArtifacts};
use super::identity::{
    MAIN_REGION, RouteCanon, SHELL_REGIONS, choose_locator, is_error_page, is_generated_id,
    is_input_role, is_page_kind, landmark_region, locator_attr, normalize_text, region_of,
    role_for_element, role_for_kind_slug, route_template, tag_from_selector,
};
use super::sources;
use super::{
    BuildOptions, Control, ControlStateEntry, ControlStateEntryKind, ControlStatus,
    CoverageSummary, EndpointEntry, IDENTITY_VERSION, INVENTORY_SCHEMA, Inventory, ObscuredCover,
    Outcome, RouteEntry, stable_endpoint,
};
use crate::code_link::runtime_source::ResolvedSource;
use crate::explorer::url_utils::effective_url_path_and_query;
use crate::network::filters::{
    endpoint_template_path, is_background_heartbeat_or_poll_path, looks_like_static_asset_path,
};
use crate::network::path_parameterizer::path_to_template;
use crate::output::interactions::{InteractionOutcome, InteractionRecord};
use crate::route_discovery::DiscoveredRoute;
use crate::types::dom::{
    ElementSourceCapture, ElementType, InteractionSnapshot, InteractiveElement, LocatorKind,
};

/// Fraction of visited routes a control must appear on to become global.
const GLOBAL_MIN_SHARE: f64 = 0.6;
const GLOBAL_MIN_ROUTES: usize = 3;
/// Link probe limits.
const PROBE_MAX_URLS: usize = 200;
const PROBE_CONCURRENCY: usize = 8;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Requests attributed by `(view, selector)` must land near the control's
/// interaction records (guards against stale attribution of background polls).
const ACTION_WINDOW_SLACK_MS: i64 = 5_000;
/// Distinct member labels kept per grouped control.
const MAX_MEMBER_LABELS: usize = 50;
/// Page variants kept per route / per control.
const MAX_ROUTE_VARIANTS: usize = 50;
/// Path probed to learn whether the server answers unknown paths with 2xx
/// (an SPA fallback), in which case HTTP status cannot reveal missing routes.
const UNKNOWN_ROUTE_PROBE_PATH: &str = "/__brokenapp-route-check-7d1e";

/// Third-party telemetry that clicks often fire; not what a control "does".
const TELEMETRY_HOSTS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "analytics.google.com",
    "csp.withgoogle.com",
    "segment.io",
    "segment.com",
    "sentry.io",
    "mixpanel.com",
    "hotjar.com",
    "plausible.io",
    "posthog.com",
    "clarity.ms",
    "facebook.com",
    "datadoghq.com",
    "nr-data.net",
    "intercom.io",
    "vercel-insights.com",
];

/// Dev-server and bundler endpoints (HMR, overlays, module serving). They
/// are tooling, not what a control does, and never app endpoints.
const DEV_TOOL_PREFIXES: &[&str] = &[
    "/__nextjs",
    "/_next/",
    "/__vite",
    "/@vite/",
    "/@fs/",
    "/@id/",
    "/@react-refresh",
    "/__webpack_hmr",
    "/_astro/",
    "/__astro",
    "/__wrangler",
    "/__turbopack",
    "/__open-in-editor",
    "/_nuxt/",
    "/__nuxt",
    "/node_modules/.vite/",
];

/// Link-probe results, keyed by URL without fragment.
#[derive(Debug, Clone, Default)]
pub(super) struct ProbeTable {
    pub results: BTreeMap<String, ProbeResult>,
    /// `Some(true)`: the server answers a made-up path with 2xx (SPA
    /// fallback), so a 2xx says nothing about whether a route exists.
    /// `Some(false)`: unknown paths get 404. `None`: not probed.
    pub soft_404: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProbeResult {
    pub status: u16,
    /// Final URL when the request was redirected.
    pub landed: Option<String>,
}

pub(super) async fn build(scan_dir: &Path, opts: &BuildOptions) -> Result<Inventory> {
    build_with(scan_dir, opts, None).await
}

/// [`build`] with a fixed link-probe table instead of live probing (offline
/// evaluation against recorded field scans).
pub(super) async fn build_with(
    scan_dir: &Path,
    opts: &BuildOptions,
    probe_override: Option<ProbeTable>,
) -> Result<Inventory> {
    let art = artifacts::load(scan_dir)?;
    let target_url = if opts.target_url.trim().is_empty() {
        art.target_url.clone()
    } else {
        opts.target_url.clone()
    };
    let base = Url::parse(&target_url).ok();
    let mut canon = RouteCanon::new(&opts.discovered_routes);
    match &opts.concrete_routes {
        Some(routes) => canon.add_concrete(routes),
        None => canon.add_concrete(&read_seed_routes(scan_dir)),
    }
    let api = ApiPatterns::new(&opts.discovered_routes);

    let mut b = Builder::new(&art, base.clone(), canon, api);
    b.index_documents();
    b.collect_spec_instances();
    if art.has_interactions {
        b.attach_interactions();
    }
    b.attach_network();
    if !art.has_interactions {
        b.attach_legacy_evidence();
    }
    b.attach_gaps();
    b.index_openers();

    let mut groups = b.group_instances();
    let visited: BTreeSet<String> = b.visited_routes();
    if !opts.keep_route_scope {
        promote_globals(&mut groups, &b, &visited);
    }
    assign_keys(&mut groups);
    let merged: Vec<Evidence> = groups
        .iter()
        .map(|g| merge_evidence(g, &b.instances))
        .collect();
    let inherited = inherit_exercised_elsewhere(&groups, &merged, &b);
    let opened_by = opener_keys(&groups, &b);
    let state_entries = observed_state_entries(&groups, &b);

    let probe = match probe_override {
        Some(p) => p,
        None if opts.check_links && opts.exclude_routes.is_empty() => {
            probe_links(&groups, &b, &merged).await
        }
        None => ProbeTable::default(),
    };

    let route_variants = b.route_variants();
    let mut controls = Vec::with_capacity(groups.len());
    let mut control_groups: HashMap<String, usize> = HashMap::new();
    for (gi, g) in groups.iter().enumerate() {
        let ev = inherited.get(&gi).map(|(ev, _)| ev).unwrap_or(&merged[gi]);
        let via = inherited.get(&gi).map(|(_, route)| route.as_str());
        let Some(mut control) = finalize_control(
            g,
            ev,
            via,
            &b,
            &visited,
            &route_variants,
            &probe,
            art.has_interactions,
        ) else {
            continue;
        };
        // Unlabeled generic elements nobody exercised are decorative noise
        // (layout divs with pointer cursors), not controls.
        if control.role == "other" && control.label.is_empty() && !control.status.is_exercised() {
            continue;
        }
        control.opened_by = opened_by.get(&gi).cloned().unwrap_or_default();
        control.state_entries = state_entries.get(&gi).cloned().unwrap_or_default();
        control
            .state_entries
            .retain(|entry| !crate::scope::route_is_excluded(&entry.route, &opts.exclude_routes));
        if crate::scope::route_is_excluded(&control.route, &opts.exclude_routes) {
            continue;
        }
        if control.route == "*" {
            control
                .routes
                .retain(|r| !crate::scope::route_is_excluded(r, &opts.exclude_routes));
            if control.routes.is_empty() {
                continue;
            }
        }
        if control.role == "link"
            && g.members.iter().any(|idx| {
                matches!(&b.instances[*idx].link, Some(LinkTarget::Internal { url, .. })
                if crate::scope::route_is_excluded(url, &opts.exclude_routes))
            })
        {
            control.status = ControlStatus::Skipped;
            control.reason = Some("route_excluded".to_string());
        }
        control_groups.insert(control.key.clone(), gi);
        controls.push(control);
    }
    controls.sort_by(|a, c| a.route.cmp(&c.route).then_with(|| a.key.cmp(&c.key)));

    let endpoints = b.endpoint_index(&controls);
    let routes: Vec<RouteEntry> = b
        .route_entries(&controls, &visited, &opts.discovered_routes)
        .into_iter()
        .filter(|r| !crate::scope::route_is_excluded(&r.route, &opts.exclude_routes))
        .collect();
    if opts.resolve_sources
        && let Some(codebase) = opts.codebase.as_deref()
    {
        let route_files: HashMap<&str, &str> = routes
            .iter()
            .filter_map(|r| r.source.as_deref().map(|s| (r.route.as_str(), s)))
            .collect();
        let resolved =
            resolve_control_sources(&target_url, codebase, &groups, &b, &controls, &route_files)
                .await;
        for c in &mut controls {
            if let Some(src) = resolved.get(&c.key) {
                c.source = Some(src.clone());
            }
        }
        let frames = sources::resolve_error_frames(
            &target_url,
            codebase,
            &error_frames(&controls, base.as_ref()),
        )
        .await;
        for c in &mut controls {
            rewrite_error_locations(c, base.as_ref(), &frames);
        }
    } else {
        for c in &mut controls {
            rewrite_error_locations(c, base.as_ref(), &BTreeMap::new());
        }
    }
    for c in &mut controls {
        // A resolved event handler is handler evidence too.
        if c.status == ControlStatus::Dead
            && c.source.as_ref().is_some_and(|s| s.handler.is_some())
            && !c.reason.as_deref().is_some_and(is_detector_reason)
        {
            c.status = ControlStatus::NoEffect;
            c.reason = Some(HANDLER_NO_EFFECT.to_string());
        }
        if let Some(gi) = control_groups.get(&c.key) {
            downgrade_shared_source(c, &groups[*gi], &b);
        }
    }
    let mut coverage = coverage_summary(&routes, &controls);
    coverage.obscured_top_covers = b.obscured_top_covers(&opts.exclude_routes);

    let write_guard = if opts.write_guard.trim().is_empty() {
        detect_write_guard(&art.network)
    } else {
        opts.write_guard.clone()
    };
    let project = if opts.project.trim().is_empty() {
        base.as_ref()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| "app".to_string())
    } else {
        opts.project.clone()
    };

    Ok(Inventory {
        schema: INVENTORY_SCHEMA.to_string(),
        identity_version: IDENTITY_VERSION,
        project,
        generated_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        started_at: None,
        scan_dir: scan_dir
            .canonicalize()
            .unwrap_or_else(|_| scan_dir.to_path_buf())
            .display()
            .to_string(),
        target_url,
        role: None,
        git: opts.codebase.as_deref().and_then(sources::git_info),
        write_guard,
        coverage,
        routes,
        controls,
        endpoints,
        route_scans: BTreeMap::new(),
        incremental: None,
        evidence_annotations: None,
        source_reviews: None,
    })
}

/// Concrete routes the crawl was seeded with: `brokenapp map` writes
/// `seed-routes.txt` next to the scan directory.
fn read_seed_routes(scan_dir: &Path) -> Vec<String> {
    let Some(file) = scan_dir.parent().map(|p| p.join("seed-routes.txt")) else {
        return Vec::new();
    };
    std::fs::read_to_string(file)
        .map(|body| {
            body.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Reason for a control with handler evidence but no observable effect.
pub(super) const HANDLER_NO_EFFECT: &str = "handler attached";

fn is_detector_reason(r: &str) -> bool {
    r.starts_with("flagged by")
}

// ---------------------------------------------------------------------------
// Instances and evidence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum LinkTarget {
    /// Same-origin target in another document: route template, absolute URL,
    /// and the identity signature (`/route` or `/route#frag`).
    Internal {
        route: String,
        url: String,
        sig: String,
    },
    /// Off-site (`https://other`, `mailto:`...).
    External(String),
    /// Same-document anchor (`#reviews`): scrolls, never navigates.
    Anchor { fragment: String, sig: String },
}

impl LinkTarget {
    /// What makes two links with the same label the same control.
    fn signature(&self) -> String {
        match self {
            LinkTarget::Internal { sig, .. } | LinkTarget::Anchor { sig, .. } => sig.clone(),
            LinkTarget::External(u) => u.clone(),
        }
    }
}

fn same_record_page(a: &str, b: &str) -> bool {
    Url::parse(a)
        .ok()
        .zip(Url::parse(b).ok())
        .is_some_and(|(a, b)| a == b)
}

/// None means an unresolved target, distinct from a control without an href.
/// Do not template entity IDs, strip query/fragment, decode or sort query pairs.
fn resolved_record_href(href: Option<&str>, page_url: &str) -> Option<Option<String>> {
    match href {
        None => Some(None),
        Some(href) => Some(Some(
            Url::parse(page_url)
                .ok()?
                .join(href.trim())
                .ok()?
                .to_string(),
        )),
    }
}

#[derive(Debug, Clone, Default)]
struct CallAgg {
    status: Option<u16>,
    blocked: bool,
}

#[derive(Debug, Clone, Default)]
struct Evidence {
    exercised: bool,
    /// Effect outcomes except calls (merged separately).
    outcomes: BTreeSet<Outcome>,
    calls: BTreeMap<String, CallAgg>,
    /// Reasons the control is broken (app-side).
    errors: Vec<String>,
    network_activity: bool,
    skip: Option<String>,
    /// View where an identical control was exercised instead.
    elsewhere: Option<String>,
    /// Older scans: the dead-button detector flagged it.
    dead_hint: bool,
    /// The control was already in its active state when clicked.
    already_active: bool,
    /// Tool-side failures (`interaction_timeout`): not app errors.
    tool_errors: Vec<String>,
    /// A re-test on a fresh view confirmed / contradicted "no effect", or
    /// reported something else.
    retest_confirmed: bool,
    retest_effect: bool,
    retest_other: bool,
    /// Event-handler props or handler frames were captured for it.
    handler: bool,
    /// Group level only: members exercised, those that showed no effect, and
    /// those that only hit tool-side failures.
    exercised_members: u32,
    no_effect_members: u32,
    tool_error_members: u32,
}

impl Evidence {
    fn has_effect(&self) -> bool {
        !self.calls.is_empty()
            || self.outcomes.iter().any(|o| {
                matches!(
                    o,
                    Outcome::Navigates { .. }
                        | Outcome::DomChange { .. }
                        | Outcome::Dialog { .. }
                        | Outcome::Download
                        | Outcome::External { .. }
                        | Outcome::Anchor { .. }
                        | Outcome::SideEffect { .. }
                )
            })
    }

    fn add_call(&mut self, endpoint: String, status: Option<u16>, blocked: bool) {
        let agg = self.calls.entry(endpoint).or_default();
        agg.blocked |= blocked;
        if let Some(s) = status {
            agg.status = Some(agg.status.map_or(s, |cur| cur.max(s)));
        }
    }

    fn add_error(&mut self, msg: String) {
        if !self.errors.contains(&msg) {
            self.errors.push(msg);
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Hints {
    tag: String,
    aria: Option<String>,
    test_id: Option<String>,
    element_id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Clone)]
struct Instance {
    view_id: String,
    /// (view order, element order) for deterministic picks and ordinals.
    order: (usize, usize),
    route: String,
    role: &'static str,
    label: String,
    selector: String,
    locator: String,
    region: &'static str,
    /// A landmark was visible in the element's ancestor path; otherwise the
    /// region is `main` by default (the path may be truncated).
    region_known: bool,
    /// Ancestor path (structural locator), for recognizing layout elements.
    structural: Option<String>,
    needs_ordinal: bool,
    ordinal: Option<usize>,
    href: Option<String>,
    link: Option<LinkTarget>,
    disabled: bool,
    /// Submit button in a form with empty required fields.
    validation_pending: bool,
    capture: Option<ElementSourceCapture>,
    /// Seen in a sub-view (a state reached by an interaction: modal, panel,
    /// wizard step), not on the page as loaded.
    sub_view: bool,
    /// Page variant of the view (query string, or concrete path of a
    /// dynamic route); `None` for the plain route.
    variant: Option<String>,
    /// Actual page URLs retained when raw view IDs attach to an aggregated
    /// spec instance through the route/selector fallback.
    record_variants: BTreeSet<Option<String>>,
    page_url: String,
    /// An explicit spec URL or a raw record establishes this page's presence;
    /// an aggregated route-only spec may instead be a metadata placeholder.
    page_presence_known: bool,
    hints: Hints,
    ev: Evidence,
}

/// API route patterns from source, used to template endpoint paths
/// (`/api/availability/item-slug` -> `/api/availability/:slug`).
#[derive(Debug, Default)]
struct ApiPatterns {
    patterns: Vec<(Vec<String>, String)>,
}

impl ApiPatterns {
    fn new(discovered: &[DiscoveredRoute]) -> Self {
        let mut patterns: Vec<(Vec<String>, String)> = discovered
            .iter()
            .filter(|r| !is_page_kind(&r.kind) || !r.methods.is_empty())
            .filter(|r| r.path.contains(':') || r.path.contains('['))
            .map(|r| {
                let segs: Vec<String> = r
                    .path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                (segs, r.path.clone())
            })
            // A pattern needs a literal segment to anchor on.
            .filter(|(segs, _)| segs.iter().any(|s| !is_param(s)))
            .collect();
        // Most literal segments first: the most specific pattern wins.
        patterns.sort_by(|a, b| {
            let lit = |p: &Vec<String>| p.iter().filter(|s| !is_param(s)).count();
            lit(&b.0).cmp(&lit(&a.0)).then_with(|| a.1.cmp(&b.1))
        });
        patterns.dedup_by(|a, b| a.1 == b.1);
        Self { patterns }
    }

    /// Template a same-origin endpoint key's path with a matching pattern.
    fn template(&self, key: &str) -> String {
        let Some((method, path)) = key.split_once(' ') else {
            return key.to_string();
        };
        if !path.starts_with('/') || path.contains('#') || path.contains(' ') {
            return key.to_string();
        }
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        for (pattern, template) in &self.patterns {
            if pattern.len() == segs.len()
                && pattern
                    .iter()
                    .zip(segs.iter())
                    .all(|(p, s)| is_param(p) || p == s)
            {
                return format!("{method} {template}");
            }
        }
        key.to_string()
    }
}

fn is_param(seg: &str) -> bool {
    seg.starts_with(':') || seg.starts_with('[') || seg.starts_with('*')
}

struct InteractionNetActivity {
    instance_idx: usize,
    action_id: Option<String>,
    view_id: String,
    selector: String,
    window: Option<(i64, i64)>,
    saw_poll: bool,
    saw_non_poll: bool,
}

struct Builder<'a> {
    art: &'a ScanArtifacts,
    base: Option<Url>,
    canon: RouteCanon,
    api: ApiPatterns,
    instances: Vec<Instance>,
    by_view_sel: HashMap<(String, String), Vec<usize>>,
    by_route_sel: HashMap<(String, String), Vec<usize>>,
    view_routes: HashMap<String, String>,
    view_urls: HashMap<String, String>,
    view_order: HashMap<String, usize>,
    /// Views whose document came back 404/410: error pages, not routes.
    error_views: HashSet<String>,
    /// action_id -> instance.
    actions: HashMap<String, usize>,
    /// (view, selector) -> (matched instance, start ms, end ms) per action.
    /// A selector can name different controls after the DOM changes.
    action_windows: HashMap<(String, String), Vec<(usize, i64, i64)>>,
    /// Route -> lowest document status seen by the crawler (non-hash routes).
    doc_status: BTreeMap<String, u16>,
    /// URL (no fragment) -> document status.
    doc_by_url: HashMap<String, u16>,
    /// URL (no fragment) -> where its redirect landed.
    doc_redirect: HashMap<String, String>,
    /// Endpoint -> routes where it was called on page load.
    on_load: BTreeMap<String, BTreeSet<String>>,
    /// Endpoint -> statuses observed anywhere.
    endpoint_statuses: BTreeMap<String, BTreeSet<u16>>,
    /// Endpoints hit by a write-guarded request.
    endpoint_guarded: BTreeSet<String>,
    /// Requests attributed to a control we could not find.
    unattributed: BTreeSet<String>,
    /// Routes reported unvisited by route-level coverage gaps, with why.
    gap_routes: BTreeMap<String, Option<String>>,
    /// Sub-view id -> instances whose interaction opened it.
    openers: HashMap<String, Vec<usize>>,
    /// Interaction records that reported `network_activity = true`, used to
    /// clear spurious `ev.network_activity` when every network row attributed
    /// to that interaction turned out to be a suppressed background poll.
    net_activity_records: Vec<InteractionNetActivity>,
}

impl<'a> Builder<'a> {
    fn new(art: &'a ScanArtifacts, base: Option<Url>, canon: RouteCanon, api: ApiPatterns) -> Self {
        for v in &art.views {
            if let Some((before, frag)) = v.route.split_once('#') {
                let base_path = before.split_once('?').map_or(before, |(p, _)| p).trim();
                if matches!(base_path, "" | "/" | "/index.html") {
                    crate::explorer::url_utils::register_route_fragment(frag);
                }
            }
            if let Some(url) = v.url.as_deref()
                && v.route.starts_with("/#")
            {
                crate::explorer::url_utils::register_route_fragment_from_url(url);
            }
        }
        for rec in &art.interactions {
            let scroll_only = rec.side_effects.iter().any(|s| s == "scroll")
                && rec.dom_change.is_none()
                && !rec.network_activity;
            if rec.outcome == InteractionOutcome::Navigated
                && rec.element_kind != "navigation_link"
                && !scroll_only
                && let Some(after) = rec.after_url.as_deref()
            {
                crate::explorer::url_utils::register_route_fragment_from_url(after);
            }
        }
        Self {
            art,
            base,
            canon,
            api,
            instances: Vec::new(),
            by_view_sel: HashMap::new(),
            by_route_sel: HashMap::new(),
            view_routes: HashMap::new(),
            view_urls: HashMap::new(),
            view_order: HashMap::new(),
            error_views: HashSet::new(),
            actions: HashMap::new(),
            action_windows: HashMap::new(),
            doc_status: BTreeMap::new(),
            doc_by_url: HashMap::new(),
            doc_redirect: HashMap::new(),
            on_load: BTreeMap::new(),
            endpoint_statuses: BTreeMap::new(),
            endpoint_guarded: BTreeSet::new(),
            unattributed: BTreeSet::new(),
            gap_routes: BTreeMap::new(),
            openers: HashMap::new(),
            net_activity_records: Vec::new(),
        }
    }

    fn route_of(&self, raw: &str) -> String {
        self.canon.route(raw)
    }

    fn absolute(&self, route_or_url: &str) -> String {
        if Url::parse(route_or_url).is_ok() {
            return route_or_url.to_string();
        }
        self.base
            .as_ref()
            .and_then(|b| b.join(route_or_url).ok())
            .map(|u| u.to_string())
            .unwrap_or_else(|| route_or_url.to_string())
    }

    fn internal(&self, url: &Url) -> bool {
        self.base.as_ref().is_some_and(|b| same_origin(b, url))
    }

    /// Document statuses and redirect landings, before anything else: error
    /// pages are dropped from the views.
    fn index_documents(&mut self) {
        let art = self.art;
        let mut chain_last: HashMap<&str, &str> = HashMap::new();
        let mut chain_first: HashMap<&str, Vec<&str>> = HashMap::new();
        for row in &art.network {
            if !(row.is_document && row.method == "GET" && !row.is_guarded()) {
                continue;
            }
            let Ok(url) = Url::parse(&row.url) else {
                continue;
            };
            if !self.internal(&url) || looks_like_static_asset_path(url.path()) {
                continue;
            }
            let key = strip_fragment(url.as_str());
            if let Some(status) = row.status {
                let route = self.route_of(url.as_str());
                let e = self.doc_status.entry(route).or_insert(status);
                *e = (*e).min(status);
                self.doc_by_url.insert(key.clone(), status);
                if (300..400).contains(&status)
                    && let Some(loc) = row.location.as_deref()
                    && let Ok(landed) = url.join(loc)
                {
                    self.doc_redirect
                        .insert(key.clone(), strip_fragment(landed.as_str()));
                }
            }
            if let Some(id) = row.request_id.as_deref() {
                chain_first.entry(id).or_default().push(row.url.as_str());
                chain_last.insert(id, row.url.as_str());
            }
        }
        // A redirect chain shares one request id: every hop lands on the last.
        for (id, hops) in chain_first {
            let Some(last) = chain_last.get(id) else {
                continue;
            };
            let last = strip_fragment(last);
            for hop in hops {
                let hop = strip_fragment(hop);
                if hop != last {
                    self.doc_redirect.entry(hop).or_insert_with(|| last.clone());
                }
            }
        }
    }

    fn collect_spec_instances(&mut self) {
        // View routes/urls first: interaction records may refine page URLs.
        let art = self.art;
        for rec in &art.interactions {
            self.view_urls
                .entry(rec.view_id.clone())
                .or_insert_with(|| rec.page_url.clone());
        }
        for (vi, v) in art.views.iter().enumerate() {
            let raw_route = if v.route.is_empty() {
                v.url.clone().unwrap_or_default()
            } else {
                v.route.clone()
            };
            let route = self.route_of(&raw_route);
            self.view_routes.insert(v.id.clone(), route.clone());
            self.view_order.insert(v.id.clone(), vi);
            let page_url = v
                .url
                .clone()
                .or_else(|| self.view_urls.get(&v.id).cloned())
                .unwrap_or_else(|| self.absolute(&raw_route));
            if crate::explorer::url_utils::is_browser_internal_url(&raw_route)
                || crate::explorer::url_utils::is_browser_internal_url(&page_url)
            {
                // Browser-generated error/internal documents (`chrome-error://`,
                // `about:neterror`, etc.) are never application views or controls.
                self.error_views.insert(v.id.clone());
                continue;
            }
            let page_presence_known = v.url.is_some()
                || self
                    .view_urls
                    .get(&v.id)
                    .is_some_and(|url| same_record_page(url, &page_url));
            self.view_urls.insert(v.id.clone(), page_url.clone());
            if self
                .doc_by_url
                .get(&strip_fragment(&page_url))
                .is_some_and(|s| *s == 404 || *s == 410)
            {
                // A crawled "page not found" is a broken link target, not a route.
                self.error_views.insert(v.id.clone());
                continue;
            }
            for (ei, el) in v.elements.iter().enumerate() {
                let inst = self.instance_from_element(
                    el,
                    &v.id,
                    (vi, ei),
                    &route,
                    &page_url,
                    page_presence_known,
                );
                self.push_instance(inst);
            }
        }
        for rec in &art.interactions {
            if crate::explorer::url_utils::is_browser_internal_url(&rec.page_url) {
                self.error_views.insert(rec.view_id.clone());
                continue;
            }
            if !self.view_routes.contains_key(&rec.view_id) {
                let route = self.route_of(&rec.page_url);
                self.view_routes.insert(rec.view_id.clone(), route);
            }
        }
    }

    fn instance_from_element(
        &self,
        el: &InteractiveElement,
        view_id: &str,
        order: (usize, usize),
        route: &str,
        page_url: &str,
        page_presence_known: bool,
    ) -> Instance {
        let role = role_for_element(&el.element_type);
        let label = clean_label(el.label.as_deref().unwrap_or(""));
        let (href, in_nav) = match &el.element_type {
            ElementType::NavigationLink { href, in_nav } => {
                (href.clone().filter(|h| !h.trim().is_empty()), *in_nav)
            }
            ElementType::DropdownMenu { in_nav } => (None, *in_nav),
            _ => (None, false),
        };
        let structural: Vec<&str> = el
            .locators
            .iter()
            .filter(|l| l.kind == LocatorKind::Structural)
            .map(|l| l.value.as_str())
            .collect();
        let landmark = landmark_region(
            structural
                .iter()
                .copied()
                .chain(std::iter::once(el.selector.as_str())),
            in_nav,
        );
        let region = landmark.unwrap_or(MAIN_REGION);
        let link = href.as_deref().and_then(|h| self.link_target(h, page_url));
        let choice = choose_locator(
            &el.locators,
            &el.selector,
            role,
            region,
            &label,
            link.as_ref().map(LinkTarget::signature).as_deref(),
        );
        let hints = Hints {
            tag: element_tag(el),
            aria: locator_attr(&el.locators, &el.selector, LocatorKind::Aria),
            test_id: locator_attr(&el.locators, &el.selector, LocatorKind::TestId),
            element_id: locator_attr(&el.locators, &el.selector, LocatorKind::Id),
            name: locator_attr(&el.locators, &el.selector, LocatorKind::Name).or_else(|| match &el
                .element_type
            {
                ElementType::TextInput { name, .. }
                | ElementType::Checkbox { name, .. }
                | ElementType::RadioButton { name, .. } => name.clone(),
                _ => None,
            }),
        };
        let mut ev = Evidence {
            handler: el.source.as_ref().is_some_and(has_handler_evidence),
            ..Default::default()
        };
        if let Some(snapshot) = el.snapshot.as_ref() {
            // Snapshots are only taken after an interaction; used as legacy
            // evidence when there is no interactions.jsonl.
            // The crawler only keeps a snapshot when it saw a DOM mutation.
            if !self.art.has_interactions {
                ev.exercised = true;
                let kind = snapshot_change_kind(snapshot).unwrap_or_else(|| "other".to_string());
                ev.outcomes.insert(Outcome::DomChange { kind });
            }
        }
        Instance {
            view_id: view_id.to_string(),
            order,
            route: route.to_string(),
            role,
            label,
            selector: el.selector.clone(),
            locator: choice.locator,
            region,
            region_known: landmark.is_some(),
            structural: structural.first().map(|s| s.to_string()),
            needs_ordinal: choice.needs_ordinal,
            ordinal: None,
            href,
            link,
            disabled: el.disabled,
            validation_pending: matches!(
                el.element_type,
                ElementType::Button { form_submit: true }
            ) && el.empty_required_fields_in_form > 0,
            capture: el.source.clone(),
            sub_view: is_sub_view(view_id),
            variant: page_variant(page_url, route),
            record_variants: BTreeSet::new(),
            page_url: page_url.to_string(),
            page_presence_known,
            hints,
            ev,
        }
    }

    fn push_instance(&mut self, inst: Instance) -> usize {
        let idx = self.instances.len();
        self.by_view_sel
            .entry((inst.view_id.clone(), inst.selector.clone()))
            .or_default()
            .push(idx);
        self.by_route_sel
            .entry((inst.route.clone(), inst.selector.clone()))
            .or_default()
            .push(idx);
        self.instances.push(inst);
        idx
    }

    fn find_instance(&self, view: &str, selector: &str) -> Option<usize> {
        if let Some(found) = self
            .by_view_sel
            .get(&(view.to_string(), selector.to_string()))
        {
            return found.first().copied();
        }
        let route = self.view_routes.get(view)?;
        self.by_route_sel
            .get(&(route.clone(), selector.to_string()))
            .and_then(|v| v.first().copied())
    }

    fn find_record_instance(&mut self, rec: &InteractionRecord) -> Option<usize> {
        let mut candidates = self.record_instance_candidates(rec)?;
        let idx = candidates[0];
        // An exact-page copy may coexist with an unobserved aggregate base
        // copy. Refine only placeholders with the same proved identity, not
        // other concrete pages or controls sharing merely a canonical key.
        if let Some(route_candidates) = self
            .by_route_sel
            .get(&(self.instances[idx].route.clone(), rec.selector.clone()))
        {
            let placeholders: Vec<_> = route_candidates
                .iter()
                .copied()
                .filter(|other| {
                    let instance = &self.instances[*other];
                    !candidates.contains(other)
                        && !instance.page_presence_known
                        && instance.variant.as_deref().is_none_or(template_variant)
                        && self
                            .equivalent_record_candidate(&[idx, *other], rec)
                            .is_some()
                })
                .collect();
            candidates.extend(placeholders);
        }
        // Only this strictly equivalent matched cohort supplies metadata to
        // the raw view. Refine aggregate placeholder coverage without lending
        // outcomes to it or erasing an actual page's observed variant.
        let variant = page_variant(&rec.page_url, &self.route_of(&rec.page_url));
        for candidate in candidates {
            let instance = &mut self.instances[candidate];
            if instance.page_presence_known
                || instance
                    .variant
                    .as_deref()
                    .is_some_and(|v| !template_variant(v))
            {
                instance.record_variants.insert(instance.variant.clone());
            }
            instance.record_variants.insert(variant.clone());
        }
        let candidate = &self.instances[idx];
        if candidate.view_id == rec.view_id
            && same_record_page(&candidate.page_url, &rec.page_url)
            && candidate.route == self.route_of(&rec.page_url)
        {
            return Some(idx);
        }

        // Aggregation can retain several equivalent copies while dropping the
        // raw view. Restore its metadata in the actual record context, without
        // borrowing another view's outcomes, target resolution or variants.
        let mut instance = candidate.clone();
        instance.view_id = rec.view_id.clone();
        instance.order = (
            self.view_order
                .get(&rec.view_id)
                .copied()
                .unwrap_or(usize::MAX / 2),
            usize::MAX / 2 + self.instances.len(),
        );
        instance.route = self.route_of(&rec.page_url);
        instance.page_url = rec.page_url.clone();
        instance.page_presence_known = true;
        instance.link = instance
            .href
            .as_deref()
            .and_then(|href| self.link_target(href, &rec.page_url));
        instance.sub_view = is_sub_view(&rec.view_id);
        instance.variant = page_variant(&rec.page_url, &instance.route);
        instance.record_variants.clear();
        instance.ordinal = None;
        instance.ev = Evidence {
            handler: instance.capture.as_ref().is_some_and(has_handler_evidence),
            ..Default::default()
        };
        Some(self.push_instance(instance))
    }

    fn record_instance_candidates(&self, rec: &InteractionRecord) -> Option<Vec<usize>> {
        let role = role_for_record(rec);
        let label = rec.label.as_deref().map(clean_label);
        let route = self.route_of(&rec.page_url);
        let compatible = |idx: &&usize| {
            let instance = &self.instances[**idx];
            // An ID/class selector cannot reveal the tag of an `other`
            // record. A unique label+selector match can retain the richer
            // spec role; competing roles remain ambiguous below.
            (instance.role == role || (role == "other" && label.is_some()))
                && label.as_ref().is_none_or(|label| instance.label == *label)
        };
        if let Some(candidates) = self
            .by_view_sel
            .get(&(rec.view_id.clone(), rec.selector.clone()))
        {
            let found: Vec<_> = candidates
                .iter()
                .filter(compatible)
                .copied()
                .filter(|idx| {
                    self.instances[*idx].route == route
                        && same_record_page(&self.instances[*idx].page_url, &rec.page_url)
                })
                .collect();
            if !found.is_empty() {
                return self.equivalent_record_candidate(&found, rec).map(|_| found);
            }
        }
        // Aggregated specs may use different IDs from the recorded views.
        // A matching selector alone must not attach a Save action to Retry.
        // A reused view ID can describe a different before_url after an
        // interaction. The actual source page outranks that stale view ID.
        let found: Vec<_> = self
            .by_route_sel
            .get(&(route, rec.selector.clone()))?
            .iter()
            .filter(compatible)
            .copied()
            .collect();
        let exact_page: Vec<_> = found
            .iter()
            .copied()
            .filter(|idx| same_record_page(&self.instances[*idx].page_url, &rec.page_url))
            .collect();
        let preferred = if exact_page.is_empty() {
            found
        } else {
            exact_page
        };
        self.equivalent_record_candidate(&preferred, rec)
            .map(|_| preferred)
    }

    fn equivalent_record_candidate(
        &self,
        candidates: &[usize],
        rec: &InteractionRecord,
    ) -> Option<usize> {
        let first = *candidates.first()?;
        let a = &self.instances[first];
        // Ordinals represent distinct controls without a stable handle, not
        // duplicate evidence for one identity. Never select the first of many.
        if candidates.len() > 1 && a.needs_ordinal {
            return None;
        }
        let target = resolved_record_href(a.href.as_deref(), &rec.page_url)?;
        candidates
            .iter()
            .all(|idx| {
                let b = &self.instances[*idx];
                a.role == b.role
                && a.label == b.label
                && a.selector == b.selector
                && a.locator == b.locator
                && a.region == b.region
                && a.region_known == b.region_known
                && a.structural == b.structural
                && a.needs_ordinal == b.needs_ordinal
                && a.disabled == b.disabled
                && a.validation_pending == b.validation_pending
                && a.hints == b.hints
                && a.capture == b.capture
                && a.sub_view == b.sub_view
                // LinkTarget::signature templates IDs and drops queries. It
                // cannot establish equivalent control targets. Resolve every
                // candidate href against this record, retaining the entire URL.
                && resolved_record_href(b.href.as_deref(), &rec.page_url)
                    .is_some_and(|other| other == target)
            })
            .then_some(first)
    }

    fn link_target(&self, href: &str, page_url: &str) -> Option<LinkTarget> {
        let h = href.trim();
        let lower = h.to_ascii_lowercase();
        if h.is_empty()
            || h == "#"
            || lower.starts_with("javascript:")
            || crate::explorer::url_utils::is_browser_internal_url(h)
        {
            return None;
        }
        if ["mailto:", "tel:", "sms:"]
            .iter()
            .any(|p| lower.starts_with(p))
        {
            return Some(LinkTarget::External(h.to_string()));
        }
        let page = Url::parse(page_url).ok().or_else(|| self.base.clone())?;
        let resolved = page.join(h).ok()?;
        if !matches!(resolved.scheme(), "http" | "https") {
            return Some(LinkTarget::External(h.to_string()));
        }
        if !self.internal(&resolved) {
            let mut u = resolved;
            u.set_fragment(None);
            return Some(LinkTarget::External(u.to_string()));
        }
        let fragment = resolved
            .fragment()
            .filter(|f| !f.is_empty() && !crate::explorer::url_utils::fragment_is_route(Some(*f)))
            .map(str::to_string);
        if let Some(frag) = fragment {
            // Bare `#frag` hrefs mean "this page" on every route.
            if h.starts_with('#') {
                return Some(LinkTarget::Anchor {
                    sig: format!("#{frag}"),
                    fragment: frag,
                });
            }
            let target_route = self.route_of(resolved.as_str());
            let sig = format!("{target_route}#{frag}");
            let same_doc = Url::parse(page_url)
                .ok()
                .is_some_and(|p| p.path() == resolved.path() && p.query() == resolved.query());
            if same_doc {
                return Some(LinkTarget::Anchor {
                    fragment: frag,
                    sig,
                });
            }
            return Some(LinkTarget::Internal {
                route: target_route,
                url: resolved.to_string(),
                sig,
            });
        }
        let target_route = self.route_of(resolved.as_str());
        Some(LinkTarget::Internal {
            sig: target_route.clone(),
            route: target_route,
            url: resolved.to_string(),
        })
    }

    // -- interactions.jsonl ---------------------------------------------------

    fn attach_interactions(&mut self) {
        let art = self.art;
        let guard_rejections = guard_rejected_actions(&art.network);
        let action_ids_in_network: HashSet<&str> = art
            .network
            .iter()
            .filter_map(|row| row.action_id.as_deref().filter(|id| !id.is_empty()))
            .collect();
        let mut trigger_counts: HashMap<(&str, &str), usize> = HashMap::new();
        for rec in &art.interactions {
            if self.error_views.contains(&rec.view_id) || rec.outcome == InteractionOutcome::Skipped
            {
                continue;
            }
            *trigger_counts
                .entry((rec.view_id.as_str(), rec.selector.as_str()))
                .or_insert(0) += 1;
        }
        for rec in &art.interactions {
            if self.error_views.contains(&rec.view_id) {
                continue;
            }
            let idx = match self.find_record_instance(rec) {
                Some(i) => i,
                None => {
                    let inst = self.instance_from_record(rec);
                    self.push_instance(inst)
                }
            };
            if let Some(aid) = rec.action_id.as_deref().filter(|a| !a.is_empty()) {
                self.actions.insert(aid.to_string(), idx);
            }
            if rec.outcome != InteractionOutcome::Skipped
                && let Some(start) = parse_time(&rec.started_at)
            {
                let s = start.timestamp_millis();
                let e = s + rec.duration_ms as i64;
                self.action_windows
                    .entry((rec.view_id.clone(), rec.selector.clone()))
                    .or_default()
                    .push((idx, s, e));
            }
            let after_link = rec
                .after_url
                .as_deref()
                .map(|u| self.link_target(u, &rec.page_url));
            let variant = page_variant(&rec.page_url, &self.instances[idx].route);
            self.instances[idx].record_variants.insert(variant);
            let ev = &mut self.instances[idx].ev;
            let has_explicit_action_network = rec
                .action_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .is_some_and(|id| action_ids_in_network.contains(id));
            let unique_for_trigger = trigger_counts
                .get(&(rec.view_id.as_str(), rec.selector.as_str()))
                .copied()
                .unwrap_or(0)
                == 1;
            let guard_rejection = rec
                .action_id
                .as_ref()
                .is_some_and(|id| guard_rejections.contains(id))
                || (!has_explicit_action_network
                    && window_guard_rejected(&art.network, rec, unique_for_trigger));
            apply_record(ev, rec, after_link.flatten(), guard_rejection);
            let is_pure_tool_error = rec.outcome == InteractionOutcome::Error
                && rec.console_errors.is_empty()
                && is_tool_error(rec.error.as_deref().unwrap_or(""));
            if rec.network_activity
                && rec.outcome != InteractionOutcome::Skipped
                && !is_pure_tool_error
            {
                let window = parse_time(&rec.started_at).map(|start| {
                    let s = start.timestamp_millis();
                    (s, s + rec.duration_ms as i64)
                });
                self.net_activity_records.push(InteractionNetActivity {
                    instance_idx: idx,
                    action_id: rec
                        .action_id
                        .as_deref()
                        .filter(|id| !id.is_empty())
                        .map(str::to_string),
                    view_id: rec.view_id.clone(),
                    selector: rec.selector.clone(),
                    window,
                    saw_poll: false,
                    saw_non_poll: false,
                });
            }
        }
    }

    fn obscured_top_covers(&self, exclude_routes: &[String]) -> Vec<ObscuredCover> {
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        for rec in &self.art.interactions {
            if rec.outcome != InteractionOutcome::Skipped || self.error_views.contains(&rec.view_id)
            {
                continue;
            }
            if crate::scope::route_is_excluded(&self.route_of(&rec.page_url), exclude_routes) {
                continue;
            }
            if !rec
                .skipped_reason
                .as_deref()
                .is_some_and(|r| r.to_ascii_lowercase().contains("obscured"))
            {
                continue;
            }
            let Some(cover) = rec
                .obscured_by
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            *counts.entry(cover.to_string()).or_insert(0) += 1;
        }
        let mut out: Vec<ObscuredCover> = counts
            .into_iter()
            .map(|(cover, count)| ObscuredCover { cover, count })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.cover.cmp(&b.cover)));
        out.truncate(5);
        out
    }

    fn instance_from_record(&self, rec: &InteractionRecord) -> Instance {
        let route = self.route_of(&rec.page_url);
        let variant = page_variant(&rec.page_url, &route);
        let role = role_for_record(rec);
        let label = clean_label(rec.label.as_deref().unwrap_or(""));
        let region = region_of([rec.selector.as_str()], false);
        let choice = choose_locator(&[], &rec.selector, role, region, &label, None);
        let view_order = self
            .view_order
            .get(&rec.view_id)
            .copied()
            .unwrap_or(usize::MAX / 2);
        Instance {
            view_id: rec.view_id.clone(),
            order: (view_order, usize::MAX / 2 + self.instances.len()),
            route,
            role,
            label,
            selector: rec.selector.clone(),
            locator: choice.locator,
            region,
            region_known: false,
            structural: None,
            needs_ordinal: choice.needs_ordinal,
            ordinal: None,
            href: None,
            link: None,
            disabled: false,
            validation_pending: false,
            capture: None,
            sub_view: is_sub_view(&rec.view_id),
            variant,
            record_variants: BTreeSet::new(),
            page_url: rec.page_url.clone(),
            page_presence_known: true,
            hints: Hints {
                tag: tag_from_selector(&rec.selector).unwrap_or_default(),
                aria: super::identity::quoted_attr(&rec.selector, "aria-label"),
                test_id: None,
                element_id: super::identity::id_from_selector(&rec.selector),
                name: super::identity::quoted_attr(&rec.selector, "name"),
            },
            ev: Evidence::default(),
        }
    }

    // -- network.jsonl --------------------------------------------------------

    /// Identify background polling & heartbeat endpoints across the scan so
    /// periodic timers (session renewals, status polls) are never attributed
    /// to whichever UI control happened to be clicked when the timer fired.
    fn detect_background_polling_endpoints(&self) -> HashSet<String> {
        let mut background: HashSet<String> = HashSet::new();
        let mut seen_on_load: HashSet<String> = HashSet::new();

        for v in &self.art.views {
            if self.error_views.contains(&v.id) {
                continue;
            }
            for raw in &v.on_load {
                let path = raw.split_once(' ').map_or(raw.as_str(), |(_, p)| p);
                if is_dev_tool_path(path) {
                    continue;
                }
                let key = self.api.template(&stable_endpoint(raw));
                let templ_path = key.split_once(' ').map_or(key.as_str(), |(_, p)| p);
                if is_background_heartbeat_or_poll_path(endpoint_template_path(templ_path)) {
                    background.insert(key.clone());
                }
                seen_on_load.insert(key);
            }
        }

        struct PollStats<'s> {
            is_get: bool,
            controls: HashSet<(&'s str, &'s str)>,
            labels: HashSet<String>,
        }

        let mut stats: HashMap<String, PollStats<'_>> = HashMap::new();
        for row in &self.art.network {
            if row.method == "OPTIONS" {
                continue;
            }
            let Ok(url) = Url::parse(&row.url) else {
                continue;
            };
            if is_telemetry(&url) || is_dev_tool_path(url.path()) {
                continue;
            }
            let guarded = row.is_guarded();
            let call_like = guarded || (!row.is_document && is_api_like(row, &url));
            if !call_like {
                continue;
            }
            let key = self.endpoint_key(row, &url);
            if is_background_heartbeat_or_poll_path(url.path()) {
                background.insert(key);
                continue;
            }
            if matches!(
                &row.trigger,
                Some((view, selector))
                    if selector == "__page_load__" || view.starts_with("__load_")
            ) {
                seen_on_load.insert(key);
                continue;
            }
            if row.is_page_load() {
                continue;
            }
            let Some(idx) = self.attribute_row(row) else {
                continue;
            };
            let inst = &self.instances[idx];
            let entry = stats.entry(key).or_insert_with(|| PollStats {
                is_get: row.method.eq_ignore_ascii_case("GET")
                    || row.method.eq_ignore_ascii_case("HEAD"),
                controls: HashSet::new(),
                labels: HashSet::new(),
            });
            entry
                .controls
                .insert((inst.view_id.as_str(), inst.selector.as_str()));
            let label = control_poll_label(inst);
            if !label.is_empty() {
                entry.labels.insert(label);
            }
        }

        for (key, st) in stats {
            let on_load_and_unrelated =
                seen_on_load.contains(&key) && st.controls.len() >= 2 && st.labels.len() >= 2;
            let repeated_get_across_unrelated =
                st.is_get && st.controls.len() >= 3 && st.labels.len() >= 3;
            if on_load_and_unrelated || repeated_get_across_unrelated {
                background.insert(key);
            }
        }

        background
    }

    fn attach_network(&mut self) {
        let art = self.art;
        let base = self.base.clone();
        let background_polls = self.detect_background_polling_endpoints();
        for row in &art.network {
            if row.method == "OPTIONS" {
                continue;
            }
            let Ok(url) = Url::parse(&row.url) else {
                continue;
            };
            if is_telemetry(&url) || is_dev_tool_path(url.path()) {
                continue;
            }
            let guarded = row.is_guarded();
            let doc_nav = row.is_document
                && row.method == "GET"
                && !guarded
                && !looks_like_static_asset_path(url.path());
            let call_like = guarded || (!row.is_document && is_api_like(row, &url));
            if !call_like && !doc_nav {
                continue;
            }
            let key = self.endpoint_key(row, &url);
            let is_poll = call_like && background_polls.contains(&key);
            if call_like && (!is_poll || row.is_page_load()) {
                if let Some(s) = row.status {
                    self.endpoint_statuses
                        .entry(key.clone())
                        .or_default()
                        .insert(s);
                }
                if guarded {
                    self.endpoint_guarded.insert(key.clone());
                }
            }

            if row.is_page_load() {
                if call_like
                    && let Some(route) = row
                        .trigger
                        .as_ref()
                        .and_then(|(view, _)| self.view_routes.get(view))
                {
                    self.on_load.entry(key).or_default().insert(route.clone());
                }
                continue;
            }

            let Some(idx) = self.attribute_row(row) else {
                if call_like && !is_poll {
                    self.unattributed.insert(key);
                }
                continue;
            };
            if is_poll {
                for rec in &mut self.net_activity_records {
                    if row_matches_net_activity(rec, row, idx) {
                        rec.saw_poll = true;
                    }
                }
                continue;
            }
            for rec in &mut self.net_activity_records {
                if row_matches_net_activity(rec, row, idx) {
                    rec.saw_non_poll = true;
                }
            }
            let blocked = guarded;
            let failed_hard = row
                .failure
                .as_deref()
                .is_some_and(|f| !is_nonfatal_network_failure(f));
            let route_target = self.route_of(url.as_str());
            let ev = &mut self.instances[idx].ev;
            ev.exercised = true;
            if call_like {
                ev.add_call(key.clone(), row.status, blocked);
                if !blocked {
                    if let Some(s) = row.status.filter(|s| *s >= 400) {
                        ev.add_error(format!("{key} returned {s}"));
                    } else if failed_hard && row.status.is_none() {
                        ev.add_error(format!(
                            "{key} failed: {}",
                            row.failure.as_deref().unwrap_or("request failed")
                        ));
                    }
                }
            } else if doc_nav {
                let internal = base.as_ref().is_some_and(|b| same_origin(b, &url));
                if internal {
                    ev.outcomes.insert(Outcome::Navigates {
                        to: route_target.clone(),
                    });
                    if let Some(s) = row.status.filter(|s| *s == 404 || *s == 410 || *s >= 500) {
                        ev.add_error(format!("navigates to {route_target} which returned {s}"));
                    }
                } else {
                    let mut u = url.clone();
                    u.set_fragment(None);
                    ev.outcomes.insert(Outcome::External { url: u.to_string() });
                }
            }
        }

        if !self.net_activity_records.is_empty() {
            let mut has_real_or_unexplained: HashSet<usize> = HashSet::new();
            let mut had_poll_only: HashSet<usize> = HashSet::new();
            for rec in &self.net_activity_records {
                if rec.saw_poll && !rec.saw_non_poll {
                    had_poll_only.insert(rec.instance_idx);
                } else {
                    has_real_or_unexplained.insert(rec.instance_idx);
                }
            }
            for idx in had_poll_only {
                if !has_real_or_unexplained.contains(&idx)
                    && self.instances[idx].ev.calls.is_empty()
                {
                    self.instances[idx].ev.network_activity = false;
                }
            }
        }
    }

    /// Stable endpoint key: the scanner's key (or one rebuilt from the row),
    /// with Server Action ids folded and paths templated by source patterns.
    fn endpoint_key(&self, row: &NetRow, url: &Url) -> String {
        let raw = endpoint_key(row, url, self.base.as_ref());
        self.api.template(&stable_endpoint(&raw))
    }

    fn attribute_row(&self, row: &NetRow) -> Option<usize> {
        if let Some(aid) = row.action_id.as_deref().filter(|aid| !aid.is_empty()) {
            return self.actions.get(aid).copied();
        }
        let (view, selector) = row.trigger.as_ref()?;
        if let Some(windows) = self.action_windows.get(&(view.clone(), selector.clone())) {
            let at = row.occurred_at.map(|at| at.timestamp_millis());
            let candidates: BTreeSet<_> = windows
                .iter()
                .filter(|(_, start, end)| {
                    at.is_none_or(|at| at >= start - 1_000 && at <= end + ACTION_WINDOW_SLACK_MS)
                })
                .map(|(idx, _, _)| *idx)
                .collect();
            return (candidates.len() == 1).then(|| *candidates.first().unwrap());
        }
        // Network-only evidence has no label or action window. Keep
        // only an unambiguous selector match, never the first of many.
        let candidates = self
            .by_view_sel
            .get(&(view.clone(), selector.clone()))
            .or_else(|| {
                self.view_routes
                    .get(view)
                    .and_then(|route| self.by_route_sel.get(&(route.clone(), selector.clone())))
            })?;
        (candidates.len() == 1).then(|| candidates[0])
    }

    // -- legacy evidence (scans without interactions.jsonl) ------------------

    fn attach_legacy_evidence(&mut self) {
        let art = self.art;
        for t in &art.transitions {
            let Some(idx) = self.find_instance(&t.trigger_view, &t.trigger_selector) else {
                continue;
            };
            let to_route = self.view_routes.get(&t.to_view).cloned();
            let ev = &mut self.instances[idx].ev;
            ev.exercised = true;
            match t.kind.as_str() {
                "navigation" | "spa_route_change" => {
                    if let Some(to) = to_route {
                        ev.outcomes.insert(Outcome::Navigates { to });
                    }
                }
                "modal_open" | "modal_close" => {
                    ev.outcomes.insert(Outcome::DomChange {
                        kind: "modal".into(),
                    });
                }
                "tab_switch" => {
                    ev.outcomes
                        .insert(Outcome::DomChange { kind: "tab".into() });
                }
                "accordion_toggle" => {
                    ev.outcomes.insert(Outcome::DomChange {
                        kind: "panel".into(),
                    });
                }
                _ => {
                    ev.outcomes.insert(Outcome::DomChange {
                        kind: "other".into(),
                    });
                }
            }
        }

        if art.network.is_empty() {
            for e in &art.endpoints {
                let raw_path = e.key.split_once(' ').map_or("", |(_, p)| p);
                if is_dev_tool_path(raw_path) {
                    continue;
                }
                let key = self.api.template(&stable_endpoint(&e.key));
                let is_heartbeat =
                    is_background_heartbeat_or_poll_path(endpoint_template_path(raw_path));
                let mut seen_on_load = false;
                for (view, selector) in &e.triggered_by {
                    if selector == "__page_load__" {
                        seen_on_load = true;
                        if let Some(route) = self.view_routes.get(view) {
                            self.on_load
                                .entry(key.clone())
                                .or_default()
                                .insert(route.clone());
                        }
                        continue;
                    }
                    if is_heartbeat {
                        continue;
                    }
                    if let Some(idx) = self.find_instance(view, selector) {
                        let ev = &mut self.instances[idx].ev;
                        ev.exercised = true;
                        ev.add_call(key.clone(), None, false);
                    }
                }
                if !is_heartbeat || seen_on_load {
                    for s in &e.statuses {
                        self.endpoint_statuses
                            .entry(key.clone())
                            .or_default()
                            .insert(*s);
                    }
                }
            }
        }

        for (view, selector) in &art.dead_buttons {
            let found = match view {
                Some(v) => self
                    .find_instance(v, selector)
                    .into_iter()
                    .collect::<Vec<_>>(),
                None => Vec::new(),
            };
            let targets = if found.is_empty() {
                self.instances
                    .iter()
                    .enumerate()
                    .filter(|(_, i)| &i.selector == selector)
                    .map(|(i, _)| i)
                    .collect()
            } else {
                found
            };
            for idx in targets {
                let ev = &mut self.instances[idx].ev;
                ev.exercised = true;
                ev.dead_hint = true;
            }
        }
    }

    /// Coverage gaps fill in skip reasons for controls with no other record,
    /// and say why seeded routes were not reached.
    fn attach_gaps(&mut self) {
        let art = self.art;
        for gap in &art.gaps {
            match gap.kind.as_str() {
                "route" | "seeded_route" => {
                    if gap.target.trim().is_empty() {
                        continue;
                    }
                    let route = self.route_of(&gap.target);
                    let why = unvisited_reason_for_gap(&gap.reason);
                    let slot = self.gap_routes.entry(route).or_insert(None);
                    // A streamed redirect can return HTTP 200 and produce both
                    // gaps. Its explicit destination explains the missing view.
                    let redirect =
                        matches!(why.as_deref(), Some("redirects" | "redirects to login"));
                    if slot.is_none() || slot.as_deref() == Some(GAP_NO_VIEW) && redirect {
                        *slot = why;
                    }
                }
                "interaction" => {
                    let targets: Vec<usize> = match gap.view.as_deref() {
                        Some(v) => self.find_instance(v, &gap.target).into_iter().collect(),
                        None => self
                            .instances
                            .iter()
                            .enumerate()
                            .filter(|(_, i)| i.selector == gap.target)
                            .map(|(i, _)| i)
                            .collect(),
                    };
                    for idx in targets {
                        let ev = &mut self.instances[idx].ev;
                        if !ev.exercised && ev.skip.is_none() && ev.elsewhere.is_none() {
                            ev.skip = Some(gap.reason.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        for (url, msg) in &art.nav_failures {
            let route = self.route_of(url);
            let why = if msg.to_ascii_lowercase().contains("timed out") {
                "navigation timeout"
            } else {
                "navigation failed"
            };
            // A failed navigation explains more than "attempted, no view".
            let slot = self.gap_routes.entry(route).or_insert(None);
            if slot.as_deref().is_none_or(|s| s == GAP_NO_VIEW) {
                *slot = Some(why.to_string());
            }
        }
    }

    /// Which control opened each sub-view (`view_0001:d1:0` is a state
    /// reached from `view_0001` by clicking a control).
    fn index_openers(&mut self) {
        let art = self.art;
        for t in &art.transitions {
            if !is_sub_view(&t.to_view) || self.error_views.contains(&t.to_view) {
                continue;
            }
            let from = if t.trigger_view.is_empty() {
                &t.from_view
            } else {
                &t.trigger_view
            };
            if let Some(idx) = self.find_instance(from, &t.trigger_selector) {
                let list = self.openers.entry(t.to_view.clone()).or_default();
                if !list.contains(&idx) {
                    list.push(idx);
                }
            }
        }
    }

    /// Route -> observed page variants (`None` = plain route). Spec views
    /// can aggregate several records under a synthetic template ID; their
    /// concrete URLs survive in the interaction log under the original IDs.
    fn route_variants(&self) -> BTreeMap<String, BTreeSet<Option<String>>> {
        let mut out: BTreeMap<String, BTreeSet<Option<String>>> = BTreeMap::new();
        for v in &self.art.views {
            if self.error_views.contains(&v.id) || is_sub_view(&v.id) {
                continue;
            }
            let (Some(route), Some(url)) = (self.view_routes.get(&v.id), self.view_urls.get(&v.id))
            else {
                continue;
            };
            let variant = page_variant(url, route);
            if !variant.as_deref().is_some_and(template_variant) {
                out.entry(route.clone()).or_default().insert(variant);
            }
        }
        for rec in &self.art.interactions {
            if self.error_views.contains(&rec.view_id) {
                continue;
            }
            let route = self.route_of(&rec.page_url);
            let variant = page_variant(&rec.page_url, &route);
            if !variant.as_deref().is_some_and(template_variant) {
                out.entry(route).or_default().insert(variant);
            }
        }
        out
    }

    fn visited_routes(&self) -> BTreeSet<String> {
        let views = self.art.views.iter().map(|v| &v.id);
        let records = self.art.interactions.iter().map(|r| &r.view_id);
        views
            .chain(records)
            .filter(|id| !self.error_views.contains(*id))
            .filter_map(|id| self.view_routes.get(id).cloned())
            .collect()
    }

    // -- grouping -------------------------------------------------------------

    fn group_instances(&mut self) -> Vec<Group> {
        // Ordinals for controls with no stable handle, per (view, role), in
        // document order.
        let mut order: Vec<usize> = (0..self.instances.len()).collect();
        order.sort_by_key(|i| self.instances[*i].order);
        let mut counters: HashMap<(String, &'static str), usize> = HashMap::new();
        for idx in &order {
            let inst = &self.instances[*idx];
            if inst.needs_ordinal {
                let n = counters
                    .entry((inst.view_id.clone(), inst.role))
                    .or_insert(0);
                *n += 1;
                let n = *n;
                self.instances[*idx].ordinal = Some(n);
            }
        }

        type GroupId = (String, &'static str, String, String, Option<usize>);
        let mut groups: BTreeMap<GroupId, Group> = BTreeMap::new();
        for idx in order {
            let inst = &self.instances[idx];
            let target = inst
                .link
                .as_ref()
                .map(LinkTarget::signature)
                .unwrap_or_default();
            let k = (
                inst.route.clone(),
                inst.role,
                inst.locator.clone(),
                target.clone(),
                inst.ordinal,
            );
            groups
                .entry(k)
                .or_insert_with(|| Group {
                    route: inst.route.clone(),
                    role: inst.role,
                    locator: inst.locator.clone(),
                    target,
                    ordinal: inst.ordinal,
                    members: Vec::new(),
                    routes: BTreeSet::new(),
                    global: false,
                    disambiguate: false,
                })
                .members
                .push(idx);
        }
        let mut out: Vec<Group> = groups.into_values().collect();
        for g in &mut out {
            g.routes.insert(g.route.clone());
        }
        out
    }

    // -- outputs --------------------------------------------------------------

    fn endpoint_index(&self, controls: &[Control]) -> Vec<EndpointEntry> {
        let mut entries: BTreeMap<String, EndpointEntry> = BTreeMap::new();
        fn entry<'m>(
            entries: &'m mut BTreeMap<String, EndpointEntry>,
            key: &str,
        ) -> &'m mut EndpointEntry {
            entries
                .entry(key.to_string())
                .or_insert_with(|| EndpointEntry {
                    endpoint: key.to_string(),
                    ..Default::default()
                })
        }
        for c in controls {
            for o in &c.outcomes {
                if let Outcome::Calls {
                    endpoint,
                    status,
                    blocked,
                } = o
                {
                    let e = entry(&mut entries, endpoint);
                    e.controls.push(c.key.clone());
                    if let Some(s) = status {
                        e.statuses.push(*s);
                    }
                    e.write |= *blocked;
                }
            }
        }
        for v in &self.art.views {
            if self.error_views.contains(&v.id) {
                continue;
            }
            let Some(route) = self.view_routes.get(&v.id) else {
                continue;
            };
            for key in &v.on_load {
                if is_dev_tool_path(key.split_once(' ').map_or("", |(_, p)| p)) {
                    continue;
                }
                let key = self.api.template(&stable_endpoint(key));
                entry(&mut entries, &key).on_load.push(route.clone());
            }
        }
        for (key, routes) in &self.on_load {
            entry(&mut entries, key)
                .on_load
                .extend(routes.iter().cloned());
        }
        for key in &self.unattributed {
            entry(&mut entries, key);
        }
        for (key, e) in entries.iter_mut() {
            if let Some(statuses) = self.endpoint_statuses.get(key) {
                e.statuses.extend(statuses.iter().copied());
            }
            e.write |= self.endpoint_guarded.contains(key);
            e.controls.sort();
            e.controls.dedup();
            e.on_load.sort();
            e.on_load.dedup();
            e.statuses.sort_unstable();
            e.statuses.dedup();
        }
        entries.into_values().collect()
    }

    fn route_entries(
        &self,
        controls: &[Control],
        visited: &BTreeSet<String>,
        discovered: &[DiscoveredRoute],
    ) -> Vec<RouteEntry> {
        let mut routes: BTreeMap<String, RouteEntry> = BTreeMap::new();
        let knows = self.canon.knows_routes();
        // Titles at view load: top-level views only (a sub-view's title is
        // usually the modal's).
        let mut views: Vec<&artifacts::SpecView> = self
            .art
            .views
            .iter()
            .filter(|v| !self.error_views.contains(&v.id))
            .collect();
        views.sort_by_key(|v| (is_sub_view(&v.id), self.view_order.get(&v.id).copied()));
        for v in views {
            let Some(route) = self.view_routes.get(&v.id) else {
                continue;
            };
            let e = routes.entry(route.clone()).or_insert_with(|| RouteEntry {
                route: route.clone(),
                visited: true,
                ..Default::default()
            });
            if e.title.is_none() && !is_sub_view(&v.id) {
                e.title = v.title.clone();
            }
        }
        for d in discovered
            .iter()
            .filter(|d| is_page_kind(&d.kind) && !is_error_page(d))
        {
            let source = (!d.file.is_empty()).then(|| {
                if d.line > 0 {
                    format!("{}:{}", d.file, d.line)
                } else {
                    d.file.clone()
                }
            });
            let mut paths: Vec<String> = d
                .examples
                .iter()
                .map(|e| self.canon.canonical(&route_template(e)))
                .collect();
            let pattern = self.canon.canonical(&route_template(&d.path));
            // A dynamic route whose values source enumerates is listed through
            // those pages; the bare pattern only when it was reached itself.
            if paths.is_empty() || visited.contains(&pattern) {
                paths.push(pattern);
            }
            for path in paths {
                let e = routes.entry(path.clone()).or_insert_with(|| RouteEntry {
                    route: path.clone(),
                    visited: visited.contains(&path),
                    ..Default::default()
                });
                if e.source.is_none() {
                    e.source = source.clone();
                }
            }
        }
        // Routes only seen in interaction records were visited too.
        for c in controls.iter().filter(|c| c.route != "*") {
            routes.entry(c.route.clone()).or_insert_with(|| RouteEntry {
                route: c.route.clone(),
                visited: true,
                ..Default::default()
            });
        }
        // Link targets and seeds: only pages of the app. A target no source
        // route matches (when discovery knows the routes) or that only ever
        // redirected is a link result, not a route.
        let link_targets = self.instances.iter().filter_map(|i| match &i.link {
            Some(LinkTarget::Internal { route, url, .. }) => Some((route.clone(), Some(url))),
            _ => None,
        });
        let gap_targets = self.gap_routes.keys().map(|r| (r.clone(), None));
        for (route, url) in link_targets.chain(gap_targets) {
            if routes.contains_key(&route) || !is_page_like_route(&route) {
                continue;
            }
            if knows && !self.canon.is_known(&route) {
                continue;
            }
            // Without route discovery, a target that only ever redirected is
            // an alias, not a page.
            let redirect_only = !knows
                && url.is_some_and(|u| {
                    self.doc_by_url
                        .get(&strip_fragment(u))
                        .is_some_and(|s| (300..400).contains(s))
                });
            if redirect_only {
                continue;
            }
            routes.insert(
                route.clone(),
                RouteEntry {
                    route: route.clone(),
                    visited: visited.contains(&route),
                    ..Default::default()
                },
            );
        }
        let variants = self.route_variants();
        for (route, e) in routes.iter_mut() {
            if let Some(vs) = variants.get(route) {
                e.variants = vs
                    .iter()
                    .flatten()
                    .take(MAX_ROUTE_VARIANTS)
                    .cloned()
                    .collect();
            }
            if !route.contains("/#") {
                e.status = self.doc_status.get(route).copied();
            }
            e.controls = controls.iter().filter(|c| &c.route == route).count() as u32;
            e.not_in_source = knows && e.visited && !self.canon.is_known(route);
            if !e.visited {
                e.unvisited_reason = Some(self.unvisited_reason(route));
            }
        }
        routes.into_values().collect()
    }

    fn unvisited_reason(&self, route: &str) -> String {
        let gap = self.gap_routes.get(route).cloned().flatten();
        if let Some(why) = gap.as_deref().filter(|w| *w != GAP_NO_VIEW) {
            return why.to_string();
        }
        // Where the crawler's document request for this route landed.
        let mut redirected: Vec<&String> = self
            .doc_by_url
            .iter()
            .filter(|(u, s)| (300..400).contains(*s) && self.route_of(u) == route)
            .map(|(u, _)| u)
            .collect();
        redirected.sort();
        let landed = redirected
            .into_iter()
            .find_map(|u| self.doc_redirect.get(u));
        if let Some(to) = landed {
            return if is_login_url(to) {
                "redirects to login".to_string()
            } else {
                "redirects".to_string()
            };
        }
        if let Some(why) = gap {
            return why;
        }
        if route.split('/').any(is_param) {
            "dynamic route: no concrete URL visited".to_string()
        } else {
            "not linked or seeded".to_string()
        }
    }
}

const GAP_NO_VIEW: &str = "attempted, no view captured";

fn unvisited_reason_for_gap(reason: &str) -> Option<String> {
    let r = reason.to_ascii_lowercase();
    let why = if r.contains("login") || r.contains("auth") {
        "redirects to login"
    } else if r.contains("redirect") {
        "redirects"
    } else if r.contains("timeout") || r.contains("timed_out") {
        "navigation timeout"
    } else if r.contains("without_view") {
        GAP_NO_VIEW
    } else if r.contains("duplicate") {
        return None;
    } else {
        return Some(reason.replace('_', " "));
    };
    Some(why.to_string())
}

/// Page variant of a view URL: the query (sorted params) for a static
/// route, or the concrete path plus query for a dynamic one. `None` for the
/// plain route.
fn page_variant(url: &str, route: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let (path, raw_query) = effective_url_path_and_query(&parsed);
    let mut params: Vec<(String, String)> =
        url::form_urlencoded::parse(raw_query.as_deref().unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    params.sort();
    let query = (!params.is_empty()).then(|| {
        let joined: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!("?{}", joined.join("&"))
    });
    let dynamic = route.split('/').any(is_param);
    if dynamic {
        let path = path.trim_end_matches('/');
        Some(format!("{}{}", path, query.unwrap_or_default()))
    } else {
        query
    }
}

/// A route template is not evidence that any concrete record was visited.
fn template_variant(variant: &str) -> bool {
    variant
        .split('?')
        .next()
        .unwrap_or(variant)
        .split('/')
        .any(is_param)
}

fn is_sub_view(view_id: &str) -> bool {
    view_id.contains(':')
}

fn has_handler_evidence(cap: &ElementSourceCapture) -> bool {
    !cap.handlers.is_empty() || cap.frames.iter().any(|f| f.role == "handler")
}

/// Crawler-side failures (the click timed out in the tool) say nothing about
/// the app on their own.
fn is_tool_error(msg: &str) -> bool {
    let m = msg.trim_start().to_ascii_lowercase();
    m.starts_with("interaction_timeout") || m.starts_with("view_time_budget")
}

fn role_for_record(rec: &InteractionRecord) -> &'static str {
    let role = role_for_kind_slug(&rec.element_kind);
    if role == "other"
        && record_terminal_tag(&rec.selector)
            .is_some_and(|tag| tag.eq_ignore_ascii_case("textarea"))
    {
        "input"
    } else {
        role
    }
}

/// Infer only an explicit terminal type selector. Attribute values and nested
/// pseudo-classes can contain spaces/combinators; selector lists are ambiguous.
fn record_terminal_tag(selector: &str) -> Option<&str> {
    let selector = selector.trim();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut brackets = 0usize;
    let mut parentheses = 0usize;
    for (index, ch) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => brackets += 1,
            ']' => brackets = brackets.checked_sub(1)?,
            '(' if brackets == 0 => parentheses += 1,
            ')' if brackets == 0 => parentheses = parentheses.checked_sub(1)?,
            ',' | '/' if brackets == 0 && parentheses == 0 => return None,
            ch if brackets == 0
                && parentheses == 0
                && (ch.is_ascii_whitespace() || matches!(ch, '>' | '+' | '~')) =>
            {
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if quote.is_some() || escaped || brackets != 0 || parentheses != 0 {
        return None;
    }
    let compound = selector.get(start..)?;
    let tag_len = compound
        .bytes()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == b'-')
        .count();
    if tag_len == 0
        || compound[tag_len..]
            .chars()
            .next()
            .is_some_and(|ch| !matches!(ch, '.' | '#' | '[' | ':'))
    {
        return None;
    }
    Some(&compound[..tag_len])
}

/// Whether `row` is a real application operation blocked by the write guard
/// (as opposed to a stubbed response, OPTIONS preflight, telemetry, or dev
/// server diagnostic call).
fn is_write_blocked_row(row: &NetRow) -> bool {
    matches!(row.write_guard.as_deref(), Some("blocked" | "block"))
        && row.method != "OPTIONS"
        && Url::parse(&row.url)
            .is_ok_and(|url| !is_telemetry(&url) && !is_dev_tool_path(url.path()))
}

/// Whether `row` represents an actual application network/HTTP failure rather
/// than a write-guarded request, canceled prefetch, telemetry, or dev-tool call.
fn is_real_network_failure_row(row: &NetRow) -> bool {
    if row.is_guarded() {
        return false;
    }
    if Url::parse(&row.url).is_ok_and(|url| is_telemetry(&url) || is_dev_tool_path(url.path())) {
        return false;
    }
    row.status.is_some_and(|status| status >= 400)
        || row
            .failure
            .as_deref()
            .filter(|failure| !failure.is_empty())
            .is_some_and(|failure| !is_nonfatal_network_failure(failure))
}

/// The guard rejects fetch with a generic browser error. Only correlate that
/// error with an exact action that has a blocked operation and no real failure.
/// Error overlays and telemetry can fire after an unrelated application error;
/// their blocked requests are not proof that the original operation was guarded.
/// Canceled requests (including completed-header prefetches) use the same
/// nonfatal policy as ordinary network evidence.
fn guard_rejected_actions(rows: &[NetRow]) -> HashSet<String> {
    let mut blocked = HashSet::new();
    let mut failed = HashSet::new();
    for row in rows {
        let Some(id) = row.action_id.as_ref().filter(|id| !id.is_empty()) else {
            continue;
        };
        if is_write_blocked_row(row) {
            blocked.insert(id.clone());
        } else if is_real_network_failure_row(row) {
            failed.insert(id.clone());
        }
    }
    blocked.retain(|id| !failed.contains(id));
    blocked
}

/// Fallback correlation for write-blocked rows that lack an `action_id` and
/// are attributed to `rec` via `(view, selector)` within its action window.
/// Rows carrying a different `action_id` are never borrowed.
fn window_guard_rejected(
    rows: &[NetRow],
    rec: &InteractionRecord,
    unique_for_trigger: bool,
) -> bool {
    if rec.outcome == InteractionOutcome::Skipped {
        return false;
    }
    let window = parse_time(&rec.started_at).map(|start| {
        let s = start.timestamp_millis();
        (s, s + rec.duration_ms as i64)
    });
    if window.is_none() && !unique_for_trigger {
        return false;
    }
    let mut saw_blocked = false;
    for row in rows {
        if row.action_id.as_deref().is_some_and(|id| !id.is_empty()) {
            continue;
        }
        let Some((view, selector)) = row.trigger.as_ref() else {
            continue;
        };
        if view != &rec.view_id || selector != &rec.selector {
            continue;
        }
        if let Some((start, end)) = window
            && !row.occurred_at.is_none_or(|at| {
                let t = at.timestamp_millis();
                t >= start - 1_000 && t <= end + ACTION_WINDOW_SLACK_MS
            })
        {
            continue;
        }
        if is_write_blocked_row(row) {
            saw_blocked = true;
        } else if is_real_network_failure_row(row) {
            return false;
        }
    }
    saw_blocked
}

fn is_nonfatal_network_failure(failure: &str) -> bool {
    let failure = failure.to_ascii_lowercase();
    failure.contains("blockedbyclient")
        || failure.contains("blocked_by_client")
        || failure.contains("aborted")
        || failure.contains("canceled")
        || failure.contains("cancelled")
}

fn is_guard_fetch_error(message: &str) -> bool {
    let trimmed = message.trim();
    let (head, frame) = match trimmed.split_once(" @ ") {
        Some((h, f)) => (h.trim(), Some(f.trim())),
        None => (trimmed, None),
    };
    if !is_network_abort_error_head(head) {
        return false;
    }
    match frame {
        None => true,
        Some(f) => is_guard_fetch_frame(f),
    }
}

fn is_network_abort_error_head(head: &str) -> bool {
    const ABORT_PHRASES: &[&str] = &[
        "typeerror: failed to fetch",
        "typeerror: load failed",
        "typeerror: networkerror when attempting to fetch resource",
        "typeerror: networkerror",
        "typeerror: network error",
        "failed to load resource: net::err_failed",
        "failed to load resource: net::err_aborted",
        "failed to load resource: net::err_blocked_by_client",
        "networkerror when attempting to fetch resource",
        "net::err_blocked_by_client",
        "net::err_aborted",
        "net::err_failed",
        "failed to fetch",
        "load failed",
        "networkerror",
        "network error",
    ];
    let lower = head.trim().to_ascii_lowercase();
    let core = lower.trim_end_matches(|c: char| c.is_whitespace() || c == '.');
    ABORT_PHRASES.iter().any(|phrase| {
        core.strip_suffix(phrase).is_some_and(|prefix| {
            prefix.is_empty()
                || prefix
                    .ends_with(|c: char| c.is_whitespace() || matches!(c, ':' | ',' | '-' | ';'))
        })
    })
}

fn is_guard_fetch_frame(frame: &str) -> bool {
    let f = frame.trim();
    if f.is_empty() {
        return true;
    }
    // Injected fetch wrapper in cdp_helpers (`at w.fetch (<anonymous>:...)`,
    // `at async w.fetch (<anonymous>:...)`, `at window.fetch (<anonymous>:...)`).
    if f.contains("(<anonymous>:") || f.contains("<anonymous>:") {
        return true;
    }
    let lower = f.to_ascii_lowercase();
    if lower.contains("w.fetch")
        || lower.contains("window.fetch")
        || lower.contains("fetchserveraction")
        || lower.contains("callserver")
        || lower.contains("webpack-internal:")
        || lower.contains("turbopack:")
    {
        return true;
    }
    // Framework/bundler chunks (e.g. Next.js Server Action runtime in `/_next/...`),
    // while keeping direct application frames (`at onClick (http://app.local/page.js:...)`)
    // visible as real failures.
    if let Some(cap) = stack_location_re().captures(f)
        && let Ok(url) = Url::parse(&cap[1])
        && is_bundle_path(url.path())
    {
        return true;
    }
    false
}

fn apply_record(
    ev: &mut Evidence,
    rec: &InteractionRecord,
    after: Option<LinkTarget>,
    guard_rejection: bool,
) {
    if rec.outcome == InteractionOutcome::Skipped {
        let reason = rec
            .skipped_reason
            .clone()
            .unwrap_or_else(|| "skipped".to_string());
        if reason == "exercised_elsewhere" {
            if ev.elsewhere.is_none() {
                ev.elsewhere = rec.exercised_on.clone().or_else(|| Some(String::new()));
            }
        } else if ev.skip.is_none() {
            ev.skip = Some(reason);
        }
        return;
    }
    if rec.outcome == InteractionOutcome::Error
        && rec.console_errors.is_empty()
        && is_tool_error(rec.error.as_deref().unwrap_or(""))
    {
        let msg = first_line(rec.error.as_deref().unwrap_or("interaction_timeout"));
        if !ev.tool_errors.contains(&msg) {
            ev.tool_errors.push(msg);
        }
        return;
    }
    match rec.outcome {
        InteractionOutcome::Skipped => unreachable!("handled above"),
        InteractionOutcome::Navigated => match after {
            Some(LinkTarget::Internal { route, .. }) => {
                ev.outcomes.insert(Outcome::Navigates { to: route });
            }
            Some(LinkTarget::External(url)) => {
                ev.outcomes.insert(Outcome::External { url });
            }
            Some(LinkTarget::Anchor { fragment, .. }) => {
                ev.outcomes.insert(Outcome::Anchor { fragment });
            }
            None => {
                let after = rec
                    .after_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|u| !u.is_empty());
                if !after.is_some_and(crate::explorer::url_utils::is_browser_internal_url) {
                    ev.outcomes.insert(Outcome::Navigates {
                        to: after.unwrap_or("(unknown)").to_string(),
                    });
                }
            }
        },
        InteractionOutcome::DomChange => {
            let kind = rec
                .dom_change
                .clone()
                .filter(|k| !k.trim().is_empty())
                .unwrap_or_else(|| "other".to_string());
            if kind == "download" {
                ev.outcomes.insert(Outcome::Download);
            } else {
                ev.outcomes.insert(Outcome::DomChange { kind });
            }
        }
        InteractionOutcome::NoEffect => {}
        InteractionOutcome::Error => {
            let msg = first_line(rec.error.as_deref().unwrap_or("interaction failed"));
            if !(guard_rejection && is_guard_fetch_error(&msg)) {
                ev.outcomes.insert(Outcome::Error {
                    message: msg.clone(),
                });
                ev.add_error(msg);
            }
        }
    }
    ev.exercised = true;
    ev.network_activity |= rec.network_activity;
    ev.already_active |= rec.already_active;
    for effect in &rec.side_effects {
        match effect.as_str() {
            "" => {}
            "download" => {
                ev.outcomes.insert(Outcome::Download);
            }
            other => {
                ev.outcomes.insert(Outcome::SideEffect {
                    kind: other.to_string(),
                });
            }
        }
    }
    match rec.retest.as_deref() {
        Some("confirmed_no_effect") => ev.retest_confirmed = true,
        Some("effect_on_retest") => ev.retest_effect = true,
        Some(_) => ev.retest_other = true,
        None => {}
    }
    if let Some(dialog) = rec
        .native_dialog
        .as_deref()
        .filter(|d| !d.trim().is_empty())
    {
        ev.outcomes.insert(Outcome::Dialog {
            message: first_line(dialog),
        });
    }
    for err in &rec.console_errors {
        let msg = first_line(err);
        if guard_rejection && is_guard_fetch_error(&msg) {
            continue;
        }
        ev.outcomes.insert(Outcome::Error {
            message: msg.clone(),
        });
        ev.add_error(format!("console error: {msg}"));
    }
    for err in &rec.ui_errors {
        let msg = first_line(err);
        if msg.is_empty() || (guard_rejection && is_guard_fetch_error(&msg)) {
            continue;
        }
        ev.outcomes.insert(Outcome::Error {
            message: msg.clone(),
        });
        ev.add_error(format!("ui error: {msg}"));
    }
}

// ---------------------------------------------------------------------------
// Groups -> controls
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Group {
    route: String,
    role: &'static str,
    locator: String,
    /// Link target signature (empty for non-links).
    target: String,
    ordinal: Option<usize>,
    members: Vec<usize>,
    routes: BTreeSet<String>,
    global: bool,
    /// Same route/role/locator as another group with a different target:
    /// the key carries the target.
    disambiguate: bool,
}

impl Group {
    fn key(&self) -> String {
        let route = if self.global {
            "*"
        } else {
            self.route.as_str()
        };
        let mut key = format!("{route}|{}|{}", self.role, self.locator);
        if self.disambiguate && !self.target.is_empty() {
            key.push_str("->");
            key.push_str(&self.target);
        }
        if let Some(n) = self.ordinal {
            key.push_str(&format!("#{n}"));
        }
        key
    }

    fn region(&self, instances: &[Instance]) -> &'static str {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for m in &self.members {
            *counts.entry(instances[*m].region).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(r, _)| r)
            .unwrap_or(MAIN_REGION)
    }
}

/// Author-declared handles identify the same element wherever it renders.
fn is_declared_locator(locator: &str) -> bool {
    locator.starts_with("testid=") || locator.starts_with("id=")
}

/// Shell controls -- the same header/nav/footer/aside control (same label,
/// same target, same render file when known) on >= 60% of visited routes
/// (and >= 3 routes) -- become one control with route `*`. Main-content
/// controls stay on their route even when they share a target with the nav.
/// When no landmark is visible in an element's (depth-limited) ancestor
/// path, an identical DOM path on every route marks it as layout.
fn promote_globals(groups: &mut Vec<Group>, b: &Builder<'_>, visited: &BTreeSet<String>) {
    if visited.len() < GLOBAL_MIN_ROUTES {
        return;
    }
    type Identity = (&'static str, String, String, Option<String>);
    let mut by_identity: BTreeMap<Identity, Vec<usize>> = BTreeMap::new();
    for (i, g) in groups.iter().enumerate() {
        if g.ordinal.is_some() || !visited.contains(&g.route) {
            continue;
        }
        let region = g.region(&b.instances);
        let layout_path = g
            .members
            .iter()
            .all(|m| !b.instances[*m].region_known)
            .then(|| shared_structural(g, &b.instances))
            .flatten();
        if !(SHELL_REGIONS.contains(&region)
            || is_declared_locator(&g.locator)
            || layout_path.is_some())
        {
            continue;
        }
        by_identity
            .entry((
                g.role,
                g.locator.clone(),
                g.target.clone(),
                render_file(g, &b.instances).or(layout_path),
            ))
            .or_default()
            .push(i);
    }
    let mut merged_away: BTreeSet<usize> = BTreeSet::new();
    let mut promoted: Vec<Group> = Vec::new();
    for ((role, locator, target, _), idxs) in by_identity {
        let routes: BTreeSet<String> = idxs.iter().map(|i| groups[*i].route.clone()).collect();
        let share = routes.len() as f64 / visited.len() as f64;
        if routes.len() < GLOBAL_MIN_ROUTES || share < GLOBAL_MIN_SHARE {
            continue;
        }
        let mut members = Vec::new();
        for i in &idxs {
            members.extend(groups[*i].members.iter().copied());
            merged_away.insert(*i);
        }
        promoted.push(Group {
            route: "*".to_string(),
            role,
            locator,
            target,
            ordinal: None,
            members,
            routes,
            global: true,
            disambiguate: false,
        });
    }
    if promoted.is_empty() {
        return;
    }
    let mut kept: Vec<Group> = groups
        .drain(..)
        .enumerate()
        .filter(|(i, _)| !merged_away.contains(i))
        .map(|(_, g)| g)
        .collect();
    kept.extend(promoted);
    *groups = kept;
}

/// The one ancestor path every member shares, if any.
fn shared_structural(g: &Group, instances: &[Instance]) -> Option<String> {
    let mut paths = g
        .members
        .iter()
        .map(|m| instances[*m].structural.as_deref());
    let first = paths.next()??;
    paths.all(|p| p == Some(first)).then(|| first.to_string())
}

/// Render file from a framework annotation (`SiteHeader.astro`), when known.
fn render_file(g: &Group, instances: &[Instance]) -> Option<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for m in &g.members {
        if let Some(file) = instances[*m]
            .capture
            .as_ref()
            .and_then(|c| c.annotated.as_deref())
            .map(|a| a.split(':').next().unwrap_or(a).to_string())
        {
            *counts.entry(file).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|(f, _)| f)
}

/// Groups that share route, role, and locator but point at different targets
/// carry the target in their key.
fn assign_keys(groups: &mut [Group]) {
    let mut by_ns: HashMap<(String, &'static str, String, Option<usize>), BTreeSet<String>> =
        HashMap::new();
    for g in groups.iter() {
        let route = if g.global { "*" } else { g.route.as_str() };
        by_ns
            .entry((route.to_string(), g.role, g.locator.clone(), g.ordinal))
            .or_default()
            .insert(g.target.clone());
    }
    for g in groups.iter_mut() {
        let route = if g.global { "*" } else { g.route.as_str() };
        g.disambiguate = by_ns
            .get(&(route.to_string(), g.role, g.locator.clone(), g.ordinal))
            .is_some_and(|t| t.len() > 1);
    }
}

fn merge_evidence(g: &Group, instances: &[Instance]) -> Evidence {
    let mut out = Evidence::default();
    for idx in &g.members {
        let ev = &instances[*idx].ev;
        out.exercised |= ev.exercised;
        out.outcomes.extend(ev.outcomes.iter().cloned());
        for (k, c) in &ev.calls {
            out.add_call(k.clone(), c.status, c.blocked);
        }
        for e in &ev.errors {
            out.add_error(e.clone());
        }
        for e in &ev.tool_errors {
            if !out.tool_errors.contains(e) {
                out.tool_errors.push(e.clone());
            }
        }
        out.network_activity |= ev.network_activity;
        if out.skip.is_none() {
            out.skip = ev.skip.clone();
        }
        if out.elsewhere.is_none() {
            out.elsewhere = ev.elsewhere.clone();
        }
        out.dead_hint |= ev.dead_hint;
        out.already_active |= ev.already_active;
        out.retest_confirmed |= ev.retest_confirmed;
        out.retest_effect |= ev.retest_effect;
        out.retest_other |= ev.retest_other;
        out.handler |= ev.handler;
        if ev.exercised {
            out.exercised_members += 1;
            let counts_network =
                ev.network_activity && (is_interactive_control_role(g.role) || ev.handler);
            if !ev.has_effect() && ev.errors.is_empty() && !counts_network {
                out.no_effect_members += 1;
            }
        } else if !ev.tool_errors.is_empty() {
            out.tool_error_members += 1;
        }
    }
    out
}

/// Controls skipped as `exercised_elsewhere` take the evidence of the same
/// control on the route where it was exercised.
fn inherit_exercised_elsewhere(
    groups: &[Group],
    merged: &[Evidence],
    b: &Builder<'_>,
) -> HashMap<usize, (Evidence, String)> {
    let mut by_identity: HashMap<(&'static str, &str), Vec<usize>> = HashMap::new();
    for (i, g) in groups.iter().enumerate() {
        by_identity
            .entry((g.role, g.locator.as_str()))
            .or_default()
            .push(i);
    }
    let mut out = HashMap::new();
    for (gi, g) in groups.iter().enumerate() {
        let ev = &merged[gi];
        if ev.exercised || g.ordinal.is_some() {
            continue;
        }
        let Some(view) = ev.elsewhere.as_deref() else {
            continue;
        };
        let target_route = b.view_routes.get(view).cloned();
        let candidates = by_identity
            .get(&(g.role, g.locator.as_str()))
            .cloned()
            .unwrap_or_default();
        let source = candidates
            .into_iter()
            .filter(|o| *o != gi && merged[*o].exercised)
            .min_by_key(|o| {
                let same_route = target_route
                    .as_ref()
                    .is_some_and(|r| groups[*o].routes.contains(r));
                let same_target = groups[*o].target == g.target;
                (!same_route, !same_target, groups[*o].route.clone())
            });
        if let Some(src) = source {
            let mut inherited = merged[src].clone();
            inherited.skip = None;
            let route = if groups[src].global {
                "*".to_string()
            } else {
                groups[src].route.clone()
            };
            out.insert(gi, (inherited, route));
        }
    }
    out
}

/// For groups only seen in sub-views: the keys of the controls that opened them.
fn opener_keys(groups: &[Group], b: &Builder<'_>) -> HashMap<usize, Vec<String>> {
    let mut group_of: HashMap<usize, usize> = HashMap::new();
    for (gi, g) in groups.iter().enumerate() {
        for m in &g.members {
            group_of.insert(*m, gi);
        }
    }
    let mut out = HashMap::new();
    for (gi, g) in groups.iter().enumerate() {
        if g.members.iter().any(|m| !b.instances[*m].sub_view) {
            continue;
        }
        let mut keys: BTreeSet<String> = BTreeSet::new();
        for m in &g.members {
            let view = &b.instances[*m].view_id;
            for opener in b.openers.get(view).into_iter().flatten() {
                if let Some(og) = group_of.get(opener)
                    && *og != gi
                {
                    keys.insert(groups[*og].key());
                }
            }
        }
        if !keys.is_empty() {
            out.insert(gi, keys.into_iter().collect());
        }
    }
    out
}

/// Keep each member's entry context intact. In particular, an opened plain
/// page and a directly loaded query page must not become an unrestricted
/// plain-page observation when their control rows are grouped together.
fn observed_state_entries(
    groups: &[Group],
    b: &Builder<'_>,
) -> HashMap<usize, Vec<ControlStateEntry>> {
    let group_of: HashMap<usize, usize> = groups
        .iter()
        .enumerate()
        .flat_map(|(gi, g)| g.members.iter().map(move |m| (*m, gi)))
        .collect();
    let page_known = |m: &Instance| {
        !m.variant.as_deref().is_some_and(template_variant)
            && (m.page_presence_known || m.variant.is_some())
    };
    groups
        .iter()
        .enumerate()
        .map(|(gi, g)| {
            let mut entries = BTreeSet::new();
            for member in &g.members {
                let m = &b.instances[*member];
                let mut kinds = BTreeSet::new();
                if page_known(m) {
                    if !m.sub_view {
                        kinds.insert(ControlStateEntryKind::Direct);
                    } else {
                        for t in b.art.transitions.iter().filter(|t| t.to_view == m.view_id) {
                            let from = if t.trigger_view.is_empty() {
                                &t.from_view
                            } else {
                                &t.trigger_view
                            };
                            // Unlike the legacy summary, do not fall back to
                            // an arbitrary same-route selector. Entry proof
                            // needs the actual parent view and page context.
                            let opener_groups: BTreeSet<usize> = b
                                .by_view_sel
                                .get(&(from.clone(), t.trigger_selector.clone()))
                                .into_iter()
                                .flatten()
                                .filter(|idx| {
                                    let opener = &b.instances[**idx];
                                    page_known(opener)
                                        && opener.route == m.route
                                        && opener.variant == m.variant
                                })
                                .filter_map(|idx| group_of.get(idx).copied())
                                .collect();
                            // Multiple identities sharing the selector are
                            // ambiguous, even though their page agrees.
                            if opener_groups.len() == 1
                                && let Some(og) = opener_groups.first()
                                && *og != gi
                            {
                                kinds.insert(ControlStateEntryKind::Opened {
                                    opener: groups[*og].key(),
                                });
                            }
                        }
                    }
                }
                if kinds.is_empty() {
                    kinds.insert(ControlStateEntryKind::Unknown);
                }
                for kind in kinds {
                    // Do not cross aggregate record_variants with the
                    // aggregate view's entry kind. Raw records restore their
                    // own view/page instances in find_record_instance.
                    entries.insert(ControlStateEntry {
                        route: m.route.clone(),
                        variant: m.variant.clone(),
                        kind,
                    });
                }
            }
            (gi, entries.into_iter().collect())
        })
        .collect()
}

struct LinkCheck {
    errors: Vec<String>,
    verified: bool,
}

/// Same-origin link checks: HTTP status (crawl or probe), where redirects
/// land, and whether the target is a route of the app at all.
fn check_link(
    route: &str,
    urls: &[&str],
    b: &Builder<'_>,
    visited: &BTreeSet<String>,
    probe: &ProbeTable,
) -> LinkCheck {
    let mut statuses: Vec<(u16, Option<String>)> = Vec::new();
    for url in urls {
        let key = strip_fragment(url);
        if let Some(p) = probe.results.get(&key) {
            statuses.push((p.status, p.landed.clone()));
        }
        if let Some(s) = b.doc_by_url.get(&key) {
            statuses.push((*s, b.doc_redirect.get(&key).cloned()));
        }
    }
    if statuses.is_empty()
        && !route.contains("/#")
        && let Some(s) = b.doc_status.get(route)
    {
        statuses.push((*s, None));
    }
    let mut out = LinkCheck {
        errors: Vec::new(),
        verified: false,
    };
    if let Some(s) = statuses
        .iter()
        .map(|(s, _)| *s)
        .filter(|s| *s == 404 || *s == 410 || *s >= 500)
        .max()
    {
        out.errors.push(format!("link target {route} returned {s}"));
        return out;
    }
    let page_like = is_page_like_route(route);
    let known = !page_like || b.canon.is_known(route);
    let landed: Option<&str> = statuses.iter().find_map(|(_, l)| l.as_deref());
    if let Some(to) = landed {
        if !known && is_login_url(to) {
            out.errors.push(format!(
                "link target {route} redirects to login (unknown route)"
            ));
            return out;
        }
        // A redirect alias of a real page.
        out.verified = true;
        return out;
    }
    let ok_status = statuses.iter().any(|(s, _)| *s < 400);
    if !known {
        let server_404s = probe.soft_404 == Some(false);
        if !(server_404s && ok_status) {
            out.errors.push(format!(
                "link target {route} is not a route in source (unknown route)"
            ));
            return out;
        }
    }
    out.verified = ok_status || visited.contains(route);
    out
}

#[allow(clippy::too_many_arguments)]
fn finalize_control(
    g: &Group,
    ev: &Evidence,
    inherited_from: Option<&str>,
    b: &Builder<'_>,
    visited: &BTreeSet<String>,
    route_variants: &BTreeMap<String, BTreeSet<Option<String>>>,
    probe: &ProbeTable,
    has_interactions: bool,
) -> Option<Control> {
    let members: Vec<&Instance> = g.members.iter().map(|i| &b.instances[*i]).collect();
    let first = members.iter().min_by_key(|m| m.order).copied()?;

    // Count: max instances seen together on one page state. A raw view ID can
    // be reused after navigation; record-context clones are not simultaneous.
    let mut per_view: BTreeMap<(&str, &str), u32> = BTreeMap::new();
    for m in &members {
        *per_view
            .entry((m.view_id.as_str(), m.page_url.as_str()))
            .or_insert(0) += 1;
    }
    let count = per_view.values().copied().max().unwrap_or(1);

    // Most frequent label (ties: alphabetical); every distinct label is kept.
    let mut label_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in members.iter().filter(|m| !m.label.is_empty()) {
        *label_counts.entry(m.label.as_str()).or_insert(0) += 1;
    }
    let distinct: BTreeSet<String> = label_counts.keys().map(|l| normalize_text(l)).collect();
    let top = label_counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(l, _)| *l);
    let label = match top {
        None => fallback_label(first),
        Some(l) if distinct.len() > 1 => format!("{l} (+{} more)", distinct.len() - 1),
        Some(l) => l.to_string(),
    };
    let labels: Vec<String> = if label_counts.len() > 1 {
        label_counts
            .keys()
            .take(MAX_MEMBER_LABELS)
            .map(|l| l.to_string())
            .collect()
    } else {
        Vec::new()
    };

    let mut outcomes: BTreeSet<Outcome> = ev.outcomes.clone();
    for (endpoint, c) in &ev.calls {
        outcomes.insert(Outcome::Calls {
            endpoint: endpoint.clone(),
            status: c.status,
            blocked: c.blocked,
        });
    }
    let mut errors = ev.errors.clone();

    // Link targets: href outcome even when not clicked; status/route checks.
    let link = members.iter().find_map(|m| m.link.clone());
    let mut link_verified = false;
    match &link {
        Some(LinkTarget::Internal { route, .. }) => {
            outcomes.insert(Outcome::Navigates { to: route.clone() });
            let urls: Vec<&str> = members
                .iter()
                .filter_map(|m| match &m.link {
                    Some(LinkTarget::Internal { url, .. }) => Some(url.as_str()),
                    _ => None,
                })
                .collect();
            let check = check_link(route, &urls, b, visited, probe);
            for e in check.errors {
                if !errors.contains(&e) {
                    errors.push(e);
                }
            }
            link_verified = check.verified;
        }
        Some(LinkTarget::External(url)) => {
            outcomes.insert(Outcome::External { url: url.clone() });
        }
        Some(LinkTarget::Anchor { fragment, .. }) => {
            outcomes.insert(Outcome::Anchor {
                fragment: fragment.clone(),
            });
            // The page it points into is the one it is on.
            link_verified = true;
        }
        None => {}
    }

    let disabled = members.iter().all(|m| m.disabled);
    let validation_pending = members.iter().any(|m| m.validation_pending);
    let skip = ev.skip.clone();
    // Repeated tool-side failures on most attempts are reported as broken; an
    // isolated single timeout/tool error is unconfirmed and stays
    // `not_exercised` so transient stalls do not create false positives.
    let attempts = ev.exercised_members + ev.tool_error_members;
    let tool_broken = ev.tool_error_members >= 2 && ev.tool_error_members * 2 > attempts;
    if tool_broken && let Some(e) = ev.tool_errors.first() {
        errors.push(format!(
            "{e} (on {} of {attempts} attempts)",
            ev.tool_error_members
        ));
    }

    let (status, reason) = if !errors.is_empty() {
        (ControlStatus::Broken, Some(errors[0].clone()))
    } else if matches!(link, Some(LinkTarget::External(_))) {
        (ControlStatus::External, None)
    } else if ev.exercised {
        exercised_status(g, ev, link_verified, validation_pending, has_interactions)
    } else if link_verified {
        let reason = if matches!(link, Some(LinkTarget::Anchor { .. })) {
            "in-page anchor"
        } else {
            "href_target_reached"
        };
        (ControlStatus::Ok, Some(reason.to_string()))
    } else if let Some(reason) = skip {
        // The interaction pass can enable an initially disabled button. If
        // it stopped before checking that button, retain the recorded gap
        // instead of treating the discovery snapshot as its final state.
        (classify_skip(&reason), Some(reason))
    } else if disabled {
        (ControlStatus::Disabled, Some("disabled".to_string()))
    } else if ev.tool_error_members > 0 {
        let detail = ev
            .tool_errors
            .first()
            .cloned()
            .unwrap_or_else(|| "interaction_timeout".to_string());
        (ControlStatus::NotExercised, Some(detail))
    } else if matches!(link, Some(LinkTarget::Internal { .. })) {
        (
            ControlStatus::NotExercised,
            Some("href_not_followed".to_string()),
        )
    } else {
        let reason = if has_interactions {
            "not_attempted"
        } else {
            "no_outcome_recorded"
        };
        (ControlStatus::NotExercised, Some(reason.to_string()))
    };
    let reason = match (inherited_from, &status) {
        (
            Some(route),
            ControlStatus::Ok
            | ControlStatus::Dead
            | ControlStatus::NoEffect
            | ControlStatus::Broken,
        ) => Some(match reason {
            Some(r) => format!("{r}; exercised on {route}"),
            None => format!("exercised on {route}"),
        }),
        _ => reason,
    };
    let region = g.region(&b.instances);
    let mut seen: BTreeSet<Option<String>> = members
        .iter()
        .flat_map(|m| {
            if m.record_variants.is_empty() {
                BTreeSet::from([m.variant.clone()])
            } else {
                m.record_variants.clone()
            }
        })
        .collect();
    let dynamic = g.route.split('/').any(is_param);
    if dynamic && !g.global {
        // A synthetic spec instance has no concrete record provenance. It
        // must not make a record-specific control look universal.
        seen.retain(|v| v.as_deref().is_some_and(|v| !template_variant(v)));
        if seen.is_empty() {
            // Keep unknown provenance explicit for coverage-aware diffs.
            seen.insert(Some(g.route.clone()));
        }
    }
    let variants: Vec<String> = match route_variants.get(&g.route) {
        // Seen on the plain route, or on every variant: not state-specific.
        _ if g.global || seen.contains(&None) => Vec::new(),
        Some(all) if !dynamic && !all.is_empty() && all.is_subset(&seen) => Vec::new(),
        _ => seen
            .into_iter()
            .flatten()
            .take(MAX_ROUTE_VARIANTS)
            .collect(),
    };

    Some(Control {
        key: g.key(),
        route: if g.global {
            "*".to_string()
        } else {
            g.route.clone()
        },
        routes: if g.global {
            g.routes.iter().cloned().collect()
        } else {
            Vec::new()
        },
        role: g.role.to_string(),
        label,
        labels,
        region: region.to_string(),
        target: (!g.target.is_empty()).then(|| g.target.clone()),
        opened_by: Vec::new(),
        variants,
        state_entries: Vec::new(),
        selector: first.selector.clone(),
        locator: g.locator.clone(),
        count,
        status,
        outcomes: outcomes.into_iter().collect(),
        reason,
        href: members.iter().find_map(|m| m.href.clone()),
        source: None,
    })
}

/// Semantic interactive control roles (excluding generic `other` elements like
/// `<th>` or `<div>` that lack handler evidence).
fn is_interactive_control_role(role: &str) -> bool {
    matches!(
        role,
        "button" | "link" | "form" | "tab" | "input" | "select" | "checkbox" | "radio"
    )
}

/// Status of an exercised control with no app error.
fn exercised_status(
    g: &Group,
    ev: &Evidence,
    link_verified: bool,
    validation_pending: bool,
    has_interactions: bool,
) -> (ControlStatus, Option<String>) {
    if ev.has_effect() || link_verified && ev.no_effect_members < ev.exercised_members.max(1) {
        let reason = (ev.no_effect_members > 0).then(|| {
            format!(
                "no effect on {} of {} exercised instances",
                ev.no_effect_members, ev.exercised_members
            )
        });
        return (ControlStatus::Ok, reason);
    }
    let ok = |r: &str| (ControlStatus::Ok, Some(r.to_string()));
    if ev.network_activity && (is_interactive_control_role(g.role) || ev.handler) {
        return ok("network_activity_unattributed");
    }
    if is_input_role(g.role) {
        return ok("focus_only");
    }
    if validation_pending {
        return ok("validation_blocked");
    }
    if ev.retest_effect {
        return ok("effect on retest");
    }
    if ev.already_active {
        return ok("already active");
    }
    if ev.handler && is_drag_resize_locator(&g.locator) {
        return ok("drag_only_control");
    }
    if !has_interactions && !ev.dead_hint && link_verified {
        return (ControlStatus::Ok, None);
    }
    if ev.dead_hint {
        return (
            ControlStatus::Dead,
            Some("flagged by the dead-button detector".to_string()),
        );
    }
    // Dead is reserved for high confidence: nothing happened and nothing
    // suggests a handler ran.
    if ev.handler {
        return (ControlStatus::NoEffect, Some(HANDLER_NO_EFFECT.to_string()));
    }
    if ev.retest_other {
        return (
            ControlStatus::NoEffect,
            Some("no effect not confirmed on retest".to_string()),
        );
    }
    let reason = ev
        .retest_confirmed
        .then(|| "confirmed on retest".to_string());
    (ControlStatus::Dead, reason)
}

/// Drag-only resize/reorder controls with an attached handler (e.g.
/// `aria=resize sidebar`) respond to pointer drag rather than a single click.
fn is_drag_resize_locator(locator: &str) -> bool {
    let base = locator.split('@').next().unwrap_or(locator);
    let label = base
        .strip_prefix("aria=")
        .or_else(|| base.strip_prefix("text="))
        .unwrap_or(base)
        .trim();
    matches!(
        label,
        "resize sidebar"
            | "resize panel"
            | "resize pane"
            | "resize drawer"
            | "resize column"
            | "resize split"
            | "drag handle"
            | "drag to reorder"
    )
}

/// Skip reasons that mean "deliberately not exercised". Everything else
/// (`interaction_limit`, `hidden`, `obscured`, ...) is a coverage gap.
fn classify_skip(reason: &str) -> ControlStatus {
    let r = reason.to_ascii_lowercase();
    if r == "disabled" {
        return ControlStatus::Disabled;
    }
    if r.contains("hidden") || r.contains("obscured") || r.contains("not_visible") {
        return ControlStatus::NotExercised;
    }
    const DELIBERATE: &[&str] = &[
        "safety",
        "danger",
        "destructive",
        "logout",
        "log_out",
        "sign_out",
        "signout",
        "file",
        "upload",
        "scope",
        "write_guard",
        "auth",
        "excluded",
        "policy",
        "external",
    ];
    if DELIBERATE.iter().any(|d| r.contains(d)) {
        ControlStatus::Skipped
    } else {
        ControlStatus::NotExercised
    }
}

pub(super) fn coverage_summary(routes: &[RouteEntry], controls: &[Control]) -> CoverageSummary {
    let mut by_reason: BTreeMap<String, u32> = BTreeMap::new();
    for c in controls {
        if matches!(
            c.status,
            ControlStatus::NotExercised | ControlStatus::Skipped | ControlStatus::Disabled
        ) {
            let reason = c.reason.clone().unwrap_or_else(|| "unknown".to_string());
            *by_reason.entry(reason).or_insert(0) += 1;
        }
    }
    let n = |st: ControlStatus| controls.iter().filter(|c| c.status == st).count() as u32;
    let (external, disabled, skipped) = (
        n(ControlStatus::External),
        n(ControlStatus::Disabled),
        n(ControlStatus::Skipped),
    );
    let mut unvisited_by_reason: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in routes.iter().filter(|r| !r.visited) {
        unvisited_by_reason
            .entry(
                r.unvisited_reason
                    .clone()
                    .unwrap_or_else(|| "not linked or seeded".to_string()),
            )
            .or_default()
            .push(r.route.clone());
    }
    CoverageSummary {
        routes_known: routes.len() as u32,
        routes_visited: routes.iter().filter(|r| r.visited).count() as u32,
        controls_total: controls.len() as u32,
        controls_exercised: controls.iter().filter(|c| c.status.is_exercised()).count() as u32,
        controls_exercisable: (controls.len() as u32).saturating_sub(external + disabled + skipped),
        controls_external: external,
        controls_disabled: disabled,
        controls_skipped: skipped,
        not_exercised_by_reason: by_reason,
        obscured_top_covers: Vec::new(),
        unvisited_routes: routes
            .iter()
            .filter(|r| !r.visited)
            .map(|r| r.route.clone())
            .collect(),
        unvisited_by_reason,
    }
}

// ---------------------------------------------------------------------------
// Link probe
// ---------------------------------------------------------------------------

async fn probe_links(groups: &[Group], b: &Builder<'_>, merged: &[Evidence]) -> ProbeTable {
    let Some(base) = b.base.as_ref() else {
        return ProbeTable::default();
    };
    let mut urls: BTreeSet<String> = BTreeSet::new();
    for (gi, g) in groups.iter().enumerate() {
        if merged[gi]
            .skip
            .as_deref()
            .is_some_and(|r| classify_skip(r) == ControlStatus::Skipped)
        {
            continue;
        }
        for idx in &g.members {
            let m = &b.instances[*idx];
            let Some(LinkTarget::Internal { url, .. }) = &m.link else {
                continue;
            };
            let Ok(parsed) = Url::parse(url) else {
                continue;
            };
            if !same_origin(base, &parsed)
                || crate::explorer::url_utils::fragment_is_route(parsed.fragment())
            {
                continue;
            }
            let lower = format!("{} {}", parsed.path(), m.label).to_ascii_lowercase();
            if [
                "logout",
                "log-out",
                "signout",
                "sign-out",
                "sign out",
                "log out",
                "delete",
                "remove",
                "unsubscribe",
            ]
            .iter()
            .any(|w| lower.contains(w))
            {
                continue;
            }
            if looks_like_static_asset_path(parsed.path()) {
                continue;
            }
            urls.insert(strip_fragment(url));
        }
    }
    let mut urls: Vec<String> = urls.into_iter().take(PROBE_MAX_URLS).collect();
    if urls.is_empty() {
        return ProbeTable::default();
    }
    let canary = base
        .join(UNKNOWN_ROUTE_PROBE_PATH)
        .map(|u| u.to_string())
        .ok();
    if let Some(c) = &canary {
        urls.push(c.clone());
    }
    let client = match reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!("brokenapp-link-probe/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!("link probe disabled: {err}");
            return ProbeTable::default();
        }
    };
    let mut results: BTreeMap<String, ProbeResult> = futures::stream::iter(urls)
        .map(|url| {
            let client = client.clone();
            async move {
                let res = client
                    .get(&url)
                    .header("Accept", "text/html,*/*;q=0.8")
                    .send()
                    .await
                    .ok()
                    .map(|r| {
                        let final_url = strip_fragment(r.url().as_str());
                        ProbeResult {
                            status: r.status().as_u16(),
                            landed: (final_url != strip_fragment(&url)).then_some(final_url),
                        }
                    });
                (url, res)
            }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .filter_map(|(url, res)| async move { res.map(|r| (url, r)) })
        .collect()
        .await;
    let soft_404 = canary
        .and_then(|c| results.remove(&c))
        .map(|r| r.status < 400 && r.landed.is_none());
    ProbeTable { results, soft_404 }
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// Deterministic identity of a capture: annotation, else the render frame.
fn capture_signature(cap: &ElementSourceCapture) -> Option<String> {
    if let Some(a) = cap.annotated.as_deref().filter(|a| !a.is_empty()) {
        return Some(a.to_string());
    }
    let f = cap
        .frames
        .iter()
        .find(|f| f.role == "render")
        .or_else(|| cap.frames.first())?;
    Some(format!("{}:{}:{}", f.url, f.line, f.col))
}

/// The most common signature (ties: lexicographically first).
fn most_common<'s>(sigs: impl IntoIterator<Item = &'s str>) -> Option<&'s str> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for s in sigs {
        *counts.entry(s).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(s, _)| s)
}

/// The capture shared by most members (ties: lexicographically first), so a
/// grouped control's source does not depend on crawl order.
fn representative_capture(members: &[&Instance]) -> Option<(ElementSourceCapture, String)> {
    let with_sig: Vec<(String, &Instance)> = members
        .iter()
        .filter_map(|m| {
            let cap = m
                .capture
                .as_ref()
                .filter(|cap| !cap.frames.is_empty() || cap.annotated.is_some())?;
            Some((capture_signature(cap)?, *m))
        })
        .collect();
    let best = most_common(with_sig.iter().map(|(s, _)| s.as_str()))?;
    let m = with_sig
        .iter()
        .filter(|(s, _)| s == best)
        .map(|(_, m)| *m)
        .min_by_key(|m| m.order)?;
    m.capture.clone().map(|c| (c, m.page_url.clone()))
}

fn distinct_capture_sites(members: &[&Instance]) -> usize {
    members
        .iter()
        .filter_map(|m| m.capture.as_ref().and_then(capture_signature))
        .collect::<BTreeSet<_>>()
        .len()
}

/// A source that belongs to one member of a group rendered from several
/// places is not exact for the whole group.
fn downgrade_shared_source(c: &mut Control, g: &Group, b: &Builder<'_>) {
    let Some(src) = c.source.as_mut() else {
        return;
    };
    if src.confidence != "exact" {
        return;
    }
    let members: Vec<&Instance> = g.members.iter().map(|i| &b.instances[*i]).collect();
    if distinct_capture_sites(&members) > 1 {
        src.confidence = "probable".to_string();
    }
}

async fn resolve_control_sources(
    target_url: &str,
    codebase: &Path,
    groups: &[Group],
    b: &Builder<'_>,
    controls: &[Control],
    route_files: &HashMap<&str, &str>,
) -> BTreeMap<String, ResolvedSource> {
    let by_key: HashMap<String, &Group> = groups.iter().map(|g| (g.key(), g)).collect();
    let mut inputs = Vec::new();
    for c in controls {
        let Some(g) = by_key.get(&c.key) else {
            continue;
        };
        let mut members: Vec<&Instance> = g.members.iter().map(|i| &b.instances[*i]).collect();
        members.sort_by_key(|m| m.order);
        let static_route = if g.global {
            g.routes.iter().next().cloned().unwrap_or_default()
        } else {
            g.route.clone()
        };
        let route_file = route_files
            .get(static_route.as_str())
            .map(|f| f.to_string());
        inputs.push(sources::SourceInput {
            key: c.key.clone(),
            route: static_route,
            capture: representative_capture(&members),
            tag: members
                .iter()
                .map(|m| m.hints.tag.clone())
                .find(|t| !t.is_empty())
                .unwrap_or_default(),
            label: Some(c.label.clone()).filter(|l| !l.is_empty()),
            aria_label: members.iter().find_map(|m| m.hints.aria.clone()),
            test_id: members.iter().find_map(|m| m.hints.test_id.clone()),
            element_id: members.iter().find_map(|m| m.hints.element_id.clone()),
            name: members.iter().find_map(|m| m.hints.name.clone()),
            href: c.href.clone(),
            route_file,
        });
    }
    sources::resolve(target_url, codebase, &inputs).await
}

// ---------------------------------------------------------------------------
// Error locations
// ---------------------------------------------------------------------------

fn stack_location_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(https?://[^\s()/]+/[^\s()]*?):(\d+)(?::(\d+))?\b").expect("regex")
    })
}

/// Same-origin `url:line:col` stack positions in error reasons.
fn error_frames(controls: &[Control], base: Option<&Url>) -> Vec<(String, u32, u32)> {
    let mut out: BTreeSet<(String, u32, u32)> = BTreeSet::new();
    for c in controls {
        for msg in error_messages(c) {
            for cap in stack_location_re().captures_iter(msg) {
                let url = cap[1].to_string();
                if !Url::parse(&url).is_ok_and(|u| base.is_some_and(|b| same_origin(b, &u))) {
                    continue;
                }
                let line = cap[2].parse().unwrap_or(0);
                let col = cap
                    .get(3)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);
                out.insert((url, line, col));
            }
        }
    }
    out.into_iter().collect()
}

fn error_messages(c: &Control) -> Vec<&str> {
    let mut out: Vec<&str> = c
        .outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Error { message } => Some(message.as_str()),
            _ => None,
        })
        .collect();
    if c.status == ControlStatus::Broken
        && let Some(r) = c.reason.as_deref()
    {
        out.push(r);
    }
    out
}

/// Replace dev-server stack positions with repo `file:line` (resolved through
/// source maps while the server was up), or drop bundle-chunk noise.
fn rewrite_error_locations(
    c: &mut Control,
    base: Option<&Url>,
    resolved: &BTreeMap<(String, u32, u32), crate::code_link::runtime_source::FileLine>,
) {
    let rewrite = |msg: &str| -> String {
        stack_location_re()
            .replace_all(msg, |cap: &regex::Captures<'_>| {
                let url = &cap[1];
                let Ok(parsed) = Url::parse(url) else {
                    return cap[0].to_string();
                };
                if !base.is_some_and(|b| same_origin(b, &parsed)) {
                    return cap[0].to_string();
                }
                let line: u32 = cap[2].parse().unwrap_or(0);
                let col: u32 = cap
                    .get(3)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);
                if let Some(fl) = resolved.get(&(url.to_string(), line, col)) {
                    return format!("{}:{}", fl.file, fl.line);
                }
                let path = parsed.path();
                if is_bundle_path(path) {
                    "bundled code".to_string()
                } else {
                    format!("{}:{line} (unmapped)", path.trim_start_matches('/'))
                }
            })
            .into_owned()
    };
    for o in &mut c.outcomes {
        if let Outcome::Error { message } = o {
            *message = rewrite(message);
        }
    }
    if c.status == ControlStatus::Broken
        && let Some(r) = c.reason.as_mut()
    {
        *r = rewrite(r);
    }
}

/// Served bundles (as opposed to dev-served source modules like `/src/x.tsx`).
fn is_bundle_path(path: &str) -> bool {
    path.starts_with("/_next/")
        || path.starts_with("/assets/")
        || path.starts_with("/_astro/")
        || path.starts_with("/build/")
        || path.contains("/node_modules/")
        || path.contains("/.vite/")
        || path.starts_with("/@")
        || path.contains("/chunks/")
        || path.contains("/chunk-")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn first_line(s: &str) -> String {
    let line = s
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let mut out: String = line.chars().take(200).collect();
    if line.chars().count() > 200 {
        out.push('…');
    }
    out
}

fn clean_label(s: &str) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = collapsed.chars().take(120).collect();
    if collapsed.chars().count() > 120 {
        out.push('…');
    }
    out
}

fn fallback_label(inst: &Instance) -> String {
    inst.hints
        .aria
        .clone()
        .or_else(|| inst.hints.name.clone())
        .or_else(|| inst.hints.test_id.clone())
        .or_else(|| {
            inst.hints
                .element_id
                .as_deref()
                .filter(|id| !is_generated_id(id))
                .map(str::to_string)
        })
        .map(|s| clean_label(&s))
        .unwrap_or_default()
}

/// Normalized non-empty label used to distinguish unrelated UI controls during
/// background-polling detection (falls back to accessible/id/name attributes
/// for unlabeled inputs like `#amount`).
fn control_poll_label(inst: &Instance) -> String {
    if !inst.label.is_empty() {
        normalize_text(&inst.label)
    } else {
        let fb = fallback_label(inst);
        if fb.is_empty() {
            String::new()
        } else {
            normalize_text(&fb)
        }
    }
}

fn row_matches_net_activity(
    rec: &InteractionNetActivity,
    row: &NetRow,
    attributed_idx: usize,
) -> bool {
    if rec.instance_idx != attributed_idx {
        return false;
    }
    if let Some(row_aid) = row.action_id.as_deref().filter(|id| !id.is_empty()) {
        return rec.action_id.as_deref() == Some(row_aid);
    }
    let Some((view, selector)) = row.trigger.as_ref() else {
        return false;
    };
    if view != &rec.view_id || selector != &rec.selector {
        return false;
    }
    match (rec.window, row.occurred_at) {
        (Some((start, end)), Some(at)) => {
            let t = at.timestamp_millis();
            t >= start - 1_000 && t <= end + ACTION_WINDOW_SLACK_MS
        }
        _ => true,
    }
}

fn element_tag(el: &InteractiveElement) -> String {
    match &el.element_type {
        ElementType::Other { tag, .. } => tag.to_ascii_lowercase(),
        ElementType::NavigationLink { .. } => "a".to_string(),
        ElementType::SelectDropdown { .. } => "select".to_string(),
        ElementType::TextInput { input_type, .. } if input_type == "textarea" => {
            "textarea".to_string()
        }
        ElementType::TextInput { .. }
        | ElementType::Checkbox { .. }
        | ElementType::RadioButton { .. }
        | ElementType::FileUpload { .. } => "input".to_string(),
        _ => el
            .locators
            .iter()
            .filter(|l| l.kind == LocatorKind::Structural)
            .find_map(|l| tag_from_selector(&l.value))
            .or_else(|| tag_from_selector(&el.selector))
            .unwrap_or_default(),
    }
}

fn strip_fragment(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut u) => {
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => url.split('#').next().unwrap_or(url).to_string(),
    }
}

fn is_page_like_route(route: &str) -> bool {
    let path = route.split("/#").next().unwrap_or(route);
    if looks_like_static_asset_path(path) || is_dev_tool_path(path) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    ![
        ".pdf", ".zip", ".csv", ".xml", ".json", ".txt", ".xlsx", ".docx",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
        && !lower.starts_with("/api/")
}

/// A sign-in page (`/login`, `/sign-in`, `/auth/...`), where auth gates land.
pub(super) fn is_login_url(url: &str) -> bool {
    let path = Url::parse(url)
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_else(|_| url.to_ascii_lowercase());
    path.split('/').any(|seg| {
        matches!(
            seg,
            "login" | "log-in" | "signin" | "sign-in" | "sign_in" | "auth" | "authenticate"
        )
    })
}

/// Dev-server/bundler tooling path (HMR, overlays, module serving).
pub(super) fn is_dev_tool_path(path: &str) -> bool {
    let path = path
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or(path);
    DEV_TOOL_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn normalized_host(u: &Url) -> String {
    match u.host_str() {
        Some("localhost") | Some("127.0.0.1") | Some("[::1]") | Some("::1") => {
            "localhost".to_string()
        }
        Some(h) => h.to_ascii_lowercase(),
        None => String::new(),
    }
}

/// Same origin, treating loopback names and ws/http schemes as equivalent.
fn same_origin(a: &Url, b: &Url) -> bool {
    fn norm_scheme(s: &str) -> &str {
        match s {
            "ws" => "http",
            "wss" => "https",
            other => other,
        }
    }
    norm_scheme(a.scheme()) == norm_scheme(b.scheme())
        && a.port_or_known_default() == b.port_or_known_default()
        && normalized_host(a) == normalized_host(b)
}

fn is_telemetry(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        let host = host.to_ascii_lowercase();
        TELEMETRY_HOSTS
            .iter()
            .any(|t| host == *t || host.ends_with(&format!(".{t}")))
    })
}

fn is_api_like(row: &NetRow, url: &Url) -> bool {
    if row.method.eq_ignore_ascii_case("WS") {
        return !is_dev_tool_path(url.path());
    }
    if let Some(is_api) = row.is_api {
        return is_api;
    }
    let path = url.path();
    if looks_like_static_asset_path(path) {
        return false;
    }
    if path.starts_with("/api/") || path.starts_with("/graphql") {
        return true;
    }
    if row.method != "GET" && row.method != "HEAD" {
        return true;
    }
    row.mime.as_deref().is_some_and(|m| {
        let m = m.to_ascii_lowercase();
        m.contains("json") || m.contains("graphql") || m.contains("event-stream")
    })
}

/// The scanner's `endpoint_key` when recorded; otherwise the same identity
/// rebuilt from the row: `METHOD /path/template`, origin-prefixed when
/// cross-origin (`POST https://x.supabase.co/rest/v1/cart`), GraphQL
/// operations (`POST /graphql#MUTATION Name`) and Next.js Server Actions
/// (`POST /path#action:<id>`) split out.
fn endpoint_key(row: &NetRow, url: &Url, base: Option<&Url>) -> String {
    if let Some(k) = row.endpoint.as_deref().filter(|k| !k.trim().is_empty()) {
        return k.to_string();
    }
    let mut path = path_to_template(url.path());
    if base.is_some_and(|b| !same_origin(b, url)) && url.origin().is_tuple() {
        path = format!("{}{path}", url.origin().ascii_serialization());
    }
    if let Some(op) =
        crate::network::graphql::detect_graphql_request(url.as_str(), row.post_data.as_deref())
    {
        path = crate::network::graphql::graphql_endpoint_key(&path, &op).path_template;
    } else if let Some(action) = row.next_action.as_deref().filter(|_| row.method == "POST") {
        path = format!("{path}#action:{action}");
    }
    format!("{} {path}", row.method)
}

fn detect_write_guard(rows: &[NetRow]) -> String {
    let mut modes: BTreeSet<&str> = BTreeSet::new();
    for r in rows {
        if let Some(g) = r.write_guard.as_deref() {
            match g {
                "blocked" | "block" => {
                    modes.insert("block");
                }
                "stubbed" | "stub" => {
                    modes.insert("stub");
                }
                _ => {}
            }
        }
    }
    if modes.contains("stub") {
        "stub".to_string()
    } else if modes.contains("block") {
        "block".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Classify a post-interaction snapshot, ignoring focus/ripple/tooltip noise.
fn snapshot_change_kind(s: &InteractionSnapshot) -> Option<String> {
    if s.modal_opened.is_some() {
        return Some("modal".to_string());
    }
    if s.attribute_changes
        .iter()
        .any(|c| c.attribute == "aria-expanded" || c.attribute == "open")
    {
        return Some("menu".to_string());
    }
    if s.appeared_text.iter().any(|t| t.kind == "error") {
        return Some("validation".to_string());
    }
    if s.appeared_text
        .iter()
        .any(|t| t.kind == "success" || t.kind == "info")
    {
        return Some("toast".to_string());
    }
    const NOISE: &[&str] = &["ripple", "tooltip", "focus", "hover", "active", "pressed"];
    let noisy = |s: &str| {
        let s = s.to_ascii_lowercase();
        NOISE.iter().any(|n| s.contains(n))
    };
    let meaningful_elements = s
        .appeared_elements
        .iter()
        .any(|e| !(noisy(&e.selector) || e.element_kind == "text" && e.label.is_none()));
    let meaningful_attrs = s.attribute_changes.iter().any(|c| {
        if c.attribute != "class" {
            return !noisy(&c.attribute);
        }
        let before: BTreeSet<&str> = c
            .old_value
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        let after: BTreeSet<&str> = c
            .new_value
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        before
            .symmetric_difference(&after)
            .any(|cls| !noisy(cls) && !cls.starts_with("ng-") && !cls.starts_with("cdk-"))
    });
    if meaningful_elements || meaningful_attrs || !s.side_effects.is_empty() || s.truncated {
        return Some("other".to_string());
    }
    if !s.appeared_text.is_empty() {
        return Some("other".to_string());
    }
    None
}

#[cfg(test)]
pub(super) mod tests_support {
    /// The render-site signature a group's source is resolved from.
    pub fn representative_signature(sigs: &[&str]) -> Option<String> {
        super::most_common(sigs.iter().copied()).map(str::to_string)
    }

    /// Inspect attribution before canonical grouping can combine equal keys.
    pub fn record_match_metadata(
        scan_dir: &std::path::Path,
        record: &crate::output::interactions::InteractionRecord,
    ) -> Option<serde_json::Value> {
        let art = super::artifacts::load(scan_dir).unwrap();
        let mut builder = super::Builder::new(
            &art,
            url::Url::parse(&art.target_url).ok(),
            super::RouteCanon::new(&[]),
            super::ApiPatterns::default(),
        );
        builder.collect_spec_instances();
        let idx = builder.find_record_instance(record)?;
        let instance = &builder.instances[idx];
        Some(serde_json::json!({
            "view_id": instance.view_id,
            "page_url": instance.page_url,
            "route": instance.route,
            "variant": instance.variant,
            "role": instance.role,
            "locator": instance.locator,
            "structural": instance.structural,
            "capture": instance.capture,
            "target": super::resolved_record_href(instance.href.as_deref(), &instance.page_url),
            "link_url": match &instance.link {
                Some(super::LinkTarget::Internal { url, .. }) => Some(url),
                _ => None,
            },
            "exercised": instance.ev.exercised,
            "outcomes": instance.ev.outcomes,
            "record_variants": instance.record_variants,
        }))
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::output::interactions::{INTERACTIONS_FILE, InteractionOutcome, InteractionRecord};
    use serde_json::json;

    const BASE: &str = "http://127.0.0.1:3000";

    async fn build_fixture(
        views: Vec<serde_json::Value>,
        interactions: &[InteractionRecord],
        network: &[serde_json::Value],
    ) -> Inventory {
        let dir = tempfile::tempdir().unwrap();
        let spec = json!({
            "meta": { "target_url": BASE },
            "views": views,
            "api_surface": { "endpoints": [] },
            "state_machine": { "transitions": [] },
        });
        std::fs::write(
            dir.path().join("spec.json"),
            serde_json::to_vec_pretty(&spec).unwrap(),
        )
        .unwrap();
        let mut inter_buf = String::new();
        for rec in interactions {
            inter_buf.push_str(&serde_json::to_string(rec).unwrap());
            inter_buf.push('\n');
        }
        std::fs::write(dir.path().join(INTERACTIONS_FILE), inter_buf).unwrap();
        if !network.is_empty() {
            let mut net_buf = String::new();
            for row in network {
                net_buf.push_str(&serde_json::to_string(row).unwrap());
                net_buf.push('\n');
            }
            std::fs::write(dir.path().join("network.jsonl"), net_buf).unwrap();
        }
        let opts = BuildOptions {
            project: "test-app".into(),
            target_url: BASE.into(),
            ..Default::default()
        };
        build_with(dir.path(), &opts, Some(ProbeTable::default()))
            .await
            .unwrap()
    }

    fn base_record(
        view: &str,
        route: &str,
        selector: &str,
        kind: &str,
        outcome: InteractionOutcome,
    ) -> InteractionRecord {
        let mut rec = InteractionRecord::new(view, &format!("{BASE}{route}"), selector, kind);
        rec.outcome = outcome;
        rec.started_at = "2026-11-20T10:00:00Z".into();
        rec.duration_ms = 150;
        rec
    }

    fn save_item_view() -> Vec<serde_json::Value> {
        vec![json!({
            "id": "v1",
            "route": "/staff/inventory",
            "url": format!("{BASE}/staff/inventory"),
            "elements": [{
                "selector": "#save-item",
                "label": "Save item",
                "found_on": "v1",
                "element_type": { "kind": "button", "form_submit": true },
                "locators": [{ "kind": "id", "value": "#save-item", "stability": 0.85, "unique": true }]
            }]
        })]
    }

    #[tokio::test]
    async fn write_guarded_server_action_abort_errors_stay_ok_while_real_errors_stay_broken() {
        let abort_errors = [
            "TypeError: Failed to fetch @ at async w.fetch (<anonymous>:260:34)",
            "TypeError: Failed to fetch @ at async fetchServerAction (http://127.0.0.1:3000/_next/static/chunks/app-pages-internals.js:45:12)",
            "Uncaught (in promise) TypeError: Failed to fetch",
            "Failed to fetch",
            "TypeError: Load failed",
            "TypeError: NetworkError when attempting to fetch resource.",
            "Failed to load resource: net::ERR_FAILED",
            "Failed to load resource: net::ERR_ABORTED",
            "Failed to load resource: net::ERR_BLOCKED_BY_CLIENT",
            "net::ERR_ABORTED",
        ];

        for msg in abort_errors {
            let mut rec = base_record(
                "v1",
                "/staff/inventory",
                "#save-item",
                "button",
                InteractionOutcome::NoEffect,
            );
            rec.label = Some("Save item".into());
            rec.action_id = Some("act-1".into());
            rec.console_errors = vec![msg.to_string()];

            let blocked_sa = json!({
                "occurred_at": "2026-11-20T10:00:00.050Z",
                "trace": { "action_id": "act-1", "cdp_request_id": "req-1" },
                "triggered_by": { "view": "v1", "selector": "#save-item" },
                "request": {
                    "method": "POST",
                    "url": format!("{BASE}/staff/inventory"),
                    "headers": { "next-action": "7f3a1234" }
                },
                "failure": "net::ERR_BLOCKED_BY_CLIENT",
                "write_guard": "blocked"
            });

            let inv = build_fixture(save_item_view(), &[rec], &[blocked_sa]).await;

            let ctl = inv
                .controls
                .iter()
                .find(|c| c.key == "/staff/inventory|button|id=save-item")
                .unwrap();
            assert_eq!(ctl.status, ControlStatus::Ok, "msg={msg} ctl={ctl:?}");
            assert!(
                ctl.outcomes.iter().any(|o| matches!(
                    o,
                    Outcome::Calls { endpoint, blocked: true, .. }
                        if endpoint == "POST /staff/inventory [server action]"
                )),
                "msg={msg} outcomes={:?}",
                ctl.outcomes
            );
            assert!(
                !ctl.outcomes
                    .iter()
                    .any(|o| matches!(o, Outcome::Error { .. })),
                "msg={msg} outcomes={:?}",
                ctl.outcomes
            );
        }

        // Un-ID'd write-blocked Server Action attributed via (view, selector) window stays Ok.
        let mut window_rec = base_record(
            "v1",
            "/staff/inventory",
            "#save-item",
            "button",
            InteractionOutcome::NoEffect,
        );
        window_rec.label = Some("Save item".into());
        window_rec.action_id = Some("act-untagged".into());
        window_rec.console_errors = vec!["TypeError: Failed to fetch".into()];
        let untagged_blocked = json!({
            "occurred_at": "2026-11-20T10:00:00.050Z",
            "triggered_by": { "view": "v1", "selector": "#save-item" },
            "request": {
                "method": "POST",
                "url": format!("{BASE}/staff/inventory"),
                "headers": { "next-action": "7f3a1234" }
            },
            "failure": "net::ERR_BLOCKED_BY_CLIENT",
            "write_guard": "blocked"
        });
        let inv_window = build_fixture(save_item_view(), &[window_rec], &[untagged_blocked]).await;
        assert_eq!(inv_window.controls[0].status, ControlStatus::Ok);

        // Real non-fetch runtime errors remain Broken even with a blocked Server Action.
        for real_err in [
            "ReferenceError: missingHandler is not defined",
            "TypeError: Cannot read properties of undefined (reading 'id')",
        ] {
            let mut rec = base_record(
                "v1",
                "/staff/inventory",
                "#save-item",
                "button",
                InteractionOutcome::NoEffect,
            );
            rec.label = Some("Save item".into());
            rec.action_id = Some("act-real".into());
            rec.console_errors = vec!["TypeError: Failed to fetch".into(), real_err.to_string()];
            let blocked_sa = json!({
                "occurred_at": "2026-11-20T10:00:00.050Z",
                "trace": { "action_id": "act-real" },
                "triggered_by": { "view": "v1", "selector": "#save-item" },
                "request": {
                    "method": "POST",
                    "url": format!("{BASE}/staff/inventory"),
                    "headers": { "next-action": "7f3a1234" }
                },
                "write_guard": "blocked"
            });
            let inv = build_fixture(save_item_view(), &[rec], &[blocked_sa]).await;
            assert_eq!(inv.controls[0].status, ControlStatus::Broken, "{real_err}");
        }

        // HTTP 500 on the same action also remains Broken.
        let mut rec_500 = base_record(
            "v1",
            "/staff/inventory",
            "#save-item",
            "button",
            InteractionOutcome::NoEffect,
        );
        rec_500.label = Some("Save item".into());
        rec_500.action_id = Some("act-500".into());
        rec_500.console_errors = vec!["TypeError: Failed to fetch".into()];
        let blocked_500 = json!({
            "occurred_at": "2026-11-20T10:00:00.050Z",
            "trace": { "action_id": "act-500" },
            "triggered_by": { "view": "v1", "selector": "#save-item" },
            "request": {
                "method": "POST",
                "url": format!("{BASE}/staff/inventory"),
                "headers": { "next-action": "7f3a1234" }
            },
            "write_guard": "blocked"
        });
        let http_500 = json!({
            "occurred_at": "2026-11-20T10:00:00.060Z",
            "trace": { "action_id": "act-500" },
            "triggered_by": { "view": "v1", "selector": "#save-item" },
            "request": {
                "method": "GET",
                "url": format!("{BASE}/api/inventory/check"),
                "headers": {}
            },
            "response": { "status": 500, "headers": {}, "mime_type": "application/json" },
            "is_api": true
        });
        let inv_500 = build_fixture(save_item_view(), &[rec_500], &[blocked_500, http_500]).await;
        assert_eq!(inv_500.controls[0].status, ControlStatus::Broken);
    }

    #[tokio::test]
    async fn unattributed_network_activity_does_not_flip_static_other_elements() {
        let th_view = |with_handler: bool| {
            let mut el = json!({
                "selector": "table > thead > tr > th",
                "label": "Property Details",
                "found_on": "v1",
                "element_type": { "kind": "other", "tag": "th", "role": null },
                "locators": []
            });
            if with_handler {
                el["source"] = json!({ "frames": [], "handlers": ["onClick"] });
            }
            vec![json!({
                "id": "v1",
                "route": "/deals",
                "url": format!("{BASE}/deals"),
                "elements": [
                    el,
                    {
                        "selector": "#refresh-btn",
                        "label": "Refresh",
                        "found_on": "v1",
                        "element_type": { "kind": "button", "form_submit": false },
                        "locators": [{ "kind": "id", "value": "#refresh-btn", "stability": 0.85, "unique": true }]
                    }
                ]
            })]
        };

        let mut th_with_net = base_record(
            "v1",
            "/deals",
            "table > thead > tr > th",
            "other",
            InteractionOutcome::NoEffect,
        );
        th_with_net.label = Some("Property Details".into());
        th_with_net.network_activity = true;

        let mut th_without_net = th_with_net.clone();
        th_without_net.network_activity = false;

        let mut btn_with_net = base_record(
            "v1",
            "/deals",
            "#refresh-btn",
            "button",
            InteractionOutcome::NoEffect,
        );
        btn_with_net.label = Some("Refresh".into());
        btn_with_net.network_activity = true;

        let run1 = build_fixture(
            th_view(false),
            &[th_with_net.clone(), btn_with_net.clone()],
            &[],
        )
        .await;
        let run2 = build_fixture(th_view(false), &[th_without_net, btn_with_net], &[]).await;

        let th1 = run1
            .controls
            .iter()
            .find(|c| c.label == "Property Details")
            .unwrap();
        let th2 = run2
            .controls
            .iter()
            .find(|c| c.label == "Property Details")
            .unwrap();
        assert_ne!(th1.status, ControlStatus::Ok);
        assert_eq!(
            th1.status, th2.status,
            "static <th> must not flip across runs"
        );
        let diff = crate::inventory::diff(Some(&run1), &run2);
        assert!(
            !diff.changes.iter().any(|c| c.kind == "now_dead"),
            "no spurious NOW DEAD on static <th>: {diff:?}"
        );

        // Interactive roles (button) and `other` elements with handler evidence still use unattributed network activity.
        let btn1 = run1.controls.iter().find(|c| c.label == "Refresh").unwrap();
        assert_eq!(btn1.status, ControlStatus::Ok);
        assert_eq!(
            btn1.reason.as_deref(),
            Some("network_activity_unattributed")
        );

        let run_handler = build_fixture(th_view(true), &[th_with_net], &[]).await;
        let th_handler = run_handler
            .controls
            .iter()
            .find(|c| c.label == "Property Details")
            .unwrap();
        assert_eq!(th_handler.status, ControlStatus::Ok);
        assert_eq!(
            th_handler.reason.as_deref(),
            Some("network_activity_unattributed")
        );
    }

    #[tokio::test]
    async fn app_wrapped_write_guard_console_errors_stay_ok_while_real_errors_stay_broken() {
        let wrapped_abort_errors = [
            "Failed to save settings: TypeError: Failed to fetch @ at w.fetch (<anonymous>:275:34)",
            "Error submitting contact form: Failed to fetch @ at async w.fetch (<anonymous>:260:34)",
            "Failed to save: TypeError: Failed to fetch",
            "Inquiry error: Failed to fetch.",
            "Failed to save TypeError: Failed to fetch",
            "Save failed - net::ERR_BLOCKED_BY_CLIENT",
            "Save failed: net::ERR_FAILED",
            "Request failed: NetworkError",
            "Submit failed: Load failed",
        ];

        for msg in wrapped_abort_errors {
            let mut rec = base_record(
                "v1",
                "/staff/inventory",
                "#save-item",
                "button",
                InteractionOutcome::NoEffect,
            );
            rec.label = Some("Save item".into());
            rec.action_id = Some("act-wrap".into());
            rec.console_errors = vec![msg.to_string()];

            let blocked = json!({
                "occurred_at": "2026-11-20T10:00:00.050Z",
                "trace": { "action_id": "act-wrap", "cdp_request_id": "req-1" },
                "triggered_by": { "view": "v1", "selector": "#save-item" },
                "request": {
                    "method": "POST",
                    "url": format!("{BASE}/api/settings"),
                    "headers": {}
                },
                "failure": "net::ERR_BLOCKED_BY_CLIENT",
                "write_guard": "blocked"
            });

            let inv = build_fixture(save_item_view(), &[rec], &[blocked]).await;
            let ctl = inv
                .controls
                .iter()
                .find(|c| c.key == "/staff/inventory|button|id=save-item")
                .unwrap();
            assert_eq!(ctl.status, ControlStatus::Ok, "msg={msg} ctl={ctl:?}");
            assert!(
                ctl.outcomes
                    .iter()
                    .any(|o| matches!(o, Outcome::Calls { blocked: true, .. })),
                "msg={msg} outcomes={:?}",
                ctl.outcomes
            );
            assert!(
                !ctl.outcomes
                    .iter()
                    .any(|o| matches!(o, Outcome::Error { .. })),
                "msg={msg} outcomes={:?}",
                ctl.outcomes
            );
        }

        // Negative cases must remain Broken even when paired with a blocked write.
        let real_errors = [
            "TypeError: Failed to fetch configuration",
            "Failed to save settings: Failed to fetch configuration",
            "Unknown event handler property 'onPlaceSelect'",
            "Failed to save settings: TypeError: Failed to fetch @ at onClick (http://app.local/page.js:260:34)",
            "NotFailed to fetch",
        ];
        for msg in real_errors {
            let mut rec = base_record(
                "v1",
                "/staff/inventory",
                "#save-item",
                "button",
                InteractionOutcome::NoEffect,
            );
            rec.label = Some("Save item".into());
            rec.action_id = Some("act-real".into());
            rec.console_errors = vec![msg.to_string()];

            let blocked = json!({
                "occurred_at": "2026-11-20T10:00:00.050Z",
                "trace": { "action_id": "act-real" },
                "triggered_by": { "view": "v1", "selector": "#save-item" },
                "request": {
                    "method": "POST",
                    "url": format!("{BASE}/api/settings"),
                    "headers": {}
                },
                "failure": "net::ERR_BLOCKED_BY_CLIENT",
                "write_guard": "blocked"
            });

            let inv = build_fixture(save_item_view(), &[rec], &[blocked]).await;
            let ctl = inv
                .controls
                .iter()
                .find(|c| c.key == "/staff/inventory|button|id=save-item")
                .unwrap();
            assert_eq!(ctl.status, ControlStatus::Broken, "msg={msg} ctl={ctl:?}");
        }

        // Real HTTP 500 on the same action keeps the control Broken even with a wrapped fetch error.
        let mut rec_500 = base_record(
            "v1",
            "/staff/inventory",
            "#save-item",
            "button",
            InteractionOutcome::NoEffect,
        );
        rec_500.label = Some("Save item".into());
        rec_500.action_id = Some("act-500".into());
        rec_500.console_errors = vec![
            "Failed to save settings: TypeError: Failed to fetch @ at w.fetch (<anonymous>:275:34)"
                .into(),
        ];
        let blocked_500 = json!({
            "occurred_at": "2026-11-20T10:00:00.050Z",
            "trace": { "action_id": "act-500" },
            "triggered_by": { "view": "v1", "selector": "#save-item" },
            "request": {
                "method": "POST",
                "url": format!("{BASE}/api/settings"),
                "headers": {}
            },
            "write_guard": "blocked"
        });
        let http_500 = json!({
            "occurred_at": "2026-11-20T10:00:00.060Z",
            "trace": { "action_id": "act-500" },
            "triggered_by": { "view": "v1", "selector": "#save-item" },
            "request": {
                "method": "GET",
                "url": format!("{BASE}/api/settings/validate"),
                "headers": {}
            },
            "response": { "status": 500, "headers": {}, "mime_type": "application/json" },
            "is_api": true
        });
        let inv_500 = build_fixture(save_item_view(), &[rec_500], &[blocked_500, http_500]).await;
        assert_eq!(inv_500.controls[0].status, ControlStatus::Broken);
    }

    #[tokio::test]
    async fn obscured_top_covers_aggregates_sorts_and_caps_at_five() {
        let covers: &[(&str, Option<&str>, &str)] = &[
            ("#b1", Some("div[data-radix-overlay]"), "obscured"),
            ("#b2", Some("div[data-radix-overlay]"), "obscured"),
            ("#b3", Some("div[data-radix-overlay]"), "obscured"),
            ("#b4", Some(".ai-chat-widget"), "obscured"),
            ("#b5", Some(".ai-chat-widget"), "obscured"),
            ("#b6", Some(".banner-b"), "obscured"),
            ("#b7", Some(".banner-a"), "obscured"),
            ("#b8", Some(".cookie-modal"), "obscured"),
            ("#b9", Some(".zeta-toast"), "obscured"),
            // No cover detail -> ignored in top covers
            ("#b10", None, "obscured"),
            // Non-obscured skip reason -> ignored
            ("#b11", Some(".should-ignore"), "hidden"),
        ];

        let mut elements = Vec::new();
        let mut records = Vec::new();
        for (idx, (sel, cover, reason)) in covers.iter().enumerate() {
            elements.push(json!({
                "selector": sel,
                "label": format!("Button {idx}"),
                "found_on": "v1",
                "element_type": { "kind": "button", "form_submit": false },
                "locators": [{ "kind": "id", "value": sel, "stability": 0.85, "unique": true }]
            }));
            let mut rec = base_record("v1", "/", sel, "button", InteractionOutcome::Skipped);
            rec.action = "skip".into();
            rec.label = Some(format!("Button {idx}"));
            rec.skipped_reason = Some((*reason).into());
            rec.obscured_by = cover.map(str::to_string);
            records.push(rec);
        }

        let views = vec![json!({
            "id": "v1",
            "route": "/",
            "url": format!("{BASE}/"),
            "elements": elements
        })];

        let inv = build_fixture(views, &records, &[]).await;
        assert_eq!(
            inv.coverage.not_exercised_by_reason.get("obscured"),
            Some(&10)
        );
        assert_eq!(
            inv.coverage.obscured_top_covers,
            vec![
                ObscuredCover {
                    cover: "div[data-radix-overlay]".into(),
                    count: 3,
                },
                ObscuredCover {
                    cover: ".ai-chat-widget".into(),
                    count: 2,
                },
                ObscuredCover {
                    cover: ".banner-a".into(),
                    count: 1,
                },
                ObscuredCover {
                    cover: ".banner-b".into(),
                    count: 1,
                },
                ObscuredCover {
                    cover: ".cookie-modal".into(),
                    count: 1,
                },
            ]
        );
    }

    #[tokio::test]
    async fn background_heartbeat_and_polling_endpoints_excluded_from_controls_and_diff_stable() {
        let views = vec![json!({
            "id": "v1",
            "route": "/dashboard",
            "url": format!("{BASE}/dashboard"),
            "elements": [
                {
                    "selector": "#amount",
                    "label": "",
                    "found_on": "v1",
                    "element_type": { "kind": "text_input", "input_type": "text", "name": "amount" },
                    "locators": [{ "kind": "id", "value": "#amount", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#tab-b",
                    "label": "Tab B",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": false },
                    "locators": [{ "kind": "id", "value": "#tab-b", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#export",
                    "label": "Export",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": false },
                    "locators": [{ "kind": "id", "value": "#export", "stability": 0.85, "unique": true }]
                }
            ]
        })];

        let mut rec_amount_run1 = base_record(
            "v1",
            "/dashboard",
            "#amount",
            "text_input",
            InteractionOutcome::NoEffect,
        );
        rec_amount_run1.action_id = Some("act-amount".into());
        rec_amount_run1.network_activity = true;

        let mut rec_tab_run1 = base_record(
            "v1",
            "/dashboard",
            "#tab-b",
            "button",
            InteractionOutcome::DomChange,
        );
        rec_tab_run1.label = Some("Tab B".into());
        rec_tab_run1.dom_change = Some("tab".into());
        rec_tab_run1.action_id = Some("act-tab".into());
        rec_tab_run1.network_activity = true;

        let mut rec_export_run1 = base_record(
            "v1",
            "/dashboard",
            "#export",
            "button",
            InteractionOutcome::NoEffect,
        );
        rec_export_run1.label = Some("Export".into());
        rec_export_run1.action_id = Some("act-export".into());
        rec_export_run1.network_activity = true;

        // Run 1: periodic POST /api/session/renew, 5s GET /api/periods/status
        // (seen on __page_load__ + #amount + Tab B), and GET /api/notifications/unread
        // (seen across 3 distinct controls #amount, Tab B, Export) all tick during clicks.
        let net_run1 = vec![
            json!({
                "occurred_at": "2026-11-20T10:00:00.010Z",
                "triggered_by": { "view": "v1", "selector": "__page_load__" },
                "request": { "method": "GET", "url": format!("{BASE}/api/periods/status"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.050Z",
                "trace": { "action_id": "act-amount" },
                "triggered_by": { "view": "v1", "selector": "#amount" },
                "request": { "method": "POST", "url": format!("{BASE}/api/session/renew"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.060Z",
                "trace": { "action_id": "act-amount" },
                "triggered_by": { "view": "v1", "selector": "#amount" },
                "request": { "method": "GET", "url": format!("{BASE}/api/periods/status"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.070Z",
                "trace": { "action_id": "act-tab" },
                "triggered_by": { "view": "v1", "selector": "#tab-b" },
                "request": { "method": "GET", "url": format!("{BASE}/api/periods/status"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.080Z",
                "trace": { "action_id": "act-amount" },
                "triggered_by": { "view": "v1", "selector": "#amount" },
                "request": { "method": "GET", "url": format!("{BASE}/api/notifications/unread"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.090Z",
                "trace": { "action_id": "act-tab" },
                "triggered_by": { "view": "v1", "selector": "#tab-b" },
                "request": { "method": "GET", "url": format!("{BASE}/api/notifications/unread"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.100Z",
                "trace": { "action_id": "act-export" },
                "triggered_by": { "view": "v1", "selector": "#export" },
                "request": { "method": "GET", "url": format!("{BASE}/api/notifications/unread"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
        ];

        // Run 2: none of the background timers happen to align with clicks
        // (only __page_load__ fires GET /api/periods/status).
        let mut rec_amount_run2 = rec_amount_run1.clone();
        rec_amount_run2.network_activity = false;
        let mut rec_tab_run2 = rec_tab_run1.clone();
        rec_tab_run2.network_activity = false;
        let mut rec_export_run2 = rec_export_run1.clone();
        rec_export_run2.network_activity = false;
        let net_run2 = vec![json!({
            "occurred_at": "2026-11-20T10:05:00.010Z",
            "triggered_by": { "view": "v1", "selector": "__page_load__" },
            "request": { "method": "GET", "url": format!("{BASE}/api/periods/status"), "headers": {} },
            "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
            "is_api": true
        })];

        let inv1 = build_fixture(
            views.clone(),
            &[rec_amount_run1, rec_tab_run1, rec_export_run1],
            &net_run1,
        )
        .await;
        let inv2 = build_fixture(
            views,
            &[rec_amount_run2, rec_tab_run2, rec_export_run2],
            &net_run2,
        )
        .await;

        let amount1 = inv1
            .controls
            .iter()
            .find(|c| c.key == "/dashboard|input|id=amount")
            .unwrap();
        assert!(
            amount1.endpoints().next().is_none(),
            "heartbeat/poll must not attach to #amount: {:?}",
            amount1.outcomes
        );
        assert_eq!(amount1.status, ControlStatus::Ok);
        assert_eq!(amount1.reason.as_deref(), Some("focus_only"));

        let tab1 = inv1
            .controls
            .iter()
            .find(|c| c.key == "/dashboard|button|id=tab-b")
            .unwrap();
        assert!(
            tab1.endpoints().next().is_none(),
            "poll must not attach to Tab B: {:?}",
            tab1.outcomes
        );
        assert_eq!(
            tab1.outcomes,
            vec![Outcome::DomChange { kind: "tab".into() }]
        );

        let export1 = inv1
            .controls
            .iter()
            .find(|c| c.key == "/dashboard|button|id=export")
            .unwrap();
        assert!(
            export1.endpoints().next().is_none(),
            "poll must not attach to Export: {:?}",
            export1.outcomes
        );
        // Spurious network_activity from the suppressed poll must be cleared so
        // Export does not flap between Ok(network_activity_unattributed) and Dead.
        assert_eq!(export1.status, ControlStatus::Dead);

        // On-load traffic is still preserved for GET /api/periods/status, with no controls.
        let periods = inv1
            .endpoints
            .iter()
            .find(|e| e.endpoint == "GET /api/periods/status")
            .expect("on-load poll kept in endpoint index");
        assert_eq!(periods.on_load, vec!["/dashboard"]);
        assert!(periods.controls.is_empty());

        // Consecutive inventory builds stay completely diff-stable (no REWIRED / ENDPOINT REMOVED / NOW DEAD).
        let diff = crate::inventory::diff(Some(&inv1), &inv2);
        assert!(
            diff.changes.is_empty(),
            "expected zero diff noise between runs, got: {:?}",
            diff.changes
        );
    }

    #[tokio::test]
    async fn real_shared_and_single_control_endpoints_remain_attributed() {
        let views = vec![json!({
            "id": "v1",
            "route": "/orders",
            "url": format!("{BASE}/orders"),
            "elements": [
                {
                    "selector": "#del-1",
                    "label": "Delete",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": false },
                    "locators": [{ "kind": "id", "value": "#del-1", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#del-2",
                    "label": "Delete",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": false },
                    "locators": [{ "kind": "id", "value": "#del-2", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#del-3",
                    "label": "Delete",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": false },
                    "locators": [{ "kind": "id", "value": "#del-3", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#save",
                    "label": "Save",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": true },
                    "locators": [{ "kind": "id", "value": "#save", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#add",
                    "label": "Add",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": false },
                    "locators": [{ "kind": "id", "value": "#add", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#submit",
                    "label": "Submit",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": true },
                    "locators": [{ "kind": "id", "value": "#submit", "stability": 0.85, "unique": true }]
                },
                {
                    "selector": "#refresh",
                    "label": "Refresh",
                    "found_on": "v1",
                    "element_type": { "kind": "button", "form_submit": false },
                    "locators": [{ "kind": "id", "value": "#refresh", "stability": 0.85, "unique": true }]
                }
            ]
        })];

        let make_rec = |sel: &str, label: &str, aid: &str| {
            let mut r = base_record("v1", "/orders", sel, "button", InteractionOutcome::NoEffect);
            r.label = Some(label.into());
            r.action_id = Some(aid.into());
            r.network_activity = true;
            r
        };

        let records = vec![
            make_rec("#del-1", "Delete", "act-del-1"),
            make_rec("#del-2", "Delete", "act-del-2"),
            make_rec("#del-3", "Delete", "act-del-3"),
            make_rec("#save", "Save", "act-save"),
            make_rec("#add", "Add", "act-add"),
            make_rec("#submit", "Submit", "act-submit"),
            make_rec("#refresh", "Refresh", "act-refresh"),
        ];

        let net = vec![
            json!({
                "occurred_at": "2026-11-20T10:00:00.010Z",
                "triggered_by": { "view": "v1", "selector": "__page_load__" },
                "request": { "method": "GET", "url": format!("{BASE}/api/orders"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.020Z",
                "trace": { "action_id": "act-del-1" },
                "triggered_by": { "view": "v1", "selector": "#del-1" },
                "request": { "method": "DELETE", "url": format!("{BASE}/api/items/1"), "headers": {} },
                "write_guard": "blocked"
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.030Z",
                "trace": { "action_id": "act-del-2" },
                "triggered_by": { "view": "v1", "selector": "#del-2" },
                "request": { "method": "DELETE", "url": format!("{BASE}/api/items/2"), "headers": {} },
                "write_guard": "blocked"
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.040Z",
                "trace": { "action_id": "act-del-3" },
                "triggered_by": { "view": "v1", "selector": "#del-3" },
                "request": { "method": "DELETE", "url": format!("{BASE}/api/items/3"), "headers": {} },
                "write_guard": "blocked"
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.050Z",
                "trace": { "action_id": "act-save" },
                "triggered_by": { "view": "v1", "selector": "#save" },
                "request": { "method": "POST", "url": format!("{BASE}/api/settings"), "headers": {} },
                "write_guard": "blocked"
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.060Z",
                "trace": { "action_id": "act-add" },
                "triggered_by": { "view": "v1", "selector": "#add" },
                "request": { "method": "POST", "url": format!("{BASE}/api/orders"), "headers": {} },
                "write_guard": "blocked"
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.070Z",
                "trace": { "action_id": "act-submit" },
                "triggered_by": { "view": "v1", "selector": "#submit" },
                "request": { "method": "POST", "url": format!("{BASE}/api/orders"), "headers": {} },
                "write_guard": "blocked"
            }),
            json!({
                "occurred_at": "2026-11-20T10:00:00.080Z",
                "trace": { "action_id": "act-refresh" },
                "triggered_by": { "view": "v1", "selector": "#refresh" },
                "request": { "method": "GET", "url": format!("{BASE}/api/orders"), "headers": {} },
                "response": { "status": 200, "headers": {}, "mime_type": "application/json" },
                "is_api": true
            }),
        ];

        let inv = build_fixture(views, &records, &net).await;
        let eps_by_label = |label: &str| {
            inv.controls
                .iter()
                .filter(|c| c.label == label)
                .flat_map(|c| c.endpoints())
                .collect::<Vec<_>>()
        };

        assert!(
            eps_by_label("Delete").contains(&"DELETE /api/items/:id"),
            "{:?}",
            inv.controls
        );
        assert_eq!(eps_by_label("Save"), vec!["POST /api/settings"]);
        assert_eq!(eps_by_label("Add"), vec!["POST /api/orders"]);
        assert_eq!(eps_by_label("Submit"), vec!["POST /api/orders"]);
        assert_eq!(eps_by_label("Refresh"), vec!["GET /api/orders"]);
    }

    #[tokio::test]
    async fn ui_errors_mark_control_broken_and_ws_calls_count_as_ok() {
        let mut toast_rec = base_record(
            "v1",
            "/staff/inventory",
            "#save-item",
            "button",
            InteractionOutcome::DomChange,
        );
        toast_rec.label = Some("Save item".into());
        toast_rec.action_id = Some("act-toast".into());
        toast_rec.dom_change = Some("error_toast".into());
        toast_rec.ui_errors = vec![
            "Setting not saved: This connection lacks permission to change these settings.".into(),
        ];

        let inv_broken = build_fixture(save_item_view(), &[toast_rec], &[]).await;
        let ctl = &inv_broken.controls[0];
        assert_eq!(ctl.status, ControlStatus::Broken);
        assert!(
            ctl.reason
                .as_deref()
                .is_some_and(|r| r.contains("lacks permission")),
            "reason={:?}",
            ctl.reason
        );

        let mut ws_rec = base_record(
            "v1",
            "/staff/inventory",
            "#save-item",
            "button",
            InteractionOutcome::NoEffect,
        );
        ws_rec.label = Some("Save item".into());
        ws_rec.action_id = Some("act-ws".into());
        ws_rec.network_activity = true;
        ws_rec.side_effects = vec!["websocket_guarded".into()];

        let ws_row = json!({
            "occurred_at": "2026-11-20T10:00:00.050Z",
            "trace": { "action_id": "act-ws", "cdp_request_id": "ws-guard-1" },
            "triggered_by": { "view": "v1", "selector": "#save-item" },
            "request": {
                "method": "WS",
                "url": "ws://127.0.0.1:3000/ws",
                "headers": {},
                "post_data": "{\"_tag\":\"Request\",\"tag\":\"server.upsertKeybinding\"}"
            },
            "is_api": true,
            "endpoint_key": "WS /ws#server.upsertKeybinding",
            "write_guard": "blocked"
        });
        let inv_ws = build_fixture(save_item_view(), &[ws_rec], &[ws_row]).await;
        let ws_ctl = &inv_ws.controls[0];
        assert_eq!(ws_ctl.status, ControlStatus::Ok, "ws_ctl={ws_ctl:?}");
        assert!(
            ws_ctl.outcomes.iter().any(|o| matches!(
                o,
                Outcome::Calls { endpoint, blocked: true, .. }
                    if endpoint == "WS /ws#server.upsertKeybinding"
            )),
            "outcomes={:?}",
            ws_ctl.outcomes
        );
    }
}
