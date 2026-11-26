pub mod coverage;
pub mod cycle_detection;
mod engine;
mod form_mapping;
mod interaction;
pub mod interrupt;
pub mod priority;
mod route_seeds;
pub mod run_report;
pub mod scheduler;
pub mod state_machine;
pub mod template_sampler;
pub mod url_utils;

pub use coverage::{CoverageGap, CoverageGapKind, CoverageGapReport, CoverageSummary};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::browser::{BrowserLaunchOptions, BrowserManager};
use crate::bugs::BugDetector;
use crate::config::{AuthConfig, BrokenAppConfig};
use crate::explorer::template_sampler::TemplateSampler;
use crate::network::interceptor::{NetworkInterceptor, NetworkLogWriter};
use crate::network::schema_inference;
use crate::output::{
    self,
    checkpoint::{CheckpointWriter, PendingTransition, ScanCheckpoint},
    interactions::InteractionLog,
};
use crate::scope::{ScopeFilter, load_scope_filter};
use crate::session::SessionManager;
use crate::types::api::{ApiEndpoint, EndpointKey, HttpMethod};
use crate::types::bugs::Bug;
use crate::types::classifier::ComponentType;
use crate::types::graph::{AppView, ViewTransition};

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub scan_duration_seconds: u64,
    pub completion_status: String,
    pub target_url: String,
    pub output_dir: PathBuf,
    pub network_log_path: Option<PathBuf>,
    pub views: Vec<AppView>,
    pub template_sampler: TemplateSampler,
    pub transitions: Vec<ViewTransition>,
    pub endpoints: Vec<ApiEndpoint>,
    pub bugs: Vec<Bug>,
    pub coverage: CoverageSummary,
    pub coverage_gaps: CoverageGapReport,
}

/// Upper bound for `scan.max_concurrent_tabs`: tabs share one Chrome and the
/// app's dev server, which stop scaling long before this.
pub const MAX_CONCURRENT_TABS: usize = 8;

/// Environment override for `scan.max_concurrent_tabs`. `brokenapp map`
/// passes its environment to the scan it runs.
pub const CONCURRENT_TABS_ENV: &str = "BROKENAPP_MAX_CONCURRENT_TABS";

/// Page workers (tabs) a crawl runs: `scan.max_concurrent_tabs`, or the
/// `BROKENAPP_MAX_CONCURRENT_TABS` override, clamped to
/// 1..=[`MAX_CONCURRENT_TABS`].
pub fn crawl_tab_count(cfg: &BrokenAppConfig) -> usize {
    let env = std::env::var(CONCURRENT_TABS_ENV).ok();
    resolve_tab_count(cfg.scan.max_concurrent_tabs, env.as_deref())
}

fn resolve_tab_count(configured: usize, env_override: Option<&str>) -> usize {
    let requested = match env_override.map(str::trim) {
        Some(raw) => match raw.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    value = %raw,
                    "{CONCURRENT_TABS_ENV} is not a number; using scan.max_concurrent_tabs"
                );
                configured
            }
        },
        None => configured,
    };
    let tabs = requested.clamp(1, MAX_CONCURRENT_TABS);
    if tabs != requested {
        tracing::warn!(
            requested,
            tabs,
            "max_concurrent_tabs out of range (1-{MAX_CONCURRENT_TABS}); clamped"
        );
    }
    tabs
}

/// Runtime state shared by the crawl's page workers. Locked only for
/// synchronous sections, never across an `.await`.
type SharedState<'a> = std::sync::Mutex<&'a mut RuntimeState>;

fn lock_state<'g, 'a>(
    shared: &'g SharedState<'a>,
) -> std::sync::MutexGuard<'g, &'a mut RuntimeState> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Bookkeeping of the crawl loop, shared by its page workers.
#[derive(Debug, Clone)]
struct LoopControl {
    /// Queue items popped (visited or skipped).
    processed_items: usize,
    /// Visits started and not finished yet.
    in_flight: usize,
    /// A stop condition was met or the queue drained: no new visits start.
    stopping: bool,
    last_new_fingerprint_at: Instant,
    recent_new_fingerprints: VecDeque<bool>,
    last_progress_emit_at: Instant,
    last_progress_file_write: Instant,
    /// Highest view number handed out (`view_0007` is 7).
    last_view_number: usize,
    /// View identities (route + DOM skeleton) being explored right now: a
    /// view is explored by one tab at a time.
    active_views: HashSet<String>,
    /// Control-identity scopes (route template, else route) with a visit in
    /// flight, and how many. A URL whose scope is busy waits: sibling
    /// instances of a template share page-content controls, and exercising
    /// them in parallel would split stateful widgets (a quantity's "more"
    /// and "fewer") across instances.
    busy_scopes: HashMap<String, usize>,
    /// Visits in flight by visit number: a checkpoint taken meanwhile puts
    /// their URLs back in the queue and leaves their partial views out, so
    /// a resume explores them again from the start.
    in_flight_visits: BTreeMap<u64, InFlightVisit>,
    next_visit_number: u64,
    /// Why the crawl stopped (`run_report::stop_reason`), once it did.
    stop_reason: Option<&'static str>,
    /// Page creations that failed in a row (the browser may be gone).
    consecutive_page_failures: usize,
}

/// A visit in progress, as a checkpoint sees it.
#[derive(Debug, Clone)]
struct InFlightVisit {
    item: crate::output::checkpoint::QueuedUrl,
    /// View identity being explored (inserted in `visited_fingerprints`).
    view_key: Option<String>,
    /// View id being explored (its sub-views may be recorded already).
    view_id: Option<String>,
    /// Sampling is committed only when the visit finishes. Interrupted or
    /// withdrawn visits must not consume the template's sampling budget.
    template_sample: Option<PendingTemplateSample>,
}

#[derive(Debug, Clone)]
struct PendingTemplateSample {
    url: String,
    fingerprint: String,
    view_id: String,
}

impl LoopControl {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            processed_items: 0,
            in_flight: 0,
            stopping: false,
            last_new_fingerprint_at: now,
            recent_new_fingerprints: VecDeque::new(),
            last_progress_emit_at: now,
            last_progress_file_write: now,
            last_view_number: 0,
            active_views: HashSet::new(),
            busy_scopes: HashMap::new(),
            in_flight_visits: BTreeMap::new(),
            next_visit_number: 0,
            stop_reason: None,
            consecutive_page_failures: 0,
        }
    }

    /// Stop the crawl for `reason` (the first reason wins).
    fn stop(&mut self, reason: &'static str) {
        self.stopping = true;
        self.stop_reason.get_or_insert(reason);
    }
}

#[derive(Debug, Clone)]
struct RuntimeState {
    scheduler: scheduler::ScanScheduler,

    visited_fingerprints: HashSet<String>,
    fingerprint_to_view: HashMap<String, String>,
    url_to_view: HashMap<String, String>,
    attempted_urls: HashSet<String>,
    seeded_route_sources: BTreeMap<String, Vec<String>>,

    views: Vec<AppView>,
    pending_transitions: Vec<PendingTransition>,
    expanded_nav_dropdown_triggers: HashSet<String>,

    template_sampler: TemplateSampler,

    elements_discovered: usize,
    elements_interacted: usize,
    coverage_gaps: Vec<CoverageGap>,

    /// Set to true after the "no API traffic" hint has been shown once.
    no_traffic_warned: bool,

    /// Route templates that have been visited (for canary-before-new-route).
    visited_route_templates: BTreeSet<String>,

    /// Controls already exercised (shell controls scan-wide, page content per
    /// route template), so later views record them as `exercised_elsewhere`
    /// instead of clicking them again.
    exercised_controls: interaction::ExercisedControls,

    /// Concrete paths explored per route template, in visit order (the
    /// instance number decides how fully an instance is exercised).
    template_instances: HashMap<String, Vec<String>>,
    /// URLs whose navigation failed once and were queued for one retry.
    navigation_retries: HashSet<String>,
    /// URLs reloaded once because they rendered far fewer elements than
    /// comparable views (lazy route content).
    revisited_urls: HashSet<String>,
    /// Element counts of explored top-level views, overall and per template.
    view_element_counts: Vec<usize>,
    template_element_counts: HashMap<String, Vec<usize>>,
    /// Route scopes (route template, else path) of the explored views: a
    /// queued URL outside them is a route not visited yet, which keeps the
    /// stagnation and convergence stops from ending the crawl.
    visited_route_scopes: HashSet<String>,
    /// Auth session history (re-logins, expiry) across the crawl.
    session_log: run_report::SessionLog,
    /// Times this scan was resumed.
    resumes: u32,
    /// Highest view number found in a resumed checkpoint (ids are never
    /// reused, also for visits a checkpoint abandoned).
    resumed_view_number: usize,
    /// Views whose evidence was withdrawn: visits cut off when the crawl
    /// stopped, or overlapped by a re-login and explored again under a new
    /// view id. Their `interactions.jsonl` rows are dropped when the scan
    /// is finalized.
    retracted_views: BTreeSet<String>,
    /// URLs explored again because a re-login happened during their visit
    /// (once each).
    session_retries: HashSet<String>,
    /// Crawl loop bookkeeping (reset when a crawl starts).
    ctl: LoopControl,
}

/// Number of a view id (`view_0007` and `view_0007:d1:2` are 7).
fn view_number(view_id: &str) -> Option<usize> {
    view_id
        .strip_prefix("view_")?
        .split(':')
        .next()?
        .parse()
        .ok()
}

/// Base view of a (sub-)view id (`view_0007:d1:2` is `view_0007`).
fn base_view_id(view_id: &str) -> &str {
    view_id.split(':').next().unwrap_or(view_id)
}

/// Route scope of a URL: its route template when it is an instance of one,
/// else its path, with observed UI query selections and hash routes kept.
fn route_scope_of(sampler: &TemplateSampler, url: &str) -> String {
    let route = sampler
        .template_of(url)
        .or_else(|| template_sampler::url_to_template_path(url))
        .unwrap_or_else(|| url.to_string());
    url_utils::ui_state_scope(route, url)
}

impl RuntimeState {
    /// The next view id. Ids follow the number of views (sub-views
    /// included) and never repeat, also when views are explored in
    /// parallel or a visit is abandoned after its id was handed out.
    fn allocate_view_id(&mut self) -> String {
        let n = self
            .views
            .len()
            .max(self.ctl.last_view_number)
            .max(self.resumed_view_number)
            + 1;
        self.ctl.last_view_number = n;
        format!("view_{n:04}")
    }

    /// Start a visit of `item`: it counts as in flight until
    /// [`Self::finish_visit`] or [`Self::abandon_visit`].
    fn begin_visit(&mut self, item: &crate::output::checkpoint::QueuedUrl) -> u64 {
        self.ctl.next_visit_number += 1;
        let number = self.ctl.next_visit_number;
        self.ctl.in_flight_visits.insert(
            number,
            InFlightVisit {
                item: item.clone(),
                view_key: None,
                view_id: None,
                template_sample: None,
            },
        );
        number
    }

    /// The visit decided to explore `view_key` as `view_id`.
    fn visit_explores(&mut self, number: u64, view_key: &str, view_id: &str) {
        if let Some(v) = self.ctl.in_flight_visits.get_mut(&number) {
            v.view_key = Some(view_key.to_string());
            v.view_id = Some(view_id.to_string());
        }
    }

    fn finish_visit(&mut self, number: u64) {
        if let Some(visit) = self.ctl.in_flight_visits.remove(&number)
            && let Some(sample) = visit.template_sample
            && let Some(outcome) = self.template_sampler.record_visit(
                &sample.url,
                &sample.fingerprint,
                &sample.view_id,
            )
            && outcome.new_variant
        {
            tracing::info!(
                template = %outcome.template,
                variants = outcome.variants,
                example_url = %sample.url,
                fingerprint = %sample.fingerprint,
                "new layout variant discovered"
            );
        }
    }

    fn sample_when_visit_finishes(
        &mut self,
        number: u64,
        url: &str,
        fingerprint: &str,
        view_id: &str,
    ) {
        if let Some(visit) = self.ctl.in_flight_visits.get_mut(&number) {
            visit.template_sample = Some(PendingTemplateSample {
                url: url.to_string(),
                fingerprint: fingerprint.to_string(),
                view_id: view_id.to_string(),
            });
        }
    }

    /// The visit was cut off (the crawl was stopped or interrupted): put its
    /// URL back at the front of the queue and drop what it recorded of its
    /// view, so the view is explored again from the start.
    fn abandon_visit(&mut self, number: u64) {
        let Some(visit) = self.ctl.in_flight_visits.remove(&number) else {
            return;
        };
        self.withdraw_visit(&visit);
    }

    /// A re-login happened while visit `number` explored its view: what it
    /// observed may come from the expired session. Explore the view again
    /// under the new session (once per URL; then its evidence is kept).
    fn retry_visit_after_relogin(&mut self, number: u64) -> bool {
        let Some(visit) = self.ctl.in_flight_visits.get(&number) else {
            return false;
        };
        let canonical = crate::explorer::url_utils::canonicalize_crawl_url(&visit.item.url);
        if !self.session_retries.insert(canonical) {
            return false;
        }
        if let Some(visit) = self.ctl.in_flight_visits.remove(&number) {
            self.withdraw_visit(&visit);
        }
        true
    }

    /// Drop what a visit recorded of its view and put its URL back at the
    /// front of the queue. The view id is retired (a new visit gets a new
    /// one) and its interaction rows are dropped at finalization.
    fn withdraw_visit(&mut self, visit: &InFlightVisit) {
        if let Some(key) = visit.view_key.as_deref() {
            self.visited_fingerprints.remove(key);
        }
        if let Some(view_id) = visit.view_id.as_deref() {
            self.retracted_views.insert(view_id.to_string());
            self.fingerprint_to_view.retain(|_, v| v != view_id);
            self.url_to_view.retain(|_, v| v != view_id);
            self.views.retain(|v| base_view_id(&v.id) != view_id);
            self.pending_transitions
                .retain(|t| base_view_id(&t.from_view) != view_id);
            self.exercised_controls
                .retain(|_, c| base_view_id(&c.view_id) != view_id);
            let prefix = format!("{view_id}::");
            self.expanded_nav_dropdown_triggers
                .retain(|k| !k.starts_with(&prefix));
        }
        self.scheduler
            .requeue_front(&visit.item.url, visit.item.depth);
    }

    /// View ids of the visits in flight (their partial state is left out of
    /// checkpoints).
    fn in_flight_view_ids(&self) -> HashSet<&str> {
        self.ctl
            .in_flight_visits
            .values()
            .filter_map(|v| v.view_id.as_deref())
            .collect()
    }

    /// Whether `url` (just taken from the queue) or a queued URL belongs to a
    /// route no view was explored for yet, that the crawl would still visit.
    /// The stagnation and convergence stops wait for those.
    fn unvisited_route_pending(&self, cfg: &BrokenAppConfig, url: &str) -> bool {
        let unvisited = |u: &str| {
            !self.template_sampler.is_saturated_url(u)
                && !self
                    .visited_route_scopes
                    .contains(&route_scope_of(&self.template_sampler, u))
        };
        unvisited(url)
            || self
                .scheduler
                .queue_snapshot()
                .iter()
                .any(|q| q.depth <= cfg.scan.max_depth && unvisited(&q.url))
    }

    fn new(entry_url: String) -> Self {
        url_utils::register_route_fragment_from_url(&entry_url);
        let scheduler = scheduler::ScanScheduler::new(entry_url);
        Self {
            scheduler,
            visited_fingerprints: HashSet::new(),
            fingerprint_to_view: HashMap::new(),
            url_to_view: HashMap::new(),
            attempted_urls: HashSet::new(),
            seeded_route_sources: BTreeMap::new(),
            views: Vec::new(),
            pending_transitions: Vec::new(),
            expanded_nav_dropdown_triggers: HashSet::new(),
            template_sampler: TemplateSampler::default(),
            elements_discovered: 0,
            elements_interacted: 0,
            coverage_gaps: Vec::new(),
            no_traffic_warned: false,
            visited_route_templates: BTreeSet::new(),
            exercised_controls: HashMap::new(),
            template_instances: HashMap::new(),
            navigation_retries: HashSet::new(),
            revisited_urls: HashSet::new(),
            view_element_counts: Vec::new(),
            template_element_counts: HashMap::new(),
            visited_route_scopes: HashSet::new(),
            session_log: run_report::SessionLog::default(),
            resumes: 0,
            resumed_view_number: 0,
            retracted_views: BTreeSet::new(),
            session_retries: HashSet::new(),
            ctl: LoopControl::new(),
        }
    }

    fn from_checkpoint(cp: ScanCheckpoint) -> (Self, Vec<ApiEndpoint>, Vec<Bug>) {
        url_utils::register_route_fragment_from_url(cp.config.target.url.as_str());
        for q in &cp.queue {
            url_utils::register_route_fragment_from_url(&q.url);
        }
        for u in &cp.queued_urls {
            url_utils::register_route_fragment_from_url(u);
        }
        for v in &cp.views {
            url_utils::register_route_fragment_from_url(&v.url);
        }
        for u in cp.url_to_view.keys() {
            url_utils::register_route_fragment_from_url(u);
        }
        let crawl = cp.crawl;
        let scheduler = scheduler::ScanScheduler::from_checkpoint(cp.queue, cp.queued_urls);
        let endpoints = cp.endpoints;
        let bugs = cp.bugs;

        let view_id_to_fingerprint: HashMap<String, String> = cp
            .views
            .iter()
            .map(|v| (v.id.clone(), v.fingerprint.0.clone()))
            .collect();
        let mut template_sampler = if cp.template_sampler.templates.is_empty()
            && cp.template_sampler.source_templates.is_empty()
        {
            TemplateSampler::reconstruct_from_url_map(&cp.url_to_view, &view_id_to_fingerprint)
        } else {
            cp.template_sampler
        };
        template_sampler.set_route_templates(template_sampler::RouteTemplates::new(
            &cp.config.scan.route_templates,
        ));
        // These gaps describe the previous attempt's stopping point. The
        // resumed crawl recomputes them from its final queue and visited
        // URLs; retaining them would report already-reached seeds as gaps
        // and a completed resume as still interrupted.
        let coverage_gaps = cp
            .coverage_gaps
            .into_iter()
            .filter(|gap| {
                !matches!(
                    gap.kind,
                    coverage::CoverageGapKind::StopCondition
                        | coverage::CoverageGapKind::SeededRoute
                        | coverage::CoverageGapKind::OrphanNavItem
                )
            })
            .collect();
        let mut state = Self {
            scheduler,
            visited_fingerprints: cp.visited_fingerprints.into_iter().collect(),
            fingerprint_to_view: cp.fingerprint_to_view,
            url_to_view: cp.url_to_view,
            attempted_urls: HashSet::new(),
            seeded_route_sources: BTreeMap::new(),
            views: cp.views,
            pending_transitions: cp.pending_transitions,
            expanded_nav_dropdown_triggers: cp.expanded_nav_dropdown_triggers.into_iter().collect(),
            template_sampler,
            elements_discovered: cp.elements_discovered,
            elements_interacted: cp.elements_interacted,
            coverage_gaps,
            no_traffic_warned: false,
            visited_route_templates: BTreeSet::new(),
            exercised_controls: HashMap::new(),
            template_instances: HashMap::new(),
            navigation_retries: HashSet::new(),
            revisited_urls: HashSet::new(),
            view_element_counts: Vec::new(),
            template_element_counts: HashMap::new(),
            visited_route_scopes: HashSet::new(),
            session_log: crawl.session,
            resumes: crawl.resumes,
            resumed_view_number: 0,
            retracted_views: BTreeSet::new(),
            session_retries: HashSet::new(),
            ctl: LoopControl::new(),
        };
        state.seeded_route_sources = crawl.seeded_route_sources;
        state.attempted_urls = crawl.attempted_urls.into_iter().collect();
        state.navigation_retries = crawl.navigation_retries.into_iter().collect();
        state.template_instances = crawl.template_instances.into_iter().collect();
        state.exercised_controls = crawl
            .exercised_controls
            .into_iter()
            .map(|e| {
                (
                    e.key,
                    interaction::ExercisedControl {
                        view_id: e.view_id,
                        navigated: e.navigated,
                        claimed: false,
                    },
                )
            })
            .collect();

        // Reconstruct visited route templates from views
        for view in &state.views {
            let template = crate::explorer::template_sampler::route_key(&view.url);
            state.visited_route_templates.insert(template);
            if view.parent_view.is_none() {
                state
                    .visited_route_scopes
                    .insert(route_scope_of(&state.template_sampler, &view.url));
            }
            state
                .attempted_urls
                .insert(crate::explorer::url_utils::canonicalize_crawl_url(
                    &view.url,
                ));
        }
        // View ids are never reused: also not those of visits the checkpoint
        // put back in the queue (their ids stay mapped to their fingerprints).
        state.resumed_view_number = state
            .views
            .iter()
            .map(|v| v.id.as_str())
            .chain(state.fingerprint_to_view.values().map(String::as_str))
            .chain(state.url_to_view.values().map(String::as_str))
            .filter_map(view_number)
            .max()
            .unwrap_or(0);

        // Drop queued URLs for templates already known to be saturated. This
        // prevents spending time popping/skipping hundreds of entries on resume.
        let saturated: Vec<String> = state
            .template_sampler
            .templates
            .iter()
            .filter_map(|(t, s)| if s.saturated { Some(t.clone()) } else { None })
            .collect();
        for t in saturated {
            let _ = state.scheduler.purge_template_from_queue(&t);
        }

        (state, endpoints, bugs)
    }
}

/// How a scan run is driven.
#[derive(Debug, Clone, Default)]
pub struct ScanRunOptions {
    /// Handle SIGINT/SIGTERM: the first signal stops the crawl, which then
    /// checkpoints and finalizes its artifacts with status `interrupted`
    /// (resumable with `brokenapp resume`); a second one exits at once. For
    /// the CLI; library hosts with their own signal handling leave it off.
    pub handle_signals: bool,
    /// Progress snapshots for a resumed scan (`--progress-file`; a fresh
    /// scan takes it from `output.progress_file`).
    pub progress_file: Option<PathBuf>,
}

pub async fn run_scan(cfg: BrokenAppConfig) -> Result<ScanOutcome> {
    run_scan_with_options(cfg, ScanRunOptions::default()).await
}

pub async fn run_scan_with_options(
    cfg: BrokenAppConfig,
    opts: ScanRunOptions,
) -> Result<ScanOutcome> {
    let started_at = Utc::now();
    let start_instant = Instant::now();
    let state = RuntimeState::new(cfg.target.url.to_string());
    run_scan_with_state(
        cfg,
        started_at,
        start_instant,
        state,
        None,
        None,
        crate::network::interceptor::NetworkLogMode::Truncate,
        None,
        opts,
    )
    .await
}

pub async fn resume_scan(checkpoint_path: PathBuf) -> Result<ScanOutcome> {
    resume_scan_with_options(checkpoint_path, ScanRunOptions::default()).await
}

/// Continue a scan from its checkpoint: same config, queue, views and
/// crawl memory; the auth session is established again (a form role logs
/// in again, a saved session is reloaded from its file); visits that were
/// in flight when the checkpoint was taken are explored again from the
/// start (their partial `interactions.jsonl` rows are dropped first).
pub async fn resume_scan_with_options(
    checkpoint_path: PathBuf,
    opts: ScanRunOptions,
) -> Result<ScanOutcome> {
    // Accept either a direct path to checkpoint.json, or a scan directory that contains it.
    let checkpoint_path = resolve_checkpoint_path(checkpoint_path)?;
    let cp = crate::output::checkpoint::load_checkpoint(&checkpoint_path).await?;
    let mut cfg = cp.config.clone();
    if opts.progress_file.is_some() {
        cfg.output.progress_file = opts.progress_file.clone();
    }
    let started_at = cp.started_at;
    // Budgets count crawl time: time the scan was stopped in between does
    // not. Checkpoints from before crawl time was recorded fall back to the
    // wall time since the scan started.
    let elapsed = if cp.crawl.crawl_seconds > 0 || cp.crawl.resumes > 0 {
        Duration::from_secs(cp.crawl.crawl_seconds)
    } else {
        (Utc::now() - started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0))
    };
    let start_instant = Instant::now()
        .checked_sub(elapsed)
        .unwrap_or_else(Instant::now);

    let (mut state, endpoints_seed, bugs_seed) = RuntimeState::from_checkpoint(cp);
    state.resumes = state.resumes.saturating_add(1);
    let keep: HashSet<String> = state
        .views
        .iter()
        .map(|v| base_view_id(&v.id).to_string())
        .collect();
    match compact_interaction_log(&cfg.output.directory, &keep) {
        Ok(0) => {}
        Ok(dropped) => tracing::info!(
            dropped,
            "resume: dropped interaction rows of views the checkpoint does not hold"
        ),
        Err(err) => tracing::warn!(error = ?err, "resume: could not compact interactions.jsonl"),
    }

    run_scan_with_state(
        cfg,
        started_at,
        start_instant,
        state,
        Some(endpoints_seed),
        Some(bugs_seed),
        crate::network::interceptor::NetworkLogMode::Append,
        Some(checkpoint_path),
        opts,
    )
    .await
}

/// Keep only the `interactions.jsonl` rows of views in `keep` (base view
/// ids): rows of visits a checkpoint did not complete are written again when
/// the resumed crawl explores those views. Returns the rows dropped.
fn compact_interaction_log(output_dir: &Path, keep: &HashSet<String>) -> Result<usize> {
    filter_interaction_log(output_dir, |view| keep.contains(view))
}

/// Drop the `interactions.jsonl` rows of withdrawn views (see
/// `RuntimeState::retracted_views`). Returns the rows dropped.
fn drop_retracted_interactions(output_dir: &Path, retracted: &BTreeSet<String>) -> Result<usize> {
    if retracted.is_empty() {
        return Ok(0);
    }
    filter_interaction_log(output_dir, |view| !retracted.contains(view))
}

/// Rewrite `interactions.jsonl` with the rows whose base view id passes
/// `keep` (torn lines are dropped). Returns the rows dropped.
fn filter_interaction_log(output_dir: &Path, keep: impl Fn(&str) -> bool) -> Result<usize> {
    use std::io::{BufRead, Write};
    let path = output_dir.join(crate::output::interactions::INTERACTIONS_FILE);
    let Ok(file) = std::fs::File::open(&path) else {
        return Ok(0);
    };
    #[derive(serde::Deserialize)]
    struct Row {
        view_id: String,
    }
    let tmp = path.with_extension("jsonl.tmp");
    let mut dropped = 0usize;
    let rewrite = (|| -> Result<()> {
        let mut out = std::io::BufWriter::new(
            std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?,
        );
        for line in std::io::BufReader::new(file).lines() {
            let line = line.with_context(|| format!("read {}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            // Stream the log: a multi-hour run must not load every row in RAM.
            match serde_json::from_str::<Row>(&line) {
                Ok(row) if keep(base_view_id(&row.view_id)) => {
                    out.write_all(line.as_bytes())?;
                    out.write_all(b"\n")?;
                }
                _ => dropped += 1,
            }
        }
        out.flush()?;
        Ok(())
    })();
    if let Err(err) = rewrite {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    if dropped == 0 {
        std::fs::remove_file(&tmp)?;
    } else {
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    }
    Ok(dropped)
}

fn resolve_checkpoint_path(input: PathBuf) -> Result<PathBuf> {
    let md = std::fs::metadata(&input).with_context(|| format!("stat {}", input.display()))?;
    if md.is_dir() {
        let candidate = input.join("checkpoint.json");
        if !candidate.exists() {
            anyhow::bail!(
                "expected checkpoint.json in scan directory {} (looked for {})",
                input.display(),
                candidate.display()
            );
        }
        Ok(candidate)
    } else {
        Ok(input)
    }
}

fn enqueue_route_seed(
    state: &mut RuntimeState,
    base_url: &url::Url,
    scope_filter: Option<&ScopeFilter>,
    raw_seed: &str,
    source: &str,
    strategy: crate::config::ExplorationStrategy,
    novelty_scoring: bool,
) {
    crate::explorer::url_utils::register_route_fragment_from_url(raw_seed);
    if let Some((_, frag)) = raw_seed.split_once('#') {
        crate::explorer::url_utils::register_route_fragment(frag);
    }
    let Some(seed_url) = crate::explorer::url_utils::normalize_href(base_url, None, raw_seed)
    else {
        state.coverage_gaps.push(coverage::CoverageGap {
            kind: coverage::CoverageGapKind::SeededRoute,
            target: raw_seed.to_string(),
            reason: "seed_route_invalid_or_cross_origin".to_string(),
            context: Some(format!("source={source}")),
        });
        tracing::warn!(seed = %raw_seed, source = %source, "invalid or cross-origin route seed");
        return;
    };

    if let Some(sf) = scope_filter {
        if !sf.allows_path(seed_url.as_str()) {
            state.coverage_gaps.push(coverage::CoverageGap {
                kind: coverage::CoverageGapKind::SeededRoute,
                target: seed_url.to_string(),
                reason: "seed_route_outside_scope".to_string(),
                context: Some(format!("source={source} scope={}", sf.name)),
            });
            tracing::debug!(seed = %seed_url, scope = %sf.name, "route seed outside scan scope");
            return;
        }
    }

    let canonical = crate::explorer::url_utils::canonicalize_crawl_url(seed_url.as_str());
    let sources = state
        .seeded_route_sources
        .entry(canonical.clone())
        .or_default();
    if !sources.iter().any(|existing| existing == source) {
        sources.push(source.to_string());
    }
    state.scheduler.enqueue_priority(
        canonical,
        0,
        0,
        base_url,
        scope_filter,
        strategy,
        novelty_scoring,
        false,
    );
}

async fn run_scan_with_state(
    mut cfg: BrokenAppConfig,
    started_at: DateTime<Utc>,
    start_instant: Instant,
    mut state: RuntimeState,
    seed_endpoints: Option<Vec<ApiEndpoint>>,
    seed_bugs: Option<Vec<Bug>>,
    log_mode: crate::network::interceptor::NetworkLogMode,
    checkpoint_path_override: Option<PathBuf>,
    opts: ScanRunOptions,
) -> Result<ScanOutcome> {
    let is_fresh_scan = checkpoint_path_override.is_none();

    // Manual auth requires a visible browser window. Force headful regardless
    // of config/CLI settings.
    if matches!(cfg.auth, Some(AuthConfig::Manual { .. })) && cfg.target.headless {
        tracing::info!("manual auth enabled: forcing headless=false");
        cfg.target.headless = false;
    }

    // Fresh scans should not overwrite an existing run directory. If the output
    // directory already contains prior scan artifacts, derive a new unique
    // directory for this run.
    if is_fresh_scan {
        if should_force_fresh_output_dir(&cfg.output.directory)
            || output_dir_has_scan_artifacts(&cfg.output.directory)
        {
            let new_dir = derive_fresh_output_dir(&cfg.output.directory);
            tracing::info!(
                old = %cfg.output.directory.display(),
                new = %new_dir.display(),
                "output directory already contains a run; writing this scan to a new directory"
            );
            cfg.output.directory = new_dir;
        }
    }

    tokio::fs::create_dir_all(&cfg.output.directory)
        .await
        .with_context(|| format!("create output dir {}", cfg.output.directory.display()))?;

    // Per-control outcome log, in the run's actual output directory (after any
    // fresh-sibling redirection above). Resumed scans append to it.
    let interaction_log = match InteractionLog::create(&cfg.output.directory) {
        Ok(log) => Some(log),
        Err(err) => {
            tracing::warn!(error = ?err, "interaction log unavailable; interactions.jsonl will not be written");
            None
        }
    };

    // Network replay fuzzing needs `network.jsonl` for request seeds + evidence linking.
    if cfg.scan.fuzzing.enabled && !cfg.output.include_network_log {
        tracing::info!(
            "scan.fuzzing.enabled=true: forcing output.include_network_log=true for replay fuzzing"
        );
        cfg.output.include_network_log = true;
    }
    if !cfg.output.include_network_log {
        tracing::info!(
            "passive header and runtime-template checks require network evidence; forcing output.include_network_log=true"
        );
        cfg.output.include_network_log = true;
    }

    let scope_filter: Option<ScopeFilter> = match cfg.scan.scope.as_deref() {
        Some(name) => Some(load_scope_filter(name, cfg.scan.scopes_file.as_deref())?),
        None => None,
    };
    if let Some(sf) = scope_filter.as_ref() {
        tracing::info!(
            scope = %sf.name,
            seed_paths = sf.seed_paths().len(),
            "scan scope enabled"
        );
    }
    let seed_routes_file_seeds = match cfg.scan.seed_routes_file.as_ref() {
        Some(path) if is_fresh_scan => {
            let seeds = route_seeds::load_route_seed_file(path)
                .with_context(|| format!("load seed routes file {}", path.display()))?;
            tracing::info!(
                file = %path.display(),
                seeds = seeds.len(),
                "loaded route seed file"
            );
            seeds
        }
        _ => Vec::new(),
    };

    let chrome_path = cfg
        .target
        .chrome_executable
        .clone()
        .or_else(crate::browser::pool::BrowserManager::detect_chrome_executable);

    if let Some(ref locale) = cfg.target.locale {
        tracing::info!(locale = %locale, "using configured locale");
    } else {
        tracing::info!("no locale configured; browser will use host system default");
    }

    if cfg.scan.via_playwright_mcp {
        anyhow::bail!(
            "--via-playwright-mcp is reserved for the Playwright MCP substrate adapter, but this build does not include that adapter yet; use the default direct-CDP substrate for scans"
        );
    }

    let browser = BrowserManager::launch(BrowserLaunchOptions {
        chrome_executable: chrome_path,
        headless: cfg.target.headless,
        ignore_https_errors: cfg.target.ignore_https_errors,
        remote_chrome_url: cfg.target.remote_chrome_url.clone(),
        locale: cfg.target.locale.clone(),
    })
    .await?;

    let result: Result<ScanOutcome> = async {
        let network_log_path = if cfg.output.include_network_log {
            Some(cfg.output.directory.join("network.jsonl"))
        } else {
            None
        };
        let writer = match &network_log_path {
            Some(path) => Some(Arc::new(
                NetworkLogWriter::new_with_options(
                    path.clone(),
                    log_mode,
                    cfg.output.include_response_bodies,
                )
                .await?,
            )),
            None => None,
        };

        let default_block_private_egress = !crate::safety::is_non_production_target(&cfg.target.url);
        let block_private_egress = cfg
            .scan
            .block_private_egress
            .unwrap_or(default_block_private_egress);
        if block_private_egress {
            tracing::info!("egress guard enabled: blocking private/non-global IP requests");
        }

        let network = Arc::new(NetworkInterceptor::new(
            cfg.scan.clone(),
            writer,
            block_private_egress,
        ));
        network.set_first_party_origin(&cfg.target.url);
        if let Some(seed) = seed_endpoints {
            network.seed_endpoints(seed);
        }

        let mut session_state = SessionManager::authenticate(
            browser.browser(),
            &cfg.target,
            &cfg.auth,
            cfg.auth_contract.as_ref(),
            Some(&network),
        )
        .await?;

        let bug_detector = Arc::new(match seed_bugs {
            Some(bugs) => BugDetector::from_existing(bugs),
            None => BugDetector::new(),
        });

        let checkpoint_path =
            checkpoint_path_override.unwrap_or_else(|| cfg.output.directory.join("checkpoint.json"));
        let mut checkpoint_writer =
            CheckpointWriter::new(checkpoint_path, cfg.output.checkpoint_interval_seconds);

        // Write an initial snapshot so resume scans immediately produce `spec.json`
        // and `bugs.*` even if the process dies before exploring a new view.
        if let Err(err) = engine::save_progress(
            &mut checkpoint_writer,
            &cfg,
            started_at,
            start_instant,
            &state,
            &network,
            &bug_detector,
        )
        .await
        {
            tracing::warn!(error = ?err, "initial incremental save failed");
        }

        let base_url = cfg.target.url.clone();
        // If a scope is configured, seed the queue with the scope's concrete routes
        // (when available). This keeps targeted scans fast and avoids exploring
        // irrelevant parts of the application.
        if is_fresh_scan {
            if let Some(sf) = scope_filter.as_ref() {
                let seeds = sf.seed_urls(&base_url);
                if !seeds.is_empty() {
                    state.scheduler.clear();
                    for u in seeds {
                        url_utils::register_route_fragment_from_url(&u);
                        state.scheduler.enqueue(u, 0);
                    }
                }
            }

            // Optional extra seeds (same-origin URLs/paths) to cover known entry
            // points that are not reachable via current crawl heuristics.
            for seed in &cfg.scan.seed_urls {
                enqueue_route_seed(
                    &mut state,
                    &base_url,
                    scope_filter.as_ref(),
                    seed,
                    "scan.seed_urls",
                    cfg.scan.exploration.strategy,
                    cfg.scan.exploration.novelty_scoring,
                );
            }

            if let Some(path) = cfg.scan.seed_routes_file.as_ref() {
                let source = format!("seed_routes_file:{}", path.display());
                for seed in &seed_routes_file_seeds {
                    enqueue_route_seed(
                        &mut state,
                        &base_url,
                        scope_filter.as_ref(),
                        seed,
                        &source,
                        cfg.scan.exploration.strategy,
                        cfg.scan.exploration.novelty_scoring,
                    );
                }
            }
        }
        // The crawl ends when its loop does, at the hard timeout (the time
        // budget plus a grace period), or at the first SIGINT/SIGTERM. A cut
        // off crawl drops its in-flight visits: their URLs go back to the
        // queue (see `RuntimeState::abandon_visit`), so the final checkpoint
        // resumes them.
        let mut interrupt = if opts.handle_signals {
            match interrupt::InterruptWatch::install() {
                Ok(watch) => Some(watch),
                Err(err) => {
                    tracing::warn!(error = ?err, "signal handling unavailable; Ctrl-C ends the scan without a checkpoint");
                    None
                }
            }
        } else {
            None
        };
        let hard_timeout = hard_scan_timeout(&cfg).map(|limit| {
            // Budgets count crawl time across resumes.
            limit.saturating_sub(start_instant.elapsed()).max(Duration::from_secs(1))
        });
        let crawl_end = {
            let crawl = engine::scan_loop(
                &cfg,
                started_at,
                start_instant,
                &browser,
                &mut session_state,
                &network,
                &bug_detector,
                &base_url,
                scope_filter.as_ref(),
                &mut state,
                &mut checkpoint_writer,
                interaction_log.as_ref(),
            );
            tokio::pin!(crawl);
            let timeout = async {
                match hard_timeout {
                    Some(t) => tokio::time::sleep(t).await,
                    None => std::future::pending::<()>().await,
                }
            };
            let signal = async {
                match interrupt.as_mut() {
                    Some(watch) => watch.triggered().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                result = &mut crawl => {
                    result?;
                    CrawlEnd::Finished
                }
                _ = timeout => CrawlEnd::HardTimeout,
                kind = signal => CrawlEnd::Interrupted(kind),
            }
        };
        if let Some(watch) = interrupt.as_ref() {
            watch.finishing();
        }
        match crawl_end {
            CrawlEnd::Finished => {
                if state.ctl.stop_reason.is_none() {
                    state.ctl.stop(run_report::stop_reason::QUEUE_EXHAUSTED);
                }
            }
            CrawlEnd::HardTimeout => {
                let timeout = hard_timeout.unwrap_or_default();
                state
                    .coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                        target: "scan".to_string(),
                        reason: "hard_timeout".to_string(),
                        context: Some(format!("timeout_seconds={}", timeout.as_secs())),
                    });
                tracing::warn!(
                    timeout_seconds = timeout.as_secs(),
                    "hard scan timeout reached; finalizing partial artifacts"
                );
                state.ctl.stop(run_report::stop_reason::HARD_TIMEOUT);
            }
            CrawlEnd::Interrupted(kind) => {
                state
                    .coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                        target: "scan".to_string(),
                        reason: "interrupted".to_string(),
                        context: Some(format!(
                            "signal={} queue_remaining={}",
                            kind.name(),
                            state.scheduler.len()
                        )),
                    });
                tracing::warn!(
                    signal = kind.name(),
                    queue_remaining = state.scheduler.len(),
                    "scan interrupted; checkpointing for `brokenapp resume`"
                );
                // Interrupted before the stop reason of the crawl itself.
                state.ctl.stop_reason = Some(run_report::stop_reason::INTERRUPTED);
                state.ctl.stopping = true;
            }
        }
        match drop_retracted_interactions(&cfg.output.directory, &state.retracted_views) {
            Ok(0) => {}
            Ok(dropped) => tracing::info!(
                dropped,
                views = state.retracted_views.len(),
                "dropped interaction rows of withdrawn views"
            ),
            Err(err) => tracing::warn!(error = ?err, "could not drop interaction rows of withdrawn views"),
        }
        let interrupted = matches!(crawl_end, CrawlEnd::Interrupted(_));
        let completion_status = completion_status_for(&crawl_end, state.ctl.stop_reason);
        let crawl_seconds = start_instant.elapsed().as_secs();
        // The checkpoint first: it is what a resume needs, and an interrupted
        // scan may be killed for good shortly after.
        if interrupted {
            let bugs = bug_detector.bugs_snapshot().await;
            let cp = engine::build_checkpoint(
                &cfg,
                started_at,
                crawl_seconds,
                &state,
                network.endpoints_snapshot(),
                bugs,
            );
            if let Err(err) = checkpoint_writer.save(&cp).await {
                tracing::warn!(error = ?err, "failed to write the interrupt checkpoint");
            }
        }

        // Detect orphan nav items (nav links/buttons that exist but were never visited).
        let orphan_gaps = coverage::detect_orphan_nav_items(
            &state.views,
            &state.url_to_view,
            &state.expanded_nav_dropdown_triggers,
            &base_url,
        );
        if !orphan_gaps.is_empty() {
            tracing::info!(orphan_nav_items = orphan_gaps.len(), "orphan nav items detected");
            state.coverage_gaps.extend(orphan_gaps);
        }

        let visited_urls: HashSet<String> = state.url_to_view.keys().cloned().collect();
        let seeded_route_gaps = coverage::detect_seeded_route_gaps(
            &state.seeded_route_sources,
            &visited_urls,
            &state.attempted_urls,
            &base_url,
        );
        if !seeded_route_gaps.is_empty() {
            tracing::info!(
                seeded_route_gaps = seeded_route_gaps.len(),
                "seeded route gaps detected"
            );
            state.coverage_gaps.extend(seeded_route_gaps);
        }

        // Form fuzzing via network replay (opt-in). Runs after exploration completes so it
        // doesn't interfere with DOM traversal or view mapping.
        if cfg.scan.fuzzing.enabled {
            if interrupted {
                tracing::info!("scan interrupted; skipping form fuzzing");
            } else if cfg.scan.write_guard.mode != crate::config::WriteGuardMode::Off {
                tracing::info!(
                    "scan.fuzzing.enabled=true but scan.write_guard is active; skipping fuzzing (it replays writes outside the browser)"
                );
            } else if !cfg.scan.exploration.submit_forms {
                tracing::info!(
                    "scan.fuzzing.enabled=true but scan.exploration.submit_forms=false; skipping fuzzing for safety"
                );
            } else if let Some(ref net_path) = network_log_path {
                // Collect form submit endpoints discovered during the scan.
                let mut form_endpoints: HashSet<EndpointKey> = HashSet::new();
                for v in &state.views {
                    for c in &v.components {
                        if let ComponentType::Form {
                            submit_endpoint: Some(ep),
                            ..
                        } = c
                        {
                            if let Some((m, path)) = ep.split_once(' ') {
                                let method = HttpMethod::from_str_lossy(m.trim());
                                let path_template = path.trim().to_string();
                                if !path_template.is_empty() {
                                    form_endpoints.insert(EndpointKey {
                                        method,
                                        path_template,
                                    });
                                }
                            }
                        }
                    }
                }

                if form_endpoints.is_empty() {
                    tracing::info!(
                        "scan.fuzzing.enabled=true but no form submit endpoints were discovered; skipping fuzzing"
                    );
                } else {
                    let mut cookie_override: Option<String> = None;
                    if let Some(AuthConfig::Cookie { cookie }) = cfg.auth.as_ref() {
                        cookie_override = Some(cookie.clone());
                    } else if let Ok(cookie) =
                        crate::session::cookies::capture_cookie_header(&browser, &base_url).await
                    {
                        if !cookie.trim().is_empty() {
                            cookie_override = Some(cookie);
                        }
                    }

                    let authorization_override =
                        session_state.extra_headers.get("Authorization").cloned();

                    let fuzz_summary = crate::bugs::form_fuzz_replay::run_form_fuzz_replay(
                        net_path,
                        &base_url,
                        &form_endpoints,
                        cookie_override.as_deref(),
                        authorization_override.as_deref(),
                        cfg.scan.fuzzing.max_payloads_per_field,
                        cfg.target.ignore_https_errors,
                        &bug_detector,
                    )
                    .await
                    .unwrap_or_default();

                    if fuzz_summary.requests_sent > 0 {
                        tracing::info!(
                            seeds_considered = fuzz_summary.seeds_considered,
                            seeds_fuzzed = fuzz_summary.seeds_fuzzed,
                            requests_sent = fuzz_summary.requests_sent,
                            findings_recorded = fuzz_summary.findings_recorded,
                            "form fuzz replay complete"
                        );
                    }
                }
            }
        }

        // Finalize endpoints.
        let mut endpoints = network.endpoints_snapshot();
        for ep in &mut endpoints {
            if ep.response_body_schema.is_none() && !ep.response_body_samples.is_empty() {
                ep.response_body_schema = schema_inference::infer_schema(&ep.response_body_samples);
            }
            if ep.request_body_schema.is_none() && !ep.request_body_samples.is_empty() {
                ep.request_body_schema = schema_inference::infer_schema(&ep.request_body_samples);
            }
        }
        endpoints.sort_by(|a, b| a.key.cmp(&b.key));

        let mut bugs = bug_detector.bugs_snapshot().await;

        let passive_header_findings =
            crate::bugs::passive_headers::evaluate_passive_header_findings_from_log(
                network_log_path.as_deref(),
                Some(&cfg.target.url),
            );
        if !passive_header_findings.is_empty() {
            tracing::info!(
                findings = passive_header_findings.len(),
                "passive security header checks evaluated"
            );
            bugs.extend(passive_header_findings);
        }

        // Evaluate custom rules and runtime templates (post-scan pass).
        let mut post_scan_rules = cfg.custom_rules.clone();
        if !cfg.scan.runtime_templates.is_empty() {
            let runtime_template_rules =
                crate::bugs::runtime_templates::load_runtime_templates(&cfg.scan.runtime_templates)?;
            tracing::info!(
                templates = cfg.scan.runtime_templates.len(),
                rules = runtime_template_rules.len(),
                "runtime templates loaded"
            );
            post_scan_rules.extend(runtime_template_rules);
        }
        if !post_scan_rules.is_empty() {
            let custom_eval = crate::bugs::custom_rules::evaluate_custom_rules(
                &post_scan_rules,
                &endpoints,
                network_log_path.as_deref(),
                &state.views,
            );
            if !custom_eval.findings.is_empty() {
                tracing::info!(
                    rules = custom_eval.rules_evaluated,
                    findings = custom_eval.findings.len(),
                    "custom rules evaluated"
                );
                bugs.extend(custom_eval.findings);
            }
        }

        // Resolve transitions.
        let mut transitions = Vec::new();
        for t in &state.pending_transitions {
            let to_view = if t.target_url.contains(":d") {
                t.target_url.clone()
            } else {
                engine::resolve_transition_target(&state, &t.target_url)
            };
            transitions.push(ViewTransition {
                from_view: t.from_view.clone(),
                to_view,
                trigger: t.trigger.clone(),
                trigger_locators: t.trigger_locators.clone(),
                transition_type: t.transition_type,
                api_calls: Vec::new(),
                preconditions: Vec::new(),
            });
        }

        let finished_at = Utc::now();
        let scan_duration_seconds = start_instant.elapsed().as_secs();

        let views_discovered = state.url_to_view.len();
        let views_explored = state.views.len();
        let api_endpoints_discovered = endpoints.len();

        let outcome = ScanOutcome {
            started_at,
            finished_at,
            scan_duration_seconds,
            completion_status: completion_status.to_string(),
            target_url: cfg.target.url.to_string(),
            output_dir: cfg.output.directory.clone(),
            network_log_path: network_log_path.clone(),
            views: state.views.clone(),
            template_sampler: state.template_sampler.clone(),
            transitions,
            endpoints: endpoints.clone(),
            bugs: bugs.clone(),
            coverage: coverage::summarize(
                views_discovered,
                views_explored,
                state.elements_discovered,
                state.elements_interacted,
                api_endpoints_discovered,
            ),
            coverage_gaps: coverage::summarize_gaps(state.coverage_gaps.clone()),
        };

        // Write a final checkpoint.
        let final_cp = engine::build_checkpoint(
            &cfg,
            started_at,
            scan_duration_seconds,
            &state,
            endpoints,
            bugs,
        );
        let _ = checkpoint_writer.save(&final_cp).await;

        output::write_scan_output(&outcome, &cfg.scan, &cfg.output, cfg.auth.is_some()).await?;
        let run = run_report::RunReport::build(
            &cfg,
            run_report::RunFacts {
                status: completion_status,
                stop_reason: state.ctl.stop_reason,
                started_at,
                crawl_seconds: scan_duration_seconds,
                resumes: state.resumes,
                tabs: crawl_tab_count(&cfg),
                views: state.views.len(),
                queue_remaining: state.scheduler.len(),
                session: &state.session_log,
            },
        );
        if let Err(err) = run_report::write_run_report(&cfg.output.directory, &run).await {
            tracing::warn!(error = ?err, "failed to write scan-run.json");
        }
        // Write final progress after output artifacts so bugs_found reflects
        // finalized bugs.json, not only raw detector observations.
        let progress_phase = match completion_status {
            "ok" => "complete",
            other => other,
        };
        engine::write_final_progress(
            &cfg,
            start_instant,
            &state,
            &network,
            &bug_detector,
            progress_phase,
        )
        .await;
        if let Err(err) = refresh_latest_scan_pointer(&outcome.output_dir) {
            tracing::warn!(
                error = ?err,
                output = %outcome.output_dir.display(),
                "failed to refresh latest scan pointer"
            );
        }
        Ok(outcome)
    }
    .await;

    if let Err(err) = browser.shutdown().await {
        tracing::warn!(error = ?err, "browser shutdown failed");
    }

    result
}

fn output_dir_has_scan_artifacts(dir: &Path) -> bool {
    let markers = [
        "spec.json",
        "checkpoint.json",
        "bugs.json",
        "bugs.md",
        "network.jsonl",
        "normalized.json",
        "components.json",
    ];

    for m in markers {
        if dir.join(m).exists() {
            return true;
        }
    }

    // If the directory is non-empty, assume it's unsafe to overwrite.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy() == ".DS_Store" {
                continue;
            }
            return true;
        }
    }

    false
}

/// How the crawl loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrawlEnd {
    /// The loop returned: queue exhausted, or a stop condition.
    Finished,
    /// The hard timeout (time budget plus grace) cut it off.
    HardTimeout,
    /// SIGINT/SIGTERM.
    Interrupted(interrupt::InterruptKind),
}

/// The scan's `completion_status`: `interrupted`, `partial_timeout`,
/// `session_expired` (the auth session ended and could not be renewed),
/// `browser_unavailable` (the browser stopped answering), else `ok`.
fn completion_status_for(end: &CrawlEnd, stop_reason: Option<&str>) -> &'static str {
    match end {
        CrawlEnd::Interrupted(_) => "interrupted",
        CrawlEnd::HardTimeout => "partial_timeout",
        CrawlEnd::Finished => match stop_reason {
            Some(run_report::stop_reason::SESSION_EXPIRED) => "session_expired",
            Some(run_report::stop_reason::BROWSER_UNAVAILABLE) => "browser_unavailable",
            _ => "ok",
        },
    }
}

fn hard_scan_timeout(cfg: &BrokenAppConfig) -> Option<Duration> {
    (cfg.scan.max_duration_minutes > 0).then(|| {
        Duration::from_secs(cfg.scan.max_duration_minutes.saturating_mul(60))
            .saturating_add(Duration::from_secs(15))
    })
}

fn derive_fresh_output_dir(base: &Path) -> PathBuf {
    let ts = Utc::now().format("%Y%m%d-%H%M%S").to_string();

    // Use a sibling directory by default: <base>-<timestamp> (and add a UUID suffix if needed).
    let parent = base.parent().unwrap_or_else(|| Path::new("."));
    let name = base
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("scan-results");

    let mut candidate = parent.join(format!("{name}-{ts}"));
    if !candidate.exists() {
        return candidate;
    }

    let suffix = Uuid::new_v4().to_string();
    candidate = parent.join(format!("{name}-{ts}-{}", &suffix[..8]));
    candidate
}

fn should_force_fresh_output_dir(dir: &Path) -> bool {
    // Treat the canonical default directory specially:
    // `./.brokenapp/scans/scan-results` should always fan out into
    // per-run timestamped siblings for better scan history.
    let Some(name) = dir.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if name != "scan-results" {
        return false;
    }
    let Some(parent) = dir
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
    else {
        return false;
    };
    if parent != "scans" {
        return false;
    }
    let Some(grand) = dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
    else {
        return false;
    };
    grand == ".brokenapp"
}

fn latest_scan_pointer_path(run_dir: &Path) -> Option<PathBuf> {
    let scans_dir = run_dir.parent()?;
    let parent_name = scans_dir.file_name().and_then(|s| s.to_str())?;
    if parent_name != "scans" {
        return None;
    }

    let grand_name = scans_dir
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())?;
    if grand_name != ".brokenapp" {
        return None;
    }

    Some(scans_dir.join("latest"))
}

pub fn refresh_latest_scan_pointer(run_dir: &Path) -> io::Result<()> {
    let Some(pointer_path) = latest_scan_pointer_path(run_dir) else {
        return Ok(());
    };

    remove_existing_pointer_path(&pointer_path)?;

    let target = run_dir
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| run_dir.to_path_buf());
    match create_dir_symlink(&target, &pointer_path) {
        Ok(_) => {
            let _ = std::fs::remove_file(pointer_path.with_extension("txt"));
            Ok(())
        }
        Err(link_err) => {
            let fallback = pointer_path.with_extension("txt");
            std::fs::write(&fallback, format!("{}\n", run_dir.display()))?;
            tracing::warn!(
                error = ?link_err,
                pointer = %pointer_path.display(),
                fallback = %fallback.display(),
                "symlink creation failed; wrote text pointer instead"
            );
            Ok(())
        }
    }
}

fn remove_existing_pointer_path(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let file_type = meta.file_type();
            if file_type.is_dir() && !file_type.is_symlink() {
                std::fs::remove_dir_all(path)
            } else {
                std::fs::remove_file(path)
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_dir_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_dir_symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "directory symlinks are not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_scan_pointer_path_matches_default_layout() {
        let run = Path::new("./.brokenapp/scans/e2e-cli-20260215-010203");
        let pointer = latest_scan_pointer_path(run).expect("pointer path");
        assert_eq!(pointer, PathBuf::from("./.brokenapp/scans/latest"));
    }

    #[test]
    fn latest_scan_pointer_path_rejects_other_layouts() {
        let run = Path::new("./scan-results");
        assert!(latest_scan_pointer_path(run).is_none());
    }

    #[test]
    fn tab_count_is_clamped_and_env_overrides_config() {
        assert_eq!(resolve_tab_count(1, None), 1);
        assert_eq!(resolve_tab_count(0, None), 1);
        assert_eq!(resolve_tab_count(4, None), 4);
        assert_eq!(resolve_tab_count(64, None), MAX_CONCURRENT_TABS);
        assert_eq!(resolve_tab_count(1, Some(" 3 ")), 3);
        assert_eq!(resolve_tab_count(2, Some("99")), MAX_CONCURRENT_TABS);
        assert_eq!(resolve_tab_count(2, Some("many")), 2);
    }

    #[test]
    fn view_ids_never_repeat() {
        let mut state = RuntimeState::new("http://127.0.0.1:47280/".to_string());
        assert_eq!(state.allocate_view_id(), "view_0001");
        // A visit that was abandoned after its id was handed out (watchdog,
        // or another tab still working) does not free the number.
        assert_eq!(state.allocate_view_id(), "view_0002");
        // Ids follow the views recorded so far (sub-views included).
        for n in 0..5 {
            state.views.push(AppView {
                id: format!("view_000{n}:d1:0"),
                url: "http://127.0.0.1:47280/".to_string(),
                fingerprint: crate::types::graph::DomFingerprint("fp".to_string()),
                title: None,
                component_type: "sub_view".to_string(),
                description: String::new(),
                components: vec![],
                component_instances: vec![],
                elements: vec![],
                on_load_api_calls: vec![],
                detected_framework: None,
                screenshot: None,
                parent_view: None,
                depth: 1,
                trigger_selector: None,
                sub_view_transition_type: None,
            });
        }
        assert_eq!(state.allocate_view_id(), "view_0006");
    }

    #[test]
    fn hard_scan_timeout_adds_finalization_grace() {
        let mut cfg: BrokenAppConfig = toml::from_str(
            r#"
[target]
url = "http://127.0.0.1:47620/index.html"
"#,
        )
        .expect("config");

        cfg.scan.max_duration_minutes = 2;
        assert_eq!(hard_scan_timeout(&cfg), Some(Duration::from_secs(135)));

        cfg.scan.max_duration_minutes = 0;
        assert_eq!(hard_scan_timeout(&cfg), None);
    }

    #[test]
    fn refresh_latest_scan_pointer_writes_pointer() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scans = tmp.path().join(".brokenapp/scans");
        std::fs::create_dir_all(&scans).expect("create scans dir");

        let run_a = scans.join("e2e-cli-20260215-010203");
        std::fs::create_dir_all(&run_a).expect("create run_a");
        refresh_latest_scan_pointer(&run_a).expect("pointer for run_a");

        let latest = scans.join("latest");
        let latest_txt = scans.join("latest.txt");
        assert!(
            std::fs::symlink_metadata(&latest).is_ok() || latest_txt.exists(),
            "expected symlink or fallback pointer"
        );

        let run_b = scans.join("rescan-20260215-020304");
        std::fs::create_dir_all(&run_b).expect("create run_b");
        refresh_latest_scan_pointer(&run_b).expect("pointer for run_b");

        if let Ok(target) = std::fs::read_link(&latest) {
            assert_eq!(target, PathBuf::from("rescan-20260215-020304"));
        } else {
            let txt = std::fs::read_to_string(&latest_txt).expect("read fallback pointer");
            assert!(txt.contains("rescan-20260215-020304"));
        }
    }

    fn test_cfg(extra: &str) -> BrokenAppConfig {
        toml::from_str(&format!(
            r#"
[target]
url = "http://127.0.0.1:47280/"
{extra}
"#
        ))
        .expect("config")
    }

    fn view(id: &str, url: &str) -> AppView {
        AppView {
            id: id.to_string(),
            url: url.to_string(),
            fingerprint: crate::types::graph::DomFingerprint(format!("fp-{id}")),
            title: None,
            component_type: "page".to_string(),
            description: String::new(),
            components: vec![],
            component_instances: vec![],
            elements: vec![],
            on_load_api_calls: vec![],
            detected_framework: None,
            screenshot: None,
            parent_view: None,
            depth: 0,
            trigger_selector: None,
            sub_view_transition_type: None,
        }
    }

    fn transition(from: &str) -> PendingTransition {
        PendingTransition {
            from_view: from.to_string(),
            trigger: crate::types::dom::InteractionRef {
                view: from.to_string(),
                selector: "a".to_string(),
            },
            trigger_locators: vec![],
            transition_type: crate::types::graph::TransitionType::Navigation,
            target_url: "http://127.0.0.1:47280/next".to_string(),
        }
    }

    /// A state with one finished view (`/done`) and one visit in flight
    /// (`/busy`) that has recorded part of its view.
    fn state_with_visit_in_flight() -> (RuntimeState, u64) {
        let mut state = RuntimeState::new("http://127.0.0.1:47280/".to_string());
        state.scheduler.clear();
        let done = state.allocate_view_id();
        state.views.push(view(&done, "http://127.0.0.1:47280/done"));
        state.visited_fingerprints.insert("done-key".to_string());
        state.visited_route_scopes.insert(route_scope_of(
            &state.template_sampler,
            "http://127.0.0.1:47280/done",
        ));
        state.exercised_controls.insert(
            "done-control".to_string(),
            interaction::ExercisedControl {
                view_id: done.clone(),
                navigated: false,
                claimed: false,
            },
        );
        state.pending_transitions.push(transition(&done));
        state
            .scheduler
            .enqueue("http://127.0.0.1:47280/later".to_string(), 1);

        let item = crate::output::checkpoint::QueuedUrl {
            url: "http://127.0.0.1:47280/busy".to_string(),
            depth: 1,
            priority: 100,
        };
        let number = state.begin_visit(&item);
        let busy = state.allocate_view_id();
        state.visited_fingerprints.insert("busy-key".to_string());
        state.visit_explores(number, "busy-key", &busy);
        state
            .fingerprint_to_view
            .insert("busy-key".to_string(), busy.clone());
        let mut sub = view(&format!("{busy}:d1:0"), "http://127.0.0.1:47280/busy");
        sub.parent_view = Some(busy.clone());
        state.views.push(sub);
        state.pending_transitions.push(transition(&busy));
        state.exercised_controls.insert(
            "busy-control".to_string(),
            interaction::ExercisedControl {
                view_id: busy.clone(),
                navigated: true,
                claimed: false,
            },
        );
        state
            .expanded_nav_dropdown_triggers
            .insert(format!("{busy}::button.menu"));
        (state, number)
    }

    #[test]
    fn checkpoints_requeue_visits_in_flight_and_leave_their_partial_views_out() {
        let cfg = test_cfg("");
        let (state, _) = state_with_visit_in_flight();
        let cp = engine::build_checkpoint(&cfg, Utc::now(), 42, &state, vec![], vec![]);

        assert_eq!(cp.queue[0].url, "http://127.0.0.1:47280/busy");
        assert_eq!(cp.queue[0].priority, 0, "in-flight visits resume first");
        assert!(
            cp.queue
                .iter()
                .any(|q| q.url == "http://127.0.0.1:47280/later")
        );
        assert!(
            cp.queued_urls
                .contains(&"http://127.0.0.1:47280/busy".to_string())
        );
        assert_eq!(cp.visited_fingerprints, vec!["done-key".to_string()]);
        let ids: Vec<&str> = cp.views.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, vec!["view_0001"]);
        assert!(
            cp.pending_transitions
                .iter()
                .all(|t| t.from_view == "view_0001")
        );
        assert!(cp.expanded_nav_dropdown_triggers.is_empty());
        let keys: Vec<&str> = cp
            .crawl
            .exercised_controls
            .iter()
            .map(|e| e.key.as_str())
            .collect();
        assert_eq!(keys, vec!["done-control"]);
        assert_eq!(cp.crawl.crawl_seconds, 42);

        // It verifies, and a resume continues from it with fresh view ids.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("checkpoint.json");
        std::fs::write(&path, serde_json::to_vec(&cp).unwrap()).unwrap();
        let loaded = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(crate::output::checkpoint::load_checkpoint(&path))
            .expect("checkpoint verifies");
        let (mut resumed, _, _) = RuntimeState::from_checkpoint(loaded);
        assert!(resumed.exercised_controls.contains_key("done-control"));
        assert!(!resumed.exercised_controls.contains_key("busy-control"));
        assert_eq!(
            resumed.allocate_view_id(),
            "view_0003",
            "ids are never reused"
        );
        assert!(resumed.visited_route_scopes.contains(&route_scope_of(
            &resumed.template_sampler,
            "http://127.0.0.1:47280/done"
        )));
    }

    #[test]
    fn interrupted_template_sample_is_retryable_before_saturation() {
        for (template, prefix) in [("/clients/:id", "clients"), ("/towns/:slug", "towns")] {
            let mut cfg = test_cfg("");
            cfg.scan.route_templates = vec![template.to_string()];
            let mut state = RuntimeState::new(cfg.target.url.to_string());
            state.scheduler.clear();
            state
                .template_sampler
                .set_route_templates(template_sampler::RouteTemplates::new(
                    &cfg.scan.route_templates,
                ));
            let url = |n| {
                if prefix == "towns" {
                    format!("http://127.0.0.1:47280/towns/town-{n}")
                } else {
                    format!("http://127.0.0.1:47280/clients/{n}")
                }
            };
            let item = |n| crate::output::checkpoint::QueuedUrl {
                url: url(n),
                depth: 1,
                priority: 100,
            };
            for n in 1..=4 {
                let number = state.begin_visit(&item(n));
                state.sample_when_visit_finishes(
                    number,
                    &url(n),
                    "same-layout",
                    &format!("view_{n:04}"),
                );
                state.finish_visit(number);
            }
            let fifth = item(5);
            assert!(matches!(
                state.template_sampler.should_visit(&fifth.url),
                template_sampler::TemplateVisitDecision::Visit
            ));
            let _reservation = state.template_sampler.reserve(&fifth.url).unwrap();
            let number = state.begin_visit(&fifth);
            state.sample_when_visit_finishes(number, &fifth.url, "same-layout", "view_0005");
            state.visit_explores(number, "fifth-key", "view_0005");

            // A real checkpoint crosses a serialization boundary: reservations
            // are transient, and unfinished samples must not be committed.
            let checkpoint = engine::build_checkpoint(&cfg, Utc::now(), 42, &state, vec![], vec![]);
            let checkpoint =
                serde_json::from_slice(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
            let (mut resumed, _, _) = RuntimeState::from_checkpoint(checkpoint);
            let sample = resumed
                .template_sampler
                .templates
                .get(template)
                .or_else(|| resumed.template_sampler.source_templates.get(template))
                .expect("both numeric and source-only sampler state survive resume");
            assert_eq!(sample.visited_count, 4);
            assert_eq!(sample.consecutive_duplicates, 3);
            assert!(
                resumed
                    .scheduler
                    .queue_snapshot()
                    .iter()
                    .any(|q| q.url == fifth.url)
            );
            assert!(
                matches!(
                    resumed.template_sampler.should_visit(&fifth.url),
                    template_sampler::TemplateVisitDecision::Visit
                ),
                "the interrupted fifth instance must still be explored"
            );

            let number = resumed.begin_visit(&fifth);
            resumed.sample_when_visit_finishes(number, &fifth.url, "same-layout", "view_0005");
            resumed.finish_visit(number);
            assert!(
                matches!(
                    resumed.template_sampler.should_visit(&url(6)),
                    template_sampler::TemplateVisitDecision::Skip { .. }
                ),
                "a finished fifth duplicate reaches the normal saturation threshold"
            );
        }
    }

    #[test]
    fn withdrawn_visit_does_not_consume_template_sample() {
        let mut state = RuntimeState::new("http://127.0.0.1:47280/".to_string());
        let item = crate::output::checkpoint::QueuedUrl {
            url: "http://127.0.0.1:47280/clients/5".to_string(),
            depth: 1,
            priority: 100,
        };
        let number = state.begin_visit(&item);
        state.sample_when_visit_finishes(number, &item.url, "partial-layout", "view_0001");
        state.visit_explores(number, "partial-key", "view_0001");
        assert!(state.retry_visit_after_relogin(number));
        state.finish_visit(number); // VisitSlot may still finish after withdrawing.
        assert!(state.template_sampler.templates.is_empty());
        assert!(state.template_sampler.source_templates.is_empty());
    }

    #[test]
    fn resume_recomputes_derived_gaps_and_preserves_observed_gaps() {
        use coverage::{CoverageGap, CoverageGapKind};
        let mut state = RuntimeState::new("http://127.0.0.1:47280/".into());
        state.coverage_gaps = vec![
            (CoverageGapKind::StopCondition, "interrupted"),
            (CoverageGapKind::SeededRoute, "seed_route_not_reached"),
            (CoverageGapKind::OrphanNavItem, "not_visited"),
            (CoverageGapKind::Interaction, "view_time_budget"),
            (CoverageGapKind::Route, "navigation_failed"),
            (CoverageGapKind::UnexploredMutation, "modal_depth_limit"),
        ]
        .into_iter()
        .map(|(kind, reason)| CoverageGap {
            kind,
            target: "http://127.0.0.1:47280/later".into(),
            reason: reason.into(),
            context: None,
        })
        .collect();
        let cfg = test_cfg("");
        let cp = engine::build_checkpoint(&cfg, Utc::now(), 42, &state, vec![], vec![]);
        let cp = serde_json::from_slice(&serde_json::to_vec(&cp).unwrap()).unwrap();
        let (resumed, _, _) = RuntimeState::from_checkpoint(cp);
        let reasons: Vec<_> = resumed
            .coverage_gaps
            .iter()
            .map(|g| g.reason.as_str())
            .collect();
        assert_eq!(
            reasons,
            ["view_time_budget", "navigation_failed", "modal_depth_limit"]
        );

        // The current pass still reports genuinely unreached seeds, and
        // drops them once reached, independently of the old attempt.
        let base = url::Url::parse("http://127.0.0.1:47280/").unwrap();
        let seeded =
            BTreeMap::from([("http://127.0.0.1:47280/later".into(), vec!["source".into()])]);
        assert_eq!(
            coverage::detect_seeded_route_gaps(&seeded, &HashSet::new(), &HashSet::new(), &base)
                .len(),
            1
        );
        let visited = seeded.keys().cloned().collect();
        assert!(
            coverage::detect_seeded_route_gaps(&seeded, &visited, &HashSet::new(), &base)
                .is_empty()
        );
    }

    #[test]
    fn abandoned_visits_go_back_to_the_front_of_the_queue() {
        let (mut state, number) = state_with_visit_in_flight();
        state.abandon_visit(number);
        assert!(state.ctl.in_flight_visits.is_empty());
        assert!(!state.visited_fingerprints.contains("busy-key"));
        assert!(state.visited_fingerprints.contains("done-key"));
        assert_eq!(state.views.len(), 1);
        assert_eq!(state.pending_transitions.len(), 1);
        assert!(!state.exercised_controls.contains_key("busy-control"));
        assert!(state.expanded_nav_dropdown_triggers.is_empty());
        let next = state
            .scheduler
            .pop_next(crate::config::ExplorationStrategy::BreadthFirst)
            .unwrap();
        assert_eq!(next.url, "http://127.0.0.1:47280/busy");
        // A finished visit leaves everything in place.
        let (mut state, number) = state_with_visit_in_flight();
        state.finish_visit(number);
        assert_eq!(state.views.len(), 2);
        assert!(state.visited_fingerprints.contains("busy-key"));
    }

    #[test]
    fn withdrawn_views_retire_their_ids_and_drop_their_rows_at_finalization() {
        let (mut state, number) = state_with_visit_in_flight();
        assert!(state.retry_visit_after_relogin(number));
        assert!(state.retracted_views.contains("view_0002"));
        assert!(!state.fingerprint_to_view.values().any(|v| v == "view_0002"));
        assert_eq!(state.views.len(), 1);
        // Explored again under a new id, and only once per URL.
        assert_eq!(state.allocate_view_id(), "view_0003");
        let item = crate::output::checkpoint::QueuedUrl {
            url: "http://127.0.0.1:47280/busy".to_string(),
            depth: 1,
            priority: 0,
        };
        let again = state.begin_visit(&item);
        assert!(!state.retry_visit_after_relogin(again));
        assert!(state.ctl.in_flight_visits.contains_key(&again));

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path()
                .join(crate::output::interactions::INTERACTIONS_FILE),
            "{\"view_id\":\"view_0002:d1:0\"}\n{\"view_id\":\"view_0003\"}\n",
        )
        .unwrap();
        assert_eq!(
            drop_retracted_interactions(tmp.path(), &state.retracted_views).unwrap(),
            1
        );
        assert_eq!(
            drop_retracted_interactions(tmp.path(), &BTreeSet::new()).unwrap(),
            0
        );
    }

    #[test]
    fn stop_rules_wait_for_routes_not_visited_yet() {
        let cfg = test_cfg("");
        let (mut state, _) = state_with_visit_in_flight();
        // `/later` is queued and its route was never explored.
        assert!(state.unvisited_route_pending(&cfg, "http://127.0.0.1:47280/done"));
        assert!(state.unvisited_route_pending(&cfg, "http://127.0.0.1:47280/new"));
        state.scheduler.clear();
        assert!(state.unvisited_route_pending(&cfg, "http://127.0.0.1:47280/done?tab=2"));
        assert!(!state.unvisited_route_pending(
            &cfg,
            "http://127.0.0.1:47280/done?utm_source=mail&page=2&q=test"
        ));
        state
            .scheduler
            .enqueue("http://127.0.0.1:47280/done#top".to_string(), 1);
        assert!(!state.unvisited_route_pending(&cfg, "http://127.0.0.1:47280/done"));
        // Too deep to be visited: does not hold the crawl.
        state.scheduler.clear();
        state.scheduler.enqueue(
            "http://127.0.0.1:47280/deep".to_string(),
            cfg.scan.max_depth + 1,
        );
        assert!(!state.unvisited_route_pending(&cfg, "http://127.0.0.1:47280/done"));
    }

    #[test]
    fn completion_status_reflects_how_the_crawl_ended() {
        use run_report::stop_reason as r;
        let finished = CrawlEnd::Finished;
        assert_eq!(
            completion_status_for(&finished, Some(r::QUEUE_EXHAUSTED)),
            "ok"
        );
        assert_eq!(completion_status_for(&finished, Some(r::CONVERGENCE)), "ok");
        assert_eq!(
            completion_status_for(&finished, Some(r::SESSION_EXPIRED)),
            "session_expired"
        );
        assert_eq!(
            completion_status_for(&finished, Some(r::BROWSER_UNAVAILABLE)),
            "browser_unavailable"
        );
        assert_eq!(
            completion_status_for(&CrawlEnd::HardTimeout, None),
            "partial_timeout"
        );
        assert_eq!(
            completion_status_for(
                &CrawlEnd::Interrupted(interrupt::InterruptKind::Terminate),
                Some(r::SESSION_EXPIRED)
            ),
            "interrupted"
        );
    }

    #[test]
    fn resume_compacts_interaction_rows_of_views_the_checkpoint_does_not_hold() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp
            .path()
            .join(crate::output::interactions::INTERACTIONS_FILE);
        std::fs::write(
            &log,
            concat!(
                "{\"view_id\":\"view_0001\",\"selector\":\"a\"}\n",
                "{\"view_id\":\"view_0001:d1:0\",\"selector\":\"b\"}\n",
                "{\"view_id\":\"view_0002\",\"selector\":\"c\"}\n",
                "{\"view_id\":\"view_00"
            ),
        )
        .unwrap();
        let keep: HashSet<String> = ["view_0001".to_string()].into_iter().collect();
        assert_eq!(compact_interaction_log(tmp.path(), &keep).unwrap(), 2);
        let rows = std::fs::read_to_string(&log).unwrap();
        assert_eq!(rows.lines().count(), 2);
        assert!(rows.lines().all(|l| l.contains("view_0001")));
        // Nothing to drop: the file is left alone.
        assert_eq!(compact_interaction_log(tmp.path(), &keep).unwrap(), 0);
        assert_eq!(
            compact_interaction_log(&tmp.path().join("missing"), &keep).unwrap(),
            0
        );
    }

    #[test]
    fn fresh_checkpoints_keep_the_previous_format() {
        let cfg = test_cfg("");
        let state = RuntimeState::new("http://127.0.0.1:47280/".to_string());
        let cp = engine::build_checkpoint(&cfg, Utc::now(), 0, &state, vec![], vec![]);
        let json = serde_json::to_value(&cp).unwrap();
        assert!(json.get("crawl").is_none(), "{json}");
    }
}
