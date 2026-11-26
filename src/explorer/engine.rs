use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chromiumoxide::cdp::browser_protocol::page as cdp_page;
use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;

use crate::browser::{BrowserManager, cdp_helpers};
use crate::bugs::BugDetector;
use crate::config::BrokenAppConfig;
use crate::dom::classifier::{
    classify_current_view, enrich_detail_view_entity, enrich_forms_with_endpoints,
};
use crate::dom::{discover_interactive_elements, fingerprint_dom};
use crate::explorer::template_sampler::TemplateVisitDecision;
use crate::network::interceptor::NetworkInterceptor;
use crate::network::schema_inference;
use crate::output::{
    self,
    checkpoint::{CheckpointWriter, PendingTransition, QueuedUrl, ScanCheckpoint},
    interactions::InteractionLog,
};
use crate::scope::ScopeFilter;
use crate::session::SessionManager;
use crate::types::api::{ApiEndpoint, EndpointKey, HttpMethod, TrafficEntry};
use crate::types::bugs::{Bug, BugCategory, BugEvidence, BugLocation, BugSeverity};
use crate::types::classifier::{ClassifiedView, ComponentType};
use crate::types::dom::{ElementType, InteractionRef};
use crate::types::graph::{AppView, DomFingerprint, TransitionType, ViewTransition};

use super::{
    RuntimeState, ScanOutcome, SharedState, coverage, form_mapping, interaction, url_utils,
};

#[derive(Debug, Clone, Copy)]
struct EtaEstimate {
    seconds: u64,
    basis: &'static str,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RawA11yResult {
    category: String,
    #[serde(default)]
    selector: Option<String>,
    description: String,
}

/// Real-time progress snapshot written to `--progress-file` for external
/// consumers (e.g. the hosted scan service or CI integrations).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanProgress {
    pub phase: String,
    pub views_found: usize,
    pub endpoints_found: usize,
    pub bugs_found: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_observations_found: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_url: Option<String>,
    pub coverage_pct: f64,
    pub elapsed_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_remaining_seconds: Option<u64>,
}

fn is_antibot_challenge(title: &str, url: &str, body_text: &str) -> bool {
    let t = title.trim().to_ascii_lowercase();
    let u = url.to_ascii_lowercase();
    let b = body_text.to_ascii_lowercase();

    let title_markers = [
        "just a moment",
        "attention required",
        "checking your browser",
        "verify you are human",
        "ddos-guard",
        "security check",
        "human verification",
    ];
    let url_markers = [
        "/cdn-cgi/challenge-platform",
        "/cdn-cgi/l/chk_",
        "__cf_chl_",
        "datadome.co/captcha",
    ];
    let body_phrases = [
        "verify you are human",
        "checking if the site connection is secure",
        "please stand by, while we are checking your browser",
        "enable javascript and cookies to continue",
    ];

    title_markers.iter().any(|k| t.contains(k))
        || url_markers.iter().any(|k| u.contains(k))
        || body_phrases.iter().any(|k| b.contains(k))
        || (b.contains("cloudflare") && b.contains("ray id:"))
}

/// Crawl the queue with `scan.max_concurrent_tabs` page workers (tabs of
/// one browser) pulling views from the shared scheduler. With one tab the
/// crawl is sequential, as before.
///
/// Workers share the runtime state behind a lock that is only held for
/// synchronous sections. Each view is explored by exactly one tab; each tab
/// has its own page, write guard (Fetch interception attached before its
/// first navigation) and attribution state, so requests, console errors and
/// dialogs are only ever credited to actions of the tab they happened in.
#[allow(clippy::too_many_arguments)]
pub(super) async fn scan_loop(
    cfg: &BrokenAppConfig,
    started_at: DateTime<Utc>,
    start_instant: Instant,
    browser: &BrowserManager,
    session_state: &mut crate::session::SessionState,
    network: &Arc<NetworkInterceptor>,
    bug_detector: &Arc<BugDetector>,
    base_url: &Url,
    scope_filter: Option<&ScopeFilter>,
    state: &mut RuntimeState,
    checkpoint_writer: &mut CheckpointWriter,
    interaction_log: Option<&InteractionLog>,
) -> Result<()> {
    if state.template_sampler.route_templates.is_empty() {
        state
            .template_sampler
            .set_route_templates(source_route_templates(cfg));
    }
    state
        .scheduler
        .set_route_templates(state.template_sampler.route_templates.clone());
    for view in &state.views {
        state.scheduler.mark_visited_template(&view.url);
    }
    for url in state.url_to_view.keys() {
        state.scheduler.mark_visited_template(url);
    }
    register_pinned_seed_urls(cfg, state);
    if state.views.is_empty() && state.resumes == 0 {
        prioritize_fresh_scan_seeds(cfg, base_url, state);
    }
    state.ctl = super::LoopControl::new();
    let tabs = super::crawl_tab_count(cfg);
    if tabs > 1 {
        tracing::info!(tabs, "crawling with parallel tabs");
    }

    let (cancel, _) = tokio::sync::watch::channel(false);
    let login_hint = session_state.login_hint.clone();
    let crawl = Crawl {
        cfg,
        started_at,
        start_instant,
        browser,
        network,
        bug_detector,
        base_url,
        scope_filter,
        interaction_log,
        tabs,
        progress_interval_seconds: scan_progress_interval_seconds(cfg),
        state: std::sync::Mutex::new(state),
        session: tokio::sync::Mutex::new(SessionCtl {
            session_state,
            reauth_attempts: 0,
            generation: 0,
            alive_at: None,
            expired: false,
        }),
        saver: tokio::sync::Mutex::new(checkpoint_writer),
        save_timing: std::sync::Mutex::new(SaveTiming::default()),
        session_health: crate::session::health::SessionHealthMonitor::default(),
        visit_done: tokio::sync::Notify::new(),
        cancel,
        login_hint,
        antibot_challenges: std::sync::atomic::AtomicUsize::new(0),
    };

    crawl.verify_saved_session_at_start().await;
    let workers = futures::future::try_join_all(
        (0..tabs).map(|worker| assert_send(crawl.run_worker(worker))),
    );
    tokio::select! {
        result = workers => {
            result?;
        }
        _ = assert_send(crawl.checkpoint_ticker()) => {}
        _ = assert_send(crawl.duration_stopper()) => {}
    }

    // The final checkpoint and artifacts are written by the caller.
    crawl.process_network_errors().await
}

/// Compile-time check that a worker never holds the state lock (a
/// `std::sync::MutexGuard`) across an `.await`: such a future is not `Send`.
fn assert_send<F: std::future::Future + Send>(future: F) -> F {
    future
}

/// How long an idle worker waits for a running visit to end before it
/// looks at the queue again (visits normally wake it right away).
const IDLE_WORKER_POLL: Duration = Duration::from_millis(250);

/// How often the checkpoint ticker looks whether a save is due (saves also
/// follow visits; the ticker covers long views).
const CHECKPOINT_TICK: Duration = Duration::from_secs(5);
/// Longest interval between incremental saves (plus the current save time).
const MAX_SAVE_INTERVAL: Duration = Duration::from_secs(60);
/// Page creations failing in a row before the browser is taken for gone.
const MAX_CONSECUTIVE_PAGE_FAILURES: usize = 4;
/// Failed re-logins in a row before the session counts as expired.
const MAX_REAUTH_ATTEMPTS: usize = 3;
/// A session canary that passed this recently is trusted without another.
const CANARY_FRESHNESS: Duration = Duration::from_secs(30);
/// View budget a session check after a view's interactions needs (a
/// re-login runs inside the view's watchdog).
const SESSION_CHECK_RESERVE: Duration = Duration::from_secs(30);
/// Grace window after `max_duration_minutes` expires during which in-flight
/// visits flush and commit their current view before remaining stuck workers
/// are cancelled (kept safely inside `hard_scan_timeout`'s 15s grace).
const GRACEFUL_DURATION_FLUSH: Duration = Duration::from_secs(10);
/// Upper bound for closing a single browser tab (open SSE streams can stall an
/// unbounded `Target.closeTarget`).
const PAGE_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// When the last incremental save ran and what it cost.
#[derive(Debug, Clone, Copy)]
struct SaveTiming {
    last: Instant,
    cost: Duration,
}

impl Default for SaveTiming {
    fn default() -> Self {
        Self {
            last: Instant::now(),
            cost: Duration::ZERO,
        }
    }
}

/// Interval between incremental saves: `output.checkpoint_interval_seconds`
/// stretched to five times the last save's cost when useful, but never
/// beyond a minute. Saves run serially; a save already running is not repeated.
fn save_interval(configured_seconds: u64, last_cost: Duration) -> Duration {
    Duration::from_secs(configured_seconds.max(1))
        .max(last_cost.saturating_mul(5))
        .min(MAX_SAVE_INTERVAL)
}

/// Everything the page workers of one crawl share.
struct Crawl<'a> {
    cfg: &'a BrokenAppConfig,
    started_at: DateTime<Utc>,
    start_instant: Instant,
    browser: &'a BrowserManager,
    network: &'a Arc<NetworkInterceptor>,
    bug_detector: &'a Arc<BugDetector>,
    base_url: &'a Url,
    scope_filter: Option<&'a ScopeFilter>,
    interaction_log: Option<&'a InteractionLog>,
    /// Page workers (tabs) crawling concurrently.
    tabs: usize,
    progress_interval_seconds: u64,
    /// Queue, view identity, budgets and everything the crawl accumulates.
    state: SharedState<'a>,
    /// The auth session and re-auth bookkeeping. Held across awaits
    /// (re-auth, canaries), so workers apply a consistent session.
    session: tokio::sync::Mutex<SessionCtl<'a>>,
    /// Incremental saves, one at a time (they write the same files).
    saver: tokio::sync::Mutex<&'a mut CheckpointWriter>,
    save_timing: std::sync::Mutex<SaveTiming>,
    session_health: crate::session::health::SessionHealthMonitor,
    /// Wakes idle workers when a visit ends: the queue may have grown, or
    /// the crawl is done.
    visit_done: tokio::sync::Notify,
    /// Set when the crawl must stop at once (the session expired, the
    /// browser is gone): visits in flight are abandoned and requeued.
    cancel: tokio::sync::watch::Sender<bool>,
    /// The app's login page path, when the auth method names one.
    login_hint: Option<String>,
    /// Number of WAF / anti-bot challenge pages encountered during this crawl.
    antibot_challenges: std::sync::atomic::AtomicUsize,
}

struct SessionCtl<'a> {
    session_state: &'a mut crate::session::SessionState,
    /// Re-logins that failed in a row.
    reauth_attempts: usize,
    /// Bumped by every successful re-login. A tab whose page got an older
    /// session and then hit the login page retries with the new session
    /// instead of logging in again: one re-login per expiry, however many
    /// tabs notice it.
    generation: u64,
    /// When the session canary last passed.
    alive_at: Option<Instant>,
    /// The session ended and cannot be renewed: the crawl stops.
    expired: bool,
}

/// What [`Crawl::recover_session`] concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovery {
    /// The session is alive: a login page reached now is a route gated for
    /// this role, not an expired session.
    Alive,
    /// A new session is in place (logged in again here or by another tab):
    /// apply it and retry.
    Renewed,
    /// Logging in again failed; the crawl goes on (it stops once the
    /// attempts are exhausted).
    Failed,
    /// The session is gone for good: the crawl stops (`session_expired`).
    Expired,
}

/// What raised a session check.
#[derive(Debug, Clone)]
enum SessionTrigger {
    /// A tab asked for `url` and landed on the login page `landed`.
    LoginGate { url: String, landed: String },
    /// Repeated 401/403 responses.
    AuthFailures,
    /// A periodic or pre-route canary failed.
    Canary,
}

impl SessionTrigger {
    fn name(&self) -> &'static str {
        match self {
            SessionTrigger::LoginGate { .. } => "login_gate",
            SessionTrigger::AuthFailures => "auth_failures",
            SessionTrigger::Canary => "canary",
        }
    }

    fn urls(&self) -> (Option<String>, Option<String>) {
        match self {
            SessionTrigger::LoginGate { url, landed } => (Some(url.clone()), Some(landed.clone())),
            _ => (None, None),
        }
    }
}

/// Result of a session canary.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Canary {
    Alive,
    LoggedOut(String),
    /// No canary is known for this session (no protected probe, no page the
    /// login landed on).
    Unknown,
}

/// What a worker does next.
enum Next<'c, 'a> {
    Visit(QueuedUrl, VisitSlot<'c, 'a>),
    /// A route template just saturated: persist progress, then ask again.
    Persist,
    /// Nothing to start now, but visits are running that may queue more
    /// (or the view budget is spoken for by running visits).
    Wait,
    Done,
}

/// A visit in progress. It counts as in flight until dropped; it holds the
/// route-template sampling reservation of its URL, its control-identity
/// scope and the identity of the view it explores.
struct VisitSlot<'c, 'a> {
    crawl: &'c Crawl<'a>,
    /// Visit number (`RuntimeState::begin_visit`).
    visit: u64,
    /// The visit ran to its end. A slot dropped unfinished (the crawl was
    /// stopped or interrupted mid-visit) puts its URL back in the queue.
    finished: bool,
    template: Option<crate::explorer::template_sampler::TemplateSlot>,
    scope: Option<String>,
    view_key: Option<String>,
    /// The view explored, once known: claims on controls it still holds
    /// when the visit ends (watchdog) are released.
    view_id: Option<String>,
}

impl Drop for VisitSlot<'_, '_> {
    fn drop(&mut self) {
        {
            let mut st = self.crawl.lock();
            if self.finished {
                st.finish_visit(self.visit);
            } else {
                st.abandon_visit(self.visit);
            }
            if let Some(slot) = self.template.take() {
                st.template_sampler.release(slot);
            }
            if let Some(key) = self.view_key.take() {
                st.ctl.active_views.remove(&key);
            }
            if let Some(view_id) = self.view_id.take() {
                interaction::release_view_claims(&mut st.exercised_controls, &view_id);
            }
            if let Some(scope) = self.scope.take()
                && let Some(busy) = st.ctl.busy_scopes.get_mut(&scope)
            {
                *busy = busy.saturating_sub(1);
                if *busy == 0 {
                    st.ctl.busy_scopes.remove(&scope);
                }
            }
            st.ctl.in_flight = st.ctl.in_flight.saturating_sub(1);
        }
        self.crawl.visit_done.notify_waiters();
    }
}

impl<'a> Crawl<'a> {
    fn lock(&self) -> std::sync::MutexGuard<'_, &'a mut RuntimeState> {
        super::lock_state(&self.state)
    }

    async fn run_worker(&self, worker: usize) -> Result<()> {
        let mut pacer = interaction::AdaptiveRateLimitPacer::new(
            self.cfg.scan.pacing.delay_between_interactions_ms,
            self.network.as_ref(),
        );
        loop {
            // Register for the wake-up before looking at the queue, so a
            // visit that ends in between is not missed.
            let woken = self.visit_done.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            let (next, progress) = self.next_item();
            if let Some(progress) = progress {
                write_progress_file(self.cfg, self.bug_detector, progress).await;
            }
            match next {
                Next::Done => return Ok(()),
                Next::Wait => {
                    let _ = tokio::time::timeout(IDLE_WORKER_POLL, woken).await;
                }
                Next::Persist => self.save_progress(false).await,
                Next::Visit(item, mut slot) => {
                    tracing::debug!(worker, url = %item.url, "worker took a url");
                    let mut cancelled = self.cancel.subscribe();
                    let visit = async {
                        self.canary_before_new_route(&item).await?;
                        self.visit(&mut pacer, &item, &mut slot).await
                    };
                    // A crawl stopped at once (expired session, browser gone)
                    // drops the visit: the slot puts its URL back in the queue
                    // unless the visit already committed its view (`slot.finished`).
                    let finished = tokio::select! {
                        result = visit => {
                            result?;
                            true
                        }
                        _ = cancelled.wait_for(|stop| *stop) => false,
                    };
                    slot.finished |= finished;
                }
            }
        }
    }

    /// Stop the crawl now for `reason`: no new visits start and visits in
    /// flight are abandoned (their URLs go back to the queue, so a resume
    /// explores them).
    fn stop_now(&self, reason: &'static str) {
        self.lock().ctl.stop(reason);
        let _ = self.cancel.send(true);
        self.visit_done.notify_waiters();
    }

    /// Saves due incremental checkpoints while visits run (a view may take
    /// minutes on a full run) and keeps `--progress-file` fresh. Never ends.
    async fn checkpoint_ticker(&self) {
        loop {
            tokio::time::sleep(CHECKPOINT_TICK).await;
            let progress = {
                let mut st = self.lock();
                progress_file_due(self.cfg, self.start_instant, &mut st, self.network, None)
            };
            if let Some(progress) = progress {
                write_progress_file(self.cfg, self.bug_detector, progress).await;
            }
            self.save_progress(false).await;
        }
    }

    /// Gracefully stops the crawl when `max_duration_minutes` elapses: marks
    /// the loop stopping so idle workers exit and active visits finish and
    /// commit their views within [`GRACEFUL_DURATION_FLUSH`], cancelling only
    /// still-stuck workers before `hard_timeout` drops the scan loop.
    async fn duration_stopper(&self) {
        if self.cfg.scan.max_duration_minutes == 0 {
            std::future::pending::<()>().await;
            return;
        }
        let budget = Duration::from_secs(self.cfg.scan.max_duration_minutes.saturating_mul(60));
        let remaining = budget.saturating_sub(self.start_instant.elapsed());
        if !remaining.is_zero() {
            tokio::time::sleep(remaining).await;
        }
        {
            let mut st = self.lock();
            if !st.ctl.stopping {
                st.coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                        target: "scan_loop".to_string(),
                        reason: "max_duration_reached".to_string(),
                        context: Some(format!(
                            "max_duration_minutes={}",
                            self.cfg.scan.max_duration_minutes
                        )),
                    });
                st.ctl.stop(super::run_report::stop_reason::MAX_DURATION);
            }
        }
        self.visit_done.notify_waiters();
        tokio::time::sleep(GRACEFUL_DURATION_FLUSH).await;
        self.stop_now(super::run_report::stop_reason::MAX_DURATION);
        std::future::pending::<()>().await;
    }

    /// Pop the next URL to visit, applying the stop conditions and template
    /// sampling, plus a progress-file snapshot when one is due.
    fn next_item(&self) -> (Next<'_, 'a>, Option<ScanProgress>) {
        let cfg = self.cfg;
        let mut guard = self.lock();
        let st: &mut RuntimeState = &mut guard;
        if st.ctl.stopping {
            return (Next::Done, None);
        }
        // Running visits may each add a view: do not start one that could
        // take the crawl past `max_views` (a sequential crawl never waits).
        if cfg.scan.max_views > 0
            && st.ctl.in_flight > 0
            && st.views.len() + st.ctl.in_flight >= cfg.scan.max_views
        {
            return (Next::Wait, None);
        }
        let mut progress = None;
        loop {
            // A URL whose control-identity scope (route template, else route)
            // another tab is exploring waits for it, so sibling instances of a
            // template are explored one after the other, as in a sequential
            // crawl. Other routes go ahead.
            let next = {
                let busy = &st.ctl.busy_scopes;
                let sampler = &st.template_sampler;
                st.scheduler
                    .pop_next_matching(cfg.scan.exploration.strategy, |queued| {
                        busy.is_empty()
                            || !busy
                                .contains_key(&interaction::identity_scope(sampler, &queued.url))
                    })
            };
            let Some(item) = next else {
                if st.ctl.in_flight == 0 {
                    st.ctl.stopping = true;
                    return (Next::Done, progress);
                }
                return (Next::Wait, progress);
            };
            st.ctl.processed_items = st.ctl.processed_items.saturating_add(1);
            maybe_emit_scan_checkpoint(
                cfg,
                self.start_instant,
                st,
                self.network,
                self.progress_interval_seconds,
            );
            if progress.is_none() {
                progress = progress_file_due(
                    cfg,
                    self.start_instant,
                    st,
                    self.network,
                    Some(item.url.as_str()),
                );
            }
            if cfg.scan.stop_on_convergence {
                let window = cfg.scan.convergence_window_views.max(1);
                if st.ctl.recent_new_fingerprints.len() >= window {
                    let new_count = st
                        .ctl
                        .recent_new_fingerprints
                        .iter()
                        .filter(|v| **v)
                        .count();
                    let coverage_pct = if st.elements_discovered == 0 {
                        0.0
                    } else {
                        (st.elements_interacted as f64 / st.elements_discovered as f64) * 100.0
                    };
                    // Never converged while a route was not visited yet: a
                    // long run of known views does not mean nothing new is
                    // left.
                    if coverage_pct >= cfg.scan.convergence_min_coverage_percent
                        && new_count <= cfg.scan.convergence_max_new_views
                        && !st.unvisited_route_pending(cfg, &item.url)
                    {
                        st.coverage_gaps
                            .push(crate::explorer::coverage::CoverageGap {
                                kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                                target: "scan_loop".to_string(),
                                reason: "convergence_reached".to_string(),
                                context: Some(format!(
                                    "coverage={coverage_pct:.2} new_views_window={new_count}/{window}"
                                )),
                            });
                        tracing::info!(
                            coverage_pct,
                            new_views_window = new_count,
                            window,
                            "stopping scan: convergence criteria satisfied"
                        );
                        st.ctl.stop(super::run_report::stop_reason::CONVERGENCE);
                        return (Next::Done, progress);
                    }
                }
            }
            if let Some(sf) = self.scope_filter {
                if let Ok(u) = Url::parse(&item.url) {
                    if url_utils::same_origin(self.base_url, &u) && !sf.allows_path(u.as_str()) {
                        st.coverage_gaps
                            .push(crate::explorer::coverage::CoverageGap {
                                kind: crate::explorer::coverage::CoverageGapKind::Route,
                                target: item.url.clone(),
                                reason: "outside_scope".to_string(),
                                context: Some(sf.name.clone()),
                            });
                        tracing::debug!(
                            url = %item.url,
                            scope = %sf.name,
                            "skipping url: outside scan scope"
                        );
                        continue;
                    }
                }
            }
            if !cfg.scan.allowed_hosts.is_empty()
                && !crate::network::filters::url_matches_allowed_hosts(
                    &item.url,
                    &cfg.scan.allowed_hosts,
                )
            {
                st.coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::Route,
                        target: item.url.clone(),
                        reason: "outside_allowed_hosts".to_string(),
                        context: None,
                    });
                tracing::debug!(url = %item.url, "skipping url: outside scan.allowed_hosts");
                continue;
            }
            if cfg.scan.abort_on_rate_limits > 0 {
                let recent_429 = self
                    .network
                    .recent_rate_limit_count(Duration::from_secs(60));
                if recent_429 >= cfg.scan.abort_on_rate_limits {
                    st.coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                            target: "scan_loop".to_string(),
                            reason: super::run_report::stop_reason::RATE_LIMITED.to_string(),
                            context: Some(format!(
                                "http_429_last_60s={recent_429} threshold={}",
                                cfg.scan.abort_on_rate_limits
                            )),
                        });
                    tracing::warn!(
                        http_429_last_60s = recent_429,
                        threshold = cfg.scan.abort_on_rate_limits,
                        "aborting scan: target returned repeated HTTP 429 rate-limit responses"
                    );
                    st.ctl.stop(super::run_report::stop_reason::RATE_LIMITED);
                    let _ = self.cancel.send(true);
                    return (Next::Done, progress);
                }
            }
            if item.depth > cfg.scan.max_depth {
                st.coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::Route,
                        target: item.url.clone(),
                        reason: "max_depth".to_string(),
                        context: Some(format!(
                            "depth={} max_depth={}",
                            item.depth, cfg.scan.max_depth
                        )),
                    });
                continue;
            }
            if cfg.scan.max_views > 0 && st.views.len() >= cfg.scan.max_views {
                st.coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                        target: "scan_loop".to_string(),
                        reason: "max_views_reached".to_string(),
                        context: Some(format!(
                            "views={} max_views={}",
                            st.views.len(),
                            cfg.scan.max_views
                        )),
                    });
                st.ctl.stop(super::run_report::stop_reason::MAX_VIEWS);
                return (Next::Done, progress);
            }
            if cfg.scan.max_duration_minutes > 0
                && self.start_instant.elapsed()
                    > Duration::from_secs(cfg.scan.max_duration_minutes.saturating_mul(60))
            {
                st.coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                        target: "scan_loop".to_string(),
                        reason: "max_duration_reached".to_string(),
                        context: Some(format!(
                            "max_duration_minutes={}",
                            cfg.scan.max_duration_minutes
                        )),
                    });
                st.ctl.stop(super::run_report::stop_reason::MAX_DURATION);
                return (Next::Done, progress);
            }
            if cfg.scan.max_stagnation_minutes > 0
                && st.ctl.last_new_fingerprint_at.elapsed()
                    > Duration::from_secs(cfg.scan.max_stagnation_minutes.saturating_mul(60))
                && !st.unvisited_route_pending(cfg, &item.url)
            {
                st.coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                        target: "scan_loop".to_string(),
                        reason: "stagnation_guard".to_string(),
                        context: Some(format!(
                            "max_stagnation_minutes={}",
                            cfg.scan.max_stagnation_minutes
                        )),
                    });
                tracing::info!(
                    stagnation_minutes = cfg.scan.max_stagnation_minutes,
                    queue_remaining = st.scheduler.len(),
                    views = st.views.len(),
                    "stopping scan: no new view fingerprints discovered recently"
                );
                st.ctl.stop(super::run_report::stop_reason::STAGNATION);
                return (Next::Done, progress);
            }

            match st.template_sampler.should_visit(&item.url) {
                TemplateVisitDecision::Visit => {}
                TemplateVisitDecision::Skip {
                    template,
                    reason,
                    saturated_now,
                } => {
                    st.coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: crate::explorer::coverage::CoverageGapKind::Route,
                            target: item.url.clone(),
                            reason: format!("template_sampling:{reason}"),
                            context: Some(template.clone()),
                        });
                    if saturated_now {
                        tracing::info!(template = %template, reason = %reason, "template sampling saturated; skipping further instances");
                        if !st.template_sampler.has_pinned_for_template(&template) {
                            let removed = st.scheduler.purge_template_from_queue(&template);
                            if removed > 0 {
                                tracing::info!(template = %template, removed, "removed queued urls for saturated template");
                            }
                        }
                        return (Next::Persist, progress);
                    }
                    tracing::debug!(url = %item.url, template = %template, reason = %reason, "skipping url due to template sampling");
                    continue;
                }
            }

            let template = st.template_sampler.reserve(&item.url);
            let scope = interaction::identity_scope(&st.template_sampler, &item.url);
            *st.ctl.busy_scopes.entry(scope.clone()).or_insert(0) += 1;
            st.ctl.in_flight += 1;
            let visit = st.begin_visit(&item);
            let slot = VisitSlot {
                crawl: self,
                visit,
                finished: false,
                template,
                scope: Some(scope),
                view_key: None,
                view_id: None,
            };
            return (Next::Visit(item, slot), progress);
        }
    }

    /// A page for one visit. Parallel tabs get a window each, so no tab is
    /// a hidden background tab.
    async fn new_page(&self) -> Result<crate::browser::PageClient> {
        if self.tabs > 1 {
            self.browser.new_window_page("about:blank").await
        } else {
            self.browser.new_page("about:blank").await
        }
    }

    /// Apply the current auth session to a fresh page; returns its
    /// generation (see [`SessionCtl::generation`]).
    async fn apply_session(&self, page: &crate::browser::PageClient) -> Result<u64> {
        let session = self.session.lock().await;
        SessionManager::apply_to_page(page, &*session.session_state).await?;
        Ok(session.generation)
    }

    /// Record findings for failed requests and re-authenticate when the
    /// session died. One worker at a time.
    async fn process_network_errors(&self) -> Result<()> {
        let entries = self.network.take_error_traffic().await;
        process_network_errors(
            self.bug_detector,
            entries,
            Some(&self.session_health),
            Some(self.base_url),
        )
        .await?;
        let ws_errors = self.network.take_ws_errors().await;
        for ws_err in ws_errors {
            let (view, element) = match ws_err.triggered_by {
                Some(ref r) if r.selector != "__page_load__" => {
                    (Some(r.view.clone()), Some(r.selector.clone()))
                }
                Some(ref r) => (Some(r.view.clone()), None),
                None => (None, None),
            };
            self.bug_detector
                .record_websocket_error(
                    ws_err.url,
                    ws_err.message,
                    view,
                    element,
                    None,
                    ws_err.action_id,
                )
                .await;
        }
        if self.cfg.auth.is_none() {
            return Ok(());
        }
        // One 401/403 is checked right away when a protected probe can tell
        // (cheap); otherwise a run of them makes the session suspect.
        let probe_configured = self
            .cfg
            .auth_contract
            .as_ref()
            .is_some_and(|c| c.protected_probe.is_some());
        let dead = self.session_health.is_session_dead();
        if !dead && !(probe_configured && self.session_health.is_single_failure_recoverable()) {
            return Ok(());
        }
        let generation = {
            let mut session = self.session.lock().await;
            if session.expired {
                return Ok(());
            }
            // A token refresh (Supabase, Firebase) renews without a login.
            if dead && session.session_state.refresh_token.is_some() {
                match SessionManager::try_token_refresh(session.session_state).await {
                    Ok(true) => {
                        tracing::info!("token refresh succeeded; resetting session health");
                        self.session_health.reset();
                        session.reauth_attempts = 0;
                        session.generation += 1;
                        return Ok(());
                    }
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!(error = ?err, "token refresh failed, falling back to full re-auth");
                    }
                }
            }
            session.generation
        };
        match self
            .recover_session(generation, SessionTrigger::AuthFailures, false)
            .await
        {
            Recovery::Alive => self.session_health.clear_consecutive_failures(),
            Recovery::Renewed => self.session_health.reset(),
            Recovery::Failed | Recovery::Expired => {}
        }
        Ok(())
    }

    /// `true` when visiting `requested` landed on the login page.
    fn landed_on_login(&self, requested: &str, landed: &str) -> bool {
        crate::session::health::landed_on_login_gate(requested, landed, self.login_hint.as_deref())
    }

    /// Record an auth-session event (`scan-run.json`, telemetry).
    fn record_session_event(
        &self,
        event: &str,
        trigger: &str,
        urls: (Option<String>, Option<String>),
        success: bool,
        attempt: Option<usize>,
        detail: Option<String>,
    ) {
        let (url, landed) = urls;
        self.lock()
            .session_log
            .record(super::run_report::SessionEvent {
                at: Utc::now(),
                event: event.to_string(),
                trigger: trigger.to_string(),
                url,
                landed,
                success,
                attempt,
                detail,
            });
    }

    /// Decide what a suspected session loss means, one tab at a time.
    /// `observed` is the session generation the caller's page got. A new
    /// generation means another tab renewed the session meanwhile (retry,
    /// no second login). Otherwise the session canary decides, unless
    /// `confirmed` (a canary failed already): alive means the login page is
    /// a gate of this role; gone means log in again (form roles: once, then
    /// retry the view) or stop the crawl (`session_expired`: a saved or
    /// manual session cannot be renewed unattended).
    async fn recover_session(
        &self,
        observed: u64,
        trigger: SessionTrigger,
        confirmed: bool,
    ) -> Recovery {
        let Some(auth) = self.cfg.auth.as_ref() else {
            return Recovery::Alive;
        };
        let mut session = self.session.lock().await;
        if session.expired {
            return Recovery::Expired;
        }
        if session.generation != observed {
            return Recovery::Renewed;
        }
        let gate = matches!(trigger, SessionTrigger::LoginGate { .. });
        let mut detail = None;
        if !confirmed {
            let fresh = session
                .alive_at
                .is_some_and(|at| at.elapsed() < CANARY_FRESHNESS);
            let canary = if fresh && !gate {
                Canary::Alive
            } else {
                self.session_canary(&session).await
            };
            match canary {
                Canary::Alive => {
                    session.alive_at = Some(Instant::now());
                    drop(session);
                    if gate {
                        tracing::info!(
                            url = ?trigger.urls().0,
                            "login page reached while the session is alive: gated for this role"
                        );
                        self.record_session_event(
                            super::run_report::EVENT_ALIVE,
                            trigger.name(),
                            trigger.urls(),
                            true,
                            None,
                            None,
                        );
                    }
                    return Recovery::Alive;
                }
                Canary::LoggedOut(why) => detail = Some(why),
                // Without a canary, 401/403 responses alone never end a
                // session that cannot be renewed: they may be role denials.
                Canary::Unknown if !auth.is_renewable() && !gate => {
                    return Recovery::Alive;
                }
                Canary::Unknown => {}
            }
        }

        if !auth.is_renewable() {
            session.expired = true;
            drop(session);
            self.expire_session(&trigger, detail, None).await;
            return Recovery::Expired;
        }

        // Log in again. Other tabs wait on the session lock meanwhile.
        let attempt = session.reauth_attempts + 1;
        tracing::warn!(
            attempt,
            trigger = trigger.name(),
            "session appears expired; logging in again"
        );
        let renewed = match SessionManager::authenticate(
            self.browser.browser(),
            &self.cfg.target,
            &self.cfg.auth,
            self.cfg.auth_contract.as_ref(),
            Some(self.network),
        )
        .await
        {
            Ok(state) => {
                *session.session_state = state;
                // The new session must open the canary page; a login that
                // "succeeds" into the login page again is a failure.
                match self.session_canary(&session).await {
                    Canary::LoggedOut(why) => Err(format!("still logged out after login: {why}")),
                    _ => Ok(()),
                }
            }
            Err(err) => Err(format!("{err:#}")),
        };
        match renewed {
            Ok(()) => {
                session.generation += 1;
                session.reauth_attempts = 0;
                session.alive_at = Some(Instant::now());
                drop(session);
                self.session_health.reset();
                tracing::info!(attempt, "logged in again; retrying with the new session");
                self.record_session_event(
                    super::run_report::EVENT_REAUTH,
                    trigger.name(),
                    trigger.urls(),
                    true,
                    Some(attempt),
                    detail,
                );
                Recovery::Renewed
            }
            Err(why) => {
                session.reauth_attempts = attempt;
                let exhausted = attempt >= MAX_REAUTH_ATTEMPTS;
                if exhausted {
                    session.expired = true;
                }
                drop(session);
                tracing::warn!(attempt, error = %why, "logging in again failed");
                self.record_session_event(
                    super::run_report::EVENT_REAUTH,
                    trigger.name(),
                    trigger.urls(),
                    false,
                    Some(attempt),
                    Some(why.clone()),
                );
                if exhausted {
                    record_session_expired_bug(self.bug_detector, MAX_REAUTH_ATTEMPTS).await;
                    self.expire_session(&trigger, Some(why), Some(attempt))
                        .await;
                    Recovery::Expired
                } else {
                    Recovery::Failed
                }
            }
        }
    }

    /// The session is gone for good: record it and stop the crawl now.
    async fn expire_session(
        &self,
        trigger: &SessionTrigger,
        detail: Option<String>,
        attempt: Option<usize>,
    ) {
        let kind = self
            .cfg
            .auth
            .as_ref()
            .map(|a| a.type_name())
            .unwrap_or("none");
        tracing::error!(
            auth = kind,
            trigger = trigger.name(),
            "the auth session expired and cannot be renewed; stopping the scan (session_expired)"
        );
        self.record_session_event(
            super::run_report::EVENT_EXPIRED,
            trigger.name(),
            trigger.urls(),
            false,
            attempt,
            detail,
        );
        {
            let mut st = self.lock();
            let remaining = st.scheduler.len() + st.ctl.in_flight;
            st.coverage_gaps
                .push(crate::explorer::coverage::CoverageGap {
                    kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                    target: "scan_loop".to_string(),
                    reason: "session_expired".to_string(),
                    context: Some(format!(
                        "auth={kind} trigger={} queue_remaining={remaining}",
                        trigger.name()
                    )),
                });
        }
        self.stop_now(super::run_report::stop_reason::SESSION_EXPIRED);
    }

    /// Is the session still alive? A protected probe when the auth contract
    /// has one, else a visit to the page the login (or the session capture)
    /// landed on: landing on the login page means logged out. Runs in a
    /// write-guarded page of its own.
    async fn session_canary(&self, session: &SessionCtl<'_>) -> Canary {
        let state = &*session.session_state;
        let probe = self
            .cfg
            .auth_contract
            .as_ref()
            .and_then(|c| c.protected_probe.as_ref());
        let target = match (probe, state.canary_url.as_deref()) {
            (Some(_), _) => self.cfg.target.url.to_string(),
            (None, Some(url)) => url.to_string(),
            (None, None) => return Canary::Unknown,
        };
        let run = async {
            let page = self.new_page().await?;
            let checked = async {
                page.enable_domains().await?;
                SessionManager::apply_to_page(&page, state).await?;
                let _guard = Arc::clone(self.network)
                    .attach_isolated(
                        page.inner(),
                        Some(format!("session_canary_{}", Uuid::new_v4())),
                    )
                    .await?;
                page.goto_and_wait(&target, Duration::from_secs(20)).await?;
                settle_page_bounded(&page, settle_timeout_for_url(self.cfg, &target)).await;
                let landed = page.url().await?.unwrap_or_else(|| target.clone());
                if let Some(probe) = probe {
                    let ok =
                        crate::session::auth::run_protected_probe(&page, &self.cfg.target, probe)
                            .await?;
                    return Ok::<_, anyhow::Error>(if ok {
                        Canary::Alive
                    } else {
                        Canary::LoggedOut("protected probe failed".to_string())
                    });
                }
                Ok(if self.landed_on_login(&target, &landed) {
                    Canary::LoggedOut(format!("{target} -> {landed}"))
                } else {
                    Canary::Alive
                })
            }
            .await;
            close_page_bounded(&page).await;
            checked
        };
        match tokio::time::timeout(Duration::from_secs(60), run).await {
            Ok(Ok(canary)) => canary,
            Ok(Err(err)) => {
                tracing::warn!(error = ?err, "session canary could not run");
                Canary::Unknown
            }
            Err(_) => {
                tracing::warn!("session canary timed out");
                Canary::Unknown
            }
        }
    }

    /// A saved session that is already gone when the crawl starts stops it
    /// right away (`session_expired`) instead of mapping the logged-out app.
    async fn verify_saved_session_at_start(&self) {
        let Some(auth) = self.cfg.auth.as_ref() else {
            return;
        };
        if auth.is_renewable() {
            return;
        }
        let canary = {
            let session = self.session.lock().await;
            self.session_canary(&session).await
        };
        match canary {
            Canary::Alive => {
                self.session.lock().await.alive_at = Some(Instant::now());
            }
            Canary::Unknown => {
                tracing::info!("saved session loaded; no session canary is known for it");
            }
            Canary::LoggedOut(why) => {
                self.session.lock().await.expired = true;
                self.record_session_event(
                    super::run_report::EVENT_EXPIRED,
                    "scan_start",
                    (None, None),
                    false,
                    None,
                    Some(why.clone()),
                );
                tracing::error!(reason = %why, "the saved session is no longer signed in; capture it again (`brokenapp login`)");
                {
                    let mut st = self.lock();
                    st.coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                            target: "scan_loop".to_string(),
                            reason: "session_expired".to_string(),
                            context: Some(format!("auth={} trigger=scan_start", auth.type_name())),
                        });
                }
                self.stop_now(super::run_report::stop_reason::SESSION_EXPIRED);
            }
        }
    }

    /// A page could not be created. A few failures in a row mean the
    /// browser is gone: the crawl stops (`browser_unavailable`) with the URL
    /// back in the queue, for a resume with a new browser. A first failure
    /// of a URL retries it later. Returns `true` when the visit is handled.
    fn browser_unavailable(&self, item: &QueuedUrl) -> bool {
        let gone = {
            let mut st = self.lock();
            st.ctl.consecutive_page_failures += 1;
            let gone = st.ctl.consecutive_page_failures >= MAX_CONSECUTIVE_PAGE_FAILURES;
            let canonical = url_utils::canonicalize_crawl_url(&item.url);
            if gone {
                st.scheduler.requeue_front(&item.url, item.depth);
            } else if st.navigation_retries.insert(canonical) {
                st.scheduler.requeue(&item.url, item.depth);
                return true;
            }
            gone
        };
        if gone {
            tracing::error!(
                failures = MAX_CONSECUTIVE_PAGE_FAILURES,
                "the browser stopped creating pages; stopping the scan (resume it to continue)"
            );
            self.stop_now(super::run_report::stop_reason::BROWSER_UNAVAILABLE);
        }
        gone
    }

    /// Incremental save of the checkpoint and the scan artifacts, when due
    /// ([`save_interval`]) or `force`d. Saves write the same files: while
    /// one is running a concurrent request is skipped (the next covers it).
    async fn save_progress(&self, force: bool) {
        let Ok(mut writer) = self.saver.try_lock() else {
            return;
        };
        if !force {
            let timing = *self
                .save_timing
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let interval = save_interval(self.cfg.output.checkpoint_interval_seconds, timing.cost);
            if timing.last.elapsed() < interval {
                return;
            }
        }
        let started = Instant::now();
        let bugs = self.bug_detector.bugs_snapshot().await;
        let (checkpoint, outcome, run) = {
            let st = self.lock();
            progress_artifacts(
                self.cfg,
                self.started_at,
                self.start_instant,
                &st,
                self.network,
                bugs,
            )
        };
        if let Err(err) =
            write_progress_artifacts(&mut writer, self.cfg, checkpoint, outcome, run).await
        {
            tracing::warn!(error = ?err, "incremental save failed");
        }
        let mut timing = self
            .save_timing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        timing.last = Instant::now();
        timing.cost = started.elapsed();
    }

    /// `scan.canary_before_new_route`: verify the session before the first
    /// visit of a route template, re-authenticating when it fails.
    async fn canary_before_new_route(&self, item: &QueuedUrl) -> Result<()> {
        let cfg = self.cfg;
        if !cfg.scan.canary_before_new_route || cfg.auth.is_none() {
            return Ok(());
        }
        let route_template = crate::explorer::template_sampler::route_key(&item.url);
        if self
            .lock()
            .visited_route_templates
            .contains(&route_template)
        {
            return Ok(());
        }
        // New template — run the session canary.
        let (canary, generation) = {
            let session = self.session.lock().await;
            if session.expired {
                return Ok(());
            }
            (self.session_canary(&session).await, session.generation)
        };
        match canary {
            Canary::Alive | Canary::Unknown => {
                tracing::debug!(template = %route_template, "pre-route canary passed");
            }
            Canary::LoggedOut(why) => {
                tracing::warn!(
                    template = %route_template,
                    reason = %why,
                    "pre-route canary failed — checking the session"
                );
                self.recover_session(generation, SessionTrigger::Canary, true)
                    .await;
            }
        }
        Ok(())
    }

    /// Record a page-level failure (setup, processing, watchdog) as a finding.
    async fn record_page_failure(
        &self,
        url: &str,
        title: &str,
        category: String,
        description: String,
    ) {
        self.bug_detector
            .record(Bug {
                id: String::new(),
                severity: BugSeverity::High,
                confidence: Some(if title.starts_with("Page setup") {
                    0.95
                } else {
                    0.90
                }),
                category: BugCategory::Other {
                    description: category,
                },
                title: title.to_string(),
                description,
                remediation: None,
                location: BugLocation {
                    view: None,
                    element: None,
                    url: Some(url.to_string()),
                },
                reproduction: vec![format!("Navigate to {url}")],
                evidence: BugEvidence::default(),
                discovered_at: chrono::Utc::now(),
                cwe: None,
                owasp: None,
            })
            .await;
    }

    /// Visit one URL in a fresh page: navigate, fingerprint, classify,
    /// discover, exercise the controls, audit, and record the view.
    async fn visit(
        &self,
        pacer: &mut interaction::AdaptiveRateLimitPacer,
        item: &QueuedUrl,
        slot: &mut VisitSlot<'_, 'a>,
    ) -> Result<()> {
        let cfg = self.cfg;
        let network = self.network;
        let bug_detector = self.bug_detector;
        let base_url = self.base_url;
        let scope_filter = self.scope_filter;
        let interaction_log = self.interaction_log;

        tracing::info!(depth = item.depth, url = %item.url, "visiting");
        let queued = self.lock().scheduler.len();
        let scan_deadline = (cfg.scan.max_duration_minutes > 0).then(|| {
            self.start_instant
                + Duration::from_secs(cfg.scan.max_duration_minutes.saturating_mul(60))
        });
        let mut page_timeout = adaptive_page_timeout(
            page_watchdog_timeout_for_url(cfg, &item.url),
            cfg,
            self.start_instant,
            queued,
            self.tabs,
        );
        if let Some(deadline) = scan_deadline {
            let flush_deadline = deadline + GRACEFUL_DURATION_FLUSH;
            let remaining = flush_deadline.saturating_duration_since(Instant::now());
            page_timeout = page_timeout.min(remaining.max(Duration::from_secs(5)));
        }

        let page = match tokio::time::timeout(page_timeout, self.new_page()).await {
            Ok(Ok(page)) => {
                self.lock().ctl.consecutive_page_failures = 0;
                page
            }
            Ok(Err(err)) => {
                if self.browser_unavailable(item) {
                    return Ok(());
                }
                tracing::warn!(error = ?err, url = %item.url, "failed to create page; skipping url");
                self.record_page_failure(
                    &item.url,
                    "Page setup failed",
                    format!("Failed to create browser page: {err:#}"),
                    format!("Failed to create browser page for {}: {err:#}", item.url),
                )
                .await;
                if let Err(err) = self.process_network_errors().await {
                    tracing::warn!(error = ?err, "failed to process network errors after page setup failure");
                }
                self.save_progress(false).await;
                return Ok(());
            }
            Err(_) => {
                if self.browser_unavailable(item) {
                    return Ok(());
                }
                tracing::warn!(
                    url = %item.url,
                    timeout_seconds = page_timeout.as_secs(),
                    "page creation exceeded watchdog timeout; skipping url"
                );
                self.record_page_failure(
                    &item.url,
                    "Page setup timeout",
                    format!("Page creation timed out after {}s", page_timeout.as_secs()),
                    format!(
                        "Timed out creating browser page for {} after {}s",
                        item.url,
                        page_timeout.as_secs()
                    ),
                )
                .await;
                if let Err(err) = self.process_network_errors().await {
                    tracing::warn!(error = ?err, "failed to process network errors after page setup timeout");
                }
                self.save_progress(false).await;
                return Ok(());
            }
        };
        let tab = page.tab();

        let view_budget = ViewBudget::new(Instant::now(), page_timeout);
        let phase_tracker: PhaseTracker = Arc::new(Mutex::new("setup"));
        let visit_phase_tracker = Arc::clone(&phase_tracker);
        let visit_result = tokio::time::timeout(page_timeout, async {
            set_phase(&visit_phase_tracker, "setup");
            let page_id = format!("page_{}", Uuid::new_v4());
            page.enable_domains().await?;
            if let Err(err) = page
                .set_viewport(cfg.scan.viewport_width, cfg.scan.viewport_height)
                .await
            {
                tracing::debug!(error = ?err, "failed to apply scan viewport");
            }
            if let Some(ua) = cfg.scan.user_agent.as_deref()
                && let Err(err) = page.set_user_agent(ua).await
            {
                tracing::debug!(error = ?err, "failed to apply scan user_agent");
            }
            let _ = install_settle_stream_exclusions_pre(&page).await;
            cdp_helpers::install_instrumentation(&page).await?;
            let _ = install_settle_stream_exclusions_post(&page).await;
            let mut session_generation = self.apply_session(&page).await?;
            self.lock()
                .attempted_urls
                .insert(url_utils::canonicalize_crawl_url(&item.url));

            // Request interception (write guard) and attribution for this
            // tab, attached before its first navigation.
            let _net_handle = network
                .clone()
                .attach_isolated(page.inner(), Some(page_id))
                .await?;
            let _bug_handle = Arc::clone(bug_detector)
                .attach_console(page.inner())
                .await?;

            // Navigate.
            set_phase(&visit_phase_tracker, "navigate");
            let load_marker_view = format!("__load_{}", Uuid::new_v4());
            network.set_current_interaction_on(
                &tab,
                Some(InteractionRef {
                    view: load_marker_view.clone(),
                    selector: "__page_load__".to_string(),
                }),
            );
            if let Err(err) = page.goto_and_wait(&item.url, Duration::from_secs(20)).await {
                network.drop_interaction_view(&load_marker_view).await;
                network.set_current_interaction_on(&tab, None);
                let message = format!("{err:#}");
                let canonical = url_utils::canonicalize_crawl_url(&item.url);
                let retry = {
                    let mut st = self.lock();
                    let retry = st.navigation_retries.insert(canonical);
                    if retry {
                        // Cold dev-server compiles and transient stalls: one
                        // retry at the end of the queue.
                        st.scheduler.requeue(&item.url, item.depth);
                    } else {
                        st.coverage_gaps
                            .push(crate::explorer::coverage::CoverageGap {
                                kind: crate::explorer::coverage::CoverageGapKind::Route,
                                target: item.url.clone(),
                                reason: if message.contains("timed out") {
                                    "navigation_timeout".to_string()
                                } else {
                                    "navigation_failed".to_string()
                                },
                                context: Some(message.clone()),
                            });
                    }
                    retry
                };
                if retry {
                    tracing::warn!(error = %message, url = %item.url, "navigation failed; retrying once later");
                    close_page_bounded(&page).await;
                    return Ok(());
                }
                tracing::warn!(error = %message, url = %item.url, "navigation failed again; skipping url");
                bug_detector
                    .record(Bug {
                        id: String::new(),
                        severity: BugSeverity::High,
                        confidence: Some(0.90),
                        category: BugCategory::Other {
                            description: format!("Navigation failed: {err:#}"),
                        },
                        title: "Navigation failed".to_string(),
                        description: format!("Failed to navigate to {}: {err:#}", item.url),
                        remediation: None,
                        location: BugLocation {
                            view: None,
                            element: None,
                            url: Some(item.url.clone()),
                        },
                        reproduction: vec![format!("Navigate to {}", item.url)],
                        evidence: BugEvidence::default(),
                        discovered_at: chrono::Utc::now(),
                        cwe: None,
                        owasp: None,
                    })
                    .await;

                close_page_bounded(&page).await;
                self.process_network_errors().await?;
                self.save_progress(false).await;
                return Ok(());
            }
            set_phase(&visit_phase_tracker, "settle");
            let settle_timeout = settle_timeout_for_url(cfg, &item.url);
            // Lazy routes render their controls only after a route chunk
            // loads: wait for in-flight chunks and an empty/loading <main>,
            // strictly bounded so a stalled CDP eval never hits the 78s watchdog.
            settle_page_bounded(&page, settle_timeout).await;

            set_phase(&visit_phase_tracker, "post_settle");
            let mut final_url = tokio::time::timeout(Duration::from_secs(5), page.url())
                .await
                .ok()
                .and_then(|r| r.ok())
                .flatten()
                .unwrap_or_else(|| item.url.clone());
            // Landed on the login page: the session may have expired (log in
            // again once and retry the view), or the route is gated for this
            // role (the session canary is still alive: map the gate).
            if cfg.auth.is_some() && self.landed_on_login(&item.url, &final_url) {
                set_phase(&visit_phase_tracker, "session");
                let trigger = SessionTrigger::LoginGate {
                    url: item.url.clone(),
                    landed: final_url.clone(),
                };
                match self.recover_session(session_generation, trigger, false).await {
                    Recovery::Renewed => {
                        session_generation = self.apply_session(&page).await?;
                        set_phase(&visit_phase_tracker, "navigate");
                        page.goto_and_wait(&item.url, Duration::from_secs(20)).await?;
                        set_phase(&visit_phase_tracker, "settle");
                        settle_page_bounded(&page, settle_timeout).await;
                        set_phase(&visit_phase_tracker, "post_settle");
                        final_url = tokio::time::timeout(Duration::from_secs(5), page.url())
                            .await
                            .ok()
                            .and_then(|r| r.ok())
                            .flatten()
                            .unwrap_or_else(|| item.url.clone());
                        if self.landed_on_login(&item.url, &final_url) {
                            self.lock().coverage_gaps.push(
                                crate::explorer::coverage::CoverageGap {
                                    kind: crate::explorer::coverage::CoverageGapKind::Route,
                                    target: item.url.clone(),
                                    reason: "login_gate_after_reauth".to_string(),
                                    context: Some(format!("final_url={final_url}")),
                                },
                            );
                        }
                    }
                    Recovery::Alive => {}
                    Recovery::Failed | Recovery::Expired => {
                        // Not explored with a dead session: back in the queue
                        // (a resume picks it up once the session is renewed).
                        network.drop_interaction_view(&load_marker_view).await;
                        network.set_current_interaction_on(&tab, None);
                        close_page_bounded(&page).await;
                        let mut st = self.lock();
                        // Re-login has its own bounded retry count. Do not
                        // lose the final URL after only two failed attempts.
                        st.scheduler.requeue_front(&item.url, item.depth);
                        return Ok(());
                    }
                }
            }
            if Url::parse(&item.url).ok().and_then(|u| u.fragment().map(str::to_string))
                != Url::parse(&final_url).ok().and_then(|u| u.fragment().map(str::to_string))
            {
                url_utils::register_route_fragment_from_url(&final_url);
            }
            record_seed_redirect_gap(&mut self.lock(), base_url, &item.url, &final_url);

            // Browser-generated error documents (`chrome-error://chromewebdata/`,
            // `about:neterror`, Chromium's `body.neterror` / `#main-frame-error`
            // interstitials) are never application views or controls.
            let is_browser_error_doc = url_utils::is_browser_internal_url(&final_url)
                || tokio::time::timeout(
                    Duration::from_secs(3),
                    page.evaluate_json::<bool>(
                        "Boolean(document.body && (document.body.classList.contains('neterror') || document.querySelector('#main-frame-error, #interstitial-wrapper')))",
                    ),
                )
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(false);
            if is_browser_error_doc {
                self.lock()
                    .coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::Route,
                        target: item.url.clone(),
                        reason: "browser_error_document".to_string(),
                        context: Some(format!("final_url={final_url}")),
                    });
                tracing::debug!(
                    requested = %item.url,
                    final_url = %final_url,
                    "skipping browser-generated error document"
                );
                network.drop_interaction_view(&load_marker_view).await;
                network.set_current_interaction_on(&tab, None);
                close_page_bounded(&page).await;
                return Ok(());
            }

            let page_title = tokio::time::timeout(Duration::from_secs(5), page.title())
                .await
                .ok()
                .and_then(|r| r.ok())
                .flatten()
                .unwrap_or_default();
            // Also inspect rendered DOM text for challenge markers (many challenge
            // pages keep a benign title but render a challenge in the body).
            let body_text: String = tokio::time::timeout(
                Duration::from_secs(5),
                page.evaluate_json::<String>(
                    "document.body ? (document.body.innerText || '').slice(0, 2000) : ''",
                ),
            )
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_default();
            if !cfg.scan.allowed_hosts.is_empty()
                && !crate::network::filters::url_matches_allowed_hosts(
                    &final_url,
                    &cfg.scan.allowed_hosts,
                )
            {
                self.lock()
                    .coverage_gaps
                    .push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::Route,
                        target: final_url.clone(),
                        reason: "outside_allowed_hosts".to_string(),
                        context: Some(format!("requested={}", item.url)),
                    });
                tracing::debug!(
                    requested = %item.url,
                    final_url = %final_url,
                    "skipping url: final url outside scan.allowed_hosts"
                );
                network.set_current_interaction_on(&tab, None);
                close_page_bounded(&page).await;
                return Ok(());
            }
            if cfg.scan.abort_on_rate_limits > 0 {
                let recent_429 = network.recent_rate_limit_count(Duration::from_secs(60));
                if recent_429 >= cfg.scan.abort_on_rate_limits {
                    tracing::warn!(
                        http_429_last_60s = recent_429,
                        threshold = cfg.scan.abort_on_rate_limits,
                        url = %final_url,
                        "aborting scan: target returned repeated HTTP 429 rate-limit responses"
                    );
                    self.lock()
                        .coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                            target: "scan_loop".to_string(),
                            reason: super::run_report::stop_reason::RATE_LIMITED.to_string(),
                            context: Some(format!(
                                "http_429_last_60s={recent_429} threshold={}",
                                cfg.scan.abort_on_rate_limits
                            )),
                        });
                    self.stop_now(super::run_report::stop_reason::RATE_LIMITED);
                    network.set_current_interaction_on(&tab, None);
                    close_page_bounded(&page).await;
                    return Ok(());
                }
            }
            let challenge_detected = is_antibot_challenge(&page_title, &final_url, &body_text);
            if challenge_detected {
                tracing::warn!(
                    url = %final_url,
                    title = %page_title,
                    "antibot/challenge page detected; skipping discovery"
                );
                self.lock().coverage_gaps.push(crate::explorer::coverage::CoverageGap {
                    kind: crate::explorer::coverage::CoverageGapKind::Route,
                    target: final_url.clone(),
                    reason: "antibot_challenge_detected".to_string(),
                    context: Some(page_title.clone()),
                });
                let challenges = self
                    .antibot_challenges
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                if cfg.scan.abort_on_antibot_challenges > 0
                    && challenges >= cfg.scan.abort_on_antibot_challenges
                {
                    tracing::warn!(
                        challenges,
                        threshold = cfg.scan.abort_on_antibot_challenges,
                        url = %final_url,
                        "aborting scan: repeated WAF / anti-bot challenge pages detected"
                    );
                    self.lock()
                        .coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: crate::explorer::coverage::CoverageGapKind::StopCondition,
                            target: "scan_loop".to_string(),
                            reason: super::run_report::stop_reason::ANTIBOT_CHALLENGE.to_string(),
                            context: Some(format!(
                                "challenges={challenges} threshold={} url={final_url}",
                                cfg.scan.abort_on_antibot_challenges
                            )),
                        });
                    self.stop_now(super::run_report::stop_reason::ANTIBOT_CHALLENGE);
                    network.set_current_interaction_on(&tab, None);
                    close_page_bounded(&page).await;
                    return Ok(());
                }
            }
            if let Some(sf) = scope_filter {
                if final_url_is_outside_scope(base_url, sf, &final_url) {
                    self.lock()
                        .coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: crate::explorer::coverage::CoverageGapKind::Route,
                            target: final_url.clone(),
                            reason: "final_url_outside_scope".to_string(),
                            context: Some(format!("scope={} requested={}", sf.name, item.url)),
                        });
                    tracing::debug!(
                        requested = %item.url,
                        final_url = %final_url,
                        scope = %sf.name,
                        "skipping url: final url outside scan scope"
                    );
                    network.set_current_interaction_on(&tab, None);
                    close_page_bounded(&page).await;
                    return Ok(());
                }
            }

            // Detect locale redirects (e.g. /products/ -> /ar/products/).
            if let Some(redirect_kind) = detect_locale_redirect(&item.url, &final_url) {
                bug_detector
                    .record_unexpected_redirect(
                        item.url.clone(),
                        final_url.clone(),
                        redirect_kind,
                    )
                    .await;
            }

            // Dismiss on-load blocking overlays (cookie banners, welcome dialogs)
            // before fingerprinting, classification and discovery — they hide the
            // SPA behind an aria-hidden root, starve element discovery (e.g.,
            // full-screen welcome dialogs masking page elements), and make the
            // view fingerprint/type describe the overlay. Best-effort; settle so
            // the DOM re-renders after.
            if !challenge_detected {
                set_phase(&visit_phase_tracker, "overlays");
                let dismissed = tokio::time::timeout(
                    Duration::from_secs(5),
                    crate::dom::interaction::dismiss_blocking_overlays(&page),
                )
                .await
                .unwrap_or(0);
                if dismissed > 0 {
                    settle_bounded(&page, Duration::from_millis(700)).await;
                    tracing::debug!(dismissed, url=%final_url, "dismissed blocking overlays before fingerprinting");
                }
            }

            // Even a legitimate consent dismissal can navigate. Do not
            // label its destination DOM with the pre-dismissal route/title,
            // or reuse that route's auth/scope/challenge checks. Visit the
            // destination through the normal guarded navigation path.
            let after_overlay = tokio::time::timeout(Duration::from_secs(5), page.url())
                .await
                .ok()
                .and_then(|r| r.ok())
                .flatten()
                .unwrap_or_else(|| final_url.clone());
            if !view_urls_match_for_restore(&after_overlay, &final_url) {
                {
                    let mut st = self.lock();
                    st.coverage_gaps.push(crate::explorer::coverage::CoverageGap {
                        kind: crate::explorer::coverage::CoverageGapKind::Route,
                        target: final_url.clone(),
                        reason: "navigation_before_discovery".to_string(),
                        context: Some(format!("landed on {after_overlay} after initial overlay handling")),
                    });
                    if let Ok(target) = Url::parse(&after_overlay)
                        && url_utils::same_origin(base_url, &target)
                    {
                        st.scheduler.enqueue_scoped(
                            target.to_string(), item.depth + 1, base_url, scope_filter,
                            cfg.scan.exploration.strategy, cfg.scan.exploration.novelty_scoring, true,
                        );
                    }
                }
                network.drop_interaction_view(&load_marker_view).await;
                network.set_current_interaction_on(&tab, None);
                close_page_bounded(&page).await;
                return Ok(());
            }

            set_phase(&visit_phase_tracker, "fingerprint");
            let fingerprint = fingerprint_dom(&page).await?;

            // Views are identified by (route, DOM skeleton): distinct routes that
            // share a layout (App Router layouts, hash routes) stay distinct.
            let view_key = view_identity_key(&final_url, &fingerprint.0);
            let (view_id, retain_seeded_duplicate_view) = {
                let mut st = self.lock();
                let retain = is_seeded_route_visit(&st, &item.url, &final_url)
                    && (cfg.scan.ui_consistency.enabled || cfg.scan.layout_consistency.enabled);
                let id = if retain {
                    let id = st.allocate_view_id();
                    st.fingerprint_to_view
                        .entry(view_key.clone())
                        .or_insert_with(|| id.clone());
                    id
                } else if let Some(existing) = st.fingerprint_to_view.get(&view_key).cloned() {
                    existing
                } else {
                    let id = st.allocate_view_id();
                    st.fingerprint_to_view.insert(view_key.clone(), id.clone());
                    id
                };
                (id, retain)
            };
            // Remap any network activity captured during navigation to the final view id.
            network
                .remap_interaction_view(&load_marker_view, &view_id)
                .await;
            // Continue attributing on-load requests to this view until we start clicking.
            network.set_current_interaction_on(
                &tab,
                Some(InteractionRef {
                    view: view_id.clone(),
                    selector: "__page_load__".to_string(),
                }),
            );
            let template_variant_changed = {
                let mut st = self.lock();
                st.url_to_view.insert(final_url.clone(), view_id.clone());
                st.scheduler
                    .record_visit_for_novelty(&final_url, &fingerprint.0);
                st.scheduler.mark_visited_template(&final_url);
                let changed = st.template_sampler.is_new_variant(&final_url, &fingerprint.0);
                // Keep the reservation until the visit ends. A checkpoint
                // or re-login that abandons it must not mark this instance
                // sampled before its controls have been explored.
                st.sample_when_visit_finishes(
                    slot.visit, &final_url, &fingerprint.0, &view_id,
                );
                changed
            };

            let route = crate::explorer::template_sampler::route_key(&final_url);

            let explore = {
                let mut st = self.lock();
                // Another tab is exploring this very view right now (a
                // revisit, a retained seeded duplicate): it is that tab's.
                let concurrent = st.ctl.active_views.contains(&view_key);
                let is_new = st.visited_fingerprints.insert(view_key.clone());
                st.ctl.recent_new_fingerprints.push_back(is_new);
                let window_cap = cfg.scan.convergence_window_views.max(1);
                while st.ctl.recent_new_fingerprints.len() > window_cap {
                    st.ctl.recent_new_fingerprints.pop_front();
                }
                if is_new {
                    st.ctl.last_new_fingerprint_at = Instant::now();
                }
                let explore = !concurrent
                    && (is_new || retain_seeded_duplicate_view || cfg.scan.exploration.revisit_views);
                if explore {
                    st.ctl.active_views.insert(view_key.clone());
                    st.visit_explores(slot.visit, &view_key, &view_id);
                    slot.view_key = Some(view_key.clone());
                    slot.view_id = Some(view_id.clone());
                } else {
                    st.coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: crate::explorer::coverage::CoverageGapKind::Route,
                            target: final_url.clone(),
                            reason: "duplicate_fingerprint".to_string(),
                            context: Some(view_id.clone()),
                        });
                }
                explore
            };
            if !explore {
                network.set_current_interaction_on(&tab, None);
                close_page_bounded(&page).await;
                self.process_network_errors().await?;
                self.save_progress(false).await;
                return Ok(());
            }

            let title = page.title().await.ok().flatten();
            let detected_framework = detect_framework(&page).await.ok().flatten();

            let screenshot = if cfg.scan.screenshot_each_view && cfg.output.include_screenshots {
                set_phase(&visit_phase_tracker, "screenshot");
                match view_budget.phase_timeout(VIEW_BUDGET_RESERVE, PHASE_SCREENSHOT_MAX) {
                    Some(timeout) => match tokio::time::timeout(timeout, page.screenshot_png(true)).await {
                        Ok(Ok(png)) => {
                            match write_view_screenshot(&cfg.output.directory, &view_id, &png).await {
                                Ok(rel) => Some(rel),
                                Err(err) => {
                                    tracing::debug!(error=?err, "screenshot write failed");
                                    None
                                }
                            }
                        }
                        Ok(Err(err)) => {
                            tracing::debug!(error=?err, "screenshot capture failed");
                            None
                        }
                        Err(_) => {
                            tracing::debug!(view_id = %view_id, url = %final_url, "screenshot timed out");
                            None
                        }
                    },
                    None => {
                        tracing::debug!(view_id = %view_id, url = %final_url, "skipping screenshot: time budget exhausted");
                        None
                    }
                }
            } else {
                None
            };

            set_phase(&visit_phase_tracker, "classify");
            let mut classified = match view_budget.phase_timeout(VIEW_BUDGET_RESERVE, PHASE_CLASSIFY_MAX) {
                Some(timeout) => match tokio::time::timeout(timeout, classify_current_view(&page)).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(err)) => {
                        tracing::debug!(error=?err, url=%final_url, "component classification failed");
                        ClassifiedView {
                            primary_type: "unknown".to_string(),
                            description: "Unclassified view".to_string(),
                            components: Vec::new(),
                        }
                    }
                    Err(_) => {
                        tracing::debug!(url=%final_url, "component classification timed out");
                        ClassifiedView {
                            primary_type: "unknown".to_string(),
                            description: "Unclassified view".to_string(),
                            components: Vec::new(),
                        }
                    }
                },
                None => {
                    tracing::debug!(url=%final_url, "skipping classification: time budget exhausted");
                    ClassifiedView {
                        primary_type: "unknown".to_string(),
                        description: "Unclassified view".to_string(),
                        components: Vec::new(),
                    }
                }
            };
            enrich_detail_view_entity(&mut classified, &final_url);

            set_phase(&visit_phase_tracker, "discover_elements");
            let mut elements = if challenge_detected {
                Vec::new()
            } else {
                match view_budget.phase_timeout(VIEW_BUDGET_RESERVE, PHASE_DISCOVERY_MAX) {
                Some(timeout) => match tokio::time::timeout(timeout, discover_interactive_elements(&page, &view_id)).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(err)) => {
                        tracing::debug!(error=?err, url=%final_url, "element discovery failed");
                        Vec::new()
                    }
                    Err(_) => {
                        tracing::debug!(url=%final_url, "element discovery timed out");
                        record_view_budget_skip(
                            &mut self.lock(),
                            crate::explorer::coverage::CoverageGapKind::Interaction,
                            &final_url,
                            Some(&view_id),
                            "discover_elements",
                        );
                        Vec::new()
                    }
                },
                None => {
                    tracing::debug!(url=%final_url, "skipping element discovery: time budget exhausted");
                    record_view_budget_skip(
                        &mut self.lock(),
                        crate::explorer::coverage::CoverageGapKind::Interaction,
                        &final_url,
                        Some(&view_id),
                        "discover_elements",
                    );
                    Vec::new()
                }
            }
            };
            // A view that rendered far fewer controls than comparable views was
            // probably snapshotted before its lazy content arrived: reload it
            // once and wait longer.
            if !challenge_detected {
                let (template, revisit_expected) = {
                    let mut st = self.lock();
                    let template = st.template_sampler.template_of(&final_url);
                    let expected = expected_element_count(&st, template.as_deref())
                        .filter(|expected| elements_far_below(elements.len(), *expected))
                        .filter(|_| {
                            st.revisited_urls
                                .insert(url_utils::canonicalize_crawl_url(&final_url))
                        });
                    (template, expected)
                };
                if let Some(expected) = revisit_expected
                    && let Some(timeout) =
                        view_budget.phase_timeout(VIEW_BUDGET_RESERVE, PHASE_DISCOVERY_MAX)
                {
                    tracing::info!(
                        url = %final_url,
                        elements = elements.len(),
                        expected,
                        "view looks incomplete; reloading it once"
                    );
                    let revisit = async {
                        page.reload_and_wait(timeout).await?;
                        settle_page_bounded(&page, settle_timeout.saturating_mul(2)).await;
                        if crate::dom::interaction::dismiss_blocking_overlays(&page).await > 0 {
                            settle_bounded(&page, Duration::from_millis(700)).await;
                        }
                        discover_interactive_elements(&page, &view_id).await
                    };
                    match tokio::time::timeout(timeout.saturating_mul(2), revisit).await {
                        Ok(Ok(again)) if again.len() > elements.len() => {
                            tracing::info!(url = %final_url, before = elements.len(), after = again.len(), "revisit found more controls");
                            elements = again;
                        }
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            tracing::debug!(error = ?err, url = %final_url, "revisit failed");
                        }
                        Err(_) => {
                            tracing::debug!(url = %final_url, "revisit timed out");
                        }
                    }
                }
                let mut st = self.lock();
                st.view_element_counts.push(elements.len());
                if let Some(template) = template {
                    st.template_element_counts
                        .entry(template)
                        .or_default()
                        .push(elements.len());
                }
            }
            self.lock().elements_discovered += elements.len();
            tracing::info!(
                view_id = %view_id,
                url = %final_url,
                elements = elements.len(),
                "view mapped"
            );

            // Queue navigation targets.
            let current_url = Url::parse(&final_url).ok();
            {
                let mut st = self.lock();
                for el in &elements {
                    if let ElementType::NavigationLink {
                        href: Some(href),
                        in_nav,
                    } = &el.element_type
                    {
                        if let Some(target) =
                            url_utils::normalize_href(base_url, current_url.as_ref(), href)
                        {
                            let depth = item.depth + 1;
                            let target_str = target.to_string();
                            if target_str == final_url {
                                continue;
                            }

                            let destructive = crate::dom::heuristics::is_destructive_mutation_label(
                                el.label.as_deref(),
                            );
                            if st.template_sampler.is_saturated_url(&target_str) {
                                st.coverage_gaps
                                    .push(crate::explorer::coverage::CoverageGap {
                                        kind: crate::explorer::coverage::CoverageGapKind::Route,
                                        target: target_str.clone(),
                                        reason: "template_saturated".to_string(),
                                        context: Some(view_id.clone()),
                                    });
                                tracing::debug!(
                                    target = %target_str,
                                    "skipping enqueue: template is saturated"
                                );
                            } else {
                                // Skip enqueuing URLs we have already visited (but still
                                // record a transition edge for the state machine).
                                if destructive {
                                    // Avoid actions like logout/delete being prioritized and accidentally
                                    // disrupting scan coverage. We still record the transition edge.
                                    st.coverage_gaps
                                        .push(crate::explorer::coverage::CoverageGap {
                                            kind: crate::explorer::coverage::CoverageGapKind::Route,
                                            target: target_str.clone(),
                                            reason: "destructive_nav_link_skipped".to_string(),
                                            context: Some(format!(
                                                "{view_id} label={}",
                                                el.label.as_deref().unwrap_or("(none)")
                                            )),
                                        });
                                } else if !st.url_to_view.contains_key(&target_str) {
                                    if *in_nav {
                                        st.scheduler.enqueue_priority(
                                            target_str.clone(),
                                            depth,
                                            0,
                                            base_url,
                                            scope_filter,
                                            cfg.scan.exploration.strategy,
                                            cfg.scan.exploration.novelty_scoring,
                                            template_variant_changed,
                                        );
                                    } else {
                                        st.scheduler.enqueue_scoped(
                                            target_str.clone(),
                                            depth,
                                            base_url,
                                            scope_filter,
                                            cfg.scan.exploration.strategy,
                                            cfg.scan.exploration.novelty_scoring,
                                            template_variant_changed,
                                        );
                                    }
                                }
                            }
                            st.pending_transitions.push(PendingTransition {
                                from_view: view_id.clone(),
                                trigger: InteractionRef {
                                    view: view_id.clone(),
                                    selector: el.selector.clone(),
                                },
                                trigger_locators: el.locators.clone(),
                                transition_type: TransitionType::Navigation,
                                target_url: target_str,
                            });
                        }
                    }
                }
            }

            // Expand nav dropdown buttons to discover hidden links.
            set_phase(&visit_phase_tracker, "nav_expand");
            if let Some(timeout) = view_budget.phase_timeout(VIEW_BUDGET_RESERVE, PHASE_NAV_EXPAND_MAX) {
                if tokio::time::timeout(
                    timeout,
                    expand_nav_dropdowns(
                        &page,
                        cfg,
                        network,
                        bug_detector,
                        interaction_log,
                        base_url,
                        current_url.as_ref(),
                        scope_filter,
                        &view_id,
                        &final_url,
                        item.depth,
                        &elements,
                        &self.state,
                    ),
                )
                .await
                .is_err()
                {
                    tracing::debug!(url=%final_url, "nav dropdown expansion timed out");
                    record_view_budget_skip(
                        &mut self.lock(),
                        crate::explorer::coverage::CoverageGapKind::Route,
                        &final_url,
                        Some(&view_id),
                        "nav_expand",
                    );
                }
            } else {
                tracing::debug!(url=%final_url, "skipping nav dropdown expansion: time budget exhausted");
                record_view_budget_skip(
                    &mut self.lock(),
                    crate::explorer::coverage::CoverageGapKind::Route,
                    &final_url,
                    Some(&view_id),
                    "nav_expand",
                );
            }

            // Done with on-load attribution; subsequent network calls should be tied
            // to explicit interactions.
            network.set_current_interaction_on(&tab, None);

            // Safe interaction pass (buttons). Skip entirely on antibot challenge pages.
            set_phase(&visit_phase_tracker, "interactions");
            let mut interaction_deadline = view_budget.phase_deadline(VIEW_BUDGET_RESERVE);
            if let Some(deadline) = scan_deadline {
                interaction_deadline = interaction_deadline.min(deadline);
            }
            let mut known_links =
                interaction::link_targets(base_url, current_url.as_ref(), &elements);
            let interaction_out = if challenge_detected {
                interaction::InteractionPassOutput::default()
            } else {
                let (identity_scope, template_instance, recorded_elsewhere) = {
                    let mut st = self.lock();
                    let template = st.template_sampler.template_of(&final_url);
                    let identity_scope =
                        interaction::identity_scope(&st.template_sampler, &final_url);
                    let template_instance = template.map(|template| {
                        let path = interaction::route_scope(&final_url);
                        let paths = st.template_instances.entry(template).or_default();
                        match paths.iter().position(|p| *p == path) {
                            Some(i) => i + 1,
                            None => {
                                paths.push(path);
                                paths.len()
                            }
                        }
                    });
                    // Nav dropdowns this view expanded (and recorded) above.
                    let prefix = format!("{view_id}::");
                    let recorded_elsewhere: std::collections::HashSet<String> = st
                        .expanded_nav_dropdown_triggers
                        .iter()
                        .filter(|key| key.starts_with(&prefix))
                        .cloned()
                        .collect();
                    (identity_scope, template_instance, recorded_elsewhere)
                };
                let ctx = interaction::PassContext {
                    page: &page,
                    cfg,
                    network,
                    bug_detector,
                    base_url,
                    scope_filter,
                    log: interaction_log,
                    current_depth: item.depth,
                    view_url: &final_url,
                    classified: &classified,
                    deadline: Some(interaction_deadline),
                    recorded_elsewhere: &recorded_elsewhere,
                    identity_scope: &identity_scope,
                    template_instance,
                };
                let mut pass_state = interaction::PassState {
                    pacer: &mut *pacer,
                    shared: &self.state,
                    known_links: &mut known_links,
                };
                interaction::run_interaction_pass(
                    &ctx,
                    &mut pass_state,
                    &view_id,
                    &elements,
                    cfg.scan.limits.max_interactions_per_view,
                    0,
                    &std::collections::HashSet::new(),
                    &[],
                )
                .await?
            };
            // A re-login (by any tab) while this view was explored: what it
            // observed may come from the expired session. Explore it again
            // under the new session, once.
            if cfg.auth.is_some() {
                // Did the session end during this view? Check its auth
                // failures and where the tab is now (a restore that landed on
                // the login page), while the view budget leaves room for a
                // re-login (else the post-visit check covers the next views).
                if view_budget.remaining() > SESSION_CHECK_RESERVE {
                    self.process_network_errors().await?;
                    let landed = page.url().await.ok().flatten().unwrap_or_default();
                    if self.session.lock().await.generation == session_generation
                        && self.landed_on_login(&final_url, &landed)
                    {
                        let trigger = SessionTrigger::LoginGate {
                            url: final_url.clone(),
                            landed,
                        };
                        self.recover_session(session_generation, trigger, false)
                            .await;
                    }
                }
                let generation = self.session.lock().await.generation;
                if generation != session_generation
                    && self.lock().retry_visit_after_relogin(slot.visit)
                {
                    tracing::info!(
                        url = %final_url,
                        "a re-login happened during this view; exploring it again under the new session"
                    );
                    network.set_current_interaction_on(&tab, None);
                    close_page_bounded(&page).await;
                    self.process_network_errors().await?;
                    return Ok(());
                }
            }
            if interaction_out.budget_exhausted {
                record_view_budget_skip(
                    &mut self.lock(),
                    crate::explorer::coverage::CoverageGapKind::Interaction,
                    &final_url,
                    Some(&view_id),
                    "interactions",
                );
            }

            // Apply captured post-interaction snapshots and outcomes onto elements.
            for (sel, snap) in &interaction_out.interaction_snapshots {
                if let Some(el) = elements.iter_mut().find(|e| e.selector == *sel) {
                    el.snapshot = Some(snap.clone());
                }
            }
            for (sel, result) in &interaction_out.interaction_results {
                if let Some(el) = elements.iter_mut().find(|e| e.selector == *sel) {
                    el.interaction_result = Some(result.clone());
                }
            }

            let form_action_interactions = interaction_out.form_action_interactions;
            let selector_query_params = interaction_out.selector_query_params;
            let sub_views = interaction_out.sub_views;
            let deep_transitions = interaction_out.deep_transitions;

            // Links revealed by clicks (hamburger sidenavs, menus): queue them
            // and keep them as controls of this view.
            if !interaction_out.revealed_links.is_empty() {
                let mut known = interaction::link_targets(base_url, current_url.as_ref(), &elements);
                let mut st = self.lock();
                let fresh = enqueue_revealed_links(
                    &mut st,
                    cfg,
                    base_url,
                    current_url.as_ref(),
                    scope_filter,
                    &view_id,
                    item.depth,
                    &mut known,
                    &interaction_out.revealed_links,
                );
                let in_sub_views: std::collections::HashSet<&str> = sub_views
                    .iter()
                    .flat_map(|sv| sv.elements.iter().map(|e| e.selector.as_str()))
                    .collect();
                let mut added = 0usize;
                for link in fresh {
                    if in_sub_views.contains(link.selector.as_str())
                        || elements.iter().any(|e| e.selector == link.selector)
                    {
                        continue;
                    }
                    let mut link = link.clone();
                    link.found_on = view_id.clone();
                    interaction::write_interaction_record(
                        interaction_log,
                        &interaction::skipped_record(
                            &view_id,
                            &final_url,
                            &link,
                            "navigation_via_href",
                        ),
                    );
                    elements.push(link);
                    added += 1;
                }
                st.elements_discovered += added;
                if added > 0 {
                    tracing::info!(view_id = %view_id, added, "links revealed by interactions");
                }
            }
            {
                let mut st = self.lock();
                for skipped in interaction_out.skipped_interactions {
                    let context = match skipped.label {
                        Some(label) if !label.trim().is_empty() => {
                            Some(format!("{view_id} label={label}"))
                        }
                        _ => Some(view_id.clone()),
                    };
                    let gap_kind = if skipped.reason == "modal_depth_limit"
                        || skipped.reason == "modal_dismiss_failed"
                    {
                        crate::explorer::coverage::CoverageGapKind::UnexploredMutation
                    } else {
                        crate::explorer::coverage::CoverageGapKind::Interaction
                    };
                    st.coverage_gaps
                        .push(crate::explorer::coverage::CoverageGap {
                            kind: gap_kind,
                            target: skipped.selector,
                            reason: skipped.reason,
                            context,
                        });
                }

                // Merge deep exploration results into scan state.
                for sv in sub_views {
                    st.views.push(AppView {
                        id: sv.id.clone(),
                        url: final_url.clone(),
                        fingerprint: sv.fingerprint.unwrap_or_else(|| DomFingerprint(format!("sub_{}", sv.id))),
                        title: sv.snapshot
                            .as_ref()
                            .and_then(|s| s.modal_opened.as_ref())
                            .and_then(|m| m.title.clone()),
                        component_type: "sub_view".to_string(),
                        description: format!("Sub-view at depth {} triggered by {}", sv.depth, sv.trigger_selector),
                        components: vec![],
                        component_instances: vec![],
                        elements: sv.elements,
                        on_load_api_calls: sv.api_calls,
                        detected_framework: None,
                        screenshot: None,
                        parent_view: Some(sv.parent_view),
                        depth: sv.depth,
                        trigger_selector: Some(sv.trigger_selector),
                        sub_view_transition_type: Some(sv.transition_type),
                    });
                }
                st.pending_transitions.extend(deep_transitions);
            }

            if !form_action_interactions.is_empty() {
                let mut endpoints_snapshot = network.endpoints_snapshot();
                for ep in &mut endpoints_snapshot {
                    if ep.request_body_schema.is_none() && !ep.request_body_samples.is_empty() {
                        ep.request_body_schema =
                            schema_inference::infer_schema(&ep.request_body_samples);
                    }
                }
                let view_route =
                    crate::explorer::template_sampler::url_to_template_path(&final_url)
                        .unwrap_or_else(|| final_url.clone());

                // Form selector -> field defs (used for endpoint scoring).
                let mut form_fields_by_selector: HashMap<
                    String,
                    Vec<crate::types::classifier::FormFieldDef>,
                > = HashMap::new();
                for comp in &classified.components {
                    if let ComponentType::Form { fields, .. } = &comp.component {
                        form_fields_by_selector
                            .entry(comp.selector.clone())
                            .or_insert_with(|| fields.clone());
                    }
                }

                // Map form selector -> best (most likely) submit endpoint.
                let mut form_endpoint_map: HashMap<String, String> = HashMap::new();
                let mut form_endpoint_score: HashMap<String, i64> = HashMap::new();
                let mut form_submit_label_map: HashMap<String, String> = HashMap::new();

                for interaction in form_action_interactions {
                    let interaction_ref = &interaction.trigger;
                    let form_selector = &interaction.form_selector;
                    let fields: &[crate::types::classifier::FormFieldDef] = form_fields_by_selector
                        .get(form_selector)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);

                    let Some((ep_desc, score)) = form_mapping::best_endpoint_for_form_interaction(
                        &endpoints_snapshot,
                        interaction_ref,
                        fields,
                        &view_route,
                    ) else {
                        continue;
                    };

                    let replace = match form_endpoint_score.get(form_selector).copied() {
                        None => true,
                        Some(existing) => score > existing,
                    };
                    if replace {
                        form_endpoint_score.insert(form_selector.clone(), score);
                        form_endpoint_map.insert(form_selector.clone(), ep_desc);
                        if let Some(lbl) = interaction
                            .submit_label
                            .as_deref()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                        {
                            form_submit_label_map.insert(form_selector.clone(), lbl);
                        }
                    }
                }
                enrich_forms_with_endpoints(&mut classified, &form_endpoint_map);
                form_mapping::enrich_forms_with_submit_labels(
                    &mut classified,
                    &form_submit_label_map,
                );
                form_mapping::enrich_form_field_names_from_request_schema(
                    &mut classified,
                    &endpoints_snapshot,
                );

                // Form validation fuzzing is handled via network replay after the scan completes.
            }

            form_mapping::enrich_form_fields_with_query_param_mapping(
                &mut classified,
                &selector_query_params,
            );

            // Derive the view's "on load" API calls from the special load marker.
            let on_load_api_calls = derive_on_load_api_calls(network, &view_id);

            // When the scan duration budget has elapsed (or the view budget is
            // down to its commit reserve), skip slow post-interaction restores
            // and accessibility audits so the collected view commits before
            // `hard_timeout` fires.
            let scan_time_up = scan_deadline.is_some_and(|d| Instant::now() >= d);
            let fast_commit = scan_time_up || view_budget.remaining() <= VIEW_BUDGET_RESERVE;
            if !fast_commit {
                let restore_timeout = restore_navigation_timeout(cfg)
                    .min(view_budget.remaining())
                    .max(Duration::from_millis(500));
                network.forget_recent_interactions_on(&tab);
                restore_page_to_view_url(&page, &final_url, cfg, restore_timeout).await;
            }

            // Accessibility audit: run the WCAG audit script post-settle.
            set_phase(&visit_phase_tracker, "accessibility");
            if cfg.scan.accessibility.enabled && !fast_commit {
                #[derive(serde::Deserialize)]
                struct AccessibilityDocumentMetadata {
                    #[serde(default)]
                    content_type: Option<String>,
                    #[serde(default)]
                    root_tag: Option<String>,
                }

                let a11y_document = page
                    .evaluate_json::<AccessibilityDocumentMetadata>(
                        r#"
(() => ({
  content_type: document.contentType || null,
  root_tag: document.documentElement ? document.documentElement.tagName : null
}))()
"#,
                    )
                    .await
                    .ok();

                if !should_run_accessibility_audit_for_document(
                    &final_url,
                    a11y_document
                        .as_ref()
                        .and_then(|doc| doc.content_type.as_deref()),
                    a11y_document.as_ref().and_then(|doc| doc.root_tag.as_deref()),
                ) {
                    tracing::debug!(
                        url = %final_url,
                        content_type = ?a11y_document
                            .as_ref()
                            .and_then(|doc| doc.content_type.as_deref()),
                        root_tag = ?a11y_document.as_ref().and_then(|doc| doc.root_tag.as_deref()),
                        "skipping a11y audit for non-html document"
                    );
                } else {
                    let a11y_timeout =
                        view_budget.phase_timeout(VIEW_BUDGET_RESERVE, PHASE_A11Y_MAX);
                    let a11y_result = if let Some(timeout) = a11y_timeout {
                        match tokio::time::timeout(
                            timeout,
                            page.evaluate_json::<Vec<RawA11yResult>>(
                                crate::bugs::accessibility::A11Y_AUDIT_SCRIPT,
                            ),
                        )
                        .await
                        {
                            Ok(res) => res,
                            Err(_) => Err(anyhow::anyhow!("a11y audit timed out")),
                        }
                    } else {
                        Err(anyhow::anyhow!("a11y audit skipped: time budget exhausted"))
                    };

                    match a11y_result {
                        Ok(raw_findings) => {
                            let raw_findings =
                                reconcile_missing_lang_findings(&page, &final_url, raw_findings)
                                    .await;
                            let max = cfg.scan.accessibility.max_findings_per_view;
                            for (i, raw) in raw_findings.into_iter().enumerate() {
                                if i >= max {
                                    tracing::debug!(view = %view_id, "a11y findings capped at {max}");
                                    break;
                                }
                                if let Some(cat) =
                                    crate::bugs::accessibility::parse_category(&raw.category)
                                {
                                    if let Some(rule) =
                                        crate::bugs::accessibility::rule_for_category(cat)
                                    {
                                        let finding = crate::bugs::accessibility::A11yFinding {
                                            category: cat,
                                            wcag_criterion: rule.wcag_criterion,
                                            wcag_level: rule.wcag_level,
                                            selector: raw.selector.clone(),
                                            description: raw.description.clone(),
                                            impact: rule.impact,
                                        };
                                        bug_detector
                                            .record_a11y_finding(
                                                raw.category,
                                                rule.wcag_criterion.to_string(),
                                                rule.impact.into(),
                                                raw.description,
                                                raw.selector,
                                                finding.to_bug_severity(),
                                                Some(view_id.clone()),
                                                Some(final_url.clone()),
                                            )
                                            .await;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            tracing::debug!(error = ?err, "a11y audit script failed");
                        }
                    }
                }
            }

            let view = AppView {
                id: view_id.clone(),
                url: final_url.clone(),
                fingerprint: DomFingerprint(fingerprint.0.clone()),
                title,
                component_type: classified.primary_type.clone(),
                description: classified.description.clone(),
                components: classified
                    .components
                    .iter()
                    .map(|c| c.component.clone())
                    .collect(),
                component_instances: classified.components.clone(),
                elements,
                on_load_api_calls,
                detected_framework,
                screenshot,
                parent_view: None,
                depth: 0,
                trigger_selector: None,
                sub_view_transition_type: None,
            };
            let views_explored = {
                let mut st = self.lock();
                st.views.push(view);
                st.visited_route_templates.insert(route);
                let scope = super::route_scope_of(&st.template_sampler, &final_url);
                st.visited_route_scopes.insert(scope);
                // Commit the visit as soon as the view is recorded so a late
                // `hard_timeout` or cancellation during cleanup (canary, page
                // close, save_progress) never retracts a completed view.
                st.finish_visit(slot.visit);
                slot.finished = true;
                st.views.len()
            };
            self.session_health.record_view_completed();

            // Proactive canary: periodically verify the session is still valid.
            if !scan_time_up
                && cfg.scan.canary_interval_views > 0
                && cfg.auth.is_some()
                && self.session_health.canary_due(cfg.scan.canary_interval_views)
            {
                self.session_health.reset_canary_counter();
                let (canary, generation) = {
                    let session = self.session.lock().await;
                    if session.expired {
                        (Canary::Unknown, session.generation)
                    } else {
                        (self.session_canary(&session).await, session.generation)
                    }
                };
                if let Canary::LoggedOut(why) = canary {
                    tracing::warn!(reason = %why, "auth canary failed — session may be expired");
                    self.recover_session(generation, SessionTrigger::Canary, true)
                        .await;
                }
            }

            // After a few views, warn the user if no API traffic was captured.
            // This catches common localhost hostname mismatches, dead servers, etc.
            if views_explored >= 3 && network.endpoint_count() == 0 {
                let mut st = self.lock();
                if !st.no_traffic_warned {
                    tracing::warn!(
                        url = %base_url,
                        views = views_explored,
                        "no API traffic captured yet across {views_explored} views"
                    );
                    st.no_traffic_warned = true;
                }
            }

            close_page_bounded(&page).await;

            self.process_network_errors().await?;
            self.save_progress(false).await;

            Ok::<(), anyhow::Error>(())
        })
        .await;

        match visit_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::warn!(error = ?err, url = %item.url, "page processing failed; skipping url");
                self.record_page_failure(
                    &item.url,
                    "Page processing failed",
                    format!("Page processing failed: {err:#}"),
                    format!("Failed while processing {}: {err:#}", item.url),
                )
                .await;

                network.set_current_interaction_on(&tab, None);
                close_page_bounded(&page).await;
                if let Err(err) = self.process_network_errors().await {
                    tracing::warn!(error = ?err, "failed to process network errors after page failure");
                }
                self.save_progress(false).await;
            }
            Err(_) => {
                let last_phase = phase_snapshot(&phase_tracker);
                tracing::warn!(
                    url = %item.url,
                    timeout_seconds = page_timeout.as_secs(),
                    last_phase = %last_phase,
                    "page processing exceeded watchdog timeout; skipping url"
                );
                self.record_page_failure(
                    &item.url,
                    "Page processing timeout",
                    format!(
                        "Page processing timed out after {}s",
                        page_timeout.as_secs()
                    ),
                    format!(
                        "Timed out processing {} after {}s (last_phase={})",
                        item.url,
                        page_timeout.as_secs(),
                        last_phase
                    ),
                )
                .await;

                network.set_current_interaction_on(&tab, None);
                close_page_bounded(&page).await;
                if let Err(err) = self.process_network_errors().await {
                    tracing::warn!(error = ?err, "failed to process network errors after page timeout");
                }
                self.save_progress(false).await;
            }
        }
        Ok(())
    }
}

fn maybe_emit_scan_checkpoint(
    cfg: &BrokenAppConfig,
    start_instant: Instant,
    state: &mut RuntimeState,
    network: &Arc<NetworkInterceptor>,
    interval_seconds: u64,
) {
    if state.ctl.last_progress_emit_at.elapsed() < Duration::from_secs(interval_seconds) {
        return;
    }
    state.ctl.last_progress_emit_at = Instant::now();
    let processed_items = state.ctl.processed_items;

    let elapsed_seconds = start_instant.elapsed().as_secs();
    let views = state.views.len();
    let queue_remaining = state.scheduler.len();
    let endpoints = network.endpoint_count();
    let coverage_percent =
        interaction_coverage_percent(state.elements_discovered, state.elements_interacted);
    let views_per_min = rate_per_minute(views, elapsed_seconds);
    let urls_per_min = rate_per_minute(processed_items, elapsed_seconds);
    let eta = estimate_scan_eta(
        cfg,
        elapsed_seconds,
        views,
        queue_remaining,
        processed_items,
    );

    let (eta_seconds, eta_basis, eta_human) = if let Some(eta) = eta {
        (
            Some(eta.seconds),
            Some(eta.basis.to_string()),
            Some(format_duration_compact(eta.seconds)),
        )
    } else {
        (None, None, None)
    };

    tracing::info!(
        elapsed = %format_duration_compact(elapsed_seconds),
        elapsed_seconds,
        views,
        queue_remaining,
        endpoints,
        urls_processed = processed_items,
        views_per_min,
        urls_per_min,
        coverage_percent,
        in_flight = state.ctl.in_flight,
        eta = eta_human.as_deref().unwrap_or("unknown"),
        eta_seconds = ?eta_seconds,
        eta_basis = ?eta_basis,
        "scan checkpoint"
    );
}

/// A `ScanProgress` snapshot for `--progress-file` when at least 5 seconds
/// have elapsed since the last write (`bugs_found` is filled in by
/// [`write_progress_file`]).
fn progress_file_due(
    cfg: &BrokenAppConfig,
    start_instant: Instant,
    state: &mut RuntimeState,
    network: &Arc<NetworkInterceptor>,
    current_url: Option<&str>,
) -> Option<ScanProgress> {
    const PROGRESS_FILE_INTERVAL_SECS: u64 = 5;

    cfg.output.progress_file.as_ref()?;
    if state.ctl.last_progress_file_write.elapsed()
        < Duration::from_secs(PROGRESS_FILE_INTERVAL_SECS)
    {
        return None;
    }
    state.ctl.last_progress_file_write = Instant::now();

    let elapsed_seconds = start_instant.elapsed().as_secs();
    let views_found = state.views.len();
    let eta = estimate_scan_eta(
        cfg,
        elapsed_seconds,
        views_found,
        state.scheduler.len(),
        state.ctl.processed_items,
    );
    Some(ScanProgress {
        phase: "exploring".to_string(),
        views_found,
        endpoints_found: network.endpoint_count(),
        bugs_found: 0,
        raw_observations_found: None,
        current_url: current_url.map(String::from),
        coverage_pct: interaction_coverage_percent(
            state.elements_discovered,
            state.elements_interacted,
        ),
        elapsed_seconds,
        estimated_remaining_seconds: eta.map(|e| e.seconds),
    })
}

/// Write a [`progress_file_due`] snapshot to `--progress-file` (atomically,
/// so external readers never observe partial JSON).
async fn write_progress_file(
    cfg: &BrokenAppConfig,
    bug_detector: &Arc<BugDetector>,
    mut progress: ScanProgress,
) {
    let Some(progress_path) = cfg.output.progress_file.as_ref() else {
        return;
    };
    let bugs_found = bug_detector.bug_count().await;
    progress.bugs_found = bugs_found;
    progress.raw_observations_found = Some(bugs_found);
    if let Err(err) = output::write_json(progress_path, &progress).await {
        tracing::warn!(
            path = %progress_path.display(),
            error = %err,
            "failed to write progress file"
        );
    }
}

/// Write a final "complete" progress snapshot so external consumers know the
/// scan has finished.
pub(super) async fn write_final_progress(
    cfg: &BrokenAppConfig,
    start_instant: Instant,
    state: &RuntimeState,
    network: &Arc<NetworkInterceptor>,
    bug_detector: &Arc<BugDetector>,
    phase: &str,
) {
    let progress_path = match cfg.output.progress_file.as_ref() {
        Some(p) => p,
        None => return,
    };

    let coverage_pct =
        interaction_coverage_percent(state.elements_discovered, state.elements_interacted);

    let raw_observations_found = bug_detector.bug_count().await;
    let bugs_found = finalized_bug_count(&cfg.output.directory)
        .await
        .unwrap_or(raw_observations_found);

    let progress = ScanProgress {
        phase: phase.to_string(),
        views_found: state.views.len(),
        endpoints_found: network.endpoint_count(),
        bugs_found,
        raw_observations_found: Some(raw_observations_found),
        current_url: None,
        coverage_pct,
        elapsed_seconds: start_instant.elapsed().as_secs(),
        estimated_remaining_seconds: Some(0),
    };

    if let Err(err) = output::write_json(progress_path, &progress).await {
        tracing::warn!(
            path = %progress_path.display(),
            error = %err,
            "failed to write final progress file"
        );
    }
}

async fn finalized_bug_count(output_dir: &Path) -> Option<usize> {
    let raw = tokio::fs::read_to_string(output_dir.join("bugs.json"))
        .await
        .ok()?;
    let report: crate::output::bug_report::BugReport = serde_json::from_str(&raw).ok()?;
    Some(report.items.len())
}

fn scan_progress_interval_seconds(cfg: &BrokenAppConfig) -> u64 {
    cfg.output.checkpoint_interval_seconds.max(15).min(120)
}

fn rate_per_minute(count: usize, elapsed_seconds: u64) -> f64 {
    if count == 0 || elapsed_seconds == 0 {
        return 0.0;
    }
    (count as f64 / elapsed_seconds as f64) * 60.0
}

fn interaction_coverage_percent(discovered: usize, interacted: usize) -> f64 {
    if discovered == 0 {
        return 0.0;
    }
    ((interacted as f64 / discovered as f64) * 100.0).clamp(0.0, 100.0)
}

fn estimate_scan_eta(
    cfg: &BrokenAppConfig,
    elapsed_seconds: u64,
    views: usize,
    queue_remaining: usize,
    processed_items: usize,
) -> Option<EtaEstimate> {
    if elapsed_seconds < 30 {
        return None;
    }
    let elapsed = elapsed_seconds as f64;
    let mut candidates: Vec<EtaEstimate> = Vec::new();

    if cfg.scan.max_views > 0 && views < cfg.scan.max_views && views > 0 {
        let views_per_second = views as f64 / elapsed;
        if views_per_second > 0.0 {
            let remaining_views = (cfg.scan.max_views - views) as f64;
            let eta_seconds = (remaining_views / views_per_second).ceil() as u64;
            if eta_seconds > 0 {
                candidates.push(EtaEstimate {
                    seconds: eta_seconds,
                    basis: "max_views",
                });
            }
        }
    }

    if queue_remaining > 0 && processed_items >= 10 {
        let urls_per_second = processed_items as f64 / elapsed;
        if urls_per_second > 0.0 {
            let eta_seconds = (queue_remaining as f64 / urls_per_second).ceil() as u64;
            if eta_seconds > 0 {
                candidates.push(EtaEstimate {
                    seconds: eta_seconds,
                    basis: "frontier_queue",
                });
            }
        }
    }

    if cfg.scan.max_duration_minutes > 0 {
        let max_duration = cfg.scan.max_duration_minutes.saturating_mul(60);
        if max_duration > elapsed_seconds {
            candidates.push(EtaEstimate {
                seconds: max_duration - elapsed_seconds,
                basis: "max_duration",
            });
        }
    }

    candidates.into_iter().min_by_key(|c| c.seconds)
}

fn format_duration_compact(total_seconds: u64) -> String {
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Record findings for failed requests (taken from the interceptor's error
/// buffer) and feed their statuses to the session health monitor.
async fn process_network_errors(
    bug_detector: &Arc<BugDetector>,
    entries: Vec<TrafficEntry>,
    session_health: Option<&crate::session::health::SessionHealthMonitor>,
    base_url: Option<&Url>,
) -> Result<NetworkErrorDigest> {
    let mut digest = NetworkErrorDigest::default();

    for entry in entries {
        if let Some(resp) = entry.response.as_ref() {
            digest.total_statuses += 1;
            if let Some(health) = session_health {
                health.record_status(resp.status);
            }
            if resp.status == 401 || resp.status == 403 {
                digest.auth_failures += 1;
            }
            if resp.status >= 500 && should_record_server_error(&entry, base_url) {
                bug_detector
                    .record_server_error(
                        entry.request.url.clone(),
                        resp.status,
                        resp.body_snippet.clone(),
                    )
                    .await;
            } else if resp.status >= 400 && should_record_action_api_error(&entry, base_url) {
                bug_detector
                    .record_api_error(
                        entry.request.url.clone(),
                        resp.status,
                        resp.body_snippet.clone(),
                    )
                    .await;
            } else if resp.status == 404 && should_record_asset_load_failure(&entry, base_url) {
                bug_detector
                    .record_asset_load_failure(entry.request.url.clone(), resp.status)
                    .await;
            } else if resp.status == 404 {
                if should_record_broken_link(&entry, base_url) {
                    bug_detector
                        .record_broken_link(entry.request.url.clone(), resp.status)
                        .await;
                }
            }
        } else if should_record_network_failure(&entry, base_url) {
            if let Some(failure) = entry.failure.as_ref() {
                bug_detector
                    .record_network_request_failure(entry.request.url.clone(), failure.clone())
                    .await;
            }
        }
    }
    Ok(digest)
}

#[derive(Debug, Default)]
struct NetworkErrorDigest {
    total_statuses: usize,
    auth_failures: usize,
}

fn should_record_broken_link(entry: &TrafficEntry, base_url: Option<&Url>) -> bool {
    if !matches!(entry.request.method, HttpMethod::Get | HttpMethod::Head) {
        return false;
    }
    if entry.is_api == Some(true) {
        return false;
    }

    let target_url = match Url::parse(&entry.request.url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if is_framework_data_request(&target_url) {
        return false;
    }
    if let Some(base) = base_url {
        if !url_utils::same_origin(base, &target_url) {
            return false;
        }
    }

    if crate::network::filters::looks_like_static_asset_path(target_url.path()) {
        return false;
    }

    if let Some(resp) = entry.response.as_ref() {
        if let Some(ct) = resp.mime_type.as_deref() {
            let ct = ct.to_ascii_lowercase();
            if ct.starts_with("image/")
                || ct.starts_with("video/")
                || ct.starts_with("audio/")
                || ct.contains("font/")
                || ct.contains("text/css")
                || ct.contains("javascript")
            {
                return false;
            }
        }
    }

    true
}

fn should_record_asset_load_failure(entry: &TrafficEntry, base_url: Option<&Url>) -> bool {
    if !matches!(entry.request.method, HttpMethod::Get | HttpMethod::Head) {
        return false;
    }
    let Some(resp) = entry.response.as_ref() else {
        return false;
    };
    if !matches!(resp.status, 404 | 410) {
        return false;
    }

    let target_url = match Url::parse(&entry.request.url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if let Some(base) = base_url {
        if !url_utils::same_origin(base, &target_url) {
            return false;
        }
    }

    if is_browser_default_favicon_probe(entry, &target_url) {
        return false;
    }

    if crate::network::filters::looks_like_static_asset_path(target_url.path()) {
        return true;
    }
    resp.mime_type
        .as_deref()
        .map(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("image/")
                || ct.starts_with("video/")
                || ct.starts_with("audio/")
                || ct.contains("font/")
                || ct.contains("text/css")
                || ct.contains("javascript")
        })
        .unwrap_or(false)
}

/// True when a request is the browser's automatic `<origin>/favicon.ico` probe.
///
/// Chrome issues this request on every navigation even when the page references
/// no icon, so a 404 there is not a *referenced* static-asset failure (which is
/// what `asset_load_failure` reports). A favicon explicitly linked by the page
/// carries a page-driven initiator (e.g. `parser`) and is still reported.
fn is_browser_default_favicon_probe(entry: &TrafficEntry, target_url: &Url) -> bool {
    if !target_url.path().eq_ignore_ascii_case("/favicon.ico") {
        return false;
    }
    let initiator = entry
        .trace
        .as_ref()
        .and_then(|trace| trace.initiator_type.as_deref());
    // Browser-internal probes report initiator "other" (or carry no trace at
    // all); page-referenced assets report a markup/script initiator.
    matches!(initiator, None | Some("other"))
}

fn should_record_action_api_error(entry: &TrafficEntry, base_url: Option<&Url>) -> bool {
    let Some(resp) = entry.response.as_ref() else {
        return false;
    };
    if resp.status < 400 {
        return false;
    }
    if entry.is_api != Some(true) {
        return false;
    }
    if entry.triggered_by.is_none()
        && entry
            .trace
            .as_ref()
            .and_then(|trace| trace.action_id.as_deref())
            .is_none()
    {
        return false;
    }

    let target_url = match Url::parse(&entry.request.url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if let Some(base) = base_url {
        if !url_utils::same_origin(base, &target_url) {
            return false;
        }
    }

    true
}

fn should_record_server_error(entry: &TrafficEntry, base_url: Option<&Url>) -> bool {
    let target_url = match Url::parse(&entry.request.url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    if let Some(base) = base_url {
        if !url_utils::same_origin(base, &target_url) {
            return false;
        }
    }

    !crate::network::filters::looks_like_static_asset_path(target_url.path())
}

fn should_record_network_failure(entry: &TrafficEntry, base_url: Option<&Url>) -> bool {
    let Some(failure) = entry.failure.as_deref() else {
        return false;
    };
    let normalized_failure = failure.to_ascii_lowercase();
    if normalized_failure.contains("blockedbyclient")
        || normalized_failure.contains("blocked_by_client")
        || normalized_failure.contains("aborted")
    {
        return false;
    }
    if entry.triggered_by.is_none()
        && entry
            .trace
            .as_ref()
            .and_then(|trace| trace.action_id.as_deref())
            .is_none()
    {
        return false;
    }

    let target_url = match Url::parse(&entry.request.url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if let Some(base) = base_url {
        if url_utils::same_origin(base, &target_url) {
            return true;
        }
        return true;
    }

    true
}

fn is_framework_data_request(url: &Url) -> bool {
    url.query_pairs().any(|(key, _)| {
        matches!(
            key.as_ref(),
            "_rsc" | "__flight__" | "__flight_serialized__" | "__nextDataReq"
        )
    })
}

fn should_run_accessibility_audit_for_document(
    final_url: &str,
    document_content_type: Option<&str>,
    root_tag_name: Option<&str>,
) -> bool {
    if let Ok(parsed) = Url::parse(final_url) {
        let path = parsed.path().to_ascii_lowercase();
        if crate::network::filters::looks_like_static_asset_path(&path)
            || looks_like_non_html_document_path(&path)
        {
            return false;
        }
    }

    if let Some(root_tag) = root_tag_name
        .map(str::trim)
        .filter(|root_tag| !root_tag.is_empty())
    {
        if !root_tag.eq_ignore_ascii_case("html") {
            return false;
        }
    }

    match document_content_type
        .map(str::trim)
        .filter(|content_type| !content_type.is_empty())
        .map(|content_type| content_type.to_ascii_lowercase())
    {
        Some(content_type)
            if content_type.starts_with("text/html")
                || content_type.contains("application/xhtml") =>
        {
            true
        }
        Some(content_type) if is_non_html_content_type(&content_type) => false,
        _ => true,
    }
}

fn drop_missing_lang_findings_if_lang_present(
    raw_findings: Vec<RawA11yResult>,
    document_lang: Option<&str>,
) -> Vec<RawA11yResult> {
    let Some(_document_lang) = document_lang.map(str::trim).filter(|lang| !lang.is_empty()) else {
        return raw_findings;
    };

    raw_findings
        .into_iter()
        .filter(|finding| finding.category != "missing_lang")
        .collect()
}

async fn reconcile_missing_lang_findings(
    page: &crate::browser::PageClient,
    final_url: &str,
    raw_findings: Vec<RawA11yResult>,
) -> Vec<RawA11yResult> {
    if !raw_findings
        .iter()
        .any(|finding| finding.category == "missing_lang")
    {
        return raw_findings;
    }

    let before = raw_findings.len();
    let document_lang = recheck_document_lang(page).await;

    let filtered =
        drop_missing_lang_findings_if_lang_present(raw_findings, document_lang.as_deref());
    if filtered.len() != before {
        tracing::debug!(
            url = %final_url,
            document_lang = document_lang.as_deref().unwrap_or_default(),
            "dropping transient missing_lang finding after lang recheck"
        );
    }
    filtered
}

/// Order fresh-scan seeds so the entry URL (`/`) gets priority `0`, explicit
/// `scan.seed_urls` get priority `5` in order, normal discovered/seed-file
/// routes are explored breadth-first by path depth at priority `10`, and
/// `scan.deprioritize_routes` follow at priority `40`.
fn prioritize_fresh_scan_seeds(cfg: &BrokenAppConfig, base_url: &Url, state: &mut RuntimeState) {
    let explicit_seeds: Vec<String> = cfg
        .scan
        .seed_urls
        .iter()
        .filter_map(|raw| url_utils::normalize_href(base_url, None, raw))
        .map(|u| url_utils::canonicalize_crawl_url(u.as_str()))
        .collect();
    state.scheduler.prioritize_initial_seeds(
        base_url.as_str(),
        &explicit_seeds,
        &cfg.scan.deprioritize_routes,
        cfg.scan.exploration.strategy,
        cfg.scan.exploration.novelty_scoring,
    );
}

/// Snapshot native `fetch`/`XMLHttpRequest.prototype.send` before
/// `cdp_helpers::install_instrumentation` wraps them, so SSE and Next.js HMR
/// requests can bypass the in-page `pending` settle counter cleanly.
async fn install_settle_stream_exclusions_pre(page: &crate::browser::PageClient) -> Result<()> {
    const PRE_SCRIPT: &str = r#"
(() => {
  try {
    const w = window;
    if (!w.__BROKENAPP_RAW_FETCH && typeof w.fetch === "function") {
      w.__BROKENAPP_RAW_FETCH = w.fetch.bind(w);
    }
    if (!w.__BROKENAPP_RAW_XHR_SEND && w.XMLHttpRequest && w.XMLHttpRequest.prototype) {
      w.__BROKENAPP_RAW_XHR_SEND = w.XMLHttpRequest.prototype.send;
    }
  } catch (_) {}
  return true;
})()
"#;
    let params = cdp_page::AddScriptToEvaluateOnNewDocumentParams::builder()
        .source(PRE_SCRIPT)
        .run_immediately(true)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    page.inner()
        .execute(params)
        .await
        .context("Page.addScriptToEvaluateOnNewDocument (settle exclusions pre)")?;
    Ok(())
}

/// Bypass `window.__BROKENAPP.pending` for long-lived SSE (`text/event-stream`)
/// and framework dev-tool / HMR requests (`/_next/webpack-hmr`,
/// `/__nextjs_original-stack-frame`, `/__nextjs_error_feedback`, etc.) so they
/// never hold `settle` open until the view watchdog fires.
async fn install_settle_stream_exclusions_post(page: &crate::browser::PageClient) -> Result<()> {
    const POST_SCRIPT: &str = r#"
(() => {
  try {
    const w = window;
    if (w.__BROKENAPP_STREAM_EXCLUDED) return true;
    function isIgnoredUrl(rawUrl) {
      try {
        const u = new URL(String(rawUrl || ""), w.location && w.location.href ? w.location.href : undefined);
        const p = (u.pathname || "").toLowerCase();
        return p === "/_next/webpack-hmr"
          || p.startsWith("/_next/webpack-hmr/")
          || p.startsWith("/__nextjs")
          || p.startsWith("/__webpack")
          || p.startsWith("/__vite")
          || p.startsWith("/@vite/")
          || p.startsWith("/@react-refresh")
          || p.startsWith("/__turbopack");
      } catch (_) {
        return false;
      }
    }
    function acceptsSse(input, init) {
      try {
        const isReq = (typeof Request !== "undefined") && (input instanceof Request);
        const raw = (init && init.headers !== undefined) ? init.headers : (isReq ? input.headers : undefined);
        if (!raw) return false;
        const h = new Headers(raw);
        const accept = h.get("accept");
        return !!accept && accept.toLowerCase().includes("text/event-stream");
      } catch (_) {
        return false;
      }
    }
    try {
      const rawFetch = w.__BROKENAPP_RAW_FETCH;
      const wrappedFetch = w.fetch;
      if (typeof rawFetch === "function" && typeof wrappedFetch === "function" && wrappedFetch !== rawFetch) {
        w.fetch = function(input, init) {
          const isReq = (typeof Request !== "undefined") && (input instanceof Request);
          const url = (typeof input === "string") ? input
            : (isReq ? input.url : (input && typeof input.href === "string" ? input.href : ""));
          if (isIgnoredUrl(url) || acceptsSse(input, init)) {
            return rawFetch(input, init);
          }
          return wrappedFetch.apply(this, arguments);
        };
      }
    } catch (_) {}
    try {
      const rawSend = w.__BROKENAPP_RAW_XHR_SEND;
      const proto = w.XMLHttpRequest && w.XMLHttpRequest.prototype;
      const wrappedSend = proto && proto.send;
      if (proto && typeof rawSend === "function" && typeof wrappedSend === "function" && wrappedSend !== rawSend) {
        const origSetHeader = proto.setRequestHeader;
        if (typeof origSetHeader === "function" && !origSetHeader.__brokenappSseWrapped) {
          const wrappedSetHeader = function(name, value) {
            try {
              if (String(name || "").toLowerCase() === "accept"
                  && String(value || "").toLowerCase().includes("text/event-stream")) {
                this.__brokenappSse = true;
              }
            } catch (_) {}
            return origSetHeader.apply(this, arguments);
          };
          try { Object.defineProperty(wrappedSetHeader, "__brokenappSseWrapped", { value: true }); } catch (_) {}
          proto.setRequestHeader = wrappedSetHeader;
        }
        proto.send = function() {
          const url = this.__brokenappUrl ? String(this.__brokenappUrl) : "";
          if (this.__brokenappSse || isIgnoredUrl(url)) {
            return rawSend.apply(this, arguments);
          }
          return wrappedSend.apply(this, arguments);
        };
      }
    } catch (_) {}
    w.__BROKENAPP_STREAM_EXCLUDED = true;
  } catch (_) {}
  return true;
})()
"#;
    let params = cdp_page::AddScriptToEvaluateOnNewDocumentParams::builder()
        .source(POST_SCRIPT)
        .run_immediately(true)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    page.inner()
        .execute(params)
        .await
        .context("Page.addScriptToEvaluateOnNewDocument (settle exclusions post)")?;
    Ok(())
}

/// Run [`cdp_helpers::settle_page`] with a strict outer wall-clock ceiling so
/// stalled CDP `Runtime.evaluate` probes on busy multi-tab dev servers never
/// hang until the 78s page watchdog kills the visit.
async fn settle_page_bounded(page: &crate::browser::PageClient, timeout: Duration) {
    let ceiling = timeout.saturating_add(Duration::from_secs(8));
    if tokio::time::timeout(ceiling, cdp_helpers::settle_page(page, timeout))
        .await
        .is_err()
    {
        tracing::debug!(
            ceiling_ms = ceiling.as_millis() as u64,
            "settle_page hit outer wall-clock bound; continuing"
        );
    }
}

async fn settle_bounded(page: &crate::browser::PageClient, timeout: Duration) {
    let ceiling = timeout.saturating_add(Duration::from_secs(3));
    let _ = tokio::time::timeout(ceiling, cdp_helpers::settle(page, timeout)).await;
}

async fn close_page_bounded(page: &crate::browser::PageClient) {
    let _ = tokio::time::timeout(PAGE_CLOSE_TIMEOUT, page.inner().clone().close()).await;
}

/// In full mode (`!stop_on_convergence`), exempt explicitly declared fixture
/// seeds (`scan.seed_urls` and `scan.seed_routes_file`) from route-template
/// saturation so declared seed routes are never skipped.
fn register_pinned_seed_urls(cfg: &BrokenAppConfig, state: &mut RuntimeState) {
    if cfg.scan.stop_on_convergence {
        return;
    }
    let pinned: Vec<String> = state
        .seeded_route_sources
        .iter()
        .filter(|(_, sources)| {
            sources
                .iter()
                .any(|s| s == "scan.seed_urls" || s.starts_with("seed_routes_file:"))
        })
        .map(|(url, _)| url.clone())
        .collect();
    if !pinned.is_empty() {
        state.template_sampler.set_pinned_urls(pinned);
    }
}

/// Route templates whose instances share control identities: from the scan
/// config, else dynamic page routes discovered in `scan.codebase_path`.
fn source_route_templates(
    cfg: &BrokenAppConfig,
) -> crate::explorer::template_sampler::RouteTemplates {
    use crate::explorer::template_sampler::RouteTemplates;
    if !cfg.scan.route_templates.is_empty() {
        return RouteTemplates::new(&cfg.scan.route_templates);
    }
    let Some(codebase) = cfg.scan.codebase_path.as_deref() else {
        return RouteTemplates::default();
    };
    match crate::route_discovery::discover_routes(codebase) {
        Ok(discovery) => {
            let templates: Vec<String> = discovery
                .routes
                .iter()
                .filter(|r| r.dynamic && r.kind == "page")
                .map(|r| r.path.clone())
                .collect();
            let templates = RouteTemplates::new(&templates);
            tracing::debug!(
                framework = %discovery.framework,
                templates = ?templates,
                "route templates from source"
            );
            templates
        }
        Err(err) => {
            tracing::debug!(error = ?err, "route discovery for templates failed");
            RouteTemplates::default()
        }
    }
}

/// Element count a view is expected to have: the average of earlier
/// instances of its template, else the median of explored views (when
/// there are enough of them to say).
fn expected_element_count(state: &RuntimeState, template: Option<&str>) -> Option<usize> {
    if let Some(counts) = template.and_then(|t| state.template_element_counts.get(t))
        && !counts.is_empty()
    {
        return Some(counts.iter().sum::<usize>() / counts.len());
    }
    let counts = &state.view_element_counts;
    if counts.len() < 3 {
        return None;
    }
    let mut sorted = counts.clone();
    sorted.sort_unstable();
    Some(sorted[sorted.len() / 2])
}

/// `found` is far below `expected` (under 40%, with a meaningful expectation).
fn elements_far_below(found: usize, expected: usize) -> bool {
    expected >= 10 && found * 10 < expected * 4
}

/// Navigate the page back to `view_url` when it drifted (a control navigated
/// away). Returns whether the page shows the view afterwards.
pub(super) async fn restore_page_to_view_url(
    page: &crate::browser::PageClient,
    view_url: &str,
    cfg: &BrokenAppConfig,
    navigate_timeout: Duration,
) -> bool {
    let current_url = page.url().await.ok().flatten().unwrap_or_default();
    if view_urls_match_for_restore(&current_url, view_url) {
        return true;
    }

    tracing::debug!(
        current_url = %current_url,
        view_url = %view_url,
        "restoring page to the view URL"
    );

    if let Err(err) = page.goto_and_wait(view_url, navigate_timeout).await {
        tracing::debug!(
            error = ?err,
            view_url = %view_url,
            "failed to restore page to the view URL"
        );
        return false;
    }

    // The restored page re-initializes: let it load, and close on-load
    // overlays again before anything is clicked on it.
    let settle_timeout = Duration::from_millis(cfg.scan.settle_timeout_ms.max(500));
    settle_page_bounded(page, settle_timeout).await;
    if crate::dom::interaction::dismiss_blocking_overlays(page).await > 0 {
        settle_bounded(page, Duration::from_millis(700)).await;
    }
    let restored_url = page.url().await.ok().flatten().unwrap_or_default();
    view_urls_match_for_restore(&restored_url, view_url)
}

/// Time budget for re-loading a view URL (a cross-document restore can need
/// a full page load on slow dev servers).
fn restore_navigation_timeout(cfg: &BrokenAppConfig) -> Duration {
    Duration::from_millis(cfg.scan.settle_timeout_ms.max(500)).max(Duration::from_secs(10))
}

/// Identity of a view: route template plus finite UI query state and DOM skeleton.
fn view_identity_key(final_url: &str, fingerprint: &str) -> String {
    let scope = url_utils::ui_state_scope(interaction::route_scope(final_url), final_url);
    format!("{scope}|{fingerprint}")
}

pub(super) fn view_urls_match_for_restore(current_url: &str, final_url: &str) -> bool {
    let normalize = |raw: &str| -> Option<String> {
        let mut url = Url::parse(raw).ok()?;
        if !crate::explorer::url_utils::fragment_is_route(url.fragment()) {
            url.set_fragment(None);
        }
        Some(url.to_string())
    };

    match (normalize(current_url), normalize(final_url)) {
        (Some(current), Some(final_url)) => current == final_url,
        _ => current_url == final_url,
    }
}

async fn recheck_document_lang(page: &crate::browser::PageClient) -> Option<String> {
    const LANG_RECHECK_ATTEMPTS: usize = 12;
    const LANG_RECHECK_SETTLE_MS: u64 = 750;

    for attempt in 0..LANG_RECHECK_ATTEMPTS {
        let document_lang = page
            .evaluate_json::<String>(
                r#"
(() => {
  const root = document.documentElement;
  if (!root) return "";
  return String(root.getAttribute('lang') || root.getAttribute('xml:lang') || root.lang || '').trim();
})()
"#,
            )
            .await
            .ok()
            .map(|lang| lang.trim().to_string())
            .filter(|lang| !lang.is_empty());

        if document_lang.is_some() {
            return document_lang;
        }

        if attempt + 1 < LANG_RECHECK_ATTEMPTS {
            settle_bounded(page, Duration::from_millis(LANG_RECHECK_SETTLE_MS)).await;
        }
    }

    None
}

fn looks_like_non_html_document_path(path: &str) -> bool {
    [
        ".json", ".xml", ".rss", ".atom", ".txt", ".csv", ".pdf", ".zip", ".gz", ".tgz", ".tar",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
}

fn is_non_html_content_type(content_type: &str) -> bool {
    content_type.starts_with("image/")
        || content_type.starts_with("video/")
        || content_type.starts_with("audio/")
        || content_type.contains("font/")
        || content_type.contains("application/json")
        || content_type.contains("application/xml")
        || content_type.contains("text/xml")
        || content_type.contains("application/rss+xml")
        || content_type.contains("application/atom+xml")
        || content_type.contains("image/svg+xml")
        || content_type.contains("text/plain")
        || content_type.contains("text/csv")
        || content_type.contains("application/pdf")
        || content_type.contains("application/zip")
        || content_type.contains("application/octet-stream")
}

async fn record_session_expired_bug(bug_detector: &Arc<BugDetector>, max_attempts: usize) {
    bug_detector
        .record(Bug {
            id: String::new(),
            severity: BugSeverity::Critical,
            confidence: Some(0.99),
            category: BugCategory::Other {
                description: "Scan session expired and all re-authentication attempts failed"
                    .to_string(),
            },
            title: "Session expired — findings may be incomplete".to_string(),
            description: format!(
                "The authenticated session expired during scanning and {} re-authentication \
                 attempts all failed. Findings discovered after this point may be incomplete \
                 or reflect unauthenticated behavior.",
                max_attempts,
            ),
            remediation: Some(
                "Check auth credentials and increase token lifetime, or configure a \
                 refresh_token for automatic token renewal."
                    .to_string(),
            ),
            location: BugLocation {
                view: None,
                element: None,
                url: None,
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        })
        .await;
}

/// Incremental save: the checkpoint plus the scan artifacts so far.
pub(super) async fn save_progress(
    writer: &mut CheckpointWriter,
    cfg: &BrokenAppConfig,
    started_at: DateTime<Utc>,
    start_instant: Instant,
    state: &RuntimeState,
    network: &Arc<NetworkInterceptor>,
    bug_detector: &Arc<BugDetector>,
) -> Result<()> {
    let bugs = bug_detector.bugs_snapshot().await;
    let (checkpoint, outcome, run) =
        progress_artifacts(cfg, started_at, start_instant, state, network, bugs);
    write_progress_artifacts(writer, cfg, checkpoint, outcome, run).await
}

/// The checkpoint, scan outcome and run report of an incremental save,
/// built from a consistent view of the state (synchronous: callers may hold
/// the state lock).
fn progress_artifacts(
    cfg: &BrokenAppConfig,
    started_at: DateTime<Utc>,
    start_instant: Instant,
    state: &RuntimeState,
    network: &Arc<NetworkInterceptor>,
    mut bugs: Vec<Bug>,
) -> (ScanCheckpoint, ScanOutcome, super::run_report::RunReport) {
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
    bugs.sort_by(|a, b| a.id.cmp(&b.id));

    let crawl_seconds = start_instant.elapsed().as_secs();
    let checkpoint = build_checkpoint(
        cfg,
        started_at,
        crawl_seconds,
        state,
        endpoints.clone(),
        bugs.clone(),
    );

    tracing::info!(
        views = state.views.len(),
        endpoints = endpoints.len(),
        elements_discovered = state.elements_discovered,
        elements_interacted = state.elements_interacted,
        coverage_gaps = state.coverage_gaps.len(),
        queue_remaining = state.scheduler.len(),
        in_flight = state.ctl.in_flight,
        "scan progress"
    );

    let mut transitions = Vec::new();
    for t in &state.pending_transitions {
        let to_view = resolve_transition_target(state, &t.target_url);
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

    let views_discovered = state.url_to_view.len();
    let views_explored = state.views.len();
    let api_endpoints_discovered = endpoints.len();

    let outcome = ScanOutcome {
        started_at,
        finished_at: Utc::now(),
        scan_duration_seconds: crawl_seconds,
        completion_status: "running".to_string(),
        target_url: cfg.target.url.to_string(),
        output_dir: cfg.output.directory.clone(),
        network_log_path: if cfg.output.include_network_log {
            Some(cfg.output.directory.join("network.jsonl"))
        } else {
            None
        },
        views: state.views.clone(),
        template_sampler: state.template_sampler.clone(),
        transitions,
        endpoints,
        bugs,
        coverage: coverage::summarize(
            views_discovered,
            views_explored,
            state.elements_discovered,
            state.elements_interacted,
            api_endpoints_discovered,
        ),
        coverage_gaps: coverage::summarize_gaps(state.coverage_gaps.clone()),
    };
    let run = super::run_report::RunReport::build(
        cfg,
        super::run_report::RunFacts {
            status: "running",
            stop_reason: state.ctl.stop_reason,
            started_at,
            crawl_seconds,
            resumes: state.resumes,
            tabs: super::crawl_tab_count(cfg),
            views: state.views.len(),
            queue_remaining: state.scheduler.len(),
            session: &state.session_log,
        },
    );
    (checkpoint, outcome, run)
}

/// Write an incremental save: the checkpoint first (what a resume needs),
/// then the scan's core artifacts (`spec.json`, `bugs.json`,
/// `coverage-gaps.json`, `scan-status.json` with status `running`,
/// `scan-run.json`). The derived reports (exposure scan of `network.jsonl`,
/// summaries, reachability, consistency) are only written when the scan
/// ends: rebuilding them on every save would make a long crawl's saves
/// grow with everything it has seen so far.
async fn write_progress_artifacts(
    writer: &mut CheckpointWriter,
    cfg: &BrokenAppConfig,
    checkpoint: ScanCheckpoint,
    outcome: ScanOutcome,
    run: super::run_report::RunReport,
) -> Result<()> {
    writer.save(&checkpoint).await?;
    drop(checkpoint);
    let dir = &outcome.output_dir;
    let spec = crate::output::spec_generator::generate_spec(&outcome);
    output::write_json(&dir.join("spec.json"), &spec).await?;
    drop(spec);
    let bug_report = crate::output::bug_report::generate_bug_report(
        &outcome,
        &cfg.scan,
        cfg.auth.is_some(),
        None,
    );
    output::write_json(&dir.join("bugs.json"), &bug_report).await?;
    output::write_json(&dir.join("coverage-gaps.json"), &outcome.coverage_gaps).await?;
    output::write_json(
        &dir.join("scan-status.json"),
        &serde_json::json!({
            "status": outcome.completion_status.as_str(),
            "started_at": outcome.started_at,
            "finished_at": serde_json::Value::Null,
            "updated_at": outcome.finished_at,
            "duration_seconds": outcome.scan_duration_seconds,
            "target_url": outcome.target_url,
        }),
    )
    .await?;
    super::run_report::write_run_report(dir, &run).await?;
    Ok(())
}

pub(super) fn resolve_transition_target(state: &RuntimeState, target_url: &str) -> String {
    if let Some(to_view) = state.url_to_view.get(target_url) {
        return to_view.clone();
    }

    if let Some(template) = crate::explorer::template_sampler::url_to_template_path(target_url) {
        if state.template_sampler.templates.contains_key(&template) {
            return crate::explorer::template_sampler::template_to_view_id(&template);
        }
    }

    "__unvisited__".to_string()
}

/// The checkpoint of the crawl so far. Visits in flight are left out: their
/// URLs go back in the queue (first) and their partial view state (the view
/// identity, sub-views, transitions, exercised controls, expanded nav
/// dropdowns) is dropped, so a resume explores those views from the start.
pub(super) fn build_checkpoint(
    cfg: &BrokenAppConfig,
    started_at: DateTime<Utc>,
    crawl_seconds: u64,
    state: &RuntimeState,
    mut endpoints: Vec<ApiEndpoint>,
    mut bugs: Vec<Bug>,
) -> ScanCheckpoint {
    endpoints.sort_by(|a, b| a.key.cmp(&b.key));
    bugs.sort_by(|a, b| a.id.cmp(&b.id));

    let in_flight_views = state.in_flight_view_ids();
    let in_flight_keys: std::collections::HashSet<&str> = state
        .ctl
        .in_flight_visits
        .values()
        .filter_map(|v| v.view_key.as_deref())
        .collect();
    let partial = |view_id: &str| in_flight_views.contains(super::base_view_id(view_id));

    let mut queue = state.scheduler.queue_snapshot();
    let mut queued_urls = state.scheduler.queued_urls_snapshot();
    for visit in state.ctl.in_flight_visits.values() {
        let canonical = url_utils::canonicalize_crawl_url(&visit.item.url);
        if !queue.iter().any(|q| q.url == canonical) {
            queue.push(QueuedUrl {
                url: canonical.clone(),
                depth: visit.item.depth,
                priority: 0,
            });
        }
        if !queued_urls.contains(&canonical) {
            queued_urls.push(canonical);
        }
    }
    let mut visited_fingerprints = state
        .visited_fingerprints
        .iter()
        .filter(|key| !in_flight_keys.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let mut expanded_nav_dropdown_triggers = state
        .expanded_nav_dropdown_triggers
        .iter()
        .filter(|key| key.split_once("::").is_none_or(|(view, _)| !partial(view)))
        .cloned()
        .collect::<Vec<_>>();
    queued_urls.sort();
    visited_fingerprints.sort();
    expanded_nav_dropdown_triggers.sort();

    // Make checkpoint output stable-ish.
    queue.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.depth.cmp(&b.depth))
            .then_with(|| a.url.cmp(&b.url))
    });

    let mut exercised_controls: Vec<crate::output::checkpoint::ExercisedControlEntry> = state
        .exercised_controls
        .iter()
        .filter(|(_, c)| !c.claimed && !partial(&c.view_id))
        .map(
            |(key, c)| crate::output::checkpoint::ExercisedControlEntry {
                key: key.clone(),
                view_id: c.view_id.clone(),
                navigated: c.navigated,
            },
        )
        .collect();
    exercised_controls.sort();
    let mut navigation_retries: Vec<String> = state.navigation_retries.iter().cloned().collect();
    navigation_retries.sort();
    let mut attempted_urls: Vec<String> = state.attempted_urls.iter().cloned().collect();
    attempted_urls.sort();
    let crawl = crate::output::checkpoint::CrawlResumeState {
        crawl_seconds,
        resumes: state.resumes,
        seeded_route_sources: state.seeded_route_sources.clone(),
        attempted_urls,
        navigation_retries,
        exercised_controls,
        template_instances: state
            .template_instances
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        session: state.session_log.clone(),
    };

    let mut checkpoint = ScanCheckpoint {
        schema: crate::output::schema::scan_checkpoint_v1(),
        version: 2,
        saved_at: Utc::now(),
        started_at,
        config: cfg.clone(),
        queue,
        queued_urls,
        visited_fingerprints,
        fingerprint_to_view: state.fingerprint_to_view.clone(),
        url_to_view: state.url_to_view.clone(),
        views: state
            .views
            .iter()
            .filter(|v| !partial(&v.id))
            .cloned()
            .collect(),
        pending_transitions: state
            .pending_transitions
            .iter()
            .filter(|t| !partial(&t.from_view))
            .cloned()
            .collect(),
        expanded_nav_dropdown_triggers,
        template_sampler: state.template_sampler.clone(),
        endpoints,
        bugs,
        elements_discovered: state.elements_discovered,
        elements_interacted: state.elements_interacted,
        coverage_gaps: state.coverage_gaps.clone(),
        crawl,
        integrity: crate::output::checkpoint::CheckpointIntegrity {
            hash_algorithm: "blake3".to_string(),
            state_hash: String::new(),
        },
    };
    match crate::output::checkpoint::state_hash_for_checkpoint(&checkpoint) {
        Ok(hash) => checkpoint.integrity.state_hash = hash,
        Err(err) => {
            tracing::warn!(error = ?err, "failed to compute checkpoint integrity hash");
        }
    }
    checkpoint
}

fn derive_on_load_api_calls(network: &Arc<NetworkInterceptor>, view_id: &str) -> Vec<EndpointKey> {
    let endpoints = network.endpoints_snapshot();
    let mut out: Vec<EndpointKey> = Vec::new();
    for ep in endpoints {
        if !crate::network::filters::is_application_api(&ep) {
            continue;
        }
        if ep
            .triggered_by
            .iter()
            .any(|t| t.view == view_id && t.selector == "__page_load__")
        {
            out.push(ep.key.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrameworkSignals {
    react_hook: bool,
    vue_hook: bool,
    angular: bool,
    next: bool,
    nuxt: bool,
    remix: bool,
    astro: bool,
    gatsby: bool,
    qwik: bool,
    ember: bool,
}

fn infer_framework_name(signals: &FrameworkSignals) -> Option<&'static str> {
    if signals.next {
        return Some("Next.js");
    }
    if signals.nuxt {
        return Some("Nuxt");
    }
    if signals.remix {
        return Some("Remix");
    }
    if signals.astro {
        return Some("Astro");
    }
    if signals.gatsby {
        return Some("Gatsby");
    }
    if signals.qwik {
        return Some("Qwik");
    }
    if signals.ember {
        return Some("Ember");
    }
    if signals.angular {
        return Some("Angular");
    }
    if signals.vue_hook {
        return Some("Vue");
    }
    if signals.react_hook {
        return Some("React");
    }
    None
}

async fn detect_framework(page: &crate::browser::PageClient) -> Result<Option<String>> {
    let script = r#"
(() => {
  const w = window;
  const d = document;
  const has = (sel) => {
    try { return !!d.querySelector(sel); } catch (_) { return false; }
  };

  return {
    reactHook: !!w.__REACT_DEVTOOLS_GLOBAL_HOOK__,
    vueHook: !!w.__VUE_DEVTOOLS_GLOBAL_HOOK__ || has('[data-v-app]'),
    angular: !!w.angular || !!(w.ng && w.ng.coreTokens) || has('[ng-version]'),
    next: !!w.__NEXT_DATA__
      || has('script#__NEXT_DATA__')
      || has('[data-nextjs-router]')
      || has('[data-nextjs-scroll-focus-boundary]'),
    nuxt: !!w.__NUXT__
      || !!w.$nuxt
      || has('#__nuxt')
      || has('[data-nuxt-data]'),
    remix: !!w.__remixManifest
      || !!w.__remixRouteModules
      || has('script[data-remix-run]')
      || has('script[type="module"][data-route-manifest]'),
    astro: !!w.Astro
      || has('astro-island')
      || has('script[type="module"][data-astro-exec]'),
    gatsby: !!w.___gatsby
      || !!w.___loader
      || has('#___gatsby'),
    qwik: !!w.qwikCityPlan
      || has('[q\\:container]'),
    ember: !!w.Ember
      || has('.ember-application')
      || has('[id^="ember"]')
  };
})()
"#;
    let signals: FrameworkSignals = page.evaluate_json(script).await?;
    Ok(infer_framework_name(&signals).map(str::to_string))
}

async fn write_view_screenshot(out_dir: &Path, view_id: &str, png: &[u8]) -> Result<String> {
    let dir = out_dir.join("screenshots");
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create {}", dir.display()))?;

    let name = sanitize_filename_component(view_id);
    let path = dir.join(format!("{name}.png"));
    crate::output::write_bytes_atomic(&path, png)
        .await
        .with_context(|| format!("write {}", path.display()))?;

    Ok(format!("screenshots/{name}.png"))
}

fn sanitize_filename_component(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "view".to_string()
    } else {
        out
    }
}

const VIEW_BUDGET_RESERVE: Duration = Duration::from_secs(8);
const PHASE_CLASSIFY_MAX: Duration = Duration::from_secs(6);
const PHASE_DISCOVERY_MAX: Duration = Duration::from_secs(12);
const PHASE_NAV_EXPAND_MAX: Duration = Duration::from_secs(8);
const PHASE_SCREENSHOT_MAX: Duration = Duration::from_secs(6);
const PHASE_A11Y_MAX: Duration = Duration::from_secs(6);

#[derive(Clone, Copy)]
struct ViewBudget {
    deadline: Instant,
}

impl ViewBudget {
    fn new(started_at: Instant, timeout: Duration) -> Self {
        Self {
            deadline: started_at + timeout,
        }
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    fn phase_timeout(&self, reserve: Duration, max: Duration) -> Option<Duration> {
        let remaining = self.remaining();
        if remaining <= reserve {
            return None;
        }
        Some(remaining.saturating_sub(reserve).min(max))
    }

    fn phase_deadline(&self, reserve: Duration) -> Instant {
        self.deadline.checked_sub(reserve).unwrap_or(self.deadline)
    }
}

type PhaseTracker = Arc<Mutex<&'static str>>;

fn set_phase(tracker: &PhaseTracker, phase: &'static str) {
    if let Ok(mut guard) = tracker.lock() {
        *guard = phase;
    }
}

fn phase_snapshot(tracker: &PhaseTracker) -> String {
    tracker
        .lock()
        .map(|p| p.to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn record_view_budget_skip(
    state: &mut RuntimeState,
    kind: crate::explorer::coverage::CoverageGapKind,
    url: &str,
    view_id: Option<&str>,
    phase: &str,
) {
    state
        .coverage_gaps
        .push(crate::explorer::coverage::CoverageGap {
            kind,
            target: url.to_string(),
            reason: format!("view_time_budget:{phase}"),
            context: view_id.map(|v| v.to_string()),
        });
}

/// Smallest explicit `scan.view_budget_seconds` honoured.
const MIN_VIEW_BUDGET: Duration = Duration::from_secs(10);

fn page_watchdog_timeout_for_url(cfg: &BrokenAppConfig, url: &str) -> Duration {
    // An explicit per-view budget (full runs over rich views) is used as is.
    if cfg.scan.view_budget_seconds > 0 {
        return Duration::from_secs(cfg.scan.view_budget_seconds).max(MIN_VIEW_BUDGET);
    }
    // Hard-stop a single page visit so one hanging route cannot freeze the
    // entire scan/resume run. Keep this adaptive to configured interaction and
    // settle timings for slower pages.
    let settle_budget = settle_timeout_for_url(cfg, url).saturating_mul(4);
    let interaction_budget =
        Duration::from_millis(cfg.scan.interaction_timeout_ms).saturating_mul(8);
    let budget = Duration::from_secs(20)
        .saturating_add(settle_budget)
        .saturating_add(interaction_budget)
        .saturating_add(Duration::from_secs(10));
    budget
        .max(Duration::from_secs(45))
        .min(Duration::from_secs(180))
}

/// Longest a single view may take when little else is queued.
const MAX_ADAPTIVE_PAGE_TIMEOUT: Duration = Duration::from_secs(300);

/// The per-view watchdog, raised to a fair share of the remaining scan time
/// when few URLs are queued: a single-URL app (a wizard) is explored within
/// one view and would otherwise stop after a minute of a ten-minute budget.
fn adaptive_page_timeout(
    base: Duration,
    cfg: &BrokenAppConfig,
    start_instant: Instant,
    queued: usize,
    tabs: usize,
) -> Duration {
    if cfg.scan.max_duration_minutes == 0 || cfg.scan.view_budget_seconds > 0 {
        return base;
    }
    let budget = Duration::from_secs(cfg.scan.max_duration_minutes.saturating_mul(60));
    let remaining = budget.saturating_sub(start_instant.elapsed());
    // `tabs` views run at a time: the remaining time is shared by the rounds
    // it takes to work through the queue (this view included).
    let rounds = (queued + 1).div_ceil(tabs.max(1));
    let share = remaining / u32::try_from(rounds).unwrap_or(u32::MAX);
    base.max(share.min(MAX_ADAPTIVE_PAGE_TIMEOUT))
}

fn settle_timeout_for_url(cfg: &BrokenAppConfig, url: &str) -> Duration {
    let base = Duration::from_millis(cfg.scan.settle_timeout_ms);
    // Parameterized templates are exactly where we care about differentiating
    // data-driven layout variants. Spend a little more time letting them load.
    let is_parameterized = crate::explorer::template_sampler::url_to_template_path(url)
        .as_deref()
        .map(|t| t.contains(":id"))
        .unwrap_or(false);
    if is_parameterized {
        base.max(Duration::from_secs(8))
    } else {
        base
    }
}

/// Click nav dropdown buttons to reveal hidden links, then queue those links.
///
/// This runs **before** the interaction pass so the newly discovered nav links
/// get scheduled before any entity-page links that the interaction pass might
/// find. Each expansion is recorded in `interactions.jsonl`.
#[allow(clippy::too_many_arguments)]
async fn expand_nav_dropdowns(
    page: &crate::browser::PageClient,
    cfg: &BrokenAppConfig,
    network: &Arc<NetworkInterceptor>,
    bug_detector: &Arc<BugDetector>,
    interaction_log: Option<&InteractionLog>,
    base_url: &Url,
    current_url: Option<&Url>,
    scope_filter: Option<&ScopeFilter>,
    view_id: &str,
    view_url: &str,
    current_depth: usize,
    elements: &[crate::types::dom::InteractiveElement],
    shared: &SharedState<'_>,
) {
    use crate::types::dom::ElementType;

    let max = cfg.scan.exploration.max_dropdown_expansions_per_view;
    if max == 0 {
        return;
    }

    // Collect nav dropdown buttons.
    let nav_dropdowns: Vec<&crate::types::dom::InteractiveElement> = elements
        .iter()
        .filter(|el| matches!(&el.element_type, ElementType::DropdownMenu { in_nav: true }))
        .take(max)
        .collect();

    if nav_dropdowns.is_empty() {
        return;
    }

    // Collect normalized nav targets we already know about (to diff after expansion).
    let mut known_targets = interaction::link_targets(base_url, current_url, elements);

    let settle_timeout = Duration::from_millis(cfg.scan.settle_timeout_ms);
    let guard_active = interaction::write_guard_active(cfg);

    for dd in &nav_dropdowns {
        // Build a minimal InteractiveElement for clicking.
        let click_el = crate::types::dom::InteractiveElement {
            selector: dd.selector.clone(),
            label: dd.label.clone(),
            element_type: ElementType::Button { form_submit: false },
            interaction_result: None,
            source: None,
            found_on: view_id.to_string(),
            bounding_box: dd.bounding_box.clone(),
            snapshot: None,
            disabled: false,
            empty_required_fields_in_form: 0,
            locators: dd.locators.clone(),
        };

        // Click to open the dropdown.
        let exercise = interaction::exercise_with(
            page,
            cfg,
            network,
            bug_detector,
            view_id,
            view_url,
            &click_el,
            "click",
            interaction::per_interaction_budget(cfg),
            false,
        )
        .await;
        let not_attempted = exercise.not_attempted();
        let mut record = exercise.record;
        record.element_kind = interaction::element_kind_slug(&dd.element_type).to_string();
        if not_attempted {
            // Hidden or covered (e.g. a mobile-only menu at desktop width):
            // its row is written here, not again by the interaction pass.
            interaction::write_interaction_record(interaction_log, &record);
            super::lock_state(shared)
                .expanded_nav_dropdown_triggers
                .insert(format!("{view_id}::{}", dd.selector));
            continue;
        }
        let Some(obs) = exercise.observation else {
            if exercise.timed_out {
                record.outcome = crate::output::interactions::InteractionOutcome::Error;
                record.error = Some("interaction_timeout".to_string());
            }
            tracing::debug!(
                selector = %dd.selector,
                label = ?dd.label,
                "nav dropdown click did not complete"
            );
            interaction::write_interaction_record(interaction_log, &record);
            continue;
        };
        interaction::apply_observation(&mut record, &obs, &exercise.capture, guard_active);
        let _ = cdp_helpers::settle(page, settle_timeout).await;

        // Track the current URL for this dropdown expansion in case the click
        // triggered a client-side route change.
        let refreshed_current_url = page
            .url()
            .await
            .ok()
            .flatten()
            .and_then(|u| Url::parse(&u).ok());
        let refreshed_current_url_ref = refreshed_current_url.as_ref().or(current_url);

        // Re-discover elements to find newly revealed links.
        let refreshed =
            match crate::dom::discover_interactive_elements(page, &view_id.to_string()).await {
                Ok(els) => els,
                Err(err) => {
                    tracing::debug!(error = ?err, "re-discovery after dropdown click failed");
                    interaction::write_interaction_record(interaction_log, &record);
                    continue;
                }
            };

        // Mark this trigger as expanded (used by coverage gap detection).
        let new_links = {
            let mut st = super::lock_state(shared);
            st.expanded_nav_dropdown_triggers
                .insert(format!("{view_id}::{}", dd.selector));
            enqueue_revealed_links(
                &mut st,
                cfg,
                base_url,
                refreshed_current_url_ref,
                scope_filter,
                view_id,
                current_depth,
                &mut known_targets,
                &refreshed,
            )
            .len()
        };
        if new_links > 0
            && record.outcome == crate::output::interactions::InteractionOutcome::NoEffect
        {
            record.outcome = crate::output::interactions::InteractionOutcome::DomChange;
        }
        if new_links > 0
            && record.outcome == crate::output::interactions::InteractionOutcome::DomChange
        {
            record.dom_change = Some("menu".to_string());
        }
        interaction::write_interaction_record(interaction_log, &record);

        tracing::info!(
            selector = %dd.selector,
            label = ?dd.label,
            new_links,
            "expanded nav dropdown"
        );

        // Close the dropdown: dispatch an Escape key event.
        let _ = page
            .evaluate_json::<serde_json::Value>(
                "document.activeElement && document.activeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }))",
            )
            .await;
        let _ = cdp_helpers::settle(page, Duration::from_millis(300)).await;
    }
}

/// Queue same-origin links in `found` whose targets are not in `known`:
/// links revealed by a click (nav dropdowns, off-canvas sidenavs, menus).
/// Records a navigation transition for each and returns the new link elements.
#[allow(clippy::too_many_arguments)]
fn enqueue_revealed_links<'e>(
    state: &mut RuntimeState,
    cfg: &BrokenAppConfig,
    base_url: &Url,
    current_url: Option<&Url>,
    scope_filter: Option<&ScopeFilter>,
    view_id: &str,
    current_depth: usize,
    known: &mut std::collections::HashSet<String>,
    found: &'e [crate::types::dom::InteractiveElement],
) -> Vec<&'e crate::types::dom::InteractiveElement> {
    let mut fresh = Vec::new();
    for el in found {
        let ElementType::NavigationLink {
            href: Some(href), ..
        } = &el.element_type
        else {
            continue;
        };
        let Some(target) = url_utils::normalize_href(base_url, current_url, href) else {
            continue;
        };
        let target_str = target.to_string();
        if !known.insert(target_str.clone()) {
            continue;
        }
        fresh.push(el);

        if crate::dom::heuristics::is_destructive_mutation_label(el.label.as_deref()) {
            state
                .coverage_gaps
                .push(crate::explorer::coverage::CoverageGap {
                    kind: crate::explorer::coverage::CoverageGapKind::Route,
                    target: target_str.clone(),
                    reason: "destructive_nav_link_skipped".to_string(),
                    context: Some(format!(
                        "{view_id} label={}",
                        el.label.as_deref().unwrap_or("(none)")
                    )),
                });
        } else if !state.url_to_view.contains_key(&target_str) {
            state.scheduler.enqueue_priority(
                target_str.clone(),
                current_depth + 1,
                0,
                base_url,
                scope_filter,
                cfg.scan.exploration.strategy,
                cfg.scan.exploration.novelty_scoring,
                false,
            );
        }
        state.pending_transitions.push(PendingTransition {
            from_view: view_id.to_string(),
            trigger: InteractionRef {
                view: view_id.to_string(),
                selector: el.selector.clone(),
            },
            trigger_locators: el.locators.clone(),
            transition_type: TransitionType::Navigation,
            target_url: target_str,
        });
    }
    fresh
}

fn record_seed_redirect_gap(
    state: &mut RuntimeState,
    base_url: &Url,
    requested: &str,
    landed: &str,
) {
    let requested_canonical = url_utils::canonicalize_crawl_url(requested);
    let landed_canonical = url_utils::canonicalize_crawl_url(landed);
    if requested_canonical == landed_canonical {
        return;
    }

    let route_template = Url::parse(&requested_canonical)
        .ok()
        .filter(|url| url_utils::same_origin(base_url, url))
        .map(|url| {
            let (route_path, _) = url_utils::effective_url_path_and_query(&url);
            crate::network::path_parameterizer::path_to_template(&route_path)
        })
        .unwrap_or_else(|| "(unknown)".to_string());

    if let Some(sources) = state.seeded_route_sources.get(&requested_canonical) {
        let reason = if looks_like_auth_gate_url(landed) {
            "seed_route_redirected_to_login"
        } else {
            "seed_route_redirected"
        };
        state
            .coverage_gaps
            .push(crate::explorer::coverage::CoverageGap {
                kind: crate::explorer::coverage::CoverageGapKind::SeededRoute,
                target: requested_canonical,
                reason: reason.to_string(),
                context: Some(format!(
                    "source={} route_template={} final_url={}",
                    sources.join(","),
                    route_template,
                    landed_canonical
                )),
            });
    } else if Url::parse(&requested_canonical)
        .ok()
        .is_some_and(|url| url_utils::same_origin(base_url, &url))
    {
        let reason = if looks_like_auth_gate_url(landed) {
            "route_redirected_to_login"
        } else {
            "route_redirected"
        };
        state
            .coverage_gaps
            .push(crate::explorer::coverage::CoverageGap {
                kind: crate::explorer::coverage::CoverageGapKind::Route,
                target: requested_canonical,
                reason: reason.to_string(),
                context: Some(format!(
                    "route_template={} final_url={}",
                    route_template, landed_canonical
                )),
            });
    }
}

fn is_seeded_route_visit(state: &RuntimeState, requested: &str, landed: &str) -> bool {
    let requested_canonical = url_utils::canonicalize_crawl_url(requested);
    let landed_canonical = url_utils::canonicalize_crawl_url(landed);
    state
        .seeded_route_sources
        .contains_key(&requested_canonical)
        || state.seeded_route_sources.contains_key(&landed_canonical)
}

fn final_url_is_outside_scope(base_url: &Url, scope_filter: &ScopeFilter, final_url: &str) -> bool {
    Url::parse(final_url)
        .ok()
        .filter(|url| url_utils::same_origin(base_url, url))
        .is_some_and(|url| !scope_filter.allows_path(url.as_str()))
}

fn looks_like_auth_gate_url(url: &str) -> bool {
    let path = Url::parse(url)
        .ok()
        .map(|u| {
            url_utils::effective_url_path_and_query(&u)
                .0
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|| url.to_ascii_lowercase());
    let auth_markers = [
        "login",
        "log-in",
        "signin",
        "sign-in",
        "auth",
        "oauth",
        "sso",
        "unauthorized",
        "forbidden",
    ];
    auth_markers.iter().any(|marker| path.contains(marker))
}

/// Detect when navigation to `requested` landed on `landed` due to a locale
/// prefix redirect (e.g. `/products/` → `/ar/products/`).
///
/// Returns `Some(redirect_kind)` if the final URL has a locale-style path
/// prefix that the original did not.
fn detect_locale_redirect(requested: &str, landed: &str) -> Option<String> {
    let req = Url::parse(requested).ok()?;
    let land = Url::parse(landed).ok()?;

    // Only compare same-origin redirects.
    if req.scheme() != land.scheme() || req.host() != land.host() || req.port() != land.port() {
        return None;
    }

    let req_path = req.path();
    let land_path = land.path();

    // No redirect if paths are identical.
    if req_path == land_path {
        return None;
    }

    // Check if the landed path has a locale prefix that the requested path doesn't.
    // Locale prefixes match: /xx/ or /xx-XX/ (ISO 639 + optional region).
    if let Some(prefix_end) = extract_locale_prefix_end(land_path) {
        // The requested path should NOT already start with a locale prefix.
        if extract_locale_prefix_end(req_path).is_none() {
            // Verify the landed path is the locale-prefixed version of the requested path.
            // `prefix_end` points at the slash between locale and the rest of the path,
            // so slicing from there preserves the leading '/' in the remainder.
            let land_without_prefix = &land_path[prefix_end..];
            // Normalize: both may or may not have trailing slash.
            let req_normalized = req_path.trim_end_matches('/');
            let land_normalized = land_without_prefix.trim_end_matches('/');
            if req_normalized == land_normalized {
                return Some("locale".to_string());
            }
        }
    }

    None
}

/// If `path` starts with a locale segment, return the byte index where the
/// remainder path begins (preserving the leading slash in the remainder).
///
/// Examples:
/// - `/ar/foo`    => Some(3) (remainder: `/foo`)
/// - `/en-US/`    => Some(6) (remainder: `/`)
/// - `/en`        => Some(3) (remainder: ``)
/// - `/foo`       => None
fn extract_locale_prefix_end(path: &str) -> Option<usize> {
    // Path must start with `/`.
    let rest = path.strip_prefix('/')?;
    let seg_end = rest.find('/').unwrap_or(rest.len());
    let segment = &rest[..seg_end];
    if is_locale_tag(segment) {
        // Index just after `/<segment>` (points at the next slash, or end of string).
        Some(1 + segment.len())
    } else {
        None
    }
}

/// Check if a string matches a locale tag pattern: `xx` or `xx-XX` or `xxx-XX`.
fn is_locale_tag(s: &str) -> bool {
    let bytes = s.as_bytes();
    match bytes.len() {
        // e.g. "en", "ar", "fr"
        2 => bytes.iter().all(|b| b.is_ascii_alphabetic()),
        // e.g. "eng" (3-letter ISO 639-2)
        3 => bytes.iter().all(|b| b.is_ascii_alphabetic()),
        // e.g. "en-US", "fr-FR"
        5 => {
            bytes[0].is_ascii_alphabetic()
                && bytes[1].is_ascii_alphabetic()
                && bytes[2] == b'-'
                && bytes[3].is_ascii_alphabetic()
                && bytes[4].is_ascii_alphabetic()
        }
        // e.g. "eng-US"
        6 => {
            bytes[0].is_ascii_alphabetic()
                && bytes[1].is_ascii_alphabetic()
                && bytes[2].is_ascii_alphabetic()
                && bytes[3] == b'-'
                && bytes[4].is_ascii_alphabetic()
                && bytes[5].is_ascii_alphabetic()
        }
        _ => false,
    }
}

#[cfg(test)]
mod locale_redirect_tests {
    use super::*;

    #[test]
    fn same_layout_query_tabs_have_distinct_view_identities() {
        for route in ["/account", "/#/account"] {
            let profile = view_identity_key(&format!("http://x.test{route}"), "same-layout");
            let payout =
                view_identity_key(&format!("http://x.test{route}?tab=payout"), "same-layout");
            let payments =
                view_identity_key(&format!("http://x.test{route}?tab=payments"), "same-layout");
            assert_ne!(profile, payout);
            assert_ne!(payout, payments);
            assert_eq!(
                payout,
                view_identity_key(
                    &format!("http://x.test{route}?tab=payout&utm_source=mail&page=2"),
                    "same-layout"
                )
            );
        }
    }

    #[test]
    fn detects_locale_prefix_redirect() {
        let req = "https://example.com/products/";
        let land = "https://example.com/ar/products/";
        assert_eq!(detect_locale_redirect(req, land).as_deref(), Some("locale"));
    }

    #[test]
    fn detects_locale_prefix_redirect_no_trailing_slash() {
        let req = "https://example.com/products";
        let land = "https://example.com/ar/products";
        assert_eq!(detect_locale_redirect(req, land).as_deref(), Some("locale"));
    }

    #[test]
    fn detects_root_locale_redirect() {
        let req = "https://example.com/";
        let land = "https://example.com/en/";
        assert_eq!(detect_locale_redirect(req, land).as_deref(), Some("locale"));
    }

    #[test]
    fn does_not_flag_when_requested_already_has_locale_prefix() {
        let req = "https://example.com/en/products/";
        let land = "https://example.com/en/products/";
        assert_eq!(detect_locale_redirect(req, land), None);
    }

    #[test]
    fn does_not_flag_when_remainder_does_not_match_requested_path() {
        let req = "https://example.com/a";
        let land = "https://example.com/en/b";
        assert_eq!(detect_locale_redirect(req, land), None);
    }

    #[test]
    fn does_not_flag_cross_origin_redirects() {
        let req = "https://example.com/a";
        let land = "https://other.com/en/a";
        assert_eq!(detect_locale_redirect(req, land), None);
    }
}

#[cfg(test)]
mod broken_link_filter_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn scope_filter_for_test(routes: &[&str]) -> ScopeFilter {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scopes_path = tmp.path().join("scopes.toml");
        let routes_toml = routes
            .iter()
            .map(|route| format!("{route:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            &scopes_path,
            format!("[scope.test]\nroutes = [{routes_toml}]\n"),
        )
        .expect("write scope");
        crate::scope::load_scope_filter("test", Some(&scopes_path)).expect("load scope")
    }

    #[test]
    fn final_url_scope_guard_flags_same_origin_redirects_outside_scope() {
        let base = Url::parse("https://example.com/dashboard").unwrap();
        let scope = scope_filter_for_test(&["/reports"]);

        assert!(!final_url_is_outside_scope(
            &base,
            &scope,
            "https://example.com/reports?tab=cof"
        ));
        assert!(final_url_is_outside_scope(
            &base,
            &scope,
            "https://example.com/analytics"
        ));
        assert!(!final_url_is_outside_scope(
            &base,
            &scope,
            "https://other.example.com/analytics"
        ));
    }

    #[test]
    fn seeded_route_visit_matches_requested_or_landed_canonical_url() {
        let mut state = RuntimeState::new("https://example.com/dashboard".to_string());
        state.seeded_route_sources.insert(
            "https://example.com/clients".to_string(),
            vec!["scan.seed_urls".to_string()],
        );

        assert!(is_seeded_route_visit(
            &state,
            "https://example.com/clients",
            "https://example.com/clients"
        ));
        assert!(is_seeded_route_visit(
            &state,
            "https://example.com/clients?ignored=1",
            "https://example.com/clients"
        ));
        assert!(!is_seeded_route_visit(
            &state,
            "https://example.com/partners",
            "https://example.com/partners"
        ));
    }

    fn make_entry(
        url: &str,
        status: u16,
        mime: Option<&str>,
        is_api: Option<bool>,
    ) -> TrafficEntry {
        TrafficEntry {
            occurred_at: chrono::Utc::now(),
            trace: None,
            request: crate::types::api::HttpRequestLog {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: BTreeMap::new(),
                post_data: None,
            },
            response: Some(crate::types::api::HttpResponseLog {
                status,
                headers: BTreeMap::new(),
                mime_type: mime.map(|s| s.to_string()),
                body_snippet: None,
            }),
            failure: None,
            triggered_by: None,
            is_api,
            duration_ms: None,
            attribution: None,
        }
    }

    #[test]
    fn skips_external_static_asset_404() {
        let base = Url::parse("https://example.com").unwrap();
        let entry = make_entry(
            "https://img.youtube.com/vi/H_XMqRhLhic/hqdefault.jpg",
            404,
            Some("image/jpeg"),
            Some(false),
        );
        assert!(!should_record_broken_link(&entry, Some(&base)));
    }

    #[test]
    fn records_same_origin_static_asset_404_as_finding() {
        let base = Url::parse("https://example.com").unwrap();
        let entry = make_entry(
            "https://example.com/assets/logo.png",
            404,
            Some("image/png"),
            Some(false),
        );
        assert!(should_record_asset_load_failure(&entry, Some(&base)));
    }

    fn trace_with_initiator(initiator: Option<&str>) -> crate::types::api::RequestTrace {
        crate::types::api::RequestTrace {
            trace_id: "t".to_string(),
            cdp_request_id: "c".to_string(),
            page_id: None,
            frame_id: None,
            document_url: None,
            initiator_type: initiator.map(str::to_string),
            initiator_url: None,
            initiator_line_number: None,
            initiator_column_number: None,
            initiator_request_id: None,
            has_user_gesture: None,
            action_id: None,
        }
    }

    #[test]
    fn skips_browser_default_favicon_probe_404() {
        // Chrome auto-probes <origin>/favicon.ico on every navigation even when
        // the page references no icon (initiator "other"). A 404 there is not a
        // referenced-asset failure, so it must not be reported.
        let base = Url::parse("https://example.com").unwrap();
        let mut entry = make_entry(
            "https://example.com/favicon.ico",
            404,
            Some("text/html"),
            Some(false),
        );
        entry.trace = Some(trace_with_initiator(Some("other")));
        assert!(!should_record_asset_load_failure(&entry, Some(&base)));

        // Same probe without trace metadata: still a browser default, not a gap.
        let mut entry_no_trace = make_entry(
            "https://example.com/favicon.ico",
            404,
            Some("text/html"),
            Some(false),
        );
        entry_no_trace.trace = None;
        assert!(!should_record_asset_load_failure(
            &entry_no_trace,
            Some(&base)
        ));
    }

    #[test]
    fn records_page_referenced_favicon_404() {
        // A favicon explicitly linked by the page (initiator "parser") that 404s
        // IS a genuine referenced-asset failure and should still be reported.
        let base = Url::parse("https://example.com").unwrap();
        let mut entry = make_entry(
            "https://example.com/favicon.ico",
            404,
            Some("image/x-icon"),
            Some(false),
        );
        entry.trace = Some(trace_with_initiator(Some("parser")));
        assert!(should_record_asset_load_failure(&entry, Some(&base)));
    }

    #[test]
    fn records_action_triggered_api_404_as_finding() {
        let base = Url::parse("https://example.com").unwrap();
        let mut entry = make_entry(
            "https://example.com/api/users/123",
            404,
            Some("application/json"),
            Some(true),
        );
        entry.triggered_by = Some(InteractionRef {
            view: "view_0001".to_string(),
            selector: "#load-user".to_string(),
        });
        assert!(should_record_action_api_error(&entry, Some(&base)));
    }

    #[test]
    fn records_action_triggered_cross_origin_failure_as_finding() {
        let base = Url::parse("https://example.com").unwrap();
        let mut entry = make_entry("https://api.example-cdn.test/session", 0, None, Some(true));
        entry.response = None;
        entry.failure = Some("net::ERR_FAILED".to_string());
        entry.triggered_by = Some(InteractionRef {
            view: "view_0001".to_string(),
            selector: "#login".to_string(),
        });
        assert!(should_record_network_failure(&entry, Some(&base)));
    }

    #[test]
    fn skips_next_rsc_broken_links() {
        let base = Url::parse("https://supabase.com").unwrap();
        let entry = make_entry(
            "https://supabase.com/docs?_rsc=ikamf",
            404,
            Some("text/html"),
            Some(false),
        );
        assert!(!should_record_broken_link(&entry, Some(&base)));
    }

    #[test]
    fn records_same_origin_html_404() {
        let base = Url::parse("https://example.com").unwrap();
        let entry = make_entry(
            "https://example.com/missing",
            404,
            Some("text/html"),
            Some(false),
        );
        assert!(should_record_broken_link(&entry, Some(&base)));
    }

    #[test]
    fn skips_cross_origin_server_errors() {
        let base = Url::parse("https://app.example.com").unwrap();
        let entry = make_entry(
            "https://analytics.example.com/v1/t",
            503,
            Some("application/json"),
            Some(true),
        );
        assert!(!should_record_server_error(&entry, Some(&base)));
    }

    #[test]
    fn records_same_origin_server_errors() {
        let base = Url::parse("https://example.com").unwrap();
        let entry = make_entry(
            "https://example.com/api/orders/123",
            500,
            Some("application/json"),
            Some(true),
        );
        assert!(should_record_server_error(&entry, Some(&base)));
    }

    #[test]
    fn skips_image_mime_even_without_extension() {
        let base = Url::parse("https://example.com").unwrap();
        let entry = make_entry(
            "https://example.com/hero",
            404,
            Some("image/webp"),
            Some(false),
        );
        assert!(!should_record_broken_link(&entry, Some(&base)));
    }

    #[test]
    fn skips_a11y_for_json_documents() {
        assert!(!should_run_accessibility_audit_for_document(
            "https://example.com/schema.json",
            Some("application/json"),
            Some("PRE"),
        ));
    }

    #[test]
    fn skips_a11y_for_xml_documents() {
        assert!(!should_run_accessibility_audit_for_document(
            "https://example.com/rss.xml",
            Some("application/xml"),
            Some("rss"),
        ));
    }

    #[test]
    fn allows_a11y_for_html_pages() {
        assert!(should_run_accessibility_audit_for_document(
            "https://example.com/docs/button",
            Some("text/html"),
            Some("HTML"),
        ));
    }

    #[test]
    fn drops_missing_lang_when_recheck_finds_document_lang() {
        let findings = vec![
            RawA11yResult {
                category: "missing_lang".to_string(),
                selector: Some("html".to_string()),
                description: "Document missing lang attribute".to_string(),
            },
            RawA11yResult {
                category: "missing_title".to_string(),
                selector: Some("head > title".to_string()),
                description: "Page has no title or empty title".to_string(),
            },
        ];

        let filtered = drop_missing_lang_findings_if_lang_present(findings, Some("en-US"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].category, "missing_title");
    }

    #[test]
    fn keeps_missing_lang_when_recheck_is_still_empty() {
        let findings = vec![RawA11yResult {
            category: "missing_lang".to_string(),
            selector: Some("html".to_string()),
            description: "Document missing lang attribute".to_string(),
        }];

        let filtered = drop_missing_lang_findings_if_lang_present(findings, Some("  "));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].category, "missing_lang");
    }

    #[test]
    fn view_identity_keeps_routes_that_share_a_layout() {
        let fp = "skeleton-hash";
        assert_ne!(
            view_identity_key("http://x.test/#/inbox", fp),
            view_identity_key("http://x.test/#/team", fp)
        );
        assert_ne!(
            view_identity_key("http://x.test/dashboard", fp),
            view_identity_key("http://x.test/settings", fp)
        );
        // Same route: entity instances, query variants and the hash-router root.
        assert_eq!(
            view_identity_key("http://x.test/products/1", fp),
            view_identity_key("http://x.test/products/2", fp)
        );
        assert_eq!(
            view_identity_key("http://x.test/search?q=a", fp),
            view_identity_key("http://x.test/search?q=b", fp)
        );
        assert_eq!(
            view_identity_key("http://x.test/", fp),
            view_identity_key("http://x.test/#/", fp)
        );
        assert_ne!(
            view_identity_key("http://x.test/#/inbox", fp),
            view_identity_key("http://x.test/#/inbox", "other-skeleton")
        );
    }

    #[test]
    fn view_restore_match_ignores_fragment_only_changes() {
        assert!(view_urls_match_for_restore(
            "https://example.com/path?x=1#section",
            "https://example.com/path?x=1",
        ));
    }

    #[test]
    fn view_restore_match_detects_navigation_changes() {
        assert!(!view_urls_match_for_restore(
            "https://example.com/login",
            "https://example.com/forgot-password",
        ));
    }

    #[tokio::test]
    async fn finalized_bug_count_reads_final_bug_report_items() {
        let tmp = tempfile::tempdir().expect("tempdir");
        tokio::fs::write(
            tmp.path().join("bugs.json"),
            serde_json::json!({
                "$schema": "https://brokenapp.dev/schemas/bug-report-v1.json",
                "tool_version": "test",
                "scan_date": "2026-06-01T00:00:00Z",
                "target_url": "https://example.test",
                "summary": {},
                "items": []
            })
            .to_string(),
        )
        .await
        .expect("write bugs report");

        assert_eq!(super::finalized_bug_count(tmp.path()).await, Some(0));
    }
}

#[cfg(test)]
mod framework_detection_tests {
    use super::{FrameworkSignals, infer_framework_name};

    #[test]
    fn prefers_next_over_generic_react() {
        let signals = FrameworkSignals {
            react_hook: true,
            next: true,
            ..FrameworkSignals::default()
        };
        assert_eq!(infer_framework_name(&signals), Some("Next.js"));
    }

    #[test]
    fn prefers_nuxt_over_generic_vue() {
        let signals = FrameworkSignals {
            vue_hook: true,
            nuxt: true,
            ..FrameworkSignals::default()
        };
        assert_eq!(infer_framework_name(&signals), Some("Nuxt"));
    }

    #[test]
    fn detects_astro_without_other_markers() {
        let signals = FrameworkSignals {
            astro: true,
            ..FrameworkSignals::default()
        };
        assert_eq!(infer_framework_name(&signals), Some("Astro"));
    }

    #[test]
    fn falls_back_to_react() {
        let signals = FrameworkSignals {
            react_hook: true,
            ..FrameworkSignals::default()
        };
        assert_eq!(infer_framework_name(&signals), Some("React"));
    }

    #[test]
    fn returns_none_when_no_markers_exist() {
        assert_eq!(infer_framework_name(&FrameworkSignals::default()), None);
    }
}

#[cfg(test)]
mod long_run_tests {
    use super::*;

    fn cfg(scan: &str) -> BrokenAppConfig {
        toml::from_str(&format!(
            "[target]\nurl = \"http://127.0.0.1:47280/\"\n\n[scan]\n{scan}\n"
        ))
        .expect("config")
    }

    #[test]
    fn explicit_view_budget_replaces_the_automatic_watchdog() {
        let auto = cfg("");
        let automatic = page_watchdog_timeout_for_url(&auto, "http://127.0.0.1:47280/");
        assert!(
            automatic >= Duration::from_secs(45) && automatic <= Duration::from_secs(180),
            "{automatic:?}"
        );

        let full = cfg("view_budget_seconds = 300\nmax_duration_minutes = 0");
        let budget = page_watchdog_timeout_for_url(&full, "http://127.0.0.1:47280/");
        assert_eq!(budget, Duration::from_secs(300), "not clamped to 180 s");
        // Neither the remaining-time share nor the 5-minute cap applies.
        assert_eq!(
            adaptive_page_timeout(budget, &full, Instant::now(), 0, 4),
            Duration::from_secs(300)
        );
        let long = cfg("view_budget_seconds = 900\nmax_duration_minutes = 600");
        assert_eq!(
            adaptive_page_timeout(
                page_watchdog_timeout_for_url(&long, "http://127.0.0.1:47280/"),
                &long,
                Instant::now(),
                0,
                1
            ),
            Duration::from_secs(900)
        );
        // Tiny budgets are raised to a workable minimum.
        let tiny = cfg("view_budget_seconds = 1");
        assert_eq!(
            page_watchdog_timeout_for_url(&tiny, "http://127.0.0.1:47280/"),
            MIN_VIEW_BUDGET
        );
    }

    #[test]
    fn automatic_watchdog_shares_the_remaining_time_but_unlimited_runs_keep_the_base() {
        let unlimited = cfg("max_duration_minutes = 0");
        let base = Duration::from_secs(60);
        assert_eq!(
            adaptive_page_timeout(base, &unlimited, Instant::now(), 0, 1),
            base
        );
        let ten = cfg("max_duration_minutes = 10");
        let one_url = adaptive_page_timeout(base, &ten, Instant::now(), 0, 1);
        assert_eq!(one_url, MAX_ADAPTIVE_PAGE_TIMEOUT);
        let busy = adaptive_page_timeout(base, &ten, Instant::now(), 500, 4);
        assert_eq!(busy, base);
    }

    #[test]
    fn saves_run_at_least_every_minute() {
        assert_eq!(save_interval(15, Duration::ZERO), Duration::from_secs(15));
        assert_eq!(save_interval(0, Duration::ZERO), Duration::from_secs(1));
        assert_eq!(save_interval(600, Duration::ZERO), MAX_SAVE_INTERVAL);
        assert_eq!(
            save_interval(15, Duration::from_secs(4)),
            Duration::from_secs(20)
        );
        assert_eq!(
            save_interval(15, Duration::from_secs(30)),
            MAX_SAVE_INTERVAL
        );
    }

    #[test]
    fn eta_has_no_budget_basis_for_unlimited_runs() {
        let unlimited = cfg("max_duration_minutes = 0\nmax_views = 0");
        assert!(estimate_scan_eta(&unlimited, 600, 50, 0, 50).is_none());
        let eta = estimate_scan_eta(&unlimited, 600, 50, 100, 50).expect("frontier eta");
        assert_eq!(eta.basis, "frontier_queue");
        assert_eq!(eta.seconds, 1200);
    }

    #[test]
    fn full_mode_pins_explicit_seeds_against_template_saturation() {
        let seeded = "http://127.0.0.1:47280/items/42";
        let from_file = "http://127.0.0.1:47280/items/43";
        let discovered = "http://127.0.0.1:47280/items/99";

        // Standard mode (`stop_on_convergence = true`) does not pin seeds.
        let standard = cfg("stop_on_convergence = true");
        let mut st = RuntimeState::new("http://127.0.0.1:47280/".to_string());
        st.seeded_route_sources
            .insert(seeded.to_string(), vec!["scan.seed_urls".to_string()]);
        st.seeded_route_sources.insert(
            from_file.to_string(),
            vec!["seed_routes_file:/tmp/seeds.txt".to_string()],
        );
        register_pinned_seed_urls(&standard, &mut st);
        assert!(!st.template_sampler.is_pinned(seeded));
        assert!(!st.template_sampler.is_pinned(from_file));

        // Full mode (`stop_on_convergence = false`) pins explicit seeds only.
        let full = cfg("stop_on_convergence = false");
        register_pinned_seed_urls(&full, &mut st);
        assert!(st.template_sampler.is_pinned(seeded));
        assert!(st.template_sampler.is_pinned(from_file));
        assert!(!st.template_sampler.is_pinned(discovered));
        assert!(st.template_sampler.has_pinned_for_template("/items/:id"));
    }

    #[test]
    fn prioritize_fresh_scan_seeds_orders_root_explicit_and_shallow_routes() {
        let mut config = cfg("seed_urls = [\"/special/deep\"]");
        config.scan.exploration.strategy = crate::config::ExplorationStrategy::BreadthFirst;
        let base = Url::parse("http://127.0.0.1:47280/").unwrap();
        let mut st = RuntimeState::new(base.to_string());
        for seed in [
            "http://127.0.0.1:47280/special/deep",
            "http://127.0.0.1:47280/staff/administration/warehouse-stations",
            "http://127.0.0.1:47280/clients",
            "http://127.0.0.1:47280/orders",
            "http://127.0.0.1:47280/",
        ] {
            st.scheduler.enqueue_priority(
                seed.to_string(),
                0,
                0,
                &base,
                None,
                config.scan.exploration.strategy,
                false,
                false,
            );
        }
        prioritize_fresh_scan_seeds(&config, &base, &mut st);
        let urls: Vec<String> = st
            .scheduler
            .queue_snapshot()
            .into_iter()
            .map(|q| q.url)
            .collect();
        assert_eq!(
            urls,
            vec![
                "http://127.0.0.1:47280/",
                "http://127.0.0.1:47280/special/deep",
                "http://127.0.0.1:47280/clients",
                "http://127.0.0.1:47280/orders",
                "http://127.0.0.1:47280/staff/administration/warehouse-stations",
            ]
        );
    }

    #[test]
    fn prioritize_fresh_scan_seeds_applies_deprioritize_routes_from_config() {
        let mut config =
            cfg("seed_urls = [\"/ops\"]\ndeprioritize_routes = [\"/pricing\", \"/privacy\"]");
        config.scan.exploration.strategy = crate::config::ExplorationStrategy::BreadthFirst;
        let base = Url::parse("http://127.0.0.1:47280/").unwrap();
        let mut st = RuntimeState::new(base.to_string());
        for seed in [
            "http://127.0.0.1:47280/pricing",
            "http://127.0.0.1:47280/privacy",
            "http://127.0.0.1:47280/ops",
            "http://127.0.0.1:47280/dashboard",
            "http://127.0.0.1:47280/",
        ] {
            st.scheduler.enqueue_priority(
                seed.to_string(),
                0,
                0,
                &base,
                None,
                config.scan.exploration.strategy,
                false,
                false,
            );
        }
        prioritize_fresh_scan_seeds(&config, &base, &mut st);
        let urls: Vec<String> = st
            .scheduler
            .queue_snapshot()
            .into_iter()
            .map(|q| q.url)
            .collect();
        assert_eq!(
            urls,
            vec![
                "http://127.0.0.1:47280/",
                "http://127.0.0.1:47280/ops",
                "http://127.0.0.1:47280/dashboard",
                "http://127.0.0.1:47280/pricing",
                "http://127.0.0.1:47280/privacy",
            ]
        );
    }
}
