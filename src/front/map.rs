//! `brokenapp map`: scan the running app and refresh the UI map.
//!
//! Flow: preflight (protected? local URL? reachable?) → start the dev server
//! when needed (own process group) → discover routes from source → warm every
//! seeded route with a GET (cold dev compiles) → run `brokenapp scan` as a
//! subprocess with a generated config (write guard on, seeded routes, route
//! templates, budgets, crawl knobs) → build the inventory while the server is
//! still up → stop the server if we started it → save history, diff, write
//! map files and changelog → update the registry → print a summary (with
//! `--json`, always a JSON object, including on failure).
//!
//! `--changed` maps incrementally: it finds the files changed since the
//! latest map ([`super::changed`]), the routes they affect
//! ([`super::impact`]), re-crawls only those routes, and merges the result
//! into the latest map ([`crate::inventory::merge_incremental`]). It skips
//! the scan when no route is affected and falls back to a whole-app map
//! (with the active budget) when the change is app-wide.
//!
//! Roles: `map` maps the anonymous (logged-out) app and every configured
//! `[[roles]]` login type, each as its own scan subprocess with its own
//! `[auth]` (secrets as `env:` references; values only in the subprocess
//! environment), its own map under `map/roles/<role>/` and its own history.
//! The guarded engine authenticates each role; a role
//! whose login fails or whose credentials are missing is reported and
//! skipped while the others continue. `ROLE-ACCESS.md` compares them.
//!
//! Full mode (`--full`, `[scan] mode = "full"`) removes time/view caps and
//! raises per-view control budgets; runs can take hours. Progress goes to stderr and
//! `map-progress.json`; the dev server is restarted if it dies; an
//! interrupted run is continued with `map --resume`.
//!
//! Run layout: `.brokenapp/scans/<ts>/` holds `run.json` (the run manifest),
//! `scan.toml`, `seed-routes.txt`, `progress.json`, `map-progress.json`,
//! `dev-server.log`, `scan.json` (the scan's JSON summary) and the raw scan
//! artifacts in `scan/` for the anonymous role, and the same files under
//! `roles/<role>/` for each configured role.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Args;
use futures::StreamExt;
use serde::Serialize;
use serde_json::Value;
use tokio::io::AsyncReadExt;
use url::Url;

use super::changed::{self, ChangedFiles};
use super::impact::{self, AffectedRoute, Impact, UnmappedFile};
use super::locality;
use super::process::{DevSpec, DevSupervisor, ManagedChild, StopReport, resolve_dev_env};
use super::project::{
    self, ANONYMOUS_ROLE, ProjectCtx, ProjectTarget, Registry, RolePaths, ScanMode,
};
use super::role_access;
use super::roles::{self, Redactor, ResolvedRole, RoleMethod};
use super::run_state::{RunManifest, RunRole, RunSettings, RunStatus};
use super::scan_facts::{self, InteractionTally, ScanFacts};
use super::secrets;
use super::warmup::{self, WarmupReport};
use crate::inventory::{
    self, ChangeSet, ControlStatus, CoverageSummary, IDENTITY_VERSION, Inventory, MergeOptions,
    Merged,
};
use crate::route_discovery::{self, RouteDiscovery};

#[derive(Debug, Args)]
pub struct MapArgs {
    /// Only these routes (repeatable); default: whole app. When a whole-app
    /// map already exists, the re-crawled routes merge into it unless
    /// `--no-merge` is set.
    #[arg(long = "route")]
    pub routes: Vec<String>,
    /// With --route: save only a standalone partial inventory instead of
    /// merging into the existing whole-app map.
    #[arg(long, requires = "routes")]
    pub no_merge: bool,
    /// Map the whole app: no time/view caps and larger per-view budgets.
    /// Can take hours. Same as `--mode full`.
    #[arg(long, conflicts_with_all = ["quick", "mode"])]
    pub full: bool,
    /// `standard` (bounded; default) or `full` (the whole app). Overrides [scan] mode.
    #[arg(long, value_name = "standard|full", conflicts_with = "quick")]
    pub mode: Option<String>,
    /// Map only this role (repeatable; `anonymous` = the logged-out app).
    /// Default: anonymous plus every configured role.
    #[arg(long = "role", value_name = "ROLE")]
    pub roles_only: Vec<String>,
    /// `all` (default: anonymous plus every configured role) or `none` (anonymous only).
    #[arg(long = "roles", value_name = "all|none", conflicts_with = "roles_only")]
    pub roles: Option<String>,
    /// Continue the last interrupted or budget-stopped `--full` map run with
    /// its settings: finished roles are kept, incomplete crawls resume from
    /// their checkpoint.
    #[arg(long, conflicts_with_all = ["changed", "routes", "quick", "full", "mode", "roles_only", "roles", "depth", "max_interactions", "view_budget"])]
    pub resume: bool,
    /// Re-crawl only the routes affected by files changed since the latest
    /// map (git, else file modification times) and merge them into it.
    #[arg(long, conflicts_with = "routes")]
    pub changed: bool,
    /// With --changed: changes since this git ref instead of the latest map's commit.
    #[arg(long, requires = "changed", value_name = "GIT_REF")]
    pub since: Option<String>,
    /// With --changed: map even when no route is affected (a whole-app map with the active budget).
    #[arg(long, requires = "changed")]
    pub force: bool,
    /// Browser tabs the crawler may use at once (overrides [scan] tabs; default 4).
    #[arg(long)]
    pub tabs: Option<usize>,
    /// Quick pass: small time/view budget.
    #[arg(long)]
    pub quick: bool,
    /// Max scan minutes (overrides config).
    #[arg(long)]
    pub max_minutes: Option<u64>,
    /// Max views (overrides config).
    #[arg(long)]
    pub max_views: Option<usize>,
    /// Revealed-UI nesting depth for modals/tabs/wizards (0-10; default 2 in standard, 4 in --full).
    #[arg(long, value_name = "N")]
    pub depth: Option<usize>,
    /// Max controls exercised per view before budget stop (1-1000; default 25 in standard, 1000 in --full).
    #[arg(long, value_name = "N")]
    pub max_interactions: Option<usize>,
    /// Per-view time budget in seconds (10-7200; default automatic in standard, 300 in --full).
    #[arg(long, value_name = "SECS")]
    pub view_budget: Option<u64>,
    /// Let state-changing requests through (only for disposable local backends).
    #[arg(long)]
    pub allow_writes: bool,
    /// Do not start the dev server; fail if the URL is not reachable.
    #[arg(long)]
    pub no_start: bool,
    /// Show the browser window.
    #[arg(long)]
    pub headed: bool,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

const QUICK_MAX_MINUTES: u64 = 3;
const QUICK_MAX_VIEWS: usize = 25;
const DEFAULT_TABS: usize = 4;
const MAX_TABS: usize = 16;
/// Standard mode scanner defaults (mirrored in [`ResolvedLimits`]).
const STANDARD_MAX_INTERACTION_DEPTH: usize = 2;
const STANDARD_MAX_INTERACTIONS_PER_VIEW: usize = 25;
const STANDARD_INTERACTIONS_PER_DEPTH: [usize; 3] = [25, 15, 10];
/// Full mode defaults (each overridable in `[scan]`).
const FULL_VIEW_BUDGET_SECONDS: u64 = 300;
const FULL_MAX_INTERACTION_DEPTH: usize = 4;
const FULL_PROGRESS_SECONDS: u64 = 60;
/// Full mode: stop only when no new page state was found for this long (a
/// crawl stuck in an endless generated-URL loop), not on coverage convergence.
const FULL_STAGNATION_MINUTES: u64 = 60;
/// Full mode: controls exercised inside revealed UI per depth (modal, step, ...).
const FULL_INTERACTIONS_PER_DEPTH: [usize; 4] = [MAX_INTERACTIONS_PER_VIEW, 250, 100, 50];
/// Full mode with a role `check` probe: verify the session every N views.
const FULL_CANARY_INTERVAL_VIEWS: u64 = 25;
const MIN_VIEW_BUDGET_SECONDS: u64 = 10;
const MAX_VIEW_BUDGET_SECONDS: u64 = 7200;
const MAX_HOURS: u64 = 720;
const MAX_ROLE_CONCURRENCY: usize = 8;
/// Concrete URLs seeded per affected dynamic route (`--changed`).
const MAX_SEEDS_PER_TEMPLATE: usize = 3;
/// Extra time the scan subprocess gets beyond its own budget (normalize,
/// artifact writing, optional store import) before `map` stops it.
const SCAN_FINALIZE_GRACE: Duration = Duration::from_secs(300);
const SCOPE_NAME: &str = "map";

/// What `map` decided before touching the app.
#[derive(Debug, Clone)]
struct MapPlan {
    url: Url,
    /// `standard` or `full`.
    mode: ScanMode,
    /// 0 = no time cap (full mode).
    max_minutes: u64,
    /// 0 = no view cap (full mode).
    max_views: usize,
    /// `block`, `stub`, or `off`.
    write_guard: String,
    headless: bool,
    /// `--route` values; empty for a whole-app map.
    only_routes: Vec<String>,
    /// With `--route`: skip merging into the existing whole-app map.
    no_merge: bool,
    /// True when this role's `--route` scan will merge into an existing map
    /// (keeps shell controls route-scoped so `merge_incremental` folds them).
    merge_partial: bool,
    /// Literal field overrides from `[scan.test_data]`, also reused on resume.
    test_data: BTreeMap<String, String>,
    /// Crawl knobs from `[scan]` (scanner defaults when unset).
    knobs: CrawlKnobs,
    /// Scope, identifying headers, pacing, and circuit-breaker knobs from `[scan]`.
    compliance: ComplianceKnobs,
    /// -> `scan.view_budget_seconds` (`None` = automatic).
    view_budget_seconds: Option<u64>,
    /// Full mode: endless-crawl guard and per-depth budgets.
    full: Option<FullKnobs>,
    /// Browser tabs (`--tabs`, `[scan] tabs`, default 4) -> `scan.max_concurrent_tabs`.
    tabs: usize,
    /// Roles mapped at once (`[scan] role_concurrency`, default 1).
    role_concurrency: usize,
    /// Fixed progress interval (full mode); `None` = print on change.
    progress_every: Option<Duration>,
    /// `--changed` re-crawl of the affected routes, merged into the latest map.
    incremental: Option<IncrementalPlan>,
}

/// Scanner settings only full mode emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FullKnobs {
    /// -> `scan.max_stagnation_minutes`
    stagnation_minutes: u64,
    /// -> `scan.exploration.max_interactions_per_depth`
    per_depth: [usize; 4],
}

impl Default for FullKnobs {
    fn default() -> Self {
        Self {
            stagnation_minutes: FULL_STAGNATION_MINUTES,
            per_depth: FULL_INTERACTIONS_PER_DEPTH,
        }
    }
}

/// What `--changed` decided to re-crawl.
#[derive(Debug, Clone)]
struct IncrementalPlan {
    latest: Inventory,
    discovery: RouteDiscovery,
    changed: ChangedFiles,
    impact: Impact,
    /// Inventory routes to re-crawl.
    routes: Vec<String>,
    /// Concrete paths to seed (dynamic routes: URLs the latest map visited).
    seeds: Vec<String>,
    /// Whole-app seeds: the re-crawl names routes like a whole-app map would.
    full_seeds: Vec<String>,
}

/// Optional crawler tuning from `[scan]` in `.brokenapp/config.toml` or CLI flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CrawlKnobs {
    /// -> `scan.exploration.max_interaction_depth`
    max_interaction_depth: Option<usize>,
    /// -> `scan.limits.max_interactions_per_view`
    max_interactions_per_view: Option<usize>,
    /// -> `scan.exploration.max_interactions_per_depth`
    max_interactions_per_depth: Option<Vec<usize>>,
    /// -> `scan.settle_timeout_ms`
    settle_ms: Option<u64>,
}

const MAX_INTERACTION_DEPTH: usize = 10;
const MAX_INTERACTIONS_PER_VIEW: usize = 1000;
const MAX_SETTLE_MS: u64 = 60_000;
const MAX_INTERACTION_DELAY_MS: u64 = 60_000;
const MAX_REQUESTS_PER_SECOND: f64 = 1000.0;
const DEFAULT_REMOTE_ABORT_ON_RATE_LIMITS: usize = 5;
const DEFAULT_REMOTE_ABORT_ON_ANTIBOT_CHALLENGES: usize = 2;

/// Compliance, scope, identifying headers, pacing, and circuit-breaker knobs
/// from `[scan]` in `.brokenapp/config.toml`.
#[derive(Debug, Clone, Default, PartialEq)]
struct ComplianceKnobs {
    /// -> `scan.extra_headers`
    extra_headers: BTreeMap<String, String>,
    /// -> `scan.user_agent`
    user_agent: Option<String>,
    /// -> `scan.allowed_hosts`
    allowed_hosts: Vec<String>,
    /// -> `scan.pacing.delay_between_interactions_ms`
    interaction_delay_ms: Option<u64>,
    /// -> `scan.pacing.max_requests_per_second`
    max_requests_per_second: Option<f64>,
    /// -> `scan.abort_on_rate_limits`
    abort_on_rate_limits: Option<usize>,
    /// -> `scan.abort_on_antibot_challenges`
    abort_on_antibot_challenges: Option<usize>,
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn compliance_knobs(scan: &project::ScanSection, config_path: &Path) -> Result<ComplianceKnobs> {
    let mut extra_headers = BTreeMap::new();
    for (raw_name, raw_val) in &scan.extra_headers {
        let name = raw_name.trim();
        if !is_valid_header_name(name) {
            bail!(
                "invalid scan.extra_headers header name {:?} in {}",
                raw_name,
                config_path.display()
            );
        }
        if raw_val.contains(['\r', '\n']) {
            bail!(
                "invalid scan.extra_headers value for {:?} in {} (newlines are not allowed)",
                name,
                config_path.display()
            );
        }
        extra_headers.insert(name.to_string(), raw_val.trim().to_string());
    }

    let user_agent = match scan.user_agent.as_deref().map(str::trim) {
        Some("") | None => None,
        Some(ua) if ua.contains(['\r', '\n']) => {
            bail!(
                "invalid scan.user_agent in {} (newlines are not allowed)",
                config_path.display()
            );
        }
        Some(ua) => Some(ua.to_string()),
    };

    let mut allowed_hosts = Vec::new();
    for raw_host in &scan.allowed_hosts {
        let host = raw_host.trim().to_ascii_lowercase();
        if host.is_empty()
            || host.contains("://")
            || host.contains('/')
            || host.chars().any(char::is_whitespace)
        {
            bail!(
                "invalid scan.allowed_hosts entry {:?} in {} (expected a hostname or *.domain pattern without scheme or path)",
                raw_host,
                config_path.display()
            );
        }
        if let Some(rest) = host.strip_prefix("*.") {
            if rest.is_empty() || rest.contains('*') || rest.starts_with('.') {
                bail!(
                    "invalid scan.allowed_hosts wildcard {:?} in {} (expected *.example.com)",
                    raw_host,
                    config_path.display()
                );
            }
        } else if host.contains('*') {
            bail!(
                "invalid scan.allowed_hosts entry {:?} in {} (wildcards are only allowed as a leading *. prefix)",
                raw_host,
                config_path.display()
            );
        }
        if !allowed_hosts.contains(&host) {
            allowed_hosts.push(host);
        }
    }

    if let Some(ms) = scan
        .interaction_delay_ms
        .filter(|ms| *ms > MAX_INTERACTION_DELAY_MS)
    {
        bail!(
            "scan.interaction_delay_ms = {ms} in {} is out of range (0-{MAX_INTERACTION_DELAY_MS})",
            config_path.display()
        );
    }

    if let Some(rps) = scan.max_requests_per_second
        && (!rps.is_finite() || rps <= 0.0 || rps > MAX_REQUESTS_PER_SECOND)
    {
        bail!(
            "scan.max_requests_per_second = {rps} in {} is out of range (>0 and <={MAX_REQUESTS_PER_SECOND})",
            config_path.display()
        );
    }

    let abort_on_rate_limits = scan.abort_on_rate_limits.or_else(|| {
        scan.allow_remote
            .then_some(DEFAULT_REMOTE_ABORT_ON_RATE_LIMITS)
    });
    let abort_on_antibot_challenges = scan.abort_on_antibot_challenges.or_else(|| {
        scan.allow_remote
            .then_some(DEFAULT_REMOTE_ABORT_ON_ANTIBOT_CHALLENGES)
    });

    Ok(ComplianceKnobs {
        extra_headers,
        user_agent,
        allowed_hosts,
        interaction_delay_ms: scan.interaction_delay_ms,
        max_requests_per_second: scan.max_requests_per_second,
        abort_on_rate_limits,
        abort_on_antibot_challenges,
    })
}

/// Validate the crawl knobs; out-of-range values are config errors.
fn crawl_knobs(scan: &project::ScanSection, config_path: &Path) -> Result<CrawlKnobs> {
    if let Some(depth) = scan
        .max_interaction_depth
        .filter(|d| *d > MAX_INTERACTION_DEPTH)
    {
        bail!(
            "scan.max_interaction_depth = {depth} in {} is too deep (0-{MAX_INTERACTION_DEPTH})",
            config_path.display()
        );
    }
    if let Some(n) = scan
        .max_interactions_per_view
        .filter(|n| *n == 0 || *n > MAX_INTERACTIONS_PER_VIEW)
    {
        bail!(
            "scan.max_interactions_per_view = {n} in {} is out of range (1-{MAX_INTERACTIONS_PER_VIEW})",
            config_path.display()
        );
    }
    if let Some(per_depth) = scan.max_interactions_per_depth.as_ref() {
        if per_depth.is_empty() || per_depth.len() > MAX_INTERACTION_DEPTH {
            bail!(
                "scan.max_interactions_per_depth in {} must have 1-{MAX_INTERACTION_DEPTH} entries (got {})",
                config_path.display(),
                per_depth.len()
            );
        }
        if let Some(&n) = per_depth
            .iter()
            .find(|&&n| n == 0 || n > MAX_INTERACTIONS_PER_VIEW)
        {
            bail!(
                "scan.max_interactions_per_depth entry {n} in {} is out of range (1-{MAX_INTERACTIONS_PER_VIEW})",
                config_path.display()
            );
        }
    }
    if let Some(ms) = scan.settle_ms.filter(|ms| *ms > MAX_SETTLE_MS) {
        bail!(
            "scan.settle_ms = {ms} in {} is out of range (0-{MAX_SETTLE_MS})",
            config_path.display()
        );
    }
    Ok(CrawlKnobs {
        max_interaction_depth: scan.max_interaction_depth,
        max_interactions_per_view: scan.max_interactions_per_view,
        max_interactions_per_depth: scan.max_interactions_per_depth.clone(),
        settle_ms: scan.settle_ms,
    })
}

impl MapPlan {
    /// A `--route` map (kept out of the whole-app history).
    fn partial(&self) -> bool {
        !self.only_routes.is_empty()
    }

    /// The crawl is limited to a route scope (`--route` or `--changed`).
    fn scoped(&self) -> bool {
        self.partial() || self.incremental.is_some()
    }
}

/// `--tabs`, else `[scan] tabs`, else 4; 1-16.
fn tabs(cfg_tabs: Option<usize>, flag: Option<usize>, config_path: &Path) -> Result<usize> {
    let tabs = flag.or(cfg_tabs).unwrap_or(DEFAULT_TABS);
    if tabs == 0 || tabs > MAX_TABS {
        bail!(
            "tabs = {tabs} is out of range (1-{MAX_TABS}; --tabs or scan.tabs in {})",
            config_path.display()
        );
    }
    Ok(tabs)
}

/// Refusals and budgets.
fn make_plan(ctx: &ProjectCtx, args: &MapArgs, registry: &Registry) -> Result<MapPlan> {
    let cfg = &ctx.config;
    if cfg.project.protected {
        bail!(
            "project '{}' is protected (project.protected = true in {}); `brokenapp map` refuses to scan it",
            ctx.name(),
            ctx.config_path.display()
        );
    }
    if let Some(entry) = registry_entry(registry, ctx).filter(|e| e.protected) {
        bail!(
            "project '{}' is marked protected in the registry ({}); `brokenapp map` refuses to scan it",
            entry.name,
            Registry::path().display()
        );
    }
    let url = locality::parse_target_url(&cfg.project.url, cfg.scan.allow_remote)?;

    let mode = scan_mode(cfg.scan.mode, args)?;
    let full = mode == ScanMode::Full;
    let (max_minutes, max_views) = if full {
        let minutes = match cfg.scan.max_hours {
            Some(0) | None => 0,
            Some(h) if h > MAX_HOURS => bail!(
                "scan.max_hours = {h} in {} is out of range (1-{MAX_HOURS}; leave it unset for no cap)",
                ctx.config_path.display()
            ),
            Some(h) => h * 60,
        };
        (
            args.max_minutes.unwrap_or(minutes),
            args.max_views.unwrap_or(0),
        )
    } else {
        budgets(
            cfg.scan.max_minutes,
            cfg.scan.max_views,
            args.quick,
            args.max_minutes,
            args.max_views,
        )
    };
    let view_budget_seconds = if let Some(s) = args.view_budget {
        if !(MIN_VIEW_BUDGET_SECONDS..=MAX_VIEW_BUDGET_SECONDS).contains(&s) {
            bail!(
                "--view-budget = {s} is out of range ({MIN_VIEW_BUDGET_SECONDS}-{MAX_VIEW_BUDGET_SECONDS})"
            );
        }
        Some(s)
    } else {
        match cfg.scan.view_budget_seconds {
            Some(0) => None,
            Some(s) if s > MAX_VIEW_BUDGET_SECONDS => bail!(
                "scan.view_budget_seconds = {s} in {} is out of range (1-{MAX_VIEW_BUDGET_SECONDS}; 0 = automatic)",
                ctx.config_path.display()
            ),
            Some(s) => Some(s),
            None if full && max_minutes > 0 => {
                Some(FULL_VIEW_BUDGET_SECONDS.min((max_minutes * 60 / 2).max(30)))
            }
            None if full => Some(FULL_VIEW_BUDGET_SECONDS),
            None => None,
        }
    };
    let role_concurrency = match cfg.scan.role_concurrency.unwrap_or(1) {
        0 => 1,
        n if n > MAX_ROLE_CONCURRENCY => bail!(
            "scan.role_concurrency = {n} in {} is out of range (1-{MAX_ROLE_CONCURRENCY})",
            ctx.config_path.display()
        ),
        n => n,
    };
    let progress_every = match cfg.scan.progress_seconds {
        Some(s) if !(5..=3600).contains(&s) => bail!(
            "scan.progress_seconds = {s} in {} is out of range (5-3600)",
            ctx.config_path.display()
        ),
        Some(s) => Some(Duration::from_secs(s)),
        None if full => Some(Duration::from_secs(FULL_PROGRESS_SECONDS)),
        None => None,
    };
    let mut knobs = crawl_knobs(&cfg.scan, &ctx.config_path)?;
    let compliance = compliance_knobs(&cfg.scan, &ctx.config_path)?;
    if let Some(depth) = args.depth {
        if depth > MAX_INTERACTION_DEPTH {
            bail!("--depth = {depth} is too deep (0-{MAX_INTERACTION_DEPTH})");
        }
        knobs.max_interaction_depth = Some(depth);
    }
    if let Some(n) = args.max_interactions {
        if n == 0 || n > MAX_INTERACTIONS_PER_VIEW {
            bail!("--max-interactions = {n} is out of range (1-{MAX_INTERACTIONS_PER_VIEW})");
        }
        knobs.max_interactions_per_view = Some(n);
    }
    if full {
        knobs.max_interaction_depth = knobs
            .max_interaction_depth
            .or(Some(FULL_MAX_INTERACTION_DEPTH));
        knobs.max_interactions_per_view = knobs
            .max_interactions_per_view
            .or(Some(MAX_INTERACTIONS_PER_VIEW));
    }
    let write_guard = if args.allow_writes {
        "off".to_string()
    } else {
        let mode = cfg.scan.write_guard.trim().to_ascii_lowercase();
        if !matches!(mode.as_str(), "block" | "stub" | "off") {
            bail!(
                "invalid scan.write_guard {:?} in {} (expected block, stub, or off)",
                cfg.scan.write_guard,
                ctx.config_path.display()
            );
        }
        mode
    };
    Ok(MapPlan {
        url,
        mode,
        max_minutes,
        max_views,
        write_guard,
        headless: cfg.scan.headless && !args.headed,
        only_routes: normalize_routes(&args.routes),
        no_merge: args.no_merge,
        merge_partial: false,
        test_data: cfg.scan.test_data.clone(),
        knobs,
        compliance,
        view_budget_seconds,
        full: full.then(FullKnobs::default),
        tabs: tabs(cfg.scan.tabs, args.tabs, &ctx.config_path)?,
        role_concurrency,
        progress_every,
        incremental: None,
    })
}

/// `--full` / `--mode` override `[scan] mode`; `--quick` is always standard.
fn scan_mode(cfg_mode: ScanMode, args: &MapArgs) -> Result<ScanMode> {
    if args.quick {
        return Ok(ScanMode::Standard);
    }
    if args.full {
        return Ok(ScanMode::Full);
    }
    match args.mode.as_deref() {
        Some(raw) => ScanMode::parse(raw)
            .with_context(|| format!("--mode {raw:?}: expected standard or full")),
        None => Ok(cfg_mode),
    }
}

fn registry_entry<'a>(
    registry: &'a Registry,
    ctx: &ProjectCtx,
) -> Option<&'a project::RegistryEntry> {
    registry
        .projects
        .iter()
        .find(|e| Path::new(&e.state_dir) == ctx.state_dir)
        .or_else(|| registry.find(ctx.name()))
}

/// `--quick` sets 3 minutes / 25 views; explicit flags override both.
fn budgets(
    cfg_minutes: u64,
    cfg_views: usize,
    quick: bool,
    flag_minutes: Option<u64>,
    flag_views: Option<usize>,
) -> (u64, usize) {
    let (minutes, views) = if quick {
        (QUICK_MAX_MINUTES, QUICK_MAX_VIEWS)
    } else {
        (cfg_minutes, cfg_views)
    };
    (flag_minutes.unwrap_or(minutes), flag_views.unwrap_or(views))
}

/// Trim, ensure a leading `/` (URLs kept as-is), de-duplicate, sort.
fn normalize_routes(routes: &[String]) -> Vec<String> {
    let set: BTreeSet<String> = routes
        .iter()
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .map(|r| {
            if r.starts_with('/') || r.starts_with("http://") || r.starts_with("https://") {
                r.to_string()
            } else {
                format!("/{r}")
            }
        })
        .collect();
    set.into_iter().collect()
}

fn is_excluded(route: &str, excludes: &[String]) -> bool {
    crate::scope::route_is_excluded(route, excludes)
}

/// Seeds for the scan: `--route` values, or discovered + extra routes; minus
/// excluded prefixes. Discovered sign-out/revoke pages (`/logout`) are never
/// seeded (visiting one can end the session or change server state); they
/// are returned separately for the report. Explicit `--route` and
/// `extra_routes` values are kept as given.
fn seed_routes(
    discovered: Vec<String>,
    extra: &[String],
    exclude: &[String],
    only: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut session_ending = Vec::new();
    let candidates: Vec<String> = if only.is_empty() {
        let (safe, unsafe_): (Vec<String>, Vec<String>) = discovered
            .into_iter()
            .partition(|r| !crate::safety::is_session_ending_url(r));
        session_ending = normalize_routes(&unsafe_);
        safe.into_iter().chain(extra.iter().cloned()).collect()
    } else {
        only.to_vec()
    };
    let seeds = normalize_routes(&candidates)
        .into_iter()
        .filter(|r| !is_excluded(r, exclude))
        .collect();
    session_ending.retain(|r| !is_excluded(r, exclude));
    (seeds, session_ending)
}

/// What `--changed` decided.
enum ChangedDecision {
    /// Nothing to crawl: report and exit.
    Skip(ChangedReport),
    /// A whole-app map (with the active budget: no previous map, an app-wide
    /// change, most routes, `--force`).
    Full(ChangedReport),
    /// Re-crawl the affected routes and merge them into the latest map.
    Incremental(Box<IncrementalPlan>, ChangedReport),
}

/// The `--changed` part of `map --json`.
#[derive(Debug, Clone, Default, Serialize)]
struct ChangedReport {
    /// `incremental`, `full` (whole-app crawl with active budget), or `skipped`.
    mode: String,
    /// Why a whole-app map ran, or why nothing was scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    mode_reason: Option<String>,
    /// `git` or `mtime`.
    #[serde(skip_serializing_if = "String::is_empty")]
    change_source: String,
    /// The commit (git) or time (mtime) changes are counted from.
    #[serde(skip_serializing_if = "String::is_empty")]
    change_base: String,
    /// Codebase-relative.
    changed_files: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deleted_files: Vec<String>,
    /// Routes picked for the re-crawl, each with why.
    affected_routes: Vec<AffectedRoute>,
    /// Changed files that map to no route (tests, docs, config, ...).
    unmapped_files: Vec<UnmappedFile>,
    /// Routes dropped because the file defining them was deleted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed_routes: Vec<String>,
    /// Affected routes re-crawled and merged into the map.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    recrawled_routes: Vec<String>,
    /// Affected routes the re-crawl did not reach or could not open; their
    /// entries are kept from the previous map.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kept_routes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    change_notes: Vec<String>,
}

impl ChangedReport {
    fn with_mode(mut self, mode: &str, reason: Option<String>) -> Self {
        self.mode = mode.to_string();
        self.mode_reason = reason;
        self
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Seeds added and route prefixes excluded for one role: `[scan]` lists
/// plus the role's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RouteLists {
    extra: Vec<String>,
    exclude: Vec<String>,
}

fn route_lists(ctx: &ProjectCtx, role: &str) -> RouteLists {
    let scan = &ctx.config.scan;
    let mut lists = RouteLists {
        extra: scan.extra_routes.clone(),
        exclude: scan.exclude_routes.clone(),
    };
    if let Some(r) = roles::find_role(&ctx.config, role) {
        lists.extra.extend(r.extra_routes.iter().cloned());
        lists.exclude.extend(r.exclude_routes.iter().cloned());
    }
    lists
}

fn only_defines_excluded_routes(
    file: &str,
    discovery: &RouteDiscovery,
    exclude: &[String],
) -> bool {
    let definitions: Vec<_> = discovery
        .routes
        .iter()
        .filter(|route| route.file == file)
        .collect();
    !definitions.is_empty()
        && definitions
            .iter()
            .all(|route| route.kind == "page" && is_excluded(&route.path, exclude))
}

/// Read the exact fixture values used by this role's latest scan. A missing
/// table in a valid older scan config means no overrides; a missing config does
/// not prove the old values were empty. Incremental inventories point to the
/// most recent scan, whose fixture values matched the retained baseline.
fn previous_test_data(latest: &Inventory) -> Result<BTreeMap<String, String>> {
    let run = Path::new(&latest.scan_dir)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .context("previous scan directory unavailable")?;
    let raw =
        std::fs::read_to_string(run.join("scan.toml")).context("read previous scan config")?;
    let config: toml::Table =
        toml::from_str(&raw).map_err(|_| anyhow::anyhow!("invalid previous scan config"))?;
    let scan = config
        .get("scan")
        .and_then(toml::Value::as_table)
        .context("previous scan settings unavailable")?;
    scan.get("test_data")
        .cloned()
        .unwrap_or_else(|| toml::Value::Table(toml::Table::new()))
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid previous test-data configuration"))
}

/// `--changed`: changed files -> affected routes -> skip, full, or a scoped
/// re-crawl. Needs no running app.
fn plan_changed(
    ctx: &ProjectCtx,
    paths: &RolePaths,
    routes: &RouteLists,
    args: &MapArgs,
    warnings: &mut Vec<String>,
) -> Result<ChangedDecision> {
    let full = |reason: String| {
        ChangedDecision::Full(ChangedReport::default().with_mode("full", Some(reason)))
    };
    let Some(latest) = load_previous(&paths.latest_inventory_path(), warnings) else {
        return Ok(full("no previous map to update".to_string()));
    };
    if latest
        .routes
        .iter()
        .any(|r| is_excluded(&r.route, &routes.exclude))
    {
        return Ok(full(
            "the previous map contains routes now excluded; rebuild the allowed coverage"
                .to_string(),
        ));
    }
    if latest.identity_version != IDENTITY_VERSION {
        return Ok(full(format!(
            "the previous map uses control identity v{} (now v{IDENTITY_VERSION})",
            latest.identity_version.max(1)
        )));
    }
    // Config lives in the excluded state directory. Compare the actual prior
    // scan inputs before source-file detection can decide that nothing changed.
    match previous_test_data(&latest) {
        Ok(previous) if previous == ctx.config.scan.test_data => {}
        Ok(_) => return Ok(full("scan.test_data changed since the previous map".into())),
        Err(_) => {
            return Ok(full(
                "previous scan.test_data unavailable; rebuild with current fixture values".into(),
            ));
        }
    }
    // The state dir may live inside the codebase; its own files are not changes.
    let exclude: Vec<String> = ctx
        .state_dir
        .strip_prefix(&ctx.root)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .into_iter()
        .collect();
    let changed = changed::detect(&ctx.root, &latest, args.since.as_deref(), &exclude)
        .context("find files changed since the previous map")?;
    for note in &changed.notes {
        eprintln!("--changed: {note}");
    }
    let discovery = route_discovery::discover_routes(&ctx.root).unwrap_or_else(|err| {
        let w = format!("route discovery failed: {err:#}");
        eprintln!("warning: {w}");
        warnings.push(w);
        RouteDiscovery::default()
    });
    // Discovery is shared by incremental role jobs. Keep it complete so one
    // role's exclusions cannot erase another role's source routes/templates.
    let mut allowed_discovery = discovery.clone();
    allowed_discovery
        .routes
        .retain(|r| !is_excluded(&r.path, &routes.exclude));
    let cfg = &ctx.config;
    let discovered_seeds = if cfg.scan.seed_from_source {
        route_discovery::seed_paths(&allowed_discovery)
    } else {
        Vec::new()
    };
    let (full_seeds, _) = seed_routes(discovered_seeds, &routes.extra, &routes.exclude, &[]);
    let impact = impact::analyze(
        &ctx.root,
        &changed,
        &latest,
        &allowed_discovery,
        &full_seeds,
    );
    let report = ChangedReport {
        change_source: changed.source.clone(),
        change_base: changed.base.clone(),
        changed_files: changed.files.iter().cloned().collect(),
        deleted_files: changed.deleted.iter().cloned().collect(),
        affected_routes: impact.affected_routes(),
        unmapped_files: impact.unmapped.clone(),
        removed_routes: impact.removed.iter().cloned().collect(),
        change_notes: changed.notes.clone(),
        ..Default::default()
    };
    let n = changed.files.len();
    if n == 0 {
        return Ok(if args.force {
            ChangedDecision::Full(report.with_mode("full", Some("--force".to_string())))
        } else {
            ChangedDecision::Skip(report.with_mode(
                "skipped",
                Some("no files changed since the previous map".to_string()),
            ))
        });
    }
    if let Some(reason) = &impact.full_reason {
        return Ok(ChangedDecision::Full(
            report.with_mode("full", Some(reason.clone())),
        ));
    }
    // The import graph and saved control sources are incomplete evidence:
    // e.g. a public script loaded by a <script src> has no module importer.
    // Missing route attribution cannot prove a changed source/style is unused,
    // even when other changed files do map to known routes. The only exception
    // is a route file whose every discovered definition is explicitly excluded.
    let unattributed: Vec<&str> = impact
        .unmapped
        .iter()
        .filter(|file| matches!(file.kind.as_str(), "source" | "style"))
        .filter(|file| !only_defines_excluded_routes(&file.file, &discovery, &routes.exclude))
        .map(|file| file.file.as_str())
        .collect();
    if !unattributed.is_empty() {
        return Ok(ChangedDecision::Full(report.with_mode(
            "full",
            Some(format!(
                "route impact is unknown for changed source or style files: {}",
                unattributed.join(", ")
            )),
        )));
    }
    if impact.affected.is_empty() {
        return Ok(if args.force {
            ChangedDecision::Full(report.with_mode(
                "full",
                Some(format!(
                    "--force: no UI routes affected by {n} changed file{}",
                    plural(n)
                )),
            ))
        } else {
            ChangedDecision::Skip(report.with_mode(
                "skipped",
                Some(format!(
                    "no UI routes affected by {n} changed file{}",
                    plural(n)
                )),
            ))
        });
    }

    let (recrawl, seeds, uncrawlable) =
        incremental_seeds(&impact, &latest, &allowed_discovery, &routes.exclude);
    for (route, why) in &uncrawlable {
        let w =
            format!("affected route {route} not re-crawled ({why}); kept from the previous map");
        eprintln!("warning: {w}");
        warnings.push(w);
    }
    if seeds.is_empty() {
        let reason = format!(
            "none of the {} affected route{} can be opened by the crawler",
            impact.affected.len(),
            plural(impact.affected.len())
        );
        return Ok(if args.force {
            ChangedDecision::Full(report.with_mode("full", Some(format!("--force: {reason}"))))
        } else {
            let mut report = report.with_mode("skipped", Some(reason));
            report.kept_routes = uncrawlable.iter().map(|(r, _)| r.clone()).collect();
            ChangedDecision::Skip(report)
        });
    }
    let mut report = report.with_mode("incremental", None);
    report.kept_routes = uncrawlable.into_iter().map(|(r, _)| r).collect();
    Ok(ChangedDecision::Incremental(
        Box::new(IncrementalPlan {
            latest,
            discovery,
            changed,
            impact,
            routes: recrawl,
            seeds,
            full_seeds,
        }),
        report,
    ))
}

/// Routes `--changed` can re-crawl, their concrete seeds, and the affected
/// routes it cannot open (with why). A dynamic route is seeded with the
/// pages of it the latest map visited.
fn incremental_seeds(
    impact: &Impact,
    latest: &Inventory,
    discovery: &RouteDiscovery,
    exclude: &[String],
) -> (Vec<String>, Vec<String>, Vec<(String, String)>) {
    let mut routes = Vec::new();
    let mut seeds: BTreeSet<String> = BTreeSet::new();
    let mut skipped = Vec::new();
    for route in impact.affected.keys() {
        if is_excluded(route, exclude) {
            skipped.push((route.clone(), "in scan.exclude_routes".to_string()));
            continue;
        }
        if crate::safety::is_session_ending_url(route) {
            skipped.push((route.clone(), "sign-out route".to_string()));
            continue;
        }
        let dynamic = route
            .split('/')
            .any(|seg| seg.starts_with(':') || seg.starts_with('*') || seg.starts_with('['));
        let found: Vec<String> = if dynamic {
            latest
                .routes
                .iter()
                .filter(|r| &r.route == route)
                .flat_map(|r| r.variants.iter())
                .filter(|v| v.starts_with('/'))
                .take(MAX_SEEDS_PER_TEMPLATE)
                .cloned()
                .collect()
        } else if discovery.trailing_slash
            && !route.ends_with('/')
            && !route.contains('#')
            && !route.rsplit('/').next().is_some_and(|s| s.contains('.'))
        {
            vec![format!("{route}/")]
        } else {
            vec![route.clone()]
        };
        if found.is_empty() {
            skipped.push((
                route.clone(),
                "dynamic route: the previous map visited no page of it".to_string(),
            ));
            continue;
        }
        routes.push(route.clone());
        seeds.extend(found);
    }
    (routes, seeds.into_iter().collect(), skipped)
}

/// Per-phase wall times of one `map` run, in milliseconds.
#[derive(Debug, Clone, Default, Serialize)]
struct Timings {
    /// `--changed`: finding changed files and affected routes.
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis_ms: Option<u64>,
    /// Starting the dev server until it answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    dev_server_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warmup_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_ms: Option<u64>,
    /// Building the inventory (link probe, source resolution).
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_ms: Option<u64>,
    /// Merge, diff, history, map files, changelog.
    #[serde(skip_serializing_if = "Option::is_none")]
    persist_ms: Option<u64>,
    total_ms: u64,
}

/// `map --changed --json` when nothing was scanned.
#[derive(Debug, Serialize)]
struct SkippedReport {
    exit_code: i32,
    status: String,
    project: String,
    url: String,
    message: String,
    note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    next: Vec<String>,
    #[serde(flatten)]
    changed: ChangedReport,
    /// Every role of the run (when roles are configured).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<RoleReport>,
    timings: Timings,
    warnings: Vec<String>,
}

/// Inputs for the generated scan config.
struct ScanToml<'a> {
    url: &'a Url,
    name: &'a str,
    headless: bool,
    max_minutes: u64,
    max_views: usize,
    write_guard: &'a str,
    write_guard_allow: &'a [String],
    output_dir: &'a Path,
    seed_routes_file: Option<&'a Path>,
    /// Explicit high-priority seeds (`scan.seed_urls`), e.g. a role's UI `--check` page.
    seed_urls: &'a [String],
    /// Routes already mapped under `anonymous` to place in a lower priority tier (`scan.deprioritize_routes`).
    deprioritize_routes: &'a [String],
    scope: Option<(&'a str, &'a Path)>,
    codebase: Option<&'a Path>,
    /// Dynamic route templates from source (`scan.route_templates`).
    route_templates: &'a [String],
    test_data: &'a BTreeMap<String, String>,
    knobs: CrawlKnobs,
    compliance: ComplianceKnobs,
    /// -> `scan.max_concurrent_tabs`
    tabs: usize,
    /// -> `scan.view_budget_seconds` (`None` = automatic).
    view_budget_seconds: Option<u64>,
    /// Full mode settings.
    full: Option<FullKnobs>,
    /// The role's `[auth]` table (`env:` references only, never values).
    auth: Option<&'a toml::Table>,
    /// The role's `[auth_contract]` table (`check` probe).
    auth_contract: Option<&'a toml::Table>,
    /// -> `scan.canary_interval_views` (full mode with a `check` probe).
    canary_interval_views: Option<u64>,
}

/// Generate the `brokenapp scan` TOML (schema: [`crate::config::BrokenAppConfig`]).
fn scan_config_toml(s: &ScanToml<'_>) -> Result<String> {
    use toml::Value as V;
    fn path(p: &Path) -> V {
        V::String(p.display().to_string())
    }
    fn int(n: u64) -> V {
        V::Integer(i64::try_from(n).unwrap_or(i64::MAX))
    }

    let mut target = toml::Table::new();
    target.insert("url".into(), V::String(s.url.to_string()));
    target.insert("name".into(), V::String(s.name.to_string()));
    target.insert("headless".into(), V::Boolean(s.headless));
    // Local dev servers often use self-signed certificates.
    target.insert(
        "ignore_https_errors".into(),
        V::Boolean(locality::is_local_url(s.url)),
    );

    let mut write_guard = toml::Table::new();
    write_guard.insert("mode".into(), V::String(s.write_guard.to_string()));
    if !s.write_guard_allow.is_empty() {
        write_guard.insert(
            "allow".into(),
            V::Array(
                s.write_guard_allow
                    .iter()
                    .map(|p| V::String(p.clone()))
                    .collect(),
            ),
        );
    }

    let mut scan = toml::Table::new();
    scan.insert("max_views".into(), int(s.max_views as u64));
    scan.insert("max_duration_minutes".into(), int(s.max_minutes));
    scan.insert("viewport_width".into(), int(1366));
    scan.insert("viewport_height".into(), int(900));
    scan.insert("max_concurrent_tabs".into(), int(s.tabs as u64));
    if let Some(file) = s.seed_routes_file {
        scan.insert("seed_routes_file".into(), path(file));
    }
    if !s.seed_urls.is_empty() {
        scan.insert(
            "seed_urls".into(),
            V::Array(s.seed_urls.iter().map(|u| V::String(u.clone())).collect()),
        );
    }
    if !s.deprioritize_routes.is_empty() {
        scan.insert(
            "deprioritize_routes".into(),
            V::Array(
                s.deprioritize_routes
                    .iter()
                    .map(|r| V::String(r.clone()))
                    .collect(),
            ),
        );
    }
    if let Some((name, file)) = s.scope {
        scan.insert("scope".into(), V::String(name.to_string()));
        scan.insert("scopes_file".into(), path(file));
    }
    if let Some(codebase) = s.codebase {
        scan.insert("codebase_path".into(), path(codebase));
    }
    if !s.route_templates.is_empty() {
        scan.insert(
            "route_templates".into(),
            V::Array(
                s.route_templates
                    .iter()
                    .map(|t| V::String(t.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(ms) = s.knobs.settle_ms {
        scan.insert("settle_timeout_ms".into(), int(ms));
    }
    if let Some(secs) = s.view_budget_seconds {
        scan.insert("view_budget_seconds".into(), int(secs));
    }
    if let Some(full) = s.full {
        // The whole app: end when the queue is exhausted, not on coverage
        // convergence; only an endless crawl (no new page state for an hour)
        // stops early.
        scan.insert(
            "max_stagnation_minutes".into(),
            int(full.stagnation_minutes),
        );
        scan.insert("stop_on_convergence".into(), V::Boolean(false));
    }
    if let Some(n) = s.canary_interval_views {
        scan.insert("canary_interval_views".into(), int(n));
    }
    let mut exploration = toml::Table::new();
    if let Some(depth) = s.knobs.max_interaction_depth {
        exploration.insert("max_interaction_depth".into(), int(depth as u64));
    }
    if let Some(per_depth) = s.knobs.max_interactions_per_depth.as_deref() {
        exploration.insert(
            "max_interactions_per_depth".into(),
            V::Array(per_depth.iter().map(|n| int(*n as u64)).collect()),
        );
    } else if let Some(full) = s.full {
        exploration.insert(
            "max_interactions_per_depth".into(),
            V::Array(full.per_depth.iter().map(|n| int(*n as u64)).collect()),
        );
    }
    if !exploration.is_empty() {
        scan.insert("exploration".into(), V::Table(exploration));
    }
    if let Some(n) = s.knobs.max_interactions_per_view {
        let mut limits = toml::Table::new();
        limits.insert("max_interactions_per_view".into(), int(n as u64));
        scan.insert("limits".into(), V::Table(limits));
    }
    if !s.compliance.allowed_hosts.is_empty() {
        scan.insert(
            "allowed_hosts".into(),
            V::Array(
                s.compliance
                    .allowed_hosts
                    .iter()
                    .map(|h| V::String(h.clone()))
                    .collect(),
            ),
        );
    }
    if !s.compliance.extra_headers.is_empty() {
        scan.insert(
            "extra_headers".into(),
            V::Table(
                s.compliance
                    .extra_headers
                    .iter()
                    .map(|(k, v)| (k.clone(), V::String(v.clone())))
                    .collect(),
            ),
        );
    }
    if let Some(ua) = s.compliance.user_agent.as_deref() {
        scan.insert("user_agent".into(), V::String(ua.to_string()));
    }
    if let Some(n) = s.compliance.abort_on_rate_limits.filter(|&n| n > 0) {
        scan.insert("abort_on_rate_limits".into(), int(n as u64));
    }
    if let Some(n) = s.compliance.abort_on_antibot_challenges.filter(|&n| n > 0) {
        scan.insert("abort_on_antibot_challenges".into(), int(n as u64));
    }
    let mut pacing = toml::Table::new();
    if let Some(ms) = s.compliance.interaction_delay_ms {
        pacing.insert("delay_between_interactions_ms".into(), int(ms));
    }
    if let Some(rps) = s.compliance.max_requests_per_second {
        pacing.insert("max_requests_per_second".into(), V::Float(rps));
    }
    if !pacing.is_empty() {
        scan.insert("pacing".into(), V::Table(pacing));
    }
    scan.insert("write_guard".into(), V::Table(write_guard));
    if !s.test_data.is_empty() {
        scan.insert(
            "test_data".into(),
            V::Table(
                s.test_data
                    .iter()
                    .map(|(name, value)| (name.clone(), V::String(value.clone())))
                    .collect(),
            ),
        );
    }

    let mut output = toml::Table::new();
    output.insert("directory".into(), path(s.output_dir));
    // network.jsonl carries per-click request attribution for the inventory.
    output.insert("include_network_log".into(), V::Boolean(true));
    output.insert("include_screenshots".into(), V::Boolean(false));

    let mut root = toml::Table::new();
    root.insert("target".into(), V::Table(target));
    if let Some(auth) = s.auth {
        root.insert("auth".into(), V::Table(auth.clone()));
    }
    if let Some(contract) = s.auth_contract {
        root.insert("auth_contract".into(), V::Table(contract.clone()));
    }
    root.insert("scan".into(), V::Table(scan));
    root.insert("output".into(), V::Table(output));
    let body = toml::to_string_pretty(&root).context("serialize scan config")?;
    Ok(format!(
        "# Generated by `brokenapp map` for this run. Edit .brokenapp/config.toml instead.\n{body}"
    ))
}

/// Scope of a scoped crawl: the `--route` values, or the routes `--changed`
/// re-crawls plus their concrete seeds.
fn scope_routes(plan: &MapPlan) -> Vec<String> {
    match &plan.incremental {
        Some(inc) => {
            let all: BTreeSet<String> = inc.routes.iter().chain(&inc.seeds).cloned().collect();
            all.into_iter().collect()
        }
        None => plan.only_routes.clone(),
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// One scope combines requested routes with project/role exclusions.
fn scopes_toml(routes: &[String], exclude_routes: &[String]) -> Result<String> {
    let mut def = toml::Table::new();
    def.insert(
        "routes".into(),
        toml::Value::Array(routes.iter().cloned().map(toml::Value::String).collect()),
    );
    if !exclude_routes.is_empty() {
        def.insert(
            "exclude_routes".into(),
            toml::Value::Array(
                exclude_routes
                    .iter()
                    .cloned()
                    .map(toml::Value::String)
                    .collect(),
            ),
        );
    }
    let mut scopes = toml::Table::new();
    scopes.insert(SCOPE_NAME.into(), toml::Value::Table(def));
    let mut root = toml::Table::new();
    root.insert("scope".into(), toml::Value::Table(scopes));
    toml::to_string_pretty(&root).context("serialize scopes")
}

/// Files of one map run under `.brokenapp/scans/<ts>/` (anonymous role) or
/// `.brokenapp/scans/<ts>/roles/<role>/`.
#[derive(Debug, Clone)]
struct RunPaths {
    ts: String,
    dir: PathBuf,
    scan_out: PathBuf,
    scan_toml: PathBuf,
    scan_json: PathBuf,
    seeds: PathBuf,
    scopes: PathBuf,
    progress: PathBuf,
    /// `map`'s own progress snapshot (routes, controls, ETA) for long runs.
    map_progress: PathBuf,
    dev_log: PathBuf,
}

impl RunPaths {
    fn create(ctx: &ProjectCtx) -> Result<Self> {
        let base = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let scans = ctx.scans_dir();
        let mut ts = base.clone();
        let mut n = 2;
        while scans.join(&ts).exists() {
            ts = format!("{base}-{n}");
            n += 1;
        }
        let dir = scans.join(&ts);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Self::at(&ts, dir))
    }

    fn at(ts: &str, dir: PathBuf) -> Self {
        Self {
            scan_out: dir.join("scan"),
            scan_toml: dir.join("scan.toml"),
            scan_json: dir.join("scan.json"),
            seeds: dir.join("seed-routes.txt"),
            scopes: dir.join("scopes.toml"),
            progress: dir.join("progress.json"),
            map_progress: dir.join("map-progress.json"),
            dev_log: dir.join("dev-server.log"),
            ts: ts.to_string(),
            dir,
        }
    }

    /// The run directory of `role`: the run itself for the anonymous role,
    /// `roles/<role>/` inside it otherwise.
    fn for_role(&self, role: &str) -> Result<Self> {
        if role == ANONYMOUS_ROLE {
            return Ok(self.clone());
        }
        let dir = self.dir.join("roles").join(role);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let mut paths = Self::at(&self.ts, dir);
        // One dev server per run.
        paths.dev_log = self.dev_log.clone();
        Ok(paths)
    }
}

/// Result of the scan subprocess.
struct ScanRun {
    output_dir: PathBuf,
    status: String,
    duration_seconds: Option<f64>,
    stop_reason: Option<String>,
    queue_remaining: Option<usize>,
}

fn scan_stop_reason(summary: &Value) -> Option<String> {
    summary
        .pointer("/run/stop_reason")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn scan_queue_remaining(summary: &Value) -> Option<usize> {
    summary
        .pointer("/run/queue_remaining")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
}

/// Parse the scan's `--json` stdout, tolerating stray leading output.
fn parse_scan_json(stdout: &str) -> Result<Value> {
    let trimmed = stdout.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return Ok(v);
    }
    let start = trimmed
        .find('{')
        .context("scan printed no JSON summary on stdout")?;
    serde_json::Deserializer::from_str(&trimmed[start..])
        .into_iter::<Value>()
        .next()
        .context("scan printed no JSON summary on stdout")?
        .context("parse scan JSON summary")
}

/// The real scan output dir from the summary (`artifacts.output_dir`).
fn scan_output_dir(summary: &Value, cwd: &Path) -> Result<PathBuf> {
    let raw = summary
        .pointer("/artifacts/output_dir")
        .and_then(Value::as_str)
        .context("scan JSON summary has no artifacts.output_dir")?;
    let p = PathBuf::from(raw);
    Ok(if p.is_absolute() { p } else { cwd.join(p) })
}

/// Prints scan progress to stderr without flooding it: routes visited/known
/// and controls exercised/seen (from `interactions.jsonl`, unless
/// `progress.json` carries explicit counts), elapsed time and the ETA. Also
/// writes `map-progress.json` in the run directory for long runs.
struct ProgressPrinter {
    progress: PathBuf,
    map_progress: PathBuf,
    interactions: PathBuf,
    seeds: BTreeSet<String>,
    tally: InteractionTally,
    started: Instant,
    last_key: Option<(u64, u64, usize)>,
    last_print: Option<Instant>,
    last_write: Option<Instant>,
    /// `[admin] ` in multi-role runs.
    prefix: String,
    role: String,
    /// Fixed interval (full mode); `None` = print on change.
    every: Option<Duration>,
    /// 0 = no time cap (full mode).
    max_minutes: u64,
}

/// Seconds between `map-progress.json` writes.
const MAP_PROGRESS_WRITE: Duration = Duration::from_secs(10);
/// `progress.json` older than this is from an earlier process (a resumed
/// crawl does not rewrite it): its current URL is stale.
const STALE_PROGRESS: Duration = Duration::from_secs(60);

impl ProgressPrinter {
    fn new(
        run: &RunPaths,
        seeds: &[String],
        role: &str,
        prefix: &str,
        every: Option<Duration>,
        max_minutes: u64,
    ) -> Self {
        Self {
            progress: run.progress.clone(),
            map_progress: run.map_progress.clone(),
            interactions: run.scan_out.join("interactions.jsonl"),
            seeds: seeds
                .iter()
                .map(|s| scan_facts::normalize_route(s))
                .collect(),
            tally: InteractionTally::default(),
            started: Instant::now(),
            last_key: None,
            last_print: None,
            last_write: None,
            prefix: prefix.to_string(),
            role: role.to_string(),
            every,
            max_minutes,
        }
    }

    /// `progress.json` (or `{}`) with this process's clock and an ETA.
    fn snapshot(&mut self) -> Value {
        let fresh = std::fs::metadata(&self.progress)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < STALE_PROGRESS);
        let mut v = std::fs::read_to_string(&self.progress)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .filter(Value::is_object)
            .unwrap_or_else(|| Value::Object(Default::default()));
        self.tally.update(&self.interactions);
        let elapsed = self.started.elapsed().as_secs();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("elapsed_seconds".into(), Value::from(elapsed));
            if !fresh {
                obj.remove("current_url");
                obj.remove("estimated_remaining_seconds");
            }
            let raw_eta = obj
                .get("estimated_remaining_seconds")
                .and_then(Value::as_u64)
                .filter(|s| *s > 0)
                .or_else(|| {
                    let visited = self.tally.routes.len() as u64;
                    let known = self.seeds.union(&self.tally.routes).count() as u64;
                    route_eta(elapsed, visited, known)
                });
            if let Some(eta) = cap_eta_to_budget(raw_eta, elapsed, self.max_minutes) {
                obj.insert("estimated_remaining_seconds".into(), Value::from(eta));
            } else {
                obj.remove("estimated_remaining_seconds");
            }
        }
        v
    }

    fn maybe_print(&mut self) {
        let v = self.snapshot();
        let key = (
            self.tally.seen,
            self.tally.exercised,
            self.tally.routes.len(),
        );
        if self
            .last_write
            .is_none_or(|t| t.elapsed() >= MAP_PROGRESS_WRITE)
        {
            self.write_snapshot(&v);
            self.last_write = Some(Instant::now());
        }
        let changed = self.last_key != Some(key);
        let since = self.last_print.map(|t| t.elapsed());
        let due = match (self.every, since) {
            (_, None) => true,
            (Some(every), Some(d)) => d >= every,
            (None, Some(d)) => {
                (changed && d >= Duration::from_secs(5)) || d >= Duration::from_secs(30)
            }
        };
        if !due {
            return;
        }
        let line = scan_facts::progress_line(&v, &self.tally, &self.seeds);
        if self.prefix.is_empty() {
            eprintln!("{line}");
        } else {
            eprintln!(
                "{}",
                line.replacen("  scanning:", &format!("  {}scanning:", self.prefix), 1)
            );
        }
        self.last_key = Some(key);
        self.last_print = Some(Instant::now());
    }

    /// Final `map-progress.json` once the scan exited.
    fn finish(&mut self) {
        let mut v = self.snapshot();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("estimated_remaining_seconds".into(), Value::from(0));
            obj.remove("current_url");
        }
        self.write_snapshot(&v);
    }

    fn write_snapshot(&self, v: &Value) {
        let num = |k: &str| v.get(k).and_then(Value::as_u64);
        let doc = serde_json::json!({
            "role": self.role,
            "updated_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "elapsed_seconds": num("elapsed_seconds").unwrap_or(0),
            "routes_visited": num("routes_visited").unwrap_or(self.tally.routes.len() as u64),
            "routes_known": num("routes_known")
                .unwrap_or(self.seeds.union(&self.tally.routes).count() as u64),
            "controls_exercised": num("controls_exercised").unwrap_or(self.tally.exercised),
            "controls_seen": num("controls_discovered").unwrap_or(self.tally.seen),
            "estimated_remaining_seconds": num("estimated_remaining_seconds"),
            "current_url": v.get("current_url").cloned().unwrap_or(Value::Null),
        });
        if let Ok(body) = serde_json::to_string_pretty(&doc) {
            let tmp = self.map_progress.with_extension("json.tmp");
            if std::fs::write(&tmp, body).is_ok() {
                let _ = std::fs::rename(&tmp, &self.map_progress);
            }
        }
    }
}

/// ETA from the route visit rate: elapsed × unvisited ÷ visited, once a few
/// routes and a minute are in (earlier estimates are noise).
fn route_eta(elapsed_secs: u64, visited: u64, known: u64) -> Option<u64> {
    if elapsed_secs < 60 || visited < 3 || known <= visited {
        return None;
    }
    Some(elapsed_secs.saturating_mul(known - visited) / visited)
}

/// Never display an ETA exceeding the remaining scan budget when `max_minutes > 0`.
fn cap_eta_to_budget(raw_eta: Option<u64>, elapsed_secs: u64, max_minutes: u64) -> Option<u64> {
    let eta = raw_eta.filter(|s| *s > 0)?;
    if max_minutes == 0 {
        return Some(eta);
    }
    let budget_secs = max_minutes.saturating_mul(60);
    let remaining_budget = budget_secs.saturating_sub(elapsed_secs);
    let capped = eta.min(remaining_budget);
    (capped > 0).then_some(capped)
}

/// The scan subprocess exited unsuccessfully; `tail` is its last stderr
/// lines (redacted).
#[derive(Debug)]
struct ScanFailed {
    status: String,
    tail: Vec<String>,
}

impl std::fmt::Display for ScanFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scan failed ({}); see the scan errors above",
            self.status
        )
    }
}

impl std::error::Error for ScanFailed {}

/// Lines of the scan's stderr kept for error reports.
const STDERR_TAIL: usize = 40;

/// How to run one role's scan subprocess.
struct ScanProc<'a> {
    role: &'a str,
    /// `[admin] ` for multi-role runs, else empty.
    prefix: String,
    /// Credentials-file values the scan reads as `env:` references.
    env: &'a [(String, String)],
    redactor: &'a Redactor,
    /// Manual login: the scan reads Enter from this terminal.
    interactive: bool,
    /// Continue an interrupted crawl (`brokenapp resume <dir>`) instead of a fresh scan.
    resume_from: Option<&'a Path>,
    progress_every: Option<Duration>,
    /// 0 = no time cap (full mode).
    max_minutes: u64,
    dev: Option<&'a DevSupervisor>,
    stop: &'a tokio::sync::watch::Receiver<bool>,
}

/// Run `brokenapp scan --config <toml> --json` (or `brokenapp resume`) as a
/// subprocess of this exe. Its stderr is forwarded (redacted, prefixed for
/// roles) and the last lines kept for error reports.
async fn run_scan_subprocess(
    ctx: &ProjectCtx,
    run: &RunPaths,
    seeds: &[String],
    timeout: Option<Duration>,
    sp: &ScanProc<'_>,
    warnings: &mut Vec<String>,
) -> Result<ScanRun> {
    let exe = std::env::current_exe().context("locate the brokenapp executable")?;
    let mut cmd = tokio::process::Command::new(&exe);
    match sp.resume_from {
        Some(dir) => {
            cmd.arg("resume")
                .arg(dir)
                .arg("--json")
                .arg("--progress-file")
                .arg(&run.progress);
        }
        None => {
            cmd.arg("scan")
                .arg("--config")
                .arg(&run.scan_toml)
                .arg("--json")
                .arg("--progress-file")
                .arg(&run.progress);
        }
    }
    // Credentials from credentials.toml: environment only, never a file.
    for (k, v) in sp.env {
        cmd.env(k, v);
    }
    cmd.current_dir(&ctx.root)
        .env("BROKENAPP_NO_BANNER", "1")
        .stdin(if sp.interactive {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut proc = ManagedChild::spawn(cmd, "scan subprocess")?;
    let mut stdout = proc.child.stdout.take().context("capture scan stdout")?;
    let stderr = proc.child.stderr.take().context("capture scan stderr")?;
    // Read incrementally into a shared buffer: a grandchild that inherits the
    // pipe (e.g. Chrome's macOS updater) can keep it open long after the scan
    // exits, so after exit we take what was read instead of waiting for EOF.
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let sink = std::sync::Arc::clone(&captured);
    let reader = tokio::spawn(async move {
        let mut chunk = [0u8; 8192];
        loop {
            match stdout.read(&mut chunk).await {
                Ok(0) => break Ok(()),
                Ok(n) => match sink.lock() {
                    Ok(mut buf) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break Err(std::io::Error::other("scan stdout buffer poisoned")),
                },
                Err(err) => break Err(err),
            }
        }
    });
    let tail = std::sync::Arc::new(std::sync::Mutex::new(
        std::collections::VecDeque::<String>::new(),
    ));
    let tail_sink = std::sync::Arc::clone(&tail);
    let redactor = sp.redactor.clone();
    let prefix = sp.prefix.clone();
    let err_reader = tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = redactor.redact(&line);
            eprintln!("{prefix}{line}");
            if let Ok(mut t) = tail_sink.lock() {
                if t.len() == STDERR_TAIL {
                    t.pop_front();
                }
                t.push_back(line);
            }
        }
    });

    let started = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    let mut printer = ProgressPrinter::new(
        run,
        seeds,
        sp.role,
        &sp.prefix,
        sp.progress_every,
        sp.max_minutes,
    );
    let status = loop {
        tokio::select! {
            status = proc.child.wait() => break Some(status.context("wait for scan subprocess")?),
            _ = stop_requested(sp.stop.clone()) => {
                // Signal only the engine first. Chrome must stay alive while
                // the engine snapshots in-flight tabs and writes its checkpoint.
                #[cfg(unix)]
                let _ = std::process::Command::new("kill")
                    .args(["-TERM", &proc.pid().to_string()])
                    .stdout(Stdio::null()).stderr(Stdio::null()).status();
                #[cfg(not(unix))]
                let _ = proc.child.start_kill();
                break tokio::time::timeout(Duration::from_secs(30), proc.child.wait())
                    .await.ok().and_then(Result::ok);
            },
            _ = ticker.tick() => {
                printer.maybe_print();
                if let Some(dev) = sp.dev
                    && let Some(msg) = dev.watch().await
                {
                    eprintln!("warning: {msg}");
                    warnings.push(msg);
                }
                if timeout.is_some_and(|t| started.elapsed() > t) {
                    break None;
                }
            }
        }
    };
    // Also stops anything the scan left in its process group (e.g. Chrome).
    proc.stop(Duration::from_secs(5)).await;
    printer.finish();
    let _ = tokio::time::timeout(Duration::from_secs(2), err_reader).await;
    let Some(status) = status else {
        bail!(
            "scan did not finish within {}s; stopped it (partial artifacts in {})",
            timeout.map(|t| t.as_secs()).unwrap_or_default(),
            run.scan_out.display()
        );
    };
    match tokio::time::timeout(Duration::from_secs(2), reader).await {
        Ok(joined) => joined
            .context("join scan stdout reader")?
            .context("read scan stdout")?,
        Err(_) => tracing::debug!("scan stdout still open after exit; using what was read"),
    }
    let stdout = {
        let buf = captured
            .lock()
            .map_err(|_| anyhow::anyhow!("scan stdout buffer poisoned"))?;
        String::from_utf8_lossy(&buf).into_owned()
    };
    if let Ok(mut summary) = parse_scan_json(&stdout) {
        sp.redactor.redact_json(&mut summary);
        std::fs::write(&run.scan_json, serde_json::to_string_pretty(&summary)?)
            .with_context(|| format!("write {}", run.scan_json.display()))?;
    }
    if !status.success() {
        let tail = tail
            .lock()
            .map(|t| t.iter().cloned().collect())
            .unwrap_or_default();
        return Err(anyhow::Error::new(ScanFailed {
            status: status.to_string(),
            tail,
        }));
    }
    if let Some(dir) = sp.resume_from {
        let summary = parse_scan_json(&stdout)?;
        let status = summary
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Ok(ScanRun {
            output_dir: dir.to_path_buf(),
            status: if matches!(
                status,
                "session_expired" | "login_failed" | "interrupted" | "failed"
            ) {
                status.to_string()
            } else {
                "resumed".to_string()
            },
            duration_seconds: Some(started.elapsed().as_secs_f64()),
            stop_reason: scan_stop_reason(&summary),
            queue_remaining: scan_queue_remaining(&summary),
        });
    }
    let summary = parse_scan_json(&stdout)?;
    Ok(ScanRun {
        output_dir: scan_output_dir(&summary, &ctx.root)?,
        status: summary
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        duration_seconds: summary.get("duration_seconds").and_then(Value::as_f64),
        stop_reason: scan_stop_reason(&summary),
        queue_remaining: scan_queue_remaining(&summary),
    })
}

/// Dev server facts for the report.
#[derive(Debug, Clone, Serialize)]
struct DevServerReport {
    started: bool,
    /// The dev command as started, with assignment values redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ready_after_ms: Option<u64>,
    /// Times the dev server died during the run and was started again.
    #[serde(default, skip_serializing_if = "is_zero")]
    restarts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stopped: Option<StopReport>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Make sure the app answers: wait for a server that is still starting, or
/// start `dev_cmd` (through `dev`, which restarts it if it dies later).
/// Returns how long a started server took to answer.
async fn ensure_app(
    ctx: &ProjectCtx,
    no_start: bool,
    url: &Url,
    run: &RunPaths,
    dev: &DevSupervisor,
    warnings: &mut Vec<String>,
) -> Result<Option<Duration>> {
    let cfg = &ctx.config;
    let ready_timeout = Duration::from_secs(cfg.project.ready_timeout_secs.max(1));
    let mut preflight = locality::probe(url, Duration::from_secs(5)).await;
    if !preflight.reachable && locality::port_open(url).await {
        // Something already listens (e.g. a dev server compiling its first
        // page). Starting dev_cmd would only collide on the port; wait instead.
        eprintln!(
            "{url} accepts connections but has not answered yet; waiting up to {}s",
            ready_timeout.as_secs()
        );
        preflight = locality::wait_reachable(url, ready_timeout).await;
        if !preflight.reachable {
            bail!(
                "{url} is listening but did not answer HTTP within {}s ({})",
                ready_timeout.as_secs(),
                preflight.error.unwrap_or_else(|| "no response".into())
            );
        }
    }
    if preflight.reachable {
        return Ok(None);
    }
    let reason = preflight.error.unwrap_or_else(|| "no response".into());
    let Some(dev_cmd) = cfg
        .project
        .dev_cmd
        .as_deref()
        .filter(|c| !c.trim().is_empty())
    else {
        bail!(
            "{url} is not reachable ({reason}). Start the app, or set project.dev_cmd in {} so `map` can start it.",
            ctx.config_path.display()
        );
    };
    if no_start {
        bail!("{url} is not reachable ({reason}) and --no-start was given");
    }
    let cwd = match cfg.project.dev_cwd.as_deref() {
        Some(rel) => ctx.root.join(rel),
        None => ctx.root.clone(),
    };
    let (env, env_warnings) = resolve_dev_env(&cfg.project.dev_env);
    for w in &env_warnings {
        eprintln!("warning: {w}");
    }
    warnings.extend(env_warnings);
    let shown = secrets::scan(dev_cmd);
    if shown.has_secrets() {
        let w = format!(
            "project.dev_cmd in {} carries secret values inline ({}); move them to [project.dev_env] as \"env:NAME\" references",
            ctx.config_path.display(),
            shown.secret_names().join(", ")
        );
        eprintln!("warning: {w}");
        warnings.push(w);
    }
    eprintln!(
        "starting dev server: {} (in {}; log {})",
        shown.redacted(),
        cwd.display(),
        run.dev_log.display()
    );
    let (waited, pid) = dev
        .start(DevSpec {
            cmd: dev_cmd.to_string(),
            cwd,
            env,
            log: run.dev_log.clone(),
        })
        .await?;
    eprintln!(
        "dev server ready at {url} after {:.1}s (pid {pid})",
        waited.as_secs_f64()
    );
    Ok(Some(waited))
}

/// Routes from source feed coverage ("known but not visited") and, unless
/// disabled, seed the crawl so pages without inbound links are visited.
fn discover(ctx: &ProjectCtx, plan: &MapPlan, warnings: &mut Vec<String>) -> RouteDiscovery {
    if let Some(inc) = &plan.incremental {
        return inc.discovery.clone();
    }
    if plan.partial() {
        return RouteDiscovery::default();
    }
    route_discovery::discover_routes(&ctx.root).unwrap_or_else(|err| {
        let w = format!("route discovery failed: {err:#}");
        eprintln!("warning: {w}");
        warnings.push(w);
        RouteDiscovery::default()
    })
}

/// One role's crawl seeds.
#[derive(Debug, Clone, Default)]
struct Seeds {
    seeds: Vec<String>,
    /// Discovered sign-out pages, never seeded.
    session_ending: Vec<String>,
    /// Dynamic route templates for instance sampling.
    templates: Vec<String>,
}

fn role_seeds(
    ctx: &ProjectCtx,
    plan: &MapPlan,
    discovery: &RouteDiscovery,
    lists: &RouteLists,
) -> Seeds {
    let discovered = if ctx.config.scan.seed_from_source {
        route_discovery::seed_paths(discovery)
    } else {
        Vec::new()
    };
    let (seeds, session_ending) = match &plan.incremental {
        Some(inc) => (inc.seeds.clone(), Vec::new()),
        None => seed_routes(discovered, &lists.extra, &lists.exclude, &plan.only_routes),
    };
    let templates = route_discovery::route_templates(discovery)
        .into_iter()
        .filter(|t| !is_excluded(t, &lists.exclude))
        .collect();
    Seeds {
        seeds,
        session_ending,
        templates,
    }
}

fn role_check_path(ctx: &ProjectCtx, role: &ResolvedRole) -> Option<String> {
    roles::find_role(&ctx.config, &role.name)
        .and_then(|r| r.check.as_deref())
        .or_else(|| {
            role.contract
                .as_ref()
                .and_then(|c| c.get("protected_probe"))
                .and_then(toml::Value::as_table)
                .and_then(|p| p.get("path"))
                .and_then(toml::Value::as_str)
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Return the role's `--check` path as a high-priority UI seed when it looks
/// like an app page (starts with `/`, is not `/`, and does not start with `/api/`).
fn role_ui_check_seed(check: Option<&str>) -> Option<String> {
    let raw = check?.trim();
    if !raw.starts_with('/') {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower == "/api" || lower.starts_with("/api/") {
        return None;
    }
    if scan_facts::normalize_route(raw) == "/" {
        return None;
    }
    Some(raw.to_string())
}

/// Normalized paths of routes cleanly visited (HTTP 200) under `anonymous`,
/// excluding `/` and the role's own `--check` path, so authenticated roles
/// map role-specific app routes before re-crawling public marketing pages.
fn deprioritized_public_routes(anon: &Inventory, role_check: Option<&str>) -> Vec<String> {
    let excluded_check = role_check.map(scan_facts::normalize_route);
    let mut routes: BTreeSet<String> = BTreeSet::new();
    for r in &anon.routes {
        if !r.visited || r.status != Some(200) {
            continue;
        }
        let norm = scan_facts::normalize_route(&r.route);
        if norm == "/" {
            continue;
        }
        if excluded_check.as_deref() == Some(norm.as_str()) {
            continue;
        }
        routes.insert(norm);
    }
    routes.into_iter().collect()
}

/// Write `seed-routes.txt`, `scopes.toml` and `scan.toml` for one role.
fn write_scan_inputs(
    ctx: &ProjectCtx,
    plan: &MapPlan,
    run: &RunPaths,
    seeds: &Seeds,
    role: &ResolvedRole,
    anon_inventory: Option<&Inventory>,
) -> Result<()> {
    let lists = route_lists(ctx, &role.name);
    let scoped = plan.scoped() || !lists.exclude.is_empty();
    if !seeds.seeds.is_empty() {
        let mut body = String::from("# Route seeds generated by `brokenapp map`.\n");
        for s in &seeds.seeds {
            body.push_str(s);
            body.push('\n');
        }
        std::fs::write(&run.seeds, body)
            .with_context(|| format!("write {}", run.seeds.display()))?;
    }
    if scoped {
        std::fs::write(
            &run.scopes,
            scopes_toml(&scope_routes(plan), &lists.exclude)?,
        )
        .with_context(|| format!("write {}", run.scopes.display()))?;
    }
    let mut seed_urls: Vec<String> = Vec::new();
    let mut deprioritize_routes: Vec<String> = Vec::new();
    if role.name != ANONYMOUS_ROLE {
        let check = role_check_path(ctx, role);
        if let Some(ui_check) = role_ui_check_seed(check.as_deref()) {
            let norm = scan_facts::normalize_route(&ui_check);
            if !plan.scoped() && !is_excluded(&norm, &lists.exclude) {
                seed_urls.push(ui_check);
            }
        }
        let loaded_anon = if anon_inventory.is_none() {
            let p = ctx.role_paths(ANONYMOUS_ROLE).latest_inventory_path();
            p.is_file().then(|| inventory::load(&p).ok()).flatten()
        } else {
            None
        };
        if let Some(anon) = anon_inventory.or(loaded_anon.as_ref()) {
            deprioritize_routes = deprioritized_public_routes(anon, check.as_deref());
        }
    }
    let canary = (plan.full.is_some() && role.has_check).then_some(FULL_CANARY_INTERVAL_VIEWS);
    let toml = scan_config_toml(&ScanToml {
        url: &plan.url,
        name: ctx.name(),
        // A manual login needs a window a person can use.
        headless: plan.headless && role.method != RoleMethod::Manual,
        max_minutes: plan.max_minutes,
        max_views: plan.max_views,
        write_guard: &plan.write_guard,
        write_guard_allow: &ctx.config.scan.write_guard_allow,
        output_dir: &run.scan_out,
        seed_routes_file: (!seeds.seeds.is_empty()).then_some(run.seeds.as_path()),
        seed_urls: &seed_urls,
        deprioritize_routes: &deprioritize_routes,
        scope: scoped.then_some((SCOPE_NAME, run.scopes.as_path())),
        codebase: None,
        route_templates: &seeds.templates,
        test_data: &plan.test_data,
        knobs: plan.knobs.clone(),
        compliance: plan.compliance.clone(),
        tabs: plan.tabs,
        view_budget_seconds: plan.view_budget_seconds,
        full: plan.full,
        auth: role.auth.as_ref().filter(|_| role.name != ANONYMOUS_ROLE),
        auth_contract: role.contract.as_ref(),
        canary_interval_views: canary,
    })?;
    std::fs::write(&run.scan_toml, toml)
        .with_context(|| format!("write {}", run.scan_toml.display()))
}

fn resolve_role_secret_for_warmup(
    resolved: &ResolvedRole,
    field: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let src = resolved.sources.iter().find(|s| s.field == field)?;
    let raw = if src.from == "credentials" {
        resolved
            .env
            .iter()
            .find(|(k, _)| k == &src.env)
            .map(|(_, v)| v.clone())
    } else {
        env(&src.env)
    }?;
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn storage_state_cookie_header(path: &Path, url: &Url) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let state = crate::session::storage_state::read_storage_state(path).ok()?;
    let now = chrono::Utc::now().timestamp() as f64;
    let allow_secure = url.scheme() == "https" || locality::is_local_url(url);
    let pairs: Vec<String> = state
        .cookies
        .iter()
        .filter(|c| !c.name.trim().is_empty())
        .filter(|c| !c.secure || allow_secure)
        .filter(|c| !c.expires.is_finite() || c.expires <= 0.0 || c.expires > now)
        .filter(|c| crate::session::auth::cookie_matches_host(&c.domain, url.host_str()))
        .map(|c| format!("{}={}", c.name, c.value))
        .collect();
    (!pairs.is_empty()).then(|| pairs.join("; "))
}

/// Extract direct HTTP auth headers (`Cookie` / `Authorization`) for one ready
/// authenticated role so warm-up compiles auth-gated routes instead of bouncing
/// to `/login`. Returns an empty map when no direct HTTP credentials exist.
fn warmup_auth_headers_for_role(
    ctx: &ProjectCtx,
    url: &Url,
    resolved: &ResolvedRole,
    env: &dyn Fn(&str) -> Option<String>,
) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    if resolved.name == ANONYMOUS_ROLE || !resolved.ready() {
        return headers;
    }
    match resolved.method {
        RoleMethod::Cookie => {
            if let Some(raw) = resolve_role_secret_for_warmup(resolved, "cookie", env)
                && let Ok(hdr) = crate::session::auth::cookie_header_from_raw(&raw)
            {
                headers.insert("Cookie".to_string(), hdr);
            }
        }
        RoleMethod::Bearer => {
            if let Some(token) = resolve_role_secret_for_warmup(resolved, "token", env) {
                headers.insert("Authorization".to_string(), format!("Bearer {token}"));
            }
        }
        RoleMethod::Session | RoleMethod::Manual => {
            let path = resolved.session_file.clone().or_else(|| {
                roles::find_role(&ctx.config, &resolved.name)
                    .map(|r| r.session_path(&ctx.state_dir))
            });
            if let Some(path) = path
                && let Some(hdr) = storage_state_cookie_header(&path, url)
            {
                headers.insert("Cookie".to_string(), hdr);
            }
        }
        RoleMethod::Form | RoleMethod::Supabase | RoleMethod::Firebase => {
            if let Some(role) = roles::find_role(&ctx.config, &resolved.name) {
                let path = role.session_path(&ctx.state_dir);
                if let Some(hdr) = storage_state_cookie_header(&path, url) {
                    headers.insert("Cookie".to_string(), hdr);
                }
            }
        }
    }
    headers
}

/// Build optional warm-up auth headers from the first ready authenticated role
/// that has direct HTTP credentials (`cookie`, `bearer`, or a saved session
/// whose cookies match `url`).
fn warmup_auth_headers_for_roles(
    ctx: &ProjectCtx,
    url: &Url,
    jobs: &[RoleJob],
    env: &dyn Fn(&str) -> Option<String>,
) -> BTreeMap<String, String> {
    for job in jobs
        .iter()
        .filter(|j| j.name != ANONYMOUS_ROLE && j.outcome.is_none() && j.resolved.ready())
    {
        let headers = warmup_auth_headers_for_role(ctx, url, &job.resolved, env);
        if !headers.is_empty() {
            return headers;
        }
    }
    BTreeMap::new()
}

/// Cold dev compiles can outlast the crawler's navigation timeout: request
/// every seeded route once before the crawl.
async fn warm(
    ctx: &ProjectCtx,
    url: &Url,
    seeds: &[String],
    extra_headers: BTreeMap<String, String>,
    user_agent: Option<String>,
    framework: Option<&str>,
    warnings: &mut Vec<String>,
) -> Option<WarmupReport> {
    if seeds.is_empty() || !locality::is_local_url(url) {
        return None;
    }
    eprintln!("warming {} seeded routes", seeds.len());
    let opts = warmup::WarmupOptions {
        extra_headers,
        user_agent,
        ..warmup::WarmupOptions::default()
    };
    let report = warmup::warm_routes(url, seeds, &opts).await;
    eprintln!("{}", report.summary_line(opts.max_routes));
    for w in report.warnings() {
        eprintln!("warning: {w}");
        warnings.push(w);
    }
    if let Some(tip) = warmup::slow_next_dev_tip(
        report.elapsed_ms,
        ctx.config.project.dev_cmd.as_deref(),
        framework,
    ) {
        eprintln!("tip: {tip}");
        warnings.push(tip);
    }
    Some(report)
}

/// One role's scan and inventory.
struct ScanOut {
    scan: ScanRun,
    inventory: Inventory,
    scan_ms: u64,
    inventory_ms: u64,
    facts: ScanFacts,
}

fn budget_text(plan: &MapPlan) -> String {
    let minutes = if plan.max_minutes == 0 {
        "no time cap".to_string()
    } else {
        format!("{} min", plan.max_minutes)
    };
    let views = if plan.max_views == 0 {
        "no view cap".to_string()
    } else {
        format!("{} views", plan.max_views)
    };
    format!("{} mode, {minutes} / {views}", plan.mode.as_str())
}

/// Suppress the noisy "add a role" hint on `anonymous` when login roles are
/// already configured in `.brokenapp/config.toml`.
fn normalize_scan_warnings(raw: Vec<String>, role: &str, role_aware: bool) -> Vec<String> {
    if role == ANONYMOUS_ROLE && role_aware {
        raw.into_iter()
            .filter(|w| !w.contains("add a role ([[roles]] in .brokenapp/config.toml)"))
            .collect()
    } else {
        raw
    }
}

/// On a `--route` partial scan, unvisited routes discovered via DOM links that
/// were outside `--route` are not "not linked or seeded" — label them honestly.
fn relabel_outside_route_filter(inv: &mut Inventory, only_routes: &[String]) {
    if only_routes.is_empty() {
        return;
    }
    const OUTSIDE_FILTER: &str = "outside --route filter";
    const NOT_LINKED: &str = "not linked or seeded";
    let allowed: BTreeSet<String> = only_routes
        .iter()
        .map(|r| scan_facts::normalize_route(r))
        .collect();
    for route in &mut inv.routes {
        if !route.visited
            && !allowed.contains(&scan_facts::normalize_route(&route.route))
            && matches!(route.unvisited_reason.as_deref(), None | Some(NOT_LINKED))
        {
            route.unvisited_reason = Some(OUTSIDE_FILTER.to_string());
        }
    }
    if let Some(routes) = inv.coverage.unvisited_by_reason.remove(NOT_LINKED) {
        let (in_filter, outside): (Vec<String>, Vec<String>) = routes
            .into_iter()
            .partition(|r| allowed.contains(&scan_facts::normalize_route(r)));
        if !in_filter.is_empty() {
            inv.coverage
                .unvisited_by_reason
                .insert(NOT_LINKED.to_string(), in_filter);
        }
        if !outside.is_empty() {
            let entry = inv
                .coverage
                .unvisited_by_reason
                .entry(OUTSIDE_FILTER.to_string())
                .or_default();
            for r in outside {
                if !entry.contains(&r) {
                    entry.push(r);
                }
            }
        }
    }
}

/// Run one role's scan subprocess and build its inventory (the dev server
/// is still up: link probing and runtime source resolution need it).
#[allow(clippy::too_many_arguments)]
async fn scan_role(
    ctx: &ProjectCtx,
    plan: &MapPlan,
    run: &RunPaths,
    seeds: &Seeds,
    discovery: &RouteDiscovery,
    sp: &ScanProc<'_>,
    warnings: &mut Vec<String>,
) -> Result<ScanOut> {
    eprintln!(
        "{}scanning {} ({}, write guard {}, {} seeded routes, {} route templates{})",
        sp.prefix,
        plan.url,
        budget_text(plan),
        plan.write_guard,
        seeds.seeds.len(),
        seeds.templates.len(),
        if sp.resume_from.is_some() {
            ", resuming from the checkpoint"
        } else {
            ""
        }
    );
    if plan.write_guard == "off" {
        eprintln!(
            "{}warning: write guard is OFF (--allow-writes); run only against disposable data",
            sp.prefix
        );
    } else {
        let guard_verb = if plan.write_guard == "stub" {
            "stubbed"
        } else {
            "blocked"
        };
        eprintln!(
            "{}guard limits: HTTP mutations and structured WS writes are {guard_verb}; state-changing GETs, Service Workers, and background opaque WS frames remain outside the guard — use disposable data or scan.exclude_routes",
            sp.prefix
        );
    }
    let timeout = (plan.max_minutes > 0)
        .then(|| Duration::from_secs(plan.max_minutes * 60) + SCAN_FINALIZE_GRACE);
    let scan_started = Instant::now();
    let scan = run_scan_subprocess(ctx, run, &seeds.seeds, timeout, sp, warnings).await?;
    if *sp.stop.borrow() {
        bail!("scan interrupted; partial artifacts retained");
    }
    let scan_ms = millis(scan_started.elapsed());
    eprintln!(
        "{}scan {} in {:.0}s; building the UI inventory",
        sp.prefix,
        scan.status,
        scan.duration_seconds.unwrap_or_default()
    );
    let facts = ScanFacts::read(&scan.output_dir);
    let role_aware = !ctx.config.roles.is_empty();
    for w in normalize_scan_warnings(facts.warnings(), sp.role, role_aware) {
        eprintln!("warning: {}{w}", sp.prefix);
        warnings.push(w);
    }
    let build_started = Instant::now();
    let lists = route_lists(ctx, sp.role);
    let mut inventory = inventory::build_from_scan_dir(
        &scan.output_dir,
        &inventory::BuildOptions {
            project: ctx.name().to_string(),
            target_url: plan.url.to_string(),
            codebase: Some(ctx.root.clone()),
            discovered_routes: discovery
                .routes
                .iter()
                .filter(|r| !is_excluded(&r.path, &lists.exclude))
                .cloned()
                .collect(),
            exclude_routes: lists.exclude.clone(),
            // The inventory HTTP probe has no browser session. Authenticated
            // maps must use their captured role evidence rather than anonymous GETs.
            // Scoped maps also avoid unscoped probes and their redirects, and
            // remote targets skip unpaced parallel link probing altogether.
            check_links: sp.role == ANONYMOUS_ROLE
                && !plan.scoped()
                && lists.exclude.is_empty()
                && locality::is_local_url(&plan.url),
            resolve_sources: true,
            write_guard: plan.write_guard.clone(),
            // A re-crawl of a few routes (`--changed` or `--route` merging into
            // an existing map): shell controls stay route-scoped so
            // `merge_incremental` folds them into the latest map's globals.
            keep_route_scope: plan.incremental.is_some() || plan.merge_partial,
            concrete_routes: plan.incremental.as_ref().map(|i| i.full_seeds.clone()),
        },
    )
    .await
    .with_context(|| {
        format!(
            "build the UI inventory from {} (the scan itself succeeded)",
            scan.output_dir.display()
        )
    })?;
    if plan.partial() {
        relabel_outside_route_filter(&mut inventory, &plan.only_routes);
    }
    Ok(ScanOut {
        scan,
        inventory,
        scan_ms,
        inventory_ms: millis(build_started.elapsed()),
        facts,
    })
}

/// Why a role's scan failed at sign-in, from the scan's `auth_result`
/// telemetry event or its last stderr lines; `None` for other failures.
fn auth_failure(run: &RunPaths, tail: &[String]) -> Option<String> {
    let telemetry = std::env::var_os("BROKENAPP_TELEMETRY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| run.dir.join("telemetry.jsonl"));
    if let Ok(raw) = std::fs::read_to_string(telemetry) {
        for line in raw.lines().rev() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if v.get("event_type").and_then(Value::as_str) != Some("auth_result") {
                continue;
            }
            let p = v.get("payload").cloned().unwrap_or(Value::Null);
            if p.get("success").and_then(Value::as_bool) == Some(false) {
                return Some(
                    p.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("sign-in failed")
                        .to_string(),
                );
            }
            break;
        }
    }
    tail.iter()
        .rev()
        .find(|l| {
            let l = l.to_ascii_lowercase();
            l.contains("login_failed")
                || l.contains("resolve auth secrets")
                || l.contains("auth contract")
                || l.contains("authenticat")
                || l.contains("storage state")
                || l.contains("saved session")
                || l.contains("sign-in")
        })
        .map(|l| l.trim().to_string())
}

/// A non-form role that saw nothing the anonymous map does not, and was sent
/// to login: its session is expired or was not applied.
fn looks_logged_out(role: &Inventory, anonymous: &Inventory) -> Option<String> {
    let visited = |inv: &Inventory| -> BTreeSet<String> {
        inv.routes
            .iter()
            .filter(|r| role_access::route_access(r) == role_access::Access::Visited)
            .map(|r| r.route.trim_end_matches('/').to_string())
            .collect()
    };
    let login: Vec<String> = role
        .routes
        .iter()
        .filter(|r| role_access::route_access(r) == role_access::Access::Login)
        .map(|r| r.route.clone())
        .collect();
    let mine = visited(role);
    if login.is_empty() || !mine.is_subset(&visited(anonymous)) {
        return None;
    }
    Some(format!(
        "it reached nothing the anonymous map does not ({} route{} visited) and was sent to login on {} route{} ({}); its session is expired or was not applied",
        mine.len(),
        plural(mine.len()),
        login.len(),
        plural(login.len()),
        scan_facts::preview(&login, 4)
    ))
}

async fn stop_requested(mut receiver: tokio::sync::watch::Receiver<bool>) {
    if !*receiver.borrow() {
        let _ = receiver.wait_for(|stop| *stop).await;
    }
}

/// Resolves on SIGINT/SIGTERM/SIGHUP (Ctrl-C elsewhere).
async fn shutdown_signal() -> &'static str {
    async fn ctrl_c() {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        async fn wait(kind: SignalKind) {
            match signal(kind) {
                Ok(mut s) => {
                    s.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        }
        tokio::select! {
            _ = ctrl_c() => "SIGINT",
            _ = wait(SignalKind::terminate()) => "SIGTERM",
            _ = wait(SignalKind::hangup()) => "SIGHUP",
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c().await;
        "Ctrl-C"
    }
}

/// Keep only controls/routes/endpoints on `routes` (for `--route` diffs).
fn restrict(inv: &Inventory, routes: &BTreeSet<String>) -> Inventory {
    fn norm(r: &str) -> String {
        let t = r.trim_end_matches('/');
        if t.is_empty() {
            "/".to_string()
        } else {
            t.to_string()
        }
    }
    let routes: BTreeSet<String> = routes.iter().map(|r| norm(r)).collect();
    let mut out = inv.clone();
    out.controls.retain(|c| routes.contains(&norm(&c.route)));
    out.routes.retain(|r| routes.contains(&norm(&r.route)));
    let keys: BTreeSet<&str> = out.controls.iter().map(|c| c.key.as_str()).collect();
    out.endpoints = inv
        .endpoints
        .iter()
        .cloned()
        .filter_map(|mut e| {
            e.controls.retain(|k| keys.contains(k.as_str()));
            e.on_load.retain(|r| routes.contains(&norm(r)));
            (!e.controls.is_empty() || !e.on_load.is_empty()).then_some(e)
        })
        .collect();
    out
}

fn status_name(status: ControlStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{status:?}").to_ascii_lowercase())
}

/// Control rows per status.
fn status_counts(inv: &Inventory) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for c in &inv.controls {
        *counts.entry(status_name(c.status)).or_insert(0) += 1;
    }
    counts
}

fn summary_line(cov: &CoverageSummary, counts: &BTreeMap<String, u32>) -> String {
    let n = |k: &str| counts.get(k).copied().unwrap_or(0);
    format!(
        "{}/{} routes, {}/{} controls exercised, {} dead, {} broken",
        cov.routes_visited,
        cov.routes_known.max(cov.routes_visited),
        cov.controls_exercised,
        cov.controls_total,
        n("dead"),
        n("broken")
    )
}

#[derive(Debug, Clone, Serialize)]
struct ChangesReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    first_map: bool,
    total: usize,
    summary: BTreeMap<String, u32>,
    /// First 50 change lines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lines: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ScanReport {
    dir: String,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stop_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queue_remaining: Option<usize>,
    config: String,
    seeded_routes: usize,
    /// Dynamic route templates passed to the scanner for instance sampling.
    route_templates: usize,
    route_framework: String,
    routes_from_source: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ResolvedLimits {
    scan_mode: String,
    max_minutes: u64,
    max_views: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    view_budget_seconds: Option<u64>,
    max_interaction_depth: usize,
    max_interactions_per_view: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    max_interactions_per_depth: Vec<usize>,
    tabs: usize,
}

fn resolved_limits(plan: &MapPlan) -> ResolvedLimits {
    let full = plan.mode == ScanMode::Full;
    let max_interaction_depth = plan.knobs.max_interaction_depth.unwrap_or(if full {
        FULL_MAX_INTERACTION_DEPTH
    } else {
        STANDARD_MAX_INTERACTION_DEPTH
    });
    let max_interactions_per_view = plan.knobs.max_interactions_per_view.unwrap_or(if full {
        MAX_INTERACTIONS_PER_VIEW
    } else {
        STANDARD_MAX_INTERACTIONS_PER_VIEW
    });
    let mut max_interactions_per_depth = plan
        .knobs
        .max_interactions_per_depth
        .clone()
        .unwrap_or_else(|| {
            if let Some(f) = plan.full {
                f.per_depth.to_vec()
            } else {
                STANDARD_INTERACTIONS_PER_DEPTH.to_vec()
            }
        });
    let needed = max_interaction_depth + 1;
    if let Some(&last) = max_interactions_per_depth.last()
        && max_interactions_per_depth.len() < needed
    {
        max_interactions_per_depth.resize(needed, last);
    }
    ResolvedLimits {
        scan_mode: plan.mode.as_str().to_string(),
        max_minutes: plan.max_minutes,
        max_views: plan.max_views,
        view_budget_seconds: plan.view_budget_seconds,
        max_interaction_depth,
        max_interactions_per_view,
        max_interactions_per_depth,
        tabs: plan.tabs,
    }
}

struct NextHintsInput<'a> {
    partial: bool,
    inventory: &'a str,
    resumable_full: bool,
    incomplete: bool,
    has_dead_or_broken: bool,
    role_aware: bool,
    state_dir: Option<&'a str>,
}

fn state_dir_flag(state_dir: Option<&str>) -> String {
    state_dir
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!(" --state-dir {}", shell_words::quote(s)))
        .unwrap_or_default()
}

fn build_next_hints(input: &NextHintsInput<'_>) -> Vec<String> {
    let mut next = Vec::new();
    let sd = state_dir_flag(input.state_dir);
    if input.partial {
        next.push(format!(
            "brokenapp ui --inventory {} --compact",
            input.inventory
        ));
        next.push(format!(
            "brokenapp journey <goal> --inventory {}",
            input.inventory
        ));
    }
    if input.incomplete {
        if input.resumable_full {
            next.push(format!("brokenapp map --resume{sd}"));
        } else {
            next.push(format!("brokenapp map --full{sd}"));
        }
    }
    if input.has_dead_or_broken {
        if input.role_aware {
            next.push(format!("brokenapp dead --role all{sd}"));
        } else {
            next.push(format!("brokenapp dead{sd}"));
        }
    }
    next
}

fn is_view_budget_reason(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("view_time_budget")
        || lower.contains("view_budget")
        || lower.contains("view_timeout")
}

/// Detect single-route tabbed SPAs (`1..=2` visited routes) that hit per-view
/// budget/timeout exhaustion and return an actionable `(warning, next_cmd)` pair
/// suggesting `brokenapp map --full --view-budget 600` (preserving `--role` and
/// `--state-dir` when applicable).
fn single_route_view_budget_hint(
    inv: &Inventory,
    stop_reason: Option<&str>,
    role: Option<&str>,
    state_dir: Option<&str>,
) -> Option<(String, String)> {
    if inv.coverage.routes_visited == 0 || inv.coverage.routes_visited > 2 {
        return None;
    }
    let budget_controls: u32 = inv
        .coverage
        .not_exercised_by_reason
        .iter()
        .filter(|(reason, _)| is_view_budget_reason(reason))
        .map(|(_, count)| *count)
        .sum();
    let budget_controls = if budget_controls > 0 {
        budget_controls
    } else {
        inv.controls
            .iter()
            .filter(|c| {
                c.status == ControlStatus::NotExercised
                    && c.reason.as_deref().is_some_and(is_view_budget_reason)
            })
            .count() as u32
    };
    let stop_is_view_budget = stop_reason.is_some_and(is_view_budget_reason);
    if budget_controls == 0 && !stop_is_view_budget {
        return None;
    }

    let role_flag = role
        .filter(|r| !r.trim().is_empty() && *r != ANONYMOUS_ROLE)
        .map(|r| format!(" --role {}", shell_words::quote(r)))
        .unwrap_or_default();
    let sd = state_dir_flag(state_dir);
    let cmd = format!("brokenapp map --full --view-budget 600{role_flag}{sd}");
    let detail = if budget_controls > 0 {
        format!(
            "{budget_controls} control{} skipped by per-view time budget across {} visited route{}",
            plural(budget_controls as usize),
            inv.coverage.routes_visited,
            plural(inv.coverage.routes_visited as usize),
        )
    } else {
        format!(
            "per-view budget exhausted across {} visited route{}",
            inv.coverage.routes_visited,
            plural(inv.coverage.routes_visited as usize),
        )
    };
    let warning = format!("single-route SPA hit per-view budget ({detail}); raise it with: {cmd}");
    Some((warning, cmd))
}

/// Control coverage over what the crawler can exercise: external links,
/// disabled and deliberately skipped controls are not exercisable.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
struct ExercisableCoverage {
    exercised: u32,
    exercisable: u32,
    total: u32,
    external: u32,
    disabled: u32,
    skipped: u32,
}

impl ExercisableCoverage {
    /// Prefers `coverage.controls_exercisable` when the inventory provides
    /// it; otherwise counts statuses (exercised = ok, dead, no_effect,
    /// broken; exercisable = exercised + not_exercised).
    fn compute(inv: &Inventory, counts: &BTreeMap<String, u32>) -> Self {
        let n = |k: &str| counts.get(k).copied().unwrap_or(0);
        let exercised = n("ok") + n("dead") + n("no_effect") + n("broken");
        // Only trust the builder's figure when it actually filled coverage
        // (a defaulted CoverageSummary reports 0 for everything).
        let provided = serde_json::to_value(&inv.coverage)
            .ok()
            .and_then(|c| {
                c.get("controls_exercisable")
                    .and_then(Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok())
            })
            .filter(|_| inv.coverage.controls_total > 0);
        let (exercised, exercisable) = match provided {
            Some(exercisable) => (
                inv.coverage.controls_exercised.min(exercisable),
                exercisable,
            ),
            None => (exercised, exercised + n("not_exercised")),
        };
        Self {
            exercised,
            exercisable,
            total: inv.controls.len() as u32,
            external: n("external"),
            disabled: n("disabled"),
            skipped: n("skipped"),
        }
    }
}

/// `brokenapp map --json` output. Always has `exit_code`, `scan_dir`,
/// `inventory`, `status_counts`, `coverage`, `changes` and `warnings`.
#[derive(Debug, Serialize)]
struct MapReport {
    /// Process exit code (0 on success).
    exit_code: i32,
    /// `ok`; failures print a [`MapFailure`] instead.
    status: String,
    project: String,
    url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    only_routes: Vec<String>,
    write_guard: String,
    max_minutes: u64,
    max_views: usize,
    dev_server: DevServerReport,
    /// Raw scan output directory.
    scan_dir: String,
    scan: ScanReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    warmup: Option<WarmupReport>,
    coverage: CoverageSummary,
    exercisable: ExercisableCoverage,
    /// Unvisited routes grouped by why they were not visited.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    unvisited_by_reason: BTreeMap<String, Vec<String>>,
    status_counts: BTreeMap<String, u32>,
    dead: u32,
    broken: u32,
    no_effect: u32,
    changes: ChangesReport,
    /// Map directory (whole-app maps only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    map_dir: Option<String>,
    /// `DEAD-UI.md` (whole-app maps only): dead/broken controls and caveats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dead_ui: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    files: Vec<String>,
    inventory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changelog: Option<String>,
    /// `--changed`: mode, changed files, affected routes with reasons, ...
    #[serde(flatten)]
    changed: Option<ChangedReport>,
    /// Browser tabs requested for the crawl.
    tabs: usize,
    /// `standard` or `full`.
    scan_mode: String,
    /// Per-view budget passed to the scanner (`None` = automatic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    view_budget_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stop_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queue_remaining: Option<usize>,
    resolved_limits: ResolvedLimits,
    /// The run directory (`run.json`, per-role inputs and raw scans).
    run_dir: String,
    /// The role the top-level fields describe, when roles are configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    /// Every role of the run, with its status (`mapped`, `unchanged`,
    /// `login_failed`, `credentials_missing`, ...). Present when roles are
    /// configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<RoleReport>,
    /// `ROLE-ACCESS.md`, when roles are configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    role_access: Option<String>,
    /// The interrupted run this one continued (`map --resume`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resumed: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    next: Vec<String>,
    timings: Timings,
    /// Route warm-up failures, navigation failures, skipped seeds, budget
    /// stops and other caveats. Always present (possibly empty).
    warnings: Vec<String>,
}

/// One role in `map --json`.
#[derive(Debug, Clone, Serialize)]
struct RoleReport {
    role: String,
    /// Login method; absent for the anonymous role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    /// `mapped`, `unchanged` (`--changed`: nothing to re-crawl),
    /// `credentials_missing`, `session_missing`, `login_failed`,
    /// `session_expired`, `failed`, `interrupted`, `pending`.
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stop_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queue_remaining: Option<usize>,
    /// Where each secret came from (`env` or `credentials`) and the variable
    /// the scan read; never values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credentials: Vec<roles::SecretSource>,
    map_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inventory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coverage: Option<CoverageSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exercisable: Option<ExercisableCoverage>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    status_counts: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    unvisited_by_reason: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changes: Option<ChangesReport>,
    /// `--changed`: mode, changed files and affected routes for this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changed: Option<ChangedReport>,
    warnings: Vec<String>,
}

/// `brokenapp map --json` output when the map did not complete.
#[derive(Debug, Serialize)]
struct MapFailure {
    exit_code: i32,
    /// `error` or `interrupted`.
    status: String,
    error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inventory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_dir: Option<String>,
    /// Roles finished before the failure or interrupt, and the rest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<RoleReport>,
    /// The command that continues an interrupted run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume: Option<String>,
    warnings: Vec<String>,
}

/// Unvisited routes by reason: the inventory's own reasons when it has
/// them, otherwise what this run observed.
fn unvisited_by_reason(
    inv: &Inventory,
    facts: &ScanFacts,
    warmup: Option<&WarmupReport>,
) -> BTreeMap<String, Vec<String>> {
    if inv.coverage.unvisited_routes.is_empty() {
        return BTreeMap::new();
    }
    if let Some(provided) = serde_json::to_value(inv)
        .ok()
        .and_then(|v| scan_facts::inventory_unvisited_reasons(&v))
    {
        return provided;
    }
    let warm_failed: BTreeMap<String, String> = warmup
        .map(|w| {
            w.failed
                .iter()
                .map(|f| (scan_facts::normalize_route(&f.route), f.error.clone()))
                .collect()
        })
        .unwrap_or_default();
    scan_facts::group_unvisited(&inv.coverage.unvisited_routes, facts, &warm_failed)
}

/// Avoid duplicating `unvisited_by_reason` across top-level, `coverage`, and `roles[]`.
fn dedup_unvisited_by_reason(
    computed: BTreeMap<String, Vec<String>>,
    cov: &CoverageSummary,
    has_roles: bool,
) -> BTreeMap<String, Vec<String>> {
    if has_roles || computed == cov.unvisited_by_reason {
        BTreeMap::new()
    } else {
        computed
    }
}

fn is_empty_timeout_or_error_stop(stop_reason: Option<&str>) -> bool {
    matches!(
        stop_reason,
        Some(
            "hard_timeout"
                | "max_duration_reached"
                | "browser_unavailable"
                | "partial_timeout"
                | "rate_limited"
                | "antibot_challenge"
        )
    )
}

/// Protect a non-empty previous whole-app map from being overwritten by a
/// 0-route timeout/error run. Returns the previous `routes_visited` count when
/// the previous map must be preserved.
fn should_preserve_previous_map(
    paths: &RolePaths,
    plan: &MapPlan,
    inv: &Inventory,
    stop_reason: Option<&str>,
) -> Option<u32> {
    if plan.partial() || plan.incremental.is_some() {
        return None;
    }
    if inv.coverage.routes_visited > 0 || !is_empty_timeout_or_error_stop(stop_reason) {
        return None;
    }
    let latest = paths.latest_inventory_path();
    if !latest.is_file() {
        return None;
    }
    let prev = inventory::load(&latest).ok()?;
    (prev.coverage.routes_visited > 0).then_some(prev.coverage.routes_visited)
}

/// Only refresh `ROLE-ACCESS.md` / `role-access.tsv` on whole-app or incremental
/// runs, never during `--route` partial scans.
fn should_write_role_access(role_aware: bool, plan: &MapPlan) -> bool {
    role_aware && !plan.partial()
}

/// Saved inventory + diff + map files.
struct Persisted {
    inventory_path: PathBuf,
    changes: ChangeSet,
    first_map: bool,
    files: Vec<PathBuf>,
    changelog: Option<PathBuf>,
    /// `--changed`: the re-crawl merged into the previous map.
    merged: Option<Merged>,
}

fn load_previous(path: &Path, warnings: &mut Vec<String>) -> Option<Inventory> {
    if !path.exists() {
        return None;
    }
    match inventory::load(path) {
        Ok(inv) => Some(inv),
        Err(err) => {
            let w = format!(
                "ignoring unreadable previous map {}: {err:#}",
                path.display()
            );
            eprintln!("warning: {w}");
            warnings.push(w);
            None
        }
    }
}

fn persist(
    paths: &RolePaths,
    plan: &MapPlan,
    ts: &str,
    inv: &Inventory,
    started_at: &str,
    warnings: &mut Vec<String>,
) -> Result<Persisted> {
    let history = paths.history_dir.clone();
    let latest = paths.latest_inventory_path();

    if let Some(inc) = &plan.incremental {
        // `--changed`: merge the re-crawl into the map it was planned
        // against; the changelog diffs that map against the merge, so only
        // re-crawled routes (and refreshed globals) can change.
        let merged = inventory::merge_incremental(
            &inc.latest,
            inv,
            &MergeOptions {
                requested: inc.routes.iter().cloned().collect(),
                removed: inc.impact.removed.clone(),
                changed_files: inc.changed.files.clone(),
                trigger_files: inc
                    .changed
                    .files
                    .iter()
                    .filter(|f| !inc.impact.unmapped.iter().any(|u| &u.file == *f))
                    .cloned()
                    .collect(),
                started_at: started_at.to_string(),
            },
        );
        let changes = inventory::diff(Some(&inc.latest), &merged.inventory);
        inventory::save(
            inv,
            &history
                .join("partial")
                .join(format!("{ts}.recrawl.inventory.json")),
        )?;
        let inventory_path = history.join(format!("{ts}.inventory.json"));
        inventory::save(&merged.inventory, &inventory_path)?;
        inventory::save(&merged.inventory, &latest)?;
        let (files, changelog) = write_map_files(&paths.map_dir, &merged.inventory, &changes)?;
        return Ok(Persisted {
            inventory_path,
            changes,
            first_map: false,
            files,
            changelog: Some(changelog),
            merged: Some(merged),
        });
    }

    let prev = load_previous(&latest, warnings);
    let first_map = prev.is_none();

    if plan.partial() {
        let routes: BTreeSet<String> = plan.only_routes.iter().cloned().collect();
        if !plan.no_merge
            && let Some(base) = prev.as_ref()
        {
            // Merge `--route` re-crawl into the existing whole-app map so newly
            // visited routes replace `not_reached` entries and update the map
            // files, changelog, and role-access matrix.
            let mut requested: BTreeSet<String> = BTreeSet::new();
            for raw in &plan.only_routes {
                requested.insert(scan_facts::normalize_route(raw));
                for matched in inventory::identity::select_routes(
                    inv.routes
                        .iter()
                        .chain(base.routes.iter())
                        .map(|r| r.route.as_str()),
                    raw,
                ) {
                    requested.insert(matched.to_string());
                }
            }
            let merged = inventory::merge_incremental(
                base,
                inv,
                &MergeOptions {
                    requested,
                    started_at: started_at.to_string(),
                    ..Default::default()
                },
            );
            let changes = inventory::diff(Some(base), &merged.inventory);
            inventory::save(
                inv,
                &history
                    .join("partial")
                    .join(format!("{ts}.recrawl.inventory.json")),
            )?;
            let inventory_path = history.join(format!("{ts}.inventory.json"));
            inventory::save(&merged.inventory, &inventory_path)?;
            inventory::save(&merged.inventory, &latest)?;
            let (files, changelog) = write_map_files(&paths.map_dir, &merged.inventory, &changes)?;
            return Ok(Persisted {
                inventory_path,
                changes,
                first_map: false,
                files,
                changelog: Some(changelog),
                merged: Some(merged),
            });
        }

        // Standalone `--route` map (no prior whole-app map, or `--no-merge`):
        // diff only those routes and keep it out of the whole-app history, map
        // files and changelog.
        let changes = inventory::diff(
            prev.as_ref().map(|p| restrict(p, &routes)).as_ref(),
            &restrict(inv, &routes),
        );
        let inventory_path = history.join("partial").join(format!("{ts}.inventory.json"));
        inventory::save(inv, &inventory_path)?;
        return Ok(Persisted {
            inventory_path,
            changes,
            first_map,
            files: Vec::new(),
            changelog: None,
            merged: None,
        });
    }

    let changes = inventory::diff(prev.as_ref(), inv);
    let inventory_path = history.join(format!("{ts}.inventory.json"));
    inventory::save(inv, &inventory_path)?;
    inventory::save(inv, &latest)?;
    let (files, changelog) = write_map_files(&paths.map_dir, inv, &changes)?;
    Ok(Persisted {
        inventory_path,
        changes,
        first_map,
        files,
        changelog: Some(changelog),
        merged: None,
    })
}

/// Clone an inventory into a portable copy safe to commit inside `.brokenapp/map/`
/// (strips local absolute `scan_dir` paths while preserving all routes, controls,
/// endpoints, coverage, and timestamps for `ui`, `dead`, `journey`, and `parity`).
fn portable_inventory(inv: &Inventory) -> Inventory {
    let mut copy = inv.clone();
    copy.scan_dir.clear();
    for rs in copy.route_scans.values_mut() {
        rs.scan_dir.clear();
    }
    copy
}

/// Map files plus the portable inventory and changelog entry for a whole-app map.
fn write_map_files(
    map_dir: &Path,
    inv: &Inventory,
    changes: &ChangeSet,
) -> Result<(Vec<PathBuf>, PathBuf)> {
    let mut files = inventory::write_map(inv, map_dir).context("write map files")?;
    let html_path = map_dir.join(inventory::render::UI_MAP_HTML);
    std::fs::write(&html_path, inventory::render::render_ui_map_html(inv))
        .with_context(|| format!("write {}", html_path.display()))?;
    files.push(html_path);
    let portable_path = map_dir.join(project::PORTABLE_INVENTORY);
    inventory::save(&portable_inventory(inv), &portable_path)
        .context("write portable ui-inventory.json")?;
    files.push(portable_path);
    let changelog = map_dir.join("CHANGELOG.md");
    inventory::append_changelog(changes, inv, &changelog).context("append changelog")?;
    if changelog.is_file() && !files.contains(&changelog) {
        files.push(changelog.clone());
    }
    Ok((files, changelog))
}

/// Record a finished map in the registry, registering the project when it
/// is not listed yet. Never takes over another project's entry.
fn record_scan(reg: &mut Registry, ctx: &ProjectCtx, summary: &str, at: &str) -> Result<()> {
    let url = ctx.config.project.url.clone();
    if let Some(entry) = reg
        .projects
        .iter_mut()
        .find(|e| Path::new(&e.state_dir) == ctx.state_dir)
    {
        entry.url = url;
        entry.last_scan_at = Some(at.to_string());
        entry.last_summary = Some(summary.to_string());
        return Ok(());
    }
    if let Some(other) = reg.find(ctx.name()) {
        bail!(
            "the name '{}' is registered for another project ({}); rename this one in {}",
            ctx.name(),
            other.root,
            ctx.config_path.display()
        );
    }
    reg.upsert(project::RegistryEntry {
        name: ctx.name().to_string(),
        root: ctx.root.display().to_string(),
        state_dir: ctx.state_dir.display().to_string(),
        url,
        protected: false,
        last_scan_at: Some(at.to_string()),
        last_summary: Some(summary.to_string()),
    });
    Ok(())
}

fn update_registry(ctx: &ProjectCtx, summary: &str) -> Result<()> {
    let mut reg = Registry::load()?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    record_scan(&mut reg, ctx, summary, &now)?;
    reg.save()
}

/// `path` relative to `base` when inside it.
fn rel(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

/// What is known about a run that failed, for the `--json` failure object.
#[derive(Debug, Default)]
struct RunState {
    project: Option<String>,
    scan_dir: Option<PathBuf>,
    inventory: Option<PathBuf>,
    run_dir: Option<PathBuf>,
    roles: Vec<RoleReport>,
    resume: Option<String>,
    redactor: Redactor,
    warnings: Vec<String>,
}

pub async fn run(args: MapArgs) -> Result<i32> {
    let json = args.json;
    let mut state = RunState::default();
    match run_map(args, &mut state).await {
        Ok(code) => Ok(code),
        Err(err) => {
            // Never print a secret, even inside an error from deep below.
            let msg = state.redactor.redact(&format!("{err:#}"));
            if json {
                eprintln!("error: {msg}");
                print_failure(&state, 1, "error", msg)?;
                Ok(1)
            } else {
                Err(anyhow::anyhow!(msg))
            }
        }
    }
}

fn print_failure(state: &RunState, exit_code: i32, status: &str, error: String) -> Result<()> {
    let failure = MapFailure {
        exit_code,
        status: status.to_string(),
        error,
        project: state.project.clone(),
        scan_dir: state.scan_dir.as_ref().map(|p| p.display().to_string()),
        inventory: state.inventory.as_ref().map(|p| p.display().to_string()),
        run_dir: state.run_dir.as_ref().map(|p| p.display().to_string()),
        roles: state.roles.clone(),
        resume: state.resume.clone(),
        warnings: state.warnings.clone(),
    };
    let mut v = serde_json::to_value(&failure).context("serialize map failure")?;
    state.redactor.redact_json(&mut v);
    println!(
        "{}",
        serde_json::to_string_pretty(&v).context("serialize map failure")?
    );
    Ok(())
}

/// One role through a run.
struct RoleJob {
    name: String,
    resolved: ResolvedRole,
    paths: RolePaths,
    lists: RouteLists,
    plan: MapPlan,
    changed: Option<ChangedReport>,
    /// Not scanned this run: `(status, why)`.
    outcome: Option<(String, Option<String>)>,
    /// `map --resume`: the interrupted crawl's checkpoint directory.
    resume_from: Option<PathBuf>,
    seeds: Seeds,
}

impl RoleJob {
    fn method(&self) -> Option<RoleMethod> {
        (self.name != ANONYMOUS_ROLE).then_some(self.resolved.method)
    }
}

/// What one role's scan produced.
struct RoleResult {
    name: String,
    /// `mapped`, `login_failed`, `session_expired`, `failed`.
    status: String,
    error: Option<String>,
    run: RunPaths,
    out: Option<ScanOut>,
    persisted: Option<Persisted>,
    seeds: usize,
    templates: usize,
    warnings: Vec<String>,
}

/// State shared by the role scans of one run.
struct Shared<'a> {
    ctx: &'a ProjectCtx,
    args: &'a MapArgs,
    base: &'a MapPlan,
    run: &'a RunPaths,
    dev: &'a DevSupervisor,
    manifest: &'a std::sync::Mutex<RunManifest>,
    finished: &'a std::sync::Mutex<Vec<RoleResult>>,
    redactor: &'a Redactor,
    started_at: &'a str,
    role_aware: bool,
    stop: &'a tokio::sync::watch::Receiver<bool>,
    /// This run's anonymous map, once built (baseline for `session_expired`).
    anon: std::sync::Mutex<Option<Inventory>>,
}

impl Shared<'_> {
    /// Update one role in `run.json` (best effort; never fails the run).
    fn mark(&self, role: &str, status: &str, edit: impl FnOnce(&mut RunRole)) {
        if let Ok(mut m) = self.manifest.lock() {
            if let Some(r) = m.role_mut(role) {
                r.status = status.to_string();
                edit(r);
            }
            if let Err(err) = m.save(&self.run.dir) {
                tracing::warn!("could not update run.json: {err:#}");
            }
        }
    }

    fn prefix(&self, role: &str) -> String {
        if self.role_aware {
            format!("[{role}] ")
        } else {
            String::new()
        }
    }
}

fn settings_of(plan: &MapPlan) -> RunSettings {
    RunSettings {
        target_url: plan.url.to_string(),
        codebase: String::new(),
        scan_mode: plan.mode.as_str().to_string(),
        max_minutes: plan.max_minutes,
        max_views: plan.max_views,
        write_guard: plan.write_guard.clone(),
        headless: plan.headless,
        tabs: plan.tabs,
        only_routes: plan.only_routes.clone(),
        test_data: plan.test_data.clone(),
        max_interaction_depth: plan.knobs.max_interaction_depth,
        max_interactions_per_view: plan.knobs.max_interactions_per_view,
        max_interactions_per_depth: plan.knobs.max_interactions_per_depth.clone(),
        settle_ms: plan.knobs.settle_ms,
        view_budget_seconds: plan.view_budget_seconds,
        progress_seconds: plan.progress_every.map(|d| d.as_secs()),
        role_concurrency: plan.role_concurrency,
        store: false,
    }
}

/// `map --resume`: the interrupted run's budgets and knobs. The write guard
/// is never weaker than this invocation's (an interrupted `--allow-writes`
/// run needs `--allow-writes` again).
fn apply_settings(plan: &mut MapPlan, s: &RunSettings) -> Result<()> {
    if s.write_guard == "off" && plan.write_guard != "off" {
        bail!(
            "the interrupted run had the write guard off (--allow-writes); pass --allow-writes again to resume it, or start a new `brokenapp map`"
        );
    }
    plan.write_guard = s.write_guard.clone();
    plan.mode = ScanMode::parse(&s.scan_mode).unwrap_or_default();
    plan.max_minutes = s.max_minutes;
    plan.max_views = s.max_views;
    plan.headless = s.headless;
    plan.tabs = s.tabs.clamp(1, MAX_TABS);
    plan.only_routes = s.only_routes.clone();
    plan.test_data = s.test_data.clone();
    plan.knobs = CrawlKnobs {
        max_interaction_depth: s.max_interaction_depth,
        max_interactions_per_view: s.max_interactions_per_view,
        max_interactions_per_depth: s.max_interactions_per_depth.clone(),
        settle_ms: s.settle_ms,
    };
    plan.view_budget_seconds = s.view_budget_seconds;
    plan.full = (plan.mode == ScanMode::Full).then(FullKnobs::default);
    plan.progress_every = s.progress_seconds.map(Duration::from_secs);
    plan.role_concurrency = s.role_concurrency.clamp(1, MAX_ROLE_CONCURRENCY);
    Ok(())
}

/// This identity contains only the config references passed to the engine.
fn auth_identity(role: &ResolvedRole) -> Value {
    if role.name == ANONYMOUS_ROLE {
        Value::Null
    } else {
        serde_json::json!({ "auth": role.auth, "contract": role.contract })
    }
}

/// A checkpoint must still describe the same target and authentication.
fn validate_resume_context(ctx: &ProjectCtx, job: &RoleJob, dir: &Path) -> Result<()> {
    let raw =
        std::fs::read_to_string(dir.join("checkpoint.json")).context("read resume checkpoint")?;
    let checkpoint: Value = serde_json::from_str(&raw)
        .map_err(|_| anyhow::anyhow!("invalid resume checkpoint JSON"))?;
    let saved_exclusions = match (
        checkpoint
            .pointer("/config/scan/scope")
            .and_then(Value::as_str),
        checkpoint
            .pointer("/config/scan/scopes_file")
            .and_then(Value::as_str),
    ) {
        (Some(name), Some(file)) => {
            let saved: crate::scope::ScopesFile = toml::from_str(
                &std::fs::read_to_string(file).context("read checkpoint route scope")?,
            )
            .context("parse checkpoint route scope")?;
            saved
                .scope
                .get(name)
                .context("checkpoint route scope is missing")?
                .exclude_routes
                .clone()
        }
        _ => Vec::new(),
    };
    if normalize_routes(&saved_exclusions) != normalize_routes(&job.lists.exclude) {
        bail!(
            "cannot resume role '{}': route exclusions differ from the checkpoint scope; start a new `brokenapp map`",
            job.name
        );
    }
    let target = checkpoint
        .pointer("/config/target/url")
        .and_then(Value::as_str);
    if target != Some(job.plan.url.as_str()) {
        bail!(
            "cannot resume role '{}': checkpoint target differs; start a new `brokenapp map`",
            job.name
        );
    }
    if let Some(source) = checkpoint
        .pointer("/config/scan/codebase_path")
        .and_then(Value::as_str)
        && Path::new(source) != ctx.root
    {
        bail!(
            "cannot resume role '{}': checkpoint codebase differs; start a new `brokenapp map`",
            job.name
        );
    }
    let saved_test_data: BTreeMap<String, String> = serde_json::from_value(
        checkpoint
            .pointer("/config/scan/test_data")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .map_err(|_| anyhow::anyhow!("invalid checkpoint test-data configuration"))?;
    if saved_test_data != job.plan.test_data {
        bail!(
            "cannot resume role '{}': checkpoint test data differs from the saved run; start a new `brokenapp map`",
            job.name
        );
    }
    // Deserialize both sides so omitted optional fields compare identically.
    let expected: Option<crate::config::AuthConfig> = job
        .resolved
        .auth
        .clone()
        .map(|auth| toml::Value::Table(auth).try_into())
        .transpose()
        .map_err(|_| anyhow::anyhow!("invalid role auth configuration"))?;
    let saved: Option<crate::config::AuthConfig> = serde_json::from_value(
        checkpoint
            .pointer("/config/auth")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|_| anyhow::anyhow!("invalid checkpoint authentication configuration"))?;
    if serde_json::to_value(expected)? != serde_json::to_value(saved)? {
        bail!(
            "cannot resume role '{}': checkpoint auth differs; start a new `brokenapp map`",
            job.name
        );
    }
    Ok(())
}

/// The directory `brokenapp resume` continues: the one holding the role's
/// `checkpoint.json` (its recorded output directory when readable).
fn checkpoint_dir(scan_out: &Path) -> Option<PathBuf> {
    let cp = scan_out.join("checkpoint.json");
    if !cp.is_file() {
        return None;
    }
    let recorded = std::fs::read_to_string(&cp)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| {
            v.pointer("/config/output/directory")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .filter(|p| p.join("checkpoint.json").is_file());
    Some(recorded.unwrap_or_else(|| scan_out.to_path_buf()))
}

async fn run_map(args: MapArgs, state: &mut RunState) -> Result<i32> {
    let run_started = Instant::now();
    // Recorded as the map's `started_at`: the next `--changed` counts files
    // modified after it (when git cannot tell). Milliseconds, so an edit made
    // just before this run is not counted again by the next one.
    let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let ctx = project::resolve(&args.target)?;
    state.project = Some(ctx.name().to_string());
    let explicit_state_dir = args
        .target
        .state_dir
        .as_ref()
        .map(|_| ctx.state_dir.display().to_string());
    // Fail closed: an unreadable registry could hide a `protected` flag.
    let registry = Registry::load().context("read the project registry (protected flags)")?;
    roles::validate_roles(&ctx.config, &ctx.config_path)?;
    let mut base = make_plan(&ctx, &args, &registry)?;
    let mut warnings = Vec::new();
    let mut timings = Timings::default();
    let role_aware = !ctx.config.roles.is_empty();

    // Which roles, and (resume) which run.
    let mut resumed: Option<(PathBuf, RunManifest)> = None;
    let names: Vec<String> = if args.resume {
        let (dir, manifest) = super::run_state::latest_resumable(&ctx.scans_dir())?;
        if manifest.settings.target_url != base.url.as_str()
            || manifest.settings.codebase != ctx.root.display().to_string()
        {
            bail!(
                "cannot resume: the target URL or codebase differs from the interrupted run (or its identity was not recorded); start a new `brokenapp map`"
            );
        }
        apply_settings(&mut base, &manifest.settings)?;
        let role_needs_resume = |r: &RunRole| {
            if manifest.settings.scan_mode == "full" {
                r.has_remaining_work()
            } else {
                !r.finished()
            }
        };
        let mut names = Vec::new();
        for r in manifest.roles.iter().filter(|r| role_needs_resume(r)) {
            if r.name == ANONYMOUS_ROLE || roles::find_role(&ctx.config, &r.name).is_some() {
                names.push(r.name.clone());
            } else {
                let w = format!(
                    "role '{}' of the interrupted run is no longer configured; not resumed",
                    r.name
                );
                eprintln!("warning: {w}");
                warnings.push(w);
            }
        }
        eprintln!(
            "resuming map run {} ({} mode): {}",
            manifest.ts,
            manifest.settings.scan_mode,
            manifest
                .roles
                .iter()
                .map(|r| {
                    if r.budget_stopped_with_remaining() {
                        format!(
                            "{} {} ({}, {} queued)",
                            r.name,
                            r.status,
                            r.stop_reason.as_deref().unwrap_or("budget"),
                            r.queue_remaining
                        )
                    } else {
                        format!("{} {}", r.name, r.status)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
        resumed = Some((dir, manifest));
        names
    } else {
        roles::select_roles(&ctx, &args.roles_only, args.roles.as_deref())?
    };
    if names.is_empty() {
        bail!(
            "nothing to resume: no unfinished role remains configured; start a new `brokenapp map`"
        );
    }
    if ctx.config.auth.session.is_some() {
        let w = format!(
            "[auth] session in {} is not used; add a role with method = \"session\" (`brokenapp roles add <name> --method session`) instead",
            ctx.config_path.display()
        );
        eprintln!("warning: {w}");
        warnings.push(w);
    }
    let resolved = roles::resolve_roles(&ctx, &names)?;
    if let Some((_, manifest)) = &resumed {
        for role in &manifest.roles {
            if let Some(current) = resolved.get(&role.name)
                && role.auth_identity != auth_identity(current)
            {
                bail!(
                    "cannot resume role '{}': its auth configuration changed; start a new `brokenapp map`",
                    role.name
                );
            }
        }
    }
    let mut keep_names = ctx.role_names();
    keep_names.push(ctx.name().to_string());
    let keep: Vec<&str> = keep_names.iter().map(String::as_str).collect();
    let redactor = Redactor::new(
        resolved
            .values()
            .flat_map(|r| r.secret_values.iter().cloned()),
        &keep,
    );
    state.redactor = redactor.clone();

    // Plan each role: credentials, `--changed` analysis.
    let analysis_started = Instant::now();
    let mut jobs: Vec<RoleJob> = Vec::new();
    for name in &names {
        let mut job = RoleJob {
            name: name.clone(),
            resolved: resolved.get(name).cloned().unwrap_or_default(),
            paths: ctx.role_paths(name),
            lists: route_lists(&ctx, name),
            plan: base.clone(),
            changed: None,
            outcome: None,
            resume_from: None,
            seeds: Seeds::default(),
        };
        if !job.resolved.ready() {
            let status = if job.resolved.method == RoleMethod::Session {
                "session_missing"
            } else {
                "credentials_missing"
            };
            let why = job.resolved.missing.join("; ");
            let w = format!("role '{name}' skipped ({status}): {why}");
            eprintln!("warning: {w}");
            warnings.push(w);
            job.outcome = Some((status.to_string(), Some(why)));
        } else if args.changed {
            state.warnings = warnings.clone();
            match plan_changed(&ctx, &job.paths, &job.lists, &args, &mut warnings)? {
                ChangedDecision::Skip(report) => {
                    job.outcome = Some(("unchanged".to_string(), report.mode_reason.clone()));
                    job.changed = Some(report);
                }
                ChangedDecision::Full(report) => {
                    eprintln!(
                        "--changed: {}running a whole-app map ({})",
                        if role_aware {
                            format!("[{name}] ")
                        } else {
                            String::new()
                        },
                        report.mode_reason.as_deref().unwrap_or("whole-app map")
                    );
                    job.changed = Some(report);
                }
                ChangedDecision::Incremental(inc, report) => {
                    eprintln!(
                        "--changed: {}{} changed file{} ({} since {}); re-crawling {} of {} known route{}: {}",
                        if role_aware {
                            format!("[{name}] ")
                        } else {
                            String::new()
                        },
                        inc.changed.files.len(),
                        plural(inc.changed.files.len()),
                        inc.changed.source,
                        short_base(&inc.changed.base),
                        inc.routes.len(),
                        inc.impact.known_routes,
                        plural(inc.impact.known_routes),
                        scan_facts::preview(&inc.routes, 8)
                    );
                    job.plan.incremental = Some(*inc);
                    job.changed = Some(report);
                }
            }
        } else if job.plan.partial()
            && !job.plan.no_merge
            && job.paths.latest_inventory_path().is_file()
        {
            job.plan.merge_partial = true;
        }
        jobs.push(job);
    }
    if args.changed {
        timings.analysis_ms = Some(millis(analysis_started.elapsed()));
    }
    state.warnings = warnings.clone();

    // Nothing to crawl.
    if jobs.iter().all(|j| j.outcome.is_some()) {
        let all_unchanged = jobs
            .iter()
            .all(|j| j.outcome.as_ref().is_some_and(|(s, _)| s == "unchanged"));
        let reports: Vec<RoleReport> = if role_aware {
            jobs.iter().map(|j| role_report(&ctx, j, None)).collect()
        } else {
            Vec::new()
        };
        if all_unchanged {
            timings.total_ms = millis(run_started.elapsed());
            let primary = jobs[0].changed.clone().unwrap_or_default();
            print_skipped(
                &ctx,
                &base,
                primary,
                reports,
                timings,
                warnings,
                explicit_state_dir.as_deref(),
                args.json,
            )?;
            return Ok(0);
        }
        state.roles = reports;
        let why: Vec<String> = jobs
            .iter()
            .filter_map(|j| {
                j.outcome
                    .as_ref()
                    .filter(|(s, _)| s != "unchanged")
                    .map(|(s, w)| format!("{}: {s} ({})", j.name, w.as_deref().unwrap_or("-")))
            })
            .collect();
        bail!("no role could be mapped: {}", why.join("; "));
    }

    if base.write_guard == "off" {
        eprintln!(
            "WARNING: write guard is OFF: controls the crawler clicks can create, change, or delete data in {}'s backend. Use only with a disposable local backend.",
            ctx.name()
        );
    }
    let run = match &resumed {
        Some((dir, m)) => RunPaths::at(&m.ts, dir.clone()),
        None => RunPaths::create(&ctx)?,
    };
    state.run_dir = Some(run.dir.clone());
    if !role_aware {
        state.scan_dir = Some(run.scan_out.clone());
    }
    let mut manifest = match resumed {
        Some((_, mut m)) => {
            m.status = RunStatus::Running;
            m.resumed_at
                .push(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            // Interrupted crawls continue from their checkpoints.
            for job in jobs.iter_mut() {
                let Some(r) = m.roles.iter().find(|r| r.name == job.name) else {
                    continue;
                };
                let scan_out = r
                    .scan_dir
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(&r.dir).join("scan"));
                job.resume_from = checkpoint_dir(&scan_out);
                if let Some(dir) = &job.resume_from {
                    validate_resume_context(&ctx, job, dir)?;
                }
            }
            m
        }
        None => {
            let mut m = RunManifest::new(
                &run.ts,
                &started_at,
                RunSettings {
                    codebase: ctx.root.display().to_string(),
                    ..settings_of(&base)
                },
                names
                    .iter()
                    .map(|n| RunRole {
                        name: n.clone(),
                        auth_identity: resolved.get(n).map(auth_identity).unwrap_or_default(),
                        status: "pending".to_string(),
                        dir: run
                            .dir
                            .join(if n == ANONYMOUS_ROLE {
                                PathBuf::new()
                            } else {
                                Path::new("roles").join(n)
                            })
                            .display()
                            .to_string(),
                        ..Default::default()
                    })
                    .collect(),
            );
            m.incremental = args.changed;
            m
        }
    };
    for job in &jobs {
        if let (Some((status, why)), Some(r)) = (&job.outcome, manifest.role_mut(&job.name)) {
            r.status = status.clone();
            r.error = why.clone();
        }
    }
    manifest.save(&run.dir)?;
    let manifest = std::sync::Mutex::new(manifest);
    let finished: std::sync::Mutex<Vec<RoleResult>> = std::sync::Mutex::new(Vec::new());
    let dev = DevSupervisor::new(
        base.url.clone(),
        Duration::from_secs(ctx.config.project.ready_timeout_secs.max(1)),
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let shared = Shared {
        ctx: &ctx,
        args: &args,
        base: &base,
        run: &run,
        dev: &dev,
        manifest: &manifest,
        finished: &finished,
        redactor: &redactor,
        started_at: &started_at,
        role_aware,
        stop: &stop_rx,
        anon: std::sync::Mutex::new(None),
    };

    let result: std::result::Result<Result<ExecOut>, &'static str> = {
        let work = execute(&shared, &mut jobs, &mut warnings);
        tokio::pin!(work);
        tokio::select! {
            result = &mut work => Ok(result),
            sig = shutdown_signal() => {
                let _ = stop_tx.send(true);
                eprintln!("map stopping: waiting for scan checkpoints (up to 45s)");
                // Keep scan futures alive through their bounded engine shutdown.
                // If a browser/server cannot stop, dropping them still kills
                // their owned process groups as a final fallback.
                let _ = tokio::time::timeout(Duration::from_secs(45), &mut work).await;
                Err(sig)
            },
        }
    };
    // Always stop a dev server we started, whatever happened above.
    let dev_info = dev.info().await;
    let mut dev_report = DevServerReport {
        started: dev_info.is_some(),
        command: dev_info
            .as_ref()
            .and(ctx.config.project.dev_cmd.as_deref())
            .map(secrets::redact_command),
        pid: dev_info.as_ref().map(|(pid, _)| *pid),
        log: dev_info.as_ref().map(|(_, log)| log.display().to_string()),
        ready_after_ms: None,
        restarts: dev.restarts(),
        stopped: None,
    };
    if let Some(stop) = dev.stop().await {
        eprintln!(
            "stopped dev server (process group {}, {}{})",
            stop.pid,
            stop.signal,
            if stop.group_gone {
                ""
            } else {
                "; some processes may remain"
            }
        );
        dev_report.stopped = Some(stop);
    }
    let finished = finished.into_inner().unwrap_or_default();
    let mut manifest = manifest.into_inner().unwrap_or_else(|p| p.into_inner());

    let exec = match result {
        Ok(Ok(exec)) => exec,
        Ok(Err(err)) => {
            for r in manifest.roles.iter_mut().filter(|r| r.status == "scanning") {
                r.status = "failed".to_string();
            }
            manifest.status = RunStatus::Failed;
            let started_any =
                !finished.is_empty() || manifest.roles.iter().any(|r| r.status == "failed");
            if started_any || !manifest.resumed_at.is_empty() {
                let _ = manifest.save(&run.dir);
                state.resume = Some("brokenapp map --resume".to_string());
            } else {
                // Nothing ran (e.g. the app was unreachable): drop the run dir
                // when nothing else was written into it.
                let _ = std::fs::remove_file(run.dir.join(super::run_state::RUN_MANIFEST));
                let _ = std::fs::remove_dir(run.dir.join("roles"));
                for n in &names {
                    let _ = std::fs::remove_dir(run.dir.join("roles").join(n));
                }
                let _ = std::fs::remove_dir(run.dir.join("roles"));
                if std::fs::remove_dir(&run.dir).is_ok() {
                    state.scan_dir = None;
                    state.run_dir = None;
                }
            }
            state.roles = final_reports(&ctx, &jobs, &finished, &manifest, role_aware);
            state.warnings = warnings.clone();
            return Err(err);
        }
        Err(sig) => {
            for r in manifest.roles.iter_mut().filter(|r| r.status == "scanning") {
                r.status = "interrupted".to_string();
            }
            manifest.status = RunStatus::Interrupted;
            let _ = manifest.save(&run.dir);
            if should_write_role_access(role_aware, &base) {
                if let Err(err) = write_role_access(&ctx, &manifest) {
                    tracing::warn!("role access not written: {err:#}");
                }
            }
            let done: Vec<&str> = finished
                .iter()
                .filter(|r| r.status == "mapped")
                .map(|r| r.name.as_str())
                .collect();
            eprintln!(
                "map interrupted by {sig}; partial artifacts in {}{}",
                run.dir.display(),
                if done.is_empty() {
                    String::new()
                } else {
                    format!("; finished roles are saved: {}", done.join(", "))
                }
            );
            eprintln!("resume with: brokenapp map --resume");
            state.resume = Some("brokenapp map --resume".to_string());
            state.roles = final_reports(&ctx, &jobs, &finished, &manifest, role_aware);
            state.warnings = warnings.clone();
            if args.json {
                print_failure(state, 130, "interrupted", format!("interrupted by {sig}"))?;
            }
            return Ok(130);
        }
    };

    // Roles finished: run status, registry, role access, report.
    let reports = final_reports(&ctx, &jobs, &finished, &manifest, role_aware);
    let ok_statuses = ["mapped", "unchanged"];
    let all_ok = reports.is_empty()
        || reports
            .iter()
            .all(|r| ok_statuses.contains(&r.status.as_str()));
    let primary_idx = names.iter().find_map(|n| {
        finished
            .iter()
            .position(|r| &r.name == n && r.status == "mapped")
    });
    manifest.status = if all_ok && primary_idx.is_some() {
        RunStatus::Completed
    } else if primary_idx.is_some() {
        RunStatus::Partial
    } else {
        RunStatus::Failed
    };
    let _ = manifest.save(&run.dir);
    let any_merged = finished
        .iter()
        .any(|r| r.persisted.as_ref().is_some_and(|p| p.merged.is_some()));
    let role_access_path =
        if should_write_role_access(role_aware, &base) || (role_aware && any_merged) {
            match write_role_access(&ctx, &manifest) {
                Ok(p) => Some(p),
                Err(err) => {
                    let w = format!("ROLE-ACCESS.md not written: {err:#}");
                    eprintln!("warning: {w}");
                    warnings.push(w);
                    None
                }
            }
        } else {
            None
        };
    let Some(primary_idx) = primary_idx else {
        state.roles = reports;
        state.warnings = warnings.clone();
        if !role_aware {
            // One anonymous map, as before roles: its own error.
            if let Some(err) = finished.first().and_then(|r| r.error.clone()) {
                bail!("{err}");
            }
        }
        let why: Vec<String> = finished
            .iter()
            .map(|r| {
                format!(
                    "{}: {} ({})",
                    r.name,
                    r.status,
                    r.error.as_deref().unwrap_or("-")
                )
            })
            .collect();
        bail!("no role could be mapped: {}", why.join("; "));
    };
    let primary = &finished[primary_idx];
    let primary_job = jobs
        .iter()
        .find(|j| j.name == primary.name)
        .context("primary role job")?;
    let (Some(out), Some(persisted)) = (primary.out.as_ref(), primary.persisted.as_ref()) else {
        bail!("role '{}' was mapped without a scan result", primary.name);
    };
    state.inventory = Some(persisted.inventory_path.clone());
    dev_report.ready_after_ms = exec.ready_after.map(millis);
    timings.dev_server_ms = dev_report.ready_after_ms;
    timings.warmup_ms = exec.warmup.as_ref().map(|w| w.elapsed_ms);
    timings.scan_ms = Some(out.scan_ms);
    timings.inventory_ms = Some(out.inventory_ms);
    timings.persist_ms = exec.persist_ms.get(&primary.name).copied();

    let inv = persisted
        .merged
        .as_ref()
        .map_or(&out.inventory, |m| &m.inventory);
    let primary_partial_only = primary_job.plan.partial() && persisted.merged.is_none();
    let counts = status_counts(inv);
    if !primary_partial_only {
        let mut summary = summary_line(&inv.coverage, &counts);
        if primary.name != ANONYMOUS_ROLE {
            summary.push_str(&format!(" (as {})", primary.name));
        }
        if let Err(err) = update_registry(&ctx, &summary) {
            let w = format!("registry not updated: {err:#}");
            eprintln!("warning: {w}");
            warnings.push(w);
        }
    }
    // Top-level warnings: the run's own, the primary role's, then the other
    // roles' (prefixed).
    warnings.extend(primary.warnings.iter().cloned());
    for r in finished.iter().filter(|r| r.name != primary.name) {
        warnings.extend(r.warnings.iter().map(|w| format!("[{}] {w}", r.name)));
    }
    for r in &reports {
        if !ok_statuses.contains(&r.status.as_str()) {
            warnings.push(format!(
                "role '{}' not mapped ({}): {}",
                r.role,
                r.status,
                r.error.as_deref().unwrap_or("-")
            ));
        }
    }
    let mut view_budget_next_hints: Vec<String> = Vec::new();
    for r in std::iter::once(primary).chain(finished.iter().filter(|r| r.name != primary.name)) {
        if r.status != "mapped" {
            continue;
        }
        let (Some(r_out), Some(r_persisted)) = (r.out.as_ref(), r.persisted.as_ref()) else {
            continue;
        };
        let r_inv = r_persisted
            .merged
            .as_ref()
            .map_or(&r_out.inventory, |m| &m.inventory);
        let hint_role = role_aware.then_some(r.name.as_str());
        if let Some((warn, cmd)) = single_route_view_budget_hint(
            r_inv,
            r_out.scan.stop_reason.as_deref(),
            hint_role,
            explicit_state_dir.as_deref(),
        ) {
            let msg = if r.name == primary.name {
                warn
            } else {
                format!("[{}] {warn}", r.name)
            };
            warnings.push(msg);
            if !view_budget_next_hints.contains(&cmd) {
                view_budget_next_hints.push(cmd);
            }
        }
    }

    let n = |k: &str| counts.get(k).copied().unwrap_or(0);
    let map_dir = (!primary_partial_only).then(|| primary_job.paths.map_dir.clone());
    let dead_ui = map_dir
        .as_ref()
        .map(|d| d.join("DEAD-UI.md"))
        .filter(|p| p.is_file());
    let mut changed = primary_job.changed.clone();
    if let (Some(report), Some(merged)) = (changed.as_mut(), persisted.merged.as_ref()) {
        report.recrawled_routes = merged.recrawled.clone();
    }
    let exit_code = if all_ok { 0 } else { 3 };
    let dead = n("dead");
    let broken = n("broken");
    let inventory_str = persisted.inventory_path.display().to_string();
    let is_budget_stop = |reason: Option<&str>| {
        matches!(
            reason,
            Some("max_views_reached" | "max_duration_reached" | "hard_timeout")
        )
    };
    let incomplete = out.scan.queue_remaining.is_some_and(|q| q > 0)
        || is_budget_stop(out.scan.stop_reason.as_deref())
        || reports.iter().any(|r| {
            r.queue_remaining.is_some_and(|q| q > 0) || is_budget_stop(r.stop_reason.as_deref())
        });
    let resumable_full = base.mode == ScanMode::Full
        && !manifest.incremental
        && manifest.roles.iter().any(RunRole::has_remaining_work);
    let has_dead_or_broken = dead > 0
        || broken > 0
        || reports.iter().any(|r| {
            r.status_counts.get("dead").copied().unwrap_or(0) > 0
                || r.status_counts.get("broken").copied().unwrap_or(0) > 0
        });
    let mut next = build_next_hints(&NextHintsInput {
        partial: primary_partial_only,
        inventory: &inventory_str,
        resumable_full,
        incomplete,
        has_dead_or_broken,
        role_aware,
        state_dir: explicit_state_dir.as_deref(),
    });
    for cmd in view_budget_next_hints {
        if !next.contains(&cmd) {
            if let Some(pos) = next
                .iter()
                .position(|h| h.starts_with("brokenapp map --full") && !h.contains("--view-budget"))
            {
                next[pos] = cmd;
            } else {
                next.push(cmd);
            }
        }
    }
    let top_unvisited = dedup_unvisited_by_reason(
        unvisited_by_reason(inv, &out.facts, exec.warmup.as_ref()),
        &inv.coverage,
        !reports.is_empty(),
    );
    let mut top_coverage = inv.coverage.clone();
    if !reports.is_empty() {
        top_coverage.unvisited_by_reason.clear();
    }
    let report = MapReport {
        exit_code,
        status: if all_ok { "ok" } else { "partial" }.to_string(),
        project: ctx.name().to_string(),
        url: base.url.to_string(),
        only_routes: base.only_routes.clone(),
        write_guard: base.write_guard.clone(),
        max_minutes: base.max_minutes,
        max_views: base.max_views,
        dev_server: dev_report,
        scan_dir: out.scan.output_dir.display().to_string(),
        scan: ScanReport {
            dir: out.scan.output_dir.display().to_string(),
            status: out.scan.status.clone(),
            duration_seconds: out.scan.duration_seconds,
            stop_reason: out.scan.stop_reason.clone(),
            queue_remaining: out.scan.queue_remaining,
            config: primary.run.scan_toml.display().to_string(),
            seeded_routes: primary.seeds,
            route_templates: primary.templates,
            route_framework: exec.discovery.framework.clone(),
            routes_from_source: exec.discovery.routes.len(),
        },
        unvisited_by_reason: top_unvisited,
        warmup: exec.warmup.clone(),
        coverage: top_coverage,
        exercisable: ExercisableCoverage::compute(inv, &counts),
        dead,
        broken,
        no_effect: n("no_effect"),
        status_counts: counts.clone(),
        changes: changes_report(persisted),
        map_dir: map_dir.map(|d| d.display().to_string()),
        dead_ui: dead_ui.map(|p| p.display().to_string()),
        files: persisted
            .files
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        inventory: inventory_str,
        changelog: persisted
            .changelog
            .as_ref()
            .map(|p| p.display().to_string()),
        changed,
        tabs: base.tabs,
        scan_mode: base.mode.as_str().to_string(),
        view_budget_seconds: base.view_budget_seconds,
        stop_reason: out.scan.stop_reason.clone(),
        queue_remaining: out.scan.queue_remaining,
        resolved_limits: resolved_limits(&base),
        run_dir: run.dir.display().to_string(),
        role: role_aware.then(|| primary.name.clone()),
        roles: reports,
        role_access: role_access_path.map(|p| p.display().to_string()),
        resumed: (!manifest.resumed_at.is_empty()).then(|| manifest.ts.clone()),
        next,
        timings: Timings {
            total_ms: millis(run_started.elapsed()),
            ..timings
        },
        warnings,
    };

    if args.json {
        let mut v = serde_json::to_value(&report).context("serialize map report")?;
        redactor.redact_json(&mut v);
        println!(
            "{}",
            serde_json::to_string_pretty(&v).context("serialize map report")?
        );
    } else {
        print_report(&ctx, &report, &redactor);
    }
    Ok(exit_code)
}

fn changes_report(p: &Persisted) -> ChangesReport {
    ChangesReport {
        from: p.changes.from.clone(),
        first_map: p.first_map,
        total: p.changes.changes.len(),
        summary: p.changes.summary.clone(),
        lines: p
            .changes
            .changes
            .iter()
            .take(50)
            .map(|c| c.line.clone())
            .collect(),
    }
}

/// What the shared part of a run produced.
#[derive(Default)]
struct ExecOut {
    ready_after: Option<Duration>,
    warmup: Option<WarmupReport>,
    discovery: RouteDiscovery,
    /// Persist time per role.
    persist_ms: BTreeMap<String, u64>,
}

/// Everything that needs the app: dev server, discovery, sign-in checks,
/// warm-up, then every role's scan, inventory and map files.
async fn execute(
    sh: &Shared<'_>,
    jobs: &mut [RoleJob],
    warnings: &mut Vec<String>,
) -> Result<ExecOut> {
    let ctx = sh.ctx;
    let base = sh.base;
    let mut out = ExecOut {
        ready_after: ensure_app(ctx, sh.args.no_start, &base.url, sh.run, sh.dev, warnings).await?,
        ..Default::default()
    };
    let needs_discovery = jobs
        .iter()
        .any(|j| j.outcome.is_none() && j.plan.incremental.is_none());
    out.discovery = if needs_discovery {
        discover(ctx, base, warnings)
    } else {
        jobs.iter()
            .find_map(|j| j.plan.incremental.as_ref().map(|i| i.discovery.clone()))
            .unwrap_or_default()
    };
    let mut warned_session_ending = false;
    for job in jobs.iter_mut().filter(|j| j.outcome.is_none()) {
        job.seeds = role_seeds(ctx, &job.plan, &out.discovery, &job.lists);
        if !job.seeds.session_ending.is_empty() && !warned_session_ending {
            warned_session_ending = true;
            let w = format!(
                "skipped seeds: {} sign-out/revoke route(s) not seeded: {}",
                job.seeds.session_ending.len(),
                scan_facts::preview(&job.seeds.session_ending, 8)
            );
            eprintln!("warning: {w}");
            warnings.push(w);
        }
    }

    // Authentication is performed once by the guarded scan engine. A separate
    // browser preflight could allow writes and could not prove the crawl's login.

    // One warm-up for every role's seeds (the dev server compiles once).
    let union: BTreeSet<String> = jobs
        .iter()
        .filter(|j| j.outcome.is_none() && j.resume_from.is_none())
        .flat_map(|j| j.seeds.seeds.iter().cloned())
        .collect();
    let union: Vec<String> = union.into_iter().collect();
    let mut warmup_headers = base.compliance.extra_headers.clone();
    warmup_headers.extend(warmup_auth_headers_for_roles(
        ctx,
        &base.url,
        jobs,
        &|name| std::env::var(name).ok(),
    ));
    out.warmup = warm(
        ctx,
        &base.url,
        &union,
        warmup_headers,
        base.compliance.user_agent.clone(),
        Some(out.discovery.framework.as_str()),
        warnings,
    )
    .await;

    let to_scan = jobs.iter().filter(|j| j.outcome.is_none()).count();
    let manual = jobs
        .iter()
        .any(|j| j.outcome.is_none() && j.method() == Some(RoleMethod::Manual));
    let concurrency = if manual {
        if base.role_concurrency > 1 {
            let w = "a role uses manual login: roles are mapped one at a time".to_string();
            eprintln!("warning: {w}");
            warnings.push(w);
        }
        1
    } else {
        base.role_concurrency.min(to_scan.max(1))
    };
    let tabs_each = (base.tabs / concurrency).max(1);
    if concurrency > 1 {
        eprintln!(
            "mapping {to_scan} roles, {concurrency} at a time ({tabs_each} tab{} each)",
            plural(tabs_each)
        );
    }
    let discovery = &out.discovery;
    let persist_ms: std::sync::Mutex<BTreeMap<String, u64>> =
        std::sync::Mutex::new(BTreeMap::new());
    let persist_ref = &persist_ms;
    futures::stream::iter(jobs.iter_mut().filter(|j| j.outcome.is_none()).map(|job| {
        job.plan.tabs = tabs_each;
        async move {
            let disc = job
                .plan
                .incremental
                .as_ref()
                .map(|i| i.discovery.clone())
                .unwrap_or_else(|| discovery.clone());
            let ms = scan_and_persist(sh, job, &disc).await;
            if let Ok(mut m) = persist_ref.lock() {
                m.insert(job.name.clone(), ms);
            }
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<()>>()
    .await;
    out.persist_ms = persist_ms.into_inner().unwrap_or_default();
    Ok(out)
}

/// Scan one role, build its inventory, and save its map. Records the result
/// in `sh.finished` (and `run.json`). Returns the persist time in ms.
async fn scan_and_persist(sh: &Shared<'_>, job: &mut RoleJob, discovery: &RouteDiscovery) -> u64 {
    if *sh.stop.borrow() {
        return 0;
    }
    let mut warnings = Vec::new();
    let prefix = sh.prefix(&job.name);
    let record = |status: &str,
                  error: Option<String>,
                  run: RunPaths,
                  out: Option<ScanOut>,
                  persisted: Option<Persisted>,
                  warnings: Vec<String>,
                  seeds: &Seeds| {
        let error = error.map(|e| sh.redactor.redact(&e));
        let scan_dir = out
            .as_ref()
            .map(|o| o.scan.output_dir.display().to_string());
        let stop_reason = out.as_ref().and_then(|o| o.scan.stop_reason.clone());
        let queue_remaining = out.as_ref().and_then(|o| o.scan.queue_remaining);
        let has_out = out.is_some();
        sh.mark(&job.name, status, |r| {
            r.error = error.clone();
            if scan_dir.is_some() {
                r.scan_dir = scan_dir.clone();
            }
            if has_out {
                r.stop_reason = stop_reason.clone();
                r.queue_remaining = queue_remaining.unwrap_or(0);
            }
        });
        if let Ok(mut f) = sh.finished.lock() {
            f.push(RoleResult {
                name: job.name.clone(),
                status: status.to_string(),
                error,
                run,
                out,
                persisted,
                seeds: seeds.seeds.len(),
                templates: seeds.templates.len(),
                warnings,
            });
        }
    };
    let run = match sh.run.for_role(&job.name) {
        Ok(r) => r,
        Err(err) => {
            record(
                "failed",
                Some(format!("{err:#}")),
                sh.run.clone(),
                None,
                None,
                warnings,
                &job.seeds,
            );
            return 0;
        }
    };
    let scan_out = run.scan_out.display().to_string();
    sh.mark(&job.name, "scanning", |r| {
        r.dir = run.dir.display().to_string();
        r.scan_dir.get_or_insert(scan_out);
    });
    if job.resume_from.is_none() {
        let anon_inv = sh.anon.lock().ok().and_then(|a| a.clone());
        if let Err(err) = write_scan_inputs(
            sh.ctx,
            &job.plan,
            &run,
            &job.seeds,
            &job.resolved,
            anon_inv.as_ref(),
        ) {
            record(
                "failed",
                Some(format!("{err:#}")),
                run,
                None,
                None,
                warnings,
                &job.seeds,
            );
            return 0;
        }
    }
    if job.method() == Some(RoleMethod::Manual) {
        eprintln!(
            "{prefix}role '{}' signs in manually: a browser window opens; sign in there, then press Enter here",
            job.name
        );
    }
    let sp = ScanProc {
        role: &job.name,
        prefix: prefix.clone(),
        env: &job.resolved.env,
        redactor: sh.redactor,
        interactive: job.method() == Some(RoleMethod::Manual),
        resume_from: job.resume_from.as_deref(),
        progress_every: job.plan.progress_every,
        max_minutes: job.plan.max_minutes,
        dev: Some(sh.dev),
        stop: sh.stop,
    };
    let mut scanned = scan_role(
        sh.ctx,
        &job.plan,
        &run,
        &job.seeds,
        discovery,
        &sp,
        &mut warnings,
    )
    .await;
    if *sh.stop.borrow() {
        sh.mark(&job.name, "interrupted", |_| {});
        return 0;
    }
    // A checkpoint the engine cannot resume (corrupt, incompatible): map
    // the role from the start rather than not at all.
    if job.resume_from.is_some()
        && let Err(err) = &scanned
        && let Some(failed) = err.downcast_ref::<ScanFailed>()
        && failed
            .tail
            .iter()
            .any(|l| l.to_ascii_lowercase().contains("checkpoint"))
    {
        let w = format!(
            "the {} checkpoint could not be resumed ({}); mapping the role from the start",
            job.name,
            failed
                .tail
                .iter()
                .rev()
                .find(|l| l.to_ascii_lowercase().contains("checkpoint"))
                .map(|l| l.trim().to_string())
                .unwrap_or_default()
        );
        eprintln!("warning: {prefix}{w}");
        warnings.push(w);
        let anon_inv = sh.anon.lock().ok().and_then(|a| a.clone());
        if let Err(err) = write_scan_inputs(
            sh.ctx,
            &job.plan,
            &run,
            &job.seeds,
            &job.resolved,
            anon_inv.as_ref(),
        ) {
            record(
                "failed",
                Some(format!("{err:#}")),
                run,
                None,
                None,
                warnings,
                &job.seeds,
            );
            return 0;
        }
        let fresh = ScanProc {
            resume_from: None,
            ..sp
        };
        scanned = scan_role(
            sh.ctx,
            &job.plan,
            &run,
            &job.seeds,
            discovery,
            &fresh,
            &mut warnings,
        )
        .await;
    }
    let mut out = match scanned {
        Ok(o) => o,
        Err(err) => {
            let (status, msg) = match err.downcast_ref::<ScanFailed>() {
                Some(failed) => match auth_failure(&run, &failed.tail) {
                    Some(why) if job.name != ANONYMOUS_ROLE => ("login_failed", why),
                    _ => (
                        "failed",
                        format!(
                            "{err:#}{}",
                            failed
                                .tail
                                .iter()
                                .rev()
                                .find(|l| !l.trim().is_empty())
                                .map(|l| format!(" (last scan output: {})", l.trim()))
                                .unwrap_or_default()
                        ),
                    ),
                },
                None => ("failed", format!("{err:#}")),
            };
            let msg = sh.redactor.redact(&msg);
            if sh.role_aware {
                eprintln!("warning: role '{}' {status}: {msg}", job.name);
            }
            record(status, Some(msg), run, None, None, warnings, &job.seeds);
            return 0;
        }
    };

    if matches!(out.scan.status.as_str(), "session_expired" | "login_failed") {
        let status = out.scan.status.clone();
        let why = auth_failure(&run, &[])
            .filter(|detail| !detail.trim().is_empty())
            .unwrap_or_else(|| {
                format!("the scan reported {status}; the previous role map is kept")
            });
        record(
            &status,
            Some(why),
            run,
            Some(out),
            None,
            warnings,
            &job.seeds,
        );
        return 0;
    }

    // A saved session / cookie / token that no longer works maps the
    // logged-out app under the role's name: refuse to save that.
    if job.name != ANONYMOUS_ROLE && job.resolved.method != RoleMethod::Form {
        let anon = sh.anon.lock().ok().and_then(|a| a.clone()).or_else(|| {
            let p = sh.ctx.role_paths(ANONYMOUS_ROLE).latest_inventory_path();
            p.is_file().then(|| inventory::load(&p).ok()).flatten()
        });
        if let Some(why) = anon
            .as_ref()
            .and_then(|a| looks_logged_out(&out.inventory, a))
        {
            eprintln!(
                "warning: {prefix}role '{}' session_expired: {why}; its previous map is kept",
                job.name
            );
            record(
                "session_expired",
                Some(why),
                run,
                Some(out),
                None,
                warnings,
                &job.seeds,
            );
            return 0;
        }
    }

    // Never overwrite a non-empty existing whole-app map with a 0-route timeout/error run.
    if let Some(prev_visited) = should_preserve_previous_map(
        &job.paths,
        &job.plan,
        &out.inventory,
        out.scan.stop_reason.as_deref(),
    ) {
        let reason = out.scan.stop_reason.as_deref().unwrap_or("timeout");
        let why = format!(
            "scan ended with {reason} and 0 visited routes; preserved previous good map ({prev_visited} visited route{}) instead of overwriting latest.inventory.json and map/",
            plural(prev_visited as usize)
        );
        eprintln!(
            "warning: {prefix}role '{}' timed_out_empty: {why}",
            job.name
        );
        warnings.push(why.clone());
        record(
            "timed_out_empty",
            Some(why),
            run,
            Some(out),
            None,
            warnings,
            &job.seeds,
        );
        return 0;
    }

    if job.name != ANONYMOUS_ROLE {
        out.inventory.role = Some(job.name.clone());
    }
    out.inventory.started_at = Some(sh.started_at.to_string());
    let persist_started = Instant::now();
    let persisted = match persist(
        &job.paths,
        &job.plan,
        &run.ts,
        &out.inventory,
        sh.started_at,
        &mut warnings,
    ) {
        Ok(p) => p,
        Err(err) => {
            record(
                "failed",
                Some(format!("{err:#}")),
                run,
                Some(out),
                None,
                warnings,
                &job.seeds,
            );
            return 0;
        }
    };
    let ms = millis(persist_started.elapsed());
    if let (Some(report), Some(merged)) = (job.changed.as_mut(), persisted.merged.as_ref()) {
        report.recrawled_routes = merged.recrawled.clone();
        for r in &merged.kept {
            if !report.kept_routes.contains(r) {
                let w = format!(
                    "affected route {r} was not reached by the re-crawl; kept from the previous map"
                );
                eprintln!("warning: {prefix}{w}");
                warnings.push(w);
                report.kept_routes.push(r.clone());
            }
        }
        report.kept_routes.sort();
    }
    if job.name == ANONYMOUS_ROLE {
        let inv = persisted
            .merged
            .as_ref()
            .map_or(&out.inventory, |m| &m.inventory)
            .clone();
        if let Ok(mut a) = sh.anon.lock() {
            *a = Some(inv);
        }
    }
    if sh.role_aware {
        let inv = persisted
            .merged
            .as_ref()
            .map_or(&out.inventory, |m| &m.inventory);
        eprintln!(
            "{prefix}mapped: {}",
            summary_line(&inv.coverage, &status_counts(inv))
        );
    }
    record(
        "mapped",
        None,
        run,
        Some(out),
        Some(persisted),
        warnings,
        &job.seeds,
    );
    ms
}

/// Per-role reports in run order.
fn final_reports(
    ctx: &ProjectCtx,
    jobs: &[RoleJob],
    finished: &[RoleResult],
    manifest: &RunManifest,
    role_aware: bool,
) -> Vec<RoleReport> {
    if !role_aware {
        return Vec::new();
    }
    jobs.iter()
        .map(|j| {
            let result = finished.iter().find(|r| r.name == j.name);
            let mut report = role_report(ctx, j, result);
            if result.is_none() && j.outcome.is_none() {
                report.status = manifest
                    .roles
                    .iter()
                    .find(|r| r.name == j.name)
                    .map(|r| r.status.clone())
                    .filter(|s| s != "scanning")
                    .unwrap_or_else(|| "interrupted".to_string());
            }
            report
        })
        .collect()
}

fn role_report(ctx: &ProjectCtx, job: &RoleJob, result: Option<&RoleResult>) -> RoleReport {
    let (status, error) = match (result, &job.outcome) {
        (Some(r), _) => (r.status.clone(), r.error.clone()),
        (None, Some((s, why))) => (s.clone(), why.clone()),
        (None, None) => ("pending".to_string(), None),
    };
    let mut report = RoleReport {
        role: job.name.clone(),
        method: job.method().map(|m| m.as_str().to_string()),
        status,
        error,
        stop_reason: None,
        queue_remaining: None,
        credentials: job.resolved.sources.clone(),
        map_dir: rel(&job.paths.map_dir, &ctx.root),
        inventory: None,
        scan_dir: None,
        coverage: None,
        exercisable: None,
        status_counts: BTreeMap::new(),
        unvisited_by_reason: BTreeMap::new(),
        changes: None,
        changed: job.changed.clone(),
        warnings: result.map(|r| r.warnings.clone()).unwrap_or_default(),
    };
    if let Some(r) = result {
        if let Some(out) = &r.out {
            report.scan_dir = Some(out.scan.output_dir.display().to_string());
            report.stop_reason = out.scan.stop_reason.clone();
            report.queue_remaining = out.scan.queue_remaining;
        }
        if let (Some(out), Some(p)) = (&r.out, &r.persisted) {
            let inv = p.merged.as_ref().map_or(&out.inventory, |m| &m.inventory);
            let counts = status_counts(inv);
            report.inventory = Some(p.inventory_path.display().to_string());
            report.coverage = Some(inv.coverage.clone());
            report.exercisable = Some(ExercisableCoverage::compute(inv, &counts));
            report.unvisited_by_reason = dedup_unvisited_by_reason(
                unvisited_by_reason(inv, &out.facts, None),
                &inv.coverage,
                false,
            );
            report.status_counts = counts;
            report.changes = Some(changes_report(p));
        }
    }
    report
}

/// Format a role's `This run` cell for `ROLE-ACCESS.md` and `map/README.md`.
/// Successful outcomes stay plain (`mapped`, `unchanged`); failure outcomes
/// include a single-line, pipe-safe, length-capped summary of `role.error`.
fn format_this_run(role: &RunRole) -> String {
    if matches!(role.status.as_str(), "mapped" | "unchanged") {
        return role.status.clone();
    }
    let Some(raw_detail) = role.error.as_deref() else {
        return role.status.clone();
    };
    let collapsed: String = raw_detail.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut trimmed = collapsed.as_str();
    loop {
        if let Some(rest) = trimmed.strip_prefix("error:") {
            trimmed = rest.trim_start();
        } else if let Some(rest) = trimmed
            .strip_prefix(role.status.as_str())
            .and_then(|s| s.strip_prefix(':'))
        {
            trimmed = rest.trim_start();
        } else {
            break;
        }
    }
    if trimmed.is_empty() {
        return role.status.clone();
    }
    const MAX_DETAIL_CHARS: usize = 120;
    let truncated = if trimmed.chars().count() > MAX_DETAIL_CHARS {
        let mut s: String = trimmed
            .chars()
            .take(MAX_DETAIL_CHARS.saturating_sub(3))
            .collect();
        s.push_str("...");
        s
    } else {
        trimmed.to_string()
    };
    let safe = truncated.replace('|', "\\|");
    format!("{} ({safe})", role.status)
}

/// Rebuild `ROLE-ACCESS.md`, `role-access.tsv` and `map/README.md` from
/// every role's latest map.
fn write_role_access(ctx: &ProjectCtx, manifest: &RunManifest) -> Result<PathBuf> {
    // The anonymous column only when it is mapped or has a map.
    let names: Vec<String> = ctx
        .role_names()
        .into_iter()
        .filter(|n| {
            n != ANONYMOUS_ROLE
                || ctx.config.auth.include_anonymous()
                || ctx.role_paths(n).latest_inventory_path().is_file()
        })
        .collect();
    let loaded: Vec<Option<Inventory>> = names
        .iter()
        .map(|n| {
            let p = ctx.role_paths(n).latest_inventory_path();
            p.is_file().then(|| inventory::load(&p).ok()).flatten()
        })
        .collect();
    let method = |n: &str| {
        roles::find_role(&ctx.config, n)
            .map(|r| r.method.as_str().to_string())
            .unwrap_or_else(|| "-".to_string())
    };
    let role_entry = |n: &str| manifest.roles.iter().find(|r| r.name == n);
    let this_run_status = |n: &str| role_entry(n).map(|r| r.status.as_str());
    let this_run_display = |n: &str| role_entry(n).map(format_this_run);
    let maps: Vec<role_access::RoleMap<'_>> = names
        .iter()
        .zip(&loaded)
        .map(|(n, inv)| role_access::RoleMap {
            name: n.clone(),
            method: method(n),
            // Retain old map files, but never present their access as evidence
            // from a role whose current run failed or expired.
            inventory: inv
                .as_ref()
                .filter(|_| this_run_status(n).is_none_or(|s| matches!(s, "mapped" | "unchanged"))),
            this_run: this_run_display(n),
        })
        .collect();
    let ra = role_access::build(ctx.name(), &maps);
    let index: Vec<role_access::IndexRow> = names
        .iter()
        .zip(&loaded)
        .map(|(n, inv)| {
            let paths = ctx.role_paths(n);
            role_access::IndexRow {
                name: n.clone(),
                method: method(n),
                dir: paths
                    .map_dir
                    .strip_prefix(ctx.map_dir())
                    .map(|p| {
                        let s = p.display().to_string();
                        if s.is_empty() {
                            "./".to_string()
                        } else {
                            format!("{s}/")
                        }
                    })
                    .unwrap_or_else(|_| paths.map_dir.display().to_string()),
                map_at: inv.as_ref().map(|i| i.generated_at.clone()),
                coverage: inv.as_ref().map(|i| inventory::render::coverage_line(i)),
                this_run: this_run_display(n),
            }
        })
        .collect();
    role_access::write(&ctx.map_dir(), &ra, &index)?;
    Ok(ctx.map_dir().join(role_access::ROLE_ACCESS_MD))
}

/// First 12 characters of a commit; times unchanged.
fn short_base(base: &str) -> String {
    if base.len() == 40 && base.bytes().all(|b| b.is_ascii_hexdigit()) {
        base.chars().take(12).collect()
    } else {
        base.to_string()
    }
}

/// `2 test: a.test.ts, b.spec.ts; 1 docs: README.md`.
fn unmapped_summary(files: &[UnmappedFile]) -> String {
    let mut by_kind: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for f in files {
        by_kind
            .entry(f.kind.as_str())
            .or_default()
            .push(f.file.clone());
    }
    by_kind
        .iter()
        .map(|(kind, files)| format!("{} {kind}: {}", files.len(), scan_facts::preview(files, 4)))
        .collect::<Vec<_>>()
        .join("; ")
}

fn changed_source_text(c: &ChangedReport) -> String {
    match c.change_source.as_str() {
        "git" => format!("git since {}", short_base(&c.change_base)),
        "mtime" => format!("modified after {}", c.change_base),
        _ => String::new(),
    }
}

/// `map --changed` with nothing to scan.
#[allow(clippy::too_many_arguments)]
fn print_skipped(
    ctx: &ProjectCtx,
    plan: &MapPlan,
    changed: ChangedReport,
    roles: Vec<RoleReport>,
    timings: Timings,
    warnings: Vec<String>,
    state_dir: Option<&str>,
    json: bool,
) -> Result<()> {
    let message = format!(
        "{}; the map is unchanged",
        changed
            .mode_reason
            .as_deref()
            .unwrap_or("no UI routes affected")
    );
    let note = "No new snapshot written (latest map is unchanged).".to_string();
    let sd = state_dir_flag(state_dir);
    if json {
        let report = SkippedReport {
            exit_code: 0,
            status: "ok".to_string(),
            project: ctx.name().to_string(),
            url: plan.url.to_string(),
            message,
            note,
            next: vec![
                format!("brokenapp map --changed --force{sd}"),
                format!("brokenapp map{sd}"),
            ],
            changed,
            roles,
            timings,
            warnings,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize map report")?
        );
        return Ok(());
    }
    let source = changed_source_text(&changed);
    if source.is_empty() {
        println!("{message}.");
    } else {
        println!("{message} ({source}).");
    }
    println!("  note      {note}");
    if !changed.unmapped_files.is_empty() {
        println!("  unmapped  {}", unmapped_summary(&changed.unmapped_files));
    }
    for (route, why) in changed
        .affected_routes
        .iter()
        .filter(|a| changed.kept_routes.contains(&a.route))
        .map(|a| (&a.route, a.reasons.join("; ")))
    {
        println!("  affected  {route} (not crawlable): {why}");
    }
    for r in roles.iter().filter(|r| r.status != "unchanged") {
        println!(
            "  role      {}: {}{}",
            r.role,
            r.status,
            r.error
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        );
    }
    for w in &warnings {
        println!("  warning   {w}");
    }
    println!(
        "next: brokenapp map --changed --force{sd} (map anyway) | brokenapp map{sd} (whole-app map)"
    );
    Ok(())
}

fn print_changed(c: &ChangedReport, known_routes: u32) {
    let n = c.changed_files.len();
    let source = changed_source_text(c);
    let head = format!(
        "{n} file{}{}",
        plural(n),
        if source.is_empty() {
            String::new()
        } else {
            format!(" ({source})")
        }
    );
    match c.mode.as_str() {
        "incremental" => println!(
            "  changed   {head}: incremental, re-crawled {} of {} routes: {}",
            c.recrawled_routes.len(),
            known_routes,
            scan_facts::preview(&c.recrawled_routes, 6)
        ),
        _ => println!(
            "  changed   {head}: whole-app map ({})",
            c.mode_reason.as_deref().unwrap_or("whole-app")
        ),
    }
    if !c.kept_routes.is_empty() {
        println!(
            "  kept      {} affected route{} not re-crawled (previous entries kept): {}",
            c.kept_routes.len(),
            plural(c.kept_routes.len()),
            scan_facts::preview(&c.kept_routes, 6)
        );
    }
    if !c.unmapped_files.is_empty() {
        println!("  unmapped  {}", unmapped_summary(&c.unmapped_files));
    }
}

fn print_report(ctx: &ProjectCtx, r: &MapReport, redactor: &Redactor) {
    let cov = &r.coverage;
    let scope = if r.only_routes.is_empty() {
        String::new()
    } else {
        format!(" [routes: {}]", r.only_routes.join(", "))
    };
    let as_role = r
        .role
        .as_deref()
        .map(|role| format!(" as {role}"))
        .unwrap_or_default();
    println!(
        "Mapped {} ({}){as_role}{scope}: scan {} in {}, write guard {}{}",
        r.project,
        r.url,
        r.scan.status,
        scan_facts::clock(r.scan.duration_seconds.unwrap_or_default() as u64),
        r.write_guard,
        if r.scan_mode == "full" {
            ", full mode"
        } else {
            ""
        }
    );
    let incomplete_stop = r
        .stop_reason
        .as_deref()
        .is_some_and(|s| s != "queue_exhausted");
    let queued = r.queue_remaining.unwrap_or(0);
    if incomplete_stop || queued > 0 {
        let reason = r.stop_reason.as_deref().unwrap_or("unknown");
        println!(
            "  stopped   {reason} ({queued} queued route{} remaining)",
            plural(queued)
        );
    }
    if let Some(c) = &r.changed {
        print_changed(c, r.coverage.routes_known);
    }
    let mut routes_line = format!(
        "  routes    {}/{} visited",
        cov.routes_visited,
        cov.routes_known.max(cov.routes_visited)
    );
    let display_unvisited: Option<&BTreeMap<String, Vec<String>>> =
        if !r.unvisited_by_reason.is_empty() {
            Some(&r.unvisited_by_reason)
        } else if !cov.unvisited_by_reason.is_empty() {
            Some(&cov.unvisited_by_reason)
        } else {
            r.roles
                .iter()
                .find(|role| r.role.as_deref() == Some(role.role.as_str()))
                .and_then(|role| {
                    if !role.unvisited_by_reason.is_empty() {
                        Some(&role.unvisited_by_reason)
                    } else {
                        role.coverage
                            .as_ref()
                            .map(|c| &c.unvisited_by_reason)
                            .filter(|m| !m.is_empty())
                    }
                })
        };
    if let Some(unvisited_map) = display_unvisited {
        let groups: Vec<String> = unvisited_map
            .iter()
            .map(|(reason, routes)| {
                let mut label = scan_facts::unvisited_reason_label(reason);
                if !r.roles.is_empty() {
                    label = label.replace(" (add a role to map them)", "");
                }
                format!(
                    "{} {label}: {}",
                    routes.len(),
                    scan_facts::preview(routes, 5)
                )
            })
            .collect();
        routes_line.push_str("; not visited: ");
        routes_line.push_str(&groups.join("; "));
    } else if !cov.unvisited_routes.is_empty() {
        routes_line.push_str(&format!(
            ", {} known but not visited",
            cov.unvisited_routes.len()
        ));
    }
    println!("{routes_line}");
    let ex = &r.exercisable;
    let mut not_exercisable = Vec::new();
    for (label, n) in [
        ("external", ex.external),
        ("disabled", ex.disabled),
        ("skipped", ex.skipped),
    ] {
        if n > 0 {
            not_exercisable.push(format!("{n} {label}"));
        }
    }
    let others: Vec<String> = r
        .status_counts
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "dead" | "broken" | "no_effect"))
        .map(|(k, v)| format!("{k} {v}"))
        .collect();
    println!(
        "  controls  {}/{} exercisable exercised ({} total{}); dead {}, broken {}, no effect {}; {}",
        ex.exercised,
        ex.exercisable,
        ex.total,
        if not_exercisable.is_empty() {
            String::new()
        } else {
            format!(": {}", not_exercisable.join(", "))
        },
        r.dead,
        r.broken,
        r.no_effect,
        others.join(", ")
    );
    if let Some(w) = &r.warmup {
        let mut notes = Vec::new();
        let capped = w.capped_count();
        if capped > 0 {
            let total = w.requested + capped;
            notes.push(format!(
                "cap {} of {total} seeded routes; {capped} lazy-compiled on visit",
                w.requested
            ));
        }
        if !w.failed.is_empty() {
            notes.push(format!("{} failed (see warnings)", w.failed.len()));
        }
        let suffix = if notes.is_empty() {
            String::new()
        } else {
            format!(" ({})", notes.join("; "))
        };
        println!(
            "  warm-up   {}/{} warmed in {:.1}s{suffix}",
            w.ok,
            w.requested,
            w.elapsed_ms as f64 / 1000.0
        );
    }
    if r.changes.first_map {
        println!("  changes   first map (baseline recorded)");
    } else if r.changes.total == 0 {
        println!("  changes   none since the previous map");
    } else {
        let kinds: Vec<String> = r
            .changes
            .summary
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect();
        println!("  changes   {} ({})", r.changes.total, kinds.join(", "));
        for line in r.changes.lines.iter().take(10) {
            println!("    {line}");
        }
        if r.changes.total > 10 {
            println!("    ... see `brokenapp changes` for the full list");
        }
    }
    match &r.map_dir {
        Some(dir) => {
            let names: Vec<String> = r
                .files
                .iter()
                .filter_map(|f| {
                    Path::new(f)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                })
                .collect();
            println!(
                "  map       {}/ ({})",
                rel(Path::new(dir), &ctx.root),
                names.join(", ")
            );
        }
        None => {
            let inv_rel = rel(Path::new(&r.inventory), &ctx.root);
            println!("  inventory {inv_rel} (partial map; whole-app map files unchanged)");
            println!(
                "  query     brokenapp ui --inventory {inv_rel} --compact | brokenapp journey <goal> --inventory {inv_rel}"
            );
        }
    }
    if let Some(dead_ui) = &r.dead_ui {
        println!(
            "  review    {}: {} dead, {} broken, {} no effect, plus coverage caveats; read it before trusting \"0 dead\"",
            rel(Path::new(dead_ui), &ctx.root),
            r.dead,
            r.broken,
            r.no_effect
        );
    }
    for role in &r.roles {
        let detail = match (&role.coverage, &role.exercisable) {
            (Some(cov), Some(ex)) if role.status == "mapped" => {
                let mut line = format!(
                    "{}/{} routes, {}/{} controls exercised, {} dead, {} broken; map {}",
                    cov.routes_visited,
                    cov.routes_known.max(cov.routes_visited),
                    ex.exercised,
                    ex.exercisable,
                    role.status_counts.get("dead").copied().unwrap_or(0),
                    role.status_counts.get("broken").copied().unwrap_or(0),
                    role.map_dir
                );
                let role_incomplete = role
                    .stop_reason
                    .as_deref()
                    .is_some_and(|s| s != "queue_exhausted");
                let role_queued = role.queue_remaining.unwrap_or(0);
                if role_incomplete || role_queued > 0 {
                    line.push_str(&format!(
                        "; stopped {} ({role_queued} queued)",
                        role.stop_reason.as_deref().unwrap_or("unknown")
                    ));
                }
                line
            }
            _ => role
                .error
                .clone()
                .map(|e| {
                    if role.status == "unchanged" {
                        e
                    } else {
                        format!("{e}; skipped (previous map kept)")
                    }
                })
                .unwrap_or_default(),
        };
        let status = if matches!(role.status.as_str(), "mapped" | "unchanged") {
            role.status.clone()
        } else {
            role.status.to_ascii_uppercase()
        };
        println!(
            "  role      {}{}: {status}{}",
            role.role,
            role.method
                .as_deref()
                .map(|m| format!(" ({m})"))
                .unwrap_or_default(),
            if detail.is_empty() {
                String::new()
            } else {
                format!(", {}", redactor.redact(&detail))
            }
        );
    }
    if let Some(access) = &r.role_access {
        println!(
            "  access    {}: route x role matrix, controls that differ by role, review flags",
            rel(Path::new(access), &ctx.root)
        );
    }
    if let Some(ts) = &r.resumed {
        println!("  resumed   run {ts}");
    }
    for w in &r.warnings {
        println!("  warning   {}", redactor.redact(w));
    }
    if !r.only_routes.is_empty() {
        let inv_rel = rel(Path::new(&r.inventory), &ctx.root);
        let mut cmds = vec![
            format!("brokenapp ui --inventory {inv_rel} --compact"),
            format!("brokenapp journey <goal> --inventory {inv_rel}"),
        ];
        for hint in &r.next {
            if hint.starts_with("brokenapp map ") {
                cmds.push(hint.clone());
            }
        }
        println!("next: {}", cmds.join(" | "));
    } else if r.roles.is_empty() {
        let map_hint = r
            .next
            .iter()
            .find(|h| h.starts_with("brokenapp map "))
            .map(|h| format!("{h} | "))
            .unwrap_or_default();
        println!(
            "next: {map_hint}brokenapp dead | brokenapp ui --route / | brokenapp journey <route|\"METHOD /path\"> | brokenapp changes"
        );
    } else {
        let map_hint = r
            .next
            .iter()
            .find(|h| h.starts_with("brokenapp map "))
            .map(|h| format!("{h} | "))
            .unwrap_or_default();
        println!(
            "next: {map_hint}brokenapp dead --role <role> | brokenapp ui --role <role> --route / | brokenapp ui --role all --text <label> | read ROLE-ACCESS.md"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BrokenAppConfig, WriteGuardMode};
    use crate::front::project::{ProjectConfig, ProjectSection, RegistryEntry};

    fn ctx_with(cfg: ProjectConfig, dir: &Path) -> ProjectCtx {
        ProjectCtx {
            state_dir: dir.join(".brokenapp"),
            root: dir.to_path_buf(),
            config_path: dir.join(".brokenapp/config.toml"),
            config: cfg,
        }
    }

    fn cfg(url: &str) -> ProjectConfig {
        ProjectConfig {
            project: ProjectSection {
                name: "demo".into(),
                url: url.into(),
                codebase: ".".into(),
                ready_timeout_secs: 120,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn args() -> MapArgs {
        MapArgs {
            routes: Vec::new(),
            no_merge: false,
            full: false,
            mode: None,
            roles_only: Vec::new(),
            roles: None,
            resume: false,
            changed: false,
            since: None,
            force: false,
            tabs: None,
            quick: false,
            max_minutes: None,
            max_views: None,
            depth: None,
            max_interactions: None,
            view_budget: None,
            allow_writes: false,
            no_start: false,
            headed: false,
            json: false,
            target: ProjectTarget::default(),
        }
    }

    #[test]
    fn budgets_quick_and_overrides() {
        assert_eq!(budgets(10, 80, false, None, None), (10, 80));
        assert_eq!(budgets(10, 80, true, None, None), (3, 25));
        assert_eq!(budgets(10, 80, true, Some(5), None), (5, 25));
        assert_eq!(budgets(10, 80, false, Some(1), Some(7)), (1, 7));
    }

    #[test]
    fn plan_refuses_protected_and_remote() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::default();

        let mut c = cfg("http://localhost:3000");
        c.project.protected = true;
        let err = make_plan(&ctx_with(c, dir.path()), &args(), &reg).unwrap_err();
        assert!(format!("{err:#}").contains("protected"));

        let err = make_plan(
            &ctx_with(cfg("https://example.com"), dir.path()),
            &args(),
            &reg,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not a local development host"));

        let mut c = cfg("https://example.com");
        c.scan.allow_remote = true;
        assert!(make_plan(&ctx_with(c, dir.path()), &args(), &reg).is_ok());

        let ctx = ctx_with(cfg("http://localhost:3000"), dir.path());
        let reg = Registry {
            projects: vec![RegistryEntry {
                name: "demo".into(),
                state_dir: ctx.state_dir.display().to_string(),
                protected: true,
                ..Default::default()
            }],
        };
        let err = make_plan(&ctx, &args(), &reg).unwrap_err();
        assert!(format!("{err:#}").contains("protected in the registry"));
    }

    #[test]
    fn plan_write_guard_modes() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::default();
        let ctx = ctx_with(cfg("http://127.0.0.1:3000"), dir.path());
        assert_eq!(make_plan(&ctx, &args(), &reg).unwrap().write_guard, "block");
        let mut a = args();
        a.allow_writes = true;
        assert_eq!(make_plan(&ctx, &a, &reg).unwrap().write_guard, "off");

        let mut c = cfg("http://127.0.0.1:3000");
        c.scan.write_guard = "nope".into();
        assert!(make_plan(&ctx_with(c, dir.path()), &args(), &reg).is_err());
    }

    #[test]
    fn seeds_merge_filter_and_route_override() {
        let (seeds, session_ending) = seed_routes(
            vec![
                "/".into(),
                "/about".into(),
                "/logout".into(),
                "/admin/users".into(),
            ],
            &["pricing".into(), "/about".into()],
            &["/logout".into(), "/admin/".into()],
            &[],
        );
        assert_eq!(seeds, vec!["/", "/about", "/pricing"]);
        assert!(
            session_ending.is_empty(),
            "excluded routes are not reported"
        );
        let (only, _) = seed_routes(vec!["/".into()], &["/x".into()], &[], &["/checkout".into()]);
        assert_eq!(only, vec!["/checkout"]);
        assert!(!is_excluded("/login", &["/log".into()]));
    }

    #[test]
    fn discovered_sign_out_pages_are_never_seeded() {
        let (seeds, session_ending) = seed_routes(
            vec!["/".into(), "/auth/sign-out".into(), "/logout".into()],
            &["/signout-help".into()],
            &[],
            &[],
        );
        assert_eq!(
            seeds,
            vec!["/", "/signout-help"],
            "explicit extra routes are kept"
        );
        assert_eq!(session_ending, vec!["/auth/sign-out", "/logout"]);
        let (only, _) = seed_routes(vec![], &[], &[], &["/logout".into()]);
        assert_eq!(only, vec!["/logout"], "--route is honored as given");
    }

    #[test]
    fn tabs_default_to_four_and_flags_override_config() {
        let path = Path::new("/r/.brokenapp/config.toml");
        assert_eq!(tabs(None, None, path).unwrap(), 4);
        assert_eq!(tabs(Some(2), None, path).unwrap(), 2);
        assert_eq!(tabs(Some(2), Some(6), path).unwrap(), 6);
        assert!(tabs(None, Some(0), path).is_err());
        assert!(format!("{:#}", tabs(Some(64), None, path).unwrap_err()).contains("scan.tabs"));
        // --quick shrinks the budget, not the tabs.
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg("http://127.0.0.1:3000");
        c.scan.tabs = Some(3);
        let mut a = args();
        a.quick = true;
        let plan = make_plan(&ctx_with(c, dir.path()), &a, &Registry::default()).unwrap();
        assert_eq!((plan.max_minutes, plan.max_views, plan.tabs), (3, 25, 3));
    }

    /// An Astro site with a previous map whose run started an hour after the
    /// files were written.
    fn changed_fixture() -> (tempfile::TempDir, ProjectCtx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("site");
        for (rel, body) in [
            ("package.json", r#"{"dependencies":{"astro":"5.0.0"}}"#),
            ("astro.config.mjs", "export default {}\n"),
            ("README.md", "# site\n"),
            ("src/pages/index.astro", "<a href=\"/about\">About</a>\n"),
            ("src/pages/about.astro", "<button>Call</button>\n"),
            ("src/pages/towns/[slug].astro", "<p />\n"),
            ("src/pages/logout.astro", "<p />\n"),
            ("src/pages/contact.astro", "<p />\n"),
            ("src/pages/pricing.astro", "<p />\n"),
            ("src/pages/faq.astro", "<p />\n"),
            ("src/pages/blog.astro", "<p />\n"),
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body).unwrap();
            let past = std::time::SystemTime::now() - Duration::from_secs(7200);
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(past)
                .unwrap();
        }
        let mut c = cfg("http://127.0.0.1:3000");
        c.scan.exclude_routes = vec!["/logout".into()];
        let ctx = ProjectCtx {
            root,
            ..ctx_with(c, dir.path())
        };
        let route = |r: &str, file: &str, variants: &[&str]| crate::inventory::RouteEntry {
            route: r.into(),
            visited: true,
            source: Some(format!("{file}:1")),
            variants: variants.iter().map(|v| v.to_string()).collect(),
            ..Default::default()
        };
        let prior_run = ctx.scans_dir().join("previous");
        std::fs::create_dir_all(prior_run.join("scan")).unwrap();
        std::fs::write(prior_run.join("scan.toml"), "[scan]\n").unwrap();
        let latest = Inventory {
            scan_dir: prior_run.join("scan").display().to_string(),
            schema: inventory::INVENTORY_SCHEMA.into(),
            identity_version: IDENTITY_VERSION,
            generated_at: "2026-10-22T10:00:00Z".into(),
            started_at: Some(
                (chrono::Utc::now() - chrono::Duration::hours(1))
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ),
            routes: vec![
                route("/", "src/pages/index.astro", &[]),
                route("/about", "src/pages/about.astro", &[]),
                route("/contact", "src/pages/contact.astro", &[]),
                route("/pricing", "src/pages/pricing.astro", &[]),
                route("/faq", "src/pages/faq.astro", &[]),
                route("/blog", "src/pages/blog.astro", &[]),
                route(
                    "/towns/:slug",
                    "src/pages/towns/[slug].astro",
                    &["/towns/ames", "/towns/boone"],
                ),
            ],
            ..Default::default()
        };
        inventory::save(&latest, &ctx.latest_inventory_path()).unwrap();
        (dir, ctx)
    }

    fn touch(ctx: &ProjectCtx, rel: &str, body: &str) {
        std::fs::write(ctx.root.join(rel), body).unwrap();
    }

    #[test]
    fn changed_skips_maps_incrementally_or_falls_back_to_a_full_map() {
        let (_dir, ctx) = changed_fixture();
        let mut warnings = Vec::new();
        let mut a = args();
        a.changed = true;
        let paths = ctx.role_paths(ANONYMOUS_ROLE);
        let lists = route_lists(&ctx, ANONYMOUS_ROLE);
        let plan_changed = |ctx: &ProjectCtx, a: &MapArgs, w: &mut Vec<String>| {
            plan_changed(ctx, &paths, &lists, a, w)
        };

        // Nothing changed since the previous map.
        let ChangedDecision::Skip(r) = plan_changed(&ctx, &a, &mut warnings).unwrap() else {
            panic!("expected a skip");
        };
        assert_eq!(r.mode, "skipped");
        assert_eq!(r.change_source, "mtime");
        assert!(r.mode_reason.unwrap().contains("no files changed"));

        // Docs only: reported, not mapped.
        touch(&ctx, "README.md", "# changed\n");
        let ChangedDecision::Skip(r) = plan_changed(&ctx, &a, &mut warnings).unwrap() else {
            panic!("expected a skip");
        };
        assert_eq!(
            r.mode_reason.as_deref(),
            Some("no UI routes affected by 1 changed file")
        );
        assert_eq!(r.unmapped_files[0].kind, "docs");
        // --force maps anyway.
        let mut forced = args();
        forced.changed = true;
        forced.force = true;
        assert!(matches!(
            plan_changed(&ctx, &forced, &mut warnings).unwrap(),
            ChangedDecision::Full(_)
        ));

        // A page and a dynamic route: seeded with the pages the map visited;
        // the excluded sign-out page does not enter coverage or crawl planning.
        touch(&ctx, "src/pages/about.astro", "<button>Call us</button>\n");
        touch(&ctx, "src/pages/towns/[slug].astro", "<p>town</p>\n");
        touch(&ctx, "src/pages/logout.astro", "<p>bye</p>\n");
        let ChangedDecision::Incremental(plan, r) = plan_changed(&ctx, &a, &mut warnings).unwrap()
        else {
            panic!("expected an incremental map");
        };
        assert_eq!(r.mode, "incremental");
        assert_eq!(plan.routes, vec!["/about", "/towns/:slug"]);
        assert_eq!(plan.seeds, vec!["/about", "/towns/ames", "/towns/boone"]);
        assert!(r.kept_routes.is_empty());
        assert!(!warnings.iter().any(|w| w.contains("/logout")));
        assert!(plan.full_seeds.contains(&"/about".to_string()));
        assert!(!plan.full_seeds.contains(&"/logout".to_string()));
        assert!(plan.discovery.routes.iter().any(|r| r.path == "/logout"));
        let reasons: Vec<&str> = r
            .affected_routes
            .iter()
            .find(|a| a.route == "/about")
            .map(|a| a.reasons.iter().map(String::as_str).collect())
            .unwrap();
        assert_eq!(reasons, vec!["route file changed: src/pages/about.astro"]);
        // The re-crawl is scoped to the routes and their seeds.
        let scoped = MapPlan {
            incremental: Some(*plan),
            ..plan_for(&[])
        };
        assert!(scoped.scoped() && !scoped.partial());
        assert_eq!(
            scope_routes(&scoped),
            vec!["/about", "/towns/:slug", "/towns/ames", "/towns/boone"]
        );

        // App-wide config: a full map, with the reason.
        touch(&ctx, "astro.config.mjs", "export default { site: 'x' }\n");
        let ChangedDecision::Full(r) = plan_changed(&ctx, &a, &mut warnings).unwrap() else {
            panic!("expected a full map");
        };
        assert_eq!(
            r.mode_reason.as_deref(),
            Some("app config changed: astro.config.mjs")
        );
        assert_eq!(r.changed_files.len(), 5);

        // No previous map at all.
        std::fs::remove_file(ctx.latest_inventory_path()).unwrap();
        let ChangedDecision::Full(r) = plan_changed(&ctx, &a, &mut warnings).unwrap() else {
            panic!("expected a full map");
        };
        assert_eq!(r.mode_reason.as_deref(), Some("no previous map to update"));
    }

    #[test]
    fn changed_unattributed_source_and_style_require_a_full_map() {
        for rel in [
            "public/js/calendar.js",
            "src/components/Unused.tsx",
            "public/calendar.css",
        ] {
            let (_dir, ctx) = changed_fixture();
            std::fs::create_dir_all(ctx.root.join(rel).parent().unwrap()).unwrap();
            touch(&ctx, rel, "/* changed */\n");
            let mut a = args();
            a.changed = true;
            let paths = ctx.role_paths(ANONYMOUS_ROLE);
            let lists = route_lists(&ctx, ANONYMOUS_ROLE);
            let ChangedDecision::Full(r) =
                plan_changed(&ctx, &paths, &lists, &a, &mut Vec::new()).unwrap()
            else {
                panic!("unattributed {rel} must not skip the map");
            };
            assert_eq!(r.mode, "full");
            assert_eq!(
                r.mode_reason,
                Some(format!(
                    "route impact is unknown for changed source or style files: {rel}"
                ))
            );
            assert_eq!(r.changed_files, vec![rel]);
            assert!(
                r.affected_routes.is_empty(),
                "do not invent route ownership"
            );
            assert_eq!(r.unmapped_files[0].file, rel);

            // Knowing one other route's impact does not bound the unknown file.
            touch(&ctx, "src/pages/about.astro", "<button>Changed</button>\n");
            let ChangedDecision::Full(r) =
                plan_changed(&ctx, &paths, &lists, &a, &mut Vec::new()).unwrap()
            else {
                panic!("unattributed {rel} must not allow a scoped map");
            };
            assert_eq!(r.affected_routes.len(), 1);
            assert_eq!(r.affected_routes[0].route, "/about");
            assert_eq!(r.unmapped_files[0].file, rel);
        }
    }

    #[test]
    fn changed_only_excluded_route_file_still_skips() {
        let (_dir, ctx) = changed_fixture();
        touch(&ctx, "src/pages/logout.astro", "<p>Changed</p>\n");
        let mut a = args();
        a.changed = true;
        let ChangedDecision::Skip(r) = plan_changed(
            &ctx,
            &ctx.role_paths(ANONYMOUS_ROLE),
            &route_lists(&ctx, ANONYMOUS_ROLE),
            &a,
            &mut Vec::new(),
        )
        .unwrap() else {
            panic!("an explicitly excluded route must remain outside the map");
        };
        assert_eq!(r.changed_files, vec!["src/pages/logout.astro"]);
        assert_eq!(r.unmapped_files[0].kind, "source");
    }

    #[test]
    fn changed_exclusion_exception_requires_every_file_definition_to_be_excluded() {
        let route = |path: &str, kind: &str| crate::route_discovery::DiscoveredRoute {
            path: path.into(),
            kind: kind.into(),
            file: "src/routes.tsx".into(),
            dynamic: false,
            line: 1,
            methods: Vec::new(),
            examples: Vec::new(),
        };
        let mut discovery = RouteDiscovery {
            routes: vec![route("/private/a", "page"), route("/private/b", "page")],
            ..Default::default()
        };
        let excludes = vec!["/private".into()];
        assert!(only_defines_excluded_routes(
            "src/routes.tsx",
            &discovery,
            &excludes
        ));
        assert!(!only_defines_excluded_routes(
            "public/js/calendar.js",
            &discovery,
            &excludes
        ));
        discovery.routes.push(route("/allowed", "page"));
        assert!(!only_defines_excluded_routes(
            "src/routes.tsx",
            &discovery,
            &excludes
        ));
        discovery.routes.pop();
        discovery.routes.push(route("/private", "layout"));
        assert!(!only_defines_excluded_routes(
            "src/routes.tsx",
            &discovery,
            &excludes
        ));
    }

    #[test]
    fn crawl_knobs_are_validated() {
        let path = Path::new("/r/.brokenapp/config.toml");
        let mut scan = project::ScanSection::default();
        assert_eq!(crawl_knobs(&scan, path).unwrap(), CrawlKnobs::default());
        scan.max_interaction_depth = Some(4);
        scan.max_interactions_per_view = Some(60);
        scan.max_interactions_per_depth = Some(vec![60, 30, 15]);
        scan.settle_ms = Some(3500);
        let knobs = crawl_knobs(&scan, path).unwrap();
        assert_eq!(knobs.max_interaction_depth, Some(4));
        assert_eq!(knobs.max_interactions_per_view, Some(60));
        assert_eq!(knobs.max_interactions_per_depth, Some(vec![60, 30, 15]));
        assert_eq!(knobs.settle_ms, Some(3500));
        scan.max_interaction_depth = Some(50);
        let err = crawl_knobs(&scan, path).unwrap_err();
        assert!(format!("{err:#}").contains("max_interaction_depth"));
        scan.max_interaction_depth = None;
        scan.max_interactions_per_view = Some(0);
        assert!(crawl_knobs(&scan, path).is_err());
        scan.max_interactions_per_view = None;
        scan.max_interactions_per_depth = Some(vec![]);
        assert!(crawl_knobs(&scan, path).is_err());
        scan.max_interactions_per_depth = Some(vec![10; MAX_INTERACTION_DEPTH + 1]);
        assert!(crawl_knobs(&scan, path).is_err());
        scan.max_interactions_per_depth = Some(vec![10, 0]);
        assert!(crawl_knobs(&scan, path).is_err());
        scan.max_interactions_per_depth = Some(vec![MAX_INTERACTIONS_PER_VIEW + 1]);
        assert!(crawl_knobs(&scan, path).is_err());
        scan.max_interactions_per_depth = None;
        scan.settle_ms = Some(600_000);
        assert!(crawl_knobs(&scan, path).is_err());
    }

    #[test]
    fn generated_scan_config_parses_with_the_scan_schema() {
        let dir = tempfile::tempdir().unwrap();
        let url = Url::parse("http://localhost:3000/").unwrap();
        let out = dir.path().join("scans/x/scan");
        let seeds = dir.path().join("scans/x/seed-routes.txt");
        let scopes = dir.path().join("scans/x/scopes.toml");
        let raw = scan_config_toml(&ScanToml {
            url: &url,
            name: "demo",
            headless: true,
            max_minutes: 3,
            max_views: 25,
            write_guard: "block",
            write_guard_allow: &[],
            output_dir: &out,
            seed_routes_file: Some(&seeds),
            seed_urls: &[],
            deprioritize_routes: &[],
            scope: Some((SCOPE_NAME, &scopes)),
            codebase: None,
            route_templates: &[],
            test_data: &BTreeMap::new(),
            knobs: CrawlKnobs::default(),
            compliance: ComplianceKnobs::default(),
            tabs: 4,
            view_budget_seconds: None,
            full: None,
            auth: None,
            auth_contract: None,
            canary_interval_views: None,
        })
        .unwrap();
        let path = dir.path().join("scan.toml");
        std::fs::write(&path, &raw).unwrap();
        let parsed = BrokenAppConfig::from_toml_path(&path).unwrap();
        assert_eq!(parsed.target.url.as_str(), "http://localhost:3000/");
        assert!(parsed.target.headless);
        assert!(parsed.target.ignore_https_errors);
        assert_eq!(parsed.scan.max_views, 25);
        assert_eq!(parsed.scan.max_duration_minutes, 3);
        assert_eq!(parsed.scan.write_guard.mode, WriteGuardMode::Block);
        assert_eq!(
            parsed.scan.seed_routes_file.as_deref(),
            Some(seeds.as_path())
        );
        assert_eq!(parsed.scan.scope.as_deref(), Some(SCOPE_NAME));
        assert_eq!(parsed.scan.scopes_file.as_deref(), Some(scopes.as_path()));
        assert_eq!(parsed.scan.viewport_width, 1366);
        assert_eq!(parsed.scan.viewport_height, 900);
        assert_eq!(parsed.scan.max_concurrent_tabs, 4);
        assert_eq!(parsed.output.directory, out);
        assert!(parsed.output.include_network_log);
        assert!(parsed.scan.codebase_path.is_none());
        // Unset knobs leave the scanner defaults alone.
        let defaults = crate::config::ScanConfig::default();
        assert!(parsed.scan.route_templates.is_empty());
        assert_eq!(parsed.scan.settle_timeout_ms, defaults.settle_timeout_ms);
        assert_eq!(
            parsed.scan.exploration.max_interaction_depth,
            defaults.exploration.max_interaction_depth
        );
        assert_eq!(
            parsed.scan.limits.max_interactions_per_view,
            defaults.limits.max_interactions_per_view
        );
        assert!(!raw.contains("route_templates") && !raw.contains("settle_timeout_ms"));
        // Standard mode leaves the per-view budget and stop conditions to the scanner.
        for absent in [
            "view_budget_seconds",
            "stop_on_convergence",
            "max_stagnation_minutes",
            "[auth]",
            "canary_interval_views",
        ] {
            assert!(!raw.contains(absent), "{absent} in {raw}");
        }

        let raw = scan_config_toml(&ScanToml {
            url: &url,
            name: "demo",
            headless: false,
            max_minutes: 10,
            max_views: 80,
            write_guard: "off",
            write_guard_allow: &[],
            output_dir: &out,
            seed_routes_file: None,
            seed_urls: &[],
            deprioritize_routes: &[],
            scope: None,
            codebase: Some(dir.path()),
            route_templates: &["/towns/:slug".to_string(), "/#/items/:id".to_string()],
            test_data: &BTreeMap::new(),
            knobs: CrawlKnobs {
                max_interaction_depth: Some(4),
                max_interactions_per_view: Some(60),
                max_interactions_per_depth: None,
                settle_ms: Some(3500),
            },
            compliance: ComplianceKnobs::default(),
            tabs: 2,
            view_budget_seconds: None,
            full: None,
            auth: None,
            auth_contract: None,
            canary_interval_views: None,
        })
        .unwrap();
        std::fs::write(&path, &raw).unwrap();
        let parsed = BrokenAppConfig::from_toml_path(&path).unwrap();
        assert_eq!(
            parsed.scan.route_templates,
            vec!["/towns/:slug", "/#/items/:id"]
        );
        assert_eq!(parsed.scan.exploration.max_interaction_depth, 4);
        assert_eq!(parsed.scan.max_concurrent_tabs, 2);
        assert_eq!(parsed.scan.limits.max_interactions_per_view, 60);
        assert_eq!(parsed.scan.settle_timeout_ms, 3500);
        // Other exploration/limits settings keep their defaults.
        assert!(parsed.scan.exploration.fill_forms_with_test_data);
        assert_eq!(
            parsed.scan.limits.max_body_bytes,
            crate::config::LimitsConfig::default().max_body_bytes
        );
        assert_eq!(parsed.scan.write_guard.mode, WriteGuardMode::Off);
        assert!(!parsed.target.headless);
        assert!(parsed.scan.seed_routes_file.is_none());
        assert_eq!(parsed.scan.codebase_path.as_deref(), Some(dir.path()));
    }

    #[test]
    fn scopes_file_loads_as_scope_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scopes.toml");
        std::fs::write(
            &path,
            scopes_toml(&["/checkout".into(), "/cart".into()], &[]).unwrap(),
        )
        .unwrap();
        let filter = crate::scope::load_scope_filter(SCOPE_NAME, Some(&path)).unwrap();
        assert!(filter.allows_path("/checkout"));
        assert!(!filter.allows_path("/settings"));
    }

    #[test]
    fn map_scopes_combine_project_and_role_exclusions_in_every_mode() {
        use crate::front::roles::RoleConfig;
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg("http://localhost:3000");
        c.scan.exclude_routes = vec!["/private".into()];
        c.roles.push(RoleConfig {
            name: "staff".into(),
            exclude_routes: vec!["/billing".into()],
            ..Default::default()
        });
        let ctx = ctx_with(c, dir.path());
        for full in [false, true] {
            for name in [ANONYMOUS_ROLE, "staff"] {
                let mut a = args();
                a.full = full;
                let plan = make_plan(&ctx, &a, &Registry::default()).unwrap();
                let run = RunPaths::at("test", dir.path().join(format!("{full}-{name}")));
                std::fs::create_dir_all(&run.dir).unwrap();
                let role = ResolvedRole {
                    name: name.into(),
                    ..Default::default()
                };
                write_scan_inputs(&ctx, &plan, &run, &Seeds::default(), &role, None).unwrap();
                let scan = BrokenAppConfig::from_toml_path(&run.scan_toml).unwrap();
                assert_eq!(scan.scan.scope.as_deref(), Some(SCOPE_NAME));
                let scope =
                    crate::scope::load_scope_filter(SCOPE_NAME, scan.scan.scopes_file.as_deref())
                        .unwrap();
                assert!(scope.allows_path("/public"));
                assert!(!scope.allows_path("/private/linked"));
                assert_eq!(scope.allows_path("/billing"), name == ANONYMOUS_ROLE);
            }
        }
        // Incremental/--route include scopes intersect with the same exclusions.
        let file = dir.path().join("incremental-scope.toml");
        std::fs::write(
            &file,
            scopes_toml(
                &["/public".into(), "/private".into(), "/billing".into()],
                &route_lists(&ctx, "staff").exclude,
            )
            .unwrap(),
        )
        .unwrap();
        let scope = crate::scope::load_scope_filter(SCOPE_NAME, Some(&file)).unwrap();
        assert_eq!(scope.seed_paths(), ["/public"]);
        assert!(!scope.allows_path("/other"));
    }

    #[test]
    fn changed_rebuilds_when_previous_inventory_contains_excluded_routes() {
        let (_dir, mut ctx) = changed_fixture();
        ctx.config.scan.exclude_routes.push("/about".into());
        let result = plan_changed(
            &ctx,
            &ctx.role_paths(ANONYMOUS_ROLE),
            &route_lists(&ctx, ANONYMOUS_ROLE),
            &args(),
            &mut Vec::new(),
        )
        .unwrap();
        let ChangedDecision::Full(report) = result else {
            panic!("excluded old routes require a new allowed baseline")
        };
        assert!(report.mode_reason.unwrap().contains("now excluded"));
    }

    #[test]
    fn incremental_roles_share_complete_discovery_without_sharing_exclusions() {
        use crate::front::roles::RoleConfig;
        use crate::inventory::identity::RouteCanon;

        let (_dir, mut ctx) = changed_fixture();
        ctx.config.roles = vec![
            RoleConfig {
                name: "viewer".into(),
                exclude_routes: vec!["/towns".into()],
                ..Default::default()
            },
            RoleConfig {
                name: "staff".into(),
                ..Default::default()
            },
        ];
        let baseline = inventory::load(&ctx.latest_inventory_path()).unwrap();
        for role in ["viewer", "staff"] {
            let mut latest = baseline.clone();
            let lists = route_lists(&ctx, role);
            latest
                .routes
                .retain(|r| !is_excluded(&r.route, &lists.exclude));
            inventory::save(&latest, &ctx.role_paths(role).latest_inventory_path()).unwrap();
        }
        touch(&ctx, "src/pages/about.astro", "<button>Updated</button>\n");
        touch(
            &ctx,
            "src/pages/towns/[slug].astro",
            "<button>Inspect town</button>\n",
        );
        let plan_role = |role: &str| {
            let result = plan_changed(
                &ctx,
                &ctx.role_paths(role),
                &route_lists(&ctx, role),
                &args(),
                &mut Vec::new(),
            )
            .unwrap();
            let ChangedDecision::Incremental(inc, _) = result else {
                panic!("{role} should have an incremental plan")
            };
            MapPlan {
                incremental: Some(*inc),
                ..make_plan(&ctx, &args(), &Registry::default()).unwrap()
            }
        };
        let viewer = plan_role("viewer");
        let staff = plan_role("staff");
        let first = viewer.incremental.as_ref().unwrap();
        assert_eq!(first.routes, ["/about"]);
        assert!(!first.full_seeds.iter().any(|r| r.starts_with("/towns")));
        assert_eq!(
            staff.incremental.as_ref().unwrap().routes,
            ["/about", "/towns/:slug"]
        );

        // execute() uses the first incremental job's discovery for every role.
        // Both role orders must preserve templates and source metadata while
        // each role's scheduling lists still enforce its own exclusions.
        for shared in [
            &first.discovery,
            &staff.incremental.as_ref().unwrap().discovery,
        ] {
            let source = shared
                .routes
                .iter()
                .find(|r| r.path == "/towns/:slug")
                .unwrap();
            assert_eq!(source.file, "src/pages/towns/[slug].astro");
            assert_eq!(
                RouteCanon::new(&shared.routes).route("/towns/ames"),
                "/towns/:slug"
            );
            let viewer_seeds = role_seeds(&ctx, &viewer, shared, &route_lists(&ctx, "viewer"));
            assert!(
                !viewer_seeds
                    .templates
                    .iter()
                    .any(|r| r.starts_with("/towns"))
            );
            assert!(!viewer_seeds.seeds.iter().any(|r| r.starts_with("/towns")));
            let staff_seeds = role_seeds(&ctx, &staff, shared, &route_lists(&ctx, "staff"));
            assert!(staff_seeds.templates.contains(&"/towns/:slug".to_string()));
            assert!(staff_seeds.seeds.contains(&"/towns/ames".to_string()));
        }
    }

    #[test]
    fn scan_json_parsing_tolerates_noise() {
        let json =
            r#"{"status":"ok","duration_seconds":12.5,"artifacts":{"output_dir":"/tmp/x/scan"}}"#;
        let v = parse_scan_json(json).unwrap();
        assert_eq!(
            scan_output_dir(&v, Path::new("/repo")).unwrap(),
            PathBuf::from("/tmp/x/scan")
        );
        let noisy = format!("BrokenApp\nsome line\n{json}\n");
        let v = parse_scan_json(&noisy).unwrap();
        assert_eq!(v["status"], "ok");
        let v: Value = serde_json::json!({"artifacts":{"output_dir":"rel/scan"}});
        assert_eq!(
            scan_output_dir(&v, Path::new("/repo")).unwrap(),
            PathBuf::from("/repo/rel/scan")
        );
        assert!(parse_scan_json("no json here").is_err());
        assert!(scan_output_dir(&serde_json::json!({}), Path::new("/")).is_err());
    }

    #[test]
    fn restrict_keeps_only_requested_routes() {
        use crate::inventory::{Control, EndpointEntry, RouteEntry};
        let control = |route: &str, key: &str| Control {
            key: key.into(),
            route: route.into(),
            ..Default::default()
        };
        let inv = Inventory {
            routes: vec![
                RouteEntry {
                    route: "/checkout".into(),
                    ..Default::default()
                },
                RouteEntry {
                    route: "/".into(),
                    ..Default::default()
                },
            ],
            controls: vec![
                control("/checkout", "/checkout|button|text=Pay"),
                control("/", "/|link|href=/about"),
                control("*", "*|link|text=Home"),
            ],
            endpoints: vec![
                EndpointEntry {
                    endpoint: "POST /api/pay".into(),
                    controls: vec!["/checkout|button|text=Pay".into()],
                    ..Default::default()
                },
                EndpointEntry {
                    endpoint: "GET /api/home".into(),
                    on_load: vec!["/".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let only: BTreeSet<String> = ["/checkout/".to_string()].into_iter().collect();
        let r = restrict(&inv, &only);
        assert_eq!(r.controls.len(), 1);
        assert_eq!(r.routes.len(), 1);
        assert_eq!(r.endpoints.len(), 1);
        assert_eq!(r.endpoints[0].endpoint, "POST /api/pay");
    }

    fn plan_for(only: &[&str]) -> MapPlan {
        MapPlan {
            url: Url::parse("http://localhost:3000/").unwrap(),
            mode: ScanMode::Standard,
            max_minutes: 3,
            max_views: 25,
            write_guard: "block".into(),
            headless: true,
            only_routes: only.iter().map(|s| s.to_string()).collect(),
            no_merge: false,
            merge_partial: false,
            test_data: BTreeMap::new(),
            knobs: CrawlKnobs::default(),
            compliance: ComplianceKnobs::default(),
            view_budget_seconds: None,
            full: None,
            tabs: 4,
            role_concurrency: 1,
            progress_every: None,
            incremental: None,
        }
    }

    #[test]
    fn persist_writes_history_latest_and_changelog() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with(cfg("http://localhost:3000"), dir.path());
        let inv = Inventory {
            schema: inventory::INVENTORY_SCHEMA.into(),
            project: "demo".into(),
            generated_at: "2026-10-21T00:00:00Z".into(),
            ..Default::default()
        };
        let mut warnings = Vec::new();
        let anon = ctx.role_paths(ANONYMOUS_ROLE);

        let first = persist(
            &anon,
            &plan_for(&[]),
            "20261021T000000Z",
            &inv,
            "2026-10-21T00:00:00Z",
            &mut warnings,
        )
        .unwrap();
        assert!(first.first_map);
        assert!(
            ctx.history_dir()
                .join("20261021T000000Z.inventory.json")
                .is_file()
        );
        assert!(ctx.latest_inventory_path().is_file());
        let changelog = ctx.map_dir().join("CHANGELOG.md");
        assert_eq!(first.changelog.as_deref(), Some(changelog.as_path()));
        assert_eq!(first.files.contains(&changelog), changelog.is_file());

        let second = persist(
            &anon,
            &plan_for(&[]),
            "20261021T000100Z",
            &inv,
            "2026-10-21T00:00:00Z",
            &mut warnings,
        )
        .unwrap();
        assert!(!second.first_map);

        // A --route map stays out of the whole-app history and map files.
        std::fs::remove_file(ctx.latest_inventory_path()).unwrap();
        let partial = persist(
            &anon,
            &plan_for(&["/checkout"]),
            "20261021T000200Z",
            &inv,
            "2026-10-21T00:00:00Z",
            &mut warnings,
        )
        .unwrap();
        assert_eq!(
            partial.inventory_path,
            ctx.history_dir()
                .join("partial/20261021T000200Z.inventory.json")
        );
        assert!(partial.inventory_path.is_file());
        assert!(!ctx.latest_inventory_path().exists());
        assert!(partial.files.is_empty() && partial.changelog.is_none());

        // When a whole-app map already exists, `--route` merges into it by default.
        let base_inv = Inventory {
            schema: inventory::INVENTORY_SCHEMA.into(),
            project: "demo".into(),
            generated_at: "2026-10-21T00:00:00Z".into(),
            target_url: "http://localhost:3000/".into(),
            routes: vec![
                crate::inventory::RouteEntry {
                    route: "/".into(),
                    visited: true,
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/checkout".into(),
                    visited: false,
                    unvisited_reason: Some("seed route not reached".into()),
                    ..Default::default()
                },
            ],
            coverage: CoverageSummary {
                routes_known: 2,
                routes_visited: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        persist(
            &anon,
            &plan_for(&[]),
            "20261021T000230Z",
            &base_inv,
            "2026-10-21T00:02:30Z",
            &mut warnings,
        )
        .unwrap();
        let recrawl_inv = Inventory {
            schema: inventory::INVENTORY_SCHEMA.into(),
            project: "demo".into(),
            generated_at: "2026-10-21T00:02:45Z".into(),
            target_url: "http://localhost:3000/".into(),
            routes: vec![crate::inventory::RouteEntry {
                route: "/checkout".into(),
                visited: true,
                status: Some(200),
                ..Default::default()
            }],
            coverage: CoverageSummary {
                routes_known: 1,
                routes_visited: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = persist(
            &anon,
            &plan_for(&["/checkout"]),
            "20261021T000245Z",
            &recrawl_inv,
            "2026-10-21T00:02:45Z",
            &mut warnings,
        )
        .unwrap();
        assert!(merged.merged.is_some());
        assert!(!merged.files.is_empty() && merged.changelog.is_some());
        let saved_latest = inventory::load(&ctx.latest_inventory_path()).unwrap();
        assert_eq!(saved_latest.coverage.routes_visited, 2);
        assert!(
            saved_latest
                .routes
                .iter()
                .any(|r| r.route == "/checkout" && r.visited)
        );
        // `--route --no-merge` leaves `latest.inventory.json` untouched.
        let mut no_merge_plan = plan_for(&["/checkout"]);
        no_merge_plan.no_merge = true;
        let standalone = persist(
            &anon,
            &no_merge_plan,
            "20261021T000250Z",
            &recrawl_inv,
            "2026-10-21T00:02:50Z",
            &mut warnings,
        )
        .unwrap();
        assert!(standalone.merged.is_none());
        assert!(standalone.files.is_empty() && standalone.changelog.is_none());

        // An unreadable previous map is a warning, not a failure.
        std::fs::write(ctx.latest_inventory_path(), "not json").unwrap();
        let again = persist(
            &anon,
            &plan_for(&[]),
            "20261021T000300Z",
            &inv,
            "2026-10-21T00:00:00Z",
            &mut warnings,
        )
        .unwrap();
        assert!(again.first_map);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn record_scan_updates_or_registers() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with(cfg("http://localhost:3000"), dir.path());
        let mut reg = Registry::default();
        record_scan(&mut reg, &ctx, "1/1 routes", "2026-10-21T00:00:00Z").unwrap();
        assert_eq!(reg.projects.len(), 1);
        assert_eq!(reg.projects[0].name, "demo");
        assert_eq!(
            reg.projects[0].state_dir,
            ctx.state_dir.display().to_string()
        );

        reg.projects[0].root = "/kept".into();
        record_scan(&mut reg, &ctx, "2/2 routes", "2026-10-21T00:05:00Z").unwrap();
        assert_eq!(reg.projects.len(), 1);
        let e = &reg.projects[0];
        assert_eq!(e.root, "/kept", "existing fields are kept");
        assert_eq!(e.last_summary.as_deref(), Some("2/2 routes"));
        assert_eq!(e.last_scan_at.as_deref(), Some("2026-10-21T00:05:00Z"));

        // Another project already owns the name: do not take over its entry.
        let other = tempfile::tempdir().unwrap();
        let ctx2 = ctx_with(cfg("http://localhost:3001"), other.path());
        assert!(record_scan(&mut reg, &ctx2, "x", "y").is_err());
        assert_eq!(reg.projects.len(), 1);
        assert_eq!(reg.projects[0].last_summary.as_deref(), Some("2/2 routes"));
    }

    #[test]
    fn exercisable_coverage_excludes_external_disabled_skipped() {
        let control = |status| crate::inventory::Control {
            status,
            ..Default::default()
        };
        let mut controls = vec![control(ControlStatus::Ok); 30];
        controls.push(control(ControlStatus::Dead));
        controls.push(control(ControlStatus::NoEffect));
        controls.push(control(ControlStatus::Broken));
        controls.push(control(ControlStatus::NotExercised));
        controls.extend(vec![control(ControlStatus::External); 63]);
        controls.push(control(ControlStatus::Disabled));
        controls.push(control(ControlStatus::Skipped));
        let inv = Inventory {
            controls,
            ..Default::default()
        };
        let ex = ExercisableCoverage::compute(&inv, &status_counts(&inv));
        assert_eq!(
            ex,
            ExercisableCoverage {
                exercised: 33,
                exercisable: 34,
                total: 99,
                external: 63,
                disabled: 1,
                skipped: 1,
            }
        );
    }

    #[test]
    fn unvisited_routes_are_grouped_by_reason() {
        let inv = Inventory {
            coverage: CoverageSummary {
                unvisited_routes: vec!["/".into(), "/privacy".into(), "/blog/:slug".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let facts = ScanFacts {
            nav_failures: vec![scan_facts::NavFailure {
                route: "/".into(),
                error: "Page.navigate timed out after 20000ms".into(),
            }],
            ..Default::default()
        };
        let warm = WarmupReport {
            failed: vec![warmup::WarmupFailure {
                route: "/privacy/".into(),
                status: None,
                error: "timed out after 15s".into(),
            }],
            ..Default::default()
        };
        let grouped = unvisited_by_reason(&inv, &facts, Some(&warm));
        assert_eq!(grouped[scan_facts::UNVISITED_NAV_FAILED], vec!["/"]);
        assert_eq!(
            grouped[scan_facts::UNVISITED_WARMUP_FAILED],
            vec!["/privacy"]
        );
        assert_eq!(grouped[scan_facts::UNVISITED_DYNAMIC], vec!["/blog/:slug"]);
        assert!(unvisited_by_reason(&Inventory::default(), &facts, None).is_empty());
    }

    #[test]
    fn failure_json_always_has_exit_code_and_warnings() {
        let failure = MapFailure {
            exit_code: 1,
            status: "error".into(),
            error: "http://127.0.0.1:1/ is not reachable".into(),
            project: Some("demo".into()),
            scan_dir: None,
            inventory: None,
            run_dir: None,
            roles: Vec::new(),
            resume: None,
            warnings: Vec::new(),
        };
        let v = serde_json::to_value(&failure).unwrap();
        assert_eq!(v["exit_code"], 1);
        assert_eq!(v["status"], "error");
        assert_eq!(v["warnings"], serde_json::json!([]));
    }

    #[test]
    fn summary_line_counts() {
        let inv = Inventory {
            coverage: CoverageSummary {
                routes_known: 7,
                routes_visited: 5,
                controls_total: 52,
                controls_exercised: 34,
                ..Default::default()
            },
            controls: vec![
                crate::inventory::Control {
                    status: ControlStatus::Dead,
                    ..Default::default()
                },
                crate::inventory::Control {
                    status: ControlStatus::NotExercised,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let counts = status_counts(&inv);
        assert_eq!(counts.get("not_exercised"), Some(&1));
        assert_eq!(
            summary_line(&inv.coverage, &counts),
            "5/7 routes, 34/52 controls exercised, 1 dead, 0 broken"
        );
    }

    #[test]
    fn full_mode_plans_without_caps() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::default();
        let mut a = args();
        a.full = true;
        let plan = make_plan(
            &ctx_with(cfg("http://127.0.0.1:3000"), dir.path()),
            &a,
            &reg,
        )
        .unwrap();
        assert_eq!(plan.mode, ScanMode::Full);
        assert_eq!(
            (plan.max_minutes, plan.max_views),
            (0, 0),
            "no time or view cap"
        );
        assert_eq!(plan.view_budget_seconds, Some(FULL_VIEW_BUDGET_SECONDS));
        assert_eq!(
            plan.knobs.max_interaction_depth,
            Some(FULL_MAX_INTERACTION_DEPTH)
        );
        assert_eq!(
            plan.knobs.max_interactions_per_view,
            Some(MAX_INTERACTIONS_PER_VIEW)
        );
        assert_eq!(plan.tabs, DEFAULT_TABS);
        assert_eq!(
            plan.progress_every,
            Some(Duration::from_secs(FULL_PROGRESS_SECONDS))
        );
        assert!(plan.full.is_some());

        // Config: mode = "full" with a ceiling, a budget and deeper crawl.
        let mut c = cfg("http://127.0.0.1:3000");
        c.scan.mode = ScanMode::Full;
        c.scan.max_hours = Some(5);
        c.scan.view_budget_seconds = Some(120);
        c.scan.max_interaction_depth = Some(6);
        c.scan.tabs = Some(8);
        let plan = make_plan(&ctx_with(c.clone(), dir.path()), &args(), &reg).unwrap();
        assert_eq!((plan.max_minutes, plan.max_views), (300, 0));
        assert_eq!(plan.view_budget_seconds, Some(120));
        assert_eq!(plan.knobs.max_interaction_depth, Some(6));
        assert_eq!(plan.tabs, 8);
        // --mode standard and --quick override the config.
        let mut a = args();
        a.mode = Some("standard".into());
        let plan = make_plan(&ctx_with(c.clone(), dir.path()), &a, &reg).unwrap();
        assert_eq!(
            (plan.mode, plan.max_minutes, plan.max_views),
            (ScanMode::Standard, 10, 80)
        );
        assert_eq!(
            plan.view_budget_seconds,
            Some(120),
            "explicit budgets apply in any mode"
        );
        let mut a = args();
        a.quick = true;
        let plan = make_plan(&ctx_with(c.clone(), dir.path()), &a, &reg).unwrap();
        assert_eq!((plan.max_minutes, plan.max_views), (3, 25));
        let mut a = args();
        a.mode = Some("forever".into());
        assert!(make_plan(&ctx_with(c.clone(), dir.path()), &a, &reg).is_err());
        // Out-of-range settings are config errors.
        c.scan.max_hours = Some(10_000);
        assert!(make_plan(&ctx_with(c.clone(), dir.path()), &args(), &reg).is_err());
        c.scan.max_hours = None;
        c.scan.role_concurrency = Some(99);
        assert!(make_plan(&ctx_with(c, dir.path()), &args(), &reg).is_err());
        // Standard mode keeps today's budget and automatic per-view budget.
        let plan = make_plan(
            &ctx_with(cfg("http://127.0.0.1:3000"), dir.path()),
            &args(),
            &reg,
        )
        .unwrap();
        assert_eq!((plan.max_minutes, plan.max_views), (10, 80));
        assert!(plan.view_budget_seconds.is_none() && plan.full.is_none());
        assert!(plan.progress_every.is_none());
    }

    #[test]
    fn full_mode_scan_config_emits_no_caps() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::default();
        let mut a = args();
        a.full = true;
        let plan = make_plan(
            &ctx_with(cfg("http://localhost:3000"), dir.path()),
            &a,
            &reg,
        )
        .unwrap();
        let out = dir.path().join("scan");
        let raw = scan_config_toml(&ScanToml {
            url: &plan.url,
            name: "demo",
            headless: true,
            max_minutes: plan.max_minutes,
            max_views: plan.max_views,
            write_guard: "block",
            write_guard_allow: &[],
            output_dir: &out,
            seed_routes_file: None,
            seed_urls: &[],
            deprioritize_routes: &[],
            scope: None,
            codebase: None,
            route_templates: &[],
            test_data: &BTreeMap::new(),
            knobs: plan.knobs.clone(),
            compliance: plan.compliance.clone(),
            tabs: plan.tabs,
            view_budget_seconds: plan.view_budget_seconds,
            full: plan.full,
            auth: None,
            auth_contract: None,
            canary_interval_views: None,
        })
        .unwrap();
        for line in [
            "max_views = 0",
            "max_duration_minutes = 0",
            "view_budget_seconds = 300",
            "stop_on_convergence = false",
            "max_stagnation_minutes = 60",
            "max_interactions_per_view = 1000",
            "max_interaction_depth = 4",
            "max_interactions_per_depth = [",
            "max_concurrent_tabs = 4",
        ] {
            assert!(raw.contains(line), "missing {line:?} in\n{raw}");
        }
        let path = dir.path().join("scan.toml");
        std::fs::write(&path, &raw).unwrap();
        let parsed = BrokenAppConfig::from_toml_path(&path).unwrap();
        assert_eq!(parsed.scan.max_views, 0);
        assert_eq!(parsed.scan.max_duration_minutes, 0);
        assert!(!parsed.scan.stop_on_convergence);
        assert_eq!(parsed.scan.limits.max_interactions_per_view, 1000);
        assert_eq!(parsed.scan.exploration.max_interaction_depth, 4);
        assert_eq!(
            parsed.scan.exploration.max_interactions_per_depth,
            vec![1000, 250, 100, 50]
        );
        assert!(parsed.auth.is_none());
    }

    #[test]
    fn role_scan_config_carries_env_references_never_values() {
        use crate::front::roles::{CredentialsFile, RoleConfig, RoleCredentials};
        let dir = tempfile::tempdir().unwrap();
        let mut creds = CredentialsFile::default();
        creds.roles.insert(
            "admin".into(),
            RoleCredentials {
                username: Some("admin@fixture.test".into()),
                password: Some("s3cret-value-xyz".into()),
                ..Default::default()
            },
        );
        let role = RoleConfig {
            name: "admin".into(),
            method: RoleMethod::Form,
            login_url: Some("/sign-in".into()),
            check: Some("/api/me".into()),
            ..Default::default()
        };
        let resolved = roles::resolve_role(&role, dir.path(), &creds, &|_| None);
        assert!(resolved.ready());
        let mut a = args();
        a.full = true;
        let plan = make_plan(
            &ctx_with(cfg("http://localhost:3000"), dir.path()),
            &a,
            &Registry::default(),
        )
        .unwrap();
        let ctx = ctx_with(cfg("http://localhost:3000"), dir.path());
        let run = RunPaths::at("20261022T000000Z", dir.path().join("run"));
        std::fs::create_dir_all(&run.dir).unwrap();
        let seeds = Seeds {
            seeds: vec!["/".into(), "/admin".into()],
            ..Default::default()
        };
        write_scan_inputs(&ctx, &plan, &run, &seeds, &resolved, None).unwrap();
        let raw = std::fs::read_to_string(&run.scan_toml).unwrap();
        assert!(
            !raw.contains("admin@fixture.test") && !raw.contains("s3cret-value-xyz"),
            "{raw}"
        );
        assert!(
            raw.contains("username = \"env:BROKENAPP_ROLE_ADMIN_USERNAME\""),
            "{raw}"
        );
        assert!(
            raw.contains("password = \"env:BROKENAPP_ROLE_ADMIN_PASSWORD\""),
            "{raw}"
        );
        assert!(raw.contains("canary_interval_views = 25"), "{raw}");
        let parsed = BrokenAppConfig::from_toml_path(&run.scan_toml).unwrap();
        match parsed.auth {
            Some(crate::config::AuthConfig::Form {
                login_url,
                username,
                username_selector,
                ..
            }) => {
                assert_eq!(login_url, "/sign-in");
                assert_eq!(username, "env:BROKENAPP_ROLE_ADMIN_USERNAME");
                assert_eq!(username_selector, roles::DEFAULT_USERNAME_SELECTOR);
            }
            other => panic!("expected form auth, got {other:?}"),
        }
        let probe = parsed.auth_contract.unwrap().protected_probe.unwrap();
        assert_eq!(probe.path, "/api/me");
        // The values reach the scan through its environment only.
        assert_eq!(
            resolved.env,
            vec![
                (
                    "BROKENAPP_ROLE_ADMIN_USERNAME".to_string(),
                    "admin@fixture.test".to_string()
                ),
                (
                    "BROKENAPP_ROLE_ADMIN_PASSWORD".to_string(),
                    "s3cret-value-xyz".to_string()
                ),
            ]
        );

        // A saved-session role: `[auth] type = "storage_state"` with the file path.
        let session = RoleConfig {
            name: "coach".into(),
            method: RoleMethod::Session,
            ..Default::default()
        };
        let resolved = roles::resolve_role(&session, dir.path(), &creds, &|_| None);
        let run = RunPaths::at("20261022T000000Z", dir.path().join("run2"));
        std::fs::create_dir_all(&run.dir).unwrap();
        write_scan_inputs(&ctx, &plan, &run, &seeds, &resolved, None).unwrap();
        let raw: toml::Table =
            toml::from_str(&std::fs::read_to_string(&run.scan_toml).unwrap()).unwrap();
        assert_eq!(raw["auth"]["type"].as_str(), Some("storage_state"));
        assert_eq!(
            raw["auth"]["path"].as_str(),
            Some(
                dir.path()
                    .join("session/coach.json")
                    .display()
                    .to_string()
                    .as_str()
            )
        );
        assert!(raw.get("auth_contract").is_none());

        // The anonymous role never gets an [auth] table.
        let anon = ResolvedRole {
            name: ANONYMOUS_ROLE.into(),
            ..Default::default()
        };
        let run = RunPaths::at("20261022T000000Z", dir.path().join("run3"));
        std::fs::create_dir_all(&run.dir).unwrap();
        write_scan_inputs(&ctx, &plan, &run, &seeds, &anon, None).unwrap();
        assert!(
            !std::fs::read_to_string(&run.scan_toml)
                .unwrap()
                .contains("[auth")
        );
    }

    #[test]
    fn role_run_dirs_nest_under_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunPaths::at(
            "20261022T000000Z",
            dir.path().join("scans/20261022T000000Z"),
        );
        let anon = run.for_role(ANONYMOUS_ROLE).unwrap();
        assert_eq!(anon.dir, run.dir);
        let admin = run.for_role("admin").unwrap();
        assert_eq!(admin.dir, run.dir.join("roles/admin"));
        assert_eq!(admin.scan_out, run.dir.join("roles/admin/scan"));
        assert_eq!(admin.dev_log, run.dev_log, "one dev server per run");
        assert_eq!(admin.ts, run.ts);
        assert!(admin.dir.is_dir());
    }

    #[test]
    fn eta_from_route_rate() {
        assert_eq!(route_eta(30, 5, 10), None, "too early");
        assert_eq!(route_eta(600, 2, 10), None, "too few routes");
        assert_eq!(route_eta(600, 10, 10), None, "nothing left");
        assert_eq!(route_eta(600, 10, 40), Some(1800));
        assert_eq!(scan_facts::clock(7380), "2h03m");
    }

    #[test]
    fn logged_out_role_maps_are_detected() {
        use crate::inventory::RouteEntry;
        let route = |r: &str, visited: bool, why: Option<&str>| RouteEntry {
            route: r.into(),
            visited,
            unvisited_reason: why.map(str::to_string),
            ..Default::default()
        };
        let anon = Inventory {
            routes: vec![
                route("/", true, None),
                route("/login", true, None),
                route("/dashboard", false, Some("redirects to login")),
            ],
            ..Default::default()
        };
        let expired = Inventory {
            routes: vec![
                route("/", true, None),
                route("/dashboard", false, Some("redirects to login")),
            ],
            ..Default::default()
        };
        let why = looks_logged_out(&expired, &anon).unwrap();
        assert!(
            why.contains("sent to login on 1 route (/dashboard)"),
            "{why}"
        );
        let working = Inventory {
            routes: vec![route("/", true, None), route("/dashboard", true, None)],
            ..Default::default()
        };
        assert!(looks_logged_out(&working, &anon).is_none());
        // Same pages as anonymous but never sent to login: not a verdict.
        let same = Inventory {
            routes: vec![route("/", true, None)],
            ..Default::default()
        };
        assert!(looks_logged_out(&same, &anon).is_none());
    }

    #[test]
    fn auth_failures_are_read_from_telemetry_then_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunPaths::at("x", dir.path().to_path_buf());
        // Under `cargo test` BROKENAPP_TELEMETRY_PATH is normally unset.
        if std::env::var_os("BROKENAPP_TELEMETRY_PATH").is_some() {
            return;
        }
        std::fs::write(
            run.dir.join("telemetry.jsonl"),
            concat!(
                r#"{"timestamp":"t","event_type":"scan_phase","payload":{}}"#,
                "\n",
                r#"{"timestamp":"t","event_type":"auth_result","payload":{"success":false,"error":"resolve auth secrets: auth.form.password requires env var \"X\""}}"#,
                "\n"
            ),
        )
        .unwrap();
        assert!(
            auth_failure(&run, &[])
                .unwrap()
                .contains("requires env var")
        );
        std::fs::remove_file(run.dir.join("telemetry.jsonl")).unwrap();
        let tail = vec![
            "INFO visiting".to_string(),
            "Error: authenticate: wait for username selector input".to_string(),
        ];
        assert!(
            auth_failure(&run, &tail)
                .unwrap()
                .contains("wait for username selector")
        );
        assert!(auth_failure(&run, &["Error: Chrome crashed".to_string()]).is_none());
    }

    #[test]
    fn failed_role_history_is_not_current_access_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = cfg("http://127.0.0.1:3000");
        config.roles.push(roles::RoleConfig {
            name: "admin".into(),
            ..Default::default()
        });
        let ctx = ctx_with(config, dir.path());
        let old = Inventory {
            generated_at: "old-map".into(),
            routes: vec![crate::inventory::RouteEntry {
                route: "/admin".into(),
                visited: true,
                status: Some(200),
                ..Default::default()
            }],
            ..Default::default()
        };
        inventory::save(&old, &ctx.role_paths("admin").latest_inventory_path()).unwrap();
        inventory::save(
            &old,
            &ctx.role_paths(ANONYMOUS_ROLE).latest_inventory_path(),
        )
        .unwrap();
        let manifest = RunManifest::new(
            "run",
            "now",
            RunSettings::default(),
            vec![RunRole {
                name: "admin".into(),
                status: "login_failed".into(),
                ..Default::default()
            }],
        );
        write_role_access(&ctx, &manifest).unwrap();
        let tsv = std::fs::read_to_string(ctx.map_dir().join("role-access.tsv")).unwrap();
        assert!(tsv.contains("route\t/admin\t\tvisited\t-\t"), "{tsv}");
        assert!(ctx.role_paths("admin").latest_inventory_path().is_file());
        let index = std::fs::read_to_string(ctx.map_dir().join("README.md")).unwrap();
        assert!(index.contains("old-map") && index.contains("login_failed"));
    }

    #[test]
    fn map_test_data_reaches_standard_full_and_role_scan_configs() {
        let dir = tempfile::tempdir().unwrap();
        let config: ProjectConfig = toml::from_str(
            r#"
[project]
name = "fixture"
url = "http://127.0.0.1:3000/"
[scan.test_data]
"Find shipment" = ""
sku = "  fixture-42  "
"Literal reference" = "env:FIXTURE_LITERAL"
"Quoted label \"x\"" = "line one\nline two"
"#,
        )
        .unwrap();
        let values = config.scan.test_data.clone();
        assert_eq!(values["Find shipment"], "");
        let round_trip: ProjectConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert_eq!(round_trip.scan.test_data, values);
        let ctx = ctx_with(config, dir.path());
        for full in [false, true] {
            let mut a = args();
            a.full = full;
            let plan = make_plan(&ctx, &a, &Registry::default()).unwrap();
            for role in [ANONYMOUS_ROLE, "reviewer"] {
                let resolved = ResolvedRole {
                    name: role.into(),
                    ..Default::default()
                };
                let run = RunPaths::at("fixture", dir.path().join(format!("run-{full}-{role}")));
                std::fs::create_dir_all(&run.dir).unwrap();
                write_scan_inputs(&ctx, &plan, &run, &Seeds::default(), &resolved, None).unwrap();
                let parsed = BrokenAppConfig::from_toml_path(&run.scan_toml).unwrap();
                assert_eq!(parsed.scan.test_data.values, values);
                assert_eq!(parsed.scan.write_guard.mode, WriteGuardMode::Block);
                assert!(parsed.scan.exploration.fill_forms_with_test_data);
                assert_eq!(parsed.scan.max_views == 0, full);
            }
        }
    }

    #[test]
    fn map_test_data_resume_preserves_values_and_checks_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with(cfg("http://localhost:3000/"), dir.path());
        let mut initial = plan_for(&[]);
        initial.test_data = BTreeMap::from([
            ("Find shipment".into(), "".into()),
            ("sku".into(), "fixture-42".into()),
        ]);
        let mut manifest = RunManifest::new("fixture", "now", settings_of(&initial), vec![]);
        manifest.save(dir.path()).unwrap();
        let saved = RunManifest::load(dir.path()).unwrap();
        let mut plan = plan_for(&[]);
        plan.test_data
            .insert("Find shipment".into(), "changed".into());
        apply_settings(&mut plan, &saved.settings).unwrap();
        assert_eq!(plan.test_data, initial.test_data);
        let job = RoleJob {
            name: ANONYMOUS_ROLE.into(),
            resolved: ResolvedRole {
                name: ANONYMOUS_ROLE.into(),
                ..Default::default()
            },
            paths: ctx.role_paths(ANONYMOUS_ROLE),
            lists: route_lists(&ctx, ANONYMOUS_ROLE),
            plan,
            changed: None,
            outcome: None,
            resume_from: None,
            seeds: Seeds::default(),
        };
        // Pending roles and fallback from an unusable checkpoint both use this
        // same writer, with the restored plan rather than the current config.
        let run = RunPaths::at("pending", dir.path().join("pending"));
        std::fs::create_dir_all(&run.dir).unwrap();
        write_scan_inputs(&ctx, &job.plan, &run, &job.seeds, &job.resolved, None).unwrap();
        let parsed = BrokenAppConfig::from_toml_path(&run.scan_toml).unwrap();
        assert_eq!(parsed.scan.test_data.values, initial.test_data);
        let mut checkpoint = serde_json::json!({"config": {
            "target": {"url": job.plan.url.as_str()},
            "scan": {"test_data": initial.test_data}
        }});
        let checkpoint_path = dir.path().join("checkpoint.json");
        std::fs::write(&checkpoint_path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
        validate_resume_context(&ctx, &job, dir.path()).unwrap();
        checkpoint["config"]["scan"]["test_data"]["Find shipment"] = "changed".into();
        std::fs::write(&checkpoint_path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
        let err = validate_resume_context(&ctx, &job, dir.path()).unwrap_err();
        assert!(err.to_string().contains("test data differs"));

        // Old manifests/checkpoints without the setting mean no overrides.
        let mut legacy = serde_json::to_value(&saved.settings).unwrap();
        legacy.as_object_mut().unwrap().remove("test_data");
        let legacy: RunSettings = serde_json::from_value(legacy).unwrap();
        let mut job = job;
        apply_settings(&mut job.plan, &legacy).unwrap();
        assert!(job.plan.test_data.is_empty());
        checkpoint["config"]["scan"]
            .as_object_mut()
            .unwrap()
            .remove("test_data");
        std::fs::write(&checkpoint_path, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
        validate_resume_context(&ctx, &job, dir.path()).unwrap();
    }

    #[test]
    fn map_test_data_changed_detection_covers_add_change_remove_and_missing_config() {
        let (_dir, mut ctx) = changed_fixture();
        let paths = ctx.role_paths(ANONYMOUS_ROLE);
        let latest = inventory::load(&paths.latest_inventory_path()).unwrap();
        let config_path = Path::new(&latest.scan_dir)
            .parent()
            .unwrap()
            .join("scan.toml");
        let decide = |ctx: &ProjectCtx| {
            plan_changed(
                ctx,
                &paths,
                &route_lists(ctx, ANONYMOUS_ROLE),
                &args(),
                &mut vec![],
            )
            .unwrap()
        };
        assert!(matches!(decide(&ctx), ChangedDecision::Skip(_)));
        ctx.config
            .scan
            .test_data
            .insert("Find shipment".into(), "".into());
        let ChangedDecision::Full(report) = decide(&ctx) else {
            panic!("adding an empty override must refresh the map");
        };
        assert_eq!(
            report.mode_reason.as_deref(),
            Some("scan.test_data changed since the previous map")
        );
        std::fs::write(&config_path, "[scan.test_data]\n\"Find shipment\" = \"\"\n").unwrap();
        assert!(matches!(decide(&ctx), ChangedDecision::Skip(_)));
        ctx.config
            .scan
            .test_data
            .insert("Find shipment".into(), "fixture".into());
        assert!(matches!(decide(&ctx), ChangedDecision::Full(_)));
        ctx.config.scan.test_data.clear();
        assert!(matches!(decide(&ctx), ChangedDecision::Full(_)));
        std::fs::remove_file(&config_path).unwrap();
        let ChangedDecision::Full(report) = decide(&ctx) else {
            panic!("a missing prior config must not prove unchanged fixture values");
        };
        assert!(report.mode_reason.unwrap().contains("unavailable"));
        std::fs::write(&config_path, "[scan.test_data]\nsearch = 123\n").unwrap();
        assert!(matches!(decide(&ctx), ChangedDecision::Full(_)));
    }

    #[test]
    fn resume_settings_never_weaken_the_write_guard() {
        let mut plan = plan_for(&[]);
        let settings = RunSettings {
            scan_mode: "full".into(),
            max_minutes: 0,
            max_views: 0,
            write_guard: "off".into(),
            headless: true,
            tabs: 4,
            role_concurrency: 2,
            ..Default::default()
        };
        assert!(apply_settings(&mut plan, &settings).is_err());
        let settings = RunSettings {
            write_guard: "block".into(),
            view_budget_seconds: Some(300),
            ..settings
        };
        apply_settings(&mut plan, &settings).unwrap();
        assert_eq!(plan.mode, ScanMode::Full);
        assert_eq!((plan.max_minutes, plan.max_views), (0, 0));
        assert_eq!(plan.write_guard, "block");
        assert_eq!(plan.role_concurrency, 2);
        assert!(plan.full.is_some());
        assert_eq!(settings_of(&plan).scan_mode, "full");
    }

    #[test]
    fn cli_spa_override_flags_validate_and_apply_to_plan_and_scan_toml() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::default();
        let mut c = cfg("http://127.0.0.1:3000");
        c.scan.max_interaction_depth = Some(3);
        c.scan.max_interactions_per_view = Some(40);
        c.scan.max_interactions_per_depth = Some(vec![120, 60, 30]);

        let mut a = args();
        a.depth = Some(6);
        a.max_interactions = Some(200);
        a.view_budget = Some(180);
        let plan = make_plan(&ctx_with(c.clone(), dir.path()), &a, &reg).unwrap();
        assert_eq!(plan.mode, ScanMode::Standard);
        assert_eq!(plan.knobs.max_interaction_depth, Some(6));
        assert_eq!(plan.knobs.max_interactions_per_view, Some(200));
        assert_eq!(
            plan.knobs.max_interactions_per_depth,
            Some(vec![120, 60, 30])
        );
        assert_eq!(plan.view_budget_seconds, Some(180));

        // Explicit max_interactions_per_depth overrides full mode's default too.
        a.full = true;
        let full_plan = make_plan(&ctx_with(c.clone(), dir.path()), &a, &reg).unwrap();
        let out = dir.path().join("scan");
        let raw = scan_config_toml(&ScanToml {
            url: &full_plan.url,
            name: "demo",
            headless: true,
            max_minutes: full_plan.max_minutes,
            max_views: full_plan.max_views,
            write_guard: "block",
            write_guard_allow: &[],
            output_dir: &out,
            seed_routes_file: None,
            seed_urls: &[],
            deprioritize_routes: &[],
            scope: None,
            codebase: None,
            route_templates: &[],
            test_data: &BTreeMap::new(),
            knobs: full_plan.knobs.clone(),
            compliance: full_plan.compliance.clone(),
            tabs: full_plan.tabs,
            view_budget_seconds: full_plan.view_budget_seconds,
            full: full_plan.full,
            auth: None,
            auth_contract: None,
            canary_interval_views: None,
        })
        .unwrap();
        let path = dir.path().join("override-scan.toml");
        std::fs::write(&path, &raw).unwrap();
        let parsed = BrokenAppConfig::from_toml_path(&path).unwrap();
        assert_eq!(parsed.scan.exploration.max_interaction_depth, 6);
        assert_eq!(parsed.scan.limits.max_interactions_per_view, 200);
        assert_eq!(parsed.scan.view_budget_seconds, 180);
        assert_eq!(
            parsed.scan.exploration.max_interactions_per_depth,
            vec![120, 60, 30]
        );

        // Resume settings round-trip max_interactions_per_depth.
        let saved = settings_of(&full_plan);
        assert_eq!(saved.max_interactions_per_depth, Some(vec![120, 60, 30]));
        let mut restored = plan_for(&[]);
        apply_settings(&mut restored, &saved).unwrap();
        assert_eq!(
            restored.knobs.max_interactions_per_depth,
            Some(vec![120, 60, 30])
        );

        // Out-of-range CLI overrides fail cleanly.
        let ctx = ctx_with(cfg("http://127.0.0.1:3000"), dir.path());
        let mut bad = args();
        bad.depth = Some(MAX_INTERACTION_DEPTH + 1);
        assert!(format!("{:#}", make_plan(&ctx, &bad, &reg).unwrap_err()).contains("--depth"));
        let mut bad = args();
        bad.max_interactions = Some(0);
        assert!(
            format!("{:#}", make_plan(&ctx, &bad, &reg).unwrap_err())
                .contains("--max-interactions")
        );
        let mut bad = args();
        bad.max_interactions = Some(MAX_INTERACTIONS_PER_VIEW + 1);
        assert!(make_plan(&ctx, &bad, &reg).is_err());
        let mut bad = args();
        bad.view_budget = Some(MIN_VIEW_BUDGET_SECONDS - 1);
        assert!(
            format!("{:#}", make_plan(&ctx, &bad, &reg).unwrap_err()).contains("--view-budget")
        );
        let mut bad = args();
        bad.view_budget = Some(MAX_VIEW_BUDGET_SECONDS + 1);
        assert!(make_plan(&ctx, &bad, &reg).is_err());
    }

    #[test]
    fn scan_json_extracts_stop_reason_and_queue_remaining() {
        let v = serde_json::json!({
            "status": "ok",
            "run": {
                "stop_reason": "max_views_reached",
                "queue_remaining": 14
            }
        });
        assert_eq!(scan_stop_reason(&v).as_deref(), Some("max_views_reached"));
        assert_eq!(scan_queue_remaining(&v), Some(14));
        assert_eq!(scan_stop_reason(&serde_json::json!({})), None);
        assert_eq!(scan_queue_remaining(&serde_json::json!({})), None);
    }

    #[test]
    fn resolved_limits_and_next_hints_reflect_mode_partial_and_completion() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::default();
        let ctx = ctx_with(cfg("http://127.0.0.1:3000"), dir.path());

        let std_plan = make_plan(&ctx, &args(), &reg).unwrap();
        let std_limits = resolved_limits(&std_plan);
        assert_eq!(std_limits.scan_mode, "standard");
        assert_eq!(std_limits.max_interaction_depth, 2);
        assert_eq!(std_limits.max_interactions_per_view, 25);
        assert_eq!(std_limits.max_interactions_per_depth, vec![25, 15, 10]);
        assert_eq!(std_limits.view_budget_seconds, None);

        let mut full_args = args();
        full_args.full = true;
        let full_plan = make_plan(&ctx, &full_args, &reg).unwrap();
        let full_limits = resolved_limits(&full_plan);
        assert_eq!(full_limits.scan_mode, "full");
        assert_eq!(full_limits.max_interaction_depth, 4);
        assert_eq!(full_limits.max_interactions_per_view, 1000);
        assert_eq!(
            full_limits.max_interactions_per_depth,
            vec![1000, 250, 100, 50, 50]
        );
        assert_eq!(full_limits.view_budget_seconds, Some(300));

        // --full --depth 6 pads max_interactions_per_depth to cover depths 0..=6.
        let mut deep_args = args();
        deep_args.full = true;
        deep_args.depth = Some(6);
        let deep_plan = make_plan(&ctx, &deep_args, &reg).unwrap();
        let deep_limits = resolved_limits(&deep_plan);
        assert_eq!(
            deep_limits.max_interactions_per_depth,
            vec![1000, 250, 100, 50, 50, 50, 50]
        );

        // Partial --route run gets --inventory hints.
        let partial_next = build_next_hints(&NextHintsInput {
            partial: true,
            inventory: "/repo/.brokenapp/history/partial/run.inventory.json",
            resumable_full: false,
            incomplete: true,
            has_dead_or_broken: true,
            role_aware: false,
            state_dir: None,
        });
        assert_eq!(
            partial_next,
            vec![
                "brokenapp ui --inventory /repo/.brokenapp/history/partial/run.inventory.json --compact",
                "brokenapp journey <goal> --inventory /repo/.brokenapp/history/partial/run.inventory.json",
                "brokenapp map --full",
                "brokenapp dead",
            ]
        );

        // Resumable full run with roles gets --resume and --role all.
        let full_next = build_next_hints(&NextHintsInput {
            partial: false,
            inventory: "/repo/.brokenapp/history/latest.inventory.json",
            resumable_full: true,
            incomplete: true,
            has_dead_or_broken: true,
            role_aware: true,
            state_dir: None,
        });
        assert_eq!(
            full_next,
            vec!["brokenapp map --resume", "brokenapp dead --role all"]
        );

        // Explicit --state-dir propagates into generated next hints.
        let custom_next = build_next_hints(&NextHintsInput {
            partial: false,
            inventory: "/tmp/custom/history/latest.inventory.json",
            resumable_full: true,
            incomplete: true,
            has_dead_or_broken: true,
            role_aware: true,
            state_dir: Some("/tmp/custom"),
        });
        assert_eq!(
            custom_next,
            vec![
                "brokenapp map --resume --state-dir /tmp/custom",
                "brokenapp dead --role all --state-dir /tmp/custom",
            ]
        );
    }

    #[test]
    fn full_mode_clamps_view_budget_when_max_minutes_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::default();
        let ctx = ctx_with(cfg("http://127.0.0.1:3000"), dir.path());

        let mut a = args();
        a.full = true;
        a.max_minutes = Some(3);
        let plan = make_plan(&ctx, &a, &reg).unwrap();
        assert_eq!(plan.view_budget_seconds, Some(90));

        // Very short --max-minutes floors at 30s.
        a.max_minutes = Some(1);
        let plan = make_plan(&ctx, &a, &reg).unwrap();
        assert_eq!(plan.view_budget_seconds, Some(30));

        // Large --max-minutes stays capped at FULL_VIEW_BUDGET_SECONDS (300).
        a.max_minutes = Some(20);
        let plan = make_plan(&ctx, &a, &reg).unwrap();
        assert_eq!(plan.view_budget_seconds, Some(300));

        // Explicit --view-budget overrides the clamp.
        a.max_minutes = Some(3);
        a.view_budget = Some(240);
        let plan = make_plan(&ctx, &a, &reg).unwrap();
        assert_eq!(plan.view_budget_seconds, Some(240));
    }

    #[test]
    fn empty_timeout_run_preserves_previous_good_map() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with(cfg("http://127.0.0.1:3000"), dir.path());
        let paths = ctx.role_paths("csm");
        let plan = plan_for(&[]);
        let empty_inv = Inventory {
            coverage: CoverageSummary {
                routes_known: 78,
                routes_visited: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        // No previous map -> nothing to preserve.
        assert_eq!(
            should_preserve_previous_map(&paths, &plan, &empty_inv, Some("hard_timeout")),
            None
        );

        // Save a non-empty previous good map (4 routes visited).
        let good_prev = Inventory {
            schema: inventory::INVENTORY_SCHEMA.into(),
            project: "demo".into(),
            generated_at: "2026-11-20T00:00:00Z".into(),
            coverage: CoverageSummary {
                routes_known: 78,
                routes_visited: 4,
                ..Default::default()
            },
            ..Default::default()
        };
        inventory::save(&good_prev, &paths.latest_inventory_path()).unwrap();

        for reason in [
            "hard_timeout",
            "max_duration_reached",
            "browser_unavailable",
            "partial_timeout",
        ] {
            assert_eq!(
                should_preserve_previous_map(&paths, &plan, &empty_inv, Some(reason)),
                Some(4),
                "expected preserve for {reason}"
            );
        }

        // Normal queue_exhausted or non-empty run or --route partial does not trigger.
        assert_eq!(
            should_preserve_previous_map(&paths, &plan, &empty_inv, Some("queue_exhausted")),
            None
        );
        assert_eq!(
            should_preserve_previous_map(&paths, &plan, &good_prev, Some("hard_timeout")),
            None
        );
        assert_eq!(
            should_preserve_previous_map(
                &paths,
                &plan_for(&["/login"]),
                &empty_inv,
                Some("hard_timeout")
            ),
            None
        );
    }

    #[test]
    fn role_access_skipped_for_partial_route_scans() {
        assert!(should_write_role_access(true, &plan_for(&[])));
        assert!(!should_write_role_access(false, &plan_for(&[])));
        assert!(!should_write_role_access(true, &plan_for(&["/login"])));
    }

    #[test]
    fn partial_route_scan_relabels_unrequested_unvisited_routes() {
        let mut inv = Inventory {
            routes: vec![
                crate::inventory::RouteEntry {
                    route: "/login".into(),
                    visited: true,
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/lead-intake".into(),
                    visited: false,
                    unvisited_reason: Some("not linked or seeded".into()),
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/dashboard".into(),
                    visited: false,
                    unvisited_reason: Some("not linked or seeded".into()),
                    ..Default::default()
                },
            ],
            coverage: CoverageSummary {
                unvisited_by_reason: BTreeMap::from([(
                    "not linked or seeded".to_string(),
                    vec!["/lead-intake".to_string(), "/dashboard".to_string()],
                )]),
                ..Default::default()
            },
            ..Default::default()
        };

        relabel_outside_route_filter(
            &mut inv,
            &["/login".to_string(), "/lead-intake".to_string()],
        );
        assert_eq!(
            inv.routes[1].unvisited_reason.as_deref(),
            Some("not linked or seeded")
        );
        assert_eq!(
            inv.routes[2].unvisited_reason.as_deref(),
            Some("outside --route filter")
        );
        assert_eq!(
            inv.coverage.unvisited_by_reason.get("not linked or seeded"),
            Some(&vec!["/lead-intake".to_string()])
        );
        assert_eq!(
            inv.coverage
                .unvisited_by_reason
                .get("outside --route filter"),
            Some(&vec!["/dashboard".to_string()])
        );
    }

    #[test]
    fn anonymous_add_role_warning_suppressed_when_roles_configured_and_eta_and_unvisited_deduped() {
        let warnings = vec![
            "skipped seeds: 5 seeded route(s) redirect to login; add a role ([[roles]] in .brokenapp/config.toml) to map pages behind login: /dashboard".to_string(),
            "scan stopped early: max_duration_reached".to_string(),
        ];
        // Roles already configured: suppress on anonymous, keep other warnings.
        let filtered = normalize_scan_warnings(warnings.clone(), ANONYMOUS_ROLE, true);
        assert_eq!(filtered, vec!["scan stopped early: max_duration_reached"]);
        // No roles configured yet: keep the add-a-role hint on anonymous.
        assert_eq!(
            normalize_scan_warnings(warnings.clone(), ANONYMOUS_ROLE, false).len(),
            2
        );
        // Non-anonymous role keeps warnings.
        assert_eq!(normalize_scan_warnings(warnings, "admin", true).len(), 2);

        // ETA capped to remaining budget when max_minutes > 0.
        assert_eq!(cap_eta_to_budget(Some(3780), 65, 2), Some(55));
        assert_eq!(cap_eta_to_budget(Some(30), 65, 2), Some(30));
        assert_eq!(cap_eta_to_budget(Some(3780), 125, 2), None);
        assert_eq!(cap_eta_to_budget(Some(3780), 65, 0), Some(3780));

        // unvisited_by_reason deduplication.
        let map = BTreeMap::from([("not linked or seeded".to_string(), vec!["/a".to_string()])]);
        let cov = CoverageSummary {
            unvisited_by_reason: map.clone(),
            ..Default::default()
        };
        assert!(dedup_unvisited_by_reason(map.clone(), &cov, false).is_empty());
        assert!(
            dedup_unvisited_by_reason(map.clone(), &CoverageSummary::default(), true).is_empty()
        );
        assert_eq!(
            dedup_unvisited_by_reason(map.clone(), &CoverageSummary::default(), false),
            map
        );
    }

    #[test]
    fn authenticated_role_scan_config_seeds_ui_check_and_deprioritizes_anon_public_routes() {
        use crate::front::roles::RoleConfig;

        let dir = tempfile::tempdir().unwrap();
        let mut config = cfg("http://127.0.0.1:3000/");
        config.roles.push(RoleConfig {
            name: "ops".into(),
            method: RoleMethod::Form,
            check: Some("/ops".into()),
            ..Default::default()
        });
        config.roles.push(RoleConfig {
            name: "admin".into(),
            method: RoleMethod::Form,
            check: Some("/api/me".into()),
            ..Default::default()
        });
        let ctx = ctx_with(config, dir.path());

        let anon_inv = Inventory {
            generated_at: "2026-11-21T00:00:00Z".into(),
            routes: vec![
                crate::inventory::RouteEntry {
                    route: "/".into(),
                    visited: true,
                    status: Some(200),
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/pricing".into(),
                    visited: true,
                    status: Some(200),
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/features/".into(),
                    visited: true,
                    status: Some(200),
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/ops".into(),
                    visited: true,
                    status: Some(200),
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/dashboard".into(),
                    visited: false,
                    status: None,
                    unvisited_reason: Some("redirects to login".into()),
                    ..Default::default()
                },
                crate::inventory::RouteEntry {
                    route: "/admin".into(),
                    visited: true,
                    status: Some(403),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        inventory::save(
            &anon_inv,
            &ctx.role_paths(ANONYMOUS_ROLE).latest_inventory_path(),
        )
        .unwrap();

        let plan = make_plan(&ctx, &args(), &Registry::default()).unwrap();

        // Authenticated role with a UI `--check` page: seeded in `seed_urls` and
        // excluded from `deprioritize_routes`, while anonymous's 200 public routes
        // (excluding `/`) are deprioritized.
        let ops_resolved = ResolvedRole {
            name: "ops".into(),
            method: RoleMethod::Form,
            ..Default::default()
        };
        let ops_run = RunPaths::at("ops", dir.path().join("run-ops"));
        std::fs::create_dir_all(&ops_run.dir).unwrap();
        write_scan_inputs(
            &ctx,
            &plan,
            &ops_run,
            &Seeds::default(),
            &ops_resolved,
            None,
        )
        .unwrap();
        let ops_cfg = BrokenAppConfig::from_toml_path(&ops_run.scan_toml).unwrap();
        assert_eq!(ops_cfg.scan.seed_urls, vec!["/ops"]);
        assert_eq!(
            ops_cfg.scan.deprioritize_routes,
            vec!["/features", "/pricing"]
        );

        // Authenticated role with an `/api/` `--check` probe: NOT added to `seed_urls`,
        // still deprioritizes anonymous's 200 routes.
        let admin_resolved = ResolvedRole {
            name: "admin".into(),
            method: RoleMethod::Form,
            ..Default::default()
        };
        let admin_run = RunPaths::at("admin", dir.path().join("run-admin"));
        std::fs::create_dir_all(&admin_run.dir).unwrap();
        write_scan_inputs(
            &ctx,
            &plan,
            &admin_run,
            &Seeds::default(),
            &admin_resolved,
            None,
        )
        .unwrap();
        let admin_cfg = BrokenAppConfig::from_toml_path(&admin_run.scan_toml).unwrap();
        assert!(admin_cfg.scan.seed_urls.is_empty());
        assert_eq!(
            admin_cfg.scan.deprioritize_routes,
            vec!["/features", "/ops", "/pricing"]
        );

        // Anonymous role never sets `seed_urls` or `deprioritize_routes`.
        let anon_resolved = ResolvedRole {
            name: ANONYMOUS_ROLE.into(),
            ..Default::default()
        };
        let anon_run = RunPaths::at("anon", dir.path().join("run-anon"));
        std::fs::create_dir_all(&anon_run.dir).unwrap();
        write_scan_inputs(
            &ctx,
            &plan,
            &anon_run,
            &Seeds::default(),
            &anon_resolved,
            None,
        )
        .unwrap();
        let anon_cfg = BrokenAppConfig::from_toml_path(&anon_run.scan_toml).unwrap();
        assert!(anon_cfg.scan.seed_urls.is_empty());
        assert!(anon_cfg.scan.deprioritize_routes.is_empty());

        // In-memory anonymous inventory works even when no saved file exists on disk.
        std::fs::remove_file(ctx.role_paths(ANONYMOUS_ROLE).latest_inventory_path()).unwrap();
        let mem_run = RunPaths::at("ops-mem", dir.path().join("run-ops-mem"));
        std::fs::create_dir_all(&mem_run.dir).unwrap();
        write_scan_inputs(
            &ctx,
            &plan,
            &mem_run,
            &Seeds::default(),
            &ops_resolved,
            Some(&anon_inv),
        )
        .unwrap();
        let mem_cfg = BrokenAppConfig::from_toml_path(&mem_run.scan_toml).unwrap();
        assert_eq!(mem_cfg.scan.seed_urls, vec!["/ops"]);
        assert_eq!(
            mem_cfg.scan.deprioritize_routes,
            vec!["/features", "/pricing"]
        );
    }

    #[test]
    fn role_access_renders_failed_role_error_details_in_this_run_column() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = cfg("http://127.0.0.1:3000/");
        for name in ["ops", "staff", "viewer", "member"] {
            config.roles.push(roles::RoleConfig {
                name: name.into(),
                method: RoleMethod::Form,
                ..Default::default()
            });
        }
        let ctx = ctx_with(config, dir.path());
        let sample_inv = |route: &str| Inventory {
            generated_at: "2026-11-21T00:00:00Z".into(),
            routes: vec![crate::inventory::RouteEntry {
                route: route.into(),
                visited: true,
                status: Some(200),
                ..Default::default()
            }],
            ..Default::default()
        };
        inventory::save(
            &sample_inv("/"),
            &ctx.role_paths(ANONYMOUS_ROLE).latest_inventory_path(),
        )
        .unwrap();
        inventory::save(
            &sample_inv("/ops"),
            &ctx.role_paths("ops").latest_inventory_path(),
        )
        .unwrap();
        inventory::save(
            &sample_inv("/member"),
            &ctx.role_paths("member").latest_inventory_path(),
        )
        .unwrap();

        let long_err = "x".repeat(160);
        let manifest = RunManifest::new(
            "run",
            "now",
            RunSettings::default(),
            vec![
                RunRole {
                    name: ANONYMOUS_ROLE.into(),
                    status: "mapped".into(),
                    ..Default::default()
                },
                RunRole {
                    name: "ops".into(),
                    status: "login_failed".into(),
                    error: Some("GET /ops returned HTTP 307 -> /ops".into()),
                    ..Default::default()
                },
                RunRole {
                    name: "staff".into(),
                    status: "session_expired".into(),
                    error: Some("first line\n   second line | with pipe".into()),
                    ..Default::default()
                },
                RunRole {
                    name: "viewer".into(),
                    status: "failed".into(),
                    error: Some(long_err),
                    ..Default::default()
                },
                RunRole {
                    name: "member".into(),
                    status: "unchanged".into(),
                    error: Some("no UI files changed".into()),
                    ..Default::default()
                },
            ],
        );
        let path = write_role_access(&ctx, &manifest).unwrap();
        let md = std::fs::read_to_string(&path).unwrap();
        assert!(
            md.contains(
                "| ops | form | no map | 0/0 | login_failed (GET /ops returned HTTP 307 -> /ops) |"
            ),
            "{md}"
        );
        assert!(
            md.contains("session_expired (first line second line \\| with pipe)"),
            "{md}"
        );
        let viewer_line = md
            .lines()
            .find(|l| l.starts_with("| viewer |"))
            .expect("viewer row");
        assert!(viewer_line.contains("failed ("), "{viewer_line}");
        assert!(viewer_line.contains("...) |"), "{viewer_line}");
        let detail = viewer_line
            .split("failed (")
            .nth(1)
            .and_then(|s| s.strip_suffix(") |"))
            .expect("truncated detail");
        assert_eq!(detail.chars().count(), 120, "{detail}");
        // Unchanged role keeps its inventory and does not append `mode_reason`.
        assert!(
            md.contains("| member | form | 2026-11-21T00:00:00Z | 0/0 | unchanged |")
                || md.contains("| member | form | 2026-11-21T00:00:00Z |"),
            "{md}"
        );
        assert!(!md.contains("unchanged ("), "{md}");
        // Failed `ops` history is still excluded from access evidence, while `member` is kept.
        let tsv = std::fs::read_to_string(ctx.map_dir().join("role-access.tsv")).unwrap();
        assert!(
            tsv.contains("route\t/member\t\tnot_linked\t-\t-\t-\tvisited\t"),
            "{tsv}"
        );
        assert!(!tsv.contains("route\t/ops\t"), "{tsv}");

        let index = std::fs::read_to_string(ctx.map_dir().join("README.md")).unwrap();
        assert!(
            index.contains("login_failed (GET /ops returned HTTP 307 -> /ops)"),
            "{index}"
        );
    }

    #[test]
    fn single_route_view_budget_hint_suggests_view_budget_for_tabbed_spas() {
        let mut spa_inv = Inventory {
            coverage: CoverageSummary {
                routes_known: 1,
                routes_visited: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        spa_inv
            .coverage
            .not_exercised_by_reason
            .insert("view_time_budget".into(), 19);

        let (warn, cmd) = single_route_view_budget_hint(&spa_inv, None, None, None).unwrap();
        assert_eq!(cmd, "brokenapp map --full --view-budget 600");
        assert!(warn.contains("19 controls skipped"), "{warn}");
        assert!(warn.contains(&cmd), "{warn}");

        // Role + state-dir are preserved and quoted when set; anonymous omits --role.
        let (_, role_cmd) = single_route_view_budget_hint(
            &spa_inv,
            Some("queue_exhausted"),
            Some("admin"),
            Some("/tmp/my app/.brokenapp"),
        )
        .unwrap();
        assert_eq!(
            role_cmd,
            "brokenapp map --full --view-budget 600 --role admin --state-dir '/tmp/my app/.brokenapp'"
        );
        let (_, anon_cmd) =
            single_route_view_budget_hint(&spa_inv, None, Some(ANONYMOUS_ROLE), None).unwrap();
        assert_eq!(anon_cmd, "brokenapp map --full --view-budget 600");

        // 2 routes + view_timeout stop_reason without pre-populated counts still triggers.
        let two_route_stop = Inventory {
            coverage: CoverageSummary {
                routes_known: 2,
                routes_visited: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            single_route_view_budget_hint(&two_route_stop, Some("view_timeout"), None, None)
                .is_some()
        );

        // Fallback scans inv.controls directly when coverage.not_exercised_by_reason is empty.
        let control_only = Inventory {
            coverage: CoverageSummary {
                routes_known: 1,
                routes_visited: 1,
                ..Default::default()
            },
            controls: vec![crate::inventory::Control {
                status: ControlStatus::NotExercised,
                reason: Some("view_budget_exhausted".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(single_route_view_budget_hint(&control_only, None, None, None).is_some());

        // Multi-route apps (> 2 visited routes), 0-route runs, and non-budget skips do not trigger.
        let mut multi_route = spa_inv.clone();
        multi_route.coverage.routes_visited = 3;
        assert!(single_route_view_budget_hint(&multi_route, None, None, None).is_none());

        let mut zero_route = spa_inv.clone();
        zero_route.coverage.routes_visited = 0;
        assert!(single_route_view_budget_hint(&zero_route, None, None, None).is_none());

        let mut non_budget = Inventory {
            coverage: CoverageSummary {
                routes_known: 1,
                routes_visited: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        non_budget
            .coverage
            .not_exercised_by_reason
            .insert("obscured".into(), 12);
        assert!(single_route_view_budget_hint(&non_budget, None, None, None).is_none());
    }

    #[test]
    fn warmup_auth_headers_extracts_cookie_bearer_and_matching_storage_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = cfg("http://127.0.0.1:3000/");
        config.roles.push(roles::RoleConfig {
            name: "form-user".into(),
            method: RoleMethod::Form,
            login_url: Some("/login".into()),
            ..Default::default()
        });
        config.roles.push(roles::RoleConfig {
            name: "cookie-user".into(),
            method: RoleMethod::Cookie,
            cookie: Some("env:TEST_WARMUP_COOKIE".into()),
            ..Default::default()
        });
        config.roles.push(roles::RoleConfig {
            name: "bearer-user".into(),
            method: RoleMethod::Bearer,
            token: Some("env:TEST_WARMUP_TOKEN".into()),
            ..Default::default()
        });
        config.roles.push(roles::RoleConfig {
            name: "session-user".into(),
            method: RoleMethod::Session,
            ..Default::default()
        });
        let ctx = ctx_with(config, dir.path());
        let url = Url::parse("http://127.0.0.1:3000/").unwrap();
        let creds = roles::CredentialsFile::default();

        // Cookie role produces normalized Cookie header.
        let env_cookie = |k: &str| {
            (k == "TEST_WARMUP_COOKIE").then(|| "Set-Cookie: sid=abc123; Path=/; HttpOnly".into())
        };
        let resolved_cookie =
            roles::resolve_role(&ctx.config.roles[1], &ctx.state_dir, &creds, &env_cookie);
        let hdrs = warmup_auth_headers_for_role(&ctx, &url, &resolved_cookie, &env_cookie);
        assert_eq!(hdrs.get("Cookie").map(String::as_str), Some("sid=abc123"));

        // Bearer role produces Authorization header.
        let env_bearer = |k: &str| (k == "TEST_WARMUP_TOKEN").then(|| "tok-xyz".into());
        let resolved_bearer =
            roles::resolve_role(&ctx.config.roles[2], &ctx.state_dir, &creds, &env_bearer);
        let hdrs = warmup_auth_headers_for_role(&ctx, &url, &resolved_bearer, &env_bearer);
        assert_eq!(
            hdrs.get("Authorization").map(String::as_str),
            Some("Bearer tok-xyz")
        );

        // Storage-state session filters cookies by matching host (including localhost alias) and expiry.
        let sess_path = ctx.config.roles[3].session_path(&ctx.state_dir);
        let state = crate::session::storage_state::StorageState {
            cookies: vec![
                crate::session::storage_state::StoredCookie {
                    name: "app_sid".into(),
                    value: "live-1".into(),
                    domain: "localhost".into(),
                    path: "/".into(),
                    expires: -1.0,
                    http_only: true,
                    secure: false,
                    same_site: Some("Lax".into()),
                },
                crate::session::storage_state::StoredCookie {
                    name: "expired_sid".into(),
                    value: "old".into(),
                    domain: "127.0.0.1".into(),
                    path: "/".into(),
                    expires: 1.0,
                    http_only: false,
                    secure: false,
                    same_site: None,
                },
                crate::session::storage_state::StoredCookie {
                    name: "other_site".into(),
                    value: "nope".into(),
                    domain: "evil.example.com".into(),
                    path: "/".into(),
                    expires: -1.0,
                    http_only: false,
                    secure: false,
                    same_site: None,
                },
            ],
            ..Default::default()
        };
        crate::session::storage_state::write_storage_state(&sess_path, &state).unwrap();
        let no_env = |_: &str| None;
        let resolved_session =
            roles::resolve_role(&ctx.config.roles[3], &ctx.state_dir, &creds, &no_env);
        let hdrs = warmup_auth_headers_for_role(&ctx, &url, &resolved_session, &no_env);
        assert_eq!(
            hdrs.get("Cookie").map(String::as_str),
            Some("app_sid=live-1")
        );

        // Form role without saved session returns empty (graceful unauthenticated warm-up).
        let form_creds = roles::CredentialsFile {
            roles: BTreeMap::from([(
                "form-user".into(),
                roles::RoleCredentials {
                    username: Some("u".into()),
                    password: Some("p".into()),
                    ..Default::default()
                },
            )]),
        };
        let resolved_form =
            roles::resolve_role(&ctx.config.roles[0], &ctx.state_dir, &form_creds, &no_env);
        assert!(warmup_auth_headers_for_role(&ctx, &url, &resolved_form, &no_env).is_empty());
    }

    #[test]
    fn compliance_knobs_validation_remote_defaults_and_scan_toml_roundtrip() {
        let path = Path::new("/repo/.brokenapp/config.toml");

        // Local default leaves abort thresholds unset (0 in ScanConfig).
        let local_scan = project::ScanSection::default();
        let local = compliance_knobs(&local_scan, path).unwrap();
        assert_eq!(local, ComplianceKnobs::default());

        // allow_remote = true defaults abort_on_rate_limits = 5 and abort_on_antibot_challenges = 2.
        let mut remote_scan = project::ScanSection {
            allow_remote: true,
            ..Default::default()
        };
        let remote = compliance_knobs(&remote_scan, path).unwrap();
        assert_eq!(remote.abort_on_rate_limits, Some(5));
        assert_eq!(remote.abort_on_antibot_challenges, Some(2));

        // Explicit 0 disables remote abort.
        remote_scan.abort_on_rate_limits = Some(0);
        remote_scan.abort_on_antibot_challenges = Some(0);
        let disabled = compliance_knobs(&remote_scan, path).unwrap();
        assert_eq!(disabled.abort_on_rate_limits, Some(0));
        assert_eq!(disabled.abort_on_antibot_challenges, Some(0));

        // Validation catches bad header names, newlines, schemes/paths in allowed_hosts, bad wildcards, bad RPS.
        let mut bad = project::ScanSection::default();
        bad.extra_headers.insert("Bad Header".into(), "x".into());
        assert!(compliance_knobs(&bad, path).is_err());

        let mut bad = project::ScanSection::default();
        bad.extra_headers
            .insert("X-QA-Runner".into(), "ci\r\nEvil: 1".into());
        assert!(compliance_knobs(&bad, path).is_err());

        let mut bad = project::ScanSection {
            user_agent: Some("UA\nEvil".into()),
            ..Default::default()
        };
        assert!(compliance_knobs(&bad, path).is_err());

        bad.user_agent = None;
        bad.allowed_hosts = vec!["https://example.com".into()];
        assert!(compliance_knobs(&bad, path).is_err());
        bad.allowed_hosts = vec!["foo.*.example.com".into()];
        assert!(compliance_knobs(&bad, path).is_err());
        bad.allowed_hosts.clear();
        bad.max_requests_per_second = Some(0.0);
        assert!(compliance_knobs(&bad, path).is_err());
        bad.max_requests_per_second = Some(f64::NAN);
        assert!(compliance_knobs(&bad, path).is_err());
        bad.max_requests_per_second = None;
        bad.interaction_delay_ms = Some(120_000);
        assert!(compliance_knobs(&bad, path).is_err());

        // Full valid compliance section round-trips through scan_config_toml -> BrokenAppConfig.
        let mut valid = project::ScanSection {
            allow_remote: true,
            user_agent: Some("BrokenApp/0.1 (staging-qa)".into()),
            allowed_hosts: vec!["APP.EXAMPLE.COM".into(), "*.example.com".into()],
            interaction_delay_ms: Some(400),
            max_requests_per_second: Some(2.5),
            abort_on_rate_limits: Some(4),
            abort_on_antibot_challenges: Some(1),
            ..Default::default()
        };
        valid
            .extra_headers
            .insert("X-QA-Runner".into(), "staging-ci".into());
        let compliance = compliance_knobs(&valid, path).unwrap();
        assert_eq!(
            compliance.allowed_hosts,
            vec!["app.example.com", "*.example.com"]
        );

        let dir = tempfile::tempdir().unwrap();
        let url = Url::parse("https://app.example.com/").unwrap();
        let out = dir.path().join("scan");
        let raw = scan_config_toml(&ScanToml {
            url: &url,
            name: "remote-demo",
            headless: true,
            max_minutes: 5,
            max_views: 30,
            write_guard: "block",
            write_guard_allow: &[],
            output_dir: &out,
            seed_routes_file: None,
            seed_urls: &[],
            deprioritize_routes: &[],
            scope: None,
            codebase: None,
            route_templates: &[],
            test_data: &BTreeMap::new(),
            knobs: CrawlKnobs::default(),
            compliance,
            tabs: 2,
            view_budget_seconds: None,
            full: None,
            auth: None,
            auth_contract: None,
            canary_interval_views: None,
        })
        .unwrap();
        let toml_path = dir.path().join("scan.toml");
        std::fs::write(&toml_path, &raw).unwrap();
        let parsed = BrokenAppConfig::from_toml_path(&toml_path).unwrap();
        assert_eq!(
            parsed.scan.allowed_hosts,
            vec!["app.example.com", "*.example.com"]
        );
        assert_eq!(
            parsed
                .scan
                .extra_headers
                .get("X-QA-Runner")
                .map(String::as_str),
            Some("staging-ci")
        );
        assert_eq!(
            parsed.scan.user_agent.as_deref(),
            Some("BrokenApp/0.1 (staging-qa)")
        );
        assert_eq!(parsed.scan.pacing.delay_between_interactions_ms, 400);
        assert_eq!(parsed.scan.pacing.max_requests_per_second, Some(2.5));
        assert_eq!(parsed.scan.abort_on_rate_limits, 4);
        assert_eq!(parsed.scan.abort_on_antibot_challenges, 1);

        // Hard-abort stop reasons preserve previous whole-app baseline maps.
        assert!(is_empty_timeout_or_error_stop(Some("rate_limited")));
        assert!(is_empty_timeout_or_error_stop(Some("antibot_challenge")));
    }
}
