//! Project resolution for the front-door commands.
//!
//! Layout inside a project (default state dir `<repo>/.brokenapp/`):
//!
//! ```text
//! .brokenapp/
//!   config.toml        project config (commit it; `[[roles]]` hold env: references only)
//!   .gitignore         ignores everything but config.toml and map/
//!   credentials.toml   role credentials (chmod 600, never commit)
//!   map/               greppable UI map (commit it); the anonymous (logged-out) map
//!     UI-MAP.md  ui-map.tsv  endpoints.tsv  DEAD-UI.md  CHANGELOG.md
//!     README.md  ROLE-ACCESS.md  role-access.tsv   (when roles are configured)
//!     roles/<role>/    the same map files for each configured role
//!   history/           <timestamp>.inventory.json + latest.inventory.json
//!     roles/<role>/    per-role inventory history
//!   scans/             raw scan directories (`<ts>/run.json` + `roles/<role>/`)
//!   session/           saved browser sessions per role (never commit)
//! ```
//!
//! A global registry at `$BROKENAPP_HOME/registry.json` (default
//! `~/.brokenapp/registry.json`) lists projects so commands can run with
//! `--project <name>` from anywhere.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use serde::{Deserialize, Serialize};

pub const STATE_DIR_NAME: &str = ".brokenapp";
pub const CONFIG_FILE: &str = "config.toml";
pub const LATEST_INVENTORY: &str = "latest.inventory.json";
/// Portable inventory emitted inside `.brokenapp/map/` (and `map/roles/<role>/`)
/// so `ui`, `dead`, `journey`, and `parity` work on fresh clones without `history/`.
pub const PORTABLE_INVENTORY: &str = "ui-inventory.json";
/// Role credentials file inside the state dir (gitignored, mode 0600).
pub const CREDENTIALS_FILE: &str = "credentials.toml";
/// The implicit logged-out role; its map is the top-level `map/`.
pub const ANONYMOUS_ROLE: &str = "anonymous";
/// Default seconds `map` waits for a dev server it started to answer.
pub const DEFAULT_READY_TIMEOUT_SECS: u64 = 120;

/// Shared flags for selecting a project.
#[derive(Debug, Clone, Default, Args)]
pub struct ProjectTarget {
    /// Registered project name (see `brokenapp projects`). Defaults to the
    /// project containing the current directory.
    #[arg(long, global = true)]
    pub project: Option<String>,
    /// Explicit state directory (overrides discovery; also `BROKENAPP_STATE_DIR`).
    #[arg(long, global = true, env = "BROKENAPP_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
}

/// `.brokenapp/config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProjectConfig {
    pub project: ProjectSection,
    #[serde(default)]
    pub scan: ScanSection,
    #[serde(default)]
    pub auth: AuthSection,
    /// Login types to map besides the anonymous (logged-out) app. Any
    /// number; secret fields hold `env:NAME` references only (see
    /// [`super::roles`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<super::roles::RoleConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProjectSection {
    pub name: String,
    /// Local URL of the running app, e.g. `http://127.0.0.1:3100`.
    pub url: String,
    /// Codebase root, relative to the state dir's parent (usually `.`).
    #[serde(default = "default_codebase")]
    pub codebase: String,
    /// Command that starts the dev server (run when `url` is not reachable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_cmd: Option<String>,
    /// Working directory for `dev_cmd`, relative to the codebase root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_cwd: Option<String>,
    /// Extra environment for `dev_cmd` (values may be `env:NAME` references).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub dev_env: std::collections::BTreeMap<String, String>,
    #[serde(default = "default_ready_timeout_secs")]
    pub ready_timeout_secs: u64,
    /// Refuse to scan (live-user / production projects).
    #[serde(default)]
    pub protected: bool,
}

/// `[scan] mode`: how much of the app one `map` run covers.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    /// Bounded run: `max_minutes` / `max_views` (10 minutes / 80 views by default).
    #[default]
    Standard,
    /// No global time/view caps, with larger per-view budgets.
    /// Runs can take hours; `max_hours` is an optional ceiling.
    Full,
}

impl ScanMode {
    pub fn is_standard(&self) -> bool {
        *self == ScanMode::Standard
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ScanMode::Standard => "standard",
            ScanMode::Full => "full",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "standard" => Some(ScanMode::Standard),
            "full" => Some(ScanMode::Full),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanSection {
    /// `standard` (default) or `full` (map the whole app; no caps).
    #[serde(default, skip_serializing_if = "ScanMode::is_standard")]
    pub mode: ScanMode,
    /// Standard mode only (full mode has no time cap).
    #[serde(default = "default_max_minutes")]
    pub max_minutes: u64,
    /// Standard mode only (full mode has no view cap).
    #[serde(default = "default_max_views")]
    pub max_views: usize,
    /// Full mode: optional safety ceiling in hours (default: none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hours: Option<u64>,
    /// Seconds one view (page) may take, including all of its controls.
    /// Unset: automatic in standard mode, 300 in full mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_budget_seconds: Option<u64>,
    /// Roles mapped at the same time (default 1: one after another). The
    /// browser tabs (`tabs`) are shared between them, so the total stays bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_concurrency: Option<usize>,
    /// Seconds between progress lines (default: 60 in full mode; standard
    /// mode prints when progress changes, at most every 5 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_seconds: Option<u64>,
    /// `block` (default), `stub`, or `off`.
    #[serde(default = "default_write_guard")]
    pub write_guard: String,
    /// `METHOD url-glob` patterns let through the write guard, for endpoints
    /// the app needs to function locally (e.g. `POST */api/session`). Only
    /// list endpoints that write to local/disposable data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_guard_allow: Vec<String>,
    /// Extra routes to seed (in addition to routes discovered from source).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_routes: Vec<String>,
    /// Route prefixes never to visit (e.g. `/logout`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_routes: Vec<String>,
    /// Use routes discovered from source as seeds.
    #[serde(default = "default_true")]
    pub seed_from_source: bool,
    #[serde(default = "default_true")]
    pub headless: bool,
    /// Allow non-local target URLs (off by default).
    #[serde(default)]
    pub allow_remote: bool,
    /// How many levels of revealed UI (modal -> step -> dialog) the crawler
    /// follows on one page. Scanner default 2; raise it for wizards and
    /// multi-step flows on a single URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interaction_depth: Option<usize>,
    /// Controls exercised per view before the rest are left `not_exercised`
    /// (reason `interaction_limit`). Scanner default 25.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interactions_per_view: Option<usize>,
    /// Controls exercised inside revealed UI at each nesting depth
    /// (`[depth0, depth1, ...]`; the last value repeats for deeper levels).
    /// Unset: scanner default `[25, 15, 10]` in standard mode,
    /// `[1000, 250, 100, 50]` in full mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interactions_per_depth: Option<Vec<usize>>,
    /// Milliseconds to wait for the page to settle after each action.
    /// Scanner default 2000; raise it for slow lazy-loaded screens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_ms: Option<u64>,
    /// Browser tabs the crawler may use at once (`brokenapp map` default 4;
    /// `--tabs` overrides it). 1 crawls one page at a time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tabs: Option<usize>,
    /// Literal fixture values keyed by input name, then label. Saved in scan
    /// artifacts and resume settings; never put credentials or secrets here.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub test_data: std::collections::BTreeMap<String, String>,
    /// Extra identifying HTTP headers sent only to in-scope / allowed hosts
    /// (e.g. `X-QA-Runner = "staging-ci"`). Never sent to third-party origins.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extra_headers: std::collections::BTreeMap<String, String>,
    /// Custom browser `User-Agent` applied via CDP and HTTP requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Fail-closed host allowlist (`example.com`, `*.example.com`). Navigations,
    /// redirects, API/XHR/Fetch, WebSockets, and mutating requests outside this
    /// list are blocked at the browser network layer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
    /// Milliseconds to wait between UI interactions (`scan.pacing.delay_between_interactions_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction_delay_ms: Option<u64>,
    /// Maximum in-scope non-static HTTP requests per second (polite rate cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_second: Option<f64>,
    /// Hard-abort the crawl with `stop_reason = "rate_limited"` once this many
    /// HTTP 429 responses occur within 60 seconds (`0` disables abort; defaults
    /// to `5` when `allow_remote = true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_on_rate_limits: Option<usize>,
    /// Hard-abort the crawl with `stop_reason = "antibot_challenge"` once this
    /// many WAF / anti-bot challenge pages are observed (`0` disables abort;
    /// defaults to `2` when `allow_remote = true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_on_antibot_challenges: Option<usize>,
}

impl Default for ScanSection {
    fn default() -> Self {
        Self {
            mode: ScanMode::Standard,
            max_minutes: default_max_minutes(),
            max_views: default_max_views(),
            max_hours: None,
            view_budget_seconds: None,
            role_concurrency: None,
            progress_seconds: None,
            write_guard: default_write_guard(),
            write_guard_allow: Vec::new(),
            extra_routes: Vec::new(),
            exclude_routes: Vec::new(),
            seed_from_source: true,
            headless: true,
            allow_remote: false,
            max_interaction_depth: None,
            max_interactions_per_view: None,
            max_interactions_per_depth: None,
            settle_ms: None,
            tabs: None,
            test_data: Default::default(),
            extra_headers: Default::default(),
            user_agent: None,
            allowed_hosts: Vec::new(),
            interaction_delay_ms: None,
            max_requests_per_second: None,
            abort_on_rate_limits: None,
            abort_on_antibot_challenges: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuthSection {
    /// Deprecated and unused: add a role with `method = "session"` instead
    /// (`map` warns when it is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Map the logged-out app as the implicit `anonymous` role (default
    /// true). Its map is the top-level `map/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_anonymous: Option<bool>,
}

impl AuthSection {
    pub fn include_anonymous(&self) -> bool {
        self.include_anonymous.unwrap_or(true)
    }
}

fn default_codebase() -> String {
    ".".to_string()
}
fn default_ready_timeout_secs() -> u64 {
    DEFAULT_READY_TIMEOUT_SECS
}
fn default_max_minutes() -> u64 {
    10
}
fn default_max_views() -> usize {
    80
}
fn default_write_guard() -> String {
    "block".to_string()
}
fn default_true() -> bool {
    true
}

/// A resolved project.
#[derive(Debug, Clone)]
pub struct ProjectCtx {
    /// The `.brokenapp` directory.
    pub state_dir: PathBuf,
    /// Codebase root (absolute).
    pub root: PathBuf,
    pub config_path: PathBuf,
    pub config: ProjectConfig,
}

impl ProjectCtx {
    pub fn name(&self) -> &str {
        &self.config.project.name
    }
    pub fn map_dir(&self) -> PathBuf {
        self.state_dir.join("map")
    }
    pub fn history_dir(&self) -> PathBuf {
        self.state_dir.join("history")
    }
    pub fn scans_dir(&self) -> PathBuf {
        self.state_dir.join("scans")
    }
    pub fn session_dir(&self) -> PathBuf {
        self.state_dir.join("session")
    }
    pub fn latest_inventory_path(&self) -> PathBuf {
        self.history_dir().join(LATEST_INVENTORY)
    }
    pub fn credentials_path(&self) -> PathBuf {
        self.state_dir.join(CREDENTIALS_FILE)
    }

    /// Map and history directories of one role. The anonymous role uses the
    /// top-level `map/` and `history/` (the map before roles existed).
    pub fn role_paths(&self, role: &str) -> RolePaths {
        if role == ANONYMOUS_ROLE {
            RolePaths {
                role: role.to_string(),
                map_dir: self.map_dir(),
                history_dir: self.history_dir(),
            }
        } else {
            RolePaths {
                role: role.to_string(),
                map_dir: self.map_dir().join("roles").join(role),
                history_dir: self.history_dir().join("roles").join(role),
            }
        }
    }

    /// Roles with a map file set: anonymous first (when it has a map or is
    /// included), then configured roles in config order.
    pub fn role_names(&self) -> Vec<String> {
        let mut out = vec![ANONYMOUS_ROLE.to_string()];
        out.extend(self.config.roles.iter().map(|r| r.name.clone()));
        out
    }

    pub fn load_latest_inventory(&self) -> Result<crate::inventory::Inventory> {
        self.role_paths(ANONYMOUS_ROLE).load_latest(self.name())
    }
}

/// Where one role's map and inventory history live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePaths {
    pub role: String,
    pub map_dir: PathBuf,
    pub history_dir: PathBuf,
}

impl RolePaths {
    pub fn latest_inventory_path(&self) -> PathBuf {
        self.history_dir.join(LATEST_INVENTORY)
    }

    pub fn portable_inventory_path(&self) -> PathBuf {
        self.map_dir.join(PORTABLE_INVENTORY)
    }

    /// Preferred inventory path for read commands: `history/latest.inventory.json`
    /// when present, otherwise the committed portable `map/.../ui-inventory.json`.
    pub fn readable_inventory_path(&self) -> Option<PathBuf> {
        let latest = self.latest_inventory_path();
        if latest.is_file() {
            return Some(latest);
        }
        let portable = self.portable_inventory_path();
        if portable.is_file() {
            return Some(portable);
        }
        None
    }

    pub fn has_saved_inventory(&self) -> bool {
        self.readable_inventory_path().is_some()
    }

    pub fn is_anonymous(&self) -> bool {
        self.role == ANONYMOUS_ROLE
    }

    pub fn load_latest(&self, project: &str) -> Result<crate::inventory::Inventory> {
        let Some(path) = self.readable_inventory_path() else {
            let expected = self.latest_inventory_path();
            if self.is_anonymous() {
                bail!(
                    "no UI map yet for project '{project}' (expected {} or {}). Run `brokenapp map` first.",
                    expected.display(),
                    self.portable_inventory_path().display()
                );
            }
            bail!(
                "no UI map yet for role '{}' of project '{project}' (expected {} or {}). Run `brokenapp map --role {}` first.",
                self.role,
                expected.display(),
                self.portable_inventory_path().display(),
                self.role
            );
        };
        crate::inventory::load(&path)
    }
}

/// Load `config.toml` from a state dir.
pub fn load_ctx(state_dir: &Path) -> Result<ProjectCtx> {
    let state_dir = state_dir
        .canonicalize()
        .with_context(|| format!("state dir {}", state_dir.display()))?;
    let config_path = state_dir.join(CONFIG_FILE);
    let raw = std::fs::read_to_string(&config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let config: ProjectConfig = toml::from_str(&raw).map_err(|err: toml::de::Error| {
        // Parser diagnostics quote source lines, which can contain a pasted
        // password even though valid configurations reject literal secrets.
        let line = err
            .span()
            .map(|span| raw[..span.start.min(raw.len())].lines().count().max(1));
        anyhow::anyhow!(
            "invalid project config {} (near line {}); check TOML syntax and field types",
            config_path.display(),
            line.unwrap_or(0)
        )
    })?;
    let base = state_dir.parent().unwrap_or(&state_dir).to_path_buf();
    let root = base.join(&config.project.codebase);
    let root = root.canonicalize().unwrap_or(root);
    Ok(ProjectCtx {
        state_dir,
        root,
        config_path,
        config,
    })
}

/// Walk up from `start` to find a directory containing `.brokenapp/config.toml`.
pub fn find_state_dir_from(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        let candidate = dir.join(STATE_DIR_NAME);
        if candidate.join(CONFIG_FILE).is_file() {
            return Some(candidate);
        }
        cur = dir.parent();
    }
    None
}

/// Find the registered project whose canonical `root` is the deepest ancestor
/// of (or equals) canonical `cwd`, and whose `state_dir/config.toml` exists.
pub fn find_registered_state_dir_from(cwd: &Path, registry: &Registry) -> Option<PathBuf> {
    let canon_cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let mut best: Option<(usize, PathBuf)> = None;
    for entry in &registry.projects {
        if entry.root.trim().is_empty() || entry.state_dir.trim().is_empty() {
            continue;
        }
        let state_dir = PathBuf::from(&entry.state_dir);
        if !state_dir.join(CONFIG_FILE).is_file() {
            continue;
        }
        let root_path = Path::new(&entry.root);
        let canon_root = root_path
            .canonicalize()
            .unwrap_or_else(|_| root_path.to_path_buf());
        if canon_cwd.starts_with(&canon_root) {
            let depth = canon_root.components().count();
            if best
                .as_ref()
                .is_none_or(|(best_depth, _)| depth > *best_depth)
            {
                best = Some((depth, state_dir));
            }
        }
    }
    best.map(|(_, dir)| dir)
}

/// Resolve the target project: `--state-dir` > `--project` (registry) > cwd walk-up > registry root match.
pub fn resolve(target: &ProjectTarget) -> Result<ProjectCtx> {
    resolve_with(
        target,
        || std::env::current_dir().context("current dir"),
        Registry::load,
    )
}

fn resolve_with(
    target: &ProjectTarget,
    get_cwd: impl FnOnce() -> Result<PathBuf>,
    load_registry: impl FnOnce() -> Result<Registry>,
) -> Result<ProjectCtx> {
    if let Some(dir) = &target.state_dir {
        return load_ctx(dir);
    }
    if let Some(name) = &target.project {
        let reg = load_registry()?;
        let Some(entry) = reg.find(name) else {
            bail!("project '{name}' is not registered (see `brokenapp projects`)");
        };
        return load_ctx(Path::new(&entry.state_dir));
    }
    let cwd = get_cwd()?;
    if let Some(dir) = find_state_dir_from(&cwd) {
        return load_ctx(&dir);
    }
    if let Ok(reg) = load_registry()
        && let Some(dir) = find_registered_state_dir_from(&cwd, &reg)
    {
        return load_ctx(&dir);
    }
    bail!(
        "no .brokenapp/config.toml found from {} upward. Run `brokenapp init --url <local url>` in the project, or pass --project/--state-dir.",
        cwd.display()
    )
}

/// `$BROKENAPP_HOME` or `~/.brokenapp`.
pub fn brokenapp_home() -> PathBuf {
    if let Ok(home) = std::env::var("BROKENAPP_HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home);
        }
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".brokenapp")
}

/// Global project registry (`$BROKENAPP_HOME/registry.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Registry {
    #[serde(default)]
    pub projects: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RegistryEntry {
    pub name: String,
    /// Codebase root (absolute).
    pub root: String,
    /// `.brokenapp` dir (absolute).
    pub state_dir: String,
    pub url: String,
    #[serde(default)]
    pub protected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_at: Option<String>,
    /// Short summary of the last scan (counts), free-form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_summary: Option<String>,
}

impl Registry {
    pub fn path() -> PathBuf {
        brokenapp_home().join("registry.json")
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let raw = serde_json::to_string_pretty(self).context("serialize registry")?;
        std::fs::write(&path, raw).with_context(|| format!("write {}", path.display()))
    }

    pub fn find(&self, name: &str) -> Option<&RegistryEntry> {
        self.projects
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// Insert or replace by state dir (and name).
    pub fn upsert(&mut self, entry: RegistryEntry) {
        self.projects.retain(|p| {
            p.state_dir != entry.state_dir && !p.name.eq_ignore_ascii_case(&entry.name)
        });
        self.projects.push(entry);
        self.projects
            .sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parse_errors_do_not_quote_literal_credentials() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CONFIG_FILE), "[project]\nname='x'\nurl='http://127.0.0.1:1'\n[[roles]]\nname='admin'\nmethod='form'\npassword=\"private-pasted-secret\n").unwrap();
        let err = load_ctx(dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid project config"));
        assert!(!msg.contains("private-pasted-secret"));
    }

    #[test]
    fn config_round_trip_with_defaults() {
        let raw = r#"
[project]
name = "demo"
url = "http://127.0.0.1:3000"
"#;
        let cfg: ProjectConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.project.codebase, ".");
        assert_eq!(cfg.scan.write_guard, "block");
        assert!(cfg.scan.seed_from_source);
        assert_eq!(cfg.project.ready_timeout_secs, 120);
        assert_eq!(cfg.scan.max_interaction_depth, None);
    }

    #[test]
    fn crawl_knobs_parse_and_stay_out_when_unset() {
        let raw = r#"
[project]
name = "demo"
url = "http://127.0.0.1:3000"

[scan]
max_interaction_depth = 4
max_interactions_per_view = 60
max_interactions_per_depth = [80, 40, 20]
settle_ms = 3500
tabs = 2
"#;
        let cfg: ProjectConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.scan.tabs, Some(2));
        assert_eq!(cfg.scan.max_interaction_depth, Some(4));
        assert_eq!(cfg.scan.max_interactions_per_view, Some(60));
        assert_eq!(cfg.scan.max_interactions_per_depth, Some(vec![80, 40, 20]));
        assert_eq!(cfg.scan.settle_ms, Some(3500));
        let defaults = toml::to_string(&ProjectConfig::default()).unwrap();
        assert!(!defaults.contains("max_interaction_depth"));
        assert!(!defaults.contains("max_interactions_per_depth"));
        assert!(!defaults.contains("settle_ms"));
        assert!(!defaults.contains("tabs"));
    }

    #[test]
    fn finds_state_dir_walking_up() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(STATE_DIR_NAME);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(CONFIG_FILE),
            "[project]\nname='x'\nurl='http://127.0.0.1:1'\n",
        )
        .unwrap();
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let found = find_state_dir_from(&nested).unwrap();
        assert_eq!(found, state);
        let ctx = load_ctx(&found).unwrap();
        assert_eq!(ctx.name(), "x");
        assert_eq!(ctx.root, dir.path().canonicalize().unwrap());
    }

    #[test]
    fn resolve_finds_registered_external_state_dir_from_root_and_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("monorepo");
        let app_root = repo.join("apps/portal");
        let nested = app_root.join("src/components");
        std::fs::create_dir_all(&nested).unwrap();

        let repo_state = dir.path().join("states/monorepo");
        let app_state = dir.path().join("states/portal");
        std::fs::create_dir_all(&repo_state).unwrap();
        std::fs::create_dir_all(&app_state).unwrap();
        std::fs::write(
            repo_state.join(CONFIG_FILE),
            format!(
                "[project]\nname='monorepo'\nurl='http://127.0.0.1:3000'\ncodebase='{}'\n",
                repo.display()
            ),
        )
        .unwrap();
        std::fs::write(
            app_state.join(CONFIG_FILE),
            format!(
                "[project]\nname='portal'\nurl='http://127.0.0.1:3001'\ncodebase='{}'\n",
                app_root.display()
            ),
        )
        .unwrap();

        let reg = Registry {
            projects: vec![
                RegistryEntry {
                    name: "monorepo".into(),
                    root: repo.canonicalize().unwrap().display().to_string(),
                    state_dir: repo_state.canonicalize().unwrap().display().to_string(),
                    url: "http://127.0.0.1:3000".into(),
                    ..Default::default()
                },
                RegistryEntry {
                    name: "portal".into(),
                    root: app_root.canonicalize().unwrap().display().to_string(),
                    state_dir: app_state.canonicalize().unwrap().display().to_string(),
                    url: "http://127.0.0.1:3001".into(),
                    ..Default::default()
                },
                // Stale entry with missing config.toml is ignored.
                RegistryEntry {
                    name: "stale".into(),
                    root: nested.canonicalize().unwrap().display().to_string(),
                    state_dir: dir.path().join("states/missing").display().to_string(),
                    url: "http://127.0.0.1:3002".into(),
                    ..Default::default()
                },
            ],
        };

        // At app root: deepest matching ancestor wins (`portal`, not `monorepo`).
        let ctx_root = resolve_with(
            &ProjectTarget::default(),
            || Ok(app_root.clone()),
            || Ok(reg.clone()),
        )
        .unwrap();
        assert_eq!(ctx_root.name(), "portal");
        assert_eq!(ctx_root.state_dir, app_state.canonicalize().unwrap());

        // Inside nested subdirectory: still resolves `portal` (skipping stale deeper entry).
        let ctx_nested = resolve_with(
            &ProjectTarget::default(),
            || Ok(nested.clone()),
            || Ok(reg.clone()),
        )
        .unwrap();
        assert_eq!(ctx_nested.name(), "portal");

        // Outside registered roots: errors cleanly.
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(
            resolve_with(
                &ProjectTarget::default(),
                || Ok(elsewhere.path().to_path_buf()),
                || Ok(reg),
            )
            .is_err()
        );
    }

    #[test]
    fn role_paths_falls_back_to_portable_map_inventory_without_history() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(STATE_DIR_NAME);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(CONFIG_FILE),
            "[project]\nname='demo'\nurl='http://127.0.0.1:3000'\n[[roles]]\nname='admin'\nmethod='form'\n",
        )
        .unwrap();
        let ctx = load_ctx(&state).unwrap();

        let anon_inv = crate::inventory::Inventory {
            schema: crate::inventory::INVENTORY_SCHEMA.into(),
            project: "demo".into(),
            target_url: "http://127.0.0.1:3000".into(),
            ..Default::default()
        };
        let admin_inv = crate::inventory::Inventory {
            role: Some("admin".into()),
            ..anon_inv.clone()
        };

        // Only write portable `map/.../ui-inventory.json` (no `history/` dir).
        let anon_paths = ctx.role_paths(ANONYMOUS_ROLE);
        let admin_paths = ctx.role_paths("admin");
        crate::inventory::save(&anon_inv, &anon_paths.portable_inventory_path()).unwrap();
        crate::inventory::save(&admin_inv, &admin_paths.portable_inventory_path()).unwrap();

        assert!(!anon_paths.latest_inventory_path().exists());
        assert!(anon_paths.has_saved_inventory());
        assert!(admin_paths.has_saved_inventory());
        assert_eq!(anon_paths.load_latest(ctx.name()).unwrap().project, "demo");
        assert_eq!(
            admin_paths.load_latest(ctx.name()).unwrap().role.as_deref(),
            Some("admin")
        );
    }
}
