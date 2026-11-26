use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokenAppConfig {
    pub target: TargetConfig,

    /// Optional in config files for unauthenticated scans.
    #[serde(default, deserialize_with = "deserialize_optional_auth_config")]
    pub auth: Option<AuthConfig>,

    /// Optional auth success contract used to validate login/session health.
    ///
    /// When `auth_paths` is configured and a path-specific contract is set, it
    /// overrides this global contract for that selected path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_contract: Option<AuthSuccessContract>,

    /// Optional alternate authentication paths (role/login variants).
    ///
    /// Use with `scan.auth_path` (or `--auth-path`) to select one path for a
    /// scan. If `auth` is not set and `auth_paths` is non-empty, the first
    /// entry is used.
    #[serde(
        default,
        alias = "auth_profiles",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub auth_paths: Vec<NamedAuthPathConfig>,

    #[serde(default)]
    pub scan: ScanConfig,

    #[serde(default)]
    pub output: OutputConfig,

    /// Custom security check rules evaluated after the scan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_rules: Vec<crate::bugs::custom_rules::CustomRule>,
}

impl BrokenAppConfig {
    pub fn from_toml_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config file {}", path.display()))?;
        let mut cfg: Self =
            toml::from_str(&raw).with_context(|| format!("parse TOML {}", path.display()))?;
        let base_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let base_dir = std::path::absolute(&base_dir).unwrap_or(base_dir);
        cfg.resolve_relative_auth_paths(&base_dir);
        cfg.resolve_auth_path()?;
        Ok(cfg)
    }

    /// Make relative file paths in `[auth]` and `[[auth_paths]]` (saved
    /// sessions) absolute against `base_dir` (the config file's directory).
    pub fn resolve_relative_auth_paths(&mut self, base_dir: &Path) {
        if let Some(auth) = self.auth.as_mut() {
            auth.resolve_relative_paths(base_dir);
        }
        for named in &mut self.auth_paths {
            named.auth.resolve_relative_paths(base_dir);
        }
    }

    pub fn resolve_auth_path(&mut self) -> Result<()> {
        let fallback_contract = self.auth_contract.clone();
        if let Some(name) = self.scan.auth_path.as_deref() {
            let selected = self
                .auth_paths
                .iter()
                .find(|p| p.name == name)
                .with_context(|| format!("unknown auth path {name:?}"))?;
            self.auth = Some(selected.auth.clone());
            self.auth_contract = selected.contract.clone().or(fallback_contract);
            return Ok(());
        }

        if self.auth.is_none() {
            if let Some(first) = self.auth_paths.first() {
                self.auth = Some(first.auth.clone());
                self.auth_contract = first.contract.clone().or(fallback_contract);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OptionalAuthConfig {
    None {
        #[serde(rename = "type")]
        _auth_type: NoAuthType,
    },
    Config(AuthConfig),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NoAuthType {
    None,
}

fn deserialize_optional_auth_config<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<AuthConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        match Option::<OptionalAuthConfig>::deserialize(deserializer)? {
            None | Some(OptionalAuthConfig::None { .. }) => Ok(None),
            Some(OptionalAuthConfig::Config(auth)) => Ok(Some(auth)),
        }?,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub url: Url,

    #[serde(default)]
    pub name: Option<String>,

    /// Chromium/Chrome executable path.
    ///
    /// Default (macOS): `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`.
    #[serde(default)]
    pub chrome_executable: Option<PathBuf>,

    #[serde(default = "default_true")]
    pub headless: bool,

    #[serde(default)]
    pub ignore_https_errors: bool,

    /// WebSocket URL to connect to a remote Chrome/Chromium instance
    /// (e.g. `ws://localhost:9222/devtools/browser/...` or a Browserless.io URL).
    /// When set, skips local Chrome detection and launches no local process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_chrome_url: Option<String>,

    /// Browser locale / Accept-Language value (e.g. "en-US", "ar", "fr-FR").
    /// When set, sends `Accept-Language` header on all requests and passes
    /// `--lang=<locale>` to Chrome.
    /// When unset, Chrome uses the host system's locale (LANG/LC_ALL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    Form {
        login_url: String,
        username_selector: String,
        password_selector: String,
        submit_selector: String,
        username: String,
        password: String,
    },
    /// Launch a headful browser and let the user complete authentication
    /// manually (SSO/MFA/CAPTCHA), then continue scanning using the captured
    /// browser session.
    Manual {
        /// Optional URL (relative to `target.url`) to open before prompting.
        #[serde(default)]
        login_url: Option<String>,
    },
    Cookie {
        /// Raw cookie header value, e.g. `session=abc; token=xyz`.
        cookie: String,
    },
    // Historically this was serialized as "bearer_token" due to serde snake_case renaming.
    // Accept both to match docs/UX ("bearer") and to remain backward-compatible with
    // existing config files.
    #[serde(rename = "bearer")]
    #[serde(alias = "bearer_token")]
    BearerToken { token: String },
    // Similar to bearer_token, serde snake_case would serialize this as "o_auth".
    // Keep the canonical config value as "oauth" and accept the legacy spelling too.
    #[serde(rename = "oauth")]
    #[serde(alias = "o_auth")]
    OAuth {
        token: String,
        #[serde(default)]
        refresh_url: Option<String>,
        #[serde(default)]
        refresh_token: Option<String>,
    },
    Supabase {
        /// Project URL, e.g. "https://xyz.supabase.co"
        #[serde(alias = "supabase_url")]
        project_url: String,
        #[serde(alias = "supabase_anon_key")]
        anon_key: String,
        #[serde(alias = "username")]
        email: String,
        password: String,
    },
    Firebase {
        #[serde(alias = "firebase_api_key")]
        api_key: String,
        #[serde(alias = "username")]
        email: String,
        password: String,
    },
    #[serde(rename = "google_oauth")]
    GoogleOAuth {
        /// Target app's login/signup page (relative to target URL). Defaults to "/".
        #[serde(default)]
        login_url: Option<String>,
        /// CSS selector for the "Sign in with Google" button. Auto-detected if omitted.
        #[serde(default)]
        google_button_selector: Option<String>,
        /// Google account email (injected by worker from env).
        google_email: String,
        /// Google app-specific password (injected by worker from env).
        google_password: String,
    },
    /// A saved browser session (cookies plus local/session storage for the
    /// app's origins) captured once by a human (`brokenapp login`): SSO, MFA,
    /// magic links. Loaded into every crawl tab before its first navigation.
    /// Not renewable: when the session expires mid-scan the scan stops with
    /// status `session_expired` (re-capture it, then `brokenapp resume`).
    ///
    /// The file is Playwright `storageState` JSON (plus optional
    /// `sessionStorage` per origin and capture metadata); see
    /// [`crate::session::storage_state`]. A relative `path` is resolved
    /// against the directory of the config file that names it.
    StorageState { path: String },
}

impl AuthConfig {
    /// Config `type` value (`form`, `storage_state`, ...).
    pub fn type_name(&self) -> &'static str {
        match self {
            AuthConfig::Form { .. } => "form",
            AuthConfig::Manual { .. } => "manual",
            AuthConfig::Cookie { .. } => "cookie",
            AuthConfig::BearerToken { .. } => "bearer",
            AuthConfig::OAuth { .. } => "oauth",
            AuthConfig::Supabase { .. } => "supabase",
            AuthConfig::Firebase { .. } => "firebase",
            AuthConfig::GoogleOAuth { .. } => "google_oauth",
            AuthConfig::StorageState { .. } => "storage_state",
        }
    }

    /// Whether the scanner can log in again by itself when the session
    /// expires mid-scan. Saved sessions and manual logins need a human, so an
    /// expired one stops the scan (`session_expired`) instead of looping on
    /// re-authentication.
    pub fn is_renewable(&self) -> bool {
        !matches!(
            self,
            AuthConfig::StorageState { .. } | AuthConfig::Manual { .. }
        )
    }

    /// Login page path hint used to recognize "this tab landed on the login
    /// page" (`/login` for a form login). `None` when the method has no login
    /// page of its own.
    pub fn login_path_hint(&self) -> Option<&str> {
        match self {
            AuthConfig::Form { login_url, .. } => Some(login_url.as_str()),
            AuthConfig::Manual { login_url } | AuthConfig::GoogleOAuth { login_url, .. } => {
                login_url.as_deref()
            }
            _ => None,
        }
    }

    /// Make a relative `storage_state` path absolute against `base_dir`.
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let AuthConfig::StorageState { path } = self {
            let trimmed = path.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with("env:")
                && !trimmed.starts_with("${")
                && Path::new(trimmed).is_relative()
            {
                *path = base_dir.join(trimmed).display().to_string();
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedAuthPathConfig {
    pub name: String,
    #[serde(flatten)]
    pub auth: AuthConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<AuthSuccessContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthSuccessContract {
    /// Any of these substrings must appear in the post-login URL.
    /// Leave empty to skip URL matching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub success_url_patterns: Vec<String>,
    /// Cookie names that must exist in the authenticated browser session.
    /// Leave empty to skip cookie checks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_cookie_names: Vec<String>,
    /// Optional endpoint probe expected to return an authenticated response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_probe: Option<AuthProtectedProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProtectedProbe {
    /// Relative or absolute probe path/URL.
    pub path: String,
    /// Request method used for the probe.
    #[serde(default)]
    pub method: AuthProbeMethod,
    /// Accepted HTTP response status codes.
    #[serde(default = "default_auth_probe_expected_statuses")]
    pub expected_statuses: Vec<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthProbeMethod {
    Get,
    Head,
}

impl Default for AuthProbeMethod {
    fn default() -> Self {
        Self::Get
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    /// Max mapped views before stopping. Set to `0` for no cap.
    #[serde(default = "default_max_views")]
    pub max_views: usize,

    /// Max scan time in minutes. Set to `0` for no cap (multi-hour full
    /// runs: the scan ends when the queue is exhausted, it converged, or it
    /// is interrupted).
    #[serde(default = "default_max_duration_minutes")]
    pub max_duration_minutes: u64,

    /// Per-view time budget in seconds: how long one view (navigate, discover,
    /// exercise its controls, audit) may take before the view watchdog stops
    /// it. `0` (default) = automatic: derived from the settle and interaction
    /// timeouts (45-180 s) and raised to a fair share of the remaining scan
    /// time when few URLs are queued. `> 0` = exactly this many seconds (at
    /// least 10), e.g. `300` for full runs over rich views.
    #[serde(default)]
    pub view_budget_seconds: u64,

    /// Stop when no new DOM fingerprint has been discovered for this many
    /// minutes. Set to `0` to disable this guard. Never fires while the
    /// queue still holds a route that has not been visited yet.
    #[serde(default = "default_max_stagnation_minutes")]
    pub max_stagnation_minutes: u64,

    /// Stop when coverage converges (high interaction coverage + almost no
    /// new views in a recent window). Never fires while the queue still
    /// holds a route that has not been visited yet. Set to `false` to crawl
    /// until the queue is exhausted (or another budget ends the scan).
    #[serde(default = "default_true")]
    pub stop_on_convergence: bool,
    /// Minimum interaction coverage percentage required for convergence stop.
    #[serde(default = "default_convergence_min_coverage_percent")]
    pub convergence_min_coverage_percent: f64,
    /// Number of recently completed view visits considered for convergence.
    #[serde(default = "default_convergence_window_views")]
    pub convergence_window_views: usize,
    /// Max allowed newly discovered fingerprints inside the convergence window.
    #[serde(default = "default_convergence_max_new_views")]
    pub convergence_max_new_views: usize,

    #[serde(default)]
    pub screenshot_each_view: bool,

    #[serde(default = "default_interaction_timeout_ms")]
    pub interaction_timeout_ms: u64,

    #[serde(default = "default_settle_timeout_ms")]
    pub settle_timeout_ms: u64,

    /// Page workers (tabs of the one browser) that crawl views in parallel,
    /// pulling from the shared queue. 1 (default) crawls sequentially; values
    /// are clamped to 1-8. Each tab has its own write guard and attribution
    /// state, so requests, console errors and dialogs are only credited to
    /// actions of the tab they happened in. The app's dev server is shared,
    /// so more tabs help only while it keeps up.
    /// `BROKENAPP_MAX_CONCURRENT_TABS` overrides it.
    #[serde(default = "default_max_concurrent_tabs")]
    pub max_concurrent_tabs: usize,

    /// Block unnecessary resource classes like images, fonts, and media
    /// during scans to reduce page-load cost.
    #[serde(default = "default_true")]
    pub block_unnecessary_resources: bool,

    /// Resource types to block via CDP Fetch interception.
    #[serde(default = "default_blocked_resource_types")]
    pub blocked_resource_types: Vec<String>,

    /// Domain suffixes to block entirely during scans.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_domains: Vec<String>,

    /// Fail-closed host allowlist (`example.com`, `*.example.com`). When
    /// non-empty, navigations, redirects, API/XHR/Fetch, WebSockets, and
    /// mutating requests to hosts outside this list fail closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,

    /// Extra identifying HTTP headers stamped only onto in-scope / allowed
    /// host requests (never sent to third-party origins).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extra_headers: std::collections::BTreeMap<String, String>,

    /// Custom browser `User-Agent` applied via CDP emulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Hard-abort the scan with `stop_reason = "rate_limited"` once this many
    /// HTTP 429 responses are observed within 60 seconds (`0` disables abort).
    #[serde(default)]
    pub abort_on_rate_limits: usize,

    /// Hard-abort the scan with `stop_reason = "antibot_challenge"` once this
    /// many WAF / anti-bot challenge pages are observed (`0` disables abort).
    #[serde(default)]
    pub abort_on_antibot_challenges: usize,

    /// Ignore HTTP 502 findings in bug output.
    #[serde(default)]
    pub ignore_502: bool,

    /// When many different entity IDs return HTTP 404 under the same route
    /// family (e.g. `/api/deals/:id/...`), collapse them into a single
    /// low-severity "stale entity references" finding to reduce noise.
    ///
    /// Set to `0` to disable this aggregation.
    #[serde(default = "default_stale_entity_404_group_threshold")]
    pub stale_entity_404_group_threshold: usize,

    /// Block browser-initiated requests to private/non-global IP ranges when
    /// scanning a public target (SSRF guardrail).
    ///
    /// Even when the primary target URL is public, the app can attempt to fetch
    /// internal resources (e.g. cloud metadata at 169.254.169.254). In hosted
    /// scanning environments this must be blocked.
    ///
    /// Default behavior when unset:
    /// - public targets: enabled
    /// - localhost/private targets: disabled (so local dev scans still work)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_private_egress: Option<bool>,

    /// Minimum number of HTTP 502 occurrences required to collapse them into
    /// one infrastructure instability finding.
    #[serde(default = "default_infra_502_group_threshold")]
    pub infra_502_group_threshold: usize,

    /// Minimum number of repeated console errors with the same message
    /// signature required to collapse them into a single finding.
    ///
    /// Set to `0` to disable this aggregation.
    #[serde(default = "default_console_error_group_threshold")]
    pub console_error_group_threshold: usize,

    /// When many dead-button findings accumulate on the same route family,
    /// collapse them into a single info-severity finding to reduce noise.
    /// Dead buttons often represent controls that require specific
    /// preconditions (selected row, filled form, specific state) to be active.
    ///
    /// Set to `0` to disable this aggregation.
    #[serde(default = "default_dead_button_group_threshold")]
    pub dead_button_group_threshold: usize,

    /// UI consistency drift analysis config.
    #[serde(default)]
    pub ui_consistency: UiConsistencyConfig,

    /// Layout-shell spacing consistency analysis config.
    #[serde(default)]
    pub layout_consistency: LayoutConsistencyConfig,

    /// Optional scan scope name (loaded from a scopes file) to restrict which
    /// routes are explored. This enables fast, targeted rescans.
    #[serde(default)]
    pub scope: Option<String>,

    /// Additional seed URLs/paths to enqueue at scan start (same origin).
    /// Useful when a section of the app is only reachable via interactions
    /// the crawler cannot currently infer (e.g. custom sidebar nav).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seed_urls: Vec<String>,

    /// Route paths (e.g. public routes already mapped under `anonymous`) to
    /// visit after normal static/app seeds so authenticated scans spend their
    /// view budget on role-specific routes first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deprioritize_routes: Vec<String>,

    /// Optional file containing browser route seeds. Supports newline-delimited
    /// routes/URLs and JSON artifacts with route/page/view arrays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_routes_file: Option<PathBuf>,

    /// Nuclei-style runtime templates to evaluate against observed traffic
    /// after exploration. Supports files or directories of .yaml/.yml files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_templates: Vec<PathBuf>,

    /// Experimental substrate switch for routing browser work through a
    /// Playwright MCP adapter when that adapter is installed.
    #[serde(default)]
    pub via_playwright_mcp: bool,

    /// Write guard: what happens to state-changing requests (non-GET/HEAD/
    /// OPTIONS, GraphQL mutations, beacons, form posts) fired while the
    /// crawler interacts with the app. Default `block`: record the attempt
    /// (method, URL, triggering action) and stop it before it reaches any
    /// backend, so scans of real projects never mutate data.
    #[serde(default)]
    pub write_guard: WriteGuardConfig,

    /// Route templates known from source (e.g. `/towns/:slug`). Instances of
    /// a template share an identity: the explorer samples a few instances and
    /// does not re-exercise the same controls on every instance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_templates: Vec<String>,

    /// Browser viewport width in CSS pixels used for scans.
    #[serde(default = "default_viewport_width")]
    pub viewport_width: u32,

    /// Browser viewport height in CSS pixels used for scans.
    #[serde(default = "default_viewport_height")]
    pub viewport_height: u32,

    /// API path prefixes that should never be flagged as `api_bypass`.
    /// Example: `["/admin", "/internal"]` to whitelist known alternate prefixes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_prefix_whitelist: Vec<String>,

    /// POST endpoints matching these patterns will not be flagged as
    /// `post_for_read`. Supports prefix globs (e.g. `/api/analytics/*`)
    /// and exact paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_for_read_ignore: Vec<String>,

    /// Optional auth path name to select from `auth_paths`.
    #[serde(
        default,
        alias = "auth_profile",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_path: Option<String>,

    /// Optional path to a TOML scopes file. If not set and `scope` is set,
    /// BrokenApp will look for `./.brokenapp/scopes.toml` or
    /// `./scopes.toml`.
    #[serde(default)]
    pub scopes_file: Option<PathBuf>,

    /// Optional path to the application codebase. When set, `link-code`
    /// runs automatically after normalization so endpoints include
    /// `code_locations` without a separate manual command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codebase_path: Option<PathBuf>,

    /// How often (in views) to run a proactive auth canary check.
    /// 0 = disabled. When set, after every N views the scanner verifies the
    /// session is still valid using `auth_contract.protected_probe`.
    #[serde(default)]
    pub canary_interval_views: u64,

    /// Run a lightweight canary check before exploring new route templates.
    #[serde(default)]
    pub canary_before_new_route: bool,

    #[serde(default)]
    pub exploration: ExplorationConfig,

    #[serde(default)]
    pub test_data: TestDataConfig,

    #[serde(default)]
    pub limits: LimitsConfig,

    #[serde(default)]
    pub pacing: PacingConfig,

    #[serde(default)]
    pub performance: PerformanceConfig,

    #[serde(default)]
    pub accessibility: AccessibilityConfig,

    #[serde(default)]
    pub fuzzing: FuzzingConfig,

    /// Route sensitivity classification for context-aware severity adjustment.
    #[serde(default)]
    pub route_sensitivity: RouteSensitivityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConsistencyConfig {
    /// Generate UI consistency report from captured component visuals.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Drift score upper bound treated as "slight_drift". Scores below this
    /// are "aligned".
    #[serde(default = "default_ui_slight_drift_threshold")]
    pub slight_drift_threshold: f64,

    /// Drift score upper bound treated as "redesign". Scores above this are
    /// considered major visual redesigns.
    #[serde(default = "default_ui_redesign_threshold")]
    pub redesign_threshold: f64,

    /// Ignore rules for intentional visual variants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<UiConsistencyIgnoreRule>,

    /// Notes for intentional visual variants that should still be visible in
    /// the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<UiConsistencyNoteRule>,
}

impl Default for UiConsistencyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            slight_drift_threshold: default_ui_slight_drift_threshold(),
            redesign_threshold: default_ui_redesign_threshold(),
            ignore: Vec::new(),
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutConsistencyConfig {
    /// Generate layout consistency report from captured component positions.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum pixel delta from the scan baseline before a route is flagged.
    #[serde(default = "default_layout_consistency_tolerance_px")]
    pub tolerance_px: f64,

    /// Minimum route samples required before BrokenApp builds a baseline.
    #[serde(default = "default_layout_consistency_min_routes")]
    pub min_routes_for_baseline: usize,
}

impl Default for LayoutConsistencyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tolerance_px: default_layout_consistency_tolerance_px(),
            min_routes_for_baseline: default_layout_consistency_min_routes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConsistencyIgnoreRule {
    /// Component kind (e.g. "data_table", "modal"). Use "*" for all kinds.
    pub component_kind: String,
    /// Route globs where this rule applies (e.g. "/reports/**").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_patterns: Vec<String>,
    /// Optional selector globs to further scope the rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    /// Optional structure fingerprint matchers to scope the rule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprints: Vec<String>,
    /// Human reason shown in reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConsistencyNoteRule {
    /// Component kind (e.g. "data_table", "modal"). Use "*" for all kinds.
    pub component_kind: String,
    /// Route globs where this note applies (e.g. "/reports/**").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_patterns: Vec<String>,
    /// Optional selector globs to further scope the note.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    /// Optional structure fingerprint matchers to scope the note.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprints: Vec<String>,
    /// User-visible note.
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationConfig {
    #[serde(default)]
    pub strategy: ExplorationStrategy,

    #[serde(default)]
    pub revisit_views: bool,

    #[serde(default)]
    pub interact_with_delete_buttons: bool,

    #[serde(default = "default_true")]
    pub fill_forms_with_test_data: bool,

    /// Submit forms during scanning. Default is `false` for safety.
    #[serde(default)]
    pub submit_forms: bool,

    /// Maximum number of nav dropdown buttons to expand per view during the
    /// dropdown expansion pass. Each expansion clicks the button, re-scans
    /// for new links, and queues them. Default: 5.
    #[serde(default = "default_max_dropdown_expansions_per_view")]
    pub max_dropdown_expansions_per_view: usize,

    /// Enable novelty-based priority scoring when strategy is `priority`.
    /// URLs are scored by route template novelty, depth, and saturation.
    #[serde(default)]
    pub novelty_scoring: bool,

    /// Maximum depth for exploring DOM mutations (modals, tabs, accordions).
    /// 0 = disabled (current behavior). Default: 2.
    #[serde(default = "default_max_interaction_depth")]
    pub max_interaction_depth: usize,

    /// Interaction budget per depth level. Index 0 = depth 0, etc.
    /// If the vector has fewer entries than depth, the last value repeats.
    /// Default: [25, 15, 10].
    #[serde(default = "default_max_interactions_per_depth")]
    pub max_interactions_per_depth: Vec<usize>,

    /// Whether to fill and submit forms discovered inside modals/panels.
    /// Default: true.
    #[serde(default = "default_true")]
    pub deep_explore_forms: bool,

    /// Milliseconds to wait after attempting to dismiss a modal.
    /// Default: 2000.
    #[serde(default = "default_modal_dismiss_timeout_ms")]
    pub modal_dismiss_timeout_ms: u64,
}

fn default_max_dropdown_expansions_per_view() -> usize {
    5
}

fn default_max_interaction_depth() -> usize {
    2
}

fn default_max_interactions_per_depth() -> Vec<usize> {
    vec![25, 15, 10]
}

fn default_modal_dismiss_timeout_ms() -> u64 {
    2000
}

impl Default for ExplorationConfig {
    fn default() -> Self {
        Self {
            strategy: ExplorationStrategy::default(),
            revisit_views: false,
            interact_with_delete_buttons: false,
            fill_forms_with_test_data: true,
            submit_forms: false,
            max_dropdown_expansions_per_view: default_max_dropdown_expansions_per_view(),
            novelty_scoring: false,
            max_interaction_depth: default_max_interaction_depth(),
            max_interactions_per_depth: default_max_interactions_per_depth(),
            deep_explore_forms: true,
            modal_dismiss_timeout_ms: default_modal_dismiss_timeout_ms(),
        }
    }
}

impl ExplorationConfig {
    /// Returns the interaction budget for a given depth level.
    pub fn interaction_budget_for_depth(&self, depth: usize) -> usize {
        if self.max_interactions_per_depth.is_empty() {
            return 25;
        }
        let idx = depth.min(self.max_interactions_per_depth.len() - 1);
        self.max_interactions_per_depth[idx]
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplorationStrategy {
    BreadthFirst,
    DepthFirst,
    Priority,
}

impl Default for ExplorationStrategy {
    fn default() -> Self {
        Self::BreadthFirst
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TestDataConfig {
    /// Arbitrary key/value test data matched by field name or label.
    #[serde(default, flatten)]
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Max number of element interactions per view (excluding navigation link discovery).
    #[serde(default = "default_max_interactions_per_view")]
    pub max_interactions_per_view: usize,

    /// Max bytes to store per response body sample.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Max JSON samples stored per endpoint for schema inference.
    #[serde(default = "default_max_schema_samples")]
    pub max_schema_samples: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_interactions_per_view: default_max_interactions_per_view(),
            max_body_bytes: default_max_body_bytes(),
            max_schema_samples: default_max_schema_samples(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacingConfig {
    /// Sleep between interactions (ms) to avoid hammering the target.
    #[serde(default = "default_delay_between_interactions_ms")]
    pub delay_between_interactions_ms: u64,

    /// Optional maximum in-scope non-static HTTP requests per second enforced
    /// at the CDP Fetch layer (`None` = uncapped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_second: Option<f64>,
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self {
            delay_between_interactions_ms: default_delay_between_interactions_ms(),
            max_requests_per_second: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_output_dir")]
    pub directory: PathBuf,

    #[serde(default = "default_true")]
    pub include_screenshots: bool,

    #[serde(default)]
    pub include_network_log: bool,

    /// Retain redacted API response body snippets in `network.jsonl`.
    /// Defaults to `false` so raw API payloads are omitted from logs unless
    /// explicitly enabled.
    #[serde(default)]
    pub include_response_bodies: bool,

    #[serde(default)]
    pub include_dom_snapshots: bool,

    #[serde(default = "default_bug_report_formats")]
    pub bug_report_format: Vec<BugReportFormat>,

    #[serde(default = "default_checkpoint_interval_seconds")]
    pub checkpoint_interval_seconds: u64,

    /// Path to write periodic progress updates (JSON) during a scan.
    /// Set via `--progress-file` CLI flag; not part of the TOML config.
    #[serde(skip)]
    pub progress_file: Option<PathBuf>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            directory: default_output_dir(),
            include_screenshots: true,
            include_network_log: true,
            include_response_bodies: false,
            include_dom_snapshots: false,
            bug_report_format: default_bug_report_formats(),
            checkpoint_interval_seconds: default_checkpoint_interval_seconds(),
            progress_file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BugReportFormat {
    Json,
    Markdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable Core Web Vitals collection and N+1 detection during scans.
    #[serde(default)]
    pub enabled: bool,

    /// LCP threshold in ms (default: 2500).
    #[serde(default = "default_lcp_threshold")]
    pub lcp_threshold_ms: f64,

    /// FCP threshold in ms (default: 1800).
    #[serde(default = "default_fcp_threshold")]
    pub fcp_threshold_ms: f64,

    /// CLS threshold (default: 0.1).
    #[serde(default = "default_cls_threshold")]
    pub cls_threshold: f64,

    /// TTFB threshold in ms (default: 800).
    #[serde(default = "default_ttfb_threshold")]
    pub ttfb_threshold_ms: f64,

    /// Minimum duplicate API calls to flag as N+1 pattern (default: 3).
    #[serde(default = "default_n_plus_one_threshold")]
    pub n_plus_one_threshold: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lcp_threshold_ms: default_lcp_threshold(),
            fcp_threshold_ms: default_fcp_threshold(),
            cls_threshold: default_cls_threshold(),
            ttfb_threshold_ms: default_ttfb_threshold(),
            n_plus_one_threshold: default_n_plus_one_threshold(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilityConfig {
    /// Enable WCAG accessibility auditing during scans.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum a11y findings per view before stopping (avoids noise on badly broken pages).
    #[serde(default = "default_max_a11y_findings_per_view")]
    pub max_findings_per_view: usize,

    /// Max same-category a11y findings before collapsing into a summary.
    /// Set to `0` to disable this aggregation.
    #[serde(default = "default_a11y_collapse_threshold")]
    pub collapse_threshold: usize,
}

impl Default for AccessibilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_findings_per_view: default_max_a11y_findings_per_view(),
            collapse_threshold: default_a11y_collapse_threshold(),
        }
    }
}

fn default_max_a11y_findings_per_view() -> usize {
    50
}

fn default_a11y_collapse_threshold() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingConfig {
    /// Enable form validation fuzzing during scans.
    /// Requires `exploration.submit_forms = true` to have any effect.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum fuzzing payloads to try per form field (default: 3).
    #[serde(default = "default_max_payloads_per_field")]
    pub max_payloads_per_field: usize,
}

impl Default for FuzzingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_payloads_per_field: default_max_payloads_per_field(),
        }
    }
}

fn default_max_payloads_per_field() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSensitivityConfig {
    /// Route path prefixes considered critical (e.g. admin panels, billing).
    #[serde(default = "default_critical_patterns")]
    pub critical_patterns: Vec<String>,

    /// Route path prefixes considered sensitive (e.g. settings, user data).
    #[serde(default = "default_sensitive_patterns")]
    pub sensitive_patterns: Vec<String>,

    /// Route path prefixes considered public (e.g. marketing pages, docs).
    #[serde(default = "default_public_patterns")]
    pub public_patterns: Vec<String>,

    /// Minimum tier at which authentication is required.
    /// Routes at or above this tier are expected to require auth.
    #[serde(default = "default_auth_required_tier")]
    pub auth_required_tier: String,
}

impl Default for RouteSensitivityConfig {
    fn default() -> Self {
        Self {
            critical_patterns: default_critical_patterns(),
            sensitive_patterns: default_sensitive_patterns(),
            public_patterns: default_public_patterns(),
            auth_required_tier: default_auth_required_tier(),
        }
    }
}

fn default_critical_patterns() -> Vec<String> {
    vec![
        "/admin",
        "/api/admin",
        "/billing",
        "/api/payment",
        "/api/internal",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn default_sensitive_patterns() -> Vec<String> {
    vec!["/settings", "/account", "/api/users", "/api/auth"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn default_public_patterns() -> Vec<String> {
    vec![
        "/about", "/pricing", "/blog", "/docs", "/legal", "/terms", "/privacy",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn default_auth_required_tier() -> String {
    "sensitive".to_string()
}

fn default_lcp_threshold() -> f64 {
    2500.0
}
fn default_fcp_threshold() -> f64 {
    1800.0
}
fn default_cls_threshold() -> f64 {
    0.1
}
fn default_ttfb_threshold() -> f64 {
    800.0
}
fn default_n_plus_one_threshold() -> usize {
    3
}

fn default_true() -> bool {
    true
}

fn default_max_depth() -> usize {
    10
}

fn default_max_views() -> usize {
    500
}

fn default_max_duration_minutes() -> u64 {
    120
}

fn default_max_stagnation_minutes() -> u64 {
    20
}

fn default_convergence_min_coverage_percent() -> f64 {
    95.0
}

fn default_convergence_window_views() -> usize {
    40
}

fn default_convergence_max_new_views() -> usize {
    1
}

fn default_interaction_timeout_ms() -> u64 {
    5_000
}

fn default_settle_timeout_ms() -> u64 {
    2_000
}

fn default_max_concurrent_tabs() -> usize {
    1
}

fn default_blocked_resource_types() -> Vec<String> {
    vec!["image".to_string(), "font".to_string(), "media".to_string()]
}

fn default_infra_502_group_threshold() -> usize {
    5
}

fn default_console_error_group_threshold() -> usize {
    4
}

fn default_dead_button_group_threshold() -> usize {
    3
}

fn default_stale_entity_404_group_threshold() -> usize {
    4
}

fn default_ui_slight_drift_threshold() -> f64 {
    0.25
}

fn default_ui_redesign_threshold() -> f64 {
    0.65
}

fn default_layout_consistency_tolerance_px() -> f64 {
    8.0
}

fn default_layout_consistency_min_routes() -> usize {
    3
}

fn default_output_dir() -> PathBuf {
    // Keep scan output inside the project-local .brokenapp folder by default.
    PathBuf::from("./.brokenapp/scans/scan-results")
}

fn default_bug_report_formats() -> Vec<BugReportFormat> {
    vec![BugReportFormat::Json, BugReportFormat::Markdown]
}

fn default_checkpoint_interval_seconds() -> u64 {
    15
}

fn default_auth_probe_expected_statuses() -> Vec<u16> {
    vec![200, 204]
}

fn default_delay_between_interactions_ms() -> u64 {
    250
}

fn default_max_interactions_per_view() -> usize {
    25
}

fn default_max_body_bytes() -> usize {
    256 * 1024
}

fn default_max_schema_samples() -> usize {
    10
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_depth: default_max_depth(),
            max_views: default_max_views(),
            max_duration_minutes: default_max_duration_minutes(),
            view_budget_seconds: 0,
            max_stagnation_minutes: default_max_stagnation_minutes(),
            stop_on_convergence: true,
            convergence_min_coverage_percent: default_convergence_min_coverage_percent(),
            convergence_window_views: default_convergence_window_views(),
            convergence_max_new_views: default_convergence_max_new_views(),
            screenshot_each_view: false,
            interaction_timeout_ms: default_interaction_timeout_ms(),
            settle_timeout_ms: default_settle_timeout_ms(),
            max_concurrent_tabs: default_max_concurrent_tabs(),
            block_unnecessary_resources: true,
            blocked_resource_types: default_blocked_resource_types(),
            blocked_domains: Vec::new(),
            allowed_hosts: Vec::new(),
            extra_headers: std::collections::BTreeMap::new(),
            user_agent: None,
            abort_on_rate_limits: 0,
            abort_on_antibot_challenges: 0,
            ignore_502: false,
            stale_entity_404_group_threshold: default_stale_entity_404_group_threshold(),
            block_private_egress: None,
            infra_502_group_threshold: default_infra_502_group_threshold(),
            console_error_group_threshold: default_console_error_group_threshold(),
            dead_button_group_threshold: default_dead_button_group_threshold(),
            ui_consistency: UiConsistencyConfig::default(),
            layout_consistency: LayoutConsistencyConfig::default(),
            scope: None,
            seed_urls: Vec::new(),
            deprioritize_routes: Vec::new(),
            seed_routes_file: None,
            runtime_templates: Vec::new(),
            via_playwright_mcp: false,
            write_guard: WriteGuardConfig::default(),
            route_templates: Vec::new(),
            viewport_width: default_viewport_width(),
            viewport_height: default_viewport_height(),
            api_prefix_whitelist: Vec::new(),
            post_for_read_ignore: Vec::new(),
            auth_path: None,
            scopes_file: None,
            codebase_path: None,
            canary_interval_views: 0,
            canary_before_new_route: false,
            exploration: ExplorationConfig {
                strategy: ExplorationStrategy::default(),
                revisit_views: false,
                interact_with_delete_buttons: false,
                fill_forms_with_test_data: true,
                submit_forms: false,
                max_dropdown_expansions_per_view: default_max_dropdown_expansions_per_view(),
                novelty_scoring: false,
                max_interaction_depth: default_max_interaction_depth(),
                max_interactions_per_depth: default_max_interactions_per_depth(),
                deep_explore_forms: true,
                modal_dismiss_timeout_ms: default_modal_dismiss_timeout_ms(),
            },
            test_data: TestDataConfig::default(),
            limits: LimitsConfig::default(),
            pacing: PacingConfig::default(),
            performance: PerformanceConfig::default(),
            accessibility: AccessibilityConfig::default(),
            fuzzing: FuzzingConfig::default(),
            route_sensitivity: RouteSensitivityConfig::default(),
        }
    }
}

fn default_viewport_width() -> u32 {
    1366
}

fn default_viewport_height() -> u32 {
    900
}

/// How the scanner treats state-changing requests during interaction.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WriteGuardMode {
    /// Record the attempted write and fail it before it leaves the browser.
    #[default]
    Block,
    /// Record the attempted write and answer it locally with a stub response
    /// (`stub_status`, empty JSON body) so the UI can continue its flow.
    Stub,
    /// Let writes through (only for disposable local backends).
    Off,
}

/// Write-guard settings. See [`ScanConfig::write_guard`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteGuardConfig {
    #[serde(default)]
    pub mode: WriteGuardMode,
    /// `METHOD url-glob` patterns that are allowed through even when guarded
    /// (e.g. `POST */api/search*` for read-only POST endpoints).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Allow auth token refresh/session endpoints through (never logout).
    #[serde(default = "default_true")]
    pub allow_auth: bool,
    /// Status code used by `stub` mode.
    #[serde(default = "default_write_guard_stub_status")]
    pub stub_status: u16,
}

fn default_write_guard_stub_status() -> u16 {
    200
}

impl Default for WriteGuardConfig {
    fn default() -> Self {
        Self {
            mode: WriteGuardMode::Block,
            allow: Vec::new(),
            allow_auth: true,
            stub_status: default_write_guard_stub_status(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_state_auth_parses_and_resolves_relative_paths_against_the_config() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("scans/run1");
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("scan.toml");
        std::fs::write(
            &config,
            r#"
[target]
url = "http://127.0.0.1:47280/"

[auth]
type = "storage_state"
path = "../../session/admin.json"

[[auth_paths]]
name = "coach"
type = "storage_state"
path = "/abs/coach.json"

[[auth_paths]]
name = "user"
type = "storage_state"
path = "user.json"

[scan]
max_duration_minutes = 0
max_views = 0
view_budget_seconds = 300
stop_on_convergence = false
"#,
        )
        .unwrap();
        let cfg = BrokenAppConfig::from_toml_path(&config).unwrap();
        let Some(AuthConfig::StorageState { path }) = cfg.auth.as_ref() else {
            panic!("storage_state auth: {:?}", cfg.auth);
        };
        assert!(Path::new(path).is_absolute(), "{path}");
        assert!(
            path.ends_with("scans/run1/../../session/admin.json"),
            "{path}"
        );
        assert!(matches!(
            &cfg.auth_paths[0].auth,
            AuthConfig::StorageState { path } if path == "/abs/coach.json"
        ));
        assert!(matches!(
            &cfg.auth_paths[1].auth,
            AuthConfig::StorageState { path } if path.ends_with("scans/run1/user.json")
        ));
        assert_eq!(cfg.scan.view_budget_seconds, 300);
        assert_eq!(cfg.scan.max_duration_minutes, 0);
        assert_eq!(cfg.scan.max_views, 0);
        assert!(!cfg.scan.stop_on_convergence);

        let auth = cfg.auth.unwrap();
        assert_eq!(auth.type_name(), "storage_state");
        assert!(!auth.is_renewable());
        assert!(auth.login_path_hint().is_none());
        // Round-trips through TOML with the contract's field names.
        let toml = toml::to_string(&auth).unwrap();
        assert!(toml.contains("type = \"storage_state\""), "{toml}");
        assert!(toml.contains("path = "), "{toml}");
    }

    #[test]
    fn storage_state_env_paths_are_resolved_at_login_not_absolutized() {
        for path in ["env:SAVED_SESSION_PATH", "${SAVED_SESSION_PATH}"] {
            let mut auth = AuthConfig::StorageState {
                path: path.to_string(),
            };
            auth.resolve_relative_paths(Path::new("/config"));
            assert!(matches!(auth, AuthConfig::StorageState { path: actual } if actual == path));
        }
    }

    #[test]
    fn selected_auth_path_keeps_its_resolved_session_file() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("brokenapp.toml");
        std::fs::write(
            &config,
            r#"
[target]
url = "http://127.0.0.1:47280/"

[[auth_paths]]
name = "admin"
type = "storage_state"
path = "session/admin.json"

[scan]
auth_path = "admin"
"#,
        )
        .unwrap();
        let cfg = BrokenAppConfig::from_toml_path(&config).unwrap();
        let Some(AuthConfig::StorageState { path }) = cfg.auth.as_ref() else {
            panic!("selected auth path: {:?}", cfg.auth);
        };
        assert!(path.ends_with("session/admin.json") && Path::new(path).is_absolute());
    }

    #[test]
    fn renewable_auth_methods_and_defaults() {
        let form: AuthConfig = toml::from_str(
            r##"
type = "form"
login_url = "/session/new"
username_selector = "#u"
password_selector = "#p"
submit_selector = "#s"
username = "env:ROLE_USER"
password = "env:ROLE_PASS"
"##,
        )
        .unwrap();
        assert!(form.is_renewable());
        assert_eq!(form.login_path_hint(), Some("/session/new"));
        assert!(!AuthConfig::Manual { login_url: None }.is_renewable());
        assert_eq!(ScanConfig::default().view_budget_seconds, 0);
    }
}
