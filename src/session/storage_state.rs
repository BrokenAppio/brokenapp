//! Saved browser sessions ("storage state") for roles that can't log in with
//! a form: SSO, MFA, magic links. `brokenapp login --role <name>` opens a
//! headed browser, the human signs in, and the session (cookies plus
//! local/session storage for the app's origins) is written to a gitignored
//! file under `.brokenapp/session/`. Scans load it into every tab before the
//! first navigation.
//!
//! # File format
//!
//! Playwright `storageState` JSON, so a file saved by Playwright loads too,
//! plus two optional extensions: `sessionStorage` per origin and a
//! `brokenapp` block with capture metadata (where the human ended up after
//! signing in is the scan's session canary).
//!
//! ```json
//! {
//!   "cookies": [{"name": "sid", "value": "…", "domain": "127.0.0.1", "path": "/",
//!                "expires": -1, "httpOnly": true, "secure": false, "sameSite": "Lax"}],
//!   "origins": [{"origin": "http://127.0.0.1:3000",
//!                "localStorage": [{"name": "token", "value": "…"}],
//!                "sessionStorage": [{"name": "tab", "value": "…"}]}],
//!   "brokenapp": {"version": 1, "capturedAt": "2026-10-22T10:00:00Z",
//!                 "url": "http://127.0.0.1:3000/login",
//!                 "landingUrl": "http://127.0.0.1:3000/dashboard",
//!                 "loginPattern": "/login"}
//! }
//! ```
//!
//! The file holds live credentials: it is written with `0600` permissions
//! (owner only), loading tightens looser permissions, and nothing here ever
//! logs or returns a cookie or storage value (only names and counts).
//!
//! # Loading into a scan
//!
//! Cookies are set once in the browser's cookie jar, which every crawl tab
//! shares. Local and session storage are written by a script registered on
//! every crawl page before its first navigation (session storage is per tab):
//! it runs before the app's own scripts and only fills keys that are absent,
//! so values the app rotates during the scan (refresh tokens) are never put
//! back to the captured ones.

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chromiumoxide::cdp::browser_protocol::network::{CookieParam, CookieSameSite, TimeSinceEpoch};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::browser::{BrowserLaunchOptions, BrowserManager, PageClient};

/// Version of the `brokenapp` metadata block written by [`capture_storage_state`].
pub const STORAGE_STATE_VERSION: u32 = 1;

/// Environment switch for automation (CI, tests): capture in a headless
/// browser. A human sign-in needs the default headed window.
pub const CAPTURE_HEADLESS_ENV: &str = "BROKENAPP_LOGIN_HEADLESS";

/// Options for [`capture_storage_state`].
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// App URL to open (the login page or the app root).
    pub url: String,
    /// Where to write the captured session (JSON). Parent dirs are created.
    pub out_path: PathBuf,
    /// Chrome executable override (else auto-detected).
    pub chrome_executable: Option<String>,
    /// Max seconds to wait for the human to finish signing in.
    pub timeout_secs: u64,
    /// Finish when the page URL no longer matches this pattern (e.g. a login
    /// path). `None` = finish when the human presses Enter in the terminal.
    pub done_when_url_leaves: Option<String>,
}

/// What was captured (never contains secret values).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CapturedSession {
    pub path: String,
    pub cookies: usize,
    pub origins: Vec<String>,
    pub captured_at: String,
}

/// Extra knobs for [`capture_storage_state_with`].
#[derive(Debug, Clone, Default)]
pub struct CaptureControl {
    /// Run the capture browser headless (automation only: nobody can sign in
    /// in a headless window). [`capture_storage_state`] reads it from
    /// [`CAPTURE_HEADLESS_ENV`].
    pub headless: bool,
    /// Do not wait for Enter on stdin (finish only through
    /// `done_when_url_leaves`).
    pub ignore_stdin: bool,
}

// ── File format ─────────────────────────────────────────────────────────────

/// A saved browser session (Playwright `storageState` plus extensions).
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StorageState {
    #[serde(default)]
    pub cookies: Vec<StoredCookie>,
    #[serde(default)]
    pub origins: Vec<StoredOrigin>,
    /// Capture metadata (absent in files saved by Playwright).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brokenapp: Option<CaptureMeta>,
}

impl fmt::Debug for StorageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageState")
            .field("cookies", &self.cookies)
            .field("origins", &self.origins)
            .field("brokenapp", &self.brokenapp)
            .finish()
    }
}

/// One cookie (Playwright field names; `expires` is seconds since the epoch,
/// `-1` for a session cookie).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    #[serde(default = "default_cookie_path")]
    pub path: String,
    #[serde(default = "session_cookie_expiry")]
    pub expires: f64,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    /// `Strict`, `Lax` or `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

impl fmt::Debug for StoredCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCookie")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("expires", &self.expires)
            .finish()
    }
}

fn default_cookie_path() -> String {
    "/".to_string()
}

fn session_cookie_expiry() -> f64 {
    -1.0
}

/// Web storage of one origin.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredOrigin {
    /// `scheme://host[:port]`.
    pub origin: String,
    #[serde(default)]
    pub local_storage: Vec<NameValue>,
    /// Extension: Playwright does not save session storage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_storage: Vec<NameValue>,
}

/// A storage entry.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct NameValue {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for NameValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=<redacted>", self.name)
    }
}

/// Capture metadata written by [`capture_storage_state`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureMeta {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub captured_at: String,
    /// URL the capture browser opened.
    #[serde(default)]
    pub url: String,
    /// Where the human was when the capture finished: an authenticated
    /// page, used as the scan's session canary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landing_url: Option<String>,
    /// The login-page pattern the capture waited to leave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_pattern: Option<String>,
}

impl StorageState {
    /// Origins with web storage, or (without any) the origins implied by
    /// the cookies' domains; sorted and deduplicated (no values).
    pub fn origin_names(&self) -> Vec<String> {
        let mut out: std::collections::BTreeSet<String> = self
            .origins
            .iter()
            .map(|o| o.origin.trim_end_matches('/').to_string())
            .filter(|o| !o.is_empty())
            .collect();
        if out.is_empty() {
            for c in &self.cookies {
                let host = c.domain.trim_start_matches('.');
                if !host.is_empty() {
                    let scheme = if c.secure { "https" } else { "http" };
                    out.insert(format!("{scheme}://{host}"));
                }
            }
        }
        out.into_iter().collect()
    }

    /// Earliest expiry (seconds since the epoch) of the persistent cookies,
    /// when there are any.
    pub fn earliest_cookie_expiry(&self) -> Option<f64> {
        self.cookies
            .iter()
            .map(|c| c.expires)
            .filter(|e| e.is_finite() && *e > 0.0)
            .min_by(|a, b| a.total_cmp(b))
    }

    /// Validate the parts a scan relies on.
    fn validate(&self) -> Result<()> {
        let no_storage = self
            .origins
            .iter()
            .all(|o| o.local_storage.is_empty() && o.session_storage.is_empty());
        if self.cookies.is_empty() && no_storage {
            bail!("the saved session is empty (no cookies, no local or session storage)");
        }
        for c in &self.cookies {
            if c.name.trim().is_empty() {
                bail!("the saved session has a cookie without a name");
            }
            if c.domain.trim_start_matches('.').trim().is_empty() {
                bail!("the saved session's cookie {:?} has no domain", c.name);
            }
        }
        for o in &self.origins {
            let url = Url::parse(&o.origin)
                .with_context(|| format!("saved session origin {:?} is not a URL", o.origin))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                bail!(
                    "saved session origin {:?} is not an http(s) origin",
                    o.origin
                );
            }
        }
        Ok(())
    }
}

fn cookie_expired(expires: f64, now_secs: f64) -> bool {
    expires.is_finite() && expires > 0.0 && expires <= now_secs
}

fn now_secs() -> f64 {
    let now = chrono::Utc::now();
    now.timestamp() as f64 + f64::from(now.timestamp_subsec_millis()) / 1000.0
}

/// Read and validate a saved session. Group/world permissions on the file
/// are removed (with a warning): it holds live credentials.
pub fn read_storage_state(path: &Path) -> Result<StorageState> {
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "read saved session {} (capture it with `brokenapp login`)",
            path.display()
        )
    })?;
    tighten_permissions(path);
    // Never echo the file on parse errors: it holds credentials.
    let state: StorageState = serde_json::from_str(&raw).map_err(|err| {
        anyhow!(
            "saved session {} is not valid storage-state JSON (line {}, column {})",
            path.display(),
            err.line(),
            err.column()
        )
    })?;
    state
        .validate()
        .with_context(|| format!("saved session {}", path.display()))?;
    Ok(state)
}

/// Write `state` to `path` atomically with owner-only (`0600`) permissions.
/// Missing parent directories are created owner-only (`0700`).
pub fn write_storage_state(path: &Path, state: &StorageState) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    create_private_dir_all(&parent)?;
    let data = serde_json::to_vec_pretty(state).context("serialize saved session")?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "session.json".to_string());
    let tmp = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    {
        let mut file = open_private(&tmp)?;
        if let Err(err) = file.write_all(&data) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err).with_context(|| format!("write {}", tmp.display()));
        }
        let _ = file.sync_all();
    }
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("move saved session to {}", path.display()));
    }
    set_mode(path, 0o600)?;
    Ok(())
}

fn open_private(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("create {}", path.display()))
}

fn create_private_dir_all(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("set permissions of {}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Permission bits of `path` (unix), `None` elsewhere or when unreadable.
pub fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Remove group/other permissions from a saved session file.
fn tighten_permissions(path: &Path) {
    let Some(mode) = file_mode(path) else {
        return;
    };
    if mode & 0o077 == 0 {
        return;
    }
    match set_mode(path, mode & 0o700) {
        Ok(()) => tracing::warn!(
            file = %path.display(),
            mode = format!("{mode:o}"),
            "saved session was readable by other users; restricted it to the owner (0600)"
        ),
        Err(err) => tracing::warn!(
            file = %path.display(),
            error = %err,
            "saved session is readable by other users and its permissions could not be changed"
        ),
    }
}

/// What a saved session holds (counts and origins only).
pub fn summarize_storage_state(path: &Path, state: &StorageState) -> CapturedSession {
    let captured_at = state
        .brokenapp
        .as_ref()
        .map(|m| m.captured_at.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
        })
        .unwrap_or_default();
    CapturedSession {
        path: path.display().to_string(),
        cookies: state.cookies.len(),
        origins: state.origin_names(),
        captured_at,
    }
}

/// Read a saved session's metadata (for `doctor`/`projects`); errors if missing.
pub fn describe_storage_state(path: &Path) -> Result<CapturedSession> {
    let state = read_storage_state(path)?;
    Ok(summarize_storage_state(path, &state))
}

// ── Loading into a scan ─────────────────────────────────────────────────────

/// A saved session ready to apply to a scan's browser.
pub struct LoadedStorageState {
    /// Cookies to set in the browser (expired ones dropped).
    pub cookies: Vec<CookieParam>,
    /// Cookies in the file that had already expired.
    pub expired_cookies: usize,
    /// Script that fills local/session storage on every page (see the
    /// module docs). Holds secret values: never log it.
    pub init_script: Option<String>,
    /// Authenticated page the session reached at capture time (canary).
    pub landing_url: Option<String>,
    /// Login page pattern recorded at capture time.
    pub login_pattern: Option<String>,
    pub summary: CapturedSession,
}

impl fmt::Debug for LoadedStorageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedStorageState")
            .field("cookies", &self.cookies.len())
            .field("expired_cookies", &self.expired_cookies)
            .field(
                "init_script",
                &self.init_script.as_ref().map(|_| "<redacted>"),
            )
            .field("landing_url", &self.landing_url)
            .field("login_pattern", &self.login_pattern)
            .field("summary", &self.summary)
            .finish()
    }
}

/// Read `path` and prepare it for a scan (see [`apply_storage_state`]).
pub fn load_storage_state(path: &Path) -> Result<LoadedStorageState> {
    let state = read_storage_state(path)?;
    Ok(prepare(path, &state, now_secs()))
}

fn prepare(path: &Path, state: &StorageState, now: f64) -> LoadedStorageState {
    let mut cookies = Vec::new();
    let mut expired = 0usize;
    for c in &state.cookies {
        if cookie_expired(c.expires, now) {
            expired += 1;
            continue;
        }
        cookies.push(cookie_param(c));
    }
    let meta = state.brokenapp.clone().unwrap_or_default();
    LoadedStorageState {
        cookies,
        expired_cookies: expired,
        init_script: storage_init_script(&state.origins),
        landing_url: meta.landing_url.filter(|u| !u.trim().is_empty()),
        login_pattern: meta.login_pattern.filter(|p| !p.trim().is_empty()),
        summary: summarize_storage_state(path, state),
    }
}

/// CDP cookie for a stored one. Host-only cookies (no leading dot) are set
/// through a URL so they stay host-only; domain cookies keep their domain.
fn cookie_param(c: &StoredCookie) -> CookieParam {
    let mut p = CookieParam::new(c.name.clone(), c.value.clone());
    let path = if c.path.trim().is_empty() {
        "/".to_string()
    } else {
        c.path.clone()
    };
    if c.domain.starts_with('.') {
        p.domain = Some(c.domain.clone());
    } else {
        let scheme = if c.secure { "https" } else { "http" };
        p.url = Some(format!("{scheme}://{}{}", c.domain, path));
    }
    p.path = Some(path);
    p.secure = Some(c.secure);
    p.http_only = Some(c.http_only);
    p.same_site = match c
        .same_site
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("strict") => Some(CookieSameSite::Strict),
        Some("lax") => Some(CookieSameSite::Lax),
        Some("none") => Some(CookieSameSite::None),
        _ => None,
    };
    if c.expires.is_finite() && c.expires > 0.0 {
        p.expires = Some(TimeSinceEpoch::new(c.expires));
    }
    p
}

/// Page script that fills absent local/session storage keys for the page's
/// origin (top frame only), before the app's own scripts run.
pub fn storage_init_script(origins: &[StoredOrigin]) -> Option<String> {
    let mut map = serde_json::Map::new();
    for o in origins {
        if o.local_storage.is_empty() && o.session_storage.is_empty() {
            continue;
        }
        let pairs = |entries: &[NameValue]| {
            serde_json::Value::Array(
                entries
                    .iter()
                    .map(|e| serde_json::json!([e.name, e.value]))
                    .collect(),
            )
        };
        map.insert(
            o.origin.trim_end_matches('/').to_string(),
            serde_json::json!({
                "local": pairs(&o.local_storage),
                "session": pairs(&o.session_storage),
            }),
        );
    }
    if map.is_empty() {
        return None;
    }
    let data = serde_json::Value::Object(map).to_string();
    Some(format!(
        r#"(() => {{
  try {{
    if (window.top !== window) return;
    const saved = {data};
    const entry = saved[location.origin];
    if (!entry) return;
    const fill = (store, pairs) => {{
      for (const [k, v] of pairs) {{
        try {{ if (store.getItem(k) === null) store.setItem(k, v); }} catch (_) {{}}
      }}
    }};
    fill(window.localStorage, entry.local);
    fill(window.sessionStorage, entry.session);
  }} catch (_) {{}}
}})();"#
    ))
}

/// Set the saved session's cookies in `browser` (shared by every tab of the
/// scan) and return what the tabs still need (the storage script, canary).
pub async fn apply_storage_state(
    browser: &chromiumoxide::browser::Browser,
    path: &Path,
) -> Result<LoadedStorageState> {
    let loaded = load_storage_state(path)?;
    if loaded.expired_cookies > 0 {
        tracing::warn!(
            file = %path.display(),
            expired = loaded.expired_cookies,
            "saved session has expired cookies; they were not loaded"
        );
    }
    if !loaded.cookies.is_empty() {
        browser
            .set_cookies(loaded.cookies.clone())
            .await
            .context("load the saved session's cookies into the browser")?;
    }
    tracing::info!(
        file = %path.display(),
        cookies = loaded.cookies.len(),
        origins = loaded.summary.origins.len(),
        "saved session loaded"
    );
    Ok(loaded)
}

// ── Capture ─────────────────────────────────────────────────────────────────

/// Open a headed browser, let the human sign in, and save the session.
pub async fn capture_storage_state(opts: &CaptureOptions) -> Result<CapturedSession> {
    let headless = std::env::var(CAPTURE_HEADLESS_ENV)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    capture_storage_state_with(
        opts,
        &CaptureControl {
            headless,
            ignore_stdin: false,
        },
    )
    .await
}

/// [`capture_storage_state`] with explicit [`CaptureControl`].
///
/// Finishes when the page leaves `done_when_url_leaves` for one of the app's
/// own pages (after having been on it, and once the URL held still for a
/// moment: OAuth callbacks redirect again), or when Enter is pressed. Then
/// it saves the cookies of the app's hosts (the start URL's and the landing
/// page's, parent domains included) and the landing page's local and
/// session storage.
pub async fn capture_storage_state_with(
    opts: &CaptureOptions,
    control: &CaptureControl,
) -> Result<CapturedSession> {
    let start = Url::parse(opts.url.trim())
        .with_context(|| format!("login URL {:?} is not a valid URL", opts.url))?;
    if !matches!(start.scheme(), "http" | "https") {
        bail!("login URL must be http(s): {start}");
    }
    let pattern = opts
        .done_when_url_leaves
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    if pattern.is_none() && control.ignore_stdin {
        bail!("capture needs done_when_url_leaves when stdin is ignored");
    }
    let chrome = opts
        .chrome_executable
        .as_deref()
        .map(PathBuf::from)
        .or_else(BrowserManager::detect_chrome_executable);
    let browser = BrowserManager::launch(BrowserLaunchOptions {
        chrome_executable: chrome,
        headless: control.headless,
        ignore_https_errors: crate::safety::is_non_production_target(&start),
        remote_chrome_url: None,
        locale: None,
    })
    .await
    .context("launch the browser for sign-in")?;
    let result = capture_in_browser(&browser, &start, pattern, opts, control).await;
    if let Err(err) = browser.shutdown().await {
        tracing::debug!(error = ?err, "capture browser shutdown failed");
    }
    result
}

/// How long the URL must hold still on an app page before it is saved.
const LANDING_STABLE: Duration = Duration::from_millis(1500);

async fn capture_in_browser(
    browser: &BrowserManager,
    start: &Url,
    pattern: Option<String>,
    opts: &CaptureOptions,
    control: &CaptureControl,
) -> Result<CapturedSession> {
    let page = browser.new_page("about:blank").await?;
    page.enable_domains().await?;
    page.goto_and_wait(start.as_str(), Duration::from_secs(60))
        .await
        .with_context(|| format!("open {start}"))?;

    let timeout = Duration::from_secs(opts.timeout_secs.max(1));
    if control.headless {
        eprintln!(
            "Waiting up to {}s for the sign-in at {start} to finish (headless).",
            timeout.as_secs()
        );
    } else {
        eprintln!();
        eprintln!("Sign in in the browser window that just opened ({start}).");
        match pattern.as_deref() {
            Some(p) => eprintln!(
                "The session is saved once you leave the login page ({p}), or press Enter here when you are signed in."
            ),
            None => eprintln!("Press Enter here once you are signed in."),
        }
        eprintln!("Waiting up to {}s.", timeout.as_secs());
    }

    let (enter_tx, mut enter_rx) = tokio::sync::mpsc::channel::<()>(1);
    if !control.ignore_stdin {
        // Tokio's stdin uses an uncancellable blocking task; aborting the
        // async reader after URL completion can hang runtime shutdown. A
        // detached native reader does not keep the capture process alive.
        std::thread::spawn(move || {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_ok_and(|n| n > 0) {
                let _ = enter_tx.blocking_send(());
            }
        });
    }
    let waited = wait_for_sign_in(&page, start, pattern.as_deref(), timeout, &mut enter_rx).await;
    let landing = waited?;
    let _ = crate::browser::cdp_helpers::settle(&page, Duration::from_secs(5)).await;

    let landing_url = Url::parse(&landing).ok();
    let mut hosts = HostSet::from_url(start);
    if let Some(u) = landing_url.as_ref() {
        hosts.add_url(u);
    }
    let state = dump_session(browser, &page, &hosts, start, landing_url.as_ref(), pattern).await?;
    write_storage_state(&opts.out_path, &state)?;
    let summary = summarize_storage_state(&opts.out_path, &state);
    tracing::info!(
        file = %opts.out_path.display(),
        cookies = summary.cookies,
        origins = summary.origins.len(),
        "saved browser session"
    );
    let _ = page.inner().clone().close().await;
    Ok(summary)
}

/// Poll the page until the sign-in is done; returns the landing URL.
async fn wait_for_sign_in(
    page: &PageClient,
    start: &Url,
    pattern: Option<&str>,
    timeout: Duration,
    enter: &mut tokio::sync::mpsc::Receiver<()>,
) -> Result<String> {
    let app_hosts = HostSet::from_url(start);
    let started = Instant::now();
    let mut seen_login = pattern.is_some_and(|p| url_matches_login_pattern(start.as_str(), p));
    let mut stable: Option<(String, Instant)> = None;
    loop {
        if started.elapsed() > timeout {
            bail!(
                "timed out after {}s waiting for the sign-in to finish",
                timeout.as_secs()
            );
        }
        let current = page
            .url()
            .await
            .context("the sign-in browser window was closed")?
            .unwrap_or_default();
        if enter.try_recv().is_ok() {
            return Ok(current);
        }
        if let Some(p) = pattern {
            if url_matches_login_pattern(&current, p) {
                seen_login = true;
                stable = None;
            } else if seen_login && app_hosts.contains_url(&current) {
                // Left the login page for the app: wait until the URL holds
                // still (OAuth callbacks redirect again) before saving.
                match &stable {
                    Some((u, since)) if *u == current => {
                        if since.elapsed() >= LANDING_STABLE {
                            return Ok(current);
                        }
                    }
                    _ => stable = Some((current.clone(), Instant::now())),
                }
            } else {
                stable = None;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Cookies of the app's hosts and the landing page's web storage.
async fn dump_session(
    browser: &BrowserManager,
    page: &PageClient,
    hosts: &HostSet,
    start: &Url,
    landing: Option<&Url>,
    login_pattern: Option<String>,
) -> Result<StorageState> {
    let all = browser
        .browser()
        .get_cookies()
        .await
        .context("read the browser's cookies")?;
    let mut cookies: Vec<StoredCookie> = all
        .into_iter()
        .filter(|c| hosts.matches_cookie_domain(&c.domain))
        .map(|c| StoredCookie {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            expires: if c.session { -1.0 } else { c.expires },
            http_only: c.http_only,
            secure: c.secure,
            same_site: c.same_site.map(|s| s.as_ref().to_string()),
        })
        .collect();
    cookies.sort_by(|a, b| {
        (a.domain.as_str(), a.path.as_str(), a.name.as_str()).cmp(&(
            b.domain.as_str(),
            b.path.as_str(),
            b.name.as_str(),
        ))
    });

    #[derive(Deserialize)]
    struct WebStorage {
        origin: String,
        local: Vec<(String, String)>,
        session: Vec<(String, String)>,
    }
    let storage: Option<WebStorage> = page
        .evaluate_json(
            "(() => { const dump = (s) => { const out = []; try { for (let i = 0; i < s.length; i++) { const k = s.key(i); out.push([k, String(s.getItem(k))]); } } catch (_) {} return out; }; return { origin: location.origin, local: dump(window.localStorage), session: dump(window.sessionStorage) }; })()",
        )
        .await
        .ok();
    let mut origins = Vec::new();
    if let Some(ws) = storage
        && ws.origin.starts_with("http")
    {
        let to_pairs = |mut v: Vec<(String, String)>| {
            v.sort();
            v.into_iter()
                .map(|(name, value)| NameValue { name, value })
                .collect::<Vec<_>>()
        };
        let origin = StoredOrigin {
            origin: ws.origin,
            local_storage: to_pairs(ws.local),
            session_storage: to_pairs(ws.session),
        };
        if !origin.local_storage.is_empty() || !origin.session_storage.is_empty() {
            origins.push(origin);
        }
    }
    let state = StorageState {
        cookies,
        origins,
        brokenapp: Some(CaptureMeta {
            version: STORAGE_STATE_VERSION,
            captured_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            url: start.to_string(),
            landing_url: landing.map(Url::to_string),
            login_pattern,
        }),
    };
    if state.validate().is_err() {
        bail!(
            "no cookies or storage were found for {} after sign-in; was the sign-in completed?",
            hosts.describe()
        );
    }
    Ok(state)
}

/// `true` when `url` (path, query and fragment, or the full URL when the
/// pattern names a scheme) contains `pattern`, case-insensitively.
pub fn url_matches_login_pattern(url: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    if pattern.contains("://") {
        return url.to_ascii_lowercase().contains(&pattern);
    }
    let Ok(parsed) = Url::parse(url) else {
        return url.to_ascii_lowercase().contains(&pattern);
    };
    let mut tail = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        tail.push('?');
        tail.push_str(q);
    }
    if let Some(f) = parsed.fragment() {
        tail.push('#');
        tail.push_str(f);
    }
    tail.to_ascii_lowercase().contains(&pattern)
}

/// Hosts that belong to the app (cookie domains are matched against them).
#[derive(Debug, Clone, Default)]
struct HostSet {
    hosts: Vec<String>,
}

impl HostSet {
    fn from_url(url: &Url) -> Self {
        let mut set = Self::default();
        set.add_url(url);
        set
    }

    fn add_host(&mut self, host: &str) {
        let host = host.to_ascii_lowercase();
        if !self.hosts.contains(&host) {
            self.hosts.push(host);
        }
    }

    fn add_url(&mut self, url: &Url) {
        if let Some(host) = url.host_str() {
            self.add_host(host);
            // `localhost` and `127.0.0.1` are the same dev server.
            if crate::url_origin::is_localhost_alias(host) {
                self.add_host("localhost");
                self.add_host("127.0.0.1");
            }
        }
    }

    fn contains_url(&self, url: &str) -> bool {
        Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .is_some_and(|h| self.hosts.contains(&h))
    }

    /// A cookie for `domain` is sent to one of the hosts.
    fn matches_cookie_domain(&self, domain: &str) -> bool {
        let d = domain.trim_start_matches('.').to_ascii_lowercase();
        !d.is_empty()
            && self
                .hosts
                .iter()
                .any(|h| *h == d || h.ends_with(&format!(".{d}")))
    }

    fn describe(&self) -> String {
        self.hosts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StorageState {
        StorageState {
            cookies: vec![
                StoredCookie {
                    name: "sid".into(),
                    value: "secret-session-value".into(),
                    domain: "127.0.0.1".into(),
                    path: "/".into(),
                    expires: -1.0,
                    http_only: true,
                    secure: false,
                    same_site: Some("Lax".into()),
                },
                StoredCookie {
                    name: "pref".into(),
                    value: "secret-pref".into(),
                    domain: ".example.test".into(),
                    path: "/app".into(),
                    expires: 4_102_444_800.0,
                    http_only: false,
                    secure: true,
                    same_site: Some("None".into()),
                },
                StoredCookie {
                    name: "old".into(),
                    value: "secret-stale".into(),
                    domain: "127.0.0.1".into(),
                    path: "/".into(),
                    expires: 1_000.0,
                    http_only: false,
                    secure: false,
                    same_site: None,
                },
            ],
            origins: vec![StoredOrigin {
                origin: "http://127.0.0.1:47280".into(),
                local_storage: vec![NameValue {
                    name: "token".into(),
                    value: "secret-local-value".into(),
                }],
                session_storage: vec![NameValue {
                    name: "tab".into(),
                    value: "secret-tab-value".into(),
                }],
            }],
            brokenapp: Some(CaptureMeta {
                version: 1,
                captured_at: "2026-10-22T10:00:00Z".into(),
                url: "http://127.0.0.1:47280/login".into(),
                landing_url: Some("http://127.0.0.1:47280/dashboard".into()),
                login_pattern: Some("/login".into()),
            }),
        }
    }

    #[test]
    fn file_format_round_trips_with_playwright_field_names() {
        let state = sample();
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["cookies"][0]["httpOnly"], true);
        assert_eq!(json["cookies"][0]["sameSite"], "Lax");
        assert_eq!(json["cookies"][0]["expires"], -1.0);
        assert_eq!(json["origins"][0]["localStorage"][0]["name"], "token");
        assert_eq!(json["origins"][0]["sessionStorage"][0]["name"], "tab");
        assert_eq!(
            json["brokenapp"]["landingUrl"],
            "http://127.0.0.1:47280/dashboard"
        );
        let back: StorageState = serde_json::from_value(json).unwrap();
        assert_eq!(back, state);
        assert_eq!(state.earliest_cookie_expiry(), Some(1_000.0));
    }

    #[test]
    fn playwright_files_without_extensions_load() {
        let raw = r#"{"cookies":[{"name":"a","value":"b","domain":"localhost","path":"/","expires":-1,"httpOnly":false,"secure":false,"sameSite":"Lax"}],
                     "origins":[{"origin":"http://localhost:3000","localStorage":[{"name":"k","value":"v"}]}]}"#;
        let state: StorageState = serde_json::from_str(raw).unwrap();
        state.validate().unwrap();
        assert!(state.brokenapp.is_none());
        assert!(state.origins[0].session_storage.is_empty());
        assert_eq!(
            state.origin_names(),
            vec!["http://localhost:3000".to_string()]
        );
        let cookies_only: StorageState = serde_json::from_str(
            r#"{"cookies":[{"name":"a","value":"b","domain":".app.test","secure":true}]}"#,
        )
        .unwrap();
        cookies_only.validate().unwrap();
        assert_eq!(cookies_only.cookies[0].path, "/");
        assert_eq!(cookies_only.cookies[0].expires, -1.0);
        assert_eq!(cookies_only.origin_names(), vec!["https://app.test"]);
    }

    #[test]
    fn invalid_states_are_rejected() {
        let no_domain: StorageState =
            serde_json::from_str(r#"{"cookies":[{"name":"a","value":"b","domain":"."}]}"#).unwrap();
        assert!(no_domain.validate().is_err());
        let bad_origin: StorageState = serde_json::from_str(
            r#"{"origins":[{"origin":"file:///etc","localStorage":[{"name":"k","value":"v"}]}]}"#,
        )
        .unwrap();
        assert!(bad_origin.validate().is_err());
    }

    #[test]
    fn debug_output_never_contains_values() {
        let state = sample();
        let dbg = format!("{state:?}");
        assert!(!dbg.contains("secret"), "{dbg}");
        let loaded = prepare(Path::new("/tmp/x.json"), &state, 2_000.0);
        let dbg = format!("{loaded:?}");
        assert!(!dbg.contains("secret"), "{dbg}");
        let summary = serde_json::to_string(&loaded.summary).unwrap();
        assert!(!summary.contains("secret"), "{summary}");
    }

    #[test]
    fn prepare_drops_expired_cookies_and_keeps_host_only_cookies_host_only() {
        let loaded = prepare(Path::new("/tmp/x.json"), &sample(), 2_000.0);
        assert_eq!(loaded.cookies.len(), 2);
        assert_eq!(loaded.expired_cookies, 1);
        let sid = &loaded.cookies[0];
        assert_eq!(sid.url.as_deref(), Some("http://127.0.0.1/"));
        assert!(sid.domain.is_none());
        assert_eq!(sid.http_only, Some(true));
        assert!(
            sid.expires.is_none(),
            "session cookies stay session cookies"
        );
        let pref = &loaded.cookies[1];
        assert_eq!(pref.domain.as_deref(), Some(".example.test"));
        assert_eq!(pref.path.as_deref(), Some("/app"));
        assert!(matches!(pref.same_site, Some(CookieSameSite::None)));
        assert!(pref.expires.is_some());
        assert_eq!(
            loaded.landing_url.as_deref(),
            Some("http://127.0.0.1:47280/dashboard")
        );
        assert_eq!(loaded.login_pattern.as_deref(), Some("/login"));
    }

    #[test]
    fn init_script_fills_only_absent_keys_for_the_matching_origin() {
        let script = storage_init_script(&sample().origins).expect("script");
        assert!(script.contains(r#""http://127.0.0.1:47280""#));
        assert!(script.contains("getItem(k) === null"));
        assert!(script.contains("window.top !== window"));
        assert!(script.contains("sessionStorage"));
        // Values are JSON-encoded, never spliced raw into the script.
        let tricky = vec![StoredOrigin {
            origin: "http://a.test/".into(),
            local_storage: vec![NameValue {
                name: "k".into(),
                value: "\"); alert(1); (\"".into(),
            }],
            session_storage: vec![],
        }];
        let script = storage_init_script(&tricky).unwrap();
        assert!(script.contains(r#"\"); alert(1); (\""#), "{script}");
        assert!(script.contains(r#""http://a.test""#), "{script}");
        assert!(storage_init_script(&[]).is_none());
    }

    #[test]
    fn writes_owner_only_files_and_tightens_loose_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("session/admin.json");
        write_storage_state(&path, &sample()).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(file_mode(&path), Some(0o600));
            assert_eq!(file_mode(path.parent().unwrap()), Some(0o700));
            set_mode(&path, 0o644).unwrap();
        }
        let summary = describe_storage_state(&path).unwrap();
        #[cfg(unix)]
        assert_eq!(
            file_mode(&path),
            Some(0o600),
            "loading tightens permissions"
        );
        assert_eq!(summary.cookies, 3);
        assert_eq!(summary.origins, vec!["http://127.0.0.1:47280".to_string()]);
        assert_eq!(summary.captured_at, "2026-10-22T10:00:00Z");
        // Overwriting keeps owner-only permissions and leaves no temp files.
        write_storage_state(&path, &sample()).unwrap();
        #[cfg(unix)]
        assert_eq!(file_mode(&path), Some(0o600));
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn describe_reports_missing_and_invalid_files_without_echoing_content() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = describe_storage_state(&tmp.path().join("none.json")).unwrap_err();
        assert!(
            format!("{missing:#}").contains("brokenapp login"),
            "{missing:#}"
        );
        let bad = tmp.path().join("bad.json");
        std::fs::write(&bad, "{\"cookies\": [secret-garbage").unwrap();
        let err = format!("{:#}", describe_storage_state(&bad).unwrap_err());
        assert!(err.contains("not valid storage-state JSON"), "{err}");
        assert!(!err.contains("secret"), "{err}");
        let empty = tmp.path().join("empty.json");
        std::fs::write(&empty, "{\"cookies\": [], \"origins\": []}").unwrap();
        let err = format!("{:#}", describe_storage_state(&empty).unwrap_err());
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn login_pattern_matching() {
        assert!(url_matches_login_pattern(
            "http://127.0.0.1:3000/login?next=/x",
            "/login"
        ));
        assert!(url_matches_login_pattern(
            "http://127.0.0.1:3000/#/login",
            "/login"
        ));
        assert!(!url_matches_login_pattern(
            "http://127.0.0.1:3000/dashboard",
            "/login"
        ));
        assert!(url_matches_login_pattern(
            "https://idp.test/authorize",
            "https://idp.test"
        ));
        assert!(!url_matches_login_pattern("http://a.test/login", "  "));
    }

    #[test]
    fn cookie_domains_match_app_hosts_and_parents_only() {
        let mut hosts = HostSet::from_url(&Url::parse("http://app.example.test:3000/").unwrap());
        assert!(hosts.matches_cookie_domain("app.example.test"));
        assert!(hosts.matches_cookie_domain(".example.test"));
        assert!(!hosts.matches_cookie_domain("idp.example.test"));
        assert!(!hosts.matches_cookie_domain("accounts.google.com"));
        hosts.add_url(&Url::parse("http://localhost:3000/").unwrap());
        assert!(hosts.matches_cookie_domain("127.0.0.1"));
        assert!(hosts.contains_url("http://127.0.0.1:3000/x"));
        assert!(!hosts.contains_url("https://accounts.google.com/x"));
    }
}
