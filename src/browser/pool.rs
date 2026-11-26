use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::target::CreateTargetParams;
use chromiumoxide::error::CdpError;
use futures::StreamExt;
use uuid::Uuid;

use crate::browser::PageClient;

#[derive(Debug, Clone)]
pub struct BrowserLaunchOptions {
    pub chrome_executable: Option<PathBuf>,
    pub headless: bool,
    pub ignore_https_errors: bool,
    /// WebSocket URL to connect to a remote Chrome/Chromium instance
    /// (e.g. `ws://localhost:9222/devtools/browser/...` or a Browserless.io URL).
    /// When set, skips local Chrome detection and launches no local process.
    pub remote_chrome_url: Option<String>,
    /// Browser locale (e.g. "en-US"). When set, passes `--lang=<locale>` to Chrome.
    pub locale: Option<String>,
}

impl Default for BrowserLaunchOptions {
    fn default() -> Self {
        Self {
            chrome_executable: None,
            headless: true,
            ignore_https_errors: false,
            remote_chrome_url: None,
            locale: None,
        }
    }
}

pub struct BrowserManager {
    browser: Browser,
    _handler_task: tokio::task::JoinHandle<()>,
    shutting_down: Arc<AtomicBool>,
    user_data_dir: Option<PathBuf>,
}

impl Drop for BrowserManager {
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::Release);
    }
}

impl BrowserManager {
    pub async fn launch(opts: BrowserLaunchOptions) -> Result<Self> {
        // Remote Chrome: connect to an existing browser via WebSocket.
        if let Some(ref ws_url) = opts.remote_chrome_url {
            return Self::connect_remote(ws_url).await;
        }

        let mut builder = BrowserConfig::builder();
        let mut chrome_args = default_chrome_args();

        // Default performance-oriented flags. Keep these ahead of env-provided
        // args so operators can override them when needed.
        // Allow environment-based overrides for containerized runs and power
        // users. This keeps CLI/config stable while letting docker images set
        // sane defaults.
        //
        // Examples:
        //   BROKENAPP_NO_SANDBOX=1
        //   BROKENAPP_CHROME_ARGS="--disable-dev-shm-usage --disable-gpu"
        if env_truthy("BROKENAPP_NO_SANDBOX") {
            builder = builder.no_sandbox();
        }
        if let Some(args) = env_string_list("BROKENAPP_CHROME_ARGS") {
            chrome_args.extend(args);
        }
        if let Some(timeout_ms) = env_duration_ms("BROKENAPP_CHROME_REQUEST_TIMEOUT_MS") {
            builder = builder.request_timeout(Duration::from_millis(timeout_ms));
        }

        // By default chromiumoxide uses `HeadlessMode::True`. Only switch to
        // headful when requested.
        if !opts.headless {
            builder = builder.with_head();
        }

        // By default chromiumoxide ignores HTTPS errors. Respect HTTPS errors
        // unless configured otherwise.
        if !opts.ignore_https_errors {
            builder = builder.respect_https_errors();
        }

        // A shorter default helps fail fast on bad chrome paths.
        builder = builder.launch_timeout(Duration::from_secs(20));

        // Use a per-run profile directory to avoid singleton lock issues when a
        // previous run crashes/kills Chrome mid-scan.
        let user_data_dir = std::env::temp_dir()
            .join("brokenapp-chrome-profile")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&user_data_dir)
            .with_context(|| format!("create {}", user_data_dir.display()))?;
        builder = builder.user_data_dir(&user_data_dir);

        if let Some(ref locale) = opts.locale {
            // Allow locale from config to override any env-provided --lang flag.
            chrome_args.retain(|a| a != "--lang" && !a.starts_with("--lang="));
            chrome_args.push(format!("--lang={locale}"));
        }

        if !chrome_args.is_empty() {
            builder = builder.args(chrome_args);
        }

        if let Some(executable) = opts.chrome_executable.clone() {
            builder = builder.chrome_executable(executable);
        }

        let config = builder
            .build()
            .map_err(|e| anyhow!(e))
            .context("build browser config")?;

        let (browser, handler) = Browser::launch(config)
            .await
            .with_context(|| chrome_launch_help(opts.chrome_executable.as_deref()))?;
        let shutting_down = Arc::new(AtomicBool::new(false));
        let handler_task = spawn_handler_task(handler, Arc::clone(&shutting_down), false);

        Ok(Self {
            browser,
            _handler_task: handler_task,
            shutting_down,
            user_data_dir: Some(user_data_dir),
        })
    }

    /// Connect to a remote Chrome/Chromium instance via a WebSocket URL.
    ///
    /// Use this for cloud/CI environments where Chrome runs remotely (e.g.
    /// Browserless.io, or a Docker sidecar).
    async fn connect_remote(ws_url: &str) -> Result<Self> {
        let (browser, handler) = Browser::connect(ws_url)
            .await
            .with_context(|| format!("connect to remote Chrome at {ws_url}"))?;

        let shutting_down = Arc::new(AtomicBool::new(false));
        let handler_task = spawn_handler_task(handler, Arc::clone(&shutting_down), true);

        Ok(Self {
            browser,
            _handler_task: handler_task,
            shutting_down,
            // No local user_data_dir — the remote browser manages its own profile.
            user_data_dir: None,
        })
    }

    pub fn browser(&self) -> &Browser {
        &self.browser
    }

    pub async fn shutdown(mut self) -> Result<()> {
        self.shutting_down.store(true, Ordering::Release);
        // Close open pages first with a short per-page bound so tabs holding
        // open SSE/HMR streams (`EventSource`, `/_next/webpack-hmr`, etc.)
        // tear down cleanly instead of stalling `Browser.close` for 5s.
        if let Ok(Ok(pages)) =
            tokio::time::timeout(Duration::from_millis(500), self.browser.pages()).await
        {
            let closes = pages.into_iter().map(|page| async move {
                let _ = tokio::time::timeout(Duration::from_millis(500), page.close()).await;
            });
            futures::future::join_all(closes).await;
        }

        let total_timeout = browser_shutdown_timeout();
        let graceful_timeout = total_timeout.min(Duration::from_millis(1500));
        let graceful = wait_for_shutdown(
            async {
                let _ =
                    tokio::time::timeout(Duration::from_millis(750), self.browser.close()).await;
                let _ = self.browser.wait().await;
            },
            graceful_timeout,
        )
        .await;

        let close_result = match graceful {
            Ok(()) => Ok(()),
            Err(graceful_err) => {
                // Local Chrome processes occasionally linger after `Browser.close`
                // (e.g. background network helpers or persistent streams). Terminate
                // and reap the child cleanly instead of waiting out a 5s timeout.
                match tokio::time::timeout(Duration::from_secs(2), self.browser.kill()).await {
                    Ok(Some(Ok(()))) => {
                        tracing::debug!(
                            "browser did not exit within {}ms; terminated child process",
                            graceful_timeout.as_millis()
                        );
                        Ok(())
                    }
                    Ok(Some(Err(err))) => Err(anyhow!("browser kill failed: {err}")),
                    // Remote browser (`connect_remote`) has no local child process.
                    Ok(None) => Ok(()),
                    Err(_) => Err(graceful_err),
                }
            }
        };

        self._handler_task.abort();
        if let Some(dir) = self.user_data_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
        close_result
    }

    pub async fn new_page(&self, url: &str) -> Result<PageClient> {
        let page = self
            .browser
            .new_page(CreateTargetParams::new(url))
            .await
            .with_context(|| format!("create page {url}"))?;
        Ok(PageClient::new(page))
    }

    /// A page in a window of its own. Parallel crawl tabs use this: a tab
    /// that shares a window with others is a background tab (hidden, its
    /// animation frames paused), which changes what the page renders and
    /// when it settles.
    pub async fn new_window_page(&self, url: &str) -> Result<PageClient> {
        let mut params = CreateTargetParams::new(url);
        params.new_window = Some(true);
        let page = self
            .browser
            .new_page(params)
            .await
            .with_context(|| format!("create page {url} in a new window"))?;
        Ok(PageClient::new(page))
    }

    pub fn default_macos_chrome_path() -> &'static Path {
        Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    }

    /// Best-effort lookup for a local Chrome/Chromium executable.
    ///
    /// If this returns `None`, chromiumoxide will still attempt to find a
    /// Chromium-based browser on its own.
    pub fn detect_chrome_executable() -> Option<PathBuf> {
        fn first_existing<I>(paths: I) -> Option<PathBuf>
        where
            I: IntoIterator<Item = PathBuf>,
        {
            for p in paths {
                if p.is_file() {
                    return Some(p);
                }
            }
            None
        }

        // Explicit overrides.
        for var in [
            "BROKENAPP_CHROME_EXECUTABLE",
            "BROKENAPP_CHROME",
            "CHROME_PATH",
        ] {
            if let Some(v) = std::env::var_os(var) {
                let p = PathBuf::from(v);
                if p.is_file() {
                    return Some(p);
                }
            }
        }

        // Common install locations.
        #[cfg(target_os = "macos")]
        {
            let candidates = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ];
            if let Some(p) = first_existing(candidates.iter().map(|p| PathBuf::from(p))) {
                return Some(p);
            }
        }

        #[cfg(target_os = "windows")]
        {
            let mut candidates = Vec::new();
            for pf_var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
                if let Some(pf) = std::env::var_os(pf_var) {
                    let pf = PathBuf::from(pf);
                    candidates.push(
                        pf.join("Google")
                            .join("Chrome")
                            .join("Application")
                            .join("chrome.exe"),
                    );
                    candidates.push(pf.join("Chromium").join("Application").join("chrome.exe"));
                    candidates.push(
                        pf.join("Microsoft")
                            .join("Edge")
                            .join("Application")
                            .join("msedge.exe"),
                    );
                }
            }
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                let local = PathBuf::from(local);
                candidates.push(
                    local
                        .join("Google")
                        .join("Chrome")
                        .join("Application")
                        .join("chrome.exe"),
                );
                candidates.push(
                    local
                        .join("Microsoft")
                        .join("Edge")
                        .join("Application")
                        .join("msedge.exe"),
                );
            }

            if let Some(p) = first_existing(candidates) {
                return Some(p);
            }
        }

        #[cfg(target_os = "linux")]
        {
            let candidates = [
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/snap/bin/chromium",
                "/usr/bin/microsoft-edge",
                "/usr/bin/microsoft-edge-stable",
            ];
            if let Some(p) = first_existing(candidates.iter().map(|p| PathBuf::from(p))) {
                return Some(p);
            }
        }

        // PATH search (cross-platform).
        let names: &[&str] = if cfg!(target_os = "windows") {
            &["chrome.exe", "chromium.exe", "msedge.exe"]
        } else {
            &[
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
                "chrome",
                "microsoft-edge",
                "microsoft-edge-stable",
            ]
        };

        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                if let Some(p) = first_existing(names.iter().map(|n| dir.join(n))) {
                    return Some(p);
                }
            }
        }

        None
    }
}

fn chrome_launch_help(chrome_executable: Option<&Path>) -> String {
    let mut msg = String::new();
    msg.push_str("launch browser\n\n");
    msg.push_str("Chrome/Chromium failed to start.\n");
    if let Some(p) = chrome_executable {
        msg.push_str(&format!(
            "- chrome_executable was set to: {}\n",
            p.display()
        ));
    } else {
        msg.push_str("- chrome_executable was not set (auto-detection was used)\n");
    }
    msg.push_str("\nTry one of:\n");
    msg.push_str(
        "- Env: set BROKENAPP_CHROME_EXECUTABLE=/path/to/chrome (or BROKENAPP_CHROME / CHROME_PATH)\n",
    );
    msg.push_str("- Install Google Chrome or Chromium in a standard location or on PATH\n");

    #[cfg(target_os = "windows")]
    {
        msg.push_str(
            "- Windows tip: typical path is C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe\n",
        );
    }

    #[cfg(target_os = "linux")]
    {
        msg.push_str("- Linux tip: ensure chromium/google-chrome is installed.\n");
        msg.push_str("- Docker/root tip: set BROKENAPP_NO_SANDBOX=1 and consider BROKENAPP_CHROME_ARGS=\"--disable-dev-shm-usage\".\n");
    }

    #[cfg(target_os = "macos")]
    {
        msg.push_str("- macOS tip: install Google Chrome or set BROKENAPP_CHROME_EXECUTABLE=\"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\"\n");
    }

    msg
}

fn env_truthy(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "y" | "on")
        }
        Err(_) => false,
    }
}

fn env_string_list(key: &str) -> Option<Vec<String>> {
    let raw = std::env::var(key).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Some(Vec::new());
    }
    Some(raw.split_whitespace().map(|s| s.to_string()).collect())
}

fn env_duration_ms(key: &str) -> Option<u64> {
    let raw = std::env::var(key).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    raw.parse::<u64>().ok()
}

fn browser_shutdown_timeout() -> Duration {
    env_duration_ms("BROKENAPP_CHROME_SHUTDOWN_TIMEOUT_MS")
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(5))
}

fn default_chrome_args() -> Vec<String> {
    [
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--disable-translate",
        "--no-first-run",
        "--disable-background-timer-throttling",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn spawn_handler_task(
    mut handler: chromiumoxide::Handler,
    shutting_down: Arc<AtomicBool>,
    remote: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(res) = handler.next().await {
            if let Err(err) = res {
                let is_shutting_down = shutting_down.load(Ordering::Acquire);
                if is_expected_shutdown_handler_error(&err, is_shutting_down) {
                    tracing::debug!(
                        error = ?err,
                        remote,
                        "chromiumoxide handler closed during browser shutdown"
                    );
                } else if remote {
                    tracing::error!(error = ?err, "chromiumoxide handler error (remote)");
                } else {
                    tracing::error!(error = ?err, "chromiumoxide handler error");
                }
                break;
            }
        }
    })
}

fn is_expected_shutdown_handler_error(err: &CdpError, shutting_down: bool) -> bool {
    if !shutting_down {
        return false;
    }
    match err {
        CdpError::Ws(ws) => is_expected_ws_teardown(&format!("{ws:?}")),
        CdpError::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionAborted
        ),
        CdpError::ChannelSendError(_) => true,
        _ => false,
    }
}

fn is_expected_ws_teardown(debug_msg: &str) -> bool {
    debug_msg.contains("ResetWithoutClosingHandshake")
        || debug_msg.contains("ConnectionClosed")
        || debug_msg.contains("AlreadyClosed")
        || debug_msg.contains("ConnectionReset")
        || debug_msg.contains("BrokenPipe")
        || debug_msg.contains("UnexpectedEof")
}

async fn wait_for_shutdown<F>(future: F, timeout: Duration) -> Result<()>
where
    F: Future<Output = ()>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| anyhow!("browser shutdown timed out after {}ms", timeout.as_millis()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[tokio::test]
    async fn wait_for_shutdown_times_out_slow_cleanup() {
        // A never-completing future deterministically exercises the timeout
        // path. Racing a short sleep against a shorter timeout is flaky under
        // load because the runtime may not poll the future until after both
        // deadlines have elapsed.
        let result =
            super::wait_for_shutdown(std::future::pending::<()>(), Duration::from_millis(5)).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn wait_for_shutdown_allows_fast_cleanup() {
        let result = super::wait_for_shutdown(async {}, Duration::from_millis(50)).await;

        assert!(result.is_ok());
    }

    #[test]
    fn default_chrome_args_preserve_devtools_stderr() {
        let args = super::default_chrome_args();

        assert!(!args.iter().any(|arg| arg == "--disable-logging"));
        assert!(!args.iter().any(|arg| arg.starts_with("--log-level")));
    }

    #[test]
    fn chrome_launch_help_omits_nonexistent_cli_flag() {
        let help = super::chrome_launch_help(None);

        assert!(!help.contains("--chrome-executable"), "{help}");
        assert!(help.contains("BROKENAPP_CHROME_EXECUTABLE"), "{help}");
        assert!(help.contains("BROKENAPP_CHROME"), "{help}");
    }

    #[test]
    fn shutdown_suppresses_expected_ws_teardown_errors_only_after_shutdown_starts() {
        assert!(super::is_expected_ws_teardown(
            "Protocol(ResetWithoutClosingHandshake)"
        ));
        assert!(super::is_expected_ws_teardown("ConnectionClosed"));
        assert!(super::is_expected_ws_teardown("AlreadyClosed"));
        assert!(!super::is_expected_ws_teardown("Http(403)"));

        let reset = chromiumoxide::error::CdpError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset",
        ));
        assert!(!super::is_expected_shutdown_handler_error(&reset, false));
        assert!(super::is_expected_shutdown_handler_error(&reset, true));

        let timeout = chromiumoxide::error::CdpError::Timeout;
        assert!(!super::is_expected_shutdown_handler_error(&timeout, true));
    }
}
