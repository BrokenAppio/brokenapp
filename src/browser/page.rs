use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chromiumoxide::cdp::browser_protocol::{emulation, network, page as cdp_page};
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::StreamExt;
use serde::Deserialize;
use serde::de::DeserializeOwned;

/// Identity of one browser tab: its CDP target id.
///
/// Attribution state (the action being exercised, main-document epochs,
/// native dialogs, console windows) is kept per tab, so tabs crawling in
/// parallel never credit each other's requests, console errors or dialogs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TabKey(String);

impl TabKey {
    /// The lane of pages attached without a tab of their own (auth flows,
    /// mutation replay), which drive one page at a time.
    pub fn shared() -> Self {
        Self(String::new())
    }

    /// The tab of `page`.
    pub fn of(page: &Page) -> Self {
        Self(page.target_id().inner().clone())
    }

    /// A tab key from a raw id (tests).
    pub fn from_raw(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn is_shared(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TabKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_shared() {
            f.write_str("shared")
        } else {
            f.write_str(&self.0)
        }
    }
}

#[derive(Debug, Clone)]
pub struct PageClient {
    page: Page,
    /// Same-origin script/module requests in flight (dynamic `import()` route
    /// chunks), tracked from CDP Network events once [`Self::enable_domains`]
    /// ran. Shared by every clone of this client.
    script_loads: Arc<ScriptLoads>,
}

/// In-flight same-origin script requests by CDP request id.
#[derive(Debug, Default)]
struct ScriptLoads {
    pending: Mutex<ScriptLoadState>,
    tracking: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Default)]
struct ScriptLoadState {
    pending: HashMap<String, Instant>,
    /// Requests whose end was seen before their start (the three CDP event
    /// streams are separate channels): a late start must not count.
    ended_early: HashMap<String, Instant>,
}

impl ScriptLoadState {
    fn started(&mut self, id: String) {
        if self.ended_early.remove(&id).is_none() {
            self.pending.insert(id, Instant::now());
        }
    }

    fn ended(&mut self, id: &str) {
        if self.pending.remove(id).is_none() {
            // Most ended requests are not scripts; remember them briefly.
            if self.ended_early.len() >= 2048 {
                self.ended_early
                    .retain(|_, at| at.elapsed() < SCRIPT_END_MEMORY);
            }
            self.ended_early.insert(id.to_string(), Instant::now());
        }
    }

    fn in_flight(&mut self) -> usize {
        self.pending
            .retain(|_, started| started.elapsed() < SCRIPT_LOAD_STALE_AFTER);
        self.pending.len()
    }
}

/// How long the end of a request not (yet) known as started is remembered.
const SCRIPT_END_MEMORY: Duration = Duration::from_secs(5);

/// A script request older than this is assumed finished (a missed
/// `loadingFinished` must not block settling forever).
const SCRIPT_LOAD_STALE_AFTER: Duration = Duration::from_secs(10);
/// After a cross-document navigation, a document that reached
/// `interactive` but not `complete` within this long is accepted: lazy
/// subresources (off-screen `loading=lazy` iframes, slow images) must not
/// hold up the crawl.
const INTERACTIVE_GRACE: Duration = Duration::from_millis(1500);
/// A script navigation that shows no sign of starting within this long is
/// retried with `Page.navigate`.
const SCRIPT_NAVIGATION_START_GRACE: Duration = Duration::from_secs(2);
/// Upper bound for one document-state probe while a navigation is pending.
const STATE_PROBE_TIMEOUT: Duration = Duration::from_millis(400);

/// Identity of the document currently in the main frame.
#[derive(Debug, Clone, Deserialize, PartialEq)]
struct DocumentState {
    /// `performance.timeOrigin`: unique per document.
    origin: f64,
    ready: String,
    href: String,
}

impl DocumentState {
    fn is_ready(&self) -> bool {
        self.ready == "complete" || self.ready == "interactive"
    }
}

const DOCUMENT_STATE_JS: &str = "({ origin: (performance && performance.timeOrigin) || 0, ready: String(document.readyState || ''), href: String(location.href || '') })";

impl PageClient {
    pub fn new(page: Page) -> Self {
        Self {
            page,
            script_loads: Arc::new(ScriptLoads::default()),
        }
    }

    pub fn inner(&self) -> &Page {
        &self.page
    }

    /// The tab this page lives in (attribution scope).
    pub fn tab(&self) -> TabKey {
        TabKey::of(&self.page)
    }

    pub async fn enable_domains(&self) -> Result<()> {
        // Network events are required for API mapping and bug detection.
        self.page
            .execute(network::EnableParams::default())
            .await
            .context("enable Network domain")?;

        // Runtime is enabled by default, but explicit is fine.
        self.page
            .enable_runtime()
            .await
            .context("enable Runtime domain")?;

        // Log is enabled by default.
        self.page.enable_log().await.context("enable Log domain")?;

        // DOM is needed for selector queries.
        self.page.enable_dom().await.context("enable DOM domain")?;
        if let Err(err) = self.track_script_loads().await {
            tracing::debug!(error = ?err, "script load tracking unavailable");
        }
        Ok(())
    }

    /// Same-origin script/module requests currently in flight (route chunks
    /// loaded by dynamic `import()`). Zero until [`Self::enable_domains`] ran.
    pub fn pending_script_loads(&self) -> usize {
        let Ok(mut state) = self.script_loads.pending.lock() else {
            return 0;
        };
        state.in_flight()
    }

    async fn track_script_loads(&self) -> Result<()> {
        use std::sync::atomic::Ordering;
        if self.script_loads.tracking.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut started = self
            .page
            .event_listener::<network::EventRequestWillBeSent>()
            .await
            .context("Network.requestWillBeSent listener (script loads)")?;
        let mut finished = self
            .page
            .event_listener::<network::EventLoadingFinished>()
            .await
            .context("Network.loadingFinished listener (script loads)")?;
        let mut failed = self
            .page
            .event_listener::<network::EventLoadingFailed>()
            .await
            .context("Network.loadingFailed listener (script loads)")?;
        let loads = Arc::clone(&self.script_loads);
        tokio::spawn(async move {
            loop {
                // Starts first: a request's start is delivered before its end.
                tokio::select! {
                    biased;
                    ev = started.next() => match ev {
                        Some(ev) => {
                            if matches!(ev.r#type, Some(network::ResourceType::Script))
                                && same_origin(&ev.request.url, &ev.document_url)
                                && let Ok(mut state) = loads.pending.lock()
                            {
                                state.started(ev.request_id.inner().clone());
                            }
                        }
                        None => break,
                    },
                    ev = finished.next() => match ev {
                        Some(ev) => {
                            if let Ok(mut state) = loads.pending.lock() {
                                state.ended(ev.request_id.inner());
                            }
                        }
                        None => break,
                    },
                    ev = failed.next() => match ev {
                        Some(ev) => {
                            if let Ok(mut state) = loads.pending.lock() {
                                state.ended(ev.request_id.inner());
                            }
                        }
                        None => break,
                    },
                }
            }
        });
        Ok(())
    }

    pub async fn set_extra_http_headers(
        &self,
        headers: impl IntoIterator<Item = (String, String)>,
    ) -> Result<()> {
        let headers_map: std::collections::HashMap<String, String> = headers.into_iter().collect();
        let headers_json = serde_json::to_value(headers_map).context("serialize headers")?;
        let headers = network::Headers::new(headers_json);
        self.page
            .execute(network::SetExtraHttpHeadersParams::new(headers))
            .await
            .context("Network.setExtraHTTPHeaders")?;
        Ok(())
    }

    /// Emulate a desktop viewport of `width`x`height` CSS pixels (chromiumoxide
    /// defaults new pages to 800x600, which collapses responsive navigation).
    pub async fn set_viewport(&self, width: u32, height: u32) -> Result<()> {
        if width == 0 || height == 0 {
            return Ok(());
        }
        self.page
            .execute(emulation::SetDeviceMetricsOverrideParams::new(
                width, height, 1.0, false,
            ))
            .await
            .context("Emulation.setDeviceMetricsOverride")?;
        Ok(())
    }

    /// Override the browser's `User-Agent` string for this page via CDP emulation.
    pub async fn set_user_agent(&self, user_agent: &str) -> Result<()> {
        let ua = user_agent.trim();
        if ua.is_empty() {
            return Ok(());
        }
        self.page
            .execute(emulation::SetUserAgentOverrideParams::new(ua.to_string()))
            .await
            .context("Emulation.setUserAgentOverride")?;
        Ok(())
    }

    /// Navigate the main frame to `url` and wait until the new document is
    /// interactive, bounded by `timeout`.
    ///
    /// Cross-document navigations are started from the page
    /// (`location.href = url`) rather than with `Page.navigate`: chromiumoxide
    /// holds a `Page.navigate` until *every* child frame fired `load`, which
    /// never happens for an off-screen `loading=lazy` iframe, and it queues
    /// every later navigation of the page behind that stuck one. The script
    /// navigation is watched here instead: the call returns once a new
    /// document is `complete` (or `interactive` for [`INTERACTIVE_GRACE`]).
    /// When the page cannot start the navigation (no script context), this
    /// falls back to `Page.navigate`, and a timed-out `Page.navigate` is still
    /// accepted when the main frame already shows the new document.
    pub async fn goto_and_wait(&self, url: &str, timeout: Duration) -> Result<()> {
        // A navigation that only changes the fragment is same-document: Chrome
        // applies it immediately, but chromiumoxide's navigation watcher never
        // completes, so `Page.navigate` would sit out the CDP request timeout
        // (~30 s). Set `location.hash` instead; hash routers react to the
        // resulting `hashchange`, and callers settle afterwards.
        let current = self.url().await.ok().flatten();
        if let Some(hash) = current
            .as_deref()
            .and_then(|current| same_document_fragment_target(current, url))
        {
            let hash_json = serde_json::to_string(&hash).context("serialize location.hash")?;
            self.evaluate_json::<bool>(&format!(
                "(() => {{ location.hash = {hash_json}; return true; }})()"
            ))
            .await
            .context("set location.hash")?;
            return Ok(());
        }

        let deadline = Instant::now() + timeout;
        let before = tokio::time::timeout(STATE_PROBE_TIMEOUT, self.document_state())
            .await
            .ok()
            .and_then(Result::ok);
        if let Some(before) = before.as_ref().filter(|b| script_navigable(&b.href)) {
            let url_json = serde_json::to_string(url).context("serialize navigation url")?;
            let statement = format!("window.location.href = {url_json}");
            match self
                .script_navigate(&statement, Some(url), before, deadline)
                .await
            {
                Ok(ScriptNavigation::Done) => return Ok(()),
                Ok(ScriptNavigation::NotStarted) => {
                    tracing::debug!(url, "script navigation did not start; using Page.navigate");
                }
                Err(err) => return Err(err),
            }
        }
        self.cdp_navigate(url, before.as_ref(), deadline, timeout)
            .await
    }

    /// `Page.navigate` (watched by chromiumoxide), then poll readiness.
    async fn cdp_navigate(
        &self,
        url: &str,
        before: Option<&DocumentState>,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let navigated = tokio::time::timeout(
            remaining,
            self.page.execute(cdp_page::NavigateParams::new(url)),
        )
        .await;
        match navigated {
            Ok(result) => {
                result.context("Page.navigate")?;
            }
            Err(_) => {
                // The watcher waits for every child frame's `load`; the page
                // itself may well be usable.
                if let Ok(Ok(state)) =
                    tokio::time::timeout(STATE_PROBE_TIMEOUT, self.document_state()).await
                    && state.is_ready()
                    && before.is_none_or(|b| b.origin != state.origin)
                {
                    tracing::debug!(url, ready = %state.ready, "Page.navigate watcher timed out; document is ready");
                    return Ok(());
                }
                anyhow::bail!("Page.navigate timed out after {}ms", timeout.as_millis());
            }
        }
        while Instant::now() < deadline {
            if let Ok(ready) = self
                .evaluate_json::<bool>(
                    "Boolean(document && (document.readyState === 'complete' || document.readyState === 'interactive'))",
                )
                .await
                && ready
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }

    async fn document_state(&self) -> Result<DocumentState> {
        self.evaluate_json::<DocumentState>(DOCUMENT_STATE_JS).await
    }

    /// Reload the current document (a fresh copy of the view, e.g. to reset
    /// a single-URL app's in-memory state) and wait for it like
    /// [`Self::goto_and_wait`]. Falls back to `Page.reload` when the page
    /// cannot run script.
    pub async fn reload_and_wait(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let before = tokio::time::timeout(STATE_PROBE_TIMEOUT, self.document_state())
            .await
            .ok()
            .and_then(Result::ok);
        if let Some(before) = before.as_ref().filter(|b| script_navigable(&b.href)) {
            match self
                .script_navigate("window.location.reload()", None, before, deadline)
                .await
            {
                Ok(ScriptNavigation::Done) => return Ok(()),
                Ok(ScriptNavigation::NotStarted) => {}
                Err(err) => return Err(err),
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, self.page.reload()).await {
            Ok(result) => {
                result.context("Page.reload")?;
                Ok(())
            }
            Err(_) => {
                if let Ok(Ok(state)) =
                    tokio::time::timeout(STATE_PROBE_TIMEOUT, self.document_state()).await
                    && state.is_ready()
                    && before.as_ref().is_none_or(|b| b.origin != state.origin)
                {
                    return Ok(());
                }
                anyhow::bail!("Page.reload timed out after {}ms", timeout.as_millis())
            }
        }
    }

    /// Start a navigation from the page itself and wait for its document.
    async fn script_navigate(
        &self,
        statement: &str,
        target: Option<&str>,
        before: &DocumentState,
        deadline: Instant,
    ) -> Result<ScriptNavigation> {
        let mut started_loading = self
            .page
            .event_listener::<cdp_page::EventFrameStartedLoading>()
            .await
            .context("Page.frameStartedLoading listener")?;
        let mut stopped_loading = self
            .page
            .event_listener::<cdp_page::EventFrameStoppedLoading>()
            .await
            .context("Page.frameStoppedLoading listener")?;
        let main_frame = self.page.mainframe().await.ok().flatten();
        let is_main = |frame: &cdp_page::FrameId| main_frame.as_ref().is_none_or(|m| m == frame);

        let start = tokio::time::timeout(
            SCRIPT_NAVIGATION_START_GRACE,
            self.evaluate_json::<bool>(&format!(
                "(() => {{ try {{ {statement}; return true; }} catch (_) {{ return false; }} }})()"
            )),
        )
        .await;
        // A start call that does not answer is a navigation already under way.
        if matches!(start, Ok(Ok(false)) | Ok(Err(_))) {
            return Ok(ScriptNavigation::NotStarted);
        }

        let navigation_started = Instant::now();
        let mut loading = false;
        let mut stopped = false;
        let mut interactive_since: Option<Instant> = None;
        let mut last: Option<DocumentState> = None;
        while Instant::now() < deadline {
            // Drain lifecycle events without blocking.
            while let Some(Some(ev)) = futures::FutureExt::now_or_never(started_loading.next()) {
                if is_main(&ev.frame_id) {
                    loading = true;
                }
            }
            while let Some(Some(ev)) = futures::FutureExt::now_or_never(stopped_loading.next()) {
                if is_main(&ev.frame_id) && loading {
                    stopped = true;
                }
            }
            // Chrome holds `Runtime.evaluate` on a document whose navigation
            // is pending until the new document commits: bound each probe.
            let probe_timeout = deadline
                .saturating_duration_since(Instant::now())
                .min(STATE_PROBE_TIMEOUT);
            let probe = tokio::time::timeout(probe_timeout, self.document_state()).await;
            if let Ok(Ok(state)) = probe {
                if state.origin != before.origin {
                    if state.ready == "complete" {
                        return Ok(ScriptNavigation::Done);
                    }
                    if state.ready == "interactive" {
                        let since = *interactive_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= INTERACTIVE_GRACE {
                            return Ok(ScriptNavigation::Done);
                        }
                    }
                } else if target.is_some_and(|target| {
                    state.href != before.href && same_document_target(&state.href, target)
                }) {
                    // A router intercepted the navigation (Navigation API).
                    return Ok(ScriptNavigation::Done);
                } else if stopped {
                    // Loading ended without a new document (204, download):
                    // `Page.navigate` reports these as successful too.
                    return Ok(ScriptNavigation::Done);
                } else if !loading && navigation_started.elapsed() >= SCRIPT_NAVIGATION_START_GRACE
                {
                    return Ok(ScriptNavigation::NotStarted);
                }
                last = Some(state);
            } else if probe.is_err() {
                loading = true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        match last {
            Some(state) if state.origin != before.origin && state.is_ready() => {
                Ok(ScriptNavigation::Done)
            }
            _ => anyhow::bail!(
                "navigation to {} timed out after {}ms",
                target.unwrap_or("the current URL"),
                deadline
                    .saturating_duration_since(navigation_started)
                    .as_millis()
                    .max(1)
            ),
        }
    }

    pub async fn url(&self) -> Result<Option<String>> {
        self.page.url().await.context("get page url")
    }

    pub async fn title(&self) -> Result<Option<String>> {
        // Page.title is implemented as DOM query internally.
        let title: Option<String> = self
            .page
            .evaluate("document.title")
            .await
            .context("evaluate document.title")?
            .into_value()
            .ok();
        Ok(title)
    }

    pub async fn evaluate_json<T: DeserializeOwned>(&self, expression: &str) -> Result<T> {
        let v = self
            .page
            .evaluate(expression)
            .await
            .with_context(|| format!("evaluate expression: {expression}"))?
            .into_value()
            .context("decode evaluation result")?;
        Ok(v)
    }

    pub async fn screenshot_png(&self, full_page: bool) -> Result<Vec<u8>> {
        let params = ScreenshotParams::builder()
            .format(cdp_page::CaptureScreenshotFormat::Png)
            .full_page(full_page)
            .build();
        self.page
            .screenshot(params)
            .await
            .context("take screenshot")
    }
}

enum ScriptNavigation {
    Done,
    NotStarted,
}

/// Documents a script navigation can start from: web pages and the blank
/// page of a fresh tab (not `chrome-error://` or other internal pages).
fn script_navigable(href: &str) -> bool {
    href == "about:blank" || href.starts_with("http://") || href.starts_with("https://")
}

/// `href` (the page's URL after a navigation) is `target`, ignoring a
/// trailing slash on the path.
fn same_document_target(href: &str, target: &str) -> bool {
    let (Ok(a), Ok(b)) = (url::Url::parse(href), url::Url::parse(target)) else {
        return href == target;
    };
    a.origin() == b.origin()
        && a.path().trim_end_matches('/') == b.path().trim_end_matches('/')
        && a.query() == b.query()
        && a.fragment() == b.fragment()
}

/// Request and document share an origin.
fn same_origin(request_url: &str, document_url: &str) -> bool {
    match (url::Url::parse(request_url), url::Url::parse(document_url)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

/// When `target` differs from `current` only in its fragment, return the
/// target fragment (without `#`). Such navigations are same-document: Chrome
/// does not reload the page and fires `hashchange` instead.
fn same_document_fragment_target(current: &str, target: &str) -> Option<String> {
    let mut current = url::Url::parse(current).ok()?;
    let mut target = url::Url::parse(target).ok()?;
    if !matches!(current.scheme(), "http" | "https") {
        return None;
    }
    let fragment = target.fragment()?.to_string();
    current.set_fragment(None);
    target.set_fragment(None);
    (current == target).then_some(fragment)
}

#[cfg(test)]
mod tests {
    use super::{
        same_document_fragment_target, same_document_target, same_origin, script_navigable,
    };

    #[test]
    fn script_load_ends_seen_before_their_start_do_not_leak() {
        let mut state = super::ScriptLoadState::default();
        state.started("a".into());
        assert_eq!(state.in_flight(), 1);
        state.ended("a");
        assert_eq!(state.in_flight(), 0);
        // End delivered before start (separate event channels).
        state.ended("b");
        state.started("b".into());
        assert_eq!(state.in_flight(), 0);
        // Ends of requests that were never scripts are only remembered.
        state.ended("img");
        assert_eq!(state.in_flight(), 0);
    }

    #[test]
    fn script_navigation_starts_only_from_web_or_blank_pages() {
        assert!(script_navigable("about:blank"));
        assert!(script_navigable("http://127.0.0.1:3000/"));
        assert!(!script_navigable("chrome-error://chromewebdata/"));
        assert!(!script_navigable("data:text/html,x"));
    }

    #[test]
    fn same_document_target_ignores_trailing_slash_only() {
        assert!(same_document_target("http://x.test/a/", "http://x.test/a"));
        assert!(!same_document_target(
            "http://x.test/a?q=1",
            "http://x.test/a"
        ));
        assert!(!same_document_target("http://x.test/a", "http://y.test/a"));
        assert!(same_origin(
            "http://x.test/src/a.js",
            "http://x.test/receiving"
        ));
        assert!(!same_origin("https://maps.example/x.js", "http://x.test/"));
    }

    #[test]
    fn fragment_only_change_is_same_document() {
        assert_eq!(
            same_document_fragment_target("http://x.test/#/cart", "http://x.test/#/"),
            Some("/".to_string())
        );
        assert_eq!(
            same_document_fragment_target("http://x.test/app", "http://x.test/app#/settings"),
            Some("/settings".to_string())
        );
    }

    #[test]
    fn path_query_or_fragment_removal_is_a_real_navigation() {
        // Removing the fragment reloads the document.
        assert_eq!(
            same_document_fragment_target("http://x.test/#/cart", "http://x.test/"),
            None
        );
        assert_eq!(
            same_document_fragment_target("http://x.test/a#/x", "http://x.test/b#/x"),
            None
        );
        assert_eq!(
            same_document_fragment_target("http://x.test/?q=1#/x", "http://x.test/?q=2#/x"),
            None
        );
        // A fresh tab is never same-document with an http target.
        assert_eq!(
            same_document_fragment_target("about:blank", "about:blank#/x"),
            None
        );
    }
}
