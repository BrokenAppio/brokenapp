use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chromiumoxide::cdp::browser_protocol::emulation;
use chromiumoxide::cdp::browser_protocol::fetch;
use chromiumoxide::cdp::browser_protocol::network;
use chromiumoxide::cdp::browser_protocol::page as cdp_page;
use chromiumoxide::cdp::js_protocol::runtime;
use chromiumoxide::page::Page;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use url::Url;
use uuid::Uuid;

use crate::browser::TabKey;
use crate::config::{ScanConfig, WriteGuardMode};
use crate::network::path_parameterizer::path_to_template;
use crate::safety::{WriteRequest, WriteVerdict};
use crate::types::api::{
    ApiEndpoint, EndpointKey, ErrorResponse, HttpMethod, HttpRequestLog, HttpResponseLog,
    RequestTrace, TrafficEntry, WriteGuardAction,
};
use crate::types::dom::InteractionRef;

/// Page ids that `crate::session::auth` gives the pages it drives through the
/// user-configured login (`auth_form_*`, `auth_manual_*`, `auth_google_oauth_*`).
/// These pages carry credentials; their traffic is omitted from artifacts.
/// Write authorization is supplied separately, for individual login endpoints.
const AUTH_PAGE_ID_PREFIX: &str = "auth_";

/// The explicitly authorized operations of one login page. App requests on
/// the landing page retain the ordinary write guard, including background saves.
#[derive(Clone, Default)]
pub struct AuthWriteScope {
    urls: Arc<Mutex<Vec<Url>>>,
    auth_origin: Arc<Mutex<Option<Url>>>,
    google_identity: bool,
}

impl AuthWriteScope {
    pub fn allow_url(&self, url: &str) {
        if let Ok(url) = Url::parse(url) {
            let mut urls = self.urls.lock().unwrap_or_else(|p| p.into_inner());
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }

    pub fn allow_auth_origin(&self, login_url: &str) {
        if let Ok(url) = Url::parse(login_url) {
            let mut auth_origin = self.auth_origin.lock().unwrap_or_else(|p| p.into_inner());
            *auth_origin = Some(url);
        }
    }

    pub fn clear_auth_origin(&self) {
        let mut auth_origin = self.auth_origin.lock().unwrap_or_else(|p| p.into_inner());
        *auth_origin = None;
    }

    pub fn google_identity(mut self) -> Self {
        self.google_identity = true;
        self
    }

    fn allows(&self, method: &str, url: &str) -> bool {
        if !method.eq_ignore_ascii_case("POST") {
            return false;
        }
        let Ok(url) = Url::parse(url) else {
            return false;
        };
        if crate::safety::is_session_ending_url(url.as_str()) {
            return false;
        }
        if self.google_identity
            && url.scheme() == "https"
            && url.host_str() == Some("accounts.google.com")
        {
            return true;
        }
        {
            let mut urls = self.urls.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(position) = urls.iter().position(|allowed| {
                allowed.origin() == url.origin()
                    && allowed.path() == url.path()
                    && allowed.query() == url.query()
            }) {
                // One configured submission, not a reusable landing-page exception.
                urls.remove(position);
                return true;
            }
        }
        let auth_origin = self.auth_origin.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(login_url) = auth_origin.as_ref()
            && login_url.origin() == url.origin()
            && is_auth_submission_path(url.path(), login_url.path())
        {
            return true;
        }
        false
    }
}

fn is_auth_submission_path(path: &str, login_path: &str) -> bool {
    let path_lower = path.to_ascii_lowercase();
    let login_lower = login_path.to_ascii_lowercase();
    fn norm(p: &str) -> &str {
        let trimmed = p.trim_end_matches('/');
        if trimmed.is_empty() { "/" } else { trimmed }
    }
    if norm(&path_lower) == norm(&login_lower) {
        return true;
    }
    const AUTH_SEGMENTS: &[&str] = &[
        "auth",
        "login",
        "signin",
        "sign-in",
        "sign_in",
        "oauth",
        "oauth2",
        "callback",
        "session",
        "sessions",
        "token",
        "credentials",
        "verify",
    ];
    path_lower
        .split('/')
        .filter(|seg| !seg.is_empty())
        .any(|seg| AUTH_SEGMENTS.contains(&seg))
}

fn is_auth_trace(trace: Option<&RequestTrace>) -> bool {
    trace
        .and_then(|t| t.page_id.as_deref())
        .is_some_and(|id| id.starts_with(AUTH_PAGE_ID_PREFIX))
}

/// How long a write-guarded request id is remembered so its trailing Network
/// events (`loadingFailed`, `responseReceived`, ...) are ignored.
const GUARDED_ID_TTL: Duration = Duration::from_secs(120);

/// A native JS dialog (`alert`/`confirm`/`prompt`/`beforeunload`) the page
/// raised, and how the scanner answered it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeDialog {
    /// `alert`, `confirm`, `prompt`, or `beforeunload`.
    pub kind: String,
    pub message: String,
    /// URL of the frame that opened the dialog.
    pub url: String,
    /// `true` when accepted (write guard on), `false` when dismissed.
    pub accepted: bool,
    /// Interaction that was current when the dialog opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<InteractionRef>,
    /// Action id of that interaction, when it was registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

impl NativeDialog {
    /// Compact form for `InteractionRecord::native_dialog`, e.g.
    /// `confirm: Archive this item?` (message capped at 200 chars).
    pub fn summary(&self) -> String {
        const MAX_CHARS: usize = 200;
        let message = self.message.trim();
        let mut out = format!("{}: ", self.kind);
        if message.chars().count() > MAX_CHARS {
            out.extend(message.chars().take(MAX_CHARS));
            out.push('…');
        } else {
            out.push_str(message);
        }
        out
    }
}

#[derive(Debug, Clone)]
struct PendingRequest {
    started_at: Instant,
    trace: Option<RequestTrace>,
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    has_post_data: bool,
    post_data: Option<String>,
    response: Option<HttpResponseLog>,
    triggered_by: Option<InteractionRef>,
    preparation: bool,
    /// Infrastructure/stream/telemetry request (SSE, Next.js HMR/dev-tools,
    /// CSP/Reporting API beacons) that must never be attributed to a UI control
    /// or folded into application endpoints.
    ignore_attribution: bool,
}

/// Timeout for CDP body/post-data fetches inside the per-tab network event
/// loop so an evicted or slow response body can never stall `Fetch.requestPaused`
/// on parallel tabs.
const CDP_BODY_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Build CDP `Fetch.enable` parameters.
///
/// When the private-network SSRF egress guard is enabled (`egress_enabled = true`),
/// intercept all resource types (`url_pattern = "*"`) so cross-origin image/script
/// probes stay blocked. When only the local write guard is active
/// (`egress_enabled = false`), scope interception to resource types that can
/// perform state-changing requests and omit read-only static assets (`Script`,
/// `Stylesheet`, `Image`, `Media`, `Font`, `Manifest`, `TextTrack`) so dev
/// servers (e.g. Next.js with 25+ static chunks) load at full native parallel
/// speed without CDP pause round-trips.
fn fetch_enable_params(egress_enabled: bool) -> fetch::EnableParams {
    if egress_enabled {
        return fetch::EnableParams::builder()
            .pattern(fetch::RequestPattern::builder().url_pattern("*").build())
            .build();
    }
    const WRITE_GUARD_RESOURCE_TYPES: &[network::ResourceType] = &[
        network::ResourceType::Document,
        network::ResourceType::Xhr,
        network::ResourceType::Fetch,
        network::ResourceType::EventSource,
        network::ResourceType::Ping,
        network::ResourceType::Other,
    ];
    fetch::EnableParams::builder()
        .patterns(WRITE_GUARD_RESOURCE_TYPES.iter().cloned().map(|rt| {
            fetch::RequestPattern::builder()
                .url_pattern("*")
                .resource_type(rt)
                .build()
        }))
        .build()
}

/// True when `url` points to a static asset path (`.js`, `.mjs`, `.css`, `.map`,
/// `.woff`, `.woff2`, `.png`, `.svg`, `.ico`, `/_next/static/`, etc.) whose body
/// should never be fetched over CDP.
fn is_static_asset_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let lower = parsed.path().to_ascii_lowercase();
    crate::network::filters::looks_like_static_asset_path(&lower)
        || lower.starts_with("/_next/static/")
        || lower.ends_with(".mjs")
}

/// Whether `on_loading_finished` should invoke CDP `Network.getResponseBody`.
fn should_fetch_response_body(url: &str, mime_type: Option<&str>) -> bool {
    if is_static_asset_url(url) {
        return false;
    }
    mime_type
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("application/json")
}

/// Returns `true` for SSE streams, dev-server HMR/error-overlay requests, and
/// browser CSP/Reporting API beacons that must never be attributed to UI
/// controls or treated as application endpoints.
fn should_ignore_from_attribution(
    url: &str,
    headers: &BTreeMap<String, String>,
    resource_type: Option<&network::ResourceType>,
) -> bool {
    if resource_type.is_some_and(|rt| {
        let kind = rt.as_ref();
        kind.eq_ignore_ascii_case("eventsource") || kind.eq_ignore_ascii_case("cspviolationreport")
    }) {
        return true;
    }
    if crate::network::filters::is_sse_content_type(header_value(headers, "accept")) {
        return true;
    }
    let req_ct = header_value(headers, "content-type");
    if let Ok(parsed) = Url::parse(url) {
        let path = parsed.path();
        if crate::network::filters::is_dev_tool_or_hmr_path(path)
            || crate::network::filters::is_csp_or_telemetry_report(path, req_ct)
        {
            return true;
        }
    } else if req_ct.is_some_and(crate::network::filters::is_csp_or_telemetry_content_type) {
        return true;
    }
    false
}

/// Returns `true` when a completed traffic entry is SSE, dev-tool/HMR, or a
/// browser CSP/telemetry beacon and must be excluded from endpoint aggregation
/// and control attribution.
fn should_ignore_from_endpoints(entry: &TrafficEntry) -> bool {
    if should_ignore_from_attribution(&entry.request.url, &entry.request.headers, None) {
        return true;
    }
    entry
        .response
        .as_ref()
        .is_some_and(|r| crate::network::filters::is_sse_content_type(r.mime_type.as_deref()))
}

#[derive(Debug, Clone)]
struct ResponseExtraInfo {
    status: u16,
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct RateLimitObservation {
    at: Instant,
    retry_after: Option<Duration>,
}

/// Selector of the explorer's page-load marker interaction (on-load requests).
const PAGE_LOAD_SELECTOR: &str = "__page_load__";
/// Stamped by the page instrumentation on same-origin requests started after
/// an action moved the page to another client-side route (pushState or
/// popstate to another path/query): the new route's load traffic, never
/// attributed to the action.
const ROUTE_LOAD_HEADER: &str = "x-brokenapp-route-load";
/// Same-origin requests started by synthetic target preparation, not a UI action.
const PREPARATION_HEADER: &str = "x-brokenapp-preparation";
/// CDP `Runtime.addBinding` name used by the in-page WebSocket write guard to
/// report intercepted mutating frames immediately.
const WS_GUARD_BINDING_NAME: &str = "__brokenappWsGuardReport";

/// Structured error observed on a WebSocket connection (either a CDP
/// `Network.webSocketFrameError` or a received RPC/GraphQL/JSON error frame).
#[derive(Debug, Clone)]
pub struct WsErrorEvent {
    pub url: String,
    pub message: String,
    pub triggered_by: Option<InteractionRef>,
    pub action_id: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct WsGuardBindingPayload {
    url: String,
    #[serde(default)]
    op: Option<String>,
    #[serde(default)]
    payload: Option<String>,
    #[serde(default, rename = "actionId")]
    action_id: Option<String>,
    #[serde(default, rename = "routeLoad")]
    route_load: bool,
    #[serde(default)]
    preparing: bool,
}

/// Attribution state of one tab ([`TabKey`]). Requests, dialogs and
/// action ids are only ever matched against the state of the tab they
/// happened in.
#[derive(Debug, Default)]
struct TabAttribution {
    preparation_depth: usize,
    /// Interaction being exercised on this tab.
    current: Option<InteractionRef>,
    /// Main-frame document epoch when `current` was set.
    current_epoch: u64,
    /// Bumped on every main-frame document request of this tab (navigation,
    /// reload, restore). Requests of a later document than the one an
    /// interaction started in are that document's own load traffic
    /// (bootstrap calls, session refreshes), not the interaction's.
    document_epoch: u64,
    /// Recent interactions with the main-frame document epoch they started in.
    recent: VecDeque<(Instant, InteractionRef, u64)>,
    /// Most recently registered action (id, interaction). Cross-origin and
    /// header-less requests (beacons, form posts) get their `trace.action_id`
    /// from it when they are attributed to the same interaction.
    latest_action: Option<(String, InteractionRef)>,
    native_dialogs: Vec<NativeDialog>,
    /// Action ids on this tab that triggered at least one write-guarded HTTP
    /// or WebSocket operation.
    guarded_actions: HashSet<String>,
    /// Concise WebSocket error messages attributed to each `action_id` on this tab.
    action_ws_errors: HashMap<String, Vec<String>>,
}

/// Suppress implicit attribution only on the page being prepared. Drop also
/// covers a cancelled preparation future; registered explicit action ids survive.
pub(crate) struct PreparationAttribution<'a> {
    network: &'a NetworkInterceptor,
    tab: TabKey,
}

impl Drop for PreparationAttribution<'_> {
    fn drop(&mut self) {
        self.network.with_tab(&self.tab, |state| {
            state.preparation_depth = state.preparation_depth.saturating_sub(1);
            state.current = None;
            state.recent.clear();
            state.latest_action = None;
        });
    }
}

impl TabAttribution {
    fn set_current(&mut self, interaction: Option<InteractionRef>) {
        let epoch = self.document_epoch;
        if let Some(ref i) = interaction {
            // Keep a small ring buffer of recent interactions. This enables
            // best-effort attribution for requests that start shortly after the
            // explorer clears the current interaction (debounced actions, delayed
            // mutations, cross-origin calls where we can't stamp headers, etc).
            self.recent.push_back((Instant::now(), i.clone(), epoch));
            while self.recent.len() > 50 {
                self.recent.pop_front();
            }
        }
        self.current_epoch = epoch;
        self.current = interaction;
    }

    /// Action id of the most recently registered action, when `interaction`
    /// is that action's interaction.
    fn action_id_for(&self, interaction: &InteractionRef) -> Option<String> {
        self.latest_action
            .as_ref()
            .filter(|(_, i)| i == interaction)
            .map(|(id, _)| id.clone())
    }
}

pub struct NetworkInterceptor {
    endpoints: DashMap<EndpointKey, ApiEndpoint>,
    /// In-flight requests by [`request_key`] (tab-scoped CDP request id).
    pending: DashMap<String, PendingRequest>,
    /// Action id -> (tab it was registered on, interaction).
    action_to_interaction: DashMap<String, (TabKey, InteractionRef)>,
    rate_limits: Mutex<VecDeque<RateLimitObservation>>,
    rate_limit_total: AtomicUsize,
    request_extra_headers: DashMap<String, BTreeMap<String, String>>,
    response_extra_info: DashMap<String, ResponseExtraInfo>,
    error_traffic: tokio::sync::Mutex<Vec<TrafficEntry>>,
    /// Open WebSocket connections keyed by tab-scoped CDP request id -> WS URL.
    ws_connections: DashMap<String, String>,
    /// Observed WebSocket protocol or RPC error events awaiting bug conversion.
    ws_errors: tokio::sync::Mutex<Vec<WsErrorEvent>>,
    /// Attribution state per tab. The shared lane ([`TabKey::shared`])
    /// always exists; isolated tabs live from [`Self::attach_isolated`]
    /// until their handle is dropped.
    tabs: Mutex<HashMap<TabKey, TabAttribution>>,
    writer: Option<Arc<NetworkLogWriter>>,
    egress: Option<crate::network::egress::EgressBlocker>,
    egress_blocked_total: AtomicUsize,
    allowed_hosts_blocked_total: AtomicUsize,
    rate_cap_gate: tokio::sync::Mutex<Option<Instant>>,
    /// Origin of the scan target (`http://localhost:3000`). Requests to other
    /// origins keep their origin in the endpoint key. Set explicitly via
    /// [`Self::set_first_party_origin`], otherwise learned from the first
    /// document request.
    first_party_origin: RwLock<Option<String>>,
    /// Tab-scoped CDP request ids the write guard answered, with the time
    /// they were guarded. Their Network events are ignored (the guard wrote
    /// the row).
    guarded_requests: DashMap<String, Instant>,
    write_guard_total: AtomicUsize,
    cfg: ScanConfig,
}

pub struct NetworkInterceptorHandle {
    task: tokio::task::JoinHandle<()>,
    /// Isolated tab whose attribution state is dropped with the handle.
    tab: Option<(Weak<NetworkInterceptor>, TabKey)>,
}

impl Drop for NetworkInterceptorHandle {
    fn drop(&mut self) {
        self.task.abort();
        if let Some((interceptor, tab)) = self.tab.take()
            && let Some(interceptor) = interceptor.upgrade()
        {
            interceptor.release_tab(&tab);
        }
    }
}

/// Key of a request in the per-request maps: the CDP request id, prefixed
/// with the tab for isolated tabs (request ids are per target).
fn request_key(tab: &TabKey, request_id: &str) -> String {
    if tab.is_shared() {
        request_id.to_string()
    } else {
        format!("{}/{request_id}", tab.as_str())
    }
}

impl NetworkInterceptor {
    pub fn new(
        cfg: ScanConfig,
        writer: Option<Arc<NetworkLogWriter>>,
        block_private_egress: bool,
    ) -> Self {
        let mut tabs = HashMap::new();
        tabs.insert(TabKey::shared(), TabAttribution::default());
        Self {
            endpoints: DashMap::new(),
            pending: DashMap::new(),
            action_to_interaction: DashMap::new(),
            rate_limits: Mutex::new(VecDeque::new()),
            rate_limit_total: AtomicUsize::new(0),
            request_extra_headers: DashMap::new(),
            response_extra_info: DashMap::new(),
            error_traffic: tokio::sync::Mutex::new(Vec::new()),
            ws_connections: DashMap::new(),
            ws_errors: tokio::sync::Mutex::new(Vec::new()),
            tabs: Mutex::new(tabs),
            writer,
            egress: block_private_egress
                .then_some(crate::network::egress::EgressBlocker::default()),
            egress_blocked_total: AtomicUsize::new(0),
            allowed_hosts_blocked_total: AtomicUsize::new(0),
            rate_cap_gate: tokio::sync::Mutex::new(None),
            first_party_origin: RwLock::new(None),
            guarded_requests: DashMap::new(),
            write_guard_total: AtomicUsize::new(0),
            cfg,
        }
    }

    /// Run `f` on the attribution state of `tab`; `None` when the tab is
    /// not attached (anymore).
    fn with_tab<R>(&self, tab: &TabKey, f: impl FnOnce(&mut TabAttribution) -> R) -> Option<R> {
        let mut tabs = self.tabs.lock().unwrap_or_else(|p| p.into_inner());
        tabs.get_mut(tab).map(f)
    }

    /// Start keeping attribution state for an isolated tab.
    fn register_tab(&self, tab: &TabKey) {
        self.tabs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(tab.clone())
            .or_default();
    }

    /// Forget an isolated tab: its attribution state, its action ids, and
    /// requests that never finished. Its event loop is gone, so nothing can
    /// refer to them anymore.
    fn release_tab(&self, tab: &TabKey) {
        if tab.is_shared() {
            return;
        }
        self.tabs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(tab);
        self.action_to_interaction.retain(|_, (t, _)| t != tab);
        let prefix = request_key(tab, "");
        self.pending.retain(|k, _| !k.starts_with(&prefix));
        self.request_extra_headers
            .retain(|k, _| !k.starts_with(&prefix));
        self.response_extra_info
            .retain(|k, _| !k.starts_with(&prefix));
        self.ws_connections.retain(|k, _| !k.starts_with(&prefix));
    }

    /// Number of tabs with attribution state (the shared lane included).
    pub fn tracked_tab_count(&self) -> usize {
        self.tabs.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Effective write-guard mode (`scan.write_guard.mode`).
    pub fn write_guard_mode(&self) -> WriteGuardMode {
        self.cfg.write_guard.mode
    }

    /// `true` when state-changing requests are intercepted (mode != off).
    pub fn write_guard_active(&self) -> bool {
        self.cfg.write_guard.mode != WriteGuardMode::Off
    }

    /// Number of state-changing requests the write guard blocked or stubbed.
    pub fn guarded_write_count(&self) -> usize {
        self.write_guard_total.load(Ordering::Relaxed)
    }

    /// Declare the scan target's origin. Requests to any other origin keep
    /// their origin in endpoint keys (`POST https://x.supabase.co/rest/v1/cart`).
    pub fn set_first_party_origin(&self, url: &Url) {
        let origin = url.origin();
        if !origin.is_tuple() {
            return;
        }
        let mut guard = self
            .first_party_origin
            .write()
            .unwrap_or_else(|p| p.into_inner());
        *guard = Some(origin.ascii_serialization());
    }

    fn first_party_origin(&self) -> Option<String> {
        self.first_party_origin
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn learn_first_party_origin(&self, document_url: &str) {
        let Ok(url) = Url::parse(document_url) else {
            return;
        };
        if !matches!(url.scheme(), "http" | "https") {
            return;
        }
        let mut guard = self
            .first_party_origin
            .write()
            .unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(url.origin().ascii_serialization());
        }
    }

    fn is_cross_origin(&self, url: &str) -> bool {
        let Some(first_party) = self.first_party_origin() else {
            return false;
        };
        Url::parse(url)
            .map(|u| u.origin().ascii_serialization() != first_party)
            .unwrap_or(false)
    }

    /// Action id of the most recently registered action on `tab`, when
    /// `interaction` is that action's interaction.
    fn action_id_for(&self, tab: &TabKey, interaction: &InteractionRef) -> Option<String> {
        self.with_tab(tab, |state| state.action_id_for(interaction))
            .flatten()
    }

    /// Cursor for [`Self::native_dialogs_since`] (shared lane).
    pub fn native_dialog_cursor(&self) -> usize {
        self.native_dialog_cursor_on(&TabKey::shared())
    }

    /// Cursor for [`Self::native_dialogs_since_on`]: take it before an
    /// action, read the dialogs the action raised on `tab` afterwards.
    pub fn native_dialog_cursor_on(&self, tab: &TabKey) -> usize {
        self.with_tab(tab, |state| state.native_dialogs.len())
            .unwrap_or(0)
    }

    /// Native dialogs raised since `cursor` (shared lane), plus the next cursor.
    pub fn native_dialogs_since(&self, cursor: usize) -> (Vec<NativeDialog>, usize) {
        self.native_dialogs_since_on(&TabKey::shared(), cursor)
    }

    /// Native dialogs `tab` raised since `cursor`, plus the next cursor.
    pub fn native_dialogs_since_on(
        &self,
        tab: &TabKey,
        cursor: usize,
    ) -> (Vec<NativeDialog>, usize) {
        self.with_tab(tab, |state| {
            let items = state
                .native_dialogs
                .get(cursor..)
                .map(<[_]>::to_vec)
                .unwrap_or_default();
            (items, state.native_dialogs.len())
        })
        .unwrap_or((Vec::new(), cursor))
    }

    /// The most recent native dialog on the shared lane, if any.
    pub fn last_native_dialog(&self) -> Option<NativeDialog> {
        self.with_tab(&TabKey::shared(), |state| {
            state.native_dialogs.last().cloned()
        })
        .flatten()
    }

    fn is_guarded_request(&self, request_id: &str) -> bool {
        self.guarded_requests.contains_key(request_id)
    }

    fn mark_guarded(&self, request_id: &str) {
        let now = Instant::now();
        if self.guarded_requests.len() >= 256 {
            self.guarded_requests
                .retain(|_, at| now.duration_since(*at) <= GUARDED_ID_TTL);
        }
        self.guarded_requests.insert(request_id.to_string(), now);
    }

    /// Count recent HTTP 429 (Too Many Requests) responses observed by the
    /// interceptor within `window`.
    pub fn recent_rate_limit_count(&self, window: Duration) -> usize {
        let now = Instant::now();
        let mut guard = self
            .rate_limits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_rate_limit_events(&mut guard, now);
        guard
            .iter()
            .filter(|ev| now.duration_since(ev.at) <= window)
            .count()
    }

    /// Total number of HTTP 429 responses observed since the interceptor was created.
    pub fn rate_limit_total(&self) -> usize {
        self.rate_limit_total.load(Ordering::Relaxed)
    }

    /// Most recently observed `Retry-After` value from a 429 response, if any.
    pub fn last_rate_limit_retry_after(&self) -> Option<Duration> {
        let now = Instant::now();
        let mut guard = self
            .rate_limits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_rate_limit_events(&mut guard, now);
        guard.back().and_then(|ev| ev.retry_after)
    }

    fn record_rate_limit_event(&self, retry_after: Option<Duration>) {
        let now = Instant::now();
        self.rate_limit_total.fetch_add(1, Ordering::Relaxed);
        let mut guard = self
            .rate_limits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.push_back(RateLimitObservation {
            at: now,
            retry_after,
        });
        Self::prune_rate_limit_events(&mut guard, now);
    }

    fn prune_rate_limit_events(events: &mut VecDeque<RateLimitObservation>, now: Instant) {
        const MAX_EVENTS: usize = 256;
        const MAX_AGE: Duration = Duration::from_secs(30 * 60);

        while events.len() > MAX_EVENTS {
            events.pop_front();
        }

        while let Some(front) = events.front() {
            if now.duration_since(front.at) > MAX_AGE {
                events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Set the interaction being exercised on the shared lane (pages
    /// attached with [`Self::attach`]: auth flows, mutation replay).
    pub async fn set_current_interaction(&self, interaction: Option<InteractionRef>) {
        self.set_current_interaction_on(&TabKey::shared(), interaction);
    }

    /// Set the interaction being exercised on `tab`. Requests, dialogs and
    /// action ids of other tabs are never attributed to it.
    pub fn set_current_interaction_on(&self, tab: &TabKey, interaction: Option<InteractionRef>) {
        if self
            .with_tab(tab, |state| state.set_current(interaction))
            .is_none()
        {
            tracing::debug!(tab = %tab, "interaction set on a tab that is not attached");
        }
    }

    /// [`Self::forget_recent_interactions_on`] for the shared lane.
    pub async fn forget_recent_interactions(&self) {
        self.forget_recent_interactions_on(&TabKey::shared());
    }

    /// Forget `tab`'s recent interactions so nothing that starts from now on
    /// (a restore navigation, a reload, a replayed click) is attributed to
    /// them through the time-window fallback. Explicit action ids still map.
    pub fn forget_recent_interactions_on(&self, tab: &TabKey) {
        self.with_tab(tab, |state| {
            state.recent.clear();
            state.latest_action = None;
        });
    }

    pub(crate) fn preparation_scope_on(&self, tab: &TabKey) -> PreparationAttribution<'_> {
        self.with_tab(tab, |state| {
            state.preparation_depth += 1;
            state.current = None;
            state.recent.clear();
            state.latest_action = None;
        });
        PreparationAttribution {
            network: self,
            tab: tab.clone(),
        }
    }

    /// [`Self::register_action_on`] for the shared lane.
    pub fn register_action(&self, action_id: impl Into<String>, interaction: InteractionRef) {
        self.register_action_on(&TabKey::shared(), action_id, interaction);
    }

    /// Register a short-lived UI action id to interaction mapping on `tab`.
    ///
    /// The browser-side instrumentation stamps `x-brokenapp-action-id` on
    /// same-origin fetch/XHR calls. We use this table to attribute delayed
    /// requests back to the originating interaction even after the explorer has
    /// cleared the current interaction. Only requests of the same tab map.
    pub fn register_action_on(
        &self,
        tab: &TabKey,
        action_id: impl Into<String>,
        interaction: InteractionRef,
    ) {
        let action_id = action_id.into();
        self.action_to_interaction
            .insert(action_id.clone(), (tab.clone(), interaction.clone()));
        self.with_tab(tab, |state| {
            state.latest_action = Some((action_id, interaction));
        });
    }

    /// The interaction registered for `action_id`, when it was registered on
    /// `tab`: a stamp seen on another tab's request never maps.
    fn action_interaction(&self, tab: &TabKey, action_id: &str) -> Option<InteractionRef> {
        self.action_to_interaction
            .get(action_id)
            .filter(|entry| entry.0 == *tab)
            .map(|entry| entry.1.clone())
    }

    /// Remap interaction view IDs stored in network state. This is used when we
    /// tag requests during navigation with a temporary view id before the final
    /// fingerprint-based view id is known.
    pub async fn remap_interaction_view(&self, from_view: &str, to_view: &str) {
        if from_view == to_view {
            return;
        }

        for mut ep in self.endpoints.iter_mut() {
            let v = ep.value_mut();
            for t in &mut v.triggered_by {
                if t.view == from_view {
                    t.view = to_view.to_string();
                }
            }
        }

        for mut p in self.pending.iter_mut() {
            let v = p.value_mut();
            if let Some(ref mut t) = v.triggered_by {
                if t.view == from_view {
                    t.view = to_view.to_string();
                }
            }
        }

        {
            let mut guard = self.error_traffic.lock().await;
            for e in guard.iter_mut() {
                if let Some(ref mut t) = e.triggered_by {
                    if t.view == from_view {
                        t.view = to_view.to_string();
                    }
                }
            }
        }

        let mut tabs = self.tabs.lock().unwrap_or_else(|p| p.into_inner());
        for state in tabs.values_mut() {
            if let Some(ref mut t) = state.current
                && t.view == from_view
            {
                t.view = to_view.to_string();
            }
        }
    }

    /// Drop (forget) any interaction attribution for a given view id. This is
    /// primarily used when a navigation fails after we tagged in-flight
    /// requests with a temporary load marker view id.
    pub async fn drop_interaction_view(&self, view_id: &str) {
        for mut ep in self.endpoints.iter_mut() {
            let v = ep.value_mut();
            v.triggered_by.retain(|t| t.view != view_id);
        }

        for mut p in self.pending.iter_mut() {
            let v = p.value_mut();
            if let Some(ref t) = v.triggered_by {
                if t.view == view_id {
                    v.triggered_by = None;
                }
            }
        }

        {
            let mut guard = self.error_traffic.lock().await;
            for e in guard.iter_mut() {
                if let Some(ref t) = e.triggered_by {
                    if t.view == view_id {
                        e.triggered_by = None;
                    }
                }
            }
        }

        let mut tabs = self.tabs.lock().unwrap_or_else(|p| p.into_inner());
        for state in tabs.values_mut() {
            if state.current.as_ref().is_some_and(|t| t.view == view_id) {
                state.current = None;
            }
        }
    }

    pub fn endpoints_snapshot(&self) -> Vec<ApiEndpoint> {
        self.endpoints.iter().map(|e| e.value().clone()).collect()
    }

    /// Number of distinct API endpoints captured so far.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    pub fn seed_endpoints(&self, endpoints: Vec<ApiEndpoint>) {
        for ep in endpoints {
            self.endpoints.insert(ep.key.clone(), ep);
        }
    }

    pub async fn error_traffic_snapshot(&self) -> Vec<TrafficEntry> {
        self.error_traffic.lock().await.clone()
    }

    /// Take the error traffic recorded so far, emptying the buffer, so a
    /// long crawl keeps only the failures not processed yet in memory.
    pub async fn take_error_traffic(&self) -> Vec<TrafficEntry> {
        std::mem::take(&mut *self.error_traffic.lock().await)
    }

    /// Take observed WebSocket errors recorded since the previous drain.
    pub async fn take_ws_errors(&self) -> Vec<WsErrorEvent> {
        std::mem::take(&mut *self.ws_errors.lock().await)
    }

    /// True if `action_id` on `tab` triggered at least one write-guarded HTTP
    /// or WebSocket request.
    pub fn action_had_guarded_write(&self, tab: &TabKey, action_id: &str) -> bool {
        self.with_tab(tab, |state| state.guarded_actions.contains(action_id))
            .unwrap_or(false)
    }

    /// Concise WebSocket error messages attributed to `action_id` on `tab`.
    pub fn ws_errors_for_action(&self, tab: &TabKey, action_id: &str) -> Vec<String> {
        self.with_tab(tab, |state| {
            state
                .action_ws_errors
                .get(action_id)
                .cloned()
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    /// Return error traffic entries since `cursor` and the next cursor.
    pub async fn error_traffic_since(&self, cursor: usize) -> (Vec<TrafficEntry>, usize) {
        let guard = self.error_traffic.lock().await;
        let next = guard.len();
        if cursor >= next {
            return (Vec::new(), next);
        }
        (guard.iter().skip(cursor).cloned().collect::<Vec<_>>(), next)
    }

    /// Watch `page` with attribution on the shared lane: one page at a time
    /// (auth flows, mutation replay), driven through
    /// [`Self::set_current_interaction`] and [`Self::register_action`].
    pub async fn attach(
        self: Arc<Self>,
        page: &Page,
        page_id: Option<String>,
    ) -> Result<NetworkInterceptorHandle> {
        self.attach_tab(page, page_id, TabKey::shared(), None).await
    }

    /// Watch `page` with attribution state of its own tab
    /// ([`TabKey::of`]), driven through the `*_on` methods: tabs crawled in
    /// parallel never claim each other's requests or dialogs. The tab's
    /// state is dropped with the returned handle.
    pub async fn attach_isolated(
        self: Arc<Self>,
        page: &Page,
        page_id: Option<String>,
    ) -> Result<NetworkInterceptorHandle> {
        let tab = TabKey::of(page);
        self.attach_tab(page, page_id, tab, None).await
    }

    /// Attach a login page with isolated attribution and narrowly authorized
    /// login POST endpoints. Its credential-bearing traffic is not persisted.
    pub async fn attach_auth(
        self: Arc<Self>,
        page: &Page,
        page_id: String,
        scope: AuthWriteScope,
    ) -> Result<NetworkInterceptorHandle> {
        self.attach_tab(page, Some(page_id), TabKey::of(page), Some(scope))
            .await
    }

    async fn attach_tab(
        self: Arc<Self>,
        page: &Page,
        page_id: Option<String>,
        tab: TabKey,
        auth_scope: Option<AuthWriteScope>,
    ) -> Result<NetworkInterceptorHandle> {
        // Each Page has its own event streams.
        let mut reqs = page
            .event_listener::<network::EventRequestWillBeSent>()
            .await
            .context("Network.requestWillBeSent listener")?;
        let mut reqs_extra = page
            .event_listener::<network::EventRequestWillBeSentExtraInfo>()
            .await
            .context("Network.requestWillBeSentExtraInfo listener")?;
        let mut resps = page
            .event_listener::<network::EventResponseReceived>()
            .await
            .context("Network.responseReceived listener")?;
        let mut resps_extra = page
            .event_listener::<network::EventResponseReceivedExtraInfo>()
            .await
            .context("Network.responseReceivedExtraInfo listener")?;
        let mut finished = page
            .event_listener::<network::EventLoadingFinished>()
            .await
            .context("Network.loadingFinished listener")?;
        let mut failed = page
            .event_listener::<network::EventLoadingFailed>()
            .await
            .context("Network.loadingFailed listener")?;
        let mut ws_created = page
            .event_listener::<network::EventWebSocketCreated>()
            .await
            .context("Network.webSocketCreated listener")?;
        let mut ws_closed = page
            .event_listener::<network::EventWebSocketClosed>()
            .await
            .context("Network.webSocketClosed listener")?;
        let mut ws_sent = page
            .event_listener::<network::EventWebSocketFrameSent>()
            .await
            .context("Network.webSocketFrameSent listener")?;
        let mut ws_recv = page
            .event_listener::<network::EventWebSocketFrameReceived>()
            .await
            .context("Network.webSocketFrameReceived listener")?;
        let mut ws_err = page
            .event_listener::<network::EventWebSocketFrameError>()
            .await
            .context("Network.webSocketFrameError listener")?;
        let mut bindings = page
            .event_listener::<runtime::EventBindingCalled>()
            .await
            .context("Runtime.bindingCalled listener")?;

        // Native JS dialogs block the page until answered; answer them here so
        // every page the interceptor watches (scan, auth, replay) keeps moving.
        let mut dialogs = page
            .event_listener::<cdp_page::EventJavascriptDialogOpening>()
            .await
            .context("Page.javascriptDialogOpening listener")?;

        // Request interception (all origins, request stage): write guard,
        // private-network egress guard (SSRF guardrail), host allowlist,
        // scoped extra headers, and polite request rate cap. Enabled before
        // the caller navigates, so every guardrail covers the first request.
        if let Some(ua) = self
            .cfg
            .user_agent
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && let Err(err) = page
                .execute(emulation::SetUserAgentOverrideParams::new(ua.to_string()))
                .await
        {
            tracing::debug!(error = ?err, "Emulation.setUserAgentOverride failed");
        }
        let mut fetch_paused = page
            .event_listener::<fetch::EventRequestPaused>()
            .await
            .context("Fetch.requestPaused listener")?;
        let fetch_enabled = self.egress.is_some()
            || self.write_guard_active()
            || !self.cfg.allowed_hosts.is_empty()
            || !self.cfg.extra_headers.is_empty()
            || self
                .cfg
                .pacing
                .max_requests_per_second
                .is_some_and(|r| r.is_finite() && r > 0.0);
        if self.write_guard_active() || !self.cfg.allowed_hosts.is_empty() {
            let ws_guard_cfg = serde_json::json!({
                "mode": match self.cfg.write_guard.mode {
                    WriteGuardMode::Stub => "stub",
                    _ => "block",
                },
                "allow": &self.cfg.write_guard.allow,
                "allowedHosts": &self.cfg.allowed_hosts,
            });
            let ws_guard_script = if self.write_guard_active() {
                format!(
                    "window.__BROKENAPP_WRITE_GUARD = true; window.__BROKENAPP_WS_GUARD = {};",
                    ws_guard_cfg
                )
            } else {
                format!("window.__BROKENAPP_WS_GUARD = {};", ws_guard_cfg)
            };
            // Read by the page instrumentation (`crate::browser::cdp_helpers`)
            // to keep POST forms aimed at new windows inside this page and to
            // enforce WebSocket write-guard and allowed_hosts rules.
            let flag = cdp_page::AddScriptToEvaluateOnNewDocumentParams::builder()
                .source(ws_guard_script)
                .run_immediately(true)
                .build()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            page.execute(flag)
                .await
                .context("Page.addScriptToEvaluateOnNewDocument (write guard / ws guard flag)")?;
            if self.write_guard_active()
                && let Err(err) = page
                    .execute(runtime::AddBindingParams::new(WS_GUARD_BINDING_NAME))
                    .await
            {
                tracing::debug!(error = ?err, "Runtime.addBinding for WebSocket write guard failed");
            }
        }
        if fetch_enabled {
            page.execute(fetch_enable_params(self.egress.is_some()))
                .await
                .context("enable Fetch domain (write guard / egress / compliance guard)")?;
        }

        // The main frame keeps its id across navigations.
        let main_frame = page
            .mainframe()
            .await
            .ok()
            .flatten()
            .map(|frame| frame.inner().clone());
        let page = page.clone();
        let this = Arc::clone(&self);
        let page_id = page_id.clone();
        if !tab.is_shared() {
            self.register_tab(&tab);
        }
        let task_tab = tab.clone();
        let task = tokio::spawn(async move {
            let tab = task_tab;
            let mut reqs_done = false;
            let mut reqs_extra_done = false;
            let mut resps_done = false;
            let mut resps_extra_done = false;
            let mut finished_done = false;
            let mut failed_done = false;
            let mut fetch_done = !fetch_enabled;
            let mut dialogs_done = false;
            let mut bindings_done = false;
            let mut ws_created_done = false;
            let mut ws_closed_done = false;
            let mut ws_sent_done = false;
            let mut ws_recv_done = false;
            let mut ws_err_done = false;

            while !(reqs_done
                && reqs_extra_done
                && resps_done
                && resps_extra_done
                && finished_done
                && failed_done
                && fetch_done
                && dialogs_done
                && bindings_done
                && ws_created_done
                && ws_closed_done
                && ws_sent_done
                && ws_recv_done
                && ws_err_done)
            {
                // Prioritize paused Fetch interceptions and blocking JS dialogs
                // ahead of passive Network logging events so multi-tab scans on
                // busy dev servers never starve `Fetch.continueRequest`.
                tokio::select! {
                    biased;
                    ev = fetch_paused.next(), if !fetch_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_fetch_request_paused(&page, &ev, page_id.as_deref(), &tab, auth_scope.as_ref()).await {
                                    tracing::debug!(error=?err, "fetch requestPaused handler error");
                                    // Never leave requests paused: reads continue,
                                    // writes fail closed while the guard is on.
                                    this.release_after_error(&page, &ev).await;
                                }
                            }
                            None => fetch_done = true,
                        }
                    }
                    ev = dialogs.next(), if !dialogs_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_dialog_opening(&page, &ev, &tab).await {
                                    tracing::debug!(error=?err, "page javascriptDialogOpening handler error");
                                }
                            }
                            None => dialogs_done = true,
                        }
                    }
                    ev = bindings.next(), if !bindings_done => {
                        match ev {
                            Some(ev) => {
                                if ev.name == WS_GUARD_BINDING_NAME
                                    && let Err(err) = this.on_ws_guard_binding_called(&ev, page_id.as_deref(), &tab).await
                                {
                                    tracing::debug!(error=?err, "ws write guard binding handler error");
                                }
                            }
                            None => bindings_done = true,
                        }
                    }
                    ev = ws_created.next(), if !ws_created_done => {
                        match ev {
                            Some(ev) => {
                                this.on_ws_created(&ev, &tab);
                            }
                            None => ws_created_done = true,
                        }
                    }
                    ev = ws_closed.next(), if !ws_closed_done => {
                        match ev {
                            Some(ev) => {
                                this.on_ws_closed(&ev, &tab);
                            }
                            None => ws_closed_done = true,
                        }
                    }
                    ev = ws_sent.next(), if !ws_sent_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_ws_frame_sent(&ev, page_id.as_deref(), &tab).await {
                                    tracing::debug!(error=?err, "ws frameSent handler error");
                                }
                            }
                            None => ws_sent_done = true,
                        }
                    }
                    ev = ws_recv.next(), if !ws_recv_done => {
                        match ev {
                            Some(ev) => {
                                this.on_ws_frame_received(&ev, page_id.as_deref(), &tab).await;
                            }
                            None => ws_recv_done = true,
                        }
                    }
                    ev = ws_err.next(), if !ws_err_done => {
                        match ev {
                            Some(ev) => {
                                this.on_ws_frame_error(&ev, page_id.as_deref(), &tab).await;
                            }
                            None => ws_err_done = true,
                        }
                    }
                    ev = reqs.next(), if !reqs_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_request_will_be_sent(&ev, page_id.as_deref(), main_frame.as_deref(), &tab).await {
                                    tracing::debug!(error=?err, "network requestWillBeSent handler error");
                                }
                            }
                            None => reqs_done = true,
                        }
                    }
                    ev = reqs_extra.next(), if !reqs_extra_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_request_will_be_sent_extra_info(&ev, &tab).await {
                                    tracing::debug!(error=?err, "network requestWillBeSentExtraInfo handler error");
                                }
                            }
                            None => reqs_extra_done = true,
                        }
                    }
                    ev = resps.next(), if !resps_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_response_received(&ev, &tab).await {
                                    tracing::debug!(error=?err, "network responseReceived handler error");
                                }
                            }
                            None => resps_done = true,
                        }
                    }
                    ev = resps_extra.next(), if !resps_extra_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_response_received_extra_info(&ev, &tab).await {
                                    tracing::debug!(error=?err, "network responseReceivedExtraInfo handler error");
                                }
                            }
                            None => resps_extra_done = true,
                        }
                    }
                    ev = finished.next(), if !finished_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_loading_finished(&page, &ev, &tab).await {
                                    tracing::debug!(error=?err, "network loadingFinished handler error");
                                }
                            }
                            None => finished_done = true,
                        }
                    }
                    ev = failed.next(), if !failed_done => {
                        match ev {
                            Some(ev) => {
                                if let Err(err) = this.on_loading_failed(&page, &ev, &tab).await {
                                    tracing::debug!(error=?err, "network loadingFailed handler error");
                                }
                            }
                            None => failed_done = true,
                        }
                    }
                }
            }
        });

        let released = (!tab.is_shared()).then(|| (Arc::downgrade(&self), tab));
        Ok(NetworkInterceptorHandle {
            task,
            tab: released,
        })
    }

    /// Total requests blocked by `scan.allowed_hosts`.
    pub fn allowed_hosts_blocked_total(&self) -> usize {
        self.allowed_hosts_blocked_total.load(Ordering::Relaxed)
    }

    fn is_passive_static_get(ev: &fetch::EventRequestPaused) -> bool {
        matches!(
            ev.request.method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD"
        ) && matches!(
            ev.resource_type,
            network::ResourceType::Script
                | network::ResourceType::Stylesheet
                | network::ResourceType::Image
                | network::ResourceType::Font
                | network::ResourceType::Media
                | network::ResourceType::Manifest
                | network::ResourceType::TextTrack
        )
    }

    fn should_stamp_extra_headers(&self, url: &str, resource_type: &network::ResourceType) -> bool {
        if self.cfg.extra_headers.is_empty() {
            return false;
        }
        let Ok(parsed) = Url::parse(url) else {
            return false;
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            return false;
        }
        if !self.cfg.allowed_hosts.is_empty() {
            return crate::network::filters::url_matches_allowed_hosts(
                url,
                &self.cfg.allowed_hosts,
            );
        }
        if let Some(origin) = self.first_party_origin() {
            return parsed.origin().ascii_serialization() == origin;
        }
        if *resource_type == network::ResourceType::Document {
            self.set_first_party_origin(&parsed);
            return true;
        }
        false
    }

    fn build_continue_params(
        &self,
        ev: &fetch::EventRequestPaused,
    ) -> fetch::ContinueRequestParams {
        let mut params = fetch::ContinueRequestParams::new(ev.request_id.clone());
        if !self.should_stamp_extra_headers(&ev.request.url, &ev.resource_type) {
            return params;
        }
        let existing = headers_to_btreemap(&ev.request.headers);
        let override_keys: HashSet<String> = self
            .cfg
            .extra_headers
            .keys()
            .map(|k| k.trim().to_ascii_lowercase())
            .filter(|k| !k.is_empty())
            .collect();
        let mut merged: Vec<fetch::HeaderEntry> =
            Vec::with_capacity(existing.len().saturating_add(self.cfg.extra_headers.len()));
        for (name, value) in existing {
            let trimmed = name.trim();
            if trimmed.is_empty()
                || trimmed.starts_with(':')
                || override_keys.contains(&trimmed.to_ascii_lowercase())
            {
                continue;
            }
            merged.push(fetch::HeaderEntry::new(trimmed.to_string(), value));
        }
        for (name, value) in &self.cfg.extra_headers {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                merged.push(fetch::HeaderEntry::new(trimmed.to_string(), value.clone()));
            }
        }
        params.headers = Some(merged);
        params
    }

    async fn wait_rate_cap(&self) {
        let Some(rps) = self
            .cfg
            .pacing
            .max_requests_per_second
            .filter(|r| r.is_finite() && *r > 0.0)
        else {
            return;
        };
        let min_interval = Duration::from_secs_f64((1.0 / rps).min(60.0));
        let sleep_for = {
            let mut gate = self.rate_cap_gate.lock().await;
            let now = Instant::now();
            match *gate {
                Some(next_ready) if next_ready > now => {
                    let wait = next_ready.duration_since(now);
                    *gate = Some(next_ready + min_interval);
                    wait
                }
                _ => {
                    *gate = Some(now + min_interval);
                    Duration::ZERO
                }
            }
        };
        if !sleep_for.is_zero() {
            tokio::time::sleep(sleep_for).await;
        }
    }

    async fn on_fetch_request_paused(
        &self,
        page: &Page,
        ev: &fetch::EventRequestPaused,
        page_id: Option<&str>,
        tab: &TabKey,
        auth_scope: Option<&AuthWriteScope>,
    ) -> Result<()> {
        let url = ev.request.url.clone();
        let is_passive_static_get = Self::is_passive_static_get(ev);

        // Fail-closed host allowlist: block navigations, redirects, API/XHR/Fetch,
        // EventSource, Ping, Other, and any non-GET/HEAD requests outside
        // `scan.allowed_hosts` before a packet leaves Chrome. Passive read-only
        // static assets (GET scripts/styles/images/fonts) remain permitted so
        // first-party pages backed by CDNs still render.
        if !self.cfg.allowed_hosts.is_empty()
            && !is_passive_static_get
            && !crate::network::filters::url_matches_allowed_hosts(&url, &self.cfg.allowed_hosts)
        {
            let n = self
                .allowed_hosts_blocked_total
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            if n <= 5 {
                tracing::warn!(
                    url = %url,
                    method = %ev.request.method,
                    resource_type = ?ev.resource_type,
                    "blocked request outside scan.allowed_hosts"
                );
            } else if n == 6 {
                tracing::warn!(
                    "blocked requests outside scan.allowed_hosts continue; suppressing further logs"
                );
            }
            page.execute(fetch::FailRequestParams::new(
                ev.request_id.clone(),
                network::ErrorReason::BlockedByClient,
            ))
            .await
            .context("Fetch.failRequest (outside allowed_hosts)")?;
            return Ok(());
        }

        // Browser CSP/Reporting beacons and dev-server error feedback POSTs
        // are infrastructure noise: drop them quietly under the write guard
        // (with 204 so the browser stops retrying) without recording them as
        // application endpoints or attributing them to UI controls.
        let paused_headers = headers_to_btreemap(&ev.request.headers);
        let is_non_app_noise = Url::parse(&url).ok().is_some_and(|u| {
            let path = u.path();
            crate::network::filters::is_dev_tool_or_hmr_path(path)
                || crate::network::filters::is_csp_or_telemetry_report(
                    path,
                    header_value(&paused_headers, "content-type"),
                )
        });
        if is_non_app_noise
            && !crate::safety::is_read_only_method(&ev.request.method)
            && self.write_guard_active()
        {
            let request_id = ev
                .network_id
                .as_ref()
                .map(|id| id.inner().clone())
                .unwrap_or_else(|| ev.request_id.inner().clone());
            self.mark_guarded(&request_key(tab, &request_id));
            self.pending.remove(&request_key(tab, &request_id));
            let _ = page
                .execute(fetch::FulfillRequestParams::new(ev.request_id.clone(), 204))
                .await;
            return Ok(());
        }

        if self.write_guard_active() {
            let (verdict, body) = self.write_guard_check(ev, auth_scope);
            if verdict == WriteVerdict::Guard {
                self.guard_write(page, ev, page_id, body, tab).await;
                return Ok(());
            }
        }

        // Resource-class/domain blocking has always ridden on the egress
        // guard's interception (public targets). Fetch is now on for every
        // guarded scan; keep this scoped as before so local scans still load
        // images and fonts (asset-404 findings and icon-sized controls rely
        // on them).
        if self.cfg.block_unnecessary_resources && self.egress.is_some() {
            let resource_type = ev.resource_type.as_ref();
            let should_block_type = self
                .cfg
                .blocked_resource_types
                .iter()
                .any(|blocked| resource_type.eq_ignore_ascii_case(blocked.trim()));
            let should_block_domain = Url::parse(&url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_string))
                .is_some_and(|host| {
                    self.cfg
                        .blocked_domains
                        .iter()
                        .any(|blocked| host.ends_with(blocked.trim()))
                });

            if should_block_type || should_block_domain {
                page.execute(fetch::FailRequestParams::new(
                    ev.request_id.clone(),
                    network::ErrorReason::BlockedByClient,
                ))
                .await
                .context("Fetch.failRequest (resource blocked)")?;
                return Ok(());
            }
        }

        if let Some(ref guard) = self.egress {
            let blocked = guard.check_url(&url).await;
            if let Some(reason) = blocked {
                let n = self.egress_blocked_total.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 5 {
                    tracing::warn!(url = %url, reason = ?reason, "blocked private egress request");
                } else if n == 6 {
                    tracing::warn!(
                        "blocked private egress requests continue; suppressing further logs"
                    );
                }

                page.execute(fetch::FailRequestParams::new(
                    ev.request_id.clone(),
                    network::ErrorReason::BlockedByClient,
                ))
                .await
                .context("Fetch.failRequest")?;
                return Ok(());
            }
        }

        if !is_passive_static_get && !is_non_app_noise {
            self.wait_rate_cap().await;
        }

        page.execute(self.build_continue_params(ev))
            .await
            .context("Fetch.continueRequest")?;

        Ok(())
    }

    /// Classify a paused request for the write guard. Returns the verdict and
    /// the decoded request body (when the browser exposed one).
    fn write_guard_check(
        &self,
        ev: &fetch::EventRequestPaused,
        auth_scope: Option<&AuthWriteScope>,
    ) -> (WriteVerdict, Option<String>) {
        let method = ev.request.method.as_str();
        let url = ev.request.url.as_str();
        let body = if crate::safety::is_read_only_method(method) {
            None
        } else {
            decode_post_data_entries(ev.request.post_data_entries.as_deref())
        };
        let body_unavailable = ev.request.has_post_data.unwrap_or(false) && body.is_none();
        let graphql_mutation = crate::network::graphql::request_may_be_mutation(
            url,
            body.as_deref(),
            body_unavailable,
        );
        let in_auth_flow =
            !graphql_mutation && auth_scope.is_some_and(|scope| scope.allows(method, url));
        let verdict = crate::safety::write_guard_verdict(
            &self.cfg.write_guard,
            &WriteRequest {
                method,
                url,
                graphql_mutation,
                in_auth_flow,
            },
        );
        if let WriteVerdict::Allowed(reason) = verdict {
            tracing::debug!(method, reason = ?reason, "write guard: allowed write");
        }
        (verdict, body)
    }

    /// Record a guarded write, then stop it before it leaves the browser.
    ///
    /// Native form posts (document navigations) get an empty 204 so the page
    /// stays put; other requests are failed (`block`) or answered with the
    /// configured stub (`stub`). Fails closed: if answering fails, the request
    /// is failed, and if that fails too it stays paused. It is never continued.
    async fn guard_write(
        &self,
        page: &Page,
        ev: &fetch::EventRequestPaused,
        page_id: Option<&str>,
        body: Option<String>,
        tab: &TabKey,
    ) {
        let action = match self.cfg.write_guard.mode {
            WriteGuardMode::Stub => WriteGuardAction::Stubbed,
            _ => WriteGuardAction::Blocked,
        };
        let request_id = ev
            .network_id
            .as_ref()
            .map(|id| id.inner().clone())
            .unwrap_or_else(|| ev.request_id.inner().clone());
        self.mark_guarded(&request_key(tab, &request_id));

        let logged_url = if page_id.is_some_and(|id| id.starts_with(AUTH_PAGE_ID_PREFIX)) {
            "<auth request>"
        } else {
            ev.request.url.as_str()
        };
        let n = self.write_guard_total.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 5 {
            tracing::info!(
                method = %ev.request.method,
                url = %logged_url,
                action = action.as_str(),
                "write guard stopped a state-changing request"
            );
        } else if n == 6 {
            tracing::info!("write guard keeps stopping writes; suppressing further logs");
        }

        if let Err(err) = self
            .record_guarded_write(&request_id, ev, page_id, body, action, tab)
            .await
        {
            tracing::warn!(error = ?err, url = %logged_url, "failed to record guarded write");
        }

        let is_document = matches!(ev.resource_type, network::ResourceType::Document);
        let answered = if is_document {
            page.execute(fetch::FulfillRequestParams::new(ev.request_id.clone(), 204))
                .await
                .map(|_| ())
                .context("Fetch.fulfillRequest (write guard, document)")
        } else if action == WriteGuardAction::Stubbed {
            page.execute(self.stub_response(ev))
                .await
                .map(|_| ())
                .context("Fetch.fulfillRequest (write guard stub)")
        } else {
            page.execute(fetch::FailRequestParams::new(
                ev.request_id.clone(),
                network::ErrorReason::BlockedByClient,
            ))
            .await
            .map(|_| ())
            .context("Fetch.failRequest (write guard)")
        };
        if let Err(err) = answered {
            tracing::debug!(error = ?err, "write guard response failed; failing request");
            let _ = page
                .execute(fetch::FailRequestParams::new(
                    ev.request_id.clone(),
                    network::ErrorReason::BlockedByClient,
                ))
                .await;
        }
    }

    /// Stub answer for `mode = "stub"`: `stub_status` with an empty JSON body
    /// (`[]` when PostgREST-style `Prefer: return=representation` asks for
    /// rows), plus CORS headers echoing the request origin so cross-origin
    /// callers can read it.
    fn stub_response(&self, ev: &fetch::EventRequestPaused) -> fetch::FulfillRequestParams {
        let status = match self.cfg.write_guard.stub_status {
            s @ 200..=599 => s,
            _ => 200,
        };
        let headers = headers_to_btreemap(&ev.request.headers);
        let mut response_headers = vec![
            fetch::HeaderEntry::new("content-type", "application/json"),
            fetch::HeaderEntry::new("cache-control", "no-store"),
            fetch::HeaderEntry::new("x-brokenapp-write-guard", "stubbed"),
        ];
        let request_origin = header_value(&headers, "origin")
            .filter(|o| !o.is_empty() && *o != "null")
            .map(str::to_string)
            .or_else(|| {
                header_value(&headers, "referer")
                    .and_then(|r| Url::parse(r).ok())
                    .map(|u| u.origin().ascii_serialization())
            });
        match request_origin {
            Some(origin) => {
                response_headers.push(fetch::HeaderEntry::new(
                    "access-control-allow-origin",
                    origin,
                ));
                response_headers.push(fetch::HeaderEntry::new(
                    "access-control-allow-credentials",
                    "true",
                ));
                response_headers.push(fetch::HeaderEntry::new("vary", "Origin"));
            }
            None => {
                response_headers.push(fetch::HeaderEntry::new("access-control-allow-origin", "*"));
            }
        }
        response_headers.push(fetch::HeaderEntry::new(
            "access-control-expose-headers",
            "*",
        ));

        let mut params = fetch::FulfillRequestParams::new(ev.request_id.clone(), i64::from(status));
        params.response_headers = Some(response_headers);
        if !matches!(status, 204 | 205 | 304) {
            let wants_rows = header_value(&headers, "prefer")
                .is_some_and(|p| p.to_ascii_lowercase().contains("return=representation"));
            let body = if wants_rows { "[]" } else { "{}" };
            use base64::Engine as _;
            params.body = Some(
                base64::engine::general_purpose::STANDARD
                    .encode(body)
                    .into(),
            );
        }
        params
    }

    /// Write the `network.jsonl` row for a guarded request and fold it into
    /// the endpoint map (so `triggered_by` links the control to the write).
    async fn record_guarded_write(
        &self,
        request_id: &str,
        ev: &fetch::EventRequestPaused,
        page_id: Option<&str>,
        body: Option<String>,
        action: WriteGuardAction,
        tab: &TabKey,
    ) -> Result<()> {
        let method = HttpMethod::from_str_lossy(&ev.request.method);
        let url = ev.request.url.clone();
        let mut headers = redact_headers(&headers_to_btreemap(&ev.request.headers));
        let key = request_key(tab, request_id);
        if let Some((_, extra)) = self.request_extra_headers.remove(&key) {
            headers.extend(extra);
        }
        let header_action_id = take_header_case_insensitive(&mut headers, "x-brokenapp-action-id");
        let route_load = take_header_case_insensitive(&mut headers, ROUTE_LOAD_HEADER).is_some();
        let preparation = take_header_case_insensitive(&mut headers, PREPARATION_HEADER).is_some();

        // Network.requestWillBeSent usually arrives first; reuse what it
        // captured (initiator, attribution at request start).
        let pending = self.pending.remove(&key).map(|(_, p)| p);
        let preparation = preparation || pending.as_ref().is_some_and(|p| p.preparation);
        let ignore_attribution =
            should_ignore_from_attribution(&url, &headers, Some(&ev.resource_type))
                || pending.as_ref().is_some_and(|p| p.ignore_attribution);
        let header_action_id = header_action_id.filter(|_| !preparation && !ignore_attribution);
        let (mut trace, triggered_by) = match pending {
            Some(mut p) => {
                if preparation || p.preparation || ignore_attribution {
                    p.triggered_by = None;
                    if let Some(trace) = p.trace.as_mut() {
                        trace.action_id = None;
                    }
                } else if let Some(interaction) = header_action_id
                    .as_deref()
                    .and_then(|id| self.action_interaction(tab, id))
                {
                    p.triggered_by = Some(interaction);
                    if let Some(trace) = p.trace.as_mut() {
                        trace.action_id = header_action_id.clone();
                    }
                }
                (p.trace, p.triggered_by)
            }
            None => {
                let triggered_by = if route_load || preparation || ignore_attribution {
                    None
                } else {
                    self.attribute_request(tab, header_action_id.as_deref(), true, false, false)
                };
                let trace = RequestTrace {
                    trace_id: Uuid::new_v4().to_string(),
                    cdp_request_id: request_id.to_string(),
                    page_id: page_id.map(str::to_string),
                    frame_id: Some(ev.frame_id.inner().clone()),
                    document_url: None,
                    initiator_type: None,
                    initiator_url: None,
                    initiator_line_number: None,
                    initiator_column_number: None,
                    initiator_request_id: None,
                    has_user_gesture: None,
                    action_id: None,
                };
                (Some(trace), triggered_by)
            }
        };
        if let Some(t) = trace.as_mut() {
            if t.action_id.is_none() {
                t.action_id = header_action_id.or_else(|| {
                    triggered_by
                        .as_ref()
                        .and_then(|i| self.action_id_for(tab, i))
                });
            }
            if let Some(ref aid) = t.action_id {
                self.with_tab(tab, |state| {
                    state.guarded_actions.insert(aid.clone());
                });
            }
        }

        let json_request_sample = body
            .as_deref()
            .filter(|s| s.len() <= self.cfg.limits.max_body_bytes)
            .and_then(parse_request_body)
            .map(|mut v| {
                redact_json_value(&mut v);
                v
            });
        let post_data = body.as_deref().map(|s| {
            let mut s = redact_post_data(s);
            truncate_at_char_boundary(&mut s, self.cfg.limits.max_body_bytes);
            s
        });

        let mut entry = TrafficEntry {
            occurred_at: DateTime::<Utc>::from(std::time::SystemTime::now()),
            trace,
            request: HttpRequestLog {
                method,
                url,
                headers,
                post_data,
            },
            response: None,
            failure: None,
            triggered_by,
            is_api: None,
            duration_ms: None,
            attribution: None,
        };
        entry.is_api = Some(crate::network::filters::is_application_traffic(&entry));

        if is_auth_trace(entry.trace.as_ref()) {
            return Ok(());
        }

        // Non-standard methods (PURGE, PROPFIND, ...) have no `HttpMethod`
        // variant; log them under their real method instead of folding them
        // into a GET endpoint.
        let raw_method = ev.request.method.trim().to_ascii_uppercase();
        if raw_method != method.as_str() {
            if let Some(w) = self.writer.as_ref() {
                let key = endpoint_identity(&entry.request, self.first_party_origin().as_deref())
                    .map(|id| format!("{raw_method} {}", id.key.path_template))
                    .ok();
                if let Err(err) = w
                    .append_annotated(&entry, key.as_deref(), Some(action))
                    .await
                {
                    tracing::warn!(error = ?err, "failed to append guarded network.jsonl row");
                }
            }
            return Ok(());
        }
        self.record_entry(entry, None, json_request_sample, Some(action))
            .await
    }

    /// Fallback when the paused-request handler failed: never leave the
    /// request paused, but never let a write through while the guard is on.
    async fn release_after_error(&self, page: &Page, ev: &fetch::EventRequestPaused) {
        let blocked_host = !self.cfg.allowed_hosts.is_empty()
            && !Self::is_passive_static_get(ev)
            && !crate::network::filters::url_matches_allowed_hosts(
                &ev.request.url,
                &self.cfg.allowed_hosts,
            );
        let fail_closed = blocked_host
            || (self.write_guard_active()
                && !crate::safety::is_read_only_method(&ev.request.method));
        let res = if fail_closed {
            page.execute(fetch::FailRequestParams::new(
                ev.request_id.clone(),
                network::ErrorReason::BlockedByClient,
            ))
            .await
            .map(|_| ())
        } else {
            page.execute(self.build_continue_params(ev))
                .await
                .map(|_| ())
        };
        if let Err(err) = res {
            tracing::debug!(error = ?err, "failed to release paused request");
        }
    }

    /// Answer a native JS dialog: accept while the write guard is on (writes
    /// are stopped anyway, so following the confirm reveals what it would
    /// call), dismiss otherwise. Records it for the action current on the
    /// tab that raised it.
    async fn on_dialog_opening(
        &self,
        page: &Page,
        ev: &cdp_page::EventJavascriptDialogOpening,
        tab: &TabKey,
    ) -> Result<()> {
        let accept = self.write_guard_active();
        let mut dialog = NativeDialog {
            kind: ev.r#type.as_ref().to_string(),
            message: ev.message.clone(),
            url: ev.url.clone(),
            accepted: accept,
            triggered_by: None,
            action_id: None,
            occurred_at: Utc::now(),
        };
        tracing::debug!(dialog = %dialog.summary(), accepted = accept, tab = %tab, "native dialog");
        self.with_tab(tab, |state| {
            dialog.triggered_by = state.current.clone();
            dialog.action_id = dialog
                .triggered_by
                .as_ref()
                .and_then(|i| state.action_id_for(i));
            state.native_dialogs.push(dialog);
        });

        let mut params = cdp_page::HandleJavaScriptDialogParams::new(accept);
        if accept && matches!(ev.r#type, cdp_page::DialogType::Prompt) {
            params.prompt_text = Some(ev.default_prompt.clone().unwrap_or_default());
        }
        page.execute(params)
            .await
            .context("Page.handleJavaScriptDialog")?;
        Ok(())
    }

    fn on_ws_created(&self, ev: &network::EventWebSocketCreated, tab: &TabKey) {
        let key = request_key(tab, ev.request_id.inner());
        self.ws_connections.insert(key, ev.url.clone());
    }

    fn on_ws_closed(&self, ev: &network::EventWebSocketClosed, tab: &TabKey) {
        let key = request_key(tab, ev.request_id.inner());
        self.ws_connections.remove(&key);
    }

    async fn on_ws_guard_binding_called(
        &self,
        ev: &runtime::EventBindingCalled,
        page_id: Option<&str>,
        tab: &TabKey,
    ) -> Result<()> {
        let parsed: WsGuardBindingPayload =
            serde_json::from_str(&ev.payload).context("parse ws guard binding payload")?;
        if parsed.url.trim().is_empty() || crate::safety::is_ws_dev_tool_url(&parsed.url) {
            return Ok(());
        }
        let action = match self.cfg.write_guard.mode {
            WriteGuardMode::Stub => WriteGuardAction::Stubbed,
            _ => WriteGuardAction::Blocked,
        };
        let n = self.write_guard_total.fetch_add(1, Ordering::Relaxed) + 1;
        let logged_url = if page_id.is_some_and(|id| id.starts_with(AUTH_PAGE_ID_PREFIX)) {
            "<auth ws>"
        } else {
            parsed.url.as_str()
        };
        if n <= 5 {
            tracing::info!(
                method = "WS",
                url = %logged_url,
                op = parsed.op.as_deref().unwrap_or(""),
                action = action.as_str(),
                "write guard stopped a mutating WebSocket frame"
            );
        }

        let ignore = parsed.preparing || parsed.route_load;
        let triggered_by = if ignore {
            None
        } else {
            self.attribute_request(tab, parsed.action_id.as_deref(), true, false, false)
        };
        let action_id = if ignore {
            None
        } else {
            parsed.action_id.or_else(|| {
                triggered_by
                    .as_ref()
                    .and_then(|i| self.action_id_for(tab, i))
            })
        };
        if let Some(ref aid) = action_id {
            self.with_tab(tab, |state| {
                state.guarded_actions.insert(aid.clone());
            });
        }
        let redacted_post = parsed.payload.as_deref().map(|raw| {
            crate::safety::redact_ws_payload(raw, self.cfg.limits.max_body_bytes.min(4096))
        });
        let json_request_sample = redacted_post
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let trace = RequestTrace {
            trace_id: Uuid::new_v4().to_string(),
            cdp_request_id: format!("ws-guard-{}", Uuid::new_v4()),
            page_id: page_id.map(str::to_string),
            frame_id: None,
            document_url: None,
            initiator_type: Some("websocket".to_string()),
            initiator_url: None,
            initiator_line_number: None,
            initiator_column_number: None,
            initiator_request_id: None,
            has_user_gesture: None,
            action_id,
        };
        if is_auth_trace(Some(&trace)) {
            return Ok(());
        }
        let entry = TrafficEntry {
            occurred_at: DateTime::<Utc>::from(std::time::SystemTime::now()),
            trace: Some(trace),
            request: HttpRequestLog {
                method: HttpMethod::Ws,
                url: parsed.url,
                headers: BTreeMap::new(),
                post_data: redacted_post,
            },
            response: None,
            failure: None,
            triggered_by,
            is_api: Some(true),
            duration_ms: None,
            attribution: None,
        };
        self.record_entry(entry, None, json_request_sample, Some(action))
            .await
    }

    async fn on_ws_frame_sent(
        &self,
        ev: &network::EventWebSocketFrameSent,
        page_id: Option<&str>,
        tab: &TabKey,
    ) -> Result<()> {
        if page_id.is_some_and(|id| id.starts_with(AUTH_PAGE_ID_PREFIX)) {
            return Ok(());
        }
        // Only inspect text frames (opcode 1).
        if (ev.response.opcode - 1.0).abs() > f64::EPSILON {
            return Ok(());
        }
        let key = request_key(tab, ev.request_id.inner());
        let Some(url) = self.ws_connections.get(&key).map(|v| v.value().clone()) else {
            return Ok(());
        };
        if crate::safety::is_ws_dev_tool_url(&url) {
            return Ok(());
        }
        let analysis = crate::safety::classify_ws_frame(&url, &ev.response.payload_data);
        if analysis.class == crate::safety::WsFrameClass::Heartbeat {
            return Ok(());
        }
        let is_mutation = analysis.class == crate::safety::WsFrameClass::Mutation;
        let triggered_by = self.attribute_request(tab, None, is_mutation, false, false);
        let action_id = triggered_by
            .as_ref()
            .and_then(|i| self.action_id_for(tab, i));
        let redacted_post = crate::safety::redact_ws_payload(
            &ev.response.payload_data,
            self.cfg.limits.max_body_bytes.min(4096),
        );
        let json_request_sample = serde_json::from_str::<serde_json::Value>(&redacted_post).ok();
        let trace = RequestTrace {
            trace_id: Uuid::new_v4().to_string(),
            cdp_request_id: ev.request_id.inner().clone(),
            page_id: page_id.map(str::to_string),
            frame_id: None,
            document_url: None,
            initiator_type: Some("websocket".to_string()),
            initiator_url: None,
            initiator_line_number: None,
            initiator_column_number: None,
            initiator_request_id: None,
            has_user_gesture: None,
            action_id,
        };
        let entry = TrafficEntry {
            occurred_at: DateTime::<Utc>::from(std::time::SystemTime::now()),
            trace: Some(trace),
            request: HttpRequestLog {
                method: HttpMethod::Ws,
                url,
                headers: BTreeMap::new(),
                post_data: Some(redacted_post),
            },
            response: None,
            failure: None,
            triggered_by,
            is_api: Some(true),
            duration_ms: None,
            attribution: None,
        };
        self.record_entry(entry, None, json_request_sample, None)
            .await
    }

    async fn on_ws_frame_received(
        &self,
        ev: &network::EventWebSocketFrameReceived,
        page_id: Option<&str>,
        tab: &TabKey,
    ) {
        if page_id.is_some_and(|id| id.starts_with(AUTH_PAGE_ID_PREFIX)) {
            return;
        }
        if (ev.response.opcode - 1.0).abs() > f64::EPSILON {
            return;
        }
        let key = request_key(tab, ev.request_id.inner());
        let Some(url) = self.ws_connections.get(&key).map(|v| v.value().clone()) else {
            return;
        };
        if crate::safety::is_ws_dev_tool_url(&url) {
            return;
        }
        let Some(message) = crate::safety::detect_ws_error_frame(&ev.response.payload_data) else {
            return;
        };
        self.record_ws_error_event(tab, url, message).await;
    }

    async fn on_ws_frame_error(
        &self,
        ev: &network::EventWebSocketFrameError,
        page_id: Option<&str>,
        tab: &TabKey,
    ) {
        if page_id.is_some_and(|id| id.starts_with(AUTH_PAGE_ID_PREFIX)) {
            return;
        }
        let key = request_key(tab, ev.request_id.inner());
        let Some(url) = self.ws_connections.get(&key).map(|v| v.value().clone()) else {
            return;
        };
        if crate::safety::is_ws_dev_tool_url(&url) {
            return;
        }
        let msg = ev.error_message.trim();
        if msg.is_empty() {
            return;
        }
        self.record_ws_error_event(tab, url, msg.to_string()).await;
    }

    async fn record_ws_error_event(&self, tab: &TabKey, url: String, message: String) {
        let triggered_by = self.attribute_request(tab, None, true, false, false);
        let action_id = triggered_by
            .as_ref()
            .and_then(|i| self.action_id_for(tab, i));
        if let Some(ref aid) = action_id {
            let formatted = format!("WebSocket error: {message}");
            self.with_tab(tab, |state| {
                let list = state.action_ws_errors.entry(aid.clone()).or_default();
                if list.len() < 8 && !list.contains(&formatted) {
                    list.push(formatted);
                }
            });
        }
        self.ws_errors.lock().await.push(WsErrorEvent {
            url,
            message,
            triggered_by,
            action_id,
            occurred_at: Utc::now(),
        });
    }

    /// Attribute a request to a UI interaction: an explicit action-id mapping,
    /// else the current interaction, else (for writes and user-gesture
    /// requests) the most recent interaction within a short window.
    ///
    /// Interactions only claim requests of the main-frame document they
    /// started in (`main_document` requests themselves excepted): when a click
    /// navigates or the explorer restores the view, the new document's load
    /// traffic is not the click's. The page-load marker (`__page_load__`) is
    /// exempt, since it exists to collect exactly that traffic.
    fn attribute_request(
        &self,
        tab: &TabKey,
        action_id: Option<&str>,
        is_mutation: bool,
        has_user_gesture: bool,
        main_document: bool,
    ) -> Option<InteractionRef> {
        let mut tabs = self.tabs.lock().unwrap_or_else(|p| p.into_inner());
        let state = tabs.get_mut(tab)?;
        let epoch = state.document_epoch;
        let same_document = |interaction: &InteractionRef, started: u64| {
            main_document || started == epoch || interaction.selector == PAGE_LOAD_SELECTOR
        };
        if let Some(interaction) = action_id.and_then(|id| self.action_interaction(tab, id)) {
            return Some(interaction);
        }
        if state.preparation_depth > 0 {
            return None;
        }
        if let Some(current) = state.current.as_ref() {
            return same_document(current, state.current_epoch).then(|| current.clone());
        }
        // If we didn't catch a current interaction and we don't have an
        // action-id stamp, try a time-window fallback for mutation requests or
        // user-gesture initiated requests: this tab's recent actions only.
        if is_mutation || has_user_gesture {
            const WINDOW_MS: u64 = 4_000;
            let now = Instant::now();
            // Prune old entries.
            while let Some((t, _, _)) = state.recent.front() {
                if now.duration_since(*t) > Duration::from_millis(WINDOW_MS * 2) {
                    state.recent.pop_front();
                } else {
                    break;
                }
            }
            // Pick the most recent within the window.
            if let Some((_t, recent, _)) = state.recent.iter().rev().find(|(t, recent, started)| {
                now.duration_since(*t) <= Duration::from_millis(WINDOW_MS)
                    && same_document(recent, *started)
            }) {
                return Some(recent.clone());
            }
        }
        None
    }

    async fn on_request_will_be_sent(
        &self,
        ev: &network::EventRequestWillBeSent,
        page_id: Option<&str>,
        main_frame: Option<&str>,
        tab: &TabKey,
    ) -> Result<()> {
        let page_id = page_id.map(|s| s.to_string());
        let request_id = ev.request_id.inner().clone();
        let key = request_key(tab, &request_id);
        let is_document = matches!(ev.r#type, Some(network::ResourceType::Document));
        if is_document {
            self.learn_first_party_origin(&ev.request.url);
        }
        // A GET document request in the main frame starts a new document
        // (guarded form POSTs are answered in place and do not).
        let main_document = is_document
            && ev.redirect_response.is_none()
            && ev.request.method.eq_ignore_ascii_case("GET")
            && main_frame.is_some_and(|main| {
                ev.frame_id
                    .as_ref()
                    .is_some_and(|frame| frame.inner() == main)
            });
        // The write guard already logged this request (events from separate
        // CDP streams can arrive in either order).
        if self.is_guarded_request(&key) {
            self.request_extra_headers.remove(&key);
            return Ok(());
        }
        if let Some(redirect) = ev.redirect_response.as_ref() {
            self.finish_redirect_hop(&key, redirect).await?;
        }
        let method = HttpMethod::from_str_lossy(&ev.request.method);
        let url = ev.request.url.clone();
        let mut headers = redact_headers(&headers_to_btreemap(&ev.request.headers));
        if let Some((_, extra)) = self.request_extra_headers.remove(&key) {
            for (k, v) in extra {
                headers.insert(k, v);
            }
        }
        let mut action_id = take_header_case_insensitive(&mut headers, "x-brokenapp-action-id");
        // Started after the action moved the page to another client-side
        // route: that route's load traffic, not the action's.
        let route_load = take_header_case_insensitive(&mut headers, ROUTE_LOAD_HEADER).is_some();
        let preparation = take_header_case_insensitive(&mut headers, PREPARATION_HEADER).is_some();
        let ignore_attribution = should_ignore_from_attribution(&url, &headers, ev.r#type.as_ref());
        if preparation || ignore_attribution {
            action_id = None;
        }
        let has_post_data = ev.request.has_post_data.unwrap_or(false);
        let post_data = None;
        // Capture the interaction at request start time so we don't misattribute
        // long-running requests to whatever interaction is current when they finish.
        let is_mutation = !crate::safety::is_read_only_method(&ev.request.method);
        let triggered_by = if route_load || preparation || ignore_attribution {
            None
        } else {
            self.attribute_request(
                tab,
                action_id.as_deref(),
                is_mutation,
                ev.has_user_gesture.unwrap_or(false),
                main_document,
            )
        };
        if main_document {
            // Everything after this request belongs to the new document.
            self.with_tab(tab, |state| state.document_epoch += 1);
        }
        // Cross-origin calls carry no action header (it is only stamped
        // same-origin); map them through the interaction they were attributed to.
        if !ignore_attribution && action_id.is_none() && self.is_cross_origin(&url) {
            action_id = triggered_by
                .as_ref()
                .and_then(|i| self.action_id_for(tab, i));
        }

        let initiator = &ev.initiator;
        let trace = Some(RequestTrace {
            trace_id: Uuid::new_v4().to_string(),
            cdp_request_id: request_id.clone(),
            page_id,
            frame_id: ev.frame_id.as_ref().map(|f| f.inner().clone()),
            document_url: Some(ev.document_url.clone()),
            initiator_type: Some(initiator.r#type.as_ref().to_string()),
            initiator_url: initiator.url.clone(),
            initiator_line_number: initiator.line_number,
            initiator_column_number: initiator.column_number,
            initiator_request_id: initiator.request_id.as_ref().map(|r| r.inner().clone()),
            has_user_gesture: ev.has_user_gesture,
            action_id,
        });
        self.pending.insert(
            key,
            PendingRequest {
                started_at: Instant::now(),
                trace,
                method,
                url,
                headers,
                has_post_data,
                post_data,
                response: None,
                triggered_by,
                preparation,
                ignore_attribution,
            },
        );
        Ok(())
    }

    async fn on_request_will_be_sent_extra_info(
        &self,
        ev: &network::EventRequestWillBeSentExtraInfo,
        tab: &TabKey,
    ) -> Result<()> {
        let request_id = request_key(tab, ev.request_id.inner());
        if self.is_guarded_request(&request_id) {
            return Ok(());
        }
        let headers = redact_headers(&headers_to_btreemap(&ev.headers));
        if let Some(mut pending) = self.pending.get_mut(&request_id) {
            self.merge_pending_request_headers(tab, &mut pending, headers);
            return Ok(());
        }
        // Keep internal stamps only until requestWillBeSent consumes them;
        // neither marker is stored in the eventual request headers.
        self.request_extra_headers.insert(request_id, headers);
        Ok(())
    }

    fn merge_pending_request_headers(
        &self,
        tab: &TabKey,
        pending: &mut PendingRequest,
        mut headers: BTreeMap<String, String>,
    ) {
        let action_id = take_header_case_insensitive(&mut headers, "x-brokenapp-action-id");
        let _ = take_header_case_insensitive(&mut headers, ROUTE_LOAD_HEADER);
        pending.preparation |=
            take_header_case_insensitive(&mut headers, PREPARATION_HEADER).is_some();
        pending.ignore_attribution |= should_ignore_from_attribution(&pending.url, &headers, None);
        if pending.preparation || pending.ignore_attribution {
            pending.triggered_by = None;
            if let Some(trace) = pending.trace.as_mut() {
                trace.action_id = None;
            }
        } else if let Some(action_id) = action_id {
            if let Some(interaction) = self.action_interaction(tab, &action_id) {
                pending.triggered_by = Some(interaction);
                if let Some(trace) = pending.trace.as_mut() {
                    trace.action_id = Some(action_id);
                }
            } else if let Some(trace) = pending.trace.as_mut() {
                if trace.action_id.is_none() {
                    trace.action_id = Some(action_id);
                }
            }
        }
        pending.headers.extend(headers);
    }

    /// Drop long-lived SSE streams (`text/event-stream`) from in-flight tracking
    /// as soon as response headers arrive so they never accumulate or log
    /// spurious `ERR_ABORTED` failures / misattributions on tab close.
    fn drop_if_sse_response(&self, request_id: &str, mime_type: &str) -> bool {
        if crate::network::filters::is_sse_content_type(Some(mime_type)) {
            self.pending.remove(request_id);
            self.request_extra_headers.remove(request_id);
            self.response_extra_info.remove(request_id);
            return true;
        }
        false
    }

    async fn on_response_received(
        &self,
        ev: &network::EventResponseReceived,
        tab: &TabKey,
    ) -> Result<()> {
        let request_id = request_key(tab, ev.request_id.inner());
        if self.drop_if_sse_response(&request_id, &ev.response.mime_type) {
            return Ok(());
        }
        if let Some(mut pending) = self.pending.get_mut(&request_id) {
            let status = ev.response.status as u16;
            let headers = redact_headers(&headers_to_btreemap(&ev.response.headers));
            let mime_type = ev.response.mime_type.clone();
            pending.response = Some(HttpResponseLog {
                status,
                headers,
                mime_type: Some(mime_type),
                body_snippet: None,
            });

            if let Some((_, extra)) = self.response_extra_info.remove(&request_id) {
                if let Some(ref mut resp) = pending.response {
                    resp.status = extra.status;
                    for (k, v) in extra.headers {
                        resp.headers.insert(k, v);
                    }
                } else {
                    pending.response = Some(HttpResponseLog {
                        status: extra.status,
                        headers: extra.headers,
                        mime_type: None,
                        body_snippet: None,
                    });
                }
            }
        }
        Ok(())
    }

    async fn on_response_received_extra_info(
        &self,
        ev: &network::EventResponseReceivedExtraInfo,
        tab: &TabKey,
    ) -> Result<()> {
        let request_id = request_key(tab, ev.request_id.inner());
        if self.is_guarded_request(&request_id) {
            return Ok(());
        }
        let status = ev.status_code.clamp(0, u16::MAX as i64) as u16;
        let headers = redact_headers(&headers_to_btreemap(&ev.headers));

        if let Some(mut pending) = self.pending.get_mut(&request_id) {
            match pending.response.as_mut() {
                Some(resp) => {
                    resp.status = status;
                    for (k, v) in headers {
                        resp.headers.insert(k, v);
                    }
                }
                None => {
                    pending.response = Some(HttpResponseLog {
                        status,
                        headers,
                        mime_type: None,
                        body_snippet: None,
                    });
                }
            }
            return Ok(());
        }

        self.response_extra_info
            .insert(request_id, ResponseExtraInfo { status, headers });
        Ok(())
    }

    async fn on_loading_finished(
        &self,
        page: &Page,
        ev: &network::EventLoadingFinished,
        tab: &TabKey,
    ) -> Result<()> {
        let request_id = request_key(tab, ev.request_id.inner());
        if self.forget_if_guarded(&request_id) {
            return Ok(());
        }
        let Some((_, mut pending)) = self.pending.remove(&request_id) else {
            return Ok(());
        };

        if let Some((_, extra)) = self.request_extra_headers.remove(&request_id) {
            self.merge_pending_request_headers(tab, &mut pending, extra);
        }
        if let Some((_, extra)) = self.response_extra_info.remove(&request_id) {
            match pending.response.as_mut() {
                Some(resp) => {
                    resp.status = extra.status;
                    for (k, v) in extra.headers {
                        resp.headers.insert(k, v);
                    }
                }
                None => {
                    pending.response = Some(HttpResponseLog {
                        status: extra.status,
                        headers: extra.headers,
                        mime_type: None,
                        body_snippet: None,
                    });
                }
            }
        }

        let duration_ms = pending.started_at.elapsed().as_secs_f64() * 1000.0;

        // Best-effort request post data capture (JSON, forms, etc.), bounded
        // so a slow/evicted body never stalls `Fetch.requestPaused`.
        let mut raw_post_data: Option<String> = None;
        if pending.has_post_data && !pending.ignore_attribution {
            if let Ok(Ok(res)) = tokio::time::timeout(
                CDP_BODY_FETCH_TIMEOUT,
                page.execute(network::GetRequestPostDataParams::new(
                    ev.request_id.clone(),
                )),
            )
            .await
            {
                raw_post_data = Some(res.result.post_data);
            }
        }
        let json_request_sample = raw_post_data
            .as_deref()
            .filter(|s| s.len() <= self.cfg.limits.max_body_bytes)
            .and_then(|s| parse_request_body(s))
            .map(|mut v| {
                // Avoid storing secrets in memory; schemas are inferred from keys/types.
                redact_json_value(&mut v);
                v
            });

        pending.post_data = raw_post_data.as_deref().map(|s| {
            let cap = self.cfg.limits.max_body_bytes;
            let mut s = redact_post_data(s);
            truncate_at_char_boundary(&mut s, cap);
            s
        });

        let mut body_snippet: Option<String> = None;
        let mut json_sample: Option<serde_json::Value> = None;

        if !pending.ignore_attribution
            && let Some(ref resp) = pending.response
            && should_fetch_response_body(&pending.url, resp.mime_type.as_deref())
            && let Ok(Ok(res)) = tokio::time::timeout(
                CDP_BODY_FETCH_TIMEOUT,
                page.execute(network::GetResponseBodyParams::new(ev.request_id.clone())),
            )
            .await
        {
            let network::GetResponseBodyReturns {
                body,
                base64_encoded,
            } = res.result;
            let mut body = body;
            if base64_encoded {
                use base64::Engine as _;
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&body) {
                    body = String::from_utf8_lossy(&bytes).to_string();
                }
            }
            let cap = self.cfg.limits.max_body_bytes;
            truncate_at_char_boundary(&mut body, cap);
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&body) {
                // Scrub sensitive fields/tokens before retaining schema samples
                // or any body snippet in memory.
                redact_json_value(&mut v);
                let mut scrubbed = v.to_string();
                truncate_at_char_boundary(&mut scrubbed, cap);
                body_snippet = Some(scrubbed);
                json_sample = Some(v);
            } else {
                let mut scrubbed = redact_response_body(&body);
                truncate_at_char_boundary(&mut scrubbed, cap);
                body_snippet = Some(scrubbed);
            }
        }

        if let Some(ref mut resp) = pending.response {
            resp.body_snippet = body_snippet.clone();
        }

        let triggered_by = pending.triggered_by.clone();
        let occurred_at = DateTime::<Utc>::from(std::time::SystemTime::now());
        let mut entry = TrafficEntry {
            occurred_at,
            trace: pending.trace.clone(),
            request: HttpRequestLog {
                method: pending.method,
                url: pending.url.clone(),
                headers: pending.headers.clone(),
                post_data: pending.post_data.clone(),
            },
            response: pending.response.clone(),
            failure: None,
            triggered_by,
            is_api: None,
            duration_ms: Some(duration_ms),
            attribution: None,
        };
        entry.is_api = Some(crate::network::filters::is_application_traffic(&entry));

        self.record_entry(entry, json_sample, json_request_sample, None)
            .await?;
        Ok(())
    }

    /// A redirect reuses the request id for the next hop; log the hop that
    /// just ended (e.g. `POST /login -> 303`) instead of silently replacing
    /// it with the follow-up request.
    async fn finish_redirect_hop(
        &self,
        request_id: &str,
        redirect: &network::Response,
    ) -> Result<()> {
        let Some((_, hop)) = self.pending.remove(request_id) else {
            return Ok(());
        };
        let response = HttpResponseLog {
            status: redirect.status.clamp(0, i64::from(u16::MAX)) as u16,
            headers: redact_headers(&headers_to_btreemap(&redirect.headers)),
            mime_type: Some(redirect.mime_type.clone()),
            body_snippet: None,
        };
        let mut entry = TrafficEntry {
            occurred_at: DateTime::<Utc>::from(std::time::SystemTime::now()),
            trace: hop.trace,
            request: HttpRequestLog {
                method: hop.method,
                url: hop.url,
                headers: hop.headers,
                post_data: None,
            },
            response: Some(response),
            failure: None,
            triggered_by: hop.triggered_by,
            is_api: None,
            duration_ms: Some(hop.started_at.elapsed().as_secs_f64() * 1000.0),
            attribution: None,
        };
        entry.is_api = Some(crate::network::filters::is_application_traffic(&entry));
        self.record_entry(entry, None, None, None).await
    }

    /// For a write-guarded request id: drop any request state the Network
    /// events created and report `true` (the guard already logged it).
    fn forget_if_guarded(&self, request_id: &str) -> bool {
        if !self.is_guarded_request(request_id) {
            return false;
        }
        self.pending.remove(request_id);
        self.request_extra_headers.remove(request_id);
        self.response_extra_info.remove(request_id);
        true
    }

    async fn on_loading_failed(
        &self,
        page: &Page,
        ev: &network::EventLoadingFailed,
        tab: &TabKey,
    ) -> Result<()> {
        let request_id = request_key(tab, ev.request_id.inner());
        if self.forget_if_guarded(&request_id) {
            return Ok(());
        }
        let Some((_, mut pending)) = self.pending.remove(&request_id) else {
            return Ok(());
        };

        if let Some((_, extra)) = self.request_extra_headers.remove(&request_id) {
            self.merge_pending_request_headers(tab, &mut pending, extra);
        }
        if let Some((_, extra)) = self.response_extra_info.remove(&request_id) {
            match pending.response.as_mut() {
                Some(resp) => {
                    resp.status = extra.status;
                    for (k, v) in extra.headers {
                        resp.headers.insert(k, v);
                    }
                }
                None => {
                    pending.response = Some(HttpResponseLog {
                        status: extra.status,
                        headers: extra.headers,
                        mime_type: None,
                        body_snippet: None,
                    });
                }
            }
        }

        let duration_ms = pending.started_at.elapsed().as_secs_f64() * 1000.0;
        let occurred_at = DateTime::<Utc>::from(std::time::SystemTime::now());
        let triggered_by = pending.triggered_by.clone();

        // Best-effort: capture request post data even on failures (bounded).
        if pending.post_data.is_none() && pending.has_post_data && !pending.ignore_attribution {
            if let Ok(Ok(res)) = tokio::time::timeout(
                CDP_BODY_FETCH_TIMEOUT,
                page.execute(network::GetRequestPostDataParams::new(
                    ev.request_id.clone(),
                )),
            )
            .await
            {
                let cap = self.cfg.limits.max_body_bytes;
                let mut s = redact_post_data(&res.result.post_data);
                truncate_at_char_boundary(&mut s, cap);
                pending.post_data = Some(s);
            }
        }

        let mut entry = TrafficEntry {
            occurred_at,
            trace: pending.trace.clone(),
            request: HttpRequestLog {
                method: pending.method,
                url: pending.url.clone(),
                headers: pending.headers.clone(),
                post_data: pending.post_data.clone(),
            },
            response: pending.response.clone(),
            failure: Some(ev.error_text.clone()),
            triggered_by,
            is_api: None,
            duration_ms: Some(duration_ms),
            attribution: None,
        };
        entry.is_api = Some(crate::network::filters::is_application_traffic(&entry));

        if is_auth_trace(entry.trace.as_ref()) {
            return Ok(());
        }

        // Ignore aborted/failed SSE, Next.js HMR/dev-tool, and browser telemetry
        // beacons so they do not generate noisy error findings.
        if pending.ignore_attribution || should_ignore_from_endpoints(&entry) {
            return Ok(());
        }

        // Always keep failures in memory.
        self.error_traffic.lock().await.push(entry.clone());
        if let Some(w) = self.writer.as_ref() {
            let key = endpoint_identity(&entry.request, self.first_party_origin().as_deref())
                .ok()
                .map(|id| id.key.to_string());
            if let Err(err) = w.append_annotated(&entry, key.as_deref(), None).await {
                tracing::warn!(error = ?err, "failed to append failed-request network.jsonl row");
            }
        }
        Ok(())
    }

    /// Fold one request into the endpoint map and append its `network.jsonl`
    /// row. `write_guard` marks a request the guard stopped: it is attributed
    /// like any other call but has no response, timing, or error semantics.
    async fn record_entry(
        &self,
        mut entry: TrafficEntry,
        json_response_sample: Option<serde_json::Value>,
        json_request_sample: Option<serde_json::Value>,
        write_guard: Option<WriteGuardAction>,
    ) -> Result<()> {
        // Credentials, custom form fields and token-bearing responses must
        // never reach network.jsonl, endpoint samples, checkpoints or bugs.
        if is_auth_trace(entry.trace.as_ref()) {
            return Ok(());
        }
        // Drop successful (2xx/304) static assets and dev-server module/HMR
        // loads (Vite `.ts`/`.tsx`/`/@fs/`/`/node_modules/`, bundles, fonts,
        // images) before endpoint aggregation or `network.jsonl` serialization.
        // Failed (4xx/5xx) static assets, HTML documents, redirects, APIs, and
        // write-guarded requests are always preserved.
        if write_guard.is_none() && crate::network::filters::is_static_or_dev_module_noise(&entry) {
            return Ok(());
        }
        // SSE streams, Next.js HMR/dev-tool requests, and browser CSP/telemetry
        // beacons are never application endpoints and must never be attributed
        // to a UI control.
        if should_ignore_from_endpoints(&entry) {
            entry.triggered_by = None;
            entry.is_api = Some(false);
            if let Some(trace) = entry.trace.as_mut() {
                trace.action_id = None;
            }
            if let Some(w) = self.writer.as_ref()
                && let Err(err) = w.append_annotated(&entry, None, write_guard).await
            {
                tracing::warn!(error = ?err, "failed to append ignored network.jsonl row");
            }
            return Ok(());
        }
        let EndpointIdentity {
            key: endpoint_key,
            url_pattern,
            path_params,
            query_params,
        } = match endpoint_identity(&entry.request, self.first_party_origin().as_deref()) {
            Ok(v) => v,
            Err(_) => {
                if let Some(w) = self.writer.as_ref()
                    && let Err(err) = w.append_annotated(&entry, None, write_guard).await
                {
                    tracing::warn!(error = ?err, "failed to append unkeyed network.jsonl row");
                }
                return Ok(());
            }
        };
        let observed_query_params = query_params.clone();

        // Update endpoint aggregation.
        let status = entry.response.as_ref().map(|r| r.status);
        let dur = entry.duration_ms.unwrap_or(0.0);

        if status == Some(429) {
            let retry_after = entry
                .response
                .as_ref()
                .and_then(|r| header_value(&r.headers, "retry-after"))
                .and_then(parse_retry_after);
            self.record_rate_limit_event(retry_after);
        }

        let mut ep = self
            .endpoints
            .entry(endpoint_key.clone())
            .or_insert_with(|| ApiEndpoint {
                key: endpoint_key.clone(),
                url_pattern,
                path_params,
                query_params,
                request_headers: entry.request.headers.clone(),
                request_body_schema: None,
                response_status_codes: Vec::new(),
                response_body_schema: None,
                auth_required: false,
                auth_type: None,
                observed_count: 0,
                status_code_counts: BTreeMap::new(),
                error_responses: Vec::new(),
                avg_response_time_ms: 0.0,
                triggered_by: Vec::new(),
                request_body_samples: Vec::new(),
                response_body_samples: Vec::new(),
            });

        // Mark endpoints as authenticated when we observe auth signals. This is
        // important for security/compliance reporting and for generating
        // meaningful API tests.
        if let Some((required, auth_type)) = detect_auth_from_request(&entry.request) {
            if required {
                ep.auth_required = true;
                if ep.auth_type.is_none() {
                    ep.auth_type = auth_type;
                }

                // If the first observation was a CORS preflight (or otherwise
                // lacked auth headers), upgrade the stored header sample so the
                // spec reflects that this endpoint was hit with auth.
                if header_value(&ep.request_headers, "authorization").is_none() {
                    if let Some(v) = header_value(&entry.request.headers, "authorization") {
                        ep.request_headers
                            .insert("authorization".to_string(), v.to_string());
                    }
                }
                if header_value(&ep.request_headers, "cookie").is_none() {
                    if let Some(v) = header_value(&entry.request.headers, "cookie") {
                        ep.request_headers
                            .insert("cookie".to_string(), v.to_string());
                    }
                }
            }
        }

        merge_query_params(&mut ep.query_params, &observed_query_params);

        if let Some(ref triggered) = entry.triggered_by {
            if !ep.triggered_by.contains(triggered) {
                ep.triggered_by.push(triggered.clone());
            }
        }

        ep.observed_count = ep.observed_count.saturating_add(1);
        if write_guard.is_none() {
            let n = ep.observed_count as f64;
            ep.avg_response_time_ms = if n <= 1.0 {
                dur
            } else {
                // incremental average
                ((ep.avg_response_time_ms * (n - 1.0)) + dur) / n
            };
        }

        if let Some(status) = status {
            *ep.status_code_counts.entry(status).or_insert(0) += 1;
            if !ep.response_status_codes.contains(&status) {
                ep.response_status_codes.push(status);
                ep.response_status_codes.sort_unstable();
            }

            if status >= 500 {
                ep.error_responses.push(ErrorResponse {
                    status,
                    body_snippet: entry.response.as_ref().and_then(|r| r.body_snippet.clone()),
                });
            }
        }

        // Capture schema samples.
        if let Some(sample) = json_response_sample {
            if ep.response_body_samples.len() < self.cfg.limits.max_schema_samples {
                ep.response_body_samples.push(sample);
            }
        }
        if let Some(sample) = json_request_sample {
            if ep.request_body_samples.len() < self.cfg.limits.max_schema_samples {
                ep.request_body_samples.push(sample);
            }
        }

        drop(ep);

        // Store traffic entry if requested, or if it's an error. Guarded
        // writes never reached a server, so they are never errors (no
        // NetworkRequestFailure / ApiError findings).
        let is_error = write_guard.is_none()
            && (status.map(|s| s >= 400).unwrap_or(false) || entry.failure.is_some());
        if is_error {
            self.error_traffic.lock().await.push(entry.clone());
        }
        if let Some(w) = self.writer.as_ref() {
            let key = endpoint_key.to_string();
            if let Err(err) = w.append_annotated(&entry, Some(&key), write_guard).await {
                tracing::warn!(error = ?err, "failed to append network.jsonl row");
            }
        }

        Ok(())
    }
}

/// Decode `Fetch.requestPaused` post data entries (base64 chunks) into text.
fn decode_post_data_entries(entries: Option<&[network::PostDataEntry]>) -> Option<String> {
    use base64::Engine as _;
    let entries = entries?;
    let mut bytes = Vec::new();
    for entry in entries {
        let Some(chunk) = entry.bytes.as_ref() else {
            continue;
        };
        let encoded: &str = chunk.as_ref();
        match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(decoded) => bytes.extend_from_slice(&decoded),
            Err(_) => return None,
        }
    }
    if bytes.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn truncate_at_char_boundary(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

fn parse_request_body(s: &str) -> Option<serde_json::Value> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }

    // JSON
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return serde_json::from_str::<serde_json::Value>(trimmed).ok();
    }

    // Form-encoded: a=b&c=d...
    if looks_like_form_urlencoded(trimmed) {
        return parse_form_urlencoded(trimmed);
    }

    // Multipart form-data (best-effort): extract field names.
    if looks_like_multipart_form_data(trimmed) {
        return parse_multipart_form_data(trimmed);
    }

    None
}

fn redact_post_data(post_data: &str) -> String {
    // Best-effort redaction to avoid leaking credentials into `network.jsonl`.
    // The spec output only emits inferred schemas, not raw samples.
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(post_data) {
        redact_json_value(&mut v);
        return v.to_string();
    }

    // Form-encoded bodies: a=b&c=d...
    if post_data.contains('=') && post_data.contains('&') && !post_data.contains('{') {
        let mut out = Vec::new();
        for part in post_data.split('&') {
            let mut it = part.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if is_sensitive_field_name(k) {
                out.push(format!("{k}=<redacted>"));
            } else {
                out.push(format!("{k}={v}"));
            }
        }
        return out.join("&");
    }

    post_data.to_string()
}

fn looks_like_form_urlencoded(body: &str) -> bool {
    let s = body.trim();
    if s.is_empty() {
        return false;
    }
    // Multipart uploads are not URL-encoded.
    if s.starts_with("----") {
        return false;
    }
    // Must at least contain `k=v`.
    if !s.contains('=') {
        return false;
    }
    // Heuristic: avoid treating JSON-ish strings as urlencoded.
    if s.contains('{') || s.contains('[') {
        return false;
    }
    true
}

fn looks_like_multipart_form_data(body: &str) -> bool {
    let s = body.trim_start();
    if !s.starts_with("--") {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    lower.contains("content-disposition: form-data")
}

fn parse_form_urlencoded(body: &str) -> Option<serde_json::Value> {
    use serde_json::{Map, Value};

    let mut map: Map<String, Value> = Map::new();
    for (k, v) in url::form_urlencoded::parse(body.as_bytes()) {
        let key = k.into_owned();
        let val = Value::String(v.into_owned());
        match map.get_mut(&key) {
            None => {
                map.insert(key, val);
            }
            Some(existing) => {
                if existing.is_array() {
                    existing.as_array_mut().unwrap().push(val);
                } else {
                    let prev = std::mem::replace(existing, Value::Null);
                    *existing = Value::Array(vec![prev, val]);
                }
            }
        }
    }

    if map.is_empty() {
        None
    } else {
        Some(Value::Object(map))
    }
}

fn parse_multipart_form_data(body: &str) -> Option<serde_json::Value> {
    use serde_json::{Map, Value};

    let mut map: Map<String, Value> = Map::new();

    for line in body.lines() {
        let l = line.trim_end_matches('\r').trim();
        if !l.to_ascii_lowercase().starts_with("content-disposition:") {
            continue;
        }
        // Example:
        // Content-Disposition: form-data; name="foo"; filename="bar.png"
        let lower = l.to_ascii_lowercase();
        if !lower.contains("form-data") {
            continue;
        }
        let Some(name) = extract_quoted_attr(l, "name") else {
            continue;
        };

        let is_file = lower.contains("filename=");
        let val = if is_file {
            Value::String("<file>".to_string())
        } else {
            Value::String("<redacted>".to_string())
        };

        match map.get_mut(&name) {
            None => {
                map.insert(name, val);
            }
            Some(existing) => {
                if existing.is_array() {
                    existing.as_array_mut().unwrap().push(val);
                } else {
                    let prev = std::mem::replace(existing, Value::Null);
                    *existing = Value::Array(vec![prev, val]);
                }
            }
        }
    }

    if map.is_empty() {
        None
    } else {
        Some(Value::Object(map))
    }
}

fn extract_quoted_attr(s: &str, attr: &str) -> Option<String> {
    // Find attr="...".
    let pat = format!("{attr}=\"");
    let idx = s.find(&pat)?;
    let rest = &s[idx + pat.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn redact_text_secrets(input: &str) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    static JWT_RE: OnceLock<Regex> = OnceLock::new();
    static KEY_RE: OnceLock<Regex> = OnceLock::new();
    static BEARER_RE: OnceLock<Regex> = OnceLock::new();
    static COOKIE_RE: OnceLock<Regex> = OnceLock::new();
    static URL_CREDS_RE: OnceLock<Regex> = OnceLock::new();

    let jwt = JWT_RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b").unwrap()
    });
    let key = KEY_RE.get_or_init(|| {
        Regex::new(
            r"\b(sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|xox[bpoar]-[A-Za-z0-9-]{16,}|glpat-[A-Za-z0-9_-]{16,})\b",
        )
        .unwrap()
    });
    let bearer =
        BEARER_RE.get_or_init(|| Regex::new(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}").unwrap());
    let cookie = COOKIE_RE
        .get_or_init(|| Regex::new(r"(?i)((?:set-)?cookie\s*[:=]\s*)[^\r\n;]{6,}").unwrap());
    let url_creds = URL_CREDS_RE
        .get_or_init(|| Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)([^:@/\s]+):([^@/\s]+)@").unwrap());

    let out = jwt.replace_all(input, "<redacted>");
    let out = key.replace_all(&out, "<redacted>");
    let out = bearer.replace_all(&out, "${1}<redacted>");
    let out = cookie.replace_all(&out, "${1}<redacted>");
    let out = url_creds.replace_all(&out, "${1}***:***@");
    out.into_owned()
}

fn redact_response_body(body: &str) -> String {
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(body) {
        redact_json_value(&mut v);
        return v.to_string();
    }
    redact_text_secrets(body)
}

fn redact_json_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, vv) in map.iter_mut() {
                if is_sensitive_field_name(k) {
                    *vv = serde_json::Value::String("<redacted>".to_string());
                } else {
                    redact_json_value(vv);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for vv in arr {
                redact_json_value(vv);
            }
        }
        serde_json::Value::String(s) => {
            let scrubbed = redact_text_secrets(s);
            if scrubbed != *s {
                *s = scrubbed;
            }
        }
        _ => {}
    }
}

fn merge_query_params(
    target: &mut Vec<crate::types::api::QueryParam>,
    observed: &[crate::types::api::QueryParam],
) {
    const MAX_SAMPLES_PER_PARAM: usize = 10;

    for qp in observed {
        let name = qp.name.trim().to_string();
        if name.is_empty() {
            continue;
        }

        let mut samples: Vec<String> = qp.value_samples.clone().unwrap_or_default();
        if is_sensitive_field_name(&name) {
            samples.clear();
            samples.push("<redacted>".to_string());
        }
        if samples.is_empty() {
            // Always record param presence even if there's no captured value.
            samples.push(String::new());
        }
        if samples.len() > MAX_SAMPLES_PER_PARAM {
            samples.truncate(MAX_SAMPLES_PER_PARAM);
        }

        if let Some(existing) = target.iter_mut().find(|e| e.name == name) {
            let list = existing.value_samples.get_or_insert_with(Vec::new);
            for s in samples {
                if list.len() >= MAX_SAMPLES_PER_PARAM {
                    break;
                }
                if !list.contains(&s) {
                    list.push(s);
                }
            }
        } else {
            target.push(crate::types::api::QueryParam {
                name,
                value_samples: Some(samples),
            });
        }
    }

    target.sort_by(|a, b| a.name.cmp(&b.name));
}

fn is_sensitive_field_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "password"
            | "pass"
            | "passwd"
            | "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "jwt"
            | "bearer"
            | "secret"
            | "client_secret"
            | "api_key"
            | "apikey"
            | "access_key"
            | "secret_key"
            | "private_key"
            | "authorization"
            | "cookie"
            | "set_cookie"
            | "set-cookie"
            | "csrf"
            | "csrf_token"
            | "session"
            | "session_id"
            | "sessionid"
            | "otp"
            | "mfa"
            | "code"
            | "ssn"
            | "credit_card"
            | "card_number"
            | "cvv"
    )
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    parse_retry_after_with_now(value, Utc::now())
}

fn parse_retry_after_with_now(value: &str, now: DateTime<Utc>) -> Option<Duration> {
    let s = value.trim();
    if s.is_empty() {
        return None;
    }

    // Retry-After: <delay-seconds>
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }

    // Retry-After: <http-date>
    //
    // In practice servers almost always use IMF-fixdate with a trailing "GMT".
    let dt = match chrono::DateTime::parse_from_rfc2822(s) {
        Ok(v) => v,
        Err(_) => {
            let upper = s.to_ascii_uppercase();
            let candidate = if upper.ends_with(" GMT") && s.len() >= 4 {
                let base = s[..(s.len() - 4)].trim_end();
                format!("{base} +0000")
            } else if upper.ends_with("GMT") && s.len() >= 3 {
                let base = s[..(s.len() - 3)].trim_end();
                format!("{base} +0000")
            } else {
                return None;
            };
            chrono::DateTime::parse_from_rfc2822(&candidate).ok()?
        }
    };
    let dt = dt.with_timezone(&Utc);
    let remaining = dt.signed_duration_since(now);
    if remaining <= chrono::Duration::zero() {
        return Some(Duration::from_secs(0));
    }
    remaining.to_std().ok()
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.as_str());
        }
    }
    None
}

fn detect_auth_from_request(req: &HttpRequestLog) -> Option<(bool, Option<String>)> {
    // For CORS preflight, infer intended auth header usage from the requested headers.
    if req.method == HttpMethod::Options {
        if let Some(v) = header_value(&req.headers, "access-control-request-headers") {
            let lower = v.to_ascii_lowercase();
            if lower.contains("authorization") {
                return Some((true, Some("bearer".to_string())));
            }
            if lower.contains("cookie") {
                return Some((true, Some("cookie".to_string())));
            }
        }
        return None;
    }

    if let Some(v) = header_value(&req.headers, "authorization") {
        let lower = v.trim().to_ascii_lowercase();
        let kind = if lower.starts_with("bearer ") {
            "bearer"
        } else if lower.starts_with("basic ") {
            "basic"
        } else {
            "authorization"
        };
        return Some((true, Some(kind.to_string())));
    }

    if header_value(&req.headers, "cookie").is_some() {
        return Some((true, Some("cookie".to_string())));
    }

    None
}

fn redact_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            if k.eq_ignore_ascii_case("set-cookie") {
                return (k.clone(), redact_set_cookie_header(v));
            }
            if k.eq_ignore_ascii_case("cookie") {
                return (k.clone(), redact_cookie_header(v));
            }
            if is_sensitive_header_name(k) {
                if k.eq_ignore_ascii_case("authorization") {
                    let lower = v.trim().to_ascii_lowercase();
                    if lower.starts_with("bearer ") {
                        return (k.clone(), "Bearer <redacted>".to_string());
                    }
                    if lower.starts_with("basic ") {
                        return (k.clone(), "Basic <redacted>".to_string());
                    }
                }
                (k.clone(), "<redacted>".to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

fn redact_cookie_header(value: &str) -> String {
    // Keep cookie names (useful for auth/session mapping), but redact values.
    // Example: "a=1; b=2" -> "a=<redacted>; b=<redacted>"
    let mut out = Vec::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut it = part.splitn(2, '=');
        let name = it.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        out.push(format!("{name}=<redacted>"));
    }
    out.join("; ")
}

fn redact_set_cookie_header(value: &str) -> String {
    // Keep cookie names and security attributes (Secure/HttpOnly/SameSite/etc),
    // but redact cookie values.
    //
    // CDP concatenates duplicates with "\n". Preserve that separator.
    let mut out_lines = Vec::new();
    for line in value.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(';');
        let first = parts.next().unwrap_or("").trim();
        let cookie_name = first.split('=').next().unwrap_or("").trim();
        if cookie_name.is_empty() {
            out_lines.push("<redacted>".to_string());
            continue;
        }
        let mut out = format!("{cookie_name}=<redacted>");
        let attrs: Vec<&str> = parts.map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
        if !attrs.is_empty() {
            out.push_str("; ");
            out.push_str(&attrs.join("; "));
        }
        out_lines.push(out);
    }
    out_lines.join("\n")
}

fn is_sensitive_header_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-csrf-token"
    )
}

fn headers_to_btreemap(h: &network::Headers) -> BTreeMap<String, String> {
    let Some(obj) = h.inner().as_object() else {
        return BTreeMap::new();
    };
    obj.iter()
        .map(|(k, v)| {
            let s = if let Some(s) = v.as_str() {
                s.to_string()
            } else {
                v.to_string()
            };
            (k.clone(), s)
        })
        .collect()
}

fn take_header_case_insensitive(
    headers: &mut BTreeMap<String, String>,
    name: &str,
) -> Option<String> {
    let keys: Vec<_> = headers
        .keys()
        .filter(|k| k.eq_ignore_ascii_case(name))
        .cloned()
        .collect();
    let mut value = None;
    for key in keys {
        let removed = headers.remove(&key);
        if value.is_none() {
            value = removed;
        }
    }
    value
}

/// Endpoint identity of one request plus the URL facts aggregated with it.
struct EndpointIdentity {
    key: EndpointKey,
    url_pattern: String,
    path_params: Vec<String>,
    query_params: Vec<crate::types::api::QueryParam>,
}

/// Compute the endpoint key a request is aggregated under.
///
/// - Same-origin (or unknown first-party origin): `METHOD /path/:param`.
/// - Cross-origin: the origin is kept, `POST https://x.supabase.co/rest/v1/cart`.
/// - GraphQL operations: `POST /graphql#MUTATION Name`.
/// - Next.js Server Actions (POST with a `Next-Action` header):
///   `POST /path#action:<id>`.
fn endpoint_identity(
    request: &HttpRequestLog,
    first_party_origin: Option<&str>,
) -> Result<EndpointIdentity> {
    let parsed = Url::parse(&request.url).context("parse url")?;
    let mut template = path_to_template(parsed.path());

    let mut path_params = Vec::new();
    for seg in template.split('/') {
        if seg.starts_with(':') {
            path_params.push(seg.trim_start_matches(':').to_string());
        }
    }

    let mut query_params = Vec::new();
    for (k, v) in parsed.query_pairs() {
        query_params.push(crate::types::api::QueryParam {
            name: k.to_string(),
            value_samples: Some(vec![v.to_string()]),
        });
    }

    let origin = parsed.origin();
    if origin.is_tuple() {
        let origin_str = origin.ascii_serialization();
        let comparable_origin = if let Some(rest) = origin_str.strip_prefix("ws://") {
            format!("http://{rest}")
        } else if let Some(rest) = origin_str.strip_prefix("wss://") {
            format!("https://{rest}")
        } else {
            origin_str.clone()
        };
        if first_party_origin.is_some_and(|fp| fp != origin_str && fp != comparable_origin) {
            template = format!("{origin_str}{template}");
        }
    }

    let mut key = EndpointKey {
        method: request.method,
        path_template: template.clone(),
    };
    if request.method == HttpMethod::Ws {
        if let Some(data) = request.post_data.as_deref() {
            let analysis = crate::safety::classify_ws_frame(&request.url, data);
            if let Some(op) = analysis.operation {
                key.path_template = format!("{template}#{op}");
            }
        }
    } else if let Some(op) =
        crate::network::graphql::detect_graphql_request(&request.url, request.post_data.as_deref())
    {
        key = crate::network::graphql::graphql_endpoint_key(&template, &op);
    } else if request.method == HttpMethod::Post {
        if let Some(action) = header_value(&request.headers, "next-action")
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            key.path_template = format!("{template}#action:{action}");
        }
    }

    Ok(EndpointIdentity {
        key,
        url_pattern: template,
        path_params,
        query_params,
    })
}

/// Appends `network.jsonl` rows.
///
/// Every row is flushed as it is written: the writer is dropped without an
/// async flush at scan end, so buffered rows (often the last actions' writes)
/// would otherwise be lost.
pub struct NetworkLogWriter {
    path: PathBuf,
    include_response_bodies: bool,
    inner: tokio::sync::Mutex<tokio::io::BufWriter<tokio::fs::File>>,
}

/// Borrowed serialization of a [`crate::types::api::NetworkLogRecord`].
#[derive(Serialize)]
struct NetworkLogLine<'a> {
    #[serde(flatten)]
    entry: &'a TrafficEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    write_guard: Option<WriteGuardAction>,
}

impl NetworkLogWriter {
    pub async fn new(path: PathBuf, mode: NetworkLogMode) -> Result<Self> {
        Self::new_with_options(path, mode, false).await
    }

    pub async fn new_with_options(
        path: PathBuf,
        mode: NetworkLogMode,
        include_response_bodies: bool,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create network log dir {}", parent.display()))?;
        }
        let mut opts = tokio::fs::OpenOptions::new();
        opts.create(true).write(true);
        match mode {
            NetworkLogMode::Truncate => {
                opts.truncate(true);
            }
            NetworkLogMode::Append => {
                opts.append(true);
            }
        }
        let f = opts
            .open(&path)
            .await
            .with_context(|| format!("open {}", path.display()))?;
        Ok(Self {
            path,
            include_response_bodies,
            inner: tokio::sync::Mutex::new(tokio::io::BufWriter::new(f)),
        })
    }

    pub async fn append(&self, entry: &TrafficEntry) -> Result<()> {
        self.append_annotated(entry, None, None).await
    }

    /// Append a row with its endpoint key and write-guard action (see
    /// [`crate::types::api::NetworkLogRecord`]).
    ///
    /// By default (`include_response_bodies == false`), `response.body_snippet`
    /// is omitted from `network.jsonl` so raw API payloads are not written to
    /// disk. When explicitly enabled, any retained snippet is scrubbed before
    /// serialization.
    pub async fn append_annotated(
        &self,
        entry: &TrafficEntry,
        endpoint_key: Option<&str>,
        write_guard: Option<WriteGuardAction>,
    ) -> Result<()> {
        let sanitized: Option<TrafficEntry> = if let Some(resp) = entry.response.as_ref()
            && resp.body_snippet.is_some()
        {
            let mut cloned = entry.clone();
            if let Some(r) = cloned.response.as_mut() {
                if self.include_response_bodies {
                    r.body_snippet = r.body_snippet.as_deref().map(redact_response_body);
                } else {
                    r.body_snippet = None;
                }
            }
            Some(cloned)
        } else {
            None
        };
        let entry_ref = sanitized.as_ref().unwrap_or(entry);
        let line = serde_json::to_string(&NetworkLogLine {
            entry: entry_ref,
            endpoint_key,
            write_guard,
        })
        .context("serialize traffic entry")?;
        let mut writer = self.inner.lock().await;
        writer
            .write_all(line.as_bytes())
            .await
            .context("write network log row")?;
        writer
            .write_all(b"\n")
            .await
            .context("write network log row")?;
        writer.flush().await.context("flush network log")?;
        Ok(())
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NetworkLogMode {
    Truncate,
    Append,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};

    use super::*;

    fn request(method: HttpMethod, url: &str, headers: &[(&str, &str)]) -> HttpRequestLog {
        HttpRequestLog {
            method,
            url: url.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            post_data: None,
        }
    }

    fn key_of(req: &HttpRequestLog, first_party: Option<&str>) -> String {
        endpoint_identity(req, first_party)
            .expect("endpoint identity")
            .key
            .to_string()
    }

    #[test]
    fn login_write_scope_only_allows_authorized_post_endpoints() {
        let scope = AuthWriteScope::default();
        scope.allow_url("http://localhost:3000/login");
        assert!(!scope.allows("POST", "http://localhost:3000/login?next=/dashboard"));
        assert!(scope.allows("POST", "http://localhost:3000/login"));
        assert!(!scope.allows("POST", "http://localhost:3000/login"));
        assert!(!scope.allows("POST", "http://localhost:3000/api/autosave"));
        assert!(!scope.allows("POST", "http://other.test/login"));
        assert!(!scope.allows("DELETE", "http://localhost:3000/login"));
    }

    #[test]
    fn login_write_scope_auth_origin_allows_same_origin_auth_posts_only() {
        let scope = AuthWriteScope::default();
        scope.allow_auth_origin("http://localhost:3000/login");

        for url in [
            "http://localhost:3000/api/auth/callback/credentials",
            "http://localhost:3000/api/auth/sign-in/email",
            "http://localhost:3000/api/login",
            "http://localhost:3000/login?callbackUrl=/admin",
            "http://localhost:3000/API/Auth/Callback/Credentials",
            "http://localhost:3000/auth/token",
            "http://localhost:3000/oauth/callback",
            "http://localhost:3000/api/sessions",
            "http://localhost:3000/api/verify",
        ] {
            assert!(
                scope.allows("POST", url),
                "expected POST {url} to be allowed"
            );
        }

        for (method, url) in [
            ("POST", "http://localhost:3000/api/autosave"),
            ("POST", "http://localhost:3000/api/orders"),
            ("POST", "http://localhost:3000/api/authors"),
            ("POST", "http://other.test/api/auth/callback/credentials"),
            ("POST", "http://localhost:3000/api/auth/signout"),
            ("DELETE", "http://localhost:3000/api/auth/session"),
        ] {
            assert!(
                !scope.allows(method, url),
                "expected {method} {url} to be denied"
            );
        }

        // Custom login path with query parameters is also allowed on the same origin.
        let custom = AuthWriteScope::default();
        custom.allow_auth_origin("http://localhost:3000/portal-entry");
        assert!(custom.allows(
            "POST",
            "http://localhost:3000/portal-entry?callbackUrl=/app"
        ));
        assert!(!custom.allows("POST", "http://localhost:3000/api/orders"));

        scope.clear_auth_origin();
        assert!(!scope.allows(
            "POST",
            "http://localhost:3000/api/auth/callback/credentials"
        ));
        assert!(!scope.allows("POST", "http://localhost:3000/login?callbackUrl=/admin"));
    }

    #[test]
    fn endpoint_keys_keep_cross_origin_hosts() {
        let fp = Some("http://localhost:3000");
        let same = request(HttpMethod::Post, "http://localhost:3000/api/orders/42", &[]);
        assert_eq!(key_of(&same, fp), "POST /api/orders/:id");
        let cross = request(
            HttpMethod::Post,
            "https://abc.supabase.co/rest/v1/cart?select=*",
            &[],
        );
        assert_eq!(
            key_of(&cross, fp),
            "POST https://abc.supabase.co/rest/v1/cart"
        );
        let other_port = request(HttpMethod::Get, "http://localhost:4000/items", &[]);
        assert_eq!(key_of(&other_port, fp), "GET http://localhost:4000/items");
        // Unknown first-party origin: keys stay path-only (old behaviour).
        assert_eq!(key_of(&cross, None), "POST /rest/v1/cart");
    }

    #[test]
    fn endpoint_keys_split_next_server_actions_and_graphql() {
        let fp = Some("http://localhost:3000");
        let action = request(
            HttpMethod::Post,
            "http://localhost:3000/cart",
            &[("Next-Action", "7f3a9c")],
        );
        assert_eq!(key_of(&action, fp), "POST /cart#action:7f3a9c");
        let mut gql = request(HttpMethod::Post, "https://api.example.test/graphql", &[]);
        gql.post_data = Some(r#"{"query":"mutation Refund { refund { ok } }"}"#.to_string());
        assert_eq!(
            key_of(&gql, fp),
            "POST https://api.example.test/graphql#MUTATION Refund"
        );
    }

    #[test]
    fn network_log_rows_carry_endpoint_and_write_guard() {
        let entry = TrafficEntry {
            occurred_at: Utc.timestamp_opt(1_700_000_000, 0).single().expect("ts"),
            trace: None,
            request: request(HttpMethod::Post, "http://localhost:3000/api/orders", &[]),
            response: None,
            failure: None,
            triggered_by: Some(InteractionRef {
                view: "view_0001".to_string(),
                selector: "#buy".to_string(),
            }),
            is_api: Some(true),
            duration_ms: None,
            attribution: None,
        };
        let line = serde_json::to_string(&NetworkLogLine {
            entry: &entry,
            endpoint_key: Some("POST /api/orders"),
            write_guard: Some(WriteGuardAction::Blocked),
        })
        .expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(value["write_guard"], "blocked");
        assert_eq!(value["endpoint_key"], "POST /api/orders");
        assert_eq!(value["triggered_by"]["selector"], "#buy");
        let record: crate::types::api::NetworkLogRecord =
            serde_json::from_str(&line).expect("record");
        assert_eq!(record.write_guard, Some(WriteGuardAction::Blocked));
        assert_eq!(record.entry.request.url, "http://localhost:3000/api/orders");
        // Plain TrafficEntry readers still parse the row.
        let plain: TrafficEntry = serde_json::from_str(&line).expect("traffic entry");
        assert_eq!(plain.request.method, HttpMethod::Post);
        // Unguarded rows omit the keys.
        let line = serde_json::to_string(&NetworkLogLine {
            entry: &entry,
            endpoint_key: None,
            write_guard: None,
        })
        .expect("serialize");
        assert!(!line.contains("write_guard"));
    }

    #[test]
    fn decodes_fetch_post_data_entries() {
        use base64::Engine as _;
        let chunk = |s: &str| network::PostDataEntry {
            bytes: Some(base64::engine::general_purpose::STANDARD.encode(s).into()),
        };
        let entries = vec![chunk("{\"a\":"), chunk("1}")];
        assert_eq!(
            decode_post_data_entries(Some(&entries)).as_deref(),
            Some("{\"a\":1}")
        );
        assert_eq!(decode_post_data_entries(None), None);
        assert_eq!(decode_post_data_entries(Some(&[])), None);
    }

    #[test]
    fn native_dialog_summary_is_compact() {
        let dialog = NativeDialog {
            kind: "confirm".to_string(),
            message: "Archive this item?".to_string(),
            url: "http://localhost/".to_string(),
            accepted: true,
            triggered_by: None,
            action_id: None,
            occurred_at: Utc::now(),
        };
        assert_eq!(dialog.summary(), "confirm: Archive this item?");
        let long = NativeDialog {
            message: "x".repeat(500),
            ..dialog
        };
        assert_eq!(long.summary().chars().count(), "confirm: ".len() + 201);
    }

    #[test]
    fn guarded_ids_suppress_network_rows() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        assert!(interceptor.write_guard_active());
        interceptor.mark_guarded("req-1");
        assert!(interceptor.forget_if_guarded("req-1"));
        assert!(!interceptor.forget_if_guarded("req-2"));
    }

    fn bump_document_epoch(interceptor: &NetworkInterceptor, tab: &TabKey) {
        interceptor.with_tab(tab, |state| state.document_epoch += 1);
    }

    fn interaction(view: &str, selector: &str) -> InteractionRef {
        InteractionRef {
            view: view.to_string(),
            selector: selector.to_string(),
        }
    }

    #[tokio::test]
    async fn interactions_do_not_claim_a_later_documents_requests() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        let shared = TabKey::shared();
        let click = interaction("view_0001", "#theme-card");
        interceptor
            .set_current_interaction(Some(click.clone()))
            .await;
        // Same document: the click owns its requests.
        assert_eq!(
            interceptor.attribute_request(&shared, None, true, false, false),
            Some(click.clone())
        );
        // The click navigates: the document request itself is the click's...
        assert_eq!(
            interceptor.attribute_request(&shared, None, false, true, true),
            Some(click.clone())
        );
        bump_document_epoch(&interceptor, &shared);
        // ...but the new document's bootstrap POST is not.
        assert_eq!(
            interceptor.attribute_request(&shared, None, true, false, false),
            None
        );
        // Nor through the time-window fallback once the click is cleared.
        interceptor.set_current_interaction(None).await;
        assert_eq!(
            interceptor.attribute_request(&shared, None, true, true, false),
            None
        );
        // The page-load marker collects load traffic across the navigation.
        let load = interaction("view_0002", PAGE_LOAD_SELECTOR);
        interceptor
            .set_current_interaction(Some(load.clone()))
            .await;
        bump_document_epoch(&interceptor, &shared);
        assert_eq!(
            interceptor.attribute_request(&shared, None, false, false, false),
            Some(load)
        );
        // Forgetting recent interactions disables the fallback entirely.
        interceptor
            .set_current_interaction(Some(click.clone()))
            .await;
        interceptor.set_current_interaction(None).await;
        interceptor.forget_recent_interactions().await;
        assert_eq!(
            interceptor.attribute_request(&shared, None, true, true, false),
            None
        );
    }

    #[test]
    fn cross_origin_requests_get_the_latest_action_id() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        interceptor.set_first_party_origin(&Url::parse("http://localhost:3000/").expect("url"));
        assert!(interceptor.is_cross_origin("https://abc.supabase.co/rest/v1/cart"));
        assert!(!interceptor.is_cross_origin("http://localhost:3000/api"));
        let shared = TabKey::shared();
        let click = interaction("view_0001", "#cart");
        interceptor.register_action("act-1", click.clone());
        assert_eq!(
            interceptor.action_id_for(&shared, &click).as_deref(),
            Some("act-1")
        );
        let other = interaction("view_0001", "#other");
        assert_eq!(interceptor.action_id_for(&shared, &other), None);
    }

    #[tokio::test]
    async fn preparation_scope_cleans_up_success_skip_error_timeout_and_cancel() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        let tab = TabKey::shared();
        let prior = interaction("view", "#addon");
        interceptor.register_action("prior", prior.clone());
        for outcome in ["ready", "skip", "error", "timeout", "cancel"] {
            interceptor.set_current_interaction_on(&tab, Some(prior.clone()));
            interceptor.set_current_interaction_on(&tab, None);
            let future = async {
                let _scope = interceptor.preparation_scope_on(&tab);
                assert_eq!(
                    interceptor.attribute_request(&tab, None, true, true, false),
                    None
                );
                assert_eq!(
                    interceptor.attribute_request(&tab, Some("prior"), false, false, false),
                    Some(prior.clone())
                );
                if matches!(outcome, "timeout" | "cancel") {
                    std::future::pending::<()>().await;
                }
                if outcome == "error" {
                    Err(())
                } else {
                    Ok(outcome)
                }
            };
            if outcome == "cancel" {
                let mut future = Box::pin(future);
                assert!(futures::poll!(future.as_mut()).is_pending());
                drop(future);
            } else {
                let result = tokio::time::timeout(Duration::from_millis(1), future).await;
                assert_eq!(result.is_err(), outcome == "timeout");
            }
            assert_eq!(interceptor.with_tab(&tab, |s| s.preparation_depth), Some(0));
            assert_eq!(
                interceptor.attribute_request(&tab, None, true, true, false),
                None
            );
            let next = interaction("view", "#continue");
            interceptor.set_current_interaction_on(&tab, Some(next.clone()));
            assert_eq!(
                interceptor.attribute_request(&tab, None, true, true, false),
                Some(next)
            );
            // The explicit prior stamp must also beat a later current action.
            assert_eq!(
                interceptor.attribute_request(&tab, Some("prior"), false, false, false),
                Some(prior.clone())
            );
        }
    }

    fn preparation_request(
        id: &str,
        headers: serde_json::Value,
    ) -> network::EventRequestWillBeSent {
        serde_json::from_value(serde_json::json!({
            "requestId":id,"loaderId":"loader","documentURL":"http://localhost/form",
            "request":{"url":"http://localhost/api/availability","method":"GET","headers":headers,
                "initialPriority":"High","referrerPolicy":"no-referrer"},
            "timestamp":1.0,"wallTime":1.0,"initiator":{"type":"script"},"type":"Fetch","redirectHasExtraInfo":false,
            "hasUserGesture":true
        })).unwrap()
    }

    fn preparation_extra(
        id: &str,
        headers: serde_json::Value,
    ) -> network::EventRequestWillBeSentExtraInfo {
        serde_json::from_value(serde_json::json!({
            "requestId":id,"associatedCookies":[],"headers":headers,"connectTiming":{"requestTime":1.0}
        })).unwrap()
    }

    #[tokio::test]
    async fn preparation_markers_survive_late_and_early_cdp_delivery_without_header_leaks() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        let tab = TabKey::shared();
        let next = interaction("next", "#continue");
        interceptor.register_action("next", next.clone());
        interceptor.set_current_interaction_on(&tab, Some(next.clone()));
        // The prep scope has already ended. Its request-start marker must
        // still prevent this later action from claiming delayed CDP traffic.
        let headers = serde_json::json!({"X-BrokenApp-Preparation":"1"});
        interceptor
            .on_request_will_be_sent(
                &preparation_request("direct", headers.clone()),
                None,
                None,
                &tab,
            )
            .await
            .unwrap();
        interceptor
            .on_request_will_be_sent_extra_info(&preparation_extra("early", headers.clone()), &tab)
            .await
            .unwrap();
        interceptor
            .on_request_will_be_sent(
                &preparation_request("early", serde_json::json!({})),
                None,
                None,
                &tab,
            )
            .await
            .unwrap();
        interceptor
            .on_request_will_be_sent(
                &preparation_request("late", serde_json::json!({})),
                None,
                None,
                &tab,
            )
            .await
            .unwrap();
        assert_eq!(
            interceptor.pending.get("late").unwrap().triggered_by,
            Some(next)
        );
        interceptor
            .on_request_will_be_sent_extra_info(&preparation_extra("late", headers), &tab)
            .await
            .unwrap();
        for id in ["direct", "early", "late"] {
            let row = interceptor.pending.get(id).unwrap();
            assert!(row.preparation);
            assert!(row.triggered_by.is_none());
            assert!(row.trace.as_ref().unwrap().action_id.is_none());
            assert!(
                !row.headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case(PREPARATION_HEADER))
            );
        }
        let prior = interaction("prior", "#addon");
        interceptor.register_action("prior", prior.clone());
        interceptor
            .on_request_will_be_sent(
                &preparation_request("explicit", serde_json::json!({})),
                None,
                None,
                &tab,
            )
            .await
            .unwrap();
        interceptor
            .on_request_will_be_sent_extra_info(
                &preparation_extra(
                    "explicit",
                    serde_json::json!({"x-brokenapp-action-id":"prior"}),
                ),
                &tab,
            )
            .await
            .unwrap();
        assert_eq!(
            interceptor.pending.get("explicit").unwrap().triggered_by,
            Some(prior)
        );
        assert_eq!(
            interceptor
                .pending
                .get("explicit")
                .unwrap()
                .trace
                .as_ref()
                .unwrap()
                .action_id
                .as_deref(),
            Some("prior")
        );
    }

    #[test]
    fn preparation_does_not_suppress_other_tabs_or_disable_write_guard() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        let (a, b) = (TabKey::from_raw("PREP"), TabKey::from_raw("ACTION"));
        interceptor.register_tab(&a);
        interceptor.register_tab(&b);
        let action = interaction("other", "#submit");
        interceptor.register_action_on(&b, "other", action.clone());
        interceptor.set_current_interaction_on(&b, Some(action.clone()));
        let _scope = interceptor.preparation_scope_on(&a);
        assert!(interceptor.write_guard_active());
        assert_eq!(
            interceptor.attribute_request(&a, Some("other"), true, true, false),
            None
        );
        assert_eq!(
            interceptor.attribute_request(&b, None, true, true, false),
            Some(action)
        );
    }

    #[tokio::test]
    async fn preparation_guard_records_consume_cached_stamps_and_preserve_explicit_owner() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("network.jsonl");
        let writer = Arc::new(
            NetworkLogWriter::new(path.clone(), NetworkLogMode::Truncate)
                .await
                .unwrap(),
        );
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), Some(writer), false);
        interceptor.set_first_party_origin(&Url::parse("http://localhost/").unwrap());
        let tab = TabKey::shared();
        let old = interaction("prior", "#addon");
        let next = interaction("next", "#continue");
        interceptor.register_action("prior", old.clone());
        interceptor.register_action("next", next.clone());
        interceptor.set_current_interaction_on(&tab, Some(next));
        for id in ["cached-prep", "pending-prep", "explicit"] {
            if id == "cached-prep" {
                interceptor.on_request_will_be_sent_extra_info(&preparation_extra(id,serde_json::json!({"X-BrokenApp-Preparation":"1","x-brokenapp-preparation":"1"})),&tab).await.unwrap();
            } else {
                let headers = if id == "pending-prep" {
                    serde_json::json!({"x-brokenapp-preparation":"1"})
                } else {
                    serde_json::json!({})
                };
                let mut request = preparation_request(id, headers);
                request.request.method = "POST".into();
                request.request.url = "http://localhost/api/reserve".into();
                interceptor
                    .on_request_will_be_sent(&request, None, None, &tab)
                    .await
                    .unwrap();
            }
            let ev: fetch::EventRequestPaused = serde_json::from_value(serde_json::json!({
                "requestId":format!("fetch-{id}"),"frameId":"frame","resourceType":"XHR",
                "request":{"url":"http://localhost/api/reserve","method":"POST",
                    "headers":{"x-brokenapp-action-id":"prior"},"initialPriority":"High","referrerPolicy":"no-referrer"}
            })).unwrap();
            interceptor
                .record_guarded_write(id, &ev, None, None, WriteGuardAction::Blocked, &tab)
                .await
                .unwrap();
        }
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(rows.len(), 3);
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row["write_guard"], "blocked");
            assert!(
                row["request"]["headers"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .all(|k| !k.eq_ignore_ascii_case(PREPARATION_HEADER)
                        && !k.eq_ignore_ascii_case("x-brokenapp-action-id"))
            );
            if index < 2 {
                assert!(row.get("triggered_by").is_none());
                assert!(
                    row.pointer("/trace/action_id")
                        .is_none_or(serde_json::Value::is_null)
                );
            } else {
                assert_eq!(row["triggered_by"], serde_json::to_value(&old).unwrap());
                assert_eq!(row["trace"]["action_id"], "prior");
            }
        }
    }

    #[test]
    fn tabs_never_claim_each_others_requests() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        let (a, b) = (TabKey::from_raw("TAB-A"), TabKey::from_raw("TAB-B"));
        interceptor.register_tab(&a);
        interceptor.register_tab(&b);
        let click_a = interaction("view_0001", "#save");
        let click_b = interaction("view_0002", "#load");

        // Current interaction: only the tab it runs on.
        interceptor.set_current_interaction_on(&a, Some(click_a.clone()));
        assert_eq!(
            interceptor.attribute_request(&a, None, false, false, false),
            Some(click_a.clone())
        );
        assert_eq!(
            interceptor.attribute_request(&b, None, true, true, false),
            None
        );
        assert_eq!(
            interceptor.attribute_request(&TabKey::shared(), None, true, true, false),
            None
        );

        // Action-id stamps map only on the tab that registered them.
        interceptor.register_action_on(&a, "act-a", click_a.clone());
        interceptor.register_action_on(&b, "act-b", click_b.clone());
        interceptor.set_current_interaction_on(&a, None);
        interceptor.forget_recent_interactions_on(&a);
        assert_eq!(
            interceptor.attribute_request(&a, Some("act-a"), false, false, false),
            Some(click_a.clone())
        );
        assert_eq!(
            interceptor.attribute_request(&b, Some("act-a"), false, false, false),
            None
        );
        assert_eq!(
            interceptor.attribute_request(&b, Some("act-b"), false, false, false),
            Some(click_b.clone())
        );

        // Time-window fallback: this tab's recent actions only.
        interceptor.set_current_interaction_on(&b, Some(click_b.clone()));
        interceptor.set_current_interaction_on(&b, None);
        assert_eq!(
            interceptor.attribute_request(&a, None, true, true, false),
            None
        );
        assert_eq!(
            interceptor.attribute_request(&b, None, true, true, false),
            Some(click_b.clone())
        );

        // Latest action ids (cross-origin calls, dialogs) are per tab too.
        assert_eq!(interceptor.action_id_for(&a, &click_b), None);
        assert_eq!(
            interceptor.action_id_for(&b, &click_b).as_deref(),
            Some("act-b")
        );

        // A navigation on one tab does not end the other tab's action.
        interceptor.set_current_interaction_on(&a, Some(click_a.clone()));
        bump_document_epoch(&interceptor, &b);
        assert_eq!(
            interceptor.attribute_request(&a, None, true, false, false),
            Some(click_a.clone())
        );
        bump_document_epoch(&interceptor, &a);
        assert_eq!(
            interceptor.attribute_request(&a, None, true, false, false),
            None
        );
    }

    #[test]
    fn native_dialogs_are_kept_per_tab() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        let (a, b) = (TabKey::from_raw("TAB-A"), TabKey::from_raw("TAB-B"));
        interceptor.register_tab(&a);
        interceptor.register_tab(&b);
        let cursor_a = interceptor.native_dialog_cursor_on(&a);
        let cursor_b = interceptor.native_dialog_cursor_on(&b);
        interceptor.with_tab(&b, |state| {
            state.native_dialogs.push(NativeDialog {
                kind: "confirm".to_string(),
                message: "Archive?".to_string(),
                url: "http://localhost/".to_string(),
                accepted: true,
                triggered_by: None,
                action_id: None,
                occurred_at: Utc::now(),
            })
        });
        assert!(
            interceptor
                .native_dialogs_since_on(&a, cursor_a)
                .0
                .is_empty()
        );
        let (dialogs, next) = interceptor.native_dialogs_since_on(&b, cursor_b);
        assert_eq!(dialogs.len(), 1);
        assert_eq!(next, cursor_b + 1);
        assert!(interceptor.native_dialogs_since(0).0.is_empty());
    }

    #[test]
    fn released_tabs_drop_their_attribution_state() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        let a = TabKey::from_raw("TAB-A");
        interceptor.register_tab(&a);
        assert_eq!(interceptor.tracked_tab_count(), 2);
        let click = interaction("view_0001", "#go");
        interceptor.register_action_on(&a, "act-a", click.clone());
        interceptor.mark_guarded(&request_key(&a, "42.1"));
        interceptor.release_tab(&a);
        assert_eq!(interceptor.tracked_tab_count(), 1);
        assert!(interceptor.action_to_interaction.get("act-a").is_none());
        // Setting an interaction on a released tab is a no-op, never a new lane.
        interceptor.set_current_interaction_on(&a, Some(click));
        assert_eq!(interceptor.tracked_tab_count(), 1);
        // Request ids are scoped by tab: the same CDP id on another tab is
        // a different request.
        assert!(interceptor.is_guarded_request(&request_key(&a, "42.1")));
        assert!(!interceptor.is_guarded_request(&request_key(&TabKey::from_raw("TAB-B"), "42.1")));
        assert!(!interceptor.is_guarded_request("42.1"));
        // The shared lane is never released.
        interceptor.release_tab(&TabKey::shared());
        assert_eq!(interceptor.tracked_tab_count(), 1);
    }

    #[test]
    fn parse_retry_after_seconds() {
        assert_eq!(
            parse_retry_after_with_now(
                "120",
                Utc.timestamp_opt(1_700_000_000, 0).single().unwrap()
            ),
            Some(std::time::Duration::from_secs(120))
        );
    }

    #[test]
    fn parse_retry_after_http_date_future() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let dt = now + chrono::Duration::seconds(5);
        let header = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        assert_eq!(
            parse_retry_after_with_now(&header, now),
            Some(std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn parse_retry_after_http_date_past_clamps_to_zero() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
        let dt = now - chrono::Duration::seconds(5);
        let header = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        assert_eq!(
            parse_retry_after_with_now(&header, now),
            Some(std::time::Duration::from_secs(0))
        );
    }

    #[tokio::test]
    async fn sse_nextjs_hmr_and_csp_beacons_are_ignored_from_attribution_and_endpoints() {
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), None, false);
        interceptor.set_first_party_origin(&Url::parse("http://localhost:3000/").unwrap());
        let tab = TabKey::shared();
        let click = interaction("view_0001", "#submit");
        interceptor.register_action("act-1", click.clone());
        interceptor.set_current_interaction_on(&tab, Some(click));

        let cases = [
            (
                "hmr",
                "GET",
                "http://localhost:3000/_next/webpack-hmr",
                serde_json::json!({}),
                "Other",
            ),
            (
                "stack-frame",
                "GET",
                "http://localhost:3000/__nextjs_original-stack-frame",
                serde_json::json!({}),
                "Fetch",
            ),
            (
                "error-feedback",
                "POST",
                "http://localhost:3000/__nextjs_error_feedback",
                serde_json::json!({"x-brokenapp-action-id": "act-1"}),
                "Fetch",
            ),
            (
                "sse-es",
                "GET",
                "http://localhost:3000/api/messages/stream",
                serde_json::json!({"Accept": "text/event-stream", "x-brokenapp-action-id": "act-1"}),
                "EventSource",
            ),
            (
                "csp-path",
                "POST",
                "http://localhost:3000/api/security/csp-report",
                serde_json::json!({"Content-Type": "application/csp-report", "x-brokenapp-action-id": "act-1"}),
                "Other",
            ),
            (
                "reports-ct",
                "POST",
                "http://localhost:3000/api/telemetry",
                serde_json::json!({"Content-Type": "application/reports+json"}),
                "Other",
            ),
        ];

        for (id, method, url, headers, resource_type) in cases {
            let ev: network::EventRequestWillBeSent = serde_json::from_value(serde_json::json!({
                "requestId": id,
                "loaderId": "loader",
                "documentURL": "http://localhost:3000/",
                "request": {
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "initialPriority": "High",
                    "referrerPolicy": "no-referrer"
                },
                "timestamp": 1.0,
                "wallTime": 1.0,
                "initiator": {"type": "script"},
                "type": resource_type,
                "redirectHasExtraInfo": false,
                "hasUserGesture": true
            }))
            .unwrap();
            interceptor
                .on_request_will_be_sent(&ev, None, None, &tab)
                .await
                .unwrap();
            let pending = interceptor.pending.get(id).expect("pending row");
            assert!(pending.ignore_attribution, "{id}");
            assert!(pending.triggered_by.is_none(), "{id}");
            assert!(pending.trace.as_ref().unwrap().action_id.is_none(), "{id}");
        }

        // An SSE response received for a fetch without an EventSource type is
        // immediately removed from `pending` so it never hangs or logs errors.
        let mut sse_fetch = preparation_request("sse-resp", serde_json::json!({}));
        sse_fetch.request.url = "http://localhost:3000/api/live".to_string();
        interceptor
            .on_request_will_be_sent(&sse_fetch, None, None, &tab)
            .await
            .unwrap();
        assert!(interceptor.pending.contains_key("sse-resp"));
        assert!(interceptor.drop_if_sse_response("sse-resp", "text/event-stream; charset=utf-8"));
        assert!(!interceptor.pending.contains_key("sse-resp"));

        // Recording a CSP beacon directly must not create an endpoint.
        let csp_entry = TrafficEntry {
            occurred_at: Utc::now(),
            trace: None,
            request: request(
                HttpMethod::Post,
                "http://localhost:3000/api/security/csp-report",
                &[("Content-Type", "application/csp-report")],
            ),
            response: None,
            failure: None,
            triggered_by: Some(interaction("view_0001", "#submit")),
            is_api: Some(false),
            duration_ms: Some(2.0),
            attribution: None,
        };
        interceptor
            .record_entry(csp_entry, None, None, None)
            .await
            .unwrap();
        assert_eq!(interceptor.endpoint_count(), 0);
    }

    #[test]
    fn fetch_enable_params_scopes_out_static_assets_when_egress_disabled() {
        let local = fetch_enable_params(false);
        let patterns = local.patterns.expect("write-guard patterns");
        assert!(!patterns.is_empty());
        for p in &patterns {
            assert_eq!(p.url_pattern.as_deref(), Some("*"));
            assert!(
                p.resource_type.is_some(),
                "local mode must scope by resource type: {p:?}"
            );
        }
        let types: Vec<network::ResourceType> = patterns
            .iter()
            .filter_map(|p| p.resource_type.clone())
            .collect();
        for included in [
            network::ResourceType::Document,
            network::ResourceType::Xhr,
            network::ResourceType::Fetch,
            network::ResourceType::EventSource,
            network::ResourceType::Ping,
            network::ResourceType::Other,
        ] {
            assert!(types.contains(&included), "missing {included:?}");
        }
        for excluded in [
            network::ResourceType::Script,
            network::ResourceType::Stylesheet,
            network::ResourceType::Image,
            network::ResourceType::Media,
            network::ResourceType::Font,
            network::ResourceType::Manifest,
            network::ResourceType::TextTrack,
        ] {
            assert!(!types.contains(&excluded), "must exclude {excluded:?}");
        }

        let remote = fetch_enable_params(true);
        let remote_patterns = remote.patterns.expect("egress wildcard pattern");
        assert_eq!(remote_patterns.len(), 1);
        assert_eq!(remote_patterns[0].url_pattern.as_deref(), Some("*"));
        assert_eq!(remote_patterns[0].resource_type, None);
    }

    #[test]
    fn should_fetch_response_body_skips_static_asset_paths_even_with_json_mime() {
        for url in [
            "http://localhost:3000/_next/static/chunks/app-pages-internals.js",
            "http://localhost:3000/assets/bundle.mjs?v=1",
            "http://localhost:3000/styles/app.css",
            "http://localhost:3000/main.js.map",
            "http://localhost:3000/fonts/inter.woff",
            "http://localhost:3000/fonts/inter.woff2",
            "http://localhost:3000/logo.png",
            "http://localhost:3000/icon.svg",
            "http://localhost:3000/favicon.ico",
        ] {
            assert!(
                !should_fetch_response_body(url, Some("application/json")),
                "must skip GetResponseBody for {url}"
            );
        }

        assert!(should_fetch_response_body(
            "http://localhost:3000/api/orders",
            Some("application/json; charset=utf-8")
        ));
        assert!(!should_fetch_response_body(
            "http://localhost:3000/api/orders",
            Some("text/html")
        ));
    }

    #[tokio::test]
    async fn record_entry_omits_successful_static_and_vite_dev_modules_from_network_log() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("network.jsonl");
        let writer = Arc::new(
            NetworkLogWriter::new(path.clone(), NetworkLogMode::Truncate)
                .await
                .unwrap(),
        );
        let interceptor = NetworkInterceptor::new(ScanConfig::default(), Some(writer), false);
        interceptor.set_first_party_origin(&Url::parse("http://localhost:5833/").unwrap());

        let mk_entry = |url: &str, status: u16, mime: &str, is_api: bool| TrafficEntry {
            occurred_at: Utc::now(),
            trace: None,
            request: HttpRequestLog {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: BTreeMap::new(),
                post_data: None,
            },
            response: Some(HttpResponseLog {
                status,
                headers: BTreeMap::new(),
                mime_type: Some(mime.to_string()),
                body_snippet: None,
            }),
            failure: None,
            triggered_by: None,
            is_api: Some(is_api),
            duration_ms: Some(1.0),
            attribution: None,
        };

        // 200 Vite dev modules & static assets should be dropped from network.jsonl.
        for (url, mime) in [
            ("http://localhost:5833/src/bootstrap.ts", "text/javascript"),
            (
                "http://localhost:5833/@fs/tmp/demo-app/pkg.tsx",
                "text/javascript",
            ),
            ("http://localhost:5833/@vite/client", "text/javascript"),
            (
                "http://localhost:5833/node_modules/.vite/deps/react.js",
                "text/javascript",
            ),
            ("http://localhost:5833/apple-touch-icon.png", "image/png"),
        ] {
            interceptor
                .record_entry(mk_entry(url, 200, mime, false), None, None, None)
                .await
                .unwrap();
        }

        // HTML document, API call, and 404 broken static asset MUST still be recorded.
        interceptor
            .record_entry(
                mk_entry(
                    "http://localhost:5833/settings/general",
                    200,
                    "text/html",
                    false,
                ),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        interceptor
            .record_entry(
                mk_entry(
                    "http://localhost:5833/api/shell",
                    200,
                    "application/json",
                    true,
                ),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        interceptor
            .record_entry(
                mk_entry(
                    "http://localhost:5833/src/broken.tsx",
                    404,
                    "text/javascript",
                    false,
                ),
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let urls: Vec<&str> = rows
            .iter()
            .map(|r| r["request"]["url"].as_str().unwrap())
            .collect();
        assert_eq!(
            urls,
            vec![
                "http://localhost:5833/settings/general",
                "http://localhost:5833/api/shell",
                "http://localhost:5833/src/broken.tsx",
            ]
        );
    }

    #[tokio::test]
    async fn network_log_writer_omits_response_bodies_by_default_and_scrubs_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let default_path = dir.path().join("default.jsonl");
        let opt_in_path = dir.path().join("opt_in.jsonl");

        let secret_body = r#"{"user":"alice","access_token":"super-secret-tok","note":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcde12345"}"#;
        let entry = TrafficEntry {
            occurred_at: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            trace: None,
            request: request(HttpMethod::Get, "http://127.0.0.1:3000/api/me", &[]),
            response: Some(HttpResponseLog {
                status: 200,
                headers: BTreeMap::new(),
                mime_type: Some("application/json".to_string()),
                body_snippet: Some(secret_body.to_string()),
            }),
            failure: None,
            triggered_by: None,
            is_api: Some(true),
            duration_ms: Some(10.0),
            attribution: None,
        };

        let default_writer = NetworkLogWriter::new(default_path.clone(), NetworkLogMode::Truncate)
            .await
            .unwrap();
        default_writer
            .append_annotated(&entry, Some("GET /api/me"), None)
            .await
            .unwrap();
        let default_raw = std::fs::read_to_string(&default_path).unwrap();
        let default_row: serde_json::Value =
            serde_json::from_str(default_raw.lines().next().unwrap()).unwrap();
        assert!(
            default_row["response"].get("body_snippet").is_none(),
            "default network.jsonl must omit response.body_snippet: {default_raw}"
        );
        assert!(!default_raw.contains("super-secret-tok"));
        assert!(!default_raw.contains("eyJhbGci"));

        let opt_in_writer =
            NetworkLogWriter::new_with_options(opt_in_path.clone(), NetworkLogMode::Truncate, true)
                .await
                .unwrap();
        opt_in_writer
            .append_annotated(&entry, Some("GET /api/me"), None)
            .await
            .unwrap();
        let opt_in_raw = std::fs::read_to_string(&opt_in_path).unwrap();
        let opt_in_row: serde_json::Value =
            serde_json::from_str(opt_in_raw.lines().next().unwrap()).unwrap();
        let snippet = opt_in_row["response"]["body_snippet"]
            .as_str()
            .expect("opt-in body_snippet retained");
        assert!(snippet.contains("\"user\":\"alice\""), "{snippet}");
        assert!(!snippet.contains("super-secret-tok"), "{snippet}");
        assert!(!snippet.contains("eyJhbGci"), "{snippet}");
        assert!(snippet.contains("<redacted>"), "{snippet}");
    }
}
