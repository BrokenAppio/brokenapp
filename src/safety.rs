//! Runtime safety gates for potentially mutating operations.
//!
//! By default, BrokenApp blocks write/replay style commands against likely
//! production hosts. Users can explicitly override with
//! `--allow-live-mutations` when they understand the risk.
//!
//! This module also holds the scan write-guard policy
//! ([`write_guard_verdict`]): which browser requests count as writes and which
//! of those are allowed through. The CDP enforcement lives in
//! `crate::network::interceptor`.

use std::net::IpAddr;

use anyhow::{Result, bail};
use url::Url;

use crate::config::{WriteGuardConfig, WriteGuardMode};

/// Why the write guard let a state-changing request through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAllowReason {
    /// Matched a `scan.write_guard.allow` pattern.
    AllowPattern,
    /// Token refresh / session endpoint (`scan.write_guard.allow_auth`).
    AuthRefresh,
    /// Issued while the user-configured authentication flow was running.
    AuthFlow,
}

/// Write-guard verdict for one browser request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteVerdict {
    /// Not state-changing: GET/HEAD/OPTIONS that is not a GraphQL mutation.
    Read,
    /// State-changing but explicitly allowed.
    Allowed(WriteAllowReason),
    /// State-changing; record it and stop it before it reaches a server.
    Guard,
}

/// The request facts the write guard decides on.
#[derive(Debug, Clone, Copy)]
pub struct WriteRequest<'a> {
    /// Raw HTTP method as sent by the browser (any case, may be non-standard).
    pub method: &'a str,
    pub url: &'a str,
    /// The request carries (or may carry) a GraphQL mutation.
    pub graphql_mutation: bool,
    /// The request was issued while the configured auth flow was running.
    pub in_auth_flow: bool,
}

/// Token refresh / session endpoints let through when `allow_auth` is set.
/// Logins that create sessions run through the configured auth flow instead,
/// and sign-out/revoke endpoints never match (see [`is_session_ending_url`]).
const AUTH_REFRESH_PATTERNS: &[&str] = &[
    // Supabase GoTrue (refresh_token and password grants).
    "*/auth/v1/token*",
    // Auth.js / NextAuth session read/update and CSRF token.
    "*/api/auth/session*",
    "*/api/auth/csrf*",
    // Firebase Auth token refresh.
    "*securetoken.googleapis.com/v1/token*",
    // Clerk session token refresh and keep-alive.
    "*/v1/client/sessions/*/tokens*",
    "*/v1/client/sessions/*/touch*",
    // OAuth2 token endpoint and common refresh routes.
    "*/oauth/token*",
    "*/oauth2/token*",
    "*/token/refresh*",
    "*/auth/refresh*",
    "*/refresh-token*",
    "*/refresh_token*",
];

/// Substrings that mark an endpoint as ending or revoking a session. These are
/// never let through by the auth allowance or the auth flow, because they
/// would end the scan's session (and usually change server-side state).
const SESSION_ENDING_MARKERS: &[&str] = &[
    "logout", "log-out", "log_out", "signout", "sign-out", "sign_out", "revoke",
];

/// Path/query segments that mark a GET/HEAD/OPTIONS request as a mutation:
/// unsafe GET-based writes (e.g. `GET /delete?id=1`, `GET /api/place-order`).
/// Segment-aware: `delete` matches `delete`/`remove`, not `deleted-products`.
const GET_WRITE_MARKERS: &[&str] = &[
    "delete",
    "remove",
    "destroy",
    "purge",
    "clear",
    "pay",
    "checkout",
    "place-order",
    "place_order",
    "create-order",
    "create_order",
    "refund",
    "charge",
    "cancel",
    "reset",
    "logout",
    "signout",
    "revoke",
    "activate",
    "deactivate",
    "disable",
    "enable",
    "suspend",
    "subscribe",
    "unsubscribe",
];

/// Well-known password-recovery UI route segments that contain words like
/// `reset` in a read-only page route (e.g. `GET /reset-password?token=...`),
/// not a GET-based mutation. Ignored only on non-`/api/` paths; destructive
/// action query parameters (`?action=reset`, `?action=delete`) are still guarded.
const PASSWORD_RECOVERY_UI_SEGMENTS: &[&str] = &[
    "reset-password",
    "password-reset",
    "reset_password",
    "password_reset",
    "forgot-password",
    "forgot_password",
    "change-password",
    "change_password",
];

/// `true` when a read-only method URL looks like a GET-based mutation.
/// Checks path segments (split on `/`, `-`, `_`, `.`) and action-like query keys.
pub fn is_get_write_like(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let path = parsed.path().to_ascii_lowercase();
    let raw_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let is_api_path = raw_segments.contains(&"api");
    let segments: Vec<&str> = raw_segments
        .iter()
        .copied()
        .filter(|seg| is_api_path || !PASSWORD_RECOVERY_UI_SEGMENTS.contains(seg))
        .flat_map(|seg| seg.split(|c: char| c == '-' || c == '_' || c == '.'))
        .filter(|s| !s.is_empty())
        .collect();
    if segments.iter().any(|seg| {
        GET_WRITE_MARKERS
            .iter()
            .any(|m| seg == m || seg.starts_with(&format!("{m}-")))
    }) {
        return true;
    }
    // Query: `?action=delete`, `?method=pay`, etc.
    parsed.query_pairs().any(|(k, v)| {
        const KEYS: &[&str] = &["action", "method", "cmd", "op", "operation", "do", "intent"];
        if !KEYS.iter().any(|key| k.eq_ignore_ascii_case(key)) {
            return false;
        }
        let vv = v.to_ascii_lowercase();
        GET_WRITE_MARKERS.iter().any(|m| vv == *m)
    })
}

/// `true` for GET/HEAD/OPTIONS (case-insensitive). Every other method,
/// including non-standard ones, is state-changing.
pub fn is_read_only_method(method: &str) -> bool {
    let m = method.trim();
    m.eq_ignore_ascii_case("GET")
        || m.eq_ignore_ascii_case("HEAD")
        || m.eq_ignore_ascii_case("OPTIONS")
}

/// `true` when a URL looks like a logout / sign-out / token revocation endpoint.
pub fn is_session_ending_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    SESSION_ENDING_MARKERS.iter().any(|m| lower.contains(m))
}

/// Decide what the write guard does with a request.
///
/// Order: read-only requests pass; explicit `allow` patterns pass (except
/// GraphQL mutations, which a URL pattern cannot tell apart from queries);
/// sign-out/revoke endpoints are guarded; the configured auth flow passes;
/// token refresh/session endpoints pass when `allow_auth`; everything else is
/// guarded. The caller decides whether the guard is enabled at all.
pub fn write_guard_verdict(cfg: &WriteGuardConfig, req: &WriteRequest<'_>) -> WriteVerdict {
    if is_read_only_method(req.method) && !req.graphql_mutation && !is_get_write_like(req.url) {
        return WriteVerdict::Read;
    }
    // GET/HEAD/OPTIONS that looks like a mutation (e.g. GET /delete): fall
    // through so allowlists can still permit it explicitly, otherwise Guard.
    if is_read_only_method(req.method)
        && !req.graphql_mutation
        && is_get_write_like(req.url)
        && !cfg
            .allow
            .iter()
            .any(|pattern| allow_pattern_matches(pattern, req.method, req.url))
    {
        return WriteVerdict::Guard;
    }
    if !req.graphql_mutation
        && cfg
            .allow
            .iter()
            .any(|pattern| allow_pattern_matches(pattern, req.method, req.url))
    {
        return WriteVerdict::Allowed(WriteAllowReason::AllowPattern);
    }
    if is_session_ending_url(req.url) {
        return WriteVerdict::Guard;
    }
    if req.in_auth_flow {
        return WriteVerdict::Allowed(WriteAllowReason::AuthFlow);
    }
    if cfg.allow_auth
        && !req.graphql_mutation
        && AUTH_REFRESH_PATTERNS
            .iter()
            .any(|glob| url_glob_matches(glob, req.url))
    {
        return WriteVerdict::Allowed(WriteAllowReason::AuthRefresh);
    }
    WriteVerdict::Guard
}

/// Match one `scan.write_guard.allow` entry against a request.
///
/// Format: `METHOD url-glob` (`POST */api/search*`), or just `url-glob` for any
/// method. `METHOD` may be `*` or `ANY`. `*` in the glob matches any run of
/// characters; a glob starting with `/` is matched against the URL's path and
/// query instead of the full URL.
pub fn allow_pattern_matches(pattern: &str, method: &str, url: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let (method_part, glob) = match pattern.split_once(char::is_whitespace) {
        Some((m, g)) => (Some(m.trim()), g.trim()),
        None => (None, pattern),
    };
    if let Some(m) = method_part {
        let any = m == "*" || m.eq_ignore_ascii_case("ANY");
        if !any && !m.eq_ignore_ascii_case(method.trim()) {
            return false;
        }
    }
    if glob.starts_with('/') {
        let Ok(parsed) = Url::parse(url) else {
            return false;
        };
        let mut path_and_query = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }
        return url_glob_matches(glob, &path_and_query);
    }
    url_glob_matches(glob, url)
}

/// Glob match where `*` matches any (possibly empty) run of characters and
/// every other character matches itself.
fn url_glob_matches(glob: &str, text: &str) -> bool {
    let g = glob.as_bytes();
    let t = text.as_bytes();
    let (mut gi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;
    while ti < t.len() {
        if gi < g.len() && g[gi] == b'*' {
            star = Some(gi);
            gi += 1;
            star_ti = ti;
        } else if gi < g.len() && g[gi] == t[ti] {
            gi += 1;
            ti += 1;
        } else if let Some(s) = star {
            gi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while gi < g.len() && g[gi] == b'*' {
        gi += 1;
    }
    gi == g.len()
}

/// Return `true` when a target URL looks like a non-production environment.
pub fn is_non_production_target(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_non_production_ip(ip);
    }

    let host = host.to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }

    [".local", ".internal", ".test", ".example", ".invalid"]
        .iter()
        .any(|suffix| host.ends_with(suffix))
}

/// Block mutating operations against likely production targets unless explicitly
/// overridden.
pub fn ensure_mutating_target_safe(
    target_url: &Url,
    allow_live_mutations: bool,
    operation: &str,
) -> Result<()> {
    if allow_live_mutations {
        tracing::warn!(
            operation,
            target = %target_url,
            "live mutation safety gate overridden by user"
        );
        return Ok(());
    }

    if is_non_production_target(target_url) {
        return Ok(());
    }

    bail!(
        "refusing to run {operation} against likely production target `{}`; \
pass --allow-live-mutations to override intentionally",
        target_url
    );
}

/// Write-guard policy for live actuation (`replay-flow`, `test-flow`).
///
/// These drive recorded or author-specified clicks against a live target, so a
/// "Save"/"Delete" step could otherwise fire a real write. The guard defaults to
/// `Block` (fail-closed) against every target; `--allow-live-mutations` turns it
/// `Off` and is gated + logged exactly like the mutation-replay write path.
pub fn actuation_write_guard(
    target: &Url,
    allow_live_mutations: bool,
    operation: &str,
) -> Result<WriteGuardConfig> {
    let mut cfg = WriteGuardConfig::default();
    if allow_live_mutations {
        ensure_mutating_target_safe(target, allow_live_mutations, operation)?;
        cfg.mode = WriteGuardMode::Off;
    }
    Ok(cfg)
}

fn is_non_production_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
                || v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
        }
    }
}

/// Classification of an outbound WebSocket frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsFrameClass {
    /// Keepalive, ping/pong, protocol ack, or connection handshake.
    Heartbeat,
    /// Read-only query, subscription, status fetch, or unsubscribe.
    Read,
    /// State-changing RPC, GraphQL mutation, command dispatch, or destructive event.
    Mutation,
    /// Unclassified payload (not clearly a read or mutation).
    Unknown,
}

/// Result of inspecting a single WebSocket text frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrameAnalysis {
    pub class: WsFrameClass,
    /// Extracted RPC method, GraphQL operation, or event name when structured.
    pub operation: Option<String>,
}

/// True when a WebSocket URL belongs to a framework dev-server / HMR socket
/// (Vite, Next.js, Webpack, Turbopack) rather than application traffic.
pub fn is_ws_dev_tool_url(url: &str) -> bool {
    let path = Url::parse(url)
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_else(|_| url.to_ascii_lowercase());
    crate::network::filters::is_dev_tool_or_hmr_path(&path)
        || path.contains("/sockjs-node")
        || path.contains("/webpack-dev-server")
        || path.contains("/_hmr")
}

const WS_HEARTBEAT_TOKENS: &[&str] = &[
    "ping",
    "pong",
    "hb",
    "heartbeat",
    "keepalive",
    "keep_alive",
    "keep-alive",
    "ack",
    "connection_init",
    "connection_ack",
    "ka",
    "hello",
    "interrupt",
    "complete",
    "phx_join",
    "phx_leave",
    "phx_close",
    "unsubscribe",
    "unwatch",
];

const WS_READ_VERBS: &[&str] = &[
    "get",
    "list",
    "fetch",
    "read",
    "load",
    "query",
    "search",
    "find",
    "check",
    "describe",
    "inspect",
    "status",
    "health",
    "version",
    "subscribe",
    "unsubscribe",
    "watch",
    "unwatch",
    "listen",
    "poll",
    "diff",
    "preview",
    "count",
    "exists",
    "validate",
    "refresh",
    "snapshot",
    "info",
    "meta",
    "whoami",
    "me",
    "ping",
    "pong",
    "heartbeat",
];

const WS_MUTATION_VERBS: &[&str] = &[
    "create",
    "update",
    "upsert",
    "delete",
    "remove",
    "destroy",
    "drop",
    "insert",
    "add",
    "put",
    "patch",
    "post",
    "set",
    "save",
    "write",
    "submit",
    "send",
    "dispatch",
    "exec",
    "execute",
    "run",
    "start",
    "stop",
    "kill",
    "restart",
    "cancel",
    "abort",
    "revoke",
    "logout",
    "signout",
    "archive",
    "restore",
    "rename",
    "move",
    "copy",
    "clone",
    "merge",
    "publish",
    "unpublish",
    "approve",
    "reject",
    "toggle",
    "enable",
    "disable",
    "pin",
    "unpin",
    "open",
    "spawn",
    "apply",
    "reset",
    "clear",
    "flush",
    "purge",
    "import",
    "upload",
    "checkout",
    "pay",
    "charge",
    "refund",
    "transfer",
    "invite",
    "ban",
    "kick",
    "mute",
    "mutate",
    "mutation",
    "buy",
    "order",
    "place",
    "book",
    "reserve",
    "edit",
    "modify",
    "change",
    "assign",
    "unassign",
    "complete",
    "reopen",
    "lock",
    "unlock",
    "grant",
    "deny",
    "promote",
    "demote",
    "trigger",
    "commit",
    "push",
    "pull",
    "stash",
    "branch",
    "install",
    "uninstall",
    "upgrade",
    "downgrade",
    "download",
    "pair",
    "unpair",
    "connect",
    "disconnect",
    "reconnect",
    "login",
    "signin",
    "signup",
    "register",
    "settle",
    "unsettle",
    "snooze",
    "wake",
    "mark",
    "unarchive",
    "fork",
    "rebase",
    "revert",
    "amend",
    "stage",
    "unstage",
    "discard",
    "clean",
    "init",
    "setup",
    "configure",
    "switch",
];

/// Split an RPC operation name (`shell.openInEditor`, `server/upsert_keybinding`,
/// `MUTATION RefundOrder`) into lowercase identifier tokens.
fn ws_operation_tokens(op: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev_lower_or_digit = false;
    for ch in op.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            prev_lower_or_digit = false;
            continue;
        }
        if ch.is_ascii_uppercase() && prev_lower_or_digit && !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
        }
        cur.push(ch.to_ascii_lowercase());
        prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// True when `payload` is a WebSocket heartbeat, keepalive, or protocol-control
/// frame that should not count as application interaction activity.
pub fn is_ws_heartbeat_frame(payload: &str) -> bool {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return true;
    }
    // Engine.IO / Socket.IO ping/pong/handshake frames.
    if matches!(
        trimmed,
        "2" | "3" | "2probe" | "3probe" | "0" | "40" | "41" | "5"
    ) {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if WS_HEARTBEAT_TOKENS.contains(&lower.as_str()) {
        return true;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(obj) = val.as_object()
    {
        for key in ["type", "_tag", "event", "op", "action", "method", "command"] {
            if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                let s_low = s.trim().to_ascii_lowercase();
                if WS_HEARTBEAT_TOKENS.contains(&s_low.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract an application-level operation name and GraphQL query (if any) from
/// a structured WebSocket text payload.
fn extract_ws_operation(trimmed: &str) -> (Option<String>, Option<String>) {
    // Socket.IO event packet: `42["eventName", {...}]` or `42/ns,["eventName", ...]`.
    if let Some(rest) = trimmed.strip_prefix("42") {
        let json_part = rest.find('[').map(|i| &rest[i..]).unwrap_or(rest);
        if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(json_part)
            && let Some(event) = arr.first().and_then(|v| v.as_str())
        {
            return (sanitize_ws_op(event), None);
        }
    }

    let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return (None, None);
    };

    // Phoenix Channels array tuple: `[join_ref, ref, topic, event, payload]`.
    if let Some(arr) = val.as_array() {
        if arr.len() >= 4
            && let (Some(topic), Some(event)) = (arr[2].as_str(), arr[3].as_str())
        {
            return (sanitize_ws_op(&format!("{topic}:{event}")), None);
        }
        if let Some(first) = arr.first() {
            return extract_ws_operation_from_value(first);
        }
        return (None, None);
    }

    extract_ws_operation_from_value(&val)
}

fn extract_ws_operation_from_value(val: &serde_json::Value) -> (Option<String>, Option<String>) {
    let Some(obj) = val.as_object() else {
        return (None, None);
    };

    // GraphQL-WS (`graphql-transport-ws` / `subscriptions-transport-ws`).
    let gql_query = obj
        .get("payload")
        .and_then(|p| p.get("query"))
        .and_then(|q| q.as_str())
        .or_else(|| obj.get("query").and_then(|q| q.as_str()));
    if let Some(query) = gql_query {
        let op_name = obj
            .get("payload")
            .and_then(|p| p.get("operationName"))
            .and_then(|n| n.as_str())
            .or_else(|| obj.get("operationName").and_then(|n| n.as_str()))
            .and_then(sanitize_ws_op);
        let q_low = query.trim_start().to_ascii_lowercase();
        let kind = if q_low.starts_with("mutation")
            || q_low.contains("mutation ")
            || q_low.contains("mutation{")
        {
            "MUTATION"
        } else if q_low.starts_with("subscription") {
            "SUBSCRIPTION"
        } else {
            "QUERY"
        };
        let label = match op_name {
            Some(name) => format!("{kind}:{name}"),
            None => kind.to_string(),
        };
        return (Some(label), Some(query.to_string()));
    }

    // Effect-RPC: `{ "_tag": "Request", "tag": "shell.openInEditor", ... }`
    if obj.get("_tag").and_then(|v| v.as_str()) == Some("Request")
        && let Some(tag) = obj.get("tag").and_then(|v| v.as_str())
    {
        return (sanitize_ws_op(tag), None);
    }

    // tRPC-WS: `{ "method": "mutation"|"query"|"subscription", "params": { "path": "post.create" } }`
    if let (Some(method), Some(path)) = (
        obj.get("method").and_then(|v| v.as_str()),
        obj.get("params")
            .and_then(|p| p.get("path"))
            .and_then(|v| v.as_str()),
    ) {
        let m = method.trim().to_ascii_lowercase();
        if matches!(m.as_str(), "mutation" | "query" | "subscription") {
            return (sanitize_ws_op(&format!("{m}:{path}")), None);
        }
    }

    // JSON-RPC / generic RPC envelopes.
    for key in [
        "method", "tag", "action", "command", "cmd", "op", "event", "path", "route", "topic",
        "type", "_tag",
    ] {
        if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }
            if matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "request" | "message" | "rpc" | "call" | "data" | "next"
            ) {
                continue;
            }
            return (sanitize_ws_op(trimmed), None);
        }
    }

    (None, None)
}

fn sanitize_ws_op(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control() && !c.is_whitespace())
        .take(96)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Classify a WebSocket text frame into Heartbeat / Read / Mutation / Unknown.
pub fn classify_ws_frame(_url: &str, payload: &str) -> WsFrameAnalysis {
    let trimmed = payload.trim();
    if is_ws_heartbeat_frame(trimmed) {
        return WsFrameAnalysis {
            class: WsFrameClass::Heartbeat,
            operation: None,
        };
    }

    let (operation, gql_query) = extract_ws_operation(trimmed);
    if let Some(query) = gql_query.as_deref() {
        let q = query.trim_start().to_ascii_lowercase();
        if q.starts_with("mutation") || q.contains("mutation ") || q.contains("mutation{") {
            return WsFrameAnalysis {
                class: WsFrameClass::Mutation,
                operation,
            };
        }
        return WsFrameAnalysis {
            class: WsFrameClass::Read,
            operation,
        };
    }

    let Some(ref op) = operation else {
        return WsFrameAnalysis {
            class: WsFrameClass::Unknown,
            operation: None,
        };
    };

    let op_lower = op.to_ascii_lowercase();
    if op_lower.starts_with("mutation:") || op_lower == "mutation" {
        return WsFrameAnalysis {
            class: WsFrameClass::Mutation,
            operation,
        };
    }
    if op_lower.starts_with("query:")
        || op_lower.starts_with("subscription:")
        || op_lower == "query"
        || op_lower == "subscription"
    {
        return WsFrameAnalysis {
            class: WsFrameClass::Read,
            operation,
        };
    }

    let tokens = ws_operation_tokens(op);
    if tokens
        .iter()
        .any(|t| WS_HEARTBEAT_TOKENS.contains(&t.as_str()))
    {
        return WsFrameAnalysis {
            class: WsFrameClass::Heartbeat,
            operation,
        };
    }

    let action_segment = op
        .rsplit(['.', '/', ':'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(op.as_str());
    let seg_tokens = ws_operation_tokens(action_segment);
    if let Some(first) = seg_tokens.first() {
        if WS_READ_VERBS.contains(&first.as_str()) {
            return WsFrameAnalysis {
                class: WsFrameClass::Read,
                operation,
            };
        }
        if WS_MUTATION_VERBS.contains(&first.as_str()) {
            return WsFrameAnalysis {
                class: WsFrameClass::Mutation,
                operation,
            };
        }
    }

    if tokens
        .iter()
        .any(|t| WS_MUTATION_VERBS.contains(&t.as_str()))
    {
        return WsFrameAnalysis {
            class: WsFrameClass::Mutation,
            operation,
        };
    }
    if tokens.iter().any(|t| WS_READ_VERBS.contains(&t.as_str())) {
        return WsFrameAnalysis {
            class: WsFrameClass::Read,
            operation,
        };
    }

    WsFrameAnalysis {
        class: WsFrameClass::Unknown,
        operation,
    }
}

/// Decide whether an outbound WebSocket frame should pass or be stopped by the
/// write guard. Supports `WS <url-glob>` and `WS <url-glob>#<op-glob>` in
/// `cfg.allow`.
pub fn ws_write_guard_verdict(
    cfg: &WriteGuardConfig,
    url: &str,
    payload: &str,
) -> (WriteVerdict, WsFrameAnalysis) {
    let analysis = classify_ws_frame(url, payload);
    if cfg.mode == WriteGuardMode::Off {
        return (WriteVerdict::Read, analysis);
    }
    if is_ws_dev_tool_url(url) {
        return (WriteVerdict::Read, analysis);
    }
    if analysis.class != WsFrameClass::Mutation {
        return (WriteVerdict::Read, analysis);
    }

    let url_with_op = match analysis.operation.as_deref() {
        Some(op) => format!("{url}#{op}"),
        None => url.to_string(),
    };
    for pattern in &cfg.allow {
        if allow_pattern_matches(pattern, "WS", url)
            || allow_pattern_matches(pattern, "WS", &url_with_op)
        {
            return (
                WriteVerdict::Allowed(WriteAllowReason::AllowPattern),
                analysis,
            );
        }
    }

    (WriteVerdict::Guard, analysis)
}

/// Inspect a received WebSocket text frame for structured RPC / application
/// errors (JSON-RPC, Effect-RPC, GraphQL-WS, generic `{ok:false}` / `{error:...}`).
/// Returns a redacted, concise error summary when an error payload is detected.
pub fn detect_ws_error_frame(payload: &str) -> Option<String> {
    let trimmed = payload.trim();
    if trimmed.is_empty() || trimmed.len() > 262_144 {
        return None;
    }
    let val = serde_json::from_str::<serde_json::Value>(trimmed).ok()?;
    extract_ws_error_from_value(&val).map(|msg| {
        let clean = redact_ws_inline_secrets(&msg);
        truncate_ws_summary(&clean, 300)
    })
}

fn extract_ws_error_from_value(val: &serde_json::Value) -> Option<String> {
    let obj = val.as_object()?;

    // 1. Effect-RPC Exit Failure: `{"_tag":"Exit","exit":{"_tag":"Failure","cause":...}}`
    if obj.get("_tag").and_then(|v| v.as_str()) == Some("Exit")
        && let Some(exit) = obj.get("exit").and_then(|v| v.as_object())
        && exit.get("_tag").and_then(|v| v.as_str()) == Some("Failure")
    {
        return Some(
            extract_nested_error_message(exit.get("cause").unwrap_or(&serde_json::Value::Null))
                .unwrap_or_else(|| "RPC request failed".to_string()),
        );
    }
    if matches!(
        obj.get("_tag").and_then(|v| v.as_str()),
        Some("Failure" | "Defect" | "Error")
    ) {
        return Some(
            extract_nested_error_message(val).unwrap_or_else(|| "WebSocket RPC error".to_string()),
        );
    }

    // 2. GraphQL-WS: `{"type":"error","payload":...}` or `{"type":"next"|"data","payload":{"errors":[...]}}`
    if let Some(ty) = obj.get("type").and_then(|v| v.as_str()) {
        let ty_low = ty.to_ascii_lowercase();
        if matches!(ty_low.as_str(), "error" | "connection_error" | "rpc_error") {
            let msg = obj
                .get("payload")
                .and_then(extract_nested_error_message)
                .or_else(|| extract_nested_error_message(val))
                .unwrap_or_else(|| "WebSocket error frame".to_string());
            return Some(msg);
        }
        if let Some(errors) = obj
            .get("payload")
            .and_then(|p| p.get("errors"))
            .and_then(|e| e.as_array())
            && !errors.is_empty()
        {
            let msg = errors
                .first()
                .and_then(extract_nested_error_message)
                .unwrap_or_else(|| "GraphQL WebSocket error".to_string());
            return Some(msg);
        }
    }

    // 3. JSON-RPC / generic `error` field (non-null, non-empty, not `false`).
    if let Some(err) = obj.get("error") {
        let is_real_error = match err {
            serde_json::Value::Null => false,
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::String(s) => !s.trim().is_empty(),
            serde_json::Value::Array(a) => !a.is_empty(),
            serde_json::Value::Object(m) => !m.is_empty(),
            serde_json::Value::Number(_) => true,
        };
        if is_real_error {
            let msg = extract_nested_error_message(err)
                .or_else(|| {
                    obj.get("message")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "WebSocket error response".to_string());
            return Some(msg);
        }
    }

    // 4. Generic `{ "ok": false, ... }` or `{ "status": "error"|"failed", ... }`.
    let explicit_failed = obj.get("ok").and_then(|v| v.as_bool()) == Some(false)
        || obj.get("status").and_then(|v| v.as_str()).is_some_and(|s| {
            matches!(s.to_ascii_lowercase().as_str(), "error" | "failed" | "fail")
        });
    if explicit_failed {
        let msg = extract_nested_error_message(val)
            .unwrap_or_else(|| "WebSocket operation failed".to_string());
        return Some(msg);
    }

    None
}

fn extract_nested_error_message(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        }
        serde_json::Value::Array(arr) => arr.iter().find_map(extract_nested_error_message),
        serde_json::Value::Object(map) => {
            let tag = map
                .get("_tag")
                .or_else(|| map.get("name"))
                .or_else(|| map.get("code"))
                .and_then(|v| match v {
                    serde_json::Value::String(s) => {
                        let t = s.trim();
                        if t.is_empty()
                            || matches!(t, "Fail" | "Die" | "Failure" | "Exit" | "Error")
                        {
                            None
                        } else {
                            Some(t.to_string())
                        }
                    }
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                });
            let direct_msg = ["message", "detail", "reason", "description", "error"]
                .iter()
                .find_map(|k| {
                    map.get(*k)
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                });
            if let Some(msg) = direct_msg {
                return Some(match tag {
                    Some(t) if !msg.contains(&t) => format!("{t}: {msg}"),
                    _ => msg,
                });
            }
            for nested_key in ["error", "defect", "cause", "failure", "payload", "data"] {
                if let Some(nested) = map.get(nested_key)
                    && let Some(found) = extract_nested_error_message(nested)
                {
                    return Some(match tag {
                        Some(t) if !found.contains(&t) => format!("{t}: {found}"),
                        _ => found,
                    });
                }
            }
            tag
        }
        _ => None,
    }
}

/// Redact sensitive keys and inline bearer/token strings from a WebSocket
/// text payload before writing it to scan logs or bug evidence.
pub fn redact_ws_payload(payload: &str, max_bytes: usize) -> String {
    let mut out = if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(payload.trim()) {
        redact_ws_json(&mut val);
        serde_json::to_string(&val).unwrap_or_else(|_| redact_ws_inline_secrets(payload))
    } else {
        redact_ws_inline_secrets(payload)
    };
    if out.len() > max_bytes {
        let mut idx = max_bytes;
        while idx > 0 && !out.is_char_boundary(idx) {
            idx -= 1;
        }
        out.truncate(idx);
    }
    out
}

fn redact_ws_json(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let lower = k.trim().to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "password"
                        | "pass"
                        | "passwd"
                        | "token"
                        | "access_token"
                        | "accesstoken"
                        | "refresh_token"
                        | "refreshtoken"
                        | "id_token"
                        | "idtoken"
                        | "secret"
                        | "client_secret"
                        | "apikey"
                        | "api_key"
                        | "authorization"
                        | "cookie"
                        | "csrf"
                        | "csrf_token"
                        | "session"
                        | "session_id"
                        | "sessionid"
                        | "otp"
                        | "mfa"
                ) {
                    *v = serde_json::Value::String("<redacted>".to_string());
                } else {
                    redact_ws_json(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                redact_ws_json(v);
            }
        }
        serde_json::Value::String(s) => {
            *s = redact_ws_inline_secrets(s);
        }
        _ => {}
    }
}

fn redact_ws_inline_secrets(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let lower = rest.to_ascii_lowercase();
        if let Some(pos) = lower.find("bearer ") {
            out.push_str(&rest[..pos]);
            out.push_str("Bearer <redacted>");
            let after = &rest[pos + 7..];
            let token_len = after
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '}' | ']'))
                .unwrap_or(after.len());
            rest = &after[token_len..];
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

fn truncate_ws_summary(s: &str, max_chars: usize) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        collapsed
    } else {
        let mut out: String = collapsed.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_is_non_production() {
        let u = Url::parse("http://localhost:3000/dashboard").expect("url");
        assert!(is_non_production_target(&u));
    }

    #[test]
    fn private_ipv4_is_non_production() {
        let u = Url::parse("https://192.168.1.20/api").expect("url");
        assert!(is_non_production_target(&u));
    }

    #[test]
    fn public_domain_is_not_non_production() {
        let u = Url::parse("https://app.examplecorp.com/dashboard").expect("url");
        assert!(!is_non_production_target(&u));
    }

    fn req<'a>(method: &'a str, url: &'a str) -> WriteRequest<'a> {
        WriteRequest {
            method,
            url,
            graphql_mutation: false,
            in_auth_flow: false,
        }
    }

    #[test]
    fn write_guard_get_writes_are_guarded_unless_allowlisted() {
        let cfg = WriteGuardConfig::default();
        for url in [
            "http://localhost:3000/delete?id=1",
            "http://localhost:3000/api/remove/42",
            "http://localhost:3000/checkout",
            "http://localhost:3000/cart?action=delete",
        ] {
            assert_eq!(
                write_guard_verdict(&cfg, &req("GET", url)),
                WriteVerdict::Guard,
                "{url} must be guarded"
            );
        }
        // Reads still pass, including benign segments like `/api/data`.
        for url in [
            "http://localhost:3000/api/data",
            "http://localhost:3000/api/addresses",
        ] {
            assert_eq!(
                write_guard_verdict(&cfg, &req("GET", url)),
                WriteVerdict::Read,
                "{url} must pass"
            );
        }
        // Explicit allow should still permit a GET write.
        let mut allowed = WriteGuardConfig::default();
        allowed.allow.push("GET */delete*".to_string());
        assert_eq!(
            write_guard_verdict(&allowed, &req("GET", "http://localhost:3000/delete?id=1")),
            WriteVerdict::Allowed(WriteAllowReason::AllowPattern)
        );
    }

    #[test]
    fn write_guard_allows_password_recovery_ui_routes_but_guards_resets() {
        let cfg = WriteGuardConfig::default();
        for url in [
            "http://localhost:3000/reset-password",
            "http://localhost:3000/reset-password?token=abc",
            "http://localhost:3000/auth/password-reset",
            "http://localhost:3000/forgot-password",
            "http://localhost:3000/account/change-password",
            "http://localhost:3000/reset_password?token=xyz",
        ] {
            assert_eq!(
                write_guard_verdict(&cfg, &req("GET", url)),
                WriteVerdict::Read,
                "{url} must pass as a read-only UI route"
            );
        }
        for url in [
            "http://localhost:3000/api/reset",
            "http://localhost:3000/api/reset-password",
            "http://localhost:3000/reset",
            "http://localhost:3000/reset-password?action=reset",
            "http://localhost:3000/reset-password?action=delete",
        ] {
            assert_eq!(
                write_guard_verdict(&cfg, &req("GET", url)),
                WriteVerdict::Guard,
                "{url} must still be guarded"
            );
        }
    }

    #[test]
    fn write_guard_reads_pass_and_writes_are_guarded() {
        let cfg = WriteGuardConfig::default();
        for m in ["GET", "head", "OPTIONS"] {
            assert_eq!(
                write_guard_verdict(&cfg, &req(m, "http://localhost:3000/api/x")),
                WriteVerdict::Read
            );
        }
        for m in ["POST", "put", "PATCH", "DELETE", "PURGE"] {
            assert_eq!(
                write_guard_verdict(&cfg, &req(m, "http://localhost:3000/api/x")),
                WriteVerdict::Guard,
                "{m} must be guarded"
            );
        }
    }

    #[test]
    fn write_guard_graphql_mutation_is_guarded_even_over_get_or_allowlisted() {
        let mut cfg = WriteGuardConfig::default();
        cfg.allow.push("POST */graphql".to_string());
        let mut r = req("GET", "http://localhost/graphql?query=mutation%20X%7Ba%7D");
        r.graphql_mutation = true;
        assert_eq!(write_guard_verdict(&cfg, &r), WriteVerdict::Guard);
        let mut r = req("POST", "http://localhost/graphql");
        r.graphql_mutation = true;
        assert_eq!(write_guard_verdict(&cfg, &r), WriteVerdict::Guard);
        // Plain queries go through the allow pattern.
        assert_eq!(
            write_guard_verdict(&cfg, &req("POST", "http://localhost/graphql")),
            WriteVerdict::Allowed(WriteAllowReason::AllowPattern)
        );
    }

    #[test]
    fn write_guard_allow_patterns() {
        assert!(allow_pattern_matches(
            "POST */api/search*",
            "post",
            "http://localhost:3000/api/search?q=a"
        ));
        assert!(!allow_pattern_matches(
            "POST */api/search*",
            "DELETE",
            "http://localhost:3000/api/search"
        ));
        assert!(allow_pattern_matches(
            "* /rpc/lookup",
            "POST",
            "https://x.supabase.co/rpc/lookup"
        ));
        assert!(!allow_pattern_matches(
            "/rpc/lookup",
            "POST",
            "https://x.supabase.co/rpc/lookup_and_purge"
        ));
        assert!(allow_pattern_matches(
            "https://api.example.test/*",
            "PATCH",
            "https://api.example.test/v1/items/1"
        ));
        assert!(!allow_pattern_matches("", "POST", "http://localhost/"));
    }

    #[test]
    fn write_guard_auth_allowance_never_passes_logout() {
        let cfg = WriteGuardConfig::default();
        for url in [
            "https://abc.supabase.co/auth/v1/token?grant_type=refresh_token",
            "http://localhost:3000/api/auth/session",
            "https://securetoken.googleapis.com/v1/token?key=k",
            "https://clerk.example.test/v1/client/sessions/sess_1/tokens",
        ] {
            assert_eq!(
                write_guard_verdict(&cfg, &req("POST", url)),
                WriteVerdict::Allowed(WriteAllowReason::AuthRefresh),
                "{url}"
            );
        }
        for url in [
            "https://abc.supabase.co/auth/v1/logout",
            "http://localhost:3000/api/auth/signout",
            "https://auth.example.test/oauth/revoke",
            "http://localhost:3000/auth/sign-out",
        ] {
            assert_eq!(
                write_guard_verdict(&cfg, &req("POST", url)),
                WriteVerdict::Guard,
                "{url}"
            );
            let mut r = req("POST", url);
            r.in_auth_flow = true;
            assert_eq!(write_guard_verdict(&cfg, &r), WriteVerdict::Guard, "{url}");
        }
        let no_auth = WriteGuardConfig {
            allow_auth: false,
            ..WriteGuardConfig::default()
        };
        assert_eq!(
            write_guard_verdict(
                &no_auth,
                &req(
                    "POST",
                    "https://abc.supabase.co/auth/v1/token?grant_type=refresh_token"
                )
            ),
            WriteVerdict::Guard
        );
    }

    #[test]
    fn write_guard_configured_auth_flow_passes() {
        let cfg = WriteGuardConfig::default();
        let mut r = req("POST", "http://localhost:3000/login");
        assert_eq!(write_guard_verdict(&cfg, &r), WriteVerdict::Guard);
        r.in_auth_flow = true;
        assert_eq!(
            write_guard_verdict(&cfg, &r),
            WriteVerdict::Allowed(WriteAllowReason::AuthFlow)
        );
    }

    #[test]
    fn url_glob_matching() {
        assert!(url_glob_matches("*", ""));
        assert!(url_glob_matches("a*c", "abbbc"));
        assert!(url_glob_matches("*/x/*", "http://h/x/y"));
        assert!(!url_glob_matches("a*c", "abd"));
        assert!(!url_glob_matches("abc", "abcd"));
    }

    #[test]
    fn override_allows_live_mutations() {
        let u = Url::parse("https://app.examplecorp.com/dashboard").expect("url");
        let ok = ensure_mutating_target_safe(&u, true, "test operation");
        assert!(ok.is_ok());
    }

    #[test]
    fn actuation_guard_defaults_to_block_even_on_production() {
        let prod = Url::parse("https://app.examplecorp.com/dashboard").expect("url");
        let cfg = actuation_write_guard(&prod, false, "flow replay").expect("guard");
        assert_eq!(cfg.mode, WriteGuardMode::Block);
        let local = Url::parse("http://localhost:3000/").expect("url");
        let cfg = actuation_write_guard(&local, false, "flow test").expect("guard");
        assert_eq!(cfg.mode, WriteGuardMode::Block);
    }

    #[test]
    fn actuation_guard_opt_in_turns_off() {
        let prod = Url::parse("https://app.examplecorp.com/dashboard").expect("url");
        let cfg = actuation_write_guard(&prod, true, "flow replay").expect("guard");
        assert_eq!(cfg.mode, WriteGuardMode::Off);
    }

    #[test]
    fn ws_frame_classification_covers_rpc_graphql_socketio_and_heartbeats() {
        let url = "ws://127.0.0.1:3773/ws";

        // Heartbeats / pings
        for hb in [
            "",
            "ping",
            "2",
            "3",
            r#"{"type":"ping"}"#,
            r#"{"_tag":"Ping"}"#,
            r#"{"type":"connection_init"}"#,
            r#"[null,"1","phoenix","heartbeat",{}]"#,
        ] {
            assert_eq!(
                classify_ws_frame(url, hb).class,
                WsFrameClass::Heartbeat,
                "heartbeat: {hb}"
            );
        }

        // Reads / subscriptions (Effect-RPC, JSON-RPC, GraphQL-WS, tRPC-WS)
        for (payload, expected_op) in [
            (
                r#"{"_tag":"Request","id":"1","tag":"orchestration.getSnapshot"}"#,
                "orchestration.getSnapshot",
            ),
            (
                r#"{"_tag":"Request","id":"2","tag":"server.subscribeConfig"}"#,
                "server.subscribeConfig",
            ),
            (
                r#"{"_tag":"Request","id":"3","tag":"git.status"}"#,
                "git.status",
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"items.list"}"#,
                "items.list",
            ),
            (
                r#"{"type":"subscribe","id":"1","payload":{"query":"query Items { items { id } }","operationName":"Items"}}"#,
                "QUERY:Items",
            ),
            (
                r#"{"method":"query","params":{"path":"settings.get"}}"#,
                "query:settings.get",
            ),
        ] {
            let analysis = classify_ws_frame(url, payload);
            assert_eq!(analysis.class, WsFrameClass::Read, "read: {payload}");
            assert_eq!(
                analysis.operation.as_deref(),
                Some(expected_op),
                "op: {payload}"
            );
        }

        // Mutations (Effect-RPC, JSON-RPC, GraphQL-WS, Socket.IO, tRPC-WS)
        for (payload, expected_op) in [
            (
                r#"{"_tag":"Request","id":"4","tag":"shell.openInEditor","payload":{"cwd":"/tmp"}}"#,
                "shell.openInEditor",
            ),
            (
                r#"{"_tag":"Request","id":"5","tag":"server.upsertKeybinding"}"#,
                "server.upsertKeybinding",
            ),
            (
                r#"{"_tag":"Request","id":"6","tag":"orchestration.dispatchCommand"}"#,
                "orchestration.dispatchCommand",
            ),
            (
                r#"{"type":"subscribe","id":"2","payload":{"query":"mutation RefundOrder($id: ID!) { refundOrder(id: $id) }","operationName":"RefundOrder"}}"#,
                "MUTATION:RefundOrder",
            ),
            (r#"42["create_order",{"amount":10}]"#, "create_order"),
            (
                r#"{"method":"mutation","params":{"path":"settings.save"}}"#,
                "mutation:settings.save",
            ),
        ] {
            let analysis = classify_ws_frame(url, payload);
            assert_eq!(
                analysis.class,
                WsFrameClass::Mutation,
                "mutation: {payload}"
            );
            assert_eq!(
                analysis.operation.as_deref(),
                Some(expected_op),
                "op: {payload}"
            );
        }
    }

    #[test]
    fn ws_write_guard_verdict_respects_mode_and_allow_patterns() {
        let mut cfg = WriteGuardConfig::default();
        let url = "ws://127.0.0.1:3773/ws";
        let open_editor = r#"{"_tag":"Request","tag":"shell.openInEditor"}"#;
        let upsert_kb = r#"{"_tag":"Request","tag":"server.upsertKeybinding"}"#;
        let get_cfg = r#"{"_tag":"Request","tag":"server.getConfig"}"#;

        assert_eq!(
            ws_write_guard_verdict(&cfg, url, open_editor).0,
            WriteVerdict::Guard
        );
        assert_eq!(
            ws_write_guard_verdict(&cfg, url, get_cfg).0,
            WriteVerdict::Read
        );

        cfg.allow.push("WS */ws#shell.openInEditor".to_string());
        assert_eq!(
            ws_write_guard_verdict(&cfg, url, open_editor).0,
            WriteVerdict::Allowed(WriteAllowReason::AllowPattern)
        );
        assert_eq!(
            ws_write_guard_verdict(&cfg, url, upsert_kb).0,
            WriteVerdict::Guard
        );

        cfg.mode = WriteGuardMode::Off;
        assert_eq!(
            ws_write_guard_verdict(&cfg, url, upsert_kb).0,
            WriteVerdict::Read
        );
    }

    #[test]
    fn detect_ws_error_frame_extracts_and_redacts_rpc_errors() {
        let effect_err = r#"{"_tag":"Exit","requestId":"1","exit":{"_tag":"Failure","cause":{"_tag":"Fail","error":{"_tag":"EnvironmentAuthorizationError","message":"This connection lacks permission to change settings with Bearer supersecret123"}}}}"#;
        let extracted = detect_ws_error_frame(effect_err).expect("effect failure detected");
        assert!(
            extracted.contains("EnvironmentAuthorizationError"),
            "{extracted}"
        );
        assert!(extracted.contains("lacks permission"), "{extracted}");
        assert!(!extracted.contains("supersecret123"), "{extracted}");
        assert!(extracted.contains("Bearer <redacted>"), "{extracted}");

        let jsonrpc_err =
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid params"}}"#;
        let extracted = detect_ws_error_frame(jsonrpc_err).expect("jsonrpc error detected");
        assert!(extracted.contains("Invalid params"), "{extracted}");

        let gql_err =
            r#"{"type":"next","id":"1","payload":{"errors":[{"message":"Forbidden resource"}]}}"#;
        let extracted = detect_ws_error_frame(gql_err).expect("graphql ws error detected");
        assert!(extracted.contains("Forbidden resource"), "{extracted}");

        let ok_frame = r#"{"_tag":"Exit","requestId":"1","exit":{"_tag":"Success","value":{}}}"#;
        assert!(detect_ws_error_frame(ok_frame).is_none());
    }

    #[test]
    fn redact_ws_payload_scrubs_secrets() {
        let raw = r#"{"method":"auth.update","token":"tok_live_999","nested":{"password":"p@ss","header":"Bearer abc.def.ghi"}}"#;
        let redacted = redact_ws_payload(raw, 4096);
        assert!(!redacted.contains("tok_live_999"), "{redacted}");
        assert!(!redacted.contains("p@ss"), "{redacted}");
        assert!(!redacted.contains("abc.def.ghi"), "{redacted}");
        assert!(redacted.contains("<redacted>"), "{redacted}");
    }
}
