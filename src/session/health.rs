//! Session health monitoring.
//!
//! Tracks auth failure rates and consecutive 401/403 responses to detect
//! when a session has expired or become invalid.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct SessionHealthMonitor {
    total_requests: AtomicU64,
    auth_failures: AtomicU64,
    consecutive_failures: AtomicU64,
    views_since_last_canary: AtomicU64,
    forced_dead: AtomicBool,
}

impl SessionHealthMonitor {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            views_since_last_canary: AtomicU64::new(0),
            forced_dead: AtomicBool::new(false),
        }
    }

    /// Record a response status code.
    pub fn record_status(&self, status: u16) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if status == 401 || status == 403 {
            self.auth_failures.fetch_add(1, Ordering::Relaxed);
            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        } else {
            self.consecutive_failures.store(0, Ordering::Relaxed);
        }
    }

    /// Returns true if the session appears dead (>3 consecutive 401/403).
    pub fn is_session_dead(&self) -> bool {
        self.forced_dead.load(Ordering::Relaxed)
            || self.consecutive_failures.load(Ordering::Relaxed) > 3
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    pub fn auth_failure_rate(&self) -> f64 {
        let total = self.total_requests();
        if total == 0 {
            return 0.0;
        }
        self.auth_failures() as f64 / total as f64
    }

    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.auth_failures.store(0, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.views_since_last_canary.store(0, Ordering::Relaxed);
        self.forced_dead.store(false, Ordering::Relaxed);
    }

    /// Force the session into a dead state until `reset()` is called.
    /// Used by proactive canary checks that may not show up as 401/403
    /// responses in the main network error stream.
    pub fn force_dead(&self) {
        self.forced_dead.store(true, Ordering::Relaxed);
    }

    /// Record that a view exploration completed.
    pub fn record_view_completed(&self) {
        self.views_since_last_canary.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns true if a canary health-check is due.
    /// An `interval` of 0 disables canary checks.
    pub fn canary_due(&self, interval: u64) -> bool {
        if interval == 0 {
            return false;
        }
        self.views_since_last_canary.load(Ordering::Relaxed) >= interval
    }

    /// Reset the canary counter after performing a canary check.
    pub fn reset_canary_counter(&self) {
        self.views_since_last_canary.store(0, Ordering::Relaxed);
    }

    /// Returns true if there's exactly one consecutive failure and the session
    /// hasn't been force-dead. Used for single-request retry logic.
    pub fn is_single_failure_recoverable(&self) -> bool {
        self.consecutive_failures.load(Ordering::Relaxed) == 1
            && !self.forced_dead.load(Ordering::Relaxed)
    }

    /// Clear the consecutive failure counter (e.g., after a successful canary
    /// confirms the session is still alive).
    pub fn clear_consecutive_failures(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }
}

impl Default for SessionHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Signal indicating the session may have been invalidated.
#[derive(Debug, Clone)]
pub struct InvalidationSignal {
    pub kind: InvalidationKind,
    pub evidence: String,
}

/// Category of session invalidation signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationKind {
    /// HTTP 401 or 403 response.
    AuthStatus,
    /// Redirect to a login page.
    LoginRedirect,
    /// Response body contains session expiration markers.
    ExpiredBodyMarker,
    /// Session cookie was deleted or expired.
    CookieDeletion,
}

/// Common login-page URL patterns.
const LOGIN_PATTERNS: &[&str] = &[
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/auth/signin",
    "/accounts/login",
    "/sso/login",
];

/// Path segments that name a login page (`/login`, `/auth/sign-in`,
/// `/users/sign_in`, `/#/login`). Whole segments only: `/authors` is not one.
const LOGIN_SEGMENTS: &[&str] = &[
    "login", "log-in", "log_in", "signin", "sign-in", "sign_in", "logon", "sso",
];

/// `true` when `url` looks like the app's login page: its path (or hash
/// route) has a login segment, or contains `hint` (the configured login
/// path, e.g. `/session/new`).
pub fn looks_like_login_page(url: &str, hint: Option<&str>) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    let path = parsed.path().to_ascii_lowercase();
    let hash_route = parsed
        .fragment()
        .map(|f| f.split('?').next().unwrap_or(f).to_ascii_lowercase())
        .filter(|f| f.starts_with('/') || f.starts_with("!/"))
        .unwrap_or_default();
    if let Some(hint) = hint.map(str::trim).filter(|h| !h.is_empty() && *h != "/") {
        let hint = hint.to_ascii_lowercase();
        // A full URL hint is matched on its path.
        let hint_path = url::Url::parse(&hint)
            .map(|u| u.path().to_string())
            .unwrap_or(hint);
        let hint_path = hint_path.split('?').next().unwrap_or_default().to_string();
        if !hint_path.is_empty()
            && hint_path != "/"
            && (path.contains(&hint_path) || hash_route.contains(&hint_path))
        {
            return true;
        }
    }
    path.split('/')
        .chain(hash_route.split('/'))
        .any(|segment| LOGIN_SEGMENTS.contains(&segment))
}

/// `true` when visiting `requested` landed on the login page instead: the
/// session did not open the page. A login page the crawler asked for itself
/// is not a gate.
pub fn landed_on_login_gate(requested: &str, landed: &str, hint: Option<&str>) -> bool {
    looks_like_login_page(landed, hint) && !looks_like_login_page(requested, hint)
}

/// Common session-expired body markers.
const EXPIRED_MARKERS: &[&str] = &[
    "session expired",
    "session has expired",
    "your session has expired",
    "token expired",
    "token has expired",
    "please log in",
    "please sign in",
    "authentication required",
    "login required",
    "unauthorized",
];

/// Check a response for signs of session invalidation.
pub fn check_response_for_invalidation(
    status: u16,
    headers: &std::collections::BTreeMap<String, String>,
    body_snippet: Option<&str>,
    current_url: &str,
    _login_patterns: Option<&[String]>,
) -> Option<InvalidationSignal> {
    // 1. Auth status codes
    if status == 401 || status == 403 {
        return Some(InvalidationSignal {
            kind: InvalidationKind::AuthStatus,
            evidence: format!("HTTP {}", status),
        });
    }

    // 2. Login redirect (3xx to login URL)
    if (300..400).contains(&status) {
        if let Some(location) = headers.get("location") {
            let loc_lower = location.to_lowercase();
            for pattern in LOGIN_PATTERNS {
                if loc_lower.contains(pattern) {
                    return Some(InvalidationSignal {
                        kind: InvalidationKind::LoginRedirect,
                        evidence: format!("redirect to {}", location),
                    });
                }
            }
        }
    }

    // 3. Non-redirect that landed on a login page
    if let Ok(url) = url::Url::parse(current_url) {
        let path = url.path().to_lowercase();
        for pattern in LOGIN_PATTERNS {
            if path.contains(pattern) && status == 200 {
                return Some(InvalidationSignal {
                    kind: InvalidationKind::LoginRedirect,
                    evidence: format!("landed on login page: {}", current_url),
                });
            }
        }
    }

    // 4. Body contains session expired markers
    if let Some(body) = body_snippet {
        let body_lower = body.to_lowercase();
        for marker in EXPIRED_MARKERS {
            if body_lower.contains(marker) {
                return Some(InvalidationSignal {
                    kind: InvalidationKind::ExpiredBodyMarker,
                    evidence: format!("body contains: {}", marker),
                });
            }
        }
    }

    // 5. Cookie deletion (set-cookie with max-age=0 or expires in the past for session cookies)
    if let Some(set_cookie) = headers.get("set-cookie") {
        let sc_lower = set_cookie.to_lowercase();
        if sc_lower.contains("max-age=0") || sc_lower.contains("expires=thu, 01 jan 1970") {
            // Check if it is a common session cookie
            let common_session_cookies = ["session", "sid", "token", "auth", "jwt"];
            for name in common_session_cookies {
                if sc_lower.starts_with(name) || sc_lower.contains(&format!("{}=", name)) {
                    return Some(InvalidationSignal {
                        kind: InvalidationKind::CookieDeletion,
                        evidence: format!("session cookie deletion: {}", name),
                    });
                }
            }
        }
    }

    None
}

impl SessionHealthMonitor {
    /// Record an invalidation signal, feeding into the existing consecutive_failures counter.
    pub fn record_invalidation(&self, signal: &InvalidationSignal) {
        self.total_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match signal.kind {
            InvalidationKind::AuthStatus => {
                self.auth_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.consecutive_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            InvalidationKind::LoginRedirect
            | InvalidationKind::ExpiredBodyMarker
            | InvalidationKind::CookieDeletion => {
                // These are strong signals -- count as 2 consecutive failures
                self.auth_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.consecutive_failures
                    .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_pages_are_recognized_by_whole_segments() {
        for url in [
            "http://127.0.0.1:3000/login",
            "http://127.0.0.1:3000/login?next=%2Freports",
            "http://127.0.0.1:3000/auth/sign-in",
            "http://127.0.0.1:3000/users/sign_in",
            "http://127.0.0.1:3000/#/login",
            "https://app.test/sso/start",
        ] {
            assert!(looks_like_login_page(url, None), "{url}");
        }
        for url in [
            "http://127.0.0.1:3000/authors",
            "http://127.0.0.1:3000/dashboard",
            "http://127.0.0.1:3000/blog/login-tips-2026",
            "http://127.0.0.1:3000/forbidden",
            "about:blank",
            "not a url",
        ] {
            assert!(!looks_like_login_page(url, None), "{url}");
        }
    }

    #[test]
    fn configured_login_paths_are_recognized() {
        assert!(looks_like_login_page(
            "http://127.0.0.1:3000/session/new?r=1",
            Some("/session/new")
        ));
        assert!(looks_like_login_page(
            "http://127.0.0.1:3000/session/new",
            Some("http://127.0.0.1:3000/session/new")
        ));
        assert!(!looks_like_login_page(
            "http://127.0.0.1:3000/dashboard",
            Some("/")
        ));
    }

    #[test]
    fn a_requested_login_page_is_not_a_gate() {
        assert!(landed_on_login_gate(
            "http://127.0.0.1:3000/reports",
            "http://127.0.0.1:3000/login?next=/reports",
            None
        ));
        assert!(!landed_on_login_gate(
            "http://127.0.0.1:3000/login",
            "http://127.0.0.1:3000/login",
            None
        ));
        assert!(!landed_on_login_gate(
            "http://127.0.0.1:3000/reports",
            "http://127.0.0.1:3000/reports",
            None
        ));
    }
}
