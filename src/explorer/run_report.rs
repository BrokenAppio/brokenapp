//! `scan-run.json`: how a (possibly multi-hour, possibly resumed) crawl ran:
//! its status and stop reason, the budgets it ran with, crawl time across
//! resumes, the auth session's history (re-logins, expiry) and the scanner's
//! peak memory. Written with every incremental save and at the end; `scan
//! --json` embeds it as `run`.

use std::collections::VecDeque;
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::BrokenAppConfig;

pub const RUN_REPORT_FILE: &str = "scan-run.json";
pub const RUN_REPORT_SCHEMA: &str = "brokenapp.scan-run.v1";

/// Session events kept (the oldest are dropped first; counters keep counting).
const MAX_SESSION_EVENTS: usize = 200;

/// Why the crawl stopped.
pub mod stop_reason {
    pub const QUEUE_EXHAUSTED: &str = "queue_exhausted";
    pub const MAX_VIEWS: &str = "max_views_reached";
    pub const MAX_DURATION: &str = "max_duration_reached";
    pub const STAGNATION: &str = "stagnation_guard";
    pub const CONVERGENCE: &str = "convergence_reached";
    pub const HARD_TIMEOUT: &str = "hard_timeout";
    pub const SESSION_EXPIRED: &str = "session_expired";
    pub const INTERRUPTED: &str = "interrupted";
    pub const BROWSER_UNAVAILABLE: &str = "browser_unavailable";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const ANTIBOT_CHALLENGE: &str = "antibot_challenge";
}

/// One auth-session event of the crawl.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionEvent {
    pub at: DateTime<Utc>,
    /// `session_reauth` (a re-login, successful or not), `session_expired`
    /// (the session ended and could not be renewed: the crawl stopped) or
    /// `session_alive` (a login page was reached, but the session canary
    /// showed the session alive: the route is gated for this role).
    pub event: String,
    /// What raised it: `login_gate` (a tab landed on the login page),
    /// `auth_failures` (repeated 401/403 responses), `canary` (a periodic or
    /// pre-route check), `scan_start` (the saved session was already gone).
    pub trigger: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landed: Option<String>,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub const EVENT_REAUTH: &str = "session_reauth";
pub const EVENT_EXPIRED: &str = "session_expired";
pub const EVENT_ALIVE: &str = "session_alive";

/// The auth session's history over the crawl (resumes included).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SessionLog {
    /// Successful re-logins.
    pub reauths: usize,
    /// Failed re-login attempts.
    pub failed_reauths: usize,
    /// Login pages reached while the session was alive (role-gated routes).
    pub role_gated: usize,
    /// The session ended for good (the crawl stopped `session_expired`).
    pub expired: bool,
    /// Most recent events (bounded).
    #[serde(default)]
    pub events: VecDeque<SessionEvent>,
}

impl SessionLog {
    pub fn record(&mut self, event: SessionEvent) {
        match event.event.as_str() {
            EVENT_REAUTH if event.success => self.reauths += 1,
            EVENT_REAUTH => self.failed_reauths += 1,
            EVENT_EXPIRED => self.expired = true,
            EVENT_ALIVE => self.role_gated += 1,
            _ => {}
        }
        self.events.push_back(event);
        while self.events.len() > MAX_SESSION_EVENTS {
            self.events.pop_front();
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Budgets the crawl ran with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunBudgets {
    /// `0` = no cap.
    pub max_duration_minutes: u64,
    /// `0` = no cap.
    pub max_views: usize,
    /// `0` = automatic per-view watchdog.
    pub view_budget_seconds: u64,
    pub max_stagnation_minutes: u64,
    pub stop_on_convergence: bool,
}

/// The configured auth method (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunAuth {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub renewable: bool,
}

/// `scan-run.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunReport {
    pub schema: String,
    /// `running` while the crawl goes on, then the scan's completion status
    /// (`ok`, `partial_timeout`, `interrupted`, `session_expired`,
    /// `browser_unavailable`).
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Crawl time across all runs of this scan (resumes included; time the
    /// scan was stopped in between does not count).
    pub crawl_seconds: u64,
    /// How often the scan was resumed from its checkpoint.
    pub resumes: u32,
    pub tabs: usize,
    pub budgets: RunBudgets,
    pub views: usize,
    pub queue_remaining: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<RunAuth>,
    #[serde(default, skip_serializing_if = "SessionLog::is_empty")]
    pub session: SessionLog,
    /// Peak resident memory of the scanner process (Chrome not included).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_bytes: Option<u64>,
}

/// Facts of the crawl a report is built from.
pub struct RunFacts<'a> {
    pub status: &'a str,
    pub stop_reason: Option<&'a str>,
    pub started_at: DateTime<Utc>,
    pub crawl_seconds: u64,
    pub resumes: u32,
    pub tabs: usize,
    pub views: usize,
    pub queue_remaining: usize,
    pub session: &'a SessionLog,
}

impl RunReport {
    pub fn build(cfg: &BrokenAppConfig, facts: RunFacts<'_>) -> Self {
        Self {
            schema: RUN_REPORT_SCHEMA.to_string(),
            status: facts.status.to_string(),
            stop_reason: facts.stop_reason.map(str::to_string),
            started_at: facts.started_at,
            updated_at: Utc::now(),
            crawl_seconds: facts.crawl_seconds,
            resumes: facts.resumes,
            tabs: facts.tabs,
            budgets: RunBudgets {
                max_duration_minutes: cfg.scan.max_duration_minutes,
                max_views: cfg.scan.max_views,
                view_budget_seconds: cfg.scan.view_budget_seconds,
                max_stagnation_minutes: cfg.scan.max_stagnation_minutes,
                stop_on_convergence: cfg.scan.stop_on_convergence,
            },
            views: facts.views,
            queue_remaining: facts.queue_remaining,
            auth: cfg.auth.as_ref().map(|auth| RunAuth {
                kind: auth.type_name().to_string(),
                role: cfg.scan.auth_path.clone(),
                renewable: auth.is_renewable(),
            }),
            session: facts.session.clone(),
            peak_rss_bytes: peak_rss_bytes(),
        }
    }
}

pub async fn write_run_report(output_dir: &Path, report: &RunReport) -> Result<()> {
    crate::output::write_json(&output_dir.join(RUN_REPORT_FILE), report).await
}

/// Read `scan-run.json` from a scan directory.
pub fn read_run_report(output_dir: &Path) -> Option<RunReport> {
    let raw = std::fs::read_to_string(output_dir.join(RUN_REPORT_FILE)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Peak resident set size of this process (`getrusage`), when available.
pub fn peak_rss_bytes() -> Option<u64> {
    #[cfg(all(unix, target_pointer_width = "64"))]
    {
        // `struct rusage` on 64-bit Linux and macOS: two `timeval`s (16 bytes
        // each) followed by 14 longs; `ru_maxrss` is the first long.
        unsafe extern "C" {
            fn getrusage(who: i32, usage: *mut [i64; 18]) -> i32;
        }
        let mut usage = [0i64; 18];
        // SAFETY: `usage` is a writable buffer at least as large as `struct
        // rusage` (144 bytes) on the 64-bit targets this is compiled for;
        // RUSAGE_SELF is 0.
        let rc = unsafe { getrusage(0, &mut usage) };
        if rc != 0 || usage[4] <= 0 {
            return None;
        }
        let max_rss = usage[4] as u64;
        // Linux reports kilobytes, macOS bytes.
        if cfg!(target_os = "macos") {
            Some(max_rss)
        } else {
            Some(max_rss.saturating_mul(1024))
        }
    }
    #[cfg(not(all(unix, target_pointer_width = "64")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(event: &str, success: bool) -> SessionEvent {
        SessionEvent {
            at: Utc::now(),
            event: event.to_string(),
            trigger: "login_gate".to_string(),
            url: Some("http://127.0.0.1:47280/reports".to_string()),
            landed: None,
            success,
            attempt: Some(1),
            detail: None,
        }
    }

    #[test]
    fn session_log_counts_and_bounds_events() {
        let mut log = SessionLog::default();
        assert!(log.is_empty());
        log.record(event(EVENT_REAUTH, true));
        log.record(event(EVENT_REAUTH, false));
        log.record(event(EVENT_ALIVE, true));
        assert_eq!((log.reauths, log.failed_reauths, log.role_gated), (1, 1, 1));
        assert!(!log.expired);
        log.record(event(EVENT_EXPIRED, false));
        assert!(log.expired);
        for _ in 0..(MAX_SESSION_EVENTS + 10) {
            log.record(event(EVENT_ALIVE, true));
        }
        assert_eq!(log.events.len(), MAX_SESSION_EVENTS);
        assert_eq!(log.role_gated, MAX_SESSION_EVENTS + 11);
    }

    #[test]
    fn report_describes_budgets_and_auth_without_secrets() {
        let mut cfg: BrokenAppConfig = toml::from_str(
            r##"
[target]
url = "http://127.0.0.1:47280/"

[auth]
type = "form"
login_url = "/login"
username_selector = "#email"
password_selector = "#password"
submit_selector = "#submit"
username = "admin@fixture.test"
password = "very-secret-password"

[scan]
max_duration_minutes = 0
max_views = 0
view_budget_seconds = 300
auth_path = "admin"
"##,
        )
        .unwrap();
        cfg.scan.auth_path = Some("admin".into());
        let log = SessionLog::default();
        let report = RunReport::build(
            &cfg,
            RunFacts {
                status: "running",
                stop_reason: None,
                started_at: Utc::now(),
                crawl_seconds: 12,
                resumes: 1,
                tabs: 4,
                views: 3,
                queue_remaining: 9,
                session: &log,
            },
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("very-secret-password"), "{json}");
        assert!(
            !json.contains("\"session\""),
            "empty session log omitted: {json}"
        );
        assert_eq!(report.budgets.view_budget_seconds, 300);
        assert_eq!(report.budgets.max_duration_minutes, 0);
        let auth = report.auth.unwrap();
        assert_eq!(auth.kind, "form");
        assert_eq!(auth.role.as_deref(), Some("admin"));
        assert!(auth.renewable);
    }

    #[test]
    fn peak_rss_is_reported_on_unix() {
        if cfg!(all(unix, target_pointer_width = "64")) {
            let rss = peak_rss_bytes().expect("rss");
            // Anything from 1 MB to 64 GB is a plausible test process.
            assert!(rss > 1 << 20 && rss < 1 << 36, "{rss}");
        }
    }
}
