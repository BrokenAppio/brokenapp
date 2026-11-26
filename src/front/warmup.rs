//! Route warm-up before a crawl.
//!
//! Dev servers (Next, Vite, Astro) compile a page the first time it is
//! requested; a cold compile can outlast the crawler's navigation timeout and
//! silently drop a seeded route. `map` therefore GETs every seeded route
//! first, a few at a time with a short timeout, retries the ones that timed
//! out once (their compile usually finished meanwhile), and reports routes
//! that still failed. Only GETs to the target's own origin are sent, and
//! sign-out/revoke URLs are never requested.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use futures::StreamExt;
use serde::Serialize;
use url::Url;

use super::locality;

/// Warm-up duration above which a Next.js dev server triggers a production-build tip.
pub const SLOW_NEXT_DEV_THRESHOLD_MS: u64 = 10_000;

/// Warm-up tuning.
#[derive(Clone)]
pub struct WarmupOptions {
    /// Requests in flight at once.
    pub concurrency: usize,
    /// Per-request timeout (headers and body).
    pub timeout: Duration,
    /// Wall-clock budget for the whole warm-up; routes not started in time
    /// are reported as skipped.
    pub budget: Duration,
    /// Maximum distinct document targets to warm (`0` = unlimited). Routes
    /// beyond the cap are compiled lazily on first crawler visit.
    pub max_routes: usize,
    /// Extra request headers (e.g. `Cookie`, `Authorization`, identifying headers)
    /// sent only to the target's own origin so auth-gated routes compile during
    /// warm-up. Values are never logged.
    pub extra_headers: BTreeMap<String, String>,
    /// Optional custom `User-Agent` header for warm-up requests.
    pub user_agent: Option<String>,
}

impl fmt::Debug for WarmupOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self.extra_headers.keys().map(String::as_str).collect();
        f.debug_struct("WarmupOptions")
            .field("concurrency", &self.concurrency)
            .field("timeout", &self.timeout)
            .field("budget", &self.budget)
            .field("max_routes", &self.max_routes)
            .field("extra_headers", &header_names)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Default for WarmupOptions {
    fn default() -> Self {
        Self {
            concurrency: 2,
            timeout: Duration::from_secs(15),
            budget: Duration::from_secs(45),
            max_routes: 20,
            extra_headers: BTreeMap::new(),
            user_agent: None,
        }
    }
}

/// A seeded route that did not answer cleanly.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WarmupFailure {
    pub route: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// `HTTP 500`, `timed out after 15s`, `connection refused`, ...
    pub error: String,
}

/// A seeded route that was not requested.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WarmupSkip {
    pub route: String,
    pub reason: String,
}

/// What the warm-up did.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct WarmupReport {
    /// Distinct URLs requested (hash routes share their document).
    pub requested: usize,
    pub ok: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<WarmupFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<WarmupSkip>,
    /// Routes that timed out first and answered on the retry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovered: Vec<String>,
    pub elapsed_ms: u64,
}

impl WarmupReport {
    /// Number of seeded routes deferred by `max_routes` (lazy-compiled on visit).
    pub fn capped_count(&self) -> usize {
        self.skipped.iter().filter(|s| s.reason == SKIP_CAP).count()
    }

    /// Concise progress summary line explaining warmed vs. capped seeded routes.
    pub fn summary_line(&self, max_routes: usize) -> String {
        let secs = self.elapsed_ms as f64 / 1000.0;
        let capped = self.capped_count();
        let mut extras = Vec::new();
        if capped > 0 {
            let budget_skipped = self
                .skipped
                .iter()
                .filter(|s| s.reason == SKIP_BUDGET)
                .count();
            let total = self.requested + capped + budget_skipped;
            let cap = if max_routes > 0 {
                max_routes
            } else {
                self.requested
            };
            extras.push(format!(
                "cap {cap} of {total} seeded routes; {capped} lazy-compiled on visit"
            ));
        }
        if !self.recovered.is_empty() {
            extras.push(format!("{} answered on retry", self.recovered.len()));
        }
        let suffix = if extras.is_empty() {
            String::new()
        } else {
            format!(" ({})", extras.join("; "))
        };
        format!(
            "warm-up: {}/{} warmed in {:.1}s{suffix}",
            self.ok, self.requested, secs
        )
    }

    /// One line per problem, for the map's `warnings[]`.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.failed.is_empty() {
            let list: Vec<String> = self
                .failed
                .iter()
                .map(|f| format!("{} ({})", f.route, f.error))
                .collect();
            out.push(format!(
                "route warm-up: {} of {} seeded routes failed: {}",
                self.failed.len(),
                self.requested,
                list.join(", ")
            ));
        }
        let budget: Vec<&str> = self
            .skipped
            .iter()
            .filter(|s| s.reason == SKIP_BUDGET)
            .map(|s| s.route.as_str())
            .collect();
        if !budget.is_empty() {
            out.push(format!(
                "route warm-up budget ran out; {} routes not warmed: {}",
                budget.len(),
                budget.join(", ")
            ));
        }
        out
    }
}

/// Suggest building and starting a production Next.js server when warm-up
/// took `>= 10s` against a `next dev` server.
pub fn slow_next_dev_tip(
    elapsed_ms: u64,
    dev_cmd: Option<&str>,
    framework: Option<&str>,
) -> Option<String> {
    if elapsed_ms < SLOW_NEXT_DEV_THRESHOLD_MS {
        return None;
    }
    let cmd = dev_cmd.unwrap_or_default().to_ascii_lowercase();
    if cmd.contains("next start") {
        return None;
    }
    let fw = framework.unwrap_or_default().to_ascii_lowercase();
    if !cmd.contains("next dev") && !fw.contains("next") {
        return None;
    }
    let secs = elapsed_ms as f64 / 1000.0;
    Some(format!(
        "warm-up took {secs:.1}s on a Next.js dev server (on-demand compilation); for much faster crawls, run `next build && next start` (or point project.dev_cmd at `next start`)"
    ))
}

const SKIP_BUDGET: &str = "warm-up budget exhausted";
const SKIP_CAP: &str = "warm-up cap (lazy-compiled on visit)";

/// One distinct document to request.
struct Target {
    /// Seeded routes served by this document (`/` and `/#/admin` share one).
    routes: Vec<String>,
    url: Url,
}

/// Priority order when selecting which targets to warm: always warm the entry
/// route (`/`) first, then shallowest path-depth routes first (preserving input
/// order within each depth).
fn target_priority_key(base: &Url, target: &Target) -> (bool, usize) {
    let path = target.url.path();
    let base_path = base.path().trim_end_matches('/');
    let trimmed = path.trim_end_matches('/');
    let is_entry = path == "/" || trimmed == base_path;
    let depth = path.split('/').filter(|seg| !seg.is_empty()).count();
    (!is_entry, depth)
}

enum Attempt {
    Ok,
    Failed {
        status: Option<u16>,
        error: String,
        timed_out: bool,
    },
    Skipped,
}

/// Resolve seeds against `base`, de-duplicate by document URL (fragment
/// dropped) and refuse anything that would leave the target's origin.
fn plan_targets(base: &Url, routes: &[String]) -> (Vec<Target>, Vec<WarmupSkip>) {
    let mut targets: Vec<Target> = Vec::new();
    let mut skipped = Vec::new();
    for route in routes {
        let joined = if route.starts_with("http://") || route.starts_with("https://") {
            Url::parse(route)
        } else {
            base.join(route)
        };
        let Ok(mut url) = joined else {
            skipped.push(WarmupSkip {
                route: route.clone(),
                reason: "not a valid URL path".into(),
            });
            continue;
        };
        if url.origin() != base.origin() {
            skipped.push(WarmupSkip {
                route: route.clone(),
                reason: "outside the target origin".into(),
            });
            continue;
        }
        if crate::safety::is_session_ending_url(url.as_str()) {
            skipped.push(WarmupSkip {
                route: route.clone(),
                reason: "sign-out/revoke URL".into(),
            });
            continue;
        }
        url.set_fragment(None);
        match targets.iter_mut().find(|t| t.url == url) {
            Some(t) => t.routes.push(route.clone()),
            None => targets.push(Target {
                routes: vec![route.clone()],
                url,
            }),
        }
    }
    (targets, skipped)
}

fn client(
    base: &Url,
    timeout: Duration,
    user_agent: Option<&str>,
) -> anyhow::Result<reqwest::Client> {
    use anyhow::Context;
    let ua = user_agent
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(concat!("brokenapp-map-warmup/", env!("CARGO_PKG_VERSION")));
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(5)))
        // Never follow redirects: they may point at another (remote) host,
        // and a redirect already means the route answered.
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(locality::is_local_url(base))
        .no_proxy()
        .user_agent(ua)
        .build()
        .context("build warm-up http client")
}

async fn fetch(
    client: &reqwest::Client,
    base: &Url,
    url: &Url,
    timeout: Duration,
    extra_headers: &BTreeMap<String, String>,
) -> Attempt {
    let mut req = client.get(url.clone());
    if url.origin() == base.origin() {
        for (name, value) in extra_headers {
            let name = name.trim();
            if !name.is_empty() && !value.trim().is_empty() {
                req = req.header(name, value.as_str());
            }
        }
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Drain the body so streamed server rendering finishes too.
            let _ = resp.bytes().await;
            if status >= 500 || matches!(status, 404 | 410) {
                Attempt::Failed {
                    status: Some(status),
                    error: format!("HTTP {status}"),
                    timed_out: false,
                }
            } else {
                Attempt::Ok
            }
        }
        Err(err) if err.is_timeout() => Attempt::Failed {
            status: None,
            error: format!("timed out after {}s", timeout.as_secs()),
            timed_out: true,
        },
        Err(err) if err.is_connect() => Attempt::Failed {
            status: None,
            error: "connection refused".into(),
            timed_out: false,
        },
        Err(err) => Attempt::Failed {
            status: None,
            error: err.without_url().to_string(),
            timed_out: false,
        },
    }
}

/// Run `targets` with bounded concurrency; targets that cannot start before
/// `deadline` are skipped.
async fn run_pass(
    client: &reqwest::Client,
    base: &Url,
    targets: &[&Target],
    opts: &WarmupOptions,
    deadline: Instant,
) -> Vec<Attempt> {
    let mut results: Vec<(usize, Attempt)> = futures::stream::iter(targets.iter().enumerate())
        .map(|(i, t)| async move {
            if Instant::now() >= deadline {
                return (i, Attempt::Skipped);
            }
            (
                i,
                fetch(client, base, &t.url, opts.timeout, &opts.extra_headers).await,
            )
        })
        .buffer_unordered(opts.concurrency.max(1))
        .collect()
        .await;
    results.sort_by_key(|(i, _)| *i);
    results.into_iter().map(|(_, a)| a).collect()
}

/// GET every seeded route once (see the module docs).
pub async fn warm_routes(base: &Url, routes: &[String], opts: &WarmupOptions) -> WarmupReport {
    let started = Instant::now();
    let deadline = started + opts.budget;
    let (mut targets, mut skipped) = plan_targets(base, routes);
    targets.sort_by_key(|t| target_priority_key(base, t));
    if opts.max_routes > 0 && targets.len() > opts.max_routes {
        for excess in targets.drain(opts.max_routes..) {
            for route in excess.routes {
                skipped.push(WarmupSkip {
                    route,
                    reason: SKIP_CAP.into(),
                });
            }
        }
    }
    let mut report = WarmupReport::default();
    let client = match client(base, opts.timeout, opts.user_agent.as_deref()) {
        Ok(c) => c,
        Err(err) => {
            for t in &targets {
                for route in &t.routes {
                    skipped.push(WarmupSkip {
                        route: route.clone(),
                        reason: format!("{err:#}"),
                    });
                }
            }
            report.skipped = skipped;
            return report;
        }
    };

    let all: Vec<&Target> = targets.iter().collect();
    let mut attempts = run_pass(&client, base, &all, opts, deadline).await;
    let retry_idx: Vec<usize> = attempts
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            matches!(
                a,
                Attempt::Failed {
                    timed_out: true,
                    ..
                }
            )
        })
        .map(|(i, _)| i)
        .collect();
    if !retry_idx.is_empty() {
        let retry: Vec<&Target> = retry_idx.iter().map(|&i| all[i]).collect();
        let second = run_pass(&client, base, &retry, opts, deadline).await;
        for (i, attempt) in retry_idx.into_iter().zip(second) {
            match attempt {
                // Budget ran out before the retry: keep the first result.
                Attempt::Skipped => {}
                Attempt::Ok => {
                    report.recovered.extend(all[i].routes.iter().cloned());
                    attempts[i] = Attempt::Ok;
                }
                failed => attempts[i] = failed,
            }
        }
    }

    for (t, attempt) in all.iter().zip(attempts) {
        match attempt {
            Attempt::Ok => {
                report.requested += 1;
                report.ok += 1;
            }
            Attempt::Failed { status, error, .. } => {
                report.requested += 1;
                for route in &t.routes {
                    report.failed.push(WarmupFailure {
                        route: route.clone(),
                        status,
                        error: error.clone(),
                    });
                }
            }
            Attempt::Skipped => {
                for route in &t.routes {
                    skipped.push(WarmupSkip {
                        route: route.clone(),
                        reason: SKIP_BUDGET.into(),
                    });
                }
            }
        }
    }
    report.skipped = skipped;
    report.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Tiny HTTP server: `/slow-once` sleeps past the timeout on its first
    /// request only (a cold compile), `/boom` is a 500, `/missing` a 404,
    /// `/hang` never answers, everything else 200. Records request paths.
    async fn server() -> (Url, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = Arc::clone(&seen);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let line = head.lines().next().unwrap_or_default().to_string();
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let first_slow = {
                        let mut seen = log.lock().unwrap();
                        let first = !seen.iter().any(|p| p == &path);
                        seen.push(path.clone());
                        first
                    };
                    let status = match path.as_str() {
                        "/boom" => "500 Internal Server Error",
                        "/missing" => "404 Not Found",
                        "/hang" => {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            "200 OK"
                        }
                        "/slow-once" if first_slow => {
                            tokio::time::sleep(Duration::from_millis(1500)).await;
                            "200 OK"
                        }
                        _ => "200 OK",
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (
            Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
            seen,
            handle,
        )
    }

    #[tokio::test]
    async fn warms_routes_reports_failures_and_retries_cold_ones() {
        let (base, seen, handle) = server().await;
        let routes: Vec<String> = [
            "/",
            "/#/admin",
            "/about",
            "/boom",
            "/missing",
            "/slow-once",
            "/hang",
            "/logout",
            "http://example.com/x",
            "//evil.test/x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = WarmupOptions {
            concurrency: 4,
            timeout: Duration::from_millis(700),
            budget: Duration::from_secs(20),
            max_routes: 0,
            ..Default::default()
        };
        let report = warm_routes(&base, &routes, &opts).await;

        // `/` and `/#/admin` share a document.
        assert_eq!(report.requested, 6, "{report:?}");
        assert_eq!(report.ok, 3, "{report:?}");
        assert_eq!(report.recovered, vec!["/slow-once"]);
        let failed: Vec<(&str, &str)> = report
            .failed
            .iter()
            .map(|f| (f.route.as_str(), f.error.as_str()))
            .collect();
        assert!(failed.contains(&("/boom", "HTTP 500")), "{failed:?}");
        assert!(failed.contains(&("/missing", "HTTP 404")), "{failed:?}");
        assert!(
            failed
                .iter()
                .any(|(r, e)| *r == "/hang" && e.starts_with("timed out")),
            "{failed:?}"
        );
        let skipped: Vec<&str> = report.skipped.iter().map(|s| s.route.as_str()).collect();
        assert_eq!(
            skipped,
            vec!["/logout", "http://example.com/x", "//evil.test/x"]
        );

        let requested = seen.lock().unwrap().clone();
        assert!(!requested.iter().any(|p| p.contains("logout")));
        assert_eq!(requested.iter().filter(|p| *p == "/").count(), 1);
        let warnings = report.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("3 of 6 seeded routes failed"),
            "{warnings:?}"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn budget_skips_routes_not_started_in_time() {
        let (base, _seen, handle) = server().await;
        let routes: Vec<String> = ["/hang", "/a", "/b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = WarmupOptions {
            concurrency: 1,
            timeout: Duration::from_millis(400),
            budget: Duration::from_millis(200),
            max_routes: 0,
            ..Default::default()
        };
        let report = warm_routes(&base, &routes, &opts).await;
        let skipped: Vec<&str> = report
            .skipped
            .iter()
            .filter(|s| s.reason == SKIP_BUDGET)
            .map(|s| s.route.as_str())
            .collect();
        assert_eq!(skipped, vec!["/a", "/b"]);
        assert!(report.warnings().iter().any(|w| w.contains("budget")));
        handle.abort();
    }

    #[tokio::test]
    async fn max_routes_caps_warmup_and_preserves_root_and_shallow_routes_first() {
        let defaults = WarmupOptions::default();
        assert_eq!(defaults.concurrency, 2);
        assert_eq!(defaults.budget, Duration::from_secs(45));
        assert_eq!(defaults.max_routes, 20);

        let (base, seen, handle) = server().await;
        let routes: Vec<String> = [
            "/staff/administration/warehouse-stations",
            "/admin/reports/daily",
            "/clients",
            "/orders",
            "/settings",
            "/billing/invoices",
            "/",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = WarmupOptions {
            concurrency: 1,
            timeout: Duration::from_secs(5),
            budget: Duration::from_secs(10),
            max_routes: 4,
            ..Default::default()
        };
        let report = warm_routes(&base, &routes, &opts).await;

        assert_eq!(report.requested, 4, "{report:?}");
        assert_eq!(report.ok, 4, "{report:?}");
        let requested = seen.lock().unwrap().clone();
        assert_eq!(
            requested,
            vec!["/", "/clients", "/orders", "/settings"],
            "root must warm first, followed by shallowest routes"
        );
        let capped: Vec<&str> = report
            .skipped
            .iter()
            .filter(|s| s.reason == SKIP_CAP)
            .map(|s| s.route.as_str())
            .collect();
        assert_eq!(
            capped,
            vec![
                "/billing/invoices",
                "/staff/administration/warehouse-stations",
                "/admin/reports/daily",
            ]
        );
        // Capped routes are lazily compiled on visit and must not emit warnings.
        assert!(report.warnings().is_empty(), "{:?}", report.warnings());
        handle.abort();
    }

    #[tokio::test]
    async fn extra_headers_sent_on_same_origin_warmup_gets_and_redacted_in_debug() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = Arc::clone(&captured);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let raw = String::from_utf8_lossy(&buf[..n]).to_string();
                    log.lock().unwrap().push(raw);
                    let resp =
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        let base = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let mut extra_headers = BTreeMap::new();
        extra_headers.insert("Cookie".to_string(), "sid=super-secret-cookie".to_string());
        extra_headers.insert(
            "Authorization".to_string(),
            "Bearer super-secret-jwt".to_string(),
        );
        let opts = WarmupOptions {
            concurrency: 2,
            timeout: Duration::from_secs(5),
            budget: Duration::from_secs(10),
            max_routes: 0,
            extra_headers,
            user_agent: None,
        };
        let debug_str = format!("{opts:?}");
        assert!(!debug_str.contains("super-secret-cookie"), "{debug_str}");
        assert!(!debug_str.contains("super-secret-jwt"), "{debug_str}");
        assert!(debug_str.contains("Cookie"), "{debug_str}");
        assert!(debug_str.contains("Authorization"), "{debug_str}");

        let routes = vec![
            "/dashboard".to_string(),
            "http://example.com/offsite".to_string(),
        ];
        let report = warm_routes(&base, &routes, &opts).await;
        assert_eq!(report.requested, 1, "{report:?}");
        assert_eq!(report.ok, 1, "{report:?}");
        assert_eq!(report.skipped.len(), 1, "{report:?}");

        let reqs = captured.lock().unwrap().clone();
        assert_eq!(reqs.len(), 1);
        let lower = reqs[0].to_ascii_lowercase();
        assert!(
            lower.contains("cookie: sid=super-secret-cookie"),
            "{}",
            reqs[0]
        );
        assert!(
            lower.contains("authorization: bearer super-secret-jwt"),
            "{}",
            reqs[0]
        );
        handle.abort();
    }

    #[test]
    fn summary_line_clarifies_cap_and_retries() {
        let mut skipped = Vec::new();
        for i in 0..11 {
            skipped.push(WarmupSkip {
                route: format!("/extra-{i}"),
                reason: SKIP_CAP.into(),
            });
        }
        let report = WarmupReport {
            requested: 20,
            ok: 18,
            failed: Vec::new(),
            skipped,
            recovered: Vec::new(),
            elapsed_ms: 4200,
        };
        assert_eq!(report.capped_count(), 11);
        assert_eq!(
            report.summary_line(20),
            "warm-up: 18/20 warmed in 4.2s (cap 20 of 31 seeded routes; 11 lazy-compiled on visit)"
        );

        let uncapped = WarmupReport {
            requested: 6,
            ok: 6,
            failed: Vec::new(),
            skipped: Vec::new(),
            recovered: vec!["/slow".to_string()],
            elapsed_ms: 1500,
        };
        assert_eq!(
            uncapped.summary_line(20),
            "warm-up: 6/6 warmed in 1.5s (1 answered on retry)"
        );
    }

    #[test]
    fn slow_next_dev_tip_matches_slow_dev_servers_only() {
        assert_eq!(
            slow_next_dev_tip(9_999, Some("next dev"), Some("nextjs-app")),
            None
        );
        let from_cmd = slow_next_dev_tip(12_400, Some("npx next dev -p 3000"), None).unwrap();
        assert!(from_cmd.contains("next build && next start"), "{from_cmd}");
        let from_fw = slow_next_dev_tip(10_000, Some("npm run dev"), Some("nextjs-app")).unwrap();
        assert!(from_fw.contains("next build && next start"), "{from_fw}");
        assert!(
            slow_next_dev_tip(15_000, None, Some("nextjs-pages")).is_some(),
            "Next.js framework without explicit next start should get the tip"
        );
        assert_eq!(
            slow_next_dev_tip(
                15_000,
                Some("next build && next start -p 3000"),
                Some("nextjs-app")
            ),
            None
        );
        assert_eq!(
            slow_next_dev_tip(15_000, Some("vite --port 5173"), Some("vite")),
            None
        );
    }
}
