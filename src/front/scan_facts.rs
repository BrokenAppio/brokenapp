//! Facts `map` reads from a scan's output directory for its progress lines,
//! warnings and coverage summary: interaction counts (`interactions.jsonl`,
//! read incrementally while the scan runs), seeded routes the crawler could
//! not map and stop conditions (`coverage-gaps.json`), and navigation
//! failures (`checkpoint.json` / `bugs.json`).
//!
//! Everything here is best effort: a missing or unparsable artifact yields no
//! facts, never an error.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

/// Route key of a page URL: path without trailing slash, plus the fragment
/// for hash routes (`/#/basket`). Queries are dropped.
pub fn route_key(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    let mut path = url.path().trim_end_matches('/').to_string();
    if path.is_empty() {
        path.push('/');
    }
    match url.fragment() {
        Some(frag) if crate::explorer::url_utils::fragment_is_route(Some(frag)) => {
            let frag = frag.split('?').next().unwrap_or(frag);
            let frag = if frag.len() > 1 {
                frag.trim_end_matches('/')
            } else {
                frag
            };
            let base = path.trim_end_matches('/');
            Some(format!("{base}/#{frag}"))
        }
        _ => Some(path),
    }
}

/// Normalize a seed or route string for comparisons (no query, no trailing slash).
pub fn normalize_route(route: &str) -> String {
    if route.starts_with("http://") || route.starts_with("https://") {
        return route_key(route).unwrap_or_else(|| route.to_string());
    }
    let route = route.split('?').next().unwrap_or(route);
    let (path, frag) = match route.split_once('#') {
        Some((p, f)) => (p, Some(f)),
        None => (route, None),
    };
    let mut out = path.trim_end_matches('/').to_string();
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    if let Some(frag) = frag {
        let frag = if frag.len() > 1 {
            frag.trim_end_matches('/')
        } else {
            frag
        };
        out = format!("{}/#{frag}", out.trim_end_matches('/'));
    }
    out
}

/// Running counts from `interactions.jsonl`, read incrementally.
#[derive(Debug, Default, Clone)]
pub struct InteractionTally {
    offset: u64,
    /// Controls the crawler attempted (any outcome except `skipped`).
    pub exercised: u64,
    /// Controls it logged (attempted or skipped).
    pub seen: u64,
    /// Routes with at least one logged control.
    pub routes: BTreeSet<String>,
}

impl InteractionTally {
    /// Consume complete lines appended since the last call.
    pub fn update(&mut self, path: &Path) {
        let Ok(mut file) = std::fs::File::open(path) else {
            return;
        };
        let Ok(len) = file.metadata().map(|m| m.len()) else {
            return;
        };
        if len < self.offset {
            // Truncated or replaced: start over.
            *self = Self::default();
        }
        if len == self.offset || file.seek(SeekFrom::Start(self.offset)).is_err() {
            return;
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            return;
        }
        // Only whole lines; a partially written last line is read next time.
        let Some(last_newline) = buf.iter().rposition(|b| *b == b'\n') else {
            return;
        };
        for line in buf[..last_newline].split(|b| *b == b'\n') {
            self.record(line);
        }
        self.offset += (last_newline + 1) as u64;
    }

    fn record(&mut self, line: &[u8]) {
        #[derive(Deserialize)]
        struct Rec {
            #[serde(default)]
            outcome: String,
            #[serde(default)]
            page_url: String,
        }
        let Ok(rec) = serde_json::from_slice::<Rec>(line) else {
            return;
        };
        self.seen += 1;
        if rec.outcome != "skipped" {
            self.exercised += 1;
        }
        if let Some(route) = route_key(&rec.page_url) {
            self.routes.insert(route);
        }
    }
}

/// One progress line from `progress.json` plus the interaction tally.
/// Prefers explicit counts in `progress.json` (`routes_visited`,
/// `routes_known`, `controls_exercised`, `controls_discovered`) when the
/// scanner provides them.
pub fn progress_line(
    progress: &Value,
    tally: &InteractionTally,
    seeds: &BTreeSet<String>,
) -> String {
    let num = |k: &str| progress.get(k).and_then(Value::as_u64);
    let routes_visited = num("routes_visited").unwrap_or(tally.routes.len() as u64);
    let routes_known =
        num("routes_known").unwrap_or_else(|| seeds.union(&tally.routes).count() as u64);
    let exercised = num("controls_exercised").unwrap_or(tally.exercised);
    let discovered = num("controls_discovered").unwrap_or(tally.seen);
    let mut line = format!(
        "  scanning: {routes_visited}/{} routes visited, {exercised}/{} controls exercised, {}",
        routes_known.max(routes_visited),
        discovered.max(exercised),
        clock(num("elapsed_seconds").unwrap_or(0))
    );
    if let Some(eta) = num("estimated_remaining_seconds").filter(|s| *s > 0) {
        line.push_str(&format!(" (~{} left)", clock(eta)));
    }
    if let Some(route) = progress
        .get("current_url")
        .and_then(Value::as_str)
        .and_then(route_key)
    {
        line.push_str(&format!(" at {route}"));
    }
    line
}

/// `95` -> `1m35s`; `7380` -> `2h03m`.
pub fn clock(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// A seeded route the crawler attempted but could not map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedGap {
    pub route: String,
    /// Scanner reason, e.g. `seed_route_redirected_to_login`.
    pub reason: String,
}

/// A page the crawler could not load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavFailure {
    pub route: String,
    pub error: String,
}

/// What a finished scan says about routes it could not map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanFacts {
    pub seed_gaps: Vec<SeedGap>,
    pub nav_failures: Vec<NavFailure>,
    /// Stop conditions such as `max_duration_reached`.
    pub stop_reasons: Vec<String>,
}

impl ScanFacts {
    pub fn read(scan_dir: &Path) -> Self {
        let mut facts = ScanFacts::default();
        facts.read_gaps(&scan_dir.join("coverage-gaps.json"));
        for file in ["bugs.json", "checkpoint.json"] {
            facts.read_nav_failures(&scan_dir.join(file));
        }
        facts
    }

    fn read_gaps(&mut self, path: &Path) {
        #[derive(Deserialize)]
        struct Gaps {
            #[serde(default)]
            items: Vec<Gap>,
        }
        #[derive(Deserialize)]
        struct Gap {
            #[serde(default)]
            kind: String,
            #[serde(default)]
            target: String,
            #[serde(default)]
            reason: String,
            #[serde(default)]
            context: Option<String>,
        }
        let Some(gaps) = read_json::<Gaps>(path) else {
            return;
        };
        let mut seen = BTreeSet::new();
        for gap in gaps.items {
            match gap.kind.as_str() {
                "seeded_route" => {
                    let route = gap
                        .context
                        .as_deref()
                        .and_then(|c| {
                            c.split_whitespace()
                                .find_map(|w| w.strip_prefix("route_template="))
                        })
                        .map(normalize_route)
                        .or_else(|| route_key(&gap.target))
                        .unwrap_or_else(|| gap.target.clone());
                    if seen.insert((route.clone(), gap.reason.clone())) {
                        self.seed_gaps.push(SeedGap {
                            route,
                            reason: gap.reason,
                        });
                    }
                }
                "stop_condition" if !self.stop_reasons.contains(&gap.reason) => {
                    self.stop_reasons.push(gap.reason);
                }
                _ => {}
            }
        }
    }

    fn read_nav_failures(&mut self, path: &Path) {
        #[derive(Deserialize)]
        struct Bugs {
            #[serde(default, alias = "items")]
            bugs: Vec<Bug>,
        }
        #[derive(Deserialize)]
        struct Bug {
            #[serde(default)]
            title: String,
            #[serde(default)]
            description: String,
            #[serde(default)]
            location: Option<Loc>,
        }
        #[derive(Deserialize)]
        struct Loc {
            #[serde(default)]
            url: Option<String>,
        }
        let Some(bugs) = read_json::<Bugs>(path) else {
            return;
        };
        for bug in bugs.bugs {
            let Some(rest) = bug.description.strip_prefix("Failed to navigate to ") else {
                if bug.title != "Navigation failed" {
                    continue;
                }
                let Some(route) = bug.location.and_then(|l| l.url).and_then(|u| route_key(&u))
                else {
                    continue;
                };
                self.push_nav(route, bug.description);
                continue;
            };
            // "<url>: <error>"; the URL itself contains ':' so split after "://".
            let (url, error) = match rest
                .find("://")
                .and_then(|i| rest[i + 3..].find(": ").map(|j| i + 3 + j))
            {
                Some(split) => (&rest[..split], rest[split + 2..].to_string()),
                None => (rest, String::new()),
            };
            let route = bug
                .location
                .and_then(|l| l.url)
                .and_then(|u| route_key(&u))
                .or_else(|| route_key(url));
            if let Some(route) = route {
                self.push_nav(route, error);
            }
        }
    }

    fn push_nav(&mut self, route: String, error: String) {
        if !self.nav_failures.iter().any(|n| n.route == route) {
            self.nav_failures.push(NavFailure { route, error });
        }
    }

    /// Warning lines: navigation failures, seeded routes the crawler could
    /// not map, and stop conditions.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.nav_failures.is_empty() {
            let list: Vec<String> = self
                .nav_failures
                .iter()
                .map(|n| {
                    if n.error.is_empty() {
                        n.route.clone()
                    } else {
                        format!("{} ({})", n.route, n.error)
                    }
                })
                .collect();
            out.push(format!(
                "navigation failed for {} route(s); their controls are not in the map: {}",
                self.nav_failures.len(),
                list.join(", ")
            ));
        }
        // "Attempted without a view" is the generic outcome; skip routes a
        // more specific reason (navigation failure, redirect) already explains.
        let explained: BTreeSet<&str> = self
            .nav_failures
            .iter()
            .map(|n| n.route.as_str())
            .chain(
                self.seed_gaps
                    .iter()
                    .filter(|g| g.reason != GAP_NO_VIEW)
                    .map(|g| g.route.as_str()),
            )
            .collect();
        let mut by_reason: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for g in self
            .seed_gaps
            .iter()
            .filter(|g| !(g.reason == GAP_NO_VIEW && explained.contains(g.route.as_str())))
        {
            by_reason
                .entry(g.reason.as_str())
                .or_default()
                .push(g.route.as_str());
        }
        for (reason, routes) in by_reason {
            let hint = match reason {
                "seed_route_redirected_to_login" => {
                    "; add a role ([[roles]] in .brokenapp/config.toml) to map pages behind login"
                }
                _ => "",
            };
            out.push(format!(
                "skipped seeds: {} seeded route(s) {}{hint}: {}",
                routes.len(),
                gap_reason_label(reason),
                preview(&routes, 8)
            ));
        }
        for reason in &self.stop_reasons {
            let hint = match reason.as_str() {
                "max_duration_reached" => {
                    " (raise [scan] max_minutes or map with --route for the rest)"
                }
                "rate_limited" => {
                    " (target returned repeated HTTP 429 responses; lower [scan] tabs / max_requests_per_second or raise interaction_delay_ms)"
                }
                "antibot_challenge" => {
                    " (target presented WAF / anti-bot challenge pages; verify authorized access or skip automated crawling on this host)"
                }
                _ => "",
            };
            out.push(format!("scan stopped early: {reason}{hint}"));
        }
        out
    }
}

/// Scanner gap reason for a seeded route that produced no view.
const GAP_NO_VIEW: &str = "seed_route_attempted_without_view";

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let file = std::fs::File::open(path).ok()?;
    serde_json::from_reader(std::io::BufReader::new(file)).ok()
}

/// Human wording of a scanner gap reason for seeded routes.
fn gap_reason_label(reason: &str) -> String {
    match reason {
        "seed_route_redirected_to_login" => "redirect to login".to_string(),
        "seed_route_redirected" => "redirect elsewhere".to_string(),
        GAP_NO_VIEW => "were attempted but produced no view".to_string(),
        other => other.replace('_', " "),
    }
}

/// `a, b, c (+4 more)`.
pub fn preview<S: AsRef<str>>(items: &[S], max: usize) -> String {
    let shown: Vec<&str> = items.iter().take(max).map(AsRef::as_ref).collect();
    let mut out = shown.join(", ");
    if items.len() > max {
        out.push_str(&format!(" (+{} more)", items.len() - max));
    }
    out
}

/// Reason keys for unvisited routes, most specific first.
pub const UNVISITED_NAV_FAILED: &str = "navigation_failed";
pub const UNVISITED_WARMUP_FAILED: &str = "warmup_failed";
pub const UNVISITED_LOGIN: &str = "redirected_to_login";
pub const UNVISITED_REDIRECTED: &str = "redirected";
pub const UNVISITED_NO_VIEW: &str = "no_view_recorded";
pub const UNVISITED_DYNAMIC: &str = "dynamic_route";
pub const UNVISITED_NOT_REACHED: &str = "not_reached";

/// Human label for an unvisited-route reason key.
pub fn unvisited_reason_label(reason: &str) -> String {
    match reason {
        UNVISITED_NAV_FAILED => "navigation failed".to_string(),
        UNVISITED_WARMUP_FAILED => "failed the warm-up GET".to_string(),
        UNVISITED_LOGIN => "redirect to login (add a role to map them)".to_string(),
        UNVISITED_REDIRECTED => "redirect elsewhere".to_string(),
        UNVISITED_NO_VIEW => "attempted, no view recorded".to_string(),
        UNVISITED_DYNAMIC => "dynamic, no example URL or link".to_string(),
        UNVISITED_NOT_REACHED => "not reached (budget, or no seed or link)".to_string(),
        other => other.replace('_', " "),
    }
}

/// Unvisited-route reasons the inventory itself provides, if any. Read
/// defensively from the serialized inventory: a coverage map keyed by reason
/// (or by route), or a reason field on unvisited route entries.
pub fn inventory_unvisited_reasons(inventory: &Value) -> Option<BTreeMap<String, Vec<String>>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let coverage = inventory.get("coverage");
    for key in [
        "unvisited_by_reason",
        "unvisited_route_reasons",
        "unvisited_reasons",
        "routes_unvisited_by_reason",
    ] {
        let Some(map) = coverage.and_then(|c| c.get(key)).and_then(Value::as_object) else {
            continue;
        };
        for (k, v) in map {
            match v {
                Value::Array(routes) => {
                    let list = out.entry(k.clone()).or_default();
                    list.extend(routes.iter().filter_map(Value::as_str).map(str::to_string));
                }
                Value::String(reason) => out.entry(reason.clone()).or_default().push(k.clone()),
                _ => {}
            }
        }
    }
    if out.is_empty() {
        for route in inventory
            .get("routes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if route.get("visited").and_then(Value::as_bool) != Some(false) {
                continue;
            }
            let Some(name) = route.get("route").and_then(Value::as_str) else {
                continue;
            };
            let reason = [
                "unvisited_reason",
                "reason",
                "gap_reason",
                "not_visited_reason",
            ]
            .iter()
            .find_map(|k| route.get(*k).and_then(Value::as_str));
            if let Some(reason) = reason {
                out.entry(reason.to_string())
                    .or_default()
                    .push(name.to_string());
            }
        }
    }
    out.retain(|_, routes| !routes.is_empty());
    (!out.is_empty()).then_some(out)
}

/// Group unvisited routes by why they were not visited, from what the run
/// observed: navigation failures, warm-up failures, scanner seed gaps,
/// dynamic templates without an example, and everything else as
/// `not_reached`.
pub fn group_unvisited(
    unvisited: &[String],
    facts: &ScanFacts,
    warmup_failed: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for route in unvisited {
        let key = normalize_route(route);
        let gap_reason = |reason: &str| {
            facts
                .seed_gaps
                .iter()
                .any(|g| g.reason == reason && normalize_route(&g.route) == key)
        };
        let reason = if facts
            .nav_failures
            .iter()
            .any(|n| normalize_route(&n.route) == key)
        {
            UNVISITED_NAV_FAILED
        } else if warmup_failed.contains_key(&key) {
            UNVISITED_WARMUP_FAILED
        } else if gap_reason("seed_route_redirected_to_login") {
            UNVISITED_LOGIN
        } else if gap_reason("seed_route_redirected") {
            UNVISITED_REDIRECTED
        } else if gap_reason(GAP_NO_VIEW) {
            UNVISITED_NO_VIEW
        } else if route.contains(':') || route.contains('*') {
            UNVISITED_DYNAMIC
        } else {
            UNVISITED_NOT_REACHED
        };
        out.entry(reason.to_string())
            .or_default()
            .push(route.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_keys_keep_hash_routes_and_drop_queries() {
        assert_eq!(route_key("http://h:1/").as_deref(), Some("/"));
        assert_eq!(
            route_key("http://h:1/about/?x=1").as_deref(),
            Some("/about")
        );
        assert_eq!(
            route_key("http://h:1/#/basket/").as_deref(),
            Some("/#/basket")
        );
        assert_eq!(route_key("http://h:1/#/").as_deref(), Some("/#/"));
        assert_eq!(
            route_key("http://h:1/page#section").as_deref(),
            Some("/page")
        );
        assert_eq!(normalize_route("/about/"), "/about");
        assert_eq!(normalize_route("/#/basket?x=1"), "/#/basket");
        assert_eq!(normalize_route("http://h:1/x/"), "/x");
        assert_eq!(normalize_route("/"), "/");
    }

    #[test]
    fn tally_reads_whole_lines_incrementally() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interactions.jsonl");
        let a = r#"{"page_url":"http://h:1/","outcome":"dom_change"}"#;
        let b = r#"{"page_url":"http://h:1/about","outcome":"skipped"}"#;
        let c = r#"{"page_url":"http://h:1/about","outcome":"no_effect"}"#;
        std::fs::write(&path, format!("{a}\n{b}\n{{\"page_url\":\"http://h:1/pa")).unwrap();
        let mut tally = InteractionTally::default();
        tally.update(&path);
        assert_eq!((tally.seen, tally.exercised), (2, 1));
        // Finish the partial line, then append another.
        let raw = std::fs::read_to_string(&path).unwrap();
        let fixed = raw.replace("{\"page_url\":\"http://h:1/pa", &format!("{c}\n"));
        std::fs::write(&path, fixed).unwrap();
        tally.update(&path);
        assert_eq!((tally.seen, tally.exercised), (3, 2));
        assert_eq!(
            tally.routes.iter().cloned().collect::<Vec<_>>(),
            vec!["/", "/about"]
        );
        tally.update(&path);
        assert_eq!(tally.seen, 3, "no double counting");

        let seeds: BTreeSet<String> = ["/", "/about", "/contact"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let progress = serde_json::json!({
            "views_found": 4, "endpoints_found": 328, "elapsed_seconds": 95,
            "estimated_remaining_seconds": 30, "current_url": "http://h:1/about?x=1"
        });
        let line = progress_line(&progress, &tally, &seeds);
        assert_eq!(
            line,
            "  scanning: 2/3 routes visited, 2/3 controls exercised, 1m35s (~30s left) at /about"
        );
        assert!(!line.contains("328"), "no raw endpoint counts");
        let explicit = serde_json::json!({
            "routes_visited": 5, "routes_known": 9, "controls_exercised": 40,
            "controls_discovered": 100, "elapsed_seconds": 5
        });
        assert_eq!(
            progress_line(&explicit, &tally, &seeds),
            "  scanning: 5/9 routes visited, 40/100 controls exercised, 5s"
        );
    }

    #[test]
    fn facts_from_gaps_and_navigation_failures() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("coverage-gaps.json"),
            r#"{"summary":{},"items":[
              {"kind":"interaction","target":"a.x","reason":"navigation_via_href"},
              {"kind":"seeded_route","target":"http://h:1/account","reason":"seed_route_attempted_without_view","context":"source=seed_routes_file:/x route_template=/account"},
              {"kind":"seeded_route","target":"http://h:1/account","reason":"seed_route_redirected_to_login","context":"source=seed_routes_file:/x route_template=/account final_url=http://h:1/sign-in"},
              {"kind":"seeded_route","target":"http://h:1/admin/","reason":"seed_route_redirected_to_login"},
              {"kind":"stop_condition","target":"scan_loop","reason":"max_duration_reached"}
            ]}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("checkpoint.json"),
            r#"{"version":2,"bugs":[
              {"title":"Missing CSP","description":"x"},
              {"title":"Navigation failed","description":"Failed to navigate to http://h:1/: Page.navigate timed out after 20000ms","location":{"url":"http://h:1/"}}
            ]}"#,
        )
        .unwrap();
        let facts = ScanFacts::read(dir.path());
        assert_eq!(facts.nav_failures.len(), 1);
        assert_eq!(facts.nav_failures[0].route, "/");
        assert_eq!(
            facts.nav_failures[0].error,
            "Page.navigate timed out after 20000ms"
        );
        assert_eq!(facts.stop_reasons, vec!["max_duration_reached"]);
        assert_eq!(facts.seed_gaps.len(), 3);
        let warnings = facts.warnings();
        assert!(
            warnings[0].starts_with("navigation failed for 1 route(s)"),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w
                .contains("2 seeded route(s) redirect to login; add a role ([[roles]]")
                && w.contains("/account, /admin")),
            "{warnings:?}"
        );
        assert!(warnings.iter().any(|w| w.contains("max_duration_reached")));
        assert!(
            !warnings.iter().any(|w| w.contains("no view")),
            "/account is already explained by its login redirect: {warnings:?}"
        );

        let mut warm = BTreeMap::new();
        warm.insert("/broken".to_string(), "HTTP 500".to_string());
        let grouped = group_unvisited(
            &[
                "/".into(),
                "/account".into(),
                "/admin".into(),
                "/broken".into(),
                "/blog/:slug".into(),
                "/orphan".into(),
            ],
            &facts,
            &warm,
        );
        assert_eq!(grouped[UNVISITED_NAV_FAILED], vec!["/"]);
        assert_eq!(grouped[UNVISITED_LOGIN], vec!["/account", "/admin"]);
        assert_eq!(grouped[UNVISITED_WARMUP_FAILED], vec!["/broken"]);
        assert_eq!(grouped[UNVISITED_DYNAMIC], vec!["/blog/:slug"]);
        assert_eq!(grouped[UNVISITED_NOT_REACHED], vec!["/orphan"]);
    }

    #[test]
    fn missing_artifacts_yield_no_facts() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(ScanFacts::read(dir.path()), ScanFacts::default());
        let mut tally = InteractionTally::default();
        tally.update(&dir.path().join("interactions.jsonl"));
        assert_eq!(tally.seen, 0);
    }

    #[test]
    fn inventory_reasons_are_read_defensively() {
        let none = serde_json::json!({"coverage": {"routes_known": 3}, "routes": [{"route": "/x", "visited": false}]});
        assert_eq!(inventory_unvisited_reasons(&none), None);
        let by_reason =
            serde_json::json!({"coverage": {"unvisited_by_reason": {"needs_login": ["/a", "/b"]}}});
        assert_eq!(
            inventory_unvisited_reasons(&by_reason).unwrap()["needs_login"],
            vec!["/a", "/b"]
        );
        let by_route =
            serde_json::json!({"coverage": {"unvisited_reasons": {"/a": "needs_login"}}});
        assert_eq!(
            inventory_unvisited_reasons(&by_route).unwrap()["needs_login"],
            vec!["/a"]
        );
        let on_routes = serde_json::json!({"routes": [
            {"route": "/a", "visited": false, "unvisited_reason": "navigation_failed"},
            {"route": "/b", "visited": true, "unvisited_reason": "ignored"}
        ]});
        let r = inventory_unvisited_reasons(&on_routes).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r["navigation_failed"], vec!["/a"]);
    }
}
