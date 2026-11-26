//! Merge semantics of incremental maps (`brokenapp map --changed`): a
//! re-crawl of a few routes merged into the previous whole-app map must
//! leave untouched routes byte-identical, replace re-crawled routes, and
//! produce the same change lines a full re-map would.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::build::{ProbeResult, ProbeTable, build_with};
use super::tests::{BASE, button, el, link, opts, rec, row, spec, view, write_scan};
use super::*;
use crate::code_link::runtime_source::FileLine;
use crate::output::interactions::{InteractionOutcome, InteractionRecord};
use crate::route_discovery::DiscoveredRoute;

const ROUTES: &[&str] = &["/", "/about", "/pricing", "/terms"];

/// Element whose ancestor path puts it in a page region.
fn at(path: &str, label: &str, kind: Value) -> Value {
    el(path, label, kind, &[("structural", path)])
}

fn discovered() -> Vec<DiscoveredRoute> {
    ROUTES
        .iter()
        .map(|r| DiscoveredRoute {
            path: r.to_string(),
            kind: "page".into(),
            file: format!("src/pages{}.astro", if *r == "/" { "/index" } else { r }),
            ..Default::default()
        })
        .collect()
}

/// What one version of the site looks like.
#[derive(Clone)]
struct Site {
    /// Header "Contact" href per route.
    contact: BTreeMap<&'static str, &'static str>,
    /// Footer "Terms" href per route.
    terms: BTreeMap<&'static str, &'static str>,
    /// /about's booking button: label and the endpoint it posts to.
    book: (&'static str, &'static str),
}

impl Site {
    fn base() -> Self {
        Self {
            contact: ROUTES.iter().map(|r| (*r, "/about")).collect(),
            terms: ROUTES.iter().map(|r| (*r, "/terms")).collect(),
            book: ("Book a call", "/api/book"),
        }
    }

    fn view_id(route: &str) -> String {
        let i = ROUTES.iter().position(|r| *r == route).unwrap_or(0) + 1;
        format!("view_{i:04}")
    }

    fn view(&self, route: &'static str) -> Value {
        let mut els = vec![
            at("body > header > nav > a:nth-of-type(1)", "Home", link("/")),
            at(
                "body > header > nav > a:nth-of-type(2)",
                "Contact",
                link(self.contact[route]),
            ),
            at(
                "body > footer > nav > a:nth-of-type(1)",
                "Terms",
                link(self.terms[route]),
            ),
        ];
        match route {
            "/" => els.push(at(
                "body > main > section > a",
                "See pricing",
                link("/pricing"),
            )),
            "/about" => els.push(el("#book", self.book.0, button(), &[("id", "book")])),
            "/pricing" => els.push(at("body > main > p > a", "Read the terms", link("/terms"))),
            _ => {}
        }
        view(&Self::view_id(route), route, els)
    }

    fn records(&self, routes: &[&'static str]) -> Vec<InteractionRecord> {
        routes
            .iter()
            .filter(|r| **r == "/about")
            .map(|_| {
                rec(
                    &Self::view_id("/about"),
                    "/about",
                    "#book",
                    "button",
                    InteractionOutcome::NoEffect,
                )
            })
            .collect()
    }

    fn rows(&self, routes: &[&'static str]) -> Vec<Value> {
        let mut rows = Vec::new();
        for r in routes {
            let view = Self::view_id(r);
            rows.push(row(
                "GET",
                "/api/session",
                Some(200),
                Some((&view, "__page_load__")),
                None,
            ));
            if *r == "/about" {
                let mut blocked = row(
                    "POST",
                    self.book.1,
                    None,
                    Some((&view, "#book")),
                    Some(&format!("act-{view}-#book")),
                );
                blocked["write_guard"] = json!("blocked");
                blocked["failure"] = json!("net::ERR_BLOCKED_BY_CLIENT");
                rows.push(blocked);
            }
        }
        rows
    }

    /// Inventory of a crawl of `routes` (a full map, or a scoped re-crawl).
    async fn crawl(&self, routes: &[&'static str], recrawl: bool) -> Inventory {
        self.crawl_probed(routes, recrawl, probe_ok()).await
    }

    async fn crawl_probed(
        &self,
        routes: &[&'static str],
        recrawl: bool,
        probe: ProbeTable,
    ) -> Inventory {
        let dir = tempfile::tempdir().unwrap();
        let views: Vec<Value> = routes.iter().map(|r| self.view(r)).collect();
        write_scan(
            dir.path(),
            &spec(views),
            Some(&self.records(routes)),
            &self.rows(routes),
        );
        let mut o = opts();
        o.discovered_routes = discovered();
        o.keep_route_scope = recrawl;
        o.concrete_routes = recrawl.then(|| ROUTES.iter().map(|r| r.to_string()).collect());
        let mut inv = build_with(dir.path(), &o, Some(probe)).await.unwrap();
        inv.generated_at = if recrawl {
            "2026-10-22T11:00:00Z".into()
        } else {
            "2026-10-22T10:00:00Z".into()
        };
        inv
    }
}

/// Every page answers 200 to the link probe.
fn probe_ok() -> ProbeTable {
    let mut results = BTreeMap::new();
    for r in ROUTES.iter().chain(&["/legal"]) {
        results.insert(
            format!("{BASE}{r}"),
            ProbeResult {
                status: 200,
                landed: None,
            },
        );
    }
    ProbeTable {
        results,
        soft_404: Some(false),
    }
}

fn opts_for(requested: &[&str], changed: &[&str]) -> MergeOptions {
    let files: BTreeSet<String> = changed.iter().map(|f| f.to_string()).collect();
    MergeOptions {
        requested: requested.iter().map(|r| r.to_string()).collect(),
        removed: BTreeSet::new(),
        trigger_files: files.clone(),
        changed_files: files,
        started_at: "2026-10-22T10:59:00Z".into(),
    }
}

fn json_of<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

fn lines(cs: &ChangeSet) -> Vec<String> {
    cs.changes.iter().map(|c| c.line.clone()).collect()
}

fn set_source(inv: &mut Inventory, key_suffix: &str, file: &str) {
    for c in inv
        .controls
        .iter_mut()
        .filter(|c| c.key.ends_with(key_suffix))
    {
        c.source = Some(ResolvedSource {
            render: Some(FileLine {
                file: file.into(),
                line: 7,
                col: 3,
            }),
            method: "annotation".into(),
            confidence: "exact".into(),
            ..Default::default()
        });
    }
}

#[tokio::test]
async fn untouched_routes_stay_byte_identical_and_changes_match_a_full_remap() {
    let base_site = Site::base();
    let mut base = base_site.crawl(ROUTES, false).await;
    base.started_at = Some("2026-10-22T09:59:00Z".into());
    // Shell controls are global in the whole-app map.
    assert!(
        base.controls
            .iter()
            .any(|c| c.key == "*|link|text=home@header")
    );

    // Edit /about's booking button: new label, new endpoint.
    let mut edited = base_site.clone();
    edited.book = ("Schedule a call", "/api/schedule");
    let recrawl = edited.crawl(&["/about"], true).await;
    assert!(
        recrawl.controls.iter().all(|c| c.route != "*"),
        "a re-crawl keeps shell controls on their routes"
    );
    let opts = opts_for(&["/about"], &["src/pages/about.astro"]);
    let merged = merge_incremental(&base, &recrawl, &opts);
    assert_eq!(merged.recrawled, vec!["/about"]);
    assert!(merged.kept.is_empty());
    let m = &merged.inventory;

    // Untouched routes: controls, route entries, endpoint rows unchanged.
    for route in ["/", "/pricing", "/terms"] {
        let pick = |inv: &Inventory| {
            json_of(
                &inv.controls
                    .iter()
                    .filter(|c| c.route == route)
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(pick(&base), pick(m), "controls on {route}");
        let entry = |inv: &Inventory| json_of(&inv.routes.iter().find(|r| r.route == route));
        assert_eq!(entry(&base), entry(m), "route entry {route}");
    }
    let globals = |inv: &Inventory| {
        json_of(
            &inv.controls
                .iter()
                .filter(|c| c.route == "*")
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(globals(&base), globals(m), "globals unchanged");
    let endpoint =
        |inv: &Inventory, e: &str| json_of(&inv.endpoints.iter().find(|x| x.endpoint == e));
    assert_eq!(
        endpoint(&base, "GET /api/session"),
        endpoint(m, "GET /api/session")
    );

    // The re-crawled route is replaced.
    let book = m
        .controls
        .iter()
        .find(|c| c.key == "/about|button|id=book")
        .unwrap();
    assert_eq!(book.label, "Schedule a call");
    assert!(
        m.endpoints
            .iter()
            .any(|e| e.endpoint == "POST /api/schedule"
                && e.controls == vec!["/about|button|id=book".to_string()])
    );
    assert!(!m.endpoints.iter().any(|e| e.endpoint == "POST /api/book"));
    assert!(
        !m.controls
            .iter()
            .any(|c| c.route == "/about" && c.region == "header"),
        "the re-crawl's shell copies were folded into the globals"
    );

    // Provenance.
    assert_eq!(m.started_at.as_deref(), Some("2026-10-22T10:59:00Z"));
    assert_eq!(m.route_scans["/about"].scanned_at, "2026-10-22T10:59:00Z");
    assert_eq!(m.route_scans["/about"].scan_dir, recrawl.scan_dir);
    assert_eq!(m.route_scans["/"].scanned_at, "2026-10-22T09:59:00Z");
    assert_eq!(m.route_scans["/"].scan_dir, base.scan_dir);
    let inc = m.incremental.as_ref().unwrap();
    assert_eq!(inc.routes, vec!["/about"]);
    assert_eq!(inc.base, base.generated_at);
    assert_eq!(inc.changed_files, vec!["src/pages/about.astro"]);

    // Same coverage and change lines as a full re-map of the edited site,
    // and every line is about the re-crawled route.
    let full = edited.crawl(ROUTES, false).await;
    assert_eq!(json_of(&m.coverage), json_of(&full.coverage));
    let from_merge = diff(Some(&base), m);
    let from_full = diff(Some(&base), &full);
    assert!(!from_merge.changes.is_empty());
    assert_eq!(
        lines(&from_merge),
        lines(&from_full),
        "{:#?}",
        lines(&from_merge)
    );
    for c in &from_merge.changes {
        assert!(
            c.route == "/about" || c.kind.starts_with("endpoint_"),
            "change outside the re-crawled route: {c:?}"
        );
    }
    assert!(!from_merge.changes.iter().any(|c| c.kind == "removed"));

    // Changelog heading and UI-MAP.md say what was re-crawled and why.
    let entry = render::render_changelog_entry(&from_merge, m);
    assert!(
        entry
            .lines()
            .next()
            .is_some_and(|h| h
                .ends_with("· incremental: re-crawled 1 route (changed: src/pages/about.astro)")),
        "{entry}"
    );
    assert!(entry.contains("Re-crawled: /about. Every other route is kept"));
    assert!(render::render_ui_map(m).contains(
        "- Incremental: re-crawled /about (changed: src/pages/about.astro); other routes are kept"
    ));
    assert!(!render::render_ui_map(&full).contains("Incremental"));

    // Merging is deterministic.
    let again = merge_incremental(&base, &recrawl, &opts);
    assert_eq!(json_of(&again.inventory), json_of(m));
}

#[tokio::test]
async fn a_changed_shell_file_refreshes_its_global_controls_on_every_route() {
    let base_site = Site::base();
    let mut base = base_site.crawl(ROUTES, false).await;
    set_source(
        &mut base,
        "|link|text=contact@header",
        "src/components/Header.astro",
    );

    // Header.astro now points "Contact" at /legal; one representative route
    // is re-crawled.
    let mut edited = base_site.clone();
    for r in ROUTES {
        edited.contact.insert(r, "/legal");
    }
    let mut recrawl = edited.crawl(&["/pricing"], true).await;
    set_source(
        &mut recrawl,
        "|link|text=contact@header",
        "src/components/Header.astro",
    );
    let merged = merge_incremental(
        &base,
        &recrawl,
        &opts_for(&["/pricing"], &["src/components/Header.astro"]),
    );
    let m = &merged.inventory;
    let contact = m
        .controls
        .iter()
        .find(|c| c.key == "*|link|text=contact@header")
        .unwrap();
    assert_eq!(contact.target.as_deref(), Some("/legal"));
    assert_eq!(contact.routes.len(), ROUTES.len(), "still on every route");
    assert_eq!(merged.refreshed_globals, vec!["*|link|text=contact@header"]);

    let mut full = edited.crawl(ROUTES, false).await;
    set_source(
        &mut full,
        "|link|text=contact@header",
        "src/components/Header.astro",
    );
    let from_merge = lines(&diff(Some(&base), m));
    assert_eq!(from_merge, lines(&diff(Some(&base), &full)));
    assert!(
        from_merge
            .iter()
            .any(|l| l.starts_with("REWIRED * link \"Contact\"")),
        "{from_merge:#?}"
    );
}

#[tokio::test]
async fn a_global_that_now_differs_only_on_the_recrawled_route_splits_off() {
    let base_site = Site::base();
    let base = base_site.crawl(ROUTES, false).await;

    // Only /about's page changed its footer link, not the shell's file.
    let mut edited = base_site.clone();
    edited.terms.insert("/about", "/legal");
    let recrawl = edited.crawl(&["/about"], true).await;
    let merged = merge_incremental(
        &base,
        &recrawl,
        &opts_for(&["/about"], &["src/pages/about.astro"]),
    );
    let m = &merged.inventory;
    let global = m
        .controls
        .iter()
        .find(|c| c.key == "*|link|text=terms@footer")
        .unwrap();
    assert!(!global.routes.contains(&"/about".to_string()));
    assert_eq!(
        global.target.as_deref(),
        Some("/terms"),
        "other routes unchanged"
    );
    let local = m
        .controls
        .iter()
        .find(|c| c.key == "/about|link|text=terms@footer")
        .unwrap();
    assert_eq!(local.target.as_deref(), Some("/legal"));

    let full = edited.crawl(ROUTES, false).await;
    let from_merge = lines(&diff(Some(&base), m));
    assert_eq!(from_merge, lines(&diff(Some(&base), &full)));
    assert!(
        from_merge
            .iter()
            .any(|l| l.contains("/about link \"Terms\"")),
        "{from_merge:#?}"
    );
}

#[tokio::test]
async fn a_fresh_probe_fixes_a_global_link_whose_target_now_exists() {
    let mut site = Site::base();
    for r in ROUTES {
        site.terms.insert(r, "/legal");
    }
    let mut missing = probe_ok();
    missing.results.insert(
        format!("{BASE}/legal"),
        ProbeResult {
            status: 404,
            landed: None,
        },
    );
    let base = site.crawl_probed(ROUTES, false, missing).await;
    let terms = |inv: &Inventory| {
        inv.controls
            .iter()
            .find(|c| c.key == "*|link|text=terms@footer")
            .map(|c| c.status)
    };
    assert_eq!(terms(&base), Some(ControlStatus::Broken));

    // The /legal page now exists; one route showing the link is re-crawled.
    let recrawl = site.crawl(&["/"], true).await;
    let merged = merge_incremental(
        &base,
        &recrawl,
        &opts_for(&["/"], &["src/pages/legal.astro"]),
    );
    assert_eq!(terms(&merged.inventory), Some(ControlStatus::Ok));
    let full = site.crawl(ROUTES, false).await;
    let from_merge = lines(&diff(Some(&base), &merged.inventory));
    assert_eq!(from_merge, lines(&diff(Some(&base), &full)));
    assert!(
        from_merge
            .iter()
            .any(|l| l.starts_with("FIXED * link \"Terms\"")),
        "{from_merge:#?}"
    );
}

#[tokio::test]
async fn unreached_routes_are_kept_and_deleted_routes_dropped() {
    let base_site = Site::base();
    let base = base_site.crawl(ROUTES, false).await;
    // /about was requested but the re-crawl only reached /pricing; /terms'
    // page file was deleted.
    let recrawl = base_site.crawl(&["/pricing"], true).await;
    let mut o = opts_for(&["/about", "/pricing"], &["src/pages/terms.astro"]);
    o.removed.insert("/terms".into());
    let merged = merge_incremental(&base, &recrawl, &o);
    assert_eq!(merged.recrawled, vec!["/pricing"]);
    assert_eq!(merged.kept, vec!["/about"]);
    let m = &merged.inventory;
    let on = |inv: &Inventory, r: &str| {
        json_of(
            &inv.controls
                .iter()
                .filter(|c| c.route == r)
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(on(&base, "/about"), on(m, "/about"), "kept as it was");
    assert!(!m.routes.iter().any(|r| r.route == "/terms"));
    assert!(!m.controls.iter().any(|c| c.route == "/terms"));
    for g in m.controls.iter().filter(|c| c.route == "*") {
        assert!(!g.routes.contains(&"/terms".to_string()), "{g:?}");
    }
    let inc = m.incremental.as_ref().unwrap();
    assert_eq!(inc.removed, vec!["/terms"]);
    assert_eq!(inc.kept, vec!["/about"]);
    let changes = lines(&diff(Some(&base), m));
    assert!(
        changes.contains(&"ROUTE REMOVED /terms".to_string()),
        "{changes:#?}"
    );
}

#[test]
fn run_start_falls_back_to_the_run_directory_then_generated_at() {
    let mut inv = Inventory {
        generated_at: "2026-10-22T10:05:00Z".into(),
        scan_dir: "/x/.brokenapp/scans/20261022T100000Z-2/scan".into(),
        ..Default::default()
    };
    assert_eq!(
        inv.run_started_at().unwrap().to_rfc3339(),
        "2026-10-22T10:00:00+00:00"
    );
    inv.started_at = Some("2026-10-22T09:59:00Z".into());
    assert_eq!(
        inv.run_started_at().unwrap().to_rfc3339(),
        "2026-10-22T09:59:00+00:00"
    );
    inv.started_at = None;
    inv.scan_dir = "/elsewhere/scan".into();
    assert_eq!(
        inv.run_started_at().unwrap().to_rfc3339(),
        "2026-10-22T10:05:00+00:00"
    );
}
