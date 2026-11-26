//! Regression tests for the field-test fixes: control identity and grouping,
//! data-folded labels, routes, status rules, link checks, coverage-aware
//! diffs, coverage reporting, and journey explanations.

use std::path::Path;

use serde_json::{Value, json};

use super::tests::{
    BASE, build, button, calls, ctl, el, find, inv_with, link, opts, rec, row, spec, text_input,
    view, write_scan,
};
use super::*;
use crate::code_link::runtime_source::FileLine;
use crate::output::interactions::{InteractionOutcome, InteractionRecord};
use crate::route_discovery::DiscoveredRoute;

/// Element whose ancestor path (structural locator) puts it in a region.
fn at(path: &str, label: &str, kind: Value) -> Value {
    el(path, label, kind, &[("structural", path)])
}

fn page(route: &str) -> DiscoveredRoute {
    DiscoveredRoute {
        path: route.into(),
        kind: "page".into(),
        file: format!("src/pages{route}.tsx"),
        ..Default::default()
    }
}

fn routes(paths: &[&str]) -> Vec<DiscoveredRoute> {
    paths.iter().map(|p| page(p)).collect()
}

async fn build_scan(
    views: Vec<Value>,
    records: &[InteractionRecord],
    rows: &[Value],
    discovered: &[&str],
) -> Inventory {
    let dir = tempfile::tempdir().unwrap();
    write_scan(dir.path(), &spec(views), Some(records), rows);
    let mut o = opts();
    o.discovered_routes = routes(discovered);
    build(dir.path(), &o).await
}

fn lines(cs: &ChangeSet) -> Vec<&str> {
    cs.changes.iter().map(|c| c.line.as_str()).collect()
}

#[tokio::test]
async fn excluded_routes_do_not_inflate_link_or_source_coverage() {
    let dir = tempfile::tempdir().unwrap();
    write_scan(
        dir.path(),
        &spec(vec![view(
            "home",
            "/",
            vec![
                at(
                    "body > main > a.private",
                    "Private",
                    link("/private/detail"),
                ),
                at("body > main > a.billing", "Billing", link("/#/billing")),
                at("body > main > a.public", "Public", link("/public")),
            ],
        )]),
        Some(&[]),
        &[],
    );
    let mut o = opts();
    o.discovered_routes = routes(&["/", "/private/detail", "/#/billing", "/public"]);
    o.exclude_routes = vec!["/private".into(), "/#/billing".into()];
    let inv = build(dir.path(), &o).await;
    assert_eq!(
        inv.routes
            .iter()
            .map(|r| r.route.as_str())
            .collect::<Vec<_>>(),
        ["/", "/public"]
    );
    assert_eq!(inv.coverage.routes_known, 2);
    assert_eq!(inv.coverage.unvisited_routes, ["/public"]);
    for label in ["Private", "Billing"] {
        let c = inv.controls.iter().find(|c| c.label == label).unwrap();
        assert_eq!(c.status, ControlStatus::Skipped, "{c:?}");
        assert_eq!(c.reason.as_deref(), Some("route_excluded"));
    }
}

/// Shell + content of a small marketing site.
fn site_view(id: &str, route: &str, terms_href: &str, extra: Vec<Value>) -> Value {
    let mut els = vec![
        at("body > header > nav > a:nth-of-type(1)", "Home", link("/")),
        at(
            "body > header > nav > a:nth-of-type(2)",
            "Contact",
            link("/contact"),
        ),
        at(
            "body > footer > nav > a:nth-of-type(1)",
            "Terms",
            link(terms_href),
        ),
        at("body > header > a.skip", "Skip to content", link("#main")),
    ];
    els.extend(extra);
    view(id, route, els)
}

// ---------------------------------------------------------------------------
// 1. Identity and grouping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn link_identity_is_label_and_region_and_a_new_href_is_a_rewire() {
    let hero = |href: &str| {
        at(
            "body > main > section > a:nth-of-type(1)",
            "Contact",
            link(href),
        )
    };
    let site = |terms_home: &str, hero_href: &str| {
        vec![
            site_view("view_0001", "/", terms_home, vec![hero(hero_href)]),
            site_view("view_0002", "/about", "/terms", vec![]),
            site_view("view_0003", "/pricing", "/terms", vec![]),
            site_view("view_0004", "/terms", "/terms", vec![]),
        ]
    };
    let known = &["/", "/about", "/pricing", "/terms", "/contact"];
    let base = build_scan(site("/terms", "/contact"), &[], &[], known).await;
    // Header links repeated on every route are one shell control each.
    let nav_contact = find(&base, "*|link|text=contact@header");
    assert_eq!(nav_contact.routes.len(), 4);
    // The hero "Contact" shares the href but is main content: it stays on /.
    let hero_contact = find(&base, "/|link|text=contact");
    assert_eq!(hero_contact.region, "main");
    assert_eq!(hero_contact.target.as_deref(), Some("/contact"));
    // A same-document `#main` skip link is an anchor, not a link to the page.
    let skip = find(&base, "*|link|text=skip to content@header");
    assert_eq!(
        skip.outcomes,
        vec![Outcome::Anchor {
            fragment: "main".into()
        }]
    );
    find(&base, "*|link|text=terms@footer");

    // Mutant: the footer "Terms" on / and the hero link point elsewhere.
    let mut cur = build_scan(site("/legal/terms", "/pricing"), &[], &[], known).await;
    cur.generated_at = "2026-10-22T00:00:00Z".into();
    // The changed footer link is now route-scoped on /, paired with the
    // shell control it left; the hero link keeps its key.
    find(&cur, "/|link|text=terms@footer");
    let cs = diff(Some(&base), &cur);
    let ls = lines(&cs);
    assert!(
        ls.contains(
            &"NOW BROKEN / link \"Terms\": link target /legal/terms is not a route in source (unknown route) (was → /terms)"
        ),
        "{ls:#?}"
    );
    assert!(
        ls.contains(&"REWIRED / link \"Contact\": → /pricing (was → /contact)"),
        "{ls:#?}"
    );
    assert!(
        !cs.changes
            .iter()
            .any(|c| c.kind == "added" || c.kind == "removed"),
        "a retarget is not added + removed: {ls:#?}"
    );
}

#[tokio::test]
async fn same_label_links_to_different_targets_are_separate_controls() {
    let v = view(
        "view_0001",
        "/",
        vec![
            at(
                "body > main > div:nth-of-type(1) > a",
                "Learn more",
                link("/a"),
            ),
            at(
                "body > main > div:nth-of-type(2) > a",
                "Learn more",
                link("/b"),
            ),
            at(
                "body > main > div:nth-of-type(3) > a",
                "Learn more",
                link("/b"),
            ),
        ],
    );
    let inv = build_scan(vec![v], &[], &[], &[]).await;
    assert_eq!(find(&inv, "/|link|text=learn more->/a").count, 1);
    let b = find(&inv, "/|link|text=learn more->/b");
    assert_eq!(b.count, 2, "truly identical controls are grouped");
    assert_eq!(b.locator, "text=learn more");
}

#[tokio::test]
async fn layout_elements_without_a_visible_landmark_are_still_shell() {
    // Footer links nested deeper than the 6-level structural path: no
    // landmark is visible, but the identical DOM path on every route marks
    // them as layout. Content with the same label on different paths is not.
    let deep = "div:nth-of-type(1) > div > div:nth-of-type(4) > ul > li:nth-of-type(3) > a";
    let mk = |id: &str, route: &str, promo_path: &str| {
        view(
            id,
            route,
            vec![
                at(deep, "Rental policies", link("/rental-policies")),
                at(promo_path, "Book", link("/book")),
            ],
        )
    };
    let inv = build_scan(
        vec![
            mk("view_0001", "/", "div > section:nth-of-type(1) > a"),
            mk("view_0002", "/a", "div > section:nth-of-type(2) > a"),
            mk("view_0003", "/b", "div > section:nth-of-type(3) > a"),
        ],
        &[],
        &[],
        &[],
    )
    .await;
    find(&inv, "*|link|text=rental policies");
    find(&inv, "/|link|text=book");
    find(&inv, "/a|link|text=book");
}

#[tokio::test]
async fn grouped_controls_keep_member_labels_for_search() {
    let v = view(
        "view_0001",
        "/",
        vec![
            el(
                "[data-testid=\"tile\"]",
                "6 Devices here",
                link("/inventory"),
                &[("test_id", "[data-testid=\"tile\"]")],
            ),
            el(
                "[data-testid=\"tile\"]:nth-of-type(2)",
                "2 Boxes coming",
                link("/inventory"),
                &[("test_id", "[data-testid=\"tile\"]")],
            ),
        ],
    );
    let inv = build_scan(vec![v], &[], &[], &[]).await;
    let tile = find(&inv, "/|link|testid=tile");
    assert_eq!(tile.labels, vec!["2 Boxes coming", "6 Devices here"]);
    let filter = query::ControlFilter {
        text: Some("boxes coming".into()),
        ..Default::default()
    };
    assert_eq!(filter.apply(&inv).len(), 1);
    let goal = journey::parse_goal("label:Boxes coming", &inv);
    assert_eq!(journey::journey(&inv, &goal, None, 6).direct.len(), 1);
}

#[test]
fn shell_source_is_the_most_common_site_not_the_first_crawled() {
    use super::build::tests_support::representative_signature;
    let a = "http://x/_next/static/chunks/a.js:10:1";
    let b = "http://x/_next/static/chunks/b.js:20:1";
    // Crawl order puts the rare site first; the common one wins.
    assert_eq!(representative_signature(&[b, a, a]).as_deref(), Some(a));
    assert_eq!(representative_signature(&[a, a, b]).as_deref(), Some(a));
    // Ties: lexicographically first, whatever the order.
    assert_eq!(representative_signature(&[b, a]).as_deref(), Some(a));
    assert_eq!(representative_signature(&[a, b]).as_deref(), Some(a));
}

// ---------------------------------------------------------------------------
// 2. Data- and time-dependent labels
// ---------------------------------------------------------------------------

#[tokio::test]
async fn calendar_day_cells_collapse_into_one_control() {
    let day = |n: u32, state: &str| {
        let aria = format!("Nov {n}, 2026, {state}");
        el(
            &format!("button[aria-label=\"{aria}\"]"),
            &n.to_string(),
            button(),
            &[("aria", &format!("button[aria-label=\"{aria}\"]"))],
        )
    };
    let v = view(
        "view_0001",
        "/book",
        vec![day(10, "open"), day(11, "booked"), day(12, "limited")],
    );
    let inv = build_scan(vec![v], &[], &[], &[]).await;
    let days: Vec<&Control> = inv.controls.iter().filter(|c| c.role == "button").collect();
    assert_eq!(days.len(), 1, "{:?}", inv.controls);
    assert_eq!(days[0].key, "/book|button|aria=#");
    assert_eq!(days[0].count, 3);
}

// ---------------------------------------------------------------------------
// 3. Routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enumerated_params_stay_distinct_and_error_pages_are_not_routes() {
    let dir = tempfile::tempdir().unwrap();
    let mut modal = view(
        "view_0001:d1:0",
        "/universe",
        vec![at("body > dialog > button", "Close", button())],
    );
    modal["title"] = json!("Accenture");
    let s = spec(vec![
        modal,
        view(
            "view_0001",
            "/universe",
            vec![at("body > main > a", "Strategies", link("/strategies"))],
        ),
        view("view_0002", "/strategies", vec![]),
        view(
            "view_0003",
            "/gone",
            vec![at("body > main > a", "Home", link("/"))],
        ),
    ]);
    // /gone came back 404: a broken link target, not a route.
    let mut doc = row("GET", "/gone", Some(404), None, None);
    doc["request"]["headers"] = json!({"Sec-Fetch-Dest": "document"});
    write_scan(dir.path(), &s, Some(&[]), &[doc]);
    let mut o = opts();
    o.discovered_routes = vec![
        DiscoveredRoute {
            path: "/:view".into(),
            dynamic: true,
            kind: "page".into(),
            file: "src/app/[view]/page.tsx".into(),
            examples: vec!["/universe".into(), "/strategies".into()],
            ..Default::default()
        },
        DiscoveredRoute {
            path: "/404".into(),
            kind: "page".into(),
            file: "src/pages/404.astro".into(),
            ..Default::default()
        },
    ];
    let inv = build(dir.path(), &o).await;
    let names: Vec<&str> = inv.routes.iter().map(|r| r.route.as_str()).collect();
    assert_eq!(names, vec!["/strategies", "/universe"], "{:?}", inv.routes);
    let universe = inv.routes.iter().find(|r| r.route == "/universe").unwrap();
    assert_eq!(
        universe.title.as_deref(),
        Some("Page /universe"),
        "title at view load, not the modal's"
    );
    assert!(
        find(&inv, "/universe|link|text=strategies")
            .navigates_to()
            .any(|t| t == "/strategies")
    );
    assert!(inv.controls.iter().all(|c| c.route != "/gone"));
}

#[tokio::test]
async fn seeded_concrete_paths_stay_distinct_routes() {
    let run = tempfile::tempdir().unwrap();
    let scan = run.path().join("scan");
    std::fs::create_dir_all(&scan).unwrap();
    std::fs::write(
        run.path().join("seed-routes.txt"),
        "# Route seeds generated by `brokenapp map`.\n/settings\n/activity\n",
    )
    .unwrap();
    let s = spec(vec![
        view("view_0001", "/settings", vec![]),
        view("view_0002", "/activity", vec![]),
        view("view_0003", "/other", vec![]),
    ]);
    write_scan(&scan, &s, Some(&[]), &[]);
    let mut o = opts();
    o.discovered_routes = vec![DiscoveredRoute {
        path: "/:view".into(),
        dynamic: true,
        kind: "page".into(),
        ..Default::default()
    }];
    let inv = build(&scan, &o).await;
    let names: Vec<&str> = inv.routes.iter().map(|r| r.route.as_str()).collect();
    assert_eq!(names, vec!["/:view", "/activity", "/settings"]);
}

#[tokio::test]
async fn browser_error_documents_are_excluded_from_routes_and_controls() {
    let dir = tempfile::tempdir().unwrap();
    let mut err_view = view(
        "view_err",
        "chrome-error://chromewebdata",
        vec![el(
            "#reload-button",
            "Reload",
            button(),
            &[("id", "#reload-button")],
        )],
    );
    err_view["url"] = json!("chrome-error://chromewebdata/");
    let s = spec(vec![
        view(
            "view_0001",
            "/",
            vec![el("#ok-btn", "Continue", button(), &[("id", "#ok-btn")])],
        ),
        err_view,
    ]);
    let mut err_rec = rec(
        "view_err",
        "chrome-error://chromewebdata/",
        "#reload-button",
        "button",
        InteractionOutcome::Navigated,
    );
    err_rec.page_url = "chrome-error://chromewebdata/".to_string();
    err_rec.after_url = Some("http://127.0.0.1:3000/missing".to_string());
    let records = vec![err_rec];
    write_scan(dir.path(), &s, Some(&records), &[]);
    let inv = build(dir.path(), &opts()).await;
    assert!(
        inv.routes
            .iter()
            .all(|r| !r.route.contains("chrome-error") && !r.route.contains("chromewebdata")),
        "browser error document leaked into routes: {:?}",
        inv.routes
    );
    assert!(
        inv.controls
            .iter()
            .all(|c| !c.route.contains("chrome-error") && c.selector != "#reload-button"),
        "browser error Reload button leaked into controls: {:?}",
        inv.controls
    );
    assert_eq!(inv.coverage.routes_visited, 1);
}

#[tokio::test]
async fn dev_tool_requests_are_not_calls_and_api_paths_follow_source_patterns() {
    let dir = tempfile::tempdir().unwrap();
    let s = spec(vec![view(
        "view_0001",
        "/",
        vec![el("#next", "Next month", button(), &[("id", "#next")])],
    )]);
    let records = vec![rec(
        "view_0001",
        "/",
        "#next",
        "button",
        InteractionOutcome::NoEffect,
    )];
    let aid = Some("act-view_0001-#next");
    let trig = Some(("view_0001", "#next"));
    let rows = vec![
        row(
            "POST",
            "/__nextjs_original-stack-frames",
            Some(200),
            trig,
            aid,
        ),
        row("GET", "/api/availability/blue-widget", Some(200), trig, aid),
    ];
    write_scan(dir.path(), &s, Some(&records), &rows);
    let mut o = opts();
    o.discovered_routes = vec![DiscoveredRoute {
        path: "/api/availability/:slug".into(),
        dynamic: true,
        kind: "api".into(),
        methods: vec!["GET".into()],
        ..Default::default()
    }];
    let inv = build(dir.path(), &o).await;
    let next = find(&inv, "/|button|id=next");
    assert_eq!(
        next.endpoints().collect::<Vec<_>>(),
        vec!["GET /api/availability/:slug"]
    );
    assert!(
        inv.endpoints
            .iter()
            .all(|e| !e.endpoint.contains("__nextjs")),
        "{:?}",
        inv.endpoints
    );
}

// ---------------------------------------------------------------------------
// 4. Status rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_needs_high_confidence_for_dead() {
    let dir = tempfile::tempdir().unwrap();
    let mut handled = el("#filter", "All 17", button(), &[("id", "#filter")]);
    handled["source"] = json!({"frames": [], "handlers": ["onClick"]});
    let mut handled2 = el("#noop", "Do nothing", button(), &[("id", "#noop")]);
    handled2["source"] = json!({"frames": [
        {"role": "handler", "owner": "onClick", "url": format!("{BASE}/src/a.tsx"), "line": 3, "col": 1}
    ]});
    let s = spec(vec![view(
        "view_0001",
        "/",
        vec![
            el("#active", "Print tab", button(), &[("id", "#active")]),
            el("#print", "Print", button(), &[("id", "#print")]),
            handled,
            handled2,
            el("#dead", "Nothing", button(), &[("id", "#dead")]),
            el("#retested", "Gone quiet", button(), &[("id", "#retested")]),
            el("#flaky", "Flaky", button(), &[("id", "#flaky")]),
            el("#hidden", "In details", button(), &[("id", "#hidden")]),
            el(
                "#hang_once",
                "Stalled once",
                button(),
                &[("id", "#hang_once")],
            ),
            el("#hang", "Hangs", button(), &[("id", "#hang")]),
        ],
    )]);
    let ne = |sel: &str| {
        rec(
            "view_0001",
            "/",
            sel,
            "button",
            InteractionOutcome::NoEffect,
        )
    };
    let mut active = ne("#active");
    active.already_active = true;
    let mut print = ne("#print");
    print.side_effects = vec!["print".into()];
    let mut retested = ne("#retested");
    retested.retest = Some("confirmed_no_effect".into());
    let mut flaky_ok = ne("#flaky");
    flaky_ok.outcome = InteractionOutcome::DomChange;
    flaky_ok.dom_change = Some("panel".into());
    let mut flaky_timeout = flaky_ok.clone();
    flaky_timeout.view_id = "view_0002".into();
    // Three visits to the same control on one route, not aliases for /b or /c.
    flaky_timeout.page_url = format!("{BASE}/?attempt=timeout");
    flaky_timeout.outcome = InteractionOutcome::Error;
    flaky_timeout.error = Some("interaction_timeout: no response within 8000ms".into());
    let mut flaky2 = flaky_ok.clone();
    flaky2.view_id = "view_0003".into();
    flaky2.page_url = format!("{BASE}/?attempt=ok");
    let mut hidden = rec(
        "view_0001",
        "/",
        "#hidden",
        "button",
        InteractionOutcome::Skipped,
    );
    hidden.skipped_reason = Some("hidden".into());
    let mut hang_once = ne("#hang_once");
    hang_once.outcome = InteractionOutcome::Error;
    hang_once.error = Some("interaction_timeout: no response within 8000ms".into());
    let mut hang = ne("#hang");
    hang.outcome = InteractionOutcome::Error;
    hang.error = Some("interaction_timeout: no response within 8000ms".into());
    let mut hang2 = hang.clone();
    hang2.view_id = "view_0002".into();
    hang2.page_url = format!("{BASE}/?attempt=timeout");
    let records = vec![
        active,
        print,
        ne("#filter"),
        ne("#noop"),
        ne("#dead"),
        retested,
        flaky_ok,
        flaky_timeout,
        flaky2,
        hidden,
        hang_once,
        hang,
        hang2,
    ];
    let mut s = s;
    s["views"].as_array_mut().unwrap().extend([
        view(
            "view_0002",
            "/",
            vec![
                el("#flaky", "Flaky", button(), &[("id", "#flaky")]),
                el("#hang", "Hangs", button(), &[("id", "#hang")]),
            ],
        ),
        view(
            "view_0003",
            "/",
            vec![el("#flaky", "Flaky", button(), &[("id", "#flaky")])],
        ),
    ]);
    write_scan(dir.path(), &s, Some(&records), &[]);
    let inv = build(dir.path(), &opts()).await;
    let st = |k: &str| {
        let c = find(&inv, k);
        (c.status, c.reason.clone().unwrap_or_default())
    };
    assert_eq!(
        st("/|button|id=active"),
        (ControlStatus::Ok, "already active".into())
    );
    let print = find(&inv, "/|button|id=print");
    assert_eq!(print.status, ControlStatus::Ok);
    assert_eq!(
        print.outcomes,
        vec![Outcome::SideEffect {
            kind: "print".into()
        }]
    );
    assert_eq!(render::describe_does(print), "opens the print dialog");
    assert_eq!(
        st("/|button|id=filter"),
        (ControlStatus::NoEffect, "handler attached".into())
    );
    assert_eq!(st("/|button|id=noop").0, ControlStatus::NoEffect);
    assert_eq!(st("/|button|id=dead"), (ControlStatus::Dead, String::new()));
    assert_eq!(
        st("/|button|id=retested"),
        (ControlStatus::Dead, "confirmed on retest".into())
    );
    // A tool-side timeout on 1 of 3 attempts is flakiness, not an app error.
    assert_eq!(st("/|button|id=flaky").0, ControlStatus::Ok);
    assert_eq!(
        st("/|button|id=hidden"),
        (ControlStatus::NotExercised, "hidden".into())
    );
    // A single isolated timeout (1 of 1) stays `not_exercised`, not `broken`.
    let hang_once = find(&inv, "/|button|id=hang_once");
    assert_eq!(hang_once.status, ControlStatus::NotExercised);
    assert!(
        hang_once
            .reason
            .as_deref()
            .unwrap()
            .contains("interaction_timeout")
    );
    // Repeated tool-side timeouts (2 of 2) are reported as `broken`.
    let hang = find(&inv, "/|button|id=hang");
    assert_eq!(hang.status, ControlStatus::Broken);
    assert!(
        hang.reason
            .as_deref()
            .unwrap()
            .contains("on 2 of 2 attempts")
    );
    assert_eq!(inv.coverage.controls_exercised, 8);
}

#[tokio::test]
async fn error_locations_drop_bundle_noise_offline() {
    let dir = tempfile::tempdir().unwrap();
    let s = spec(vec![view(
        "view_0001",
        "/",
        vec![
            el("#a", "How it works", button(), &[("id", "#a")]),
            el("#b", "Refresh", button(), &[("id", "#b")]),
        ],
    )]);
    let mut a = rec("view_0001", "/", "#a", "button", InteractionOutcome::Error);
    a.error = Some(format!(
        "Error: guide unavailable @ at onClick ({BASE}/_next/static/chunks/src_1-x._.js:2365:43)"
    ));
    let mut b = rec("view_0001", "/", "#b", "button", InteractionOutcome::Error);
    b.error = Some(format!(
        "Error: refresh failed @ at onClick ({BASE}/src/screens/History.tsx:59:11)"
    ));
    write_scan(dir.path(), &s, Some(&[a, b]), &[]);
    let inv = build(dir.path(), &opts()).await;
    assert_eq!(
        find(&inv, "/|button|id=a").reason.as_deref(),
        Some("Error: guide unavailable @ at onClick (bundled code)")
    );
    assert_eq!(
        find(&inv, "/|button|id=b").reason.as_deref(),
        Some("Error: refresh failed @ at onClick (src/screens/History.tsx:59 (unmapped))")
    );
}

// ---------------------------------------------------------------------------
// 5. Link checks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn links_to_unknown_routes_and_login_redirects_are_broken() {
    let dir = tempfile::tempdir().unwrap();
    let s = spec(vec![
        view(
            "view_0001",
            "/",
            vec![
                at(
                    "body > main > a:nth-of-type(1)",
                    "Returns",
                    link("/seller-returns"),
                ),
                at(
                    "body > main > a:nth-of-type(2)",
                    "Privacy",
                    link("/privacy-policy"),
                ),
                at(
                    "body > main > a:nth-of-type(3)",
                    "Account",
                    link("/account"),
                ),
                at("body > main > a:nth-of-type(4)", "Old blog", link("/blog")),
            ],
        ),
        view("view_0002", "/seller-returns", vec![]),
    ]);
    let doc = |path: &str, status: u16, location: Option<&str>| {
        let mut r = row("GET", path, Some(status), None, None);
        r["request"]["headers"] = json!({"Sec-Fetch-Dest": "document"});
        r["trace"]["cdp_request_id"] = json!(format!("req-{path}"));
        if let Some(l) = location {
            r["response"]["headers"] = json!({"location": l});
        }
        r
    };
    let rows = vec![
        doc("/seller-returns", 200, None),
        doc(
            "/privacy-policy",
            307,
            Some("/sign-in?next=%2Fprivacy-policy"),
        ),
        doc("/account", 307, Some("/sign-in?next=%2Faccount")),
        doc("/blog", 301, Some("/news")),
    ];
    write_scan(dir.path(), &s, Some(&[]), &rows);
    let mut o = opts();
    o.discovered_routes = routes(&["/", "/returns", "/account", "/sign-in", "/news"]);
    let inv = build(dir.path(), &o).await;
    let reason = |k: &str| {
        let c = find(&inv, k);
        (c.status, c.reason.clone().unwrap_or_default())
    };
    assert_eq!(
        reason("/|link|text=returns"),
        (
            ControlStatus::Broken,
            "link target /seller-returns is not a route in source (unknown route)".into()
        ),
        "SPA soft 404"
    );
    assert_eq!(
        reason("/|link|text=privacy"),
        (
            ControlStatus::Broken,
            "link target /privacy-policy redirects to login (unknown route)".into()
        )
    );
    // A known, auth-gated route that redirects to login is fine.
    assert_eq!(reason("/|link|text=account").0, ControlStatus::Ok);
    // A redirect alias to a real page is fine.
    assert_eq!(reason("/|link|text=old blog").0, ControlStatus::Ok);
    let names: Vec<&str> = inv.routes.iter().map(|r| r.route.as_str()).collect();
    assert!(!names.contains(&"/privacy-policy"), "{names:?}");
    assert!(
        !names.contains(&"/blog"),
        "3xx-only unknown paths are not routes"
    );
    let soft = inv
        .routes
        .iter()
        .find(|r| r.route == "/seller-returns")
        .unwrap();
    assert!(soft.not_in_source);
    let account = inv.routes.iter().find(|r| r.route == "/account").unwrap();
    assert_eq!(
        account.unvisited_reason.as_deref(),
        Some("redirects to login")
    );
    assert_eq!(
        inv.coverage.unvisited_by_reason.get("redirects to login"),
        Some(&vec!["/account".to_string()])
    );
}

#[tokio::test]
async fn link_probe_records_redirect_landing_and_spa_fallback() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/privacy-policy"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/login"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    // Everything else: the SPA fallback page with 200.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let base = server.uri();
    let dir = tempfile::tempdir().unwrap();
    let mut s = spec(vec![view(
        "view_0001",
        "/",
        vec![
            at(
                "body > main > a:nth-of-type(1)",
                "Privacy",
                link("/privacy-policy"),
            ),
            at(
                "body > main > a:nth-of-type(2)",
                "Returns",
                link("/seller-returns"),
            ),
            at("body > main > a:nth-of-type(3)", "Orders", link("/orders")),
        ],
    )]);
    s["meta"]["target_url"] = json!(format!("{base}/"));
    write_scan(dir.path(), &s, Some(&[]), &[]);
    let mut o = opts();
    o.target_url = format!("{base}/");
    o.check_links = true;
    o.discovered_routes = routes(&["/", "/orders", "/login"]);
    let inv = build(dir.path(), &o).await;
    assert_eq!(
        find(&inv, "/|link|text=privacy").reason.as_deref(),
        Some("link target /privacy-policy redirects to login (unknown route)")
    );
    assert_eq!(
        find(&inv, "/|link|text=returns").status,
        ControlStatus::Broken,
        "the server answers made-up paths with 200, so 200 proves nothing"
    );
    assert_eq!(find(&inv, "/|link|text=orders").status, ControlStatus::Ok);
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
}

// ---------------------------------------------------------------------------
// 6. Diff semantics
// ---------------------------------------------------------------------------

fn with_routes(mut inv: Inventory, visited: &[&str], unvisited: &[&str]) -> Inventory {
    inv.routes = visited
        .iter()
        .map(|r| RouteEntry {
            route: r.to_string(),
            visited: true,
            ..Default::default()
        })
        .chain(unvisited.iter().map(|r| RouteEntry {
            route: r.to_string(),
            ..Default::default()
        }))
        .collect();
    inv
}

#[test]
fn absences_are_removed_only_when_the_control_could_have_been_seen() {
    let ok = |route: &str, id: &str| {
        ctl(
            route,
            &format!("id={id}"),
            id,
            ControlStatus::Ok,
            calls("GET /api/x"),
        )
    };
    let mut in_modal = ok("/a", "copy");
    in_modal.opened_by = vec!["/a|button|id=inspect".into()];
    let mut in_dialog = ok("/a", "agree");
    in_dialog.region = "dialog".into();
    let mut variant = ok("/a", "hide-count");
    variant.variants = vec!["?shipment=3".into()];
    let mut never = ok("/a", "later");
    never.status = ControlStatus::NotExercised;
    let prev = with_routes(
        inv_with(
            vec![
                ok("/a", "inspect"),
                ok("/a", "gone"),
                ok("/b", "elsewhere"),
                in_modal,
                in_dialog,
                variant,
                never,
            ],
            &[],
            &[],
            "2026-10-20T00:00:00Z",
        ),
        &["/a", "/b"],
        &[],
    );
    let cur = with_routes(
        inv_with(vec![ok("/a", "inspect")], &[], &[], "2026-10-21T00:00:00Z"),
        &["/a"],
        &["/b"],
    );
    let cs = diff(Some(&prev), &cur);
    assert_eq!(
        lines(&cs),
        vec!["REMOVED /a button \"gone\" (was calls GET /api/x)"]
    );
    assert_eq!(cs.summary.get("not_observed"), Some(&5));
    assert_eq!(cs.not_observed.len(), 5);
    assert!(
        cs.notes[0].contains("not counted as removed"),
        "{:?}",
        cs.notes
    );
    for why in [
        "route not visited this time",
        "the state it is in was not reached",
        "its dialog was not open",
        "its page variant (query or record) was not visited",
        "not exercised in the previous map",
    ] {
        assert!(
            cs.not_observed.iter().any(|l| l.contains(why)),
            "{why}: {:?}",
            cs.not_observed
        );
    }
}

#[test]
fn controls_behind_a_now_broken_opener_are_not_reached() {
    let mut close = ctl(
        "/",
        "text=close dialog",
        "Close dialog",
        ControlStatus::Ok,
        vec![],
    );
    close.outcomes = vec![Outcome::DomChange {
        kind: "modal".into(),
    }];
    close.opened_by = vec!["/|button|text=privacy".into()];
    let opener = |status| {
        ctl(
            "/",
            "text=privacy",
            "Privacy",
            status,
            vec![Outcome::DomChange {
                kind: "modal".into(),
            }],
        )
    };
    let prev = inv_with(
        vec![opener(ControlStatus::Ok), close],
        &["/"],
        &[],
        "2026-10-20T00:00:00Z",
    );
    let mut broken = opener(ControlStatus::Broken);
    broken.reason = Some("Error: privacy panel failed".into());
    let cur = inv_with(vec![broken], &["/"], &[], "2026-10-21T00:00:00Z");
    let cs = diff(Some(&prev), &cur);
    assert_eq!(
        lines(&cs),
        vec![
            "NOW BROKEN / button \"Privacy\": Error: privacy panel failed (was opens modal)",
            "NOT REACHED 1 control behind / button \"Privacy\" (opener now broken): \"Close dialog\"",
        ]
    );
}

#[test]
fn legacy_opener_reachability_is_bound_to_the_missing_child_route() {
    let make = |route: &str, locator: &str, label: &str| {
        ctl(route, locator, label, ControlStatus::Ok, vec![])
    };
    let route = "/receiving";
    let other_route = "/testing/:holdingId";
    let opener = make(route, "text=start camera", "Start camera");
    let mut missing = make(route, "text=open system settings", "Open System Settings");
    missing.opened_by = vec![opener.key.clone()];
    let prev = inv_with(
        vec![opener.clone(), missing.clone()],
        &[route, other_route],
        &[],
        "before",
    );
    for paired in [false, true] {
        let other_opener = make(other_route, "text=start camera", "Start camera");
        let mut reached = make(other_route, "text=stop camera", "Stop camera");
        reached.opened_by = vec![other_opener.key.clone()];
        if paired {
            reached.state_entries = vec![opened_entry(
                other_route,
                Some("/testing/7"),
                &other_opener.key,
            )];
        }
        let cur = inv_with(
            vec![opener.clone(), other_opener, reached],
            &[route, other_route],
            &[],
            "after",
        );
        let cs = diff(Some(&prev), &cur);
        assert!(
            !cs.changes
                .iter()
                .any(|c| c.kind == "removed" && c.key == missing.key),
            "{cs:?}"
        );
        assert!(
            cs.not_observed
                .iter()
                .any(|line| line.contains("Open System Settings")),
            "{cs:?}"
        );
    }
}

#[test]
fn legacy_exact_global_opener_key_does_not_prove_another_child_route() {
    let route = "/receiving";
    let other_route = "/testing/:holdingId";
    let mut opener = ctl(
        "*",
        "text=start camera",
        "Start camera",
        ControlStatus::Ok,
        vec![],
    );
    opener.routes = vec![route.into(), other_route.into()];
    let mut missing = ctl(route, "id=settings", "Settings", ControlStatus::Ok, vec![]);
    missing.opened_by = vec![opener.key.clone()];
    let prev = inv_with(
        vec![opener.clone(), missing.clone()],
        &[route, other_route],
        &[],
        "before",
    );
    for paired in [false, true] {
        let mut reached = ctl(other_route, "id=stop", "Stop", ControlStatus::Ok, vec![]);
        reached.opened_by = vec![opener.key.clone()];
        if paired {
            reached.state_entries =
                vec![opened_entry(other_route, Some("/testing/7"), &opener.key)];
        }
        let cur = inv_with(
            vec![opener.clone(), reached],
            &[route, other_route],
            &[],
            "after",
        );
        let cs = diff(Some(&prev), &cur);
        assert!(
            !cs.changes
                .iter()
                .any(|c| c.kind == "removed" && c.key == missing.key),
            "{cs:?}"
        );
        assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");
    }
}

#[test]
fn legacy_same_route_and_supported_shell_openers_still_prove_removal() {
    let route = "/receiving";
    for (before_route, after_route, covered) in [
        (route, route, true),
        (route, "*", true),
        ("*", route, true),
        (route, "*", false),
        ("*", route, false),
    ] {
        let make_opener = |scope: &str| {
            let mut c = ctl(
                scope,
                "text=start camera",
                "Start camera",
                ControlStatus::Ok,
                vec![],
            );
            if scope == "*" {
                c.routes = vec![if covered { route } else { "/other" }.into()];
            }
            c
        };
        let before = make_opener(before_route);
        let after = make_opener(after_route);
        let mut missing = ctl(route, "id=settings", "Settings", ControlStatus::Ok, vec![]);
        missing.opened_by = vec![before.key.clone()];
        let prev = inv_with(vec![before, missing.clone()], &[route], &[], "before");
        for paired in [false, true] {
            let mut reached = ctl(route, "id=stop", "Stop", ControlStatus::Ok, vec![]);
            reached.opened_by = vec![after.key.clone()];
            if paired {
                reached.state_entries = vec![opened_entry(route, None, &after.key)];
            }
            let cur = inv_with(vec![after.clone(), reached], &[route], &[], "after");
            let cs = diff(Some(&prev), &cur);
            assert_eq!(
                cs.changes
                    .iter()
                    .any(|c| c.kind == "removed" && c.key == missing.key),
                covered,
                "{cs:?}"
            );
        }
    }
}

#[test]
fn legacy_rewired_same_label_opener_does_not_prove_the_old_child_state() {
    let route = "/receiving";
    for same_key in [false, true] {
        let mut before = ctl(route, "text=open", "Open", ControlStatus::Ok, vec![]);
        before.target = Some("#old-panel".into());
        let mut after = before.clone();
        after.target = Some("#new-panel".into());
        if !same_key {
            after.key.push_str("#new-target");
        }
        let mut missing = ctl(route, "id=settings", "Settings", ControlStatus::Ok, vec![]);
        missing.opened_by = vec![before.key.clone()];
        let mut reached = ctl(route, "id=other", "Other panel", ControlStatus::Ok, vec![]);
        reached.opened_by = vec![after.key.clone()];
        let prev = inv_with(vec![before, missing.clone()], &[route], &[], "before");
        let cur = inv_with(vec![after, reached], &[route], &[], "after");
        let cs = diff(Some(&prev), &cur);
        assert!(
            !cs.changes
                .iter()
                .any(|c| c.kind == "removed" && c.key == missing.key),
            "{cs:?}"
        );
        assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");
    }
}

#[test]
fn legacy_ambiguous_shell_child_and_other_route_failure_remain_unobserved() {
    let route = "/receiving";
    let other_route = "/testing/:holdingId";
    let mut opener = ctl("*", "text=open", "Open", ControlStatus::Ok, vec![]);
    opener.routes = vec![route.into(), other_route.into()];
    let mut missing = ctl("*", "id=settings", "Settings", ControlStatus::Ok, vec![]);
    missing.routes = opener.routes.clone();
    missing.opened_by = vec![opener.key.clone()];
    let mut reached = ctl(route, "id=other", "Other", ControlStatus::Ok, vec![]);
    reached.opened_by = vec![opener.key.clone()];
    let prev = inv_with(
        vec![opener.clone(), missing.clone()],
        &[route, other_route],
        &[],
        "before",
    );
    let cur = inv_with(
        vec![opener.clone(), reached],
        &[route, other_route],
        &[],
        "after",
    );
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key),
        "{cs:?}"
    );
    assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");

    missing.route = route.into();
    missing.key = format!("{route}|button|id=settings");
    missing.routes.clear();
    let prev = inv_with(
        vec![opener, missing.clone()],
        &[route, other_route],
        &[],
        "before",
    );
    let failed = ctl(
        other_route,
        "text=open",
        "Open",
        ControlStatus::Broken,
        vec![],
    );
    let cur = inv_with(vec![failed], &[route, other_route], &[], "after");
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| matches!(c.kind.as_str(), "removed" | "not_reached")
                && (c.key == missing.key || c.line.contains("Settings"))),
        "{cs:?}"
    );
    assert!(
        cs.not_observed.iter().any(|line| line.contains("Settings")),
        "{cs:?}"
    );
}

#[test]
fn modern_child_entries_are_not_replaced_by_legacy_opened_by_reachability() {
    let route = "/receiving";
    let opener = state_control(route, "open", vec![direct_entry(route, None)]);
    let expected = opened_entry(route, None, &opener.key);
    let mut missing = state_control(route, "settings", vec![expected.clone()]);
    missing.opened_by = vec![opener.key.clone()];
    let prev = inv_with(
        vec![opener.clone(), missing.clone()],
        &[route],
        &[],
        "before",
    );
    let mut seen = state_control(route, "other", vec![direct_entry(route, None)]);
    seen.opened_by = vec![opener.key.clone()];
    let mut cur = inv_with(vec![opener, seen], &[route], &[], "after");
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key),
        "{cs:?}"
    );
    assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");
    cur.controls[1].state_entries = vec![expected];
    assert!(
        diff(Some(&prev), &cur)
            .changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key)
    );
}

#[test]
fn legacy_opener_reachability_keeps_record_and_query_variants_paired() {
    for (route, first, second) in [
        ("/records/:id", "/records/1", "/records/2"),
        ("/a", "?mode=x", "?mode=y"),
    ] {
        for paired in [false, true] {
            let opener = ctl(route, "id=open", "Open", ControlStatus::Ok, vec![]);
            let mut missing = ctl(route, "id=missing", "Missing", ControlStatus::Ok, vec![]);
            missing.opened_by = vec![opener.key.clone()];
            missing.variants = vec![first.into()];
            let mut prev = inv_with(
                vec![opener.clone(), missing.clone()],
                &[route],
                &[],
                "before",
            );
            prev.routes[0].variants = vec![first.into(), second.into()];
            for (reached_variant, removed) in [(second, false), (first, true)] {
                let mut reached = ctl(route, "id=seen", "Seen", ControlStatus::Ok, vec![]);
                reached.opened_by = vec![opener.key.clone()];
                reached.variants = vec![reached_variant.into()];
                if paired {
                    reached.state_entries =
                        vec![opened_entry(route, Some(reached_variant), &opener.key)];
                }
                let direct = state_control(route, "direct", vec![direct_entry(route, Some(first))]);
                let mut cur = inv_with(
                    vec![opener.clone(), direct, reached],
                    &[route],
                    &[],
                    "after",
                );
                cur.routes[0].variants = vec![first.into(), second.into()];
                let cs = diff(Some(&prev), &cur);
                assert_eq!(
                    cs.changes
                        .iter()
                        .any(|c| c.kind == "removed" && c.key == missing.key),
                    removed,
                    "{route} {paired} {reached_variant}: {cs:?}"
                );
                if !removed {
                    assert!(
                        cs.not_observed.iter().any(|line| line.contains("Missing")),
                        "{cs:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn legacy_multiple_openers_and_variants_do_not_form_a_cross_product() {
    let route = "/a";
    let first = "?mode=x";
    let second = "?mode=y";
    let opener = ctl(route, "id=open", "Open", ControlStatus::Ok, vec![]);
    let other_opener = ctl(
        route,
        "id=other-open",
        "Other open",
        ControlStatus::Ok,
        vec![],
    );
    let mut missing = ctl(route, "id=missing", "Missing", ControlStatus::Ok, vec![]);
    missing.opened_by = vec![opener.key.clone()];
    missing.variants = vec![first.into()];
    let mut reached = ctl(route, "id=seen", "Seen", ControlStatus::Ok, vec![]);
    reached.opened_by = vec![opener.key.clone(), other_opener.key.clone()];
    reached.variants = vec![first.into(), second.into()];
    let mut prev = inv_with(
        vec![opener.clone(), other_opener.clone(), missing.clone()],
        &[route],
        &[],
        "before",
    );
    prev.routes[0].variants = vec![first.into(), second.into()];
    let mut cur = inv_with(
        vec![opener.clone(), other_opener.clone(), reached.clone()],
        &[route],
        &[],
        "after",
    );
    cur.routes[0].variants = prev.routes[0].variants.clone();
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key),
        "{cs:?}"
    );
    assert!(
        cs.not_observed.iter().any(|line| line.contains("Missing")),
        "{cs:?}"
    );

    // Paired current evidence can prove the specific location and opener.
    cur.controls[2].state_entries = vec![opened_entry(route, Some(first), &opener.key)];
    assert!(
        diff(Some(&prev), &cur)
            .changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key)
    );

    // The missing legacy child can itself have an ambiguous flat pairing.
    prev.controls[2].opened_by = reached.opened_by;
    prev.controls[2].variants = reached.variants;
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key),
        "{cs:?}"
    );
    assert!(
        cs.not_observed.iter().any(|line| line.contains("Missing")),
        "{cs:?}"
    );
}

#[test]
fn legacy_failed_opener_must_be_bound_to_the_child_variant() {
    for (route, first, second) in [
        ("/records/:id", "/records/1", "/records/2"),
        ("/a", "?mode=x", "?mode=y"),
    ] {
        for paired in [false, true] {
            let mut opener = ctl(route, "id=open", "Open", ControlStatus::Ok, vec![]);
            opener.variants = vec![first.into()];
            let mut missing = ctl(route, "id=missing", "Missing", ControlStatus::Ok, vec![]);
            missing.opened_by = vec![opener.key.clone()];
            missing.variants = vec![first.into()];
            let mut prev = inv_with(
                vec![opener.clone(), missing.clone()],
                &[route],
                &[],
                "before",
            );
            prev.routes[0].variants = vec![first.into(), second.into()];
            for (variants, not_reached) in [
                (vec![second], false),
                (vec![first, second], false),
                (vec![first], true),
            ] {
                let mut failed = opener.clone();
                failed.status = ControlStatus::Broken;
                failed.variants = variants.iter().map(|v| (*v).into()).collect();
                if paired {
                    failed.state_entries = variants
                        .iter()
                        .map(|v| direct_entry(route, Some(v)))
                        .collect();
                }
                let mut cur = inv_with(vec![failed], &[route], &[], "after");
                cur.routes[0].variants = prev.routes[0].variants.clone();
                let cs = diff(Some(&prev), &cur);
                assert_eq!(
                    cs.changes
                        .iter()
                        .any(|c| c.kind == "not_reached" && c.line.contains("Missing")),
                    not_reached,
                    "{route} {paired} {variants:?}: {cs:?}"
                );
                assert!(
                    !cs.changes
                        .iter()
                        .any(|c| c.kind == "removed" && c.key == missing.key),
                    "{cs:?}"
                );
                if !not_reached {
                    assert!(
                        cs.not_observed.iter().any(|line| line.contains("Missing")),
                        "{cs:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn legacy_ambiguous_reached_shell_child_does_not_prove_a_route() {
    let route = "/receiving";
    let other = "/testing/:holdingId";
    let mut opener = ctl("*", "id=open", "Open", ControlStatus::Ok, vec![]);
    opener.routes = vec![route.into(), other.into()];
    let mut missing = ctl(route, "id=missing", "Missing", ControlStatus::Ok, vec![]);
    missing.opened_by = vec![opener.key.clone()];
    let mut reached = ctl("*", "id=seen", "Seen", ControlStatus::Ok, vec![]);
    reached.routes = opener.routes.clone();
    reached.opened_by = vec![opener.key.clone()];
    let prev = inv_with(
        vec![opener.clone(), missing.clone()],
        &[route, other],
        &[],
        "before",
    );
    let mut cur = inv_with(vec![opener, reached], &[route, other], &[], "after");
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key),
        "{cs:?}"
    );
    assert!(
        cs.not_observed.iter().any(|line| line.contains("Missing")),
        "{cs:?}"
    );
    cur.controls[1].routes = vec![route.into()];
    assert!(
        diff(Some(&prev), &cur)
            .changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key)
    );
}

#[test]
fn legacy_empty_variants_do_not_infer_plain_or_query_presence() {
    let route = "/a";
    let query = "?mode=x";
    let mut opener = ctl(route, "id=open", "Open", ControlStatus::Ok, vec![]);
    opener.variants = vec![query.into()];
    let mut missing = ctl(route, "id=missing", "Missing", ControlStatus::Ok, vec![]);
    missing.opened_by = vec![opener.key.clone()];
    let mut prev = inv_with(
        vec![opener.clone(), missing.clone()],
        &[route],
        &[],
        "before",
    );
    prev.routes[0].variants = vec![query.into()];
    // Empty legacy variants also represent plain-only presence even when
    // another view visited this route's query state. Neither state is proven.
    for reached_variant in [None, Some(query)] {
        let reached = state_control(
            route,
            "seen",
            vec![opened_entry(route, reached_variant, &opener.key)],
        );
        let mut cur = inv_with(vec![opener.clone(), reached], &[route], &[], "after");
        cur.routes[0].variants = vec![query.into()];
        let cs = diff(Some(&prev), &cur);
        assert!(
            !cs.changes
                .iter()
                .any(|c| c.kind == "removed" && c.key == missing.key),
            "{cs:?}"
        );
        assert!(
            cs.not_observed.iter().any(|line| line.contains("Missing")),
            "{cs:?}"
        );
    }
    // A reached legacy child's empty list is equally ambiguous.
    prev.controls[1].variants = vec![query.into()];
    let mut reached = ctl(route, "id=seen", "Seen", ControlStatus::Ok, vec![]);
    reached.opened_by = vec![opener.key.clone()];
    let mut cur = inv_with(vec![opener.clone(), reached], &[route], &[], "after");
    cur.routes[0].variants = vec![query.into()];
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| c.kind == "removed" && c.key == missing.key),
        "{cs:?}"
    );
    assert!(
        cs.not_observed.iter().any(|line| line.contains("Missing")),
        "{cs:?}"
    );

    // An ambiguous grouped failure cannot explain a known query child.
    let mut failed = opener;
    failed.status = ControlStatus::Broken;
    failed.variants.clear();
    cur.controls = vec![failed];
    let cs = diff(Some(&prev), &cur);
    assert!(
        !cs.changes
            .iter()
            .any(|c| matches!(c.kind.as_str(), "removed" | "not_reached")
                && c.line.contains("Missing")),
        "{cs:?}"
    );
    assert!(
        cs.not_observed.iter().any(|line| line.contains("Missing")),
        "{cs:?}"
    );
}

fn direct_entry(route: &str, variant: Option<&str>) -> ControlStateEntry {
    ControlStateEntry {
        route: route.into(),
        variant: variant.map(str::to_string),
        kind: ControlStateEntryKind::Direct,
    }
}

fn opened_entry(route: &str, variant: Option<&str>, opener: &str) -> ControlStateEntry {
    ControlStateEntry {
        route: route.into(),
        variant: variant.map(str::to_string),
        kind: ControlStateEntryKind::Opened {
            opener: opener.into(),
        },
    }
}

fn state_control(route: &str, id: &str, entries: Vec<ControlStateEntry>) -> Control {
    let mut c = ctl(route, &format!("id={id}"), id, ControlStatus::Ok, vec![]);
    c.state_entries = entries;
    c
}

#[test]
fn mixed_direct_and_opened_entries_are_alternatives_without_false_removals() {
    let route = "/receiving";
    let base = direct_entry(route, None);
    let query = direct_entry(route, Some("?shipment=3"));
    let opener = state_control(route, "open-count", vec![base.clone()]);
    let opened = opened_entry(route, None, &opener.key);
    let mut child = state_control(route, "save-count", vec![opened.clone(), query.clone()]);
    // Saved field shape: aggregation lost both restrictions. New entries
    // retain the alternatives even though these legacy projections are empty.
    child.opened_by.clear();
    child.variants.clear();
    let prev = inv_with(vec![opener.clone(), child.clone()], &[route], &[], "before");
    let mut failed = opener;
    failed.status = ControlStatus::NoEffect;
    failed.reason = Some("handler attached".into());
    let cur = inv_with(vec![failed.clone()], &[route], &[], "after");
    let cs = diff(Some(&prev), &cur);
    assert_eq!(cs.summary.get("not_reached"), Some(&1), "{cs:?}");
    assert_eq!(
        cs.summary.get("now_no_effect"),
        Some(&1),
        "the seeded opener failure remains visible: {cs:?}"
    );
    assert!(!cs.changes.iter().any(|c| c.kind == "removed"), "{cs:?}");

    // Either recorded alternative can prove coverage. The failed opener
    // must not hide a real removal when the direct shipment page was seen.
    let mut direct = cur.clone();
    direct
        .controls
        .push(state_control(route, "query-sibling", vec![query]));
    let cs = diff(Some(&prev), &direct);
    assert_eq!(cs.summary.get("removed"), Some(&1), "{cs:?}");
    assert!(
        !cs.changes.iter().any(|c| c.kind == "not_reached"),
        "{cs:?}"
    );

    let mut via_opener = cur;
    via_opener
        .controls
        .push(state_control(route, "panel-sibling", vec![opened]));
    let cs = diff(Some(&prev), &via_opener);
    assert_eq!(cs.summary.get("removed"), Some(&1), "{cs:?}");
    assert!(
        !cs.changes.iter().any(|c| c.kind == "not_reached"),
        "{cs:?}"
    );

    // Symmetric additions: merely revisiting the base is not evidence the
    // child is new; reaching either alternative makes a genuine add visible.
    let before = inv_with(vec![failed], &[route], &[], "earlier");
    let now = inv_with(vec![child], &[route], &[], "later");
    let cs = diff(Some(&before), &now);
    assert_eq!(cs.summary.get("newly_observed"), Some(&1), "{cs:?}");
    assert!(!cs.changes.iter().any(|c| c.kind == "added"), "{cs:?}");
    let cs = diff(Some(&direct), &now);
    assert_eq!(cs.summary.get("added"), Some(&1), "{cs:?}");
}

#[tokio::test]
async fn grouped_opener_failure_on_b_does_not_explain_missing_child_on_skipped_a() {
    let route = "/receiving";
    let make_view = |id, path| {
        let mut open = el("#open", "Open count", button(), &[("id", "#open")]);
        open["source"] = json!({"frames": [], "handlers": ["onClick"]});
        let mut v = view(id, path, vec![open]);
        v["url"] = json!(format!("{BASE}{path}"));
        v
    };
    let mut skipped = rec(
        "record-a",
        "/receiving?shipment=a",
        "#open",
        "button",
        InteractionOutcome::Skipped,
    );
    skipped.skipped_reason = Some("obscured".into());
    let mut failed = rec(
        "record-b",
        "/receiving?shipment=b",
        "#open",
        "button",
        InteractionOutcome::NoEffect,
    );
    failed.retest = Some("confirmed_no_effect".into());
    let cur = build_scan(
        vec![
            make_view("record-a", "/receiving?shipment=a"),
            make_view("record-b", "/receiving?shipment=b"),
        ],
        &[skipped, failed],
        &[],
        &[route],
    )
    .await;
    let opener = find(&cur, "/receiving|button|id=open");
    assert_eq!(opener.status, ControlStatus::NoEffect, "{opener:?}");
    assert_eq!(
        opener.state_entries,
        vec![
            direct_entry(route, Some("?shipment=a")),
            direct_entry(route, Some("?shipment=b")),
        ],
        "the raw records must actually produce the ambiguous group"
    );
    let mut previous_opener = opener.clone();
    previous_opener.status = ControlStatus::Ok;
    previous_opener.reason = None;
    previous_opener.outcomes = vec![Outcome::DomChange {
        kind: "panel".into(),
    }];
    let child = state_control(
        route,
        "save-count",
        vec![opened_entry(route, Some("?shipment=a"), &opener.key)],
    );
    let mut prev = inv_with(vec![previous_opener, child], &[route], &[], "before");
    prev.identity_version = cur.identity_version;
    let cs = diff(Some(&prev), &cur);
    assert_eq!(cs.summary.get("now_no_effect"), Some(&1), "{cs:?}");
    assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");
    assert!(
        !cs.changes
            .iter()
            .any(|c| matches!(c.kind.as_str(), "not_reached" | "removed")),
        "an attempt only on B cannot explain the missing child on A: {cs:?}"
    );
}

#[test]
fn failed_opener_requires_unambiguous_noninherited_context() {
    let route = "/receiving";
    let matching = direct_entry(route, Some("?shipment=a"));
    let opener = state_control(route, "open-count", vec![matching.clone()]);
    let child = state_control(
        route,
        "save-count",
        vec![opened_entry(route, Some("?shipment=a"), &opener.key)],
    );
    let prev = inv_with(vec![opener.clone(), child], &[route], &[], "before");
    let unknown = ControlStateEntry {
        kind: ControlStateEntryKind::Unknown,
        ..matching.clone()
    };
    for status in [
        ControlStatus::Dead,
        ControlStatus::Broken,
        ControlStatus::NoEffect,
    ] {
        for (entries, reason) in [
            (vec![], None),
            (vec![matching.clone(), unknown.clone()], None),
            (
                vec![matching.clone(), direct_entry(route, Some("?shipment=b"))],
                None,
            ),
            (
                vec![
                    matching.clone(),
                    direct_entry("/other", Some("?shipment=a")),
                ],
                None,
            ),
            (vec![matching.clone()], Some("exercised on /other")),
            // Even the same inherited route does not bind the failed query.
            (
                vec![matching.clone()],
                Some("handler attached; exercised on /receiving"),
            ),
        ] {
            let mut failed = opener.clone();
            failed.status = status;
            failed.state_entries = entries;
            failed.reason = reason.map(str::to_string);
            let cur = inv_with(vec![failed], &[route], &[], "after");
            let cs = diff(Some(&prev), &cur);
            assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cur:?}: {cs:?}");
            assert!(
                !cs.changes
                    .iter()
                    .any(|c| matches!(c.kind.as_str(), "not_reached" | "removed")),
                "{cur:?}: {cs:?}"
            );
        }
        let mut failed = opener.clone();
        failed.status = status;
        let cur = inv_with(vec![failed], &[route], &[], "after");
        let cs = diff(Some(&prev), &cur);
        assert_eq!(cs.summary.get("not_reached"), Some(&1), "{cs:?}");
        assert!(!cs.changes.iter().any(|c| c.kind == "removed"), "{cs:?}");
    }
}

#[test]
fn state_entry_coverage_keeps_route_variant_and_opener_paired() {
    let route = "/receiving";
    let opener = state_control(route, "open-count", vec![direct_entry(route, None)]);
    let expected = opened_entry(route, Some("?shipment=3"), &opener.key);
    let child = state_control(route, "save-count", vec![expected.clone()]);
    let prev = inv_with(
        vec![opener.clone(), child],
        &[route, "/other"],
        &[],
        "before",
    );
    for entries in [
        vec![opened_entry(route, Some("?shipment=4"), &opener.key)],
        vec![opened_entry("/other", Some("?shipment=3"), &opener.key)],
        vec![direct_entry(route, Some("?shipment=3"))],
        vec![opened_entry(
            route,
            Some("?shipment=3"),
            "/receiving|button|id=other",
        )],
        // A flat cross-product would incorrectly combine this query and opener.
        vec![
            direct_entry(route, Some("?shipment=3")),
            opened_entry(route, None, &opener.key),
        ],
    ] {
        let cur = inv_with(
            vec![opener.clone(), state_control(route, "other", entries)],
            &[route, "/other"],
            &[],
            "after",
        );
        let cs = diff(Some(&prev), &cur);
        assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");
        assert!(!cs.changes.iter().any(|c| c.kind == "removed"), "{cs:?}");
    }
    let cur = inv_with(
        vec![opener, state_control(route, "other", vec![expected])],
        &[route],
        &[],
        "after",
    );
    assert_eq!(diff(Some(&prev), &cur).summary.get("removed"), Some(&1));
}

#[test]
fn unknown_placeholder_and_missing_entry_evidence_do_not_prove_coverage() {
    for (route, entry) in [
        (
            "/receiving",
            ControlStateEntry {
                route: "/receiving".into(),
                variant: None,
                kind: ControlStateEntryKind::Unknown,
            },
        ),
        (
            "/devices/:id",
            direct_entry("/devices/:id", Some("/devices/:id")),
        ),
        ("/devices/:id", direct_entry("/devices/:id", None)),
    ] {
        let prev = inv_with(
            vec![state_control(route, "gone", vec![entry.clone()])],
            &[route],
            &[],
            "before",
        );
        let cur = inv_with(
            vec![state_control(route, "sibling", vec![entry])],
            &[route],
            &[],
            "after",
        );
        let cs = diff(Some(&prev), &cur);
        assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");
        assert_eq!(cs.summary.get("newly_observed"), Some(&1), "{cs:?}");
        assert!(cs.changes.is_empty(), "{cs:?}");
    }
    let prev = inv_with(
        vec![state_control("/a", "gone", vec![direct_entry("/a", None)])],
        &["/a"],
        &[],
        "before",
    );
    let cur = inv_with(
        vec![state_control("/a", "sibling", vec![])],
        &["/a"],
        &[],
        "after",
    );
    assert_eq!(
        diff(Some(&prev), &cur).summary.get("not_observed"),
        Some(&1)
    );
}

#[test]
fn global_control_entry_coverage_is_scoped_to_its_actual_route() {
    let mut missing = state_control(
        "*",
        "global-panel",
        vec![direct_entry("/a", Some("?view=detail"))],
    );
    missing.routes = vec!["/a".into(), "/b".into()];
    let prev = inv_with(vec![missing], &["/a", "/b"], &[], "before");
    let mut cur = inv_with(
        vec![state_control(
            "/b",
            "sibling",
            vec![direct_entry("/b", Some("?view=detail"))],
        )],
        &["/a", "/b"],
        &[],
        "after",
    );
    let cs = diff(Some(&prev), &cur);
    assert_eq!(cs.summary.get("not_observed"), Some(&1), "{cs:?}");
    assert!(!cs.changes.iter().any(|c| c.kind == "removed"), "{cs:?}");
    cur.controls[0]
        .state_entries
        .push(direct_entry("/a", Some("?view=detail")));
    assert_eq!(diff(Some(&prev), &cur).summary.get("removed"), Some(&1));
}

#[test]
fn relabel_requires_a_shared_recorded_entry_context_when_available() {
    let route = "/receiving";
    let mut old = state_control(route, "action", vec![direct_entry(route, None)]);
    old.label = "Start".into();
    let mut new = old.clone();
    new.label = "Continue".into();
    new.state_entries = vec![opened_entry(route, None, "/receiving|button|id=open")];
    let prev = inv_with(vec![old], &[route], &[], "before");
    let mut cur = inv_with(vec![new], &[route], &[], "after");
    assert!(
        !diff(Some(&prev), &cur)
            .changes
            .iter()
            .any(|c| c.kind == "relabeled")
    );
    cur.controls[0]
        .state_entries
        .push(direct_entry(route, None));
    assert_eq!(diff(Some(&prev), &cur).summary.get("relabeled"), Some(&1));
}

#[test]
fn shell_and_route_scoped_forms_pair_without_flip_lines() {
    let nav = |route: &str| {
        let mut c = ctl(
            route,
            "text=docs@header",
            "Docs",
            ControlStatus::Ok,
            vec![Outcome::Navigates { to: "/docs".into() }],
        );
        c.role = "link".into();
        c.region = "header".into();
        c.key = format!("{route}|link|text=docs@header");
        c
    };
    let mut shell = nav("*");
    shell.routes = vec!["/".into(), "/a".into(), "/b".into()];
    let prev = inv_with(vec![shell], &["/", "/a", "/b"], &[], "2026-10-20T00:00:00Z");
    // Demoted: fewer routes visited, so it is route-scoped now.
    let cur = inv_with(
        vec![nav("/"), nav("/a")],
        &["/", "/a", "/b"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    let cs = diff(Some(&prev), &cur);
    assert!(cs.changes.is_empty(), "{:?}", lines(&cs));
    assert!(diff(Some(&cur), &prev).changes.is_empty());
    // A route-scoped form that now points elsewhere is a rewire on that route.
    let mut moved = nav("/");
    moved.outcomes = vec![Outcome::Navigates {
        to: "/guides".into(),
    }];
    let cur = inv_with(
        vec![moved, nav("/a")],
        &["/", "/a", "/b"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    assert_eq!(
        lines(&diff(Some(&prev), &cur)),
        vec!["REWIRED / link \"Docs\": → /guides (was → /docs)"]
    );
}

#[test]
fn uniform_line_shifts_are_not_moves() {
    let at_line = |id: &str, file: &str, line: u32| {
        let mut c = ctl("/", &format!("id={id}"), id, ControlStatus::Ok, vec![]);
        c.source = Some(ResolvedSource {
            render: Some(FileLine {
                file: file.into(),
                line,
                col: 0,
            }),
            method: "runtime".into(),
            confidence: "exact".into(),
            ..Default::default()
        });
        c
    };
    let prev = inv_with(
        vec![
            at_line("a", "src/App.tsx", 10),
            at_line("b", "src/App.tsx", 20),
            at_line("c", "src/App.tsx", 30),
            at_line("d", "src/Other.tsx", 5),
            at_line("e", "src/Lone.tsx", 7),
        ],
        &["/"],
        &[],
        "2026-10-20T00:00:00Z",
    );
    let cur = inv_with(
        vec![
            at_line("a", "src/App.tsx", 10),
            at_line("b", "src/App.tsx", 22),
            at_line("c", "src/App.tsx", 32),
            at_line("d", "src/Moved.tsx", 5),
            at_line("e", "src/Lone.tsx", 9),
        ],
        &["/"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    let cs = diff(Some(&prev), &cur);
    assert_eq!(
        lines(&cs),
        vec![
            "MOVED / button \"d\": src/Moved.tsx:5 (was src/Other.tsx:5)",
            "MOVED / button \"e\": src/Lone.tsx:9 (was line 7)",
        ]
    );
    assert_eq!(cs.summary.get("shifted"), Some(&2));
    assert!(
        cs.notes.contains(
            &"src/App.tsx: 2 controls shifted +2 lines (edits above them; not moved).".to_string()
        ),
        "{:?}",
        cs.notes
    );
}

#[tokio::test]
async fn aggregated_spec_views_preserve_concrete_record_coverage() {
    let record = |id, path, selector, label: &str| {
        let mut r = rec(id, path, selector, "button", InteractionOutcome::DomChange);
        r.label = Some(label.into());
        r
    };
    let shared = || el("#shared", "Shared", button(), &[("id", "#shared")]);
    let buy = || el("#buy", "Buy", button(), &[("id", "#buy")]);
    let prev = build_scan(
        vec![view("view_devices_id", "/devices/:id", vec![shared()])],
        &[record("view_0001", "/devices/111", "#shared", "Shared")],
        &[],
        &["/devices/:identifier"],
    )
    .await;
    let cur = build_scan(
        vec![view(
            "view_devices_id",
            "/devices/:id",
            vec![shared(), buy(), el("#unknown", "Unknown", button(), &[])],
        )],
        &[
            record("view_0001", "/devices/111", "#shared", "Shared"),
            record("view_0002", "/devices/222", "#shared", "Shared"),
            record("view_0002", "/devices/222", "#buy", "Buy"),
        ],
        &[],
        &["/devices/:identifier"],
    )
    .await;
    let route = cur
        .routes
        .iter()
        .find(|r| r.route == "/devices/:identifier")
        .unwrap();
    assert_eq!(route.variants, ["/devices/111", "/devices/222"]);
    assert_eq!(
        find(&cur, "/devices/:identifier|button|id=buy").variants,
        ["/devices/222"]
    );
    assert_eq!(
        find(&prev, "/devices/:identifier|button|id=shared").variants,
        ["/devices/111"]
    );
    assert_eq!(
        find(&cur, "/devices/:identifier|button|id=shared").variants,
        ["/devices/111", "/devices/222"]
    );
    assert_eq!(
        find(&cur, "/devices/:identifier|button|id=unknown").variants,
        ["/devices/:identifier"]
    );
    let changes = diff(Some(&prev), &cur);
    assert!(!changes.summary.contains_key("added"), "{changes:?}");
    assert_eq!(changes.summary.get("newly_observed"), Some(&2));

    // A real addition on the same sampled record remains actionable.
    let comparable = build_scan(
        vec![view(
            "view_devices_id",
            "/devices/:id",
            vec![shared(), buy()],
        )],
        &[
            record("view_0001", "/devices/111", "#shared", "Shared"),
            record("view_0001", "/devices/111", "#buy", "Buy"),
        ],
        &[],
        &["/devices/:identifier"],
    )
    .await;
    assert_eq!(
        diff(Some(&prev), &comparable).summary.get("added"),
        Some(&1)
    );
}

#[tokio::test]
async fn aggregated_query_variants_preserve_browser_and_hash_route_controls() {
    for route in ["/account", "/#/account", "/#!/account"] {
        let profile = format!("{route}?tab=profile");
        let payout = format!("{route}?tab=payout");
        let record = |id, path: &str, selector, label: &str| {
            let mut r = rec(id, path, selector, "button", InteractionOutcome::DomChange);
            r.label = Some(label.into());
            r
        };
        let inv = build_scan(
            vec![view(
                "view_account",
                route,
                vec![
                    el("#profile", "Profile", button(), &[("id", "#profile")]),
                    el("#save", "Save payout", button(), &[("id", "#save")]),
                ],
            )],
            &[
                record("view_0001", &profile, "#profile", "Profile"),
                record("view_0002", &payout, "#save", "Save payout"),
            ],
            &[],
            &[route],
        )
        .await;
        assert_eq!(
            find(&inv, &format!("{route}|button|id=save")).variants,
            ["?tab=payout"],
            "{route}"
        );
        assert_eq!(
            find(&inv, &format!("{route}|button|id=profile")).variants,
            ["?tab=profile"],
            "{route}"
        );
        let variants = &inv
            .routes
            .iter()
            .find(|r| r.route == route)
            .unwrap()
            .variants;
        assert!(
            variants.contains(&"?tab=payout".to_string()),
            "{route}: {variants:?}"
        );
        assert!(
            variants.contains(&"?tab=profile".to_string()),
            "{route}: {variants:?}"
        );
    }
}

#[test]
fn placeholder_only_record_coverage_does_not_prove_addition_or_removal() {
    let route = "/devices/:identifier";
    let mut prev = inv_with(vec![], &[route], &[], "before");
    prev.routes[0].variants = vec!["/devices/:id".into()];
    let mut cur = inv_with(
        vec![ctl(route, "id=buy", "Buy", ControlStatus::Ok, vec![])],
        &[route],
        &[],
        "after",
    );
    cur.routes[0].variants = vec!["/devices/:id".into()];
    assert_eq!(
        diff(Some(&prev), &cur).summary.get("newly_observed"),
        Some(&1)
    );
    assert_eq!(
        diff(Some(&cur), &prev).summary.get("not_observed"),
        Some(&1)
    );
    // Unknown control provenance remains unknown even when another control
    // establishes a concrete route sample.
    prev.routes[0].variants = vec!["/devices/111".into()];
    cur.routes[0].variants = vec!["/devices/111".into()];
    cur.controls[0].variants = vec![route.into()];
    assert!(!diff(Some(&prev), &cur).summary.contains_key("added"));
}

#[test]
fn source_attribution_depth_changes_are_not_control_moves() {
    let location = |file: &str, line| FileLine {
        file: file.into(),
        line,
        col: 0,
    };
    let control = |id: &str, render, caller, method: &str| {
        let mut c = ctl("/", &format!("id={id}"), id, ControlStatus::Ok, vec![]);
        c.source = Some(ResolvedSource {
            render: Some(render),
            caller,
            method: method.into(),
            confidence: "exact".into(),
            ..Default::default()
        });
        c
    };
    let prev = inv_with(
        vec![
            control(
                "depth",
                location("src/Bench.tsx", 144),
                Some(location("src/Fixture.tsx", 35)),
                "runtime",
            ),
            control(
                "fallback",
                location("src/Card.tsx", 182),
                Some(location("src/Page.tsx", 555)),
                "runtime",
            ),
            control(
                "caller-moved",
                location("src/Card.tsx", 20),
                Some(location("src/OldPage.tsx", 30)),
                "runtime",
            ),
            control("render-moved", location("src/Old.tsx", 10), None, "runtime"),
        ],
        &["/"],
        &[],
        "before",
    );
    let cur = inv_with(
        vec![
            control(
                "depth",
                location("src/Workspace.tsx", 627),
                Some(location("src/Bench.tsx", 144)),
                "runtime",
            ),
            control("fallback", location("src/Card.tsx", 182), None, "static"),
            control(
                "caller-moved",
                location("src/Card.tsx", 20),
                Some(location("src/NewPage.tsx", 40)),
                "runtime",
            ),
            control("render-moved", location("src/New.tsx", 10), None, "runtime"),
        ],
        &["/"],
        &[],
        "after",
    );
    let changes = diff(Some(&prev), &cur);
    let moved: Vec<_> = changes
        .changes
        .iter()
        .filter(|c| c.kind == "moved")
        .map(|c| c.label.as_str())
        .collect();
    assert_eq!(moved, ["caller-moved", "render-moved"]);
}

#[test]
fn saved_static_to_runtime_capture_changes_are_not_source_moves() {
    // Earlier inventory comparisons reported these as source moves. Static
    // label/literal lines became JSX render/caller frames in unchanged files.
    let mut before = Vec::new();
    let mut after = Vec::new();
    for (route, label, render, old_line, new_line, caller, caller_line, confidence) in [
        (
            "/devices/:identifier",
            "Add to a purchase",
            "src/diagnostics/CounterDecisionCard.tsx",
            310,
            302,
            "src/screens/DevicePage.tsx",
            555,
            "exact",
        ),
        (
            "/devices/:identifier",
            "Buy now",
            "src/diagnostics/CounterDecisionCard.tsx",
            299,
            289,
            "src/screens/DevicePage.tsx",
            555,
            "exact",
        ),
        (
            "/testing/:holdingId",
            "Send to inspection bench",
            "src/screens/Inspection.tsx",
            523,
            517,
            "src/App.tsx",
            797,
            "probable",
        ),
    ] {
        let mut p = ctl(
            route,
            &format!("text={label}"),
            label,
            ControlStatus::Ok,
            vec![],
        );
        p.source = Some(ResolvedSource {
            render: Some(FileLine {
                file: render.into(),
                line: old_line,
                col: 9,
            }),
            method: "static".into(),
            confidence: "probable".into(),
            ..Default::default()
        });
        let mut c = p.clone();
        c.source = Some(ResolvedSource {
            render: Some(FileLine {
                file: render.into(),
                line: new_line,
                col: 9,
            }),
            caller: Some(FileLine {
                file: caller.into(),
                line: caller_line,
                col: 9,
            }),
            method: "runtime".into(),
            confidence: confidence.into(),
            ..Default::default()
        });
        before.push(p);
        after.push(c);
    }
    let routes = &["/devices/:identifier", "/testing/:holdingId"];
    let changes = diff(
        Some(&inv_with(before, routes, &[], "before")),
        &inv_with(after, routes, &[], "after"),
    );
    assert!(changes.changes.is_empty(), "{changes:?}");
    assert!(
        changes.notes.is_empty(),
        "an attribution change is not a line shift: {changes:?}"
    );
}

#[test]
fn source_moves_require_compatible_method_trust_and_frame_role() {
    for (before_method, after_method, confidence, before_caller, after_caller, expected) in [
        ("runtime", "runtime", "exact", false, false, 1),
        ("runtime", "runtime", "exact", true, true, 1),
        ("annotation", "annotation", "exact", false, false, 1),
        ("runtime", "runtime", "probable", false, false, 0),
        ("static", "static", "probable", false, false, 0),
        ("static", "static", "exact", false, false, 0),
        ("runtime", "annotation", "exact", false, false, 0),
        ("runtime", "runtime", "exact", true, false, 0),
        ("runtime", "runtime", "exact", false, true, 0),
    ] {
        let source = |method: &str, file: &str, has_caller: bool| ResolvedSource {
            render: Some(FileLine {
                file: file.into(),
                line: 10,
                col: 2,
            }),
            caller: has_caller.then(|| FileLine {
                file: format!("caller-{file}"),
                line: 20,
                col: 3,
            }),
            method: method.into(),
            confidence: confidence.into(),
            ..Default::default()
        };
        let mut p = ctl("/", "id=move", "Move", ControlStatus::Ok, vec![]);
        p.source = Some(source(before_method, "src/Old.tsx", before_caller));
        let mut c = p.clone();
        c.source = Some(source(after_method, "src/New.tsx", after_caller));
        let changes = diff(
            Some(&inv_with(vec![p], &["/"], &[], "before")),
            &inv_with(vec![c], &["/"], &[], "after"),
        );
        assert_eq!(
            changes.summary.get("moved").copied().unwrap_or(0),
            expected,
            "{before_method}/{after_method}/{confidence}/caller={before_caller}->{after_caller}: {changes:?}"
        );
    }
}

#[test]
fn relabel_does_not_join_saved_controls_by_their_component_caller() {
    // Minimal saved field evidence: these coexist on sampled records. The
    // summary and next-step Button share App.tsx's Inspection caller, but have
    // different render sites, selectors, and effects; neither was renamed.
    let route = "/testing/:holdingId";
    let mut report = ctl(
        route,
        "text=condition report",
        "Condition report",
        ControlStatus::Ok,
        vec![Outcome::DomChange {
            kind: "panel".into(),
        }],
    );
    report.region = "main".into();
    report.selector = "summary.cursor-pointer.text-\\[14px\\].font-semibold".into();
    report.source = Some(ResolvedSource {
        render: Some(FileLine {
            file: "src/screens/Inspection.tsx".into(),
            line: 573,
            col: 19,
        }),
        caller: Some(FileLine {
            file: "src/App.tsx".into(),
            line: 797,
            col: 57,
        }),
        method: "runtime".into(),
        confidence: "exact".into(),
        ..Default::default()
    });
    let mut next = ctl(
        route,
        "text=open next device",
        "Open next device",
        ControlStatus::Ok,
        vec![Outcome::Navigates { to: route.into() }],
    );
    next.region = "main".into();
    next.selector = "div:nth-of-type(1) > div:nth-of-type(1) > main:nth-of-type(1) > div:nth-of-type(1) > section:nth-of-type(1) > button:nth-of-type(1)".into();
    next.variants = vec!["/testing/00000008-0000-4000-8000-000000000002".into()];
    next.source = Some(ResolvedSource {
        render: Some(FileLine {
            file: "src/screens/Inspection.tsx".into(),
            line: 406,
            col: 13,
        }),
        caller: report.source.as_ref().unwrap().caller.clone(),
        handler: Some(FileLine {
            file: "src/screens/Inspection.tsx".into(),
            line: 409,
            col: 15,
        }),
        method: "runtime".into(),
        confidence: "exact".into(),
        ..Default::default()
    });
    let prev = inv_with(vec![report.clone()], &[route], &[], "before");
    let cur = inv_with(vec![next.clone()], &[route], &[], "after");
    let changes = diff(Some(&prev), &cur);
    assert!(!changes.summary.contains_key("relabeled"));
    assert_eq!(changes.summary.get("not_observed"), Some(&1));
    assert_eq!(changes.summary.get("newly_observed"), Some(&1));
    // The four-tab saved map retains both controls; do not collapse them.
    let both = inv_with(vec![report, next], &[route], &[], "both");
    assert!(!diff(Some(&prev), &both).summary.contains_key("relabeled"));
}

#[test]
fn relabel_does_not_join_saved_conditional_labels_across_record_scopes() {
    // Fixture evidence: this one JSX Button renders nextStep.action's
    // Start/Open labels. Equal render, handler, caller, and selector establish
    // an element, but do not establish a rename between different records.
    let route = "/testing/:holdingId";
    let open_record = "/testing/00000008-0000-4000-8000-000000000002";
    let start_record = "/testing/00000008-0000-4000-8000-000000000003";
    let mut start = ctl(
        route,
        "text=start the test",
        "Start the test",
        ControlStatus::Ok,
        vec![Outcome::Navigates { to: route.into() }],
    );
    start.region = "main".into();
    start.selector = "div:nth-of-type(1) > div:nth-of-type(1) > main:nth-of-type(1) > div:nth-of-type(1) > section:nth-of-type(1) > button:nth-of-type(1)".into();
    start.source = Some(ResolvedSource {
        render: Some(FileLine {
            file: "src/screens/Inspection.tsx".into(),
            line: 406,
            col: 13,
        }),
        caller: Some(FileLine {
            file: "src/App.tsx".into(),
            line: 797,
            col: 57,
        }),
        handler: Some(FileLine {
            file: "src/screens/Inspection.tsx".into(),
            line: 409,
            col: 15,
        }),
        method: "runtime".into(),
        confidence: "exact".into(),
        ..Default::default()
    });
    let mut open = start.clone();
    open.label = "Open next device".into();
    open.locator = "text=open next device".into();
    open.key = format!("{route}|button|{}", open.locator);
    open.variants = vec![open_record.into()];
    let inventory = |controls, variants: &[&str], at| {
        let mut inv = inv_with(controls, &[route], &[], at);
        inv.routes[0].variants = variants.iter().map(|s| s.to_string()).collect();
        inv
    };
    let before = inventory(vec![start.clone()], &["/testing/:id"], "before");
    let tabs1 = inventory(vec![open.clone()], &[open_record], "tabs1");
    let changes = diff(Some(&before), &tabs1);
    assert!(!changes.summary.contains_key("relabeled"));
    assert_eq!(changes.summary.get("not_observed"), Some(&1));
    assert_eq!(changes.summary.get("newly_observed"), Some(&1));

    start.variants = vec![start_record.into()];
    let all_records = &[open_record, start_record];
    let prev = inventory(vec![start.clone()], all_records, "before-concrete");
    let cur = inventory(vec![open.clone()], all_records, "after-concrete");
    // Both route unions contain both records, but these controls do not.
    assert!(!diff(Some(&prev), &cur).summary.contains_key("relabeled"));
    let tabs4 = inventory(vec![start.clone(), open], all_records, "tabs4");
    assert!(
        !diff(Some(&before), &tabs4)
            .summary
            .contains_key("relabeled")
    );

    let mut renamed = start.clone();
    renamed.label = "Begin the test".into();
    renamed.locator = "text=begin the test".into();
    renamed.key = format!("{route}|button|{}", renamed.locator);
    renamed.variants = all_records.iter().map(|s| s.to_string()).collect();
    let cur = inventory(vec![renamed], all_records, "renamed");
    // One common concrete state suffices; the complete scopes need not match.
    assert_eq!(diff(Some(&prev), &cur).summary.get("relabeled"), Some(&1));
    start.variants.clear();
    let route_fallback = inventory(vec![start], &[start_record], "route-fallback");
    assert_eq!(
        diff(Some(&route_fallback), &cur).summary.get("relabeled"),
        Some(&1)
    );
}

#[test]
fn relabel_requires_overlapping_query_states_for_text_and_stable_locators() {
    for route in ["/account", "/#/account"] {
        for text_locator in [true, false] {
            let mut old = ctl(
                route,
                if text_locator { "text=save" } else { "id=save" },
                "Save",
                ControlStatus::Ok,
                calls("POST /api/account"),
            );
            let mut new = ctl(
                route,
                if text_locator {
                    "text=apply"
                } else {
                    "id=save"
                },
                "Apply",
                ControlStatus::Ok,
                calls("POST /api/account"),
            );
            new.selector = old.selector.clone();
            old.variants = vec!["?tab=profile".into()];
            new.variants = vec!["?tab=payout".into()];
            let inventory = |c| {
                let mut inv = inv_with(vec![c], &[route], &[], "scan");
                inv.routes[0].variants = vec!["?tab=profile".into(), "?tab=payout".into()];
                inv
            };
            let mut prev = inventory(old);
            let mut cur = inventory(new);
            assert!(!diff(Some(&prev), &cur).summary.contains_key("relabeled"));
            cur.controls[0].variants = vec!["?tab=profile".into()];
            assert_eq!(diff(Some(&prev), &cur).summary.get("relabeled"), Some(&1));
            prev.controls[0].variants.clear();
            // Route coverage is usable only if the control has no explicit scope.
            assert_eq!(diff(Some(&prev), &cur).summary.get("relabeled"), Some(&1));
            prev.routes[0].variants.clear();
            assert!(!diff(Some(&prev), &cur).summary.contains_key("relabeled"));
        }
    }
}

#[test]
fn text_relabel_fallback_preserves_known_label_state_guard() {
    let old = ctl(
        "/",
        "text=closed",
        "Closed",
        ControlStatus::Ok,
        calls("POST /api/toggle"),
    );
    let mut new = ctl(
        "/",
        "text=open",
        "Open",
        ControlStatus::Ok,
        calls("POST /api/toggle"),
    );
    new.selector = old.selector.clone();
    for known_state in ["previous_labels", "current_labels", "seen_label"] {
        let mut prev = inv_with(vec![old.clone()], &["/"], &[], "before");
        let mut cur = inv_with(vec![new.clone()], &["/"], &[], "after");
        match known_state {
            "previous_labels" => prev.controls[0].labels = vec!["Closed".into(), "Open".into()],
            "current_labels" => cur.controls[0].labels = vec!["Closed".into(), "Open".into()],
            "seen_label" => {
                // A prior state retained the same stable text identity while
                // exposing another observed label; the regular guard knows it.
                let mut known = old.clone();
                known.route = "/other".into();
                known.key = "/other|button|text=closed".into();
                known.label = "Open".into();
                prev.controls.push(known);
            }
            _ => unreachable!(),
        }
        assert!(
            !diff(Some(&prev), &cur).summary.contains_key("relabeled"),
            "{known_state}"
        );
    }
}

#[test]
fn relabel_requires_control_evidence_beyond_a_shared_caller() {
    let site = |line, col| FileLine {
        file: "src/Buttons.tsx".into(),
        line,
        col,
    };
    for evidence in [
        "render",
        "annotation_render",
        "handler",
        "caller_with_selector",
        "caller_only",
        "weak_render",
        "probable_runtime_render",
        "probable_static_render",
        "mixed_exact_probable_render",
        "exact_static_render",
        "probable_with_selector",
        "shared_render_different_caller",
        "conflicting_render",
        "different_column",
    ] {
        let mut prev = ctl(
            "/",
            "text=pay",
            "Pay",
            ControlStatus::Ok,
            calls("POST /api/pay"),
        );
        let mut cur = ctl(
            "/",
            "text=pay now",
            "Pay now",
            ControlStatus::Ok,
            calls("POST /api/pay"),
        );
        prev.source = Some(ResolvedSource {
            caller: Some(site(1, 1)),
            method: "runtime".into(),
            confidence: "exact".into(),
            ..Default::default()
        });
        cur.source = prev.source.clone();
        match evidence {
            "render"
            | "annotation_render"
            | "weak_render"
            | "probable_runtime_render"
            | "probable_static_render"
            | "mixed_exact_probable_render"
            | "exact_static_render"
            | "probable_with_selector"
            | "shared_render_different_caller"
            | "conflicting_render"
            | "different_column" => {
                prev.source.as_mut().unwrap().render = Some(site(10, 2));
                cur.source.as_mut().unwrap().render = Some(site(
                    if evidence == "conflicting_render" {
                        20
                    } else {
                        10
                    },
                    if evidence == "different_column" { 9 } else { 2 },
                ));
                if evidence == "weak_render" {
                    prev.source.as_mut().unwrap().confidence = "guess".into();
                    cur.source.as_mut().unwrap().confidence = "guess".into();
                }
                if matches!(
                    evidence,
                    "probable_runtime_render" | "probable_static_render" | "probable_with_selector"
                ) {
                    prev.source.as_mut().unwrap().confidence = "probable".into();
                    cur.source.as_mut().unwrap().confidence = "probable".into();
                }
                if evidence == "mixed_exact_probable_render" {
                    cur.source.as_mut().unwrap().confidence = "probable".into();
                }
                if matches!(evidence, "probable_static_render" | "exact_static_render") {
                    prev.source.as_mut().unwrap().method = "static".into();
                    cur.source.as_mut().unwrap().method = "static".into();
                }
                if evidence == "annotation_render" {
                    prev.source.as_mut().unwrap().method = "annotation".into();
                    cur.source.as_mut().unwrap().method = "annotation".into();
                }
                if evidence == "probable_with_selector" {
                    cur.selector = prev.selector.clone();
                }
                if evidence == "shared_render_different_caller" {
                    cur.source.as_mut().unwrap().caller = Some(site(2, 1));
                }
                if matches!(
                    evidence,
                    "probable_runtime_render"
                        | "probable_static_render"
                        | "mixed_exact_probable_render"
                        | "exact_static_render"
                        | "shared_render_different_caller"
                ) {
                    cur.outcomes = calls("POST /api/other-operation");
                }
                if evidence == "conflicting_render" {
                    // Contradictory render sites override these weaker anchors.
                    cur.selector = prev.selector.clone();
                    prev.href = Some("/pay".into());
                    cur.href = prev.href.clone();
                }
            }
            "handler" => {
                prev.source.as_mut().unwrap().handler = Some(site(12, 3));
                cur.source.as_mut().unwrap().handler = Some(site(12, 3));
                cur.selector = prev.selector.clone();
            }
            "caller_with_selector" => cur.selector = prev.selector.clone(),
            "caller_only" => {}
            _ => unreachable!(),
        }
        let changes = diff(
            Some(&inv_with(vec![prev], &["/"], &[], "before")),
            &inv_with(vec![cur], &["/"], &[], "after"),
        );
        assert_eq!(
            changes.summary.get("relabeled").copied().unwrap_or(0),
            u32::from(matches!(
                evidence,
                "render"
                    | "annotation_render"
                    | "handler"
                    | "caller_with_selector"
                    | "probable_with_selector"
            )),
            "{evidence}"
        );
    }
}

#[test]
fn relabel_does_not_pick_the_first_ambiguous_text_counterpart() {
    let control = |label: &str| {
        let mut c = ctl(
            "/",
            &format!("text={label}"),
            label,
            ControlStatus::Ok,
            vec![],
        );
        c.source = Some(ResolvedSource {
            render: Some(FileLine {
                file: "src/Action.tsx".into(),
                line: 10,
                col: 2,
            }),
            method: "runtime".into(),
            confidence: "exact".into(),
            ..Default::default()
        });
        c
    };
    for (before, after) in [
        (vec!["Old A", "Old B"], vec!["New"]),
        (vec!["Old"], vec!["New A", "New B"]),
    ] {
        let prev = inv_with(
            before.into_iter().map(control).collect(),
            &["/"],
            &[],
            "before",
        );
        let cur = inv_with(
            after.into_iter().map(control).collect(),
            &["/"],
            &[],
            "after",
        );
        assert!(!diff(Some(&prev), &cur).summary.contains_key("relabeled"));
    }
}

#[test]
fn relabels_ignore_data_and_known_state_flips() {
    let toggle =
        |route: &str, label: &str| ctl(route, "testid=theme", label, ControlStatus::Ok, vec![]);
    let row = |label: &str| ctl("/", "id=row", label, ControlStatus::Ok, vec![]);
    let prev = inv_with(
        vec![
            toggle("/a", "Switch to dark mode"),
            toggle("/b", "Switch to light mode"),
            row("IS-PV198 Expected 9:29 PM"),
            ctl("/", "id=cta", "Buy", ControlStatus::Ok, vec![]),
        ],
        &["/", "/a", "/b"],
        &[],
        "2026-10-20T00:00:00Z",
    );
    let cur = inv_with(
        vec![
            toggle("/a", "Switch to light mode"),
            toggle("/b", "Switch to light mode"),
            row("IS-PV198 Expected 10:36 PM"),
            ctl("/", "id=cta", "Purchase", ControlStatus::Ok, vec![]),
        ],
        &["/", "/a", "/b"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    assert_eq!(
        lines(&diff(Some(&prev), &cur)),
        vec!["RELABELED / button \"Buy\" -> \"Purchase\""]
    );
}

#[test]
fn status_changes_need_both_maps_to_have_exercised_the_control() {
    let c = |id: &str, status| ctl("/", &format!("id={id}"), id, status, vec![]);
    let prev = inv_with(
        vec![
            c("a", ControlStatus::NotExercised),
            c("b", ControlStatus::Dead),
            c("c", ControlStatus::Ok),
            c("d", ControlStatus::Broken),
        ],
        &["/"],
        &[],
        "2026-10-20T00:00:00Z",
    );
    let mut ok_b = c("b", ControlStatus::Ok);
    ok_b.outcomes = vec![Outcome::DomChange {
        kind: "panel".into(),
    }];
    let mut no_effect = c("c", ControlStatus::NoEffect);
    no_effect.reason = Some("handler attached".into());
    let cur = inv_with(
        vec![
            c("a", ControlStatus::Dead),
            ok_b,
            no_effect,
            c("d", ControlStatus::NotExercised),
        ],
        &["/"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    let cs = diff(Some(&prev), &cur);
    assert_eq!(
        lines(&cs),
        vec![
            "NOW NO EFFECT / button \"c\": no visible effect (handler attached) (was ok)",
            "FIXED / button \"b\": opens panel (was dead)",
        ]
    );
    assert!(
        cs.notes
            .iter()
            .any(|n| n.contains("status unknown, not fixed"))
    );
}

#[test]
fn group_splits_are_rewires_and_counts_are_reported() {
    let link = |route: &str, key_suffix: &str, label: &str, to: &str, count: u32| {
        let mut c = ctl(
            route,
            "text=get started",
            label,
            ControlStatus::Ok,
            vec![Outcome::Navigates { to: to.into() }],
        );
        c.role = "link".into();
        c.key = format!("{route}|link|text=get started{key_suffix}");
        c.target = Some(to.into());
        c.count = count;
        c
    };
    let mut cta = ctl("/", "text=request", "Request", ControlStatus::Ok, vec![]);
    cta.count = 2;
    let prev = inv_with(
        vec![link("/", "", "Get started", "/invitation", 2), cta.clone()],
        &["/"],
        &[],
        "2026-10-20T00:00:00Z",
    );
    let mut cta1 = cta;
    cta1.count = 1;
    let cur = inv_with(
        vec![
            link("/", "->/invitation", "Get started", "/invitation", 1),
            link("/", "->/sign-in", "GET STARTED", "/sign-in", 1),
            cta1,
        ],
        &["/"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    assert_eq!(
        lines(&diff(Some(&prev), &cur)),
        vec![
            "REWIRED / link \"GET STARTED\": → /sign-in (was → /invitation; 1 of 2)",
            "COUNT CHANGED / button \"Request\": x2 -> x1",
        ]
    );
}

#[test]
fn identical_changes_on_many_routes_are_one_line() {
    let toggle = |route: &str, status| {
        let mut c = ctl(route, "testid=theme", "Switch to dark mode", status, vec![]);
        if status == ControlStatus::Ok {
            c.outcomes = vec![Outcome::DomChange {
                kind: "other".into(),
            }];
        } else {
            c.reason = Some("handler attached".into());
        }
        c
    };
    let rs = ["/a", "/b", "/c", "/d", "/e"];
    let prev = inv_with(
        rs.iter().map(|r| toggle(r, ControlStatus::Ok)).collect(),
        &rs,
        &[],
        "2026-10-20T00:00:00Z",
    );
    let cur = inv_with(
        rs.iter()
            .map(|r| toggle(r, ControlStatus::NoEffect))
            .collect(),
        &rs,
        &[],
        "2026-10-21T00:00:00Z",
    );
    let cs = diff(Some(&prev), &cur);
    assert_eq!(
        lines(&cs),
        vec![
            "NOW NO EFFECT /a, /b, /c +2 more button \"Switch to dark mode\": no visible effect (handler attached) (was updates page)"
        ]
    );
    assert_eq!(cs.changes[0].routes, rs);
}

#[test]
fn a_page_that_lost_its_content_is_one_line() {
    let ids = ["a", "b", "c", "d", "e", "f"];
    let mk = |id: &str| {
        ctl(
            "/receiving",
            &format!("id={id}"),
            id,
            ControlStatus::Ok,
            vec![],
        )
    };
    let prev = inv_with(
        ids.iter().map(|i| mk(i)).collect(),
        &["/receiving"],
        &[],
        "2026-10-20T00:00:00Z",
    );
    let cur = inv_with(vec![mk("a")], &["/receiving"], &[], "2026-10-21T00:00:00Z");
    let cs = diff(Some(&prev), &cur);
    assert_eq!(cs.changes.len(), 1, "{:?}", lines(&cs));
    assert!(
        cs.changes[0]
            .line
            .starts_with("ROUTE CONTENT MISSING /receiving: 1 of 6 controls seen"),
        "{}",
        cs.changes[0].line
    );
}

#[test]
fn maps_from_another_identity_scheme_are_rebaselined() {
    let mut prev = inv_with(
        vec![ctl("/", "href=/cart", "Cart", ControlStatus::Ok, vec![])],
        &["/"],
        &[],
        "2026-10-20T00:00:00Z",
    );
    prev.identity_version = 0;
    let mut cur = inv_with(
        vec![ctl("/", "text=cart", "Cart", ControlStatus::Ok, vec![])],
        &["/"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    cur.identity_version = IDENTITY_VERSION;
    let cs = diff(Some(&prev), &cur);
    assert_eq!(cs.changes.len(), 1);
    assert_eq!(cs.changes[0].kind, "rebaselined");
}

// ---------------------------------------------------------------------------
// 7. Coverage reporting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabled_snapshot_does_not_hide_recorded_operational_gaps() {
    for reason in [
        "form_state_recovery_interaction_limit",
        "form_state_recovery_time_budget",
        "form_state_recovery_target_changed",
        "interaction_limit",
        "view_time_budget",
        "state_lost",
    ] {
        let mut open = el(
            "button.button.primary",
            "Open practice collection",
            button(),
            &[],
        );
        open["disabled"] = json!(true);
        let back = el("#back", "Back", button(), &[("id", "#back")]);
        let mut skipped = rec(
            "nested",
            "/",
            "button.button.primary",
            "button",
            InteractionOutcome::Skipped,
        );
        skipped.skipped_reason = Some(reason.into());
        let exercised = rec(
            "nested",
            "/",
            "#back",
            "button",
            InteractionOutcome::DomChange,
        );
        let inv = build_scan(
            vec![view("nested", "/", vec![open, back])],
            &[exercised, skipped],
            &[],
            &["/"],
        )
        .await;
        let open = find(&inv, "/|button|text=open practice collection");
        assert_eq!(open.status, ControlStatus::NotExercised, "{reason}");
        assert_eq!(open.reason.as_deref(), Some(reason));
        assert_eq!(inv.coverage.controls_exercised, 1);
        assert_eq!(inv.coverage.controls_exercisable, 2);
        assert_eq!(inv.coverage.controls_disabled, 0);
        assert_eq!(inv.coverage.not_exercised_by_reason.get(reason), Some(&1));
    }
}

#[tokio::test]
async fn disabled_snapshot_preserves_disabled_and_successful_evidence() {
    for (reason, exercised, expected) in [
        (None, false, ControlStatus::Disabled),
        (Some("disabled"), false, ControlStatus::Disabled),
        (Some("dangerous_label"), false, ControlStatus::Skipped),
        (None, true, ControlStatus::Ok),
        (Some("disabled"), true, ControlStatus::Ok),
        (
            Some("form_state_recovery_interaction_limit"),
            true,
            ControlStatus::Ok,
        ),
    ] {
        let mut open = el("#open", "Open collection", button(), &[("id", "#open")]);
        open["disabled"] = json!(true);
        let mut records = Vec::new();
        if exercised {
            records.push(rec(
                "nested",
                "/",
                "#open",
                "button",
                InteractionOutcome::DomChange,
            ));
        }
        if let Some(reason) = reason {
            let mut skipped = rec(
                "nested",
                "/",
                "#open",
                "button",
                InteractionOutcome::Skipped,
            );
            skipped.skipped_reason = Some(reason.into());
            records.push(skipped);
        }
        let inv = build_scan(vec![view("nested", "/", vec![open])], &records, &[], &["/"]).await;
        let open = find(&inv, "/|button|id=open");
        assert_eq!(open.status, expected, "{reason:?}, exercised={exercised}");
        assert_eq!(inv.coverage.controls_exercisable, u32::from(exercised));
        assert_eq!(inv.coverage.controls_exercised, u32::from(exercised));
        if !exercised {
            assert_eq!(open.reason.as_deref(), Some(reason.unwrap_or("disabled")));
        }
    }
}

#[tokio::test]
async fn coverage_counts_exercisable_controls_and_groups_unvisited_routes() {
    let dir = tempfile::tempdir().unwrap();
    let s = spec(vec![view(
        "view_0001",
        "/",
        vec![
            el("#go", "Go", button(), &[("id", "#go")]),
            el("#q", "Search", text_input(), &[("id", "#q")]),
            el(
                "#gh",
                "GitHub",
                link("https://github.com/x"),
                &[("id", "#gh")],
            ),
        ],
    )]);
    let mut go = rec(
        "view_0001",
        "/",
        "#go",
        "button",
        InteractionOutcome::NoEffect,
    );
    go.already_active = true;
    write_scan(dir.path(), &s, Some(&[go]), &[]);
    std::fs::write(
        dir.path().join("checkpoint.json"),
        json!({"bugs": [{"description": format!(
            "Failed to navigate to {BASE}/slow: Page.navigate timed out after 20000ms"
        )}]})
        .to_string(),
    )
    .unwrap();
    let mut o = opts();
    o.discovered_routes = routes(&["/", "/slow", "/orphan"]);
    let inv = build(dir.path(), &o).await;
    let c = &inv.coverage;
    assert_eq!(
        (
            c.controls_total,
            c.controls_exercisable,
            c.controls_external
        ),
        (3, 2, 1)
    );
    assert_eq!(
        c.unvisited_by_reason.get("navigation timeout"),
        Some(&vec!["/slow".to_string()])
    );
    assert_eq!(
        c.unvisited_by_reason.get("not linked or seeded"),
        Some(&vec!["/orphan".to_string()])
    );
    assert_eq!(
        render::coverage_line(&inv),
        "1/2 exercisable controls exercised (+1 external not counted); 1/3 known routes visited"
    );
    let md = render::render_ui_map(&inv);
    assert!(
        md.contains("- Not visited: 1 navigation timeout: /slow"),
        "{md}"
    );
    let dead = render::render_dead_ui(&inv);
    assert!(
        dead.contains("Routes never visited: 1 navigation timeout: /slow"),
        "{dead}"
    );
}

// ---------------------------------------------------------------------------
// 8. Journey explanations
// ---------------------------------------------------------------------------

#[test]
fn unmatched_journeys_explain_what_was_not_observed() {
    let mut submit = ctl("/lab", "id=research", "Research", ControlStatus::Ok, vec![]);
    submit.reason = Some("validation_blocked".into());
    let mut inv = inv_with(
        vec![
            submit,
            ctl("/about", "id=x", "X", ControlStatus::NotExercised, vec![]),
        ],
        &["/lab", "/about"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    inv.routes.push(RouteEntry {
        route: "/".into(),
        ..Default::default()
    });
    let goal = journey::parse_goal("POST /api/research", &inv);
    let res = journey::journey(&inv, &goal, None, 6);
    assert!(res.matched.is_empty());
    let text = res.notes.join("\n");
    assert!(text.contains("Start route / was not visited"), "{text}");
    assert!(text.contains("the endpoint was never observed"), "{text}");
    assert!(
        text.contains("1 form submit stopped at empty required fields"),
        "{text}"
    );
    assert!(text.contains("1 control was not exercised"), "{text}");
    let out = journey::render_text(&res, 6);
    assert!(out.contains("Coverage:"), "{out}");
}

#[test]
fn journey_prefers_the_exact_static_route() {
    let to = |route: &str, label: &str, target: &str| {
        let mut c = ctl(
            route,
            &format!("text={}", label.to_lowercase()),
            label,
            ControlStatus::Ok,
            vec![Outcome::Navigates { to: target.into() }],
        );
        c.role = "link".into();
        c
    };
    let inv = inv_with(
        vec![to("/", "Lab", "/lab"), to("/", "Activity", "/:view")],
        &["/", "/lab", "/:view"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    let goal = journey::parse_goal("/lab", &inv);
    let res = journey::journey(&inv, &goal, None, 6);
    assert_eq!(res.matched, vec!["/lab"]);
    assert_eq!(res.direct.len(), 1);
}

#[test]
fn static_endpoint_references_are_found() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/workspace.tsx"),
        "const x = 1;\nawait fetch(\"/api/research\", { method: \"POST\" });\n",
    )
    .unwrap();
    let hits =
        crate::code_link::find_endpoint_references(dir.path(), Some("POST"), "/api/research", 5)
            .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(
        (hits[0].file.as_str(), hits[0].line),
        ("src/workspace.tsx", 2)
    );
    let none = crate::code_link::find_endpoint_references(Path::new("/nonexistent"), None, "/", 5)
        .unwrap();
    assert!(none.is_empty());
}

#[test]
fn archived_route_queries_keep_literal_ids_and_static_priority() {
    use super::identity::{query_route_parts, route_matches, select_routes};
    let order = "/selling/10000000-0000-4000-8000-000000000201";
    let routes = ["/selling/review", "/selling/:orderId"];
    for concrete in [order, "/selling/42"] {
        assert!(!route_matches("/selling/review", concrete));
        assert_eq!(select_routes(routes, concrete), vec!["/selling/:orderId"]);
    }
    assert_eq!(
        select_routes(routes, "/selling/review"),
        vec!["/selling/review"]
    );
    for template in ["/selling/:orderId", "/selling/:id"] {
        assert_eq!(select_routes(routes, template), vec!["/selling/:orderId"]);
    }
    assert_eq!(select_routes(["/404", "/:id"], "/404"), vec!["/404"]);
    assert_eq!(
        query_route_parts("https://example.test/#!/orders/42?b=2&a=1"),
        ("/#!/orders/42".into(), Some("?a=1&b=2".into()))
    );
    assert!(route_matches("/#!/orders/:id", "/#!/orders/42"));
    assert!(route_matches(
        "/#/orders/:id",
        "https://example.test/#/orders/42"
    ));
    assert!(!route_matches("/#!/orders/review", "/#!/orders/42"));
    assert_ne!(
        query_route_parts("/account?tab=payout&tab=payments"),
        query_route_parts("/account?tab=payments&tab=payout")
    );
    assert_ne!(
        query_route_parts("/account?a=x%26b%3Dy"),
        query_route_parts("/account?a=x&b=y")
    );
    assert_ne!(
        query_route_parts("/account?tab=payout&tab=payments"),
        query_route_parts("/account?tab=payout")
    );
}

#[test]
fn archived_ui_route_selection_keeps_prefixes_and_global_scope() {
    let mut global = ctl("*", "id=global", "Global", ControlStatus::Ok, vec![]);
    global.routes = vec!["/selling/review".into()];
    let inv = inv_with(
        vec![
            global,
            ctl(
                "/selling/review",
                "id=review",
                "Review",
                ControlStatus::Ok,
                vec![],
            ),
            ctl(
                "/selling/:orderId",
                "id=order",
                "Order",
                ControlStatus::Ok,
                vec![],
            ),
            ctl("/admin", "id=admin", "Admin", ControlStatus::Ok, vec![]),
            ctl(
                "/admin/users",
                "id=users",
                "Users",
                ControlStatus::Ok,
                vec![],
            ),
            ctl(
                "/administrator",
                "id=other",
                "Other",
                ControlStatus::Ok,
                vec![],
            ),
        ],
        &[
            "/selling/review",
            "/selling/:orderId",
            "/admin",
            "/admin/users",
            "/administrator",
        ],
        &[],
        "2026-10-22T00:00:00Z",
    );
    let labels = |route: &str| {
        query::ControlFilter {
            route: Some(route.into()),
            ..Default::default()
        }
        .apply(&inv)
        .iter()
        .map(|c| c.label.as_str())
        .collect::<Vec<_>>()
    };
    assert_eq!(labels("/selling/review"), vec!["Global", "Review"]);
    assert_eq!(labels("/selling/:orderId"), vec!["Order"]);
    assert_eq!(labels("/selling/:id"), vec!["Order"]);
    assert_eq!(labels("/admin/"), vec!["Admin", "Users"]);
    assert_eq!(labels("/selling"), vec!["Global", "Review", "Order"]);
    assert_eq!(labels("*"), vec!["Global"]);
    let compatibility = query::ControlFilter {
        route: Some("/admin".into()),
        ..Default::default()
    };
    assert!(compatibility.matches(&inv.controls[4]));
    assert!(!compatibility.matches(&inv.controls[5]));
}

#[test]
fn archived_ui_variants_require_the_requested_observed_state() {
    let mut payout = ctl("/account", "id=payout", "Payout", ControlStatus::Ok, vec![]);
    payout.variants = vec!["?tab=payout".into()];
    let mut payments = ctl(
        "/account",
        "id=payments",
        "Payments",
        ControlStatus::Ok,
        vec![],
    );
    payments.variants = vec!["?tab=payments".into()];
    let shared = ctl("/account", "id=shared", "Shared", ControlStatus::Ok, vec![]);
    let mut global = ctl("*", "id=global", "Global", ControlStatus::Ok, vec![]);
    global.routes = vec!["/account".into(), "/orders/:id".into()];
    let mut order_a = ctl("/orders/:id", "id=a", "Order A", ControlStatus::Ok, vec![]);
    order_a.variants = vec!["/orders/42?tab=shipping&view=all".into()];
    let mut order_b = ctl("/orders/:id", "id=b", "Order B", ControlStatus::Ok, vec![]);
    order_b.variants = vec!["/orders/43".into()];
    let mut inv = inv_with(
        vec![payout, payments, shared, global, order_a, order_b],
        &["/account", "/orders/:id"],
        &[],
        "2026-10-22T00:00:00Z",
    );
    inv.routes
        .iter_mut()
        .find(|r| r.route == "/account")
        .unwrap()
        .variants = vec!["?tab=payout".into(), "?tab=payments".into()];
    inv.routes
        .iter_mut()
        .find(|r| r.route == "/orders/:id")
        .unwrap()
        .variants = vec![
        "/orders/42?tab=shipping&view=all".into(),
        "/orders/43".into(),
    ];
    let labels = |route: &str| {
        query::ControlFilter {
            route: Some(route.into()),
            ..Default::default()
        }
        .apply(&inv)
        .iter()
        .map(|c| c.label.as_str())
        .collect::<Vec<_>>()
    };
    assert_eq!(
        labels("/account?tab=payout"),
        vec!["Payout", "Shared", "Global"]
    );
    assert_eq!(
        labels("/account?tab=payments"),
        vec!["Payments", "Shared", "Global"]
    );
    assert!(labels("/account?tab=unknown").is_empty());
    assert_eq!(
        labels("/orders/42?view=all&tab=shipping"),
        vec!["Global", "Order A"]
    );
    assert_eq!(labels("/orders/43"), vec!["Global", "Order B"]);
    assert!(labels("/orders/44").is_empty());
    assert_eq!(labels("/account").len(), 4);
    assert_eq!(labels("/orders/:id").len(), 3);
}

#[test]
fn archived_journey_requires_exact_record_or_query_navigation_evidence() {
    let go = |label: &str, target: &str| {
        ctl(
            "/",
            &format!("id={label}"),
            label,
            ControlStatus::Ok,
            vec![Outcome::Navigates { to: target.into() }],
        )
    };
    let mut inv = inv_with(
        vec![
            go("Review", "/selling/review"),
            go("Order", "/selling/:orderId"),
            go("Payout", "/account"),
        ],
        &["/", "/selling/review", "/selling/:orderId", "/account"],
        &[],
        "2026-10-22T00:00:00Z",
    );
    let record = "/selling/10000000-0000-4000-8000-000000000201";
    inv.routes
        .iter_mut()
        .find(|r| r.route == "/selling/:orderId")
        .unwrap()
        .variants = vec![record.into()];
    inv.routes
        .iter_mut()
        .find(|r| r.route == "/account")
        .unwrap()
        .variants = vec!["?tab=payments".into()];
    for (goal, context) in [
        (record, "/selling/:orderId"),
        ("/account?tab=payments", "/account"),
    ] {
        let result = journey::journey(&inv, &journey::parse_goal(goal, &inv), Some("/"), 6);
        assert_eq!(result.matched, vec![context]);
        assert!(!result.reachable);
        assert_eq!(result.distance, None);
        assert!(result.paths.is_empty() && result.direct.is_empty());
        assert!(
            result
                .notes
                .join(" ")
                .contains("observed as a page variant")
        );
        assert!(result.notes.join(" ").contains("reachability is unknown"));
        let text = journey::render_text(&result, 6);
        assert!(text.contains("reachability is unknown"));
        assert!(text.contains("No direct navigation to this destination was recorded."));
        assert!(text.contains("No path from / within 6 hops is established by this map."));
        assert!(!text.contains("Not reachable"));
        assert!(!text.contains("No control leads here"));
    }
    for goal in ["/selling/review", "/selling/:orderId", "/account"] {
        let result = journey::journey(&inv, &journey::parse_goal(goal, &inv), Some("/"), 6);
        assert!(result.reachable);
        assert_eq!(result.distance, Some(1));
        assert_eq!(result.direct.len(), 1);
    }
    // Exact observed targets are evidence; neither other records nor tabs are.
    inv.controls.push(go("Exact order", record));
    inv.controls
        .push(go("Exact payments", "/account?view=all&tab=payments"));
    for goal in [record, "/account?tab=payments&view=all"] {
        let result = journey::journey(&inv, &journey::parse_goal(goal, &inv), Some("/"), 6);
        assert!(result.reachable);
        assert_eq!(result.distance, Some(1));
        assert_eq!(result.direct.len(), 1);
        assert_eq!(result.paths.len(), 1);
    }
    let other = journey::journey(
        &inv,
        &journey::parse_goal("/account?tab=payout", &inv),
        Some("/"),
        6,
    );
    assert!(!other.reachable && other.direct.is_empty());
}

#[test]
fn archived_journey_does_not_collapse_a_specific_start_state() {
    let finish = ctl(
        "/account",
        "id=finish",
        "Finish",
        ControlStatus::Ok,
        vec![Outcome::Navigates { to: "/done".into() }],
    );
    let order_finish = ctl(
        "/orders/:id",
        "id=finish",
        "Finish",
        ControlStatus::Ok,
        vec![Outcome::Navigates { to: "/done".into() }],
    );
    let inv = inv_with(
        vec![finish, order_finish],
        &["/account", "/orders/:id", "/done"],
        &[],
        "2026-10-22T00:00:00Z",
    );
    let goal = journey::parse_goal("/done", &inv);
    for from in ["/account?tab=payout", "/orders/42"] {
        let result = journey::journey(&inv, &goal, Some(from), 6);
        assert_eq!(result.from, from);
        assert!(!result.reachable);
        assert_eq!(result.distance, None);
        assert!(result.paths.is_empty());
        assert!(
            result
                .notes
                .join(" ")
                .contains("shortest paths are unknown")
        );
    }
    for from in ["/account", "/orders/:id"] {
        assert!(journey::journey(&inv, &goal, Some(from), 6).reachable);
    }
}

#[test]
fn focus_only_rendering_does_not_claim_tested_input() {
    let mut input = ctl("/", "id=input", "Input", ControlStatus::Ok, vec![]);
    input.reason = Some("focus_only".into());
    for text in [
        render::tsv_row(&input),
        render::md_table_with_route(&[&input]),
    ] {
        assert!(text.contains("focus only (input not tested)"));
        assert!(!text.contains("accepts input"));
    }
    assert_eq!(input.status, ControlStatus::Ok);
}

#[tokio::test]
async fn guarded_fetch_errors_require_exact_action_and_preserve_real_failures() {
    for scenario in [
        "console",
        "injected_stack",
        "application_stack",
        "top_level",
        "no_id",
        "different_id",
        "stubbed",
        "http_failure",
        "network_failure",
        "unrelated_error",
        "similar_message",
        "another_action",
    ] {
        let mut action = rec("v", "/", "#save", "button", InteractionOutcome::NoEffect);
        action.label = Some("Save".into());
        action.action_id = Some("save-1".into());
        action.console_errors = vec!["TypeError: Failed to fetch".into()];
        if scenario == "injected_stack" {
            action.console_errors =
                vec!["TypeError: Failed to fetch @ at w.fetch (<anonymous>:260:34)".into()];
        }
        if scenario == "application_stack" {
            action.console_errors = vec![
                "TypeError: Failed to fetch @ at onClick (http://app.local/page.js:260:34)".into(),
            ];
        }
        if scenario == "top_level" {
            action.console_errors.clear();
            action.outcome = InteractionOutcome::Error;
            action.error = Some("TypeError: Failed to fetch".into());
        }
        if scenario == "no_id" {
            action.action_id = None;
        }
        if scenario == "unrelated_error" {
            action
                .console_errors
                .push("ReferenceError: missing is not defined".into());
        }
        if scenario == "similar_message" {
            action.console_errors = vec!["TypeError: Failed to fetch configuration".into()];
        }
        let mut blocked = row(
            "POST",
            "/api/save",
            None,
            Some(("v", "#save")),
            Some("save-1"),
        );
        blocked["write_guard"] = json!(if scenario == "stubbed" {
            "stubbed"
        } else {
            "blocked"
        });
        blocked["failure"] = json!("net::ERR_BLOCKED_BY_CLIENT");
        if scenario == "different_id" {
            blocked["trace"]["action_id"] = json!("unrelated-1");
        }
        let mut rows = vec![blocked];
        if scenario == "http_failure" {
            rows.push(row(
                "GET",
                "/api/real",
                Some(500),
                Some(("v", "#save")),
                Some("save-1"),
            ));
        }
        if scenario == "network_failure" {
            let mut failure = row(
                "GET",
                "/api/real",
                None,
                Some(("v", "#save")),
                Some("save-1"),
            );
            failure["failure"] = json!("net::ERR_CONNECTION_REFUSED");
            rows.push(failure);
        }
        let mut records = vec![action];
        if scenario == "another_action" {
            let mut real_error = records[0].clone();
            real_error.action_id = Some("save-2".into());
            records.push(real_error);
        }
        let inv = build_scan(
            vec![view("v", "/", vec![el("#save", "Save", button(), &[])])],
            &records,
            &rows,
            &["/"],
        )
        .await;
        let save = find(&inv, "/|button|id=save");
        let expected = if matches!(scenario, "console" | "top_level" | "injected_stack") {
            ControlStatus::Ok
        } else {
            ControlStatus::Broken
        };
        assert_eq!(save.status, expected, "{scenario}: {save:?}");
        if expected == ControlStatus::Ok {
            assert!(
                save.outcomes
                    .iter()
                    .any(|outcome| matches!(outcome, Outcome::Calls { blocked: true, .. }))
            );
            assert!(
                !save
                    .outcomes
                    .iter()
                    .any(|outcome| matches!(outcome, Outcome::Error { .. }))
            );
        }
    }
}

#[tokio::test]
async fn csp_telemetry_cannot_promote_no_effect_controls_but_app_writes_remain() {
    for (url, telemetry) in [
        (
            "https://csp.withgoogle.com/csp/frame-ancestors/synthetic",
            true,
        ),
        ("https://reports.csp.withgoogle.com/csp/report", true),
        ("https://CSP.WITHGOOGLE.COM/csp/report", true),
        ("https://csp.withgoogle.com.example.test/csp/report", false),
        ("https://othercsp.withgoogle.com/csp/report", false),
        ("https://withgoogle.com/api/orders", false),
        ("/api/orders", false),
    ] {
        for guard in ["blocked", "stubbed", "allowed"] {
            for handler in [false, true] {
                let mut element = el("#about", "About", button(), &[]);
                if handler {
                    element["source"] = json!({"frames": [], "handlers": ["onClick"]});
                }
                let action = rec("v", "/", "#about", "button", InteractionOutcome::NoEffect);
                let mut report = row(
                    "POST",
                    "/api/orders",
                    (guard == "allowed").then_some(204),
                    Some(("v", "#about")),
                    action.action_id.as_deref(),
                );
                report["request"]["url"] = json!(if url.starts_with('/') {
                    format!("{BASE}{url}")
                } else {
                    url.to_string()
                });
                report["request"]["headers"]["Content-Type"] = json!("application/csp-report");
                report["write_guard"] = json!(guard);
                // Guarded requests are calls even when is_api is false. The
                // telemetry boundary must precede that promotion; request MIME
                // alone must not discard real app writes or lookalike hosts.
                report["is_api"] = json!(guard == "allowed");
                let inv = build_scan(
                    vec![view("v", "/", vec![element])],
                    &[action],
                    &[report],
                    &["/"],
                )
                .await;
                let about = find(&inv, "/|button|id=about");
                let expected = if !telemetry {
                    ControlStatus::Ok
                } else if handler {
                    ControlStatus::NoEffect
                } else {
                    ControlStatus::Dead
                };
                assert_eq!(
                    about.status, expected,
                    "{url} {guard} handler={handler}: {about:?}"
                );
                assert_eq!(
                    about.endpoints().count(),
                    usize::from(!telemetry),
                    "{url} {guard}"
                );
                assert_eq!(
                    inv.endpoints.len(),
                    usize::from(!telemetry),
                    "{url} {guard}"
                );
                assert!(about.outcomes.iter().all(|outcome| !matches!(outcome,
                    Outcome::Calls { blocked, .. } if *blocked != (guard != "allowed"))));
            }
        }
    }
}

#[tokio::test]
async fn ancillary_guarded_requests_do_not_explain_an_application_fetch_error() {
    for scenario in [
        "diagnostic_only",
        "diagnostic_top_level_error",
        "diagnostic_and_failed_signup",
        "diagnostic_and_canceled_prefetch",
        "diagnostic_and_blocked_signup",
        "diagnostic_and_blocked_server_action",
        "telemetry_only",
        "csp_telemetry_only",
        "csp_and_blocked_signup",
        "invalid_url_only",
        "options_only",
    ] {
        let mut action = rec(
            "signup",
            "/sign-up",
            "#signup",
            "button",
            InteractionOutcome::DomChange,
        );
        action.label = Some("Create Account".into());
        action.action_id = Some("signup-1".into());
        action.dom_change = Some("toast".into());
        let error = "TypeError: Failed to fetch @ at w.fetch (<anonymous>:260:34)";
        action.console_errors = vec![error.into()];
        if scenario == "diagnostic_top_level_error" {
            action.outcome = InteractionOutcome::Error;
            action.console_errors.clear();
            action.error = Some(error.into());
        }
        // Gym's one-tab trace captured only this exact-action diagnostic POST,
        // not the signup operation. Its error must remain even without a
        // separately captured failed request.
        let mut diagnostic = row(
            "POST",
            "/__nextjs_original-stack-frames",
            None,
            Some(("signup", "#signup")),
            Some("signup-1"),
        );
        diagnostic["write_guard"] = json!("blocked");
        match scenario {
            "telemetry_only" => {
                diagnostic["request"]["url"] =
                    json!("https://synthetic.ingest.sentry.io/api/1/envelope/");
            }
            "csp_telemetry_only" | "csp_and_blocked_signup" => {
                diagnostic["request"]["url"] =
                    json!("https://csp.withgoogle.com/csp/frame-ancestors/synthetic");
                diagnostic["request"]["headers"]["content-type"] = json!("application/csp-report");
            }
            "invalid_url_only" => diagnostic["request"]["url"] = json!("not a URL"),
            "options_only" => {
                diagnostic["request"]["method"] = json!("OPTIONS");
                diagnostic["request"]["url"] = json!(format!("{BASE}/auth/v1/signup"));
            }
            _ => {}
        }
        let mut rows = vec![diagnostic];
        if scenario == "diagnostic_and_failed_signup" {
            for method in ["OPTIONS", "POST"] {
                let mut failure = row(
                    method,
                    "/auth/v1/signup",
                    None,
                    Some(("signup", "#signup")),
                    Some("signup-1"),
                );
                failure["request"]["url"] = json!("http://127.0.0.1:58321/auth/v1/signup");
                failure["failure"] = json!("net::ERR_CONNECTION_REFUSED");
                rows.push(failure);
            }
        }
        if scenario == "diagnostic_and_canceled_prefetch" {
            let mut prefetch = row(
                "GET",
                "/staff?_rsc=synthetic",
                Some(200),
                Some(("signup", "#signup")),
                Some("signup-1"),
            );
            prefetch["failure"] = json!("net::ERR_ABORTED");
            prefetch["is_api"] = json!(false);
            prefetch["request"]["headers"]["next-router-prefetch"] = json!("1");
            rows.push(prefetch);
        }
        let genuine_block = matches!(
            scenario,
            "diagnostic_and_blocked_signup"
                | "diagnostic_and_blocked_server_action"
                | "csp_and_blocked_signup"
        );
        if genuine_block {
            let server_action = scenario == "diagnostic_and_blocked_server_action";
            let mut operation = row(
                "POST",
                if server_action {
                    "/sign-up"
                } else {
                    "/auth/v1/signup"
                },
                None,
                Some(("signup", "#signup")),
                Some("signup-1"),
            );
            operation["write_guard"] = json!("blocked");
            if server_action {
                operation["request"]["headers"]["next-action"] = json!("synthetic-action");
            }
            rows.push(operation);
        }
        let inv = build_scan(
            vec![view(
                "signup",
                "/sign-up",
                vec![el("#signup", "Create Account", button(), &[])],
            )],
            &[action],
            &rows,
            &["/sign-up"],
        )
        .await;
        let signup = find(&inv, "/sign-up|button|id=signup");
        assert_eq!(
            signup.status,
            if genuine_block {
                ControlStatus::Ok
            } else {
                ControlStatus::Broken
            },
            "{scenario}: {signup:?}"
        );
        assert_eq!(
            signup.outcomes.iter().any(|outcome| matches!(outcome,
                Outcome::Error { message } if message == error)),
            !genuine_block,
            "{scenario}: incidental error reporting cannot prove the operation was blocked"
        );
        assert_eq!(
            signup
                .outcomes
                .iter()
                .any(|outcome| matches!(outcome, Outcome::Calls { blocked: true, .. })),
            genuine_block,
            "{scenario}: preserve real blocked calls, without promoting ancillary traffic"
        );
        assert!(signup.outcomes.iter().all(|outcome| !matches!(outcome,
            Outcome::Calls { endpoint, .. } if endpoint.contains("__nextjs") || endpoint.contains("sentry.io") || endpoint.contains("csp.withgoogle.com"))));
        if scenario == "diagnostic_and_failed_signup" {
            assert!(signup.outcomes.iter().any(|outcome| matches!(outcome,
                Outcome::Calls { endpoint, blocked: false, .. } if endpoint == "POST http://127.0.0.1:58321/auth/v1/signup")));
        }
        if scenario == "diagnostic_and_blocked_server_action" {
            assert!(signup.outcomes.iter().any(|outcome| matches!(outcome,
                Outcome::Calls { endpoint, blocked: true, .. } if endpoint == "POST /sign-up [server action]")));
        }
    }
}

#[tokio::test]
async fn guarded_fetch_with_canceled_prefetches_preserves_only_real_failures() {
    for (scenario, status, failure, prefetch_count, broken) in [
        (
            "aborted_prefetches",
            Some(200),
            "net::ERR_ABORTED",
            8,
            false,
        ),
        ("canceled_prefetch", Some(200), "canceled", 1, false),
        ("canceled_without_response", None, "canceled", 1, false),
        ("failed_get", None, "net::ERR_CONNECTION_REFUSED", 1, true),
        (
            "failed_after_headers",
            Some(200),
            "net::ERR_CONTENT_LENGTH_MISMATCH",
            1,
            true,
        ),
        ("http403_aborted", Some(403), "net::ERR_ABORTED", 1, true),
    ] {
        let mut action = rec(
            "inventory",
            "/staff/inventory",
            "#save-filters",
            "button",
            InteractionOutcome::DomChange,
        );
        action.label = Some("Save current filters".into());
        action.action_id = Some("save-filters-1".into());
        action.dom_change = Some("message".into());
        action.console_errors =
            vec!["TypeError: Failed to fetch @ at w.fetch (<anonymous>:260:34)".into()];
        let mut blocked = row(
            "POST",
            "/staff/inventory",
            None,
            Some(("inventory", "#save-filters")),
            Some("save-filters-1"),
        );
        blocked["write_guard"] = json!("blocked");
        blocked["request"]["headers"]["next-action"] = json!("synthetic-action");
        let mut rows = vec![blocked];
        for index in 0..prefetch_count {
            let mut prefetch = row(
                "GET",
                &format!("/staff/prefetch-{index}?_rsc=synthetic"),
                status,
                Some(("inventory", "#save-filters")),
                Some("save-filters-1"),
            );
            prefetch["trace"]["cdp_request_id"] = json!(format!("prefetch-{index}"));
            prefetch["is_api"] = json!(false);
            prefetch["request"]["headers"]["next-router-prefetch"] = json!("1");
            prefetch["request"]["headers"]["RSC"] = json!("1");
            if status.is_some() {
                prefetch["response"]["mime_type"] = json!("text/x-component");
            }
            prefetch["failure"] = json!(failure);
            rows.push(prefetch);
        }
        let inv = build_scan(
            vec![view(
                "inventory",
                "/staff/inventory",
                vec![el("#save-filters", "Save current filters", button(), &[])],
            )],
            &[action],
            &rows,
            &["/staff/inventory"],
        )
        .await;
        let save = find(&inv, "/staff/inventory|button|id=save-filters");
        assert_eq!(
            save.status,
            if broken {
                ControlStatus::Broken
            } else {
                ControlStatus::Ok
            },
            "{scenario}: {save:?}"
        );
        assert_eq!(
            inv.controls
                .iter()
                .filter(|c| c.status == ControlStatus::Broken)
                .count(),
            usize::from(broken),
            "{scenario}"
        );
        assert!(
            save.outcomes.iter().any(|outcome| matches!(
                outcome,
                Outcome::Calls { endpoint, blocked: true, .. }
                    if endpoint == "POST /staff/inventory [server action]"
            )),
            "{scenario}: the blocked write remains evidence, not a successful save"
        );
        assert_eq!(
            save.outcomes
                .iter()
                .any(|outcome| matches!(outcome, Outcome::Error { .. })),
            broken,
            "{scenario}: only canceled requests may leave the guard error suppressed"
        );
    }
}

#[tokio::test]
async fn record_only_textarea_is_focus_only_without_claiming_input_tested() {
    for (selector, kind, expected_role) in [
        ("textarea[name=\"noteBody\"]", "other", "input"),
        ("main > textarea[name=\"noteBody\"]", "unknown", "input"),
        (
            "textarea[aria-label=\"Additional notes\"]",
            "other",
            "input",
        ),
        (
            "textarea[aria-label=\"Notes > details + history\"]",
            "other",
            "input",
        ),
        (
            "main[data-note=\"x > y\"] > textarea[aria-label='Additional notes']",
            "other",
            "input",
        ),
        (
            r#"textarea[aria-label="Notes \" and more"]"#,
            "other",
            "input",
        ),
        ("textarea:is(.wide, .narrow)", "other", "input"),
        ("textarea[name=\"noteBody\"]", "button", "button"),
        ("div.textarea", "other", "other"),
        ("#textarea", "other", "other"),
        ("textarea > button", "other", "other"),
        ("div[data-note=\"x textarea\"]", "other", "other"),
        ("div[data-note=\"x > textarea\"]", "other", "other"),
        (
            "textarea[aria-label='Additional notes'] > button",
            "other",
            "other",
        ),
        ("button, textarea", "other", "other"),
        ("textarea, button", "other", "other"),
        ("div:is(.wide, textarea)", "other", "other"),
    ] {
        let action = rec("v", "/", selector, kind, InteractionOutcome::NoEffect);
        let inv = build_scan(vec![view("v", "/", vec![])], &[action], &[], &["/"]).await;
        assert_eq!(inv.controls.len(), 1);
        let control = &inv.controls[0];
        assert_eq!(control.role, expected_role, "{selector}");
        if expected_role == "input" {
            assert_eq!(control.status, ControlStatus::Ok);
            assert_eq!(control.reason.as_deref(), Some("focus_only"));
            assert!(render::tsv_row(control).contains("focus only (input not tested)"));
        } else {
            assert_ne!(control.reason.as_deref(), Some("focus_only"));
        }
    }
}

#[tokio::test]
async fn generated_id_fallback_labels_and_quiet_diff_invariants() {
    use crate::code_link::runtime_source::{FileLine, ResolvedSource};

    // 1. Building an inventory never leaks generated Base UI IDs as fallback labels,
    //    and a drag-resize handle with a handler scores `ok` (`drag_only_control`).
    let mut gen_switch = el(
        "#base-ui-_r_1v_",
        "",
        json!({"kind": "checkbox", "checked": false}),
        &[("id", "#base-ui-_r_1v_")],
    );
    gen_switch["label"] = json!(null);
    let mut resize = el(
        r#"button[aria-label="Resize Sidebar"]"#,
        "Resize Sidebar",
        button(),
        &[("aria", r#"button[aria-label="Resize Sidebar"]"#)],
    );
    resize["source"] = json!({"frames": [], "handlers": ["onPointerDown"]});
    let resize_rec = rec(
        "v1",
        "/settings/general",
        r#"button[aria-label="Resize Sidebar"]"#,
        "button",
        InteractionOutcome::NoEffect,
    );
    let built = build_scan(
        vec![view("v1", "/settings/general", vec![gen_switch, resize])],
        &[resize_rec],
        &[],
        &["/settings/general"],
    )
    .await;
    let sw = built
        .controls
        .iter()
        .find(|c| c.role == "checkbox")
        .expect("switch control");
    assert_eq!(
        sw.label, "",
        "generated Base UI id must not leak into fallback label"
    );
    let rz = built
        .controls
        .iter()
        .find(|c| c.label == "Resize Sidebar")
        .expect("resize control");
    assert_eq!(rz.status, ControlStatus::Ok);
    assert_eq!(rz.reason.as_deref(), Some("drag_only_control"));

    // 2. Diffing two unchanged-commit inventories with:
    //    - generated Base UI labels on ordinal controls (`base-ui-_r_r_` -> `base-ui-_r_1v_`)
    //    - an extra unlabeled hidden input shifting ordinal `#2` to `#3`
    //    - singular/plural count label change (`1 client` -> `2 clients`)
    //    - non-global inherited-evidence control (`exercised on /new`) hidden on one route
    //      while still present on `/new`
    //    produces ZERO changes.
    let src_at = |file: &str, line: u32, caller: Option<(&str, u32)>| ResolvedSource {
        render: Some(FileLine {
            file: file.into(),
            line,
            col: 13,
        }),
        caller: caller.map(|(f, l)| FileLine {
            file: f.into(),
            line: l,
            col: 24,
        }),
        handler: None,
        method: "runtime".into(),
        confidence: "exact".into(),
        candidates: Vec::new(),
    };
    let mk_route = |r: &str| crate::inventory::RouteEntry {
        route: r.into(),
        visited: true,
        status: Some(200),
        ..Default::default()
    };
    let prev = crate::inventory::Inventory {
        schema: crate::inventory::INVENTORY_SCHEMA.into(),
        identity_version: crate::inventory::IDENTITY_VERSION,
        project: "demo".into(),
        generated_at: "2026-11-26T02:16:42Z".into(),
        routes: vec![
            mk_route("/new"),
            mk_route("/settings/access"),
            mk_route("/settings/general"),
        ],
        controls: vec![
            crate::inventory::Control {
                key: "/settings/access|button|text=authorized clients # client".into(),
                route: "/settings/access".into(),
                role: "button".into(),
                label: "Authorized clients 1 client".into(),
                locator: "text=authorized clients # client".into(),
                count: 1,
                status: ControlStatus::NotExercised,
                ..Default::default()
            },
            crate::inventory::Control {
                key: "/settings/general|checkbox|text=#1".into(),
                route: "/settings/general".into(),
                role: "checkbox".into(),
                label: "base-ui-_r_r_".into(),
                locator: "text=".into(),
                count: 1,
                status: ControlStatus::NotExercised,
                source: Some(src_at("src/Switch.tsx", 12, None)),
                ..Default::default()
            },
            crate::inventory::Control {
                key: "/settings/general|input|text=#2".into(),
                route: "/settings/general".into(),
                role: "input".into(),
                label: "base-ui-_r_n_-hidden-input".into(),
                locator: "text=".into(),
                count: 1,
                status: ControlStatus::NotExercised,
                source: Some(src_at("src/SettingsPanels.tsx", 1668, None)),
                ..Default::default()
            },
            crate::inventory::Control {
                key: "/settings/general|button|aria=resize sidebar".into(),
                route: "/settings/general".into(),
                role: "button".into(),
                label: "Resize Sidebar".into(),
                locator: "aria=resize sidebar".into(),
                count: 1,
                status: ControlStatus::NoEffect,
                reason: Some("handler attached; exercised on /new".into()),
                ..Default::default()
            },
            crate::inventory::Control {
                key: "/new|button|aria=resize sidebar".into(),
                route: "/new".into(),
                role: "button".into(),
                label: "Resize Sidebar".into(),
                locator: "aria=resize sidebar".into(),
                count: 1,
                status: ControlStatus::NoEffect,
                reason: Some("handler attached".into()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let cur = crate::inventory::Inventory {
        schema: crate::inventory::INVENTORY_SCHEMA.into(),
        identity_version: crate::inventory::IDENTITY_VERSION,
        project: "demo".into(),
        generated_at: "2026-11-26T02:57:49Z".into(),
        routes: vec![
            mk_route("/new"),
            mk_route("/settings/access"),
            mk_route("/settings/general"),
        ],
        controls: vec![
            crate::inventory::Control {
                key: "/settings/access|button|text=authorized clients # clients".into(),
                route: "/settings/access".into(),
                role: "button".into(),
                label: "Authorized clients 2 clients".into(),
                locator: "text=authorized clients # clients".into(),
                count: 1,
                status: ControlStatus::NotExercised,
                ..Default::default()
            },
            crate::inventory::Control {
                key: "/settings/general|checkbox|text=#1".into(),
                route: "/settings/general".into(),
                role: "checkbox".into(),
                label: "base-ui-_r_1v_".into(),
                locator: "text=".into(),
                count: 1,
                status: ControlStatus::NotExercised,
                source: Some(src_at("src/Switch.tsx", 12, None)),
                ..Default::default()
            },
            // Extra hidden input inserted at `#2` shifts previous `#2` to `#3`
            crate::inventory::Control {
                key: "/settings/general|input|text=#2".into(),
                route: "/settings/general".into(),
                role: "input".into(),
                label: "base-ui-_r_24_-hidden-input".into(),
                locator: "text=".into(),
                count: 1,
                status: ControlStatus::NotExercised,
                source: Some(src_at(
                    "src/SettingsPanels.tsx",
                    934,
                    Some(("src/routes/_chat.settings.general.tsx", 9)),
                )),
                ..Default::default()
            },
            crate::inventory::Control {
                key: "/settings/general|input|text=#3".into(),
                route: "/settings/general".into(),
                role: "input".into(),
                label: "base-ui-_r_2m_-hidden-input".into(),
                locator: "text=".into(),
                count: 1,
                status: ControlStatus::NotExercised,
                source: Some(src_at("src/SettingsPanels.tsx", 1668, None)),
                ..Default::default()
            },
            // Resize Sidebar collapsed on /settings/general, still present on /new
            crate::inventory::Control {
                key: "/new|button|aria=resize sidebar".into(),
                route: "/new".into(),
                role: "button".into(),
                label: "Resize Sidebar".into(),
                locator: "aria=resize sidebar".into(),
                count: 1,
                status: ControlStatus::NoEffect,
                reason: Some("handler attached".into()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let diff = crate::inventory::diff(Some(&prev), &cur);
    assert!(
        diff.changes.is_empty(),
        "unchanged commit must produce empty diff, got: {:#?}",
        diff.changes
    );
}
