//! Inventory builder tests over synthetic scan directories.

use std::path::Path;

use serde_json::{Value, json};

use super::*;
use crate::code_link::runtime_source::FileLine;
use crate::output::interactions::{InteractionOutcome, InteractionRecord};

pub(super) const BASE: &str = "http://127.0.0.1:47260";
pub(super) const T0: &str = "2026-10-21T10:00:00Z";
const T_IN: &str = "2026-10-21T10:00:00.200Z";

pub(super) fn button() -> Value {
    json!({"kind": "button", "form_submit": false})
}

pub(super) fn submit() -> Value {
    json!({"kind": "button", "form_submit": true})
}

pub(super) fn link(href: &str) -> Value {
    json!({"kind": "navigation_link", "href": href})
}

pub(super) fn text_input() -> Value {
    json!({"kind": "text_input", "input_type": "text", "required": false})
}

pub(super) fn el(selector: &str, label: &str, kind: Value, locators: &[(&str, &str)]) -> Value {
    let locs: Vec<Value> = locators
        .iter()
        .map(|(k, v)| json!({"kind": k, "value": v, "stability": 0.8, "unique": true}))
        .collect();
    let mut e = json!({
        "selector": selector,
        "element_type": kind,
        "found_on": "x",
        "locators": locs,
    });
    if !label.is_empty() {
        e["label"] = json!(label);
    }
    e
}

pub(super) fn view(id: &str, route: &str, elements: Vec<Value>) -> Value {
    json!({
        "id": id,
        "route": route,
        "title": format!("Page {route}"),
        "component_type": "unknown",
        "description": "",
        "elements": elements,
        "on_load_api_calls": [],
    })
}

pub(super) fn spec(views: Vec<Value>) -> Value {
    json!({
        "$schema": "x",
        "meta": {"tool_version": "t", "scan_date": T0, "scan_duration_seconds": 1, "target_url": format!("{BASE}/")},
        "application": {"base_url": format!("{BASE}/")},
        "views": views,
        "api_surface": {"base_url": BASE, "endpoints": []},
        "data_models": {},
        "state_machine": {"entry_point": "view_0001", "transitions": []},
    })
}

pub(super) fn rec(
    view: &str,
    path: &str,
    selector: &str,
    kind: &str,
    outcome: InteractionOutcome,
) -> InteractionRecord {
    let mut r = InteractionRecord::new(view, &format!("{BASE}{path}"), selector, kind);
    r.outcome = outcome;
    r.started_at = T0.to_string();
    r.duration_ms = 500;
    if outcome == InteractionOutcome::Skipped {
        r.action = "skip".into();
    } else {
        r.action_id = Some(format!("act-{view}-{selector}"));
    }
    r
}

pub(super) fn row(
    method: &str,
    path: &str,
    status: Option<u16>,
    trigger: Option<(&str, &str)>,
    action_id: Option<&str>,
) -> Value {
    let mut r = json!({
        "occurred_at": T_IN,
        "trace": {"trace_id": "t", "cdp_request_id": "c"},
        "request": {"method": method, "url": format!("{BASE}{path}"), "headers": {}},
        "is_api": true,
    });
    if let Some(s) = status {
        r["response"] = json!({"status": s, "headers": {}, "mime_type": "application/json"});
    }
    if let Some((v, s)) = trigger {
        r["triggered_by"] = json!({"view": v, "selector": s});
    }
    if let Some(a) = action_id {
        r["trace"]["action_id"] = json!(a);
    }
    r
}

pub(super) fn write_scan(
    dir: &Path,
    spec: &Value,
    records: Option<&[InteractionRecord]>,
    rows: &[Value],
) {
    std::fs::write(dir.join("spec.json"), spec.to_string()).unwrap();
    if let Some(records) = records {
        let lines: Vec<String> = records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        std::fs::write(dir.join("interactions.jsonl"), lines.join("\n") + "\n").unwrap();
    }
    let lines: Vec<String> = rows.iter().map(|r| r.to_string()).collect();
    std::fs::write(dir.join("network.jsonl"), lines.join("\n")).unwrap();
}

pub(super) fn opts() -> BuildOptions {
    BuildOptions {
        project: "demo".into(),
        target_url: format!("{BASE}/"),
        write_guard: "block".into(),
        ..Default::default()
    }
}

pub(super) async fn build(dir: &Path, opts: &BuildOptions) -> Inventory {
    build_from_scan_dir(dir, opts).await.unwrap()
}

pub(super) fn find<'a>(inv: &'a Inventory, key: &str) -> &'a Control {
    inv.controls
        .iter()
        .find(|c| c.key == key)
        .unwrap_or_else(|| {
            panic!(
                "no control {key}; have {:?}",
                inv.controls.iter().map(|c| &c.key).collect::<Vec<_>>()
            )
        })
}

#[tokio::test]
async fn keys_locators_grouping_and_ordinals() {
    let dir = tempfile::tempdir().unwrap();
    let spec = spec(vec![view(
        "view_0001",
        "/",
        vec![
            el(
                "[data-testid=\"buy\"]",
                "Buy",
                button(),
                &[("test_id", "[data-testid=\"buy\"]"), ("id", "#buy-btn")],
            ),
            el("#checkout", "Checkout", button(), &[("id", "#checkout")]),
            el(
                "#mat-select-0",
                "16",
                button(),
                &[
                    ("id", "#mat-select-0"),
                    ("aria", "div[aria-label=\"Items per page\"]"),
                ],
            ),
            el(
                "input[name=\"email\"]",
                "",
                text_input(),
                &[("name", "input[name=\"email\"]")],
            ),
            el("main > a:nth-of-type(1)", "Cart (2)", link("/cart"), &[]),
            el("main > button:nth-of-type(3)", "Add to cart", button(), &[]),
            el("main > button:nth-of-type(4)", "Add to cart", button(), &[]),
            el(
                "main > button:nth-of-type(5)",
                "Add to Cart ",
                button(),
                &[],
            ),
            el("main > button:nth-of-type(6)", "", button(), &[]),
            el("main > button:nth-of-type(7)", "", button(), &[]),
            // Decorative, unlabeled, never exercised: dropped.
            el(
                "div.mat-select-arrow",
                "",
                json!({"kind": "other", "tag": "div"}),
                &[("class", "div.mat-select-arrow")],
            ),
        ],
    )]);
    write_scan(dir.path(), &spec, Some(&[]), &[]);
    let inv = build(dir.path(), &opts()).await;

    find(&inv, "/|button|testid=buy");
    find(&inv, "/|button|id=checkout");
    find(&inv, "/|button|aria=items per page");
    let email = find(&inv, "/|input|name=email");
    assert_eq!(email.label, "email");
    // Links are identified by label (digits folded); the href is an outcome.
    let cart = find(&inv, "/|link|text=cart (#)");
    assert!(
        cart.outcomes
            .contains(&Outcome::Navigates { to: "/cart".into() })
    );
    assert_eq!(cart.target.as_deref(), Some("/cart"));
    let add = find(&inv, "/|button|text=add to cart");
    assert_eq!(add.count, 3);
    let unlabeled = find(&inv, "/|button|text=#1");
    assert_eq!(
        unlabeled.display_label(),
        "(no label) main > button:nth-of-type(6)"
    );
    find(&inv, "/|button|text=#2");
    assert_eq!(inv.controls.len(), 8);
    // Sorted by (route, key) for stable output.
    let keys: Vec<&str> = inv.controls.iter().map(|c| c.key.as_str()).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[tokio::test]
async fn global_controls_need_three_routes_and_sixty_percent() {
    let dir = tempfile::tempdir().unwrap();
    let shell = |extra: Vec<Value>| {
        let mut v = vec![
            el("header > a", "Home", link("/"), &[]),
            el("#menu", "Menu", button(), &[("id", "#menu")]),
        ];
        v.extend(extra);
        v
    };
    let promo = || el("#promo", "Promo", button(), &[("id", "#promo")]);
    let spec = spec(vec![
        view("view_0001", "/", shell(vec![promo()])),
        view("view_0002", "/a", shell(vec![promo()])),
        view("view_0003", "/b", shell(vec![])),
        view(
            "view_0004",
            "/c",
            vec![el("#menu", "Menu", button(), &[("id", "#menu")])],
        ),
        view(
            "view_0005",
            "/d",
            vec![el("main > a", "Back home", link("/"), &[])],
        ),
    ]);
    let mut skipped = rec(
        "view_0002",
        "/a",
        "#menu",
        "button",
        InteractionOutcome::Skipped,
    );
    skipped.skipped_reason = Some("exercised_elsewhere".into());
    skipped.exercised_on = Some("view_0001".into());
    let records = vec![
        rec(
            "view_0001",
            "/",
            "#menu",
            "button",
            InteractionOutcome::DomChange,
        ),
        skipped,
    ];
    write_scan(dir.path(), &spec, Some(&records), &[]);
    let inv = build(dir.path(), &opts()).await;

    let menu = find(&inv, "*|button|id=menu");
    assert_eq!(menu.route, "*");
    assert_eq!(menu.routes, vec!["/", "/a", "/b", "/c"]);
    assert_eq!(menu.status, ControlStatus::Ok);
    // The header Home link is on 3 of 5 routes; the main-content "Back home"
    // link on /d shares its href but is a different control.
    let home = find(&inv, "*|link|text=home@header");
    assert_eq!(home.label, "Home");
    assert_eq!(home.region, "header");
    assert_eq!(home.routes, vec!["/", "/a", "/b"]);
    let back = find(&inv, "/d|link|text=back home");
    assert_eq!(back.target.as_deref(), Some("/"));
    // Promo on 2 routes stays per-route.
    find(&inv, "/|button|id=promo");
    find(&inv, "/a|button|id=promo");
    assert_eq!(inv.controls[0].route, "*", "global controls sort first");
    let root = inv.routes.iter().find(|r| r.route == "/").unwrap();
    assert_eq!(root.controls, 1, "route counts exclude shell controls");
}

#[tokio::test]
async fn status_rules_from_interactions_and_network() {
    let dir = tempfile::tempdir().unwrap();
    let mut submit_el = el("#submit", "Sign up", submit(), &[("id", "#submit")]);
    submit_el["empty_required_fields_in_form"] = json!(2);
    let mut off = el("#off", "Off", button(), &[("id", "#off")]);
    off["disabled"] = json!(true);
    let elements = vec![
        el("#nav", "Go to cart", button(), &[("id", "#nav")]),
        el("#buy", "Buy now", button(), &[("id", "#buy")]),
        el("#beacon", "Upgrade", button(), &[("id", "#beacon")]),
        el("#pay", "Pay", button(), &[("id", "#pay")]),
        el("#dead", "Do nothing", button(), &[("id", "#dead")]),
        el("#boom", "Explode", button(), &[("id", "#boom")]),
        el("#err", "Load report", button(), &[("id", "#err")]),
        el("#fail", "Retry", button(), &[("id", "#fail")]),
        el("#modal", "Details", button(), &[("id", "#modal")]),
        el("#confirm", "Remove item", button(), &[("id", "#confirm")]),
        submit_el,
        el("#q", "Search", text_input(), &[("id", "#q")]),
        off,
        el(
            "#gh",
            "GitHub",
            link("https://github.com/x/y"),
            &[("id", "#gh")],
        ),
        el("#del", "Delete account", button(), &[("id", "#del")]),
        el("#later", "Later", button(), &[("id", "#later")]),
        el("#never", "Never tried", button(), &[("id", "#never")]),
    ];
    let mut v = view("view_0001", "/", elements);
    v["on_load_api_calls"] = json!([{"method": "GET", "path_template": "/api/me"}]);
    let spec = spec(vec![v, view("view_0002", "/cart", vec![])]);

    let mut nav = rec(
        "view_0001",
        "/",
        "#nav",
        "button",
        InteractionOutcome::Navigated,
    );
    nav.after_url = Some(format!("{BASE}/cart?ref=1"));
    let mut boom = rec(
        "view_0001",
        "/",
        "#boom",
        "button",
        InteractionOutcome::NoEffect,
    );
    boom.console_errors = vec!["Error: handler exploded\n    at onclick".into()];
    let mut modal = rec(
        "view_0001",
        "/",
        "#modal",
        "button",
        InteractionOutcome::DomChange,
    );
    modal.dom_change = Some("modal".into());
    let mut confirm = rec(
        "view_0001",
        "/",
        "#confirm",
        "button",
        InteractionOutcome::NoEffect,
    );
    confirm.native_dialog = Some("confirm: Remove item?".into());
    let mut del = rec(
        "view_0001",
        "/",
        "#del",
        "button",
        InteractionOutcome::Skipped,
    );
    del.skipped_reason = Some("dangerous_label".into());
    let mut later = rec(
        "view_0001",
        "/",
        "#later",
        "button",
        InteractionOutcome::Skipped,
    );
    later.skipped_reason = Some("interaction_limit".into());
    let mut err = rec(
        "view_0001",
        "/",
        "#err",
        "button",
        InteractionOutcome::Error,
    );
    err.error = Some("click intercepted".into());
    let records = vec![
        nav,
        rec(
            "view_0001",
            "/",
            "#buy",
            "button",
            InteractionOutcome::NoEffect,
        ),
        rec(
            "view_0001",
            "/",
            "#beacon",
            "button",
            InteractionOutcome::NoEffect,
        ),
        rec(
            "view_0001",
            "/",
            "#pay",
            "button",
            InteractionOutcome::NoEffect,
        ),
        rec(
            "view_0001",
            "/",
            "#dead",
            "button",
            InteractionOutcome::NoEffect,
        ),
        boom,
        err,
        rec(
            "view_0001",
            "/",
            "#fail",
            "button",
            InteractionOutcome::NoEffect,
        ),
        modal,
        confirm,
        rec(
            "view_0001",
            "/",
            "#submit",
            "button",
            InteractionOutcome::NoEffect,
        ),
        rec(
            "view_0001",
            "/",
            "#q",
            "text_input",
            InteractionOutcome::NoEffect,
        ),
        del,
        later,
    ];
    let mut blocked = row(
        "POST",
        "/api/orders",
        None,
        Some(("view_0001", "#buy")),
        Some("act-view_0001-#buy"),
    );
    blocked["write_guard"] = json!("blocked");
    blocked["failure"] = json!("net::ERR_BLOCKED_BY_CLIENT");
    let rows = vec![
        row(
            "GET",
            "/api/me",
            Some(200),
            Some(("view_0001", "__page_load__")),
            None,
        ),
        blocked,
        // No action id (sendBeacon): joined by triggered_by.
        row(
            "POST",
            "/api/beacon",
            Some(204),
            Some(("view_0001", "#beacon")),
            None,
        ),
        row(
            "GET",
            "/api/pay/42",
            Some(200),
            Some(("view_0001", "#pay")),
            Some("act-view_0001-#pay"),
        ),
        row(
            "GET",
            "/api/report",
            Some(500),
            Some(("view_0001", "#fail")),
            Some("act-view_0001-#fail"),
        ),
    ];
    write_scan(dir.path(), &spec, Some(&records), &rows);
    let inv = build(dir.path(), &opts()).await;
    let st = |k: &str| find(&inv, k).status;

    let nav = find(&inv, "/|button|id=nav");
    assert_eq!(nav.status, ControlStatus::Ok);
    assert_eq!(
        nav.outcomes,
        vec![Outcome::Navigates { to: "/cart".into() }]
    );

    let buy = find(&inv, "/|button|id=buy");
    assert_eq!(
        buy.status,
        ControlStatus::Ok,
        "blocked write is an effect, not an error"
    );
    assert_eq!(
        buy.outcomes,
        vec![Outcome::Calls {
            endpoint: "POST /api/orders".into(),
            status: None,
            blocked: true
        }]
    );
    assert_eq!(st("/|button|id=beacon"), ControlStatus::Ok);
    let pay = find(&inv, "/|button|id=pay");
    assert!(pay.outcomes.contains(&Outcome::Calls {
        endpoint: "GET /api/pay/:id".into(),
        status: Some(200),
        blocked: false
    }));
    assert_eq!(st("/|button|id=dead"), ControlStatus::Dead);
    assert_eq!(st("/|button|id=boom"), ControlStatus::Broken);
    assert!(
        find(&inv, "/|button|id=boom")
            .reason
            .as_deref()
            .unwrap()
            .contains("handler exploded")
    );
    assert_eq!(st("/|button|id=err"), ControlStatus::Broken);
    assert_eq!(st("/|button|id=fail"), ControlStatus::Broken);
    assert_eq!(
        find(&inv, "/|button|id=fail").reason.as_deref(),
        Some("GET /api/report returned 500")
    );
    assert_eq!(st("/|button|id=modal"), ControlStatus::Ok);
    let confirm = find(&inv, "/|button|id=confirm");
    assert_eq!(confirm.status, ControlStatus::Ok);
    assert!(confirm.outcomes.contains(&Outcome::Dialog {
        message: "confirm: Remove item?".into()
    }));
    let submit = find(&inv, "/|button|id=submit");
    assert_eq!(
        (submit.status, submit.reason.as_deref()),
        (ControlStatus::Ok, Some("validation_blocked"))
    );
    let q = find(&inv, "/|input|id=q");
    assert_eq!(
        (q.status, q.reason.as_deref()),
        (ControlStatus::Ok, Some("focus_only"))
    );
    assert_eq!(st("/|button|id=off"), ControlStatus::Disabled);
    assert_eq!(st("/|link|id=gh"), ControlStatus::External);
    let del = find(&inv, "/|button|id=del");
    assert_eq!(
        (del.status, del.reason.as_deref()),
        (ControlStatus::Skipped, Some("dangerous_label"))
    );
    let later = find(&inv, "/|button|id=later");
    assert_eq!(
        (later.status, later.reason.as_deref()),
        (ControlStatus::NotExercised, Some("interaction_limit"))
    );
    let never = find(&inv, "/|button|id=never");
    assert_eq!(
        (never.status, never.reason.as_deref()),
        (ControlStatus::NotExercised, Some("not_attempted"))
    );

    // Endpoint index: on-load requests stay out of controls.
    let me = inv
        .endpoints
        .iter()
        .find(|e| e.endpoint == "GET /api/me")
        .unwrap();
    assert!(me.controls.is_empty());
    assert_eq!(me.on_load, vec!["/"]);
    let orders = inv
        .endpoints
        .iter()
        .find(|e| e.endpoint == "POST /api/orders")
        .unwrap();
    assert!(orders.write);
    assert_eq!(orders.controls, vec!["/|button|id=buy"]);

    assert_eq!(inv.coverage.controls_total, 17);
    assert_eq!(inv.coverage.controls_exercised, 12);
    assert_eq!(
        inv.coverage
            .not_exercised_by_reason
            .get("interaction_limit"),
        Some(&1)
    );
    assert_eq!(inv.write_guard, "block");
}

#[tokio::test]
async fn grouped_controls_note_partial_no_effect() {
    let dir = tempfile::tempdir().unwrap();
    let spec = spec(vec![view(
        "view_0001",
        "/",
        vec![
            el("main > button:nth-of-type(1)", "Add", button(), &[]),
            el("main > button:nth-of-type(2)", "Add", button(), &[]),
        ],
    )]);
    let records = vec![
        rec(
            "view_0001",
            "/",
            "main > button:nth-of-type(1)",
            "button",
            InteractionOutcome::NoEffect,
        ),
        rec(
            "view_0001",
            "/",
            "main > button:nth-of-type(2)",
            "button",
            InteractionOutcome::NoEffect,
        ),
    ];
    let rows = vec![row(
        "POST",
        "/api/cart",
        Some(200),
        Some(("view_0001", "main > button:nth-of-type(1)")),
        Some("act-view_0001-main > button:nth-of-type(1)"),
    )];
    write_scan(dir.path(), &spec, Some(&records), &rows);
    let inv = build(dir.path(), &opts()).await;
    let add = find(&inv, "/|button|text=add");
    assert_eq!(add.count, 2);
    assert_eq!(add.status, ControlStatus::Ok);
    assert_eq!(
        add.reason.as_deref(),
        Some("no effect on 1 of 2 exercised instances")
    );
}

#[tokio::test]
async fn endpoint_keys_follow_the_scanner_format() {
    let dir = tempfile::tempdir().unwrap();
    let spec = spec(vec![view(
        "view_0001",
        "/",
        vec![
            el("#cart", "Add to cart", button(), &[("id", "#cart")]),
            el("#act", "Save draft", button(), &[("id", "#act")]),
            el("#gql", "Refund", button(), &[("id", "#gql")]),
            el("#stub", "Subscribe", button(), &[("id", "#stub")]),
        ],
    )]);
    let records: Vec<InteractionRecord> = ["#cart", "#act", "#gql", "#stub"]
        .iter()
        .map(|s| rec("view_0001", "/", s, "button", InteractionOutcome::NoEffect))
        .collect();
    // Older rows without endpoint_key: keys are rebuilt from the request.
    let mut cross = row("POST", "/x", None, Some(("view_0001", "#cart")), None);
    cross["request"]["url"] = json!("https://db.example.co/rest/v1/cart?select=*");
    cross["response"] = json!({"status": 201, "headers": {}});
    let mut action = row(
        "POST",
        "/drafts",
        Some(200),
        Some(("view_0001", "#act")),
        None,
    );
    action["request"]["headers"] = json!({"Next-Action": "7f3a"});
    let mut gql = row(
        "POST",
        "/graphql",
        Some(200),
        Some(("view_0001", "#gql")),
        None,
    );
    gql["request"]["post_data"] = json!(r#"{"query":"mutation RefundOrder { refund }"}"#);
    // A1-style row: scanner key and guard verdict recorded.
    let mut stub = row(
        "POST",
        "/api/subscribe",
        Some(200),
        Some(("view_0001", "#stub")),
        None,
    );
    stub["endpoint_key"] = json!("POST /api/subscribe");
    stub["write_guard"] = json!("stubbed");
    write_scan(
        dir.path(),
        &spec,
        Some(&records),
        &[cross, action, gql, stub],
    );
    let mut o = opts();
    o.write_guard = String::new();
    let inv = build(dir.path(), &o).await;
    let eps = |k: &str| {
        find(&inv, k)
            .endpoints()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        eps("/|button|id=cart"),
        vec!["POST https://db.example.co/rest/v1/cart"]
    );
    // Server Action ids change per build: keyed by the stable form.
    assert_eq!(eps("/|button|id=act"), vec!["POST /drafts [server action]"]);
    assert!(journey::endpoint_matches(
        "POST /drafts [server action]",
        Some("POST"),
        "/drafts"
    ));
    assert_eq!(
        eps("/|button|id=gql"),
        vec!["POST /graphql#MUTATION RefundOrder"]
    );
    let stub = find(&inv, "/|button|id=stub");
    assert_eq!(stub.status, ControlStatus::Ok);
    assert!(stub.outcomes.contains(&Outcome::Calls {
        endpoint: "POST /api/subscribe".into(),
        status: Some(200),
        blocked: true
    }));
    assert_eq!(inv.write_guard, "stub");
    assert!(journey::endpoint_matches(
        "POST https://db.example.co/rest/v1/cart",
        Some("POST"),
        "/rest/v1/cart"
    ));
    let goal = journey::parse_goal("/rest/v1/cart", &inv);
    assert_eq!(journey::journey(&inv, &goal, None, 6).direct.len(), 1);
}

#[tokio::test]
async fn exercised_elsewhere_inherits_and_window_rejects_stale_requests() {
    let dir = tempfile::tempdir().unwrap();
    let spec = spec(vec![
        view(
            "view_0001",
            "/",
            vec![el("#help", "Help", button(), &[("id", "#help")])],
        ),
        view(
            "view_0002",
            "/about",
            vec![el("#help", "Help", button(), &[("id", "#help")])],
        ),
    ]);
    let mut help = rec(
        "view_0001",
        "/",
        "#help",
        "button",
        InteractionOutcome::DomChange,
    );
    help.dom_change = Some("panel".into());
    let mut elsewhere = rec(
        "view_0002",
        "/about",
        "#help",
        "button",
        InteractionOutcome::Skipped,
    );
    elsewhere.skipped_reason = Some("exercised_elsewhere".into());
    elsewhere.exercised_on = Some("view_0001".into());
    let mut stale = row(
        "GET",
        "/api/poll",
        Some(200),
        Some(("view_0001", "#help")),
        None,
    );
    stale["occurred_at"] = json!("2026-10-21T10:05:00Z");
    write_scan(dir.path(), &spec, Some(&[help, elsewhere]), &[stale]);
    let inv = build(dir.path(), &opts()).await;
    let about = find(&inv, "/about|button|id=help");
    assert_eq!(about.status, ControlStatus::Ok);
    assert_eq!(about.reason.as_deref(), Some("exercised on /"));
    assert!(about.outcomes.contains(&Outcome::DomChange {
        kind: "panel".into()
    }));
    let home = find(&inv, "/|button|id=help");
    assert!(
        home.endpoints().next().is_none(),
        "request 5 minutes later is not the click's"
    );
}

#[tokio::test]
async fn hash_routes_and_link_targets() {
    let dir = tempfile::tempdir().unwrap();
    let spec = spec(vec![
        view(
            "view_0001",
            "/#/",
            vec![
                el("a.basket", "Basket", link("#/basket"), &[]),
                el("a.top", "Top", link("#top"), &[]),
                el("a.js", "Menu", link("javascript:void(0)"), &[]),
            ],
        ),
        view("view_0002", "/#/basket", vec![]),
    ]);
    let js = rec(
        "view_0001",
        "/#/",
        "a.js",
        "navigation_link",
        InteractionOutcome::NoEffect,
    );
    // Static asset fallback (e.g. Vite SPA fallback serving text/html for /favicon.ico)
    // must never be misclassified as a document navigation.
    let mut fav = row(
        "GET",
        "/favicon.ico",
        Some(200),
        Some(("view_0001", "a.basket")),
        None,
    );
    fav["is_api"] = json!(false);
    fav["response"]["mime_type"] = json!("text/html");
    write_scan(dir.path(), &spec, Some(&[js]), &[fav]);
    let inv = build(dir.path(), &opts()).await;
    let basket = find(&inv, "/#/|link|text=basket");
    assert_eq!(basket.status, ControlStatus::Ok);
    assert_eq!(basket.reason.as_deref(), Some("href_target_reached"));
    assert_eq!(basket.navigates_to().collect::<Vec<_>>(), vec!["/#/basket"]);
    // A same-document `#top` link is an in-page anchor, not a navigation.
    let top = find(&inv, "/#/|link|text=top");
    assert_eq!(
        top.outcomes,
        vec![Outcome::Anchor {
            fragment: "top".into()
        }]
    );
    assert_eq!(
        (top.status, top.reason.as_deref()),
        (ControlStatus::Ok, Some("in-page anchor"))
    );
    assert_eq!(find(&inv, "/#/|link|text=menu").status, ControlStatus::Dead);
    assert!(
        inv.routes
            .iter()
            .any(|r| r.route == "/#/basket" && r.visited)
    );
}

#[tokio::test]
async fn link_probe_marks_missing_targets_broken() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/about"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let base = server.uri();
    let dir = tempfile::tempdir().unwrap();
    let mut s = spec(vec![view(
        "view_0001",
        "/",
        vec![
            el("a.missing", "Old page", link("/missing"), &[]),
            el("a.about", "About", link("/about"), &[]),
            el("a.logout", "Log out", link("/logout"), &[]),
        ],
    )]);
    s["meta"]["target_url"] = json!(format!("{base}/"));
    write_scan(dir.path(), &s, Some(&[]), &[]);
    let mut o = opts();
    o.target_url = format!("{base}/");
    o.check_links = true;
    let inv = build(dir.path(), &o).await;
    let missing = find(&inv, "/|link|text=old page");
    assert_eq!(missing.status, ControlStatus::Broken);
    assert_eq!(
        missing.reason.as_deref(),
        Some("link target /missing returned 404")
    );
    assert_eq!(find(&inv, "/|link|text=about").status, ControlStatus::Ok);
    // Logout links are never probed.
    assert_eq!(
        find(&inv, "/|link|text=log out").status,
        ControlStatus::NotExercised
    );
    let requests = server.received_requests().await.unwrap();
    assert!(requests.iter().all(|r| r.url.path() != "/logout"));
    assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
}

#[tokio::test]
async fn legacy_scans_use_transitions_triggers_bugs_and_gaps() {
    let dir = tempfile::tempdir().unwrap();
    let mut open = el("#open", "Open", button(), &[("id", "#open")]);
    open["snapshot"] = json!({"modal_opened": {"selector": ".modal"}});
    let mut s = spec(vec![
        view(
            "view_0001",
            "/",
            vec![
                el("#go", "Go", button(), &[("id", "#go")]),
                el("#save", "Save", button(), &[("id", "#save")]),
                el("#dead", "Dead", button(), &[("id", "#dead")]),
                el("#more", "More", button(), &[("id", "#more")]),
                open,
            ],
        ),
        view("view_0002", "/next", vec![]),
    ]);
    s["state_machine"]["transitions"] = json!([{
        "from_view": "view_0001", "to_view": "view_0002",
        "trigger": {"view": "view_0001", "selector": "#go"},
        "transition_type": "navigation", "api_calls": [], "preconditions": []
    }]);
    s["api_surface"]["endpoints"] = json!([{
        "key": {"method": "POST", "path_template": "/api/save"}, "url_pattern": "/api/save",
        "triggered_by": [{"view": "view_0001", "selector": "#save"}]
    }]);
    std::fs::write(dir.path().join("spec.json"), s.to_string()).unwrap();
    std::fs::write(
        dir.path().join("bugs.json"),
        json!({"items": [{"category": {"kind": "other", "description": "dead_button_group"},
            "description": "2 buttons\n\nSelectors:\n- `#dead`\n- `#ghost`",
            "location": {"view": "view_0001"}}]})
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("coverage-gaps.json"),
        json!({"items": [
            {"kind": "interaction", "target": "#more", "reason": "interaction_limit",
             "context": "view_0001 label=More"},
            {"kind": "route", "target": format!("{BASE}/settings"), "reason": "max_views_reached"}
        ]})
        .to_string(),
    )
    .unwrap();
    let mut o = opts();
    o.write_guard = String::new();
    let inv = build(dir.path(), &o).await;
    assert_eq!(
        find(&inv, "/|button|id=go").outcomes,
        vec![Outcome::Navigates { to: "/next".into() }]
    );
    let save = find(&inv, "/|button|id=save");
    assert_eq!(save.status, ControlStatus::Ok);
    assert_eq!(save.endpoints().collect::<Vec<_>>(), vec!["POST /api/save"]);
    assert_eq!(find(&inv, "/|button|id=dead").status, ControlStatus::Dead);
    let more = find(&inv, "/|button|id=more");
    assert_eq!(
        (more.status, more.reason.as_deref()),
        (ControlStatus::NotExercised, Some("interaction_limit"))
    );
    assert_eq!(
        find(&inv, "/|button|id=open").outcomes,
        vec![Outcome::DomChange {
            kind: "modal".into()
        }]
    );
    assert!(
        inv.coverage
            .unvisited_routes
            .contains(&"/settings".to_string())
    );
    assert_eq!(inv.write_guard, "unknown");
}

#[tokio::test]
async fn discovered_routes_canonicalize_and_report_unvisited() {
    let dir = tempfile::tempdir().unwrap();
    let like = || el("#like", "Like", button(), &[("id", "#like")]);
    let spec = spec(vec![
        view("view_0001", "/blog/hello-world", vec![like()]),
        view("view_0002", "/blog/second-post", vec![like()]),
    ]);
    write_scan(dir.path(), &spec, Some(&[]), &[]);
    let mut o = opts();
    o.discovered_routes = vec![
        crate::route_discovery::DiscoveredRoute {
            path: "/blog/:slug".into(),
            dynamic: true,
            kind: "page".into(),
            file: "app/blog/[slug]/page.tsx".into(),
            line: 1,
            ..Default::default()
        },
        crate::route_discovery::DiscoveredRoute {
            path: "/pricing".into(),
            kind: "page".into(),
            file: "app/pricing/page.tsx".into(),
            ..Default::default()
        },
    ];
    let inv = build(dir.path(), &o).await;
    let like = find(&inv, "/blog/:slug|button|id=like");
    assert_eq!(like.count, 1);
    let blog = inv
        .routes
        .iter()
        .find(|r| r.route == "/blog/:slug")
        .unwrap();
    assert!(blog.visited);
    assert_eq!(blog.source.as_deref(), Some("app/blog/[slug]/page.tsx:1"));
    assert_eq!(inv.coverage.unvisited_routes, vec!["/pricing"]);
}

// ---------------------------------------------------------------------------
// diff, map files, journey
// ---------------------------------------------------------------------------

pub(super) fn ctl(
    route: &str,
    locator: &str,
    label: &str,
    status: ControlStatus,
    outcomes: Vec<Outcome>,
) -> Control {
    Control {
        key: format!("{route}|button|{locator}"),
        route: route.into(),
        role: "button".into(),
        label: label.into(),
        selector: format!("sel-{label}"),
        locator: locator.into(),
        count: 1,
        status,
        outcomes,
        ..Default::default()
    }
}

pub(super) fn calls(e: &str) -> Vec<Outcome> {
    vec![Outcome::Calls {
        endpoint: e.into(),
        status: Some(200),
        blocked: false,
    }]
}

pub(super) fn inv_with(
    controls: Vec<Control>,
    routes: &[&str],
    endpoints: &[&str],
    at: &str,
) -> Inventory {
    Inventory {
        schema: INVENTORY_SCHEMA.into(),
        project: "demo".into(),
        generated_at: at.into(),
        target_url: format!("{BASE}/"),
        write_guard: "block".into(),
        routes: routes
            .iter()
            .map(|r| RouteEntry {
                route: r.to_string(),
                visited: true,
                ..Default::default()
            })
            .collect(),
        endpoints: endpoints
            .iter()
            .map(|e| EndpointEntry {
                endpoint: e.to_string(),
                ..Default::default()
            })
            .collect(),
        controls,
        ..Default::default()
    }
}

#[test]
fn diff_reports_every_change_kind() {
    let src = |file: &str| {
        Some(ResolvedSource {
            render: Some(FileLine {
                file: file.into(),
                line: 10,
                col: 0,
            }),
            method: "runtime".into(),
            confidence: "exact".into(),
            ..Default::default()
        })
    };
    let mut moved_prev = ctl("/", "id=mv", "Move", ControlStatus::Ok, calls("GET /api/a"));
    moved_prev.source = src("src/a.tsx");
    let mut moved_cur = moved_prev.clone();
    moved_cur.source = src("src/b.tsx");
    let mut rel_prev = ctl(
        "/",
        "text=pay",
        "Pay",
        ControlStatus::Ok,
        calls("POST /api/pay"),
    );
    rel_prev.source = src("src/pay.tsx");
    let mut rel_cur = ctl(
        "/",
        "text=pay now",
        "Pay now",
        ControlStatus::Ok,
        calls("POST /api/pay"),
    );
    rel_cur.source = src("src/pay.tsx");
    let prev = inv_with(
        vec![
            ctl("/", "id=gone", "Gone", ControlStatus::Ok, vec![]),
            ctl(
                "/",
                "id=dying",
                "Dying",
                ControlStatus::Ok,
                calls("POST /api/x"),
            ),
            ctl("/", "id=breaking", "Breaking", ControlStatus::Ok, vec![]),
            ctl("/", "id=fix", "Fix", ControlStatus::Dead, vec![]),
            ctl(
                "/",
                "id=wire",
                "Wire",
                ControlStatus::Ok,
                calls("POST /api/old"),
            ),
            ctl("/", "id=label", "Old label", ControlStatus::Ok, vec![]),
            moved_prev,
            rel_prev,
        ],
        &["/", "/old"],
        &["POST /api/old"],
        "2026-10-20T00:00:00Z",
    );
    let mut prev = prev;
    prev.endpoints[0].controls = vec!["/|button|id=wire".into()];
    let cur = inv_with(
        vec![
            ctl("/", "id=new", "New", ControlStatus::Ok, vec![]),
            ctl("/", "id=dying", "Dying", ControlStatus::Dead, vec![]),
            ctl(
                "/",
                "id=breaking",
                "Breaking",
                ControlStatus::Broken,
                vec![],
            ),
            ctl(
                "/",
                "id=fix",
                "Fix",
                ControlStatus::Ok,
                vec![Outcome::DomChange {
                    kind: "modal".into(),
                }],
            ),
            ctl(
                "/",
                "id=wire",
                "Wire",
                ControlStatus::Ok,
                calls("POST /api/new"),
            ),
            ctl("/", "id=label", "New label", ControlStatus::Ok, vec![]),
            moved_cur,
            rel_cur,
        ],
        &["/", "/new"],
        &["POST /api/new"],
        "2026-10-21T00:00:00Z",
    );
    let mut cur = cur;
    cur.endpoints[0].controls = vec!["/|button|id=wire".into()];
    let cs = diff(Some(&prev), &cur);
    let kinds: Vec<(&str, &str)> = cs
        .changes
        .iter()
        .map(|c| (c.kind.as_str(), c.key.as_str()))
        .collect();
    for expected in [
        ("added", "/|button|id=new"),
        ("removed", "/|button|id=gone"),
        ("now_dead", "/|button|id=dying"),
        ("now_broken", "/|button|id=breaking"),
        ("fixed", "/|button|id=fix"),
        ("rewired", "/|button|id=wire"),
        ("relabeled", "/|button|id=label"),
        ("relabeled", "/|button|text=pay now"),
        ("moved", "/|button|id=mv"),
        ("route_added", "/new"),
        ("route_removed", "/old"),
        ("endpoint_added", "POST /api/new"),
        ("endpoint_removed", "POST /api/old"),
    ] {
        assert!(
            kinds.contains(&expected),
            "missing {expected:?} in {kinds:?}"
        );
    }
    assert_eq!(kinds.len(), 13, "{kinds:?}");
    let dying = cs.changes.iter().find(|c| c.kind == "now_dead").unwrap();
    assert_eq!(
        dying.line,
        "NOW DEAD / button \"Dying\" (was calls POST /api/x)"
    );
    assert_eq!(cs.changes[0].kind, "now_broken", "most actionable first");
    assert_eq!(cs.summary.get("relabeled"), Some(&2));
    assert_eq!(cs.from.as_deref(), Some("2026-10-20T00:00:00Z"));

    let first = diff(None, &cur);
    assert!(first.changes.is_empty());
    assert_eq!(first.summary.get("added"), Some(&8));
    assert!(diff(Some(&cur), &cur).changes.is_empty());
}

#[test]
fn map_files_are_deterministic_and_changelog_is_newest_first() {
    let dir = tempfile::tempdir().unwrap();
    let mut shell = ctl(
        "*",
        "id=menu",
        "Menu",
        ControlStatus::Ok,
        vec![Outcome::DomChange {
            kind: "menu".into(),
        }],
    );
    shell.routes = vec!["/".into(), "/a".into(), "/b".into()];
    let buy = ctl(
        "/",
        "id=buy",
        "Buy | now",
        ControlStatus::Ok,
        vec![Outcome::Calls {
            endpoint: "POST /api/orders".into(),
            status: None,
            blocked: true,
        }],
    );
    let later = Control {
        reason: Some("interaction_limit".into()),
        ..ctl(
            "/",
            "id=later",
            "Later",
            ControlStatus::NotExercised,
            vec![],
        )
    };
    let inv = inv_with(
        vec![
            shell,
            buy,
            ctl("/", "id=dead", "Dead", ControlStatus::Dead, vec![]),
            later,
        ],
        &["/", "/a", "/b"],
        &[],
        "2026-10-21T00:00:00Z",
    );
    let files = write_map(&inv, dir.path()).unwrap();
    assert_eq!(files.len(), 4);
    let md = std::fs::read_to_string(dir.path().join("UI-MAP.md")).unwrap();
    assert!(
        md.find("## Global controls").unwrap() < md.find("## /\n").unwrap(),
        "{md}"
    );
    assert!(
        md.contains(
            "| \"Buy \\| now\" `id=buy` | button | calls POST /api/orders [write blocked] | ok |  |"
        ),
        "{md}"
    );
    assert!(md.contains("<details><summary>Not exercised (1)</summary>"));
    assert!(md.contains("- button \"Later\" — interaction_limit"));
    let tsv = std::fs::read_to_string(dir.path().join("ui-map.tsv")).unwrap();
    assert!(tsv.starts_with(
        "route\trole\tlabel\tstatus\tdoes\tendpoints\tnavigates_to\tsource\tkey\tlabels\treason\tvariants\toutcomes\tsource_method\tsource_confidence\tsource_candidates\tobservation\n"
    ));
    assert_eq!(tsv.lines().count(), 5);
    let dead = std::fs::read_to_string(dir.path().join("DEAD-UI.md")).unwrap();
    assert!(dead.contains("## Dead (high confidence) (1)"));
    assert!(dead.contains("## No visible effect (review) (0)"));
    assert!(dead.contains("## Coverage caveat"));
    assert_eq!(render::render_ui_tsv(&inv), tsv);

    let log = dir.path().join("CHANGELOG.md");
    append_changelog(&diff(None, &inv), &inv, &log).unwrap();
    let mut next = inv.clone();
    next.generated_at = "2026-10-22T00:00:00Z".into();
    next.controls.retain(|c| c.label != "Dead");
    append_changelog(&diff(Some(&inv), &next), &next, &log).unwrap();
    // No changes: nothing appended.
    append_changelog(&diff(Some(&next), &next), &next, &log).unwrap();
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(text.matches("# UI changelog").count(), 1);
    let newer = text.find("## 2026-10-22").unwrap();
    let older = text.find("## 2026-10-21").unwrap();
    assert!(newer < older, "{text}");
    assert!(text.contains("- REMOVED / button \"Dead\""), "{text}");
    assert!(text.contains("Initial map: 4 controls"), "{text}");
    assert_eq!(text.matches("## 2026-").count(), 2);
}

#[test]
fn changelog_entries_are_capped() {
    let prev = inv_with(vec![], &["/"], &[], "2026-10-20T00:00:00Z");
    let many: Vec<Control> = (0..250)
        .map(|i| {
            ctl(
                "/",
                &format!("id=b{i:03}"),
                &format!("B{i}"),
                ControlStatus::Ok,
                vec![],
            )
        })
        .collect();
    let cur = inv_with(many, &["/"], &[], "2026-10-21T00:00:00Z");
    let entry = render::render_changelog_entry(&diff(Some(&prev), &cur), &cur);
    assert!(entry.contains("- +50 more"), "{entry}");
    assert_eq!(
        entry.lines().filter(|l| l.starts_with("- ADDED")).count(),
        200
    );
}

#[test]
fn journey_finds_multi_hop_paths_through_shell_controls() {
    let mut cart_link = ctl(
        "*",
        "href=/cart",
        "Cart",
        ControlStatus::Ok,
        vec![Outcome::Navigates { to: "/cart".into() }],
    );
    cart_link.role = "link".into();
    cart_link.key = "*|link|href=/cart".into();
    cart_link.routes = vec!["/".into(), "/products".into(), "/about".into()];
    let mut checkout = ctl(
        "/cart",
        "id=checkout",
        "Checkout",
        ControlStatus::Ok,
        vec![Outcome::Navigates {
            to: "/checkout".into(),
        }],
    );
    checkout.role = "link".into();
    let pay = ctl("/checkout", "id=pay", "Pay", ControlStatus::Dead, vec![]);
    let place = ctl(
        "/checkout",
        "id=place",
        "Place order",
        ControlStatus::Ok,
        vec![Outcome::Calls {
            endpoint: "POST /api/orders".into(),
            status: None,
            blocked: true,
        }],
    );
    let inv = inv_with(
        vec![cart_link, checkout, pay, place],
        &["/", "/products", "/about", "/cart", "/checkout"],
        &["POST /api/orders"],
        "2026-10-21T00:00:00Z",
    );

    let goal = journey::parse_goal("POST /api/orders", &inv);
    assert_eq!(
        goal,
        journey::Goal::Endpoint {
            method: Some("POST".into()),
            path: "/api/orders".into()
        }
    );
    let res = journey::journey(&inv, &goal, None, 6);
    assert_eq!(res.distance, Some(3));
    assert_eq!(res.paths.len(), 1);
    let labels: Vec<&str> = res.paths[0]
        .steps
        .iter()
        .map(|s| s.label.as_str())
        .collect();
    assert_eq!(labels, vec!["Cart", "Checkout", "Place order"]);
    assert_eq!(res.paths[0].steps[0].route, "/");
    assert_eq!(res.direct.len(), 1);

    // Path-only and route goals.
    assert!(matches!(
        journey::parse_goal("/api/orders", &inv),
        journey::Goal::Endpoint { method: None, .. }
    ));
    let route_goal = journey::parse_goal("/checkout", &inv);
    let res = journey::journey(&inv, &route_goal, Some("/products"), 6);
    assert_eq!(res.distance, Some(2));
    let text = journey::render_text(&res, 6);
    assert!(
        text.contains("/products → link \"Cart\" → /cart → link \"Checkout\" → /checkout"),
        "{text}"
    );

    // Label goal marks dead controls.
    let res = journey::journey(&inv, &journey::parse_goal("label:pay", &inv), None, 6);
    let text = journey::render_text(&res, 6);
    assert!(text.contains("\"Pay\" [dead]"), "{text}");

    // Max hops limits reachability.
    let res = journey::journey(&inv, &goal, None, 2);
    assert!(!res.reachable);
}

#[tokio::test]
async fn git_info_and_source_resolution_degrade_gracefully() {
    let repo = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    if !git(&["init", "-q", "-b", "main"]) {
        return; // git unavailable
    }
    std::fs::write(repo.path().join("a.txt"), "x").unwrap();
    assert!(git(&["add", "a.txt"]) && git(&["commit", "-q", "-m", "init"]));

    let dir = tempfile::tempdir().unwrap();
    let spec = spec(vec![view(
        "view_0001",
        "/",
        vec![el("#buy", "Buy", button(), &[("id", "#buy")])],
    )]);
    write_scan(dir.path(), &spec, Some(&[]), &[]);
    let mut o = opts();
    o.codebase = Some(repo.path().to_path_buf());
    o.resolve_sources = true;
    let inv = build(dir.path(), &o).await;
    let info = inv.git.expect("git info");
    assert_eq!(info.commit.len(), 40);
    assert_eq!(info.branch.as_deref(), Some("main"));
    assert!(!info.dirty);
    std::fs::write(repo.path().join("a.txt"), "changed").unwrap();
    assert!(sources::git_info(repo.path()).unwrap().dirty);
    // Source linkers find nothing here; controls simply carry no source.
    assert!(inv.controls.iter().all(|c| c.source.is_none()));
}

/// Dev hook for live checks: builds a real scan directory into a project
/// state dir the way `brokenapp map` does (history, map files, changelog).
///
/// ```text
/// BROKENAPP_INVENTORY_SCAN=<scan dir> BROKENAPP_INVENTORY_STATE=<dir>/.brokenapp \
///   [BROKENAPP_INVENTORY_TARGET=<url>] [BROKENAPP_INVENTORY_CHECK_LINKS=1] \
///   [BROKENAPP_INVENTORY_CODEBASE=<repo>] \
///   cargo test --lib inventory::tests::live_scan_dir -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "needs BROKENAPP_INVENTORY_SCAN / BROKENAPP_INVENTORY_STATE"]
async fn live_scan_dir() {
    let (Ok(scan), Ok(state)) = (
        std::env::var("BROKENAPP_INVENTORY_SCAN"),
        std::env::var("BROKENAPP_INVENTORY_STATE"),
    ) else {
        return;
    };
    let state = std::path::PathBuf::from(state);
    let codebase = std::env::var("BROKENAPP_INVENTORY_CODEBASE")
        .ok()
        .map(std::path::PathBuf::from);
    let opts = BuildOptions {
        project: std::env::var("BROKENAPP_INVENTORY_NAME").unwrap_or_else(|_| "live".into()),
        target_url: std::env::var("BROKENAPP_INVENTORY_TARGET").unwrap_or_default(),
        resolve_sources: codebase.is_some(),
        codebase,
        check_links: std::env::var("BROKENAPP_INVENTORY_CHECK_LINKS").is_ok_and(|v| v == "1"),
        ..Default::default()
    };
    let started = std::time::Instant::now();
    let inv = build_from_scan_dir(Path::new(&scan), &opts).await.unwrap();
    let elapsed = started.elapsed();
    let history = state.join("history");
    let latest = history.join("latest.inventory.json");
    let prev = load(&latest).ok();
    let changes = diff(prev.as_ref(), &inv);
    let stamp = inv.generated_at.replace([':', '-'], "");
    save(&inv, &history.join(format!("{stamp}.inventory.json"))).unwrap();
    save(&inv, &latest).unwrap();
    let map_dir = state.join("map");
    write_map(&inv, &map_dir).unwrap();
    append_changelog(&changes, &inv, &map_dir.join("CHANGELOG.md")).unwrap();
    let config = state.join("config.toml");
    if !config.exists() {
        std::fs::write(
            &config,
            format!(
                "[project]\nname = \"{}\"\nurl = \"{}\"\n",
                inv.project, inv.target_url
            ),
        )
        .unwrap();
    }
    let mut by_status = std::collections::BTreeMap::new();
    for c in &inv.controls {
        *by_status.entry(c.status.as_str()).or_insert(0) += 1;
    }
    println!(
        "built in {elapsed:?}: {} controls {:?}, {} routes ({} visited), {} endpoints; changes {:?}",
        inv.controls.len(),
        by_status,
        inv.routes.len(),
        inv.coverage.routes_visited,
        inv.endpoints.len(),
        changes.summary
    );
}

#[test]
fn render_ui_map_html_embeds_inventory() {
    let inv = inv_with(vec![], &["/"], &[], "2026-10-31T00:00:00Z");
    let html = crate::inventory::render::render_ui_map_html(&inv);
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("BrokenApp Interactive UI Map"));
    assert!(html.contains(r#"<script id="inventory-data" type="application/json">"#));
}

#[test]
fn render_ui_map_html_words_cells_like_the_markdown() {
    let mut broken = ctl(
        "/checkout",
        "text=apply",
        "Apply",
        ControlStatus::Broken,
        vec![Outcome::Calls {
            endpoint: "GET /api/coupons/:code".into(),
            status: Some(500),
            blocked: false,
        }],
    );
    broken.source = Some(ResolvedSource {
        handler: Some(FileLine {
            file: "app/checkout/coupon.tsx".into(),
            line: 58,
            col: 0,
        }),
        method: "runtime".into(),
        confidence: "exact".into(),
        ..Default::default()
    });
    let dead = ctl(
        "/checkout",
        "text=gift wrap",
        "Gift wrap",
        ControlStatus::Dead,
        vec![],
    );
    let inv = inv_with(
        vec![broken, dead],
        &["/checkout"],
        &[],
        "2026-11-25T00:00:00Z",
    );
    let html = crate::inventory::render::render_ui_map_html(&inv);

    let start = html
        .find(r#"<script id="inventory-text" type="application/json">"#)
        .expect("text block is embedded");
    let rest = &html[start..];
    let body = &rest[rest.find('>').unwrap() + 1..rest.find("</script>").unwrap()];
    let cells: Vec<[String; 2]> = serde_json::from_str(body).expect("text block is JSON");

    // One [does, source] pair per control, in inventory order, in the same
    // words UI-MAP.md uses.
    assert_eq!(cells.len(), inv.controls.len());
    for (cell, c) in cells.iter().zip(&inv.controls) {
        assert_eq!(cell[0], crate::inventory::render::describe_does(c));
        assert_eq!(
            cell[1],
            crate::inventory::render::source_text(c.source.as_ref())
        );
    }
    assert_eq!(cells[0][0], "calls GET /api/coupons/:code (500)");
    assert_eq!(cells[0][1], "handler app/checkout/coupon.tsx:58");
    assert_eq!(
        cells[1][0],
        "nothing (no navigation, request, or DOM change)"
    );
    assert_eq!(cells[1][1], "");
    // The script reads the rendered text, not raw outcome fields.
    assert!(html.contains("esc(c.does_text)"));
    assert!(html.contains("esc(c.source_text)"));
}
