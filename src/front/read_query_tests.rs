//! Saved-map query regressions; no running app or browser is needed.

use super::*;
use crate::code_link::runtime_source::{FileLine, ResolvedSource};
use crate::front::{FrontCommand, roles::RoleConfig};
use crate::inventory::{CoverageSummary, Outcome, RouteEntry};
use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: FrontCommand,
}

fn args(flags: &[&str]) -> UiArgs {
    let argv = ["brokenapp", "ui"].into_iter().chain(flags.iter().copied());
    let FrontCommand::Ui(args) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected ui");
    };
    args
}

fn control(route: &str, label: &str) -> Control {
    Control {
        key: format!("{route}|button|text={label}"),
        route: route.into(),
        role: "button".into(),
        label: label.into(),
        selector: format!("[data-testid={label}]"),
        locator: format!("text={label}"),
        count: 1,
        status: ControlStatus::Ok,
        ..Default::default()
    }
}

fn fixture() -> Inventory {
    let routes = [
        "/account",
        "/account/settings",
        "/orders/review",
        "/orders/:id",
    ];
    let mut payout = control("/account", "payout");
    payout.variants = vec!["?tab=payout".into()];
    let mut payments = control("/account", "payments");
    payments.variants = vec!["?tab=payments".into()];
    let mut order = control("/orders/:id", "record");
    order.variants = vec!["/orders/42?tab=shipping".into()];
    let mut shell = control("*", "shared");
    shell.routes = routes.iter().map(|r| r.to_string()).collect();
    let mut nav = control("/account", "navigation");
    nav.region = "nav".into();
    Inventory {
        schema: inventory::INVENTORY_SCHEMA.into(),
        project: "query-fixture".into(),
        generated_at: "2026-10-23T00:00:00Z".into(),
        target_url: "http://127.0.0.1:1/".into(),
        coverage: CoverageSummary {
            routes_known: 4,
            routes_visited: 4,
            controls_total: 7,
            controls_exercised: 7,
            ..Default::default()
        },
        routes: routes
            .iter()
            .map(|route| RouteEntry {
                route: route.to_string(),
                visited: true,
                variants: match *route {
                    "/account" => vec!["?tab=payout".into(), "?tab=payments".into()],
                    "/orders/:id" => vec!["/orders/42?tab=shipping".into()],
                    _ => vec![],
                },
                ..Default::default()
            })
            .collect(),
        controls: vec![
            payout,
            payments,
            control("/account/settings", "settings"),
            control("/orders/review", "review"),
            order,
            shell,
            nav,
        ],
        ..Default::default()
    }
}

fn labels(inv: &Inventory, flags: &[&str]) -> Vec<String> {
    filter(inv, &args(flags), None)
        .unwrap()
        .apply(inv)
        .into_iter()
        .map(|c| c.label.clone())
        .collect()
}

#[test]
fn query_cli_defaults_and_json_detection_remain_compatible() {
    let a = args(&[]);
    assert!(!a.exact_route && !a.exclude_shell && !a.compact && !a.json);
    assert_eq!(a.format, "table");
    assert!(Cli::try_parse_from(["brokenapp", "ui", "--exact-route"]).is_err());
    for flags in [vec!["--compact"], vec!["--json"], vec!["--format", "json"]] {
        assert!(FrontCommand::Ui(args(&flags)).wants_json());
    }
    assert!(!FrontCommand::Ui(a).wants_json());
    let (kind, role) = ui_selection(&args(&["--role", "button"]));
    assert_eq!(kind.as_deref(), Some("button"));
    assert_eq!(role, RoleSel::One(ANONYMOUS_ROLE.into()));
}

#[test]
fn exact_route_drops_descendants_but_keeps_static_priority() {
    let inv = fixture();
    assert_eq!(
        labels(&inv, &["--route", "/account"]),
        ["payout", "payments", "settings", "shared", "navigation"]
    );
    assert_eq!(
        labels(&inv, &["--route", "/account/", "--exact-route"]),
        ["payout", "payments", "shared", "navigation"]
    );
    assert_eq!(
        labels(&inv, &["--route", "/orders/review", "--exact-route"]),
        ["review", "shared"]
    );
    assert_eq!(
        labels(&inv, &["--route", "/orders/:id", "--exact-route"]),
        ["record", "shared"]
    );
    assert!(labels(&inv, &["--route", "/orders", "--exact-route"]).is_empty());
    assert_eq!(
        labels(&inv, &["--route", "/orders"]),
        ["review", "record", "shared"]
    );
}

#[test]
fn exact_route_preserves_record_and_query_state_evidence() {
    let inv = fixture();
    for (route, expected, observed) in [
        (
            "/account?tab=payout",
            vec!["payout", "shared", "navigation"],
            true,
        ),
        ("/account?tab=unknown", vec![], false),
        ("/orders/42?tab=shipping", vec!["record", "shared"], true),
        ("/orders/42?tab=unknown", vec![], false),
        ("/orders/43", vec![], false),
    ] {
        assert_eq!(
            labels(&inv, &["--route", route, "--exact-route"]),
            expected,
            "{route}"
        );
        let f = filter(&inv, &args(&["--route", route, "--exact-route"]), None).unwrap();
        assert_eq!(f.requested_state_observed(&inv), Some(observed), "{route}");
    }
    assert_eq!(
        filter(&inv, &args(&["--route", "/orders"]), None)
            .unwrap()
            .requested_state_observed(&inv),
        None
    );
}

#[test]
fn exact_queries_keep_mixed_state_entry_alternatives_scoped() {
    use crate::inventory::{ControlStateEntry, ControlStateEntryKind};
    let route = "/receiving";
    let entry = |route: &str, variant: Option<&str>, kind| ControlStateEntry {
        route: route.into(),
        variant: variant.map(str::to_string),
        kind,
    };
    let mut conditional = control(route, "count-form");
    conditional.state_entries = vec![
        entry(
            route,
            None,
            ControlStateEntryKind::Opened {
                opener: "/receiving|button|text=open & count".into(),
            },
        ),
        entry(
            route,
            Some("?shipment=three"),
            ControlStateEntryKind::Direct,
        ),
    ];
    // The old flattened fields cannot express this OR; they remain empty.
    assert!(conditional.variants.is_empty() && conditional.opened_by.is_empty());
    let mut other = control(route, "other-record");
    other.state_entries = vec![entry(
        route,
        Some("?shipment=four"),
        ControlStateEntryKind::Direct,
    )];
    let mut unknown = control(route, "unknown");
    unknown.state_entries = vec![entry(
        route,
        Some("?shipment=three"),
        ControlStateEntryKind::Unknown,
    )];
    let mut wrong_route = control(route, "different-route");
    wrong_route.state_entries = vec![entry(
        "/elsewhere",
        Some("?shipment=three"),
        ControlStateEntryKind::Direct,
    )];
    let inv = Inventory {
        routes: vec![RouteEntry {
            route: route.into(),
            visited: true,
            variants: vec!["?shipment=three".into(), "?shipment=four".into()],
            ..Default::default()
        }],
        controls: vec![
            conditional.clone(),
            other,
            unknown,
            wrong_route,
            control(route, "legacy-shared"),
        ],
        ..Default::default()
    };
    for (request, expected) in [
        (
            "/receiving?shipment=three",
            vec!["count-form", "legacy-shared"],
        ),
        (
            "/receiving?shipment=four",
            vec!["other-record", "legacy-shared"],
        ),
        ("/receiving?shipment=unknown", vec![]),
    ] {
        assert_eq!(
            labels(&inv, &["--route", request, "--exact-route"]),
            expected
        );
    }
    assert_eq!(labels(&inv, &["--route", route, "--exact-route"]).len(), 5);
    let compact = compact_control(&inv, &conditional).unwrap();
    assert_eq!(compact["state_entries"], json!(conditional.state_entries));
    assert!(
        compact_control(&inv, &inv.controls[4])
            .unwrap()
            .get("state_entries")
            .is_none()
    );
}

#[test]
fn exact_record_queries_do_not_borrow_other_entry_contexts() {
    use crate::inventory::{ControlStateEntry, ControlStateEntryKind};
    let mut inv = fixture();
    let route = "/orders/:id";
    inv.routes
        .iter_mut()
        .find(|r| r.route == route)
        .unwrap()
        .variants = vec![
        "/orders/42?tab=shipping".into(),
        "/orders/43?tab=shipping".into(),
    ];
    let mut c = control("*", "record-entry");
    c.routes = vec![route.into(), "/account".into()];
    c.state_entries = vec![ControlStateEntry {
        route: route.into(),
        variant: Some("/orders/42?tab=shipping".into()),
        kind: ControlStateEntryKind::Direct,
    }];
    inv.controls = vec![c];
    assert_eq!(
        labels(
            &inv,
            &["--route", "/orders/42?tab=shipping", "--exact-route"]
        ),
        ["record-entry"]
    );
    assert!(
        labels(
            &inv,
            &["--route", "/orders/43?tab=shipping", "--exact-route"]
        )
        .is_empty()
    );
    assert!(labels(&inv, &["--route", "/account?tab=shipping", "--exact-route"]).is_empty());
}

#[test]
fn exact_hash_routes_keep_alias_and_query_checks() {
    let mut inv = fixture();
    inv.routes = vec![RouteEntry {
        route: "/#/account".into(),
        visited: true,
        variants: vec!["?tab=payout".into()],
        ..Default::default()
    }];
    let mut payout = control("/#/account", "hash-payout");
    payout.variants = vec!["?tab=payout".into()];
    inv.controls = vec![payout, control("/#/account/settings", "nested")];
    assert_eq!(
        labels(&inv, &["--route", "/account?tab=payout", "--exact-route"]),
        ["hash-payout"]
    );
    assert_eq!(
        labels(&inv, &["--route", "/#/account", "--exact-route"]),
        ["hash-payout"]
    );
    assert!(labels(&inv, &["--route", "/account?tab=other", "--exact-route"]).is_empty());
}

#[test]
fn exclude_shell_handles_global_and_route_landmarks_without_changing_default() {
    let mut inv = fixture();
    for region in ["header", "footer", "aside", "main", "dialog"] {
        let mut c = control("/account", region);
        c.region = region.into();
        inv.controls.push(c);
    }
    assert_eq!(
        labels(
            &inv,
            &["--route", "/account", "--exact-route", "--exclude-shell"]
        ),
        ["payout", "payments", "main", "dialog"]
    );
    assert_eq!(labels(&inv, &["--route", "*"]), ["shared"]);
    assert!(labels(&inv, &["--route", "*", "--exclude-shell"]).is_empty());
    let f = filter(&inv, &args(&["--exclude-shell"]), None).unwrap();
    assert!(!f.matches(&inv.controls[5]));
    assert!(!f.matches(&inv.controls[6]));
    assert!(f.matches(&inv.controls[0]));
}

#[test]
fn compact_json_retains_keys_uncertainty_variants_and_all_source_candidates() {
    let mut inv = fixture();
    let c = &mut inv.controls[0];
    c.status = ControlStatus::NotExercised;
    c.reason = Some("view_time_budget".into());
    c.opened_by = vec!["/account|tab|text=payout".into()];
    c.outcomes = vec![Outcome::Calls {
        endpoint: "POST /api/payout".into(),
        status: None,
        blocked: true,
    }];
    c.source = Some(ResolvedSource {
        confidence: "ambiguous".into(),
        method: "static".into(),
        candidates: vec![
            FileLine {
                file: "src/a.tsx".into(),
                line: 10,
                col: 0,
            },
            FileLine {
                file: "src/b.tsx".into(),
                line: 20,
                col: 0,
            },
        ],
        ..Default::default()
    });
    let raw = ui_output(
        &inv,
        &args(&[
            "--route",
            "/account?tab=payout",
            "--text",
            "payout",
            "--compact",
        ]),
    )
    .unwrap();
    assert_eq!(raw.lines().count(), 1);
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(doc["count"], 1);
    assert_eq!(doc["business_result_verified"], false);
    assert_eq!(doc["coverage"]["routes_known"], inv.coverage.routes_known);
    assert_eq!(
        doc["coverage"]["controls_exercised"],
        inv.coverage.controls_exercised
    );
    assert!(doc["coverage"].get("not_exercised_by_reason").is_none());
    assert_eq!(doc["route_summaries"].as_array().unwrap().len(), 1);
    let row = &doc["controls"][0];
    assert_eq!(row["key"], inv.controls[0].key);
    assert_eq!(row["variants"], json!(["?tab=payout"]));
    assert_eq!(row["reason"], "view_time_budget");
    assert_eq!(row["source"]["confidence"], "ambiguous");
    assert_eq!(row["source"]["candidates"].as_array().unwrap().len(), 2);
    assert_eq!(row["outcomes"][0]["blocked"], true);
    assert!(row.get("evidence").is_none());
    assert!(row.get("does").is_none());
    assert!(row.get("coverage").is_none());
    assert!(row.get("selector").is_none());
    let full: serde_json::Value =
        serde_json::from_str(&ui_output(&inv, &args(&["--json"])).unwrap()).unwrap();
    assert_eq!(full["controls"][0]["selector"], inv.controls[0].selector);
    assert!(full.get("target_url").is_some());
}

#[test]
fn compact_missing_state_retains_route_context_without_claiming_state_observed() {
    let inv = fixture();
    for (route, observed) in [
        ("/orders/43", false),
        ("/orders/42", true),
        ("/account?tab=unknown", false),
        ("/account?tab=payout", true),
    ] {
        let doc: serde_json::Value = serde_json::from_str(
            &ui_output(
                &inv,
                &args(&[
                    "--route",
                    route,
                    "--exact-route",
                    "--exclude-shell",
                    "--compact",
                ]),
            )
            .unwrap(),
        )
        .unwrap();
        if !observed {
            assert_eq!(doc["count"], 0);
        }
        assert_eq!(doc["query"]["requested_state_observed"], observed);
        assert_eq!(doc["query"]["exact_route"], true);
        assert_eq!(doc["query"]["exclude_shell"], true);
        assert!(doc["query"].get("text").is_none());
        assert_eq!(doc["route_summaries"].as_array().unwrap().len(), 1);
        assert_eq!(doc["coverage"]["routes_known"], inv.coverage.routes_known);
        assert_eq!(doc["business_result_verified"], false);
        assert!(
            doc["evidence_limits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().contains("saved map before filters"))
        );
        let summary = &doc["route_summaries"][0];
        assert!(summary.get("scope").is_none());
        assert!(summary.get("limitations").is_none());
        assert!(summary.get("login_role").is_none());
    }
}

#[test]
fn compact_all_roles_keeps_one_coverage_per_map_and_no_row_role_repetition() {
    let maps = vec![("seller".into(), fixture()), ("receiver".into(), fixture())];
    let raw = ui_output_roles(&maps, &args(&["--compact"]), None, true).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let roles = doc["roles"].as_array().unwrap();
    assert_eq!(roles.len(), 2);
    assert_eq!(raw.matches("\"coverage\":").count(), 2);
    assert_eq!(raw.matches("\"business_result_verified\":").count(), 1);
    assert_eq!(doc["business_result_verified"], false);
    for (role, expected) in roles.iter().zip(["seller", "receiver"]) {
        assert_eq!(role["login_role"], expected);
        assert!(role.get("business_result_verified").is_none());
        assert!(
            role["controls"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row.get("login_role").is_none())
        );
    }
}

#[test]
fn compact_json_hoists_caveats_omits_empty_fields_and_stays_token_slim() {
    let mut cart_checkout = control("/cart", "Checkout");
    cart_checkout.outcomes = vec![Outcome::Calls {
        endpoint: "POST /api/checkout".into(),
        status: None,
        blocked: true,
    }];
    cart_checkout.source = Some(ResolvedSource {
        method: "static".into(),
        confidence: "probable".into(),
        render: Some(FileLine {
            file: "src/cart.tsx".into(),
            line: 42,
            col: 0,
        }),
        ..Default::default()
    });
    let mut cart_qty = control("/cart", "Quantity");
    cart_qty.role = "input".into();
    cart_qty.key = "/cart|input|text=quantity".into();
    cart_qty.reason = Some("focus_only".into());
    let mut cart_continue = control("/cart", "Continue shopping");
    cart_continue.role = "link".into();
    cart_continue.key = "/cart|link|text=continue shopping".into();
    cart_continue.outcomes = vec![Outcome::Navigates {
        to: "/products".into(),
    }];

    let inv = Inventory {
        schema: inventory::INVENTORY_SCHEMA.into(),
        project: "shop".into(),
        generated_at: "2026-10-23T00:00:00Z".into(),
        target_url: "http://127.0.0.1:3000/".into(),
        write_guard: "block".into(),
        coverage: CoverageSummary {
            routes_known: 2,
            routes_visited: 2,
            controls_total: 3,
            controls_exercised: 3,
            controls_exercisable: 3,
            ..Default::default()
        },
        routes: vec![RouteEntry {
            route: "/cart".into(),
            visited: true,
            status: Some(200),
            controls: 3,
            ..Default::default()
        }],
        controls: vec![cart_checkout, cart_qty, cart_continue],
        ..Default::default()
    };

    let raw = ui_output(
        &inv,
        &args(&["--route", "/cart", "--exact-route", "--compact"]),
    )
    .unwrap();
    // 3 controls on /cart used to emit ~2.3-2.6 KB; keep it lean (< 1.35 KB, >50% smaller).
    assert!(
        raw.len() < 1350,
        "compact 3-control output bloated ({} bytes): {raw}",
        raw.len()
    );
    // Repeated per-control / per-route boilerplate must never come back.
    for banned in [
        "not_verified_by_this_observation",
        "saved_route_context",
        "all_saved_variants_before_query_filters",
        "source_basis",
        "\"variants\":[]",
        "\"labels\":[]",
        "\"state_entries\":[]",
        "\"candidates\":[]",
        "\"state_observations\":[]",
        "\"gaps_by_reason\":{}",
        "\"blocked\":false",
        "\"text\":null",
        "\"status\":null",
        "\"calls\":null",
    ] {
        assert!(
            !raw.contains(banned),
            "compact JSON should not contain boilerplate/empty field {banned:?}: {raw}"
        );
    }
    assert_eq!(raw.matches("\"business_result_verified\":").count(), 1);
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(doc["business_result_verified"], false);
    assert_eq!(doc["count"], 3);
    // Blocked write is already conveyed by outcomes[0].blocked == true without repeating observation.
    assert_eq!(doc["controls"][0]["outcomes"][0]["blocked"], true);
    assert!(doc["controls"][0].get("observation").is_none());
    // Non-obvious epistemic caveats remain attached to the specific control.
    assert_eq!(
        doc["controls"][1]["observation"],
        "focus_only_input_not_tested"
    );
    // Ordinary observable-effect controls do not repeat redundant observation prose.
    assert!(doc["controls"][2].get("observation").is_none());

    // Timeout controls retain their inconclusive_timeout observation flag.
    let mut timeout_ctl = control("/cart", "Slow submit");
    timeout_ctl.status = ControlStatus::Broken;
    timeout_ctl.reason = Some("interaction_timeout: no response".into());
    let timeout_row = compact_control(&inv, &timeout_ctl).unwrap();
    assert_eq!(timeout_row["observation"], "inconclusive_timeout");

    // Scaling check: adding 10 controls should not duplicate caveats per control.
    let mut big = inv.clone();
    for i in 0..10 {
        let mut c = control("/cart", &format!("Item {i}"));
        c.outcomes = vec![Outcome::Calls {
            endpoint: format!("GET /api/items/{i}"),
            status: Some(200),
            blocked: false,
        }];
        big.controls.push(c);
    }
    let big_raw = ui_output(
        &big,
        &args(&["--route", "/cart", "--exact-route", "--compact"]),
    )
    .unwrap();
    assert_eq!(big_raw.matches("\"business_result_verified\":").count(), 1);
    assert!(!big_raw.contains("\"blocked\":false"));
    let per_added_control = (big_raw.len() - raw.len()) / 10;
    assert!(
        per_added_control < 180,
        "marginal bytes per control too high ({per_added_control} bytes)"
    );
    let full_raw = ui_output(
        &big,
        &args(&["--route", "/cart", "--exact-route", "--json"]),
    )
    .unwrap();
    assert!(
        big_raw.len() * 10 < full_raw.len() * 6,
        "compact ({} bytes) should be under 60% of full JSON ({} bytes)",
        big_raw.len(),
        full_raw.len()
    );
}

#[test]
fn compact_text_search_limits_route_context_and_deduplicates_evidence_limits() {
    let inv = fixture();
    let read = |flags: &[&str]| -> serde_json::Value {
        serde_json::from_str(&ui_output(&inv, &args(flags)).unwrap()).unwrap()
    };
    let narrowed = read(&["--text", "payout", "--compact"]);
    assert_eq!(narrowed["count"], 1);
    assert_eq!(narrowed["route_summaries"].as_array().unwrap().len(), 1);
    assert_eq!(narrowed["route_summaries"][0]["route"], "/account");
    assert_eq!(narrowed["query"]["text"], "payout");
    let all = read(&["--compact"]);
    assert_eq!(all["route_summaries"].as_array().unwrap().len(), 4);
    let limits = all["evidence_limits"].as_array().unwrap();
    assert!(!limits.is_empty());
    assert!(
        all["route_summaries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row.get("limitations").is_none())
    );
    assert_eq!(
        limits.len(),
        limits
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    assert!(
        read(&["--text", "does-not-exist", "--compact"])["route_summaries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        read(&[
            "--route",
            "/account",
            "--text",
            "does-not-exist",
            "--compact"
        ])["route_summaries"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "an explicit prefix keeps both matching route contexts despite no controls"
    );
}

#[test]
fn missing_anonymous_map_points_to_existing_role_without_silent_selection() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = ProjectCtx {
        state_dir: temp.path().join(".brokenapp"),
        root: temp.path().into(),
        config_path: temp.path().join(".brokenapp/config.toml"),
        config: project::ProjectConfig {
            project: project::ProjectSection {
                name: "query-fixture".into(),
                ..Default::default()
            },
            roles: vec![
                RoleConfig {
                    name: "seller".into(),
                    ..Default::default()
                },
                RoleConfig {
                    name: "unmapped".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    };
    let mut inv = fixture();
    inv.role = Some("seller".into());
    inventory::save(&inv, &ctx.role_paths("seller").latest_inventory_path()).unwrap();
    let error = load_maps(&ctx, &role_sel(None)).unwrap_err().to_string();
    assert!(error.contains("no anonymous UI map"), "{error}");
    assert!(error.contains("Saved role maps: seller"), "{error}");
    assert!(
        error.contains("--role seller") && error.contains("--role all"),
        "{error}"
    );
    assert!(
        !error.contains("unmapped") && !error.contains("Run `brokenapp map`"),
        "{error}"
    );
    assert_eq!(
        load_maps(&ctx, &role_sel(Some("seller"))).unwrap()[0].0,
        "seller"
    );
    assert_eq!(load_maps(&ctx, &RoleSel::All).unwrap().len(), 1);
}

#[test]
fn compact_query_loads_bound_review_without_rewriting_the_saved_map() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = ProjectCtx {
        state_dir: temp.path().join(".brokenapp"),
        root: temp.path().into(),
        config_path: temp.path().join(".brokenapp/config.toml"),
        config: project::ProjectConfig::default(),
    };
    let inv = fixture();
    let paths = ctx.role_paths(ANONYMOUS_ROLE);
    let inventory_path = paths.latest_inventory_path();
    inventory::save(&inv, &inventory_path).unwrap();
    let before = std::fs::read(&inventory_path).unwrap();
    let mut sidecar = json!({
        "schema": evidence::ANNOTATIONS_SCHEMA,
        "inventory_sha256": evidence::inventory_sha256(&before),
        "role": null, "surface": "web", "environment": "isolated fixture",
        "fixture": "empty payout account", "limitations": ["No business write verified."],
        "routes": [{ "route": "/account", "variant": "?tab=payout", "state": "empty",
            "basis": "reviewed_join", "observation_note": "No payout account in this fixture.",
            "evidence": [{ "kind": "inventory", "path": "latest.inventory.json" },
                { "kind": "source", "path": "src/account.tsx", "locator": "empty payout branch" }] }],
    });
    std::fs::create_dir_all(&paths.map_dir).unwrap();
    let annotation_path = paths.map_dir.join(evidence::ANNOTATIONS_FILE);
    std::fs::write(&annotation_path, serde_json::to_vec(&sidecar).unwrap()).unwrap();
    let maps = load_maps(&ctx, &role_sel(None)).unwrap();
    let raw = ui_output_roles(
        &maps,
        &args(&["--route", "/account?tab=payout", "--compact"]),
        None,
        false,
    )
    .unwrap();
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(doc["context"]["fixture"], "empty payout account");
    assert_eq!(
        doc["route_summaries"][0]["state_observations"][0]["state"],
        "empty"
    );
    assert_eq!(std::fs::read(&inventory_path).unwrap(), before);
    sidecar["inventory_sha256"] = json!("0".repeat(64));
    std::fs::write(annotation_path, serde_json::to_vec(&sidecar).unwrap()).unwrap();
    assert!(
        load_maps(&ctx, &role_sel(None))
            .unwrap_err()
            .to_string()
            .contains("hash mismatch")
    );
}

#[test]
fn saved_source_reviews_are_labeled_in_full_and_compact_queries_without_archive_writes() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = ProjectCtx {
        state_dir: temp.path().join(".brokenapp"),
        root: temp.path().into(),
        config_path: temp.path().join(".brokenapp/config.toml"),
        config: project::ProjectConfig::default(),
    };
    let source = |file: &str| ResolvedSource {
        method: "static".into(),
        confidence: "probable".into(),
        render: Some(FileLine {
            file: file.into(),
            line: 12,
            col: 0,
        }),
        ..Default::default()
    };
    let mut inv = fixture();
    inv.controls[0].source = Some(source("src/old.tsx"));
    inv.controls[1].source = Some(source("src/withdrawn.tsx"));
    let paths = ctx.role_paths(ANONYMOUS_ROLE);
    let inventory_path = paths.latest_inventory_path();
    inventory::save(&inv, &inventory_path).unwrap();
    let before = std::fs::read(&inventory_path).unwrap();
    let reviews = evidence::SourceReviews {
        schema: "brokenapp.source-attribution-review.v1".into(),
        inventory_sha256: evidence::inventory_sha256(&before),
        role: None,
        resolver_sha256: "a".repeat(64),
        source_snapshot_sha256: "b".repeat(64),
        source_root: temp.path().to_string_lossy().into_owned(),
        controls: vec![
            evidence::ControlSourceReview {
                key: inv.controls[0].key.clone(),
                original_source: inv.controls[0].source.clone(),
                resolved_source: Some(source("src/reviewed.tsx")),
            },
            evidence::ControlSourceReview {
                key: inv.controls[1].key.clone(),
                original_source: inv.controls[1].source.clone(),
                resolved_source: None,
            },
            evidence::ControlSourceReview {
                key: inv.controls[2].key.clone(),
                original_source: None,
                resolved_source: Some(source("src/settings.tsx")),
            },
        ],
    };
    std::fs::create_dir_all(&paths.map_dir).unwrap();
    std::fs::write(
        paths.map_dir.join("source-attribution.json"),
        serde_json::to_vec(&reviews).unwrap(),
    )
    .unwrap();
    let maps = load_maps(&ctx, &role_sel(None)).unwrap();
    for flags in [vec!["--json"], vec!["--compact"]] {
        let raw = ui_output_roles(&maps, &args(&flags), None, false).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            doc["source_review_provenance"]["resolver_sha256"],
            "a".repeat(64)
        );
        assert_eq!(
            doc["source_review_provenance"]["basis"],
            "static_recomputation_not_new_runtime_capture"
        );
        assert_eq!(
            doc["controls"][0]["recorded_source"]["render"]["file"],
            "src/old.tsx"
        );
        assert_eq!(
            doc["controls"][0]["source"]["render"]["file"],
            "src/reviewed.tsx"
        );
        assert_eq!(doc["controls"][1]["source"], serde_json::Value::Null);
        assert!(
            doc["controls"][1].get("source").is_some(),
            "withdrawn attribution is explicitly null"
        );
        assert_eq!(
            doc["controls"][2]["recorded_source"],
            serde_json::Value::Null
        );
        assert!(
            doc["controls"][2].get("recorded_source").is_some(),
            "new static candidate retains recorded unknown"
        );
        assert!(doc["controls"][3].get("recorded_source").is_none());
    }
    let all: serde_json::Value =
        serde_json::from_str(&ui_output_roles(&maps, &args(&["--json"]), None, true).unwrap())
            .unwrap();
    assert_eq!(
        all["roles"][0]["source_review_provenance"]["reviewed_controls"],
        3
    );
    let mut findings = maps[0].1.clone();
    findings.controls[0].status = ControlStatus::Broken;
    findings.controls[1].status = ControlStatus::NoEffect;
    let dead: serde_json::Value =
        serde_json::from_str(&dead_output(&findings, true, true).unwrap()).unwrap();
    assert_eq!(dead["source_review_provenance"]["reviewed_controls"], 3);
    assert_eq!(
        dead["broken"][0]["recorded_source"]["render"]["file"],
        "src/old.tsx"
    );
    assert_eq!(
        dead["broken"][0]["source"]["render"]["file"],
        "src/reviewed.tsx"
    );
    assert_eq!(
        dead["no_effect"][0]["recorded_source"]["render"]["file"],
        "src/withdrawn.tsx"
    );
    assert_eq!(dead["no_effect"][0]["source"], serde_json::Value::Null);
    let history = load_recorded_maps(&ctx, &role_sel(None)).unwrap();
    assert!(history[0].1.source_reviews.is_none());
    assert_eq!(history[0].1.controls, inv.controls);
    assert!(
        inventory::diff(Some(&inv), &history[0].1)
            .changes
            .is_empty()
    );
    assert_eq!(std::fs::read(inventory_path).unwrap(), before);
    assert_eq!(
        inv.controls[0]
            .source
            .as_ref()
            .unwrap()
            .render
            .as_ref()
            .unwrap()
            .file,
        "src/old.tsx"
    );
}
