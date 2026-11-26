use std::fs;
use std::path::Path;
use std::process::Command;

use brokenapp::inventory::{
    Control, ControlStatus, CoverageSummary, EndpointEntry, IDENTITY_VERSION, INVENTORY_SCHEMA,
    Inventory, Outcome, RouteEntry,
};
use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_brokenapp")
}

fn run_cli(cwd: &Path, home: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin())
        .current_dir(cwd)
        .env("BROKENAPP_HOME", home)
        .args(args)
        .output()
        .expect("run brokenapp");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn make_route(route: &str, visited: bool, status: Option<u16>, reason: Option<&str>) -> RouteEntry {
    RouteEntry {
        route: route.to_string(),
        visited,
        status,
        unvisited_reason: reason.map(str::to_string),
        ..Default::default()
    }
}

fn make_control(
    key: &str,
    route: &str,
    role: &str,
    label: &str,
    locator: &str,
    status: ControlStatus,
    outcomes: Vec<Outcome>,
    reason: Option<&str>,
) -> Control {
    Control {
        key: key.to_string(),
        route: route.to_string(),
        role: role.to_string(),
        label: label.to_string(),
        selector: format!("button[data-test=\"{locator}\"]"),
        locator: locator.to_string(),
        count: 1,
        status,
        outcomes,
        reason: reason.map(str::to_string),
        ..Default::default()
    }
}

fn make_inventory(
    generated_at: &str,
    role: Option<&str>,
    routes: Vec<RouteEntry>,
    controls: Vec<Control>,
    endpoints: Vec<EndpointEntry>,
) -> String {
    let routes_visited = routes.iter().filter(|r| r.visited).count() as u32;
    let inv = Inventory {
        schema: INVENTORY_SCHEMA.to_string(),
        identity_version: IDENTITY_VERSION,
        project: "acme-shop".to_string(),
        generated_at: generated_at.to_string(),
        scan_dir: "/tmp/scan".to_string(),
        target_url: "http://127.0.0.1:3000".to_string(),
        role: role.map(str::to_string),
        write_guard: "block".to_string(),
        coverage: CoverageSummary {
            routes_known: routes.len() as u32,
            routes_visited,
            controls_total: controls.len() as u32,
            controls_exercised: controls.len() as u32,
            controls_exercisable: controls.len() as u32,
            ..Default::default()
        },
        routes,
        controls,
        endpoints,
        ..Default::default()
    };
    serde_json::to_string_pretty(&inv).unwrap()
}

fn write_project_with_roles(root: &Path) {
    let state = root.join(".brokenapp");
    fs::create_dir_all(state.join("history/roles/member")).unwrap();
    fs::create_dir_all(state.join("map/roles/member")).unwrap();
    fs::write(
        state.join("config.toml"),
        "[project]\nname = \"acme-shop\"\nurl = \"http://127.0.0.1:3000\"\n\n[[roles]]\nname = \"member\"\nmethod = \"form\"\nlogin_url = \"/login\"\nusername = \"env:MEMBER_EMAIL\"\npassword = \"env:MEMBER_PASS\"\n",
    )
    .unwrap();

    // Anonymous baseline (v1) & regressed (v2): Pay Now becomes dead!
    let anon_v1 = make_inventory(
        "2026-11-20T10:00:00Z",
        None,
        vec![
            make_route("/", true, Some(200), None),
            make_route("/cart", true, Some(200), None),
            make_route("/admin", false, None, Some("redirects to login")),
        ],
        vec![make_control(
            "/cart|button|text=pay now",
            "/cart",
            "button",
            "Pay Now",
            "text=pay now",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "POST /api/orders".to_string(),
                status: None,
                blocked: true,
            }],
            None,
        )],
        vec![EndpointEntry {
            endpoint: "POST /api/orders".to_string(),
            controls: vec!["/cart|button|text=pay now".to_string()],
            write: true,
            ..Default::default()
        }],
    );
    let anon_v2 = make_inventory(
        "2026-11-20T11:00:00Z",
        None,
        vec![
            make_route("/", true, Some(200), None),
            make_route("/cart", true, Some(200), None),
            make_route("/admin", false, None, Some("redirects to login")),
        ],
        vec![make_control(
            "/cart|button|text=pay now",
            "/cart",
            "button",
            "Pay Now",
            "text=pay now",
            ControlStatus::Dead,
            vec![],
            Some("no handler and no observable effect"),
        )],
        vec![],
    );
    fs::write(
        state.join("history/20261120T100000Z.inventory.json"),
        &anon_v1,
    )
    .unwrap();
    fs::write(
        state.join("history/20261120T110000Z.inventory.json"),
        &anon_v2,
    )
    .unwrap();
    fs::write(state.join("history/latest.inventory.json"), &anon_v2).unwrap();

    // Member baseline (v1): /admin forbidden -> v2: /admin visited (RBAC escalation!)
    let member_v1 = make_inventory(
        "2026-11-20T10:00:00Z",
        Some("member"),
        vec![
            make_route("/", true, Some(200), None),
            make_route("/admin", true, Some(403), None),
        ],
        vec![],
        vec![],
    );
    let member_v2 = make_inventory(
        "2026-11-20T11:00:00Z",
        Some("member"),
        vec![
            make_route("/", true, Some(200), None),
            make_route("/admin", true, Some(200), None),
        ],
        vec![],
        vec![],
    );
    fs::write(
        state.join("history/roles/member/20261120T100000Z.inventory.json"),
        &member_v1,
    )
    .unwrap();
    fs::write(
        state.join("history/roles/member/20261120T110000Z.inventory.json"),
        &member_v2,
    )
    .unwrap();
    fs::write(
        state.join("history/roles/member/latest.inventory.json"),
        &member_v2,
    )
    .unwrap();
}

#[test]
fn help_exposes_only_lean_v1_public_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), tmp.path(), &["--help"]);
    assert_eq!(code, 0, "stderr: {stderr}");

    for expected in [
        "init", "map", "ui", "dead", "journey", "changes", "parity", "projects", "doctor", "roles",
        "login",
    ] {
        assert!(
            stdout.contains(expected),
            "expected command `{expected}` in --help:\n{stdout}"
        );
    }

    for removed in [
        "store",
        "serve",
        "idor-scan",
        "compliance-report",
        "exposure-scan",
        "auth-matrix",
        "logic-test",
        "fix-packet",
        "replay-flow",
        "test-flow",
        "open-session",
        "self-check",
    ] {
        assert!(
            !stdout.contains(&format!("  {removed}")),
            "removed legacy command `{removed}` leaked into --help:\n{stdout}"
        );
    }
}

#[test]
fn changes_gate_catches_dead_ui_and_rbac_access_gained_in_markdown_and_json() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write_project_with_roles(tmp.path());

    // Markdown PR comment + CI gate failure
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        home.path(),
        &[
            "changes",
            "--role",
            "all",
            "--fail-on",
            "dead,broken,access-gained",
            "--format",
            "markdown",
        ],
    );
    assert_eq!(
        code, 1,
        "expected exit 1 on dead+access-gained; stderr: {stderr}\nstdout:\n{stdout}"
    );
    assert!(stdout.contains("CI Gate: `FAIL`"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("RBAC Escalation (`ACCESS GAINED`)"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("/admin"), "stdout:\n{stdout}");
    assert!(stdout.contains("Pay Now"), "stdout:\n{stdout}");

    // JSON output includes role_access and gate verdict
    let (code_json, out_json, err_json) = run_cli(
        tmp.path(),
        home.path(),
        &[
            "changes",
            "--role",
            "all",
            "--fail-on",
            "access-gained",
            "--json",
        ],
    );
    assert_eq!(code_json, 1, "stderr: {err_json}");
    let parsed: Value = serde_json::from_str(&out_json).expect("valid json");
    assert_eq!(parsed["gate"]["passed"], false);
    assert_eq!(parsed["role_access"]["changes"][0]["kind"], "access_gained");
    assert_eq!(parsed["role_access"]["changes"][0]["role"], "member");
    assert_eq!(parsed["role_access"]["changes"][0]["route"], "/admin");

    // Non-triggered gate passes with exit 0
    let (code_pass, _, err_pass) = run_cli(
        tmp.path(),
        home.path(),
        &["changes", "--role", "all", "--fail-on", "broken"],
    );
    assert_eq!(
        code_pass, 0,
        "expected exit 0 when only --fail-on broken; stderr: {err_pass}"
    );
}

#[test]
fn parity_command_catches_legacy_to_rewrite_regressions_and_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let legacy = tmp.path().join("legacy-map");
    let rewrite = tmp.path().join("rewrite-map");
    fs::create_dir_all(legacy.join("roles/member")).unwrap();
    fs::create_dir_all(rewrite.join("roles/member")).unwrap();

    fs::write(
        legacy.join("ui-inventory.json"),
        make_inventory(
            "2026-11-20T09:00:00Z",
            None,
            vec![
                make_route("/", true, Some(200), None),
                make_route("/invoices", true, Some(200), None),
                make_route("/settings", true, Some(200), None),
            ],
            vec![make_control(
                "/invoices|button|text=export csv",
                "/invoices",
                "button",
                "Export CSV",
                "text=export csv",
                ControlStatus::Ok,
                vec![Outcome::Calls {
                    endpoint: "GET /api/invoices/export".to_string(),
                    status: Some(200),
                    blocked: false,
                }],
                None,
            )],
            vec![EndpointEntry {
                endpoint: "GET /api/invoices/export".to_string(),
                statuses: vec![200],
                ..Default::default()
            }],
        ),
    )
    .unwrap();
    fs::write(
        legacy.join("roles/member/ui-inventory.json"),
        make_inventory(
            "2026-11-20T09:00:00Z",
            Some("member"),
            vec![make_route("/admin", true, Some(403), None)],
            vec![],
            vec![],
        ),
    )
    .unwrap();

    // Rewrite is missing /settings, missing GET /api/invoices/export, and leaks /admin to member!
    fs::write(
        rewrite.join("ui-inventory.json"),
        make_inventory(
            "2026-11-20T12:00:00Z",
            None,
            vec![
                make_route("/", true, Some(200), None),
                make_route("/invoices", true, Some(200), None),
            ],
            vec![],
            vec![],
        ),
    )
    .unwrap();
    fs::write(
        rewrite.join("roles/member/ui-inventory.json"),
        make_inventory(
            "2026-11-20T12:00:00Z",
            Some("member"),
            vec![make_route("/admin", true, Some(200), None)],
            vec![],
            vec![],
        ),
    )
    .unwrap();

    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        home.path(),
        &[
            "parity",
            legacy.to_str().unwrap(),
            rewrite.to_str().unwrap(),
            "--fail-on",
            "missing-route,missing-endpoint,access-gained",
            "--json",
        ],
    );
    assert_eq!(
        code, 1,
        "expected exit 1 on parity failure; stderr: {stderr}\nstdout:\n{stdout}"
    );
    let report: Value = serde_json::from_str(&stdout).expect("valid parity json");
    assert_eq!(report["gate"]["passed"], false);
    assert!(
        report["routes"]["missing_routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "/settings")
    );
    assert!(
        report["endpoints"]["missing_endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "GET /api/invoices/export")
    );
    assert_eq!(report["role_access"]["changes"][0]["kind"], "access_gained");

    // Self-parity against identical baseline passes cleanly (exit 0)
    let (ok_code, _, ok_err) = run_cli(
        tmp.path(),
        home.path(),
        &[
            "parity",
            legacy.to_str().unwrap(),
            legacy.to_str().unwrap(),
            "--fail-on",
            "any",
        ],
    );
    assert_eq!(ok_code, 0, "self-parity should pass: {ok_err}");
}

#[test]
fn doctor_warns_on_legacy_brokenapp_toml_and_init_detects_non_js_stacks() {
    let home = tempfile::tempdir().unwrap();

    // Django project with stray legacy brokenapp.toml
    let django = tempfile::tempdir().unwrap();
    fs::write(django.path().join("manage.py"), "#!/usr/bin/env python3\n").unwrap();
    fs::write(
        django.path().join("brokenapp.toml"),
        "[target]\nurl = \"http://127.0.0.1:8000\"\n",
    )
    .unwrap();

    let (init_code, init_out, init_err) = run_cli(
        django.path(),
        home.path(),
        &["init", "--agent", "none", "--json"],
    );
    assert_eq!(init_code, 0, "django init failed: {init_err}\n{init_out}");
    let init_json: Value = serde_json::from_str(&init_out).expect("init json");
    assert_eq!(init_json["detected"]["framework"], "django");

    let (_doc_code, doc_out, _doc_err) = run_cli(django.path(), home.path(), &["doctor", "--json"]);
    let doc_json: Value = serde_json::from_str(&doc_out).expect("doctor json");
    let has_legacy_warn = doc_json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "legacy_config" && c["status"] == "warn");
    assert!(
        has_legacy_warn,
        "doctor should warn on legacy brokenapp.toml:\n{doc_out}"
    );

    // Compact UI token-slim check
    let shop = tempfile::tempdir().unwrap();
    write_project_with_roles(shop.path());
    let (ui_code, ui_out, ui_err) = run_cli(
        shop.path(),
        home.path(),
        &["ui", "--route", "/cart", "--exact-route", "--compact"],
    );
    assert_eq!(ui_code, 0, "ui --compact failed: {ui_err}");
    let ui_json: Value = serde_json::from_str(&ui_out).expect("compact json");
    assert_eq!(ui_json["business_result_verified"], false);
    assert!(ui_json["controls"][0].get("evidence").is_none());
    assert!(ui_json["controls"][0].get("does").is_none());
}
