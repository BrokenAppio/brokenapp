//! UI-map read commands end to end (no browser): inventories are built from
//! two synthetic scan directories with the library, saved as map history, and
//! read back through the `brokenapp` binary (`changes`, `ui`, `dead`,
//! `journey`). Covers the field-test fixes: label + region identity (a
//! retargeted link is rewired, not removed + added), coverage-aware removals,
//! controls behind a now-broken opener, member-label search, the no-effect
//! section, and unmatched-journey explanations with static code hits.

use std::path::Path;
use std::process::Command;

use brokenapp::inventory::{self, BuildOptions};
use brokenapp::route_discovery::DiscoveredRoute;
use serde_json::{Value, json};

const BASE: &str = "http://127.0.0.1:47999";

fn brokenapp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brokenapp")
}

fn el(path: &str, label: &str, kind: Value) -> Value {
    json!({
        "selector": path,
        "label": label,
        "element_type": kind,
        "found_on": "x",
        "locators": [{"kind": "structural", "value": path, "stability": 0.3, "unique": true}],
    })
}

fn link(href: &str) -> Value {
    json!({"kind": "navigation_link", "href": href})
}

fn button() -> Value {
    json!({"kind": "button", "form_submit": false})
}

fn view(id: &str, route: &str, elements: Vec<Value>) -> Value {
    json!({"id": id, "route": route, "title": route, "elements": elements, "on_load_api_calls": []})
}

fn record(view: &str, route: &str, selector: &str, outcome: &str, extra: Value) -> Value {
    let mut r = json!({
        "schema": "brokenapp.interaction.v1",
        "action_id": format!("{view}-{selector}"),
        "view_id": view,
        "page_url": format!("{BASE}{route}"),
        "selector": selector,
        "element_kind": "button",
        "action": "click",
        "outcome": outcome,
        "started_at": "2026-10-21T10:00:00Z",
        "duration_ms": 200,
    });
    if let (Some(r), Some(extra)) = (r.as_object_mut(), extra.as_object()) {
        r.extend(extra.clone());
    }
    r
}

/// A small site: header nav, footer Terms, a hero CTA, a guide modal on /lab.
fn write_scan(dir: &Path, mutant: bool) {
    std::fs::create_dir_all(dir).unwrap();
    let shell = |terms: &str| {
        vec![
            el(
                "body > header > nav > a:nth-of-type(1)",
                "Lab",
                link("/lab"),
            ),
            el(
                "body > header > nav > a:nth-of-type(2)",
                "About",
                link("/about"),
            ),
            el("body > footer > a", "Terms", link(terms)),
        ]
    };
    let hero = el(
        "body > main > a.hero",
        "Explore universe",
        link(if mutant { "/strategies" } else { "/universe" }),
    );
    let guide = el("body > main > button.guide", "How it works", button());
    let mut home = shell(if mutant { "/legal/terms" } else { "/terms" });
    home.push(hero);
    let mut lab = shell("/terms");
    lab.push(guide);
    let mut views = vec![
        view("view_0001", "/", home),
        view("view_0002", "/lab", lab),
        view("view_0003", "/about", shell("/terms")),
        view("view_0005", "/universe", shell("/terms")),
        view("view_0006", "/strategies", shell("/terms")),
    ];
    let mut records = vec![record(
        "view_0002",
        "/lab",
        "body > main > button.guide",
        if mutant { "error" } else { "dom_change" },
        if mutant {
            json!({"error": format!("Error: guide unavailable @ at onClick ({BASE}/_next/static/chunks/app.js:12:3)")})
        } else {
            json!({"dom_change": "modal"})
        },
    )];
    let mut transitions = Vec::new();
    if !mutant {
        // The guide modal (a sub-view opened by "How it works").
        views.push(view(
            "view_0002:d1:0",
            "/lab",
            vec![el("body > dialog > button", "Read the guide", button())],
        ));
        records.push(record(
            "view_0002:d1:0",
            "/lab",
            "body > dialog > button",
            "dom_change",
            json!({"dom_change": "panel"}),
        ));
        transitions.push(json!({
            "from_view": "view_0002", "to_view": "view_0002:d1:0",
            "trigger": {"view": "view_0002", "selector": "body > main > button.guide"},
            "transition_type": "modal_open"
        }));
        // /pricing is only visited in the base map.
        views.push(view(
            "view_0004",
            "/pricing",
            vec![el("body > main > button", "Compare plans", button())],
        ));
        records.push(record(
            "view_0004",
            "/pricing",
            "body > main > button",
            "no_effect",
            json!({}),
        ));
    }
    let spec = json!({
        "meta": {"target_url": format!("{BASE}/")},
        "application": {"base_url": format!("{BASE}/")},
        "views": views,
        "api_surface": {"endpoints": []},
        "state_machine": {"transitions": transitions},
    });
    std::fs::write(dir.join("spec.json"), spec.to_string()).unwrap();
    let lines: Vec<String> = records.iter().map(Value::to_string).collect();
    std::fs::write(dir.join("interactions.jsonl"), lines.join("\n") + "\n").unwrap();
    std::fs::write(dir.join("network.jsonl"), "").unwrap();
}

fn discovered() -> Vec<DiscoveredRoute> {
    ["/", "/lab", "/about", "/pricing", "/terms", "/:view"]
        .iter()
        .map(|p| DiscoveredRoute {
            path: p.to_string(),
            dynamic: p.contains(':'),
            kind: "page".into(),
            file: format!("src/app{p}/page.tsx"),
            examples: if p.contains(':') {
                vec!["/universe".into(), "/strategies".into()]
            } else {
                Vec::new()
            },
            ..Default::default()
        })
        .collect()
}

fn run_json(args: &[&str]) -> Value {
    let out = Command::new(brokenapp_bin())
        .args(args)
        .output()
        .expect("run brokenapp");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: {e}\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn read_commands_report_field_regressions_without_noise() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("app");
    let state = project.join(".brokenapp");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(
        project.join("src/research.ts"),
        "export const submit = (b) => fetch(\"/api/research\", { method: \"POST\", body: b });\n",
    )
    .unwrap();
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join("config.toml"),
        format!("[project]\nname = \"fixture\"\nurl = \"{BASE}\"\n"),
    )
    .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut built = Vec::new();
    for (name, mutant, at) in [
        ("base", false, "20261021T100000Z"),
        ("mutant", true, "20261021T110000Z"),
    ] {
        let scan = state.join("scans").join(name).join("scan");
        write_scan(&scan, mutant);
        let opts = BuildOptions {
            project: "fixture".into(),
            target_url: format!("{BASE}/"),
            discovered_routes: discovered(),
            write_guard: "block".into(),
            ..Default::default()
        };
        let mut inv = rt
            .block_on(inventory::build_from_scan_dir(&scan, &opts))
            .unwrap();
        inv.generated_at = format!("2026-10-21T{}:00:00Z", if mutant { "11" } else { "10" });
        inventory::save(
            &inv,
            &state.join("history").join(format!("{at}.inventory.json")),
        )
        .unwrap();
        built.push(inv);
    }
    inventory::save(&built[1], &state.join("history/latest.inventory.json")).unwrap();
    let sd = state.to_str().unwrap();

    let changes = run_json(&["changes", "--state-dir", sd, "--json"]);
    let lines: Vec<&str> = changes["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["line"].as_str().unwrap())
        .collect();
    assert_eq!(
        lines,
        vec![
            "NOW BROKEN / link \"Terms\": link target /legal/terms is not a route in source (unknown route) (was → /terms, not exercised)",
            "NOW BROKEN /lab button \"How it works\": Error: guide unavailable @ at onClick (bundled code) (was opens modal)",
            "NOT REACHED 1 control behind /lab button \"How it works\" (opener now broken): \"Read the guide\"",
            "REWIRED / link \"Explore universe\": → /strategies (was → /universe)",
        ],
        "{changes:#}"
    );
    assert_eq!(changes["summary"]["not_observed"], 1, "{changes:#}");
    assert!(
        changes["not_observed"][0]
            .as_str()
            .unwrap()
            .contains("\"Compare plans\" (route not visited this time)"),
        "{changes:#}"
    );

    // Concrete pages behind `/:view` stay distinct routes.
    let ui = run_json(&["ui", "--state-dir", sd, "--route", "/universe", "--json"]);
    assert_eq!(ui["count"], 3, "shell controls listed on /universe: {ui:#}");
    let dead = run_json(&["dead", "--state-dir", sd, "--json"]);
    assert_eq!(dead["broken"].as_array().unwrap().len(), 2, "{dead:#}");
    assert!(dead["no_effect"].is_array());
    assert!(
        dead["coverage"]["controls_exercisable"].as_u64().unwrap() > 0,
        "{dead:#}"
    );

    let journey = run_json(&["journey", "POST /api/research", "--state-dir", sd, "--json"]);
    assert_eq!(journey["matched"].as_array().unwrap().len(), 0);
    assert!(
        journey["notes"][0]
            .as_str()
            .unwrap()
            .contains("never observed"),
        "{journey:#}"
    );
    assert!(
        journey["code_references"][0]
            .as_str()
            .unwrap()
            .starts_with("src/research.ts:1"),
        "{journey:#}"
    );
}
