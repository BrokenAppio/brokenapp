//! Preserve the alternatives by which a control's state was actually seen.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::tests::{BASE, build, button, el, opts, rec, spec, view, write_scan};
use super::*;
use crate::output::interactions::InteractionOutcome;

fn observed_view(id: &str, route: &str, elements: Vec<Value>) -> Value {
    let mut v = view(id, route, elements);
    v["url"] = json!(format!("{BASE}{route}"));
    v
}

fn transition(from: &str, to: &str, selector: &str) -> Value {
    json!({
        "from_view": from, "to_view": to,
        "trigger": {"view": from, "selector": selector},
        "transition_type": "view_state_change"
    })
}

fn entry(route: &str, variant: Option<&str>, kind: ControlStateEntryKind) -> ControlStateEntry {
    ControlStateEntry {
        route: route.into(),
        variant: variant.map(str::to_string),
        kind,
    }
}

fn entries(control: &Control) -> BTreeSet<ControlStateEntry> {
    control.state_entries.iter().cloned().collect()
}

fn control<'a>(inv: &'a Inventory, label: &str) -> &'a Control {
    inv.controls.iter().find(|c| c.label == label).unwrap()
}

#[tokio::test]
async fn mixed_direct_query_and_opened_plain_entries_remain_alternatives() {
    let save = el("#save", "Save count", button(), &[]);
    let mut s = spec(vec![
        observed_view(
            "base",
            "/receiving",
            vec![el("#open", "Open count", button(), &[])],
        ),
        observed_view("base:d1:0", "/receiving", vec![save.clone()]),
        observed_view("query", "/receiving?shipment=three", vec![save]),
        observed_view("other", "/receiving?shipment=one", vec![]),
    ]);
    s["state_machine"]["transitions"] = json!([transition("base", "base:d1:0", "#open")]);
    let dir = tempfile::tempdir().unwrap();
    write_scan(dir.path(), &s, Some(&[]), &[]);
    let inv = build(dir.path(), &opts()).await;
    let save = control(&inv, "Save count");
    let opener = control(&inv, "Open count").key.clone();
    assert!(save.variants.is_empty(), "legacy summary remains unchanged");
    assert!(save.opened_by.is_empty(), "direct alternative still exists");
    assert_eq!(
        entries(save),
        BTreeSet::from([
            entry("/receiving", None, ControlStateEntryKind::Opened { opener }),
            entry(
                "/receiving",
                Some("?shipment=three"),
                ControlStateEntryKind::Direct
            ),
        ])
    );
    assert!(
        !save
            .state_entries
            .iter()
            .any(|e| e.variant.is_none() && e.kind == ControlStateEntryKind::Direct)
    );
}

#[tokio::test]
async fn opener_and_variant_pairs_do_not_form_a_cross_product() {
    let save = el("#save", "Save", button(), &[]);
    let mut s = spec(vec![
        observed_view(
            "payout",
            "/account?tab=payout",
            vec![el("#first", "Open payout", button(), &[])],
        ),
        observed_view("payout:d1:0", "/account?tab=payout", vec![save.clone()]),
        observed_view(
            "profile",
            "/account?tab=profile",
            vec![el("#second", "Open profile", button(), &[])],
        ),
        observed_view("profile:d1:0", "/account?tab=profile", vec![save]),
    ]);
    s["state_machine"]["transitions"] = json!([
        transition("payout", "payout:d1:0", "#first"),
        transition("profile", "profile:d1:0", "#second"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    write_scan(dir.path(), &s, Some(&[]), &[]);
    let inv = build(dir.path(), &opts()).await;
    assert_eq!(
        entries(control(&inv, "Save")),
        BTreeSet::from([
            entry(
                "/account",
                Some("?tab=payout"),
                ControlStateEntryKind::Opened {
                    opener: control(&inv, "Open payout").key.clone()
                }
            ),
            entry(
                "/account",
                Some("?tab=profile"),
                ControlStateEntryKind::Opened {
                    opener: control(&inv, "Open profile").key.clone()
                }
            ),
        ])
    );
}

#[tokio::test]
async fn aggregate_refinement_does_not_turn_a_child_record_into_direct_entry() {
    let mut s = spec(vec![
        // This route-only aggregate has no actual initial-page URL evidence.
        view(
            "aggregate",
            "/account",
            vec![el("#save", "Save", button(), &[])],
        ),
        observed_view("raw", "/account", vec![el("#open", "Open", button(), &[])]),
    ]);
    s["state_machine"]["transitions"] = json!([transition("raw", "raw:d1:0", "#open")]);
    let mut action = rec(
        "raw:d1:0",
        "/account",
        "#save",
        "button",
        InteractionOutcome::DomChange,
    );
    action.label = Some("Save".into());
    let dir = tempfile::tempdir().unwrap();
    write_scan(dir.path(), &s, Some(&[action]), &[]);
    let inv = build(dir.path(), &opts()).await;
    let save = control(&inv, "Save");
    assert_eq!(
        entries(save),
        BTreeSet::from([
            entry("/account", None, ControlStateEntryKind::Unknown),
            entry(
                "/account",
                None,
                ControlStateEntryKind::Opened {
                    opener: control(&inv, "Open").key.clone()
                }
            ),
        ])
    );
}

#[tokio::test]
async fn direct_plain_entry_requires_positive_page_presence() {
    for evidence in ["placeholder", "explicit_url", "raw_record"] {
        let element = el("#save", "Save payout", button(), &[]);
        let mut aggregate = view("aggregate", "/account", vec![element.clone()]);
        if evidence == "explicit_url" {
            aggregate["url"] = json!(format!("{BASE}/account"));
        }
        let mut action = rec(
            "payout",
            "/account?tab=payout",
            "#save",
            "button",
            InteractionOutcome::DomChange,
        );
        action.label = Some("Save payout".into());
        let mut actions = vec![action];
        if evidence == "raw_record" {
            actions.push(rec(
                "aggregate",
                "/account",
                "#other",
                "button",
                InteractionOutcome::Skipped,
            ));
        }
        let dir = tempfile::tempdir().unwrap();
        write_scan(
            dir.path(),
            &spec(vec![
                aggregate,
                view("payout", "/account?tab=payout", vec![element]),
            ]),
            Some(&actions),
            &[],
        );
        let inv = build(dir.path(), &opts()).await;
        let save = control(&inv, "Save payout");
        assert_eq!(
            save.state_entries
                .contains(&entry("/account", None, ControlStateEntryKind::Direct)),
            evidence != "placeholder",
            "{evidence}"
        );
        assert!(save.state_entries.contains(&entry(
            "/account",
            Some("?tab=payout"),
            ControlStateEntryKind::Direct
        )));
    }
}

#[tokio::test]
async fn unresolved_child_template_and_wrong_context_openers_are_unknown() {
    let mut s = spec(vec![
        observed_view(
            "parent",
            "/account?tab=profile",
            vec![el("#open", "Open", button(), &[])],
        ),
        observed_view(
            "parent:d1:0",
            "/account?tab=payout",
            vec![el("#save", "Wrong context", button(), &[])],
        ),
        observed_view(
            "orphan:d1:0",
            "/account",
            vec![el("#orphan", "Orphan", button(), &[])],
        ),
        view(
            "aggregate",
            "/orders/:id",
            vec![el("#template", "Template", button(), &[])],
        ),
    ]);
    s["state_machine"]["transitions"] = json!([transition("parent", "parent:d1:0", "#open")]);
    let dir = tempfile::tempdir().unwrap();
    write_scan(dir.path(), &s, Some(&[]), &[]);
    let inv = build(dir.path(), &opts()).await;
    for label in ["Wrong context", "Orphan", "Template"] {
        let c = control(&inv, label);
        assert!(!c.state_entries.is_empty());
        assert!(
            c.state_entries
                .iter()
                .all(|e| e.kind == ControlStateEntryKind::Unknown),
            "{label}: {:?}",
            c.state_entries
        );
    }
}

#[tokio::test]
async fn global_entries_retain_the_actual_route_contexts() {
    let dir = tempfile::tempdir().unwrap();
    let views = ["/", "/account", "/orders"]
        .into_iter()
        .enumerate()
        .map(|(i, route)| {
            observed_view(
                &format!("page{i}"),
                route,
                vec![el(
                    "header > button",
                    "Menu",
                    button(),
                    &[("structural", "header > button")],
                )],
            )
        })
        .collect();
    write_scan(dir.path(), &spec(views), Some(&[]), &[]);
    let inv = build(dir.path(), &opts()).await;
    let menu = control(&inv, "Menu");
    assert_eq!(menu.route, "*");
    assert_eq!(
        entries(menu),
        ["/", "/account", "/orders"]
            .into_iter()
            .map(|route| entry(route, None, ControlStateEntryKind::Direct))
            .collect()
    );
}

#[test]
fn state_entry_schema_preserves_legacy_absence_and_round_trips_alternatives() {
    let legacy = serde_json::to_value(Control::default()).unwrap();
    assert!(legacy.get("state_entries").is_none());
    let mut control: Control = serde_json::from_value(legacy.clone()).unwrap();
    assert!(control.state_entries.is_empty());
    assert_eq!(serde_json::to_value(&control).unwrap(), legacy);
    control.state_entries = vec![
        entry("/account", None, ControlStateEntryKind::Direct),
        entry(
            "/account",
            Some("?tab=payout"),
            ControlStateEntryKind::Opened {
                opener: "/account|button|text=open".into(),
            },
        ),
        entry(
            "/orders/:id",
            Some("/orders/:id"),
            ControlStateEntryKind::Unknown,
        ),
    ];
    let value = serde_json::to_value(&control).unwrap();
    assert_eq!(
        value["state_entries"][0],
        json!({"route":"/account", "kind":"direct"})
    );
    assert_eq!(value["state_entries"][1]["kind"], "opened");
    assert_eq!(serde_json::from_value::<Control>(value).unwrap(), control);
}

fn map(routes: &[&str], controls: Vec<Control>) -> Inventory {
    Inventory {
        routes: routes
            .iter()
            .map(|route| RouteEntry {
                route: (*route).into(),
                visited: true,
                ..Default::default()
            })
            .collect(),
        controls,
        ..Default::default()
    }
}

fn menu(route: &str, entries: Vec<ControlStateEntry>) -> Control {
    Control {
        key: format!("{route}|button|text=menu"),
        route: route.into(),
        role: "button".into(),
        label: "Menu".into(),
        locator: "text=menu".into(),
        state_entries: entries,
        ..Default::default()
    }
}

#[test]
fn incremental_globals_replace_only_observed_route_entries_and_remap_openers() {
    let mut global = menu(
        "*",
        vec![
            entry("/a", Some("?tab=old"), ControlStateEntryKind::Direct),
            entry("/b", None, ControlStateEntryKind::Direct),
            entry("/gone", None, ControlStateEntryKind::Direct),
        ],
    );
    global.routes = vec!["/a".into(), "/b".into(), "/gone".into()];
    let base = map(&["/a", "/b", "/gone"], vec![global]);
    let mut child = Control {
        key: "/a|button|text=save".into(),
        route: "/a".into(),
        role: "button".into(),
        label: "Save".into(),
        locator: "text=save".into(),
        ..Default::default()
    };
    child.state_entries = vec![entry(
        "/a",
        Some("?tab=new"),
        ControlStateEntryKind::Opened {
            opener: "/a|button|text=menu".into(),
        },
    )];
    let partial = map(
        &["/a"],
        vec![
            menu(
                "/a",
                vec![entry("/a", Some("?tab=new"), ControlStateEntryKind::Direct)],
            ),
            child,
        ],
    );
    let merged = merge_incremental(
        &base,
        &partial,
        &MergeOptions {
            requested: BTreeSet::from(["/a".into()]),
            removed: BTreeSet::from(["/gone".into()]),
            ..Default::default()
        },
    )
    .inventory;
    assert_eq!(
        entries(control(&merged, "Menu")),
        BTreeSet::from([
            entry("/a", Some("?tab=new"), ControlStateEntryKind::Direct),
            entry("/b", None, ControlStateEntryKind::Direct),
        ])
    );
    assert_eq!(
        entries(control(&merged, "Save")),
        BTreeSet::from([entry(
            "/a",
            Some("?tab=new"),
            ControlStateEntryKind::Opened {
                opener: "*|button|text=menu".into()
            }
        ),])
    );
}

#[test]
fn incremental_global_absence_drops_old_entries_without_inventing_legacy_observations() {
    let mut global = menu("*", vec![entry("/a", None, ControlStateEntryKind::Direct)]);
    global.routes = vec!["/a".into(), "/b".into()];
    let base = map(&["/a", "/b"], vec![global]);
    let merged = merge_incremental(
        &base,
        &map(&["/a"], vec![]),
        &MergeOptions {
            requested: BTreeSet::from(["/a".into()]),
            ..Default::default()
        },
    )
    .inventory;
    let menu = control(&merged, "Menu");
    assert_eq!(menu.routes, ["/b"]);
    assert_eq!(
        menu.state_entries,
        [entry("/b", None, ControlStateEntryKind::Unknown)],
        "no invented observations or fallback to legacy unrestricted provenance"
    );
}
