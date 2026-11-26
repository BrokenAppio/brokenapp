//! Recorded actions must keep their control identity when a selector is reused.

use serde_json::{Value, json};

use super::tests::{BASE, build, button, el, link, opts, rec, row, spec, view, write_scan};
use super::*;
use crate::output::interactions::{InteractionOutcome, InteractionRecord};

const SELECTOR: &str = "button.button--primary";

fn action(id: &str, view: &str, label: &str) -> InteractionRecord {
    let mut record = rec(
        view,
        "/record",
        SELECTOR,
        "button",
        InteractionOutcome::DomChange,
    );
    record.action_id = Some(id.into());
    record.label = Some(label.into());
    record.dom_change = Some("message".into());
    record
}

async fn recorded(
    views: Vec<Value>,
    actions: &[InteractionRecord],
    network: &[Value],
) -> Inventory {
    let dir = tempfile::tempdir().unwrap();
    write_scan(dir.path(), &spec(views), Some(actions), network);
    build(dir.path(), &opts()).await
}

fn control<'a>(inventory: &'a Inventory, label: &str) -> &'a Control {
    inventory
        .controls
        .iter()
        .find(|control| control.label == label)
        .unwrap()
}

#[tokio::test]
async fn aggregate_spec_retry_does_not_inherit_save_action_or_endpoint() {
    // The raw Save view was folded out of spec.json; its later Retry subview
    // remains with the same selector. The interaction log retains both.
    let mut save = action("save", "raw", "Save note");
    save.console_errors = vec!["Error: actual save failure".into()];
    let retry = action("retry", "raw:d1:0", "Try again");
    let inv = recorded(
        vec![view(
            "raw:d1:0",
            "/record",
            vec![el(SELECTOR, "Try again", button(), &[])],
        )],
        &[save, retry],
        &[row(
            "POST",
            "/api/notes",
            Some(500),
            Some(("raw", SELECTOR)),
            Some("save"),
        )],
    )
    .await;
    let save = control(&inv, "Save note");
    assert_eq!(save.status, ControlStatus::Broken);
    assert_eq!(save.endpoints().collect::<Vec<_>>(), ["POST /api/notes"]);
    let retry = control(&inv, "Try again");
    assert_eq!(retry.status, ControlStatus::Ok);
    assert!(retry.endpoints().next().is_none());
    assert!(
        !retry
            .outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Error { .. }))
    );
}

#[tokio::test]
async fn exact_view_reused_selector_requires_matching_label() {
    let inv = recorded(
        vec![view(
            "same",
            "/record",
            vec![
                el(SELECTOR, "Try again", button(), &[]),
                el(SELECTOR, "Save note", button(), &[]),
            ],
        )],
        &[action("save", "same", "Save note")],
        &[row(
            "POST",
            "/api/notes",
            Some(200),
            Some(("same", SELECTOR)),
            Some("save"),
        )],
    )
    .await;
    assert_eq!(
        control(&inv, "Save note").endpoints().collect::<Vec<_>>(),
        ["POST /api/notes"]
    );
    assert!(control(&inv, "Try again").endpoints().next().is_none());
}

#[tokio::test]
async fn unique_compatible_route_fallback_preserves_kind_and_source_instance() {
    let inv = recorded(
        vec![view(
            "normalized",
            "/record",
            vec![
                el(SELECTOR, "Save", link("/help"), &[]),
                el(
                    SELECTOR,
                    "Save",
                    button(),
                    &[("test_id", "[data-testid=\"save-note\"]")],
                ),
            ],
        )],
        &[action("save", "raw", "Save")],
        &[row(
            "POST",
            "/api/notes",
            Some(200),
            Some(("raw", SELECTOR)),
            Some("save"),
        )],
    )
    .await;
    let button = inv
        .controls
        .iter()
        .find(|control| control.role == "button")
        .unwrap();
    assert_eq!(button.locator, "testid=save-note");
    assert_eq!(button.endpoints().collect::<Vec<_>>(), ["POST /api/notes"]);
    let link = inv
        .controls
        .iter()
        .find(|control| control.role == "link")
        .unwrap();
    assert!(link.endpoints().next().is_none());
}

#[tokio::test]
async fn actionless_network_uses_unique_matched_instance_window() {
    let views = || {
        vec![view(
            "same",
            "/record",
            vec![
                el(SELECTOR, "Save note", button(), &[]),
                el(SELECTOR, "Try again", button(), &[]),
            ],
        )]
    };
    let save = action("save", "same", "Save note");
    let retry = action("retry", "same", "Try again");
    let ambiguous = row(
        "POST",
        "/api/unknown",
        Some(500),
        Some(("same", SELECTOR)),
        None,
    );
    let inv = recorded(views(), &[save.clone(), retry.clone()], &[ambiguous]).await;
    assert!(
        inv.controls
            .iter()
            .all(|control| control.endpoints().next().is_none())
    );
    assert!(
        inv.controls
            .iter()
            .all(|control| control.status != ControlStatus::Broken)
    );

    let mut later_retry = retry;
    later_retry.started_at = "2026-10-21T10:00:20Z".into();
    let mut later = row(
        "GET",
        "/api/retry",
        Some(200),
        Some(("same", SELECTOR)),
        None,
    );
    later["occurred_at"] = json!("2026-10-21T10:00:20.200Z");
    let unknown_action = row(
        "POST",
        "/api/stale",
        Some(500),
        Some(("same", SELECTOR)),
        Some("unknown"),
    );
    let inv = recorded(views(), &[save, later_retry], &[later, unknown_action]).await;
    assert_eq!(
        control(&inv, "Try again").endpoints().collect::<Vec<_>>(),
        ["GET /api/retry"]
    );
    assert!(control(&inv, "Save note").endpoints().next().is_none());
}

#[tokio::test]
async fn unknown_record_kind_retains_unique_spec_textarea_identity() {
    // The interaction selector contains only an ID. The spec still knows its
    // tag and richer locator; do not replace it with a record-only `other`.
    for record_view in ["known", "raw"] {
        let mut record = rec(
            record_view,
            "/record",
            "#verify-report",
            "other",
            InteractionOutcome::NoEffect,
        );
        record.label = Some("Diagnostic report".into());
        let inv = recorded(
            vec![view(
                "known",
                "/record",
                vec![el(
                    "#verify-report",
                    "Diagnostic report",
                    json!({"kind": "other", "tag": "textarea"}),
                    &[("test_id", "[data-testid=\"diagnostic-report\"]")],
                )],
            )],
            &[record],
            &[],
        )
        .await;
        assert_eq!(inv.controls.len(), 1, "{record_view}");
        let input = &inv.controls[0];
        assert_eq!(input.role, "input");
        assert_eq!(input.locator, "testid=diagnostic-report");
        assert_eq!(input.status, ControlStatus::Ok);
        assert_eq!(input.reason.as_deref(), Some("focus_only"));
        assert!(render::tsv_row(input).contains("focus only (input not tested)"));
    }
}

#[tokio::test]
async fn unknown_record_kind_cannot_choose_between_matching_spec_roles() {
    let mut record = action("unknown", "same", "Open");
    record.element_kind = "other".into();
    let inv = recorded(
        vec![view(
            "same",
            "/record",
            vec![
                el(SELECTOR, "Open", button(), &[]),
                el(SELECTOR, "Open", link("/help"), &[]),
            ],
        )],
        &[record],
        &[row(
            "GET",
            "/api/unknown-control",
            Some(200),
            Some(("same", SELECTOR)),
            Some("unknown"),
        )],
    )
    .await;
    assert!(
        inv.controls
            .iter()
            .filter(|control| control.role != "other")
            .all(|control| control.endpoints().next().is_none())
    );
    let unknown = inv
        .controls
        .iter()
        .find(|control| control.role == "other")
        .unwrap();
    assert_eq!(
        unknown.endpoints().collect::<Vec<_>>(),
        ["GET /api/unknown-control"]
    );
}

fn match_metadata(views: Vec<Value>, record: &InteractionRecord) -> Option<Value> {
    let dir = tempfile::tempdir().unwrap();
    // No log: a retained legacy snapshot can carry prior effect evidence. A
    // fresh record-context match must not copy it into the new raw view.
    write_scan(dir.path(), &spec(views), None, &[]);
    super::build::tests_support::record_match_metadata(dir.path(), record)
}

fn layout_element(label: &str, kind: Value) -> Value {
    el(
        SELECTOR,
        label,
        kind,
        &[(
            "structural",
            "html > body > header > button.button--primary",
        )],
    )
}

fn owner_capture(owner: &str) -> Value {
    json!({"frames": [
        {"role": "render", "url": format!("{BASE}/src/Shared.tsx"), "line": 4, "col": 2},
        {"role": "owner", "owner": owner, "url": format!("{BASE}/src/{owner}.tsx"), "line": 8, "col": 1}
    ], "handlers": ["onClick"]})
}

#[tokio::test]
async fn equivalent_duplicate_links_rehydrate_the_actual_record_page() {
    let href = "?view=activity&tag=a%26b&tag=c#details";
    let mut element = layout_element("Activity", link(href));
    element["snapshot"] = json!({"truncated": true});
    let views = vec![
        view("normalized", "/organizations/:id", vec![element.clone()]),
        view(
            "retained",
            "/organizations/111?view=overview",
            vec![element],
        ),
    ];
    let path = "/organizations/222?view=overview#old";
    let mut record = rec(
        "actual",
        path,
        SELECTOR,
        "navigation_link",
        InteractionOutcome::Skipped,
    );
    record.label = Some("Activity".into());
    record.skipped_reason = Some("navigation_via_href".into());
    let metadata = match_metadata(views.clone(), &record).expect("one equivalent control identity");
    assert_eq!(metadata["view_id"], "actual");
    assert_eq!(metadata["page_url"], format!("{BASE}{path}"));
    assert_eq!(metadata["route"], "/organizations/:id");
    let target = format!("{BASE}/organizations/222?view=activity&tag=a%26b&tag=c#details");
    assert_eq!(metadata["target"], target);
    assert_eq!(metadata["link_url"], target);
    assert_eq!(metadata["exercised"], false, "no borrowed legacy snapshot");
    assert_eq!(metadata["outcomes"], json!([]));
    assert_eq!(metadata["record_variants"], json!([]));
    assert!(
        metadata["variant"]
            .as_str()
            .unwrap()
            .starts_with("/organizations/222?")
    );

    let inv = recorded(views, &[record], &[]).await;
    assert_eq!(inv.controls.len(), 1, "no metadata-less duplicate control");
    let activity = control(&inv, "Activity");
    assert!(activity.outcomes.contains(&Outcome::Navigates {
        to: "/organizations/:id".into()
    }));
    assert!(
        activity
            .variants
            .iter()
            .any(|variant| variant.starts_with("/organizations/222?"))
    );
}

#[tokio::test]
async fn equivalent_duplicate_shell_metadata_retains_exercised_elsewhere() {
    let element = layout_element("Open account menu", button());
    let mut opened = action("opened", "home", "Open account menu");
    opened.page_url = format!("{BASE}/staff");
    let mut skipped = rec(
        "raw",
        "/customers/222",
        SELECTOR,
        "button",
        InteractionOutcome::Skipped,
    );
    skipped.label = Some("Open account menu".into());
    skipped.skipped_reason = Some("exercised_elsewhere".into());
    skipped.exercised_on = Some("home".into());
    let views = vec![
        view("home", "/staff", vec![element.clone()]),
        view("normalized", "/customers/:id", vec![element.clone()]),
        view("retained", "/customers/111", vec![element]),
    ];
    let metadata = match_metadata(views.clone(), &skipped).unwrap();
    assert_eq!(
        metadata["structural"],
        "html > body > header > button.button--primary"
    );
    let inv = recorded(views, &[opened, skipped], &[]).await;
    let customer_menu = inv
        .controls
        .iter()
        .find(|c| c.route == "/customers/:id")
        .unwrap();
    assert_eq!(customer_menu.status, ControlStatus::Ok);
    assert_eq!(customer_menu.reason.as_deref(), Some("exercised on /staff"));
    assert!(customer_menu.outcomes.contains(&Outcome::DomChange {
        kind: "message".into()
    }));
}

#[test]
fn duplicate_targets_must_agree_before_template_grouping() {
    // Several pairs share the same LinkTarget signature. None establishes a
    // single concrete destination for this record. Preserve query order,
    // encoded separators, fragments and entity IDs at the matching boundary.
    for (first, second) in [
        ("/destination?tab=one", "/destination?tab=two"),
        ("/entities/111", "/entities/222"),
        ("/destination#one", "/destination#two"),
        (
            "https://other.invalid/destination#one",
            "https://other.invalid/destination#two",
        ),
        ("?tag=a&tag=b", "?tag=b&tag=a"),
        ("?q=a%26b", "?q=a&b="),
    ] {
        let mut record = rec(
            "raw",
            "/records/333",
            SELECTOR,
            "navigation_link",
            InteractionOutcome::Skipped,
        );
        record.label = Some("Open".into());
        let views = vec![
            view(
                "one",
                "/records/111",
                vec![layout_element("Open", link(first))],
            ),
            view(
                "two",
                "/records/222",
                vec![layout_element("Open", link(second))],
            ),
        ];
        assert!(
            match_metadata(views, &record).is_none(),
            "{first} versus {second}"
        );
    }
}

#[tokio::test]
async fn actual_record_page_outranks_reused_view_id_for_actions() {
    for (before, actual) in [
        ("/records/111?tab=one#old", "/records/222?tab=two#new"),
        ("/records/111?tab=one#same", "/records/111?tab=two#same"),
        ("/records/111?tab=one#old", "/records/111?tab=one#new"),
        ("/before", "/after"),
    ] {
        let mut old = el(
            SELECTOR,
            "Open",
            button(),
            &[("test_id", "[data-testid=\"old\"]")],
        );
        old["source"] = owner_capture("OldOwner");
        let mut current = el(
            SELECTOR,
            "Open",
            button(),
            &[("test_id", "[data-testid=\"current\"]")],
        );
        current["source"] = owner_capture("CurrentOwner");
        let mut old_view = view("reused", before, vec![old]);
        old_view["url"] = json!(format!("{BASE}{before}"));
        let mut current_view = view("actual-spec", actual, vec![current]);
        current_view["url"] = json!(format!("{BASE}{actual}"));
        let views = vec![old_view, current_view];
        let mut record = action("open", "reused", "Open");
        record.page_url = format!("{BASE}{actual}");
        let metadata = match_metadata(views.clone(), &record).unwrap();
        assert_eq!(metadata["page_url"], format!("{BASE}{actual}"));
        assert_eq!(metadata["view_id"], "reused");
        assert_eq!(metadata["locator"], "testid=current");
        assert_eq!(metadata["capture"], owner_capture("CurrentOwner"));
        let inv = recorded(
            views,
            &[record],
            &[row(
                "GET",
                "/api/current",
                Some(200),
                Some(("reused", SELECTOR)),
                Some("open"),
            )],
        )
        .await;
        let old = inv
            .controls
            .iter()
            .find(|c| c.locator == "testid=old")
            .unwrap();
        let current = inv
            .controls
            .iter()
            .find(|c| c.locator == "testid=current")
            .unwrap();
        assert!(old.endpoints().next().is_none(), "{before} -> {actual}");
        assert_eq!(
            current.endpoints().collect::<Vec<_>>(),
            ["GET /api/current"]
        );
        if actual == "/after" {
            assert_eq!(current.route, "/after");
        }
    }
}

#[test]
fn duplicate_source_or_layout_ambiguity_does_not_choose_an_owner() {
    let mut record = action("open", "raw", "Open");
    record.page_url = format!("{BASE}/records/333");
    for difference in [
        "owner",
        "missing_owner",
        "structural",
        "disabled",
        "validation",
        "hint",
    ] {
        let mut first = layout_element("Open", button());
        first["source"] = owner_capture("FirstOwner");
        let mut second = first.clone();
        match difference {
            "owner" => second["source"] = owner_capture("SecondOwner"),
            "missing_owner" => {
                second.as_object_mut().unwrap().remove("source");
            }
            "structural" => {
                second["locators"][0]["value"] =
                    json!("html > body > main > button.button--primary")
            }
            "disabled" => second["disabled"] = json!(true),
            "validation" => {
                second["element_type"]["form_submit"] = json!(true);
                second["empty_required_fields_in_form"] = json!(1);
            }
            "hint" => second["locators"].as_array_mut().unwrap().push(
                json!({"kind":"name", "value":"[name=\"other\"]", "stability":0.8, "unique":true}),
            ),
            _ => unreachable!(),
        }
        let views = vec![
            view("one", "/records/111", vec![first]),
            view("two", "/records/222", vec![second]),
        ];
        assert!(
            match_metadata(views, &record).is_none(),
            "ambiguous {difference}"
        );
    }
}

#[test]
fn duplicate_ordinal_only_controls_remain_unmatched() {
    let record = rec(
        "raw",
        "/record",
        "button",
        "button",
        InteractionOutcome::DomChange,
    );
    let element = el("button", "", button(), &[]);
    let views = vec![view("known", "/record", vec![element.clone(), element])];
    assert!(
        match_metadata(views, &record).is_none(),
        "unlabelled buttons are separate ordinal identities"
    );
}

#[tokio::test]
async fn reused_view_without_spec_url_does_not_lend_a_different_routes_metadata() {
    let old = el(
        SELECTOR,
        "Open",
        button(),
        &[("test_id", "[data-testid=\"old\"]")],
    );
    let current = el(
        SELECTOR,
        "Open",
        button(),
        &[("test_id", "[data-testid=\"current\"]")],
    );
    let views = vec![
        view("reused", "/before", vec![old]),
        view("current", "/after", vec![current]),
    ];
    let mut record = action("open", "reused", "Open");
    record.page_url = format!("{BASE}/after");
    // Include the log: the old spec's absent url is inferred from this first
    // record, leaving route=/before but page_url=/after. URL equality alone
    // must not make that old metadata an exact-view match.
    let dir = tempfile::tempdir().unwrap();
    write_scan(
        dir.path(),
        &spec(views),
        Some(std::slice::from_ref(&record)),
        &[row(
            "GET",
            "/api/current",
            Some(200),
            Some(("reused", SELECTOR)),
            Some("open"),
        )],
    );
    let metadata = super::build::tests_support::record_match_metadata(dir.path(), &record).unwrap();
    assert_eq!(metadata["route"], "/after");
    assert_eq!(metadata["locator"], "testid=current");
    let inv = build(dir.path(), &opts()).await;
    assert!(
        inv.controls
            .iter()
            .find(|c| c.locator == "testid=old")
            .unwrap()
            .endpoints()
            .next()
            .is_none()
    );
    let current = inv
        .controls
        .iter()
        .find(|c| c.locator == "testid=current")
        .unwrap();
    assert_eq!(current.route, "/after");
    assert_eq!(
        current.endpoints().collect::<Vec<_>>(),
        ["GET /api/current"]
    );
}

#[tokio::test]
async fn aggregate_placeholder_refinement_preserves_a_real_base_observation() {
    for base_evidence in ["placeholder", "explicit_url", "raw_record"] {
        let element = el("#save", "Save payout", button(), &[("id", "#save")]);
        let mut aggregate = view("aggregate", "/account", vec![element.clone()]);
        if base_evidence == "explicit_url" {
            aggregate["url"] = json!(format!("{BASE}/account"));
        }
        let mut record = rec(
            "payout",
            "/account?tab=payout",
            "#save",
            "button",
            InteractionOutcome::DomChange,
        );
        record.label = Some("Save payout".into());
        let mut records = vec![record];
        if base_evidence == "raw_record" {
            // A different control's record proves this raw view really was on
            // the plain page when its spec captured the Save control.
            records.push(rec(
                "aggregate",
                "/account",
                "#other",
                "button",
                InteractionOutcome::Skipped,
            ));
        }
        let inv = recorded(
            vec![
                aggregate,
                view("payout", "/account?tab=payout", vec![element]),
                view("profile", "/account?tab=profile", vec![]),
            ],
            &records,
            &[],
        )
        .await;
        let save = control(&inv, "Save payout");
        if base_evidence == "placeholder" {
            assert_eq!(
                save.variants,
                ["?tab=payout"],
                "synthetic None is not shared-state evidence"
            );
        } else {
            assert!(
                save.variants.is_empty(),
                "real base observation remains shared: {base_evidence}"
            );
        }
    }
}

#[tokio::test]
async fn reused_view_id_on_distinct_pages_does_not_inflate_control_count() {
    let element = el("#save", "Save", button(), &[("id", "#save")]);
    let mut saved_view = view("reused", "/account?tab=profile", vec![element]);
    saved_view["url"] = json!(format!("{BASE}/account?tab=profile"));
    let records: Vec<_> = ["profile", "payout", "payout"]
        .into_iter()
        .enumerate()
        .map(|(n, tab)| {
            let mut record = rec(
                "reused",
                &format!("/account?tab={tab}"),
                "#save",
                "button",
                InteractionOutcome::DomChange,
            );
            record.label = Some("Save".into());
            record.action_id = Some(format!("save-{n}"));
            record
        })
        .collect();
    let inv = recorded(vec![saved_view], &records, &[]).await;
    assert_eq!(inv.controls.len(), 1);
    assert_eq!(
        control(&inv, "Save").count,
        1,
        "different page states were never simultaneous controls"
    );
}
