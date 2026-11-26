//! Evidence projections for agents. A visit or UI effect never establishes a
//! business transaction. Optional reviewed annotations are bound to the exact
//! saved inventory; the original observations are not rewritten.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{Control, ControlStatus, Inventory, Outcome};
use crate::code_link::runtime_source::ResolvedSource;

pub const ANNOTATIONS_FILE: &str = "route-evidence.json";
pub const ANNOTATIONS_SCHEMA: &str = "brokenapp.route-evidence-annotations.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceReviews {
    pub schema: String,
    pub inventory_sha256: String,
    pub role: Option<String>,
    pub resolver_sha256: String,
    pub source_snapshot_sha256: String,
    pub source_root: String,
    pub controls: Vec<ControlSourceReview>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ControlSourceReview {
    pub key: String,
    pub original_source: Option<ResolvedSource>,
    pub resolved_source: Option<ResolvedSource>,
}

fn validate_source_reviews(inv: &Inventory, reviews: &SourceReviews) -> Result<()> {
    ensure!(
        reviews.schema == "brokenapp.source-attribution-review.v1",
        "unsupported source review schema"
    );
    ensure!(
        reviews.role == inv.role,
        "source review login role mismatch"
    );
    ensure!(
        !reviews.source_root.trim().is_empty(),
        "source review needs its source snapshot root"
    );
    for digest in [&reviews.resolver_sha256, &reviews.source_snapshot_sha256] {
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid source review provenance digest"
        );
    }
    let mut seen = BTreeSet::new();
    for review in &reviews.controls {
        ensure!(
            seen.insert(&review.key),
            "duplicate source review control key"
        );
        let mut found = inv.controls.iter().filter(|c| c.key == review.key);
        let control = found
            .next()
            .context("source review refers to unknown control")?;
        ensure!(
            found.next().is_none(),
            "source review control key is ambiguous"
        );
        ensure!(
            control.source == review.original_source,
            "source review original owner differs from the archived observation"
        );
        ensure!(
            control.source.as_ref().is_none_or(|s| s.method == "static"),
            "static review cannot replace runtime source evidence"
        );
        if let Some(source) = &review.resolved_source {
            ensure!(
                source.method == "static"
                    && matches!(
                        source.confidence.as_str(),
                        "probable" | "guess" | "ambiguous"
                    ),
                "offline source review cannot assert runtime or exact ownership"
            );
        }
    }
    Ok(())
}

pub fn load_source_reviews(
    inventory_path: &Path,
    map_dir: &Path,
    inv: &Inventory,
) -> Result<Option<SourceReviews>> {
    let path = map_dir.join("source-attribution.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    ensure!(
        std::fs::metadata(&path)?.len() <= 32 * 1024 * 1024,
        "source review exceeds 32 MiB"
    );
    let reviews: SourceReviews = serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        reviews.inventory_sha256 == inventory_sha256(&std::fs::read(inventory_path)?),
        "source review inventory hash mismatch; regenerate for this map"
    );
    validate_source_reviews(inv, &reviews)?;
    Ok(Some(reviews))
}

pub fn apply_source_reviews(inv: &mut Inventory, reviews: SourceReviews) -> Result<()> {
    validate_source_reviews(inv, &reviews)?;
    for review in &reviews.controls {
        if let Some(control) = inv.controls.iter_mut().find(|c| c.key == review.key) {
            control.source = review.resolved_source.clone();
        }
    }
    inv.source_reviews = Some(reviews);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteEvidenceAnnotations {
    pub schema: String,
    pub inventory_sha256: String,
    pub role: Option<String>,
    #[serde(default)]
    pub surface: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub fixture: Option<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub routes: Vec<RouteObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteObservation {
    pub route: String,
    pub variant: Option<String>,
    pub state: String,
    pub basis: String,
    #[serde(default)]
    pub observation_note: Option<String>,
    #[serde(default)]
    pub source_explanation: Option<String>,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub locator: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

pub fn inventory_sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Absent annotations mean unknown page state. Present but invalid annotations
/// fail closed; silently using a stale review is worse than an explicit error.
pub fn load_annotations(
    inventory_path: &Path,
    map_dir: &Path,
    inv: &Inventory,
) -> Result<Option<RouteEvidenceAnnotations>> {
    let path = map_dir.join(ANNOTATIONS_FILE);
    if !path
        .try_exists()
        .with_context(|| format!("inspect {}", path.display()))?
    {
        return Ok(None);
    }
    ensure!(
        std::fs::metadata(&path)?.len() <= 4 * 1024 * 1024,
        "route evidence annotations exceed 4 MiB"
    );
    let annotations: RouteEvidenceAnnotations = serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        annotations.schema == ANNOTATIONS_SCHEMA,
        "unsupported route evidence schema"
    );
    let bytes = std::fs::read(inventory_path)?;
    ensure!(
        annotations.inventory_sha256 == inventory_sha256(&bytes),
        "route evidence inventory hash mismatch; rebuild annotations for this map"
    );
    ensure!(
        annotations.role == inv.role,
        "route evidence login role mismatch"
    );
    for observation in &annotations.routes {
        let route = inv
            .routes
            .iter()
            .find(|r| r.route == observation.route)
            .with_context(|| {
                format!(
                    "route evidence refers to unknown route {}",
                    observation.route
                )
            })?;
        ensure!(
            matches!(
                observation.state.as_str(),
                "unknown"
                    | "empty"
                    | "not_found"
                    | "error"
                    | "denied"
                    | "partial_denial"
                    | "populated"
                    | "redirect"
            ),
            "unsupported route evidence state"
        );
        ensure!(
            matches!(
                observation.basis.as_str(),
                "recorded_runtime" | "reviewed_join" | "source_inference" | "unknown"
            ),
            "unsupported route evidence basis"
        );
        if let Some(variant) = &observation.variant {
            ensure!(
                route.variants.contains(variant),
                "route evidence variant was not recorded on {}",
                route.route
            );
        }
        ensure!(
            observation.evidence.iter().all(|e| matches!(
                e.kind.as_str(),
                "inventory" | "access_audit" | "source" | "fixture"
            ) && !e.path.trim().is_empty()),
            "invalid route evidence reference"
        );
        if observation.state != "unknown" {
            ensure!(
                observation.basis != "unknown" && !observation.evidence.is_empty(),
                "classified route state requires evidence and a named basis"
            );
        }
        if observation.basis == "source_inference" {
            ensure!(
                observation.state == "unknown",
                "source explanation cannot establish the rendered state"
            );
        }
        if matches!(
            observation.basis.as_str(),
            "recorded_runtime" | "reviewed_join"
        ) {
            ensure!(
                observation
                    .evidence
                    .iter()
                    .any(|e| matches!(e.kind.as_str(), "inventory" | "access_audit")),
                "runtime state requires an inventory or access audit reference"
            );
        }
        if observation.basis == "reviewed_join" {
            ensure!(
                observation
                    .evidence
                    .iter()
                    .any(|e| matches!(e.kind.as_str(), "source" | "fixture")),
                "reviewed state join requires its source explanation or fixture reference"
            );
        }
    }
    Ok(Some(annotations))
}

/// A convenience grouping by recorded region, not a semantic assertion that a
/// sidebar can never contain task controls. Queries explicitly opt out of it.
pub fn is_shell(control: &Control) -> bool {
    control.route == "*"
        || matches!(
            control.region.as_str(),
            "header" | "nav" | "aside" | "footer"
        )
}

#[derive(Debug, Serialize)]
pub struct ControlEvidence {
    pub observation: &'static str,
    pub business_result: &'static str,
    pub source_basis: &'static str,
}

pub fn control_evidence(control: &Control) -> ControlEvidence {
    let timeout = control
        .reason
        .as_deref()
        .is_some_and(|r| r.contains("interaction_timeout"))
        || control.outcomes.iter().any(
            |o| matches!(o, Outcome::Error { message } if message.contains("interaction_timeout")),
        );
    let observation = if timeout {
        "inconclusive_timeout"
    } else if !control.status.is_exercised() {
        "not_exercised"
    } else if control.status == ControlStatus::Broken {
        "recorded_failure"
    } else if control.reason.as_deref() == Some("focus_only") {
        "focus_only_input_not_tested"
    } else if control
        .outcomes
        .iter()
        .any(|o| matches!(o, Outcome::Calls { blocked: true, .. }))
    {
        "request_blocked"
    } else {
        match control.status {
            ControlStatus::Ok => "observable_effect",
            ControlStatus::Dead | ControlStatus::NoEffect => "no_observable_effect",
            ControlStatus::Broken => "recorded_failure",
            _ => "not_exercised",
        }
    };
    let source_basis = match control.source.as_ref() {
        None => "unknown",
        Some(source) if source.method == "static" => "static_candidate_verify_in_source",
        Some(source) if source.confidence == "exact" => "runtime_source_capture",
        Some(_) => "source_candidate_verify_in_source",
    };
    ControlEvidence {
        observation,
        business_result: "not_verified_by_this_observation",
        source_basis,
    }
}

#[derive(Debug, Default, Serialize)]
pub struct ControlCounts {
    pub rows: usize,
    pub exercised: usize,
    pub exercisable: usize,
    pub statuses: BTreeMap<String, usize>,
    pub gaps_by_reason: BTreeMap<String, usize>,
}

fn counts(controls: &[&Control]) -> ControlCounts {
    let mut out = ControlCounts {
        rows: controls.len(),
        ..Default::default()
    };
    for control in controls {
        *out.statuses
            .entry(control.status.as_str().to_string())
            .or_default() += 1;
        out.exercised += usize::from(control.status.is_exercised());
        out.exercisable += usize::from(!matches!(
            control.status,
            ControlStatus::Disabled | ControlStatus::External | ControlStatus::Skipped
        ));
        if control.status == ControlStatus::NotExercised {
            *out.gaps_by_reason
                .entry(control.reason.clone().unwrap_or_else(|| "unknown".into()))
                .or_default() += 1;
        }
    }
    out
}

#[derive(Debug, Serialize)]
pub struct RouteEvidenceSummary {
    pub route: String,
    pub login_role: Option<String>,
    pub visited: bool,
    pub http_status: Option<u16>,
    pub page_state: &'static str,
    pub state_observations: Vec<RouteObservation>,
    pub page_controls: ControlCounts,
    pub shell_controls: ControlCounts,
    pub observed_control_endpoints: usize,
    pub endpoint_evidence: &'static str,
    pub write_guard: String,
    pub limitations: Vec<String>,
}

pub fn route_summary(inv: &Inventory, route: &str) -> RouteEvidenceSummary {
    let entry = inv.routes.iter().find(|r| r.route == route);
    let controls: Vec<&Control> = inv
        .controls
        .iter()
        .filter(|c| c.present_on().contains(&route))
        .collect();
    let (shell, page): (Vec<_>, Vec<_>) = controls.iter().copied().partition(|c| is_shell(c));
    let endpoints: BTreeSet<_> = controls.iter().flat_map(|c| c.endpoints()).collect();
    let observations: Vec<_> = inv
        .evidence_annotations
        .as_ref()
        .map(|a| {
            a.routes
                .iter()
                .filter(|o| o.route == route)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let mut limitations = vec![
        "A visit or HTTP success does not establish populated content, access to work queues, or business completion.".into(),
        "Counts are saved control rows; shared regions are grouped by recorded landmark, not unique physical controls.".into(),
        "State observations apply to their cited fixtures and variants; they do not cover every state of this route.".into(),
    ];
    if let Some(annotations) = &inv.evidence_annotations {
        limitations.extend(annotations.limitations.clone());
    }
    RouteEvidenceSummary {
        route: route.into(),
        login_role: inv.role.clone(),
        visited: entry.is_some_and(|r| r.visited),
        http_status: entry.and_then(|r| r.status),
        page_state: if observations.is_empty() {
            "unknown"
        } else {
            "see_scoped_state_observations"
        },
        state_observations: observations,
        page_controls: counts(&page),
        shell_controls: counts(&shell),
        observed_control_endpoints: endpoints.len(),
        endpoint_evidence: if endpoints.is_empty() {
            "none_captured_not_proof_of_no_backend"
        } else {
            "captured_requests_not_business_verification"
        },
        write_guard: inv.write_guard.clone(),
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::RouteEntry;

    fn fixture() -> (tempfile::TempDir, Inventory, RouteEvidenceAnnotations) {
        let dir = tempfile::tempdir().unwrap();
        let inv = Inventory {
            role: Some("seller".into()),
            routes: vec![RouteEntry {
                route: "/orders/:id".into(),
                visited: true,
                status: Some(200),
                variants: vec!["/orders/one".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let path = dir.path().join("inventory.json");
        crate::inventory::save(&inv, &path).unwrap();
        let annotations = RouteEvidenceAnnotations {
            schema: ANNOTATIONS_SCHEMA.into(),
            inventory_sha256: inventory_sha256(&std::fs::read(path).unwrap()),
            role: inv.role.clone(),
            surface: None,
            environment: None,
            fixture: None,
            limitations: vec![],
            routes: vec![RouteObservation {
                route: "/orders/:id".into(),
                variant: Some("/orders/one".into()),
                state: "empty".into(),
                basis: "reviewed_join".into(),
                observation_note: Some("Empty fixture order".into()),
                source_explanation: None,
                evidence: vec![
                    EvidenceReference {
                        kind: "inventory".into(),
                        path: "inventory.json".into(),
                        locator: None,
                        sha256: None,
                    },
                    EvidenceReference {
                        kind: "source".into(),
                        path: "src/order.tsx".into(),
                        locator: Some("empty branch".into()),
                        sha256: None,
                    },
                ],
            }],
        };
        (dir, inv, annotations)
    }

    #[test]
    fn annotations_bind_inventory_role_route_and_variant() {
        let (dir, inv, annotations) = fixture();
        let load = |a: &RouteEvidenceAnnotations| {
            std::fs::write(
                dir.path().join(ANNOTATIONS_FILE),
                serde_json::to_vec(a).unwrap(),
            )
            .unwrap();
            load_annotations(&dir.path().join("inventory.json"), dir.path(), &inv)
        };
        assert!(load(&annotations).unwrap().is_some());
        for case in 0..9 {
            let mut bad = annotations.clone();
            match case {
                0 => bad.inventory_sha256 = "0".repeat(64),
                1 => bad.role = Some("buyer".into()),
                2 => bad.routes[0].route = "/other".into(),
                3 => bad.routes[0].variant = Some("/orders/unobserved".into()),
                4 => bad.routes[0].basis = "certain".into(),
                5 => bad.routes[0].evidence[0].kind = "source".into(),
                6 => bad.routes[0].evidence.clear(),
                7 => {
                    bad.routes[0].evidence.retain(|e| e.kind == "inventory");
                    bad.routes[0].evidence[0].kind = "fixture".into();
                }
                _ => {
                    bad.routes[0].basis = "recorded_runtime".into();
                    bad.routes[0].evidence[0].kind = "fixture".into();
                }
            }
            assert!(load(&bad).is_err(), "case {case}");
        }
    }

    #[test]
    fn http_success_and_many_controls_do_not_infer_page_state() {
        let (_dir, mut inv, _) = fixture();
        inv.controls = vec![
            Control {
                route: "/orders/:id".into(),
                region: "aside".into(),
                status: ControlStatus::Ok,
                ..Default::default()
            },
            Control {
                route: "/orders/:id".into(),
                status: ControlStatus::NotExercised,
                reason: Some("obscured".into()),
                ..Default::default()
            },
        ];
        let summary = route_summary(&inv, "/orders/:id");
        assert_eq!(summary.page_state, "unknown");
        assert_eq!(summary.page_controls.exercised, 0);
        assert_eq!(summary.shell_controls.exercised, 1);
        assert_eq!(summary.page_controls.gaps_by_reason["obscured"], 1);
        assert_eq!(
            summary.endpoint_evidence,
            "none_captured_not_proof_of_no_backend"
        );
    }

    #[test]
    fn ui_effect_focus_guard_and_timeout_are_not_business_success() {
        let mut control = Control {
            status: ControlStatus::Ok,
            reason: Some("focus_only".into()),
            ..Default::default()
        };
        assert_eq!(
            control_evidence(&control).observation,
            "focus_only_input_not_tested"
        );
        control.reason = None;
        control.outcomes.push(Outcome::Calls {
            endpoint: "POST /save".into(),
            status: None,
            blocked: true,
        });
        assert_eq!(control_evidence(&control).observation, "request_blocked");
        control.status = ControlStatus::Broken;
        control.outcomes.push(Outcome::Error {
            message: "TypeError: Failed to fetch".into(),
        });
        assert_eq!(control_evidence(&control).observation, "recorded_failure");
        control.reason = Some("interaction_timeout: no response".into());
        assert_eq!(
            control_evidence(&control).observation,
            "inconclusive_timeout"
        );
        assert_eq!(
            control_evidence(&control).business_result,
            "not_verified_by_this_observation"
        );
        assert_eq!(control.status, ControlStatus::Broken);
    }

    #[test]
    fn rendering_keeps_uncertainty_candidates_and_structured_fields() {
        let (_dir, mut inv, annotations) = fixture();
        let candidate = crate::code_link::runtime_source::FileLine {
            file: "src/shared.tsx".into(),
            line: 18,
            col: 0,
        };
        inv.evidence_annotations = Some(annotations);
        inv.controls.push(Control {
            route: "/orders/:id".into(),
            label: "Save".into(),
            key: "save".into(),
            status: ControlStatus::Ok,
            reason: Some("focus_only".into()),
            variants: vec!["/orders/one".into()],
            source: Some(crate::code_link::runtime_source::ResolvedSource {
                method: "static".into(),
                confidence: "ambiguous".into(),
                candidates: vec![candidate],
                ..Default::default()
            }),
            ..Default::default()
        });
        let text = super::super::render::render_ui_map(&inv);
        assert!(text.contains("reviewed_join"));
        assert!(text.contains("Empty fixture order"));
        assert!(text.contains("static candidate; verify in source"));
        assert!(text.contains("focus only (input not tested)"));
        let tsv = super::super::render::render_ui_tsv(&inv);
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(b'\t')
            .from_reader(tsv.as_bytes());
        let headers = reader.headers().unwrap().clone();
        let row = reader.records().next().unwrap().unwrap();
        let get = |key| &row[headers.iter().position(|h| h == key).unwrap()];
        assert_eq!(get("source_confidence"), "ambiguous");
        assert_eq!(get("reason"), "focus_only");
        assert!(get("source_candidates").contains("src/shared.tsx"));
        assert_eq!(get("variants"), "[\"/orders/one\"]");
        // Review annotations remain separate and cannot be injected through
        // an inventory JSON field or accidentally persisted into history.
        let saved = serde_json::to_value(&inv).unwrap();
        assert!(saved.get("evidence_annotations").is_none());
    }

    #[test]
    fn static_reviews_preserve_raw_owners_and_reject_stale_or_promoted_evidence() {
        let (dir, mut inv, _) = fixture();
        inv.controls.push(Control {
            key: "home".into(),
            ..Default::default()
        });
        let path = dir.path().join("inventory.json");
        crate::inventory::save(&inv, &path).unwrap();
        let raw = std::fs::read(&path).unwrap();
        let reviews = SourceReviews {
            schema: "brokenapp.source-attribution-review.v1".into(),
            inventory_sha256: inventory_sha256(&raw),
            role: inv.role.clone(),
            resolver_sha256: "a".repeat(64),
            source_snapshot_sha256: "b".repeat(64),
            source_root: "/approved/clone".into(),
            controls: vec![ControlSourceReview {
                key: "home".into(),
                original_source: None,
                resolved_source: Some(ResolvedSource {
                    method: "static".into(),
                    confidence: "guess".into(),
                    ..Default::default()
                }),
            }],
        };
        let load = |r: &SourceReviews| {
            std::fs::write(
                dir.path().join("source-attribution.json"),
                serde_json::to_vec(r).unwrap(),
            )
            .unwrap();
            load_source_reviews(&path, dir.path(), &inv)
        };
        assert!(load(&reviews).unwrap().is_some());
        for case in 0..6 {
            let mut bad = reviews.clone();
            match case {
                0 => bad.inventory_sha256 = "f".repeat(64),
                1 => bad.controls[0].resolved_source.as_mut().unwrap().confidence = "exact".into(),
                2 => bad.controls[0].key = "missing".into(),
                3 => bad.controls.push(bad.controls[0].clone()),
                4 => bad.controls[0].original_source = Some(ResolvedSource::default()),
                _ => bad.role = None,
            }
            assert!(load(&bad).is_err(), "case {case}");
        }
        let mut current = inv.clone();
        apply_source_reviews(&mut current, reviews.clone()).unwrap();
        assert!(current.controls[0].source.is_some());
        assert!(
            current.source_reviews.as_ref().unwrap().controls[0]
                .original_source
                .is_none()
        );
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        inv.controls[0].source = Some(ResolvedSource {
            method: "runtime".into(),
            confidence: "probable".into(),
            ..Default::default()
        });
        let mut forbidden = reviews;
        forbidden.controls[0].original_source = inv.controls[0].source.clone();
        assert!(apply_source_reviews(&mut inv, forbidden).is_err());
    }
}
