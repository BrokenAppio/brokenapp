use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::explorer::template_sampler::template_to_view_id;
use crate::explorer::{CoverageSummary, ScanOutcome};
use crate::network::filters::is_application_api;
use crate::types::api::{ApiEndpoint, EndpointKey};
use crate::types::classifier::{ComponentType, DetectedComponent};
use crate::types::dom::InteractiveElement;
use crate::types::graph::ViewTransition;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSpecV1 {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub meta: SpecMeta,
    pub application: ApplicationInfo,
    pub views: Vec<ViewSpec>,
    pub api_surface: ApiSurface,
    #[serde(default)]
    pub data_models: serde_json::Value,
    pub state_machine: StateMachineSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecMeta {
    pub tool_version: String,
    pub scan_date: String,
    pub scan_duration_seconds: u64,
    pub target_url: String,
    pub coverage: CoverageSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_gaps: Option<crate::explorer::coverage::CoverageGapSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationInfo {
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_framework: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSurface {
    pub base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<ApiSurfaceSummary>,
    pub endpoints: Vec<ApiEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSurfaceSummary {
    pub total_endpoints_captured: usize,
    pub application_api_endpoints: usize,
    pub filtered_infrastructure: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachineSpec {
    pub entry_point: String,
    pub transitions: Vec<ViewTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewSpec {
    pub id: String,
    pub route: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub component_type: String,
    pub description: String,
    #[serde(default)]
    pub components: Vec<ComponentType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub component_instances: Vec<DetectedComponent>,
    #[serde(default)]
    pub elements: Vec<InteractiveElement>,
    #[serde(default)]
    pub on_load_api_calls: Vec<EndpointKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_framework: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<ViewSampling>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layout_variants: Vec<LayoutVariant>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewSampling {
    pub instances_visited: usize,
    pub unique_layouts: usize,
    pub saturated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutVariant {
    pub variant_id: String,
    pub fingerprint: String,
    pub frequency: String,
    pub description: String,
    pub components: Vec<ComponentType>,
    pub example_url: String,
}

pub fn generate_spec(outcome: &ScanOutcome) -> AppSpecV1 {
    let detected_framework = outcome
        .views
        .iter()
        .find_map(|v| v.detected_framework.clone());

    let mut endpoints_all = outcome.endpoints.clone();
    endpoints_all.sort_by(|a, b| a.key.cmp(&b.key));
    let mut endpoints_app: Vec<ApiEndpoint> = endpoints_all
        .iter()
        .cloned()
        .filter(|e| is_application_api(e))
        .map(redact_endpoint_for_spec)
        .collect();
    remap_endpoint_triggers(&mut endpoints_app, outcome);
    let api_summary = ApiSurfaceSummary {
        total_endpoints_captured: endpoints_all.len(),
        application_api_endpoints: endpoints_app.len(),
        filtered_infrastructure: endpoints_all.len().saturating_sub(endpoints_app.len()),
    };

    let views = build_view_specs(outcome);
    let entry_point = views
        .first()
        .map(|v| v.id.clone())
        .unwrap_or_else(|| "view_0001".to_string());

    AppSpecV1 {
        schema: "https://brokenapp.dev/schemas/app-spec-v1.json".to_string(),
        meta: SpecMeta {
            tool_version: env!("BROKENAPP_BUILD_VERSION").to_string(),
            scan_date: outcome.started_at.to_rfc3339(),
            scan_duration_seconds: outcome.scan_duration_seconds,
            target_url: outcome.target_url.clone(),
            coverage: outcome.coverage.clone(),
            coverage_gaps: if outcome.coverage_gaps.summary.total > 0 {
                Some(outcome.coverage_gaps.summary.clone())
            } else {
                None
            },
        },
        application: ApplicationInfo {
            base_url: outcome.target_url.clone(),
            detected_framework,
        },
        views,
        api_surface: ApiSurface {
            base_url: outcome.target_url.clone(),
            summary: Some(api_summary),
            endpoints: endpoints_app,
        },
        data_models: serde_json::json!({}),
        state_machine: StateMachineSpec {
            entry_point,
            transitions: remap_transitions(outcome),
        },
    }
}

fn remap_endpoint_triggers(endpoints: &mut [ApiEndpoint], outcome: &ScanOutcome) {
    // Map internal view IDs to template-level IDs for variant views.
    let mut mapping: HashMap<&str, String> = HashMap::new();
    for (template, state) in &outcome.template_sampler.templates {
        let spec_id = template_to_view_id(template);
        for v in &state.variants {
            mapping.entry(v.view_id.as_str()).or_insert(spec_id.clone());
        }
    }

    for ep in endpoints {
        for t in &mut ep.triggered_by {
            if let Some(mapped) = mapping.get(t.view.as_str()) {
                t.view = mapped.clone();
            }
        }
    }
}

fn redact_endpoint_for_spec(mut ep: ApiEndpoint) -> ApiEndpoint {
    ep.request_headers = redact_headers(&ep.request_headers);
    ep
}

fn redact_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            if k.eq_ignore_ascii_case("set-cookie") {
                return (k.clone(), redact_set_cookie_header(v));
            }
            if k.eq_ignore_ascii_case("cookie") {
                return (k.clone(), redact_cookie_header(v));
            }
            if is_sensitive_header_name(k) {
                if k.eq_ignore_ascii_case("authorization") {
                    let lower = v.trim().to_ascii_lowercase();
                    if lower.starts_with("bearer ") {
                        return (k.clone(), "Bearer <redacted>".to_string());
                    }
                    if lower.starts_with("basic ") {
                        return (k.clone(), "Basic <redacted>".to_string());
                    }
                }
                (k.clone(), "<redacted>".to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

fn redact_cookie_header(value: &str) -> String {
    let mut out = Vec::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut it = part.splitn(2, '=');
        let name = it.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        out.push(format!("{name}=<redacted>"));
    }
    out.join("; ")
}

fn redact_set_cookie_header(value: &str) -> String {
    let mut out_lines = Vec::new();
    for line in value.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(';');
        let first = parts.next().unwrap_or("").trim();
        let cookie_name = first.split('=').next().unwrap_or("").trim();
        if cookie_name.is_empty() {
            out_lines.push("<redacted>".to_string());
            continue;
        }
        let mut out = format!("{cookie_name}=<redacted>");
        let attrs: Vec<&str> = parts.map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
        if !attrs.is_empty() {
            out.push_str("; ");
            out.push_str(&attrs.join("; "));
        }
        out_lines.push(out);
    }
    out_lines.join("\n")
}

fn is_sensitive_header_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "x-api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-csrf-token"
    )
}

fn build_view_specs(outcome: &ScanOutcome) -> Vec<ViewSpec> {
    let view_by_id: HashMap<&str, &crate::types::graph::AppView> =
        outcome.views.iter().map(|v| (v.id.as_str(), v)).collect();

    // Track which internal views are represented as layout variants so we don't
    // also emit them as standalone views.
    let mut variant_view_ids: HashSet<String> = HashSet::new();
    let mut out: Vec<ViewSpec> = Vec::new();

    for (template, state) in &outcome.template_sampler.templates {
        if state.variants.is_empty() {
            continue;
        }

        let mut variants = state.variants.clone();
        variants.sort_by(|a, b| {
            b.seen_count
                .cmp(&a.seen_count)
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
        });

        let primary = variants.first().cloned();
        let Some(primary) = primary else { continue };

        for v in &variants {
            variant_view_ids.insert(v.view_id.clone());
        }

        let spec_id = template_to_view_id(template);
        let sampling = ViewSampling {
            instances_visited: state.visited_count,
            unique_layouts: state.variants.len(),
            saturated: state.saturated,
        };

        let primary_view = view_by_id.get(primary.view_id.as_str()).copied();
        let (
            title,
            component_type,
            mut description,
            components,
            component_instances,
            elements,
            on_load_api_calls,
            detected_framework,
            screenshot,
        ) = if let Some(v) = primary_view {
            (
                v.title.clone(),
                v.component_type.clone(),
                v.description.clone(),
                v.components.clone(),
                v.component_instances.clone(),
                with_found_on(&v.elements, &spec_id),
                v.on_load_api_calls.clone(),
                v.detected_framework.clone(),
                v.screenshot.clone(),
            )
        } else {
            (
                None,
                "unknown".to_string(),
                "Unclassified view".to_string(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                None,
            )
        };

        let mut layout_variants: Vec<LayoutVariant> = Vec::new();
        if variants.len() >= 2 {
            description = format!(
                "{} ({} layout variants across {} sampled instances)",
                description,
                variants.len(),
                state.visited_count
            );
            for (idx, var) in variants.iter().enumerate() {
                let v = view_by_id.get(var.view_id.as_str()).copied();
                let (v_desc, v_components) = if let Some(v) = v {
                    (v.description.clone(), v.components.clone())
                } else {
                    ("Unclassified variant".to_string(), Vec::new())
                };

                layout_variants.push(LayoutVariant {
                    variant_id: format!("variant_{}", idx + 1),
                    fingerprint: var.fingerprint.clone(),
                    frequency: format!("{} of {} sampled", var.seen_count, state.visited_count),
                    description: v_desc,
                    components: v_components,
                    example_url: var.example_url.clone(),
                });
            }
        }

        let dom_fingerprint = primary_view.map(|v| v.fingerprint.0.clone());
        out.push(ViewSpec {
            id: spec_id,
            route: state.template.clone(),
            title,
            component_type,
            description,
            components,
            component_instances,
            elements,
            on_load_api_calls,
            detected_framework,
            screenshot,
            sampling: Some(sampling),
            layout_variants,
            dom_fingerprint,
        });
    }

    // Emit all other views normally.
    for v in &outcome.views {
        if variant_view_ids.contains(&v.id) {
            continue;
        }
        let route = route_for_view(&v.url);
        out.push(ViewSpec {
            id: v.id.clone(),
            route,
            title: v.title.clone(),
            component_type: v.component_type.clone(),
            description: v.description.clone(),
            components: v.components.clone(),
            component_instances: v.component_instances.clone(),
            elements: with_found_on(&v.elements, &v.id),
            on_load_api_calls: v.on_load_api_calls.clone(),
            detected_framework: v.detected_framework.clone(),
            screenshot: v.screenshot.clone(),
            sampling: None,
            layout_variants: Vec::new(),
            dom_fingerprint: Some(v.fingerprint.0.clone()),
        });
    }

    out
}

fn route_for_view(url: &str) -> String {
    if let Ok(u) = Url::parse(url) {
        let (path, query) = crate::explorer::url_utils::effective_url_path_and_query(&u);
        if let Some(q) = query {
            format!("{path}?{q}")
        } else {
            path
        }
    } else {
        url.to_string()
    }
}

fn with_found_on(elements: &[InteractiveElement], view_id: &str) -> Vec<InteractiveElement> {
    elements
        .iter()
        .cloned()
        .map(|mut el| {
            el.found_on = view_id.to_string();
            el
        })
        .collect()
}

fn remap_transitions(outcome: &ScanOutcome) -> Vec<ViewTransition> {
    // Map internal view IDs to template-level IDs for variant views.
    let mut mapping: HashMap<&str, String> = HashMap::new();
    for (template, state) in &outcome.template_sampler.templates {
        let spec_id = template_to_view_id(template);
        for v in &state.variants {
            // If the same internal view ID maps to multiple templates (rare but possible),
            // keep the original to avoid creating dangling references.
            mapping.entry(v.view_id.as_str()).or_insert(spec_id.clone());
        }
    }

    outcome
        .transitions
        .iter()
        .cloned()
        .map(|mut t| {
            if let Some(mapped) = mapping.get(t.from_view.as_str()) {
                t.from_view = mapped.clone();
            }
            if let Some(mapped) = mapping.get(t.to_view.as_str()) {
                t.to_view = mapped.clone();
            }
            if let Some(mapped) = mapping.get(t.trigger.view.as_str()) {
                t.trigger.view = mapped.clone();
            }
            t
        })
        .collect()
}
