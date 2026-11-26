use std::collections::{BTreeSet, HashMap};

use crate::types::api::{ApiEndpoint, HttpMethod, JsonSchemaType};
use crate::types::classifier::{ClassifiedView, ComponentType, FormFieldDef};
use crate::types::dom::InteractionRef;

fn http_method_rank(m: HttpMethod) -> u8 {
    match m {
        HttpMethod::Post => 0,
        HttpMethod::Put => 1,
        HttpMethod::Patch => 2,
        HttpMethod::Delete => 3,
        HttpMethod::Ws => 4,
        HttpMethod::Get => 5,
        HttpMethod::Head => 6,
        HttpMethod::Options => 7,
    }
}

pub(super) fn best_endpoint_for_form_interaction(
    endpoints: &[ApiEndpoint],
    trigger: &InteractionRef,
    form_fields: &[FormFieldDef],
    view_route: &str,
) -> Option<(String, i64)> {
    let mut candidates: Vec<&ApiEndpoint> = endpoints
        .iter()
        .filter(|ep| crate::network::filters::is_application_api(ep))
        .filter(|ep| ep.triggered_by.iter().any(|t| t == trigger))
        .collect();

    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by(|a, b| {
        let sa = score_endpoint_for_form(a, form_fields, view_route);
        let sb = score_endpoint_for_form(b, form_fields, view_route);
        sb.cmp(&sa)
            .then_with(|| http_method_rank(a.key.method).cmp(&http_method_rank(b.key.method)))
            .then_with(|| b.key.path_template.len().cmp(&a.key.path_template.len()))
    });

    let best = *candidates.first()?;
    let score = score_endpoint_for_form(best, form_fields, view_route);
    Some((
        format!("{} {}", best.key.method.as_str(), best.key.path_template),
        score,
    ))
}

fn score_endpoint_for_form(
    ep: &ApiEndpoint,
    form_fields: &[FormFieldDef],
    view_route: &str,
) -> i64 {
    let mut score: i64 = 0;

    // Prefer write methods when mapping form submits.
    score += match ep.key.method {
        HttpMethod::Put => 50,
        HttpMethod::Patch => 48,
        HttpMethod::Post => 45,
        HttpMethod::Ws => 35,
        HttpMethod::Delete => 15,
        HttpMethod::Get => 10,
        HttpMethod::Head => 5,
        HttpMethod::Options => -100,
    };

    let path = ep.key.path_template.to_ascii_lowercase();

    // De-prioritize telemetry/tracking endpoints that often fire alongside real mutations.
    if looks_like_telemetry_endpoint(&path) {
        score -= 35;
    }

    // Prefer endpoints that "look like" they belong to this view's resource.
    for hint in view_route_hints(view_route) {
        if hint.is_empty() {
            continue;
        }
        if path.contains(&format!("/api/{hint}")) || path.contains(&format!("/{hint}/")) {
            score += 10;
        }
    }

    // Prefer endpoints where the request schema keys overlap form fields.
    let schema_keys: Vec<String> = ep
        .request_body_schema
        .as_ref()
        .and_then(|schema| {
            if schema.schema_type != JsonSchemaType::Object || schema.properties.is_empty() {
                None
            } else {
                Some(schema.properties.keys().cloned().collect::<Vec<String>>())
            }
        })
        .unwrap_or_default();
    let query_keys: Vec<String> = ep.query_params.iter().map(|q| q.name.clone()).collect();

    let mut hits = 0_i64;
    for f in form_fields {
        let inferred = f
            .name
            .clone()
            .or_else(|| f.label.as_deref().map(infer_field_name_from_label))
            .unwrap_or_default();
        if inferred.is_empty() {
            continue;
        }
        let candidates = field_name_candidates(&inferred);
        if find_best_schema_key(&schema_keys, &candidates).is_some()
            || find_best_schema_key(&query_keys, &candidates).is_some()
        {
            hits += 1;
        }
    }
    if hits > 0 {
        score += 6 * hits;
        score += 8; // bonus for any overlap at all
    }
    if ep.request_body_schema.is_some() {
        score += 6;
    }

    // Prefer successful observations.
    if ep
        .response_status_codes
        .iter()
        .any(|s| matches!(*s, 200 | 201 | 202 | 204))
    {
        score += 3;
    }
    if ep.response_status_codes.iter().any(|s| *s >= 500) {
        score -= 10;
    }

    if ep.auth_required {
        score += 2;
    }

    // Prefer more specific paths.
    score += (ep.key.path_template.len() as i64).min(60) / 10;
    score
}

fn looks_like_telemetry_endpoint(path_lower: &str) -> bool {
    // Common endpoint patterns that fire during interactions but are not the
    // primary business mutation.
    let needles = [
        "/analytics",
        "/telemetry",
        "/events",
        "/event",
        "/track",
        "/tracking",
        "/sentry",
        "/log",
        "/logs",
    ];
    needles.iter().any(|n| path_lower.contains(n))
}

fn view_route_hints(view_route: &str) -> Vec<String> {
    let path = view_route.split('?').next().unwrap_or(view_route);
    let mut out = Vec::new();
    for seg in path.trim_matches('/').split('/') {
        if seg.is_empty() || seg == ":id" {
            continue;
        }
        // Avoid adding numeric/id-ish segments as hints.
        if seg.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if seg.len() >= 3 {
            out.push(seg.to_ascii_lowercase());
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(super) fn enrich_form_field_names_from_request_schema(
    classified: &mut ClassifiedView,
    endpoints: &[ApiEndpoint],
) {
    for comp in &mut classified.components {
        let ComponentType::Form {
            fields,
            submit_endpoint,
            ..
        } = &mut comp.component
        else {
            continue;
        };

        let Some(desc) = submit_endpoint.as_deref() else {
            continue;
        };
        let Some((method, path_template)) = parse_endpoint_desc(desc) else {
            continue;
        };

        let Some(ep) = endpoints
            .iter()
            .find(|e| e.key.method == method && e.key.path_template == path_template)
        else {
            continue;
        };

        let schema_keys: Vec<String> = ep
            .request_body_schema
            .as_ref()
            .and_then(|schema| {
                if schema.schema_type != JsonSchemaType::Object || schema.properties.is_empty() {
                    None
                } else {
                    Some(schema.properties.keys().cloned().collect::<Vec<String>>())
                }
            })
            .unwrap_or_default();
        let query_keys: Vec<String> = ep.query_params.iter().map(|q| q.name.clone()).collect();

        for f in fields.iter_mut() {
            if f.name.is_some() {
                continue;
            }
            let Some(label) = f.label.as_deref() else {
                continue;
            };

            let inferred = infer_field_name_from_label(label);
            if inferred.is_empty() {
                continue;
            }

            let candidates = field_name_candidates(&inferred);
            // Prefer request body keys, then fall back to query param names.
            if let Some(found) = find_best_schema_key(&schema_keys, &candidates)
                .or_else(|| find_best_schema_key(&query_keys, &candidates))
            {
                f.name = Some(found);
            }
        }
    }
}

pub(super) fn enrich_forms_with_submit_labels(
    classified: &mut ClassifiedView,
    form_submit_label_map: &HashMap<String, String>,
) {
    if form_submit_label_map.is_empty() {
        return;
    }

    for comp in &mut classified.components {
        let ComponentType::Form {
            has_submit,
            submit_label,
            ..
        } = &mut comp.component
        else {
            continue;
        };

        let Some(label) = form_submit_label_map.get(&comp.selector) else {
            continue;
        };

        let should_override = submit_label.as_deref().is_none()
            || crate::dom::heuristics::is_bad_submit_label(submit_label.as_deref())
            || crate::dom::heuristics::is_destructive_mutation_label(submit_label.as_deref());

        if should_override {
            *submit_label = Some(label.clone());
        }
        *has_submit = true;
    }
}

pub(super) fn enrich_form_fields_with_query_param_mapping(
    classified: &mut ClassifiedView,
    selector_to_query_params: &HashMap<String, BTreeSet<String>>,
) {
    if selector_to_query_params.is_empty() {
        return;
    }

    for comp in &mut classified.components {
        let ComponentType::Form { fields, .. } = &mut comp.component else {
            continue;
        };

        for f in fields.iter_mut() {
            let Some(set) = selector_to_query_params.get(&f.selector) else {
                continue;
            };
            if set.is_empty() {
                continue;
            }

            // Persist the mapping for rebuild/spec consumption.
            f.drives_query_params = set.iter().cloned().collect::<Vec<_>>();

            // Opportunistically infer `name` from the URL query param key.
            if f.name.is_none() {
                if set.len() == 1 {
                    if let Some(k) = set.iter().next() {
                        if !k.trim().is_empty() {
                            f.name = Some(k.clone());
                            continue;
                        }
                    }
                }

                if let Some(label) = f.label.as_deref() {
                    let inferred = infer_field_name_from_label(label);
                    if !inferred.is_empty() {
                        let candidates = field_name_candidates(&inferred);
                        let keys = set.iter().cloned().collect::<Vec<_>>();
                        if let Some(found) = find_best_schema_key(&keys, &candidates) {
                            f.name = Some(found);
                        }
                    }
                }
            }
        }
    }
}

fn parse_endpoint_desc(desc: &str) -> Option<(HttpMethod, String)> {
    let mut it = desc.split_whitespace();
    let m = it.next()?;
    let path = it.next()?;
    Some((HttpMethod::from_str_lossy(m), path.to_string()))
}

fn infer_field_name_from_label(label: &str) -> String {
    // Similar to normalize::label_cleaner::infer_field_name_from_label, but kept local
    // to avoid coupling the scan pipeline to the post-scan normalizer.
    let mut out = String::new();
    let mut prev_us = false;
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_us = false;
        } else if ch.is_whitespace()
            || ch == '_'
            || ch == '-'
            || ch == '/'
            || ch == '('
            || ch == ')'
        {
            if !prev_us && !out.is_empty() {
                out.push('_');
                prev_us = true;
            }
        }
    }
    out.trim_matches('_').to_string()
}

fn field_name_candidates(snake: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !snake.is_empty() {
        out.push(snake.to_string());
        out.push(snake_to_camel(snake));
        out.push(snake.replace('_', ""));
    }
    out.sort();
    out.dedup();
    out
}

fn snake_to_camel(s: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for ch in s.chars() {
        if ch == '_' {
            upper = true;
            continue;
        }
        if upper {
            out.push(ch.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn find_best_schema_key(schema_keys: &[String], candidates: &[String]) -> Option<String> {
    // 1) Exact matches.
    for c in candidates {
        if schema_keys.iter().any(|k| k == c) {
            return Some(c.clone());
        }
    }

    // 2) Normalized matches (ignore case and underscores).
    let norm_candidates: Vec<String> = candidates.iter().map(|c| normalize_key(c)).collect();
    for c_norm in &norm_candidates {
        for k in schema_keys {
            if normalize_key(k) == *c_norm {
                return Some(k.clone());
            }
        }
        // Small preference: if the schema has a key that starts with the candidate.
        for k in schema_keys {
            if normalize_key(k).starts_with(c_norm) {
                return Some(k.clone());
            }
        }
    }
    None
}

fn normalize_key(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}
