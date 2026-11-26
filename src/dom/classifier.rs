//! Component classifier.
//!
//! This injects a JS payload (via CDP Runtime.evaluate) to analyze the DOM
//! structure of the current page, then maps the raw JSON results into typed
//! `ComponentType` variants.

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, instrument, warn};

use crate::browser::PageClient;
use crate::dom::selector::{LOCATOR_RUNTIME_JS, primary_locator_json};
use crate::types::classifier::{
    BreadcrumbItem, ClassifiedView, ColumnDef, ComponentType, ComponentVisualProfile,
    DashboardWidget, DashboardWidgetType, DetailFieldDef, DetectedComponent, DomClassSample,
    DomTextSample, FilterDef, FilterType, FormFieldDef, FormFieldType, NavItem, NavType, TabDef,
};
use crate::types::dom::{InteractiveElement, LocatorStrategy};

use super::classify_js::CLASSIFY_PAGE_COMPONENTS;

// ---------------------------------------------------------------------------
// Raw JSON shape coming back from the injected JS
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawComponent {
    kind: String,
    selector: String,
    confidence: f64,
    meta: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Classify all detectable UI components on the current page.
#[instrument(skip(page))]
pub async fn classify_current_view(page: &PageClient) -> Result<ClassifiedView> {
    let raw_json: String = page
        .inner()
        .evaluate(CLASSIFY_PAGE_COMPONENTS)
        .await
        .context("evaluate classification JS")?
        .into_value()
        .context("classification JS returned non-string")?;

    debug!(raw_len = raw_json.len(), "classification JS returned");

    let raw_components: Vec<RawComponent> =
        serde_json::from_str(&raw_json).context("parse classification JSON")?;

    debug!(count = raw_components.len(), "raw components detected");

    let mut components: Vec<DetectedComponent> = Vec::new();
    for raw in &raw_components {
        match convert_raw_component(raw) {
            Ok(component) => {
                components.push(DetectedComponent {
                    selector: raw.selector.clone(),
                    component,
                    confidence: raw.confidence,
                    visual: parse_visual_profile(&raw.meta),
                });
            }
            Err(e) => {
                warn!(
                    kind = %raw.kind,
                    selector = %raw.selector,
                    error = %e,
                    "failed to convert component, skipping"
                );
            }
        }
    }

    let primary_type = determine_primary_type(&components);
    let description = generate_description(&primary_type, &components);

    Ok(ClassifiedView {
        primary_type,
        description,
        components,
    })
}

/// Enrich form components with their submit endpoints, discovered by
/// correlating the network interceptor's captured API calls with the form's
/// submit interactions.
pub fn enrich_forms_with_endpoints(
    classified: &mut ClassifiedView,
    form_endpoint_map: &std::collections::HashMap<String, String>,
) {
    for comp in &mut classified.components {
        if let ComponentType::Form {
            submit_endpoint, ..
        } = &mut comp.component
        {
            if let Some(endpoint) = form_endpoint_map.get(&comp.selector) {
                *submit_endpoint = Some(endpoint.clone());
            }
        }
    }
}

/// Enrich detail views with entity type guesses based on URL patterns.
pub fn enrich_detail_view_entity(classified: &mut ClassifiedView, current_url: &str) {
    for comp in &mut classified.components {
        if let ComponentType::DetailView { entity_type, .. } = &mut comp.component {
            if entity_type.is_none() {
                *entity_type = infer_entity_from_url(current_url);
            }
        }
    }
}

/// For a given element selector, find the closest `<form>` ancestor (or a
/// "form-like" container) and return its selector using the same
/// `getSelector()` algorithm used by the classifier JS.
pub async fn closest_form_selector(
    page: &PageClient,
    element: &InteractiveElement,
) -> Result<Option<String>> {
    let locator_json = primary_locator_json(element)?;
    let script = format!(
        r#"
(() => {{
  const targetLocator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  let el = null;
  try {{ el = resolveBrokenAppLocator(targetLocator); }} catch (_) {{ return null; }}
  if (!el) return null;
  const form = el.closest && el.closest('form');

  function getSelector(el) {{
    if (el.id) return '#' + CSS.escape(el.id);
    if (el.dataset && el.dataset.testid) return `[data-testid="${{CSS.escape(el.dataset.testid)}}"]`;
    const parts = [];
    let cur = el;
    while (cur && cur !== document.body && parts.length < 5) {{
      let seg = cur.tagName.toLowerCase();
      if (cur.id) {{ parts.unshift('#' + CSS.escape(cur.id)); break; }}
      if (cur.className && typeof cur.className === 'string') {{
        const cls = cur.className.trim().split(/\s+/)
          .filter(c => !c.match(/^(active|selected|open|show|visible|hidden|hover|focus)/))
          .slice(0, 2);
        if (cls.length) seg += '.' + cls.map(c => CSS.escape(c)).join('.');
      }}
      const parent = cur.parentElement;
      if (parent) {{
        const siblings = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
        if (siblings.length > 1) seg += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
      }}
      parts.unshift(seg);
      cur = cur.parentElement;
    }}
    return parts.join(' > ');
  }}

  if (form) return getSelector(form);

  // Implicit forms: find an ancestor container that looks like a form.
  // This mirrors the classifier's heuristic for "implicit forms".
  let candidate = null;
  let cur = el;
  while (cur && cur !== document.body && cur.nodeType === 1) {{
    const tag = (cur.tagName || '').toLowerCase();
    if ((tag === 'div' || tag === 'section' || tag === 'article' || tag === 'main') && !cur.closest('form')) {{
      const inputs = cur.querySelectorAll('input:not([type="hidden"]), select, textarea');
      const buttons = cur.querySelectorAll('button, [role="button"]');
      if (inputs.length >= 3 && buttons.length >= 1) {{
        const directInputs = Array.from(inputs).filter(inp => {{
          let depth = 0, n = inp;
          while (n !== cur && depth < 6) {{ n = n.parentElement; depth++; }}
          return n === cur;
        }});
        if (directInputs.length >= 3) {{
          candidate = cur;
          break; // Prefer the nearest form-like ancestor.
        }}
      }}
    }}
    cur = cur.parentElement;
  }}

  if (candidate) return getSelector(candidate);
  return null;
}})()
"#
    );

    let out: Option<String> = page
        .inner()
        .evaluate(script)
        .await
        .context("evaluate closest form selector")?
        .into_value()
        .ok();
    Ok(out)
}

/// Convert any element selector into the canonical selector form used by the
/// classifier (`getSelector()` in `classify_js.rs`).
///
/// This lets the explorer correlate interactions discovered by the element
/// discovery pass with `FormFieldDef.selector` values generated by the
/// classifier.
pub async fn canonical_selector(
    page: &PageClient,
    element: &InteractiveElement,
) -> Result<Option<String>> {
    let locator_json = primary_locator_json(element)?;
    let script = format!(
        r#"
(() => {{
  const targetLocator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  let el = null;
  try {{ el = resolveBrokenAppLocator(targetLocator); }} catch (_) {{ return null; }}
  if (!el) return null;

  function getSelector(el) {{
    if (el.id) return '#' + CSS.escape(el.id);
    if (el.dataset && el.dataset.testid) return `[data-testid="${{CSS.escape(el.dataset.testid)}}"]`;
    const parts = [];
    let cur = el;
    while (cur && cur !== document.body && parts.length < 5) {{
      let seg = cur.tagName.toLowerCase();
      if (cur.id) {{ parts.unshift('#' + CSS.escape(cur.id)); break; }}
      if (cur.className && typeof cur.className === 'string') {{
        const cls = cur.className.trim().split(/\s+/)
          .filter(c => !c.match(/^(active|selected|open|show|visible|hidden|hover|focus)/))
          .slice(0, 2);
        if (cls.length) seg += '.' + cls.map(c => CSS.escape(c)).join('.');
      }}
      const parent = cur.parentElement;
      if (parent) {{
        const siblings = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
        if (siblings.length > 1) seg += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
      }}
      parts.unshift(seg);
      cur = cur.parentElement;
    }}
    return parts.join(' > ');
  }}

  return getSelector(el);
}})()
"#
    );

    let out: Option<String> = page
        .inner()
        .evaluate(script)
        .await
        .context("evaluate canonical selector")?
        .into_value()
        .ok();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Conversion: raw JSON → typed ComponentType
// ---------------------------------------------------------------------------

fn convert_raw_component(raw: &RawComponent) -> Result<ComponentType> {
    let meta = &raw.meta;

    match raw.kind.as_str() {
        "data_table" => {
            let columns: Vec<ColumnDef> = meta
                .get("columns")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| {
                            Some(ColumnDef {
                                label: c.get("label")?.as_str()?.to_string(),
                                field: infer_field_name(c.get("label")?.as_str()?),
                                sortable: c
                                    .get("sortable")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                                index: c.get("index").and_then(|v| v.as_u64()).unwrap_or(0)
                                    as usize,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::DataTable {
                columns,
                row_count: meta.get("row_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
                has_pagination: meta
                    .get("has_pagination")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                has_sorting: meta
                    .get("has_sorting")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                has_filtering: meta
                    .get("has_filtering")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                has_bulk_actions: meta
                    .get("has_bulk_actions")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            })
        }

        "form" => {
            let fields: Vec<FormFieldDef> = meta
                .get("fields")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|f| {
                            let raw_type = f.get("field_type")?.as_str()?.to_string();
                            let options: Vec<String> = f
                                .get("options")
                                .and_then(|v| v.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|o| o.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();

                            let field_type = parse_form_field_type(&raw_type, options);

                            Some(FormFieldDef {
                                label: f.get("label").and_then(|v| v.as_str()).map(String::from),
                                name: f.get("name").and_then(|v| v.as_str()).map(String::from),
                                field_type,
                                required: f
                                    .get("required")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                                placeholder: f
                                    .get("placeholder")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                selector: f.get("selector")?.as_str()?.to_string(),
                                locators: parse_locator_strategies(f.get("locators")),
                                drives_query_params: Vec::new(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::Form {
                fields,
                has_submit: meta
                    .get("has_submit")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                submit_label: meta
                    .get("submit_label")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                submit_selector: meta
                    .get("submit_selector")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                submit_locators: parse_locator_strategies(meta.get("submit_locators")),
                submit_endpoint: None,
            })
        }

        "navigation" => {
            let nav_type_str = meta
                .get("nav_type")
                .and_then(|v| v.as_str())
                .unwrap_or("top_bar");
            let nav_type = match nav_type_str {
                "sidebar" => NavType::Sidebar,
                "tab_bar" => NavType::TabBar,
                "breadcrumbs" => NavType::Breadcrumbs,
                "pagination" => NavType::Pagination,
                "step_wizard" => NavType::StepWizard,
                "footer" => NavType::Footer,
                _ => NavType::TopBar,
            };

            let items: Vec<NavItem> = meta
                .get("items")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            Some(NavItem {
                                label: item.get("label")?.as_str()?.to_string(),
                                href: item.get("href").and_then(|v| v.as_str()).map(String::from),
                                is_active: item
                                    .get("is_active")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                                icon: item.get("icon").and_then(|v| v.as_str()).map(String::from),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::Navigation { nav_type, items })
        }

        "breadcrumbs" => {
            let items: Vec<BreadcrumbItem> = meta
                .get("items")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            Some(BreadcrumbItem {
                                label: item.get("label")?.as_str()?.to_string(),
                                href: item.get("href").and_then(|v| v.as_str()).map(String::from),
                                is_current: item
                                    .get("is_current")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::Breadcrumbs { items })
        }

        "detail_view" => {
            let fields: Vec<DetailFieldDef> = meta
                .get("fields")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|f| {
                            Some(DetailFieldDef {
                                label: f.get("label")?.as_str()?.to_string(),
                                value_preview: f
                                    .get("value_preview")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                value_type: f
                                    .get("value_type")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::DetailView {
                entity_type: meta
                    .get("entity_type")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                fields,
            })
        }

        "dashboard" => {
            let widgets: Vec<DashboardWidget> = meta
                .get("widgets")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|w| {
                            let wtype = match w.get("widget_type")?.as_str()? {
                                "stat_card" => DashboardWidgetType::StatCard,
                                "chart" => DashboardWidgetType::Chart,
                                "table" => DashboardWidgetType::Table,
                                "list" => DashboardWidgetType::List,
                                "calendar" => DashboardWidgetType::Calendar,
                                "recent_activity" => DashboardWidgetType::RecentActivity,
                                _ => DashboardWidgetType::Unknown,
                            };
                            Some(DashboardWidget {
                                widget_type: wtype,
                                title: w.get("title").and_then(|v| v.as_str()).map(String::from),
                                selector: w.get("selector")?.as_str()?.to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::Dashboard { widgets })
        }

        "search" => {
            let filters: Vec<FilterDef> = meta
                .get("filters")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|f| {
                            let ft = match f.get("filter_type")?.as_str()? {
                                "select" => FilterType::Select { options: vec![] },
                                "multi_select" => FilterType::MultiSelect { options: vec![] },
                                "date_range" => FilterType::DateRange,
                                "number_range" => FilterType::NumberRange,
                                "toggle" => FilterType::Toggle,
                                _ => FilterType::Text,
                            };
                            Some(FilterDef {
                                label: f.get("label").and_then(|v| v.as_str()).map(String::from),
                                field: f.get("field").and_then(|v| v.as_str()).map(String::from),
                                filter_type: ft,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::SearchInterface {
                input_selector: meta
                    .get("input_selector")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                has_results_container: meta
                    .get("has_results_container")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                has_filters: !filters.is_empty(),
                filters,
            })
        }

        "tab_group" => {
            let tabs: Vec<TabDef> = meta
                .get("tabs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            Some(TabDef {
                                label: t.get("label")?.as_str()?.to_string(),
                                is_active: t
                                    .get("is_active")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                                selector: t.get("selector")?.as_str()?.to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ComponentType::TabGroup {
                active_index: meta
                    .get("active_index")
                    .and_then(|v| v.as_i64())
                    .map(|i| i.max(0) as usize),
                tabs,
            })
        }

        "modal" => Ok(ComponentType::Modal {
            title: meta.get("title").and_then(|v| v.as_str()).map(String::from),
            has_close_button: meta
                .get("has_close_button")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            inner_component: None,
        }),

        "chart" => Ok(ComponentType::Chart {
            chart_type: meta
                .get("chart_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            canvas_or_svg: meta
                .get("canvas_or_svg")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
        }),

        "list_view" => Ok(ComponentType::ListView {
            item_count: meta.get("item_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            item_selector: meta
                .get("item_selector")
                .and_then(|v| v.as_str())
                .map(String::from),
            has_pagination: meta
                .get("has_pagination")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        }),

        "stat_card" => Ok(ComponentType::StatsCard {
            label: meta.get("label").and_then(|v| v.as_str()).map(String::from),
            value: meta.get("value").and_then(|v| v.as_str()).map(String::from),
        }),

        "empty_state" => Ok(ComponentType::EmptyState {
            message: meta
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from),
            has_cta: meta
                .get("has_cta")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        }),

        "error_page" => Ok(ComponentType::ErrorPage {
            error_type: meta
                .get("error_type")
                .and_then(|v| v.as_str())
                .map(String::from),
            message: meta
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from),
        }),

        other => {
            warn!(kind = other, "unknown component kind from JS");
            Ok(ComponentType::Unknown {
                tag: other.to_string(),
                role: None,
                child_count: 0,
            })
        }
    }
}

fn parse_visual_profile(meta: &serde_json::Value) -> Option<ComponentVisualProfile> {
    let visual = meta.get("visual")?;

    let class_list = visual
        .get("class_list")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let probe_class_list = visual
        .get("probe_class_list")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let token_mismatches = visual
        .get("token_mismatches")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let class_samples = visual
        .get("class_samples")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|node| {
                    let tag = node.get("tag")?.as_str()?.to_string();
                    if tag.trim().is_empty() {
                        return None;
                    }
                    let class_list = node
                        .get("class_list")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToString::to_string))
                                .collect::<Vec<String>>()
                        })
                        .unwrap_or_default();
                    Some(DomClassSample {
                        tag,
                        role: get_opt_string(node, "role"),
                        class_list,
                        has_inline_style: node
                            .get("has_inline_style")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                    })
                })
                .collect::<Vec<DomClassSample>>()
        })
        .unwrap_or_default();

    let text_samples = visual
        .get("text_samples")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|node| {
                    let text = node.get("text")?.as_str()?.trim().to_string();
                    let selector = node.get("selector")?.as_str()?.trim().to_string();
                    if text.is_empty() || selector.is_empty() {
                        return None;
                    }
                    let class_list = node
                        .get("class_list")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToString::to_string))
                                .collect::<Vec<String>>()
                        })
                        .unwrap_or_default();
                    Some(DomTextSample {
                        text,
                        selector,
                        x_px: get_opt_f64(node, "x_px")?,
                        y_px: get_opt_f64(node, "y_px")?,
                        width_px: get_opt_f64(node, "width_px")?,
                        height_px: get_opt_f64(node, "height_px")?,
                        container_selector: get_opt_string(node, "container_selector"),
                        container_x_px: get_opt_f64(node, "container_x_px"),
                        container_y_px: get_opt_f64(node, "container_y_px"),
                        container_width_px: get_opt_f64(node, "container_width_px"),
                        container_height_px: get_opt_f64(node, "container_height_px"),
                        class_list,
                    })
                })
                .collect::<Vec<DomTextSample>>()
        })
        .unwrap_or_default();

    let profile = ComponentVisualProfile {
        class_list,
        has_inline_style: visual
            .get("has_inline_style")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        inline_style_preview: get_opt_string(visual, "inline_style_preview"),
        display: get_opt_string(visual, "display"),
        position: get_opt_string(visual, "position"),
        z_index: get_opt_i64(visual, "z_index"),
        color: get_opt_string(visual, "color"),
        background_color: get_opt_string(visual, "background_color"),
        border_color: get_opt_string(visual, "border_color"),
        border_radius_px: get_opt_f64(visual, "border_radius_px"),
        border_width_px: get_opt_f64(visual, "border_width_px"),
        padding_x_px: get_opt_f64(visual, "padding_x_px"),
        padding_y_px: get_opt_f64(visual, "padding_y_px"),
        margin_x_px: get_opt_f64(visual, "margin_x_px"),
        margin_y_px: get_opt_f64(visual, "margin_y_px"),
        gap_px: get_opt_f64(visual, "gap_px"),
        font_size_px: get_opt_f64(visual, "font_size_px"),
        line_height_px: get_opt_f64(visual, "line_height_px"),
        font_weight: get_opt_u16(visual, "font_weight"),
        x_px: get_opt_f64(visual, "x_px"),
        y_px: get_opt_f64(visual, "y_px"),
        width_px: get_opt_f64(visual, "width_px"),
        height_px: get_opt_f64(visual, "height_px"),
        probe_padding_x_px: get_opt_f64(visual, "probe_padding_x_px"),
        probe_padding_y_px: get_opt_f64(visual, "probe_padding_y_px"),
        probe_font_size_px: get_opt_f64(visual, "probe_font_size_px"),
        probe_border_radius_px: get_opt_f64(visual, "probe_border_radius_px"),

        probe_tag: get_opt_string(visual, "probe_tag"),
        probe_selector: get_opt_string(visual, "probe_selector"),
        probe_class_list,
        probe_has_inline_style: visual
            .get("probe_has_inline_style")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        probe_inline_style_preview: get_opt_string(visual, "probe_inline_style_preview"),
        class_samples,
        text_samples,
        token_mismatches,
    };

    let has_signal = !profile.class_list.is_empty()
        || profile.has_inline_style
        || profile.inline_style_preview.is_some()
        || profile.display.is_some()
        || profile.position.is_some()
        || profile.z_index.is_some()
        || profile.color.is_some()
        || profile.background_color.is_some()
        || profile.border_color.is_some()
        || profile.border_radius_px.is_some()
        || profile.border_width_px.is_some()
        || profile.padding_x_px.is_some()
        || profile.padding_y_px.is_some()
        || profile.margin_x_px.is_some()
        || profile.margin_y_px.is_some()
        || profile.gap_px.is_some()
        || profile.font_size_px.is_some()
        || profile.line_height_px.is_some()
        || profile.font_weight.is_some()
        || profile.x_px.is_some()
        || profile.y_px.is_some()
        || profile.width_px.is_some()
        || profile.height_px.is_some()
        || profile.probe_padding_x_px.is_some()
        || profile.probe_padding_y_px.is_some()
        || profile.probe_font_size_px.is_some()
        || profile.probe_border_radius_px.is_some()
        || profile.probe_tag.is_some()
        || profile.probe_selector.is_some()
        || !profile.probe_class_list.is_empty()
        || profile.probe_has_inline_style
        || profile.probe_inline_style_preview.is_some()
        || !profile.class_samples.is_empty()
        || !profile.text_samples.is_empty()
        || !profile.token_mismatches.is_empty();

    if has_signal { Some(profile) } else { None }
}

// ---------------------------------------------------------------------------
// Primary type determination
// ---------------------------------------------------------------------------

fn determine_primary_type(components: &[DetectedComponent]) -> String {
    if components.is_empty() {
        return "unknown".to_string();
    }

    let has_substantial_app_surface = components.iter().any(is_substantial_app_surface);
    let mut scores: Vec<(&str, f64)> = components
        .iter()
        .map(|c| {
            let (type_name, importance) = match &c.component {
                ComponentType::ErrorPage { .. } => (
                    "error_page",
                    if has_substantial_app_surface {
                        2.0
                    } else {
                        10.0
                    },
                ),
                ComponentType::DataTable { has_filtering, .. } => {
                    if *has_filtering {
                        ("data_table_with_search", 8.0)
                    } else {
                        ("data_table", 7.0)
                    }
                }
                ComponentType::Form { fields, .. } => {
                    if fields.len() > 5 {
                        ("form", 7.5)
                    } else {
                        ("form", 6.0)
                    }
                }
                ComponentType::Dashboard { .. } => ("dashboard", 8.0),
                ComponentType::DetailView { .. } => ("detail_view", 6.5),
                ComponentType::SearchInterface { .. } => ("search", 5.0),
                ComponentType::ListView { .. } => ("list_view", 5.5),
                ComponentType::EmptyState { .. } => ("empty_state", 3.0),
                ComponentType::Modal { .. } => ("modal", 2.0),
                ComponentType::Navigation { .. } => ("navigation", 1.0),
                ComponentType::Breadcrumbs { .. } => ("breadcrumbs", 0.5),
                ComponentType::TabGroup { .. } => ("tabbed_view", 4.0),
                ComponentType::Chart { .. } => ("chart", 4.0),
                ComponentType::StatsCard { .. } => ("stats", 3.0),
                ComponentType::Calendar => ("calendar", 6.0),
                ComponentType::FileUploadZone => ("file_upload", 5.0),
                ComponentType::RichTextEditor => ("editor", 5.0),
                _ => ("unknown", 1.0),
            };
            (type_name, importance * c.confidence)
        })
        .collect();

    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Composite: table + search => data_table_with_search
    let has_table = scores
        .iter()
        .any(|(t, _)| *t == "data_table" || *t == "data_table_with_search");
    let has_search = scores.iter().any(|(t, _)| *t == "search");
    if has_table && has_search {
        return "data_table_with_search".to_string();
    }

    scores
        .first()
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_substantial_app_surface(component: &DetectedComponent) -> bool {
    match &component.component {
        ComponentType::DataTable {
            columns, row_count, ..
        } => *row_count >= 2 || columns.len() >= 2,
        ComponentType::Form { fields, .. } => fields.len() >= 3,
        ComponentType::Dashboard { widgets } => !widgets.is_empty(),
        ComponentType::DetailView { fields, .. } => fields.len() >= 3,
        ComponentType::ListView { item_count, .. } => *item_count >= 3,
        _ => false,
    }
}

fn generate_description(_primary_type: &str, components: &[DetectedComponent]) -> String {
    let mut parts: Vec<String> = Vec::new();

    for comp in components {
        match &comp.component {
            ComponentType::DataTable {
                columns,
                row_count,
                has_pagination,
                has_sorting,
                has_bulk_actions,
                ..
            } => {
                let mut desc = format!("{}-column data table", columns.len());
                if *row_count > 0 {
                    desc += &format!(" with {} rows", row_count);
                }
                let features: Vec<&str> = [
                    if *has_pagination {
                        Some("pagination")
                    } else {
                        None
                    },
                    if *has_sorting { Some("sorting") } else { None },
                    if *has_bulk_actions {
                        Some("bulk actions")
                    } else {
                        None
                    },
                ]
                .into_iter()
                .flatten()
                .collect();
                if !features.is_empty() {
                    desc += &format!(" ({})", features.join(", "));
                }
                parts.push(desc);
            }
            ComponentType::Form {
                fields,
                submit_label,
                ..
            } => {
                parts.push(format!(
                    "form with {} fields{}",
                    fields.len(),
                    submit_label
                        .as_ref()
                        .map(|l| format!(" (submit: \"{l}\")"))
                        .unwrap_or_default()
                ));
            }
            ComponentType::SearchInterface {
                has_filters,
                filters,
                ..
            } => {
                if *has_filters {
                    parts.push(format!("search with {} filters", filters.len()));
                } else {
                    parts.push("search bar".to_string());
                }
            }
            ComponentType::DetailView { fields, .. } => {
                parts.push(format!("detail view with {} fields", fields.len()));
            }
            ComponentType::Dashboard { widgets, .. } => {
                parts.push(format!("dashboard with {} widgets", widgets.len()));
            }
            ComponentType::TabGroup { tabs, .. } => {
                parts.push(format!("{}-tab group", tabs.len()));
            }
            ComponentType::Navigation {
                nav_type, items, ..
            } => {
                let type_str = match nav_type {
                    NavType::Sidebar => "sidebar",
                    NavType::TopBar => "top bar",
                    NavType::TabBar => "tab bar",
                    NavType::Breadcrumbs => "breadcrumbs",
                    NavType::Pagination => "pagination",
                    NavType::StepWizard => "step wizard",
                    NavType::Footer => "footer",
                };
                parts.push(format!("{type_str} navigation ({} items)", items.len()));
            }
            ComponentType::Chart { chart_type, .. } => {
                parts.push(format!("{chart_type} chart"));
            }
            ComponentType::Modal { title, .. } => {
                if let Some(t) = title {
                    parts.push(format!("modal: \"{t}\""));
                }
            }
            _ => {}
        }
    }

    if parts.is_empty() {
        return "Unclassified view".to_string();
    }

    let mut desc = parts.join(", ");
    if let Some(first) = desc.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    desc
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_opt_string(obj: &serde_json::Value, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

fn get_opt_f64(obj: &serde_json::Value, key: &str) -> Option<f64> {
    let v = obj.get(key)?;
    if let Some(n) = v.as_f64() {
        return Some(n);
    }
    if let Some(n) = v.as_i64() {
        return Some(n as f64);
    }
    let s = v.as_str()?;
    s.parse::<f64>().ok()
}

fn get_opt_i64(obj: &serde_json::Value, key: &str) -> Option<i64> {
    let v = obj.get(key)?;
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(n) = v.as_u64() {
        return i64::try_from(n).ok();
    }
    let s = v.as_str()?;
    s.parse::<i64>().ok()
}

fn get_opt_u16(obj: &serde_json::Value, key: &str) -> Option<u16> {
    let v = obj.get(key)?;
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).ok();
    }
    if let Some(n) = v.as_i64() {
        if n >= 0 {
            return u16::try_from(n as u64).ok();
        }
        return None;
    }
    let s = v.as_str()?;
    s.parse::<u16>().ok()
}

fn infer_field_name(label: &str) -> Option<String> {
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect();

    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("_"))
}

fn parse_form_field_type(raw_type: &str, options: Vec<String>) -> FormFieldType {
    match raw_type {
        "text" => FormFieldType::Text,
        "email" => FormFieldType::Email,
        "password" => FormFieldType::Password,
        "number" => FormFieldType::Number,
        "tel" => FormFieldType::Tel,
        "url" => FormFieldType::Url,
        "date" => FormFieldType::Date,
        "datetime-local" | "datetime" => FormFieldType::DateTime,
        "time" => FormFieldType::Time,
        "color" => FormFieldType::Color,
        "file" => FormFieldType::File,
        "hidden" => FormFieldType::Hidden,
        "textarea" => FormFieldType::Textarea,
        "select" => FormFieldType::Select { options },
        "multi_select" => FormFieldType::MultiSelect { options },
        "checkbox" => FormFieldType::Checkbox,
        "radio" => FormFieldType::Radio {
            group: None,
            options,
        },
        other => FormFieldType::Unknown {
            raw_type: other.to_string(),
        },
    }
}

fn infer_entity_from_url(url: &str) -> Option<String> {
    let path = url.split('?').next().unwrap_or(url);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    for seg in segments.iter().rev() {
        if seg.parse::<u64>().is_ok() {
            continue;
        }
        if seg.len() == 36 && seg.contains('-') {
            continue;
        }
        // Heuristic: slug/ID-like segments often include multiple '-' parts.
        // Skip these so we can return the parent entity segment (e.g. "/users/abc-def-ghi" -> "user").
        if seg.len() >= 8 && seg.matches('-').count() >= 2 {
            continue;
        }
        if seg.chars().all(|c| c.is_ascii_hexdigit()) && seg.len() > 8 {
            continue;
        }

        let entity = if seg.ends_with("ies") {
            format!("{}y", &seg[..seg.len() - 3])
        } else if seg.ends_with('s') && !seg.ends_with("ss") {
            seg[..seg.len() - 1].to_string()
        } else {
            seg.to_string()
        };

        let stop = [
            "api",
            "v1",
            "v2",
            "v3",
            "app",
            "admin",
            "dashboard",
            "settings",
            "setting",
            "edit",
            "new",
            "detail",
        ];
        if stop.contains(seg) || stop.contains(&entity.as_str()) {
            continue;
        }

        return Some(entity);
    }

    None
}

fn parse_locator_strategies(value: Option<&serde_json::Value>) -> Vec<LocatorStrategy> {
    value
        .cloned()
        .and_then(|v| serde_json::from_value::<Vec<LocatorStrategy>>(v).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_field_name() {
        assert_eq!(
            infer_field_name("Last Activity"),
            Some("last_activity".into())
        );
        assert_eq!(infer_field_name("Email"), Some("email".into()));
        assert_eq!(
            infer_field_name("Company Name"),
            Some("company_name".into())
        );
        assert_eq!(infer_field_name(""), None);
    }

    #[test]
    fn test_infer_entity_from_url() {
        assert_eq!(
            infer_entity_from_url("/contacts/123"),
            Some("contact".into())
        );
        assert_eq!(
            infer_entity_from_url("/api/v2/users/abc-def-ghi"),
            Some("user".into())
        );
        assert_eq!(infer_entity_from_url("/companies"), Some("company".into()));
        assert_eq!(infer_entity_from_url("/dashboard"), None);
        assert_eq!(infer_entity_from_url("/settings"), None);
    }

    #[test]
    fn test_parse_form_field_type() {
        assert!(matches!(
            parse_form_field_type("email", vec![]),
            FormFieldType::Email
        ));
        assert!(matches!(
            parse_form_field_type("select", vec!["a".into()]),
            FormFieldType::Select { .. }
        ));
        assert!(matches!(
            parse_form_field_type("range", vec![]),
            FormFieldType::Unknown { .. }
        ));
    }

    #[test]
    fn test_determine_primary_type_empty() {
        assert_eq!(determine_primary_type(&[]), "unknown");
    }

    #[test]
    fn test_determine_primary_type_table_wins_over_nav() {
        let components = vec![
            DetectedComponent {
                selector: "nav".into(),
                component: ComponentType::Navigation {
                    nav_type: NavType::Sidebar,
                    items: vec![],
                },
                confidence: 0.9,
                visual: None,
            },
            DetectedComponent {
                selector: "table".into(),
                component: ComponentType::DataTable {
                    columns: vec![],
                    row_count: 10,
                    has_pagination: true,
                    has_sorting: true,
                    has_filtering: false,
                    has_bulk_actions: false,
                },
                confidence: 0.95,
                visual: None,
            },
        ];
        assert_eq!(determine_primary_type(&components), "data_table");
    }

    #[test]
    fn test_determine_primary_type_table_plus_search() {
        let components = vec![
            DetectedComponent {
                selector: "table".into(),
                component: ComponentType::DataTable {
                    columns: vec![],
                    row_count: 10,
                    has_pagination: true,
                    has_sorting: true,
                    has_filtering: false,
                    has_bulk_actions: false,
                },
                confidence: 0.95,
                visual: None,
            },
            DetectedComponent {
                selector: "input".into(),
                component: ComponentType::SearchInterface {
                    input_selector: None,
                    has_results_container: true,
                    has_filters: false,
                    filters: vec![],
                },
                confidence: 0.85,
                visual: None,
            },
        ];
        assert_eq!(
            determine_primary_type(&components),
            "data_table_with_search"
        );
    }

    #[test]
    fn test_error_page_wins_without_substantial_app_surface() {
        let components = vec![
            DetectedComponent {
                selector: "nav".into(),
                component: ComponentType::Navigation {
                    nav_type: NavType::TopBar,
                    items: vec![],
                },
                confidence: 0.9,
                visual: None,
            },
            DetectedComponent {
                selector: "body".into(),
                component: ComponentType::ErrorPage {
                    error_type: Some("404".into()),
                    message: Some("Not Found".into()),
                },
                confidence: 0.8,
                visual: None,
            },
        ];
        assert_eq!(determine_primary_type(&components), "error_page");
    }

    #[test]
    fn test_error_page_does_not_override_substantial_app_surface() {
        let components = vec![
            DetectedComponent {
                selector: "table".into(),
                component: ComponentType::DataTable {
                    columns: vec![
                        ColumnDef {
                            label: "IMEI / Serial".into(),
                            field: Some("imei_serial".into()),
                            sortable: false,
                            index: 1,
                        },
                        ColumnDef {
                            label: "Product".into(),
                            field: Some("product".into()),
                            sortable: false,
                            index: 2,
                        },
                        ColumnDef {
                            label: "Color".into(),
                            field: Some("color".into()),
                            sortable: false,
                            index: 3,
                        },
                    ],
                    row_count: 10,
                    has_pagination: true,
                    has_sorting: true,
                    has_filtering: true,
                    has_bulk_actions: true,
                },
                confidence: 0.99,
                visual: None,
            },
            DetectedComponent {
                selector: "body".into(),
                component: ComponentType::ErrorPage {
                    error_type: Some("404".into()),
                    message: Some("Not Found".into()),
                },
                confidence: 0.8,
                visual: None,
            },
        ];
        assert_eq!(
            determine_primary_type(&components),
            "data_table_with_search"
        );
    }

    #[test]
    fn test_generate_description() {
        let components = vec![
            DetectedComponent {
                selector: "table".into(),
                component: ComponentType::DataTable {
                    columns: vec![
                        ColumnDef {
                            label: "Name".into(),
                            field: Some("name".into()),
                            sortable: true,
                            index: 0,
                        },
                        ColumnDef {
                            label: "Email".into(),
                            field: Some("email".into()),
                            sortable: true,
                            index: 1,
                        },
                    ],
                    row_count: 25,
                    has_pagination: true,
                    has_sorting: true,
                    has_filtering: false,
                    has_bulk_actions: true,
                },
                confidence: 0.95,
                visual: None,
            },
            DetectedComponent {
                selector: "input".into(),
                component: ComponentType::SearchInterface {
                    input_selector: Some("input.search".into()),
                    has_results_container: true,
                    has_filters: true,
                    filters: vec![FilterDef {
                        label: Some("Status".into()),
                        field: Some("status".into()),
                        filter_type: FilterType::Select { options: vec![] },
                    }],
                },
                confidence: 0.85,
                visual: None,
            },
        ];

        let desc = generate_description("data_table_with_search", &components);
        assert!(desc.contains("2-column data table"));
        assert!(desc.contains("25 rows"));
        assert!(desc.contains("pagination"));
        assert!(desc.contains("search with 1 filter"));
    }
}
