//! Selector and locator helpers shared by discovery, interaction, and
//! snapshot attribution.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::types::dom::{DomPathLocator, InteractiveElement, LocatorKind, LocatorStrategy};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsLocator {
    Selector { value: String },
    DomPath { value: DomPathLocator },
}

pub const LOCATOR_RUNTIME_JS: &str = r#"
function resolveBrokenAppLocator(locator) {
  if (!locator || typeof locator !== "object") return null;

  if (locator.kind === "selector") {
    try {
      return document.querySelector(locator.value);
    } catch (_) {
      return null;
    }
  }

  if (locator.kind !== "dom_path") return null;

  const value = locator.value || {};
  const segments = Array.isArray(value.segments) ? value.segments : [];
  if (!segments.length) return null;

  let root = document;
  let node = null;

  for (const segment of segments) {
    if (!segment || typeof segment.selector !== "string" || !segment.selector.trim()) {
      return null;
    }

    try {
      node = root.querySelector(segment.selector);
    } catch (_) {
      return null;
    }
    if (!node) return null;

    const enter = segment.enter || "none";
    if (enter === "shadow") {
      if (!node.shadowRoot) return null;
      root = node.shadowRoot;
    } else if (enter === "frame") {
      let frameDoc = null;
      try {
        frameDoc = node.contentDocument || (node.contentWindow && node.contentWindow.document) || null;
      } catch (_) {
        frameDoc = null;
      }
      if (!frameDoc) return null;
      root = frameDoc;
    }
  }

  return node;
}
"#;

pub fn selector_locator_json(selector: &str) -> Result<String> {
    serde_json::to_string(&JsLocator::Selector {
        value: selector.to_string(),
    })
    .context("serialize selector locator")
}

pub fn primary_locator_json_from_parts(
    selector: &str,
    locators: &[LocatorStrategy],
) -> Result<String> {
    if let Some(path) = locators.iter().find_map(dom_path_locator) {
        return serde_json::to_string(&JsLocator::DomPath { value: path })
            .context("serialize dom-path locator");
    }
    selector_locator_json(selector)
}

pub fn primary_locator_json(element: &InteractiveElement) -> Result<String> {
    primary_locator_json_from_parts(&element.selector, &element.locators)
}

pub fn dom_path_locator_for_element(element: &InteractiveElement) -> Option<DomPathLocator> {
    element.locators.iter().find_map(dom_path_locator)
}

pub fn dom_path_locator(locator: &LocatorStrategy) -> Option<DomPathLocator> {
    if locator.kind != LocatorKind::DomPath {
        return None;
    }
    serde_json::from_str(&locator.value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dom::{DomPathEnter, DomPathSegment, ElementType, LocatorStrategy};

    fn sample_element() -> InteractiveElement {
        InteractiveElement {
            selector: "button.save".to_string(),
            label: Some("Save".to_string()),
            element_type: ElementType::Button { form_submit: false },
            interaction_result: None,
            source: None,
            found_on: "view_1".to_string(),
            bounding_box: None,
            snapshot: None,
            disabled: false,
            empty_required_fields_in_form: 0,
            locators: vec![LocatorStrategy {
                kind: LocatorKind::DomPath,
                value: serde_json::to_string(&DomPathLocator {
                    segments: vec![
                        DomPathSegment {
                            selector: "app-shell".to_string(),
                            enter: DomPathEnter::Shadow,
                        },
                        DomPathSegment {
                            selector: "button.save".to_string(),
                            enter: DomPathEnter::None,
                        },
                    ],
                })
                .unwrap(),
                stability: LocatorKind::DomPath.default_stability(),
                unique: true,
            }],
        }
    }

    #[test]
    fn prefers_dom_path_for_cross_root_elements() {
        let locator_json = primary_locator_json(&sample_element()).unwrap();
        assert!(locator_json.contains("\"kind\":\"dom_path\""));
        assert!(locator_json.contains("app-shell"));
    }

    #[test]
    fn falls_back_to_plain_selector_when_no_dom_path_exists() {
        let mut element = sample_element();
        element.locators.clear();
        let locator_json = primary_locator_json(&element).unwrap();
        assert_eq!(locator_json, r#"{"kind":"selector","value":"button.save"}"#);
    }
}
