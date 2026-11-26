//! Pre-click pattern recognition and post-interaction classification.
//!
//! Detects common client-side UI patterns (accordions, tabs, toggles) before
//! clicking, then classifies the interaction result to distinguish truly dead
//! buttons from working client-side-only controls.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::browser::PageClient;
use crate::types::dom::InteractionSnapshot;

/// Recognized UI pattern detected before clicking an element.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreClickPattern {
    Accordion,
    Tab,
    Carousel,
    DisclosureToggle,
    Modal,
    Dropdown,
    CopyToClipboard,
    MediaControl,
    Unknown,
}

impl PreClickPattern {
    /// Whether this pattern is a known, recognized UI pattern (not Unknown).
    pub fn is_recognized(self) -> bool {
        self != Self::Unknown
    }

    /// Human-readable label for bug titles.
    pub fn label(self) -> &'static str {
        match self {
            Self::Accordion => "accordion",
            Self::Tab => "tab",
            Self::Carousel => "carousel control",
            Self::DisclosureToggle => "disclosure toggle",
            Self::Modal => "modal trigger",
            Self::Dropdown => "dropdown",
            Self::CopyToClipboard => "copy button",
            Self::MediaControl => "media control",
            Self::Unknown => "interactive element",
        }
    }
}

/// Classification of an interaction's outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InteractionClassification {
    /// Truly dead: no signals at all.
    Dead,
    /// DOM mutation counter fired but snapshot is empty — ambiguous.
    WeakResponse,
    /// Client-side functional: attribute changes, DOM additions, or modal opened.
    ClientSideFunctional,
    /// Recognized pattern but no response signals — needs manual verification.
    NeedsVerification,
}

impl InteractionClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dead => "dead",
            Self::WeakResponse => "weak_response",
            Self::ClientSideFunctional => "client_side_functional",
            Self::NeedsVerification => "needs_verification",
        }
    }
}

/// Detect the pre-click UI pattern for an element by inspecting its ARIA
/// attributes, role, and surrounding context.
pub async fn detect_pre_click_pattern(
    page: &PageClient,
    selector: &str,
) -> Result<PreClickPattern> {
    let sel_json = serde_json::to_string(selector)?;
    let script = format!(
        r#"
(() => {{
  try {{
    const el = document.querySelector({sel_json});
    if (!el) return "unknown";
    const tag = (el.tagName || "").toLowerCase();
    const role = (el.getAttribute("role") || "").toLowerCase();
    const ariaExpanded = el.hasAttribute("aria-expanded");
    const ariaHaspopup = (el.getAttribute("aria-haspopup") || "").toLowerCase();
    const ariaControls = el.getAttribute("aria-controls") || "";
    const cls = ((el.className && typeof el.className === "string") ? el.className : "").toLowerCase();
    const title = (el.getAttribute("title") || "").toLowerCase();
    const label = ((el.getAttribute("aria-label") || "") + " " + title + " " + (el.textContent || "").slice(0, 200)).toLowerCase();
    const parentCls = el.parentElement ? ((el.parentElement.className && typeof el.parentElement.className === "string") ? el.parentElement.className : "").toLowerCase() : "";
    const nearestClass = el.closest("[class]") ? ((el.closest("[class]").className && typeof el.closest("[class]").className === "string") ? el.closest("[class]").className : "").toLowerCase() : "";
    const context = [tag, role, cls, parentCls, nearestClass, ariaControls].join(" ");

    // <summary> or inside <details>
    if (tag === "summary" || el.closest("details")) return "disclosure_toggle";

    // role="tab" or inside [role="tablist"]
    if (role === "tab" || el.closest('[role="tablist"]')) return "tab";

    // Carousel pagination and next/previous controls often update slides
    // without navigation or directly observable network activity.
    const carouselAction = /\b(current slide|go to slide|slide \d+ of \d+|next|previous|prev)\b/.test(label);
    const carouselContext =
      context.includes("carousel") ||
      context.includes("slider") ||
      context.includes("swiper") ||
      context.includes("slick") ||
      context.includes("splide") ||
      context.includes("glider") ||
      !!el.closest(
        '[aria-roledescription="carousel"], [class*="carousel"], [class*="slider"], [class*="swiper"], [class*="slick"], [class*="splide"], [data-testid*="carousel"], [data-testid*="slider"]'
      );
    if (carouselContext && carouselAction) return "carousel";
    if (/\b(current slide|go to slide|slide \d+ of \d+)\b/.test(label)) return "carousel";

    // aria-haspopup="dialog" or Bootstrap/common modal triggers
    if (ariaHaspopup === "dialog" ||
        el.getAttribute("data-toggle") === "modal" ||
        el.getAttribute("data-bs-toggle") === "modal") return "modal";

    // aria-expanded + aria-haspopup (dropdown menus)
    if (ariaExpanded && (ariaHaspopup === "true" || ariaHaspopup === "menu" || ariaHaspopup === "listbox")) return "dropdown";

    // aria-expanded with accordion/faq/collapsible context
    if (ariaExpanded) {{
      if (context.includes("accordion") || context.includes("faq") || context.includes("collapsible") || context.includes("expandable")) return "accordion";
      // heading-inside-button pattern (common in accordions)
      if (el.querySelector("h1,h2,h3,h4,h5,h6") || tag.match(/^h[1-6]$/)) return "accordion";
      // aria-controls pointing to a panel
      if (ariaControls) {{
        const panel = document.getElementById(ariaControls);
        if (panel) {{
          const panelRole = (panel.getAttribute("role") || "").toLowerCase();
          if (panelRole === "region" || panelRole === "tabpanel") return "accordion";
        }}
      }}
      // Fallback: aria-expanded without other context → most likely accordion
      return "accordion";
    }}

    // Copy-to-clipboard detection
    const copyLike = /\bcopy\b/.test(label) || context.includes("clipboard");
    if (copyLike && (el.closest("pre, code, [class*='code'], [class*='snippet'], [class*='clipboard'], [class*='copy']") || context.includes("code") || context.includes("snippet"))) return "copy_to_clipboard";

    // Media/playback controls often produce effects the scanner cannot directly
    // observe (video playback, audio state, fullscreen).
    const mediaAction = /\b(play( video)?|pause|mute|unmute|fullscreen|full screen|replay|resume|watch( video)?)\b/.test(label);
    const mediaContext = context.includes("video") || context.includes("player") || context.includes("media") || context.includes("audio") || !!el.closest("video, audio, [class*='video'], [class*='player'], [class*='media'], [data-testid*='video'], [data-testid*='player']");
    if ((mediaAction && mediaContext) || (tag === "button" && label.trim() === "watch")) return "media_control";

    return "unknown";
  }} catch (_) {{
    return "unknown";
  }}
}})()
"#
    );

    let pattern: String = page.evaluate_json(&script).await.unwrap_or_default();
    Ok(match pattern.as_str() {
        "accordion" => PreClickPattern::Accordion,
        "tab" => PreClickPattern::Tab,
        "carousel" => PreClickPattern::Carousel,
        "disclosure_toggle" => PreClickPattern::DisclosureToggle,
        "modal" => PreClickPattern::Modal,
        "dropdown" => PreClickPattern::Dropdown,
        "copy_to_clipboard" => PreClickPattern::CopyToClipboard,
        "media_control" => PreClickPattern::MediaControl,
        _ => PreClickPattern::Unknown,
    })
}

/// Classify the interaction outcome using the snapshot, pattern, and signals.
///
/// Decision tree:
/// 1. Snapshot has attribute_changes with ARIA state changes → ClientSideFunctional
/// 2. Snapshot has attribute_changes with class/style/data-state changes → ClientSideFunctional
/// 3. Snapshot has appeared_elements / appeared_text / modal_opened → ClientSideFunctional
/// 4. dom_mutated true but snapshot empty → WeakResponse
/// 5. Pattern is recognized but no signals → NeedsVerification
/// 6. No signals, no pattern → Dead
pub fn classify_interaction(
    snapshot: &Option<InteractionSnapshot>,
    pattern: PreClickPattern,
    dom_mutated: bool,
    network_activity: bool,
) -> InteractionClassification {
    if let Some(snap) = snapshot {
        // Check attribute changes for ARIA state toggles.
        if snap
            .attribute_changes
            .iter()
            .any(|ac| is_aria_state_attr(&ac.attribute))
        {
            return InteractionClassification::ClientSideFunctional;
        }

        // Check attribute changes for class/style/data-state changes.
        if snap
            .attribute_changes
            .iter()
            .any(|ac| is_ui_state_attr(&ac.attribute))
        {
            return InteractionClassification::ClientSideFunctional;
        }

        // Check for appeared elements, text, or modal.
        if !snap.appeared_elements.is_empty()
            || !snap.appeared_text.is_empty()
            || snap.modal_opened.is_some()
        {
            return InteractionClassification::ClientSideFunctional;
        }
    }

    // dom_mutated true but snapshot empty → ambiguous signal.
    if dom_mutated {
        return InteractionClassification::WeakResponse;
    }

    if network_activity {
        return InteractionClassification::ClientSideFunctional;
    }

    // Recognized pattern but no signals → needs manual check.
    if pattern.is_recognized() {
        return InteractionClassification::NeedsVerification;
    }

    // No signals, no pattern → dead.
    InteractionClassification::Dead
}

fn is_aria_state_attr(attr: &str) -> bool {
    matches!(
        attr,
        "aria-expanded"
            | "aria-hidden"
            | "aria-selected"
            | "aria-pressed"
            | "aria-checked"
            | "aria-disabled"
    )
}

fn is_ui_state_attr(attr: &str) -> bool {
    matches!(
        attr,
        "class"
            | "style"
            | "disabled"
            | "hidden"
            | "open"
            | "data-state"
            | "data-active"
            | "data-open"
            | "data-expanded"
            | "data-disabled"
    )
}

/// Check whether an element type is button-like (Button or Other with role="button").
pub fn is_button_like(element_type: &crate::types::dom::ElementType) -> bool {
    matches!(element_type, crate::types::dom::ElementType::Button { .. })
        || matches!(
            element_type,
            crate::types::dom::ElementType::Other { role: Some(r), .. } if r == "button"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dom::{AttributeChange, InteractionSnapshot};

    #[test]
    fn snapshot_is_empty_false_when_attribute_changes_present() {
        let snap = InteractionSnapshot {
            attribute_changes: vec![AttributeChange {
                selector: "button".into(),
                attribute: "aria-expanded".into(),
                old_value: Some("false".into()),
                new_value: Some("true".into()),
            }],
            ..Default::default()
        };
        assert!(!snap.is_empty());
    }

    #[test]
    fn classify_client_side_functional_for_aria_expanded() {
        let snap = InteractionSnapshot {
            attribute_changes: vec![AttributeChange {
                selector: "button".into(),
                attribute: "aria-expanded".into(),
                old_value: Some("false".into()),
                new_value: Some("true".into()),
            }],
            ..Default::default()
        };
        let result = classify_interaction(&Some(snap), PreClickPattern::Accordion, false, false);
        assert_eq!(result, InteractionClassification::ClientSideFunctional);
    }

    #[test]
    fn classify_client_side_functional_for_class_change() {
        let snap = InteractionSnapshot {
            attribute_changes: vec![AttributeChange {
                selector: "div".into(),
                attribute: "class".into(),
                old_value: Some("panel collapsed".into()),
                new_value: Some("panel expanded".into()),
            }],
            ..Default::default()
        };
        let result = classify_interaction(&Some(snap), PreClickPattern::Unknown, false, false);
        assert_eq!(result, InteractionClassification::ClientSideFunctional);
    }

    #[test]
    fn classify_client_side_functional_for_disabled_state_change() {
        let snap = InteractionSnapshot {
            attribute_changes: vec![AttributeChange {
                selector: "button.carousel-prev".into(),
                attribute: "disabled".into(),
                old_value: Some("true".into()),
                new_value: None,
            }],
            ..Default::default()
        };
        let result = classify_interaction(&Some(snap), PreClickPattern::Unknown, false, false);
        assert_eq!(result, InteractionClassification::ClientSideFunctional);
    }

    #[test]
    fn classify_client_side_functional_for_hidden_panel_change() {
        let snap = InteractionSnapshot {
            attribute_changes: vec![AttributeChange {
                selector: "#panel".into(),
                attribute: "hidden".into(),
                old_value: Some(String::new()),
                new_value: None,
            }],
            ..Default::default()
        };
        let result = classify_interaction(&Some(snap), PreClickPattern::Unknown, false, false);
        assert_eq!(result, InteractionClassification::ClientSideFunctional);
    }

    #[test]
    fn classify_dead_for_no_signals_unknown_pattern() {
        let result = classify_interaction(&None, PreClickPattern::Unknown, false, false);
        assert_eq!(result, InteractionClassification::Dead);
    }

    #[test]
    fn classify_needs_verification_for_recognized_pattern_no_signals() {
        let result = classify_interaction(&None, PreClickPattern::Accordion, false, false);
        assert_eq!(result, InteractionClassification::NeedsVerification);
    }

    #[test]
    fn classify_needs_verification_for_media_control_no_signals() {
        let result = classify_interaction(&None, PreClickPattern::MediaControl, false, false);
        assert_eq!(result, InteractionClassification::NeedsVerification);
    }

    #[test]
    fn classify_needs_verification_for_carousel_no_signals() {
        let result = classify_interaction(&None, PreClickPattern::Carousel, false, false);
        assert_eq!(result, InteractionClassification::NeedsVerification);
    }

    #[test]
    fn classify_weak_response_for_dom_mutated_empty_snapshot() {
        let result = classify_interaction(&None, PreClickPattern::Unknown, true, false);
        assert_eq!(result, InteractionClassification::WeakResponse);
    }

    #[test]
    fn classify_client_side_functional_for_network_activity() {
        let result = classify_interaction(&None, PreClickPattern::Unknown, false, true);
        assert_eq!(result, InteractionClassification::ClientSideFunctional);
    }

    #[test]
    fn is_button_like_matches_button() {
        use crate::types::dom::ElementType;
        assert!(is_button_like(&ElementType::Button { form_submit: false }));
        assert!(is_button_like(&ElementType::Other {
            tag: "div".into(),
            role: Some("button".into()),
        }));
        assert!(!is_button_like(&ElementType::NavigationLink {
            href: None,
            in_nav: false,
        }));
    }
}
