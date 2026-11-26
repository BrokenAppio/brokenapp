//! Accessibility scanning — WCAG checker, ARIA validation, contrast analysis.
//!
//! Provides a JavaScript-based accessibility audit that runs in the browser
//! context to detect common WCAG 2.2 violations, missing ARIA attributes,
//! and color contrast issues.

use serde::{Deserialize, Serialize};

// ── WCAG Rule definitions ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WcagLevel {
    A,
    Aa,
    Aaa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A11yCategory {
    /// Missing alternative text for images.
    MissingAltText,
    /// Missing form labels or aria-label.
    MissingFormLabel,
    /// Insufficient color contrast ratio.
    InsufficientContrast,
    /// Missing document language.
    MissingLang,
    /// Missing page title.
    MissingTitle,
    /// Empty links or buttons.
    EmptyInteractive,
    /// Missing ARIA landmarks (main, nav, etc.).
    MissingLandmarks,
    /// Duplicate IDs in the document.
    DuplicateId,
    /// Keyboard trap (focusable element with no escape).
    KeyboardTrap,
    /// Missing skip navigation link.
    MissingSkipNav,
    /// Invalid ARIA attribute or role.
    InvalidAria,
    /// Heading hierarchy issues (e.g., h1 followed by h3).
    HeadingHierarchy,
    /// Interactive elements with touch target smaller than 24x24px.
    SmallTouchTarget,
    /// PII inputs missing autocomplete attribute.
    MissingAutocomplete,
    /// Required ARIA state attributes missing (aria-expanded, aria-selected, aria-checked).
    MissingAriaState,
    /// Focus indicator suppressed via CSS (outline: none without replacement).
    MissingFocusIndicator,
}

/// A single accessibility finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A11yFinding {
    pub category: A11yCategory,
    pub wcag_criterion: &'static str,
    pub wcag_level: WcagLevel,
    pub selector: Option<String>,
    pub description: String,
    pub impact: A11yImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A11yImpact {
    Critical,
    Serious,
    Moderate,
    Minor,
}

impl From<A11yImpact> for crate::types::bugs::AccessibilityImpact {
    fn from(value: A11yImpact) -> Self {
        match value {
            A11yImpact::Critical => crate::types::bugs::AccessibilityImpact::Critical,
            A11yImpact::Serious => crate::types::bugs::AccessibilityImpact::Serious,
            A11yImpact::Moderate => crate::types::bugs::AccessibilityImpact::Moderate,
            A11yImpact::Minor => crate::types::bugs::AccessibilityImpact::Minor,
        }
    }
}

// ── Rule registry ──────────────────────────────────────────────────

/// Static rule definition used to drive JavaScript audits.
#[derive(Debug, Clone)]
pub struct A11yRule {
    pub category: A11yCategory,
    pub wcag_criterion: &'static str,
    pub wcag_level: WcagLevel,
    pub impact: A11yImpact,
    pub description: &'static str,
}

/// All accessibility rules in the rule set.
pub const RULES: &[A11yRule] = &[
    A11yRule {
        category: A11yCategory::MissingAltText,
        wcag_criterion: "1.1.1",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Critical,
        description: "Images must have alternative text",
    },
    A11yRule {
        category: A11yCategory::MissingFormLabel,
        wcag_criterion: "1.3.1",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Critical,
        description: "Form inputs must have associated labels",
    },
    A11yRule {
        category: A11yCategory::InsufficientContrast,
        wcag_criterion: "1.4.3",
        wcag_level: WcagLevel::Aa,
        impact: A11yImpact::Serious,
        description: "Text must have sufficient color contrast (4.5:1 for normal, 3:1 for large)",
    },
    A11yRule {
        category: A11yCategory::MissingLang,
        wcag_criterion: "3.1.1",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Serious,
        description: "Document must have a lang attribute",
    },
    A11yRule {
        category: A11yCategory::MissingTitle,
        wcag_criterion: "2.4.2",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Serious,
        description: "Page must have a descriptive title",
    },
    A11yRule {
        category: A11yCategory::EmptyInteractive,
        wcag_criterion: "2.4.4",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Serious,
        description: "Links and buttons must have discernible text",
    },
    A11yRule {
        category: A11yCategory::MissingLandmarks,
        wcag_criterion: "1.3.1",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Moderate,
        description: "Page should use ARIA landmark roles or HTML5 landmarks",
    },
    A11yRule {
        category: A11yCategory::DuplicateId,
        wcag_criterion: "4.1.1",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Serious,
        description: "Element IDs must be unique",
    },
    A11yRule {
        category: A11yCategory::KeyboardTrap,
        wcag_criterion: "2.1.2",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Serious,
        description: "Keyboard focus must not be trapped within interface regions",
    },
    A11yRule {
        category: A11yCategory::MissingSkipNav,
        wcag_criterion: "2.4.1",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Moderate,
        description: "Page should have a skip navigation link",
    },
    A11yRule {
        category: A11yCategory::InvalidAria,
        wcag_criterion: "4.1.2",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Critical,
        description: "ARIA attributes must be valid and correctly used",
    },
    A11yRule {
        category: A11yCategory::HeadingHierarchy,
        wcag_criterion: "1.3.1",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Moderate,
        description: "Heading levels should not skip (e.g., h1 to h3)",
    },
    A11yRule {
        category: A11yCategory::SmallTouchTarget,
        // WCAG 2.2: 2.5.8 Target Size (Minimum)
        wcag_criterion: "2.5.8",
        wcag_level: WcagLevel::Aa,
        impact: A11yImpact::Moderate,
        description: "Interactive elements must have a touch target of at least 24x24 CSS pixels",
    },
    A11yRule {
        category: A11yCategory::MissingAutocomplete,
        wcag_criterion: "1.3.5",
        wcag_level: WcagLevel::Aa,
        impact: A11yImpact::Moderate,
        description: "Inputs that collect personal information should have autocomplete attributes",
    },
    A11yRule {
        category: A11yCategory::MissingAriaState,
        wcag_criterion: "4.1.2",
        wcag_level: WcagLevel::A,
        impact: A11yImpact::Serious,
        description: "Interactive widgets must expose required ARIA state attributes",
    },
    A11yRule {
        category: A11yCategory::MissingFocusIndicator,
        wcag_criterion: "2.4.7",
        wcag_level: WcagLevel::Aa,
        impact: A11yImpact::Serious,
        description: "Interactive elements must have a visible focus indicator",
    },
];

// ── Contrast ratio calculation ─────────────────────────────────────

/// Parse a CSS color string into (R, G, B) in 0..255 range.
/// Supports `rgb(r, g, b)` and `#RRGGBB` / `#RGB` formats.
pub fn parse_css_color(color: &str) -> Option<(u8, u8, u8)> {
    let trimmed = color.trim();

    // rgb(r, g, b) or rgba(r, g, b, a)
    if trimmed.starts_with("rgb") {
        let inner = trimmed
            .find('(')
            .and_then(|start| trimmed.rfind(')').map(|end| &trimmed[start + 1..end]))?;
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() >= 3 {
            let r = parts[0].trim().parse::<u8>().ok()?;
            let g = parts[1].trim().parse::<u8>().ok()?;
            let b = parts[2].trim().parse::<u8>().ok()?;
            return Some((r, g, b));
        }
        return None;
    }

    // Hex colors
    if trimmed.starts_with('#') {
        let hex = &trimmed[1..];
        match hex.len() {
            3 => {
                let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
                let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
                let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
                return Some((r, g, b));
            }
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                return Some((r, g, b));
            }
            _ => return None,
        }
    }

    None
}

/// Calculate the relative luminance of a color per WCAG.
/// <https://www.w3.org/TR/WCAG21/#dfn-relative-luminance>
pub fn relative_luminance(r: u8, g: u8, b: u8) -> f64 {
    fn linearize(c: u8) -> f64 {
        let s = c as f64 / 255.0;
        if s <= 0.04045 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)
}

/// Calculate WCAG contrast ratio between two colors.
/// Returns a value >= 1.0 (higher = more contrast).
pub fn contrast_ratio(fg: (u8, u8, u8), bg: (u8, u8, u8)) -> f64 {
    let l1 = relative_luminance(fg.0, fg.1, fg.2);
    let l2 = relative_luminance(bg.0, bg.1, bg.2);
    let (lighter, darker) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
    (lighter + 0.05) / (darker + 0.05)
}

/// Check if a contrast ratio meets WCAG AA for normal text (4.5:1).
pub fn meets_aa_normal(ratio: f64) -> bool {
    ratio >= 4.5
}

/// Check if a contrast ratio meets WCAG AA for large text (3:1).
pub fn meets_aa_large(ratio: f64) -> bool {
    ratio >= 3.0
}

/// Check if a contrast ratio meets WCAG AAA for normal text (7:1).
pub fn meets_aaa_normal(ratio: f64) -> bool {
    ratio >= 7.0
}

// ── Bug conversion ─────────────────────────────────────────────────

impl A11yFinding {
    pub fn to_bug_severity(&self) -> crate::types::bugs::BugSeverity {
        use crate::types::bugs::BugSeverity;
        match self.impact {
            A11yImpact::Critical => BugSeverity::High,
            A11yImpact::Serious => BugSeverity::Medium,
            A11yImpact::Moderate => BugSeverity::Low,
            A11yImpact::Minor => BugSeverity::Info,
        }
    }
}

/// JavaScript expression to perform basic accessibility audit in browser.
///
/// Returns an array of `{ category, selector, description }` objects.
pub const A11Y_AUDIT_SCRIPT: &str = r##"
(() => {
  const findings = [];

  function isElementVisibleForA11y(el) {
    if (!el) return false;
    if (el.hidden) return false;
    const ariaHidden = el.getAttribute && el.getAttribute('aria-hidden') === 'true';
    if (ariaHidden) return false;
    const role = ((el.getAttribute && el.getAttribute('role')) || '').toLowerCase();
    if (role === 'presentation' || role === 'none') return false;
    const style = window.getComputedStyle(el);
    if (!style) return false;
    if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity || '1') === 0) {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function isDecorativeImage(el) {
    if (!el) return false;
    const role = ((el.getAttribute && el.getAttribute('role')) || '').toLowerCase();
    return (el.getAttribute && el.getAttribute('aria-hidden') === 'true') ||
      role === 'presentation' ||
      role === 'none';
  }

  // Missing alt text on images
  document.querySelectorAll('img').forEach(el => {
    if (!isElementVisibleForA11y(el)) return;
    const alt = el.getAttribute('alt');
    const interactive = !!el.closest('a[href], button, [role="button"], [role="link"]');
    const missingAlt = alt == null;
    const suspiciousEmptyAlt = alt != null && alt.trim() === '' && interactive && !isDecorativeImage(el);
    if (!missingAlt && !suspiciousEmptyAlt) return;
    findings.push({
      category: 'missing_alt_text',
      selector: el.tagName.toLowerCase() + (el.src ? '[src="' + el.src.substring(0, 80) + '"]' : ''),
      description: 'Image missing alt text: ' + (el.src || '').substring(0, 100)
    });
  });

  // Missing form labels
  document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), textarea, select').forEach(el => {
    if (!isElementVisibleForA11y(el)) return;
    const id = el.id;
    const hasLabel = id && document.querySelector('label[for="' + id + '"]');
    const hasWrappingLabel = el.closest('label');
    const hasAriaLabel = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby');
    const hasTitle = el.title;
    const hasPlaceholder = el.placeholder;
    if (!hasLabel && !hasWrappingLabel && !hasAriaLabel && !hasTitle && !hasPlaceholder) {
      findings.push({
        category: 'missing_form_label',
        selector: el.tagName.toLowerCase() + (el.name ? '[name="' + el.name + '"]' : ''),
        description: 'Form input missing label: ' + (el.name || el.type || 'unknown')
      });
    }
  });

  // Missing lang attribute
  const root = document.documentElement;
  const documentLang = root
    ? ((root.getAttribute('lang') || root.getAttribute('xml:lang') || root.lang || '').trim())
    : '';
  if (!documentLang) {
    findings.push({
      category: 'missing_lang',
      selector: 'html',
      description: 'Document missing lang attribute'
    });
  }

  // Missing page title
  if (!document.title || document.title.trim() === '') {
    findings.push({
      category: 'missing_title',
      selector: 'head > title',
      description: 'Page has no title or empty title'
    });
  }

  // Empty links and buttons
  document.querySelectorAll('a, button, [role="button"], [role="link"]').forEach(el => {
    if (!isElementVisibleForA11y(el)) return;
    const text = (el.textContent || '').trim();
    const ariaLabel = el.getAttribute('aria-label') || '';
    const ariaLabelledBy = el.getAttribute('aria-labelledby') || '';
    const title = el.title || '';
    const img = el.querySelector('img[alt]');
    if (!text && !ariaLabel && !ariaLabelledBy && !title && !img) {
      findings.push({
        category: 'empty_interactive',
        selector: el.tagName.toLowerCase() + (el.className ? '.' + el.className.split(' ')[0] : ''),
        description: 'Empty ' + el.tagName.toLowerCase() + ' element (no accessible text)'
      });
    }
  });

	  // Missing landmarks
	  const hasMain = document.querySelector('main, [role="main"]');
	  if (!hasMain) {
	    findings.push({
	      category: 'missing_landmarks',
	      selector: 'body',
	      description: 'Page missing main landmark'
	    });
	  }

	  // Missing skip navigation link (best-effort heuristic)
	  const hasSkipNav = Array.from(document.querySelectorAll('a[href^=\"#\"]')).some(a => {
	    const t = (a.textContent || '').trim();
	    return t && /skip/i.test(t);
	  });
		  if (!hasSkipNav) {
		    findings.push({
		      category: 'missing_skip_nav',
		      selector: 'body',
		      description: 'Page missing a skip navigation link (e.g., \"Skip to content\")'
		    });
		  }

		  // Potential keyboard trap heuristic: modal-like container has focusable controls
		  // but no obvious close/escape control.
		  const modalLike = document.querySelectorAll('dialog[open], [role=\"dialog\"][aria-modal=\"true\"], [aria-modal=\"true\"]');
		  modalLike.forEach(el => {
		    const focusable = el.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])');
		    if (focusable.length === 0) return;
		    const hasClose = el.querySelector('[aria-label*=\"close\" i], [title*=\"close\" i], button.close, [class*=\"close\"], [data-close], [data-dismiss], [data-testid*=\"close\" i]');
		    if (!hasClose) {
		      findings.push({
		        category: 'keyboard_trap',
		        selector: el.tagName.toLowerCase() + (el.id ? ('#' + el.id) : ''),
		        description: 'Modal/dialog appears to trap keyboard focus (no obvious close control)'
		      });
		    }
		  });

  // Heading hierarchy
  const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
  let prevLevel = 0;
  headings.forEach(h => {
    const level = parseInt(h.tagName[1]);
    if (prevLevel > 0 && level > prevLevel + 1) {
      findings.push({
        category: 'heading_hierarchy',
        selector: h.tagName.toLowerCase(),
        description: 'Heading level skips from h' + prevLevel + ' to h' + level
      });
    }
    prevLevel = level;
  });

	  // Duplicate IDs
	  const ids = {};
	  document.querySelectorAll('[id]').forEach(el => {
	    if (ids[el.id]) {
	      findings.push({
	        category: 'duplicate_id',
	        selector: '#' + el.id,
	        description: 'Duplicate ID: ' + el.id
	      });
	    }
	    ids[el.id] = true;
	  });

	  // Invalid ARIA references (aria-labelledby / aria-describedby → missing IDs)
	  const ariaRefAttrs = ['aria-labelledby', 'aria-describedby'];
	  document.querySelectorAll('[aria-labelledby], [aria-describedby]').forEach(el => {
	    ariaRefAttrs.forEach(attr => {
	      const v = el.getAttribute(attr);
	      if (!v) return;
	      v.split(/\\s+/).filter(Boolean).forEach(id => {
	        if (!document.getElementById(id)) {
	          findings.push({
	            category: 'invalid_aria',
	            selector: el.tagName.toLowerCase() + (el.id ? ('#' + el.id) : ''),
	            description: attr + ' references missing id: ' + id
	          });
	        }
	      });
	    });
	  });

	  // Insufficient contrast (best-effort; checks a limited number of leaf text elements)
	  try {
	    function parseRgb(s) {
	      const m = String(s || '').match(/rgba?\\((\\d+)\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)(?:\\s*,\\s*([0-9.]+))?\\)/i);
	      if (!m) return null;
	      return { r: parseInt(m[1], 10), g: parseInt(m[2], 10), b: parseInt(m[3], 10), a: (m[4] !== undefined ? parseFloat(m[4]) : 1.0) };
	    }
	    function composite(top, bottom) {
	      const alpha = top.a + bottom.a * (1 - top.a);
	      if (alpha <= 0) return { r: 0, g: 0, b: 0, a: 0 };
	      return {
	        r: Math.round((top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha),
	        g: Math.round((top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha),
	        b: Math.round((top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha),
	        a: alpha,
	      };
	    }
	    function isTransparentColor(s) {
	      if (!s) return true;
	      if (s === 'transparent') return true;
	      const c = parseRgb(s);
	      return !!c && c.a === 0;
	    }
	    function linearize(v) {
	      const s = v / 255;
	      return (s <= 0.04045) ? (s / 12.92) : Math.pow((s + 0.055) / 1.055, 2.4);
	    }
	    function luminance(c) {
	      return 0.2126 * linearize(c.r) + 0.7152 * linearize(c.g) + 0.0722 * linearize(c.b);
	    }
	    function contrastRatio(fg, bg) {
	      const l1 = luminance(fg);
	      const l2 = luminance(bg);
	      const lighter = Math.max(l1, l2);
	      const darker = Math.min(l1, l2);
	      return (lighter + 0.05) / (darker + 0.05);
	    }
	    function pageBackgroundColor() {
	      let bg = { r: 255, g: 255, b: 255, a: 1 };
	      const htmlBg = parseRgb(window.getComputedStyle(document.documentElement).backgroundColor);
	      const bodyBg = document.body ? parseRgb(window.getComputedStyle(document.body).backgroundColor) : null;
	      if (htmlBg && htmlBg.a > 0) bg = composite(htmlBg, bg);
	      if (bodyBg && bodyBg.a > 0) bg = composite(bodyBg, bg);
	      return bg;
	    }
	    function effectiveBackgroundColor(el) {
	      const layers = [];
	      let cur = el;
	      while (cur) {
	        const bg = parseRgb(window.getComputedStyle(cur).backgroundColor);
	        if (bg && !isTransparentColor(window.getComputedStyle(cur).backgroundColor)) {
	          layers.push(bg);
	        }
	        cur = cur.parentElement;
	      }
	      let out = pageBackgroundColor();
	      for (let i = layers.length - 1; i >= 0; i--) {
	        out = composite(layers[i], out);
	      }
	      return out;
	    }
	    function isVisible(el) {
	      return isElementVisibleForA11y(el);
	    }

	    let checked = 0;
	    const maxChecked = 200;
	    const nodes = document.querySelectorAll('body *');
	    for (const el of nodes) {
	      if (checked >= maxChecked) break;
	      if (!el || el.children && el.children.length > 0) continue; // leaf-ish elements
	      const text = (el.textContent || '').trim();
	      if (!text) continue;
	      if (!isVisible(el)) continue;

	      const style = window.getComputedStyle(el);
	      const fgStr = style.color;
	      const bgStr = effectiveBackgroundColor(el);
	      const fg = parseRgb(fgStr);
	      const bg = bgStr;
	      if (!fg || !bg) continue;
	      const effectiveFg = fg.a < 1 ? composite(fg, bg) : fg;

	      let fontSize = parseFloat(style.fontSize || '0');
	      let fw = style.fontWeight || '400';
	      let weightNum = parseInt(fw, 10);
	      if (isNaN(weightNum)) weightNum = (String(fw).toLowerCase() === 'bold' ? 700 : 400);
	      const isBold = weightNum >= 700;
	      const isLargeText = (fontSize >= 24) || (isBold && fontSize >= 18.66);
	      const required = isLargeText ? 3.0 : 4.5;

	      const ratio = contrastRatio(effectiveFg, bg);
	      if (ratio < required) {
	        findings.push({
	          category: 'insufficient_contrast',
	          selector: el.tagName.toLowerCase() + (el.id ? ('#' + el.id) : (el.className ? ('.' + String(el.className).split(' ')[0]) : '')),
	          description: 'Contrast ratio ' + ratio.toFixed(2) + ':1 (needs ' + required.toFixed(1) + ':1)'
	        });
	      }
	      checked += 1;
	    }
	  } catch (_) {}

  // Small touch targets (< 24x24px)
  try {
    document.querySelectorAll('a[href], button, input:not([type="hidden"]), select, textarea, [role="button"], [role="link"], [role="tab"], [tabindex]:not([tabindex="-1"])').forEach(el => {
      if (!isElementVisibleForA11y(el)) return;
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0 && (r.width < 24 || r.height < 24)) {
        findings.push({
          category: 'small_touch_target',
          selector: el.tagName.toLowerCase() + (el.id ? ('#' + el.id) : (el.className ? ('.' + String(el.className).split(' ')[0]) : '')),
          description: 'Touch target ' + Math.round(r.width) + 'x' + Math.round(r.height) + 'px (minimum 24x24)'
        });
      }
    });
  } catch (_) {}

  // Missing autocomplete on PII inputs
  try {
    const piiSelectors = [
      'input[name*="name" i]:not([autocomplete])',
      'input[name*="email" i]:not([autocomplete])',
      'input[name*="phone" i]:not([autocomplete])',
      'input[name*="tel" i]:not([autocomplete])',
      'input[name*="address" i]:not([autocomplete])',
      'input[name*="zip" i]:not([autocomplete])',
      'input[name*="postal" i]:not([autocomplete])',
      'input[type="email"]:not([autocomplete])',
      'input[type="tel"]:not([autocomplete])'
    ];
    document.querySelectorAll(piiSelectors.join(',')).forEach(el => {
      if (el.type === 'hidden') return;
      findings.push({
        category: 'missing_autocomplete',
        selector: el.tagName.toLowerCase() + (el.name ? '[name="' + el.name + '"]' : ''),
        description: 'PII input missing autocomplete: ' + (el.name || el.type || 'unknown')
      });
    });
  } catch (_) {}

  // Missing required ARIA state attributes
  try {
    const ariaStateRules = [
      { sel: '[aria-haspopup]:not([aria-expanded])', attr: 'aria-expanded' },
      { sel: '[role="tab"]:not([aria-selected])', attr: 'aria-selected' },
      { sel: '[role="checkbox"]:not([aria-checked])', attr: 'aria-checked' },
      { sel: '[role="radio"]:not([aria-checked])', attr: 'aria-checked' },
      { sel: '[role="switch"]:not([aria-checked])', attr: 'aria-checked' },
      { sel: '[role="treeitem"]:not([aria-expanded])', attr: 'aria-expanded' }
    ];
    ariaStateRules.forEach(rule => {
      document.querySelectorAll(rule.sel).forEach(el => {
        findings.push({
          category: 'missing_aria_state',
          selector: el.tagName.toLowerCase() + (el.id ? ('#' + el.id) : (el.className ? ('.' + String(el.className).split(' ')[0]) : '')),
          description: 'Missing ' + rule.attr + ' on ' + (el.getAttribute('role') || el.tagName.toLowerCase())
        });
      });
    });
  } catch (_) {}

  // Missing focus indicator (outline:none heuristic via stylesheet scan)
  try {
    const suppressors = new Set();
    for (const sheet of document.styleSheets) {
      try {
        for (const rule of sheet.cssRules || []) {
          if (rule.selectorText && /:(focus|focus-visible)/i.test(rule.selectorText)) {
            const outline = rule.style.getPropertyValue('outline');
            const outlineStyle = rule.style.getPropertyValue('outline-style');
            if ((outline && /\bnone\b|\b0\b/.test(outline)) || (outlineStyle && outlineStyle === 'none')) {
              const boxShadow = rule.style.getPropertyValue('box-shadow');
              const border = rule.style.getPropertyValue('border');
              const borderColor = rule.style.getPropertyValue('border-color');
              if (!boxShadow && !border && !borderColor) {
                const base = rule.selectorText.replace(/:focus(-visible)?/g, '').trim();
                if (base) suppressors.add(base);
              }
            }
          }
        }
      } catch (_) {}
    }
    suppressors.forEach(sel => {
      try {
        document.querySelectorAll(sel).forEach(el => {
          if (!el.matches('a[href], button, input, select, textarea, [tabindex]')) return;
          findings.push({
            category: 'missing_focus_indicator',
            selector: sel,
            description: 'Focus indicator suppressed (outline:none) on ' + sel
          });
        });
      } catch (_) {}
    });
  } catch (_) {}

	  return findings;
})()
"##;

/// Lookup a rule definition by category.
pub fn rule_for_category(category: A11yCategory) -> Option<&'static A11yRule> {
    RULES.iter().find(|r| r.category == category)
}

/// Parse the category string returned by browser JavaScript to the enum.
pub fn parse_category(s: &str) -> Option<A11yCategory> {
    match s {
        "missing_alt_text" => Some(A11yCategory::MissingAltText),
        "missing_form_label" => Some(A11yCategory::MissingFormLabel),
        "insufficient_contrast" => Some(A11yCategory::InsufficientContrast),
        "missing_lang" => Some(A11yCategory::MissingLang),
        "missing_title" => Some(A11yCategory::MissingTitle),
        "empty_interactive" => Some(A11yCategory::EmptyInteractive),
        "missing_landmarks" => Some(A11yCategory::MissingLandmarks),
        "duplicate_id" => Some(A11yCategory::DuplicateId),
        "keyboard_trap" => Some(A11yCategory::KeyboardTrap),
        "missing_skip_nav" => Some(A11yCategory::MissingSkipNav),
        "invalid_aria" => Some(A11yCategory::InvalidAria),
        "heading_hierarchy" => Some(A11yCategory::HeadingHierarchy),
        "small_touch_target" => Some(A11yCategory::SmallTouchTarget),
        "missing_autocomplete" => Some(A11yCategory::MissingAutocomplete),
        "missing_aria_state" => Some(A11yCategory::MissingAriaState),
        "missing_focus_indicator" => Some(A11yCategory::MissingFocusIndicator),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Color parsing ───────────────────────────────────────────────

    #[test]
    fn parse_hex_6_digit() {
        assert_eq!(parse_css_color("#FF0000"), Some((255, 0, 0)));
        assert_eq!(parse_css_color("#00ff00"), Some((0, 255, 0)));
        assert_eq!(parse_css_color("#0000FF"), Some((0, 0, 255)));
    }

    #[test]
    fn parse_hex_3_digit() {
        assert_eq!(parse_css_color("#F00"), Some((255, 0, 0)));
        assert_eq!(parse_css_color("#fff"), Some((255, 255, 255)));
        assert_eq!(parse_css_color("#000"), Some((0, 0, 0)));
    }

    #[test]
    fn parse_rgb() {
        assert_eq!(parse_css_color("rgb(255, 0, 0)"), Some((255, 0, 0)));
        assert_eq!(parse_css_color("rgb(0, 128, 255)"), Some((0, 128, 255)));
    }

    #[test]
    fn parse_rgba() {
        assert_eq!(parse_css_color("rgba(255, 0, 0, 0.5)"), Some((255, 0, 0)));
    }

    #[test]
    fn parse_invalid_color() {
        assert_eq!(parse_css_color("red"), None);
        assert_eq!(parse_css_color(""), None);
        assert_eq!(parse_css_color("#GG0000"), None);
        assert_eq!(parse_css_color("hsl(0, 100%, 50%)"), None);
    }

    // ── Luminance & contrast ────────────────────────────────────────

    #[test]
    fn luminance_black() {
        let l = relative_luminance(0, 0, 0);
        assert!(l.abs() < 0.001);
    }

    #[test]
    fn luminance_white() {
        let l = relative_luminance(255, 255, 255);
        assert!((l - 1.0).abs() < 0.001);
    }

    #[test]
    fn contrast_black_white() {
        let ratio = contrast_ratio((0, 0, 0), (255, 255, 255));
        assert!((ratio - 21.0).abs() < 0.1);
    }

    #[test]
    fn contrast_same_color_is_one() {
        let ratio = contrast_ratio((128, 128, 128), (128, 128, 128));
        assert!((ratio - 1.0).abs() < 0.01);
    }

    #[test]
    fn contrast_is_symmetric() {
        let ratio_ab = contrast_ratio((255, 0, 0), (0, 0, 255));
        let ratio_ba = contrast_ratio((0, 0, 255), (255, 0, 0));
        assert!((ratio_ab - ratio_ba).abs() < 0.001);
    }

    // ── WCAG thresholds ─────────────────────────────────────────────

    #[test]
    fn aa_normal_threshold() {
        assert!(meets_aa_normal(4.5));
        assert!(meets_aa_normal(5.0));
        assert!(!meets_aa_normal(4.4));
    }

    #[test]
    fn aa_large_threshold() {
        assert!(meets_aa_large(3.0));
        assert!(meets_aa_large(4.0));
        assert!(!meets_aa_large(2.9));
    }

    #[test]
    fn aaa_normal_threshold() {
        assert!(meets_aaa_normal(7.0));
        assert!(meets_aaa_normal(21.0));
        assert!(!meets_aaa_normal(6.9));
    }

    #[test]
    fn black_on_white_passes_all() {
        let ratio = contrast_ratio((0, 0, 0), (255, 255, 255));
        assert!(meets_aa_normal(ratio));
        assert!(meets_aa_large(ratio));
        assert!(meets_aaa_normal(ratio));
    }

    #[test]
    fn light_gray_on_white_fails_aa() {
        let ratio = contrast_ratio((200, 200, 200), (255, 255, 255));
        assert!(!meets_aa_normal(ratio));
        assert!(!meets_aa_large(ratio));
    }

    // ── Rule registry ───────────────────────────────────────────────

    #[test]
    fn rules_are_nonempty() {
        assert!(RULES.len() >= 10);
    }

    #[test]
    fn all_rules_have_descriptions() {
        for rule in RULES {
            assert!(!rule.description.is_empty());
            assert!(!rule.wcag_criterion.is_empty());
        }
    }

    #[test]
    fn rules_contain_key_categories() {
        let categories: Vec<A11yCategory> = RULES.iter().map(|r| r.category).collect();
        assert!(categories.contains(&A11yCategory::MissingAltText));
        assert!(categories.contains(&A11yCategory::MissingFormLabel));
        assert!(categories.contains(&A11yCategory::InsufficientContrast));
        assert!(categories.contains(&A11yCategory::MissingLang));
        assert!(categories.contains(&A11yCategory::EmptyInteractive));
    }

    // ── Category parsing ────────────────────────────────────────────

    #[test]
    fn parse_all_categories() {
        assert_eq!(
            parse_category("missing_alt_text"),
            Some(A11yCategory::MissingAltText)
        );
        assert_eq!(
            parse_category("missing_form_label"),
            Some(A11yCategory::MissingFormLabel)
        );
        assert_eq!(
            parse_category("insufficient_contrast"),
            Some(A11yCategory::InsufficientContrast)
        );
        assert_eq!(
            parse_category("missing_lang"),
            Some(A11yCategory::MissingLang)
        );
        assert_eq!(
            parse_category("missing_title"),
            Some(A11yCategory::MissingTitle)
        );
        assert_eq!(
            parse_category("empty_interactive"),
            Some(A11yCategory::EmptyInteractive)
        );
        assert_eq!(
            parse_category("missing_landmarks"),
            Some(A11yCategory::MissingLandmarks)
        );
        assert_eq!(
            parse_category("duplicate_id"),
            Some(A11yCategory::DuplicateId)
        );
        assert_eq!(
            parse_category("keyboard_trap"),
            Some(A11yCategory::KeyboardTrap)
        );
        assert_eq!(
            parse_category("heading_hierarchy"),
            Some(A11yCategory::HeadingHierarchy)
        );
    }

    #[test]
    fn parse_all_new_categories() {
        assert_eq!(
            parse_category("small_touch_target"),
            Some(A11yCategory::SmallTouchTarget)
        );
        assert_eq!(
            parse_category("missing_autocomplete"),
            Some(A11yCategory::MissingAutocomplete)
        );
        assert_eq!(
            parse_category("missing_aria_state"),
            Some(A11yCategory::MissingAriaState)
        );
        assert_eq!(
            parse_category("missing_focus_indicator"),
            Some(A11yCategory::MissingFocusIndicator)
        );
    }

    #[test]
    fn rules_contain_new_categories() {
        let categories: Vec<A11yCategory> = RULES.iter().map(|r| r.category).collect();
        assert!(categories.contains(&A11yCategory::SmallTouchTarget));
        assert!(categories.contains(&A11yCategory::MissingAutocomplete));
        assert!(categories.contains(&A11yCategory::MissingAriaState));
        assert!(categories.contains(&A11yCategory::MissingFocusIndicator));
    }

    #[test]
    fn parse_unknown_category() {
        assert_eq!(parse_category("unknown_thing"), None);
        assert_eq!(parse_category(""), None);
    }

    // ── Rule lookup ─────────────────────────────────────────────────

    #[test]
    fn rule_for_category_found() {
        let rule = rule_for_category(A11yCategory::MissingAltText);
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.wcag_criterion, "1.1.1");
        assert_eq!(rule.wcag_level, WcagLevel::A);
        assert_eq!(rule.impact, A11yImpact::Critical);
    }

    #[test]
    fn rule_for_category_keyboard_trap_present() {
        let rule = rule_for_category(A11yCategory::KeyboardTrap);
        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.wcag_criterion, "2.1.2");
        assert_eq!(rule.wcag_level, WcagLevel::A);
    }

    // ── Severity mapping ────────────────────────────────────────────

    #[test]
    fn finding_severity_mapping() {
        use crate::types::bugs::BugSeverity;

        let finding = A11yFinding {
            category: A11yCategory::MissingAltText,
            wcag_criterion: "1.1.1",
            wcag_level: WcagLevel::A,
            selector: Some("img".into()),
            description: "test".into(),
            impact: A11yImpact::Critical,
        };
        assert_eq!(finding.to_bug_severity(), BugSeverity::High);

        let finding2 = A11yFinding {
            impact: A11yImpact::Minor,
            ..finding.clone()
        };
        assert_eq!(finding2.to_bug_severity(), BugSeverity::Info);
    }

    // ── Contrast with real-world examples ───────────────────────────

    #[test]
    fn dark_blue_on_white_passes_aa() {
        // #003366 on #FFFFFF
        let ratio = contrast_ratio((0, 51, 102), (255, 255, 255));
        assert!(meets_aa_normal(ratio), "ratio was {ratio}");
    }

    #[test]
    fn medium_gray_on_white_boundary() {
        // #767676 on #FFFFFF is exactly the AA boundary for normal text
        let ratio = contrast_ratio((118, 118, 118), (255, 255, 255));
        assert!(meets_aa_normal(ratio), "ratio was {ratio}");
    }
}
