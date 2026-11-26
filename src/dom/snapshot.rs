//! Post-interaction DOM snapshot capture.
//!
//! Installs a targeted `MutationObserver` before an interaction, then collects
//! the added nodes afterwards to produce a structured [`InteractionSnapshot`].

use anyhow::{Context, Result};

use crate::browser::PageClient;
use crate::dom::selector::{LOCATOR_RUNTIME_JS, primary_locator_json};
use crate::types::dom::{InteractionSnapshot, InteractiveElement};
use crate::types::graph::TransitionType;

/// Inject a pre-interaction MutationObserver. Returns a snapshot ID that must be
/// passed to [`end_snapshot`] after the interaction settles.
pub async fn begin_snapshot(page: &PageClient) -> Result<String> {
    let id: String = page
        .evaluate_json(BEGIN_SNAPSHOT_JS)
        .await
        .context("begin_snapshot JS")?;
    Ok(id)
}

/// Collect post-interaction DOM changes recorded by the observer installed via
/// [`begin_snapshot`] and return a structured snapshot.
pub async fn end_snapshot(
    page: &PageClient,
    snapshot_id: &str,
    trigger: Option<&InteractiveElement>,
) -> Result<InteractionSnapshot> {
    let id_json = serde_json::to_string(snapshot_id)?;
    let trigger_json = match trigger {
        Some(element) => primary_locator_json(element)?,
        None => "null".to_string(),
    };
    let script = format!(
        "(() => {{ const id = {id_json}; const trigger_locator = {trigger_json}; {LOCATOR_RUNTIME_JS} {END_SNAPSHOT_JS} }})()"
    );
    let snap: InteractionSnapshot = page
        .evaluate_json(&script)
        .await
        .context("end_snapshot JS")?;
    Ok(snap)
}

// ---------------------------------------------------------------------------
// JavaScript snippets
// ---------------------------------------------------------------------------

const BEGIN_SNAPSHOT_JS: &str = r#"
(() => {
  const key = "__BROKENAPP_SNAP";
  const id = "snap_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8);
  const MAX_ADDED = 250;
  const MAX_ATTR = 100;

  if (!window[key]) window[key] = {};
  const state = { added: [], attr_changes: [], truncated: false, observer: null };

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === "attributes") {
        if (state.attr_changes.length < MAX_ATTR) {
          state.attr_changes.push({ target: m.target, attr: m.attributeName, oldValue: m.oldValue });
        }
        continue;
      }
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (state.added.length < MAX_ADDED) {
          state.added.push(node);
        } else {
          state.truncated = true;
          observer.disconnect();
          return;
        }
      }
    }
  });
  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeOldValue: true,
    attributeFilter: [
      "aria-expanded", "aria-hidden", "aria-selected", "aria-pressed",
      "aria-checked", "aria-disabled", "disabled", "class", "hidden", "open",
      "data-state", "data-active", "data-open", "data-expanded", "data-disabled",
      "style"
    ],
  });

  state.observer = observer;
  window[key][id] = state;
  return id;
})()
"#;

const END_SNAPSHOT_JS: &str = r##"
  const key = "__BROKENAPP_SNAP";
  const state = (window[key] || {})[id];
  const result = { appeared_elements: [], appeared_text: [], attribute_changes: [], modal_opened: null, truncated: false };
  if (!state) return result;

  state.observer.disconnect();
  delete window[key][id];

  result.truncated = !!state.truncated;

  function scrubText(s) {
    if (!s) return s;
    let out = String(s);
    out = out.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "<email>");
    out = out.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<id>");
    out = out.replace(/\b[0-9a-f]{32,}\b/gi, "<token>");
    out = out.replace(/\b\d{5,}\b/g, "<num>");
    out = out.replace(/\s+/g, " ").trim();
    return out;
  }

  const added = state.added || [];
  let triggerEl = null;
  if (trigger_locator) {
    try {
      triggerEl = resolveBrokenAppLocator(trigger_locator);
    } catch (_) {
      triggerEl = null;
    }
  }

  function isRelatedToTrigger(target) {
    if (!triggerEl || !target || target.nodeType !== 1) return true;
    if (target === triggerEl) return true;
    if (triggerEl.contains && triggerEl.contains(target)) return true;
    if (target.contains && target.contains(triggerEl)) return true;
    // Common disclosure pattern: trigger controls a separate panel.
    const controlsId = triggerEl.getAttribute && triggerEl.getAttribute("aria-controls");
    if (controlsId) {
      const controlled = document.getElementById(controlsId);
      if (controlled) {
        if (target === controlled) return true;
        if (controlled.contains && controlled.contains(target)) return true;
        if (target.contains && target.contains(controlled)) return true;
      }
    }
    return false;
  }

  function isUiStateAttribute(attr) {
    return [
      "aria-expanded", "aria-hidden", "aria-selected", "aria-pressed",
      "aria-checked", "aria-disabled", "disabled", "class", "hidden", "open",
      "data-state", "data-active", "data-open", "data-expanded", "data-disabled",
      "style"
    ].includes(attr);
  }

  function isNearbyTriggerTarget(target) {
    if (!triggerEl || !target || target.nodeType !== 1) return false;

    if (triggerEl.parentElement && target.parentElement && triggerEl.parentElement === target.parentElement) {
      return true;
    }

    const scopeSelector = "main, section, article, aside, nav, form, [role='region'], [role='dialog']";
    const triggerScope = triggerEl.closest && triggerEl.closest(scopeSelector);
    const targetScope = target.closest && target.closest(scopeSelector);
    if (triggerScope && targetScope && triggerScope === targetScope) {
      return true;
    }

    let sibling = triggerEl.nextElementSibling;
    let hops = 0;
    while (sibling && hops < 5) {
      if (sibling === target || sibling.contains(target) || target.contains(sibling)) return true;
      sibling = sibling.nextElementSibling;
      hops += 1;
    }

    return false;
  }

  function isVisible(el) {
    if (!el || !el.getBoundingClientRect) return false;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  }

  function isRevealedByAttr(ac) {
    const el = ac && ac.target;
    if (!el || el.nodeType !== 1 || el === triggerEl || !document.body.contains(el)) return false;
    if (!isVisible(el)) return false;
    const oldVal = ac.oldValue != null ? String(ac.oldValue) : null;
    const newVal = el.getAttribute ? el.getAttribute(ac.attr) : null;
    if (oldVal === newVal) return false;
    switch (ac.attr) {
      case "hidden":
        return oldVal !== null && newVal === null;
      case "open":
        return oldVal === null && newVal !== null;
      case "aria-hidden":
        return oldVal === "true" && newVal !== "true";
      case "data-state":
        return newVal === "open" || newVal === "active" || newVal === "expanded" || newVal === "visible";
      case "data-open":
      case "data-expanded":
        return newVal === "true" || newVal === "";
      case "style":
        return !!(oldVal && /(?:display\s*:\s*none|visibility\s*:\s*hidden)/i.test(oldVal));
      case "class":
        return !!(oldVal && /(?:^|\s)(?:hidden|d-none|invisible|collapsed|closed|is-hidden|sr-only)(?:\s|$)/i.test(oldVal));
      default:
        return false;
    }
  }

  // Combine newly inserted DOM nodes with pre-rendered UI revealed by
  // visibility/state attribute mutations (e.g. `hidden`, `open`, `aria-hidden`,
  // `data-state="open"`, `display:none`, Tailwind/Bootstrap `hidden`/`d-none`).
  const candidates = added.slice();
  if (state.attr_changes && state.attr_changes.length > 0) {
    for (const ac of state.attr_changes) {
      try {
        if (isRevealedByAttr(ac) && !candidates.includes(ac.target)) {
          candidates.push(ac.target);
        }
      } catch (_) {}
    }
  }

  // Deduplicate: skip children if their ancestor is also in the list.
  const roots = [];
  for (const node of candidates) {
    if (!document.body.contains(node)) continue;
    let dominated = false;
    for (const r of roots) {
      if (r.contains(node)) { dominated = true; break; }
    }
    if (!dominated) {
      // Remove any existing roots that this node dominates.
      for (let i = roots.length - 1; i >= 0; i--) {
        if (node.contains(roots[i])) roots.splice(i, 1);
      }
      roots.push(node);
    }
  }

  function shortSelector(el) {
    if (el.id) return "#" + CSS.escape(el.id);
    const tag = (el.tagName || "").toLowerCase();
    const role = el.getAttribute && el.getAttribute("role");
    if (role) return tag + '[role="' + role + '"]';
    const cls = (el.className && typeof el.className === "string")
      ? el.className.trim().split(/\s+/).slice(0, 2).map(c => "." + CSS.escape(c)).join("")
      : "";
    if (cls) return tag + cls;
    return tag;
  }

  function isUnique(sel) {
    try { return document.querySelectorAll(sel).length === 1; } catch (_) { return false; }
  }

  // Short selector when unique (classes kept: they describe the element);
  // otherwise a structural path from the nearest id/body that ends in it,
  // so `document.querySelector` finds this element and not the first match.
  function bestSelector(el) {
    const short = shortSelector(el);
    if (isUnique(short)) return short;
    const parts = [];
    let cur = el;
    for (let i = 0; cur && cur.nodeType === 1 && i < 12; i++) {
      const tag = (cur.tagName || "").toLowerCase();
      if (cur !== el && cur.id && isUnique("#" + CSS.escape(cur.id))) {
        parts.unshift("#" + CSS.escape(cur.id));
        break;
      }
      if (tag === "body" || tag === "html") {
        parts.unshift(tag);
        break;
      }
      const parent = cur.parentElement;
      const base = cur === el && !short.startsWith("#") ? short : tag;
      if (!parent) { parts.unshift(base); break; }
      const same = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
      parts.unshift(base + ":nth-of-type(" + (same.indexOf(cur) + 1) + ")");
      cur = parent;
    }
    const path = parts.join(" > ");
    return isUnique(path) ? path : short;
  }

  function isToastLikeElement(el) {
    if (!el || el.nodeType !== 1) return false;
    const role = ((el.getAttribute && el.getAttribute("role")) || "").toLowerCase();
    const cls = ((el.className && typeof el.className === "string") ? el.className : "").toLowerCase();
    const slot = ((el.getAttribute && el.getAttribute("data-slot")) || "").toLowerCase();
    const dtype = ((el.getAttribute && el.getAttribute("data-type")) || "").toLowerCase();
    const dvar = ((el.getAttribute && el.getAttribute("data-variant")) || "").toLowerCase();
    const live = ((el.getAttribute && el.getAttribute("aria-live")) || "").toLowerCase();
    if (el.hasAttribute && (el.hasAttribute("data-sonner-toast") || el.hasAttribute("data-toast"))) return true;
    if (slot.includes("toast") || slot.includes("snackbar") || slot.includes("notification")) return true;
    if (cls.includes("toast") || cls.includes("snackbar") || cls.includes("notistack")
        || cls.includes("notification") || cls.includes("callout")) return true;
    if (role === "alert" || role === "alertdialog" || live === "assertive") return true;
    if (["error", "destructive", "danger", "warning", "success", "info"].includes(dtype)
        || ["error", "destructive", "danger"].includes(dvar)) return true;
    return false;
  }

  function toastAncestor(el) {
    let cur = el;
    for (let i = 0; cur && cur.nodeType === 1 && i < 8; i++) {
      if (isToastLikeElement(cur)) return cur;
      cur = cur.parentElement;
    }
    return null;
  }

  function hasErrorActionButton(el) {
    const scope = toastAncestor(el) || el;
    if (!scope || !scope.querySelectorAll) return false;
    try {
      for (const btn of scope.querySelectorAll("button, a, [role='button']")) {
        const label = ((btn.getAttribute && (btn.getAttribute("aria-label") || btn.getAttribute("title"))) || btn.textContent || "")
          .trim()
          .toLowerCase();
        if (label === "copy error" || label.includes("copy error")
            || label.includes("report error") || label.includes("view error")
            || label.includes("error details") || label.includes("show error")) {
          return true;
        }
      }
    } catch (_) {}
    return false;
  }

  function classifyText(el) {
    const targets = [el];
    const ancestor = toastAncestor(el);
    if (ancestor && ancestor !== el) targets.push(ancestor);
    let sawSuccess = false;
    let sawInfo = false;
    for (const node of targets) {
      const cls = ((node.className && typeof node.className === "string") ? node.className : "").toLowerCase();
      const role = ((node.getAttribute && node.getAttribute("role")) || "").toLowerCase();
      const dtype = ((node.getAttribute && (node.getAttribute("data-type") || node.getAttribute("data-variant") || node.getAttribute("data-status") || node.getAttribute("data-intent"))) || "").toLowerCase();
      const live = ((node.getAttribute && node.getAttribute("aria-live")) || "").toLowerCase();
      if (["success", "ok", "positive"].includes(dtype) || cls.includes("success") || cls.includes("toast-success")) {
        sawSuccess = true;
      }
      if (["info", "notice"].includes(dtype) || cls.includes("info") || cls.includes("notice") || role === "status") {
        sawInfo = true;
      }
      if (role === "alert" || role === "alertdialog"
          || ["error", "destructive", "danger", "failed", "failure"].includes(dtype)
          || cls.includes("error") || cls.includes("danger") || cls.includes("invalid") || cls.includes("destructive")
          || (live === "assertive" && !sawSuccess && !sawInfo)) {
        return "error";
      }
    }
    if (hasErrorActionButton(el)) return "error";
    if (sawSuccess) return "success";
    if (sawInfo) return "info";
    return "unknown";
  }

  function isToastOnlyOverlay(el) {
    const slot = ((el.getAttribute && el.getAttribute("data-slot")) || "").toLowerCase();
    const cls = ((el.className && typeof el.className === "string") ? el.className : "").toLowerCase();
    const role = ((el.getAttribute && el.getAttribute("role")) || "").toLowerCase();
    if (el.hasAttribute && (el.hasAttribute("data-sonner-toast") || el.hasAttribute("data-toast"))) return true;
    if (slot.includes("toast") || slot.includes("snackbar")) return true;
    if (el.closest && el.closest('[data-slot*="toast"], [data-radix-toast-viewport]')) return true;
    if (el.querySelector && el.querySelector('[data-slot="toast-close"], [data-slot="toast-description"], [data-slot="toast-title"]')) return true;
    if ((cls.includes("toast") || cls.includes("snackbar") || cls.includes("notistack"))
        && !cls.includes("modal") && !cls.includes("dialog-popup")) return true;
    if (role === "dialog" && hasErrorActionButton(el)) {
      try {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.height > 0 && r.width <= 560 && r.height <= 260) return true;
      } catch (_) {}
    }
    return false;
  }

  const CONTROL_SELECTOR = 'a[href], button, input, select, textarea, summary, [role="button"], [role="tab"], [role="checkbox"], [role="radio"], [role="switch"], [role="menuitem"], [tabindex]:not([tabindex="-1"])';
  function elementKind(el) {
    const tag = (el.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return "form_field";
    if (tag === "button" || (el.getAttribute && el.getAttribute("role") === "button")) return "button";
    if (tag === "div" || tag === "section" || tag === "article" || tag === "main") return "container";
    // Any other element that brings controls with it (a form, a list, a
    // paragraph wrapping a button) is a root to explore.
    try { if (el.querySelector && el.querySelector(CONTROL_SELECTOR)) return "container"; } catch (_) {}
    return "text";
  }

  // Check for modals among roots.
  for (const el of roots) {
    if (!isVisible(el)) continue;
    const role = el.getAttribute && el.getAttribute("role");
    const tag = (el.tagName || "").toLowerCase();
    const cls = ((el.className && typeof el.className === "string") ? el.className : "").toLowerCase();
    const isModal = !isToastOnlyOverlay(el) && (
                    role === "dialog" || role === "alertdialog" || tag === "dialog" ||
                    cls.includes("modal") || cls.includes("dialog") ||
                    el.getAttribute("aria-modal") === "true");
    if (isModal) {
      const titleEl = el.querySelector("[class*='title'], h1, h2, h3, [class*='header'] h1, [class*='header'] h2");
      const title = titleEl ? scrubText((titleEl.textContent || "").trim()).slice(0, 200) : null;
      const buttons = [];
      for (const btn of el.querySelectorAll("button, [role='button']")) {
        const t = scrubText((btn.textContent || "").trim());
        if (t && t.length < 100) buttons.push(t);
      }
      const form_fields = [];
      for (const inp of el.querySelectorAll("input, textarea, select")) {
        if (!isVisible(inp)) continue;
        const itag = (inp.tagName || "").toLowerCase();
        const itype = ((inp.getAttribute && inp.getAttribute("type")) || "text").toLowerCase();
        if (itype === "hidden") continue;
        const name = inp.getAttribute("name") || null;
        const label_text = (() => {
          const lid = inp.getAttribute("id");
          if (lid) {
            const lbl = el.querySelector('label[for="' + CSS.escape(lid) + '"]');
            if (lbl) return scrubText((lbl.textContent || "").trim()).slice(0, 200);
          }
          const parent = inp.closest("label");
          if (parent) return scrubText((parent.textContent || "").trim()).slice(0, 200);
          return null;
        })();
        const placeholder = inp.getAttribute("placeholder") ? scrubText(inp.getAttribute("placeholder")).slice(0, 200) : null;
        let field_type = "text";
        if (itag === "textarea") field_type = "textarea";
        else if (itag === "select") {
          const opts = Array.from(inp.options || []).map(o => scrubText((o.label || o.textContent || "").trim())).filter(Boolean);
          field_type = inp.multiple ? { multi_select: { options: opts.slice(0, 20) } } : { select: { options: opts.slice(0, 20) } };
        } else {
          const typeMap = {
            email: "email", password: "password", number: "number",
            tel: "tel", url: "url", date: "date", datetime: "date_time",
            "datetime-local": "date_time", time: "time", color: "color",
            file: "file", checkbox: "checkbox", radio: "radio",
          };
          if (itype === "radio") {
            const group = inp.getAttribute("name") || null;
            const opts = group ? Array.from(el.querySelectorAll('input[name="' + CSS.escape(group) + '"]')).map(r => {
              const rl = r.closest("label");
              return rl ? scrubText((rl.textContent || "").trim()) : scrubText(r.value || "");
            }).filter(Boolean) : [];
            field_type = { radio: { group: group, options: opts.slice(0, 20) } };
          } else {
            field_type = typeMap[itype] || "text";
          }
        }
        form_fields.push({
          label: label_text,
          name: name,
          field_type: field_type,
          required: inp.required || false,
          placeholder: placeholder,
          selector: bestSelector(inp),
          drives_query_params: [],
        });
      }
      result.modal_opened = {
        selector: bestSelector(el),
        title: title,
        form_fields: form_fields,
        buttons: buttons.slice(0, 10),
      };
      break;
    }
  }

  // Collect appeared elements and text (limit to 30 each).
  for (const el of roots) {
    if (!isVisible(el)) continue;
    const sel = bestSelector(el);
    const tag = (el.tagName || "").toLowerCase();
    const role = el.getAttribute && el.getAttribute("role");

    result.appeared_elements.push({
      selector: sel,
      tag: tag,
      role: role || null,
      label: (el.getAttribute && scrubText(el.getAttribute("aria-label") || el.getAttribute("title"))) || null,
      element_kind: elementKind(el),
    });
    if (result.appeared_elements.length >= 30) break;

    // Check for text-like appearances (toasts, alerts, validation messages).
    const rawText = (typeof el.innerText === "string" && el.innerText.trim()) ? el.innerText : (el.textContent || "");
    const text = scrubText(rawText.trim());
    if (text && text.length > 0 && text.length < 600) {
      const isTextual = tag === "p" || tag === "span" || tag === "div" || tag === "li" || tag === "section"
        || role === "alert" || role === "alertdialog" || role === "status";
      const cls = ((el.className && typeof el.className === "string") ? el.className : "").toLowerCase();
      const isToast = !!toastAncestor(el);
      const isMessage = isToast || cls.includes("error") || cls.includes("success") || cls.includes("toast") ||
                        cls.includes("alert") || cls.includes("message") || cls.includes("notice") ||
                        cls.includes("destructive") || cls.includes("danger") ||
                        role === "alert" || role === "alertdialog" || role === "status" ||
                        el.getAttribute("aria-live");
      if (isTextual || isMessage) {
        const inForm = !!(el.closest && el.closest("form")) && !isToast;
        result.appeared_text.push({
          selector: sel,
          text: text.slice(0, 500),
          kind: classifyText(el),
          is_toast: isToast,
          in_form: inForm,
          has_error_action: hasErrorActionButton(el),
        });
        if (result.appeared_text.length >= 20) break;
      }
    }

    // Also scan children for text nodes (toasts/alerts/validation messages inside portals).
    if (result.appeared_text.length < 20) {
      const msgQuery = [
        "[role='alert']", "[role='alertdialog']", "[role='status']", "[aria-live]",
        "[data-sonner-toast]", "[data-toast]", "[data-slot*='toast']",
        "[data-type='error']", "[data-variant='destructive']", "[data-variant='error']",
        "[class*='error']", "[class*='destructive']", "[class*='danger']",
        "[class*='success']", "[class*='toast']", "[class*='snackbar']",
        "[class*='notification']", "[class*='message']"
      ].join(", ");
      for (const child of el.querySelectorAll(msgQuery)) {
        if (!isVisible(child)) continue;
        const rawChild = (typeof child.innerText === "string" && child.innerText.trim()) ? child.innerText : (child.textContent || "");
        const ct = scrubText(rawChild.trim());
        if (ct && ct.length > 0 && ct.length < 600) {
          const isToast = !!toastAncestor(child);
          const inForm = !!(child.closest && child.closest("form")) && !isToast;
          result.appeared_text.push({
            selector: bestSelector(child),
            text: ct.slice(0, 500),
            kind: classifyText(child),
            is_toast: isToast,
            in_form: inForm,
            has_error_action: hasErrorActionButton(child),
          });
          if (result.appeared_text.length >= 20) break;
        }
      }
    }
  }

  // Process attribute changes captured by the observer.
  if (state.attr_changes && state.attr_changes.length > 0) {
    for (const ac of state.attr_changes) {
      try {
        if (!ac.target || !ac.target.getAttribute) continue;
        // Class/style churn only describes the action on the control itself,
        // its ancestors or the element it controls; other UI-state
        // attributes may come from a nearby element.
        const related = isRelatedToTrigger(ac.target);
        const nearbyState = isUiStateAttribute(ac.attr) && ac.attr !== "class" && ac.attr !== "style" && isNearbyTriggerTarget(ac.target);
        if (!related && !nearbyState) continue;
        const newValue = ac.target.getAttribute(ac.attr);
        let oldVal = ac.oldValue != null ? String(ac.oldValue) : null;
        let newVal = newValue != null ? String(newValue) : null;
        // For class changes, normalize by sorting to avoid noise from reordering.
        if (ac.attr === "class") {
          if (oldVal) oldVal = oldVal.trim().split(/\s+/).sort().join(" ");
          if (newVal) newVal = newVal.trim().split(/\s+/).sort().join(" ");
          if (oldVal === newVal) continue;
        }
        // For style changes, truncate to 200 chars.
        if (ac.attr === "style") {
          if (oldVal && oldVal.length > 200) oldVal = oldVal.slice(0, 200);
          if (newVal && newVal.length > 200) newVal = newVal.slice(0, 200);
        }
        // Skip no-ops.
        if (oldVal === newVal) continue;
        result.attribute_changes.push({
          selector: bestSelector(ac.target),
          attribute: ac.attr,
          old_value: oldVal,
          new_value: newVal,
        });
      } catch (_) {}
    }
  }

  return result;
"##;

/// Classify a post-interaction snapshot into a transition type based on the
/// observed DOM changes (modal opened, aria-expanded toggled, etc.).
pub fn classify_mutation(snapshot: &InteractionSnapshot) -> TransitionType {
    if snapshot.modal_opened.is_some() {
        return TransitionType::ModalOpen;
    }

    for change in &snapshot.attribute_changes {
        match change.attribute.as_str() {
            "aria-expanded" => {
                if change.new_value.as_deref() == Some("true") {
                    return TransitionType::AccordionToggle;
                }
            }
            "aria-selected" => {
                if change.new_value.as_deref() == Some("true") {
                    return TransitionType::TabSwitch;
                }
            }
            "data-state" => {
                let new = change.new_value.as_deref().unwrap_or("");
                if new == "open" || new == "active" || new == "expanded" {
                    return TransitionType::AccordionToggle;
                }
            }
            _ => {}
        }
    }

    TransitionType::ViewStateChange
}

/// Short, stable description of what an interaction changed in the DOM, for
/// `interactions.jsonl` (`dom_change`): `modal`, `menu`, `tab`, `toast`,
/// `panel`, `message`, `content`, `side_effect`, or `other`.
pub fn describe_dom_change(snapshot: &InteractionSnapshot) -> &'static str {
    const MENU_ROLES: [&str; 3] = ["menu", "menubar", "listbox"];
    const MENU_HINTS: [&str; 7] = [
        "menu",
        "nav",
        "drawer",
        "dropdown",
        "popover",
        "sidebar",
        "offcanvas",
    ];
    const TOAST_HINTS: [&str; 4] = ["toast", "snackbar", "notification", "notice"];
    const MODAL_HINTS: [&str; 3] = ["modal", "dialog", "lightbox"];

    if snapshot.modal_opened.is_some() {
        return "modal";
    }
    // Only the element's own selector segment describes it (structural
    // paths carry every ancestor's tag, e.g. `nav`).
    let has_hint = |selector: &str, hints: &[&str]| {
        let own = selector.rsplit(" > ").next().unwrap_or(selector);
        let s = own.to_ascii_lowercase();
        hints.iter().any(|h| s.contains(h))
    };
    // Attribute changes that reveal something (class/style only count when
    // the target itself looks like a menu/drawer; they are noisy otherwise).
    let reveals = |c: &crate::types::dom::AttributeChange| {
        let new = c.new_value.as_deref().unwrap_or("");
        match c.attribute.as_str() {
            "aria-expanded" => new == "true",
            "data-state" => matches!(new, "open" | "expanded" | "active"),
            "open" | "data-open" | "data-expanded" => c.new_value.is_some(),
            "hidden" => c.old_value.is_some() && c.new_value.is_none(),
            "aria-hidden" => new == "false" || c.new_value.is_none(),
            "class" | "style" => true,
            _ => false,
        }
    };

    // A pre-rendered dialog revealed by toggling `hidden`/`open`/`aria-hidden`.
    if snapshot.attribute_changes.iter().any(|c| {
        reveals(c)
            && c.attribute != "class"
            && c.attribute != "style"
            && has_hint(&c.selector, &MODAL_HINTS)
    }) {
        return "modal";
    }

    let appeared_menu = snapshot.appeared_elements.iter().any(|e| {
        e.role.as_deref().is_some_and(|r| MENU_ROLES.contains(&r))
            || has_hint(&e.selector, &MENU_HINTS)
    });
    let revealed_menu = snapshot
        .attribute_changes
        .iter()
        .any(|c| reveals(c) && has_hint(&c.selector, &MENU_HINTS));
    if appeared_menu || revealed_menu {
        return "menu";
    }
    if snapshot
        .attribute_changes
        .iter()
        .any(|c| c.attribute == "aria-selected" && c.new_value.as_deref() == Some("true"))
    {
        return "tab";
    }
    if snapshot
        .appeared_text
        .iter()
        .any(|t| t.kind == "error" && (t.is_toast || t.has_error_action))
    {
        return "error_toast";
    }
    let appeared_toast = snapshot.appeared_elements.iter().any(|e| {
        matches!(e.role.as_deref(), Some("alert" | "status")) || has_hint(&e.selector, &TOAST_HINTS)
    }) || snapshot
        .appeared_text
        .iter()
        .any(|t| t.is_toast || has_hint(&t.selector, &TOAST_HINTS));
    if appeared_toast {
        return "toast";
    }
    if snapshot
        .attribute_changes
        .iter()
        .any(|c| reveals(c) && c.attribute != "class" && c.attribute != "style")
    {
        return "panel";
    }
    if !snapshot.appeared_text.is_empty() {
        return "message";
    }
    if !snapshot.appeared_elements.is_empty() {
        return "content";
    }
    if snapshot.attribute_changes.is_empty()
        && !snapshot.truncated
        && snapshot.side_effects.iter().any(|e| e.kind != "navigation")
    {
        return "side_effect";
    }
    "other"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dom::{AppearedElement, AttributeChange, ModalSnapshot};

    #[test]
    fn classify_modal_open() {
        let snap = InteractionSnapshot {
            appeared_elements: vec![],
            appeared_text: vec![],
            attribute_changes: vec![],
            modal_opened: Some(ModalSnapshot {
                selector: "dialog#edit".into(),
                title: Some("Edit User".into()),
                form_fields: vec![],
                buttons: vec![],
            }),
            side_effects: vec![],
            truncated: false,
        };
        assert!(matches!(
            classify_mutation(&snap),
            TransitionType::ModalOpen
        ));
    }

    #[test]
    fn classify_accordion_toggle() {
        let snap = InteractionSnapshot {
            appeared_elements: vec![],
            appeared_text: vec![],
            attribute_changes: vec![AttributeChange {
                selector: "button.accordion".into(),
                attribute: "aria-expanded".into(),
                old_value: Some("false".into()),
                new_value: Some("true".into()),
            }],
            modal_opened: None,
            side_effects: vec![],
            truncated: false,
        };
        assert!(matches!(
            classify_mutation(&snap),
            TransitionType::AccordionToggle
        ));
    }

    #[test]
    fn classify_tab_switch() {
        let snap = InteractionSnapshot {
            appeared_elements: vec![],
            appeared_text: vec![],
            attribute_changes: vec![AttributeChange {
                selector: "[role=tab]".into(),
                attribute: "aria-selected".into(),
                old_value: Some("false".into()),
                new_value: Some("true".into()),
            }],
            modal_opened: None,
            side_effects: vec![],
            truncated: false,
        };
        assert!(matches!(
            classify_mutation(&snap),
            TransitionType::TabSwitch
        ));
    }

    #[test]
    fn classify_generic_change() {
        let snap = InteractionSnapshot {
            appeared_elements: vec![AppearedElement {
                selector: "div.panel".into(),
                tag: "div".into(),
                role: None,
                label: None,
                element_kind: "container".into(),
            }],
            appeared_text: vec![],
            attribute_changes: vec![],
            modal_opened: None,
            side_effects: vec![],
            truncated: false,
        };
        assert!(matches!(
            classify_mutation(&snap),
            TransitionType::ViewStateChange
        ));
    }

    fn attr(
        selector: &str,
        attribute: &str,
        old: Option<&str>,
        new: Option<&str>,
    ) -> AttributeChange {
        AttributeChange {
            selector: selector.into(),
            attribute: attribute.into(),
            old_value: old.map(str::to_string),
            new_value: new.map(str::to_string),
        }
    }

    #[test]
    fn describe_dom_change_names_common_reveals() {
        let attrs = |changes: Vec<AttributeChange>| InteractionSnapshot {
            attribute_changes: changes,
            ..Default::default()
        };
        let describe_attr =
            |selector: &str, attribute: &str, old: Option<&str>, new: Option<&str>| {
                describe_dom_change(&attrs(vec![attr(selector, attribute, old, new)]))
            };

        assert_eq!(
            describe_attr("#sidenav", "class", Some("drawer"), Some("drawer open")),
            "menu"
        );
        assert_eq!(
            describe_attr("#faq-1", "aria-expanded", Some("false"), Some("true")),
            "panel"
        );
        assert_eq!(
            describe_attr(
                "button[role=\"tab\"]",
                "aria-selected",
                Some("false"),
                Some("true")
            ),
            "tab"
        );
        // A pre-rendered dialog revealed by removing `hidden`.
        assert_eq!(
            describe_attr("#fixture-modal", "hidden", Some(""), None),
            "modal"
        );
        // A cosmetic class change on the trigger itself is not a reveal.
        assert_eq!(
            describe_attr("button.like", "class", Some("like"), Some("like active")),
            "other"
        );

        let toast = InteractionSnapshot {
            appeared_elements: vec![AppearedElement {
                selector: "div.toast".into(),
                tag: "div".into(),
                role: Some("status".into()),
                label: None,
                element_kind: "container".into(),
            }],
            ..Default::default()
        };
        assert_eq!(describe_dom_change(&toast), "toast");

        let modal = InteractionSnapshot {
            modal_opened: Some(ModalSnapshot {
                selector: "dialog#edit".into(),
                title: None,
                form_fields: vec![],
                buttons: vec![],
            }),
            ..Default::default()
        };
        assert_eq!(describe_dom_change(&modal), "modal");

        let clipboard = InteractionSnapshot {
            side_effects: vec![crate::types::dom::InteractionSideEffect {
                kind: "clipboard_write".into(),
                count: 1,
                before: None,
                after: None,
            }],
            ..Default::default()
        };
        assert_eq!(describe_dom_change(&clipboard), "side_effect");

        let err_toast = InteractionSnapshot {
            appeared_text: vec![crate::types::dom::AppearedText {
                selector: "div[data-slot='toast']".into(),
                text: "Setting not saved".into(),
                kind: "error".into(),
                is_toast: true,
                in_form: false,
                has_error_action: true,
            }],
            ..Default::default()
        };
        assert_eq!(describe_dom_change(&err_toast), "error_toast");
    }
}
