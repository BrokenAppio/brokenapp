use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Context, Result};
use chromiumoxide::cdp::js_protocol::{profiler, runtime};
use serde::{Deserialize, Serialize};

use crate::browser::PageClient;
use crate::types::dom::{
    BoundingBox, ElementSourceCapture, ElementType, InteractiveElement, LocatorKind,
    LocatorStrategy, SelectOption, SourceFrame,
};
use crate::types::graph::ViewId;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsElementInfo {
    selector: String,
    label: Option<String>,
    tag: String,
    role: Option<String>,
    dom_path_locator: Option<String>,
    test_selector: Option<String>,
    id_selector: Option<String>,
    aria_selector: Option<String>,
    name_selector: Option<String>,
    role_selector: Option<String>,
    class_selector: Option<String>,
    structural_selector: Option<String>,
    href: Option<String>,
    input_type: Option<String>,
    name: Option<String>,
    required: Option<bool>,
    checked: Option<bool>,
    accept: Option<String>,
    options: Option<Vec<JsOption>>,
    form_submit: Option<bool>,
    bbox: Option<JsBbox>,
    aria_haspopup: Option<String>,
    #[allow(dead_code)]
    aria_expanded: Option<String>,
    in_nav: Option<bool>,
    disabled: Option<bool>,
    empty_required_fields_in_form: Option<u32>,
    #[serde(default, deserialize_with = "lenient_source")]
    source: Option<JsSourceCapture>,
}

/// A malformed source capture drops only that element's capture, never the
/// whole discovery result.
fn lenient_source<'de, D>(deserializer: D) -> std::result::Result<Option<JsSourceCapture>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

/// Browser-side source evidence (see `sourceFor` in the discovery script).
/// Every field is lenient so a malformed capture never fails discovery.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsSourceCapture {
    #[serde(default)]
    frames: Vec<JsSourceFrame>,
    #[serde(default)]
    handlers: Vec<String>,
    #[serde(default)]
    annotated: Option<String>,
    /// Index into the page's handler-function array (`__BROKENAPP_HANDLER_FNS`).
    #[serde(default)]
    handler_slot: Option<usize>,
    #[serde(default)]
    handler_prop: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct JsSourceFrame {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    line: Option<f64>,
    #[serde(default)]
    col: Option<f64>,
}

#[derive(Debug, Deserialize, Clone)]
struct JsOption {
    label: String,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JsBbox {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

/// Core JavaScript that defines `discoverIn(root)`. The function discovers all
/// interactive elements inside `root` (an Element or document.body) and returns
/// an array of element-info objects.
///
/// **Scoping rule:** Element enumeration (`querySelectorAll` for selectors,
/// click-handler attributes, and cursor-pointer scanning) is performed on
/// `root`. Page-level lookups that must reach outside the subtree (e.g.
/// `document.querySelector('label[for="…"]')` and uniqueness checks via
/// `document.querySelectorAll`) intentionally remain on `document`.
const DISCOVER_ELEMENTS_BODY: &str = r#"
  function isVisible(el) {
    try {
      const style = window.getComputedStyle(el);
      if (!style || style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
      const r = el.getBoundingClientRect();
      return r && r.width > 0 && r.height > 0;
    } catch (_) {
      return false;
    }
  }

  function cleanText(s) {
    const t = String(s || '').replace(/\s+/g, ' ').trim();
    if (!t) return null;
    const hasAlnum = /[a-z0-9]/i.test(t);
    const repCount = (t.match(/\uFFFD/g) || []).length; // replacement char from broken glyphs
    if (!hasAlnum && t.length <= 4) return null;
    if (repCount > 0 && t.length <= 16) return null;
    return t.slice(0, 200);
  }

  function normLabel(s) {
    return String(s || '').replace(/\s+/g, ' ').trim().toLowerCase();
  }

  function isSubmitLikeLabel(s) {
    const t = normLabel(s);
    if (!t) return false;
    const good = [
      'save', 'submit', 'create', 'update', 'apply', 'search',
      'log in', 'login', 'sign in', 'send',
      'add', 'attach', 'link', 'unlink', 'import'
    ];
    return good.some(w => t === w || t.startsWith(w + ' '));
  }

  function isBadSubmitLabel(s) {
    const t = normLabel(s);
    if (!t) return true;
    const bad = [
      'reset', 'sort', 'sort by',
      'close', 'cancel',
      // Pagination labels — not submit buttons but handled separately.
      'next', 'previous', 'next page', 'prev',
      'load more', 'show more', 'view more', 'see more',
    ];
    return bad.some(w => t === w || t.startsWith(w + ' '));
  }

  // Text of `el` as an accessible name reads it: words of block-level
  // children (and <br>) are separated (`<strong>WhatsApp</strong>` +
  // `<small style="display:block">Chat export</small>` -> "WhatsApp Chat
  // export"), display:none content is left out, and nested form controls are
  // skipped when `skipControls` is set.
  function nameText(el, skipControls) {
    const parts = [];
    let budget = 400;
    function walk(node) {
      if (budget-- <= 0) return;
      if (node.nodeType === 3) { parts.push(node.nodeValue || ''); return; }
      if (node.nodeType !== 1) return;
      const tag = node.tagName.toLowerCase();
      if (tag === 'script' || tag === 'style' || tag === 'template') return;
      if (tag === 'br') { parts.push(' '); return; }
      if (skipControls && node !== el && (tag === 'input' || tag === 'select' || tag === 'textarea' || tag === 'button')) return;
      let display = 'inline';
      try { display = window.getComputedStyle(node).display || 'inline'; } catch (_) {}
      if (display === 'none' && node !== el) return;
      const block = node !== el && !display.startsWith('inline') && display !== 'contents';
      if (block) parts.push(' ');
      for (const child of node.childNodes) walk(child);
      if (block) parts.push(' ');
    }
    try { walk(el); } catch (_) { return el.textContent || ''; }
    return parts.join('');
  }

  function labelTextFromLabelEl(labelEl) {
    if (!labelEl) return null;
    // Avoid concatenating nested control text (e.g. <label>Occupancy<select>...</select></label>)
    return cleanText(nameText(labelEl, true));
  }

  function queryOne(root, selector) {
    if (!root || typeof selector !== 'string' || !selector.trim()) return null;
    try {
      return root.querySelector(selector);
    } catch (_) {
      return null;
    }
  }

  function queryAll(root, selector) {
    if (!root || typeof selector !== 'string' || !selector.trim()) return [];
    try {
      const out = [];
      if (root.nodeType === 1 && root.matches && root.matches(selector)) out.push(root);
      if (root.querySelectorAll) out.push(...root.querySelectorAll(selector));
      return out;
    } catch (_) {
      return [];
    }
  }

  function elementSearchRoot(el) {
    try {
      const root = el && el.getRootNode ? el.getRootNode() : null;
      if (!root) return document;
      if (root.nodeType === Node.DOCUMENT_NODE) return root;
      if (typeof ShadowRoot !== 'undefined' && root instanceof ShadowRoot) return root;
      return document;
    } catch (_) {
      return document;
    }
  }

  function labelFor(el) {
    const searchRoot = elementSearchRoot(el);
    const aria = el.getAttribute && el.getAttribute('aria-label');
    if (aria) return cleanText(aria);
    const labelledBy = el.getAttribute && el.getAttribute('aria-labelledby');
    if (labelledBy) {
      const text = labelledBy.split(/\s+/)
        .map(id => { try { return searchRoot.getElementById ? searchRoot.getElementById(id) : document.getElementById(id); } catch (_) { return null; } })
        .filter(Boolean)
        .map(n => nameText(n, false))
        .join(' ');
      const t = cleanText(text);
      if (t) return t;
    }
    const title = el.getAttribute && el.getAttribute('title');
    if (title) return cleanText(title);

    // Prefer associated label if available.
    try {
      const id = el.getAttribute && el.getAttribute('id');
      if (id) {
        const labelEl = queryOne(searchRoot, `label[for="${CSS.escape(id)}"]`);
        const t = labelTextFromLabelEl(labelEl);
        if (t) return t;
      }
      if (el.closest) {
        const wrapping = el.closest('label');
        const t = labelTextFromLabelEl(wrapping);
        if (t) return t;
      }
    } catch (_) {}

    const placeholder = el.getAttribute && el.getAttribute('placeholder');
    if (placeholder) return cleanText(placeholder);

    // As a last resort, use element text (filtered to avoid icon/emoji noise).
    return cleanText(nameText(el, false));
  }

  function cssEscape(str) {
    // Minimal escape for attribute selectors.
    return String(str).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }

  function uniqueWithin(root, sel) {
    try { return queryAll(root, sel).length === 1; } catch (_) { return false; }
  }

  function selectorFor(el, root) {
    const locators = locatorCandidates(el, root || elementSearchRoot(el));
    return locators.testSelector
      || locators.idSelector
      || locators.ariaSelector
      || locators.nameSelector
      || locators.roleSelector
      || locators.classSelector
      || locators.structuralSelector;
  }

  function structuralSelectorFor(el) {
    const parts = [];
    let cur = el;
    for (let i = 0; i < 6 && cur && cur.nodeType === 1; i++) {
      const tag = cur.tagName.toLowerCase();
      const parent = cur.parentElement;
      if (!parent) { parts.unshift(tag); break; }
      const siblings = Array.from(parent.children).filter(c => c.tagName.toLowerCase() === tag);
      const idx = siblings.indexOf(cur) + 1;
      parts.unshift(`${tag}:nth-of-type(${idx})`);
      cur = parent;
    }
    return parts.join(" > ");
  }

  function stableClasses(el) {
    const cls = (el.getAttribute && el.getAttribute("class")) || "";
    return cls
      .split(/\s+/)
      .filter(Boolean)
      .filter(c => !/^(active|selected|open|show|visible|hidden|hover|focus)/i.test(c))
      .slice(0, 3);
  }

  function locatorCandidates(el, root) {
    const tag = el.tagName ? el.tagName.toLowerCase() : "";
    const scope = root || elementSearchRoot(el);
    const out = {
      domPathLocator: null,
      testSelector: null,
      idSelector: null,
      ariaSelector: null,
      nameSelector: null,
      roleSelector: null,
      classSelector: null,
      structuralSelector: structuralSelectorFor(el),
    };

    const attrCandidates = ["data-testid", "data-cy", "data-test", "data-qa"];
    for (const a of attrCandidates) {
      const v = el.getAttribute && el.getAttribute(a);
      if (!v) continue;
      const sel = `[${a}="${cssEscape(v)}"]`;
      if (uniqueWithin(scope, sel)) {
        out.testSelector = sel;
        break;
      }
    }

    const id = el.getAttribute && el.getAttribute("id");
    if (id) {
      const sel = `#${CSS.escape(id)}`;
      if (uniqueWithin(scope, sel)) out.idSelector = sel;
    }

    const aria = el.getAttribute && el.getAttribute("aria-label");
    if (aria) {
      const sel = `${tag}[aria-label="${cssEscape(aria)}"]`;
      if (uniqueWithin(scope, sel)) out.ariaSelector = sel;
    }

    const name = el.getAttribute && el.getAttribute("name");
    if (name) {
      const sel = `${tag}[name="${cssEscape(name)}"]`;
      if (uniqueWithin(scope, sel)) out.nameSelector = sel;
    }

    const role = el.getAttribute && el.getAttribute("role");
    if (role) {
      const sel = `${tag}[role="${cssEscape(role)}"]`;
      if (uniqueWithin(scope, sel)) out.roleSelector = sel;
    }

    const classes = stableClasses(el);
    if (classes.length) {
      const sel = `${tag}.${classes.map(c => CSS.escape(c)).join('.')}`;
      if (uniqueWithin(scope, sel)) out.classSelector = sel;
    }

    return out;
  }

  function domPathFor(el) {
    const segments = [];
    let current = el;
    let nextEnter = 'none';
    let depth = 0;

    while (current && depth < 8) {
      depth++;
      const root = elementSearchRoot(current);
      const selector = selectorFor(current, root);
      if (!selector) return null;
      segments.push({ selector, enter: nextEnter });

      if (typeof ShadowRoot !== 'undefined' && root instanceof ShadowRoot && root.host) {
        current = root.host;
        nextEnter = 'shadow';
        continue;
      }

      const doc = root && root.nodeType === Node.DOCUMENT_NODE ? root : (current.ownerDocument || document);
      const frameEl = doc && doc.defaultView ? doc.defaultView.frameElement : null;
      if (frameEl) {
        current = frameEl;
        nextEnter = 'frame';
        continue;
      }

      break;
    }

    segments.reverse();
    return { segments };
  }

  // Framework dev overlays (Next dev tools / error overlay, Astro toolbar,
  // Vite error overlay) render controls in shadow roots or portal elements;
  // they are not part of the application UI.
  const devToolHosts = new Set([
    'nextjs-portal',
    'astro-dev-toolbar',
    'astro-dev-overlay',
    'vite-error-overlay',
    'vite-plugin-checker-error-overlay',
    'nuxt-devtools-container'
  ]);

  const devOverlaySelector = [
    'nextjs-portal',
    '#nextjs__container_errors_label',
    '[data-nextjs-dialog]',
    '[data-nextjs-dialog-overlay]',
    '[data-nextjs-toast]',
    '[data-nextjs-error-overlay]',
    'vite-error-overlay',
    'vite-plugin-checker-error-overlay',
    'astro-dev-toolbar',
    'astro-dev-overlay',
    'nuxt-devtools-container'
  ].join(',');

  function isDevToolHost(node) {
    try {
      return !!(node && node.tagName && devToolHosts.has(node.tagName.toLowerCase()));
    } catch (_) {
      return false;
    }
  }

  function isInsideDevOverlay(node) {
    try {
      let cur = node;
      for (let depth = 0; cur && depth < 32; depth++) {
        if (cur.nodeType === 1) {
          if (isDevToolHost(cur)) return true;
          if (cur.matches && cur.matches(devOverlaySelector)) return true;
          if (cur.closest && cur.closest(devOverlaySelector)) return true;
          const root = cur.getRootNode ? cur.getRootNode() : null;
          if (typeof ShadowRoot !== 'undefined' && root instanceof ShadowRoot && root.host) {
            cur = root.host;
            continue;
          }
          break;
        }
        if (typeof ShadowRoot !== 'undefined' && cur instanceof ShadowRoot && cur.host) {
          cur = cur.host;
          continue;
        }
        break;
      }
    } catch (_) {}
    return false;
  }

  function enumerateQueryRoots(startRoot) {
    const out = [];
    const queue = [startRoot];
    const seen = new Set();
    let scanned = 0;

    while (queue.length && out.length < 64 && scanned < 20000) {
      const root = queue.shift();
      if (!root || seen.has(root) || isInsideDevOverlay(root)) continue;
      seen.add(root);
      out.push(root);

      let nodes = [];
      try {
        if (root.nodeType === 1) nodes.push(root);
        if (root.querySelectorAll) {
          nodes.push(...Array.from(root.querySelectorAll('*')).slice(0, 5000));
        }
      } catch (_) {
        nodes = [];
      }

      scanned += nodes.length;

      for (const node of nodes) {
        try {
          if (isDevToolHost(node) || isInsideDevOverlay(node)) continue;
          if (node.shadowRoot) queue.push(node.shadowRoot);
          if (node.tagName && node.tagName.toLowerCase() === 'iframe') {
            try {
              const frameDoc = node.contentDocument || (node.contentWindow && node.contentWindow.document) || null;
              if (frameDoc) queue.push(frameDoc);
            } catch (_) {}
          }
        } catch (_) {}
      }
    }

    return out;
  }

  function bbox(el) {
    try {
      const r = el.getBoundingClientRect();
      return { x: r.x, y: r.y, width: r.width, height: r.height };
    } catch (_) { return null; }
  }

  // --- Source capture (React 19 _debugStack, React 18 _debugSource, Astro/Svelte/Vue/Angular dev metadata) ---
  // Everything here is best-effort: any failure yields `source: null`.
  const sourceOwnerMemo = new Map();
  // Handler functions whose definition site is looked up over CDP afterwards
  // (`[[FunctionLocation]]`); exposed by the main discovery wrapper only.
  const sourceHandlerFns = [];
  const sourceHandlerIndex = new Map();
  const primaryHandlerProps = ['onClick', 'onSubmit', 'onChange', 'onInput', 'onPointerDown', 'onMouseDown', 'onKeyDown'];

  function handlerSlot(fn) {
    let slot = sourceHandlerIndex.get(fn);
    if (slot === undefined) {
      if (sourceHandlerFns.length >= 200) return null;
      slot = sourceHandlerFns.length;
      sourceHandlerFns.push(fn);
      sourceHandlerIndex.set(fn, slot);
    }
    return slot;
  }

  // Parse one V8 stack line: `at fn (url:line:col)` or `at url:line:col`.
  function parseStackLine(line) {
    let body = line.trim();
    if (!body.startsWith('at ')) return null;
    body = body.slice(3).trim();
    if (body.startsWith('async ')) body = body.slice(6);
    let fn = null;
    let loc = body;
    if (body.endsWith(')')) {
      const open = body.indexOf(' (');
      if (open !== -1) {
        fn = body.slice(0, open);
        loc = body.slice(open + 2, -1);
      }
    }
    const m = /^(.*):(\d+):(\d+)$/.exec(loc);
    if (!m) return null;
    const url = m[1];
    if (!url || url.indexOf('<anonymous>') !== -1 || url === 'native' || url.startsWith('eval at') || url.startsWith('node:')) return null;
    return { fn, url, line: Number(m[2]), col: Number(m[3]) };
  }

  // First call-site frame of a React debug stack (`Error('react-stack-top-frame')`):
  // skip the message line and the JSX runtime frame (jsxDEV / createElement /
  // fakeJSXCallSite), stop at React's bottom frame.
  function debugStackTop(stack) {
    let text = null;
    try { text = typeof stack === 'string' ? stack : (stack && stack.stack); } catch (_) { return null; }
    if (typeof text !== 'string' || !text) return null;
    const lines = text.split('\n', 16);
    let i = /^\s*at\s/.test(lines[0] || '') ? 1 : 2;
    for (; i < lines.length; i++) {
      if (lines[i].indexOf('react_stack_bottom_frame') !== -1 || lines[i].indexOf('react-stack-bottom-frame') !== -1) break;
      const frame = parseStackLine(lines[i]);
      if (frame) return frame;
    }
    return null;
  }

  // React 18 dev `_debugSource`: `{ fileName, lineNumber, columnNumber }`.
  function debugSourceFrame(src) {
    try {
      if (!src || typeof src !== 'object') return null;
      const file = typeof src.fileName === 'string' ? src.fileName.trim() : '';
      const line = Number(src.lineNumber);
      if (!file || !(line > 0)) return null;
      const url = file.startsWith('/') ? 'file://' + file : file;
      const col = Number(src.columnNumber);
      return { fn: null, url, line, col: col > 0 ? col : 0 };
    } catch (_) {
      return null;
    }
  }

  // Server component infos also carry the raw `[name, file, line, col, ...]` stack.
  function rawStackTop(stack) {
    if (!Array.isArray(stack)) return null;
    for (const entry of stack.slice(0, 8)) {
      if (!Array.isArray(entry) || entry[6] === true) continue;
      const file = typeof entry[1] === 'string' ? entry[1] : '';
      const line = Number(entry[2]);
      if (!file || !(line > 0)) continue;
      const url = file.startsWith('/') ? 'file://' + file : file;
      return { fn: typeof entry[0] === 'string' ? entry[0] : null, url, line, col: Number(entry[3]) || 0 };
    }
    return null;
  }

  function componentName(owner) {
    try {
      if (typeof owner.tag === 'number') {
        const t = owner.type;
        if (!t) return null;
        if (typeof t === 'string') return t;
        return t.displayName || t.name
          || (t.render && (t.render.displayName || t.render.name))
          || (t.type && (t.type.displayName || t.type.name))
          || null;
      }
      return typeof owner.name === 'string' ? owner.name : null;
    } catch (_) { return null; }
  }

  function frameEnv(url) {
    const m = /^(?:about|rsc):\/\/React\/([^/]+)\//.exec(url || '');
    return m ? m[1] : null;
  }

  // Owner creation site, memoized per owner object (owners repeat a lot).
  function ownerInfo(owner) {
    const hit = sourceOwnerMemo.get(owner);
    if (hit) return hit;
    let info = { name: null, env: null, frame: null, next: null };
    try {
      const isFiber = typeof owner.tag === 'number';
      info.name = componentName(owner);
      if (isFiber) {
        info.frame = debugStackTop(owner._debugStack) || debugSourceFrame(owner._debugSource);
        info.next = owner._debugOwner || null;
      } else {
        info.env = typeof owner.env === 'string' ? owner.env : null;
        info.frame = debugStackTop(owner.debugStack) || rawStackTop(owner.stack);
        info.next = owner.owner || null;
      }
    } catch (_) {}
    sourceOwnerMemo.set(owner, info);
    return info;
  }

  function sourceFrame(role, owner, env, f) {
    return {
      role,
      owner: owner || null,
      env: env || frameEnv(f.url),
      url: String(f.url).slice(0, 1024),
      line: f.line,
      col: f.col
    };
  }

  // Vue 3 dev mode: walk `el.__vueParentComponent` (and `.parent`) for `comp.type.__file`.
  function vueSourceAnnotation(el) {
    try {
      let comp = el && el.__vueParentComponent ? el.__vueParentComponent : null;
      for (let p = el && el.parentElement, hops = 0; !comp && p && hops < 6; p = p.parentElement, hops++) {
        if (p.__vueParentComponent) comp = p.__vueParentComponent;
      }
      const seen = new Set();
      for (let depth = 0; comp && depth < 16; depth++) {
        if (seen.has(comp)) break;
        seen.add(comp);
        const t = comp.type;
        const raw = t && typeof t.__file === 'string' ? t.__file.trim() : '';
        if (raw && raw.indexOf('node_modules') === -1) {
          const clean = raw.split('?')[0].trim();
          if (clean) return /:\d+(?::\d+)?$/.test(clean) ? clean : clean + ':1';
        }
        comp = comp.parent || null;
      }
    } catch (_) {}
    return null;
  }

  function parseFileSpec(spec) {
    if (typeof spec !== 'string') return null;
    let path = spec.trim();
    if (!path) return null;
    let line = 1;
    let col = 0;
    const m2 = /^(.*):(\d+):(\d+)$/.exec(path);
    const m1 = !m2 ? /^(.*):(\d+)$/.exec(path) : null;
    if (m2 && Number(m2[2]) > 0) {
      path = m2[1];
      line = Number(m2[2]);
      col = Number(m2[3]) || 0;
    } else if (m1 && Number(m1[2]) > 0) {
      path = m1[1];
      line = Number(m1[2]);
    }
    path = path.trim();
    if (!path) return null;
    const url = path.startsWith('/') ? 'file://' + path : path;
    return { url, line, col };
  }

  function angularCtorFrame(ctor) {
    try {
      if (!ctor) return null;
      const cmp = ctor.ɵcmp || null;
      const dbg = cmp && cmp.debugInfo ? cmp.debugInfo : null;
      const owner = (dbg && typeof dbg.className === 'string' && dbg.className)
        || (typeof ctor.name === 'string' && ctor.name !== 'Object' ? ctor.name : null);
      if (dbg && typeof dbg.filePath === 'string' && dbg.filePath.trim()) {
        const file = dbg.filePath.trim();
        const url = file.startsWith('/') ? 'file://' + file : file;
        const lineNum = Number(dbg.lineNumber);
        return { owner, frame: { fn: owner, url, line: lineNum > 0 ? lineNum : 1, col: 0 } };
      }
      const src = ctor.__source;
      if (typeof src === 'string') {
        const parsed = parseFileSpec(src);
        if (parsed) return { owner, frame: { fn: owner, url: parsed.url, line: parsed.line, col: parsed.col } };
      } else if (src && typeof src === 'object') {
        const file = typeof src.filePath === 'string' ? src.filePath
          : (typeof src.file === 'string' ? src.file : (typeof src.fileName === 'string' ? src.fileName : ''));
        if (file.trim()) {
          const clean = file.trim();
          const url = clean.startsWith('/') ? 'file://' + clean : clean;
          const lineNum = Number(src.lineNumber || src.line);
          const colNum = Number(src.columnNumber || src.col);
          return { owner, frame: { fn: owner, url, line: lineNum > 0 ? lineNum : 1, col: colNum > 0 ? colNum : 0 } };
        }
      }
    } catch (_) {}
    return null;
  }

  // Angular dev mode (`window.ng`): capture component constructor + Angular 17+ `ɵcmp.debugInfo` or `__source`.
  function collectAngularFrames(el, outFrames) {
    try {
      const ng = window.ng;
      if (!ng || (typeof ng.getComponent !== 'function' && typeof ng.getOwningComponent !== 'function')) return;
      const seen = new Set();
      const comps = [];
      const pushComp = (c) => {
        if (c && typeof c === 'object' && !seen.has(c)) {
          seen.add(c);
          comps.push(c);
        }
      };
      if (typeof ng.getComponent === 'function') {
        try { pushComp(ng.getComponent(el)); } catch (_) {}
      }
      if (typeof ng.getOwningComponent === 'function') {
        try { pushComp(ng.getOwningComponent(el)); } catch (_) {}
      }
      if (typeof ng.getHostElement === 'function' && typeof ng.getOwningComponent === 'function') {
        let cur = comps.length ? comps[comps.length - 1] : null;
        for (let i = 0; cur && comps.length < 6 && i < 6; i++) {
          let host = null;
          try { host = ng.getHostElement(cur); } catch (_) {}
          if (!host) break;
          let next = null;
          try { next = ng.getOwningComponent(host); } catch (_) {}
          if (!next || seen.has(next)) break;
          pushComp(next);
          cur = next;
        }
      }
      let added = 0;
      for (const comp of comps) {
        const info = angularCtorFrame(comp.constructor);
        if (info && info.frame) {
          outFrames.push(sourceFrame(added === 0 ? 'render' : 'owner', info.owner, null, info.frame));
          added++;
        }
      }
    } catch (_) {}
  }

  function sourceFor(el) {
    try {
      const out = { frames: [], handlers: [], annotated: null };

      // Astro dev annotations (live, or stashed before the dev toolbar strips them),
      // then Svelte dev metadata, then Vue 3 dev `__file` metadata.
      let file = el.getAttribute && el.getAttribute('data-astro-source-file');
      let loc = el.getAttribute && el.getAttribute('data-astro-source-loc');
      if (!file) {
        const stash = window.__BROKENAPP_SOURCE_ANN;
        const rec = stash && typeof stash.get === 'function' ? stash.get(el) : null;
        if (rec && rec.file) { file = rec.file; loc = rec.loc || null; }
      }
      if (file) {
        out.annotated = loc ? file + ':' + loc : file;
      } else if (el.__svelte_meta && el.__svelte_meta.loc && el.__svelte_meta.loc.file) {
        const l = el.__svelte_meta.loc;
        out.annotated = l.file + ':' + l.line + ':' + ((Number(l.column) || 0) + 1);
      } else {
        const vueAnn = vueSourceAnnotation(el);
        if (vueAnn) out.annotated = vueAnn;
      }

      let fiber = null;
      let props = null;
      const keys = Object.keys(el);
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        if (fiber === null && k.startsWith('__reactFiber$')) fiber = el[k];
        else if (props === null && k.startsWith('__reactProps$')) props = el[k];
      }

      if (fiber) {
        let owner = fiber._debugOwner || null;
        const host = debugStackTop(fiber._debugStack) || debugSourceFrame(fiber._debugSource);
        if (host) out.frames.push(sourceFrame('render', owner ? ownerInfo(owner).name : host.fn, null, host));
        for (let n = 0; owner && n < 6; n++) {
          const info = ownerInfo(owner);
          if (info.frame) out.frames.push(sourceFrame('owner', info.name, info.env, info.frame));
          owner = info.next;
        }
      } else if (!out.annotated) {
        collectAngularFrames(el, out.frames);
      }

      if (props && typeof props === 'object') {
        for (const k in props) {
          if (out.handlers.length >= 16) break;
          if (k.length > 2 && k[0] === 'o' && k[1] === 'n' && k[2] >= 'A' && k[2] <= 'Z' && typeof props[k] === 'function') {
            out.handlers.push(k);
          }
        }
        if (fiber && out.handlers.length) {
          const prop = primaryHandlerProps.find(k => typeof props[k] === 'function') || out.handlers[0];
          const slot = handlerSlot(props[prop]);
          if (slot !== null) {
            out.handlerProp = prop;
            out.handlerSlot = slot;
          }
        }
      }

      if (!out.frames.length && !out.handlers.length && !out.annotated) return null;
      return out;
    } catch (_) {
      return null;
    }
  }

  const selectors = [
    'a',
    'button',
    'input',
    'select',
    'textarea',
    '[role="button"]',
    '[role="link"]',
    '[role="tab"]',
    '[role="menuitem"]',
    '[role="checkbox"]',
    '[role="radio"]',
    '[role="switch"]',
    '[role="combobox"]',
    '[role="searchbox"]',
    '[aria-haspopup]',
    'summary'
  ];

  const clickableAncestorSelector = 'a,button,[role="button"],[role="link"],[role="tab"],[role="menuitem"]';
  // Containers whose plain descendants are part of the same click target.
  const pointerContainerSelector = clickableAncestorSelector + ',summary,label,[role="option"],[onclick]';

  function hasExplicitClickHandler(el) {
    if (!el) return false;
    if (el.getAttribute && el.getAttribute('onclick')) return true;
    const role = el.getAttribute && el.getAttribute('role');
    if (role && ['button','link','tab','menuitem','checkbox','radio','switch','combobox','searchbox'].includes(role)) return true;
    const tab = el.getAttribute && el.getAttribute('tabindex');
    if (tab && tab !== '-1') return true;
    return false;
  }

  function isInsideClickableContainer(el, selector) {
    if (!el || !el.closest) return false;
    const parent = el.closest(selector || clickableAncestorSelector);
    return !!(parent && parent !== el);
  }

  function discoverIn(root) {
    const seen = new Set();
    const pushed = new Set();
    const elements = [];

    // Inside an element already discovered as a control (or a clickable
    // container): a row's text spans, a label's caption, a summary's icon.
    function insideDiscovered(el) {
      for (let p = el.parentElement, i = 0; p && i < 12; p = p.parentElement, i++) {
        if (pushed.has(p)) return true;
      }
      return false;
    }

    function labelledToggle(el) {
      try {
        const type = String(el.type || '').toLowerCase();
        if (el.tagName !== 'INPUT' || (type !== 'checkbox' && type !== 'radio')) return false;
        if (!el.labels) return false;
        const visibleLabels = Array.from(el.labels).filter(isVisible);
        if (!visibleLabels.length) return false;
        // Headless UI / Base UI / Radix switches render a visible button or ARIA
        // switch/checkbox alongside a visually-hidden backing <input>. Keep only
        // the visible control so the hidden backing input does not fail as obscured.
        const hasVisibleProxy = visibleLabels.some(lbl => {
          try {
            return Array.from(
              lbl.querySelectorAll('button, [role="switch"], [role="checkbox"], [role="radio"]')
            ).some(p => p !== el && isVisible(p));
          } catch (_) {
            return false;
          }
        });
        return !hasVisibleProxy;
      } catch (_) {
        return false;
      }
    }

    function push(el) {
      // Never capture controls inside framework dev/error overlays
      // (Next.js error dialog/toast, Vite error overlay, Astro toolbar, etc.)
      // or inside inert subtrees (background content behind active modals).
      if (!el || isInsideDevOverlay(el)) return;
      if (el.closest && el.closest('[inert]')) return;
      // A visually hidden native checkbox/radio styled through its label is
      // still the control (the label is what gets clicked).
      if (!(isVisible(el) || labelledToggle(el))) return;
      const tag = el.tagName ? el.tagName.toLowerCase() : '';

      // Drop SVG internals / decorative nodes unless they are explicitly clickable.
      if ((tag === 'path' || tag === 'circle') && !hasExplicitClickHandler(el)) return;
      if ((tag === 'svg' || tag === 'g') && !hasExplicitClickHandler(el)) return;

      // Prefer capturing the actual button/link, not its internal span/svg children.
      if ((tag === 'span' || tag === 'div' || tag === 'svg' || tag === 'path' || tag === 'circle') && isInsideClickableContainer(el)) return;

      const searchRoot = elementSearchRoot(el);
      const locators = locatorCandidates(el, searchRoot);
      const sel = selectorFor(el, searchRoot);
      if (!sel) return;

      const domPath = domPathFor(el);
      const domPathLocator = domPath && domPath.segments && domPath.segments.length > 1
        ? JSON.stringify(domPath)
        : null;
      const seenKey = domPathLocator || sel;
      if (seen.has(seenKey)) return;
      seen.add(seenKey);
      pushed.add(el);

      const role = el.getAttribute && el.getAttribute("role");
      const href = tag === "a" ? (el.getAttribute("href") || null) : null;
      const inputType = tag === "input" ? (el.getAttribute("type") || "text") : null;
      const name = el.getAttribute && el.getAttribute("name");
      const required = el.required === true;
      const checked = (tag === "input" && (inputType === "checkbox" || inputType === "radio")) ? (el.checked === true) : null;
      const accept = (tag === "input" && inputType === "file") ? (el.getAttribute("accept") || null) : null;
      const label = labelFor(el);
      let options = null;
      if (tag === "select") {
        options = Array.from(el.options || []).slice(0, 200).map(o => ({ label: (o.label || o.text || "").trim(), value: o.value || null }));
      }
      const typeAttr = (tag === "button" ? (el.getAttribute("type") || "") : "").toLowerCase();
      const inForm = !!(el.closest && el.closest("form"));
      let formSubmit = false;
      if (inForm) {
        const isButtonLike =
          tag === "button" ||
          (tag === "input" && (inputType === "submit" || inputType === "image" || inputType === "button")) ||
          role === "button";

        if (isButtonLike) {
          const isExplicit =
            (tag === "button" && (typeAttr === "" || typeAttr === "submit")) ||
            (tag === "input" && (inputType === "submit" || inputType === "image"));
          if (isExplicit) {
            formSubmit = true;
          } else if (isSubmitLikeLabel(label) && !isBadSubmitLabel(label)) {
            formSubmit = true;
          }
        }
      }
      const ariaHaspopup = el.getAttribute('aria-haspopup') || null;
      const ariaExpanded = el.getAttribute('aria-expanded') || null;
      const inNav = !!(el.closest && (el.closest('nav') || el.closest('[role="navigation"]')));
      const disabled = !!(el.disabled || (el.getAttribute && el.getAttribute('aria-disabled') === 'true'));
      const emptyRequiredFieldsInForm = (() => {
        if (!el.closest) return 0;
        const form = el.closest('form');
        if (!form) return 0;
        let count = 0;
        form.querySelectorAll('[required], [aria-required="true"]').forEach(f => {
          if (!f.value) count++;
        });
        return count;
      })();
      elements.push({
        selector: sel,
        label: label,
        tag,
        role: role || null,
        domPathLocator,
        testSelector: locators.testSelector,
        idSelector: locators.idSelector,
        ariaSelector: locators.ariaSelector,
        nameSelector: locators.nameSelector,
        roleSelector: locators.roleSelector,
        classSelector: locators.classSelector,
        structuralSelector: locators.structuralSelector,
        href,
        inputType,
        name: name || null,
        required,
        checked,
        accept,
        options,
        formSubmit,
        bbox: bbox(el),
        ariaHaspopup,
        ariaExpanded,
        inNav,
        disabled,
        emptyRequiredFieldsInForm,
        source: sourceFor(el)
      });
    }

    for (const scope of enumerateQueryRoots(root)) {
      queryAll(scope, selectors.join(",")).forEach(push);

      // Framework-specific click handler attributes. Some of these require escaping.
      for (const sel of ['[onclick]', '[ng-click]', '[v-on\\:click]', '[\\@click]']) {
        queryAll(scope, sel).forEach(push);
      }

      // Clickable-looking elements (cursor pointer). `cursor` is inherited:
      // only the outermost element of a pointer subtree is a control (a
      // clickable row, not each cell and span inside it).
      Array.from(queryAll(scope, '*')).slice(0, 5000).forEach(el => {
        try {
          const style = window.getComputedStyle(el);
          if (!style || style.cursor !== 'pointer') return;
          const tag = el.tagName ? el.tagName.toLowerCase() : '';
          if (tag === 'path' || tag === 'circle' || tag === 'svg' || tag === 'g') return;
          if (isInsideClickableContainer(el, pointerContainerSelector)) return;
          if (insideDiscovered(el)) return;
          const parent = el.parentElement;
          if (parent && parent !== root && window.getComputedStyle(parent).cursor === 'pointer') return;
          // A label whose control was discovered is that control's caption.
          if (tag === 'label' && el.control && pushed.has(el.control)) return;
          push(el);
        } catch (_) {}
      });
    }

    return elements.slice(0, 5000);
  }

  function isToastDialog(el) {
    if (!el || el.nodeType !== 1) return false;
    const slot = ((el.getAttribute && el.getAttribute('data-slot')) || '').toLowerCase();
    const cls = ((el.className && typeof el.className === 'string') ? el.className : '').toLowerCase();
    if (el.hasAttribute && (el.hasAttribute('data-sonner-toast') || el.hasAttribute('data-toast'))) return true;
    if (slot.includes('toast') || slot.includes('snackbar')) return true;
    if (el.closest && el.closest('[data-slot*="toast"], [data-radix-toast-viewport]')) return true;
    if (el.querySelector && el.querySelector('[data-slot="toast-close"], [data-slot="toast-description"], [data-slot="toast-title"]')) return true;
    if ((cls.includes('toast') || cls.includes('snackbar') || cls.includes('notistack'))
        && !cls.includes('modal') && !cls.includes('dialog-popup')) return true;
    return false;
  }

  function effectiveZIndex(el) {
    let best = 0;
    let cur = el;
    for (let i = 0; cur && cur.nodeType === 1 && cur !== document.documentElement && i < 20; i++) {
      try {
        const s = window.getComputedStyle(cur);
        const z = parseInt(s.zIndex, 10);
        if (!Number.isNaN(z) && z > best) best = z;
      } catch (_) {}
      cur = cur.parentElement;
    }
    return best;
  }

  function hasInertOrHiddenBackground(dialog) {
    const body = document.body;
    if (!body) return false;
    const vw = window.innerWidth || 1280;
    const vh = window.innerHeight || 800;
    for (const child of Array.from(body.children)) {
      if (!child || child === dialog || child.contains(dialog) || dialog.contains(child)) continue;
      if (isInsideDevOverlay(child)) continue;
      const marked = child.hasAttribute('inert') || child.getAttribute('aria-hidden') === 'true';
      if (!marked) continue;
      try {
        const r = child.getBoundingClientRect();
        const isMainLike = child.tagName === 'MAIN' || child.id === 'root' || child.id === 'app' || child.id === '__next'
          || (r.width >= vw * 0.45 && r.height >= vh * 0.35);
        if (isMainLike) return true;
      } catch (_) {}
    }
    return false;
  }

  function isOverlayBlockingModal(dialog) {
    try {
      if (dialog.tagName === 'DIALOG' && dialog.open && dialog.matches && dialog.matches(':modal')) {
        return true;
      }
    } catch (_) {}

    if (hasInertOrHiddenBackground(dialog)) return true;

    const vw = window.innerWidth || 1280;
    const vh = window.innerHeight || 800;
    let positionedOverlay = false;
    let wrapper = dialog;
    let cur = dialog;
    for (let i = 0; cur && cur.nodeType === 1 && cur !== document.body && cur !== document.documentElement && i < 12; i++) {
      try {
        const s = window.getComputedStyle(cur);
        if (s.position === 'fixed' || s.position === 'absolute') {
          positionedOverlay = true;
          wrapper = cur;
        }
      } catch (_) {}
      cur = cur.parentElement;
    }
    // Inline / static dialogs in document flow (e.g. an embedded order sheet)
    // do not block the rest of the page and must not hide sibling controls.
    if (!positionedOverlay) return false;

    try {
      const r = dialog.getBoundingClientRect();
      if (r.width >= vw * 0.75 && r.height >= vh * 0.75) return true;
    } catch (_) {}

    // Check if viewport corners outside the dialog hit a full-viewport backdrop
    // or modal wrapper, proving background controls are actually obscured.
    const corners = [[8, 8], [vw - 8, 8], [8, vh - 8], [vw - 8, vh - 8]];
    let blockedCorners = 0;
    for (const [cx, cy] of corners) {
      try {
        const hit = document.elementFromPoint(cx, cy);
        if (!hit) continue;
        if (dialog.contains(hit) || wrapper.contains(hit)) {
          blockedCorners++;
          continue;
        }
        let h = hit;
        for (let i = 0; h && h.nodeType === 1 && h !== document.body && i < 8; i++) {
          const hs = window.getComputedStyle(h);
          if (hs.position === 'fixed' || hs.position === 'absolute') {
            const hr = h.getBoundingClientRect();
            if (hr.width >= vw * 0.6 && hr.height >= vh * 0.6) {
              blockedCorners++;
              break;
            }
          }
          h = h.parentElement;
        }
      } catch (_) {}
    }
    if (blockedCorners >= 2) return true;

    return false;
  }

  function findActiveModalRoots() {
    const sel = 'dialog[open], [role="dialog"], [role="alertdialog"], [aria-modal="true"], [data-slot="dialog-popup"], [data-slot="alert-dialog-popup"]';
    const raw = Array.from(document.querySelectorAll(sel));
    const blocking = [];
    for (let idx = 0; idx < raw.length; idx++) {
      const el = raw[idx];
      if (!el || !isVisible(el) || isInsideDevOverlay(el) || isToastDialog(el)) continue;
      if (el.closest && el.closest('[inert]')) continue;
      if (el.getAttribute && el.getAttribute('aria-hidden') === 'true') continue;
      if (!isOverlayBlockingModal(el)) continue;
      blocking.push({ el, idx });
    }
    if (!blocking.length) return [];

    // Drop outer modals that wrap an inner active blocking modal.
    const innermost = blocking.filter(item =>
      !blocking.some(other => other.el !== item.el && item.el.contains(other.el))
    );
    innermost.sort((a, b) => {
      const aNative = (a.el.tagName === 'DIALOG' && a.el.matches && a.el.matches(':modal')) ? 1 : 0;
      const bNative = (b.el.tagName === 'DIALOG' && b.el.matches && b.el.matches(':modal')) ? 1 : 0;
      if (bNative !== aNative) return bNative - aNative;
      const zDiff = effectiveZIndex(b.el) - effectiveZIndex(a.el);
      if (zDiff !== 0) return zDiff;
      return b.idx - a.idx;
    });

    const topModal = innermost[0].el;
    const topZ = effectiveZIndex(topModal);
    const roots = [topModal];

    // Include open visible popovers/menus/select-listboxes portaled above the
    // modal (e.g. Base UI / Radix Select popups) so they remain discoverable.
    const popupSel = '[role="listbox"], [role="menu"], [data-slot*="popover"], [data-slot*="select-content"], [data-radix-popper-content-wrapper]';
    for (const pop of document.querySelectorAll(popupSel)) {
      if (!isVisible(pop) || isInsideDevOverlay(pop)) continue;
      if (pop.closest && pop.closest('[inert]')) continue;
      if (topModal.contains(pop)) continue;
      if (effectiveZIndex(pop) >= topZ) {
        roots.push(pop);
      }
    }
    return roots;
  }
"#;

pub async fn discover_interactive_elements(
    page: &PageClient,
    view_id: &ViewId,
) -> Result<Vec<InteractiveElement>> {
    let script = format!(
        r#"
(() => {{
  {DISCOVER_ELEMENTS_BODY}
  const modalRoots = findActiveModalRoots();
  let found = [];
  if (modalRoots.length > 0) {{
    const dedupe = new Set();
    for (const mr of modalRoots) {{
      for (const item of discoverIn(mr)) {{
        const k = item.domPathLocator || item.selector;
        if (!dedupe.has(k)) {{
          dedupe.add(k);
          found.push(item);
        }}
      }}
    }}
  }}
  if (found.length === 0) {{
    found = discoverIn(document.body || document.documentElement);
  }}
  try {{
    if (sourceHandlerFns.length) {{
      Object.defineProperty(window, '{HANDLER_FNS_GLOBAL}', {{ value: sourceHandlerFns, configurable: true, writable: true }});
    }}
  }} catch (_) {{}}
  return found;
}})()
"#
    );

    let mut js: Vec<JsElementInfo> = page
        .evaluate_json(&script)
        .await
        .context("discover interactive elements")?;

    attach_handler_locations(page, &mut js).await;
    parse_js_elements(js, view_id)
}

/// Page global holding the handler functions collected by discovery.
const HANDLER_FNS_GLOBAL: &str = "__BROKENAPP_HANDLER_FNS";
const HANDLER_OBJECT_GROUP: &str = "brokenapp-handler-locations";
/// Upper bound for the whole handler lookup pass on one page.
const HANDLER_PASS_BUDGET: Duration = Duration::from_millis(1500);
const HANDLER_CLEANUP_TIMEOUT: Duration = Duration::from_millis(500);

/// Look up where each captured React handler prop is defined
/// (`[[FunctionLocation]]` via `Runtime.getProperties`, script URLs via
/// `Profiler.getBestEffortCoverage`) and append a `handler` frame per element.
/// Best-effort and time-boxed: on any failure elements keep their frames.
///
/// Script URLs come from coverage rather than `Debugger.scriptParsed` because
/// chromiumoxide 0.8 cannot decode current Chrome's `scriptParsed` events, and
/// this avoids enabling the debugger (and its pause semantics) on the page.
async fn attach_handler_locations(page: &PageClient, js: &mut [JsElementInfo]) {
    let wanted = js
        .iter()
        .any(|el| el.source.as_ref().is_some_and(|s| s.handler_slot.is_some()));
    if !wanted {
        return;
    }
    let started = std::time::Instant::now();
    let locations = tokio::time::timeout(HANDLER_PASS_BUDGET, handler_function_locations(page))
        .await
        .ok()
        .and_then(|res| {
            res.map_err(|err| tracing::debug!("handler location lookup failed: {err:#}"))
                .ok()
        })
        .unwrap_or_default();

    // Always restore page state, even after a timeout.
    let inner = page.inner();
    let _ = tokio::time::timeout(
        HANDLER_CLEANUP_TIMEOUT,
        inner.execute(profiler::DisableParams::default()),
    )
    .await;
    let _ = tokio::time::timeout(
        HANDLER_CLEANUP_TIMEOUT,
        inner.execute(runtime::ReleaseObjectGroupParams::new(HANDLER_OBJECT_GROUP)),
    )
    .await;
    let _ = tokio::time::timeout(
        HANDLER_CLEANUP_TIMEOUT,
        page.evaluate_json::<bool>(&format!("delete window.{HANDLER_FNS_GLOBAL}")),
    )
    .await;

    tracing::debug!(
        resolved = locations.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "handler locations"
    );
    for el in js.iter_mut() {
        let Some(source) = el.source.as_mut() else {
            continue;
        };
        let Some(slot) = source.handler_slot else {
            continue;
        };
        let Some((url, line, col)) = locations.get(&slot) else {
            continue;
        };
        source.frames.push(JsSourceFrame {
            role: Some("handler".to_string()),
            owner: source.handler_prop.clone(),
            env: None,
            url: Some(url.clone()),
            line: Some(f64::from(*line)),
            col: Some(f64::from(*col)),
        });
    }
}

/// `Runtime.getProperties` with an untyped response: chromiumoxide 0.8's typed
/// `RemoteObject` cannot decode the `internal#location` subtype that carries
/// `[[FunctionLocation]]`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RawGetProperties {
    object_id: String,
    own_properties: bool,
}

impl chromiumoxide::Method for RawGetProperties {
    fn identifier(&self) -> chromiumoxide::types::MethodId {
        "Runtime.getProperties".into()
    }
}

impl chromiumoxide::Command for RawGetProperties {
    type Response = serde_json::Value;
}

/// Map handler slot -> (script URL, 1-based line, 1-based column).
async fn handler_function_locations(
    page: &PageClient,
) -> Result<HashMap<usize, (String, u32, u32)>> {
    let inner = page.inner();
    let array = inner
        .execute(
            runtime::EvaluateParams::builder()
                .expression(format!("window.{HANDLER_FNS_GLOBAL}"))
                .object_group(HANDLER_OBJECT_GROUP)
                .return_by_value(false)
                .build()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .await
        .context("Runtime.evaluate handler array")?;
    let array_id = array
        .result
        .result
        .object_id
        .clone()
        .context("handler array has no object id")?;
    let items = inner
        .execute(
            runtime::GetPropertiesParams::builder()
                .object_id(array_id)
                .own_properties(true)
                .build()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .await
        .context("Runtime.getProperties handler array")?;

    let mut raw: Vec<(usize, String, u32, u32)> = Vec::new();
    for item in &items.result.result {
        let Ok(slot) = item.name.parse::<usize>() else {
            continue;
        };
        let Some(fn_id) = item.value.as_ref().and_then(|v| v.object_id.clone()) else {
            continue;
        };
        let Ok(props) = inner
            .execute(RawGetProperties {
                object_id: fn_id.inner().clone(),
                own_properties: true,
            })
            .await
        else {
            continue;
        };
        let location = props
            .result
            .get("internalProperties")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .find(|p| p.get("name").and_then(|n| n.as_str()) == Some("[[FunctionLocation]]"))
            .and_then(|p| p.get("value"))
            .and_then(|v| v.get("value"));
        let Some(location) = location else {
            continue;
        };
        let script_id = location.get("scriptId").and_then(|v| v.as_str());
        let line = location.get("lineNumber").and_then(|v| v.as_u64());
        let col = location.get("columnNumber").and_then(|v| v.as_u64());
        if let (Some(script_id), Some(line), Some(col)) = (script_id, line, col) {
            raw.push((
                slot,
                script_id.to_string(),
                u32::try_from(line + 1).unwrap_or(u32::MAX),
                u32::try_from(col + 1).unwrap_or(u32::MAX),
            ));
        }
    }
    if raw.is_empty() {
        return Ok(HashMap::new());
    }

    inner
        .execute(profiler::EnableParams::default())
        .await
        .context("Profiler.enable")?;
    let coverage = inner
        .execute(profiler::GetBestEffortCoverageParams::default())
        .await
        .context("Profiler.getBestEffortCoverage")?;
    let urls: HashMap<&str, &str> = coverage
        .result
        .result
        .iter()
        .filter(|script| !script.url.is_empty())
        .map(|script| (script.script_id.inner().as_str(), script.url.as_str()))
        .collect();

    Ok(raw
        .into_iter()
        .filter_map(|(slot, script_id, line, col)| {
            let url = urls.get(script_id.as_str())?;
            Some((slot, ((*url).to_string(), line, col)))
        })
        .collect())
}

/// Discover interactive elements within a DOM subtree, scoped to the given
/// root element selectors. Used for deep exploration of modals, panels, etc.
pub async fn discover_elements_in_subtree(
    page: &PageClient,
    view_id: &ViewId,
    root_selectors: &[String],
) -> Result<Vec<InteractiveElement>> {
    if root_selectors.is_empty() {
        return Ok(vec![]);
    }

    let selectors_json = serde_json::to_string(root_selectors)?;
    let script = format!(
        r#"
(() => {{
  const rootSelectors = {selectors_json};
  const roots = [];
  for (const sel of rootSelectors) {{
    try {{
      const el = document.querySelector(sel);
      if (el) roots.push(el);
    }} catch (_) {{}}
  }}
  if (roots.length === 0) return [];

  {DISCOVER_ELEMENTS_BODY}

  const results = [];
  for (const root of roots) {{
    if (isInsideDevOverlay(root)) continue;
    results.push(...discoverIn(root));
  }}
  try {{
    if (sourceHandlerFns.length) {{
      Object.defineProperty(window, '{HANDLER_FNS_GLOBAL}', {{ value: sourceHandlerFns, configurable: true, writable: true }});
    }}
  }} catch (_) {{}}
  return results;
}})()
"#
    );

    let mut js: Vec<JsElementInfo> = page
        .evaluate_json(&script)
        .await
        .context("discover elements in subtree")?;

    attach_handler_locations(page, &mut js).await;
    parse_js_elements(js, view_id)
}

/// Shared parsing logic for converting JS discovery results into
/// `InteractiveElement` values.
fn parse_js_elements(js: Vec<JsElementInfo>, view_id: &ViewId) -> Result<Vec<InteractiveElement>> {
    let mut out = Vec::with_capacity(js.len());
    for mut el in js {
        let element_type = classify(&el);
        let locators = build_locators(&el);
        let source = el.source.take().and_then(source_capture);
        out.push(InteractiveElement {
            selector: el.selector,
            label: el.label,
            element_type,
            interaction_result: None,
            source,
            found_on: view_id.clone(),
            bounding_box: el.bbox.as_ref().map(|b| BoundingBox {
                x: b.x,
                y: b.y,
                width: b.width,
                height: b.height,
            }),
            snapshot: None,
            disabled: el.disabled.unwrap_or(false),
            empty_required_fields_in_form: el.empty_required_fields_in_form.unwrap_or(0),
            locators,
        });
    }

    Ok(out)
}

/// Convert the browser capture into the stored contract type, dropping
/// frames without a usable URL/line. Returns `None` when nothing is left.
fn source_capture(js: JsSourceCapture) -> Option<ElementSourceCapture> {
    fn non_empty(s: Option<String>) -> Option<String> {
        s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
    fn position(v: Option<f64>) -> Option<u32> {
        v.filter(|v| v.is_finite() && *v >= 0.0 && *v <= u32::MAX as f64)
            .map(|v| v as u32)
    }

    let frames: Vec<SourceFrame> = js
        .frames
        .into_iter()
        .filter_map(|f| {
            let url = non_empty(f.url)?;
            let line = position(f.line).filter(|line| *line > 0)?;
            let role = match f.role.as_deref() {
                Some(role @ ("render" | "owner" | "handler")) => role.to_string(),
                _ => "owner".to_string(),
            };
            Some(SourceFrame {
                role,
                owner: non_empty(f.owner),
                env: non_empty(f.env),
                url,
                line,
                col: position(f.col).unwrap_or(0),
            })
        })
        .collect();
    let mut handlers: Vec<String> = js
        .handlers
        .into_iter()
        .filter(|h| h.len() > 2 && h.starts_with("on"))
        .collect();
    handlers.sort();
    handlers.dedup();
    let annotated = non_empty(js.annotated);

    if frames.is_empty() && handlers.is_empty() && annotated.is_none() {
        return None;
    }
    Some(ElementSourceCapture {
        frames,
        handlers,
        annotated,
    })
}

fn build_locators(el: &JsElementInfo) -> Vec<LocatorStrategy> {
    let mut locators = Vec::new();
    let mut seen = HashSet::new();
    let cross_root = el.dom_path_locator.is_some();

    let mut push = |kind: LocatorKind, value: Option<&str>, unique: bool| {
        let Some(value) = value else {
            return;
        };
        let value = value.trim();
        if value.is_empty() || !seen.insert(value.to_string()) {
            return;
        }
        locators.push(LocatorStrategy {
            kind,
            value: value.to_string(),
            stability: kind.default_stability(),
            unique,
        });
    };

    push(
        LocatorKind::TestId,
        el.test_selector.as_deref(),
        !cross_root,
    );
    push(LocatorKind::Id, el.id_selector.as_deref(), !cross_root);
    push(LocatorKind::Aria, el.aria_selector.as_deref(), !cross_root);
    push(LocatorKind::Name, el.name_selector.as_deref(), !cross_root);
    push(LocatorKind::Role, el.role_selector.as_deref(), !cross_root);
    push(
        LocatorKind::Class,
        el.class_selector.as_deref(),
        !cross_root,
    );
    push(
        LocatorKind::DomPath,
        el.dom_path_locator.as_deref(),
        cross_root,
    );
    push(
        LocatorKind::Structural,
        el.structural_selector
            .as_deref()
            .or(Some(el.selector.as_str())),
        !cross_root,
    );

    locators
}

fn classify(el: &JsElementInfo) -> ElementType {
    let has_popup = el
        .aria_haspopup
        .as_deref()
        .is_some_and(|v| v == "true" || v == "menu" || v == "listbox");
    let has_expanded = el.aria_expanded.is_some();
    let has_chevron = el.label.as_deref().is_some_and(|l| {
        l.contains('\u{25BE}') || l.contains('\u{25BC}') || l.contains('\u{25B8}')
    });
    let in_nav = el.in_nav.unwrap_or(false);

    // Some apps use <div role="button">Save</div> inside a <form>. Our JS marks
    // these as `formSubmit=true` so default scans (submit_forms=false) can avoid
    // accidental mutations. Preserve that intent by treating them as buttons
    // here, even though the tag is not `<button>`.
    if el.role.as_deref() == Some("button") && el.form_submit.unwrap_or(false) {
        return ElementType::Button { form_submit: true };
    }

    // Treat role="button" dropdown triggers as dropdown menus even when the tag is
    // not `<button>`.
    if el.role.as_deref() == Some("button")
        && (has_popup || has_chevron || (in_nav && has_expanded))
    {
        return ElementType::DropdownMenu { in_nav };
    }

    match el.tag.as_str() {
        "a" => {
            // Some apps use `<a aria-haspopup="menu" href="#">Menu</a>` as a
            // dropdown trigger. Only treat anchors as dropdown triggers when they
            // don't have a meaningful navigation target.
            let href = el.href.as_deref().map(|s| s.trim()).unwrap_or("");
            let anchor_is_trigger = (has_popup || (in_nav && has_expanded))
                && (href.is_empty()
                    || href == "#"
                    || href.starts_with('#')
                    || href.to_ascii_lowercase().starts_with("javascript:"));

            if anchor_is_trigger {
                ElementType::DropdownMenu { in_nav }
            } else {
                ElementType::NavigationLink {
                    href: el.href.clone(),
                    in_nav,
                }
            }
        }
        "button" => {
            if has_popup || has_chevron || (in_nav && has_expanded) {
                ElementType::DropdownMenu { in_nav }
            } else if crate::dom::heuristics::is_pagination_label(el.label.as_deref())
                && !el.form_submit.unwrap_or(false)
            {
                ElementType::Pagination
            } else {
                ElementType::Button {
                    form_submit: el.form_submit.unwrap_or(false),
                }
            }
        }
        // A <details> disclosure toggle.
        "summary" => ElementType::Accordion,
        "select" => ElementType::SelectDropdown {
            options: el
                .options
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|o| SelectOption {
                    label: o.label,
                    value: o.value,
                })
                .collect(),
        },
        "input" => {
            let t = el.input_type.clone().unwrap_or_else(|| "text".to_string());
            match t.as_str() {
                "submit" | "image" => ElementType::Button { form_submit: true },
                "checkbox" => ElementType::Checkbox {
                    name: el.name.clone(),
                    checked: el.checked.unwrap_or(false),
                },
                "radio" => ElementType::RadioButton {
                    name: el.name.clone(),
                    group: el.name.clone(),
                },
                "file" => ElementType::FileUpload {
                    accept: el.accept.clone(),
                },
                _ => ElementType::TextInput {
                    input_type: t,
                    name: el.name.clone(),
                    required: el.required.unwrap_or(false),
                },
            }
        }
        _ => {
            // Detect pagination controls even when they use non-button tags
            // (e.g. <div role="button">Load More</div>).
            if el.role.as_deref() == Some("button")
                && crate::dom::heuristics::is_pagination_label(el.label.as_deref())
            {
                ElementType::Pagination
            } else {
                ElementType::Other {
                    tag: el.tag.clone(),
                    role: el.role.clone(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_element() -> JsElementInfo {
        JsElementInfo {
            selector: r#"[data-testid="save-button"]"#.to_string(),
            label: Some("Save".to_string()),
            tag: "button".to_string(),
            role: Some("button".to_string()),
            dom_path_locator: None,
            test_selector: Some(r#"[data-testid="save-button"]"#.to_string()),
            id_selector: Some("#save-button".to_string()),
            aria_selector: Some(r#"button[aria-label="Save"]"#.to_string()),
            name_selector: Some(r#"button[name="save"]"#.to_string()),
            role_selector: Some(r#"button[role="button"]"#.to_string()),
            class_selector: Some("button.btn.primary".to_string()),
            structural_selector: Some("main > form > button:nth-of-type(1)".to_string()),
            href: None,
            input_type: None,
            name: Some("save".to_string()),
            required: Some(false),
            checked: None,
            accept: None,
            options: None,
            form_submit: Some(false),
            bbox: None,
            aria_haspopup: None,
            aria_expanded: None,
            in_nav: Some(false),
            disabled: Some(false),
            empty_required_fields_in_form: Some(0),
            source: None,
        }
    }

    #[test]
    fn builds_locator_strategies_in_stability_order() {
        let locators = build_locators(&sample_element());
        let kinds = locators
            .iter()
            .map(|locator| locator.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                LocatorKind::TestId,
                LocatorKind::Id,
                LocatorKind::Aria,
                LocatorKind::Name,
                LocatorKind::Role,
                LocatorKind::Class,
                LocatorKind::Structural,
            ]
        );
        assert!(locators.iter().all(|locator| locator.unique));
    }

    #[test]
    fn parse_js_elements_preserves_locators() {
        let view_id = "view_0001".to_string();
        let elements = parse_js_elements(vec![sample_element()], &view_id).unwrap();
        let element = &elements[0];
        assert_eq!(element.selector, r#"[data-testid="save-button"]"#);
        assert_eq!(element.locators.len(), 7);
        assert_eq!(element.locators[0].value, r#"[data-testid="save-button"]"#);
        assert_eq!(element.locators[6].kind, LocatorKind::Structural);
    }

    #[test]
    fn parses_source_capture_from_discovery_payload() {
        let payload = serde_json::json!([{
            "selector": "button.btn",
            "label": "Checkout",
            "tag": "button",
            "source": {
                "frames": [
                    {"role": "render", "owner": "Button", "env": null,
                     "url": "http://127.0.0.1:3000/_next/static/chunks/_1lh8s6g._.js",
                     "line": 45, "col": 214},
                    {"role": "owner", "owner": "CheckoutButton", "env": "Server",
                     "url": "about://React/Server/file:///repo/.next/dev/server/chunks/ssr/x._.js?11",
                     "line": 62, "col": 264},
                    {"role": "owner", "url": "", "line": 3, "col": 1},
                    {"role": "weird", "url": "http://127.0.0.1:3000/x.js", "line": 0, "col": 1}
                ],
                "handlers": ["onClick", "onClick", "onMouseEnter", "x"],
                "annotated": null
            }
        }, {
            "selector": "a.cta",
            "tag": "a",
            "source": {"frames": [], "handlers": [],
                       "annotated": "/repo/src/pages/index.astro:12:5"}
        }, {
            "selector": "a.plain",
            "tag": "a",
            "source": {"frames": [{"url": "u", "line": null}], "handlers": []}
        }, {
            "selector": "a.malformed",
            "tag": "a",
            "source": {"frames": {"not": "a list"}}
        }]);
        let js: Vec<JsElementInfo> = serde_json::from_value(payload).unwrap();
        let elements = parse_js_elements(js, &"view_0001".to_string()).unwrap();

        let src = elements[0].source.as_ref().unwrap();
        assert_eq!(src.frames.len(), 2, "frames without url/line are dropped");
        assert_eq!(src.frames[0].role, "render");
        assert_eq!(src.frames[0].owner.as_deref(), Some("Button"));
        assert_eq!((src.frames[0].line, src.frames[0].col), (45, 214));
        assert_eq!(src.frames[1].env.as_deref(), Some("Server"));
        assert_eq!(src.handlers, vec!["onClick", "onMouseEnter"]);

        let astro = elements[1].source.as_ref().unwrap();
        assert!(astro.frames.is_empty());
        assert_eq!(
            astro.annotated.as_deref(),
            Some("/repo/src/pages/index.astro:12:5")
        );

        assert!(elements[2].source.is_none(), "empty capture becomes None");
        assert_eq!(elements.len(), 4, "malformed capture keeps the element");
        assert!(elements[3].source.is_none());
    }

    #[test]
    fn cross_root_elements_prefer_dom_path_for_resolution() {
        let mut element = sample_element();
        element.dom_path_locator = Some(
            r#"{"segments":[{"selector":"app-shell","enter":"shadow"},{"selector":"button.save"}]}"#
                .to_string(),
        );

        let locators = build_locators(&element);
        assert_eq!(locators[6].kind, LocatorKind::DomPath);
        assert!(locators[6].unique);
        assert!(locators[..6].iter().all(|locator| !locator.unique));
        assert!(!locators[7].unique);
    }

    #[test]
    fn parses_react18_vue_and_angular_source_captures() {
        // Ensure the in-page discovery probe includes all runtime source hooks.
        assert!(DISCOVER_ELEMENTS_BODY.contains("_debugSource"));
        assert!(DISCOVER_ELEMENTS_BODY.contains("__vueParentComponent"));
        assert!(DISCOVER_ELEMENTS_BODY.contains("getOwningComponent"));
        assert!(DISCOVER_ELEMENTS_BODY.contains("debugInfo"));

        let payload = serde_json::json!([
            {
                "selector": "button.react18",
                "label": "Pay now",
                "tag": "button",
                "source": {
                    "frames": [
                        {"role": "render", "owner": "Button", "env": null,
                         "url": "file:///repo/src/components/ui/Button.tsx",
                         "line": 12, "col": 5},
                        {"role": "owner", "owner": "CheckoutForm", "env": null,
                         "url": "file:///repo/src/pages/Checkout.tsx",
                         "line": 28, "col": 9}
                    ],
                    "handlers": ["onClick"],
                    "annotated": null
                }
            },
            {
                "selector": "button.vue3",
                "label": "Add to cart",
                "tag": "button",
                "source": {
                    "frames": [],
                    "handlers": [],
                    "annotated": "/repo/src/components/ProductCard.vue:1"
                }
            },
            {
                "selector": "button.angular",
                "label": "Submit order",
                "tag": "button",
                "source": {
                    "frames": [
                        {"role": "render", "owner": "CheckoutComponent", "env": null,
                         "url": "src/app/checkout/checkout.component.ts",
                         "line": 14, "col": 0},
                        {"role": "owner", "owner": "AppComponent", "env": null,
                         "url": "src/app/app.component.ts",
                         "line": 8, "col": 0}
                    ],
                    "handlers": [],
                    "annotated": null
                }
            }
        ]);
        let js: Vec<JsElementInfo> = serde_json::from_value(payload).unwrap();
        let elements = parse_js_elements(js, &"view_0001".to_string()).unwrap();

        let react18 = elements[0].source.as_ref().unwrap();
        assert_eq!(react18.frames.len(), 2);
        assert_eq!(react18.frames[0].role, "render");
        assert_eq!(
            react18.frames[0].url,
            "file:///repo/src/components/ui/Button.tsx"
        );
        assert_eq!(react18.frames[1].role, "owner");
        assert_eq!(react18.frames[1].owner.as_deref(), Some("CheckoutForm"));

        let vue3 = elements[1].source.as_ref().unwrap();
        assert!(vue3.frames.is_empty());
        assert_eq!(
            vue3.annotated.as_deref(),
            Some("/repo/src/components/ProductCard.vue:1")
        );

        let angular = elements[2].source.as_ref().unwrap();
        assert_eq!(angular.frames.len(), 2);
        assert_eq!(
            angular.frames[0].owner.as_deref(),
            Some("CheckoutComponent")
        );
        assert_eq!(
            angular.frames[0].url,
            "src/app/checkout/checkout.component.ts"
        );
        assert_eq!(angular.frames[0].line, 14);
        assert_eq!(angular.frames[1].owner.as_deref(), Some("AppComponent"));
    }

    #[test]
    fn discovery_script_excludes_nextjs_and_vite_dev_error_overlays() {
        for marker in [
            "nextjs-portal",
            "#nextjs__container_errors_label",
            "[data-nextjs-dialog]",
            "[data-nextjs-toast]",
            "vite-error-overlay",
            "isInsideDevOverlay",
        ] {
            assert!(
                DISCOVER_ELEMENTS_BODY.contains(marker),
                "DISCOVER_ELEMENTS_BODY missing overlay exclusion marker {marker}"
            );
        }
    }
}
