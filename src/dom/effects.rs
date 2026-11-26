//! Click-scoped effect evidence.
//!
//! Before a control is clicked, [`FX_RUNTIME_JS`] prepares it the way a user
//! would meet it (ancestor `<details>` opened, scrolled into view, hit-tested
//! at the click point) and records a baseline of what is *visible*: the text
//! of every rendered element, form field values, media sources, interactive
//! elements, the page theme and the control's own state. After the click the
//! same digest is diffed against the baseline. Only visible differences count
//! as a DOM effect, so attribute writes that change nothing (`aria-expanded`
//! re-set to its value), class/style/`inert` churn elsewhere on the page and
//! re-renders that recreate identical content are not mistaken for an effect.
//! Elements whose content changed on their own while the page was supposed to
//! be quiet, or that keep changing between actions (clocks, timers, tickers;
//! tracked by the page instrumentation), are excluded from the diff. A list
//! whose texts only changed order (sorted) counts as a change.

use serde::{Deserialize, Serialize};

/// Installs `window.__BROKENAPP_FX` (idempotent per document).
pub(crate) const FX_RUNTIME_JS: &str = r#"
(() => {
  const w = window;
  if (w.__BROKENAPP_FX && w.__BROKENAPP_FX.version === 1) return true;
  const ids = new WeakMap();
  let nextId = 1;
  function idOf(el) {
    let id = ids.get(el);
    if (!id) { id = nextId++; ids.set(el, id); }
    return id;
  }
  const NORM = (s) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();

  function visible(el) {
    if (!el || !el.isConnected) return false;
    try {
      if (typeof el.checkVisibility === 'function') {
        if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
      } else {
        const s = getComputedStyle(el);
        if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return false;
      }
      const r = el.getBoundingClientRect();
      return r.width > 0 || r.height > 0;
    } catch (_) { return false; }
  }

  function hiddenReason(el) {
    try {
      const d = el.closest && el.closest('details:not([open])');
      if (d) return 'inside a closed <details>';
      const s = getComputedStyle(el);
      if (s.display === 'none') return 'display:none';
      if (s.visibility === 'hidden') return 'visibility:hidden';
      if (s.opacity === '0') return 'opacity:0';
      const r = el.getBoundingClientRect();
      if (r.width <= 0 || r.height <= 0) return 'zero-size';
      return 'not rendered';
    } catch (_) { return 'not rendered'; }
  }

  function composedContains(a, b) {
    for (let n = b; n; n = n.parentNode || n.host) {
      if (n === a) return true;
    }
    return false;
  }

  function owns(el, node) {
    if (!el || !node) return false;
    if (composedContains(el, node)) return true;
    try {
      if (el.labels) {
        for (const l of el.labels) if (composedContains(l, node)) return true;
      }
    } catch (_) {}
    return false;
  }

  function deepElementFromPoint(x, y) {
    let e = document.elementFromPoint(x, y);
    for (let i = 0; e && e.shadowRoot && i < 8; i++) {
      const inner = e.shadowRoot.elementFromPoint(x, y);
      if (!inner || inner === e) break;
      e = inner;
    }
    return e;
  }

  function describe(el) {
    try {
      const tag = (el.tagName || '').toLowerCase();
      const id = el.id ? '#' + el.id : '';
      const cls = (typeof el.className === 'string' && el.className.trim())
        ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '';
      return tag + id + cls;
    } catch (_) { return 'element'; }
  }

  const TRANSIENT_CLASS = /(^|[-_])(focus|focused|focus-visible|focus-within|hover|hovered|ripple)([-_]|$)/i;
  function classKey(el) {
    let c = '';
    try {
      c = (el.className && typeof el.className === 'object' && 'baseVal' in el.className)
        ? el.className.baseVal : String(el.className || '');
    } catch (_) {}
    return c.split(/\s+/).filter(t => t && !TRANSIENT_CLASS.test(t)).sort().join(' ');
  }

  function controlled(el) {
    try {
      const ids = String(el.getAttribute('aria-controls') || '').split(/\s+/).filter(Boolean);
      return ids.length ? document.getElementById(ids[0]) : null;
    } catch (_) { return null; }
  }

  function ctrlState(el) {
    if (!el) return null;
    const a = (n) => { try { return el.getAttribute(n); } catch (_) { return null; } };
    const target = controlled(el);
    let open = null;
    try {
      const d = el.closest && el.closest('details');
      if (d) open = !!d.open;
    } catch (_) {}
    const type = String(el.type || '').toLowerCase();
    const toggle = el.tagName === 'INPUT' && (type === 'checkbox' || type === 'radio');
    return {
      expanded: a('aria-expanded'),
      pressed: a('aria-pressed'),
      selected: a('aria-selected'),
      checked: a('aria-checked'),
      // A native checkbox/radio shows its own state flip.
      toggled: toggle ? !!el.checked : null,
      current: a('aria-current'),
      state: a('data-state'),
      disabled: !!(el.disabled || a('aria-disabled') === 'true'),
      open,
      cls: classKey(el),
      target_vis: target ? visible(target) : null,
      target_cls: target ? classKey(target) : null,
    };
  }

  function isActive(el, st) {
    if (!el || !st) return false;
    const role = String(el.getAttribute('role') || '').toLowerCase();
    const type = String(el.type || '').toLowerCase();
    const toggles = role === 'checkbox' || role === 'switch' || role === 'menuitemcheckbox' || type === 'checkbox';
    if (st.pressed === 'true' || st.selected === 'true') return true;
    if (st.current && st.current !== 'false') return true;
    if (st.checked === 'true' && !toggles) return true;
    if (type === 'radio' && el.checked) return true;
    const ds = String(st.state || '').toLowerCase();
    if ((ds === 'active' || ds === 'on' || ds === 'checked') && !toggles) return true;
    return /(^|\s)(active|is-active|selected|is-selected|current|is-current)(\s|$)/i.test(st.cls || '');
  }

  // --- Visible-state digest ---------------------------------------------
  const FIELD = 'input,textarea,select';
  const MEDIA = 'img,video,audio,canvas,iframe,object,embed';
  const CONTROLS = 'button,a[href],[role="button"],[role="tab"],[role="checkbox"],[role="switch"],[role="option"],[role="menuitem"],[role="radio"],[contenteditable="true"]';
  function isTicker(el) {
    try { return !!(w.__BROKENAPP && w.__BROKENAPP.isTicker && w.__BROKENAPP.isTicker(el)); } catch (_) { return false; }
  }
  function mediaKey(el) {
    if (el.tagName === 'IMG') {
      // currentSrc can switch from the fallback to a responsive candidate
      // as an image loads, without any action or DOM mutation. Compare the
      // declared sources instead, including picture source changes.
      const attrs = (node, names) => names.map(name => node.getAttribute(name) || '');
      const picture = el.parentElement && el.parentElement.tagName === 'PICTURE'
        ? Array.from(el.parentElement.children)
          .filter(node => node.tagName === 'SOURCE')
          .map(node => attrs(node, ['srcset', 'sizes', 'media', 'type']))
        : [];
      return 'IMG:' + JSON.stringify([attrs(el, ['src', 'srcset', 'sizes']), picture]);
    }
    return el.tagName + ':' + String(el.currentSrc || el.src || el.getAttribute('src') || el.getAttribute('data') || '');
  }
  function snap(control) {
    const texts = new Map(), fields = new Map(), media = new Map(), controls = new Map();
    const els = new Map();
    const vis = new Map();
    const isVis = (el) => {
      let v = vis.get(el);
      if (v === undefined) { v = visible(el); vis.set(el, v); }
      return v;
    };
    const root = document.body || document.documentElement;
    if (root) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      let n = 0, node;
      while ((node = walker.nextNode()) && n < 20000) {
        const t = node.nodeValue;
        if (!t || !/\S/.test(t)) continue;
        const p = node.parentElement;
        if (!p) continue;
        const tag = p.tagName;
        if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEMPLATE') continue;
        n++;
        if (!isVis(p) || isTicker(p)) continue;
        const id = idOf(p);
        const prev = texts.get(id);
        texts.set(id, prev ? prev + ' ' + NORM(t) : NORM(t));
        if (!prev) els.set(id, p);
      }
      let m = 0;
      for (const el of root.querySelectorAll(FIELD + ',' + MEDIA + ',' + CONTROLS)) {
        if (++m > 6000) break;
        if (!isVis(el)) continue;
        const id = idOf(el);
        if (el.matches(FIELD)) {
          if (el === control) continue;
          const type = String(el.type || '').toLowerCase();
          const val = (type === 'checkbox' || type === 'radio') ? String(!!el.checked) : String(el.value == null ? '' : el.value);
          fields.set(id, el.tagName + ':' + val.slice(0, 200) + (el.disabled ? ':d' : ''));
        } else if (el.matches(MEDIA)) {
          media.set(id, mediaKey(el));
        } else {
          const disabled = !!(el.disabled || el.getAttribute('aria-disabled') === 'true');
          controls.set(id, el.tagName + '|' + (el.getAttribute('role') || '') + '|' + NORM(el.getAttribute('aria-label') || '') + (disabled ? '|d' : ''));
        }
      }
    }
    let theme = '';
    try {
      const b = document.body ? getComputedStyle(document.body) : null;
      const h = getComputedStyle(document.documentElement);
      theme = [b ? b.backgroundColor : '', b ? b.color : '', h.backgroundColor, h.color, h.colorScheme].join('|');
    } catch (_) {}
    return { texts, fields, media, controls, theme, els };
  }

  // The visible text `snap` records for `el`: its own text nodes.
  function ownText(el) {
    const parts = [];
    for (const n of el.childNodes) {
      if (n.nodeType === 3 && n.nodeValue && /\S/.test(n.nodeValue)) parts.push(NORM(n.nodeValue));
    }
    return parts.join(' ');
  }

  const KINDS = ['texts', 'fields', 'media', 'controls'];
  function multisetDelta(gone, added) {
    const counts = new Map();
    for (const x of gone) counts.set(x, (counts.get(x) || 0) - 1);
    for (const x of added) counts.set(x, (counts.get(x) || 0) + 1);
    let n = 0;
    for (const v of counts.values()) n += Math.abs(v);
    return n;
  }
  function diffMap(before, after, churn) {
    const changed = [], changedIds = [], gone = [], added = [];
    for (const [id, v] of before) {
      if (churn && churn.has(id)) continue;
      if (!after.has(id)) gone.push(v);
      else if (after.get(id) !== v) { changed.push(after.get(id)); changedIds.push(id); }
    }
    for (const [id, v] of after) {
      if (churn && churn.has(id)) continue;
      if (!before.has(id)) added.push(v);
    }
    // Recreated nodes with identical content cancel out.
    const counts = new Map();
    for (const x of gone) counts.set(x, (counts.get(x) || 0) - 1);
    for (const x of added) counts.set(x, (counts.get(x) || 0) + 1);
    const appeared = [];
    for (const [x, c] of counts) if (c > 0) appeared.push(x);
    return { n: changed.length + multisetDelta(gone, added), changed, changedIds, appeared };
  }
  // Elements whose text did not change now appear in another document order
  // (`Map` keeps first-seen order): a list was sorted or reordered by moving
  // its existing nodes. Other changes (a ticking clock) do not hide it.
  function reorderedTexts(before, after, churn) {
    const kept = (m, other) => {
      const out = [];
      for (const [id, v] of m) if ((!churn || !churn.has(id)) && other.get(id) === v) out.push(id);
      return out;
    };
    const a = kept(before, after), b = kept(after, before);
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return true;
    return false;
  }
  function churnIds(a, b) {
    const out = new Set();
    for (const k of KINDS) {
      for (const [id, v] of a[k]) if (b[k].get(id) !== v) out.add(id);
      for (const [id] of b[k]) if (!a[k].has(id)) out.add(id);
    }
    return out;
  }

  function mutationCount() {
    try { return (w.__BROKENAPP && typeof w.__BROKENAPP.domMutations === 'number') ? w.__BROKENAPP.domMutations : 0; } catch (_) { return 0; }
  }

  function isFocusTarget(el) {
    try {
      if (!el || el === document.body || el === document.documentElement) return false;
      if (el.matches('input,textarea,select,[contenteditable="true"]')) return true;
      const ti = el.getAttribute('tabindex');
      return ti !== null && ti !== '-1';
    } catch (_) { return false; }
  }

  // --- Synthetic form data ----------------------------------------------
  function setNative(el, value) {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
      : el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    const d = Object.getOwnPropertyDescriptor(proto, 'value');
    try { el.focus({ preventScroll: true }); } catch (_) {}
    try { if (el._valueTracker) el._valueTracker.setValue(''); } catch (_) {}
    if (d && d.set) d.set.call(el, value); else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }
  function fitLength(el, v) {
    let out = String(v);
    const min = parseInt(el.getAttribute('minlength') || '', 10);
    if (min > 0) while (out.length < min) out += ' ' + v;
    const max = parseInt(el.getAttribute('maxlength') || '', 10);
    if (max > 0 && out.length > max) out = out.slice(0, max);
    return out;
  }
  function labelText(el) {
    let t = el.getAttribute('aria-label') || el.getAttribute('placeholder') || '';
    try { if (el.labels && el.labels[0]) t += ' ' + el.labels[0].textContent; } catch (_) {}
    return (t + ' ' + (el.name || '') + ' ' + (el.id || '')).toLowerCase();
  }
  function lookup(values, el) {
    if (!values) return null;
    for (const k of [el.name, el.id, el.getAttribute('aria-label'), el.getAttribute('placeholder')]) {
      if (k && Object.prototype.hasOwnProperty.call(values, k)) return values[k];
    }
    return null;
  }
  function numberFor(el) {
    const min = parseFloat(el.getAttribute('min'));
    const max = parseFloat(el.getAttribute('max'));
    if (!isNaN(min) && !isNaN(max)) {
      if (min <= 1 && 1 <= max) return '1';
      return String(min);
    }
    if (!isNaN(min)) return String(Math.max(min, 1));
    if (!isNaN(max)) return String(Math.min(max, 1));
    return '1';
  }
  // A date two weeks out, moved into the field's [min, max] range so the
  // browser accepts it.
  function dateFor(el) {
    const pad = (n) => String(n).padStart(2, '0');
    const d = new Date(Date.now() + 14 * 86400000);
    let v = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
    const min = el.getAttribute('min'), max = el.getAttribute('max');
    if (min && /^\d{4}-\d{2}-\d{2}$/.test(min) && v < min) v = min;
    if (max && /^\d{4}-\d{2}-\d{2}$/.test(max) && v > max) v = max;
    return v;
  }
  function inRange(el, v) {
    const min = el.getAttribute('min'), max = el.getAttribute('max');
    if (min && v < min) return min;
    if (max && v > max) return max;
    return v;
  }
  function textFor(el) {
    const type = String(el.type || 'text').toLowerCase();
    const hint = labelText(el);
    switch (type) {
      case 'email': return 'test@example.com';
      case 'tel': return '+15550100';
      case 'url': return 'https://example.com';
      case 'number': case 'range': return numberFor(el);
      case 'date': return dateFor(el);
      case 'datetime-local': return inRange(el, dateFor(el) + 'T10:00');
      case 'time': return inRange(el, '10:00');
      case 'month': return inRange(el, dateFor(el).slice(0, 7));
      case 'week': return inRange(el, '2026-W03');
      case 'password': return 'BrokenApp-Test-1!';
    }
    if (/e-?mail/.test(hint)) return 'test@example.com';
    if (/phone|tel\b|mobile/.test(hint)) return '+15550100';
    if (/zip|postal/.test(hint)) return '10001';
    if (/first/.test(hint)) return 'Test';
    if (/last|surname/.test(hint)) return 'User';
    if (/name/.test(hint)) return 'Test User';
    if (/city|town/.test(hint)) return 'Springfield';
    if (/address|street/.test(hint)) return '1 Test Street';
    if (/company|organi[sz]ation/.test(hint)) return 'Test Co';
    if (/url|website|link/.test(hint)) return 'https://example.com';
    return 'BrokenApp test input';
  }
  function fillContainer(el, opts) {
    let root = (el.form) || (el.closest && (el.closest('form') || el.closest('[role="form"]')));
    if (!root) {
      for (let p = el.parentElement, i = 0; p && i < 6 && p !== document.body; p = p.parentElement, i++) {
        if (p.querySelector('input:not([type="hidden"]),textarea,select')) { root = p; break; }
      }
    }
    if (!root) return 0;
    const passwords = Array.from(root.querySelectorAll('input[type="password"]'));
    const registration = passwords.length >= 2 || /sign ?up|register|create (an )?account|join/i.test(NORM(el.textContent || el.value || ''));
    const allowPasswords = !!opts.passwords || registration;
    let filled = 0;
    const radioGroups = new Set();
    for (const f of root.querySelectorAll('input,textarea,select')) {
      if (f === el || f.disabled || f.readOnly) continue;
      const type = String(f.type || '').toLowerCase();
      if (['hidden', 'file', 'submit', 'button', 'reset', 'image', 'color'].includes(type)) continue;
      if (!visible(f) && !(type === 'checkbox' || type === 'radio')) continue;
      try {
        if (type === 'checkbox') {
          if (!f.checked && (f.required || opts.check_all) && (visible(f) || (f.labels && Array.from(f.labels).some(visible)))) {
            f.click();
            filled++;
          }
          continue;
        }
        if (type === 'radio') {
          if (!f.name || radioGroups.has(f.name)) continue;
          radioGroups.add(f.name);
          const group = Array.from(root.querySelectorAll('input[type="radio"]')).filter(r => r.name === f.name);
          if (!group.some(r => r.checked) && (f.required || opts.check_all)) { f.click(); filled++; }
          continue;
        }
        if (type === 'password' && !allowPasswords) continue;
        const given = lookup(opts.values, f);
        if (f.tagName === 'SELECT') {
          const cur = f.options[f.selectedIndex];
          if (f.selectedIndex >= 0 && cur && cur.value !== '') continue;
          const opt = Array.from(f.options).find(o => !o.disabled && o.value !== '');
          if (opt) { setNative(f, given != null ? given : opt.value); filled++; }
          continue;
        }
        const valid = typeof f.checkValidity === 'function' ? f.checkValidity() : true;
        if (String(f.value || '') !== '' && valid) continue;
        const value = given != null ? String(given)
          : f.tagName === 'TEXTAREA' ? 'BrokenApp synthetic test input for this field.'
          : textFor(f);
        setNative(f, f.tagName === 'TEXTAREA' || ['text', 'search', ''].includes(type) ? fitLength(f, value) : value);
        filled++;
      } catch (_) {}
    }
    return filled;
  }

  // --- Public API ---------------------------------------------------------
  const api = {
    version: 1,
    base: null,
    valueFor(el, values) {
      if (!el) return 'test';
      const given = lookup(values, el);
      const type = String(el.type || '').toLowerCase();
      const value = given != null ? String(given)
        : el.tagName === 'TEXTAREA' ? 'BrokenApp synthetic test input for this field.'
        : textFor(el);
      return (el.tagName === 'TEXTAREA' || ['text', 'search', ''].includes(type)) ? fitLength(el, value) : value;
    },
    prepare(el, opts) {
      opts = opts || {};
      if (!el || !el.isConnected) return { status: 'missing' };
      if (opts.expand) {
        const closed = [];
        for (let d = el.parentElement && el.parentElement.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) {
          if (d.open) continue;
          const sum = Array.from(d.children).find(c => c.tagName === 'SUMMARY');
          if (sum && sum.contains(el)) continue;
          closed.unshift({ d, sum });
        }
        let expanded = 0;
        for (const { d, sum } of closed) {
          try { if (sum) sum.click(); } catch (_) {}
          if (!d.open) { try { d.open = true; } catch (_) {} }
          if (d.open) expanded++;
        }
        if (expanded) return { status: 'expanded', expanded };
      }
      if (el.closest && el.closest('[inert]')) return { status: 'hidden', detail: 'inert' };
      if (el.disabled === true || (el.getAttribute && el.getAttribute('aria-disabled') === 'true')) {
        if (!opts.unlock) return { status: 'disabled' };
        const filled = fillContainer(el, Object.assign({}, opts, { check_all: true }));
        return { status: 'unlock', filled };
      }
      let filled = 0;
      if (opts.fill) filled = fillContainer(el, opts);
      if (el.ownerDocument !== document) {
        const st = ctrlState(el);
        return { status: 'ready', already_active: isActive(el, st), filled };
      }
      let target = el;
      let proxy = false;
      if (!visible(el)) {
        const type = String(el.type || '').toLowerCase();
        const labels = (el.labels ? Array.from(el.labels) : []).filter(visible);
        if (labels.length && (type === 'checkbox' || type === 'radio')) { target = labels[0]; proxy = true; }
        else return { status: 'hidden', detail: hiddenReason(el) };
      }
      const vw = window.innerWidth, vh = window.innerHeight;
      const scrollCenter = () => {
        try { target.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); }
        catch (_) { try { target.scrollIntoView(); } catch (_) {} }
      };
      const hitTest = () => {
        const r = target.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return { status: 'hidden', detail: 'zero-size' };
        const x0 = Math.max(r.left, 0), y0 = Math.max(r.top, 0);
        const x1 = Math.min(r.right, vw), y1 = Math.min(r.bottom, vh);
        if (x1 <= x0 || y1 <= y0) return { status: 'hidden', detail: 'outside the viewport' };
        const points = [[0.5, 0.5], [0.3, 0.5], [0.7, 0.5], [0.5, 0.3], [0.5, 0.7], [0.15, 0.2], [0.85, 0.8]];
        let point = null, blocker = null;
        for (const [fx, fy] of points) {
          const x = x0 + (x1 - x0) * fx, y = y0 + (y1 - y0) * fy;
          const hit = deepElementFromPoint(x, y);
          if (hit && (composedContains(target, hit) || owns(el, hit))) { point = [x, y]; break; }
          if (!blocker && hit) blocker = describe(hit);
        }
        return { point, blocker };
      };
      const r0 = target.getBoundingClientRect();
      let scrolled = false;
      if (r0.top < 0 || r0.left < 0 || r0.bottom > vh || r0.right > vw) {
        scrollCenter();
        scrolled = true;
      }
      let ht = hitTest();
      if (!ht.point && !scrolled) {
        scrollCenter();
        ht = hitTest();
      }
      if (ht.status) return ht;
      if (!ht.point) return { status: 'obscured', detail: 'covered by ' + (ht.blocker || 'nothing at the click point') };
      const st = ctrlState(el);
      return { status: 'ready', x: ht.point[0], y: ht.point[1], already_active: isActive(el, st), filled, proxy };
    },
    baseline(el) {
      if (!el) return false;
      const fx = api;
      fx.suspects = null;
      fx.baseEl = el;
      fx.base = snap(el);
      fx.baseCtrl = ctrlState(el);
      fx.baseFocus = document.activeElement;
      fx.baseMutations = mutationCount();
      fx.churn = null;
      fx.churnScroll = [];
      try { if (w.__BROKENAPP && w.__BROKENAPP.armFx) w.__BROKENAPP.armFx(); } catch (_) {}
      return true;
    },
    // Right before the click: anything that changed since the baseline
    // changed on its own (clocks, tickers) and is excluded from the diff.
    rebase() {
      const fx = api;
      if (!fx.base) return false;
      let quiet = null;
      try { if (w.__BROKENAPP && w.__BROKENAPP.takeFx) quiet = w.__BROKENAPP.takeFx(); } catch (_) {}
      fx.churnScroll = quiet ? quiet.scrollTargets.slice() : [];
      if (mutationCount() !== fx.baseMutations) {
        const again = snap(fx.baseEl);
        fx.churn = churnIds(fx.base, again);
        fx.base = again;
        fx.baseCtrl = ctrlState(fx.baseEl);
      }
      fx.baseFocus = document.activeElement;
      try { if (w.__BROKENAPP && w.__BROKENAPP.armFx) w.__BROKENAPP.armFx(); } catch (_) {}
      return true;
    },
    effects() {
      const fx = api;
      let ev = null;
      try { if (w.__BROKENAPP && w.__BROKENAPP.takeFx) ev = w.__BROKENAPP.takeFx(); } catch (_) {}
      if (!fx.base) return { missing_base: true };
      const el = fx.baseEl;
      const after = snap(el);
      const t = diffMap(fx.base.texts, after.texts, fx.churn);
      const reordered = reorderedTexts(fx.base.texts, after.texts, fx.churn);
      const f = diffMap(fx.base.fields, after.fields, fx.churn);
      const m = diffMap(fx.base.media, after.media, fx.churn);
      const c = diffMap(fx.base.controls, after.controls, fx.churn);
      const now = el && el.isConnected ? ctrlState(el) : null;
      const changes = [];
      if (fx.baseCtrl && now) {
        for (const k of Object.keys(fx.baseCtrl)) {
          if (JSON.stringify(fx.baseCtrl[k]) !== JSON.stringify(now[k])) changes.push(k);
        }
      }
      let inside = null;
      if (ev && ev.clicks > 0) inside = owns(el, ev.clickTarget);
      const scrolled = !!ev && ev.scrollTargets.some(s => (fx.churnScroll || []).indexOf(s) < 0);
      const ae = document.activeElement;
      const focusMoved = !!ae && ae !== fx.baseFocus && !owns(el, ae) && isFocusTarget(ae);
      const samples = t.changed.concat(t.appeared).filter(Boolean).slice(0, 5).map(s => s.slice(0, 200));
      const theme = after.theme !== fx.base.theme;
      // Only numbers in existing elements changed: maybe a timer that was
      // not known to tick yet. `recheck` tells after a pause.
      const tickerSuspect = t.n > 0 && t.changedIds.length === t.n && f.n === 0 && m.n === 0
        && c.n === 0 && !theme && changes.length === 0 && !!el && el.isConnected
        && t.changed.every(v => /\d/.test(v));
      fx.suspects = tickerSuspect
        ? t.changedIds.map(id => [after.els.get(id), after.texts.get(id)]).filter(([e]) => !!e)
        : null;
      fx.base = null;
      fx.baseEl = null;
      fx.baseCtrl = null;
      fx.churn = null;
      return {
        text: t.n,
        reordered,
        fields: f.n,
        media: m.n,
        controls: c.n,
        theme,
        samples,
        control_changes: changes,
        removed: !!el && !el.isConnected,
        click_inside: inside,
        clicks: ev ? ev.clicks : 0,
        scrolled,
        focus_moved: focusMoved,
        ticker_suspect: tickerSuspect,
        invalid: ev ? (ev.invalid || 0) : 0,
      };
    },
    // After a pause: how many of the elements a click changed (when only
    // numbers changed) kept their new text. Those that changed again tick
    // on their own and are remembered as tickers.
    recheck() {
      const list = api.suspects || [];
      api.suspects = null;
      const now = Date.now();
      let stable = 0;
      for (const [el, value] of list) {
        if (el.isConnected && ownText(el) !== value) {
          try { if (w.__BROKENAPP && w.__BROKENAPP.tickers) w.__BROKENAPP.tickers.set(el, { n: 3, last: now }); } catch (_) {}
        } else {
          stable++;
        }
      }
      return stable;
    },
  };
  try { Object.defineProperty(w, '__BROKENAPP_FX', { value: api, configurable: true }); } catch (_) { w.__BROKENAPP_FX = api; }
  return true;
})()
"#;

/// Result of preparing a control for a click.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct PrepareReport {
    pub status: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub x: Option<f64>,
    #[serde(default)]
    pub y: Option<f64>,
    #[serde(default)]
    pub already_active: bool,
    #[serde(default)]
    pub expanded: u32,
    #[serde(default)]
    pub filled: u32,
}

/// Options for [`FX_RUNTIME_JS`]'s `prepare`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PrepareOptions {
    /// Open closed ancestor `<details>` first.
    pub expand: bool,
    /// Fill the control's form/container with synthetic values first.
    pub fill: bool,
    /// The control is disabled: fill its container and check its checkboxes
    /// to try to enable it (gated wizard steps, consent checkboxes).
    pub unlock: bool,
    /// Fill password fields (registration forms always get one; login forms
    /// only when this is set).
    pub passwords: bool,
    /// Configured test data (`[scan.test_data]`) by field name, id or label.
    pub values: std::collections::BTreeMap<String, String>,
}

/// What a click visibly changed (see [`FX_RUNTIME_JS`]'s `effects`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct EffectReport {
    /// The baseline was gone: the document was replaced.
    #[serde(default)]
    pub missing_base: bool,
    /// Elements whose visible text changed, appeared or disappeared.
    /// Elements that change on their own (clocks, timers) are left out.
    #[serde(default)]
    pub text: u32,
    /// The same visible texts in a different order (a sorted list).
    #[serde(default)]
    pub reordered: bool,
    /// Other form fields whose value changed (the control's own value is
    /// excluded: typing into a field is not an effect of the field).
    #[serde(default)]
    pub fields: u32,
    #[serde(default)]
    pub media: u32,
    /// Interactive elements that appeared, disappeared or changed state.
    #[serde(default)]
    pub controls: u32,
    /// Page colors changed (theme toggles).
    #[serde(default)]
    pub theme: bool,
    /// Up to five changed/appeared texts.
    #[serde(default)]
    pub samples: Vec<String>,
    /// Control state that changed: `expanded`, `pressed`, `selected`,
    /// `checked`, `toggled` (a native checkbox/radio), `current`, `state`,
    /// `disabled`, `open`, `cls`, `target_vis`, `target_cls`.
    #[serde(default)]
    pub control_changes: Vec<String>,
    /// The control left the document.
    #[serde(default)]
    pub removed: bool,
    /// The first click event's target was inside the control (or one of its
    /// labels). `None` when no click event was seen.
    #[serde(default)]
    pub click_inside: Option<bool>,
    #[serde(default)]
    pub clicks: u32,
    /// A scroll container (or the window) scrolled because of the click.
    #[serde(default)]
    pub scrolled: bool,
    /// Focus moved to another field or focusable element.
    #[serde(default)]
    pub focus_moved: bool,
    /// The only change was numbers in existing elements: possibly a timer
    /// ticking on its own (see `recheck`).
    #[serde(default)]
    pub ticker_suspect: bool,
    /// Form fields the browser flagged invalid when the click tried to
    /// submit their form (it showed a validation message instead).
    #[serde(default)]
    pub invalid: u32,
}

impl EffectReport {
    /// Something visible changed: text, fields, media, controls, theme, the
    /// control's state, or the whole document.
    pub fn visible_change(&self) -> bool {
        self.missing_base
            || self.text > 0
            || self.reordered
            || self.fields > 0
            || self.media > 0
            || self.controls > 0
            || self.theme
            || self.removed
            || !self.control_changes.is_empty()
    }

    /// Visible text is the only thing that changed.
    pub fn only_text_changed(&self) -> bool {
        self.text > 0
            && !self.missing_base
            && !self.reordered
            && self.fields == 0
            && self.media == 0
            && self.controls == 0
            && !self.theme
            && !self.removed
            && self.control_changes.is_empty()
    }

    /// The click event landed outside the control (an overlay, a row).
    pub fn click_missed(&self) -> bool {
        self.click_inside == Some(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_report_counts_only_visible_change() {
        let none = EffectReport::default();
        assert!(!none.visible_change());
        let scroll_only = EffectReport {
            scrolled: true,
            ..Default::default()
        };
        assert!(!scroll_only.visible_change());
        let text = EffectReport {
            text: 1,
            ..Default::default()
        };
        assert!(text.visible_change());
        let sorted = EffectReport {
            reordered: true,
            ..Default::default()
        };
        assert!(sorted.visible_change());
        let pressed = EffectReport {
            control_changes: vec!["pressed".into()],
            ..Default::default()
        };
        assert!(pressed.visible_change());
        let reloaded = EffectReport {
            missing_base: true,
            ..Default::default()
        };
        assert!(reloaded.visible_change());
    }

    #[test]
    fn only_text_changes_qualify_for_the_ticker_recheck() {
        let digits = EffectReport {
            text: 1,
            ticker_suspect: true,
            ..Default::default()
        };
        assert!(digits.only_text_changed());
        let with_state = EffectReport {
            text: 1,
            control_changes: vec!["expanded".into()],
            ..Default::default()
        };
        assert!(!with_state.only_text_changed());
        let with_controls = EffectReport {
            text: 1,
            controls: 1,
            ..Default::default()
        };
        assert!(!with_controls.only_text_changed());
        assert!(!EffectReport::default().only_text_changed());
    }

    #[test]
    fn effect_report_parses_runtime_json() {
        let report: EffectReport = serde_json::from_str(
            r#"{"text":0,"fields":0,"media":0,"controls":0,"theme":false,"samples":[],
                "control_changes":[],"removed":false,"click_inside":false,"clicks":1,
                "scrolled":true,"focus_moved":false}"#,
        )
        .expect("parse");
        assert!(report.click_missed());
        assert!(report.scrolled);
        assert!(!report.visible_change());
    }
}
