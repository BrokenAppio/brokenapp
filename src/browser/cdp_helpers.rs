use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chromiumoxide::cdp::browser_protocol::page as cdp_page;
use serde::Serialize;

use crate::browser::PageClient;

#[derive(Debug, Clone, Copy)]
pub struct SettleStats {
    pub pending_requests: u64,
    pub ms_since_last_dom_mutation: u64,
}

/// Page instrumentation: action probe, request/DOM settle counters and
/// interaction evidence (click target, scrolls, print/open/download,
/// clipboard, storage). Idempotent per document.
const INSTRUMENTATION_JS: &str = r#"
(() => {
  const key = "__BROKENAPP";
  const w = window;
  if (w[key] && w[key].installed) return true;
  w[key] = w[key] || {};

  // --- Action probe (best-effort request correlation) ---
  // BrokenApp sets currentAction right before interacting with the UI.
  // The wrappers below attach a header on same-origin fetch/XHR calls so
  // network traffic can be attributed back to a specific UI action.
  w[key].currentAction = null;
  w[key].currentActionExpiresAt = 0;
  w[key].preparation = null;
  // Client-side route changes (pushState/popstate to another path or
  // query). Requests a page starts after the action moved it to another
  // route are that route's load traffic, not the action's.
  w[key].routeEpoch = 0;
  w[key].actionRouteEpoch = 0;
  w[key].beginAction = function(action, ttlMs) {
    try {
      // Also recover from a cancelled preparation whose end RPC never ran.
      w[key].preparation = null;
      const ttl = (typeof ttlMs === "number" && ttlMs > 0) ? ttlMs : 4000;
      w[key].currentAction = action || null;
      w[key].currentActionExpiresAt = Date.now() + ttl;
      w[key].actionRouteEpoch = w[key].routeEpoch;
      return action && action.id ? String(action.id) : null;
    } catch (_) { return null; }
  };
  w[key].endAction = function(actionId) {
    try {
      if (!w[key].currentAction) return true;
      if (!actionId || (w[key].currentAction && String(w[key].currentAction.id) === String(actionId))) {
        w[key].currentAction = null;
        w[key].currentActionExpiresAt = 0;
      }
      return true;
    } catch (_) { return false; }
  };

  function sameOrigin(url) {
    try {
      const u = new URL(url, w.location && w.location.href ? w.location.href : undefined);
      return !!w.location && u.origin === w.location.origin;
    } catch (_) {
      return false;
    }
  }

  function routeLoadSinceAction() {
    try {
      return !!w[key].currentAction && w[key].routeEpoch !== w[key].actionRouteEpoch;
    } catch (_) { return false; }
  }

  function actionHeaderValue() {
    try {
      const a = w[key].currentAction;
      if (!a) return null;
      if (Date.now() > (w[key].currentActionExpiresAt || 0)) return null;
      if (!a.id) return null;
      return String(a.id);
    } catch (_) { return null; }
  }

  function preparing() {
    const p = w[key].preparation;
    return !!p && Date.now() <= p.expiresAt;
  }

  function fnv1aHex(str, seed) {
    let h = (seed >>> 0) || 0x811c9dc5;
    const s = String(str || "");
    for (let i = 0; i < s.length; i++) {
      h ^= (s.charCodeAt(i) & 0xff);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ("00000000" + (h >>> 0).toString(16)).slice(-8);
  }

  function traceIdForAction(id) {
    const s = String(id || "");
    const tid = (
      fnv1aHex(s, 0x811c9dc5) +
      fnv1aHex(s, 0x9e3779b9) +
      fnv1aHex(s, 0x85ebca6b) +
      fnv1aHex(s, 0xc2b2ae35)
    ).toLowerCase();
    return /^0+$/.test(tid) ? "00000000000000000000000000000001" : tid;
  }

  function traceparentForAction(id) {
    const tid = traceIdForAction(id);
    const seq = (typeof w[key].requestsStarted === "number") ? w[key].requestsStarted : 1;
    const sid = (
      fnv1aHex(String(id) + ":" + String(seq), 0x27d4eb2d) +
      fnv1aHex(String(seq), 0x165667b1)
    ).toLowerCase();
    const safeSid = /^0+$/.test(sid) ? "0000000000000001" : sid;
    return "00-" + tid + "-" + safeSid + "-01";
  }

	  // --- DOM + network settle probes ---
		  w[key].pending = 0;
		  w[key].requestsStarted = 0;
		  w[key].wsFramesSent = 0;
		  w[key].wsFramesBlocked = 0;
		  w[key].domMutations = 0;
		  w[key].clipboardWrites = 0;
		  w[key].localStorageWrites = 0;
		  w[key].localStorageClears = 0;
		  w[key].sessionStorageWrites = 0;
		  w[key].sessionStorageClears = 0;
		  w[key].cookieWrites = 0;
		  w[key].locationAssigns = 0;
		  w[key].locationReplaces = 0;
		  w[key].lastDomMutation = Date.now();

	  // Elements whose own text keeps changing while no action is being
	  // observed (clocks, timers, tickers): at least three changes at least
	  // 600ms apart. Effect diffs ignore them, so a ticking clock does not
	  // make a dead button look alive.
	  w[key].tickers = new WeakMap();
	  w[key].isTicker = function(el) {
	    try { const t = w[key].tickers.get(el); return !!t && t.n >= 3; } catch (_) { return false; }
	  };
	  function noteTickers(records) {
	    try {
	      if (w[key].fx) return;
	      const now = Date.now();
	      for (const m of records) {
	        let el = null;
	        if (m.type === "characterData") {
	          el = m.target && m.target.parentElement;
	        } else if (m.type === "childList") {
	          let text = false;
	          for (const n of m.addedNodes) { if (n.nodeType === 3) { text = true; break; } }
	          if (!text) for (const n of m.removedNodes) { if (n.nodeType === 3) { text = true; break; } }
	          if (text) el = m.target;
	        }
	        if (!el || el.nodeType !== 1) continue;
	        const t = w[key].tickers.get(el) || { n: 0, last: 0 };
	        if (now - t.last >= 600) {
	          t.n++;
	          t.last = now;
	          w[key].tickers.set(el, t);
	        }
	      }
	    } catch (_) {}
	  }

	  // DOM mutation tracker (deferred-safe when evaluated at document_start).
	  function ensureObserver() {
	    try {
	      const root = document.documentElement || document.body;
	      if (!root) return false;
	      if (w[key].mo && w[key].moRoot === root) return true;
	      if (w[key].mo) {
	        try { w[key].mo.disconnect(); } catch (_) {}
	      }
	      // Attribute writes that leave the value unchanged (a focusout handler
	      // re-setting aria-expanded="false") are not activity.
	      const mo = new MutationObserver((records) => {
	        noteTickers(records);
	        let real = false;
	        for (const m of records) {
	          if (m.type !== "attributes") { real = true; break; }
	          try {
	            if (m.target.getAttribute(m.attributeName) !== m.oldValue) { real = true; break; }
	          } catch (_) { real = true; break; }
	        }
	        if (!real) return;
	        try {
	          w[key].domMutations = (typeof w[key].domMutations === "number") ? (w[key].domMutations + 1) : 1;
	        } catch (_) {}
	        w[key].lastDomMutation = Date.now();
	      });
	      mo.observe(root, { subtree: true, childList: true, attributes: true, attributeOldValue: true, characterData: true });
	      w[key].mo = mo;
	      w[key].moRoot = root;
	      return true;
	    } catch (_) {
	      return false;
	    }
	  }
	  w[key].ensureObserver = ensureObserver;
	  if (!ensureObserver()) {
	    try {
	      w.addEventListener("DOMContentLoaded", () => {
	        w[key].lastDomMutation = Date.now();
	        ensureObserver();
	      }, { once: true });
	    } catch (_) {}
	  }

	  // Track SPA hashchange / popstate / history API transitions as navigation + settle signals.
	  try {
	    w.addEventListener("hashchange", () => {
	      w[key].lastDomMutation = Date.now();
	      try { w[key].locationAssigns = (typeof w[key].locationAssigns === "number") ? (w[key].locationAssigns + 1) : 1; } catch (_) {}
	    });
	    const routeKey = () => { try { return w.location.pathname + w.location.search; } catch (_) { return ""; } };
	    w.addEventListener("popstate", () => {
	      w[key].lastDomMutation = Date.now();
	      w[key].routeEpoch++;
	    });
	    if (w.history) {
	      if (typeof w.history.pushState === "function" && !w.history.pushState.__brokenappWrapped) {
	        const origPush = w.history.pushState.bind(w.history);
	        const wrappedPush = function() {
	          w[key].lastDomMutation = Date.now();
	          try { w[key].locationAssigns = (typeof w[key].locationAssigns === "number") ? (w[key].locationAssigns + 1) : 1; } catch (_) {}
	          const before = routeKey();
	          const out = origPush.apply(w.history, arguments);
	          if (routeKey() !== before) w[key].routeEpoch++;
	          return out;
	        };
	        try { Object.defineProperty(wrappedPush, "__brokenappWrapped", { value: true }); } catch (_) {}
	        w.history.pushState = wrappedPush;
	      }
	      if (typeof w.history.replaceState === "function" && !w.history.replaceState.__brokenappWrapped) {
	        const origReplace = w.history.replaceState.bind(w.history);
	        const wrappedReplace = function() {
	          w[key].lastDomMutation = Date.now();
	          try { w[key].locationReplaces = (typeof w[key].locationReplaces === "number") ? (w[key].locationReplaces + 1) : 1; } catch (_) {}
	          return origReplace.apply(w.history, arguments);
	        };
	        try { Object.defineProperty(wrappedReplace, "__brokenappWrapped", { value: true }); } catch (_) {}
	        w.history.replaceState = wrappedReplace;
	      }
	    }
	  } catch (_) {}

  // Wrap fetch() to track pending and (when possible) attach action header.
  try {
    const origFetch = w.fetch;
    if (origFetch) {
      w.fetch = async function(input, init) {
        w[key].requestsStarted++;
        w[key].pending++;
        try {
          const id = actionHeaderValue();
          const isRequest = (typeof Request !== "undefined") && (input instanceof Request);
          const url = (typeof input === "string") ? input
            : (isRequest ? input.url : (input && typeof input.href === "string" ? input.href : ""));
          if (preparing() && url && sameOrigin(url)) {
            const base = (init && init.headers !== undefined) ? init.headers
              : (isRequest ? input.headers : undefined);
            const h = new Headers(base);
            // An explicitly stamped delayed action remains its own evidence.
            if (!h.has("x-brokenapp-action-id")) h.set("x-brokenapp-preparation", "1");
            init = Object.assign({}, init || {}, { headers: h });
          } else if (id && url && sameOrigin(url) && routeLoadSinceAction()) {
            const base = (init && init.headers !== undefined) ? init.headers
              : (isRequest ? input.headers : undefined);
            const h = new Headers(base);
            h.set("x-brokenapp-route-load", "1");
            init = Object.assign({}, init || {}, { headers: h });
          } else if (id && url && sameOrigin(url)) {
            // fetch(Request, init): init.headers replaces the Request's own
            // headers; without it the Request's headers apply. Start from
            // whichever wins so Authorization/Content-Type are kept.
            const base = (init && init.headers !== undefined) ? init.headers
              : (isRequest ? input.headers : undefined);
            const h = new Headers(base);
            // Headers.has() is case-insensitive; never duplicate an app's own
            // traceparent (two values make the header invalid).
            if (!h.has("x-brokenapp-action-id")) {
              h.set("x-brokenapp-action-id", id);
            }
            if (!h.has("traceparent")) {
              h.set("traceparent", traceparentForAction(id));
            }
            init = Object.assign({}, init || {}, { headers: h });
          }
          return await origFetch.call(this, input, init);
        } finally {
          w[key].pending--;
        }
      };
    }
  } catch (_) {}

  // Wrap XHR to track pending and attach action header on same-origin requests.
  try {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    const origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function(method, url) {
      try {
        this.__brokenappUrl = url;
        this.__brokenappHeaders = {};
      } catch (_) {}
      return origOpen.apply(this, arguments);
    };
    // Remember which headers the app set (lower-cased) so ours never
    // duplicate them: setRequestHeader appends rather than replaces.
    XMLHttpRequest.prototype.setRequestHeader = function(name) {
      try {
        if (!this.__brokenappHeaders) this.__brokenappHeaders = {};
        this.__brokenappHeaders[String(name).toLowerCase()] = true;
      } catch (_) {}
      return origSetRequestHeader.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function() {
      w[key].requestsStarted++;
      w[key].pending++;
      try {
        const id = actionHeaderValue();
        const url = this.__brokenappUrl ? String(this.__brokenappUrl) : "";
        if (preparing() && url && sameOrigin(url)) {
          const set = this.__brokenappHeaders || {};
          if (!set["x-brokenapp-action-id"] && !set["x-brokenapp-preparation"]) {
            try { origSetRequestHeader.call(this, "x-brokenapp-preparation", "1"); } catch (_) {}
          }
        } else if (id && url && sameOrigin(url) && routeLoadSinceAction()) {
          try { origSetRequestHeader.call(this, "x-brokenapp-route-load", "1"); } catch (_) {}
        } else if (id && url && sameOrigin(url)) {
          const set = this.__brokenappHeaders || {};
          if (!set["x-brokenapp-action-id"]) {
            try { origSetRequestHeader.call(this, "x-brokenapp-action-id", id); } catch (_) {}
          }
          if (!set["traceparent"]) {
            try { origSetRequestHeader.call(this, "traceparent", traceparentForAction(id)); } catch (_) {}
          }
        }
        this.addEventListener("loadend", () => { w[key].pending--; }, { once: true });
        return origSend.apply(this, arguments);
      } catch (e) {
        w[key].pending--;
        throw e;
      }
    };
	  } catch (_) {}

  // navigator.sendBeacon() is a fire-and-forget POST: count it as network
  // activity so a control whose only effect is a beacon is not called dead.
  try {
    const nav = w.navigator;
    if (nav && typeof nav.sendBeacon === "function" && !nav.sendBeacon.__brokenappWrapped) {
      const origBeacon = nav.sendBeacon;
      const wrappedBeacon = function() {
        try { w[key].requestsStarted++; } catch (_) {}
        return origBeacon.apply(nav, arguments);
      };
      try { Object.defineProperty(wrappedBeacon, "__brokenappWrapped", { value: true }); } catch (_) {}
      nav.sendBeacon = wrappedBeacon;
    }
  } catch (_) {}

  // Wrap WebSocket.prototype.send to:
  //   1. Count non-heartbeat outbound frames as network activity so WS-driven
  //      controls are not misclassified as dead/no_effect.
  //   2. Guard mutating WS RPC/GraphQL/command frames when the write guard is
  //      active, reporting each blocked frame to the CDP interceptor without
  //      sending it over the wire.
  try {
    const wsProto = w.WebSocket && w.WebSocket.prototype;
    if (wsProto && typeof wsProto.send === "function" && !wsProto.send.__brokenappWrapped) {
      const WS_HEARTBEAT = new Set([
        "ping","pong","hb","heartbeat","keepalive","keep_alive","keep-alive",
        "ack","connection_init","connection_ack","ka","hello","interrupt",
        "complete","phx_join","phx_leave","phx_close","unsubscribe","unwatch"
      ]);
      const WS_READ_VERBS = new Set([
        "get","list","fetch","read","load","query","search","find","check",
        "describe","inspect","status","health","version","subscribe","unsubscribe",
        "watch","unwatch","listen","poll","diff","preview","count","exists",
        "validate","refresh","snapshot","info","meta","whoami","me","ping","pong","heartbeat"
      ]);
      const WS_MUTATION_VERBS = new Set([
        "create","update","upsert","delete","remove","destroy","drop","insert",
        "add","put","patch","post","set","save","write","submit","send","dispatch",
        "exec","execute","run","start","stop","kill","restart","cancel","abort",
        "revoke","logout","signout","archive","restore","rename","move","copy",
        "clone","merge","publish","unpublish","approve","reject","toggle","enable",
        "disable","pin","unpin","open","spawn","apply","reset","clear","flush",
        "purge","import","upload","checkout","pay","charge","refund","transfer",
        "invite","ban","kick","mute","mutate","mutation","buy","order","place",
        "book","reserve","edit","modify","change","assign","unassign","complete",
        "reopen","lock","unlock","grant","deny","promote","demote","trigger",
        "commit","push","pull","stash","branch","install","uninstall","upgrade",
        "downgrade","download","pair","unpair","connect","disconnect","reconnect",
        "login","signin","signup","register","settle","unsettle","snooze","wake",
        "mark","unarchive","fork","rebase","revert","amend","stage","unstage",
        "discard","clean","init","setup","configure","switch"
      ]);
      const wsGlobMatch = (pattern, text) => {
        const p = String(pattern || ""), t = String(text || "");
        let pi = 0, ti = 0, starP = -1, starT = 0;
        while (ti < t.length) {
          if (pi < p.length && p[pi] === "*") { starP = pi++; starT = ti; }
          else if (pi < p.length && p[pi] === t[ti]) { pi++; ti++; }
          else if (starP >= 0) { pi = starP + 1; ti = ++starT; }
          else return false;
        }
        while (pi < p.length && p[pi] === "*") pi++;
        return pi === p.length;
      };
      const wsAllowMatches = (pattern, url, op) => {
        const p = String(pattern || "").trim();
        if (!p) return false;
        const parts = p.split(/\s+/);
        let method = "*", urlPat = p;
        if (parts.length >= 2) { method = parts[0].toUpperCase(); urlPat = parts.slice(1).join(" "); }
        if (method !== "*" && method !== "WS" && method !== "WEBSOCKET") return false;
        const targetWithOp = op ? (url + '#' + op) : url;
        if (wsGlobMatch(urlPat, url) || wsGlobMatch(urlPat, targetWithOp)) return true;
        try {
          const u = new URL(url);
          const pathWithOp = op ? (u.pathname + '#' + op) : u.pathname;
          return wsGlobMatch(urlPat, u.pathname) || wsGlobMatch(urlPat, pathWithOp);
        } catch (_) { return false; }
      };
      const isDevWs = (ws) => {
        try {
          if (String(ws.protocol || "").toLowerCase() === "vite-hmr") return true;
          const u = new URL(ws.url || "", w.location ? w.location.href : undefined);
          const p = (u.pathname || "").toLowerCase();
          return p === "/_next/webpack-hmr" || p.startsWith("/_next/webpack-hmr/")
            || p.startsWith("/__nextjs") || p.startsWith("/__webpack")
            || p.startsWith("/__vite") || p.startsWith("/@vite/")
            || p.startsWith("/@react-refresh") || p.startsWith("/__turbopack")
            || p.includes("/sockjs-node") || p.includes("/webpack-dev-server")
            || p.includes("/_hmr");
        } catch (_) { return false; }
      };
      const wsTokens = (op) => {
        const out = [];
        let cur = "", prevLower = false;
        for (const ch of String(op || "")) {
          if (!/[A-Za-z0-9]/.test(ch)) {
            if (cur) { out.push(cur); cur = ""; }
            prevLower = false;
            continue;
          }
          if (ch >= "A" && ch <= "Z" && prevLower && cur) {
            out.push(cur);
            cur = "";
          }
          cur += ch.toLowerCase();
          prevLower = (ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9");
        }
        if (cur) out.push(cur);
        return out;
      };
      const wsIsHeartbeat = (trimmed) => {
        if (!trimmed) return true;
        if (trimmed === "2" || trimmed === "3" || trimmed === "2probe" || trimmed === "3probe"
            || trimmed === "0" || trimmed === "40" || trimmed === "41" || trimmed === "5") return true;
        if (WS_HEARTBEAT.has(trimmed.toLowerCase())) return true;
        if (trimmed[0] === "{") {
          try {
            const obj = JSON.parse(trimmed);
            if (obj && typeof obj === "object" && !Array.isArray(obj)) {
              for (const k of ["type","_tag","event","op","action","method","command"]) {
                if (typeof obj[k] === "string" && WS_HEARTBEAT.has(obj[k].trim().toLowerCase())) return true;
              }
            }
          } catch (_) {}
        }
        return false;
      };
      const wsExtractOp = (trimmed) => {
        if (trimmed.startsWith("42")) {
          const idx = trimmed.indexOf("[");
          if (idx >= 0) {
            try {
              const arr = JSON.parse(trimmed.slice(idx));
              if (Array.isArray(arr) && typeof arr[0] === "string") return { op: arr[0].trim(), gql: null };
            } catch (_) {}
          }
        }
        let val;
        try { val = JSON.parse(trimmed); } catch (_) { return { op: null, gql: null }; }
        if (Array.isArray(val)) {
          if (val.length >= 4 && typeof val[2] === "string" && typeof val[3] === "string") {
            return { op: val[2] + ":" + val[3], gql: null };
          }
          val = val[0];
        }
        if (!val || typeof val !== "object" || Array.isArray(val)) return { op: null, gql: null };
        const gql = (val.payload && typeof val.payload.query === "string") ? val.payload.query
          : (typeof val.query === "string" ? val.query : null);
        if (gql) {
          const opName = (val.payload && typeof val.payload.operationName === "string" && val.payload.operationName.trim())
            || (typeof val.operationName === "string" && val.operationName.trim()) || "";
          const ql = gql.trimStart().toLowerCase();
          const kind = (ql.startsWith("mutation") || ql.includes("mutation ") || ql.includes("mutation{"))
            ? "MUTATION" : (ql.startsWith("subscription") ? "SUBSCRIPTION" : "QUERY");
          return { op: opName ? (kind + ":" + opName) : kind, gql };
        }
        if (val._tag === "Request" && typeof val.tag === "string" && val.tag.trim()) {
          return { op: val.tag.trim(), gql: null };
        }
        if (typeof val.method === "string" && val.params && typeof val.params.path === "string") {
          const m = val.method.trim().toLowerCase();
          if (m === "mutation" || m === "query" || m === "subscription") {
            return { op: m + ":" + val.params.path.trim(), gql: null };
          }
        }
        for (const k of ["method","tag","action","command","cmd","op","event","path","route","topic","type","_tag"]) {
          if (typeof val[k] === "string") {
            const s = val[k].trim();
            const sl = s.toLowerCase();
            if (!s || sl === "request" || sl === "message" || sl === "rpc" || sl === "call" || sl === "data" || sl === "next") continue;
            return { op: s, gql: null };
          }
        }
        return { op: null, gql: null };
      };
      const wsClassify = (trimmed) => {
        if (wsIsHeartbeat(trimmed)) return { cls: "heartbeat", op: null };
        const { op, gql } = wsExtractOp(trimmed);
        if (gql) {
          const ql = gql.trimStart().toLowerCase();
          const isMut = ql.startsWith("mutation") || ql.includes("mutation ") || ql.includes("mutation{");
          return { cls: isMut ? "mutation" : "read", op };
        }
        if (!op) return { cls: "unknown", op: null };
        const opl = op.toLowerCase();
        if (opl === "mutation" || opl.startsWith("mutation:")) return { cls: "mutation", op };
        if (opl === "query" || opl.startsWith("query:") || opl === "subscription" || opl.startsWith("subscription:")) return { cls: "read", op };
        const toks = wsTokens(op);
        if (toks.some(t => WS_HEARTBEAT.has(t))) return { cls: "heartbeat", op };
        const segs = op.split(/[./:]/).filter(Boolean);
        const lastSeg = segs.length ? segs[segs.length - 1] : op;
        const segToks = wsTokens(lastSeg);
        if (segToks.length) {
          if (WS_READ_VERBS.has(segToks[0])) return { cls: "read", op };
          if (WS_MUTATION_VERBS.has(segToks[0])) return { cls: "mutation", op };
        }
        if (toks.some(t => WS_MUTATION_VERBS.has(t))) return { cls: "mutation", op };
        if (toks.some(t => WS_READ_VERBS.has(t))) return { cls: "read", op };
        return { cls: "unknown", op };
      };
      const decodeWsText = (data) => {
        if (typeof data === "string") return data;
        try {
          if (typeof TextDecoder !== "undefined" && (data instanceof ArrayBuffer || ArrayBuffer.isView(data))) {
            const len = data.byteLength || 0;
            if (len > 0 && len <= 65536) {
              const txt = new TextDecoder("utf-8", { fatal: true }).decode(data);
              if (txt && txt.trim().length > 0) return txt;
            }
          }
        } catch (_) {}
        return null;
      };
      const wsHostAllowed = (rawUrl) => {
        const cfg = w.__BROKENAPP_WS_GUARD || {};
        const allowedHosts = Array.isArray(cfg.allowedHosts) ? cfg.allowedHosts : [];
        if (allowedHosts.length === 0) return true;
        try {
          const parsed = new URL(String(rawUrl || ""), w.location ? w.location.href : undefined);
          if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:" && parsed.protocol !== "http:" && parsed.protocol !== "https:") {
            return true;
          }
          const host = String(parsed.hostname || "").toLowerCase().replace(/\.$/, "");
          if (!host) return false;
          return allowedHosts.some((rawPat) => {
            const pat = String(rawPat || "").trim().toLowerCase().replace(/\.$/, "").replace(/:[0-9]+$/, "");
            if (!pat) return false;
            if (pat.startsWith("*.")) {
              const suffix = pat.slice(2);
              return suffix.length > 0 && host.length > suffix.length + 1 && host.endsWith("." + suffix);
            }
            return host === pat;
          });
        } catch (_) {
          return false;
        }
      };
      if (typeof w.WebSocket === "function" && !w.WebSocket.__brokenappCtorWrapped) {
        const OrigWebSocket = w.WebSocket;
        const WrappedWebSocket = function(url, protocols) {
          if (!wsHostAllowed(url)) {
            w[key].wsFramesBlocked = (w[key].wsFramesBlocked || 0) + 1;
            const msg = "Blocked WebSocket connection outside allowed_hosts: " + String(url || "");
            if (typeof DOMException !== "undefined") {
              throw new DOMException(msg, "SecurityError");
            }
            throw new Error(msg);
          }
          return arguments.length > 1
            ? new OrigWebSocket(url, protocols)
            : new OrigWebSocket(url);
        };
        WrappedWebSocket.prototype = OrigWebSocket.prototype;
        WrappedWebSocket.CONNECTING = OrigWebSocket.CONNECTING;
        WrappedWebSocket.OPEN = OrigWebSocket.OPEN;
        WrappedWebSocket.CLOSING = OrigWebSocket.CLOSING;
        WrappedWebSocket.CLOSED = OrigWebSocket.CLOSED;
        try { Object.setPrototypeOf(WrappedWebSocket, OrigWebSocket); } catch (_) {}
        try { Object.defineProperty(WrappedWebSocket, "__brokenappCtorWrapped", { value: true }); } catch (_) {}
        w.WebSocket = WrappedWebSocket;
      }
      const origWsSend = wsProto.send;
      const wrappedWsSend = function(data) {
        try {
          if (isDevWs(this)) return origWsSend.apply(this, arguments);
          const url = String(this.url || "");
          const actionId = actionHeaderValue();
          const decoded = decodeWsText(data);
          if (decoded === null) {
            const size = (data && (data.byteLength || data.size)) || 0;
            if (size > 0) {
              w[key].wsFramesSent = (w[key].wsFramesSent || 0) + 1;
              // Fail closed for opaque binary frames sent during an active UI
              // interaction while the write guard is on (unless allowlisted).
              if (w.__BROKENAPP_WRITE_GUARD === true && actionId) {
                const cfg = w.__BROKENAPP_WS_GUARD || {};
                const allow = Array.isArray(cfg.allow) ? cfg.allow : [];
                if (!allow.some(pat => wsAllowMatches(pat, url, "binary"))) {
                  w[key].wsFramesBlocked = (w[key].wsFramesBlocked || 0) + 1;
                  if (typeof w.__brokenappWsGuardReport === "function") {
                    try {
                      w.__brokenappWsGuardReport(JSON.stringify({
                        url,
                        op: "binary",
                        payload: "<binary:" + size + "B>",
                        actionId,
                        routeLoad: routeLoadSinceAction(),
                        preparing: preparing()
                      }));
                    } catch (_) {}
                  }
                  return undefined;
                }
              }
            }
            return origWsSend.apply(this, arguments);
          }
          const trimmed = decoded.trim();
          const info = wsClassify(trimmed);
          if (info.cls === "heartbeat") return origWsSend.apply(this, arguments);
          w[key].wsFramesSent = (w[key].wsFramesSent || 0) + 1;
          // Block recognized mutations at any time (including debounced/autosave
          // timers), and fail closed on unrecognized non-read frames sent during
          // an active UI interaction so custom WS RPC names cannot leak writes.
          const shouldGuard = info.cls === "mutation" || (info.cls === "unknown" && !!actionId);
          if (w.__BROKENAPP_WRITE_GUARD === true && shouldGuard) {
            const cfg = w.__BROKENAPP_WS_GUARD || {};
            const allow = Array.isArray(cfg.allow) ? cfg.allow : [];
            const allowed = allow.some(pat => wsAllowMatches(pat, url, info.op));
            if (!allowed) {
              w[key].wsFramesBlocked = (w[key].wsFramesBlocked || 0) + 1;
              if (typeof w.__brokenappWsGuardReport === "function") {
                try {
                  w.__brokenappWsGuardReport(JSON.stringify({
                    url,
                    op: info.op || null,
                    payload: decoded.slice(0, 4096),
                    actionId,
                    routeLoad: routeLoadSinceAction(),
                    preparing: preparing()
                  }));
                } catch (_) {}
              }
              return undefined;
            }
          }
        } catch (_) {}
        return origWsSend.apply(this, arguments);
      };
      try { Object.defineProperty(wrappedWsSend, "__brokenappWrapped", { value: true }); } catch (_) {}
      wsProto.send = wrappedWsSend;
    }
  } catch (_) {}

  // Native form submissions are requests too. Under the write guard a
  // native POST is answered with 204 and the page stays put, so without this
  // the submitting control would look dead. Count programmatic submit() and
  // submit events whose default (the native request) was not prevented.
  //
  // The write guard (window.__BROKENAPP_WRITE_GUARD, set by the network
  // interceptor) only watches this page: a POST form aimed at a new window
  // (target=_blank or an unknown window name) would escape it, so keep such
  // submissions in this page.
  try {
    const opensNewContext = (target) => {
      const name = String(target || "").trim();
      if (!name || /^_(self|parent|top)$/i.test(name)) return false;
      if (/^_blank$/i.test(name)) return true;
      try {
        const sel = 'iframe[name="' + CSS.escape(name) + '"], frame[name="' + CSS.escape(name) + '"]';
        return !document.querySelector(sel);
      } catch (_) { return true; }
    };
    const keepPostInPage = (form, submitter) => {
      try {
        if (w.__BROKENAPP_WRITE_GUARD !== true || !form || !form.getAttribute) return;
        const fromSubmitter = submitter && submitter.getAttribute ? submitter.getAttribute("formmethod") : null;
        const method = String(fromSubmitter || form.getAttribute("method") || "get").toLowerCase();
        if (method !== "post") return;
        if (submitter && submitter.hasAttribute && submitter.hasAttribute("formtarget")
            && opensNewContext(submitter.getAttribute("formtarget"))) {
          submitter.setAttribute("formtarget", "_self");
        }
        if (opensNewContext(form.getAttribute("target"))) form.setAttribute("target", "_self");
      } catch (_) {}
    };
    const formProto = w.HTMLFormElement && w.HTMLFormElement.prototype;
    if (formProto && typeof formProto.submit === "function" && !formProto.submit.__brokenappWrapped) {
      const origSubmit = formProto.submit;
      const wrappedSubmit = function() {
        try { w[key].requestsStarted++; } catch (_) {}
        keepPostInPage(this, null);
        return origSubmit.apply(this, arguments);
      };
      try { Object.defineProperty(wrappedSubmit, "__brokenappWrapped", { value: true }); } catch (_) {}
      formProto.submit = wrappedSubmit;
    }
    w.addEventListener("submit", (ev) => {
      keepPostInPage(ev.target, ev.submitter);
      setTimeout(() => {
        try { if (!ev.defaultPrevented) w[key].requestsStarted++; } catch (_) {}
      }, 0);
    }, true);
  } catch (_) {}

	  // Clipboard writes are a legitimate passive side effect: many copy buttons
	  // intentionally leave the DOM unchanged. Count attempts so the scanner
	  // does not report a wired copy action as a dead button when headless
	  // clipboard permissions are restrictive.
	  try {
	    const clip = navigator && navigator.clipboard;
	    if (clip && typeof clip.writeText === "function" && !clip.writeText.__brokenappWrapped) {
	      const origWriteText = clip.writeText.bind(clip);
	      const wrappedWriteText = function() {
	        try { w[key].clipboardWrites = (typeof w[key].clipboardWrites === "number") ? (w[key].clipboardWrites + 1) : 1; } catch (_) {}
	        return origWriteText.apply(clip, arguments);
	      };
	      try { Object.defineProperty(wrappedWriteText, "__brokenappWrapped", { value: true }); } catch (_) {}
	      clip.writeText = wrappedWriteText;
	    }
	    if (clip && typeof clip.write === "function" && !clip.write.__brokenappWrapped) {
	      const origWrite = clip.write.bind(clip);
	      const wrappedWrite = function() {
	        try { w[key].clipboardWrites = (typeof w[key].clipboardWrites === "number") ? (w[key].clipboardWrites + 1) : 1; } catch (_) {}
	        return origWrite.apply(clip, arguments);
	      };
	      try { Object.defineProperty(wrappedWrite, "__brokenappWrapped", { value: true }); } catch (_) {}
	      clip.write = wrappedWrite;
	    }
	  } catch (_) {}
	  try {
	    const docProto = w.Document && w.Document.prototype;
	    if (docProto && typeof docProto.execCommand === "function" && !docProto.execCommand.__brokenappWrapped) {
	      const origExec = docProto.execCommand;
	      const wrappedExec = function(command) {
	        try {
	          const c = String(command || "").toLowerCase();
	          if (c === "copy" || c === "cut") w[key].clipboardWrites = (typeof w[key].clipboardWrites === "number") ? (w[key].clipboardWrites + 1) : 1;
	        } catch (_) {}
	        return origExec.apply(this, arguments);
	      };
	      try { Object.defineProperty(wrappedExec, "__brokenappWrapped", { value: true }); } catch (_) {}
	      docProto.execCommand = wrappedExec;
	    }
	  } catch (_) {}

	  function bumpCounter(name) {
	    try { w[key][name] = (typeof w[key][name] === "number") ? (w[key][name] + 1) : 1; } catch (_) {}
	  }

	  // --- Interaction evidence ---
	  // While the crawler has an evidence window armed (`armFx`), remember the
	  // first click's target (capture phase, so it is seen even when the app
	  // stops propagation) and every element that scrolled. A click whose
	  // target is outside the control (an overlay, a clickable row ancestor)
	  // must not be credited with what that other element did.
	  w[key].fx = null;
	  w[key].armFx = function() {
	    w[key].fx = { clickTarget: null, clickTrusted: false, clicks: 0, scrolls: 0, scrollTargets: [], invalid: 0 };
	    return true;
	  };
	  w[key].takeFx = function() {
	    const fx = w[key].fx;
	    w[key].fx = null;
	    return fx;
	  };
	  w[key].prints = 0;
	  w[key].windowOpens = 0;
	  w[key].lastWindowOpen = null;
	  w[key].downloads = 0;
	  try {
	    w.addEventListener("click", function(ev) {
	      const fx = w[key].fx;
	      if (fx) {
	        // The crawler's own (trusted) click decides; a synthetic click
	        // the page dispatches is only used when no trusted one was seen.
	        if (ev.isTrusted && !fx.clickTrusted) {
	          fx.clickTarget = ev.target || null;
	          fx.clickTrusted = true;
	        } else if (fx.clicks === 0) {
	          fx.clickTarget = ev.target || null;
	        }
	        fx.clicks++;
	      }
	      try {
	        const t = ev.target;
	        const a = t && t.closest ? t.closest("a[download]") : null;
	        if (a) bumpCounter("downloads");
	        // A click on a file input (or its label) opens the file chooser.
	        const label = t && t.closest ? t.closest("label") : null;
	        const field = (t && t.matches && t.matches("input")) ? t : (label ? label.control : null);
	        if (ev.isTrusted && field && String(field.type || "").toLowerCase() === "file") bumpCounter("fileChoosers");
	      } catch (_) {}
	    }, true);
	    // The browser refused to submit a form and showed a validation
	    // message (`invalid` does not bubble; the capture phase sees it).
	    w.addEventListener("invalid", function() {
	      const fx = w[key].fx;
	      if (fx) fx.invalid = (fx.invalid || 0) + 1;
	    }, true);
	    w.addEventListener("scroll", function(ev) {
	      const fx = w[key].fx;
	      if (!fx) return;
	      fx.scrolls++;
	      if (fx.scrollTargets.length < 20 && fx.scrollTargets.indexOf(ev.target) < 0) fx.scrollTargets.push(ev.target);
	    }, { capture: true, passive: true });
	  } catch (_) {}

	  // window.print() / window.open(): count the call and do not open a print
	  // dialog or a new window (a dialog blocks a headful page; a new window
	  // would escape this page's write guard).
	  try {
	    if (typeof w.print === "function" && !w.print.__brokenappWrapped) {
	      const wrappedPrint = function() { bumpCounter("prints"); };
	      try { Object.defineProperty(wrappedPrint, "__brokenappWrapped", { value: true }); } catch (_) {}
	      w.print = wrappedPrint;
	    }
	    if (typeof w.open === "function" && !w.open.__brokenappWrapped) {
	      // An inert stand-in for the opened window, so handlers that use it
	      // (`window.open(url).focus()`, print-preview windows written with
	      // document.write) do not throw where a real open would succeed.
	      const inertWindow = function() {
	        const noop = function() {};
	        const doc = { write: noop, writeln: noop, open: noop, close: noop, title: "", body: null };
	        return {
	          closed: false,
	          opener: null,
	          document: doc,
	          location: { href: "about:blank", assign: noop, replace: noop, reload: noop },
	          focus: noop,
	          blur: noop,
	          print: noop,
	          postMessage: noop,
	          addEventListener: noop,
	          removeEventListener: noop,
	          close: function() { this.closed = true; }
	        };
	      };
	      const wrappedOpen = function(url) {
	        bumpCounter("windowOpens");
	        try { w[key].lastWindowOpen = url == null ? "" : String(url); } catch (_) {}
	        return inertWindow();
	      };
	      try { Object.defineProperty(wrappedOpen, "__brokenappWrapped", { value: true }); } catch (_) {}
	      w.open = wrappedOpen;
	    }
	  } catch (_) {}

	  // Programmatic file choosers (`fileInput.click()`, `showPicker()`): count
	  // them and do not open a native dialog.
	  try {
	    const inputProto = w.HTMLInputElement && w.HTMLInputElement.prototype;
	    const isFile = (el) => { try { return String(el.type || "").toLowerCase() === "file"; } catch (_) { return false; } };
	    if (inputProto && typeof inputProto.click === "function" && !inputProto.click.__brokenappWrapped) {
	      const origInputClick = inputProto.click;
	      const wrappedInputClick = function() {
	        if (isFile(this)) { bumpCounter("fileChoosers"); return; }
	        return origInputClick.apply(this, arguments);
	      };
	      try { Object.defineProperty(wrappedInputClick, "__brokenappWrapped", { value: true }); } catch (_) {}
	      inputProto.click = wrappedInputClick;
	    }
	    if (inputProto && typeof inputProto.showPicker === "function" && !inputProto.showPicker.__brokenappWrapped) {
	      const origPicker = inputProto.showPicker;
	      const wrappedPicker = function() {
	        if (isFile(this)) { bumpCounter("fileChoosers"); return; }
	        return origPicker.apply(this, arguments);
	      };
	      try { Object.defineProperty(wrappedPicker, "__brokenappWrapped", { value: true }); } catch (_) {}
	      inputProto.showPicker = wrappedPicker;
	    }
	  } catch (_) {}

	  // Programmatic downloads: `a.click()` on a detached `<a download>` or a
	  // blob:/data: link never reaches the capture listener above.
	  try {
	    const anchorProto = w.HTMLAnchorElement && w.HTMLAnchorElement.prototype;
	    if (anchorProto && typeof anchorProto.click === "function" && !anchorProto.click.__brokenappWrapped) {
	      const origAnchorClick = anchorProto.click;
	      const wrappedAnchorClick = function() {
	        try {
	          const href = String(this.getAttribute("href") || "");
	          if (!this.isConnected && (this.hasAttribute("download") || /^(blob|data):/i.test(href))) bumpCounter("downloads");
	        } catch (_) {}
	        return origAnchorClick.apply(this, arguments);
	      };
	      try { Object.defineProperty(wrappedAnchorClick, "__brokenappWrapped", { value: true }); } catch (_) {}
	      anchorProto.click = wrappedAnchorClick;
	    }
	  } catch (_) {}

	  // Storage/cookie/location side effects often do not leave visible DOM
	  // evidence. Count attempts without collecting keys or values.
	  try {
	    const proto = w.Storage && w.Storage.prototype;
	    if (proto && !proto.__brokenappStorageWrapped) {
	      const origSetItem = proto.setItem;
	      const origRemoveItem = proto.removeItem;
	      const origClear = proto.clear;
	      function storageName(storage) {
	        try { if (storage === w.localStorage) return "local"; } catch (_) {}
	        try { if (storage === w.sessionStorage) return "session"; } catch (_) {}
	        return null;
	      }
	      if (typeof origSetItem === "function") {
	        proto.setItem = function() {
	          const name = storageName(this);
	          if (name === "local") bumpCounter("localStorageWrites");
	          if (name === "session") bumpCounter("sessionStorageWrites");
	          return origSetItem.apply(this, arguments);
	        };
	      }
	      if (typeof origRemoveItem === "function") {
	        proto.removeItem = function() {
	          const name = storageName(this);
	          if (name === "local") bumpCounter("localStorageWrites");
	          if (name === "session") bumpCounter("sessionStorageWrites");
	          return origRemoveItem.apply(this, arguments);
	        };
	      }
	      if (typeof origClear === "function") {
	        proto.clear = function() {
	          const name = storageName(this);
	          if (name === "local") bumpCounter("localStorageClears");
	          if (name === "session") bumpCounter("sessionStorageClears");
	          return origClear.apply(this, arguments);
	        };
	      }
	      try { Object.defineProperty(proto, "__brokenappStorageWrapped", { value: true }); } catch (_) {}
	    }
	  } catch (_) {}

	  try {
	    const docProto = Document.prototype;
	    const desc = Object.getOwnPropertyDescriptor(docProto, "cookie") ||
	      Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");
	    if (desc && desc.set && !docProto.__brokenappCookieWrapped) {
	      Object.defineProperty(docProto, "cookie", {
	        configurable: true,
	        enumerable: desc.enumerable,
	        get: desc.get ? function() { return desc.get.call(this); } : undefined,
	        set: function(value) {
	          bumpCounter("cookieWrites");
	          return desc.set.call(this, value);
	        }
	      });
	      try { Object.defineProperty(docProto, "__brokenappCookieWrapped", { value: true }); } catch (_) {}
	    }
	  } catch (_) {}

	  try {
	    const loc = w.location;
	    if (loc && typeof loc.assign === "function" && !loc.assign.__brokenappWrapped) {
	      const origAssign = loc.assign.bind(loc);
	      const wrappedAssign = function() {
	        bumpCounter("locationAssigns");
	        return origAssign.apply(loc, arguments);
	      };
	      try { Object.defineProperty(wrappedAssign, "__brokenappWrapped", { value: true }); } catch (_) {}
	      loc.assign = wrappedAssign;
	    }
	  } catch (_) {}

	  try {
	    const loc = w.location;
	    if (loc && typeof loc.replace === "function" && !loc.replace.__brokenappWrapped) {
	      const origReplace = loc.replace.bind(loc);
	      const wrappedReplace = function() {
	        bumpCounter("locationReplaces");
	        return origReplace.apply(loc, arguments);
	      };
	      try { Object.defineProperty(wrappedReplace, "__brokenappWrapped", { value: true }); } catch (_) {}
	      loc.replace = wrappedReplace;
	    }
	  } catch (_) {}
	
	  w[key].installed = true;
	  return true;
	})()
"#;

pub async fn install_instrumentation(page: &PageClient) -> Result<()> {
    // Keep the injected script small and side-effect aware. We do not collect any app data.
    //
    // IMPORTANT: This must survive navigations. We install it via
    // Page.addScriptToEvaluateOnNewDocument and also run it immediately.
    let script = INSTRUMENTATION_JS;

    let params = cdp_page::AddScriptToEvaluateOnNewDocumentParams::builder()
        .source(script)
        .run_immediately(true)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    page.inner()
        .execute(params)
        .await
        .context("Page.addScriptToEvaluateOnNewDocument (instrumentation)")?;
    if let Err(err) = install_source_annotation_stash(page).await {
        tracing::debug!("source annotation stash not installed: {err:#}");
    }
    Ok(())
}

/// Run the instrumentation in the current document when it is missing
/// (pages not set up by the explorer). Unlike [`install_instrumentation`]
/// this does not register another new-document script.
pub async fn ensure_instrumentation(page: &PageClient) -> Result<()> {
    let installed = page
        .evaluate_json::<bool>("Boolean(window.__BROKENAPP && window.__BROKENAPP.installed)")
        .await
        .unwrap_or(false);
    if installed {
        return Ok(());
    }
    let _: bool = page
        .evaluate_json(INSTRUMENTATION_JS)
        .await
        .context("run instrumentation in the current document")?;
    Ok(())
}

/// Wait until the page is quiet: no DOM mutation for a short window, no
/// in-page fetch/XHR in flight and no same-origin script/module load in
/// flight (route chunks), stable for a moment. Returns at `timeout` at the
/// latest.
pub async fn settle(page: &PageClient, timeout: Duration) -> Result<SettleStats> {
    let start = Instant::now();
    let quiet_dom_ms = 300_u64;
    let stable_for_ms = 500_u64;

    let mut stable_since: Option<Instant> = None;

    loop {
        if start.elapsed() > timeout {
            let stats = read_settle_stats(page).await.unwrap_or(SettleStats {
                pending_requests: 0,
                ms_since_last_dom_mutation: 0,
            });
            return Ok(stats);
        }

        let stats = read_settle_stats(page).await.unwrap_or(SettleStats {
            pending_requests: 0,
            ms_since_last_dom_mutation: 0,
        });

        let dom_quiet = stats.ms_since_last_dom_mutation >= quiet_dom_ms;
        let no_pending = stats.pending_requests == 0;
        if dom_quiet && no_pending {
            match stable_since {
                Some(since) if since.elapsed() >= Duration::from_millis(stable_for_ms) => {
                    return Ok(stats);
                }
                Some(_) => {}
                None => stable_since = Some(Instant::now()),
            }
        } else {
            stable_since = None;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until no DOM mutation happened for `quiet` and no request or route
/// chunk is in flight, at most `max`. Cheaper than [`settle`]: returns at
/// once on a page that is already quiet.
pub async fn wait_quiet(page: &PageClient, quiet: Duration, max: Duration) {
    let start = Instant::now();
    loop {
        let Ok(stats) = read_settle_stats(page).await else {
            return;
        };
        let quiet_ms = u64::try_from(quiet.as_millis()).unwrap_or(u64::MAX);
        if stats.pending_requests == 0 && stats.ms_since_last_dom_mutation >= quiet_ms {
            return;
        }
        if start.elapsed() >= max {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Longest extra wait [`settle_page`] spends on lazy content after `timeout`.
const PAGE_CONTENT_WAIT_MAX: Duration = Duration::from_secs(6);

/// Settle after a page load or reload. Like [`settle`], then keep waiting
/// (bounded by [`PAGE_CONTENT_WAIT_MAX`]) while route chunks are still
/// loading or the main content is empty or shows a loading fallback
/// (Suspense spinner, `aria-busy`, "Loading…"): lazy routes render their
/// controls only after a dynamic `import()` resolves.
pub async fn settle_page(page: &PageClient, timeout: Duration) -> Result<SettleStats> {
    let deadline = Instant::now() + timeout + PAGE_CONTENT_WAIT_MAX;
    let mut stats = settle(page, timeout).await?;
    loop {
        let scripts = page.pending_script_loads();
        let content = page
            .evaluate_json::<ContentState>(CONTENT_STATE_JS)
            .await
            .unwrap_or_default();
        if scripts == 0 && content.ready {
            return Ok(stats);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tracing::debug!(
                scripts,
                content_ready = content.ready,
                "page content still loading at the settle deadline"
            );
            return Ok(stats);
        }
        tokio::time::sleep(Duration::from_millis(200).min(remaining)).await;
        let remaining = deadline.saturating_duration_since(Instant::now());
        stats = settle(page, remaining.min(Duration::from_millis(1500))).await?;
    }
}

#[derive(Debug, serde::Deserialize)]
struct ContentState {
    ready: bool,
}

impl Default for ContentState {
    fn default() -> Self {
        Self { ready: true }
    }
}

/// Is the page's main content rendered? `false` while `<main>` (or the app
/// root) is empty or only shows a loading fallback.
const CONTENT_STATE_JS: &str = r#"
(() => {
  try {
    const main = document.querySelector('main, [role="main"]')
      || document.querySelector('#root, #app, #__next, #svelte, [data-reactroot]');
    if (!main) return { ready: true };
    const loading = '[aria-busy="true"], [role="progressbar"], [data-loading="true"], .spinner, .loading, [class*="skeleton" i], [class*="spinner" i], [class*="suspense" i]';
    const busy = (main.matches && main.matches('[aria-busy="true"]')) || !!main.querySelector(loading);
    const text = String(main.innerText || '').replace(/\s+/g, ' ').trim();
    const hasContent = !!main.querySelector('a[href], button, input, select, textarea, [role="button"], img, svg, canvas, video, iframe, table');
    if (!text && !hasContent) return { ready: false };
    const loadingText = /^(loading|please wait|one moment)\b/i.test(text);
    // Suspense fallbacks also use role=status with text such as "Opening
    // workspace…". Ordinary status text and useful short pages remain ready.
    const openingStatus = !!main.querySelector('[role="status"]')
      && /^(opening|preparing|starting)\s+(workspace|page|screen|view|app(?:lication)?)\b/i.test(text);
    if (text.length < 40 && (loadingText || openingStatus) && !main.querySelector('button, input, select, textarea, a[href]')) {
      return { ready: false };
    }
    if (busy && text.length < 200) return { ready: false };
    return { ready: true };
  } catch (_) {
    return { ready: true };
  }
})()
"#;

#[derive(Debug, Clone, Serialize)]
pub struct ActionProbe {
    pub id: String,
    pub view: String,
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub kind: String,
}

/// Mark only same-origin fetch/XHR started while synthetic preparation runs.
/// This request-start stamp survives delayed CDP delivery into the next action.
pub async fn begin_preparation(page: &PageClient, id: &str, ttl_ms: u64) -> Result<()> {
    ensure_instrumentation(page).await?;
    let id = serde_json::to_string(id)?;
    let script = format!(
        r#"(() => {{
      const p = window.__BROKENAPP;
      if (!p || !p.installed) return false;
      p.currentAction = null;
      p.currentActionExpiresAt = 0;
      p.preparation = {{ id: {id}, expiresAt: Date.now() + {ttl_ms} }};
      return true;
    }})()"#
    );
    anyhow::ensure!(
        page.evaluate_json::<bool>(&script).await?,
        "preparation probe unavailable"
    );
    Ok(())
}

pub async fn end_preparation(page: &PageClient, id: &str) -> Result<()> {
    let id = serde_json::to_string(id)?;
    let script = format!(
        r#"(() => {{
      const p = window.__BROKENAPP;
      // A new document has no old preparation state to clear.
      if (p && p.preparation && p.preparation.id === {id}) p.preparation = null;
      return true;
    }})()"#
    );
    anyhow::ensure!(
        page.evaluate_json::<bool>(&script).await?,
        "preparation probe cleanup failed"
    );
    Ok(())
}

pub async fn begin_action(page: &PageClient, action: &ActionProbe, ttl_ms: u64) -> Result<()> {
    let action_json = serde_json::to_string(action).context("serialize action probe")?;
    let script = format!(
        r#"
(() => {{
  try {{
    const key = "__BROKENAPP";
    const w = window;
    if (!w[key] || typeof w[key].beginAction !== "function") return false;
    w[key].beginAction({action_json}, {ttl_ms});
    return true;
  }} catch (_) {{
    return false;
  }}
}})()
"#
    );
    let _: bool = page
        .evaluate_json(&script)
        .await
        .context("begin action probe")?;
    Ok(())
}

pub async fn end_action(page: &PageClient, action_id: &str) -> Result<()> {
    let id_json = serde_json::to_string(action_id).context("serialize action_id")?;
    let script = format!(
        r#"
(() => {{
  try {{
    const key = "__BROKENAPP";
    const w = window;
    if (!w[key] || typeof w[key].endAction !== "function") return false;
    w[key].endAction({id_json});
    return true;
  }} catch (_) {{
    return false;
  }}
}})()
"#
    );
    let _: bool = page
        .evaluate_json(&script)
        .await
        .context("end action probe")?;
    Ok(())
}

async fn read_settle_stats(page: &PageClient) -> Result<SettleStats> {
    #[derive(serde::Deserialize)]
    struct JsStats {
        pending: u64,
        ms_since_last_dom_mutation: u64,
    }

    let script = r#"
(() => {
  const key = "__BROKENAPP";
  const w = window;
  if (w[key] && typeof w[key].ensureObserver === "function") {
    try { w[key].ensureObserver(); } catch (_) {}
  }
  const pending = (w[key] && typeof w[key].pending === "number") ? w[key].pending : 0;
  const last = (w[key] && typeof w[key].lastDomMutation === "number") ? w[key].lastDomMutation : Date.now();
  return { pending, ms_since_last_dom_mutation: Math.max(0, Date.now() - last) };
})()
"#;

    let v: JsStats = page.evaluate_json(script).await?;
    let scripts = u64::try_from(page.pending_script_loads()).unwrap_or(u64::MAX);
    Ok(SettleStats {
        pending_requests: v.pending.saturating_add(scripts),
        ms_since_last_dom_mutation: v.ms_since_last_dom_mutation,
    })
}

/// Stash framework dev source annotations before dev tooling strips them.
///
/// Astro's dev toolbar reads `data-astro-source-file` / `data-astro-source-loc`
/// and then removes them from the live DOM. This wraps
/// `Element.prototype.removeAttribute` so those two values are kept in a
/// `WeakMap` (`window.__BROKENAPP_SOURCE_ANN`) that discovery reads for
/// element-to-source linking. Idempotent per page: the in-page global marks
/// that the new-document script is already registered.
async fn install_source_annotation_stash(page: &PageClient) -> Result<()> {
    const SCRIPT: &str = r#"
(() => {
  try {
    const w = window;
    if (w.__BROKENAPP_SOURCE_ANN) return true;
    const store = new WeakMap();
    Object.defineProperty(w, "__BROKENAPP_SOURCE_ANN", { value: store, configurable: true });
    const proto = Element.prototype;
    const orig = proto.removeAttribute;
    if (typeof orig !== "function" || orig.__brokenappSourceStash) return true;
    const wrapped = function(name) {
      try {
        if (name === "data-astro-source-file" || name === "data-astro-source-loc") {
          const value = this.getAttribute(name);
          if (value != null) {
            const rec = store.get(this) || {};
            if (name === "data-astro-source-file") rec.file = value; else rec.loc = value;
            store.set(this, rec);
          }
        }
      } catch (_) {}
      return orig.apply(this, arguments);
    };
    try { Object.defineProperty(wrapped, "__brokenappSourceStash", { value: true }); } catch (_) {}
    proto.removeAttribute = wrapped;
  } catch (_) {}
  return true;
})()
"#;

    let installed = page
        .evaluate_json::<bool>("Boolean(window.__BROKENAPP_SOURCE_ANN)")
        .await
        .unwrap_or(false);
    if installed {
        return Ok(());
    }
    let params = cdp_page::AddScriptToEvaluateOnNewDocumentParams::builder()
        .source(SCRIPT)
        .run_immediately(true)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    page.inner()
        .execute(params)
        .await
        .context("Page.addScriptToEvaluateOnNewDocument (source annotation stash)")?;
    Ok(())
}
