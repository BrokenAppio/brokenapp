/// Main classification script. Returns a JSON stringified array of raw component
/// regions with enough structural metadata for the Rust classifier to produce
/// typed `ComponentType` variants.
///
/// Each region in the returned array has:
/// - kind: string (detected pattern)
/// - selector: string (CSS selector to root element)
/// - meta: object (pattern-specific metadata)
/// - confidence: number (0.0–1.0)
pub(crate) const CLASSIFY_PAGE_COMPONENTS: &str = r#"
(function classifyPageComponents() {
    'use strict';

    const results = [];
    const classified = new Set(); // track already-classified elements
    let _cachedRoots = null;

    // ---- Utility helpers ----

    function queryAllInRoot(root, selector) {
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

    function enumerateRoots() {
        if (_cachedRoots !== null) return _cachedRoots;

        const out = [];
        const queue = [document];
        const seen = new Set();
        let scanned = 0;

        while (queue.length && out.length < 64 && scanned < 20000) {
            const root = queue.shift();
            if (!root || seen.has(root)) continue;
            seen.add(root);
            out.push(root);

            let nodes = [];
            try {
                if (root.querySelectorAll) {
                    nodes = Array.from(root.querySelectorAll('*')).slice(0, 5000);
                }
            } catch (_) {
                nodes = [];
            }

            scanned += nodes.length;

            for (const node of nodes) {
                try {
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

        _cachedRoots = out;
        return _cachedRoots;
    }

    function queryAllRoots(selector) {
        const out = [];
        const seen = new Set();
        enumerateRoots().forEach(root => {
            queryAllInRoot(root, selector).forEach(el => {
                if (!el || seen.has(el)) return;
                seen.add(el);
                out.push(el);
            });
        });
        return out;
    }

    function parentForTraversal(el) {
        if (!el) return null;
        if (el.parentElement) return el.parentElement;
        try {
            const root = el.getRootNode ? el.getRootNode() : null;
            if (typeof ShadowRoot !== 'undefined' && root instanceof ShadowRoot && root.host) {
                return root.host;
            }
            const doc = root && root.nodeType === Node.DOCUMENT_NODE ? root : (el.ownerDocument || null);
            return doc && doc.defaultView ? doc.defaultView.frameElement || null : null;
        } catch (_) {
            return null;
        }
    }

    function searchRootForElement(el) {
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

    function domPathFor(el) {
        const segments = [];
        let current = el;
        let nextEnter = 'none';
        let depth = 0;

        while (current && depth < 8) {
            depth++;
            const selector = getSelector(current);
            if (!selector) return null;
            segments.push({ selector, enter: nextEnter });

            const root = searchRootForElement(current);
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
        return segments.length > 1 ? { segments } : null;
    }

    function locatorStrategiesFor(el) {
        const domPath = domPathFor(el);
        if (!domPath) return [];
        return [{
            kind: 'dom_path',
            value: JSON.stringify(domPath),
            stability: 0.72,
            unique: true
        }];
    }

    function getSelector(el) {
        if (el.id) return '#' + CSS.escape(el.id);
        if (el.dataset && el.dataset.testid) return `[data-testid="${CSS.escape(el.dataset.testid)}"]`;
        // Build a minimal unique selector
        const parts = [];
        let cur = el;
        while (cur && cur !== document.body && parts.length < 5) {
            let seg = cur.tagName.toLowerCase();
            if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
            if (cur.className && typeof cur.className === 'string') {
                const cls = cur.className.trim().split(/\s+/).filter(c => !c.match(/^(active|selected|open|show|visible|hidden|hover|focus)/)).slice(0, 2);
                if (cls.length) seg += '.' + cls.map(c => CSS.escape(c)).join('.');
            }
            const parent = cur.parentElement;
            if (parent) {
                const siblings = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
                if (siblings.length > 1) seg += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
            }
            parts.unshift(seg);
            cur = cur.parentElement;
        }
        return parts.join(' > ');
    }

    function isVisible(el) {
        if (!el.offsetParent && el.tagName !== 'BODY' && el.tagName !== 'HTML') return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
    }

    function isAlreadyClassified(el) {
        let cur = el;
        while (cur) {
            if (classified.has(cur)) return true;
            cur = parentForTraversal(cur);
        }
        return false;
    }

    function markClassified(el) {
        classified.add(el);
    }

    function textOf(el) {
        return (el.textContent || '').trim().substring(0, 200);
    }

    function labelOf(el) {
        // Try aria-label, title, innerText (first line)
        return el.getAttribute('aria-label')
            || el.getAttribute('title')
            || (el.textContent || '').trim().split('\n')[0].substring(0, 100)
            || null;
    }

    function cleanLabel(s) {
        if (!s) return '';
        return String(s).replace(/\s+/g, ' ').trim();
    }

    function isSubmitLikeLabel(s) {
        const t = cleanLabel(s).toLowerCase();
        if (!t) return false;
        const good = [
            'save', 'submit', 'create', 'update', 'apply',
            'log in', 'login', 'sign in',
            'send', 'invite',
            'import', 'export',
            'enable', 'disable', 'activate', 'deactivate'
        ];
        return good.some(w => t === w || t.startsWith(w + ' '));
    }

    function isDestructiveLabel(s) {
        const t = cleanLabel(s).toLowerCase();
        if (!t) return false;
        const bad = [
            'delete', 'remove', 'destroy', 'archive',
            'revoke', 'detach', 'unlink', 'end ownership',
            'log out', 'logout', 'sign out'
        ];
        return bad.some(w => t === w || t.startsWith(w + ' '));
    }

    function isBadSubmitLabel(s) {
        const t = cleanLabel(s).toLowerCase();
        if (!t) return true;
        const bad = [
            'next', 'previous', 'next page', 'prev',
            'reset', 'sort', 'sort by',
            'library',
            'close', 'cancel'
        ];
        return bad.some(w => t === w || t.startsWith(w + ' '));
    }

    function findBestSubmitButton(container) {
        const candidates = Array.from(container.querySelectorAll('button, input[type="submit"], [role="button"]'));
        let best = null;
        let bestScore = -1e9;

        candidates.forEach(btn => {
            if (!isVisible(btn)) return;
            const lbl = cleanLabel(labelOf(btn));
            if (!lbl) return;

            let score = 0;
            const tag = (btn.tagName || '').toLowerCase();
            if (tag === 'input') {
                const t = (btn.getAttribute('type') || '').toLowerCase();
                if (t === 'submit' || t === 'image') score += 100;
            } else if (tag === 'button') {
                const t = (btn.getAttribute('type') || '').toLowerCase();
                if (t === 'submit') score += 100;
            }
            if (isSubmitLikeLabel(lbl)) score += 50;
            if (isBadSubmitLabel(lbl)) score -= 60;
            if (isDestructiveLabel(lbl)) score -= 120;
            if (lbl.length > 80) score -= 40;
            if (btn.disabled) score -= 5;

            if (score > bestScore) {
                bestScore = score;
                best = btn;
            }
        });

        if (!best) return null;

        const bestLbl = cleanLabel(labelOf(best));
        const isExplicitSubmit = (() => {
            const tag = (best.tagName || '').toLowerCase();
            if (tag === 'input') {
                const t = (best.getAttribute('type') || '').toLowerCase();
                return t === 'submit' || t === 'image';
            }
            if (tag === 'button') {
                const t = (best.getAttribute('type') || '').toLowerCase();
                return t === 'submit';
            }
            return false;
        })();

        // Require either an explicit submit type or submit-like text, and reject
        // obvious false positives (pagination/sort/reset).
        if (!isExplicitSubmit && !isSubmitLikeLabel(bestLbl)) return null;
        if (isBadSubmitLabel(bestLbl)) return null;
        return best;
    }

    function round2(n) {
        if (!Number.isFinite(n)) return null;
        return Math.round(n * 100) / 100;
    }

    function parsePx(v) {
        if (v == null) return null;
        const n = parseFloat(String(v));
        return Number.isFinite(n) ? round2(n) : null;
    }

    function parseMaybeInt(v) {
        if (v == null) return null;
        const n = parseInt(String(v), 10);
        return Number.isFinite(n) ? n : null;
    }

    function normalizeColor(v) {
        if (!v) return null;
        const s = String(v).trim().toLowerCase().replace(/\s+/g, '');
        return s.length > 0 ? s : null;
    }

    function avg(values) {
        const nums = values.filter(v => Number.isFinite(v));
        if (!nums.length) return null;
        const sum = nums.reduce((acc, n) => acc + n, 0);
        return round2(sum / nums.length);
    }

    // Cache CSS variables and base font size so we can do best-effort design-token
    // adherence checks without heavy DOM work per component.
    let _cachedRootVars = null;
    let _cachedRootFontPx = null;

    function rootFontPx() {
        if (_cachedRootFontPx !== null) return _cachedRootFontPx;
        try {
            const s = window.getComputedStyle(document.documentElement);
            const n = parseFloat(String(s.fontSize || ''));
            _cachedRootFontPx = Number.isFinite(n) ? n : null;
        } catch (_) {
            _cachedRootFontPx = null;
        }
        return _cachedRootFontPx;
    }

    function getRootVars() {
        if (_cachedRootVars !== null) return _cachedRootVars;
        const vars = {};
        try {
            const s = window.getComputedStyle(document.documentElement);
            for (let i = 0; i < s.length; i++) {
                const name = s[i];
                if (!name || typeof name !== 'string') continue;
                if (!name.startsWith('--')) continue;
                const v = (s.getPropertyValue(name) || '').trim();
                if (v) vars[name] = v;
            }
        } catch (_) {}
        _cachedRootVars = vars;
        return _cachedRootVars;
    }

    function parseLenToPx(value, depth) {
        if (!value) return null;
        const s = String(value).trim();
        if (!s) return null;
        const d = depth || 0;
        if (d > 3) return null;

        const mVar = s.match(/^var\(\s*(--[A-Za-z0-9\-_]+)\s*\)$/);
        if (mVar) {
            const vars = getRootVars();
            return parseLenToPx(vars[mVar[1]], d + 1);
        }

        const m = s.match(/^(-?\d+(?:\.\d+)?)(px|rem|em)?$/);
        if (!m) return null;
        const num = parseFloat(m[1]);
        if (!Number.isFinite(num)) return null;
        const unit = m[2] || 'px';
        if (unit === 'px') return round2(num);
        const base = rootFontPx();
        if (!Number.isFinite(base)) return null;
        return round2(num * base);
    }

    function parseSpacingToXY(value) {
        if (!value) return null;
        const s = String(value).trim();
        if (!s) return null;
        const parts = s.split(/\s+/).filter(Boolean);
        if (!parts.length) return null;
        const pxs = parts.map(p => parseLenToPx(p, 0));
        if (pxs.some(v => !Number.isFinite(v))) return null;
        if (pxs.length === 1) return { x: pxs[0], y: pxs[0] };
        if (pxs.length === 2) return { x: pxs[1], y: pxs[0] };
        if (pxs.length === 3) return { x: pxs[1], y: round2((pxs[0] + pxs[2]) / 2) };
        // 4+ values: top right bottom left
        return {
            x: round2((pxs[1] + pxs[3]) / 2),
            y: round2((pxs[0] + pxs[2]) / 2)
        };
    }

    function tokenKeywordsForKind(kind) {
        const k = String(kind || '').toLowerCase();
        if (!k) return [];
        if (k === 'stats_card' || k === 'dashboard' || k === 'list_view' || k === 'detail_view') return ['card', 'panel', 'surface'];
        if (k === 'modal') return ['modal', 'dialog'];
        if (k === 'form' || k === 'search') return ['input', 'field', 'form', 'control'];
        if (k === 'data_table') return ['table', 'grid'];
        return [k.replace(/_/g, '-')];
    }

    function findTokenVar(vars, keywords, tokenType) {
        if (!vars) return null;
        const typeWords = tokenType === 'radius'
            ? ['radius', 'radii', 'rounded']
            : tokenType === 'padding'
                ? ['padding']
                : [];
        if (!typeWords.length) return null;
        const keys = (keywords || []).map(s => String(s).toLowerCase()).filter(Boolean);

        let best = null;
        let bestScore = -1;
        for (const name in vars) {
            if (!Object.prototype.hasOwnProperty.call(vars, name)) continue;
            const n = String(name).toLowerCase();
            if (!n.startsWith('--')) continue;
            if (!typeWords.some(w => n.includes(w))) continue;
            let score = 0;
            for (const k of keys) {
                if (n.includes(k)) score += 3;
                if (n.startsWith(`--${k}-`)) score += 1;
                if (n === `--${k}-${tokenType}` || n === `--${k}_${tokenType}`) score += 5;
            }
            if (score <= 0) continue; // require a keyword hit to avoid noisy guesses
            if (score > bestScore) {
                bestScore = score;
                best = name;
            }
        }

        // Conservative fallback: only check these if explicitly present.
        if (!best && tokenType === 'radius') {
            if (vars['--radius']) return '--radius';
            if (vars['--border-radius']) return '--border-radius';
        }
        return best;
    }

    function hasHardcodedColorLiteral(value) {
        if (!value) return false;
        const s = String(value);
        if (/var\(\s*--/i.test(s)) return false;
        return /#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})\b/i.test(s)
            || /\b(?:rgb|rgba|hsl|hsla)\s*\(/i.test(s);
    }

    function findArbitraryColorClasses(classList) {
        if (!Array.isArray(classList)) return [];
        return classList.filter(cls =>
            /^(?:bg|text|border|fill|stroke|ring)-\[[^\]]+\]$/i.test(String(cls || ''))
        );
    }

    function isOnPreferredFontScale(valuePx) {
        if (!Number.isFinite(valuePx)) return true;
        const preferred = [10, 12, 14, 16, 18, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72];
        for (const size of preferred) {
            if (Math.abs(valuePx - size) <= 0.75) {
                return true;
            }
        }
        return false;
    }

    function collectClassSamples(root, maxSamples) {
        const out = [];
        const seen = new Set();

        function push(node) {
            if (!node) return;
            const tag = (node.tagName || '').toLowerCase();
            if (!tag) return;
            const role = (node.getAttribute && node.getAttribute('role')) || null;
            const classes = Array.from(node.classList || []).slice(0, 12);
            const key = tag + '|' + (role || '') + '|' + classes.slice(0, 4).join('.');
            if (seen.has(key)) return;
            seen.add(key);
            const inlineStyle = (node.getAttribute && node.getAttribute('style') || '').trim();
            out.push({
                tag: tag,
                role: role,
                class_list: classes,
                has_inline_style: inlineStyle.length > 0
            });
        }

        push(root);
        const selectors = [
            'table', 'thead', 'tbody', 'th', 'td',
            'button', 'input', 'select', 'textarea',
            '[role="dialog"]', '[role="alertdialog"]'
        ];
        selectors.forEach(sel => {
            try { push(root.querySelector(sel)); } catch (_) {}
        });

        return out.slice(0, maxSamples || 10);
    }

    function firstTextSample(node) {
        try {
            const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, {
                acceptNode(textNode) {
                    const text = (textNode.nodeValue || '').replace(/\s+/g, ' ').trim();
                    if (text.length < 2) return NodeFilter.FILTER_REJECT;
                    if (!textNode.parentElement || !isVisible(textNode.parentElement)) return NodeFilter.FILTER_REJECT;
                    return NodeFilter.FILTER_ACCEPT;
                }
            });
            const textNode = walker.nextNode();
            if (!textNode || !document.createRange) return null;
            const range = document.createRange();
            range.selectNodeContents(textNode);
            const rect = range.getBoundingClientRect();
            if (!rect || rect.width <= 0 || rect.height <= 0) return null;
            return {
                text: (textNode.nodeValue || '').replace(/\s+/g, ' ').trim(),
                rect: rect,
                element: textNode.parentElement
            };
        } catch (_) {
            return null;
        }
    }

    function collectTextSamples(root, maxSamples) {
        const out = [];
        const seen = new Set();

        function normalizeSampleText(raw) {
            const text = String(raw || '').replace(/\s+/g, ' ').trim();
            if (!text || text.length % 2 !== 0) return text;
            const mid = text.length / 2;
            const left = text.slice(0, mid);
            const right = text.slice(mid);
            if (left === right && left.trim().split(/\s+/).length <= 4) return left;
            return text;
        }

        function push(node) {
            if (!node || !isVisible(node)) return;
            const textSample = firstTextSample(node);
            const text = normalizeSampleText(textSample && textSample.text ? textSample.text : textOf(node));
            if (text.length < 2 || text.length > 120) return;
            const lower = text.toLowerCase();
            if (/^(name|created|last activity|closed deals|renewals|actions|status)$/.test(lower)) return;
            const rect = (textSample && textSample.rect) || (node.getBoundingClientRect ? node.getBoundingClientRect() : null);
            if (!rect || rect.width <= 0 || rect.height <= 0) return;
            const sampleElement = (textSample && textSample.element) || node;
            const selector = getSelector(sampleElement);
            const key = selector + '|' + text.substring(0, 80);
            if (seen.has(key)) return;
            seen.add(key);
            out.push({
                text: text.substring(0, 120),
                selector: selector,
                x_px: round2(rect.left || 0),
                y_px: round2(rect.top || 0),
                width_px: round2(rect.width || 0),
                height_px: round2(rect.height || 0),
                container_selector: getSelector(node),
                container_x_px: round2((node.getBoundingClientRect ? node.getBoundingClientRect().left : rect.left) || 0),
                container_y_px: round2((node.getBoundingClientRect ? node.getBoundingClientRect().top : rect.top) || 0),
                container_width_px: round2((node.getBoundingClientRect ? node.getBoundingClientRect().width : rect.width) || 0),
                container_height_px: round2((node.getBoundingClientRect ? node.getBoundingClientRect().height : rect.height) || 0),
                class_list: Array.from(sampleElement.classList || []).slice(0, 12)
            });
        }

        const preferred = [
            '[class*="name"]',
            '[class*="title"]',
            '[class*="primary"]',
            '[class*="label"]',
            '[data-field]',
            '[role="cell"]',
            'td',
            'th',
            'strong',
            'a',
            'span',
            'p'
        ];
        preferred.forEach(sel => {
            try {
                if (root.matches && root.matches(sel)) push(root);
                if (root.querySelectorAll) Array.from(root.querySelectorAll(sel)).slice(0, 12).forEach(push);
            } catch (_) {}
        });
        if (out.length === 0) push(root);
        return out.slice(0, maxSamples || 12);
    }

    function collectVisualProfile(el, kind) {
        if (!el || !window.getComputedStyle) return null;
        try {
            const style = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect ? el.getBoundingClientRect() : { width: 0, height: 0 };
            const inlineStyle = (el.getAttribute && el.getAttribute('style') || '').trim();
            const elementClassList = Array.from(el.classList || []).slice(0, 16);

            let probe = null;
            try {
                probe = el.querySelector && el.querySelector('th, td, button, input, select, textarea');
            } catch (_) {}
            const probeStyle = probe ? window.getComputedStyle(probe) : null;
            const probeInline = (probe && probe.getAttribute && probe.getAttribute('style') || '').trim();
            const probeClassList = probe ? Array.from(probe.classList || []).slice(0, 16) : [];

            // Best-effort token adherence: compare computed values against likely :root CSS vars.
            const tokenMismatches = [];
            try {
                const vars = getRootVars();
                const keys = tokenKeywordsForKind(kind);

                const radiusVar = findTokenVar(vars, keys, 'radius');
                if (radiusVar) {
                    const expected = parseLenToPx(vars[radiusVar], 0);
                    const actual = parsePx(style.borderTopLeftRadius);
                    if (Number.isFinite(expected) && Number.isFinite(actual) && Math.abs(expected - actual) > 1.0) {
                        tokenMismatches.push(`border_radius_px token=${radiusVar} expected=${expected}px actual=${actual}px`);
                    }
                }

                const paddingVar = findTokenVar(vars, keys, 'padding');
                if (paddingVar) {
                    const expected = parseSpacingToXY(vars[paddingVar]);
                    const actualX = avg([parsePx(style.paddingLeft), parsePx(style.paddingRight)]);
                    const actualY = avg([parsePx(style.paddingTop), parsePx(style.paddingBottom)]);
                    if (expected && Number.isFinite(actualX) && Math.abs(expected.x - actualX) > 1.0) {
                        tokenMismatches.push(`padding_x_px token=${paddingVar} expected=${expected.x}px actual=${actualX}px`);
                    }
                    if (expected && Number.isFinite(actualY) && Math.abs(expected.y - actualY) > 1.0) {
                        tokenMismatches.push(`padding_y_px token=${paddingVar} expected=${expected.y}px actual=${actualY}px`);
                    }
                }

                if (hasHardcodedColorLiteral(inlineStyle)) {
                    tokenMismatches.push('inline_color_literal source=inline_style');
                }

                const arbitraryColorClasses = findArbitraryColorClasses(elementClassList);
                if (arbitraryColorClasses.length > 0) {
                    tokenMismatches.push(`arbitrary_color_class class=${arbitraryColorClasses[0]}`);
                }

                const fontSizePx = parsePx(style.fontSize);
                if (Number.isFinite(fontSizePx) && !isOnPreferredFontScale(fontSizePx)) {
                    tokenMismatches.push(`font_size_off_scale value=${fontSizePx}px`);
                }

                if (hasHardcodedColorLiteral(probeInline)) {
                    tokenMismatches.push('probe_inline_color_literal source=inline_style');
                }

                const probeArbitraryColorClasses = findArbitraryColorClasses(probeClassList);
                if (probeArbitraryColorClasses.length > 0) {
                    tokenMismatches.push(`probe_arbitrary_color_class class=${probeArbitraryColorClasses[0]}`);
                }
            } catch (_) {}

            return {
                class_list: elementClassList,
                has_inline_style: inlineStyle.length > 0,
                inline_style_preview: inlineStyle ? inlineStyle.substring(0, 240) : null,
                display: style.display || null,
                position: style.position || null,
                z_index: parseMaybeInt(style.zIndex),
                color: normalizeColor(style.color),
                background_color: (function() {
                    let c = el;
                    while (c) {
                        const bg = window.getComputedStyle(c).backgroundColor;
                        if (bg && bg !== 'transparent' && bg !== 'rgba(0, 0, 0, 0)') return normalizeColor(bg);
                        c = parentForTraversal(c);
                    }
                    return normalizeColor(window.getComputedStyle(document.body).backgroundColor);
                })(),
                border_color: normalizeColor(style.borderColor),
                border_radius_px: parsePx(style.borderTopLeftRadius),
                border_width_px: parsePx(style.borderTopWidth),
                padding_x_px: avg([parsePx(style.paddingLeft), parsePx(style.paddingRight)]),
                padding_y_px: avg([parsePx(style.paddingTop), parsePx(style.paddingBottom)]),
                margin_x_px: avg([parsePx(style.marginLeft), parsePx(style.marginRight)]),
                margin_y_px: avg([parsePx(style.marginTop), parsePx(style.marginBottom)]),
                gap_px: parsePx(style.gap),
                font_size_px: parsePx(style.fontSize),
                line_height_px: parsePx(style.lineHeight),
                font_weight: parseMaybeInt(style.fontWeight),
                x_px: round2(rect.left || 0),
                y_px: round2(rect.top || 0),
                width_px: round2(rect.width || 0),
                height_px: round2(rect.height || 0),
                probe_padding_x_px: probeStyle ? avg([parsePx(probeStyle.paddingLeft), parsePx(probeStyle.paddingRight)]) : null,
                probe_padding_y_px: probeStyle ? avg([parsePx(probeStyle.paddingTop), parsePx(probeStyle.paddingBottom)]) : null,
                probe_font_size_px: probeStyle ? parsePx(probeStyle.fontSize) : null,
                probe_border_radius_px: probeStyle ? parsePx(probeStyle.borderTopLeftRadius) : null,
                probe_tag: probe ? String((probe.tagName || '')).toLowerCase() : null,
                probe_selector: probe ? getSelector(probe) : null,
                probe_class_list: probeClassList,
                probe_has_inline_style: probeInline.length > 0,
                probe_inline_style_preview: probeInline ? probeInline.substring(0, 240) : null,
                class_samples: collectClassSamples(el, 10),
                text_samples: collectTextSamples(el, 12),
                token_mismatches: tokenMismatches
            };
        } catch (_) {
            return null;
        }
    }

    function withVisual(el, kind, meta) {
        const visual = collectVisualProfile(el, kind);
        if (visual) meta.visual = visual;
        return meta;
    }

    // ---- Pattern detectors (ordered by specificity, high to low) ----

    // 1. DATA TABLES
    function detectTables() {
        // Semantic <table> elements
        queryAllRoots('table').forEach(table => {
            if (!isVisible(table) || isAlreadyClassified(table)) return;
            const thead = table.querySelector('thead');
            const tbody = table.querySelector('tbody');
            const rows = tbody ? tbody.querySelectorAll('tr') : table.querySelectorAll('tr');
            if (rows.length < 1) return;

            const headers = [];
            const headerEls = thead
                ? thead.querySelectorAll('th, td')
                : (rows.length > 0 ? rows[0].querySelectorAll('th') : []);

            headerEls.forEach((th, i) => {
                const sortable = !!(th.querySelector('[class*="sort"], [aria-sort], .sortable, svg')
                    || th.style.cursor === 'pointer'
                    || th.getAttribute('aria-sort'));
                headers.push({
                    label: textOf(th),
                    index: i,
                    sortable: sortable
                });
            });

            // Check for nearby pagination
            const parent = table.parentElement;
            const hasPagination = !!(
                parent && (
                    parent.querySelector('[class*="pagination"], [class*="pager"], [aria-label*="pagination"], nav[class*="page"]')
                    || parent.querySelector('button[aria-label*="next"], button[aria-label*="previous"]')
                    || parent.querySelector('[class*="page-size"], [class*="per-page"]')
                )
            );

            // Check for filtering
            const hasFiltering = !!(parent && (
                parent.querySelector('[class*="filter"], [class*="search"], input[type="search"]')
            ));

            // Check for bulk actions (checkboxes in first column)
            const hasBulk = !!(rows.length > 0 && rows[0].querySelector('input[type="checkbox"]'));

            markClassified(table);
            results.push({
                kind: 'data_table',
                selector: getSelector(table),
                confidence: headers.length > 0 ? 0.95 : 0.7,
                meta: withVisual(table, 'data_table', {
                    columns: headers,
                    row_count: rows.length - (thead ? 0 : 1),
                    has_pagination: hasPagination,
                    has_sorting: headers.some(h => h.sortable),
                    has_filtering: hasFiltering,
                    has_bulk_actions: hasBulk
                })
            });
        });

        // Div-based data grids (role="grid" or repeated row structure)
        queryAllRoots('[role="grid"], [role="table"], [class*="data-grid"], [class*="datagrid"], [class*="ag-root"]').forEach(grid => {
            if (!isVisible(grid) || isAlreadyClassified(grid)) return;
            const headerRow = grid.querySelector('[role="row"]:first-child, [class*="header-row"], [class*="header"]');
            const rows = grid.querySelectorAll('[role="row"]');
            if (rows.length < 2) return;

            const headers = [];
            if (headerRow) {
                headerRow.querySelectorAll('[role="columnheader"], [class*="header-cell"]').forEach((cell, i) => {
                    headers.push({ label: textOf(cell), index: i, sortable: false });
                });
            }

            markClassified(grid);
            results.push({
                kind: 'data_table',
                selector: getSelector(grid),
                confidence: 0.8,
                meta: withVisual(grid, 'data_table', {
                    columns: headers,
                    row_count: rows.length - 1,
                    has_pagination: false,
                    has_sorting: false,
                    has_filtering: false,
                    has_bulk_actions: false
                })
            });
        });
    }

    // 2. FORMS
    function detectForms() {
        // Explicit <form> tags
        queryAllRoots('form').forEach(form => {
            if (!isVisible(form) || isAlreadyClassified(form)) return;
            const fields = extractFormFields(form);
            if (fields.length === 0) return;

            const submitBtn = findBestSubmitButton(form);

            markClassified(form);
            results.push({
                kind: 'form',
                selector: getSelector(form),
                confidence: 0.95,
                meta: withVisual(form, 'form', {
                    fields: fields,
                    has_submit: !!submitBtn,
                    submit_label: submitBtn ? labelOf(submitBtn) : null,
                    submit_selector: submitBtn ? getSelector(submitBtn) : null,
                    submit_locators: submitBtn ? locatorStrategiesFor(submitBtn) : []
                })
            });
        });

        // Implicit forms: containers with 3+ inputs and a button that aren't inside a <form>
        queryAllRoots('div, section, article, main').forEach(container => {
            if (!isVisible(container) || isAlreadyClassified(container)) return;
            if (container.closest('form')) return; // skip if nested in a real form

            const inputs = container.querySelectorAll('input:not([type="hidden"]), select, textarea');
            const buttons = container.querySelectorAll('button, [role="button"]');
            if (inputs.length < 3 || buttons.length < 1) return;

            // Make sure inputs are direct-ish children (not deeply nested in sub-components)
            const directInputs = Array.from(inputs).filter(inp => {
                let depth = 0, cur = inp;
                while (cur !== container && depth < 6) { cur = cur.parentElement; depth++; }
                return cur === container;
            });
            if (directInputs.length < 3) return;

            const fields = extractFormFields(container);
            const submitBtn = findBestSubmitButton(container);

            markClassified(container);
            results.push({
                kind: 'form',
                selector: getSelector(container),
                confidence: 0.7,
                meta: withVisual(container, 'form', {
                    fields: fields,
                    has_submit: !!submitBtn,
                    submit_label: submitBtn ? labelOf(submitBtn) : null,
                    submit_selector: submitBtn ? getSelector(submitBtn) : null,
                    submit_locators: submitBtn ? locatorStrategiesFor(submitBtn) : []
                })
            });
        });
    }

    function extractFormFields(container) {
        function labelTextFromLabelEl(labelEl) {
            if (!labelEl) return null;
            try {
                // Avoid concatenating nested control text (e.g. <label>Occupancy<select>...</select></label>)
                const clone = labelEl.cloneNode(true);
                clone.querySelectorAll('input, select, textarea, button').forEach(n => n.remove());
                const txt = (clone.textContent || '').trim();
                return txt ? txt.substring(0, 200) : null;
            } catch (_) {
                const txt = (labelEl.textContent || '').trim();
                return txt ? txt.substring(0, 200) : null;
            }
        }

        function labelFromAriaLabelledBy(inp) {
            try {
                const ids = inp.getAttribute && inp.getAttribute('aria-labelledby');
                if (!ids) return null;
                const parts = ids.split(/\s+/).map(id => {
                    const root = inp.getRootNode ? inp.getRootNode() : document;
                    const el = root && root.getElementById ? root.getElementById(id) : document.getElementById(id);
                    if (!el) return null;
                    const txt = (el.textContent || '').trim().replace(/\s+/g, ' ');
                    return txt ? txt.substring(0, 200) : null;
                }).filter(Boolean);
                if (!parts.length) return null;
                return parts.join(' ').trim().substring(0, 200) || null;
            } catch (_) {
                return null;
            }
        }

        function findNearbyLabel(inp, root) {
            // Common pattern for filter bars: <span>Status</span><select>...</select>
            // Walk up a few levels and look for a short, non-control sibling that appears before the control.
            let cur = inp;
            let depth = 0;
            while (cur && cur !== root && depth < 4) {
                const parent = cur.parentElement;
                if (!parent) break;
                const kids = Array.from(parent.children || []);
                let idx = -1;
                for (let i = 0; i < kids.length; i++) {
                    const k = kids[i];
                    if (k === cur || (k.contains && k.contains(cur))) { idx = i; break; }
                }
                if (idx > 0) {
                    for (let j = idx - 1; j >= 0; j--) {
                        const sib = kids[j];
                        if (!sib) continue;
                        if (sib.querySelector && sib.querySelector('input, select, textarea')) continue;
                        const txt = (sib.textContent || '').trim().replace(/\s+/g, ' ');
                        if (txt && txt.length <= 60) return txt.substring(0, 200);
                    }
                }
                cur = parent;
                depth++;
            }
            return null;
        }

        const fields = [];
        container.querySelectorAll('input, select, textarea').forEach(inp => {
            if (inp.type === 'hidden') return;
            if (!isVisible(inp)) return;

            // Find label
            let label = null;
            if (inp.id) {
                const labelEl = container.querySelector(`label[for="${CSS.escape(inp.id)}"]`);
                if (labelEl) label = labelTextFromLabelEl(labelEl);
            }
            if (!label && inp.closest('label')) label = labelTextFromLabelEl(inp.closest('label'));
            if (!label) label = inp.getAttribute('aria-label') || inp.getAttribute('placeholder') || null;
            if (!label) label = labelFromAriaLabelledBy(inp);
            if (!label) label = findNearbyLabel(inp, container);

            let fieldType = 'text';
            let options = [];

            if (inp.tagName === 'SELECT') {
                fieldType = inp.multiple ? 'multi_select' : 'select';
                options = Array.from(inp.options).map(o => o.textContent.trim()).filter(Boolean).slice(0, 50);
            } else if (inp.tagName === 'TEXTAREA') {
                fieldType = 'textarea';
            } else if (inp.type === 'checkbox') {
                fieldType = 'checkbox';
            } else if (inp.type === 'radio') {
                fieldType = 'radio';
            } else {
                fieldType = inp.type || 'text';
            }

            fields.push({
                label: label,
                name: inp.name || null,
                field_type: fieldType,
                options: options.length > 0 ? options : undefined,
                required: inp.required || inp.getAttribute('aria-required') === 'true',
                placeholder: inp.placeholder || null,
                selector: getSelector(inp),
                locators: locatorStrategiesFor(inp)
            });
        });
        return fields;
    }

    // 3. NAVIGATION
    function detectNavigation() {
        // <nav> elements
        queryAllRoots('nav, [role="navigation"]').forEach(nav => {
            if (!isVisible(nav) || isAlreadyClassified(nav)) return;
            const links = nav.querySelectorAll('a, [role="link"], [role="tab"], [role="menuitem"]');
            if (links.length < 2) return;

            const items = Array.from(links).slice(0, 30).map(a => ({
                label: labelOf(a) || '',
                href: a.getAttribute('href') || null,
                is_active: a.classList.contains('active') || a.getAttribute('aria-current') === 'page' || a.getAttribute('aria-selected') === 'true',
                icon: a.querySelector('svg, i, [class*="icon"]') ? 'yes' : null
            }));

            // Determine nav type by layout
            const rect = nav.getBoundingClientRect();
            const isHorizontal = rect.width > rect.height * 2;
            const isSidebar = rect.height > rect.width * 1.5 || rect.left < 100;

            let navType = 'top_bar';
            if (nav.querySelector('[role="tablist"], [class*="tab"]')) navType = 'tab_bar';
            else if (nav.querySelector('[class*="breadcrumb"], [aria-label*="breadcrumb"]')) navType = 'breadcrumbs';
            else if (nav.querySelector('[class*="pagination"], [aria-label*="pagination"]')) navType = 'pagination';
            else if (nav.querySelector('[class*="step"], [class*="wizard"]')) navType = 'step_wizard';
            else if (isSidebar) navType = 'sidebar';
            else if (isHorizontal) navType = 'top_bar';

            markClassified(nav);
            results.push({
                kind: 'navigation',
                selector: getSelector(nav),
                confidence: 0.9,
                meta: withVisual(nav, 'navigation', { nav_type: navType, items: items })
            });
        });

        // Breadcrumbs (often outside <nav>)
        queryAllRoots('[class*="breadcrumb"], [aria-label*="breadcrumb"], ol[class*="bread"]').forEach(bc => {
            if (!isVisible(bc) || isAlreadyClassified(bc)) return;
            const items = Array.from(bc.querySelectorAll('li, a, span')).filter(el => textOf(el).length > 0 && textOf(el).length < 60);
            if (items.length < 2) return;

            markClassified(bc);
            results.push({
                kind: 'breadcrumbs',
                selector: getSelector(bc),
                confidence: 0.85,
                meta: withVisual(bc, 'breadcrumbs', {
                    items: items.slice(0, 10).map((item, i) => ({
                        label: textOf(item),
                        href: item.tagName === 'A' ? item.getAttribute('href') : null,
                        is_current: i === items.length - 1
                    }))
                })
            });
        });
    }

    // 4. MODALS / DIALOGS
    function detectModals() {
        queryAllRoots('[role="dialog"], [role="alertdialog"], [class*="modal"], [class*="dialog"], dialog').forEach(modal => {
            if (!isVisible(modal) || isAlreadyClassified(modal)) return;

            const titleEl = modal.querySelector('[class*="title"], [class*="header"] h1, [class*="header"] h2, [class*="header"] h3, h1, h2');
            const closeBtn = modal.querySelector('[class*="close"], [aria-label*="close"], [aria-label*="dismiss"], button:has(svg)');

            markClassified(modal);
            results.push({
                kind: 'modal',
                selector: getSelector(modal),
                confidence: 0.9,
                meta: withVisual(modal, 'modal', {
                    title: titleEl ? textOf(titleEl) : null,
                    has_close_button: !!closeBtn
                })
            });
        });
    }

    // 5. DETAIL VIEWS (label-value pairs)
    function detectDetailViews() {
        // <dl> definition lists are classic detail views
        queryAllRoots('dl').forEach(dl => {
            if (!isVisible(dl) || isAlreadyClassified(dl)) return;
            const dts = dl.querySelectorAll('dt');
            const dds = dl.querySelectorAll('dd');
            if (dts.length < 2) return;

            const fields = Array.from(dts).slice(0, 30).map((dt, i) => ({
                label: textOf(dt),
                value_preview: dds[i] ? textOf(dds[i]).substring(0, 100) : null,
                value_type: guessValueType(dds[i] ? textOf(dds[i]) : '')
            }));

            markClassified(dl);
            results.push({
                kind: 'detail_view',
                selector: getSelector(dl),
                confidence: 0.9,
                meta: withVisual(dl, 'detail_view', { fields: fields, entity_type: null })
            });
        });

        // Div-based label:value patterns
        queryAllRoots('[class*="detail"], [class*="profile"], [class*="info-card"], [class*="summary"]').forEach(container => {
            if (!isVisible(container) || isAlreadyClassified(container)) return;

            // Look for repeated label-value structure
            const pairs = [];
            container.querySelectorAll('[class*="label"], [class*="key"], dt, th').forEach(labelEl => {
                const valueEl = labelEl.nextElementSibling;
                if (valueEl && textOf(labelEl).length < 60 && textOf(labelEl).length > 0) {
                    pairs.push({
                        label: textOf(labelEl),
                        value_preview: textOf(valueEl).substring(0, 100),
                        value_type: guessValueType(textOf(valueEl))
                    });
                }
            });

            if (pairs.length < 3) return;

            markClassified(container);
            results.push({
                kind: 'detail_view',
                selector: getSelector(container),
                confidence: 0.7,
                meta: withVisual(container, 'detail_view', { fields: pairs, entity_type: null })
            });
        });
    }

    function guessValueType(value) {
        if (!value) return 'text';
        if (value.match(/^\S+@\S+\.\S+$/)) return 'email';
        if (value.match(/^[\+\d\s\-\(\)]{7,}$/)) return 'phone';
        if (value.match(/^https?:\/\//)) return 'url';
        if (value.match(/^\d{4}-\d{2}-\d{2}/) || value.match(/\d{1,2}\/\d{1,2}\/\d{2,4}/)) return 'date';
        if (value.match(/^\$[\d,]+/) || value.match(/^[\d,]+\.\d{2}$/)) return 'currency';
        return 'text';
    }

    // 6. DASHBOARDS (multiple widget cards)
    function detectDashboards() {
        // Look for grid/flex containers with 3+ card-like children
        queryAllRoots('[class*="dashboard"], [class*="grid"], [class*="widgets"], main, [role="main"]').forEach(container => {
            if (!isVisible(container) || isAlreadyClassified(container)) return;

            const children = Array.from(container.children).filter(c => isVisible(c));
            if (children.length < 3) return;

            // Check if children look like cards/widgets
            const cards = children.filter(child => {
                const r = child.getBoundingClientRect();
                // Card-like: has some height, has border/shadow/background
                const style = window.getComputedStyle(child);
                return r.height > 60 && r.height < 600
                    && (style.borderRadius !== '0px'
                        || style.boxShadow !== 'none'
                        || child.classList.toString().match(/card|widget|panel|stat|metric/));
            });

            if (cards.length < 3) return;

            const widgets = cards.slice(0, 20).map(card => {
                let widgetType = 'unknown';
                if (card.querySelector('canvas, svg[class*="chart"], [class*="chart"], [class*="recharts"]')) widgetType = 'chart';
                else if (card.querySelector('table')) widgetType = 'table';
                else if (card.querySelector('ul, ol, [class*="list"]')) widgetType = 'list';
                else if (card.querySelector('[class*="calendar"]')) widgetType = 'calendar';
                else {
                    // Stat card: typically a large number + label
                    const text = textOf(card);
                    if (text.length < 100 && text.match(/\d/)) widgetType = 'stat_card';
                }

                const titleEl = card.querySelector('h1, h2, h3, h4, [class*="title"], [class*="heading"]');
                return {
                    widget_type: widgetType,
                    title: titleEl ? textOf(titleEl) : null,
                    selector: getSelector(card)
                };
            });

            markClassified(container);
            results.push({
                kind: 'dashboard',
                selector: getSelector(container),
                confidence: cards.length >= 4 ? 0.85 : 0.65,
                meta: withVisual(container, 'dashboard', { widgets: widgets })
            });
        });
    }

    // 7. SEARCH INTERFACES
    function detectSearch() {
        queryAllRoots('input[type="search"], [role="searchbox"], input[class*="search"], input[placeholder*="Search" i], input[placeholder*="Filter" i]').forEach(input => {
            if (!isVisible(input) || isAlreadyClassified(input)) return;

            // Walk up to find the search container
            let container = input.parentElement;
            for (let i = 0; i < 4 && container; i++) {
                if (container.querySelector('[class*="result"], [class*="list"], [class*="dropdown"], ul, table')) break;
                container = container.parentElement;
            }
            if (!container) container = input.parentElement;

            // Look for associated filters
            const filters = [];
            if (container) {
                container.querySelectorAll('select, [class*="filter"] select, [class*="filter"] input').forEach(filterEl => {
                    if (filterEl === input) return;
                    filters.push({
                        label: filterEl.getAttribute('aria-label') || filterEl.name || null,
                        field: filterEl.name || null,
                        filter_type: filterEl.tagName === 'SELECT' ? 'select' : 'text'
                    });
                });
            }

            const hasResults = container && !!(
                container.querySelector('[class*="result"], [class*="list"], table, ul')
            );

            markClassified(input);
            results.push({
                kind: 'search',
                selector: getSelector(input),
                confidence: 0.85,
                meta: withVisual(input, 'search', {
                    input_selector: getSelector(input),
                    has_results_container: hasResults,
                    has_filters: filters.length > 0,
                    filters: filters
                })
            });
        });
    }

    // 8. TAB GROUPS
    function detectTabs() {
        queryAllRoots('[role="tablist"], [class*="tab-bar"], [class*="tabs"]').forEach(tablist => {
            if (!isVisible(tablist) || isAlreadyClassified(tablist)) return;
            // Exclude if already classified as nav
            if (tablist.closest('nav')) return;

            const tabs = tablist.querySelectorAll('[role="tab"], [class*="tab-item"], [class*="tab"]:not([class*="tablist"]):not([class*="tabs"]):not([class*="tab-bar"])');
            if (tabs.length < 2) return;

            const tabDefs = Array.from(tabs).slice(0, 15).map(tab => ({
                label: labelOf(tab) || '',
                is_active: tab.getAttribute('aria-selected') === 'true' || tab.classList.contains('active'),
                selector: getSelector(tab)
            }));

            markClassified(tablist);
            results.push({
                kind: 'tab_group',
                selector: getSelector(tablist),
                confidence: 0.85,
                meta: withVisual(tablist, 'tab_group', {
                    tabs: tabDefs,
                    active_index: tabDefs.findIndex(t => t.is_active)
                })
            });
        });
    }

    // 9. CHARTS
    function detectCharts() {
        // Canvas-based charts (Chart.js, etc.)
        queryAllRoots('canvas').forEach(canvas => {
            if (!isVisible(canvas) || isAlreadyClassified(canvas)) return;
            const r = canvas.getBoundingClientRect();
            if (r.width < 100 || r.height < 80) return;

            markClassified(canvas);
            results.push({
                kind: 'chart',
                selector: getSelector(canvas),
                confidence: 0.7, // could be other canvas uses
                meta: withVisual(canvas, 'chart', { chart_type: 'unknown_canvas', canvas_or_svg: 'canvas' })
            });
        });

        // SVG charts (D3, Recharts, etc.)
        queryAllRoots('svg[class*="chart"], svg[class*="recharts"], [class*="chart"] svg, [class*="graph"] svg').forEach(svg => {
            if (!isVisible(svg) || isAlreadyClassified(svg)) return;
            const r = svg.getBoundingClientRect();
            if (r.width < 100 || r.height < 80) return;

            let chartType = 'unknown_svg';
            if (svg.querySelector('rect') && svg.querySelectorAll('rect').length > 3) chartType = 'bar';
            else if (svg.querySelector('circle') && svg.querySelectorAll('circle').length > 2) chartType = 'scatter_or_bubble';
            else if (svg.querySelector('path[d*="L"]')) chartType = 'line';
            else if (svg.querySelector('path[d*="A"]')) chartType = 'pie_or_donut';

            markClassified(svg);
            results.push({
                kind: 'chart',
                selector: getSelector(svg),
                confidence: 0.75,
                meta: withVisual(svg, 'chart', { chart_type: chartType, canvas_or_svg: 'svg' })
            });
        });
    }

    // 10. LIST VIEWS (repeated items that aren't tables)
    function detectListViews() {
        queryAllRoots('ul, ol, [role="list"], [class*="list-view"], [class*="card-list"]').forEach(list => {
            if (!isVisible(list) || isAlreadyClassified(list)) return;
            const items = list.querySelectorAll(':scope > li, :scope > [role="listitem"], :scope > [class*="item"], :scope > [class*="card"]');
            if (items.length < 3) return;

            // Check for pagination nearby
            const parent = list.parentElement;
            const hasPagination = parent && !!(
                parent.querySelector('[class*="pagination"], [class*="pager"], button[aria-label*="next"]')
            );

            markClassified(list);
            results.push({
                kind: 'list_view',
                selector: getSelector(list),
                confidence: 0.75,
                meta: withVisual(list, 'list_view', {
                    item_count: items.length,
                    item_selector: items[0] ? getSelector(items[0]) : null,
                    has_pagination: hasPagination
                })
            });
        });

        queryAllRoots('[class*="record-list-row"], [class*="record-row"], [class*="borrower-row"]').forEach(row => {
            if (!isVisible(row) || isAlreadyClassified(row)) return;
            const text = textOf(row);
            if (!text || text.trim().length < 2) return;

            markClassified(row);
            results.push({
                kind: 'list_view',
                selector: getSelector(row),
                confidence: 0.7,
                meta: withVisual(row, 'list_view', {
                    item_count: 1,
                    item_selector: getSelector(row),
                    has_pagination: false
                })
            });
        });
    }

    // 11. STAT CARDS (standalone)
    function detectStatCards() {
        queryAllRoots('[class*="stat"], [class*="metric"], [class*="kpi"]').forEach(card => {
            if (!isVisible(card) || isAlreadyClassified(card)) return;
            const text = textOf(card);
            if (text.length > 200 || !text.match(/\d/)) return;

            const labelEl = card.querySelector('[class*="label"], [class*="title"], small, span');
            const valueEl = card.querySelector('[class*="value"], [class*="number"], [class*="count"], h1, h2, h3, strong');

            markClassified(card);
            results.push({
                kind: 'stat_card',
                selector: getSelector(card),
                confidence: 0.7,
                meta: withVisual(card, 'stats_card', {
                    label: labelEl ? textOf(labelEl) : null,
                    value: valueEl ? textOf(valueEl) : null
                })
            });
        });
    }

    // 12. EMPTY STATES
    function detectEmptyStates() {
        queryAllRoots('[class*="empty"], [class*="no-data"], [class*="no-results"], [class*="placeholder"]').forEach(el => {
            if (!isVisible(el) || isAlreadyClassified(el)) return;
            const text = textOf(el);
            if (text.length < 5 || text.length > 500) return;
            const hasCta = !!el.querySelector('a, button, [role="button"]');

            markClassified(el);
            results.push({
                kind: 'empty_state',
                selector: getSelector(el),
                confidence: 0.65,
                meta: withVisual(el, 'empty_state', { message: text.substring(0, 200), has_cta: hasCta })
            });
        });
    }

    // 13. ERROR PAGES
    function detectErrorPages() {
        // Check for classic error page indicators
        const bodyText = document.body.textContent || '';
        const h1 = queryAllRoots('h1')[0] || null;
        const h1Text = h1 ? textOf(h1) : '';
        const heading = (h1Text + ' ' + (document.title || '')).trim();

        // A page full of working controls is usually an app page that merely
        // mentions a number like an error code (prices, counts, order numbers);
        // only an explicit error heading counts there.
        const manyControls = queryAllRoots('a[href], button, input, select, textarea, [role="button"]')
            .filter(isVisible).length > 15;

        // Status codes must be standalone tokens: "404" and "HTTP 500." match;
        // "5000¤", "$500.00", "1,500" and "order 1404" do not.
        const codeToken = (code) => new RegExp('(?<![\\w$€£¤-]|\\d[.,])' + code + '(?![\\w%$€£¤]|[.,]\\d)');
        const errorWords = /\b(error|not found|forbidden|denied|unavailable|unauthori[sz]ed|bad gateway)\b/i;
        const errorPatterns = [
            { code: '404', vocab: /\bnot found\b|\b(could|can)( ?not|n't) be found\b|\bdoes(n't| not) exist\b/i, type: '404' },
            { code: '403', vocab: /\bforbidden\b|\baccess denied\b/i, type: '403' },
            { code: '500', vocab: /\binternal server error\b/i, type: '500' },
            { code: '502', vocab: /\bbad gateway\b/i, type: '502' },
            { code: '503', vocab: /\bservice unavailable\b/i, type: '503' },
        ];

        for (const { code, vocab, type } of errorPatterns) {
            const token = codeToken(code);
            const headingToken = token.test(heading);
            const strongHeading = vocab.test(heading)
                || (headingToken && errorWords.test(heading + ' ' + bodyText.slice(0, 2000)));
            const weakHeading = !manyControls && headingToken;
            const bodyHit = !manyControls && bodyText.length < 2000 && token.test(bodyText)
                && (vocab.test(bodyText) || errorWords.test(bodyText));
            if (strongHeading || weakHeading || bodyHit) {
                results.push({
                    kind: 'error_page',
                    selector: 'body',
                    confidence: 0.8,
                    meta: withVisual(document.body, 'error_page', {
                        error_type: type,
                        message: h1Text || bodyText.substring(0, 200)
                    })
                });
                break;
            }
        }
    }

    // ---- Run all detectors ----
    detectTables();
    detectForms();
    detectNavigation();
    detectModals();
    detectDetailViews();
    detectDashboards();
    detectSearch();
    detectTabs();
    detectCharts();
    detectListViews();
    detectStatCards();
    detectEmptyStates();
    detectErrorPages();

    return JSON.stringify(results);
})()
"#;
