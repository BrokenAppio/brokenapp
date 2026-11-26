//! Routers configured in code: React Router (JSX `<Route>` trees and route
//! objects), React Router v7 / Remix `app/routes.ts`, Vue Router, Angular.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::LazyLock;

use regex::Regex;

use super::file_routers::remix_flat_routes;
use super::fs;
use super::js::{self, JsSource, Node, Value};
use super::next::has_default_export;
use super::paths;
use super::{Ctx, Found, Origin, Outcome};

const MAX_DEPTH: usize = 24;
const SCRIPT_EXTS: &[&str] = &["tsx", "ts", "jsx", "js", "mjs", "mts", "vue"];

static IMPORT_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)"#).expect("valid regex")
});
static THEN_MEMBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.then\s*\(\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)")
        .expect("valid regex")
});
static EXPORT_DEFAULT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bexport\s+default\s+").expect("valid regex"));
static BASENAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bbasename\s*(?:=|:)\s*\{?\s*["'`](/[^"'`]*)["'`]"#).expect("valid regex")
});

/// Walks route trees, following identifiers and imports, and remembers which
/// arrays were already visited so shared arrays are not counted as roots.
struct Walker<'a> {
    ctx: &'a Ctx,
    out: Vec<Found>,
    consumed: HashSet<(PathBuf, usize)>,
}

impl<'a> Walker<'a> {
    fn new(ctx: &'a Ctx) -> Self {
        Self {
            ctx,
            out: Vec::new(),
            consumed: HashSet::new(),
        }
    }

    fn note_runtime_path(&self, file: &Path, src: &JsSource, offset: usize) {
        self.ctx.note(format!(
            "route path computed at runtime, not listed: {}:{}",
            self.ctx.rel(file),
            src.line(offset)
        ));
    }

    /// Resolves an identifier to the offset of its value: same-file
    /// declaration first, then an imported binding.
    fn resolve_ident(
        &self,
        file: &Path,
        src: &Rc<JsSource>,
        name: &str,
        depth: usize,
    ) -> Option<(PathBuf, Rc<JsSource>, usize)> {
        if depth > 4 {
            return None;
        }
        if let Some(off) = js::find_const_value(&src.text, name) {
            return Some((file.to_path_buf(), src.clone(), off));
        }
        let import = js::parse_imports(&src.text)
            .into_iter()
            .find(|i| i.local == name)?;
        let target = self.ctx.resolve_import(file, &import.spec)?;
        let target_src = self.ctx.source(&target)?;
        self.resolve_export(&target, &target_src, &import.imported, depth + 1)
    }

    /// Offset of an exported value (`default` or a named export).
    fn resolve_export(
        &self,
        file: &Path,
        src: &Rc<JsSource>,
        export: &str,
        depth: usize,
    ) -> Option<(PathBuf, Rc<JsSource>, usize)> {
        if export != "default" {
            return self.resolve_ident(file, src, export, depth);
        }
        let m = EXPORT_DEFAULT_RE.find(&src.text)?;
        let start = m.end();
        let bytes = src.bytes();
        if bytes
            .get(start)
            .is_some_and(|b| js::is_ident_byte(*b) && !b.is_ascii_digit())
        {
            let end = js::skip_expression(bytes, start);
            let ident = src.text[start..end].trim();
            if js::is_plain_ident(ident) {
                return self.resolve_ident(file, src, ident, depth + 1);
            }
        }
        Some((file.to_path_buf(), src.clone(), start))
    }

    fn walk_value(
        &mut self,
        file: &Path,
        src: &Rc<JsSource>,
        node: &Node,
        parent: &str,
        depth: usize,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        match &node.value {
            Value::Arr(items) => {
                self.consumed.insert((file.to_path_buf(), node.offset));
                for item in items {
                    self.walk_value(file, src, item, parent, depth + 1);
                }
            }
            Value::Obj(_) => self.walk_object(file, src, node, parent, depth),
            Value::Spread(inner) => self.walk_value(file, src, inner, parent, depth + 1),
            Value::Raw(_) => {
                // Only follow conditional branches after a value is known to
                // belong to a route tree; arbitrary objects with `path` fields
                // elsewhere in the application are not route declarations.
                if let Some(branches) = conditional_values(src, node) {
                    self.ctx.note(format!(
                        "conditional route branches listed as source hints, not verified active: {}:{}",
                        self.ctx.rel(file),
                        src.line(node.offset)
                    ));
                    for branch in branches {
                        self.walk_value(file, src, &branch, parent, depth + 1);
                    }
                    return;
                }
                let Some(name) = node.as_ident() else {
                    return;
                };
                if let Some((f2, s2, off)) = self.resolve_ident(file, src, name, 0)
                    && self.consumed.insert((f2.clone(), off))
                {
                    let value = js::parse_value(s2.bytes(), off);
                    self.walk_value(&f2, &s2, &value, parent, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn walk_object(
        &mut self,
        file: &Path,
        src: &Rc<JsSource>,
        node: &Node,
        parent: &str,
        depth: usize,
    ) {
        let path_node = node.prop("path");
        let path: Option<String> = match path_node {
            None => None,
            Some(n) => match &n.value {
                Value::Str(s) => Some(s.clone()),
                Value::Raw(_) => match n.as_ident().and_then(|id| self.const_string(file, src, id))
                {
                    Some(s) => Some(s),
                    None => {
                        self.note_runtime_path(file, src, n.offset);
                        return;
                    }
                },
                _ => {
                    self.note_runtime_path(file, src, n.offset);
                    return;
                }
            },
        };
        let is_index = node.prop("index").and_then(Node::raw_text) == Some("true");
        let element_text = ["element", "component", "Component", "render"]
            .iter()
            .filter_map(|k| node.prop(k))
            .filter_map(Node::raw_text)
            .collect::<Vec<_>>()
            .join(" ");
        let redirect = node.prop("redirect").is_some()
            || node.prop("redirectTo").is_some()
            || element_text.contains("<Navigate")
            || element_text.contains("<Redirect");
        let has_view = [
            "element",
            "component",
            "Component",
            "components",
            "lazy",
            "loadComponent",
            "render",
        ]
        .iter()
        .any(|k| node.prop(k).is_some());
        let children = node.prop("children");
        let load_children = node.prop("loadChildren");

        let own = match &path {
            Some(p) => paths::join(parent, &paths::clean_param_syntax(p)),
            None => paths::normalize(parent),
        };
        let wildcard = path.as_deref().is_some_and(|p| {
            let cleaned = paths::clean_param_syntax(p);
            paths::is_wildcard_only(&cleaned)
        });
        if (path.is_some() || is_index) && !wildcard {
            let line = src.line(path_node.map_or(node.offset, |n| n.offset));
            let kind = if redirect {
                Some("redirect")
            } else if has_view || (children.is_none() && load_children.is_none()) {
                Some("page")
            } else {
                None
            };
            if let Some(kind) = kind {
                self.out
                    .push(Found::new(own.clone(), kind, file, line, Origin::Client));
            }
        }
        if wildcard {
            return;
        }
        if let Some(children) = children {
            self.walk_value(file, src, children, &own, depth + 1);
        }
        if let Some(text) = load_children.and_then(Node::raw_text) {
            self.walk_lazy_children(file, text, &own, depth);
        }
    }

    /// Angular `loadChildren: () => import('./x').then(m => m.ROUTES)`.
    fn walk_lazy_children(&mut self, file: &Path, text: &str, parent: &str, depth: usize) {
        let Some(spec) = IMPORT_CALL_RE.captures(text).map(|c| c[1].to_string()) else {
            return;
        };
        let Some(target) = self.ctx.resolve_import(file, &spec) else {
            return;
        };
        let Some(target_src) = self.ctx.source(&target) else {
            return;
        };
        let export = THEN_MEMBER_RE
            .captures(text)
            .filter(|c| c[1] == c[2])
            .map(|c| c[3].to_string());
        let resolved = match export {
            Some(name) => self.resolve_export(&target, &target_src, &name, 0),
            None => self.first_routes_array(&target, &target_src),
        };
        if let Some((f2, s2, off)) = resolved
            && self.consumed.insert((f2.clone(), off))
        {
            let value = js::parse_value(s2.bytes(), off);
            self.walk_value(&f2, &s2, &value, parent, depth + 1);
        }
    }

    /// A lazily loaded module's routes: `forChild([...])`, a `Routes`-typed
    /// const, or the default export.
    fn first_routes_array(
        &self,
        file: &Path,
        src: &Rc<JsSource>,
    ) -> Option<(PathBuf, Rc<JsSource>, usize)> {
        if let Some(m) = FOR_CHILD_RE.find(&src.text) {
            return Some((file.to_path_buf(), src.clone(), m.end()));
        }
        if let Some(m) = TYPED_ROUTES_RE.find(&src.text) {
            return Some((file.to_path_buf(), src.clone(), m.end()));
        }
        self.resolve_export(file, src, "default", 0)
    }

    fn const_string(&self, file: &Path, src: &Rc<JsSource>, name: &str) -> Option<String> {
        let (_, s2, off) = self.resolve_ident(file, src, name, 0)?;
        js::string_at(s2.bytes(), off).map(|(s, _)| s)
    }

    /// Parses the first argument of every `CALL(` match in `src` as a root
    /// route tree. `routes_prop` reads `{ routes: [...] }` (Vue
    /// `createRouter`).
    fn walk_calls(&mut self, file: &Path, src: &Rc<JsSource>, re: &Regex, routes_prop: bool) {
        let starts: Vec<usize> = re.find_iter(&src.text).map(|m| m.end()).collect();
        for start in starts {
            let arg = js::parse_value(src.bytes(), start);
            if routes_prop {
                if let Some(routes) = arg.prop("routes") {
                    self.walk_value(file, src, routes, "/", 0);
                }
            } else {
                self.walk_value(file, src, &arg, "/", 0);
            }
        }
    }

    /// Typed route arrays not reached from a router call are roots too.
    fn walk_unconsumed(&mut self, candidates: Vec<(PathBuf, Rc<JsSource>, usize)>) {
        for (file, src, off) in candidates {
            if self.consumed.contains(&(file.clone(), off)) {
                continue;
            }
            let value = js::parse_value(src.bytes(), off);
            if matches!(value.value, Value::Arr(_)) {
                self.walk_value(&file, &src, &value, "/", 0);
            }
        }
    }

    // ------------------------------------------------------------ JSX

    /// `<Route path="..." element={...}>` trees (React Router, wouter).
    fn walk_jsx(&mut self, file: &Path, src: &Rc<JsSource>) {
        let text = src.text.as_str();
        let bytes = src.bytes();
        let mut stack: Vec<String> = Vec::new();
        let mut i = 0;
        loop {
            let open_at = text[i..].find("<Route").map(|r| r + i);
            let close_at = text[i..].find("</Route").map(|r| r + i);
            let (at, is_close) = match (open_at, close_at) {
                (Some(o), Some(c)) if c < o => (c, true),
                (Some(o), _) => (o, false),
                (None, Some(c)) => (c, true),
                (None, None) => break,
            };
            if is_close {
                let after = at + "</Route".len();
                if bytes.get(js::skip_ws(bytes, after)) == Some(&b'>') {
                    stack.pop();
                }
                i = after;
                continue;
            }
            let after = at + "<Route".len();
            if !bytes
                .get(after)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'/' || *b == b'>')
            {
                i = after;
                continue;
            }
            let Some(tag) = parse_tag(bytes, after) else {
                break;
            };
            i = tag.end + 1;
            let parent = stack.last().cloned().unwrap_or_else(|| "/".to_string());
            let own = self.emit_jsx_route(file, src, &tag, &parent);
            if !tag.self_closing {
                stack.push(own.unwrap_or(parent));
            }
        }
    }

    /// Emits the route for one `<Route>` tag and returns its full path
    /// (`None` when the path could not be read).
    fn emit_jsx_route(
        &mut self,
        file: &Path,
        src: &Rc<JsSource>,
        tag: &Tag,
        parent: &str,
    ) -> Option<String> {
        let attr = |name: &str| tag.attrs.iter().find(|a| a.name == name);
        let is_index = attr("index")
            .is_some_and(|a| matches!(&a.value, AttrValue::Bool) || a.text() == "true");
        let element = ["element", "component", "Component", "render"]
            .iter()
            .filter_map(|k| attr(k))
            .map(Attr::text)
            .collect::<Vec<_>>()
            .join(" ");
        let redirect = element.contains("<Navigate") || element.contains("<Redirect");
        let kind = if redirect { "redirect" } else { "page" };

        let paths_found: Vec<String> = match attr("path") {
            None if is_index => {
                let line = src.line(tag.start);
                self.out.push(Found::new(
                    paths::normalize(parent),
                    kind,
                    file,
                    line,
                    Origin::Client,
                ));
                return Some(paths::normalize(parent));
            }
            None => return Some(paths::normalize(parent)),
            Some(a) => match self.attr_paths(file, src, a) {
                Some(p) => p,
                None => {
                    self.note_runtime_path(file, src, a.offset);
                    return None;
                }
            },
        };
        let line = src.line(attr("path").map_or(tag.start, |a| a.offset));
        let mut first = None;
        for p in paths_found {
            let cleaned = paths::clean_param_syntax(&p);
            let own = paths::join(parent, &cleaned);
            if !paths::is_wildcard_only(&cleaned) {
                self.out
                    .push(Found::new(own.clone(), kind, file, line, Origin::Client));
            }
            first.get_or_insert(own);
        }
        first
    }

    fn attr_paths(&self, file: &Path, src: &Rc<JsSource>, attr: &Attr) -> Option<Vec<String>> {
        match &attr.value {
            AttrValue::Str(s) => Some(vec![s.clone()]),
            AttrValue::Bool => None,
            AttrValue::Expr(inner) => {
                let node = js::parse_value(inner.as_bytes(), 0);
                match &node.value {
                    Value::Str(s) => Some(vec![s.clone()]),
                    Value::Arr(items) => {
                        let v: Vec<String> = items
                            .iter()
                            .filter_map(|n| n.as_str().map(str::to_string))
                            .collect();
                        (!v.is_empty()).then_some(v)
                    }
                    Value::Raw(_) => node
                        .as_ident()
                        .and_then(|id| self.const_string(file, src, id))
                        .map(|s| vec![s]),
                    _ => None,
                }
            }
        }
    }
}

static FOR_CHILD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bRouterModule\s*\.\s*forChild\s*\(\s*").expect("valid regex"));
static TYPED_ROUTES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*:\s*(?:Readonly\s*<\s*)?(?:Array\s*<\s*)?(?:Routes|Route\[\]|RouteObject|RouteRecordRaw)\b[^=;]*=\s*",
    )
    .expect("valid regex")
});

#[derive(Debug)]
enum AttrValue {
    Str(String),
    Expr(String),
    Bool,
}

#[derive(Debug)]
struct Attr {
    name: String,
    value: AttrValue,
    offset: usize,
}

impl Attr {
    fn text(&self) -> &str {
        match &self.value {
            AttrValue::Str(s) | AttrValue::Expr(s) => s,
            AttrValue::Bool => "",
        }
    }
}

struct Tag {
    start: usize,
    attrs: Vec<Attr>,
    /// Index of the closing `>`.
    end: usize,
    self_closing: bool,
}

/// Reads JSX attributes from just after the tag name up to its `>`.
fn parse_tag(bytes: &[u8], mut i: usize) -> Option<Tag> {
    let start = i;
    let mut attrs = Vec::new();
    loop {
        i = js::skip_ws(bytes, i);
        match bytes.get(i)? {
            b'/' if bytes.get(i + 1) == Some(&b'>') => {
                return Some(Tag {
                    start,
                    attrs,
                    end: i + 1,
                    self_closing: true,
                });
            }
            b'>' => {
                return Some(Tag {
                    start,
                    attrs,
                    end: i,
                    self_closing: false,
                });
            }
            b'{' => {
                i = js::find_matching(bytes, i)? + 1;
                continue;
            }
            _ => {}
        }
        let name_start = i;
        while i < bytes.len()
            && (js::is_ident_byte(bytes[i]) || bytes[i] == b'-' || bytes[i] == b':')
        {
            i += 1;
        }
        if i == name_start {
            i += 1;
            continue;
        }
        let name = String::from_utf8_lossy(&bytes[name_start..i]).into_owned();
        let eq = js::skip_ws(bytes, i);
        if bytes.get(eq) != Some(&b'=') {
            attrs.push(Attr {
                name,
                value: AttrValue::Bool,
                offset: name_start,
            });
            continue;
        }
        let v = js::skip_ws(bytes, eq + 1);
        match bytes.get(v)? {
            b'"' | b'\'' => {
                let (s, end) = js::string_at(bytes, v)?;
                attrs.push(Attr {
                    name,
                    value: AttrValue::Str(s),
                    offset: name_start,
                });
                i = end;
            }
            b'{' => {
                let close = js::find_matching(bytes, v)?;
                let inner = String::from_utf8_lossy(&bytes[v + 1..close])
                    .trim()
                    .to_string();
                attrs.push(Attr {
                    name,
                    value: AttrValue::Expr(inner),
                    offset: name_start,
                });
                i = close + 1;
            }
            _ => i = v + 1,
        }
    }
}

fn script_files(ctx: &Ctx) -> Vec<PathBuf> {
    ctx.files.with_ext(SCRIPT_EXTS).cloned().collect()
}

fn typed_candidates(
    file: &Path,
    src: &Rc<JsSource>,
    re: &Regex,
) -> Vec<(PathBuf, Rc<JsSource>, usize)> {
    re.find_iter(&src.text)
        .map(|m| (file.to_path_buf(), src.clone(), m.end()))
        .collect()
}

// ---------------------------------------------------------------- React Router

static RR_HASH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<HashRouter\b|\bcreateHashHistory\b|\buseHashLocation\b").expect("valid regex")
});
static RR_BROWSER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<BrowserRouter\b").expect("valid regex"));
static CONST_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bconst\s+([A-Za-z_$][\w$]*)").expect("valid regex"));
static BINDING_DECL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)").expect("valid regex")
});
static IDENT_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(\s*").expect("valid regex")
});
static RR_NAMESPACE_IMPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bimport\s*\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*["'](react-router(?:-dom)?(?:/server)?)["']"#)
        .expect("valid regex")
});

/// Keep offsets while excluding strings from declaration/call matching.
fn code_tokens(src: &JsSource) -> String {
    let bytes = src.bytes();
    let mut code = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'\'' | b'"' | b'`') {
            let end = js::skip_string(bytes, i);
            for b in &mut code[i..end] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    String::from_utf8(code).expect("blanking strings preserves UTF-8")
}

/// Preserve module specifiers for the existing import parser, but do not let
/// import examples embedded in strings prove a router binding.
fn import_tokens(src: &JsSource, code: &str) -> String {
    static MODULE_PREFIX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:from\s*|require\s*\(\s*)$").expect("valid regex"));
    let mut imports = code.as_bytes().to_vec();
    let bytes = src.bytes();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], b'\'' | b'"' | b'`') {
            let end = js::skip_string(bytes, i);
            if bytes[i] != b'`' && MODULE_PREFIX.is_match(&code[..i]) {
                imports[i..end].copy_from_slice(&bytes[i..end]);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    String::from_utf8(imports).expect("preserving module strings preserves UTF-8")
}

/// This bounded source reader does not implement JavaScript lexical scopes.
/// Omit a factory name when parameters or repeated declarations make its
/// binding ambiguous, rather than attribute unrelated data calls to a router.
fn ambiguous_factory_names(code: &str) -> HashSet<String> {
    static SINGLE_ARROW: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=>").expect("valid regex"));
    static IDENT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z_$][\w$]*").expect("valid regex"));
    let mut ambiguous = HashSet::new();
    let mut declared = HashSet::new();
    for cap in BINDING_DECL_RE.captures_iter(code) {
        if !declared.insert(cap[1].to_string()) {
            ambiguous.insert(cap[1].to_string());
        }
    }
    for cap in SINGLE_ARROW.captures_iter(code) {
        ambiguous.insert(cap[1].to_string());
    }
    let bytes = code.as_bytes();
    for (open, _) in code.match_indices('(') {
        let Some(close) = js::find_matching(bytes, open) else {
            continue;
        };
        let after = js::skip_ws(bytes, close + 1);
        let prefix = code[..open].trim_end();
        let head = IDENT.find_iter(prefix).last().map(|m| m.as_str());
        if matches!(head, Some("if" | "while" | "for" | "switch" | "with")) {
            continue;
        }
        let tail = &code[after..];
        let parameter_list = tail.starts_with("=>")
            || tail.starts_with('{')
            || (tail.starts_with(':')
                && tail
                    .split(';')
                    .next()
                    .is_some_and(|s| s.contains('{') || s.contains("=>")));
        if parameter_list {
            for ident in IDENT.find_iter(&code[open + 1..close]) {
                ambiguous.insert(ident.as_str().to_string());
            }
        }
    }
    ambiguous
}

/// Literal branches of a top-level ternary, with original source offsets.
/// No conditions are evaluated, and nested brackets/strings cannot supply
/// a false `?` or `:` delimiter.
fn conditional_values(src: &JsSource, node: &Node) -> Option<[Node; 2]> {
    let raw = node.raw_text()?;
    let bytes = src.bytes();
    let mut start = js::skip_ws(bytes, node.offset);
    let mut end = node.offset + raw.len();
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    while bytes.get(start) == Some(&b'(') && js::find_matching(bytes, start) == Some(end - 1) {
        start = js::skip_ws(bytes, start + 1);
        end -= 1;
        while end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
    }
    let mut question = None;
    let mut nested = 0usize;
    let mut i = start;
    while i < end {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                i = js::skip_string(bytes, i);
                continue;
            }
            b'(' | b'[' | b'{' => {
                i = js::find_matching(bytes, i)? + 1;
                continue;
            }
            b'?' if matches!(bytes.get(i + 1), Some(b'?') | Some(b'.')) => {
                i += 2;
                continue;
            }
            b'?' => {
                if question.is_none() {
                    question = Some(i);
                } else {
                    nested += 1;
                }
            }
            b':' if question.is_some() => {
                if nested == 0 {
                    return Some([
                        js::parse_value(&bytes[..i], question? + 1),
                        js::parse_value(&bytes[..end], i + 1),
                    ]);
                }
                nested -= 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// Bit flags: hash, browser. `useRoutes` itself does not choose a history.
const RR_HASH: u8 = 1;
const RR_BROWSER: u8 = 2;

fn factory_mode(
    src: &JsSource,
    node: &Node,
    known: &BTreeMap<String, u8>,
    depth: usize,
) -> Option<u8> {
    if depth > 4 {
        return None;
    }
    if let Some(mode) = node.raw_text().and_then(|name| known.get(name)) {
        return Some(*mode);
    }
    let [a, b] = conditional_values(src, node)?;
    Some(factory_mode(src, &a, known, depth + 1)? | factory_mode(src, &b, known, depth + 1)?)
}

/// Only imported React Router factories and bounded same-file const aliases
/// may establish a route tree. A name like `createCustomRouter` is not proof.
fn router_factories(src: &JsSource, code: &str) -> (BTreeMap<String, u8>, HashSet<String>) {
    let mut factories = BTreeMap::new();
    let mut omitted = HashSet::new();
    let mut ambiguous = ambiguous_factory_names(code);
    let imports = import_tokens(src, code);
    let add_namespace = |factories: &mut BTreeMap<String, u8>, local: &str| {
        for (name, mode) in [
            ("createBrowserRouter", RR_BROWSER),
            ("createHashRouter", RR_HASH),
            ("createStaticRouter", RR_BROWSER),
            ("useRoutes", 0),
        ] {
            factories.insert(format!("{local}.{name}"), mode);
        }
    };
    for import in js::parse_imports(&imports) {
        if !matches!(
            import.spec.as_str(),
            "react-router" | "react-router-dom" | "react-router-dom/server"
        ) {
            continue;
        }
        let declared = js::find_const_value(code, &import.local);
        let is_require = declared.is_some_and(|offset| {
            matches!(js::parse_value(src.bytes(), offset).value, Value::Call { callee, .. } if callee == "require")
        });
        let has_declaration = BINDING_DECL_RE
            .captures_iter(code)
            .any(|cap| cap[1] == import.local);
        if has_declaration && !is_require {
            ambiguous.insert(import.local.clone());
        }
        if ambiguous.contains(&import.local) {
            omitted.insert(import.local);
            continue;
        }
        if import.imported == "default" {
            add_namespace(&mut factories, &import.local);
            continue;
        }
        let mode = match import.imported.as_str() {
            "createHashRouter" => RR_HASH,
            "createBrowserRouter" | "createStaticRouter" => RR_BROWSER,
            "useRoutes" => 0,
            _ => continue,
        };
        factories.insert(import.local, mode);
    }
    for cap in RR_NAMESPACE_IMPORT_RE.captures_iter(&imports) {
        if ambiguous.contains(&cap[1])
            || BINDING_DECL_RE
                .captures_iter(code)
                .any(|decl| decl[1] == cap[1])
        {
            omitted.insert(cap[1].to_string());
            continue;
        }
        add_namespace(&mut factories, &cap[1]);
    }
    for _ in 0..4 {
        let before = factories.len();
        for cap in CONST_NAME_RE.captures_iter(code) {
            let name = &cap[1];
            if factories.contains_key(name) {
                continue;
            }
            let Some(offset) = js::find_const_value(code, name) else {
                continue;
            };
            let node = js::parse_value(src.bytes(), offset);
            if let Some(mode) = factory_mode(src, &node, &factories, 0) {
                if ambiguous.contains(name) {
                    omitted.insert(name.to_string());
                } else {
                    factories.insert(name.to_string(), mode);
                }
            }
        }
        if factories.len() == before {
            break;
        }
    }
    (factories, omitted)
}

pub(crate) fn react_router(ctx: &Ctx) -> Outcome {
    let framework = if ctx.pkg.has_any(&["react-router", "react-router-dom"]) {
        "react-router"
    } else {
        "wouter"
    };
    let mut outcome = Outcome::new(framework);
    let mut walker = Walker::new(ctx);
    let mut candidates = Vec::new();
    let mut history_modes = 0u8;
    for file in script_files(ctx) {
        let Some(src) = ctx.source(&file) else {
            continue;
        };
        let text = &src.text;
        let routerish = text.contains("react-router")
            || text.contains("wouter")
            || text.contains("RouteObject");
        if !routerish {
            continue;
        }
        if text.contains("<Route") {
            walker.walk_jsx(&file, &src);
        }
        let code = code_tokens(&src);
        let (factories, omitted) = router_factories(&src, &code);
        for name in omitted {
            ctx.note(format!("ambiguous or shadowed React Router binding `{name}`; affected calls/routes omitted: {}", ctx.rel(&file)));
        }
        for cap in IDENT_CALL_RE.captures_iter(&code) {
            let call = cap.get(0).expect("whole call");
            if code[..call.start()].trim_end().ends_with('.') {
                continue;
            }
            let callee: String = cap[1].chars().filter(|c| !c.is_whitespace()).collect();
            let Some(mode) = factories.get(&callee) else {
                continue;
            };
            history_modes |= *mode;
            let arg = js::parse_value(src.bytes(), call.end());
            walker.walk_value(&file, &src, &arg, "/", 0);
        }
        candidates.extend(typed_candidates(&file, &src, &TYPED_ROUTES_RE));
        if RR_HASH_RE.is_match(&code) {
            history_modes |= RR_HASH;
        }
        if RR_BROWSER_RE.is_match(&code) {
            history_modes |= RR_BROWSER;
        }
        if outcome.base_path.is_empty()
            && let Some(cap) = BASENAME_RE.captures(text)
        {
            outcome.base_path = paths::normalize_base(&cap[1]);
        }
    }
    walker.walk_unconsumed(candidates);
    if history_modes == (RR_HASH | RR_BROWSER) {
        ctx.note("React Router can select browser or hash history at runtime; source hints use browser paths. Confirm the active runtime before scanning hash-only deployments.".to_string());
    }
    outcome.hash_routing = history_modes == RR_HASH;
    outcome.routes = walker.out;
    outcome
}

// ---------------------------------------------------------------- Vue Router

static VUE_CREATE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcreateRouter\s*\(\s*").expect("valid regex"));
static VUE_V3_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnew\s+(?:VueRouter|Router)\s*\(\s*").expect("valid regex"));
static VUE_HASH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bcreateWebHashHistory\b|\bmode\s*:\s*["']hash["']"#).expect("valid regex")
});
static VUE_BASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bcreateWeb(?:Hash)?History\s*\(\s*["'`](/[^"'`]*)["'`]"#).expect("valid regex")
});

pub(crate) fn vue(ctx: &Ctx) -> Outcome {
    let mut outcome = Outcome::new("vue-router");
    let mut walker = Walker::new(ctx);
    let mut candidates = Vec::new();
    for file in script_files(ctx) {
        let Some(src) = ctx.source(&file) else {
            continue;
        };
        let text = &src.text;
        if !(text.contains("vue-router")
            || text.contains("RouteRecordRaw")
            || text.contains("createRouter"))
        {
            continue;
        }
        walker.walk_calls(&file, &src, &VUE_CREATE_RE, true);
        walker.walk_calls(&file, &src, &VUE_V3_RE, true);
        candidates.extend(typed_candidates(&file, &src, &TYPED_ROUTES_RE));
        if VUE_HASH_RE.is_match(text) {
            outcome.hash_routing = true;
        }
        if outcome.base_path.is_empty()
            && let Some(cap) = VUE_BASE_RE.captures(text)
        {
            outcome.base_path = paths::normalize_base(&cap[1]);
        }
    }
    walker.walk_unconsumed(candidates);
    outcome.routes = walker.out;
    outcome
}

// ---------------------------------------------------------------- Angular

static NG_ROOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:RouterModule\s*\.\s*forRoot|provideRouter)\s*\(\s*").expect("valid regex")
});
static NG_HASH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\buseHash\s*:\s*true\b|\bwithHashLocation\s*\(|\bHashLocationStrategy\b")
        .expect("valid regex")
});
static NG_BASE_HREF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<base\s+href\s*=\s*["'](/[^"']*)["']"#).expect("valid regex"));

pub(crate) fn angular(ctx: &Ctx) -> Outcome {
    let mut outcome = Outcome::new("angular");
    let mut walker = Walker::new(ctx);
    let mut candidates = Vec::new();
    for file in script_files(ctx) {
        let Some(src) = ctx.source(&file) else {
            continue;
        };
        let text = &src.text;
        if !text.contains("@angular/router") && !text.contains("Routes") {
            continue;
        }
        walker.walk_calls(&file, &src, &NG_ROOT_RE, false);
        candidates.extend(typed_candidates(&file, &src, &TYPED_ROUTES_RE));
        candidates.extend(typed_candidates(&file, &src, &FOR_CHILD_RE));
        if NG_HASH_RE.is_match(text) {
            outcome.hash_routing = true;
        }
    }
    walker.walk_unconsumed(candidates);
    outcome.routes = walker.out;
    if let Some(index) = fs::read_source(&ctx.app_dir.join("src/index.html"))
        && let Some(cap) = NG_BASE_HREF_RE.captures(&index)
    {
        outcome.base_path = paths::normalize_base(&cap[1]);
    }
    outcome
}

// ---------------------------------------------------------------- Remix / RR7

/// Remix and React Router v7 framework mode: `app/routes.ts` when present
/// (with `flatRoutes()` support), else the `app/routes/` file convention.
pub(crate) fn remix(ctx: &Ctx) -> Outcome {
    let mut outcome = Outcome::new("remix");
    let app = ctx.app_dir.join("app");
    let v1 = ["@remix-run/react", "@remix-run/dev"]
        .iter()
        .any(|d| ctx.pkg.major(d).is_some_and(|m| m < 2));
    let config = fs::first_config(&app, &["routes"]).and_then(|p| ctx.source(&p).map(|s| (p, s)));
    match config {
        Some((cfg_file, src)) if !v1 => {
            let mut rr7 = Rr7 {
                ctx,
                app: app.clone(),
                cfg_file: cfg_file.clone(),
                out: Vec::new(),
            };
            if let Some(m) = EXPORT_DEFAULT_RE.find(&src.text) {
                let node = js::parse_value(src.bytes(), m.end());
                rr7.walk(&src, std::slice::from_ref(&node), "/", 0);
            }
            outcome.routes = rr7.out;
        }
        _ => outcome.routes = remix_flat_routes(ctx, &app.join("routes"), "/", v1),
    }
    for name in ["react-router.config", "vite.config", "remix.config"] {
        if let Some(text) =
            fs::first_config(&ctx.app_dir, &[name]).and_then(|p| fs::read_source(&p))
            && let Some(cap) = BASENAME_RE.captures(&JsSource::new(&text).text)
        {
            outcome.base_path = paths::normalize_base(&cap[1]);
            break;
        }
    }
    outcome
}

/// React Router v7 `app/routes.ts` helpers: `index`, `route`, `layout`,
/// `prefix`, `flatRoutes`.
struct Rr7<'a> {
    ctx: &'a Ctx,
    app: PathBuf,
    cfg_file: PathBuf,
    out: Vec<Found>,
}

impl Rr7<'_> {
    fn walk(&mut self, src: &Rc<JsSource>, nodes: &[Node], parent: &str, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        for node in nodes {
            match &node.value {
                Value::Arr(items) => self.walk(src, items, parent, depth + 1),
                Value::Spread(inner) => {
                    self.walk(src, std::slice::from_ref(inner), parent, depth + 1)
                }
                Value::Raw(_) => {
                    if let Some(off) = node
                        .as_ident()
                        .and_then(|id| js::find_const_value(&src.text, id))
                    {
                        let value = js::parse_value(src.bytes(), off);
                        self.walk(src, std::slice::from_ref(&value), parent, depth + 1);
                    }
                }
                Value::Call { callee, args } => {
                    let name = callee.rsplit('.').next().unwrap_or(callee);
                    self.call(src, node, name, args, parent, depth);
                }
                _ => {}
            }
        }
    }

    fn call(
        &mut self,
        src: &Rc<JsSource>,
        node: &Node,
        name: &str,
        args: &[Node],
        parent: &str,
        depth: usize,
    ) {
        let line = src.line(node.offset);
        match name {
            "index" => {
                if let Some(file) = args.first().and_then(Node::as_str) {
                    self.emit(paths::normalize(parent), file, line);
                }
            }
            "route" => {
                let Some(path) = args.first().and_then(Node::as_str) else {
                    self.ctx.note(format!(
                        "route path computed at runtime, not listed: {}:{line}",
                        self.ctx.rel(&self.cfg_file)
                    ));
                    return;
                };
                let cleaned = paths::clean_param_syntax(path);
                let own = paths::join(parent, &cleaned);
                if !paths::is_wildcard_only(&cleaned)
                    && let Some(file) = args.get(1).and_then(Node::as_str)
                {
                    self.emit(own.clone(), file, line);
                }
                if let Some(children) = args.get(2) {
                    self.walk(src, std::slice::from_ref(children), &own, depth + 1);
                }
            }
            "layout" => {
                if let Some(children) = args.get(1) {
                    self.walk(src, std::slice::from_ref(children), parent, depth + 1);
                }
            }
            "prefix" => {
                if let (Some(path), Some(children)) =
                    (args.first().and_then(Node::as_str), args.get(1))
                {
                    let own = paths::join(parent, path);
                    self.walk(src, std::slice::from_ref(children), &own, depth + 1);
                }
            }
            "flatRoutes" => {
                let routes_dir = self.app.join("routes");
                self.out
                    .extend(remix_flat_routes(self.ctx, &routes_dir, parent, false));
            }
            _ => {}
        }
    }

    fn emit(&mut self, path: String, file_spec: &str, line: u32) {
        let file = fs::clean_path(&self.app.join(file_spec));
        let (file, line, kind) = match self.ctx.source(&file) {
            Some(src) => {
                let markdown = file.extension().is_some_and(|e| e == "md" || e == "mdx");
                let kind = if markdown || has_default_export(&src) {
                    "page"
                } else {
                    "api"
                };
                (file, 1, kind)
            }
            None => (self.cfg_file.clone(), line, "page"),
        };
        self.out
            .push(Found::new(path, kind, &file, line, Origin::File));
    }
}

// ---------------------------------------------------------------- Custom Hash Router

static HASH_DEFAULT_VIEW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\?\s*[A-Za-z_$][\w$]*(?:\s+as\s+[A-Za-z_$][\w$]*)?\s*:\s*['"]([a-zA-Z0-9_-]+)['"]"#,
    )
    .expect("valid regex")
});
static HASH_VIEW_BRANCH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bview\s*===\s*['"]([a-zA-Z0-9_-]+)['"]"#).expect("valid regex")
});
static HASH_ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"location\.hash\s*=\s*(?:'([^']+)'|"([^"]+)"|`([^`]+)`)"#).expect("valid regex")
});
static TEMPLATE_EXPR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));

/// Detects hand-rolled `window.location.hash` + `hashchange` SPA routers
/// (e.g., Vite + React apps that switch on `view === '...'` without a router library).
pub(crate) fn custom_hash_routes(ctx: &Ctx) -> Outcome {
    let is_vite = ctx.pkg.has("vite");
    let mut outcome = Outcome::new(if is_vite { "vite" } else { "static" });
    for file in script_files(ctx) {
        let Some(src) = ctx.source(&file) else {
            continue;
        };
        let text = &src.text;
        if !(text.contains("location.hash") && text.contains("hashchange")) {
            continue;
        }
        let default_view = HASH_DEFAULT_VIEW_RE
            .captures(text)
            .map(|c| c[1].to_string());

        for cap in HASH_VIEW_BRANCH_RE.captures_iter(text) {
            let m = cap.get(0).expect("match");
            let line = src.line(m.start());
            let view_name = &cap[1];
            if default_view.as_deref() == Some(view_name) {
                outcome.routes.push(Found::new(
                    "/".to_string(),
                    "page",
                    &file,
                    line,
                    Origin::File,
                ));
            } else {
                crate::explorer::url_utils::register_route_fragment(view_name);
                outcome.routes.push(Found::new(
                    format!("/#{view_name}"),
                    "page",
                    &file,
                    line,
                    Origin::File,
                ));
            }
        }

        for cap in HASH_ASSIGN_RE.captures_iter(text) {
            let m = cap.get(0).expect("match");
            let line = src.line(m.start());
            let Some(val) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) else {
                continue;
            };
            let raw = val.as_str().trim().trim_start_matches('#');
            let path_part = raw.split('?').next().unwrap_or(raw).trim_matches('/');
            if path_part.is_empty() {
                continue;
            }
            let templated = TEMPLATE_EXPR_RE.replace_all(path_part, ":id");
            if templated.split('/').all(|seg| {
                !seg.is_empty()
                    && (seg == ":id"
                        || seg
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            }) {
                crate::explorer::url_utils::register_route_fragment(&templated);
                outcome.routes.push(Found::new(
                    format!("/#{templated}"),
                    "page",
                    &file,
                    line,
                    Origin::File,
                ));
            }
        }
    }
    outcome
}
