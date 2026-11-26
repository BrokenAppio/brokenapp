//! Server routes registered in code: Hono, Express and Fastify.
//!
//! Router instances are found by declaration (`new Hono()`, `express()`,
//! `express.Router()`, `Router()`, `fastify()`) or, in files that import a
//! server framework, by conventional receiver names (`app`, `router`,
//! `fastify`, `server`, `instance`). Method calls (`.get('/x', ...)`, chained
//! calls, Express `.route('/x').get(...)`, Hono `.on(...)`, Fastify
//! `.route({ ... })`) become routes. Mounts (`app.route('/admin', admin)`,
//! `app.use('/api', router)`, `fastify.register(plugin, { prefix })`) are
//! followed across imports so sub-router paths get their prefixes.
//!
//! A `GET` handler is a `page` when it renders HTML (JSX, `c.html`,
//! `res.render`, `render(c, ...)`, directly or through a helper function);
//! other handlers are `api` (or `redirect` when that is all they do).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::LazyLock;

use regex::Regex;

use super::js::{self, Import, JsSource, Node, Value};
use super::paths;
use super::{Ctx, Found, Origin, Outcome};

const SCRIPT_EXTS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];
const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "all",
];

static DECL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=;]+?)?=\s*(new\s+(?:Hono|OpenAPIHono)\b|express\s*\(\s*\)|(?:express\s*\.\s*)?Router\b|[Ff]astify\b)",
    )
    .expect("valid regex")
});
static DEFAULT_NEW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bexport\s+default\s+new\s+(?:Hono|OpenAPIHono)\b").expect("valid regex")
});
static SERVER_EVIDENCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"["'](?:hono(?:/[\w-]+)*|express|fastify|itty-router)["']|\bFastify(?:Instance|PluginAsync|PluginCallback)\b|\bHono\b"#,
    )
    .expect("valid regex")
});
static EXPORT_DEFAULT_IDENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bexport\s+default\s+([A-Za-z_$][\w$]*)\s*(?:;|\n|$)").expect("valid regex")
});
static MODULE_EXPORTS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bmodule\s*\.\s*exports\s*=\s*([A-Za-z_$][\w$]*)\s*(?:;|\n|$)")
        .expect("valid regex")
});
static EXPORT_DEFAULT_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:export\s+default|module\s*\.\s*exports\s*=)\s+(?:async\s+)?(?:function\b|\()")
        .expect("valid regex")
});
static EXPORT_NAMED_DECL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bexport\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)").expect("valid regex")
});
static EXPORT_LIST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bexport\s*\{([^}]*)\}").expect("valid regex"));

static PAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i:<!doctype|<html\b)|\b(?:c|ctx|context)\s*\.\s*(?:html|render)\s*\(|\bres\s*\.\s*(?:render|sendFile)\s*\(|\breply\s*\.\s*(?:view|html)\s*\(|\brender\w*\s*\(\s*(?:c|ctx|context|req|res)\b|\brenderTo(?:String|ReadableStream|PipeableStream|StaticMarkup)\b|\bhtml\s*`|text/html",
    )
    .expect("valid regex")
});
static API_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\.\s*json\s*\(|\b(?:c|ctx|context)\s*\.\s*(?:text|body|newResponse)\s*\(|\bres\s*\.\s*(?:send|end|sendStatus|download|attachment|write|type)\s*\(|\bnew\s+Response\s*\(|\breply\s*\.\s*(?:send|code|status|type)\s*\(|\bstream\w*\s*\(",
    )
    .expect("valid regex")
});
static REDIRECT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\s*redirect\s*\(").expect("valid regex"));
static CALLED_IDENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\(").expect("valid regex"));
static TOP_LEVEL_LINE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\n[A-Za-z_$@]").expect("valid regex"));
static IMPLICIT_RECEIVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:^|[^.\w$])(app|router|fastify|server|instance)\s*\.\s*(?:get|post|put|delete|patch|head|options|all)\s*\(\s*["'`/]"#,
    )
    .expect("valid regex")
});
static RECEIVER_DOT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*\.").expect("valid regex"));
static TOP_LEVEL_FN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)|^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)",
    )
    .expect("valid regex")
});

type RouterKey = (PathBuf, String);

#[derive(Debug)]
struct Registration {
    path: String,
    method: String,
    kind: &'static str,
    line: u32,
}

#[derive(Debug)]
enum Target {
    Local(String),
    Import { file: PathBuf, name: String },
}

#[derive(Debug)]
struct Mount {
    prefix: String,
    target: Target,
}

#[derive(Debug, Default)]
struct RouterInfo {
    base: String,
    regs: Vec<Registration>,
    mounts: Vec<Mount>,
}

#[derive(Debug, Default)]
struct FileInfo {
    routers: BTreeMap<String, RouterInfo>,
    default_export: Option<String>,
    /// exported name -> local router variable
    exports: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Page,
    Api,
    Unknown,
}

pub(crate) fn discover(ctx: &Ctx, framework: &'static str) -> Outcome {
    let mut outcome = Outcome::new(framework);
    let scanner = Scanner {
        ctx,
        fn_shapes: RefCell::new(HashMap::new()),
    };
    let mut files: BTreeMap<PathBuf, FileInfo> = BTreeMap::new();
    for file in ctx.files.with_ext(SCRIPT_EXTS) {
        let Some(src) = ctx.source(file) else {
            continue;
        };
        if !SERVER_EVIDENCE_RE.is_match(&src.text) && !DECL_RE.is_match(&src.text) {
            continue;
        }
        let info = scanner.parse_file(file, &src);
        if !info.routers.is_empty() {
            files.insert(file.clone(), info);
        }
    }

    // Resolve mounts into edges between routers.
    let mut edges: BTreeMap<RouterKey, Vec<(String, RouterKey)>> = BTreeMap::new();
    let mut children: BTreeSet<RouterKey> = BTreeSet::new();
    for (file, info) in &files {
        for (var, router) in &info.routers {
            for mount in &router.mounts {
                let child = match &mount.target {
                    Target::Local(name) => info
                        .routers
                        .contains_key(name)
                        .then(|| (file.clone(), name.clone())),
                    Target::Import { file: f, name } => files.get(f).and_then(|target| {
                        let var =
                            if name == "default" {
                                target.default_export.clone()
                            } else {
                                target.exports.get(name).cloned().or_else(|| {
                                    target.routers.contains_key(name).then(|| name.clone())
                                })
                            }?;
                        target.routers.contains_key(&var).then(|| (f.clone(), var))
                    }),
                };
                if let Some(child) = child {
                    children.insert(child.clone());
                    edges
                        .entry((file.clone(), var.clone()))
                        .or_default()
                        .push((mount.prefix.clone(), child));
                }
            }
        }
    }

    let mut out = Vec::new();
    for (file, info) in &files {
        for (var, router) in &info.routers {
            let key = (file.clone(), var.clone());
            if children.contains(&key) || (router.regs.is_empty() && router.mounts.is_empty()) {
                continue;
            }
            let mut visiting = Vec::new();
            emit(&files, &edges, &key, "/", &mut visiting, &mut out);
        }
    }
    outcome.routes = out;
    outcome
}

fn emit(
    files: &BTreeMap<PathBuf, FileInfo>,
    edges: &BTreeMap<RouterKey, Vec<(String, RouterKey)>>,
    key: &RouterKey,
    prefix: &str,
    visiting: &mut Vec<RouterKey>,
    out: &mut Vec<Found>,
) {
    if visiting.len() > 12 || visiting.contains(key) {
        return;
    }
    let Some(router) = files.get(&key.0).and_then(|f| f.routers.get(&key.1)) else {
        return;
    };
    let base = concat(prefix, &router.base);
    for reg in &router.regs {
        let mut found = Found::new(
            concat(&base, &reg.path),
            reg.kind,
            &key.0,
            reg.line,
            Origin::Server,
        );
        found.methods.insert(reg.method.clone());
        out.push(found);
    }
    visiting.push(key.clone());
    for (mount_prefix, child) in edges.get(key).into_iter().flatten() {
        emit(
            files,
            edges,
            child,
            &concat(&base, mount_prefix),
            visiting,
            out,
        );
    }
    visiting.pop();
}

/// Server mounts concatenate: `/admin` + `/login` -> `/admin/login`.
fn concat(prefix: &str, path: &str) -> String {
    paths::normalize(&format!("{prefix}/{path}"))
}

struct Scanner<'a> {
    ctx: &'a Ctx,
    /// Shape of every top-level function per file.
    fn_shapes: RefCell<HashMap<PathBuf, Rc<HashMap<String, Shape>>>>,
}

/// Per-file parse state.
struct FileScan<'s> {
    file: &'s Path,
    src: &'s Rc<JsSource>,
    imports: Vec<Import>,
    router_names: BTreeSet<String>,
}

impl Scanner<'_> {
    fn parse_file(&self, file: &Path, src: &Rc<JsSource>) -> FileInfo {
        let text = src.text.as_str();
        let bytes = src.bytes();
        let mut info = FileInfo::default();
        // (router var, chain start offset) for declarations.
        let mut decl_chains: Vec<(String, usize)> = Vec::new();

        for cap in DECL_RE.captures_iter(text) {
            let var = cap[1].to_string();
            let Some(ctor) = cap.get(2) else {
                continue;
            };
            let start = if ctor.as_str().ends_with(')') {
                Some(ctor.end())
            } else {
                after_constructor(bytes, ctor.end())
            };
            if let Some(start) = start {
                info.routers.entry(var.clone()).or_default();
                decl_chains.push((var, start));
            }
        }
        if let Some(m) = DEFAULT_NEW_RE.find(text)
            && let Some(start) = after_constructor(bytes, m.end())
        {
            info.routers.entry("default".to_string()).or_default();
            info.default_export = Some("default".to_string());
            decl_chains.push(("default".to_string(), start));
        }
        let mut implicit = Vec::new();
        if SERVER_EVIDENCE_RE.is_match(text) {
            for cap in IMPLICIT_RECEIVER_RE.captures_iter(text) {
                let name = cap[1].to_string();
                if !info.routers.contains_key(&name) {
                    info.routers.insert(name.clone(), RouterInfo::default());
                    implicit.push(name);
                }
            }
        }
        if info.routers.is_empty() {
            return info;
        }

        let scan = FileScan {
            file,
            src,
            imports: js::parse_imports(text),
            router_names: info.routers.keys().cloned().collect(),
        };
        for (var, start) in decl_chains {
            let mut router = info.routers.remove(&var).unwrap_or_default();
            self.parse_chain(&scan, &mut router, start);
            info.routers.insert(var, router);
        }
        let receivers: Vec<(String, usize)> = RECEIVER_DOT_RE
            .captures_iter(text)
            .filter_map(|cap| {
                let name = cap.get(1)?;
                let whole = cap.get(0)?;
                (name.as_str() != "default" && scan.router_names.contains(name.as_str()))
                    .then(|| (name.as_str().to_string(), whole.end() - 1))
            })
            .collect();
        for (var, start) in receivers {
            let mut router = info.routers.remove(&var).unwrap_or_default();
            self.parse_chain(&scan, &mut router, start);
            info.routers.insert(var, router);
        }

        // Exports.
        if info.default_export.is_none() {
            info.default_export = EXPORT_DEFAULT_IDENT_RE
                .captures(text)
                .or_else(|| MODULE_EXPORTS_RE.captures(text))
                .map(|c| c[1].to_string())
                .filter(|v| info.routers.contains_key(v));
        }
        for cap in EXPORT_LIST_RE.captures_iter(text) {
            for part in cap[1].split(',') {
                let (local, exported) = match part.split_once(" as ") {
                    Some((l, e)) => (l.trim(), e.trim()),
                    None => (part.trim(), part.trim()),
                };
                if info.routers.contains_key(local) {
                    if exported == "default" {
                        info.default_export = Some(local.to_string());
                    } else {
                        info.exports.insert(exported.to_string(), local.to_string());
                    }
                }
            }
        }
        for cap in EXPORT_NAMED_DECL_RE.captures_iter(text) {
            if info.routers.contains_key(&cap[1]) {
                info.exports.insert(cap[1].to_string(), cap[1].to_string());
            }
        }
        if info.default_export.is_none() && EXPORT_DEFAULT_FN_RE.is_match(text) {
            info.default_export = implicit.first().cloned();
        }
        info
    }

    /// Parses `.method(args)` calls chained from `p` (which points at `.`).
    fn parse_chain(&self, scan: &FileScan<'_>, router: &mut RouterInfo, mut p: usize) {
        let bytes = scan.src.bytes();
        let text = scan.src.text.as_str();
        let mut route_paths: Option<Vec<String>> = None;
        loop {
            p = js::skip_ws(bytes, p);
            if bytes.get(p) != Some(&b'.') {
                return;
            }
            let name_start = js::skip_ws(bytes, p + 1);
            let mut name_end = name_start;
            while name_end < bytes.len() && js::is_ident_byte(bytes[name_end]) {
                name_end += 1;
            }
            let open = js::skip_ws(bytes, name_end);
            if name_end == name_start || bytes.get(open) != Some(&b'(') {
                return;
            }
            let Some((args, close)) = js::parse_call_args(bytes, open) else {
                return;
            };
            let name = &text[name_start..name_end];
            let line = scan.src.line(name_start);
            let lower = name.to_ascii_lowercase();
            if HTTP_METHODS.contains(&lower.as_str()) && name == lower {
                let first_is_path = args
                    .first()
                    .is_some_and(|a| self.path_values(scan, a).is_some());
                let (path_list, handler_idx) = match (&route_paths, first_is_path) {
                    (Some(rp), false) => (Some(rp.clone()), 0),
                    _ => (args.first().and_then(|a| self.path_values(scan, a)), 1),
                };
                if let Some(path_list) = path_list {
                    let handler = args
                        .get(handler_idx)
                        .map_or("", |h| &text[h.offset.min(close)..close]);
                    for path in path_list {
                        self.register(
                            scan,
                            router,
                            &path,
                            &lower.to_ascii_uppercase(),
                            handler,
                            line,
                        );
                    }
                }
            } else {
                match name {
                    "on" => {
                        let methods = args.first().map(string_list).unwrap_or_default();
                        let path_list = args.get(1).and_then(|a| self.path_values(scan, a));
                        if let Some(path_list) = path_list {
                            let handler = args
                                .get(2)
                                .map_or("", |h| &text[h.offset.min(close)..close]);
                            for method in &methods {
                                for path in &path_list {
                                    self.register(
                                        scan,
                                        router,
                                        path,
                                        &method.to_ascii_uppercase(),
                                        handler,
                                        line,
                                    );
                                }
                            }
                        }
                    }
                    "route" => match args.as_slice() {
                        [single] => route_paths = self.path_values(scan, single),
                        [prefix, target, ..] => {
                            if let (Some(prefix), Some(target)) =
                                (prefix.as_str(), self.target_of(scan, target))
                            {
                                router.mounts.push(Mount {
                                    prefix: prefix.to_string(),
                                    target,
                                });
                            }
                        }
                        [] => {}
                    },
                    "use" => {
                        let (prefix, targets) = match args.first().and_then(Node::as_str) {
                            Some(prefix) => (prefix.to_string(), &args[1..]),
                            None => (String::new(), &args[..]),
                        };
                        for target in targets.iter().filter_map(|t| self.target_of(scan, t)) {
                            router.mounts.push(Mount {
                                prefix: prefix.clone(),
                                target,
                            });
                        }
                    }
                    "register" => {
                        if let Some(target) = args.first().and_then(|t| self.target_of(scan, t)) {
                            let prefix = args
                                .get(1)
                                .and_then(|o| o.prop("prefix"))
                                .and_then(Node::as_str)
                                .unwrap_or_default()
                                .to_string();
                            router.mounts.push(Mount { prefix, target });
                        }
                    }
                    "basePath" => {
                        if let Some(base) = args.first().and_then(Node::as_str) {
                            router.base = concat(&router.base, base);
                        }
                    }
                    _ => {}
                }
                // Fastify `fastify.route({ method, url, handler })`.
                if name == "route"
                    && let Some(obj) = args.first().filter(|a| matches!(a.value, Value::Obj(_)))
                    && let Some(url) = obj
                        .prop("url")
                        .or_else(|| obj.prop("path"))
                        .and_then(Node::as_str)
                {
                    let methods = obj.prop("method").map(string_list).unwrap_or_default();
                    let handler = obj
                        .prop("handler")
                        .map_or("", |h| &text[h.offset.min(close)..close]);
                    for method in methods {
                        self.register(
                            scan,
                            router,
                            url,
                            &method.to_ascii_uppercase(),
                            handler,
                            line,
                        );
                    }
                }
            }
            p = close + 1;
        }
    }

    /// Route path strings from a literal, array of literals, or const.
    fn path_values(&self, scan: &FileScan<'_>, node: &Node) -> Option<Vec<String>> {
        let values = match &node.value {
            Value::Str(s) => vec![s.clone()],
            Value::Arr(items) => items
                .iter()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect(),
            Value::Raw(_) => vec![js::resolve_const_string(&scan.src.text, node.as_ident()?)?],
            _ => return None,
        };
        let values: Vec<String> = values
            .into_iter()
            .filter(|v| v.starts_with('/') || v == "*")
            .collect();
        (!values.is_empty()).then_some(values)
    }

    fn register(
        &self,
        scan: &FileScan<'_>,
        router: &mut RouterInfo,
        path: &str,
        method: &str,
        handler: &str,
        line: u32,
    ) {
        let path = paths::clean_param_syntax(path);
        if paths::is_wildcard_only(&path) {
            return;
        }
        let kind = self.classify(scan, method, &path, handler);
        router.regs.push(Registration {
            path,
            method: method.to_string(),
            kind,
            line,
        });
    }

    fn target_of(&self, scan: &FileScan<'_>, node: &Node) -> Option<Target> {
        match &node.value {
            Value::Raw(_) => {
                let name = node.as_ident()?;
                if scan.router_names.contains(name) {
                    return Some(Target::Local(name.to_string()));
                }
                let import = scan.imports.iter().find(|i| i.local == name)?;
                let file = self.ctx.resolve_import(scan.file, &import.spec)?;
                Some(Target::Import {
                    file,
                    name: import.imported.clone(),
                })
            }
            Value::Call { callee, args } if callee == "require" => {
                let spec = args.first().and_then(Node::as_str)?;
                let file = self.ctx.resolve_import(scan.file, spec)?;
                Some(Target::Import {
                    file,
                    name: "default".to_string(),
                })
            }
            _ => None,
        }
    }

    fn classify(
        &self,
        scan: &FileScan<'_>,
        method: &str,
        path: &str,
        handler: &str,
    ) -> &'static str {
        if !matches!(method, "GET" | "ALL") {
            return "api";
        }
        let last = path.rsplit('/').next().unwrap_or_default();
        if let Some((_, ext)) = last.rsplit_once('.')
            && !matches!(ext, "html" | "htm")
            && !ext.contains(':')
        {
            return "api";
        }
        // A page handler often has JSON/text guards, so any HTML signal
        // (direct or through a helper) wins over API signals.
        let direct = shape(handler);
        if direct == Shape::Page {
            return "page";
        }
        let mut helper_api = false;
        // `app.get('/x', showPage)` passes the handler by name.
        let by_name =
            Some(handler.trim().trim_end_matches(',').trim()).filter(|h| js::is_plain_ident(h));
        let called = CALLED_IDENT_RE
            .captures_iter(handler)
            .filter_map(|c| c.get(1).map(|m| m.as_str()));
        for name in by_name.into_iter().chain(called) {
            match self.helper_shape(scan, name) {
                Shape::Page => return "page",
                Shape::Api => helper_api = true,
                Shape::Unknown => {}
            }
        }
        if direct == Shape::Api || helper_api {
            return "api";
        }
        if REDIRECT_RE.is_match(handler) {
            return "redirect";
        }
        let jsx_file = scan
            .file
            .extension()
            .is_some_and(|e| e == "tsx" || e == "jsx");
        if jsx_file { "page" } else { "api" }
    }

    /// Shape of a helper function called by a handler, defined at the top
    /// level of the same file or imported from another module.
    fn helper_shape(&self, scan: &FileScan<'_>, name: &str) -> Shape {
        if let Some(shape) = self.file_fn_shapes(scan.file, &scan.src.text).get(name) {
            return *shape;
        }
        let Some(import) = scan.imports.iter().find(|i| i.local == name) else {
            return Shape::Unknown;
        };
        let Some(target) = self.ctx.resolve_import(scan.file, &import.spec) else {
            return Shape::Unknown;
        };
        let Some(src) = self.ctx.source(&target) else {
            return Shape::Unknown;
        };
        let fn_name = if import.imported == "default" {
            name
        } else {
            import.imported.as_str()
        };
        self.file_fn_shapes(&target, &src.text)
            .get(fn_name)
            .copied()
            .unwrap_or(Shape::Unknown)
    }

    fn file_fn_shapes(&self, file: &Path, text: &str) -> Rc<HashMap<String, Shape>> {
        if let Some(cached) = self.fn_shapes.borrow().get(file) {
            return cached.clone();
        }
        let shapes = Rc::new(top_level_fn_shapes(text));
        self.fn_shapes
            .borrow_mut()
            .insert(file.to_path_buf(), shapes.clone());
        shapes
    }
}

/// Shape of each top-level function / arrow const body (a body runs to the
/// next line that starts at column zero).
fn top_level_fn_shapes(text: &str) -> HashMap<String, Shape> {
    let mut out = HashMap::new();
    for cap in TOP_LEVEL_FN_RE.captures_iter(text) {
        let (Some(whole), Some(name)) = (cap.get(0), cap.get(1).or_else(|| cap.get(2))) else {
            continue;
        };
        let rest = &text[whole.end()..];
        let end = TOP_LEVEL_LINE_RE
            .find(rest)
            .map_or(rest.len(), |m| m.start());
        out.entry(name.as_str().to_string())
            .or_insert_with(|| shape(js::clip(&rest[..end], 12_000)));
    }
    out
}

fn shape(text: &str) -> Shape {
    if PAGE_RE.is_match(text) || js::has_jsx(text) {
        Shape::Page
    } else if API_RE.is_match(text) {
        Shape::Api
    } else {
        Shape::Unknown
    }
}

/// Offset just past `(...)` following a constructor name (skipping generic
/// arguments), where a method chain may start. `None` when the name is not
/// called (`= fastify.instance`, a type reference).
fn after_constructor(bytes: &[u8], mut i: usize) -> Option<usize> {
    i = js::skip_ws(bytes, i);
    if bytes.get(i) == Some(&b'<') {
        i = js::skip_ws(bytes, js::find_matching(bytes, i)? + 1);
    }
    if bytes.get(i) == Some(&b'(') {
        return Some(js::find_matching(bytes, i)? + 1);
    }
    None
}

fn string_list(node: &Node) -> Vec<String> {
    match &node.value {
        Value::Str(s) => vec![s.clone()],
        Value::Arr(items) => items
            .iter()
            .filter_map(|n| n.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}
