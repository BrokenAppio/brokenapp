//! Which routes a set of changed files affects (`brokenapp map --changed`).
//!
//! A route is affected when:
//!
//! - its defining file changed (a changed layout affects every route under
//!   it; a router file every route it defines);
//! - a control on it (in the latest map) is rendered, called, or handled in
//!   a changed file. Without a known import scope, global (`*`) controls
//!   select one representative route that shows them;
//! - its page transitively imports a changed file (bounded import closure,
//!   tsconfig aliases plus `@/`, `~/`, `src/`; styles included). A changed
//!   file only reached through a layout or another shell file affects every
//!   route under that shell. Sampled controls do not narrow import scope;
//! - it calls an endpoint whose API route file changed, or it links to a
//!   page that was added or removed.
//!
//! App-wide files (framework config, middleware, the SPA entry) and
//! changes touching most routes call for a full map instead.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;

use serde::Serialize;

use super::changed::{ChangedFiles, strip_line};
use crate::code_link::static_source::{import_bases, module_specifiers};
use crate::inventory::identity::{RouteCanon, is_error_page, route_template};
use crate::inventory::{Control, Inventory};
use crate::route_discovery::{DiscoveredRoute, ImportResolver, RouteDiscovery};

/// Share of known (or visited) routes above which a full map is cheaper
/// and simpler than an incremental one.
const FULL_MAP_SHARE: f64 = 0.6;
/// Import-closure bounds (reverse walk from a changed file).
const MAX_IMPORT_DEPTH: usize = 12;
const MAX_CLOSURE_FILES: usize = 5_000;
/// Files indexed for the import graph.
const MAX_GRAPH_FILES: usize = 30_000;
const MAX_FILE_BYTES: u64 = 1_000_000;

const GRAPH_EXTS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts", "vue", "svelte", "astro", "mdx", "md",
    "css", "scss", "sass", "less",
];
/// Backend, server template, HTML, and schema source extensions whose edits can
/// alter rendered UI or API behavior even when absent from the JS import graph.
const NON_JS_UI_SOURCE_EXTS: &[&str] = &[
    "py", "rb", "php", "java", "kt", "cs", "go", "rs", "erb", "haml", "slim", "jinja", "jinja2",
    "twig", "jsp", "jspx", "cshtml", "razor", "hbs", "ejs", "pug", "html", "htm", "sql", "graphql",
    "gql", "proto",
];
const STYLE_EXTS: &[&str] = &["css", "scss", "sass", "less", "styl", "pcss"];
const ASSET_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "woff", "woff2", "ttf", "otf",
    "eot", "mp4", "webm", "mp3", "wav", "pdf",
];
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "bower_components",
    "dist",
    "build",
    "out",
    "coverage",
    "target",
    "storybook-static",
    "playwright-report",
    "test-results",
    "__tests__",
    "__mocks__",
    "__snapshots__",
];
/// Framework/build config at the codebase root: app-wide.
const APP_CONFIG_PREFIXES: &[&str] = &[
    "next.config.",
    "astro.config.",
    "vite.config.",
    "svelte.config.",
    "nuxt.config.",
    "remix.config.",
    "react-router.config.",
    "vinext.config.",
    "tailwind.config.",
    "postcss.config.",
    "angular.json",
];

/// Why a changed file maps to no route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnmappedFile {
    pub file: String,
    /// `test`, `docs`, `config`, `style`, `asset`, `api`, `source`, or `other`.
    pub kind: String,
}

/// One route to re-crawl and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AffectedRoute {
    pub route: String,
    pub reasons: Vec<String>,
}

/// Result of [`analyze`].
#[derive(Debug, Clone, Default)]
pub struct Impact {
    /// Route -> reasons it was picked.
    pub affected: BTreeMap<String, BTreeSet<String>>,
    pub unmapped: Vec<UnmappedFile>,
    /// Routes whose defining file was deleted (dropped from the map).
    pub removed: BTreeSet<String>,
    /// Set when a full map is needed instead (app-wide change, most routes).
    pub full_reason: Option<String>,
    /// Routes the decision was measured against.
    pub known_routes: usize,
    pub visited_routes: usize,
}

impl Impact {
    pub fn affected_routes(&self) -> Vec<AffectedRoute> {
        self.affected
            .iter()
            .map(|(route, reasons)| AffectedRoute {
                route: route.clone(),
                reasons: reasons.iter().cloned().collect(),
            })
            .collect()
    }
}

/// Which routes `changed` affects, given the latest map and the current
/// route discovery. `concrete_seeds` are the whole-app seeds (route naming).
pub fn analyze(
    root: &Path,
    changed: &ChangedFiles,
    latest: &Inventory,
    discovery: &RouteDiscovery,
    concrete_seeds: &[String],
) -> Impact {
    let routes = RouteIndex::new(latest, discovery, concrete_seeds);
    let graph = ImportGraph::build(root, &discovery.app_dir, &changed.deleted);
    let controls = ControlIndex::new(latest);
    let mut a = Analysis {
        routes: &routes,
        graph: &graph,
        controls: &controls,
        latest,
        discovery,
        changed,
        impact: Impact {
            known_routes: routes.known.len(),
            visited_routes: routes.visited.len(),
            ..Default::default()
        },
        global_needs: BTreeMap::new(),
    };
    for file in &changed.files {
        a.file(file);
    }
    a.links_to_added_and_removed_routes();
    a.resolve_global_needs();
    a.decide_full();
    a.impact
}

// ---------------------------------------------------------------------------
// Indexes
// ---------------------------------------------------------------------------

/// Routes of the latest map and of current route discovery, by file.
struct RouteIndex {
    /// Defining file -> inventory route names.
    by_file: BTreeMap<String, BTreeSet<String>>,
    /// Defining file -> number of distinct route patterns it defines.
    patterns_per_file: BTreeMap<String, usize>,
    /// Every known route (latest map + discovery).
    known: BTreeSet<String>,
    visited: BTreeSet<String>,
    /// Routes discovery finds now.
    current: BTreeSet<String>,
    /// Layout files by discovery (`kind = layout`) -> route path prefix.
    discovered_layouts: BTreeMap<String, String>,
    /// API route file -> (methods, path).
    api: BTreeMap<String, Vec<(Vec<String>, String)>>,
}

impl RouteIndex {
    fn new(latest: &Inventory, discovery: &RouteDiscovery, seeds: &[String]) -> Self {
        let mut canon = RouteCanon::new(&discovery.routes);
        canon.add_concrete(seeds);
        let mut by_file: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut known = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for r in &latest.routes {
            known.insert(r.route.clone());
            if r.visited {
                visited.insert(r.route.clone());
            }
            if let Some(src) = &r.source {
                by_file
                    .entry(strip_line(src).to_string())
                    .or_default()
                    .insert(r.route.clone());
            }
        }
        let mut patterns_per_file: BTreeMap<String, usize> = BTreeMap::new();
        let mut current = BTreeSet::new();
        let mut discovered_layouts = BTreeMap::new();
        let mut api: BTreeMap<String, Vec<(Vec<String>, String)>> = BTreeMap::new();
        for d in &discovery.routes {
            match d.kind.as_str() {
                "layout" => {
                    discovered_layouts.insert(d.file.clone(), d.path.clone());
                }
                "api" => api
                    .entry(d.file.clone())
                    .or_default()
                    .push((d.methods.clone(), d.path.clone())),
                "page" if !is_error_page(d) => {
                    *patterns_per_file.entry(d.file.clone()).or_insert(0) += 1;
                    for name in page_route_names(d, &canon, &latest.routes) {
                        known.insert(name.clone());
                        current.insert(name.clone());
                        by_file.entry(d.file.clone()).or_default().insert(name);
                    }
                }
                _ => {}
            }
        }
        Self {
            by_file,
            patterns_per_file,
            known,
            visited,
            current,
            discovered_layouts,
            api,
        }
    }

    /// A file defining several route patterns is a router, not a page.
    fn is_router_file(&self, file: &str) -> bool {
        self.patterns_per_file.get(file).copied().unwrap_or(0) > 1
    }

    /// Routes whose defining file sits under `dir` (`""` = everywhere).
    fn under_dir(&self, dir: &str) -> BTreeSet<String> {
        self.by_file
            .iter()
            .filter(|(f, _)| dir.is_empty() || f.starts_with(&format!("{dir}/")))
            .flat_map(|(_, rs)| rs.iter().cloned())
            .collect()
    }

    /// Routes at or below a path prefix (`/admin` -> `/admin`, `/admin/x`).
    fn under_path(&self, prefix: &str) -> BTreeSet<String> {
        let prefix = prefix.trim_end_matches('/');
        self.known
            .iter()
            .filter(|r| {
                prefix.is_empty() || r.as_str() == prefix || r.starts_with(&format!("{prefix}/"))
            })
            .cloned()
            .collect()
    }
}

/// Inventory route names for a discovered page: its enumerated examples, and
/// the pattern itself when there are none or the map has it.
fn page_route_names(
    d: &DiscoveredRoute,
    canon: &RouteCanon,
    latest: &[crate::inventory::RouteEntry],
) -> Vec<String> {
    let pattern = canon.route(&d.path);
    let mut out: Vec<String> = d.examples.iter().map(|e| canon.route(e)).collect();
    if out.is_empty() || latest.iter().any(|r| r.route == pattern) {
        out.push(pattern);
    }
    out.sort();
    out.dedup();
    out
}

/// Latest-map controls by the files their sources name.
struct ControlIndex<'a> {
    by_file: BTreeMap<String, Vec<&'a Control>>,
}

impl<'a> ControlIndex<'a> {
    fn new(latest: &'a Inventory) -> Self {
        let mut by_file: BTreeMap<String, Vec<&'a Control>> = BTreeMap::new();
        for c in &latest.controls {
            let Some(src) = &c.source else { continue };
            let mut files: BTreeSet<&str> = [&src.render, &src.caller, &src.handler]
                .into_iter()
                .flatten()
                .map(|s| s.file.as_str())
                .collect();
            // Weak static matches: any candidate may be the real site.
            if matches!(src.confidence.as_str(), "guess" | "ambiguous") {
                files.extend(src.candidates.iter().map(|s| s.file.as_str()));
            }
            for f in files {
                by_file.entry(f.to_string()).or_default().push(c);
            }
        }
        Self { by_file }
    }
}

/// Import graph over the codebase's source and style files.
struct ImportGraph {
    files: Vec<String>,
    index: HashMap<String, usize>,
    importers: Vec<Vec<usize>>,
}

impl ImportGraph {
    fn build(root: &Path, app_dir: &str, deleted: &BTreeSet<String>) -> Self {
        let mut files = walk(root);
        // Deleted files stay resolvable so their importers are found.
        files.extend(deleted.iter().cloned());
        files.sort();
        files.dedup();
        let index: HashMap<String, usize> = files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.clone(), i))
            .collect();
        let resolver = ImportResolver::load(&root.join(app_dir));
        let mut importers: Vec<Vec<usize>> = vec![Vec::new(); files.len()];
        for (fi, rel) in files.iter().enumerate() {
            if deleted.contains(rel) || is_test_path(rel) {
                continue;
            }
            let path = root.join(rel);
            let Some(text) = std::fs::metadata(&path)
                .ok()
                .filter(|m| m.len() <= MAX_FILE_BYTES)
                .and_then(|_| std::fs::read_to_string(&path).ok())
            else {
                continue;
            };
            let dir = rel.rsplit_once('/').map_or("", |(d, _)| d);
            let mut targets: BTreeSet<usize> = BTreeSet::new();
            for spec in module_specifiers(&text) {
                let resolved = resolver
                    .resolve(&path, spec)
                    .and_then(|p| p.strip_prefix(root).ok().map(slash))
                    .and_then(|r| index.get(&r).copied())
                    .or_else(|| {
                        import_bases(dir, spec)
                            .iter()
                            .find_map(|base| find_module(&index, base))
                    });
                if let Some(t) = resolved.filter(|t| *t != fi) {
                    targets.insert(t);
                }
            }
            for t in targets {
                importers[t].push(fi);
            }
        }
        Self {
            files,
            index,
            importers,
        }
    }

    /// Files that transitively import `file` (not including it), nearest
    /// first, bounded.
    fn importers_of(&self, file: &str) -> Vec<&str> {
        let Some(&start) = self.index.get(file) else {
            return Vec::new();
        };
        let mut seen: BTreeSet<usize> = BTreeSet::from([start]);
        let mut order = Vec::new();
        let mut queue: VecDeque<(usize, usize)> = VecDeque::from([(start, 0)]);
        while let Some((fi, depth)) = queue.pop_front() {
            if depth >= MAX_IMPORT_DEPTH || seen.len() >= MAX_CLOSURE_FILES {
                continue;
            }
            for &imp in &self.importers[fi] {
                if seen.insert(imp) {
                    order.push(self.files[imp].as_str());
                    queue.push_back((imp, depth + 1));
                }
            }
        }
        order
    }
}

fn find_module(index: &HashMap<String, usize>, base: &str) -> Option<usize> {
    if let Some(i) = index.get(base) {
        return Some(*i);
    }
    GRAPH_EXTS.iter().find_map(|ext| {
        index
            .get(&format!("{base}.{ext}"))
            .or_else(|| index.get(&format!("{base}/index.{ext}")))
            .copied()
    })
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Source and style files under `root`, codebase-relative, sorted.
fn walk(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if ft.is_dir() {
                if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push(entry.path());
                }
                continue;
            }
            if !ft.is_file() || ext_of(&name).is_none_or(|e| !GRAPH_EXTS.contains(&e)) {
                continue;
            }
            if let Ok(rel) = entry.path().strip_prefix(root) {
                out.push(slash(rel));
                if out.len() >= MAX_GRAPH_FILES {
                    return out;
                }
            }
        }
    }
    out
}

fn ext_of(name: &str) -> Option<&str> {
    name.rsplit_once('.').map(|(_, e)| e)
}

fn file_name(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

/// Tests, stories and test harness directories (`tests/` and `e2e/` only at
/// the codebase root: `app/tests/page.tsx` is a route).
fn is_test_path(rel: &str) -> bool {
    let orig_name = file_name(rel);
    let name = orig_name.to_ascii_lowercase();
    let mut dirs = rel.split('/').rev().skip(1).collect::<Vec<_>>();
    let top = dirs.pop();
    if [".test.", ".spec.", ".e2e.", ".cy.", ".stories.", ".story."]
        .iter()
        .any(|m| name.contains(m))
        || top.is_some_and(|d| {
            matches!(
                d,
                "tests"
                    | "test"
                    | "spec"
                    | "e2e"
                    | "cypress"
                    | "playwright"
                    | "__tests__"
                    | "__mocks__"
            )
        })
        || dirs
            .iter()
            .any(|d| matches!(*d, "__tests__" | "__mocks__" | "__snapshots__"))
        || rel.starts_with("src/test/")
        || rel.contains("/src/test/")
    {
        return true;
    }
    if matches!(name.as_str(), "tests.py" | "conftest.py")
        || (name.ends_with(".py") && (name.starts_with("test_") || name.ends_with("_test.py")))
        || (name.ends_with(".rb") && (name.ends_with("_spec.rb") || name.ends_with("_test.rb")))
        || name.ends_with("_test.go")
        || name.ends_with("_test.rs")
        || name.ends_with("_test.php")
    {
        return true;
    }
    [
        "Test.php",
        "Tests.php",
        "Test.java",
        "Tests.java",
        "Spec.java",
        "Test.kt",
        "Tests.kt",
        "Spec.kt",
        "Test.cs",
        "Tests.cs",
    ]
    .iter()
    .any(|suffix| orig_name.ends_with(suffix) && orig_name.len() > suffix.len())
}

fn is_non_js_ui_source(rel: &str) -> bool {
    let name = file_name(rel).to_ascii_lowercase();
    ext_of(&name).is_some_and(|ext| NON_JS_UI_SOURCE_EXTS.contains(&ext))
}

/// Companion `.component.ts` for an Angular template or component stylesheet.
fn angular_component_ts(rel: &str) -> Option<String> {
    for suffix in [
        ".component.html",
        ".component.css",
        ".component.scss",
        ".component.sass",
        ".component.less",
    ] {
        if let Some(stem) = rel.strip_suffix(suffix) {
            return Some(format!("{stem}.component.ts"));
        }
    }
    None
}

/// Where a layout file applies.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LayoutScope {
    /// Routes whose defining file is under this directory.
    Dir(String),
    /// Routes at or below this path.
    Path(String),
    /// Every route.
    All,
}

/// Layout and shell files by naming convention (Next `layout`/`template`,
/// SvelteKit `+layout`, Next pages `_app`/`_document`, Remix/React Router
/// `root`, TanStack `__root`, Nuxt `app.vue`/`layouts/`), then discovery's
/// layout routes.
fn layout_scope(rel: &str, routes: &RouteIndex) -> Option<LayoutScope> {
    let name = file_name(rel);
    let dir = rel.rsplit_once('/').map_or("", |(d, _)| d);
    let stem = name.split('.').next().unwrap_or(name);
    let ext = ext_of(name).unwrap_or("");
    let script = matches!(ext, "tsx" | "jsx" | "ts" | "js" | "mdx" | "svelte" | "vue");
    let in_dir = |d: &str| rel.split('/').any(|seg| seg == d);
    if script && matches!(stem, "layout" | "template") && in_dir("app") {
        return Some(LayoutScope::Dir(dir.to_string()));
    }
    if stem == "+layout" {
        return Some(LayoutScope::Dir(dir.to_string()));
    }
    if script && matches!(stem, "_app" | "_document") && in_dir("pages") {
        return Some(LayoutScope::All);
    }
    if script && stem == "root" && (dir == "app" || dir.ends_with("/app")) {
        return Some(LayoutScope::All);
    }
    if stem == "__root" || (ext == "vue" && (name == "app.vue" || dir.ends_with("layouts"))) {
        return Some(LayoutScope::All);
    }
    routes
        .discovered_layouts
        .get(rel)
        .map(|path| LayoutScope::Path(path.clone()))
}

/// App-wide files: framework config, middleware, SPA entries.
fn app_wide_reason(rel: &str, framework: &str) -> Option<String> {
    let name = file_name(rel);
    let top = !rel.contains('/');
    if top && APP_CONFIG_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return Some(format!("app config changed: {rel}"));
    }
    let stem = name.split('.').next().unwrap_or(name);
    let script = matches!(ext_of(name), Some("ts" | "tsx" | "js" | "jsx" | "mjs"));
    if script && stem == "middleware" && (top || rel.starts_with("src/")) {
        return Some(format!("middleware changed: {rel}"));
    }
    if rel == "src/app.html" {
        return Some(format!("app shell changed: {rel}"));
    }
    let spa = !matches!(
        framework,
        "nextjs-app" | "nextjs-pages" | "astro" | "sveltekit" | "nuxt" | "remix" | "static"
    );
    if spa && rel == "index.html" {
        return Some(format!("app entry changed: {rel}"));
    }
    if framework == "angular" && rel == "src/index.html" {
        return Some(format!("app entry changed: {rel}"));
    }
    if spa
        && script
        && matches!(stem, "main" | "index" | "App" | "app")
        && (rel.starts_with("src/") && rel.matches('/').count() == 1)
    {
        return Some(format!("app entry changed: {rel}"));
    }
    None
}

fn unmapped_kind(rel: &str) -> &'static str {
    let name = file_name(rel).to_ascii_lowercase();
    let ext = ext_of(&name).unwrap_or("");
    if is_test_path(rel) {
        "test"
    } else if matches!(ext, "md" | "mdx" | "txt" | "rst" | "adoc")
        || rel.starts_with("docs/")
        || matches!(
            name.as_str(),
            "license" | "copying" | "notice" | "authors" | "changelog"
        )
        || name.starts_with("license.")
        || name.starts_with("changelog.")
    {
        "docs"
    } else if STYLE_EXTS.contains(&ext) {
        "style"
    } else if ASSET_EXTS.contains(&ext) {
        "asset"
    } else if rel.starts_with(".github/")
        || rel.starts_with(".gitlab/")
        || rel.starts_with(".circleci/")
        || matches!(ext, "json" | "yaml" | "yml" | "toml" | "lock" | "lockb")
        || matches!(name.as_str(), "dockerfile" | "go.sum" | "gradle.lockfile")
        || name.contains(".config.")
        || name.starts_with('.')
    {
        "config"
    } else if GRAPH_EXTS.contains(&ext) || NON_JS_UI_SOURCE_EXTS.contains(&ext) {
        "source"
    } else {
        "other"
    }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// What the latest map knows a changed file renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    None,
    /// Only global (`*`) controls.
    GlobalsOnly,
    /// Controls on specific routes (and maybe globals).
    Routes,
}

struct Analysis<'a> {
    routes: &'a RouteIndex,
    graph: &'a ImportGraph,
    controls: &'a ControlIndex<'a>,
    latest: &'a Inventory,
    discovery: &'a RouteDiscovery,
    changed: &'a ChangedFiles,
    impact: Impact,
    /// Global control key -> files that changed it.
    global_needs: BTreeMap<String, BTreeSet<String>>,
}

impl Analysis<'_> {
    fn add(&mut self, route: &str, reason: String) {
        self.impact
            .affected
            .entry(route.to_string())
            .or_default()
            .insert(reason);
    }

    fn add_all(&mut self, routes: impl IntoIterator<Item = String>, reason: &str) {
        for r in routes {
            self.add(&r, reason.to_string());
        }
    }

    fn file(&mut self, rel: &str) {
        let deleted = self.changed.deleted.contains(rel);
        if is_test_path(rel) {
            self.unmapped(rel, "test");
            return;
        }
        if let Some(reason) = app_wide_reason(rel, &self.discovery.framework) {
            self.impact.full_reason.get_or_insert(reason);
            return;
        }
        let mut mapped = false;

        // 1. Route files.
        if let Some(routes) = self.routes.by_file.get(rel) {
            mapped = true;
            let router = self.routes.is_router_file(rel);
            let reason = match (deleted, router) {
                (true, _) => format!("route file deleted: {rel}"),
                (false, true) => format!("router file changed: {rel}"),
                (false, false) => format!("route file changed: {rel}"),
            };
            for r in routes.clone() {
                if deleted && !self.routes.current.contains(&r) {
                    self.impact.removed.insert(r);
                } else {
                    self.add(&r, reason.clone());
                }
            }
        }

        // 2. Layouts.
        if let Some(scope) = layout_scope(rel, self.routes) {
            mapped = true;
            let routes = self.scope_routes(&scope);
            self.add_all(routes, &format!("layout changed: {rel}"));
        }

        // 3. Controls the map says this file renders, calls, or handles.
        let evidence = self.control_evidence(rel);
        mapped |= evidence != Evidence::None;

        // 4. Pages and shells that import it.
        mapped |= self.importers(rel);

        // 4b. Angular component templates/styles (`*.component.{html,css,scss,...}`)
        // are linked to their sibling `*.component.ts` via `templateUrl`/`styleUrls`
        // rather than JS `import` statements.
        if let Some(sibling_ts) = angular_component_ts(rel) {
            if let Some(routes) = self.routes.by_file.get(&sibling_ts).cloned() {
                mapped = true;
                let reason = format!("component template/style changed: {rel} (for {sibling_ts})");
                for r in routes {
                    self.add(&r, reason.clone());
                }
            }
            let sibling_evidence = self.control_evidence(&sibling_ts);
            mapped |= sibling_evidence != Evidence::None;
            mapped |= self.importers(&sibling_ts);
        }

        // 5. API route handlers: controls and page loads calling them.
        if self.routes.api.contains_key(rel) {
            mapped = true;
            if !self.api_callers(rel) {
                self.unmapped(rel, "api");
            }
        }

        if !mapped {
            let kind = unmapped_kind(rel);
            self.unmapped(rel, kind);
            if kind == "source" && is_non_js_ui_source(rel) {
                self.impact.full_reason.get_or_insert_with(|| {
                    format!("unattributed server/template source changed: {rel}")
                });
            }
        }
    }

    fn unmapped(&mut self, rel: &str, kind: &str) {
        self.impact.unmapped.push(UnmappedFile {
            file: rel.to_string(),
            kind: kind.to_string(),
        });
    }

    fn scope_routes(&self, scope: &LayoutScope) -> BTreeSet<String> {
        match scope {
            LayoutScope::Dir(dir) => {
                // `app/layout.tsx` at the routing root covers everything.
                self.routes.under_dir(dir)
            }
            LayoutScope::Path(path) => self.routes.under_path(path),
            LayoutScope::All => self.routes.known.clone(),
        }
    }

    fn control_evidence(&mut self, rel: &str) -> Evidence {
        let Some(controls) = self.controls.by_file.get(rel) else {
            return Evidence::None;
        };
        let mut evidence = Evidence::None;
        for c in controls.clone() {
            if c.route == "*" {
                self.global_needs
                    .entry(c.key.clone())
                    .or_default()
                    .insert(rel.to_string());
                if evidence == Evidence::None {
                    evidence = Evidence::GlobalsOnly;
                }
            } else {
                self.add(&c.route, format!("renders controls on this route: {rel}"));
                evidence = Evidence::Routes;
            }
        }
        evidence
    }

    /// Positive import dependencies establish affected scope independently
    /// of sampled control evidence. A shell (layout, router, app entry)
    /// importing the file affects every route under it, even when the last
    /// map only attributed global controls or one page's controls to it.
    fn importers(&mut self, rel: &str) -> bool {
        let importers: Vec<String> = self
            .graph
            .importers_of(rel)
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut any = false;
        for imp in importers {
            if self.routes.api.contains_key(&imp) {
                any = true;
                self.api_callers(&imp);
                continue;
            }
            if let Some(reason) = app_wide_reason(&imp, &self.discovery.framework) {
                self.impact.full_reason.get_or_insert(format!(
                    "{rel} is part of the app shell ({})",
                    reason.split(": ").nth(1).unwrap_or(&imp)
                ));
                any = true;
                continue;
            }
            if let Some(scope) = layout_scope(&imp, self.routes) {
                any = true;
                let routes = self.scope_routes(&scope);
                self.add_all(
                    routes,
                    &format!("shell file changed: {rel} (used by {imp})"),
                );
                continue;
            }
            let Some(routes) = self.routes.by_file.get(&imp).cloned() else {
                continue;
            };
            any = true;
            if self.routes.is_router_file(&imp) {
                self.add_all(
                    routes,
                    &format!("shell file changed: {rel} (used by {imp})"),
                );
            } else {
                self.add_all(routes, &format!("imports {rel}"));
            }
        }
        any
    }

    /// Controls and page loads that call an endpoint the API route file
    /// `rel` serves. False when the map shows no caller.
    fn api_callers(&mut self, rel: &str) -> bool {
        let Some(defs) = self.routes.api.get(rel).cloned() else {
            return false;
        };
        let mut any = false;
        for e in &self.latest.endpoints {
            let Some((method, path)) = e.endpoint.split_once(' ') else {
                continue;
            };
            let path = path.split(" [").next().unwrap_or(path);
            let hit = defs.iter().any(|(methods, api_path)| {
                (methods.is_empty() || methods.iter().any(|m| m.eq_ignore_ascii_case(method)))
                    && same_template(api_path, path)
            });
            if !hit {
                continue;
            }
            any = true;
            let reason = format!("calls {method} {path} (handler {rel} changed)");
            for key in &e.controls {
                if let Some(c) = self.latest.controls.iter().find(|c| &c.key == key) {
                    if c.route == "*" {
                        self.global_needs
                            .entry(c.key.clone())
                            .or_default()
                            .insert(rel.to_string());
                    } else {
                        self.add(&c.route, reason.clone());
                    }
                }
            }
            for r in &e.on_load {
                self.add(r, format!("loads {method} {path} (handler {rel} changed)"));
            }
        }
        any
    }

    /// Pages that link to a route that was added (its links were broken) or
    /// removed (its links now break).
    fn links_to_added_and_removed_routes(&mut self) {
        let added: BTreeSet<String> = self
            .routes
            .current
            .iter()
            .filter(|r| !self.latest.routes.iter().any(|l| &l.route == *r))
            .cloned()
            .collect();
        let targets: Vec<(String, &'static str)> = added
            .iter()
            .map(|r| (r.clone(), "links to new route"))
            .chain(
                self.impact
                    .removed
                    .iter()
                    .map(|r| (r.clone(), "links to removed route")),
            )
            .collect();
        for (target, why) in targets {
            let linking: Vec<&Control> = self
                .latest
                .controls
                .iter()
                .filter(|c| c.navigates_to().any(|t| t == target))
                .collect();
            for c in linking {
                if c.route == "*" {
                    self.global_needs
                        .entry(c.key.clone())
                        .or_default()
                        .insert(format!("{why} {target}"));
                } else if !self.impact.removed.contains(&c.route) {
                    let reason = format!("{why} {target}");
                    self.add(&c.route, reason);
                }
            }
        }
    }

    /// Global controls need one route that shows them: an already affected
    /// one, else the visited route showing the most of them (`/` on ties).
    fn resolve_global_needs(&mut self) {
        let mut pending: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
        for (key, files) in std::mem::take(&mut self.global_needs) {
            let Some(g) = self.latest.controls.iter().find(|c| c.key == key) else {
                continue;
            };
            let routes: BTreeSet<String> = g
                .routes
                .iter()
                .filter(|r| self.routes.visited.contains(*r))
                .cloned()
                .collect();
            if routes.iter().any(|r| self.impact.affected.contains_key(r)) || routes.is_empty() {
                continue;
            }
            pending.insert(key, (routes, files));
        }
        while !pending.is_empty() {
            let mut counts: BTreeMap<&String, usize> = BTreeMap::new();
            for (routes, _) in pending.values() {
                for r in routes {
                    *counts.entry(r).or_insert(0) += 1;
                }
            }
            // Most globals covered, then `/`, then the first route by name.
            let Some(pick) = counts
                .iter()
                .max_by_key(|(r, n)| (**n, r.as_str() == "/", std::cmp::Reverse(r.as_str())))
                .map(|(r, _)| (*r).clone())
            else {
                break;
            };
            let covered: Vec<String> = pending
                .iter()
                .filter(|(_, (routes, _))| routes.contains(&pick))
                .map(|(k, _)| k.clone())
                .collect();
            let mut files = BTreeSet::new();
            for k in &covered {
                if let Some((_, f)) = pending.remove(k) {
                    files.extend(f);
                }
            }
            let files: Vec<String> = files.into_iter().collect();
            self.add(
                &pick,
                format!(
                    "shows {} global control{} changed in {}",
                    covered.len(),
                    if covered.len() == 1 { "" } else { "s" },
                    files.join(", ")
                ),
            );
        }
    }

    fn decide_full(&mut self) {
        if self.impact.full_reason.is_some() {
            return;
        }
        let known = self.impact.known_routes;
        let visited = self.impact.visited_routes;
        let affected = self.impact.affected.len();
        let affected_visited = self
            .impact
            .affected
            .keys()
            .filter(|r| self.routes.visited.contains(*r))
            .count();
        let share = |n: usize, of: usize| of > 0 && n as f64 >= FULL_MAP_SHARE * of as f64;
        if share(affected, known) {
            self.impact.full_reason =
                Some(format!("{affected} of {known} known routes are affected"));
        } else if share(affected_visited, visited) && affected_visited > 1 {
            self.impact.full_reason = Some(format!(
                "{affected_visited} of {visited} visited routes are affected"
            ));
        } else if affected == 0 && !self.impact.removed.is_empty() {
            self.impact.full_reason = Some(format!(
                "route{} removed: {}",
                if self.impact.removed.len() == 1 {
                    ""
                } else {
                    "s"
                },
                self.impact
                    .removed
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
}

/// `/api/items/:id` matches `/api/items/:itemId` and `/api/items/[id]`.
fn same_template(a: &str, b: &str) -> bool {
    let norm = |p: &str| route_template(p);
    let (a, b) = (norm(a), norm(b));
    let (sa, sb): (Vec<&str>, Vec<&str>) = (a.split('/').collect(), b.split('/').collect());
    let dynamic = |s: &str| s.starts_with(':') || s.starts_with('[') || s.starts_with('*');
    sa.len() == sb.len()
        && sa
            .iter()
            .zip(sb.iter())
            .all(|(x, y)| x == y || dynamic(x) || dynamic(y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_link::runtime_source::{FileLine, ResolvedSource};
    use crate::inventory::{Control, EndpointEntry, Outcome, RouteEntry};

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        dir
    }

    /// A Next app-router site: root layout with header and footer, a nested
    /// blog layout, pages importing components, an API route.
    fn next_site() -> tempfile::TempDir {
        tree(&[
            (
                "package.json",
                r#"{"dependencies":{"next":"15.0.0","react":"19.0.0"}}"#,
            ),
            (
                "tsconfig.json",
                r#"{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}"#,
            ),
            ("next.config.js", "module.exports = {}\n"),
            ("README.md", "# site\n"),
            ("e2e/home.spec.ts", "import '../src/app/page'\n"),
            (
                "src/app/layout.tsx",
                "import './globals.css'\nimport Header from '@/components/Header'\nimport { Footer } from '@/components/Footer'\nexport default function L({children}) { return <html><body><Header />{children}<Footer /></body></html> }\n",
            ),
            ("src/app/globals.css", "body { margin: 0 }\n"),
            (
                "src/app/page.tsx",
                "import Hero from '@/components/Hero'\nexport default function P() { return <Hero /> }\n",
            ),
            (
                "src/app/about/page.tsx",
                "import ContactForm from '@/components/ContactForm'\nimport styles from './about.module.css'\nexport default function P() { return <ContactForm /> }\n",
            ),
            ("src/app/about/about.module.css", ".x { color: red }\n"),
            (
                "src/app/pricing/page.tsx",
                "import PriceTable from '../../components/PriceTable'\nexport default function P() { return <PriceTable /> }\n",
            ),
            (
                "src/app/blog/layout.tsx",
                "export default function L({children}) { return <div>{children}</div> }\n",
            ),
            (
                "src/app/blog/page.tsx",
                "export default function P() { return <a href=\"/blog/hello\">Hello</a> }\n",
            ),
            (
                "src/app/blog/[slug]/page.tsx",
                "export default function P() { return <p /> }\n",
            ),
            (
                "src/app/api/subscribe/route.ts",
                "import { db } from '@/lib/db'\nexport async function POST() { return db() }\n",
            ),
            ("src/lib/db.ts", "export const db = () => null\n"),
            (
                "src/components/Header.tsx",
                "import NavLink from './NavLink'\nexport default function H() { return <header><NavLink href=\"/\">Home</NavLink></header> }\n",
            ),
            (
                "src/components/NavLink.tsx",
                "export default function N(p) { return <a {...p} /> }\n",
            ),
            (
                "src/components/Footer.tsx",
                "export function Footer() { return <footer /> }\n",
            ),
            (
                "src/components/Hero.tsx",
                "export default function H() { return <button>Subscribe</button> }\n",
            ),
            (
                "src/components/ContactForm.tsx",
                "import Button from './Button'\nexport default function C() { return <Button>Send</Button> }\n",
            ),
            (
                "src/components/Button.tsx",
                "export default function B(p) { return <button {...p} /> }\n",
            ),
            (
                "src/components/PriceTable.tsx",
                "import { money } from '@/utils/format'\nexport default function T() { return <a href=\"/checkout\">Buy</a> }\n",
            ),
            (
                "src/utils/format.ts",
                "export const money = (n) => `$${n}`\n",
            ),
        ])
    }

    fn site(file: &str, line: u32) -> Option<FileLine> {
        Some(FileLine {
            file: file.into(),
            line,
            col: 1,
        })
    }

    fn control(key: &str, routes: &[&str], render: &str, caller: Option<&str>) -> Control {
        let route = key.split('|').next().unwrap_or_default().to_string();
        Control {
            key: key.into(),
            route,
            routes: routes.iter().map(|r| r.to_string()).collect(),
            source: Some(ResolvedSource {
                render: site(render, 3),
                caller: caller.and_then(|c| site(c, 5)),
                method: "runtime".into(),
                confidence: "exact".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn latest() -> Inventory {
        let visited = ["/", "/about", "/pricing", "/blog", "/blog/:slug"];
        let mut subscribe = control(
            "/|button|text=subscribe",
            &[],
            "src/components/Hero.tsx",
            None,
        );
        subscribe.outcomes = vec![Outcome::Calls {
            endpoint: "POST /api/subscribe".into(),
            status: None,
            blocked: true,
        }];
        let mut see_pricing = control(
            "/|link|text=see pricing",
            &[],
            "src/components/Hero.tsx",
            None,
        );
        see_pricing.outcomes = vec![Outcome::Navigates {
            to: "/pricing".into(),
        }];
        let mut contact = control(
            "/about|link|text=contact",
            &[],
            "src/components/ContactForm.tsx",
            None,
        );
        contact.outcomes = vec![Outcome::Navigates {
            to: "/contact".into(),
        }];
        Inventory {
            routes: visited
                .iter()
                .map(|r| RouteEntry {
                    route: r.to_string(),
                    visited: true,
                    source: Some(match *r {
                        "/" => "src/app/page.tsx:2".to_string(),
                        "/blog/:slug" => "src/app/blog/[slug]/page.tsx:1".to_string(),
                        other => format!("src/app{other}/page.tsx:1"),
                    }),
                    variants: if *r == "/blog/:slug" {
                        vec!["/blog/hello".into()]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                })
                .collect(),
            controls: vec![
                control(
                    "*|link|text=home@header",
                    &visited,
                    "src/components/NavLink.tsx",
                    Some("src/components/Header.tsx"),
                ),
                subscribe,
                see_pricing,
                control(
                    "/about|button|text=send",
                    &[],
                    "src/components/Button.tsx",
                    Some("src/components/ContactForm.tsx"),
                ),
                contact,
                control(
                    "/pricing|link|text=buy",
                    &[],
                    "src/components/PriceTable.tsx",
                    None,
                ),
            ],
            endpoints: vec![EndpointEntry {
                endpoint: "POST /api/subscribe".into(),
                controls: vec!["/|button|text=subscribe".into()],
                write: true,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn run(dir: &Path, files: &[&str], deleted: &[&str]) -> Impact {
        let changed = ChangedFiles {
            source: "git".into(),
            base: "abc".into(),
            files: files.iter().map(|f| f.to_string()).collect(),
            deleted: deleted.iter().map(|f| f.to_string()).collect(),
            notes: Vec::new(),
        };
        let discovery = crate::route_discovery::discover_routes(dir).unwrap();
        let seeds = crate::route_discovery::seed_paths(&discovery);
        analyze(dir, &changed, &latest(), &discovery, &seeds)
    }

    fn routes(i: &Impact) -> Vec<&str> {
        i.affected.keys().map(String::as_str).collect()
    }

    fn reasons<'a>(i: &'a Impact, route: &str) -> Vec<&'a str> {
        i.affected[route].iter().map(String::as_str).collect()
    }

    #[test]
    fn route_files_component_imports_and_styles_map_to_their_pages() {
        let dir = next_site();
        let d = dir.path();

        let i = run(d, &["src/app/about/page.tsx"], &[]);
        assert_eq!(routes(&i), vec!["/about"]);
        assert_eq!(
            reasons(&i, "/about"),
            vec!["route file changed: src/app/about/page.tsx"]
        );
        assert!(i.full_reason.is_none() && i.unmapped.is_empty());

        // A shared component: controls the map attributes to it, and the
        // pages that import it.
        let i = run(d, &["src/components/Button.tsx"], &[]);
        assert_eq!(routes(&i), vec!["/about"]);
        assert!(
            reasons(&i, "/about")
                .contains(&"renders controls on this route: src/components/Button.tsx"),
            "{i:#?}"
        );
        assert!(reasons(&i, "/about").contains(&"imports src/components/Button.tsx"));
        assert!(
            i.full_reason.is_none(),
            "a page-only leaf stays scoped: {i:#?}"
        );

        // No control evidence: the import closure (through an `@/` alias).
        let i = run(d, &["src/utils/format.ts"], &[]);
        assert_eq!(routes(&i), vec!["/pricing"]);
        assert_eq!(reasons(&i, "/pricing"), vec!["imports src/utils/format.ts"]);

        // A CSS module affects the page importing it.
        let i = run(d, &["src/app/about/about.module.css"], &[]);
        assert_eq!(routes(&i), vec!["/about"]);

        // A nested layout affects the routes under it only.
        let i = run(d, &["src/app/blog/layout.tsx"], &[]);
        assert_eq!(routes(&i), vec!["/blog", "/blog/:slug"]);
        assert!(i.full_reason.is_none(), "{i:#?}");
    }

    #[test]
    fn known_global_controls_do_not_narrow_layout_import_scope() {
        let dir = next_site();
        let d = dir.path();

        // A sampled global Home control cannot narrow the root layout's
        // positive dependency on Header: all five routes are affected.
        let i = run(d, &["src/components/Header.tsx"], &[]);
        assert_eq!(i.affected.len(), 5);
        assert!(reasons(&i, "/blog").contains(
            &"shell file changed: src/components/Header.tsx (used by src/app/layout.tsx)"
        ));
        assert_eq!(
            i.full_reason.as_deref(),
            Some("5 of 5 known routes are affected")
        );
        // A separately changed page does not replace the shared scope.
        let i = run(
            d,
            &["src/components/Header.tsx", "src/app/about/page.tsx"],
            &[],
        );
        assert_eq!(i.affected.len(), 5);
        assert!(i.full_reason.is_some());

        // Footer renders nothing the map knows, inside the root layout: every
        // route, so a full map.
        let i = run(d, &["src/components/Footer.tsx"], &[]);
        assert_eq!(i.affected.len(), 5);
        assert!(reasons(&i, "/blog").contains(
            &"shell file changed: src/components/Footer.tsx (used by src/app/layout.tsx)"
        ));
        assert_eq!(
            i.full_reason.as_deref(),
            Some("5 of 5 known routes are affected")
        );
        let i = run(d, &["src/app/globals.css"], &[]);
        assert!(i.full_reason.is_some(), "global styles affect every route");
        let i = run(d, &["src/app/layout.tsx"], &[]);
        assert!(i.full_reason.is_some());

        // App-wide config.
        let i = run(d, &["next.config.js"], &[]);
        assert_eq!(
            i.full_reason.as_deref(),
            Some("app config changed: next.config.js")
        );
    }

    #[test]
    fn global_controls_without_import_scope_keep_a_representative_route() {
        let dir = next_site();
        // The saved map still observes Header, but there is no module path
        // from it to a known page/layout in this fixture (e.g. external loading).
        std::fs::write(
            dir.path().join("src/app/layout.tsx"),
            "import './globals.css'\nexport default function L({children}) { return <html><body>{children}</body></html> }\n",
        )
        .unwrap();
        let i = run(dir.path(), &["src/components/Header.tsx"], &[]);
        assert_eq!(routes(&i), vec!["/"]);
        assert_eq!(
            reasons(&i, "/"),
            vec!["shows 1 global control changed in src/components/Header.tsx"]
        );
        assert!(i.full_reason.is_none());
        let i = run(
            dir.path(),
            &["src/components/Header.tsx", "src/app/about/page.tsx"],
            &[],
        );
        assert_eq!(routes(&i), vec!["/about"]);
        assert!(i.full_reason.is_none());
    }

    #[test]
    fn astro_header_imported_through_layout_affects_all_thirteen_pages() {
        // The saved MidAmerica benchmark selected only `/` because all
        // attributed header controls were global. Its actual import chain
        // is Header -> BaseLayout -> each of these thirteen page files.
        let dir = tree(&[
            ("package.json", r#"{"dependencies":{"astro":"5.0.0"}}"#),
            (
                "src/components/SiteHeader.astro",
                "<header><button>Visit</button></header>\n",
            ),
            (
                "src/layouts/BaseLayout.astro",
                "---\nimport SiteHeader from '../components/SiteHeader.astro';\n---\n<html><body><SiteHeader /><slot /></body></html>\n",
            ),
        ]);
        let paths = [
            "/",
            "/about",
            "/blog",
            "/careers",
            "/contact",
            "/docs",
            "/faq",
            "/features",
            "/pricing",
            "/privacy",
            "/security",
            "/support",
            "/terms",
        ];
        std::fs::create_dir_all(dir.path().join("src/pages")).unwrap();
        for route in paths {
            let name = if route == "/" { "index" } else { &route[1..] };
            std::fs::write(
                dir.path().join(format!("src/pages/{name}.astro")),
                "---\nimport BaseLayout from '../layouts/BaseLayout.astro';\n---\n<BaseLayout><main>Page</main></BaseLayout>\n",
            )
            .unwrap();
        }
        let discovery = crate::route_discovery::discover_routes(dir.path()).unwrap();
        let seeds = crate::route_discovery::seed_paths(&discovery);
        let latest = Inventory {
            routes: discovery
                .routes
                .iter()
                .filter(|r| r.kind == "page")
                .map(|r| RouteEntry {
                    route: r.path.clone(),
                    visited: true,
                    source: Some(format!("{}:1", r.file)),
                    ..Default::default()
                })
                .collect(),
            controls: vec![control(
                "*|button|text=visit@header",
                &paths,
                "src/components/SiteHeader.astro",
                None,
            )],
            ..Default::default()
        };
        let changed = ChangedFiles {
            files: BTreeSet::from(["src/components/SiteHeader.astro".into()]),
            ..Default::default()
        };
        let i = analyze(dir.path(), &changed, &latest, &discovery, &seeds);
        assert_eq!(routes(&i), paths);
        assert_eq!(
            i.full_reason.as_deref(),
            Some("13 of 13 known routes are affected")
        );
        assert!(i.unmapped.is_empty());
        for route in paths {
            assert!(
                reasons(&i, route).contains(&"imports src/components/SiteHeader.astro"),
                "{i:#?}"
            );
        }
    }

    #[test]
    fn non_ui_files_api_handlers_and_added_or_removed_pages() {
        let dir = next_site();
        let d = dir.path();

        let i = run(d, &["README.md", "e2e/home.spec.ts", "package.json"], &[]);
        assert!(i.affected.is_empty() && i.full_reason.is_none());
        let kinds: Vec<(&str, &str)> = i
            .unmapped
            .iter()
            .map(|u| (u.file.as_str(), u.kind.as_str()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("README.md", "docs"),
                ("e2e/home.spec.ts", "test"),
                ("package.json", "config")
            ]
        );

        // A library the API route imports: the controls calling it.
        let i = run(d, &["src/lib/db.ts"], &[]);
        assert_eq!(routes(&i), vec!["/"]);
        assert_eq!(
            reasons(&i, "/"),
            vec!["calls POST /api/subscribe (handler src/app/api/subscribe/route.ts changed)"]
        );

        // A deleted page is dropped; pages linking to it are re-crawled.
        std::fs::remove_file(d.join("src/app/pricing/page.tsx")).unwrap();
        let i = run(
            d,
            &["src/app/pricing/page.tsx"],
            &["src/app/pricing/page.tsx"],
        );
        assert_eq!(i.removed.iter().collect::<Vec<_>>(), vec!["/pricing"]);
        assert_eq!(routes(&i), vec!["/"]);
        assert_eq!(reasons(&i, "/"), vec!["links to removed route /pricing"]);

        // A new page, and the page whose link to it was broken.
        std::fs::create_dir_all(d.join("src/app/contact")).unwrap();
        std::fs::write(
            d.join("src/app/contact/page.tsx"),
            "export default function P() { return <p /> }\n",
        )
        .unwrap();
        let i = run(d, &["src/app/contact/page.tsx"], &[]);
        assert_eq!(routes(&i), vec!["/about", "/contact"]);
        assert_eq!(reasons(&i, "/about"), vec!["links to new route /contact"]);
    }

    #[test]
    fn test_paths_are_test_files_and_root_harness_dirs_only() {
        assert!(is_test_path("e2e/home.spec.ts"));
        assert!(is_test_path("tests/unit/a.ts"));
        assert!(is_test_path("src/components/Button.test.tsx"));
        assert!(is_test_path("src/components/__tests__/Button.tsx"));
        assert!(is_test_path("src/x/Card.stories.tsx"));
        assert!(!is_test_path("src/app/tests/page.tsx"), "a /tests route");
        assert!(!is_test_path("src/pages/test.astro"));
        assert!(!is_test_path("README.md"));
    }

    #[test]
    fn spa_entry_import_scope_is_not_narrowed_by_sampled_control_sources() {
        let dir = tree(&[
            (
                "package.json",
                r#"{"dependencies":{"react":"19.0.0","react-router-dom":"7.0.0","vite":"6.0.0"}}"#,
            ),
            (
                "index.html",
                "<div id=root></div><script type=module src=/src/main.tsx></script>\n",
            ),
            (
                "src/main.tsx",
                "import './index.css'\nimport App from './App'\ncreateRoot(root).render(<App />)\n",
            ),
            ("src/index.css", "body{}\n"),
            (
                "src/App.tsx",
                "import { Routes, Route } from 'react-router-dom'\nimport Home from './pages/Home'\nimport Settings from './pages/Settings'\nexport default function App() { return <Routes><Route path=\"/\" element={<Home />} /><Route path=\"/settings\" element={<Settings />} /></Routes> }\n",
            ),
            (
                "src/pages/Home.tsx",
                "export default function Home() { return <h1 /> }\n",
            ),
            (
                "src/pages/Settings.tsx",
                "import Toggle from '../components/Toggle'\nexport default function S() { return <Toggle /> }\n",
            ),
            (
                "src/components/Toggle.tsx",
                "export default function T() { return <button>Dark</button> }\n",
            ),
            (
                "src/components/Unused.tsx",
                "export default function U() { return null }\n",
            ),
        ]);
        let d = dir.path();
        let discovery = crate::route_discovery::discover_routes(d).unwrap();
        assert!(
            discovery.routes.iter().any(|r| r.path == "/settings"),
            "{discovery:#?}"
        );
        let inv = Inventory {
            routes: ["/", "/settings"]
                .iter()
                .map(|r| RouteEntry {
                    route: r.to_string(),
                    visited: true,
                    source: Some("src/App.tsx:4".into()),
                    ..Default::default()
                })
                .collect(),
            controls: vec![control(
                "/settings|button|text=dark",
                &[],
                "src/components/Toggle.tsx",
                Some("src/pages/Settings.tsx"),
            )],
            ..Default::default()
        };
        let analyze_files = |files: &[&str]| {
            let changed = ChangedFiles {
                files: files.iter().map(|f| f.to_string()).collect(),
                ..Default::default()
            };
            analyze(
                d,
                &changed,
                &inv,
                &discovery,
                &["/".into(), "/settings".into()],
            )
        };
        // The router/entry imports this module. Sampled controls on /settings
        // do not prove it cannot affect the rest of the shell. Without separate
        // route-component dependency boundaries this requires a full map.
        let i = analyze_files(&["src/components/Toggle.tsx"]);
        assert_eq!(routes(&i), vec!["/settings"]);
        assert!(i.full_reason.is_some(), "{i:#?}");
        // Without control evidence a component under the SPA entry is app-wide.
        let i = analyze_files(&["src/pages/Home.tsx"]);
        assert!(i.full_reason.is_some(), "{i:#?}");
        // Entries and global styles.
        for f in ["src/App.tsx", "index.html", "src/index.css"] {
            assert!(analyze_files(&[f]).full_reason.is_some(), "{f}");
        }
        // A file nothing imports maps to nothing.
        let i = analyze_files(&["src/components/Unused.tsx"]);
        assert!(i.affected.is_empty() && i.full_reason.is_none());
        assert_eq!(i.unmapped[0].kind, "source");
    }

    #[test]
    fn non_js_backend_and_template_edits_trigger_safe_full_fallback() {
        let dir = tree(&[
            ("Gemfile", "gem 'rails'\n"),
            (
                "app/controllers/orders_controller.rb",
                "class OrdersController < ApplicationController; end\n",
            ),
            (
                "app/views/orders/index.html.erb",
                "<button>Place order</button>\n",
            ),
            (
                "app/views/orders/show.html.erb",
                "<button>Cancel order</button>\n",
            ),
            ("shop/views.py", "def checkout(request): pass\n"),
            ("templates/checkout.html", "<button>Pay now</button>\n"),
            ("resources/views/home.blade.php", "<a href='/'>Home</a>\n"),
            ("db/schema.sql", "CREATE TABLE orders (id INT);\n"),
            ("schema.graphql", "type Query { orders: [Order] }\n"),
            ("README.md", "# docs\n"),
            ("LICENSE", "MIT\n"),
            ("Gemfile.lock", "GEM\n"),
            ("tests/test_views.py", "def test_ok(): pass\n"),
            ("shop/orders_test.py", "def test_order(): pass\n"),
            (
                "spec/requests/orders_spec.rb",
                "RSpec.describe 'Orders' {}\n",
            ),
            ("app/models/order_spec.rb", "RSpec.describe Order {}\n"),
            (".github/workflows/ci.yml", "name: CI\n"),
        ]);
        let discovery = RouteDiscovery::default();
        let inv = Inventory {
            routes: vec![
                RouteEntry {
                    route: "/".into(),
                    visited: true,
                    ..Default::default()
                },
                RouteEntry {
                    route: "/orders".into(),
                    visited: true,
                    ..Default::default()
                },
                RouteEntry {
                    route: "/orders/:id".into(),
                    visited: true,
                    ..Default::default()
                },
                RouteEntry {
                    route: "/checkout".into(),
                    visited: true,
                    ..Default::default()
                },
            ],
            controls: vec![control(
                "/orders/:id|button|text=cancel order",
                &[],
                "app/views/orders/show.html.erb",
                None,
            )],
            ..Default::default()
        };
        let run_non_js = |files: &[&str]| {
            let changed = ChangedFiles {
                files: files.iter().map(|f| f.to_string()).collect(),
                ..Default::default()
            };
            analyze(dir.path(), &changed, &inv, &discovery, &[])
        };

        // Rails .rb and unattributed .html.erb must trigger full fallback.
        for file in [
            "app/controllers/orders_controller.rb",
            "app/views/orders/index.html.erb",
            "shop/views.py",
            "templates/checkout.html",
            "resources/views/home.blade.php",
            "db/schema.sql",
            "schema.graphql",
        ] {
            let i = run_non_js(&[file]);
            assert!(
                i.full_reason.is_some(),
                "{file} must trigger full fallback, not silent skip: {i:#?}"
            );
            assert_eq!(i.unmapped.len(), 1, "{file}");
            assert_eq!(i.unmapped[0].kind, "source", "{file}");
        }

        // An .html.erb file directly attributed in the saved map stays scoped.
        let i = run_non_js(&["app/views/orders/show.html.erb"]);
        assert_eq!(routes(&i), vec!["/orders/:id"]);
        assert!(i.full_reason.is_none(), "{i:#?}");

        // Docs, license, lockfiles, CI, and non-JS unit tests still skip cleanly.
        let i = run_non_js(&[
            "README.md",
            "LICENSE",
            "Gemfile.lock",
            "tests/test_views.py",
            "shop/orders_test.py",
            "spec/requests/orders_spec.rb",
            "app/models/order_spec.rb",
            ".github/workflows/ci.yml",
        ]);
        assert!(
            i.affected.is_empty() && i.full_reason.is_none(),
            "docs/tests/lockfiles/CI must fast-skip: {i:#?}"
        );
    }

    #[test]
    fn angular_component_templates_scope_via_sibling_ts_or_fall_back_safely() {
        let dir = tree(&[
            (
                "package.json",
                r#"{"dependencies":{"@angular/core":"18.0.0","@angular/router":"18.0.0"}}"#,
            ),
            (
                "src/app/checkout/checkout.routes.ts",
                "import { Routes } from '@angular/router';\nimport { CheckoutComponent } from './checkout.component';\nexport const CHECKOUT_ROUTES: Routes = [{ path: 'checkout', component: CheckoutComponent }];\n",
            ),
            (
                "src/app/checkout/checkout.component.ts",
                "export class CheckoutComponent {}\n",
            ),
            (
                "src/app/checkout/checkout.component.html",
                "<button>Pay now</button>\n",
            ),
            (
                "src/app/checkout/checkout.component.scss",
                ".pay { color: green; }\n",
            ),
            (
                "src/app/orphan/orphan.component.html",
                "<button>Orphan</button>\n",
            ),
        ]);
        let discovery = RouteDiscovery {
            framework: "angular".into(),
            routes: vec![
                DiscoveredRoute {
                    path: "/checkout".into(),
                    kind: "page".into(),
                    file: "src/app/checkout/checkout.routes.ts".into(),
                    line: 3,
                    ..Default::default()
                },
                DiscoveredRoute {
                    path: "/home".into(),
                    kind: "page".into(),
                    file: "src/app/home/home.routes.ts".into(),
                    line: 1,
                    ..Default::default()
                },
                DiscoveredRoute {
                    path: "/about".into(),
                    kind: "page".into(),
                    file: "src/app/about/about.routes.ts".into(),
                    line: 1,
                    ..Default::default()
                },
                DiscoveredRoute {
                    path: "/pricing".into(),
                    kind: "page".into(),
                    file: "src/app/pricing/pricing.routes.ts".into(),
                    line: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let inv = Inventory {
            routes: ["/checkout", "/home", "/about", "/pricing"]
                .iter()
                .map(|r| RouteEntry {
                    route: r.to_string(),
                    visited: true,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let run_ng = |files: &[&str]| {
            let changed = ChangedFiles {
                files: files.iter().map(|f| f.to_string()).collect(),
                ..Default::default()
            };
            analyze(dir.path(), &changed, &inv, &discovery, &[])
        };

        // Template and stylesheet edits link through sibling checkout.component.ts
        // to the /checkout route without forcing a full crawl.
        let html = run_ng(&["src/app/checkout/checkout.component.html"]);
        assert_eq!(routes(&html), vec!["/checkout"]);
        assert!(html.full_reason.is_none(), "{html:#?}");
        assert!(html.unmapped.is_empty(), "{html:#?}");

        let scss = run_ng(&["src/app/checkout/checkout.component.scss"]);
        assert_eq!(routes(&scss), vec!["/checkout"]);
        assert!(scss.full_reason.is_none(), "{scss:#?}");

        // An unlinked Angular template with no sibling TS falls back safely.
        let orphan = run_ng(&["src/app/orphan/orphan.component.html"]);
        assert!(
            orphan.full_reason.is_some(),
            "orphan template must not silently skip: {orphan:#?}"
        );
        assert_eq!(orphan.unmapped[0].kind, "source");
    }
}
