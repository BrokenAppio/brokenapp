//! Discover a web app's routes from its codebase (file-based routing and
//! router configs) so scans can seed every page instead of relying on links
//! the crawler happens to find.
//!
//! Adapters: Next.js (app and pages routers), Astro, SvelteKit, Nuxt, Remix /
//! React Router v7 (flat files and `app/routes.ts`), TanStack Router file
//! routes, React Router (JSX and route objects), Vue Router, Angular, Hono /
//! Express / Fastify server routes, and static HTML files. Detection is driven
//! by `package.json` dependencies plus the files present. Everything is
//! best-effort static reading: paths built at runtime are skipped and counted
//! in [`RouteDiscovery::notes`].

mod config_routers;
mod file_routers;
mod fs;
mod js;
mod next;
mod paths;
mod server;
mod static_params;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use self::fs::{Aliases, FileSet, Package};
use self::js::JsSource;

/// One route found in source.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredRoute {
    /// Browser path as the crawler sees it, with the base path and hash
    /// prefix already applied: `/checkout`, `/products/[id]` ->
    /// `/products/:id`, `/#/admin` for hash-routed SPAs, `/docs/intro` under
    /// a `/docs` base path. Optional segments end in `?` (`/:lang?/about`),
    /// catch-alls in `*` (zero or more) or `+` (one or more), splats are `*`.
    /// No trailing slash (see [`RouteDiscovery::trailing_slash`]).
    pub path: String,
    /// Contains a dynamic segment (`:id`, catch-all) and needs a real value.
    pub dynamic: bool,
    /// `page`, `api`, `redirect`, `layout`, or `error` (framework error
    /// pages such as `/404` and `/500`: never seeded, not app routes).
    pub kind: String,
    /// Repo-relative file that defines the route.
    pub file: String,
    #[serde(default)]
    pub line: u32,
    /// HTTP methods for `api` routes and server handlers (`GET`, `POST`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Concrete browser paths for a dynamic route, read from literal
    /// `generateStaticParams` / `getStaticPaths` values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
}

/// Result of scanning a codebase for routes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RouteDiscovery {
    /// `nextjs-app`, `nextjs-pages`, `astro`, `sveltekit`, `nuxt`, `remix`,
    /// `tanstack-router`, `react-router`, `vue-router`, `angular`, `hono`,
    /// `express`, `fastify`, `vite`, `static`, `unknown`.
    pub framework: String,
    /// Client routes live in the URL fragment (`/#/path`).
    pub hash_routing: bool,
    /// Base path prefix (Next `basePath`, Vite `base`), `""` if none.
    /// Already included in every route `path`.
    pub base_path: String,
    pub routes: Vec<DiscoveredRoute>,
    /// The app directory that was scanned, relative to the given codebase
    /// (`apps/web` in a monorepo), `""` when it is the codebase itself.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub app_dir: String,
    /// The framework serves pages with a trailing slash (Next
    /// `trailingSlash: true`, Astro `trailingSlash: 'always'`). Applied by
    /// [`seed_paths`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trailing_slash: bool,
    /// Coverage caveats, e.g. route paths computed at runtime.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Scan `codebase` (a repo or app directory) for routes. Never panics on
/// unreadable files; returns `framework = "unknown"` with no routes when
/// nothing is recognized; errors only when `codebase` is not a readable
/// directory. In a monorepo whose root is not itself an app, the best
/// workspace app (`pnpm-workspace.yaml` / `package.json#workspaces` globs,
/// `apps/*`, `packages/*`, `web/`, ...) is scanned instead and reported in
/// `app_dir`; `file` paths stay relative to `codebase`.
pub fn discover_routes(codebase: &Path) -> Result<RouteDiscovery> {
    let meta = std::fs::metadata(codebase)
        .with_context(|| format!("read codebase {}", codebase.display()))?;
    anyhow::ensure!(
        meta.is_dir(),
        "codebase {} is not a directory",
        codebase.display()
    );
    let root = codebase.to_path_buf();

    let at_root = discover_app(&root, &root);
    if !at_root.routes.is_empty() {
        return Ok(at_root);
    }
    let best = fs::workspace_apps(&root)
        .into_iter()
        .map(|app| discover_app(&root, &app))
        .filter(|d| !d.routes.is_empty())
        .max_by_key(|d| {
            let pages = d.routes.iter().filter(|r| r.kind == "page").count();
            (app_name_rank(&d.app_dir), pages)
        });
    Ok(best.unwrap_or(at_root))
}

/// Preferred monorepo app directory names, higher is better.
fn app_name_rank(app_dir: &str) -> usize {
    const PREFERRED: &[&[&str]] = &[
        &["admin", "dashboard"],
        &["client", "frontend"],
        &["www", "site", "website"],
        &["app", "web"],
    ];
    let name = app_dir.rsplit('/').next().unwrap_or(app_dir);
    PREFERRED
        .iter()
        .position(|group| group.contains(&name))
        .map_or(0, |i| i + 1)
}

/// Concrete (non-dynamic) page routes formatted for `--seed-routes-file`:
/// one path per line, base path applied, `/#` prefix for hash routing.
/// Dynamic routes contribute their `examples` and, when every dynamic segment
/// is optional, the path without them (`/admin/:section*` -> `/admin`).
/// Error pages (`/404`, `/500`) are left out.
pub fn seed_paths(discovery: &RouteDiscovery) -> Vec<String> {
    let already_hashed = discovery.routes.iter().any(|r| r.path.contains('#'));
    let mut out = BTreeSet::new();
    for route in discovery.routes.iter().filter(|r| r.kind == "page") {
        let mut candidates = Vec::new();
        if route.dynamic {
            candidates.extend(paths::concrete_variant(&route.path));
            candidates.extend(route.examples.iter().cloned());
        } else {
            candidates.push(route.path.clone());
        }
        for path in candidates {
            let path = ensure_browser_path(discovery, &path, already_hashed);
            let bare = path
                .strip_prefix(discovery.base_path.as_str())
                .unwrap_or(&path)
                .trim_start_matches("/#");
            if matches!(bare, "/404" | "/500") || paths::is_dynamic(&path) {
                continue;
            }
            out.insert(with_trailing_slash(discovery, path));
        }
    }
    out.into_iter().collect()
}

/// Route templates of dynamic page routes, for the scanner's instance
/// sampling (`scan.route_templates`): instances of one template share an
/// identity, so the crawler samples a few instead of re-crawling every
/// `/towns/<slug>` page. Left out:
///
/// - routes whose values are enumerated in source (`generateStaticParams`,
///   `getStaticPaths` examples): each example is seeded and can be a
///   distinct page (`/[view]` rendering `/universe` and `/settings`);
/// - templates without a static segment (`/:slug`, `/*`), which would make
///   every top-level page an instance of one template.
pub fn route_templates(discovery: &RouteDiscovery) -> Vec<String> {
    let already_hashed = discovery.routes.iter().any(|r| r.path.contains('#'));
    let mut out = BTreeSet::new();
    for route in discovery
        .routes
        .iter()
        .filter(|r| r.kind == "page" && r.dynamic && r.examples.is_empty())
    {
        let path = ensure_browser_path(discovery, &route.path, already_hashed);
        let rel = path
            .strip_prefix(discovery.base_path.as_str())
            .unwrap_or(&path);
        let has_static_segment = rel
            .split('/')
            .any(|seg| !seg.is_empty() && seg != "#" && !paths::is_dynamic(seg));
        if has_static_segment {
            out.insert(path);
        }
    }
    out.into_iter().collect()
}

/// Framework error pages (`404.astro`, `pages/500.tsx`, `public/404.html`)
/// are not app routes: they would be seeded, reported as never visited, and
/// templated like `/:id`.
fn is_error_page(router_path: &str) -> bool {
    matches!(
        router_path.trim_end_matches('/'),
        "/404" | "/500" | "/404.html" | "/500.html" | "/_error" | "/_not-found"
    )
}

/// Applies the base path and hash prefix for discoveries built by hand.
/// Paths produced by [`discover_routes`] already carry both (hash-routed
/// discoveries contain `#` paths), so they pass through unchanged.
fn ensure_browser_path(discovery: &RouteDiscovery, path: &str, already_hashed: bool) -> String {
    let base = discovery.base_path.as_str();
    let bare = if base.is_empty() {
        path
    } else if path == base {
        "/"
    } else {
        path.strip_prefix(base)
            .filter(|rest| rest.starts_with('/'))
            .unwrap_or(path)
    };
    if discovery.hash_routing
        && !already_hashed
        && !bare.starts_with("/#")
        && !last_segment_has_ext(bare)
    {
        format!("{base}/#{bare}")
    } else {
        prefix_path(base, bare)
    }
}

fn with_trailing_slash(discovery: &RouteDiscovery, path: String) -> String {
    if discovery.trailing_slash
        && !path.ends_with('/')
        && !path.contains('#')
        && !last_segment_has_ext(&path)
    {
        format!("{path}/")
    } else {
        path
    }
}

fn last_segment_has_ext(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|s| s.contains('.'))
}

fn prefix_path(base: &str, path: &str) -> String {
    if base.is_empty() {
        path.to_string()
    } else if path == "/" {
        base.to_string()
    } else {
        format!("{base}{path}")
    }
}

/// Resolves import specifiers the way route discovery does: relative paths
/// and the tsconfig/jsconfig `paths` aliases of an app directory (plus the
/// `@/` and `~/` defaults). Used by `map --changed` to follow imports from a
/// changed file to the routes that render it.
pub(crate) struct ImportResolver(fs::Aliases);

impl ImportResolver {
    pub(crate) fn load(app_dir: &Path) -> Self {
        Self(fs::Aliases::load(app_dir))
    }

    /// The file `spec` resolves to from the file `from`, when it exists.
    pub(crate) fn resolve(&self, from: &Path, spec: &str) -> Option<PathBuf> {
        self.0.resolve(from, spec)
    }
}

// ---------------------------------------------------------------------------
// Internal model shared by the adapters.

/// Which URL rules a route follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Client-side router: base path and hash prefix apply.
    Client,
    /// File-based framework router or static file: base path applies.
    File,
    /// Server handler: paths are absolute.
    Server,
}

/// A route before base/hash finalization. `path` is router-relative.
#[derive(Debug, Clone)]
pub(crate) struct Found {
    pub path: String,
    pub kind: &'static str,
    pub file: PathBuf,
    pub line: u32,
    pub methods: BTreeSet<String>,
    pub examples: Vec<String>,
    pub origin: Origin,
}

impl Found {
    pub fn new(path: String, kind: &'static str, file: &Path, line: u32, origin: Origin) -> Self {
        Self {
            path,
            kind,
            file: file.to_path_buf(),
            line,
            methods: BTreeSet::new(),
            examples: Vec::new(),
            origin,
        }
    }
}

/// What one adapter found.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub framework: &'static str,
    pub routes: Vec<Found>,
    pub base_path: String,
    pub hash_routing: bool,
    pub trailing_slash: bool,
}

impl Outcome {
    pub fn new(framework: &'static str) -> Self {
        Self {
            framework,
            ..Default::default()
        }
    }
}

/// Shared state for one app directory.
pub(crate) struct Ctx {
    pub app_dir: PathBuf,
    pub files: FileSet,
    pub pkg: Package,
    pub aliases: Aliases,
    notes: RefCell<BTreeMap<String, usize>>,
    sources: RefCell<HashMap<PathBuf, Option<Rc<JsSource>>>>,
}

impl Ctx {
    fn new(app_dir: &Path) -> Self {
        Self {
            app_dir: app_dir.to_path_buf(),
            files: FileSet::walk(app_dir),
            pkg: Package::read(app_dir),
            aliases: Aliases::load(app_dir),
            notes: RefCell::new(BTreeMap::new()),
            sources: RefCell::new(HashMap::new()),
        }
    }

    /// Cached, comment-stripped source of a file.
    pub fn source(&self, path: &Path) -> Option<Rc<JsSource>> {
        if let Some(cached) = self.sources.borrow().get(path) {
            return cached.clone();
        }
        let loaded = fs::read_js(path).map(Rc::new);
        self.sources
            .borrow_mut()
            .insert(path.to_path_buf(), loaded.clone());
        loaded
    }

    /// Records a coverage caveat; repeated messages are counted.
    pub fn note(&self, message: impl Into<String>) {
        *self.notes.borrow_mut().entry(message.into()).or_default() += 1;
    }

    pub fn rel(&self, path: &Path) -> String {
        fs::rel_path(&self.app_dir, path)
    }

    pub fn resolve_import(&self, from: &Path, spec: &str) -> Option<PathBuf> {
        self.aliases.resolve(from, spec)
    }
}

/// Runs every adapter that applies to `app_dir` and merges the results.
fn discover_app(root: &Path, app_dir: &Path) -> RouteDiscovery {
    let ctx = Ctx::new(app_dir);
    let pkg = &ctx.pkg;
    let mut outcomes: Vec<Outcome> = Vec::new();
    let remix = file_routers::is_remix(&ctx);

    if pkg.has_any(&["next", "vinext"]) {
        outcomes.push(next::discover(&ctx));
    }
    if remix {
        outcomes.push(config_routers::remix(&ctx));
    }
    if pkg.has("astro") {
        outcomes.push(file_routers::astro(&ctx));
    }
    if pkg.has("@sveltejs/kit") {
        outcomes.push(file_routers::sveltekit(&ctx));
    }
    if pkg.has("nuxt") {
        outcomes.push(file_routers::nuxt(&ctx));
    }
    if pkg.has_any(&["@tanstack/react-router", "@tanstack/solid-router"]) {
        outcomes.push(file_routers::tanstack(&ctx));
    }
    if pkg.has_any(&["@angular/router", "@angular/core"]) {
        outcomes.push(config_routers::angular(&ctx));
    }
    if pkg.has("vue-router") {
        outcomes.push(config_routers::vue(&ctx));
    }
    if pkg.has_any(&["react-router", "react-router-dom", "wouter"]) && !remix {
        outcomes.push(config_routers::react_router(&ctx));
    }
    let has_client_routes = outcomes.iter().any(|o| !o.routes.is_empty());
    for (dep, framework) in [
        ("hono", "hono"),
        ("express", "express"),
        ("fastify", "fastify"),
    ] {
        if pkg.has(dep) {
            outcomes.push(server::discover(&ctx, framework));
        }
    }
    if !has_client_routes {
        let custom = config_routers::custom_hash_routes(&ctx);
        if !custom.routes.is_empty() {
            outcomes.push(custom);
        }
    }
    let has_app_routes = outcomes.iter().any(|o| !o.routes.is_empty());
    outcomes.push(file_routers::static_html(&ctx, has_app_routes));

    merge(root, &ctx, outcomes)
}

fn merge(root: &Path, ctx: &Ctx, outcomes: Vec<Outcome>) -> RouteDiscovery {
    let primary = outcomes.iter().find(|o| !o.routes.is_empty()).or_else(|| {
        outcomes
            .iter()
            .find(|o| !matches!(o.framework, "static" | "vite"))
    });
    let framework = primary.map_or("unknown", |o| o.framework);
    let base_path = primary
        .map(|o| o.base_path.clone())
        .filter(|b| !b.is_empty())
        .or_else(|| {
            outcomes
                .iter()
                .map(|o| o.base_path.clone())
                .find(|b| !b.is_empty())
        })
        .unwrap_or_default();
    let hash_routing = outcomes
        .iter()
        .any(|o| o.hash_routing && !o.routes.is_empty());
    let trailing_slash = primary.is_some_and(|o| o.trailing_slash);

    let mut found: Vec<Found> = outcomes.into_iter().flat_map(|o| o.routes).collect();
    found.sort_by(|a, b| {
        (a.path.as_str(), a.kind, &a.file, a.line).cmp(&(b.path.as_str(), b.kind, &b.file, b.line))
    });

    let browser = |path: &str, origin: Origin| -> String {
        match origin {
            Origin::Server => path.to_string(),
            Origin::File => prefix_path(&base_path, path),
            Origin::Client if hash_routing => format!("{base_path}/#{path}"),
            Origin::Client => prefix_path(&base_path, path),
        }
    };

    let mut merged: BTreeMap<(String, &'static str), DiscoveredRoute> = BTreeMap::new();
    for f in found {
        let path = browser(&f.path, f.origin);
        let kind = if f.kind == "page" && is_error_page(&f.path) {
            "error"
        } else {
            f.kind
        };
        let entry = merged
            .entry((path.clone(), kind))
            .or_insert_with(|| DiscoveredRoute {
                dynamic: paths::is_dynamic(&f.path),
                path,
                kind: kind.to_string(),
                file: fs::rel_path(root, &f.file),
                line: f.line,
                methods: Vec::new(),
                examples: Vec::new(),
            });
        for m in f.methods {
            if !entry.methods.contains(&m) {
                entry.methods.push(m);
            }
        }
        for ex in f.examples {
            let ex = browser(&ex, f.origin);
            if !entry.examples.contains(&ex) {
                entry.examples.push(ex);
            }
        }
    }
    let routes: Vec<DiscoveredRoute> = merged
        .into_values()
        .map(|mut r| {
            r.methods.sort();
            r.examples.sort();
            r
        })
        .collect();

    let notes = ctx
        .notes
        .borrow()
        .iter()
        .map(|(msg, n)| {
            if *n > 1 {
                format!("{msg} (x{n})")
            } else {
                msg.clone()
            }
        })
        .collect();

    RouteDiscovery {
        framework: framework.to_string(),
        hash_routing,
        base_path,
        routes,
        app_dir: fs::rel_path(root, &ctx.app_dir),
        trailing_slash,
        notes,
    }
}

#[cfg(test)]
mod tests;
