//! File-system routers: Astro, SvelteKit, Nuxt, Remix / React Router v7 flat
//! routes, TanStack Router file routes, and static HTML.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use super::fs::{self, file_name, rel_dirs};
use super::js::JsSource;
use super::next::{default_export_line, exported_methods, has_default_export};
use super::paths::{self, bracket_segment, from_segments};
use super::{Ctx, Found, Origin, Outcome, static_params};

static ASTRO_BASE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bbase\s*:\s*["'`](/[^"'`]*)["'`]"#).expect("valid regex"));
static ASTRO_TRAILING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\btrailingSlash\s*:\s*["']always["']"#).expect("valid regex"));

fn split_name(name: &str) -> (&str, &str) {
    name.rsplit_once('.').unwrap_or((name, ""))
}

fn config_text(ctx: &Ctx, names: &[&str]) -> Option<String> {
    fs::first_config(&ctx.app_dir, names)
        .and_then(|p| fs::read_source(&p))
        .map(|raw| JsSource::new(&raw).text)
}

// ---------------------------------------------------------------- Astro

pub(crate) fn astro(ctx: &Ctx) -> Outcome {
    let mut outcome = Outcome::new("astro");
    if let Some(cfg) = config_text(ctx, &["astro.config"]) {
        if let Some(cap) = ASTRO_BASE_RE.captures(&cfg) {
            outcome.base_path = paths::normalize_base(&cap[1]);
        }
        outcome.trailing_slash = ASTRO_TRAILING_RE.is_match(&cfg);
    }
    let dir = ctx.app_dir.join("src/pages");
    for file in ctx.files.under(&dir) {
        let dirs = rel_dirs(&dir, file);
        let name = file_name(file);
        let (stem, ext) = split_name(&name);
        if stem.starts_with('_') || dirs.iter().any(|d| d.starts_with('_')) {
            continue;
        }
        let kind = match ext {
            "astro" | "md" | "mdx" | "markdown" | "html" => "page",
            "ts" | "js" | "mjs" | "mts" => "api",
            _ => continue,
        };
        let mut segments: Vec<String> = dirs.iter().map(|d| bracket_segment(d, true)).collect();
        if stem != "index" {
            segments.push(bracket_segment(stem, true));
        }
        let mut found = Found::new(from_segments(segments), kind, file, 1, Origin::File);
        if let Some(src) = ctx.source(file) {
            if kind == "api" {
                found.methods = exported_methods(&src);
            } else if paths::is_dynamic(&found.path) {
                found.examples =
                    static_params::examples(ctx, file, &src, &found.path, &["getStaticPaths"]);
            }
        }
        outcome.routes.push(found);
    }
    outcome
}

// ---------------------------------------------------------------- SvelteKit

static SVELTE_PAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\+(page|layout|server)(@[^.]*)?\.(svelte|ts|js)$").expect("valid regex")
});
static SVELTE_BASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bpaths\s*:\s*\{[^}]*\bbase\s*:\s*["'`](/[^"'`]*)["'`]"#).expect("valid regex")
});

pub(crate) fn sveltekit(ctx: &Ctx) -> Outcome {
    let mut outcome = Outcome::new("sveltekit");
    if let Some(cfg) = config_text(ctx, &["svelte.config"])
        && let Some(cap) = SVELTE_BASE_RE.captures(&cfg)
    {
        outcome.base_path = paths::normalize_base(&cap[1]);
    }
    let dir = ctx.app_dir.join("src/routes");
    for file in ctx.files.under(&dir) {
        let name = file_name(file);
        let Some(cap) = SVELTE_PAGE_RE.captures(&name) else {
            continue;
        };
        let kind = match (&cap[1], &cap[3]) {
            ("page", "svelte") => "page",
            ("layout", "svelte") => "layout",
            ("server", "ts" | "js") => "api",
            _ => continue,
        };
        let dirs = rel_dirs(&dir, file);
        let path = from_segments(
            dirs.iter()
                .filter(|d| !(d.starts_with('(') && d.ends_with(')')))
                .map(|d| bracket_segment(d, true)),
        );
        let mut found = Found::new(path, kind, file, 1, Origin::File);
        if kind == "api"
            && let Some(src) = ctx.source(file)
        {
            found.methods = exported_methods(&src);
        }
        outcome.routes.push(found);
    }
    outcome
}

// ---------------------------------------------------------------- Nuxt

static NUXT_METHOD_SUFFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.(get|post|put|patch|delete|head|options)$").expect("valid regex")
});

pub(crate) fn nuxt(ctx: &Ctx) -> Outcome {
    let mut outcome = Outcome::new("nuxt");
    let pages = ["app/pages", "pages", "src/pages"]
        .iter()
        .map(|p| ctx.app_dir.join(p))
        .find(|p| p.is_dir());
    if let Some(dir) = pages {
        for file in ctx.files.under(&dir) {
            let name = file_name(file);
            let (stem, ext) = split_name(&name);
            if ext != "vue" {
                continue;
            }
            let dirs = rel_dirs(&dir, file);
            let mut segments: Vec<String> = dirs
                .iter()
                .filter(|d| !(d.starts_with('(') && d.ends_with(')')))
                .map(|d| bracket_segment(d, true))
                .collect();
            if stem != "index" {
                segments.push(bracket_segment(stem, true));
            }
            outcome.routes.push(Found::new(
                from_segments(segments),
                "page",
                file,
                1,
                Origin::File,
            ));
        }
    }
    for (sub, prefix) in [("server/api", "api"), ("server/routes", "")] {
        let dir = ctx.app_dir.join(sub);
        for file in ctx.files.under(&dir) {
            let name = file_name(file);
            let (stem, ext) = split_name(&name);
            if !matches!(ext, "ts" | "js" | "mjs") {
                continue;
            }
            let method = NUXT_METHOD_SUFFIX_RE
                .captures(stem)
                .map(|c| c[1].to_ascii_uppercase());
            let stem = NUXT_METHOD_SUFFIX_RE.replace(stem, "");
            let mut segments = vec![prefix.to_string()];
            segments.extend(
                rel_dirs(&dir, file)
                    .iter()
                    .map(|d| bracket_segment(d, true)),
            );
            if stem != "index" {
                segments.push(bracket_segment(&stem, true));
            }
            let mut found = Found::new(from_segments(segments), "api", file, 1, Origin::Server);
            found.methods.extend(method);
            outcome.routes.push(found);
        }
    }
    outcome
}

// ---------------------------------------------------------------- Remix

/// Remix or React Router v7 framework mode (file routes or `app/routes.ts`).
pub(crate) fn is_remix(ctx: &Ctx) -> bool {
    let deps = ctx.pkg.has_any(&[
        "@remix-run/react",
        "@remix-run/dev",
        "@remix-run/node",
        "@remix-run/cloudflare",
        "@react-router/dev",
    ]);
    deps && (ctx.app_dir.join("app/routes").is_dir()
        || fs::first_config(&ctx.app_dir.join("app"), &["routes"]).is_some())
}

const REMIX_EXTS: &[&str] = &["tsx", "ts", "jsx", "js", "mdx", "md"];

/// One route module in a flat-routes directory.
struct RemixModule {
    /// Segments of the route id (`concerts.$city` -> `["concerts", "$city"]`).
    id: Vec<String>,
    file: PathBuf,
}

/// Remix v2 / React Router v7 flat routes (`app/routes/concerts.$city.tsx`,
/// `app/routes/concerts.$city/route.tsx`), or the Remix v1 nested-folder
/// convention when `v1` is set. Paths are joined onto `prefix`.
pub(crate) fn remix_flat_routes(
    ctx: &Ctx,
    routes_dir: &Path,
    prefix: &str,
    v1: bool,
) -> Vec<Found> {
    let modules = if v1 {
        remix_v1_modules(ctx, routes_dir)
    } else {
        remix_v2_modules(routes_dir)
    };
    let mut paths_by_id: BTreeMap<String, String> = BTreeMap::new();
    for m in &modules {
        paths_by_id.insert(m.id.join("."), remix_path(prefix, &m.id));
    }
    let mut out = Vec::new();
    for m in &modules {
        let id = m.id.join(".");
        let path = paths_by_id
            .get(&id)
            .cloned()
            .unwrap_or_else(|| "/".to_string());
        let src = ctx.source(&m.file);
        let markdown = m.file.extension().is_some_and(|e| e == "md" || e == "mdx");
        let resource = !markdown && src.as_ref().is_some_and(|s| !has_default_export(s));
        let pathless =
            m.id.last()
                .is_some_and(|s| s.starts_with('_') && s != "_index" && !s.ends_with('_'));
        let has_same_path_child = paths_by_id.iter().any(|(other, other_path)| {
            other.len() > id.len()
                && other.starts_with(&id)
                && other.as_bytes().get(id.len()) == Some(&b'.')
                && *other_path == path
        });
        let kind = if resource {
            "api"
        } else if pathless || has_same_path_child {
            "layout"
        } else {
            "page"
        };
        if paths::is_wildcard_only(&path) && kind != "api" {
            continue;
        }
        let line = src.as_ref().map_or(1, |s| default_export_line(s));
        out.push(Found::new(path, kind, &m.file, line, Origin::File));
    }
    out
}

fn remix_v2_modules(routes_dir: &Path) -> Vec<RemixModule> {
    let Ok(entries) = std::fs::read_dir(routes_dir) else {
        return Vec::new();
    };
    let mut modules = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = file_name(&path);
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            let route_file = REMIX_EXTS
                .iter()
                .map(|ext| path.join(format!("route.{ext}")))
                .find(|p| p.is_file());
            if let Some(file) = route_file {
                modules.push(RemixModule {
                    id: split_route_id(&name),
                    file,
                });
            }
            continue;
        }
        let (stem, ext) = split_name(&name);
        if !REMIX_EXTS.contains(&ext) || stem.ends_with(".test") || stem.ends_with(".spec") {
            continue;
        }
        modules.push(RemixModule {
            id: split_route_id(stem),
            file: path,
        });
    }
    modules.sort_by(|a, b| a.file.cmp(&b.file));
    modules
}

fn remix_v1_modules(ctx: &Ctx, routes_dir: &Path) -> Vec<RemixModule> {
    let mut modules = Vec::new();
    for file in ctx.files.under(routes_dir) {
        let name = file_name(file);
        let (stem, ext) = split_name(&name);
        if !REMIX_EXTS.contains(&ext) {
            continue;
        }
        let mut id: Vec<String> = rel_dirs(routes_dir, file)
            .into_iter()
            .map(|d| d.replace("__", "_"))
            .collect();
        id.push(if stem == "index" {
            "_index".to_string()
        } else {
            stem.replace("__", "_")
        });
        modules.push(RemixModule {
            id,
            file: file.clone(),
        });
    }
    modules
}

/// Splits a flat route id on `.` outside `[...]` escapes.
fn split_route_id(id: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut escaped = 0usize;
    for c in id.chars() {
        match c {
            '[' => {
                escaped += 1;
                current.push(c);
            }
            ']' => {
                escaped = escaped.saturating_sub(1);
                current.push(c);
            }
            '.' if escaped == 0 => out.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    out.push(current);
    out
}

fn remix_path(prefix: &str, id: &[String]) -> String {
    let mut segments = Vec::new();
    for seg in id {
        if seg == "_index" {
            continue;
        }
        if seg.starts_with('_') && !seg.ends_with('_') {
            continue; // pathless layout
        }
        let seg = seg.strip_suffix('_').unwrap_or(seg);
        let (optional, seg) = match seg.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
            Some(inner) => (true, inner),
            None => (false, seg),
        };
        let mut converted = if seg == "$" {
            "*".to_string()
        } else if let Some(name) = seg.strip_prefix('$') {
            format!(":{name}")
        } else {
            seg.replace(['[', ']'], "")
        };
        if optional {
            converted.push('?');
        }
        if !converted.is_empty() {
            segments.push(converted);
        }
    }
    paths::join(prefix, from_segments(segments).trim_start_matches('/'))
}

// ---------------------------------------------------------------- TanStack

static CREATE_FILE_ROUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bcreateFileRoute\s*\(\s*["'`]([^"'`]+)["'`]\s*\)"#).expect("valid regex")
});

pub(crate) fn tanstack(ctx: &Ctx) -> Outcome {
    let mut outcome = Outcome::new("tanstack-router");
    for file in ctx.files.with_ext(&["tsx", "ts", "jsx", "js"]) {
        let Some(src) = ctx.source(file) else {
            continue;
        };
        let Some(cap) = CREATE_FILE_ROUTE_RE.captures(&src.text) else {
            continue;
        };
        let line = src.line(cap.get(0).map_or(0, |m| m.start()));
        let segments: Vec<String> = cap[1]
            .split('/')
            .filter(|s| !s.is_empty())
            .filter(|s| !s.starts_with('_') || s.ends_with('_'))
            .filter(|s| !(s.starts_with('(') && s.ends_with(')')))
            .map(|s| {
                let s = s.strip_suffix('_').unwrap_or(s);
                if s == "$" {
                    "*".to_string()
                } else if let Some(inner) = s.strip_prefix("{-$").and_then(|x| x.strip_suffix('}'))
                {
                    format!(":{inner}?")
                } else if let Some(name) = s.strip_prefix('$') {
                    format!(":{name}")
                } else {
                    s.to_string()
                }
            })
            .collect();
        let path = from_segments(segments);
        if paths::is_wildcard_only(&path) {
            continue;
        }
        outcome
            .routes
            .push(Found::new(path, "page", file, line, Origin::Client));
    }
    outcome
}

// ---------------------------------------------------------------- Static HTML

static VITE_BASE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bbase\s*:\s*["'`](/[^"'`]*)["'`]"#).expect("valid regex"));

/// `public/**/*.html` files (served as-is by every dev server) plus, when no
/// router produced routes, the root `index.html` of a Vite or plain static
/// site.
pub(crate) fn static_html(ctx: &Ctx, has_app_routes: bool) -> Outcome {
    let is_vite = ctx.pkg.has("vite");
    let mut outcome = Outcome::new(if is_vite { "vite" } else { "static" });
    if is_vite
        && let Some(cfg) = config_text(ctx, &["vite.config"])
        && let Some(cap) = VITE_BASE_RE.captures(&cfg)
    {
        outcome.base_path = paths::normalize_base(&cap[1]);
    }
    let public = ctx.app_dir.join("public");
    for file in ctx.files.under(&public) {
        if let Some(path) = html_path(&public, file) {
            outcome
                .routes
                .push(Found::new(path, "page", file, 1, Origin::File));
        }
    }
    if !has_app_routes {
        let root_html: Vec<&PathBuf> = ctx
            .files
            .files
            .iter()
            .filter(|f| f.parent() == Some(ctx.app_dir.as_path()))
            .filter(|f| f.extension().is_some_and(|e| e == "html"))
            .collect();
        for file in root_html {
            if let Some(path) = html_path(&ctx.app_dir, file) {
                outcome
                    .routes
                    .push(Found::new(path, "page", file, 1, Origin::File));
            }
        }
    }
    outcome
}

fn html_path(dir: &Path, file: &Path) -> Option<String> {
    let name = file_name(file);
    let (stem, ext) = split_name(&name);
    if !matches!(ext, "html" | "htm") {
        return None;
    }
    let mut segments = rel_dirs(dir, file);
    if stem != "index" {
        segments.push(name.clone());
    }
    Some(from_segments(segments))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remix_ids_convert_to_paths() {
        let p = |id: &str| remix_path("/", &split_route_id(id));
        assert_eq!(p("_index"), "/");
        assert_eq!(p("about"), "/about");
        assert_eq!(p("concerts.$city"), "/concerts/:city");
        assert_eq!(p("concerts._index"), "/concerts");
        assert_eq!(p("_auth.login"), "/login");
        assert_eq!(p("concerts_.mine"), "/concerts/mine");
        assert_eq!(p("files.$"), "/files/*");
        assert_eq!(p("($lang).categories"), "/:lang?/categories");
        assert_eq!(p("sitemap[.]xml"), "/sitemap.xml");
    }
}
