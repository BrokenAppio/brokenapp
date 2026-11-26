//! Next.js app router (`app/`, `src/app/`) and pages router (`pages/`,
//! `src/pages/`). Also covers vinext (Next app router on Vite).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use super::fs::{self, file_name, rel_dirs};
use super::js::{self, JsSource};
use super::paths::{self, bracket_segment, from_segments};
use super::{Ctx, Found, Origin, Outcome, static_params};

const PAGE_EXTS: &[&str] = &["tsx", "ts", "jsx", "js", "mdx", "md"];
const ROUTE_EXTS: &[&str] = &["ts", "js", "tsx", "jsx", "mjs", "mts"];
const PAGES_ROUTER_EXTS: &[&str] = &["tsx", "ts", "jsx", "js", "mdx"];

static BASE_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bbasePath\s*:\s*["'`](/[^"'`]*)["'`]"#).expect("valid regex"));
static TRAILING_SLASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\btrailingSlash\s*:\s*true\b").expect("valid regex"));
static EXPORT_DEFAULT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bexport\s+default\b").expect("valid regex"));
static REDIRECT_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:redirect|permanentRedirect)\s*\(").expect("valid regex"));

pub(crate) fn discover(ctx: &Ctx) -> Outcome {
    let app_dir = pick_dir(ctx, &["app", "src/app"]);
    let pages_dir = pick_dir(ctx, &["pages", "src/pages"]);

    let mut app_routes = Vec::new();
    if let Some(dir) = &app_dir {
        app_routes = app_router(ctx, dir);
    }
    let mut page_routes = Vec::new();
    if let Some(dir) = &pages_dir {
        page_routes = pages_router(ctx, dir);
    }
    let framework = if app_routes.is_empty() && !page_routes.is_empty() {
        "nextjs-pages"
    } else {
        "nextjs-app"
    };

    let mut outcome = Outcome::new(framework);
    if let Some(cfg) = fs::first_config(&ctx.app_dir, &["next.config"])
        .and_then(|p| fs::read_source(&p))
        .map(|raw| JsSource::new(&raw).text)
    {
        if let Some(cap) = BASE_PATH_RE.captures(&cfg) {
            outcome.base_path = paths::normalize_base(&cap[1]);
        }
        outcome.trailing_slash = TRAILING_SLASH_RE.is_match(&cfg);
    }
    outcome.routes = app_routes;
    outcome.routes.extend(page_routes);
    outcome
}

/// First candidate directory that exists (Next prefers root over `src/`).
fn pick_dir(ctx: &Ctx, candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(|c| ctx.app_dir.join(c))
        .find(|p| p.is_dir())
}

fn is_interception(seg: &str) -> bool {
    seg.starts_with("(.)") || seg.starts_with("(..)") || seg.starts_with("(...)")
}

fn is_group(seg: &str) -> bool {
    seg.starts_with('(') && seg.ends_with(')') && !is_interception(seg)
}

fn split_name(name: &str) -> (&str, &str) {
    name.rsplit_once('.').unwrap_or((name, ""))
}

fn app_router(ctx: &Ctx, dir: &Path) -> Vec<Found> {
    let mut out = Vec::new();
    for file in ctx.files.under(dir) {
        let dirs = rel_dirs(dir, file);
        // Private folders, parallel-route slots and interception routes do
        // not define their own URLs.
        if dirs
            .iter()
            .any(|d| d.starts_with('_') || d.starts_with('@') || is_interception(d))
        {
            continue;
        }
        let name = file_name(file);
        let (stem, ext) = split_name(&name);
        let kind = match stem {
            "page" if PAGE_EXTS.contains(&ext) => "page",
            "route" if ROUTE_EXTS.contains(&ext) => "api",
            "layout" if PAGE_EXTS.contains(&ext) => "layout",
            _ => continue,
        };
        let path = from_segments(
            dirs.iter()
                .filter(|d| !is_group(d))
                .map(|d| bracket_segment(d, false)),
        );
        let src = ctx.source(file);
        let mut found = Found::new(path, kind, file, 1, Origin::File);
        if let Some(src) = &src {
            match kind {
                "api" => {
                    found.methods = exported_methods(src);
                    found.line = first_export_line(src);
                }
                _ => {
                    found.line = default_export_line(src);
                    if kind == "page" && is_redirect_only(src) {
                        found.kind = "redirect";
                    }
                }
            }
            if found.kind == "page" && paths::is_dynamic(&found.path) {
                found.examples =
                    static_params::examples(ctx, file, src, &found.path, &["generateStaticParams"]);
            }
        }
        out.push(found);
    }
    out
}

fn pages_router(ctx: &Ctx, dir: &Path) -> Vec<Found> {
    let mut out = Vec::new();
    for file in ctx.files.under(dir) {
        let dirs = rel_dirs(dir, file);
        let name = file_name(file);
        let (stem, ext) = split_name(&name);
        if !PAGES_ROUTER_EXTS.contains(&ext) {
            continue;
        }
        if dirs.is_empty() && matches!(stem, "_app" | "_document" | "_error" | "_middleware") {
            continue;
        }
        let is_api = dirs.first().is_some_and(|d| d == "api");
        let mut segments: Vec<String> = dirs.iter().map(|d| bracket_segment(d, false)).collect();
        if stem != "index" {
            segments.push(bracket_segment(stem, false));
        }
        let path = from_segments(segments);
        let kind = if is_api { "api" } else { "page" };
        let mut found = Found::new(path, kind, file, 1, Origin::File);
        if let Some(src) = ctx.source(file) {
            found.line = default_export_line(&src);
            if kind == "page" && paths::is_dynamic(&found.path) {
                found.examples =
                    static_params::examples(ctx, file, &src, &found.path, &["getStaticPaths"]);
            }
        }
        out.push(found);
    }
    out
}

static METHOD_EXPORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bexport\s+(?:async\s+)?(?:function\s*\*?\s*|const\s+|let\s+|var\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|get|post|put|patch|delete|del|head|options|ALL|all)\b",
    )
    .expect("valid regex")
});
static EXPORT_LIST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bexport\s*\{([^}]*)\}").expect("valid regex"));

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// HTTP methods exported by a route handler module (`export async function
/// GET`, `export const POST = ...`, `export { handler as GET }`).
pub(crate) fn exported_methods(src: &JsSource) -> BTreeSet<String> {
    let mut methods = BTreeSet::new();
    for cap in METHOD_EXPORT_RE.captures_iter(&src.text) {
        let m = cap[1].to_ascii_uppercase();
        let m = if m == "DEL" { "DELETE".to_string() } else { m };
        if m == "ALL" {
            methods.insert("ALL".to_string());
        } else {
            methods.insert(m);
        }
    }
    for cap in EXPORT_LIST_RE.captures_iter(&src.text) {
        for part in cap[1].split(',') {
            let exported = part.rsplit(" as ").next().unwrap_or(part).trim();
            if HTTP_METHODS.contains(&exported) {
                methods.insert(exported.to_string());
            }
        }
    }
    methods
}

fn first_export_line(src: &JsSource) -> u32 {
    METHOD_EXPORT_RE
        .find(&src.text)
        .map_or(1, |m| src.line(m.start()))
}

pub(crate) fn default_export_line(src: &JsSource) -> u32 {
    EXPORT_DEFAULT_RE
        .find(&src.text)
        .map_or(1, |m| src.line(m.start()))
}

pub(crate) fn has_default_export(src: &JsSource) -> bool {
    EXPORT_DEFAULT_RE.is_match(&src.text)
}

/// A page whose only job is `redirect("/elsewhere")` (no markup).
fn is_redirect_only(src: &JsSource) -> bool {
    REDIRECT_CALL_RE.is_match(&src.text) && !js::has_jsx(&src.text)
}
