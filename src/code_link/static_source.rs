//! Static fallback: link UI elements to source by searching the codebase for
//! their stable attributes (data-testid, id, aria-label, name, href) and
//! visible text, scoped to files reachable from the route when possible.
//! Used when runtime capture is unavailable (production builds, non-React).
//!
//! Matching runs one Aho-Corasick pass over whitespace-collapsed copies of the
//! source files (so JSX text split across lines still matches). Every hit is
//! classified by its syntactic context and scored:
//!
//! - exact attribute literals (`data-testid="x"`, `id=`, `aria-label=`,
//!   `name=`, `placeholder=`, `href=`/`to=`) rank far above text;
//! - text in a JSX/HTML text node ranks above a string prop, which ranks
//!   above call arguments and object-literal data definitions;
//! - files of the element's route (Next `app/<route>`, Astro
//!   `src/pages/<route>`, SvelteKit, Remix, Next pages), files the route page
//!   imports, and layouts on the route's path get a bonus; pages of other
//!   routes get a penalty.
//!
//! Test, story, and OG-image files and build output are never searched. When
//! several locations tie for the best score the result is `ambiguous`.
//! Needles exceeding the hit budget are omitted: a truncated search cannot
//! establish which source location is best. Other complete needles may still
//! identify the element.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result};
use regex::Regex;

use super::runtime_source::{FileLine, ResolvedSource};

/// One element to link statically.
#[derive(Debug, Clone, Default)]
pub struct StaticQuery {
    pub key: String,
    /// Route template the element was found on (e.g. `/checkout`, `/#/admin`).
    pub route: String,
    pub tag: String,
    pub label: Option<String>,
    pub aria_label: Option<String>,
    pub test_id: Option<String>,
    pub element_id: Option<String>,
    pub name: Option<String>,
    pub href: Option<String>,
    pub placeholder: Option<String>,
    /// Repo-relative file that defines the route (route discovery, may end
    /// in `:line`): for server-rendered apps without file routing, the
    /// strongest hint for where the route's elements render.
    pub route_file: Option<String>,
}

const MAX_FILES: usize = 8_000;
const MAX_FILE_BYTES: u64 = 1_000_000;
const MAX_HITS_PER_NEEDLE: usize = 400;
const MAX_CANDIDATES: usize = 4;
const MIN_NEEDLE_LEN: usize = 2;
const MAX_LABEL_LEN: usize = 160;
const MAX_IMPORT_CLOSURE: usize = 400;
const IMPORT_DEPTH: usize = 3;
/// Candidates within this many points of the best one make it ambiguous.
const AMBIGUITY_MARGIN: i32 = 6;

const SOURCE_EXTENSIONS: &[&str] = &[
    "tsx", "jsx", "ts", "js", "vue", "svelte", "astro", "mdx", "html", "erb", "haml", "slim",
    "jinja", "jinja2", "twig", "php", "jsp", "cshtml", "razor", "hbs", "ejs", "pug",
];

const SERVER_TEMPLATE_EXTENSIONS: &[&str] = &[
    "erb", "haml", "slim", "jinja", "jinja2", "twig", "php", "jsp", "cshtml", "razor", "hbs",
    "ejs", "pug",
];

const SKIP_DIRS: &[&str] = &[
    ".astro",
    ".brokenapp",
    ".cache",
    ".git",
    ".next",
    ".nuxt",
    ".output",
    ".storybook",
    ".svelte-kit",
    ".turbo",
    ".vercel",
    "__mocks__",
    "__tests__",
    "build",
    "coverage",
    "cypress",
    "dist",
    "e2e",
    "fixtures",
    "node_modules",
    "out",
    "playwright-report",
    "storybook-static",
    "target",
    "test",
    "test-results",
    "tests",
    "vendor",
];

/// Returns best-effort matches keyed by `StaticQuery::key`, with
/// `method = "static"` and confidence `probable`/`guess`/`ambiguous`.
pub fn link_static_sources(
    codebase: &Path,
    queries: &[StaticQuery],
) -> Result<BTreeMap<String, ResolvedSource>> {
    let mut out = BTreeMap::new();
    if queries.is_empty() {
        return Ok(out);
    }
    let files = load_source_files(codebase)
        .with_context(|| format!("collect source files under {}", codebase.display()))?;
    if files.is_empty() {
        return Ok(out);
    }
    let index = Index::build(files, queries);
    let mut closures = RouteClosures::default();
    for (qi, query) in queries.iter().enumerate() {
        if let Some(resolved) = index.resolve(qi, query, &mut closures) {
            out.insert(query.key.clone(), resolved);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

struct SourceFile {
    rel: String,
    /// Whitespace-collapsed text used for matching.
    text: String,
    /// `(collapsed_offset, original_offset)` breakpoints, ascending.
    breaks: Vec<(u32, u32)>,
    /// Original byte offsets of line starts.
    line_starts: Vec<u32>,
    route: FileRoute,
    /// Source-relative paths proven by local import resolution (including
    /// declared workspace packages). These are context, never runtime proof.
    imports: Vec<String>,
    import_specs: Vec<String>,
    fallback_import_specs: Vec<String>,
}

impl SourceFile {
    fn new(rel: String, original: &str) -> Self {
        let (text, breaks) = collapse_whitespace(original);
        let mut line_starts = vec![0u32];
        line_starts.extend(
            original
                .bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| (i + 1) as u32),
        );
        let route = FileRoute::of(&rel);
        Self {
            rel,
            text,
            breaks,
            line_starts,
            route,
            imports: Vec::new(),
            import_specs: static_module_specifiers(original),
            fallback_import_specs: Vec::new(),
        }
    }

    /// 1-based (line, col) in the original file for a collapsed offset.
    fn position(&self, collapsed: usize) -> (u32, u32) {
        let c = collapsed as u32;
        let idx = self.breaks.partition_point(|(cb, _)| *cb <= c);
        let original = idx
            .checked_sub(1)
            .map_or(c, |i| self.breaks[i].1 + (c - self.breaks[i].0));
        let line_idx = self
            .line_starts
            .partition_point(|start| *start <= original)
            .saturating_sub(1);
        let line_start = self.line_starts.get(line_idx).copied().unwrap_or(0);
        (line_idx as u32 + 1, original - line_start + 1)
    }
}

/// Collapse whitespace runs to a single space, keeping breakpoints to map
/// offsets back to the original text.
fn collapse_whitespace(original: &str) -> (String, Vec<(u32, u32)>) {
    let bytes = original.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut breaks = vec![(0u32, 0u32)];
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
            let start = i;
            while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
                i += 1;
            }
            out.push(b' ');
            if i - start > 1 {
                // The next collapsed byte maps to the end of the run.
                breaks.push((out.len() as u32, i as u32));
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    // Only ASCII whitespace bytes were replaced, so UTF-8 stays valid.
    (String::from_utf8_lossy(&out).into_owned(), breaks)
}

fn load_source_files(codebase: &Path) -> Result<Vec<SourceFile>> {
    let mut rels = git_ls_files(codebase).unwrap_or_else(|| walk_files(codebase));
    rels.retain(|rel| is_candidate_file(rel));
    rels.sort();
    rels.dedup();
    rels.truncate(MAX_FILES);

    let mut files = Vec::with_capacity(rels.len());
    for rel in rels {
        let path = codebase.join(&rel);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        files.push(SourceFile::new(rel, &text));
    }
    add_workspace_sources(codebase, &mut files);
    resolve_local_imports(codebase, &mut files);
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    files.dedup_by(|a, b| a.rel == b.rel);
    // A `routes/` directory is only file-routed for some frameworks
    // (SvelteKit `+page`, TanStack `__root`, Remix `app/routes`). Server
    // route modules (Hono/Express `src/routes/pages.tsx`) say nothing about
    // which page a file renders.
    let rels: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
    let routed = file_routed_dirs(&rels);
    for f in &mut files {
        if f.rel.starts_with("../") {
            continue;
        }
        if let Some(dir) = routes_dir(&f.rel)
            && !routed.contains(&dir)
        {
            f.route = FileRoute {
                segs: None,
                kind: RouteFileKind::Colocated,
            };
        } else if routes_dir(&f.rel)
            .is_some_and(|d| routed.contains(&d) && !d.ends_with("app/routes"))
        {
            f.route = FileRoute::of_flat(&f.rel);
        }
    }
    Ok(files)
}

/// Resolve only declared packages in the enclosing workspace. Never walk
/// parent repositories or node_modules as a fallback for a missing owner.
struct WorkspacePackage {
    root: PathBuf,
    manifest: serde_json::Value,
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn workspace_packages(codebase: &Path) -> Vec<WorkspacePackage> {
    let Ok(app) = codebase.canonicalize() else {
        return Vec::new();
    };
    let Some(app_manifest) = read_json(&app.join("package.json")) else {
        return Vec::new();
    };
    for root in app.ancestors().skip(1).take(4) {
        let Some(manifest) = read_json(&root.join("package.json")) else {
            continue;
        };
        let Some(ws) = manifest.get("workspaces") else {
            continue;
        };
        let Some(patterns) = ws
            .as_array()
            .or_else(|| ws.get("packages").and_then(|v| v.as_array()))
        else {
            continue;
        };
        let mut available = BTreeMap::new();
        for pattern in patterns.iter().filter_map(|v| v.as_str()) {
            let pattern = pattern.trim_start_matches("./").trim_end_matches('/');
            if pattern.starts_with('/') || pattern.split('/').any(|s| s == "..") {
                continue;
            }
            let dirs: Vec<PathBuf> = if let Some(parent) = pattern.strip_suffix("/*") {
                if parent.contains('*') {
                    continue;
                }
                std::fs::read_dir(root.join(parent))
                    .into_iter()
                    .flatten()
                    .flatten()
                    .take(128)
                    .map(|e| e.path())
                    .collect()
            } else if !pattern.contains('*') {
                vec![root.join(pattern)]
            } else {
                continue;
            };
            for path in dirs {
                let Ok(path) = path.canonicalize() else {
                    continue;
                };
                if !path.starts_with(root) {
                    continue;
                }
                let Some(json) = read_json(&path.join("package.json")) else {
                    continue;
                };
                let Some(name) = json.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                available.insert(
                    name.to_string(),
                    WorkspacePackage {
                        root: path,
                        manifest: json,
                    },
                );
            }
        }
        if !available.values().any(|p| p.root == app) {
            continue;
        }
        let dependencies = |json: &serde_json::Value| -> Vec<String> {
            ["dependencies", "peerDependencies", "optionalDependencies"]
                .into_iter()
                .filter_map(|key| json.get(key).and_then(|v| v.as_object()))
                .flat_map(|m| m.keys().cloned())
                .collect()
        };
        let mut queue: VecDeque<String> = dependencies(&app_manifest).into();
        let mut seen = HashSet::new();
        let mut selected = Vec::new();
        while let Some(name) = queue.pop_front() {
            if selected.len() >= 32 {
                break;
            }
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some(package) = available.remove(&name) else {
                continue;
            };
            queue.extend(dependencies(&package.manifest));
            if package.root != app {
                selected.push(package);
            }
        }
        return selected;
    }
    Vec::new()
}

fn relative_source_path(base: &Path, path: &Path) -> Option<String> {
    let base = base.canonicalize().ok()?;
    let path = path.canonicalize().ok()?;
    let common = base.ancestors().find(|p| path.starts_with(p))?;
    let mut rel = PathBuf::new();
    for _ in base.strip_prefix(common).ok()?.components() {
        rel.push("..");
    }
    rel.push(path.strip_prefix(common).ok()?);
    Some(rel.to_string_lossy().replace('\\', "/"))
}

fn add_workspace_sources(codebase: &Path, files: &mut Vec<SourceFile>) {
    for package in workspace_packages(codebase) {
        let mut paths = git_ls_files(&package.root).unwrap_or_else(|| walk_files(&package.root));
        paths.retain(|p| is_candidate_file(p));
        paths.sort();
        for path in paths {
            if files.len() >= MAX_FILES {
                return;
            }
            let path = package.root.join(path);
            let Some(rel) = relative_source_path(codebase, &path) else {
                continue;
            };
            if !path
                .canonicalize()
                .is_ok_and(|p| p.starts_with(&package.root))
            {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if meta.len() > MAX_FILE_BYTES {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let mut file = SourceFile::new(rel, &text);
            // A dependency's src/pages folder is not this app's route tree.
            file.route.segs = None;
            files.push(file);
        }
    }
}

/// A package export pointing at compiled JS may be traced back through its
/// explicit TypeScript rootDir/outDir pair. No conventional src/dist guess.
fn package_entry(package: &WorkspacePackage, spec: &str) -> Option<PathBuf> {
    let name = package.manifest.get("name")?.as_str()?;
    let suffix = spec.strip_prefix(name)?;
    if !suffix.is_empty() && !suffix.starts_with('/') {
        return None;
    }
    let key = if suffix.is_empty() {
        ".".to_string()
    } else {
        format!(".{suffix}")
    };
    let mut value = if let Some(exports) = package.manifest.get("exports") {
        if let Some(entry) = exports.get(&key) {
            entry
        } else if key == "."
            && (exports.is_string()
                || exports
                    .as_object()
                    .is_some_and(|m| !m.keys().any(|k| k.starts_with('.'))))
        {
            exports
        } else {
            return None;
        }
    } else if key == "." {
        package
            .manifest
            .get("source")
            .or_else(|| package.manifest.get("module"))
            .or_else(|| package.manifest.get("main"))?
    } else {
        return None;
    };
    while value.is_object() {
        value = value
            .get("source")
            .or_else(|| value.get("import"))
            .or_else(|| value.get("default"))?;
    }
    let target = value
        .as_str()?
        .strip_prefix("./")
        .unwrap_or(value.as_str()?);
    if target.starts_with('/') || target.split('/').any(|s| s == "..") {
        return None;
    }
    let config = read_json(&package.root.join("tsconfig.json"));
    let opts = config.as_ref().and_then(|v| v.get("compilerOptions"));
    let source_target = opts
        .and_then(|o| Some((o.get("outDir")?.as_str()?, o.get("rootDir")?.as_str()?)))
        .and_then(|(out, src)| {
            Path::new(target)
                .strip_prefix(out)
                .ok()
                .map(|rest| Path::new(src).join(rest))
        });
    let target = source_target.unwrap_or_else(|| PathBuf::from(target));
    let resolver = crate::route_discovery::ImportResolver::load(&package.root);
    let found = resolver
        .resolve(
            &package.root.join("package.json"),
            &format!("./{}", target.display()),
        )?
        .canonicalize()
        .ok()?;
    found.starts_with(&package.root).then_some(found)
}

fn resolve_local_imports(codebase: &Path, files: &mut [SourceFile]) {
    let packages = workspace_packages(codebase);
    let app_resolver = crate::route_discovery::ImportResolver::load(codebase);
    let package_resolvers: Vec<_> = packages
        .iter()
        .map(|p| crate::route_discovery::ImportResolver::load(&p.root))
        .collect();
    let known: HashMap<PathBuf, String> = files
        .iter()
        .filter_map(|f| Some((codebase.join(&f.rel).canonicalize().ok()?, f.rel.clone())))
        .collect();
    let mut package_targets: HashMap<String, Option<PathBuf>> = HashMap::new();
    for file in files {
        let from = codebase.join(&file.rel);
        let package_index = from
            .canonicalize()
            .ok()
            .and_then(|path| packages.iter().position(|p| path.starts_with(&p.root)));
        let resolver = package_index.map_or(&app_resolver, |i| &package_resolvers[i]);
        let module_root = package_index.map_or(codebase, |i| packages[i].root.as_path());
        let configured = ["tsconfig.json", "tsconfig.app.json", "jsconfig.json"]
            .iter()
            .any(|name| module_root.join(name).is_file());
        for spec in &file.import_specs {
            let target = resolver.resolve(&from, spec).or_else(|| {
                package_targets
                    .entry(spec.to_string())
                    .or_insert_with(|| packages.iter().find_map(|p| package_entry(p, spec)))
                    .clone()
            });
            if let Some(target) = target {
                if let Some(rel) = target.canonicalize().ok().and_then(|p| known.get(&p)) {
                    file.imports.push(rel.clone());
                }
            } else if !configured {
                file.fallback_import_specs.push(spec.clone());
            }
        }
    }
}

/// The `.../routes` directory a file sits under when that is its routing root.
fn routes_dir(rel: &str) -> Option<String> {
    let parts: Vec<&str> = rel.split('/').collect();
    let (_, dirs) = parts.split_last()?;
    let root_idx = dirs
        .iter()
        .take(5)
        .rposition(|d| matches!(*d, "app" | "pages" | "routes"))?;
    (dirs[root_idx] == "routes").then(|| dirs[..=root_idx].join("/"))
}

/// `routes/` directories that use file-based routing.
fn file_routed_dirs(rels: &[&str]) -> HashSet<String> {
    let mut out = HashSet::new();
    for rel in rels {
        let Some(dir) = routes_dir(rel) else {
            continue;
        };
        let file = rel.rsplit('/').next().unwrap_or(rel);
        let stem = file.split('.').next().unwrap_or(file);
        if dir == "app/routes"
            || dir.ends_with("/app/routes")
            || stem.starts_with("+page")
            || stem.starts_with("+layout")
            || stem.starts_with("+server")
            || stem == "__root"
        {
            out.insert(dir);
        }
    }
    out
}

/// Tracked plus untracked-but-not-ignored files (honours `.gitignore`).
fn git_ls_files(codebase: &Path) -> Option<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(codebase)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Some(
        text.split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// Fallback when the codebase is not a git checkout.
fn walk_files(codebase: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![codebase.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if file_type.is_dir() {
                if !SKIP_DIRS.contains(&name.as_ref()) && !name.starts_with('.') {
                    stack.push(path);
                }
            } else if file_type.is_file()
                && let Ok(rel) = path.strip_prefix(codebase)
            {
                out.push(rel.to_string_lossy().replace('\\', "/"));
                if out.len() > MAX_FILES * 4 {
                    return out;
                }
            }
        }
    }
    out
}

fn is_candidate_file(rel: &str) -> bool {
    let mut segments: Vec<&str> = rel.split('/').collect();
    let Some(name) = segments.pop() else {
        return false;
    };
    if segments.iter().any(|seg| SKIP_DIRS.contains(seg)) {
        return false;
    }
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    if !SOURCE_EXTENSIONS.contains(&ext) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    let skipped_infix = [
        ".spec.",
        ".test.",
        ".stories.",
        ".story.",
        ".e2e.",
        ".cy.",
        ".config.",
        ".min.",
    ];
    if skipped_infix.iter().any(|infix| lower.contains(infix)) || lower.ends_with(".d.ts") {
        return false;
    }
    let skipped_prefix = [
        "opengraph-image",
        "twitter-image",
        "apple-icon",
        "icon.",
        "sitemap.",
        "robots.",
        "manifest.",
    ];
    !(skipped_prefix.iter().any(|p| lower.starts_with(p)) || stem.is_empty())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteFileKind {
    Page,
    Layout,
    /// A non-route file inside a route directory (Next colocation).
    Colocated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileRoute {
    /// Route segments (`*` = dynamic, `**` = catch-all), or `None` when the
    /// file is not under a routing root.
    segs: Option<Vec<String>>,
    kind: RouteFileKind,
}

const PAGE_STEMS: &[&str] = &["page", "+page", "index", "_index", "route"];
const LAYOUT_STEMS: &[&str] = &[
    "layout",
    "+layout",
    "_layout",
    "template",
    "_app",
    "_document",
    "root",
];

impl FileRoute {
    /// Route of a file under a TanStack-style flat `routes/` directory
    /// (`routes/posts.$postId.tsx`), wherever that directory is.
    fn of_flat(rel: &str) -> Self {
        let route = Self::of(rel);
        if route.segs.as_ref().is_some_and(|s| !s.is_empty())
            || route.kind != RouteFileKind::Colocated
        {
            return route;
        }
        let file = rel.rsplit('/').next().unwrap_or(rel);
        let full_stem = file.rsplit_once('.').map_or(file, |(s, _)| s);
        if full_stem.starts_with("__") {
            return Self {
                segs: Some(Vec::new()),
                kind: RouteFileKind::Layout,
            };
        }
        Self {
            segs: Some(
                full_stem
                    .split('.')
                    .filter_map(normalize_route_segment)
                    .collect(),
            ),
            kind: RouteFileKind::Page,
        }
    }

    fn of(rel: &str) -> Self {
        let none = Self {
            segs: None,
            kind: RouteFileKind::Colocated,
        };
        let parts: Vec<&str> = rel.split('/').collect();
        let Some((file, dirs)) = parts.split_last() else {
            return none;
        };
        let ext = file.rsplit_once('.').map_or("", |(_, e)| e);
        if SERVER_TEMPLATE_EXTENSIONS.contains(&ext) {
            return none;
        }
        // Last routing root among the first few directories (`routes` inside
        // Remix `app/` wins over `app`).
        let Some(root_idx) = dirs
            .iter()
            .take(5)
            .rposition(|d| matches!(*d, "app" | "pages" | "routes"))
        else {
            return none;
        };
        let root = dirs[root_idx];
        // Rails `app/views/...` and Django `app/templates/...` are server
        // templates, not Next.js App Router pages.
        if root == "app"
            && dirs
                .get(root_idx + 1)
                .is_some_and(|d| matches!(*d, "views" | "templates"))
        {
            return none;
        }
        let stem = file.split('.').next().unwrap_or(file);
        let full_stem = file.rsplit_once('.').map_or(*file, |(s, _)| s);
        let mut raw: Vec<&str> = dirs[root_idx + 1..].to_vec();
        let kind = if PAGE_STEMS.contains(&stem) {
            RouteFileKind::Page
        } else if LAYOUT_STEMS.contains(&stem) {
            RouteFileKind::Layout
        } else if root == "pages" {
            // Next pages router / Astro / Nuxt: every file is a route.
            raw.push(full_stem);
            RouteFileKind::Page
        } else if root == "routes"
            && raw.is_empty()
            && !stem.starts_with('+')
            && root_idx > 0
            && dirs[root_idx - 1] == "app"
        {
            // Remix / React Router flat routes: `app/routes/checkout.$id.tsx`.
            raw.extend(full_stem.split('.'));
            RouteFileKind::Page
        } else {
            // Next app router colocation, SvelteKit components next to
            // `+page.svelte`, Remix nested-route helpers.
            RouteFileKind::Colocated
        };
        let segs = raw
            .into_iter()
            .filter_map(normalize_route_segment)
            .collect();
        Self {
            segs: Some(segs),
            kind,
        }
    }
}

/// Normalize one path segment: drop groups/slots/private/pathless segments,
/// map dynamic segments to `*` and catch-alls to `**`.
fn normalize_route_segment(seg: &str) -> Option<String> {
    let seg = seg.trim();
    if seg.is_empty()
        || seg == "index"
        || seg == "_index"
        || seg.starts_with('(')
        || seg.starts_with('@')
        || seg.starts_with('_')
    {
        return None;
    }
    if seg.starts_with("[...") || seg.starts_with("[[...") || seg == "$" || seg == "*" {
        return Some("**".to_string());
    }
    if (seg.starts_with('[') && seg.ends_with(']'))
        || seg.starts_with('$')
        || seg.starts_with(':')
        || (seg.starts_with('{') && seg.ends_with('}'))
    {
        return Some("*".to_string());
    }
    Some(seg.to_ascii_lowercase())
}

/// Route segments for a query route (`/checkout/[id]`, `/#/admin`, `*`).
fn query_route_segments(route: &str) -> Option<Vec<String>> {
    let route = route.trim();
    if route.is_empty() || route == "*" {
        return None;
    }
    let route = route.split(['?']).next().unwrap_or(route);
    let route = route.trim_start_matches('/');
    let route = route.strip_prefix("#").unwrap_or(route);
    Some(
        route
            .split('/')
            .filter_map(normalize_route_segment)
            .collect(),
    )
}

fn route_segments_match(file: &[String], route: &[String]) -> bool {
    let mut i = 0;
    while i < file.len() {
        if file[i] == "**" {
            return true;
        }
        let Some(r) = route.get(i) else {
            return false;
        };
        if file[i] != "*" && r != "*" && r != "**" && file[i] != *r {
            return false;
        }
        i += 1;
    }
    i == route.len()
}

fn is_route_prefix(file: &[String], route: &[String]) -> bool {
    file.len() <= route.len() && route_segments_match(file, &route[..file.len()])
}

/// Per-route bonus sets: files imported (transitively) by the route's pages
/// and by layouts on its path.
#[derive(Default)]
struct RouteClosures {
    by_route: HashMap<Vec<String>, (HashSet<usize>, HashSet<usize>)>,
    imports: HashMap<usize, Vec<usize>>,
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AttrKind {
    TestId,
    Id,
    Aria,
    Name,
    Placeholder,
    Href,
}

impl AttrKind {
    fn base_score(self) -> i32 {
        match self {
            Self::TestId => 100,
            Self::Id => 90,
            Self::Aria => 85,
            Self::Name => 75,
            Self::Placeholder => 72,
            Self::Href => 70,
        }
    }

    /// Accepts a normalized (lowercase, no `-`/`_`) attribute or prop name.
    fn accepts(self, name: &str) -> bool {
        match self {
            Self::TestId => matches!(
                name,
                "datatestid" | "testid" | "datacy" | "datatest" | "dataqa" | "datatestsubj"
            ),
            Self::Id => name == "id",
            Self::Aria => name == "arialabel",
            Self::Name => name == "name",
            Self::Placeholder => name == "placeholder",
            Self::Href => matches!(name, "href" | "to"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NeedleUse {
    Attr(AttrKind),
    Text,
    /// Shortened label (e.g. `Remove` for `Remove Apples`, from `Remove {it}`).
    TextPrefix,
}

/// `(file index, 1-based line)`.
type LocationKey = (usize, u32);
/// `(score, 1-based column, strong)` of the best hit at a location.
type LocationScore = (i32, u32, bool);

/// One classified needle occurrence for a query.
struct Hit {
    fi: usize,
    line: u32,
    col: u32,
    score: i32,
    strong: bool,
    /// `None` for label text, `Some(kind)` for attribute literals.
    evidence: Option<AttrKind>,
    needle: usize,
}

/// Context classification of a hit.
struct HitClass {
    score: i32,
    /// The context alone is strong evidence of the render site (JSX/HTML
    /// attribute or text node), as opposed to data definitions and strings.
    strong: bool,
}

struct Index {
    files: Vec<SourceFile>,
    /// Per query: `(needle id, use)`.
    query_needles: Vec<Vec<(usize, NeedleUse)>>,
    needles: Vec<String>,
    /// Per needle: `(file index, collapsed start offset)`.
    hits: Vec<Vec<(usize, usize)>>,
    /// More matches existed than the budget retained. Never rank that prefix
    /// as if it were the complete candidate set.
    saturated: Vec<bool>,
}

impl Index {
    fn build(files: Vec<SourceFile>, queries: &[StaticQuery]) -> Self {
        let mut needles: Vec<String> = Vec::new();
        let mut needle_ids: HashMap<String, usize> = HashMap::new();
        let mut query_needles = Vec::with_capacity(queries.len());
        for query in queries {
            let mut uses = Vec::new();
            for (needle, use_) in query_needles_for(query) {
                let id = *needle_ids.entry(needle.clone()).or_insert_with(|| {
                    needles.push(needle);
                    needles.len() - 1
                });
                if !uses.contains(&(id, use_)) {
                    uses.push((id, use_));
                }
            }
            query_needles.push(uses);
        }

        let mut hits = vec![Vec::new(); needles.len()];
        let mut saturated = vec![false; needles.len()];
        if !needles.is_empty()
            && let Ok(ac) = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(&needles)
        {
            for (fi, file) in files.iter().enumerate() {
                for m in ac.find_overlapping_iter(&file.text) {
                    let needle_id = m.pattern().as_usize();
                    let slot = &mut hits[needle_id];
                    if slot.len() < MAX_HITS_PER_NEEDLE {
                        slot.push((fi, m.start()));
                    } else {
                        saturated[needle_id] = true;
                    }
                }
            }
        }
        Self {
            files,
            query_needles,
            needles,
            hits,
            saturated,
        }
    }

    fn resolve(
        &self,
        qi: usize,
        query: &StaticQuery,
        closures: &mut RouteClosures,
    ) -> Option<ResolvedSource> {
        let route = query_route_segments(&query.route);
        let tag = query.tag.to_ascii_lowercase();
        let route_file = query
            .route_file
            .as_deref()
            .map(|f| f.split(':').next().unwrap_or(f))
            .and_then(|f| self.files.iter().position(|x| x.rel == f));
        let route_file_closure = route_file
            .map(|fi| self.import_closure(&[fi], &mut closures.imports))
            .unwrap_or_default();
        // A known route/import context is a boundary, not merely a ranking
        // bonus. A button in an unrelated page cannot establish this owner.
        let mut scope = route_file_closure.clone();
        scope.extend(route_file);
        if let Some(route) = route.as_deref() {
            let (pages, layouts) = self.closures_for(route, closures);
            scope.extend(pages);
            scope.extend(layouts);
            scope.extend(self.files.iter().enumerate().filter_map(|(fi, f)| {
                let segs = f.route.segs.as_ref()?;
                ((f.route.kind == RouteFileKind::Page && route_segments_match(segs, route))
                    || (f.route.kind == RouteFileKind::Layout && is_route_prefix(segs, route)))
                .then_some(fi)
            }));
        }
        let public_route = route
            .as_deref()
            .is_some_and(|r| r.first().is_none_or(|s| s != "admin"));
        let mut hits: Vec<Hit> = Vec::new();
        let mut text_found = false;

        let mut uses = self.query_needles[qi].clone();
        // Prefix variants only count when the full label found nothing.
        uses.sort_by_key(|(_, u)| matches!(u, NeedleUse::TextPrefix));
        for (needle_id, use_) in uses {
            if self.saturated[needle_id] {
                // A saturated full-label search is incomplete, not absent.
                // Do not use that omission to fall back to a shorter label.
                text_found |= use_ == NeedleUse::Text;
                continue;
            }
            if use_ == NeedleUse::TextPrefix && text_found {
                continue;
            }
            let needle = &self.needles[needle_id];
            for &(fi, start) in &self.hits[needle_id] {
                if !scope.is_empty() && !scope.contains(&fi) {
                    continue;
                }
                let file = &self.files[fi];
                let Some(class) = classify_hit(&file.text, start, needle, use_, &tag) else {
                    continue;
                };
                if use_ == NeedleUse::Text {
                    text_found = true;
                }
                let mut affinity = route
                    .as_deref()
                    .map_or(0, |r| self.route_affinity(fi, r, closures));
                if route_file == Some(fi) {
                    affinity = affinity.max(25);
                } else if route_file_closure.contains(&fi) {
                    affinity = affinity.max(12);
                }
                // Admin screens do not render public pages.
                if public_route && file.rel.split('/').any(|seg| seg == "admin") {
                    affinity -= 8;
                }
                let (line, col) = file.position(start);
                hits.push(Hit {
                    fi,
                    line,
                    col,
                    score: class.score + affinity,
                    strong: class.strong,
                    evidence: match use_ {
                        NeedleUse::Attr(kind) => Some(kind),
                        NeedleUse::Text | NeedleUse::TextPrefix => None,
                    },
                    needle: needle_id,
                });
            }
        }
        if hits.is_empty() {
            return None;
        }

        // Corroboration: a different needle of a different kind (label text
        // + href, testid + label, ...) close by makes a location much more
        // likely to be the element itself.
        hits.sort_by_key(|h| (h.fi, h.line));
        let mut best: HashMap<LocationKey, LocationScore> = HashMap::new();
        for (i, hit) in hits.iter().enumerate() {
            let near = |o: &&Hit| o.fi == hit.fi && o.line.abs_diff(hit.line) <= 10;
            let bonus = hits[..i]
                .iter()
                .rev()
                .take_while(near)
                .chain(hits[i + 1..].iter().take_while(near))
                .filter(|o| o.needle != hit.needle && o.evidence != hit.evidence)
                .map(|o| {
                    if o.line.abs_diff(hit.line) <= 3 {
                        30
                    } else {
                        15
                    }
                })
                .max()
                .unwrap_or(0);
            let score = hit.score + bonus;
            let entry = best
                .entry((hit.fi, hit.line))
                .or_insert((i32::MIN, hit.col, false));
            if score > entry.0 {
                *entry = (score, hit.col, hit.strong);
            }
        }

        let mut ranked: Vec<(LocationKey, LocationScore)> = best.into_iter().collect();
        ranked.sort_by(|a, b| {
            b.1.0
                .cmp(&a.1.0)
                .then_with(|| self.files[a.0.0].rel.cmp(&self.files[b.0.0].rel))
                .then_with(|| a.0.1.cmp(&b.0.1))
        });
        // Near-ties (route/import bonuses are weak signals) are ambiguous.
        let top_score = ranked[0].1.0;
        let tied = ranked
            .iter()
            .filter(|(_, (s, _, _))| *s >= top_score - AMBIGUITY_MARGIN)
            .count();
        let confidence = if tied > 1 {
            "ambiguous"
        } else if ranked[0].1.2 {
            "probable"
        } else {
            "guess"
        };
        let to_file_line = |((fi, line), (_, col, _)): &(LocationKey, LocationScore)| FileLine {
            file: self.files[*fi].rel.clone(),
            line: *line,
            col: *col,
        };
        Some(ResolvedSource {
            render: Some(to_file_line(&ranked[0])),
            caller: None,
            handler: None,
            method: "static".to_string(),
            confidence: confidence.to_string(),
            candidates: ranked
                .iter()
                .skip(1)
                .take(MAX_CANDIDATES)
                .map(to_file_line)
                .collect(),
        })
    }

    fn route_affinity(&self, fi: usize, route: &[String], closures: &mut RouteClosures) -> i32 {
        let file_route = &self.files[fi].route;
        let mut score = 0;
        if let Some(segs) = &file_route.segs {
            match file_route.kind {
                RouteFileKind::Page if route_segments_match(segs, route) => return 25,
                RouteFileKind::Colocated if route_segments_match(segs, route) => return 18,
                RouteFileKind::Layout if is_route_prefix(segs, route) => score = 6,
                RouteFileKind::Page => return -20,
                _ => {}
            }
        }
        let (page_closure, layout_closure) = self.closures_for(route, closures);
        if page_closure.contains(&fi) {
            score = score.max(12);
        } else if layout_closure.contains(&fi) {
            score = score.max(6);
        }
        score
    }

    fn closures_for<'a>(
        &self,
        route: &[String],
        closures: &'a mut RouteClosures,
    ) -> &'a (HashSet<usize>, HashSet<usize>) {
        if !closures.by_route.contains_key(route) {
            let mut pages = Vec::new();
            let mut layouts = Vec::new();
            for (fi, file) in self.files.iter().enumerate() {
                let Some(segs) = &file.route.segs else {
                    continue;
                };
                match file.route.kind {
                    RouteFileKind::Page if route_segments_match(segs, route) => pages.push(fi),
                    RouteFileKind::Layout if is_route_prefix(segs, route) => layouts.push(fi),
                    _ => {}
                }
            }
            let page_closure = self.import_closure(&pages, &mut closures.imports);
            let layout_closure = self.import_closure(&layouts, &mut closures.imports);
            closures
                .by_route
                .insert(route.to_vec(), (page_closure, layout_closure));
        }
        &closures.by_route[route]
    }

    fn import_closure(
        &self,
        roots: &[usize],
        cache: &mut HashMap<usize, Vec<usize>>,
    ) -> HashSet<usize> {
        let mut seen: HashSet<usize> = roots.iter().copied().collect();
        let mut queue: VecDeque<(usize, usize)> = roots.iter().map(|&r| (r, 0)).collect();
        while let Some((fi, depth)) = queue.pop_front() {
            if depth >= IMPORT_DEPTH || seen.len() >= MAX_IMPORT_CLOSURE {
                continue;
            }
            let imports = cache
                .entry(fi)
                .or_insert_with(|| self.resolve_imports(fi))
                .clone();
            for target in imports {
                if seen.insert(target) {
                    queue.push_back((target, depth + 1));
                }
            }
        }
        for root in roots {
            seen.remove(root);
        }
        seen
    }

    fn resolve_imports(&self, fi: usize) -> Vec<usize> {
        let file = &self.files[fi];
        let dir = file.rel.rsplit_once('/').map_or("", |(d, _)| d);
        let mut out: Vec<usize> = file
            .imports
            .iter()
            .filter_map(|path| self.files.iter().position(|f| f.rel == *path))
            .collect();
        for spec in file.fallback_import_specs.iter().map(String::as_str) {
            for base in import_bases(dir, spec) {
                if let Some(target) = self.find_module(&base) {
                    if !out.contains(&target) {
                        out.push(target);
                    }
                    break;
                }
            }
        }
        out
    }

    fn find_module(&self, base: &str) -> Option<usize> {
        let exact = self.files.binary_search_by(|f| f.rel.as_str().cmp(base));
        if let Ok(i) = exact {
            return Some(i);
        }
        for ext in SOURCE_EXTENSIONS {
            for candidate in [format!("{base}.{ext}"), format!("{base}/index.{ext}")] {
                if let Ok(i) = self
                    .files
                    .binary_search_by(|f| f.rel.as_str().cmp(candidate.as_str()))
                {
                    return Some(i);
                }
            }
        }
        None
    }
}

/// Static owner context must not be established by import examples inside
/// comments or string literals. Keep the public changed-route scanner's
/// contract separate; this filter only narrows attribution evidence.
fn static_module_specifiers(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut code = vec![true; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i..].starts_with(b"//") {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i..].starts_with(b"/*") {
            i += 2;
            while i + 1 < bytes.len() && !bytes[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else if matches!(bytes[i], b'\'' | b'"' | b'`') {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == quote {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            i += 1;
            continue;
        }
        code[start..i].fill(false);
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"'\s]+)["']"#)
            .unwrap()
    })
    .captures_iter(text)
    .filter(|c| code[c.get(0).unwrap().start()])
    .map(|c| c[1].to_string())
    .collect()
}

/// Module specifiers a source file imports, in order: `import ... from
/// "x"`, side-effect `import "./styles.css"`, dynamic `import("x")` and
/// `require("x")`. Also used by `map --changed` to find the routes a
/// changed file reaches.
pub(crate) fn module_specifiers(text: &str) -> Vec<&str> {
    static IMPORT_RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(re) = IMPORT_RE
        .get_or_init(|| {
            Regex::new(r#"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"'\s]+)["']"#)
                .ok()
        })
        .as_ref()
    else {
        return Vec::new();
    };
    re.captures_iter(text)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str()))
        .collect()
}

/// Candidate repo-relative module paths (without extension) for an import
/// from a file in `dir`: relative specifiers, and the `@/`, `~/`, `$lib/`
/// and `src/` aliases.
pub(crate) fn import_bases(dir: &str, spec: &str) -> Vec<String> {
    let spec = spec.split('?').next().unwrap_or(spec);
    if spec.starts_with("./") || spec.starts_with("../") {
        return normalize_rel(&format!("{dir}/{spec}"))
            .into_iter()
            .collect();
    }
    let aliases: &[(&str, &[&str])] = &[
        ("@/", &["src/", ""]),
        ("~/", &["src/", "app/", ""]),
        ("$lib/", &["src/lib/"]),
        ("src/", &["src/"]),
    ];
    for (prefix, targets) in aliases {
        if let Some(rest) = spec.strip_prefix(prefix) {
            return targets
                .iter()
                .filter_map(|t| normalize_rel(&format!("{t}{rest}")))
                .collect();
        }
    }
    Vec::new()
}

fn normalize_rel(path: &str) -> Option<String> {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            seg => out.push(seg),
        }
    }
    (!out.is_empty()).then(|| out.join("/"))
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Strip a selector wrapper (`[data-testid="x"]`, `#x`) to the raw value.
fn raw_attr_value(value: &str) -> String {
    let v = value.trim();
    if let Some(inner) = v.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Some((_, rhs)) = inner.split_once('=')
    {
        return rhs.trim().trim_matches(['"', '\'']).to_string();
    }
    v.strip_prefix('#').unwrap_or(v).to_string()
}

/// Framework-generated ids are not in source.
fn is_generated_id(id: &str) -> bool {
    let lower = id.to_ascii_lowercase();
    if lower.contains(":r")
        || lower.starts_with("radix-")
        || lower.starts_with("headlessui-")
        || lower.starts_with("react-aria")
        || lower.starts_with("mui-")
        || lower.starts_with("rc-")
        || lower.starts_with("__")
    {
        return true;
    }
    let digits = id.chars().filter(char::is_ascii_digit).count();
    let mut run = 0;
    let mut max_run = 0;
    for c in id.chars() {
        run = if c.is_ascii_digit() { run + 1 } else { 0 };
        max_run = max_run.max(run);
    }
    max_run >= 4 || (id.len() >= 8 && digits * 3 >= id.len())
}

fn query_needles_for(query: &StaticQuery) -> Vec<(String, NeedleUse)> {
    let mut out = Vec::new();
    let mut push_attr = |value: Option<&String>, kind: AttrKind| {
        let Some(value) = value else {
            return;
        };
        let raw = raw_attr_value(value);
        if raw.len() < MIN_NEEDLE_LEN || raw.len() > MAX_LABEL_LEN || raw.contains(['"', '\n']) {
            return;
        }
        if kind == AttrKind::Id && is_generated_id(&raw) {
            return;
        }
        if kind == AttrKind::Href
            && (raw == "#" || raw.to_ascii_lowercase().starts_with("javascript:"))
        {
            return;
        }
        out.push((raw, NeedleUse::Attr(kind)));
    };
    push_attr(query.test_id.as_ref(), AttrKind::TestId);
    push_attr(query.element_id.as_ref(), AttrKind::Id);
    push_attr(query.aria_label.as_ref(), AttrKind::Aria);
    push_attr(query.name.as_ref(), AttrKind::Name);
    push_attr(query.placeholder.as_ref(), AttrKind::Placeholder);
    push_attr(query.href.as_ref(), AttrKind::Href);

    if let Some(label) = query.label.as_deref().map(collapse)
        && label.chars().count() >= MIN_NEEDLE_LEN
        && label.len() <= MAX_LABEL_LEN
        && label.chars().any(char::is_alphanumeric)
    {
        let trimmed = label
            .trim_matches(|c: char| !c.is_alphanumeric() && !matches!(c, ')' | '!' | '?' | '.'))
            .to_string();
        if trimmed != label && trimmed.len() >= MIN_NEEDLE_LEN {
            out.push((trimmed.clone(), NeedleUse::Text));
        }
        let words: Vec<&str> = trimmed.split(' ').collect();
        // JSX/HTML sources often spell typographic characters as entities.
        let encoded = encode_entities(&label);
        if encoded != label {
            out.push((encoded, NeedleUse::Text));
        }
        out.push((label, NeedleUse::Text));
        // `Remove Apples` rendered from `Remove {item}`; long card text.
        let prefix_len = if trimmed.len() > 40 {
            words.len().min(3)
        } else {
            words.len().saturating_sub(1)
        };
        if prefix_len >= 1 && prefix_len < words.len() {
            let prefix = words[..prefix_len].join(" ");
            if prefix.len() >= 4 {
                out.push((prefix, NeedleUse::TextPrefix));
            }
        }
    }
    out
}

/// The label as it would be written with HTML entities (`&amp;`, `&rsquo;`).
fn encode_entities(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '\u{2019}' => out.push_str("&rsquo;"),
            '\u{2018}' => out.push_str("&lsquo;"),
            '\u{201C}' => out.push_str("&ldquo;"),
            '\u{201D}' => out.push_str("&rdquo;"),
            '\u{2014}' => out.push_str("&mdash;"),
            '\u{2013}' => out.push_str("&ndash;"),
            '\u{00A0}' => out.push_str("&nbsp;"),
            '\u{00A9}' => out.push_str("&copy;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Classify a hit by its context in collapsed text.
fn classify_hit(
    text: &str,
    start: usize,
    needle: &str,
    use_: NeedleUse,
    tag: &str,
) -> Option<HitClass> {
    let end = start + needle.len();
    let bytes = text.as_bytes();
    if end > bytes.len() {
        return None;
    }
    let before = &text[..start];
    let after = &text[end..];
    match use_ {
        NeedleUse::Attr(kind) => {
            // Attribute values are case-sensitive.
            if &text[start..end] != needle {
                return None;
            }
            let quote = *before.as_bytes().last()?;
            if !matches!(quote, b'"' | b'\'' | b'`') || after.as_bytes().first() != Some(&quote) {
                return None;
            }
            let (name, assign) = attr_name_before(&before[..before.len() - 1])?;
            if !kind.accepts(&name) {
                return None;
            }
            let context = control_context(before, tag);
            if assign == b'=' && context == ControlContext::Incompatible {
                return None;
            }
            let mut score = kind.base_score();
            if assign == b':' {
                // Object literal (`{ href: "/x" }`): a data definition, not the
                // render site.
                score -= 25;
            }
            Some(HitClass {
                score,
                strong: assign == b'=' && context == ControlContext::Compatible,
            })
        }
        NeedleUse::Text | NeedleUse::TextPrefix => {
            let prev = before.trim_end_matches(' ').as_bytes().last().copied();
            let next = after.trim_start_matches(' ').as_bytes().first().copied();
            let prefix_penalty = if use_ == NeedleUse::TextPrefix { 15 } else { 0 };
            let tag_bonus = if opening_tag_matches(before, tag) {
                8
            } else {
                0
            };
            // Matching is ASCII case-insensitive (CSS text-transform changes
            // innerText); exact case is a tie-breaker.
            let case_bonus = if &text[start..end] == needle { 5 } else { 0 };
            // Word boundaries: never match inside a longer word.
            let boundary_ok = !before
                .as_bytes()
                .last()
                .is_some_and(|b| b.is_ascii_alphanumeric())
                && !after
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_alphanumeric());
            if !boundary_ok {
                return None;
            }
            // JSX / HTML / server template text node, or Markdown link text.
            let before_trimmed = before.trim_end_matches(' ');
            let after_trimmed = after.trim_start_matches(' ');
            let template_wrapped = (before_trimmed.ends_with("%}")
                || before_trimmed.ends_with("}}"))
                && (after_trimmed.starts_with("{%") || after_trimmed.starts_with("{{"));
            let razor_interpolated = matches!(prev, Some(b'>')) && after.starts_with(" @");
            let text_node = (matches!(prev, Some(b'>')) && matches!(next, Some(b'<' | b'{')))
                || (matches!(prev, Some(b'>' | b'}')) && matches!(next, Some(b'<')))
                || template_wrapped
                || razor_interpolated
                || (matches!(prev, Some(b'[')) && matches!(next, Some(b']')));
            if text_node {
                let context = control_context(before, tag);
                if context == ControlContext::Incompatible {
                    return None;
                }
                return Some(HitClass {
                    score: 60 + tag_bonus + case_bonus - prefix_penalty,
                    strong: use_ == NeedleUse::Text && context == ControlContext::Compatible,
                });
            }
            if use_ == NeedleUse::TextPrefix {
                // Prefixes are only trusted in text nodes (`Remove {item}`).
                return None;
            }
            // String literal: same quote on both sides.
            let quote = *before.as_bytes().last()?;
            if !matches!(quote, b'"' | b'\'' | b'`') || after.as_bytes().first() != Some(&quote) {
                return None;
            }
            let lead = before[..before.len() - 1]
                .trim_end_matches([' ', '{'])
                .as_bytes()
                .last()
                .copied();
            let score = match lead {
                Some(b'=') => 50,
                Some(b'(' | b',' | b'[') => 35,
                Some(b':' | b'?') => 30,
                _ => 25,
            };
            Some(HitClass {
                score: score + tag_bonus + case_bonus,
                strong: false,
            })
        }
    }
}

/// Parse backwards from just before an attribute value's opening quote:
/// `name="`, `name={"`, `"name": "`, `name: '`. Returns the normalized name
/// (lowercase, `-`/`_` removed) and the assignment byte (`=` or `:`).
fn attr_name_before(before: &str) -> Option<(String, u8)> {
    let rest = before.trim_end_matches(' ');
    let rest = rest.strip_suffix('{').unwrap_or(rest).trim_end_matches(' ');
    let assign = *rest.as_bytes().last()?;
    if !matches!(assign, b'=' | b':') {
        return None;
    }
    let rest = rest[..rest.len() - 1].trim_end_matches(' ');
    let rest = rest.trim_end_matches(['"', '\'']);
    let name_start = rest
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '$' | ':')))
        .map_or(0, |i| i + 1);
    let name = &rest[name_start..];
    // Vue/Svelte bindings (`:href`, `bind:value`) keep the last part.
    let name = name.rsplit(':').next().unwrap_or(name);
    if name.is_empty() {
        return None;
    }
    let normalized: String = name
        .chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    Some((normalized, assign))
}

/// The lightweight markup check does not prove what an arbitrary custom
/// component renders. Keep those sites weak; native controls, explicit roles
/// and conventional control components can corroborate the captured DOM tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlContext {
    Compatible,
    Incompatible,
    Unknown,
}

fn control_context(before: &str, tag: &str) -> ControlContext {
    if !matches!(tag, "button" | "a" | "input" | "select" | "textarea") {
        return ControlContext::Unknown;
    }
    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let re = TAG_RE.get_or_init(|| {
        Regex::new(r#"<(/?)([A-Za-z][\w:.-]*)\b((?:"[^"]*(?:"|$)|'[^']*(?:'|$)|<%.*?%>|<\?.*?\?>|[^'"<>])*)(?:>|$)"#)
            .unwrap()
    });
    // Bound each lookup. A missing ancestor lowers confidence; it never
    // authorizes a repo-wide owner guess.
    let start = before.len().saturating_sub(4096);
    let start = (start..=before.len())
        .find(|&i| before.is_char_boundary(i))
        .unwrap();
    let mut stack: Vec<(String, String)> = Vec::new();
    for cap in re.captures_iter(&before[start..]) {
        let name = cap[2].to_string();
        if &cap[1] == "/" {
            if let Some(i) = stack.iter().rposition(|(n, _)| *n == name) {
                stack.truncate(i);
            }
        } else {
            let attrs = cap[3].to_string();
            // The final opening tag can still be incomplete at an attribute
            // value hit, and must participate in compatibility checking.
            if !attrs.trim_end().ends_with('/') {
                stack.push((name, attrs));
            }
        }
    }
    if stack
        .iter()
        .any(|(name, _)| matches!(name.as_str(), "svg" | "text" | "title" | "desc"))
    {
        return ControlContext::Incompatible;
    }
    let mut custom = false;
    for (name, attrs) in stack.iter().rev() {
        let lower = name.to_ascii_lowercase();
        let compatible = match tag {
            "a" => lower == "a" || lower.ends_with("link"),
            "button" => lower.ends_with("button"),
            "input" => lower.ends_with("input"),
            "select" => lower.ends_with("select"),
            "textarea" => lower.ends_with("textarea"),
            _ => false,
        };
        if compatible {
            return ControlContext::Compatible;
        }
        if matches!(
            lower.as_str(),
            "button" | "a" | "input" | "select" | "textarea"
        ) {
            return ControlContext::Incompatible;
        }
        if attrs.contains(&format!("role=\"{tag}\"")) || attrs.contains(&format!("role='{tag}'")) {
            return ControlContext::Compatible;
        }
        if tag == "button" && (attrs.contains("onClick=") || attrs.contains("onclick=")) {
            return ControlContext::Compatible;
        }
        custom |= name.starts_with(char::is_uppercase);
    }
    if stack.is_empty() || custom {
        ControlContext::Unknown
    } else {
        ControlContext::Incompatible
    }
}

/// Whether the nearest preceding opening tag (within 200 bytes) matches the
/// element tag (`<button`, `<Button`, `<SubmitButton`, `<a`, `<Link`, …).
fn opening_tag_matches(before: &str, tag: &str) -> bool {
    if tag.is_empty() {
        return false;
    }
    let window_start = before.len().saturating_sub(200);
    let window_start = (window_start..before.len())
        .find(|i| before.is_char_boundary(*i))
        .unwrap_or(before.len());
    let window = &before[window_start..];
    let mut search_end = window.len();
    let after_lt = loop {
        let Some(lt) = window[..search_end].rfind('<') else {
            return false;
        };
        let rest = &window[lt + 1..];
        // Skip server template tags (`<%`, `<?`) and HTML comments/doctypes (`<!`)
        // embedded inside an opening tag.
        if rest.starts_with(['%', '?', '!']) {
            search_end = lt;
            continue;
        }
        break rest;
    };
    if after_lt.starts_with('/') {
        return false;
    }
    let name: String = after_lt
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let lower = name.to_ascii_lowercase();
    match tag {
        "a" => lower == "a" || lower.ends_with("link"),
        "button" => lower.ends_with("button"),
        "input" => lower.ends_with("input"),
        "select" => lower.ends_with("select"),
        "textarea" => lower.ends_with("textarea"),
        other => lower == other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (rel, body) in files {
            let p = dir.path().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
        dir
    }

    fn q(key: &str, route: &str, tag: &str) -> StaticQuery {
        StaticQuery {
            key: key.into(),
            route: route.into(),
            tag: tag.into(),
            ..Default::default()
        }
    }

    #[test]
    fn svg_navigation_illustrations_are_not_control_owners() {
        let dir = tree(&[
            (
                "src/app/portal/account/page.tsx",
                "export default () => <p>Account</p>",
            ),
            (
                "src/app/portal/layout.tsx",
                "import { Demo } from '../../components/demo';\nimport { nav } from './nav';\nexport default () => <Demo />",
            ),
            (
                "src/components/demo.tsx",
                "export const Demo = () => <svg><text>Home</text><text>Test a device</text></svg>",
            ),
            (
                "src/app/portal/nav.tsx",
                "export const nav = [{ label: 'Home' }, { label: 'Test a device' }];",
            ),
        ]);
        for label in ["Home", "Test a device"] {
            let out = link_static_sources(
                dir.path(),
                &[StaticQuery {
                    label: Some(label.into()),
                    ..q("nav", "/portal/account", "button")
                }],
            )
            .unwrap();
            let source = &out["nav"];
            assert_eq!(
                source.confidence, "guess",
                "a data definition is not a render owner"
            );
            assert_eq!(
                source.render.as_ref().unwrap().file,
                "src/app/portal/nav.tsx"
            );
            assert!(
                source
                    .candidates
                    .iter()
                    .all(|c| !c.file.ends_with("demo.tsx"))
            );
        }
        let only_svg = tree(&[(
            "src/app/page.tsx",
            "export default () => <svg><text>Test a device</text></svg>",
        )]);
        assert!(
            link_static_sources(
                only_svg.path(),
                &[StaticQuery {
                    label: Some("Test a device".into()),
                    ..q("nav", "/", "button")
                }]
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn route_context_does_not_borrow_an_unrelated_review_button() {
        let dir = tree(&[
            (
                "app/receiving/page.tsx",
                "import './workspace';\n// import '../sell/page';\nconst example = \"import '../sell/page'\";\nexport default () => <Workspace />",
            ),
            (
                "app/receiving/workspace.tsx",
                "export const Workspace = () => <button>Review</button>",
            ),
            (
                "app/sell/page.tsx",
                "export default () => <button data-testid='review-sale'>Review</button>",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[StaticQuery {
                label: Some("Review".into()),
                test_id: Some("review-sale".into()),
                ..q("review", "/receiving", "button")
            }],
        )
        .unwrap();
        assert_eq!(
            out["review"].render.as_ref().unwrap().file,
            "app/receiving/workspace.tsx"
        );
        assert!(out["review"].candidates.is_empty());
        assert!(
            link_static_sources(
                dir.path(),
                &[StaticQuery {
                    test_id: Some("review-sale".into()),
                    ..q("missing", "/receiving", "button")
                }]
            )
            .unwrap()
            .is_empty(),
            "missing route evidence stays unknown"
        );
    }

    #[test]
    fn nested_and_custom_controls_keep_compatible_evidence() {
        let dir = tree(&[(
            "app/page.tsx",
            concat!(
                "export default () => <section>\n",
                "<button><span>Nested save</span></button>\n",
                "<Action onClick={save}>Custom save</Action>\n",
                "<SubmitButton>Submit save</SubmitButton>\n",
                "<Tile>Unknown render</Tile>\n",
                "<p aria-label='Decorative label'>Decoration</p>\n",
                "</section>"
            ),
        )]);
        let queries: Vec<_> = [
            "Nested save",
            "Custom save",
            "Submit save",
            "Unknown render",
        ]
        .into_iter()
        .map(|label| StaticQuery {
            label: Some(label.into()),
            ..q(label, "/", "button")
        })
        .collect();
        let out = link_static_sources(dir.path(), &queries).unwrap();
        for label in ["Nested save", "Custom save", "Submit save"] {
            assert_eq!(out[label].confidence, "probable", "{label}");
        }
        assert_eq!(out["Unknown render"].confidence, "guess");
        assert!(
            link_static_sources(
                dir.path(),
                &[StaticQuery {
                    aria_label: Some("Decorative label".into()),
                    ..q("decoration", "/", "button")
                }]
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn explicit_alias_does_not_also_add_a_guessed_source_directory() {
        let dir = tree(&[
            (
                "tsconfig.json",
                r#"{"compilerOptions":{"paths":{"@/*":["lib/*"]}}}"#,
            ),
            (
                "app/page.tsx",
                "import Action from '@/Action';\nexport default () => <Action />",
            ),
            (
                "lib/Action.tsx",
                "export default () => <button>Review</button>",
            ),
            (
                "src/Action.tsx",
                "export default () => <button data-testid='review'>Review</button>",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[StaticQuery {
                label: Some("Review".into()),
                test_id: Some("review".into()),
                ..q("review", "/", "button")
            }],
        )
        .unwrap();
        assert_eq!(
            out["review"].render.as_ref().unwrap().file,
            "lib/Action.tsx"
        );
        assert!(out["review"].candidates.is_empty());
    }

    #[test]
    fn package_exports_are_authoritative_over_legacy_main() {
        let dir = tree(&[
            (
                "src/actual.tsx",
                "export const Actual = () => <button>Review</button>",
            ),
            (
                "src/old.tsx",
                "export const Old = () => <button>Review</button>",
            ),
        ]);
        let package = |manifest| WorkspacePackage {
            // workspace_packages canonicalizes roots before package_entry receives them.
            root: dir.path().canonicalize().unwrap(),
            manifest,
        };
        let resolved = package_entry(&package(serde_json::json!({
            "name":"@demo/seller", "exports":{"default":"./src/actual.tsx"}, "main":"./src/old.tsx"
        })), "@demo/seller").unwrap();
        assert_eq!(
            resolved,
            dir.path().join("src/actual.tsx").canonicalize().unwrap()
        );
        for exports in [
            serde_json::json!({"./other":"./src/actual.tsx"}),
            serde_json::Value::Null,
        ] {
            assert!(
                package_entry(
                    &package(serde_json::json!({
                        "name":"@demo/seller", "exports":exports, "main":"./src/old.tsx"
                    })),
                    "@demo/seller"
                )
                .is_none()
            );
        }
    }

    #[test]
    fn declared_workspace_sources_follow_exports_and_keep_shared_candidates() {
        let dir = tree(&[
            ("package.json", r#"{"workspaces":["apps/*","packages/*"]}"#),
            (
                "apps/web/package.json",
                r#"{"name":"web","dependencies":{"@demo/seller":"*"}}"#,
            ),
            (
                "apps/web/src/app/orders/page.tsx",
                "import { ShipmentSetup } from '@demo/seller';\nexport default () => <ShipmentSetup />",
            ),
            (
                "packages/seller/package.json",
                r#"{"name":"@demo/seller","exports":{".":{"import":"./dist/index.js"}}}"#,
            ),
            (
                "packages/seller/tsconfig.json",
                r#"{"compilerOptions":{"outDir":"dist","rootDir":"src"}}"#,
            ),
            (
                "packages/seller/src/index.ts",
                "export { ShipmentSetup } from './ShipmentSetup.js';",
            ),
            (
                "packages/seller/src/ShipmentSetup.tsx",
                "export const ShipmentSetup = () => <>\n<button>Save tracking</button>\n<button>Save tracking</button>\n<input name='trackingCode' />\n</>",
            ),
            (
                "packages/unrelated/package.json",
                r#"{"name":"@demo/unrelated"}"#,
            ),
            (
                "packages/unrelated/src/Wrong.tsx",
                "export const Wrong = () => <button>Save tracking</button>",
            ),
        ]);
        let out = link_static_sources(
            &dir.path().join("apps/web"),
            &[
                StaticQuery {
                    label: Some("Save tracking".into()),
                    ..q("tracking", "/orders", "button")
                },
                StaticQuery {
                    name: Some("trackingCode".into()),
                    ..q("field", "/orders", "input")
                },
            ],
        )
        .unwrap();
        let shared = &out["tracking"];
        assert_eq!(shared.confidence, "ambiguous");
        assert_eq!(
            shared.render.as_ref().unwrap().file,
            "../../packages/seller/src/ShipmentSetup.tsx"
        );
        assert_eq!(shared.candidates.len(), 1);
        assert_eq!(
            shared.candidates[0].file,
            shared.render.as_ref().unwrap().file
        );
        assert_eq!(out["field"].confidence, "probable");
        assert_eq!(out["field"].render.as_ref().unwrap().line, 4);
    }

    #[test]
    fn collapses_whitespace_and_maps_positions_back() {
        let original = "a\n  <button>\n    Get\n    started\n  </button>\n";
        let file = SourceFile::new("x.tsx".into(), original);
        assert_eq!(file.text, "a <button> Get started </button> ");
        let start = file.text.find("Get started").unwrap();
        assert_eq!(file.position(start), (3, 5));
        assert_eq!(file.position(0), (1, 1));
        let close = file.text.find("</button>").unwrap();
        assert_eq!(file.position(close), (5, 3));
    }

    #[test]
    fn excludes_tests_stories_og_images_and_build_output() {
        for rel in [
            "tests/checkout.spec.ts",
            "src/app/opengraph-image.tsx",
            "src/components/Button.stories.tsx",
            "e2e/flow.ts",
            "src/__tests__/a.tsx",
            ".next/server/app/page.js",
            "node_modules/x/index.js",
            "src/app/icon.tsx",
            "vite.config.ts",
            "src/types.d.ts",
            "README.md",
        ] {
            assert!(!is_candidate_file(rel), "{rel}");
        }
        for rel in [
            "src/app/page.tsx",
            "src/pages/index.astro",
            "src/routes/+page.svelte",
            "docs/guide.mdx",
            "public/index.html",
            "app/views/orders/show.html.erb",
            "resources/views/checkout.blade.php",
            "templates/cart.jinja2",
            "Views/Checkout/Index.cshtml",
            "WEB-INF/views/checkout.jsp",
            "templates/order.html.twig",
            "views/invoice.hbs",
            "views/invoice.ejs",
            "views/invoice.pug",
            "app/views/orders/index.html.haml",
            "app/views/orders/index.html.slim",
            "Components/Checkout.razor",
        ] {
            assert!(is_candidate_file(rel), "{rel}");
        }
    }

    #[test]
    fn derives_file_routes_for_common_frameworks() {
        let cases = [
            (
                "src/app/(shop)/checkout/[id]/page.tsx",
                Some(vec!["checkout", "*"]),
                RouteFileKind::Page,
            ),
            ("app/layout.tsx", Some(vec![]), RouteFileKind::Layout),
            (
                "app/settings/profile-form.tsx",
                Some(vec!["settings"]),
                RouteFileKind::Colocated,
            ),
            (
                "src/pages/about.astro",
                Some(vec!["about"]),
                RouteFileKind::Page,
            ),
            (
                "src/pages/blog/index.astro",
                Some(vec!["blog"]),
                RouteFileKind::Page,
            ),
            (
                "pages/products/[id].tsx",
                Some(vec!["products", "*"]),
                RouteFileKind::Page,
            ),
            (
                "src/routes/cart/+page.svelte",
                Some(vec!["cart"]),
                RouteFileKind::Page,
            ),
            (
                "app/routes/checkout.$id.tsx",
                Some(vec!["checkout", "*"]),
                RouteFileKind::Page,
            ),
            ("app/routes/_index.tsx", Some(vec![]), RouteFileKind::Page),
        ];
        for (rel, segs, kind) in cases {
            let route = FileRoute::of(rel);
            assert_eq!(
                route.segs,
                segs.map(|v| v.into_iter().map(String::from).collect::<Vec<_>>()),
                "{rel}"
            );
            assert_eq!(route.kind, kind, "{rel}");
        }
        assert_eq!(FileRoute::of("src/components/Header.tsx").segs, None);
        // Only `app/routes` is a Remix flat-route directory.
        assert_eq!(
            FileRoute::of("src/routes/pages.tsx").kind,
            RouteFileKind::Colocated
        );
        assert_eq!(
            FileRoute::of_flat("src/routes/posts.$postId.tsx").segs,
            Some(vec!["posts".to_string(), "*".to_string()])
        );
        assert_eq!(
            query_route_segments("/#/admin/users"),
            Some(vec!["admin".to_string(), "users".to_string()])
        );
        assert_eq!(query_route_segments("*"), None);
        assert!(route_segments_match(
            &["checkout".into(), "*".into()],
            &["checkout".into(), "[orderid]".into()]
                .map(|s: String| { normalize_route_segment(&s).unwrap() })
        ));
    }

    #[test]
    fn attribute_literals_rank_first_and_tests_are_ignored() {
        let dir = tree(&[
            (
                "src/pages/Cart.tsx",
                "export function Cart() {\n  return (\n    <section>\n      <Button testId=\"checkout-cta\" onClick={go}>\n        Checkout\n      </Button>\n      <p>Checkout</p>\n    </section>\n  )\n}\n",
            ),
            (
                "tests/cart.spec.ts",
                "await page.getByTestId('checkout-cta').click(); // data-testid=\"checkout-cta\"\n",
            ),
            (
                "src/components/ui/Button.tsx",
                "export const Button = (p) => <button data-testid={p.testId}>{p.children}</button>\n",
            ),
        ]);
        let mut query = q("cta", "/cart", "button");
        query.test_id = Some("[data-testid=\"checkout-cta\"]".into());
        query.label = Some("Checkout".into());
        let out = link_static_sources(dir.path(), &[query]).unwrap();
        let src = &out["cta"];
        assert_eq!(src.method, "static");
        assert_eq!(src.confidence, "probable");
        let render = src.render.as_ref().unwrap();
        assert_eq!(
            (render.file.as_str(), render.line),
            ("src/pages/Cart.tsx", 4)
        );
        assert!(src.candidates.iter().all(|c| !c.file.starts_with("tests/")));
    }

    #[test]
    fn server_route_modules_are_not_file_routes() {
        // Hono-style `src/routes/*.tsx` modules: `pages.tsx` defines /contact,
        // `admin/settings.tsx` has a field with the same label.
        let dir = tree(&[
            (
                "src/routes/pages.tsx",
                "app.get('/contact', (c) => c.html(\n  <form>\n    <label>Message <textarea name=\"message\"></textarea></label>\n  </form>\n))\n",
            ),
            (
                "src/routes/admin/settings.tsx",
                "export const Settings = () => (\n  <label>Message <textarea name=\"message\"></textarea></label>\n)\n",
            ),
        ]);
        let mut query = q("msg", "/contact", "textarea");
        query.name = Some("message".into());
        query.label = Some("Message".into());
        query.route_file = Some("src/routes/pages.tsx:1".into());
        let out = link_static_sources(dir.path(), &[query.clone()]).unwrap();
        let render = out["msg"].render.as_ref().unwrap();
        assert_eq!(
            (render.file.as_str(), render.line),
            ("src/routes/pages.tsx", 3)
        );
        // Without the route file, the admin screen still loses on a public route.
        query.route_file = None;
        let out = link_static_sources(dir.path(), &[query]).unwrap();
        assert_eq!(
            out["msg"].render.as_ref().unwrap().file,
            "src/routes/pages.tsx"
        );
    }

    #[test]
    fn route_scoping_breaks_label_ties() {
        let dir = tree(&[
            (
                "app/settings/page.tsx",
                "export default () => <button>Save</button>\n",
            ),
            (
                "app/profile/page.tsx",
                "export default () => <button>Save</button>\n",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[
                StaticQuery {
                    label: Some("Save".into()),
                    ..q("settings", "/settings", "button")
                },
                StaticQuery {
                    label: Some("Save".into()),
                    ..q("global", "*", "button")
                },
            ],
        )
        .unwrap();
        let settings = &out["settings"];
        assert_eq!(
            settings.render.as_ref().unwrap().file,
            "app/settings/page.tsx"
        );
        assert_eq!(settings.confidence, "probable");
        assert!(
            settings.candidates.is_empty(),
            "other route is outside the context"
        );
        assert_eq!(out["global"].confidence, "ambiguous");
    }

    #[test]
    fn saturated_label_does_not_claim_an_early_unrelated_owner() {
        // Generic names consume the raw-hit budget before a later route's
        // actual button. The sole retained text node used to become probable.
        let early = format!(
            "{}\nexport const other = <span>Review</span>;\n",
            "// reviewData\n".repeat(MAX_HITS_PER_NEEDLE - 1)
        );
        let dir = tree(&[
            ("src/app/sell/bulk-quote-import.tsx", &early),
            (
                "src/app/staff/receiving/workspace/receive-workspace.tsx",
                "export const Receiving = () => <button onClick={selectScan}>Review</button>;\n",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[StaticQuery {
                label: Some("Review".into()),
                ..q("review", "/staff/receiving/workspace", "button")
            }],
        )
        .unwrap();
        assert!(
            !out.contains_key("review"),
            "incomplete search must stay unknown"
        );
    }

    #[test]
    fn complete_attribute_can_resolve_when_the_label_is_saturated() {
        let early = "// reviewData\n".repeat(MAX_HITS_PER_NEEDLE);
        let dir = tree(&[
            ("src/app/sell/data.ts", &early),
            (
                "src/app/staff/receiving/workspace/receive-workspace.tsx",
                "export const Receiving = () => <button data-testid=\"select-receiving-scan\">Review</button>;\n",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[StaticQuery {
                label: Some("Review".into()),
                test_id: Some("select-receiving-scan".into()),
                ..q("review", "/staff/receiving/workspace", "button")
            }],
        )
        .unwrap();
        assert_eq!(out["review"].confidence, "probable");
        assert_eq!(
            out["review"].render.as_ref().unwrap().file,
            "src/app/staff/receiving/workspace/receive-workspace.tsx"
        );
    }

    #[test]
    fn exactly_the_hit_budget_keeps_complete_route_evidence() {
        let early = format!(
            "{}\nexport const other = <span>Review</span>;\n",
            "// reviewData\n".repeat(MAX_HITS_PER_NEEDLE - 2)
        );
        let dir = tree(&[
            ("src/app/sell/bulk-quote-import.tsx", &early),
            (
                "src/app/staff/receiving/workspace/receive-workspace.tsx",
                "export const Receiving = () => <button>Review</button>;\n",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[StaticQuery {
                label: Some("Review".into()),
                ..q("review", "/staff/receiving/workspace", "button")
            }],
        )
        .unwrap();
        assert_eq!(out["review"].confidence, "probable");
        assert_eq!(
            out["review"].render.as_ref().unwrap().file,
            "src/app/staff/receiving/workspace/receive-workspace.tsx"
        );
    }

    #[test]
    fn import_closure_prefers_components_used_by_the_route() {
        let dir = tree(&[
            (
                "app/checkout/page.tsx",
                "import { PayForm } from '@/components/pay-form'\nexport default () => <PayForm />\n",
            ),
            (
                "components/pay-form.tsx",
                "export function PayForm() {\n  return <form><button type=\"submit\">Pay now</button></form>\n}\n",
            ),
            (
                "components/legacy-pay.tsx",
                "export function LegacyPay() {\n  return <button>Pay now</button>\n}\n",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[StaticQuery {
                label: Some("Pay now".into()),
                ..q("pay", "/checkout", "button")
            }],
        )
        .unwrap();
        let src = &out["pay"];
        assert_eq!(src.render.as_ref().unwrap().file, "components/pay-form.tsx");
        assert_eq!(src.confidence, "probable");
        assert!(
            src.candidates.is_empty(),
            "unimported component is not an owner candidate"
        );
    }

    #[test]
    fn text_contexts_multiline_jsx_data_definitions_and_prefixes() {
        let dir = tree(&[
            (
                "src/pages/index.astro",
                "---\nimport Layout from '../layouts/Layout.astro'\n---\n<Layout>\n  <a href=\"/start\" class=\"cta\">\n    Get\n    started\n  </a>\n</Layout>\n",
            ),
            (
                "src/lib/site.ts",
                "export const nav = [\n  { label: \"Computers & IT\", href: \"/it-services\" },\n]\n",
            ),
            (
                "src/components/Cart.tsx",
                "export const Cart = () => items.map((it) => (\n  <button key={it}>\n    Remove {it}\n  </button>\n))\n",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[
                StaticQuery {
                    label: Some("Get started".into()),
                    ..q("start", "/", "a")
                },
                StaticQuery {
                    label: Some("Computers & IT".into()),
                    href: Some("/it-services".into()),
                    ..q("nav", "*", "a")
                },
                StaticQuery {
                    label: Some("Remove Apples".into()),
                    ..q("remove", "/cart", "button")
                },
                StaticQuery {
                    label: Some("Nothing like this".into()),
                    ..q("missing", "/", "button")
                },
            ],
        )
        .unwrap();
        let start = &out["start"];
        let render = start.render.as_ref().unwrap();
        assert_eq!(
            (render.file.as_str(), render.line),
            ("src/pages/index.astro", 6)
        );
        assert_eq!(start.confidence, "probable", "text node in the route page");

        let nav = &out["nav"];
        let render = nav.render.as_ref().unwrap();
        assert_eq!((render.file.as_str(), render.line), ("src/lib/site.ts", 2));
        assert_eq!(
            nav.confidence, "guess",
            "data definition, not a render site"
        );

        let remove = &out["remove"];
        let render = remove.render.as_ref().unwrap();
        assert_eq!(
            (render.file.as_str(), render.line),
            ("src/components/Cart.tsx", 3)
        );

        assert!(!out.contains_key("missing"));
    }

    #[test]
    fn corroborated_label_and_href_beat_href_only_matches() {
        let dir = tree(&[
            (
                "src/app/layout.tsx",
                "import { Footer } from '@/components/footer'\nexport default function Layout({ children }) {\n  return <body>{children}<Footer /></body>\n}\n",
            ),
            (
                "src/app/page.tsx",
                "export default function Home() {\n  return <Link href=\"/contact\">Plan a visit</Link>\n}\n",
            ),
            (
                "src/components/footer.tsx",
                "export function Footer() {\n  return (\n    <nav>\n      <Link href=\"/contact\">Visit &amp; contact</Link>\n    </nav>\n  )\n}\n",
            ),
        ]);
        let out = link_static_sources(
            dir.path(),
            &[StaticQuery {
                label: Some("Visit & contact".into()),
                href: Some("/contact".into()),
                ..q("visit", "/", "a")
            }],
        )
        .unwrap();
        let src = &out["visit"];
        let render = src.render.as_ref().unwrap();
        assert_eq!(
            (render.file.as_str(), render.line),
            ("src/components/footer.tsx", 4)
        );
        assert_eq!(src.confidence, "probable");
        assert_eq!(src.candidates[0].file, "src/app/page.tsx");
    }

    #[test]
    fn attribute_context_parsing() {
        assert_eq!(
            attr_name_before("<button data-testid="),
            Some(("datatestid".into(), b'='))
        );
        assert_eq!(attr_name_before("<a href={"), Some(("href".into(), b'=')));
        assert_eq!(
            attr_name_before("{ 'aria-label': "),
            Some(("arialabel".into(), b':'))
        );
        assert_eq!(attr_name_before("<a :href="), Some(("href".into(), b'=')));
        assert_eq!(attr_name_before("console.log("), None);
        assert!(is_generated_id(":r1:"));
        assert!(is_generated_id("radix-:R2:-content"));
        assert!(is_generated_id("field-12345"));
        assert!(!is_generated_id("email"));
        assert!(!is_generated_id("main-content"));
        assert!(opening_tag_matches(
            "<SubmitButton type=\"submit\">",
            "button"
        ));
        assert!(opening_tag_matches("<Link href=\"/x\">", "a"));
        assert!(!opening_tag_matches("</div> <p>", "button"));
    }

    #[test]
    fn honours_gitignore_when_git_is_available() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tree(&[
            (".gitignore", "generated/\n"),
            (
                "generated/page.tsx",
                "export default () => <button>Ghost</button>\n",
            ),
            (
                "src/app.tsx",
                "export default () => <button>Real</button>\n",
            ),
        ]);
        let init = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .status();
        if !init.is_ok_and(|s| s.success()) {
            return;
        }
        let out = link_static_sources(
            dir.path(),
            &[
                StaticQuery {
                    label: Some("Ghost".into()),
                    ..q("ghost", "/", "button")
                },
                StaticQuery {
                    label: Some("Real".into()),
                    ..q("real", "/", "button")
                },
            ],
        )
        .unwrap();
        assert!(!out.contains_key("ghost"));
        assert!(out.contains_key("real"));
    }

    #[test]
    fn server_templates_resolve_controls_to_exact_file_and_line() {
        let dir = tree(&[
            (
                "app/views/orders/show.html.erb",
                "<section>\n  <h1>Order <%= @order.id %></h1>\n  <button <%= 'disabled' if @order.locked? %> data-testid=\"refund-order\" type=\"submit\">Issue refund</button>\n</section>\n",
            ),
            (
                "templates/checkout.html",
                "<form method=\"post\">\n  <input type=\"email\" name=\"buyer_email\" placeholder=\"you@example.com\" />\n  <button type=\"submit\">{% if express %}Express checkout{% endif %}</button>\n</form>\n",
            ),
            (
                "resources/views/orders/index.blade.php",
                "<main>\n  <a href=\"/orders/new\" class=\"btn\">Create order</a>\n</main>\n",
            ),
            (
                "templates/cart.jinja2",
                "<div>\n  <button type=\"button\">Apply coupon</button>\n</div>\n",
            ),
            (
                "Views/Billing/Index.cshtml",
                "<form>\n  <button type=\"submit\">Download invoice @Model.Number</button>\n</form>\n",
            ),
            (
                "WEB-INF/views/shipping.jsp",
                "<form>\n  <button type=\"submit\">Save shipping address</button>\n</form>\n",
            ),
        ]);

        let queries = vec![
            StaticQuery {
                test_id: Some("refund-order".into()),
                label: Some("Issue refund".into()),
                ..q("rails", "/orders/:id", "button")
            },
            StaticQuery {
                label: Some("Express checkout".into()),
                ..q("django_btn", "/checkout", "button")
            },
            StaticQuery {
                name: Some("buyer_email".into()),
                ..q("django_input", "/checkout", "input")
            },
            StaticQuery {
                label: Some("Create order".into()),
                href: Some("/orders/new".into()),
                ..q("blade", "/orders", "a")
            },
            StaticQuery {
                label: Some("Apply coupon".into()),
                ..q("jinja", "/cart", "button")
            },
            StaticQuery {
                label: Some("Download invoice 42".into()),
                ..q("cshtml", "/billing", "button")
            },
            StaticQuery {
                label: Some("Save shipping address".into()),
                ..q("jsp", "/shipping", "button")
            },
        ];

        let out = link_static_sources(dir.path(), &queries).unwrap();

        let assert_loc = |key: &str, file: &str, line: u32| {
            let src = out
                .get(key)
                .unwrap_or_else(|| panic!("expected match for {key}: {out:#?}"));
            let render = src.render.as_ref().unwrap();
            assert_eq!((render.file.as_str(), render.line), (file, line), "{key}");
            assert_eq!(src.method, "static");
        };

        assert_loc("rails", "app/views/orders/show.html.erb", 3);
        assert_eq!(out["rails"].confidence, "probable");
        assert_loc("django_btn", "templates/checkout.html", 3);
        assert_eq!(out["django_btn"].confidence, "probable");
        assert_loc("django_input", "templates/checkout.html", 2);
        assert_loc("blade", "resources/views/orders/index.blade.php", 2);
        assert_loc("jinja", "templates/cart.jinja2", 2);
        assert_loc("cshtml", "Views/Billing/Index.cshtml", 2);
        assert_loc("jsp", "WEB-INF/views/shipping.jsp", 2);
    }
}
