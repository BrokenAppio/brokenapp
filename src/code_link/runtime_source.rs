//! Resolve browser-captured element source evidence to repo `file:line`.
//!
//! During discovery the crawler records raw stack frames for each element
//! (React 19 dev `_debugStack` + owner chain, handler locations, Astro dev
//! annotations) in [`crate::types::dom::ElementSourceCapture`]. Those frames
//! point at URLs served by the dev server. This module maps them back to
//! files in the codebase via source maps / dev-server endpoints while the dev
//! server is still running, and derives three sites per element:
//! `render` (first app frame), `caller` (first owner frame in a different
//! file, crossing shared components like `components/ui/*`), and `handler`.
//!
//! Resolution order per frame:
//! 1. Served scripts (`http(s)://…`, Turbopack chunks, Vite modules): fetch the
//!    script, follow its `sourceMappingURL` (inline `data:` or relative URL,
//!    including index maps with sections) and look the position up.
//! 2. Server frames (`about://React/Server/file:///…?N`) and other `file://`
//!    paths: bundles under build dirs (`.next/…`) use the sibling `.map` on disk
//!    or Next's `GET /__nextjs_source-map?filename=`; source files inside the
//!    codebase (vinext / vite-rsc) use `GET /__vite_rsc_findSourceMapURL`, and
//!    fall back to the path itself with an unmapped line.
//! 3. Last resort for Next: `POST /__nextjs_original-stack-frames`.
//!
//! Frames that map into `node_modules`, ignore-listed sources, or files outside
//! the codebase are dropped. Fetches are restricted to the dev server's origin,
//! use short timeouts and a global deadline, and never fail the caller.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::types::dom::{ElementSourceCapture, SourceFrame};
use source_map::SourceMap;

pub(crate) mod source_map;

/// A resolved repo-relative source location.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileLine {
    /// Path relative to the codebase root, `/`-separated.
    pub file: String,
    pub line: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub col: u32,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

/// Where an element lives in source.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ResolvedSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render: Option<FileLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<FileLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<FileLine>,
    /// `runtime`, `annotation`, or `static`.
    pub method: String,
    /// `exact`, `probable`, `guess`, or `ambiguous`.
    pub confidence: String,
    /// Other plausible locations (static matching, duplicates).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<FileLine>,
}

/// One element to resolve.
#[derive(Debug, Clone, Default)]
pub struct SourceQuery {
    /// Caller-chosen key (e.g. the inventory control key).
    pub key: String,
    pub capture: ElementSourceCapture,
    pub page_url: String,
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
/// Upper bound for the whole network phase of one resolve call.
const OVERALL_DEADLINE: Duration = Duration::from_secs(45);
const MAX_BODY_BYTES: usize = 48 * 1024 * 1024;
const MAX_MAP_JOBS: usize = 600;
const FETCH_CONCURRENCY: usize = 8;
const NEXT_FRAMES_BATCH: usize = 50;

/// Resolve captured frames for many elements. Unresolvable elements are
/// omitted from the result. Must not fail the caller on network errors to the
/// dev server: degrade to an empty/partial map.
pub async fn resolve_runtime_sources(
    base_url: &str,
    codebase: &Path,
    queries: &[SourceQuery],
) -> Result<BTreeMap<String, ResolvedSource>> {
    let mut out = BTreeMap::new();
    if queries.is_empty() {
        return Ok(out);
    }
    let root = CodebaseRoot::new(codebase);

    let mut frames: Vec<FrameKey> = Vec::new();
    let mut seen = HashSet::new();
    for query in queries {
        for frame in &query.capture.frames {
            let key = FrameKey::of(frame);
            if seen.insert(key.clone()) {
                frames.push(key);
            }
        }
    }

    let resolutions = if frames.is_empty() {
        HashMap::new()
    } else {
        match FetchCtx::new(base_url, queries) {
            Ok(ctx) => resolve_frames(&ctx, &root, &frames).await,
            Err(err) => {
                tracing::debug!("runtime source resolution disabled: {err:#}");
                HashMap::new()
            }
        }
    };

    for query in queries {
        if let Some(resolved) = derive_resolved_source(&query.capture, &resolutions, &root) {
            out.insert(query.key.clone(), resolved);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Frame identity and classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FrameKey {
    url: String,
    line: u32,
    col: u32,
    env: Option<String>,
}

impl FrameKey {
    fn of(frame: &SourceFrame) -> Self {
        Self {
            url: frame.url.clone(),
            line: frame.line,
            col: frame.col,
            env: frame.env.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum FrameResolution {
    App {
        loc: FileLine,
        exact: bool,
    },
    /// Library / framework / ignore-listed code: skip this frame.
    Library,
    Unresolved,
}

/// Strip React's virtual server-frame prefix:
/// `about://React/<Env>/<url>?<n>` (React 19.1+) or `rsc://React/<Env>/<url>?<n>`
/// becomes `<url>` plus the environment name.
pub(crate) fn normalize_frame_url(url: &str) -> (String, Option<String>) {
    for prefix in ["about://React/", "rsc://React/"] {
        let Some(rest) = url.strip_prefix(prefix) else {
            continue;
        };
        let Some(slash) = rest.find('/') else {
            break;
        };
        let env = &rest[..slash];
        let mut inner = &rest[slash + 1..];
        if let Some(q) = inner.rfind('?')
            && !inner[q + 1..].is_empty()
            && inner[q + 1..].bytes().all(|b| b.is_ascii_digit())
        {
            inner = &inner[..q];
        }
        let env = (!env.is_empty()).then(|| env.to_string());
        return (inner.to_string(), env);
    }
    (url.to_string(), None)
}

#[derive(Debug, Clone, PartialEq)]
enum FrameTarget {
    /// A script served over http(s).
    Script(Url),
    /// A file on disk (React server frames, vite-rsc modules).
    File {
        path: PathBuf,
        env: Option<String>,
    },
    /// Next/webpack dev module id (`webpack-internal:///(layer)/./app/x.tsx`).
    Webpack {
        raw: String,
        rel: Option<String>,
    },
    /// Repo-relative source path reported directly by a runtime hook (e.g.
    /// React 18 `_debugSource.fileName` or Angular `debugInfo.filePath`).
    RelativeFile(String),
    Unsupported,
}

fn classify_frame_url(url: &str) -> FrameTarget {
    let (normalized, env) = normalize_frame_url(url);
    let s = normalized.as_str();
    if s.starts_with("file://") {
        return match Url::parse(s).ok().and_then(|u| u.to_file_path().ok()) {
            Some(path) => FrameTarget::File { path, env },
            None => FrameTarget::Unsupported,
        };
    }
    if s.starts_with('/') && !s.starts_with("//") {
        return FrameTarget::File {
            path: PathBuf::from(s),
            env,
        };
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return match Url::parse(s) {
            Ok(u) => FrameTarget::Script(u),
            Err(_) => FrameTarget::Unsupported,
        };
    }
    if s.starts_with("webpack-internal://") || s.starts_with("webpack://") {
        return FrameTarget::Webpack {
            raw: s.to_string(),
            rel: strip_bundler_prefix(s).filter(|r| !is_library_path(r)),
        };
    }
    if !s.is_empty()
        && !s.contains("://")
        && !s.starts_with('<')
        && (s.contains('/') || s.contains('\\'))
    {
        return FrameTarget::RelativeFile(s.to_string());
    }
    FrameTarget::Unsupported
}

/// Scripts whose URL already says they are library code (no fetch needed).
fn is_library_script(url: &Url) -> bool {
    let path = percent_decode(url.path());
    let file = path.rsplit('/').next().unwrap_or("");
    path.contains("/node_modules/")
        || path.contains("/.vite/deps/")
        || path.starts_with("/@vite/")
        || path.starts_with("/@react-refresh")
        || path.starts_with("/@id/")
        || file.starts_with("node_modules_")
        || file.starts_with("[turbopack]")
        || file.starts_with("[externals]")
}

fn is_library_path(rel: &str) -> bool {
    rel.split('/').any(|seg| seg == "node_modules")
        || rel.starts_with("[turbopack]")
        || rel.starts_with("[externals]")
        || rel.starts_with("next/dist/")
        || rel.starts_with("webpack/")
        || rel.starts_with("(webpack)")
}

/// Build output / cache directories whose files are bundles that need a map.
fn is_build_path(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some(".next" | ".vite" | ".svelte-kit" | ".output" | ".turbo" | ".vercel" | ".nuxt")
        )
    })
}

/// Shared design-system components are skipped when picking the caller site.
fn is_shared_component(file: &str) -> bool {
    file.split('/')
        .any(|seg| matches!(seg, "ui" | "primitives" | "design-system"))
}

/// Strip webpack/turbopack virtual prefixes to a project-relative path.
fn strip_bundler_prefix(s: &str) -> Option<String> {
    let rest = if let Some(rest) = s.strip_prefix("webpack-internal:///") {
        // `(app-pages-browser)/./app/page.tsx`
        match rest.strip_prefix('(').and_then(|r| r.split_once(")/")) {
            Some((_, after)) => after,
            None => rest,
        }
    } else if let Some(rest) = s.strip_prefix("webpack://") {
        // `_N_E/./app/page.tsx`, `/./src/x.tsx`, `app/./src/x.tsx`
        match rest.find("/./") {
            Some(i) => &rest[i + 3..],
            None => rest.trim_start_matches('/'),
        }
    } else if let Some(rest) = s.strip_prefix("turbopack:///") {
        rest.strip_prefix("[project]/").unwrap_or(rest)
    } else {
        s.strip_prefix("[project]/")?
    };
    let rest = strip_query(rest.trim_start_matches("./"));
    (!rest.is_empty()).then(|| rest.to_string())
}

fn strip_query(s: &str) -> &str {
    let end = s.find(['?', '#']).unwrap_or(s.len());
    &s[..end]
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Codebase-relative path mapping
// ---------------------------------------------------------------------------

/// The codebase root in its given and canonical forms (macOS maps `/tmp` to
/// `/private/tmp`, and dev servers report the canonical path).
#[derive(Debug, Clone)]
pub(crate) struct CodebaseRoot {
    roots: Vec<PathBuf>,
}

impl CodebaseRoot {
    pub(crate) fn new(codebase: &Path) -> Self {
        let given = if codebase.is_absolute() {
            codebase.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(codebase))
                .unwrap_or_else(|_| codebase.to_path_buf())
        };
        let mut roots = vec![given.clone()];
        if let Ok(canonical) = std::fs::canonicalize(&given)
            && canonical != given
        {
            roots.push(canonical);
        }
        Self { roots }
    }

    pub(crate) fn primary(&self) -> &Path {
        &self.roots[0]
    }

    /// Repo-relative `/`-separated path for an absolute path inside the codebase.
    pub(crate) fn relativize(&self, abs: &Path) -> Option<String> {
        self.roots.iter().find_map(|root| {
            let rel = abs.strip_prefix(root).ok()?;
            let rel = rel.to_string_lossy().replace('\\', "/");
            (!rel.is_empty()).then_some(rel)
        })
    }

    fn contains(&self, abs: &Path) -> bool {
        self.roots.iter().any(|root| abs.starts_with(root))
    }

    fn is_file(&self, rel: &str) -> bool {
        !rel.split('/').any(|seg| seg == "..") && self.primary().join(rel).is_file()
    }

    /// Accept a candidate repo-relative path if it exists; tolerate monorepo
    /// prefixes (`apps/web/src/x.tsx` with codebase `apps/web`) by stripping
    /// leading segments while at least two remain.
    fn existing_rel(&self, rel: &str) -> Option<String> {
        let rel = rel.trim_start_matches("./").trim_start_matches('/');
        if rel.is_empty() || is_library_path(rel) {
            return None;
        }
        if self.is_file(rel) {
            return Some(rel.to_string());
        }
        let segments: Vec<&str> = rel.split('/').collect();
        for skip in 1..segments.len().saturating_sub(1).min(4) {
            let candidate = segments[skip..].join("/");
            if self.is_file(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SourceClass {
    App(String),
    Library,
    Unknown,
}

/// Map a source-map `sources` entry (or a dev endpoint's file field) to a
/// repo-relative path. `base` resolves relative sources (map or script URL).
fn classify_source(source: &str, base: Option<&Url>, root: &CodebaseRoot) -> SourceClass {
    let source = source.trim();
    if source.is_empty() {
        return SourceClass::Unknown;
    }
    if let Some(rel) = strip_bundler_prefix(source) {
        if is_library_path(&rel) {
            return SourceClass::Library;
        }
        return root
            .existing_rel(&rel)
            .map_or(SourceClass::Unknown, SourceClass::App);
    }
    if source.starts_with("file://") {
        let Some(path) = Url::parse(source).ok().and_then(|u| u.to_file_path().ok()) else {
            return SourceClass::Unknown;
        };
        return classify_abs_path(&path, root);
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        return match Url::parse(source) {
            Ok(u) => classify_url_path(&u, root),
            Err(_) => SourceClass::Unknown,
        };
    }
    if source.starts_with('/') {
        let path = Path::new(strip_query(source));
        if root.contains(path) {
            return classify_abs_path(path, root);
        }
        // Root-relative URL path (Vite: `/src/App.tsx`, `/@fs/abs/path`).
        return classify_served_path(strip_query(source), root);
    }
    // Relative source: resolve against the map/script URL when we have one.
    if let Some(base) = base
        && let Ok(joined) = base.join(source)
    {
        if joined.scheme() == "file" {
            return match joined.to_file_path() {
                Ok(path) => classify_abs_path(&path, root),
                Err(_) => SourceClass::Unknown,
            };
        }
        if joined.scheme() == "http" || joined.scheme() == "https" {
            return classify_url_path(&joined, root);
        }
    }
    let rel = strip_query(source);
    if is_library_path(rel) {
        return SourceClass::Library;
    }
    root.existing_rel(rel)
        .map_or(SourceClass::Unknown, SourceClass::App)
}

fn classify_abs_path(path: &Path, root: &CodebaseRoot) -> SourceClass {
    if path
        .components()
        .any(|c| c.as_os_str().to_str() == Some("node_modules"))
    {
        return SourceClass::Library;
    }
    match root.relativize(path) {
        Some(rel) if root.is_file(&rel) => SourceClass::App(rel),
        _ => SourceClass::Unknown,
    }
}

fn classify_url_path(url: &Url, root: &CodebaseRoot) -> SourceClass {
    classify_served_path(&percent_decode(url.path()), root)
}

/// A dev-server URL path (`/src/pages/Cart.tsx`, `/@fs/abs/x.tsx`).
fn classify_served_path(path: &str, root: &CodebaseRoot) -> SourceClass {
    if let Some(abs) = path.strip_prefix("/@fs") {
        return classify_abs_path(Path::new(abs), root);
    }
    if path.split('/').any(|seg| seg == "node_modules") {
        return SourceClass::Library;
    }
    root.existing_rel(path)
        .map_or(SourceClass::Unknown, SourceClass::App)
}

/// Parse an already-resolved annotation (`/abs/src/pages/x.astro:12:5`,
/// `src/routes/+page.svelte:3`) into a repo-relative location.
fn parse_annotation(annotated: &str, root: &CodebaseRoot) -> Option<FileLine> {
    let mut numbers = Vec::new();
    let mut path = annotated.trim();
    for _ in 0..2 {
        let Some((head, tail)) = path.rsplit_once(':') else {
            break;
        };
        let Ok(n) = tail.parse::<u32>() else {
            break;
        };
        numbers.push(n);
        path = head;
    }
    numbers.reverse();
    let line = *numbers.first().filter(|line| **line > 0)?;
    let col = numbers.get(1).copied().unwrap_or(0);
    match classify_source(path, None, root) {
        SourceClass::App(file) => Some(FileLine { file, line, col }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Network context
// ---------------------------------------------------------------------------

struct FetchCtx {
    client: reqwest::Client,
    /// Endpoint bases: the dev-server origin and, when the target URL has a
    /// path (Next `basePath`), origin + path.
    endpoint_bases: Vec<Url>,
    allowed: Vec<OriginKey>,
    deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginKey {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl OriginKey {
    fn of(url: &Url) -> Option<Self> {
        let host = url
            .host_str()?
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        let host = if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
            || host.ends_with(".localhost")
        {
            "loopback".to_string()
        } else {
            host
        };
        Some(Self {
            scheme: url.scheme().to_string(),
            host,
            port: url.port_or_known_default(),
        })
    }
}

impl FetchCtx {
    fn new(base_url: &str, queries: &[SourceQuery]) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .no_proxy()
            .build()
            .context("build source-map HTTP client")?;
        let mut allowed = Vec::new();
        let mut endpoint_bases = Vec::new();
        if let Ok(base) = Url::parse(base_url) {
            if let Some(key) = OriginKey::of(&base) {
                allowed.push(key);
            }
            let mut origin = base.clone();
            origin.set_path("/");
            origin.set_query(None);
            origin.set_fragment(None);
            let base_path = base.path().trim_matches('/').to_string();
            endpoint_bases.push(origin.clone());
            if !base_path.is_empty()
                && let Ok(with_path) = origin.join(&format!("{base_path}/"))
            {
                endpoint_bases.push(with_path);
            }
        }
        for query in queries {
            if let Ok(page) = Url::parse(&query.page_url)
                && let Some(key) = OriginKey::of(&page)
                && !allowed.contains(&key)
            {
                allowed.push(key);
            }
        }
        Ok(Self {
            client,
            endpoint_bases,
            allowed,
            deadline: Instant::now() + OVERALL_DEADLINE,
        })
    }

    fn is_allowed(&self, url: &Url) -> bool {
        OriginKey::of(url).is_some_and(|key| self.allowed.contains(&key))
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn endpoint_urls(&self, path: &str) -> Vec<Url> {
        let rel = path.trim_start_matches('/');
        self.endpoint_bases
            .iter()
            .filter_map(|base| base.join(rel).ok())
            .collect()
    }

    /// GET a text body. Returns `None` on any error, non-2xx status, or when
    /// the body exceeds the size cap.
    async fn get_text(&self, url: Url) -> Option<FetchedText> {
        if self.expired() {
            return None;
        }
        let resp = self.client.get(url).send().await.ok()?;
        read_text(resp).await
    }

    async fn post_json(&self, url: Url, body: &Value) -> Option<Value> {
        if self.expired() {
            return None;
        }
        let resp = self.client.post(url).json(body).send().await.ok()?;
        let fetched = read_text(resp).await?;
        serde_json::from_str(&fetched.body).ok()
    }
}

struct FetchedText {
    body: String,
    source_map_header: Option<String>,
}

async fn read_text(mut resp: reqwest::Response) -> Option<FetchedText> {
    if !resp.status().is_success() || resp.status() == reqwest::StatusCode::NO_CONTENT {
        return None;
    }
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
    {
        return None;
    }
    let source_map_header = ["sourcemap", "x-sourcemap"].iter().find_map(|name| {
        resp.headers()
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    });
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > MAX_BODY_BYTES {
                    return None;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    Some(FetchedText {
        body: String::from_utf8_lossy(&buf).into_owned(),
        source_map_header,
    })
}

/// Find the last `//# sourceMappingURL=` (or `//@`, `/*#`) reference.
pub(crate) fn find_source_mapping_url(script: &str) -> Option<String> {
    const NEEDLE: &str = "sourceMappingURL=";
    let mut search_end = script.len();
    while let Some(idx) = script[..search_end].rfind(NEEDLE) {
        let before = script[..idx].trim_end_matches([' ', '\t']);
        let is_comment = before.ends_with("//#")
            || before.ends_with("//@")
            || before.ends_with("/*#")
            || before.ends_with("/*@");
        if is_comment {
            let value = &script[idx + NEEDLE.len()..];
            let end = value
                .find(|c: char| c.is_whitespace() || c == '*' || c == '\'' || c == '"')
                .unwrap_or(value.len());
            let value = value[..end].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        search_end = idx;
    }
    None
}

/// Decode a `data:` URI JSON payload (base64 or percent-encoded).
pub(crate) fn decode_data_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    if meta.split(';').any(|p| p.eq_ignore_ascii_case("base64")) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload.trim())
            .ok()?;
        String::from_utf8(bytes).ok()
    } else {
        Some(percent_decode(payload))
    }
}

// ---------------------------------------------------------------------------
// Map loading
// ---------------------------------------------------------------------------

struct LoadedMap {
    map: SourceMap,
    /// URL that relative `sources` entries resolve against.
    base: Option<Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MapJob {
    /// Source map for a served script.
    Script(String),
    /// Source map for a bundle file on disk (Next server chunks).
    Bundle(PathBuf),
    /// vite-rsc module map for a source file (`environmentName`).
    ViteRsc { module: String, env: String },
}

async fn load_map(ctx: &FetchCtx, root: &CodebaseRoot, job: &MapJob) -> Option<LoadedMap> {
    match job {
        MapJob::Script(url) => {
            let url = Url::parse(url).ok()?;
            load_script_map(ctx, &url).await
        }
        MapJob::Bundle(path) => load_bundle_map(ctx, root, path).await,
        MapJob::ViteRsc { module, env } => load_vite_rsc_map(ctx, module, env).await,
    }
}

async fn load_script_map(ctx: &FetchCtx, script_url: &Url) -> Option<LoadedMap> {
    let fetched = ctx.get_text(script_url.clone()).await?;
    let reference = fetched
        .source_map_header
        .or_else(|| find_source_mapping_url(&fetched.body))?;
    load_map_reference(ctx, script_url, &reference).await
}

async fn load_map_reference(ctx: &FetchCtx, base: &Url, reference: &str) -> Option<LoadedMap> {
    if reference.starts_with("data:") {
        let json = decode_data_uri(reference)?;
        let map = SourceMap::from_json(&json).ok()?;
        return Some(LoadedMap {
            map,
            base: Some(base.clone()),
        });
    }
    let map_url = base.join(reference).ok()?;
    if !ctx.is_allowed(&map_url) {
        return None;
    }
    let fetched = ctx.get_text(map_url.clone()).await?;
    let map = SourceMap::from_json(&fetched.body).ok()?;
    Some(LoadedMap {
        map,
        base: Some(map_url),
    })
}

/// Read a source map from disk (bundles inside the codebase only).
async fn read_disk_map(root: &CodebaseRoot, map_path: &Path) -> Option<LoadedMap> {
    if !root.contains(map_path) {
        return None;
    }
    let text = tokio::fs::read_to_string(map_path).await.ok()?;
    let map = SourceMap::from_json(&text).ok()?;
    Some(LoadedMap {
        map,
        base: Url::from_file_path(map_path).ok(),
    })
}

async fn load_bundle_map(ctx: &FetchCtx, root: &CodebaseRoot, path: &Path) -> Option<LoadedMap> {
    if root.contains(path) {
        // Sibling `<bundle>.map` (Turbopack writes these next to server chunks).
        let mut sibling = path.as_os_str().to_owned();
        sibling.push(".map");
        if let Some(loaded) = read_disk_map(root, Path::new(&sibling)).await {
            return Some(loaded);
        }
        // The bundle's own `sourceMappingURL`.
        if let Ok(text) = tokio::fs::read_to_string(path).await
            && let Some(reference) = find_source_mapping_url(&text)
        {
            if reference.starts_with("data:") {
                if let Some(json) = decode_data_uri(&reference)
                    && let Ok(map) = SourceMap::from_json(&json)
                {
                    return Some(LoadedMap {
                        map,
                        base: Url::from_file_path(path).ok(),
                    });
                }
            } else if let Some(map_path) = Url::from_file_path(path)
                .ok()
                .and_then(|u| u.join(&reference).ok())
                .and_then(|u| u.to_file_path().ok())
                && let Some(loaded) = read_disk_map(root, &map_path).await
            {
                return Some(loaded);
            }
        }
    }
    // Next dev server: GET /__nextjs_source-map?filename=<file url>.
    let file_url = Url::from_file_path(path).ok()?;
    for mut endpoint in ctx.endpoint_urls("/__nextjs_source-map") {
        endpoint
            .query_pairs_mut()
            .append_pair("filename", file_url.as_str());
        if let Some(fetched) = ctx.get_text(endpoint).await
            && let Ok(map) = SourceMap::from_json(&fetched.body)
        {
            return Some(LoadedMap {
                map,
                base: Some(file_url.clone()),
            });
        }
    }
    None
}

async fn load_vite_rsc_map(ctx: &FetchCtx, module: &str, env: &str) -> Option<LoadedMap> {
    for mut endpoint in ctx.endpoint_urls("/__vite_rsc_findSourceMapURL") {
        endpoint
            .query_pairs_mut()
            .append_pair("filename", module)
            .append_pair("environmentName", env);
        if let Some(fetched) = ctx.get_text(endpoint).await
            && let Ok(map) = SourceMap::from_json(&fetched.body)
        {
            return Some(LoadedMap { map, base: None });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Frame resolution
// ---------------------------------------------------------------------------

/// What to do with one frame before any network work.
enum FramePlan {
    Done(FrameResolution),
    /// Look up through a map job; `fallback` applies when no map is found.
    /// `next_file` is the frame file to send to Next's overlay endpoint when
    /// the map lookup fails and there is no usable fallback.
    Map {
        job: MapJob,
        fallback: FrameResolution,
        next_file: Option<String>,
    },
    /// Only Next's original-stack-frames endpoint can map it exactly.
    NextOnly {
        fallback: FrameResolution,
        next_file: String,
    },
}

fn plan_frame(
    key: &FrameKey,
    root: &CodebaseRoot,
    ctx: &FetchCtx,
    next_dist: Option<&Path>,
) -> FramePlan {
    match classify_frame_url(&key.url) {
        FrameTarget::Script(url) => {
            if is_library_script(&url) {
                return FramePlan::Done(FrameResolution::Library);
            }
            if !ctx.is_allowed(&url) {
                return FramePlan::Done(FrameResolution::Unresolved);
            }
            // Vite serves source files at their repo path; if no map is
            // available, the file is still right (line unmapped).
            let fallback = match classify_url_path(&url, root) {
                SourceClass::App(file) => FrameResolution::App {
                    loc: FileLine {
                        file,
                        line: key.line,
                        col: key.col,
                    },
                    exact: false,
                },
                SourceClass::Library => return FramePlan::Done(FrameResolution::Library),
                SourceClass::Unknown => FrameResolution::Unresolved,
            };
            let next_file = next_client_chunk_file(&url, next_dist);
            let mut script = url;
            script.set_fragment(None);
            FramePlan::Map {
                job: MapJob::Script(script.to_string()),
                fallback,
                next_file,
            }
        }
        FrameTarget::File { path, env } => {
            if path
                .components()
                .any(|c| c.as_os_str().to_str() == Some("node_modules"))
            {
                return FramePlan::Done(FrameResolution::Library);
            }
            if is_build_path(&path) {
                let next_file = Url::from_file_path(&path).ok().map(|u| u.to_string());
                return FramePlan::Map {
                    job: MapJob::Bundle(path),
                    fallback: FrameResolution::Unresolved,
                    next_file,
                };
            }
            let Some(rel) = root.relativize(&path).filter(|rel| root.is_file(rel)) else {
                return FramePlan::Done(FrameResolution::Unresolved);
            };
            if let Some(env) = env.or_else(|| key.env.clone()) {
                FramePlan::Map {
                    job: MapJob::ViteRsc {
                        module: path.to_string_lossy().into_owned(),
                        env,
                    },
                    fallback: FrameResolution::App {
                        loc: FileLine {
                            file: rel,
                            line: key.line,
                            col: key.col,
                        },
                        exact: false,
                    },
                    next_file: None,
                }
            } else {
                // Direct on-disk source file outside build dirs (e.g. React 18
                // `_debugSource` or Angular `debugInfo`): already points at the
                // original source file and line.
                FramePlan::Done(FrameResolution::App {
                    loc: FileLine {
                        file: rel,
                        line: key.line,
                        col: key.col,
                    },
                    exact: true,
                })
            }
        }
        FrameTarget::Webpack { raw, rel } => {
            let fallback = rel.and_then(|rel| root.existing_rel(&rel)).map_or(
                FrameResolution::Unresolved,
                |file| FrameResolution::App {
                    loc: FileLine {
                        file,
                        line: key.line,
                        col: key.col,
                    },
                    exact: false,
                },
            );
            FramePlan::NextOnly {
                fallback,
                next_file: raw,
            }
        }
        FrameTarget::RelativeFile(rel) => {
            let normalized = strip_query(&rel).replace('\\', "/");
            if is_library_path(&normalized) {
                return FramePlan::Done(FrameResolution::Library);
            }
            match root.existing_rel(&normalized) {
                Some(file) => FramePlan::Done(FrameResolution::App {
                    loc: FileLine {
                        file,
                        line: key.line,
                        col: key.col,
                    },
                    exact: true,
                }),
                None => FramePlan::Done(FrameResolution::Unresolved),
            }
        }
        FrameTarget::Unsupported => FramePlan::Done(FrameResolution::Unresolved),
    }
}

/// Next's dev overlay maps client frames only when given the chunk's on-disk
/// `file://` path (as `parseStack` does): `/_next/static/chunks/x.js` ->
/// `file://<project>/<distDir>/static/chunks/x.js`.
fn next_client_chunk_file(url: &Url, next_dist: Option<&Path>) -> Option<String> {
    let dist = next_dist?;
    let path = percent_decode(url.path());
    let rest = path.split_once("/_next/").map(|(_, rest)| rest)?;
    Url::from_file_path(dist.join(rest))
        .ok()
        .map(|u| u.to_string())
}

/// `<codebase>/.next/dev` (Next 16) or `<codebase>/.next`.
fn next_dist_dir(root: &CodebaseRoot) -> Option<PathBuf> {
    [".next/dev", ".next"]
        .iter()
        .map(|cand| root.primary().join(cand))
        .find(|dir| dir.join("static").is_dir())
}

fn resolve_with_map(
    loaded: &LoadedMap,
    key: &FrameKey,
    root: &CodebaseRoot,
) -> Option<FrameResolution> {
    let pos = loaded.map.lookup(key.line, key.col)?;
    if pos.ignored {
        return Some(FrameResolution::Library);
    }
    match classify_source(&pos.source, loaded.base.as_ref(), root) {
        SourceClass::App(file) => Some(FrameResolution::App {
            loc: FileLine {
                file,
                line: pos.line,
                col: pos.col,
            },
            exact: true,
        }),
        SourceClass::Library => Some(FrameResolution::Library),
        SourceClass::Unknown => None,
    }
}

/// A frame waiting for Next's overlay endpoint.
struct NextPending {
    key: FrameKey,
    file: String,
    is_server: bool,
    fallback: FrameResolution,
}

async fn resolve_frames(
    ctx: &FetchCtx,
    root: &CodebaseRoot,
    frames: &[FrameKey],
) -> HashMap<FrameKey, FrameResolution> {
    let next_dist = next_dist_dir(root);
    let plans: Vec<(FrameKey, FramePlan)> = frames
        .iter()
        .map(|key| {
            (
                key.clone(),
                plan_frame(key, root, ctx, next_dist.as_deref()),
            )
        })
        .collect();

    let mut jobs: Vec<MapJob> = Vec::new();
    let mut job_set = HashSet::new();
    for (_, plan) in &plans {
        if let FramePlan::Map { job, .. } = plan
            && job_set.len() < MAX_MAP_JOBS
            && job_set.insert(job.clone())
        {
            jobs.push(job.clone());
        }
    }
    let maps: HashMap<MapJob, Arc<LoadedMap>> = stream::iter(jobs)
        .map(|job| async move {
            let loaded = load_map(ctx, root, &job).await;
            (job, loaded)
        })
        .buffer_unordered(FETCH_CONCURRENCY)
        .filter_map(|(job, loaded)| async move { loaded.map(|m| (job, Arc::new(m))) })
        .collect()
        .await;

    let mut out = HashMap::with_capacity(plans.len());
    let mut next_pending: Vec<NextPending> = Vec::new();
    for (key, plan) in plans {
        match plan {
            FramePlan::Done(res) => {
                out.insert(key, res);
            }
            FramePlan::Map {
                job,
                fallback,
                next_file,
            } => {
                if let Some(res) = maps
                    .get(&job)
                    .and_then(|loaded| resolve_with_map(loaded, &key, root))
                {
                    out.insert(key, res);
                    continue;
                }
                match next_file {
                    Some(file) if !matches!(fallback, FrameResolution::App { .. }) => {
                        next_pending.push(NextPending {
                            key,
                            file,
                            is_server: matches!(job, MapJob::Bundle(_)),
                            fallback,
                        });
                    }
                    _ => {
                        out.insert(key, fallback);
                    }
                }
            }
            FramePlan::NextOnly {
                fallback,
                next_file,
            } => next_pending.push(NextPending {
                key,
                file: next_file,
                is_server: false,
                fallback,
            }),
        }
    }

    if !next_pending.is_empty() {
        let mapped = next_original_frames(ctx, root, &next_pending).await;
        for (pending, mapped) in next_pending.into_iter().zip(mapped) {
            out.insert(pending.key, mapped.unwrap_or(pending.fallback));
        }
    }
    out
}

/// Last resort: Next's dev overlay endpoint. Returns one entry per pending
/// frame (in order); `None` when the endpoint could not map it.
async fn next_original_frames(
    ctx: &FetchCtx,
    root: &CodebaseRoot,
    pending: &[NextPending],
) -> Vec<Option<FrameResolution>> {
    let mut out: Vec<Option<FrameResolution>> = vec![None; pending.len()];
    let Some(endpoint) = ctx
        .endpoint_urls("/__nextjs_original-stack-frames")
        .into_iter()
        .next()
    else {
        return out;
    };
    for is_server in [true, false] {
        let indices: Vec<usize> = (0..pending.len())
            .filter(|&i| pending[i].is_server == is_server)
            .collect();
        for batch in indices.chunks(NEXT_FRAMES_BATCH) {
            let frames: Vec<Value> = batch
                .iter()
                .map(|&i| {
                    let p = &pending[i];
                    json!({
                        "file": p.file,
                        "methodName": "<unknown>",
                        "line1": p.key.line,
                        "column1": p.key.col,
                        "arguments": [],
                    })
                })
                .collect();
            let body = json!({
                "frames": frames,
                "isServer": is_server,
                "isEdgeServer": false,
                "isAppDirectory": true,
            });
            let Some(Value::Array(results)) = ctx.post_json(endpoint.clone(), &body).await else {
                // Endpoint missing (not Next) or failing: stop trying.
                return out;
            };
            for (&i, result) in batch.iter().zip(results.iter()) {
                out[i] = parse_next_frame_result(result, root);
            }
        }
    }
    out
}

fn parse_next_frame_result(result: &Value, root: &CodebaseRoot) -> Option<FrameResolution> {
    if result.get("status").and_then(Value::as_str) != Some("fulfilled") {
        return None;
    }
    let frame = result.get("value")?.get("originalStackFrame")?;
    if frame.get("ignored").and_then(Value::as_bool) == Some(true) {
        return Some(FrameResolution::Library);
    }
    let file = frame.get("file").and_then(Value::as_str)?;
    let line = frame
        .get("line1")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)?;
    let col = frame
        .get("column1")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    match classify_source(file, None, root) {
        SourceClass::App(file) => Some(FrameResolution::App {
            loc: FileLine { file, line, col },
            exact: true,
        }),
        SourceClass::Library => Some(FrameResolution::Library),
        SourceClass::Unknown => None,
    }
}

// ---------------------------------------------------------------------------
// Site derivation
// ---------------------------------------------------------------------------

fn derive_resolved_source(
    capture: &ElementSourceCapture,
    resolutions: &HashMap<FrameKey, FrameResolution>,
    root: &CodebaseRoot,
) -> Option<ResolvedSource> {
    let mut chain: Vec<(&FileLine, bool)> = Vec::new();
    let mut handler: Option<FileLine> = None;
    // A precisely mapped owner is still only ancestor context when the host
    // render is missing or unresolved. Confirm every frame through the first
    // app site, allowing known library wrappers to lead to their app caller.
    let mut render_ancestry_resolved = capture
        .frames
        .iter()
        .find(|frame| frame.role != "handler")
        .is_some_and(|frame| frame.role == "render");
    for frame in &capture.frames {
        let resolution = resolutions.get(&FrameKey::of(frame));
        if frame.role != "handler"
            && chain.is_empty()
            && !matches!(
                resolution,
                Some(FrameResolution::App { .. } | FrameResolution::Library)
            )
        {
            render_ancestry_resolved = false;
        }
        let Some(FrameResolution::App { loc, exact }) = resolution else {
            continue;
        };
        if frame.role == "handler" {
            if handler.is_none() {
                handler = Some(loc.clone());
            }
        } else {
            chain.push((loc, *exact));
        }
    }

    if let Some(render) = capture
        .annotated
        .as_deref()
        .and_then(|a| parse_annotation(a, root))
    {
        return Some(ResolvedSource {
            render: Some(render),
            caller: None,
            handler,
            method: "annotation".to_string(),
            confidence: "exact".to_string(),
            candidates: Vec::new(),
        });
    }

    let Some(&(render, render_exact)) = chain.first() else {
        return handler.map(|handler| ResolvedSource {
            handler: Some(handler),
            method: "runtime".to_string(),
            confidence: "probable".to_string(),
            ..Default::default()
        });
    };
    let caller = chain
        .iter()
        .skip(1)
        .find(|(loc, _)| loc.file != render.file && !is_shared_component(&loc.file))
        .map(|(loc, _)| (*loc).clone());
    Some(ResolvedSource {
        render: Some(render.clone()),
        caller,
        handler,
        method: "runtime".to_string(),
        confidence: if render_exact && render_ancestry_resolved {
            "exact"
        } else {
            "probable"
        }
        .to_string(),
        candidates: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::source_map::test_support::encode;
    use super::*;
    use std::fs;

    fn codebase(files: &[&str]) -> (tempfile::TempDir, CodebaseRoot) {
        let dir = tempfile::tempdir().unwrap();
        for f in files {
            let p = dir.path().join(f);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, "export {}\n").unwrap();
        }
        let root = CodebaseRoot::new(dir.path());
        (dir, root)
    }

    fn frame(role: &str, url: &str, line: u32, col: u32) -> SourceFrame {
        SourceFrame {
            role: role.to_string(),
            owner: None,
            env: None,
            url: url.to_string(),
            line,
            col,
        }
    }

    fn canonical(dir: &tempfile::TempDir) -> PathBuf {
        fs::canonicalize(dir.path()).unwrap()
    }

    #[test]
    fn normalizes_react_virtual_server_urls() {
        let (url, env) = normalize_frame_url(
            "about://React/Server/file:///private/tmp/app/.next/dev/server/chunks/ssr/%5Broot-of-the-server%5D__01d8c38._.js?6",
        );
        assert_eq!(
            url,
            "file:///private/tmp/app/.next/dev/server/chunks/ssr/%5Broot-of-the-server%5D__01d8c38._.js"
        );
        assert_eq!(env.as_deref(), Some("Server"));

        let (url, env) = normalize_frame_url("rsc://React/Prerender/file:///repo/app/page.tsx?12");
        assert_eq!(url, "file:///repo/app/page.tsx");
        assert_eq!(env.as_deref(), Some("Prerender"));

        // Non-numeric queries on plain URLs are preserved.
        let (url, env) = normalize_frame_url("http://127.0.0.1:5173/src/App.tsx?t=123");
        assert_eq!(url, "http://127.0.0.1:5173/src/App.tsx?t=123");
        assert!(env.is_none());
    }

    #[test]
    fn classifies_frame_targets() {
        match classify_frame_url(
            "about://React/Server/file:///private/tmp/app/.next/dev/server/chunks/ssr/%5Broot-of-the-server%5D__x._.js?3",
        ) {
            FrameTarget::File { path, env } => {
                assert_eq!(
                    path,
                    PathBuf::from(
                        "/private/tmp/app/.next/dev/server/chunks/ssr/[root-of-the-server]__x._.js"
                    )
                );
                assert_eq!(env.as_deref(), Some("Server"));
                assert!(is_build_path(&path));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            classify_frame_url("http://localhost:3000/_next/static/chunks/_1lh8s6g._.js"),
            FrameTarget::Script(_)
        ));
        match classify_frame_url("webpack-internal:///(app-pages-browser)/./app/page.tsx") {
            FrameTarget::Webpack { rel, .. } => assert_eq!(rel.as_deref(), Some("app/page.tsx")),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(classify_frame_url("<anonymous>"), FrameTarget::Unsupported);
    }

    #[test]
    fn library_scripts_are_skipped_without_fetching() {
        for url in [
            "http://127.0.0.1:3000/_next/static/chunks/node_modules_next_dist_compiled_react-dom_096_9a-._.js",
            "http://127.0.0.1:5173/node_modules/.vite/deps/react-dom_client.js?v=abc",
            "http://127.0.0.1:5173/@vite/client",
            "http://127.0.0.1:3000/_next/static/chunks/%5Bturbopack%5D_browser_dev_hmr-client.js",
        ] {
            assert!(is_library_script(&Url::parse(url).unwrap()), "{url}");
        }
        for url in [
            "http://127.0.0.1:3000/_next/static/chunks/_1lh8s6g._.js",
            "http://127.0.0.1:5173/src/pages/Cart.tsx",
        ] {
            assert!(!is_library_script(&Url::parse(url).unwrap()), "{url}");
        }
    }

    #[test]
    fn classifies_map_sources_to_repo_paths() {
        let (dir, root) = codebase(&[
            "app/page.tsx",
            "src/pages/Cart.tsx",
            "components/ui/button.tsx",
        ]);
        let abs = canonical(&dir);
        let cases: Vec<(String, Option<Url>, SourceClass)> = vec![
            (
                "webpack://_N_E/./app/page.tsx".into(),
                None,
                SourceClass::App("app/page.tsx".into()),
            ),
            (
                "turbopack:///[project]/components/ui/button.tsx".into(),
                None,
                SourceClass::App("components/ui/button.tsx".into()),
            ),
            (
                format!("file://{}/app/page.tsx", abs.display()),
                None,
                SourceClass::App("app/page.tsx".into()),
            ),
            (
                format!("{}/src/pages/Cart.tsx", dir.path().display()),
                None,
                SourceClass::App("src/pages/Cart.tsx".into()),
            ),
            // Vite inline map: relative to the module URL.
            (
                "Cart.tsx".into(),
                Url::parse("http://127.0.0.1:5173/src/pages/Cart.tsx?t=1").ok(),
                SourceClass::App("src/pages/Cart.tsx".into()),
            ),
            // vite-rsc: root-relative module URL.
            (
                "/app/page.tsx?v=1234".into(),
                None,
                SourceClass::App("app/page.tsx".into()),
            ),
            (
                format!("/@fs{}/app/page.tsx", abs.display()),
                None,
                SourceClass::App("app/page.tsx".into()),
            ),
            (
                format!(
                    "file://{}/node_modules/next/dist/client/link.js",
                    abs.display()
                ),
                None,
                SourceClass::Library,
            ),
            (
                "webpack://_N_E/../../node_modules/react/index.js".into(),
                None,
                SourceClass::Library,
            ),
            ("app/missing.tsx".into(), None, SourceClass::Unknown),
            ("file:///etc/hosts".into(), None, SourceClass::Unknown),
        ];
        for (source, base, expected) in cases {
            assert_eq!(
                classify_source(&source, base.as_ref(), &root),
                expected,
                "source {source}"
            );
        }
    }

    #[test]
    fn monorepo_prefixes_are_stripped() {
        let (_dir, root) = codebase(&["src/app/page.tsx"]);
        assert_eq!(
            root.existing_rel("apps/web/src/app/page.tsx").as_deref(),
            Some("src/app/page.tsx")
        );
        assert_eq!(root.existing_rel("x/page.tsx"), None);
    }

    #[test]
    fn finds_source_mapping_urls() {
        assert_eq!(
            find_source_mapping_url("a();\n//# sourceMappingURL=_1lh8s6g._.js.map\n").as_deref(),
            Some("_1lh8s6g._.js.map")
        );
        assert_eq!(
            find_source_mapping_url("x\n//@ sourceMappingURL=data:application/json;base64,eyJ9\n")
                .as_deref(),
            Some("data:application/json;base64,eyJ9")
        );
        assert_eq!(
            find_source_mapping_url("/*# sourceMappingURL=main.css.map */").as_deref(),
            Some("main.css.map")
        );
        // A string literal containing the needle is not a reference.
        assert_eq!(
            find_source_mapping_url("const s = \"sourceMappingURL=nope\";"),
            None
        );
    }

    #[test]
    fn decodes_data_uris() {
        assert_eq!(
            decode_data_uri("data:application/json;charset=utf-8;base64,eyJhIjoxfQ==").as_deref(),
            Some("{\"a\":1}")
        );
        assert_eq!(
            decode_data_uri("data:application/json,%7B%22a%22%3A1%7D").as_deref(),
            Some("{\"a\":1}")
        );
        assert_eq!(decode_data_uri("data:nocomma"), None);
    }

    #[test]
    fn parses_annotations() {
        let (dir, root) = codebase(&["src/pages/index.astro", "src/routes/+page.svelte"]);
        let abs = canonical(&dir);
        assert_eq!(
            parse_annotation(
                &format!("{}/src/pages/index.astro:12:5", abs.display()),
                &root
            ),
            Some(FileLine {
                file: "src/pages/index.astro".into(),
                line: 12,
                col: 5
            })
        );
        assert_eq!(
            parse_annotation("src/routes/+page.svelte:3", &root),
            Some(FileLine {
                file: "src/routes/+page.svelte".into(),
                line: 3,
                col: 0
            })
        );
        assert_eq!(parse_annotation("/elsewhere/x.astro:1:1", &root), None);
        assert_eq!(parse_annotation("src/pages/index.astro", &root), None);
    }

    fn app(file: &str, line: u32) -> FrameResolution {
        FrameResolution::App {
            loc: FileLine {
                file: file.into(),
                line,
                col: 1,
            },
            exact: true,
        }
    }

    #[test]
    fn derives_render_caller_and_handler_sites() {
        let (_dir, root) = codebase(&[]);
        let capture = ElementSourceCapture {
            frames: vec![
                frame("render", "lib-host", 1, 1),
                frame("owner", "button", 6, 5),
                frame("owner", "dialog-footer", 9, 3),
                frame("owner", "checkout", 14, 7),
                frame("owner", "page", 3, 1),
                frame("handler", "handler", 20, 9),
            ],
            handlers: vec!["onClick".into()],
            annotated: None,
        };
        let mut res = HashMap::new();
        res.insert(FrameKey::of(&capture.frames[0]), FrameResolution::Library);
        res.insert(
            FrameKey::of(&capture.frames[1]),
            app("components/ui/button.tsx", 6),
        );
        res.insert(
            FrameKey::of(&capture.frames[2]),
            app("components/ui/dialog-footer.tsx", 9),
        );
        res.insert(
            FrameKey::of(&capture.frames[3]),
            app("app/checkout/checkout-form.tsx", 14),
        );
        res.insert(
            FrameKey::of(&capture.frames[4]),
            app("app/checkout/page.tsx", 3),
        );
        res.insert(
            FrameKey::of(&capture.frames[5]),
            app("app/checkout/checkout-form.tsx", 20),
        );

        let out = derive_resolved_source(&capture, &res, &root).unwrap();
        assert_eq!(out.method, "runtime");
        assert_eq!(out.confidence, "exact");
        assert_eq!(out.render.unwrap().file, "components/ui/button.tsx");
        let caller = out.caller.unwrap();
        assert_eq!(
            (caller.file.as_str(), caller.line),
            ("app/checkout/checkout-form.tsx", 14)
        );
        assert_eq!(out.handler.unwrap().line, 20);

        // Inexact render frames downgrade confidence; nothing resolved -> None.
        res.insert(
            FrameKey::of(&capture.frames[1]),
            FrameResolution::App {
                loc: FileLine {
                    file: "components/ui/button.tsx".into(),
                    line: 30,
                    col: 2,
                },
                exact: false,
            },
        );
        let out = derive_resolved_source(&capture, &res, &root).unwrap();
        assert_eq!(out.confidence, "probable");
        assert!(derive_resolved_source(&capture, &HashMap::new(), &root).is_none());
    }

    #[test]
    fn annotation_wins_over_frames() {
        let (_dir, root) = codebase(&["src/pages/index.astro"]);
        let capture = ElementSourceCapture {
            frames: Vec::new(),
            handlers: Vec::new(),
            annotated: Some("src/pages/index.astro:7:3".into()),
        };
        let out = derive_resolved_source(&capture, &HashMap::new(), &root).unwrap();
        assert_eq!(out.method, "annotation");
        assert_eq!(out.confidence, "exact");
        assert_eq!(out.render.unwrap().line, 7);
    }

    #[test]
    fn owner_only_bench_capture_is_probable_ancestor_context() {
        let (_dir, root) = codebase(&[]);
        // Recorded "View device & history" sequence: the complete capture has
        // a library Link render and its app use site; another capture starts
        // at the enclosing BenchDeviceWorkspace owner, two frames higher.
        let mut capture = ElementSourceCapture {
            frames: vec![
                frame("render", "router-link", 7316, 42),
                frame("owner", "bench-device-workspace", 638, 29),
                frame("owner", "bench-test", 138, 25),
                frame("owner", "bench-test", 104, 25),
                frame("owner", "bench-test", 1856, 32),
                frame("owner", "dev-bench-fixture", 33, 30),
                frame("owner", "app", 1098, 38),
                frame("handler", "router-link", 7311, 22),
            ],
            handlers: vec!["onClick".into()],
            annotated: None,
        };
        let mut res = HashMap::new();
        res.insert(FrameKey::of(&capture.frames[0]), FrameResolution::Library);
        res.insert(
            FrameKey::of(&capture.frames[1]),
            app("src/diagnostics/BenchDeviceWorkspace.tsx", 627),
        );
        res.insert(
            FrameKey::of(&capture.frames[2]),
            app("src/screens/BenchTest.tsx", 144),
        );
        res.insert(
            FrameKey::of(&capture.frames[5]),
            app("src/preview/DevBenchFixture.tsx", 35),
        );
        res.insert(FrameKey::of(&capture.frames[7]), FrameResolution::Library);

        let complete = derive_resolved_source(&capture, &res, &root).unwrap();
        assert_eq!(complete.confidence, "exact");
        assert_eq!(complete.render.as_ref().unwrap().line, 627);
        assert_eq!(complete.caller.as_ref().unwrap().line, 144);

        capture.frames.drain(..2);
        let ancestor = derive_resolved_source(&capture, &res, &root).unwrap();
        assert_eq!(
            ancestor,
            ResolvedSource {
                render: Some(FileLine {
                    file: "src/screens/BenchTest.tsx".into(),
                    line: 144,
                    col: 1,
                }),
                caller: Some(FileLine {
                    file: "src/preview/DevBenchFixture.tsx".into(),
                    line: 35,
                    col: 1,
                }),
                method: "runtime".into(),
                confidence: "probable".into(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn unresolved_render_ancestry_downgrades_exact_owner_mapping() {
        let (_dir, root) = codebase(&[]);
        let capture = ElementSourceCapture {
            frames: vec![
                frame("render", "host", 1, 1),
                frame("owner", "wrapper", 2, 1),
                frame("owner", "feature", 3, 1),
                frame("handler", "handler", 4, 1),
            ],
            handlers: vec!["onClick".into()],
            annotated: None,
        };
        let mut res = HashMap::new();
        res.insert(FrameKey::of(&capture.frames[0]), FrameResolution::Library);
        res.insert(FrameKey::of(&capture.frames[1]), FrameResolution::Library);
        res.insert(FrameKey::of(&capture.frames[2]), app("src/Feature.tsx", 30));
        res.insert(FrameKey::of(&capture.frames[3]), app("src/Feature.tsx", 40));
        let complete = derive_resolved_source(&capture, &res, &root).unwrap();
        assert_eq!(complete.confidence, "exact");
        let mut expected = complete;
        expected.confidence = "probable".into();

        // Both an unresolved host render and a gap in its library ancestry
        // prevent exact ownership, including when no resolution was stored.
        for index in [0, 1] {
            let key = FrameKey::of(&capture.frames[index]);
            res.insert(key.clone(), FrameResolution::Unresolved);
            assert_eq!(
                derive_resolved_source(&capture, &res, &root).unwrap(),
                expected
            );
            res.remove(&key);
            assert_eq!(
                derive_resolved_source(&capture, &res, &root).unwrap(),
                expected
            );
            res.insert(key, FrameResolution::Library);
        }
    }

    #[test]
    fn direct_render_stays_exact_and_handler_only_stays_probable() {
        let (_dir, root) = codebase(&[]);
        let mut capture = ElementSourceCapture {
            frames: vec![
                frame("handler", "handler", 4, 1),
                frame("render", "feature", 3, 1),
            ],
            handlers: vec!["onClick".into()],
            annotated: None,
        };
        let mut res = HashMap::new();
        res.insert(FrameKey::of(&capture.frames[0]), app("src/Feature.tsx", 40));
        res.insert(FrameKey::of(&capture.frames[1]), app("src/Feature.tsx", 30));
        let direct = derive_resolved_source(&capture, &res, &root).unwrap();
        assert_eq!(direct.confidence, "exact");
        assert_eq!(direct.render.unwrap().line, 30);
        assert_eq!(direct.handler.unwrap().line, 40);

        capture.frames.pop();
        let handler = derive_resolved_source(&capture, &res, &root).unwrap();
        assert_eq!(handler.confidence, "probable");
        assert_eq!(handler.method, "runtime");
        assert!(handler.render.is_none());
        assert!(handler.caller.is_none());
        assert_eq!(handler.handler.unwrap().line, 40);
    }

    /// End-to-end against a mock dev server: a Vite-style module with an
    /// inline map, a Turbopack-style chunk with an index map, a node_modules
    /// chunk that must not be fetched, and Next's overlay endpoint for a
    /// server frame whose bundle has no map on disk.
    #[tokio::test]
    async fn resolves_frames_against_mock_dev_server() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let (dir, _root) = codebase(&[
            "src/pages/Cart.tsx",
            "src/components/ui/Button.tsx",
            "components/checkout-button.tsx",
            "app/page.tsx",
        ]);
        let abs = canonical(&dir);
        let server = MockServer::start().await;

        // Vite module: generated line 24 col 19 -> Cart.tsx 14:7.
        let mut vite_lines: Vec<Vec<(i64, i64, i64, i64)>> = vec![Vec::new(); 23];
        vite_lines.push(vec![(18, 0, 13, 6)]);
        let vite_map = json!({
            "version": 3,
            "sources": ["Cart.tsx"],
            "mappings": encode(&vite_lines),
        });
        let vite_body = format!(
            "export function Cart() {{}}\n//# sourceMappingURL=data:application/json;base64,{}\n",
            base64::engine::general_purpose::STANDARD.encode(vite_map.to_string())
        );
        Mock::given(method("GET"))
            .and(path("/src/pages/Cart.tsx"))
            .respond_with(ResponseTemplate::new(200).set_body_string(vite_body))
            .mount(&server)
            .await;
        // Vite module without a map: file is still known, line unmapped.
        Mock::given(method("GET"))
            .and(path("/src/components/ui/Button.tsx"))
            .respond_with(ResponseTemplate::new(200).set_body_string("export {}\n"))
            .mount(&server)
            .await;

        // Turbopack chunk + index map with file:// sources.
        Mock::given(method("GET"))
            .and(path("/_next/static/chunks/_app._.js"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("x\n//# sourceMappingURL=_app._.js.map"),
            )
            .mount(&server)
            .await;
        let chunk_map = json!({
            "version": 3,
            "sections": [{
                "offset": {"line": 10, "column": 0},
                "map": {
                    "version": 3,
                    "sources": [format!("file://{}/components/checkout-button.tsx", abs.display())],
                    "mappings": encode(&[vec![], vec![], vec![], vec![], vec![(200, 0, 5, 4)]]),
                }
            }]
        });
        Mock::given(method("GET"))
            .and(path("/_next/static/chunks/_app._.js.map"))
            .respond_with(ResponseTemplate::new(200).set_body_string(chunk_map.to_string()))
            .mount(&server)
            .await;
        // Next overlay endpoint resolves the server frame.
        Mock::given(method("POST"))
            .and(path("/__nextjs_original-stack-frames"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"status": "fulfilled", "value": {"originalStackFrame": {
                    "file": "app/page.tsx", "line1": 12, "column1": 7, "ignored": false
                }}}
            ])))
            .mount(&server)
            .await;

        let base = server.uri();
        let server_chunk = format!(
            "about://React/Server/file://{}/.next/dev/server/chunks/ssr/%5Broot-of-the-server%5D__x._.js?4",
            abs.display()
        );
        let queries = vec![
            SourceQuery {
                key: "vite".into(),
                page_url: format!("{base}/cart"),
                capture: ElementSourceCapture {
                    frames: vec![
                        frame(
                            "render",
                            &format!("{base}/src/components/ui/Button.tsx"),
                            30,
                            5,
                        ),
                        frame("owner", &format!("{base}/src/pages/Cart.tsx"), 24, 19),
                    ],
                    handlers: vec!["onClick".into()],
                    annotated: None,
                },
            },
            SourceQuery {
                key: "next".into(),
                page_url: format!("{base}/"),
                capture: ElementSourceCapture {
                    frames: vec![
                        frame(
                            "render",
                            &format!("{base}/_next/static/chunks/node_modules_next_dist_x._.js"),
                            1,
                            1,
                        ),
                        frame(
                            "owner",
                            &format!("{base}/_next/static/chunks/_app._.js"),
                            15,
                            214,
                        ),
                        frame("owner", &server_chunk, 62, 264),
                    ],
                    handlers: Vec::new(),
                    annotated: None,
                },
            },
            SourceQuery {
                key: "offorigin".into(),
                page_url: format!("{base}/"),
                capture: ElementSourceCapture {
                    frames: vec![frame("render", "https://cdn.example.com/app.js", 1, 1)],
                    handlers: Vec::new(),
                    annotated: None,
                },
            },
        ];

        let out = resolve_runtime_sources(&base, dir.path(), &queries)
            .await
            .unwrap();

        let vite = &out["vite"];
        let render = vite.render.as_ref().unwrap();
        assert_eq!(
            (render.file.as_str(), render.line),
            ("src/components/ui/Button.tsx", 30)
        );
        assert_eq!(vite.confidence, "probable", "unmapped render frame");
        let caller = vite.caller.as_ref().unwrap();
        assert_eq!(
            (caller.file.as_str(), caller.line, caller.col),
            ("src/pages/Cart.tsx", 14, 7)
        );

        let next = &out["next"];
        let render = next.render.as_ref().unwrap();
        assert_eq!(
            (render.file.as_str(), render.line, render.col),
            ("components/checkout-button.tsx", 6, 5)
        );
        assert_eq!(next.confidence, "exact");
        let caller = next.caller.as_ref().unwrap();
        assert_eq!((caller.file.as_str(), caller.line), ("app/page.tsx", 12));

        assert!(!out.contains_key("offorigin"));

        // The node_modules chunk and the off-origin script were never fetched.
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .all(|r| !r.url.path().contains("node_modules")),
            "library chunk fetched"
        );
    }

    #[tokio::test]
    async fn unreachable_dev_server_degrades_gracefully() {
        let (dir, _root) = codebase(&["src/App.tsx"]);
        let queries = vec![SourceQuery {
            key: "k".into(),
            page_url: "http://127.0.0.1:9/".into(),
            capture: ElementSourceCapture {
                frames: vec![frame("render", "http://127.0.0.1:9/src/App.tsx", 3, 1)],
                handlers: Vec::new(),
                annotated: None,
            },
        }];
        let out = resolve_runtime_sources("http://127.0.0.1:9/", dir.path(), &queries)
            .await
            .unwrap();
        // The Vite path fallback still yields the file with an unmapped line.
        let src = &out["k"];
        assert_eq!(src.render.as_ref().unwrap().file, "src/App.tsx");
        assert_eq!(src.confidence, "probable");
    }

    #[tokio::test]
    async fn resolves_react18_debug_source_vue_file_and_angular_debug_info() {
        let (dir, _root) = codebase(&[
            "src/components/ui/Button.tsx",
            "src/pages/Checkout.tsx",
            "src/components/ProductCard.vue",
            "src/app/ui/action-button.component.ts",
            "src/app/checkout/checkout.component.ts",
        ]);
        let abs = canonical(&dir);

        let queries = vec![
            // React 18 `_debugSource`: file:// absolute paths resolve directly without HTTP.
            SourceQuery {
                key: "react18".into(),
                page_url: "http://127.0.0.1:9/checkout".into(),
                capture: ElementSourceCapture {
                    frames: vec![
                        frame(
                            "render",
                            &format!("file://{}/src/components/ui/Button.tsx", abs.display()),
                            12,
                            5,
                        ),
                        frame(
                            "owner",
                            &format!("file://{}/src/pages/Checkout.tsx", abs.display()),
                            28,
                            9,
                        ),
                    ],
                    handlers: vec!["onClick".into()],
                    annotated: None,
                },
            },
            // Vue 3 dev mode `__file` annotation (line 1 fallback).
            SourceQuery {
                key: "vue3".into(),
                page_url: "http://127.0.0.1:9/products".into(),
                capture: ElementSourceCapture {
                    frames: Vec::new(),
                    handlers: Vec::new(),
                    annotated: Some(format!(
                        "{}/src/components/ProductCard.vue:1",
                        abs.display()
                    )),
                },
            },
            // Angular 17+ `ɵcmp.debugInfo`: repo-relative `filePath` + `lineNumber`.
            SourceQuery {
                key: "angular".into(),
                page_url: "http://127.0.0.1:9/checkout".into(),
                capture: ElementSourceCapture {
                    frames: vec![
                        SourceFrame {
                            role: "render".into(),
                            owner: Some("ActionButtonComponent".into()),
                            env: None,
                            url: "src/app/ui/action-button.component.ts".into(),
                            line: 7,
                            col: 0,
                        },
                        SourceFrame {
                            role: "owner".into(),
                            owner: Some("CheckoutComponent".into()),
                            env: None,
                            url: "src/app/checkout/checkout.component.ts".into(),
                            line: 14,
                            col: 0,
                        },
                    ],
                    handlers: Vec::new(),
                    annotated: None,
                },
            },
        ];

        let out = resolve_runtime_sources("http://127.0.0.1:9/", dir.path(), &queries)
            .await
            .unwrap();

        let react18 = &out["react18"];
        assert_eq!(react18.method, "runtime");
        assert_eq!(react18.confidence, "exact");
        let r18_render = react18.render.as_ref().unwrap();
        assert_eq!(
            (r18_render.file.as_str(), r18_render.line, r18_render.col),
            ("src/components/ui/Button.tsx", 12, 5)
        );
        let r18_caller = react18.caller.as_ref().unwrap();
        assert_eq!(
            (r18_caller.file.as_str(), r18_caller.line, r18_caller.col),
            ("src/pages/Checkout.tsx", 28, 9)
        );

        let vue3 = &out["vue3"];
        assert_eq!(vue3.method, "annotation");
        assert_eq!(vue3.confidence, "exact");
        let v3_render = vue3.render.as_ref().unwrap();
        assert_eq!(
            (v3_render.file.as_str(), v3_render.line),
            ("src/components/ProductCard.vue", 1)
        );

        let angular = &out["angular"];
        assert_eq!(angular.method, "runtime");
        assert_eq!(angular.confidence, "exact");
        let ng_render = angular.render.as_ref().unwrap();
        assert_eq!(
            (ng_render.file.as_str(), ng_render.line),
            ("src/app/ui/action-button.component.ts", 7)
        );
        let ng_caller = angular.caller.as_ref().unwrap();
        assert_eq!(
            (ng_caller.file.as_str(), ng_caller.line),
            ("src/app/checkout/checkout.component.ts", 14)
        );
    }
}
