//! File walking, package.json and import resolution for route discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use super::js::JsSource;

/// Directories never walked, at any depth.
const IGNORED_DIRS: &[&str] = &[
    "node_modules",
    "__tests__",
    "__mocks__",
    "__snapshots__",
    "src-tauri",
    "target",
    "storybook-static",
    "bower_components",
    "jspm_packages",
];

/// Directories ignored only directly under the app root (build output and
/// non-app code that can contain look-alike servers or pages).
const IGNORED_ROOT_DIRS: &[&str] = &[
    "dist",
    "build",
    "out",
    "coverage",
    "tests",
    "test",
    "e2e",
    "cypress",
    "playwright",
    "scripts",
    "docs",
    "examples",
    "fixtures",
    "migrations",
    "seed",
    "logs",
    "artifacts",
    "tmp",
    "temp",
    "vendor",
];

/// Extensions read by any adapter.
const ROUTE_EXTS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts", "vue", "svelte", "astro", "md", "mdx",
    "html", "markdown",
];

const MAX_FILES: usize = 60_000;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Every route-relevant file under an app directory, sorted.
pub(crate) struct FileSet {
    pub files: Vec<PathBuf>,
}

impl FileSet {
    pub fn walk(root: &Path) -> Self {
        let mut files = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let at_root = dir == root;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                let path = entry.path();
                if ft.is_dir() {
                    if (name.starts_with('.') && name != ".well-known")
                        || IGNORED_DIRS.contains(&name.as_ref())
                        || (at_root && IGNORED_ROOT_DIRS.contains(&name.as_ref()))
                    {
                        continue;
                    }
                    stack.push(path);
                } else if ft.is_file() && is_candidate_file(&name) {
                    if files.len() >= MAX_FILES {
                        break;
                    }
                    files.push(path);
                }
            }
        }
        files.sort();
        Self { files }
    }

    /// Files under `dir` (absolute), sorted.
    pub fn under<'a>(&'a self, dir: &'a Path) -> impl Iterator<Item = &'a PathBuf> + 'a {
        self.files.iter().filter(move |f| f.starts_with(dir))
    }

    /// Source files with one of the given extensions.
    pub fn with_ext<'a>(&'a self, exts: &'a [&str]) -> impl Iterator<Item = &'a PathBuf> + 'a {
        self.files.iter().filter(move |f| {
            f.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| exts.contains(&e))
        })
    }
}

fn is_candidate_file(name: &str) -> bool {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    if !ROUTE_EXTS.contains(&ext) || name.ends_with(".d.ts") || name.ends_with(".min.js") {
        return false;
    }
    !(stem.ends_with(".test")
        || stem.ends_with(".spec")
        || stem.ends_with(".stories")
        || stem.ends_with(".story"))
}

/// Reads a source file (size-capped, lossy UTF-8).
pub(crate) fn read_source(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn read_js(path: &Path) -> Option<JsSource> {
    read_source(path).map(|raw| JsSource::new(&raw))
}

/// Dependency names and version ranges from `package.json`.
#[derive(Debug, Default, Clone)]
pub(crate) struct Package {
    pub deps: BTreeMap<String, String>,
}

impl Package {
    pub fn read(dir: &Path) -> Self {
        let Some(raw) = read_source(&dir.join("package.json")) else {
            return Self::default();
        };
        let Ok(json) = serde_json::from_str::<Value>(&raw) else {
            return Self::default();
        };
        let mut deps = BTreeMap::new();
        for key in ["dependencies", "devDependencies", "peerDependencies"] {
            if let Some(map) = json.get(key).and_then(Value::as_object) {
                for (name, version) in map {
                    deps.entry(name.clone())
                        .or_insert_with(|| version.as_str().unwrap_or_default().to_string());
                }
            }
        }
        Self { deps }
    }

    pub fn has(&self, name: &str) -> bool {
        self.deps.contains_key(name)
    }

    pub fn has_any(&self, names: &[&str]) -> bool {
        names.iter().any(|n| self.has(n))
    }

    /// Major version from a semver range like `^1.19.3`, if readable.
    pub fn major(&self, name: &str) -> Option<u32> {
        let version = self.deps.get(name)?;
        let digits: String = version
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }
}

/// First existing file among `dir/<name>.<ext>` combinations.
pub(crate) fn first_config(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    const EXTS: &[&str] = &["ts", "mts", "js", "mjs", "cjs"];
    names.iter().find_map(|name| {
        EXTS.iter()
            .map(|ext| dir.join(format!("{name}.{ext}")))
            .find(|p| p.is_file())
    })
}

/// tsconfig `compilerOptions.paths` aliases, e.g. `@/*` -> `<app>/src/*`.
#[derive(Debug, Default, Clone)]
pub(crate) struct Aliases {
    /// (prefix before `*`, absolute target prefixes)
    entries: Vec<(String, Vec<PathBuf>)>,
}

impl Aliases {
    pub fn load(app_dir: &Path) -> Self {
        let mut entries = Vec::new();
        for name in ["tsconfig.json", "tsconfig.app.json", "jsconfig.json"] {
            let Some(raw) = read_source(&app_dir.join(name)) else {
                continue;
            };
            let Some(json) = parse_jsonc(&raw) else {
                continue;
            };
            let opts = json.get("compilerOptions");
            let base = opts
                .and_then(|o| o.get("baseUrl"))
                .and_then(Value::as_str)
                .unwrap_or(".");
            let base_dir = app_dir.join(base);
            let Some(paths) = opts.and_then(|o| o.get("paths")).and_then(Value::as_object) else {
                continue;
            };
            for (alias, targets) in paths {
                let prefix = alias.trim_end_matches('*').to_string();
                let targets: Vec<PathBuf> = targets
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(|t| base_dir.join(t.trim_end_matches('*')))
                    .collect();
                if !prefix.is_empty() && !targets.is_empty() {
                    entries.push((prefix, targets));
                }
            }
        }
        if !entries.iter().any(|(p, _)| p == "@/") && app_dir.join("src").is_dir() {
            entries.push(("@/".to_string(), vec![app_dir.join("src")]));
        }
        if !entries.iter().any(|(p, _)| p == "~/") {
            let tilde = if app_dir.join("app").is_dir() {
                "app"
            } else {
                "src"
            };
            entries.push(("~/".to_string(), vec![app_dir.join(tilde)]));
        }
        // Longest prefix first.
        entries.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        Self { entries }
    }

    /// Resolves an import specifier relative to `from` (a file).
    pub fn resolve(&self, from: &Path, spec: &str) -> Option<PathBuf> {
        if spec.starts_with('.') {
            let base = from.parent()?.join(spec);
            return resolve_module_path(&base);
        }
        for (prefix, targets) in &self.entries {
            if let Some(rest) = spec.strip_prefix(prefix.as_str()) {
                for target in targets {
                    if let Some(found) = resolve_module_path(&target.join(rest)) {
                        return Some(found);
                    }
                }
            }
        }
        None
    }
}

/// JSON with comments and trailing commas (tsconfig style).
fn parse_jsonc(raw: &str) -> Option<Value> {
    let stripped = JsSource::new(raw).text;
    let bytes = stripped.as_bytes();
    let mut cleaned = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            let end = super::js::skip_string(bytes, i);
            cleaned.extend_from_slice(&bytes[i..end]);
            i = end;
            continue;
        }
        if b == b',' {
            let next = super::js::skip_ws(bytes, i + 1);
            if matches!(bytes.get(next), Some(b'}') | Some(b']')) {
                i += 1;
                continue;
            }
        }
        cleaned.push(b);
        i += 1;
    }
    serde_json::from_slice(&cleaned).ok()
}

const MODULE_EXTS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts", "vue"];

fn resolve_module_path(base: &Path) -> Option<PathBuf> {
    let base = clean_path(base);
    if base.is_file() {
        return Some(base);
    }
    // ESM `.js` specifiers that point at TypeScript sources.
    if let Some(ext) = base.extension().and_then(|e| e.to_str())
        && matches!(ext, "js" | "jsx" | "mjs" | "cjs")
    {
        let stem = base.with_extension("");
        for ext in ["ts", "tsx", "mts", "cts"] {
            let candidate = stem.with_extension(ext);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let file_name = base.file_name()?.to_string_lossy().into_owned();
    for ext in MODULE_EXTS {
        let candidate = base.with_file_name(format!("{file_name}.{ext}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for ext in MODULE_EXTS {
        let candidate = base.join(format!("index.{ext}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Lexically resolves `.` and `..` components.
pub(crate) fn clean_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Repo-relative display path with forward slashes.
pub(crate) fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Path components of `file` relative to `dir`, without the file name.
pub(crate) fn rel_dirs(dir: &Path, file: &Path) -> Vec<String> {
    let rel = file.strip_prefix(dir).unwrap_or(file);
    let mut parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    parts.pop();
    parts
}

pub(crate) fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Package directories of a monorepo: `pnpm-workspace.yaml` and
/// `package.json#workspaces` globs (`dir/*` or exact paths), plus the usual
/// `apps/*`, `packages/*` folders and single `web/`, `client/` style dirs.
pub(crate) fn workspace_apps(root: &Path) -> Vec<PathBuf> {
    let mut patterns: Vec<String> = ["apps/*", "packages/*", "sites/*", "services/*"]
        .iter()
        .chain(["web", "app", "frontend", "client", "site", "website", "www"].iter())
        .map(|p| (*p).to_string())
        .collect();
    patterns.extend(declared_workspaces(root));
    let mut out = BTreeSet::new();
    for pattern in patterns {
        if pattern.starts_with('!') {
            continue;
        }
        let pattern = pattern.trim_start_matches("./").trim_end_matches('/');
        match pattern
            .strip_suffix("/**")
            .or_else(|| pattern.strip_suffix("/*"))
        {
            Some(parent) if !parent.contains('*') => {
                let Ok(entries) = std::fs::read_dir(root.join(parent)) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.join("package.json").is_file() {
                        out.insert(path);
                    }
                }
            }
            None if !pattern.contains('*') && !pattern.is_empty() => {
                let path = root.join(pattern);
                if path.join("package.json").is_file() {
                    out.insert(path);
                }
            }
            _ => {}
        }
    }
    out.remove(root);
    out.into_iter().collect()
}

fn declared_workspaces(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(raw) = read_source(&root.join("pnpm-workspace.yaml"))
        && let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&raw)
        && let Some(list) = yaml
            .get("packages")
            .and_then(serde_yaml::Value::as_sequence)
    {
        out.extend(list.iter().filter_map(|v| v.as_str().map(str::to_string)));
    }
    if let Some(raw) = read_source(&root.join("package.json"))
        && let Ok(json) = serde_json::from_str::<Value>(&raw)
        && let Some(ws) = json.get("workspaces")
    {
        let list = ws
            .as_array()
            .or_else(|| ws.get("packages").and_then(Value::as_array));
        out.extend(
            list.into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string)),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tsconfig_with_comments_and_trailing_commas() {
        let raw = r#"{
  // comment
  "compilerOptions": { "baseUrl": ".", "paths": { "@lib/*": ["./src/lib/*"], }, },
}"#;
        let json = parse_jsonc(raw).expect("parse");
        assert!(json["compilerOptions"]["paths"]["@lib/*"].is_array());
    }

    #[test]
    fn workspace_apps_follow_declared_globs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for rel in [
            "pnpm-workspace.yaml",
            "desktop/client/package.json",
            "desktop/lawyer/package.json",
            "website/package.json",
            "tools/x/package.json",
        ] {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(&p, "{}").expect("write");
        }
        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - \"desktop/*\"\n  - \"website\"\n  - \"!tools/*\"\n",
        )
        .expect("write");
        let apps: Vec<String> = workspace_apps(root)
            .iter()
            .map(|p| rel_path(root, p))
            .collect();
        assert_eq!(apps, vec!["desktop/client", "desktop/lawyer", "website"]);
    }

    #[test]
    fn walk_skips_ignored_dirs_and_test_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for rel in [
            "src/app/page.tsx",
            "src/app/page.test.tsx",
            "node_modules/x/index.js",
            "dist/index.html",
            "src/dist/keep.ts",
            ".next/server/page.js",
            "tests/server.ts",
            "app/.well-known/security.txt/route.ts",
        ] {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(&p, "x").expect("write");
        }
        let set = FileSet::walk(root);
        let rels: Vec<String> = set.files.iter().map(|f| rel_path(root, f)).collect();
        assert_eq!(
            rels,
            vec![
                "app/.well-known/security.txt/route.ts",
                "src/app/page.tsx",
                "src/dist/keep.ts"
            ]
        );
    }
}
