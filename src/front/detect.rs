//! Framework, dev command and port detection for `brokenapp init`.
//!
//! Sources, most explicit first: `.claude/launch.json` (a curated dev-server
//! entry), then `package.json` (`scripts.dev`, port flags, dependencies),
//! then framework config files (`vite.config.*`, `astro.config.*`,
//! `wrangler.toml`), then non-JS web stack markers (Rails, Django, FastAPI,
//! Flask, Laravel/PHP, Go, Spring Boot, ASP.NET, static HTML), then framework
//! default ports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use super::locality;

/// What `init` could infer about how the app runs locally.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Detection {
    /// `next`, `vinext`, `vite`, `astro`, `wrangler`, `sveltekit`, `nuxt`,
    /// `angular`, `create-react-app`, `remix`, `gatsby`, `rails`, `django`,
    /// `fastapi`, `flask`, `laravel`, `php`, `go`, `spring-boot`, `aspnet`,
    /// `static`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_manager: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_cmd: Option<String>,
    /// Working directory for `dev_cmd`, relative to the codebase root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Where each value came from, for the init report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Detect framework, dev command and port for the app rooted at `root`.
pub fn detect(root: &Path) -> Detection {
    let mut det = Detection::default();
    let pkg = read_json(&root.join("package.json"));
    if let Some(pkg) = pkg.as_ref() {
        detect_from_package(root, pkg, &mut det);
    }
    detect_monorepo_workspaces(root, pkg.as_ref(), &mut det);
    if det.framework.is_none() && det.dev_cmd.is_none() && det.port.is_none() {
        detect_non_js_stack(root, &mut det);
    }
    if let Some(launch) = read_json(&root.join(".claude").join("launch.json")) {
        apply_launch_json(&launch, &mut det);
    }
    if det.url.is_none() {
        det.url = det.port.map(|p| format!("http://localhost:{p}"));
    }
    det
}

fn read_json(path: &Path) -> Option<Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn detect_from_package(root: &Path, pkg: &Value, det: &mut Detection) {
    let scripts: BTreeMap<String, String> = pkg
        .get("scripts")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let (pm, pm_source) = package_manager(root, pkg);
    if let Some(source) = pm_source {
        det.notes
            .push(format!("package manager {pm} from {source}"));
    }
    det.package_manager = Some(pm.clone());

    let script_name = if scripts.contains_key("dev") {
        Some("dev")
    } else if scripts
        .get("start")
        .is_some_and(|s| is_dev_server_script(s))
    {
        Some("start")
    } else {
        None
    };

    let script_text = script_name.map(|name| resolve_script(&scripts, name));
    if let Some(name) = script_name {
        det.dev_cmd = Some(format!("{pm} run {name}"));
        det.notes
            .push(format!("dev command from package.json scripts.{name}"));
    } else {
        det.notes.push(
            "no dev script in package.json; pass --dev-cmd to let `map` start the app".into(),
        );
    }

    det.framework = script_text
        .as_deref()
        .and_then(framework_from_script)
        .or_else(|| framework_from_deps(pkg))
        .map(str::to_string);

    if let Some(port) = script_text.as_deref().and_then(port_from_script) {
        det.port = Some(port);
        det.notes.push(format!(
            "port {port} from package.json scripts.{}",
            script_name.unwrap_or("dev")
        ));
    } else if let Some((port, file)) = det
        .framework
        .as_deref()
        .and_then(|fw| port_from_config_files(root, fw))
    {
        det.port = Some(port);
        det.notes.push(format!("port {port} from {file}"));
    } else if let Some(port) = det.framework.as_deref().and_then(default_port) {
        det.port = Some(port);
        det.notes.push(format!(
            "port {port} is the {} default",
            det.framework.as_deref().unwrap_or("framework")
        ));
    }
}

/// How many directories above the app `init` looks for a workspace root.
const WORKSPACE_WALK_LIMIT: usize = 8;

/// The package manager and, when it was found above the app directory (a
/// pnpm/yarn/bun workspace), where. Order per directory, walking up from the
/// app to the repository root (`.git`): the `packageManager` field, a
/// `pnpm-workspace.yaml`, then lockfiles. An app whose dependencies use the
/// `workspace:` protocol (which npm does not support) defaults to pnpm.
fn package_manager(root: &Path, pkg: &Value) -> (String, Option<String>) {
    for (depth, dir) in root.ancestors().take(WORKSPACE_WALK_LIMIT + 1).enumerate() {
        let source = |file: &str| {
            (depth > 0).then(|| {
                let up = "../".repeat(depth);
                format!("{up}{file}")
            })
        };
        let field_pkg = if depth == 0 {
            Some(pkg.clone())
        } else {
            read_json(&dir.join("package.json"))
        };
        if let Some(name) = field_pkg
            .as_ref()
            .and_then(|p| p.get("packageManager"))
            .and_then(Value::as_str)
            .map(|f| f.split('@').next().unwrap_or("").trim().to_string())
            .filter(|n| matches!(n.as_str(), "npm" | "pnpm" | "yarn" | "bun"))
        {
            return (name, source("package.json#packageManager"));
        }
        for (marker, pm) in [
            ("pnpm-workspace.yaml", "pnpm"),
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "yarn"),
            ("bun.lockb", "bun"),
            ("bun.lock", "bun"),
            ("package-lock.json", "npm"),
        ] {
            if dir.join(marker).is_file() {
                return (pm.to_string(), source(marker));
            }
        }
        if dir.join(".git").exists() {
            break;
        }
    }
    if uses_workspace_protocol(pkg) {
        return (
            "pnpm".to_string(),
            Some("`workspace:` dependencies (no lockfile found)".to_string()),
        );
    }
    ("npm".to_string(), None)
}

/// Any dependency declared as `workspace:*` / `workspace:^`.
fn uses_workspace_protocol(pkg: &Value) -> bool {
    ["dependencies", "devDependencies", "peerDependencies"]
        .iter()
        .filter_map(|section| pkg.get(section).and_then(Value::as_object))
        .flat_map(|deps| deps.values())
        .any(|v| v.as_str().is_some_and(|s| s.starts_with("workspace:")))
}

fn split_words(script: &str) -> Vec<String> {
    shell_words::split(script)
        .unwrap_or_else(|_| script.split_whitespace().map(str::to_string).collect())
}

/// Follow `npm run x` / `pnpm x` / `yarn x` / `bun run x` delegation (a few
/// levels) so `"dev": "npm run dev:web"` is analyzed as `dev:web`.
fn resolve_script(scripts: &BTreeMap<String, String>, name: &str) -> String {
    let mut current = scripts.get(name).cloned().unwrap_or_default();
    for _ in 0..3 {
        let words = split_words(&current);
        let Some(first) = words.first() else { break };
        if !matches!(first.as_str(), "npm" | "pnpm" | "yarn" | "bun") {
            break;
        }
        let idx = if words.get(1).map(String::as_str) == Some("run") {
            2
        } else {
            1
        };
        if words.len() != idx + 1 {
            break;
        }
        match scripts.get(&words[idx]) {
            Some(next) => current = next.clone(),
            None => break,
        }
    }
    current
}

/// A `start` script that runs a dev server (not a production server).
fn is_dev_server_script(script: &str) -> bool {
    let s = script.to_ascii_lowercase();
    if s.contains("vite preview") || s.contains("vite build") {
        return false;
    }
    [
        "react-scripts start",
        "ng serve",
        "next dev",
        "astro dev",
        "vite",
        "webpack serve",
        "webpack-dev-server",
        "gatsby develop",
        "nuxt dev",
        "nuxi dev",
        "wrangler dev",
        "parcel",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

/// Framework implied by the tool a script runs.
pub fn framework_from_script(script: &str) -> Option<&'static str> {
    let words = split_words(script);
    for (i, word) in words.iter().enumerate() {
        let bin = word.rsplit('/').next().unwrap_or(word);
        let next = words.get(i + 1).map(String::as_str);
        let fw = match bin {
            "vinext" => "vinext",
            "next" => "next",
            "astro" => "astro",
            "wrangler" => "wrangler",
            "nuxt" | "nuxi" => "nuxt",
            "ng" if next == Some("serve") => "angular",
            "react-scripts" => "create-react-app",
            "gatsby" => "gatsby",
            "remix" if next == Some("vite:dev") => "vite",
            "remix" => "remix",
            "vite" => "vite",
            _ => continue,
        };
        return Some(fw);
    }
    None
}

fn framework_from_deps(pkg: &Value) -> Option<&'static str> {
    let has = |dep: &str| {
        ["dependencies", "devDependencies"]
            .iter()
            .any(|section| pkg.get(section).and_then(|d| d.get(dep)).is_some())
    };
    [
        ("vinext", "vinext"),
        ("next", "next"),
        ("astro", "astro"),
        ("@sveltejs/kit", "sveltekit"),
        ("nuxt", "nuxt"),
        ("@angular/core", "angular"),
        ("react-scripts", "create-react-app"),
        ("gatsby", "gatsby"),
        ("@remix-run/dev", "remix"),
        ("vite", "vite"),
        ("wrangler", "wrangler"),
    ]
    .into_iter()
    .find(|(dep, _)| has(dep))
    .map(|(_, fw)| fw)
}

/// Default dev-server port per framework.
pub fn default_port(framework: &str) -> Option<u16> {
    Some(match framework {
        "next" | "vinext" | "nuxt" | "create-react-app" | "remix" | "rails" => 3000,
        "vite" | "sveltekit" => 5173,
        "astro" => 4321,
        "wrangler" => 8787,
        "angular" => 4200,
        "gatsby" | "django" | "fastapi" | "laravel" | "php" | "static" => 8000,
        "flask" | "aspnet" => 5000,
        "go" | "spring-boot" => 8080,
        _ => return None,
    })
}

/// Port flags in a script: `-p 3100`, `-p=3100`, `--port 3100`,
/// `--port=3100`, `PORT=3100`.
pub fn port_from_script(script: &str) -> Option<u16> {
    let words = split_words(script);
    let parse = |s: &str| s.trim().parse::<u16>().ok().filter(|p| *p > 0);
    for (i, word) in words.iter().enumerate() {
        if let Some(v) = word.strip_prefix("PORT=") {
            if let Some(p) = parse(v) {
                return Some(p);
            }
        }
        if let Some(v) = word
            .strip_prefix("--port=")
            .or_else(|| word.strip_prefix("-p="))
        {
            if let Some(p) = parse(v) {
                return Some(p);
            }
        }
        if matches!(word.as_str(), "-p" | "--port") {
            if let Some(p) = words.get(i + 1).and_then(|v| parse(v)) {
                return Some(p);
            }
        }
    }
    None
}

/// `server.port` in Vite/Astro configs, `[dev] port` in `wrangler.toml`.
fn port_from_config_files(root: &Path, framework: &str) -> Option<(u16, String)> {
    let prefixes: &[&str] = match framework {
        "vite" | "sveltekit" | "remix" | "vinext" => &["vite.config"],
        "astro" => &["astro.config"],
        "wrangler" => {
            let raw = std::fs::read_to_string(root.join("wrangler.toml")).ok()?;
            let value: toml::Value = toml::from_str(&raw).ok()?;
            let port = value.get("dev")?.get("port")?.as_integer()?;
            return u16::try_from(port)
                .ok()
                .filter(|p| *p > 0)
                .map(|p| (p, "wrangler.toml".to_string()));
        }
        _ => return None,
    };
    let re = regex::Regex::new(r"(?s)\bserver\s*:\s*\{[^}]*?\bport\s*:\s*(\d{2,5})").ok()?;
    for prefix in prefixes {
        for ext in ["ts", "mts", "js", "mjs", "cjs"] {
            let file = format!("{prefix}.{ext}");
            let Ok(raw) = std::fs::read_to_string(root.join(&file)) else {
                continue;
            };
            if let Some(port) = re
                .captures(&raw)
                .and_then(|c| c[1].parse::<u16>().ok())
                .filter(|p| *p > 0)
            {
                return Some((port, file));
            }
        }
    }
    None
}

/// Detect npm/pnpm/yarn monorepo workspaces when `root` has no direct app entry.
fn detect_monorepo_workspaces(root: &Path, pkg: Option<&Value>, det: &mut Detection) {
    let mut patterns = Vec::new();
    if let Some(pkg) = pkg {
        if let Some(ws) = pkg.get("workspaces") {
            if let Some(arr) = ws.as_array() {
                patterns.extend(arr.iter().filter_map(Value::as_str).map(str::to_string));
            } else if let Some(arr) = ws.get("packages").and_then(Value::as_array) {
                patterns.extend(arr.iter().filter_map(Value::as_str).map(str::to_string));
            }
        }
    }
    patterns.extend(pnpm_workspace_patterns(root));
    if patterns.is_empty() || has_direct_root_app_entry(root) {
        return;
    }

    let mut candidates = BTreeSet::new();
    for raw in patterns {
        let pat = raw
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .trim_start_matches("./")
            .trim_end_matches('/');
        if pat.is_empty() || pat.starts_with('!') {
            continue;
        }
        if let Some(base) = pat.strip_suffix("/**").or_else(|| pat.strip_suffix("/*")) {
            let base = base.trim_end_matches('/');
            let search_dir = if base.is_empty() {
                root.to_path_buf()
            } else {
                root.join(base)
            };
            let Ok(entries) = std::fs::read_dir(&search_dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || name == "node_modules" {
                    continue;
                }
                let rel = if base.is_empty() {
                    name
                } else {
                    format!("{base}/{name}")
                };
                candidates.insert(rel);
            }
        } else if !pat.contains('*') {
            candidates.insert(pat.to_string());
        }
    }

    let mut preferred_apps = Vec::new();
    let mut all_dev_apps = Vec::new();
    for rel in candidates {
        let Some(child_pkg) = read_json(&root.join(&rel).join("package.json")) else {
            continue;
        };
        let scripts: BTreeMap<String, String> = child_pkg
            .get("scripts")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let dev_script = scripts
            .get("dev")
            .filter(|s| !s.trim().is_empty())
            .or_else(|| scripts.get("start").filter(|s| is_dev_server_script(s)));
        let Some(script) = dev_script else {
            continue;
        };
        let is_web_dir =
            rel.starts_with("apps/") || rel.starts_with("web/") || rel.starts_with("sites/");
        let has_web_fw =
            framework_from_script(script).is_some() || framework_from_deps(&child_pkg).is_some();
        if is_web_dir || has_web_fw {
            preferred_apps.push(rel.clone());
        }
        all_dev_apps.push(rel);
    }

    let apps = if preferred_apps.is_empty() {
        all_dev_apps
    } else {
        preferred_apps
    };
    if !apps.is_empty() {
        det.notes.push(format!(
            "monorepo workspaces detected: {}; pass --codebase <app-dir> to target a specific app",
            apps.join(", ")
        ));
    }
}

fn pnpm_workspace_patterns(root: &Path) -> Vec<String> {
    let Some(raw) = read_text(&root.join("pnpm-workspace.yaml")) else {
        return Vec::new();
    };
    let mut patterns = Vec::new();
    let mut in_packages = false;
    for line in raw.lines() {
        let uncommented = line.split('#').next().unwrap_or("");
        let trimmed = uncommented.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(rest) = trimmed.strip_prefix("packages:") {
                in_packages = true;
                let rest = rest.trim();
                if let Some(inner) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                    for item in inner.split(',') {
                        let p = item.trim().trim_matches(|c| c == '"' || c == '\'');
                        if !p.is_empty() {
                            patterns.push(p.to_string());
                        }
                    }
                    in_packages = false;
                }
            } else {
                in_packages = false;
            }
            continue;
        }
        if in_packages && let Some(item) = trimmed.strip_prefix('-') {
            let p = item.trim().trim_matches(|c| c == '"' || c == '\'');
            if !p.is_empty() {
                patterns.push(p.to_string());
            }
        }
    }
    patterns
}

fn has_direct_root_app_entry(root: &Path) -> bool {
    if root.join("index.html").is_file() || root.join("public").join("index.html").is_file() {
        return true;
    }
    for dir in ["pages", "src/pages", "src/app", "src/routes"] {
        if root.join(dir).is_dir() {
            return true;
        }
    }
    if root.join("app").is_dir() {
        for ext in ["tsx", "ts", "jsx", "js"] {
            if root.join("app").join(format!("page.{ext}")).is_file()
                || root.join("app").join(format!("layout.{ext}")).is_file()
            {
                return true;
            }
        }
    }
    for prefix in [
        "next.config",
        "vite.config",
        "astro.config",
        "nuxt.config",
        "svelte.config",
    ] {
        for ext in ["ts", "mts", "js", "mjs", "cjs"] {
            if root.join(format!("{prefix}.{ext}")).is_file() {
                return true;
            }
        }
    }
    root.join("angular.json").is_file()
}

fn is_disallowed_launch_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if ["staging", "production", "remote", "hosted"]
        .iter()
        .any(|k| lower.contains(k))
    {
        return true;
    }
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "prod")
}

/// Whether `text` contains an `http://` or `https://` URL targeting a non-local host.
fn contains_remote_http_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut offset = 0;
    while offset < lower.len() {
        let rest = &lower[offset..];
        let next = match (rest.find("http://"), rest.find("https://")) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        let Some(rel) = next else { break };
        let start = offset + rel;
        let tail = &text[start..];
        let end = tail
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '\'' | '"' | '`' | ';' | ',' | ')' | ']' | '}' | '<' | '>'
                    )
            })
            .unwrap_or(tail.len());
        let candidate = &tail[..end];
        if let Ok(url) = url::Url::parse(candidate)
            && !locality::is_local_url(&url)
        {
            return true;
        }
        offset = start
            + if lower[start..].starts_with("https://") {
                8
            } else {
                7
            };
    }
    false
}

fn launch_config_is_disallowed(cfg: &Value) -> bool {
    if cfg
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(is_disallowed_launch_name)
    {
        return true;
    }
    if cfg
        .get("url")
        .and_then(Value::as_str)
        .is_some_and(contains_remote_http_url)
    {
        return true;
    }
    if cfg
        .get("runtimeExecutable")
        .and_then(Value::as_str)
        .is_some_and(contains_remote_http_url)
    {
        return true;
    }
    if cfg
        .get("runtimeArgs")
        .and_then(Value::as_array)
        .is_some_and(|args| {
            args.iter()
                .filter_map(Value::as_str)
                .any(contains_remote_http_url)
        })
    {
        return true;
    }
    if cfg
        .get("env")
        .and_then(Value::as_object)
        .is_some_and(|env| {
            env.values()
                .filter_map(Value::as_str)
                .any(contains_remote_http_url)
        })
    {
        return true;
    }
    false
}

fn launch_config_score(cfg: &Value, det: &Detection) -> i32 {
    let name = cfg
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let cwd = cfg
        .get("cwd")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut cmd_parts = Vec::new();
    if let Some(exe) = cfg.get("runtimeExecutable").and_then(Value::as_str) {
        cmd_parts.push(exe);
    }
    if let Some(args) = cfg.get("runtimeArgs").and_then(Value::as_array) {
        cmd_parts.extend(args.iter().filter_map(Value::as_str));
    }
    let cmd_joined = cmd_parts.join(" ");
    let cmd_lower = cmd_joined.to_ascii_lowercase();
    let cfg_fw = framework_from_script(&cmd_joined);
    let mut score = 0i32;

    if let Some(fw) = det.framework.as_deref() {
        if cfg_fw == Some(fw) {
            score += 100;
        } else if cfg_fw.is_some() {
            score -= 40;
        }
        let matches_fw = |s: &str| {
            s.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|t| t == fw || (fw == "next" && t == "nextjs"))
        };
        if matches_fw(&name) || matches_fw(&cwd) || matches_fw(&cmd_lower) {
            score += 50;
        }
    }
    if let Some(det_port) = det.port {
        let cfg_port = cfg
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok());
        if cfg_port == Some(det_port) {
            score += 15;
        }
    }
    fn tokens(s: &str) -> Vec<&str> {
        s.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .collect()
    }
    let meta_tokens: Vec<&str> = tokens(&name).into_iter().chain(tokens(&cwd)).collect();
    if meta_tokens.iter().any(|t| {
        matches!(
            *t,
            "web" | "portal" | "frontend" | "site" | "client" | "app"
        )
    }) {
        score += 20;
    }
    if meta_tokens.iter().any(|t| {
        matches!(
            *t,
            "desktop"
                | "electron"
                | "tauri"
                | "mobile"
                | "ios"
                | "android"
                | "storybook"
                | "preview"
                | "worker"
                | "docs"
        )
    }) {
        score -= 25;
    }
    score
}

/// Use the best local `.claude/launch.json` configuration that names a port or URL,
/// skipping staging/prod/remote configurations and preferring web/framework matches.
fn apply_launch_json(launch: &Value, det: &mut Detection) {
    let Some(configs) = launch.get("configurations").and_then(Value::as_array) else {
        return;
    };
    let mut skipped_remote = 0usize;
    let mut best: Option<(i32, &Value)> = None;
    for cfg in configs {
        if cfg.get("port").is_none() && cfg.get("url").is_none() {
            continue;
        }
        if launch_config_is_disallowed(cfg) {
            skipped_remote += 1;
            continue;
        }
        let score = launch_config_score(cfg, det);
        if best.is_none_or(|(best_score, _)| score > best_score) {
            best = Some((score, cfg));
        }
    }
    let Some((_, cfg)) = best else {
        if skipped_remote > 0 {
            det.notes.push(
                "skipped non-local/staging/prod .claude/launch.json configurations".to_string(),
            );
        }
        return;
    };
    let name = cfg.get("name").and_then(Value::as_str).unwrap_or("first");
    let env: BTreeMap<String, String> = cfg
        .get("env")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    if let Some(exe) = cfg.get("runtimeExecutable").and_then(Value::as_str) {
        let mut words = vec![exe.to_string()];
        if let Some(args) = cfg.get("runtimeArgs").and_then(Value::as_array) {
            words.extend(args.iter().filter_map(Value::as_str).map(str::to_string));
        }
        let joined_raw = words.join(" ");
        if det.framework.is_none() {
            det.framework = framework_from_script(&joined_raw).map(str::to_string);
        }
        let mut cmd = shell_words::join(&words);
        // A non-secret port/host override is kept inline in the command;
        // anything else must be wired as an `env:NAME` reference by hand.
        for key in ["HOST", "PORT"] {
            if let Some(v) = env.get(key) {
                cmd = format!("{key}={} {cmd}", shell_words::quote(v));
            }
        }
        det.dev_cmd = Some(cmd);
        det.dev_cwd = cfg
            .get("cwd")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|c| !c.is_empty() && c != ".");
        det.notes.push(format!(
            "dev command from .claude/launch.json configuration '{name}'"
        ));
    }
    let skipped: Vec<&str> = env
        .keys()
        .map(String::as_str)
        .filter(|k| !matches!(*k, "HOST" | "PORT"))
        .collect();
    if !skipped.is_empty() {
        det.notes.push(format!(
            "launch.json env not copied ({}); add them to [project.dev_env] as \"env:NAME\" references",
            skipped.join(", ")
        ));
    }

    let port = cfg
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p > 0);
    if let Some(port) = port {
        det.port = Some(port);
        det.notes.push(format!(
            "port {port} from .claude/launch.json configuration '{name}'"
        ));
    }
    if let Some(url) = cfg.get("url").and_then(Value::as_str) {
        det.url = Some(url.to_string());
    } else if let Some(port) = port {
        det.url = Some(format!("http://localhost:{port}"));
    }
}

/// Priority-ordered fallback detection for major non-JS web stacks when
/// `package.json` did not identify a JS/TS framework or dev server.
fn detect_non_js_stack(root: &Path, det: &mut Detection) {
    let apply = |det: &mut Detection,
                 framework: &str,
                 dev_cmd: Option<String>,
                 port: u16,
                 source: String| {
        if dev_cmd.is_some() {
            det.notes
                .retain(|n| !n.starts_with("no dev script in package.json"));
        }
        det.framework = Some(framework.to_string());
        det.dev_cmd = dev_cmd;
        det.port = Some(port);
        det.url = Some(format!("http://127.0.0.1:{port}"));
        det.notes
            .push(format!("framework {framework} from {source}"));
        det.notes
            .push(format!("port {port} is the {framework} default"));
    };

    // 1. Ruby on Rails: `bin/rails` or `Gemfile` referencing `rails`.
    let has_bin_rails = root.join("bin").join("rails").is_file();
    let has_gemfile_rails =
        read_text(&root.join("Gemfile")).is_some_and(|raw| contains_dep_token(&raw, "rails"));
    if has_bin_rails || has_gemfile_rails {
        let (dev_cmd, source) = if has_bin_rails {
            ("bin/rails server".to_string(), "bin/rails".to_string())
        } else {
            (
                "bundle exec rails server".to_string(),
                "Gemfile".to_string(),
            )
        };
        apply(det, "rails", Some(dev_cmd), 3000, source);
        return;
    }

    // 2. Django: `manage.py`.
    if root.join("manage.py").is_file() {
        apply(
            det,
            "django",
            Some("python manage.py runserver 127.0.0.1:8000".to_string()),
            8000,
            "manage.py".to_string(),
        );
        return;
    }

    // 3. FastAPI / Flask: `pyproject.toml` or `requirements.txt`.
    for dep_file in ["pyproject.toml", "requirements.txt"] {
        let Some(raw) = read_text(&root.join(dep_file)) else {
            continue;
        };
        if contains_dep_token(&raw, "fastapi") {
            let target = if root.join("app").join("main.py").is_file() {
                "app.main:app"
            } else if root.join("src").join("main.py").is_file() {
                "src.main:app"
            } else {
                "main:app"
            };
            apply(
                det,
                "fastapi",
                Some(format!(
                    "uvicorn {target} --reload --host 127.0.0.1 --port 8000"
                )),
                8000,
                dep_file.to_string(),
            );
            return;
        }
        if contains_dep_token(&raw, "flask") {
            apply(
                det,
                "flask",
                Some("flask run --host=127.0.0.1 --port=5000".to_string()),
                5000,
                dep_file.to_string(),
            );
            return;
        }
    }

    // 4. Laravel / PHP.
    if root.join("artisan").is_file() && root.join("composer.json").is_file() {
        apply(
            det,
            "laravel",
            Some("php artisan serve --host=127.0.0.1 --port=8000".to_string()),
            8000,
            "artisan + composer.json".to_string(),
        );
        return;
    }
    if root.join("index.php").is_file() {
        apply(
            det,
            "php",
            Some("php -S 127.0.0.1:8000".to_string()),
            8000,
            "index.php".to_string(),
        );
        return;
    }
    if root.join("public").join("index.php").is_file() {
        apply(
            det,
            "php",
            Some("php -S 127.0.0.1:8000 -t public".to_string()),
            8000,
            "public/index.php".to_string(),
        );
        return;
    }

    // 5. Go web server: `go.mod` + (`main.go` or `cmd/`).
    if root.join("go.mod").is_file()
        && (root.join("main.go").is_file() || root.join("cmd").is_dir())
    {
        let source = if root.join("main.go").is_file() {
            "go.mod + main.go"
        } else {
            "go.mod + cmd/"
        };
        apply(
            det,
            "go",
            Some("go run .".to_string()),
            8080,
            source.to_string(),
        );
        return;
    }

    // 6. Spring Boot / Java: `pom.xml`, `build.gradle`, or `build.gradle.kts`.
    for (build_file, dev_cmd) in [
        ("pom.xml", "./mvnw spring-boot:run"),
        ("build.gradle", "./gradlew bootRun"),
        ("build.gradle.kts", "./gradlew bootRun"),
    ] {
        if let Some(raw) = read_text(&root.join(build_file)) {
            let lower = raw.to_ascii_lowercase();
            if lower.contains("spring-boot") || lower.contains("org.springframework.boot") {
                apply(
                    det,
                    "spring-boot",
                    Some(dev_cmd.to_string()),
                    8080,
                    build_file.to_string(),
                );
                return;
            }
        }
    }

    // 7. ASP.NET / .NET: `*.csproj` referencing `Microsoft.NET.Sdk.Web`.
    if let Some(csproj) = find_aspnet_csproj(root) {
        apply(det, "aspnet", Some("dotnet run".to_string()), 5000, csproj);
        return;
    }

    // 8. Static HTML fallback: `index.html` or `public/index.html`.
    for candidate in ["index.html", "public/index.html"] {
        if root.join(candidate).is_file() {
            apply(det, "static", None, 8000, candidate.to_string());
            return;
        }
    }
}

fn read_text(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 1_000_000 {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Case-insensitive package-name token search across non-comment lines
/// (`#`-prefixed comments are ignored). Prevents matching substrings like
/// `trails` or `flask-cors` when looking for `rails` or `flask`.
fn contains_dep_token(text: &str, token: &str) -> bool {
    let needle = token.to_ascii_lowercase();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    for raw_line in text.lines() {
        let line = raw_line
            .split('#')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let bytes = line.as_bytes();
        let mut offset = 0;
        while let Some(pos) = line[offset..].find(&needle) {
            let start = offset + pos;
            let end = start + needle.len();
            let before_ok = start == 0 || !is_ident(bytes[start - 1]);
            let after_ok = end == bytes.len() || !is_ident(bytes[end]);
            if before_ok && after_ok {
                return true;
            }
            offset = end;
        }
    }
    false
}

fn find_aspnet_csproj(root: &Path) -> Option<String> {
    let entries = std::fs::read_dir(root).ok()?;
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|ft| ft.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.to_ascii_lowercase().ends_with(".csproj"))
        .collect();
    names.sort();
    for name in names {
        if let Some(raw) = read_text(&root.join(&name))
            && raw.contains("Microsoft.NET.Sdk.Web")
        {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, body: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn port_flags_in_scripts() {
        assert_eq!(port_from_script("next dev -p 3100"), Some(3100));
        assert_eq!(
            port_from_script("next dev --turbopack --port=3200"),
            Some(3200)
        );
        assert_eq!(port_from_script("vite --port 5174 --host"), Some(5174));
        assert_eq!(
            port_from_script("cross-env PORT=4000 react-scripts start"),
            Some(4000)
        );
        assert_eq!(port_from_script("wrangler dev -p=8788"), Some(8788));
        assert_eq!(port_from_script("next dev --port $PORT"), None);
        assert_eq!(port_from_script("astro dev"), None);
    }

    #[test]
    fn framework_from_script_tokens() {
        assert_eq!(framework_from_script("next dev --turbopack"), Some("next"));
        assert_eq!(framework_from_script("vinext dev"), Some("vinext"));
        assert_eq!(framework_from_script("npx astro dev"), Some("astro"));
        assert_eq!(
            framework_from_script("wrangler dev src/index.ts"),
            Some("wrangler")
        );
        assert_eq!(framework_from_script("ng serve --open"), Some("angular"));
        assert_eq!(framework_from_script("remix vite:dev"), Some("vite"));
        assert_eq!(framework_from_script("node server.js"), None);
    }

    #[test]
    fn next_project_defaults_to_3000() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"15.0.0"}}"#,
        );
        write(dir.path(), "pnpm-lock.yaml", "");
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("next"));
        assert_eq!(det.dev_cmd.as_deref(), Some("pnpm run dev"));
        assert_eq!(det.port, Some(3000));
        assert_eq!(det.url.as_deref(), Some("http://localhost:3000"));
    }

    #[test]
    fn script_port_wins_and_delegation_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"packageManager":"yarn@4.1.0","scripts":{"dev":"npm run dev:web","dev:web":"next dev -p 3100"}}"#,
        );
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("next"));
        assert_eq!(det.dev_cmd.as_deref(), Some("yarn run dev"));
        assert_eq!(det.port, Some(3100));
    }

    #[test]
    fn vite_config_port_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"6"}}"#,
        );
        let det = detect(dir.path());
        assert_eq!(det.port, Some(5173));
        write(
            dir.path(),
            "vite.config.ts",
            "export default defineConfig({ plugins: [react()], server: {\n  host: true,\n  port: 3005,\n} })",
        );
        let det = detect(dir.path());
        assert_eq!(det.port, Some(3005));
        assert!(det.notes.iter().any(|n| n.contains("vite.config.ts")));
    }

    #[test]
    fn astro_and_wrangler_defaults() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"astro dev"},"dependencies":{"astro":"5"}}"#,
        );
        assert_eq!(detect(dir.path()).port, Some(4321));

        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"wrangler dev"},"devDependencies":{"wrangler":"4"}}"#,
        );
        assert_eq!(detect(dir.path()).port, Some(8787));
        write(
            dir.path(),
            "wrangler.toml",
            "name = \"x\"\n[dev]\nport = 8790\n",
        );
        assert_eq!(detect(dir.path()).port, Some(8790));
    }

    #[test]
    fn production_start_script_is_not_a_dev_command() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"start":"next start"},"dependencies":{"next":"15"}}"#,
        );
        let det = detect(dir.path());
        assert_eq!(det.dev_cmd, None);
        assert_eq!(det.framework.as_deref(), Some("next"));
        assert_eq!(det.port, Some(3000));
    }

    #[test]
    fn launch_json_overrides_package_json() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"6"}}"#,
        );
        write(
            dir.path(),
            ".claude/launch.json",
            r#"{"version":"0.0.1","configurations":[{"name":"web","runtimeExecutable":"npm","runtimeArgs":["run","dev"],"port":3100,"cwd":"apps/web","env":{"PORT":"3100","API_KEY":"secret"}}]}"#,
        );
        let det = detect(dir.path());
        assert_eq!(det.dev_cmd.as_deref(), Some("PORT=3100 npm run dev"));
        assert_eq!(det.dev_cwd.as_deref(), Some("apps/web"));
        assert_eq!(det.port, Some(3100));
        assert_eq!(det.url.as_deref(), Some("http://localhost:3100"));
        assert!(det.notes.iter().any(|n| n.contains("API_KEY")));
        assert!(!det.dev_cmd.as_deref().unwrap().contains("secret"));
    }

    #[test]
    fn pnpm_workspace_is_found_above_the_app() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        write(dir.path(), "pnpm-workspace.yaml", "packages:\n  - apps/*\n");
        write(dir.path(), "pnpm-lock.yaml", "");
        write(
            dir.path(),
            "apps/web/package.json",
            r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"16","@acme/ui":"workspace:*"}}"#,
        );
        let det = detect(&dir.path().join("apps/web"));
        assert_eq!(det.package_manager.as_deref(), Some("pnpm"));
        assert_eq!(det.dev_cmd.as_deref(), Some("pnpm run dev"));
        assert!(
            det.notes
                .iter()
                .any(|n| n.contains("../../pnpm-workspace.yaml")),
            "{:?}",
            det.notes
        );
    }

    #[test]
    fn workspace_walk_stops_at_the_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "yarn.lock", "");
        std::fs::create_dir_all(dir.path().join("repo/.git")).unwrap();
        write(
            dir.path(),
            "repo/package.json",
            r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"6"}}"#,
        );
        let det = detect(&dir.path().join("repo"));
        assert_eq!(det.package_manager.as_deref(), Some("npm"));

        // `workspace:` deps without any lockfile imply a workspace manager.
        write(
            dir.path(),
            "repo/package.json",
            r#"{"scripts":{"dev":"vite"},"dependencies":{"@acme/ui":"workspace:^"}}"#,
        );
        let det = detect(&dir.path().join("repo"));
        assert_eq!(det.package_manager.as_deref(), Some("pnpm"));
    }

    #[test]
    fn empty_dir_detects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let det = detect(dir.path());
        assert_eq!(det.url, None);
        assert_eq!(det.dev_cmd, None);
    }

    #[test]
    fn rails_detection_bin_rails_and_gemfile() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "Gemfile",
            "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n",
        );
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("rails"));
        assert_eq!(det.dev_cmd.as_deref(), Some("bundle exec rails server"));
        assert_eq!(det.port, Some(3000));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:3000"));

        write(dir.path(), "bin/rails", "#!/usr/bin/env ruby\n");
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("rails"));
        assert_eq!(det.dev_cmd.as_deref(), Some("bin/rails server"));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:3000"));

        // Non-rails gems like `trails` or commented lines do not trigger Rails.
        let non_rails = tempfile::tempdir().unwrap();
        write(
            non_rails.path(),
            "Gemfile",
            "# gem 'rails'\ngem 'trails'\ngem 'rails-html-sanitizer'\n",
        );
        assert_eq!(detect(non_rails.path()).framework, None);
    }

    #[test]
    fn django_detection() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "manage.py", "#!/usr/bin/env python\n");
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("django"));
        assert_eq!(
            det.dev_cmd.as_deref(),
            Some("python manage.py runserver 127.0.0.1:8000")
        );
        assert_eq!(det.port, Some(8000));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8000"));
    }

    #[test]
    fn fastapi_and_flask_detection() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "pyproject.toml",
            "[project]\ndependencies = [\"fastapi>=0.115\", \"uvicorn\"]\n",
        );
        write(dir.path(), "app/main.py", "app = FastAPI()\n");
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("fastapi"));
        assert!(
            det.dev_cmd
                .as_deref()
                .is_some_and(|c| c.contains("uvicorn") && c.contains("app.main:app")),
            "{det:?}"
        );
        assert_eq!(det.port, Some(8000));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8000"));

        let flask_dir = tempfile::tempdir().unwrap();
        write(flask_dir.path(), "requirements.txt", "Flask==3.0.3\n");
        let det = detect(flask_dir.path());
        assert_eq!(det.framework.as_deref(), Some("flask"));
        assert!(
            det.dev_cmd
                .as_deref()
                .is_some_and(|c| c.starts_with("flask run")),
            "{det:?}"
        );
        assert_eq!(det.port, Some(5000));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:5000"));
    }

    #[test]
    fn laravel_and_php_detection() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "artisan", "#!/usr/bin/env php\n");
        write(dir.path(), "composer.json", r#"{"name":"acme/app"}"#);
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("laravel"));
        assert_eq!(
            det.dev_cmd.as_deref(),
            Some("php artisan serve --host=127.0.0.1 --port=8000")
        );
        assert_eq!(det.port, Some(8000));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8000"));

        let php_dir = tempfile::tempdir().unwrap();
        write(php_dir.path(), "index.php", "<?php echo 'hi'; ?>\n");
        let det = detect(php_dir.path());
        assert_eq!(det.framework.as_deref(), Some("php"));
        assert_eq!(det.dev_cmd.as_deref(), Some("php -S 127.0.0.1:8000"));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8000"));
    }

    #[test]
    fn go_web_server_detection() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "go.mod", "module example.com/app\ngo 1.22\n");
        write(dir.path(), "main.go", "package main\nfunc main() {}\n");
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("go"));
        assert_eq!(det.dev_cmd.as_deref(), Some("go run ."));
        assert_eq!(det.port, Some(8080));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8080"));

        let cmd_dir = tempfile::tempdir().unwrap();
        write(
            cmd_dir.path(),
            "go.mod",
            "module example.com/app\ngo 1.22\n",
        );
        write(
            cmd_dir.path(),
            "cmd/server/main.go",
            "package main\nfunc main() {}\n",
        );
        let det = detect(cmd_dir.path());
        assert_eq!(det.framework.as_deref(), Some("go"));
        assert_eq!(det.dev_cmd.as_deref(), Some("go run ."));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn spring_boot_maven_and_gradle_detection() {
        let maven = tempfile::tempdir().unwrap();
        write(
            maven.path(),
            "pom.xml",
            "<project><parent><artifactId>spring-boot-starter-parent</artifactId></parent></project>",
        );
        let det = detect(maven.path());
        assert_eq!(det.framework.as_deref(), Some("spring-boot"));
        assert_eq!(det.dev_cmd.as_deref(), Some("./mvnw spring-boot:run"));
        assert_eq!(det.port, Some(8080));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8080"));

        let gradle = tempfile::tempdir().unwrap();
        write(
            gradle.path(),
            "build.gradle.kts",
            "plugins { id(\"org.springframework.boot\") version \"3.3.0\" }\n",
        );
        let det = detect(gradle.path());
        assert_eq!(det.framework.as_deref(), Some("spring-boot"));
        assert_eq!(det.dev_cmd.as_deref(), Some("./gradlew bootRun"));
        assert_eq!(det.port, Some(8080));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn aspnet_detection() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "Storefront.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>",
        );
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("aspnet"));
        assert_eq!(det.dev_cmd.as_deref(), Some("dotnet run"));
        assert_eq!(det.port, Some(5000));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:5000"));
    }

    #[test]
    fn static_html_fallback_and_js_precedence() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "index.html", "<!doctype html><h1>Hello</h1>\n");
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("static"));
        assert_eq!(det.port, Some(8000));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8000"));

        let pub_dir = tempfile::tempdir().unwrap();
        write(pub_dir.path(), "public/index.html", "<h1>Static</h1>\n");
        let det = detect(pub_dir.path());
        assert_eq!(det.framework.as_deref(), Some("static"));
        assert_eq!(det.url.as_deref(), Some("http://127.0.0.1:8000"));

        // A JS project that also has `index.html` must still detect as Vite.
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"6"}}"#,
        );
        let det = detect(dir.path());
        assert_eq!(det.framework.as_deref(), Some("vite"));
        assert_eq!(det.port, Some(5173));
        assert_eq!(det.url.as_deref(), Some("http://localhost:5173"));
    }

    #[test]
    fn launch_json_skips_staging_prod_and_remote_api_configs() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"15"}}"#,
        );
        write(
            dir.path(),
            ".claude/launch.json",
            r#"{
                "configurations": [
                    {
                        "name": "client-portal-staging-api",
                        "runtimeExecutable": "env",
                        "runtimeArgs": ["NEXT_PUBLIC_API_URL=https://staging-api.example.com/api", "npm", "run", "dev"],
                        "port": 3100
                    },
                    {
                        "name": "web-prod",
                        "runtimeExecutable": "npm",
                        "runtimeArgs": ["run", "dev"],
                        "port": 3200
                    },
                    {
                        "name": "remote-env-entry",
                        "runtimeExecutable": "npm",
                        "runtimeArgs": ["run", "dev"],
                        "env": {"API_URL": "https://hosted.example.com/api"},
                        "port": 3300
                    },
                    {
                        "name": "remote-url-entry",
                        "runtimeExecutable": "npm",
                        "runtimeArgs": ["run", "dev"],
                        "url": "https://app.example.com"
                    }
                ]
            }"#,
        );
        let det = detect(dir.path());
        // None of the remote/staging/prod launch.json configs are imported; falls back to package.json.
        assert_eq!(det.dev_cmd.as_deref(), Some("npm run dev"));
        assert_eq!(det.port, Some(3000));
        assert_eq!(det.url.as_deref(), Some("http://localhost:3000"));
        assert!(
            det.notes
                .iter()
                .any(|n| n.contains("skipped non-local/staging/prod")),
            "{:?}",
            det.notes
        );
    }

    #[test]
    fn launch_json_prefers_matching_web_framework_over_first_desktop_preview() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"15"}}"#,
        );
        write(
            dir.path(),
            ".claude/launch.json",
            r#"{
                "configurations": [
                    {
                        "name": "seller-desktop-preview",
                        "runtimeExecutable": "npx",
                        "runtimeArgs": ["vite", "--port", "5174"],
                        "port": 5174
                    },
                    {
                        "name": "web-portal",
                        "cwd": "apps/web",
                        "runtimeExecutable": "npx",
                        "runtimeArgs": ["next", "dev", "-p", "3000"],
                        "port": 3000
                    }
                ]
            }"#,
        );
        let det = detect(dir.path());
        assert_eq!(det.port, Some(3000));
        assert_eq!(det.dev_cwd.as_deref(), Some("apps/web"));
        assert!(
            det.dev_cmd
                .as_deref()
                .is_some_and(|c| c.contains("next dev")),
            "{:?}",
            det.dev_cmd
        );
    }

    #[test]
    fn monorepo_workspaces_are_reported_when_root_has_no_direct_app() {
        // npm/yarn workspaces in package.json
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"private":true,"workspaces":["apps/*","packages/*"]}"#,
        );
        write(
            dir.path(),
            "apps/portal/package.json",
            r#"{"scripts":{"dev":"next dev"},"dependencies":{"next":"15"}}"#,
        );
        write(
            dir.path(),
            "apps/staff-portal/package.json",
            r#"{"scripts":{"dev":"next dev -p 3001"},"dependencies":{"next":"15"}}"#,
        );
        write(
            dir.path(),
            "packages/shared/package.json",
            r#"{"scripts":{"dev":"tsc --watch"}}"#,
        );
        let det = detect(dir.path());
        let note = det
            .notes
            .iter()
            .find(|n| n.starts_with("monorepo workspaces detected:"))
            .expect("monorepo note");
        assert!(note.contains("apps/portal"), "{note}");
        assert!(note.contains("apps/staff-portal"), "{note}");
        assert!(note.contains("--codebase <app-dir>"), "{note}");
        assert!(!note.contains("packages/shared"), "{note}");

        // pnpm-workspace.yaml without root package.json workspaces field
        let pnpm_dir = tempfile::tempdir().unwrap();
        write(
            pnpm_dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - 'apps/*'\n",
        );
        write(
            pnpm_dir.path(),
            "apps/web/package.json",
            r#"{"scripts":{"dev":"vite"},"devDependencies":{"vite":"6"}}"#,
        );
        let det_pnpm = detect(pnpm_dir.path());
        assert!(
            det_pnpm
                .notes
                .iter()
                .any(|n| n.contains("monorepo workspaces detected: apps/web")),
            "{:?}",
            det_pnpm.notes
        );
    }
}
