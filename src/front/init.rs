//! `brokenapp init`: set a project up for mapping.
//!
//! Writes `.brokenapp/config.toml` (no secrets), `.brokenapp/.gitignore`
//! (only `config.toml` and `map/` are committed), registers the project in
//! the global registry, and installs agent instructions.
//!
//! Secret inline assignments in the dev command (`DATABASE_URL=...`,
//! `*_KEY=...`, URLs with credentials) are never written: they move to
//! `[project] dev_env` as `"env:NAME"` references when this shell exports the
//! same value, otherwise init refuses and explains how to pass them.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use serde::Serialize;

use super::detect::{self, Detection};
use super::locality;
use super::project::{
    self, AuthSection, CONFIG_FILE, DEFAULT_READY_TIMEOUT_SECS, ProjectConfig, ProjectSection,
    ProjectTarget, Registry, RegistryEntry, STATE_DIR_NAME, ScanSection,
};
use super::secrets;

#[derive(Debug, Args)]
#[command(after_help = "\
Environment:
  BROKENAPP_HOME       Global state directory for registry.json and settings (default: ~/.brokenapp).
                       In sandboxed or isolated runs, set BROKENAPP_HOME=/tmp/brokenapp-home.")]
pub struct InitArgs {
    /// Local URL of the running app (e.g. http://127.0.0.1:3000). Detected from package.json when omitted.
    #[arg(long)]
    pub url: Option<String>,
    /// Command that starts the dev server (e.g. "npm run dev"). Detected when omitted.
    #[arg(long)]
    pub dev_cmd: Option<String>,
    /// Project name (default: directory name).
    #[arg(long)]
    pub name: Option<String>,
    /// Codebase root (default: current directory).
    #[arg(long, default_value = ".")]
    pub codebase: String,
    /// Install agent instructions (claude-code | agents-md | all | none).
    #[arg(long, default_value = "claude-code")]
    pub agent: String,
    /// Mark the project protected (map will refuse to scan it).
    #[arg(long)]
    pub protected: bool,
    /// Overwrite an existing config.
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

/// Agent instructions installed into `<repo>/.claude/skills/brokenapp/SKILL.md`.
const CLAUDE_CODE_SKILL: &str = include_str!("../../agent/claude-code/SKILL.md");

/// Agent instructions installed into `<repo>/AGENTS.md` (marker-delimited).
const AGENTS_SNIPPET: &str = include_str!("../../agent/AGENTS-snippet.md");
const AGENTS_START_MARKER: &str = "<!-- brokenapp:start -->";
const AGENTS_END_MARKER: &str = "<!-- brokenapp:end -->";

/// Keeps scan artifacts, history, sessions and stores out of git; commits
/// the config and the greppable map.
const GITIGNORE: &str = "\
# BrokenApp state. Commit config.toml and map/; everything else is local
# (raw scans, inventory history, saved sessions, SQLite stores).
/*
!/.gitignore
!/config.toml
!/map/
# Never commit role credentials or saved sessions.
/credentials.toml
/session/
";

#[derive(Debug, Serialize)]
struct InitReport {
    project: String,
    root: String,
    state_dir: String,
    config: String,
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dev_cmd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dev_cwd: Option<String>,
    /// `dev_env` written to the config (`env:NAME` references only).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    dev_env: std::collections::BTreeMap<String, String>,
    /// Secret assignments moved out of the dev command into `dev_env`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    moved_to_dev_env: Vec<String>,
    protected: bool,
    detected: Detection,
    files_written: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    files_kept: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    skill: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agents_md: Option<String>,
    registry: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    next: String,
}

/// Absolute path without requiring it to exist.
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir().context("current dir")?.join(path))
    }
}

/// `localhost:3000` → `http://localhost:3000`.
fn with_scheme(url: &str) -> String {
    let url = url.trim();
    if url.contains("://") {
        url.to_string()
    } else {
        format!("http://{url}")
    }
}

/// Canonical form of a path that may not exist yet (its parent is resolved).
fn canonical_lenient(path: &Path) -> PathBuf {
    if let Ok(p) = path.canonicalize() {
        return p;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => canonical_lenient(parent).join(name),
        _ => path.to_path_buf(),
    }
}

/// `codebase` value for the config: the root relative to the state dir's parent.
fn codebase_field(root: &Path, state_dir: &Path) -> String {
    let base = state_dir.parent().unwrap_or(state_dir);
    match root.strip_prefix(base) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
        Ok(rel) => rel.display().to_string(),
        Err(_) => root.display().to_string(),
    }
}

fn absolute_codebase_warning(codebase: &str) -> Option<String> {
    Path::new(codebase).is_absolute().then(|| {
        format!(
            "config.toml records an absolute codebase path ({codebase}); keep it local or use the default .brokenapp/ inside the repo before committing"
        )
    })
}

fn is_port_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u16>().is_ok_and(|p| p > 0)
}

/// Split `s` into `(start, end, token)` spans delimited by ASCII whitespace.
fn whitespace_tokens(s: &str) -> Vec<(usize, usize, &str)> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if start < i {
            out.push((start, i, &s[start..i]));
        }
    }
    out
}

/// Sync an explicit `--url` port into an auto-detected `dev_cmd` when the user
/// passed `--url` with a custom port without overriding `--dev-cmd`.
///
/// Returns `Some(updated_cmd)` when a port adjustment is applied, or `None`
/// when ports already match or the command shape is unrecognized.
fn sync_dev_cmd_port(
    cmd: &str,
    framework: Option<&str>,
    target_port: u16,
    detected_port: Option<u16>,
) -> Option<String> {
    if detected_port == Some(target_port) {
        return None;
    }
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    let tokens = whitespace_tokens(trimmed);
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut found_port_arg = false;
    let mut i = 0;
    while i < tokens.len() {
        let (start, end, tok) = tokens[i];
        if let Some(val) = tok.strip_prefix("PORT=")
            && is_port_digits(val)
        {
            found_port_arg = true;
            if val.parse::<u16>().ok() != Some(target_port) {
                edits.push((start, end, format!("PORT={target_port}")));
            }
            i += 1;
            continue;
        }
        if let Some((prefix, val)) = tok
            .strip_prefix("--port=")
            .map(|v| ("--port=", v))
            .or_else(|| tok.strip_prefix("-p=").map(|v| ("-p=", v)))
            && is_port_digits(val)
        {
            found_port_arg = true;
            if val.parse::<u16>().ok() != Some(target_port) {
                edits.push((start, end, format!("{prefix}{target_port}")));
            }
            i += 1;
            continue;
        }
        if matches!(tok, "-p" | "--port")
            && let Some(&(v_start, v_end, val)) = tokens.get(i + 1)
            && is_port_digits(val)
        {
            found_port_arg = true;
            if val.parse::<u16>().ok() != Some(target_port) {
                edits.push((v_start, v_end, target_port.to_string()));
            }
            i += 2;
            continue;
        }
        i += 1;
    }

    if found_port_arg {
        if edits.is_empty() {
            return None;
        }
        let mut out = String::with_capacity(trimmed.len() + 8);
        let mut pos = 0;
        for (start, end, replacement) in edits {
            out.push_str(&trimmed[pos..start]);
            out.push_str(&replacement);
            pos = end;
        }
        out.push_str(&trimmed[pos..]);
        return Some(out);
    }

    if tokens
        .iter()
        .any(|(_, _, t)| matches!(*t, "&&" | "||" | ";" | "|"))
        || trimmed.contains(';')
        || trimmed.contains('|')
        || trimmed.contains("&&")
    {
        return None;
    }

    // Skip leading inline `NAME=value` assignments (e.g. `HOST=127.0.0.1 npm run dev`).
    let cmd_idx = tokens.iter().position(|(_, _, tok)| {
        tok.split_once('=')
            .is_none_or(|(name, _)| !is_env_var_name(name))
    })?;
    let words: Vec<&str> = tokens[cmd_idx..].iter().map(|(_, _, t)| *t).collect();
    let bin = words[0].rsplit('/').next().unwrap_or(words[0]);
    let second = words.get(1).copied();
    let third = words.get(2).copied();

    // Direct dev-server binaries.
    if bin == "next" && second == Some("dev") {
        return Some(format!("{trimmed} -p {target_port}"));
    }
    if (bin == "vite" && !matches!(second, Some("build" | "preview")))
        || (matches!(bin, "astro" | "nuxt" | "nuxi") && second == Some("dev"))
    {
        return Some(format!("{trimmed} --port {target_port}"));
    }

    // Package-manager dev scripts (`PORT` is classified Sensitivity::Public).
    let is_pm_script = match (bin, second, third) {
        ("npm" | "pnpm" | "yarn" | "bun", Some("run"), Some("dev" | "start")) => true,
        ("pnpm" | "yarn" | "bun", Some("dev"), _) => true,
        ("npm" | "pnpm" | "yarn" | "bun", Some("start"), _) => true,
        _ => false,
    };
    if is_pm_script {
        return Some(format!("PORT={target_port} {trimmed}"));
    }

    if framework == Some("rails")
        && (trimmed == "bin/rails server" || trimmed == "bundle exec rails server")
    {
        return Some(format!("{trimmed} -p {target_port}"));
    }

    None
}

fn render_config(cfg: &ProjectConfig) -> Result<String> {
    let body = toml::to_string_pretty(cfg).context("serialize project config")?;
    Ok(format!(
        "# BrokenApp project config. Commit this file; never put secrets in it.\n\
         # dev_env values must be \"env:NAME\" references to your shell environment.\n\
         # scan.write_guard: block (default) | stub | off. `brokenapp map --help` for flags.\n\
         # Optional [scan] crawl knobs: max_interaction_depth (default 2; raise for wizards),\n\
         # max_interactions_per_view (default 25), settle_ms (default 2000), tabs (default 4).\n\
         # [scan] mode = \"full\" maps the whole app (no time/view caps; can take hours).\n\
         # Login roles: `brokenapp roles add admin --login-url /sign-in` adds a [[roles]] entry\n\
         # (env: references only; values go to the gitignored credentials.toml).\n\n{body}"
    ))
}

/// Write `contents` to `path` unless it exists (or `force`). Returns whether it was written.
fn write_file(path: &Path, contents: &str, force: bool) -> Result<bool> {
    if path.exists() && !force {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

/// Create or update `<root>/AGENTS.md` using the `<!-- brokenapp:start -->` /
/// `<!-- brokenapp:end -->` markers. Returns whether the file was written.
fn write_agents_md(path: &Path, force: bool) -> Result<bool> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(path, AGENTS_SNIPPET)
            .with_context(|| format!("write {}", path.display()))?;
        return Ok(true);
    }
    let existing =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if let Some(start) = existing.find(AGENTS_START_MARKER)
        && let Some(rel_end) = existing[start..].find(AGENTS_END_MARKER)
    {
        if !force {
            return Ok(false);
        }
        let end = start + rel_end + AGENTS_END_MARKER.len();
        let mut updated = String::with_capacity(existing.len() + AGENTS_SNIPPET.len());
        updated.push_str(&existing[..start]);
        updated.push_str(AGENTS_SNIPPET.trim());
        updated.push_str(&existing[end..]);
        std::fs::write(path, updated).with_context(|| format!("write {}", path.display()))?;
        return Ok(true);
    }
    let base = existing.trim_end_matches('\n');
    let updated = if base.is_empty() {
        AGENTS_SNIPPET.to_string()
    } else {
        format!("{base}\n\n{AGENTS_SNIPPET}")
    };
    std::fs::write(path, updated).with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

fn is_env_var_name(name: &str) -> bool {
    !name.is_empty()
        && !name.as_bytes()[0].is_ascii_digit()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Scrub secret `NAME=value` tokens and URL credentials from a free-form string
/// (such as a detection note or inner quoted command string).
fn scrub_inline_secrets(text: &str) -> String {
    let out = secrets::redact_url_credentials(text);
    let bytes = out.as_bytes();
    let mut result = String::with_capacity(out.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            result.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let token = &out[start..i];
        let trimmed_start = token
            .bytes()
            .take_while(|b| matches!(b, b'\'' | b'"' | b'(' | b'['))
            .count();
        let trimmed_end = token
            .bytes()
            .rev()
            .take_while(|b| matches!(b, b'\'' | b'"' | b')' | b']' | b';' | b','))
            .count();
        let inner_end = token.len().saturating_sub(trimmed_end);
        let core = if trimmed_start < inner_end {
            &token[trimmed_start..inner_end]
        } else {
            ""
        };
        if let Some((name, val)) = core.split_once('=')
            && is_env_var_name(name)
            && secrets::classify(name, val) == secrets::Sensitivity::Secret
        {
            result.push_str(&token[..trimmed_start]);
            result.push_str(name);
            result.push('=');
            result.push_str(secrets::REDACTED);
            result.push_str(&token[inner_end..]);
        } else {
            result.push_str(&secrets::redact_url_credentials(token));
        }
    }
    result
}

const GENERIC_APP_DIRS: &[&str] = &[
    "web", "app", "apps", "frontend", "client", "portal", "site", "ui", "www",
];

/// Derive a default project name from `root`. Generic monorepo leaf names
/// (`web`, `app`, `frontend`, ...) combine with the enclosing repo name
/// (skipping intermediate `apps`/`packages` segments), e.g.
/// `/.../acme-shop/apps/web` -> `acme-shop-web`.
fn default_project_name(root: &Path) -> Option<String> {
    let leaf = root
        .file_name()
        .map(|n| n.to_string_lossy().trim().to_string())
        .filter(|n| !n.is_empty())?;
    let leaf_lower = leaf.to_ascii_lowercase();
    if !GENERIC_APP_DIRS.contains(&leaf_lower.as_str()) {
        return Some(leaf);
    }
    let mut cur = root.parent();
    while let Some(dir) = cur {
        if let Some(parent_name) = dir
            .file_name()
            .map(|n| n.to_string_lossy().trim().to_string())
            .filter(|n| !n.is_empty())
        {
            let parent_lower = parent_name.to_ascii_lowercase();
            if !matches!(parent_lower.as_str(), "apps" | "packages") {
                return Some(format!("{parent_lower}-{leaf_lower}"));
            }
        }
        cur = dir.parent();
    }
    Some(leaf)
}

/// Redact secrets from a detected or effective dev command, including quoted
/// assignments (e.g. `shell_words::join` output) and `-c` subshell strings.
/// Leaves non-secret-classified assignments intact so `InitReport` JSON stays
/// consistent with what is written to `config.toml`.
fn sanitize_detected_cmd(raw: &str) -> String {
    let redacted = secrets::scan(raw).redact_secrets_only();
    if let Ok(words) = shell_words::split(&redacted) {
        let mut changed = false;
        let mut prev: Option<String> = None;
        let mut scrubbed = Vec::with_capacity(words.len());
        for w in words {
            let next_word = if matches!(prev.as_deref(), Some("-c" | "-lc" | "-cl")) {
                let inner = scrub_inline_secrets(&secrets::scan(&w).redact_secrets_only());
                if inner != w {
                    changed = true;
                }
                inner
            } else if let Some((name, val)) = w.split_once('=')
                && is_env_var_name(name)
                && secrets::classify(name, val) == secrets::Sensitivity::Secret
                && val != secrets::REDACTED
            {
                changed = true;
                format!("{name}={}", secrets::REDACTED)
            } else {
                let inner = scrub_inline_secrets(&w);
                if inner != w {
                    changed = true;
                }
                inner
            };
            prev = Some(next_word.clone());
            scrubbed.push(next_word);
        }
        if changed {
            return shell_words::join(&scrubbed);
        }
    }
    scrub_inline_secrets(&redacted)
}

/// Produce a secret-free copy of `Detection` safe for `InitReport` / `--json`.
fn sanitize_detection(
    detected: &Detection,
    effective_dev_cmd: Option<&str>,
    dev_cmd_overridden: bool,
) -> Detection {
    let dev_cmd = if !dev_cmd_overridden {
        effective_dev_cmd.map(sanitize_detected_cmd)
    } else {
        detected.dev_cmd.as_deref().map(sanitize_detected_cmd)
    };
    let url = detected.url.as_deref().map(secrets::redact_url_credentials);
    let notes = detected
        .notes
        .iter()
        .map(|n| scrub_inline_secrets(n))
        .collect();
    Detection {
        framework: detected.framework.clone(),
        package_manager: detected.package_manager.clone(),
        dev_cmd,
        dev_cwd: detected.dev_cwd.clone(),
        port: detected.port,
        url,
        notes,
    }
}

fn permission_denied_io(err: &anyhow::Error) -> Option<&std::io::Error> {
    err.chain().find_map(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .filter(|io| io.kind() == ErrorKind::PermissionDenied)
    })
}

fn registry_access_error(action: &str, path: &Path, err: &dyn std::fmt::Display) -> anyhow::Error {
    anyhow!(
        "cannot {action} global registry {} ({err}); if running in a sandbox, set BROKENAPP_HOME=/tmp/brokenapp-home (or another writable directory)",
        path.display()
    )
}

/// Verify that `path` (the global project registry) can be created or written
/// before `init` mutates the project directory, so a read-only `$BROKENAPP_HOME`
/// does not strand an unregistered `.brokenapp/config.toml`.
fn ensure_registry_writable(path: &Path) -> Result<()> {
    match std::fs::metadata(path) {
        Ok(_) => {
            return match std::fs::OpenOptions::new().write(true).open(path) {
                Ok(_) => Ok(()),
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    Err(registry_access_error("write", path, &err))
                }
                Err(err) => Err(err).with_context(|| format!("write {}", path.display())),
            };
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            return Err(registry_access_error("write", path, &err));
        }
        Err(_) => {}
    }

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    match std::fs::metadata(parent) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            bail!(
                "cannot write global registry {} ({} exists and is not a directory); if running in a sandbox, set BROKENAPP_HOME=/tmp/brokenapp-home (or another writable directory)",
                path.display(),
                parent.display()
            );
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            return Err(registry_access_error("write", path, &err));
        }
        Err(_) => {
            if let Err(err) = std::fs::create_dir_all(parent) {
                if matches!(
                    err.kind(),
                    ErrorKind::AlreadyExists | ErrorKind::PermissionDenied
                ) {
                    return Err(registry_access_error("write", path, &err));
                }
                return Err(err).with_context(|| format!("create {}", parent.display()));
            }
        }
    }
    match tempfile::NamedTempFile::new_in(parent) {
        Ok(probe) => {
            drop(probe);
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            Err(registry_access_error("write", path, &err))
        }
        Err(err) => Err(err).with_context(|| format!("write {}", path.display())),
    }
}

fn build_init_report(
    args: &InitArgs,
    lookup_env: impl Fn(&str) -> Option<String>,
    registry_override: Option<&Path>,
) -> Result<InitReport> {
    let root = Path::new(&args.codebase)
        .canonicalize()
        .with_context(|| format!("codebase {}", args.codebase))?;
    let state_dir = match &args.target.state_dir {
        Some(dir) => canonical_lenient(&absolute(dir)?),
        None => canonical_lenient(&root.join(STATE_DIR_NAME)),
    };
    let state_dir_str = state_dir.display().to_string();
    let config_path = state_dir.join(CONFIG_FILE);
    let agent = args.agent.trim().to_ascii_lowercase();
    if !matches!(agent.as_str(), "claude-code" | "agents-md" | "all" | "none") {
        bail!(
            "unknown --agent {:?} (expected claude-code, agents-md, all, or none)",
            args.agent
        );
    }

    let (mut registry, registry_path) = match registry_override {
        Some(path) => {
            let reg = match std::fs::metadata(path) {
                Ok(_) => {
                    let raw = std::fs::read_to_string(path).map_err(|err| {
                        if err.kind() == ErrorKind::PermissionDenied {
                            registry_access_error("read", path, &err)
                        } else {
                            anyhow::Error::new(err).context(format!("read {}", path.display()))
                        }
                    })?;
                    serde_json::from_str(&raw)
                        .with_context(|| format!("parse {}", path.display()))?
                }
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    return Err(registry_access_error("read", path, &err));
                }
                Err(_) => Registry::default(),
            };
            (reg, path.to_path_buf())
        }
        None => {
            let path = Registry::path();
            let reg = Registry::load().map_err(|err| {
                if let Some(io_err) = permission_denied_io(&err) {
                    registry_access_error("read", &path, io_err)
                } else {
                    err
                }
            })?;
            (reg, path)
        }
    };

    let recovered_ctx = if config_path.exists() && !args.force {
        let already_registered = registry.projects.iter().any(|e| {
            e.state_dir == state_dir_str
                || Path::new(&e.state_dir).canonicalize().ok().as_deref()
                    == Some(state_dir.as_path())
        });
        if already_registered {
            bail!(
                "{} already exists; pass --force to overwrite it",
                config_path.display()
            );
        }
        match project::load_ctx(&state_dir) {
            Ok(ctx) => Some(ctx),
            Err(_) => bail!(
                "{} already exists; pass --force to overwrite it",
                config_path.display()
            ),
        }
    } else {
        None
    };

    let mut detected = detect::detect(&root);
    let (
        name,
        url,
        codebase,
        dev_cmd,
        dev_cwd,
        dev_env,
        moved_to_dev_env,
        protected,
        dev_cmd_overridden,
        cfg_to_write,
    ) = if let Some(existing) = recovered_ctx {
        let project = existing.config.project;
        (
            project.name,
            project.url,
            project.codebase,
            project.dev_cmd,
            project.dev_cwd,
            project.dev_env,
            Vec::new(),
            project.protected,
            false,
            None,
        )
    } else {
        let name = args
            .name
            .clone()
            .or_else(|| args.target.project.clone())
            .or_else(|| default_project_name(&root))
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .context("could not derive a project name; pass --name")?;
        let url = args
            .url
            .clone()
            .or_else(|| detected.url.clone())
            .with_context(|| {
                let hints: Vec<&str> = detected
                    .notes
                    .iter()
                    .filter(|n| {
                        n.starts_with("monorepo workspaces detected:")
                            || n.starts_with("skipped non-local")
                    })
                    .map(String::as_str)
                    .collect();
                if hints.is_empty() {
                    "could not detect the app URL; pass --url http://localhost:<port>".to_string()
                } else {
                    format!(
                        "could not detect the app URL; pass --url http://localhost:<port> ({})",
                        hints.join("; ")
                    )
                }
            })?;
        let url = with_scheme(&url);
        let parsed_url = locality::parse_target_url(&url, false)
            .with_context(|| "init only records local development URLs")?;
        let url = parsed_url.to_string();
        let dev_cmd_overridden = args.dev_cmd.is_some();
        let (dev_cmd, dev_cwd) = match &args.dev_cmd {
            Some(cmd) => (Some(cmd.trim().to_string()).filter(|c| !c.is_empty()), None),
            None => {
                let mut cmd = detected.dev_cmd.clone();
                if args.url.is_some()
                    && let Some(target_port) = parsed_url.port()
                    && let Some(synced) = detected.dev_cmd.as_deref().and_then(|raw_cmd| {
                        sync_dev_cmd_port(
                            raw_cmd,
                            detected.framework.as_deref(),
                            target_port,
                            detected.port,
                        )
                    })
                {
                    detected
                        .notes
                        .push(format!("synced --url port {target_port} into dev_cmd"));
                    cmd = Some(synced);
                }
                (cmd, detected.dev_cwd.clone())
            }
        };
        // Never write secret values: move them to `env:` references or refuse.
        let mut dev_env = std::collections::BTreeMap::new();
        let mut moved_to_dev_env = Vec::new();
        let dev_cmd = match dev_cmd {
            Some(cmd) => {
                let out = secrets::externalize(&cmd, &lookup_env).map_err(anyhow::Error::msg)?;
                for name in &out.moved {
                    dev_env.insert(name.clone(), format!("env:{name}"));
                }
                moved_to_dev_env = out.moved;
                Some(out.command)
            }
            None => None,
        };
        let codebase = codebase_field(&root, &state_dir);
        let cfg = ProjectConfig {
            project: ProjectSection {
                name: name.clone(),
                url: url.clone(),
                codebase: codebase.clone(),
                dev_cmd: dev_cmd.clone(),
                dev_cwd: dev_cwd.clone(),
                dev_env: dev_env.clone(),
                ready_timeout_secs: DEFAULT_READY_TIMEOUT_SECS,
                protected: args.protected,
            },
            scan: ScanSection::default(),
            auth: AuthSection::default(),
            roles: Vec::new(),
        };
        (
            name,
            url,
            codebase,
            dev_cmd,
            dev_cwd,
            dev_env,
            moved_to_dev_env,
            args.protected,
            dev_cmd_overridden,
            Some(cfg),
        )
    };
    let warnings: Vec<String> = absolute_codebase_warning(&codebase).into_iter().collect();

    if let Some(other) = registry
        .find(&name)
        .filter(|e| e.state_dir != state_dir_str)
    {
        if !args.force {
            bail!(
                "project name '{name}' is already registered for {} (see `brokenapp projects`); pass --name <other> or --force to replace it",
                other.root
            );
        }
    }

    ensure_registry_writable(&registry_path)?;

    let mut written = Vec::new();
    let mut kept = Vec::new();
    let mut record = |path: &Path, did_write: bool| {
        let s = path.display().to_string();
        if did_write {
            written.push(s);
        } else {
            kept.push(s);
        }
    };
    if let Some(cfg) = cfg_to_write {
        record(
            &config_path,
            write_file(&config_path, &render_config(&cfg)?, true)?,
        );
    } else {
        record(&config_path, false);
    }
    let gitignore = state_dir.join(".gitignore");
    record(&gitignore, write_file(&gitignore, GITIGNORE, args.force)?);
    let map_dir = state_dir.join("map");
    std::fs::create_dir_all(&map_dir).with_context(|| format!("create {}", map_dir.display()))?;

    let skill = if matches!(agent.as_str(), "claude-code" | "all") {
        let path = root
            .join(".claude")
            .join("skills")
            .join("brokenapp")
            .join("SKILL.md");
        record(&path, write_file(&path, CLAUDE_CODE_SKILL, args.force)?);
        Some(path.display().to_string())
    } else {
        None
    };

    let agents_md = if matches!(agent.as_str(), "agents-md" | "all") {
        let path = root.join("AGENTS.md");
        record(&path, write_agents_md(&path, args.force)?);
        Some(path.display().to_string())
    } else {
        None
    };

    let previous = registry
        .projects
        .iter()
        .find(|e| e.state_dir == state_dir_str)
        .cloned();
    registry.upsert(RegistryEntry {
        name: name.clone(),
        root: root.display().to_string(),
        state_dir: state_dir_str.clone(),
        url: url.clone(),
        protected,
        last_scan_at: previous.as_ref().and_then(|p| p.last_scan_at.clone()),
        last_summary: previous.and_then(|p| p.last_summary),
    });
    match registry_override {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            let raw = serde_json::to_string_pretty(&registry).context("serialize registry")?;
            std::fs::write(path, raw).with_context(|| format!("write {}", path.display()))?;
        }
        None => registry.save().map_err(|err| {
            if let Some(io_err) = permission_denied_io(&err) {
                registry_access_error("write", &registry_path, io_err)
            } else {
                err
            }
        })?,
    }

    // Validate what we wrote round-trips through the loader `map` uses.
    project::load_ctx(&state_dir).context("re-read the written config")?;

    // The first map is the baseline every later changelog diffs against, so
    // it should be a standard baseline map, not a partial slice.
    let state_flag = args
        .target
        .state_dir
        .as_ref()
        .map(|_| format!(" --state-dir {}", shell_words::quote(&state_dir_str)))
        .unwrap_or_default();
    let next = if protected {
        "project is protected: `brokenapp map` will refuse to scan it".to_string()
    } else if dev_cmd.is_some() {
        format!(
            "brokenapp map{state_flag}   (baseline standard map; starts the dev server if it is not running)"
        )
    } else {
        format!("start the app at {url}, then run: brokenapp map{state_flag}")
    };
    let detected_report = sanitize_detection(&detected, dev_cmd.as_deref(), dev_cmd_overridden);
    Ok(InitReport {
        project: name,
        root: root.display().to_string(),
        state_dir: state_dir_str,
        config: config_path.display().to_string(),
        url,
        dev_cmd: dev_cmd.as_deref().map(sanitize_detected_cmd),
        dev_cwd,
        dev_env,
        moved_to_dev_env,
        protected,
        detected: detected_report,
        files_written: written,
        files_kept: kept,
        skill,
        agents_md,
        registry: registry_path.display().to_string(),
        warnings,
        next,
    })
}

pub async fn run(args: InitArgs) -> Result<i32> {
    let report = build_init_report(&args, |name| std::env::var(name).ok(), None)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize init report")?
        );
        return Ok(0);
    }
    println!("Initialized BrokenApp project '{}'", report.project);
    println!("  url       {}", report.url);
    println!(
        "  dev cmd   {}",
        report
            .dev_cmd
            .as_deref()
            .unwrap_or("(none; start the app yourself or pass --dev-cmd)")
    );
    for name in &report.moved_to_dev_env {
        println!(
            "  dev env   {name} = \"env:{name}\" (moved out of the dev command; read from your shell)"
        );
    }
    if let Some(fw) = &report.detected.framework {
        println!("  framework {fw}");
    }
    for note in &report.detected.notes {
        println!("  detected  {note}");
    }
    println!("  config    {}", report.config);
    if let Some(agents_md) = &report.agents_md {
        let note = if report.files_written.contains(agents_md) {
            "written"
        } else {
            "kept; exists, --force to update"
        };
        println!("  agents.md {agents_md} ({note})");
    }
    for f in report
        .files_written
        .iter()
        .filter(|f| **f != report.config && report.agents_md.as_deref() != Some(f.as_str()))
    {
        println!("  wrote     {f}");
    }
    for f in report
        .files_kept
        .iter()
        .filter(|f| report.agents_md.as_deref() != Some(f.as_str()))
    {
        println!("  kept      {f} (exists; --force to overwrite)");
    }
    println!("  registry  {}", report.registry);
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    println!("next: {}", report.next);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_without_scheme_default_to_http() {
        assert_eq!(with_scheme("localhost:3000"), "http://localhost:3000");
        assert_eq!(with_scheme(" https://app.test "), "https://app.test");
    }

    #[test]
    fn codebase_field_is_relative_to_state_parent() {
        assert_eq!(
            codebase_field(Path::new("/r/app"), Path::new("/r/app/.brokenapp")),
            "."
        );
        assert_eq!(
            codebase_field(Path::new("/r/app/web"), Path::new("/r/app/.brokenapp")),
            "web"
        );
        assert_eq!(
            codebase_field(Path::new("/r/app"), Path::new("/elsewhere/.brokenapp")),
            "/r/app"
        );
    }

    #[test]
    fn rendered_config_round_trips_without_secrets() {
        let mut cfg = ProjectConfig {
            project: ProjectSection {
                name: "demo".into(),
                url: "http://localhost:3000/".into(),
                codebase: ".".into(),
                dev_cmd: Some("npm run dev".into()),
                ready_timeout_secs: 120,
                ..Default::default()
            },
            ..Default::default()
        };
        cfg.project
            .dev_env
            .insert("DATABASE_URL".into(), "env:DATABASE_URL".into());
        let raw = render_config(&cfg).unwrap();
        let parsed: ProjectConfig = toml::from_str(&raw).unwrap();
        assert_eq!(parsed, cfg);
        assert!(raw.contains("write_guard = \"block\""));
    }

    #[test]
    fn gitignore_commits_only_config_and_map() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(repo)
                .output()
        };
        let Ok(out) = git(&["init", "-q"]) else {
            return; // git not installed
        };
        if !out.status.success() {
            return;
        }
        let state = repo.join(STATE_DIR_NAME);
        for rel in [
            "config.toml",
            "map/UI-MAP.md",
            "history/latest.inventory.json",
            "scans/20261021T000000Z/scan/spec.json",
            "session/state.json",
            "store.db",
            "credentials.toml",
            "map/roles/admin/UI-MAP.md",
        ] {
            let p = state.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        std::fs::write(state.join(".gitignore"), GITIGNORE).unwrap();
        let ignored = |rel: &str| {
            git(&["check-ignore", "-q", &format!("{STATE_DIR_NAME}/{rel}")])
                .unwrap()
                .status
                .success()
        };
        assert!(!ignored("config.toml"));
        assert!(!ignored(".gitignore"));
        assert!(!ignored("map/UI-MAP.md"));
        assert!(ignored("history/latest.inventory.json"));
        assert!(ignored("scans/20261021T000000Z/scan/spec.json"));
        assert!(ignored("session/state.json"));
        assert!(ignored("store.db"));
        assert!(ignored("credentials.toml"));
        assert!(!ignored("map/roles/admin/UI-MAP.md"));
        // The generated file already has the explicit private lines.
        assert!(
            super::super::roles::ensure_private_ignored(&state)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn skill_is_embedded() {
        assert!(!CLAUDE_CODE_SKILL.trim().is_empty());
    }

    #[test]
    fn agents_snippet_is_embedded_with_markers() {
        assert!(!AGENTS_SNIPPET.trim().is_empty());
        assert!(AGENTS_SNIPPET.contains(AGENTS_START_MARKER));
        assert!(AGENTS_SNIPPET.contains(AGENTS_END_MARKER));
    }

    fn base_init_args(root: &Path, agent: &str) -> InitArgs {
        InitArgs {
            url: Some("http://127.0.0.1:3000".to_string()),
            dev_cmd: Some("npm run dev".to_string()),
            name: Some("demo".to_string()),
            codebase: root.display().to_string(),
            agent: agent.to_string(),
            protected: false,
            force: false,
            json: true,
            target: ProjectTarget::default(),
        }
    }

    #[test]
    fn agents_md_create_append_keep_and_force_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");

        // 1. Missing file -> created with snippet.
        assert!(write_agents_md(&path, false).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), AGENTS_SNIPPET);

        // 2. Existing markers without --force -> kept untouched.
        let custom = format!(
            "# Repo Rules\n\nBefore marker.\n\n{AGENTS_START_MARKER}\nSTALE SECTION\n{AGENTS_END_MARKER}\n\nAfter marker.\n"
        );
        std::fs::write(&path, &custom).unwrap();
        assert!(!write_agents_md(&path, false).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), custom);

        // 3. Existing markers with --force -> replaces only marked section.
        assert!(write_agents_md(&path, true).unwrap());
        let replaced = std::fs::read_to_string(&path).unwrap();
        assert!(replaced.starts_with("# Repo Rules\n\nBefore marker.\n\n"));
        assert!(replaced.ends_with("\n\nAfter marker.\n"));
        assert!(!replaced.contains("STALE SECTION"));
        assert!(replaced.contains(AGENTS_SNIPPET.trim()));

        // 4. Existing file without markers -> appended with blank line separator.
        let existing_no_markers = "# Existing Agents\nFollow style guide.\n";
        std::fs::write(&path, existing_no_markers).unwrap();
        assert!(write_agents_md(&path, false).unwrap());
        let appended = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            appended,
            format!("# Existing Agents\nFollow style guide.\n\n{AGENTS_SNIPPET}")
        );
    }

    #[test]
    fn init_supports_agents_md_and_all_agent_modes() {
        let dir = tempfile::tempdir().unwrap();
        let reg = dir.path().join("registry.json");

        // `--agent agents-md` creates AGENTS.md and does not create SKILL.md.
        let repo_a = dir.path().join("repo-a");
        std::fs::create_dir_all(&repo_a).unwrap();
        let args_a = base_init_args(&repo_a, "agents-md");
        let report_a = build_init_report(&args_a, |_| None, Some(&reg)).unwrap();
        assert!(report_a.skill.is_none());
        let agents_path_a = repo_a.canonicalize().unwrap().join("AGENTS.md");
        assert_eq!(
            report_a.agents_md.as_deref(),
            Some(agents_path_a.to_str().unwrap())
        );
        assert!(agents_path_a.is_file());
        assert!(!repo_a.join(".claude/skills/brokenapp/SKILL.md").exists());
        assert_eq!(
            report_a.next,
            "brokenapp map   (baseline standard map; starts the dev server if it is not running)"
        );

        // Re-running with `--force` updates the marked section while keeping surrounding text.
        std::fs::write(
            &agents_path_a,
            format!("TOP\n{AGENTS_START_MARKER}\nOLD\n{AGENTS_END_MARKER}\nBOTTOM\n"),
        )
        .unwrap();
        let mut force_args = base_init_args(&repo_a, "agents-md");
        force_args.force = true;
        let report_force = build_init_report(&force_args, |_| None, Some(&reg)).unwrap();
        let updated = std::fs::read_to_string(&agents_path_a).unwrap();
        assert!(updated.contains("TOP\n") && updated.contains("\nBOTTOM\n"));
        assert!(!updated.contains("\nOLD\n"));
        assert!(updated.contains(AGENTS_SNIPPET.trim()));
        assert!(
            report_force
                .files_written
                .iter()
                .any(|p| p == agents_path_a.to_str().unwrap())
        );

        // `--agent all` writes both SKILL.md and AGENTS.md.
        let repo_b = dir.path().join("repo-b");
        std::fs::create_dir_all(&repo_b).unwrap();
        let mut args_b = base_init_args(&repo_b, "all");
        args_b.name = Some("demo-b".to_string());
        let report_b = build_init_report(&args_b, |_| None, Some(&reg)).unwrap();
        assert!(report_b.skill.is_some());
        assert!(report_b.agents_md.is_some());
        assert!(repo_b.join(".claude/skills/brokenapp/SKILL.md").is_file());
        assert!(repo_b.join("AGENTS.md").is_file());

        // Unknown `--agent` is rejected with the full option list.
        let repo_c = dir.path().join("repo-c");
        std::fs::create_dir_all(&repo_c).unwrap();
        let args_c = base_init_args(&repo_c, "bogus");
        let err = build_init_report(&args_c, |_| None, Some(&reg)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("agents-md") && msg.contains("all"), "{msg}");
    }

    #[test]
    fn init_json_never_leaks_secrets_from_detected_launch_json() {
        const LAUNCH_SECRET: &str = "super_secret_launch_key_99123";
        const URL_SECRET: &str = "launch_url_pw_77889";
        let dir = tempfile::tempdir().unwrap();
        let reg = dir.path().join("registry.json");

        // Case 1: launch.json has an inline API_KEY exported in env, no `--dev-cmd` override.
        let repo_env = dir.path().join("repo-env");
        std::fs::create_dir_all(repo_env.join(".claude")).unwrap();
        std::fs::write(
            repo_env.join(".claude/launch.json"),
            format!(
                r#"{{
                    "configurations": [{{
                        "name": "web",
                        "runtimeExecutable": "env",
                        "runtimeArgs": ["API_KEY={LAUNCH_SECRET}", "npm", "run", "dev"],
                        "port": 3000
                    }}]
                }}"#
            ),
        )
        .unwrap();
        let args_env = InitArgs {
            url: None,
            dev_cmd: None,
            name: Some("launch-env".to_string()),
            codebase: repo_env.display().to_string(),
            agent: "none".to_string(),
            protected: false,
            force: false,
            json: true,
            target: ProjectTarget::default(),
        };
        let report_env = build_init_report(
            &args_env,
            |k| (k == "API_KEY").then(|| LAUNCH_SECRET.to_string()),
            Some(&reg),
        )
        .unwrap();
        let json_env = serde_json::to_string_pretty(&report_env).unwrap();
        assert!(
            !json_env.contains(LAUNCH_SECRET),
            "raw secret leaked in init --json:\n{json_env}"
        );
        assert_eq!(report_env.moved_to_dev_env, vec!["API_KEY".to_string()]);
        assert_eq!(
            report_env.dev_env.get("API_KEY").map(String::as_str),
            Some("env:API_KEY")
        );

        // Case 2: launch.json has inline API_KEY and URL password, overridden via CLI flags.
        let repo_override = dir.path().join("repo-override");
        std::fs::create_dir_all(repo_override.join(".claude")).unwrap();
        std::fs::write(
            repo_override.join(".claude/launch.json"),
            format!(
                r#"{{
                    "configurations": [{{
                        "name": "API_KEY={LAUNCH_SECRET}",
                        "runtimeExecutable": "env",
                        "runtimeArgs": ["API_KEY={LAUNCH_SECRET}", "npm", "run", "dev"],
                        "url": "http://admin:{URL_SECRET}@127.0.0.1:3000"
                    }}]
                }}"#
            ),
        )
        .unwrap();
        let args_override = InitArgs {
            url: Some("http://127.0.0.1:3000".to_string()),
            dev_cmd: Some("npm run dev".to_string()),
            name: Some("launch-override".to_string()),
            codebase: repo_override.display().to_string(),
            agent: "none".to_string(),
            protected: false,
            force: false,
            json: true,
            target: ProjectTarget::default(),
        };
        let report_override = build_init_report(&args_override, |_| None, Some(&reg)).unwrap();
        let json_override = serde_json::to_string_pretty(&report_override).unwrap();
        assert!(
            !json_override.contains(LAUNCH_SECRET),
            "raw secret leaked in overridden init --json:\n{json_override}"
        );
        assert!(
            !json_override.contains(URL_SECRET),
            "URL password leaked in overridden init --json:\n{json_override}"
        );
        assert!(
            report_override
                .detected
                .dev_cmd
                .as_deref()
                .is_some_and(|c| c.contains("API_KEY=***")),
            "{:?}",
            report_override.detected.dev_cmd
        );
    }

    #[test]
    fn default_name_prefixes_generic_monorepo_folders() {
        assert_eq!(
            default_project_name(Path::new("/workspace/acme-shop/apps/web")).as_deref(),
            Some("acme-shop-web")
        );
        assert_eq!(
            default_project_name(Path::new("/workspace/acme/packages/ui")).as_deref(),
            Some("acme-ui")
        );
        assert_eq!(
            default_project_name(Path::new("/workspace/acme/frontend")).as_deref(),
            Some("acme-frontend")
        );
        assert_eq!(
            default_project_name(Path::new("/workspace/monorepo/apps/billing")).as_deref(),
            Some("billing")
        );
    }

    #[test]
    fn init_with_state_dir_uses_canonical_paths_and_includes_flag_in_next_and_matches_config_dev_cmd()
     {
        let dir = tempfile::tempdir().unwrap();
        let reg = dir.path().join("registry.json");
        let app_root = dir.path().join("acme-shop/apps/web");
        std::fs::create_dir_all(&app_root).unwrap();
        let state_dir = dir.path().join("custom-state/web");
        let dev_cmd = "NEXT_PUBLIC_API_URL=https://api.example.com/api npm run dev";

        let mut args = base_init_args(&app_root, "none");
        args.name = None;
        args.dev_cmd = Some(dev_cmd.to_string());
        args.target.state_dir = Some(state_dir);

        let report = build_init_report(&args, |_| None, Some(&reg)).unwrap();
        assert_eq!(report.project, "acme-shop-web");
        // config and files_written all share the canonical state_dir prefix.
        assert!(
            report.config.starts_with(&report.state_dir),
            "config={} state_dir={}",
            report.config,
            report.state_dir
        );
        assert!(
            report
                .files_written
                .iter()
                .all(|f| f.starts_with(&report.state_dir)),
            "files_written={:?} state_dir={}",
            report.files_written,
            report.state_dir
        );
        // next hint carries --state-dir <path>.
        assert!(
            report.next.contains(&format!(
                "--state-dir {}",
                shell_words::quote(&report.state_dir)
            )),
            "next={}",
            report.next
        );
        // Non-secret-classified remote URL is not silently masked differently between config.toml and JSON.
        let written_cfg = std::fs::read_to_string(&report.config).unwrap();
        assert!(written_cfg.contains(dev_cmd), "{written_cfg}");
        assert_eq!(report.dev_cmd.as_deref(), Some(dev_cmd));
    }

    #[test]
    fn init_fails_before_writing_config_when_registry_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        // Parent path is a regular file, so registry creation fails portably even as root.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, "blocker").unwrap();
        let unwritable_reg = blocker.join("registry.json");

        let args = base_init_args(&repo, "none");
        let err = build_init_report(&args, |_| None, Some(&unwritable_reg)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not-a-dir"),
            "expected registry path error, got: {msg}"
        );
        assert!(
            !repo.join(STATE_DIR_NAME).join(CONFIG_FILE).exists(),
            "config.toml must not be stranded when registry is unwritable"
        );
        assert!(
            !repo.join(STATE_DIR_NAME).exists(),
            ".brokenapp dir must not be created when registry is unwritable"
        );

        // Also test an existing read-only parent directory on Unix when not running as root.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ro_dir = dir.path().join("ro-home");
            std::fs::create_dir_all(&ro_dir).unwrap();
            std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
            let enforced = tempfile::NamedTempFile::new_in(&ro_dir).is_err();
            if enforced {
                let ro_reg = ro_dir.join("registry.json");
                let err = build_init_report(&args, |_| None, Some(&ro_reg)).unwrap_err();
                let msg = format!("{err:#}");
                assert!(
                    msg.contains("registry.json"),
                    "expected registry write error, got: {msg}"
                );
                assert!(
                    !repo.join(STATE_DIR_NAME).join(CONFIG_FILE).exists(),
                    "config.toml must not be written when registry dir is read-only"
                );
            }
            std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn init_recovers_existing_unregistered_config_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let state_dir = repo.join(STATE_DIR_NAME);
        std::fs::create_dir_all(&state_dir).unwrap();

        let original_config = "\
# custom user comment preserved on recovery
[project]
name = \"recovered-app\"
url = \"http://127.0.0.1:4123/\"
codebase = \".\"
dev_cmd = \"pnpm dev\"
ready_timeout_secs = 120
protected = false
";
        let config_path = state_dir.join(CONFIG_FILE);
        std::fs::write(&config_path, original_config).unwrap();

        let reg = dir.path().join("registry.json");
        let args = InitArgs {
            url: None,
            dev_cmd: None,
            name: None,
            codebase: repo.display().to_string(),
            agent: "none".to_string(),
            protected: false,
            force: false,
            json: true,
            target: ProjectTarget::default(),
        };

        // Recovering an unregistered valid config succeeds without --force and keeps config.toml.
        let report = build_init_report(&args, |_| None, Some(&reg)).unwrap();
        assert_eq!(report.project, "recovered-app");
        assert_eq!(report.url, "http://127.0.0.1:4123/");
        assert_eq!(report.dev_cmd.as_deref(), Some("pnpm dev"));
        assert!(
            report.files_kept.contains(&report.config),
            "config.toml should be reported in files_kept, got written={:?} kept={:?}",
            report.files_written,
            report.files_kept
        );
        assert!(
            !report.files_written.contains(&report.config),
            "config.toml must not be overwritten during recovery"
        );
        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            original_config
        );

        let saved_reg: Registry =
            serde_json::from_str(&std::fs::read_to_string(&reg).unwrap()).unwrap();
        let entry = saved_reg.find("recovered-app").expect("registered entry");
        assert_eq!(entry.state_dir, report.state_dir);
        assert_eq!(entry.url, "http://127.0.0.1:4123/");

        // Once registered, re-running without --force is rejected as usual.
        let err = build_init_report(&args, |_| None, Some(&reg)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already exists; pass --force to overwrite it"),
            "{msg}"
        );

        // An unregistered corrupt config.toml without --force is still rejected.
        let bad_repo = dir.path().join("bad-repo");
        std::fs::create_dir_all(bad_repo.join(STATE_DIR_NAME)).unwrap();
        std::fs::write(
            bad_repo.join(STATE_DIR_NAME).join(CONFIG_FILE),
            "[project\nnot valid toml",
        )
        .unwrap();
        let bad_args = base_init_args(&bad_repo, "none");
        let err = build_init_report(&bad_args, |_| None, Some(&reg)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already exists; pass --force to overwrite it"),
            "{msg}"
        );
    }

    #[test]
    fn init_help_documents_brokenapp_home() {
        use clap::CommandFactory as _;

        #[allow(dead_code)]
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: crate::front::FrontCommand,
        }

        let mut cli = TestCli::command();
        let init_cmd = cli.find_subcommand_mut("init").expect("init subcommand");
        let help = init_cmd.render_help().to_string();
        assert!(help.contains("BROKENAPP_HOME"), "{help}");
        assert!(help.contains("~/.brokenapp"), "{help}");
    }

    #[test]
    fn ensure_registry_writable_reports_brokenapp_home_hint() {
        let dir = tempfile::tempdir().unwrap();

        // Non-directory parent must give an actionable BROKENAPP_HOME hint, not raw os error 17.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, "blocker").unwrap();
        let err = ensure_registry_writable(&blocker.join("registry.json")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("BROKENAPP_HOME=/tmp/brokenapp-home"), "{msg}");
        assert!(!msg.contains("os error 17"), "{msg}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Read-only parent directory.
            let ro_dir = dir.path().join("ro-home");
            std::fs::create_dir_all(&ro_dir).unwrap();
            std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
            if tempfile::NamedTempFile::new_in(&ro_dir).is_err() {
                let err = ensure_registry_writable(&ro_dir.join("registry.json")).unwrap_err();
                let msg = format!("{err:#}");
                assert!(msg.contains("cannot write global registry"), "{msg}");
                assert!(msg.contains("BROKENAPP_HOME=/tmp/brokenapp-home"), "{msg}");
            }
            std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

            // Existing read-only registry.json.
            let ro_file_dir = dir.path().join("ro-file-home");
            std::fs::create_dir_all(&ro_file_dir).unwrap();
            let ro_file = ro_file_dir.join("registry.json");
            std::fs::write(&ro_file, r#"{"projects":[]}"#).unwrap();
            std::fs::set_permissions(&ro_file, std::fs::Permissions::from_mode(0o444)).unwrap();
            if std::fs::OpenOptions::new()
                .write(true)
                .open(&ro_file)
                .is_err()
            {
                let err = ensure_registry_writable(&ro_file).unwrap_err();
                let msg = format!("{err:#}");
                assert!(msg.contains("cannot write global registry"), "{msg}");
                assert!(msg.contains("BROKENAPP_HOME=/tmp/brokenapp-home"), "{msg}");
            }
            std::fs::set_permissions(&ro_file, std::fs::Permissions::from_mode(0o644)).unwrap();

            // Existing unreadable registry.json surfaces BROKENAPP_HOME hint on load.
            let repo = dir.path().join("repo-unreadable-reg");
            std::fs::create_dir_all(&repo).unwrap();
            std::fs::set_permissions(&ro_file, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read_to_string(&ro_file).is_err() {
                let args = base_init_args(&repo, "none");
                let err = build_init_report(&args, |_| None, Some(&ro_file)).unwrap_err();
                let msg = format!("{err:#}");
                assert!(msg.contains("cannot read global registry"), "{msg}");
                assert!(msg.contains("BROKENAPP_HOME=/tmp/brokenapp-home"), "{msg}");
                assert!(!repo.join(STATE_DIR_NAME).exists());
            }
            std::fs::set_permissions(&ro_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    #[test]
    fn sync_dev_cmd_port_handles_direct_binaries_package_scripts_and_explicit_flags() {
        assert_eq!(
            secrets::classify("PORT", "4102"),
            secrets::Sensitivity::Public
        );

        assert_eq!(
            sync_dev_cmd_port("next dev", Some("next"), 4102, Some(3000)).as_deref(),
            Some("next dev -p 4102")
        );
        assert_eq!(
            sync_dev_cmd_port("npm run dev", Some("next"), 4102, Some(3000)).as_deref(),
            Some("PORT=4102 npm run dev")
        );
        assert_eq!(
            sync_dev_cmd_port("pnpm dev", Some("next"), 4102, Some(3000)).as_deref(),
            Some("PORT=4102 pnpm dev")
        );
        assert_eq!(
            sync_dev_cmd_port("pnpm run dev", Some("next"), 4102, Some(3000)).as_deref(),
            Some("PORT=4102 pnpm run dev")
        );
        assert_eq!(
            sync_dev_cmd_port("yarn dev", Some("vite"), 4102, Some(5173)).as_deref(),
            Some("PORT=4102 yarn dev")
        );
        assert_eq!(
            sync_dev_cmd_port("bun run dev", Some("astro"), 4102, Some(4321)).as_deref(),
            Some("PORT=4102 bun run dev")
        );
        assert_eq!(
            sync_dev_cmd_port("vite", Some("vite"), 4102, Some(5173)).as_deref(),
            Some("vite --port 4102")
        );
        assert_eq!(
            sync_dev_cmd_port("astro dev", Some("astro"), 4102, Some(4321)).as_deref(),
            Some("astro dev --port 4102")
        );
        assert_eq!(
            sync_dev_cmd_port("nuxt dev", Some("nuxt"), 4102, Some(3000)).as_deref(),
            Some("nuxt dev --port 4102")
        );
        assert_eq!(
            sync_dev_cmd_port("vite --port 5173", Some("vite"), 4102, Some(5173)).as_deref(),
            Some("vite --port 4102")
        );
        assert_eq!(
            sync_dev_cmd_port(
                "uvicorn app:app --port 8000",
                Some("fastapi"),
                4102,
                Some(8000)
            )
            .as_deref(),
            Some("uvicorn app:app --port 4102")
        );
        assert_eq!(
            sync_dev_cmd_port(
                "flask run --host=127.0.0.1 --port=5000",
                Some("flask"),
                4102,
                Some(5000)
            )
            .as_deref(),
            Some("flask run --host=127.0.0.1 --port=4102")
        );
        assert_eq!(
            sync_dev_cmd_port("PORT=3000 npm run dev", Some("next"), 4102, Some(3000)).as_deref(),
            Some("PORT=4102 npm run dev")
        );
        assert_eq!(
            sync_dev_cmd_port("next dev -p 3000", Some("next"), 4102, Some(3000)).as_deref(),
            Some("next dev -p 4102")
        );
        // No-op when ports already match.
        assert_eq!(
            sync_dev_cmd_port("npm run dev", Some("next"), 3000, Some(3000)),
            None
        );
        assert_eq!(
            sync_dev_cmd_port("vite --port 4102", Some("vite"), 4102, None),
            None
        );

        // End-to-end: custom --url port syncs into detected dev_cmd when --dev-cmd is omitted.
        let dir = tempfile::tempdir().unwrap();
        let reg = dir.path().join("registry.json");

        let repo_sync = dir.path().join("next-sync");
        std::fs::create_dir_all(&repo_sync).unwrap();
        std::fs::write(
            repo_sync.join("package.json"),
            r#"{"name":"next-sync","scripts":{"dev":"next dev"},"dependencies":{"next":"15.0.0"}}"#,
        )
        .unwrap();
        let args_sync = InitArgs {
            url: Some("http://localhost:4102/".to_string()),
            dev_cmd: None,
            name: Some("next-sync".to_string()),
            codebase: repo_sync.display().to_string(),
            agent: "none".to_string(),
            protected: false,
            force: false,
            json: true,
            target: ProjectTarget::default(),
        };
        let report_sync = build_init_report(&args_sync, |_| None, Some(&reg)).unwrap();
        assert_eq!(
            report_sync.dev_cmd.as_deref(),
            Some("PORT=4102 npm run dev")
        );
        assert!(report_sync.moved_to_dev_env.is_empty());
        assert!(
            report_sync
                .detected
                .notes
                .iter()
                .any(|n| n == "synced --url port 4102 into dev_cmd"),
            "{:?}",
            report_sync.detected.notes
        );
        let cfg_raw = std::fs::read_to_string(&report_sync.config).unwrap();
        assert!(cfg_raw.contains("PORT=4102 npm run dev"), "{cfg_raw}");

        // End-to-end: matching port is a no-op.
        let repo_same = dir.path().join("next-same");
        std::fs::create_dir_all(&repo_same).unwrap();
        std::fs::write(
            repo_same.join("package.json"),
            r#"{"name":"next-same","scripts":{"dev":"next dev"},"dependencies":{"next":"15.0.0"}}"#,
        )
        .unwrap();
        let args_same = InitArgs {
            url: Some("http://localhost:3000/".to_string()),
            dev_cmd: None,
            name: Some("next-same".to_string()),
            codebase: repo_same.display().to_string(),
            agent: "none".to_string(),
            protected: false,
            force: false,
            json: true,
            target: ProjectTarget::default(),
        };
        let report_same = build_init_report(&args_same, |_| None, Some(&reg)).unwrap();
        assert_eq!(report_same.dev_cmd.as_deref(), Some("npm run dev"));
        assert!(
            !report_same
                .detected
                .notes
                .iter()
                .any(|n| n.starts_with("synced --url port")),
            "{:?}",
            report_same.detected.notes
        );

        // End-to-end: explicit --dev-cmd is never rewritten.
        let repo_explicit = dir.path().join("next-explicit");
        std::fs::create_dir_all(&repo_explicit).unwrap();
        std::fs::write(
            repo_explicit.join("package.json"),
            r#"{"name":"next-explicit","scripts":{"dev":"next dev"},"dependencies":{"next":"15.0.0"}}"#,
        )
        .unwrap();
        let args_explicit = InitArgs {
            url: Some("http://localhost:4102/".to_string()),
            dev_cmd: Some("npm run dev".to_string()),
            name: Some("next-explicit".to_string()),
            codebase: repo_explicit.display().to_string(),
            agent: "none".to_string(),
            protected: false,
            force: false,
            json: true,
            target: ProjectTarget::default(),
        };
        let report_explicit = build_init_report(&args_explicit, |_| None, Some(&reg)).unwrap();
        assert_eq!(report_explicit.dev_cmd.as_deref(), Some("npm run dev"));
        assert!(
            !report_explicit
                .detected
                .notes
                .iter()
                .any(|n| n.starts_with("synced --url port")),
            "{:?}",
            report_explicit.detected.notes
        );
    }

    #[test]
    fn init_warns_only_when_codebase_path_is_absolute() {
        assert_eq!(absolute_codebase_warning("."), None);
        assert_eq!(absolute_codebase_warning(".."), None);
        assert_eq!(absolute_codebase_warning("web"), None);
        let abs_example = if cfg!(windows) {
            r"C:\tmp\example-repo"
        } else {
            "/tmp/example-repo"
        };
        let abs_warn = absolute_codebase_warning(abs_example).expect("warning expected");
        assert!(
            abs_warn.contains(&format!(
                "config.toml records an absolute codebase path ({abs_example})"
            )),
            "{abs_warn}"
        );

        let dir = tempfile::tempdir().unwrap();
        let reg = dir.path().join("registry.json");

        // Relative codebase (`.` with default .brokenapp/ inside repo) -> no warning.
        let repo_rel = dir.path().join("repo-rel");
        std::fs::create_dir_all(&repo_rel).unwrap();
        let mut args_rel = base_init_args(&repo_rel, "none");
        args_rel.name = Some("repo-rel".to_string());
        let report_rel = build_init_report(&args_rel, |_| None, Some(&reg)).unwrap();
        assert!(report_rel.warnings.is_empty(), "{:?}", report_rel.warnings);
        let json_rel = serde_json::to_string(&report_rel).unwrap();
        assert!(!json_rel.contains("\"warnings\""), "{json_rel}");

        // External --state-dir outside repo tree -> absolute codebase in config.toml -> warning emitted.
        let repo_abs = dir.path().join("repo-abs");
        std::fs::create_dir_all(&repo_abs).unwrap();
        let mut args_abs = base_init_args(&repo_abs, "none");
        args_abs.name = Some("repo-abs".to_string());
        args_abs.target.state_dir = Some(dir.path().join("elsewhere").join("external-state"));
        let report_abs = build_init_report(&args_abs, |_| None, Some(&reg)).unwrap();
        assert_eq!(report_abs.warnings.len(), 1, "{:?}", report_abs.warnings);
        assert!(
            report_abs.warnings[0].contains("config.toml records an absolute codebase path"),
            "{}",
            report_abs.warnings[0]
        );
        assert!(
            report_abs.warnings[0].contains(&report_abs.root),
            "{}",
            report_abs.warnings[0]
        );
        let json_abs = serde_json::to_string(&report_abs).unwrap();
        assert!(json_abs.contains("\"warnings\""), "{json_abs}");
    }
}
