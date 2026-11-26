//! `brokenapp doctor`: install and project health checks.
//!
//! Checks this binary (version, store schema), which `brokenapp` agents get
//! from PATH, Chrome, the project config, the target URL (locality and
//! reachability), the dev command, the write guard, the project store, and
//! each login role's readiness (credentials present, saved session age; never
//! values). Exit code 1 when any check fails.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use super::locality;
use super::process::resolve_dev_env;
use super::project::{self, ProjectCtx, ProjectTarget, Registry};

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
struct Check {
    name: String,
    status: Status,
    detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

fn check(name: impl Into<String>, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status,
        detail: detail.into(),
        fix: None,
    }
}

impl Check {
    fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    ok: bool,
    version: String,
    executable: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project: Option<String>,
    checks: Vec<Check>,
}

/// First `brokenapp` executable on PATH.
fn first_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| {
            dir.join(if cfg!(windows) {
                "brokenapp.exe"
            } else {
                "brokenapp"
            })
        })
        .find(|p| p.is_file())
}

/// Run another `brokenapp` binary briefly and capture stdout.
async fn run_other(bin: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args)
        .env("BROKENAPP_NO_BANNER", "1")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .ok()?
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Version from `brokenapp --version` (`brokenapp 0.1.0+abc (built ...)`).
fn parse_version(stdout: &str) -> Option<String> {
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("brokenapp "))?;
    line.split_whitespace().nth(1).map(str::to_string)
}

async fn path_check(version: &str, exe: &Path) -> Check {
    let Some(hit) = first_on_path() else {
        return check(
            "path",
            Status::Warn,
            "no `brokenapp` on PATH; agents and hooks that call `brokenapp` will not find this build",
        )
        .fix(format!(
            "put this binary on PATH, e.g. ln -s {} ~/.local/bin/brokenapp",
            exe.display()
        ));
    };
    let same = match (hit.canonicalize(), exe.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if same {
        return check(
            "path",
            Status::Ok,
            format!("`brokenapp` on PATH is this binary ({})", hit.display()),
        );
    }
    let other_version = run_other(&hit, &["--version"])
        .await
        .and_then(|s| parse_version(&s));
    let describe = format!(
        "{} (version {})",
        hit.display(),
        other_version.as_deref().unwrap_or("unknown"),
    );
    let fix = format!(
        "agents run the first `brokenapp` on PATH; replace {} with this build ({})",
        hit.display(),
        exe.display()
    );
    match other_version.as_deref() {
        Some(v) if v == version => check(
            "path",
            Status::Ok,
            format!("`brokenapp` on PATH is another copy of this build: {describe}"),
        ),
        _ => check(
            "path",
            Status::Warn,
            format!("`brokenapp` on PATH is a different binary: {describe} vs version {version}"),
        )
        .fix(fix),
    }
}

const LEGACY_CONFIG_FILE: &str = "brokenapp.toml";

const KNOWN_TOP_KEYS: &[&str] = &["project", "scan", "auth", "roles"];

const KNOWN_PROJECT_KEYS: &[&str] = &[
    "name",
    "url",
    "codebase",
    "dev_cmd",
    "dev_cwd",
    "dev_env",
    "ready_timeout_secs",
    "protected",
];

const KNOWN_SCAN_KEYS: &[&str] = &[
    "mode",
    "max_minutes",
    "max_views",
    "max_hours",
    "view_budget_seconds",
    "role_concurrency",
    "progress_seconds",
    "write_guard",
    "write_guard_allow",
    "extra_routes",
    "exclude_routes",
    "seed_from_source",
    "headless",
    "allow_remote",
    "max_interaction_depth",
    "max_interactions_per_view",
    "max_interactions_per_depth",
    "settle_ms",
    "tabs",
    "test_data",
];

const KNOWN_AUTH_KEYS: &[&str] = &["session", "include_anonymous"];

const KNOWN_ROLE_KEYS: &[&str] = &[
    "name",
    "method",
    "description",
    "login_url",
    "username",
    "password",
    "username_selector",
    "password_selector",
    "submit_selector",
    "session",
    "cookie",
    "token",
    "project_url",
    "anon_key",
    "api_key",
    "check",
    "extra_routes",
    "exclude_routes",
];

/// Warn about unrecognized keys in `.brokenapp/config.toml` that serde silently
/// ignores (e.g. typoed or legacy keys like `scan.max_duration_minutes`).
/// Never echoes values.
fn unknown_config_keys_check(config_path: &Path) -> Option<Check> {
    let raw = std::fs::read_to_string(config_path).ok()?;
    let table = toml::from_str::<toml::Table>(&raw).ok()?;
    let mut unknown = Vec::new();

    for key in table.keys() {
        if !KNOWN_TOP_KEYS.contains(&key.as_str()) {
            unknown.push(key.clone());
        }
    }
    if let Some(proj) = table.get("project").and_then(toml::Value::as_table) {
        for key in proj.keys() {
            if !KNOWN_PROJECT_KEYS.contains(&key.as_str()) {
                unknown.push(format!("project.{key}"));
            }
        }
    }
    if let Some(scan) = table.get("scan").and_then(toml::Value::as_table) {
        for key in scan.keys() {
            if !KNOWN_SCAN_KEYS.contains(&key.as_str()) {
                unknown.push(format!("scan.{key}"));
            }
        }
    }
    if let Some(auth) = table.get("auth").and_then(toml::Value::as_table) {
        for key in auth.keys() {
            if !KNOWN_AUTH_KEYS.contains(&key.as_str()) {
                unknown.push(format!("auth.{key}"));
            }
        }
    }
    if let Some(roles) = table.get("roles").and_then(toml::Value::as_array) {
        for (idx, item) in roles.iter().enumerate() {
            let Some(role_table) = item.as_table() else {
                continue;
            };
            let label = role_table
                .get("name")
                .and_then(toml::Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .map(|s| format!("roles[{s}]"))
                .unwrap_or_else(|| format!("roles[{idx}]"));
            for key in role_table.keys() {
                if !KNOWN_ROLE_KEYS.contains(&key.as_str()) {
                    unknown.push(format!("{label}.{key}"));
                }
            }
        }
    }

    if unknown.is_empty() {
        return None;
    }
    unknown.sort();
    unknown.dedup();
    Some(
        check(
            "config_keys",
            Status::Warn,
            format!(
                "unrecognized config keys in {}: {}",
                config_path.display(),
                unknown.join(", ")
            ),
        )
        .fix("remove unrecognized keys or move them to supported .brokenapp/config.toml fields (see docs/ui-map.md)"),
    )
}

/// Warn when a legacy repo-root `brokenapp.toml` is present alongside or
/// instead of `.brokenapp/config.toml`.
fn legacy_config_check(dir: &Path) -> Option<Check> {
    let legacy = dir.join(LEGACY_CONFIG_FILE);
    if !legacy.is_file() {
        return None;
    }
    Some(
        check(
            "legacy_config",
            Status::Warn,
            format!(
                "legacy {} found; .brokenapp/config.toml is now the sole config file and brokenapp.toml is ignored",
                legacy.display()
            ),
        )
        .fix("migrate any needed settings into .brokenapp/config.toml and remove brokenapp.toml"),
    )
}

/// Inspect raw TOML syntax/fields when `project::load_ctx` fails, producing
/// specific actionable diagnostics (without ever echoing secret values).
fn diagnose_config_error(config_path: &Path, err: &anyhow::Error) -> Vec<Check> {
    let mut out = Vec::new();
    let Ok(raw) = std::fs::read_to_string(config_path) else {
        out.push(check("project", Status::Fail, format!("{err:#}")));
        return out;
    };
    let Ok(table) = toml::from_str::<toml::Table>(&raw) else {
        out.push(
            check("project", Status::Fail, format!("{err:#}"))
                .fix("fix the TOML syntax in .brokenapp/config.toml"),
        );
        return out;
    };
    if let Some(scan) = table.get("scan").and_then(toml::Value::as_table) {
        if let Some(mode_val) = scan.get("mode") {
            let valid = mode_val
                .as_str()
                .and_then(project::ScanMode::parse)
                .is_some();
            if !valid {
                let got = mode_val
                    .as_str()
                    .map(|s| format!("{s:?}"))
                    .unwrap_or_else(|| format!("type {}", mode_val.type_str()));
                out.push(
                    check(
                        "scan_mode",
                        Status::Fail,
                        format!("invalid scan.mode {got} (expected \"standard\" or \"full\")"),
                    )
                    .fix("set scan.mode = \"standard\" or \"full\" in .brokenapp/config.toml"),
                );
            }
        }
        if let Some(guard_val) = scan.get("write_guard") {
            let valid = guard_val.as_str().is_some_and(|s| {
                matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "block" | "stub" | "off"
                )
            });
            if !valid {
                let got = guard_val
                    .as_str()
                    .map(|s| format!("{s:?}"))
                    .unwrap_or_else(|| format!("type {}", guard_val.type_str()));
                out.push(
                    check(
                        "write_guard",
                        Status::Fail,
                        format!(
                            "invalid scan.write_guard {got} (expected \"block\", \"stub\", or \"off\")"
                        ),
                    )
                    .fix("set scan.write_guard = \"block\", \"stub\", or \"off\" in .brokenapp/config.toml"),
                );
            }
        }
    }
    if let Some(proj) = table.get("project").and_then(toml::Value::as_table) {
        let allow_remote = table
            .get("scan")
            .and_then(toml::Value::as_table)
            .and_then(|s| s.get("allow_remote"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if let Some(url_str) = proj.get("url").and_then(toml::Value::as_str)
            && let Err(url_err) = locality::parse_target_url(url_str, allow_remote)
        {
            out.push(
                check("url", Status::Fail, format!("{url_err:#}"))
                    .fix("set project.url to a valid local http(s) URL in .brokenapp/config.toml"),
            );
        }
    }
    if out.is_empty() {
        out.push(
            check("project", Status::Fail, format!("{err:#}"))
                .fix("check field names and types in .brokenapp/config.toml"),
        );
    }
    out
}

/// Resolve the project like the other commands, but report "none here"
/// separately from a broken config, returning the config path when known.
fn find_project(
    target: &ProjectTarget,
) -> std::result::Result<Option<ProjectCtx>, (Option<PathBuf>, anyhow::Error)> {
    if let Some(dir) = &target.state_dir {
        let cfg_path = dir.join(project::CONFIG_FILE);
        return project::resolve(target)
            .map(Some)
            .map_err(|e| (Some(cfg_path), e));
    }
    if target.project.is_some() {
        return project::resolve(target).map(Some).map_err(|e| (None, e));
    }
    let cwd = std::env::current_dir()
        .context("current dir")
        .map_err(|e| (None, e))?;
    let state_dir = project::find_state_dir_from(&cwd).or_else(|| {
        Registry::load()
            .ok()
            .and_then(|reg| project::find_registered_state_dir_from(&cwd, &reg))
    });
    match state_dir {
        Some(dir) => {
            let cfg_path = dir.join(project::CONFIG_FILE);
            project::load_ctx(&dir)
                .map(Some)
                .map_err(|e| (Some(cfg_path), e))
        }
        None => Ok(None),
    }
}

async fn project_checks(ctx: &ProjectCtx, checks: &mut Vec<Check>) {
    let cfg = &ctx.config;
    if cfg.project.name.trim().is_empty() {
        checks.push(
            check(
                "project",
                Status::Fail,
                format!("project.name is empty in {}", ctx.config_path.display()),
            )
            .fix("set project.name in .brokenapp/config.toml"),
        );
    } else {
        checks.push(check(
            "project",
            Status::Ok,
            format!("'{}' ({})", ctx.name(), ctx.config_path.display()),
        ));
    }

    // Warn if legacy `brokenapp.toml` is present in the repo root (or state dir parent).
    if let Some(legacy) = legacy_config_check(&ctx.root) {
        checks.push(legacy);
    } else if let Some(parent) = ctx.state_dir.parent()
        && parent != ctx.root
        && let Some(legacy) = legacy_config_check(parent)
    {
        checks.push(legacy);
    }

    if let Some(unknown_keys) = unknown_config_keys_check(&ctx.config_path) {
        checks.push(unknown_keys);
    }

    if !ctx.root.is_dir() {
        checks.push(
            check(
                "codebase",
                Status::Fail,
                format!(
                    "project.codebase '{}' resolves to {}, which does not exist",
                    cfg.project.codebase,
                    ctx.root.display()
                ),
            )
            .fix("set project.codebase to an existing directory in .brokenapp/config.toml"),
        );
    }

    match Registry::load() {
        Ok(reg) => {
            let entry = reg
                .projects
                .iter()
                .find(|e| Path::new(&e.state_dir) == ctx.state_dir);
            checks.push(match entry {
                Some(e) if e.protected => check(
                    "registry",
                    Status::Warn,
                    "registered as protected: `brokenapp map` will refuse to scan it",
                ),
                Some(e) => check(
                    "registry",
                    Status::Ok,
                    format!(
                        "registered as '{}' in {}",
                        e.name,
                        Registry::path().display()
                    ),
                ),
                None => check(
                    "registry",
                    Status::Warn,
                    format!("not registered in {}", Registry::path().display()),
                )
                .fix("run `brokenapp map` once to register this project without overwriting .brokenapp/config.toml"),
            });
        }
        Err(err) => checks.push(check("registry", Status::Fail, format!("{err:#}"))),
    }

    if cfg.project.protected {
        checks.push(check(
            "protected",
            Status::Warn,
            "project.protected = true: `brokenapp map` will refuse to scan it",
        ));
    }

    checks.push(match cfg.scan.mode {
        project::ScanMode::Standard => check(
            "scan_mode",
            Status::Ok,
            format!(
                "standard (max {}m, {} views)",
                cfg.scan.max_minutes, cfg.scan.max_views
            ),
        ),
        project::ScanMode::Full => check(
            "scan_mode",
            Status::Ok,
            match cfg.scan.max_hours {
                Some(h) => format!("full (no view cap, {h}h ceiling)"),
                None => "full (no global time or view caps)".to_string(),
            },
        ),
    });

    if cfg.scan.tabs == Some(0) {
        checks.push(
            check("tabs", Status::Fail, "scan.tabs must be at least 1")
                .fix("set scan.tabs = 1 (or higher) in .brokenapp/config.toml"),
        );
    }
    if cfg.scan.role_concurrency == Some(0) {
        checks.push(
            check(
                "role_concurrency",
                Status::Fail,
                "scan.role_concurrency must be at least 1",
            )
            .fix("set scan.role_concurrency = 1 (or higher) in .brokenapp/config.toml"),
        );
    }
    if cfg
        .auth
        .session
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        checks.push(
            check(
                "auth_session",
                Status::Warn,
                "auth.session is deprecated and ignored",
            )
            .fix("replace it with a [[roles]] entry using method = \"session\""),
        );
    }

    checks.push(
        match cfg.scan.write_guard.trim().to_ascii_lowercase().as_str() {
            "block" => check(
                "write_guard",
                Status::Ok,
                "block: state-changing requests are recorded and never reach the backend",
            ),
            "stub" => check(
                "write_guard",
                Status::Ok,
                "stub: state-changing requests are recorded and answered locally",
            ),
            "off" => check(
                "write_guard",
                Status::Warn,
                "off: scans can create, change, or delete data in the app's backend",
            )
            .fix("set scan.write_guard = \"block\" unless the backend is disposable"),
            other => check(
                "write_guard",
                Status::Fail,
                format!("invalid scan.write_guard {other:?} (expected block, stub, or off)"),
            )
            .fix(
                "set scan.write_guard = \"block\", \"stub\", or \"off\" in .brokenapp/config.toml",
            ),
        },
    );

    let dev_cmd = cfg
        .project
        .dev_cmd
        .as_deref()
        .filter(|c| !c.trim().is_empty());
    if let Some(cwd) = cfg.project.dev_cwd.as_deref() {
        let dir = ctx.root.join(cwd);
        if !dir.is_dir() {
            checks.push(check(
                "dev_cwd",
                Status::Fail,
                format!("project.dev_cwd {} does not exist", dir.display()),
            ));
        }
    }
    let (_, env_warnings) = resolve_dev_env(&cfg.project.dev_env);
    if !env_warnings.is_empty() {
        checks.push(check("dev_env", Status::Warn, env_warnings.join("; ")));
    }
    if let Some(cmd) = dev_cmd {
        let scanned = super::secrets::scan(cmd);
        if scanned.has_secrets() {
            checks.push(
                check(
                    "dev_cmd",
                    Status::Warn,
                    format!(
                        "project.dev_cmd carries secret values inline ({}) in a committed file",
                        scanned.secret_names().join(", ")
                    ),
                )
                .fix("move them to [project.dev_env] as NAME = \"env:NAME\" references and export them in your shell"),
            );
        }
    }

    match locality::parse_target_url(&cfg.project.url, cfg.scan.allow_remote) {
        Err(err) => {
            let msg = format!("{err:#}");
            let mut c = check("url", Status::Fail, msg.clone());
            if !msg.contains("allow_remote") {
                c = c.fix("set project.url to a valid local http(s) URL in .brokenapp/config.toml");
            }
            checks.push(c);
        }
        Ok(url) => {
            const URL_PROBE_TIMEOUT_SECS: u64 = 8;
            let probe = locality::probe(&url, Duration::from_secs(URL_PROBE_TIMEOUT_SECS)).await;
            checks.push(if probe.reachable {
                check(
                    "url",
                    Status::Ok,
                    format!(
                        "{url} answers (HTTP {})",
                        probe.status.map(|s| s.to_string()).unwrap_or_default()
                    ),
                )
            } else if probe.is_permission_denied() {
                check(
                    "url",
                    Status::Fail,
                    format!(
                        "{url} cannot be probed ({})",
                        probe.error.unwrap_or_default()
                    ),
                )
                .fix("allow loopback connections in your OS/firewall/sandbox, or run outside the sandbox")
            } else if locality::port_open(&url).await {
                check(
                    "url",
                    Status::Warn,
                    format!(
                        "{url} accepts connections but did not answer within {URL_PROBE_TIMEOUT_SECS}s (still starting?)"
                    ),
                )
            } else if let Some(cmd) = dev_cmd {
                check(
                    "url",
                    Status::Ok,
                    format!(
                        "{url} is not running ({}); `brokenapp map` will start it with `{}`",
                        probe.error.unwrap_or_default(),
                        super::secrets::redact_command(cmd)
                    ),
                )
            } else {
                check(
                    "url",
                    Status::Fail,
                    format!(
                        "{url} is not reachable ({}) and project.dev_cmd is not set",
                        probe.error.unwrap_or_default()
                    ),
                )
                .fix("start the app, or set project.dev_cmd in .brokenapp/config.toml")
            });
        }
    }

    if let Ok((_, manifest)) = super::run_state::latest_resumable(&ctx.scans_dir()) {
        checks.push(
            check(
                "resumable_run",
                Status::Warn,
                format!(
                    "incomplete map run {} ({}) can be resumed",
                    manifest.ts,
                    manifest.status.as_str()
                ),
            )
            .fix("run `brokenapp map --resume` to continue before starting a new map"),
        );
    }

    role_checks(ctx, checks);
}

/// One check per login role: credentials present (env or credentials.toml),
/// saved session present and how old; the credentials file's permissions and
/// that git ignores it.
fn role_checks(ctx: &ProjectCtx, checks: &mut Vec<Check>) {
    use super::roles;
    use super::roles_cmd::{self, SESSION_STALE_HOURS};
    if let Err(err) = roles::validate_roles(&ctx.config, &ctx.config_path) {
        checks.push(check("roles", Status::Fail, format!("{err:#}")));
        return;
    }
    if ctx.config.roles.is_empty() {
        return;
    }
    let statuses = match roles_cmd::role_statuses(ctx) {
        Ok(s) => s,
        Err(err) => {
            checks.push(
                check("credentials", Status::Fail, format!("{err:#}"))
                    .fix("chmod 600 .brokenapp/credentials.toml, or recreate it with `brokenapp roles add <role> --force`"),
            );
            return;
        }
    };
    for st in statuses
        .iter()
        .filter(|s| s.name != super::project::ANONYMOUS_ROLE)
    {
        let name = format!("role:{}", st.name);
        let mut parts = vec![st.method.clone()];
        if !st.credentials.is_empty() {
            parts.push(
                st.credentials
                    .iter()
                    .map(|c| {
                        if c.from == "env" {
                            format!("{} from ${}", c.field, c.env)
                        } else {
                            format!("{} from credentials.toml", c.field)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        if let (Some(f), Some(h)) = (&st.session_file, st.session_age_hours) {
            parts.push(format!("session {f} {}", roles_cmd::age_text(h)));
        }
        parts.push(match &st.last_map {
            Some(at) => format!("mapped {at}"),
            None => "no map yet".to_string(),
        });
        let detail = parts.join("; ");
        checks.push(if !st.ready {
            check(
                name,
                Status::Warn,
                format!("{detail}; not ready: {}", st.missing.join("; ")),
            )
            .fix(if matches!(st.method.as_str(), "session" | "manual") {
                format!("brokenapp login --role {}", st.name)
            } else {
                format!(
                    "export the variables, or `brokenapp roles add {} --force`",
                    st.name
                )
            })
        } else if st
            .session_age_hours
            .is_some_and(|h| h > SESSION_STALE_HOURS)
        {
            check(
                name,
                Status::Warn,
                format!("{detail}; the saved session may have expired"),
            )
            .fix(format!("brokenapp login --role {}", st.name))
        } else {
            check(name, Status::Ok, detail)
        });
    }
    let creds = ctx.credentials_path();
    if creds.is_file() {
        match roles::git_ignores(&ctx.state_dir, super::project::CREDENTIALS_FILE) {
            Some(false) => checks.push(
                check(
                    "credentials",
                    Status::Fail,
                    format!("{} is NOT ignored by git", creds.display()),
                )
                .fix("run `brokenapp roles add <role> --force` (adds it to .brokenapp/.gitignore) or add /credentials.toml there"),
            ),
            _ => checks.push(check(
                "credentials",
                Status::Ok,
                format!("{} (mode 600, gitignored)", creds.display()),
            )),
        }
    }
}

pub async fn run(args: DoctorArgs) -> Result<i32> {
    let version = env!("BROKENAPP_BUILD_VERSION").to_string();
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("brokenapp"));
    let mut checks = vec![check(
        "binary",
        Status::Ok,
        format!("brokenapp {version} at {}", exe.display()),
    )];
    checks.push(path_check(&version, &exe).await);
    checks.push(
        match crate::browser::BrowserManager::detect_chrome_executable() {
            Some(p) => check("chrome", Status::Ok, p.display().to_string()),
            None => check("chrome", Status::Fail, "Chrome/Chromium not found")
                .fix("install Google Chrome or set BROKENAPP_CHROME=/path/to/chrome"),
        },
    );

    let mut project_name = None;
    match find_project(&args.target) {
        Ok(Some(ctx)) => {
            project_name = Some(ctx.name().to_string());
            project_checks(&ctx, &mut checks).await;
        }
        Ok(None) => {
            checks.push(
                check(
                    "project",
                    Status::Warn,
                    "no .brokenapp/config.toml here or above",
                )
                .fix("run `brokenapp init` in the project (or pass --project/--state-dir)"),
            );
            if let Ok(cwd) = std::env::current_dir()
                && let Some(legacy) = legacy_config_check(&cwd)
            {
                checks.push(legacy);
            }
        }
        Err((Some(cfg_path), err)) => {
            checks.extend(diagnose_config_error(&cfg_path, &err));
            if let Some(root) = cfg_path.parent().and_then(Path::parent)
                && let Some(legacy) = legacy_config_check(root)
            {
                checks.push(legacy);
            }
        }
        Err((None, err)) => checks.push(check("project", Status::Fail, format!("{err:#}"))),
    }

    let ok = !checks.iter().any(|c| c.status == Status::Fail);
    let report = DoctorReport {
        ok,
        version,
        executable: exe.display().to_string(),
        project: project_name,
        checks,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize doctor report")?
        );
    } else {
        for c in &report.checks {
            let tag = match c.status {
                Status::Ok => "ok  ",
                Status::Warn => "warn",
                Status::Fail => "FAIL",
            };
            println!("{tag}  {:<14} {}", c.name, c.detail);
            if let Some(fix) = &c.fix {
                println!("      {:<14} fix: {fix}", "");
            }
        }
    }
    Ok(if ok { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_other_binary_output() {
        assert_eq!(
            parse_version("brokenapp 0.1.0+11d8ab6 (built 2026-05-29T14:22:28Z)\n"),
            Some("0.1.0+11d8ab6".to_string())
        );
        assert_eq!(
            parse_version("brokenapp 0.1.0\n"),
            Some("0.1.0".to_string())
        );
        assert_eq!(parse_version("garbage"), None);
    }

    #[tokio::test]
    async fn project_checks_flag_problems() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='x'\nurl='https://example.com'\nprotected=true\n[scan]\nwrite_guard='off'\n",
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let mut checks = Vec::new();
        project_checks(&ctx, &mut checks).await;
        let status = |n: &str| checks.iter().find(|c| c.name == n).map(|c| c.status);
        assert_eq!(status("protected"), Some(Status::Warn));
        assert_eq!(status("write_guard"), Some(Status::Warn));
        assert_eq!(status("url"), Some(Status::Fail));
    }

    #[tokio::test]
    async fn role_readiness_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='x'\nurl='http://127.0.0.1:1'\n\n\
             [[roles]]\nname='admin'\nmethod='form'\nlogin_url='/login'\n\
             username='env:BROKENAPP_DOCTOR_TEST_UNSET_USER'\npassword='env:BROKENAPP_DOCTOR_TEST_UNSET_PW'\n\n\
             [[roles]]\nname='coach'\nmethod='session'\n",
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let mut checks = Vec::new();
        role_checks(&ctx, &mut checks);
        let admin = checks.iter().find(|c| c.name == "role:admin").unwrap();
        assert_eq!(admin.status, Status::Warn);
        assert!(
            admin
                .detail
                .contains("BROKENAPP_DOCTOR_TEST_UNSET_USER is not set"),
            "{}",
            admin.detail
        );
        let coach = checks.iter().find(|c| c.name == "role:coach").unwrap();
        assert_eq!(coach.status, Status::Warn);
        assert_eq!(coach.fix.as_deref(), Some("brokenapp login --role coach"));

        // A literal secret in config.toml fails the roles check.
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='x'\nurl='http://127.0.0.1:1'\n\n\
             [[roles]]\nname='admin'\nmethod='form'\npassword='hunter2'\n",
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let mut checks = Vec::new();
        role_checks(&ctx, &mut checks);
        assert_eq!(checks[0].name, "roles");
        assert_eq!(checks[0].status, Status::Fail);
        assert!(!checks[0].detail.contains("hunter2"));
    }

    #[tokio::test]
    async fn config_validation_catches_invalid_fields_and_legacy_toml() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        // Legacy brokenapp.toml in repo root triggers a clear warning.
        std::fs::write(
            dir.path().join("brokenapp.toml"),
            "[target]\nurl='http://127.0.0.1:3000'\n",
        )
        .unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname=''\nurl='ftp://localhost:3000'\ncodebase='does-not-exist'\n\
             [scan]\nmode='full'\nwrite_guard='bogus'\ntabs=0\nrole_concurrency=0\n\
             [auth]\nsession='old.json'\n",
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let mut checks = Vec::new();
        project_checks(&ctx, &mut checks).await;
        let find = |n: &str| checks.iter().find(|c| c.name == n).unwrap();

        assert_eq!(find("project").status, Status::Fail);
        assert!(find("project").detail.contains("empty"));

        let legacy = find("legacy_config");
        assert_eq!(legacy.status, Status::Warn);
        assert!(
            legacy
                .detail
                .contains(".brokenapp/config.toml is now the sole config file"),
            "{}",
            legacy.detail
        );
        assert!(legacy.fix.is_some());

        assert_eq!(find("codebase").status, Status::Fail);
        assert_eq!(find("scan_mode").status, Status::Ok);
        assert!(find("scan_mode").detail.starts_with("full"));
        assert_eq!(find("tabs").status, Status::Fail);
        assert_eq!(find("role_concurrency").status, Status::Fail);
        assert_eq!(find("auth_session").status, Status::Warn);

        let wg = find("write_guard");
        assert_eq!(wg.status, Status::Fail);
        assert!(wg.detail.contains("invalid scan.write_guard"));
        assert!(wg.fix.is_some());

        let url = find("url");
        assert_eq!(url.status, Status::Fail);
        assert!(url.detail.contains("http(s)"));
        assert!(url.fix.is_some());

        // No legacy brokenapp.toml -> no legacy_config check.
        std::fs::remove_file(dir.path().join("brokenapp.toml")).unwrap();
        let mut clean_checks = Vec::new();
        project_checks(&ctx, &mut clean_checks).await;
        assert!(clean_checks.iter().all(|c| c.name != "legacy_config"));
    }

    #[test]
    fn diagnose_config_error_pinpoints_invalid_mode_and_write_guard_without_leaking_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[project]\nname='demo'\nurl='not-a-url'\n\
             [scan]\nmode='turbo'\nwrite_guard='warn'\n\
             [[roles]]\nname='admin'\npassword='super-secret-password'\n",
        )
        .unwrap();
        let err = project::load_ctx(dir.path()).unwrap_err();
        let checks = diagnose_config_error(&cfg, &err);
        let joined: String = checks
            .iter()
            .map(|c| format!("{}: {} {:?}", c.name, c.detail, c.fix))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains("super-secret-password"), "{joined}");
        assert!(
            checks.iter().any(|c| c.name == "scan_mode"
                && c.status == Status::Fail
                && c.detail.contains("turbo")),
            "{joined}"
        );
        assert!(
            checks.iter().any(|c| c.name == "write_guard"
                && c.status == Status::Fail
                && c.detail.contains("warn")),
            "{joined}"
        );
        assert!(
            checks
                .iter()
                .any(|c| c.name == "url" && c.status == Status::Fail),
            "{joined}"
        );
    }

    #[tokio::test]
    async fn unregistered_project_fix_never_suggests_init_force() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='unreg-demo'\nurl='http://127.0.0.1:1'\n",
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let mut checks = Vec::new();
        project_checks(&ctx, &mut checks).await;
        let reg = checks.iter().find(|c| c.name == "registry").unwrap();
        assert_eq!(reg.status, Status::Warn);
        let fix = reg.fix.as_deref().unwrap();
        assert!(!fix.contains("init --force"), "unexpected fix: {fix}");
        assert!(
            fix.contains("brokenapp map"),
            "fix should suggest brokenapp map: {fix}"
        );
    }

    #[tokio::test]
    async fn unknown_config_keys_warns_without_false_positives_or_secret_leaks() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();

        // All valid keys across [project], [scan] (including max_interactions_per_depth),
        // [auth], and [[roles]] must produce no config_keys warning.
        std::fs::write(
            state.join("config.toml"),
            r##"
[project]
name = "demo"
url = "http://127.0.0.1:1"
codebase = "."
dev_cmd = "npm run dev"
dev_cwd = "."
ready_timeout_secs = 90
protected = false
[project.dev_env]
CUSTOM_VAR = "env:CUSTOM_VAR"

[scan]
mode = "standard"
max_minutes = 10
max_views = 80
max_hours = 2
view_budget_seconds = 60
role_concurrency = 1
progress_seconds = 30
write_guard = "block"
write_guard_allow = []
extra_routes = []
exclude_routes = []
seed_from_source = true
headless = true
allow_remote = false
max_interaction_depth = 3
max_interactions_per_view = 30
max_interactions_per_depth = [25, 15, 10]
settle_ms = 2000
tabs = 2
[scan.test_data]
email = "test@example.com"

[auth]
include_anonymous = true

[[roles]]
name = "admin"
method = "form"
description = "Admin role"
login_url = "/login"
username = "env:ADMIN_USER"
password = "env:ADMIN_PASS"
username_selector = "#user"
password_selector = "#pass"
submit_selector = "button[type=submit]"
check = "/api/me"
extra_routes = ["/admin"]
exclude_routes = ["/logout"]

[[roles]]
name = "coach"
method = "session"
session = "session/coach.json"

[[roles]]
name = "api-cookie"
method = "cookie"
cookie = "env:API_COOKIE"

[[roles]]
name = "api-bearer"
method = "bearer"
token = "env:API_TOKEN"

[[roles]]
name = "sb-user"
method = "supabase"
project_url = "https://demo.supabase.co"
anon_key = "public-anon-key"

[[roles]]
name = "fb-user"
method = "firebase"
api_key = "public-firebase-key"
"##,
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        assert!(unknown_config_keys_check(&ctx.config_path).is_none());
        let mut clean = Vec::new();
        project_checks(&ctx, &mut clean).await;
        assert!(clean.iter().all(|c| c.name != "config_keys"));

        // Unknown keys trigger a Status::Warn "config_keys" check listing dotted keys,
        // without echoing values.
        std::fs::write(
            state.join("config.toml"),
            r#"
bogus_top = "never-echo-secret-123"

[project]
name = "demo"
url = "http://127.0.0.1:1"
typo_field = true

[scan]
max_duration_minutes = 15
stop_on_convergence = true

[[roles]]
name = "admin"
method = "session"
bogus_role_key = "never-echo-role-secret"
"#,
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let mut checks = Vec::new();
        project_checks(&ctx, &mut checks).await;
        let warn = checks.iter().find(|c| c.name == "config_keys").unwrap();
        assert_eq!(warn.status, Status::Warn);
        for expected in [
            "bogus_top",
            "project.typo_field",
            "scan.max_duration_minutes",
            "scan.stop_on_convergence",
            "roles[admin].bogus_role_key",
        ] {
            assert!(
                warn.detail.contains(expected),
                "missing {expected} in {}",
                warn.detail
            );
        }
        assert!(!warn.detail.contains("never-echo-secret-123"));
        assert!(!warn.detail.contains("never-echo-role-secret"));
        assert!(
            warn.fix
                .as_deref()
                .is_some_and(|f| f.contains("docs/ui-map.md"))
        );
    }

    #[tokio::test]
    async fn interrupted_run_triggers_resumable_run_warning() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='demo'\nurl='http://127.0.0.1:1'\n",
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();

        // No scans yet -> no resumable_run check.
        let mut checks = Vec::new();
        project_checks(&ctx, &mut checks).await;
        assert!(checks.iter().all(|c| c.name != "resumable_run"));

        // Interrupted run -> Status::Warn "resumable_run" with map --resume fix.
        let run_dir = ctx.scans_dir().join("20261120T120000Z");
        std::fs::create_dir_all(&run_dir).unwrap();
        let mut manifest = super::super::run_state::RunManifest::new(
            "20261120T120000Z",
            "2026-11-20T12:00:00Z",
            super::super::run_state::RunSettings::default(),
            vec![super::super::run_state::RunRole {
                name: "anonymous".to_string(),
                status: "interrupted".to_string(),
                dir: run_dir.join("roles/anonymous").display().to_string(),
                ..Default::default()
            }],
        );
        manifest.status = super::super::run_state::RunStatus::Interrupted;
        manifest.save(&run_dir).unwrap();

        let mut checks = Vec::new();
        project_checks(&ctx, &mut checks).await;
        let resumable = checks.iter().find(|c| c.name == "resumable_run").unwrap();
        assert_eq!(resumable.status, Status::Warn);
        assert!(
            resumable.detail.contains("20261120T120000Z")
                && resumable.detail.contains("interrupted"),
            "{}",
            resumable.detail
        );
        assert_eq!(
            resumable.fix.as_deref(),
            Some("run `brokenapp map --resume` to continue before starting a new map")
        );

        // Completed run -> no resumable_run warning.
        manifest.status = super::super::run_state::RunStatus::Completed;
        manifest.save(&run_dir).unwrap();
        let mut checks = Vec::new();
        project_checks(&ctx, &mut checks).await;
        assert!(checks.iter().all(|c| c.name != "resumable_run"));
    }
}
