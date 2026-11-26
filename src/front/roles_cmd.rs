//! `brokenapp roles list|add|remove` and `brokenapp login --role <name>`.
//!
//! `roles add` writes the `[[roles]]` entry into `.brokenapp/config.toml`
//! (env: references only; the rest of the file is kept as written) and, for
//! values that are not in the environment, prompts with hidden input (or
//! reads `--stdin`) and stores them in the gitignored, mode-0600
//! `.brokenapp/credentials.toml`. Values are never printed.
//!
//! `login --role` signs a role in: for `method = "session"` (and `manual`) it
//! opens a browser so a person can sign in (SSO, MFA, magic links) and saves
//! the session for `map`; for `form`, `cookie`, `bearer`, `supabase`, and
//! `firebase` it verifies the credentials with the same check `map` runs before
//! a crawl.

use std::io::{BufRead, IsTerminal};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde::Serialize;

use super::locality;
use super::login_check::{self, LoginCheck};
use super::process::{DevSpec, DevSupervisor, resolve_dev_env};
use super::project::{self, ANONYMOUS_ROLE, ProjectCtx, ProjectTarget};
use super::roles::{
    self, CredentialsFile, ResolvedRole, RoleConfig, RoleCredentials, RoleMethod, SecretField,
    SecretSource,
};
use crate::config::AuthConfig;
use crate::session::storage_state::{self, CaptureOptions};

#[derive(Debug, Args)]
pub struct RolesArgs {
    #[command(subcommand)]
    pub cmd: RolesCommand,
}

impl RolesArgs {
    pub fn wants_json(&self) -> bool {
        match &self.cmd {
            RolesCommand::List(a) => a.json,
            RolesCommand::Add(a) => a.json,
            RolesCommand::Remove(a) => a.json,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum RolesCommand {
    /// List roles: method, where credentials come from (never values), session age, last map.
    List(RolesListArgs),
    /// Add (or with --force replace) a role; prompts for values not in the environment.
    Add(RolesAddArgs),
    /// Remove a role from config.toml and its values from credentials.toml (maps are kept).
    Remove(RolesRemoveArgs),
}

#[derive(Debug, Args)]
pub struct RolesListArgs {
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Args)]
pub struct RolesAddArgs {
    /// Role name: lowercase letters, digits, `-`, `_` (e.g. admin, coach, store-manager).
    pub name: String,
    /// form | session | cookie | bearer | supabase | firebase | manual.
    #[arg(long, default_value = "form")]
    pub method: String,
    /// Login page (form, manual), e.g. /sign-in. Default for form: /login.
    #[arg(long)]
    pub login_url: Option<String>,
    /// Read the username/email from this environment variable (config gets `env:NAME`).
    #[arg(long, value_name = "NAME")]
    pub username_env: Option<String>,
    /// Read the password from this environment variable.
    #[arg(long, value_name = "NAME")]
    pub password_env: Option<String>,
    /// method = bearer: read the token from this environment variable.
    #[arg(long, value_name = "NAME")]
    pub token_env: Option<String>,
    /// method = cookie: read the Cookie header value from this environment variable.
    #[arg(long, value_name = "NAME")]
    pub cookie_env: Option<String>,
    /// CSS selector of the username field (auto-detected when omitted).
    #[arg(long)]
    pub username_selector: Option<String>,
    #[arg(long)]
    pub password_selector: Option<String>,
    #[arg(long)]
    pub submit_selector: Option<String>,
    /// method = session: session file relative to .brokenapp/ (default session/<name>.json).
    #[arg(long)]
    pub session: Option<String>,
    /// method = supabase: project URL (e.g. https://<ref>.supabase.co or http://127.0.0.1:54321).
    #[arg(long)]
    pub project_url: Option<String>,
    /// method = supabase: anon key (literal or env:NAME).
    #[arg(long, conflicts_with = "anon_key_env")]
    pub anon_key: Option<String>,
    /// method = supabase: read the anon key from this environment variable (config gets `env:NAME`).
    #[arg(long, value_name = "NAME", conflicts_with = "anon_key")]
    pub anon_key_env: Option<String>,
    /// method = firebase: web API key (literal or env:NAME).
    #[arg(long, conflicts_with = "api_key_env")]
    pub api_key: Option<String>,
    /// method = firebase: read the web API key from this environment variable (config gets `env:NAME`).
    #[arg(long, value_name = "NAME", conflicts_with = "api_key")]
    pub api_key_env: Option<String>,
    /// A path that answers 200 only when signed in (e.g. /api/me); verified after login.
    #[arg(long)]
    pub check: Option<String>,
    /// Extra routes to seed for this role (repeatable), e.g. /admin.
    #[arg(long = "extra-route")]
    pub extra_routes: Vec<String>,
    #[arg(long)]
    pub description: Option<String>,
    /// Read secret values from stdin, one per line, in order: username then
    /// password (form/supabase/firebase), token (bearer), or cookie (cookie).
    #[arg(long, conflicts_with = "no_prompt")]
    pub stdin: bool,
    /// Never prompt; values not given now can be added later.
    #[arg(long)]
    pub no_prompt: bool,
    /// Replace a role with the same name.
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Args)]
pub struct RolesRemoveArgs {
    pub name: String,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// The role to sign in as.
    #[arg(long)]
    pub role: String,
    /// Seconds to wait for a person to finish signing in (session/manual).
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,
    /// Do not start the dev server; fail if the URL is not reachable.
    #[arg(long)]
    pub no_start: bool,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

pub async fn run(args: RolesArgs) -> Result<i32> {
    match args.cmd {
        RolesCommand::List(a) => run_list(a),
        RolesCommand::Add(a) => run_add(a),
        RolesCommand::Remove(a) => run_remove(a),
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// Readiness of one role (never values).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RoleStatus {
    pub name: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    /// Ready to map: credentials (or session) present.
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<SecretSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_file: Option<String>,
    /// Age of the saved session file, in hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_age_hours: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_map: Option<String>,
    pub map_dir: String,
}

/// Saved sessions older than this are flagged (sessions often expire).
pub const SESSION_STALE_HOURS: u64 = 24 * 7;

fn file_age_hours(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(modified.elapsed().ok()?.as_secs() / 3600)
}

/// Effective missing list and saved-session path for a role.
///
/// `method = "manual"` requires a saved session file before headless `map` can
/// run it (just like `method = "session"`), so agents are never misled into
/// thinking a manual role is ready before a human runs `brokenapp login`.
fn effective_missing_and_session(
    role: &RoleConfig,
    state_dir: &Path,
    resolved: &ResolvedRole,
) -> (Vec<String>, Option<std::path::PathBuf>) {
    let mut missing = resolved.missing.clone();
    let mut session_path = resolved.session_file.clone();
    if role.method == RoleMethod::Manual {
        let path = session_path.unwrap_or_else(|| role.session_path(state_dir));
        if !path.is_file() && !missing.iter().any(|m| m.starts_with("session:")) {
            missing.push(format!(
                "session: no saved session at {} (run `brokenapp login --role {}`)",
                path.display(),
                role.name
            ));
        }
        session_path = Some(path);
    }
    (missing, session_path)
}

/// Passwordless dev-picker form role: `--submit-selector` is set, and no
/// username/password env refs, selectors, or stored credentials are configured.
fn is_button_only_form(role: &RoleConfig, creds: &CredentialsFile) -> bool {
    if role.method != RoleMethod::Form {
        return false;
    }
    if !role
        .submit_selector
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return false;
    }
    if role.username.is_some()
        || role.password.is_some()
        || role.username_selector.is_some()
        || role.password_selector.is_some()
    {
        return false;
    }
    creds.roles.get(&role.name).is_none_or(|c| {
        c.get(SecretField::Username).is_none() && c.get(SecretField::Password).is_none()
    })
}

/// Readiness of every configured role (anonymous first).
pub fn role_statuses(ctx: &ProjectCtx) -> Result<Vec<RoleStatus>> {
    let creds = roles::load_credentials(&ctx.credentials_path())?;
    let env = |name: &str| std::env::var(name).ok();
    let mut out = vec![RoleStatus {
        name: ANONYMOUS_ROLE.to_string(),
        method: "-".to_string(),
        login_url: None,
        ready: ctx.config.auth.include_anonymous(),
        credentials: Vec::new(),
        missing: if ctx.config.auth.include_anonymous() {
            Vec::new()
        } else {
            vec!["[auth] include_anonymous = false".to_string()]
        },
        session_file: None,
        session_age_hours: None,
        last_map: last_map(ctx, ANONYMOUS_ROLE),
        map_dir: rel(&ctx.role_paths(ANONYMOUS_ROLE).map_dir, &ctx.root),
    }];
    for role in &ctx.config.roles {
        let resolved = roles::resolve_role(role, &ctx.state_dir, &creds, &env);
        let (missing, session_path) =
            effective_missing_and_session(role, &ctx.state_dir, &resolved);
        let ready = missing.is_empty();
        out.push(RoleStatus {
            name: role.name.clone(),
            method: role.method.as_str().to_string(),
            login_url: matches!(role.method, RoleMethod::Form | RoleMethod::Manual)
                .then(|| role.login_path()),
            ready,
            credentials: resolved.sources.clone(),
            missing,
            session_file: session_path.as_ref().map(|p| rel(p, &ctx.state_dir)),
            session_age_hours: session_path.as_deref().and_then(file_age_hours),
            last_map: last_map(ctx, &role.name),
            map_dir: rel(&ctx.role_paths(&role.name).map_dir, &ctx.root),
        });
    }
    Ok(out)
}

fn last_map(ctx: &ProjectCtx, role: &str) -> Option<String> {
    let p = ctx.role_paths(role).latest_inventory_path();
    if !p.is_file() {
        return None;
    }
    crate::inventory::load(&p).ok().map(|i| i.generated_at)
}

fn rel(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"))
}

fn sources_text(sources: &[SecretSource]) -> String {
    sources
        .iter()
        .map(|s| {
            if s.from == "env" {
                format!("{} from ${}", s.field, s.env)
            } else {
                format!("{} from credentials.toml", s.field)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn run_list(args: RolesListArgs) -> Result<i32> {
    let ctx = project::resolve(&args.target)?;
    roles::validate_roles(&ctx.config, &ctx.config_path)?;
    let statuses = role_statuses(&ctx)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "project": ctx.name(),
                "credentials_file": ctx.credentials_path().display().to_string(),
                "roles": statuses,
            }))
            .context("serialize roles")?
        );
        return Ok(0);
    }
    if ctx.config.roles.is_empty() {
        println!(
            "No roles configured: `brokenapp map` maps the anonymous (logged-out) app only.\n\
             Add one: brokenapp roles add admin --login-url /sign-in   (prompts for the credentials)"
        );
        return Ok(0);
    }
    for s in &statuses {
        let mut detail = Vec::new();
        if let Some(url) = &s.login_url {
            detail.push(format!("login {url}"));
        }
        if !s.credentials.is_empty() {
            detail.push(sources_text(&s.credentials));
        }
        if let Some(f) = &s.session_file {
            detail.push(match s.session_age_hours {
                Some(h) => format!("session {f} ({})", age_text(h)),
                None => format!("session {f} (missing)"),
            });
        }
        detail.push(match &s.last_map {
            Some(at) => format!("mapped {at}"),
            None => "no map yet".to_string(),
        });
        println!(
            "{:<12} {:<9} {:<8} {}",
            s.name,
            s.method,
            if s.ready { "ready" } else { "NOT READY" },
            detail.join("; ")
        );
        for m in &s.missing {
            println!("{:<12} {:<9} {:<8} missing: {m}", "", "", "");
        }
    }
    Ok(0)
}

pub fn age_text(hours: u64) -> String {
    if hours < 1 {
        "saved under an hour ago".to_string()
    } else if hours < 48 {
        format!("saved {hours}h ago")
    } else {
        format!("saved {} days ago", hours / 24)
    }
}

// ---------------------------------------------------------------------------
// add / remove
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct AddReport {
    role: String,
    method: String,
    config: String,
    /// Fields read from the environment (`env:NAME` in config.toml).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    env_refs: Vec<String>,
    /// Fields stored in credentials.toml (names only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stored: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credentials_file: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    gitignore_added: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    missing: Vec<String>,
    next: String,
}

/// Where secret values come from during `roles add`.
enum ValueSource {
    Stdin(Vec<String>),
    Prompt,
    None,
}

fn env_flag(field: SecretField, a: &RolesAddArgs) -> Option<&str> {
    match field {
        SecretField::Username => a.username_env.as_deref(),
        SecretField::Password => a.password_env.as_deref(),
        SecretField::Token => a.token_env.as_deref(),
        SecretField::Cookie => a.cookie_env.as_deref(),
    }
}

/// Whether `roles add` may interactively prompt on stdin/TTY.
/// Never prompts in `--json`, `--no-prompt`, `--stdin`, or non-TTY mode.
fn should_prompt_for_add(a: &RolesAddArgs, stdin_is_terminal: bool) -> bool {
    !a.stdin && !a.no_prompt && !a.json && stdin_is_terminal
}

/// Whether `roles add` should skip prompting for `field` (either the user
/// explicitly passed `--<field>-env`, or its env var is already exported).
fn should_skip_secret_prompt(explicit_env_flag: bool, env_var_is_set: bool) -> bool {
    explicit_env_flag || env_var_is_set
}

fn normalize_env_flag_name(flag: &str, raw: &str) -> Result<String> {
    let name = raw
        .trim()
        .trim_start_matches("env:")
        .trim_start_matches('$');
    if roles::env_ref(&format!("env:{name}")).is_none() {
        bail!("{flag} {name:?} is not a valid environment variable name");
    }
    Ok(name.to_string())
}

/// Prompt for one value (hidden for secrets). With a stored value or
/// `allow_blank`, Enter keeps/skips it (`None`).
fn prompt_value(
    role: &str,
    field: SecretField,
    has_stored: bool,
    allow_blank: bool,
) -> Result<Option<String>> {
    let prompt = if has_stored {
        format!("{role} {} (Enter keeps the stored value)", field.as_str())
    } else if allow_blank {
        format!(
            "{role} {} (Enter skips for button-only login)",
            field.as_str()
        )
    } else {
        format!("{role} {}", field.as_str())
    };
    let can_empty = has_stored || allow_blank;
    let value = if field.hidden() {
        dialoguer::Password::new()
            .with_prompt(prompt)
            .allow_empty_password(can_empty)
            .interact()
            .context("read value")?
    } else {
        dialoguer::Input::<String>::new()
            .with_prompt(prompt)
            .allow_empty(can_empty)
            .interact_text()
            .context("read value")?
    };
    Ok(Some(value).filter(|v| !v.is_empty()))
}

/// Build the role from flags (no values).
fn role_from_args(a: &RolesAddArgs) -> Result<RoleConfig> {
    let method = RoleMethod::parse(&a.method).with_context(|| {
        format!(
            "--method {:?}: expected form, session, cookie, bearer, supabase, firebase or manual",
            a.method
        )
    })?;
    if a.anon_key.is_some() && a.anon_key_env.is_some() {
        bail!("--anon-key and --anon-key-env cannot both be set");
    }
    if a.api_key.is_some() && a.api_key_env.is_some() {
        bail!("--api-key and --api-key-env cannot both be set");
    }
    let mut role = RoleConfig {
        name: a.name.trim().to_string(),
        method,
        description: a.description.clone(),
        login_url: a.login_url.clone(),
        username_selector: a.username_selector.clone(),
        password_selector: a.password_selector.clone(),
        submit_selector: a.submit_selector.clone(),
        session: a.session.clone(),
        project_url: a.project_url.clone(),
        anon_key: a.anon_key.clone(),
        api_key: a.api_key.clone(),
        check: a.check.clone(),
        extra_routes: a.extra_routes.clone(),
        ..Default::default()
    };
    if method == RoleMethod::Form && role.login_url.is_none() {
        role.login_url = Some("/login".to_string());
    }
    if let Some(raw) = a.anon_key_env.as_deref() {
        let name = normalize_env_flag_name("--anon-key-env", raw)?;
        if method != RoleMethod::Supabase {
            bail!("--anon-key-env is not used by method \"{method}\"");
        }
        role.anon_key = Some(format!("env:{name}"));
    }
    if let Some(raw) = a.api_key_env.as_deref() {
        let name = normalize_env_flag_name("--api-key-env", raw)?;
        if method != RoleMethod::Firebase {
            bail!("--api-key-env is not used by method \"{method}\"");
        }
        role.api_key = Some(format!("env:{name}"));
    }
    if method == RoleMethod::Supabase
        && role
            .project_url
            .as_deref()
            .is_none_or(|u| url::Url::parse(u).is_err())
    {
        bail!(
            "method \"supabase\" needs --project-url (e.g. https://<ref>.supabase.co or http://127.0.0.1:54321)"
        );
    }
    for field in SecretField::ALL {
        if let Some(raw) = env_flag(field, a) {
            let flag = format!("--{}-env", field.as_str());
            let name = normalize_env_flag_name(&flag, raw)?;
            if !method.secret_fields().contains(&field) {
                bail!(
                    "--{}-env is not used by method \"{method}\"",
                    field.as_str()
                );
            }
            role.set_secret(field, Some(format!("env:{name}")));
        }
    }
    roles::validate_role_name(&role.name)?;
    Ok(role)
}

fn state_dir_flag(state_dir: Option<&Path>) -> String {
    state_dir
        .map(|p| p.display().to_string())
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!(" --state-dir {}", shell_words::quote(&s)))
        .unwrap_or_default()
}

fn roles_add_next_hint(
    role: &str,
    method: RoleMethod,
    ready: bool,
    state_dir: Option<&Path>,
) -> String {
    let sd = state_dir_flag(state_dir);
    match method {
        RoleMethod::Session | RoleMethod::Manual => format!(
            "brokenapp login --role {role}{sd}   (sign in once in a browser; saves the session), then: brokenapp map --role {role}{sd}"
        ),
        _ if !ready => format!(
            "provide the missing values (export them, or `brokenapp roles add {role} --force{sd}`), then: brokenapp login --role {role}{sd} && brokenapp map --role {role}{sd}"
        ),
        _ => format!(
            "brokenapp login --role {role}{sd}   (verifies the credentials), then: brokenapp map --role {role}{sd}"
        ),
    }
}

fn login_probe_timeout(args_timeout: u64, ready_timeout_secs: u64) -> Duration {
    Duration::from_secs(args_timeout.max(ready_timeout_secs).clamp(30, 120))
}

fn run_add(a: RolesAddArgs) -> Result<i32> {
    let ctx = project::resolve(&a.target)?;
    let mut role = role_from_args(&a)?;
    if roles::find_role(&ctx.config, &role.name).is_some() && !a.force {
        bail!(
            "role '{}' already exists in {}; pass --force to replace it",
            role.name,
            ctx.config_path.display()
        );
    }
    let mut source = if a.stdin {
        let lines: Vec<String> = std::io::stdin()
            .lock()
            .lines()
            .map(|l| l.map(|l| l.trim_end_matches('\r').to_string()))
            .collect::<std::io::Result<_>>()
            .context("read values from stdin")?;
        ValueSource::Stdin(lines.into_iter().rev().collect())
    } else if should_prompt_for_add(&a, std::io::stdin().is_terminal()) {
        ValueSource::Prompt
    } else {
        ValueSource::None
    };

    // Values for fields the environment does not provide. Values stored
    // earlier stay unless a new one is given (`--force` to change a URL
    // does not drop the password).
    let creds_path = ctx.credentials_path();
    let mut creds: CredentialsFile = roles::load_credentials(&creds_path)?;
    let previous = creds.roles.get(&role.name).cloned().unwrap_or_default();
    let mut stored = RoleCredentials::default();
    let mut provided = Vec::new();
    let mut env_refs = Vec::new();
    let allow_blank_for_button_only = role.method == RoleMethod::Form
        && role
            .submit_selector
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
    for field in role.method.secret_fields() {
        let explicit_env = env_flag(*field, &a).is_some();
        if let Some(r) = role.secret(*field).and_then(roles::env_ref) {
            let set = std::env::var(r).is_ok_and(|v| !v.trim().is_empty());
            env_refs.push(format!(
                "{} from ${r}{}",
                field.as_str(),
                if set { "" } else { " (not set in this shell)" }
            ));
            if should_skip_secret_prompt(explicit_env, set) {
                if !set && let Some(v) = previous.get(*field).map(str::to_string) {
                    stored.set(*field, Some(v));
                }
                continue;
            }
        }
        let kept = previous.get(*field).map(str::to_string);
        let value = match &mut source {
            ValueSource::Stdin(lines) => lines.pop().filter(|v| !v.is_empty()),
            ValueSource::Prompt => prompt_value(
                &role.name,
                *field,
                kept.is_some(),
                allow_blank_for_button_only,
            )?,
            ValueSource::None => None,
        };
        if value.is_some() {
            provided.push(field.as_str());
        }
        if let Some(v) = value.or(kept) {
            stored.set(*field, Some(v));
        }
    }
    for (label, raw) in [
        ("anon_key", role.anon_key.as_deref()),
        ("api_key", role.api_key.as_deref()),
    ] {
        if let Some(r) = raw.and_then(roles::env_ref) {
            let set = std::env::var(r).is_ok_and(|v| !v.trim().is_empty());
            env_refs.push(format!(
                "{label} from ${r}{}",
                if set { "" } else { " (not set in this shell)" }
            ));
        }
    }

    // Config: replace or append the [[roles]] block; validate before writing.
    let raw = std::fs::read_to_string(&ctx.config_path)
        .with_context(|| format!("read {}", ctx.config_path.display()))?;
    let (without, _) = roles::remove_role(&raw, &role.name)?;
    let updated = roles::append_role(&without, &role)?;
    let parsed: project::ProjectConfig =
        toml::from_str(&updated).context("the updated config does not parse")?;
    roles::validate_roles(&parsed, &ctx.config_path)?;

    // Credentials first (so a config naming them never exists without them).
    let mut gitignore_added = Vec::new();
    let had = creds.roles.contains_key(&role.name);
    if stored != previous {
        if stored.is_empty() {
            creds.roles.remove(&role.name);
        } else {
            creds.roles.insert(role.name.clone(), stored.clone());
        }
        gitignore_added = roles::ensure_private_ignored(&ctx.state_dir)?;
        roles::save_credentials(&creds_path, &creds)?;
    }
    if matches!(role.method, RoleMethod::Session | RoleMethod::Manual) {
        gitignore_added.extend(roles::ensure_private_ignored(&ctx.state_dir)?);
    }
    std::fs::write(&ctx.config_path, &updated)
        .with_context(|| format!("write {}", ctx.config_path.display()))?;

    // What is still missing, from the config as written.
    let ctx = project::load_ctx(&ctx.state_dir)?;
    let creds = roles::load_credentials(&creds_path)?;
    let env = |n: &str| std::env::var(n).ok();
    let written = roles::find_role(&ctx.config, &role.name).context("role written")?;
    role = written.clone();
    let resolved = roles::resolve_role(&role, &ctx.state_dir, &creds, &env);
    let (missing, _) = effective_missing_and_session(&role, &ctx.state_dir, &resolved);
    let ready = missing.is_empty();
    let explicit_state_dir = a.target.state_dir.as_ref().map(|_| ctx.state_dir.as_path());
    let next = roles_add_next_hint(&role.name, role.method, ready, explicit_state_dir);
    let report = AddReport {
        role: role.name.clone(),
        method: role.method.as_str().to_string(),
        config: ctx.config_path.display().to_string(),
        env_refs,
        stored: provided.iter().map(|s| s.to_string()).collect(),
        credentials_file: (!stored.is_empty()).then(|| creds_path.display().to_string()),
        gitignore_added,
        missing,
        next,
    };
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize roles add")?
        );
        return Ok(0);
    }
    println!(
        "{} role '{}' ({}) in {}",
        if had || a.force { "Saved" } else { "Added" },
        report.role,
        report.method,
        report.config
    );
    for r in &report.env_refs {
        println!("  env       {r}");
    }
    if let Some(f) = &report.credentials_file {
        println!(
            "  stored    {} in {f} (mode 600, gitignored; values are never printed)",
            report.stored.join(", ")
        );
    }
    for l in &report.gitignore_added {
        println!("  gitignore added {l} to .brokenapp/.gitignore");
    }
    for m in &report.missing {
        println!("  missing   {m}");
    }
    println!("next: {}", report.next);
    Ok(0)
}

fn run_remove(a: RolesRemoveArgs) -> Result<i32> {
    let ctx = project::resolve(&a.target)?;
    let raw = std::fs::read_to_string(&ctx.config_path)
        .with_context(|| format!("read {}", ctx.config_path.display()))?;
    let (updated, removed) = roles::remove_role(&raw, &a.name)?;
    if !removed {
        bail!("role '{}' is not in {}", a.name, ctx.config_path.display());
    }
    let creds_path = ctx.credentials_path();
    let mut creds = roles::load_credentials(&creds_path)?;
    let had_creds = creds.roles.remove(&a.name).is_some();
    if had_creds {
        roles::save_credentials(&creds_path, &creds)?;
    }
    std::fs::write(&ctx.config_path, updated)
        .with_context(|| format!("write {}", ctx.config_path.display()))?;
    let map_dir = ctx.role_paths(&a.name).map_dir;
    let session = roles::find_role(&ctx.config, &a.name).map(|r| r.session_path(&ctx.state_dir));
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "removed": a.name,
                "config": ctx.config_path.display().to_string(),
                "credentials_removed": had_creds,
                "kept_map_dir": map_dir.is_dir().then(|| map_dir.display().to_string()),
                "kept_session": session.as_ref().filter(|p| p.is_file()).map(|p| p.display().to_string()),
            }))
            .context("serialize roles remove")?
        );
        return Ok(0);
    }
    println!(
        "Removed role '{}' from {}",
        a.name,
        ctx.config_path.display()
    );
    if had_creds {
        println!("  credentials removed from {}", creds_path.display());
    }
    if map_dir.is_dir() {
        println!(
            "  kept      {} (delete it yourself if you no longer need the map)",
            map_dir.display()
        );
    }
    if let Some(p) = session.filter(|p| p.is_file()) {
        println!(
            "  kept      {} (saved session; delete it yourself)",
            p.display()
        );
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct LoginReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    role: String,
    method: String,
    /// `saved` (session captured), `ok` (credentials verified), `error` (failed).
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cookies: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    check: Option<LoginCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Normalize every failing `LoginReport` to the uniform CLI error envelope:
/// `exit_code: 1`, `status: "error"`, and a non-empty `error` string.
fn finalize_login_report(report: &mut LoginReport) -> i32 {
    if matches!(report.status.as_str(), "ok" | "saved") {
        report.exit_code = None;
        return 0;
    }
    report.status = "error".to_string();
    report.exit_code = Some(1);
    if report.error.as_deref().is_none_or(|e| e.trim().is_empty()) {
        report.error = Some(
            report
                .check
                .as_ref()
                .map(|c| c.detail.clone())
                .filter(|d| !d.trim().is_empty())
                .unwrap_or_else(|| "login failed".to_string()),
        );
    }
    1
}

fn resolve_secret_value_for_login(
    field: SecretField,
    resolved: &ResolvedRole,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String> {
    let src = resolved
        .sources
        .iter()
        .find(|s| s.field == field.as_str())
        .with_context(|| format!("missing resolved {} credential", field.as_str()))?;
    let val = if src.from == "credentials" {
        resolved
            .env
            .iter()
            .find(|(k, _)| k == &src.env)
            .map(|(_, v)| v.clone())
    } else {
        env(&src.env)
    };
    val.filter(|v| !v.trim().is_empty())
        .with_context(|| format!("{} value from {} is empty", field.as_str(), src.env))
}

fn resolve_public_key_for_login(
    raw: Option<&str>,
    what: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String> {
    let raw = raw.unwrap_or_default().trim();
    if let Some(var) = roles::env_ref(raw) {
        return env(var)
            .filter(|v| !v.trim().is_empty())
            .with_context(|| format!("{what}: {var} is not set (export it)"));
    }
    if raw.is_empty() {
        bail!("{what} is not configured");
    }
    Ok(raw.to_string())
}

fn build_auth_config_for_login(
    role: &RoleConfig,
    resolved: &ResolvedRole,
    creds: &CredentialsFile,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<AuthConfig> {
    match role.method {
        RoleMethod::Form => {
            if let Some(form) = resolved.form.as_ref() {
                Ok(AuthConfig::Form {
                    login_url: form.login_url.clone(),
                    username_selector: form.username_selector.clone(),
                    password_selector: form.password_selector.clone(),
                    submit_selector: form.submit_selector.clone(),
                    username: form.username.clone(),
                    password: form.password.clone(),
                })
            } else if is_button_only_form(role, creds) {
                Ok(AuthConfig::Form {
                    login_url: role.login_path(),
                    username_selector: String::new(),
                    password_selector: String::new(),
                    submit_selector: role.submit_selector.clone().unwrap_or_default(),
                    username: String::new(),
                    password: String::new(),
                })
            } else {
                bail!("{}", resolved.missing.join("; "))
            }
        }
        RoleMethod::Cookie => Ok(AuthConfig::Cookie {
            cookie: resolve_secret_value_for_login(SecretField::Cookie, resolved, env)?,
        }),
        RoleMethod::Bearer => Ok(AuthConfig::BearerToken {
            token: resolve_secret_value_for_login(SecretField::Token, resolved, env)?,
        }),
        RoleMethod::Supabase => Ok(AuthConfig::Supabase {
            project_url: role.project_url.clone().unwrap_or_default(),
            anon_key: resolve_public_key_for_login(role.anon_key.as_deref(), "anon_key", env)?,
            email: resolve_secret_value_for_login(SecretField::Username, resolved, env)?,
            password: resolve_secret_value_for_login(SecretField::Password, resolved, env)?,
        }),
        RoleMethod::Firebase => Ok(AuthConfig::Firebase {
            api_key: resolve_public_key_for_login(role.api_key.as_deref(), "api_key", env)?,
            email: resolve_secret_value_for_login(SecretField::Username, resolved, env)?,
            password: resolve_secret_value_for_login(SecretField::Password, resolved, env)?,
        }),
        RoleMethod::Session | RoleMethod::Manual => {
            bail!(
                "interactive capture method \"{}\" does not use check_auth_login",
                role.method
            )
        }
    }
}

fn emit_login_report(mut report: LoginReport, json: bool) -> Result<i32> {
    let code = finalize_login_report(&mut report);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize login report")?
        );
        return Ok(code);
    }
    match report.status.as_str() {
        "saved" => {
            println!(
                "Saved the {} session to {}{}",
                report.role,
                report.session_file.as_deref().unwrap_or("?"),
                report
                    .cookies
                    .map(|n| format!(" ({n} cookies)"))
                    .unwrap_or_default()
            );
            println!("next: brokenapp map --role {}", report.role);
        }
        "ok" => {
            println!(
                "Login for {} works: {}",
                report.role,
                report
                    .check
                    .as_ref()
                    .map(|c| c.detail.as_str())
                    .unwrap_or("")
            );
            println!("next: brokenapp map --role {}", report.role);
        }
        _ => {
            println!(
                "Login for {} FAILED: {}",
                report.role,
                report
                    .error
                    .as_deref()
                    .or(report.check.as_ref().map(|c| c.detail.as_str()))
                    .unwrap_or("unknown error")
            );
        }
    }
    Ok(code)
}

pub async fn run_login(a: LoginArgs) -> Result<i32> {
    let ctx = project::resolve(&a.target)?;
    roles::validate_roles(&ctx.config, &ctx.config_path)?;
    let Some(role) = roles::find_role(&ctx.config, &a.role).cloned() else {
        bail!(
            "unknown role '{}' (configured: {}); add it with `brokenapp roles add {}`",
            a.role,
            ctx.config
                .roles
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            a.role
        );
    };
    let cfg = &ctx.config;
    if cfg.project.protected {
        bail!(
            "project '{}' is protected (project.protected = true); `brokenapp login` refuses to open it",
            ctx.name()
        );
    }
    let registry = project::Registry::load().context("read project registry (protected flags)")?;
    if registry.projects.iter().any(|entry| {
        entry.protected
            && (Path::new(&entry.state_dir) == ctx.state_dir || entry.name == ctx.name())
    }) {
        bail!(
            "project '{}' is protected in the registry; `brokenapp login` refuses to open it",
            ctx.name()
        );
    }
    let url = locality::parse_target_url(&cfg.project.url, cfg.scan.allow_remote)?;

    // For non-interactive auth methods (`form`, `cookie`, `bearer`, `supabase`,
    // `firebase`), verify credentials are present BEFORE probing or starting
    // the dev server so missing env vars fail fast with a uniform JSON envelope.
    let preflight = if !matches!(role.method, RoleMethod::Session | RoleMethod::Manual) {
        let creds = roles::load_credentials(&ctx.credentials_path())?;
        let env = |n: &str| std::env::var(n).ok();
        let resolved = roles::resolve_role(&role, &ctx.state_dir, &creds, &env);
        if !resolved.ready() && !is_button_only_form(&role, &creds) {
            let report = LoginReport {
                exit_code: Some(1),
                role: role.name.clone(),
                method: role.method.as_str().to_string(),
                status: "error".to_string(),
                session_file: None,
                cookies: None,
                check: None,
                error: Some(resolved.missing.join("; ")),
            };
            return emit_login_report(report, a.json);
        }
        let auth = build_auth_config_for_login(&role, &resolved, &creds, &env)?;
        Some((resolved, auth))
    } else {
        None
    };

    // The app must answer; start dev_cmd like `map` does.
    let dev = DevSupervisor::new(
        url.clone(),
        Duration::from_secs(cfg.project.ready_timeout_secs.max(1)),
    );
    if !locality::probe(&url, Duration::from_secs(5))
        .await
        .reachable
    {
        let Some(cmd) = cfg.project.dev_cmd.clone().filter(|c| !c.trim().is_empty()) else {
            bail!("{url} is not reachable; start the app first");
        };
        if a.no_start {
            bail!("{url} is not reachable and --no-start was given");
        }
        let log_dir = ctx.state_dir.join("session");
        std::fs::create_dir_all(&log_dir)
            .with_context(|| format!("create {}", log_dir.display()))?;
        roles::ensure_private_ignored(&ctx.state_dir)?;
        let (env, _) = resolve_dev_env(&cfg.project.dev_env);
        eprintln!(
            "starting dev server: {}",
            super::secrets::redact_command(&cmd)
        );
        dev.start(DevSpec {
            cmd,
            cwd: match cfg.project.dev_cwd.as_deref() {
                Some(rel) => ctx.root.join(rel),
                None => ctx.root.clone(),
            },
            env,
            log: log_dir.join("login-dev-server.log"),
        })
        .await?;
    }
    let result = login_inner(&ctx, &role, &url, &a, preflight).await;
    dev.stop().await;
    let report = result?;
    emit_login_report(report, a.json)
}

async fn login_inner(
    ctx: &ProjectCtx,
    role: &RoleConfig,
    url: &url::Url,
    a: &LoginArgs,
    preflight: Option<(ResolvedRole, AuthConfig)>,
) -> Result<LoginReport> {
    let mut report = LoginReport {
        exit_code: None,
        role: role.name.clone(),
        method: role.method.as_str().to_string(),
        status: "error".to_string(),
        session_file: None,
        cookies: None,
        check: None,
        error: None,
    };
    if let Some((resolved, auth)) = preflight {
        let redactor = roles::Redactor::new(resolved.secret_values.clone(), &[role.name.as_str()]);
        let mut check = login_check::check_auth_login(
            &auth,
            &login_check::LoginCheckOptions {
                base_url: url.clone(),
                headless: ctx.config.scan.headless,
                ignore_https_errors: locality::is_local_url(url),
                write_guard_allow: ctx.config.scan.write_guard_allow.clone(),
                probe_timeout: login_probe_timeout(
                    a.timeout,
                    ctx.config.project.ready_timeout_secs,
                ),
                contract: resolved
                    .contract
                    .clone()
                    .map(|contract| toml::Value::Table(contract).try_into())
                    .transpose()
                    .context("parse role authentication check")?,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!(redactor.redact(&format!("{e:#}"))))?;
        check.detail = redactor.redact(&check.detail);
        if let Some(landed) = check.landed.as_mut() {
            *landed = redactor.redact(landed);
        }
        if let Some(alert) = check.page_alert.as_mut() {
            *alert = redactor.redact(alert);
        }
        if check.ok {
            report.status = "ok".to_string();
        } else {
            report.status = "error".to_string();
            report.exit_code = Some(1);
            report.error = Some(check.detail.clone());
        }
        report.check = Some(check);
        return Ok(report);
    }
    // Session / manual: a person signs in; the session is saved for `map`.
    let out_path = role.session_path(&ctx.state_dir);
    roles::ensure_private_ignored(&ctx.state_dir)?;
    let start = match role.login_url.as_deref() {
        Some(path) => url
            .join(path)
            .with_context(|| format!("login_url {path:?}"))?,
        None => url.clone(),
    };
    eprintln!(
        "Opening {start} in a browser window: sign in as {}; the session is saved when you are done.",
        role.name
    );
    match storage_state::capture_storage_state(&CaptureOptions {
        url: start.to_string(),
        out_path: out_path.clone(),
        chrome_executable: None,
        timeout_secs: a.timeout,
        done_when_url_leaves: role.login_url.clone(),
    })
    .await
    {
        Ok(captured) => {
            report.status = "saved".to_string();
            report.session_file = Some(out_path.display().to_string());
            report.cookies = Some(captured.cookies);
        }
        Err(err) => {
            report.status = "error".to_string();
            report.exit_code = Some(1);
            report.error = Some(format!("{err:#}"));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_args(name: &str) -> RolesAddArgs {
        RolesAddArgs {
            name: name.into(),
            method: "form".into(),
            login_url: None,
            username_env: None,
            password_env: None,
            token_env: None,
            cookie_env: None,
            username_selector: None,
            password_selector: None,
            submit_selector: None,
            session: None,
            project_url: None,
            anon_key: None,
            anon_key_env: None,
            api_key: None,
            api_key_env: None,
            check: None,
            extra_routes: Vec::new(),
            description: None,
            stdin: false,
            no_prompt: true,
            force: false,
            json: false,
            target: ProjectTarget::default(),
        }
    }

    #[test]
    fn roles_from_flags_use_env_references_only() {
        let mut a = add_args("admin");
        a.username_env = Some("ADMIN_EMAIL".into());
        a.password_env = Some("$ADMIN_PASSWORD".into());
        let role = role_from_args(&a).unwrap();
        assert_eq!(role.username.as_deref(), Some("env:ADMIN_EMAIL"));
        assert_eq!(role.password.as_deref(), Some("env:ADMIN_PASSWORD"));
        assert_eq!(role.login_url.as_deref(), Some("/login"));

        let mut bad = add_args("admin");
        bad.token_env = Some("TOKEN".into());
        assert!(format!("{:#}", role_from_args(&bad).unwrap_err()).contains("not used by method"));
        let mut bad = add_args("admin");
        bad.password_env = Some("not a name".into());
        assert!(role_from_args(&bad).is_err());
        assert!(role_from_args(&add_args("All")).is_err());
        let mut m = add_args("api");
        m.method = "token".into();
        assert_eq!(role_from_args(&m).unwrap().method, RoleMethod::Bearer);

        // Supabase --anon-key-env & local dev project URL + Firebase --api-key-env.
        let mut sb = add_args("sb");
        sb.method = "supabase".into();
        sb.project_url = Some("http://127.0.0.1:54321".into());
        sb.anon_key_env = Some("$SUPABASE_ANON_KEY".into());
        sb.username_env = Some("SB_EMAIL".into());
        sb.password_env = Some("SB_PASSWORD".into());
        let sb_role = role_from_args(&sb).unwrap();
        assert_eq!(sb_role.anon_key.as_deref(), Some("env:SUPABASE_ANON_KEY"));
        assert_eq!(
            sb_role.project_url.as_deref(),
            Some("http://127.0.0.1:54321")
        );

        let mut sb_no_url = add_args("sb2");
        sb_no_url.method = "supabase".into();
        sb_no_url.anon_key_env = Some("SUPABASE_ANON_KEY".into());
        let sb_err = format!("{:#}", role_from_args(&sb_no_url).unwrap_err());
        assert!(sb_err.contains("http://127.0.0.1:54321"), "{sb_err}");

        let mut fb = add_args("fb");
        fb.method = "firebase".into();
        fb.api_key_env = Some("FIREBASE_API_KEY".into());
        let fb_role = role_from_args(&fb).unwrap();
        assert_eq!(fb_role.api_key.as_deref(), Some("env:FIREBASE_API_KEY"));

        let mut bad_sb = add_args("admin");
        bad_sb.anon_key_env = Some("SUPABASE_ANON_KEY".into());
        assert!(
            format!("{:#}", role_from_args(&bad_sb).unwrap_err()).contains("not used by method")
        );
    }

    #[test]
    fn roles_add_cookie_env_unset_json_never_prompts_and_returns_cleanly() {
        // Even if stdin were a TTY, `--json` disables prompting and explicit
        // `--*-env` flags always skip prompting even when unset in the shell.
        let mut tty_json = add_args("staff");
        tty_json.method = "cookie".into();
        tty_json.cookie_env = Some("BROKENAPP_TEST_UNSET_COOKIE_999".into());
        tty_json.no_prompt = false;
        tty_json.json = true;
        assert!(!should_prompt_for_add(&tty_json, true));
        assert!(should_skip_secret_prompt(true, false));
        assert!(!should_skip_secret_prompt(false, false));

        // End-to-end `run_add` against a temp project without `--no-prompt`.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='x'\nurl='http://127.0.0.1:3000'\n",
        )
        .unwrap();
        tty_json.target = ProjectTarget {
            state_dir: Some(state.clone()),
            project: None,
        };
        let code = run_add(tty_json).unwrap();
        assert_eq!(code, 0);
        let cfg_raw = std::fs::read_to_string(state.join("config.toml")).unwrap();
        assert!(
            cfg_raw.contains("cookie = \"env:BROKENAPP_TEST_UNSET_COOKIE_999\""),
            "{cfg_raw}"
        );
    }

    #[test]
    fn manual_role_is_not_ready_without_saved_session_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='x'\nurl='http://127.0.0.1:3000'\n\n\
             [[roles]]\nname='sso-user'\nmethod='manual'\nlogin_url='/login'\n",
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let st = role_statuses(&ctx).unwrap();
        let manual = st.iter().find(|r| r.name == "sso-user").unwrap();
        assert!(
            !manual.ready,
            "manual role without session must not be ready"
        );
        assert!(
            manual
                .missing
                .iter()
                .any(|m| m.contains("brokenapp login --role sso-user")),
            "{:?}",
            manual.missing
        );
        assert_eq!(
            manual.session_file.as_deref(),
            Some("session/sso-user.json")
        );
        assert_eq!(manual.session_age_hours, None);

        // Once the saved session exists, the manual role becomes ready.
        std::fs::create_dir_all(state.join("session")).unwrap();
        std::fs::write(state.join("session/sso-user.json"), "{}").unwrap();
        let st = role_statuses(&ctx).unwrap();
        let manual = st.iter().find(|r| r.name == "sso-user").unwrap();
        assert!(manual.ready, "{:?}", manual.missing);
        assert_eq!(manual.session_age_hours, Some(0));
    }

    #[tokio::test]
    async fn login_json_failure_always_emits_uniform_error_envelope() {
        // 1. Direct report normalization guarantees exit_code=1, status="error", error!=None.
        let mut form_fail = LoginReport {
            exit_code: None,
            role: "admin".into(),
            method: "form".into(),
            status: "failed".into(),
            session_file: None,
            cookies: None,
            check: Some(LoginCheck {
                ok: false,
                detail: "login_failed: invalid credentials".into(),
                landed: Some("http://127.0.0.1:3000/login".into()),
                http_status: Some(401),
                page_alert: Some("Invalid password".into()),
            }),
            error: None,
        };
        let code = finalize_login_report(&mut form_fail);
        assert_eq!(code, 1);
        let val = serde_json::to_value(&form_fail).unwrap();
        assert_eq!(val["exit_code"], 1);
        assert_eq!(val["status"], "error");
        assert_eq!(val["error"], "login_failed: invalid credentials");
        assert_eq!(val["check"]["http_status"], 401);
        assert_eq!(val["check"]["page_alert"], "Invalid password");

        // 2. Missing env var for cookie/bearer/supabase fails fast with exit code 1
        //    (no refusal like "nothing to sign in to interactively").
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='brokenapp-unit-test-login-envelope'\nurl='http://127.0.0.1:3000'\n\n\
             [[roles]]\nname='api'\nmethod='cookie'\ncookie='env:BROKENAPP_TEST_MISSING_COOKIE_999'\n",
        )
        .unwrap();
        let code = run_login(LoginArgs {
            role: "api".into(),
            timeout: 10,
            no_start: true,
            json: true,
            target: ProjectTarget {
                state_dir: Some(state),
                project: None,
            },
        })
        .await
        .unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn statuses_report_sources_and_session_age_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(state.join("session")).unwrap();
        std::fs::write(
            state.join("config.toml"),
            "[project]\nname='x'\nurl='http://127.0.0.1:3000'\n\n\
             [[roles]]\nname='admin'\nmethod='form'\nlogin_url='/login'\n\
             username='env:BROKENAPP_TEST_UNSET_ADMIN_EMAIL'\n\n\
             [[roles]]\nname='coach'\nmethod='session'\n",
        )
        .unwrap();
        std::fs::write(state.join("session/coach.json"), "{}").unwrap();
        let mut creds = CredentialsFile::default();
        creds.roles.insert(
            "admin".into(),
            RoleCredentials {
                username: Some("admin@example.test".into()),
                password: Some("pw-never-shown".into()),
                ..Default::default()
            },
        );
        roles::save_credentials(&state.join(project::CREDENTIALS_FILE), &creds).unwrap();
        let ctx = project::load_ctx(&state).unwrap();
        let st = role_statuses(&ctx).unwrap();
        assert_eq!(
            st.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            vec!["anonymous", "admin", "coach"]
        );
        assert!(st[1].ready, "{:?}", st[1].missing);
        assert_eq!(
            sources_text(&st[1].credentials),
            "username from credentials.toml, password from credentials.toml"
        );
        assert!(st[2].ready && st[2].session_age_hours == Some(0));
        let json = serde_json::to_string(&st).unwrap();
        assert!(!json.contains("pw-never-shown") && !json.contains("admin@example.test"));
        assert_eq!(age_text(0), "saved under an hour ago");
        assert_eq!(age_text(72), "saved 3 days ago");
    }

    #[test]
    fn roles_add_next_hint_preserves_state_dir_and_login_probe_timeout_bounds() {
        // Without --state-dir, commands omit the flag.
        let plain = roles_add_next_hint("admin", RoleMethod::Form, true, None);
        assert!(plain.contains("brokenapp login --role admin"), "{plain}");
        assert!(plain.contains("brokenapp map --role admin"), "{plain}");
        assert!(!plain.contains("--state-dir"), "{plain}");

        // With --state-dir (including spaces), every command preserves a quoted --state-dir.
        let sd = Path::new("/tmp/my app/.brokenapp");
        let ready_hint = roles_add_next_hint("admin", RoleMethod::Cookie, true, Some(sd));
        assert!(
            ready_hint
                .contains("brokenapp login --role admin --state-dir '/tmp/my app/.brokenapp'"),
            "{ready_hint}"
        );
        assert!(
            ready_hint.contains("brokenapp map --role admin --state-dir '/tmp/my app/.brokenapp'"),
            "{ready_hint}"
        );

        let session_hint = roles_add_next_hint("sso", RoleMethod::Session, false, Some(sd));
        assert!(
            session_hint
                .contains("brokenapp login --role sso --state-dir '/tmp/my app/.brokenapp'"),
            "{session_hint}"
        );
        assert!(
            session_hint.contains("brokenapp map --role sso --state-dir '/tmp/my app/.brokenapp'"),
            "{session_hint}"
        );

        let missing_hint = roles_add_next_hint("staff", RoleMethod::Form, false, Some(sd));
        assert!(
            missing_hint
                .contains("brokenapp roles add staff --force --state-dir '/tmp/my app/.brokenapp'"),
            "{missing_hint}"
        );
        assert!(
            missing_hint
                .contains("brokenapp login --role staff --state-dir '/tmp/my app/.brokenapp'"),
            "{missing_hint}"
        );
        assert!(
            missing_hint
                .contains("brokenapp map --role staff --state-dir '/tmp/my app/.brokenapp'"),
            "{missing_hint}"
        );

        assert_eq!(login_probe_timeout(600, 120), Duration::from_secs(120));
        assert_eq!(login_probe_timeout(45, 60), Duration::from_secs(60));
        assert_eq!(login_probe_timeout(10, 10), Duration::from_secs(30));
    }
}
