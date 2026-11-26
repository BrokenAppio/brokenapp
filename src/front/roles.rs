//! Roles: the login types `brokenapp map` maps besides the anonymous
//! (logged-out) app — admin, user, coach, manager, any number of them.
//!
//! A role lives in `.brokenapp/config.toml` (committed):
//!
//! ```toml
//! [[roles]]
//! name = "admin"
//! method = "form"                 # form | session | cookie | bearer | supabase | firebase | manual
//! login_url = "/sign-in"
//! username = "env:ADMIN_EMAIL"    # env: references only; literal secrets are refused
//! password = "env:ADMIN_PASSWORD"
//! ```
//!
//! Secret values come from the shell environment (`env:NAME`) or from the
//! gitignored `.brokenapp/credentials.toml` (mode 0600, written by
//! `brokenapp roles add`). `map` hands them to the scan subprocess through
//! its environment only: the generated scan TOML carries `env:NAME`
//! references, never values, and every printed line is redacted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::project::{ANONYMOUS_ROLE, ProjectConfig, ProjectCtx};

/// Names that cannot be role names: the implicit role, `--roles` keywords,
/// and the control kinds `ui --role` accepted before roles existed.
pub const RESERVED_ROLE_NAMES: &[&str] = &[
    ANONYMOUS_ROLE,
    "all",
    "none",
    "default",
    "button",
    "link",
    "input",
    "select",
    "checkbox",
    "radio",
    "form",
    "tab",
    "other",
];

/// Control kinds (`Control.role`) accepted by `ui --kind` (and, for
/// backward compatibility, `ui --role`).
pub const CONTROL_KINDS: &[&str] = &[
    "button", "link", "input", "select", "checkbox", "radio", "form", "tab", "other",
];

const MAX_ROLE_NAME_LEN: usize = 40;

/// How a role signs in.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleMethod {
    /// Fill and submit the app's login form (selectors auto-detected).
    #[default]
    Form,
    /// A saved browser session from `brokenapp login --role <name>` (SSO, MFA, magic links).
    Session,
    /// A raw `Cookie:` header value.
    Cookie,
    /// An `Authorization: Bearer` token.
    Bearer,
    /// Supabase email/password sign-in.
    Supabase,
    /// Firebase email/password sign-in.
    Firebase,
    /// A visible browser window: a human signs in at the start of every scan.
    Manual,
}

impl RoleMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleMethod::Form => "form",
            RoleMethod::Session => "session",
            RoleMethod::Cookie => "cookie",
            RoleMethod::Bearer => "bearer",
            RoleMethod::Supabase => "supabase",
            RoleMethod::Firebase => "firebase",
            RoleMethod::Manual => "manual",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw.trim().to_ascii_lowercase().as_str() {
            "form" => RoleMethod::Form,
            "session" | "storage_state" => RoleMethod::Session,
            "cookie" => RoleMethod::Cookie,
            "bearer" | "token" => RoleMethod::Bearer,
            "supabase" => RoleMethod::Supabase,
            "firebase" => RoleMethod::Firebase,
            "manual" => RoleMethod::Manual,
            _ => return None,
        })
    }

    /// Secret fields this method needs, in prompt order.
    pub fn secret_fields(&self) -> &'static [SecretField] {
        match self {
            RoleMethod::Form | RoleMethod::Supabase | RoleMethod::Firebase => {
                &[SecretField::Username, SecretField::Password]
            }
            RoleMethod::Cookie => &[SecretField::Cookie],
            RoleMethod::Bearer => &[SecretField::Token],
            RoleMethod::Session | RoleMethod::Manual => &[],
        }
    }
}

impl fmt::Display for RoleMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A secret field of a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretField {
    Username,
    Password,
    Cookie,
    Token,
}

impl SecretField {
    pub const ALL: [SecretField; 4] = [
        SecretField::Username,
        SecretField::Password,
        SecretField::Cookie,
        SecretField::Token,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            SecretField::Username => "username",
            SecretField::Password => "password",
            SecretField::Cookie => "cookie",
            SecretField::Token => "token",
        }
    }

    /// Input is shown while typed (`username`) or hidden.
    pub fn hidden(&self) -> bool {
        true
    }
}

/// One `[[roles]]` entry of `.brokenapp/config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RoleConfig {
    /// Unique, lowercase: letters, digits, `-`, `_`.
    pub name: String,
    pub method: RoleMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Login page (form, manual), relative to the project URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    /// `env:NAME` (form: login name/email; supabase/firebase: email).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// `env:NAME`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// CSS selectors for the login form; auto-detected when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_selector: Option<String>,
    /// method = "session": saved session file, relative to `.brokenapp/`
    /// (default `session/<name>.json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// method = "cookie": `env:NAME` holding a `Cookie:` header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<String>,
    /// method = "bearer": `env:NAME` holding the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// method = "supabase": project URL (not a secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_url: Option<String>,
    /// method = "supabase": anon (public) key, literal or `env:NAME`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anon_key: Option<String>,
    /// method = "firebase": web API (public) key, literal or `env:NAME`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// A page or endpoint that answers 200/204 only when signed in (e.g.
    /// `/api/me`). Verified after login; in full mode it also detects an
    /// expired session mid-run and signs in again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// Extra routes to seed for this role only (e.g. `/admin`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_routes: Vec<String>,
    /// Route prefixes this role never visits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_routes: Vec<String>,
}

impl RoleConfig {
    /// The configured value of a secret field.
    pub fn secret(&self, field: SecretField) -> Option<&str> {
        match field {
            SecretField::Username => self.username.as_deref(),
            SecretField::Password => self.password.as_deref(),
            SecretField::Cookie => self.cookie.as_deref(),
            SecretField::Token => self.token.as_deref(),
        }
    }

    pub fn set_secret(&mut self, field: SecretField, value: Option<String>) {
        let slot = match field {
            SecretField::Username => &mut self.username,
            SecretField::Password => &mut self.password,
            SecretField::Cookie => &mut self.cookie,
            SecretField::Token => &mut self.token,
        };
        *slot = value;
    }

    /// Saved session file (method = "session"), relative to the state dir unless absolute.
    pub fn session_path(&self, state_dir: &Path) -> PathBuf {
        let rel = self
            .session
            .clone()
            .unwrap_or_else(|| format!("session/{}.json", self.name));
        let p = PathBuf::from(rel);
        if p.is_absolute() {
            p
        } else {
            state_dir.join(p)
        }
    }

    /// Login page path for form/manual roles (`/login` when unset).
    pub fn login_path(&self) -> String {
        self.login_url
            .clone()
            .filter(|u| !u.trim().is_empty())
            .unwrap_or_else(|| "/login".to_string())
    }
}

/// `env:NAME` -> `NAME` (a valid variable name), else `None`.
pub fn env_ref(raw: &str) -> Option<&str> {
    let name = raw.trim().strip_prefix("env:")?.trim();
    valid_env_name(name).then_some(name)
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Validate a role name (not checking duplicates).
pub fn validate_role_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("role names cannot be empty");
    }
    if name.len() > MAX_ROLE_NAME_LEN {
        bail!("role name '{name}' is longer than {MAX_ROLE_NAME_LEN} characters");
    }
    let ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !ok {
        bail!(
            "role name '{name}' is invalid: use lowercase letters, digits, '-' and '_' (it names map/roles/<role>/)"
        );
    }
    if RESERVED_ROLE_NAMES.contains(&name) {
        bail!(
            "'{name}' is reserved (reserved: {}); pick another role name",
            RESERVED_ROLE_NAMES.join(", ")
        );
    }
    Ok(())
}

fn is_path_or_url(raw: &str) -> bool {
    let t = raw.trim();
    t.starts_with('/') || t.starts_with("http://") || t.starts_with("https://")
}

/// Validate every `[[roles]]` entry: names, methods, and that secret fields
/// hold `env:NAME` references (a literal secret in the committed config is
/// refused; its value is never echoed).
pub fn validate_roles(cfg: &ProjectConfig, config_path: &Path) -> Result<()> {
    let mut seen = BTreeSet::new();
    let shown = config_path.display();
    for role in &cfg.roles {
        validate_role_name(&role.name).with_context(|| format!("[[roles]] in {shown}"))?;
        if !seen.insert(role.name.as_str()) {
            bail!("role '{}' is defined twice in {shown}", role.name);
        }
        let r = &role.name;
        for field in SecretField::ALL {
            let Some(value) = role.secret(field) else {
                continue;
            };
            if env_ref(value).is_none() {
                let f = field.as_str();
                let suggested = format!(
                    "{}_{}",
                    env_safe(r),
                    if field == SecretField::Username && role.method != RoleMethod::Form {
                        "EMAIL".to_string()
                    } else {
                        f.to_ascii_uppercase()
                    }
                );
                bail!(
                    "role '{r}': {f} in {shown} is a literal value. config.toml is committed, so secrets must be \
                     env: references: export {suggested}=... in your shell and set {f} = \"env:{suggested}\", \
                     or store the value in the gitignored credentials file with `brokenapp roles add {r} --force`"
                );
            }
            if !role.method.secret_fields().contains(&field) {
                bail!(
                    "role '{r}': {} is not used by method \"{}\" ({shown})",
                    field.as_str(),
                    role.method
                );
            }
        }
        let unused = |what: &str, set: bool| -> Result<()> {
            if set {
                bail!(
                    "role '{r}': {what} is not used by method \"{}\" ({shown})",
                    role.method
                );
            }
            Ok(())
        };
        let form_like = matches!(role.method, RoleMethod::Form);
        unused(
            "username_selector/password_selector/submit_selector",
            !form_like
                && (role.username_selector.is_some()
                    || role.password_selector.is_some()
                    || role.submit_selector.is_some()),
        )?;
        unused(
            "session",
            role.method != RoleMethod::Session && role.session.is_some(),
        )?;
        unused(
            "project_url/anon_key",
            role.method != RoleMethod::Supabase
                && (role.project_url.is_some() || role.anon_key.is_some()),
        )?;
        unused(
            "api_key",
            role.method != RoleMethod::Firebase && role.api_key.is_some(),
        )?;
        unused(
            "login_url",
            !matches!(
                role.method,
                RoleMethod::Form | RoleMethod::Manual | RoleMethod::Session
            ) && role.login_url.is_some(),
        )?;
        if let Some(url) = role.login_url.as_deref().filter(|u| !is_path_or_url(u)) {
            bail!("role '{r}': login_url {url:?} must be a path like \"/login\" ({shown})");
        }
        if let Some(check) = role.check.as_deref().filter(|c| !is_path_or_url(c)) {
            bail!("role '{r}': check {check:?} must be a path like \"/api/me\" ({shown})");
        }
        match role.method {
            RoleMethod::Supabase => {
                let url = role.project_url.as_deref().unwrap_or_default();
                if url::Url::parse(url).is_err() {
                    bail!(
                        "role '{r}': method \"supabase\" needs project_url = \"https://<ref>.supabase.co\" (or local dev URL like \"http://127.0.0.1:54321\") ({shown})"
                    );
                }
                if role.anon_key.as_deref().is_none_or(|k| k.trim().is_empty()) {
                    bail!("role '{r}': method \"supabase\" needs anon_key ({shown})");
                }
            }
            RoleMethod::Firebase => {
                if role.api_key.as_deref().is_none_or(|k| k.trim().is_empty()) {
                    bail!("role '{r}': method \"firebase\" needs api_key ({shown})");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// `coach-2` -> `COACH_2`.
pub fn env_safe(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Environment variable `map` sets for a credentials-file value that the
/// config does not name: `BROKENAPP_ROLE_<ROLE>_<FIELD>`.
pub fn injected_env_name(role: &str, field: SecretField) -> String {
    format!(
        "BROKENAPP_ROLE_{}_{}",
        env_safe(role),
        field.as_str().to_ascii_uppercase()
    )
}

// ---------------------------------------------------------------------------
// credentials.toml
// ---------------------------------------------------------------------------

/// Values for one role in `credentials.toml`. `Debug` never shows values.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RoleCredentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl fmt::Debug for RoleCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("RoleCredentials");
        for field in SecretField::ALL {
            if self.get(field).is_some() {
                d.field(field.as_str(), &"***");
            }
        }
        d.finish()
    }
}

impl RoleCredentials {
    pub fn get(&self, field: SecretField) -> Option<&str> {
        match field {
            SecretField::Username => self.username.as_deref(),
            SecretField::Password => self.password.as_deref(),
            SecretField::Cookie => self.cookie.as_deref(),
            SecretField::Token => self.token.as_deref(),
        }
        .filter(|v| !v.is_empty())
    }

    pub fn set(&mut self, field: SecretField, value: Option<String>) {
        let slot = match field {
            SecretField::Username => &mut self.username,
            SecretField::Password => &mut self.password,
            SecretField::Cookie => &mut self.cookie,
            SecretField::Token => &mut self.token,
        };
        *slot = value;
    }

    pub fn is_empty(&self) -> bool {
        SecretField::ALL.iter().all(|f| self.get(*f).is_none())
    }

    /// Field names stored (never values).
    pub fn stored_fields(&self) -> Vec<&'static str> {
        SecretField::ALL
            .iter()
            .filter(|f| self.get(**f).is_some())
            .map(|f| f.as_str())
            .collect()
    }
}

/// `.brokenapp/credentials.toml`: `[roles.<name>]` tables.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CredentialsFile {
    #[serde(default)]
    pub roles: BTreeMap<String, RoleCredentials>,
}

const CREDENTIALS_HEADER: &str = "\
# BrokenApp role credentials (written by `brokenapp roles add`).
# Never commit this file: it is gitignored and readable only by you (chmod 600).
# `brokenapp map` passes these values to the scan through its environment only.
";

/// Load `credentials.toml` (missing file = empty). Refuses a file other
/// users can read, and never echoes its content in errors.
pub fn load_credentials(path: &Path) -> Result<CredentialsFile> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CredentialsFile::default());
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    check_private_mode(path)?;
    toml::from_str(&raw).map_err(|err| {
        // toml errors quote the offending line, which may hold a secret.
        let line = err
            .span()
            .map(|s| raw[..s.start.min(raw.len())].lines().count().max(1))
            .unwrap_or(0);
        anyhow::anyhow!(
            "{} is not valid TOML (near line {line}); fix it or re-run `brokenapp roles add <role> --force`",
            path.display()
        )
    })
}

#[cfg(unix)]
fn check_private_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is readable by other users (mode {:o}); run `chmod 600 {}`",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_mode(_path: &Path) -> Result<()> {
    Ok(())
}

/// Write `credentials.toml` atomically with mode 0600.
pub fn save_credentials(path: &Path, creds: &CredentialsFile) -> Result<()> {
    use std::io::Write as _;
    let body = toml::to_string_pretty(creds).context("serialize credentials")?;
    let parent = path.parent().context("credentials path has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let tmp = path.with_extension("toml.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 600 {}", tmp.display()))?;
        }
        file.write_all(CREDENTIALS_HEADER.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.write_all(body.as_bytes()))
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all().ok();
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}

/// Lines `.brokenapp/.gitignore` must carry so credentials and sessions are
/// never committed (the generated file also ignores everything by default).
pub const PRIVATE_IGNORES: &[&str] = &["/credentials.toml", "/session/"];

/// Make sure `.brokenapp/.gitignore` lists [`PRIVATE_IGNORES`] (projects
/// set up before roles existed, or a hand-edited file). Returns the lines added.
pub fn ensure_private_ignored(state_dir: &Path) -> Result<Vec<String>> {
    let path = state_dir.join(".gitignore");
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    let present: BTreeSet<&str> = raw.lines().map(str::trim).collect();
    let missing: Vec<String> = PRIVATE_IGNORES
        .iter()
        .filter(|l| !present.contains(**l))
        .map(|l| l.to_string())
        .collect();
    if missing.is_empty() {
        return Ok(missing);
    }
    let mut out = raw.clone();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("# Never commit role credentials or saved sessions.\n");
    for line in &missing {
        out.push_str(line);
        out.push('\n');
    }
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("create {}", state_dir.display()))?;
    std::fs::write(&path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(missing)
}

/// Whether git ignores `rel` (relative to `state_dir`); `None` when git
/// cannot tell (not installed, not a repository).
pub fn git_ignores(state_dir: &Path, rel: &str) -> Option<bool> {
    let out = std::process::Command::new("git")
        .args(["check-ignore", "-q", "--no-index", rel])
        .current_dir(state_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    match out.code() {
        Some(0) => Some(true),
        Some(1) => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Roles one `map` run covers, anonymous first, then config order.
/// `--role` (repeatable) names roles; `--roles all|none` selects every role
/// (default) or only the anonymous app.
pub fn select_roles(ctx: &ProjectCtx, only: &[String], roles: Option<&str>) -> Result<Vec<String>> {
    let cfg = &ctx.config;
    let configured: Vec<&str> = cfg.roles.iter().map(|r| r.name.as_str()).collect();
    if !only.is_empty() {
        let mut wanted = BTreeSet::new();
        for raw in only {
            for name in raw.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                if name != ANONYMOUS_ROLE && !configured.contains(&name) {
                    bail!(
                        "unknown role '{name}' (configured: {}; add it with `brokenapp roles add {name}`)",
                        role_list(&configured)
                    );
                }
                wanted.insert(name.to_string());
            }
        }
        let mut out = Vec::new();
        if wanted.contains(ANONYMOUS_ROLE) {
            out.push(ANONYMOUS_ROLE.to_string());
        }
        out.extend(
            configured
                .iter()
                .filter(|n| wanted.contains(**n))
                .map(|n| n.to_string()),
        );
        return Ok(out);
    }
    match roles.map(|r| r.trim().to_ascii_lowercase()).as_deref() {
        None | Some("all") => {
            let mut out = Vec::new();
            if cfg.auth.include_anonymous() {
                out.push(ANONYMOUS_ROLE.to_string());
            }
            out.extend(configured.iter().map(|n| n.to_string()));
            if out.is_empty() {
                bail!(
                    "nothing to map: [auth] include_anonymous = false and no [[roles]] in {}",
                    ctx.config_path.display()
                );
            }
            Ok(out)
        }
        Some("none") => Ok(vec![ANONYMOUS_ROLE.to_string()]),
        Some(other) => {
            bail!("--roles {other:?}: expected all or none (use --role <name> for one role)")
        }
    }
}

fn role_list(names: &[&str]) -> String {
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

/// The configured role named `name`.
pub fn find_role<'a>(cfg: &'a ProjectConfig, name: &str) -> Option<&'a RoleConfig> {
    cfg.roles.iter().find(|r| r.name == name)
}

// ---------------------------------------------------------------------------
// Resolution: config + environment + credentials file -> scan auth
// ---------------------------------------------------------------------------

/// Login form selectors used when a form role does not set them. Each is a
/// CSS selector list scoped to the form that has a password field (a
/// header search box or newsletter form is never picked).
pub const DEFAULT_USERNAME_SELECTOR: &str = "form:has(input[type=password]) input:is([type=email],[type=text],[type=tel],:not([type])), \
input[type=email]:not(form:not(:has(input[type=password])) *), \
input[autocomplete=username]:not(form:not(:has(input[type=password])) *)";
pub const DEFAULT_PASSWORD_SELECTOR: &str = "input[type=password]";
pub const DEFAULT_SUBMIT_SELECTOR: &str = "form:has(input[type=password]) :is(button[type=submit],input[type=submit],button:not([type])), \
button[type=submit]:not(form:not(:has(input[type=password])) *)";

/// Resolved form login for the explicit login command. `Debug` hides the values.
#[derive(Clone)]
pub struct FormLogin {
    pub login_url: String,
    pub username_selector: String,
    pub password_selector: String,
    pub submit_selector: String,
    pub username: String,
    pub password: String,
}

impl fmt::Debug for FormLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormLogin")
            .field("login_url", &self.login_url)
            .field("username_selector", &self.username_selector)
            .field("password_selector", &self.password_selector)
            .field("submit_selector", &self.submit_selector)
            .field("username", &"***")
            .field("password", &"***")
            .finish()
    }
}

/// Where a secret value came from (never the value).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecretSource {
    pub field: String,
    /// `env` (the shell environment) or `credentials` (credentials.toml).
    pub from: String,
    /// The environment variable the scan reads it from.
    pub env: String,
}

/// A role ready to scan (or the reasons it is not). `Debug` hides values.
#[derive(Clone, Default)]
pub struct ResolvedRole {
    pub name: String,
    pub method: RoleMethod,
    /// `[auth]` table for the generated scan TOML (`env:` references only).
    pub auth: Option<toml::Table>,
    /// `[auth_contract]` table (from `check`).
    pub contract: Option<toml::Table>,
    /// Variables set on the scan subprocess: credentials-file values (and
    /// nothing from the shell, which the subprocess inherits anyway).
    pub env: Vec<(String, String)>,
    /// Every secret value (shell or file), for redaction.
    pub secret_values: Vec<String>,
    pub sources: Vec<SecretSource>,
    /// What is missing before this role can be mapped.
    pub missing: Vec<String>,
    /// Form roles: fields the explicit login command fills in.
    pub form: Option<FormLogin>,
    /// Session roles: the saved session file.
    pub session_file: Option<PathBuf>,
    /// The role has a `check` probe (re-auth canary in full mode).
    pub has_check: bool,
}

impl fmt::Debug for ResolvedRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedRole")
            .field("name", &self.name)
            .field("method", &self.method)
            .field("auth", &self.auth)
            .field("env", &self.env.iter().map(|(k, _)| k).collect::<Vec<_>>())
            .field("sources", &self.sources)
            .field("missing", &self.missing)
            .field("session_file", &self.session_file)
            .finish()
    }
}

impl ResolvedRole {
    pub fn ready(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Resolve one role: which environment variable each secret is read from
/// (the shell's, or one `map` sets from `credentials.toml`), the scan's
/// `[auth]` table, and what is missing. `env` looks up the shell environment.
pub fn resolve_role(
    role: &RoleConfig,
    state_dir: &Path,
    creds: &CredentialsFile,
    env: &dyn Fn(&str) -> Option<String>,
) -> ResolvedRole {
    let stored = creds.roles.get(&role.name).cloned().unwrap_or_default();
    let mut out = ResolvedRole {
        name: role.name.clone(),
        method: role.method,
        ..Default::default()
    };
    let button_only_form = role.method == RoleMethod::Form
        && role
            .submit_selector
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
        && role.username.is_none()
        && role.password.is_none()
        && role.username_selector.is_none()
        && role.password_selector.is_none()
        && stored.get(SecretField::Username).is_none()
        && stored.get(SecretField::Password).is_none();
    let mut refs: BTreeMap<SecretField, (String, Option<String>)> = BTreeMap::new();
    if !button_only_form {
        for field in role.method.secret_fields() {
            let configured = role.secret(*field).and_then(env_ref);
            let from_shell = configured
                .and_then(|name| env(name))
                .filter(|v| !v.trim().is_empty());
            let from_file = stored.get(*field).map(str::to_string);
            let (var, value, source) = match (configured, from_shell, from_file) {
                (Some(name), Some(v), _) => (name.to_string(), v, "env"),
                (Some(name), None, Some(v)) => {
                    out.env.push((name.to_string(), v.clone()));
                    (name.to_string(), v, "credentials")
                }
                (None, _, Some(v)) => {
                    let name = injected_env_name(&role.name, *field);
                    out.env.push((name.clone(), v.clone()));
                    (name, v, "credentials")
                }
                (Some(name), None, None) => {
                    out.missing.push(format!(
                        "{}: {name} is not set (export it, or store the value with `brokenapp roles add {} --force`)",
                        field.as_str(),
                        role.name
                    ));
                    continue;
                }
                (None, _, None) => {
                    out.missing.push(format!(
                        "{}: not configured (set {} = \"env:NAME\" in config.toml, or run `brokenapp roles add {} --force`)",
                        field.as_str(),
                        field.as_str(),
                        role.name
                    ));
                    continue;
                }
            };
            out.sources.push(SecretSource {
                field: field.as_str().to_string(),
                from: source.to_string(),
                env: var.clone(),
            });
            out.secret_values.push(value.clone());
            refs.insert(*field, (format!("env:{var}"), Some(value)));
        }
    }
    let r = |f: SecretField| refs.get(&f).map(|(r, _)| r.clone()).unwrap_or_default();
    let v = |f: SecretField| {
        refs.get(&f)
            .and_then(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let public_key = |raw: Option<&str>, what: &str, out: &mut ResolvedRole| -> String {
        let raw = raw.unwrap_or_default().trim().to_string();
        if let Some(name) = env_ref(&raw) {
            match env(name).filter(|v| !v.trim().is_empty()) {
                Some(value) => out.secret_values.push(value),
                None => out
                    .missing
                    .push(format!("{what}: {name} is not set (export it)")),
            }
        }
        raw
    };

    let s = |v: &str| toml::Value::String(v.to_string());
    let mut auth = toml::Table::new();
    match role.method {
        RoleMethod::Form => {
            let login_url = role.login_path();
            let user_sel = if button_only_form {
                String::new()
            } else {
                role.username_selector
                    .clone()
                    .unwrap_or_else(|| DEFAULT_USERNAME_SELECTOR.to_string())
            };
            let pass_sel = if button_only_form {
                String::new()
            } else {
                role.password_selector
                    .clone()
                    .unwrap_or_else(|| DEFAULT_PASSWORD_SELECTOR.to_string())
            };
            let submit_sel = role
                .submit_selector
                .clone()
                .unwrap_or_else(|| DEFAULT_SUBMIT_SELECTOR.to_string());
            auth.insert("type".into(), s("form"));
            auth.insert("login_url".into(), s(&login_url));
            auth.insert("username_selector".into(), s(&user_sel));
            auth.insert("password_selector".into(), s(&pass_sel));
            auth.insert("submit_selector".into(), s(&submit_sel));
            auth.insert("username".into(), s(&r(SecretField::Username)));
            auth.insert("password".into(), s(&r(SecretField::Password)));
            if out.missing.is_empty() {
                out.form = Some(FormLogin {
                    login_url,
                    username_selector: user_sel,
                    password_selector: pass_sel,
                    submit_selector: submit_sel,
                    username: v(SecretField::Username),
                    password: v(SecretField::Password),
                });
            }
        }
        RoleMethod::Session => {
            let path = role.session_path(state_dir);
            if !path.is_file() {
                out.missing.push(format!(
                    "session: no saved session at {} (run `brokenapp login --role {}`)",
                    path.display(),
                    role.name
                ));
            }
            auth.insert("type".into(), s("storage_state"));
            auth.insert("path".into(), s(&path.display().to_string()));
            out.session_file = Some(path);
        }
        RoleMethod::Cookie => {
            auth.insert("type".into(), s("cookie"));
            auth.insert("cookie".into(), s(&r(SecretField::Cookie)));
        }
        RoleMethod::Bearer => {
            auth.insert("type".into(), s("bearer"));
            auth.insert("token".into(), s(&r(SecretField::Token)));
        }
        RoleMethod::Supabase => {
            let anon = public_key(role.anon_key.as_deref(), "anon_key", &mut out);
            auth.insert("type".into(), s("supabase"));
            auth.insert(
                "project_url".into(),
                s(role.project_url.as_deref().unwrap_or_default()),
            );
            auth.insert("anon_key".into(), s(&anon));
            auth.insert("email".into(), s(&r(SecretField::Username)));
            auth.insert("password".into(), s(&r(SecretField::Password)));
        }
        RoleMethod::Firebase => {
            let key = public_key(role.api_key.as_deref(), "api_key", &mut out);
            auth.insert("type".into(), s("firebase"));
            auth.insert("api_key".into(), s(&key));
            auth.insert("email".into(), s(&r(SecretField::Username)));
            auth.insert("password".into(), s(&r(SecretField::Password)));
        }
        RoleMethod::Manual => {
            auth.insert("type".into(), s("manual"));
            if let Some(url) = role.login_url.as_deref() {
                auth.insert("login_url".into(), s(url));
            }
        }
    }
    out.auth = Some(auth);
    if let Some(check) = role.check.as_deref().filter(|c| !c.trim().is_empty()) {
        let mut probe = toml::Table::new();
        probe.insert("path".into(), s(check.trim()));
        probe.insert("method".into(), s("get"));
        probe.insert(
            "expected_statuses".into(),
            toml::Value::Array(vec![toml::Value::Integer(200), toml::Value::Integer(204)]),
        );
        let mut contract = toml::Table::new();
        contract.insert("protected_probe".into(), toml::Value::Table(probe));
        out.contract = Some(contract);
        out.has_check = true;
    }
    out
}

/// Resolve every role in `names` (the anonymous role resolves to no auth).
pub fn resolve_roles(ctx: &ProjectCtx, names: &[String]) -> Result<BTreeMap<String, ResolvedRole>> {
    let needs_creds = names.iter().any(|n| n != ANONYMOUS_ROLE);
    let creds = if needs_creds {
        load_credentials(&ctx.credentials_path())?
    } else {
        CredentialsFile::default()
    };
    let lookup = |name: &str| std::env::var(name).ok();
    let mut out = BTreeMap::new();
    for name in names {
        if name == ANONYMOUS_ROLE {
            out.insert(
                name.clone(),
                ResolvedRole {
                    name: name.clone(),
                    ..Default::default()
                },
            );
            continue;
        }
        let role = find_role(&ctx.config, name)
            .with_context(|| format!("role '{name}' is not configured"))?;
        out.insert(
            name.clone(),
            resolve_role(role, &ctx.state_dir, &creds, &lookup),
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Replaces secret values in anything `map` prints or writes.
#[derive(Clone, Default)]
pub struct Redactor {
    values: Vec<String>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redactor({} values)", self.values.len())
    }
}

impl Redactor {
    /// Every nonempty value is private, including short values and values
    /// that happen to equal a role or project name.
    pub fn new<I, S>(values: I, _keep: &[&str]) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut values: Vec<String> = values
            .into_iter()
            .map(Into::into)
            .filter(|v| !v.is_empty())
            .collect();
        // Longest first, so a secret containing another is replaced whole.
        values.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        values.dedup();
        Self { values }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for v in &self.values {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), "***");
            }
        }
        out
    }

    /// Redact every string inside a JSON value.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        if self.values.is_empty() {
            return;
        }
        match value {
            serde_json::Value::String(s) => {
                let r = self.redact(s);
                if r != *s {
                    *s = r;
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(|v| self.redact_json(v)),
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    // These fields are machine identifiers/paths emitted by us,
                    // never credential-derived page text. A password such as
                    // "admin", "ok", or "1" must not corrupt the JSON contract.
                    if matches!(
                        key.as_str(),
                        "role"
                            | "project"
                            | "status"
                            | "method"
                            | "scan_mode"
                            | "write_guard"
                            | "mode"
                            | "schema"
                            | "field"
                            | "env"
                            | "from"
                            | "output_dir"
                            | "scan_dir"
                            | "run_dir"
                            | "inventory"
                            | "map_dir"
                            | "role_access"
                            | "changelog"
                            | "dead_ui"
                    ) {
                        continue;
                    }
                    self.redact_json(value);
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// config.toml editing (keeps comments and the rest of the file as written)
// ---------------------------------------------------------------------------

/// `[[roles]]` block for `role`, as TOML text.
pub fn role_block(role: &RoleConfig) -> Result<String> {
    #[derive(Serialize)]
    struct One<'a> {
        roles: [&'a RoleConfig; 1],
    }
    toml::to_string_pretty(&One { roles: [role] }).context("serialize role")
}

/// Append a `[[roles]]` block to the config text. Fails when the result does
/// not parse as a project config.
pub fn append_role(raw: &str, role: &RoleConfig) -> Result<String> {
    let mut out = raw.trim_end().to_string();
    out.push_str("\n\n");
    out.push_str(role_block(role)?.trim_end());
    out.push('\n');
    toml::from_str::<ProjectConfig>(&out).context("the updated config does not parse")?;
    Ok(out)
}

/// Whether a line is a table header (`[x]` / `[[x]]`), ignoring comments.
fn is_table_header(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('[') && !t.starts_with("[]")
}

fn is_roles_header(line: &str) -> bool {
    let t = line.split('#').next().unwrap_or_default().trim();
    t.strip_prefix("[[")
        .and_then(|r| r.strip_suffix("]]"))
        .is_some_and(|n| n.trim() == "roles")
}

/// Remove the `[[roles]]` block whose name is `name`. Returns the new text
/// and whether a block was removed.
pub fn remove_role(raw: &str, name: &str) -> Result<(String, bool)> {
    let lines: Vec<&str> = raw.split_inclusive('\n').collect();
    let mut i = 0;
    let mut out = String::with_capacity(raw.len());
    let mut removed = false;
    while i < lines.len() {
        if !is_roles_header(lines[i]) {
            out.push_str(lines[i]);
            i += 1;
            continue;
        }
        let mut end = i + 1;
        while end < lines.len() && !is_table_header(lines[end]) {
            end += 1;
        }
        let body: String = lines[i + 1..end].concat();
        let block_name = toml::from_str::<toml::Table>(&body)
            .ok()
            .and_then(|t| t.get("name").and_then(|v| v.as_str()).map(str::to_string));
        if !removed && block_name.as_deref() == Some(name) {
            removed = true;
            // Drop the blank lines the block leaves behind.
            while out.ends_with("\n\n") {
                out.pop();
            }
        } else {
            for l in &lines[i..end] {
                out.push_str(l);
            }
        }
        i = end;
    }
    if removed {
        let parsed: ProjectConfig =
            toml::from_str(&out).context("the updated config does not parse")?;
        if parsed.roles.iter().any(|r| r.name == name) {
            bail!("role '{name}' is still present after removing its [[roles]] block");
        }
    }
    Ok((out, removed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::front::project::{CREDENTIALS_FILE, ProjectSection};

    fn project(roles: Vec<RoleConfig>) -> ProjectConfig {
        ProjectConfig {
            project: ProjectSection {
                name: "demo".into(),
                url: "http://127.0.0.1:3000".into(),
                codebase: ".".into(),
                ready_timeout_secs: 120,
                ..Default::default()
            },
            roles,
            ..Default::default()
        }
    }

    fn form(name: &str) -> RoleConfig {
        RoleConfig {
            name: name.into(),
            method: RoleMethod::Form,
            login_url: Some("/sign-in".into()),
            username: Some(format!("env:{}_EMAIL", env_safe(name))),
            password: Some(format!("env:{}_PASSWORD", env_safe(name))),
            ..Default::default()
        }
    }

    #[test]
    fn roles_parse_from_config_toml() {
        let raw = r#"
[project]
name = "demo"
url = "http://127.0.0.1:3000"

[auth]
include_anonymous = false

[[roles]]
name = "admin"
method = "form"
login_url = "/sign-in"
username = "env:ADMIN_EMAIL"
password = "env:ADMIN_PASSWORD"

[[roles]]
name = "coach"
method = "session"

[[roles]]
name = "api"
method = "bearer"
token = "env:API_TOKEN"
check = "/api/me"
"#;
        let cfg: ProjectConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.roles.len(), 3);
        assert_eq!(cfg.roles[1].method, RoleMethod::Session);
        assert!(!cfg.auth.include_anonymous());
        validate_roles(&cfg, Path::new("config.toml")).unwrap();
        // Round trip.
        let back: ProjectConfig = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn literal_secrets_are_refused_without_echoing_them() {
        let mut admin = form("admin");
        admin.password = Some("hunter2-literal".into());
        let err = validate_roles(
            &project(vec![admin]),
            Path::new("/r/.brokenapp/config.toml"),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("literal value"), "{msg}");
        assert!(msg.contains("env:ADMIN_PASSWORD"), "{msg}");
        assert!(!msg.contains("hunter2"), "{msg}");

        let mut bad_name = form("admin");
        bad_name.username = Some("env:".into());
        assert!(validate_roles(&project(vec![bad_name]), Path::new("c")).is_err());
    }

    #[test]
    fn names_are_unique_lowercase_and_not_reserved() {
        assert!(validate_role_name("coach-2").is_ok());
        assert!(validate_role_name("org_admin").is_ok());
        for bad in [
            "",
            "Admin",
            "a b",
            "../x",
            "anonymous",
            "all",
            "button",
            "-x",
        ] {
            assert!(validate_role_name(bad).is_err(), "{bad}");
        }
        let err = validate_roles(&project(vec![form("admin"), form("admin")]), Path::new("c"))
            .unwrap_err();
        assert!(format!("{err:#}").contains("defined twice"));
    }

    #[test]
    fn method_specific_fields_are_checked() {
        let mut r = form("admin");
        r.token = Some("env:T".into());
        assert!(
            format!(
                "{:#}",
                validate_roles(&project(vec![r]), Path::new("c")).unwrap_err()
            )
            .contains("not used by method")
        );
        let r = RoleConfig {
            name: "sb".into(),
            method: RoleMethod::Supabase,
            username: Some("env:SB_EMAIL".into()),
            password: Some("env:SB_PASSWORD".into()),
            ..Default::default()
        };
        assert!(
            format!(
                "{:#}",
                validate_roles(&project(vec![r]), Path::new("c")).unwrap_err()
            )
            .contains("project_url")
        );
        let mut r = form("admin");
        r.check = Some("api/me".into());
        assert!(validate_roles(&project(vec![r]), Path::new("c")).is_err());
    }

    fn lookup(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn env_and_credentials_file_are_injected_only_as_environment() {
        let dir = tempfile::tempdir().unwrap();
        let mut creds = CredentialsFile::default();
        creds.roles.insert(
            "admin".into(),
            RoleCredentials {
                password: Some("file-secret-pw".into()),
                ..Default::default()
            },
        );
        creds.roles.insert(
            "user".into(),
            RoleCredentials {
                username: Some("user@example.test".into()),
                password: Some("user-secret-pw".into()),
                ..Default::default()
            },
        );
        // admin: username from the shell, password (env var unset) from the file.
        let env = lookup(&[("ADMIN_EMAIL", "admin@example.test")]);
        let admin = resolve_role(&form("admin"), dir.path(), &creds, &env);
        assert!(admin.ready(), "{:?}", admin.missing);
        assert_eq!(
            admin.env,
            vec![("ADMIN_PASSWORD".to_string(), "file-secret-pw".to_string())]
        );
        let auth = admin.auth.clone().unwrap();
        assert_eq!(auth["type"].as_str(), Some("form"));
        assert_eq!(auth["username"].as_str(), Some("env:ADMIN_EMAIL"));
        assert_eq!(auth["password"].as_str(), Some("env:ADMIN_PASSWORD"));
        assert_eq!(auth["login_url"].as_str(), Some("/sign-in"));
        assert!(
            auth["username_selector"]
                .as_str()
                .unwrap()
                .contains("type=email")
        );
        let form_login = admin.form.clone().unwrap();
        assert_eq!(form_login.username, "admin@example.test");
        assert_eq!(form_login.password, "file-secret-pw");
        assert!(!format!("{admin:?}").contains("file-secret-pw"));
        assert!(!format!("{form_login:?}").contains("admin@example.test"));
        let froms: Vec<(&str, &str)> = admin
            .sources
            .iter()
            .map(|s| (s.field.as_str(), s.from.as_str()))
            .collect();
        assert_eq!(
            froms,
            vec![("username", "env"), ("password", "credentials")]
        );

        // user: nothing in config.toml, everything from the file under generated names.
        let user = RoleConfig {
            name: "user".into(),
            method: RoleMethod::Form,
            login_url: Some("/login".into()),
            ..Default::default()
        };
        let user = resolve_role(&user, dir.path(), &creds, &lookup(&[]));
        assert!(user.ready());
        let names: Vec<&str> = user.env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "BROKENAPP_ROLE_USER_USERNAME",
                "BROKENAPP_ROLE_USER_PASSWORD"
            ]
        );
        assert_eq!(
            user.auth.as_ref().unwrap()["password"].as_str(),
            Some("env:BROKENAPP_ROLE_USER_PASSWORD")
        );

        // Nothing anywhere: reported missing, never scanned.
        let missing = resolve_role(&form("coach"), dir.path(), &creds, &lookup(&[]));
        assert!(!missing.ready());
        assert_eq!(missing.missing.len(), 2);
        assert!(missing.missing[0].contains("COACH_EMAIL is not set"));
        assert!(missing.form.is_none());
    }

    #[test]
    fn saved_session_roles_can_name_the_login_page() {
        let cfg = project(vec![RoleConfig {
            name: "coach".into(),
            method: RoleMethod::Session,
            login_url: Some("/sign-in".into()),
            ..Default::default()
        }]);
        assert!(validate_roles(&cfg, Path::new("config.toml")).is_ok());
    }

    #[test]
    fn session_cookie_bearer_and_check_tables() {
        let dir = tempfile::tempdir().unwrap();
        let creds = CredentialsFile::default();
        let session = RoleConfig {
            name: "coach".into(),
            method: RoleMethod::Session,
            ..Default::default()
        };
        let r = resolve_role(&session, dir.path(), &creds, &lookup(&[]));
        assert!(!r.ready() && r.missing[0].contains("brokenapp login --role coach"));
        let path = dir.path().join("session/coach.json");
        assert_eq!(
            r.auth.as_ref().unwrap()["type"].as_str(),
            Some("storage_state")
        );
        assert_eq!(
            r.auth.as_ref().unwrap()["path"].as_str(),
            Some(path.display().to_string().as_str())
        );
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{}").unwrap();
        assert!(resolve_role(&session, dir.path(), &creds, &lookup(&[])).ready());

        let bearer = RoleConfig {
            name: "api".into(),
            method: RoleMethod::Bearer,
            token: Some("env:API_TOKEN".into()),
            check: Some("/api/me".into()),
            ..Default::default()
        };
        let r = resolve_role(
            &bearer,
            dir.path(),
            &creds,
            &lookup(&[("API_TOKEN", "tok-123456")]),
        );
        assert!(
            r.ready() && r.env.is_empty(),
            "shell values are inherited, not re-set"
        );
        assert_eq!(
            r.auth.as_ref().unwrap()["token"].as_str(),
            Some("env:API_TOKEN")
        );
        let contract = r.contract.as_ref().unwrap();
        assert_eq!(
            contract["protected_probe"]["path"].as_str(),
            Some("/api/me")
        );
        assert_eq!(r.secret_values, vec!["tok-123456".to_string()]);
    }

    #[test]
    fn credentials_file_is_private_and_errors_do_not_quote_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILE);
        assert!(load_credentials(&path).unwrap().roles.is_empty());
        let mut creds = CredentialsFile::default();
        creds.roles.insert(
            "admin".into(),
            RoleCredentials {
                username: Some("a@example.test".into()),
                password: Some("pw-on-disk".into()),
                ..Default::default()
            },
        );
        save_credentials(&path, &creds).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(load_credentials(&path).unwrap(), creds);
        assert!(!format!("{creds:?}").contains("pw-on-disk"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = load_credentials(&path).unwrap_err();
            assert!(format!("{err:#}").contains("chmod 600"));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&path, "[roles.admin]\npassword = \"broken-secret\n").unwrap();
        let msg = format!("{:#}", load_credentials(&path).unwrap_err());
        assert!(msg.contains("not valid TOML"), "{msg}");
        assert!(!msg.contains("broken-secret"), "{msg}");
    }

    #[test]
    fn redactor_replaces_short_and_name_equal_values() {
        let r = Redactor::new(["hunter2-pass", "admin", "abc"], &["admin", "demo"]);
        assert_eq!(
            r.redact("login for admin failed: bad password hunter2-pass (abc)"),
            "login for *** failed: bad password *** (***)"
        );
        let mut v = serde_json::json!({"a": ["x hunter2-pass"], "b": {"c": "hunter2-pass"}});
        r.redact_json(&mut v);
        assert_eq!(v, serde_json::json!({"a": ["x ***"], "b": {"c": "***"}}));
    }

    #[test]
    fn structured_redaction_keeps_types_and_machine_identifiers() {
        let r = Redactor::new(["1", "admin", "ok", "a\"b\\c"], &[]);
        let mut v = serde_json::json!({
            "exit_code": 1, "ready": true, "status": "ok", "role": "admin",
            "scan_dir": "/tmp/run1", "error": "password admin 1 a\"b\\c"
        });
        r.redact_json(&mut v);
        let serialized = serde_json::to_string(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed["exit_code"], 1);
        assert_eq!(parsed["ready"], true);
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["role"], "admin");
        assert_eq!(parsed["scan_dir"], "/tmp/run1");
        assert_eq!(parsed["error"], "password *** *** ***");
    }

    #[test]
    fn config_text_editing_keeps_the_rest_of_the_file() {
        let raw = "# my comment\n[project]\nname = \"demo\"\nurl = \"http://127.0.0.1:3000\"\n\n[scan]\nmax_minutes = 5 # keep\n";
        let with_admin = append_role(raw, &form("admin")).unwrap();
        let with_both = append_role(&with_admin, &form("user")).unwrap();
        assert!(with_both.starts_with(raw.trim_end()));
        let cfg: ProjectConfig = toml::from_str(&with_both).unwrap();
        assert_eq!(cfg.roles.len(), 2);
        let (without, removed) = remove_role(&with_both, "admin").unwrap();
        assert!(removed);
        assert!(without.contains("# my comment") && without.contains("max_minutes = 5 # keep"));
        let cfg: ProjectConfig = toml::from_str(&without).unwrap();
        assert_eq!(
            cfg.roles
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["user"]
        );
        let (same, removed) = remove_role(&without, "nobody").unwrap();
        assert!(!removed);
        assert_eq!(same, without);
        let (none_left, _) = remove_role(&without, "user").unwrap();
        assert!(
            toml::from_str::<ProjectConfig>(&none_left)
                .unwrap()
                .roles
                .is_empty()
        );
        assert!(none_left.contains("max_minutes = 5 # keep"));
    }

    #[test]
    fn gitignore_gets_private_lines_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "scans/\nhistory/\n").unwrap();
        let added = ensure_private_ignored(dir.path()).unwrap();
        assert_eq!(added, vec!["/credentials.toml", "/session/"]);
        assert!(ensure_private_ignored(dir.path()).unwrap().is_empty());
        let raw = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(raw.starts_with("scans/\nhistory/\n"));
        assert_eq!(raw.matches("/credentials.toml").count(), 1);
    }
}
