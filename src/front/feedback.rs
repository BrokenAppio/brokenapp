//! `brokenapp feedback`: strictly opt-in feedback submission for humans and
//! AI coding agents.
//!
//! BrokenApp never collects silent background telemetry. Feedback is only sent
//! when explicitly requested (`--send`), and agent-initiated reports
//! (`--agent <name>`) require the user to opt in first via
//! `brokenapp feedback --opt-in` or `BROKENAPP_FEEDBACK_OPT_IN=1`.
//!
//! Every message is scrubbed locally for tokens, JWTs, cookies, URL
//! credentials, and local home paths before leaving the machine. Optional
//! `--include-stats` attaches aggregate numeric counts and framework name only
//! — never URLs, routes, control labels, project names, or source code.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::project::{self, ProjectTarget};
use crate::inventory;

pub const DEFAULT_FEEDBACK_ENDPOINT: &str = "https://brokenapp.io/api/feedback";
const SETTINGS_FILE: &str = "settings.json";
const VALID_CATEGORIES: &[&str] = &["bug", "ux", "auth", "crawler", "rbac", "journey", "other"];

#[derive(Debug, Args)]
pub struct FeedbackArgs {
    /// Feedback summary or friction report (or pass `--stdin`).
    pub message: Option<String>,
    /// Read the feedback message from standard input.
    #[arg(long)]
    pub stdin: bool,
    /// Category (`bug`, `ux`, `auth`, `crawler`, `rbac`, `journey`, `other`).
    #[arg(long, default_value = "other")]
    pub category: String,
    /// Who is submitting (`claude-code`, `codex`, `antigravity`, `cursor`, `human`, ...).
    #[arg(long)]
    pub agent: Option<String>,
    /// Attach anonymized aggregate stats from the current project (counts + framework only; never URLs, routes, or labels).
    #[arg(long)]
    pub include_stats: bool,
    /// Print the exact redacted payload without sending anything over the network.
    #[arg(long)]
    pub dry_run: bool,
    /// Actually transmit the redacted payload to the feedback queue.
    #[arg(long)]
    pub send: bool,
    /// Opt in to allow AI coding agents to submit feedback (`$BROKENAPP_HOME/settings.json`).
    #[arg(long, conflicts_with_all = ["opt_out", "status"])]
    pub opt_in: bool,
    /// Opt out of agent feedback submissions.
    #[arg(long, conflicts_with_all = ["opt_in", "status"])]
    pub opt_out: bool,
    /// Show current feedback opt-in status and exit.
    #[arg(long, conflicts_with_all = ["opt_in", "opt_out"])]
    pub status: bool,
    /// Override the feedback endpoint URL (also `BROKENAPP_FEEDBACK_URL`).
    #[arg(long, env = "BROKENAPP_FEEDBACK_URL")]
    pub endpoint: Option<String>,
    /// Machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSettings {
    #[serde(default)]
    pub feedback_opt_in: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizedStats {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_visited: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_known: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls_exercised: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls_exercisable: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broken: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_effect: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles_mapped: Option<usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gap_reasons: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedbackPayload {
    pub message: String,
    pub category: String,
    pub agent: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<SanitizedStats>,
}

#[derive(Debug, Serialize)]
struct SettingsReport {
    status: &'static str,
    feedback_opt_in: bool,
    env_override: bool,
    effective_opt_in: bool,
    settings_path: String,
    endpoint: String,
}

#[derive(Debug, Serialize)]
struct FeedbackResult {
    status: &'static str,
    sent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    queued_at: Option<String>,
    endpoint: String,
    payload: FeedbackPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

pub fn settings_path() -> PathBuf {
    project::brokenapp_home().join(SETTINGS_FILE)
}

pub fn load_settings(path: &Path) -> UserSettings {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save_settings(path: &Path, settings: &UserSettings) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(settings).context("serialize settings")?;
    std::fs::write(path, raw).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn env_feedback_opt_in() -> bool {
    std::env::var("BROKENAPP_FEEDBACK_OPT_IN")
        .ok()
        .is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

fn effective_opt_in(path: &Path) -> (bool, bool, bool) {
    let saved = load_settings(path).feedback_opt_in;
    let env_on = env_feedback_opt_in();
    (saved, env_on, saved || env_on)
}

/// Scrub secrets, tokens, URL credentials, and local home directory paths from
/// free-form feedback text before previewing or transmitting it.
pub fn redact_feedback_text(input: &str) -> String {
    static JWT_RE: OnceLock<Regex> = OnceLock::new();
    static KEY_RE: OnceLock<Regex> = OnceLock::new();
    static BEARER_RE: OnceLock<Regex> = OnceLock::new();
    static COOKIE_RE: OnceLock<Regex> = OnceLock::new();
    static URL_CREDS_RE: OnceLock<Regex> = OnceLock::new();
    static HOME_UNIX_RE: OnceLock<Regex> = OnceLock::new();
    static HOME_WIN_RE: OnceLock<Regex> = OnceLock::new();

    let jwt = JWT_RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b").unwrap()
    });
    let key = KEY_RE.get_or_init(|| {
        Regex::new(
            r"\b(sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|xox[bpoar]-[A-Za-z0-9-]{16,}|glpat-[A-Za-z0-9_-]{16,})\b",
        )
        .unwrap()
    });
    let bearer =
        BEARER_RE.get_or_init(|| Regex::new(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}").unwrap());
    let cookie =
        COOKIE_RE.get_or_init(|| Regex::new(r"(?i)((?:set-)?cookie\s*:\s*)[^\r\n]{6,}").unwrap());
    let url_creds = URL_CREDS_RE
        .get_or_init(|| Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)([^:@/\s]+):([^@/\s]+)@").unwrap());
    let home_unix =
        HOME_UNIX_RE.get_or_init(|| Regex::new(r"/(?:Users|home)/[A-Za-z0-9._-]+").unwrap());
    let home_win =
        HOME_WIN_RE.get_or_init(|| Regex::new(r"(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+").unwrap());

    let out = jwt.replace_all(input, "[REDACTED_JWT]");
    let out = key.replace_all(&out, "[REDACTED_KEY]");
    let out = bearer.replace_all(&out, "${1}[REDACTED]");
    let out = cookie.replace_all(&out, "${1}[REDACTED]");
    let out = url_creds.replace_all(&out, "${1}***:***@");
    let out = home_unix.replace_all(&out, "<home>");
    let out = home_win.replace_all(&out, "<home>");
    out.trim().to_string()
}

fn collect_sanitized_stats(target: &ProjectTarget) -> Option<SanitizedStats> {
    let ctx = project::resolve(target).ok()?;
    let det = super::detect::detect(&ctx.root);
    let mut stats = SanitizedStats {
        framework: det.framework,
        scan_mode: Some(format!("{:?}", ctx.config.scan.mode).to_ascii_lowercase()),
        roles_count: Some(ctx.config.roles.len()),
        ..Default::default()
    };

    let mut seen_roles = BTreeSet::new();
    let mut roles_mapped: usize = 0;
    let mut routes_visited: u32 = 0;
    let mut routes_known: u32 = 0;
    let mut controls_exercised: u32 = 0;
    let mut controls_exercisable: u32 = 0;
    let mut dead: usize = 0;
    let mut broken: usize = 0;
    let mut no_effect: usize = 0;
    let mut all_gaps: BTreeMap<String, u32> = BTreeMap::new();

    for role in ctx.role_names() {
        if !seen_roles.insert(role.clone()) {
            continue;
        }
        let Some(inv_path) = ctx.role_paths(&role).readable_inventory_path() else {
            continue;
        };
        if let Ok(inv) = inventory::load(&inv_path) {
            roles_mapped += 1;
            routes_visited = routes_visited.max(inv.coverage.routes_visited);
            routes_known = routes_known.max(inv.coverage.routes_known);
            controls_exercised = controls_exercised.saturating_add(inv.coverage.controls_exercised);
            controls_exercisable =
                controls_exercisable.saturating_add(inv.coverage.controls_exercisable);
            dead += inv
                .controls
                .iter()
                .filter(|c| c.status == inventory::ControlStatus::Dead)
                .count();
            broken += inv
                .controls
                .iter()
                .filter(|c| c.status == inventory::ControlStatus::Broken)
                .count();
            no_effect += inv
                .controls
                .iter()
                .filter(|c| c.status == inventory::ControlStatus::NoEffect)
                .count();
            for (reason, count) in &inv.coverage.not_exercised_by_reason {
                let entry = all_gaps.entry(reason.clone()).or_insert(0);
                *entry = entry.saturating_add(*count);
            }
        }
    }

    if roles_mapped > 0 {
        stats.roles_mapped = Some(roles_mapped);
        stats.routes_visited = Some(routes_visited);
        stats.routes_known = Some(routes_known);
        stats.controls_exercised = Some(controls_exercised);
        stats.controls_exercisable = Some(controls_exercisable);
        stats.dead = Some(dead);
        stats.broken = Some(broken);
        stats.no_effect = Some(no_effect);
        for (reason, count) in all_gaps.into_iter().take(15) {
            stats.gap_reasons.insert(reason, count);
        }
    }
    Some(stats)
}

fn normalize_category(raw: &str) -> Result<String> {
    let c = raw.trim().to_ascii_lowercase();
    if VALID_CATEGORIES.contains(&c.as_str()) {
        Ok(c)
    } else {
        bail!(
            "unknown --category `{raw}`; choose one of: {}",
            VALID_CATEGORIES.join(", ")
        );
    }
}

fn should_preview_feedback(dry_run: bool, send: bool) -> bool {
    dry_run || !send
}

pub async fn run(args: FeedbackArgs) -> Result<i32> {
    let spath = settings_path();
    let endpoint = args
        .endpoint
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_FEEDBACK_ENDPOINT.to_string());

    if args.opt_in || args.opt_out || args.status {
        let mut settings = load_settings(&spath);
        let status_label = if args.opt_in {
            settings.feedback_opt_in = true;
            save_settings(&spath, &settings)?;
            "opted_in"
        } else if args.opt_out {
            settings.feedback_opt_in = false;
            save_settings(&spath, &settings)?;
            "opted_out"
        } else {
            "status"
        };
        let (saved, env_on, effective) = effective_opt_in(&spath);
        let report = SettingsReport {
            status: status_label,
            feedback_opt_in: saved,
            env_override: env_on,
            effective_opt_in: effective,
            settings_path: spath.display().to_string(),
            endpoint,
        };
        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "Agent feedback opt-in: {} (saved={}, BROKENAPP_FEEDBACK_OPT_IN={})",
                if effective { "enabled" } else { "disabled" },
                saved,
                env_on
            );
            println!("Settings: {}", spath.display());
        }
        return Ok(0);
    }

    let raw_message = if args.stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read feedback message from stdin")?;
        buf
    } else {
        args.message.clone().unwrap_or_default()
    };

    let message = redact_feedback_text(&raw_message);
    if message.chars().count() < 8 {
        bail!(
            "provide a feedback message (at least 8 characters), or use `--opt-in` / `--opt-out` / `--status`"
        );
    }

    let category = normalize_category(&args.category)?;
    let agent_explicit = args
        .agent
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let agent = agent_explicit.unwrap_or("cli").to_string();
    let is_agent_call = agent_explicit.is_some_and(|a| !a.eq_ignore_ascii_case("human"));

    let stats = if args.include_stats {
        collect_sanitized_stats(&args.target)
    } else {
        None
    };

    let payload = FeedbackPayload {
        message: message.chars().take(4000).collect(),
        category,
        agent,
        version: env!("BROKENAPP_BUILD_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        stats,
    };

    let (_saved, _env_on, opted_in) = effective_opt_in(&spath);

    // Preview mode whenever `--dry-run` is set OR `--send` is omitted, even
    // after prior opt-in. Every network transmission requires explicit `--send`.
    if should_preview_feedback(args.dry_run, args.send) {
        let hint = if args.dry_run {
            "dry-run only; pass --send (without --dry-run) to transmit".to_string()
        } else if opted_in {
            "nothing was sent (preview mode); pass --send to transmit".to_string()
        } else if is_agent_call {
            "nothing was sent (preview mode); run `brokenapp feedback --opt-in` (or export BROKENAPP_FEEDBACK_OPT_IN=1) and pass --send to transmit agent feedback".to_string()
        } else {
            "nothing was sent (preview mode); pass --send for a one-off report, or run `brokenapp feedback --opt-in` (or export BROKENAPP_FEEDBACK_OPT_IN=1) to allow your agent to submit feedback with --send".to_string()
        };
        let res = FeedbackResult {
            status: "dry_run",
            sent: false,
            id: None,
            queued_at: None,
            endpoint,
            payload,
            hint: Some(hint.clone()),
        };
        if args.json {
            println!("{}", serde_json::to_string_pretty(&res)?);
        } else {
            println!("Feedback preview (NOT sent):");
            println!("{}", serde_json::to_string_pretty(&res.payload)?);
            println!("\n{hint}");
        }
        return Ok(0);
    }

    // Strict consent gate: agent-initiated submissions require explicit opt-in.
    if is_agent_call && !opted_in {
        let hint = "agent feedback is disabled by default; ask the user to run `brokenapp feedback --opt-in` (or export BROKENAPP_FEEDBACK_OPT_IN=1) before sending agent feedback".to_string();
        let res = FeedbackResult {
            status: "opt_in_required",
            sent: false,
            id: None,
            queued_at: None,
            endpoint,
            payload,
            hint: Some(hint.clone()),
        };
        if args.json {
            println!("{}", serde_json::to_string_pretty(&res)?);
        } else {
            eprintln!("error: {hint}");
            println!("{}", serde_json::to_string_pretty(&res.payload)?);
        }
        return Ok(1);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("brokenapp/{}", env!("BROKENAPP_BUILD_VERSION")))
        .build()
        .context("build HTTP client for feedback")?;

    let resp = client
        .post(&endpoint)
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("send feedback to {endpoint}"))?;

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!(
            "feedback endpoint returned HTTP {}: {}",
            status.as_u16(),
            body_text.trim()
        );
    }

    let parsed: serde_json::Value = serde_json::from_str(&body_text).unwrap_or_default();
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let queued_at = parsed
        .get("queued_at")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let res = FeedbackResult {
        status: "queued",
        sent: true,
        id: id.clone(),
        queued_at: queued_at.clone(),
        endpoint,
        payload,
        hint: None,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        println!(
            "Feedback queued{}.",
            id.as_deref()
                .map(|i| format!(" (id: {i})"))
                .unwrap_or_default()
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_tokens_jwts_cookies_urls_and_home_paths() {
        let raw = "Hit bug in /Users/alice/work/app with Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcde12345 and sk-1234567890abcdefghij and postgres://admin:hunter2@localhost/db\nCookie: session=supersecretvalue";
        let clean = redact_feedback_text(raw);
        assert!(!clean.contains("/Users/alice"), "{clean}");
        assert!(clean.contains("<home>/work/app"), "{clean}");
        assert!(!clean.contains("eyJhbGci"), "{clean}");
        assert!(!clean.contains("sk-1234567890"), "{clean}");
        assert!(!clean.contains("hunter2"), "{clean}");
        assert!(!clean.contains("supersecretvalue"), "{clean}");
        assert!(clean.contains("[REDACTED_JWT]"), "{clean}");
        assert!(clean.contains("[REDACTED_KEY]"), "{clean}");
        assert!(clean.contains("postgres://***:***@localhost/db"), "{clean}");
    }

    #[test]
    fn settings_round_trip_opt_in_and_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        assert!(!load_settings(&path).feedback_opt_in);
        save_settings(
            &path,
            &UserSettings {
                feedback_opt_in: true,
            },
        )
        .unwrap();
        assert!(load_settings(&path).feedback_opt_in);
        save_settings(
            &path,
            &UserSettings {
                feedback_opt_in: false,
            },
        )
        .unwrap();
        assert!(!load_settings(&path).feedback_opt_in);
    }

    #[test]
    fn category_validation_rejects_unknown() {
        assert_eq!(normalize_category("AUTH").unwrap(), "auth");
        assert_eq!(normalize_category("rbac").unwrap(), "rbac");
        assert!(normalize_category("nonsense").is_err());
    }

    #[test]
    fn collect_sanitized_stats_aggregates_all_mapped_roles() {
        use super::super::project::{CONFIG_FILE, ProjectConfig, ProjectSection, STATE_DIR_NAME};
        use super::super::roles::{RoleConfig, RoleMethod};
        use crate::inventory::{
            Control, ControlStatus, CoverageSummary, INVENTORY_SCHEMA, Inventory,
        };

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("acme-private-app");
        let state_dir = repo.join(STATE_DIR_NAME);
        std::fs::create_dir_all(&state_dir).unwrap();

        let cfg = ProjectConfig {
            project: ProjectSection {
                name: "acme-private-app".into(),
                url: "http://127.0.0.1:4102/".into(),
                codebase: ".".into(),
                ..Default::default()
            },
            roles: vec![RoleConfig {
                name: "owner".into(),
                method: RoleMethod::Form,
                ..Default::default()
            }],
            ..Default::default()
        };
        std::fs::write(
            state_dir.join(CONFIG_FILE),
            toml::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();

        let ctx = project::load_ctx(&state_dir).unwrap();

        let make_control = |idx: usize, route: &str, label: &str, status: ControlStatus| Control {
            key: format!("{route}|button|text={label}#{idx}"),
            route: route.into(),
            role: "button".into(),
            label: label.into(),
            selector: format!("button[data-id='{idx}']"),
            locator: format!("text={label}"),
            count: 1,
            status,
            ..Default::default()
        };

        let mut anon_gaps = BTreeMap::new();
        anon_gaps.insert("interaction_limit".to_string(), 1);
        let anon_inv = Inventory {
            schema: INVENTORY_SCHEMA.into(),
            project: "acme-private-app".into(),
            generated_at: "2026-11-21T00:00:00Z".into(),
            scan_dir: "/tmp/scan-anon".into(),
            target_url: "http://127.0.0.1:4102/".into(),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: 10,
                routes_visited: 2,
                controls_total: 4,
                controls_exercised: 4,
                controls_exercisable: 4,
                not_exercised_by_reason: anon_gaps,
                ..Default::default()
            },
            controls: (0..4)
                .map(|i| make_control(i, "/login", "Sign in", ControlStatus::Ok))
                .collect(),
            ..Default::default()
        };
        inventory::save(
            &anon_inv,
            &ctx.role_paths("anonymous").latest_inventory_path(),
        )
        .unwrap();

        let mut owner_gaps = BTreeMap::new();
        owner_gaps.insert("interaction_limit".to_string(), 2);
        owner_gaps.insert("obscured".to_string(), 3);
        let mut owner_controls = vec![
            make_control(
                0,
                "/owner/billing",
                "Dead Owner Action",
                ControlStatus::Dead,
            ),
            make_control(
                1,
                "/owner/billing",
                "Broken Owner Action 1",
                ControlStatus::Broken,
            ),
            make_control(
                2,
                "/owner/billing",
                "Broken Owner Action 2",
                ControlStatus::Broken,
            ),
            make_control(
                3,
                "/owner/settings",
                "NoEffect Owner Action",
                ControlStatus::NoEffect,
            ),
        ];
        for i in 4..54 {
            owner_controls.push(make_control(
                i,
                "/owner/dashboard",
                "Owner Button",
                ControlStatus::Ok,
            ));
        }
        let owner_inv = Inventory {
            schema: INVENTORY_SCHEMA.into(),
            project: "acme-private-app".into(),
            generated_at: "2026-11-21T00:00:00Z".into(),
            scan_dir: "/tmp/scan-owner".into(),
            target_url: "http://127.0.0.1:4102/".into(),
            role: Some("owner".into()),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: 10,
                routes_visited: 10,
                controls_total: 54,
                controls_exercised: 54,
                controls_exercisable: 54,
                not_exercised_by_reason: owner_gaps,
                ..Default::default()
            },
            controls: owner_controls,
            ..Default::default()
        };
        inventory::save(&owner_inv, &ctx.role_paths("owner").latest_inventory_path()).unwrap();

        let target = ProjectTarget {
            project: None,
            state_dir: Some(state_dir),
        };
        let stats = collect_sanitized_stats(&target).expect("stats collected");
        assert_eq!(stats.roles_count, Some(1));
        assert_eq!(stats.roles_mapped, Some(2));
        assert_eq!(stats.routes_visited, Some(10));
        assert_eq!(stats.routes_known, Some(10));
        assert_eq!(stats.controls_exercised, Some(58));
        assert_eq!(stats.controls_exercisable, Some(58));
        assert_eq!(stats.dead, Some(1));
        assert_eq!(stats.broken, Some(2));
        assert_eq!(stats.no_effect, Some(1));
        assert_eq!(stats.gap_reasons.get("interaction_limit"), Some(&3));
        assert_eq!(stats.gap_reasons.get("obscured"), Some(&3));

        // Privacy check: zero URLs, routes, labels, role names, or project names.
        let serialized = serde_json::to_string(&stats).unwrap();
        for forbidden in [
            "owner",
            "acme",
            "127.0.0.1",
            "/owner/billing",
            "/login",
            "Dead Owner Action",
            "Sign in",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "unexpected sensitive string {forbidden:?} in {serialized}"
            );
        }
    }

    #[test]
    fn omitting_send_always_previews_even_when_opted_in() {
        // Without `--send`, feedback must stay in preview mode regardless of opt-in.
        assert!(should_preview_feedback(false, false));
        assert!(should_preview_feedback(true, false));
        assert!(should_preview_feedback(true, true));
        // Only explicit `--send` without `--dry-run` may transmit.
        assert!(!should_preview_feedback(false, true));
    }
}
