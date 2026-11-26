//! `brokenapp parity <baseline> <candidate>`: cross-app behavioral parity CLI.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::inventory::parity::{
    ParityReport, RoleAccessChangeKind, compute_parity, load_map_source, render_markdown,
    render_text,
};

#[derive(Debug, Args)]
pub struct ParityArgs {
    /// Baseline map source (inventory JSON file, `.brokenapp/map`, `.brokenapp/history`, or `.brokenapp` dir).
    pub baseline: PathBuf,
    /// Candidate map source (inventory JSON file, `.brokenapp/map`, `.brokenapp/history`, or `.brokenapp` dir).
    pub candidate: PathBuf,
    /// Output format: text|md|markdown|json.
    #[arg(long, default_value = "text")]
    pub format: String,
    /// Print machine-readable JSON output (shorthand for `--format json`).
    #[arg(long)]
    pub json: bool,
    /// Exit with code 1 when any comma-separated parity rule triggers
    /// (missing-route, missing-endpoint, missing-control, dead, broken,
    /// no-effect, rewired, access-gained, access-lost, role-error, missing-role, any).
    #[arg(long)]
    pub fail_on: Option<String>,
}

impl ParityArgs {
    pub fn wants_json(&self) -> bool {
        self.json || self.format.eq_ignore_ascii_case("json")
    }
}

/// Regression rules selectable via `brokenapp parity --fail-on`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ParityFailOnRule {
    MissingRoute,
    MissingEndpoint,
    MissingControl,
    Dead,
    Broken,
    NoEffect,
    Rewired,
    AccessGained,
    AccessLost,
    RoleError,
    MissingRole,
    Any,
}

impl ParityFailOnRule {
    pub const VALID_NAMES: &'static [&'static str] = &[
        "missing-route",
        "missing-endpoint",
        "missing-control",
        "dead",
        "broken",
        "no-effect",
        "rewired",
        "access-gained",
        "access-lost",
        "role-error",
        "missing-role",
        "any",
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            ParityFailOnRule::MissingRoute => "missing_route",
            ParityFailOnRule::MissingEndpoint => "missing_endpoint",
            ParityFailOnRule::MissingControl => "missing_control",
            ParityFailOnRule::Dead => "dead",
            ParityFailOnRule::Broken => "broken",
            ParityFailOnRule::NoEffect => "no_effect",
            ParityFailOnRule::Rewired => "rewired",
            ParityFailOnRule::AccessGained => "access_gained",
            ParityFailOnRule::AccessLost => "access_lost",
            ParityFailOnRule::RoleError => "role_error",
            ParityFailOnRule::MissingRole => "missing_role",
            ParityFailOnRule::Any => "any",
        }
    }

    pub fn included_in_any(&self) -> bool {
        !matches!(self, ParityFailOnRule::NoEffect | ParityFailOnRule::Any)
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let norm = raw.trim().to_ascii_lowercase().replace('-', "_");
        match norm.as_str() {
            "missing_route" | "route_removed" => Ok(ParityFailOnRule::MissingRoute),
            "missing_endpoint" | "endpoint_removed" => Ok(ParityFailOnRule::MissingEndpoint),
            "missing_control" | "removed" => Ok(ParityFailOnRule::MissingControl),
            "dead" | "now_dead" => Ok(ParityFailOnRule::Dead),
            "broken" | "now_broken" => Ok(ParityFailOnRule::Broken),
            "no_effect" | "now_no_effect" => Ok(ParityFailOnRule::NoEffect),
            "rewired" => Ok(ParityFailOnRule::Rewired),
            "access_gained" => Ok(ParityFailOnRule::AccessGained),
            "access_lost" => Ok(ParityFailOnRule::AccessLost),
            "role_error" => Ok(ParityFailOnRule::RoleError),
            "missing_role" => Ok(ParityFailOnRule::MissingRole),
            "any" => Ok(ParityFailOnRule::Any),
            _ => bail!(
                "unknown parity --fail-on rule '{}' (valid values: {})",
                raw.trim(),
                Self::VALID_NAMES.join(", ")
            ),
        }
    }
}

/// Parsed `--fail-on` policy for `brokenapp parity`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityFailOnPolicy {
    pub rules: BTreeSet<ParityFailOnRule>,
}

impl ParityFailOnPolicy {
    pub fn parse(spec: &str) -> Result<Self> {
        let mut rules = BTreeSet::new();
        for token in spec.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            rules.insert(ParityFailOnRule::parse(trimmed)?);
        }
        if rules.is_empty() {
            bail!(
                "--fail-on requires at least one rule (valid values: {})",
                ParityFailOnRule::VALID_NAMES.join(", ")
            );
        }
        Ok(Self { rules })
    }

    pub fn enables(&self, rule: ParityFailOnRule) -> bool {
        self.rules.contains(&rule)
            || (self.rules.contains(&ParityFailOnRule::Any) && rule.included_in_any())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityGateViolation {
    pub rule: ParityFailOnRule,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityGateResult {
    pub passed: bool,
    pub triggered_rules: Vec<ParityFailOnRule>,
    pub violations: Vec<ParityGateViolation>,
}

/// Evaluate a [`ParityFailOnPolicy`] against a computed [`ParityReport`].
pub fn evaluate_parity_gate(
    policy: &ParityFailOnPolicy,
    report: &ParityReport,
) -> ParityGateResult {
    let mut triggered = BTreeSet::new();
    let mut violations = Vec::new();

    let mut push = |rule: ParityFailOnRule, detail: String| {
        if policy.enables(rule) {
            triggered.insert(rule);
            violations.push(ParityGateViolation { rule, detail });
        }
    };

    // Role access regressions
    for missing_role in &report.role_access.roles_only_in_old {
        push(
            ParityFailOnRule::MissingRole,
            format!("MISSING ROLE {missing_role}"),
        );
    }
    for ch in &report.role_access.changes {
        match ch.kind {
            RoleAccessChangeKind::AccessGained => {
                push(ParityFailOnRule::AccessGained, ch.line.clone())
            }
            RoleAccessChangeKind::AccessLost => push(ParityFailOnRule::AccessLost, ch.line.clone()),
            RoleAccessChangeKind::RoleError => push(ParityFailOnRule::RoleError, ch.line.clone()),
            RoleAccessChangeKind::StatusChanged => {}
        }
    }

    // Routes
    for route in &report.routes.missing_routes {
        push(
            ParityFailOnRule::MissingRoute,
            format!("MISSING ROUTE {route}"),
        );
    }
    for reg in &report.routes.regressed_routes {
        push(
            ParityFailOnRule::MissingRoute,
            format!("REGRESSED ROUTE {}", reg.detail),
        );
    }

    // Endpoints
    for ep in &report.endpoints.missing_endpoints {
        push(
            ParityFailOnRule::MissingEndpoint,
            format!("MISSING ENDPOINT {ep}"),
        );
    }
    for reg in &report.endpoints.status_regressions {
        push(
            ParityFailOnRule::MissingEndpoint,
            format!("ENDPOINT REGRESSION {}", reg.detail),
        );
    }

    // Controls per role
    for rc in &report.controls.per_role {
        for ch in &rc.changes.changes {
            let rule = match ch.kind.as_str() {
                "removed" | "route_content_missing" => Some(ParityFailOnRule::MissingControl),
                "now_dead" => Some(ParityFailOnRule::Dead),
                "now_broken" => Some(ParityFailOnRule::Broken),
                "now_no_effect" => Some(ParityFailOnRule::NoEffect),
                "rewired" => Some(ParityFailOnRule::Rewired),
                _ => None,
            };
            if let Some(r) = rule {
                push(r, format!("[{}] {}", rc.role, ch.line));
            }
        }
    }

    ParityGateResult {
        passed: violations.is_empty(),
        triggered_rules: triggered.into_iter().collect(),
        violations,
    }
}

/// Compute parity output and exit code without writing to stdout (pure helper for CLI and tests).
pub fn parity_output(args: &ParityArgs) -> Result<(String, i32)> {
    let format = if args.json {
        "json"
    } else {
        args.format.as_str()
    };
    let format_norm = format.trim().to_ascii_lowercase();
    if !matches!(format_norm.as_str(), "text" | "md" | "markdown" | "json") {
        bail!("unknown format '{format}' (expected text|md|markdown|json)");
    }

    let policy = args
        .fail_on
        .as_deref()
        .map(ParityFailOnPolicy::parse)
        .transpose()?;

    let baseline = load_map_source(&args.baseline)?;
    let candidate = load_map_source(&args.candidate)?;
    let report = compute_parity(&baseline, &candidate);

    let gate = policy.as_ref().map(|p| evaluate_parity_gate(p, &report));
    let exit_code = match &gate {
        Some(g) if !g.passed => 1,
        _ => 0,
    };

    let out = match format_norm.as_str() {
        "json" => {
            let mut doc = serde_json::to_value(&report).context("serialize parity report")?;
            if let Some(g) = &gate {
                doc["gate"] = serde_json::to_value(g).context("serialize parity gate")?;
            }
            format!(
                "{}\n",
                serde_json::to_string_pretty(&doc).context("format parity json")?
            )
        }
        "md" | "markdown" => {
            let mut body = render_markdown(&report);
            if let Some(g) = &gate {
                body.push('\n');
                if g.passed {
                    body.push_str("**Parity Gate:** `PASS`\n");
                } else {
                    let rules: Vec<&str> = g
                        .triggered_rules
                        .iter()
                        .map(ParityFailOnRule::as_str)
                        .collect();
                    body.push_str(&format!(
                        "> [!CAUTION]\n> **Parity Gate: `FAIL`** — triggered `{}` ({} violation{})\n",
                        rules.join("`, `"),
                        g.violations.len(),
                        if g.violations.len() == 1 { "" } else { "s" }
                    ));
                }
            }
            body
        }
        _ => {
            let mut body = render_text(&report);
            if let Some(g) = &gate {
                body.push('\n');
                if g.passed {
                    body.push_str("Gate: PASS\n");
                } else {
                    let rules: Vec<&str> = g
                        .triggered_rules
                        .iter()
                        .map(ParityFailOnRule::as_str)
                        .collect();
                    body.push_str(&format!(
                        "Gate: FAIL (triggered: {}; {} violation{})\n",
                        rules.join(", "),
                        g.violations.len(),
                        if g.violations.len() == 1 { "" } else { "s" }
                    ));
                }
            }
            body
        }
    };

    Ok((out, exit_code))
}

pub async fn run(args: ParityArgs) -> Result<i32> {
    let (out, code) = parity_output(&args)?;
    print!("{out}");
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{
        Control, ControlStatus, CoverageSummary, EndpointEntry, IDENTITY_VERSION, Inventory,
        Outcome, RouteEntry,
    };

    fn make_inv(project: &str, visited_billing: bool, btn_status: ControlStatus) -> Inventory {
        let routes = vec![
            RouteEntry {
                route: "/".into(),
                visited: true,
                status: Some(200),
                ..Default::default()
            },
            RouteEntry {
                route: "/billing".into(),
                visited: visited_billing,
                status: if visited_billing { Some(200) } else { None },
                unvisited_reason: if visited_billing {
                    None
                } else {
                    Some("redirects to login".into())
                },
                ..Default::default()
            },
        ];
        let controls = vec![Control {
            key: "/|button|text=save".into(),
            route: "/".into(),
            routes: vec!["/".into()],
            role: "button".into(),
            label: "Save".into(),
            locator: "text=save".into(),
            selector: "#save".into(),
            count: 1,
            status: btn_status,
            outcomes: if btn_status == ControlStatus::Ok {
                vec![Outcome::Calls {
                    endpoint: "POST /api/save".into(),
                    status: Some(200),
                    blocked: false,
                }]
            } else {
                vec![]
            },
            ..Default::default()
        }];
        let endpoints = if btn_status == ControlStatus::Ok {
            vec![EndpointEntry {
                endpoint: "POST /api/save".into(),
                controls: vec!["/|button|text=save".into()],
                on_load: vec![],
                statuses: vec![200],
                write: true,
            }]
        } else {
            vec![]
        };
        Inventory {
            schema: crate::inventory::INVENTORY_SCHEMA.into(),
            identity_version: IDENTITY_VERSION,
            project: project.into(),
            generated_at: "2026-11-20T10:00:00Z".into(),
            target_url: "http://127.0.0.1:3000".into(),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: routes.len() as u32,
                routes_visited: routes.iter().filter(|r| r.visited).count() as u32,
                controls_total: controls.len() as u32,
                controls_exercised: controls.len() as u32,
                controls_exercisable: controls.len() as u32,
                ..Default::default()
            },
            routes,
            controls,
            endpoints,
            ..Default::default()
        }
    }

    #[test]
    fn parity_cmd_formats_and_fail_on_exit_codes() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("base.inventory.json");
        let cand_path = dir.path().join("cand.inventory.json");
        crate::inventory::save(&make_inv("v1", true, ControlStatus::Ok), &base_path).unwrap();
        crate::inventory::save(&make_inv("v2", false, ControlStatus::Dead), &cand_path).unwrap();

        // Without --fail-on -> exit 0, text output
        let args = ParityArgs {
            baseline: base_path.clone(),
            candidate: cand_path.clone(),
            format: "text".into(),
            json: false,
            fail_on: None,
        };
        let (out, code) = parity_output(&args).unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("Behavioral Parity: v1 -> v2 [FAIL]"), "{out}");

        // With --fail-on dead,access-lost -> exit 1
        let args_fail = ParityArgs {
            baseline: base_path.clone(),
            candidate: cand_path.clone(),
            format: "md".into(),
            json: false,
            fail_on: Some("dead,access-lost".into()),
        };
        let (out_md, code_fail) = parity_output(&args_fail).unwrap();
        assert_eq!(code_fail, 1);
        assert!(out_md.contains("**Parity Gate: `FAIL`**"), "{out_md}");

        // With --fail-on broken (not triggered) -> exit 0, json output
        let args_json = ParityArgs {
            baseline: base_path.clone(),
            candidate: cand_path.clone(),
            format: "text".into(),
            json: true,
            fail_on: Some("broken".into()),
        };
        assert!(args_json.wants_json());
        let (out_json, code_pass) = parity_output(&args_json).unwrap();
        assert_eq!(code_pass, 0);
        let parsed: serde_json::Value = serde_json::from_str(&out_json).unwrap();
        assert_eq!(parsed["gate"]["passed"], true);
        assert_eq!(parsed["summary"]["passed"], false);

        // Unknown --fail-on token errors out
        let args_bad = ParityArgs {
            baseline: base_path.clone(),
            candidate: cand_path.clone(),
            format: "text".into(),
            json: false,
            fail_on: Some("not-a-rule".into()),
        };
        assert!(parity_output(&args_bad).is_err());

        // Unknown --format errors out
        let args_bad_fmt = ParityArgs {
            baseline: base_path,
            candidate: cand_path,
            format: "xml".into(),
            json: false,
            fail_on: None,
        };
        assert!(parity_output(&args_bad_fmt).is_err());
    }

    #[test]
    fn parity_cli_subcommand_parses_all_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrapper {
            #[command(subcommand)]
            cmd: crate::front::FrontCommand,
        }
        let parsed = Wrapper::try_parse_from([
            "brokenapp",
            "parity",
            "old/.brokenapp/map",
            "new/.brokenapp/map",
            "--format",
            "markdown",
            "--fail-on",
            "missing-route,missing-endpoint,missing-control,dead,broken,rewired,access-gained,access-lost,any",
        ])
        .unwrap();
        let crate::front::FrontCommand::Parity(args) = parsed.cmd else {
            panic!("expected Parity command");
        };
        assert_eq!(args.baseline, PathBuf::from("old/.brokenapp/map"));
        assert_eq!(args.candidate, PathBuf::from("new/.brokenapp/map"));
        assert_eq!(args.format, "markdown");
        assert!(!args.wants_json());
        let policy = ParityFailOnPolicy::parse(args.fail_on.as_deref().unwrap()).unwrap();
        assert!(policy.enables(ParityFailOnRule::MissingRoute));
        assert!(policy.enables(ParityFailOnRule::MissingEndpoint));
        assert!(policy.enables(ParityFailOnRule::MissingControl));
        assert!(policy.enables(ParityFailOnRule::AccessGained));
    }
}
