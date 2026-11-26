//! CI `--fail-on` regression gate policy, PR-comment Markdown renderer, and
//! multi-role history loader for `brokenapp changes`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::project::{LATEST_INVENTORY, ProjectCtx};
use crate::inventory::parity::{
    EndpointAccessChangeKind, RoleAccessChangeKind, RoleAccessDiff, diff_role_access,
};
use crate::inventory::render::{self, md_cell};
use crate::inventory::{ChangeSet, Inventory};

/// Individual regression rule selectable via `--fail-on`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FailOnRule {
    Dead,
    Broken,
    NoEffect,
    Rewired,
    Removed,
    RouteRemoved,
    EndpointRemoved,
    AccessGained,
    AccessLost,
    Any,
}

impl FailOnRule {
    pub const VALID_NAMES: &'static [&'static str] = &[
        "dead",
        "broken",
        "no-effect",
        "rewired",
        "removed",
        "route-removed",
        "endpoint-removed",
        "access-gained",
        "access-lost",
        "any",
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            FailOnRule::Dead => "dead",
            FailOnRule::Broken => "broken",
            FailOnRule::NoEffect => "no_effect",
            FailOnRule::Rewired => "rewired",
            FailOnRule::Removed => "removed",
            FailOnRule::RouteRemoved => "route_removed",
            FailOnRule::EndpointRemoved => "endpoint_removed",
            FailOnRule::AccessGained => "access_gained",
            FailOnRule::AccessLost => "access_lost",
            FailOnRule::Any => "any",
        }
    }

    /// Whether `--fail-on any` includes this regression rule.
    pub fn included_in_any(&self) -> bool {
        matches!(
            self,
            FailOnRule::Dead
                | FailOnRule::Broken
                | FailOnRule::Removed
                | FailOnRule::Rewired
                | FailOnRule::RouteRemoved
                | FailOnRule::EndpointRemoved
                | FailOnRule::AccessGained
                | FailOnRule::AccessLost
        )
    }

    /// Parse one token (case-insensitive, hyphens or underscores).
    pub fn parse(raw: &str) -> Result<Self> {
        let norm = raw.trim().to_ascii_lowercase().replace('-', "_");
        match norm.as_str() {
            "dead" | "now_dead" => Ok(FailOnRule::Dead),
            "broken" | "now_broken" => Ok(FailOnRule::Broken),
            "no_effect" | "now_no_effect" => Ok(FailOnRule::NoEffect),
            "rewired" => Ok(FailOnRule::Rewired),
            "removed" => Ok(FailOnRule::Removed),
            "route_removed" => Ok(FailOnRule::RouteRemoved),
            "endpoint_removed" => Ok(FailOnRule::EndpointRemoved),
            "access_gained" => Ok(FailOnRule::AccessGained),
            "access_lost" => Ok(FailOnRule::AccessLost),
            "any" => Ok(FailOnRule::Any),
            _ => bail!(
                "unknown --fail-on rule '{}' (valid values: {})",
                raw.trim(),
                Self::VALID_NAMES.join(", ")
            ),
        }
    }
}

impl std::fmt::Display for FailOnRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsed `--fail-on` policy containing one or more rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailOnPolicy {
    pub rules: BTreeSet<FailOnRule>,
}

impl FailOnPolicy {
    /// Parse a comma-separated `--fail-on` specification (e.g. `"dead,broken,access-gained"`).
    pub fn parse(spec: &str) -> Result<Self> {
        let mut rules = BTreeSet::new();
        for token in spec.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            rules.insert(FailOnRule::parse(trimmed)?);
        }
        if rules.is_empty() {
            bail!(
                "--fail-on requires at least one rule (valid values: {})",
                FailOnRule::VALID_NAMES.join(", ")
            );
        }
        Ok(Self { rules })
    }

    /// Returns `true` if `rule` is enabled directly or via `FailOnRule::Any`.
    pub fn enables(&self, rule: FailOnRule) -> bool {
        self.rules.contains(&rule)
            || (self.rules.contains(&FailOnRule::Any) && rule.included_in_any())
    }
}

/// One change that tripped an enabled `--fail-on` rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateViolation {
    pub rule: FailOnRule,
    pub role: String,
    pub route: String,
    pub kind: String,
    pub line: String,
}

/// Verdict of evaluating a [`FailOnPolicy`] against behavioral + role-access diffs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateResult {
    pub passed: bool,
    pub triggered_rules: Vec<FailOnRule>,
    pub violations: Vec<GateViolation>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub inconclusive: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inconclusive_reasons: Vec<String>,
}

/// Map an inventory `Change.kind` to its corresponding [`FailOnRule`], if any.
fn rule_for_change_kind(kind: &str) -> Option<FailOnRule> {
    match kind {
        "now_dead" => Some(FailOnRule::Dead),
        "now_broken" => Some(FailOnRule::Broken),
        "now_no_effect" => Some(FailOnRule::NoEffect),
        "rewired" => Some(FailOnRule::Rewired),
        "removed" | "route_content_missing" => Some(FailOnRule::Removed),
        "route_removed" => Some(FailOnRule::RouteRemoved),
        "endpoint_removed" => Some(FailOnRule::EndpointRemoved),
        _ => None,
    }
}

/// Additional role-level coverage health signals for CI gate evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateRoleHealth {
    /// Configured roles that have no saved map (e.g. login or scan failed).
    pub missing_roles: Vec<String>,
    /// `(role, baseline_routes_visited)` for roles whose latest snapshot
    /// visited 0 routes while the baseline visited `> 0` routes.
    pub collapsed_roles: Vec<(String, u32)>,
    /// `(role, baseline_routes_visited, latest_routes_visited)` for roles where
    /// either the baseline or the latest snapshot visited 0 routes.
    pub zero_coverage_roles: Vec<(String, u32, u32)>,
}

/// Evaluate a CI `--fail-on` policy against per-role control changes and an
/// optional multi-role access diff.
pub fn evaluate_changes_gate(
    policy: &FailOnPolicy,
    control_changes: &[(&str, &ChangeSet)],
    role_diff: Option<&RoleAccessDiff>,
) -> GateResult {
    evaluate_changes_gate_with_health(
        policy,
        control_changes,
        role_diff,
        &GateRoleHealth::default(),
    )
}

/// Evaluate a CI `--fail-on` policy with role-level map health checks
/// (missing configured role maps and zero-route coverage failures).
pub fn evaluate_changes_gate_with_health(
    policy: &FailOnPolicy,
    control_changes: &[(&str, &ChangeSet)],
    role_diff: Option<&RoleAccessDiff>,
    health: &GateRoleHealth,
) -> GateResult {
    let mut triggered = BTreeSet::new();
    let mut violations = Vec::new();
    let mut inconclusive_reasons = Vec::new();
    let mut reported_zero_coverage_roles = BTreeSet::new();

    if control_changes.is_empty() {
        inconclusive_reasons.push("no role maps available to compare".to_string());
    }

    for role in &health.missing_roles {
        inconclusive_reasons.push(format!(
            "{role}: configured role has no saved map (login or scan failed)"
        ));
    }
    for (role, baseline_visited, latest_visited) in &health.zero_coverage_roles {
        if *baseline_visited == 0 || *latest_visited == 0 {
            reported_zero_coverage_roles.insert(role.as_str());
            let reason = match (*baseline_visited, *latest_visited) {
                (0, 0) => format!(
                    "{role}: both baseline and latest maps visited 0 routes; scan could not verify release"
                ),
                (0, latest) => format!(
                    "{role}: baseline map visited 0 routes (latest had {latest}); cannot verify against an empty baseline"
                ),
                (baseline, 0) => format!(
                    "{role}: latest map visited 0 routes (baseline had {baseline}); crawl likely timed out or failed to render"
                ),
                _ => unreachable!(),
            };
            inconclusive_reasons.push(reason);
        }
    }
    for (role, baseline_visited) in &health.collapsed_roles {
        if *baseline_visited > 0 && reported_zero_coverage_roles.insert(role.as_str()) {
            inconclusive_reasons.push(format!(
                "{role}: latest map visited 0 routes (baseline had {baseline_visited}); crawl likely timed out"
            ));
        }
    }

    // Evaluate RBAC changes first so critical escalations appear at the top.
    if let Some(rd) = role_diff {
        for ch in &rd.changes {
            let rule = match ch.kind {
                RoleAccessChangeKind::AccessGained => Some(FailOnRule::AccessGained),
                RoleAccessChangeKind::AccessLost => Some(FailOnRule::AccessLost),
                RoleAccessChangeKind::RoleError | RoleAccessChangeKind::StatusChanged => None,
            };
            if let Some(r) = rule
                && policy.enables(r)
            {
                triggered.insert(r);
                violations.push(GateViolation {
                    rule: r,
                    role: ch.role.clone(),
                    route: ch.route.clone(),
                    kind: ch.kind.as_str().to_string(),
                    line: ch.line.clone(),
                });
            }
        }
        for ch in &rd.endpoint_changes {
            let r = match ch.kind {
                EndpointAccessChangeKind::EndpointAccessGained => FailOnRule::AccessGained,
                EndpointAccessChangeKind::EndpointAccessLost => FailOnRule::AccessLost,
            };
            if policy.enables(r) {
                triggered.insert(r);
                violations.push(GateViolation {
                    rule: r,
                    role: ch.role.clone(),
                    route: ch.endpoint.clone(),
                    kind: ch.kind.as_str().to_string(),
                    line: ch.line.clone(),
                });
            }
        }
    }

    for (role, cs) in control_changes {
        if cs.from.is_none() {
            inconclusive_reasons.push(format!(
                "{role}: no earlier baseline map to compare against"
            ));
        }
        if cs.summary.contains_key("rebaselined")
            || cs.changes.iter().any(|c| c.kind == "rebaselined")
        {
            inconclusive_reasons.push(format!(
                "{role}: control identity scheme was rebaselined; baseline is not comparable"
            ));
        }
        for ch in &cs.changes {
            if let Some(r) = rule_for_change_kind(&ch.kind)
                && policy.enables(r)
            {
                triggered.insert(r);
                violations.push(GateViolation {
                    rule: r,
                    role: (*role).to_string(),
                    route: ch.route.clone(),
                    kind: ch.kind.clone(),
                    line: ch.line.clone(),
                });
            }
        }
    }

    let inconclusive = !inconclusive_reasons.is_empty();
    GateResult {
        passed: violations.is_empty() && !inconclusive,
        triggered_rules: triggered.into_iter().collect(),
        violations,
        inconclusive,
        inconclusive_reasons,
    }
}

/// Render a GitHub-flavored Markdown summary suitable for posting directly on a PR.
pub fn render_changes_markdown(
    role_changes: &[(&str, &ChangeSet, &Inventory)],
    role_diff: Option<&RoleAccessDiff>,
    gate: Option<&GateResult>,
) -> String {
    let project = role_changes
        .iter()
        .find_map(|(_, _, inv)| {
            let p = inv.project.trim();
            (!p.is_empty()).then_some(p)
        })
        .unwrap_or("");

    let mut out = String::new();
    if project.is_empty() {
        out.push_str("## BrokenApp Behavioral Diff\n\n");
    } else {
        let _ = writeln!(
            out,
            "## BrokenApp Behavioral Diff — `{}`\n",
            md_cell(project)
        );
    }

    if let Some(g) = gate {
        if g.passed {
            out.push_str("**CI Gate:** `PASS`\n\n");
        } else if g.inconclusive && g.violations.is_empty() {
            let _ = writeln!(
                out,
                "> [!WARNING]\n> **CI Gate: `INCONCLUSIVE`** — {}\n",
                md_cell(&g.inconclusive_reasons.join("; "))
            );
        } else {
            let rules: Vec<&str> = g.triggered_rules.iter().map(FailOnRule::as_str).collect();
            let _ = write!(
                out,
                "> [!CAUTION]\n> **CI Gate: `FAIL`** — triggered `{}` ({} violation{})",
                rules.join("`, `"),
                g.violations.len(),
                if g.violations.len() == 1 { "" } else { "s" }
            );
            if g.inconclusive {
                let _ = write!(
                    out,
                    "\n> **Inconclusive baseline:** {}",
                    md_cell(&g.inconclusive_reasons.join("; "))
                );
            }
            out.push_str("\n\n");
        }
    }

    // Summary counts table
    out.push_str("| Role | From | To | Broken | Dead | No Effect | Rewired | Removed | Added | Fixed | Routes/Endpoints |\n");
    out.push_str("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|\n");
    for (role, cs, _) in role_changes {
        let count = |k: &str| cs.summary.get(k).copied().unwrap_or(0);
        let route_ep = format!(
            "+{}/-{}r, +{}/-{}ep",
            count("route_added"),
            count("route_removed"),
            count("endpoint_added"),
            count("endpoint_removed")
        );
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            md_cell(role),
            md_cell(cs.from.as_deref().unwrap_or("initial")),
            md_cell(&cs.to),
            count("now_broken"),
            count("now_dead"),
            count("now_no_effect"),
            count("rewired"),
            count("removed") + count("route_content_missing"),
            count("added"),
            count("fixed"),
            route_ep
        );
    }
    out.push('\n');

    // RBAC ROLE-ACCESS section
    if let Some(rd) = role_diff {
        out.push_str("### ROLE-ACCESS Changes\n\n");
        let gained = rd.count(RoleAccessChangeKind::AccessGained);
        let ep_gained = rd.endpoint_count(EndpointAccessChangeKind::EndpointAccessGained);
        if gained > 0 || ep_gained > 0 {
            let mut parts = Vec::new();
            if gained > 0 {
                parts.push(format!(
                    "{gained} route{} previously denied {} now reachable",
                    if gained == 1 { "" } else { "s" },
                    if gained == 1 { "is" } else { "are" }
                ));
            }
            if ep_gained > 0 {
                parts.push(format!(
                    "{ep_gained} endpoint{} newly accessible",
                    if ep_gained == 1 { "" } else { "s" }
                ));
            }
            let _ = writeln!(
                out,
                "> [!WARNING]\n> **RBAC Escalation (`ACCESS GAINED`)**: {}.\n",
                parts.join("; ")
            );
        }
        if !rd.roles_only_in_old.is_empty() {
            let _ = writeln!(
                out,
                "- **Roles missing in latest map:** {}\n",
                rd.roles_only_in_old
                    .iter()
                    .map(|r| format!("`{}`", md_cell(r)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if rd.changes.is_empty() && rd.endpoint_changes.is_empty() {
            let _ = writeln!(
                out,
                "No role access regressions across {} compared role{}.\n",
                rd.roles_compared.len(),
                if rd.roles_compared.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
        } else {
            if !rd.changes.is_empty() {
                out.push_str("| Change | Role | Route | Previous | Current | Detail |\n");
                out.push_str("|---|---|---|---|---|---|\n");
                for ch in &rd.changes {
                    let label = if ch.kind == RoleAccessChangeKind::AccessGained {
                        "**ACCESS GAINED**"
                    } else {
                        ch.kind.heading()
                    };
                    let _ = writeln!(
                        out,
                        "| {} | `{}` | `{}` | {} | {} | {} |",
                        label,
                        md_cell(&ch.role),
                        md_cell(&ch.route),
                        ch.old_access.label(),
                        ch.new_access.label(),
                        md_cell(&ch.line)
                    );
                }
                out.push('\n');
            }
            if !rd.endpoint_changes.is_empty() {
                out.push_str("#### Endpoint Access Changes\n\n");
                out.push_str("| Change | Role | Endpoint | Previous | Current | Detail |\n");
                out.push_str("|---|---|---|---|---|---|\n");
                for ch in &rd.endpoint_changes {
                    let label = if ch.kind == EndpointAccessChangeKind::EndpointAccessGained {
                        "**ENDPOINT ACCESS GAINED**"
                    } else {
                        ch.kind.heading()
                    };
                    let _ = writeln!(
                        out,
                        "| {} | `{}` | `{}` | {} | {} | {} |",
                        label,
                        md_cell(&ch.role),
                        md_cell(&ch.endpoint),
                        ch.old_access.label(),
                        ch.new_access.label(),
                        md_cell(&ch.line)
                    );
                }
                out.push('\n');
            }
        }
        if !rd.coverage_notes.is_empty() {
            out.push_str("<details><summary>Role-access coverage notes</summary>\n\n");
            for note in &rd.coverage_notes {
                let _ = writeln!(out, "- {}", md_cell(note));
            }
            out.push_str("\n</details>\n\n");
        }
    }

    // Control changes section
    out.push_str("### Control Changes\n\n");
    let any_changes = role_changes.iter().any(|(_, cs, _)| !cs.changes.is_empty());
    let any_initial = role_changes.iter().any(|(_, cs, _)| cs.from.is_none());
    if !any_changes && !any_initial {
        out.push_str("No UI or endpoint changes detected.\n\n");
    } else {
        for (role, cs, cur) in role_changes {
            if role_changes.len() > 1 {
                let _ = writeln!(out, "#### `{}`\n", md_cell(role));
            }
            if cs.from.is_none() {
                let _ = writeln!(
                    out,
                    "Initial baseline: {}\n",
                    render::change_lines(cs, cur).join(" ")
                );
                continue;
            }
            if cs.changes.is_empty() {
                out.push_str("No changes.\n\n");
            } else {
                out.push_str("| Kind | Route | Detail |\n");
                out.push_str("|---|---|---|\n");
                for ch in &cs.changes {
                    let route_cell = if ch.route.is_empty() {
                        "-".to_string()
                    } else {
                        format!("`{}`", md_cell(&ch.route))
                    };
                    let _ = writeln!(
                        out,
                        "| `{}` | {} | {} |",
                        md_cell(&ch.kind),
                        route_cell,
                        md_cell(&ch.line)
                    );
                }
                out.push('\n');
            }
            for note in &cs.notes {
                let _ = writeln!(out, "_{}_\n", md_cell(note));
            }
        }
    }

    // Coverage footer
    out.push_str("---\n\n**Coverage:**\n");
    for (role, _, inv) in role_changes {
        let _ = writeln!(out, "- `{}`: {}", md_cell(role), render::coverage_line(inv));
    }

    out
}

/// Timestamped history files (`*.inventory.json`, not `latest.inventory.json`), oldest first.
fn history_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".inventory.json") && n != LATEST_INVENTORY)
        })
        .collect();
    files.sort();
    Ok(files)
}

/// The `since`-th inventory before `cur` (skipping copies of `cur`).
fn previous_inventory(dir: &Path, cur: &Inventory, since: usize) -> Result<Option<Inventory>> {
    let mut remaining = since;
    for path in history_files(dir)?.iter().rev() {
        let inv = match crate::inventory::load(path) {
            Ok(inv) => inv,
            Err(err) => {
                tracing::warn!("skip unreadable map {}: {err:#}", path.display());
                continue;
            }
        };
        if inv.generated_at == cur.generated_at && inv.scan_dir == cur.scan_dir {
            continue;
        }
        remaining -= 1;
        if remaining == 0 {
            return Ok(Some(inv));
        }
    }
    Ok(None)
}

/// Load current and `since`-th previous inventories for all mapped roles in
/// `ctx` and return their [`RoleAccessDiff`], or `None` when no historical
/// baseline exists yet.
pub fn load_role_access_diff_for_project(
    ctx: &ProjectCtx,
    since: usize,
) -> Result<Option<RoleAccessDiff>> {
    if since == 0 {
        bail!("--since must be 1 or more");
    }

    let mut role_names: Vec<String> = ctx.role_names();
    let extra_roles_dir = ctx.history_dir().join("roles");
    if let Ok(entries) = std::fs::read_dir(&extra_roles_dir) {
        let mut extras: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        extras.sort();
        for name in extras {
            if !role_names.contains(&name) {
                role_names.push(name);
            }
        }
    }

    let mut old_roles: BTreeMap<String, Inventory> = BTreeMap::new();
    let mut new_roles: BTreeMap<String, Inventory> = BTreeMap::new();

    for role in role_names {
        let paths = ctx.role_paths(&role);
        if !paths.has_saved_inventory() {
            continue;
        }
        let cur = paths.load_latest(ctx.name())?;
        if let Some(prev) = previous_inventory(&paths.history_dir, &cur, since)? {
            old_roles.insert(role.clone(), prev);
        }
        new_roles.insert(role, cur);
    }

    if old_roles.is_empty() || new_roles.is_empty() {
        return Ok(None);
    }
    Ok(Some(diff_role_access(&old_roles, &new_roles)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::front::project::{CONFIG_FILE, load_ctx};
    use crate::inventory::{
        Control, ControlStatus, CoverageSummary, IDENTITY_VERSION, Outcome, RouteEntry,
    };

    fn route(path: &str, visited: bool, status: Option<u16>, why: Option<&str>) -> RouteEntry {
        RouteEntry {
            route: path.into(),
            visited,
            status,
            unvisited_reason: why.map(str::to_string),
            ..Default::default()
        }
    }

    fn control(
        route: &str,
        role: &str,
        label: &str,
        status: ControlStatus,
        outcomes: Vec<Outcome>,
    ) -> Control {
        Control {
            key: format!("{route}|{role}|text={}", label.to_lowercase()),
            route: route.into(),
            routes: vec![route.into()],
            role: role.into(),
            label: label.into(),
            locator: format!("text={}", label.to_lowercase()),
            selector: format!("#{}", label.to_lowercase()),
            count: 1,
            status,
            outcomes,
            ..Default::default()
        }
    }

    fn inv(
        generated_at: &str,
        role: Option<&str>,
        routes: Vec<RouteEntry>,
        controls: Vec<Control>,
    ) -> Inventory {
        let visited = routes.iter().filter(|r| r.visited).count() as u32;
        let exercised = controls.iter().filter(|c| c.status.is_exercised()).count() as u32;
        Inventory {
            schema: crate::inventory::INVENTORY_SCHEMA.into(),
            identity_version: IDENTITY_VERSION,
            project: "acme".into(),
            generated_at: generated_at.into(),
            target_url: "http://127.0.0.1:3000".into(),
            role: role.map(str::to_string),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: routes.len() as u32,
                routes_visited: visited,
                controls_total: controls.len() as u32,
                controls_exercised: exercised,
                controls_exercisable: controls.len() as u32,
                ..Default::default()
            },
            routes,
            controls,
            ..Default::default()
        }
    }

    #[test]
    fn policy_parses_aliases_hyphens_underscores_and_rejects_unknown() {
        let p = FailOnPolicy::parse(
            "dead, NOW_BROKEN, no-effect, rewired, removed, route-removed, endpoint_removed, ACCESS-GAINED, access_lost",
        )
        .unwrap();
        assert!(p.enables(FailOnRule::Dead));
        assert!(p.enables(FailOnRule::Broken));
        assert!(p.enables(FailOnRule::NoEffect));
        assert!(p.enables(FailOnRule::Rewired));
        assert!(p.enables(FailOnRule::Removed));
        assert!(p.enables(FailOnRule::RouteRemoved));
        assert!(p.enables(FailOnRule::EndpointRemoved));
        assert!(p.enables(FailOnRule::AccessGained));
        assert!(p.enables(FailOnRule::AccessLost));

        let any = FailOnPolicy::parse("any").unwrap();
        assert!(any.enables(FailOnRule::Dead));
        assert!(any.enables(FailOnRule::Broken));
        assert!(any.enables(FailOnRule::Removed));
        assert!(any.enables(FailOnRule::Rewired));
        assert!(any.enables(FailOnRule::RouteRemoved));
        assert!(any.enables(FailOnRule::EndpointRemoved));
        assert!(any.enables(FailOnRule::AccessGained));
        assert!(any.enables(FailOnRule::AccessLost));
        // `no_effect` is review-level, not in `any`.
        assert!(!any.enables(FailOnRule::NoEffect));

        let err = FailOnPolicy::parse("dead,bogus_token").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bogus_token"), "{msg}");
        assert!(msg.contains("access-gained"), "{msg}");

        assert!(FailOnPolicy::parse(" , ").is_err());
    }

    #[test]
    fn evaluate_changes_gate_triggers_on_control_and_rbac_regressions() {
        let old_member = inv(
            "2026-11-19T10:00:00Z",
            Some("member"),
            vec![
                route("/", true, Some(200), None),
                route("/admin", true, Some(403), None),
            ],
            vec![control(
                "/",
                "button",
                "Export",
                ControlStatus::Ok,
                vec![Outcome::Download],
            )],
        );
        let new_member = inv(
            "2026-11-20T10:00:00Z",
            Some("member"),
            vec![
                route("/", true, Some(200), None),
                route("/admin", true, Some(200), None),
            ],
            vec![control(
                "/",
                "button",
                "Export",
                ControlStatus::Dead,
                vec![],
            )],
        );

        let cs = crate::inventory::diff(Some(&old_member), &new_member);
        let mut old_roles = BTreeMap::new();
        old_roles.insert("member".into(), old_member);
        let mut new_roles = BTreeMap::new();
        new_roles.insert("member".into(), new_member.clone());
        let rd = diff_role_access(&old_roles, &new_roles);

        // Gate watching only `broken` passes:
        let broken_only = FailOnPolicy::parse("broken").unwrap();
        let res_pass = evaluate_changes_gate(&broken_only, &[("member", &cs)], Some(&rd));
        assert!(res_pass.passed);
        assert!(res_pass.violations.is_empty());

        // Gate watching `access-gained,dead` fails with both violations:
        let strict = FailOnPolicy::parse("access-gained,dead").unwrap();
        let res_fail = evaluate_changes_gate(&strict, &[("member", &cs)], Some(&rd));
        assert!(!res_fail.passed);
        assert_eq!(
            res_fail.triggered_rules,
            vec![FailOnRule::Dead, FailOnRule::AccessGained]
        );
        assert_eq!(res_fail.violations.len(), 2);
        assert_eq!(res_fail.violations[0].rule, FailOnRule::AccessGained);
        assert_eq!(res_fail.violations[1].rule, FailOnRule::Dead);

        // Render Markdown PR comment
        let md =
            render_changes_markdown(&[("member", &cs, &new_member)], Some(&rd), Some(&res_fail));
        assert!(md.contains("## BrokenApp Behavioral Diff"), "{md}");
        assert!(md.contains("**CI Gate: `FAIL`**"), "{md}");
        assert!(md.contains("### ROLE-ACCESS Changes"), "{md}");
        assert!(md.contains("RBAC Escalation (`ACCESS GAINED`)"), "{md}");
        assert!(
            md.contains("ACCESS GAINED member /admin (was forbidden)"),
            "{md}"
        );
        assert!(md.contains("### Control Changes"), "{md}");
        assert!(md.contains("NOW DEAD / button \"Export\""), "{md}");
        assert!(md.contains("**Coverage:**"), "{md}");
    }

    #[test]
    fn load_role_access_diff_for_project_reads_nth_previous_per_role() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(CONFIG_FILE),
            r#"
[project]
name = "acme"
url = "http://127.0.0.1:3000"

[[roles]]
name = "member"
method = "session"
"#,
        )
        .unwrap();

        let ctx = load_ctx(&state).unwrap();

        let anon_v1 = inv(
            "2026-11-18T10:00:00Z",
            None,
            vec![
                route("/", true, Some(200), None),
                route("/admin", false, None, Some("redirects to login")),
            ],
            vec![],
        );
        let anon_v2 = inv(
            "2026-11-19T10:00:00Z",
            None,
            vec![
                route("/", true, Some(200), None),
                route("/admin", false, None, Some("redirects to login")),
            ],
            vec![],
        );
        let member_v1 = inv(
            "2026-11-18T10:00:00Z",
            Some("member"),
            vec![
                route("/", true, Some(200), None),
                route("/admin", true, Some(403), None),
            ],
            vec![],
        );
        let member_v2 = inv(
            "2026-11-19T10:00:00Z",
            Some("member"),
            vec![
                route("/", true, Some(200), None),
                route("/admin", true, Some(200), None),
            ],
            vec![],
        );

        let anon_hist = ctx.role_paths("anonymous").history_dir;
        crate::inventory::save(&anon_v1, &anon_hist.join("20261118T100000Z.inventory.json"))
            .unwrap();
        crate::inventory::save(&anon_v2, &anon_hist.join("20261119T100000Z.inventory.json"))
            .unwrap();
        crate::inventory::save(&anon_v2, &anon_hist.join(LATEST_INVENTORY)).unwrap();

        let mem_hist = ctx.role_paths("member").history_dir;
        crate::inventory::save(
            &member_v1,
            &mem_hist.join("20261118T100000Z.inventory.json"),
        )
        .unwrap();
        crate::inventory::save(
            &member_v2,
            &mem_hist.join("20261119T100000Z.inventory.json"),
        )
        .unwrap();
        crate::inventory::save(&member_v2, &mem_hist.join(LATEST_INVENTORY)).unwrap();

        let diff = load_role_access_diff_for_project(&ctx, 1).unwrap().unwrap();
        assert_eq!(diff.roles_compared, vec!["anonymous", "member"]);
        assert_eq!(diff.count(RoleAccessChangeKind::AccessGained), 1);
        assert_eq!(
            diff.changes[0].line,
            "ACCESS GAINED member /admin (was forbidden)"
        );

        // `since = 2` has no 2nd-previous snapshot -> None.
        assert!(
            load_role_access_diff_for_project(&ctx, 2)
                .unwrap()
                .is_none()
        );
        // `since = 0` is an error.
        assert!(load_role_access_diff_for_project(&ctx, 0).is_err());
    }

    #[test]
    fn evaluate_changes_gate_covers_all_regression_rules_and_any() {
        use crate::inventory::Change;

        let cs = ChangeSet {
            from: Some("t1".into()),
            to: "t2".into(),
            changes: vec![
                Change {
                    kind: "now_no_effect".into(),
                    key: "k1".into(),
                    route: "/".into(),
                    label: "Refresh".into(),
                    line: "NOW NO EFFECT / button \"Refresh\"".into(),
                    routes: vec![],
                },
                Change {
                    kind: "rewired".into(),
                    key: "k2".into(),
                    route: "/".into(),
                    label: "Go".into(),
                    line: "REWIRED / link \"Go\"".into(),
                    routes: vec![],
                },
                Change {
                    kind: "removed".into(),
                    key: "k3".into(),
                    route: "/".into(),
                    label: "Old".into(),
                    line: "REMOVED / button \"Old\"".into(),
                    routes: vec![],
                },
                Change {
                    kind: "route_removed".into(),
                    key: "/legacy".into(),
                    route: "/legacy".into(),
                    label: String::new(),
                    line: "ROUTE REMOVED /legacy".into(),
                    routes: vec![],
                },
                Change {
                    kind: "endpoint_removed".into(),
                    key: "GET /api/old".into(),
                    route: String::new(),
                    label: String::new(),
                    line: "ENDPOINT REMOVED GET /api/old".into(),
                    routes: vec![],
                },
            ],
            ..Default::default()
        };

        // `any` catches rewired, removed, route_removed, endpoint_removed, but NOT no_effect!
        let any = FailOnPolicy::parse("any").unwrap();
        let res = evaluate_changes_gate(&any, &[("anonymous", &cs)], None);
        assert!(!res.passed);
        assert_eq!(res.violations.len(), 4);
        assert!(!res.triggered_rules.contains(&FailOnRule::NoEffect));
        assert!(res.triggered_rules.contains(&FailOnRule::Rewired));
        assert!(res.triggered_rules.contains(&FailOnRule::Removed));
        assert!(res.triggered_rules.contains(&FailOnRule::RouteRemoved));
        assert!(res.triggered_rules.contains(&FailOnRule::EndpointRemoved));

        // Explicit `no_effect` catches it:
        let ne = FailOnPolicy::parse("now-no-effect").unwrap();
        let res_ne = evaluate_changes_gate(&ne, &[("anonymous", &cs)], None);
        assert!(!res_ne.passed);
        assert_eq!(res_ne.triggered_rules, vec![FailOnRule::NoEffect]);
        assert_eq!(res_ne.violations.len(), 1);
    }

    #[test]
    fn evaluate_changes_gate_is_inconclusive_when_baseline_missing() {
        let cur = inv(
            "2026-11-20T10:00:00Z",
            None,
            vec![route("/", true, Some(200), None)],
            vec![control(
                "/",
                "button",
                "Save",
                ControlStatus::Ok,
                vec![Outcome::DomChange {
                    kind: "toast".into(),
                }],
            )],
        );
        let cs = crate::inventory::diff(None, &cur);
        assert!(cs.from.is_none());

        let policy = FailOnPolicy::parse("dead,broken").unwrap();
        let res = evaluate_changes_gate(&policy, &[("anonymous", &cs)], None);
        assert!(!res.passed);
        assert!(res.inconclusive);
        assert!(res.violations.is_empty());
        assert!(res.triggered_rules.is_empty());
        assert_eq!(
            res.inconclusive_reasons,
            vec!["anonymous: no earlier baseline map to compare against"]
        );

        let val = serde_json::to_value(&res).unwrap();
        assert_eq!(val["passed"], false);
        assert_eq!(val["inconclusive"], true);
        assert_eq!(val["inconclusive_reasons"].as_array().unwrap().len(), 1);

        let md = render_changes_markdown(&[("anonymous", &cs, &cur)], None, Some(&res));
        assert!(md.contains("**CI Gate: `INCONCLUSIVE`**"), "{md}");
        assert!(md.contains("no earlier baseline map"), "{md}");
        assert!(!md.contains("**CI Gate:** `PASS`"), "{md}");
    }

    #[test]
    fn evaluate_changes_gate_is_inconclusive_when_rebaselined() {
        let mut old = inv(
            "2026-11-19T10:00:00Z",
            Some("member"),
            vec![route("/", true, Some(200), None)],
            vec![],
        );
        old.identity_version = 1;
        let cur = inv(
            "2026-11-20T10:00:00Z",
            Some("member"),
            vec![route("/", true, Some(200), None)],
            vec![],
        );
        let cs = crate::inventory::diff(Some(&old), &cur);
        assert!(cs.summary.contains_key("rebaselined"));

        let policy = FailOnPolicy::parse("any").unwrap();
        let res = evaluate_changes_gate(&policy, &[("member", &cs)], None);
        assert!(!res.passed);
        assert!(res.inconclusive);
        assert!(res.violations.is_empty());
        assert_eq!(
            res.inconclusive_reasons,
            vec!["member: control identity scheme was rebaselined; baseline is not comparable"]
        );

        let md = render_changes_markdown(&[("member", &cs, &cur)], None, Some(&res));
        assert!(md.contains("**CI Gate: `INCONCLUSIVE`**"), "{md}");
        assert!(md.contains("rebaselined"), "{md}");
    }

    #[test]
    fn evaluate_changes_gate_flags_missing_baseline_per_role_and_combines_with_violations() {
        let base_member = inv(
            "2026-11-19T10:00:00Z",
            Some("member"),
            vec![route("/", true, Some(200), None)],
            vec![control(
                "/",
                "button",
                "Export",
                ControlStatus::Ok,
                vec![Outcome::Download],
            )],
        );
        let same_member = inv(
            "2026-11-20T10:00:00Z",
            Some("member"),
            vec![route("/", true, Some(200), None)],
            vec![control(
                "/",
                "button",
                "Export",
                ControlStatus::Ok,
                vec![Outcome::Download],
            )],
        );
        let dead_member = inv(
            "2026-11-20T10:00:00Z",
            Some("member"),
            vec![route("/", true, Some(200), None)],
            vec![control(
                "/",
                "button",
                "Export",
                ControlStatus::Dead,
                vec![],
            )],
        );
        let first_admin = inv(
            "2026-11-20T10:00:00Z",
            Some("admin"),
            vec![route("/admin", true, Some(200), None)],
            vec![],
        );

        let cs_member_clean = crate::inventory::diff(Some(&base_member), &same_member);
        let cs_member_dead = crate::inventory::diff(Some(&base_member), &dead_member);
        let cs_admin_initial = crate::inventory::diff(None, &first_admin);

        let policy = FailOnPolicy::parse("dead").unwrap();

        // Comparable role passes cleanly; JSON omits inconclusive fields.
        let clean = evaluate_changes_gate(&policy, &[("member", &cs_member_clean)], None);
        assert!(clean.passed);
        assert!(!clean.inconclusive);
        assert!(clean.inconclusive_reasons.is_empty());
        let clean_json = serde_json::to_value(&clean).unwrap();
        assert!(clean_json.get("inconclusive").is_none());
        assert!(clean_json.get("inconclusive_reasons").is_none());

        // One clean role + one brand-new role without a baseline -> inconclusive fail.
        let mixed = evaluate_changes_gate(
            &policy,
            &[("member", &cs_member_clean), ("admin", &cs_admin_initial)],
            None,
        );
        assert!(!mixed.passed);
        assert!(mixed.inconclusive);
        assert!(mixed.violations.is_empty());
        assert_eq!(
            mixed.inconclusive_reasons,
            vec!["admin: no earlier baseline map to compare against"]
        );

        // Violation on one role + missing baseline on another -> FAIL + inconclusive note.
        let both = evaluate_changes_gate(
            &policy,
            &[("member", &cs_member_dead), ("admin", &cs_admin_initial)],
            None,
        );
        assert!(!both.passed);
        assert!(both.inconclusive);
        assert_eq!(both.violations.len(), 1);
        assert_eq!(both.triggered_rules, vec![FailOnRule::Dead]);
        let md = render_changes_markdown(
            &[
                ("member", &cs_member_dead, &dead_member),
                ("admin", &cs_admin_initial, &first_admin),
            ],
            None,
            Some(&both),
        );
        assert!(md.contains("**CI Gate: `FAIL`**"), "{md}");
        assert!(md.contains("**Inconclusive baseline:**"), "{md}");
        assert!(
            md.contains("admin: no earlier baseline map to compare against"),
            "{md}"
        );
    }

    #[test]
    fn evaluate_changes_gate_with_health_fails_on_missing_role_or_zero_route_collapse() {
        let base_owner = inv(
            "2026-11-19T10:00:00Z",
            Some("owner"),
            vec![route("/", true, Some(200), None)],
            vec![],
        );
        let cur_owner = inv(
            "2026-11-20T10:00:00Z",
            Some("owner"),
            vec![route("/", true, Some(200), None)],
            vec![],
        );
        let cs_owner = crate::inventory::diff(Some(&base_owner), &cur_owner);
        let policy = FailOnPolicy::parse("dead,broken,access-gained").unwrap();

        let health = GateRoleHealth {
            missing_roles: vec!["admin".into()],
            collapsed_roles: vec![("csm".into(), 4)],
            zero_coverage_roles: Vec::new(),
        };
        let res =
            evaluate_changes_gate_with_health(&policy, &[("owner", &cs_owner)], None, &health);
        assert!(!res.passed);
        assert!(res.inconclusive);
        assert!(res.violations.is_empty());
        assert_eq!(
            res.inconclusive_reasons,
            vec![
                "admin: configured role has no saved map (login or scan failed)",
                "csm: latest map visited 0 routes (baseline had 4); crawl likely timed out",
            ]
        );

        let md = render_changes_markdown(&[("owner", &cs_owner, &cur_owner)], None, Some(&res));
        assert!(md.contains("**CI Gate: `INCONCLUSIVE`**"), "{md}");
        assert!(
            md.contains("admin: configured role has no saved map"),
            "{md}"
        );
        assert!(
            md.contains("csm: latest map visited 0 routes (baseline had 4)"),
            "{md}"
        );
        assert!(!md.contains("**CI Gate:** `PASS`"), "{md}");
    }

    #[test]
    fn changes_gate_and_markdown_surface_endpoint_access_gained_and_lost() {
        use crate::inventory::EndpointEntry;

        let mut old_member = inv(
            "2026-11-25T10:00:00Z",
            Some("member"),
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
        );
        old_member.endpoints = vec![EndpointEntry {
            endpoint: "GET /api/admin/secrets".into(),
            controls: vec![],
            on_load: vec!["/dashboard".into()],
            statuses: vec![403],
            write: false,
        }];
        let mut new_member = inv(
            "2026-11-26T10:00:00Z",
            Some("member"),
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
        );
        new_member.endpoints = vec![EndpointEntry {
            endpoint: "GET /api/admin/secrets".into(),
            controls: vec![],
            on_load: vec!["/dashboard".into()],
            statuses: vec![200],
            write: false,
        }];

        let cs = crate::inventory::diff(Some(&old_member), &new_member);
        let rd = diff_role_access(
            &BTreeMap::from([("member".into(), old_member)]),
            &BTreeMap::from([("member".into(), new_member.clone())]),
        );
        let policy = FailOnPolicy::parse("access-gained").unwrap();
        let gate = evaluate_changes_gate(&policy, &[("member", &cs)], Some(&rd));
        assert!(!gate.passed);
        assert_eq!(gate.triggered_rules, vec![FailOnRule::AccessGained]);
        assert_eq!(gate.violations.len(), 1);
        assert_eq!(gate.violations[0].kind, "endpoint_access_gained");
        assert_eq!(gate.violations[0].route, "GET /api/admin/secrets");

        let md = render_changes_markdown(&[("member", &cs, &new_member)], Some(&rd), Some(&gate));
        assert!(md.contains("**CI Gate: `FAIL`**"), "{md}");
        assert!(md.contains("#### Endpoint Access Changes"), "{md}");
        assert!(md.contains("`GET /api/admin/secrets`"), "{md}");
        assert!(md.contains("1 endpoint newly accessible"), "{md}");
    }

    #[test]
    fn evaluate_changes_gate_is_inconclusive_when_either_map_visited_zero_routes() {
        let empty_a = inv("2026-11-25T10:00:00Z", None, vec![], vec![]);
        let empty_b = inv("2026-11-26T10:00:00Z", None, vec![], vec![]);
        let nonempty = inv(
            "2026-11-26T11:00:00Z",
            None,
            vec![route("/", true, Some(200), None)],
            vec![],
        );
        let policy = FailOnPolicy::parse("dead,broken").unwrap();

        // 0 -> 0 (e.g., Chrome failed to open a page on both scans) must be INCONCLUSIVE.
        let cs_zero_zero = crate::inventory::diff(Some(&empty_a), &empty_b);
        let health_zero_zero = GateRoleHealth {
            zero_coverage_roles: vec![("anonymous".into(), 0, 0)],
            ..Default::default()
        };
        let res_zz = evaluate_changes_gate_with_health(
            &policy,
            &[("anonymous", &cs_zero_zero)],
            None,
            &health_zero_zero,
        );
        assert!(!res_zz.passed);
        assert!(res_zz.inconclusive);
        assert!(
            res_zz
                .inconclusive_reasons
                .iter()
                .any(|r| r.contains("both baseline and latest maps visited 0 routes")),
            "{:?}",
            res_zz.inconclusive_reasons
        );

        // 0 -> 1 (empty baseline) must be INCONCLUSIVE.
        let cs_zero_one = crate::inventory::diff(Some(&empty_a), &nonempty);
        let health_zero_one = GateRoleHealth {
            zero_coverage_roles: vec![("anonymous".into(), 0, 1)],
            ..Default::default()
        };
        let res_zo = evaluate_changes_gate_with_health(
            &policy,
            &[("anonymous", &cs_zero_one)],
            None,
            &health_zero_one,
        );
        assert!(!res_zo.passed);
        assert!(res_zo.inconclusive);
        assert!(
            res_zo
                .inconclusive_reasons
                .iter()
                .any(|r| r.contains("baseline map visited 0 routes")),
            "{:?}",
            res_zo.inconclusive_reasons
        );

        // 1 -> 0 (collapsed current) must be INCONCLUSIVE.
        let cs_one_zero = crate::inventory::diff(Some(&nonempty), &empty_b);
        let health_one_zero = GateRoleHealth {
            zero_coverage_roles: vec![("anonymous".into(), 1, 0)],
            ..Default::default()
        };
        let res_oz = evaluate_changes_gate_with_health(
            &policy,
            &[("anonymous", &cs_one_zero)],
            None,
            &health_one_zero,
        );
        assert!(!res_oz.passed);
        assert!(res_oz.inconclusive);
        assert!(
            res_oz
                .inconclusive_reasons
                .iter()
                .any(|r| r.contains("latest map visited 0 routes")),
            "{:?}",
            res_oz.inconclusive_reasons
        );
    }
}
