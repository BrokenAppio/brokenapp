//! Read commands over the latest UI map: `ui`, `dead`, `journey`, `changes`.
//!
//! All of them read `.brokenapp/history/*.inventory.json` (a role's map:
//! `history/roles/<role>/`) and never touch the running app. `--role <name>`
//! picks a login role's map (default: the anonymous map); `--role all` reads
//! every role's map and labels each row with its `login_role`. Output goes
//! to stdout; `--json` prints one JSON document.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use serde_json::json;

use super::project::{self, ANONYMOUS_ROLE, LATEST_INVENTORY, ProjectCtx, ProjectTarget};
use super::roles::CONTROL_KINDS;
use crate::inventory::journey::{self, Goal};
use crate::inventory::query::ControlFilter;
use crate::inventory::{self, ChangeSet, Control, ControlStatus, Inventory};
use crate::inventory::{evidence, render};

#[derive(Debug, Args)]
pub struct UiArgs {
    /// Filter by route (exact, template, or path prefix: `/admin` includes
    /// `/admin/users`; `*` for global controls).
    #[arg(long)]
    pub route: Option<String>,
    /// Match only the route/template, without descendant routes. Concrete
    /// records and query states still require observed variants.
    #[arg(long, requires = "route")]
    pub exact_route: bool,
    /// Omit shared shell controls and nav/header/footer/aside landmarks.
    #[arg(long)]
    pub exclude_shell: bool,
    /// Case-insensitive text match on label (including grouped members'
    /// labels), locator, or endpoint.
    #[arg(long)]
    pub text: Option<String>,
    /// Filter by status (ok|dead|no_effect|broken|disabled|external|skipped|not_exercised).
    #[arg(long)]
    pub status: Option<String>,
    /// Controls that call this endpoint (e.g. "POST /api/orders" or "/api/orders").
    #[arg(long)]
    pub calls: Option<String>,
    /// Filter by control kind (button|link|input|select|checkbox|radio|form|tab|other).
    #[arg(long)]
    pub kind: Option<String>,
    /// Login role whose map to read (default: anonymous); `all` merges every
    /// role's map with a `login_role` column. (A control kind here still
    /// filters by kind, as before roles existed.)
    #[arg(long)]
    pub role: Option<String>,
    /// Read a specific inventory JSON file directly instead of resolving a project map.
    #[arg(long, value_name = "PATH", conflicts_with = "role")]
    pub inventory: Option<PathBuf>,
    /// Output format: table|tsv|md|json.
    #[arg(long, default_value = "table")]
    pub format: String,
    #[arg(long)]
    pub json: bool,
    /// Compact JSON: essential control evidence and one coverage summary per
    /// map. Implies JSON; full `--json` output remains available.
    #[arg(long)]
    pub compact: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Args)]
pub struct DeadArgs {
    /// Include not-exercised controls (coverage gaps) in the list.
    #[arg(long)]
    pub include_unexercised: bool,
    /// Login role whose map to read (default: anonymous); `all` = every role.
    #[arg(long)]
    pub role: Option<String>,
    /// Read a specific inventory JSON file directly instead of resolving a project map.
    #[arg(long, value_name = "PATH", conflicts_with = "role")]
    pub inventory: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Args)]
pub struct JourneyArgs {
    /// Goal: a route (`/checkout`), an endpoint (`POST /api/orders`), or `label:Pay`.
    pub to: String,
    /// Start route (default: entry `/`).
    #[arg(long)]
    pub from: Option<String>,
    /// Max hops.
    #[arg(long, default_value_t = 15)]
    pub max_hops: usize,
    /// Login role whose map to read (default: anonymous); `all` = every role.
    #[arg(long)]
    pub role: Option<String>,
    /// Read a specific inventory JSON file directly instead of resolving a project map.
    #[arg(long, value_name = "PATH", conflicts_with = "role")]
    pub inventory: Option<PathBuf>,
    /// Output format: text|md|markdown|json.
    #[arg(long, default_value = "text")]
    pub format: String,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

#[derive(Debug, Args)]
pub struct ChangesArgs {
    /// Compare against the Nth previous map (default 1 = the one before latest).
    #[arg(long, default_value_t = 1)]
    pub since: usize,
    /// Compare two inventory files explicitly.
    #[arg(long, num_args = 2, value_names = ["OLD", "NEW"])]
    pub between: Option<Vec<std::path::PathBuf>>,
    /// Login role whose map history to read (default: anonymous); `all` = every role.
    #[arg(long)]
    pub role: Option<String>,
    /// Output format: text|md|markdown|json.
    #[arg(long, default_value = "text")]
    pub format: String,
    /// Exit 1 when any comma-separated regression rule triggers
    /// (dead,broken,no-effect,rewired,removed,route-removed,endpoint-removed,access-gained,access-lost,any).
    #[arg(long)]
    pub fail_on: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub target: ProjectTarget,
}

/// `--role` selection for the read commands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RoleSel {
    One(String),
    All,
}

fn role_sel(role: Option<&str>) -> RoleSel {
    match role.map(str::trim).filter(|r| !r.is_empty()) {
        None => RoleSel::One(ANONYMOUS_ROLE.to_string()),
        Some(r) if r.eq_ignore_ascii_case("all") => RoleSel::All,
        Some(r) => RoleSel::One(r.to_string()),
    }
}

/// Latest maps of the selected roles, in role order.
fn load_maps(ctx: &ProjectCtx, sel: &RoleSel) -> Result<Vec<(String, Inventory)>> {
    let mut maps = load_recorded_maps(ctx, sel)?;
    for (role, inv) in &mut maps {
        let paths = ctx.role_paths(role);
        let inv_path = paths
            .readable_inventory_path()
            .unwrap_or_else(|| paths.latest_inventory_path());
        inv.evidence_annotations = evidence::load_annotations(&inv_path, &paths.map_dir, inv)?;
        if let Some(reviews) = evidence::load_source_reviews(&inv_path, &paths.map_dir, inv)? {
            evidence::apply_source_reviews(inv, reviews)?;
        }
    }
    Ok(maps)
}

/// History compares recorded maps. A later attribution review is not an app change.
fn load_recorded_maps(ctx: &ProjectCtx, sel: &RoleSel) -> Result<Vec<(String, Inventory)>> {
    match sel {
        RoleSel::One(role) => {
            if role != ANONYMOUS_ROLE
                && !ctx.config.roles.iter().any(|r| &r.name == role)
                && !ctx.role_paths(role).has_saved_inventory()
            {
                bail!(
                    "unknown role '{role}' (roles: {})",
                    ctx.role_names().join(", ")
                );
            }
            let paths = ctx.role_paths(role);
            if role == ANONYMOUS_ROLE && !paths.has_saved_inventory() {
                let available: Vec<String> = ctx
                    .role_names()
                    .into_iter()
                    .filter(|name| {
                        name != ANONYMOUS_ROLE && ctx.role_paths(name).has_saved_inventory()
                    })
                    .collect();
                if let Some(first) = available.first() {
                    bail!(
                        "no anonymous UI map for project '{}'. Saved role maps: {}. Select one with `--role {first}` or read them all with `--role all`.",
                        ctx.name(),
                        available.join(", ")
                    );
                }
            }
            let inv = paths.load_latest(ctx.name())?;
            Ok(vec![(role.clone(), inv)])
        }
        RoleSel::All => {
            let mut out = Vec::new();
            for role in ctx.role_names() {
                let paths = ctx.role_paths(&role);
                if paths.has_saved_inventory() {
                    let inv = paths.load_latest(ctx.name())?;
                    out.push((role.clone(), inv));
                }
            }
            if out.is_empty() {
                bail!(
                    "no UI map yet for project '{}'. Run `brokenapp map` first.",
                    ctx.name()
                );
            }
            Ok(out)
        }
    }
}

/// Split `ui --role`: a control kind (the flag's meaning before roles
/// existed; kinds are reserved role names) or a login role.
fn ui_selection(args: &UiArgs) -> (Option<String>, RoleSel) {
    match args.role.as_deref().map(str::trim) {
        Some(r) if CONTROL_KINDS.contains(&r.to_ascii_lowercase().as_str()) => {
            eprintln!(
                "note: `--role {r}` filters by control kind; use `--kind {r}` (--role selects a login role)"
            );
            (
                args.kind.clone().or_else(|| Some(r.to_string())),
                role_sel(None),
            )
        }
        other => (args.kind.clone(), role_sel(other)),
    }
}

fn load_inventory_file(path: &Path) -> Result<(String, Inventory)> {
    let inv = inventory::load(path)?;
    let role = inv
        .role
        .clone()
        .unwrap_or_else(|| ANONYMOUS_ROLE.to_string());
    Ok((role, inv))
}

fn journey_format(args: &JourneyArgs) -> Result<&str> {
    let fmt = if args.json {
        "json"
    } else {
        args.format.as_str()
    };
    if !matches!(fmt, "text" | "md" | "markdown" | "json") {
        bail!("unknown format '{fmt}' (expected text|md|markdown|json)");
    }
    Ok(fmt)
}

pub async fn run_ui(args: UiArgs) -> Result<i32> {
    if let Some(path) = args.inventory.as_deref() {
        let map = load_inventory_file(path)?;
        print!(
            "{}",
            ui_output_roles(&[map], &args, args.kind.as_deref(), false)?
        );
        return Ok(0);
    }
    let ctx = project::resolve(&args.target)?;
    let (kind, sel) = ui_selection(&args);
    let maps = load_maps(&ctx, &sel)?;
    print!(
        "{}",
        ui_output_roles(&maps, &args, kind.as_deref(), sel == RoleSel::All)?
    );
    Ok(0)
}

pub async fn run_dead(args: DeadArgs) -> Result<i32> {
    if let Some(path) = args.inventory.as_deref() {
        let (_, inv) = load_inventory_file(path)?;
        print!(
            "{}",
            dead_output(&inv, args.include_unexercised, args.json)?
        );
        return Ok(0);
    }
    let ctx = project::resolve(&args.target)?;
    let sel = role_sel(args.role.as_deref());
    let maps = load_maps(&ctx, &sel)?;
    if sel != RoleSel::All {
        print!(
            "{}",
            dead_output(&maps[0].1, args.include_unexercised, args.json)?
        );
        return Ok(0);
    }
    if args.json {
        let mut roles = Vec::new();
        for (role, inv) in &maps {
            let mut doc: serde_json::Value =
                serde_json::from_str(&dead_output(inv, args.include_unexercised, true)?)
                    .context("dead output")?;
            doc["login_role"] = json!(role);
            roles.push(doc);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "roles": roles }))
                .context("serialize dead UI")?
        );
        return Ok(0);
    }
    for (role, inv) in &maps {
        println!("== {role} ==");
        print!("{}", dead_output(inv, args.include_unexercised, false)?);
        println!();
    }
    Ok(0)
}

/// Configured roles expected to have a saved map, respecting
/// `[auth] include_anonymous`.
fn expected_roles(ctx: &ProjectCtx) -> Vec<String> {
    ctx.role_names()
        .into_iter()
        .filter(|role| role != ANONYMOUS_ROLE || ctx.config.auth.include_anonymous())
        .collect()
}

/// Configured roles expected for `--role all` that have no saved map.
fn missing_configured_roles(ctx: &ProjectCtx, loaded: &[(String, Inventory)]) -> Vec<String> {
    let loaded_names: std::collections::BTreeSet<&str> =
        loaded.iter().map(|(role, _)| role.as_str()).collect();
    expected_roles(ctx)
        .into_iter()
        .filter(|role| !loaded_names.contains(role.as_str()))
        .collect()
}

/// Default `--from` route for a configured authenticated role when `/` (and
/// `/#/`) was not visited in `inv`: prefer the role's configured `check` path
/// when that route was visited.
fn role_default_from(ctx: &ProjectCtx, role: &str, inv: &Inventory) -> Option<String> {
    let root_visited = inv
        .routes
        .iter()
        .any(|r| r.visited && matches!(r.route.as_str(), "/" | "/#/"));
    if root_visited {
        return None;
    }
    let check = super::roles::find_role(&ctx.config, role)?
        .check
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let candidate = crate::inventory::identity::route_template(check);
    inv.routes
        .iter()
        .find(|r| r.visited && r.route == candidate)
        .map(|r| r.route.clone())
}

/// Exit code 1 when the goal matches nothing in the map(s).
pub async fn run_journey(args: JourneyArgs) -> Result<i32> {
    let fmt = journey_format(&args)?;
    let as_json = fmt == "json";
    if let Some(path) = args.inventory.as_deref() {
        let (_, inv) = load_inventory_file(path)?;
        let (out, found) = journey_output(&inv, &args, None)?;
        print!("{out}");
        return Ok(if found { 0 } else { 1 });
    }
    let ctx = project::resolve(&args.target)?;
    let sel = role_sel(args.role.as_deref());
    let maps = load_maps(&ctx, &sel)?;
    if sel != RoleSel::All {
        let (role, inv) = &maps[0];
        let default_from = if args.from.is_none() {
            role_default_from(&ctx, role, inv)
        } else {
            None
        };
        let (out, found) =
            journey_output_with_default_from(inv, &args, Some(&ctx.root), default_from.as_deref())?;
        print!("{out}");
        return Ok(if found { 0 } else { 1 });
    }
    let mut any = false;
    let mut docs = Vec::new();
    for (role, inv) in &maps {
        let default_from = if args.from.is_none() {
            role_default_from(&ctx, role, inv)
        } else {
            None
        };
        let (out, found) =
            journey_output_with_default_from(inv, &args, Some(&ctx.root), default_from.as_deref())?;
        any |= found;
        if as_json {
            let mut doc: serde_json::Value =
                serde_json::from_str(&out).context("journey output")?;
            doc["login_role"] = json!(role);
            docs.push(doc);
        } else if matches!(fmt, "md" | "markdown") {
            println!("# Role: `{role}`\n");
            print!("{out}");
            println!();
        } else {
            println!("== {role} ==");
            print!("{out}");
            println!();
        }
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "roles": docs })).context("serialize journey")?
        );
    }
    Ok(if any { 0 } else { 1 })
}

pub async fn run_changes(args: ChangesArgs) -> Result<i32> {
    use super::changes_gate::{
        FailOnPolicy, GateRoleHealth, evaluate_changes_gate_with_health,
        load_role_access_diff_for_project, render_changes_markdown,
    };
    use crate::inventory::parity::{RoleAccessDiff, diff_role_access};
    use std::collections::BTreeMap;

    let policy = args
        .fail_on
        .as_deref()
        .map(FailOnPolicy::parse)
        .transpose()?;
    let fmt = if args.json {
        "json"
    } else {
        args.format.as_str()
    };
    if !matches!(fmt, "text" | "md" | "markdown" | "json") {
        bail!("unknown format '{fmt}' (expected text|md|markdown|json)");
    }

    if let Some(files) = args.between.as_deref() {
        let [old, new] = files else {
            bail!("--between takes exactly two inventory files");
        };
        let (prev, cur) = (inventory::load(old)?, inventory::load(new)?);
        let prev_visited = prev.coverage.routes_visited;
        let changes = inventory::diff(Some(&prev), &cur);
        let role_name = args
            .role
            .as_deref()
            .filter(|r| !r.trim().is_empty())
            .or_else(|| cur.role.as_deref().filter(|r| !r.trim().is_empty()))
            .or_else(|| prev.role.as_deref().filter(|r| !r.trim().is_empty()))
            .unwrap_or(ANONYMOUS_ROLE)
            .to_string();
        let role_name = role_name.as_str();
        let mut old_map = BTreeMap::new();
        let mut new_map = BTreeMap::new();
        old_map.insert(role_name.to_string(), prev);
        new_map.insert(role_name.to_string(), cur.clone());
        let role_diff = diff_role_access(&old_map, &new_map);
        let mut health = GateRoleHealth::default();
        if prev_visited == 0 || cur.coverage.routes_visited == 0 {
            health.zero_coverage_roles.push((
                role_name.to_string(),
                prev_visited,
                cur.coverage.routes_visited,
            ));
        }
        let gate = policy.as_ref().map(|p| {
            evaluate_changes_gate_with_health(
                p,
                &[(role_name, &changes)],
                Some(&role_diff),
                &health,
            )
        });

        match fmt {
            "json" => {
                let mut doc = serde_json::to_value(&changes).context("serialize changes")?;
                if !role_diff.changes.is_empty() {
                    doc["role_access"] =
                        serde_json::to_value(&role_diff).context("serialize role_access")?;
                }
                if let Some(g) = &gate {
                    doc["gate"] = serde_json::to_value(g).context("serialize gate")?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&doc).context("serialize changes")?
                );
            }
            "md" | "markdown" => {
                print!(
                    "{}",
                    render_changes_markdown(
                        &[(role_name, &changes, &cur)],
                        Some(&role_diff),
                        gate.as_ref()
                    )
                );
            }
            _ => {
                print!("{}", changes_output(&changes, &cur, false)?);
                print_role_access_text(&role_diff);
                if let Some(g) = &gate {
                    print_gate_text(g);
                }
            }
        }
        return Ok(if gate.is_some_and(|g| !g.passed) {
            1
        } else {
            0
        });
    }

    if args.since == 0 {
        bail!("--since must be 1 or more");
    }
    let ctx = project::resolve(&args.target)?;
    let sel = role_sel(args.role.as_deref());
    let maps = load_recorded_maps(&ctx, &sel)?;

    let missing_roles: Vec<String> = if sel == RoleSel::All {
        missing_configured_roles(&ctx, &maps)
    } else {
        Vec::new()
    };

    let mut per_role: Vec<(String, ChangeSet, Inventory)> = Vec::new();
    let mut old_roles_map = BTreeMap::new();
    let mut new_roles_map = BTreeMap::new();
    let mut zero_coverage_roles: Vec<(String, u32, u32)> = Vec::new();
    for (role, cur) in maps {
        let prev = previous_inventory(&ctx.role_paths(&role).history_dir, &cur, args.since)?;
        if let Some(prev_visited) = prev.as_ref().map(|p| p.coverage.routes_visited)
            && (prev_visited == 0 || cur.coverage.routes_visited == 0)
        {
            zero_coverage_roles.push((role.clone(), prev_visited, cur.coverage.routes_visited));
        }
        let changes = inventory::diff(prev.as_ref(), &cur);
        if let Some(p) = prev {
            old_roles_map.insert(role.clone(), p);
            new_roles_map.insert(role.clone(), cur.clone());
        }
        per_role.push((role, changes, cur));
    }

    let role_diff: Option<RoleAccessDiff> = if sel == RoleSel::All {
        load_role_access_diff_for_project(&ctx, args.since)?
    } else if !old_roles_map.is_empty() {
        Some(diff_role_access(&old_roles_map, &new_roles_map))
    } else {
        None
    };

    let health = GateRoleHealth {
        missing_roles: missing_roles.clone(),
        collapsed_roles: Vec::new(),
        zero_coverage_roles,
    };
    let control_refs: Vec<(&str, &ChangeSet)> =
        per_role.iter().map(|(r, cs, _)| (r.as_str(), cs)).collect();
    let gate = policy
        .as_ref()
        .map(|p| evaluate_changes_gate_with_health(p, &control_refs, role_diff.as_ref(), &health));

    match fmt {
        "json" => {
            if sel != RoleSel::All {
                let (_, changes, _) = &per_role[0];
                let mut doc = serde_json::to_value(changes).context("serialize changes")?;
                if let Some(rd) = role_diff.as_ref().filter(|d| !d.changes.is_empty()) {
                    doc["role_access"] =
                        serde_json::to_value(rd).context("serialize role_access")?;
                }
                if let Some(g) = &gate {
                    doc["gate"] = serde_json::to_value(g).context("serialize gate")?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&doc).context("serialize changes")?
                );
            } else {
                let mut docs = Vec::new();
                for (role, changes, _) in &per_role {
                    let mut doc = serde_json::to_value(changes).context("serialize changes")?;
                    doc["login_role"] = json!(role);
                    docs.push(doc);
                }
                let mut root = json!({ "roles": docs });
                if !missing_roles.is_empty() {
                    root["missing_roles"] = json!(missing_roles);
                }
                if let Some(rd) = &role_diff {
                    root["role_access"] =
                        serde_json::to_value(rd).context("serialize role_access")?;
                }
                if let Some(g) = &gate {
                    root["gate"] = serde_json::to_value(g).context("serialize gate")?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&root).context("serialize changes")?
                );
            }
        }
        "md" | "markdown" => {
            let md_refs: Vec<(&str, &ChangeSet, &Inventory)> = per_role
                .iter()
                .map(|(r, cs, inv)| (r.as_str(), cs, inv))
                .collect();
            print!(
                "{}",
                render_changes_markdown(&md_refs, role_diff.as_ref(), gate.as_ref())
            );
        }
        _ => {
            if sel != RoleSel::All {
                let (_, changes, cur) = &per_role[0];
                print!("{}", changes_output(changes, cur, false)?);
            } else {
                for (role, changes, cur) in &per_role {
                    println!("== {role} ==");
                    print!("{}", changes_output(changes, cur, false)?);
                    println!();
                }
                if !missing_roles.is_empty() {
                    println!("missing role maps: {}", missing_roles.join(", "));
                }
            }
            if let Some(rd) = &role_diff {
                print_role_access_text(rd);
            }
            if let Some(g) = &gate {
                print_gate_text(g);
            }
        }
    }

    Ok(if gate.is_some_and(|g| !g.passed) {
        1
    } else {
        0
    })
}

fn print_role_access_text(rd: &crate::inventory::parity::RoleAccessDiff) {
    if rd.changes.is_empty() && rd.roles_only_in_old.is_empty() {
        return;
    }
    println!(
        "role-access changes ({} role{} compared):",
        rd.roles_compared.len(),
        if rd.roles_compared.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    for ch in &rd.changes {
        println!("  {}", ch.line);
    }
    if !rd.roles_only_in_old.is_empty() {
        println!(
            "  missing roles in latest map: {}",
            rd.roles_only_in_old.join(", ")
        );
    }
}

fn format_gate_text(g: &super::changes_gate::GateResult) -> String {
    if g.passed {
        "gate: PASS\n".to_string()
    } else if g.inconclusive && g.violations.is_empty() {
        format!(
            "gate: INCONCLUSIVE ({})\n",
            g.inconclusive_reasons.join("; ")
        )
    } else {
        let rules: Vec<&str> = g.triggered_rules.iter().map(|r| r.as_str()).collect();
        let mut out = format!(
            "gate: FAIL (triggered: {}; {} violation{})\n",
            rules.join(", "),
            g.violations.len(),
            if g.violations.len() == 1 { "" } else { "s" }
        );
        if g.inconclusive {
            out.push_str(&format!(
                "gate: INCONCLUSIVE ({})\n",
                g.inconclusive_reasons.join("; ")
            ));
        }
        out
    }
}

fn print_gate_text(g: &super::changes_gate::GateResult) {
    print!("{}", format_gate_text(g));
}

/// `ui` over one or more role maps. One map: the classic output. `--role
/// all`: `tsv`/`json` gain a `login_role` column, `table`/`md` one section per role.
pub(crate) fn ui_output_roles(
    maps: &[(String, Inventory)],
    args: &UiArgs,
    kind: Option<&str>,
    all: bool,
) -> Result<String> {
    if args.compact {
        let doc = if all {
            let roles: Vec<serde_json::Value> = maps
                .iter()
                .map(|(role, inv)| compact_ui_document(inv, args, kind, role, false))
                .collect::<Result<_>>()?;
            json!({
                "project": maps[0].1.project,
                "business_result_verified": false,
                "evidence_limits": [COMPACT_EVIDENCE_LIMIT],
                "roles": roles,
            })
        } else {
            let (role, inv) = maps.first().context("no selected role map")?;
            compact_ui_document(inv, args, kind, role, true)?
        };
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&doc).context("serialize compact UI")?
        ));
    }
    if !all {
        return ui_output_kind(&maps[0].1, args, kind);
    }
    let format = if args.json {
        "json"
    } else {
        args.format.as_str()
    };
    match format {
        "json" => {
            let mut controls = Vec::new();
            let mut roles = Vec::new();
            for (role, inv) in maps {
                for c in filter(inv, args, kind)?.apply(inv) {
                    let mut v = full_control(inv, c)?;
                    v["login_role"] = json!(role);
                    controls.push(v);
                }
                let mut metadata = json!({
                    "login_role": role,
                    "generated_at": inv.generated_at,
                    "coverage": inv.coverage,
                });
                add_source_review_provenance(&mut metadata, inv);
                roles.push(metadata);
            }
            let doc = json!({
                "project": maps[0].1.project,
                "roles": roles,
                "count": controls.len(),
                "controls": controls,
            });
            Ok(format!(
                "{}\n",
                serde_json::to_string_pretty(&doc).context("serialize controls")?
            ))
        }
        "tsv" => {
            let mut out = format!("login_role\t{}\n", render::TSV_HEADER);
            for (role, inv) in maps {
                for c in filter(inv, args, kind)?.apply(inv) {
                    out.push_str(&format!(
                        "{}\t{}\n",
                        render::tsv_field(role),
                        render::tsv_row(c)
                    ));
                }
            }
            Ok(out)
        }
        "table" | "md" | "markdown" => {
            let mut out = String::new();
            for (role, inv) in maps {
                if format == "table" {
                    out.push_str(&format!("== {role} ==\n"));
                } else {
                    out.push_str(&format!("## {role}\n\n"));
                }
                out.push_str(&ui_output_kind(inv, args, kind)?);
                out.push('\n');
            }
            Ok(out)
        }
        other => bail!("unknown format '{other}' (expected table|tsv|md|json)"),
    }
}

fn filter(_inv: &Inventory, args: &UiArgs, kind: Option<&str>) -> Result<ControlFilter> {
    let status = args
        .status
        .as_deref()
        .map(|s| {
            ControlStatus::parse(s).ok_or_else(|| {
                anyhow!(
                    "unknown status '{s}' (expected ok|dead|no_effect|broken|disabled|external|skipped|not_exercised)"
                )
            })
        })
        .transpose()?;
    Ok(ControlFilter {
        route: args.route.clone(),
        exact_route: args.exact_route,
        exclude_shell: args.exclude_shell,
        text: args.text.clone(),
        status,
        calls: args.calls.clone(),
        role: kind.map(str::to_string),
    })
}

// ---------------------------------------------------------------------------
// Output builders (pure; tested directly)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn ui_output(inv: &Inventory, args: &UiArgs) -> Result<String> {
    ui_output_kind(inv, args, args.kind.as_deref())
}

pub(crate) fn ui_output_kind(inv: &Inventory, args: &UiArgs, kind: Option<&str>) -> Result<String> {
    if args.compact {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&compact_ui_document(
                inv,
                args,
                kind,
                inv.role.as_deref().unwrap_or(ANONYMOUS_ROLE),
                true,
            )?)
            .context("serialize compact UI")?
        ));
    }
    let controls = filter(inv, args, kind)?.apply(inv);
    let format = if args.json {
        "json"
    } else {
        args.format.as_str()
    };
    match format {
        "json" => {
            let controls = controls
                .into_iter()
                .map(|c| full_control(inv, c))
                .collect::<Result<Vec<_>>>()?;
            let mut doc = json!({
                "project": inv.project,
                "generated_at": inv.generated_at,
                "target_url": inv.target_url,
                "coverage": inv.coverage,
                "count": controls.len(),
                "controls": controls,
            });
            add_source_review_provenance(&mut doc, inv);
            Ok(format!(
                "{}\n",
                serde_json::to_string_pretty(&doc).context("serialize controls")?
            ))
        }
        "tsv" => {
            let mut out = format!("{}\n", render::TSV_HEADER);
            for c in &controls {
                out.push_str(&render::tsv_row(c));
                out.push('\n');
            }
            Ok(out)
        }
        "md" | "markdown" => Ok(render::md_table_with_route(&controls)),
        "table" => {
            if controls.is_empty() {
                return Ok(format!(
                    "No controls match. ({})\n",
                    render::coverage_line(inv)
                ));
            }
            let mut out = render::text_table(&controls);
            out.push_str(&format!(
                "\n{} control{} shown. Map: {} ({}).\n",
                controls.len(),
                if controls.len() == 1 { "" } else { "s" },
                inv.generated_at,
                render::coverage_line(inv)
            ));
            Ok(out)
        }
        other => bail!("unknown format '{other}' (expected table|tsv|md|json)"),
    }
}

const COMPACT_EVIDENCE_LIMIT: &str = "UI/network observations only (no business, content, or auth proof); coverage and route_summaries cover the saved map before filters; verify static sources.";

const COMPACT_STATE_OBSERVATION_LIMIT: &str =
    "State observations apply only to their cited fixture and variant.";

fn compact_outcome(outcome: &crate::inventory::Outcome) -> Result<serde_json::Value> {
    match outcome {
        crate::inventory::Outcome::Calls {
            endpoint,
            status,
            blocked,
        } => {
            let mut map = serde_json::Map::new();
            map.insert("type".into(), json!("calls"));
            map.insert("endpoint".into(), json!(endpoint));
            if let Some(st) = status {
                map.insert("status".into(), json!(st));
            }
            if *blocked {
                map.insert("blocked".into(), json!(true));
            }
            Ok(serde_json::Value::Object(map))
        }
        other => serde_json::to_value(other).context("serialize outcome"),
    }
}

/// Deliberately lean representation of one control for `--compact`:
/// stable handles, observed effects, non-obvious epistemic caveats, and
/// complete source confidence/candidates. Shared caveats (such as
/// `business_result_verified: false`) live once at the top-level document.
fn compact_control(inv: &Inventory, c: &Control) -> Result<serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("key".into(), json!(c.key));
    fields.insert("route".into(), json!(c.route));
    fields.insert("kind".into(), json!(c.role));
    fields.insert("label".into(), json!(c.display_label()));
    fields.insert("status".into(), json!(c.status));
    if c.count > 1 {
        fields.insert("count".into(), json!(c.count));
    }
    let observation = evidence::control_evidence(c).observation;
    if matches!(
        observation,
        "inconclusive_timeout" | "focus_only_input_not_tested"
    ) {
        fields.insert("observation".into(), json!(observation));
    }
    for (key, values) in [
        ("routes", &c.routes),
        ("labels", &c.labels),
        ("variants", &c.variants),
        ("opened_by", &c.opened_by),
    ] {
        if !values.is_empty() {
            fields.insert(key.into(), json!(values));
        }
    }
    if !c.state_entries.is_empty() {
        fields.insert("state_entries".into(), json!(c.state_entries));
    }
    if !c.outcomes.is_empty() {
        let outcomes = c
            .outcomes
            .iter()
            .map(compact_outcome)
            .collect::<Result<Vec<_>>>()?;
        fields.insert("outcomes".into(), serde_json::Value::Array(outcomes));
    }
    if let Some(reason) = c.reason.as_deref().filter(|r| !r.is_empty()) {
        fields.insert("reason".into(), json!(reason));
    }
    if let Some(source) = &c.source {
        fields.insert(
            "source".into(),
            serde_json::to_value(source).context("serialize source")?,
        );
    }
    let mut row = serde_json::Value::Object(fields);
    add_recorded_source(&mut row, inv, c);
    Ok(row)
}

fn compact_coverage(c: &crate::inventory::CoverageSummary) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("routes_known".into(), json!(c.routes_known));
    map.insert("routes_visited".into(), json!(c.routes_visited));
    map.insert("controls_total".into(), json!(c.controls_total));
    map.insert("controls_exercised".into(), json!(c.controls_exercised));
    if c.controls_exercisable > 0 {
        map.insert("controls_exercisable".into(), json!(c.controls_exercisable));
    }
    if c.controls_external > 0 {
        map.insert("controls_external".into(), json!(c.controls_external));
    }
    if c.controls_disabled > 0 {
        map.insert("controls_disabled".into(), json!(c.controls_disabled));
    }
    if c.controls_skipped > 0 {
        map.insert("controls_skipped".into(), json!(c.controls_skipped));
    }
    if !c.not_exercised_by_reason.is_empty() {
        map.insert(
            "not_exercised_by_reason".into(),
            json!(c.not_exercised_by_reason),
        );
    }
    if !c.obscured_top_covers.is_empty() {
        map.insert("obscured_top_covers".into(), json!(c.obscured_top_covers));
    }
    if !c.unvisited_routes.is_empty() {
        map.insert(
            "unvisited_routes_count".into(),
            json!(c.unvisited_routes.len()),
        );
    }
    if !c.unvisited_by_reason.is_empty() {
        let counts: std::collections::BTreeMap<&str, usize> = c
            .unvisited_by_reason
            .iter()
            .map(|(reason, routes)| (reason.as_str(), routes.len()))
            .collect();
        map.insert("unvisited_by_reason_counts".into(), json!(counts));
    }
    serde_json::Value::Object(map)
}

fn compact_control_counts(counts: &evidence::ControlCounts) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("rows".into(), json!(counts.rows));
    map.insert("exercised".into(), json!(counts.exercised));
    map.insert("exercisable".into(), json!(counts.exercisable));
    if !counts.statuses.is_empty() {
        map.insert("statuses".into(), json!(counts.statuses));
    }
    if !counts.gaps_by_reason.is_empty() {
        map.insert("gaps_by_reason".into(), json!(counts.gaps_by_reason));
    }
    serde_json::Value::Object(map)
}

fn compact_route_observation(obs: &evidence::RouteObservation) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(variant) = &obs.variant {
        map.insert("variant".into(), json!(variant));
    }
    map.insert("state".into(), json!(obs.state));
    map.insert("basis".into(), json!(obs.basis));
    if let Some(note) = &obs.observation_note {
        map.insert("observation_note".into(), json!(note));
    }
    if let Some(explanation) = &obs.source_explanation {
        map.insert("source_explanation".into(), json!(explanation));
    }
    if !obs.evidence.is_empty() {
        let refs: Vec<serde_json::Value> = obs
            .evidence
            .iter()
            .map(|r| {
                let mut m = serde_json::Map::new();
                m.insert("kind".into(), json!(r.kind));
                m.insert("path".into(), json!(r.path));
                if let Some(locator) = &r.locator {
                    m.insert("locator".into(), json!(locator));
                }
                if let Some(sha) = &r.sha256 {
                    m.insert("sha256".into(), json!(sha));
                }
                serde_json::Value::Object(m)
            })
            .collect();
        map.insert("evidence".into(), serde_json::Value::Array(refs));
    }
    serde_json::Value::Object(map)
}

fn compact_route_summary(inv: &Inventory, route: &str) -> (serde_json::Value, bool) {
    let summary = evidence::route_summary(inv, route);
    let has_observations = !summary.state_observations.is_empty();
    let mut map = serde_json::Map::new();
    map.insert("route".into(), json!(summary.route));
    map.insert("visited".into(), json!(summary.visited));
    if let Some(status) = summary.http_status {
        map.insert("http_status".into(), json!(status));
    }
    if summary.page_state != "unknown" {
        map.insert("page_state".into(), json!(summary.page_state));
    }
    if has_observations {
        let obs = summary
            .state_observations
            .iter()
            .map(compact_route_observation)
            .collect();
        map.insert("state_observations".into(), serde_json::Value::Array(obs));
    }
    if summary.page_controls.rows > 0 {
        map.insert(
            "page_controls".into(),
            compact_control_counts(&summary.page_controls),
        );
    }
    if summary.shell_controls.rows > 0 {
        map.insert(
            "shell_controls".into(),
            compact_control_counts(&summary.shell_controls),
        );
    }
    if summary.observed_control_endpoints > 0 {
        map.insert(
            "observed_endpoints".into(),
            json!(summary.observed_control_endpoints),
        );
    }
    (serde_json::Value::Object(map), has_observations)
}

fn full_control(inv: &Inventory, control: &Control) -> Result<serde_json::Value> {
    let mut row = serde_json::to_value(control).context("serialize control")?;
    add_recorded_source(&mut row, inv, control);
    Ok(row)
}

fn add_recorded_source(row: &mut serde_json::Value, inv: &Inventory, control: &Control) {
    if let Some(review) = inv.source_reviews.as_ref().and_then(|reviews| {
        reviews
            .controls
            .iter()
            .find(|review| review.key == control.key)
    }) {
        row["recorded_source"] = json!(review.original_source);
        // Explicit null means a reviewed old candidate was withdrawn.
        row["source"] = json!(control.source);
    }
}

fn add_source_review_provenance(doc: &mut serde_json::Value, inv: &Inventory) {
    if let Some(reviews) = &inv.source_reviews {
        doc["source_review_provenance"] = json!({
            "schema": reviews.schema,
            "inventory_sha256": reviews.inventory_sha256,
            "role": reviews.role,
            "resolver_sha256": reviews.resolver_sha256,
            "source_snapshot_sha256": reviews.source_snapshot_sha256,
            "source_root": reviews.source_root,
            "reviewed_controls": reviews.controls.len(),
            "basis": "static_recomputation_not_new_runtime_capture",
        });
    }
}

fn compact_ui_document(
    inv: &Inventory,
    args: &UiArgs,
    kind: Option<&str>,
    login_role: &str,
    include_shared_caveats: bool,
) -> Result<serde_json::Value> {
    let filter = filter(inv, args, kind)?;
    let matched = filter.apply(inv);
    let routes = if args.route.is_none()
        && (args.text.is_some() || args.status.is_some() || args.calls.is_some() || kind.is_some())
    {
        matched
            .iter()
            .flat_map(|c| c.present_on())
            .filter(|route| *route != "*")
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        filter.selected_routes(inv)
    };
    let mut summaries = Vec::with_capacity(routes.len());
    let mut any_state_observations = false;
    for route in routes {
        let (summary, has_obs) = compact_route_summary(inv, route);
        any_state_observations |= has_obs;
        summaries.push(summary);
    }
    let mut evidence_limits = Vec::new();
    let mut seen_limits = std::collections::BTreeSet::new();
    let mut push_limit = |limit: String| {
        if seen_limits.insert(limit.clone()) {
            evidence_limits.push(limit);
        }
    };
    if include_shared_caveats {
        push_limit(COMPACT_EVIDENCE_LIMIT.to_string());
    }
    if any_state_observations {
        push_limit(COMPACT_STATE_OBSERVATION_LIMIT.to_string());
    }
    if let Some(annotations) = &inv.evidence_annotations {
        for limit in &annotations.limitations {
            push_limit(limit.clone());
        }
    }
    let controls = matched
        .into_iter()
        .map(|c| compact_control(inv, c))
        .collect::<Result<Vec<_>>>()?;
    let mut query = serde_json::Map::new();
    if let Some(route) = &args.route {
        query.insert("route".into(), json!(route));
    }
    if args.exact_route {
        query.insert("exact_route".into(), json!(true));
    }
    if args.exclude_shell {
        query.insert("exclude_shell".into(), json!(true));
    }
    if let Some(observed) = filter.requested_state_observed(inv) {
        query.insert("requested_state_observed".into(), json!(observed));
    }
    if let Some(text) = &args.text {
        query.insert("text".into(), json!(text));
    }
    if let Some(status) = &args.status {
        query.insert("status".into(), json!(status));
    }
    if let Some(calls) = &args.calls {
        query.insert("calls".into(), json!(calls));
    }
    if let Some(kind) = kind {
        query.insert("kind".into(), json!(kind));
    }
    let mut doc_map = serde_json::Map::new();
    if include_shared_caveats {
        doc_map.insert("project".into(), json!(inv.project));
    }
    doc_map.insert("login_role".into(), json!(login_role));
    doc_map.insert("generated_at".into(), json!(inv.generated_at));
    if !inv.write_guard.is_empty() {
        doc_map.insert("write_guard".into(), json!(inv.write_guard));
    }
    doc_map.insert("coverage".into(), compact_coverage(&inv.coverage));
    if !query.is_empty() {
        doc_map.insert("query".into(), serde_json::Value::Object(query));
    }
    doc_map.insert(
        "route_summaries".into(),
        serde_json::Value::Array(summaries),
    );
    if include_shared_caveats {
        doc_map.insert("business_result_verified".into(), json!(false));
    }
    if !evidence_limits.is_empty() {
        doc_map.insert("evidence_limits".into(), json!(evidence_limits));
    }
    if let Some(annotations) = &inv.evidence_annotations {
        let mut ctx = serde_json::Map::new();
        if let Some(surface) = &annotations.surface {
            ctx.insert("surface".into(), json!(surface));
        }
        if let Some(environment) = &annotations.environment {
            ctx.insert("environment".into(), json!(environment));
        }
        if let Some(fixture) = &annotations.fixture {
            ctx.insert("fixture".into(), json!(fixture));
        }
        if !ctx.is_empty() {
            doc_map.insert("context".into(), serde_json::Value::Object(ctx));
        }
    }
    doc_map.insert("count".into(), json!(controls.len()));
    doc_map.insert("controls".into(), serde_json::Value::Array(controls));
    let mut doc = serde_json::Value::Object(doc_map);
    add_source_review_provenance(&mut doc, inv);
    Ok(doc)
}

pub(crate) fn dead_output(
    inv: &Inventory,
    include_unexercised: bool,
    as_json: bool,
) -> Result<String> {
    let pick = |st: ControlStatus| -> Vec<&Control> {
        inv.controls.iter().filter(|c| c.status == st).collect()
    };
    let broken = pick(ControlStatus::Broken);
    let dead = pick(ControlStatus::Dead);
    let no_effect = pick(ControlStatus::NoEffect);
    let unexercised = if include_unexercised {
        pick(ControlStatus::NotExercised)
    } else {
        Vec::new()
    };
    let caveat = render::coverage_caveat(inv);
    if as_json {
        let serialize = |controls: &[&Control]| {
            controls
                .iter()
                .map(|c| full_control(inv, c))
                .collect::<Result<Vec<_>>>()
        };
        let mut doc = json!({
            "project": inv.project,
            "generated_at": inv.generated_at,
            "broken": serialize(&broken)?,
            "dead": serialize(&dead)?,
            "no_effect": serialize(&no_effect)?,
            "coverage": inv.coverage,
            "caveat": caveat,
        });
        if include_unexercised {
            doc["not_exercised"] = json!(serialize(&unexercised)?);
        }
        add_source_review_provenance(&mut doc, inv);
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&doc).context("serialize dead UI")?
        ));
    }
    let mut out = String::new();
    for (title, list) in [
        ("Broken", &broken),
        ("Dead (high confidence)", &dead),
        ("No visible effect (review)", &no_effect),
    ] {
        out.push_str(&format!("{title} ({}):\n", list.len()));
        if list.is_empty() {
            out.push_str("  none\n");
        }
        for c in list.iter() {
            out.push_str(&format!(
                "  {} {} \"{}\"{}: {}",
                c.route,
                c.role,
                c.display_label(),
                count_suffix(c),
                render::evidence_text(c)
            ));
            let src = render::source_text(c.source.as_ref());
            if !src.is_empty() {
                out.push_str(&format!(" [{src}]"));
            }
            out.push('\n');
        }
        out.push('\n');
    }
    if include_unexercised {
        out.push_str(&format!("Not exercised ({}):\n", unexercised.len()));
        for c in &unexercised {
            out.push_str(&format!(
                "  {} {} \"{}\"{} — {}\n",
                c.route,
                c.role,
                c.display_label(),
                count_suffix(c),
                c.reason.as_deref().unwrap_or("not_exercised")
            ));
        }
        out.push('\n');
    }
    out.push_str(&caveat);
    out.push('\n');
    Ok(out)
}

fn count_suffix(c: &Control) -> String {
    if c.count > 1 {
        format!(" ×{}", c.count)
    } else {
        String::new()
    }
}

/// Static code hits listed for an endpoint goal the map never observed.
const JOURNEY_CODE_REFS: usize = 8;

/// Output and whether the goal matched anything in the map. With a
/// `codebase`, an unobserved endpoint goal also lists source lines that
/// mention it.
pub(crate) fn journey_output(
    inv: &Inventory,
    args: &JourneyArgs,
    codebase: Option<&Path>,
) -> Result<(String, bool)> {
    journey_output_with_default_from(inv, args, codebase, None)
}

fn journey_output_with_default_from(
    inv: &Inventory,
    args: &JourneyArgs,
    codebase: Option<&Path>,
    default_from: Option<&str>,
) -> Result<(String, bool)> {
    let fmt = journey_format(args)?;
    let goal: Goal = journey::parse_goal(&args.to, inv);
    let effective_from = args.from.as_deref().or(default_from);
    let mut res = journey::journey(inv, &goal, effective_from, args.max_hops);
    if args.from.is_none()
        && let Some(start) = default_from
        && start != "/"
        && start != "/#/"
    {
        res.notes.insert(
            0,
            format!(
                "Start route / was not visited in this map; using configured role check route {start} instead."
            ),
        );
    }
    let found = !res.matched.is_empty();
    if !found && let (Goal::Endpoint { method, path }, Some(root)) = (&goal, codebase) {
        match crate::code_link::find_endpoint_references(
            root,
            method.as_deref(),
            path,
            JOURNEY_CODE_REFS,
        ) {
            Ok(hits) => {
                res.code_references = hits
                    .into_iter()
                    .map(|h| match h.snippet {
                        Some(code) => format!("{}:{}  {code}", h.file, h.line),
                        None => format!("{}:{}", h.file, h.line),
                    })
                    .collect();
            }
            Err(err) => tracing::debug!("static endpoint search failed: {err:#}"),
        }
    }
    let out = match fmt {
        "json" => format!(
            "{}\n",
            serde_json::to_string_pretty(&res).context("serialize journey")?
        ),
        "md" | "markdown" => journey::render_markdown(&res, args.max_hops),
        _ => journey::render_text(&res, args.max_hops),
    };
    Ok((out, found))
}

pub(crate) fn changes_output(
    changes: &ChangeSet,
    cur: &Inventory,
    as_json: bool,
) -> Result<String> {
    if as_json {
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(changes).context("serialize changes")?
        ));
    }
    let Some(from) = changes.from.as_deref() else {
        return Ok(format!(
            "No earlier map to compare with. {}\n",
            render::change_lines(changes, cur).join(" ")
        ));
    };
    let notes: String = changes
        .notes
        .iter()
        .map(|n| format!("Note: {n}\n"))
        .collect();
    if changes.changes.is_empty() {
        return Ok(format!(
            "No UI changes between {from} and {}.\n{notes}",
            changes.to
        ));
    }
    let summary: Vec<String> = render::change_summary(changes)
        .iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect();
    let mut out = format!(
        "{} change{} from {from} to {} ({}):\n",
        changes.changes.len(),
        if changes.changes.len() == 1 { "" } else { "s" },
        changes.to,
        summary.join(", ")
    );
    for c in &changes.changes {
        out.push_str(&format!("  {}\n", c.line));
    }
    out.push_str(&notes);
    Ok(out)
}

/// Timestamped history files (`*.inventory.json`, not `latest`), oldest first.
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

/// The `since`-th map before `cur` (copies of the latest map are skipped).
fn previous_inventory(dir: &Path, cur: &Inventory, since: usize) -> Result<Option<Inventory>> {
    let mut remaining = since;
    for path in history_files(dir)?.iter().rev() {
        let inv = match inventory::load(path) {
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

#[cfg(test)]
#[path = "read_query_tests.rs"]
mod query_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{CoverageSummary, Outcome, RouteEntry};

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
            role: role.into(),
            label: label.into(),
            selector: format!("#{}", label.to_lowercase()),
            locator: format!("text={}", label.to_lowercase()),
            count: 1,
            status,
            outcomes,
            ..Default::default()
        }
    }

    fn inventory() -> Inventory {
        Inventory {
            schema: inventory::INVENTORY_SCHEMA.into(),
            project: "demo".into(),
            generated_at: "2026-10-21T10:00:00Z".into(),
            target_url: "http://127.0.0.1:47260/".into(),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: 2,
                routes_visited: 2,
                controls_total: 3,
                controls_exercised: 2,
                ..Default::default()
            },
            routes: vec![
                RouteEntry {
                    route: "/".into(),
                    visited: true,
                    controls: 2,
                    ..Default::default()
                },
                RouteEntry {
                    route: "/cart".into(),
                    visited: true,
                    controls: 1,
                    ..Default::default()
                },
            ],
            controls: vec![
                control(
                    "/",
                    "link",
                    "Cart",
                    ControlStatus::Ok,
                    vec![Outcome::Navigates { to: "/cart".into() }],
                ),
                control("/", "button", "Nothing", ControlStatus::Dead, vec![]),
                control(
                    "/cart",
                    "button",
                    "Pay",
                    ControlStatus::Ok,
                    vec![Outcome::Calls {
                        endpoint: "POST /api/pay".into(),
                        status: None,
                        blocked: true,
                    }],
                ),
            ],
            ..Default::default()
        }
    }

    fn ui_args() -> UiArgs {
        UiArgs {
            route: None,
            exact_route: false,
            exclude_shell: false,
            text: None,
            status: None,
            calls: None,
            kind: None,
            role: None,
            inventory: None,
            format: "table".into(),
            json: false,
            compact: false,
            target: ProjectTarget::default(),
        }
    }

    #[test]
    fn ui_filters_and_formats() {
        let inv = inventory();
        let mut args = ui_args();
        args.calls = Some("/api/pay".into());
        let out = ui_output(&inv, &args).unwrap();
        assert!(out.contains("Pay"), "{out}");
        assert!(!out.contains("Nothing"), "{out}");

        args.calls = None;
        args.status = Some("dead".into());
        args.format = "tsv".into();
        let out = ui_output(&inv, &args).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], render::TSV_HEADER);
        assert_eq!(lines.len(), 2);
        assert!(
            lines[1].starts_with("/\tbutton\tNothing\tdead\t"),
            "{}",
            lines[1]
        );

        args.status = Some("bogus".into());
        assert!(ui_output(&inv, &args).is_err());

        args.status = None;
        args.json = true;
        let v: serde_json::Value = serde_json::from_str(&ui_output(&inv, &args).unwrap()).unwrap();
        assert_eq!(v["count"], 3);
    }

    #[test]
    fn dead_lists_dead_and_caveat() {
        let out = dead_output(&inventory(), false, false).unwrap();
        assert!(out.contains("Dead (high confidence) (1):"), "{out}");
        assert!(out.contains("No visible effect (review) (0):"), "{out}");
        assert!(out.contains("/ button \"Nothing\""), "{out}");
        assert!(
            out.contains("Coverage: 2/3 exercisable controls exercised"),
            "{out}"
        );
        let v: serde_json::Value =
            serde_json::from_str(&dead_output(&inventory(), true, true).unwrap()).unwrap();
        assert_eq!(v["dead"].as_array().unwrap().len(), 1);
        assert_eq!(v["no_effect"].as_array().unwrap().len(), 0);
        assert!(v.get("not_exercised").is_some());
    }

    #[test]
    fn journey_reports_paths_and_unknown_goals() {
        let inv = inventory();
        let args = JourneyArgs {
            to: "POST /api/pay".into(),
            from: None,
            max_hops: 15,
            role: None,
            inventory: None,
            format: "text".into(),
            json: false,
            target: ProjectTarget::default(),
        };
        let (out, found) = journey_output(&inv, &args, None).unwrap();
        assert!(found);
        assert!(
            out.contains("/ → link \"Cart\" → /cart → button \"Pay\" → POST /api/pay"),
            "{out}"
        );
        let missing = JourneyArgs {
            to: "/nowhere".into(),
            ..args
        };
        let (_, found) = journey_output(&inv, &missing, None).unwrap();
        assert!(!found);
    }

    #[test]
    fn journey_formats_markdown_and_json_and_defaults_max_hops_to_15() {
        use clap::Parser;

        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            command: crate::front::FrontCommand,
        }

        let inv = inventory();
        let crate::front::FrontCommand::Journey(parsed) =
            Cli::try_parse_from(["brokenapp", "journey", "POST /api/pay"])
                .unwrap()
                .command
        else {
            panic!("expected journey");
        };
        assert_eq!(parsed.max_hops, 15);
        assert_eq!(parsed.format, "text");
        assert!(parsed.inventory.is_none());

        let md_args = JourneyArgs {
            format: "md".into(),
            ..parsed
        };
        let (md, found) = journey_output(&inv, &md_args, None).unwrap();
        assert!(found);
        assert!(md.contains("## Journey to endpoint POST /api/pay"), "{md}");
        assert!(
            md.contains("| # | Route | Control | Action | Leads To | Status | Source |"),
            "{md}"
        );
        assert!(md.contains("POST /api/pay [write blocked]"), "{md}");

        let json_args = JourneyArgs {
            format: "json".into(),
            ..md_args
        };
        let (raw_json, found) = journey_output(&inv, &json_args, None).unwrap();
        assert!(found);
        let doc: serde_json::Value = serde_json::from_str(&raw_json).unwrap();
        assert_eq!(doc["distance"], 2);
        assert_eq!(doc["path_evidence"], "stitched_candidate");

        let bogus_args = JourneyArgs {
            format: "xml".into(),
            ..json_args
        };
        assert!(journey_output(&inv, &bogus_args, None).is_err());

        // `--inventory` conflicts with `--role` on ui, dead, and journey.
        assert!(
            Cli::try_parse_from([
                "brokenapp",
                "ui",
                "--inventory",
                "a.json",
                "--role",
                "admin"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "brokenapp",
                "dead",
                "--inventory",
                "a.json",
                "--role",
                "admin"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "brokenapp",
                "journey",
                "/cart",
                "--inventory",
                "a.json",
                "--role",
                "admin"
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn inventory_flag_loads_standalone_file_without_project_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let inv_path = dir.path().join("snapshot.inventory.json");
        let mut inv = inventory();
        inv.role = Some("member".into());
        inventory::save(&inv, &inv_path).unwrap();

        let (role, loaded) = load_inventory_file(&inv_path).unwrap();
        assert_eq!(role, "member");
        assert_eq!(loaded.controls.len(), 3);

        // Point target at a nonexistent project/state dir so `project::resolve` would fail
        // if called, proving `--inventory` bypasses project resolution.
        let non_project_target = ProjectTarget {
            project: Some("nonexistent-project-for-test".into()),
            state_dir: Some(dir.path().join("missing-state-dir")),
        };

        let ui_code = run_ui(UiArgs {
            inventory: Some(inv_path.clone()),
            target: non_project_target.clone(),
            ..ui_args()
        })
        .await
        .unwrap();
        assert_eq!(ui_code, 0);

        let dead_code = run_dead(DeadArgs {
            include_unexercised: false,
            role: None,
            inventory: Some(inv_path.clone()),
            json: true,
            target: non_project_target.clone(),
        })
        .await
        .unwrap();
        assert_eq!(dead_code, 0);

        let journey_code = run_journey(JourneyArgs {
            to: "POST /api/pay".into(),
            from: None,
            max_hops: 15,
            role: None,
            inventory: Some(inv_path.clone()),
            format: "md".into(),
            json: false,
            target: non_project_target.clone(),
        })
        .await
        .unwrap();
        assert_eq!(journey_code, 0);

        let missing_code = run_journey(JourneyArgs {
            to: "/nowhere".into(),
            from: None,
            max_hops: 15,
            role: None,
            inventory: Some(inv_path),
            format: "text".into(),
            json: false,
            target: non_project_target,
        })
        .await
        .unwrap();
        assert_eq!(missing_code, 1);
    }

    #[test]
    fn format_gate_text_distinguishes_pass_fail_and_inconclusive() {
        use super::super::changes_gate::{FailOnRule, GateResult, GateViolation};

        let pass = GateResult {
            passed: true,
            triggered_rules: vec![],
            violations: vec![],
            inconclusive: false,
            inconclusive_reasons: vec![],
        };
        assert_eq!(format_gate_text(&pass), "gate: PASS\n");

        let inc = GateResult {
            passed: false,
            triggered_rules: vec![],
            violations: vec![],
            inconclusive: true,
            inconclusive_reasons: vec![
                "anonymous: no earlier baseline map to compare against".into(),
            ],
        };
        assert_eq!(
            format_gate_text(&inc),
            "gate: INCONCLUSIVE (anonymous: no earlier baseline map to compare against)\n"
        );

        let both = GateResult {
            passed: false,
            triggered_rules: vec![FailOnRule::Dead],
            violations: vec![GateViolation {
                rule: FailOnRule::Dead,
                role: "member".into(),
                route: "/".into(),
                kind: "now_dead".into(),
                line: "NOW DEAD / button \"Export\"".into(),
            }],
            inconclusive: true,
            inconclusive_reasons: vec!["admin: no earlier baseline map to compare against".into()],
        };
        let text = format_gate_text(&both);
        assert!(
            text.contains("gate: FAIL (triggered: dead; 1 violation)"),
            "{text}"
        );
        assert!(
            text.contains("gate: INCONCLUSIVE (admin: no earlier baseline map to compare against)"),
            "{text}"
        );
    }

    #[test]
    fn changes_reads_history_skipping_latest_copy() {
        let dir = tempfile::tempdir().unwrap();
        let history = dir.path();
        let mut old = inventory();
        old.generated_at = "2026-10-20T10:00:00Z".into();
        old.controls[1].status = ControlStatus::Ok;
        old.controls[1].outcomes = vec![Outcome::DomChange {
            kind: "modal".into(),
        }];
        let cur = inventory();
        inventory::save(&old, &history.join("20261020T100000Z.inventory.json")).unwrap();
        inventory::save(&cur, &history.join("20261021T100000Z.inventory.json")).unwrap();
        inventory::save(&cur, &history.join(LATEST_INVENTORY)).unwrap();

        let prev = previous_inventory(history, &cur, 1).unwrap().unwrap();
        assert_eq!(prev.generated_at, old.generated_at);
        assert!(previous_inventory(history, &cur, 2).unwrap().is_none());

        let cs = inventory::diff(Some(&prev), &cur);
        let out = changes_output(&cs, &cur, false).unwrap();
        assert!(
            out.contains("NOW DEAD / button \"Nothing\" (was opens modal)"),
            "{out}"
        );
        let first = changes_output(&inventory::diff(None, &cur), &cur, false).unwrap();
        assert!(first.contains("Initial map: 3 controls"), "{first}");
    }

    #[tokio::test]
    async fn run_changes_role_all_fails_when_role_missing_or_collapsed() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(project::CONFIG_FILE),
            r#"
[project]
name = "repairlift"
url = "http://127.0.0.1:3000"

[[roles]]
name = "csm"
method = "form"

[[roles]]
name = "owner"
method = "form"

[[roles]]
name = "admin"
method = "form"
"#,
        )
        .unwrap();
        let ctx = project::load_ctx(&state).unwrap();

        let make_inv = |ts: &str, role: Option<&str>, visited: u32| Inventory {
            schema: inventory::INVENTORY_SCHEMA.into(),
            identity_version: inventory::IDENTITY_VERSION,
            project: "repairlift".into(),
            generated_at: ts.into(),
            target_url: "http://127.0.0.1:3000/".into(),
            role: role.map(str::to_string),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: 4,
                routes_visited: visited,
                ..Default::default()
            },
            routes: (0..visited)
                .map(|i| RouteEntry {
                    route: if i == 0 { "/".into() } else { format!("/r{i}") },
                    visited: true,
                    status: Some(200),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };

        for (role, old_v, new_v) in [("anonymous", 2, 2), ("owner", 3, 3), ("csm", 4, 0)] {
            let role_opt = (role != ANONYMOUS_ROLE).then_some(role);
            let old = make_inv("2026-11-19T10:00:00Z", role_opt, old_v);
            let cur = make_inv("2026-11-20T10:00:00Z", role_opt, new_v);
            let hist = ctx.role_paths(role).history_dir;
            inventory::save(&old, &hist.join("20261119T100000Z.inventory.json")).unwrap();
            inventory::save(&cur, &hist.join("20261120T100000Z.inventory.json")).unwrap();
            inventory::save(&cur, &hist.join(LATEST_INVENTORY)).unwrap();
        }
        // `admin` has no saved map at all (login_failed).
        let loaded = load_recorded_maps(&ctx, &RoleSel::All).unwrap();
        assert_eq!(missing_configured_roles(&ctx, &loaded), vec!["admin"]);

        let code = run_changes(ChangesArgs {
            since: 1,
            between: None,
            role: Some("all".into()),
            format: "json".into(),
            fail_on: Some("dead,broken,access-gained".into()),
            json: true,
            target: ProjectTarget {
                project: None,
                state_dir: Some(state.clone()),
            },
        })
        .await
        .unwrap();
        assert_eq!(code, 1, "missing admin + collapsed csm must fail CI gate");

        // Respect `[auth] include_anonymous = false` when anonymous has no map.
        let mut ctx_no_anon = ctx.clone();
        ctx_no_anon.config.auth.include_anonymous = Some(false);
        let only_owner_csm: Vec<(String, Inventory)> = loaded
            .into_iter()
            .filter(|(r, _)| r != ANONYMOUS_ROLE)
            .collect();
        assert_eq!(
            missing_configured_roles(&ctx_no_anon, &only_owner_csm),
            vec!["admin"]
        );
    }

    #[test]
    fn compact_ui_summarizes_unvisited_routes_as_counts() {
        let mut inv = inventory();
        inv.routes.push(RouteEntry {
            route: "/verify".into(),
            visited: true,
            status: Some(200),
            controls: 1,
            ..Default::default()
        });
        inv.controls.push(control(
            "/verify",
            "button",
            "Verify",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "toast".into(),
            }],
        ));
        let not_linked: Vec<String> = (0..83).map(|i| format!("/unlinked/{i}")).collect();
        let login_gated: Vec<String> = (0..30).map(|i| format!("/private/{i}")).collect();
        inv.coverage.unvisited_routes = not_linked
            .iter()
            .chain(login_gated.iter())
            .cloned()
            .collect();
        inv.coverage
            .unvisited_by_reason
            .insert("not linked or seeded".into(), not_linked);
        inv.coverage
            .unvisited_by_reason
            .insert("redirects to login".into(), login_gated);

        let mut compact_args = ui_args();
        compact_args.route = Some("/verify".into());
        compact_args.exact_route = true;
        compact_args.exclude_shell = true;
        compact_args.compact = true;
        let compact_raw = ui_output(&inv, &compact_args).unwrap();
        let compact_doc: serde_json::Value = serde_json::from_str(&compact_raw).unwrap();
        assert_eq!(compact_doc["coverage"]["unvisited_routes_count"], 113);
        assert_eq!(
            compact_doc["coverage"]["unvisited_by_reason_counts"]["not linked or seeded"],
            83
        );
        assert_eq!(
            compact_doc["coverage"]["unvisited_by_reason_counts"]["redirects to login"],
            30
        );
        assert!(compact_doc["coverage"].get("unvisited_routes").is_none());
        assert!(compact_doc["coverage"].get("unvisited_by_reason").is_none());
        assert!(
            compact_raw.len() < 1500,
            "compact output should stay small ({} bytes): {compact_raw}",
            compact_raw.len()
        );

        let mut full_args = ui_args();
        full_args.route = Some("/verify".into());
        full_args.exact_route = true;
        full_args.exclude_shell = true;
        full_args.json = true;
        let full_doc: serde_json::Value =
            serde_json::from_str(&ui_output(&inv, &full_args).unwrap()).unwrap();
        assert_eq!(
            full_doc["coverage"]["unvisited_routes"]
                .as_array()
                .unwrap()
                .len(),
            113
        );
        assert_eq!(
            full_doc["coverage"]["unvisited_by_reason"]["redirects to login"]
                .as_array()
                .unwrap()
                .len(),
            30
        );
    }

    #[test]
    fn journey_prefers_role_check_route_when_root_not_visited() {
        let mut ctx = ProjectCtx {
            state_dir: PathBuf::from("/tmp/.brokenapp"),
            root: PathBuf::from("/tmp"),
            config_path: PathBuf::from("/tmp/.brokenapp/config.toml"),
            config: project::ProjectConfig::default(),
        };
        ctx.config.roles.push(super::super::roles::RoleConfig {
            name: "staff".into(),
            check: Some("/staff/".into()),
            ..Default::default()
        });

        let inv = Inventory {
            schema: inventory::INVENTORY_SCHEMA.into(),
            project: "demo".into(),
            generated_at: "2026-11-20T10:00:00Z".into(),
            target_url: "http://127.0.0.1:3000/".into(),
            role: Some("staff".into()),
            routes: vec![
                RouteEntry {
                    route: "/".into(),
                    visited: false,
                    ..Default::default()
                },
                RouteEntry {
                    route: "/account".into(),
                    visited: true,
                    ..Default::default()
                },
                RouteEntry {
                    route: "/staff".into(),
                    visited: true,
                    ..Default::default()
                },
                RouteEntry {
                    route: "/staff/orders".into(),
                    visited: true,
                    ..Default::default()
                },
            ],
            controls: vec![control(
                "/staff",
                "link",
                "Orders",
                ControlStatus::Ok,
                vec![Outcome::Navigates {
                    to: "/staff/orders".into(),
                }],
            )],
            ..Default::default()
        };

        let default_from = role_default_from(&ctx, "staff", &inv);
        assert_eq!(default_from.as_deref(), Some("/staff"));

        let args = JourneyArgs {
            to: "/staff/orders".into(),
            from: None,
            max_hops: 15,
            role: Some("staff".into()),
            inventory: None,
            format: "json".into(),
            json: true,
            target: ProjectTarget::default(),
        };
        let (raw, found) =
            journey_output_with_default_from(&inv, &args, None, default_from.as_deref()).unwrap();
        assert!(found);
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc["from"], "/staff");
        assert_eq!(doc["reachable"], true);
        assert_eq!(doc["distance"], 1);

        // Explicit --from overrides the role default.
        let explicit = JourneyArgs {
            from: Some("/account".into()),
            ..args
        };
        let (raw_exp, _) =
            journey_output_with_default_from(&inv, &explicit, None, default_from.as_deref())
                .unwrap();
        let doc_exp: serde_json::Value = serde_json::from_str(&raw_exp).unwrap();
        assert_eq!(doc_exp["from"], "/account");

        // When `/` IS visited, keep default `/` behavior (return None).
        let mut with_root = inv;
        with_root.routes[0].visited = true;
        assert_eq!(role_default_from(&ctx, "staff", &with_root), None);
    }

    #[test]
    fn obscured_top_covers_appear_in_dead_and_ui_outputs() {
        let mut inv = inventory();
        inv.coverage
            .not_exercised_by_reason
            .insert("obscured".into(), 214);
        inv.coverage.obscured_top_covers = vec![
            crate::inventory::ObscuredCover {
                cover: "div[data-radix-overlay]".into(),
                count: 180,
            },
            crate::inventory::ObscuredCover {
                cover: ".ai-chat-widget".into(),
                count: 34,
            },
        ];

        let expected =
            "obscured: 214 (top covers: div[data-radix-overlay] (180), .ai-chat-widget (34))";

        // `dead` text output includes top covers in caveat.
        let dead_text = dead_output(&inv, false, false).unwrap();
        assert!(dead_text.contains(expected), "{dead_text}");

        // `dead --json` includes both `coverage.obscured_top_covers` and caveat text.
        let dead_json: serde_json::Value =
            serde_json::from_str(&dead_output(&inv, false, true).unwrap()).unwrap();
        assert_eq!(
            dead_json["coverage"]["obscured_top_covers"][0]["cover"],
            "div[data-radix-overlay]"
        );
        assert_eq!(
            dead_json["coverage"]["obscured_top_covers"][0]["count"],
            180
        );
        assert!(
            dead_json["caveat"].as_str().unwrap().contains(expected),
            "{dead_json}"
        );

        // `ui` table output includes top covers in coverage summary.
        let ui_table = ui_output(&inv, &ui_args()).unwrap();
        assert!(ui_table.contains(expected), "{ui_table}");

        // `ui --json` and `ui --compact` include `coverage.obscured_top_covers`.
        let mut json_args = ui_args();
        json_args.json = true;
        let ui_json: serde_json::Value =
            serde_json::from_str(&ui_output(&inv, &json_args).unwrap()).unwrap();
        assert_eq!(
            ui_json["coverage"]["obscured_top_covers"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let mut compact_args = ui_args();
        compact_args.compact = true;
        let ui_compact: serde_json::Value =
            serde_json::from_str(&ui_output(&inv, &compact_args).unwrap()).unwrap();
        assert_eq!(
            ui_compact["coverage"]["obscured_top_covers"][1]["cover"],
            ".ai-chat-widget"
        );
        assert_eq!(
            ui_compact["coverage"]["obscured_top_covers"][1]["count"],
            34
        );

        // Absent when empty.
        let plain = inventory();
        let plain_compact: serde_json::Value =
            serde_json::from_str(&ui_output(&plain, &compact_args).unwrap()).unwrap();
        assert!(
            plain_compact["coverage"]
                .get("obscured_top_covers")
                .is_none()
        );
    }
}
