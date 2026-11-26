//! Multi-role access regression diffing and cross-app behavioral parity.
//!
//! Two complementary layers built on top of [`Inventory`] and
//! [`crate::front::role_access`]:
//!
//! 1. **Multi-Role Access Diff** ([`diff_role_access`]): compares route × role
//!    access matrices between two multi-role map sets and surfaces RBAC
//!    regressions (`AccessGained`, `AccessLost`, `RoleError`, `StatusChanged`)
//!    while keeping coverage gaps (`NotLinked` / `NotReached` / `NotMapped`)
//!    out of regression counts.
//! 2. **Cross-App Behavioral Parity** ([`compute_parity`], [`load_map_source`]):
//!    compares a baseline map source against a candidate (single inventory JSON,
//!    `.brokenapp/map`, `.brokenapp/history`, or `.brokenapp` state dir) across
//!    routes, observed HTTP endpoints, per-role UI controls, and role access.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::front::project::{ANONYMOUS_ROLE, LATEST_INVENTORY, STATE_DIR_NAME};
use crate::front::role_access::{
    Access, EndpointAccess, inventory_endpoint_access, norm_route, route_access,
};
use crate::inventory::render::md_cell;
use crate::inventory::{ChangeSet, Inventory, Outcome, stable_endpoint};

/// Optional alternate filename supported in `.brokenapp/map` exports.
const UI_INVENTORY_JSON: &str = "ui-inventory.json";

/// Deterministic role ordering: `anonymous` first, then alphabetical.
fn role_order_key(role: &str) -> (u8, &str) {
    (if role == ANONYMOUS_ROLE { 0 } else { 1 }, role)
}

fn sorted_roles<I, S>(iter: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut v: Vec<String> = iter.into_iter().map(Into::into).collect();
    v.sort_by(|a, b| role_order_key(a).cmp(&role_order_key(b)));
    v.dedup();
    v
}

// ============================================================================
// Part 1 — Multi-Role Access Diff
// ============================================================================

/// Kind of meaningful route × role access transition.
///
/// Ordered most severe first so sorting places critical RBAC escalations at the top.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RoleAccessChangeKind {
    /// Previously denied (`login` / `forbidden` / `redirected`) and now `visited`.
    /// Critical RBAC privilege-escalation regression signal.
    AccessGained,
    /// Previously `visited` and now denied (`login` / `forbidden` / `redirected`) or `error`.
    AccessLost,
    /// Route newly returning an HTTP 4xx/5xx error (not previously `visited` or `error`).
    RoleError,
    /// Other explicit access state transition (e.g., `login` <-> `forbidden`, `error` -> `visited`).
    StatusChanged,
}

impl RoleAccessChangeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoleAccessChangeKind::AccessGained => "access_gained",
            RoleAccessChangeKind::AccessLost => "access_lost",
            RoleAccessChangeKind::RoleError => "role_error",
            RoleAccessChangeKind::StatusChanged => "status_changed",
        }
    }

    pub fn heading(&self) -> &'static str {
        match self {
            RoleAccessChangeKind::AccessGained => "ACCESS GAINED",
            RoleAccessChangeKind::AccessLost => "ACCESS LOST",
            RoleAccessChangeKind::RoleError => "ROLE ERROR",
            RoleAccessChangeKind::StatusChanged => "ACCESS CHANGED",
        }
    }
}

impl std::fmt::Display for RoleAccessChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One meaningful `(role, route)` access change between two multi-role snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleAccessChange {
    pub kind: RoleAccessChangeKind,
    pub role: String,
    pub route: String,
    pub old_access: Access,
    pub new_access: Access,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_status: Option<u16>,
    /// Concise human line, e.g. `ACCESS GAINED member /admin (was forbidden)`.
    pub line: String,
}

/// Kind of meaningful endpoint × role access transition.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAccessChangeKind {
    /// Previously `forbidden` (401/403) and now `allowed`, OR newly `allowed`
    /// for this role on an already-visited route when the endpoint previously
    /// belonged only to another role.
    EndpointAccessGained,
    /// Previously `allowed` and now `forbidden` (401/403).
    EndpointAccessLost,
}

impl EndpointAccessChangeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointAccessChangeKind::EndpointAccessGained => "endpoint_access_gained",
            EndpointAccessChangeKind::EndpointAccessLost => "endpoint_access_lost",
        }
    }

    pub fn heading(&self) -> &'static str {
        match self {
            EndpointAccessChangeKind::EndpointAccessGained => "ENDPOINT ACCESS GAINED",
            EndpointAccessChangeKind::EndpointAccessLost => "ENDPOINT ACCESS LOST",
        }
    }
}

/// One meaningful `(role, endpoint)` access change between two multi-role snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointAccessChange {
    pub kind: EndpointAccessChangeKind,
    pub role: String,
    pub endpoint: String,
    pub old_access: EndpointAccess,
    pub new_access: EndpointAccess,
    /// Concise human line, e.g. `ENDPOINT ACCESS GAINED member GET /api/admin/users (was forbidden)`.
    pub line: String,
}

/// Diff of route × role and endpoint × role access across two multi-role inventory sets.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleAccessDiff {
    pub roles_compared: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles_only_in_old: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles_only_in_new: Vec<String>,
    pub changes: Vec<RoleAccessChange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_changes: Vec<EndpointAccessChange>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub summary: BTreeMap<String, u32>,
    /// Coverage-gap transitions (`not_linked` / `not_reached` / `not_mapped`)
    /// separated from RBAC regressions to avoid noisy false alarms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_notes: Vec<String>,
}

impl RoleAccessDiff {
    pub fn count(&self, kind: RoleAccessChangeKind) -> u32 {
        self.summary.get(kind.as_str()).copied().unwrap_or(0)
    }

    pub fn endpoint_count(&self, kind: EndpointAccessChangeKind) -> u32 {
        self.summary.get(kind.as_str()).copied().unwrap_or(0)
    }

    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty() || !self.endpoint_changes.is_empty()
    }

    pub fn has_rbac_regression(&self) -> bool {
        self.count(RoleAccessChangeKind::AccessGained) > 0
            || self.count(RoleAccessChangeKind::AccessLost) > 0
            || !self.endpoint_changes.is_empty()
    }

    pub fn endpoint_access_gained(&self) -> impl Iterator<Item = &EndpointAccessChange> {
        self.endpoint_changes
            .iter()
            .filter(|c| c.kind == EndpointAccessChangeKind::EndpointAccessGained)
    }

    pub fn endpoint_access_lost(&self) -> impl Iterator<Item = &EndpointAccessChange> {
        self.endpoint_changes
            .iter()
            .filter(|c| c.kind == EndpointAccessChangeKind::EndpointAccessLost)
    }

    pub fn access_gained(&self) -> impl Iterator<Item = &RoleAccessChange> {
        self.changes
            .iter()
            .filter(|c| c.kind == RoleAccessChangeKind::AccessGained)
    }

    pub fn access_lost(&self) -> impl Iterator<Item = &RoleAccessChange> {
        self.changes
            .iter()
            .filter(|c| c.kind == RoleAccessChangeKind::AccessLost)
    }

    pub fn role_errors(&self) -> impl Iterator<Item = &RoleAccessChange> {
        self.changes
            .iter()
            .filter(|c| c.kind == RoleAccessChangeKind::RoleError)
    }
}

#[derive(Debug, Clone, Copy)]
struct RouteObservation {
    access: Access,
    status: Option<u16>,
}

/// Best observed `(Access, Option<u16>)` per normalized route in one inventory.
///
/// When an inventory has a global app shell (`*` controls across >= 3 routes),
/// a route entry marked `visited: true` with zero route-scoped controls, zero
/// global shell controls covering it, and zero concrete variants indicates an
/// empty/unhydrated shell captured mid-redirect or before mount. Treat it as
/// `NotReached` so it appears in coverage notes rather than firing a false
/// `ACCESS GAINED` / `ACCESS LOST` RBAC regression.
fn route_observations(inv: &Inventory) -> BTreeMap<String, RouteObservation> {
    let has_global_shell = inv
        .controls
        .iter()
        .any(|c| c.route == "*" && c.routes.len() >= 3);
    let mut routes_with_controls: BTreeSet<String> = BTreeSet::new();
    if has_global_shell {
        for c in &inv.controls {
            for r in c.present_on() {
                if r != "*" {
                    routes_with_controls.insert(norm_route(r));
                }
            }
        }
    }

    let mut out: BTreeMap<String, RouteObservation> = BTreeMap::new();
    for r in &inv.routes {
        let key = norm_route(&r.route);
        let mut access = route_access(r);
        if access == Access::Visited
            && has_global_shell
            && r.controls == 0
            && r.variants.is_empty()
            && !routes_with_controls.contains(&key)
        {
            access = Access::NotReached;
        }
        let obs = RouteObservation {
            access,
            status: r.status,
        };
        out.entry(key)
            .and_modify(|cur| {
                if access == Access::Visited
                    || (cur.access != Access::Visited && access < cur.access)
                {
                    *cur = obs;
                }
            })
            .or_insert(obs);
    }
    out
}

/// Compare route × role access between two multi-role inventory sets.
///
/// Only roles present in both `old_roles` and `new_roles` are diffed per route;
/// roles missing from one side are reported in `roles_only_in_old` /
/// `roles_only_in_new`. Coverage-gap transitions (`not_linked`, `not_reached`,
/// `not_mapped`) are tracked in `coverage_notes` rather than as regressions
/// (except when a route newly produces an explicit HTTP 4xx/5xx `Error`).
pub fn diff_role_access(
    old_roles: &BTreeMap<String, Inventory>,
    new_roles: &BTreeMap<String, Inventory>,
) -> RoleAccessDiff {
    let roles_compared = sorted_roles(
        old_roles
            .keys()
            .filter(|r| new_roles.contains_key(*r))
            .cloned(),
    );
    let roles_only_in_old = sorted_roles(
        old_roles
            .keys()
            .filter(|r| !new_roles.contains_key(*r))
            .cloned(),
    );
    let roles_only_in_new = sorted_roles(
        new_roles
            .keys()
            .filter(|r| !old_roles.contains_key(*r))
            .cloned(),
    );

    let old_obs: BTreeMap<&str, BTreeMap<String, RouteObservation>> = old_roles
        .iter()
        .map(|(role, inv)| (role.as_str(), route_observations(inv)))
        .collect();
    let new_obs: BTreeMap<&str, BTreeMap<String, RouteObservation>> = new_roles
        .iter()
        .map(|(role, inv)| (role.as_str(), route_observations(inv)))
        .collect();

    let all_routes: BTreeSet<String> = old_obs
        .values()
        .chain(new_obs.values())
        .flat_map(|m| m.keys().cloned())
        .collect();

    let mut changes: Vec<RoleAccessChange> = Vec::new();
    let mut coverage_notes: Vec<String> = Vec::new();

    for role in &roles_compared {
        let old_map = &old_obs[role.as_str()];
        let new_map = &new_obs[role.as_str()];
        let mut role_cov: Vec<String> = Vec::new();

        for route in &all_routes {
            let old_entry = old_map.get(route).copied().unwrap_or(RouteObservation {
                access: Access::NotLinked,
                status: None,
            });
            let new_entry = new_map.get(route).copied().unwrap_or(RouteObservation {
                access: Access::NotLinked,
                status: None,
            });
            let (old_a, new_a) = (old_entry.access, new_entry.access);
            if old_a == new_a {
                continue;
            }

            // 1. Denied -> Visited: critical RBAC escalation!
            if old_a.denied() && new_a == Access::Visited {
                let line = format!("ACCESS GAINED {role} {route} (was {})", old_a.label());
                changes.push(RoleAccessChange {
                    kind: RoleAccessChangeKind::AccessGained,
                    role: role.clone(),
                    route: route.clone(),
                    old_access: old_a,
                    new_access: new_a,
                    old_status: old_entry.status,
                    new_status: new_entry.status,
                    line,
                });
                continue;
            }

            // 2. Visited -> Denied or Error: access lost!
            if old_a == Access::Visited && (new_a.denied() || new_a == Access::Error) {
                let line = format!(
                    "ACCESS LOST {role} {route} (was {}, now {})",
                    old_a.label(),
                    new_a.label()
                );
                changes.push(RoleAccessChange {
                    kind: RoleAccessChangeKind::AccessLost,
                    role: role.clone(),
                    route: route.clone(),
                    old_access: old_a,
                    new_access: new_a,
                    old_status: old_entry.status,
                    new_status: new_entry.status,
                    line,
                });
                continue;
            }

            // 3. Newly returning an HTTP 4xx/5xx error (not previously Visited or Error).
            if new_a == Access::Error {
                let status_detail = match new_entry.status {
                    Some(code) => format!(", HTTP {code}"),
                    None => String::new(),
                };
                let line = if old_a.is_coverage_gap() {
                    format!("ROLE ERROR {role} {route} (now error{status_detail})")
                } else {
                    format!(
                        "ROLE ERROR {role} {route} (was {}, now error{status_detail})",
                        old_a.label()
                    )
                };
                changes.push(RoleAccessChange {
                    kind: RoleAccessChangeKind::RoleError,
                    role: role.clone(),
                    route: route.clone(),
                    old_access: old_a,
                    new_access: new_a,
                    old_status: old_entry.status,
                    new_status: new_entry.status,
                    line,
                });
                continue;
            }

            // 4. Coverage-gap transitions: separate from RBAC regressions.
            if old_a.is_coverage_gap() || new_a.is_coverage_gap() {
                role_cov.push(format!("{route}: {} -> {}", old_a.label(), new_a.label()));
                continue;
            }

            // 5. Other explicit access status transitions (e.g. login <-> forbidden, error -> visited).
            let line = format!(
                "ACCESS CHANGED {role} {route} ({} -> {})",
                old_a.label(),
                new_a.label()
            );
            changes.push(RoleAccessChange {
                kind: RoleAccessChangeKind::StatusChanged,
                role: role.clone(),
                route: route.clone(),
                old_access: old_a,
                new_access: new_a,
                old_status: old_entry.status,
                new_status: new_entry.status,
                line,
            });
        }

        if !role_cov.is_empty() {
            const MAX_PREVIEW: usize = 5;
            let shown: Vec<&str> = role_cov
                .iter()
                .take(MAX_PREVIEW)
                .map(String::as_str)
                .collect();
            let more = role_cov.len().saturating_sub(shown.len());
            let suffix = if more > 0 {
                format!(" (+{more} more)")
            } else {
                String::new()
            };
            coverage_notes.push(format!(
                "{role}: {} coverage transition{} not counted as access regression ({}{suffix})",
                role_cov.len(),
                if role_cov.len() == 1 { "" } else { "s" },
                shown.join(", ")
            ));
        }
    }

    changes.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| role_order_key(&a.role).cmp(&role_order_key(&b.role)))
            .then_with(|| a.route.cmp(&b.route))
    });

    // Coverage-aware Endpoint × Role diff across compared roles.
    let old_ep_obs: BTreeMap<&str, BTreeMap<String, (EndpointAccess, bool)>> = old_roles
        .iter()
        .map(|(role, inv)| (role.as_str(), inventory_endpoint_access(inv)))
        .collect();
    let new_ep_obs: BTreeMap<&str, BTreeMap<String, (EndpointAccess, bool)>> = new_roles
        .iter()
        .map(|(role, inv)| (role.as_str(), inventory_endpoint_access(inv)))
        .collect();
    let baseline_exposed_roles: BTreeMap<String, BTreeSet<&str>> = {
        let mut map: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for (role, eps) in &old_ep_obs {
            for (ep, (acc, _)) in eps {
                if acc.exposed() {
                    map.entry(ep.clone()).or_default().insert(*role);
                }
            }
        }
        map
    };
    let all_endpoints: BTreeSet<String> = old_ep_obs
        .values()
        .chain(new_ep_obs.values())
        .flat_map(|m| m.keys().cloned())
        .collect();

    let endpoint_trigger_routes = |inv: &Inventory, ep_key: &str| -> BTreeSet<String> {
        let mut routes = BTreeSet::new();
        let ctrl_routes: BTreeMap<&str, Vec<String>> = inv
            .controls
            .iter()
            .map(|c| {
                (
                    c.key.as_str(),
                    c.present_on()
                        .into_iter()
                        .filter(|r| *r != "*")
                        .map(norm_route)
                        .collect(),
                )
            })
            .collect();
        for e in &inv.endpoints {
            if stable_endpoint(&e.endpoint) != ep_key {
                continue;
            }
            for r in &e.on_load {
                if r != "*" {
                    routes.insert(norm_route(r));
                }
            }
            for ck in &e.controls {
                if let Some(rs) = ctrl_routes.get(ck.as_str()) {
                    routes.extend(rs.iter().cloned());
                }
            }
        }
        for c in &inv.controls {
            for o in &c.outcomes {
                if let Outcome::Calls { endpoint, .. } = o
                    && stable_endpoint(endpoint) == ep_key
                {
                    for r in c.present_on() {
                        if r != "*" {
                            routes.insert(norm_route(r));
                        }
                    }
                }
            }
        }
        routes
    };

    let mut endpoint_changes: Vec<EndpointAccessChange> = Vec::new();
    for role in &roles_compared {
        let old_eps = &old_ep_obs[role.as_str()];
        let new_eps = &new_ep_obs[role.as_str()];
        let old_visited_routes: BTreeSet<String> = old_obs[role.as_str()]
            .iter()
            .filter(|(_, obs)| obs.access == Access::Visited)
            .map(|(r, _)| r.clone())
            .collect();
        let new_inv = &new_roles[role.as_str()];

        for ep in &all_endpoints {
            let old_a = old_eps.get(ep).map_or(EndpointAccess::NotSeen, |(a, _)| *a);
            let new_a = new_eps.get(ep).map_or(EndpointAccess::NotSeen, |(a, _)| *a);
            if old_a == new_a {
                continue;
            }

            // 1. Explicitly forbidden -> allowed (or write_guarded): unambiguous escalation.
            if old_a.denied() && new_a.exposed() {
                let line = format!(
                    "ENDPOINT ACCESS GAINED {role} {ep} (was {}, now {})",
                    old_a.label(),
                    new_a.label()
                );
                endpoint_changes.push(EndpointAccessChange {
                    kind: EndpointAccessChangeKind::EndpointAccessGained,
                    role: role.clone(),
                    endpoint: ep.clone(),
                    old_access: old_a,
                    new_access: new_a,
                    line,
                });
                continue;
            }

            // 2. Previously not_seen -> now allowed/write_guarded on an endpoint that
            //    already existed in baseline for another role, triggered from a route
            //    this role had already visited in baseline (avoids false positives on
            //    brand-new features or newly discovered routes).
            if old_a == EndpointAccess::NotSeen
                && new_a.exposed()
                && baseline_exposed_roles
                    .get(ep)
                    .is_some_and(|roles| !roles.is_empty() && !roles.contains(role.as_str()))
            {
                let triggers = endpoint_trigger_routes(new_inv, ep);
                let route_already_covered =
                    triggers.is_empty() || triggers.iter().any(|r| old_visited_routes.contains(r));
                if route_already_covered {
                    let line = format!(
                        "ENDPOINT ACCESS GAINED {role} {ep} (was not_seen for {role}, now {})",
                        new_a.label()
                    );
                    endpoint_changes.push(EndpointAccessChange {
                        kind: EndpointAccessChangeKind::EndpointAccessGained,
                        role: role.clone(),
                        endpoint: ep.clone(),
                        old_access: old_a,
                        new_access: new_a,
                        line,
                    });
                }
                continue;
            }

            // 3. Previously allowed/write_guarded -> explicitly forbidden (401/403).
            if old_a.exposed() && new_a.denied() {
                let line = format!(
                    "ENDPOINT ACCESS LOST {role} {ep} (was {}, now forbidden)",
                    old_a.label()
                );
                endpoint_changes.push(EndpointAccessChange {
                    kind: EndpointAccessChangeKind::EndpointAccessLost,
                    role: role.clone(),
                    endpoint: ep.clone(),
                    old_access: old_a,
                    new_access: new_a,
                    line,
                });
            }
        }
    }

    endpoint_changes.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| role_order_key(&a.role).cmp(&role_order_key(&b.role)))
            .then_with(|| a.endpoint.cmp(&b.endpoint))
    });

    let mut summary: BTreeMap<String, u32> = BTreeMap::new();
    for ch in &changes {
        *summary.entry(ch.kind.as_str().to_string()).or_insert(0) += 1;
    }
    for ch in &endpoint_changes {
        *summary.entry(ch.kind.as_str().to_string()).or_insert(0) += 1;
    }

    RoleAccessDiff {
        roles_compared,
        roles_only_in_old,
        roles_only_in_new,
        changes,
        endpoint_changes,
        summary,
        coverage_notes,
    }
}

// ============================================================================
// Part 2 — Cross-App Behavioral Parity
// ============================================================================

/// Loaded map source (baseline or candidate) containing one or more role inventories.
#[derive(Debug, Clone)]
pub struct MapSource {
    pub label: String,
    pub path: PathBuf,
    pub roles: BTreeMap<String, Inventory>,
}

impl MapSource {
    /// Construct a `MapSource` directly from an in-memory role map (useful for callers and tests).
    pub fn from_roles(label: impl Into<String>, roles: BTreeMap<String, Inventory>) -> Self {
        let label = label.into();
        Self {
            path: PathBuf::from(&label),
            label,
            roles,
        }
    }
}

/// Find the primary inventory JSON inside a single role directory.
fn find_inventory_in_dir(dir: &Path) -> Option<PathBuf> {
    for candidate in [UI_INVENTORY_JSON, LATEST_INVENTORY] {
        let p = dir.join(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    // Fallback: newest timestamped `*.inventory.json` in this directory.
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".inventory.json"))
        })
        .collect();
    files.sort();
    files.pop()
}

/// Load anonymous and `roles/<role>/` inventories from a single directory root
/// into `roles` without overwriting entries already populated from a higher-priority dir.
fn collect_dir_inventories(dir: &Path, roles: &mut BTreeMap<String, Inventory>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    if let Some(top) = find_inventory_in_dir(dir) {
        let inv = crate::inventory::load(&top)?;
        let role = inv
            .role
            .clone()
            .unwrap_or_else(|| ANONYMOUS_ROLE.to_string());
        roles.entry(role).or_insert(inv);
    }
    let roles_dir = dir.join("roles");
    if roles_dir.is_dir() {
        let mut subdirs: Vec<PathBuf> = std::fs::read_dir(&roles_dir)
            .with_context(|| format!("read {}", roles_dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        subdirs.sort();
        for sub in subdirs {
            let Some(role_name) = sub.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(inv_path) = find_inventory_in_dir(&sub) {
                let inv = crate::inventory::load(&inv_path)?;
                roles.entry(role_name.to_string()).or_insert(inv);
            }
        }
    }
    Ok(())
}

/// Load a map source from ANY supported path shape:
///
/// - A single `*.inventory.json` (or `ui-inventory.json`) file;
/// - A `.brokenapp/map` directory containing `ui-inventory.json` /
///   `latest.inventory.json` and optional `roles/<role>/...` (falling back to
///   sibling `../history/` when `map/` only holds rendered Markdown/TSV files);
/// - A `.brokenapp/history` directory containing `latest.inventory.json` and
///   optional `roles/<role>/latest.inventory.json`;
/// - A `.brokenapp` state directory (or project root containing `.brokenapp/`).
pub fn load_map_source(path: &Path) -> Result<MapSource> {
    if !path.exists() {
        bail!("map source does not exist: {}", path.display());
    }
    if path.is_file() {
        let inv = crate::inventory::load(path)?;
        let label = if !inv.project.trim().is_empty() {
            inv.project.clone()
        } else {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("inventory")
                .to_string()
        };
        let role = inv
            .role
            .clone()
            .unwrap_or_else(|| ANONYMOUS_ROLE.to_string());
        let mut roles = BTreeMap::new();
        roles.insert(role, inv);
        return Ok(MapSource {
            label,
            path: path.to_path_buf(),
            roles,
        });
    }

    let mut roles: BTreeMap<String, Inventory> = BTreeMap::new();

    // 1. Direct inventories in `path` (covers `.brokenapp/map`, `.brokenapp/history`, custom export dirs).
    collect_dir_inventories(path, &mut roles)?;

    // 2. `.brokenapp` state dir: check `history/` first, then `map/`.
    collect_dir_inventories(&path.join("history"), &mut roles)?;
    collect_dir_inventories(&path.join("map"), &mut roles)?;

    // 3. Project root containing `.brokenapp/`.
    let nested_state = path.join(STATE_DIR_NAME);
    if roles.is_empty() && nested_state.is_dir() {
        collect_dir_inventories(&nested_state.join("history"), &mut roles)?;
        collect_dir_inventories(&nested_state.join("map"), &mut roles)?;
        collect_dir_inventories(&nested_state, &mut roles)?;
    }

    // 4. Standard `.brokenapp/map` holds rendered docs while JSON lives in sibling `../history`.
    if roles.is_empty()
        && path.file_name().and_then(|n| n.to_str()) == Some("map")
        && let Some(parent) = path.parent()
    {
        collect_dir_inventories(&parent.join("history"), &mut roles)?;
    }

    if roles.is_empty() {
        bail!(
            "no inventory JSON files found in {} (expected ui-inventory.json, latest.inventory.json, or roles/<role>/*.inventory.json)",
            path.display()
        );
    }

    let label = roles
        .values()
        .find_map(|inv| {
            let p = inv.project.trim();
            (!p.is_empty()).then(|| p.to_string())
        })
        .unwrap_or_else(|| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string)
                .unwrap_or_else(|| path.display().to_string())
        });

    Ok(MapSource {
        label,
        path: path.to_path_buf(),
        roles,
    })
}

/// Route that was visited in baseline but regressed to unvisited/denied/error in candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRegression {
    pub route: String,
    pub baseline_access: Access,
    pub candidate_access: Access,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_status: Option<u16>,
    pub detail: String,
}

/// Route-level parity breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RouteParity {
    pub baseline_count: usize,
    pub candidate_count: usize,
    pub matched_count: usize,
    pub parity_pct: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_routes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_routes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regressed_routes: Vec<RouteRegression>,
}

/// Observed HTTP endpoint whose status codes regressed between baseline and candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointStatusRegression {
    pub endpoint: String,
    pub baseline_statuses: Vec<u16>,
    pub candidate_statuses: Vec<u16>,
    pub detail: String,
}

/// Endpoint-level parity breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EndpointParity {
    pub baseline_count: usize,
    pub candidate_count: usize,
    pub matched_count: usize,
    pub parity_pct: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_regressions: Vec<EndpointStatusRegression>,
}

/// Control-level parity diff for one matched role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoleControlParity {
    pub role: String,
    pub baseline_controls: usize,
    pub candidate_controls: usize,
    pub now_dead: u32,
    pub now_broken: u32,
    pub now_no_effect: u32,
    pub removed: u32,
    pub route_content_missing: u32,
    pub rewired: u32,
    pub added: u32,
    pub fixed: u32,
    pub changes: ChangeSet,
}

/// Control-level parity across all matched roles.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ControlParity {
    pub baseline_controls: usize,
    pub candidate_controls: usize,
    pub parity_pct: f64,
    pub now_dead: u32,
    pub now_broken: u32,
    pub now_no_effect: u32,
    pub removed: u32,
    pub route_content_missing: u32,
    pub rewired: u32,
    pub added: u32,
    pub fixed: u32,
    pub per_role: Vec<RoleControlParity>,
}

/// High-level summary counts and overall parity verdict.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ParitySummary {
    pub baseline_routes: usize,
    pub candidate_routes: usize,
    pub missing_routes: usize,
    pub regressed_routes: usize,
    pub route_parity_pct: f64,

    pub baseline_endpoints: usize,
    pub candidate_endpoints: usize,
    pub missing_endpoints: usize,
    pub endpoint_status_regressions: usize,
    pub endpoint_parity_pct: f64,

    pub baseline_controls: usize,
    pub candidate_controls: usize,
    pub controls_now_dead: u32,
    pub controls_now_broken: u32,
    pub controls_now_no_effect: u32,
    pub controls_removed: u32,
    pub controls_route_content_missing: u32,
    pub controls_rewired: u32,
    pub controls_added: u32,
    pub controls_fixed: u32,
    pub control_parity_pct: f64,

    pub roles_compared: usize,
    pub missing_roles: usize,
    pub added_roles: usize,
    pub access_gained: u32,
    pub access_lost: u32,
    pub role_errors: u32,

    pub passed: bool,
}

/// Full behavioral parity comparison report between two map sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParityReport {
    pub baseline: String,
    pub candidate: String,
    pub summary: ParitySummary,
    pub routes: RouteParity,
    pub endpoints: EndpointParity,
    pub controls: ControlParity,
    pub role_access: RoleAccessDiff,
}

fn aggregate_routes(roles: &BTreeMap<String, Inventory>) -> BTreeMap<String, RouteObservation> {
    let mut out: BTreeMap<String, RouteObservation> = BTreeMap::new();
    for inv in roles.values() {
        for (route, obs) in route_observations(inv) {
            out.entry(route)
                .and_modify(|cur| {
                    if obs.access == Access::Visited
                        || (cur.access != Access::Visited && obs.access < cur.access)
                    {
                        *cur = obs;
                    }
                })
                .or_insert(obs);
        }
    }
    out
}

fn aggregate_endpoints(roles: &BTreeMap<String, Inventory>) -> BTreeMap<String, BTreeSet<u16>> {
    let mut out: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    for inv in roles.values() {
        for e in &inv.endpoints {
            let path = e.endpoint.split_once(' ').map_or("", |(_, p)| p);
            if super::build::is_dev_tool_path(path) {
                continue;
            }
            let key = stable_endpoint(&e.endpoint);
            let set = out.entry(key).or_default();
            for &st in &e.statuses {
                set.insert(st);
            }
        }
        // Also collect Calls outcomes in case a minimal inventory omits the reverse index.
        for c in &inv.controls {
            for o in &c.outcomes {
                if let Outcome::Calls {
                    endpoint, status, ..
                } = o
                {
                    let path = endpoint.split_once(' ').map_or("", |(_, p)| p);
                    if super::build::is_dev_tool_path(path) {
                        continue;
                    }
                    let key = stable_endpoint(endpoint);
                    let set = out.entry(key).or_default();
                    if let Some(st) = status {
                        set.insert(*st);
                    }
                }
            }
        }
    }
    out
}

fn is_status_regression(baseline: &[u16], candidate: &[u16]) -> bool {
    let cand_has_5xx = candidate.iter().any(|&s| s >= 500);
    let cand_has_4xx = candidate.iter().any(|&s| (400..500).contains(&s));
    let base_has_5xx = baseline.iter().any(|&s| s >= 500);
    let base_has_4xx = baseline.iter().any(|&s| (400..500).contains(&s));
    let base_has_ok = baseline.iter().any(|&s| s < 400);

    if cand_has_5xx && !base_has_5xx {
        return true;
    }
    if cand_has_4xx && !base_has_4xx && !base_has_5xx {
        return true;
    }
    if base_has_ok && !candidate.iter().any(|&s| s < 400) && (cand_has_4xx || cand_has_5xx) {
        return true;
    }
    false
}

fn format_statuses(statuses: &[u16]) -> String {
    if statuses.is_empty() {
        "none".to_string()
    } else {
        statuses
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn parity_percentage(healthy: usize, total: usize) -> f64 {
    if total == 0 {
        100.0
    } else {
        let pct = (healthy as f64 / total as f64) * 100.0;
        (pct * 10.0).round() / 10.0
    }
}

/// Compare two map sources (`baseline` vs `candidate`) across routes, endpoints,
/// controls, and multi-role access.
pub fn compute_parity(baseline: &MapSource, candidate: &MapSource) -> ParityReport {
    // 1. Routes
    let base_routes = aggregate_routes(&baseline.roles);
    let cand_routes = aggregate_routes(&candidate.roles);

    let mut missing_routes = Vec::new();
    let mut regressed_routes = Vec::new();
    for (route, base_obs) in &base_routes {
        match cand_routes.get(route) {
            None => missing_routes.push(route.clone()),
            Some(cand_obs) => {
                if base_obs.access == Access::Visited && cand_obs.access != Access::Visited {
                    let status_note = match cand_obs.status {
                        Some(code) => format!(" (HTTP {code})"),
                        None => String::new(),
                    };
                    let detail = format!(
                        "{route}: was visited, now {}{status_note}",
                        cand_obs.access.label()
                    );
                    regressed_routes.push(RouteRegression {
                        route: route.clone(),
                        baseline_access: base_obs.access,
                        candidate_access: cand_obs.access,
                        baseline_status: base_obs.status,
                        candidate_status: cand_obs.status,
                        detail,
                    });
                }
            }
        }
    }
    let added_routes: Vec<String> = cand_routes
        .keys()
        .filter(|r| !base_routes.contains_key(*r))
        .cloned()
        .collect();

    let route_matched = base_routes
        .len()
        .saturating_sub(missing_routes.len() + regressed_routes.len());
    let route_parity_pct = parity_percentage(route_matched, base_routes.len());
    let routes = RouteParity {
        baseline_count: base_routes.len(),
        candidate_count: cand_routes.len(),
        matched_count: route_matched,
        parity_pct: route_parity_pct,
        missing_routes,
        added_routes,
        regressed_routes,
    };

    // 2. Endpoints
    let base_eps = aggregate_endpoints(&baseline.roles);
    let cand_eps = aggregate_endpoints(&candidate.roles);

    let mut missing_endpoints = Vec::new();
    let mut status_regressions = Vec::new();
    for (ep, base_set) in &base_eps {
        match cand_eps.get(ep) {
            None => missing_endpoints.push(ep.clone()),
            Some(cand_set) => {
                let b_vec: Vec<u16> = base_set.iter().copied().collect();
                let c_vec: Vec<u16> = cand_set.iter().copied().collect();
                if is_status_regression(&b_vec, &c_vec) {
                    let detail = format!(
                        "{ep}: status regressed ({} -> {})",
                        format_statuses(&b_vec),
                        format_statuses(&c_vec)
                    );
                    status_regressions.push(EndpointStatusRegression {
                        endpoint: ep.clone(),
                        baseline_statuses: b_vec,
                        candidate_statuses: c_vec,
                        detail,
                    });
                }
            }
        }
    }
    let added_endpoints: Vec<String> = cand_eps
        .keys()
        .filter(|e| !base_eps.contains_key(*e))
        .cloned()
        .collect();

    let ep_matched = base_eps
        .len()
        .saturating_sub(missing_endpoints.len() + status_regressions.len());
    let endpoint_parity_pct = parity_percentage(ep_matched, base_eps.len());
    let endpoints = EndpointParity {
        baseline_count: base_eps.len(),
        candidate_count: cand_eps.len(),
        matched_count: ep_matched,
        parity_pct: endpoint_parity_pct,
        missing_endpoints,
        added_endpoints,
        status_regressions,
    };

    // 3. Role Access
    let role_access = diff_role_access(&baseline.roles, &candidate.roles);

    // 4. Controls (per matched role via inventory::diff)
    let mut per_role = Vec::new();
    let mut total_now_dead = 0u32;
    let mut total_now_broken = 0u32;
    let mut total_now_no_effect = 0u32;
    let mut total_removed = 0u32;
    let mut total_route_content_missing = 0u32;
    let mut total_rewired = 0u32;
    let mut total_added = 0u32;
    let mut total_fixed = 0u32;
    let mut regressed_controls = 0usize;

    for role in &role_access.roles_compared {
        let base_inv = &baseline.roles[role];
        let cand_inv = &candidate.roles[role];
        let cs = crate::inventory::diff(Some(base_inv), cand_inv);

        let count_kind = |k: &str| cs.summary.get(k).copied().unwrap_or(0);
        let now_dead = count_kind("now_dead");
        let now_broken = count_kind("now_broken");
        let now_no_effect = count_kind("now_no_effect");
        let removed = count_kind("removed");
        let route_content_missing = count_kind("route_content_missing");
        let rewired = count_kind("rewired");
        let added = count_kind("added");
        let fixed = count_kind("fixed");

        total_now_dead += now_dead;
        total_now_broken += now_broken;
        total_now_no_effect += now_no_effect;
        total_removed += removed;
        total_route_content_missing += route_content_missing;
        total_rewired += rewired;
        total_added += added;
        total_fixed += fixed;

        // Count distinct regressed controls for parity % (never exceeding baseline control count).
        let mut regressed_keys: BTreeSet<&str> = BTreeSet::new();
        let mut missing_routes_in_role: BTreeSet<&str> = BTreeSet::new();
        for ch in &cs.changes {
            match ch.kind.as_str() {
                "now_dead" | "now_broken" | "removed" | "rewired" => {
                    regressed_keys.insert(ch.key.as_str());
                }
                "route_content_missing" => {
                    missing_routes_in_role.insert(ch.route.as_str());
                }
                _ => {}
            }
        }
        let mut role_regressed = regressed_keys.len();
        if !missing_routes_in_role.is_empty() {
            let wiped = base_inv
                .controls
                .iter()
                .filter(|c| {
                    missing_routes_in_role.contains(c.route.as_str())
                        && !regressed_keys.contains(c.key.as_str())
                })
                .count();
            role_regressed = (role_regressed + wiped).min(base_inv.controls.len());
        } else {
            role_regressed = role_regressed.min(base_inv.controls.len());
        }
        regressed_controls += role_regressed;

        per_role.push(RoleControlParity {
            role: role.clone(),
            baseline_controls: base_inv.controls.len(),
            candidate_controls: cand_inv.controls.len(),
            now_dead,
            now_broken,
            now_no_effect,
            removed,
            route_content_missing,
            rewired,
            added,
            fixed,
            changes: cs,
        });
    }

    // Controls in baseline roles completely absent from candidate also count as missing.
    for missing_role in &role_access.roles_only_in_old {
        if let Some(inv) = baseline.roles.get(missing_role) {
            regressed_controls += inv.controls.len();
        }
    }

    let baseline_controls: usize = baseline.roles.values().map(|i| i.controls.len()).sum();
    let candidate_controls: usize = candidate.roles.values().map(|i| i.controls.len()).sum();
    let healthy_controls = baseline_controls.saturating_sub(regressed_controls);
    let control_parity_pct = parity_percentage(healthy_controls, baseline_controls);

    let controls = ControlParity {
        baseline_controls,
        candidate_controls,
        parity_pct: control_parity_pct,
        now_dead: total_now_dead,
        now_broken: total_now_broken,
        now_no_effect: total_now_no_effect,
        removed: total_removed,
        route_content_missing: total_route_content_missing,
        rewired: total_rewired,
        added: total_added,
        fixed: total_fixed,
        per_role,
    };

    let access_gained = role_access.count(RoleAccessChangeKind::AccessGained);
    let access_lost = role_access.count(RoleAccessChangeKind::AccessLost);
    let role_errors = role_access.count(RoleAccessChangeKind::RoleError);

    let passed = routes.missing_routes.is_empty()
        && routes.regressed_routes.is_empty()
        && endpoints.missing_endpoints.is_empty()
        && endpoints.status_regressions.is_empty()
        && controls.now_dead == 0
        && controls.now_broken == 0
        && controls.removed == 0
        && controls.route_content_missing == 0
        && controls.rewired == 0
        && role_access.roles_only_in_old.is_empty()
        && access_gained == 0
        && access_lost == 0
        && role_errors == 0;

    let summary = ParitySummary {
        baseline_routes: routes.baseline_count,
        candidate_routes: routes.candidate_count,
        missing_routes: routes.missing_routes.len(),
        regressed_routes: routes.regressed_routes.len(),
        route_parity_pct: routes.parity_pct,
        baseline_endpoints: endpoints.baseline_count,
        candidate_endpoints: endpoints.candidate_count,
        missing_endpoints: endpoints.missing_endpoints.len(),
        endpoint_status_regressions: endpoints.status_regressions.len(),
        endpoint_parity_pct: endpoints.parity_pct,
        baseline_controls: controls.baseline_controls,
        candidate_controls: controls.candidate_controls,
        controls_now_dead: controls.now_dead,
        controls_now_broken: controls.now_broken,
        controls_now_no_effect: controls.now_no_effect,
        controls_removed: controls.removed,
        controls_route_content_missing: controls.route_content_missing,
        controls_rewired: controls.rewired,
        controls_added: controls.added,
        controls_fixed: controls.fixed,
        control_parity_pct: controls.parity_pct,
        roles_compared: role_access.roles_compared.len(),
        missing_roles: role_access.roles_only_in_old.len(),
        added_roles: role_access.roles_only_in_new.len(),
        access_gained,
        access_lost,
        role_errors,
        passed,
    };

    ParityReport {
        baseline: baseline.label.clone(),
        candidate: candidate.label.clone(),
        summary,
        routes,
        endpoints,
        controls,
        role_access,
    }
}

// ============================================================================
// Renderers: Text & Markdown
// ============================================================================

/// Render a human-readable terminal parity report.
pub fn render_text(report: &ParityReport) -> String {
    let s = &report.summary;
    let verdict = if s.passed { "PASS" } else { "FAIL" };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Behavioral Parity: {} -> {} [{verdict}]",
        report.baseline, report.candidate
    );
    let _ = writeln!(
        out,
        "  Routes:    {:.1}% ({}/{} matched; {} missing, {} regressed, {} added)",
        s.route_parity_pct,
        report.routes.matched_count,
        s.baseline_routes,
        s.missing_routes,
        s.regressed_routes,
        report.routes.added_routes.len()
    );
    let _ = writeln!(
        out,
        "  Endpoints: {:.1}% ({}/{} matched; {} missing, {} status regressions, {} added)",
        s.endpoint_parity_pct,
        report.endpoints.matched_count,
        s.baseline_endpoints,
        s.missing_endpoints,
        s.endpoint_status_regressions,
        report.endpoints.added_endpoints.len()
    );
    let _ = writeln!(
        out,
        "  Controls:  {:.1}% ({} baseline -> {} candidate; {} broken, {} dead, {} no_effect, {} removed, {} rewired, {} added, {} fixed)",
        s.control_parity_pct,
        s.baseline_controls,
        s.candidate_controls,
        s.controls_now_broken,
        s.controls_now_dead,
        s.controls_now_no_effect,
        s.controls_removed + s.controls_route_content_missing,
        s.controls_rewired,
        s.controls_added,
        s.controls_fixed
    );
    let _ = writeln!(
        out,
        "  Roles:     {} compared, {} missing, {} added ({} access_gained, {} access_lost, {} role_errors)",
        s.roles_compared,
        s.missing_roles,
        s.added_roles,
        s.access_gained,
        s.access_lost,
        s.role_errors
    );

    // Role access section
    if !report.role_access.roles_only_in_old.is_empty()
        || !report.role_access.changes.is_empty()
        || !report.role_access.roles_only_in_new.is_empty()
    {
        out.push_str("\nRole Access:\n");
        if !report.role_access.roles_only_in_old.is_empty() {
            let _ = writeln!(
                out,
                "  MISSING ROLES in candidate: {}",
                report.role_access.roles_only_in_old.join(", ")
            );
        }
        if !report.role_access.roles_only_in_new.is_empty() {
            let _ = writeln!(
                out,
                "  ADDED ROLES in candidate: {}",
                report.role_access.roles_only_in_new.join(", ")
            );
        }
        for ch in &report.role_access.changes {
            let tag = if ch.kind == RoleAccessChangeKind::AccessGained {
                "[CRITICAL] "
            } else {
                ""
            };
            let _ = writeln!(out, "  {tag}{}", ch.line);
        }
        for note in &report.role_access.coverage_notes {
            let _ = writeln!(out, "  Note: {note}");
        }
    }

    // Routes section
    if !report.routes.missing_routes.is_empty()
        || !report.routes.regressed_routes.is_empty()
        || !report.routes.added_routes.is_empty()
    {
        out.push_str("\nRoutes:\n");
        for r in &report.routes.missing_routes {
            let _ = writeln!(out, "  MISSING ROUTE {r}");
        }
        for r in &report.routes.regressed_routes {
            let _ = writeln!(out, "  REGRESSED ROUTE {}", r.detail);
        }
        for r in &report.routes.added_routes {
            let _ = writeln!(out, "  ADDED ROUTE {r}");
        }
    }

    // Endpoints section
    if !report.endpoints.missing_endpoints.is_empty()
        || !report.endpoints.status_regressions.is_empty()
        || !report.endpoints.added_endpoints.is_empty()
    {
        out.push_str("\nEndpoints:\n");
        for ep in &report.endpoints.missing_endpoints {
            let _ = writeln!(out, "  MISSING ENDPOINT {ep}");
        }
        for reg in &report.endpoints.status_regressions {
            let _ = writeln!(out, "  ENDPOINT REGRESSION {}", reg.detail);
        }
        for ep in &report.endpoints.added_endpoints {
            let _ = writeln!(out, "  ADDED ENDPOINT {ep}");
        }
    }

    // Controls section
    let any_control_changes = report
        .controls
        .per_role
        .iter()
        .any(|r| !r.changes.changes.is_empty());
    if any_control_changes {
        out.push_str("\nControls:\n");
        for r in &report.controls.per_role {
            if r.changes.changes.is_empty() {
                continue;
            }
            let _ = writeln!(out, "  == {} ==", r.role);
            for ch in &r.changes.changes {
                let _ = writeln!(out, "    {}", ch.line);
            }
            for note in &r.changes.notes {
                let _ = writeln!(out, "    Note: {note}");
            }
        }
    }

    out
}

/// Render a clean PR/audit GitHub-flavored Markdown parity report.
pub fn render_markdown(report: &ParityReport) -> String {
    let s = &report.summary;
    let verdict = if s.passed { "PASS" } else { "FAIL" };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "## BrokenApp Behavioral Parity: `{}` → `{}`\n",
        md_cell(&report.baseline),
        md_cell(&report.candidate)
    );
    let _ = writeln!(out, "**Verdict:** `{verdict}`\n");

    if s.access_gained > 0 {
        let _ = writeln!(
            out,
            "> [!WARNING]\n> **RBAC Escalation (`ACCESS GAINED`)**: {} route(s) previously denied are now reachable in `{}`.\n",
            s.access_gained,
            md_cell(&report.candidate)
        );
    }

    // Summary table
    out.push_str("| Dimension | Parity | Baseline | Candidate | Regressions | Added |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|\n");
    let _ = writeln!(
        out,
        "| Routes | {:.1}% | {} | {} | {} missing, {} regressed | {} |",
        s.route_parity_pct,
        s.baseline_routes,
        s.candidate_routes,
        s.missing_routes,
        s.regressed_routes,
        report.routes.added_routes.len()
    );
    let _ = writeln!(
        out,
        "| Endpoints | {:.1}% | {} | {} | {} missing, {} status | {} |",
        s.endpoint_parity_pct,
        s.baseline_endpoints,
        s.candidate_endpoints,
        s.missing_endpoints,
        s.endpoint_status_regressions,
        report.endpoints.added_endpoints.len()
    );
    let _ = writeln!(
        out,
        "| Controls | {:.1}% | {} | {} | {} broken, {} dead, {} removed, {} rewired | {} (+{} fixed) |",
        s.control_parity_pct,
        s.baseline_controls,
        s.candidate_controls,
        s.controls_now_broken,
        s.controls_now_dead,
        s.controls_removed + s.controls_route_content_missing,
        s.controls_rewired,
        s.controls_added,
        s.controls_fixed
    );
    let _ = writeln!(
        out,
        "| Role Access | {} role(s) | {} | {} | {} gained, {} lost, {} error, {} missing role | {} |\n",
        s.roles_compared,
        s.roles_compared + s.missing_roles,
        s.roles_compared + s.added_roles,
        s.access_gained,
        s.access_lost,
        s.role_errors,
        s.missing_roles,
        s.added_roles
    );

    // Role Access section
    out.push_str("### Role Access Parity\n\n");
    if !report.role_access.roles_only_in_old.is_empty() {
        let _ = writeln!(
            out,
            "- **Missing roles in candidate:** {}\n",
            report
                .role_access
                .roles_only_in_old
                .iter()
                .map(|r| format!("`{}`", md_cell(r)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !report.role_access.roles_only_in_new.is_empty() {
        let _ = writeln!(
            out,
            "- **Added roles in candidate:** {}\n",
            report
                .role_access
                .roles_only_in_new
                .iter()
                .map(|r| format!("`{}`", md_cell(r)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if report.role_access.changes.is_empty() {
        out.push_str("No role access changes detected across shared roles.\n\n");
    } else {
        out.push_str("| Change | Role | Route | Baseline | Candidate | Detail |\n");
        out.push_str("|---|---|---|---|---|---|\n");
        for ch in &report.role_access.changes {
            let badge = if ch.kind == RoleAccessChangeKind::AccessGained {
                "**ACCESS GAINED**"
            } else {
                ch.kind.heading()
            };
            let _ = writeln!(
                out,
                "| {} | `{}` | `{}` | {} | {} | {} |",
                badge,
                md_cell(&ch.role),
                md_cell(&ch.route),
                ch.old_access.label(),
                ch.new_access.label(),
                md_cell(&ch.line)
            );
        }
        out.push('\n');
    }

    // Routes section
    out.push_str("### Route Parity\n\n");
    if report.routes.missing_routes.is_empty()
        && report.routes.regressed_routes.is_empty()
        && report.routes.added_routes.is_empty()
    {
        out.push_str("All baseline routes matched in candidate.\n\n");
    } else {
        out.push_str("| Status | Route | Detail |\n");
        out.push_str("|---|---|---|\n");
        for r in &report.routes.missing_routes {
            let _ = writeln!(
                out,
                "| Missing | `{}` | absent from candidate |",
                md_cell(r)
            );
        }
        for r in &report.routes.regressed_routes {
            let _ = writeln!(
                out,
                "| Regressed | `{}` | {} |",
                md_cell(&r.route),
                md_cell(&r.detail)
            );
        }
        for r in &report.routes.added_routes {
            let _ = writeln!(out, "| Added | `{}` | new in candidate |", md_cell(r));
        }
        out.push('\n');
    }

    // Endpoints section
    out.push_str("### Endpoint Parity\n\n");
    if report.endpoints.missing_endpoints.is_empty()
        && report.endpoints.status_regressions.is_empty()
        && report.endpoints.added_endpoints.is_empty()
    {
        out.push_str("All baseline endpoints matched in candidate.\n\n");
    } else {
        out.push_str("| Status | Endpoint | Detail |\n");
        out.push_str("|---|---|---|\n");
        for ep in &report.endpoints.missing_endpoints {
            let _ = writeln!(
                out,
                "| Missing | `{}` | absent from candidate |",
                md_cell(ep)
            );
        }
        for reg in &report.endpoints.status_regressions {
            let _ = writeln!(
                out,
                "| Status Regression | `{}` | {} -> {} |",
                md_cell(&reg.endpoint),
                format_statuses(&reg.baseline_statuses),
                format_statuses(&reg.candidate_statuses)
            );
        }
        for ep in &report.endpoints.added_endpoints {
            let _ = writeln!(out, "| Added | `{}` | new in candidate |", md_cell(ep));
        }
        out.push('\n');
    }

    // Controls section
    out.push_str("### Control Parity\n\n");
    let total_control_rows: usize = report
        .controls
        .per_role
        .iter()
        .map(|r| r.changes.changes.len())
        .sum();
    if total_control_rows == 0 {
        out.push_str("No element-level control changes across matched roles.\n");
    } else {
        out.push_str("| Role | Kind | Route | Detail |\n");
        out.push_str("|---|---|---|---|\n");
        for r in &report.controls.per_role {
            for ch in &r.changes.changes {
                let route_cell = if ch.route.is_empty() {
                    "-".to_string()
                } else {
                    format!("`{}`", md_cell(&ch.route))
                };
                let _ = writeln!(
                    out,
                    "| `{}` | `{}` | {} | {} |",
                    md_cell(&r.role),
                    md_cell(&ch.kind),
                    route_cell,
                    md_cell(&ch.line)
                );
            }
        }
    }

    out
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{
        Control, ControlStatus, CoverageSummary, EndpointEntry, IDENTITY_VERSION, RouteEntry,
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
            routes: if route == "*" {
                vec!["/".into()]
            } else {
                vec![route.into()]
            },
            role: role.into(),
            label: label.into(),
            locator: format!("text={}", label.to_lowercase()),
            selector: format!("#{}", label.to_lowercase().replace(' ', "-")),
            count: 1,
            status,
            outcomes,
            ..Default::default()
        }
    }

    fn endpoint(ep: &str, statuses: Vec<u16>, controls: Vec<&str>) -> EndpointEntry {
        EndpointEntry {
            endpoint: ep.into(),
            controls: controls.into_iter().map(str::to_string).collect(),
            on_load: Vec::new(),
            statuses,
            write: ep.starts_with("POST") || ep.starts_with("DELETE"),
        }
    }

    fn make_inv(
        project: &str,
        role: Option<&str>,
        routes: Vec<RouteEntry>,
        controls: Vec<Control>,
        endpoints: Vec<EndpointEntry>,
    ) -> Inventory {
        let visited = routes.iter().filter(|r| r.visited).count() as u32;
        let exercised = controls.iter().filter(|c| c.status.is_exercised()).count() as u32;
        Inventory {
            schema: crate::inventory::INVENTORY_SCHEMA.into(),
            identity_version: IDENTITY_VERSION,
            project: project.into(),
            generated_at: "2026-11-20T10:00:00Z".into(),
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
            endpoints,
            ..Default::default()
        }
    }

    #[test]
    fn diff_role_access_detects_access_gained_lost_error_and_ignores_coverage_noise() {
        let mut old_roles = BTreeMap::new();
        old_roles.insert(
            "member".into(),
            make_inv(
                "app",
                Some("member"),
                vec![
                    route("/", true, Some(200), None),
                    route("/admin", true, Some(403), None),
                    route("/secret", false, None, Some("redirects to login")),
                    route("/unlinked", false, None, Some("navigation timeout")),
                ],
                vec![],
                vec![],
            ),
        );
        old_roles.insert(
            "admin".into(),
            make_inv(
                "app",
                Some("admin"),
                vec![
                    route("/", true, Some(200), None),
                    route("/admin", true, Some(200), None),
                    route("/billing", true, Some(200), None),
                    route("/ops", false, None, Some("redirects to login")),
                ],
                vec![],
                vec![],
            ),
        );

        let mut new_roles = BTreeMap::new();
        new_roles.insert(
            "member".into(),
            make_inv(
                "app",
                Some("member"),
                vec![
                    route("/", true, Some(200), None),
                    // RBAC regression: was forbidden, now visited!
                    route("/admin", true, Some(200), None),
                    // Explicit status change: login -> forbidden
                    route("/secret", true, Some(403), None),
                    // Coverage transition: not_reached -> not_linked (omitted)
                ],
                vec![],
                vec![],
            ),
        );
        new_roles.insert(
            "admin".into(),
            make_inv(
                "app",
                Some("admin"),
                vec![
                    route("/", true, Some(200), None),
                    route("/admin", true, Some(200), None),
                    // Access lost: was visited, now 500 error!
                    route("/billing", true, Some(500), None),
                    // Role error: was login, now 500 error!
                    route("/ops", true, Some(500), None),
                ],
                vec![],
                vec![],
            ),
        );

        let diff = diff_role_access(&old_roles, &new_roles);
        assert_eq!(diff.count(RoleAccessChangeKind::AccessGained), 1);
        assert_eq!(diff.count(RoleAccessChangeKind::AccessLost), 1);
        assert_eq!(diff.count(RoleAccessChangeKind::RoleError), 1);
        assert_eq!(diff.count(RoleAccessChangeKind::StatusChanged), 1);
        assert!(diff.has_rbac_regression());

        // Sorted by severity: AccessGained first!
        assert_eq!(diff.changes[0].kind, RoleAccessChangeKind::AccessGained);
        assert_eq!(
            diff.changes[0].line,
            "ACCESS GAINED member /admin (was forbidden)"
        );

        assert_eq!(diff.changes[1].kind, RoleAccessChangeKind::AccessLost);
        assert_eq!(
            diff.changes[1].line,
            "ACCESS LOST admin /billing (was visited, now error)"
        );

        assert_eq!(diff.changes[2].kind, RoleAccessChangeKind::RoleError);
        assert!(
            diff.changes[2]
                .line
                .contains("ROLE ERROR admin /ops (was login, now error, HTTP 500)"),
            "{}",
            diff.changes[2].line
        );

        assert_eq!(diff.changes[3].kind, RoleAccessChangeKind::StatusChanged);
        assert_eq!(
            diff.changes[3].line,
            "ACCESS CHANGED member /secret (login -> forbidden)"
        );

        // Coverage noise went into coverage_notes, NOT into changes!
        assert!(
            diff.coverage_notes
                .iter()
                .any(|n| n.contains("member") && n.contains("/unlinked: not_reached -> not_linked")),
            "{:?}",
            diff.coverage_notes
        );
    }

    #[test]
    fn diff_role_access_tracks_missing_and_added_roles() {
        let mut old_roles = BTreeMap::new();
        old_roles.insert(
            "anonymous".into(),
            make_inv(
                "app",
                None,
                vec![route("/", true, Some(200), None)],
                vec![],
                vec![],
            ),
        );
        old_roles.insert(
            "admin".into(),
            make_inv(
                "app",
                Some("admin"),
                vec![route("/admin", true, Some(200), None)],
                vec![],
                vec![],
            ),
        );

        let mut new_roles = BTreeMap::new();
        new_roles.insert(
            "anonymous".into(),
            make_inv(
                "app",
                None,
                vec![route("/", true, Some(200), None)],
                vec![],
                vec![],
            ),
        );
        new_roles.insert(
            "support".into(),
            make_inv(
                "app",
                Some("support"),
                vec![route("/tickets", true, Some(200), None)],
                vec![],
                vec![],
            ),
        );

        let diff = diff_role_access(&old_roles, &new_roles);
        assert_eq!(diff.roles_compared, vec!["anonymous"]);
        assert_eq!(diff.roles_only_in_old, vec!["admin"]);
        assert_eq!(diff.roles_only_in_new, vec!["support"]);
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn compute_parity_detects_full_parity_when_identical() {
        let inv = make_inv(
            "legacy",
            None,
            vec![
                route("/", true, Some(200), None),
                route("/checkout", true, Some(200), None),
            ],
            vec![
                control(
                    "/",
                    "link",
                    "Checkout",
                    ControlStatus::Ok,
                    vec![Outcome::Navigates {
                        to: "/checkout".into(),
                    }],
                ),
                control(
                    "/checkout",
                    "button",
                    "Pay",
                    ControlStatus::Ok,
                    vec![Outcome::Calls {
                        endpoint: "POST /api/pay".into(),
                        status: Some(200),
                        blocked: false,
                    }],
                ),
            ],
            vec![endpoint(
                "POST /api/pay",
                vec![200],
                vec!["/checkout|button|text=pay"],
            )],
        );

        let mut b_roles = BTreeMap::new();
        b_roles.insert("anonymous".into(), inv.clone());
        let mut c_roles = BTreeMap::new();
        c_roles.insert("anonymous".into(), inv);

        let base = MapSource::from_roles("legacy", b_roles);
        let cand = MapSource::from_roles("rewrite", c_roles);
        let report = compute_parity(&base, &cand);

        assert!(report.summary.passed);
        assert_eq!(report.summary.route_parity_pct, 100.0);
        assert_eq!(report.summary.endpoint_parity_pct, 100.0);
        assert_eq!(report.summary.control_parity_pct, 100.0);

        let text = render_text(&report);
        assert!(text.contains("[PASS]"), "{text}");
        let md = render_markdown(&report);
        assert!(md.contains("**Verdict:** `PASS`"), "{md}");
    }

    #[test]
    fn compute_parity_surfaces_all_regression_dimensions() {
        let mut base_roles = BTreeMap::new();
        base_roles.insert(
            "anonymous".into(),
            make_inv(
                "legacy",
                None,
                vec![
                    route("/", true, Some(200), None),
                    route("/checkout", true, Some(200), None),
                    route("/pricing", true, Some(200), None),
                    route("/admin", false, None, Some("redirects to login")),
                ],
                vec![
                    control(
                        "/",
                        "button",
                        "Subscribe",
                        ControlStatus::Ok,
                        vec![Outcome::Calls {
                            endpoint: "POST /api/subscribe".into(),
                            status: Some(200),
                            blocked: false,
                        }],
                    ),
                    control(
                        "/",
                        "button",
                        "Help",
                        ControlStatus::Ok,
                        vec![Outcome::DomChange {
                            kind: "modal".into(),
                        }],
                    ),
                    control(
                        "/",
                        "link",
                        "Docs",
                        ControlStatus::Ok,
                        vec![Outcome::Navigates { to: "/docs".into() }],
                    ),
                ],
                vec![
                    endpoint(
                        "POST /api/subscribe",
                        vec![200],
                        vec!["/|button|text=subscribe"],
                    ),
                    endpoint("GET /api/plans", vec![200], vec![]),
                ],
            ),
        );
        base_roles.insert(
            "admin".into(),
            make_inv(
                "legacy",
                Some("admin"),
                vec![route("/admin", true, Some(200), None)],
                vec![control(
                    "/admin",
                    "button",
                    "Nuke",
                    ControlStatus::Ok,
                    vec![Outcome::Calls {
                        endpoint: "DELETE /api/all".into(),
                        status: Some(200),
                        blocked: false,
                    }],
                )],
                vec![endpoint(
                    "DELETE /api/all",
                    vec![200],
                    vec!["/admin|button|text=nuke"],
                )],
            ),
        );

        let mut cand_roles = BTreeMap::new();
        cand_roles.insert(
            "anonymous".into(),
            make_inv(
                "rewrite",
                None,
                vec![
                    route("/", true, Some(200), None),
                    // Regressed: visited -> 500 error!
                    route("/checkout", true, Some(500), None),
                    // Missing: /pricing omitted!
                    // RBAC escalation: anonymous was login, now visited!
                    route("/admin", true, Some(200), None),
                    // Added route:
                    route("/changelog", true, Some(200), None),
                ],
                vec![
                    // Status regressed endpoint & now_broken control:
                    control(
                        "/",
                        "button",
                        "Subscribe",
                        ControlStatus::Broken,
                        vec![Outcome::Calls {
                            endpoint: "POST /api/subscribe".into(),
                            status: Some(500),
                            blocked: false,
                        }],
                    ),
                    // Now dead:
                    control("/", "button", "Help", ControlStatus::Dead, vec![]),
                    // Rewired:
                    control(
                        "/",
                        "link",
                        "Docs",
                        ControlStatus::Ok,
                        vec![Outcome::Navigates {
                            to: "/manual".into(),
                        }],
                    ),
                ],
                vec![
                    endpoint(
                        "POST /api/subscribe",
                        vec![500],
                        vec!["/|button|text=subscribe"],
                    ),
                    // Missing GET /api/plans; added GET /api/health
                    endpoint("GET /api/health", vec![200], vec![]),
                ],
            ),
        );
        // admin role completely missing in candidate!

        let base = MapSource::from_roles("legacy", base_roles);
        let cand = MapSource::from_roles("rewrite", cand_roles);
        let report = compute_parity(&base, &cand);

        assert!(!report.summary.passed);
        assert_eq!(report.routes.missing_routes, vec!["/pricing"]);
        assert_eq!(report.routes.added_routes, vec!["/changelog"]);
        assert_eq!(report.routes.regressed_routes.len(), 1);
        assert_eq!(report.routes.regressed_routes[0].route, "/checkout");

        assert!(
            report
                .endpoints
                .missing_endpoints
                .contains(&"GET /api/plans".to_string())
        );
        assert!(
            report
                .endpoints
                .added_endpoints
                .contains(&"GET /api/health".to_string())
        );
        assert_eq!(report.endpoints.status_regressions.len(), 1);
        assert_eq!(
            report.endpoints.status_regressions[0].endpoint,
            "POST /api/subscribe"
        );

        assert_eq!(report.summary.controls_now_broken, 1);
        assert_eq!(report.summary.controls_now_dead, 1);
        assert_eq!(report.summary.controls_rewired, 1);
        assert_eq!(report.summary.missing_roles, 1);
        assert_eq!(report.summary.access_gained, 1);

        let md = render_markdown(&report);
        assert!(md.contains("**Verdict:** `FAIL`"), "{md}");
        assert!(md.contains("RBAC Escalation (`ACCESS GAINED`)"), "{md}");
        assert!(md.contains("`admin`"), "{md}");
        assert!(md.contains("`/pricing`"), "{md}");
        assert!(md.contains("`POST /api/subscribe`"), "{md}");

        let text = render_text(&report);
        assert!(text.contains("[FAIL]"), "{text}");
        assert!(
            text.contains("[CRITICAL] ACCESS GAINED anonymous /admin (was login)"),
            "{text}"
        );
    }

    #[test]
    fn load_map_source_handles_file_map_dir_history_dir_and_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let anon = make_inv(
            "demo",
            None,
            vec![route("/", true, Some(200), None)],
            vec![],
            vec![],
        );
        let admin = make_inv(
            "demo",
            Some("admin"),
            vec![route("/admin", true, Some(200), None)],
            vec![],
            vec![],
        );

        // 1. Single inventory file
        let single = dir.path().join("single.inventory.json");
        crate::inventory::save(&anon, &single).unwrap();
        let src_file = load_map_source(&single).unwrap();
        assert_eq!(src_file.roles.len(), 1);
        assert!(src_file.roles.contains_key("anonymous"));

        // 2. `.brokenapp/map` dir with `ui-inventory.json` + `roles/admin/ui-inventory.json`
        let map_export = dir.path().join("export-map");
        crate::inventory::save(&anon, &map_export.join("ui-inventory.json")).unwrap();
        crate::inventory::save(&admin, &map_export.join("roles/admin/ui-inventory.json")).unwrap();
        let src_export = load_map_source(&map_export).unwrap();
        assert_eq!(src_export.roles.len(), 2);
        assert!(src_export.roles.contains_key("anonymous"));
        assert!(src_export.roles.contains_key("admin"));

        // 3. Full `.brokenapp` state dir with `history/` and `map/` (where `map/` only has markdown)
        let state = dir.path().join("proj/.brokenapp");
        std::fs::create_dir_all(state.join("map")).unwrap();
        std::fs::write(state.join("map/UI-MAP.md"), "# UI map").unwrap();
        crate::inventory::save(&anon, &state.join("history/latest.inventory.json")).unwrap();
        crate::inventory::save(
            &admin,
            &state.join("history/roles/admin/latest.inventory.json"),
        )
        .unwrap();

        // Loading `.brokenapp` state dir:
        let src_state = load_map_source(&state).unwrap();
        assert_eq!(src_state.roles.len(), 2);
        // Loading `.brokenapp/history`:
        let src_hist = load_map_source(&state.join("history")).unwrap();
        assert_eq!(src_hist.roles.len(), 2);
        // Loading `.brokenapp/map` falls back to sibling `../history`:
        let src_map_fallback = load_map_source(&state.join("map")).unwrap();
        assert_eq!(src_map_fallback.roles.len(), 2);
        // Loading project root falls back to `.brokenapp`:
        let src_root = load_map_source(&dir.path().join("proj")).unwrap();
        assert_eq!(src_root.roles.len(), 2);

        // Missing or empty directories error cleanly:
        assert!(load_map_source(&dir.path().join("does-not-exist")).is_err());
        let empty_dir = dir.path().join("empty");
        std::fs::create_dir_all(&empty_dir).unwrap();
        assert!(load_map_source(&empty_dir).is_err());
    }

    #[test]
    fn diff_role_access_handles_all_denied_variants_error_recovery_and_trailing_slashes() {
        let mut old_roles = BTreeMap::new();
        old_roles.insert(
            "member".into(),
            make_inv(
                "app",
                Some("member"),
                vec![
                    route("/a/", false, None, Some("redirects to login")),
                    route("/b", true, Some(401), None),
                    route("/c", false, None, Some("redirected elsewhere")),
                    route("/d", true, Some(500), None), // Error -> Visited = StatusChanged (NOT AccessGained)
                    route("/e", true, Some(200), None), // Visited -> Forbidden = AccessLost
                    route("/f", true, Some(200), None), // Visited -> Redirected = AccessLost
                ],
                vec![],
                vec![],
            ),
        );
        let mut new_roles = BTreeMap::new();
        new_roles.insert(
            "member".into(),
            make_inv(
                "app",
                Some("member"),
                vec![
                    route("/a", true, Some(200), None),
                    route("/b/", true, Some(200), None),
                    route("/c", true, Some(200), None),
                    route("/d", true, Some(200), None),
                    route("/e", true, Some(403), None),
                    route("/f", false, None, Some("redirected to /home")),
                ],
                vec![],
                vec![],
            ),
        );

        let diff = diff_role_access(&old_roles, &new_roles);
        assert_eq!(diff.count(RoleAccessChangeKind::AccessGained), 3);
        assert_eq!(diff.count(RoleAccessChangeKind::AccessLost), 2);
        assert_eq!(diff.count(RoleAccessChangeKind::StatusChanged), 1);
        assert_eq!(diff.count(RoleAccessChangeKind::RoleError), 0);

        let gained_routes: Vec<&str> = diff.access_gained().map(|c| c.route.as_str()).collect();
        assert_eq!(gained_routes, vec!["/a", "/b", "/c"]);
        let lost_routes: Vec<&str> = diff.access_lost().map(|c| c.route.as_str()).collect();
        assert_eq!(lost_routes, vec!["/e", "/f"]);
    }

    #[test]
    fn endpoint_status_regression_ignores_fixes_and_folds_server_actions() {
        assert!(is_status_regression(&[200], &[500]));
        assert!(is_status_regression(&[200], &[404]));
        assert!(is_status_regression(&[200], &[200, 500]));
        assert!(is_status_regression(&[404], &[500]));
        assert!(is_status_regression(&[200, 404], &[404]));
        assert!(!is_status_regression(&[200], &[201]));
        assert!(!is_status_regression(&[500], &[200]));
        assert!(!is_status_regression(&[404], &[404]));
        assert!(!is_status_regression(&[200], &[]));

        // Next.js server action hashes normalize across builds.
        let mut b_roles = BTreeMap::new();
        b_roles.insert(
            "anonymous".into(),
            make_inv(
                "v1",
                None,
                vec![route("/cart", true, Some(200), None)],
                vec![],
                vec![endpoint("POST /cart#action:aaaa1111", vec![200], vec![])],
            ),
        );
        let mut c_roles = BTreeMap::new();
        c_roles.insert(
            "anonymous".into(),
            make_inv(
                "v2",
                None,
                vec![route("/cart", true, Some(200), None)],
                vec![],
                vec![endpoint("POST /cart#action:bbbb2222", vec![200], vec![])],
            ),
        );
        let report = compute_parity(
            &MapSource::from_roles("v1", b_roles),
            &MapSource::from_roles("v2", c_roles),
        );
        assert!(report.summary.passed);
        assert_eq!(report.endpoints.parity_pct, 100.0);
        // JSON roundtrip check
        let serialized = serde_json::to_string(&report).unwrap();
        let roundtrip: ParityReport = serde_json::from_str(&serialized).unwrap();
        assert_eq!(roundtrip, report);
    }

    #[test]
    fn diff_role_access_ignores_empty_shell_redirect_capture_on_shell_app() {
        let mut shell = Control {
            key: "*|link|text=home".into(),
            route: "*".into(),
            routes: vec!["/".into(), "/settings/general".into(), "/projects".into()],
            role: "link".into(),
            label: "Home".into(),
            locator: "text=home".into(),
            count: 1,
            status: ControlStatus::Ok,
            ..Default::default()
        };
        let old_inv = make_inv(
            "old",
            Some("admin"),
            vec![
                route("/", true, Some(200), None),
                route("/settings", false, None, Some("redirects")),
                route("/settings/general", true, Some(200), None),
                route("/projects", true, Some(200), None),
            ],
            vec![shell.clone()],
            vec![],
        );
        // New scan captured an empty 0-control shell at `/settings` mid-redirect
        // (no global shell controls present on `/settings`, 0 route controls, no variants).
        shell.routes = vec!["/".into(), "/settings/general".into(), "/projects".into()];
        let new_inv = make_inv(
            "new",
            Some("admin"),
            vec![
                route("/", true, Some(200), None),
                route("/settings", true, Some(200), None),
                route("/settings/general", true, Some(200), None),
                route("/projects", true, Some(200), None),
            ],
            vec![shell],
            vec![],
        );
        let mut old_roles = BTreeMap::new();
        let mut new_roles = BTreeMap::new();
        old_roles.insert("admin".into(), old_inv);
        new_roles.insert("admin".into(), new_inv);
        let diff = diff_role_access(&old_roles, &new_roles);
        assert!(
            diff.changes.is_empty(),
            "empty shell capture must not trigger ACCESS GAINED: {:?}",
            diff.changes
        );
        assert!(
            diff.coverage_notes
                .iter()
                .any(|n| n.contains("/settings: redirected -> not_reached")),
            "expected coverage note, got {:?}",
            diff.coverage_notes
        );
    }

    #[test]
    fn diff_role_access_tracks_endpoint_access_gained_and_lost_without_new_feature_noise() {
        let mut old_member = make_inv(
            "old",
            Some("member"),
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
            vec![
                endpoint("GET /api/billing/invoices", vec![403], vec!["/dashboard"]),
                endpoint("GET /api/reports/export", vec![200], vec!["/dashboard"]),
            ],
        );
        let old_admin = make_inv(
            "old",
            Some("admin"),
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
            vec![
                endpoint("GET /api/billing/invoices", vec![200], vec!["/dashboard"]),
                endpoint("GET /api/admin/audit-logs", vec![200], vec!["/dashboard"]),
                endpoint("GET /api/reports/export", vec![200], vec!["/dashboard"]),
            ],
        );
        let new_member = make_inv(
            "new",
            Some("member"),
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
            vec![
                // Was 403 -> now 200: unambiguous EndpointAccessGained
                endpoint("GET /api/billing/invoices", vec![200], vec!["/dashboard"]),
                // Was admin-only in baseline, now exposed to member on already-visited /dashboard
                endpoint("GET /api/admin/audit-logs", vec![200], vec!["/dashboard"]),
                // Was 200 -> now 403: EndpointAccessLost
                endpoint("GET /api/reports/export", vec![403], vec!["/dashboard"]),
                // Brand-new endpoint not in any baseline role: must NOT alarm as escalation
                endpoint("GET /api/v2/welcome-banner", vec![200], vec!["/dashboard"]),
            ],
        );
        let new_admin = make_inv(
            "new",
            Some("admin"),
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
            vec![
                endpoint("GET /api/billing/invoices", vec![200], vec!["/dashboard"]),
                endpoint("GET /api/admin/audit-logs", vec![200], vec!["/dashboard"]),
                endpoint("GET /api/reports/export", vec![200], vec!["/dashboard"]),
                endpoint("GET /api/v2/welcome-banner", vec![200], vec!["/dashboard"]),
            ],
        );
        old_member.role = Some("member".into());

        let old_roles =
            BTreeMap::from([("member".into(), old_member), ("admin".into(), old_admin)]);
        let new_roles =
            BTreeMap::from([("member".into(), new_member), ("admin".into(), new_admin)]);
        let diff = diff_role_access(&old_roles, &new_roles);

        assert!(diff.has_changes());
        assert!(diff.has_rbac_regression());
        assert_eq!(
            diff.endpoint_count(EndpointAccessChangeKind::EndpointAccessGained),
            2
        );
        assert_eq!(
            diff.endpoint_count(EndpointAccessChangeKind::EndpointAccessLost),
            1
        );
        let gained_eps: Vec<&str> = diff
            .endpoint_access_gained()
            .map(|c| c.endpoint.as_str())
            .collect();
        assert_eq!(
            gained_eps,
            vec!["GET /api/admin/audit-logs", "GET /api/billing/invoices"]
        );
        let lost_eps: Vec<&str> = diff
            .endpoint_access_lost()
            .map(|c| c.endpoint.as_str())
            .collect();
        assert_eq!(lost_eps, vec!["GET /api/reports/export"]);
    }
}
