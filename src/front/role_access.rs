//! Role access matrix: what each role (anonymous, user, admin, ...) reaches.
//!
//! Built from each role's latest map, so it is only as complete as those
//! maps. Written to `.brokenapp/map/ROLE-ACCESS.md` and `role-access.tsv`:
//!
//! - route × role: `visited`, `login` (redirected to the login page),
//!   `forbidden` (HTTP 401/403), `redirected` (elsewhere), `error` (other
//!   4xx/5xx), `not_linked` (the role's crawl never reached it), `not_reached`
//!   (known but not visited: timeout, budget, dynamic), `-` (role not mapped);
//! - controls present for some roles but absent for others that visited the
//!   same page (e.g. "Delete member" only for admin);
//! - `review` markers: a route a role whose name suggests less privilege
//!   reaches while a more privileged-sounding role is sent to login or
//!   refused. Facts only; whether that is intended is for a human to decide.
//!
//! Output is sorted and has no wall-clock timestamps beyond the maps' own,
//! so it diffs cleanly in git.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::inventory::{EndpointEntry, Inventory, Outcome, RouteEntry, render, stable_endpoint};

pub const ROLE_ACCESS_MD: &str = "ROLE-ACCESS.md";
pub const ROLE_ACCESS_TSV: &str = "role-access.tsv";
pub const MAP_INDEX_MD: &str = "README.md";

/// What one role got on one route.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Visited,
    Login,
    Forbidden,
    Redirected,
    Error,
    NotLinked,
    NotReached,
    /// The role has no map.
    NotMapped,
}

impl Access {
    pub fn label(&self) -> &'static str {
        match self {
            Access::Visited => "visited",
            Access::Login => "login",
            Access::Forbidden => "forbidden",
            Access::Redirected => "redirected",
            Access::Error => "error",
            Access::NotLinked => "not_linked",
            Access::NotReached => "not_reached",
            Access::NotMapped => "-",
        }
    }

    /// The role was kept out (login, 401/403, or sent elsewhere).
    pub fn denied(&self) -> bool {
        matches!(self, Access::Login | Access::Forbidden | Access::Redirected)
    }

    /// Coverage-gap states rather than an observed authorization/HTTP verdict.
    pub fn is_coverage_gap(&self) -> bool {
        matches!(
            self,
            Access::NotLinked | Access::NotReached | Access::NotMapped
        )
    }
}

/// What one role observed on one API / GraphQL / WebSocket endpoint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAccess {
    /// Observed with at least one 2xx/3xx response (or a live WS RPC with no error status).
    Allowed,
    /// Attempted mutation stopped by the write guard.
    WriteGuarded,
    /// Observed only with HTTP 401/403.
    Forbidden,
    /// Observed only with other HTTP 4xx/5xx error statuses.
    Error,
    /// Not observed in this role's crawl.
    NotSeen,
    /// The role has no map.
    NotMapped,
}

impl EndpointAccess {
    pub fn label(&self) -> &'static str {
        match self {
            EndpointAccess::Allowed => "allowed",
            EndpointAccess::WriteGuarded => "write_guarded",
            EndpointAccess::Forbidden => "forbidden",
            EndpointAccess::Error => "error",
            EndpointAccess::NotSeen => "not_seen",
            EndpointAccess::NotMapped => "-",
        }
    }

    /// True when the role received a non-error response (or live WS RPC) or
    /// was able to trigger a write-guarded mutation from the UI.
    pub fn exposed(&self) -> bool {
        matches!(self, EndpointAccess::Allowed | EndpointAccess::WriteGuarded)
    }

    /// Explicitly refused with HTTP 401/403.
    pub fn denied(&self) -> bool {
        matches!(self, EndpointAccess::Forbidden)
    }

    /// Coverage-gap / unobserved state.
    pub fn is_unobserved(&self) -> bool {
        matches!(self, EndpointAccess::NotSeen | EndpointAccess::NotMapped)
    }
}

/// Classify a single [`EndpointEntry`] into [`EndpointAccess`].
pub fn endpoint_entry_access(e: &EndpointEntry) -> EndpointAccess {
    if e.write {
        // Under write_guard = "stub", a guarded call may also carry the stub
        // 200 status; keep it classified as write_guarded rather than server-allowed.
        if e.statuses.iter().any(|s| matches!(s, 401 | 403)) {
            return EndpointAccess::Forbidden;
        }
        return EndpointAccess::WriteGuarded;
    }
    if e.statuses.iter().any(|s| (200..400).contains(s)) {
        return EndpointAccess::Allowed;
    }
    if e.statuses.iter().any(|s| matches!(s, 401 | 403)) {
        return EndpointAccess::Forbidden;
    }
    if e.statuses.iter().any(|s| *s >= 400) {
        return EndpointAccess::Error;
    }
    // Live WebSocket RPC or status-less captured call without errors.
    EndpointAccess::Allowed
}

/// Per-endpoint observed access across an inventory (canonicalized by `stable_endpoint`).
pub fn inventory_endpoint_access(inv: &Inventory) -> BTreeMap<String, (EndpointAccess, bool)> {
    let mut out: BTreeMap<String, (EndpointAccess, bool)> = BTreeMap::new();
    let merge = |map: &mut BTreeMap<String, (EndpointAccess, bool)>,
                 raw_ep: &str,
                 acc: EndpointAccess,
                 write: bool| {
        let path = raw_ep.split_once(' ').map_or("", |(_, p)| p);
        if crate::network::filters::is_dev_tool_or_hmr_path(path) {
            return;
        }
        let key = stable_endpoint(raw_ep);
        map.entry(key)
            .and_modify(|(cur_acc, cur_write)| {
                *cur_write |= write;
                if acc < *cur_acc {
                    *cur_acc = acc;
                }
            })
            .or_insert((acc, write));
    };

    for e in &inv.endpoints {
        merge(&mut out, &e.endpoint, endpoint_entry_access(e), e.write);
    }
    // Also fold control `Calls` outcomes in case a minimal inventory omits the reverse index.
    for c in &inv.controls {
        for o in &c.outcomes {
            if let Outcome::Calls {
                endpoint,
                status,
                blocked,
            } = o
            {
                let is_write = *blocked;
                let acc = if is_write {
                    EndpointAccess::WriteGuarded
                } else {
                    match status {
                        Some(s) if (200..400).contains(s) => EndpointAccess::Allowed,
                        Some(401 | 403) => EndpointAccess::Forbidden,
                        Some(s) if *s >= 400 => EndpointAccess::Error,
                        _ => EndpointAccess::Allowed,
                    }
                };
                merge(&mut out, endpoint, acc, is_write);
            }
        }
    }
    out
}

/// Access of one route entry of a role's map.
pub fn route_access(r: &RouteEntry) -> Access {
    if let Some(status) = r.status {
        if matches!(status, 401 | 403) {
            return Access::Forbidden;
        }
        if status >= 400 {
            return Access::Error;
        }
    }
    if r.visited {
        return Access::Visited;
    }
    let why = r
        .unvisited_reason
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if why.contains("login") {
        Access::Login
    } else if why.contains("403")
        || why.contains("401")
        || why.contains("forbidden")
        || why.contains("unauthorized")
    {
        Access::Forbidden
    } else if why.contains("redirect") {
        Access::Redirected
    } else if why.is_empty() || why.contains("not linked") {
        Access::NotLinked
    } else {
        Access::NotReached
    }
}

/// How privileged a role name sounds: 0 anonymous .. 5 admin; `None` when
/// the name says nothing (no comparison is made then).
pub fn privilege_rank(name: &str) -> Option<u8> {
    const RANKS: &[(u8, &[&str])] = &[
        (
            0,
            &[
                "anonymous",
                "anon",
                "guest",
                "public",
                "visitor",
                "unauthenticated",
            ],
        ),
        (
            1,
            &[
                "viewer", "readonly", "reader", "basic", "free", "trial", "limited",
            ],
        ),
        (
            2,
            &[
                "user",
                "member",
                "customer",
                "client",
                "student",
                "player",
                "athlete",
                "patient",
                "learner",
                "subscriber",
                "parent",
                "buyer",
                "seller",
                "tenant",
            ],
        ),
        (
            3,
            &[
                "contributor",
                "author",
                "editor",
                "coach",
                "teacher",
                "instructor",
                "staff",
                "agent",
                "support",
                "moderator",
                "mod",
                "operator",
                "analyst",
                "trainer",
                "employee",
                "doctor",
                "nurse",
            ],
        ),
        (
            4,
            &[
                "manager",
                "lead",
                "supervisor",
                "organizer",
                "director",
                "head",
            ],
        ),
        (
            5,
            &[
                "admin",
                "administrator",
                "owner",
                "superuser",
                "superadmin",
                "root",
                "sysadmin",
            ],
        ),
    ];
    let lower = name.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    let mut best: Option<u8> = None;
    for token in &tokens {
        // `superadmin`, `orgadmin`: the strongest word inside wins.
        for (rank, words) in RANKS {
            let hit = words.contains(token)
                || (*rank == 5 && token.ends_with("admin"))
                || (token.ends_with('s') && words.contains(&&token[..token.len() - 1]));
            if hit {
                best = Some(best.map_or(*rank, |b| b.max(*rank)));
            }
        }
    }
    best
}

/// One role column of the matrix.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RoleColumn {
    pub name: String,
    /// `-` for anonymous, else the login method.
    pub method: String,
    /// `generated_at` of the role's latest map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_at: Option<String>,
    pub routes_visited: u32,
    pub routes_known: u32,
    /// Outcome of this run for the role (`mapped`, `login_failed`, ...);
    /// `None` when the role was not part of the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_run: Option<String>,
}

/// One route row.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RouteRow {
    pub route: String,
    /// Aligned with [`RoleAccess::columns`].
    pub access: Vec<Access>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review: Vec<String>,
}

/// One observed API / GraphQL / WebSocket endpoint row across roles.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EndpointRow {
    /// Canonicalized `METHOD /path/template` (or `WS /path#op`).
    pub endpoint: String,
    /// True if any role observed a write-guarded attempt on this endpoint.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write: bool,
    /// Aligned with [`RoleAccess::columns`].
    pub access: Vec<EndpointAccess>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review: Vec<String>,
}

/// A control some roles have and others (that visited its page) lack.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ControlRow {
    /// Routes it appears on (`*` = global shell control).
    pub routes: Vec<String>,
    /// `button "Delete member"`.
    pub control: String,
    pub present: Vec<String>,
    pub absent: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RoleAccess {
    pub project: String,
    pub columns: Vec<RoleColumn>,
    pub routes: Vec<RouteRow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<EndpointRow>,
    pub controls: Vec<ControlRow>,
}

/// Input for one role: its latest map (if any).
pub struct RoleMap<'a> {
    pub name: String,
    pub method: String,
    pub inventory: Option<&'a Inventory>,
    pub this_run: Option<String>,
}

pub fn norm_route(r: &str) -> String {
    if r == "*" {
        return r.to_string();
    }
    let t = r.trim_end_matches('/');
    if t.is_empty() {
        "/".to_string()
    } else {
        t.to_string()
    }
}

/// Fold known binary UI theme-toggle label pairs to a single canonical label so
/// a stateful mid-crawl toggle (e.g. `"Switch to dark mode"` -> `"Switch to light mode"`)
/// never produces false cross-role control diffs.
fn canonicalize_toggle_label(norm_label: &str) -> Option<&'static str> {
    match norm_label {
        "switch to dark mode"
        | "switch to light mode"
        | "switch to dark theme"
        | "switch to light theme"
        | "dark mode"
        | "light mode"
        | "dark theme"
        | "light theme"
        | "enable dark mode"
        | "enable light mode"
        | "enable dark theme"
        | "enable light theme"
        | "use dark mode"
        | "use light mode"
        | "use dark theme"
        | "use light theme"
        | "toggle dark mode"
        | "toggle light mode"
        | "toggle dark theme"
        | "toggle light theme"
        | "toggle theme"
        | "switch theme"
        | "activate dark mode"
        | "activate light mode"
        | "activate dark theme"
        | "activate light theme"
        | "turn on dark mode"
        | "turn on light mode"
        | "turn on dark theme"
        | "turn on light theme" => Some("theme toggle"),
        _ => None,
    }
}

/// Stable cross-role identity of a control on a concrete route:
/// `(role_kind, normalized_label_or_stable_locator, normalized_target)`.
///
/// Matches by normalized human label when present so the same control never
/// produces contradictory `present`/`absent` rows when roles get different
/// generated IDs, landmark suffixes, count plurals, or grouped counts.
fn control_match_key(c: &crate::inventory::Control) -> (String, String, Option<String>) {
    use crate::inventory::identity::{fold_count_plurals, is_generated_id, normalize_text};

    let clean_label = |raw: &str| -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() || is_generated_id(trimmed) {
            return String::new();
        }
        fold_count_plurals(&normalize_text(trimmed))
    };

    let norm_label = clean_label(&c.label);
    let handle = if !norm_label.is_empty() {
        let canonical = canonicalize_toggle_label(&norm_label).unwrap_or(&norm_label);
        format!("label={canonical}")
    } else {
        let loc_base = c.locator.split('@').next().unwrap_or(&c.locator);
        if let Some(id) = loc_base.strip_prefix("id=")
            && is_generated_id(id)
        {
            let disp = clean_label(&c.display_label());
            if !disp.is_empty() {
                let canonical = canonicalize_toggle_label(&disp).unwrap_or(&disp);
                format!("label={canonical}")
            } else {
                loc_base.to_string()
            }
        } else if !loc_base.is_empty() && loc_base != "text=" {
            let disp = clean_label(&c.display_label());
            if let Some(canonical) = canonicalize_toggle_label(&disp) {
                format!("label={canonical}")
            } else if let Some(val) = loc_base.strip_prefix("text=") {
                format!("text={}", fold_count_plurals(val))
            } else if let Some(val) = loc_base.strip_prefix("aria=") {
                format!("aria={}", fold_count_plurals(val))
            } else {
                loc_base.to_string()
            }
        } else {
            let disp = clean_label(&c.display_label());
            if !disp.is_empty() {
                let canonical = canonicalize_toggle_label(&disp).unwrap_or(&disp);
                format!("label={canonical}")
            } else {
                c.key
                    .split_once('|')
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or_else(|| c.key.clone())
            }
        }
    };
    let target = c
        .target
        .as_deref()
        .filter(|t| !t.is_empty())
        .map(norm_route);
    (c.role.clone(), handle, target)
}

/// Unlabeled ordinal controls (`text=#1`) and controls whose only display label
/// is a runtime-generated ID (`base-ui-_r_1k_-hidden-input`) do not have a
/// stable cross-role identity.
fn is_comparable_control(c: &crate::inventory::Control) -> bool {
    use crate::inventory::identity::is_generated_id;

    let loc_base = c.locator.split('@').next().unwrap_or(&c.locator);
    if loc_base == "text=" {
        let label = c.label.trim();
        return !label.is_empty() && !is_generated_id(label);
    }
    if let Some(id) = loc_base.strip_prefix("id=")
        && is_generated_id(id)
    {
        let label = c.label.trim();
        return !label.is_empty() && !is_generated_id(label);
    }
    true
}

fn is_dynamic_route(route: &str) -> bool {
    route != "*"
        && route
            .split('/')
            .any(|seg| seg.starts_with(':') || seg.starts_with('[') || seg.starts_with('*'))
}

fn has_concrete_variant(variants: &[String]) -> bool {
    variants.iter().any(|v| {
        let path = v.split('?').next().unwrap_or(v);
        !path.is_empty()
            && !path
                .split('/')
                .any(|seg| seg.starts_with(':') || seg.starts_with('[') || seg.starts_with('*'))
    })
}

/// Build the matrix from each role's latest map.
pub fn build(project: &str, maps: &[RoleMap<'_>]) -> RoleAccess {
    let columns: Vec<RoleColumn> = maps
        .iter()
        .map(|m| RoleColumn {
            name: m.name.clone(),
            method: m.method.clone(),
            map_at: m.inventory.map(|i| i.generated_at.clone()),
            routes_visited: m.inventory.map_or(0, |i| i.coverage.routes_visited),
            routes_known: m.inventory.map_or(0, |i| {
                i.coverage.routes_known.max(i.coverage.routes_visited)
            }),
            this_run: m.this_run.clone(),
        })
        .collect();

    // Route -> access, per role.
    let per_role: Vec<Option<BTreeMap<String, Access>>> = maps
        .iter()
        .map(|m| {
            m.inventory.map(|inv| {
                let mut out: BTreeMap<String, Access> = BTreeMap::new();
                for r in &inv.routes {
                    let a = route_access(r);
                    let key = norm_route(&r.route);
                    // Keep the most informative status when a route repeats.
                    out.entry(key)
                        .and_modify(|cur| {
                            if a == Access::Visited || (*cur != Access::Visited && a < *cur) {
                                *cur = a;
                            }
                        })
                        .or_insert(a);
                }
                out
            })
        })
        .collect();
    let all_routes: BTreeSet<String> = per_role
        .iter()
        .flatten()
        .flat_map(|m| m.keys().cloned())
        .collect();

    let ranks: Vec<Option<u8>> = maps.iter().map(|m| privilege_rank(&m.name)).collect();
    let mut routes = Vec::new();
    for route in &all_routes {
        let access: Vec<Access> = per_role
            .iter()
            .map(|m| match m {
                None => Access::NotMapped,
                Some(m) => m.get(route).copied().unwrap_or(Access::NotLinked),
            })
            .collect();
        let mut review = Vec::new();
        for (lo, a_lo) in access.iter().enumerate() {
            if *a_lo != Access::Visited {
                continue;
            }
            for (hi, a_hi) in access.iter().enumerate() {
                if let (Some(rl), Some(rh)) = (ranks[lo], ranks[hi])
                    && rl < rh
                    && a_hi.denied()
                {
                    review.push(format!(
                        "{} reaches it but {} gets {}",
                        maps[lo].name,
                        maps[hi].name,
                        a_hi.label()
                    ));
                }
            }
        }
        routes.push(RouteRow {
            route: route.clone(),
            access,
            review,
        });
    }

    let visited: Vec<BTreeSet<String>> = per_role
        .iter()
        .map(|m| {
            m.iter()
                .flat_map(|m| m.iter())
                .filter(|(_, a)| **a == Access::Visited)
                .map(|(r, _)| r.clone())
                .collect()
        })
        .collect();

    // Expand every control onto its concrete routes and compare per concrete
    // route by `(route, role_kind, stable_locator_or_normalized_label, target)`.
    // Only compare roles that actually had a fair chance to observe the
    // control's state:
    // - skip controls whose only identity is a random generated ID / ordinal;
    // - opened-only (modal/drawer/popover) controls are only marked absent for
    //   a role that also opened the same opener state on that route;
    // - on a dynamic route (`/:id`), require concrete variant coverage on the
    //   absent role when present roles have concrete variants;
    // - when a role's map has a global shell (`*` on >= 3 routes) yet recorded
    //   0 controls on a route where another role saw >= 3 controls, treat that
    //   route as an unrendered/empty shell capture rather than an RBAC absence.
    type MatchKey = (String, String, Option<String>);
    struct RoutePresence {
        label: String,
        present_roles: BTreeSet<usize>,
        all_global: bool,
        /// At least one present role observed this control directly on the
        /// route (not solely inside an opened modal/panel/popover).
        observed_direct: bool,
        /// Opener control match keys that revealed this control on this route.
        required_openers: BTreeSet<MatchKey>,
    }
    let mut by_route_control: BTreeMap<(String, MatchKey), RoutePresence> = BTreeMap::new();
    let mut roles_with_control_anywhere: BTreeMap<MatchKey, BTreeSet<usize>> = BTreeMap::new();
    let mut route_control_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new(); maps.len()];
    let mut role_has_global_shell: Vec<bool> = vec![false; maps.len()];
    let mut route_has_concrete_variant: Vec<BTreeSet<String>> = vec![BTreeSet::new(); maps.len()];
    // Per role & concrete route: opener match keys that were actually opened
    // during that role's crawl (evidenced by any child control referencing them).
    let mut role_opened_on_route: Vec<BTreeMap<String, BTreeSet<MatchKey>>> =
        vec![BTreeMap::new(); maps.len()];

    for (i, m) in maps.iter().enumerate() {
        let Some(inv) = m.inventory else { continue };
        role_has_global_shell[i] = inv
            .controls
            .iter()
            .any(|c| c.route == "*" && c.routes.len() >= 3);
        for r in &inv.routes {
            if r.visited && has_concrete_variant(&r.variants) {
                route_has_concrete_variant[i].insert(norm_route(&r.route));
            }
        }
        let key_to_match: BTreeMap<&str, MatchKey> = inv
            .controls
            .iter()
            .map(|c| (c.key.as_str(), control_match_key(c)))
            .collect();

        for c in &inv.controls {
            let is_global = c.route == "*";
            let concrete_routes: BTreeSet<String> = if is_global {
                let explicit: BTreeSet<String> = c
                    .present_on()
                    .into_iter()
                    .filter(|r| *r != "*")
                    .map(norm_route)
                    .collect();
                if explicit.is_empty() {
                    visited[i].clone()
                } else {
                    explicit
                }
            } else {
                c.present_on()
                    .into_iter()
                    .filter(|r| *r != "*")
                    .map(norm_route)
                    .collect()
            };
            if concrete_routes.is_empty() {
                continue;
            }
            for concrete_route in &concrete_routes {
                *route_control_counts[i]
                    .entry(concrete_route.clone())
                    .or_insert(0) += 1;
            }
            // Record every opener this role actually opened on each route
            // (even if this child control itself is not comparable).
            if !c.state_entries.is_empty() {
                for entry in &c.state_entries {
                    if let crate::inventory::ControlStateEntryKind::Opened { opener } = &entry.kind
                        && let Some(opener_mk) = key_to_match.get(opener.as_str())
                    {
                        role_opened_on_route[i]
                            .entry(norm_route(&entry.route))
                            .or_default()
                            .insert(opener_mk.clone());
                    }
                }
            } else if !c.opened_by.is_empty() {
                for concrete_route in &concrete_routes {
                    let slot = role_opened_on_route[i]
                        .entry(concrete_route.clone())
                        .or_default();
                    for opener in &c.opened_by {
                        if let Some(opener_mk) = key_to_match.get(opener.as_str()) {
                            slot.insert(opener_mk.clone());
                        }
                    }
                }
            }

            if !is_comparable_control(c) {
                continue;
            }
            let match_key = control_match_key(c);
            roles_with_control_anywhere
                .entry(match_key.clone())
                .or_default()
                .insert(i);
            let display = format!("{} \"{}\"", c.role, c.display_label());
            for concrete_route in concrete_routes {
                let (is_direct, openers_here): (bool, BTreeSet<MatchKey>) =
                    if !c.state_entries.is_empty() {
                        let matching: Vec<_> = c
                            .state_entries
                            .iter()
                            .filter(|e| norm_route(&e.route) == concrete_route)
                            .collect();
                        if matching.is_empty() {
                            (c.opened_by.is_empty(), BTreeSet::new())
                        } else {
                            let direct = matching.iter().any(|e| {
                                matches!(e.kind, crate::inventory::ControlStateEntryKind::Direct)
                            });
                            let openers = matching
                                .iter()
                                .filter_map(|e| match &e.kind {
                                    crate::inventory::ControlStateEntryKind::Opened { opener } => {
                                        key_to_match.get(opener.as_str()).cloned()
                                    }
                                    _ => None,
                                })
                                .collect();
                            (direct, openers)
                        }
                    } else if c.opened_by.is_empty() {
                        (true, BTreeSet::new())
                    } else {
                        let openers = c
                            .opened_by
                            .iter()
                            .filter_map(|op| key_to_match.get(op.as_str()).cloned())
                            .collect();
                        (false, openers)
                    };

                let entry = by_route_control
                    .entry((concrete_route, match_key.clone()))
                    .or_insert_with(|| RoutePresence {
                        label: display.clone(),
                        present_roles: BTreeSet::new(),
                        all_global: true,
                        observed_direct: false,
                        required_openers: BTreeSet::new(),
                    });
                entry.present_roles.insert(i);
                entry.all_global &= is_global;
                entry.observed_direct |= is_direct;
                entry.required_openers.extend(openers_here);
            }
        }
    }

    // Group identical `(match_key, present, absent)` splits across routes into
    // one row so global shell controls still render compactly as `*`.
    struct DiffGroup {
        label: String,
        routes: BTreeSet<String>,
        all_global: bool,
    }
    let mut grouped: BTreeMap<(MatchKey, Vec<usize>, Vec<usize>), DiffGroup> = BTreeMap::new();
    for ((concrete_route, match_key), presence) in by_route_control {
        let dynamic_route = is_dynamic_route(&concrete_route);
        let present_has_variant = presence
            .present_roles
            .iter()
            .any(|p| route_has_concrete_variant[*p].contains(&concrete_route));
        let max_present_controls = presence
            .present_roles
            .iter()
            .map(|p| {
                route_control_counts[*p]
                    .get(&concrete_route)
                    .copied()
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0);

        let absent_idxs: Vec<usize> = maps
            .iter()
            .enumerate()
            .filter(|(i, m)| {
                if m.inventory.is_none()
                    || presence.present_roles.contains(i)
                    || !visited[*i].contains(&concrete_route)
                {
                    return false;
                }
                // Unhydrated/empty-shell view: this role has a global app shell
                // on other routes, yet recorded 0 controls on this route while
                // another role saw a populated page here.
                let absent_controls = route_control_counts[*i]
                    .get(&concrete_route)
                    .copied()
                    .unwrap_or(0);
                if absent_controls == 0 && role_has_global_shell[*i] && max_present_controls >= 3 {
                    return false;
                }
                // Dynamic route where the present role sampled a concrete
                // record (`/:id`) but this role has no concrete record variant.
                if dynamic_route
                    && present_has_variant
                    && !route_has_concrete_variant[*i].contains(&concrete_route)
                {
                    return false;
                }
                // Opened-only control (modal/panel/popover): only count this
                // role as absent if it also reached one of the same openers on
                // this route.
                if !presence.observed_direct {
                    if presence.required_openers.is_empty() {
                        return false;
                    }
                    let role_openers = role_opened_on_route[*i].get(&concrete_route);
                    if !role_openers.is_some_and(|ops| {
                        presence
                            .required_openers
                            .iter()
                            .any(|req| ops.contains(req))
                    }) {
                        return false;
                    }
                }
                true
            })
            .map(|(i, _)| i)
            .collect();
        if absent_idxs.is_empty() {
            continue;
        }
        let present_idxs: Vec<usize> = presence.present_roles.into_iter().collect();
        let group = grouped
            .entry((match_key, present_idxs, absent_idxs))
            .or_insert_with(|| DiffGroup {
                label: presence.label,
                routes: BTreeSet::new(),
                all_global: true,
            });
        group.routes.insert(concrete_route);
        group.all_global &= presence.all_global;
    }

    let mut control_rows = Vec::new();
    for ((match_key, present_idxs, absent_idxs), group) in grouped {
        let absent_has_anywhere = roles_with_control_anywhere
            .get(&match_key)
            .is_some_and(|roles| absent_idxs.iter().any(|i| roles.contains(i)));
        let routes = if group.all_global && !absent_has_anywhere {
            vec!["*".to_string()]
        } else {
            group.routes.into_iter().collect()
        };
        control_rows.push(ControlRow {
            routes,
            control: group.label,
            present: present_idxs
                .into_iter()
                .map(|i| maps[i].name.clone())
                .collect(),
            absent: absent_idxs
                .into_iter()
                .map(|i| maps[i].name.clone())
                .collect(),
        });
    }
    control_rows.sort_by(|a, b| {
        a.routes
            .cmp(&b.routes)
            .then_with(|| a.control.cmp(&b.control))
            .then_with(|| a.present.cmp(&b.present))
    });

    // Endpoint -> access, per role (HTTP, GraphQL, and WebSocket RPC endpoints).
    let per_role_endpoints: Vec<Option<BTreeMap<String, (EndpointAccess, bool)>>> = maps
        .iter()
        .map(|m| m.inventory.map(inventory_endpoint_access))
        .collect();
    let all_endpoints: BTreeSet<String> = per_role_endpoints
        .iter()
        .flatten()
        .flat_map(|m| m.keys().cloned())
        .collect();
    let mut endpoints = Vec::new();
    for endpoint in &all_endpoints {
        let mut write = false;
        let access: Vec<EndpointAccess> = per_role_endpoints
            .iter()
            .map(|m| match m {
                None => EndpointAccess::NotMapped,
                Some(m) => match m.get(endpoint) {
                    Some((acc, w)) => {
                        write |= *w;
                        *acc
                    }
                    None => EndpointAccess::NotSeen,
                },
            })
            .collect();
        let mut review = Vec::new();
        for (lo, a_lo) in access.iter().enumerate() {
            if !a_lo.exposed() {
                continue;
            }
            for (hi, a_hi) in access.iter().enumerate() {
                if let (Some(rl), Some(rh)) = (ranks[lo], ranks[hi])
                    && rl < rh
                    && a_hi.denied()
                {
                    review.push(format!(
                        "{} got {} but {} got {}",
                        maps[lo].name,
                        a_lo.label(),
                        maps[hi].name,
                        a_hi.label()
                    ));
                }
            }
        }
        endpoints.push(EndpointRow {
            endpoint: endpoint.clone(),
            write,
            access,
            review,
        });
    }

    RoleAccess {
        project: project.to_string(),
        columns,
        routes,
        endpoints,
        controls: control_rows,
    }
}

fn routes_text(routes: &[String]) -> String {
    let shown: Vec<&str> = routes.iter().take(3).map(String::as_str).collect();
    let mut out = shown.join(", ");
    if routes.len() > 3 {
        let _ = write!(out, " (+{} more)", routes.len() - 3);
    }
    out
}

const LEGEND: &str = "`visited` = the role loaded the page; `login` = redirected to the login page; \
`forbidden` = HTTP 401/403; `redirected` = sent elsewhere; `error` = another 4xx/5xx; \
`not_linked` = the role's crawl never reached it; `not_reached` = known but not visited \
(timeout, budget, dynamic route); `-` = the role has no map.";

const ENDPOINT_LEGEND: &str = "`allowed` = 2xx/3xx or live WS RPC; `write_guarded` = write attempt stopped by guard; \
`forbidden` = HTTP 401/403; `error` = another 4xx/5xx; `not_seen` = not observed in this role's crawl; \
`-` = the role has no map.";

/// `ROLE-ACCESS.md`.
pub fn render_md(ra: &RoleAccess) -> String {
    let mut out = format!("# Role access: {}\n\n", ra.project);
    out.push_str(
        "Built from each role's latest map (`brokenapp map` maps every role). \
         It shows what each role's crawl observed, write guard on; it is only as complete as each map's coverage.\n\n",
    );
    out.push_str("| Role | Login | Map | Routes visited | This run |\n|---|---|---|---|---|\n");
    for c in &ra.columns {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {}/{} | {} |",
            render::md_cell(&c.name),
            render::md_cell(&c.method),
            c.map_at.as_deref().unwrap_or("no map"),
            c.routes_visited,
            c.routes_known,
            c.this_run.as_deref().unwrap_or("-")
        );
    }
    let _ = write!(out, "\n## Routes\n\n{LEGEND}\n\n| Route |");
    for c in &ra.columns {
        let _ = write!(out, " {} |", render::md_cell(&c.name));
    }
    out.push_str(" Review |\n|---|");
    for _ in &ra.columns {
        out.push_str("---|");
    }
    out.push_str("---|\n");
    for r in &ra.routes {
        let _ = write!(out, "| `{}` |", render::md_cell(&r.route));
        for a in &r.access {
            let _ = write!(out, " {} |", a.label());
        }
        let _ = writeln!(
            out,
            " {} |",
            if r.review.is_empty() {
                String::new()
            } else {
                format!("review: {}", render::md_cell(&r.review.join("; ")))
            }
        );
    }
    if !ra.endpoints.is_empty() {
        let _ = write!(
            out,
            "\n## Endpoints ({})\n\n{ENDPOINT_LEGEND}\n\n| Endpoint |",
            ra.endpoints.len()
        );
        for c in &ra.columns {
            let _ = write!(out, " {} |", render::md_cell(&c.name));
        }
        out.push_str(" Review |\n|---|");
        for _ in &ra.columns {
            out.push_str("---|");
        }
        out.push_str("---|\n");
        for ep in &ra.endpoints {
            let _ = write!(out, "| `{}` |", render::md_cell(&ep.endpoint));
            for a in &ep.access {
                let _ = write!(out, " {} |", a.label());
            }
            let _ = writeln!(
                out,
                " {} |",
                if ep.review.is_empty() {
                    String::new()
                } else {
                    format!("review: {}", render::md_cell(&ep.review.join("; ")))
                }
            );
        }
    }
    let _ = write!(
        out,
        "\n## Controls that differ by role ({})\n\n",
        ra.controls.len()
    );
    if ra.controls.is_empty() {
        out.push_str("No control differences were established by the available route coverage.\n");
    } else {
        out.push_str(
            "Controls present for some roles and absent for others that visited the same page \
             (`*` = global shell controls).\n\n| Route | Control | Present for | Absent for |\n|---|---|---|---|\n",
        );
        for c in &ra.controls {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                render::md_cell(&routes_text(&c.routes)),
                render::md_cell(&c.control),
                c.present.join(", "),
                c.absent.join(", ")
            );
        }
    }
    let flagged_routes: Vec<&RouteRow> =
        ra.routes.iter().filter(|r| !r.review.is_empty()).collect();
    let flagged_endpoints: Vec<&EndpointRow> = ra
        .endpoints
        .iter()
        .filter(|e| !e.review.is_empty())
        .collect();
    let flagged_total = flagged_routes.len() + flagged_endpoints.len();
    let _ = write!(out, "\n## Review ({flagged_total})\n\n");
    if flagged_total == 0 {
        out.push_str(
            "Nothing flagged: no role whose name suggests less privilege reached a route or endpoint \
             that a more privileged-sounding role was refused.\n",
        );
    } else {
        out.push_str(
            "Facts to check, not verdicts: a role whose name suggests less privilege reached these \
             routes or endpoints while a more privileged-sounding role was refused or sent to login.\n\n",
        );
        for r in flagged_routes {
            let _ = writeln!(out, "- `{}`: {}", r.route, r.review.join("; "));
        }
        for e in flagged_endpoints {
            let _ = writeln!(out, "- `{}`: {}", e.endpoint, e.review.join("; "));
        }
    }
    out
}

pub const TSV_HEADER_PREFIX: &str = "kind\troute\tcontrol";

/// `role-access.tsv`: one line per route (`kind = route`, cells are access),
/// per endpoint (`kind = endpoint`, endpoint in 3rd column, cells are endpoint
/// access), and per differing control (`kind = control`, cells `present`/`absent`/`-`).
pub fn render_tsv(ra: &RoleAccess) -> String {
    let mut out = String::from(TSV_HEADER_PREFIX);
    for c in &ra.columns {
        let _ = write!(out, "\t{}", render::tsv_field(&c.name));
    }
    out.push_str("\treview\n");
    for r in &ra.routes {
        let _ = write!(out, "route\t{}\t", render::tsv_field(&r.route));
        for a in &r.access {
            let _ = write!(out, "\t{}", a.label());
        }
        let _ = writeln!(out, "\t{}", render::tsv_field(&r.review.join("; ")));
    }
    for ep in &ra.endpoints {
        let _ = write!(out, "endpoint\t\t{}", render::tsv_field(&ep.endpoint));
        for a in &ep.access {
            let _ = write!(out, "\t{}", a.label());
        }
        let _ = writeln!(out, "\t{}", render::tsv_field(&ep.review.join("; ")));
    }
    for c in &ra.controls {
        let _ = write!(
            out,
            "control\t{}\t{}",
            render::tsv_field(&c.routes.join(",")),
            render::tsv_field(&c.control)
        );
        for col in &ra.columns {
            let cell = if c.present.contains(&col.name) {
                "present"
            } else if c.absent.contains(&col.name) {
                "absent"
            } else {
                "-"
            };
            let _ = write!(out, "\t{cell}");
        }
        out.push_str("\t\n");
    }
    out
}

/// One row of the `map/README.md` index.
pub struct IndexRow {
    pub name: String,
    pub method: String,
    pub dir: String,
    pub map_at: Option<String>,
    pub coverage: Option<String>,
    pub this_run: Option<String>,
}

/// `map/README.md`: which map is which.
pub fn render_index(project: &str, rows: &[IndexRow]) -> String {
    let mut out = format!("# UI maps: {project}\n\n");
    out.push_str(
        "One map per role. The files in this directory are the anonymous (logged-out) map; each \
         configured role has the same files under `roles/<role>/`. `ROLE-ACCESS.md` compares them.\n\n",
    );
    out.push_str("## Roles\n\n| Role | Login | Map files | Mapped | Coverage | This run |\n|---|---|---|---|---|---|\n");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | {} | {} | {} |",
            render::md_cell(&r.name),
            render::md_cell(&r.method),
            r.dir,
            r.map_at.as_deref().unwrap_or("no map yet"),
            render::md_cell(r.coverage.as_deref().unwrap_or("-")),
            r.this_run.as_deref().unwrap_or("-")
        );
    }
    out.push_str(
        "\nQuery one role: `brokenapp ui --role <role>`, `brokenapp dead --role <role>`, \
         `brokenapp journey <goal> --role <role>`, `brokenapp changes --role <role>`; \
         `--role all` merges every role with a `login_role` column.\n",
    );
    out
}

/// Write `ROLE-ACCESS.md`, `role-access.tsv` and `README.md` into `map_dir`.
pub fn write(map_dir: &Path, ra: &RoleAccess, index: &[IndexRow]) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(map_dir).with_context(|| format!("create {}", map_dir.display()))?;
    let mut written = Vec::new();
    for (name, body) in [
        (ROLE_ACCESS_MD, render_md(ra)),
        (ROLE_ACCESS_TSV, render_tsv(ra)),
        (MAP_INDEX_MD, render_index(&ra.project, index)),
    ] {
        let path = map_dir.join(name);
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        written.push(path);
    }
    written.sort();
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Control, ControlStatus, CoverageSummary};

    fn route(r: &str, visited: bool, status: Option<u16>, why: Option<&str>) -> RouteEntry {
        RouteEntry {
            route: r.into(),
            visited,
            status,
            unvisited_reason: why.map(str::to_string),
            ..Default::default()
        }
    }

    fn control(route: &str, role: &str, label: &str) -> Control {
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
            count: 1,
            status: ControlStatus::Ok,
            ..Default::default()
        }
    }

    fn inv(generated: &str, routes: Vec<RouteEntry>, controls: Vec<Control>) -> Inventory {
        let visited = routes.iter().filter(|r| r.visited).count() as u32;
        Inventory {
            generated_at: generated.into(),
            coverage: CoverageSummary {
                routes_known: routes.len() as u32,
                routes_visited: visited,
                ..Default::default()
            },
            routes,
            controls,
            ..Default::default()
        }
    }

    fn fixture() -> (Inventory, Inventory, Inventory) {
        let login = Some("redirects to login");
        let anon = inv(
            "2026-10-22T10:00:00Z",
            vec![
                route("/", true, Some(200), None),
                route("/login", true, Some(200), None),
                route("/dashboard", false, None, login),
                route("/admin", false, None, login),
                route("/admin/users", false, None, login),
            ],
            vec![
                control("*", "link", "Home"),
                control("/login", "button", "Sign in"),
            ],
        );
        let user = inv(
            "2026-10-22T10:05:00Z",
            vec![
                route("/", true, Some(200), None),
                route("/dashboard", true, Some(200), None),
                route("/reports", true, Some(200), None),
                route("/admin", false, None, login),
                route("/admin/users", true, Some(403), None),
            ],
            vec![
                control("*", "link", "Home"),
                control("/dashboard", "button", "Refresh"),
            ],
        );
        let admin = inv(
            "2026-10-22T10:09:00Z",
            vec![
                route("/", true, Some(200), None),
                route("/dashboard", true, Some(200), None),
                route("/reports/", false, None, login),
                route("/admin", true, Some(200), None),
                route("/admin/users", true, Some(200), None),
            ],
            vec![
                control("*", "link", "Home"),
                control("*", "link", "Admin"),
                control("/dashboard", "button", "Refresh"),
                control("/admin/users", "button", "Delete member"),
            ],
        );
        (anon, user, admin)
    }

    fn maps<'a>(a: &'a Inventory, u: &'a Inventory, ad: &'a Inventory) -> Vec<RoleMap<'a>> {
        vec![
            RoleMap {
                name: "anonymous".into(),
                method: "-".into(),
                inventory: Some(a),
                this_run: Some("mapped".into()),
            },
            RoleMap {
                name: "user".into(),
                method: "form".into(),
                inventory: Some(u),
                this_run: Some("mapped".into()),
            },
            RoleMap {
                name: "admin".into(),
                method: "form".into(),
                inventory: Some(ad),
                this_run: None,
            },
        ]
    }

    #[test]
    fn route_matrix_classifies_access() {
        let (a, u, ad) = fixture();
        let ra = build("demo", &maps(&a, &u, &ad));
        let row = |r: &str| {
            ra.routes
                .iter()
                .find(|x| x.route == r)
                .map(|x| x.access.iter().map(|a| a.label()).collect::<Vec<_>>())
                .unwrap()
        };
        assert_eq!(row("/admin"), vec!["login", "login", "visited"]);
        assert_eq!(row("/admin/users"), vec!["login", "forbidden", "visited"]);
        assert_eq!(row("/login"), vec!["visited", "not_linked", "not_linked"]);
        assert_eq!(row("/dashboard"), vec!["login", "visited", "visited"]);
        // Sorted, trailing slashes folded.
        let order: Vec<&str> = ra.routes.iter().map(|r| r.route.as_str()).collect();
        assert_eq!(
            order,
            vec![
                "/",
                "/admin",
                "/admin/users",
                "/dashboard",
                "/login",
                "/reports"
            ]
        );
    }

    #[test]
    fn review_flags_less_privileged_access() {
        let (a, u, ad) = fixture();
        let ra = build("demo", &maps(&a, &u, &ad));
        let reports = ra.routes.iter().find(|r| r.route == "/reports").unwrap();
        assert_eq!(reports.review, vec!["user reaches it but admin gets login"]);
        assert!(
            ra.routes
                .iter()
                .filter(|r| r.route != "/reports")
                .all(|r| r.review.is_empty())
        );
    }

    #[test]
    fn controls_differ_only_where_both_roles_visited() {
        let (a, u, ad) = fixture();
        let ra = build("demo", &maps(&a, &u, &ad));
        let rows: Vec<(String, String, Vec<String>, Vec<String>)> = ra
            .controls
            .iter()
            .map(|c| {
                (
                    c.routes.join(","),
                    c.control.clone(),
                    c.present.clone(),
                    c.absent.clone(),
                )
            })
            .collect();
        // Sign in (only anonymous visited /login), Refresh (anonymous never
        // reached /dashboard) and Delete member (user got a 403) are not compared.
        assert_eq!(
            rows,
            vec![(
                "*".to_string(),
                "link \"Admin\"".to_string(),
                vec!["admin".to_string()],
                vec!["anonymous".to_string(), "user".to_string()]
            )]
        );
    }

    #[test]
    fn delete_member_shows_when_user_sees_the_page_without_it() {
        let (a, mut u, ad) = fixture();
        u.routes
            .iter_mut()
            .find(|r| r.route == "/admin/users")
            .unwrap()
            .status = Some(200);
        let ra = build("demo", &maps(&a, &u, &ad));
        let row = ra
            .controls
            .iter()
            .find(|c| c.control == "button \"Delete member\"")
            .unwrap();
        assert_eq!(row.present, vec!["admin"]);
        assert_eq!(row.absent, vec!["user"]);
    }

    #[test]
    fn renders_are_deterministic_and_greppable() {
        let (a, u, ad) = fixture();
        let ra = build("demo", &maps(&a, &u, &ad));
        let md = render_md(&ra);
        assert!(
            md.contains("| Route | anonymous | user | admin | Review |"),
            "{md}"
        );
        assert!(
            md.contains("| `/admin` | login | login | visited |  |"),
            "{md}"
        );
        assert!(
            md.contains("review: user reaches it but admin gets login"),
            "{md}"
        );
        assert!(
            md.contains("| `*` | link \"Admin\" | admin | anonymous, user |"),
            "{md}"
        );
        assert_eq!(md, render_md(&build("demo", &maps(&a, &u, &ad))));
        let tsv = render_tsv(&ra);
        let lines: Vec<&str> = tsv.lines().collect();
        assert_eq!(
            lines[0],
            "kind\troute\tcontrol\tanonymous\tuser\tadmin\treview"
        );
        assert!(
            lines.contains(&"route\t/admin\t\tlogin\tlogin\tvisited\t"),
            "{tsv}"
        );
        assert!(
            lines.contains(&"control\t*\tlink \"Admin\"\tabsent\tabsent\tpresent\t"),
            "{tsv}"
        );
        assert!(lines.iter().all(|l| l.split('\t').count() == 7), "{tsv}");
    }

    #[test]
    fn unmapped_roles_show_dashes() {
        let (a, u, _) = fixture();
        let maps = vec![
            RoleMap {
                name: "anonymous".into(),
                method: "-".into(),
                inventory: Some(&a),
                this_run: None,
            },
            RoleMap {
                name: "user".into(),
                method: "form".into(),
                inventory: Some(&u),
                this_run: None,
            },
            RoleMap {
                name: "admin".into(),
                method: "form".into(),
                inventory: None,
                this_run: Some("login_failed".into()),
            },
        ];
        let ra = build("demo", &maps);
        assert!(ra.routes.iter().all(|r| r.access[2] == Access::NotMapped));
        assert!(ra.routes.iter().all(|r| r.review.is_empty()));
        assert!(render_md(&ra).contains("| admin | form | no map | 0/0 | login_failed |"));
    }

    #[test]
    fn global_controls_require_shared_route_coverage() {
        let anon = inv("now", vec![route("/login", true, Some(200), None)], vec![]);
        let mut admin_control = control("*", "link", "Admin");
        admin_control.routes = vec!["/dashboard".into(), "/admin".into()];
        let admin = inv(
            "now",
            vec![route("/dashboard", true, Some(200), None)],
            vec![admin_control],
        );
        let entries = vec![
            RoleMap {
                name: "anonymous".into(),
                method: "-".into(),
                inventory: Some(&anon),
                this_run: None,
            },
            RoleMap {
                name: "admin".into(),
                method: "form".into(),
                inventory: Some(&admin),
                this_run: None,
            },
        ];
        let matrix = build("demo", &entries);
        assert!(
            matrix.controls.is_empty(),
            "a disjoint login page is not evidence of an absent admin control"
        );
        assert!(render_md(&matrix).contains("No control differences were established"));
    }

    #[test]
    fn privilege_ranks_from_names() {
        assert_eq!(privilege_rank("anonymous"), Some(0));
        assert_eq!(privilege_rank("user"), Some(2));
        assert_eq!(privilege_rank("coach"), Some(3));
        assert_eq!(privilege_rank("manager"), Some(4));
        assert_eq!(privilege_rank("org_admin"), Some(5));
        assert_eq!(privilege_rank("superadmin"), Some(5));
        assert_eq!(privilege_rank("team-managers"), Some(4));
        assert_eq!(privilege_rank("blue"), None);
    }

    #[test]
    fn export_csv_multi_route_vs_single_route_has_no_contradictory_duplicates() {
        let mut csm_export = control("*", "button", "Export CSV");
        csm_export.key = "*|button|id=radix-_r_2_".into();
        csm_export.locator = "id=radix-_r_2_".into();
        csm_export.routes = vec![
            "/team/workload".into(),
            "/reports".into(),
            "/dashboard".into(),
        ];

        let mut owner_export = control("/team/workload", "button", "Export CSV");
        owner_export.key = "/team/workload|button|id=radix-_r_c_".into();
        owner_export.locator = "id=radix-_r_c_".into();
        owner_export.count = 2;

        let csm = inv(
            "2026-11-20T10:00:00Z",
            vec![
                route("/team/workload", true, Some(200), None),
                route("/reports", true, Some(200), None),
                route("/dashboard", true, Some(200), None),
            ],
            vec![csm_export],
        );
        let owner = inv(
            "2026-11-20T10:05:00Z",
            vec![
                route("/team/workload", true, Some(200), None),
                route("/reports", true, Some(200), None),
            ],
            vec![owner_export],
        );
        let entries = vec![
            RoleMap {
                name: "csm".into(),
                method: "form".into(),
                inventory: Some(&csm),
                this_run: Some("mapped".into()),
            },
            RoleMap {
                name: "owner".into(),
                method: "form".into(),
                inventory: Some(&owner),
                this_run: Some("mapped".into()),
            },
        ];

        let ra = build("repairlift", &entries);
        // Never emit contradictory rows on /team/workload where BOTH roles have Export CSV.
        assert!(
            ra.controls
                .iter()
                .all(|row| !row.routes.iter().any(|r| r == "/team/workload")),
            "Export CSV is on /team/workload for both roles: {:?}",
            ra.controls
        );
        // Report only /reports where csm has Export CSV and owner visited without it.
        assert_eq!(ra.controls.len(), 1, "{:?}", ra.controls);
        assert_eq!(ra.controls[0].routes, vec!["/reports"]);
        assert_eq!(ra.controls[0].control, "button \"Export CSV\"");
        assert_eq!(ra.controls[0].present, vec!["csm"]);
        assert_eq!(ra.controls[0].absent, vec!["owner"]);

        // When owner also has Export CSV on /reports, zero control diffs exist.
        let mut owner_both = owner.clone();
        owner_both
            .controls
            .push(control("/reports", "button", "Export CSV"));
        let entries_both = vec![
            RoleMap {
                name: "csm".into(),
                method: "form".into(),
                inventory: Some(&csm),
                this_run: Some("mapped".into()),
            },
            RoleMap {
                name: "owner".into(),
                method: "form".into(),
                inventory: Some(&owner_both),
                this_run: Some("mapped".into()),
            },
        ];
        assert!(build("repairlift", &entries_both).controls.is_empty());
    }

    #[test]
    fn theme_toggle_label_pairs_do_not_create_false_role_diffs() {
        let mut admin_toggle = control("*", "button", "Switch to light mode");
        admin_toggle.routes = vec!["/".into(), "/invoices".into()];
        let mut viewer_toggle = control("*", "button", "Switch to dark mode");
        viewer_toggle.routes = vec!["/".into(), "/invoices".into()];

        let mut admin_aria_toggle = control("/invoices", "button", "");
        admin_aria_toggle.locator = "aria=enable light mode".into();
        admin_aria_toggle.key = "/invoices|button|aria=enable light mode".into();
        let mut viewer_aria_toggle = control("/invoices", "button", "");
        viewer_aria_toggle.locator = "aria=enable dark mode".into();
        viewer_aria_toggle.key = "/invoices|button|aria=enable dark mode".into();

        let admin = inv(
            "2026-11-21T10:00:00Z",
            vec![
                route("/", true, Some(200), None),
                route("/invoices", true, Some(200), None),
            ],
            vec![
                admin_toggle,
                admin_aria_toggle,
                control("/invoices", "button", "Delete invoice"),
            ],
        );
        let viewer = inv(
            "2026-11-21T10:05:00Z",
            vec![
                route("/", true, Some(200), None),
                route("/invoices", true, Some(200), None),
            ],
            vec![viewer_toggle, viewer_aria_toggle],
        );

        let entries = vec![
            RoleMap {
                name: "admin".into(),
                method: "form".into(),
                inventory: Some(&admin),
                this_run: Some("mapped".into()),
            },
            RoleMap {
                name: "viewer".into(),
                method: "form".into(),
                inventory: Some(&viewer),
                this_run: Some("mapped".into()),
            },
        ];

        let ra = build("billing", &entries);
        // Only the real role-only control ("Delete invoice") appears as a diff.
        assert_eq!(ra.controls.len(), 1, "{:?}", ra.controls);
        assert_eq!(ra.controls[0].routes, vec!["/invoices"]);
        assert_eq!(ra.controls[0].control, "button \"Delete invoice\"");
        assert_eq!(ra.controls[0].present, vec!["admin"]);
        assert_eq!(ra.controls[0].absent, vec!["viewer"]);

        // Without the real role-only control, the theme toggle pair yields zero diffs.
        let mut admin_no_delete = admin.clone();
        admin_no_delete
            .controls
            .retain(|c| c.label != "Delete invoice");
        let entries_same = vec![
            RoleMap {
                name: "admin".into(),
                method: "form".into(),
                inventory: Some(&admin_no_delete),
                this_run: Some("mapped".into()),
            },
            RoleMap {
                name: "viewer".into(),
                method: "form".into(),
                inventory: Some(&viewer),
                this_run: Some("mapped".into()),
            },
        ];
        assert!(build("billing", &entries_same).controls.is_empty());
    }

    #[test]
    fn role_access_filters_coverage_noise_from_unopened_modals_empty_shells_and_generated_ids() {
        use crate::inventory::{ControlStateEntry, ControlStateEntryKind};

        let mut nav_home_admin = control("*", "link", "Home");
        nav_home_admin.routes = vec!["/".into(), "/settings".into(), "/projects".into()];
        let mut nav_home_ro = nav_home_admin.clone();
        nav_home_ro.routes = vec![
            "/".into(),
            "/settings".into(),
            "/projects".into(),
            "/issues".into(),
        ];

        // Direct modal opener present for both roles on /settings.
        let mut opener_admin = control("/settings", "button", "Add project script");
        opener_admin.state_entries = vec![ControlStateEntry {
            route: "/settings".into(),
            variant: None,
            kind: ControlStateEntryKind::Direct,
        }];
        let opener_ro = opener_admin.clone();

        // Modal child ONLY opened by readonly (admin ran out of budget before
        // opening the modal): must NOT appear as a role difference.
        let mut modal_child_ro = control("/settings", "input", "Command");
        modal_child_ro.state_entries = vec![ControlStateEntry {
            route: "/settings".into(),
            variant: None,
            kind: ControlStateEntryKind::Opened {
                opener: opener_ro.key.clone(),
            },
        }];

        // Second modal opened by BOTH roles, where only admin has "Delete script":
        // MUST still be reported as a real role difference.
        let mut edit_opener = control("/settings", "button", "Edit script");
        edit_opener.state_entries = vec![ControlStateEntry {
            route: "/settings".into(),
            variant: None,
            kind: ControlStateEntryKind::Direct,
        }];
        let mut shared_modal_field = control("/settings", "input", "Script name");
        shared_modal_field.state_entries = vec![ControlStateEntry {
            route: "/settings".into(),
            variant: None,
            kind: ControlStateEntryKind::Opened {
                opener: edit_opener.key.clone(),
            },
        }];
        let mut admin_only_modal_btn = control("/settings", "button", "Delete script");
        admin_only_modal_btn.state_entries = vec![ControlStateEntry {
            route: "/settings".into(),
            variant: None,
            kind: ControlStateEntryKind::Opened {
                opener: edit_opener.key.clone(),
            },
        }];

        // Singular/plural count difference (`1 client` vs `2 clients`): must match.
        let clients_admin = control("/settings", "button", "Authorized clients 1 client");
        let clients_ro = control("/settings", "button", "Authorized clients 2 clients");

        // Unlabeled generated-ID control (`base-ui-_r_1k_-hidden-input`): must be skipped.
        let mut gen_input_ro = control("/settings", "input", "base-ui-_r_1k_-hidden-input");
        gen_input_ro.key = "/settings|input|text=#1".into();
        gen_input_ro.locator = "text=".into();

        // /issues: admin captured an empty 0-control shell (has global shell on
        // 3 other routes), while readonly captured 3 real controls.
        let issue_a = control("/issues", "button", "New issue");
        let issue_b = control("/issues", "button", "Filter issues");
        let issue_c = control("/issues", "button", "Sort issues");

        // Dynamic route `/:env/:thread`: readonly sampled a concrete variant,
        // admin has no concrete variant.
        let mut dyn_route_admin = route("/:env/:thread", true, Some(200), None);
        dyn_route_admin.variants = vec![];
        let mut dyn_route_ro = route("/:env/:thread", true, Some(200), None);
        dyn_route_ro.variants = vec!["/env-1/thread-1".into()];
        let dyn_btn_ro = control("/:env/:thread", "button", "Attach files");

        let admin = inv(
            "2026-11-26T02:00:00Z",
            vec![
                route("/", true, Some(200), None),
                route("/settings", true, Some(200), None),
                route("/projects", true, Some(200), None),
                route("/issues", true, Some(200), None),
                dyn_route_admin,
            ],
            vec![
                nav_home_admin,
                opener_admin,
                edit_opener.clone(),
                shared_modal_field.clone(),
                admin_only_modal_btn,
                clients_admin,
            ],
        );
        let readonly = inv(
            "2026-11-26T02:05:00Z",
            vec![
                route("/", true, Some(200), None),
                route("/settings", true, Some(200), None),
                route("/projects", true, Some(200), None),
                route("/issues", true, Some(200), None),
                dyn_route_ro,
            ],
            vec![
                nav_home_ro,
                opener_ro,
                modal_child_ro,
                edit_opener,
                shared_modal_field,
                clients_ro,
                gen_input_ro,
                issue_a,
                issue_b,
                issue_c,
                dyn_btn_ro,
            ],
        );

        let ra = build(
            "demo-app",
            &[
                RoleMap {
                    name: "admin".into(),
                    method: "cookie".into(),
                    inventory: Some(&admin),
                    this_run: Some("mapped".into()),
                },
                RoleMap {
                    name: "readonly".into(),
                    method: "cookie".into(),
                    inventory: Some(&readonly),
                    this_run: Some("mapped".into()),
                },
            ],
        );

        assert_eq!(
            ra.controls.len(),
            1,
            "expected only real role diff, got {:?}",
            ra.controls
        );
        assert_eq!(ra.controls[0].control, "button \"Delete script\"");
        assert_eq!(ra.controls[0].present, vec!["admin"]);
        assert_eq!(ra.controls[0].absent, vec!["readonly"]);
    }

    #[test]
    fn endpoints_matrix_renders_md_tsv_and_flags_lower_role_escalation() {
        use crate::inventory::EndpointEntry;

        let mut viewer = inv(
            "2026-11-26T03:00:00Z",
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
        );
        viewer.endpoints = vec![
            EndpointEntry {
                endpoint: "GET /api/projects".into(),
                controls: vec![],
                on_load: vec!["/dashboard".into()],
                statuses: vec![200],
                write: false,
            },
            EndpointEntry {
                endpoint: "GET /api/internal/audit".into(),
                controls: vec![],
                on_load: vec!["/dashboard".into()],
                statuses: vec![200],
                write: false,
            },
            EndpointEntry {
                endpoint: "WS /ws#server.getConfig".into(),
                controls: vec![],
                on_load: vec!["/dashboard".into()],
                statuses: vec![],
                write: false,
            },
        ];

        let mut admin = inv(
            "2026-11-26T03:05:00Z",
            vec![route("/dashboard", true, Some(200), None)],
            vec![],
        );
        admin.endpoints = vec![
            EndpointEntry {
                endpoint: "GET /api/projects".into(),
                controls: vec![],
                on_load: vec!["/dashboard".into()],
                statuses: vec![200],
                write: false,
            },
            EndpointEntry {
                endpoint: "GET /api/internal/audit".into(),
                controls: vec![],
                on_load: vec!["/dashboard".into()],
                statuses: vec![403],
                write: false,
            },
            EndpointEntry {
                endpoint: "POST /api/admin/rotate-key".into(),
                controls: vec!["/dashboard|button|text=rotate".into()],
                on_load: vec![],
                statuses: vec![],
                write: true,
            },
        ];

        let ra = build(
            "saas",
            &[
                RoleMap {
                    name: "viewer".into(),
                    method: "cookie".into(),
                    inventory: Some(&viewer),
                    this_run: Some("mapped".into()),
                },
                RoleMap {
                    name: "admin".into(),
                    method: "cookie".into(),
                    inventory: Some(&admin),
                    this_run: Some("mapped".into()),
                },
            ],
        );

        assert_eq!(ra.endpoints.len(), 4);
        let audit = ra
            .endpoints
            .iter()
            .find(|e| e.endpoint == "GET /api/internal/audit")
            .unwrap();
        assert_eq!(
            audit.access,
            vec![EndpointAccess::Allowed, EndpointAccess::Forbidden]
        );
        assert_eq!(
            audit.review,
            vec!["viewer got allowed but admin got forbidden"]
        );

        let rotate = ra
            .endpoints
            .iter()
            .find(|e| e.endpoint == "POST /api/admin/rotate-key")
            .unwrap();
        assert!(rotate.write);
        assert_eq!(
            rotate.access,
            vec![EndpointAccess::NotSeen, EndpointAccess::WriteGuarded]
        );

        let ws = ra
            .endpoints
            .iter()
            .find(|e| e.endpoint == "WS /ws#server.getConfig")
            .unwrap();
        assert_eq!(
            ws.access,
            vec![EndpointAccess::Allowed, EndpointAccess::NotSeen]
        );

        let md = render_md(&ra);
        assert!(md.contains("## Endpoints (4)"), "{md}");
        assert!(md.contains("`WS /ws#server.getConfig`"), "{md}");
        assert!(md.contains("## Review (1)"), "{md}");
        assert!(
            md.contains("viewer got allowed but admin got forbidden"),
            "{md}"
        );

        let tsv = render_tsv(&ra);
        let lines: Vec<&str> = tsv.lines().collect();
        // Header + 1 route + 4 endpoints, every line has 4 + 2 = 6 tab-separated columns.
        assert!(lines.iter().all(|l| l.split('\t').count() == 6), "{tsv}");
        assert!(
            lines.iter().any(|l| l
                .starts_with("endpoint\t\tPOST /api/admin/rotate-key\tnot_seen\twrite_guarded\t")),
            "{tsv}"
        );
    }
}
