//! Journeys: which controls lead to a route, an endpoint, or a labeled control.
//!
//! The graph models both route navigation (`route --navigates--> route`) and
//! in-page opener chains (`route/sub-view --opens--> sub-view`) while preserving
//! `(route, variant)` state-entry provenance so cross-variant shortcuts are never
//! stitched. A reverse BFS from the goal gives every state node's distance (in
//! control hops); shortest paths are then read forward from the start route.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

use super::identity::{
    query_route_parts, route_has_parameters, route_matches, route_request_is_specific,
    route_variant_matches, select_routes,
};
use super::{Control, ControlStateEntry, ControlStateEntryKind, ControlStatus, Inventory, Outcome};
use crate::network::path_parameterizer::path_to_template;

/// Max paths listed from the start route.
const MAX_PATHS: usize = 20;
/// Max controls considered per hop when expanding paths.
const MAX_BRANCH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Goal {
    Route {
        route: String,
    },
    Endpoint {
        method: Option<String>,
        path: String,
    },
    Label {
        text: String,
    },
}

impl Goal {
    pub fn describe(&self) -> String {
        match self {
            Goal::Route { route } => format!("route {route}"),
            Goal::Endpoint {
                method: Some(m),
                path,
            } => format!("endpoint {m} {path}"),
            Goal::Endpoint { method: None, path } => format!("endpoint * {path}"),
            Goal::Label { text } => format!("control labeled \"{text}\""),
        }
    }
}

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "WS",
];

/// Parse `/route`, `METHOD /path`, `/api/path`, or `label:Text`.
pub fn parse_goal(raw: &str, inv: &Inventory) -> Goal {
    let s = raw.trim();
    if let Some(text) = s.strip_prefix("label:").or_else(|| s.strip_prefix("text:")) {
        return Goal::Label {
            text: text.trim().to_string(),
        };
    }
    if let Some((m, rest)) = s.split_once(char::is_whitespace) {
        let m_up = m.to_ascii_uppercase();
        if METHODS.contains(&m_up.as_str()) {
            return Goal::Endpoint {
                method: Some(m_up),
                path: rest.trim().to_string(),
            };
        }
    }
    if s.starts_with('/')
        || s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("ws://")
        || s.starts_with("wss://")
    {
        let matches_route = inv.routes.iter().any(|r| route_matches(&r.route, s))
            || inv
                .controls
                .iter()
                .any(|c| c.navigates_to().any(|to| route_matches(to, s)));
        let matches_endpoint = inv
            .endpoints
            .iter()
            .any(|e| endpoint_matches(&e.endpoint, None, s));
        let api_like = ["/api/", "/graphql", "/rest/", "/trpc/"]
            .iter()
            .any(|p| s.starts_with(p));
        if (matches_endpoint || api_like) && !matches_route {
            return Goal::Endpoint {
                method: None,
                path: s.to_string(),
            };
        }
        return Goal::Route {
            route: s.to_string(),
        };
    }
    Goal::Label {
        text: s.to_string(),
    }
}

/// Does an endpoint key (`METHOD path`, path maybe host-prefixed) match?
pub fn endpoint_matches(endpoint: &str, method: Option<&str>, path: &str) -> bool {
    let (em, epath) = endpoint.split_once(' ').unwrap_or(("", endpoint));
    // `POST /cart [server action]` matches `POST /cart`.
    let epath = epath.strip_suffix(" [server action]").unwrap_or(epath);
    if method.is_some_and(|m| !em.eq_ignore_ascii_case(m)) {
        return false;
    }
    let goal = path.trim();
    let goal = goal.split('?').next().unwrap_or(goal);
    // Full GraphQL op keys (`/graphql#MUTATION Refund`) match exactly or by base.
    let ebase = epath.split('#').next().unwrap_or(epath);
    if epath == goal {
        return true;
    }
    let goal_t = path_to_template(goal.split('#').next().unwrap_or(goal));
    // Host-prefixed keys: compare the path part.
    // Cross-origin keys carry the origin (`https://host/path`): compare the path.
    let without_scheme = ebase.split_once("://").map_or(ebase, |(_, rest)| rest);
    let epath_only = if ebase.starts_with('/') {
        ebase.to_string()
    } else {
        without_scheme
            .find('/')
            .map(|i| without_scheme[i..].to_string())
            .unwrap_or_default()
    };
    if goal.contains('#') {
        if epath.ends_with(goal) {
            return true;
        }
        // Full URL goal (`ws://127.0.0.1:3773/ws#op`) against a first-party
        // path-only endpoint (`WS /ws#op`).
        if let Some((_, rest)) = goal.split_once("://")
            && let Some(i) = rest.find('/')
        {
            return epath.ends_with(&rest[i..]);
        }
        return false;
    }
    let a: Vec<&str> = epath_only.split('/').filter(|s| !s.is_empty()).collect();
    let b: Vec<&str> = goal_t.split('/').filter(|s| !s.is_empty()).collect();
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x == y || x.starts_with(':') || y.starts_with(':'))
}

/// Endpoint observed when exercising a control on a journey step.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StepEndpoint {
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub blocked: bool,
}

/// One control on a path.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Step {
    /// Route the control is used on.
    pub route: String,
    pub key: String,
    pub role: String,
    pub label: String,
    pub status: ControlStatus,
    /// What this step leads to (route, sub-view, or endpoint).
    pub to: String,
    /// Action kind: `"navigates"`, `"opens"`, `"calls"`, or `"triggers"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub action: String,
    /// True when this step stays on the same route (e.g. opens a drawer/modal/tab or fires an API call).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_page: bool,
    /// Endpoints observed on this control.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<StepEndpoint>,
    /// Short `file:line` source location (`handler`, falling back to `render`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct JourneyPath {
    pub hops: usize,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub route_hops: usize,
    #[serde(default)]
    pub in_page_steps: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub control_kinds: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<StepEndpoint>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_gaps_or_failures: bool,
}

impl JourneyPath {
    fn from_steps(steps: Vec<Step>) -> Self {
        let hops = steps.len();
        let mut route_hops = 0;
        let mut in_page_steps = 0;
        let mut control_kinds: BTreeMap<String, usize> = BTreeMap::new();
        let mut endpoints: Vec<StepEndpoint> = Vec::new();
        let mut has_gaps_or_failures = false;

        for s in &steps {
            if s.in_page {
                in_page_steps += 1;
            } else {
                route_hops += 1;
            }
            if !s.role.is_empty() {
                *control_kinds.entry(s.role.clone()).or_insert(0) += 1;
            }
            for ep in &s.endpoints {
                if !endpoints.contains(ep) {
                    endpoints.push(ep.clone());
                }
            }
            if matches!(
                s.status,
                ControlStatus::Broken
                    | ControlStatus::Dead
                    | ControlStatus::NoEffect
                    | ControlStatus::NotExercised
                    | ControlStatus::Skipped
            ) {
                has_gaps_or_failures = true;
            }
        }

        Self {
            hops,
            steps,
            route_hops,
            in_page_steps,
            control_kinds,
            endpoints,
            has_gaps_or_failures,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct JourneyResult {
    pub goal: Goal,
    /// Concrete routes / endpoints / control keys the goal matched.
    pub matched: Vec<String>,
    pub from: String,
    /// Controls one hop from the goal, on any route.
    pub direct: Vec<Step>,
    /// Shortest paths from `from`.
    pub paths: Vec<JourneyPath>,
    /// `from` can reach the goal within `max_hops`.
    pub reachable: bool,
    /// Shortest hop count from `from` (0 = already at the goal route).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distance: Option<usize>,
    /// Why the answer may be incomplete: start route substitutions, and for
    /// unmatched goals what the map could not observe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Source lines that mention an unobserved endpoint goal
    /// (`file:line  code`), filled in by the caller when it has the codebase.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_references: Vec<String>,
    /// Strength of path evidence: `"already_at_goal"`, `"stitched_candidate"`,
    /// `"not_established"`, or `"unmatched"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StateNode {
    Route(String),
    SubView {
        route: String,
        variant: Option<String>,
        opener_key: String,
    },
}

impl StateNode {
    fn route(&self) -> &str {
        match self {
            StateNode::Route(r) => r.as_str(),
            StateNode::SubView { route, .. } => route.as_str(),
        }
    }

    fn opener(&self) -> Option<&str> {
        match self {
            StateNode::Route(_) => None,
            StateNode::SubView { opener_key, .. } => Some(opener_key.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AvailableControl {
    control_idx: usize,
    variant: Option<String>,
}

#[derive(Debug, Clone)]
struct GraphEdge {
    control_idx: usize,
    next: StateNode,
    action: &'static str,
    in_page: bool,
    to: String,
}

/// Default start: `/`, else the hash root, else the first visited route.
pub fn default_start(inv: &Inventory) -> String {
    for candidate in ["/", "/#/"] {
        if inv.routes.iter().any(|r| r.route == candidate && r.visited) {
            return candidate.to_string();
        }
    }
    inv.routes
        .iter()
        .find(|r| r.visited)
        .map(|r| r.route.clone())
        .unwrap_or_else(|| "/".to_string())
}

fn visited(inv: &Inventory, route: &str) -> bool {
    inv.routes.iter().any(|r| r.route == route && r.visited)
}

pub fn journey(inv: &Inventory, goal: &Goal, from: Option<&str>, max_hops: usize) -> JourneyResult {
    let mut notes = Vec::new();
    let mut specific_start = false;
    let from_route = match from {
        Some(f) => {
            let resolved = resolve_route(inv, f);
            specific_start = route_request_is_specific(f, &resolved);
            let r = if specific_start {
                let (path, query) = query_route_parts(f);
                let state = format!("{path}{}", query.unwrap_or_default());
                notes.push(format!(
                    "Start {state} identifies a specific record or query state. This map's route-level controls do not establish paths from that exact state; shortest paths are unknown."
                ));
                state
            } else {
                resolved
            };
            if !specific_start && r != "*" && !visited(inv, &r) {
                notes.push(format!(
                    "Start route {r} was not visited in this map; paths from it are unknown."
                ));
            }
            r
        }
        None => {
            let start = default_start(inv);
            if start != "/" && start != "/#/" {
                notes.push(format!(
                    "Start route / was not visited in this map; using {start} instead."
                ));
            }
            start
        }
    };

    // Terminal controls (one hop from the goal) and goal routes (zero hops).
    let mut matched: BTreeSet<String> = BTreeSet::new();
    let mut goal_routes: BTreeSet<String> = BTreeSet::new();
    let mut terminal: Vec<(usize, String)> = Vec::new(); // (control idx, leads-to)
    match goal {
        Goal::Route { route } => {
            // An exact (static) route beats `:param` templates that also match.
            let candidates: BTreeSet<&str> = inv
                .routes
                .iter()
                .map(|r| r.route.as_str())
                .chain(inv.controls.iter().flat_map(|c| c.navigates_to()))
                .collect();
            let selected = select_routes(candidates, route);
            let specific = query_route_parts(route).1.is_some()
                || selected.iter().any(|r| route_request_is_specific(route, r));
            matched.extend(selected.iter().map(|r| (*r).to_string()));
            if specific {
                // A visited record/tab is context, not an observed arrival edge.
                // Only a navigation outcome retaining the requested destination
                // can prove it; a sample href or matching label cannot.
                goal_routes.extend(
                    inv.controls
                        .iter()
                        .flat_map(|c| c.navigates_to())
                        .filter(|to| {
                            exact_destination(to, route)
                                && (!route_has_parameters(route)
                                    || select_routes(
                                        inv.routes.iter().map(|r| r.route.as_str()),
                                        to,
                                    )
                                    .iter()
                                    .any(|r| selected.contains(r)))
                        })
                        .map(str::to_string),
                );
                if goal_routes.is_empty() {
                    let observed = inv.routes.iter().any(|r| {
                        selected.contains(&r.route.as_str())
                            && r.visited
                            && r.variants
                                .iter()
                                .any(|v| route_variant_matches(&r.route, v, route))
                    });
                    let observation = if observed {
                        "was observed as a page variant"
                    } else {
                        "was not observed as a page variant"
                    };
                    notes.push(format!(
                        "Specific destination {route} {observation}, but no navigation outcome records that exact destination. Matched routes are context only; record or query-state reachability is unknown."
                    ));
                }
            } else {
                goal_routes.extend(selected.into_iter().map(str::to_string));
            }
            for (i, c) in inv.controls.iter().enumerate() {
                for to in c.navigates_to() {
                    if goal_routes.contains(to) {
                        terminal.push((i, to.to_string()));
                    }
                }
            }
            matched.extend(goal_routes.iter().cloned());
        }
        Goal::Endpoint { method, path } => {
            for (i, c) in inv.controls.iter().enumerate() {
                for e in c.endpoints() {
                    if endpoint_matches(e, method.as_deref(), path) {
                        matched.insert(e.to_string());
                        terminal.push((i, e.to_string()));
                    }
                }
            }
            for e in &inv.endpoints {
                if endpoint_matches(&e.endpoint, method.as_deref(), path) {
                    matched.insert(e.endpoint.clone());
                }
            }
        }
        Goal::Label { text } => {
            let needle = text.to_lowercase();
            for (i, c) in inv.controls.iter().enumerate() {
                if c.label_contains(&needle) || c.locator.to_lowercase().contains(&needle) {
                    matched.insert(c.key.clone());
                    terminal.push((i, super::render::describe_does(c)));
                }
            }
        }
    }

    let visited_all: Vec<String> = inv
        .routes
        .iter()
        .filter(|r| r.visited)
        .map(|r| r.route.clone())
        .collect();
    let by_key: BTreeMap<&str, usize> = inv
        .controls
        .iter()
        .enumerate()
        .map(|(i, c)| (c.key.as_str(), i))
        .collect();

    // StateNode -> controls available at that state (preserving variant provenance).
    let mut available: BTreeMap<StateNode, BTreeSet<AvailableControl>> = BTreeMap::new();
    let mut opened_targets: BTreeSet<(String, Option<String>, String)> = BTreeSet::new();
    let mut unknown_only: BTreeSet<usize> = BTreeSet::new();

    for (i, c) in inv.controls.iter().enumerate() {
        if !c.state_entries.is_empty() {
            let has_known = c
                .state_entries
                .iter()
                .any(|e| !matches!(e.kind, ControlStateEntryKind::Unknown));
            if !has_known {
                unknown_only.insert(i);
                continue;
            }
            for entry in &c.state_entries {
                match &entry.kind {
                    ControlStateEntryKind::Direct => {
                        for r in entry_routes(entry, c, &visited_all) {
                            available.entry(StateNode::Route(r)).or_default().insert(
                                AvailableControl {
                                    control_idx: i,
                                    variant: entry.variant.clone(),
                                },
                            );
                        }
                    }
                    ControlStateEntryKind::Opened { opener } => {
                        for r in entry_routes(entry, c, &visited_all) {
                            opened_targets.insert((
                                r.clone(),
                                entry.variant.clone(),
                                opener.clone(),
                            ));
                            available
                                .entry(StateNode::SubView {
                                    route: r,
                                    variant: entry.variant.clone(),
                                    opener_key: opener.clone(),
                                })
                                .or_default()
                                .insert(AvailableControl {
                                    control_idx: i,
                                    variant: entry.variant.clone(),
                                });
                        }
                    }
                    ControlStateEntryKind::Unknown => {}
                }
            }
        } else if c.opened_by.is_empty() {
            for r in present_routes(c, &visited_all) {
                available
                    .entry(StateNode::Route(r))
                    .or_default()
                    .insert(AvailableControl {
                        control_idx: i,
                        variant: None,
                    });
            }
        } else {
            for opener in &c.opened_by {
                for r in legacy_opener_routes(inv, c, opener, &by_key, &visited_all) {
                    opened_targets.insert((r.clone(), None, opener.clone()));
                    available
                        .entry(StateNode::SubView {
                            route: r,
                            variant: None,
                            opener_key: opener.clone(),
                        })
                        .or_default()
                        .insert(AvailableControl {
                            control_idx: i,
                            variant: None,
                        });
                }
            }
        }
    }

    // Build directed forward and reverse adjacency across StateNodes.
    let mut forward_adj: BTreeMap<StateNode, Vec<GraphEdge>> = BTreeMap::new();
    let mut reverse_adj: BTreeMap<StateNode, BTreeSet<StateNode>> = BTreeMap::new();
    for (node, avails) in &available {
        let cur_route = node.route();
        let cur_opener = node.opener();
        let edges = forward_adj.entry(node.clone()).or_default();
        for avail in avails {
            let c = &inv.controls[avail.control_idx];
            // In-page opener transition within the exact same (route, variant).
            if cur_opener != Some(c.key.as_str())
                && opened_targets.contains(&(
                    cur_route.to_string(),
                    avail.variant.clone(),
                    c.key.clone(),
                ))
            {
                let next = StateNode::SubView {
                    route: cur_route.to_string(),
                    variant: avail.variant.clone(),
                    opener_key: c.key.clone(),
                };
                reverse_adj
                    .entry(next.clone())
                    .or_default()
                    .insert(node.clone());
                edges.push(GraphEdge {
                    control_idx: avail.control_idx,
                    next,
                    action: "opens",
                    in_page: true,
                    to: describe_opener_target(c),
                });
            }
            // Route navigation transitions.
            for dest in c.navigates_to() {
                if dest != cur_route {
                    let next = StateNode::Route(dest.to_string());
                    reverse_adj
                        .entry(next.clone())
                        .or_default()
                        .insert(node.clone());
                    edges.push(GraphEdge {
                        control_idx: avail.control_idx,
                        next,
                        action: "navigates",
                        in_page: false,
                        to: dest.to_string(),
                    });
                }
            }
        }
    }

    // Reverse BFS: dist[state_node] = shortest control hops to the goal.
    let mut dist: BTreeMap<StateNode, usize> = BTreeMap::new();
    let mut queue: VecDeque<StateNode> = VecDeque::new();
    for r in &goal_routes {
        let node = StateNode::Route(r.clone());
        dist.insert(node.clone(), 0);
        queue.push_back(node);
    }
    // State nodes containing a terminal control are 1 hop away (unless already 0).
    let terminal_set: BTreeSet<usize> = terminal.iter().map(|(i, _)| *i).collect();
    for (node, avails) in &available {
        if avails.iter().any(|a| terminal_set.contains(&a.control_idx)) && !dist.contains_key(node)
        {
            dist.insert(node.clone(), 1);
        }
    }
    let frontier: Vec<StateNode> = dist
        .iter()
        .filter(|(_, d)| **d == 1)
        .map(|(n, _)| n.clone())
        .collect();
    queue.extend(frontier);

    while let Some(node) = queue.pop_front() {
        let d = dist[&node];
        if d >= max_hops {
            continue;
        }
        if let Some(preds) = reverse_adj.get(&node) {
            for pred in preds {
                if !dist.contains_key(pred) {
                    dist.insert(pred.clone(), d + 1);
                    queue.push_back(pred.clone());
                }
            }
        }
    }

    let direct: Vec<Step> = {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (i, to) in &terminal {
            if seen.insert((*i, to.clone())) {
                let c = &inv.controls[*i];
                let (action, in_page) = terminal_action(goal, c);
                out.push(make_step(c, &c.route, to, action, in_page));
            }
        }
        out.sort_by(|a, b| {
            status_rank(a.status)
                .cmp(&status_rank(b.status))
                .then_with(|| a.route.cmp(&b.route))
                .then_with(|| a.key.cmp(&b.key))
        });
        out
    };

    let start_node = StateNode::Route(from_route.clone());
    let distance = if specific_start {
        None
    } else {
        dist.get(&start_node).copied()
    };
    let mut paths = Vec::new();
    if let Some(d) = distance.filter(|d| *d > 0 && *d <= max_hops) {
        let mut used_openers = BTreeSet::new();
        let mut cur = Vec::new();
        expand(
            inv,
            &available,
            &forward_adj,
            &dist,
            &terminal,
            goal,
            &start_node,
            d,
            &mut used_openers,
            &mut cur,
            &mut paths,
        );
    }

    // Surface clear notes for controls that only have `Unknown` state-entry provenance.
    if !unknown_only.is_empty() {
        let mut reported_unknown: BTreeSet<usize> = BTreeSet::new();
        for (i, _) in &terminal {
            if unknown_only.contains(i) && reported_unknown.insert(*i) {
                let c = &inv.controls[*i];
                notes.push(format!(
                    "Control {} {} \"{}\" has only unknown state-entry provenance; listed in direct matches, not stitched into paths.",
                    c.route,
                    c.role,
                    c.display_label()
                ));
            }
        }
        if !matched.is_empty() {
            let candidate_routes: BTreeSet<&str> = std::iter::once(from_route.as_str())
                .chain(goal_routes.iter().map(String::as_str))
                .chain(
                    terminal
                        .iter()
                        .map(|(i, _)| inv.controls[*i].route.as_str()),
                )
                .collect();
            let mut candidate_unknown_count = 0usize;
            let mut candidate_unknown_routes: BTreeSet<String> = BTreeSet::new();
            for &i in &unknown_only {
                if reported_unknown.contains(&i) {
                    continue;
                }
                let c = &inv.controls[i];
                let mut hits = Vec::new();
                for e in &c.state_entries {
                    if candidate_routes.contains(e.route.as_str()) {
                        hits.push(e.route.clone());
                    }
                }
                if hits.is_empty() && candidate_routes.contains(c.route.as_str()) {
                    hits.push(c.route.clone());
                }
                if !hits.is_empty() {
                    candidate_unknown_count += 1;
                    candidate_unknown_routes.extend(hits);
                }
            }
            if candidate_unknown_count > 0 {
                let routes_list: Vec<&str> = candidate_unknown_routes
                    .iter()
                    .map(String::as_str)
                    .collect();
                notes.push(format!(
                    "{candidate_unknown_count} control{} on candidate route{} ({}) {} only unknown state-entry provenance and {} excluded from path stitching.",
                    if candidate_unknown_count == 1 { "" } else { "s" },
                    if routes_list.len() == 1 { "" } else { "s" },
                    routes_list.join(", "),
                    if candidate_unknown_count == 1 { "has" } else { "have" },
                    if candidate_unknown_count == 1 { "was" } else { "were" },
                ));
            }
        }
    }

    if matched.is_empty() {
        notes.extend(unmatched_notes(inv, goal));
    } else if distance.is_none() && !direct.is_empty() {
        let unexercised = direct
            .iter()
            .filter(|s| s.status == ControlStatus::NotExercised)
            .count();
        if unexercised > 0 {
            notes.push(format!(
                "{unexercised} of the controls that lead here were not exercised; links to them from {from_route} may exist but were not observed."
            ));
        }
    }

    let reachable = distance.is_some_and(|d| d <= max_hops);
    let path_evidence = if matched.is_empty() {
        "unmatched"
    } else if distance == Some(0) {
        "already_at_goal"
    } else if reachable && !paths.is_empty() {
        "stitched_candidate"
    } else {
        "not_established"
    }
    .to_string();

    JourneyResult {
        goal: goal.clone(),
        matched: matched.into_iter().collect(),
        from: from_route,
        direct,
        reachable,
        distance,
        paths,
        notes,
        code_references: Vec::new(),
        path_evidence,
    }
}

fn entry_routes(entry: &ControlStateEntry, c: &Control, visited_all: &[String]) -> Vec<String> {
    if entry.route == "*" {
        present_routes(c, visited_all)
    } else {
        vec![entry.route.clone()]
    }
}

fn legacy_opener_routes(
    inv: &Inventory,
    c: &Control,
    opener_key: &str,
    by_key: &BTreeMap<&str, usize>,
    visited_all: &[String],
) -> Vec<String> {
    if c.route != "*" {
        return vec![c.route.clone()];
    }
    if let Some(&oi) = by_key.get(opener_key) {
        let opener_routes = present_routes(&inv.controls[oi], visited_all);
        if c.routes.is_empty() {
            return opener_routes;
        }
        let opener_set: BTreeSet<&str> = opener_routes.iter().map(String::as_str).collect();
        return c
            .routes
            .iter()
            .filter(|r| opener_set.contains(r.as_str()))
            .cloned()
            .collect();
    }
    present_routes(c, visited_all)
}

/// Why an unmatched goal may still exist: what this map could not observe.
fn unmatched_notes(inv: &Inventory, goal: &Goal) -> Vec<String> {
    let mut out = Vec::new();
    let blocked_forms = inv
        .controls
        .iter()
        .filter(|c| c.reason.as_deref() == Some("validation_blocked"))
        .count();
    let unexercised = inv
        .controls
        .iter()
        .filter(|c| c.status == ControlStatus::NotExercised)
        .count();
    match goal {
        Goal::Endpoint { .. } => {
            out.push(format!(
                "No control or page load in this map called {}: the endpoint was never observed.",
                goal.describe().trim_start_matches("endpoint ")
            ));
            if blocked_forms > 0 {
                out.push(format!(
                    "{blocked_forms} form submit{} stopped at empty required fields (the crawler does not fill forms), so writes behind {} were not observed.",
                    if blocked_forms == 1 { "" } else { "s" },
                    if blocked_forms == 1 { "it" } else { "them" }
                ));
            }
        }
        Goal::Route { .. } => {
            out.push("No route or link target in the map matches this route.".to_string());
        }
        Goal::Label { .. } => {
            out.push("No control label in the map contains this text.".to_string());
        }
    }
    if unexercised > 0 {
        out.push(format!(
            "{unexercised} control{} not exercised.",
            if unexercised == 1 { " was" } else { "s were" }
        ));
    }
    let c = &inv.coverage;
    out.push(format!(
        "Coverage: {}/{} controls exercised, {}/{} known routes visited. Not observed is not the same as unreachable.",
        c.controls_exercised,
        if c.controls_exercisable > 0 {
            c.controls_exercisable
        } else {
            c.controls_total
        },
        c.routes_visited,
        c.routes_known
    ));
    out
}

fn present_routes(c: &Control, visited_all: &[String]) -> Vec<String> {
    if c.route == "*" && c.routes.is_empty() {
        visited_all.to_vec()
    } else {
        c.present_on().into_iter().map(str::to_string).collect()
    }
}

fn resolve_route(inv: &Inventory, raw: &str) -> String {
    if raw == "*" {
        return raw.to_string();
    }
    select_routes(inv.routes.iter().map(|r| r.route.as_str()), raw)
        .first()
        .map(|r| (*r).to_string())
        .unwrap_or_else(|| query_route_parts(raw).0)
}

/// Unlike a route-template match, this requires a concrete recorded target.
/// An unqualified record goal may reach any tab on that exact record.
fn exact_destination(target: &str, request: &str) -> bool {
    let (path, query) = query_route_parts(target);
    let (wanted_path, wanted_query) = query_route_parts(request);
    !route_has_parameters(&path)
        && route_matches(&path, &wanted_path)
        && (wanted_query.is_none() || query == wanted_query)
}

fn describe_opener_target(c: &Control) -> String {
    for o in &c.outcomes {
        if let Outcome::DomChange { kind } = o {
            match kind.as_str() {
                "modal" | "menu" | "panel" | "dialog" | "drawer" | "popover" | "dropdown"
                | "tab" => return format!("opens {kind}"),
                _ => {}
            }
        }
    }
    if !c.outcomes.is_empty() {
        return super::render::describe_does(c);
    }
    if c.role == "tab" {
        return "opens tab".to_string();
    }
    let does = super::render::describe_does(c);
    if does == "ok" {
        "opens sub-view".to_string()
    } else {
        does
    }
}

fn terminal_action(goal: &Goal, c: &Control) -> (&'static str, bool) {
    match goal {
        Goal::Route { .. } => ("navigates", false),
        Goal::Endpoint { .. } => ("calls", true),
        Goal::Label { .. } => {
            if c.navigates_to().next().is_some() && c.endpoints().next().is_none() {
                ("navigates", false)
            } else if c.endpoints().next().is_some() {
                ("calls", true)
            } else {
                ("triggers", true)
            }
        }
    }
}

fn step_endpoints(c: &Control) -> Vec<StepEndpoint> {
    let mut out = Vec::new();
    for o in &c.outcomes {
        if let Outcome::Calls {
            endpoint,
            status,
            blocked,
        } = o
        {
            let ep = StepEndpoint {
                endpoint: super::stable_endpoint(endpoint),
                status: *status,
                blocked: *blocked,
            };
            if !out.contains(&ep) {
                out.push(ep);
            }
        }
    }
    out
}

fn step_source(c: &Control) -> Option<String> {
    c.source
        .as_ref()
        .and_then(|s| s.handler.as_ref().or(s.render.as_ref()))
        .map(|fl| format!("{}:{}", fl.file, fl.line))
}

fn make_step(c: &Control, route: &str, to: &str, action: &str, in_page: bool) -> Step {
    Step {
        route: route.to_string(),
        key: c.key.clone(),
        role: c.role.clone(),
        label: c.display_label(),
        status: c.status,
        to: to.to_string(),
        action: action.to_string(),
        in_page,
        endpoints: step_endpoints(c),
        source: step_source(c),
    }
}

fn status_rank(s: ControlStatus) -> u8 {
    match s {
        ControlStatus::Ok => 0,
        ControlStatus::NotExercised => 1,
        ControlStatus::Skipped => 2,
        ControlStatus::Disabled => 3,
        ControlStatus::External => 4,
        ControlStatus::NoEffect => 5,
        ControlStatus::Dead => 6,
        ControlStatus::Broken => 7,
    }
}

struct ExpandOption {
    control_idx: usize,
    to: String,
    action: &'static str,
    in_page: bool,
    next: Option<StateNode>,
}

#[allow(clippy::too_many_arguments)]
fn expand(
    inv: &Inventory,
    available: &BTreeMap<StateNode, BTreeSet<AvailableControl>>,
    forward_adj: &BTreeMap<StateNode, Vec<GraphEdge>>,
    dist: &BTreeMap<StateNode, usize>,
    terminal: &[(usize, String)],
    goal: &Goal,
    node: &StateNode,
    d: usize,
    used_openers: &mut BTreeSet<(String, String)>,
    cur: &mut Vec<Step>,
    out: &mut Vec<JourneyPath>,
) {
    if out.len() >= MAX_PATHS {
        return;
    }
    let Some(avails) = available.get(node) else {
        return;
    };
    let mut options: Vec<ExpandOption> = Vec::new();
    if d == 1 {
        let avail_idxs: BTreeSet<usize> = avails.iter().map(|a| a.control_idx).collect();
        for (i, to) in terminal {
            if avail_idxs.contains(i) {
                let (action, in_page) = terminal_action(goal, &inv.controls[*i]);
                options.push(ExpandOption {
                    control_idx: *i,
                    to: to.clone(),
                    action,
                    in_page,
                    next: None,
                });
            }
        }
    } else if let Some(edges) = forward_adj.get(node) {
        let route_str = node.route();
        for edge in edges {
            if dist.get(&edge.next) != Some(&(d - 1)) {
                continue;
            }
            if edge.in_page {
                let opener_pair = (
                    route_str.to_string(),
                    inv.controls[edge.control_idx].key.clone(),
                );
                if used_openers.contains(&opener_pair) {
                    continue;
                }
            }
            options.push(ExpandOption {
                control_idx: edge.control_idx,
                to: edge.to.clone(),
                action: edge.action,
                in_page: edge.in_page,
                next: Some(edge.next.clone()),
            });
        }
    }
    options.sort_by(|a, b| {
        let (ca, cb) = (&inv.controls[a.control_idx], &inv.controls[b.control_idx]);
        status_rank(ca.status)
            .cmp(&status_rank(cb.status))
            .then_with(|| ca.key.cmp(&cb.key))
            .then_with(|| a.to.cmp(&b.to))
            .then_with(|| a.next.cmp(&b.next))
    });
    options.dedup_by(|a, b| a.control_idx == b.control_idx && a.to == b.to && a.next == b.next);
    let route_str = node.route();
    for opt in options.into_iter().take(MAX_BRANCH) {
        let c = &inv.controls[opt.control_idx];
        let s = make_step(c, route_str, &opt.to, opt.action, opt.in_page);
        cur.push(s);
        match opt.next {
            None => {
                let path = JourneyPath::from_steps(cur.clone());
                if !out.contains(&path) {
                    out.push(path);
                }
            }
            Some(next_node) => {
                let inserted_opener = if opt.in_page {
                    let pair = (route_str.to_string(), c.key.clone());
                    used_openers.insert(pair.clone());
                    Some(pair)
                } else {
                    None
                };
                expand(
                    inv,
                    available,
                    forward_adj,
                    dist,
                    terminal,
                    goal,
                    &next_node,
                    d - 1,
                    used_openers,
                    cur,
                    out,
                );
                if let Some(pair) = inserted_opener {
                    used_openers.remove(&pair);
                }
            }
        }
        cur.pop();
        if out.len() >= MAX_PATHS {
            return;
        }
    }
}

fn evidence_label(path_evidence: &str) -> &'static str {
    match path_evidence {
        "already_at_goal" => "already at goal",
        "stitched_candidate" => {
            "stitched candidate from recorded steps (not a continuous E2E replay)"
        }
        "unmatched" => "unmatched",
        _ => "not established",
    }
}

fn blocked_step_suffix(s: &Step) -> &'static str {
    if s.action == "calls"
        && !s.to.contains("[write blocked]")
        && s.endpoints
            .iter()
            .any(|e| e.blocked && e.endpoint == super::stable_endpoint(&s.to))
    {
        " [write blocked]"
    } else {
        ""
    }
}

fn format_step_endpoint(ep: &StepEndpoint) -> String {
    let mut s = ep.endpoint.clone();
    if ep.blocked {
        s.push_str(" [write blocked]");
    } else if let Some(st) = ep.status.filter(|st| *st >= 400) {
        s.push_str(&format!(" ({st})"));
    }
    s
}

fn pluralize_role(role: &str, count: usize) -> String {
    if count == 1 {
        return role.to_string();
    }
    match role {
        "checkbox" => "checkboxes".to_string(),
        "other" => "other".to_string(),
        r if r.ends_with('s') || r.ends_with('x') || r.ends_with("ch") || r.ends_with("sh") => {
            format!("{r}es")
        }
        r => format!("{r}s"),
    }
}

fn format_path_breakdown(p: &JourneyPath) -> String {
    let mut parts = format!(
        "{} step{}: {} route hop{}, {} in-page",
        p.hops,
        if p.hops == 1 { "" } else { "s" },
        p.route_hops,
        if p.route_hops == 1 { "" } else { "s" },
        p.in_page_steps
    );
    if !p.control_kinds.is_empty() {
        let mut kinds: Vec<(&String, &usize)> = p.control_kinds.iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let list: Vec<String> = kinds
            .into_iter()
            .map(|(role, count)| format!("{count} {}", pluralize_role(role, *count)))
            .collect();
        parts.push_str(" — ");
        parts.push_str(&list.join(", "));
    }
    if !p.endpoints.is_empty() {
        let eps: Vec<String> = p.endpoints.iter().map(format_step_endpoint).collect();
        parts.push_str("; calls: ");
        parts.push_str(&eps.join(", "));
    }
    if p.has_gaps_or_failures {
        parts.push_str("; has gaps/failures");
    }
    parts
}

/// Human-readable journey report.
pub fn render_text(res: &JourneyResult, max_hops: usize) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Journey to {}", res.goal.describe());
    if res.matched.is_empty() {
        let _ = writeln!(
            out,
            "No route, endpoint, or control in the map matches this goal."
        );
        for n in &res.notes {
            let _ = writeln!(out, "  {n}");
        }
        if !res.code_references.is_empty() {
            let _ = writeln!(
                out,
                "\nSource references (static search, not observed at runtime):"
            );
            for r in &res.code_references {
                let _ = writeln!(out, "  {r}");
            }
        }
        return out;
    }
    for n in &res.notes {
        let _ = writeln!(out, "Note: {n}");
    }
    let _ = writeln!(out, "Matches: {}", res.matched.join(", "));
    out.push('\n');
    if res.direct.is_empty() {
        let message = match &res.goal {
            Goal::Route { .. } => "No direct navigation to this destination was recorded.",
            _ => "No control interaction reaching this goal was recorded.",
        };
        let _ = writeln!(out, "{message}");
    } else {
        let _ = writeln!(
            out,
            "Controls that lead here directly ({}):",
            res.direct.len()
        );
        for s in &res.direct {
            let _ = writeln!(
                out,
                "  {} {} \"{}\" → {}{}{}",
                s.route,
                s.role,
                s.label,
                s.to,
                blocked_step_suffix(s),
                mark(s.status)
            );
        }
    }
    out.push('\n');
    match res.distance {
        Some(0) => {
            let _ = writeln!(out, "Start route {} is already the goal.", res.from);
        }
        Some(d) if d <= max_hops => {
            let _ = writeln!(
                out,
                "From {} (shortest: {d} hop{}):",
                res.from,
                if d == 1 { "" } else { "s" }
            );
            for (i, p) in res.paths.iter().enumerate() {
                let mut line = format!("  {}. {}", i + 1, res.from);
                for s in &p.steps {
                    let _ = write!(
                        line,
                        " → {} \"{}\"{} → {}{}",
                        s.role,
                        s.label,
                        mark(s.status),
                        s.to,
                        blocked_step_suffix(s)
                    );
                }
                let _ = writeln!(out, "{line}");
                let _ = writeln!(out, "     ({})", format_path_breakdown(p));
            }
            if res.paths.len() >= MAX_PATHS {
                let _ = writeln!(out, "  (first {MAX_PATHS} paths shown)");
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "No path from {} within {max_hops} hops is established by this map.",
                res.from
            );
        }
    }
    let _ = writeln!(out, "Evidence: {}", evidence_label(&res.path_evidence));
    out
}

/// GitHub-flavored Markdown journey report.
pub fn render_markdown(res: &JourneyResult, max_hops: usize) -> String {
    use super::render::md_cell;
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "## Journey to {}\n", md_cell(&res.goal.describe()));
    if res.matched.is_empty() {
        out.push_str("No route, endpoint, or control in the map matches this goal.\n\n");
        for n in &res.notes {
            let _ = writeln!(out, "- {}", md_cell(n));
        }
        if !res.notes.is_empty() {
            out.push('\n');
        }
        if !res.code_references.is_empty() {
            out.push_str("### Source References (static search, not observed at runtime)\n\n");
            for r in &res.code_references {
                let _ = writeln!(out, "- `{}`", md_cell(r));
            }
            out.push('\n');
        }
        let _ = writeln!(out, "**Evidence:** {}", evidence_label(&res.path_evidence));
        return out;
    }

    let _ = writeln!(out, "- **From:** `{}`", md_cell(&res.from));
    let matches_md: Vec<String> = res
        .matched
        .iter()
        .map(|m| format!("`{}`", md_cell(m)))
        .collect();
    let _ = writeln!(out, "- **Matches:** {}", matches_md.join(", "));
    let _ = writeln!(
        out,
        "- **Evidence:** {}\n",
        evidence_label(&res.path_evidence)
    );

    if !res.notes.is_empty() {
        for n in &res.notes {
            let _ = writeln!(out, "> **Note:** {}", md_cell(n));
        }
        out.push('\n');
    }

    out.push_str("### Shortest Paths\n\n");
    match res.distance {
        Some(0) => {
            let _ = writeln!(
                out,
                "Start route `{}` is already the goal.\n",
                md_cell(&res.from)
            );
        }
        Some(d) if d <= max_hops => {
            let _ = writeln!(
                out,
                "Shortest path from `{}`: **{} hop{}**.\n",
                md_cell(&res.from),
                d,
                if d == 1 { "" } else { "s" }
            );
            for (i, p) in res.paths.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "#### Path {} ({})\n",
                    i + 1,
                    md_cell(&format_path_breakdown(p))
                );
                out.push_str("| # | Route | Control | Action | Leads To | Status | Source |\n");
                out.push_str("|---:|---|---|---|---|---|---|\n");
                for (si, s) in p.steps.iter().enumerate() {
                    let action_cell = if s.in_page {
                        format!("{} (in-page)", s.action)
                    } else {
                        s.action.clone()
                    };
                    let to_cell = format!("{}{}", s.to, blocked_step_suffix(s));
                    let source_cell = s
                        .source
                        .as_deref()
                        .map(|src| format!("`{}`", md_cell(src)))
                        .unwrap_or_else(|| "-".to_string());
                    let _ = writeln!(
                        out,
                        "| {} | `{}` | {} \"{}\" | {} | {} | `{}` | {} |",
                        si + 1,
                        md_cell(&s.route),
                        md_cell(&s.role),
                        md_cell(&s.label),
                        md_cell(&action_cell),
                        md_cell(&to_cell),
                        s.status.as_str(),
                        source_cell,
                    );
                }
                out.push('\n');
            }
            if res.paths.len() >= MAX_PATHS {
                let _ = writeln!(out, "_(first {MAX_PATHS} paths shown)_\n");
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "No path from `{}` within {max_hops} hops is established by this map.\n",
                md_cell(&res.from)
            );
        }
    }

    let _ = writeln!(out, "### Direct Controls ({})\n", res.direct.len());
    if res.direct.is_empty() {
        let message = match &res.goal {
            Goal::Route { .. } => "No direct navigation to this destination was recorded.",
            _ => "No control interaction reaching this goal was recorded.",
        };
        let _ = writeln!(out, "{message}");
    } else {
        out.push_str("| Route | Control | Action | Leads To | Status | Source |\n");
        out.push_str("|---|---|---|---|---|---|\n");
        for s in &res.direct {
            let to_cell = format!("{}{}", s.to, blocked_step_suffix(s));
            let source_cell = s
                .source
                .as_deref()
                .map(|src| format!("`{}`", md_cell(src)))
                .unwrap_or_else(|| "-".to_string());
            let _ = writeln!(
                out,
                "| `{}` | {} \"{}\" | {} | {} | `{}` | {} |",
                md_cell(&s.route),
                md_cell(&s.role),
                md_cell(&s.label),
                md_cell(&s.action),
                md_cell(&to_cell),
                s.status.as_str(),
                source_cell,
            );
        }
    }
    out
}

fn mark(status: ControlStatus) -> String {
    match status {
        ControlStatus::Ok => String::new(),
        other => format!(" [{other}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_link::runtime_source::{FileLine, ResolvedSource};
    use crate::inventory::{CoverageSummary, EndpointEntry, RouteEntry};

    fn make_control(
        route: &str,
        role: &str,
        label: &str,
        status: ControlStatus,
        outcomes: Vec<Outcome>,
    ) -> Control {
        let slug = label.to_lowercase();
        Control {
            key: format!("{route}|{role}|text={slug}"),
            route: route.into(),
            role: role.into(),
            label: label.into(),
            selector: format!("[data-testid='{slug}']"),
            locator: format!("text={slug}"),
            count: 1,
            status,
            outcomes,
            ..Default::default()
        }
    }

    fn make_inv(routes: &[&str], controls: Vec<Control>, endpoints: &[&str]) -> Inventory {
        Inventory {
            schema: crate::inventory::INVENTORY_SCHEMA.into(),
            project: "journey-test".into(),
            generated_at: "2026-11-20T00:00:00Z".into(),
            target_url: "http://127.0.0.1:3000/".into(),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: routes.len() as u32,
                routes_visited: routes.len() as u32,
                controls_total: controls.len() as u32,
                controls_exercised: controls.len() as u32,
                controls_exercisable: controls.len() as u32,
                ..Default::default()
            },
            routes: routes
                .iter()
                .map(|r| RouteEntry {
                    route: (*r).into(),
                    visited: true,
                    ..Default::default()
                })
                .collect(),
            controls,
            endpoints: endpoints
                .iter()
                .map(|e| EndpointEntry {
                    endpoint: (*e).into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn state_entry(
        route: &str,
        variant: Option<&str>,
        kind: ControlStateEntryKind,
    ) -> ControlStateEntry {
        ControlStateEntry {
            route: route.into(),
            variant: variant.map(str::to_string),
            kind,
        }
    }

    #[test]
    fn multi_step_route_and_opener_chain_reports_full_depth_and_metrics() {
        let mut orders_link = make_control(
            "/",
            "link",
            "Orders",
            ControlStatus::Ok,
            vec![Outcome::Navigates {
                to: "/orders".into(),
            }],
        );
        orders_link.state_entries = vec![state_entry("/", None, ControlStateEntryKind::Direct)];

        let mut open_drawer = make_control(
            "/orders",
            "button",
            "Open drawer",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "drawer".into(),
            }],
        );
        open_drawer.state_entries =
            vec![state_entry("/orders", None, ControlStateEntryKind::Direct)];

        let mut payments_tab = make_control(
            "/orders",
            "tab",
            "Payments",
            ControlStatus::Ok,
            vec![Outcome::DomChange { kind: "tab".into() }],
        );
        payments_tab.state_entries = vec![state_entry(
            "/orders",
            None,
            ControlStateEntryKind::Opened {
                opener: open_drawer.key.clone(),
            },
        )];

        let mut review_btn = make_control(
            "/orders",
            "button",
            "Review",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "panel".into(),
            }],
        );
        review_btn.state_entries = vec![state_entry(
            "/orders",
            None,
            ControlStateEntryKind::Opened {
                opener: payments_tab.key.clone(),
            },
        )];

        let mut submit_btn = make_control(
            "/orders",
            "button",
            "Submit",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "POST /api/orders".into(),
                status: None,
                blocked: true,
            }],
        );
        submit_btn.state_entries = vec![state_entry(
            "/orders",
            None,
            ControlStateEntryKind::Opened {
                opener: review_btn.key.clone(),
            },
        )];
        submit_btn.source = Some(ResolvedSource {
            handler: Some(FileLine {
                file: "src/orders/Submit.tsx".into(),
                line: 42,
                col: 4,
            }),
            render: Some(FileLine {
                file: "src/orders/Drawer.tsx".into(),
                line: 10,
                col: 2,
            }),
            method: "runtime".into(),
            confidence: "exact".into(),
            ..Default::default()
        });

        let inv = make_inv(
            &["/", "/orders"],
            vec![
                orders_link,
                open_drawer,
                payments_tab,
                review_btn,
                submit_btn,
            ],
            &["POST /api/orders"],
        );

        let goal = parse_goal("POST /api/orders", &inv);
        let res = journey(&inv, &goal, None, 15);
        assert!(res.reachable);
        assert_eq!(res.distance, Some(5));
        assert_eq!(res.path_evidence, "stitched_candidate");
        assert_eq!(res.paths.len(), 1);

        let p = &res.paths[0];
        assert_eq!(p.hops, 5);
        assert_eq!(p.route_hops, 1);
        assert_eq!(p.in_page_steps, 4);
        assert!(!p.has_gaps_or_failures);
        assert_eq!(
            p.control_kinds,
            BTreeMap::from([("button".into(), 3), ("link".into(), 1), ("tab".into(), 1),])
        );
        assert_eq!(
            p.endpoints,
            vec![StepEndpoint {
                endpoint: "POST /api/orders".into(),
                status: None,
                blocked: true,
            }]
        );
        let labels: Vec<&str> = p.steps.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(
            labels,
            vec!["Orders", "Open drawer", "Payments", "Review", "Submit"]
        );
        assert_eq!(p.steps[0].action, "navigates");
        assert!(!p.steps[0].in_page);
        assert_eq!(p.steps[1].action, "opens");
        assert!(p.steps[1].in_page);
        assert_eq!(p.steps[1].to, "opens drawer");
        assert_eq!(p.steps[4].action, "calls");
        assert!(p.steps[4].in_page);
        assert_eq!(
            p.steps[4].source.as_deref(),
            Some("src/orders/Submit.tsx:42")
        );

        // From `/orders` directly it is still 4 hops (not falsely 1 hop!).
        let from_orders = journey(&inv, &goal, Some("/orders"), 15);
        assert_eq!(from_orders.distance, Some(4));
        assert_eq!(from_orders.paths[0].route_hops, 0);
        assert_eq!(from_orders.paths[0].in_page_steps, 4);

        let text = render_text(&res, 15);
        assert!(
            text.contains(
                "/ → link \"Orders\" → /orders → button \"Open drawer\" → opens drawer → tab \"Payments\" → opens tab → button \"Review\" → opens panel → button \"Submit\" → POST /api/orders [write blocked]"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "(5 steps: 1 route hop, 4 in-page — 3 buttons, 1 link, 1 tab; calls: POST /api/orders [write blocked])"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "Evidence: stitched candidate from recorded steps (not a continuous E2E replay)"
            ),
            "{text}"
        );

        let md = render_markdown(&res, 15);
        assert!(
            md.contains("## Journey to endpoint POST /api/orders"),
            "{md}"
        );
        assert!(
            md.contains("| # | Route | Control | Action | Leads To | Status | Source |"),
            "{md}"
        );
        assert!(md.contains("`src/orders/Submit.tsx:42`"), "{md}");
        assert!(md.contains("POST /api/orders [write blocked]"), "{md}");
        assert!(md.contains("stitched candidate"), "{md}");
    }

    #[test]
    fn cross_variant_isolation_never_stitches_across_variants() {
        let mut open_a = make_control(
            "/account",
            "button",
            "Open A",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "modal".into(),
            }],
        );
        open_a.state_entries = vec![state_entry(
            "/account",
            Some("?tab=a"),
            ControlStateEntryKind::Direct,
        )];

        let mut open_b = make_control(
            "/account",
            "button",
            "Open B",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "modal".into(),
            }],
        );
        open_b.state_entries = vec![state_entry(
            "/account",
            Some("?tab=b"),
            ControlStateEntryKind::Direct,
        )];

        // Opened by `open_b`, but only recorded on `?tab=a` — cannot stitch from `?tab=b`.
        let mut cross_btn = make_control(
            "/account",
            "button",
            "Cross Save",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "POST /api/cross".into(),
                status: Some(200),
                blocked: false,
            }],
        );
        cross_btn.state_entries = vec![state_entry(
            "/account",
            Some("?tab=a"),
            ControlStateEntryKind::Opened {
                opener: open_b.key.clone(),
            },
        )];

        // Valid chain entirely within `?tab=a`.
        let mut valid_btn = make_control(
            "/account",
            "button",
            "Valid Save",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "POST /api/valid".into(),
                status: Some(200),
                blocked: false,
            }],
        );
        valid_btn.state_entries = vec![state_entry(
            "/account",
            Some("?tab=a"),
            ControlStateEntryKind::Opened {
                opener: open_a.key.clone(),
            },
        )];

        let inv = make_inv(
            &["/account"],
            vec![open_a, open_b, cross_btn, valid_btn],
            &["POST /api/cross", "POST /api/valid"],
        );

        let cross = journey(
            &inv,
            &parse_goal("POST /api/cross", &inv),
            Some("/account"),
            15,
        );
        assert!(!cross.reachable);
        assert_eq!(cross.distance, None);
        assert!(cross.paths.is_empty());
        assert_eq!(cross.direct.len(), 1);
        assert_eq!(cross.path_evidence, "not_established");

        let valid = journey(
            &inv,
            &parse_goal("POST /api/valid", &inv),
            Some("/account"),
            15,
        );
        assert!(valid.reachable);
        assert_eq!(valid.distance, Some(2));
        assert_eq!(valid.paths.len(), 1);
        assert_eq!(valid.paths[0].steps[0].label, "Open A");
        assert_eq!(valid.paths[0].steps[1].label, "Valid Save");
    }

    #[test]
    fn unknown_state_entry_is_not_pretended_to_be_direct() {
        let mut mystery = make_control(
            "/orders",
            "button",
            "Mystery Submit",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "POST /api/mystery".into(),
                status: None,
                blocked: true,
            }],
        );
        mystery.state_entries = vec![state_entry("/orders", None, ControlStateEntryKind::Unknown)];

        let mut opener = make_control(
            "/orders",
            "button",
            "Open Panel",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "panel".into(),
            }],
        );
        opener.state_entries = vec![state_entry("/orders", None, ControlStateEntryKind::Direct)];

        // Has both Unknown and Opened: must require the Opened path (2 hops), not 1 hop.
        let mut mixed = make_control(
            "/orders",
            "button",
            "Mixed Submit",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "POST /api/mixed".into(),
                status: None,
                blocked: true,
            }],
        );
        mixed.state_entries = vec![
            state_entry("/orders", None, ControlStateEntryKind::Unknown),
            state_entry(
                "/orders",
                None,
                ControlStateEntryKind::Opened {
                    opener: opener.key.clone(),
                },
            ),
        ];

        let inv = make_inv(
            &["/orders"],
            vec![mystery, opener, mixed],
            &["POST /api/mystery", "POST /api/mixed"],
        );

        let res_unknown = journey(
            &inv,
            &parse_goal("POST /api/mystery", &inv),
            Some("/orders"),
            15,
        );
        assert!(!res_unknown.reachable);
        assert_eq!(res_unknown.distance, None);
        assert!(res_unknown.paths.is_empty());
        assert_eq!(res_unknown.direct.len(), 1);
        assert_eq!(res_unknown.path_evidence, "not_established");
        assert!(
            res_unknown
                .notes
                .iter()
                .any(|n| n.contains("unknown state-entry provenance")),
            "{:?}",
            res_unknown.notes
        );

        let res_mixed = journey(
            &inv,
            &parse_goal("POST /api/mixed", &inv),
            Some("/orders"),
            15,
        );
        assert!(res_mixed.reachable);
        assert_eq!(res_mixed.distance, Some(2));
        assert_eq!(res_mixed.paths[0].steps[0].label, "Open Panel");
        assert_eq!(res_mixed.paths[0].steps[1].label, "Mixed Submit");
    }

    #[test]
    fn legacy_opened_by_chain_and_gap_detection_work_without_state_entries() {
        let mut global_menu = make_control(
            "*",
            "button",
            "Actions",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "menu".into(),
            }],
        );
        global_menu.routes = vec!["/".into(), "/items".into()];

        let mut open_confirm = make_control(
            "/items",
            "button",
            "Archive",
            ControlStatus::NoEffect,
            vec![Outcome::DomChange {
                kind: "modal".into(),
            }],
        );
        open_confirm.opened_by = vec![global_menu.key.clone()];

        let mut confirm = make_control(
            "/items",
            "button",
            "Confirm Archive",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "DELETE /api/items/:id".into(),
                status: None,
                blocked: true,
            }],
        );
        confirm.opened_by = vec![open_confirm.key.clone()];

        let inv = make_inv(
            &["/", "/items"],
            vec![global_menu, open_confirm, confirm],
            &["DELETE /api/items/:id"],
        );

        let res = journey(
            &inv,
            &parse_goal("DELETE /api/items/:id", &inv),
            Some("/items"),
            15,
        );
        assert!(res.reachable);
        assert_eq!(res.distance, Some(3));
        assert_eq!(res.paths.len(), 1);
        assert_eq!(res.paths[0].route_hops, 0);
        assert_eq!(res.paths[0].in_page_steps, 3);
        assert!(res.paths[0].has_gaps_or_failures);
        let labels: Vec<&str> = res.paths[0]
            .steps
            .iter()
            .map(|s| s.label.as_str())
            .collect();
        assert_eq!(labels, vec!["Actions", "Archive", "Confirm Archive"]);
    }

    #[test]
    fn mutual_opener_cycle_resolves_cleanly_without_looping() {
        let mut a = make_control(
            "/",
            "button",
            "Panel A",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "panel".into(),
            }],
        );
        let mut b = make_control(
            "/",
            "button",
            "Panel B",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "panel".into(),
            }],
        );
        a.state_entries = vec![
            state_entry("/", None, ControlStateEntryKind::Direct),
            state_entry(
                "/",
                None,
                ControlStateEntryKind::Opened {
                    opener: b.key.clone(),
                },
            ),
        ];
        b.state_entries = vec![state_entry(
            "/",
            None,
            ControlStateEntryKind::Opened {
                opener: a.key.clone(),
            },
        )];
        let mut done = make_control(
            "/",
            "button",
            "Finish",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "POST /api/done".into(),
                status: Some(200),
                blocked: false,
            }],
        );
        done.state_entries = vec![state_entry(
            "/",
            None,
            ControlStateEntryKind::Opened {
                opener: b.key.clone(),
            },
        )];

        let inv = make_inv(&["/"], vec![a, b, done], &["POST /api/done"]);
        let res = journey(&inv, &parse_goal("POST /api/done", &inv), Some("/"), 15);
        assert!(res.reachable);
        assert_eq!(res.distance, Some(3));
        assert_eq!(res.paths.len(), 1);
        let labels: Vec<&str> = res.paths[0]
            .steps
            .iter()
            .map(|s| s.label.as_str())
            .collect();
        assert_eq!(labels, vec!["Panel A", "Panel B", "Finish"]);
    }

    #[test]
    fn parse_goal_and_journey_trace_websocket_rpc_endpoints() {
        let mut opener = make_control(
            "/settings",
            "button",
            "Open Settings",
            ControlStatus::Ok,
            vec![Outcome::DomChange {
                kind: "dialog".into(),
            }],
        );
        opener.state_entries = vec![state_entry(
            "/settings",
            None,
            ControlStateEntryKind::Direct,
        )];
        let mut save = make_control(
            "/settings",
            "button",
            "Save Settings",
            ControlStatus::Ok,
            vec![Outcome::Calls {
                endpoint: "WS /ws#server.updateSettings".into(),
                status: None,
                blocked: true,
            }],
        );
        save.state_entries = vec![state_entry(
            "/settings",
            None,
            ControlStateEntryKind::Opened {
                opener: opener.key.clone(),
            },
        )];
        let inv = make_inv(
            &["/settings"],
            vec![opener, save],
            &["WS /ws#server.updateSettings"],
        );

        let g_exact = parse_goal("WS /ws#server.updateSettings", &inv);
        assert_eq!(
            g_exact,
            Goal::Endpoint {
                method: Some("WS".into()),
                path: "/ws#server.updateSettings".into(),
            }
        );
        let res = journey(&inv, &g_exact, Some("/settings"), 15);
        assert!(res.reachable);
        assert_eq!(res.distance, Some(2));
        let labels: Vec<&str> = res.paths[0]
            .steps
            .iter()
            .map(|s| s.label.as_str())
            .collect();
        assert_eq!(labels, vec!["Open Settings", "Save Settings"]);

        // Base WS path and full ws:// URL with #op also match.
        let g_base = parse_goal("WS /ws", &inv);
        assert!(journey(&inv, &g_base, Some("/settings"), 15).reachable);
        let g_url = parse_goal("ws://127.0.0.1:3773/ws#server.updateSettings", &inv);
        assert!(journey(&inv, &g_url, Some("/settings"), 15).reachable);
    }
}
