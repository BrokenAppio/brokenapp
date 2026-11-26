//! Merge an incremental re-crawl (`brokenapp map --changed`) into the
//! previous whole-app map.
//!
//! The re-crawl covers a few routes and is built with
//! [`BuildOptions::keep_route_scope`](super::BuildOptions), so its shell
//! controls stay on their routes. The merge:
//!
//! - replaces the controls, route entries and endpoint-index rows of every
//!   re-crawled route with the re-crawl's;
//! - keeps every other route, control and endpoint row byte-identical;
//! - folds the re-crawl's copies of shell controls (`*`) into the previous
//!   map's global controls. A global whose own source file changed is
//!   refreshed for every route it is on (the representative route showed the
//!   new version); otherwise only an identical copy refreshes it, and a copy
//!   that now differs (another target) stays on its route, the way a
//!   whole-app map would split it off;
//! - recomputes coverage.
//!
//! So `diff(previous, merged)` can only report changes on re-crawled routes
//! and on refreshed global controls.

use std::collections::{BTreeMap, BTreeSet};

use super::build::coverage_summary;
use super::identity::SHELL_REGIONS;
use super::{
    Control, ControlStateEntryKind, ControlStatus, EndpointEntry, IncrementalInfo, Inventory,
    Outcome, RouteEntry, RouteScan,
};

/// Inputs of [`merge_incremental`] besides the two inventories.
#[derive(Debug, Clone, Default)]
pub struct MergeOptions {
    /// Routes the run set out to re-crawl (inventory route names).
    pub requested: BTreeSet<String>,
    /// Routes whose defining file was deleted: dropped from the map.
    pub removed: BTreeSet<String>,
    /// Changed files (codebase-relative). A global control whose source is
    /// one of them is refreshed for every route it is on.
    pub changed_files: BTreeSet<String>,
    /// Changed files that selected the re-crawled routes (recorded in
    /// [`IncrementalInfo::changed_files`] and the changelog heading); tests,
    /// docs and other unmapped files are left out.
    pub trigger_files: BTreeSet<String>,
    /// RFC3339 start of this run (recorded per re-crawled route).
    pub started_at: String,
}

/// Result of [`merge_incremental`].
#[derive(Debug, Clone)]
pub struct Merged {
    pub inventory: Inventory,
    /// Requested routes the re-crawl visited (replaced in the map).
    pub recrawled: Vec<String>,
    /// Requested routes the re-crawl did not visit (kept from the base map).
    pub kept: Vec<String>,
    /// Global controls refreshed from a re-crawled route.
    pub refreshed_globals: Vec<String>,
}

/// Merge `partial` (a re-crawl of `opts.requested`) into `base`.
pub fn merge_incremental(base: &Inventory, partial: &Inventory, opts: &MergeOptions) -> Merged {
    let partial_visited: BTreeSet<&str> = partial
        .routes
        .iter()
        .filter(|r| r.visited)
        .map(|r| r.route.as_str())
        .collect();
    let recrawled: BTreeSet<String> = opts
        .requested
        .iter()
        .filter(|r| !opts.removed.contains(*r) && partial_visited.contains(r.as_str()))
        .cloned()
        .collect();
    let kept: Vec<String> = opts
        .requested
        .iter()
        .filter(|r| !opts.removed.contains(*r) && !recrawled.contains(*r))
        .cloned()
        .collect();
    let replaced = |route: &str| recrawled.contains(route) || opts.removed.contains(route);

    // Re-crawled controls by route (the re-crawl has no `*` controls).
    let fresh: Vec<&Control> = partial
        .controls
        .iter()
        .filter(|c| recrawled.contains(&c.route))
        .collect();
    let mut claimed: BTreeSet<usize> = BTreeSet::new();
    // Re-crawl key -> merged key, for `opened_by` and endpoint rows.
    let mut key_map: BTreeMap<String, String> = BTreeMap::new();
    let mut controls: Vec<Control> = Vec::new();
    let mut refreshed_globals = Vec::new();
    // Source files of refreshed globals -> their routes (new shell controls
    // rendered by the same file become globals too).
    let mut shell_files: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut global_keys: BTreeSet<String> = BTreeSet::new();

    for g in base.controls.iter().filter(|c| c.route == "*") {
        let src_changed = source_files(g)
            .iter()
            .any(|f| opts.changed_files.contains(f));
        let mut routes: BTreeSet<String> =
            g.routes.iter().filter(|r| !replaced(r)).cloned().collect();
        let mut observations: Vec<usize> = Vec::new();
        for route in &recrawled {
            let on_route = |i: &usize| fresh[*i].route == *route && !claimed.contains(i);
            let candidates: Vec<usize> = (0..fresh.len()).filter(on_route).collect();
            let exact = candidates.iter().copied().find(|i| {
                let c = fresh[*i];
                c.role == g.role && c.locator == g.locator && c.target == g.target
            });
            let found = exact.or_else(|| {
                if !src_changed {
                    return None;
                }
                let same_locator: Vec<usize> = candidates
                    .iter()
                    .copied()
                    .filter(|i| fresh[*i].role == g.role && fresh[*i].locator == g.locator)
                    .collect();
                match same_locator.as_slice() {
                    [one] => Some(*one),
                    // A relabeled shell control: same role, region, render
                    // file and target, a different text locator.
                    [] => {
                        let relabels: Vec<usize> = candidates
                            .iter()
                            .copied()
                            .filter(|i| relabeled(g, fresh[*i]))
                            .collect();
                        match relabels.as_slice() {
                            [one] => Some(*one),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            });
            if let Some(i) = found {
                claimed.insert(i);
                routes.insert(route.clone());
                observations.push(i);
            }
        }
        if routes.is_empty() {
            // Gone from every route it was on, all of them re-crawled.
            continue;
        }
        let mut merged = g.clone();
        merged.routes = routes.into_iter().collect();
        // State provenance describes observations, even when source changes
        // refresh a global's identity everywhere. Keep untouched contexts and
        // replace only the contexts actually re-crawled (or removed).
        let mut entries: BTreeSet<_> = g
            .state_entries
            .iter()
            .filter(|entry| !replaced(&entry.route))
            .cloned()
            .collect();
        for i in &observations {
            entries.extend(fresh[*i].state_entries.iter().cloned());
        }
        if entries.is_empty() && !g.state_entries.is_empty() {
            // Losing the last known entry must not turn a newer control back
            // into the legacy empty-list contract on an unproven route.
            entries.extend(merged.routes.iter().map(|route| super::ControlStateEntry {
                route: route.clone(),
                variant: None,
                kind: ControlStateEntryKind::Unknown,
            }));
        }
        merged.state_entries = entries.into_iter().collect();
        // Freshest evidence: an exercised observation first, then route order.
        let best = observations
            .iter()
            .copied()
            .min_by_key(|i| (!fresh[*i].status.is_exercised(), fresh[*i].route.clone()));
        if let Some(i) = best {
            let obs = fresh[i];
            refresh_global(&mut merged, obs, src_changed, &recrawled);
            if merged != *g {
                refreshed_globals.push(merged.key.clone());
            }
            for j in &observations {
                key_map.insert(fresh[*j].key.clone(), merged.key.clone());
            }
            if src_changed {
                for f in source_files(g) {
                    shell_files
                        .entry(f)
                        .or_default()
                        .extend(merged.routes.iter().cloned());
                }
            }
        }
        if merged.key != g.key {
            key_map.insert(g.key.clone(), merged.key.clone());
        }
        global_keys.insert(merged.key.clone());
        controls.push(merged);
    }

    // Untouched routes keep their controls as they were.
    controls.extend(
        base.controls
            .iter()
            .filter(|c| c.route != "*" && !replaced(&c.route))
            .cloned(),
    );

    // Re-crawled controls not folded into a global. A shell control rendered
    // by the same changed file as refreshed globals is a new global.
    for (i, c) in fresh.iter().enumerate() {
        if claimed.contains(&i) {
            continue;
        }
        let mut c = (*c).clone();
        let shell_routes = SHELL_REGIONS
            .contains(&c.region.as_str())
            .then(|| {
                source_files(&c)
                    .into_iter()
                    .filter_map(|f| shell_files.get(&f))
                    .next()
                    .cloned()
            })
            .flatten();
        if let Some(mut routes) = shell_routes
            && let Some((_, rest)) = c.key.split_once('|')
            && !global_keys.contains(&format!("*|{rest}"))
        {
            let key = format!("*|{rest}");
            key_map.insert(c.key.clone(), key.clone());
            routes.insert(c.route.clone());
            c.key = key;
            c.route = "*".to_string();
            c.routes = routes.into_iter().collect();
            c.variants.clear();
            global_keys.insert(c.key.clone());
        }
        controls.push(c);
    }
    for c in &mut controls {
        remap_keys(&mut c.opened_by, &key_map);
        for entry in &mut c.state_entries {
            if let ControlStateEntryKind::Opened { opener } = &mut entry.kind
                && let Some(to) = key_map.get(opener)
            {
                *opener = to.clone();
            }
        }
        c.state_entries.sort();
        c.state_entries.dedup();
    }
    controls.sort_by(|a, b| a.route.cmp(&b.route).then_with(|| a.key.cmp(&b.key)));

    // Routes: re-crawled entries replace the old ones (new pages are added).
    let mut routes: BTreeMap<String, RouteEntry> = base
        .routes
        .iter()
        .filter(|r| !opts.removed.contains(&r.route))
        .map(|r| (r.route.clone(), r.clone()))
        .collect();
    for r in partial
        .routes
        .iter()
        .filter(|r| recrawled.contains(&r.route))
    {
        let mut entry = r.clone();
        entry.controls = controls.iter().filter(|c| c.route == r.route).count() as u32;
        routes.insert(r.route.clone(), entry);
    }
    let routes: Vec<RouteEntry> = routes.into_values().collect();

    let endpoints = merge_endpoints(base, partial, &controls, &recrawled, &opts.removed);
    let coverage = coverage_summary(&routes, &controls);

    // Provenance: every route gets an entry once a map is merged.
    let base_started = base
        .started_at
        .clone()
        .or_else(|| {
            base.run_started_at()
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        })
        .unwrap_or_else(|| base.generated_at.clone());
    let mut route_scans: BTreeMap<String, RouteScan> = BTreeMap::new();
    for r in &routes {
        let scan = if recrawled.contains(&r.route) {
            RouteScan {
                scanned_at: opts.started_at.clone(),
                scan_dir: partial.scan_dir.clone(),
            }
        } else {
            base.route_scans
                .get(&r.route)
                .cloned()
                .unwrap_or_else(|| RouteScan {
                    scanned_at: base_started.clone(),
                    scan_dir: base.scan_dir.clone(),
                })
        };
        route_scans.insert(r.route.clone(), scan);
    }

    let inventory = Inventory {
        schema: partial.schema.clone(),
        identity_version: partial.identity_version,
        project: partial.project.clone(),
        generated_at: partial.generated_at.clone(),
        started_at: Some(opts.started_at.clone()),
        scan_dir: partial.scan_dir.clone(),
        target_url: partial.target_url.clone(),
        role: partial.role.clone().or_else(|| base.role.clone()),
        git: partial.git.clone(),
        write_guard: partial.write_guard.clone(),
        coverage,
        routes,
        controls,
        endpoints,
        route_scans,
        evidence_annotations: None,
        source_reviews: None,
        incremental: Some(IncrementalInfo {
            base: base.generated_at.clone(),
            routes: recrawled.iter().cloned().collect(),
            changed_files: opts.trigger_files.iter().cloned().collect(),
            kept: kept.clone(),
            removed: opts
                .removed
                .iter()
                .filter(|r| base.routes.iter().any(|b| &b.route == *r))
                .cloned()
                .collect(),
        }),
    };
    refreshed_globals.sort();
    Merged {
        inventory,
        recrawled: recrawled.into_iter().collect(),
        kept,
        refreshed_globals,
    }
}

/// Files named by a control's source sites (render, caller, handler).
fn source_files(c: &Control) -> Vec<String> {
    let Some(src) = &c.source else {
        return Vec::new();
    };
    let mut out: Vec<String> = [&src.render, &src.caller, &src.handler]
        .into_iter()
        .flatten()
        .map(|site| site.file.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Same shell control under a new label: role and region agree, both are
/// text-located, and they share a render site file and link target.
fn relabeled(g: &Control, c: &Control) -> bool {
    g.role == c.role
        && g.region == c.region
        && g.locator.starts_with("text=")
        && c.locator.starts_with("text=")
        && g.target == c.target
        && {
            let (a, b) = (source_files(g), source_files(c));
            !a.is_empty() && a.iter().any(|f| b.contains(f))
        }
}

/// Take a re-crawled copy's evidence into a global control. When the
/// global's own source changed, the copy is the new version of it
/// everywhere (identity, label, target, source); otherwise the copy is the
/// same control and only refreshes what it did.
fn refresh_global(g: &mut Control, obs: &Control, src_changed: bool, recrawled: &BTreeSet<String>) {
    if src_changed {
        if g.locator != obs.locator
            && let Some((_, rest)) = obs.key.split_once('|')
        {
            g.key = format!("*|{rest}");
            g.locator = obs.locator.clone();
        }
        g.label = obs.label.clone();
        g.labels = obs.labels.clone();
        g.region = obs.region.clone();
        g.target = obs.target.clone();
        g.opened_by = obs.opened_by.clone();
        g.selector = obs.selector.clone();
        g.href = obs.href.clone();
        if obs.source.is_some() {
            g.source = obs.source.clone();
        }
        g.status = obs.status;
        g.outcomes = obs.outcomes.clone();
        g.reason = obs.reason.clone();
    } else {
        // Like a whole-app build: the shell form unions what every route
        // showed, and an error on any route makes it broken.
        let mut outcomes: BTreeSet<Outcome> = g.outcomes.iter().cloned().collect();
        outcomes.extend(obs.outcomes.iter().cloned());
        g.outcomes = outcomes.into_iter().collect();
        let new_error = obs.status == ControlStatus::Broken && g.status != ControlStatus::Broken;
        // A link-target error (404, unknown route) is the same on every
        // route the link is on: the fresh probe decides.
        let link_target_fixed = g.status == ControlStatus::Broken
            && obs.status != ControlStatus::Broken
            && g.reason
                .as_deref()
                .is_some_and(|r| r.starts_with("link target "));
        if new_error || link_target_fixed || (!g.status.is_exercised() && obs.status.is_exercised())
        {
            g.status = obs.status;
            g.reason = obs.reason.clone();
        }
    }
    // `count` is the most instances seen in one view. Other routes still
    // show the old count unless the control's own file changed or every
    // route it is on was re-crawled.
    let all_seen = g.routes.iter().all(|r| recrawled.contains(r));
    g.count = if src_changed || all_seen {
        obs.count
    } else {
        g.count.max(obs.count)
    };
}

fn remap_keys(keys: &mut Vec<String>, map: &BTreeMap<String, String>) {
    if keys.iter().any(|k| map.contains_key(k)) {
        for k in keys.iter_mut() {
            if let Some(to) = map.get(k) {
                *k = to.clone();
            }
        }
        keys.sort();
        keys.dedup();
    }
}

/// Endpoint rows: control references are re-derived from the merged
/// controls (identical for untouched routes); page-load routes, statuses and
/// the write flag come from the base map for untouched routes and from the
/// re-crawl for re-crawled ones.
fn merge_endpoints(
    base: &Inventory,
    partial: &Inventory,
    controls: &[Control],
    recrawled: &BTreeSet<String>,
    removed: &BTreeSet<String>,
) -> Vec<EndpointEntry> {
    let replaced = |route: &str| recrawled.contains(route) || removed.contains(route);
    let base_keys: BTreeMap<&str, &Control> =
        base.controls.iter().map(|c| (c.key.as_str(), c)).collect();
    let fresh_keys: BTreeSet<&str> = partial
        .controls
        .iter()
        .filter(|c| recrawled.contains(&c.route))
        .map(|c| c.key.as_str())
        .collect();
    let mut callers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in controls {
        for o in &c.outcomes {
            if let Outcome::Calls { endpoint, .. } = o {
                callers
                    .entry(endpoint.clone())
                    .or_default()
                    .insert(c.key.clone());
            }
        }
    }

    let mut out: BTreeMap<String, EndpointEntry> = BTreeMap::new();
    for e in &base.endpoints {
        let unattributed = e.controls.is_empty() && e.on_load.is_empty();
        // Did anything outside the re-crawled routes reference it?
        let kept_refs = e.controls.iter().any(|k| {
            base_keys
                .get(k.as_str())
                .is_some_and(|c| c.route == "*" || !replaced(&c.route))
        }) || e.on_load.iter().any(|r| !replaced(r));
        let mut entry = EndpointEntry {
            endpoint: e.endpoint.clone(),
            controls: Vec::new(),
            on_load: e.on_load.iter().filter(|r| !replaced(r)).cloned().collect(),
            statuses: Vec::new(),
            write: false,
        };
        if unattributed || kept_refs {
            entry.statuses = e.statuses.clone();
            entry.write = e.write;
        }
        out.insert(e.endpoint.clone(), entry);
    }
    for e in &partial.endpoints {
        let on_load: Vec<&String> = e
            .on_load
            .iter()
            .filter(|r| recrawled.contains(*r))
            .collect();
        let fresh_callers = e.controls.iter().any(|k| fresh_keys.contains(k.as_str()));
        if on_load.is_empty() && !fresh_callers {
            continue;
        }
        let entry = out
            .entry(e.endpoint.clone())
            .or_insert_with(|| EndpointEntry {
                endpoint: e.endpoint.clone(),
                ..Default::default()
            });
        entry.on_load.extend(on_load.into_iter().cloned());
        entry.statuses.extend(e.statuses.iter().copied());
        entry.write |= e.write;
    }
    out.into_iter()
        .filter_map(|(key, mut e)| {
            let base_unattributed = base
                .endpoints
                .iter()
                .any(|b| b.endpoint == key && b.controls.is_empty() && b.on_load.is_empty());
            e.controls = callers
                .get(&key)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            e.on_load.sort();
            e.on_load.dedup();
            e.statuses.sort_unstable();
            e.statuses.dedup();
            (base_unattributed || !e.controls.is_empty() || !e.on_load.is_empty()).then_some(e)
        })
        .collect()
}
