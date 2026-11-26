//! Element-level diff between two inventories.
//!
//! The changelog is meant as a regression signal, so it only reports what
//! both maps could see:
//!
//! - A control missing from the new map is `removed` only when its route was
//!   visited in both maps, the state it lives in (a modal or panel opened by
//!   another control) was reached in both, and it was observed (not
//!   `not_exercised`) before. Otherwise it is counted in the `not_observed`
//!   bucket. Controls behind an opener that is now dead or broken are one
//!   `not_reached` line per opener.
//! - A shell control (`*`) and the same control scoped to routes are paired,
//!   so promotion/demotion between maps is not a change.
//! - `moved` needs a file change or a line delta no other control in that
//!   file shares (edits above a block shift all of it: one `shifted` note).
//! - `relabeled` compares normalized labels and ignores flips back to a
//!   label already seen for that control.
//! - `fixed` / `now_dead` / `now_no_effect` need both maps to have exercised
//!   the control.

use std::collections::{BTreeMap, BTreeSet};

use super::identity::{fold_count_plurals, is_generated_id, normalize_text};
use super::render::describe_does;
use super::{
    Change, ChangeSet, Control, ControlStateEntry, ControlStateEntryKind, ControlStatus, Inventory,
    Outcome, stable_endpoint,
};

/// Order of change kinds in reports (most actionable first).
const KIND_ORDER: &[&str] = &[
    "rebaselined",
    "now_broken",
    "now_dead",
    "now_no_effect",
    "route_content_missing",
    "not_reached",
    "rewired",
    "removed",
    "added",
    "fixed",
    "relabeled",
    "count_changed",
    "moved",
    "route_removed",
    "route_added",
    "endpoint_removed",
    "endpoint_added",
];

/// A route that had at least this many observed controls and kept at most a
/// fifth of them reports one `route_content_missing` line instead of a
/// `removed` line per control.
const CONTENT_MISSING_MIN: usize = 5;
/// Count changes above this are data, not UI.
const COUNT_CHANGE_MAX: u32 = 20;

fn kind_rank(kind: &str) -> usize {
    KIND_ORDER
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(KIND_ORDER.len())
}

fn identity_version(inv: &Inventory) -> u32 {
    inv.identity_version.max(1)
}

pub(super) fn diff(prev: Option<&Inventory>, cur: &Inventory) -> ChangeSet {
    let mut cs = ChangeSet {
        from: prev.map(|p| p.generated_at.clone()),
        to: cur.generated_at.clone(),
        ..Default::default()
    };
    let Some(prev) = prev else {
        // First scan: summarize, don't list every control.
        cs.summary.insert("added".into(), cur.controls.len() as u32);
        let routes = cur.routes.iter().filter(|r| r.visited).count() as u32;
        if routes > 0 {
            cs.summary.insert("route_added".into(), routes);
        }
        if !cur.endpoints.is_empty() {
            cs.summary
                .insert("endpoint_added".into(), cur.endpoints.len() as u32);
        }
        return cs;
    };
    let (pv, cv) = (identity_version(prev), identity_version(cur));
    if pv != cv {
        cs.changes.push(Change {
            kind: "rebaselined".into(),
            key: String::new(),
            route: String::new(),
            label: String::new(),
            line: format!(
                "REBASELINED: control identity scheme changed (v{pv} -> v{cv}); keys are not \
                 comparable, so this map is the new baseline ({} controls on {} routes)",
                cur.controls.len(),
                cur.coverage.routes_visited
            ),
            routes: Vec::new(),
        });
        cs.summary.insert("rebaselined".into(), 1);
        return cs;
    }

    let mut d = Differ::new(prev, cur);
    d.match_controls();
    d.compare_pairs();
    d.absences();
    d.additions();
    d.count_changes();
    d.moves();
    d.routes_and_endpoints();
    d.finish(cs)
}

#[derive(Default)]
struct Buckets {
    not_observed: BTreeMap<String, u32>,
    not_observed_lines: Vec<String>,
    newly_observed: u32,
    shifted: BTreeMap<String, (u32, BTreeSet<i64>)>,
    status_unknown: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    file: String,
    line: u32,
    /// Static match (`guess` / `ambiguous`): may flap between candidates.
    weak: bool,
}

struct Differ<'a> {
    prev: &'a Inventory,
    cur: &'a Inventory,
    /// (prev idx, cur idx)
    pairs: Vec<(usize, usize)>,
    prev_matched: BTreeSet<usize>,
    cur_matched: BTreeSet<usize>,
    /// Pairs whose line was written while matching (text relabels).
    relabel_pairs: BTreeSet<(usize, usize)>,
    /// Pairs whose group count changed (reported last).
    count_pairs: Vec<(usize, usize)>,
    /// Count changes explained by a member rewired out of / into the group.
    count_explained: BTreeSet<(usize, usize)>,
    changes: Vec<Change>,
    buckets: Buckets,
    /// Moved candidates: (cur idx, prev site, cur site).
    moved: Vec<(usize, Site, Site)>,
    prev_visited: BTreeSet<&'a str>,
    cur_visited: BTreeSet<&'a str>,
}

impl<'a> Differ<'a> {
    fn new(prev: &'a Inventory, cur: &'a Inventory) -> Self {
        let visited = |inv: &'a Inventory| -> BTreeSet<&'a str> {
            inv.routes
                .iter()
                .filter(|r| r.visited)
                .map(|r| r.route.as_str())
                .collect()
        };
        Self {
            prev,
            cur,
            pairs: Vec::new(),
            prev_matched: BTreeSet::new(),
            cur_matched: BTreeSet::new(),
            relabel_pairs: BTreeSet::new(),
            count_pairs: Vec::new(),
            count_explained: BTreeSet::new(),
            changes: Vec::new(),
            buckets: Buckets::default(),
            moved: Vec::new(),
            prev_visited: visited(prev),
            cur_visited: visited(cur),
        }
    }

    // -- matching -------------------------------------------------------------

    fn match_controls(&mut self) {
        let (prev, cur) = (self.prev, self.cur);
        let pk: BTreeMap<&str, usize> = prev
            .controls
            .iter()
            .enumerate()
            .map(|(i, c)| (c.key.as_str(), i))
            .collect();
        // Exact-key match for controls with stable handles (non-ordinal).
        for (ci, c) in cur.controls.iter().enumerate() {
            if stem(c).is_none() {
                continue;
            }
            if let Some(pi) = pk.get(c.key.as_str()) {
                self.pair(*pi, ci);
            }
        }
        // Ordinal-keyed unlabeled controls (`text=#1`, `#2`, ...): pair by
        // unique exact runtime/annotation source anchor first so an extra
        // unlabeled element shifting `#n` never mismatches every sibling.
        let ordinal_source_match = |p: &Control, c: &Control| {
            stem(p).is_none()
                && stem(c).is_none()
                && p.route == c.route
                && p.role == c.role
                && p.region == c.region
                && exact_runtime_anchor(p).is_some()
                && exact_runtime_anchor(p) == exact_runtime_anchor(c)
        };
        for ci in 0..cur.controls.len() {
            if self.cur_matched.contains(&ci) || stem(&cur.controls[ci]).is_some() {
                continue;
            }
            let c = &cur.controls[ci];
            let cands: Vec<usize> = (0..prev.controls.len())
                .filter(|pi| {
                    !self.prev_matched.contains(pi) && ordinal_source_match(&prev.controls[*pi], c)
                })
                .take(2)
                .collect();
            if let [pi] = cands.as_slice() {
                let pi = *pi;
                let p = &prev.controls[pi];
                let reverse_unique = (0..cur.controls.len())
                    .filter(|i| {
                        !self.cur_matched.contains(i) && ordinal_source_match(p, &cur.controls[*i])
                    })
                    .take(2)
                    .count()
                    == 1;
                if reverse_unique {
                    self.pair(pi, ci);
                }
            }
        }
        // Remaining ordinal-keyed controls fall back to exact key only when
        // they do not have conflicting exact runtime source anchors.
        for (ci, c) in cur.controls.iter().enumerate() {
            if self.cur_matched.contains(&ci) || stem(c).is_some() {
                continue;
            }
            if let Some(&pi) = pk.get(c.key.as_str())
                && !self.prev_matched.contains(&pi)
            {
                let p = &prev.controls[pi];
                let conflicting_source = match (exact_runtime_anchor(p), exact_runtime_anchor(c)) {
                    (Some(a), Some(b)) => a != b,
                    _ => false,
                };
                if !conflicting_source {
                    self.pair(pi, ci);
                }
            }
        }

        // Same control under a different key: region flip, target-suffix
        // change (rewired link), or '*' <-> route scope.
        let prev_by_stem = stems(&prev.controls);
        let cur_by_stem = stems(&cur.controls);
        for (ci, c) in cur.controls.iter().enumerate() {
            if self.cur_matched.contains(&ci) {
                continue;
            }
            let Some(st) = stem(c) else { continue };
            let cands = prev_by_stem.get(&st).map(Vec::as_slice).unwrap_or(&[]);
            if let Some(pi) = best_candidate(c, cands, &prev.controls, &self.prev_matched) {
                self.pair(pi, ci);
            }
        }
        for (pi, p) in prev.controls.iter().enumerate() {
            if self.prev_matched.contains(&pi) {
                continue;
            }
            let Some(st) = stem(p) else { continue };
            let cands = cur_by_stem.get(&st).map(Vec::as_slice).unwrap_or(&[]);
            if let Some(ci) = best_candidate(p, cands, &cur.controls, &self.cur_matched) {
                self.pair(pi, ci);
            }
        }

        // A text-located control whose label changed shows up as removed +
        // added. Require a unique counterpart with a control-level anchor
        // and overlapping observed states: the same conditional element can
        // show different labels on different records or query states.
        let prev_seen = seen_labels(&prev.controls);
        let relabel_candidate = |r: &Control, a: &Control| {
            r.route == a.route
                && r.role == a.role
                && r.region == a.region
                && r.locator.starts_with("text=")
                && a.locator.starts_with("text=")
                && same_anchor(r, a)
                && relabel_states_overlap(prev, cur, r, a)
                && label_changed(r, a, &prev_seen)
        };
        for ci in 0..cur.controls.len() {
            if self.cur_matched.contains(&ci) {
                continue;
            }
            let a = &cur.controls[ci];
            let candidates: Vec<_> = (0..prev.controls.len())
                .filter(|ri| {
                    !self.prev_matched.contains(ri) && relabel_candidate(&prev.controls[*ri], a)
                })
                .take(2)
                .collect();
            if let [ri] = candidates.as_slice() {
                let ri = *ri;
                let r = &prev.controls[ri];
                if cur
                    .controls
                    .iter()
                    .enumerate()
                    .filter(|(i, c)| !self.cur_matched.contains(i) && relabel_candidate(r, c))
                    .take(2)
                    .count()
                    != 1
                {
                    continue;
                }
                self.push(
                    "relabeled",
                    a,
                    format!(
                        "RELABELED {} {} \"{}\" -> \"{}\"",
                        a.route,
                        a.role,
                        r.display_label(),
                        a.display_label()
                    ),
                );
                self.pair(ri, ci);
                self.relabel_pairs.insert((ri, ci));
            }
        }
    }

    fn pair(&mut self, pi: usize, ci: usize) {
        self.pairs.push((pi, ci));
        self.prev_matched.insert(pi);
        self.cur_matched.insert(ci);
    }

    // -- paired controls ------------------------------------------------------

    fn compare_pairs(&mut self) {
        let prev_seen = seen_labels(&self.prev.controls);
        let pairs = self.pairs.clone();
        for (pi, ci) in pairs {
            let (p, c) = (&self.prev.controls[pi], &self.cur.controls[ci]);
            let label = c.display_label();
            let scope = scope_of(p, c);
            let both_exercised = p.status.is_exercised() && c.status.is_exercised();
            let status_line = match (p.status, c.status) {
                (a, ControlStatus::Broken) if a != ControlStatus::Broken => Some((
                    "now_broken",
                    format!(
                        "NOW BROKEN {scope} {} \"{label}\": {} (was {})",
                        c.role,
                        c.reason.as_deref().unwrap_or("error"),
                        was_text(p)
                    ),
                )),
                (ControlStatus::Broken, ControlStatus::Broken)
                    if error_signature(p) != error_signature(c) =>
                {
                    Some((
                        "now_broken",
                        format!(
                            "NOW BROKEN {scope} {} \"{label}\": {} (was broken: {})",
                            c.role,
                            c.reason.as_deref().unwrap_or("error"),
                            p.reason.as_deref().unwrap_or("error")
                        ),
                    ))
                }
                (a, ControlStatus::Dead) if a != ControlStatus::Dead && both_exercised => Some((
                    "now_dead",
                    format!(
                        "NOW DEAD {scope} {} \"{label}\" (was {})",
                        c.role,
                        was_text(p)
                    ),
                )),
                (ControlStatus::Ok, ControlStatus::NoEffect) => Some((
                    "now_no_effect",
                    format!(
                        "NOW NO EFFECT {scope} {} \"{label}\": {} (was {})",
                        c.role,
                        describe_does(c),
                        was_text(p)
                    ),
                )),
                (
                    ControlStatus::Dead | ControlStatus::Broken | ControlStatus::NoEffect,
                    ControlStatus::Ok,
                ) => Some((
                    "fixed",
                    format!(
                        "FIXED {scope} {} \"{label}\": {} (was {})",
                        c.role,
                        describe_does(c),
                        p.status
                    ),
                )),
                (
                    ControlStatus::Dead | ControlStatus::Broken | ControlStatus::NoEffect,
                    ControlStatus::NotExercised,
                ) => {
                    self.buckets.status_unknown += 1;
                    None
                }
                _ => None,
            };
            if let Some((kind, line)) = status_line {
                self.push_at(kind, c, &scope, line);
            } else if rewired(p, c) {
                self.push_at(
                    "rewired",
                    c,
                    &scope,
                    format!(
                        "REWIRED {scope} {} \"{label}\": {} (was {})",
                        c.role,
                        join_effects(&effects(c)),
                        join_effects(&effects(p))
                    ),
                );
            }
            if !self.relabel_pairs.contains(&(pi, ci)) {
                self.relabel(p, c, &prev_seen);
            }
            if p.count != c.count {
                // Reported after absences/additions, which may explain it
                // as a member that was rewired out of or into the group.
                self.count_pairs.push((pi, ci));
            } else if stem(p).is_some()
                && stem(c).is_some()
                && let Some((a, b)) = movement_sites(p, c)
                && (a.file != b.file || a.line != b.line)
                && !attribution_depth_changed(p, c)
            {
                // (A group whose membership changed may simply be anchored
                // at another member; ordinal-keyed controls have no stable
                // identity and cannot reliably report moves.)
                self.moved.push((ci, a, b));
            }
        }
    }

    fn relabel(&mut self, p: &Control, c: &Control, prev_seen: &BTreeMap<Stem, BTreeSet<String>>) {
        if !label_changed(p, c, prev_seen) || !relabel_states_overlap(self.prev, self.cur, p, c) {
            return;
        }
        let (pl, cl) = (base_label(&p.label), base_label(&c.label));
        let scope = scope_of(p, c);
        self.push_at(
            "relabeled",
            c,
            &scope,
            format!("RELABELED {scope} {} \"{pl}\" -> \"{cl}\"", c.role),
        );
    }

    /// Count changes not explained by a rewired member.
    fn count_changes(&mut self) {
        let pairs = std::mem::take(&mut self.count_pairs);
        for (pi, ci) in pairs {
            if self.count_explained.contains(&(pi, ci)) {
                continue;
            }
            let (p, c) = (&self.prev.controls[pi], &self.cur.controls[ci]);
            self.count_change(p, c);
        }
    }

    /// A member that left a same-label group for another target: the group
    /// lost `n` members and an unmatched control with `n` members appeared
    /// (or the reverse). Returns the pair whose count change it explains.
    fn split_partner(&self, x: &Control, x_is_cur: bool) -> Option<(usize, usize)> {
        let st = stem(x)?;
        self.count_pairs.iter().copied().find(|(pi, ci)| {
            let (p, c) = (&self.prev.controls[*pi], &self.cur.controls[*ci]);
            let other = if x_is_cur { c } else { p };
            let (lost, gained) = if x_is_cur {
                (p.count, c.count)
            } else {
                (c.count, p.count)
            };
            !self.count_explained.contains(&(*pi, *ci))
                && other.route == x.route
                && stem(other).as_ref() == Some(&st)
                && other.target != x.target
                && lost > gained
                && lost - gained == x.count
        })
    }

    fn count_change(&mut self, p: &Control, c: &Control) {
        if p.count == c.count
            || p.route != c.route
            || p.count.max(c.count) > COUNT_CHANGE_MAX
            || normalize_text(base_label(&c.label)).contains('#')
            || (c.route != "*" && c.route.split('/').any(is_param))
        {
            return;
        }
        if c.route != "*"
            && !(self.prev_visited.contains(c.route.as_str())
                && self.cur_visited.contains(c.route.as_str()))
        {
            return;
        }
        self.push(
            "count_changed",
            c,
            format!(
                "COUNT CHANGED {} {} \"{}\": x{} -> x{}",
                c.route,
                c.role,
                base_label(&c.label),
                p.count,
                c.count
            ),
        );
    }

    fn split_rewire(&mut self, x: &Control, partner: (usize, usize), x_is_cur: bool) {
        self.count_explained.insert(partner);
        let (p, c) = (
            &self.prev.controls[partner.0],
            &self.cur.controls[partner.1],
        );
        let (now, was, total) = if x_is_cur {
            (effects(x), effects(p), p.count)
        } else {
            (effects(c), effects(x), c.count)
        };
        let line = format!(
            "REWIRED {} {} \"{}\": {} (was {}; {} of {total})",
            x.route,
            x.role,
            base_label(&x.label),
            join_effects(&now),
            join_effects(&was),
            x.count
        );
        let shown = if x_is_cur { x } else { c };
        self.push_at("rewired", shown, &x.route, line);
    }

    // -- removals -------------------------------------------------------------

    fn absences(&mut self) {
        let (prev, cur) = (self.prev, self.cur);
        let cur_dialog_routes: BTreeSet<&str> = cur
            .controls
            .iter()
            .filter(|c| c.region == "dialog")
            .map(|c| c.route.as_str())
            .collect();

        // Routes whose content largely vanished: one line, not one per control.
        let mut observed_on: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for (pi, p) in prev.controls.iter().enumerate() {
            if p.route == "*"
                || p.status == ControlStatus::NotExercised
                || !p.opened_by.is_empty()
                || p.state_entries
                    .iter()
                    .any(|e| !matches!(e.kind, ControlStateEntryKind::Direct))
            {
                continue;
            }
            let e = observed_on.entry(p.route.as_str()).or_insert((0, 0));
            e.0 += 1;
            if self.prev_matched.contains(&pi) {
                e.1 += 1;
            }
        }
        let emptied: BTreeSet<&str> = observed_on
            .iter()
            .filter(|(r, (n, kept))| {
                *n >= CONTENT_MISSING_MIN
                    && kept * 5 <= *n
                    && self.prev_visited.contains(**r)
                    && self.cur_visited.contains(**r)
            })
            .map(|(r, _)| *r)
            .collect();
        let mut emptied_lost: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let mut not_reached: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();

        for (pi, p) in prev.controls.iter().enumerate() {
            if self.prev_matched.contains(&pi) {
                continue;
            }
            let visited_now = if p.route == "*" {
                p.routes
                    .iter()
                    .any(|r| self.cur_visited.contains(r.as_str()))
            } else {
                self.cur_visited.contains(p.route.as_str())
            };
            if !visited_now {
                self.not_observed(p, "route not visited this time");
                continue;
            }
            if let Some(partner) = self.split_partner(p, false) {
                self.split_rewire(p, partner, false);
                continue;
            }
            if p.status == ControlStatus::NotExercised {
                self.not_observed(p, "not exercised in the previous map");
                continue;
            }
            // A non-global control whose only evidence on this route was
            // inherited from another route (`exercised on /other`) was never
            // directly exercised here. If the same control still exists on
            // another visited route, a collapsible container (e.g. sidebar)
            // hiding it on this route is not a removal.
            if p.route != "*"
                && has_inherited_evidence(p)
                && stem(p).is_some_and(|st| {
                    cur.controls.iter().any(|c| {
                        stem(c).as_ref() == Some(&st)
                            && (c.route == "*" || self.cur_visited.contains(c.route.as_str()))
                    })
                })
            {
                self.not_observed(
                    p,
                    "only inherited evidence on this route in the previous map",
                );
                continue;
            }
            if !p.state_entries.is_empty() {
                if !state_entry_seen_in(prev, cur, p) {
                    let opener = p.state_entries.iter().find_map(|e| {
                        let ControlStateEntryKind::Opened { opener } = &e.kind else {
                            return None;
                        };
                        if !entry_has_concrete_location(e) {
                            return None;
                        }
                        let before = prev.controls.iter().find(|o| &o.key == opener)?;
                        let now = self.cur_counterpart(before)?;
                        failed_opener_is_bound_to_entry(now, e).then_some((now, e.route.as_str()))
                    });
                    if let Some((o, route)) = opener {
                        not_reached
                            .entry(format!(
                                "{route} {} \"{}\" (opener now {})",
                                o.role,
                                o.display_label(),
                                o.status
                            ))
                            .or_insert_with(|| (route.to_string(), Vec::new()))
                            .1
                            .push(p.display_label());
                    } else {
                        self.not_observed(p, "none of its recorded state entries was reached");
                    }
                    continue;
                }
            } else if !self.variant_seen_in(self.prev, self.cur, p) {
                self.not_observed(p, "its page variant (query or record) was not visited");
                continue;
            }
            if p.state_entries.is_empty() && !p.opened_by.is_empty() {
                let reached = legacy_opener_reached(prev, cur, p);
                if !reached {
                    let opener = legacy_opened_entries(prev, p).iter().find_map(|entry| {
                        let ControlStateEntryKind::Opened { opener } = &entry.kind else {
                            return None;
                        };
                        let before = prev.controls.iter().find(|o| &o.key == opener)?;
                        let now = self.cur_counterpart(before)?;
                        let on_route = |c: &Control| {
                            c.route == entry.route
                                || (c.route == "*" && c.routes.contains(&entry.route))
                        };
                        (on_route(before)
                            && on_route(now)
                            && before.target == now.target
                            && legacy_failed_opener_is_bound_to_entry(cur, now, entry))
                        .then_some(now)
                    });
                    match opener {
                        Some(o) => {
                            let route = if o.route == "*" { &p.route } else { &o.route };
                            not_reached
                                .entry(format!(
                                    "{route} {} \"{}\" (opener now {})",
                                    o.role,
                                    o.display_label(),
                                    o.status
                                ))
                                .or_insert_with(|| (route.clone(), Vec::new()))
                                .1
                                .push(p.display_label());
                        }
                        None => self.not_observed(p, "the state it is in was not reached"),
                    }
                    continue;
                }
            }
            if p.region == "dialog"
                && p.state_entries.is_empty()
                && p.opened_by.is_empty()
                && !cur_dialog_routes.contains(p.route.as_str())
            {
                self.not_observed(p, "its dialog was not open");
                continue;
            }
            if emptied.contains(p.route.as_str()) {
                emptied_lost
                    .entry(p.route.as_str())
                    .or_default()
                    .push(p.display_label());
                continue;
            }
            self.push(
                "removed",
                p,
                format!(
                    "REMOVED {} {} \"{}\" (was {})",
                    p.route,
                    p.role,
                    p.display_label(),
                    describe_does(p)
                ),
            );
        }
        for (route, lost) in emptied_lost {
            let (n, kept) = observed_on.get(route).copied().unwrap_or_default();
            let line = format!(
                "ROUTE CONTENT MISSING {route}: {kept} of {n} controls seen (page not rendered, \
                 crashed, or loaded late); missing {}",
                preview(&lost)
            );
            self.changes.push(Change {
                kind: "route_content_missing".into(),
                key: route.to_string(),
                route: route.to_string(),
                label: String::new(),
                line,
                routes: Vec::new(),
            });
        }
        for (opener, (route, lost)) in not_reached {
            let line = format!(
                "NOT REACHED {} control{} behind {opener}: {}",
                lost.len(),
                if lost.len() == 1 { "" } else { "s" },
                preview(&lost)
            );
            self.changes.push(Change {
                kind: "not_reached".into(),
                key: opener,
                route,
                label: String::new(),
                line,
                routes: Vec::new(),
            });
        }
    }

    /// Was a page variant `c` was seen on (in `own`) visited in `other`? A
    /// control specific to some variants needs one of them; on a dynamic
    /// route every view is a variant (one record), so a control seen on all
    /// sampled records still needs one of those records revisited.
    fn variant_seen_in(&self, own: &Inventory, other: &Inventory, c: &Control) -> bool {
        let variants_of = |inv: &Inventory| -> Vec<String> {
            inv.routes
                .iter()
                .find(|r| r.route == c.route)
                .map(|r| r.variants.clone())
                .unwrap_or_default()
        };
        let dynamic = c.route != "*" && c.route.split('/').any(is_param);
        let mut mine: Vec<String> = if !c.variants.is_empty() {
            c.variants.clone()
        } else if dynamic {
            variants_of(own)
        } else {
            return true;
        };
        if dynamic {
            // Older inventories sometimes stored `/records/:id` as the
            // only visited variant. A shared placeholder is not evidence
            // that both scans sampled the same record.
            mine.retain(|v| !v.split('?').next().unwrap_or(v).split('/').any(is_param));
        }
        if mine.is_empty() {
            return !dynamic;
        }
        let theirs = variants_of(other);
        mine.iter().any(|v| theirs.contains(v))
    }

    fn cur_counterpart(&self, p: &Control) -> Option<&'a Control> {
        let cur = self.cur;
        if let Some(c) = cur.controls.iter().find(|c| c.key == p.key) {
            return Some(c);
        }
        let st = stem(p)?;
        cur.controls
            .iter()
            .filter(|c| stem(c).as_ref() == Some(&st))
            .find(|c| {
                c.route == p.route
                    || (c.route == "*" && c.routes.contains(&p.route))
                    || (p.route == "*" && p.routes.contains(&c.route))
            })
    }

    fn not_observed(&mut self, p: &Control, why: &str) {
        *self
            .buckets
            .not_observed
            .entry(why.to_string())
            .or_insert(0) += 1;
        self.buckets.not_observed_lines.push(format!(
            "{} {} \"{}\" ({why})",
            p.route,
            p.role,
            p.display_label()
        ));
    }

    // -- additions ------------------------------------------------------------

    fn additions(&mut self) {
        let (prev, cur) = (self.prev, self.cur);
        let prev_reached: BTreeSet<&str> = prev
            .controls
            .iter()
            .flat_map(|c| c.opened_by.iter().map(String::as_str))
            .collect();
        let prev_dialog_routes: BTreeSet<&str> = prev
            .controls
            .iter()
            .filter(|c| c.region == "dialog")
            .map(|c| c.route.as_str())
            .collect();
        for (ci, c) in cur.controls.iter().enumerate() {
            if self.cur_matched.contains(&ci) {
                continue;
            }
            if let Some(partner) = self.split_partner(c, true) {
                self.split_rewire(c, partner, true);
                continue;
            }
            let visited_before = if c.route == "*" {
                c.routes
                    .iter()
                    .any(|r| self.prev_visited.contains(r.as_str()))
            } else {
                self.prev_visited.contains(c.route.as_str())
            };
            let has_entries = !c.state_entries.is_empty();
            let state_before = if has_entries {
                state_entry_seen_in(cur, prev, c)
            } else {
                c.opened_by.is_empty()
                    || c.opened_by
                        .iter()
                        .any(|k| prev_reached.contains(k.as_str()))
            };
            let dialog_before = has_entries
                || c.region != "dialog"
                || !c.opened_by.is_empty()
                || prev_dialog_routes.contains(c.route.as_str());
            let variant_before = has_entries || self.variant_seen_in(self.cur, self.prev, c);
            if !visited_before
                || c.status == ControlStatus::NotExercised
                || !state_before
                || !dialog_before
                || !variant_before
            {
                self.buckets.newly_observed += 1;
                continue;
            }
            self.push(
                "added",
                c,
                format!(
                    "ADDED {} {} \"{}\": {} [{}]",
                    c.route,
                    c.role,
                    c.display_label(),
                    describe_does(c),
                    c.status
                ),
            );
        }
    }

    // -- moves ----------------------------------------------------------------

    fn moves(&mut self) {
        // Files touched by other changes: their line shifts are explained.
        let mut changed_files: BTreeSet<String> = BTreeSet::new();
        for ch in &self.changes {
            let c = self
                .cur
                .controls
                .iter()
                .find(|c| c.key == ch.key)
                .or_else(|| self.prev.controls.iter().find(|c| c.key == ch.key));
            if let Some(site) = c.and_then(primary_site) {
                changed_files.insert(site.file);
            }
        }
        let mut by_delta: BTreeMap<(String, i64), usize> = BTreeMap::new();
        for (_, a, b) in &self.moved {
            if a.file == b.file {
                *by_delta
                    .entry((a.file.clone(), i64::from(b.line) - i64::from(a.line)))
                    .or_insert(0) += 1;
            }
        }
        let moved = std::mem::take(&mut self.moved);
        for (ci, a, b) in moved {
            let c = &self.cur.controls[ci];
            if a.file != b.file {
                // Static matches flap between candidates; not a move.
                if a.weak || b.weak {
                    continue;
                }
                self.push(
                    "moved",
                    c,
                    format!(
                        "MOVED {} {} \"{}\": {}:{} (was {}:{})",
                        c.route,
                        c.role,
                        c.display_label(),
                        b.file,
                        b.line,
                        a.file,
                        a.line
                    ),
                );
                continue;
            }
            let delta = i64::from(b.line) - i64::from(a.line);
            let shared = by_delta.get(&(a.file.clone(), delta)).copied().unwrap_or(0);
            if shared >= 2 || changed_files.contains(&a.file) || a.weak || b.weak {
                let e = self
                    .buckets
                    .shifted
                    .entry(a.file.clone())
                    .or_insert((0, BTreeSet::new()));
                e.0 += 1;
                e.1.insert(delta);
                continue;
            }
            self.push(
                "moved",
                c,
                format!(
                    "MOVED {} {} \"{}\": {}:{} (was line {})",
                    c.route,
                    c.role,
                    c.display_label(),
                    b.file,
                    b.line,
                    a.line
                ),
            );
        }
    }

    // -- routes and endpoints -------------------------------------------------

    fn routes_and_endpoints(&mut self) {
        let (prev, cur) = (self.prev, self.cur);
        let routes = |inv: &'a Inventory| -> BTreeSet<&'a str> {
            inv.routes
                .iter()
                .filter(|r| !r.not_in_source)
                .map(|r| r.route.as_str())
                .collect()
        };
        let (pr, cr) = (routes(prev), routes(cur));
        for r in pr.difference(&cr) {
            self.push_plain("route_removed", r, format!("ROUTE REMOVED {r}"));
        }
        for r in cr.difference(&pr) {
            self.push_plain("route_added", r, format!("ROUTE ADDED {r}"));
        }

        // Endpoints: only those a control or page load observed in both maps
        // could have shown.
        type Callers<'b> = (Vec<&'b str>, Vec<&'b str>);
        let endpoints = |inv: &'a Inventory| -> BTreeMap<String, Callers<'a>> {
            let mut out: BTreeMap<String, Callers<'a>> = BTreeMap::new();
            for e in &inv.endpoints {
                if e.controls.is_empty() && e.on_load.is_empty() {
                    continue;
                }
                if super::build::is_dev_tool_path(e.endpoint.split_once(' ').map_or("", |(_, p)| p))
                {
                    continue;
                }
                let entry = out.entry(stable_endpoint(&e.endpoint)).or_default();
                entry.0.extend(e.controls.iter().map(String::as_str));
                entry.1.extend(e.on_load.iter().map(String::as_str));
            }
            out
        };
        let (pe, ce) = (endpoints(prev), endpoints(cur));
        let prev_idx: BTreeMap<&str, usize> = prev
            .controls
            .iter()
            .enumerate()
            .map(|(i, c)| (c.key.as_str(), i))
            .collect();
        let cur_idx: BTreeMap<&str, usize> = cur
            .controls
            .iter()
            .enumerate()
            .map(|(i, c)| (c.key.as_str(), i))
            .collect();
        let mut pair_of_prev: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut pair_of_cur: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (p, c) in &self.pairs {
            pair_of_prev.entry(*p).or_default().push(*c);
            pair_of_cur.entry(*c).or_default().push(*p);
        }
        let added: BTreeSet<&str> = self
            .changes
            .iter()
            .filter(|ch| ch.kind == "added")
            .map(|ch| ch.key.as_str())
            .collect();
        let mut lines = Vec::new();
        for (e, (controls, on_load)) in &pe {
            if ce.contains_key(e) {
                continue;
            }
            let seen = controls.iter().any(|k| {
                prev_idx
                    .get(k)
                    .and_then(|pi| pair_of_prev.get(pi))
                    .is_some_and(|cis| cis.iter().any(|ci| cur.controls[*ci].status.is_exercised()))
            }) || on_load.iter().any(|r| self.cur_visited.contains(r));
            if seen {
                lines.push((
                    "endpoint_removed",
                    e.clone(),
                    format!("ENDPOINT REMOVED {e}"),
                ));
            }
        }
        for (e, (controls, on_load)) in &ce {
            if pe.contains_key(e) {
                continue;
            }
            let seen = controls.iter().any(|k| {
                added.contains(k)
                    || cur_idx
                        .get(k)
                        .and_then(|ci| pair_of_cur.get(ci))
                        .is_some_and(|pis| {
                            pis.iter()
                                .any(|pi| prev.controls[*pi].status.is_exercised())
                        })
            }) || on_load.iter().any(|r| self.prev_visited.contains(r));
            if seen {
                lines.push(("endpoint_added", e.clone(), format!("ENDPOINT ADDED {e}")));
            }
        }
        for (kind, subject, line) in lines {
            self.push_plain(kind, &subject, line);
        }
    }

    // -- output ---------------------------------------------------------------

    fn push(&mut self, kind: &str, c: &Control, line: String) {
        let route = c.route.clone();
        self.push_at(kind, c, &route, line);
    }

    /// A control change whose line names `scope` as its route.
    fn push_at(&mut self, kind: &str, c: &Control, scope: &str, line: String) {
        self.changes.push(Change {
            kind: kind.to_string(),
            key: c.key.clone(),
            route: scope.to_string(),
            label: c.display_label(),
            line,
            routes: Vec::new(),
        });
    }

    fn push_plain(&mut self, kind: &str, subject: &str, line: String) {
        let route = if kind.starts_with("route_") {
            subject
        } else {
            ""
        };
        self.changes.push(Change {
            kind: kind.to_string(),
            key: subject.to_string(),
            route: route.to_string(),
            label: String::new(),
            line,
            routes: Vec::new(),
        });
    }

    fn finish(mut self, mut cs: ChangeSet) -> ChangeSet {
        let mut changes = merge_across_routes(std::mem::take(&mut self.changes));
        changes.sort_by(|a, b| {
            kind_rank(&a.kind)
                .cmp(&kind_rank(&b.kind))
                .then_with(|| a.route.cmp(&b.route))
                .then_with(|| a.key.cmp(&b.key))
                .then_with(|| a.line.cmp(&b.line))
        });
        changes.dedup();
        for c in &changes {
            *cs.summary.entry(c.kind.clone()).or_insert(0) += 1;
        }
        cs.changes = changes;

        let b = self.buckets;
        let not_observed: u32 = b.not_observed.values().sum();
        if not_observed > 0 {
            cs.summary.insert("not_observed".into(), not_observed);
            let why: Vec<String> = b
                .not_observed
                .iter()
                .map(|(k, v)| format!("{v} {k}"))
                .collect();
            cs.notes.push(format!(
                "{not_observed} control{} from the previous map not observed this time ({}); not counted as removed.",
                plural(not_observed),
                why.join(", ")
            ));
            cs.not_observed = b.not_observed_lines;
        }
        if b.newly_observed > 0 {
            cs.summary.insert("newly_observed".into(), b.newly_observed);
            cs.notes.push(format!(
                "{} control{} newly observed (route or state not reached before, or not exercised); not counted as added.",
                b.newly_observed,
                plural(b.newly_observed)
            ));
        }
        let shifted: u32 = b.shifted.values().map(|(n, _)| *n).sum();
        if shifted > 0 {
            cs.summary.insert("shifted".into(), shifted);
            for (file, (n, deltas)) in &b.shifted {
                let ds: Vec<String> = deltas.iter().map(|d| format!("{d:+}")).collect();
                cs.notes.push(format!(
                    "{file}: {n} control{} shifted {} line{} (edits above them; not moved).",
                    plural(*n),
                    ds.join("/"),
                    if deltas.iter().all(|d| d.abs() == 1) {
                        ""
                    } else {
                        "s"
                    }
                ));
            }
        }
        if b.status_unknown > 0 {
            cs.notes.push(format!(
                "{} control{} that {} dead, broken, or without effect {} not exercised this time: status unknown, not fixed.",
                b.status_unknown,
                plural(b.status_unknown),
                if b.status_unknown == 1 { "was" } else { "were" },
                if b.status_unknown == 1 { "was" } else { "were" }
            ));
        }
        cs
    }
}

/// One line for the same change on several routes (a shared component):
/// `NOW BROKEN /, /about, /contact +4 more link "Privacy": ...`.
fn merge_across_routes(changes: Vec<Change>) -> Vec<Change> {
    let mut groups: BTreeMap<(String, String), Vec<Change>> = BTreeMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    for c in changes {
        let needle = format!(" {} ", c.route);
        let template = if c.route.is_empty() || c.route == "*" || !c.line.contains(&needle) {
            // Unmergeable: keep it unique.
            format!("{}\u{0}{}", c.line, c.key)
        } else {
            c.line.replacen(&needle, " \u{0} ", 1)
        };
        let k = (c.kind.clone(), template);
        if !groups.contains_key(&k) {
            order.push(k.clone());
        }
        groups.entry(k).or_default().push(c);
    }
    let mut out = Vec::new();
    for k in order {
        let mut members = groups.remove(&k).unwrap_or_default();
        if members.len() == 1 {
            out.extend(members);
            continue;
        }
        members.sort_by(|a, b| a.route.cmp(&b.route));
        members.dedup_by(|a, b| a.route == b.route);
        if members.len() == 1 {
            out.extend(members);
            continue;
        }
        let routes: Vec<String> = members.iter().map(|m| m.route.clone()).collect();
        let shown = if routes.len() <= 4 {
            routes.join(", ")
        } else {
            format!("{} +{} more", routes[..3].join(", "), routes.len() - 3)
        };
        let mut first = members.swap_remove(0);
        first.line = k.1.replacen('\u{0}', &shown, 1);
        first.routes = routes;
        out.push(first);
    }
    out
}

fn plural(n: u32) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn preview(labels: &[String]) -> String {
    let shown: Vec<String> = labels.iter().take(6).map(|l| format!("\"{l}\"")).collect();
    let more = labels.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} (+{more} more)", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// Route shown on a change line: the route-scoped side of a '*' pair.
fn scope_of(p: &Control, c: &Control) -> String {
    if c.route == "*" && p.route != "*" {
        p.route.clone()
    } else {
        c.route.clone()
    }
}

/// Did navigation or calls change? For a shell control paired with a
/// route-scoped form, the route form must do something the shell form did
/// not (the shell form unions every route).
fn rewired(p: &Control, c: &Control) -> bool {
    let (pe, ce) = (effects(p), effects(c));
    if pe.is_empty() || ce.is_empty() || pe == ce {
        return false;
    }
    match (p.route == "*", c.route == "*") {
        (true, false) => !ce.is_subset(&pe),
        (false, true) => !pe.is_subset(&ce),
        _ => true,
    }
}

/// Identity without route scope, region, or target suffix:
/// `(role, locator without @region)`. `None` for ordinal-keyed controls.
type Stem = (String, String);

fn stem(c: &Control) -> Option<Stem> {
    let base = if c.region.is_empty() {
        c.locator.as_str()
    } else {
        c.locator
            .strip_suffix(&format!("@{}", c.region))
            .unwrap_or(&c.locator)
    };
    // Unlabeled controls keyed by document order have no stable identity.
    if base == "text=" {
        return None;
    }
    let normalized = if let Some(val) = base.strip_prefix("text=") {
        format!("text={}", fold_count_plurals(val))
    } else if let Some(val) = base.strip_prefix("aria=") {
        format!("aria={}", fold_count_plurals(val))
    } else {
        base.to_string()
    };
    Some((c.role.clone(), normalized))
}

fn has_inherited_evidence(c: &Control) -> bool {
    c.reason.as_deref().is_some_and(|reason| {
        reason.starts_with("exercised on ") || reason.contains("; exercised on ")
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeAnchor {
    render: (String, u32, u32),
    caller: Option<(String, u32, u32)>,
}

/// Exact runtime/annotation `(render, caller)` source anchor for pairing
/// ordinal-keyed unlabeled controls without shifting `#n` indices.
fn exact_runtime_anchor(c: &Control) -> Option<RuntimeAnchor> {
    let src = c.source.as_ref()?;
    if src.confidence != "exact" || !matches!(src.method.as_str(), "runtime" | "annotation") {
        return None;
    }
    let render = src.render.as_ref()?;
    let caller = src.caller.as_ref().map(|s| (s.file.clone(), s.line, s.col));
    Some(RuntimeAnchor {
        render: (render.file.clone(), render.line, render.col),
        caller,
    })
}

fn stems(controls: &[Control]) -> BTreeMap<Stem, Vec<usize>> {
    let mut out: BTreeMap<Stem, Vec<usize>> = BTreeMap::new();
    for (i, c) in controls.iter().enumerate() {
        if let Some(s) = stem(c) {
            out.entry(s).or_default().push(i);
        }
    }
    out
}

/// Best counterpart for `c` among same-stem controls on the other side.
/// Route-scoped counterparts pair one-to-one; a shell control (`*`) can
/// stand for several route-scoped ones.
fn best_candidate(
    c: &Control,
    cands: &[usize],
    other: &[Control],
    taken: &BTreeSet<usize>,
) -> Option<usize> {
    cands
        .iter()
        .copied()
        .filter(|i| {
            let o = &other[*i];
            let same_route = o.route == c.route;
            let o_covers = o.route == "*" && c.route != "*" && o.routes.contains(&c.route);
            let c_covers = c.route == "*" && o.route != "*" && c.routes.contains(&o.route);
            (same_route && !taken.contains(i)) || o_covers || (c_covers && !taken.contains(i))
        })
        .min_by_key(|i| {
            let o = &other[*i];
            (
                o.route != c.route,
                o.target != c.target,
                o.region != c.region,
                o.key.clone(),
            )
        })
}

/// Normalized labels seen per stem (all routes), for flip suppression.
fn seen_labels(controls: &[Control]) -> BTreeMap<Stem, BTreeSet<String>> {
    let mut out: BTreeMap<Stem, BTreeSet<String>> = BTreeMap::new();
    for c in controls {
        let Some(s) = stem(c) else { continue };
        let e = out.entry(s).or_default();
        e.insert(normalize_text(base_label(&c.label)));
        for l in &c.labels {
            e.insert(normalize_text(l));
        }
    }
    out
}

/// Apply the same known-label-state guard to stable and text-located pairs.
fn label_changed(p: &Control, c: &Control, prev_seen: &BTreeMap<Stem, BTreeSet<String>>) -> bool {
    if !p.labels.is_empty() || !c.labels.is_empty() {
        return false;
    }
    // Unlabeled ordinal-keyed controls (`text=#1`) have fallback/synthetic
    // labels only; changes between generated IDs or shifted ordinals are not
    // user-visible relabels.
    if stem(p).is_none() || stem(c).is_none() {
        return false;
    }
    let (pl, cl) = (base_label(&p.label), base_label(&c.label));
    if pl.is_empty()
        || cl.is_empty()
        || is_generated_id(pl)
        || is_generated_id(cl)
        || fold_count_plurals(&normalize_text(pl)) == fold_count_plurals(&normalize_text(cl))
    {
        return false;
    }
    // Labels that flip between known states (theme toggles, open/closed)
    // are not relabels.
    !stem(p).is_some_and(|st| {
        prev_seen
            .get(&st)
            .is_some_and(|seen| seen.contains(&normalize_text(cl)))
    })
}

/// Flat legacy opener lists cannot pair a multi-route shell child's entries.
fn legacy_child_route(control: &Control) -> Option<&str> {
    if control.route != "*" {
        return Some(control.route.as_str());
    }
    match control.routes.as_slice() {
        [route] => Some(route.as_str()),
        _ => None,
    }
}

/// Recover only concrete locations supported by the flat legacy metadata.
/// Empty legacy variants can mean plain-page presence or all route variants.
/// A static page with recorded queries cannot distinguish those cases.
fn legacy_locations(inv: &Inventory, control: &Control) -> Vec<ControlStateEntry> {
    let Some(route) = legacy_child_route(control) else {
        return Vec::new();
    };
    let variants = if control.variants.is_empty() {
        inv.routes
            .iter()
            .find(|r| r.route == route)
            .map(|r| r.variants.as_slice())
            .unwrap_or_default()
    } else {
        control.variants.as_slice()
    };
    if control.variants.is_empty()
        && !variants.is_empty()
        && (control.route == "*" || !route.split('/').any(is_param))
    {
        return Vec::new();
    }
    let variants: Vec<Option<String>> = if variants.is_empty() {
        vec![None]
    } else {
        variants.iter().cloned().map(Some).collect()
    };
    variants
        .into_iter()
        .map(|variant| ControlStateEntry {
            route: route.into(),
            variant,
            kind: ControlStateEntryKind::Direct,
        })
        .filter(entry_has_concrete_location)
        .collect()
}

fn legacy_opened_entries(inv: &Inventory, control: &Control) -> Vec<ControlStateEntry> {
    let locations = legacy_locations(inv, control);
    // Flat lists cannot tell which opener belongs to which variant.
    if locations.len() > 1 && control.opened_by.len() > 1 {
        return Vec::new();
    }
    locations
        .into_iter()
        .flat_map(|location| {
            control
                .opened_by
                .iter()
                .map(move |opener| ControlStateEntry {
                    kind: ControlStateEntryKind::Opened {
                        opener: opener.clone(),
                    },
                    ..location.clone()
                })
        })
        .collect()
}

/// Reaching the same opener elsewhere cannot prove a missing child's state.
fn legacy_opener_reached(own: &Inventory, other: &Inventory, missing: &Control) -> bool {
    let expected = legacy_opened_entries(own, missing);
    other.controls.iter().any(|seen| {
        let legacy;
        let entries = if seen.state_entries.is_empty() {
            legacy = legacy_opened_entries(other, seen);
            legacy.as_slice()
        } else {
            seen.state_entries.as_slice()
        };
        expected.iter().any(|before| {
            entries.iter().any(|after| {
                if !entry_location_matches(before, after) {
                    return false;
                }
                let (
                    ControlStateEntryKind::Opened { opener: x },
                    ControlStateEntryKind::Opened { opener: y },
                ) = (&before.kind, &after.kind)
                else {
                    return false;
                };
                let on_route = |c: &Control| {
                    c.route == before.route || (c.route == "*" && c.routes.contains(&before.route))
                };
                let left = own.controls.iter().find(|c| &c.key == x && on_route(c));
                let right = other.controls.iter().find(|c| &c.key == y && on_route(c));
                match (left, right) {
                    (Some(left), Some(right)) => {
                        left.target == right.target
                            && (x == y
                                || stem(left).is_some_and(|s| stem(right).as_ref() == Some(&s)))
                    }
                    _ => false,
                }
            })
        })
    })
}

fn legacy_failed_opener_is_bound_to_entry(
    inv: &Inventory,
    opener: &Control,
    entry: &ControlStateEntry,
) -> bool {
    if !opener.state_entries.is_empty() {
        return failed_opener_is_bound_to_entry(opener, entry);
    }
    let locations = legacy_locations(inv, opener);
    matches!(
        opener.status,
        ControlStatus::Dead | ControlStatus::Broken | ControlStatus::NoEffect
    ) && !locations.is_empty()
        && locations
            .iter()
            .all(|seen| entry_location_matches(entry, seen))
        && !has_inherited_evidence(opener)
}

/// An entry is positive evidence only for a concrete route/state. A missing
/// variant means the plain page on a static route, never an unknown record.
fn entry_has_concrete_location(entry: &ControlStateEntry) -> bool {
    if entry.route.is_empty() || entry.route == "*" {
        return false;
    }
    match entry.variant.as_deref() {
        Some(variant) => {
            !variant.is_empty()
                && !variant
                    .split('?')
                    .next()
                    .unwrap_or(variant)
                    .split('/')
                    .any(is_param)
                && (!entry.route.split('/').any(is_param) || variant.starts_with('/'))
        }
        None => !entry.route.split('/').any(is_param),
    }
}

fn entry_location_matches(a: &ControlStateEntry, b: &ControlStateEntry) -> bool {
    entry_has_concrete_location(a)
        && entry_has_concrete_location(b)
        && a.route == b.route
        && a.variant == b.variant
}

/// A grouped status is not an outcome for every entry where the opener was
/// present. Without per-entry execution provenance, attribute failure only
/// when every observed context is the child's concrete location. Inherited
/// evidence carries only a route, so it cannot prove a record/query attempt.
fn failed_opener_is_bound_to_entry(opener: &Control, entry: &ControlStateEntry) -> bool {
    matches!(
        opener.status,
        ControlStatus::Dead | ControlStatus::Broken | ControlStatus::NoEffect
    ) && !opener.state_entries.is_empty()
        && opener.state_entries.iter().all(|seen| {
            entry_location_matches(entry, seen)
                && !matches!(seen.kind, ControlStateEntryKind::Unknown)
        })
        && !has_inherited_evidence(opener)
}

fn entry_matches(
    own: &Inventory,
    other: &Inventory,
    a: &ControlStateEntry,
    b: &ControlStateEntry,
) -> bool {
    if !entry_location_matches(a, b) {
        return false;
    }
    match (&a.kind, &b.kind) {
        (ControlStateEntryKind::Direct, ControlStateEntryKind::Direct) => true,
        (
            ControlStateEntryKind::Opened { opener: x },
            ControlStateEntryKind::Opened { opener: y },
        ) => {
            if x == y {
                return true;
            }
            // Preserve shell promotion/region matching without allowing an
            // unrelated route or a rewired same-label opener to prove entry.
            let on_route =
                |c: &Control| c.route == a.route || (c.route == "*" && c.routes.contains(&a.route));
            let left = own.controls.iter().find(|c| &c.key == x && on_route(c));
            let right = other.controls.iter().find(|c| &c.key == y && on_route(c));
            match (left, right) {
                (Some(x), Some(y)) => {
                    x.target == y.target && stem(x).is_some_and(|s| stem(y).as_ref() == Some(&s))
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// Entry alternatives are OR-ed, but their route, variant and opener stay
/// paired. A visited route alone cannot prove a child panel was reached.
fn state_entry_seen_in(own: &Inventory, other: &Inventory, control: &Control) -> bool {
    control.state_entries.iter().any(|entry| {
        other
            .routes
            .iter()
            .any(|r| r.visited && r.route == entry.route)
            && other
                .controls
                .iter()
                .flat_map(|c| &c.state_entries)
                .any(|seen| entry_matches(own, other, entry, seen))
    })
}

/// A source anchor can render conditional labels. Compare each control's
/// own observed states, not just the other scan's route-wide coverage.
fn relabel_states_overlap(prev: &Inventory, cur: &Inventory, p: &Control, c: &Control) -> bool {
    if !p.state_entries.is_empty() || !c.state_entries.is_empty() {
        return p.state_entries.iter().any(|before| {
            c.state_entries
                .iter()
                .any(|after| entry_matches(prev, cur, before, after))
        });
    }
    fn states<'a>(inv: &'a Inventory, control: &'a Control) -> &'a [String] {
        if !control.variants.is_empty() {
            &control.variants
        } else {
            inv.routes
                .iter()
                .find(|r| r.route == control.route)
                .map(|r| r.variants.as_slice())
                .unwrap_or_default()
        }
    }
    let (before, after) = (states(prev, p), states(cur, c));
    let dynamic = |route: &str| route != "*" && route.split('/').any(is_param);
    if !dynamic(&p.route) && !dynamic(&c.route) && before.is_empty() && after.is_empty() {
        return true;
    }
    // Legacy placeholder-only coverage cannot establish a common record.
    // Empty coverage on one side is likewise unknown, never a wildcard.
    before.iter().any(|v| {
        !v.is_empty()
            && !v.split('?').next().unwrap_or(v).split('/').any(is_param)
            && after.contains(v)
    })
}

/// Label without the ` (+N more)` group suffix.
fn base_label(label: &str) -> &str {
    match label.rfind(" (+") {
        Some(i) if label.ends_with(" more)") => &label[..i],
        _ => label,
    }
}

/// First error without stack locations, for "broken differently" checks.
fn error_signature(c: &Control) -> String {
    let r = c.reason.as_deref().unwrap_or("");
    let head = r.split(" @ ").next().unwrap_or(r);
    let head = head.split(" (").next().unwrap_or(head);
    normalize_text(head)
}

/// Navigation targets, endpoints, and anchors (status/blocked ignored).
fn effects(c: &Control) -> BTreeSet<String> {
    c.outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Navigates { to } => Some(format!("→ {to}")),
            Outcome::Calls { endpoint, .. } => {
                let path = endpoint.split_once(' ').map_or("", |(_, p)| p);
                (!super::build::is_dev_tool_path(path))
                    .then(|| format!("calls {}", stable_endpoint(endpoint)))
            }
            Outcome::Anchor { fragment } => Some(format!("jumps to #{fragment}")),
            _ => None,
        })
        .collect()
}

fn join_effects(e: &BTreeSet<String>) -> String {
    e.iter().cloned().collect::<Vec<_>>().join("; ")
}

fn was_text(p: &Control) -> String {
    match p.status {
        // A link's target is known without clicking it.
        ControlStatus::NotExercised if !effects(p).is_empty() => {
            format!("{}, not exercised", join_effects(&effects(p)))
        }
        ControlStatus::NotExercised => "not exercised".to_string(),
        ControlStatus::Ok => describe_does(p),
        other => format!("{other}: {}", describe_does(p)),
    }
}

fn primary_site(c: &Control) -> Option<Site> {
    let src = c.source.as_ref()?;
    let site = src.caller.as_ref().or(src.render.as_ref())?;
    Some(Site {
        file: site.file.clone(),
        line: site.line,
        weak: matches!(src.confidence.as_str(), "guess" | "ambiguous"),
    })
}

/// Source movement needs comparable location evidence, independently of the
/// anchors used to pair controls. Static label matches and probable owner
/// frames can change as capture depth improves without any source edit.
fn movement_sites(a: &Control, b: &Control) -> Option<(Site, Site)> {
    let (x, y) = (a.source.as_ref()?, b.source.as_ref()?);
    if x.confidence != "exact"
        || y.confidence != "exact"
        || x.method != y.method
        || !matches!(x.method.as_str(), "runtime" | "annotation")
        || x.caller.is_some() != y.caller.is_some()
    {
        return None;
    }
    // primary_site prefers caller; equal presence ensures caller/caller or
    // render/render comparison, never an attribution-depth switch.
    Some((primary_site(a)?, primary_site(b)?))
}

/// Runtime frames and static fallbacks can resolve different depths of
/// the same component stack. Shared anchors then show attribution changed,
/// not sufficient evidence that the control moved. Keep true caller moves
/// when both maps resolve callers at different locations.
fn attribution_depth_changed(a: &Control, b: &Control) -> bool {
    let (Some(a), Some(b)) = (&a.source, &b.source) else {
        return false;
    };
    let same = |a: Option<&crate::code_link::runtime_source::FileLine>,
                b: Option<&crate::code_link::runtime_source::FileLine>| {
        a.zip(b)
            .is_some_and(|(a, b)| a.file == b.file && a.line == b.line)
    };
    same(a.render.as_ref(), b.caller.as_ref())
        || same(a.caller.as_ref(), b.render.as_ref())
        || ((a.caller.is_none() || b.caller.is_none())
            && same(a.render.as_ref(), b.render.as_ref()))
}

fn same_anchor(a: &Control, b: &Control) -> bool {
    let same_selector = !a.selector.is_empty() && a.selector == b.selector;
    if let (Some(x), Some(y)) = (&a.source, &b.source)
        && x.confidence == "exact"
        && y.confidence == "exact"
        && matches!(x.method.as_str(), "runtime" | "annotation")
        && matches!(y.method.as_str(), "runtime" | "annotation")
    {
        // A shared component's host render can serve distinct callsites.
        // Conflicting callers preclude treating it as the same control.
        if let (Some(x), Some(y)) = (&x.caller, &y.caller)
            && x != y
        {
            return false;
        }
        // Prefer the actual element render site, including its column. A
        // conflicting render site must not be rescued by a common caller,
        // handler, destination, or positional selector.
        if let (Some(x), Some(y)) = (&x.render, &y.render) {
            return x == y;
        }
        if let (Some(x), Some(y)) = (&x.handler, &y.handler) {
            return x == y && same_selector;
        }
    }
    // Probable owner/ancestor frames and static candidates describe context,
    // not control identity. They need independent structural/effect evidence.
    if a.href.is_some() && a.href == b.href {
        return true;
    }
    same_selector && !effects(a).is_empty() && effects(a) == effects(b)
}

fn is_param(seg: &str) -> bool {
    seg.starts_with(':') || seg.starts_with('[') || seg.starts_with('*')
}
