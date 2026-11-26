//! Greppable renderings of an inventory: map files, changelog, and the text
//! formats the read commands print.
//!
//! Everything here is deterministic (sorted inputs, no timestamps except the
//! UI-MAP.md header and changelog entry dates) so the committed map files only
//! change when the UI does.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::{
    ChangeSet, Control, ControlStatus, Inventory, NON_CHANGE_BUCKETS, Outcome, stable_endpoint,
};
use crate::code_link::runtime_source::{FileLine, ResolvedSource};

pub const UI_MAP_MD: &str = "UI-MAP.md";
pub const UI_MAP_HTML: &str = "UI-MAP.html";
pub const UI_MAP_TSV: &str = "ui-map.tsv";
pub const ENDPOINTS_TSV: &str = "endpoints.tsv";
pub const DEAD_UI_MD: &str = "DEAD-UI.md";
pub const CHANGELOG_MD: &str = "CHANGELOG.md";

/// Max change lines per changelog entry before "+N more".
const CHANGELOG_MAX_LINES: usize = 200;

const STATUS_LEGEND: &str = "Status: `ok` did something · `dead` exercised, nothing happened, no handler \
(high confidence) · `no_effect` exercised, a handler exists but nothing visible happened (review) · \
`broken` error, failed request, or missing/unknown link target · `disabled` · `external` off-site · \
`skipped` deliberately not exercised · `not_exercised` budget/coverage gap. \
These are observation statuses, not completed business transactions. A tool timeout is inconclusive; \
focus, a toast, or a blocked request does not establish submission success.";

// ---------------------------------------------------------------------------
// Small formatters (shared with the read commands)
// ---------------------------------------------------------------------------

/// One outcome as a short phrase.
pub fn describe_outcome(o: &Outcome) -> String {
    match o {
        Outcome::Navigates { to } => format!("→ {to}"),
        Outcome::Calls {
            endpoint,
            status,
            blocked,
        } => {
            let mut s = format!("calls {}", stable_endpoint(endpoint));
            if *blocked {
                s.push_str(" [write blocked]");
            } else if let Some(st) = status.filter(|st| *st >= 400) {
                let _ = write!(s, " ({st})");
            }
            s
        }
        Outcome::DomChange { kind } => match kind.as_str() {
            "modal" | "menu" | "panel" | "dialog" | "drawer" | "popover" | "dropdown" | "tab" => {
                format!("opens {kind}")
            }
            "toast" => "shows toast".to_string(),
            "validation" => "shows validation".to_string(),
            "other" | "" => "updates page".to_string(),
            other => format!("updates page ({other})"),
        },
        Outcome::Dialog { message } => format!("native dialog \"{message}\""),
        Outcome::Download => "downloads file".to_string(),
        Outcome::External { url } => format!("external {url}"),
        Outcome::Error { message } => format!("error: {message}"),
        Outcome::Anchor { fragment } => format!("jumps to #{fragment}"),
        Outcome::SideEffect { kind } => match kind.as_str() {
            "print" => "opens the print dialog".to_string(),
            "window_open" => "opens a new window".to_string(),
            "clipboard" => "copies to the clipboard".to_string(),
            "scroll" => "scrolls the page".to_string(),
            "focus_moved" => "moves focus".to_string(),
            "file_chooser" => "opens a file chooser".to_string(),
            "form_validation" => "shows form validation".to_string(),
            other => format!("side effect ({other})"),
        },
    }
}

/// What the control does, in one line.
pub fn describe_does(c: &Control) -> String {
    let mut parts: Vec<String> = Vec::new();
    // Effects first (navigation, calls, DOM), errors last.
    for o in c
        .outcomes
        .iter()
        .filter(|o| !matches!(o, Outcome::Error { .. }))
    {
        parts.push(describe_outcome(o));
    }
    for o in c
        .outcomes
        .iter()
        .filter(|o| matches!(o, Outcome::Error { .. }))
    {
        parts.push(describe_outcome(o));
    }
    if !parts.is_empty() {
        return parts.join("; ");
    }
    let reason = c.reason.as_deref().unwrap_or("");
    match c.status {
        ControlStatus::Dead => "nothing (no navigation, request, or DOM change)".to_string(),
        ControlStatus::NoEffect => match reason {
            "" => "no visible effect".to_string(),
            other => format!("no visible effect ({other})"),
        },
        ControlStatus::Broken => format!("error: {reason}"),
        ControlStatus::Disabled => "disabled".to_string(),
        ControlStatus::Skipped => format!("skipped ({reason})"),
        ControlStatus::NotExercised => format!("not exercised ({reason})"),
        ControlStatus::External => "external".to_string(),
        ControlStatus::Ok => match reason {
            "focus_only" => "focus only (input not tested)".to_string(),
            "validation_blocked" => {
                "blocked by form validation (empty required fields)".to_string()
            }
            "network_activity_unattributed" => "sends a request (not attributed)".to_string(),
            "already active" => "nothing to do (already active)".to_string(),
            "effect on retest" => "did something on retest".to_string(),
            "in-page anchor" => "in-page anchor".to_string(),
            "" => "ok".to_string(),
            other => other.to_string(),
        },
    }
}

/// Status with the reason when it adds information.
pub fn status_text(c: &Control) -> String {
    if super::evidence::control_evidence(c).observation == "inconclusive_timeout" {
        return format!("inconclusive timeout (recorded {})", c.status.as_str());
    }
    match (c.status, c.reason.as_deref()) {
        (ControlStatus::Ok, Some(r)) if r.starts_with("no effect on") => format!("ok ({r})"),
        (ControlStatus::Ok, Some(r)) if r.contains("exercised on") => format!("ok ({r})"),
        (ControlStatus::Ok, Some(r @ ("already active" | "effect on retest"))) => {
            format!("ok ({r})")
        }
        (ControlStatus::Dead, Some(r)) => format!("dead ({r})"),
        (ControlStatus::NoEffect, Some(r)) => format!("no_effect ({r})"),
        (ControlStatus::Broken, _) => "broken".to_string(),
        (st, _) => st.as_str().to_string(),
    }
}

fn file_line(f: &FileLine) -> String {
    format!("{}:{}", f.file, f.line)
}

/// `render[ · caller x][ · handler y]` plus a confidence note when not exact.
pub fn source_text(src: Option<&ResolvedSource>) -> String {
    let Some(src) = src else {
        return String::new();
    };
    let mut parts = Vec::new();
    if let Some(r) = &src.render {
        parts.push(file_line(r));
    }
    if let Some(c) = &src.caller
        && src.render.as_ref() != Some(c)
    {
        parts.push(format!("caller {}", file_line(c)));
    }
    if let Some(h) = &src.handler {
        parts.push(format!("handler {}", file_line(h)));
    }
    let fallback = parts.is_empty().then(|| src.candidates.first()).flatten();
    if let Some(c) = fallback {
        parts.push(file_line(c));
    }
    let mut out = parts.join(" · ");
    if !out.is_empty() && !src.confidence.is_empty() && src.confidence != "exact" {
        let _ = write!(out, " ({})", src.confidence);
    }
    if src.method == "static" && !out.is_empty() {
        out.push_str(" [static candidate; verify in source]");
    }
    let alternatives: Vec<_> = src
        .candidates
        .iter()
        .filter(|candidate| src.render.as_ref() != Some(*candidate) && fallback != Some(*candidate))
        .map(file_line)
        .collect();
    if !alternatives.is_empty() {
        let _ = write!(out, " · candidates: {}", alternatives.join(", "));
    }
    out
}

fn control_cell(c: &Control) -> String {
    let mut s = format!("\"{}\"", c.display_label());
    if c.count > 1 {
        let _ = write!(s, " ×{}", c.count);
    }
    let _ = write!(s, " `{}`", c.locator);
    s
}

/// Markdown table cell: no pipes or newlines.
pub fn md_cell(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// TSV field: single line with no tabs, newlines, or control characters;
/// collapses runs of whitespace/control chars for grep/awk readability.
pub fn tsv_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = true;
    for ch in s.chars() {
        if ch == ' '
            || ch == '\t'
            || ch == '\n'
            || ch == '\r'
            || ch.is_control()
            || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}')
        {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

fn format_tsv_outcomes(outcomes: &[Outcome]) -> String {
    outcomes
        .iter()
        .map(|o| match o {
            Outcome::Navigates { to } => format!("navigates:{to}"),
            Outcome::Calls {
                endpoint,
                status,
                blocked,
            } => {
                let mut s = format!("calls:{}", stable_endpoint(endpoint));
                if let Some(st) = status {
                    let _ = write!(s, " ({st})");
                }
                if *blocked {
                    s.push_str(" [blocked]");
                }
                s
            }
            Outcome::DomChange { kind } => {
                if kind.is_empty() {
                    "dom:other".to_string()
                } else {
                    format!("dom:{kind}")
                }
            }
            Outcome::Dialog { message } => format!("dialog:{message}"),
            Outcome::Download => "download".to_string(),
            Outcome::External { url } => format!("external:{url}"),
            Outcome::Error { message } => format!("error:{message}"),
            Outcome::Anchor { fragment } => format!("anchor:#{fragment}"),
            Outcome::SideEffect { kind } => format!("side_effect:{kind}"),
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn format_tsv_candidates(src: Option<&ResolvedSource>) -> String {
    let Some(src) = src else {
        return String::new();
    };
    if src.candidates.is_empty() {
        return String::new();
    }
    src.candidates
        .iter()
        .map(file_line)
        .collect::<Vec<_>>()
        .join(", ")
}

pub const TSV_HEADER: &str = "route\trole\tlabel\tstatus\tdoes\tendpoints\tnavigates_to\tsource\tkey\tlabels\treason\tvariants\toutcomes\tsource_method\tsource_confidence\tsource_candidates\tobservation";

/// One `ui-map.tsv` line.
pub fn tsv_row(c: &Control) -> String {
    let endpoints: Vec<String> = c.endpoints().map(stable_endpoint).collect();
    let nav: Vec<&str> = c.navigates_to().collect();
    let variants = if c.variants.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&c.variants).unwrap_or_default()
    };
    [
        c.route.clone(),
        c.role.clone(),
        c.display_label(),
        c.status.as_str().to_string(),
        describe_does(c),
        endpoints.join(", "),
        nav.join(", "),
        source_text(c.source.as_ref()),
        c.key.clone(),
        c.labels.join(" | "),
        c.reason.clone().unwrap_or_default(),
        variants,
        format_tsv_outcomes(&c.outcomes),
        c.source
            .as_ref()
            .map(|s| s.method.clone())
            .unwrap_or_default(),
        c.source
            .as_ref()
            .map(|s| s.confidence.clone())
            .unwrap_or_default(),
        format_tsv_candidates(c.source.as_ref()),
        super::evidence::control_evidence(c).observation.to_string(),
    ]
    .iter()
    .map(|f| tsv_field(f))
    .collect::<Vec<_>>()
    .join("\t")
}

/// Markdown control table (no route column).
fn md_table(controls: &[&Control]) -> String {
    let mut out =
        String::from("| Control | Role | Does | Status | Source |\n|---|---|---|---|---|\n");
    for c in controls {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            md_cell(&control_cell(c)),
            md_cell(&c.role),
            md_cell(&describe_does(c)),
            md_cell(&status_text(c)),
            md_cell(&source_text(c.source.as_ref())),
        );
    }
    out
}

/// Markdown table with a route column (for `brokenapp ui --format md`).
pub fn md_table_with_route(controls: &[&Control]) -> String {
    let mut out = String::from(
        "| Route | Control | Role | Does | Status | Source |\n|---|---|---|---|---|---|\n",
    );
    for c in controls {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            md_cell(&c.route),
            md_cell(&control_cell(c)),
            md_cell(&c.role),
            md_cell(&describe_does(c)),
            md_cell(&status_text(c)),
            md_cell(&source_text(c.source.as_ref())),
        );
    }
    out
}

/// Aligned plain-text table for terminals.
pub fn text_table(controls: &[&Control]) -> String {
    let rows: Vec<[String; 5]> = controls
        .iter()
        .map(|c| {
            let mut label = c.display_label();
            if c.count > 1 {
                let _ = write!(label, " ×{}", c.count);
            }
            [
                c.route.clone(),
                c.role.clone(),
                truncate(&label, 40),
                status_text(c),
                truncate(&describe_does(c), 70),
            ]
        })
        .collect();
    let headers = ["ROUTE", "ROLE", "CONTROL", "STATUS", "DOES"];
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            widths[i] = widths[i]
                .max(cell.chars().count())
                .min(if i == 0 { 32 } else { 72 });
        }
    }
    let mut out = String::new();
    let line = |cells: &[String]| -> String {
        let mut l = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                l.push_str(cell);
            } else {
                let cell = truncate(cell, widths[i]);
                let pad = widths[i].saturating_sub(cell.chars().count());
                l.push_str(&cell);
                l.push_str(&" ".repeat(pad + 2));
            }
        }
        l.trim_end().to_string()
    };
    out.push_str(&line(&headers.map(String::from)));
    out.push('\n');
    for r in &rows {
        out.push_str(&line(r));
        out.push('\n');
    }
    out
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn git_text(inv: &Inventory) -> String {
    match &inv.git {
        Some(g) => {
            let short: String = g.commit.chars().take(12).collect();
            let mut s = short;
            if let Some(b) = &g.branch {
                let _ = write!(s, " ({b})");
            }
            if g.dirty {
                s.push_str(" + uncommitted changes");
            }
            s
        }
        None => "not a git repo".to_string(),
    }
}

/// Compact summary of the top 3 covering elements for obscured skips, e.g.
/// `top covers: div[data-radix-overlay] (180), .ai-chat-widget (34)`.
fn format_top_obscured_covers(c: &super::CoverageSummary) -> Option<String> {
    if c.obscured_top_covers.is_empty() {
        return None;
    }
    let parts: Vec<String> = c
        .obscured_top_covers
        .iter()
        .take(3)
        .map(|oc| format!("{} ({})", oc.cover, oc.count))
        .collect();
    Some(format!("top covers: {}", parts.join(", ")))
}

fn coverage_line_core(inv: &Inventory) -> String {
    let c = &inv.coverage;
    let exercisable = if c.controls_exercisable == 0 && c.controls_total > 0 {
        // Maps written before the exercisable count existed.
        c.controls_total
    } else {
        c.controls_exercisable
    };
    let mut out = format!(
        "{}/{} exercisable controls exercised",
        c.controls_exercised, exercisable
    );
    let mut aside = Vec::new();
    for (n, what) in [
        (c.controls_external, "external"),
        (c.controls_disabled, "disabled"),
        (c.controls_skipped, "skipped"),
    ] {
        if n > 0 {
            aside.push(format!("{n} {what}"));
        }
    }
    if !aside.is_empty() {
        let _ = write!(out, " (+{} not counted)", aside.join(", "));
    }
    let _ = write!(
        out,
        "; {}/{} known routes visited",
        c.routes_visited, c.routes_known
    );
    out
}

/// One-line coverage statement: exercisable controls first (external,
/// disabled, and skipped controls are not counted against coverage but are
/// shown), then routes, plus top covering elements when controls were skipped
/// as `obscured`.
pub fn coverage_line(inv: &Inventory) -> String {
    let mut out = coverage_line_core(inv);
    if let Some(covers) = format_top_obscured_covers(&inv.coverage) {
        let obscured_count = inv
            .coverage
            .not_exercised_by_reason
            .get("obscured")
            .copied()
            .unwrap_or_else(|| {
                inv.coverage
                    .obscured_top_covers
                    .iter()
                    .map(|oc| oc.count)
                    .sum()
            });
        let _ = write!(out, "; obscured: {obscured_count} ({covers})");
    }
    out
}

/// Unvisited routes grouped by reason, one clause per reason.
pub fn unvisited_text(inv: &Inventory, max_routes: usize) -> Vec<String> {
    let c = &inv.coverage;
    let groups: Vec<(String, Vec<String>)> = if c.unvisited_by_reason.is_empty() {
        if c.unvisited_routes.is_empty() {
            Vec::new()
        } else {
            vec![("not visited".to_string(), c.unvisited_routes.clone())]
        }
    } else {
        let mut g: Vec<(String, Vec<String>)> = c
            .unvisited_by_reason
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        g.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
        g
    };
    groups
        .into_iter()
        .map(|(reason, routes)| {
            let shown: Vec<&str> = routes.iter().take(max_routes).map(String::as_str).collect();
            let more = routes.len().saturating_sub(shown.len());
            let mut line = format!("{} {reason}: {}", routes.len(), shown.join(", "));
            if more > 0 {
                let _ = write!(line, " (+{more} more)");
            }
            if reason == "redirects to login" {
                line.push_str(if inv.role.is_some() {
                    " — this role is not allowed there, or its session expired"
                } else {
                    " — add a role ([[roles]] in .brokenapp/config.toml) to map them"
                });
            }
            line
        })
        .collect()
}

/// Coverage caveat paragraph (used in DEAD-UI.md and `brokenapp dead`).
pub fn coverage_caveat(inv: &Inventory) -> String {
    let c = &inv.coverage;
    let top_covers = format_top_obscured_covers(c);
    let has_obscured_reason = c.not_exercised_by_reason.contains_key("obscured");
    let mut out = format!(
        "Coverage: {}. Controls that were not exercised are not known to work.",
        if has_obscured_reason {
            coverage_line_core(inv)
        } else {
            coverage_line(inv)
        }
    );
    if !c.not_exercised_by_reason.is_empty() {
        let mut reasons: Vec<(&String, &u32)> = c.not_exercised_by_reason.iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let list: Vec<String> = reasons
            .iter()
            .map(|(r, n)| {
                if r.as_str() == "obscured"
                    && let Some(covers) = &top_covers
                {
                    format!("{r}: {n} ({covers})")
                } else {
                    format!("{r} {n}")
                }
            })
            .collect();
        let _ = write!(out, " Not exercised by reason: {}.", list.join(", "));
    }
    let unvisited = unvisited_text(inv, 12);
    if !unvisited.is_empty() {
        let _ = write!(out, " Routes never visited: {}.", unvisited.join("; "));
    }
    out
}

// ---------------------------------------------------------------------------
// Map files
// ---------------------------------------------------------------------------

pub fn render_ui_map(inv: &Inventory) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# UI map: {}{}\n", inv.project, role_suffix(inv));
    let _ = writeln!(out, "- Target: {}", inv.target_url);
    if let Some(role) = &inv.role {
        let _ = writeln!(
            out,
            "- Role: {role} (signed in; the anonymous map is ../../UI-MAP.md, ../../ROLE-ACCESS.md compares roles)"
        );
    }
    let _ = writeln!(out, "- Git: {}", git_text(inv));
    let _ = writeln!(out, "- Scanned: {}", inv.generated_at);
    if let Some(inc) = &inv.incremental {
        let _ = writeln!(
            out,
            "- Incremental: re-crawled {} (changed: {}); other routes are kept from the map of {} (per-route crawl times: `route_scans` in history/latest.inventory.json)",
            if inc.routes.is_empty() {
                "no route".to_string()
            } else {
                inc.routes.join(", ")
            },
            changed_files_text(inc),
            inc.base
        );
    }
    let _ = writeln!(out, "- Coverage: {}", coverage_line(inv));
    for line in unvisited_text(inv, 8) {
        let _ = writeln!(out, "- Not visited: {line}");
    }
    let _ = writeln!(out, "- Write guard: {}", inv.write_guard);
    let _ = writeln!(
        out,
        "- Route denominator: source-discovered routes plus observed browser destinations; role discovery may differ. Visited does not mean populated or authorized.\n- Source references: runtime captures and static candidates have different evidence strengths. Static candidates require source verification."
    );
    let _ = writeln!(out, "\n{STATUS_LEGEND}\n");

    let globals: Vec<&Control> = inv.controls.iter().filter(|c| c.route == "*").collect();
    if !globals.is_empty() {
        let _ = writeln!(out, "## Global controls (shell)\n");
        out.push_str(&exercised_section(&globals));
    }

    for r in &inv.routes {
        let controls: Vec<&Control> = inv.controls.iter().filter(|c| c.route == r.route).collect();
        if controls.is_empty() && !r.visited {
            continue;
        }
        let _ = writeln!(out, "## {}{}\n", r.route, title_suffix(r.title.as_deref()));
        let mut meta = Vec::new();
        if !r.visited {
            meta.push("not visited".to_string());
        }
        if r.not_in_source {
            meta.push("no route in source matches this path".to_string());
        }
        if let Some(s) = r.status {
            meta.push(format!("HTTP {s}"));
        }
        if let Some(src) = &r.source {
            meta.push(format!("defined in {src}"));
        }
        if !meta.is_empty() {
            let _ = writeln!(out, "_{}_\n", meta.join(" · "));
        }
        let evidence = super::evidence::route_summary(inv, &r.route);
        let _ = writeln!(
            out,
            "Evidence: page state **{}**; non-shell controls {}/{} exercised ({} rows); shell/landmark controls {}/{} exercised ({} rows). Endpoint evidence: {}.\n",
            evidence.page_state,
            evidence.page_controls.exercised,
            evidence.page_controls.exercisable,
            evidence.page_controls.rows,
            evidence.shell_controls.exercised,
            evidence.shell_controls.exercisable,
            evidence.shell_controls.rows,
            evidence.endpoint_evidence
        );
        for observation in &evidence.state_observations {
            let _ = writeln!(
                out,
                "- State: **{}** ({}, variant: {}). {}",
                md_cell(&observation.state),
                md_cell(&observation.basis),
                md_cell(
                    observation
                        .variant
                        .as_deref()
                        .unwrap_or("route observation; not every variant")
                ),
                md_cell(observation.observation_note.as_deref().unwrap_or(""))
            );
            if let Some(explanation) = &observation.source_explanation {
                let _ = writeln!(out, "  Source explanation: {}", md_cell(explanation));
            }
            for reference in &observation.evidence {
                let _ = writeln!(
                    out,
                    "  Evidence ({}): {} {}",
                    md_cell(&reference.kind),
                    md_cell(&reference.path),
                    md_cell(reference.locator.as_deref().unwrap_or(""))
                );
            }
        }
        if !evidence.state_observations.is_empty() {
            out.push('\n');
        }
        if controls.is_empty() {
            let _ = writeln!(out, "No controls found.\n");
            continue;
        }
        out.push_str(&exercised_section(&controls));
    }

    let unvisited: Vec<_> = inv.routes.iter().filter(|r| !r.visited).collect();
    if !unvisited.is_empty() {
        let _ = writeln!(out, "## Routes never visited\n");
        for r in unvisited {
            let mut line = format!("- {}", r.route);
            if let Some(why) = &r.unvisited_reason {
                let _ = write!(line, " — {why}");
            }
            if let Some(src) = &r.source {
                let _ = write!(line, " ({src})");
            }
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
    }
    out
}

fn title_suffix(title: Option<&str>) -> String {
    match title.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => format!(" ({})", md_cell(t)),
        None => String::new(),
    }
}

/// Table of everything except not-exercised controls, then a collapsed
/// not-exercised list.
fn exercised_section(controls: &[&Control]) -> String {
    let (shown, hidden): (Vec<&Control>, Vec<&Control>) = controls
        .iter()
        .partition(|c| c.status != ControlStatus::NotExercised);
    let mut out = String::new();
    if !shown.is_empty() {
        out.push_str(&md_table(&shown));
        out.push('\n');
    }
    if !hidden.is_empty() {
        let _ = writeln!(
            out,
            "<details><summary>Not exercised ({})</summary>\n",
            hidden.len()
        );
        for c in hidden {
            let mut line = format!("- {} \"{}\"", c.role, md_cell(&c.display_label()));
            if c.count > 1 {
                let _ = write!(line, " ×{}", c.count);
            }
            let _ = write!(
                line,
                " — {}",
                c.reason.as_deref().unwrap_or("not_exercised")
            );
            let nav: Vec<&str> = c.navigates_to().collect();
            if !nav.is_empty() {
                let _ = write!(line, " (href → {})", nav.join(", "));
            }
            let _ = writeln!(out, "{line}");
        }
        out.push_str("\n</details>\n\n");
    }
    out
}

pub fn render_ui_tsv(inv: &Inventory) -> String {
    let mut out = String::from(TSV_HEADER);
    out.push('\n');
    for c in &inv.controls {
        out.push_str(&tsv_row(c));
        out.push('\n');
    }
    out
}

pub const ENDPOINTS_TSV_HEADER: &str = "endpoint\tcontrols\ton_load\tstatuses\twrite";

pub fn render_endpoints_tsv(inv: &Inventory) -> String {
    let mut out = String::from(ENDPOINTS_TSV_HEADER);
    out.push('\n');
    for e in &inv.endpoints {
        let statuses: Vec<String> = e.statuses.iter().map(u16::to_string).collect();
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            tsv_field(&e.endpoint),
            tsv_field(&e.controls.join(", ")),
            tsv_field(&e.on_load.join(", ")),
            statuses.join(","),
            if e.write { "blocked" } else { "" },
        );
    }
    out
}

/// Evidence line for a dead or broken control.
pub fn evidence_text(c: &Control) -> String {
    match c.status {
        ControlStatus::Dead => {
            let mut s =
                "clicked; no navigation, request, DOM change, or console error, and no handler found"
                    .to_string();
            if let Some(r) = &c.reason {
                let _ = write!(s, " ({r})");
            }
            s
        }
        ControlStatus::NoEffect => {
            let mut s = "clicked; nothing visible happened".to_string();
            if let Some(r) = &c.reason {
                let _ = write!(s, " ({r})");
            }
            s.push_str(". Often benign (already selected, same data, print or clipboard); check the handler");
            s
        }
        ControlStatus::Broken => {
            let mut s = c.reason.clone().unwrap_or_else(|| "error".to_string());
            let others: Vec<String> = c
                .outcomes
                .iter()
                .filter(|o| !matches!(o, Outcome::Error { .. }))
                .map(describe_outcome)
                .collect();
            if !others.is_empty() {
                let _ = write!(s, " — {}", others.join("; "));
            }
            s
        }
        _ => describe_does(c),
    }
}

/// Sections of the dead-UI report, most actionable first.
pub const DEAD_SECTIONS: [(&str, ControlStatus); 3] = [
    ("Broken", ControlStatus::Broken),
    ("Dead (high confidence)", ControlStatus::Dead),
    ("No visible effect (review)", ControlStatus::NoEffect),
];

/// ` (role: admin)` for a role's map, empty for the anonymous one.
pub fn role_suffix(inv: &Inventory) -> String {
    inv.role
        .as_deref()
        .map(|r| format!(" (role: {r})"))
        .unwrap_or_default()
}

pub fn render_dead_ui(inv: &Inventory) -> String {
    let mut out = format!(
        "# Dead and broken UI: {}{}\n\n",
        inv.project,
        role_suffix(inv)
    );
    let _ = writeln!(out, "Coverage: {}.\n", coverage_line(inv));
    for (title, status) in DEAD_SECTIONS {
        let list: Vec<&Control> = inv.controls.iter().filter(|c| c.status == status).collect();
        let _ = writeln!(out, "## {title} ({})\n", list.len());
        if list.is_empty() {
            out.push_str("None found.\n\n");
            continue;
        }
        for c in &list {
            let mut line = format!(
                "- `{}` {} \"{}\"",
                c.route,
                c.role,
                md_cell(&c.display_label())
            );
            if c.count > 1 {
                let _ = write!(line, " ×{}", c.count);
            }
            let _ = write!(line, ": {}", evidence_text(c));
            let src = source_text(c.source.as_ref());
            if !src.is_empty() {
                let _ = write!(line, " — {src}");
            }
            let _ = write!(line, " — selector `{}`", c.selector);
            let _ = writeln!(out, "{line}");
        }
        out.push('\n');
    }
    let _ = writeln!(out, "## Coverage caveat\n\n{}", coverage_caveat(inv));
    out
}

/// Render a self-contained interactive HTML UI map (`UI-MAP.html`) that embeds
/// the live inventory JSON (routes, controls, outcomes, endpoints, dead/broken UI).
pub fn render_ui_map_html(inv: &Inventory) -> String {
    let json = serde_json::to_string(inv)
        .unwrap_or_else(|_| "{}".to_string())
        .replace("</", "<\\/");
    // The "Does / Evidence" and "Source" cells, index-aligned with
    // `inv.controls` and worded by the same helpers as UI-MAP.md, so the two
    // reports cannot disagree about what a control does or where it lives.
    let text: Vec<[String; 2]> = inv
        .controls
        .iter()
        .map(|c| [describe_does(c), source_text(c.source.as_ref())])
        .collect();
    let text = serde_json::to_string(&text)
        .unwrap_or_else(|_| "[]".to_string())
        .replace("</", "<\\/");
    let title = format!("{}{}", inv.project, role_suffix(inv));
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BrokenApp UI Map — {title}</title>
<meta name="color-scheme" content="dark light">
<style>
  :root {{
    /* BrokenApp brand system, "the record" surface. Four colors only:
       Ink #060606, Bone #EFEBE3, Signal #FF2A2A (red on dark grounds) and
       Signal Deep #CC1B1B (red on light grounds). Dark is Bone on Ink; light
       ("paper") is near-black #0A0A0A on Bone. Muted text, rules and raised
       surfaces are the text color at reduced alpha, never separate greys.
       Red has one job: the logo slash and controls reported broken. Every
       other outcome is a small mark drawn in the text color (.g, .sl below).
       Fonts are named stacks with system fallbacks; nothing is fetched, so
       the report stays offline and self-contained. */
    color-scheme: dark light;
    --ground: #060606;
    --text: #EFEBE3;
    --muted: rgba(239, 235, 227, 0.66);
    --rule: rgba(239, 235, 227, 0.16);
    --rule-strong: rgba(239, 235, 227, 0.4);
    --raised: rgba(239, 235, 227, 0.04);
    --red: #FF2A2A;
    --red-on-fill: #CC1B1B;
    --serif: "Cormorant", "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
    --sans: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    --pad: clamp(20px, 4vw, 56px);
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --ground: #EFEBE3;
      --text: #0A0A0A;
      --muted: rgba(10, 10, 10, 0.66);
      --rule: rgba(10, 10, 10, 0.16);
      --rule-strong: rgba(10, 10, 10, 0.45);
      --raised: rgba(10, 10, 10, 0.04);
      --red: #CC1B1B;
      --red-on-fill: #FF2A2A;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font: 400 15px/1.5 var(--sans);
    background: var(--ground);
    color: var(--text);
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }}
  ::selection {{ background: var(--text); color: var(--ground); }}
  :focus-visible {{ outline: 2px solid var(--text); outline-offset: 2px; }}

  /* Wordmark: Broken, the slash, App. The slash is Signal in both schemes. */
  .wm {{
    display: inline-flex;
    align-items: center;
    font: 500 1em/1 var(--sans);
    letter-spacing: -0.015em;
    white-space: nowrap;
  }}
  .wm svg {{ width: 0.77em; height: 1.18em; margin: 0 -0.11em; flex: none; }}

  /* Outcome marks. ok: filled circle. no effect: left half filled. dead:
     dotted ring. skipped and other unexercised states: short dash. broken:
     the red slash (.sl), the only mark that is not the text color. */
  .g {{
    display: inline-block;
    position: relative;
    width: 0.66em;
    height: 0.66em;
    border: 1.5px solid currentColor;
    border-radius: 50%;
    flex: none;
  }}
  .g.full {{ background: currentColor; }}
  .g.half {{ overflow: hidden; }}
  .g.half::before {{
    content: "";
    position: absolute;
    inset: 0 50% 0 0;
    background: currentColor;
  }}
  .g.dead {{ border-style: dotted; }}
  .g.skip {{ height: 1.5px; border: 0; border-radius: 0; background: currentColor; }}
  .sl {{ display: inline-block; width: 0.5em; height: 0.78em; flex: none; fill: var(--red); }}

  .brand {{
    display: flex;
    align-items: center;
    height: 64px;
    padding: 0 var(--pad);
    border-bottom: 1px solid var(--rule);
    font-size: 21px;
  }}
  .title {{ padding: 36px var(--pad) 0; }}
  .meta {{
    display: flex;
    flex-wrap: wrap;
    gap: 4px 22px;
    margin: 0 0 14px;
  }}
  h1, h2 {{
    margin: 0;
    font-family: var(--serif);
    font-weight: 500;
    font-variant-numeric: lining-nums;
    text-wrap: balance;
  }}
  h1 {{
    font-size: clamp(34px, 4.4vw, 54px);
    line-height: 1.02;
    letter-spacing: -0.018em;
  }}
  h2 {{
    font-size: 28px;
    line-height: 1.08;
    letter-spacing: -0.01em;
  }}
  .badge {{
    display: inline-block;
    padding: 1px 6px;
    border: 1px solid var(--rule);
    background: var(--raised);
    color: var(--muted);
    font: 400 12px/1.4 var(--mono);
  }}
  .meta .badge {{
    padding: 0;
    border: 0;
    background: none;
    font-size: 13px;
    overflow-wrap: anywhere;
  }}
  .stats {{
    display: flex;
    flex-wrap: wrap;
    gap: 20px 48px;
    padding: 30px var(--pad) 28px;
  }}
  .stat-card {{
    display: flex;
    flex-direction: column;
    gap: 9px;
  }}
  .stat-card strong {{
    color: var(--text);
    font: 500 22px/1 var(--mono);
    font-variant-numeric: lining-nums;
  }}
  .stat-label {{
    display: inline-flex;
    align-items: center;
    gap: 7px;
    color: var(--muted);
    font-size: 13px;
    line-height: 1;
  }}
  .stat-label .g {{ color: var(--text); }}
  .toolbar {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    padding: 14px var(--pad);
    border-top: 1px solid var(--rule);
    border-bottom: 1px solid var(--rule);
  }}
  .toolbar input {{
    flex: 1;
    min-width: 240px;
    padding: 10px 12px;
    border: 1px solid var(--rule);
    border-radius: 0;
    background: var(--raised);
    color: var(--text);
    font: 400 14px/1.2 var(--sans);
    -webkit-appearance: none;
    appearance: none;
  }}
  .toolbar input::placeholder {{ color: var(--muted); opacity: 1; }}
  .toolbar input:hover, .toolbar input:focus {{ border-color: var(--rule-strong); }}
  .filter-btn {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border: 1px solid var(--rule);
    border-radius: 0;
    background: transparent;
    color: var(--text);
    font: 500 13.5px/1.2 var(--sans);
    cursor: pointer;
  }}
  .filter-btn:hover {{ border-color: var(--rule-strong); }}
  .filter-btn[data-status="broken"] {{ color: var(--red); }}
  /* Selected filter: solid text-color fill, ground-colored label. The slash
     inside switches to the red meant for that fill. */
  .filter-btn.active {{
    background: var(--text);
    border-color: var(--text);
    color: var(--ground);
    --red: var(--red-on-fill);
  }}
  main {{
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
    gap: 20px 56px;
    padding: 40px var(--pad) 72px;
  }}
  @media (max-width: 1024px) {{
    main {{ grid-template-columns: minmax(0, 1fr); }}
  }}
  .card {{
    margin-bottom: 44px;
    overflow-x: auto;
  }}
  .card-header {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: baseline;
    gap: 6px 20px;
    padding-bottom: 12px;
  }}
  .route-path {{
    font: 500 15px/1.3 var(--mono);
    overflow-wrap: anywhere;
  }}
  .route-title {{
    margin-left: 10px;
    color: var(--muted);
    font-size: 14px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    border-top: 1px solid var(--rule-strong);
    font: 400 13px/1.5 var(--mono);
    font-variant-numeric: lining-nums;
  }}
  th, td {{
    text-align: left;
    padding: 11px 18px 11px 0;
    border-bottom: 1px solid var(--rule);
    vertical-align: top;
  }}
  th:last-child, td:last-child {{ padding-right: 0; }}
  th {{
    color: var(--muted);
    font-weight: 400;
    white-space: nowrap;
  }}
  td strong {{ color: var(--text); font-weight: 500; }}
  .outcome {{
    display: flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
  }}
  .st-broken {{ color: var(--red); }}
  /* Long selectors, paths and keys wrap inside their cell instead of being
     cut off; .keep opts short tokens (role, status codes) out of that. */
  .mono {{
    font-family: var(--mono);
    font-size: 13px;
    color: var(--muted);
    overflow-wrap: anywhere;
  }}
  .keep {{ overflow-wrap: normal; }}
  .empty {{
    padding: 12px 0;
    border-top: 1px solid var(--rule-strong);
    border-bottom: 1px solid var(--rule);
    color: var(--muted);
    font-size: 14px;
  }}
</style>
</head>
<body>
<header>
  <div class="brand">
    <span class="wm" role="img" aria-label="BrokenApp">Broken<svg viewBox="130 80 252 352" aria-hidden="true"><path fill="#FF2A2A" d="M319.22 98.51L360.78 122.51L192.78 413.49L151.22 389.49Z"/></svg>App</span>
  </div>
  <div class="title">
    <p class="meta">
      <span class="badge" id="project-badge"></span>
      <span class="badge" id="role-badge"></span>
    </p>
    <h1>BrokenApp Interactive UI Map</h1>
  </div>
  <div class="stats" id="stats-bar"></div>
</header>
<div class="toolbar">
  <input type="search" id="search-input" placeholder="Search routes, controls, API endpoints, selectors, or source files...">
  <button class="filter-btn active" data-status="all">All</button>
  <button class="filter-btn" data-status="broken"><svg class="sl" viewBox="130 80 252 352" aria-hidden="true"><path d="M319.22 98.51L360.78 122.51L192.78 413.49L151.22 389.49Z"/></svg>Broken</button>
  <button class="filter-btn" data-status="dead"><i class="g dead" aria-hidden="true"></i>Dead</button>
  <button class="filter-btn" data-status="no_effect"><i class="g half" aria-hidden="true"></i>No Effect</button>
  <button class="filter-btn" data-status="ok"><i class="g full" aria-hidden="true"></i>OK</button>
</div>
<main>
  <section id="routes-col"></section>
  <aside id="side-col"></aside>
</main>
<script id="inventory-data" type="application/json">{json}</script>
<script id="inventory-text" type="application/json">{text}</script>
<script>
  const inv = JSON.parse(document.getElementById('inventory-data').textContent);
  // [does, source] per control, in inv.controls order (rendered in Rust).
  const text = JSON.parse(document.getElementById('inventory-text').textContent);
  (inv.controls || []).forEach((c, i) => {{
    c.does_text = (text[i] || [])[0] || '';
    c.source_text = (text[i] || [])[1] || '';
  }});
  document.getElementById('project-badge').textContent = inv.project + ' (' + inv.target_url + ')';
  document.getElementById('role-badge').textContent = 'role: ' + (inv.role || 'anonymous');

  const brokenCount = (inv.controls || []).filter(c => c.status === 'broken').length;
  const deadCount = (inv.controls || []).filter(c => c.status === 'dead').length;
  const statsBar = document.getElementById('stats-bar');
  const stats = [
    ['Routes', (inv.coverage?.routes_visited || 0) + '/' + (inv.coverage?.routes_known || 0), ''],
    ['Controls Exercised', (inv.coverage?.controls_exercised || 0) + '/' + (inv.coverage?.controls_exercisable || 0), ''],
    ['Broken UI', brokenCount, 'broken'],
    ['Dead UI', deadCount, 'dead'],
    ['API Endpoints', (inv.endpoints || []).length, '']
  ];
  statsBar.innerHTML = stats.map(([k, v, st]) => `<div class="stat-card"><strong>${{v}}</strong><span class="stat-label${{st ? ' ' + statusClass(st) : ''}}">${{st ? statusMark(st) : ''}}${{k}}</span></div>`).join('');

  let activeStatus = 'all';
  let query = '';

  function esc(s) {{
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }}

  function statusClass(st) {{
    if (st === 'ok') return 'st-ok';
    if (st === 'broken') return 'st-broken';
    if (st === 'dead') return 'st-dead';
    if (st === 'no_effect') return 'st-no_effect';
    return 'st-other';
  }}

  // Outcome marks, drawn in the current text color; only the broken slash is red.
  function statusMark(st) {{
    if (st === 'ok') return '<i class="g full" aria-hidden="true"></i>';
    if (st === 'no_effect') return '<i class="g half" aria-hidden="true"></i>';
    if (st === 'dead') return '<i class="g dead" aria-hidden="true"></i>';
    if (st === 'broken') return '<svg class="sl" viewBox="130 80 252 352" aria-hidden="true"><path d="M319.22 98.51L360.78 122.51L192.78 413.49L151.22 389.49Z"/></svg>';
    return '<i class="g skip" aria-hidden="true"></i>';
  }}

  function render() {{
    const q = query.toLowerCase();
    const routesCol = document.getElementById('routes-col');
    const allRoutes = [{{ route: '*', title: 'Global Shell Controls', visited: true }}, ...(inv.routes || [])];
    let html = '';

    for (const r of allRoutes) {{
      const controls = (inv.controls || []).filter(c => c.route === r.route).filter(c => {{
        if (activeStatus !== 'all' && c.status !== activeStatus) return false;
        if (!q) return true;
        const hay = [c.route, c.label, c.role, c.selector, c.reason, c.does_text, c.source_text, JSON.stringify(c.outcomes || [])].join(' ').toLowerCase();
        return hay.includes(q);
      }});
      if (controls.length === 0 && (q || activeStatus !== 'all')) continue;
      if (controls.length === 0 && r.route === '*') continue;

      html += `<div class="card">
        <div class="card-header">
          <div>
            <span class="route-path">${{esc(r.route)}}</span>
            ${{r.title ? `<span class="route-title">${{esc(r.title)}}</span>` : ''}}
          </div>
          <div class="mono">${{r.status ? 'HTTP ' + r.status : (r.visited ? 'visited' : 'unvisited')}}${{r.source ? ' · ' + esc(r.source) : ''}}</div>
        </div>`;
      if (controls.length > 0) {{
        html += `<table><thead><tr><th>Control</th><th>Role</th><th>Does / Evidence</th><th>Status</th><th>Source</th></tr></thead><tbody>`;
        for (const c of controls) {{
          html += `<tr>
            <td><strong>${{esc(c.label || '(unlabeled)')}}</strong><div class="mono">${{esc(c.selector || '')}}</div></td>
            <td class="mono keep">${{esc(c.role)}}</td>
            <td>${{esc(c.does_text)}}</td>
            <td><span class="outcome ${{statusClass(c.status)}}">${{statusMark(c.status)}}${{esc(c.status)}}</span></td>
            <td class="mono">${{esc(c.source_text)}}</td>
          </tr>`;
        }}
        html += `</tbody></table>`;
      }} else {{
        html += `<div class="empty">No controls recorded on this route.</div>`;
      }}
      html += `</div>`;
    }}
    routesCol.innerHTML = html || `<div class="card empty">No matching routes or controls.</div>`;

    const sideCol = document.getElementById('side-col');
    const eps = (inv.endpoints || []).filter(e => !q || JSON.stringify(e).toLowerCase().includes(q));
    let sideHtml = `<div class="card">
      <div class="card-header"><h2>Observed API Endpoints (${{eps.length}})</h2></div>
      <table><thead><tr><th>Endpoint</th><th>Statuses</th><th>Triggered By</th></tr></thead><tbody>`;
    for (const e of eps) {{
      const trig = [...(e.controls || []), ...(e.on_load || []).map(r => 'on_load:' + r)].join(', ');
      sideHtml += `<tr>
        <td class="mono"><strong>${{esc(e.endpoint)}}</strong>${{e.write ? ' <span class="badge">write</span>' : ''}}</td>
        <td class="mono keep">${{esc((e.statuses || []).join(', '))}}</td>
        <td class="mono">${{esc(trig).replace(/\|/g, '|<wbr>')}}</td>
      </tr>`;
    }}
    sideHtml += `</tbody></table></div>`;
    sideCol.innerHTML = sideHtml;
  }}

  document.getElementById('search-input').addEventListener('input', e => {{
    query = e.target.value;
    render();
  }});
  document.querySelectorAll('.filter-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeStatus = btn.dataset.status;
      render();
    }});
  }});
  render();
</script>
</body>
</html>"##
    )
}

/// Write the map files. Returns paths written (sorted).
pub fn write_map(inv: &Inventory, map_dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(map_dir).with_context(|| format!("create {}", map_dir.display()))?;
    let files = [
        (UI_MAP_MD, render_ui_map(inv)),
        (UI_MAP_TSV, render_ui_tsv(inv)),
        (ENDPOINTS_TSV, render_endpoints_tsv(inv)),
        (DEAD_UI_MD, render_dead_ui(inv)),
    ];
    let mut written = Vec::with_capacity(files.len());
    for (name, body) in files {
        let path = map_dir.join(name);
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        written.push(path);
    }
    written.sort();
    Ok(written)
}

// ---------------------------------------------------------------------------
// Changelog
// ---------------------------------------------------------------------------

/// Change lines for a change set (first scan: one summary line).
pub fn change_lines(changes: &ChangeSet, cur: &Inventory) -> Vec<String> {
    if changes.from.is_none() {
        return vec![format!(
            "Initial map: {} controls on {} routes, {} endpoints.",
            cur.controls.len(),
            cur.coverage.routes_visited,
            cur.endpoints.len()
        )];
    }
    changes.changes.iter().map(|c| c.line.clone()).collect()
}

fn summary_text(summary: &BTreeMap<String, u32>) -> String {
    let parts: Vec<String> = summary.iter().map(|(k, v)| format!("{v} {k}")).collect();
    parts.join(", ")
}

pub fn render_changelog_entry(changes: &ChangeSet, cur: &Inventory) -> String {
    let date = cur.generated_at.replace('T', " ");
    let date = date.trim_end_matches('Z').trim_end_matches("+00:00");
    let mut out = format!("## {date} UTC");
    if let Some(g) = &cur.git {
        let short: String = g.commit.chars().take(12).collect();
        let _ = write!(out, " · {short}");
        if let Some(b) = &g.branch {
            let _ = write!(out, " ({b})");
        }
        if g.dirty {
            out.push_str(" + uncommitted");
        }
    }
    if let Some(inc) = &cur.incremental {
        let _ = write!(out, " · {}", incremental_heading(inc));
    }
    out.push_str("\n\n");
    if let Some(inc) = &cur.incremental {
        let _ = writeln!(
            out,
            "Re-crawled: {}. Every other route is kept from the map of {}.\n",
            if inc.routes.is_empty() {
                "none".to_string()
            } else {
                inc.routes.join(", ")
            },
            inc.base.replace('T', " ")
        );
    }
    let total = changes.changes.len();
    if changes.from.is_some() {
        let _ = writeln!(
            out,
            "{total} change{}: {}. Coverage: {}.\n",
            if total == 1 { "" } else { "s" },
            summary_text(&change_summary(changes)),
            coverage_line(cur)
        );
    } else {
        let _ = writeln!(out, "Coverage: {}.\n", coverage_line(cur));
    }
    let lines = change_lines(changes, cur);
    for line in lines.iter().take(CHANGELOG_MAX_LINES) {
        let _ = writeln!(out, "- {line}");
    }
    if lines.len() > CHANGELOG_MAX_LINES {
        let _ = writeln!(out, "- +{} more", lines.len() - CHANGELOG_MAX_LINES);
    }
    if changes.from.is_some() && !changes.notes.is_empty() {
        out.push('\n');
        for note in &changes.notes {
            let _ = writeln!(out, "_{}_", md_cell(note));
        }
    }
    out
}

/// `incremental: re-crawled 2 routes (changed: src/a.tsx, src/b.tsx)`.
pub fn incremental_heading(inc: &super::IncrementalInfo) -> String {
    let n = inc.routes.len();
    format!(
        "incremental: re-crawled {n} route{} (changed: {})",
        if n == 1 { "" } else { "s" },
        changed_files_text(inc)
    )
}

/// The first few changed files, `+N more`, or `none`.
fn changed_files_text(inc: &super::IncrementalInfo) -> String {
    const MAX_FILES: usize = 4;
    if inc.changed_files.is_empty() {
        return "none".to_string();
    }
    let mut files: Vec<String> = inc.changed_files.iter().take(MAX_FILES).cloned().collect();
    let more = inc.changed_files.len().saturating_sub(MAX_FILES);
    if more > 0 {
        files.push(format!("+{more} more"));
    }
    files.join(", ")
}

/// Summary counts of element-level changes only (no `not_observed` /
/// `newly_observed` / `shifted` buckets).
pub fn change_summary(changes: &ChangeSet) -> BTreeMap<String, u32> {
    changes
        .summary
        .iter()
        .filter(|(k, _)| !NON_CHANGE_BUCKETS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

pub fn append_changelog(changes: &ChangeSet, cur: &Inventory, path: &Path) -> Result<()> {
    if changes.from.is_some() && changes.changes.is_empty() {
        return Ok(());
    }
    let header = format!(
        "# UI changelog: {}\n\nNewest first. Written by `brokenapp map`; one entry per scan that changed the UI.\n",
        cur.project
    );
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    // Keep previous entries (everything from the first `## ` heading on).
    let previous = existing
        .find("\n## ")
        .map(|i| &existing[i + 1..])
        .or_else(|| existing.starts_with("## ").then_some(existing.as_str()))
        .unwrap_or("");
    let mut out = header;
    out.push('\n');
    out.push_str(&render_changelog_entry(changes, cur));
    if !previous.is_empty() {
        out.push('\n');
        out.push_str(previous.trim_end());
        out.push('\n');
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, out).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsv_field_strips_tabs_newlines_and_control_chars() {
        assert_eq!(tsv_field("Save\tchanges\n  now\r\n"), "Save changes now");
        assert_eq!(
            tsv_field("line1\u{2028}line2\u{2029}line3"),
            "line1 line2 line3"
        );
        assert_eq!(tsv_field(" \x00\x0b  clean  "), "clean");
        assert_eq!(tsv_field("[\"/?tab=a\"]"), "[\"/?tab=a\"]");
        assert_eq!(tsv_field(""), "");
    }

    #[test]
    fn tsv_row_is_grep_friendly_and_omits_empty_json_noise() {
        let plain = Control {
            key: "/cart|button|text=pay".into(),
            route: "/cart".into(),
            role: "button".into(),
            label: "Pay\n\tnow".into(),
            status: ControlStatus::Ok,
            outcomes: vec![
                Outcome::Calls {
                    endpoint: "POST /api/pay".into(),
                    status: None,
                    blocked: true,
                },
                Outcome::Navigates {
                    to: "/receipt".into(),
                },
            ],
            ..Default::default()
        };
        let row = tsv_row(&plain);
        assert!(!row.contains('\n') && !row.contains('\r'));
        let cols: Vec<&str> = row.split('\t').collect();
        let headers: Vec<&str> = TSV_HEADER.split('\t').collect();
        assert_eq!(cols.len(), headers.len());
        let col = |name: &str| cols[headers.iter().position(|h| *h == name).unwrap()];
        assert_eq!(col("label"), "Pay now");
        assert_eq!(col("variants"), "", "empty variants must not emit []");
        assert_eq!(
            col("outcomes"),
            "calls:POST /api/pay [blocked] | navigates:/receipt"
        );
        assert_eq!(
            col("source_candidates"),
            "",
            "missing source must not emit literal null"
        );
        assert!(!row.contains("\tnull\t") && !row.contains("\t[]\t"));

        let mut with_source = plain.clone();
        with_source.variants = vec!["?step=2".into()];
        with_source.source = Some(ResolvedSource {
            method: "static".into(),
            confidence: "ambiguous".into(),
            candidates: vec![
                FileLine {
                    file: "src/a.tsx".into(),
                    line: 10,
                    col: 0,
                },
                FileLine {
                    file: "src/b.tsx".into(),
                    line: 25,
                    col: 4,
                },
            ],
            ..Default::default()
        });
        let row2 = tsv_row(&with_source);
        let cols2: Vec<&str> = row2.split('\t').collect();
        let col2 = |name: &str| cols2[headers.iter().position(|h| *h == name).unwrap()];
        assert_eq!(col2("variants"), "[\"?step=2\"]");
        assert_eq!(col2("source_candidates"), "src/a.tsx:10, src/b.tsx:25");
        assert_eq!(col2("source_method"), "static");
        assert_eq!(col2("source_confidence"), "ambiguous");
    }

    #[test]
    fn obscured_top_covers_render_in_coverage_line_dead_ui_and_ui_map() {
        use crate::inventory::{CoverageSummary, ObscuredCover, RouteEntry};

        let mut not_exercised_by_reason = BTreeMap::new();
        not_exercised_by_reason.insert("obscured".into(), 214);
        not_exercised_by_reason.insert("interaction_limit".into(), 5);

        let inv = Inventory {
            project: "demo".into(),
            generated_at: "2026-11-21T10:00:00Z".into(),
            target_url: "http://127.0.0.1:3000/".into(),
            write_guard: "block".into(),
            coverage: CoverageSummary {
                routes_known: 2,
                routes_visited: 2,
                controls_total: 230,
                controls_exercised: 11,
                controls_exercisable: 230,
                not_exercised_by_reason,
                obscured_top_covers: vec![
                    ObscuredCover {
                        cover: "div[data-radix-overlay]".into(),
                        count: 180,
                    },
                    ObscuredCover {
                        cover: ".ai-chat-widget".into(),
                        count: 34,
                    },
                    ObscuredCover {
                        cover: "header.sticky".into(),
                        count: 12,
                    },
                    ObscuredCover {
                        cover: "div.fourth-cover".into(),
                        count: 3,
                    },
                ],
                ..Default::default()
            },
            routes: vec![RouteEntry {
                route: "/".into(),
                visited: true,
                controls: 1,
                ..Default::default()
            }],
            ..Default::default()
        };

        let expected_snippet = "obscured: 214 (top covers: div[data-radix-overlay] (180), .ai-chat-widget (34), header.sticky (12))";

        let line = coverage_line(&inv);
        assert!(line.contains(expected_snippet), "{line}");
        assert!(
            !line.contains("div.fourth-cover"),
            "should cap display to top 3 covers: {line}"
        );

        let caveat = coverage_caveat(&inv);
        assert!(
            caveat.contains(&format!(
                "Not exercised by reason: {expected_snippet}, interaction_limit 5."
            )),
            "{caveat}"
        );
        assert_eq!(
            caveat.matches("top covers:").count(),
            1,
            "caveat should not duplicate top covers: {caveat}"
        );

        let ui_map = render_ui_map(&inv);
        assert!(ui_map.contains(expected_snippet), "{ui_map}");

        let dead_ui = render_dead_ui(&inv);
        assert!(dead_ui.contains(expected_snippet), "{dead_ui}");

        // Without obscured_top_covers, output stays unchanged without "top covers:".
        let mut without_covers = inv;
        without_covers.coverage.obscured_top_covers.clear();
        assert!(!coverage_line(&without_covers).contains("top covers:"));
        assert!(coverage_caveat(&without_covers).contains("Not exercised by reason: obscured 214"));
    }
}
