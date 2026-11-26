//! `brokenapp projects`: list registered projects.

use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use super::project::{CONFIG_FILE, LATEST_INVENTORY, Registry, RegistryEntry};

#[derive(Debug, Args)]
pub struct ProjectsArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct ProjectRow {
    name: String,
    url: String,
    root: String,
    state_dir: String,
    protected: bool,
    /// The state dir still has a `config.toml`.
    state_dir_exists: bool,
    /// A UI map has been built (`history/latest.inventory.json`).
    has_map: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_scan_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_summary: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProjectsReport {
    registry: String,
    projects: Vec<ProjectRow>,
}

fn row(e: &RegistryEntry) -> ProjectRow {
    let state = Path::new(&e.state_dir);
    ProjectRow {
        name: e.name.clone(),
        url: e.url.clone(),
        root: e.root.clone(),
        state_dir: e.state_dir.clone(),
        protected: e.protected,
        state_dir_exists: state.join(CONFIG_FILE).is_file(),
        has_map: state.join("history").join(LATEST_INVENTORY).is_file(),
        last_scan_at: e.last_scan_at.clone(),
        last_summary: e.last_summary.clone(),
    }
}

fn state_label(r: &ProjectRow) -> &'static str {
    match (r.state_dir_exists, r.protected) {
        (false, _) => "missing",
        (true, true) => "protected",
        (true, false) if r.has_map => "mapped",
        (true, false) => "no map",
    }
}

fn render_table(rows: &[ProjectRow]) -> String {
    let headers = ["NAME", "STATE", "URL", "LAST MAP", "SUMMARY", "ROOT"];
    let cells: Vec<[String; 6]> = rows
        .iter()
        .map(|r| {
            [
                r.name.clone(),
                state_label(r).to_string(),
                r.url.clone(),
                r.last_scan_at.clone().unwrap_or_else(|| "-".into()),
                r.last_summary.clone().unwrap_or_else(|| "-".into()),
                r.root.clone(),
            ]
        })
        .collect();
    let mut widths = headers.map(str::len);
    for c in &cells {
        for (w, v) in widths.iter_mut().zip(c.iter()) {
            *w = (*w).max(v.chars().count());
        }
    }
    let line = |vals: &[String]| {
        let mut out = String::new();
        for (i, v) in vals.iter().enumerate() {
            if i + 1 == vals.len() {
                out.push_str(v);
            } else {
                out.push_str(&format!("{v:<width$}  ", width = widths[i]));
            }
        }
        out.trim_end().to_string()
    };
    let mut out = line(&headers.map(String::from));
    out.push('\n');
    for c in &cells {
        out.push_str(&line(c));
        out.push('\n');
    }
    out
}

pub async fn run(args: ProjectsArgs) -> Result<i32> {
    let registry = Registry::load()?;
    let report = ProjectsReport {
        registry: Registry::path().display().to_string(),
        projects: registry.projects.iter().map(row).collect(),
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("serialize projects")?
        );
        return Ok(0);
    }
    if report.projects.is_empty() {
        println!(
            "No projects registered ({}). Run `brokenapp init` in a project.",
            report.registry
        );
        return Ok(0);
    }
    print!("{}", render_table(&report.projects));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_reflect_state_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".brokenapp");
        std::fs::create_dir_all(state.join("history")).unwrap();
        std::fs::write(state.join(CONFIG_FILE), "").unwrap();
        let entry = RegistryEntry {
            name: "shop".into(),
            root: dir.path().display().to_string(),
            state_dir: state.display().to_string(),
            url: "http://localhost:3000".into(),
            ..Default::default()
        };
        let r = row(&entry);
        assert!(r.state_dir_exists);
        assert!(!r.has_map);
        assert_eq!(state_label(&r), "no map");

        std::fs::write(state.join("history").join(LATEST_INVENTORY), "{}").unwrap();
        assert_eq!(state_label(&row(&entry)), "mapped");

        let gone = RegistryEntry {
            state_dir: dir.path().join("nope").display().to_string(),
            ..entry
        };
        assert_eq!(state_label(&row(&gone)), "missing");
    }

    #[test]
    fn table_aligns_columns() {
        let rows = vec![ProjectRow {
            name: "shop".into(),
            url: "http://localhost:3000".into(),
            root: "/r/shop".into(),
            state_dir: "/r/shop/.brokenapp".into(),
            protected: false,
            state_dir_exists: true,
            has_map: true,
            last_scan_at: Some("2026-10-21T18:00:00Z".into()),
            last_summary: Some("5/7 routes".into()),
        }];
        let t = render_table(&rows);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("NAME  STATE "));
        assert!(lines[1].starts_with("shop  mapped"));
        assert!(lines[1].ends_with("/r/shop"));
    }
}
