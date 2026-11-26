//! Which files changed since the latest UI map (`brokenapp map --changed`).
//!
//! With git: everything that differs between the map's commit (or
//! `--since <ref>`) and the working tree (committed, staged, unstaged), plus
//! untracked files. When the map itself was made with uncommitted changes,
//! an uncommitted file only counts when it was modified after the map
//! started (the map already saw the older edits).
//!
//! Without git (or when the map's commit is unknown here): files modified
//! after the map run started, plus files the map references (route and
//! control sources) that no longer exist.
//!
//! Paths are relative to the codebase root, `/`-separated.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::inventory::Inventory;

/// Directories never walked for modification times.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "bower_components",
    "jspm_packages",
    "dist",
    "build",
    "out",
    "coverage",
    "target",
    "storybook-static",
    "playwright-report",
    "test-results",
];
/// Upper bound on files examined by the modification-time walk.
const MAX_WALK_FILES: usize = 200_000;

/// Changed files and how they were found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChangedFiles {
    /// `git` or `mtime`.
    pub source: String,
    /// git: the base commit; mtime: the RFC3339 cutoff.
    pub base: String,
    /// Codebase-relative paths, sorted.
    pub files: BTreeSet<String>,
    /// The subset of `files` that no longer exists.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub deleted: BTreeSet<String>,
    /// How the list was made (fallbacks, filters).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Files changed since `latest` was mapped (or since `since`, a git ref).
/// `exclude` lists codebase-relative prefixes to ignore (the state dir).
pub fn detect(
    root: &Path,
    latest: &Inventory,
    since: Option<&str>,
    exclude: &[String],
) -> Result<ChangedFiles> {
    let in_git = git(root, &["rev-parse", "--is-inside-work-tree"]).as_deref() == Some("true");
    let cutoff = latest.run_started_at();
    let mut notes = Vec::new();
    let base = match since {
        Some(rev) => {
            if !in_git {
                bail!(
                    "--since {rev} needs a git checkout, and {} is not one",
                    root.display()
                );
            }
            Some(
                verify_commit(root, rev).with_context(|| {
                    format!("--since {rev} is not a commit in {}", root.display())
                })?,
            )
        }
        None if !in_git => {
            notes.push("not a git checkout: files modified after the previous map started count as changed".to_string());
            None
        }
        None => match latest.git.as_ref().map(|g| g.commit.as_str()) {
            None | Some("") => {
                notes.push("the previous map recorded no git commit: files modified after it started count as changed".to_string());
                None
            }
            Some(commit) => match verify_commit(root, commit) {
                Ok(c) => Some(c),
                Err(_) => {
                    let short: String = commit.chars().take(12).collect();
                    notes.push(format!("the previous map's commit {short} is not in this checkout: files modified after the map started count as changed"));
                    None
                }
            },
        },
    };

    let mut out = match base {
        Some(base) => {
            let dirty = since.is_none() && latest.git.as_ref().is_some_and(|g| g.dirty);
            if dirty {
                notes.push("the previous map was made with uncommitted changes: uncommitted files not modified since it started are not counted".to_string());
            }
            // Untracked files have no history: only their modification time
            // tells whether the previous map already saw them.
            let cutoffs = GitCutoffs {
                uncommitted: cutoff.filter(|_| dirty),
                untracked: cutoff.filter(|_| since.is_none()),
            };
            from_git(root, &base, cutoffs)?
        }
        None => {
            let Some(cutoff) = cutoff else {
                bail!("the previous map records no time; run a full `brokenapp map`");
            };
            from_mtime(root, latest, cutoff)
        }
    };
    out.notes.extend(notes);
    let excluded = |f: &String| {
        exclude
            .iter()
            .any(|p| !p.is_empty() && (f == p || f.starts_with(&format!("{p}/"))))
    };
    out.files.retain(|f| !excluded(f));
    out.deleted.retain(|f| out.files.contains(f));
    Ok(out)
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// NUL-separated path list from a git command.
fn git_paths(dir: &Path, args: &[&str]) -> Result<BTreeSet<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .map(|p| p.trim_end_matches(['\n', '\r']))
        .filter(|p| !p.is_empty())
        .map(|p| p.replace('\\', "/"))
        .collect())
}

fn verify_commit(root: &Path, rev: &str) -> Result<String> {
    let spec = format!("{rev}^{{commit}}");
    git(root, &["rev-parse", "--verify", "--quiet", &spec])
        .filter(|c| !c.is_empty())
        .with_context(|| format!("unknown revision {rev}"))
}

/// Modification-time filters for changes git cannot date.
#[derive(Debug, Clone, Copy, Default)]
struct GitCutoffs {
    /// Uncommitted edits to tracked files (the map was made with some).
    uncommitted: Option<DateTime<Utc>>,
    /// Untracked files.
    untracked: Option<DateTime<Utc>>,
}

fn from_git(root: &Path, base: &str, cutoffs: GitCutoffs) -> Result<ChangedFiles> {
    // Working tree vs base: committed, staged and unstaged changes.
    let all = git_paths(
        root,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            "--relative",
            "-z",
            base,
            "--",
        ],
    )?;
    let mut untracked = git_paths(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    if let Some(cutoff) = cutoffs.untracked {
        untracked.retain(|f| modified_since(&root.join(f), cutoff).unwrap_or(true));
    }
    let mut files: BTreeSet<String> = all.union(&untracked).cloned().collect();
    if let Some(cutoff) = cutoffs.uncommitted {
        let committed = git_paths(
            root,
            &[
                "diff",
                "--name-only",
                "--no-renames",
                "--relative",
                "-z",
                base,
                "HEAD",
                "--",
            ],
        )?;
        files.retain(|f| {
            committed.contains(f) || modified_since(&root.join(f), cutoff).unwrap_or(true)
        });
    }
    let deleted = files
        .iter()
        .filter(|f| !root.join(f).exists())
        .cloned()
        .collect();
    Ok(ChangedFiles {
        source: "git".to_string(),
        base: base.to_string(),
        files,
        deleted,
        notes: Vec::new(),
    })
}

/// `Some(true)` when `path` was modified at or after `cutoff` (`None` when it
/// does not exist).
fn modified_since(path: &Path, cutoff: DateTime<Utc>) -> Option<bool> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(DateTime::<Utc>::from(modified) >= cutoff)
}

fn from_mtime(root: &Path, latest: &Inventory, cutoff: DateTime<Utc>) -> ChangedFiles {
    let cutoff_sys: SystemTime = cutoff.into();
    let mut files = BTreeSet::new();
    let mut seen = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if ft.is_dir() {
                if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push(path);
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            seen += 1;
            if seen > MAX_WALK_FILES {
                break;
            }
            let newer = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .is_some_and(|m| m >= cutoff_sys);
            if newer && let Ok(rel) = path.strip_prefix(root) {
                files.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    // Deletions leave no modification time: files the map refers to that
    // are gone.
    let mut deleted = BTreeSet::new();
    for f in referenced_files(latest) {
        if !root.join(&f).exists() {
            deleted.insert(f.clone());
            files.insert(f);
        }
    }
    let mut notes = Vec::new();
    if seen > MAX_WALK_FILES {
        notes.push(format!(
            "stopped the modification-time walk after {MAX_WALK_FILES} files"
        ));
    }
    ChangedFiles {
        source: "mtime".to_string(),
        base: cutoff.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        files,
        deleted,
        notes,
    }
}

/// Source files a map refers to: route definitions and control sources.
pub fn referenced_files(inv: &Inventory) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for r in &inv.routes {
        if let Some(src) = &r.source {
            out.insert(strip_line(src).to_string());
        }
    }
    for c in &inv.controls {
        if let Some(src) = &c.source {
            for site in [&src.render, &src.caller, &src.handler]
                .into_iter()
                .flatten()
            {
                out.insert(site.file.clone());
            }
        }
    }
    out.retain(|f| !f.is_empty() && !f.starts_with('/') && !f.contains("://"));
    out
}

/// `src/app/page.tsx:40` -> `src/app/page.tsx`.
pub fn strip_line(src: &str) -> &str {
    match src.rsplit_once(':') {
        Some((file, line)) if !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()) => file,
        _ => src,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_link::runtime_source::{FileLine, ResolvedSource};
    use crate::inventory::{Control, GitInfo, RouteEntry};

    fn set_mtime(path: &Path, at: DateTime<Utc>) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(at.into()).unwrap();
    }

    fn git_ok() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "user.name=t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn without_git_files_modified_after_the_map_count_and_deletions_are_found() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for f in [
            "src/pages/index.astro",
            "src/pages/about.astro",
            "src/components/Nav.astro",
            "node_modules/x/index.js",
            ".brokenapp/map/UI-MAP.md",
        ] {
            std::fs::create_dir_all(root.join(f).parent().unwrap()).unwrap();
            std::fs::write(root.join(f), "x").unwrap();
        }
        let started: DateTime<Utc> = "2026-10-22T10:00:00Z".parse().unwrap();
        let before = started - chrono::Duration::minutes(5);
        let after = started + chrono::Duration::minutes(5);
        for f in [
            "src/pages/index.astro",
            "src/components/Nav.astro",
            "node_modules/x/index.js",
        ] {
            set_mtime(&root.join(f), before);
        }
        for f in [
            "src/pages/about.astro",
            "node_modules/x/index.js",
            ".brokenapp/map/UI-MAP.md",
        ] {
            set_mtime(&root.join(f), after);
        }
        let latest = Inventory {
            started_at: Some("2026-10-22T10:00:00Z".into()),
            routes: vec![RouteEntry {
                route: "/gone".into(),
                source: Some("src/pages/gone.astro:1".into()),
                ..Default::default()
            }],
            controls: vec![Control {
                source: Some(ResolvedSource {
                    render: Some(FileLine {
                        file: "src/components/Nav.astro".into(),
                        line: 3,
                        col: 0,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let changed = detect(root, &latest, None, &[".brokenapp".into()]).unwrap();
        assert_eq!(changed.source, "mtime");
        assert_eq!(
            changed.files.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["src/pages/about.astro", "src/pages/gone.astro"],
            "{changed:#?}"
        );
        assert_eq!(
            changed
                .deleted
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["src/pages/gone.astro"]
        );
        assert!(
            changed.notes[0].contains("not a git checkout"),
            "{changed:#?}"
        );
        // --since needs git.
        assert!(detect(root, &latest, Some("HEAD~1"), &[]).is_err());
    }

    #[test]
    fn with_git_committed_uncommitted_and_untracked_changes_count() {
        if !git_ok() {
            eprintln!("skipping: git not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let app = repo.join("apps/web");
        std::fs::create_dir_all(app.join("src/app/about")).unwrap();
        std::fs::write(app.join("src/app/page.tsx"), "a").unwrap();
        std::fs::write(app.join("src/app/about/page.tsx"), "a").unwrap();
        std::fs::write(app.join("src/app/old.tsx"), "a").unwrap();
        std::fs::write(repo.join("README.md"), "outside the codebase").unwrap();
        run_git(repo, &["init", "-q"]);
        run_git(repo, &["add", "-A"]);
        run_git(repo, &["commit", "-q", "-m", "base"]);
        let base = git(repo, &["rev-parse", "HEAD"]).unwrap();

        // Committed after the map, then uncommitted, untracked and deleted.
        std::fs::write(app.join("src/app/about/page.tsx"), "b").unwrap();
        std::fs::write(repo.join("README.md"), "changed, outside").unwrap();
        run_git(repo, &["commit", "-q", "-am", "edit about"]);
        std::fs::write(app.join("src/app/page.tsx"), "b").unwrap();
        std::fs::write(app.join("src/app/new.tsx"), "n").unwrap();
        std::fs::remove_file(app.join("src/app/old.tsx")).unwrap();

        let latest = Inventory {
            git: Some(GitInfo {
                commit: base.clone(),
                branch: None,
                dirty: false,
            }),
            ..Default::default()
        };
        let changed = detect(&app, &latest, None, &[]).unwrap();
        assert_eq!(changed.source, "git");
        assert_eq!(changed.base, base);
        assert_eq!(
            changed.files.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "src/app/about/page.tsx",
                "src/app/new.tsx",
                "src/app/old.tsx",
                "src/app/page.tsx"
            ],
            "paths are relative to the codebase, files outside it are ignored"
        );
        assert!(changed.deleted.contains("src/app/old.tsx"));

        // An untracked file older than the map was already in it, even when
        // the map recorded a clean tree (git's dirty flag ignores untracked
        // files); tracked edits still count.
        let clean = Inventory {
            started_at: Some((Utc::now() + chrono::Duration::minutes(1)).to_rfc3339()),
            ..latest.clone()
        };
        let changed = detect(&app, &clean, None, &[]).unwrap();
        assert!(!changed.files.contains("src/app/new.tsx"), "{changed:#?}");
        assert!(changed.files.contains("src/app/page.tsx"));
        assert!(changed.files.contains("src/app/about/page.tsx"));

        // --since overrides the map's commit.
        let head = git(repo, &["rev-parse", "HEAD"]).unwrap();
        let since = detect(&app, &latest, Some(&head), &[]).unwrap();
        assert!(!since.files.contains("src/app/about/page.tsx"));
        assert!(since.files.contains("src/app/page.tsx"));
        assert!(detect(&app, &latest, Some("no-such-ref"), &[]).is_err());

        // A map made with uncommitted changes: an uncommitted file not
        // touched since the map started is not a change.
        let started = Utc::now() + chrono::Duration::minutes(1);
        let dirty = Inventory {
            started_at: Some(started.to_rfc3339()),
            git: Some(GitInfo {
                commit: head,
                branch: None,
                dirty: true,
            }),
            ..Default::default()
        };
        let changed = detect(&app, &dirty, None, &[]).unwrap();
        assert_eq!(
            changed.files.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["src/app/old.tsx"],
            "only the deletion (it has no modification time) counts: {changed:#?}"
        );
        let later = started + chrono::Duration::minutes(1);
        set_mtime(&app.join("src/app/page.tsx"), later);
        let changed = detect(&app, &dirty, None, &[]).unwrap();
        assert_eq!(
            changed.files.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["src/app/old.tsx", "src/app/page.tsx"]
        );

        // A commit the checkout does not know falls back to mtimes.
        let unknown = Inventory {
            started_at: Some(Utc::now().to_rfc3339()),
            git: Some(GitInfo {
                commit: "0123456789abcdef0123456789abcdef01234567".into(),
                branch: None,
                dirty: false,
            }),
            ..Default::default()
        };
        let changed = detect(&app, &unknown, None, &[]).unwrap();
        assert_eq!(changed.source, "mtime");
        assert!(
            changed
                .notes
                .iter()
                .any(|n| n.contains("not in this checkout"))
        );
    }

    #[test]
    fn strip_line_keeps_paths_without_a_line() {
        assert_eq!(strip_line("src/app/page.tsx:40"), "src/app/page.tsx");
        assert_eq!(strip_line("src/app/page.tsx"), "src/app/page.tsx");
        assert_eq!(strip_line("C:/x"), "C:/x");
    }
}
