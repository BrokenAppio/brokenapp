//! The run manifest of one `brokenapp map` run: `.brokenapp/scans/<ts>/run.json`.
//!
//! It records the run's settings, which roles it maps, and where each role
//! stands (`pending`, `scanning`, `mapped`, `login_failed`, ...), and is
//! rewritten after every step. When a long run is interrupted (Ctrl-C, a
//! closed terminal, a crash), `brokenapp map --resume` reads it, keeps the
//! roles already mapped, resumes the interrupted role's crawl from its
//! checkpoint, and maps the roles not started yet with the same settings.
//! It never holds credential values. Test-data overrides are literal fixture
//! values, preserved with the run settings; they must not contain secrets.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const RUN_MANIFEST: &str = "run.json";
pub const RUN_SCHEMA: &str = "brokenapp.map-run.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    /// Every role mapped (or unchanged).
    Completed,
    /// Some roles could not be mapped (login failed, credentials missing).
    Partial,
    Interrupted,
    Failed,
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Completed => "completed",
            RunStatus::Partial => "partial",
            RunStatus::Interrupted => "interrupted",
            RunStatus::Failed => "failed",
        }
    }
}

/// Settings a resumed run reuses (so it maps with the same budgets).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RunSettings {
    /// Nonsecret identity of the authorized target and source tree.
    #[serde(default)]
    pub target_url: String,
    #[serde(default)]
    pub codebase: String,
    pub scan_mode: String,
    pub max_minutes: u64,
    pub max_views: usize,
    pub write_guard: String,
    pub headless: bool,
    pub tabs: usize,
    /// Literal fixture values, including explicitly empty strings.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub test_data: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_routes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interaction_depth: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interactions_per_view: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interactions_per_depth: Option<Vec<usize>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_budget_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_seconds: Option<u64>,
    #[serde(default = "one")]
    pub role_concurrency: usize,
    #[serde(default)]
    pub store: bool,
}

fn one() -> usize {
    1
}

/// One role of the run.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RunRole {
    pub name: String,
    /// Auth configuration references, never resolved credential values.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub auth_identity: serde_json::Value,
    /// `pending`, `scanning`, `mapped`, `unchanged`, `credentials_missing`,
    /// `session_missing`, `login_failed`, `session_expired`, `failed`, `interrupted`.
    pub status: String,
    /// The role's run directory (`scan.toml`, `scan/`, `progress.json`, ...).
    pub dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    #[serde(default)]
    pub queue_remaining: usize,
}

impl RunRole {
    /// Nothing left to do for this role in this run.
    pub fn finished(&self) -> bool {
        !matches!(
            self.status.as_str(),
            "pending" | "scanning" | "interrupted" | "failed"
        )
    }

    /// True when this role mapped up to a budget cap while queued routes
    /// remained to explore.
    pub fn budget_stopped_with_remaining(&self) -> bool {
        self.status == "mapped"
            && self.queue_remaining > 0
            && matches!(
                self.stop_reason.as_deref(),
                Some("max_duration_reached" | "max_views_reached" | "hard_timeout")
            )
    }

    /// True when this role either did not finish or hit a budget cap with
    /// queued routes still remaining to explore.
    pub fn has_remaining_work(&self) -> bool {
        !self.finished() || self.budget_stopped_with_remaining()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunManifest {
    pub schema: String,
    /// Run directory name under `.brokenapp/scans/`.
    pub ts: String,
    pub started_at: String,
    #[serde(default)]
    pub updated_at: String,
    pub status: RunStatus,
    /// Process that wrote the manifest last (a `running` run whose process
    /// is gone was killed).
    pub pid: u32,
    /// A `--changed` run (merged into the previous map; not resumable).
    #[serde(default)]
    pub incremental: bool,
    pub settings: RunSettings,
    pub roles: Vec<RunRole>,
    /// Times `map --resume` continued this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resumed_at: Vec<String>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl RunManifest {
    pub fn new(ts: &str, started_at: &str, settings: RunSettings, roles: Vec<RunRole>) -> Self {
        Self {
            schema: RUN_SCHEMA.to_string(),
            ts: ts.to_string(),
            started_at: started_at.to_string(),
            updated_at: now(),
            status: RunStatus::Running,
            pid: std::process::id(),
            incremental: false,
            settings,
            roles,
            resumed_at: Vec::new(),
        }
    }

    pub fn load(run_dir: &Path) -> Result<Self> {
        let path = run_dir.join(RUN_MANIFEST);
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }

    /// Atomic write.
    pub fn save(&mut self, run_dir: &Path) -> Result<()> {
        self.updated_at = now();
        self.pid = std::process::id();
        let path = run_dir.join(RUN_MANIFEST);
        let tmp = run_dir.join(format!("{RUN_MANIFEST}.tmp"));
        let body = serde_json::to_string_pretty(self).context("serialize run manifest")?;
        std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("write {}", path.display()))
    }

    pub fn role_mut(&mut self, name: &str) -> Option<&mut RunRole> {
        self.roles.iter_mut().find(|r| r.name == name)
    }
}

/// Whether process `pid` is alive.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// The latest run under `scans_dir`, if `map --resume` can continue it.
pub fn latest_resumable(scans_dir: &Path) -> Result<(PathBuf, RunManifest)> {
    let mut dirs: Vec<PathBuf> = match std::fs::read_dir(scans_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.join(RUN_MANIFEST).is_file())
            .collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err).with_context(|| format!("read {}", scans_dir.display())),
    };
    dirs.sort();
    let Some(dir) = dirs.pop() else {
        bail!(
            "nothing to resume: no map run recorded in {}",
            scans_dir.display()
        );
    };
    let manifest = RunManifest::load(&dir)?;
    let resumable_budget_stop = manifest.settings.scan_mode == "full"
        && !manifest.incremental
        && manifest
            .roles
            .iter()
            .any(RunRole::budget_stopped_with_remaining);
    match manifest.status {
        RunStatus::Completed | RunStatus::Partial if !resumable_budget_stop => bail!(
            "nothing to resume: the last map run ({}) finished ({}). Run `brokenapp map` for a new map{}",
            manifest.ts,
            manifest.status.as_str(),
            if manifest.status == RunStatus::Partial {
                ", or `brokenapp map --role <role>` for the roles it could not map"
            } else {
                ""
            }
        ),
        RunStatus::Running if manifest.pid != std::process::id() && pid_alive(manifest.pid) => {
            bail!(
                "the last map run ({}) is still running (pid {}); wait for it or stop it first",
                manifest.ts,
                manifest.pid
            )
        }
        _ => {}
    }
    if manifest.incremental {
        bail!(
            "the last map run ({}) was an incremental `map --changed` run, which is not resumable; run `brokenapp map --changed` again",
            manifest.ts
        );
    }
    let has_work = if manifest.settings.scan_mode == "full" {
        manifest.roles.iter().any(RunRole::has_remaining_work)
    } else {
        manifest.roles.iter().any(|r| !r.finished())
    };
    if !has_work {
        bail!(
            "nothing to resume: every role of the last map run ({}) already finished",
            manifest.ts
        );
    }
    Ok((dir, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(status: RunStatus, roles: &[(&str, &str)]) -> RunManifest {
        let mut m = RunManifest::new(
            "20261022T100000Z",
            "2026-10-22T10:00:00.000Z",
            RunSettings {
                scan_mode: "full".into(),
                tabs: 4,
                role_concurrency: 1,
                ..Default::default()
            },
            roles
                .iter()
                .map(|(n, s)| RunRole {
                    name: n.to_string(),
                    status: s.to_string(),
                    dir: format!("/x/{n}"),
                    ..Default::default()
                })
                .collect(),
        );
        m.status = status;
        m
    }

    #[test]
    fn resumable_runs_are_found_and_finished_ones_refused() {
        let dir = tempfile::tempdir().unwrap();
        let scans = dir.path();
        assert!(format!("{:#}", latest_resumable(scans).unwrap_err()).contains("no map run"));

        let old = scans.join("20261021T000000Z");
        std::fs::create_dir_all(&old).unwrap();
        manifest(RunStatus::Interrupted, &[("anonymous", "interrupted")])
            .save(&old)
            .unwrap();
        let new = scans.join("20261022T100000Z");
        std::fs::create_dir_all(&new).unwrap();
        let mut m = manifest(
            RunStatus::Interrupted,
            &[
                ("anonymous", "mapped"),
                ("admin", "interrupted"),
                ("user", "pending"),
            ],
        );
        m.save(&new).unwrap();
        let (found, loaded) = latest_resumable(scans).unwrap();
        assert_eq!(found, new);
        assert_eq!(loaded.roles.len(), 3);
        assert!(loaded.roles[0].finished() && !loaded.roles[1].finished());

        m.status = RunStatus::Completed;
        m.save(&new).unwrap();
        assert!(format!("{:#}", latest_resumable(scans).unwrap_err()).contains("finished"));

        m.status = RunStatus::Interrupted;
        m.incremental = true;
        m.save(&new).unwrap();
        assert!(format!("{:#}", latest_resumable(scans).unwrap_err()).contains("--changed"));

        // A `running` run whose process is gone was killed: resumable.
        m.incremental = false;
        m.status = RunStatus::Running;
        m.save(&new).unwrap();
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(new.join(RUN_MANIFEST)).unwrap())
                .unwrap();
        raw["pid"] = serde_json::json!(999_999_u32);
        std::fs::write(new.join(RUN_MANIFEST), raw.to_string()).unwrap();
        assert!(latest_resumable(scans).is_ok());
    }

    #[test]
    fn budget_stopped_full_run_is_resumable_while_drained_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let scans = dir.path();
        let run = scans.join("20261023T100000Z");
        std::fs::create_dir_all(&run).unwrap();

        let mut m = manifest(RunStatus::Completed, &[("anonymous", "mapped")]);
        m.roles[0].stop_reason = Some("max_duration_reached".into());
        m.roles[0].queue_remaining = 12;
        m.save(&run).unwrap();
        assert!(m.roles[0].has_remaining_work());
        let (found, loaded) = latest_resumable(scans).unwrap();
        assert_eq!(found, run);
        assert!(loaded.roles[0].has_remaining_work());

        // Partial full runs with a budget-stopped role are also resumable.
        let mut partial = manifest(
            RunStatus::Partial,
            &[("anonymous", "mapped"), ("admin", "login_failed")],
        );
        partial.roles[0].stop_reason = Some("max_views_reached".into());
        partial.roles[0].queue_remaining = 4;
        partial.save(&run).unwrap();
        assert!(latest_resumable(scans).is_ok());

        // Hard timeout with queued routes remaining is also resumable.
        m.roles[0].stop_reason = Some("hard_timeout".into());
        m.roles[0].queue_remaining = 2;
        m.save(&run).unwrap();
        assert!(latest_resumable(scans).is_ok());

        // Drained queue (0 remaining) is not resumable, even with a budget stop_reason.
        m.roles[0].queue_remaining = 0;
        m.save(&run).unwrap();
        assert!(!m.roles[0].has_remaining_work());
        assert!(format!("{:#}", latest_resumable(scans).unwrap_err()).contains("finished"));

        // Normal queue_exhausted completion is not resumable.
        m.roles[0].stop_reason = Some("queue_exhausted".into());
        m.roles[0].queue_remaining = 0;
        m.save(&run).unwrap();
        assert!(format!("{:#}", latest_resumable(scans).unwrap_err()).contains("finished"));

        // Standard-mode budget stops are not resumable.
        m.settings.scan_mode = "standard".into();
        m.roles[0].stop_reason = Some("max_views_reached".into());
        m.roles[0].queue_remaining = 10;
        m.save(&run).unwrap();
        assert!(format!("{:#}", latest_resumable(scans).unwrap_err()).contains("finished"));

        // Incremental full runs are not resumable.
        m.settings.scan_mode = "full".into();
        m.incremental = true;
        m.save(&run).unwrap();
        assert!(format!("{:#}", latest_resumable(scans).unwrap_err()).contains("finished"));
    }
}
