pub mod bug_report;
pub mod checkpoint;
pub mod coverage_gap;
pub mod interactions;
pub mod schema;
pub mod spec_generator;

use std::path::Path;

use anyhow::{Context, Result};

use crate::config::{OutputConfig, ScanConfig};
use crate::explorer::ScanOutcome;

pub async fn write_scan_output(
    outcome: &ScanOutcome,
    scan_cfg: &ScanConfig,
    out_cfg: &OutputConfig,
    has_auth: bool,
) -> Result<()> {
    tokio::fs::create_dir_all(&outcome.output_dir)
        .await
        .with_context(|| format!("create {}", outcome.output_dir.display()))?;

    let spec = spec_generator::generate_spec(outcome);
    let spec_path = outcome.output_dir.join("spec.json");
    write_json(&spec_path, &spec).await?;

    let status_path = outcome.output_dir.join("scan-status.json");
    write_json(
        &status_path,
        &serde_json::json!({
            "status": outcome.completion_status.as_str(),
            "started_at": outcome.started_at,
            "finished_at": outcome.finished_at,
            "duration_seconds": outcome.scan_duration_seconds,
            "target_url": outcome.target_url,
        }),
    )
    .await?;

    let bug_report = bug_report::generate_bug_report(outcome, scan_cfg, has_auth, None);
    let bugs_path = outcome.output_dir.join("bugs.json");
    write_json(&bugs_path, &bug_report).await?;

    let coverage_gap_path = outcome.output_dir.join("coverage-gaps.json");
    write_json(&coverage_gap_path, &outcome.coverage_gaps).await?;

    if out_cfg
        .bug_report_format
        .iter()
        .any(|f| *f == crate::config::BugReportFormat::Markdown)
    {
        let md_path = outcome.output_dir.join("bugs.md");
        let md = bug_report::render_markdown(&bug_report);
        write_text(&md_path, &md).await?;

        let gaps_md_path = outcome.output_dir.join("coverage-gaps.md");
        let gaps_md = coverage_gap::render_markdown(&outcome.coverage_gaps);
        write_text(&gaps_md_path, &gaps_md).await?;
    }

    Ok(())
}

pub async fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value).context("serialize json")?;
    write_bytes_atomic(path, &data).await?;
    Ok(())
}

pub async fn write_text(path: &Path, text: &str) -> Result<()> {
    write_bytes_atomic(path, text.as_bytes()).await?;
    Ok(())
}

pub(crate) async fn write_bytes_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, data)
        .await
        .with_context(|| format!("write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn write_json_creates_missing_parent_directories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out = tmp
            .path()
            .join("nested")
            .join("reports")
            .join("test-impact.json");

        super::write_json(&out, &serde_json::json!({"ok": true}))
            .await
            .expect("write json");

        assert!(out.is_file());
    }
}
