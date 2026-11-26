//! Source locations for controls (via `code_link`) and git metadata.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::code_link::runtime_source::{
    FileLine, ResolvedSource, SourceQuery, resolve_runtime_sources,
};
use crate::code_link::static_source::{StaticQuery, link_static_sources};
use crate::types::dom::{ElementSourceCapture, SourceFrame};

use super::GitInfo;

/// What we know about one control for source linking.
#[derive(Debug, Clone, Default)]
pub(super) struct SourceInput {
    pub key: String,
    pub route: String,
    /// Browser-captured evidence and the page it was captured on.
    pub capture: Option<(ElementSourceCapture, String)>,
    pub tag: String,
    pub label: Option<String>,
    pub aria_label: Option<String>,
    pub test_id: Option<String>,
    pub element_id: Option<String>,
    pub name: Option<String>,
    pub href: Option<String>,
    /// File that defines the control's route (route discovery).
    pub route_file: Option<String>,
}

/// Runtime captures first (dev server must still be up), static matching for
/// everything left. Failures degrade to fewer links, never an error.
pub(super) async fn resolve(
    target_url: &str,
    codebase: &Path,
    inputs: &[SourceInput],
) -> BTreeMap<String, ResolvedSource> {
    let runtime_queries: Vec<SourceQuery> = inputs
        .iter()
        .filter_map(|i| {
            i.capture.as_ref().map(|(capture, page_url)| SourceQuery {
                key: i.key.clone(),
                capture: capture.clone(),
                page_url: page_url.clone(),
            })
        })
        .collect();
    let mut out = if runtime_queries.is_empty() {
        BTreeMap::new()
    } else {
        match resolve_runtime_sources(target_url, codebase, &runtime_queries).await {
            Ok(map) => map,
            Err(err) => {
                tracing::warn!("runtime source resolution failed: {err:#}");
                BTreeMap::new()
            }
        }
    };

    let static_queries: Vec<StaticQuery> = inputs
        .iter()
        .filter(|i| !out.contains_key(&i.key))
        .map(|i| StaticQuery {
            key: i.key.clone(),
            route: i.route.clone(),
            tag: i.tag.clone(),
            label: i.label.clone(),
            aria_label: i.aria_label.clone(),
            test_id: i.test_id.clone(),
            element_id: i.element_id.clone(),
            name: i.name.clone(),
            href: i.href.clone(),
            placeholder: None,
            route_file: i.route_file.clone(),
        })
        .collect();
    if !static_queries.is_empty() {
        match link_static_sources(codebase, &static_queries) {
            Ok(map) => {
                for (k, v) in map {
                    out.entry(k).or_insert(v);
                }
            }
            Err(err) => tracing::warn!("static source linking failed: {err:#}"),
        }
    }
    out
}

/// Map error stack positions (`url`, line, col as served by the dev server)
/// to repo `file:line` through source maps. The dev server must be up;
/// unresolvable positions are left out.
pub(super) async fn resolve_error_frames(
    target_url: &str,
    codebase: &Path,
    frames: &[(String, u32, u32)],
) -> BTreeMap<(String, u32, u32), FileLine> {
    if frames.is_empty() {
        return BTreeMap::new();
    }
    let queries: Vec<SourceQuery> = frames
        .iter()
        .enumerate()
        .map(|(i, (url, line, col))| SourceQuery {
            key: i.to_string(),
            capture: ElementSourceCapture {
                frames: vec![SourceFrame {
                    role: "render".to_string(),
                    url: url.clone(),
                    line: *line,
                    col: *col,
                    ..Default::default()
                }],
                ..Default::default()
            },
            page_url: target_url.to_string(),
        })
        .collect();
    let resolved = match resolve_runtime_sources(target_url, codebase, &queries).await {
        Ok(map) => map,
        Err(err) => {
            tracing::warn!("error frame resolution failed: {err:#}");
            return BTreeMap::new();
        }
    };
    frames
        .iter()
        .enumerate()
        .filter_map(|(i, frame)| {
            let src = resolved.get(&i.to_string())?;
            let at = src.render.clone().or_else(|| src.caller.clone())?;
            Some((frame.clone(), at))
        })
        .collect()
}

/// Commit, branch, and dirty flag of the repo containing `dir`, if any.
pub(super) fn git_info(dir: &Path) -> Option<GitInfo> {
    let commit = git(dir, &["rev-parse", "HEAD"])?;
    let branch = git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]).filter(|b| b != "HEAD");
    let dirty =
        git(dir, &["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
    Some(GitInfo {
        commit,
        branch,
        dirty,
    })
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
