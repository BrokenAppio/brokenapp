use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::BrokenAppConfig;
use crate::explorer::coverage::CoverageGap;
use crate::explorer::template_sampler::TemplateSampler;
use crate::types::api::ApiEndpoint;
use crate::types::bugs::Bug;
use crate::types::dom::{InteractionRef, LocatorStrategy};
use crate::types::graph::{AppView, TransitionType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    #[serde(
        rename = "$schema",
        default = "crate::output::schema::scan_checkpoint_v1"
    )]
    pub schema: String,
    pub version: u32,
    pub saved_at: DateTime<Utc>,
    pub started_at: DateTime<Utc>,
    pub config: BrokenAppConfig,

    pub queue: Vec<QueuedUrl>,
    pub queued_urls: Vec<String>,

    pub visited_fingerprints: Vec<String>,
    pub fingerprint_to_view: HashMap<String, String>,
    pub url_to_view: HashMap<String, String>,

    pub views: Vec<AppView>,
    pub pending_transitions: Vec<PendingTransition>,

    /// Nav dropdown triggers (by `view_id::selector`) that were successfully expanded.
    /// Used to avoid false-positive coverage gaps on resume.
    #[serde(default)]
    pub expanded_nav_dropdown_triggers: Vec<String>,

    #[serde(default)]
    pub template_sampler: TemplateSampler,

    pub endpoints: Vec<ApiEndpoint>,
    pub bugs: Vec<Bug>,

    pub elements_discovered: usize,
    pub elements_interacted: usize,

    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGap>,

    /// Crawl continuation state (resume of long, multi-tab crawls). Absent
    /// in older checkpoints; every field defaults to empty.
    #[serde(default, skip_serializing_if = "CrawlResumeState::is_empty")]
    pub crawl: CrawlResumeState,

    #[serde(default)]
    pub integrity: CheckpointIntegrity,
}

/// What a resumed crawl needs to continue like an uninterrupted one.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CrawlResumeState {
    /// Seconds spent crawling so far (all runs; stopped time excluded).
    #[serde(default)]
    pub crawl_seconds: u64,
    /// Times the scan was resumed.
    #[serde(default)]
    pub resumes: u32,
    /// Seeded routes and where they came from (seeded-route coverage gaps).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub seeded_route_sources: std::collections::BTreeMap<String, Vec<String>>,
    /// URLs navigation was attempted for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempted_urls: Vec<String>,
    /// URLs whose navigation failed once and were requeued for their retry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub navigation_retries: Vec<String>,
    /// Controls exercised already (control identity -> view), so a resumed
    /// crawl records them `exercised_elsewhere` instead of clicking again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exercised_controls: Vec<ExercisedControlEntry>,
    /// Concrete paths explored per route template, in visit order.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub template_instances: std::collections::BTreeMap<String, Vec<String>>,
    /// Auth session history (re-logins, expiry), as in `scan-run.json`.
    #[serde(
        default,
        skip_serializing_if = "crate::explorer::run_report::SessionLog::is_empty"
    )]
    pub session: crate::explorer::run_report::SessionLog,
}

impl CrawlResumeState {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// One entry of the scan-wide exercised-controls memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExercisedControlEntry {
    pub key: String,
    pub view_id: String,
    #[serde(default)]
    pub navigated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedUrl {
    pub url: String,
    pub depth: usize,
    /// 0 = nav-discovered (high priority), 100 = default.
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_priority() -> i32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransition {
    pub from_view: String,
    pub trigger: InteractionRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trigger_locators: Vec<LocatorStrategy>,
    pub transition_type: TransitionType,
    pub target_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckpointIntegrity {
    #[serde(default)]
    pub hash_algorithm: String,
    #[serde(default)]
    pub state_hash: String,
}

pub struct CheckpointWriter {
    path: PathBuf,
    interval: Duration,
    last_saved_at: Instant,
}

impl CheckpointWriter {
    pub fn new(path: PathBuf, interval_seconds: u64) -> Self {
        Self {
            path,
            interval: Duration::from_secs(interval_seconds.max(1)),
            last_saved_at: Instant::now(),
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn due(&self) -> bool {
        self.last_saved_at.elapsed() >= self.interval
    }

    pub async fn maybe_save(&mut self, checkpoint: &ScanCheckpoint) -> Result<()> {
        if !self.due() {
            return Ok(());
        }
        self.save(checkpoint).await?;
        Ok(())
    }

    pub async fn save(&mut self, checkpoint: &ScanCheckpoint) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(checkpoint).context("serialize checkpoint")?;
        tokio::fs::write(&tmp, data)
            .await
            .with_context(|| format!("write {}", tmp.display()))?;
        tokio::fs::rename(&tmp, &self.path)
            .await
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        self.last_saved_at = Instant::now();
        Ok(())
    }
}

pub async fn load_checkpoint(path: impl AsRef<Path>) -> Result<ScanCheckpoint> {
    let path = path.as_ref();
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    let cp: ScanCheckpoint = serde_json::from_str(&raw).context("parse checkpoint")?;
    if cp.version < 2 {
        anyhow::bail!(
            "checkpoint version {} is not resume-safe; re-run a fresh scan to create a v2 checkpoint",
            cp.version
        );
    }
    if cp.integrity.hash_algorithm != "blake3" {
        anyhow::bail!(
            "checkpoint integrity hash algorithm mismatch: expected blake3, got {:?}",
            cp.integrity.hash_algorithm
        );
    }
    if cp.integrity.state_hash.trim().is_empty() {
        anyhow::bail!("checkpoint missing integrity state_hash");
    }
    let expected = state_hash_for_checkpoint(&cp).context("compute checkpoint integrity hash")?;
    if expected != cp.integrity.state_hash
        && legacy_state_hash(&cp).ok().as_deref() != Some(cp.integrity.state_hash.as_str())
    {
        anyhow::bail!(
            "checkpoint integrity verification failed (expected {}, got {})",
            expected,
            cp.integrity.state_hash
        );
    }
    Ok(cp)
}

fn crawl_state_is_empty(crawl: &&CrawlResumeState) -> bool {
    crawl.is_empty()
}

pub fn state_hash_for_checkpoint(cp: &ScanCheckpoint) -> Result<String> {
    #[derive(Serialize)]
    struct HashInput<'a> {
        version: u32,
        started_at: chrono::DateTime<chrono::Utc>,
        config: &'a BrokenAppConfig,
        queue: &'a [QueuedUrl],
        queued_urls: &'a [String],
        visited_fingerprints: &'a [String],
        fingerprint_to_view: &'a HashMap<String, String>,
        url_to_view: &'a HashMap<String, String>,
        views: &'a [AppView],
        pending_transitions: &'a [PendingTransition],
        template_sampler: &'a TemplateSampler,
        endpoints: &'a [ApiEndpoint],
        bugs: &'a [Bug],
        elements_discovered: usize,
        elements_interacted: usize,
        coverage_gaps: &'a [CoverageGap],
        // Omitted when empty, so checkpoints written before it existed
        // still verify.
        #[serde(skip_serializing_if = "crawl_state_is_empty")]
        crawl: &'a CrawlResumeState,
    }

    let input = HashInput {
        version: cp.version,
        started_at: cp.started_at,
        config: &cp.config,
        queue: &cp.queue,
        queued_urls: &cp.queued_urls,
        visited_fingerprints: &cp.visited_fingerprints,
        fingerprint_to_view: &cp.fingerprint_to_view,
        url_to_view: &cp.url_to_view,
        views: &cp.views,
        pending_transitions: &cp.pending_transitions,
        template_sampler: &cp.template_sampler,
        endpoints: &cp.endpoints,
        bugs: &cp.bugs,
        elements_discovered: cp.elements_discovered,
        elements_interacted: cp.elements_interacted,
        coverage_gaps: &cp.coverage_gaps,
        crawl: &cp.crawl,
    };
    // Canonical JSON (object keys sorted): the hash maps in the state
    // (`fingerprint_to_view`, template sampling) serialize in a different
    // order in every process, so hashing their raw serialization made a
    // checkpoint fail verification when another process resumed it.
    let value = serde_json::to_value(&input).context("serialize checkpoint hash input")?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)?;
    let h = blake3::hash(&bytes).to_hex().to_string();
    Ok(h)
}

/// The hash of checkpoints written before the hash input was canonical
/// (correct only when the process that verifies it iterates its hash maps
/// in the same order as the one that wrote it).
fn legacy_state_hash(cp: &ScanCheckpoint) -> Result<String> {
    #[derive(Serialize)]
    struct LegacyInput<'a> {
        version: u32,
        started_at: chrono::DateTime<chrono::Utc>,
        config: &'a BrokenAppConfig,
        queue: &'a [QueuedUrl],
        queued_urls: &'a [String],
        visited_fingerprints: &'a [String],
        fingerprint_to_view: &'a HashMap<String, String>,
        url_to_view: &'a HashMap<String, String>,
        views: &'a [AppView],
        pending_transitions: &'a [PendingTransition],
        template_sampler: &'a TemplateSampler,
        endpoints: &'a [ApiEndpoint],
        bugs: &'a [Bug],
        elements_discovered: usize,
        elements_interacted: usize,
        coverage_gaps: &'a [CoverageGap],
    }
    let input = LegacyInput {
        version: cp.version,
        started_at: cp.started_at,
        config: &cp.config,
        queue: &cp.queue,
        queued_urls: &cp.queued_urls,
        visited_fingerprints: &cp.visited_fingerprints,
        fingerprint_to_view: &cp.fingerprint_to_view,
        url_to_view: &cp.url_to_view,
        views: &cp.views,
        pending_transitions: &cp.pending_transitions,
        template_sampler: &cp.template_sampler,
        endpoints: &cp.endpoints,
        bugs: &cp.bugs,
        elements_discovered: cp.elements_discovered,
        elements_interacted: cp.elements_interacted,
        coverage_gaps: &cp.coverage_gaps,
    };
    let bytes = serde_json::to_vec(&input).context("serialize legacy hash input")?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// JSON with object keys in sorted order (arrays keep their order).
fn write_canonical_json(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)?;
                out.push(b':');
                write_canonical_json(&map[key], out)?;
            }
            out.push(b'}');
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        scalar => serde_json::to_writer(&mut *out, scalar)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_endpoint_metrics_keep_integrity_after_persistence() {
        let mut cp: ScanCheckpoint = serde_json::from_value(serde_json::json!({
            "version": 2,
            "saved_at": "2026-10-22T00:00:00Z",
            "started_at": "2026-10-22T00:00:00Z",
            "config": {"target": {"url": "http://127.0.0.1/"}},
            "queue": [], "queued_urls": [], "visited_fingerprints": [],
            "fingerprint_to_view": {}, "url_to_view": {},
            "views": [], "pending_transitions": [], "endpoints": [], "bugs": [],
            "elements_discovered": 1, "elements_interacted": 1
        }))
        .unwrap();
        let mut endpoint: ApiEndpoint = serde_json::from_value(serde_json::json!({
            "key": {"method": "GET", "path_template": "/api/status"},
            "url_pattern": "http://127.0.0.1/api/status"
        }))
        .unwrap();
        // Runtime timing averages can have this precision. Without
        // serde_json's float_roundtrip parser this became 255.109085 on
        // reload, invalidating the hash even though the file was intact.
        endpoint.avg_response_time_ms = 255.10908500000002;
        cp.endpoints.push(endpoint);
        cp.integrity = CheckpointIntegrity {
            hash_algorithm: "blake3".into(),
            state_hash: state_hash_for_checkpoint(&cp).unwrap(),
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("checkpoint.json");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut writer = CheckpointWriter::new(path.clone(), 1);
        rt.block_on(writer.save(&cp)).unwrap();
        let loaded = rt
            .block_on(load_checkpoint(&path))
            .expect("fractional timing survives actual checkpoint persistence");
        assert_eq!(
            loaded.endpoints[0].avg_response_time_ms.to_bits(),
            cp.endpoints[0].avg_response_time_ms.to_bits()
        );

        cp.endpoints[0].avg_response_time_ms += 1.0;
        rt.block_on(writer.save(&cp)).unwrap();
        assert!(
            rt.block_on(load_checkpoint(&path)).is_err(),
            "a changed metric must still fail integrity verification"
        );
    }

    #[test]
    fn integrity_hash_does_not_depend_on_hash_map_order() {
        let cfg: BrokenAppConfig =
            toml::from_str("[target]\nurl = \"http://127.0.0.1:47280/\"\n").unwrap();
        let mut cp = ScanCheckpoint {
            schema: crate::output::schema::scan_checkpoint_v1(),
            version: 2,
            saved_at: chrono::Utc::now(),
            started_at: chrono::Utc::now(),
            config: cfg,
            queue: vec![],
            queued_urls: vec![],
            visited_fingerprints: vec![],
            fingerprint_to_view: HashMap::new(),
            url_to_view: HashMap::new(),
            views: vec![],
            pending_transitions: vec![],
            expanded_nav_dropdown_triggers: vec![],
            template_sampler: TemplateSampler::default(),
            endpoints: vec![],
            bugs: vec![],
            elements_discovered: 0,
            elements_interacted: 0,
            coverage_gaps: vec![],
            crawl: CrawlResumeState::default(),
            integrity: CheckpointIntegrity::default(),
        };
        for i in 0..64 {
            cp.fingerprint_to_view
                .insert(format!("key-{i}"), format!("view_{i:04}"));
            cp.url_to_view.insert(
                format!("http://127.0.0.1:47280/p{i}"),
                format!("view_{i:04}"),
            );
        }
        let hash = state_hash_for_checkpoint(&cp).unwrap();
        // The same state with maps built in another order (as a resuming
        // process deserializes them) hashes the same.
        let mut reordered = cp.clone();
        let mut pairs: Vec<(String, String)> = cp
            .fingerprint_to_view
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        pairs.sort();
        pairs.reverse();
        reordered.fingerprint_to_view = pairs.into_iter().collect();
        reordered.url_to_view =
            serde_json::from_str(&serde_json::to_string(&cp.url_to_view).unwrap()).unwrap();
        assert_eq!(state_hash_for_checkpoint(&reordered).unwrap(), hash);

        cp.integrity = CheckpointIntegrity {
            hash_algorithm: "blake3".to_string(),
            state_hash: hash,
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("checkpoint.json");
        std::fs::write(&path, serde_json::to_vec(&cp).unwrap()).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(load_checkpoint(&path))
            .expect("verifies after a round trip");

        // Tampering is still detected.
        cp.elements_discovered = 99;
        std::fs::write(&path, serde_json::to_vec(&cp).unwrap()).unwrap();
        assert!(rt.block_on(load_checkpoint(&path)).is_err());
    }

    #[test]
    fn legacy_hashes_still_verify() {
        let cfg: BrokenAppConfig =
            toml::from_str("[target]\nurl = \"http://127.0.0.1:47280/\"\n").unwrap();
        let mut cp = ScanCheckpoint {
            schema: crate::output::schema::scan_checkpoint_v1(),
            version: 2,
            saved_at: chrono::Utc::now(),
            started_at: chrono::Utc::now(),
            config: cfg,
            queue: vec![QueuedUrl {
                url: "http://127.0.0.1:47280/a".into(),
                depth: 1,
                priority: 100,
            }],
            queued_urls: vec![],
            visited_fingerprints: vec![],
            fingerprint_to_view: HashMap::from([("k".to_string(), "view_0001".to_string())]),
            url_to_view: HashMap::new(),
            views: vec![],
            pending_transitions: vec![],
            expanded_nav_dropdown_triggers: vec![],
            template_sampler: TemplateSampler::default(),
            endpoints: vec![],
            bugs: vec![],
            elements_discovered: 3,
            elements_interacted: 1,
            coverage_gaps: vec![],
            crawl: CrawlResumeState::default(),
            integrity: CheckpointIntegrity::default(),
        };
        cp.integrity = CheckpointIntegrity {
            hash_algorithm: "blake3".to_string(),
            state_hash: legacy_state_hash(&cp).unwrap(),
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("checkpoint.json");
        std::fs::write(&path, serde_json::to_vec(&cp).unwrap()).unwrap();
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(load_checkpoint(&path))
            .expect("a checkpoint written by an older build verifies");
    }
}
