use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::RouteSensitivityConfig;
use crate::config::ScanConfig;
use crate::explorer::ScanOutcome;
use crate::network::filters::{is_application_api, looks_like_static_asset_path};
use crate::types::api::TrafficEntry;
use crate::types::bugs::{Bug, BugCategory, BugSeverity, RouteContext};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugReport {
    #[serde(rename = "$schema", default = "crate::output::schema::bug_report_v1")]
    pub schema: String,
    pub tool_version: String,
    pub scan_date: String,
    pub target_url: String,
    pub summary: BTreeMap<BugSeverity, usize>,
    pub items: Vec<Bug>,
}

/// Internal profile inferred from post-scan data. Used to recalibrate severity
/// for content sites vs SaaS apps. Not serialized.
#[derive(Debug, Clone)]
struct ScanProfile {
    has_auth: bool,
    form_count: usize,
    api_endpoint_count: usize,
    #[allow(dead_code)]
    view_count: usize,
}

impl ScanProfile {
    fn from_outcome(outcome: &ScanOutcome, has_auth: bool) -> Self {
        let form_count = outcome
            .views
            .iter()
            .flat_map(|v| &v.components)
            .filter(|c| matches!(c, crate::types::classifier::ComponentType::Form { .. }))
            .count();
        let api_endpoint_count = outcome
            .endpoints
            .iter()
            .filter(|ep| is_application_api(ep))
            .count();
        ScanProfile {
            has_auth,
            form_count,
            api_endpoint_count,
            view_count: outcome.views.len(),
        }
    }

    fn is_content_site(&self) -> bool {
        !self.has_auth && self.form_count == 0 && self.api_endpoint_count < 3
    }
}

pub fn generate_bug_report(
    outcome: &ScanOutcome,
    scan_cfg: &ScanConfig,
    has_auth: bool,
    min_confidence: Option<f64>,
) -> BugReport {
    let profile = ScanProfile::from_outcome(outcome, has_auth);
    let mut summary: BTreeMap<BugSeverity, usize> = BTreeMap::new();
    let mut items = refine_bug_findings(&outcome.bugs, scan_cfg, &profile);

    enrich_bug_evidence(&mut items, outcome.network_log_path.as_deref());

    // Post-scan contrast pass on ComponentVisualProfile data.
    if scan_cfg.accessibility.enabled {
        augment_with_visual_profile_contrast(outcome, &mut items);
    }

    // Run a11y collapse AFTER augmentation so newly added contrast findings get collapsed too.
    collapse_repeated_a11y_findings(&mut items, scan_cfg.accessibility.collapse_threshold);

    adjust_confidence_scores(&mut items);

    // Route-context severity promotion/demotion.
    // AppView does not currently have a `requires_auth` field, so pass empty.
    let auth_required_urls: Vec<String> = Vec::new();
    apply_route_context_severity(&mut items, &scan_cfg.route_sensitivity, &auth_required_urls);

    // Apply minimum confidence filter after all augmentation/adjustment passes.
    if let Some(min_conf) = min_confidence {
        items.retain(|b| b.confidence.unwrap_or(1.0) >= min_conf);
    }

    for b in &mut items {
        *summary.entry(b.severity).or_insert(0) += 1;
    }

    BugReport {
        schema: crate::output::schema::bug_report_v1(),
        tool_version: env!("BROKENAPP_BUILD_VERSION").to_string(),
        scan_date: outcome.started_at.to_rfc3339(),
        target_url: outcome.target_url.clone(),
        summary,
        items,
    }
}

fn enrich_bug_evidence(bugs: &mut [Bug], network_log_path: Option<&Path>) {
    let network_index = network_log_path.and_then(build_network_index);
    for bug in bugs {
        fill_reproduction_steps(bug);
        if let Some(index) = network_index.as_ref() {
            attach_network_evidence(bug, index);
        }
    }
}

fn fill_reproduction_steps(bug: &mut Bug) {
    if !bug.reproduction.is_empty() {
        return;
    }

    let mut steps = Vec::new();
    if let Some(url) = bug.location.url.as_deref() {
        steps.push(format!("Visit {url}"));
    }

    match &bug.category {
        BugCategory::BrokenLink { url, .. } => {
            steps.push(format!("Navigate to {url}"));
        }
        BugCategory::AssetLoadFailure { url, .. } => {
            steps.push(format!("Load a page that references {url}"));
            steps.push("Observe the asset request failing in the browser network log".to_string());
        }
        BugCategory::DeadButton {
            selector,
            precondition_hint,
            ..
        } => {
            steps.push(format!("Click {selector}"));
            if let Some(hint) = precondition_hint {
                steps.push(format!("Satisfy precondition: {hint}"));
            }
        }
        BugCategory::ServerError { endpoint, .. } => {
            steps.push(format!("Trigger a request to {endpoint}"));
        }
        BugCategory::ApiError { endpoint, .. } => {
            steps.push(format!("Trigger the UI action that calls {endpoint}"));
            steps.push("Observe the API error response in the browser network log".to_string());
        }
        BugCategory::NetworkRequestFailure { endpoint, .. } => {
            steps.push(format!("Trigger the UI action that requests {endpoint}"));
            steps.push("Observe the browser network failure".to_string());
        }
        BugCategory::CorsError { endpoint } => {
            steps.push(format!("Trigger a request to {endpoint} from the browser"));
            steps.push("Observe a CORS error in the console or network panel".to_string());
        }
        BugCategory::MixedContent { insecure_url } => {
            steps.push(format!(
                "Observe blocked insecure request to {insecure_url}"
            ));
        }
        BugCategory::InconsistentApiResponse { endpoint, .. } => {
            steps.push(format!("Call {endpoint} multiple times"));
            steps.push("Compare response shapes for inconsistencies".to_string());
        }
        BugCategory::OrphanedRoute { url } => {
            steps.push(format!("Navigate to {url}"));
            steps.push("Observe a missing or error page".to_string());
        }
        BugCategory::ConsoleError { .. } => {
            if let Some(url) = bug.location.url.as_deref() {
                steps.push(format!("Observe console errors on {url}"));
            }
        }
        BugCategory::UnexpectedRedirect {
            requested_url,
            landed_url,
            ..
        } => {
            steps.push(format!("Navigate to {requested_url}"));
            steps.push(format!("Observe redirect to {landed_url}"));
        }
        BugCategory::PerformanceIssue {
            metric, threshold, ..
        } => {
            steps.push(format!("Observe {metric} above {threshold}"));
        }
        BugCategory::UiErrorToast { message, .. } => {
            if let Some(el) = bug.location.element.as_deref() {
                steps.push(format!("Interact with {el}"));
            }
            steps.push(format!("Observe error toast/alert: {message}"));
        }
        BugCategory::WebSocketError { endpoint, message } => {
            if let Some(el) = bug.location.element.as_deref() {
                steps.push(format!("Interact with {el}"));
            }
            steps.push(format!("Observe WebSocket error on {endpoint}: {message}"));
        }
        _ => {}
    }

    if !steps.is_empty() {
        bug.reproduction = steps;
    }
}

#[derive(Default)]
struct NetworkEvidenceIndex {
    by_url: HashMap<(String, u16), Vec<TrafficEntry>>,
    by_path: HashMap<(String, u16), Vec<TrafficEntry>>,
    by_url_any: HashMap<String, Vec<TrafficEntry>>,
    by_path_any: HashMap<String, Vec<TrafficEntry>>,
    by_action_id: HashMap<String, Vec<TrafficEntry>>,
    by_interaction: HashMap<(String, String), Vec<TrafficEntry>>,
}

fn build_network_index(path: &Path) -> Option<NetworkEvidenceIndex> {
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let mut index = NetworkEvidenceIndex::default();

    const MAX_ENTRIES: usize = 5000;
    let mut seen = 0usize;

    for line in reader.lines().flatten() {
        if seen >= MAX_ENTRIES {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: TrafficEntry = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(resp) = entry.response.as_ref() else {
            continue;
        };

        let url = entry.request.url.clone();
        let status = resp.status;
        push_limited(&mut index.by_url, (url.clone(), status), entry.clone());
        if let Ok(parsed) = Url::parse(&url) {
            let path_key = parsed.path().to_string();
            push_limited(&mut index.by_path, (path_key, status), entry.clone());
        }

        push_limited_any(&mut index.by_url_any, url.clone(), entry.clone());
        if let Ok(parsed) = Url::parse(&url) {
            let path_key = parsed.path().to_string();
            push_limited_any(&mut index.by_path_any, path_key, entry.clone());
        }

        if let Some(ref trace) = entry.trace {
            if let Some(ref action_id) = trace.action_id {
                push_limited_any(&mut index.by_action_id, action_id.clone(), entry.clone());
            }
        }
        if let Some(ref triggered) = entry.triggered_by {
            push_limited_any(
                &mut index.by_interaction,
                (triggered.view.clone(), triggered.selector.clone()),
                entry.clone(),
            );
        }

        seen += 1;
    }

    Some(index)
}

fn push_limited(
    map: &mut HashMap<(String, u16), Vec<TrafficEntry>>,
    key: (String, u16),
    entry: TrafficEntry,
) {
    let slot = map.entry(key).or_default();
    if slot.len() < 3 {
        slot.push(entry);
    }
}

fn push_limited_any<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, Vec<TrafficEntry>>,
    key: K,
    entry: TrafficEntry,
) {
    let slot = map.entry(key).or_default();
    if slot.len() < 3 {
        slot.push(entry);
    }
}

fn attach_network_evidence(bug: &mut Bug, index: &NetworkEvidenceIndex) {
    if !bug.evidence.network_log.is_empty() {
        return;
    }

    let mut entries: Option<Vec<TrafficEntry>> = None;
    match &bug.category {
        BugCategory::BrokenLink { url, status } => {
            entries = lookup_network_entries(index, url, Some(*status))
                .or_else(|| lookup_network_entries(index, url, None));
        }
        BugCategory::AssetLoadFailure { url, status } => {
            entries = lookup_network_entries(index, url, Some(*status))
                .or_else(|| lookup_network_entries(index, url, None));
        }
        BugCategory::ServerError {
            endpoint, status, ..
        } => {
            entries = lookup_network_entries(index, endpoint, Some(*status))
                .or_else(|| lookup_network_entries(index, endpoint, None));
        }
        BugCategory::ApiError {
            endpoint, status, ..
        } => {
            entries = lookup_network_entries(index, endpoint, Some(*status))
                .or_else(|| lookup_network_entries(index, endpoint, None));
        }
        BugCategory::NetworkRequestFailure { endpoint, .. } => {
            entries = lookup_network_entries(index, endpoint, None);
        }
        BugCategory::DeadButton { selector, .. } => {
            let mut collected: Vec<TrafficEntry> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            if !bug.evidence.action_ids.is_empty() {
                for action_id in &bug.evidence.action_ids {
                    if let Some(v) = index.by_action_id.get(action_id) {
                        extend_unique(&mut collected, &mut seen, v, 3);
                    }
                }
            }

            if collected.is_empty() {
                if let Some(view) = bug.location.view.as_ref() {
                    if let Some(v) = index.by_interaction.get(&(view.clone(), selector.clone())) {
                        extend_unique(&mut collected, &mut seen, v, 3);
                    }
                }
            }

            if !collected.is_empty() {
                entries = Some(collected);
            }
        }
        BugCategory::CorsError { endpoint } => {
            entries = lookup_network_entries(index, endpoint, None);
        }
        BugCategory::MixedContent { insecure_url } => {
            entries = lookup_network_entries(index, insecure_url, None);
        }
        BugCategory::InconsistentApiResponse { endpoint, .. } => {
            entries = lookup_network_entries(index, endpoint, None);
        }
        BugCategory::OrphanedRoute { url } => {
            entries = lookup_network_entries_statuses(index, url, &[404, 410])
                .or_else(|| lookup_network_entries(index, url, None));
        }
        BugCategory::UnexpectedRedirect { requested_url, .. } => {
            entries =
                lookup_network_entries_statuses(index, requested_url, &[301, 302, 303, 307, 308])
                    .or_else(|| lookup_network_entries(index, requested_url, None));
        }
        _ => {}
    }

    if let Some(entries) = entries {
        bug.evidence.network_log = entries;
    }
}

fn lookup_network_entries(
    index: &NetworkEvidenceIndex,
    raw: &str,
    status: Option<u16>,
) -> Option<Vec<TrafficEntry>> {
    if raw.is_empty() {
        return None;
    }
    if let Some(code) = status {
        if let Some(v) = index.by_url.get(&(raw.to_string(), code)) {
            return Some(v.clone());
        }
        let path = if raw.starts_with("http://") || raw.starts_with("https://") {
            Url::parse(raw).ok().map(|u| u.path().to_string())
        } else {
            Some(raw.to_string())
        };
        if let Some(p) = path {
            if let Some(v) = index.by_path.get(&(p, code)) {
                return Some(v.clone());
            }
        }
        return None;
    }

    if let Some(v) = index.by_url_any.get(raw) {
        return Some(v.clone());
    }
    let path = if raw.starts_with("http://") || raw.starts_with("https://") {
        Url::parse(raw).ok().map(|u| u.path().to_string())
    } else {
        Some(raw.to_string())
    };
    if let Some(p) = path {
        if let Some(v) = index.by_path_any.get(&p) {
            return Some(v.clone());
        }
    }
    None
}

fn extend_unique(
    out: &mut Vec<TrafficEntry>,
    seen: &mut HashSet<String>,
    entries: &[TrafficEntry],
    max_total: usize,
) {
    for entry in entries {
        if out.len() >= max_total {
            break;
        }
        let key = if let Some(ref trace) = entry.trace {
            trace.trace_id.clone()
        } else {
            format!(
                "{}:{}",
                entry.request.url,
                entry.response.as_ref().map(|r| r.status).unwrap_or(0)
            )
        };
        if seen.insert(key) {
            out.push(entry.clone());
        }
    }
}

fn lookup_network_entries_statuses(
    index: &NetworkEvidenceIndex,
    raw: &str,
    statuses: &[u16],
) -> Option<Vec<TrafficEntry>> {
    for status in statuses {
        if let Some(v) = lookup_network_entries(index, raw, Some(*status)) {
            return Some(v);
        }
    }
    None
}

fn refine_bug_findings(raw: &[Bug], scan_cfg: &ScanConfig, profile: &ScanProfile) -> Vec<Bug> {
    let mut bugs = raw.to_vec();
    suppress_scanner_runtime_findings(&mut bugs);
    recalibrate_for_scan_profile(&mut bugs, profile);
    calibrate_server_error_severity(&mut bugs);
    correlate_console_errors_with_server_errors(&mut bugs);
    suppress_known_console_noise(&mut bugs);
    dedupe_exact_console_errors(&mut bugs);
    collapse_repeated_console_errors(&mut bugs, scan_cfg.console_error_group_threshold);
    collapse_orphaned_404_cascades(&mut bugs, 3);
    collapse_stale_entity_404s(&mut bugs, scan_cfg.stale_entity_404_group_threshold);
    apply_infrastructure_502_rules(
        &mut bugs,
        scan_cfg.ignore_502,
        scan_cfg.infra_502_group_threshold.max(1),
    );
    collapse_dead_buttons(&mut bugs, scan_cfg.dead_button_group_threshold, profile);
    // NOTE: a11y collapse moved to generate_bug_report() so it runs after augmentation
    bugs.sort_by(|a, b| a.id.cmp(&b.id));
    // Final pass: enforce the global invariant that no two emitted findings
    // share a fingerprint (= `finding_key`). The count-based collapse passes
    // above intentionally inspect repeated raw findings to make grouping
    // decisions, so this must run LAST — after they have consumed those
    // repeats. Sorting by id first means we keep the earliest occurrence.
    dedupe_by_fingerprint(&mut bugs);
    bugs
}

/// Drop findings whose content fingerprint duplicates one already kept.
///
/// `fingerprint_bug` is the canonical defect identity used by baseline
/// comparison and exposed to agents as `finding_key`. Two findings with the
/// same fingerprint denote the *same* defect (e.g. two requests to one
/// endpoint that both 500). Emitting both would collide on `finding_key` —
/// breaking `fix-packet --key` lookups — and inflate severity counts. Keeps
/// the first occurrence in the current ordering.
fn dedupe_by_fingerprint(bugs: &mut Vec<Bug>) {
    let mut seen: HashSet<String> = HashSet::new();
    bugs.retain(|bug| seen.insert(fingerprint_bug(bug)));
}

/// Stable blake3 fingerprint (32 hex chars) for deduplicating findings.
pub fn fingerprint_bug(bug: &Bug) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(category_discriminant(&bug.category).as_bytes());
    hasher.update(category_key_fields(&bug.category).as_bytes());
    if let Some(ref url) = bug.location.url {
        hasher.update(normalize_url_key(url).as_bytes());
    }
    if let Some(ref element) = bug.location.element {
        let skip_element = matches!(
            &bug.category,
            BugCategory::DeadButton {
                label: Some(lbl), ..
            } if !lbl.trim().is_empty()
        );
        if !skip_element {
            hasher.update(normalize_selector_key(element).as_bytes());
        }
    }
    hasher.finalize().to_hex().as_str()[..32].to_string()
}

fn category_discriminant(cat: &BugCategory) -> &'static str {
    match cat {
        BugCategory::BrokenLink { .. } => "broken_link",
        BugCategory::AssetLoadFailure { .. } => "asset_load_failure",
        BugCategory::DeadButton { .. } => "dead_button",
        BugCategory::ServerError { .. } => "server_error",
        BugCategory::ApiError { .. } => "api_error",
        BugCategory::NetworkRequestFailure { .. } => "network_request_failure",
        BugCategory::ConsoleError { .. } => "console_error",
        BugCategory::CorsError { .. } => "cors_error",
        BugCategory::MixedContent { .. } => "mixed_content",
        BugCategory::InconsistentApiResponse { .. } => "inconsistent_api_response",
        BugCategory::OrphanedRoute { .. } => "orphaned_route",
        BugCategory::PerformanceIssue { .. } => "performance_issue",
        BugCategory::AccessibilityViolation { .. } => "accessibility_violation",
        BugCategory::SecurityObservation { .. } => "security_observation",
        BugCategory::UnexpectedRedirect { .. } => "unexpected_redirect",
        BugCategory::UiErrorToast { .. } => "ui_error_toast",
        BugCategory::WebSocketError { .. } => "websocket_error",
        BugCategory::Other { .. } => "other",
    }
}

fn category_key_fields(cat: &BugCategory) -> String {
    match cat {
        BugCategory::BrokenLink { url, status } => format!("{}:{status}", normalize_url_key(url)),
        BugCategory::AssetLoadFailure { url, status } => {
            format!("{}:{status}", normalize_url_key(url))
        }
        BugCategory::DeadButton {
            selector, label, ..
        } => match label {
            Some(lbl) if !lbl.trim().is_empty() => normalize_free_text(lbl),
            _ => normalize_selector_key(selector),
        },
        BugCategory::ServerError {
            endpoint, status, ..
        } => format!("{}:{status}", normalize_url_key(endpoint)),
        BugCategory::ApiError {
            endpoint, status, ..
        } => format!("{}:{status}", normalize_url_key(endpoint)),
        BugCategory::NetworkRequestFailure { endpoint, failure } => format!(
            "{}:{}",
            normalize_url_key(endpoint),
            normalize_free_text(failure)
        ),
        BugCategory::ConsoleError { message, .. } => normalize_free_text(message),
        BugCategory::CorsError { endpoint } => normalize_url_key(endpoint),
        BugCategory::MixedContent { insecure_url } => normalize_url_key(insecure_url),
        BugCategory::InconsistentApiResponse { endpoint, .. } => normalize_url_key(endpoint),
        BugCategory::OrphanedRoute { url } => normalize_url_key(url),
        BugCategory::PerformanceIssue { metric, .. } => metric.clone(),
        BugCategory::AccessibilityViolation {
            category,
            wcag_criterion,
            impact,
        } => format!("{category}:{wcag_criterion}:{impact:?}"),
        BugCategory::SecurityObservation { description } => normalize_free_text(description),
        BugCategory::UnexpectedRedirect {
            requested_url,
            landed_url,
            redirect_kind,
        } => format!(
            "{}:{}:{redirect_kind}",
            normalize_url_key(requested_url),
            normalize_url_key(landed_url)
        ),
        BugCategory::UiErrorToast { message, .. } => normalize_free_text(message),
        BugCategory::WebSocketError { endpoint, message } => format!(
            "{}:{}",
            normalize_url_key(endpoint),
            normalize_free_text(message)
        ),
        BugCategory::Other { description } => normalize_free_text(description),
    }
}

fn normalize_url_key(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(url) = Url::parse(trimmed) {
        let mut out = String::new();
        if let Some(host) = url.host_str() {
            out.push_str(&host.to_ascii_lowercase());
        }
        out.push_str(&crate::network::path_parameterizer::path_to_template(
            url.path(),
        ));
        return out;
    }
    let path = trimmed
        .split_once(' ')
        .map(|(_, p)| p.trim())
        .unwrap_or(trimmed);
    let path = path.split('#').next().unwrap_or(path);
    let path = path.split('?').next().unwrap_or(path);
    crate::network::path_parameterizer::path_to_template(path)
}

fn normalize_free_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = false;
    for ch in s.chars() {
        let mapped = if ch.is_ascii_alphabetic() {
            ch.to_ascii_lowercase()
        } else if ch.is_ascii_digit() {
            '#'
        } else {
            ' '
        };
        if mapped == ' ' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        out.push(mapped);
        last_space = false;
    }
    out.split_whitespace()
        .take(16)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_selector_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = false;
    for ch in s.chars() {
        let mapped = if ch.is_ascii_alphabetic() {
            ch.to_ascii_lowercase()
        } else if ch.is_ascii_digit() {
            '#'
        } else if ch.is_ascii_whitespace() {
            ' '
        } else if matches!(
            ch,
            '#' | '.' | '[' | ']' | '=' | ':' | '>' | '+' | '~' | '*' | '-' | '_' | '"' | '\''
        ) {
            ch
        } else {
            ' '
        };
        if mapped == ' ' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        out.push(mapped);
        last_space = false;
    }
    out.split_whitespace()
        .take(24)
        .collect::<Vec<_>>()
        .join(" ")
}

fn suppress_scanner_runtime_findings(bugs: &mut Vec<Bug>) {
    let remove: Vec<bool> = bugs.iter().map(is_scanner_runtime_finding).collect();
    if remove.iter().any(|flag| *flag) {
        apply_remove_mask(bugs, &remove);
    }
}

fn is_scanner_runtime_finding(bug: &Bug) -> bool {
    match &bug.category {
        BugCategory::Other { description } => is_scanner_runtime_description(description),
        _ => false,
    }
}

fn is_scanner_runtime_description(description: &str) -> bool {
    [
        "Failed to create browser page:",
        "Page creation timed out after ",
        "Navigation failed:",
        "Page processing failed:",
        "Page processing timed out after ",
    ]
    .iter()
    .any(|prefix| description.starts_with(prefix))
}

fn suppress_known_console_noise(bugs: &mut Vec<Bug>) {
    let remove: Vec<bool> = bugs.iter().map(is_non_actionable_console_error).collect();
    if remove.iter().any(|flag| *flag) {
        apply_remove_mask(bugs, &remove);
    }
}

fn is_non_actionable_console_error(bug: &Bug) -> bool {
    match &bug.category {
        BugCategory::ConsoleError { message, source } => is_non_actionable_console_message(
            message,
            source.as_deref(),
            bug.location.url.as_deref(),
        ),
        _ => false,
    }
}

fn is_non_actionable_console_message(
    message: &str,
    _source: Option<&str>,
    _page_url: Option<&str>,
) -> bool {
    let lower = message.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    if lower.contains("dialogcontent")
        && lower.contains("dialogtitle")
        && lower.contains("screen reader")
    {
        return true;
    }

    let noisy_substrings = [
        "initialize guest error",
        "guest error",
        "product recs error",
        "ratings and reviews service",
        "error returned from storelocations",
        "product details availability api",
        "geolocationpositionerror",
        "builder manager",
    ];
    if noisy_substrings.iter().any(|needle| lower.contains(needle)) {
        return true;
    }

    if lower.contains("failed to fetch")
        && [
            "[wall]",
            "product rec",
            "ratings and reviews",
            "storelocations",
            "availability api",
            "builder manager",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }

    if is_generic_failed_fetch_noise(&lower) {
        return true;
    }

    if lower.contains("minified react error #418") {
        return true;
    }

    if lower.contains("unexpected token '<'")
        && lower.contains("<!doctype")
        && lower.contains("not valid json")
    {
        return true;
    }

    lower.contains("getworldposition") && lower.contains("cannot read properties of undefined")
}

fn is_generic_failed_fetch_noise(lower: &str) -> bool {
    if !lower.contains("failed to fetch") {
        return false;
    }

    let headline = lower.lines().next().unwrap_or(lower).trim();

    let actionable_context = [
        "unauthorized",
        "forbidden",
        "401",
        "403",
        "500",
        "502",
        "/api",
        "graphql",
        "endpoint",
        "checkout",
        "payment",
        "order",
        "cart",
        "login",
        "signup",
        "profile",
        "session",
        "auth",
        "upload",
        "download",
        "tool",
    ];
    if actionable_context
        .iter()
        .any(|needle| headline.contains(needle))
    {
        return false;
    }

    headline == "failed to fetch"
        || headline.contains("typeerror: failed to fetch")
        || headline.contains("unhandled promise rejection: failed to fetch")
}

fn is_non_opaque_css_color(color: &str) -> bool {
    let lower = color.trim().to_ascii_lowercase();
    if lower.is_empty() || lower == "transparent" {
        return true;
    }

    let Some(inner) = lower
        .strip_prefix("rgba(")
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };

    inner
        .rsplit(',')
        .next()
        .and_then(|alpha| alpha.trim().parse::<f32>().ok())
        .is_some_and(|alpha| alpha < 1.0)
}

/// On content sites (no auth, no forms, few API endpoints), demote noisy
/// categories that are tuned for SaaS apps. This runs before all other passes.
fn recalibrate_for_scan_profile(bugs: &mut [Bug], profile: &ScanProfile) {
    if !profile.is_content_site() {
        return;
    }
    for bug in bugs.iter_mut() {
        match &bug.category {
            BugCategory::DeadButton { .. } => {
                bug.severity = BugSeverity::Info;
            }
            BugCategory::BrokenLink { url, status } if *status == 404 => {
                let path = Url::parse(url)
                    .map(|u| u.path().to_string())
                    .unwrap_or_else(|_| url.clone());
                if looks_like_static_asset_path(&path) {
                    bug.severity = BugSeverity::Low;
                } else {
                    bug.severity = bug.severity.max(BugSeverity::Medium);
                }
            }
            BugCategory::ConsoleError { .. } => {
                bug.severity = bug.severity.max(BugSeverity::Low);
            }
            _ => {}
        }
    }
}

fn calibrate_server_error_severity(bugs: &mut [Bug]) {
    for bug in bugs {
        if let BugCategory::ServerError { status, .. } = &bug.category {
            bug.severity = match *status {
                500 => BugSeverity::Critical,
                502 => BugSeverity::Info,
                s if s >= 500 => BugSeverity::High,
                _ => bug.severity,
            };
        }
    }
}

fn correlate_console_errors_with_server_errors(bugs: &mut Vec<Bug>) {
    let mut server_paths: Vec<(usize, String)> = Vec::new();
    for (idx, bug) in bugs.iter().enumerate() {
        if let BugCategory::ServerError { endpoint, .. } = &bug.category {
            if let Some(path) = normalize_endpoint_for_match(endpoint) {
                server_paths.push((idx, path));
            }
        }
    }
    if server_paths.is_empty() {
        return;
    }

    let mut remove = vec![false; bugs.len()];
    let mut attachments: Vec<(usize, String)> = Vec::new();
    for (idx, bug) in bugs.iter().enumerate() {
        let BugCategory::ConsoleError { message, .. } = &bug.category else {
            continue;
        };
        let mut candidates = extract_paths_from_message(message);
        if candidates.is_empty() {
            continue;
        }
        candidates.sort();
        candidates.dedup();

        if let Some(server_idx) = best_server_match(&candidates, &server_paths) {
            attachments.push((server_idx, message.clone()));
            remove[idx] = true;
        }
    }

    for (server_idx, message) in attachments {
        if let Some(server_bug) = bugs.get_mut(server_idx) {
            if !server_bug
                .evidence
                .console_log
                .iter()
                .any(|s| s == &message)
            {
                server_bug.evidence.console_log.push(message);
            }
        }
    }
    if remove.iter().any(|v| *v) {
        apply_remove_mask(bugs, &remove);
    }
}

fn collapse_repeated_console_errors(bugs: &mut Vec<Bug>, threshold: usize) {
    if threshold == 0 {
        return;
    }

    #[derive(Default)]
    struct Group {
        indices: Vec<usize>,
        sample_pages: BTreeSet<String>,
        messages: BTreeSet<String>,
        sources: BTreeSet<String>,
    }

    let mut groups: HashMap<String, Group> = HashMap::new();
    for (idx, bug) in bugs.iter().enumerate() {
        let BugCategory::ConsoleError { message, source } = &bug.category else {
            continue;
        };
        let key = console_error_group_key(message, source.as_deref());
        let g = groups.entry(key).or_default();
        g.indices.push(idx);
        g.messages.insert(message.trim().to_string());
        if let Some(src) = source
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            g.sources.insert(src.to_string());
        }
        if let Some(url) = bug.location.url.as_deref() {
            if let Some(path) = normalize_endpoint_for_match(url) {
                g.sample_pages.insert(path);
            } else {
                g.sample_pages.insert(url.to_string());
            }
        }
    }

    if groups.is_empty() {
        return;
    }

    let mut remove = vec![false; bugs.len()];
    for group in groups.into_values() {
        if group.indices.len() <= 1 || group.indices.len() < threshold {
            continue;
        }
        let first_idx = *group.indices.first().unwrap_or(&0);
        if first_idx >= bugs.len() {
            continue;
        }

        let mut aggregate = bugs[first_idx].clone();
        let representative = match &aggregate.category {
            BugCategory::ConsoleError { message, .. } => message.trim(),
            _ => "",
        };
        let message_preview = shorten_console_message(representative);
        let most_severe = group
            .indices
            .iter()
            .filter_map(|idx| bugs.get(*idx).map(|b| b.severity))
            .min()
            .unwrap_or(aggregate.severity);

        aggregate.severity = most_severe;
        aggregate.title = if message_preview.is_empty() {
            format!(
                "Console error repeated across {} views",
                group.indices.len()
            )
        } else {
            format!(
                "Console error repeated across {} views: {}",
                group.indices.len(),
                message_preview
            )
        };
        // Treat this as a cross-view/systemic finding; store the affected pages in the
        // description and keep the location unset so it fingerprints stably.
        aggregate.location.url = None;
        aggregate.location.view = None;
        aggregate.location.element = None;
        aggregate.description = {
            let mut lines = Vec::new();
            lines.push(format!(
                "The same console error was observed **{}** times across multiple views.",
                group.indices.len()
            ));
            lines.push(String::new());
            if !representative.is_empty() {
                lines.push("Representative message:".to_string());
                lines.push(format!("`{}`", representative));
                lines.push(String::new());
            }
            if !group.sources.is_empty() {
                lines.push("Sources observed:".to_string());
                for src in group.sources.iter().take(8) {
                    lines.push(format!("- `{src}`"));
                }
                if group.sources.len() > 8 {
                    lines.push(format!("- ... and {} more", group.sources.len() - 8));
                }
                lines.push(String::new());
            }
            if !group.sample_pages.is_empty() {
                lines.push("Example pages observed:".to_string());
                for path in group.sample_pages.iter().take(12) {
                    lines.push(format!("- `{path}`"));
                }
                if group.sample_pages.len() > 12 {
                    lines.push(format!("- ... and {} more", group.sample_pages.len() - 12));
                }
            }
            lines.join("\n")
        };
        if aggregate.reproduction.is_empty() && !group.sample_pages.is_empty() {
            aggregate.reproduction = group
                .sample_pages
                .iter()
                .take(12)
                .map(|p| format!("Visit {p} and check the browser console."))
                .collect();
        }
        if aggregate.evidence.console_log.is_empty() && !group.messages.is_empty() {
            aggregate.evidence.console_log = group.messages.iter().take(20).cloned().collect();
        }
        bugs[first_idx] = aggregate;

        for idx in group.indices.into_iter().skip(1) {
            if idx < remove.len() {
                remove[idx] = true;
            }
        }
    }

    if remove.iter().any(|v| *v) {
        apply_remove_mask(bugs, &remove);
    }
}

fn dedupe_exact_console_errors(bugs: &mut Vec<Bug>) {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    bugs.retain(|bug| {
        let BugCategory::ConsoleError { message, source } = &bug.category else {
            return true;
        };
        let msg_key = console_error_group_key(message, source.as_deref());
        let url_key = bug.location.url.clone().unwrap_or_default();
        seen.insert((msg_key, url_key))
    });
}

fn shorten_console_message(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for ch in trimmed.chars().take(80) {
        out.push(ch);
    }
    if trimmed.chars().count() > 80 {
        out.push_str("...");
    }
    out
}

fn console_error_group_key(message: &str, source: Option<&str>) -> String {
    let mut key = normalize_console_error_signature(message);
    if let Some(src) = source {
        let s = normalize_console_error_signature(src);
        if !s.is_empty() {
            key.push('|');
            key.push_str(&s);
        }
    }
    key
}

fn normalize_console_error_signature(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    static URL_RE: OnceLock<Regex> = OnceLock::new();
    static UUID_RE: OnceLock<Regex> = OnceLock::new();
    static HEX_RE: OnceLock<Regex> = OnceLock::new();
    let url_re = URL_RE.get_or_init(|| Regex::new(r#"https?://[^\s"'`<>]+"#).expect("url regex"));
    let uuid_re = UUID_RE.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("uuid regex")
    });
    let hex_re = HEX_RE.get_or_init(|| Regex::new(r"(?i)\b[0-9a-f]{8,}\b").expect("hex regex"));

    let scrubbed = url_re.replace_all(trimmed, " <url> ");
    let scrubbed = uuid_re.replace_all(&scrubbed, " <id> ");
    let scrubbed = hex_re.replace_all(&scrubbed, " <id> ");

    let mut out = String::with_capacity(scrubbed.len());
    let mut last_space = false;
    for ch in scrubbed.chars() {
        let mapped = if ch.is_ascii_alphabetic() {
            ch.to_ascii_lowercase()
        } else if ch.is_ascii_digit() {
            '#'
        } else {
            ' '
        };

        if mapped == ' ' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }

        out.push(mapped);
        last_space = false;
    }

    out.split_whitespace()
        .take(24)
        .collect::<Vec<_>>()
        .join(" ")
}

fn best_server_match(console_paths: &[String], server_paths: &[(usize, String)]) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None; // (score, bug_index)
    for console_path in console_paths {
        for (bug_index, server_path) in server_paths {
            let matched = console_path == server_path
                || console_path.contains(server_path)
                || server_path.contains(console_path);
            if !matched {
                continue;
            }
            let score = console_path.len().min(server_path.len());
            match best {
                Some((best_score, _)) if best_score >= score => {}
                _ => best = Some((score, *bug_index)),
            }
        }
    }
    best.map(|(_, idx)| idx)
}

fn collapse_orphaned_404_cascades(bugs: &mut Vec<Bug>, threshold: usize) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut group_paths: HashMap<String, BTreeSet<String>> = HashMap::new();

    for (idx, bug) in bugs.iter().enumerate() {
        let BugCategory::BrokenLink { url, status } = &bug.category else {
            continue;
        };
        if *status != 404 {
            continue;
        }
        let Some((entity_id, path)) = extract_entity_id_and_path(url) else {
            continue;
        };
        groups.entry(entity_id.clone()).or_default().push(idx);
        group_paths.entry(entity_id).or_default().insert(path);
    }
    if groups.is_empty() {
        return;
    }

    let mut remove = vec![false; bugs.len()];
    for (entity_id, indices) in groups {
        if indices.len() < threshold {
            continue;
        }
        let Some(paths) = group_paths.get(&entity_id) else {
            continue;
        };
        if paths.len() < 2 {
            continue;
        }

        let first_idx = indices[0];
        let mut aggregate = bugs[first_idx].clone();
        // This is typically stale data / a dangling reference, not an endpoint-wide outage.
        aggregate.severity = BugSeverity::Low;
        aggregate.category = BugCategory::OrphanedRoute {
            url: format!("/orphaned/entity/eid-{entity_id}"),
        };
        aggregate.title = format!(
            "Orphaned entity {} - {} cascading 404s",
            shorten_entity_id(&entity_id),
            indices.len()
        );
        aggregate.description = {
            let mut lines = Vec::new();
            lines.push(format!(
                "Entity `{entity_id}` appears orphaned. {} related requests returned HTTP 404 across multiple sub-endpoints.",
                indices.len()
            ));
            lines.push(String::new());
            lines.push("Observed sub-endpoints:".to_string());
            for path in paths.iter().take(20) {
                lines.push(format!("- `{path}`"));
            }
            if paths.len() > 20 {
                lines.push(format!("- ... and {} more", paths.len() - 20));
            }
            lines.join("\n")
        };
        aggregate.reproduction = paths
            .iter()
            .take(12)
            .map(|path| format!("GET {path} -> 404"))
            .collect();
        bugs[first_idx] = aggregate;
        for idx in indices.into_iter().skip(1) {
            remove[idx] = true;
        }
    }

    if remove.iter().any(|v| *v) {
        apply_remove_mask(bugs, &remove);
    }
}

fn collapse_stale_entity_404s(bugs: &mut Vec<Bug>, threshold_entity_ids: usize) {
    if threshold_entity_ids == 0 {
        return;
    }

    #[derive(Default)]
    struct Group {
        indices: Vec<usize>,
        entity_ids: BTreeSet<String>,
        sample_paths: BTreeSet<String>,
    }

    let mut groups: HashMap<String, Group> = HashMap::new(); // key = family route (e.g. /api/deals/:id)

    for (idx, bug) in bugs.iter().enumerate() {
        let (entity_id, family_key, sample_path) = match &bug.category {
            BugCategory::BrokenLink { url, status } if *status == 404 => {
                let Some((entity_id, path)) = extract_entity_id_and_path(url) else {
                    continue;
                };
                let Some(family_key) = entity_family_key(&path) else {
                    continue;
                };
                (entity_id, family_key, path)
            }
            BugCategory::OrphanedRoute { .. } => {
                let Some(entity_id) = extract_orphaned_entity_id_from_description(&bug.description)
                else {
                    continue;
                };
                let Some(sample_path) = bug
                    .reproduction
                    .first()
                    .and_then(|line| extract_path_from_reproduction(line))
                else {
                    continue;
                };
                let Some(family_key) = entity_family_key(&sample_path) else {
                    continue;
                };
                (entity_id, family_key, sample_path)
            }
            _ => continue,
        };

        let g = groups.entry(family_key).or_default();
        g.indices.push(idx);
        g.entity_ids.insert(entity_id);
        g.sample_paths.insert(sample_path);
    }

    if groups.is_empty() {
        return;
    }

    let mut remove = vec![false; bugs.len()];
    for (family_key, group) in groups {
        if group.entity_ids.len() < threshold_entity_ids {
            continue;
        }

        let first_idx = *group.indices.first().unwrap_or(&0);
        if first_idx >= bugs.len() {
            continue;
        }

        let mut aggregate = bugs[first_idx].clone();
        aggregate.severity = BugSeverity::Info;
        aggregate.category = BugCategory::Other {
            description: "stale_entity_references_404".to_string(),
        };
        aggregate.title = format!(
            "Stale entity references detected ({} missing entities) on `{}`",
            group.entity_ids.len(),
            family_key
        );
        aggregate.description = {
            let mut lines = Vec::new();
            lines.push(format!(
                "{} distinct entity IDs returned HTTP 404 under the same route family (`{family_key}`).",
                group.entity_ids.len()
            ));
            lines.push(
                "This is commonly caused by stale test data or deleted entities still referenced by the UI.".to_string(),
            );
            lines.push(String::new());
            lines.push("Example missing entity IDs:".to_string());
            for id in group.entity_ids.iter().take(12) {
                lines.push(format!("- `{}`", shorten_entity_id(id)));
            }
            if group.entity_ids.len() > 12 {
                lines.push(format!("- ... and {} more", group.entity_ids.len() - 12));
            }
            lines.push(String::new());
            lines.push("Example 404 paths observed:".to_string());
            for path in group.sample_paths.iter().take(12) {
                lines.push(format!("- `{}`", path));
            }
            if group.sample_paths.len() > 12 {
                lines.push(format!("- ... and {} more", group.sample_paths.len() - 12));
            }
            lines.join("\n")
        };
        aggregate.reproduction = group
            .sample_paths
            .iter()
            .take(12)
            .map(|p| format!("GET {p} -> 404"))
            .collect();
        bugs[first_idx] = aggregate;

        for idx in group.indices.into_iter().skip(1) {
            if idx < remove.len() {
                remove[idx] = true;
            }
        }
    }

    if remove.iter().any(|v| *v) {
        apply_remove_mask(bugs, &remove);
    }
}

fn extract_orphaned_entity_id_from_description(desc: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"Entity `([^`]+)` appears orphaned").expect("regex"));
    let caps = re.captures(desc)?;
    Some(caps.get(1)?.as_str().to_ascii_lowercase())
}

fn extract_path_from_reproduction(line: &str) -> Option<String> {
    // Expected format: "GET /path -> 404"
    let mut parts = line.split_whitespace();
    let _method = parts.next()?;
    let path = parts.next()?;
    if path.trim().is_empty() {
        None
    } else {
        Some(path.trim().to_string())
    }
}

fn entity_family_key(path: &str) -> Option<String> {
    let normalized = normalize_path_for_match(path)?;
    let mut parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    let id_idx = parts.iter().position(|p| *p == ":id")?;
    parts.truncate(id_idx + 1);
    Some(format!("/{}", parts.join("/")))
}

fn apply_infrastructure_502_rules(bugs: &mut Vec<Bug>, ignore_502: bool, infra_threshold: usize) {
    let mut idx_502: Vec<usize> = Vec::new();
    for (idx, bug) in bugs.iter().enumerate() {
        if matches!(bug.category, BugCategory::ServerError { status: 502, .. }) {
            idx_502.push(idx);
        }
    }
    if idx_502.is_empty() {
        return;
    }

    let mut remove = vec![false; bugs.len()];
    if ignore_502 {
        for idx in idx_502 {
            remove[idx] = true;
        }
        apply_remove_mask(bugs, &remove);
        return;
    }

    if idx_502.len() >= infra_threshold && idx_502.len() > 1 {
        let first_idx = idx_502[0];
        let mut endpoints: BTreeSet<String> = BTreeSet::new();
        let mut console_lines: BTreeSet<String> = BTreeSet::new();
        for idx in &idx_502 {
            if let Some(bug) = bugs.get(*idx) {
                if let BugCategory::ServerError { endpoint, .. } = &bug.category {
                    if let Some(path) = normalize_endpoint_for_match(endpoint) {
                        endpoints.insert(path);
                    } else {
                        endpoints.insert(endpoint.clone());
                    }
                }
                for line in &bug.evidence.console_log {
                    console_lines.insert(line.clone());
                }
            }
        }

        let mut aggregate = bugs[first_idx].clone();
        aggregate.severity = BugSeverity::Info;
        aggregate.category = BugCategory::Other {
            description: "infrastructure_gateway_502".to_string(),
        };
        aggregate.title = format!(
            "Gateway instability detected ({} occurrences)",
            idx_502.len()
        );
        let mut description = vec![
            format!(
                "{} HTTP 502 responses were observed. These are typically infrastructure-layer failures (gateway/proxy/cold-start), not direct application logic defects.",
                idx_502.len()
            ),
            String::new(),
            "Affected endpoints:".to_string(),
        ];
        for endpoint in endpoints.iter().take(20) {
            description.push(format!("- `{endpoint}`"));
        }
        if endpoints.len() > 20 {
            description.push(format!("- ... and {} more", endpoints.len() - 20));
        }
        aggregate.description = description.join("\n");
        aggregate.reproduction = endpoints
            .iter()
            .take(12)
            .map(|e| format!("GET {e} -> 502"))
            .collect();
        aggregate.evidence.console_log = console_lines.into_iter().take(30).collect();
        bugs[first_idx] = aggregate;
        for idx in idx_502.into_iter().skip(1) {
            remove[idx] = true;
        }
        apply_remove_mask(bugs, &remove);
        return;
    }

    for idx in idx_502 {
        if let Some(bug) = bugs.get_mut(idx) {
            let endpoint = match &bug.category {
                BugCategory::ServerError { endpoint, .. } => endpoint.clone(),
                _ => String::new(),
            };
            bug.severity = BugSeverity::Info;
            bug.category = BugCategory::Other {
                description: "infrastructure_gateway_502".to_string(),
            };
            bug.title = "Infrastructure gateway error (502)".to_string();
            bug.description = format!(
                "{} returned HTTP 502. This is often a gateway/proxy/runtime instability signal rather than an application-code defect.",
                if endpoint.is_empty() {
                    "An endpoint".to_string()
                } else {
                    endpoint
                }
            );
        }
    }
}

/// Collapse many dead-button findings on the same page into a single info-severity
/// summary finding. Dead buttons often represent controls that require specific
/// preconditions (selected row, filled form, specific app state) to be active.
fn collapse_dead_buttons(bugs: &mut Vec<Bug>, threshold: usize, profile: &ScanProfile) {
    if threshold == 0 {
        return;
    }

    // On content sites, collapse all dead buttons (even singletons) to reduce noise.
    let effective_threshold = if profile.is_content_site() {
        1
    } else {
        threshold
    };

    // Group dead-button findings by page URL (route family).
    let mut by_route: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, bug) in bugs.iter().enumerate() {
        if matches!(bug.category, BugCategory::DeadButton { .. }) {
            let route = bug
                .location
                .url
                .as_deref()
                .and_then(|u| Url::parse(u).ok())
                .map(|u| u.path().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let template = crate::network::path_parameterizer::path_to_template(&route);
            by_route.entry(template).or_default().push(idx);
        }
    }

    let mut remove = vec![false; bugs.len()];
    for (route, indices) in &by_route {
        if indices.len() >= effective_threshold {
            // Collect selectors for the summary.
            let selectors: Vec<String> = indices
                .iter()
                .filter_map(|i| {
                    if let BugCategory::DeadButton { ref selector, .. } = bugs[*i].category {
                        Some(selector.clone())
                    } else {
                        None
                    }
                })
                .collect();

            let first_idx = indices[0];
            let mut aggregate = bugs[first_idx].clone();
            aggregate.severity = BugSeverity::Info;
            aggregate.category = BugCategory::Other {
                description: "dead_button_group".to_string(),
            };
            aggregate.title = format!("{} potential dead buttons on {}", indices.len(), route);
            let mut desc = vec![format!(
                "{} buttons on `{}` produced no observable effect. \
                 These likely require specific preconditions (selected item, \
                 filled form, or particular app state) to be active.",
                indices.len(),
                route,
            )];
            desc.push(String::new());
            desc.push("Selectors:".to_string());
            for sel in selectors.iter().take(15) {
                desc.push(format!("- `{sel}`"));
            }
            if selectors.len() > 15 {
                desc.push(format!("- ... and {} more", selectors.len() - 15));
            }
            aggregate.description = desc.join("\n");
            bugs[first_idx] = aggregate;
            for idx in indices.iter().skip(1) {
                remove[*idx] = true;
            }
        }
    }
    apply_remove_mask(bugs, &remove);
}

fn extract_entity_id_and_path(raw_url: &str) -> Option<(String, String)> {
    let path = if let Ok(url) = Url::parse(raw_url) {
        url.path().to_string()
    } else {
        let trimmed = raw_url.trim();
        if trimmed.is_empty() {
            return None;
        }
        trimmed
            .split_once(' ')
            .map(|(_, p)| p.trim())
            .unwrap_or(trimmed)
            .split('#')
            .next()
            .unwrap_or(trimmed)
            .split('?')
            .next()
            .unwrap_or(trimmed)
            .to_string()
    };

    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }

    for seg in &segments {
        if is_entity_like_segment(seg) {
            let normalized_path = if path.starts_with('/') {
                path.clone()
            } else {
                format!("/{path}")
            };
            return Some((seg.to_ascii_lowercase(), normalized_path));
        }
    }
    None
}

fn shorten_entity_id(id: &str) -> String {
    let mut out = String::new();
    for ch in id.chars().take(8) {
        out.push(ch);
    }
    if id.len() > 8 {
        out.push_str("...");
    }
    out
}

fn apply_remove_mask(bugs: &mut Vec<Bug>, remove: &[bool]) {
    let mut out = Vec::with_capacity(bugs.len());
    for (idx, bug) in bugs.drain(..).enumerate() {
        if !remove.get(idx).copied().unwrap_or(false) {
            out.push(bug);
        }
    }
    *bugs = out;
}

fn extract_paths_from_message(message: &str) -> Vec<String> {
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    static API_PATH_RE: OnceLock<Regex> = OnceLock::new();
    let url_re = URL_RE.get_or_init(|| Regex::new(r#"https?://[^\s"'`<>]+"#).expect("url regex"));
    let api_path_re =
        API_PATH_RE.get_or_init(|| Regex::new(r#"/api/[^\s"'`<>]+"#).expect("api path regex"));

    let mut out = Vec::new();
    for m in url_re.find_iter(message) {
        let token = trim_trailing_punctuation(m.as_str());
        if let Some(path) = normalize_endpoint_for_match(token) {
            out.push(path);
        }
    }
    for m in api_path_re.find_iter(message) {
        let token = trim_trailing_punctuation(m.as_str());
        if let Some(path) = normalize_endpoint_for_match(token) {
            out.push(path);
        }
    }
    out
}

fn trim_trailing_punctuation(s: &str) -> &str {
    s.trim_end_matches(|c: char| matches!(c, ')' | ']' | '}' | ',' | '.' | ';' | '"' | '\''))
}

fn normalize_endpoint_for_match(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let path = if let Ok(url) = Url::parse(trimmed) {
        url.path().to_string()
    } else {
        trimmed
            .split_once(' ')
            .map(|(_, p)| p.trim())
            .unwrap_or(trimmed)
            .split('#')
            .next()
            .unwrap_or(trimmed)
            .split('?')
            .next()
            .unwrap_or(trimmed)
            .to_string()
    };
    normalize_path_for_match(&path)
}

fn normalize_path_for_match(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() {
            continue;
        }
        if is_entity_like_segment(seg) {
            parts.push(":id".to_string());
        } else {
            parts.push(seg.to_ascii_lowercase());
        }
    }
    if parts.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", parts.join("/")))
    }
}

fn is_entity_like_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }

    static UUID_RE: OnceLock<Regex> = OnceLock::new();
    static HEX_RE: OnceLock<Regex> = OnceLock::new();
    let uuid_re = UUID_RE.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .expect("uuid regex")
    });
    let hex_re = HEX_RE.get_or_init(|| Regex::new(r"(?i)^[0-9a-f]{8,}$").expect("hex regex"));

    if seg.chars().all(|c| c.is_ascii_digit()) && seg.len() >= 3 {
        return true;
    }
    if uuid_re.is_match(seg) || hex_re.is_match(seg) {
        return true;
    }
    let has_alpha = seg.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = seg.chars().any(|c| c.is_ascii_digit());
    has_alpha && has_digit && seg.len() >= 10
}

/// Dynamically adjust confidence scores based on cross-finding signals.
///
/// Current adjustments:
/// - If the same category appears across 3+ distinct URLs, boost confidence by +0.1
///   (repeated occurrences make a finding more likely to be real).
fn adjust_confidence_scores(bugs: &mut [Bug]) {
    // Count distinct URLs per category discriminant.
    let mut category_url_counts: HashMap<String, HashSet<String>> = HashMap::new();
    for bug in bugs.iter() {
        let cat_key = bug.category.discriminant_name();
        let url = bug.location.url.clone().unwrap_or_default();
        category_url_counts.entry(cat_key).or_default().insert(url);
    }

    for bug in bugs.iter_mut() {
        let Some(ref mut conf) = bug.confidence else {
            continue;
        };
        let cat_key = bug.category.discriminant_name();

        // Repeated across 3+ views: +0.1
        if let Some(urls) = category_url_counts.get(&cat_key) {
            if urls.len() >= 3 {
                *conf += 0.1;
            }
        }

        *conf = conf.clamp(0.0, 1.0);
        // Round to 2 decimal places for stable output
        *conf = (*conf * 100.0).round() / 100.0;
    }
}

/// Classify a URL path into a sensitivity tier based on route patterns.
fn classify_route_tier(
    url: &str,
    cfg: &RouteSensitivityConfig,
    auth_required_urls: &[String],
) -> (String, String) {
    let path = url::Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| url.to_string());

    for pattern in &cfg.critical_patterns {
        if path.starts_with(pattern) {
            return (
                "critical".into(),
                format!("matches critical pattern {pattern}"),
            );
        }
    }
    for pattern in &cfg.sensitive_patterns {
        if path.starts_with(pattern) {
            return (
                "sensitive".into(),
                format!("matches sensitive pattern {pattern}"),
            );
        }
    }
    if auth_required_urls.iter().any(|u| {
        url::Url::parse(u)
            .map(|u| u.path().to_string())
            .unwrap_or_default()
            == path
    }) {
        return (cfg.auth_required_tier.clone(), "auth-required route".into());
    }
    for pattern in &cfg.public_patterns {
        if path.starts_with(pattern) {
            return ("public".into(), format!("matches public pattern {pattern}"));
        }
    }
    ("standard".into(), String::new())
}

/// Adjust finding severity based on the route sensitivity tier of each bug's URL.
///
/// - `critical` tier: promotes Medium -> High
/// - `sensitive` tier: promotes Low -> Medium
/// - `public` tier: demotes Medium -> Low
fn apply_route_context_severity(
    bugs: &mut [Bug],
    cfg: &RouteSensitivityConfig,
    auth_required_urls: &[String],
) {
    for bug in bugs.iter_mut() {
        let Some(ref url) = bug.location.url else {
            continue;
        };
        let (tier, reason) = classify_route_tier(url, cfg, auth_required_urls);

        match tier.as_str() {
            "critical" if bug.severity == BugSeverity::Medium => {
                bug.severity = BugSeverity::High;
            }
            "sensitive" if bug.severity == BugSeverity::Low => {
                bug.severity = BugSeverity::Medium;
            }
            "public" if bug.severity == BugSeverity::Medium => {
                bug.severity = BugSeverity::Low;
            }
            _ => {}
        }

        if !reason.is_empty() {
            bug.evidence.route_context = Some(RouteContext {
                tier: tier.clone(),
                reason,
            });
        }
    }
}

/// Collapse N same-category a11y findings into a single summary finding
/// when count exceeds `threshold`. Analogous to `collapse_repeated_console_errors`.
fn collapse_repeated_a11y_findings(bugs: &mut Vec<Bug>, threshold: usize) {
    if threshold == 0 {
        return;
    }

    #[derive(Default)]
    struct Group {
        indices: Vec<usize>,
        sample_views: BTreeSet<String>,
        sample_selectors: BTreeSet<String>,
    }

    let mut groups: HashMap<String, Group> = HashMap::new();
    for (idx, bug) in bugs.iter().enumerate() {
        let BugCategory::AccessibilityViolation { ref category, .. } = bug.category else {
            continue;
        };
        let g = groups.entry(category.clone()).or_default();
        g.indices.push(idx);
        if let Some(ref url) = bug.location.url {
            g.sample_views.insert(url.clone());
        }
        if let Some(ref el) = bug.location.element {
            g.sample_selectors.insert(el.clone());
        }
    }

    let mut remove = vec![false; bugs.len()];
    for (category, group) in groups {
        if group.indices.len() <= 1 || group.indices.len() < threshold {
            continue;
        }
        let first_idx = *group.indices.first().unwrap_or(&0);
        if first_idx >= bugs.len() {
            continue;
        }

        let mut aggregate = bugs[first_idx].clone();
        aggregate.title = format!(
            "Accessibility: {} ({} occurrences)",
            category.replace('_', " "),
            group.indices.len()
        );
        aggregate.location.url = None;
        aggregate.location.view = None;
        aggregate.location.element = None;
        aggregate.description = {
            let mut lines = Vec::new();
            lines.push(format!(
                "The same accessibility violation (`{}`) was found **{}** times.",
                category,
                group.indices.len(),
            ));
            lines.push(String::new());
            if !group.sample_views.is_empty() {
                lines.push("Views affected:".to_string());
                for v in group.sample_views.iter().take(12) {
                    lines.push(format!("- `{v}`"));
                }
                if group.sample_views.len() > 12 {
                    lines.push(format!("- ... and {} more", group.sample_views.len() - 12));
                }
            }
            lines.join("\n")
        };
        bugs[first_idx] = aggregate;

        for idx in group.indices.into_iter().skip(1) {
            if idx < remove.len() {
                remove[idx] = true;
            }
        }
    }

    if remove.iter().any(|v| *v) {
        apply_remove_mask(bugs, &remove);
    }
}

/// Augment bug findings with contrast violations detected from captured
/// `ComponentVisualProfile` data (Rust-side re-check of text color vs background).
fn augment_with_visual_profile_contrast(outcome: &ScanOutcome, bugs: &mut Vec<Bug>) {
    use crate::bugs::accessibility::{contrast_ratio, parse_css_color};

    // Build a set of (view_url, selector) pairs for existing contrast findings
    // so we don't duplicate what the JS audit already found.
    let mut existing: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    for bug in bugs.iter() {
        if let BugCategory::AccessibilityViolation {
            ref category,
            ref wcag_criterion,
            ..
        } = bug.category
        {
            if category == "insufficient_contrast" || wcag_criterion == "1.4.3" {
                let url = bug.location.url.clone().unwrap_or_default();
                let el = bug.location.element.clone().unwrap_or_default();
                existing.insert((url, el));
            }
        }
    }

    let mut new_findings: Vec<Bug> = Vec::new();
    // Use the max existing BUG-NNNN numeric id to avoid collisions after
    // dedupe/collapse passes removed earlier findings.
    let mut next_id: usize = bugs
        .iter()
        .filter_map(|b| b.id.strip_prefix("BUG-"))
        .filter_map(|s| s.parse::<usize>().ok())
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for view in &outcome.views {
        for c in &view.component_instances {
            let Some(ref visual) = c.visual else {
                continue;
            };
            let (Some(fg_str), Some(bg_str)) = (&visual.color, &visual.background_color) else {
                continue;
            };
            // Skip non-opaque/indeterminate colors - this Rust-side pass does not
            // composite layered backgrounds, so translucent tokens can produce
            // false positives on glassy/overlay UI surfaces.
            if is_non_opaque_css_color(fg_str) || is_non_opaque_css_color(bg_str) {
                continue;
            }
            let (Some(fg), Some(bg)) = (parse_css_color(fg_str), parse_css_color(bg_str)) else {
                continue;
            };

            let font_size = visual.font_size_px.unwrap_or(16.0);
            let font_weight = visual.font_weight.unwrap_or(400);
            let is_bold = font_weight >= 700;
            let is_large_text = font_size >= 24.0 || (is_bold && font_size >= 18.66);
            let required = if is_large_text { 3.0 } else { 4.5 };

            let ratio = contrast_ratio(fg, bg);
            if ratio >= required {
                continue;
            }

            let view_url = view.url.clone();
            let selector = c.selector.clone();
            if existing.contains(&(view_url.clone(), selector.clone())) {
                continue;
            }
            existing.insert((view_url.clone(), selector.clone()));

            new_findings.push(Bug {
                id: format!("BUG-{next_id:04}"),
                severity: BugSeverity::Medium,
                confidence: Some(0.75),
                category: BugCategory::AccessibilityViolation {
                    category: "insufficient_contrast".to_string(),
                    wcag_criterion: "1.4.3".to_string(),
                    impact: crate::types::bugs::AccessibilityImpact::Serious,
                },
                title: format!(
                    "Insufficient contrast ratio {:.2}:1 (needs {:.1}:1)",
                    ratio, required
                ),
                description: format!(
                    "Component `{}` has text color `{}` on background `{}` with contrast ratio {:.2}:1. \
                     WCAG AA requires {:.1}:1 for {} text.",
                    selector, fg_str, bg_str, ratio, required,
                    if is_large_text { "large" } else { "normal" }
                ),
                remediation: None,
                location: crate::types::bugs::BugLocation {
                    view: None,
                    element: Some(selector),
                    url: Some(view_url),
                },
                reproduction: Vec::new(),
                evidence: crate::types::bugs::BugEvidence::default(),
                discovered_at: outcome.started_at,
                cwe: None,
                owasp: None,
            });
            next_id += 1;
        }
    }

    bugs.extend(new_findings);
}

pub fn render_markdown(report: &BugReport) -> String {
    let mut out = String::new();
    out.push_str("# BrokenApp Bug Report\n\n");
    out.push_str(&format!("Target: `{}`\n\n", report.target_url));
    out.push_str("## Summary\n\n");

    for sev in [
        BugSeverity::Critical,
        BugSeverity::High,
        BugSeverity::Medium,
        BugSeverity::Low,
        BugSeverity::Info,
    ] {
        let n = report.summary.get(&sev).copied().unwrap_or(0);
        out.push_str(&format!("- {}: {}\n", severity_label(sev), n));
    }

    out.push_str("\n## Findings\n\n");
    for b in &report.items {
        out.push_str(&format!("### {} {}\n\n", b.id, b.title));
        out.push_str(&format!("- Severity: {}\n", severity_label(b.severity)));
        if let Some(conf) = b.confidence {
            out.push_str(&format!("- Confidence: {:.0}%\n", conf * 100.0));
        }
        out.push_str(&format!("- Category: {}\n", category_label(&b.category)));
        if let Some(url) = &b.location.url {
            out.push_str(&format!("- URL: `{}`\n", url));
        }
        if let Some(sel) = &b.location.element {
            out.push_str(&format!("- Element: `{}`\n", sel));
        }
        if b.cwe.is_some() || b.owasp.is_some() {
            out.push_str("- Compliance:");
            if let Some(ref cwe) = b.cwe {
                out.push_str(&format!(" {cwe}"));
            }
            if let Some(ref owasp) = b.owasp {
                out.push_str(&format!(" | {owasp}"));
            }
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&b.description);
        out.push_str("\n\n");
        if let Some(ref rem) = b.remediation {
            out.push_str("#### Remediation\n\n");
            out.push_str(rem);
            out.push_str("\n\n");
        }
    }

    out
}

fn severity_label(severity: BugSeverity) -> &'static str {
    match severity {
        BugSeverity::Critical => "Critical",
        BugSeverity::High => "High",
        BugSeverity::Medium => "Medium",
        BugSeverity::Low => "Low",
        BugSeverity::Info => "Info",
    }
}

fn category_label(category: &BugCategory) -> &'static str {
    match category {
        BugCategory::BrokenLink { .. } => "Broken Link",
        BugCategory::AssetLoadFailure { .. } => "Asset Load Failure",
        BugCategory::DeadButton { .. } => "Dead Button",
        BugCategory::ServerError { .. } => "Server Error",
        BugCategory::ApiError { .. } => "API Error",
        BugCategory::NetworkRequestFailure { .. } => "Network Request Failure",
        BugCategory::ConsoleError { .. } => "Console Error",
        BugCategory::CorsError { .. } => "CORS Error",
        BugCategory::MixedContent { .. } => "Mixed Content",
        BugCategory::InconsistentApiResponse { .. } => "Inconsistent API Response",
        BugCategory::OrphanedRoute { .. } => "Orphaned Route",
        BugCategory::PerformanceIssue { .. } => "Performance Issue",
        BugCategory::AccessibilityViolation { .. } => "Accessibility Violation",
        BugCategory::SecurityObservation { .. } => "Security Observation",
        BugCategory::UnexpectedRedirect { .. } => "Unexpected Redirect",
        BugCategory::UiErrorToast { .. } => "UI Error Toast",
        BugCategory::WebSocketError { .. } => "WebSocket Error",
        BugCategory::Other { .. } => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteSensitivityConfig, ScanConfig};
    use crate::types::bugs::{BugEvidence, BugLocation};

    fn saas_profile() -> ScanProfile {
        ScanProfile {
            has_auth: true,
            form_count: 5,
            api_endpoint_count: 20,
            view_count: 10,
        }
    }

    fn content_site_profile() -> ScanProfile {
        ScanProfile {
            has_auth: false,
            form_count: 0,
            api_endpoint_count: 0,
            view_count: 15,
        }
    }

    fn bug(id: &str, category: BugCategory, severity: BugSeverity) -> Bug {
        Bug {
            id: id.to_string(),
            severity,
            confidence: None,
            category,
            title: "x".to_string(),
            description: "x".to_string(),
            remediation: None,
            location: BugLocation {
                view: None,
                element: None,
                url: None,
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        }
    }

    #[test]
    fn demotes_and_groups_502() {
        let mut cfg = ScanConfig::default();
        cfg.infra_502_group_threshold = 2;
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/deals/69fb0856".to_string(),
                    status: 502,
                    response: None,
                },
                BugSeverity::Medium,
            ),
            bug(
                "BUG-0002",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/deals/69fb0856/timeline".to_string(),
                    status: 502,
                    response: None,
                },
                BugSeverity::Medium,
            ),
        ];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, BugSeverity::Info);
        assert!(out[0].title.contains("Gateway instability"));
    }

    #[test]
    fn dedupes_identical_fingerprint_server_errors_to_one_finding() {
        // Two real requests to the same endpoint both returned 500 during a
        // single scan. They share an identical fingerprint (endpoint + status;
        // the response body is intentionally excluded from the fingerprint), so
        // the emitted report MUST contain exactly one finding. Emitting both
        // would collide on `finding_key` (breaking `fix-packet --key`) and
        // inflate the critical count for what is a single defect.
        let cfg = ScanConfig::default();
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/orders".to_string(),
                    status: 500,
                    response: Some("{\"error\":\"internal server error\"}".to_string()),
                },
                BugSeverity::Critical,
            ),
            bug(
                "BUG-0002",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/orders".to_string(),
                    status: 500,
                    // Different body — still the same defect by fingerprint.
                    response: Some("{\"error\":\"boom\"}".to_string()),
                },
                BugSeverity::Critical,
            ),
        ];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        let server_errors: Vec<_> = out
            .iter()
            .filter(|b| matches!(b.category, BugCategory::ServerError { .. }))
            .collect();
        assert_eq!(
            server_errors.len(),
            1,
            "duplicate 500s on the same endpoint must collapse to one finding"
        );
        assert_eq!(
            server_errors[0].id, "BUG-0001",
            "dedupe must keep the earliest (lowest-id) occurrence"
        );
    }

    #[test]
    fn keeps_distinct_endpoint_server_errors_separate() {
        // Guard against over-dedupe: different endpoints are different defects
        // and must each surface as their own finding.
        let cfg = ScanConfig::default();
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/orders".to_string(),
                    status: 500,
                    response: None,
                },
                BugSeverity::Critical,
            ),
            bug(
                "BUG-0002",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/profile".to_string(),
                    status: 500,
                    response: None,
                },
                BugSeverity::Critical,
            ),
        ];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        let server_errors = out
            .iter()
            .filter(|b| matches!(b.category, BugCategory::ServerError { .. }))
            .count();
        assert_eq!(
            server_errors, 2,
            "distinct endpoints must remain distinct findings"
        );
    }

    #[test]
    fn removes_scanner_runtime_findings_from_bug_report() {
        let cfg = ScanConfig::default();
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::Other {
                    description: "Navigation failed: Page.navigate: net::ERR_ABORTED".to_string(),
                },
                BugSeverity::High,
            ),
            bug(
                "BUG-0002",
                BugCategory::BrokenLink {
                    url: "https://app.test/missing".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
        ];

        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].category, BugCategory::BrokenLink { .. }));
    }

    #[test]
    fn can_ignore_502_when_configured() {
        let mut cfg = ScanConfig::default();
        cfg.ignore_502 = true;
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/transient".to_string(),
                    status: 502,
                    response: None,
                },
                BugSeverity::Critical,
            ),
            bug(
                "BUG-0002",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/fail".to_string(),
                    status: 500,
                    response: None,
                },
                BugSeverity::Medium,
            ),
        ];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].category,
            BugCategory::ServerError { status: 500, .. }
        ));
        assert_eq!(out[0].severity, BugSeverity::Critical);
    }

    #[test]
    fn collapses_orphaned_404_cascade() {
        let cfg = ScanConfig::default();
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::BrokenLink {
                    url: "https://app.test/api/deals/69fb0856".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
            bug(
                "BUG-0002",
                BugCategory::BrokenLink {
                    url: "https://app.test/api/deals/69fb0856/timeline".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
            bug(
                "BUG-0003",
                BugCategory::BrokenLink {
                    url: "https://app.test/api/deals/69fb0856/borrowers".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
        ];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
        assert!(out[0].title.contains("Orphaned entity"));
        assert!(matches!(out[0].category, BugCategory::OrphanedRoute { .. }));
    }

    #[test]
    fn correlates_console_to_server_error() {
        let cfg = ScanConfig::default();
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::ServerError {
                    endpoint: "https://app.test/api/clients/123/financials".to_string(),
                    status: 500,
                    response: None,
                },
                BugSeverity::Medium,
            ),
            bug(
                "BUG-0002",
                BugCategory::ConsoleError {
                    message: "Failed to fetch https://app.test/api/clients/987/financials"
                        .to_string(),
                    source: None,
                },
                BugSeverity::Medium,
            ),
        ];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, BugSeverity::Critical); // status 500 calibration
        assert_eq!(out[0].evidence.console_log.len(), 1);
    }

    #[test]
    fn collapses_repeated_console_errors_into_one_finding() {
        let mut cfg = ScanConfig::default();
        cfg.console_error_group_threshold = 2;

        let mut a = bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Warning: Hydration failed (#418)".to_string(),
                source: Some("PipelineDealsPageClient.tsx:123".to_string()),
            },
            BugSeverity::High,
        );
        a.location.url = Some("https://app.test/mortgages/69fb0856".to_string());

        let mut b = bug(
            "BUG-0002",
            BugCategory::ConsoleError {
                message: "Warning: Hydration failed (#418)".to_string(),
                source: Some("PipelineDealsPageClient.tsx:456".to_string()),
            },
            BugSeverity::High,
        );
        b.location.url = Some("https://app.test/mortgages/69fb0857".to_string());

        let mut c = bug(
            "BUG-0003",
            BugCategory::ConsoleError {
                message: "TypeError: x is not a function".to_string(),
                source: None,
            },
            BugSeverity::High,
        );
        c.location.url = Some("https://app.test/mortgages/other".to_string());

        let out = refine_bug_findings(&[a, b, c], &cfg, &saas_profile());
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .any(|b| b.title.contains("Console error repeated across 2 views"))
        );
    }

    #[test]
    fn dedupes_exact_console_errors_on_same_page_before_threshold_grouping() {
        let cfg = ScanConfig::default();
        let mut a = bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Warning: Hydration failed (#418)".to_string(),
                source: None,
            },
            BugSeverity::High,
        );
        a.location.url = Some("https://app.test/diagnostics".to_string());

        let mut b = bug(
            "BUG-0002",
            BugCategory::ConsoleError {
                message: "Warning: Hydration failed (#419)".to_string(),
                source: None,
            },
            BugSeverity::High,
        );
        b.location.url = Some("https://app.test/diagnostics".to_string());

        let mut c = bug(
            "BUG-0003",
            BugCategory::ConsoleError {
                message: "Warning: Hydration failed (#418)".to_string(),
                source: None,
            },
            BugSeverity::High,
        );
        c.location.url = Some("https://app.test/login".to_string());

        let out = refine_bug_findings(&[a, b, c], &cfg, &saas_profile());
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.iter()
                .filter(|bug| matches!(bug.category, BugCategory::ConsoleError { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn collapses_many_missing_entity_ids_into_one_finding() {
        let mut cfg = ScanConfig::default();
        cfg.stale_entity_404_group_threshold = 4;
        let bugs = vec![
            bug(
                "BUG-0001",
                BugCategory::BrokenLink {
                    url: "https://app.test/api/deals/69fb0856".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
            bug(
                "BUG-0002",
                BugCategory::BrokenLink {
                    url: "https://app.test/api/deals/69fb0857".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
            bug(
                "BUG-0003",
                BugCategory::BrokenLink {
                    url: "https://app.test/api/deals/69fb0858".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
            bug(
                "BUG-0004",
                BugCategory::BrokenLink {
                    url: "https://app.test/api/deals/69fb0859/timeline".to_string(),
                    status: 404,
                },
                BugSeverity::High,
            ),
        ];

        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].category,
            BugCategory::Other { ref description } if description == "stale_entity_references_404"
        ));
        assert!(out[0].title.contains("Stale entity references"));
        assert_eq!(out[0].severity, BugSeverity::Info);
    }

    #[test]
    fn content_site_demotes_dead_button_to_info() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::DeadButton {
                selector: "button.cta".to_string(),
                label: Some("Get Started".to_string()),
                precondition_hint: None,
                precondition_satisfied: None,
                pre_click_pattern: None,
                classification: None,
            },
            BugSeverity::High,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &content_site_profile());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, BugSeverity::Info);
    }

    #[test]
    fn saas_profile_preserves_dead_button_severity() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::DeadButton {
                selector: "button.submit".to_string(),
                label: Some("Submit".to_string()),
                precondition_hint: None,
                precondition_satisfied: None,
                pre_click_pattern: None,
                classification: None,
            },
            BugSeverity::High,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, BugSeverity::High);
    }

    #[test]
    fn content_site_demotes_static_asset_404_to_low() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::BrokenLink {
                url: "https://example.com/assets/hero.png".to_string(),
                status: 404,
            },
            BugSeverity::High,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &content_site_profile());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, BugSeverity::Low);
    }

    #[test]
    fn content_site_demotes_api_404_to_medium() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::BrokenLink {
                url: "https://example.com/api/users".to_string(),
                status: 404,
            },
            BugSeverity::High,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &content_site_profile());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, BugSeverity::Medium);
    }

    #[test]
    fn content_site_demotes_console_error_to_low() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Hydration mismatch".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &content_site_profile());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, BugSeverity::Low);
    }

    #[test]
    fn suppresses_non_actionable_console_noise() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message:
                    "[WALL] No products found due to error\nReason: TypeError: Failed to fetch"
                        .to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert!(out.is_empty());
    }

    #[test]
    fn suppresses_generic_failed_fetch_noise() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Unhandled Promise Rejection: TypeError: Failed to fetch".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert!(out.is_empty());
    }

    #[test]
    fn suppresses_generic_failed_fetch_stack_trace_noise() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "TypeError: Unhandled Promise Rejection: Failed to fetch\n    at Object.initialize (https://app.example.com/static/config.chunk.js:1:20678)".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert!(out.is_empty());
    }

    #[test]
    fn suppresses_minified_react_418_noise() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Minified React error #418".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert!(out.is_empty());
    }

    #[test]
    fn suppresses_html_as_json_console_noise() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Unexpected token '<', \"<!DOCTYPE html>\" is not valid JSON".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert!(out.is_empty());
    }

    #[test]
    fn suppresses_get_world_position_console_noise() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Cannot read properties of undefined (reading 'getWorldPosition')"
                    .to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert!(out.is_empty());
    }

    #[test]
    fn suppresses_radix_dialog_accessibility_console_noise() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "`DialogContent` requires a `DialogTitle` for the component to be accessible for screen reader users.".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert!(out.is_empty());
    }

    #[test]
    fn detects_non_opaque_css_colors() {
        assert!(is_non_opaque_css_color("transparent"));
        assert!(is_non_opaque_css_color("rgba(0, 0, 0, 0)"));
        assert!(is_non_opaque_css_color("rgba(255,255,255,0.0)"));
        assert!(is_non_opaque_css_color("rgba(255,255,255,0.4)"));
        assert!(!is_non_opaque_css_color("rgb(0, 0, 0)"));
        assert!(!is_non_opaque_css_color("rgba(255,255,255,1)"));
    }

    #[test]
    fn keeps_actionable_console_errors() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Hydration mismatch: server/client markup differs".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn keeps_actionable_unauthorized_console_errors() {
        let cfg = ScanConfig::default();
        let bugs = vec![bug(
            "BUG-0001",
            BugCategory::ConsoleError {
                message: "Failed to initialize tool list: ApiError: Unauthorized".to_string(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        let out = refine_bug_findings(&bugs, &cfg, &saas_profile());
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn is_content_site_false_when_has_auth() {
        let profile = ScanProfile {
            has_auth: true,
            form_count: 0,
            api_endpoint_count: 0,
            view_count: 5,
        };
        assert!(!profile.is_content_site());
    }

    #[test]
    fn is_content_site_false_when_many_api_endpoints() {
        let profile = ScanProfile {
            has_auth: false,
            form_count: 0,
            api_endpoint_count: 10,
            view_count: 5,
        };
        assert!(!profile.is_content_site());
    }

    #[test]
    fn is_content_site_true_when_no_auth_no_forms_few_apis() {
        assert!(content_site_profile().is_content_site());
    }

    #[test]
    fn route_context_promotes_admin_findings() {
        let cfg = RouteSensitivityConfig::default();
        let mut bugs = vec![bug(
            "BUG-001",
            BugCategory::ServerError {
                endpoint: "/api/admin/users".into(),
                status: 500,
                response: None,
            },
            BugSeverity::Medium,
        )];
        bugs[0].location.url = Some("https://example.com/api/admin/users".into());
        apply_route_context_severity(&mut bugs, &cfg, &[]);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert!(bugs[0].evidence.route_context.is_some());
        assert_eq!(
            bugs[0].evidence.route_context.as_ref().unwrap().tier,
            "critical"
        );
    }

    #[test]
    fn route_context_demotes_public_findings() {
        let cfg = RouteSensitivityConfig::default();
        let mut bugs = vec![bug(
            "BUG-001",
            BugCategory::ConsoleError {
                message: "x".into(),
                source: None,
            },
            BugSeverity::Medium,
        )];
        bugs[0].location.url = Some("https://example.com/about".into());
        apply_route_context_severity(&mut bugs, &cfg, &[]);
        assert_eq!(bugs[0].severity, BugSeverity::Low);
        assert_eq!(
            bugs[0].evidence.route_context.as_ref().unwrap().tier,
            "public"
        );
    }

    #[test]
    fn adjust_confidence_boosts_repeated_findings() {
        // Create 3 bugs with same category on different views
        let mut bugs = vec![
            bug(
                "BUG-001",
                BugCategory::ConsoleError {
                    message: "TypeError".into(),
                    source: None,
                },
                BugSeverity::Medium,
            ),
            bug(
                "BUG-002",
                BugCategory::ConsoleError {
                    message: "TypeError".into(),
                    source: None,
                },
                BugSeverity::Medium,
            ),
            bug(
                "BUG-003",
                BugCategory::ConsoleError {
                    message: "TypeError".into(),
                    source: None,
                },
                BugSeverity::Medium,
            ),
        ];
        for (i, b) in bugs.iter_mut().enumerate() {
            b.confidence = Some(0.70);
            b.location.url = Some(format!("https://example.com/page{i}"));
        }
        adjust_confidence_scores(&mut bugs);
        // Repeated across 3 views -> +0.1
        assert!((bugs[0].confidence.unwrap() - 0.80).abs() < 0.01);
    }
}
