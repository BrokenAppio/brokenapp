use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use anyhow::{Context, Result};
use chromiumoxide::cdp::js_protocol::runtime;
use chromiumoxide::page::Page;
use futures::StreamExt;

use crate::browser::TabKey;
use crate::types::bugs::{
    AccessibilityImpact, Bug, BugCategory, BugEvidence, BugLocation, BugSeverity,
};
use crate::types::graph::ViewId;

pub struct BugDetector {
    seq: AtomicUsize,
    bugs: tokio::sync::Mutex<Vec<Bug>>,
    /// The UI action currently being exercised, per tab. Console errors,
    /// uncaught exceptions and native dialogs a tab produces while its action
    /// runs are attributed to that action (finding `location.view`/`element`,
    /// `evidence.action_ids`) and collected for the interaction record; other
    /// tabs' actions never see them.
    current_actions: std::sync::Mutex<HashMap<TabKey, ActionWindow>>,
}

/// Console/dialog evidence collected for one UI action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionCapture {
    /// Console errors and uncaught exceptions, in arrival order (summarized).
    pub console_errors: Vec<String>,
    /// Uncaught exceptions only (subset of `console_errors`).
    pub exceptions: Vec<String>,
    /// Native JS dialog raised during the action (`confirm: Delete item?`).
    pub native_dialog: Option<String>,
}

#[derive(Debug)]
struct ActionWindow {
    action_id: String,
    view: ViewId,
    element: String,
    capture: ActionCapture,
}

/// The action that was running when a console event arrived.
struct ActionAttribution {
    action_id: String,
    view: ViewId,
    element: String,
}

const MAX_ACTION_CONSOLE_ERRORS: usize = 20;
const MAX_ACTION_MESSAGE_CHARS: usize = 400;

pub struct BugDetectorHandle {
    task: tokio::task::JoinHandle<()>,
    /// The watched tab: an action window left open on it (an interaction cut
    /// short by a timeout) is dropped with the handle.
    tab: Option<(Weak<BugDetector>, TabKey)>,
}

impl Drop for BugDetectorHandle {
    fn drop(&mut self) {
        self.task.abort();
        if let Some((detector, tab)) = self.tab.take()
            && let Some(detector) = detector.upgrade()
        {
            detector.lock_actions().remove(&tab);
        }
    }
}

impl BugDetector {
    pub fn new() -> Self {
        Self {
            seq: AtomicUsize::new(1),
            bugs: tokio::sync::Mutex::new(Vec::new()),
            current_actions: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn from_existing(bugs: Vec<Bug>) -> Self {
        let mut max = 0usize;
        for b in &bugs {
            if let Some(n) = parse_bug_id(&b.id) {
                max = max.max(n);
            }
        }
        Self {
            seq: AtomicUsize::new(max.saturating_add(1).max(1)),
            bugs: tokio::sync::Mutex::new(bugs),
            current_actions: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn lock_actions(&self) -> std::sync::MutexGuard<'_, HashMap<TabKey, ActionWindow>> {
        self.current_actions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Start attributing console errors, exceptions and native dialogs of
    /// `tab` to `action_id` (the control `element` on `view`). Call right
    /// before the interaction; pair with [`BugDetector::end_action`] after it
    /// settles.
    pub fn begin_action(&self, tab: &TabKey, action_id: &str, view: &str, element: &str) {
        self.lock_actions().insert(
            tab.clone(),
            ActionWindow {
                action_id: action_id.to_string(),
                view: view.to_string(),
                element: element.to_string(),
                capture: ActionCapture::default(),
            },
        );
    }

    /// Stop attributing on `tab` and return what was observed during the
    /// action. Returns an empty capture when `action_id` is not the tab's
    /// current action.
    pub fn end_action(&self, tab: &TabKey, action_id: &str) -> ActionCapture {
        let mut actions = self.lock_actions();
        if actions
            .get(tab)
            .is_some_and(|window| window.action_id == action_id)
        {
            return actions
                .remove(tab)
                .map(|window| window.capture)
                .unwrap_or_default();
        }
        ActionCapture::default()
    }

    /// Note a native JS dialog (`alert`/`confirm`/`prompt`/`beforeunload`)
    /// `tab` raised while its action is running, e.g. `confirm: Delete item?`.
    pub fn note_native_dialog(&self, tab: &TabKey, description: impl Into<String>) {
        if let Some(window) = self.lock_actions().get_mut(tab)
            && window.capture.native_dialog.is_none()
        {
            window.capture.native_dialog = Some(truncate_chars(
                &description.into(),
                MAX_ACTION_MESSAGE_CHARS,
            ));
        }
    }

    /// Attribute a console message of `tab` to its current action, if one
    /// is running.
    fn attribute_console_message(
        &self,
        tab: &TabKey,
        message: &str,
        exception: bool,
    ) -> Option<ActionAttribution> {
        let mut actions = self.lock_actions();
        let window = actions.get_mut(tab)?;
        let summary = summarize_console_message(message);
        if window.capture.console_errors.len() < MAX_ACTION_CONSOLE_ERRORS {
            window.capture.console_errors.push(summary.clone());
        }
        if exception && window.capture.exceptions.len() < MAX_ACTION_CONSOLE_ERRORS {
            window.capture.exceptions.push(summary);
        }
        Some(ActionAttribution {
            action_id: window.action_id.clone(),
            view: window.view.clone(),
            element: window.element.clone(),
        })
    }

    pub async fn bugs_snapshot(&self) -> Vec<Bug> {
        self.bugs.lock().await.clone()
    }

    /// Returns the current number of recorded bugs without cloning the full list.
    pub async fn bug_count(&self) -> usize {
        self.bugs.lock().await.len()
    }

    pub async fn record(&self, mut bug: Bug) {
        if bug.id.is_empty() {
            bug.id = self.next_id();
        }
        self.bugs.lock().await.push(bug);
    }

    pub fn next_id(&self) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("BUG-{n:04}")
    }

    /// Record console errors and uncaught exceptions of `page`, attributed to
    /// the action running on its tab ([`TabKey::of`]).
    pub async fn attach_console(self: Arc<Self>, page: &Page) -> Result<BugDetectorHandle> {
        let tab = TabKey::of(page);
        let mut console = page
            .event_listener::<runtime::EventConsoleApiCalled>()
            .await
            .context("Runtime.consoleAPICalled listener")?;
        let mut exceptions = page
            .event_listener::<runtime::EventExceptionThrown>()
            .await
            .context("Runtime.exceptionThrown listener")?;

        let page = page.clone();
        let this = Arc::clone(&self);
        let task_tab = tab.clone();
        let task = tokio::spawn(async move {
            let tab = task_tab;
            let mut console_done = false;
            let mut exceptions_done = false;
            while !(console_done && exceptions_done) {
                tokio::select! {
                    ev = console.next(), if !console_done => {
                        match ev {
                            Some(ev) => {
                                if ev.r#type == runtime::ConsoleApiCalledType::Error {
                                    let msg = console_event_message(&ev);
                                    // Attribute before any await so an action that ends
                                    // meanwhile still gets the error it caused.
                                    let attribution = this.attribute_console_message(&tab, &msg, false);
                                    let url = page.url().await.ok().flatten();
                                    // Demote infrastructure noise to Low severity
                                    let severity = {
                                        let msg_lower = msg.to_ascii_lowercase();
                                        if msg_lower.contains("cross-origin")
                                            || msg_lower.contains("coop")
                                            || msg_lower.contains("coep")
                                            || msg_lower.contains("cors")
                                            || msg_lower.contains("content security policy")
                                            || msg_lower.contains("mixed content")
                                            || msg_lower.contains("deprecated")
                                            || msg_lower.contains("third-party cookie")
                                        {
                                            BugSeverity::Low
                                        } else {
                                            BugSeverity::Medium
                                        }
                                    };
                                    let (location, evidence) = attributed_location(url, attribution);
                                    let bug = Bug {
                                        id: this.next_id(),
                                        severity,
                                        confidence: Some(0.70),
                                        category: BugCategory::ConsoleError { message: msg.clone(), source: None },
                                        title: "Console error".to_string(),
                                        description: msg,
                                        remediation: None,
                                        location,
                                        reproduction: Vec::new(),
                                        evidence,
                                        discovered_at: chrono::Utc::now(),
                                        cwe: None,
                                        owasp: None,
                                    };
                                    this.record(bug).await;
                                }
                            }
                            None => console_done = true,
                        }
                    }
                    ev = exceptions.next(), if !exceptions_done => {
                        match ev {
                            Some(ev) => {
                                let msg = exception_message(&ev);
                                let attribution = this.attribute_console_message(&tab, &msg, true);
                                let url = page.url().await.ok().flatten();
                                let (location, evidence) = attributed_location(url, attribution);
                                let bug = Bug {
                                    id: this.next_id(),
                                    severity: BugSeverity::High,
                                    confidence: Some(0.85),
                                    category: BugCategory::ConsoleError { message: msg.clone(), source: None },
                                    title: "Unhandled exception".to_string(),
                                    description: msg,
                                    remediation: None,
                                    location,
                                    reproduction: Vec::new(),
                                    evidence,
                                    discovered_at: chrono::Utc::now(),
                                    cwe: None,
                                    owasp: None,
                                };
                                this.record(bug).await;
                            }
                            None => exceptions_done = true,
                        }
                    }
                }
            }
        });

        Ok(BugDetectorHandle {
            task,
            tab: Some((Arc::downgrade(&self), tab)),
        })
    }

    pub async fn record_broken_link(&self, url: String, status: u16) {
        let bug = Bug {
            id: self.next_id(),
            severity: BugSeverity::High,
            confidence: Some(0.90),
            category: BugCategory::BrokenLink {
                url: url.clone(),
                status,
            },
            title: format!("Broken link ({status})"),
            description: format!("Navigation to {url} returned HTTP {status}."),
            remediation: None,
            location: BugLocation {
                view: None,
                element: None,
                url: Some(url),
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_asset_load_failure(&self, url: String, status: u16) {
        let bug = Bug {
            id: self.next_id(),
            severity: BugSeverity::Low,
            confidence: Some(0.95),
            category: BugCategory::AssetLoadFailure {
                url: url.clone(),
                status,
            },
            title: format!("Asset failed to load ({status})"),
            description: format!("Static asset {url} returned HTTP {status}."),
            remediation: Some(
                "Restore the asset, update the reference, or remove the broken resource from the page."
                    .to_string(),
            ),
            location: BugLocation {
                view: None,
                element: None,
                url: Some(url),
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_dead_button(
        &self,
        url: Option<String>,
        view: Option<ViewId>,
        selector: String,
        label: Option<String>,
        precondition_hint: Option<String>,
        precondition_satisfied: Option<bool>,
        action_id: Option<String>,
        pre_click_pattern: Option<String>,
        classification: Option<String>,
    ) {
        // Severity inversion: recognized patterns that are truly dead get
        // higher severity because they are specific and actionable.
        let is_probable_nav_placeholder =
            is_probable_noop_sidebar_or_placeholder_nav(&selector, label.as_deref());
        let severity = if precondition_hint.is_some() {
            BugSeverity::Info
        } else {
            match classification.as_deref() {
                Some("dead") => {
                    if is_probable_nav_placeholder {
                        BugSeverity::Low
                    } else if pre_click_pattern.is_some()
                        && pre_click_pattern.as_deref() != Some("unknown")
                    {
                        BugSeverity::High
                    } else {
                        BugSeverity::Medium
                    }
                }
                Some("weak_response") => BugSeverity::Low,
                Some("needs_verification") => BugSeverity::Info,
                _ => BugSeverity::Low,
            }
        };
        let mut confidence: f64 = if precondition_hint.is_some() {
            0.2
        } else {
            match classification.as_deref() {
                Some("dead") => {
                    if pre_click_pattern.is_some()
                        && pre_click_pattern.as_deref() != Some("unknown")
                    {
                        0.7
                    } else {
                        0.5
                    }
                }
                Some("needs_verification") => 0.3,
                _ => 0.5,
            }
        };
        if precondition_satisfied == Some(true) {
            confidence += 0.2;
        }
        if let Some(lbl) = label.as_deref() {
            if !lbl.trim().is_empty() {
                confidence += 0.1;
            } else {
                confidence -= 0.1;
            }
        } else {
            confidence -= 0.1;
        }
        if selector.starts_with('#') {
            confidence += 0.15;
        }
        let sel_lc = selector.to_ascii_lowercase();
        if ["data-testid", "data-cy", "data-test", "data-qa"]
            .iter()
            .any(|a| sel_lc.contains(a))
        {
            confidence += 0.2;
        }
        if sel_lc.contains("nth-of-type") {
            confidence -= 0.1;
        }
        confidence = confidence.clamp(0.0, 1.0);
        if precondition_satisfied == Some(false) {
            confidence = confidence.min(0.79);
        }
        if classification.as_deref() == Some("needs_verification") {
            confidence = confidence.min(0.4);
        }
        if is_probable_nav_placeholder && classification.as_deref() == Some("dead") {
            confidence = confidence.min(0.55);
        }
        // Keep output stable/readable (2 decimal places).
        let confidence = Some((confidence * 100.0).round() / 100.0);

        let title = match (classification.as_deref(), pre_click_pattern.as_deref()) {
            (Some("dead"), Some("accordion")) => {
                "Broken accordion: element does not toggle on click".to_string()
            }
            (Some("dead"), Some("tab")) => {
                "Broken tab: aria-selected does not change on click".to_string()
            }
            (Some("dead"), Some("disclosure_toggle")) => {
                "Broken disclosure toggle: element does not respond".to_string()
            }
            (Some("dead"), Some("modal")) => {
                "Broken modal trigger: dialog does not open on click".to_string()
            }
            (Some("dead"), Some("dropdown")) => {
                "Broken dropdown: menu does not appear on click".to_string()
            }
            (Some("dead"), Some("copy_to_clipboard")) => {
                "Broken copy button: no clipboard action on click".to_string()
            }
            (Some("needs_verification"), Some(p)) if p != "unknown" => {
                format!("Unverified {p}: no response observed (may need manual check)")
            }
            _ => "Unresponsive interactive element".to_string(),
        };

        let description = {
            let mut parts = Vec::new();
            parts.push(format!("Element `{selector}` did not respond to click."));
            if let Some(ref lbl) = label {
                if !lbl.trim().is_empty() {
                    parts.push(format!("Button text: \"{}\".", lbl.trim()));
                }
            }
            match (classification.as_deref(), pre_click_pattern.as_deref()) {
                (Some("dead"), Some(pat)) if pat != "unknown" => {
                    parts.push(format!(
                        "Expected behavior: {} interaction. No DOM changes, network requests, or ARIA state updates were observed.",
                        pat.replace('_', " ")
                    ));
                }
                (Some("dead"), _) => {
                    parts.push("No DOM changes, network requests, or ARIA state updates were observed after clicking.".to_string());
                }
                (Some("weak_response"), _) => {
                    parts.push(
                        "A DOM mutation was detected but no visible UI change was captured."
                            .to_string(),
                    );
                }
                (Some("needs_verification"), _) => {
                    parts.push("The element may require preconditions (e.g., form input, selection) or produce effects not detectable by automated testing.".to_string());
                }
                _ => {
                    parts.push("No observable effect after clicking.".to_string());
                }
            }
            if let Some(ref hint) = precondition_hint {
                parts.push(format!("Note: {hint}."));
            }
            parts.join(" ")
        };
        let bug = Bug {
            id: self.next_id(),
            severity,
            confidence,
            category: BugCategory::DeadButton {
                selector: selector.clone(),
                label,
                precondition_hint,
                precondition_satisfied,
                pre_click_pattern,
                classification,
            },
            title,
            description,
            remediation: None,
            location: BugLocation {
                view,
                element: Some(selector),
                url,
            },
            reproduction: Vec::new(),
            evidence: BugEvidence {
                action_ids: action_id.into_iter().collect(),
                ..BugEvidence::default()
            },
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_performance_issue(
        &self,
        metric: String,
        value: f64,
        threshold: f64,
        view: Option<String>,
        url: Option<String>,
    ) {
        let severity = if metric == "CLS" && value > threshold * 2.0 {
            BugSeverity::High
        } else if value > threshold * 2.0 {
            BugSeverity::Medium
        } else {
            BugSeverity::Low
        };
        let bug = Bug {
            id: self.next_id(),
            severity,
            confidence: Some(0.80),
            category: BugCategory::PerformanceIssue {
                metric: metric.clone(),
                value,
                threshold,
            },
            title: format!("{metric} exceeds threshold"),
            description: format!("{metric} = {value:.1} (threshold: {threshold:.1})"),
            remediation: None,
            location: BugLocation {
                view,
                element: None,
                url,
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_n_plus_one(
        &self,
        endpoint: String,
        method: String,
        call_count: usize,
        view: Option<String>,
        url: Option<String>,
    ) {
        let bug = Bug {
            id: self.next_id(),
            severity: BugSeverity::Medium,
            confidence: Some(0.80),
            category: BugCategory::PerformanceIssue {
                metric: "N+1 API".into(),
                value: call_count as f64,
                threshold: 3.0,
            },
            title: format!("N+1 API pattern: {method} {endpoint}"),
            description: format!(
                "{method} {endpoint} called {call_count} times during page load. \
                 This may indicate an N+1 query pattern."
            ),
            remediation: None,
            location: BugLocation {
                view,
                element: None,
                url,
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_a11y_finding(
        &self,
        category: String,
        wcag_criterion: String,
        impact: AccessibilityImpact,
        description: String,
        selector: Option<String>,
        severity: BugSeverity,
        view: Option<String>,
        url: Option<String>,
    ) {
        let bug = Bug {
            id: self.next_id(),
            severity,
            confidence: Some(0.75),
            category: BugCategory::AccessibilityViolation {
                category: category.clone(),
                wcag_criterion: wcag_criterion.clone(),
                impact,
            },
            title: format!("Accessibility: {category}"),
            description,
            remediation: None,
            location: BugLocation {
                view,
                element: selector,
                url,
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_form_fuzz_finding(
        &self,
        payload_value: String,
        payload_category: String,
        payload_description: String,
        validation_result: String,
        severity: BugSeverity,
        field_selector: Option<String>,
        view: Option<String>,
        url: Option<String>,
        source_trace_id: Option<String>,
    ) {
        let (cwe, owasp) = form_fuzz_compliance_tags(&payload_category, &validation_result);
        let field_desc = field_selector.as_deref().unwrap_or("<field>").to_string();
        let mut reproduction = vec![
            "1. Replay the HTTP request for this endpoint".to_string(),
            format!("2. Set `{field_desc}` = {payload_value}"),
            format!("3. Observe: {validation_result}"),
        ];
        if let Some(tid) = source_trace_id {
            reproduction.push(format!("Source trace: {tid}"));
        }

        let bug = Bug {
            id: self.next_id(),
            severity,
            confidence: Some(0.60),
            category: BugCategory::SecurityObservation {
                description: format!(
                    "Form fuzzing: {payload_category} payload {validation_result}"
                ),
            },
            title: format!("Form validation: {payload_category} — {validation_result}"),
            description: format!(
                "Payload \"{payload_value}\" ({payload_description}) was {validation_result} by the server."
            ),
            remediation: None,
            location: BugLocation {
                view,
                element: field_selector,
                url,
            },
            reproduction,
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe,
            owasp,
        };
        self.record(bug).await;
    }

    pub async fn record_unexpected_redirect(
        &self,
        requested_url: String,
        landed_url: String,
        redirect_kind: String,
    ) {
        let bug = Bug {
            id: self.next_id(),
            severity: BugSeverity::Info,
            confidence: Some(0.70),
            category: BugCategory::UnexpectedRedirect {
                requested_url: requested_url.clone(),
                landed_url: landed_url.clone(),
                redirect_kind: redirect_kind.clone(),
            },
            title: format!("Unexpected redirect ({redirect_kind})"),
            description: format!(
                "Navigated to {requested_url} but landed on {landed_url} ({redirect_kind} redirect)."
            ),
            remediation: Some(
                "Set `target.locale` in your config to control the Accept-Language header \
                 and prevent locale-based redirects."
                    .to_string(),
            ),
            location: BugLocation {
                view: None,
                element: None,
                url: Some(requested_url),
            },
            reproduction: vec![
                format!("Navigate to the requested URL"),
                format!("Observe redirect to {landed_url}"),
            ],
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_server_error(&self, endpoint: String, status: u16, body: Option<String>) {
        let bug = Bug {
            id: self.next_id(),
            severity: BugSeverity::Medium,
            confidence: Some(0.95),
            category: BugCategory::ServerError {
                endpoint: endpoint.clone(),
                status,
                response: body.clone(),
            },
            title: format!("Server error ({status})"),
            description: format!("{endpoint} returned HTTP {status}."),
            remediation: None,
            location: BugLocation {
                view: None,
                element: None,
                // Record the failing endpoint as the triggering route so the
                // evidence bundle is judged complete, matching record_api_error
                // and record_network_request_failure.
                url: Some(endpoint),
            },
            reproduction: Vec::new(),
            evidence: BugEvidence {
                console_log: Vec::new(),
                dom_snapshot: None,
                screenshot: None,
                network_log: Vec::new(),
                action_ids: Vec::new(),
                route_context: None,
            },
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_api_error(&self, endpoint: String, status: u16, body: Option<String>) {
        let bug = Bug {
            id: self.next_id(),
            severity: match status {
                500..=599 => BugSeverity::High,
                400..=499 => BugSeverity::Medium,
                _ => BugSeverity::Low,
            },
            confidence: Some(0.90),
            category: BugCategory::ApiError {
                endpoint: endpoint.clone(),
                status,
                response: body.clone(),
            },
            title: format!("Action-triggered API error ({status})"),
            description: format!("{endpoint} returned HTTP {status} after a browser interaction."),
            remediation: Some(
                "Reproduce the interaction, inspect the request payload, and return a useful success or handled error response."
                    .to_string(),
            ),
            location: BugLocation {
                view: None,
                element: None,
                url: Some(endpoint),
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_network_request_failure(&self, endpoint: String, failure: String) {
        let bug = Bug {
            id: self.next_id(),
            severity: BugSeverity::Medium,
            confidence: Some(0.85),
            category: BugCategory::NetworkRequestFailure {
                endpoint: endpoint.clone(),
                failure: failure.clone(),
            },
            title: "Browser request failed".to_string(),
            description: format!("{endpoint} failed in the browser network stack: {failure}."),
            remediation: Some(
                "Check CORS, DNS/connectivity, mixed-content policy, and blocked egress for the failed browser request."
                    .to_string(),
            ),
            location: BugLocation {
                view: None,
                element: None,
                url: Some(endpoint),
            },
            reproduction: Vec::new(),
            evidence: BugEvidence::default(),
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_ui_error_toast(
        &self,
        url: Option<String>,
        view: Option<String>,
        element: String,
        label: Option<String>,
        toast_selector: Option<String>,
        message: String,
        action_id: Option<String>,
    ) {
        let preview = first_line_preview(&message, 120);
        let control_desc = label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|l| format!("`{l}` (`{element}`)"))
            .unwrap_or_else(|| format!("`{element}`"));
        let lower = message.to_ascii_lowercase();
        let severity = if lower.contains("internal server error")
            || lower.contains("500")
            || lower.contains("lacks permission")
            || lower.contains("permission denied")
            || lower.contains("unauthorized")
            || lower.contains("forbidden")
        {
            BugSeverity::High
        } else {
            BugSeverity::Medium
        };
        let mut reproduction = Vec::new();
        if let Some(ref u) = url {
            reproduction.push(format!("Visit {u}"));
        }
        reproduction.push(format!("Interact with {element}"));
        reproduction.push(format!("Observe error toast/alert: {preview}"));

        let mut evidence = BugEvidence::default();
        if let Some(aid) = action_id {
            evidence.action_ids.push(aid);
        }

        let bug = Bug {
            id: self.next_id(),
            severity,
            confidence: Some(0.88),
            category: BugCategory::UiErrorToast {
                message: message.clone(),
                selector: toast_selector,
            },
            title: format!("UI error toast after interacting with {control_desc}: {preview}"),
            description: format!(
                "Interacting with {control_desc} surfaced a visible error notification: \"{message}\"."
            ),
            remediation: Some(
                "Inspect the action handler and backend response for the error shown in the toast, and either fix the failing operation or gate/disable the control when the current session lacks permission."
                    .to_string(),
            ),
            location: BugLocation {
                view,
                element: Some(element),
                url,
            },
            reproduction,
            evidence,
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }

    pub async fn record_websocket_error(
        &self,
        endpoint: String,
        message: String,
        view: Option<String>,
        element: Option<String>,
        page_url: Option<String>,
        action_id: Option<String>,
    ) {
        let preview = first_line_preview(&message, 120);
        let mut reproduction = Vec::new();
        if let Some(ref u) = page_url {
            reproduction.push(format!("Visit {u}"));
        }
        if let Some(ref el) = element {
            reproduction.push(format!("Interact with {el}"));
        }
        reproduction.push(format!("Observe WebSocket error on {endpoint}: {preview}"));

        let mut evidence = BugEvidence::default();
        if let Some(aid) = action_id {
            evidence.action_ids.push(aid);
        }

        let bug = Bug {
            id: self.next_id(),
            severity: BugSeverity::High,
            confidence: Some(0.88),
            category: BugCategory::WebSocketError {
                endpoint: endpoint.clone(),
                message: message.clone(),
            },
            title: format!("WebSocket error on {endpoint}: {preview}"),
            description: format!(
                "WebSocket endpoint `{endpoint}` returned an error frame: \"{message}\"."
            ),
            remediation: Some(
                "Inspect the WebSocket RPC/message handler for this request and verify permissions, payload schema, and error handling."
                    .to_string(),
            ),
            location: BugLocation {
                view,
                element,
                url: page_url.or(Some(endpoint)),
            },
            reproduction,
            evidence,
            discovered_at: chrono::Utc::now(),
            cwe: None,
            owasp: None,
        };
        self.record(bug).await;
    }
}

fn first_line_preview(s: &str, max_chars: usize) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        collapsed
    } else {
        let mut out: String = collapsed.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

fn form_fuzz_compliance_tags(
    payload_category: &str,
    validation_result: &str,
) -> (Option<String>, Option<String>) {
    let cat = payload_category.to_ascii_lowercase();
    let result = validation_result.to_ascii_lowercase();
    if result == "rejected" {
        return (None, None);
    }
    if cat.contains("sql") {
        return (
            Some("CWE-89".to_string()),
            Some("A03:2021 Injection".to_string()),
        );
    }
    if cat.contains("xss") {
        return (
            Some("CWE-79".to_string()),
            Some("A03:2021 Injection".to_string()),
        );
    }
    if cat.contains("command") {
        return (
            Some("CWE-77".to_string()),
            Some("A03:2021 Injection".to_string()),
        );
    }
    (None, None)
}

fn parse_bug_id(id: &str) -> Option<usize> {
    let s = id.strip_prefix("BUG-")?;
    s.parse::<usize>().ok()
}

fn is_probable_noop_sidebar_or_placeholder_nav(selector: &str, label: Option<&str>) -> bool {
    let selector_lc = selector.to_ascii_lowercase();
    let label_lc = label.unwrap_or("").trim().to_ascii_lowercase();
    let selector_says_nav = [
        "sidebar", "side-nav", "sidenav", "nav", "menu", "tabbar", "tabs",
    ]
    .iter()
    .any(|term| selector_lc.contains(term));
    let label_says_current_or_section = [
        "dashboard",
        "home",
        "overview",
        "summary",
        "settings",
        "profile",
        "reports",
    ]
    .iter()
    .any(|term| label_lc.contains(term));
    let selector_says_active = ["active", "current", "selected"]
        .iter()
        .any(|term| selector_lc.contains(term));

    (selector_says_nav && label_says_current_or_section) || selector_says_active
}

fn console_event_message(ev: &runtime::EventConsoleApiCalled) -> String {
    // Best-effort: stringify args that have a value.
    let mut parts: Vec<String> = Vec::new();
    for a in &ev.args {
        if let Some(v) = &a.value {
            parts.push(v.to_string());
        } else if let Some(desc) = &a.description {
            parts.push(desc.clone());
        }
    }
    if parts.is_empty() {
        "console.error".to_string()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::bugs::{BugEvidence, BugLocation, BugSeverity};

    fn make_test_bug(id: &str, category: BugCategory) -> Bug {
        Bug {
            id: id.to_string(),
            severity: BugSeverity::Medium,
            confidence: None,
            category,
            title: "test".to_string(),
            description: "test".to_string(),
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
    fn next_id_starts_at_one() {
        let d = BugDetector::new();
        assert_eq!(d.next_id(), "BUG-0001");
        assert_eq!(d.next_id(), "BUG-0002");
        assert_eq!(d.next_id(), "BUG-0003");
    }

    #[test]
    fn next_id_format_is_padded() {
        let d = BugDetector::new();
        let id = d.next_id();
        assert!(id.starts_with("BUG-"));
        assert_eq!(id.len(), 8); // "BUG-XXXX"
    }

    #[test]
    fn from_existing_resumes_sequence() {
        let bugs = vec![
            make_test_bug(
                "BUG-0005",
                BugCategory::DeadButton {
                    selector: "#a".into(),
                    label: None,
                    precondition_hint: None,
                    precondition_satisfied: None,
                    pre_click_pattern: None,
                    classification: None,
                },
            ),
            make_test_bug(
                "BUG-0010",
                BugCategory::DeadButton {
                    selector: "#b".into(),
                    label: None,
                    precondition_hint: None,
                    precondition_satisfied: None,
                    pre_click_pattern: None,
                    classification: None,
                },
            ),
        ];
        let d = BugDetector::from_existing(bugs);
        // Should start after the highest existing ID (10)
        assert_eq!(d.next_id(), "BUG-0011");
    }

    #[test]
    fn from_existing_empty_starts_at_one() {
        let d = BugDetector::from_existing(Vec::new());
        assert_eq!(d.next_id(), "BUG-0001");
    }

    #[tokio::test]
    async fn record_and_snapshot() {
        let d = BugDetector::new();
        assert!(d.bugs_snapshot().await.is_empty());

        d.record(make_test_bug(
            "",
            BugCategory::ConsoleError {
                message: "test error".into(),
                source: None,
            },
        ))
        .await;

        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        // Empty ID should be auto-assigned
        assert!(bugs[0].id.starts_with("BUG-"));
    }

    #[tokio::test]
    async fn record_preserves_explicit_id() {
        let d = BugDetector::new();
        d.record(make_test_bug(
            "CUSTOM-001",
            BugCategory::Other {
                description: "x".into(),
            },
        ))
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs[0].id, "CUSTOM-001");
    }

    #[tokio::test]
    async fn record_broken_link() {
        let d = BugDetector::new();
        d.record_broken_link("https://example.com/missing".to_string(), 404)
            .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert!(bugs[0].title.contains("404"));
        match &bugs[0].category {
            BugCategory::BrokenLink { url, status } => {
                assert_eq!(url, "https://example.com/missing");
                assert_eq!(*status, 404);
            }
            _ => panic!("expected BrokenLink category"),
        }
    }

    #[tokio::test]
    async fn record_dead_button() {
        let d = BugDetector::new();
        d.record_dead_button(
            Some("https://example.com".into()),
            None,
            "#submit-btn".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        // No classification provided → default Low
        assert_eq!(bugs[0].severity, BugSeverity::Low);
        match &bugs[0].category {
            BugCategory::DeadButton {
                selector,
                precondition_hint,
                ..
            } => {
                assert_eq!(selector, "#submit-btn");
                assert!(precondition_hint.is_none());
            }
            _ => panic!("expected DeadButton category"),
        }
    }

    #[tokio::test]
    async fn record_dead_button_with_precondition() {
        let d = BugDetector::new();
        d.record_dead_button(
            Some("https://example.com".into()),
            None,
            "#save-btn".into(),
            None,
            Some("button is inside form with 2 empty required field(s)".into()),
            Some(false),
            None,
            None,
            None,
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Info);
        match &bugs[0].category {
            BugCategory::DeadButton {
                selector,
                precondition_hint,
                ..
            } => {
                assert_eq!(selector, "#save-btn");
                assert!(precondition_hint.is_some());
            }
            _ => panic!("expected DeadButton category"),
        }
    }

    #[tokio::test]
    async fn record_dead_button_severity_high_for_dead_recognized_pattern() {
        let d = BugDetector::new();
        d.record_dead_button(
            Some("https://example.com".into()),
            None,
            "#faq-btn".into(),
            Some("FAQ Toggle".into()),
            None,
            None,
            None,
            Some("accordion".into()),
            Some("dead".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert!(bugs[0].title.contains("accordion"));
    }

    #[tokio::test]
    async fn record_dead_button_severity_medium_for_dead_unknown_pattern() {
        let d = BugDetector::new();
        d.record_dead_button(
            Some("https://example.com".into()),
            None,
            "#mystery-btn".into(),
            None,
            None,
            None,
            None,
            None,
            Some("dead".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Medium);
    }

    #[tokio::test]
    async fn record_dead_sidebar_dashboard_button_as_low_suspected() {
        let d = BugDetector::new();
        d.record_dead_button(
            Some("http://localhost:9099/".into()),
            None,
            "button.sidebar-nav-dashboard".into(),
            Some("⌂ Dashboard".into()),
            None,
            Some(true),
            None,
            Some("unknown".into()),
            Some("dead".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Low);
        assert!(bugs[0].confidence.unwrap() <= 0.55);

        let judgment = crate::finding_judgment::judgment_for_bug(&bugs[0]);
        assert_eq!(judgment.judgment, "suspected");
        assert_eq!(judgment.confidence_label, "low");
    }

    #[tokio::test]
    async fn record_dead_button_severity_info_for_needs_verification() {
        let d = BugDetector::new();
        d.record_dead_button(
            Some("https://example.com".into()),
            None,
            "#tab-btn".into(),
            Some("Tab 1".into()),
            None,
            None,
            None,
            Some("tab".into()),
            Some("needs_verification".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Info);
        // Confidence capped at 0.4 for needs_verification
        assert!(bugs[0].confidence.unwrap() <= 0.4);
    }

    #[tokio::test]
    async fn record_dead_button_severity_low_for_weak_response() {
        let d = BugDetector::new();
        d.record_dead_button(
            Some("https://example.com".into()),
            None,
            "#toggle-btn".into(),
            None,
            None,
            None,
            None,
            None,
            Some("weak_response".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Low);
    }

    #[tokio::test]
    async fn record_server_error() {
        let d = BugDetector::new();
        d.record_server_error(
            "/api/users".into(),
            500,
            Some("Internal Server Error".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Medium);
        match &bugs[0].category {
            BugCategory::ServerError {
                endpoint,
                status,
                response,
            } => {
                assert_eq!(endpoint, "/api/users");
                assert_eq!(*status, 500);
                assert_eq!(response.as_deref(), Some("Internal Server Error"));
            }
            _ => panic!("expected ServerError category"),
        }
        // Regression: server_error must record the failing endpoint as the
        // triggering route (location.url), exactly like api_error and
        // network_request_failure do. The completeness assessor derives
        // `triggering_route = location.url.is_some()`, so a None here made every
        // critical 500 the lone "incomplete evidence" finding in a scan.
        assert_eq!(
            bugs[0].location.url.as_deref(),
            Some("/api/users"),
            "server_error must populate location.url with the failing endpoint"
        );
    }

    #[tokio::test]
    async fn multiple_records_sequential_ids() {
        let d = BugDetector::new();
        d.record_broken_link("a".into(), 404).await;
        d.record_broken_link("b".into(), 404).await;
        d.record_broken_link("c".into(), 404).await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 3);
        assert_eq!(bugs[0].id, "BUG-0001");
        assert_eq!(bugs[1].id, "BUG-0002");
        assert_eq!(bugs[2].id, "BUG-0003");
    }

    #[tokio::test]
    async fn record_performance_issue_low_severity() {
        let d = BugDetector::new();
        d.record_performance_issue(
            "LCP".into(),
            3000.0,
            2500.0,
            Some("view_0001".into()),
            Some("https://example.com".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Low);
        assert!(bugs[0].title.contains("LCP"));
        match &bugs[0].category {
            BugCategory::PerformanceIssue {
                metric,
                value,
                threshold,
            } => {
                assert_eq!(metric, "LCP");
                assert!((value - 3000.0).abs() < f64::EPSILON);
                assert!((threshold - 2500.0).abs() < f64::EPSILON);
            }
            _ => panic!("expected PerformanceIssue category"),
        }
    }

    #[tokio::test]
    async fn record_performance_issue_high_severity_when_double_threshold() {
        let d = BugDetector::new();
        // CLS > threshold * 2 → High
        d.record_performance_issue("CLS".into(), 0.3, 0.1, None, None)
            .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs[0].severity, BugSeverity::High);
    }

    #[tokio::test]
    async fn record_n_plus_one() {
        let d = BugDetector::new();
        d.record_n_plus_one(
            "/api/users/:id".into(),
            "GET".into(),
            5,
            Some("view_0001".into()),
            Some("https://example.com/users".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Medium);
        assert!(bugs[0].title.contains("N+1"));
        assert!(bugs[0].description.contains("5 times"));
        match &bugs[0].category {
            BugCategory::PerformanceIssue { metric, value, .. } => {
                assert_eq!(metric, "N+1 API");
                assert!((value - 5.0).abs() < f64::EPSILON);
            }
            _ => panic!("expected PerformanceIssue category"),
        }
    }

    #[test]
    fn parse_bug_id_valid() {
        assert_eq!(parse_bug_id("BUG-0001"), Some(1));
        assert_eq!(parse_bug_id("BUG-0099"), Some(99));
        assert_eq!(parse_bug_id("BUG-1234"), Some(1234));
    }

    #[test]
    fn parse_bug_id_invalid() {
        assert_eq!(parse_bug_id("CUSTOM-001"), None);
        assert_eq!(parse_bug_id("BUG-"), None);
        assert_eq!(parse_bug_id(""), None);
        assert_eq!(parse_bug_id("BUG-abc"), None);
    }

    #[tokio::test]
    async fn record_a11y_finding() {
        let d = BugDetector::new();
        d.record_a11y_finding(
            "missing_alt_text".into(),
            "1.1.1".into(),
            crate::types::bugs::AccessibilityImpact::Critical,
            "Image missing alt text".into(),
            Some("img[src=\"logo.png\"]".into()),
            BugSeverity::High,
            Some("view_0001".into()),
            Some("https://example.com".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert!(bugs[0].title.contains("Accessibility"));
        assert!(bugs[0].title.contains("missing_alt_text"));
        match &bugs[0].category {
            BugCategory::AccessibilityViolation {
                wcag_criterion,
                impact,
                ..
            } => {
                assert_eq!(wcag_criterion, "1.1.1");
                assert_eq!(*impact, crate::types::bugs::AccessibilityImpact::Critical);
            }
            _ => panic!("expected AccessibilityViolation category"),
        }
        assert_eq!(bugs[0].location.view.as_deref(), Some("view_0001"));
        assert_eq!(
            bugs[0].location.element.as_deref(),
            Some("img[src=\"logo.png\"]")
        );
    }

    #[tokio::test]
    async fn record_a11y_finding_without_selector() {
        let d = BugDetector::new();
        d.record_a11y_finding(
            "missing_lang".into(),
            "3.1.1".into(),
            crate::types::bugs::AccessibilityImpact::Serious,
            "Document missing lang attribute".into(),
            None,
            BugSeverity::Medium,
            None,
            Some("https://example.com".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::Medium);
        assert!(bugs[0].location.element.is_none());
    }

    #[tokio::test]
    async fn record_form_fuzz_finding() {
        let d = BugDetector::new();
        d.record_form_fuzz_finding(
            "<script>alert(1)</script>".into(),
            "Xss".into(),
            "Basic script injection".into(),
            "Reflected".into(),
            BugSeverity::High,
            Some("input[name=\"search\"]".into()),
            Some("view_0001".into()),
            Some("https://example.com/search".into()),
            Some("trace-123".into()),
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert!(bugs[0].title.contains("Xss"));
        assert!(bugs[0].title.contains("Reflected"));
        assert!(bugs[0].description.contains("<script>alert(1)</script>"));
        assert!(bugs[0].reproduction.iter().any(|l| l.contains("trace-123")));
        assert_eq!(bugs[0].cwe.as_deref(), Some("CWE-79"));
        assert_eq!(bugs[0].owasp.as_deref(), Some("A03:2021 Injection"));
        match &bugs[0].category {
            BugCategory::SecurityObservation { description } => {
                assert!(description.contains("Form fuzzing"));
            }
            _ => panic!("expected SecurityObservation category"),
        }
    }

    #[tokio::test]
    async fn record_form_fuzz_finding_server_error() {
        let d = BugDetector::new();
        d.record_form_fuzz_finding(
            "' OR '1'='1".into(),
            "SqlInjection".into(),
            "Classic SQL OR injection".into(),
            "ServerError".into(),
            BugSeverity::High,
            Some("input[name=\"id\"]".into()),
            Some("view_0002".into()),
            Some("https://example.com/users".into()),
            None,
        )
        .await;
        let bugs = d.bugs_snapshot().await;
        assert_eq!(bugs.len(), 1);
        assert_eq!(bugs[0].severity, BugSeverity::High);
        assert!(bugs[0].title.contains("SqlInjection"));
        assert!(bugs[0].title.contains("ServerError"));
        assert_eq!(bugs[0].cwe.as_deref(), Some("CWE-89"));
        assert_eq!(bugs[0].owasp.as_deref(), Some("A03:2021 Injection"));
    }

    #[test]
    fn action_window_collects_console_errors_and_dialogs() {
        let d = BugDetector::new();
        let tab = TabKey::from_raw("TAB-A");
        assert!(
            d.attribute_console_message(&tab, "before any action", false)
                .is_none()
        );

        d.begin_action(&tab, "act-1", "view_0001", "#boom");
        let attribution = d
            .attribute_console_message(
                &tab,
                "Error: boom\n    at HTMLButtonElement.onclick (http://x.test/:12:9)",
                true,
            )
            .expect("attributed while action is running");
        assert_eq!(attribution.action_id, "act-1");
        assert_eq!(attribution.view, "view_0001");
        assert_eq!(attribution.element, "#boom");
        d.note_native_dialog(&tab, "confirm: Really?");

        // Ending a different action leaves the current one in place.
        assert_eq!(d.end_action(&tab, "act-other"), ActionCapture::default());
        let capture = d.end_action(&tab, "act-1");
        assert_eq!(
            capture.console_errors,
            vec!["Error: boom @ at HTMLButtonElement.onclick (http://x.test/:12:9)".to_string()]
        );
        assert_eq!(capture.exceptions.len(), 1);
        assert_eq!(capture.native_dialog.as_deref(), Some("confirm: Really?"));

        // After the action ends nothing is attributed.
        assert!(d.attribute_console_message(&tab, "late", false).is_none());
        assert_eq!(d.end_action(&tab, "act-1"), ActionCapture::default());
    }

    #[test]
    fn action_windows_are_kept_per_tab() {
        let d = BugDetector::new();
        let (a, b) = (TabKey::from_raw("TAB-A"), TabKey::from_raw("TAB-B"));
        d.begin_action(&a, "act-a", "view_0001", "#save");
        d.begin_action(&b, "act-b", "view_0002", "#load");

        // A console error on one tab is credited to that tab's action only.
        let on_b = d
            .attribute_console_message(&b, "TypeError: b failed", true)
            .expect("tab B has a running action");
        assert_eq!(on_b.action_id, "act-b");
        assert_eq!(on_b.view, "view_0002");
        let on_a = d
            .attribute_console_message(&a, "Error: a failed", false)
            .expect("tab A has a running action");
        assert_eq!(on_a.action_id, "act-a");
        // A tab without an action attributes nothing, even while others run.
        assert!(
            d.attribute_console_message(&TabKey::from_raw("TAB-C"), "Error: c", false)
                .is_none()
        );
        d.note_native_dialog(&b, "alert: from b");

        // Ending an action on the wrong tab returns nothing and ends nothing.
        assert_eq!(d.end_action(&a, "act-b"), ActionCapture::default());
        let capture_a = d.end_action(&a, "act-a");
        assert_eq!(
            capture_a.console_errors,
            vec!["Error: a failed".to_string()]
        );
        assert!(capture_a.exceptions.is_empty());
        assert!(capture_a.native_dialog.is_none());
        let capture_b = d.end_action(&b, "act-b");
        assert_eq!(
            capture_b.console_errors,
            vec!["TypeError: b failed".to_string()]
        );
        assert_eq!(capture_b.exceptions.len(), 1);
        assert_eq!(capture_b.native_dialog.as_deref(), Some("alert: from b"));
        assert!(d.lock_actions().is_empty());
    }

    #[test]
    fn attributed_location_sets_view_element_and_action_id() {
        let (loc, ev) = attributed_location(
            Some("http://x.test/#/a".into()),
            Some(ActionAttribution {
                action_id: "act-9".into(),
                view: "view_0002".into(),
                element: "button.save".into(),
            }),
        );
        assert_eq!(loc.view.as_deref(), Some("view_0002"));
        assert_eq!(loc.element.as_deref(), Some("button.save"));
        assert_eq!(ev.action_ids, vec!["act-9".to_string()]);

        let (loc, ev) = attributed_location(None, None);
        assert!(loc.view.is_none() && loc.element.is_none());
        assert!(ev.action_ids.is_empty());
    }
}

/// Location/evidence for a console finding, attributed to the running action
/// when there is one.
fn attributed_location(
    url: Option<String>,
    attribution: Option<ActionAttribution>,
) -> (BugLocation, BugEvidence) {
    match attribution {
        Some(a) => (
            BugLocation {
                view: Some(a.view),
                element: Some(a.element),
                url,
            },
            BugEvidence {
                action_ids: vec![a.action_id],
                ..Default::default()
            },
        ),
        None => (
            BugLocation {
                view: None,
                element: None,
                url,
            },
            BugEvidence::default(),
        ),
    }
}

/// One-line summary of a console message or exception: the first line, plus
/// the first stack frame when present (`Error: boom @ at onClick (app.js:4:9)`).
fn summarize_console_message(message: &str) -> String {
    let mut lines = message.lines().map(str::trim).filter(|l| !l.is_empty());
    let head = lines.next().unwrap_or("").to_string();
    let summary = match lines.find(|l| l.starts_with("at ")) {
        Some(frame) => format!("{head} @ {frame}"),
        None => head,
    };
    truncate_chars(&summary, MAX_ACTION_MESSAGE_CHARS)
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn exception_message(ev: &runtime::EventExceptionThrown) -> String {
    let details = &ev.exception_details;
    if let Some(ex) = &details.exception {
        if let Some(desc) = &ex.description {
            return desc.clone();
        }
    }
    details.text.clone()
}
