use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use url::Url;
use uuid::Uuid;

use crate::browser::{PageClient, cdp_helpers};
use crate::bugs::BugDetector;
use crate::bugs::detector::ActionCapture;
use crate::config::{BrokenAppConfig, ScanConfig, WriteGuardMode};
use crate::dom::classifier::{canonical_selector, closest_form_selector};
use crate::dom::interaction::{
    InteractionEffect, InteractionObservation, NativeControlState, Prepared,
};
use crate::dom::interaction_signals::{
    InteractionClassification, PreClickPattern, classify_interaction, detect_pre_click_pattern,
    is_button_like,
};
use crate::dom::selector::{LOCATOR_RUNTIME_JS, primary_locator_json};
use crate::network::interceptor::NetworkInterceptor;
use crate::output::checkpoint::PendingTransition;
use crate::output::interactions::{InteractionLog, InteractionOutcome, InteractionRecord};
use crate::scope::ScopeFilter;
use crate::types::api::EndpointKey;
use crate::types::classifier::{ClassifiedView, ComponentType};
use crate::types::dom::{
    ElementType, InteractionRef, InteractionResult, InteractionSnapshot, InteractiveElement,
};
use crate::types::graph::{DomFingerprint, TransitionType};

use super::{SharedState, lock_state};

#[derive(Debug, Clone)]
pub(super) struct FormActionInteraction {
    pub(super) trigger: InteractionRef,
    pub(super) form_selector: String,
    pub(super) submit_label: Option<String>,
}

/// A sub-view discovered during deep exploration (e.g., a modal's contents).
#[derive(Debug, Clone)]
pub(super) struct SubView {
    pub(super) id: String,
    pub(super) parent_view: String,
    pub(super) depth: usize,
    pub(super) trigger_selector: String,
    pub(super) transition_type: TransitionType,
    pub(super) elements: Vec<InteractiveElement>,
    pub(super) api_calls: Vec<EndpointKey>,
    pub(super) snapshot: Option<InteractionSnapshot>,
    pub(super) fingerprint: Option<DomFingerprint>,
}

#[derive(Default)]
pub(super) struct InteractionPassOutput {
    pub(super) selector_query_params: HashMap<String, BTreeSet<String>>,
    pub(super) form_action_interactions: Vec<FormActionInteraction>,
    pub(super) skipped_interactions: Vec<SkippedInteraction>,
    pub(super) interaction_snapshots: HashMap<String, InteractionSnapshot>,
    pub(super) budget_exhausted: bool,
    pub(super) sub_views: Vec<SubView>,
    pub(super) deep_transitions: Vec<PendingTransition>,
    /// Same-origin links that became visible after a click (off-canvas
    /// sidenavs, menus) and were not known when the view was discovered.
    pub(super) revealed_links: Vec<InteractiveElement>,
    /// Per-selector outcome for `InteractiveElement::interaction_result`.
    pub(super) interaction_results: HashMap<String, InteractionResult>,
}

#[derive(Debug, Clone)]
pub(super) struct SkippedInteraction {
    pub(super) selector: String,
    pub(super) reason: String,
    pub(super) label: Option<String>,
}

#[derive(Debug)]
pub(super) struct AdaptiveRateLimitPacer {
    base_delay_ms: u64,
    current_delay_ms: u64,
    cap_delay_ms: u64,
    interactions_without_429: usize,
    last_rate_limit_total: usize,
}

impl AdaptiveRateLimitPacer {
    pub(super) fn new(base_delay_ms: u64, network: &NetworkInterceptor) -> Self {
        Self {
            base_delay_ms,
            current_delay_ms: base_delay_ms,
            cap_delay_ms: 5_000u64.max(base_delay_ms),
            interactions_without_429: 0,
            last_rate_limit_total: network.rate_limit_total(),
        }
    }

    pub(super) async fn after_interaction(&mut self, network: &NetworkInterceptor) {
        let total = network.rate_limit_total();
        if total > self.last_rate_limit_total {
            let delta = total.saturating_sub(self.last_rate_limit_total);
            self.last_rate_limit_total = total;
            self.interactions_without_429 = 0;

            let mut next = self.current_delay_ms;
            for _ in 0..delta {
                next = next.saturating_mul(2).min(self.cap_delay_ms);
            }

            if let Some(retry_after) = network.last_rate_limit_retry_after() {
                let retry_after_ms: u64 = retry_after
                    .as_millis()
                    .try_into()
                    .unwrap_or(self.cap_delay_ms);
                next = next.max(retry_after_ms.min(self.cap_delay_ms));
            }

            if next != self.current_delay_ms {
                self.current_delay_ms = next;
                tracing::warn!(
                    delay_ms = self.current_delay_ms,
                    recent_429 = network.recent_rate_limit_count(Duration::from_secs(60)),
                    "target returned HTTP 429; backing off interaction pacing"
                );
            } else {
                tracing::warn!(
                    delay_ms = self.current_delay_ms,
                    recent_429 = network.recent_rate_limit_count(Duration::from_secs(60)),
                    "target returned HTTP 429; interaction pacing already at cap"
                );
            }
        } else {
            self.interactions_without_429 = self.interactions_without_429.saturating_add(1);
            if self.interactions_without_429 >= 10 && self.current_delay_ms != self.base_delay_ms {
                self.current_delay_ms = self.base_delay_ms;
                self.interactions_without_429 = 0;
                tracing::info!(
                    delay_ms = self.current_delay_ms,
                    "no recent rate limiting; resetting interaction pacing"
                );
            }
        }

        // Base pacing occurs inside `dom::interaction::interact` via ScanConfig.
        // When rate limiting is observed, add extra delay so the effective
        // per-interaction pacing matches `current_delay_ms`.
        let extra_ms = self.current_delay_ms.saturating_sub(self.base_delay_ms);
        if extra_ms > 0 {
            tokio::time::sleep(Duration::from_millis(extra_ms)).await;
        }
    }
}

/// Scan-wide memory of exercise claims, keyed by [`exercise_identity_key`].
/// Value-changing fields are local to their base view. Other shell controls
/// are keyed scan-wide; other page-content controls per route template.
pub(super) type ExercisedControls = HashMap<String, ExercisedControl>;

#[derive(Debug, Clone)]
pub(super) struct ExercisedControl {
    /// View where the control was exercised (or is being exercised).
    pub(super) view_id: String,
    /// Whether exercising it navigated away from that view.
    pub(super) navigated: bool,
    /// Claimed by a view that is about to exercise it ([`claim_control`]),
    /// not exercised yet. Other tabs leave it to that view; the claim is
    /// dropped when the control turns out not to be exercisable there.
    pub(super) claimed: bool,
}

/// At most this many controls with the same identity (repeated cards, list
/// rows) are exercised per view; the rest are recorded as `repeated_control`.
const MAX_REPEATED_CONTROLS_PER_VIEW: usize = 2;
/// Stop starting new interactions when less than this remains before the
/// view's interaction deadline.
const MIN_INTERACTION_WINDOW: Duration = Duration::from_millis(1_000);
/// Upper bound for re-loading the view URL after a control navigated away.
const RESTORE_NAVIGATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared, per-view inputs to [`run_interaction_pass`].
#[derive(Clone)]
pub(super) struct PassContext<'a> {
    pub(super) page: &'a PageClient,
    pub(super) cfg: &'a BrokenAppConfig,
    pub(super) network: &'a Arc<NetworkInterceptor>,
    pub(super) bug_detector: &'a Arc<BugDetector>,
    pub(super) base_url: &'a Url,
    pub(super) scope_filter: Option<&'a ScopeFilter>,
    /// Destination for `interactions.jsonl` rows (`None` disables the log).
    pub(super) log: Option<&'a InteractionLog>,
    /// Crawl depth of the view (URLs reached by navigation get depth + 1).
    pub(super) current_depth: usize,
    /// URL of the view (fragment kept). Restored before the next control
    /// whenever an earlier one navigated away.
    pub(super) view_url: &'a str,
    pub(super) classified: &'a ClassifiedView,
    pub(super) deadline: Option<Instant>,
    /// `view::selector` keys of controls another phase already exercised and
    /// recorded (nav dropdown expansion); no `skipped` row is written for them.
    pub(super) recorded_elsewhere: &'a HashSet<String>,
    /// Scope page-content control identities are keyed by: the route
    /// template for instances of a template (`/towns/:slug`), else the route.
    pub(super) identity_scope: &'a str,
    /// 1-based instance number when the view is an instance of a route
    /// template; the first [`FULL_TEMPLATE_INSTANCES`] are exercised fully.
    pub(super) template_instance: Option<usize>,
}

/// Mutable state threaded through [`run_interaction_pass`]: this tab's
/// pacer and link set, and the scan state shared with the other tabs.
pub(super) struct PassState<'a, 's> {
    pub(super) pacer: &'a mut AdaptiveRateLimitPacer,
    /// Queue, scan-wide exercised-controls memory and interaction counter,
    /// shared by every tab of the crawl.
    pub(super) shared: &'a SharedState<'s>,
    /// Normalized link targets already known on this view; links revealed by
    /// a click are diffed against it.
    pub(super) known_links: &'a mut HashSet<String>,
}

/// A control selected for exercising, with its identity for dedupe/ordering.
struct Planned<'e> {
    el: &'e InteractiveElement,
    key: String,
    /// Lives in shell chrome (header/nav/aside/footer outside `main`).
    shell: bool,
    /// Known (from an earlier view) to navigate away when used.
    known_to_navigate: bool,
    submit: bool,
    /// Disabled at discovery; tried last.
    deferred: bool,
    /// Already exercised on a sibling instance of the same route template:
    /// re-exercised only after the controls that were not.
    on_sibling: bool,
    /// Page content of one of the first instances of a route template: it is
    /// exercised here even when a sibling instance exercised it already.
    sibling_reexercise: bool,
    /// Document `<form>` index (`document.forms`) containing this control, or
    /// `None` when outside any `<form>`. Used to scope form-state recovery and
    /// defer standalone search/filter inputs until after non-submit buttons.
    form_index: Option<usize>,
}

/// Instances of a route template exercised fully; later instances only
/// exercise controls not exercised on a sibling yet.
pub(super) const FULL_TEMPLATE_INSTANCES: usize = 3;
/// Share of a pass's remaining time a nested (modal, wizard step) pass gets.
const CHILD_PASS_TIME_SHARE: f64 = 0.6;
/// Minimum time budget for a nested pass (capped at the parent's remaining
/// time) so deep nesting (`0.6^depth`) does not starve child passes.
const MIN_CHILD_PASS_BUDGET: Duration = Duration::from_secs(15);

fn child_pass_budget(left: Duration) -> Duration {
    left.mul_f64(CHILD_PASS_TIME_SHARE)
        .max(MIN_CHILD_PASS_BUDGET)
        .min(left)
}

fn child_pass_deadline(parent_deadline: Option<Instant>) -> Option<Instant> {
    let now = Instant::now();
    parent_deadline.map(|deadline| {
        let left = deadline.saturating_duration_since(now);
        now + child_pass_budget(left)
    })
}

/// Collects coverage-gap skips and writes `interactions.jsonl` rows for one pass.
struct PassRecorder<'a> {
    log: Option<&'a InteractionLog>,
    view_id: &'a str,
    view_url: &'a str,
    skipped: Vec<SkippedInteraction>,
}

impl PassRecorder<'_> {
    fn write(&self, record: &InteractionRecord) {
        write_interaction_record(self.log, record);
    }

    /// Coverage gap only; the control's row is written elsewhere.
    fn gap(&mut self, el: &InteractiveElement, reason: impl Into<String>) {
        self.skipped.push(SkippedInteraction {
            selector: el.selector.clone(),
            reason: reason.into(),
            label: el.label.clone(),
        });
    }

    /// Coverage gap plus a `skipped` row with the same reason.
    fn skip(&mut self, el: &InteractiveElement, reason: &str) {
        self.gap(el, reason);
        self.write(&skipped_record(self.view_id, self.view_url, el, reason));
    }

    fn skip_rest(&mut self, rest: &[Planned<'_>], reason: &str) {
        for planned in rest {
            self.skip(planned.el, reason);
        }
    }

    /// `skipped` row (no coverage gap): the control was exercised on `on_view`.
    fn exercised_elsewhere(&mut self, el: &InteractiveElement, on_view: &str) {
        let mut record = skipped_record(self.view_id, self.view_url, el, "exercised_elsewhere");
        record.exercised_on = Some(on_view.to_string());
        self.write(&record);
    }
}

/// Append one row to `interactions.jsonl`; failures are logged, never fatal.
pub(super) fn write_interaction_record(log: Option<&InteractionLog>, record: &InteractionRecord) {
    if let Some(log) = log
        && let Err(err) = log.append(record)
    {
        tracing::warn!(error = ?err, selector = %record.selector, "failed to write interaction record");
    }
}

/// A `skipped` row for a control that was not exercised.
pub(super) fn skipped_record(
    view_id: &str,
    page_url: &str,
    el: &InteractiveElement,
    reason: &str,
) -> InteractionRecord {
    let mut record = InteractionRecord::new(
        view_id,
        page_url,
        &el.selector,
        element_kind_slug(&el.element_type),
    );
    record.label = el.label.clone();
    record.action = "skip".to_string();
    record.outcome = InteractionOutcome::Skipped;
    record.skipped_reason = Some(reason.to_string());
    record
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_interaction_pass(
    ctx: &PassContext<'_>,
    st: &mut PassState<'_, '_>,
    view_id: &str,
    elements: &[InteractiveElement],
    max_interactions: usize,
    interaction_depth: usize,
    parent_selectors: &HashSet<String>,
    trail: &[InteractiveElement],
) -> Result<InteractionPassOutput> {
    let page = ctx.page;
    let cfg = ctx.cfg;
    let guard_active = write_guard_active(cfg);
    let mut out = InteractionPassOutput::default();
    let mut rec = PassRecorder {
        log: ctx.log,
        view_id,
        view_url: ctx.view_url,
        skipped: Vec::new(),
    };

    // Partition: record controls that are never clicked in place. Disabled
    // buttons are tried last: an earlier sibling (consent checkbox, required
    // field) may enable them, and their turn tries to fill their container.
    let mut candidates: Vec<Candidate<'_>> = Vec::new();
    for el in elements {
        if el.disabled && !is_button_like(&el.element_type) {
            rec.skip(el, "disabled");
            continue;
        }
        if (matches!(el.element_type, ElementType::TextInput { .. }) || is_textarea(el))
            && !cfg.scan.exploration.fill_forms_with_test_data
        {
            // Typing is disabled; "exercising" the field would do nothing.
            rec.skip(el, "form_fill_disabled");
            continue;
        }
        if !is_safe_to_click(el, cfg) {
            // Coverage gaps keep the coarse reason (the store keys on
            // `safety_policy`); the row says why more precisely. Nav dropdowns
            // already have a row from the expansion phase.
            let reason = no_click_reason(el);
            rec.gap(el, reason);
            let expanded = matches!(el.element_type, ElementType::DropdownMenu { .. })
                && ctx
                    .recorded_elsewhere
                    .contains(&format!("{view_id}::{}", el.selector));
            if !expanded {
                rec.write(&skipped_record(
                    view_id,
                    ctx.view_url,
                    el,
                    skip_row_reason(el, reason),
                ));
            }
            continue;
        }
        candidates.push(Candidate {
            el,
            submit: is_submit_target_candidate(el, cfg),
            deferred: el.disabled,
        });
    }

    // Identity, scan-wide dedupe, repeated-card sampling and ordering:
    // page content first, shell chrome next, controls known to navigate away
    // last (each navigation costs a restore), disabled ones at the very end.
    let planned = plan_targets(ctx, st.shared, &mut rec, view_id, candidates).await;
    let (mut other_targets, mut submit_targets): (Vec<Planned<'_>>, Vec<Planned<'_>>) =
        planned.into_iter().partition(|p| !p.submit);
    // Controls that leave the current state (Close, Back, Cancel) go after
    // the others: everything after them needs the state restored first.
    // Standalone search/filter inputs run after non-mutating buttons/tabs so
    // live filtering does not erase rows or mutate the page before modal
    // openers and buttons are exercised.
    other_targets.sort_by_key(|p| {
        (
            p.deferred,
            p.known_to_navigate,
            leaves_state(p.el),
            p.on_sibling,
            p.shell,
            is_deferred_standalone_input(p.el, p.form_index),
            interaction_sort_key(p.el),
        )
    });
    submit_targets.sort_by_key(|p| (p.known_to_navigate, p.shell, submit_sort_key(p.el)));

    // Split non-submit controls into in-state controls (inputs, toggles,
    // non-closing buttons) and state-leaving/deferred controls (Close, Cancel,
    // known-to-navigate, disabled) so submit buttons run while the form/modal
    // is still populated and open.
    let (mut other_targets, mut exit_targets): (Vec<Planned<'_>>, Vec<Planned<'_>>) = other_targets
        .into_iter()
        .partition(|p| !p.deferred && !p.known_to_navigate && !leaves_state(p.el));

    // Reserve slots for submit-like buttons when submit clicks are allowed
    // (either submit_forms is enabled or the write guard is active).
    let per_interaction_budget = per_interaction_budget(cfg);
    let reserve_submits = if submit_clicks_allowed(cfg) && !submit_targets.is_empty() {
        if guard_active {
            submit_targets.len().min(max_interactions / 3).max(1)
        } else {
            1
        }
    } else {
        0
    };
    let max_other = max_interactions.saturating_sub(reserve_submits);
    let mut interacted = 0usize;
    // What this (sub-)view looks like: headings, landmarks, dialogs. A
    // sibling that changed it (wizard step, closed modal) is undone before
    // the next control.
    let mut view = ViewState::new(state_signature(page).await);
    view.document_origin = document_origin(page).await;
    let mut explored_sub_views: HashMap<BTreeSet<String>, String> = HashMap::new();

    let mut idx = 0usize;
    while idx < other_targets.len() {
        let planned = &other_targets[idx];
        let el = planned.el;
        if interacted >= max_other {
            for rest in &other_targets[idx..] {
                let reason = if rest.deferred {
                    "disabled"
                } else {
                    "interaction_limit"
                };
                rec.skip(rest.el, reason);
            }
            break;
        }
        if interaction_window(ctx.deadline, per_interaction_budget).is_none() {
            out.budget_exhausted = true;
            rec.skip_rest(&other_targets[idx..], "view_time_budget");
            break;
        }
        // A previous control may have navigated away (link-like buttons,
        // pushState, hash routes) or moved the view to another state (wizard
        // step, open dialog): put the view back before the next click.
        // Non-submit controls in `other_targets` (modal openers, tabs,
        // buttons, other fields) run cleanly on the baseline/restored view
        // without letting an unrelated form-state recovery failure poison or
        // bulk-skip the rest of the page.
        if !ensure_on_view(ctx, trail, &mut view).await {
            let reason = if trail.is_empty() {
                "restore_failed"
            } else {
                "state_lost"
            };
            rec.skip_rest(&other_targets[idx..], reason);
            break;
        }
        let Some((timeout, deadline_bound)) =
            interaction_window(ctx.deadline, per_interaction_budget)
        else {
            out.budget_exhausted = true;
            rec.skip_rest(&other_targets[idx..], "view_time_budget");
            break;
        };
        idx += 1;
        match claim_control(st.shared, planned, view_id) {
            Claim::Granted => {}
            Claim::Elsewhere(on_view) => {
                // Another tab claimed or exercised it after this pass was planned.
                rec.exercised_elsewhere(el, &on_view);
                continue;
            }
            Claim::Sibling => {
                // A sibling instance of this route template (another tab)
                // took it after this pass was planned: like controls known
                // from a sibling at planning time, it is exercised again
                // only after the rest.
                let mut later = other_targets.remove(idx - 1);
                later.on_sibling = true;
                other_targets.push(later);
                idx -= 1;
                continue;
            }
        }

        let mut exercise =
            exercise_control(ctx, view_id, el, action_kind(el), timeout, planned.deferred).await;
        st.pacer.after_interaction(ctx.network.as_ref()).await;
        if exercise.not_attempted() {
            // Hidden, covered or still disabled: not an interaction.
            release_claim(st.shared, planned, view_id);
            let reason = exercise
                .record
                .skipped_reason
                .clone()
                .unwrap_or_else(|| "skipped".to_string());
            rec.gap(el, reason);
            rec.write(&exercise.record);
            view.quiet = true;
            continue;
        }
        interacted += 1;
        lock_state(st.shared).elements_interacted += 1;

        if exercise.observation.is_none() {
            view.quiet = false;
            let mut record = exercise.record;
            if exercise.timed_out && deadline_bound {
                release_claim(st.shared, planned, view_id);
                record.outcome = InteractionOutcome::Skipped;
                record.skipped_reason = Some("view_time_budget".to_string());
                record.error = Some("interaction outlasted the view time budget".to_string());
                rec.gap(el, "view_time_budget");
                rec.write(&record);
                out.budget_exhausted = true;
                rec.skip_rest(&other_targets[idx..], "view_time_budget");
                break;
            }
            if exercise.timed_out {
                record.outcome = InteractionOutcome::Error;
                record.error = Some(format!(
                    "interaction_timeout: no response within {}ms",
                    timeout.as_millis()
                ));
                rec.gap(el, "interaction_timeout");
            } else if let Some(reason) = record.skipped_reason.clone() {
                rec.gap(el, reason);
            }
            remember_exercised(st.shared, planned, view_id, &record);
            if let Some(result) = interaction_result_for(&record, None) {
                out.interaction_results.insert(el.selector.clone(), result);
            }
            rec.write(&record);
            continue;
        }

        let obs = exercise
            .observation
            .take()
            .expect("observation checked above");
        apply_observation(&mut exercise.record, &obs, &exercise.capture, guard_active);
        let mut current = Attempt { exercise, obs };

        // Re-test a control that did nothing on a fresh copy of the view: a
        // click into a re-initializing page or a leftover state can look dead.
        let retest_candidate = current.exercise.record.outcome == InteractionOutcome::NoEffect
            && current.exercise.record.console_errors.is_empty()
            && current.exercise.record.ui_errors.is_empty()
            && is_button_like(&el.element_type)
            && !current.obs.network_activity
            && !current.obs.already_active
            && !(guard_active && is_submitish(el));
        if retest_candidate
            && interaction_window(ctx.deadline, per_interaction_budget).is_some()
            && restore_view(ctx, trail, &mut view, true).await
        {
            // Restore can erase fields prepared earlier in this pass. Only
            // recover fields belonging to the same form as this control so an
            // unrelated form's preparation never blocks retesting a standalone
            // button.
            let recovered = if view.has_preparation_for_form(planned.form_index) {
                recover_form_preparation(
                    ctx,
                    st,
                    &mut rec,
                    &mut view,
                    planned.form_index,
                    &mut interacted,
                    max_other.saturating_sub(1),
                )
                .await
            } else {
                Ok(())
            };
            if recovered.is_ok()
                && let Some((retest_timeout, _)) =
                    interaction_window(ctx.deadline, per_interaction_budget)
            {
                let mut again = exercise_control(
                    ctx,
                    view_id,
                    el,
                    action_kind(el),
                    retest_timeout,
                    planned.deferred,
                )
                .await;
                st.pacer.after_interaction(ctx.network.as_ref()).await;
                if let Some(obs) = again.observation.take() {
                    apply_observation(&mut again.record, &obs, &again.capture, guard_active);
                    if again.record.outcome == InteractionOutcome::NoEffect {
                        current.exercise.record.retest = Some("confirmed_no_effect".to_string());
                    } else if again.record.outcome != InteractionOutcome::Skipped {
                        again.record.retest = Some("effect_on_retest".to_string());
                        current = Attempt {
                            exercise: again,
                            obs,
                        };
                    }
                }
            }
        }
        let Attempt { exercise, obs } = current;
        let Exercise {
            action_id,
            mut record,
            pre_click_pattern,
            ..
        } = exercise;
        view.quiet = record.outcome == InteractionOutcome::NoEffect && !obs.click_missed;
        if obs.click_missed {
            // The click event went to another element (overlay, clickable
            // row): what happened is not this control's doing.
            release_claim(st.shared, planned, view_id);
            record.outcome = InteractionOutcome::Skipped;
            record.skipped_reason = Some("obscured".to_string());
            record.dom_change = None;
            record.after_url = None;
            record.side_effects.clear();
            record.error = Some("the click landed outside the control".to_string());
            rec.gap(el, "obscured");
            rec.write(&record);
            continue;
        }
        record_interaction_errors(ctx, view_id, el, &action_id, &mut record, &obs).await;

        if successful_preparation(&record) && is_page_local_value_control(el) {
            // A later radio click changes previously prepared peers in the same
            // form too. Keep the final observed group state rather than
            // historical true bits.
            if !matches!(el.element_type, ElementType::TextInput { .. }) {
                let mut capture_failed = false;
                for prior in &mut view.prepared_inputs {
                    if prior.form_index == planned.form_index && prior.native_state.is_some() {
                        if let Some(state) =
                            crate::dom::interaction::capture_native_state(page, &prior.element)
                                .await
                        {
                            prior.native_state = Some(state);
                        } else {
                            capture_failed = true;
                        }
                    }
                }
                if capture_failed {
                    view.mark_unsupported_for_form(planned.form_index);
                }
            }
            let native_state = crate::dom::interaction::capture_native_state(page, el).await;
            view.remember_preparation_in_form(el, &record, native_state, planned.form_index);
        }
        remember_exercised(st.shared, planned, view_id, &record);
        if let Some(result) = interaction_result_for(&record, Some(&obs)) {
            out.interaction_results.insert(el.selector.clone(), result);
        }
        rec.write(&record);
        if record.outcome == InteractionOutcome::Skipped {
            // The control vanished or became unclickable before the click.
            if let Some(reason) = record.skipped_reason.as_deref() {
                rec.gap(el, reason);
            }
            continue;
        }

        // Store post-interaction snapshot if present.
        if let Some(snap) = obs.snapshot.clone() {
            out.interaction_snapshots.insert(el.selector.clone(), snap);
        }

        let possibly_dead = record.outcome == InteractionOutcome::NoEffect
            && record.console_errors.is_empty()
            && record.ui_errors.is_empty()
            && is_button_like(&el.element_type)
            && !obs.network_activity
            // Guarded submit-like clicks fire requests the write guard blocks
            // before the page sees them; network.jsonl decides those.
            && !(guard_active && is_submitish(el));
        if possibly_dead && obs.already_active {
            // Clicking the selected tab/filter again is expected to do nothing.
            rec.gap(el, "already_active");
        } else if possibly_dead {
            // Check if this is a form-submit button that we didn't fill —
            // it's expected to do nothing without valid input.
            let is_unfilled_submit =
                matches!(el.element_type, ElementType::Button { form_submit: true })
                    && !cfg.scan.exploration.fill_forms_with_test_data;

            if !is_unfilled_submit {
                if is_expected_passive_button_control(el, pre_click_pattern) {
                    let reason = match pre_click_pattern {
                        PreClickPattern::CopyToClipboard => {
                            "button_expected_passive_copy_to_clipboard"
                        }
                        PreClickPattern::MediaControl => "button_expected_passive_media_control",
                        _ if has_drag_or_resize_handle_hint(el) => {
                            "button_expected_passive_drag_handle"
                        }
                        _ if has_idempotent_refresh_hint(el) => "button_expected_passive_refresh",
                        _ => "button_expected_passive_control",
                    };
                    rec.gap(el, reason);
                    continue;
                }

                let classification = classify_interaction(
                    &obs.snapshot,
                    pre_click_pattern,
                    obs.dom_mutated,
                    obs.network_activity,
                );

                if classification == InteractionClassification::Dead {
                    if is_terminal_one_way_reveal_control(el)
                        && terminal_one_way_reveal_target_visible(page, el)
                            .await
                            .unwrap_or(false)
                    {
                        rec.gap(el, "one_way_reveal_already_visible");
                        continue;
                    }
                    let precondition = infer_precondition_context(page, el, cfg)
                        .await
                        .unwrap_or_default();
                    if precondition.skip {
                        let reason = match precondition.hint.as_deref() {
                            Some(hint) => format!("precondition: {hint}"),
                            None => "precondition".to_string(),
                        };
                        rec.gap(el, reason);
                    } else {
                        let pattern_str = if pre_click_pattern.is_recognized() {
                            Some(
                                serde_json::to_value(pre_click_pattern)
                                    .ok()
                                    .and_then(|v| v.as_str().map(String::from))
                                    .unwrap_or_else(|| {
                                        format!("{pre_click_pattern:?}").to_ascii_lowercase()
                                    }),
                            )
                        } else {
                            None
                        };
                        ctx.bug_detector
                            .record_dead_button(
                                obs.after_url.clone(),
                                Some(view_id.to_string()),
                                el.selector.clone(),
                                el.label.clone(),
                                precondition.hint,
                                precondition.satisfied,
                                Some(action_id.clone()),
                                pattern_str,
                                Some(classification.as_str().to_string()),
                            )
                            .await;
                    }
                } else {
                    rec.gap(el, format!("button_not_dead_{}", classification.as_str()));
                }
            }
        } else if matches!(obs.effect, InteractionEffect::Navigation) {
            maybe_register_navigation_route_fragment(&obs);
            if let Some(after) = obs.after_url.as_deref()
                && let Ok(after_url) = Url::parse(after)
                && super::url_utils::same_origin(ctx.base_url, &after_url)
            {
                lock_state(st.shared).scheduler.enqueue_scoped(
                    after_url.to_string(),
                    ctx.current_depth + 1,
                    ctx.base_url,
                    ctx.scope_filter,
                    cfg.scan.exploration.strategy,
                    cfg.scan.exploration.novelty_scoring,
                    true,
                );
            }
            if let Some(transition) = navigation_transition_from_observation(view_id, el, &obs) {
                out.deep_transitions.push(transition);
            }
        }

        let dom_effect = matches!(obs.effect, InteractionEffect::DomMutation) && obs.dom_mutated;
        if dom_effect {
            // A click that reveals UI (hamburger sidenav, menu, modal) may
            // expose links that were hidden at discovery time.
            harvest_revealed_links(ctx, view_id, st.known_links, &mut out.revealed_links).await;
        }

        // Deep exploration: when a DomMutation reveals new UI (modal,
        // accordion, tab panel, wizard step), recursively explore the new
        // elements.
        if dom_effect && interaction_depth < cfg.scan.exploration.max_interaction_depth {
            if let Some(ref snap) = obs.snapshot {
                let transition_type = crate::dom::snapshot::classify_mutation(snap);

                // Determine root selectors for scoped discovery.
                let roots: Vec<String> = if let Some(ref modal) = snap.modal_opened {
                    vec![modal.selector.clone()]
                } else {
                    snap.appeared_elements
                        .iter()
                        .filter(|ae| {
                            ae.element_kind == "container"
                                || ae.element_kind == "form_field"
                                || ae.element_kind == "button"
                        })
                        .map(|ae| ae.selector.clone())
                        .collect()
                };

                if !roots.is_empty() {
                    let new_elements = crate::dom::discovery::discover_elements_in_subtree(
                        page,
                        &view_id.to_string(),
                        &roots,
                    )
                    .await
                    .unwrap_or_default();

                    // Filter out already-known elements. A replaced view (wizard
                    // step) can reuse a structural selector for a different
                    // control, so the label must match too.
                    let novel: Vec<_> = new_elements
                        .into_iter()
                        .filter(|e| !parent_selectors.contains(&known_key(e)))
                        .filter(|e| {
                            !elements
                                .iter()
                                .any(|existing| known_key(existing) == known_key(e))
                        })
                        .collect();

                    if !novel.is_empty() {
                        let novel_sig: BTreeSet<String> = novel.iter().map(known_key).collect();
                        if let Some(existing_sub_view_id) = explored_sub_views.get(&novel_sig) {
                            out.deep_transitions.push(PendingTransition {
                                from_view: view_id.to_string(),
                                trigger: InteractionRef {
                                    view: view_id.to_string(),
                                    selector: el.selector.clone(),
                                },
                                trigger_locators: el.locators.clone(),
                                transition_type,
                                target_url: existing_sub_view_id.clone(),
                            });
                            let dismiss_timeout = cfg.scan.exploration.modal_dismiss_timeout_ms;
                            let _ =
                                crate::dom::interaction::dismiss_modal(page, dismiss_timeout).await;
                        } else {
                            let sub_view_id = format!(
                                "{}:d{}:{}",
                                view_id,
                                interaction_depth + 1,
                                out.sub_views.len()
                            );

                            out.deep_transitions.push(PendingTransition {
                                from_view: view_id.to_string(),
                                trigger: InteractionRef {
                                    view: view_id.to_string(),
                                    selector: el.selector.clone(),
                                },
                                trigger_locators: el.locators.clone(),
                                transition_type,
                                target_url: sub_view_id.clone(),
                            });

                            let mut child_known: HashSet<String> = parent_selectors.clone();
                            for e in elements.iter() {
                                child_known.insert(known_key(e));
                            }

                            let child_budget = cfg
                                .scan
                                .exploration
                                .interaction_budget_for_depth(interaction_depth + 1);

                            let mut child_trail = trail.to_vec();
                            child_trail.push(el.clone());
                            // A sub-state may not starve this pass's remaining
                            // controls: it gets a share of the time left.
                            let child_ctx = PassContext {
                                deadline: child_pass_deadline(ctx.deadline),
                                ..ctx.clone()
                            };
                            let child_out = Box::pin(run_interaction_pass(
                                &child_ctx,
                                st,
                                &sub_view_id,
                                &novel,
                                child_budget,
                                interaction_depth + 1,
                                &child_known,
                                &child_trail,
                            ))
                            .await?;

                            if !child_out.budget_exhausted {
                                explored_sub_views.insert(novel_sig, sub_view_id.clone());
                            }

                            let mut novel = novel;
                            for child in novel.iter_mut() {
                                if let Some(snap) =
                                    child_out.interaction_snapshots.get(&child.selector)
                                {
                                    child.snapshot = Some(snap.clone());
                                }
                                if let Some(result) =
                                    child_out.interaction_results.get(&child.selector)
                                {
                                    child.interaction_result = Some(result.clone());
                                }
                            }
                            out.sub_views.push(SubView {
                                id: sub_view_id,
                                parent_view: view_id.to_string(),
                                depth: interaction_depth + 1,
                                trigger_selector: el.selector.clone(),
                                transition_type,
                                elements: novel,
                                api_calls: vec![],
                                snapshot: obs.snapshot.clone(),
                                fingerprint: None,
                            });
                            out.absorb_child(child_out);

                            // Dismiss the modal and resume parent interactions. If it
                            // does not close (or this was a wizard step), the next
                            // control's state check reloads the view.
                            let dismiss_timeout = cfg.scan.exploration.modal_dismiss_timeout_ms;
                            if !matches!(
                                crate::dom::interaction::dismiss_modal(page, dismiss_timeout).await,
                                Ok(crate::dom::interaction::DismissResult::Dismissed)
                            ) {
                                tracing::debug!(view_id, selector = %el.selector, "modal did not close; the view is reloaded before the next control");
                            }
                        }
                    }
                }
            }
        } else if dom_effect && interaction_depth >= cfg.scan.exploration.max_interaction_depth {
            // At depth limit — record as coverage gap so users know
            // there may be unexplored UI behind this element.
            rec.gap(el, "modal_depth_limit");
        }

        // URL query-param correlation for filters/search controls:
        // If the interaction changes the current page's query string
        // without navigating away, attribute those keys to the
        // underlying control selector (canonicalized to match the
        // classifier's `FormFieldDef.selector`).
        if let (Some(before), Some(after)) = (obs.before_url.as_deref(), obs.after_url.as_deref()) {
            let keys = super::url_utils::diff_query_keys(before, after);
            if !keys.is_empty() {
                let sel = match canonical_selector(page, el).await {
                    Ok(Some(s)) => s,
                    Ok(None) => el.selector.clone(),
                    Err(err) => {
                        tracing::debug!(
                            error = ?err,
                            selector = %el.selector,
                            "canonical selector lookup failed"
                        );
                        el.selector.clone()
                    }
                };
                let entry = out.selector_query_params.entry(sel).or_default();
                for k in keys {
                    entry.insert(k);
                }
            }
        }
    }

    if !submit_targets.is_empty() {
        let mut submitted = 0usize;
        let mut idx = 0usize;
        while idx < submit_targets.len() {
            let planned = &submit_targets[idx];
            let el = planned.el;
            if let Some(reason) = view.recovery_failure_for_form(planned.form_index) {
                rec.skip(el, reason);
                idx += 1;
                continue;
            }
            if out.budget_exhausted
                || interaction_window(ctx.deadline, per_interaction_budget).is_none()
            {
                out.budget_exhausted = true;
                rec.skip_rest(&submit_targets[idx..], "view_time_budget");
                break;
            }
            if interacted >= max_interactions {
                rec.skip_rest(&submit_targets[idx..], "interaction_limit");
                break;
            }
            if !guard_active && submitted >= reserve_submits {
                rec.skip_rest(&submit_targets[idx..], "submit_reserve_limit");
                break;
            }
            if !ensure_on_view(ctx, trail, &mut view).await {
                let reason = if trail.is_empty() {
                    "restore_failed"
                } else {
                    "state_lost"
                };
                rec.skip_rest(&submit_targets[idx..], reason);
                break;
            }
            if view.has_preparation_for_form(planned.form_index)
                && let Err(reason) = recover_form_preparation(
                    ctx,
                    st,
                    &mut rec,
                    &mut view,
                    planned.form_index,
                    &mut interacted,
                    max_interactions.saturating_sub(1),
                )
                .await
            {
                rec.skip(el, reason);
                idx += 1;
                continue;
            }
            let Some((timeout, _)) = interaction_window(ctx.deadline, per_interaction_budget)
            else {
                out.budget_exhausted = true;
                rec.skip_rest(&submit_targets[idx..], "view_time_budget");
                break;
            };
            idx += 1;

            let form_selector = match resolve_submit_form_selector(page, el, ctx.classified).await {
                Ok(v) => v,
                Err(err) => {
                    tracing::debug!(
                        error = ?err,
                        selector = %el.selector,
                        "resolve submit form selector failed"
                    );
                    None
                }
            };

            match claim_control(st.shared, planned, view_id) {
                Claim::Granted => {}
                Claim::Elsewhere(on_view) => {
                    rec.exercised_elsewhere(el, &on_view);
                    continue;
                }
                Claim::Sibling => {
                    let mut later = submit_targets.remove(idx - 1);
                    later.on_sibling = true;
                    submit_targets.push(later);
                    idx -= 1;
                    continue;
                }
            }
            let exercise =
                exercise_control(ctx, view_id, el, "submit", timeout, planned.deferred).await;
            st.pacer.after_interaction(ctx.network.as_ref()).await;
            view.quiet = exercise.not_attempted();
            if exercise.not_attempted() {
                release_claim(st.shared, planned, view_id);
                if let Some(reason) = exercise.record.skipped_reason.clone() {
                    rec.gap(el, reason);
                }
                rec.write(&exercise.record);
                continue;
            }
            interacted += 1;
            submitted += 1;
            lock_state(st.shared).elements_interacted += 1;
            let mut record = exercise.record;
            let Some(obs) = exercise.observation else {
                if exercise.timed_out {
                    record.outcome = InteractionOutcome::Error;
                    record.error = Some(format!(
                        "interaction_timeout: no response within {}ms",
                        timeout.as_millis()
                    ));
                    rec.gap(el, "interaction_timeout");
                }
                remember_exercised(st.shared, planned, view_id, &record);
                rec.write(&record);
                continue;
            };
            apply_observation(&mut record, &obs, &exercise.capture, guard_active);
            view.quiet = record.outcome == InteractionOutcome::NoEffect && !obs.click_missed;
            if obs.click_missed {
                release_claim(st.shared, planned, view_id);
                record.outcome = InteractionOutcome::Skipped;
                record.skipped_reason = Some("obscured".to_string());
                record.dom_change = None;
                record.after_url = None;
                record.side_effects.clear();
                record.error = Some("the click landed outside the control".to_string());
                rec.gap(el, "obscured");
                rec.write(&record);
                continue;
            }
            record_interaction_errors(ctx, view_id, el, &exercise.action_id, &mut record, &obs)
                .await;
            remember_exercised(st.shared, planned, view_id, &record);
            if let Some(result) = interaction_result_for(&record, Some(&obs)) {
                out.interaction_results.insert(el.selector.clone(), result);
            }
            rec.write(&record);

            if let Some(snap) = obs.snapshot.clone() {
                out.interaction_snapshots.insert(el.selector.clone(), snap);
            }
            if matches!(obs.effect, InteractionEffect::Navigation) {
                maybe_register_navigation_route_fragment(&obs);
                if let Some(after) = obs.after_url.as_deref()
                    && let Ok(after_url) = Url::parse(after)
                    && super::url_utils::same_origin(ctx.base_url, &after_url)
                {
                    lock_state(st.shared).scheduler.enqueue_scoped(
                        after_url.to_string(),
                        ctx.current_depth + 1,
                        ctx.base_url,
                        ctx.scope_filter,
                        cfg.scan.exploration.strategy,
                        cfg.scan.exploration.novelty_scoring,
                        true,
                    );
                }
                if let Some(transition) = navigation_transition_from_observation(view_id, el, &obs)
                {
                    out.deep_transitions.push(transition);
                }
            }

            let dom_effect =
                matches!(obs.effect, InteractionEffect::DomMutation) && obs.dom_mutated;
            if dom_effect {
                harvest_revealed_links(ctx, view_id, st.known_links, &mut out.revealed_links).await;
            }
            if dom_effect && interaction_depth < cfg.scan.exploration.max_interaction_depth {
                if let Some(ref snap) = obs.snapshot {
                    let transition_type = crate::dom::snapshot::classify_mutation(snap);
                    let roots: Vec<String> = if let Some(ref modal) = snap.modal_opened {
                        vec![modal.selector.clone()]
                    } else {
                        snap.appeared_elements
                            .iter()
                            .filter(|ae| {
                                ae.element_kind == "container"
                                    || ae.element_kind == "form_field"
                                    || ae.element_kind == "button"
                            })
                            .map(|ae| ae.selector.clone())
                            .collect()
                    };
                    if !roots.is_empty() {
                        let new_elements = crate::dom::discovery::discover_elements_in_subtree(
                            page,
                            &view_id.to_string(),
                            &roots,
                        )
                        .await
                        .unwrap_or_default();
                        let novel: Vec<_> = new_elements
                            .into_iter()
                            .filter(|e| !parent_selectors.contains(&known_key(e)))
                            .filter(|e| {
                                !elements
                                    .iter()
                                    .any(|existing| known_key(existing) == known_key(e))
                            })
                            .collect();
                        if !novel.is_empty() {
                            let novel_sig: BTreeSet<String> = novel.iter().map(known_key).collect();
                            if let Some(existing_sub_view_id) = explored_sub_views.get(&novel_sig) {
                                out.deep_transitions.push(PendingTransition {
                                    from_view: view_id.to_string(),
                                    trigger: InteractionRef {
                                        view: view_id.to_string(),
                                        selector: el.selector.clone(),
                                    },
                                    trigger_locators: el.locators.clone(),
                                    transition_type,
                                    target_url: existing_sub_view_id.clone(),
                                });
                                let dismiss_timeout = cfg.scan.exploration.modal_dismiss_timeout_ms;
                                let _ =
                                    crate::dom::interaction::dismiss_modal(page, dismiss_timeout)
                                        .await;
                            } else {
                                let sub_view_id = format!(
                                    "{}:d{}:{}",
                                    view_id,
                                    interaction_depth + 1,
                                    out.sub_views.len()
                                );
                                out.deep_transitions.push(PendingTransition {
                                    from_view: view_id.to_string(),
                                    trigger: InteractionRef {
                                        view: view_id.to_string(),
                                        selector: el.selector.clone(),
                                    },
                                    trigger_locators: el.locators.clone(),
                                    transition_type,
                                    target_url: sub_view_id.clone(),
                                });
                                let mut child_known: HashSet<String> = parent_selectors.clone();
                                for e in elements.iter() {
                                    child_known.insert(known_key(e));
                                }
                                let child_budget = cfg
                                    .scan
                                    .exploration
                                    .interaction_budget_for_depth(interaction_depth + 1);
                                let mut child_trail = trail.to_vec();
                                child_trail.push(el.clone());
                                let child_ctx = PassContext {
                                    deadline: child_pass_deadline(ctx.deadline),
                                    ..ctx.clone()
                                };
                                let child_out = Box::pin(run_interaction_pass(
                                    &child_ctx,
                                    st,
                                    &sub_view_id,
                                    &novel,
                                    child_budget,
                                    interaction_depth + 1,
                                    &child_known,
                                    &child_trail,
                                ))
                                .await?;
                                if !child_out.budget_exhausted {
                                    explored_sub_views.insert(novel_sig, sub_view_id.clone());
                                }
                                let mut novel = novel;
                                for child in novel.iter_mut() {
                                    if let Some(snap) =
                                        child_out.interaction_snapshots.get(&child.selector)
                                    {
                                        child.snapshot = Some(snap.clone());
                                    }
                                    if let Some(result) =
                                        child_out.interaction_results.get(&child.selector)
                                    {
                                        child.interaction_result = Some(result.clone());
                                    }
                                }
                                out.sub_views.push(SubView {
                                    id: sub_view_id,
                                    parent_view: view_id.to_string(),
                                    depth: interaction_depth + 1,
                                    trigger_selector: el.selector.clone(),
                                    transition_type,
                                    elements: novel,
                                    api_calls: vec![],
                                    snapshot: obs.snapshot.clone(),
                                    fingerprint: None,
                                });
                                out.absorb_child(child_out);
                                let dismiss_timeout = cfg.scan.exploration.modal_dismiss_timeout_ms;
                                let _ =
                                    crate::dom::interaction::dismiss_modal(page, dismiss_timeout)
                                        .await;
                            }
                        }
                    }
                }
            }

            if let Some(form_sel) = form_selector {
                out.form_action_interactions.push(FormActionInteraction {
                    trigger: InteractionRef {
                        view: view_id.to_string(),
                        selector: el.selector.clone(),
                    },
                    form_selector: form_sel,
                    submit_label: el.label.clone(),
                });
            }
        }
    }

    if !exit_targets.is_empty() {
        let mut idx = 0usize;
        while idx < exit_targets.len() {
            let planned = &exit_targets[idx];
            let el = planned.el;
            if out.budget_exhausted
                || interaction_window(ctx.deadline, per_interaction_budget).is_none()
            {
                out.budget_exhausted = true;
                rec.skip_rest(&exit_targets[idx..], "view_time_budget");
                break;
            }
            if interacted >= max_interactions {
                for rest in &exit_targets[idx..] {
                    let reason = if rest.deferred {
                        "disabled"
                    } else {
                        "interaction_limit"
                    };
                    rec.skip(rest.el, reason);
                }
                break;
            }
            if !ensure_on_view(ctx, trail, &mut view).await {
                let reason = if trail.is_empty() {
                    "restore_failed"
                } else {
                    "state_lost"
                };
                rec.skip_rest(&exit_targets[idx..], reason);
                break;
            }
            // Only deferred (initially-disabled) buttons inside a prepared form
            // depend on form-state recovery; navigation and state-leaving
            // controls (Close, Cancel, Back) always run on the clean view.
            if planned.deferred
                && !leaves_state(el)
                && view.has_preparation_for_form(planned.form_index)
            {
                if let Some(reason) = view.recovery_failure_for_form(planned.form_index) {
                    rec.skip(el, reason);
                    idx += 1;
                    continue;
                }
                if let Err(reason) = recover_form_preparation(
                    ctx,
                    st,
                    &mut rec,
                    &mut view,
                    planned.form_index,
                    &mut interacted,
                    max_interactions.saturating_sub(1),
                )
                .await
                {
                    rec.skip(el, reason);
                    idx += 1;
                    continue;
                }
            }
            let Some((timeout, deadline_bound)) =
                interaction_window(ctx.deadline, per_interaction_budget)
            else {
                out.budget_exhausted = true;
                rec.skip_rest(&exit_targets[idx..], "view_time_budget");
                break;
            };
            idx += 1;
            match claim_control(st.shared, planned, view_id) {
                Claim::Granted => {}
                Claim::Elsewhere(on_view) => {
                    rec.exercised_elsewhere(el, &on_view);
                    continue;
                }
                Claim::Sibling => {
                    let mut later = exit_targets.remove(idx - 1);
                    later.on_sibling = true;
                    exit_targets.push(later);
                    idx -= 1;
                    continue;
                }
            }
            let exercise =
                exercise_control(ctx, view_id, el, action_kind(el), timeout, planned.deferred)
                    .await;
            st.pacer.after_interaction(ctx.network.as_ref()).await;
            if exercise.not_attempted() {
                release_claim(st.shared, planned, view_id);
                let reason = exercise
                    .record
                    .skipped_reason
                    .clone()
                    .unwrap_or_else(|| "skipped".to_string());
                rec.gap(el, reason);
                rec.write(&exercise.record);
                view.quiet = true;
                continue;
            }
            interacted += 1;
            lock_state(st.shared).elements_interacted += 1;
            let mut record = exercise.record;
            let Some(obs) = exercise.observation else {
                view.quiet = false;
                if exercise.timed_out && deadline_bound {
                    release_claim(st.shared, planned, view_id);
                    record.outcome = InteractionOutcome::Skipped;
                    record.skipped_reason = Some("view_time_budget".to_string());
                    record.error = Some("interaction outlasted the view time budget".to_string());
                    rec.gap(el, "view_time_budget");
                    rec.write(&record);
                    out.budget_exhausted = true;
                    rec.skip_rest(&exit_targets[idx..], "view_time_budget");
                    break;
                }
                if exercise.timed_out {
                    record.outcome = InteractionOutcome::Error;
                    record.error = Some(format!(
                        "interaction_timeout: no response within {}ms",
                        timeout.as_millis()
                    ));
                    rec.gap(el, "interaction_timeout");
                }
                remember_exercised(st.shared, planned, view_id, &record);
                if let Some(result) = interaction_result_for(&record, None) {
                    out.interaction_results.insert(el.selector.clone(), result);
                }
                rec.write(&record);
                continue;
            };
            apply_observation(&mut record, &obs, &exercise.capture, guard_active);
            view.quiet = record.outcome == InteractionOutcome::NoEffect && !obs.click_missed;
            if obs.click_missed {
                release_claim(st.shared, planned, view_id);
                record.outcome = InteractionOutcome::Skipped;
                record.skipped_reason = Some("obscured".to_string());
                record.dom_change = None;
                record.after_url = None;
                record.side_effects.clear();
                record.error = Some("the click landed outside the control".to_string());
                rec.gap(el, "obscured");
                rec.write(&record);
                continue;
            }
            record_interaction_errors(ctx, view_id, el, &exercise.action_id, &mut record, &obs)
                .await;
            remember_exercised(st.shared, planned, view_id, &record);
            if let Some(result) = interaction_result_for(&record, Some(&obs)) {
                out.interaction_results.insert(el.selector.clone(), result);
            }
            rec.write(&record);
            if let Some(snap) = obs.snapshot.clone() {
                out.interaction_snapshots.insert(el.selector.clone(), snap);
            }
            if matches!(obs.effect, InteractionEffect::Navigation) {
                maybe_register_navigation_route_fragment(&obs);
                if let Some(after) = obs.after_url.as_deref()
                    && let Ok(after_url) = Url::parse(after)
                    && super::url_utils::same_origin(ctx.base_url, &after_url)
                {
                    lock_state(st.shared).scheduler.enqueue_scoped(
                        after_url.to_string(),
                        ctx.current_depth + 1,
                        ctx.base_url,
                        ctx.scope_filter,
                        cfg.scan.exploration.strategy,
                        cfg.scan.exploration.novelty_scoring,
                        true,
                    );
                }
                if let Some(transition) = navigation_transition_from_observation(view_id, el, &obs)
                {
                    out.deep_transitions.push(transition);
                }
            }

            // Deep exploration (parity with the other/submit loops above):
            // exit targets include disabled-at-discovery controls (e.g. a
            // wizard "Continue" that a consent checkbox enables), whose
            // DomMutation can reveal a whole new step. Without this block
            // the revealed controls were never discovered or exercised.
            let dom_effect =
                matches!(obs.effect, InteractionEffect::DomMutation) && obs.dom_mutated;
            if dom_effect {
                harvest_revealed_links(ctx, view_id, st.known_links, &mut out.revealed_links).await;
            }
            if dom_effect && interaction_depth < cfg.scan.exploration.max_interaction_depth {
                if let Some(ref snap) = obs.snapshot {
                    let transition_type = crate::dom::snapshot::classify_mutation(snap);
                    let roots: Vec<String> = if let Some(ref modal) = snap.modal_opened {
                        vec![modal.selector.clone()]
                    } else {
                        snap.appeared_elements
                            .iter()
                            .filter(|ae| {
                                ae.element_kind == "container"
                                    || ae.element_kind == "form_field"
                                    || ae.element_kind == "button"
                            })
                            .map(|ae| ae.selector.clone())
                            .collect()
                    };
                    if !roots.is_empty() {
                        let new_elements = crate::dom::discovery::discover_elements_in_subtree(
                            page,
                            &view_id.to_string(),
                            &roots,
                        )
                        .await
                        .unwrap_or_default();
                        let novel: Vec<_> = new_elements
                            .into_iter()
                            .filter(|e| !parent_selectors.contains(&known_key(e)))
                            .filter(|e| {
                                !elements
                                    .iter()
                                    .any(|existing| known_key(existing) == known_key(e))
                            })
                            .collect();
                        if !novel.is_empty() {
                            let novel_sig: BTreeSet<String> = novel.iter().map(known_key).collect();
                            if let Some(existing_sub_view_id) = explored_sub_views.get(&novel_sig) {
                                out.deep_transitions.push(PendingTransition {
                                    from_view: view_id.to_string(),
                                    trigger: InteractionRef {
                                        view: view_id.to_string(),
                                        selector: el.selector.clone(),
                                    },
                                    trigger_locators: el.locators.clone(),
                                    transition_type,
                                    target_url: existing_sub_view_id.clone(),
                                });
                                let dismiss_timeout = cfg.scan.exploration.modal_dismiss_timeout_ms;
                                let _ =
                                    crate::dom::interaction::dismiss_modal(page, dismiss_timeout)
                                        .await;
                            } else {
                                let sub_view_id = format!(
                                    "{}:d{}:{}",
                                    view_id,
                                    interaction_depth + 1,
                                    out.sub_views.len()
                                );
                                out.deep_transitions.push(PendingTransition {
                                    from_view: view_id.to_string(),
                                    trigger: InteractionRef {
                                        view: view_id.to_string(),
                                        selector: el.selector.clone(),
                                    },
                                    trigger_locators: el.locators.clone(),
                                    transition_type,
                                    target_url: sub_view_id.clone(),
                                });
                                let mut child_known: HashSet<String> = parent_selectors.clone();
                                for e in elements.iter() {
                                    child_known.insert(known_key(e));
                                }
                                let child_budget = cfg
                                    .scan
                                    .exploration
                                    .interaction_budget_for_depth(interaction_depth + 1);
                                let mut child_trail = trail.to_vec();
                                child_trail.push(el.clone());
                                let child_ctx = PassContext {
                                    deadline: child_pass_deadline(ctx.deadline),
                                    ..ctx.clone()
                                };
                                let child_out = Box::pin(run_interaction_pass(
                                    &child_ctx,
                                    st,
                                    &sub_view_id,
                                    &novel,
                                    child_budget,
                                    interaction_depth + 1,
                                    &child_known,
                                    &child_trail,
                                ))
                                .await?;
                                if !child_out.budget_exhausted {
                                    explored_sub_views.insert(novel_sig, sub_view_id.clone());
                                }
                                let mut novel = novel;
                                for child in novel.iter_mut() {
                                    if let Some(snap) =
                                        child_out.interaction_snapshots.get(&child.selector)
                                    {
                                        child.snapshot = Some(snap.clone());
                                    }
                                    if let Some(result) =
                                        child_out.interaction_results.get(&child.selector)
                                    {
                                        child.interaction_result = Some(result.clone());
                                    }
                                }
                                out.sub_views.push(SubView {
                                    id: sub_view_id,
                                    parent_view: view_id.to_string(),
                                    depth: interaction_depth + 1,
                                    trigger_selector: el.selector.clone(),
                                    transition_type,
                                    elements: novel,
                                    api_calls: vec![],
                                    snapshot: obs.snapshot.clone(),
                                    fingerprint: None,
                                });
                                out.absorb_child(child_out);
                                let dismiss_timeout = cfg.scan.exploration.modal_dismiss_timeout_ms;
                                let _ =
                                    crate::dom::interaction::dismiss_modal(page, dismiss_timeout)
                                        .await;
                            }
                        }
                    }
                }
            }
        }
    }

    out.skipped_interactions.extend(rec.skipped);
    Ok(out)
}

/// Identity of a discovered element for "already known" checks between a
/// view and its sub-states: a replaced view (wizard step) can reuse a
/// structural selector for a different control, so the label counts too.
fn known_key(el: &InteractiveElement) -> String {
    format!(
        "{}\u{1f}{}",
        el.selector,
        el.label.as_deref().unwrap_or_default()
    )
}

/// One exercised control with what was observed.
struct Attempt {
    exercise: Exercise,
    obs: InteractionObservation,
}

/// A control the pass may exercise.
struct Candidate<'e> {
    el: &'e InteractiveElement,
    submit: bool,
    /// Disabled at discovery: tried last, after an attempt to enable it.
    deferred: bool,
}

impl InteractionPassOutput {
    /// Merge a nested (deep exploration) pass into this one.
    fn absorb_child(&mut self, child: InteractionPassOutput) {
        self.sub_views.extend(child.sub_views);
        self.deep_transitions.extend(child.deep_transitions);
        self.skipped_interactions.extend(child.skipped_interactions);
        self.revealed_links.extend(child.revealed_links);
        for (selector, params) in child.selector_query_params {
            self.selector_query_params
                .entry(selector)
                .or_default()
                .extend(params);
        }
        self.form_action_interactions
            .extend(child.form_action_interactions);
    }
}

/// Outcome of exercising one control.
pub(super) struct Exercise {
    pub(super) action_id: String,
    /// Row with identity, timing and console evidence filled in; outcome
    /// fields are set by [`apply_observation`].
    pub(super) record: InteractionRecord,
    pub(super) observation: Option<InteractionObservation>,
    pub(super) pre_click_pattern: PreClickPattern,
    pub(super) capture: ActionCapture,
    /// The interaction did not finish within its time budget.
    pub(super) timed_out: bool,
}

impl Exercise {
    /// The control could not be exercised as a user would (hidden, covered,
    /// still disabled): no action ran, the row is a `skip`.
    pub(super) fn not_attempted(&self) -> bool {
        self.record.action == "skip"
    }
}

/// Upper bound for getting a control ready (opening `<details>`, filling its
/// form, scrolling, waiting for the page to go quiet).
const PREPARE_TIMEOUT: Duration = Duration::from_secs(6);

/// Exercise one control as a tracked action. The control is prepared first
/// (outside the action window, so what preparing causes is not credited to
/// it): ancestor `<details>` opened, form filled for submit-like controls,
/// scrolled into view, hit-tested. A hidden, covered or still-disabled
/// control is recorded as a `skip` (`hidden`, `obscured`, `disabled`).
/// Otherwise an action id is minted, network requests and console errors
/// are attributed to it while it runs, and it is timed.
async fn exercise_control(
    ctx: &PassContext<'_>,
    view_id: &str,
    el: &InteractiveElement,
    action: &str,
    timeout: Duration,
    unlock: bool,
) -> Exercise {
    exercise_with(
        ctx.page,
        ctx.cfg,
        ctx.network,
        ctx.bug_detector,
        view_id,
        ctx.view_url,
        el,
        action,
        timeout,
        unlock,
    )
    .await
}

/// [`exercise_control`] outside an interaction pass (nav dropdown expansion).
#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise_with(
    page: &PageClient,
    cfg: &BrokenAppConfig,
    network: &Arc<NetworkInterceptor>,
    bug_detector: &Arc<BugDetector>,
    view_id: &str,
    view_url: &str,
    el: &InteractiveElement,
    action: &str,
    timeout: Duration,
    unlock: bool,
) -> Exercise {
    exercise_with_native_state(
        page,
        cfg,
        network,
        bug_detector,
        view_id,
        view_url,
        el,
        action,
        timeout,
        unlock,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn exercise_with_native_state(
    page: &PageClient,
    cfg: &BrokenAppConfig,
    network: &Arc<NetworkInterceptor>,
    bug_detector: &Arc<BugDetector>,
    view_id: &str,
    view_url: &str,
    el: &InteractiveElement,
    action: &str,
    timeout: Duration,
    unlock: bool,
    native_state: Option<&NativeControlState>,
) -> Exercise {
    let interaction_ref = InteractionRef {
        view: view_id.to_string(),
        selector: el.selector.clone(),
    };
    let action_id = Uuid::new_v4().to_string();

    let page_url = page
        .url()
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| view_url.to_string());
    let mut record = InteractionRecord::new(
        view_id,
        &page_url,
        &el.selector,
        element_kind_slug(&el.element_type),
    );
    record.action_id = Some(action_id.clone());
    record.label = el.label.clone();
    record.action = action.to_string();

    let started = Instant::now();
    let interact_cfg = interaction_scan_config(cfg);
    let mut opts = crate::dom::interaction::prepare_options(el, &interact_cfg);
    opts.unlock = unlock && is_button_like(&el.element_type);
    let tab = page.tab();
    let preparation = network.preparation_scope_on(&tab);
    let preparation_id = Uuid::new_v4().to_string();
    let prepare_timeout = PREPARE_TIMEOUT.min(timeout);
    let prepared = tokio::time::timeout(prepare_timeout, async {
        cdp_helpers::begin_preparation(
            page,
            &preparation_id,
            u64::try_from(prepare_timeout.as_millis()).unwrap_or(u64::MAX),
        )
        .await?;
        crate::dom::interaction::prepare_target(page, el, &opts).await
    })
    .await;
    // End on ready, skip, error and timeout. The scope's Drop also protects
    // Rust attribution if this future is cancelled; the browser has a TTL and
    // the next ordinary action resets its marker. Cleanup shares the deadline.
    let cleanup = tokio::time::timeout(
        timeout.saturating_sub(started.elapsed()),
        cdp_helpers::end_preparation(page, &preparation_id),
    )
    .await;
    drop(preparation);
    let prepared = match cleanup {
        Ok(Ok(())) => prepared,
        Ok(Err(error)) => Ok(Err(error.context("preparation attribution cleanup"))),
        Err(elapsed) => Err(elapsed),
    };
    let prepared = match prepared {
        Ok(Ok(Prepared::Ready(prepared))) => prepared,
        Ok(Ok(Prepared::Skip { reason, detail })) => {
            record.action_id = None;
            record.action = "skip".to_string();
            record.outcome = InteractionOutcome::Skipped;
            record.skipped_reason = Some(reason.to_string());
            if reason == "obscured" {
                record.obscured_by = extract_obscured_by(&detail);
            }
            if !detail.is_empty() {
                tracing::debug!(selector = %el.selector, reason, detail = %detail, "control not exercisable");
            }
            record.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            return Exercise {
                action_id,
                record,
                observation: None,
                pre_click_pattern: PreClickPattern::Unknown,
                capture: ActionCapture::default(),
                timed_out: false,
            };
        }
        Ok(Err(err)) => {
            apply_failure(&mut record, &format!("{err:#}"));
            record.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            return Exercise {
                action_id,
                record,
                observation: None,
                pre_click_pattern: PreClickPattern::Unknown,
                capture: ActionCapture::default(),
                timed_out: false,
            };
        }
        Err(_) => {
            record.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            return Exercise {
                action_id,
                record,
                observation: None,
                pre_click_pattern: PreClickPattern::Unknown,
                capture: ActionCapture::default(),
                timed_out: true,
            };
        }
    };
    record.already_active = prepared.already_active;

    // Requests, console errors and dialogs are attributed per tab: another
    // tab's action never claims what this page does.
    network.register_action_on(&tab, action_id.clone(), interaction_ref.clone());
    let probe = cdp_helpers::ActionProbe {
        id: action_id.clone(),
        view: view_id.to_string(),
        selector: el.selector.clone(),
        label: el.label.clone(),
        kind: action.to_string(),
    };
    let ttl_ms = cfg
        .scan
        .interaction_timeout_ms
        .saturating_add(cfg.scan.settle_timeout_ms)
        .saturating_add(2000);
    if let Err(err) = cdp_helpers::begin_action(page, &probe, ttl_ms).await {
        tracing::debug!(error = ?err, selector = %el.selector, "action probe begin failed");
    }

    // Capture pattern before clicking so classification is based on pre-click intent.
    let pre_click_pattern = if is_button_like(&el.element_type) {
        detect_pre_click_pattern(page, &el.selector)
            .await
            .unwrap_or(PreClickPattern::Unknown)
    } else {
        PreClickPattern::Unknown
    };

    let dialog_cursor = network.native_dialog_cursor_on(&tab);
    network.set_current_interaction_on(&tab, Some(interaction_ref));
    bug_detector.begin_action(&tab, &action_id, view_id, &el.selector);
    let remaining = timeout
        .saturating_sub(started.elapsed())
        .max(Duration::from_millis(500));
    let result = tokio::time::timeout(
        remaining,
        crate::dom::interaction::perform_prepared_with_native_state(
            page,
            el,
            &prepared,
            &interact_cfg,
            native_state,
        ),
    )
    .await;
    network.set_current_interaction_on(&tab, None);
    let capture = bug_detector.end_action(&tab, &action_id);
    // Stop stamping in-page requests with this action, so a later restore
    // or click is not credited to it.
    if let Err(err) = cdp_helpers::end_action(page, &action_id).await {
        tracing::debug!(error = ?err, selector = %el.selector, "action probe end failed");
    }
    record.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    record.console_errors = capture.console_errors.clone();
    record.native_dialog = capture.native_dialog.clone().or_else(|| {
        let (dialogs, _) = network.native_dialogs_since_on(&tab, dialog_cursor);
        dialogs
            .iter()
            .rev()
            .find(|d| d.action_id.as_deref().is_none_or(|id| id == action_id))
            .map(|d| d.summary())
    });

    let (observation, timed_out) = match result {
        Ok(Ok(mut obs)) => {
            crate::dom::interaction::recheck_tickers(page, &mut obs).await;
            (Some(obs), false)
        }
        Ok(Err(err)) => {
            apply_failure(&mut record, &format!("{err:#}"));
            (None, false)
        }
        Err(_) => (None, true),
    };

    Exercise {
        action_id,
        record,
        observation,
        pre_click_pattern,
        capture,
        timed_out,
    }
}

/// Record runtime UI error toasts/alerts and action-attributed WebSocket
/// errors onto `record.ui_errors` and `ctx.bug_detector`.
async fn record_interaction_errors(
    ctx: &PassContext<'_>,
    view_id: &str,
    el: &InteractiveElement,
    action_id: &str,
    record: &mut InteractionRecord,
    obs: &InteractionObservation,
) {
    let tab = ctx.page.tab();
    let guard_blocked = ctx.network.action_had_guarded_write(&tab, action_id)
        || obs.side_effects.iter().any(|s| s == "websocket_guarded");

    if let Some(snap) = obs.snapshot.as_ref() {
        let toasts =
            crate::bugs::ui_errors::extract_error_toasts(snap, &obs.side_effects, guard_blocked);
        for toast in toasts {
            if !record.ui_errors.contains(&toast.message) {
                record.ui_errors.push(toast.message.clone());
            }
            ctx.bug_detector
                .record_ui_error_toast(
                    obs.before_url
                        .clone()
                        .or_else(|| Some(record.page_url.clone())),
                    Some(view_id.to_string()),
                    el.selector.clone(),
                    el.label.clone(),
                    toast.selector,
                    toast.message,
                    Some(action_id.to_string()),
                )
                .await;
        }
    }

    for ws_err in ctx.network.ws_errors_for_action(&tab, action_id) {
        if !record.ui_errors.contains(&ws_err) {
            record.ui_errors.push(ws_err);
        }
    }
}

/// Fill the outcome fields of `record` from what the interaction observed.
pub(super) fn apply_observation(
    record: &mut InteractionRecord,
    obs: &InteractionObservation,
    capture: &ActionCapture,
    write_guard_active: bool,
) {
    if let Some(before) = obs.before_url.as_deref() {
        record.page_url = before.to_string();
    }
    record.network_activity = obs.network_activity;
    record.side_effects = obs.side_effects.clone();
    record.already_active |= obs.already_active;
    match &obs.effect {
        InteractionEffect::Navigation => {
            record.outcome = InteractionOutcome::Navigated;
            record.after_url = obs.after_url.clone();
        }
        InteractionEffect::DomMutation => {
            record.outcome = InteractionOutcome::DomChange;
            let kind = if !obs.dom_mutated && !obs.side_effects.is_empty() {
                // Only non-DOM effects (print, scroll, clipboard...).
                if obs.side_effects.iter().any(|e| e == "download") {
                    "download"
                } else {
                    "side_effect"
                }
            } else {
                obs.snapshot
                    .as_ref()
                    .map(crate::dom::snapshot::describe_dom_change)
                    .unwrap_or("other")
            };
            record.dom_change = Some(kind.to_string());
        }
        InteractionEffect::NoEffect => match handler_exception(capture, write_guard_active) {
            Some(message) => {
                record.outcome = InteractionOutcome::Error;
                record.error = Some(message);
            }
            None => record.outcome = InteractionOutcome::NoEffect,
        },
        InteractionEffect::Error(message) => apply_failure(record, message),
    }
}

/// Extract the covering element selector/description from a prepare `obscured`
/// detail string (e.g. `"covered by div[data-radix-overlay]"` -> `Some("div[data-radix-overlay]")`).
fn extract_obscured_by(detail: &str) -> Option<String> {
    let trimmed = detail.trim();
    let blocker = if trimmed
        .get(..11)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("covered by "))
    {
        trimmed[11..].trim()
    } else {
        trimmed
    };
    if blocker.is_empty() || blocker.eq_ignore_ascii_case("nothing at the click point") {
        return None;
    }
    Some(blocker.to_string())
}

/// A click/type that failed. Missing or unclickable targets are not the
/// control's fault (an earlier action hid or removed it), so they are
/// recorded as skipped; anything else is an `error`.
fn apply_failure(record: &mut InteractionRecord, message: &str) {
    record.error = Some(truncate_message(message));
    match failure_skip_reason(message) {
        Some(reason) => {
            record.outcome = InteractionOutcome::Skipped;
            record.skipped_reason = Some(reason.to_string());
            if reason == "obscured"
                && let Some((_, rest)) = message.split_once("covered by ")
            {
                record.obscured_by = extract_obscured_by(rest);
            }
        }
        None => record.outcome = InteractionOutcome::Error,
    }
}

fn failure_skip_reason(message: &str) -> Option<&'static str> {
    let m = message.to_ascii_lowercase();
    if m.contains("not interactable (hidden)") {
        return Some("hidden");
    }
    if m.contains("not interactable (obscured)") {
        return Some("obscured");
    }
    if m.contains("locator_not_found")
        || m.contains("find element")
        || m.contains("could not find node")
        || m.contains("detached from document")
    {
        Some("element_not_found")
    } else if m.contains("not visible")
        || m.contains("not of type htmlelement")
        || m.contains("scrolling failed")
        || m.contains("content quads")
    {
        Some("element_not_interactable")
    } else {
        None
    }
}

/// The first uncaught exception raised during the action. Fetch rejections are
/// ignored while the write guard is active: blocking a write rejects the
/// page's `fetch` by design.
fn handler_exception(capture: &ActionCapture, write_guard_active: bool) -> Option<String> {
    capture
        .exceptions
        .iter()
        .find(|message| !(write_guard_active && is_fetch_rejection(message)))
        .cloned()
}

fn is_fetch_rejection(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    [
        "failed to fetch",
        "networkerror when attempting to fetch",
        "load failed",
        "err_blocked_by_client",
        "net::err_failed",
        "network error",
    ]
    .iter()
    .any(|needle| m.contains(needle))
}

fn truncate_message(message: &str) -> String {
    const MAX: usize = 400;
    let line = message.lines().next().unwrap_or("").trim();
    if line.chars().count() <= MAX {
        line.to_string()
    } else {
        let mut out: String = line.chars().take(MAX).collect();
        out.push('…');
        out
    }
}

/// `InteractiveElement::interaction_result` for a recorded outcome.
fn interaction_result_for(
    record: &InteractionRecord,
    obs: Option<&InteractionObservation>,
) -> Option<InteractionResult> {
    match record.outcome {
        InteractionOutcome::Navigated => Some(InteractionResult::Navigation {
            target_view: record.after_url.clone().unwrap_or_default(),
        }),
        InteractionOutcome::DomChange => {
            let modal = obs
                .and_then(|o| o.snapshot.as_ref())
                .and_then(|s| s.modal_opened.as_ref());
            Some(match modal {
                Some(modal) => InteractionResult::ModalOpen {
                    modal_id: modal.selector.clone(),
                },
                None => InteractionResult::DomMutation {
                    description: record.dom_change.clone().unwrap_or_else(|| "other".into()),
                },
            })
        }
        InteractionOutcome::NoEffect => Some(InteractionResult::NoEffect),
        InteractionOutcome::Error => Some(InteractionResult::Error {
            message: record.error.clone().unwrap_or_default(),
        }),
        InteractionOutcome::Skipped => None,
    }
}

/// Remember a control as exercised on `view_id` (scan-wide), or drop this
/// view's claim on it when the attempt ended up skipped.
fn remember_exercised(
    shared: &SharedState<'_>,
    planned: &Planned<'_>,
    view_id: &str,
    record: &InteractionRecord,
) {
    if record.outcome == InteractionOutcome::Skipped
        || (planned.submit
            && !record.network_activity
            && record.side_effects.iter().any(|s| s == "form_validation"))
    {
        release_claim(shared, planned, view_id);
        return;
    }
    lock_state(shared).exercised_controls.insert(
        planned.key.clone(),
        ExercisedControl {
            view_id: view_id.to_string(),
            navigated: record.outcome == InteractionOutcome::Navigated,
            claimed: false,
        },
    );
}

/// Result of [`claim_control`].
#[derive(Debug, PartialEq, Eq)]
enum Claim {
    /// Exercise it: unclaimed (now claimed by this view), or this view's.
    Granted,
    /// Another view (another tab, since this pass was planned) claimed or
    /// exercised it, and it is not exercised again here.
    Elsewhere(String),
    /// Page content a sibling instance of the route template claimed or
    /// exercised since this pass was planned: exercised again here, but
    /// after the controls nobody exercised yet.
    Sibling,
}

/// Claim `planned` for `view_id` right before exercising it, so a tab
/// exploring another view in parallel leaves it alone.
fn claim_control(shared: &SharedState<'_>, planned: &Planned<'_>, view_id: &str) -> Claim {
    let mut st = lock_state(shared);
    match st.exercised_controls.get(&planned.key) {
        Some(prev) if base_view_id(&prev.view_id) != base_view_id(view_id) => {
            if !planned.sibling_reexercise {
                Claim::Elsewhere(prev.view_id.clone())
            } else if !planned.on_sibling {
                Claim::Sibling
            } else {
                Claim::Granted
            }
        }
        Some(_) => Claim::Granted,
        None => {
            st.exercised_controls.insert(
                planned.key.clone(),
                ExercisedControl {
                    view_id: view_id.to_string(),
                    navigated: false,
                    claimed: true,
                },
            );
            Claim::Granted
        }
    }
}

/// Drop every claim `view_id` (and its nested states) still holds: a visit
/// cut short (watchdog) never finished those controls, so later views may.
pub(super) fn release_view_claims(controls: &mut ExercisedControls, view_id: &str) {
    controls.retain(|_, c| !(c.claimed && base_view_id(&c.view_id) == view_id));
}

/// Drop `view_id`'s claim on a control it did not get to exercise (hidden,
/// covered, out of time): a later view may still exercise it.
fn release_claim(shared: &SharedState<'_>, planned: &Planned<'_>, view_id: &str) {
    let mut st = lock_state(shared);
    if st
        .exercised_controls
        .get(&planned.key)
        .is_some_and(|c| c.claimed && c.view_id == view_id)
    {
        st.exercised_controls.remove(&planned.key);
    }
}

/// Resolve control identities, drop controls already exercised on another
/// view (`exercised_elsewhere`) and sample repeated identical controls.
async fn plan_targets<'e>(
    ctx: &PassContext<'_>,
    shared: &SharedState<'_>,
    rec: &mut PassRecorder<'_>,
    view_id: &str,
    candidates: Vec<Candidate<'e>>,
) -> Vec<Planned<'e>> {
    let elements: Vec<&InteractiveElement> = candidates.iter().map(|c| c.el).collect();
    let placements = element_placements(ctx.page, &elements).await;
    let st = lock_state(shared);
    let exercised = &st.exercised_controls;
    let scope = ctx.identity_scope;
    let full_instance = ctx
        .template_instance
        .is_some_and(|n| n <= FULL_TEMPLATE_INSTANCES);
    let mut group_counts: HashMap<String, usize> = HashMap::new();
    let mut planned = Vec::with_capacity(candidates.len());
    for (candidate, placement) in candidates.into_iter().zip(placements) {
        let el = candidate.el;
        let landmark = placement.landmark;
        let key = exercise_identity_key(el, landmark.as_deref(), scope, view_id);
        let previous = exercised.get(&key);
        // Page content of the first instances of a route template is
        // exercised again (data-driven differences), after the rest.
        let sibling_reexercise = full_instance && landmark.is_none();
        // Controls inside this view's own modals/panels (`view:d1:0`) are
        // re-exercised: closing one modal does not close the next.
        let mut on_sibling = false;
        if let Some(prev) =
            previous.filter(|prev| base_view_id(&prev.view_id) != base_view_id(view_id))
        {
            if sibling_reexercise {
                on_sibling = true;
            } else {
                rec.exercised_elsewhere(el, &prev.view_id);
                continue;
            }
        }
        if is_groupable_control(el) {
            let seen = group_counts.entry(key.clone()).or_insert(0);
            *seen += 1;
            if *seen > MAX_REPEATED_CONTROLS_PER_VIEW {
                rec.skip(el, "repeated_control");
                continue;
            }
        }
        planned.push(Planned {
            el,
            known_to_navigate: previous.is_some_and(|prev| prev.navigated),
            key,
            shell: landmark.is_some(),
            submit: candidate.submit,
            deferred: candidate.deferred,
            on_sibling,
            sibling_reexercise,
            form_index: placement.form_index,
        });
    }
    planned
}

/// Top-level view of a (sub-)view id: `view_0001:d1:0` -> `view_0001`.
fn base_view_id(view_id: &str) -> &str {
    view_id.split(':').next().unwrap_or(view_id)
}

/// Exercise claims for value-changing fields belong to their DOM page. Filling
/// another tab's field does not prepare this page's form. Nested states keep
/// the owning base view's scope; buttons and submits retain shared dedupe.
fn exercise_identity_key(
    el: &InteractiveElement,
    landmark: Option<&str>,
    route_scope: &str,
    view_id: &str,
) -> String {
    let key = control_identity_key(el, landmark, route_scope);
    let page_local = is_page_local_value_control(el);
    if page_local {
        format!("view:{}|{key}", base_view_id(view_id))
    } else {
        key
    }
}

fn is_page_local_value_control(el: &InteractiveElement) -> bool {
    matches!(
        &el.element_type,
        ElementType::TextInput { .. }
            | ElementType::SelectDropdown { .. }
            | ElementType::Checkbox { .. }
            | ElementType::RadioButton { .. }
            | ElementType::Toggle
    ) || matches!(
        &el.element_type,
        ElementType::Other { role: Some(role), .. }
            if matches!(role.as_str(), "checkbox" | "radio" | "switch")
    )
}

/// Identity of a control for scan-wide dedupe: label, kind and structural
/// selector without positional indexes. Shell controls are scoped scan-wide,
/// page-content controls to the view's route template. Date-like and numeric
/// labels (calendar day cells, page numbers) are normalized, so a grid of
/// such cells is one repeated control.
fn control_identity_key(
    el: &InteractiveElement,
    landmark: Option<&str>,
    route_scope: &str,
) -> String {
    let scope = if landmark.is_some() { "*" } else { route_scope };
    let label = el
        .label
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    // Cells are addressed by their own label (`button[aria-label="Nov 5..."]`):
    // their selector says nothing about the grid they belong to.
    let (label, selector) = match repeated_cell_label(&label) {
        Some(cell) => (cell, "cell".to_string()),
        None => (label, strip_positional_selector(&el.selector)),
    };
    let kind = match &el.element_type {
        ElementType::Button { form_submit: true } => "submit_button",
        other => element_kind_slug(other),
    };
    format!(
        "{scope}|{}|{kind}|{label}|{selector}",
        landmark.unwrap_or("-"),
    )
}

/// `Some(normalized)` for a date-like or purely numeric label (`12`,
/// `nov 5, 2026, open`, `tuesday 4 march`, `2026-11-05`): digits become `#`,
/// month and weekday names become `<month>`/`<day>`.
pub(super) fn repeated_cell_label(label: &str) -> Option<String> {
    let label = label.trim();
    if label.is_empty() || !label.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let numeric = label
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | ',' | '/' | ':' | '-' | ' '));
    let mut month_or_day = false;
    let mut out = String::with_capacity(label.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String, month_or_day: &mut bool| {
        if word.is_empty() {
            return;
        }
        let w = word.to_ascii_lowercase();
        if w.len() >= 3 && month_name(&w) {
            out.push_str("<month>");
            *month_or_day = true;
        } else if w.len() >= 3 && day_name(&w) {
            out.push_str("<day>");
            *month_or_day = true;
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    let mut last_digit = false;
    for c in label.chars() {
        if c.is_ascii_alphabetic() {
            word.push(c);
            last_digit = false;
            continue;
        }
        flush(&mut word, &mut out, &mut month_or_day);
        if c.is_ascii_digit() {
            if !last_digit {
                out.push('#');
            }
            last_digit = true;
        } else {
            out.push(c);
            last_digit = false;
        }
    }
    flush(&mut word, &mut out, &mut month_or_day);
    let iso_date = label.len() >= 10
        && label.as_bytes()[4] == b'-'
        && label.as_bytes()[7] == b'-'
        && label[..4].chars().all(|c| c.is_ascii_digit());
    let hyphenated_digits = out.contains("#-#") || out.contains("#/#");
    (numeric || month_or_day || iso_date || hyphenated_digits).then_some(out)
}

fn month_name(w: &str) -> bool {
    const FULL: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    FULL.iter().any(|m| m.starts_with(w)) || w == "sept"
}

fn day_name(w: &str) -> bool {
    const FULL: [&str; 7] = [
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ];
    FULL.iter().any(|d| d.starts_with(w)) || ["tues", "thur", "thurs"].contains(&w)
}

/// Scope page-content control identities are keyed by for a view at `url`:
/// the route template for instances of a template (`/towns/:slug`), else
/// the route ([`route_scope`]).
pub(super) fn identity_scope(
    sampler: &super::template_sampler::TemplateSampler,
    url: &str,
) -> String {
    let route = sampler.template_of(url).unwrap_or_else(|| route_scope(url));
    super::url_utils::ui_state_scope(route, url)
}

/// Route template of a URL without its query (`/products/:id`, `/#/cart`).
/// A hash router at its root (`/#/`) is the same route as `/`.
pub(super) fn route_scope(url: &str) -> String {
    let key = crate::explorer::template_sampler::route_key(url);
    let path = key.split_once('?').map_or(key.as_str(), |(path, _)| path);
    match path.strip_suffix("/#/") {
        Some("") => "/".to_string(),
        Some(base) => base.to_string(),
        None => path.to_string(),
    }
}

/// Remove `:nth-of-type(n)` / `:nth-child(n)`-style positional pseudo-classes.
fn strip_positional_selector(selector: &str) -> String {
    let mut out = String::with_capacity(selector.len());
    let mut rest = selector;
    while let Some(pos) = rest.find(":nth-") {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        rest = match tail.find(')') {
            Some(end) => &tail[end + 1..],
            None => "",
        };
    }
    out.push_str(rest);
    out
}

/// Controls that may repeat per card/row with identical behavior. Form
/// fields are never sampled: identical-looking inputs are distinct fields.
fn is_textarea(el: &InteractiveElement) -> bool {
    matches!(
        &el.element_type,
        ElementType::Other { tag, .. } if tag.eq_ignore_ascii_case("textarea")
    )
}

fn maybe_register_navigation_route_fragment(obs: &InteractionObservation) {
    if !matches!(obs.effect, InteractionEffect::Navigation) {
        return;
    }
    let scroll_only =
        obs.side_effects.iter().any(|s| s == "scroll") && !obs.dom_mutated && !obs.network_activity;
    if !scroll_only && let Some(after) = obs.after_url.as_deref() {
        super::url_utils::register_route_fragment_from_url(after);
    }
}

fn is_groupable_control(el: &InteractiveElement) -> bool {
    if is_textarea(el) {
        return false;
    }
    let labeled = el.label.as_deref().is_some_and(|l| !l.trim().is_empty());
    labeled
        && matches!(
            el.element_type,
            ElementType::Button { .. }
                | ElementType::Other { .. }
                | ElementType::ModalTrigger
                | ElementType::Accordion
                | ElementType::ContextMenu
        )
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
struct ElementPlacement {
    #[serde(default)]
    landmark: Option<String>,
    #[serde(default)]
    form_index: Option<usize>,
}

/// For each element, the shell landmark it sits in (`header`, `nav`, `aside`,
/// `footer` or their ARIA roles, outside `main`) and the `document.forms` index
/// of its enclosing `<form>` (or `None` when outside any `<form>`).
async fn element_placements(
    page: &PageClient,
    elements: &[&InteractiveElement],
) -> Vec<ElementPlacement> {
    let fallback = vec![ElementPlacement::default(); elements.len()];
    if elements.is_empty() {
        return fallback;
    }
    let locators: Vec<serde_json::Value> = elements
        .iter()
        .map(|el| {
            primary_locator_json(el)
                .ok()
                .and_then(|json| serde_json::from_str(&json).ok())
                .unwrap_or(serde_json::Value::Null)
        })
        .collect();
    let Ok(locators_json) = serde_json::to_string(&locators) else {
        return fallback;
    };
    let script = format!(
        r#"
(() => {{
  const locators = {locators_json};
  {LOCATOR_RUNTIME_JS}
  const SHELL = 'header, nav, aside, footer, [role="banner"], [role="navigation"], [role="complementary"], [role="contentinfo"]';
  const forms = Array.from(document.forms || []);
  return locators.map((locator) => {{
    try {{
      const el = locator ? resolveBrokenAppLocator(locator) : null;
      if (!el || !el.closest) return {{ landmark: null, form_index: null }};
      let landmark = null;
      const shell = el.closest(SHELL);
      if (shell && !shell.closest('main, [role="main"], dialog, [role="dialog"], [role="alertdialog"], [aria-modal="true"]')) {{
        landmark = shell.getAttribute('role') || shell.tagName.toLowerCase();
      }}
      const form = el.form || el.closest('form');
      const idx = form ? forms.indexOf(form) : -1;
      return {{ landmark, form_index: idx >= 0 ? idx : null }};
    }} catch (_) {{
      return {{ landmark: null, form_index: null }};
    }}
  }});
}})()
"#
    );
    match page.evaluate_json::<Vec<ElementPlacement>>(&script).await {
        Ok(placements) if placements.len() == elements.len() => placements,
        Ok(_) => fallback,
        Err(err) => {
            tracing::debug!(error = ?err, "element placement lookup failed");
            fallback
        }
    }
}

/// Time to give the next interaction, and whether the view deadline (rather
/// than the per-interaction budget) bounds it. `None` when the view's
/// interaction time is used up.
fn interaction_window(
    deadline: Option<Instant>,
    per_interaction: Duration,
) -> Option<(Duration, bool)> {
    let Some(deadline) = deadline else {
        return Some((per_interaction, false));
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < MIN_INTERACTION_WINDOW {
        None
    } else if remaining < per_interaction {
        Some((remaining, true))
    } else {
        Some((per_interaction, false))
    }
}

/// What a (sub-)view shows: visible headings and main/form landmarks outside
/// dialogs (`items`), and open dialogs by their heading (`dialogs`). Digits
/// are masked so counters do not count as a different state.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub(super) struct StateSignature {
    #[serde(default)]
    items: Vec<String>,
    #[serde(default)]
    dialogs: Vec<String>,
}

const STATE_SIGNATURE_JS: &str = r#"
(() => {
  const vis = (el) => {
    try {
      if (typeof el.checkVisibility === 'function' && !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 || r.height > 0;
    } catch (_) { return false; }
  };
  const norm = (s) => String(s || '').replace(/\d+/g, '#').replace(/\s+/g, ' ').trim().slice(0, 80);
  const DIALOG = 'dialog[open], [role="dialog"], [role="alertdialog"], [aria-modal="true"]';
  const items = [];
  for (const h of document.querySelectorAll('h1, h2, h3, [role="heading"]')) {
    if (items.length >= 60) break;
    if (!vis(h) || h.closest(DIALOG)) continue;
    items.push('h:' + norm(h.innerText || h.textContent));
  }
  for (const l of document.querySelectorAll('main, [role="main"], form, [aria-current="step"]')) {
    if (items.length >= 80) break;
    if (!vis(l) || l.closest(DIALOG)) continue;
    const step = l.matches('[aria-current="step"]') ? ':' + norm(l.textContent) : '';
    items.push('l:' + l.tagName.toLowerCase() + step);
  }
  const dialogs = [];
  for (const d of document.querySelectorAll(DIALOG)) {
    if (dialogs.length >= 10) break;
    if (!vis(d)) continue;
    const h = d.querySelector('h1, h2, h3, [role="heading"]');
    dialogs.push('d:' + norm(h ? (h.innerText || h.textContent) : (d.getAttribute('aria-label') || '')));
  }
  return { items, dialogs };
})()
"#;

pub(super) async fn state_signature(page: &PageClient) -> Option<StateSignature> {
    page.evaluate_json::<StateSignature>(STATE_SIGNATURE_JS)
        .await
        .ok()
}

/// The view no longer shows what it showed (`base`): a heading, landmark or
/// dialog is gone, or a dialog opened. New content alone (an expanded
/// accordion, an opened sidenav) is not a different state.
pub(super) fn state_drifted(base: &StateSignature, now: &StateSignature) -> bool {
    fn counts(items: &[String]) -> HashMap<&str, usize> {
        let mut out = HashMap::new();
        for item in items {
            *out.entry(item.as_str()).or_insert(0) += 1;
        }
        out
    }
    let now_items = counts(&now.items);
    let now_dialogs = counts(&now.dialogs);
    let base_dialogs = counts(&base.dialogs);
    let missing = |base: HashMap<&str, usize>, now: &HashMap<&str, usize>| {
        base.into_iter()
            .any(|(k, n)| now.get(k).copied().unwrap_or(0) < n)
    };
    missing(counts(&base.items), &now_items)
        || missing(base_dialogs.clone(), &now_dialogs)
        || missing(now_dialogs, &base_dialogs)
}

/// The only difference from `base` is one or more dialogs that opened.
fn only_dialogs_added(base: &StateSignature, now: &StateSignature) -> bool {
    let without_dialogs = |s: &StateSignature| StateSignature {
        items: s.items.clone(),
        dialogs: Vec::new(),
    };
    now.dialogs.len() > base.dialogs.len()
        && !state_drifted(&without_dialogs(base), &without_dialogs(now))
        && base.dialogs.iter().all(|d| now.dialogs.contains(d))
}

#[derive(Debug)]
struct PreparedFormInput {
    element: InteractiveElement,
    native_state: Option<NativeControlState>,
    form_index: Option<usize>,
}

/// The state an interaction pass keeps its (sub-)view in.
#[derive(Debug, Default)]
pub(super) struct ViewState {
    /// What the view looks like when it is in its starting state.
    baseline: Option<StateSignature>,
    /// Headings/landmarks that changed while the pass changed nothing
    /// (carousels, rotating banners, live headings): ignored when comparing,
    /// so they do not cost a reload before every control.
    volatile: HashSet<String>,
    /// Nothing visible was changed by the pass since the last state check
    /// (the last control had no effect or was not exercised).
    quiet: bool,
    /// No text field values are captured: these are this pass's already authorized
    /// deterministic typing intents and ephemeral native value states. Custom
    /// mutable actions remain unsupported.
    prepared_inputs: Vec<PreparedFormInput>,
    prepared_unsupported: bool,
    prepared_unsupported_forms: HashSet<Option<usize>>,
    preparation_invalidated: bool,
    recovered_forms: HashSet<Option<usize>>,
    #[cfg_attr(not(test), allow(dead_code))]
    recovery_failure: Option<&'static str>,
    recovery_failures_by_form: HashMap<Option<usize>, &'static str>,
    document_origin: Option<u64>,
}

impl ViewState {
    fn new(baseline: Option<StateSignature>) -> Self {
        Self {
            baseline,
            volatile: HashSet::new(),
            quiet: true,
            ..Self::default()
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn remember_preparation(
        &mut self,
        el: &InteractiveElement,
        record: &InteractionRecord,
        native_state: Option<NativeControlState>,
    ) {
        self.remember_preparation_in_form(el, record, native_state, None);
    }

    fn remember_preparation_in_form(
        &mut self,
        el: &InteractiveElement,
        record: &InteractionRecord,
        native_state: Option<NativeControlState>,
        form_index: Option<usize>,
    ) {
        if !successful_preparation(record) || !is_page_local_value_control(el) {
            return;
        }
        if matches!(el.element_type, ElementType::TextInput { .. }) || native_state.is_some() {
            let prepared = PreparedFormInput {
                element: el.clone(),
                native_state,
                form_index,
            };
            if let Some(prior) = self
                .prepared_inputs
                .iter_mut()
                .find(|prior| prior.element.selector == el.selector)
            {
                *prior = prepared;
            } else {
                self.prepared_inputs.push(prepared);
            }
        } else {
            self.mark_unsupported_for_form(form_index);
        }
    }

    fn mark_unsupported_for_form(&mut self, form_index: Option<usize>) {
        self.prepared_unsupported = true;
        self.prepared_unsupported_forms.insert(form_index);
    }

    fn invalidate_preparations(&mut self) {
        if !self.prepared_inputs.is_empty() || self.prepared_unsupported {
            self.preparation_invalidated = true;
            self.recovered_forms.clear();
        }
    }

    fn observe_document(&mut self, origin: Option<u64>) {
        // A nested pass or app-initiated reload can replace the document while
        // preserving both the URL and heading signature of its parent pass.
        if self.document_origin != origin {
            self.invalidate_preparations();
            self.document_origin = origin;
        }
    }

    fn has_preparation_for_form(&self, form_index: Option<usize>) -> bool {
        self.prepared_unsupported_forms.contains(&form_index)
            || self
                .prepared_inputs
                .iter()
                .any(|p| p.form_index == form_index)
    }

    fn needs_recovery_for_form(&self, form_index: Option<usize>) -> bool {
        self.preparation_invalidated
            && !self.recovered_forms.contains(&form_index)
            && self.has_preparation_for_form(form_index)
    }

    fn recovery_failure_for_form(&self, form_index: Option<usize>) -> Option<&'static str> {
        self.recovery_failures_by_form.get(&form_index).copied()
    }

    fn record_recovery_failure(&mut self, form_index: Option<usize>, reason: &'static str) {
        self.recovery_failures_by_form.insert(form_index, reason);
        self.recovery_failure = Some(reason);
    }

    fn mark_form_recovered(&mut self, form_index: Option<usize>) {
        self.recovered_forms.insert(form_index);
        let all_recovered = self
            .prepared_inputs
            .iter()
            .all(|p| self.recovered_forms.contains(&p.form_index))
            && self
                .prepared_unsupported_forms
                .iter()
                .all(|f| self.recovered_forms.contains(f));
        if all_recovered {
            self.preparation_invalidated = false;
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn recovery_precondition(
        &self,
        used: usize,
        limit: usize,
    ) -> std::result::Result<(), &'static str> {
        if let Some(reason) = self.recovery_failure {
            return Err(reason);
        }
        if self.prepared_unsupported {
            return Err("form_state_recovery_unsupported");
        }
        if !self.preparation_invalidated {
            return Ok(());
        }
        if !self.prepared_inputs.is_empty()
            && used.saturating_add(self.prepared_inputs.len()) > limit
        {
            return Err("form_state_recovery_interaction_limit");
        }
        Ok(())
    }

    fn recovery_precondition_for_form(
        &self,
        form_index: Option<usize>,
        used: usize,
        limit: usize,
    ) -> std::result::Result<(), &'static str> {
        if let Some(reason) = self.recovery_failure_for_form(form_index) {
            return Err(reason);
        }
        if self.prepared_unsupported_forms.contains(&form_index) {
            return Err("form_state_recovery_unsupported");
        }
        if !self.needs_recovery_for_form(form_index) {
            return Ok(());
        }
        let needed = self
            .prepared_inputs
            .iter()
            .filter(|p| p.form_index == form_index)
            .count();
        if needed > 0 && used.saturating_add(needed) > limit {
            return Err("form_state_recovery_interaction_limit");
        }
        Ok(())
    }

    fn strip(&self, sig: &StateSignature) -> StateSignature {
        StateSignature {
            items: sig
                .items
                .iter()
                .filter(|item| !self.volatile.contains(*item))
                .cloned()
                .collect(),
            dialogs: sig.dialogs.clone(),
        }
    }

    /// `now` no longer shows the baseline state. Headings that drifted
    /// while the pass changed nothing are learned as volatile instead.
    fn drifted(&mut self, now: &StateSignature) -> bool {
        let Some(base) = self.baseline.as_ref() else {
            return false;
        };
        let (base, now_kept) = (self.strip(base), self.strip(now));
        if !state_drifted(&base, &now_kept) {
            return false;
        }
        let dialogs_changed = state_drifted(
            &StateSignature {
                items: Vec::new(),
                dialogs: base.dialogs.clone(),
            },
            &StateSignature {
                items: Vec::new(),
                dialogs: now_kept.dialogs.clone(),
            },
        );
        if self.quiet && !dialogs_changed {
            let before: HashSet<&String> = base.items.iter().collect();
            let after: HashSet<&String> = now_kept.items.iter().collect();
            let learned: Vec<String> = before
                .symmetric_difference(&after)
                .map(|item| (*item).clone())
                .collect();
            tracing::debug!(?learned, "view headings change on their own");
            self.volatile.extend(learned);
            return false;
        }
        true
    }
}

fn successful_preparation(record: &InteractionRecord) -> bool {
    matches!(
        record.outcome,
        InteractionOutcome::NoEffect | InteractionOutcome::DomChange
    ) && record.error.is_none()
        && record.console_errors.is_empty()
        && record.skipped_reason.is_none()
}

/// Reject a missing/replaced field before reusing an intent. This checks only
/// identity metadata, never reads or persists the field's value.
async fn recovery_input_matches(page: &PageClient, el: &InteractiveElement) -> bool {
    let ElementType::TextInput {
        input_type, name, ..
    } = &el.element_type
    else {
        return false;
    };
    let Ok(locator) = primary_locator_json(el) else {
        return false;
    };
    let identity = serde_json::json!({"type":input_type,"name":name});
    let script = format!(
        r#"(() => {{
        {LOCATOR_RUNTIME_JS}
        const el = resolveBrokenAppLocator({locator});
        const expected = {identity};
        return !!el && el.tagName === 'INPUT' && el.type === expected.type
          && (el.getAttribute('name') || null) === expected.name;
    }})()"#
    );
    page.evaluate_json::<bool>(&script).await.unwrap_or(false)
}

/// Re-establish only preparation that actually ran in this pass for
/// `target_form`. Recovery actions are ordinary field evidence with their own
/// IDs, never new controls or another attempt at the button that caused the
/// restore. They consume the existing budget, leaving the caller's next
/// action/submit slot intact.
async fn recover_form_preparation(
    ctx: &PassContext<'_>,
    st: &mut PassState<'_, '_>,
    rec: &mut PassRecorder<'_>,
    view: &mut ViewState,
    target_form: Option<usize>,
    interacted: &mut usize,
    limit: usize,
) -> std::result::Result<(), &'static str> {
    if !view.needs_recovery_for_form(target_form) {
        return view.recovery_precondition_for_form(target_form, *interacted, limit);
    }
    let tab = ctx.page.tab();
    ctx.network.set_current_interaction_on(&tab, None);
    ctx.network.forget_recent_interactions_on(&tab);
    let result =
        recover_form_preparation_inner(ctx, st, rec, view, target_form, interacted, limit).await;
    // Neither restoration nor field recovery may become the fallback owner
    // of a later request from the no-op button or a submit.
    let tab = ctx.page.tab();
    ctx.network.set_current_interaction_on(&tab, None);
    ctx.network.forget_recent_interactions_on(&tab);
    if let Err(reason) = result {
        view.record_recovery_failure(target_form, reason);
    }
    result
}

async fn recover_form_preparation_inner(
    ctx: &PassContext<'_>,
    st: &mut PassState<'_, '_>,
    rec: &mut PassRecorder<'_>,
    view: &mut ViewState,
    target_form: Option<usize>,
    interacted: &mut usize,
    limit: usize,
) -> std::result::Result<(), &'static str> {
    view.recovery_precondition_for_form(target_form, *interacted, limit)?;
    if !view.needs_recovery_for_form(target_form) {
        return Ok(());
    }
    // Restore a selected radio before its unchecked peers: normal group
    // behavior then restores those peers without a transient empty group or
    // extra change events. Other preparations retain their original order.
    let unchecked_radio = |p: &&PreparedFormInput| {
        p.native_state
            .as_ref()
            .is_some_and(NativeControlState::is_unchecked_radio)
    };
    let recovery_order = view
        .prepared_inputs
        .iter()
        .filter(|p| p.form_index == target_form && !unchecked_radio(p))
        .chain(
            view.prepared_inputs
                .iter()
                .filter(|p| p.form_index == target_form && unchecked_radio(p)),
        );
    for prepared in recovery_order {
        let el = &prepared.element;
        let Some((timeout, _)) = interaction_window(ctx.deadline, per_interaction_budget(ctx.cfg))
        else {
            rec.skip(el, "form_state_recovery_time_budget");
            return Err("form_state_recovery_time_budget");
        };
        let matches = tokio::time::timeout(timeout, async {
            match prepared.native_state.as_ref() {
                Some(state) => {
                    crate::dom::interaction::native_state_compatible(ctx.page, el, state).await
                }
                None => recovery_input_matches(ctx.page, el).await,
            }
        })
        .await;
        if !matches!(matches, Ok(true)) {
            rec.skip(el, "form_state_recovery_target_changed");
            return Err("form_state_recovery_target_changed");
        }
        let Some((timeout, _)) = interaction_window(ctx.deadline, per_interaction_budget(ctx.cfg))
        else {
            rec.skip(el, "form_state_recovery_time_budget");
            return Err("form_state_recovery_time_budget");
        };
        let action = if prepared.native_state.is_some() {
            "recover_value"
        } else {
            "recover_type"
        };
        let mut recovery = exercise_with_native_state(
            ctx.page,
            ctx.cfg,
            ctx.network,
            ctx.bug_detector,
            rec.view_id,
            ctx.view_url,
            el,
            action,
            timeout,
            false,
            prepared.native_state.as_ref(),
        )
        .await;
        if !recovery.not_attempted() {
            *interacted += 1;
            lock_state(st.shared).elements_interacted += 1;
        }
        st.pacer.after_interaction(ctx.network.as_ref()).await;
        let succeeded = if let Some(obs) = recovery.observation.as_ref() {
            apply_observation(
                &mut recovery.record,
                obs,
                &recovery.capture,
                write_guard_active(ctx.cfg),
            );
            !recovery.timed_out && !obs.click_missed && successful_preparation(&recovery.record)
        } else {
            false
        };
        let same_document = document_origin(ctx.page).await == view.document_origin;
        if !succeeded || !same_document {
            // A failed prerequisite is a scanner coverage gap, not a fresh
            // app failure or permission to submit a partially prepared form.
            recovery.record.outcome = InteractionOutcome::Skipped;
            recovery.record.skipped_reason = Some("form_state_recovery_failed".into());
            rec.gap(el, "form_state_recovery_failed");
            rec.write(&recovery.record);
            return Err("form_state_recovery_failed");
        }
        rec.write(&recovery.record);
    }
    // Verify the final coupled state after all handlers have settled: restoring
    // a later radio or select must not silently undo an earlier prerequisite.
    for prepared in view
        .prepared_inputs
        .iter()
        .filter(|p| p.form_index == target_form)
    {
        if let Some(expected) = prepared.native_state.as_ref() {
            let Some((timeout, _)) =
                interaction_window(ctx.deadline, per_interaction_budget(ctx.cfg))
            else {
                rec.skip(&prepared.element, "form_state_recovery_time_budget");
                return Err("form_state_recovery_time_budget");
            };
            let actual = tokio::time::timeout(
                timeout,
                crate::dom::interaction::capture_native_state(ctx.page, &prepared.element),
            )
            .await;
            if !matches!(actual, Ok(Some(ref actual)) if actual == expected) {
                rec.skip(&prepared.element, "form_state_recovery_failed");
                return Err("form_state_recovery_failed");
            }
        }
    }
    view.mark_form_recovered(target_form);
    Ok(())
}

/// Make sure the page shows the view before the next control: restore the
/// view URL when an earlier control navigated away, and reload it when an
/// earlier control moved a single-URL app to another state (wizard step,
/// leftover dialog). Nested passes replay their `trail` of triggers after
/// the reload. Returns `false` when the view could not be restored.
async fn ensure_on_view(
    ctx: &PassContext<'_>,
    trail: &[InteractiveElement],
    view: &mut ViewState,
) -> bool {
    view.observe_document(document_origin(ctx.page).await);
    let current = ctx.page.url().await.ok().flatten().unwrap_or_default();
    if super::engine::view_urls_match_for_restore(&current, ctx.view_url) {
        let now = state_signature(ctx.page).await;
        let drifted = now.as_ref().is_some_and(|now| view.drifted(now));
        view.quiet = true;
        if !drifted {
            return true;
        }
        // A dialog left open over an otherwise unchanged view: close it.
        if let Some(base) = view.baseline.as_ref().map(|b| view.strip(b))
            && let Some(now) = now.as_ref().map(|n| view.strip(n))
            && only_dialogs_added(&base, &now)
        {
            let _ = crate::dom::interaction::dismiss_modal(ctx.page, 500).await;
            if state_signature(ctx.page)
                .await
                .is_some_and(|after| !state_drifted(&base, &view.strip(&after)))
            {
                return true;
            }
        }
        tracing::debug!(view_url = %ctx.view_url, "view state changed without a URL change; reloading");
        return restore_view(ctx, trail, view, true).await;
    }
    view.quiet = true;
    restore_view(ctx, trail, view, false).await
}

/// Bring the view back: navigate to the view URL (or reload it when
/// `reload`), wait for it, dismiss on-load overlays and replay `trail`.
/// The restored state becomes the pass baseline. `false` when the view
/// could not be loaded or the path to a nested state could not be
/// replayed.
async fn restore_view(
    ctx: &PassContext<'_>,
    trail: &[InteractiveElement],
    view: &mut ViewState,
    reload: bool,
) -> bool {
    let timeout = match ctx.deadline {
        Some(deadline) => deadline
            .saturating_duration_since(Instant::now())
            .min(RESTORE_NAVIGATION_TIMEOUT),
        None => RESTORE_NAVIGATION_TIMEOUT,
    };
    if timeout.is_zero() {
        return false;
    }
    // Nothing the restore loads (bootstrap calls, replayed clicks) belongs
    // to the last exercised control.
    let tab = ctx.page.tab();
    ctx.network.set_current_interaction_on(&tab, None);
    ctx.network.forget_recent_interactions_on(&tab);

    let restore_started = Instant::now();
    // Any actual restore may remount same-document state as well as reload a
    // document. Mark outside the inner function so its early return is covered.
    view.invalidate_preparations();
    let restored = restore_view_inner(ctx, trail, view, reload, timeout).await;
    view.observe_document(document_origin(ctx.page).await);
    view.quiet = true;
    tracing::debug!(
        view_url = %ctx.view_url,
        reload,
        replayed = trail.len(),
        restored,
        elapsed_ms = u64::try_from(restore_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "view restore"
    );
    restored
}

async fn restore_view_inner(
    ctx: &PassContext<'_>,
    trail: &[InteractiveElement],
    view: &mut ViewState,
    reload: bool,
    timeout: Duration,
) -> bool {
    let page = ctx.page;
    // A navigation back to the view URL that loaded a new document already
    // reset in-memory state: it needs no second load.
    let mut fresh = false;
    if !reload {
        let before = document_origin(page).await;
        if !super::engine::restore_page_to_view_url(page, ctx.view_url, ctx.cfg, timeout).await {
            return false;
        }
        fresh = before.is_some() && document_origin(page).await != before;
        // A same-document restore (hash route) can leave state behind (an
        // open dialog); a top-level view is done when it matches again.
        if trail.is_empty() {
            let drifted = match (view.baseline.as_ref(), state_signature(page).await) {
                (Some(base), Some(now)) => state_drifted(&view.strip(base), &view.strip(&now)),
                _ => false,
            };
            if !drifted {
                return true;
            }
        }
    }
    if !fresh {
        if let Err(err) = page.reload_and_wait(timeout).await {
            tracing::debug!(error = ?err, view_url = %ctx.view_url, "view reload failed");
            return false;
        }
        let settle = Duration::from_millis(ctx.cfg.scan.settle_timeout_ms.max(500));
        let _ = cdp_helpers::settle_page(page, settle).await;
        if crate::dom::interaction::dismiss_blocking_overlays(page).await > 0 {
            let _ = cdp_helpers::settle(page, Duration::from_millis(700)).await;
        }
    }

    if !trail.is_empty() {
        for trigger in trail {
            let step = tokio::time::timeout(
                per_interaction_budget(ctx.cfg),
                replay_step(page, ctx.cfg, trigger),
            )
            .await;
            if !matches!(step, Ok(true)) {
                tracing::debug!(selector = %trigger.selector, "could not replay the path to a nested state");
                return false;
            }
        }
        ctx.network.forget_recent_interactions_on(&page.tab());
    }

    let Some(now) = state_signature(page).await else {
        return true;
    };
    if view
        .baseline
        .as_ref()
        .is_some_and(|base| state_drifted(&view.strip(base), &view.strip(&now)))
    {
        // A fresh top-level view is the canonical state. A nested state
        // reached again by replaying its path is the closest reproduction
        // (an app that remembers a typed name shows it in a heading): its
        // remaining controls are still exercised there.
        tracing::debug!(
            view_url = %ctx.view_url,
            nested = !trail.is_empty(),
            "restored state differs from the pass baseline; adopting it"
        );
    }
    view.baseline = Some(now);
    true
}

/// `performance.timeOrigin` of the current document (unique per document).
async fn document_origin(page: &PageClient) -> Option<u64> {
    page.evaluate_json::<f64>("(performance && performance.timeOrigin) || 0")
        .await
        .ok()
        .filter(|origin| *origin > 0.0)
        .map(|origin| origin.to_bits())
}

/// Replay one trigger on the way back to a nested state (not recorded, not
/// attributed). A trigger that was enabled by filling its form (a gated
/// wizard step) is enabled the same way again.
async fn replay_step(
    page: &PageClient,
    cfg: &BrokenAppConfig,
    trigger: &InteractiveElement,
) -> bool {
    let scan = interaction_scan_config(cfg);
    let mut opts = crate::dom::interaction::prepare_options(trigger, &scan);
    opts.unlock = is_button_like(&trigger.element_type);
    match crate::dom::interaction::prepare_target(page, trigger, &opts).await {
        Ok(Prepared::Ready(prepared)) => matches!(
            crate::dom::interaction::perform_prepared(page, trigger, &prepared, &scan).await,
            Ok(obs) if !matches!(obs.effect, InteractionEffect::Error(_))
        ),
        _ => false,
    }
}

/// Visible `a[href]` attribute values, to cheaply detect links revealed by a click.
const VISIBLE_LINK_HREFS_JS: &str = r#"
(() => {
  const out = [];
  for (const a of document.querySelectorAll('a[href]')) {
    if (out.length >= 500) break;
    const style = window.getComputedStyle(a);
    if (!style || style.display === 'none' || style.visibility === 'hidden') continue;
    const r = a.getBoundingClientRect();
    if (!r || r.width <= 0 || r.height <= 0) continue;
    out.push(a.getAttribute('href') || '');
  }
  return out;
})()
"#;

/// After a click changed the DOM, collect same-origin links that became
/// visible (off-canvas sidenavs, menus, popovers) and were not known yet.
async fn harvest_revealed_links(
    ctx: &PassContext<'_>,
    view_id: &str,
    known: &mut HashSet<String>,
    revealed: &mut Vec<InteractiveElement>,
) {
    let hrefs = match ctx
        .page
        .evaluate_json::<Vec<String>>(VISIBLE_LINK_HREFS_JS)
        .await
    {
        Ok(hrefs) => hrefs,
        Err(err) => {
            tracing::debug!(error = ?err, "visible link scan failed");
            return;
        }
    };
    let current = ctx
        .page
        .url()
        .await
        .ok()
        .flatten()
        .and_then(|u| Url::parse(&u).ok());
    let has_new = hrefs
        .iter()
        .filter_map(|href| super::url_utils::normalize_href(ctx.base_url, current.as_ref(), href))
        .any(|target| !known.contains(target.as_str()));
    if !has_new {
        return;
    }
    let found =
        match crate::dom::discover_interactive_elements(ctx.page, &view_id.to_string()).await {
            Ok(found) => found,
            Err(err) => {
                tracing::debug!(error = ?err, "re-discovery after reveal failed");
                return;
            }
        };
    for el in found {
        let ElementType::NavigationLink {
            href: Some(href), ..
        } = &el.element_type
        else {
            continue;
        };
        let Some(target) = super::url_utils::normalize_href(ctx.base_url, current.as_ref(), href)
        else {
            continue;
        };
        if known.insert(target.to_string()) {
            revealed.push(el);
        }
    }
}

/// Normalized same-origin targets of the link elements in `elements`.
pub(super) fn link_targets(
    base_url: &Url,
    current_url: Option<&Url>,
    elements: &[InteractiveElement],
) -> HashSet<String> {
    elements
        .iter()
        .filter_map(|el| match &el.element_type {
            ElementType::NavigationLink {
                href: Some(href), ..
            } => {
                super::url_utils::normalize_href(base_url, current_url, href).map(|u| u.to_string())
            }
            _ => None,
        })
        .collect()
}

pub(super) fn per_interaction_budget(cfg: &BrokenAppConfig) -> Duration {
    Duration::from_millis(cfg.scan.interaction_timeout_ms)
        .saturating_add(Duration::from_millis(cfg.scan.settle_timeout_ms))
        .saturating_add(Duration::from_millis(
            cfg.scan.pacing.delay_between_interactions_ms,
        ))
        .saturating_add(Duration::from_millis(750))
}

/// Whether the write guard is on, so submit-like controls may be clicked.
pub(super) fn write_guard_active(cfg: &BrokenAppConfig) -> bool {
    cfg.scan.write_guard.mode != WriteGuardMode::Off
}

/// Submit-like controls are clicked when form submission is enabled, or when
/// the scan's write guard is active: the state-changing requests they fire are
/// then recorded and blocked/stubbed instead of reaching the backend.
fn submit_clicks_allowed(cfg: &BrokenAppConfig) -> bool {
    cfg.scan.exploration.submit_forms || write_guard_active(cfg)
}

/// Scan settings handed to `dom::interaction::interact`. That primitive only
/// clicks submit-like controls when `submit_forms` is set; guarded scans opt
/// in here, where the request guard is attached. (Other callers of
/// `interact`, such as flow replay, keep the conservative default.)
fn interaction_scan_config(cfg: &BrokenAppConfig) -> Cow<'_, ScanConfig> {
    if submit_clicks_allowed(cfg) && !cfg.scan.exploration.submit_forms {
        let mut scan = cfg.scan.clone();
        scan.exploration.submit_forms = true;
        Cow::Owned(scan)
    } else {
        Cow::Borrowed(&cfg.scan)
    }
}

fn action_kind(el: &InteractiveElement) -> &'static str {
    if is_textarea(el) {
        return "type";
    }
    match &el.element_type {
        ElementType::TextInput { .. } => "type",
        ElementType::SelectDropdown { .. } => "select",
        ElementType::Checkbox { .. } | ElementType::RadioButton { .. } | ElementType::Toggle => {
            "toggle"
        }
        _ => "click",
    }
}

/// Snake-case element kind for `interactions.jsonl` (`button`, `navigation_link`, ...).
pub(super) fn element_kind_slug(element_type: &ElementType) -> &'static str {
    match element_type {
        ElementType::NavigationLink { .. } => "navigation_link",
        ElementType::Button { .. } => "button",
        ElementType::TextInput { .. } => "text_input",
        ElementType::SelectDropdown { .. } => "select_dropdown",
        ElementType::Checkbox { .. } => "checkbox",
        ElementType::RadioButton { .. } => "radio_button",
        ElementType::FileUpload { .. } => "file_upload",
        ElementType::DatePicker => "date_picker",
        ElementType::Toggle => "toggle",
        ElementType::Tab => "tab",
        ElementType::ModalTrigger => "modal_trigger",
        ElementType::DropdownMenu { .. } => "dropdown_menu",
        ElementType::Accordion => "accordion",
        ElementType::SearchBar => "search_bar",
        ElementType::Pagination => "pagination",
        ElementType::SortControl => "sort_control",
        ElementType::FilterControl => "filter_control",
        ElementType::DragHandle => "drag_handle",
        ElementType::ContextMenu => "context_menu",
        ElementType::Other { .. } => "other",
    }
}

#[cfg(test)]
mod pass_tests {
    use super::*;

    fn el(element_type: ElementType, label: Option<&str>, selector: &str) -> InteractiveElement {
        InteractiveElement {
            selector: selector.to_string(),
            label: label.map(str::to_string),
            element_type,
            interaction_result: None,
            source: None,
            found_on: "view_0001".to_string(),
            bounding_box: None,
            snapshot: None,
            disabled: false,
            empty_required_fields_in_form: 0,
            locators: Vec::new(),
        }
    }

    fn button(label: &str, selector: &str) -> InteractiveElement {
        el(
            ElementType::Button { form_submit: false },
            Some(label),
            selector,
        )
    }

    #[test]
    fn interaction_window_is_deadline_driven() {
        let per = Duration::from_secs(8);
        assert_eq!(interaction_window(None, per), Some((per, false)));

        let far = Instant::now() + Duration::from_secs(60);
        assert_eq!(interaction_window(Some(far), per), Some((per, false)));

        // Less than one full interaction left: still try, bounded by the deadline.
        let near = Instant::now() + Duration::from_secs(3);
        let (timeout, bound) = interaction_window(Some(near), per).expect("time left");
        assert!(bound && timeout <= Duration::from_secs(3));

        // Under the minimum window: stop (view_time_budget).
        let gone = Instant::now() + Duration::from_millis(200);
        assert_eq!(interaction_window(Some(gone), per), None);
    }

    #[test]
    fn identity_key_ignores_positions_and_scopes_content_by_route() {
        let a = button(
            "Add to basket",
            "div:nth-of-type(3) > button:nth-of-type(1)",
        );
        let b = button(
            "Add to  Basket",
            "div:nth-of-type(7) > button:nth-of-type(1)",
        );
        assert_eq!(
            control_identity_key(&a, None, "/products"),
            control_identity_key(&b, None, "/products")
        );
        // Page content on another route is a different control.
        assert_ne!(
            control_identity_key(&a, None, "/products"),
            control_identity_key(&a, None, "/cart")
        );
        // Shell controls are the same control on every route.
        let menu = button("Menu", "header > button.hamburger");
        assert_eq!(
            control_identity_key(&menu, Some("header"), "/products"),
            control_identity_key(&menu, Some("header"), "/#/settings")
        );
    }

    #[test]
    fn strip_positional_selector_removes_nth_pseudo_classes() {
        assert_eq!(
            strip_positional_selector("main > div:nth-of-type(2) > li:nth-child(10) > a"),
            "main > div > li > a"
        );
        assert_eq!(strip_positional_selector("#buy"), "#buy");
        assert_eq!(strip_positional_selector("a:nth-of-type(2"), "a");
    }

    #[test]
    fn route_scope_drops_query_and_keeps_hash_routes() {
        assert_eq!(route_scope("http://x.test/search?q=shoes"), "/search");
        assert_eq!(route_scope("http://x.test/#/settings"), "/#/settings");
        assert_eq!(route_scope("http://x.test/#/"), "/");
        assert_eq!(route_scope("http://x.test/"), "/");
        assert_eq!(route_scope("http://x.test/app.html#/"), "/app.html");
    }

    #[test]
    fn query_tabs_keep_repeated_edit_controls_in_separate_scopes() {
        let sampler = super::super::template_sampler::TemplateSampler::default();
        let edit = button("Edit", "main > button#edit");
        for route in ["/account", "/#/account"] {
            let profile = identity_scope(&sampler, &format!("http://x.test{route}"));
            let payout = identity_scope(&sampler, &format!("http://x.test{route}?tab=payout"));
            assert_ne!(
                control_identity_key(&edit, None, &profile),
                control_identity_key(&edit, None, &payout)
            );
        }
    }

    #[test]
    fn form_fields_are_never_sampled_as_repeated_cards() {
        let input = el(
            ElementType::TextInput {
                input_type: "text".into(),
                name: None,
                required: false,
            },
            Some("Qty"),
            "input",
        );
        assert!(!is_groupable_control(&input));
        assert!(is_groupable_control(&button("Add", "button")));
        assert!(!is_groupable_control(&el(
            ElementType::Button { form_submit: false },
            None,
            "button"
        )));
    }

    fn observation(effect: InteractionEffect) -> InteractionObservation {
        let dom_mutated = matches!(effect, InteractionEffect::DomMutation);
        InteractionObservation {
            before_url: Some("http://x.test/#/a".into()),
            after_url: Some("http://x.test/#/a".into()),
            dom_mutated,
            network_activity: false,
            effect,
            snapshot: None,
            side_effects: Vec::new(),
            already_active: false,
            click_missed: false,
            ticker_recheck: false,
        }
    }

    #[test]
    fn side_effect_only_actions_are_described_and_recorded() {
        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#print", "button");
        let mut obs = observation(InteractionEffect::DomMutation);
        obs.dom_mutated = false;
        obs.side_effects = vec!["print".into()];
        apply_observation(&mut record, &obs, &ActionCapture::default(), true);
        assert_eq!(record.outcome, InteractionOutcome::DomChange);
        assert_eq!(record.dom_change.as_deref(), Some("side_effect"));
        assert_eq!(record.side_effects, vec!["print".to_string()]);

        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#csv", "button");
        obs.side_effects = vec!["download".into()];
        apply_observation(&mut record, &obs, &ActionCapture::default(), true);
        assert_eq!(record.dom_change.as_deref(), Some("download"));

        // An already-selected filter that did nothing keeps the flag.
        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#all", "button");
        let mut obs = observation(InteractionEffect::NoEffect);
        obs.already_active = true;
        apply_observation(&mut record, &obs, &ActionCapture::default(), true);
        assert_eq!(record.outcome, InteractionOutcome::NoEffect);
        assert!(record.already_active);
    }

    #[test]
    fn repeated_cell_labels_normalize_dates_and_numbers() {
        assert_eq!(
            repeated_cell_label("nov 5, 2026, open").as_deref(),
            Some("<month> #, #, open")
        );
        assert_eq!(
            repeated_cell_label("nov 17, 2026, open"),
            repeated_cell_label("nov 5, 2026, open")
        );
        assert_ne!(
            repeated_cell_label("nov 5, 2026, booked"),
            repeated_cell_label("nov 5, 2026, open")
        );
        assert_eq!(repeated_cell_label("12").as_deref(), Some("#"));
        assert_eq!(
            repeated_cell_label("tuesday 4 march").as_deref(),
            Some("<day> # <month>")
        );
        assert_eq!(repeated_cell_label("2026-11-05").as_deref(), Some("#-#-#"));
        assert_eq!(
            repeated_cell_label("demo guest 05-014").as_deref(),
            Some("demo guest #-#")
        );
        // Ordinary labels with a number stay distinct controls.
        assert_eq!(repeated_cell_label("add 2 items"), None);
        assert_eq!(repeated_cell_label("more: 10 yard dumpster"), None);
        assert_eq!(repeated_cell_label("print selected"), None);
        assert_eq!(repeated_cell_label("monthly plan 5"), None);
    }

    #[test]
    fn calendar_cells_share_one_identity() {
        let a = button(
            "Nov 5, 2026, open",
            "button[aria-label=\"Nov 5, 2026, open\"]",
        );
        let b = button(
            "Nov 19, 2026, open",
            "button[aria-label=\"Nov 19, 2026, open\"]",
        );
        assert_eq!(
            control_identity_key(&a, None, "/towns/:slug"),
            control_identity_key(&b, None, "/towns/:slug")
        );
        assert!(is_groupable_control(&a));
    }

    #[test]
    fn state_drift_ignores_new_content_but_not_lost_content() {
        let sig = |items: &[&str], dialogs: &[&str]| StateSignature {
            items: items.iter().map(|s| s.to_string()).collect(),
            dialogs: dialogs.iter().map(|s| s.to_string()).collect(),
        };
        let step1 = sig(&["h:Welcome", "l:main"], &[]);
        // An accordion or sidenav added content: same state.
        assert!(!state_drifted(
            &step1,
            &sig(&["h:Welcome", "h:FAQ", "l:main"], &[])
        ));
        // The wizard moved on: the step heading is gone.
        assert!(state_drifted(&step1, &sig(&["h:Connect", "l:main"], &[])));
        // A dialog stayed open.
        assert!(state_drifted(
            &step1,
            &sig(&["h:Welcome", "l:main"], &["d:Privacy"])
        ));
        // Inside a dialog's state, closing it is a drift too.
        let modal = sig(&["h:Welcome", "l:main"], &["d:Privacy"]);
        assert!(state_drifted(&modal, &step1));
    }

    #[test]
    fn headings_that_change_while_nothing_was_clicked_are_volatile() {
        let sig = |items: &[&str], dialogs: &[&str]| StateSignature {
            items: items.iter().map(|s| s.to_string()).collect(),
            dialogs: dialogs.iter().map(|s| s.to_string()).collect(),
        };
        let mut view = ViewState::new(Some(sig(&["h:Slide one", "h:Pricing", "l:main"], &[])));
        // The last control changed nothing, yet the carousel heading moved
        // on: learned as volatile, no reload.
        view.quiet = true;
        assert!(!view.drifted(&sig(&["h:Slide two", "h:Pricing", "l:main"], &[])));
        // Later the carousel shows another slide after an effective click:
        // still not a drift.
        view.quiet = false;
        assert!(!view.drifted(&sig(&["h:Slide one", "h:Pricing", "l:main"], &[])));
        assert!(!view.drifted(&sig(&["h:Slide two", "h:Pricing", "l:main"], &[])));
        // A stable heading that disappears after a click is a drift.
        assert!(view.drifted(&sig(&["h:Slide two", "l:main"], &[])));
        // A dialog that opened on its own is never learned as volatile.
        view.quiet = true;
        assert!(view.drifted(&sig(
            &["h:Slide one", "h:Pricing", "l:main"],
            &["d:Newsletter"]
        )));
    }

    #[test]
    fn handler_exception_turns_no_effect_into_error() {
        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#boom", "button");
        let capture = ActionCapture {
            console_errors: vec!["Error: boom".into()],
            exceptions: vec!["Error: boom".into()],
            native_dialog: None,
        };
        apply_observation(
            &mut record,
            &observation(InteractionEffect::NoEffect),
            &capture,
            true,
        );
        assert_eq!(record.outcome, InteractionOutcome::Error);
        assert_eq!(record.error.as_deref(), Some("Error: boom"));
        assert_eq!(record.page_url, "http://x.test/#/a");

        // A fetch rejected by the write guard is not a handler bug.
        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#save", "button");
        let capture = ActionCapture {
            console_errors: vec!["TypeError: Failed to fetch".into()],
            exceptions: vec!["Uncaught (in promise) TypeError: Failed to fetch".into()],
            native_dialog: None,
        };
        let obs = observation(InteractionEffect::NoEffect);
        apply_observation(&mut record, &obs, &capture, true);
        assert_eq!(record.outcome, InteractionOutcome::NoEffect);
        // ...but it is when the guard is off (a real network failure).
        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#save", "button");
        apply_observation(&mut record, &obs, &capture, false);
        assert_eq!(record.outcome, InteractionOutcome::Error);
    }

    #[test]
    fn click_failures_on_missing_targets_are_skips_not_errors() {
        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#gone", "button");
        apply_observation(
            &mut record,
            &observation(InteractionEffect::Error(
                "find element #gone (fallbacks tried: none)".into(),
            )),
            &ActionCapture::default(),
            true,
        );
        assert_eq!(record.outcome, InteractionOutcome::Skipped);
        assert_eq!(record.skipped_reason.as_deref(), Some("element_not_found"));

        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#x", "button");
        apply_observation(
            &mut record,
            &observation(InteractionEffect::Error("click_failed: boom".into())),
            &ActionCapture::default(),
            true,
        );
        assert_eq!(record.outcome, InteractionOutcome::Error);
        assert_eq!(record.error.as_deref(), Some("click_failed: boom"));
    }

    #[test]
    fn navigation_and_dom_change_fill_after_url_and_kind() {
        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#go", "button");
        let mut obs = observation(InteractionEffect::Navigation);
        obs.after_url = Some("http://x.test/#/b".into());
        apply_observation(&mut record, &obs, &ActionCapture::default(), true);
        assert_eq!(record.outcome, InteractionOutcome::Navigated);
        assert_eq!(record.after_url.as_deref(), Some("http://x.test/#/b"));
        assert!(matches!(
            interaction_result_for(&record, Some(&obs)),
            Some(InteractionResult::Navigation { .. })
        ));

        let mut record = InteractionRecord::new("view_0001", "http://x.test/", "#menu", "button");
        let mut obs = observation(InteractionEffect::DomMutation);
        obs.snapshot = Some(InteractionSnapshot {
            attribute_changes: vec![crate::types::dom::AttributeChange {
                selector: "#sidenav".into(),
                attribute: "class".into(),
                old_value: Some("sidenav".into()),
                new_value: Some("open sidenav".into()),
            }],
            ..Default::default()
        });
        apply_observation(&mut record, &obs, &ActionCapture::default(), true);
        assert_eq!(record.outcome, InteractionOutcome::DomChange);
        assert_eq!(record.dom_change.as_deref(), Some("menu"));
    }

    #[test]
    fn element_kind_slug_matches_serde_kind() {
        for element_type in [
            ElementType::Button { form_submit: true },
            ElementType::NavigationLink {
                href: None,
                in_nav: false,
            },
            ElementType::DropdownMenu { in_nav: true },
            ElementType::Pagination,
        ] {
            let kind = serde_json::to_value(&element_type).expect("serialize")["kind"]
                .as_str()
                .expect("kind tag")
                .to_string();
            assert_eq!(element_kind_slug(&element_type), kind);
        }
    }
}

fn is_safe_to_click(el: &InteractiveElement, cfg: &BrokenAppConfig) -> bool {
    // With the write guard on, submit-like controls are clicked: the requests
    // they fire are recorded and blocked/stubbed before reaching the backend.
    let submit_allowed = submit_clicks_allowed(cfg);
    match &el.element_type {
        ElementType::Button { form_submit } => {
            if *form_submit && !submit_allowed {
                return false;
            }
            // Implicit forms: buttons outside a `<form>` can still be the primary
            // mutation trigger (e.g. "Save"/"Update"). Treat these as submit-ish
            // and skip them unless submits are allowed.
            if !submit_allowed && is_submitish(el) {
                return false;
            }
        }
        ElementType::Other { role: Some(r), .. } if r == "button" => {
            if !submit_allowed && is_submitish(el) {
                return false;
            }
        }
        ElementType::NavigationLink { .. } => return false, // handled via href queueing
        ElementType::DropdownMenu { .. } => return false,   // handled via dropdown expansion
        ElementType::FileUpload { .. } => return false,
        _ => {}
    }

    // Logout/delete/revoke-style controls stay off even when guarded: the
    // network guard does not protect client-side session or storage state.
    cfg.scan.exploration.interact_with_delete_buttons || !has_danger_word(el)
}

/// Submit- or destructive-labelled button (`Save`, `Place order`, `Delete`).
fn is_submitish(el: &InteractiveElement) -> bool {
    matches!(el.element_type, ElementType::Button { form_submit: true })
        || crate::dom::heuristics::is_submit_mutation_label(el.label.as_deref())
        || crate::dom::heuristics::is_destructive_mutation_label(el.label.as_deref())
}

fn has_danger_word(el: &InteractiveElement) -> bool {
    let hay = format!(
        "{} {}",
        el.label.as_deref().unwrap_or_default().to_ascii_lowercase(),
        el.selector.to_ascii_lowercase()
    );
    const DANGER_WORDS: [&str; 12] = [
        "delete",
        "remove",
        "destroy",
        "archive",
        "logout",
        "log out",
        "sign out",
        "disable",
        "revoke",
        "detach",
        "unlink",
        "end ownership",
    ];
    DANGER_WORDS.iter().any(|w| hay.contains(w))
}

/// `skipped_reason` for an `interactions.jsonl` row of a control
/// `is_safe_to_click` declined. Coverage gaps keep the coarse
/// `safety_policy` reason (the store keys on it); rows separate dangerous
/// labels (logout/delete/revoke...) from submit-like controls.
fn skip_row_reason(el: &InteractiveElement, gap_reason: &'static str) -> &'static str {
    if gap_reason == "safety_policy" && has_danger_word(el) {
        "dangerous_label"
    } else {
        gap_reason
    }
}

/// Accurate coverage-gap reason for an element that `is_safe_to_click` declined
/// to click in-place.
///
/// `safety_policy` must be reserved for controls that were *deliberately* left
/// alone (destructive / submit-like mutations). Navigation links, dropdowns and
/// file uploads are not safety skips — they are reached through other
/// exploration mechanisms (href queueing, dropdown expansion, upload handling),
/// so labelling them `safety_policy` both inflates the gap count and triggers a
/// bogus "enable submit_forms" repair suggestion downstream.
fn no_click_reason(el: &InteractiveElement) -> &'static str {
    match &el.element_type {
        // A link with an href is followed as a queued route, so it is covered
        // elsewhere rather than a true gap. Without an href it cannot be
        // enqueued (JS-driven navigation) — a genuine gap, but not a safety one.
        ElementType::NavigationLink { href: Some(_), .. } => "navigation_via_href",
        ElementType::NavigationLink { href: None, .. } => "javascript_navigation",
        ElementType::DropdownMenu { .. } => "dropdown_expansion",
        ElementType::FileUpload { .. } => "file_upload",
        _ => "safety_policy",
    }
}

fn is_submit_target_candidate(el: &InteractiveElement, cfg: &BrokenAppConfig) -> bool {
    if !submit_clicks_allowed(cfg) {
        return false;
    }

    let is_button_like = matches!(el.element_type, ElementType::Button { .. })
        || matches!(
            &el.element_type,
            ElementType::Other { role: Some(r), .. } if r == "button"
        );
    if !is_button_like {
        return false;
    }

    // Explicit form submits always count.
    if matches!(el.element_type, ElementType::Button { form_submit: true }) {
        return true;
    }

    // Avoid obvious non-submit controls even when they look button-y.
    if crate::dom::heuristics::is_bad_submit_label(el.label.as_deref()) {
        return false;
    }

    if crate::dom::heuristics::is_submit_mutation_label(el.label.as_deref()) {
        return true;
    }

    // Destructive-ish mutations are only clicked when explicitly enabled.
    if cfg.scan.exploration.interact_with_delete_buttons
        && crate::dom::heuristics::is_destructive_mutation_label(el.label.as_deref())
    {
        return true;
    }

    false
}

fn submit_sort_key(el: &InteractiveElement) -> (i64, i64) {
    let mut pri = crate::dom::heuristics::submit_priority(el.label.as_deref());
    // Small boost for explicit submit buttons inside a form.
    if matches!(el.element_type, ElementType::Button { form_submit: true }) {
        pri = pri.saturating_sub(5);
    }
    let y = el
        .bounding_box
        .as_ref()
        .map(|b| b.y as i64)
        .unwrap_or(i64::MAX);
    (pri, y)
}

#[derive(Debug, Clone, Default)]
struct PreconditionCheck {
    hint: Option<String>,
    satisfied: Option<bool>,
    skip: bool,
}

async fn infer_precondition_context(
    page: &PageClient,
    el: &InteractiveElement,
    cfg: &BrokenAppConfig,
) -> Result<PreconditionCheck> {
    if el.empty_required_fields_in_form > 0 {
        return Ok(PreconditionCheck {
            hint: Some(format!(
                "button is inside form with {} empty required field(s)",
                el.empty_required_fields_in_form
            )),
            satisfied: Some(false),
            skip: true,
        });
    }

    if let Some(hint) = element_block_precondition(page, el).await {
        return Ok(PreconditionCheck {
            hint: Some(hint),
            satisfied: Some(false),
            skip: true,
        });
    }

    if let Some(hint) = environment_context_hint(el) {
        return Ok(PreconditionCheck {
            hint: Some(hint.to_string()),
            satisfied: Some(false),
            skip: true,
        });
    }

    let mut satisfied = None;

    if likely_requires_form_input(el) {
        if let Some(stats) = required_field_precondition(page, el).await {
            if stats.total_required > 0 {
                if stats.empty_required > 0 {
                    return Ok(PreconditionCheck {
                        hint: Some(format!(
                            "{} required field(s) empty in nearby form/dialog",
                            stats.empty_required
                        )),
                        satisfied: Some(false),
                        skip: true,
                    });
                }
                satisfied = Some(true);
            }
        }
    }

    if likely_requires_selection(el, cfg) {
        if let Some(stats) = selection_precondition_stats(page).await {
            if stats.checked > 0 || stats.selected_rows > 0 {
                satisfied = Some(true);
            } else if stats.selectable > 0 {
                return Ok(PreconditionCheck {
                    hint: Some("no selections detected (checkbox/radio/row selection)".to_string()),
                    satisfied: Some(false),
                    skip: true,
                });
            }
        }
    }

    Ok(PreconditionCheck {
        hint: None,
        satisfied,
        skip: false,
    })
}

fn environment_context_hint(el: &InteractiveElement) -> Option<&'static str> {
    let label = el
        .label
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let selector = el.selector.to_ascii_lowercase();

    let location_picker_phrases = [
        "selected location",
        "select your location",
        "pick up today",
        "pickup today",
        "find in store",
        "find a store",
        "store availability",
        "check store availability",
        "selected store",
    ];

    if location_picker_phrases
        .iter()
        .any(|phrase| label.contains(phrase) || selector.contains(phrase))
    {
        return Some(
            "interaction depends on store/location context and may open a picker or modal",
        );
    }

    None
}

fn is_expected_passive_button_control(
    el: &InteractiveElement,
    pre_click_pattern: PreClickPattern,
) -> bool {
    matches!(
        pre_click_pattern,
        PreClickPattern::CopyToClipboard | PreClickPattern::MediaControl
    ) || has_clipboard_control_hint(el)
        || has_media_control_hint(el)
        || has_shell_layout_control_hint(el)
        || has_drag_or_resize_handle_hint(el)
        || has_idempotent_refresh_hint(el)
}

fn is_terminal_one_way_reveal_control(el: &InteractiveElement) -> bool {
    let text = normalized_button_hint_text(el);
    [
        " open ",
        " show ",
        " reveal ",
        " expand ",
        " view ",
        " display ",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

async fn terminal_one_way_reveal_target_visible(
    page: &PageClient,
    el: &InteractiveElement,
) -> Result<bool> {
    let locator_json = primary_locator_json(el)?;
    let script = format!(
        r##"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  try {{
    const action = resolveBrokenAppLocator(locator);
    if (!action) return false;

    function isVisible(node) {{
      if (!node || node.nodeType !== 1) return false;
      if (node.hidden) return false;
      if (node.getAttribute && node.getAttribute("aria-hidden") === "true") return false;
      const style = window.getComputedStyle(node);
      if (!style || style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
      const rects = node.getClientRects();
      return !!rects && rects.length > 0;
    }}

    function isRevealTarget(node) {{
      if (!isVisible(node)) return false;
      const tag = (node.tagName || "").toLowerCase();
      if (["button", "a", "input", "select", "textarea"].includes(tag)) return false;
      const role = (node.getAttribute("role") || "").toLowerCase();
      const cls = typeof node.className === "string" ? node.className.toLowerCase() : "";
      const id = (node.id || "").toLowerCase();
      const text = (node.textContent || "").trim();
      if (!text) return false;
      return role === "dialog" ||
        role === "tabpanel" ||
        role === "region" ||
        tag === "section" ||
        tag === "dialog" ||
        /panel|modal|dialog|drawer|popover|details|content/.test(cls + " " + id);
    }}

    const controlsId = action.getAttribute && action.getAttribute("aria-controls");
    if (controlsId) {{
      const controlled = document.getElementById(controlsId);
      if (isRevealTarget(controlled)) return true;
    }}

    const rawTarget =
      (action.getAttribute && (action.getAttribute("data-target") || action.getAttribute("data-bs-target"))) || "";
    if (rawTarget && rawTarget.startsWith("#")) {{
      const target = document.querySelector(rawTarget);
      if (isRevealTarget(target)) return true;
    }}

    let sibling = action.nextElementSibling;
    let hops = 0;
    while (sibling && hops < 8) {{
      if (isRevealTarget(sibling)) return true;
      sibling = sibling.nextElementSibling;
      hops += 1;
    }}

    return false;
  }} catch (_) {{
    return false;
  }}
}})()
"##
    );
    page.evaluate_json(&script).await
}

fn has_clipboard_control_hint(el: &InteractiveElement) -> bool {
    let text = normalized_button_hint_text(el);
    text.contains(" copy ")
        && ([
            "code",
            "snippet",
            "clipboard",
            "terminal",
            "command",
            "report",
            "link",
            "url",
            "share",
        ]
        .iter()
        .any(|needle| text.contains(needle))
            || text.starts_with(" copy ")
            || text.contains(r#"[aria-label="copy"#))
}

fn has_media_control_hint(el: &InteractiveElement) -> bool {
    let text = normalized_button_hint_text(el);
    let bare_watch_button =
        text.contains(r#" button[aria-label="watch"] "#) || text.starts_with(" watch ");
    let action = [
        " play video ",
        " watch video ",
        " watch ",
        " pause ",
        " mute ",
        " unmute ",
        " fullscreen ",
        " full screen ",
        " replay ",
        " resume ",
    ]
    .iter()
    .any(|needle| text.contains(needle));
    let context = [
        "video",
        "player",
        "media",
        "audio",
        "playback",
        "hero-video",
        "video-player",
    ]
    .iter()
    .any(|needle| text.contains(needle));
    (action && context) || bare_watch_button
}

fn has_shell_layout_control_hint(el: &InteractiveElement) -> bool {
    let text = normalized_button_hint_text(el);
    let action = [
        " collapse ",
        " expand ",
        " toggle sidebar ",
        " toggle navigation ",
        " hide sidebar ",
        " show sidebar ",
    ]
    .iter()
    .any(|needle| text.contains(needle));
    let context = [
        "sidebar",
        "side-nav",
        "sidenav",
        "staff-sidebar",
        "navigation",
        "nav-toggle",
    ]
    .iter()
    .any(|needle| text.contains(needle));
    action && context
}

/// Drag-only resize rails and sortable reorder handles require pointer drag
/// gestures rather than a single click, so a click with no DOM mutation is not
/// evidence of a dead button.
fn has_drag_or_resize_handle_hint(el: &InteractiveElement) -> bool {
    if matches!(el.element_type, ElementType::DragHandle) {
        return true;
    }
    let text = normalized_button_hint_text(el);
    [
        " resize sidebar ",
        " resize panel ",
        " resize pane ",
        " resize drawer ",
        " resize column ",
        " resize split ",
        " drag handle ",
        " drag to reorder ",
        "data-sidebar=\"rail\"",
        "cursor-col-resize",
        "cursor-row-resize",
        "cursor-ew-resize",
        "cursor-ns-resize",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// Refresh/reload triggers are often idempotent when backing state has not
/// changed (or when the fetch is served from cache/debounced), so no visible
/// DOM diff on click should not emit a medium-severity `dead_button` finding.
fn has_idempotent_refresh_hint(el: &InteractiveElement) -> bool {
    let label = el
        .label
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    label == "refresh"
        || label.starts_with("refresh ")
        || label == "reload"
        || label.starts_with("reload ")
}

fn normalized_button_hint_text(el: &InteractiveElement) -> String {
    let label = el
        .label
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let selector = el.selector.to_ascii_lowercase();
    format!(" {label} {selector} ")
}

fn likely_requires_form_input(el: &InteractiveElement) -> bool {
    match &el.element_type {
        ElementType::Button { form_submit } if *form_submit => return true,
        ElementType::Button { .. } => {
            return crate::dom::heuristics::is_submit_mutation_label(el.label.as_deref());
        }
        ElementType::Other { role: Some(r), .. } if r == "button" => {
            return crate::dom::heuristics::is_submit_mutation_label(el.label.as_deref());
        }
        _ => {}
    }
    false
}

fn likely_requires_selection(el: &InteractiveElement, _cfg: &BrokenAppConfig) -> bool {
    let label = el.label.as_deref().unwrap_or("").to_ascii_lowercase();
    if crate::dom::heuristics::is_destructive_mutation_label(el.label.as_deref())
        || crate::dom::heuristics::is_submit_mutation_label(el.label.as_deref())
    {
        return true;
    }
    let selection_keywords = [
        "selected",
        "selection",
        "bulk",
        "batch",
        "multi-select",
        "multiselect",
        "multi select",
        "multiple",
    ];
    selection_keywords.iter().any(|k| label.contains(k))
}

#[derive(serde::Deserialize)]
struct SelectionStats {
    selectable: u64,
    checked: u64,
    selected_rows: u64,
}

async fn selection_precondition_stats(page: &PageClient) -> Option<SelectionStats> {
    let script = r#"
(() => {
  try {
    const boxes = Array.from(document.querySelectorAll('input[type="checkbox"], [role="checkbox"]'));
    const radios = Array.from(document.querySelectorAll('input[type="radio"], [role="radio"]'));
    const selectable = boxes.length + radios.length;
    const checked =
      boxes.filter(b => b.checked || b.getAttribute('aria-checked') === 'true').length +
      radios.filter(r => r.checked || r.getAttribute('aria-checked') === 'true').length;

    const selectedRows = Array.from(document.querySelectorAll('[aria-selected="true"], [data-selected="true"], [data-state="selected"]')).length;
    return { selectable, checked, selected_rows: selectedRows };
  } catch (_) {
    return null;
  }
})()
"#;

    page.evaluate_json(script).await.ok()
}

#[derive(serde::Deserialize)]
struct RequiredFieldStats {
    total_required: u64,
    empty_required: u64,
}

#[derive(serde::Deserialize)]
struct BlockedStats {
    disabled: bool,
    aria_disabled: bool,
    pointer_none: bool,
    hidden: bool,
    covered: bool,
}

async fn element_block_precondition(
    page: &PageClient,
    element: &InteractiveElement,
) -> Option<String> {
    let locator_json = primary_locator_json(element).ok()?;
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  try {{
    const el = resolveBrokenAppLocator(locator);
    if (!el) return null;
    const style = window.getComputedStyle(el);
    const disabled = !!el.disabled;
    const ariaDisabled = el.getAttribute('aria-disabled') === 'true';
    const pointerNone = style.pointerEvents === 'none';
    const hidden =
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      style.opacity === '0';

    let covered = false;
    const rect = el.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {{
      const x = rect.left + rect.width / 2;
      const y = rect.top + rect.height / 2;
      if (x >= 0 && y >= 0 && x <= window.innerWidth && y <= window.innerHeight) {{
        const top = document.elementFromPoint(x, y);
        if (top && top !== el && !el.contains(top) && !top.contains(el)) {{
          covered = true;
        }}
      }}
    }}

    return {{
      disabled,
      aria_disabled: ariaDisabled,
      pointer_none: pointerNone,
      hidden,
      covered
    }};
  }} catch (_) {{
    return null;
  }}
}})()
"#
    );

    let stats: BlockedStats = page.evaluate_json(&script).await.ok()?;
    if stats.disabled {
        return Some("element is disabled".to_string());
    }
    if stats.aria_disabled {
        return Some("element has aria-disabled=true".to_string());
    }
    if stats.pointer_none || stats.hidden {
        return Some("element is not interactable (pointer-events/visibility)".to_string());
    }
    if stats.covered {
        return Some("element is covered by another element".to_string());
    }
    None
}

async fn required_field_precondition(
    page: &PageClient,
    element: &InteractiveElement,
) -> Option<RequiredFieldStats> {
    let locator_json = primary_locator_json(element).ok()?;
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  try {{
    const action = resolveBrokenAppLocator(locator);
    if (!action) return null;

    let scope = action.closest('form');
    if (!scope) {{
      scope = action.closest('[role="dialog"], dialog, .modal, [data-modal="true"], .MuiDialog-root, .ReactModal__Content');
    }}
    if (!scope) return null;

    function isVisible(el) {{
      if (!el) return false;
      if (el.hidden) return false;
      const ariaHidden = el.getAttribute && el.getAttribute('aria-hidden') === 'true';
      if (ariaHidden) return false;
      const style = window.getComputedStyle(el);
      if (!style || style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {{
        return false;
      }}
      const rects = el.getClientRects();
      return rects && rects.length > 0;
    }}

    const fields = scope.querySelectorAll('input, select, textarea, [contenteditable="true"]');
    let total = 0;
    let empty = 0;
    fields.forEach((field) => {{
      if (!isVisible(field)) return;
      const tag = field.tagName ? field.tagName.toLowerCase() : '';
      const type = field.type ? String(field.type).toLowerCase() : '';
      if (type === 'hidden') return;
      if (field.disabled) return;
      const required = field.required || field.getAttribute('aria-required') === 'true';
      if (!required) return;
      total += 1;
      let isEmpty = false;
      if (tag === 'select') {{
        const val = field.value;
        isEmpty = !val;
      }} else if (type === 'checkbox' || type === 'radio') {{
        isEmpty = !field.checked && field.getAttribute('aria-checked') !== 'true';
      }} else if (field.isContentEditable) {{
        isEmpty = !field.textContent || !field.textContent.trim();
      }} else {{
        isEmpty = !field.value || !String(field.value).trim();
      }}
      if (isEmpty) empty += 1;
    }});
    return {{ total_required: total, empty_required: empty }};
  }} catch (_) {{
    return null;
  }}
}})()
"#
    );

    page.evaluate_json(&script).await.ok()
}

async fn resolve_submit_form_selector(
    page: &PageClient,
    submit_button: &InteractiveElement,
    classified: &ClassifiedView,
) -> Result<Option<String>> {
    #[derive(serde::Serialize)]
    struct FormCandidate {
        selector: String,
        field_count: usize,
    }

    let mut forms: Vec<FormCandidate> = Vec::new();
    for comp in &classified.components {
        if let ComponentType::Form { fields, .. } = &comp.component {
            forms.push(FormCandidate {
                selector: comp.selector.clone(),
                field_count: fields.len(),
            });
        }
    }
    if forms.is_empty() {
        return Ok(None);
    }

    // Use the "closest form-like container" as a scoping hint. This handles the
    // common case where the "Save" button lives in a page header outside the
    // implicit form container that the classifier detected.
    let container_sel = closest_form_selector(page, submit_button).await?;

    let submit_json = primary_locator_json(submit_button)?;
    let container_json = serde_json::to_string(&container_sel)?;
    let forms_json = serde_json::to_string(&forms)?;

    let script = format!(
        r#"
(() => {{
  const submitLocator = {submit_json};
  {LOCATOR_RUNTIME_JS}
  try {{
    const containerSel = {container_json};
    const forms = {forms_json};

    let submitEl = null;
    try {{ submitEl = resolveBrokenAppLocator(submitLocator); }} catch (_) {{}}

    let containerEl = null;
    if (containerSel) {{
      try {{ containerEl = document.querySelector(containerSel); }} catch (_) {{}}
    }}

    function depth(el) {{
      let d = 0;
      let cur = el;
      while (cur && cur.parentElement && d < 50) {{
        d++;
        cur = cur.parentElement;
      }}
      return d;
    }}

    let best = null;
    let bestScore = -1;
    for (const f of forms) {{
      if (!f || !f.selector) continue;
      let el = null;
      try {{ el = document.querySelector(f.selector); }} catch (_) {{}}
      if (!el) continue;

      let score = 0;
      if (submitEl && el.contains(submitEl)) score += 1000;
      if (containerEl && containerEl.contains(el)) score += 500;
      if (typeof f.field_count === "number") score += Math.min(200, f.field_count) * 2;
      score += depth(el);

      if (score > bestScore) {{
        bestScore = score;
        best = f.selector;
      }}
    }}

    return best;
  }} catch (e) {{
    return null;
  }}
}})()
"#
    );

    let out: Option<String> = page.evaluate_json(&script).await?;
    Ok(out)
}

/// Labelled like a control that leaves the current state: close, cancel,
/// dismiss, done, back.
fn leaves_state(el: &InteractiveElement) -> bool {
    let label = el
        .label
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    const EXITS: [&str; 9] = [
        "close", "cancel", "dismiss", "done", "back", "go back", "previous", "exit", "×",
    ];
    EXITS
        .iter()
        .any(|w| label == *w || label.starts_with(&format!("{w} ")))
        || label == "x"
}

/// True when a value-changing input should run *after* non-submit buttons,
/// tabs, and modal openers in `other_targets`. Standalone search/filter inputs
/// (outside `<form>`, `type="search"`, `role="searchbox"`, or optional
/// search/filter fields) frequently filter out table rows or mutate the page
/// DOM when typed into; running them after buttons lets modal openers and row
/// controls execute on the clean, unfiltered view.
fn is_deferred_standalone_input(el: &InteractiveElement, form_index: Option<usize>) -> bool {
    if matches!(el.element_type, ElementType::SearchBar) {
        return true;
    }
    if matches!(
        &el.element_type,
        ElementType::Other { role: Some(r), .. } if r.eq_ignore_ascii_case("searchbox")
    ) {
        return true;
    }
    if matches!(
        &el.element_type,
        ElementType::TextInput { input_type, .. } if input_type.eq_ignore_ascii_case("search")
    ) {
        return true;
    }
    if form_index.is_none() && (is_page_local_value_control(el) || is_textarea(el)) {
        return true;
    }
    if let ElementType::TextInput {
        required: false,
        name,
        ..
    } = &el.element_type
    {
        let hay = format!(
            "{} {} {}",
            el.label.as_deref().unwrap_or_default().to_ascii_lowercase(),
            name.as_deref().unwrap_or_default().to_ascii_lowercase(),
            el.selector.to_ascii_lowercase()
        );
        if hay.contains("search") || hay.contains("filter") {
            return true;
        }
    }
    false
}

fn interaction_sort_key(el: &InteractiveElement) -> (u8, u8, i64) {
    let type_rank: u8 = match &el.element_type {
        ElementType::TextInput { .. } => 0,
        ElementType::Other { tag, .. } if tag.eq_ignore_ascii_case("textarea") => 0,
        ElementType::SelectDropdown { .. } => 1,
        ElementType::Checkbox { .. } | ElementType::RadioButton { .. } | ElementType::Toggle => 2,
        ElementType::Button { .. } => 3,
        ElementType::Other { role: Some(r), .. } if r == "button" => 4,
        ElementType::Pagination => 4, // same rank as role="button" — data-loading controls
        _ => 5,
    };

    let label_rank: u8 = match el.label.as_deref() {
        Some(s) if !s.trim().is_empty() => 0,
        _ => 1,
    };

    let y = el
        .bounding_box
        .as_ref()
        .map(|b| b.y as i64)
        .unwrap_or(i64::MAX);

    (type_rank, label_rank, y)
}

fn navigation_transition_from_observation(
    view_id: &str,
    el: &InteractiveElement,
    obs: &InteractionObservation,
) -> Option<PendingTransition> {
    if !matches!(obs.effect, InteractionEffect::Navigation) {
        return None;
    }
    let target_url = obs.after_url.as_ref()?;
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return None;
    }
    if obs.before_url.as_ref() == Some(target_url) {
        return None;
    }
    Some(PendingTransition {
        from_view: view_id.to_string(),
        trigger: InteractionRef {
            view: view_id.to_string(),
            selector: el.selector.clone(),
        },
        trigger_locators: el.locators.clone(),
        transition_type: TransitionType::Navigation,
        target_url: target_url.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dom::{ElementType, InteractiveElement};

    fn test_button(label: Option<&str>, selector: &str) -> InteractiveElement {
        test_element(ElementType::Button { form_submit: false }, label, selector)
    }

    fn test_element(
        element_type: ElementType,
        label: Option<&str>,
        selector: &str,
    ) -> InteractiveElement {
        InteractiveElement {
            selector: selector.to_string(),
            label: label.map(str::to_string),
            element_type,
            interaction_result: None,
            source: None,
            found_on: "view-1".to_string(),
            bounding_box: None,
            snapshot: None,
            disabled: false,
            empty_required_fields_in_form: 0,
            locators: Vec::new(),
        }
    }

    #[test]
    fn no_click_reason_distinguishes_navigation_from_safety_skips() {
        // Read-only navigation links are explored via href queueing, NOT skipped
        // for safety. Reporting them as `safety_policy` inflates the gap count
        // and triggers a bogus "enable submit_forms" repair suggestion.
        let nav_with_href = test_element(
            ElementType::NavigationLink {
                href: Some("/users/1".to_string()),
                in_nav: false,
            },
            Some("TJ"),
            "ul > li:nth-of-type(1) > a",
        );
        assert_eq!(no_click_reason(&nav_with_href), "navigation_via_href");

        // A link with no href cannot be enqueued as a route (JS-driven nav). It
        // IS a genuine coverage gap, but still not a safety skip.
        let nav_no_href = test_element(
            ElementType::NavigationLink {
                href: None,
                in_nav: false,
            },
            Some("Next"),
            "a.js-next",
        );
        assert_eq!(no_click_reason(&nav_no_href), "javascript_navigation");

        // Dropdowns are exercised via the dropdown-expansion pass, not a click.
        let dropdown = test_element(
            ElementType::DropdownMenu { in_nav: false },
            Some("Account"),
            "div.menu",
        );
        assert_eq!(no_click_reason(&dropdown), "dropdown_expansion");

        // File uploads have their own handling; not a safety skip.
        let upload = test_element(
            ElementType::FileUpload { accept: None },
            Some("Avatar"),
            "input[type=file]",
        );
        assert_eq!(no_click_reason(&upload), "file_upload");

        // Genuine safety skip: a destructive button keeps `safety_policy`.
        let delete = test_element(
            ElementType::Button { form_submit: false },
            Some("Delete account"),
            "button.danger",
        );
        assert_eq!(no_click_reason(&delete), "safety_policy");
        // The interactions.jsonl row is more specific than the coverage gap.
        assert_eq!(skip_row_reason(&delete, "safety_policy"), "dangerous_label");
        let save = test_button(Some("Save profile"), "button.save");
        assert_eq!(skip_row_reason(&save, "safety_policy"), "safety_policy");
    }

    #[test]
    fn write_guard_allows_submit_clicks_but_never_logout_or_delete() {
        use crate::config::WriteGuardMode;

        let place_order = test_element(
            ElementType::Button { form_submit: true },
            Some("Place order"),
            "form > button",
        );
        let save = test_button(Some("Save settings"), "button.save");
        let sign_out = test_button(Some("Sign out"), "button.signout");
        let delete = test_button(Some("Delete account"), "button.danger");
        let revoke = test_element(
            ElementType::Other {
                tag: "div".into(),
                role: Some("button".into()),
            },
            Some("Revoke key"),
            "div.revoke",
        );

        let config = || -> BrokenAppConfig {
            toml::from_str("[target]\nurl = \"http://x.test/\"\n").expect("minimal config")
        };
        // Default: the write guard blocks requests, so submits are clicked.
        let guarded = config();
        assert_eq!(guarded.scan.write_guard.mode, WriteGuardMode::Block);
        assert!(is_safe_to_click(&place_order, &guarded));
        assert!(is_safe_to_click(&save, &guarded));
        for el in [&sign_out, &delete, &revoke] {
            assert!(!is_safe_to_click(el, &guarded), "{:?}", el.label);
        }

        // Guard off and submit_forms off: submit-like controls stay untouched.
        let mut unguarded = config();
        unguarded.scan.write_guard.mode = WriteGuardMode::Off;
        assert!(!is_safe_to_click(&place_order, &unguarded));
        assert!(!is_safe_to_click(&save, &unguarded));
        assert!(!is_safe_to_click(&sign_out, &unguarded));

        // Only guarded scans opt the interaction primitive into submit clicks
        // and classify submit-like controls as prioritized submit targets.
        assert!(interaction_scan_config(&guarded).exploration.submit_forms);
        assert!(!interaction_scan_config(&unguarded).exploration.submit_forms);
        assert!(is_submit_target_candidate(&place_order, &guarded));
        assert!(is_submit_target_candidate(&save, &guarded));
        assert!(!is_submit_target_candidate(&place_order, &unguarded));
        assert!(!is_submit_target_candidate(&save, &unguarded));
    }

    #[test]
    fn textarea_controls_are_typed_and_sorted_with_text_inputs() {
        let textarea = test_element(
            ElementType::Other {
                tag: "textarea".into(),
                role: None,
            },
            Some("Reply message"),
            "textarea#reply",
        );
        assert_eq!(action_kind(&textarea), "type");
        assert!(!is_groupable_control(&textarea));
        assert_eq!(interaction_sort_key(&textarea).0, 0);
    }

    #[test]
    fn environment_context_hint_detects_location_picker_buttons() {
        let el = test_button(
            Some("Selected Location: United States"),
            "button[aria-label=\"Selected Location: United States\"]",
        );
        assert!(environment_context_hint(&el).is_some());
    }

    #[test]
    fn environment_context_hint_detects_pickup_buttons() {
        let el = test_button(
            Some("Pick Up Today"),
            "button[aria-label=\"Pick Up Today\"]",
        );
        assert!(environment_context_hint(&el).is_some());
    }

    #[test]
    fn environment_context_hint_ignores_normal_ctas() {
        let el = test_button(Some("Get Started"), "button.cta");
        assert!(environment_context_hint(&el).is_none());
    }

    #[test]
    fn expected_passive_button_control_detects_copy_buttons() {
        let el = test_button(Some("Copy code"), "button.ch-code-button");
        assert!(is_expected_passive_button_control(
            &el,
            PreClickPattern::Unknown
        ));
    }

    #[test]
    fn expected_passive_button_control_detects_copy_report_buttons() {
        let el = test_button(Some("Copy report"), "button:nth-of-type(2)");
        assert!(is_expected_passive_button_control(
            &el,
            PreClickPattern::Unknown
        ));
    }

    #[test]
    fn expected_passive_button_control_detects_media_buttons() {
        let el = test_button(Some("Play Video"), "button.hero-video-control");
        assert!(is_expected_passive_button_control(
            &el,
            PreClickPattern::Unknown
        ));
    }

    #[test]
    fn expected_passive_button_control_detects_bare_watch_buttons() {
        let el = test_button(Some("Watch"), r#"button[aria-label="Watch"]"#);
        assert!(is_expected_passive_button_control(
            &el,
            PreClickPattern::Unknown
        ));
    }

    #[test]
    fn expected_passive_button_control_detects_sidebar_collapse_buttons() {
        let el = test_button(Some("Collapse"), "button.staff-sidebar-collapse");
        assert!(is_expected_passive_button_control(
            &el,
            PreClickPattern::Unknown
        ));
    }

    #[test]
    fn expected_passive_button_control_detects_drag_resize_and_refresh_buttons() {
        let resize = test_button(
            Some("Resize Sidebar"),
            r#"button[aria-label="Resize Sidebar"][data-sidebar="rail"]"#,
        );
        assert!(is_expected_passive_button_control(
            &resize,
            PreClickPattern::Unknown
        ));

        let drag = test_element(ElementType::DragHandle, Some("Reorder"), "div.handle");
        assert!(is_expected_passive_button_control(
            &drag,
            PreClickPattern::Unknown
        ));

        let refresh_diff =
            test_button(Some("Refresh diff"), r#"button[aria-label="Refresh diff"]"#);
        assert!(is_expected_passive_button_control(
            &refresh_diff,
            PreClickPattern::Unknown
        ));

        let refresh_prs = test_button(
            Some("Refresh pull requests"),
            r#"button[aria-label="Refresh pull requests"]"#,
        );
        assert!(is_expected_passive_button_control(
            &refresh_prs,
            PreClickPattern::Unknown
        ));
    }

    #[test]
    fn expected_passive_button_control_ignores_normal_ctas() {
        let el = test_button(Some("GitHub"), "button.github-login");
        assert!(!is_expected_passive_button_control(
            &el,
            PreClickPattern::Unknown
        ));
    }

    #[test]
    fn terminal_one_way_reveal_controls_are_not_dead_buttons() {
        let el = test_button(Some("Open panel"), "#working-button");
        assert!(is_terminal_one_way_reveal_control(&el));
    }

    #[test]
    fn navigation_transition_from_observation_preserves_button_trigger() {
        let el = test_button(Some("Clear local session"), "button.clear-session");
        let obs = crate::dom::interaction::InteractionObservation {
            before_url: Some("https://example.com/diagnostics".to_string()),
            after_url: Some("https://example.com/login?cleared=1".to_string()),
            dom_mutated: false,
            network_activity: false,
            effect: InteractionEffect::Navigation,
            snapshot: None,
            side_effects: Vec::new(),
            already_active: false,
            click_missed: false,
            ticker_recheck: false,
        };

        let transition = navigation_transition_from_observation("view_0003", &el, &obs)
            .expect("navigation observation should produce pending transition");

        assert_eq!(transition.from_view, "view_0003");
        assert_eq!(transition.trigger.view, "view_0003");
        assert_eq!(transition.trigger.selector, "button.clear-session");
        assert!(matches!(
            transition.transition_type,
            crate::types::graph::TransitionType::Navigation
        ));
        assert_eq!(transition.target_url, "https://example.com/login?cleared=1");
    }

    #[test]
    fn navigation_transition_from_observation_ignores_about_blank() {
        let el = test_button(Some("Back"), "button.btn.ghost");
        let obs = crate::dom::interaction::InteractionObservation {
            before_url: Some("https://example.com/forgot-password".to_string()),
            after_url: Some("about:blank".to_string()),
            dom_mutated: false,
            network_activity: false,
            effect: InteractionEffect::Navigation,
            snapshot: None,
            side_effects: Vec::new(),
            already_active: false,
            click_missed: false,
            ticker_recheck: false,
        };

        assert!(navigation_transition_from_observation("view_0002", &el, &obs).is_none());
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;
    use crate::explorer::RuntimeState;

    fn shell_button(label: &str) -> InteractiveElement {
        InteractiveElement {
            selector: "header > button".to_string(),
            label: Some(label.to_string()),
            element_type: ElementType::Button { form_submit: false },
            interaction_result: None,
            source: None,
            found_on: "view_0001".to_string(),
            bounding_box: None,
            snapshot: None,
            disabled: false,
            empty_required_fields_in_form: 0,
            locators: Vec::new(),
        }
    }

    fn planned<'e>(el: &'e InteractiveElement, sibling_reexercise: bool) -> Planned<'e> {
        Planned {
            el,
            key: control_identity_key(el, Some("header"), "/"),
            shell: true,
            known_to_navigate: false,
            submit: false,
            deferred: false,
            on_sibling: false,
            sibling_reexercise,
            form_index: None,
        }
    }

    fn record(view_id: &str, outcome: InteractionOutcome) -> InteractionRecord {
        let mut record =
            InteractionRecord::new(view_id, "http://x.test/", "header > button", "button");
        record.outcome = outcome;
        record
    }

    #[test]
    fn recovery_journals_only_successful_local_preparation_without_duplicates() {
        let mut input = shell_button("Password");
        input.element_type = ElementType::TextInput {
            input_type: "password".into(),
            name: Some("password".into()),
            required: true,
        };
        let mut view = ViewState::default();
        for outcome in [
            InteractionOutcome::Skipped,
            InteractionOutcome::Error,
            InteractionOutcome::Navigated,
        ] {
            view.remember_preparation(&input, &record("view_0001", outcome), None);
        }
        let mut failed = record("view_0001", InteractionOutcome::NoEffect);
        failed.error = Some("timeout".into());
        view.remember_preparation(&input, &failed, None);
        failed.error = None;
        failed.skipped_reason = Some("obscured".into());
        view.remember_preparation(&input, &failed, None);
        assert!(view.prepared_inputs.is_empty());
        let success = record("view_0001", InteractionOutcome::NoEffect);
        view.remember_preparation(&input, &success, None);
        view.remember_preparation(&input, &success, None);
        assert_eq!(view.prepared_inputs.len(), 1);
        view.remember_preparation(&shell_button("Sign in"), &success, None);
        assert!(!view.prepared_unsupported);
        input.element_type = ElementType::Checkbox {
            name: None,
            checked: false,
        };
        view.remember_preparation(&input, &success, None);
        assert!(view.prepared_unsupported);
    }

    #[test]
    fn recovery_detects_new_documents_and_preserves_next_action_budget() {
        let mut input = shell_button("Email");
        input.element_type = ElementType::TextInput {
            input_type: "email".into(),
            name: None,
            required: true,
        };
        let mut view = ViewState::default();
        view.document_origin = Some(1);
        view.remember_preparation(
            &input,
            &record("view_0001", InteractionOutcome::NoEffect),
            None,
        );
        view.observe_document(Some(1));
        assert!(!view.preparation_invalidated);
        view.observe_document(Some(2)); // same URL/signature, nested or app reload
        assert!(view.preparation_invalidated);
        assert_eq!(
            view.recovery_precondition(3, 3),
            Err("form_state_recovery_interaction_limit")
        );
        assert!(view.recovery_precondition(3, 4).is_ok());
        view.prepared_unsupported = true;
        assert_eq!(
            view.recovery_precondition(0, 100),
            Err("form_state_recovery_unsupported")
        );
        view.recovery_failure = Some("form_state_recovery_failed");
        view.preparation_invalidated = false;
        assert_eq!(
            view.recovery_precondition(0, 100),
            Err("form_state_recovery_failed")
        );
        assert!(
            interaction_window(
                Some(Instant::now() - Duration::from_millis(1)),
                Duration::from_secs(3)
            )
            .is_none()
        );
    }

    #[test]
    fn a_control_claimed_by_one_tab_is_left_to_it() {
        let mut state = RuntimeState::new("http://x.test/".to_string());
        let shared: SharedState<'_> = std::sync::Mutex::new(&mut state);
        let menu = shell_button("Menu");
        let on_a = planned(&menu, false);

        // Tab A claims the shell control right before clicking it.
        assert_eq!(claim_control(&shared, &on_a, "view_0001"), Claim::Granted);
        // Tab B (another view) must not click it meanwhile.
        assert_eq!(
            claim_control(&shared, &on_a, "view_0002"),
            Claim::Elsewhere("view_0001".to_string())
        );
        // A's own nested states may (the claim is the same view's).
        assert_eq!(
            claim_control(&shared, &on_a, "view_0001:d1:0"),
            Claim::Granted
        );
        // Releasing someone else's claim is a no-op.
        release_claim(&shared, &on_a, "view_0002");
        assert!(
            lock_state(&shared)
                .exercised_controls
                .contains_key(&on_a.key)
        );

        // Exercised: the claim becomes the scan-wide record.
        remember_exercised(
            &shared,
            &on_a,
            "view_0001",
            &record("view_0001", InteractionOutcome::Navigated),
        );
        {
            let st = lock_state(&shared);
            let entry = st.exercised_controls.get(&on_a.key).expect("remembered");
            assert!(!entry.claimed && entry.navigated);
            assert_eq!(entry.view_id, "view_0001");
        }
        assert_eq!(
            claim_control(&shared, &on_a, "view_0003"),
            Claim::Elsewhere("view_0001".to_string())
        );
        // A finished record is never released by a later skip elsewhere.
        release_claim(&shared, &on_a, "view_0001");
        assert!(
            lock_state(&shared)
                .exercised_controls
                .contains_key(&on_a.key)
        );
    }

    #[test]
    fn interleaved_form_fields_are_claimed_on_both_pages() {
        let mut state = RuntimeState::new("http://x.test/".to_string());
        let shared: SharedState<'_> = std::sync::Mutex::new(&mut state);
        let mut email = shell_button("Email");
        email.selector = "header > form > input#email".into();
        email.element_type = ElementType::TextInput {
            input_type: "email".into(),
            name: Some("email".into()),
            required: true,
        };
        let mut password = email.clone();
        password.selector = "header > form > input#password".into();
        password.label = Some("Password".into());
        password.element_type = ElementType::TextInput {
            input_type: "password".into(),
            name: Some("password".into()),
            required: true,
        };
        fn on<'e>(el: &'e InteractiveElement, view: &str) -> Planned<'e> {
            Planned {
                key: exercise_identity_key(el, Some("header"), "/sign-in", view),
                ..planned(el, false)
            }
        }
        let (email_a, password_a) = (on(&email, "view_a"), on(&password, "view_a"));
        let (email_b, password_b) = (on(&email, "view_b"), on(&password, "view_b"));

        // Reproduce the captured ordering: A types email while B types password.
        assert_eq!(claim_control(&shared, &email_a, "view_a"), Claim::Granted);
        assert_eq!(
            claim_control(&shared, &password_b, "view_b"),
            Claim::Granted
        );
        remember_exercised(
            &shared,
            &email_a,
            "view_a",
            &record("view_a", InteractionOutcome::NoEffect),
        );
        remember_exercised(
            &shared,
            &password_b,
            "view_b",
            &record("view_b", InteractionOutcome::NoEffect),
        );
        // Each DOM still needs its other prerequisite, despite the finished
        // action on the other page. No "exercised_elsewhere" skip is valid.
        assert_eq!(
            claim_control(&shared, &password_a, "view_a"),
            Claim::Granted
        );
        assert_eq!(claim_control(&shared, &email_b, "view_b"), Claim::Granted);
        assert_eq!(on(&email, "view_a:d1:0").key, email_a.key);
        release_view_claims(&mut lock_state(&shared).exercised_controls, "view_b");
        assert!(
            lock_state(&shared)
                .exercised_controls
                .contains_key(&password_a.key)
        );
    }

    #[test]
    fn only_value_controls_get_page_local_exercise_claims() {
        let cases = [
            (
                ElementType::SelectDropdown {
                    options: Vec::new(),
                },
                true,
            ),
            (
                ElementType::Checkbox {
                    name: None,
                    checked: false,
                },
                true,
            ),
            (
                ElementType::RadioButton {
                    name: None,
                    group: None,
                },
                true,
            ),
            (ElementType::Toggle, true),
            (
                ElementType::Other {
                    tag: "div".into(),
                    role: Some("checkbox".into()),
                },
                true,
            ),
            (
                ElementType::Other {
                    tag: "div".into(),
                    role: Some("radio".into()),
                },
                true,
            ),
            (
                ElementType::Other {
                    tag: "div".into(),
                    role: Some("switch".into()),
                },
                true,
            ),
            (ElementType::Button { form_submit: false }, false),
            (ElementType::Button { form_submit: true }, false),
            (
                ElementType::Other {
                    tag: "div".into(),
                    role: Some("button".into()),
                },
                false,
            ),
            (
                ElementType::Other {
                    tag: "textarea".into(),
                    role: None,
                },
                false,
            ),
            (ElementType::FileUpload { accept: None }, false),
        ];
        for (kind, page_local) in cases {
            for landmark in [None, Some("header")] {
                let mut state = RuntimeState::new("http://x.test/".to_string());
                let shared: SharedState<'_> = std::sync::Mutex::new(&mut state);
                let mut el = shell_button("Control");
                el.element_type = kind.clone();
                let a = Planned {
                    key: exercise_identity_key(&el, landmark, "/form", "view_a"),
                    ..planned(&el, false)
                };
                let b = Planned {
                    key: exercise_identity_key(&el, landmark, "/form", "view_b"),
                    ..planned(&el, false)
                };
                assert_eq!(claim_control(&shared, &a, "view_a"), Claim::Granted);
                let expected = if page_local {
                    Claim::Granted
                } else {
                    Claim::Elsewhere("view_a".into())
                };
                assert_eq!(claim_control(&shared, &b, "view_b"), expected, "{kind:?}");
            }
        }
    }

    #[test]
    fn claims_of_a_visit_cut_short_are_released() {
        let mut state = RuntimeState::new("http://x.test/".to_string());
        let shared: SharedState<'_> = std::sync::Mutex::new(&mut state);
        let (menu, help) = (shell_button("Menu"), shell_button("Help"));
        let (a, b) = (planned(&menu, false), planned(&help, false));
        assert_eq!(claim_control(&shared, &a, "view_0001:d1:0"), Claim::Granted);
        remember_exercised(
            &shared,
            &b,
            "view_0001",
            &record("view_0001", InteractionOutcome::DomChange),
        );
        release_view_claims(&mut lock_state(&shared).exercised_controls, "view_0001");
        let st = lock_state(&shared);
        // The pending claim of the nested state is gone; finished work stays.
        assert!(!st.exercised_controls.contains_key(&a.key));
        assert!(st.exercised_controls.contains_key(&b.key));
    }

    #[test]
    fn a_claim_that_was_not_exercised_is_released() {
        let mut state = RuntimeState::new("http://x.test/".to_string());
        let shared: SharedState<'_> = std::sync::Mutex::new(&mut state);
        let help = shell_button("Help");
        let p = planned(&help, false);
        assert_eq!(claim_control(&shared, &p, "view_0001"), Claim::Granted);
        // Hidden or covered on that view: skipped, so another view may try.
        remember_exercised(
            &shared,
            &p,
            "view_0001",
            &record("view_0001", InteractionOutcome::Skipped),
        );
        assert!(!lock_state(&shared).exercised_controls.contains_key(&p.key));
        assert_eq!(claim_control(&shared, &p, "view_0002"), Claim::Granted);
    }

    #[test]
    fn template_siblings_may_reexercise_page_content() {
        let mut state = RuntimeState::new("http://x.test/".to_string());
        let shared: SharedState<'_> = std::sync::Mutex::new(&mut state);
        let save = shell_button("Save");
        let first = planned(&save, true);
        assert_eq!(claim_control(&shared, &first, "view_0001"), Claim::Granted);
        // One of the first instances of a template, planned before the
        // sibling took it: exercised again, but after the rest.
        assert_eq!(claim_control(&shared, &first, "view_0002"), Claim::Sibling);
        let mut deferred = planned(&save, true);
        deferred.on_sibling = true;
        assert_eq!(
            claim_control(&shared, &deferred, "view_0002"),
            Claim::Granted
        );
        // Later instances leave it to the sibling.
        let later = planned(&save, false);
        assert_eq!(
            claim_control(&shared, &later, "view_0003"),
            Claim::Elsewhere("view_0001".to_string())
        );
    }

    #[test]
    fn child_pass_budget_applies_floor_without_exceeding_remaining_time() {
        assert_eq!(
            child_pass_budget(Duration::from_secs(300)),
            Duration::from_secs(180)
        );
        assert_eq!(
            child_pass_budget(Duration::from_secs(20)),
            MIN_CHILD_PASS_BUDGET
        );
        assert_eq!(
            child_pass_budget(Duration::from_secs(10)),
            Duration::from_secs(10)
        );
        assert_eq!(child_pass_budget(Duration::ZERO), Duration::ZERO);

        // Deep nesting from a 300s view budget never shrinks below the floor.
        let mut budget = Duration::from_secs(300);
        for _ in 0..10 {
            budget = child_pass_budget(budget);
        }
        assert_eq!(budget, MIN_CHILD_PASS_BUDGET);
    }

    #[test]
    fn standalone_search_and_filter_inputs_sort_after_non_submit_buttons() {
        let mut search = shell_button("Search prices");
        search.selector = "input#price-search".into();
        search.element_type = ElementType::TextInput {
            input_type: "text".into(),
            name: Some("search".into()),
            required: false,
        };
        let mut form_email = shell_button("Email");
        form_email.selector = "form > input#email".into();
        form_email.element_type = ElementType::TextInput {
            input_type: "email".into(),
            name: Some("email".into()),
            required: true,
        };
        let modal_btn = shell_button("Add Property");

        // Standalone search / non-form inputs defer after non-submit buttons.
        assert!(is_deferred_standalone_input(&search, None));
        assert!(is_deferred_standalone_input(&search, Some(0)));
        assert!(!is_deferred_standalone_input(&modal_btn, None));
        assert!(!is_deferred_standalone_input(&modal_btn, Some(0)));
        // Required form fields inside a `<form>` stay ahead of buttons.
        assert!(!is_deferred_standalone_input(&form_email, Some(0)));
        // Outside a `<form>`, even generic inputs defer after buttons.
        assert!(is_deferred_standalone_input(&form_email, None));
    }

    #[test]
    fn form_recovery_failure_is_scoped_per_form_and_does_not_poison_other_forms() {
        let mut toggle = shell_button("Is Toronto");
        toggle.selector = "#is-toronto".into();
        toggle.element_type = ElementType::Other {
            tag: "button".into(),
            role: Some("checkbox".into()),
        };
        let mut other_email = shell_button("Email");
        other_email.selector = "#other-email".into();
        other_email.element_type = ElementType::TextInput {
            input_type: "email".into(),
            name: Some("email".into()),
            required: true,
        };

        let mut view = ViewState::default();
        view.document_origin = Some(1);
        view.remember_preparation_in_form(
            &toggle,
            &record("view_0001", InteractionOutcome::DomChange),
            None,
            Some(0),
        );
        view.remember_preparation_in_form(
            &other_email,
            &record("view_0001", InteractionOutcome::NoEffect),
            None,
            Some(1),
        );
        // Form 0 already interacted with an unsupported custom control, so its
        // submits cannot safely recover — while form 1 and non-form controls
        // remain unaffected both before and after reload.
        assert_eq!(
            view.recovery_precondition_for_form(Some(0), 0, 20),
            Err("form_state_recovery_unsupported")
        );
        assert!(view.recovery_precondition_for_form(Some(1), 0, 20).is_ok());
        assert!(view.recovery_precondition_for_form(None, 0, 20).is_ok());

        view.observe_document(Some(2));

        // After document replacement, form 0 cannot recover its custom checkbox,
        // while form 1 and non-form controls stay unaffected.
        assert_eq!(
            view.recovery_precondition_for_form(Some(0), 0, 20),
            Err("form_state_recovery_unsupported")
        );
        assert!(view.recovery_precondition_for_form(Some(1), 0, 20).is_ok());
        assert!(view.recovery_precondition_for_form(None, 0, 20).is_ok());
        // Recovering form 1 must not clear invalidation for form 0.
        view.mark_form_recovered(Some(1));
        assert_eq!(
            view.recovery_precondition_for_form(Some(0), 0, 20),
            Err("form_state_recovery_unsupported")
        );

        // Recording a recovery failure on form 0 must not poison form 1 or
        // standalone controls.
        view.record_recovery_failure(Some(0), "form_state_recovery_target_changed");
        assert_eq!(
            view.recovery_failure_for_form(Some(0)),
            Some("form_state_recovery_target_changed")
        );
        assert_eq!(view.recovery_failure_for_form(Some(1)), None);
        assert_eq!(view.recovery_failure_for_form(None), None);
        assert!(view.recovery_precondition_for_form(Some(1), 0, 20).is_ok());
    }

    #[test]
    fn obscured_by_extraction_strips_prefix_and_ignores_empty_placeholder() {
        assert_eq!(
            extract_obscured_by("covered by div[data-radix-overlay]"),
            Some("div[data-radix-overlay]".into())
        );
        assert_eq!(
            extract_obscured_by("  covered by .ai-chat-widget  "),
            Some(".ai-chat-widget".into())
        );
        assert_eq!(
            extract_obscured_by("covered by nothing at the click point"),
            None
        );
        assert_eq!(extract_obscured_by(""), None);
        assert_eq!(extract_obscured_by("   "), None);

        let mut rec = InteractionRecord::new("view_0001", "http://x.test/", "#btn", "button");
        apply_failure(
            &mut rec,
            "element not interactable (obscured): covered by div.modal-backdrop",
        );
        assert_eq!(rec.outcome, InteractionOutcome::Skipped);
        assert_eq!(rec.skipped_reason.as_deref(), Some("obscured"));
        assert_eq!(rec.obscured_by.as_deref(), Some("div.modal-backdrop"));

        let mut rec_empty = InteractionRecord::new("view_0001", "http://x.test/", "#btn", "button");
        apply_failure(
            &mut rec_empty,
            "element not interactable (obscured): covered by nothing at the click point",
        );
        assert_eq!(rec_empty.skipped_reason.as_deref(), Some("obscured"));
        assert_eq!(rec_empty.obscured_by, None);
    }
}
