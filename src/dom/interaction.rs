use std::time::Duration;

use anyhow::{Context, Result};
use chromiumoxide::element::Element;
use chromiumoxide::layout::Point;

use crate::browser::{PageClient, cdp_helpers};
use crate::config::ScanConfig;
use crate::dom::effects::{EffectReport, FX_RUNTIME_JS, PrepareOptions, PrepareReport};
use crate::dom::selector::{
    LOCATOR_RUNTIME_JS, dom_path_locator_for_element, primary_locator_json, selector_locator_json,
};
use crate::types::dom::{
    ElementType, InteractionSideEffect, InteractionSnapshot, InteractiveElement, LocatorKind,
    LocatorStrategy,
};

#[derive(Debug, Clone)]
pub struct InteractionObservation {
    pub before_url: Option<String>,
    pub after_url: Option<String>,
    /// Something visibly changed because of the action (see
    /// [`crate::dom::effects`]): text, fields, media, controls, theme, or the
    /// control's own state. Unrelated churn and no-op attribute writes are
    /// not counted.
    pub dom_mutated: bool,
    pub network_activity: bool,
    pub effect: InteractionEffect,
    /// Post-action DOM snapshot; `None` when nothing visible changed.
    pub snapshot: Option<InteractionSnapshot>,
    /// Effects that are not DOM, network or navigation: `print`,
    /// `window_open`, `clipboard`, `scroll`, `download`, `file_chooser`,
    /// `form_validation` (the browser refused the submit and showed a
    /// validation message), `focus_moved`.
    pub side_effects: Vec<String>,
    /// The control was already in its active state before the action
    /// (`aria-pressed`/`aria-selected`/`aria-current`, a checked radio, an
    /// `active` class).
    pub already_active: bool,
    /// The click event landed outside the control (an overlay or a clickable
    /// ancestor caught it): whatever happened is not the control's effect.
    pub click_missed: bool,
    /// Only numbers in existing elements changed: [`recheck_tickers`] still
    /// has to tell a timer from the action's effect.
    pub ticker_recheck: bool,
}

#[derive(Debug, Clone)]
pub enum InteractionEffect {
    Navigation,
    DomMutation,
    NoEffect,
    Error(String),
}

/// Pause before re-reading elements whose numbers changed during an action
/// (see [`EffectReport::ticker_suspect`]): long enough for a once-a-second
/// timer to tick again.
const TICKER_RECHECK_DELAY: Duration = Duration::from_millis(1100);

/// A control ready to be exercised (see [`prepare_target`]).
pub struct PreparedTarget {
    resolved: ResolvedElement,
    /// Viewport point (CSS px) that hit-tests to the control; `None` when the
    /// control lives in another document (iframe) and is clicked directly.
    point: Option<Point>,
    pub already_active: bool,
    /// Closed ancestor `<details>` opened to reveal the control.
    pub expanded_details: u32,
    /// Form fields filled with synthetic values before the action.
    pub filled_fields: u32,
}

/// Result of [`prepare_target`].
pub enum Prepared {
    Ready(PreparedTarget),
    /// Not exercisable as a user would: `hidden`, `obscured` or `disabled`.
    Skip {
        reason: &'static str,
        detail: String,
    },
}

/// Default [`PrepareOptions`] for exercising `element`: open ancestor
/// `<details>`, and fill the form of a submit-like control when submits are
/// enabled (guarded scans) so the would-be write is observed.
pub fn prepare_options(element: &InteractiveElement, cfg: &ScanConfig) -> PrepareOptions {
    PrepareOptions {
        expand: true,
        fill: is_submitish_element(element)
            && cfg.exploration.submit_forms
            && cfg.exploration.fill_forms_with_test_data,
        unlock: false,
        passwords: false,
        values: cfg.test_data.values.clone(),
    }
}

/// Submit-like: an explicit form submit, or a submit/destructive label.
pub fn is_submitish_element(element: &InteractiveElement) -> bool {
    let label = element.label.as_deref();
    let button_like = matches!(element.element_type, ElementType::Button { .. })
        || matches!(&element.element_type, ElementType::Other { role: Some(r), .. } if r == "button");
    button_like
        && (matches!(
            element.element_type,
            ElementType::Button { form_submit: true }
        ) || crate::dom::heuristics::is_submit_mutation_label(label)
            || crate::dom::heuristics::is_destructive_mutation_label(label))
}

/// Exercise `element`: prepare it ([`prepare_target`]) and act on it
/// ([`perform_prepared`]). A control that is hidden, covered or disabled is
/// reported as an error (`element not interactable (...)`).
pub async fn interact(
    page: &PageClient,
    element: &InteractiveElement,
    cfg: &ScanConfig,
) -> Result<InteractionObservation> {
    match prepare_target(page, element, &prepare_options(element, cfg)).await? {
        Prepared::Ready(prepared) => {
            let mut obs = perform_prepared(page, element, &prepared, cfg).await?;
            recheck_tickers(page, &mut obs).await;
            Ok(obs)
        }
        Prepared::Skip { reason, detail } => Err(anyhow::anyhow!(
            "element not interactable ({reason}): {detail}"
        )),
    }
}

/// Get a control ready for a user-like click, before any action is
/// attributed: open closed ancestor `<details>`, optionally fill its form,
/// scroll it into view, check it is visible and that a point inside it is
/// not covered by another element, move the mouse there, wait for the page
/// to go quiet, and record the visible-state baseline the action's effect
/// is measured against.
pub async fn prepare_target(
    page: &PageClient,
    element: &InteractiveElement,
    opts: &PrepareOptions,
) -> Result<Prepared> {
    let _ = cdp_helpers::ensure_instrumentation(page).await;
    let _: bool = page
        .evaluate_json(FX_RUNTIME_JS)
        .await
        .context("install effect probe")?;
    let resolved = resolve_element(page, element).await?;
    let locator_json = resolved_locator_json(&resolved)?;

    let mut expanded_details = 0;
    let mut report = run_prepare(page, &locator_json, opts).await?;
    if report.status == "expanded" {
        expanded_details = report.expanded;
        cdp_helpers::wait_quiet(page, Duration::from_millis(150), Duration::from_millis(800)).await;
        let again = PrepareOptions {
            expand: false,
            ..opts.clone()
        };
        report = run_prepare(page, &locator_json, &again).await?;
    }
    if report.status == "unlock" {
        // Filled the container of a disabled control; see whether it enabled.
        cdp_helpers::wait_quiet(
            page,
            Duration::from_millis(200),
            Duration::from_millis(1000),
        )
        .await;
        let again = PrepareOptions {
            expand: false,
            fill: false,
            unlock: false,
            ..opts.clone()
        };
        report = run_prepare(page, &locator_json, &again).await?;
        report.filled = report.filled.max(1);
    }
    let detail = report.detail.clone().unwrap_or_default();
    match report.status.as_str() {
        "ready" => {}
        "missing" => anyhow::bail!("locator_not_found"),
        "hidden" => {
            return Ok(Prepared::Skip {
                reason: "hidden",
                detail,
            });
        }
        "obscured" => {
            return Ok(Prepared::Skip {
                reason: "obscured",
                detail,
            });
        }
        "disabled" => {
            return Ok(Prepared::Skip {
                reason: "disabled",
                detail: "disabled when its turn came".to_string(),
            });
        }
        other => anyhow::bail!("prepare failed: {other}"),
    }
    if report.filled > 0 {
        cdp_helpers::wait_quiet(
            page,
            Duration::from_millis(200),
            Duration::from_millis(1000),
        )
        .await;
    }
    let point = report.x.zip(report.y).map(|(x, y)| Point { x, y });
    if let Some(point) = point {
        let _ = page.inner().move_mouse(point).await;
    }
    // Scroll, hover and filling settle before the baseline: what they cause
    // (sticky headers, scroll observers, validation) is not the click's.
    cdp_helpers::wait_quiet(page, Duration::from_millis(150), Duration::from_millis(800)).await;
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  const el = resolveBrokenAppLocator(locator);
  return !!(window.__BROKENAPP_FX && window.__BROKENAPP_FX.baseline(el));
}})()
"#
    );
    let _: bool = page
        .evaluate_json(&script)
        .await
        .context("record effect baseline")?;
    Ok(Prepared::Ready(PreparedTarget {
        resolved,
        point,
        already_active: report.already_active,
        expanded_details,
        filled_fields: report.filled,
    }))
}

async fn run_prepare(
    page: &PageClient,
    locator_json: &str,
    opts: &PrepareOptions,
) -> Result<PrepareReport> {
    let opts_json = serde_json::to_string(opts).context("serialize prepare options")?;
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  const el = resolveBrokenAppLocator(locator);
  return window.__BROKENAPP_FX.prepare(el, {opts_json});
}})()
"#
    );
    page.evaluate_json::<PrepareReport>(&script)
        .await
        .context("prepare control")
}

/// Ephemeral post-action native state; never serialized into scan artifacts or
/// exposed through Debug. It contains option values needed to select the same
/// option again, not to advance the dropdown a second time.
#[derive(Clone, PartialEq)]
pub(crate) struct NativeControlState(serde_json::Value);

impl NativeControlState {
    pub(crate) fn is_unchecked_radio(&self) -> bool {
        self.0["kind"] == "radio" && self.0["checked"] == false
    }
}

impl std::fmt::Debug for NativeControlState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeControlState(<ephemeral>)")
    }
}

const NATIVE_STATE_JS: &str = r#"
function readNativeState(el) {
  if (!el) return null;
  const kind = el.tagName === 'SELECT' ? el.type
    : el.tagName === 'INPUT' && ['checkbox','radio'].includes(el.type) ? el.type : null;
  if (!kind) return null;
  const form = el.form ? {id:el.form.id, name:el.form.getAttribute('name'),
    index:Array.from(el.ownerDocument.forms).indexOf(el.form)} : null;
  return {kind, id:el.id, name:el.getAttribute('name'), form,
    value:kind === 'radio' ? el.value : null,
    checked:el.tagName === 'INPUT' ? el.checked : null,
    selected:el.tagName === 'SELECT' ? Array.from(el.options).flatMap((o,i)=>
      o.selected ? [{index:i,value:o.value}] : []) : null};
}
function nativeStateCompatible(el, desired) {
  const now = readNativeState(el);
  if (!now) return false;
  for (const key of ['kind','id','name','value']) {
    if (now[key] !== desired[key]) return false;
  }
  if ((now.form === null) !== (desired.form === null)) return false;
  if (now.form && ['id','name','index'].some(key=>now.form[key] !== desired.form[key])) return false;
  return desired.selected === null || desired.selected.every(s=> {
    const o = el.options[s.index];
    return o && o.value === s.value && !o.disabled &&
      !(o.parentElement && o.parentElement.tagName === 'OPTGROUP' && o.parentElement.disabled);
  });
}
"#;

pub(crate) async fn capture_native_state(
    page: &PageClient,
    element: &InteractiveElement,
) -> Option<NativeControlState> {
    let kind = match element.element_type {
        ElementType::Checkbox { .. } => "checkbox",
        ElementType::RadioButton { .. } => "radio",
        ElementType::SelectDropdown { .. } => "select",
        _ => return None,
    };
    let locator = primary_locator_json(element).ok()?;
    let script = format!(
        r#"(() => {{
        {LOCATOR_RUNTIME_JS} {NATIVE_STATE_JS}
        const state = readNativeState(resolveBrokenAppLocator({locator}));
        return state && (state.kind === '{kind}' || ('{kind}' === 'select' && state.kind.startsWith('select-'))) ? state : null;
    }})()"#
    );
    page.evaluate_json::<Option<serde_json::Value>>(&script)
        .await
        .ok()
        .flatten()
        .map(NativeControlState)
}

pub(crate) async fn native_state_compatible(
    page: &PageClient,
    element: &InteractiveElement,
    state: &NativeControlState,
) -> bool {
    let Ok(locator) = primary_locator_json(element) else {
        return false;
    };
    let desired = &state.0;
    let script = format!(
        r#"(() => {{
        {LOCATOR_RUNTIME_JS} {NATIVE_STATE_JS}
        return nativeStateCompatible(resolveBrokenAppLocator({locator}), {desired});
    }})()"#
    );
    page.evaluate_json::<bool>(&script).await.unwrap_or(false)
}

async fn restore_native_state(
    page: &PageClient,
    prepared: &PreparedTarget,
    state: &NativeControlState,
) -> Result<()> {
    let locator = resolved_locator_json(&prepared.resolved)?;
    let desired = &state.0;
    let script = format!(
        r#"(() => {{
        {LOCATOR_RUNTIME_JS} {NATIVE_STATE_JS}
        const el = resolveBrokenAppLocator({locator});
        const desired = {desired};
        if (!nativeStateCompatible(el, desired)) return false;
        if (desired.selected !== null) {{
          const before = readNativeState(el).selected;
          if (before.length !== desired.selected.length || before.some((s,i)=>
              s.index !== desired.selected[i].index || s.value !== desired.selected[i].value)) {{
            const selected = new Set(desired.selected.map(s=>s.index));
            Array.from(el.options).forEach((o,i)=>{{o.selected=selected.has(i)}});
            el.dispatchEvent(new Event('input', {{bubbles:true}}));
            el.dispatchEvent(new Event('change', {{bubbles:true}}));
          }}
        }} else if (el.checked !== desired.checked) {{
          if (desired.kind === 'radio' && !desired.checked) {{
            // Clicking an already checked radio cannot uncheck it.
            Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'checked').set.call(el,false);
            el.dispatchEvent(new Event('input', {{bubbles:true}}));
            el.dispatchEvent(new Event('change', {{bubbles:true}}));
          }} else {{ el.click(); }}
        }}
        return true;
    }})()"#
    );
    // Do not propagate an evaluation error containing the ephemeral JS values.
    if page.evaluate_json::<bool>(&script).await.unwrap_or(false) {
        Ok(())
    } else {
        anyhow::bail!("native_state_recovery_unavailable")
    }
}

/// Act on a prepared control (trusted click at the hit-tested point, typing
/// or selecting) and observe what it changed.
pub async fn perform_prepared(
    page: &PageClient,
    element: &InteractiveElement,
    prepared: &PreparedTarget,
    cfg: &ScanConfig,
) -> Result<InteractionObservation> {
    perform_prepared_with_native_state(page, element, prepared, cfg, None).await
}

pub(crate) async fn perform_prepared_with_native_state(
    page: &PageClient,
    element: &InteractiveElement,
    prepared: &PreparedTarget,
    cfg: &ScanConfig,
    native_state: Option<&NativeControlState>,
) -> Result<InteractionObservation> {
    // Install a MutationObserver to capture DOM changes (best-effort).
    let snapshot_id = crate::dom::snapshot::begin_snapshot(page).await.ok();
    let _ = page
        .evaluate_json::<bool>("window.__BROKENAPP_FX ? window.__BROKENAPP_FX.rebase() : false")
        .await;

    let before_url = page.url().await.ok().flatten();
    let before = read_probe_state(page).await.unwrap_or_default();

    let res = match native_state {
        Some(state) => {
            let result = restore_native_state(page, prepared, state).await;
            tokio::time::sleep(Duration::from_millis(
                cfg.pacing.delay_between_interactions_ms,
            ))
            .await;
            result
        }
        None => act(page, element, prepared, cfg).await,
    };

    // Give the page time to react.
    let settle_ms = cfg.settle_timeout_ms.max(100);
    let _ = cdp_helpers::settle(page, Duration::from_millis(settle_ms)).await;

    let after_url = page.url().await.ok().flatten();
    let after = read_probe_state(page).await.unwrap_or_default();
    // `null`: the probe is gone, so the document was replaced.
    let report = match page
        .evaluate_json::<Option<EffectReport>>(
            "window.__BROKENAPP_FX ? window.__BROKENAPP_FX.effects() : null",
        )
        .await
    {
        Ok(Some(report)) => Some(report),
        Ok(None) => Some(EffectReport {
            missing_base: true,
            ..Default::default()
        }),
        Err(err) => {
            tracing::debug!(error = ?err, selector = %element.selector, "effect report unavailable");
            None
        }
    };

    let network_activity = after.requests_started > before.requests_started
        || after.pending > before.pending
        || after.ws_frames_sent > before.ws_frames_sent
        || after.ws_frames_blocked > before.ws_frames_blocked;
    let side_effects = side_effect_names(before, after, report.as_ref());
    // Only numbers changed and nothing else happened: the caller looks again
    // after a pause ([`recheck_tickers`]).
    let url_changed = before_url != after_url && after_url.is_some();
    let ticker_recheck = !url_changed
        && !network_activity
        && side_effects.is_empty()
        && report
            .as_ref()
            .is_some_and(|r| r.ticker_suspect && r.only_text_changed());
    let visible_change = match &report {
        Some(report) => report.visible_change(),
        // No report: fall back to the raw mutation counter.
        None => after.dom_mutations > before.dom_mutations,
    };
    let click_missed = report.as_ref().is_some_and(EffectReport::click_missed);

    // Collect the post-interaction snapshot.
    let dom_snapshot = if let Some(sid) = snapshot_id {
        match crate::dom::snapshot::end_snapshot(page, &sid, Some(element)).await {
            Ok(snap) if !snap.is_empty() => Some(snap),
            _ => None,
        }
    } else {
        None
    };

    let navigated = before_url != after_url && after_url.is_some();
    let effect = match res {
        Ok(()) => {
            if navigated {
                InteractionEffect::Navigation
            } else if visible_change || !side_effects.is_empty() {
                InteractionEffect::DomMutation
            } else {
                InteractionEffect::NoEffect
            }
        }
        Err(e) => InteractionEffect::Error(format!("{e:#}")),
    };
    let snapshot = if matches!(effect, InteractionEffect::NoEffect) {
        None
    } else {
        let mut snapshot = snapshot_with_side_effects(
            before_url.clone(),
            after_url.clone(),
            before,
            after,
            dom_snapshot,
        );
        if visible_change && let Some(report) = report.as_ref() {
            snapshot = Some(with_changed_text(snapshot.unwrap_or_default(), report));
        }
        snapshot
    };

    Ok(InteractionObservation {
        before_url,
        after_url,
        dom_mutated: visible_change,
        network_activity,
        effect,
        snapshot,
        side_effects,
        already_active: prepared.already_active,
        click_missed,
        ticker_recheck,
    })
}

/// When the only thing an action changed was numbers in existing elements
/// ([`InteractionObservation::ticker_recheck`]), look again after a pause:
/// elements that changed again tick on their own (a timer that was not
/// known yet, e.g. right after a reload) and are not the action's effect.
/// Call it after the action window closed, so nothing that happens during
/// the pause is attributed to the action.
pub async fn recheck_tickers(page: &PageClient, obs: &mut InteractionObservation) {
    if !obs.ticker_recheck {
        return;
    }
    obs.ticker_recheck = false;
    tokio::time::sleep(TICKER_RECHECK_DELAY).await;
    let stable = page
        .evaluate_json::<u32>("window.__BROKENAPP_FX ? window.__BROKENAPP_FX.recheck() : 1")
        .await
        .unwrap_or(1);
    if stable == 0 {
        obs.dom_mutated = false;
        if matches!(obs.effect, InteractionEffect::DomMutation) && obs.side_effects.is_empty() {
            obs.effect = InteractionEffect::NoEffect;
            obs.snapshot = None;
        }
    }
}

/// Contract names of the non-DOM effects seen during an action.
fn side_effect_names(
    before: ProbeState,
    after: ProbeState,
    report: Option<&EffectReport>,
) -> Vec<String> {
    let mut out = Vec::new();
    if after.prints > before.prints {
        out.push("print".to_string());
    }
    if after.window_opens > before.window_opens {
        out.push("window_open".to_string());
    }
    if after.clipboard_writes > before.clipboard_writes {
        out.push("clipboard".to_string());
    }
    if after.downloads > before.downloads {
        out.push("download".to_string());
    }
    if after.file_choosers > before.file_choosers {
        out.push("file_chooser".to_string());
    }
    if after.ws_frames_blocked > before.ws_frames_blocked {
        out.push("websocket_guarded".to_string());
    } else if after.ws_frames_sent > before.ws_frames_sent {
        out.push("websocket".to_string());
    }
    if let Some(report) = report {
        if report.invalid > 0 {
            out.push("form_validation".to_string());
        }
        if report.scrolled {
            out.push("scroll".to_string());
        }
        if report.focus_moved {
            out.push("focus_moved".to_string());
        }
    }
    out
}

/// Text that appeared or changed (from the effect report) as
/// `appeared_text`, so in-place updates (a counter, "Copied!") are described
/// as a message rather than `other`.
fn with_changed_text(
    mut snapshot: InteractionSnapshot,
    report: &EffectReport,
) -> InteractionSnapshot {
    if snapshot.appeared_text.is_empty() && snapshot.appeared_elements.is_empty() {
        for text in report.samples.iter().take(3) {
            snapshot
                .appeared_text
                .push(crate::types::dom::AppearedText {
                    selector: String::new(),
                    text: text.clone(),
                    kind: "unknown".to_string(),
                    is_toast: false,
                    in_form: false,
                    has_error_action: false,
                });
        }
    }
    snapshot
}

async fn act(
    page: &PageClient,
    el: &InteractiveElement,
    prepared: &PreparedTarget,
    cfg: &ScanConfig,
) -> Result<()> {
    let resolved = &prepared.resolved;
    let click = || async {
        match prepared.point {
            Some(point) => {
                page.inner().click(point).await.context("dispatch click")?;
                Ok(())
            }
            None => click_resolved(page, resolved).await,
        }
    };
    match &el.element_type {
        ElementType::TextInput {
            input_type, name, ..
        } => {
            if !cfg.exploration.fill_forms_with_test_data {
                return Ok(());
            }
            let val = value_for_resolved(
                page,
                resolved,
                cfg,
                name.as_deref(),
                el.label.as_deref(),
                input_type,
            )
            .await;
            clear_and_type_resolved(page, resolved, &val).await?;
        }
        ElementType::Other { tag, .. } if tag.eq_ignore_ascii_case("textarea") => {
            if !cfg.exploration.fill_forms_with_test_data {
                return Ok(());
            }
            let val =
                value_for_resolved(page, resolved, cfg, None, el.label.as_deref(), "textarea")
                    .await;
            clear_and_type_resolved(page, resolved, &val).await?;
        }
        ElementType::SelectDropdown { options } => {
            if options.is_empty() {
                return Ok(());
            }
            select_next_option_resolved(page, resolved).await?;
        }
        ElementType::FileUpload { .. } => {
            // Skip file uploads by default.
        }
        _ => {
            if is_submitish_element(el) && !cfg.exploration.submit_forms {
                return Ok(());
            }
            click().await?;
        }
    }

    tokio::time::sleep(Duration::from_millis(
        cfg.pacing.delay_between_interactions_ms,
    ))
    .await;

    Ok(())
}

enum ResolvedElement {
    Handle {
        handle: Element,
        selector_used: String,
    },
    Locator {
        locator_json: String,
    },
}

async fn resolve_element(
    page: &PageClient,
    element: &InteractiveElement,
) -> Result<ResolvedElement> {
    if dom_path_locator_for_element(element).is_some() {
        let locator_json = primary_locator_json(element)?;
        if locator_exists(page, &locator_json).await? {
            return Ok(ResolvedElement::Locator { locator_json });
        }
    }

    if let Ok(handle) = page.inner().find_element(&element.selector).await {
        return Ok(ResolvedElement::Handle {
            handle,
            selector_used: element.selector.clone(),
        });
    }

    for locator in element
        .locators
        .iter()
        .filter(|locator| locator.unique)
        .filter(|locator| locator.kind != LocatorKind::DomPath)
        .filter(|locator| locator.value != element.selector)
    {
        if let Ok(handle) = page.inner().find_element(&locator.value).await {
            tracing::debug!(
                primary = %element.selector,
                fallback = %locator.value,
                kind = ?locator.kind,
                "resolved element via fallback locator"
            );
            return Ok(ResolvedElement::Handle {
                handle,
                selector_used: locator.value.clone(),
            });
        }
    }

    let attempted = attempted_locators(&element.locators);
    if dom_path_locator_for_element(element).is_some() {
        let locator_json = primary_locator_json(element)?;
        if locator_exists(page, &locator_json).await? {
            return Ok(ResolvedElement::Locator { locator_json });
        }
    }

    let handle = page
        .inner()
        .find_element(&element.selector)
        .await
        .with_context(|| {
            format!(
                "find element {} (fallbacks tried: {attempted})",
                element.selector
            )
        })?;

    Ok(ResolvedElement::Handle {
        handle,
        selector_used: element.selector.clone(),
    })
}

fn attempted_locators(locators: &[LocatorStrategy]) -> String {
    let attempts = locators
        .iter()
        .filter(|locator| locator.unique)
        .map(|locator| {
            if locator.kind == LocatorKind::DomPath {
                "dom_path"
            } else {
                locator.value.as_str()
            }
        })
        .take(5)
        .collect::<Vec<_>>();
    if attempts.is_empty() {
        "none".to_string()
    } else {
        attempts.join(", ")
    }
}

#[derive(serde::Deserialize)]
struct LocatorActionResult {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

async fn locator_exists(page: &PageClient, locator_json: &str) -> Result<bool> {
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  return !!resolveBrokenAppLocator(locator);
}})()
"#
    );
    page.evaluate_json(&script).await
}

async fn click_locator(page: &PageClient, locator_json: &str) -> Result<()> {
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  const el = resolveBrokenAppLocator(locator);
  if (!el) return {{ ok: false, error: "locator_not_found" }};
  try {{
    el.click();
    return {{ ok: true }};
  }} catch (e) {{
    return {{ ok: false, error: String((e && e.message) || e || "click_failed") }};
  }}
}})()
"#
    );
    let result: LocatorActionResult = page.evaluate_json(&script).await?;
    if result.ok {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            result.error.unwrap_or_else(|| "click_failed".to_string())
        ))
    }
}

async fn clear_and_type_locator(page: &PageClient, locator_json: &str, value: &str) -> Result<()> {
    let value_json = serde_json::to_string(value)?;
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  const value = {value_json};
  {LOCATOR_RUNTIME_JS}

  function setNativeValue(el, nextValue) {{
    const proto = Object.getPrototypeOf(el);
    const own = proto ? Object.getOwnPropertyDescriptor(proto, 'value') : null;
    const fallbackProto = el && el.tagName === 'TEXTAREA'
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const inputSetter = own && own.set
      ? own.set
      : Object.getOwnPropertyDescriptor(fallbackProto, 'value').set;
    try {{ if (el._valueTracker) el._valueTracker.setValue(''); }} catch (_) {{}}
    inputSetter.call(el, nextValue);
  }}

  const el = resolveBrokenAppLocator(locator);
  if (!el) return {{ ok: false, error: "locator_not_found" }};
  try {{
    if (el.focus) el.focus();
    setNativeValue(el, "");
    setNativeValue(el, value);
    el.dispatchEvent(new InputEvent("input", {{ bubbles: true, data: value, inputType: "insertText" }}));
    el.dispatchEvent(new Event("change", {{ bubbles: true }}));
    return {{ ok: true }};
  }} catch (e) {{
    return {{ ok: false, error: String((e && e.message) || e || "type_failed") }};
  }}
}})()
"#
    );
    let result: LocatorActionResult = page.evaluate_json(&script).await?;
    if result.ok {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            result.error.unwrap_or_else(|| "type_failed".to_string())
        ))
    }
}

async fn select_next_option_locator(page: &PageClient, locator_json: &str) -> Result<()> {
    let script = format!(
        r#"
(() => {{
  const locator = {locator_json};
  {LOCATOR_RUNTIME_JS}
  const el = resolveBrokenAppLocator(locator);
  if (!el) return {{ ok: false, error: "locator_not_found" }};
  try {{
    const opts = Array.from(el.options || []);
    if (!opts.length) return {{ ok: true }};
    const cur = (typeof el.selectedIndex === "number" && el.selectedIndex >= 0) ? el.selectedIndex : 0;
    let idx = -1;
    for (let i = 1; i <= opts.length; i++) {{
      const j = (cur + i) % opts.length;
      const t = (opts[j] && (opts[j].label || opts[j].textContent || "")).trim();
      if (!t) continue;
      idx = j;
      break;
    }}
    if (idx >= 0) {{
      el.selectedIndex = idx;
      el.dispatchEvent(new Event("change", {{ bubbles: true }}));
      el.dispatchEvent(new Event("input", {{ bubbles: true }}));
    }}
    return {{ ok: true }};
  }} catch (e) {{
    return {{ ok: false, error: String((e && e.message) || e || "select_failed") }};
  }}
}})()
"#
    );
    let result: LocatorActionResult = page.evaluate_json(&script).await?;
    if result.ok {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            result.error.unwrap_or_else(|| "select_failed".to_string())
        ))
    }
}

fn resolved_locator_json(target: &ResolvedElement) -> Result<String> {
    match target {
        ResolvedElement::Handle { selector_used, .. } => selector_locator_json(selector_used),
        ResolvedElement::Locator { locator_json } => Ok(locator_json.clone()),
    }
}

async fn click_resolved(page: &PageClient, target: &ResolvedElement) -> Result<()> {
    match target {
        ResolvedElement::Handle { handle, .. } => {
            handle.click().await?;
            Ok(())
        }
        ResolvedElement::Locator { locator_json } => click_locator(page, locator_json).await,
    }
}

async fn clear_and_type_resolved(
    page: &PageClient,
    target: &ResolvedElement,
    value: &str,
) -> Result<()> {
    match target {
        ResolvedElement::Handle { handle, .. } => {
            handle.click().await?;
            let _ = handle
                .call_js_fn("function() { this.value = ''; }", true)
                .await;
            handle.type_str(value).await?;
            Ok(())
        }
        ResolvedElement::Locator { locator_json } => {
            clear_and_type_locator(page, locator_json, value).await
        }
    }
}

async fn select_next_option_resolved(page: &PageClient, target: &ResolvedElement) -> Result<()> {
    match target {
        ResolvedElement::Handle { handle, .. } => {
            let js = r#"
function() {
  try {
    const opts = Array.from(this.options || []);
    if (!opts.length) return;
    const cur = (typeof this.selectedIndex === "number" && this.selectedIndex >= 0) ? this.selectedIndex : 0;
    let idx = -1;
    for (let i = 1; i <= opts.length; i++) {
      const j = (cur + i) % opts.length;
      const t = (opts[j] && (opts[j].label || opts[j].textContent || "")).trim();
      if (!t) continue;
      idx = j;
      break;
    }
    if (idx >= 0) {
      this.selectedIndex = idx;
      this.dispatchEvent(new Event("change", { bubbles: true }));
      this.dispatchEvent(new Event("input", { bubbles: true }));
    }
  } catch (_) {}
}
"#;
            let _ = handle.call_js_fn(js.to_string(), true).await?;
            Ok(())
        }
        ResolvedElement::Locator { locator_json } => {
            select_next_option_locator(page, locator_json).await
        }
    }
}

async fn value_for_resolved(
    page: &PageClient,
    target: &ResolvedElement,
    cfg: &ScanConfig,
    name: Option<&str>,
    label: Option<&str>,
    input_type: &str,
) -> String {
    if let Ok(locator_json) = resolved_locator_json(target)
        && let Ok(values_json) = serde_json::to_string(&cfg.test_data.values)
    {
        let script = format!(
            r#"(() => {{
  const locator = {locator_json};
  const values = {values_json};
  {LOCATOR_RUNTIME_JS}
  const el = resolveBrokenAppLocator(locator);
  if (el && window.__BROKENAPP_FX && typeof window.__BROKENAPP_FX.valueFor === 'function') {{
    return window.__BROKENAPP_FX.valueFor(el, values);
  }}
  return null;
}})()"#
        );
        if let Ok(Some(value)) = page.evaluate_json::<Option<String>>(&script).await
            && !value.is_empty()
        {
            return value;
        }
    }
    pick_test_value(cfg, name, label, input_type).to_string()
}

fn pick_test_value<'a>(
    cfg: &'a ScanConfig,
    name: Option<&str>,
    label: Option<&str>,
    input_type: &str,
) -> &'a str {
    if let Some(k) = name {
        if let Some(v) = cfg.test_data.values.get(&k.to_string()) {
            return v;
        }
    }
    if let Some(k) = label {
        if let Some(v) = cfg.test_data.values.get(&k.to_string()) {
            return v;
        }
    }
    match input_type {
        "email" => "test@brokenapp.dev",
        "tel" => "+1-555-0100",
        "url" => "https://example.com",
        "number" => "1",
        "password" => "Password123!",
        "search" => "test",
        "textarea" => "Test message content",
        _ => "test",
    }
}

#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
struct ProbeState {
    #[serde(default)]
    pending: u64,
    #[serde(default)]
    requests_started: u64,
    #[serde(default)]
    dom_mutations: u64,
    #[serde(default)]
    clipboard_writes: u64,
    #[serde(default)]
    local_storage_writes: u64,
    #[serde(default)]
    local_storage_clears: u64,
    #[serde(default)]
    session_storage_writes: u64,
    #[serde(default)]
    session_storage_clears: u64,
    #[serde(default)]
    cookie_writes: u64,
    #[serde(default)]
    location_assigns: u64,
    #[serde(default)]
    location_replaces: u64,
    #[serde(default)]
    prints: u64,
    #[serde(default)]
    window_opens: u64,
    #[serde(default)]
    downloads: u64,
    #[serde(default)]
    file_choosers: u64,
    #[serde(default)]
    ws_frames_sent: u64,
    #[serde(default)]
    ws_frames_blocked: u64,
}

async fn read_probe_state(page: &PageClient) -> Result<ProbeState> {
    let script = r#"
(() => {
  const s = window.__BROKENAPP || {};
  const n = (k) => (typeof s[k] === "number" ? s[k] : 0);
  return {
    pending: n("pending"),
    requests_started: n("requestsStarted"),
    dom_mutations: n("domMutations"),
    clipboard_writes: n("clipboardWrites"),
    local_storage_writes: n("localStorageWrites"),
    local_storage_clears: n("localStorageClears"),
    session_storage_writes: n("sessionStorageWrites"),
    session_storage_clears: n("sessionStorageClears"),
    cookie_writes: n("cookieWrites"),
    location_assigns: n("locationAssigns"),
    location_replaces: n("locationReplaces"),
    prints: n("prints"),
    window_opens: n("windowOpens"),
    downloads: n("downloads"),
    file_choosers: n("fileChoosers"),
    ws_frames_sent: n("wsFramesSent"),
    ws_frames_blocked: n("wsFramesBlocked")
  };
})()
"#;
    page.evaluate_json(script).await
}

fn snapshot_with_side_effects(
    before_url: Option<String>,
    after_url: Option<String>,
    before: ProbeState,
    after: ProbeState,
    snapshot: Option<InteractionSnapshot>,
) -> Option<InteractionSnapshot> {
    let mut snapshot = snapshot.unwrap_or_default();
    let mut push_delta = |kind: &str, from: u64, to: u64| {
        if to > from {
            snapshot.side_effects.push(InteractionSideEffect {
                kind: kind.to_string(),
                count: to - from,
                before: None,
                after: None,
            });
        }
    };

    push_delta(
        "clipboard_write",
        before.clipboard_writes,
        after.clipboard_writes,
    );
    push_delta(
        "local_storage_write",
        before.local_storage_writes,
        after.local_storage_writes,
    );
    push_delta(
        "local_storage_clear",
        before.local_storage_clears,
        after.local_storage_clears,
    );
    push_delta(
        "session_storage_write",
        before.session_storage_writes,
        after.session_storage_writes,
    );
    push_delta(
        "session_storage_clear",
        before.session_storage_clears,
        after.session_storage_clears,
    );
    push_delta("cookie_write", before.cookie_writes, after.cookie_writes);
    push_delta(
        "location_assign",
        before.location_assigns,
        after.location_assigns,
    );
    push_delta(
        "location_replace",
        before.location_replaces,
        after.location_replaces,
    );

    if before_url != after_url
        && after_url
            .as_deref()
            .map(is_meaningful_navigation_target)
            .unwrap_or(false)
    {
        snapshot.side_effects.push(InteractionSideEffect {
            kind: "navigation".to_string(),
            count: 1,
            before: before_url,
            after: after_url,
        });
    }

    if snapshot.is_empty() {
        None
    } else {
        Some(snapshot)
    }
}

fn is_meaningful_navigation_target(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[derive(Debug, Clone)]
pub enum DismissResult {
    Dismissed,
    NotDismissable,
}

/// Attempt to dismiss a modal/dialog overlay by pressing Escape, clicking a
/// close button, or clicking the backdrop.
pub async fn dismiss_modal(page: &PageClient, timeout_ms: u64) -> Result<DismissResult> {
    let settle = Duration::from_millis(timeout_ms.max(200));

    // Strategy 1: Press Escape.
    let escape_js = r#"
    (() => {
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
        document.dispatchEvent(new KeyboardEvent('keyup', { key: 'Escape', code: 'Escape', bubbles: true }));
    })()
    "#;
    let _ = page.evaluate_json::<()>(escape_js).await;
    let _ = cdp_helpers::settle(page, settle).await;
    if !is_modal_visible(page).await {
        return Ok(DismissResult::Dismissed);
    }

    // Strategy 2: Click a close button.
    let close_js = r#"
    (() => {
        const sel = [
            '[aria-label*="close" i]', '[title*="close" i]',
            'button.close', '[data-dismiss]', '[data-close]',
            '[data-testid*="close" i]'
        ].join(', ');
        const btn = document.querySelector(sel);
        if (btn) { btn.click(); return true; }
        return false;
    })()
    "#;
    if let Ok(true) = page.evaluate_json::<bool>(close_js).await {
        let _ = cdp_helpers::settle(page, settle).await;
        if !is_modal_visible(page).await {
            return Ok(DismissResult::Dismissed);
        }
    }

    // Strategy 3: Click backdrop overlay.
    let backdrop_js = r#"
    (() => {
        const overlay = document.querySelector(
            '[class*="overlay" i], [class*="backdrop" i], [class*="mask" i]'
        );
        if (overlay) { overlay.click(); return true; }
        return false;
    })()
    "#;
    if let Ok(true) = page.evaluate_json::<bool>(backdrop_js).await {
        let _ = cdp_helpers::settle(page, settle).await;
        if !is_modal_visible(page).await {
            return Ok(DismissResult::Dismissed);
        }
    }

    Ok(DismissResult::NotDismissable)
}

/// Best-effort dismissal of identified cookie-consent and welcome banners.
/// Route-owned dialogs are application content: a generic Close button, Material
/// dialog attribute, backdrop, or Escape handler is not permission to dismiss
/// them before discovery. Only controls inside recognized nuisance containers
/// are eligible. Returns the number of controls clicked.
///
/// Note: some SPAs (such as apps with full-screen welcome dialogs) set
/// `app-root` `aria-hidden=true` on load, blocking element discovery until the
/// overlay is dismissed.
pub async fn dismiss_blocking_overlays(page: &PageClient) -> usize {
    let js = r#"
    (() => {
      let n = 0;
      const visible = el => {
        if (!el.isConnected || el.closest('[hidden], [aria-hidden="true"]')) return false;
        const style = getComputedStyle(el);
        return style.display !== 'none' && style.visibility !== 'hidden'
          && Array.from(el.getClientRects()).some(r => r.width > 0 && r.height > 0);
      };
      const cookieContainers = [
        '.cc-window', '.cc-banner', '.cookie-banner', '.cookie-consent',
        '#cookie-banner', '#cookie-consent',
        '[data-testid="cookie-banner"]', '[data-testid="cookie-consent"]',
        '#onetrust-banner-sdk', '.fc-consent-root',
      ];
      const containers = [...cookieContainers,
        'app-welcome-banner', '#welcome-banner', '.welcome-banner',
        '[data-testid="welcome-banner"]',
      ];
      const close = [
        'button[aria-label*="close" i]', 'button[aria-label*="dismiss" i]',
        'button[mat-dialog-close]', 'button.close', 'button[data-dismiss]',
        'button[data-testid*="close" i]', 'button[data-testid*="dismiss" i]',
        '.cc-dismiss', '#onetrust-reject-all-handler',
      ].join(', ');
      const consent = [
        '.cc-allow', '#onetrust-accept-btn-handler', '.fc-cta-consent',
        'button[aria-label*="accept" i]', 'button[aria-label*="reject" i]',
      ].join(', ');
      const seen = new Set();
      const handled = [];
      for (const container of document.querySelectorAll(containers.join(', '))) {
        if (!visible(container) || handled.some(parent =>
            parent.contains(container) || container.contains(parent))) continue;
        const cookie = container.matches(cookieContainers.join(', '));
        const candidates = [
          ...container.querySelectorAll(close),
          ...(cookie ? container.querySelectorAll(consent) : []),
        ];
        for (const el of candidates) {
          if (seen.has(el) || !visible(el) || el.disabled
              || el.getAttribute('aria-disabled') === 'true'
              || (el.form && el.type !== 'button')) continue;
          seen.add(el);
          try { el.click(); n++; } catch (e) { continue; }
          handled.push(container);
          // One decision per banner. Do not also activate a second consent
          // action or a newly exposed child after the first click.
          break;
        }
      }
      return n;
    })()
    "#;
    page.evaluate_json::<i64>(js).await.unwrap_or(0).max(0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_recovery_debug_does_not_expose_ephemeral_values() {
        let state = NativeControlState(
            serde_json::json!({"selected":[{"index":1,"value":"private-option"}]}),
        );
        assert_eq!(format!("{state:?}"), "NativeControlState(<ephemeral>)");
    }

    fn probe_state() -> ProbeState {
        ProbeState::default()
    }

    #[test]
    fn side_effect_snapshot_records_clipboard_without_dom_mutation() {
        let before = probe_state();
        let mut after = probe_state();
        after.clipboard_writes = 1;

        let snapshot = snapshot_with_side_effects(None, None, before, after, None)
            .expect("clipboard write should produce evidence snapshot");

        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.side_effects.len(), 1);
        assert_eq!(snapshot.side_effects[0].kind, "clipboard_write");
        assert_eq!(snapshot.side_effects[0].count, 1);
    }

    #[test]
    fn side_effect_snapshot_records_storage_and_navigation() {
        let before = probe_state();
        let mut after = probe_state();
        after.local_storage_clears = 1;
        after.session_storage_clears = 1;
        after.location_assigns = 1;

        let snapshot = snapshot_with_side_effects(
            Some("https://example.com/diagnostics".to_string()),
            Some("https://example.com/login?cleared=1".to_string()),
            before,
            after,
            None,
        )
        .expect("storage clear + navigation should produce evidence snapshot");

        let kinds = snapshot
            .side_effects
            .iter()
            .map(|effect| effect.kind.as_str())
            .collect::<Vec<_>>();
        assert!(kinds.contains(&"local_storage_clear"));
        assert!(kinds.contains(&"session_storage_clear"));
        assert!(kinds.contains(&"location_assign"));
        assert!(kinds.contains(&"navigation"));
    }

    #[test]
    fn side_effect_snapshot_ignores_about_blank_navigation() {
        let snapshot = snapshot_with_side_effects(
            Some("https://example.com/forgot-password".to_string()),
            Some("about:blank".to_string()),
            probe_state(),
            probe_state(),
            None,
        );

        assert!(snapshot.is_none());
    }
}

async fn is_modal_visible(page: &PageClient) -> bool {
    let js = r#"
    (() => {
        const modal = document.querySelector(
            'dialog[open], [role="dialog"]:not([aria-hidden="true"]), ' +
            '[aria-modal="true"]:not([aria-hidden="true"])'
        );
        return !!modal;
    })()
    "#;
    page.evaluate_json::<bool>(js).await.unwrap_or(false)
}
