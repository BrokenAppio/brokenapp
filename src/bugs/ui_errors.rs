//! Detection of runtime UI error toasts, alerts, and error banners surfaced
//! after a user interaction.
//!
//! Distinguishes unexpected runtime/server/permission error notifications from:
//! - Expected inline form validation messages inside `<form>`
//! - Benign info/success toasts
//! - Generic network-abort toasts caused solely by BrokenApp's write guard

use crate::types::dom::{AppearedText, InteractionSnapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedErrorToast {
    pub message: String,
    pub selector: Option<String>,
}

const RUNTIME_ERROR_PHRASES: &[&str] = &[
    "failed to",
    "could not",
    "couldn't",
    "unable to",
    "not saved",
    "failed saving",
    "save failed",
    "lacks permission",
    "permission denied",
    "access denied",
    "not authorized",
    "unauthorized",
    "forbidden",
    "something went wrong",
    "unexpected error",
    "internal server error",
    "server error",
    "error occurred",
    "an error has occurred",
    "request failed",
    "operation failed",
    "timed out",
    "connection lost",
    "disconnected",
    "service unavailable",
    "rate limit",
];

const INLINE_FORM_VALIDATION_PHRASES: &[&str] = &[
    "is required",
    "are required",
    "field is required",
    "required field",
    "cannot be empty",
    "can't be empty",
    "must not be empty",
    "please enter a valid",
    "enter a valid",
    "invalid email",
    "invalid phone",
    "invalid url",
    "must be at least",
    "must be at most",
    "too short",
    "too long",
    "passwords do not match",
    "passwords must match",
    "please fill out",
    "please select",
];

const WRITE_GUARD_ABORT_PHRASES: &[&str] = &[
    "failed to fetch",
    "network error",
    "networkerror",
    "load failed",
    "err_blocked_by_client",
    "err_failed",
    "err_aborted",
    "unable to connect",
    "could not connect",
    "request failed",
    "offline",
];

const TOAST_SELECTOR_HINTS: &[&str] = &[
    "toast",
    "alert",
    "snackbar",
    "notistack",
    "notification",
    "banner",
    "callout",
    "sonner",
];

/// Extract genuine runtime error toasts/alerts from a post-interaction snapshot.
///
/// `write_guard_blocked` should be true when BrokenApp's write guard blocked an
/// HTTP or WebSocket write during this exact action, so generic fetch/network
/// abort toasts caused by the guard are not falsely reported as application bugs.
pub fn extract_error_toasts(
    snapshot: &InteractionSnapshot,
    side_effects: &[String],
    write_guard_blocked: bool,
) -> Vec<DetectedErrorToast> {
    let had_form_validation = side_effects.iter().any(|s| s == "form_validation");
    let mut candidates: Vec<(String, Option<String>)> = Vec::new();

    for item in &snapshot.appeared_text {
        if !qualifies_as_error_toast(item, had_form_validation, write_guard_blocked) {
            continue;
        }
        let cleaned = clean_toast_message(&item.text);
        if cleaned.len() < 4 {
            continue;
        }
        let selector = (!item.selector.trim().is_empty()).then(|| item.selector.clone());
        candidates.push((cleaned, selector));
    }

    dedupe_toast_messages(candidates)
}

fn qualifies_as_error_toast(
    item: &AppearedText,
    had_form_validation: bool,
    write_guard_blocked: bool,
) -> bool {
    let cleaned = clean_toast_message(&item.text);
    if cleaned.len() < 4 {
        return false;
    }
    let lower = cleaned.to_ascii_lowercase();

    // Never flag explicit success/info notifications unless they also carry an
    // explicit error-action button (e.g. "Copy error").
    if matches!(item.kind.as_str(), "success" | "info") && !item.has_error_action {
        return false;
    }

    // Inline form field validation is expected UX, not a runtime error toast.
    if item.in_form && !item.is_toast && !item.has_error_action {
        return false;
    }
    if had_form_validation && !item.is_toast && !item.has_error_action {
        return false;
    }
    if !item.is_toast
        && !item.has_error_action
        && INLINE_FORM_VALIDATION_PHRASES
            .iter()
            .any(|phrase| lower.contains(phrase))
    {
        return false;
    }

    let sel_lower = item.selector.to_ascii_lowercase();
    let selector_is_toast = TOAST_SELECTOR_HINTS
        .iter()
        .any(|hint| sel_lower.contains(hint));
    let has_runtime_phrase = RUNTIME_ERROR_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase));

    let strong_signal = item.has_error_action
        || (item.kind == "error" && (item.is_toast || selector_is_toast || has_runtime_phrase))
        || (item.is_toast && has_runtime_phrase);

    if !strong_signal {
        return false;
    }

    // If the write guard intentionally blocked this action's mutation and the
    // toast only shows a generic network-abort message, suppress it.
    if write_guard_blocked && is_guard_abort_toast_message(&lower) {
        return false;
    }

    true
}

fn is_guard_abort_toast_message(lower: &str) -> bool {
    // Specific permission/server/validation errors are real app errors even
    // when a sibling request was write-guarded.
    if [
        "lacks permission",
        "permission denied",
        "unauthorized",
        "forbidden",
        "internal server error",
        "500",
    ]
    .iter()
    .any(|real| lower.contains(real))
    {
        return false;
    }
    WRITE_GUARD_ABORT_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase))
}

/// Collapse whitespace and strip trailing toast chrome labels ("Copy error",
/// "Dismiss notification", "Dismiss", "Close") so findings report clean copy.
fn clean_toast_message(raw: &str) -> String {
    let mut text = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    const TRAILING_CHROME: &[&str] = &[
        "dismiss notification",
        "close notification",
        "copy error",
        "report error",
        "dismiss",
        "close",
    ];
    loop {
        let lower = text.to_ascii_lowercase();
        let mut stripped = false;
        for suffix in TRAILING_CHROME {
            if lower.ends_with(suffix) {
                let cut = text.len().saturating_sub(suffix.len());
                let prev = text[..cut].chars().next_back();
                let boundary = cut == 0
                    || prev.is_some_and(|c| {
                        c.is_whitespace()
                            || matches!(c, '.' | '!' | ':' | '|')
                            || (c.is_ascii_lowercase()
                                && text[cut..]
                                    .chars()
                                    .next()
                                    .is_some_and(|n| n.is_ascii_uppercase()))
                    });
                if boundary {
                    text.truncate(cut);
                    text = text.trim_end().trim_end_matches('|').trim_end().to_string();
                    stripped = true;
                    break;
                }
            }
        }
        if !stripped {
            break;
        }
    }
    if text.chars().count() > 280 {
        let mut truncated: String = text.chars().take(280).collect();
        truncated.push('…');
        truncated
    } else {
        text
    }
}

/// Deduplicate overlapping parent/child toast captures from the same action:
/// keep the most informative (longest) distinct message when one is a substring
/// of another.
fn dedupe_toast_messages(mut items: Vec<(String, Option<String>)>) -> Vec<DetectedErrorToast> {
    items.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    let mut kept: Vec<DetectedErrorToast> = Vec::new();
    for (msg, selector) in items {
        let low = msg.to_ascii_lowercase();
        if kept
            .iter()
            .any(|existing| existing.message.to_ascii_lowercase().contains(&low))
        {
            continue;
        }
        kept.push(DetectedErrorToast {
            message: msg,
            selector,
        });
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn appeared(
        selector: &str,
        text: &str,
        kind: &str,
        is_toast: bool,
        in_form: bool,
        has_error_action: bool,
    ) -> AppearedText {
        AppearedText {
            selector: selector.to_string(),
            text: text.to_string(),
            kind: kind.to_string(),
            is_toast,
            in_form,
            has_error_action,
        }
    }

    #[test]
    fn detects_permission_error_toast_and_strips_chrome() {
        let snap = InteractionSnapshot {
            appeared_text: vec![
                appeared(
                    "div[data-slot='toast']",
                    "Setting not saved This connection lacks permission to change these settings. Copy error Dismiss notification",
                    "error",
                    true,
                    false,
                    true,
                ),
                appeared(
                    "div.toast-desc",
                    "This connection lacks permission to change these settings.",
                    "error",
                    true,
                    false,
                    false,
                ),
            ],
            ..Default::default()
        };

        let found = extract_error_toasts(&snap, &[], false);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Setting not saved This connection lacks permission to change these settings."
        );
    }

    #[test]
    fn ignores_inline_form_validation_errors() {
        let snap = InteractionSnapshot {
            appeared_text: vec![
                appeared(
                    "p.field-error",
                    "Email is required",
                    "error",
                    false,
                    true,
                    false,
                ),
                appeared(
                    "span.error",
                    "Please enter a valid email address",
                    "error",
                    false,
                    false,
                    false,
                ),
            ],
            ..Default::default()
        };

        let found = extract_error_toasts(&snap, &["form_validation".to_string()], false);
        assert!(found.is_empty(), "expected no error toasts, got: {found:?}");
    }

    #[test]
    fn ignores_benign_success_toasts() {
        let snap = InteractionSnapshot {
            appeared_text: vec![appeared(
                "div[data-sonner-toast]",
                "Settings saved successfully",
                "success",
                true,
                false,
                false,
            )],
            ..Default::default()
        };

        let found = extract_error_toasts(&snap, &[], false);
        assert!(found.is_empty());
    }

    #[test]
    fn suppresses_generic_network_abort_toast_only_when_write_guarded() {
        let snap = InteractionSnapshot {
            appeared_text: vec![appeared(
                "div[role='alert']",
                "Request failed: Failed to fetch",
                "error",
                true,
                false,
                false,
            )],
            ..Default::default()
        };

        assert!(extract_error_toasts(&snap, &[], true).is_empty());
        assert_eq!(extract_error_toasts(&snap, &[], false).len(), 1);
    }

    #[test]
    fn keeps_permission_error_even_if_write_guard_active_on_sibling() {
        let snap = InteractionSnapshot {
            appeared_text: vec![appeared(
                "div[role='alert']",
                "Setting not saved: This connection lacks permission to change these settings.",
                "error",
                true,
                false,
                true,
            )],
            ..Default::default()
        };

        let found = extract_error_toasts(&snap, &[], true);
        assert_eq!(found.len(), 1);
    }
}
