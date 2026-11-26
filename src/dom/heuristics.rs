//! DOM-level heuristics for identifying mutation / submit actions.
//!
//! We keep these rules small and opinionated because they are used to gate
//! potentially mutating clicks when `submit_forms=false`, and to prioritize
//! "Save/Update/Create" actions when mutation harvesting is enabled.

fn normalize_label(label: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for ch in label.chars() {
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        prev_space = false;
        out.push(ch.to_ascii_lowercase());
    }
    out.trim().to_string()
}

fn starts_with_word(hay: &str, word: &str) -> bool {
    hay == word || hay.starts_with(&format!("{word} "))
}

pub fn is_destructive_mutation_label(label: Option<&str>) -> bool {
    let Some(label) = label else { return false };
    let t = normalize_label(label);
    if t.is_empty() {
        return false;
    }

    // Treat unlink/detach/archive/etc as destructive-ish mutations. These are
    // skipped by default unless `interact_with_delete_buttons=true`.
    let destructive = [
        "delete",
        "remove",
        "destroy",
        "archive",
        "revoke",
        "detach",
        "unlink",
        "end ownership",
        "log out",
        "logout",
        "sign out",
    ];
    destructive.iter().any(|w| starts_with_word(&t, w))
}

pub fn is_submit_mutation_label(label: Option<&str>) -> bool {
    let Some(label) = label else { return false };
    let t = normalize_label(label);
    if t.is_empty() {
        return false;
    }

    // Safe-ish mutation verbs that commonly correspond to a primary "submit"
    // action on a form-like container.
    let good = [
        "save",
        "update",
        "create",
        "submit",
        "apply",
        "send",
        "invite",
        "import",
        "export",
        "enable",
        "disable",
        "activate",
        "deactivate",
        "approve",
        "accept",
        "reject",
        "close deal",
    ];
    good.iter().any(|w| starts_with_word(&t, w))
}

pub fn is_bad_submit_label(label: Option<&str>) -> bool {
    let Some(label) = label else { return true };
    let t = normalize_label(label);
    if t.is_empty() {
        return true;
    }

    // Pagination labels are not submit buttons.
    if is_pagination_label(Some(label)) {
        return true;
    }

    // Controls that are commonly mis-detected as submit buttons.
    let bad = ["reset", "sort", "sort by", "close", "cancel", "back"];
    bad.iter().any(|w| starts_with_word(&t, w))
}

/// Returns true for labels that indicate a pagination/data-loading control.
pub fn is_pagination_label(label: Option<&str>) -> bool {
    let Some(label) = label else { return false };
    let t = normalize_label(label);
    if t.is_empty() {
        return false;
    }

    let pagination_patterns = [
        "load more",
        "show more",
        "view more",
        "see more",
        "more results",
        "next",
        "previous",
        "prev",
        "next page",
        "prev page",
        "previous page",
    ];
    if pagination_patterns.iter().any(|w| starts_with_word(&t, w)) {
        return true;
    }

    // "page 1", "page 2 of 10"
    if let Some(rest) = t.strip_prefix("page ") {
        let first = rest.split_whitespace().next().unwrap_or("");
        if !first.is_empty() && first.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    false
}

/// Lower is higher priority.
pub fn submit_priority(label: Option<&str>) -> i64 {
    if is_bad_submit_label(label) {
        return 10_000;
    }

    let Some(label) = label else { return 9_000 };
    let t = normalize_label(label);
    if t.is_empty() {
        return 9_000;
    }

    // Prefer "Save" style actions first; fall back to other mutation verbs.
    if starts_with_word(&t, "save") {
        return 0;
    }
    if starts_with_word(&t, "update") {
        return 10;
    }
    if starts_with_word(&t, "create") {
        return 20;
    }
    if starts_with_word(&t, "submit") {
        return 30;
    }
    if starts_with_word(&t, "apply") {
        return 40;
    }
    if starts_with_word(&t, "send") {
        return 50;
    }
    if starts_with_word(&t, "invite") {
        return 60;
    }
    if starts_with_word(&t, "import") {
        return 70;
    }
    if starts_with_word(&t, "export") {
        return 80;
    }
    if is_destructive_mutation_label(Some(t.as_str())) {
        return 500;
    }

    1_000
}
