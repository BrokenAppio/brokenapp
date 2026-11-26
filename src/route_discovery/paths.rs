//! Route path helpers shared by every framework adapter.
//!
//! Canonical form: leading `/`, no trailing `/` (except the root), dynamic
//! segments as `:name`, optional `:name?`, catch-alls `:name*` (zero or more)
//! and `:name+` (one or more), splats `*`.

/// Joins a child route path onto its parent. Absolute children (`/x`) replace
/// the parent, relative children append.
pub(crate) fn join(parent: &str, child: &str) -> String {
    let child = child.trim();
    if child.starts_with('/') {
        return normalize(child);
    }
    if child.is_empty() {
        return normalize(parent);
    }
    normalize(&format!("{}/{}", parent.trim_end_matches('/'), child))
}

/// Collapses duplicate slashes and trims the trailing slash.
pub(crate) fn normalize(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

pub(crate) fn from_segments<I, S>(segments: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = String::new();
    for seg in segments {
        let seg = seg.as_ref();
        if seg.is_empty() {
            continue;
        }
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() { "/".to_string() } else { out }
}

fn is_dynamic_segment(seg: &str) -> bool {
    seg.starts_with(':') || seg.contains('*') || seg.ends_with('?')
}

/// True when any segment needs a runtime value.
pub(crate) fn is_dynamic(path: &str) -> bool {
    path.split('/').any(is_dynamic_segment)
}

/// The concrete path left after dropping optional segments (`:x?`, `:x*`,
/// `en?`), when nothing dynamic remains. `/admin/:section*` -> `/admin`.
pub(crate) fn concrete_variant(path: &str) -> Option<String> {
    let kept: Vec<&str> = path
        .split('/')
        .filter(|s| !(s.is_empty() || s.ends_with('?') || (s.starts_with(':') && s.ends_with('*'))))
        .collect();
    let candidate = from_segments(kept);
    (!is_dynamic(&candidate)).then_some(candidate)
}

/// Bracket segment syntax used by Next, Astro, SvelteKit and Nuxt.
/// `[id]` -> `:id`, `[[id]]` -> `:id?`, `[...slug]` -> `:slug+` (or `:slug*`
/// when `rest_optional`), `[[...slug]]` -> `:slug*`, `[id=matcher]` -> `:id`.
/// Mixed segments (`post-[id]`) keep their literal parts.
pub(crate) fn bracket_segment(seg: &str, rest_optional: bool) -> String {
    if let Some(inner) = seg.strip_prefix("[[...").and_then(|s| s.strip_suffix("]]")) {
        return format!(":{}*", param_name(inner));
    }
    if let Some(inner) = seg.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
        return format!(":{}?", param_name(inner));
    }
    if let Some(inner) = seg.strip_prefix("[...").and_then(|s| s.strip_suffix(']')) {
        let suffix = if rest_optional { '*' } else { '+' };
        return format!(":{}{suffix}", param_name(inner));
    }
    if !seg.contains('[') {
        return seg.to_string();
    }
    // Replace every `[name]` occurrence.
    let mut out = String::new();
    let mut rest = seg;
    while let Some(open) = rest.find('[') {
        out.push_str(&rest[..open]);
        match rest[open..].find(']') {
            Some(close) => {
                let inner = &rest[open + 1..open + close];
                out.push(':');
                out.push_str(&param_name(inner));
                rest = &rest[open + close + 1..];
            }
            None => {
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn param_name(inner: &str) -> String {
    let inner = inner.trim_start_matches("...");
    inner.split('=').next().unwrap_or(inner).trim().to_string()
}

/// Normalizes router-config param syntax: `:id(\\d+)` -> `:id`,
/// Hono `:id{[0-9]+}` -> `:id`, Vue `:pathMatch(.*)*` -> `:pathMatch*`.
pub(crate) fn clean_param_syntax(path: &str) -> String {
    let segments: Vec<String> = path
        .split('/')
        .map(|seg| {
            if !seg.starts_with(':') {
                return seg.to_string();
            }
            let name_end = seg[1..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '-'))
                .map_or(seg.len(), |i| i + 1);
            let name = &seg[..name_end];
            let rest = &seg[name_end..];
            let modifier = rest
                .chars()
                .last()
                .filter(|c| matches!(c, '?' | '*' | '+'))
                .map(String::from)
                .unwrap_or_default();
            format!("{name}{modifier}")
        })
        .collect();
    segments.join("/")
}

/// Wildcard-only paths are fallbacks (404 pages, middleware), not routes.
pub(crate) fn is_wildcard_only(path: &str) -> bool {
    let trimmed = path.trim_matches('/');
    matches!(trimmed, "*" | "**" | "*splat")
        || (trimmed.starts_with(':') && trimmed.ends_with('*') && !trimmed.contains('/'))
}

/// Normalizes a configured base path: `"/app/"` -> `"/app"`, `"/"` -> `""`.
pub(crate) fn normalize_base(raw: &str) -> String {
    let raw = raw.trim();
    if !raw.starts_with('/') {
        return String::new();
    }
    let n = normalize(raw);
    if n == "/" { String::new() } else { n }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_relative_and_absolute_children() {
        assert_eq!(join("/", "about"), "/about");
        assert_eq!(join("/admin", "users"), "/admin/users");
        assert_eq!(join("/admin", "/settings"), "/settings");
        assert_eq!(join("/admin/", ""), "/admin");
        assert_eq!(join("", ""), "/");
    }

    #[test]
    fn converts_bracket_segments() {
        assert_eq!(bracket_segment("[id]", false), ":id");
        assert_eq!(bracket_segment("[...slug]", false), ":slug+");
        assert_eq!(bracket_segment("[...slug]", true), ":slug*");
        assert_eq!(bracket_segment("[[...slug]]", false), ":slug*");
        assert_eq!(bracket_segment("[[lang]]", false), ":lang?");
        assert_eq!(bracket_segment("[id=integer]", false), ":id");
        assert_eq!(bracket_segment("post-[id]", false), "post-:id");
    }

    #[test]
    fn concrete_variants_drop_optional_segments() {
        assert_eq!(
            concrete_variant("/admin/:section*").as_deref(),
            Some("/admin")
        );
        assert_eq!(concrete_variant("/:lang?/about").as_deref(), Some("/about"));
        assert_eq!(concrete_variant("/posts/:id"), None);
        assert_eq!(concrete_variant("/docs/:slug+"), None);
    }

    #[test]
    fn cleans_param_syntax() {
        assert_eq!(clean_param_syntax("/users/:id(\\d+)"), "/users/:id");
        assert_eq!(clean_param_syntax("/p/:id{[0-9]+}"), "/p/:id");
        assert_eq!(clean_param_syntax("/:pathMatch(.*)*"), "/:pathMatch*");
        assert_eq!(clean_param_syntax("/:lang?/x"), "/:lang?/x");
        assert!(is_wildcard_only("/:pathMatch*"));
        assert!(is_wildcard_only("*"));
        assert!(!is_wildcard_only("/files/*"));
    }

    #[test]
    fn normalizes_base_paths() {
        assert_eq!(normalize_base("/app/"), "/app");
        assert_eq!(normalize_base("/"), "");
        assert_eq!(normalize_base("./"), "");
    }
}
