use regex::Regex;
use std::sync::OnceLock;

/// Convert a concrete URL path into a template suitable for deduping endpoints.
///
/// Heuristics:
/// - numeric segments => `:id`
/// - UUID segments => `:id`
/// - long hex segments => `:id`
pub fn path_to_template(path: &str) -> String {
    // Compiling regexes on every call is surprisingly expensive and this is
    // used in a few hot paths (API surface inference, route templating).
    static UUID_RE: OnceLock<Regex> = OnceLock::new();
    static HEX_RE: OnceLock<Regex> = OnceLock::new();

    let uuid_re = UUID_RE.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .expect("uuid regex")
    });
    let hex_re = HEX_RE.get_or_init(|| Regex::new(r"(?i)^[0-9a-f]{16,}$").expect("hex regex"));

    // Be defensive: callers should pass a path, but if a querystring slips in
    // we should still produce a stable template.
    let path = path.split('?').next().unwrap_or(path);

    let mut out = String::new();
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if seg.is_empty() {
            continue;
        }
        let templ = if seg.chars().all(|c| c.is_ascii_digit()) {
            ":id"
        } else if uuid_re.is_match(seg) {
            ":id"
        } else if hex_re.is_match(seg) {
            ":id"
        } else {
            seg
        };
        out.push_str(templ);
    }
    if out.is_empty() { "/".to_string() } else { out }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_numeric_and_uuid() {
        assert_eq!(path_to_template("/api/contacts/123"), "/api/contacts/:id");
        assert_eq!(
            path_to_template("/api/contacts/550e8400-e29b-41d4-a716-446655440000"),
            "/api/contacts/:id"
        );
    }

    #[test]
    fn templates_long_hex() {
        assert_eq!(
            path_to_template("/api/objects/a1b2c3d4e5f6a1b2c3d4e5f6"),
            "/api/objects/:id"
        );
    }

    #[test]
    fn preserves_literal_segments() {
        assert_eq!(path_to_template("/api/users"), "/api/users");
        assert_eq!(path_to_template("/settings/profile"), "/settings/profile");
    }

    #[test]
    fn mixed_segments() {
        assert_eq!(
            path_to_template("/api/users/42/posts/99"),
            "/api/users/:id/posts/:id"
        );
    }

    #[test]
    fn root_path() {
        assert_eq!(path_to_template("/"), "/");
    }

    #[test]
    fn empty_path() {
        assert_eq!(path_to_template(""), "/");
    }

    #[test]
    fn short_hex_not_parameterized() {
        // Hex strings shorter than 16 chars should NOT be parameterized
        assert_eq!(path_to_template("/api/abc123"), "/api/abc123");
    }

    #[test]
    fn uuid_case_insensitive() {
        assert_eq!(
            path_to_template("/api/items/550E8400-E29B-41D4-A716-446655440000"),
            "/api/items/:id"
        );
    }

    #[test]
    fn deeply_nested_path() {
        assert_eq!(
            path_to_template("/api/v1/orgs/42/teams/99/members/7"),
            "/api/v1/orgs/:id/teams/:id/members/:id"
        );
    }

    #[test]
    fn hex_exactly_16_chars() {
        assert_eq!(
            path_to_template("/api/objects/a1b2c3d4e5f6a1b2"),
            "/api/objects/:id"
        );
    }
}
