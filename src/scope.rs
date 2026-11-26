use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{env, fmt};

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScopesFile {
    /// Named scope definitions.
    ///
    /// TOML example:
    /// ```toml
    /// [scope.checkout]
    /// routes = ["/checkout", "/checkout/*", "/orders/*/confirmation"]
    /// api_endpoints = ["POST /api/orders"]
    /// components = ["checkout_form"]
    /// ```
    #[serde(default)]
    pub scope: BTreeMap<String, ScopeDefinition>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScopeDefinition {
    #[serde(default)]
    pub routes: Vec<String>,
    /// Literal route prefixes excluded even when an include pattern matches.
    /// An exclusion-only scope allows every other route.
    #[serde(default)]
    pub exclude_routes: Vec<String>,
    #[serde(default)]
    pub api_endpoints: Vec<String>,
    #[serde(default)]
    pub components: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScopeFilter {
    pub name: String,
    routes: Vec<RouteMatcher>,
    exclude_routes: Vec<String>,
}

#[derive(Debug, Clone)]
struct RouteMatcher {
    raw: String,
    regex: Regex,
}

impl fmt::Display for ScopeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScopeFilter({})", self.name)
    }
}

impl ScopeFilter {
    pub fn allows_path(&self, path: &str) -> bool {
        let path = normalize_path(path);
        (self.routes.is_empty() || self.routes.iter().any(|m| m.regex.is_match(&path)))
            && !route_is_excluded(&path, &self.exclude_routes)
    }

    /// Return concrete seed paths implied by this scope (patterns without `*` or `:param`).
    pub fn seed_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        for m in &self.routes {
            let p = normalize_path(&m.raw);
            if p.contains('*') {
                continue;
            }
            if p.split('/').any(|seg| seg.starts_with(':')) {
                continue;
            }
            if p.is_empty() {
                continue;
            }
            if !self.allows_path(&p) {
                continue;
            }
            out.push(p);
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn seed_urls(&self, base: &Url) -> Vec<String> {
        self.seed_paths()
            .into_iter()
            .filter_map(|p| base.join(&p).ok().map(|u| u.to_string()))
            .collect()
    }
}

pub fn load_scope_filter(scope_name: &str, scopes_file: Option<&Path>) -> Result<ScopeFilter> {
    let scopes_path = match scopes_file {
        Some(p) => p.to_path_buf(),
        None => default_scopes_file().ok_or_else(|| {
            anyhow::anyhow!(
                "scope {scope_name:?} requested but no scopes file provided and default ./.brokenapp/scopes.toml not found"
            )
        })?,
    };

    let raw = std::fs::read_to_string(&scopes_path)
        .with_context(|| format!("read scopes file {}", scopes_path.display()))?;
    let parsed: ScopesFile =
        toml::from_str(&raw).with_context(|| format!("parse TOML {}", scopes_path.display()))?;

    let def = parsed.scope.get(scope_name).ok_or_else(|| {
        anyhow::anyhow!(
            "scope {scope_name:?} not found in {} (available: {})",
            scopes_path.display(),
            parsed.scope.keys().cloned().collect::<Vec<_>>().join(", ")
        )
    })?;

    let mut routes = Vec::new();
    for r in &def.routes {
        let raw_pat = normalize_path(r);
        if raw_pat.is_empty() {
            continue;
        }
        let regex = compile_route_pattern(&raw_pat)
            .with_context(|| format!("compile route pattern {raw_pat:?}"))?;
        routes.push(RouteMatcher {
            raw: raw_pat,
            regex,
        });
    }

    let exclude_routes: Vec<String> = def
        .exclude_routes
        .iter()
        .map(|r| normalize_path(r))
        .filter(|r| !r.is_empty())
        .collect();
    if routes.is_empty() && exclude_routes.is_empty() {
        anyhow::bail!(
            "scope {scope_name:?} has no routes; add routes=[\"/path\", ...] to your scopes file"
        );
    }

    Ok(ScopeFilter {
        name: scope_name.to_string(),
        routes,
        exclude_routes,
    })
}

fn default_scopes_file() -> Option<PathBuf> {
    let cwd = env::current_dir().ok()?;
    let p = cwd.join(".brokenapp").join("scopes.toml");
    if p.exists() {
        return Some(p);
    }
    let p = cwd.join("scopes.toml");
    if p.exists() {
        return Some(p);
    }
    None
}

fn normalize_path(p: &str) -> String {
    let p = p.trim();
    if p.is_empty() {
        return String::new();
    }
    // Preserve router fragments (including hashbang); ordinary anchors and
    // query values do not select a route scope.
    if p.starts_with("http://") || p.starts_with("https://") {
        if let Ok(u) = Url::parse(p) {
            return normalize_path(&crate::explorer::url_utils::effective_url_path_and_query(&u).0);
        }
    }
    let normalized = match p.split_once('#') {
        Some((path, fragment)) if crate::explorer::url_utils::fragment_is_route(Some(fragment)) => {
            format!(
                "{}/#{}",
                path.split('?').next().unwrap_or(path).trim_end_matches('/'),
                fragment.split('?').next().unwrap_or(fragment)
            )
        }
        _ => p.split(['?', '#']).next().unwrap_or(p).to_string(),
    };
    let p = normalized.as_str();

    if p == "/" {
        return "/".to_string();
    }
    let mut out = p.to_string();
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    while out.ends_with('/') && out.len() > 1 && !out.ends_with("#/") && !out.ends_with("#!/") {
        out.pop();
    }
    out
}

/// Match literal route prefixes on segment boundaries, shared by map seeds,
/// crawl scopes, and inventory coverage. Accepts paths or absolute URLs.
pub fn route_is_excluded(route: &str, excludes: &[String]) -> bool {
    let path = normalize_path(route);
    excludes.iter().map(|r| normalize_path(r)).any(|prefix| {
        !prefix.is_empty()
            && (prefix == "/"
                || path == prefix
                || path.starts_with(&format!("{prefix}/"))
                || ((prefix.ends_with("#/") || prefix.ends_with("#!/"))
                    && path.starts_with(&prefix)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_filter(routes: &[&str]) -> ScopeFilter {
        let mut matchers = Vec::new();
        for r in routes {
            let raw = normalize_path(r);
            let regex = compile_route_pattern(&raw).unwrap();
            matchers.push(RouteMatcher { raw, regex });
        }
        ScopeFilter {
            name: "test".to_string(),
            routes: matchers,
            exclude_routes: Vec::new(),
        }
    }

    #[test]
    fn exact_path_matches() {
        let f = make_filter(&["/checkout"]);
        assert!(f.allows_path("/checkout"));
        assert!(!f.allows_path("/settings"));
        assert!(!f.allows_path("/checkout/step1"));
    }

    #[test]
    fn single_wildcard_matches_one_segment() {
        let f = make_filter(&["/orders/*/confirmation"]);
        assert!(f.allows_path("/orders/123/confirmation"));
        assert!(f.allows_path("/orders/abc/confirmation"));
        assert!(!f.allows_path("/orders/confirmation"));
        assert!(!f.allows_path("/orders/123/456/confirmation"));
    }

    #[test]
    fn double_wildcard_matches_remainder() {
        let f = make_filter(&["/admin/**"]);
        assert!(f.allows_path("/admin/users"));
        assert!(f.allows_path("/admin/users/123"));
        assert!(f.allows_path("/admin/users/123/edit"));
        assert!(!f.allows_path("/settings"));
    }

    #[test]
    fn param_segment_matches_one() {
        let f = make_filter(&["/users/:id/profile"]);
        assert!(f.allows_path("/users/42/profile"));
        assert!(f.allows_path("/users/abc/profile"));
        assert!(!f.allows_path("/users/42/settings"));
        assert!(!f.allows_path("/users/profile"));
    }

    #[test]
    fn multiple_routes_any_matches() {
        let f = make_filter(&["/checkout", "/cart", "/orders/**"]);
        assert!(f.allows_path("/checkout"));
        assert!(f.allows_path("/cart"));
        assert!(f.allows_path("/orders/123"));
        assert!(!f.allows_path("/settings"));
    }

    #[test]
    fn trailing_slash_is_stripped() {
        let f = make_filter(&["/checkout/"]);
        assert!(f.allows_path("/checkout"));
        assert!(f.allows_path("/checkout/"));
    }

    #[test]
    fn leading_slash_is_added() {
        let f = make_filter(&["checkout"]);
        assert!(f.allows_path("/checkout"));
    }

    #[test]
    fn query_and_hash_stripped() {
        let f = make_filter(&["/settings"]);
        assert!(f.allows_path("/settings?tab=general"));
        assert!(f.allows_path("/settings#section"));
    }

    #[test]
    fn full_url_path_extraction() {
        let f = make_filter(&["/settings"]);
        assert!(f.allows_path("https://example.com/settings"));
        assert!(f.allows_path("https://example.com/settings?foo=bar"));
    }

    #[test]
    fn root_path_matches() {
        let f = make_filter(&["/"]);
        assert!(f.allows_path("/"));
        assert!(!f.allows_path("/anything"));
    }

    #[test]
    fn seed_paths_excludes_wildcards_and_params() {
        let f = make_filter(&[
            "/checkout",
            "/orders/*",
            "/users/:id/profile",
            "/admin/**",
            "/settings",
        ]);
        let seeds = f.seed_paths();
        assert_eq!(seeds, vec!["/checkout", "/settings"]);
    }

    #[test]
    fn seed_urls_constructs_full_urls() {
        let f = make_filter(&["/checkout", "/admin/**", "/settings"]);
        let base = Url::parse("https://example.com").unwrap();
        let urls = f.seed_urls(&base);
        assert_eq!(
            urls,
            vec![
                "https://example.com/checkout",
                "https://example.com/settings",
            ]
        );
    }

    #[test]
    fn regex_special_chars_escaped_in_literal_segments() {
        let f = make_filter(&["/api/v1.0/data"]);
        assert!(f.allows_path("/api/v1.0/data"));
        assert!(!f.allows_path("/api/v1X0/data")); // dot should be literal, not regex wildcard
    }

    #[test]
    fn normalize_path_empty_and_edge_cases() {
        assert_eq!(normalize_path(""), "");
        assert_eq!(normalize_path("  "), "");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("///"), "/");
    }

    #[test]
    fn exclusion_only_scope_filters_prefixes_without_creating_seeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scopes.toml");
        std::fs::write(
            &path,
            "[scope.test]\nexclude_routes = [\"/private\", \"/#/billing\", \"/#!/admin\"]\n",
        )
        .unwrap();
        let f = load_scope_filter("test", Some(&path)).unwrap();
        assert!(f.seed_paths().is_empty());
        for allowed in [
            "/",
            "/public",
            "/privateer",
            "http://local.test/#/public",
            "/#!/admins",
        ] {
            assert!(f.allows_path(allowed), "{allowed}");
        }
        for excluded in [
            "/private",
            "/private/nested?x=1",
            "http://local.test/private#section",
            "http://local.test/#/billing?tab=payments",
            "/#/billing/invoices",
            "http://local.test/#!/admin/users",
        ] {
            assert!(!f.allows_path(excluded), "{excluded}");
        }
        std::fs::write(&path, "[scope.test]\nroutes = [\"/private\", \"/public\", \"/#/billing\"]\nexclude_routes = [\"/private\", \"/#/billing\"]\n").unwrap();
        let f = load_scope_filter("test", Some(&path)).unwrap();
        assert_eq!(f.seed_paths(), ["/public"]);
        assert!(!f.allows_path("/other"));
        assert!(!f.allows_path("/private"));
        assert!(!f.allows_path("http://local.test/#/billing"));
    }

    #[test]
    fn hash_scopes_keep_router_paths_and_ordinary_anchor_compatibility() {
        for prefix in ["/#/", "/#!/"] {
            assert!(!route_is_excluded("/", &[prefix.into()]));
            assert!(route_is_excluded(
                &format!("{prefix}account"),
                &[prefix.into()]
            ));
            assert!(make_filter(&[prefix]).allows_path(&format!("http://local.test{prefix}")));
        }
        for route in ["/#/account", "/#!/account"] {
            let f = make_filter(&[route]);
            assert!(f.allows_path(&format!("http://local.test{route}?tab=payout")));
            assert!(!f.allows_path("http://local.test/"));
            assert!(!f.allows_path("http://local.test/#/other"));
        }
        assert!(make_filter(&["/settings"]).allows_path("/settings#details"));
        for (route, url) in [
            ("/app/#/dev", "http://local.test/app#/dev?tab=x"),
            ("/app/#!/dev", "http://local.test/app#!/dev"),
        ] {
            assert!(make_filter(&[route]).allows_path(url));
            assert!(route_is_excluded(url, &[route.into()]));
        }
        assert!(route_is_excluded(
            "http://local.test/anything",
            &["/".into()]
        ));
    }

    #[test]
    fn alternate_router_fragments_do_not_turn_exclusions_into_root_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scopes.toml");
        for route in ["/#admin/users", "/#!admin"] {
            std::fs::write(
                &path,
                format!("[scope.test]\nexclude_routes = [\"{route}\"]\n"),
            )
            .unwrap();
            let excluded = load_scope_filter("test", Some(&path)).unwrap();
            let included = make_filter(&[route]);
            for target in [
                route.to_string(),
                format!("http://local.test{route}?tab=details"),
            ] {
                assert!(included.allows_path(&target), "{target}");
                assert!(!excluded.allows_path(&target), "{target}");
            }
            assert!(!excluded.allows_path(&format!("http://local.test{route}/nested")));
            for allowed in ["/", "/public", "/#/public", "/#other/users", "/#!public"] {
                assert!(excluded.allows_path(allowed), "{route} excluded {allowed}");
                assert!(!included.allows_path(allowed), "{route} included {allowed}");
            }
            assert!(excluded.allows_path(&format!("{route}-other")));
        }
    }
}

fn compile_route_pattern(pattern: &str) -> Result<Regex> {
    // Segment-based glob:
    // - `*` matches exactly one path segment
    // - `**` matches any remainder (including '/')
    // - `:param` matches one path segment
    let mut out = String::from("^");
    let mut first = true;
    for seg in pattern.split('/') {
        if first {
            first = false;
            // leading empty segment from "/"
            continue;
        }
        out.push('/');
        if seg.is_empty() {
            continue;
        }
        if seg == "**" {
            out.push_str(".*");
            continue;
        }
        if seg == "*" {
            out.push_str("[^/]+");
            continue;
        }
        if seg.starts_with(':') && seg.len() > 1 {
            out.push_str("[^/]+");
            continue;
        }

        let mut seg_re = String::new();
        for ch in seg.chars() {
            match ch {
                '*' => seg_re.push_str("[^/]*"),
                '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' | '?' => {
                    seg_re.push('\\');
                    seg_re.push(ch);
                }
                _ => seg_re.push(ch),
            }
        }
        out.push_str(&seg_re);
    }
    out.push('$');
    Ok(Regex::new(&out).context("build regex")?)
}

/// Public helper: match a path against BrokenApp's segment-based glob rules.
///
/// This is used by report generators to apply user-specified ignore/note rules.
pub fn path_matches_pattern(pattern: &str, path: &str) -> bool {
    let raw = normalize_path(pattern);
    if raw.is_empty() {
        return false;
    }
    let Ok(re) = compile_route_pattern(&raw) else {
        return false;
    };
    let p = normalize_path(path);
    re.is_match(&p)
}
