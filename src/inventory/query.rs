//! Control filters for `brokenapp ui`.

use std::collections::BTreeSet;

use super::evidence;
use super::identity::{
    query_route_parts, route_matches, route_request_is_specific, route_variant_matches,
    select_routes,
};
use super::journey::endpoint_matches;
use super::render::describe_does;
use super::{Control, ControlStateEntryKind, ControlStatus, Inventory};

/// Filters; `None` matches everything.
#[derive(Debug, Clone, Default)]
pub struct ControlFilter {
    /// Route prefix; `*` selects global (shell) controls.
    pub route: Option<String>,
    /// Select only the matched route/template, without its descendants.
    pub exact_route: bool,
    /// Omit shared controls and controls in shell landmarks.
    pub exclude_shell: bool,
    /// Case-insensitive substring of the label (or any grouped member's
    /// label), locator, selector, or what it does.
    pub text: Option<String>,
    pub status: Option<ControlStatus>,
    /// Endpoint (`POST /api/orders`, `/api/orders`).
    pub calls: Option<String>,
    pub role: Option<String>,
}

impl ControlFilter {
    /// Match one control without inventory context. This retains path/template
    /// and prefix matching, but cannot establish exact-route priority or whether
    /// a requested record/query variant was visited. UI queries must use `apply`.
    pub fn matches(&self, c: &Control) -> bool {
        let route_matches = self.route.as_deref().is_none_or(|route| {
            if route == "*" {
                c.route == "*"
            } else if c.route == "*" {
                c.routes.iter().any(|r| self.matches_route(r, route))
            } else {
                self.matches_route(&c.route, route)
            }
        });
        route_matches && self.matches_details(c)
    }

    fn matches_route(&self, route: &str, request: &str) -> bool {
        route_matches(route, request)
            || (!self.exact_route && route_prefix_selected(route, request))
    }

    fn matches_details(&self, c: &Control) -> bool {
        if self.exclude_shell && evidence::is_shell(c) {
            return false;
        }
        if self.status.is_some_and(|st| c.status != st) {
            return false;
        }
        if self
            .role
            .as_deref()
            .is_some_and(|role| !c.role.eq_ignore_ascii_case(role))
        {
            return false;
        }
        if let Some(calls) = self.calls.as_deref() {
            let (method, path) = split_endpoint(calls);
            if !c.endpoints().any(|e| endpoint_matches(e, method, path)) {
                return false;
            }
        }
        if let Some(text) = self.text.as_deref() {
            let needle = text.to_lowercase();
            let hay = [c.locator.as_str(), c.selector.as_str(), c.key.as_str()];
            if !c.label_contains(&needle)
                && !hay.iter().any(|h| h.to_lowercase().contains(&needle))
                && !describe_does(c).to_lowercase().contains(&needle)
            {
                return false;
            }
        }
        true
    }

    pub fn apply<'a>(&self, inv: &'a Inventory) -> Vec<&'a Control> {
        let Some(request) = self.route.as_deref() else {
            return inv
                .controls
                .iter()
                .filter(|c| self.matches_details(c))
                .collect();
        };
        if request == "*" {
            return inv
                .controls
                .iter()
                .filter(|c| c.route == "*" && self.matches_details(c))
                .collect();
        }
        let selected: BTreeSet<&str> = self.selected_routes(inv).into_iter().collect();
        inv.controls
            .iter()
            .filter(|c| {
                self.matches_details(c)
                    && c.present_on().iter().any(|route| {
                        selected.contains(route) && control_matches_state(inv, c, route, request)
                    })
            })
            .collect()
    }

    /// Matched route contexts, including routes with no matching controls.
    /// A concrete/query request may select a template context even when that
    /// requested state was not observed; `apply` still enforces state evidence.
    pub fn selected_routes<'a>(&self, inv: &'a Inventory) -> Vec<&'a str> {
        let candidates: BTreeSet<&str> = inv
            .routes
            .iter()
            .map(|r| r.route.as_str())
            .chain(inv.controls.iter().flat_map(|c| c.present_on()))
            .filter(|r| *r != "*")
            .collect();
        let Some(request) = self.route.as_deref() else {
            return candidates.into_iter().collect();
        };
        if request == "*" {
            return inv
                .controls
                .iter()
                .filter(|c| c.route == "*")
                .flat_map(|c| c.present_on())
                .filter(|r| *r != "*")
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        }
        let mut selected: BTreeSet<&str> = select_routes(candidates.iter().copied(), request)
            .into_iter()
            .collect();
        if !self.exact_route {
            selected.extend(
                candidates
                    .into_iter()
                    .filter(|r| route_prefix_selected(r, request)),
            );
        }
        selected.into_iter().collect()
    }

    /// Whether a requested record/query state was observed, independently of
    /// text/status/kind filters. `None` means this is a route-level query.
    /// Presence never proves navigation to or business behavior in that state.
    pub fn requested_state_observed(&self, inv: &Inventory) -> Option<bool> {
        let request = self.route.as_deref().filter(|r| *r != "*")?;
        let selected = self.selected_routes(inv);
        let specific = query_route_parts(request).1.is_some()
            || selected.iter().any(|route| {
                route_matches(route, request) && route_request_is_specific(request, route)
            });
        specific.then(|| {
            selected
                .iter()
                .any(|route| observed_state(inv, route, request))
        })
    }
}

/// Route filter: exact or template match (`/products/42` selects
/// `/products/:id`), or a path-segment prefix (`/admin` selects
/// `/admin/users`; `/#/` selects every hash route). `/` selects only `/`.
pub fn route_selected(route: &str, filter: &str) -> bool {
    route_matches(route, filter) || route_prefix_selected(route, filter)
}

fn route_prefix_selected(route: &str, filter: &str) -> bool {
    let (path, query) = query_route_parts(filter);
    if query.is_some() {
        return false;
    }
    let base = path.trim_end_matches('/');
    !base.is_empty() && query_route_parts(route).0.starts_with(&format!("{base}/"))
}

fn control_matches_state(inv: &Inventory, c: &Control, route: &str, request: &str) -> bool {
    if !route_matches(route, request) || !route_request_is_specific(request, route) {
        // Descendants selected by a path prefix are not concrete instances of
        // that prefix, even when the descendant itself is parameterized.
        return true;
    }
    // Shared controls apply only to states actually observed on this route,
    // not every possible query or concrete record matching its template.
    if !observed_state(inv, route, request) {
        return false;
    }
    if !c.state_entries.is_empty() {
        // Mixed direct and opened states cannot be flattened into an empty
        // variants wildcard. Keep each observed route/variant paired; a plain
        // route entry does not prove presence on another record or query state.
        return c.state_entries.iter().any(|entry| {
            entry.route == route
                && !matches!(entry.kind, ControlStateEntryKind::Unknown)
                && entry
                    .variant
                    .as_deref()
                    .is_some_and(|v| route_variant_matches(route, v, request))
        });
    }
    c.variants.is_empty()
        || c.variants
            .iter()
            .any(|v| route_variant_matches(route, v, request))
}

fn observed_state(inv: &Inventory, route: &str, request: &str) -> bool {
    inv.routes.iter().any(|r| {
        r.route == route
            && r.visited
            && r.variants
                .iter()
                .any(|v| route_variant_matches(route, v, request))
    })
}

/// `"POST /api/x"` -> `(Some("POST"), "/api/x")`; `"/api/x"` -> `(None, "/api/x")`.
pub fn split_endpoint(s: &str) -> (Option<&str>, &str) {
    let s = s.trim();
    match s.split_once(char::is_whitespace) {
        Some((m, rest)) if m.chars().all(|c| c.is_ascii_alphabetic()) => (Some(m), rest.trim()),
        _ => (None, s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_filter_semantics() {
        assert!(route_selected("/admin/users", "/admin"));
        assert!(route_selected("/admin", "/admin/"));
        assert!(!route_selected("/administrator", "/admin"));
        assert!(route_selected("/products/:id", "/products/42"));
        assert!(route_selected("/#/search", "/#/"));
        assert!(route_selected("/", "/"));
        assert!(!route_selected("/about", "/"));
    }

    #[test]
    fn endpoint_split() {
        assert_eq!(split_endpoint("POST /api/x"), (Some("POST"), "/api/x"));
        assert_eq!(split_endpoint("/api/x"), (None, "/api/x"));
    }
}
