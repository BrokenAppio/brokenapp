use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::types::dom::ElementType;
use crate::types::graph::AppView;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub views_discovered: usize,
    pub views_explored: usize,
    pub elements_discovered: usize,
    pub elements_interacted: usize,
    pub api_endpoints_discovered: usize,
    pub coverage_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    Route,
    SeededRoute,
    Interaction,
    StopCondition,
    OrphanNavItem,
    /// A DOM mutation (modal/tab/accordion) that was not explored due to
    /// depth limits, dismiss failure, or budget exhaustion.
    UnexploredMutation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    pub kind: CoverageGapKind,
    pub target: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageGapSummary {
    pub total: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_reason: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageGapReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<CoverageGap>,
    pub summary: CoverageGapSummary,
}

pub fn detect_seeded_route_gaps(
    seeded_routes: &BTreeMap<String, Vec<String>>,
    visited_urls: &HashSet<String>,
    attempted_urls: &HashSet<String>,
    base_url: &Url,
) -> Vec<CoverageGap> {
    let visited: HashSet<String> = visited_urls
        .iter()
        .map(|url| super::url_utils::canonicalize_crawl_url(url))
        .collect();
    let attempted: HashSet<String> = attempted_urls
        .iter()
        .map(|url| super::url_utils::canonicalize_crawl_url(url))
        .collect();
    let mut gaps = Vec::new();

    for (target, sources) in seeded_routes {
        let canonical = super::url_utils::canonicalize_crawl_url(target);
        if visited.contains(&canonical) {
            continue;
        }

        let reason = if attempted.contains(&canonical) {
            "seed_route_attempted_without_view"
        } else {
            "seed_route_not_reached"
        };
        let route_template = Url::parse(&canonical)
            .ok()
            .filter(|url| super::url_utils::same_origin(base_url, url))
            .map(|url| {
                let (route_path, _) = super::url_utils::effective_url_path_and_query(&url);
                crate::network::path_parameterizer::path_to_template(&route_path)
            })
            .unwrap_or_else(|| "(unknown)".to_string());
        let source = sources.join(",");

        gaps.push(CoverageGap {
            kind: CoverageGapKind::SeededRoute,
            target: canonical,
            reason: reason.to_string(),
            context: Some(format!("source={source} route_template={route_template}")),
        });
    }

    gaps
}

pub(super) fn summarize(
    views_discovered: usize,
    views_explored: usize,
    elements_discovered: usize,
    elements_interacted: usize,
    api_endpoints_discovered: usize,
) -> CoverageSummary {
    let coverage_percentage = if elements_discovered == 0 {
        0.0
    } else {
        (elements_interacted as f64 / elements_discovered as f64) * 100.0
    };

    CoverageSummary {
        views_discovered,
        views_explored,
        elements_discovered,
        elements_interacted,
        api_endpoints_discovered,
        coverage_percentage,
    }
}

/// Detect nav items (links and dropdown triggers inside `<nav>`) that were
/// discovered during crawling but whose target URLs were never visited.
pub fn detect_orphan_nav_items(
    views: &[AppView],
    url_to_view: &HashMap<String, String>,
    expanded_nav_dropdown_triggers: &HashSet<String>,
    base_url: &Url,
) -> Vec<CoverageGap> {
    let mut gaps = Vec::new();
    let mut seen_hrefs = std::collections::HashSet::new();
    let visited_canonical: HashSet<String> = url_to_view
        .keys()
        .map(|u| super::url_utils::canonicalize_crawl_url(u))
        .collect();

    for view in views {
        for el in &view.elements {
            // Check navigation links inside nav regions.
            if let ElementType::NavigationLink {
                href: Some(href),
                in_nav,
            } = &el.element_type
            {
                if !*in_nav {
                    continue;
                }
                let abs_url = match super::url_utils::normalize_href(
                    base_url,
                    Url::parse(&view.url).ok().as_ref(),
                    href,
                ) {
                    Some(u) => u.to_string(),
                    None => continue,
                };

                if !seen_hrefs.insert(abs_url.clone()) {
                    continue;
                }

                if !visited_canonical.contains(&abs_url) {
                    let reason = if crate::dom::heuristics::is_destructive_mutation_label(
                        el.label.as_deref(),
                    ) {
                        "nav_link_skipped_destructive_label"
                    } else {
                        "nav_link_not_visited"
                    };
                    gaps.push(CoverageGap {
                        kind: CoverageGapKind::OrphanNavItem,
                        target: abs_url,
                        reason: reason.to_string(),
                        context: Some(format!(
                            "view={} label={}",
                            view.id,
                            el.label.as_deref().unwrap_or("(none)")
                        )),
                    });
                }
            }

            // Dropdown menus with no href are potential unexpanded triggers.
            if let ElementType::DropdownMenu { in_nav: true } = &el.element_type {
                let key = format!("{}::{}", view.id, el.selector);
                if expanded_nav_dropdown_triggers.contains(&key) {
                    continue;
                }
                gaps.push(CoverageGap {
                    kind: CoverageGapKind::OrphanNavItem,
                    target: el.selector.clone(),
                    reason: "unexpanded_dropdown_trigger".to_string(),
                    context: Some(format!(
                        "view={} label={}",
                        view.id,
                        el.label.as_deref().unwrap_or("(none)")
                    )),
                });
            }
        }
    }

    gaps
}

pub fn summarize_gaps(mut items: Vec<CoverageGap>) -> CoverageGapReport {
    // Keep output deterministic for easier diffs between runs.
    items.sort_by(|a, b| {
        a.reason
            .cmp(&b.reason)
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.context.cmp(&b.context))
    });
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for item in &items {
        *by_reason.entry(item.reason.clone()).or_insert(0) += 1;
    }
    CoverageGapReport {
        summary: CoverageGapSummary {
            total: items.len(),
            by_reason,
        },
        items,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use super::*;

    #[test]
    fn seeded_route_gaps_explain_routes_not_reached_by_runtime_scan() {
        let base = Url::parse("https://app.example.com/").unwrap();
        let seeded_routes = BTreeMap::from([
            (
                "https://app.example.com/staff/deals".to_string(),
                vec!["seed_routes_file:routes.json".to_string()],
            ),
            (
                "https://app.example.com/staff/tasks".to_string(),
                vec!["scan.seed_urls".to_string()],
            ),
        ]);
        let visited = HashSet::from(["https://app.example.com/staff/tasks".to_string()]);
        let attempted = HashSet::new();

        let gaps = detect_seeded_route_gaps(&seeded_routes, &visited, &attempted, &base);

        assert_eq!(gaps.len(), 1);
        assert!(matches!(gaps[0].kind, CoverageGapKind::SeededRoute));
        assert_eq!(gaps[0].target, "https://app.example.com/staff/deals");
        assert_eq!(gaps[0].reason, "seed_route_not_reached");
        assert_eq!(
            gaps[0].context.as_deref(),
            Some("source=seed_routes_file:routes.json route_template=/staff/deals")
        );
    }
}
