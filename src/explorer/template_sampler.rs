use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::network::path_parameterizer::path_to_template;

#[derive(Debug, Clone)]
pub enum TemplateVisitDecision {
    Visit,
    Skip {
        template: String,
        reason: String,
        /// True if this decision caused the template to transition to saturated.
        saturated_now: bool,
    },
}

/// Tracks sampling state for parameterized route templates (e.g. `/clients/:id/overview`).
///
/// Goal: avoid spending minutes visiting hundreds of UUID instances that all
/// fingerprint to the same view, while still discovering meaningful layout
/// variants driven by data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemplateSampler {
    pub templates: HashMap<String, TemplateSamplingState>,
    /// Sampling state of route templates known from source (`/towns/:slug`).
    /// Kept apart from `templates`: those also shape `spec.json` (one
    /// templated view per `:id` template), these only pace the crawl.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub source_templates: HashMap<String, TemplateSamplingState>,
    /// Route templates known from source (`/towns/:slug`); instances of
    /// these are sampled like `:id` templates.
    #[serde(skip)]
    pub route_templates: RouteTemplates,
    /// Visits of an instance that started and are not recorded yet, per
    /// template (parallel tabs): they count against the sampling budget so
    /// tabs do not oversample a template between deciding and recording.
    #[serde(skip)]
    reserved: HashMap<TemplateSlot, usize>,
    /// Explicitly seeded fixture URLs (canonicalized) that bypass template
    /// saturation in full mode so declared seeds are never skipped.
    #[serde(skip)]
    pinned_urls: HashSet<String>,
}

/// A started, not yet recorded visit of a template instance
/// ([`TemplateSampler::reserve`]); hand it back with
/// [`TemplateSampler::release`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TemplateSlot {
    template: String,
    source: bool,
}

/// Route templates from source (`ScanConfig::route_templates`, route
/// discovery) matched against concrete URLs: `/towns/:slug` matches
/// `/towns/brinkley-ar`. Templates without a literal segment (`/:slug`)
/// are ignored: they would claim every one-segment page.
#[derive(Debug, Clone, Default)]
pub struct RouteTemplates {
    templates: Vec<(String, Vec<Segment>)>,
}

#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Literal(String),
    Param,
    OptionalParam,
    /// `*` / `:rest*` (zero or more) or `+` / `:rest+` (one or more).
    Rest {
        at_least_one: bool,
    },
}

impl RouteTemplates {
    pub fn new<S: AsRef<str>>(templates: &[S]) -> Self {
        let mut out: Vec<(String, Vec<Segment>)> = Vec::new();
        for raw in templates {
            let template = normalize_template_path(raw.as_ref());
            let segments: Vec<Segment> = template
                .split('/')
                .filter(|s| !s.is_empty())
                .map(parse_segment)
                .collect();
            let literals = segments
                .iter()
                .filter(|s| matches!(s, Segment::Literal(_)))
                .count();
            if literals == 0 || literals == segments.len() {
                continue;
            }
            if !out.iter().any(|(t, _)| *t == template) {
                out.push((template, segments));
            }
        }
        // Most specific first: more literal segments win.
        out.sort_by_key(|(t, segs)| {
            (
                std::cmp::Reverse(
                    segs.iter()
                        .filter(|s| matches!(s, Segment::Literal(_)))
                        .count(),
                ),
                t.clone(),
            )
        });
        Self { templates: out }
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// The template matching a route path (`/towns/brinkley-ar`).
    pub fn match_path(&self, path: &str) -> Option<&str> {
        let path = normalize_template_path(path);
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        self.templates
            .iter()
            .find(|(_, segs)| segments_match(segs, &parts))
            .map(|(t, _)| t.as_str())
    }

    /// The template matching a URL's route path (hash routes included).
    pub fn template_for_url(&self, url: &str) -> Option<String> {
        if self.templates.is_empty() {
            return None;
        }
        let path = match Url::parse(url) {
            Ok(parsed) => crate::explorer::url_utils::effective_url_path_and_query(&parsed).0,
            Err(_) => split_relative_route_path_and_query(url)?.0,
        };
        self.match_path(&path).map(str::to_string)
    }
}

fn normalize_template_path(raw: &str) -> String {
    let raw = raw.trim();
    let path = raw.split(['?']).next().unwrap_or(raw);
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_segment(seg: &str) -> Segment {
    if seg == "*" || seg == "**" {
        return Segment::Rest {
            at_least_one: false,
        };
    }
    if seg == "+" {
        return Segment::Rest { at_least_one: true };
    }
    if let Some(name) = seg.strip_prefix(':') {
        if name.ends_with('*') {
            return Segment::Rest {
                at_least_one: false,
            };
        }
        if name.ends_with('+') {
            return Segment::Rest { at_least_one: true };
        }
        if name.ends_with('?') {
            return Segment::OptionalParam;
        }
        return Segment::Param;
    }
    if seg.starts_with('[') && seg.ends_with(']') {
        if seg.starts_with("[...") || seg.starts_with("[[...") {
            return Segment::Rest {
                at_least_one: !seg.starts_with("[["),
            };
        }
        return Segment::Param;
    }
    Segment::Literal(seg.to_ascii_lowercase())
}

fn segments_match(segs: &[Segment], parts: &[&str]) -> bool {
    match segs.split_first() {
        None => parts.is_empty(),
        Some((Segment::Literal(lit), rest)) => parts
            .split_first()
            .is_some_and(|(p, tail)| p.eq_ignore_ascii_case(lit) && segments_match(rest, tail)),
        Some((Segment::Param, rest)) => parts
            .split_first()
            .is_some_and(|(_, tail)| segments_match(rest, tail)),
        Some((Segment::OptionalParam, rest)) => {
            segments_match(rest, parts)
                || parts
                    .split_first()
                    .is_some_and(|(_, tail)| segments_match(rest, tail))
        }
        Some((Segment::Rest { at_least_one }, rest)) => {
            let min = usize::from(*at_least_one);
            (min..=parts.len()).any(|n| segments_match(rest, &parts[n..]))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSamplingState {
    pub template: String,
    pub variants: Vec<FingerprintVariant>,
    pub visited_count: usize,
    pub consecutive_duplicates: usize,
    pub saturated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintVariant {
    pub fingerprint: String,
    pub seen_count: usize,
    pub view_id: String,
    pub example_url: String,
}

#[derive(Debug, Clone)]
pub struct RecordVisitOutcome {
    pub template: String,
    pub variants: usize,
    pub new_variant: bool,
}

impl TemplateSamplingState {
    fn new(template: String) -> Self {
        Self {
            template,
            variants: Vec::new(),
            visited_count: 0,
            consecutive_duplicates: 0,
            saturated: false,
        }
    }
}

impl TemplateSampler {
    /// Use route templates known from source for sampling.
    pub fn set_route_templates(&mut self, templates: RouteTemplates) {
        self.route_templates = templates;
    }

    /// Exempt explicitly seeded fixture URLs from template saturation skipping.
    pub fn set_pinned_urls<I, S>(&mut self, urls: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.pinned_urls = urls
            .into_iter()
            .map(|u| crate::explorer::url_utils::canonicalize_crawl_url(u.as_ref()))
            .collect();
    }

    /// Whether `url` is an explicitly pinned seed that bypasses template saturation.
    pub fn is_pinned(&self, url: &str) -> bool {
        if self.pinned_urls.is_empty() {
            return false;
        }
        self.pinned_urls.contains(url)
            || self
                .pinned_urls
                .contains(&crate::explorer::url_utils::canonicalize_crawl_url(url))
    }

    /// Whether any pinned URL belongs to `template` (so queue purging must not
    /// drop it when `template` saturates).
    pub fn has_pinned_for_template(&self, template: &str) -> bool {
        if self.pinned_urls.is_empty() {
            return false;
        }
        self.pinned_urls
            .iter()
            .any(|url| self.template_of(url).as_deref() == Some(template))
    }

    /// The template `url` is an instance of: a `:id` path template, else a
    /// source route template.
    pub fn template_of(&self, url: &str) -> Option<String> {
        self.bucket(url).map(|(template, _)| template)
    }

    /// Template of `url` and whether it is a source route template.
    fn bucket(&self, url: &str) -> Option<(String, bool)> {
        if let Some(template) = parameterized_template(url) {
            return Some((template, false));
        }
        self.route_templates
            .template_for_url(url)
            .map(|template| (template, true))
    }

    fn states(&mut self, source: bool) -> &mut HashMap<String, TemplateSamplingState> {
        if source {
            &mut self.source_templates
        } else {
            &mut self.templates
        }
    }

    pub fn should_visit(&mut self, url: &str) -> TemplateVisitDecision {
        if self.is_pinned(url) {
            return TemplateVisitDecision::Visit;
        }
        let Some((template, source)) = self.bucket(url) else {
            return TemplateVisitDecision::Visit;
        };
        let in_flight = self
            .reserved
            .get(&TemplateSlot {
                template: template.clone(),
                source,
            })
            .copied()
            .unwrap_or(0);

        let state = self
            .states(source)
            .entry(template.clone())
            .or_insert_with(|| TemplateSamplingState::new(template.clone()));

        let visit_cap = template_visit_cap(&template);
        // Visits of this template still running on other tabs count as sampled.
        let sampled = state.visited_count.saturating_add(in_flight);

        if state.saturated {
            return TemplateVisitDecision::Skip {
                template,
                reason: format!(
                    "template saturated (variants={}, sampled={})",
                    state.variants.len(),
                    state.visited_count
                ),
                saturated_now: false,
            };
        }

        if sampled >= visit_cap {
            state.saturated = true;
            return TemplateVisitDecision::Skip {
                template,
                reason: format!("entity cap reached (sampled={sampled}, cap={visit_cap})"),
                saturated_now: true,
            };
        }

        // Phase 1: always visit the first 5 instances
        if sampled < 5 {
            return TemplateVisitDecision::Visit;
        }

        // Only one layout seen, 3+ consecutive dupes => saturated
        if state.variants.len() == 1 && state.consecutive_duplicates >= 3 {
            state.saturated = true;
            return TemplateVisitDecision::Skip {
                template,
                reason: format!(
                    "saturated early (1 variant, {} consecutive dupes, {} sampled)",
                    state.consecutive_duplicates, state.visited_count
                ),
                saturated_now: true,
            };
        }

        // Phase 2: still finding variants; sample until we hit the per-template
        // cap unless we're hitting lots of dupes.
        if sampled < visit_cap && state.consecutive_duplicates < 5 {
            return TemplateVisitDecision::Visit;
        }

        // Phase 3: hit cap or too many dupes.
        state.saturated = true;
        TemplateVisitDecision::Skip {
            template,
            reason: format!(
                "saturated (variants={}, consecutive_dupes={}, sampled={})",
                state.variants.len(),
                state.consecutive_duplicates,
                state.visited_count
            ),
            saturated_now: true,
        }
    }

    /// Count a visit of `url` that is starting as sampled until it is
    /// recorded ([`Self::record_visit`]) or abandoned: hand the slot back
    /// with [`Self::release`] either way. `None` for URLs of no template.
    pub fn reserve(&mut self, url: &str) -> Option<TemplateSlot> {
        let (template, source) = self.bucket(url)?;
        let slot = TemplateSlot { template, source };
        *self.reserved.entry(slot.clone()).or_insert(0) += 1;
        Some(slot)
    }

    /// End a reservation made by [`Self::reserve`].
    pub fn release(&mut self, slot: TemplateSlot) {
        if let Some(count) = self.reserved.get_mut(&slot) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.reserved.remove(&slot);
            }
        }
    }

    pub fn is_saturated_url(&self, url: &str) -> bool {
        if self.is_pinned(url) {
            return false;
        }
        let Some((template, source)) = self.bucket(url) else {
            return false;
        };
        let states = if source {
            &self.source_templates
        } else {
            &self.templates
        };
        states.get(&template).map(|s| s.saturated).unwrap_or(false)
    }

    /// Whether a completed visit with this fingerprint would add a layout
    /// variant. Scheduling may use this before a visit commits its sample.
    pub fn is_new_variant(&self, url: &str, fingerprint: &str) -> bool {
        let Some((template, source)) = self.bucket(url) else {
            return false;
        };
        let states = if source {
            &self.source_templates
        } else {
            &self.templates
        };
        states.get(&template).is_none_or(|state| {
            state
                .variants
                .iter()
                .all(|variant| variant.fingerprint != fingerprint)
        })
    }

    pub fn record_visit(
        &mut self,
        url: &str,
        fingerprint: &str,
        view_id: &str,
    ) -> Option<RecordVisitOutcome> {
        let (template, source) = self.bucket(url)?;

        let state = self
            .states(source)
            .entry(template.clone())
            .or_insert_with(|| TemplateSamplingState::new(template.clone()));

        state.visited_count = state.visited_count.saturating_add(1);

        if let Some(v) = state
            .variants
            .iter_mut()
            .find(|v| v.fingerprint == fingerprint)
        {
            v.seen_count = v.seen_count.saturating_add(1);
            state.consecutive_duplicates = state.consecutive_duplicates.saturating_add(1);
            return Some(RecordVisitOutcome {
                template,
                variants: state.variants.len(),
                new_variant: false,
            });
        }

        state.variants.push(FingerprintVariant {
            fingerprint: fingerprint.to_string(),
            seen_count: 1,
            view_id: view_id.to_string(),
            example_url: url.to_string(),
        });
        state.consecutive_duplicates = 0;

        Some(RecordVisitOutcome {
            template,
            variants: state.variants.len(),
            new_variant: true,
        })
    }

    /// Best-effort reconstruction for older checkpoints that don't have sampler state yet.
    pub fn reconstruct_from_url_map(
        url_to_view: &HashMap<String, String>,
        view_id_to_fingerprint: &HashMap<String, String>,
    ) -> Self {
        let mut sampler = TemplateSampler::default();

        for (url, view_id) in url_to_view {
            let Some(fingerprint) = view_id_to_fingerprint.get(view_id) else {
                continue;
            };

            let Some(template) = parameterized_template(url) else {
                continue;
            };

            let state = sampler
                .templates
                .entry(template.clone())
                .or_insert_with(|| TemplateSamplingState::new(template.clone()));

            state.visited_count = state.visited_count.saturating_add(1);

            if let Some(v) = state
                .variants
                .iter_mut()
                .find(|v| v.fingerprint == *fingerprint)
            {
                v.seen_count = v.seen_count.saturating_add(1);
            } else {
                state.variants.push(FingerprintVariant {
                    fingerprint: fingerprint.clone(),
                    seen_count: 1,
                    view_id: view_id.clone(),
                    example_url: url.clone(),
                });
            }
        }

        // Mark obviously-saturated templates so resume doesn't re-sample them.
        for state in sampler.templates.values_mut() {
            let cap = template_visit_cap(&state.template);
            if state.visited_count >= cap {
                state.saturated = true;
            } else if state.variants.len() == 1 && state.visited_count >= 5 {
                state.saturated = true;
                state.consecutive_duplicates = state.visited_count.saturating_sub(1);
            }
        }

        sampler
    }
}

fn template_visit_cap(template: &str) -> usize {
    // High-cardinality entity templates can explode queue growth quickly.
    if template.contains("/calls/:id") {
        8
    } else if template.starts_with("/clients/:id") {
        12
    } else {
        15
    }
}

fn split_relative_route_path_and_query(raw: &str) -> Option<(String, Option<String>)> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(frag) = s.strip_prefix('#') {
        if !crate::explorer::url_utils::fragment_is_route(Some(frag)) {
            return None;
        }
        let (frag_path, frag_query) = match frag.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (frag, None),
        };
        return Some((
            format!("/#{frag_path}"),
            frag_query.filter(|q| !q.is_empty()).map(str::to_string),
        ));
    }
    if let Some((before_hash, frag)) = s.split_once('#') {
        if crate::explorer::url_utils::fragment_is_route(Some(frag)) {
            let (frag_path, frag_query) = match frag.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (frag, None),
            };
            let base = before_hash
                .split('?')
                .next()
                .unwrap_or(before_hash)
                .trim_end_matches('/');
            return Some((
                format!("{base}/#{frag_path}"),
                frag_query.filter(|q| !q.is_empty()).map(str::to_string),
            ));
        }
        let (path, query) = match before_hash.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (before_hash, None),
        };
        if path.is_empty() {
            return None;
        }
        return Some((
            path.to_string(),
            query.filter(|q| !q.is_empty()).map(str::to_string),
        ));
    }
    let (path, query) = match s.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (s, None),
    };
    Some((
        path.to_string(),
        query.filter(|q| !q.is_empty()).map(str::to_string),
    ))
}

/// Convert a concrete URL into a route template.
///
/// Example: `https://x.com/clients/<uuid>/overview?tab=foo` -> `/clients/:id/overview`
pub fn url_to_template_path(url: &str) -> Option<String> {
    if let Ok(parsed) = Url::parse(url) {
        let (route_path, _) = crate::explorer::url_utils::effective_url_path_and_query(&parsed);
        Some(path_to_template(&route_path))
    } else {
        let (route_path, _) = split_relative_route_path_and_query(url)?;
        Some(path_to_template(&route_path))
    }
}

/// Canonical route key used by the store and verify scans.
///
/// Behavior:
/// - Parameterized paths (containing `:id`) are returned as templates, query stripped.
/// - Non-parameterized paths preserve query strings (so `?tab=x` variants remain distinct).
/// - Client-side hash routes (`/#/administration`, `#!/users/42`) preserve the hash route.
///
/// Examples:
/// - `https://x.com/clients/123/overview?tab=foo` -> `/clients/:id/overview`
/// - `https://x.com/reports?tab=foo` -> `/reports?tab=foo`
/// - `https://x.com/#/administration` -> `/#/administration`
/// - `https://x.com/#/users/42?tab=details` -> `/#/users/:id`
/// - `/reports?tab=foo` -> `/reports?tab=foo`
pub fn route_key(url_or_route: &str) -> String {
    let s = url_or_route.trim();
    if s.is_empty() {
        return "/".to_string();
    }

    if let Ok(parsed) = Url::parse(s) {
        let (route_path, query) = crate::explorer::url_utils::effective_url_path_and_query(&parsed);
        let templ = path_to_template(&route_path);
        if templ.contains(":id") {
            return templ;
        }
        if let Some(q) = query {
            return format!("{route_path}?{q}");
        }
        return route_path;
    }

    // Handle routes/paths that are not absolute URLs.
    let Some((path, query)) = split_relative_route_path_and_query(s) else {
        return "/".to_string();
    };
    let templ = path_to_template(&path);
    if templ.contains(":id") {
        return templ;
    }
    if let Some(q) = query {
        return format!("{path}?{q}");
    }
    templ
}

fn parameterized_template(url: &str) -> Option<String> {
    let template = url_to_template_path(url)?;
    if template.contains(":id") {
        Some(template)
    } else {
        None
    }
}

/// Stable-ish view ID derived from a template string.
///
/// Example: `/clients/:id/overview` -> `view_clients_id_overview`
pub fn template_to_view_id(template: &str) -> String {
    let mut s = template.trim_matches('/').to_string();
    if s.is_empty() {
        return "view_root".to_string();
    }
    s = s.replace(":id", "id");

    let mut out = String::from("view_");
    let mut last_was_us = false;
    for ch in s.chars() {
        let ok = ch.is_ascii_alphanumeric();
        let mapped = if ok { ch.to_ascii_lowercase() } else { '_' };
        if mapped == '_' {
            if last_was_us {
                continue;
            }
            last_was_us = true;
            out.push('_');
        } else {
            last_was_us = false;
            out.push(mapped);
        }
    }

    out.trim_end_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn running_visits_count_against_the_sampling_budget() {
        let mut sampler = TemplateSampler::default();
        // Five instances may start before any is recorded (parallel tabs)...
        let mut slots = Vec::new();
        for n in 0..5 {
            let url = format!("http://x.test/clients/{n}/overview");
            assert!(matches!(
                sampler.should_visit(&url),
                TemplateVisitDecision::Visit
            ));
            slots.push(sampler.reserve(&url).expect("templated url"));
        }
        assert!(sampler.reserve("http://x.test/about").is_none());
        // ...and running visits count: phase 1 is spent, the template is not
        // sampled again before they report (12 is the /clients/:id cap).
        for n in 5..12 {
            let url = format!("http://x.test/clients/{n}/overview");
            assert!(matches!(
                sampler.should_visit(&url),
                TemplateVisitDecision::Visit
            ));
            slots.push(sampler.reserve(&url).expect("templated url"));
        }
        assert!(matches!(
            sampler.should_visit("http://x.test/clients/99/overview"),
            TemplateVisitDecision::Skip {
                saturated_now: true,
                ..
            }
        ));

        // A recorded visit hands its slot back first: no double counting.
        let mut sampler = TemplateSampler::default();
        let url = "http://x.test/clients/1/overview";
        let slot = sampler.reserve(url).expect("templated url");
        sampler.release(slot);
        sampler.record_visit(url, "fp-a", "view_0001");
        let state = sampler
            .templates
            .get("/clients/:id/overview")
            .expect("state");
        assert_eq!(state.visited_count, 1);
        assert!(sampler.reserved.is_empty());
    }

    use super::{TemplateSampler, TemplateVisitDecision, route_key};

    #[test]
    fn clients_template_respects_entity_cap() {
        let mut sampler = TemplateSampler::default();

        // First 12 instances are sampled.
        for i in 0..12 {
            let url = format!("https://app.example.com/clients/{i:02}");
            assert!(matches!(
                sampler.should_visit(&url),
                TemplateVisitDecision::Visit
            ));
            let fp = format!("fp-{i}");
            let view = format!("view-{i}");
            let _ = sampler.record_visit(&url, &fp, &view);
        }

        // Next one should be rejected due to explicit per-template cap.
        let decision = sampler.should_visit("https://app.example.com/clients/99");
        match decision {
            TemplateVisitDecision::Skip { reason, .. } => {
                assert!(reason.contains("entity cap reached"));
            }
            TemplateVisitDecision::Visit => panic!("expected cap to stop additional client visits"),
        }
    }

    #[test]
    fn calls_template_uses_tighter_cap() {
        let mut sampler = TemplateSampler::default();

        for i in 0..8 {
            let url = format!("https://app.example.com/clients/1/calls/{i:02}");
            assert!(matches!(
                sampler.should_visit(&url),
                TemplateVisitDecision::Visit
            ));
            let fp = format!("fp-{i}");
            let view = format!("view-{i}");
            let _ = sampler.record_visit(&url, &fp, &view);
        }

        let decision = sampler.should_visit("https://app.example.com/clients/1/calls/99");
        match decision {
            TemplateVisitDecision::Skip { reason, .. } => {
                assert!(reason.contains("entity cap reached"));
            }
            TemplateVisitDecision::Visit => panic!("expected cap to stop additional call visits"),
        }
    }

    #[test]
    fn source_route_templates_match_slug_instances() {
        use super::RouteTemplates;
        let templates = RouteTemplates::new(&[
            "/dumpster-rental/:town",
            "/equipment/:slug",
            "/:slug",
            "/docs/:path*",
            "/blog/[id]",
            "/about",
        ]);
        assert_eq!(
            templates.match_path("/dumpster-rental/brinkley-ar"),
            Some("/dumpster-rental/:town")
        );
        assert_eq!(templates.match_path("/dumpster-rental/x/y"), None);
        assert_eq!(templates.match_path("/docs"), Some("/docs/:path*"));
        assert_eq!(templates.match_path("/docs/a/b"), Some("/docs/:path*"));
        assert_eq!(templates.match_path("/blog/7"), Some("/blog/[id]"));
        // `/:slug` and fully static routes are not instance templates.
        assert_eq!(templates.match_path("/about"), None);
        assert_eq!(templates.match_path("/contact"), None);
        assert_eq!(
            templates
                .template_for_url("http://x.test/equipment/mini-excavator?from=home")
                .as_deref(),
            Some("/equipment/:slug")
        );
    }

    #[test]
    fn sampler_samples_source_template_instances() {
        let mut sampler = TemplateSampler::default();
        sampler.set_route_templates(super::RouteTemplates::new(&["/towns/:slug"]));
        let mut visited = 0;
        for i in 0..12 {
            let url = format!("http://x.test/towns/town-{i}");
            if matches!(sampler.should_visit(&url), TemplateVisitDecision::Visit) {
                visited += 1;
                let _ = sampler.record_visit(&url, "same-layout", &format!("view-{i}"));
            }
        }
        // Identical layouts saturate after the first few instances.
        assert!(visited < 12, "visited {visited}");
        assert!(sampler.is_saturated_url("http://x.test/towns/town-99"));
        assert!(!sampler.is_saturated_url("http://x.test/towns"));
    }

    #[test]
    fn route_key_preserves_query_for_non_parameterized_routes() {
        assert_eq!(
            route_key("https://app.example.com/reports?tab=foo"),
            "/reports?tab=foo"
        );
        assert_eq!(route_key("/reports?tab=foo"), "/reports?tab=foo");
        assert_eq!(route_key("/reports"), "/reports");
    }

    #[test]
    fn route_key_templates_parameterized_routes_and_strips_query() {
        assert_eq!(
            route_key("https://app.example.com/clients/123/overview?tab=foo"),
            "/clients/:id/overview"
        );
        assert_eq!(
            route_key("/clients/123/overview?tab=foo"),
            "/clients/:id/overview"
        );
        assert_eq!(route_key("/clients/:id/overview"), "/clients/:id/overview");
    }

    #[test]
    fn route_key_and_template_preserve_hash_routes() {
        assert_eq!(
            route_key("https://app.example.com/#/administration"),
            "/#/administration"
        );
        assert_eq!(
            route_key("https://app.example.com/#/users/42?tab=details"),
            "/#/users/:id"
        );
        assert_eq!(
            route_key("https://app.example.com/#/search?q=apple"),
            "/#/search?q=apple"
        );
        assert_eq!(route_key("#/administration"), "/#/administration");
        assert_eq!(
            super::url_to_template_path("https://app.example.com/#/users/42?tab=details")
                .as_deref(),
            Some("/#/users/:id")
        );
        assert_eq!(super::url_to_template_path("#section"), None);
    }

    #[test]
    fn pinned_urls_bypass_parameterized_template_saturation() {
        let mut sampler = TemplateSampler::default();
        let pinned_early = "https://app.example.com/clients/100";
        let pinned_late = "https://app.example.com/clients/101";
        sampler.set_pinned_urls([pinned_early, pinned_late]);
        assert!(sampler.is_pinned(pinned_early));
        assert!(sampler.has_pinned_for_template("/clients/:id"));
        assert!(!sampler.has_pinned_for_template("/orders/:id"));

        // Saturate the /clients/:id template with unpinned instances.
        let mut visited = 0;
        for i in 0..12 {
            let url = format!("https://app.example.com/clients/{i:02}");
            if matches!(sampler.should_visit(&url), TemplateVisitDecision::Visit) {
                visited += 1;
                let _ = sampler.record_visit(&url, "same-fp", &format!("view-{i}"));
            }
        }
        assert!(
            visited < 12,
            "expected template saturation, visited {visited}"
        );

        // Unpinned URLs for the same template still saturate and skip.
        assert!(matches!(
            sampler.should_visit("https://app.example.com/clients/999"),
            TemplateVisitDecision::Skip { .. }
        ));
        assert!(sampler.is_saturated_url("https://app.example.com/clients/999"));

        // Pinned fixture seeds bypass saturation.
        assert!(matches!(
            sampler.should_visit(pinned_early),
            TemplateVisitDecision::Visit
        ));
        assert!(matches!(
            sampler.should_visit(pinned_late),
            TemplateVisitDecision::Visit
        ));
        assert!(!sampler.is_saturated_url(pinned_late));
    }

    #[test]
    fn pinned_urls_bypass_source_template_saturation() {
        let mut sampler = TemplateSampler::default();
        sampler.set_route_templates(super::RouteTemplates::new(&["/towns/:slug"]));
        let pinned = "http://x.test/towns/special-fixture";
        sampler.set_pinned_urls([pinned]);
        assert!(sampler.has_pinned_for_template("/towns/:slug"));

        for i in 0..10 {
            let url = format!("http://x.test/towns/town-{i}");
            if matches!(sampler.should_visit(&url), TemplateVisitDecision::Visit) {
                let _ = sampler.record_visit(&url, "same-layout", &format!("view-{i}"));
            }
        }
        assert!(sampler.is_saturated_url("http://x.test/towns/town-99"));
        assert!(matches!(
            sampler.should_visit("http://x.test/towns/town-99"),
            TemplateVisitDecision::Skip { .. }
        ));
        assert!(matches!(
            sampler.should_visit(pinned),
            TemplateVisitDecision::Visit
        ));
        assert!(!sampler.is_saturated_url(pinned));
    }
}
