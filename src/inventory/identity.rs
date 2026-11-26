//! Stable control identity: route templates, roles, and locators.
//!
//! A control's key is `<route template>|<role>|<locator>[#n]`. The locator is
//! the most stable handle we have for the element, in preference order:
//! `testid=` > `id=` (non-generated) > `aria=` / `name=` > `text=<normalized
//! label>` > `href=` (unlabeled links only). A link's target is what it
//! *does*, not who it is: a changed `href` on the same labelled link is a
//! rewire, not a different control. Label-based locators carry the page
//! region (`@header`, `@nav`, `@footer`, `@aside`, `@dialog`; main content
//! has no suffix), so a footer "Contact" and a hero "Contact" stay distinct.
//! Unlabeled controls with no other handle get an ordinal (`#n`, document
//! order) so they stay distinct.

use std::sync::OnceLock;

use regex::Regex;
use url::Url;

use crate::explorer::url_utils::effective_url_path_and_query;
use crate::network::path_parameterizer::path_to_template;
use crate::route_discovery::DiscoveredRoute;
use crate::types::dom::{ElementType, LocatorKind, LocatorStrategy};

/// Longest normalized label kept in a `text=` locator.
const MAX_TEXT_LOCATOR_CHARS: usize = 60;

/// Route template for a URL or a spec route: query dropped, ids templated,
/// hash routes kept (`/#/admin`), trailing slash trimmed.
pub fn route_template(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return "/".to_string();
    }
    if let Ok(url) = Url::parse(s)
        && matches!(url.scheme(), "http" | "https")
    {
        let (path, _) = effective_url_path_and_query(&url);
        return clean_route(&path_to_template(&path));
    }
    // Relative route. Keep `#/x` / `#!/x` / root-level registered route fragments, drop plain anchors.
    let mut path = s.to_string();
    if let Some(idx) = path.find('#') {
        let before = &path[..idx];
        let base_path = before.split_once('?').map_or(before, |(p, _)| p).trim();
        let frag = &path[idx + 1..];
        let f_trim = frag.trim();
        let is_explicit = f_trim.starts_with('/')
            || f_trim.starts_with('!')
            || f_trim.contains('/')
            || f_trim.contains('?');
        let keep_frag = is_explicit
            || (matches!(base_path, "" | "/" | "/index.html")
                && crate::explorer::url_utils::fragment_is_route(Some(frag)));
        if !keep_frag {
            path.truncate(idx);
        }
    }
    if let Some(idx) = path.find('?') {
        path.truncate(idx);
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    clean_route(&path_to_template(&path))
}

fn clean_route(path: &str) -> String {
    let mut out = path.trim().to_string();
    if out.is_empty() {
        return "/".to_string();
    }
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    while out.len() > 1 && out.ends_with('/') && !out.ends_with("#/") {
        out.pop();
    }
    out
}

/// Maps crawled route templates onto routes discovered from source, so
/// `/blog/hello-world` and `/blog/second` both become `/blog/:slug`.
///
/// Concrete paths that source enumerates for a dynamic route
/// (`generateStaticParams` / `getStaticPaths` examples) stay distinct
/// routes: `/universe` and `/strategies` are different pages even though both
/// match `/:view`. Error pages (`/404`, `/500`) are not routes.
#[derive(Debug, Default, Clone)]
pub struct RouteCanon {
    statics: std::collections::BTreeSet<String>,
    /// (dynamic segment count, pattern segments, pattern) sorted most-specific first.
    dynamics: Vec<(usize, Vec<String>, String)>,
    /// Every discovered route of any kind (pages, API routes, redirects):
    /// a path matching none of them is not a route of the app.
    known_static: std::collections::BTreeSet<String>,
    known_dynamic: Vec<Vec<String>>,
    pages: usize,
}

impl RouteCanon {
    pub fn new(discovered: &[DiscoveredRoute]) -> Self {
        let mut canon = RouteCanon::default();
        for r in discovered.iter().filter(|r| !is_error_page(r)) {
            if let Some((before, frag)) = r.path.split_once('#') {
                let base_path = before.split_once('?').map_or(before, |(p, _)| p).trim();
                if matches!(base_path, "" | "/" | "/index.html") {
                    crate::explorer::url_utils::register_route_fragment(frag);
                }
            }
            let path = clean_route(&r.path);
            let segs = split_segments(&path);
            let dyn_count = segs.iter().filter(|s| is_dynamic_segment(s)).count();
            if dyn_count == 0 {
                canon.known_static.insert(path.clone());
            } else {
                canon.known_dynamic.push(segs.clone());
            }
            if !is_page_kind(&r.kind) {
                continue;
            }
            canon.pages += 1;
            if dyn_count == 0 {
                canon.statics.insert(path);
            } else {
                for example in &r.examples {
                    let concrete = route_template(example);
                    canon.known_static.insert(concrete.clone());
                    canon.statics.insert(concrete);
                }
                canon.dynamics.push((dyn_count, segs, path));
            }
        }
        canon.dynamics.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| b.1.len().cmp(&a.1.len()))
                .then_with(|| a.2.cmp(&b.2))
        });
        canon
    }

    /// Keep concrete crawl seeds (`/universe`) as their own routes when they
    /// would otherwise collapse into a dynamic pattern (`/:view`).
    pub fn add_concrete(&mut self, paths: &[String]) {
        for p in paths {
            let t = route_template(p);
            let segs = split_segments(&t);
            if segs.iter().any(|s| is_dynamic_segment(s)) || self.statics.contains(&t) {
                continue;
            }
            if self
                .dynamics
                .iter()
                .any(|(_, pattern, _)| pattern_matches(pattern, &segs))
            {
                self.known_static.insert(t.clone());
                self.statics.insert(t);
            }
        }
    }

    /// Canonical route for a route template.
    pub fn canonical(&self, route: &str) -> String {
        if self.statics.contains(route) {
            return route.to_string();
        }
        let segs = split_segments(route);
        for (_, pattern, path) in &self.dynamics {
            if pattern_matches(pattern, &segs) {
                return path.clone();
            }
        }
        route.to_string()
    }

    /// Canonical route template for a URL or raw route.
    pub fn route(&self, raw: &str) -> String {
        self.canonical(&route_template(raw))
    }

    /// Source discovery found enough page routes to judge whether a path is
    /// a route of the app at all.
    pub fn knows_routes(&self) -> bool {
        self.pages >= 2
    }

    /// Is `route` (a canonical template) a route discovered in source? Always
    /// true when discovery found too little to tell.
    pub fn is_known(&self, route: &str) -> bool {
        if !self.knows_routes() || route == "/" || route == "/#/" {
            return true;
        }
        if self.known_static.contains(route) {
            return true;
        }
        let segs = split_segments(route);
        // A templated crawl path (`/orders/:id`) matches a source pattern
        // with a dynamic segment in the same place.
        self.known_dynamic.iter().any(|p| {
            pattern_matches(p, &segs)
                || (p.len() == segs.len()
                    && p.iter()
                        .zip(segs.iter())
                        .all(|(a, b)| a == b || is_dynamic_segment(a) || is_dynamic_segment(b)))
        })
    }
}

/// `/404`, `/500`, and framework error pages (`404.astro`, `_error.tsx`,
/// `not-found.tsx`) are not navigable routes.
pub fn is_error_page(r: &DiscoveredRoute) -> bool {
    let path = clean_route(&r.path);
    let last = path
        .trim_start_matches("/#")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(last.as_str(), "404" | "500" | "_error" | "_not-found") {
        return true;
    }
    let file = r.file.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    let stem = file.split('.').next().unwrap_or("");
    matches!(stem, "404" | "500" | "_error" | "not-found" | "_not-found")
}

pub fn is_page_kind(kind: &str) -> bool {
    kind.is_empty() || kind.eq_ignore_ascii_case("page")
}

fn split_segments(route: &str) -> Vec<String> {
    route
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_dynamic_segment(seg: &str) -> bool {
    seg.starts_with(':') || seg.starts_with('[') || seg == "*" || seg.starts_with('*')
}

fn is_catch_all(seg: &str) -> bool {
    seg == "*"
        || seg.starts_with('*')
        || seg.starts_with("[...")
        || seg.starts_with("[[...")
        || (seg.starts_with(':') && (seg.ends_with('*') || seg.ends_with('+')))
}

fn pattern_matches(pattern: &[String], segs: &[String]) -> bool {
    let mut i = 0;
    for (pi, p) in pattern.iter().enumerate() {
        if is_catch_all(p) {
            let optional = p.starts_with("[[") || p.ends_with('*') || p == "*";
            let rest = segs.len().saturating_sub(i);
            return pi == pattern.len() - 1 && (rest > 0 || optional);
        }
        let Some(seg) = segs.get(i) else {
            return false;
        };
        if !is_dynamic_segment(p) && p != seg {
            return false;
        }
        i += 1;
    }
    i == segs.len()
}

/// A user route query, without converting literal record IDs into parameters.
/// Query pairs are sorted and re-encoded so different values cannot collapse
/// into one state. Only archived queries use this; inventory identity still
/// uses `route_template`.
pub(super) fn query_route_parts(raw: &str) -> (String, Option<String>) {
    let raw = raw.trim();
    let parsed = Url::parse(raw)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .or_else(|| {
            let base = Url::parse("http://brokenapp.invalid/").ok()?;
            base.join(raw).ok()
        });
    let Some(parsed) = parsed else {
        return (clean_route(raw.split('?').next().unwrap_or(raw)), None);
    };
    let (path, query) = effective_url_path_and_query(&parsed);
    let mut pairs: Vec<_> =
        url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    // Key ordering is immaterial, but repeated-key value order can be meaningful.
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let query = (!pairs.is_empty()).then(|| {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            encoded.append_pair(&key, &value);
        }
        format!("?{}", encoded.finish())
    });
    (clean_route(&path), query)
}

pub(super) fn route_has_parameters(route: &str) -> bool {
    query_route_parts(route)
        .0
        .split('/')
        .any(is_dynamic_segment)
}

/// A query or a concrete record within a saved template identifies more than
/// the route-level graph knows. Visiting a variant does not prove its edges.
pub(super) fn route_request_is_specific(request: &str, route: &str) -> bool {
    let (path, query) = query_route_parts(request);
    query.is_some() || (!route_has_parameters(&path) && route_has_parameters(route))
}

/// Whether a saved page/control variant belongs to the requested state.
/// A record request without a query includes all observed tabs of that record.
pub(super) fn route_variant_matches(route: &str, variant: &str, request: &str) -> bool {
    let raw = if variant.starts_with('?') {
        format!("{route}{variant}")
    } else {
        variant.to_string()
    };
    let (path, query) = query_route_parts(&raw);
    let (wanted_path, wanted_query) = query_route_parts(request);
    if wanted_query.is_some() && query != wanted_query {
        return false;
    }
    if !route_has_parameters(&wanted_path) && route_has_parameters(route) {
        return !route_has_parameters(&path) && route_matches(&path, &wanted_path);
    }
    route_matches(&path, &wanted_path)
}

fn query_path_aliases(path: &str) -> [String; 3] {
    [path.to_string(), format!("/#{path}"), format!("/#!{path}")]
}

/// Routes in `routes` the goal selects: normalized exact matches when there
/// are any, else template matches (`/products/42` selects `/products/:id`).
/// Literal IDs in the goal must never become wildcards for static routes.
pub fn select_routes<'a>(routes: impl IntoIterator<Item = &'a str>, goal: &str) -> Vec<&'a str> {
    let all: Vec<&str> = routes.into_iter().collect();
    let (goal_path, _) = query_route_parts(goal);
    let aliases = query_path_aliases(&goal_path);
    let exact: Vec<&str> = all
        .iter()
        .copied()
        .filter(|r| aliases.contains(&query_route_parts(r).0))
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    let matching: Vec<_> = all.into_iter().filter(|r| route_matches(r, goal)).collect();
    if route_has_parameters(&goal_path) {
        let templates: Vec<_> = matching
            .iter()
            .copied()
            .filter(|r| route_has_parameters(r))
            .collect();
        if !templates.is_empty() {
            return templates;
        }
    }
    matching
}

/// Match saved templates against a literal user path. Explicit parameters on
/// either side remain supported, but ordinary numeric/UUID segments stay literal.
pub fn route_matches(route: &str, goal: &str) -> bool {
    let (goal, _) = query_route_parts(goal);
    let (route, _) = query_route_parts(route);
    let segs = split_segments(&route);
    query_path_aliases(&goal).iter().any(|g| {
        let gs = split_segments(g);
        gs.len() == segs.len()
            && gs
                .iter()
                .zip(segs.iter())
                .all(|(a, b)| a == b || is_dynamic_segment(a) || is_dynamic_segment(b))
    })
}

/// Coarse role for an element type.
pub fn role_for_element(et: &ElementType) -> &'static str {
    match et {
        ElementType::NavigationLink { .. } => "link",
        ElementType::Button { .. }
        | ElementType::ModalTrigger
        | ElementType::DropdownMenu { .. }
        | ElementType::Accordion
        | ElementType::Pagination
        | ElementType::SortControl
        | ElementType::FilterControl
        | ElementType::ContextMenu => "button",
        ElementType::TextInput { .. }
        | ElementType::DatePicker
        | ElementType::SearchBar
        | ElementType::FileUpload { .. } => "input",
        ElementType::SelectDropdown { .. } => "select",
        ElementType::Checkbox { .. } | ElementType::Toggle => "checkbox",
        ElementType::RadioButton { .. } => "radio",
        ElementType::Tab => "tab",
        ElementType::DragHandle => "other",
        ElementType::Other { tag, role } => role_for_tag(tag, role.as_deref()),
    }
}

fn role_for_tag(tag: &str, role: Option<&str>) -> &'static str {
    match role.map(|r| r.to_ascii_lowercase()).as_deref() {
        Some("button") | Some("menuitem") | Some("option") => return "button",
        Some("link") => return "link",
        Some("tab") => return "tab",
        Some("checkbox") | Some("switch") => return "checkbox",
        Some("radio") => return "radio",
        Some("textbox") | Some("searchbox") | Some("combobox") => return "input",
        _ => {}
    }
    match tag.to_ascii_lowercase().as_str() {
        "a" => "link",
        "button" | "summary" => "button",
        "input" | "textarea" => "input",
        "select" => "select",
        "form" => "form",
        _ => "other",
    }
}

/// Role for an `interactions.jsonl` `element_kind` slug.
pub fn role_for_kind_slug(slug: &str) -> &'static str {
    match slug {
        "navigation_link" | "link" => "link",
        "button" | "modal_trigger" | "dropdown_menu" | "accordion" | "pagination"
        | "sort_control" | "filter_control" | "context_menu" => "button",
        "text_input" | "date_picker" | "search_bar" | "file_upload" | "input" => "input",
        "select_dropdown" | "select" => "select",
        "checkbox" | "toggle" => "checkbox",
        "radio_button" | "radio" => "radio",
        "tab" => "tab",
        "form" => "form",
        _ => "other",
    }
}

/// Roles whose "no effect" is normal (typing/focus), never dead.
pub fn is_input_role(role: &str) -> bool {
    matches!(role, "input" | "select" | "checkbox" | "radio")
}

/// Lowercased, whitespace-collapsed label with data folded out: digit runs
/// become `#` (counts, prices), and dates and times collapse to a single `#`
/// (`Nov 10, 2026, open` -> `#`, `Expected 9:29 PM` -> `expected #`). A date
/// label's trailing comma clauses (availability states like `, booked`) are
/// dropped too, so calendar cells form one control. Capped in length.
pub fn normalize_text(label: &str) -> String {
    let folded = fold_digits(label);
    let (folded, _) = fold_dates(&folded);
    folded
        .trim()
        .chars()
        .take(MAX_TEXT_LOCATOR_CHARS)
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// Lowercase, collapse whitespace (`|` counts as a space), digit runs -> `#`.
fn fold_digits(label: &str) -> String {
    let mut out = String::new();
    let mut last_space = true;
    let mut last_digit = false;
    let mut chars = label.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            if !last_digit {
                out.push('#');
            }
            last_digit = true;
            last_space = false;
            continue;
        }
        // Count-cap badges (`99+`, `99+ unread`, `(99+)`): fold trailing `+` into `#`.
        if ch == '+'
            && last_digit
            && chars
                .peek()
                .is_none_or(|next| !next.is_ascii_alphanumeric())
        {
            last_digit = false;
            continue;
        }
        last_digit = false;
        if ch.is_whitespace() || ch == '|' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
            continue;
        }
        last_space = false;
        out.extend(ch.to_lowercase());
    }
    out.trim().to_string()
}

const MONTHS: &str = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";
const WEEKDAYS: &str = r"(?:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:r(?:s(?:day)?)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)";

/// Fold dates and times in a digit-folded label into `#`. Returns whether a
/// date (month name next to a number, or `#/#/#`) was seen.
fn fold_dates(s: &str) -> (String, bool) {
    struct Re {
        month_before: Regex,
        month_after: Regex,
        weekday: Regex,
        ordinal: Regex,
        ampm: Regex,
        numeric_date: Regex,
        run: Regex,
    }
    static RE: OnceLock<Re> = OnceLock::new();
    let re = RE.get_or_init(|| Re {
        month_before: Regex::new(&format!(r"\b{MONTHS}\.? ?#")).expect("regex"),
        month_after: Regex::new(&format!(r"# {MONTHS}\b\.?")).expect("regex"),
        weekday: Regex::new(&format!(r"\b{WEEKDAYS}\.?,? #")).expect("regex"),
        ordinal: Regex::new(r"#(?:st|nd|rd|th)\b").expect("regex"),
        ampm: Regex::new(r"# ?(?:a\.?m|p\.?m)\b\.?").expect("regex"),
        numeric_date: Regex::new(r"#[/.-]#[/.-]#").expect("regex"),
        run: Regex::new(r"#(?:[ ,./:-]*#)+").expect("regex"),
    });
    if !s.contains('#') {
        return (s.to_string(), false);
    }
    let mut date = re.numeric_date.is_match(s);
    let mut out = re.ordinal.replace_all(s, "#").into_owned();
    for month in [&re.month_before, &re.month_after] {
        if month.is_match(&out) {
            date = true;
            out = month.replace_all(&out, "#").into_owned();
        }
    }
    out = re.weekday.replace_all(&out, "#").into_owned();
    out = re.ampm.replace_all(&out, "#").into_owned();
    out = re.run.replace_all(&out, "#").into_owned();
    if date && let Some(i) = out.find("#,") {
        // `#, open` / `#, booked`: the state after a date is data.
        out.truncate(i + 1);
    }
    (out, date)
}

/// Fold English singular/plural count-noun inflections immediately following
/// a folded number token (`#` or `(#)`), e.g. `"authorized clients # clients"`
/// -> `"authorized clients # client"` and `"# entries"` -> `"# entry"`.
///
/// Used by behavioral diff and cross-role matching so a dynamic item count
/// changing from `1` to `2` never looks like a renamed or different control.
pub fn fold_count_plurals(norm: &str) -> String {
    fn singularize_count_noun(token: &str) -> String {
        let trim_end = token.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
        let suffix = &token[trim_end.len()..];
        if trim_end.len() < 3 || !trim_end.chars().all(|c| c.is_ascii_alphabetic()) {
            return token.to_string();
        }
        let stem = match trim_end {
            "children" => "child".to_string(),
            "people" => "person".to_string(),
            w if w.len() >= 5 && w.ends_with("ies") => format!("{}y", &w[..w.len() - 3]),
            w if w.len() >= 4
                && (w.ends_with("ches")
                    || w.ends_with("shes")
                    || w.ends_with("xes")
                    || w.ends_with("zes")
                    || w.ends_with("sses")) =>
            {
                w[..w.len() - 2].to_string()
            }
            w if w.ends_with('s')
                && !w.ends_with("ss")
                && !w.ends_with("us")
                && !w.ends_with("is") =>
            {
                w[..w.len() - 1].to_string()
            }
            w => w.to_string(),
        };
        format!("{stem}{suffix}")
    }

    let mut out = Vec::new();
    let mut prev_was_count = false;
    for tok in norm.split_whitespace() {
        if prev_was_count {
            out.push(singularize_count_noun(tok));
        } else {
            out.push(tok.to_string());
        }
        prev_was_count = tok == "#" || tok == "(#)" || tok == "+#" || tok == "-#";
    }
    out.join(" ")
}

/// Collapse whitespace; keep case (author-chosen attribute values).
fn clean_value(v: &str) -> String {
    v.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "/")
}

/// Ids produced by frameworks/libraries at runtime (`:r1:`, `radix-_r_2_`,
/// `base-ui-_r_1v_`, `cb_r_9_`, `mat-select-0`, `headlessui-menu-button-3`,
/// uuids) are not stable across renders.
pub fn is_generated_id(id: &str) -> bool {
    static TRAILING_NUM: OnceLock<Regex> = OnceLock::new();
    static LONG_NUM: OnceLock<Regex> = OnceLock::new();
    static UUID: OnceLock<Regex> = OnceLock::new();
    static REACT_USE_ID: OnceLock<Regex> = OnceLock::new();
    let id = id.trim();
    if id.is_empty() {
        return true;
    }
    if id.contains(':') || id.contains('\u{00ab}') || id.contains('\u{00bb}') {
        return true;
    }
    let lower = id.to_ascii_lowercase();
    if lower.starts_with("radix-")
        || lower.starts_with("base-ui-")
        || lower.starts_with("floating-ui-")
        || lower.starts_with("headlessui-")
        || lower.starts_with("react-aria")
        || lower.starts_with("react-select-")
        || lower.starts_with("downshift-")
        || lower.starts_with("ariakit-")
        || lower.starts_with("reka-")
        || lower.starts_with("mui-")
        || lower.starts_with("chakra-")
        || lower.starts_with("_r_")
        || lower.starts_with(":r")
    {
        return true;
    }
    let react_use_id =
        REACT_USE_ID.get_or_init(|| Regex::new(r"(?i)_r_[0-9a-z]+_").expect("regex"));
    let trailing = TRAILING_NUM.get_or_init(|| Regex::new(r"[-_]\d+$").expect("regex"));
    let long_num = LONG_NUM.get_or_init(|| Regex::new(r"\d{4,}").expect("regex"));
    let uuid = UUID.get_or_init(|| {
        Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("regex")
    });
    if react_use_id.is_match(id)
        || trailing.is_match(id)
        || long_num.is_match(id)
        || uuid.is_match(id)
    {
        return true;
    }
    // Hash-like tokens (`css-1x2y3z`, `a1b2c3d4`).
    id.split(['-', '_']).any(|seg| {
        seg.len() >= 6
            && seg.chars().all(|c| c.is_ascii_alphanumeric())
            && seg.chars().filter(|c| c.is_ascii_digit()).count() >= 2
            && seg.chars().any(|c| c.is_ascii_alphabetic())
    })
}

/// Value of `[attr="value"]` inside a CSS selector (first match).
pub fn quoted_attr(selector: &str, attr: &str) -> Option<String> {
    let needle = format!("[{attr}=\"");
    let start = selector.find(&needle)? + needle.len();
    let rest = &selector[start..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            '"' => return Some(out),
            _ => out.push(c),
        }
    }
    None
}

/// Id from a simple `#id` selector (CSS escapes undone).
pub fn id_from_selector(selector: &str) -> Option<String> {
    let rest = selector.trim().strip_prefix('#')?;
    let id = unescape_css_ident(rest)?;
    (!id.is_empty()).then_some(id)
}

/// Undo CSS identifier escaping. `None` when the selector continues past the
/// identifier (a compound or complex selector).
fn unescape_css_ident(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            if c.is_whitespace() || matches!(c, '>' | '.' | '[' | '+' | '~' | ',' | ':' | '#') {
                return None;
            }
            out.push(c);
            continue;
        }
        let mut hex = String::new();
        while let Some(&h) = chars.peek() {
            if h.is_ascii_hexdigit() && hex.len() < 6 {
                hex.push(h);
                chars.next();
            } else {
                break;
            }
        }
        if hex.is_empty() {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            if chars.peek() == Some(&' ') {
                chars.next();
            }
            if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                out.push(ch);
            }
        }
    }
    Some(out)
}

/// Tag name of the last compound in a selector (`main > button:nth-of-type(2)` -> `button`).
pub fn tag_from_selector(selector: &str) -> Option<String> {
    let last = selector
        .rsplit(['>', ' ', '+', '~'])
        .find(|s| !s.trim().is_empty())?;
    let tag: String = last
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    (!tag.is_empty()).then(|| tag.to_ascii_lowercase())
}

/// Page regions that make up the app shell (repeated on most routes).
pub const SHELL_REGIONS: &[&str] = &["header", "nav", "footer", "aside"];

/// Region for content outside any landmark.
pub const MAIN_REGION: &str = "main";

/// Page region of an element from its ancestor paths (structural locator,
/// selector): the outermost landmark (`header`, `nav`, `main`, `aside`,
/// `footer`, `dialog`, or the matching ARIA roles). A `<footer>` inside
/// `<main>` is main content, as in the ARIA landmark rules. Elements with no
/// landmark ancestor are `nav` when they sit in a `<nav>` (discovery's
/// `in_nav`) and `main` otherwise.
pub fn region_of<'a>(paths: impl IntoIterator<Item = &'a str>, in_nav: bool) -> &'static str {
    landmark_region(paths, in_nav).unwrap_or(MAIN_REGION)
}

/// Like [`region_of`], but `None` when no landmark (or `<nav>` ancestor) is
/// visible: the paths may be truncated above a `<footer>` or `<header>`.
pub fn landmark_region<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    in_nav: bool,
) -> Option<&'static str> {
    for path in paths {
        if let Some(region) = outermost_landmark(path) {
            return Some(region);
        }
    }
    in_nav.then_some("nav")
}

fn outermost_landmark(path: &str) -> Option<&'static str> {
    compounds(path).into_iter().find_map(|c| landmark_of(&c))
}

/// Split a selector into compounds on combinators, ignoring separators
/// inside quotes, brackets, and parentheses.
fn compounds(selector: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut depth = 0usize;
    for ch in selector.chars() {
        if let Some(q) = quote {
            cur.push(ch);
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                cur.push(ch);
            }
            '[' | '(' => {
                depth += 1;
                cur.push(ch);
            }
            ']' | ')' => {
                depth = depth.saturating_sub(1);
                cur.push(ch);
            }
            '>' | '+' | '~' if depth == 0 => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            c if c.is_whitespace() && depth == 0 => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            c => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn landmark_of(compound: &str) -> Option<&'static str> {
    let tag: String = compound
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_ascii_lowercase();
    let by_tag = match tag.as_str() {
        "header" => Some("header"),
        "nav" => Some("nav"),
        "main" => Some("main"),
        "aside" => Some("aside"),
        "footer" => Some("footer"),
        "dialog" => Some("dialog"),
        _ => None,
    };
    if by_tag.is_some() {
        return by_tag;
    }
    let role = quoted_attr(compound, "role").or_else(|| {
        let start = compound.find("[role=")? + "[role=".len();
        let rest = &compound[start..];
        Some(rest[..rest.find(']')?].to_string())
    })?;
    match role.to_ascii_lowercase().as_str() {
        "banner" => Some("header"),
        "navigation" => Some("nav"),
        "main" => Some("main"),
        "complementary" => Some("aside"),
        "contentinfo" => Some("footer"),
        "dialog" | "alertdialog" => Some("dialog"),
        _ => None,
    }
}

/// `locator@region` for label-based locators outside main content.
pub fn with_region(locator: String, region: &str) -> String {
    if region.is_empty() || region == MAIN_REGION {
        locator
    } else {
        format!("{locator}@{region}")
    }
}

/// Chosen locator for a control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatorChoice {
    pub locator: String,
    /// No stable handle at all: an ordinal must disambiguate.
    pub needs_ordinal: bool,
}

/// Pick the most stable locator. Author-declared handles (`testid=`, `id=`)
/// are used as-is; label-based handles (`aria=`, `name=`, `text=`) carry the
/// page `region`. Links are identified by their label like any control;
/// `link_target` (the normalized href) is only the locator of unlabeled
/// links.
pub fn choose_locator(
    locators: &[LocatorStrategy],
    selector: &str,
    role: &str,
    region: &str,
    label: &str,
    link_target: Option<&str>,
) -> LocatorChoice {
    let found = |kind: LocatorKind| {
        locators
            .iter()
            .find(|l| l.kind == kind)
            .map(|l| l.value.as_str())
    };

    let testid = found(LocatorKind::TestId)
        .and_then(test_id_value)
        .or_else(|| test_id_value(selector));
    if let Some(v) = testid.filter(|v| !v.trim().is_empty()) {
        return pick(format!("testid={}", clean_value(&v)));
    }
    let id = found(LocatorKind::Id)
        .and_then(id_from_selector)
        .or_else(|| id_from_selector(selector));
    if let Some(v) = id.filter(|v| !is_generated_id(v)) {
        return pick(format!("id={}", clean_value(&v)));
    }
    let aria = found(LocatorKind::Aria)
        .and_then(|s| quoted_attr(s, "aria-label"))
        .or_else(|| quoted_attr(selector, "aria-label"))
        .map(|v| normalize_text(&v));
    if let Some(v) = aria.filter(|v| !v.is_empty()) {
        return pick(with_region(format!("aria={v}"), region));
    }
    let name = found(LocatorKind::Name)
        .and_then(|s| quoted_attr(s, "name"))
        .or_else(|| quoted_attr(selector, "name"));
    if let Some(v) = name.filter(|v| !v.trim().is_empty()) {
        return pick(with_region(format!("name={}", clean_value(&v)), region));
    }
    let text = normalize_text(label);
    if role == "link"
        && text.is_empty()
        && let Some(target) = link_target.filter(|t| !t.is_empty())
    {
        return pick(with_region(format!("href={}", clean_value(target)), region));
    }
    LocatorChoice {
        needs_ordinal: text.is_empty(),
        locator: with_region(format!("text={text}"), region),
    }
}

fn pick(locator: String) -> LocatorChoice {
    LocatorChoice {
        locator,
        needs_ordinal: false,
    }
}

fn test_id_value(selector: &str) -> Option<String> {
    [
        "data-testid",
        "data-test-id",
        "data-cy",
        "data-test",
        "data-qa",
    ]
    .iter()
    .find_map(|attr| quoted_attr(selector, attr))
}

/// Raw attribute hints for static source linking.
pub fn locator_attr(
    locators: &[LocatorStrategy],
    selector: &str,
    kind: LocatorKind,
) -> Option<String> {
    let value = locators
        .iter()
        .find(|l| l.kind == kind)
        .map(|l| l.value.as_str());
    match kind {
        LocatorKind::TestId => value
            .and_then(test_id_value)
            .or_else(|| test_id_value(selector)),
        LocatorKind::Id => value
            .and_then(id_from_selector)
            .or_else(|| id_from_selector(selector)),
        LocatorKind::Aria => value
            .and_then(|s| quoted_attr(s, "aria-label"))
            .or_else(|| quoted_attr(selector, "aria-label")),
        LocatorKind::Name => value
            .and_then(|s| quoted_attr(s, "name"))
            .or_else(|| quoted_attr(selector, "name")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(kind: LocatorKind, value: &str) -> LocatorStrategy {
        LocatorStrategy {
            kind,
            value: value.to_string(),
            stability: kind.default_stability(),
            unique: true,
        }
    }

    #[test]
    fn route_templates_keep_hash_routes_and_drop_queries() {
        assert_eq!(
            route_template("http://x:3000/#/search?q=apple"),
            "/#/search"
        );
        assert_eq!(route_template("http://x:3000/#/"), "/#/");
        assert_eq!(
            route_template("http://x:3000/products/42?tab=a"),
            "/products/:id"
        );
        assert_eq!(route_template("http://x:3000/about/"), "/about");
        assert_eq!(route_template("http://x:3000/page#section"), "/page");
        assert_eq!(route_template("/#/basket"), "/#/basket");
        assert_eq!(route_template("/reports?tab=x"), "/reports");
        assert_eq!(route_template("/page#top"), "/page");
        assert_eq!(route_template(""), "/");
        assert_eq!(route_template("http://x/"), "/");
    }

    #[test]
    fn route_canon_prefers_static_then_specific_dynamic() {
        let routes = vec![
            DiscoveredRoute {
                path: "/blog/:slug".into(),
                dynamic: true,
                kind: "page".into(),
                ..Default::default()
            },
            DiscoveredRoute {
                path: "/blog/new".into(),
                kind: "page".into(),
                ..Default::default()
            },
            DiscoveredRoute {
                path: "/docs/[...rest]".into(),
                dynamic: true,
                kind: "page".into(),
                ..Default::default()
            },
            DiscoveredRoute {
                path: "/api/users/:id".into(),
                dynamic: true,
                kind: "api".into(),
                ..Default::default()
            },
        ];
        let canon = RouteCanon::new(&routes);
        assert_eq!(canon.route("http://x/blog/hello-world"), "/blog/:slug");
        assert_eq!(canon.route("http://x/blog/new"), "/blog/new");
        assert_eq!(canon.route("http://x/blog/42"), "/blog/:slug");
        assert_eq!(canon.route("http://x/docs/a/b/c"), "/docs/[...rest]");
        assert_eq!(canon.route("http://x/api/users/1"), "/api/users/:id");
        assert_eq!(canon.route("http://x/other"), "/other");
    }

    #[test]
    fn route_matches_goal_forms() {
        assert!(route_matches("/products/:id", "/products/42"));
        assert!(route_matches("/#/basket", "/basket"));
        assert!(route_matches("/#/basket", "/#/basket"));
        assert!(!route_matches("/cart", "/checkout"));
    }

    #[test]
    fn locator_preference_order() {
        let both = [
            loc(LocatorKind::TestId, r#"[data-testid="buy-btn"]"#),
            loc(LocatorKind::Id, "#buy"),
        ];
        assert_eq!(
            choose_locator(&both, "#buy", "button", "header", "Buy", None).locator,
            "testid=buy-btn",
            "declared handles carry no region"
        );
        let id = [
            loc(LocatorKind::Id, "#buy"),
            loc(LocatorKind::Aria, r#"button[aria-label="Buy now"]"#),
        ];
        assert_eq!(
            choose_locator(&id, "#buy", "button", "main", "Buy", None).locator,
            "id=buy"
        );
        let generated = [
            loc(LocatorKind::Id, "#mat-select-0"),
            loc(LocatorKind::Aria, r#"div[aria-label="Items per page"]"#),
        ];
        assert_eq!(
            choose_locator(&generated, "#mat-select-0", "select", "main", "16", None).locator,
            "aria=items per page"
        );
        let name = [loc(LocatorKind::Name, r#"input[name="email"]"#)];
        assert_eq!(
            choose_locator(&name, "x", "input", "footer", "", None).locator,
            "name=email@footer"
        );
        // Links are identified by label and region; the href is an outcome.
        assert_eq!(
            choose_locator(
                &[],
                "main > a:nth-of-type(2)",
                "link",
                "main",
                "Cart (3)",
                Some("/cart")
            )
            .locator,
            "text=cart (#)"
        );
        assert_eq!(
            choose_locator(
                &[],
                "footer > a",
                "link",
                "footer",
                "Contact",
                Some("/contact")
            )
            .locator,
            "text=contact@footer"
        );
        // Unlabeled links fall back to their target.
        assert_eq!(
            choose_locator(
                &[],
                "footer > a",
                "link",
                "footer",
                "",
                Some("https://x.com/y")
            )
            .locator,
            "href=https://x.com/y@footer"
        );
        let text = choose_locator(
            &[],
            "main > button",
            "button",
            "main",
            "  Add  to Cart (3) ",
            None,
        );
        assert_eq!(text.locator, "text=add to cart (#)");
        assert!(!text.needs_ordinal);
        let empty = choose_locator(&[], "main > button", "button", "main", "", None);
        assert_eq!(empty.locator, "text=");
        assert!(empty.needs_ordinal);
        // Date-bearing aria labels (calendar cells) fold to one identity.
        let day = |aria: &str| {
            choose_locator(
                &[loc(
                    LocatorKind::Aria,
                    &format!(r#"button[aria-label="{aria}"]"#),
                )],
                "x",
                "button",
                "main",
                "",
                None,
            )
            .locator
        };
        assert_eq!(day("Nov 10, 2026, open"), "aria=#");
        assert_eq!(day("Dec 1, 2026, booked"), "aria=#");
    }

    #[test]
    fn labels_fold_numbers_dates_and_times() {
        for (raw, want) in [
            ("Nov 10, 2026, open", "#"),
            ("Oct 12, 9:33 PM", "#"),
            ("Expected 9:29 PM", "expected #"),
            ("IS-PV00000LV198 Expected 10:36 PM", "is-pv#lv# expected #"),
            ("All 17", "all #"),
            ("From orders 2", "from orders #"),
            ("2026-10-21", "#"),
            ("Mon, Oct 21", "#"),
            ("Book Nov 10", "book #"),
            ("v3 \u{00b7} saved 10:34:32 PM", "v# \u{00b7} saved #"),
            ("Page 2 of 10", "page # of #"),
            ("May I help?", "may i help?"),
            ("Switch to dark mode", "switch to dark mode"),
            ("Add  to Cart (3)", "add to cart (#)"),
        ] {
            assert_eq!(normalize_text(raw), want, "{raw}");
        }
    }

    #[test]
    fn regions_come_from_the_outermost_landmark() {
        assert_eq!(
            region_of(
                ["header:nth-of-type(1) > div > nav:nth-of-type(1) > ul > li > a"],
                true
            ),
            "header"
        );
        assert_eq!(
            region_of(["html > body > div > main > footer > nav > a"], false),
            "main",
            "a <footer> inside <main> is content"
        );
        assert_eq!(region_of(["body > div > aside > nav > a"], false), "aside");
        assert_eq!(region_of(["body > footer > ul > li > a"], false), "footer");
        assert_eq!(
            region_of(["body > dialog > div > nav > a"], false),
            "dialog"
        );
        assert_eq!(region_of([r#"div[role="navigation"] > a"#], false), "nav");
        assert_eq!(
            region_of([r#"button[aria-label="Open main menu"]"#], false),
            "main",
            "landmark words inside attribute values do not count"
        );
        assert_eq!(region_of(["div > ul > li > a"], true), "nav");
        assert_eq!(region_of(["div > button"], false), "main");
        // First path with a landmark wins (structural before selector).
        assert_eq!(region_of(["div > a", "body > header > a"], false), "header");
    }

    #[test]
    fn route_canon_keeps_enumerated_params_and_skips_error_pages() {
        let routes = vec![
            DiscoveredRoute {
                path: "/:view".into(),
                dynamic: true,
                kind: "page".into(),
                file: "src/app/[view]/page.tsx".into(),
                examples: vec!["/universe".into(), "/strategies".into()],
                ..Default::default()
            },
            DiscoveredRoute {
                path: "/lab".into(),
                kind: "page".into(),
                ..Default::default()
            },
            DiscoveredRoute {
                path: "/404".into(),
                kind: "page".into(),
                file: "src/pages/404.astro".into(),
                ..Default::default()
            },
            DiscoveredRoute {
                path: "/api/availability/:slug".into(),
                dynamic: true,
                kind: "api".into(),
                ..Default::default()
            },
        ];
        let canon = RouteCanon::new(&routes);
        assert_eq!(canon.route("http://x/universe"), "/universe");
        assert_eq!(canon.route("http://x/strategies"), "/strategies");
        assert_eq!(canon.route("http://x/other"), "/:view");
        assert!(canon.knows_routes());
        assert!(canon.is_known("/universe"));
        assert!(canon.is_known("/:view"));
        assert!(canon.is_known("/api/availability/:id"));
        assert!(!canon.is_known("/legal/terms"));
        assert_eq!(
            select_routes(["/lab", "/:view"], "/lab"),
            vec!["/lab"],
            "exact static route beats a matching template"
        );
        assert_eq!(select_routes(["/:view"], "/settings"), vec!["/:view"]);
    }

    #[test]
    fn generated_ids_detected() {
        for id in [
            ":r1:",
            "radix-:r0:",
            "radix-_r_2_",
            "radix-_r_c_",
            "cb_r_9_",
            "_r_o_",
            "f_r_0_",
            "_R_1a2b_",
            "mat-select-0",
            "headlessui-menu-button-3",
            "headlessui-listbox-button",
            "react-aria-trigger",
            "mui-select",
            "chakra-modal-header",
            "radix-12",
            "ember1234",
            "css-1x2y3z",
        ] {
            assert!(is_generated_id(id), "{id} should be generated");
        }
        for id in [
            "checkoutButton",
            "navbarLanguageButton",
            "buy",
            "search-input",
            "main-nav",
            "user_role_select",
        ] {
            assert!(!is_generated_id(id), "{id} should be stable");
        }
    }

    #[test]
    fn react19_generated_ids_and_unread_badges_produce_stable_locators() {
        assert_eq!(normalize_text("Messages 3 unread"), "messages # unread");
        assert_eq!(normalize_text("Messages 2 unread"), "messages # unread");
        assert_eq!(normalize_text("Messages 99+ unread"), "messages # unread");
        assert_eq!(
            normalize_text("Messages 3 unread"),
            normalize_text("Messages 2 unread")
        );

        let csm = choose_locator(
            &[loc(LocatorKind::Id, "#radix-_r_2_")],
            "#radix-_r_2_",
            "link",
            "nav",
            "Messages 3 unread",
            Some("/messages"),
        );
        let owner = choose_locator(
            &[loc(LocatorKind::Id, "#radix-_r_c_")],
            "#radix-_r_c_",
            "link",
            "nav",
            "Messages 2 unread",
            Some("/messages"),
        );
        assert_eq!(csm.locator, "text=messages # unread@nav");
        assert_eq!(csm.locator, owner.locator);

        for generated_id in ["radix-_r_2_", "cb_r_9_", "_r_o_", "f_r_0_"] {
            let sel = format!("#{generated_id}");
            let chosen = choose_locator(
                &[
                    loc(LocatorKind::Id, &sel),
                    loc(LocatorKind::Aria, r#"button[aria-label="Export CSV"]"#),
                ],
                &sel,
                "button",
                "main",
                "Export CSV",
                None,
            );
            assert_eq!(
                chosen.locator, "aria=export csv",
                "{generated_id} should not become an id= locator"
            );
        }
    }

    #[test]
    fn selector_helpers() {
        assert_eq!(
            quoted_attr(r#"a[aria-label="say \"hi\""]"#, "aria-label").as_deref(),
            Some("say \"hi\"")
        );
        assert_eq!(id_from_selector("#buy").as_deref(), Some("buy"));
        assert_eq!(id_from_selector(r"#\31 23").as_deref(), Some("123"));
        assert_eq!(id_from_selector("#a > b"), None);
        assert_eq!(
            tag_from_selector("main > button:nth-of-type(2)").as_deref(),
            Some("button")
        );
        assert_eq!(
            tag_from_selector(r#"a[aria-label="x"]"#).as_deref(),
            Some("a")
        );
    }

    #[test]
    fn roles_from_kinds() {
        assert_eq!(role_for_kind_slug("navigation_link"), "link");
        assert_eq!(role_for_kind_slug("text_input"), "input");
        assert_eq!(role_for_kind_slug("dropdown_menu"), "button");
        assert_eq!(
            role_for_element(&ElementType::Other {
                tag: "div".into(),
                role: Some("button".into())
            }),
            "button"
        );
        assert_eq!(
            role_for_element(&ElementType::Other {
                tag: "section".into(),
                role: None
            }),
            "other"
        );
    }

    #[test]
    fn generated_ids_cover_modern_ui_libraries_and_count_plurals_fold() {
        for id in [
            "base-ui-_r_1v_",
            "base-ui-_r_24_-hidden-input",
            "base-ui-abc",
            "floating-ui-portal",
            "downshift-menu",
            "react-select-input",
            "ariakit-dialog",
            "reka-switch",
        ] {
            assert!(is_generated_id(id), "expected generated id: {id}");
        }
        assert!(!is_generated_id("save-settings"));
        assert!(!is_generated_id("email-input"));

        assert_eq!(
            fold_count_plurals("authorized clients # client"),
            fold_count_plurals("authorized clients # clients")
        );
        assert_eq!(
            fold_count_plurals("update # provider"),
            fold_count_plurals("update # providers")
        );
        assert_eq!(
            fold_count_plurals("# entry"),
            fold_count_plurals("# entries")
        );
        assert_eq!(
            fold_count_plurals("# match"),
            fold_count_plurals("# matches")
        );
        assert_eq!(fold_count_plurals("delete (#) items?"), "delete (#) item?");
        // Non-plural words ending in s or not preceded by `#` stay untouched.
        assert_eq!(fold_count_plurals("# status"), "# status");
        assert_eq!(fold_count_plurals("settings"), "settings");
    }
}
