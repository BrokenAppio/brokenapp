use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{LazyLock, RwLock};

use url::Url;

/// Returns `true` for browser-generated internal/error document URLs
/// (`chrome-error://chromewebdata/`, `chrome://...`, `about:neterror`,
/// `edge://...`, `devtools://...`, `data:...`, `blob:...`, `view-source:...`),
/// including legacy slash-prefixed routes such as `/chrome-error://chromewebdata`.
pub fn is_browser_internal_url(raw: &str) -> bool {
    let trimmed = raw.trim().trim_start_matches('/');
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("chrome-error://")
        || lower.starts_with("chrome://")
        || lower.starts_with("chrome-extension://")
        || lower.starts_with("edge://")
        || lower.starts_with("edge-error://")
        || lower.starts_with("about:")
        || lower.starts_with("devtools://")
        || lower.starts_with("view-source:")
        || lower.starts_with("data:")
        || lower.starts_with("blob:")
        || lower.starts_with("javascript:")
        || lower.contains("chrome-error://")
}

static REGISTERED_ROUTE_FRAGMENTS: LazyLock<RwLock<HashSet<String>>> =
    LazyLock::new(|| RwLock::new(HashSet::new()));

fn normalize_route_fragment_token(fragment: &str) -> Option<String> {
    let f = fragment.trim().trim_start_matches('#').trim();
    let path = f.split_once('?').map_or(f, |(p, _)| p).trim();
    if path.is_empty()
        || !path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return None;
    }
    Some(path.to_ascii_lowercase())
}

/// Register a bare hash token (e.g. `operations`, `calendar`) observed from a
/// non-scroll client-side navigation or explicit route seed so subsequent URL
/// canonicalization and view restoration treat `#token` as a client-side route.
pub fn register_route_fragment(fragment: &str) {
    if let Some(token) = normalize_route_fragment_token(fragment)
        && let Ok(mut set) = REGISTERED_ROUTE_FRAGMENTS.write()
    {
        set.insert(token);
    }
}

pub fn register_route_fragment_from_url(raw_url: &str) {
    if let Ok(url) = Url::parse(raw_url) {
        if matches!(url.path(), "" | "/" | "/index.html")
            && let Some(frag) = url.fragment()
        {
            register_route_fragment(frag);
        }
    } else if let Some((before_hash, frag)) = raw_url.split_once('#') {
        let base_path = before_hash
            .split_once('?')
            .map_or(before_hash, |(p, _)| p)
            .trim();
        if matches!(base_path, "" | "/" | "/index.html") {
            register_route_fragment(frag);
        }
    }
}

fn is_registered_route_fragment(fragment: &str) -> bool {
    let Some(token) = normalize_route_fragment_token(fragment) else {
        return false;
    };
    REGISTERED_ROUTE_FRAGMENTS
        .read()
        .map(|set| set.contains(&token))
        .unwrap_or(false)
}

fn is_explicit_route_fragment(fragment: Option<&str>) -> bool {
    let Some(raw) = fragment else {
        return false;
    };
    let f = raw.trim().trim_start_matches('#').trim();
    if f.is_empty() {
        return false;
    }
    f.starts_with('!') || f.starts_with('/') || f.contains('/') || f.contains('?')
}

fn url_has_route_fragment(url: &Url) -> bool {
    let frag = url.fragment();
    is_explicit_route_fragment(frag)
        || (matches!(url.path(), "" | "/" | "/index.html") && fragment_is_route(frag))
}

pub(super) fn diff_query_keys(before_url: &str, after_url: &str) -> Vec<String> {
    let (Ok(before), Ok(after)) = (Url::parse(before_url), Url::parse(after_url)) else {
        return Vec::new();
    };

    let (before_path, before_query) = effective_url_path_and_query(&before);
    let (after_path, after_query) = effective_url_path_and_query(&after);

    // Only correlate controls that tweak query params on the same route.
    if before.scheme() != after.scheme()
        || before.host_str() != after.host_str()
        || before.port_or_known_default() != after.port_or_known_default()
        || before_path != after_path
    {
        return Vec::new();
    }

    let before_q = query_map_str(before_query.as_deref());
    let after_q = query_map_str(after_query.as_deref());

    let mut changed: BTreeSet<String> = BTreeSet::new();
    for k in before_q.keys().chain(after_q.keys()) {
        let b = before_q.get(k);
        let a = after_q.get(k);
        if b != a {
            changed.insert(k.clone());
        }
    }

    changed.into_iter().collect()
}

fn query_map_str(raw_query: Option<&str>) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let Some(q) = raw_query else {
        return map;
    };
    for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
        map.entry(k.into_owned()).or_default().push(v.into_owned());
    }
    for vals in map.values_mut() {
        vals.sort();
        vals.dedup();
    }
    map
}

fn is_non_semantic_query_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if k.starts_with("utm_") {
        return true;
    }

    matches!(
        k.as_str(),
        "fbclid"
            | "gclid"
            | "msclkid"
            | "ref"
            | "source"
            | "sort"
            | "order"
            | "dir"
            | "direction"
            | "page"
            | "page_size"
            | "pagesize"
            | "per_page"
            | "perpage"
            | "limit"
            | "offset"
            | "cursor"
            | "after"
            | "before"
            | "q"
            | "query"
            | "search"
            | "filter"
            | "filters"
            | "range"
            | "to"
            | "start"
            | "end"
            | "start_date"
            | "end_date"
            | "date_from"
            | "date_to"
    )
}

fn is_login_route_path(raw_path: &str) -> bool {
    let trimmed = raw_path.trim().trim_start_matches('!');
    let segments: Vec<String> = trimmed
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let refs: Vec<&str> = segments.iter().map(String::as_str).collect();
    matches!(
        refs.as_slice(),
        ["login" | "sign-in" | "signin" | "sign_in"]
            | [
                "auth" | "users" | "account",
                "login" | "sign-in" | "signin" | "sign_in",
            ]
    )
}

fn is_login_redirect_query_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "next"
            | "redirect"
            | "redirectto"
            | "redirect_to"
            | "returnto"
            | "return_to"
            | "callbackurl"
            | "callback_url"
            | "from"
            | "continue"
            | "goto"
            | "return"
            | "r"
    )
}

/// Returns true when a URL fragment looks like a client-side route (hash router)
/// rather than a plain in-page anchor. Hash routers (Angular/React/Vue/...) encode
/// the route in the fragment, e.g. `/#/administration` or `#!/users/42`. Stripping
/// those fragments collapses distinct routes into one view and silently drops
/// entire SPAs from the graph, so they must be preserved.
pub fn fragment_is_route(fragment: Option<&str>) -> bool {
    let Some(raw) = fragment else {
        return false;
    };
    let f = raw.trim().trim_start_matches('#').trim();
    if f.is_empty() {
        return false;
    }
    if is_explicit_route_fragment(Some(f)) {
        return true;
    }
    // Dynamically observed or seeded bare hash route (e.g. `#operations`, `#calendar`).
    is_registered_route_fragment(f)
}

/// Extract the effective route path and optional query string for a URL,
/// preserving client-side hash routes (`/#/administration`, `#!/users/42?tab=details`)
/// instead of collapsing them into `/`.
pub fn effective_url_path_and_query(url: &Url) -> (String, Option<String>) {
    if url_has_route_fragment(url) {
        let raw_frag = url
            .fragment()
            .unwrap_or_default()
            .trim()
            .trim_start_matches('#')
            .trim();
        let (frag_path, frag_query) = match raw_frag.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (raw_frag, None),
        };
        let base_path = url.path().trim_end_matches('/');
        let route_path = format!("{base_path}/#{frag_path}");
        let query = frag_query
            .filter(|q| !q.is_empty())
            .map(str::to_string)
            .or_else(|| url.query().filter(|q| !q.is_empty()).map(str::to_string));
        (route_path, query)
    } else {
        let path = if url.path().is_empty() {
            "/".to_string()
        } else {
            url.path().to_string()
        };
        let query = url.query().filter(|q| !q.is_empty()).map(str::to_string);
        (path, query)
    }
}

fn encode_query(mut pairs: Vec<(String, String)>) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    pairs.sort();
    pairs.dedup();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(&key, &value);
    }
    Some(serializer.finish())
}

fn canonical_query(raw: Option<&str>, strip_login_redirect: bool) -> Option<String> {
    encode_query(
        url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes())
            .filter(|(key, _)| {
                !is_non_semantic_query_key(key)
                    && !(strip_login_redirect && is_login_redirect_query_key(key))
            })
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
    )
}

/// Finite UI selections reached through actual navigation must keep their
/// own view/control identity, even when two tabs share a DOM skeleton.
/// Search, paging and tracking variants continue to share their old scope.
pub(super) fn ui_state_scope(scope: String, raw_url: &str) -> String {
    let Ok(url) = Url::parse(raw_url) else {
        return scope;
    };
    let (_, query) = effective_url_path_and_query(&url);
    let state = encode_query(
        url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
            .filter(|(key, _)| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "tab" | "view" | "layout" | "section"
                )
            })
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
    );
    state.map_or_else(|| scope.clone(), |query| format!("{scope}?{query}"))
}

fn canonicalize_crawl_url_in_place(url: &mut Url) {
    // Apply the same query policy to browser and hash routers. Only observed
    // links/transitions are queued; retaining UI selections invents no values.
    let mut strip_login_redirect = is_login_route_path(url.path());
    if url_has_route_fragment(url) {
        let fragment = url.fragment().unwrap_or_default().to_string();
        let (path, frag_query) = match fragment.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (fragment.as_str(), None),
        };
        let frag_is_login = is_login_route_path(path);
        strip_login_redirect = strip_login_redirect || frag_is_login;
        if let Some(query) = frag_query {
            let fragment = canonical_query(Some(query), frag_is_login)
                .map_or_else(|| path.to_string(), |query| format!("{path}?{query}"));
            url.set_fragment(Some(&fragment));
        }
    } else {
        url.set_fragment(None);
    }
    let query = canonical_query(url.query(), strip_login_redirect);
    url.set_query(query.as_deref());
}

pub(super) fn canonicalize_crawl_url(raw: &str) -> String {
    if let Ok(mut parsed) = Url::parse(raw) {
        canonicalize_crawl_url_in_place(&mut parsed);
        parsed.to_string()
    } else if let Some((before_hash, frag)) = raw.split_once('#') {
        let base_path = before_hash
            .split_once('?')
            .map_or(before_hash, |(p, _)| p)
            .trim();
        let keep_frag = is_explicit_route_fragment(Some(frag))
            || (matches!(base_path, "" | "/" | "/index.html") && fragment_is_route(Some(frag)));
        if keep_frag {
            raw.to_string()
        } else {
            before_hash.to_string()
        }
    } else {
        raw.to_string()
    }
}

pub(super) fn normalize_href(base: &Url, current: Option<&Url>, href: &str) -> Option<Url> {
    let href = href.trim();
    if href.is_empty() {
        return None;
    }
    let lower = href.to_ascii_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("mailto:") || lower.starts_with("tel:")
    {
        return None;
    }

    // Hash-only hrefs: keep them when they encode a client-side route, so SPA
    // navigation links are discovered instead of silently dropped. They are
    // relative to the current document (an SPA mounted at `/app.html` routes
    // to `/app.html#/x`), not to the scan target.
    if href.starts_with('#') {
        if !fragment_is_route(Some(&href[1..])) {
            return None;
        }
        let mut u = current
            .filter(|cur| same_origin(base, cur))
            .unwrap_or(base)
            .clone();
        u.set_fragment(Some(&href[1..]));
        canonicalize_crawl_url_in_place(&mut u);
        return Some(u);
    }

    let resolved = if let Ok(u) = Url::parse(href) {
        u
    } else if let Some(cur) = current {
        cur.join(href).ok()?
    } else {
        base.join(href).ok()?
    };

    if !same_origin(base, &resolved) {
        return None;
    }

    let mut u = resolved;
    canonicalize_crawl_url_in_place(&mut u);
    Some(u)
}

pub(super) fn same_origin(a: &Url, b: &Url) -> bool {
    crate::url_origin::same_origin(a, b)
}

#[cfg(test)]
mod tests {
    use super::{
        canonicalize_crawl_url, effective_url_path_and_query, fragment_is_route,
        is_browser_internal_url, normalize_href, register_route_fragment, same_origin,
    };
    use url::Url;

    #[test]
    fn browser_internal_urls_are_recognized() {
        assert!(is_browser_internal_url("chrome-error://chromewebdata/"));
        assert!(is_browser_internal_url("/chrome-error://chromewebdata"));
        assert!(is_browser_internal_url("about:neterror"));
        assert!(is_browser_internal_url("about:blank"));
        assert!(is_browser_internal_url("chrome://settings"));
        assert!(is_browser_internal_url("edge://settings"));
        assert!(!is_browser_internal_url("http://127.0.0.1:8080/home"));
        assert!(!is_browser_internal_url("/dashboard"));
    }

    #[test]
    fn canonicalize_crawl_url_drops_non_semantic_params() {
        let got = canonicalize_crawl_url(
            "https://app.example.com/dashboard?sort=name&dir=asc&range=30d&client_id=42",
        );
        assert_eq!(got, "https://app.example.com/dashboard?client_id=42");
    }

    #[test]
    fn canonicalize_crawl_url_sorts_and_dedupes_kept_params() {
        let got =
            canonicalize_crawl_url("https://app.example.com/r?a=2&b=3&a=2&page=9&a=1&tab=metrics");
        assert_eq!(got, "https://app.example.com/r?a=1&a=2&b=3&tab=metrics");
    }

    #[test]
    fn ui_state_queries_survive_browser_and_hash_canonicalization() {
        for route in ["/account", "/#/account"] {
            let raw = format!(
                "https://app.example.com{route}?tab=payout&view=details&layout=wide&utm_source=mail&page=2&q=test"
            );
            assert_eq!(
                canonicalize_crawl_url(&raw),
                format!("https://app.example.com{route}?layout=wide&tab=payout&view=details")
            );
            assert_eq!(
                super::ui_state_scope(route.into(), &raw),
                format!("{route}?layout=wide&tab=payout&view=details")
            );
        }
        assert_eq!(
            super::ui_state_scope(
                "/account".into(),
                "https://app.example.com/account?page=2&q=test"
            ),
            "/account"
        );
    }

    #[test]
    fn normalize_href_applies_canonicalization() {
        let base = Url::parse("https://app.example.com/dashboard").unwrap();
        let cur = Url::parse("https://app.example.com/dashboard").unwrap();
        let got = normalize_href(
            &base,
            Some(&cur),
            "/dashboard?sort=name&dir=asc&client_id=7#frag",
        )
        .unwrap();
        assert_eq!(
            got.as_str(),
            "https://app.example.com/dashboard?client_id=7"
        );
    }

    #[test]
    fn same_origin_treats_localhost_aliases_as_equivalent() {
        let localhost = Url::parse("http://localhost:3000/dashboard").unwrap();
        let loopback = Url::parse("http://127.0.0.1:3000/dashboard").unwrap();
        let unspecified = Url::parse("http://0.0.0.0:3000/dashboard").unwrap();
        let ipv6 = Url::parse("http://[::1]:3000/dashboard").unwrap();

        assert!(same_origin(&localhost, &loopback));
        assert!(same_origin(&localhost, &unspecified));
        assert!(same_origin(&localhost, &ipv6));
    }

    #[test]
    fn canonicalize_preserves_hash_routes() {
        let got = canonicalize_crawl_url("https://app.example.com/#/administration");
        assert_eq!(got, "https://app.example.com/#/administration");
        let got2 = canonicalize_crawl_url("https://app.example.com/#/users/42?tab=details");
        assert_eq!(got2, "https://app.example.com/#/users/42?tab=details");
    }

    #[test]
    fn canonicalize_preserves_query_and_registered_bare_hash_routes() {
        let got = canonicalize_crawl_url(
            "https://app.example.com/#operations?property=prop-1&section=inbox&page=2",
        );
        assert_eq!(
            got,
            "https://app.example.com/#operations?property=prop-1&section=inbox"
        );

        register_route_fragment("calendar");
        assert!(fragment_is_route(Some("calendar")));
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/#calendar"),
            "https://app.example.com/#calendar"
        );
        let url = Url::parse("https://app.example.com/#calendar").unwrap();
        assert_eq!(
            effective_url_path_and_query(&url),
            ("/#calendar".to_string(), None)
        );
        // A bare registered fragment on a non-root path is still an in-page anchor.
        let deep = Url::parse("https://app.example.com/records/123?tab=one#calendar").unwrap();
        assert_eq!(
            effective_url_path_and_query(&deep),
            ("/records/123".to_string(), Some("tab=one".to_string()))
        );
    }

    #[test]
    fn canonicalize_strips_plain_anchors() {
        let got = canonicalize_crawl_url("https://app.example.com/page#section");
        assert_eq!(got, "https://app.example.com/page");
    }

    #[test]
    fn normalize_href_keeps_hash_routes() {
        let base = Url::parse("https://app.example.com/").unwrap();
        let cur = Url::parse("https://app.example.com/").unwrap();
        let got = normalize_href(&base, Some(&cur), "#/administration").unwrap();
        assert_eq!(got.as_str(), "https://app.example.com/#/administration");
        let got2 = normalize_href(&base, Some(&cur), "/#/users/42").unwrap();
        assert_eq!(got2.as_str(), "https://app.example.com/#/users/42");
        let got3 = normalize_href(&base, Some(&cur), "#!/users/42").unwrap();
        assert_eq!(got3.as_str(), "https://app.example.com/#!/users/42");
        assert!(normalize_href(&base, Some(&cur), "#section").is_none());
    }

    #[test]
    fn canonicalize_collapses_login_redirect_params_only_on_login_routes() {
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/login?next=%2Fsales"),
            "https://app.example.com/login"
        );
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/login?next=%2Fadmin"),
            "https://app.example.com/login"
        );
        assert_eq!(
            canonicalize_crawl_url(
                "https://app.example.com/auth/sign-in?callbackUrl=%2Fdashboard&tab=sso"
            ),
            "https://app.example.com/auth/sign-in?tab=sso"
        );
        assert_eq!(
            canonicalize_crawl_url(
                "https://app.example.com/sign-in?return_to=%2Fsettings&error=CredentialsSignin"
            ),
            "https://app.example.com/sign-in?error=CredentialsSignin"
        );
        assert_eq!(
            canonicalize_crawl_url(
                "https://app.example.com/users/sign_in?redirect_to=%2Fbilling&r=%2Fhome"
            ),
            "https://app.example.com/users/sign_in"
        );
        assert_eq!(
            canonicalize_crawl_url(
                "https://app.example.com/account/login?from=%2Forders&continue=%2Fcart&goto=%2Fpay&return=%2F"
            ),
            "https://app.example.com/account/login"
        );
        assert_eq!(
            canonicalize_crawl_url(
                "https://app.example.com/auth/signin?callback_url=%2Fx&redirectTo=%2Fy&returnTo=%2Fz"
            ),
            "https://app.example.com/auth/signin"
        );
        // Hash-routed login pages strip redirect params while keeping UI state tabs.
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/#/login?next=%2Fadmin&tab=magic"),
            "https://app.example.com/#/login?tab=magic"
        );
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/#!/auth/login?redirect=%2Fops"),
            "https://app.example.com/#!/auth/login"
        );
        // Non-login pages keep `from`, `next`, and non-whole-segment lookalikes untouched.
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/orders?from=2026-01-01"),
            "https://app.example.com/orders?from=2026-01-01"
        );
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/wizard?next=step-2"),
            "https://app.example.com/wizard?next=step-2"
        );
        assert_eq!(
            canonicalize_crawl_url("https://app.example.com/login-help?next=%2Ffaq"),
            "https://app.example.com/login-help?next=%2Ffaq"
        );
    }
}
