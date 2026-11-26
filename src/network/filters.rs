use std::collections::BTreeMap;

use url::Url;

use crate::types::api::{ApiEndpoint, HttpMethod, TrafficEntry};

fn strip_optional_port(host: &str) -> &str {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return &host[..=end];
        }
        return host;
    }
    match host.split_once(':') {
        Some((h, port)) if !port.contains(':') => h,
        _ => host,
    }
}

/// True when `host` matches at least one entry in `allowlist`.
///
/// Entries are matched case-insensitively (ignoring trailing dots and optional
/// `:port` suffixes):
/// - `example.com` matches only `example.com`
/// - `*.example.com` matches strict subdomains (`api.example.com`,
///   `a.b.example.com`), never `evil-example.com` or bare `example.com`
pub fn host_matches_allowlist(host: &str, allowlist: &[String]) -> bool {
    let host = strip_optional_port(host.trim())
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    allowlist.iter().any(|raw| {
        let pat = strip_optional_port(raw.trim())
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if pat.is_empty() {
            return false;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            !suffix.is_empty()
                && host.len() > suffix.len() + 1
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        } else {
            host == pat
        }
    })
}

/// True when `url` is allowed under `allowlist`.
///
/// Non-network browser schemes (`about:`, `data:`, `blob:`, `javascript:`) are
/// always allowed; `http:`, `https:`, `ws:`, and `wss:` URLs fail closed unless
/// their host matches `allowlist`.
pub fn url_matches_allowed_hosts(url: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https" | "ws" | "wss") {
        return true;
    }
    parsed
        .host_str()
        .is_some_and(|host| host_matches_allowlist(host, allowlist))
}

/// Dev-server / bundler HMR, source-module, and error-overlay tooling paths
/// (Next.js, Webpack, Turbopack, Vite, Astro, Nuxt). These are framework
/// infrastructure, never app APIs or interaction-attributed requests.
pub fn is_dev_tool_or_hmr_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == "/_next/webpack-hmr"
        || lower.starts_with("/_next/webpack-hmr/")
        || lower.starts_with("/__nextjs")
        || lower.starts_with("/__webpack")
        || lower.starts_with("/__vite")
        || lower.starts_with("/@vite/")
        || lower.starts_with("/@fs/")
        || lower.starts_with("/@id/")
        || lower.starts_with("/@react-refresh")
        || lower.starts_with("/__turbopack")
        || lower.starts_with("/_astro/")
        || lower.starts_with("/__astro")
        || lower.starts_with("/_nuxt/")
        || lower.starts_with("/__nuxt")
        || lower.starts_with("/__wrangler")
        || lower.starts_with("/__open-in-editor")
        || lower.starts_with("/node_modules/.vite/")
}

/// Content-Type or Accept value indicating a Server-Sent Events stream.
pub fn is_sse_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
}

/// Path heuristic for browser-emitted CSP / Reporting API telemetry beacons.
pub fn is_csp_or_telemetry_report_path(path: &str) -> bool {
    let lower = path.trim_end_matches('/').to_ascii_lowercase();
    lower == "/csp-report"
        || lower.ends_with("/csp-report")
        || lower.ends_with("/csp-reports")
        || lower.ends_with("/csp_report")
        || lower.contains("/csp-report/")
        || lower.ends_with("/report-to")
        || lower.ends_with("/nel-report")
}

/// Content-Type heuristic for browser-emitted CSP / Reporting API telemetry beacons.
pub fn is_csp_or_telemetry_content_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.contains("application/csp-report") || lower.contains("application/reports+json")
}

/// True when a request path or Content-Type identifies a browser telemetry /
/// CSP report beacon rather than an application API endpoint.
pub fn is_csp_or_telemetry_report(path: &str, content_type: Option<&str>) -> bool {
    is_csp_or_telemetry_report_path(path)
        || content_type.is_some_and(is_csp_or_telemetry_content_type)
}

/// Path heuristic for background session-renewal, heartbeat, keepalive, and
/// health-check polling endpoints that should not be attributed to individual
/// UI controls.
pub fn is_background_heartbeat_or_poll_path(path: &str) -> bool {
    let path = endpoint_template_path(path);
    let path = path.split('?').next().unwrap_or(path);
    let lower = path.to_ascii_lowercase();
    let segs: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
    let Some(&last) = segs.last() else {
        return false;
    };

    if matches!(
        last,
        "heartbeat" | "keepalive" | "keep-alive" | "keep_alive" | "healthz" | "readyz" | "livez"
    ) {
        return true;
    }

    if segs.len() >= 2 {
        let prev = segs[segs.len() - 2];
        if prev == "session"
            && matches!(
                last,
                "renew" | "refresh" | "keepalive" | "keep-alive" | "keep_alive" | "ping"
            )
        {
            return true;
        }
    }

    if matches!(last, "health" | "ping") && segs.first() == Some(&"api") {
        return match segs.len() {
            2 => true,
            3 => {
                let mid = segs[1];
                mid.starts_with('v')
                    && mid.len() >= 2
                    && mid[1..].bytes().all(|b| b.is_ascii_digit())
            }
            _ => false,
        };
    }

    false
}

fn header_value_ci<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn looks_like_static_asset_path(path: &str) -> bool {
    if path.starts_with("/_next/") || is_dev_tool_or_hmr_path(path) {
        return true;
    }
    if path.starts_with("/static/")
        || path.starts_with("/assets/")
        || path.starts_with("/public/")
        || path.starts_with("/node_modules/")
    {
        return true;
    }

    let lower = path.to_ascii_lowercase();
    let static_extensions = [
        ".js",
        ".mjs",
        ".cjs",
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".map",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".avif",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
        ".ogg",
        ".wasm",
        ".webmanifest",
    ];
    if static_extensions.iter().any(|ext| lower.ends_with(ext)) {
        return true;
    }
    // Dev-server raw source modules (Vite serves `.ts`/`.tsx`/`.jsx` over HTTP).
    if !lower.starts_with("/api/") {
        let dev_module_extensions = [".ts", ".tsx", ".jsx", ".mts", ".cts"];
        if dev_module_extensions.iter().any(|ext| lower.ends_with(ext)) {
            return true;
        }
    }
    false
}

/// True when a completed `GET`/`HEAD` request is a successful (2xx / 304)
/// static asset or dev-server module/HMR request that should be omitted from
/// `network.jsonl` and endpoint aggregation.
///
/// Always keeps:
/// - non-GET/HEAD requests (POST/PUT/PATCH/DELETE/WS);
/// - errors (status >= 400 or transport failure) so broken assets stay visible;
/// - HTML documents and redirects (needed for route status & passive header checks);
/// - JSON / GraphQL API responses.
pub fn is_static_or_dev_module_noise(entry: &TrafficEntry) -> bool {
    if !matches!(entry.request.method, HttpMethod::Get | HttpMethod::Head) {
        return false;
    }
    if entry.failure.is_some() {
        return false;
    }
    if let Some(resp) = entry.response.as_ref()
        && !(resp.status < 300 || resp.status == 304)
    {
        return false;
    }
    if entry.is_api == Some(true) {
        return false;
    }
    let fetch_dest = header_value_ci(&entry.request.headers, "sec-fetch-dest");
    if fetch_dest.is_some_and(|d| d.eq_ignore_ascii_case("document")) {
        return false;
    }
    let resp_mime = entry
        .response
        .as_ref()
        .and_then(|r| r.mime_type.as_deref())
        .map(|m| m.to_ascii_lowercase());
    if resp_mime.as_deref().is_some_and(|m| {
        m.contains("html")
            || m.contains("application/json")
            || m.contains("application/graphql")
            || m.contains("application/problem+json")
    }) {
        return false;
    }

    let path = Url::parse(&entry.request.url)
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    if is_dev_tool_or_hmr_path(&path) || looks_like_static_asset_path(&path) {
        return true;
    }
    resp_mime.as_deref().is_some_and(|m| {
        m.starts_with("text/javascript")
            || m.starts_with("application/javascript")
            || m.starts_with("application/x-javascript")
            || m.starts_with("text/css")
            || m.starts_with("image/")
            || m.starts_with("font/")
            || m.starts_with("audio/")
            || m.starts_with("video/")
            || m.starts_with("application/font-")
            || m.starts_with("application/wasm")
            || m.starts_with("application/manifest+json")
    })
}

/// Path portion of an endpoint `path_template`.
///
/// Cross-origin keys carry their origin (`https://x.supabase.co/rest/v1/cart`)
/// and GraphQL / Server Action keys carry a `#...` operation suffix; both are
/// stripped so path heuristics see `/rest/v1/cart`.
pub fn endpoint_template_path(template: &str) -> &str {
    let without_suffix = template.split('#').next().unwrap_or(template);
    let Some(scheme_end) = without_suffix.find("://") else {
        return without_suffix;
    };
    let after_scheme = &without_suffix[scheme_end + 3..];
    match after_scheme.find('/') {
        Some(slash) => &after_scheme[slash..],
        None => "/",
    }
}

/// Determine if a captured endpoint is an application API vs infrastructure/static assets.
pub fn is_application_api(endpoint: &ApiEndpoint) -> bool {
    let path = endpoint_template_path(&endpoint.key.path_template);
    let req_ct = header_value_ci(&endpoint.request_headers, "content-type");
    let req_accept = header_value_ci(&endpoint.request_headers, "accept");

    // ---- EXCLUDE patterns (infrastructure / static assets / browser telemetry) ----
    if looks_like_static_asset_path(path)
        || is_dev_tool_or_hmr_path(path)
        || is_csp_or_telemetry_report(path, req_ct)
        || is_sse_content_type(req_accept)
    {
        return false;
    }

    // Preflight requests are not useful as part of an LLM-facing API surface.
    if endpoint.key.method == HttpMethod::Options {
        return false;
    }

    // ---- INCLUDE patterns (likely application APIs) ----
    if path.starts_with("/api/") || path.starts_with("/graphql") {
        return true;
    }

    // Mutating methods are almost always APIs.
    if endpoint.key.method != HttpMethod::Get && endpoint.key.method != HttpMethod::Head {
        return true;
    }

    // If we've captured JSON samples or inferred a JSON schema, this is an API.
    if endpoint.response_body_schema.is_some() || !endpoint.response_body_samples.is_empty() {
        return true;
    }

    false
}

/// Tag individual traffic entries so `network.jsonl` can be filtered downstream.
pub fn is_application_traffic(entry: &TrafficEntry) -> bool {
    let url = match Url::parse(&entry.request.url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let path = url.path();
    let req_ct = header_value_ci(&entry.request.headers, "content-type");
    let req_accept = header_value_ci(&entry.request.headers, "accept");
    let resp_mime = entry.response.as_ref().and_then(|r| r.mime_type.as_deref());

    if looks_like_static_asset_path(path)
        || is_dev_tool_or_hmr_path(path)
        || is_csp_or_telemetry_report(path, req_ct)
        || is_sse_content_type(resp_mime)
        || is_sse_content_type(req_accept)
    {
        return false;
    }

    // Preflight requests are infrastructure noise.
    if entry.request.method == HttpMethod::Options {
        return false;
    }

    if path.starts_with("/api/") || path.starts_with("/graphql") {
        return true;
    }

    if entry.request.method != HttpMethod::Get && entry.request.method != HttpMethod::Head {
        return true;
    }

    // Content-type heuristics.
    if let Some(ct) = resp_mime {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("text/html") {
            return false;
        }
        if ct.contains("application/json") || ct.contains("application/graphql") {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;

    use super::{
        endpoint_template_path, is_application_api, is_application_traffic,
        is_background_heartbeat_or_poll_path, is_csp_or_telemetry_report, is_dev_tool_or_hmr_path,
        is_sse_content_type, looks_like_static_asset_path,
    };
    use crate::types::api::{
        ApiEndpoint, EndpointKey, HttpMethod, HttpRequestLog, HttpResponseLog, TrafficEntry,
    };

    fn traffic(
        method: HttpMethod,
        url: &str,
        req_headers: &[(&str, &str)],
        resp_mime: Option<&str>,
    ) -> TrafficEntry {
        TrafficEntry {
            occurred_at: Utc::now(),
            trace: None,
            request: HttpRequestLog {
                method,
                url: url.to_string(),
                headers: req_headers
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect::<BTreeMap<_, _>>(),
                post_data: None,
            },
            response: resp_mime.map(|mime| HttpResponseLog {
                status: 200,
                headers: BTreeMap::new(),
                mime_type: Some(mime.to_string()),
                body_snippet: None,
            }),
            failure: None,
            triggered_by: None,
            is_api: None,
            duration_ms: None,
            attribution: None,
        }
    }

    fn endpoint(method: HttpMethod, path: &str, req_headers: &[(&str, &str)]) -> ApiEndpoint {
        ApiEndpoint {
            key: EndpointKey {
                method,
                path_template: path.to_string(),
            },
            url_pattern: path.to_string(),
            path_params: Vec::new(),
            query_params: Vec::new(),
            request_headers: req_headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            request_body_schema: None,
            response_status_codes: vec![200],
            response_body_schema: None,
            auth_required: false,
            auth_type: None,
            observed_count: 1,
            status_code_counts: BTreeMap::new(),
            error_responses: Vec::new(),
            avg_response_time_ms: 1.0,
            triggered_by: Vec::new(),
            request_body_samples: Vec::new(),
            response_body_samples: Vec::new(),
        }
    }

    #[test]
    fn endpoint_template_path_strips_origin_and_operation_suffix() {
        assert_eq!(endpoint_template_path("/api/orders/:id"), "/api/orders/:id");
        assert_eq!(
            endpoint_template_path("https://x.supabase.co/rest/v1/cart"),
            "/rest/v1/cart"
        );
        assert_eq!(endpoint_template_path("http://127.0.0.1:4000"), "/");
        assert_eq!(
            endpoint_template_path("/graphql#MUTATION RefundOrder"),
            "/graphql"
        );
        assert_eq!(
            endpoint_template_path("https://api.example.test/graphql#QUERY Me"),
            "/graphql"
        );
        assert_eq!(endpoint_template_path("/cart#action:7f3a"), "/cart");
    }

    #[test]
    fn excludes_nextjs_hmr_sse_and_csp_telemetry_reports() {
        for path in [
            "/_next/webpack-hmr",
            "/__nextjs_original-stack-frame",
            "/__nextjs_error_feedback",
        ] {
            assert!(is_dev_tool_or_hmr_path(path), "{path}");
            assert!(
                !is_application_api(&endpoint(HttpMethod::Post, path, &[])),
                "{path}"
            );
            assert!(
                !is_application_traffic(&traffic(
                    HttpMethod::Get,
                    &format!("http://localhost:3000{path}"),
                    &[],
                    Some("application/json"),
                )),
                "{path}"
            );
        }

        // SSE streams are never treated as application traffic / endpoints.
        assert!(is_sse_content_type(Some(
            "text/event-stream; charset=utf-8"
        )));
        assert!(!is_application_traffic(&traffic(
            HttpMethod::Get,
            "http://localhost:3000/api/messages/stream",
            &[("Accept", "text/event-stream")],
            Some("text/event-stream"),
        )));
        assert!(!is_application_api(&endpoint(
            HttpMethod::Get,
            "/api/messages/stream",
            &[("Accept", "text/event-stream")],
        )));

        // CSP and browser report beacons are excluded by path or Content-Type.
        assert!(is_csp_or_telemetry_report("/csp-report", None));
        assert!(is_csp_or_telemetry_report("/api/security/csp-report", None));
        assert!(is_csp_or_telemetry_report(
            "/api/telemetry",
            Some("application/csp-report"),
        ));
        assert!(is_csp_or_telemetry_report(
            "/api/telemetry",
            Some("application/reports+json; charset=utf-8"),
        ));
        assert!(!is_application_api(&endpoint(
            HttpMethod::Post,
            "/api/security/csp-report",
            &[],
        )));
        assert!(!is_application_api(&endpoint(
            HttpMethod::Post,
            "/api/events",
            &[("Content-Type", "application/reports+json")],
        )));
        assert!(!is_application_traffic(&traffic(
            HttpMethod::Post,
            "http://localhost:3000/api/security/csp-report",
            &[("Content-Type", "application/csp-report")],
            None,
        )));

        // Ordinary application API calls still match.
        assert!(is_application_api(&endpoint(
            HttpMethod::Post,
            "/api/orders",
            &[("Content-Type", "application/json")],
        )));
        assert!(is_application_traffic(&traffic(
            HttpMethod::Get,
            "http://localhost:3000/api/orders",
            &[],
            Some("application/json"),
        )));
    }

    #[test]
    fn background_heartbeat_and_poll_path_matching() {
        for matching in [
            "/session/renew",
            "/api/session/renew",
            "/API/Session/Renew/",
            "/api/v1/auth/session/refresh",
            "/session/refresh",
            "/session/keepalive",
            "/session/keep-alive",
            "/session/ping",
            "/heartbeat",
            "/keepalive",
            "/keep-alive",
            "/healthz",
            "/readyz",
            "/livez",
            "/api/health",
            "/api/v1/health",
            "/api/ping",
            "/api/v2/ping",
            "/api/heartbeat",
            "/api/keepalive",
            "https://api.example.test/api/session/renew?t=123",
        ] {
            assert!(
                is_background_heartbeat_or_poll_path(matching),
                "expected heartbeat/poll match for {matching}"
            );
        }

        for non_matching in [
            "/",
            "/api/orders",
            "/api/sessions",
            "/api/session",
            "/api/auth/session",
            "/api/session/renewals",
            "/api/patients/:id/health",
            "/health-insurance",
            "/api/heartbeats-report",
            "/ping-pong",
        ] {
            assert!(
                !is_background_heartbeat_or_poll_path(non_matching),
                "expected no heartbeat/poll match for {non_matching}"
            );
        }

        assert!(looks_like_static_asset_path("/chunks/app.mjs"));
        assert!(looks_like_static_asset_path("/_next/static/chunks/main.js"));
        assert!(looks_like_static_asset_path("/src/bootstrap.ts"));
        assert!(looks_like_static_asset_path("/src/components/App.tsx"));
        assert!(looks_like_static_asset_path(
            "/@fs/tmp/demo-app/packages/shared.ts"
        ));
        assert!(looks_like_static_asset_path(
            "/node_modules/.vite/deps/react.js"
        ));
        assert!(looks_like_static_asset_path("/manifest.webmanifest"));
        assert!(!looks_like_static_asset_path("/api/files/example.ts"));
    }

    #[test]
    fn static_and_vite_dev_module_noise_filter_keeps_errors_docs_and_apis() {
        use super::is_static_or_dev_module_noise;

        // Vite raw source modules, pre-bundled deps, HMR, and static assets on 200 are noise.
        for (url, mime) in [
            ("http://localhost:5833/src/bootstrap.ts", "text/javascript"),
            ("http://localhost:5833/src/App.tsx", "text/javascript"),
            (
                "http://localhost:5833/@fs/tmp/repo/pkg.ts",
                "text/javascript",
            ),
            ("http://localhost:5833/@vite/client", "text/javascript"),
            ("http://localhost:5833/@react-refresh", "text/javascript"),
            (
                "http://localhost:5833/node_modules/.vite/deps/react.js",
                "text/javascript",
            ),
            ("http://localhost:5833/apple-touch-icon.png", "image/png"),
            (
                "http://localhost:5833/manifest.webmanifest",
                "application/manifest+json",
            ),
        ] {
            let mut e = traffic(HttpMethod::Get, url, &[], Some(mime));
            e.is_api = Some(false);
            assert!(is_static_or_dev_module_noise(&e), "expected noise: {url}");
        }

        // Failed (404/500) static asset must NOT be dropped.
        let mut missing_js = traffic(
            HttpMethod::Get,
            "http://localhost:5833/src/missing.tsx",
            &[],
            Some("text/javascript"),
        );
        missing_js.response.as_mut().unwrap().status = 404;
        assert!(!is_static_or_dev_module_noise(&missing_js));

        // HTML documents and API responses must NOT be dropped.
        let html = traffic(
            HttpMethod::Get,
            "http://localhost:5833/settings/general",
            &[("Sec-Fetch-Dest", "document")],
            Some("text/html"),
        );
        assert!(!is_static_or_dev_module_noise(&html));

        let mut api = traffic(
            HttpMethod::Get,
            "http://localhost:5833/api/shell",
            &[],
            Some("application/json"),
        );
        api.is_api = Some(true);
        assert!(!is_static_or_dev_module_noise(&api));

        // Mutations are never static noise.
        let post = traffic(
            HttpMethod::Post,
            "http://localhost:5833/api/save",
            &[],
            Some("application/json"),
        );
        assert!(!is_static_or_dev_module_noise(&post));
    }

    #[test]
    fn host_matches_allowlist_handles_exact_wildcards_ports_and_rejects_spoofs() {
        use super::{host_matches_allowlist, url_matches_allowed_hosts};
        let allow = vec![
            "app.example.com".to_string(),
            "*.corp.example.com".to_string(),
            "127.0.0.1:8080".to_string(),
        ];
        assert!(host_matches_allowlist("app.example.com", &allow));
        assert!(host_matches_allowlist("APP.EXAMPLE.COM.", &allow));
        assert!(host_matches_allowlist("api.corp.example.com", &allow));
        assert!(host_matches_allowlist("a.b.corp.example.com", &allow));
        assert!(host_matches_allowlist("127.0.0.1", &allow));

        // Must reject apex for wildcard, suffix spoofs, and unrelated hosts.
        assert!(!host_matches_allowlist("corp.example.com", &allow));
        assert!(!host_matches_allowlist("evil-corp.example.com", &allow));
        assert!(!host_matches_allowlist("evilapp.example.com", &allow));
        assert!(!host_matches_allowlist("localhost", &allow));

        // URL wrapper allows non-network schemes and fails closed on network hosts.
        assert!(url_matches_allowed_hosts("about:blank", &allow));
        assert!(url_matches_allowed_hosts("data:text/plain,hi", &allow));
        assert!(url_matches_allowed_hosts(
            "https://app.example.com/settings",
            &allow
        ));
        assert!(url_matches_allowed_hosts(
            "wss://ws.corp.example.com/socket",
            &allow
        ));
        assert!(!url_matches_allowed_hosts(
            "https://evil.com/redirect",
            &allow
        ));
        assert!(!url_matches_allowed_hosts(
            "wss://localhost:3000/ws",
            &allow
        ));
    }
}
