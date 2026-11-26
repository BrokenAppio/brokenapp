use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use chromiumoxide::browser::Browser;
use chromiumoxide::cdp::browser_protocol::network::{self, CookieParam};
use chromiumoxide::cdp::browser_protocol::target::CreateTargetParams;
use chromiumoxide::element::Element;
use futures::StreamExt;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;
use uuid::Uuid;

use crate::browser::{PageClient, cdp_helpers};
use crate::config::{
    AuthConfig, AuthProbeMethod, AuthProtectedProbe, AuthSuccessContract, TargetConfig,
};
use crate::network::interceptor::{AuthWriteScope, NetworkInterceptor};
use crate::session::SessionState;
use crate::types::dom::InteractionRef;

/// Structured authentication failure carrying safe diagnostic metadata
/// (landed URL, HTTP status, visible page alert). Never contains secrets.
#[derive(Debug, Clone)]
pub struct AuthFailure {
    pub message: String,
    pub landed: Option<String>,
    pub http_status: Option<u16>,
    pub page_alert: Option<String>,
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AuthFailure {}

#[derive(Debug, Clone)]
struct AuthHttpFailure {
    method: String,
    target: String,
    status: u16,
}

/// Lightweight per-auth-page CDP observer that records only HTTP 4xx/5xx
/// method/path/status metadata (never headers, cookies, query strings, or
/// request/response bodies) so failed form logins report actionable server
/// errors even while `NetworkInterceptor` intentionally omits auth traffic
/// from persisted artifacts.
struct AuthNetworkMonitor {
    failures: Arc<Mutex<Vec<AuthHttpFailure>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AuthNetworkMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AuthNetworkMonitor {
    async fn attach(page: &PageClient, base_url: &Url) -> Option<Self> {
        let mut reqs = page
            .inner()
            .event_listener::<network::EventRequestWillBeSent>()
            .await
            .ok()?;
        let mut resps = page
            .inner()
            .event_listener::<network::EventResponseReceived>()
            .await
            .ok()?;
        let failures = Arc::new(Mutex::new(Vec::new()));
        let failures_task = Arc::clone(&failures);
        let base = base_url.clone();
        let task = tokio::spawn(async move {
            let mut req_meta: HashMap<String, (String, String)> = HashMap::new();
            let mut reqs_done = false;
            let mut resps_done = false;
            while !(reqs_done && resps_done) {
                tokio::select! {
                    ev = reqs.next(), if !reqs_done => match ev {
                        Some(ev) => {
                            if req_meta.len() >= 512 {
                                req_meta.clear();
                            }
                            let id = ev.request_id.inner().clone();
                            let method = ev.request.method.to_ascii_uppercase();
                            let target = safe_request_target(&ev.request.url, &base);
                            req_meta.insert(id, (method, target));
                        }
                        None => reqs_done = true,
                    },
                    ev = resps.next(), if !resps_done => match ev {
                        Some(ev) => {
                            let status = ev.response.status.clamp(0, i64::from(u16::MAX)) as u16;
                            if status >= 400 {
                                let id = ev.request_id.inner();
                                let (method, target) = req_meta
                                    .get(id)
                                    .cloned()
                                    .unwrap_or_else(|| {
                                        ("GET".to_string(), safe_request_target(&ev.response.url, &base))
                                    });
                                if !looks_like_static_asset_path(&target) {
                                    let mut guard = failures_task
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    if guard.len() < 10 {
                                        guard.push(AuthHttpFailure {
                                            method,
                                            target,
                                            status,
                                        });
                                    }
                                }
                            }
                        }
                        None => resps_done = true,
                    },
                }
            }
        });
        Some(Self { failures, task })
    }

    fn best_failure(&self) -> Option<AuthHttpFailure> {
        let guard = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .iter()
            .rev()
            .find(|f| matches!(f.method.as_str(), "POST" | "PUT" | "PATCH"))
            .or_else(|| {
                guard.iter().rev().find(|f| {
                    let lower = f.target.to_ascii_lowercase();
                    lower.contains("auth")
                        || lower.contains("login")
                        || lower.contains("signin")
                        || lower.contains("session")
                        || lower.contains("token")
                })
            })
            .or_else(|| guard.last())
            .cloned()
    }
}

fn safe_request_target(raw: &str, base: &Url) -> String {
    let Ok(url) = Url::parse(raw) else {
        return "<unknown>".to_string();
    };
    if url.origin() == base.origin() {
        url.path().to_string()
    } else if let Some(host) = url.host_str() {
        let mut out = format!("{}://{host}", url.scheme());
        if let Some(port) = url.port() {
            out.push_str(&format!(":{port}"));
        }
        out.push_str(url.path());
        out
    } else {
        url.path().to_string()
    }
}

fn looks_like_static_asset_path(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.ends_with("/favicon.ico")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".ico")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".css")
        || lower.ends_with(".map")
}

/// Navigate with a single 30s retry when the initial 20s navigation times out
/// (common during a cold Next.js / Vite dev server compile).
pub(crate) async fn goto_with_cold_compile_retry(page: &PageClient, url: &str) -> Result<()> {
    match page.goto_and_wait(url, Duration::from_secs(20)).await {
        Ok(()) => Ok(()),
        Err(first_err) => {
            let msg = format!("{first_err:#}");
            if msg.to_ascii_lowercase().contains("timed out") {
                tracing::warn!(
                    url = %safe_auth_url(url),
                    error = %msg,
                    "auth navigation timed out after 20s; retrying once with 30s timeout"
                );
                page.goto_and_wait(url, Duration::from_secs(30)).await
            } else {
                Err(first_err)
            }
        }
    }
}

pub async fn authenticate(
    browser: &Browser,
    target: &TargetConfig,
    auth: &Option<AuthConfig>,
    auth_contract: Option<&AuthSuccessContract>,
    network: Option<&Arc<NetworkInterceptor>>,
) -> Result<SessionState> {
    let mut state = SessionState::default();
    if let Some(ref locale) = target.locale {
        state
            .extra_headers
            .insert("Accept-Language".to_string(), accept_language_value(locale));
    }

    let Some(auth) = auth else {
        return Ok(state);
    };
    let auth =
        crate::session::secrets::resolve_auth_secrets(auth).context("resolve auth secrets")?;
    state.login_hint = auth
        .login_path_hint()
        .map(str::trim)
        .filter(|hint| !hint.is_empty() && *hint != "/")
        .map(str::to_string);

    let mut probe_verified_via_http = false;

    match &auth {
        AuthConfig::Form {
            login_url,
            username_selector,
            password_selector,
            submit_selector,
            username,
            password,
        } => {
            let login = target.url.join(login_url).with_context(|| {
                format!(
                    "build login url from base={} and login_url={login_url}",
                    target.url
                )
            })?;

            let page = browser
                .new_page(CreateTargetParams::new("about:blank"))
                .await
                .context("create auth page")?;
            let page = PageClient::new(page);
            page.enable_domains().await?;
            cdp_helpers::install_instrumentation(&page).await?;
            if !state.extra_headers.is_empty() {
                page.set_extra_http_headers(
                    state
                        .extra_headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                )
                .await?;
            }

            let auth_monitor = AuthNetworkMonitor::attach(&page, &target.url).await;

            let auth_scope = AuthWriteScope::default();
            auth_scope.allow_url(login.as_str());
            auth_scope.allow_auth_origin(login.as_str());
            let auth_interaction = InteractionRef {
                view: "__auth__".to_string(),
                selector: "__auth__".to_string(),
            };
            let _net_handle = match network {
                Some(net) => {
                    let page_id = format!("auth_form_{}", Uuid::new_v4());
                    let handle = Arc::clone(net)
                        .attach_auth(page.inner(), page_id, auth_scope.clone())
                        .await?;
                    net.set_current_interaction_on(&page.tab(), Some(auth_interaction.clone()));
                    Some(handle)
                }
                None => None,
            };

            let form_result: Result<Option<String>> = async {
                goto_with_cold_compile_retry(&page, login.as_str()).await?;

                if is_button_only_form_auth(username, password, submit_selector) {
                    let outcome = wait_for_selector_or_redirect(
                        &page,
                        submit_selector,
                        login.as_str(),
                        Duration::from_secs(30),
                    )
                    .await
                    .map_err(|err| {
                        anyhow::Error::new(AuthFailure {
                            message: format!(
                                "login_failed: submit button not found for --submit-selector {submit_selector:?} ({})",
                                clean_cdp_error(&format!("{err:#}"))
                            ),
                            landed: Some(safe_auth_url(login.as_str())),
                            http_status: None,
                            page_alert: None,
                        })
                    })?;
                    match outcome {
                        SelectorWaitOutcome::Redirected { url } => {
                            if looks_like_authenticated_redirect(&url, login.as_str()) {
                                validate_form_landing(
                                    &page,
                                    None,
                                    None,
                                    login.as_str(),
                                    "",
                                    auth_monitor.as_ref(),
                                )
                                .await?;
                                tracing::info!(
                                    current_url = %safe_auth_url(&url),
                                    "already authenticated (login page redirected)"
                                );
                                return Ok(Some(safe_auth_url(&url)));
                            }
                            let landed = diagnostic_landed_url(&url, "");
                            return Err(anyhow::Error::new(AuthFailure {
                                message: format!(
                                    "login_failed: login page redirected before showing --submit-selector {submit_selector:?} (landed: {landed})"
                                ),
                                landed: Some(landed),
                                http_status: None,
                                page_alert: None,
                            }));
                        }
                        SelectorWaitOutcome::Found(submit_el) => {
                            allow_enclosing_form_action(&page, submit_selector, &auth_scope).await;
                            click_submit_element_with_retry(
                                &page,
                                submit_el,
                                Some(submit_selector),
                            )
                            .await?;
                        }
                    }

                    let _ = tokio::time::timeout(
                        Duration::from_secs(20),
                        page.inner().wait_for_navigation(),
                    )
                    .await;
                    let _ = cdp_helpers::settle(&page, Duration::from_secs(10)).await;

                    validate_form_landing(
                        &page,
                        None,
                        Some(submit_selector),
                        login.as_str(),
                        "",
                        auth_monitor.as_ref(),
                    )
                    .await?;
                    let canary = page
                        .url()
                        .await
                        .ok()
                        .flatten()
                        .filter(|u| u.starts_with("http"))
                        .map(|u| safe_auth_url(&u));
                    return Ok(canary);
                }

                // Fill username/password via element handles to trigger proper input events.
                let user_el = wait_for_selector_or_redirect(
                    &page,
                    username_selector,
                    login.as_str(),
                    Duration::from_secs(30),
                )
                .await
                .with_context(|| format!("wait for username selector {username_selector}"))?;
                let user_el = match user_el {
                    SelectorWaitOutcome::Found(el) => el,
                    SelectorWaitOutcome::Redirected { url } => {
                        if looks_like_authenticated_redirect(&url, login.as_str()) {
                            validate_form_landing(
                                &page,
                                Some(password_selector),
                                None,
                                login.as_str(),
                                password,
                                auth_monitor.as_ref(),
                            )
                            .await?;
                            tracing::info!(
                                current_url = %safe_auth_url(&url),
                                "already authenticated (login page redirected)"
                            );
                            return Ok(Some(safe_auth_url(&url)));
                        }
                        let landed = diagnostic_landed_url(&url, password);
                        return Err(anyhow::Error::new(AuthFailure {
                            message: format!(
                                "login_failed: login page redirected before showing the username control; authentication state is not confirmed (landed: {landed})"
                            ),
                            landed: Some(landed),
                            http_status: None,
                            page_alert: None,
                        }));
                    }
                };
                user_el
                    .click()
                    .await?
                    .call_js_fn("function() { this.value = ''; }", true)
                    .await?;
                user_el.type_str(username).await?;

                let pass_el =
                    find_element_retry(&page, password_selector, Duration::from_secs(20))
                        .await
                        .with_context(|| format!("find password selector {password_selector}"))?;
                pass_el
                    .click()
                    .await?
                    .call_js_fn("function() { this.value = ''; }", true)
                    .await?;
                pass_el.type_str(password).await?;

                submit_password_form(
                    &page,
                    &pass_el,
                    password_selector,
                    submit_selector,
                    &auth_scope,
                )
                .await?;

                // Give the app a chance to navigate or update in-place.
                let _ = tokio::time::timeout(
                    Duration::from_secs(20),
                    page.inner().wait_for_navigation(),
                )
                .await;
                let _ = cdp_helpers::settle(&page, Duration::from_secs(10)).await;

                validate_form_landing(
                    &page,
                    Some(password_selector),
                    None,
                    login.as_str(),
                    password,
                    auth_monitor.as_ref(),
                )
                .await?;
                // Same-route SPA sign-ins can succeed without navigation. The
                // error-document/password check and optional contract decide.
                let canary = page
                    .url()
                    .await
                    .ok()
                    .flatten()
                    .filter(|u| u.starts_with("http"))
                    .map(|u| safe_auth_url(&u));
                Ok(canary)
            }
            .await;

            auth_scope.clear_auth_origin();
            if let Some(net) = network {
                net.set_current_interaction_on(&page.tab(), None);
            }
            drop(auth_monitor);
            let _ = page.inner().clone().close().await;

            state.canary_url = form_result?;
        }
        AuthConfig::Manual { login_url } => {
            let start_url = match login_url.as_deref() {
                Some(login_url) => target.url.join(login_url).with_context(|| {
                    format!(
                        "build manual login url from base={} and login_url={login_url}",
                        target.url
                    )
                })?,
                None => target.url.clone(),
            };

            let page = browser
                .new_page(CreateTargetParams::new("about:blank"))
                .await
                .context("create manual auth page")?;
            let page = PageClient::new(page);
            page.enable_domains().await?;
            cdp_helpers::install_instrumentation(&page).await?;
            if !state.extra_headers.is_empty() {
                page.set_extra_http_headers(
                    state
                        .extra_headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                )
                .await?;
            }

            let auth_scope = AuthWriteScope::default();
            auth_scope.allow_url(start_url.as_str());
            auth_scope.allow_auth_origin(start_url.as_str());
            let auth_interaction = InteractionRef {
                view: "__auth__".to_string(),
                selector: "__manual_auth__".to_string(),
            };
            let _net_handle = match network {
                Some(net) => {
                    let page_id = format!("auth_manual_{}", Uuid::new_v4());
                    let handle = Arc::clone(net)
                        .attach_auth(page.inner(), page_id, auth_scope.clone())
                        .await?;
                    net.set_current_interaction_on(&page.tab(), Some(auth_interaction.clone()));
                    Some(handle)
                }
                None => None,
            };

            page.goto_and_wait(start_url.as_str(), Duration::from_secs(60))
                .await?;

            eprintln!();
            eprintln!("==============================================");
            eprintln!("Manual auth mode");
            eprintln!();
            eprintln!("A browser window is open.");
            eprintln!("1) Log in manually (SSO/MFA/CAPTCHA/etc)");
            eprintln!("2) Once you are logged in, press ENTER here");
            eprintln!("==============================================");
            eprintln!();

            let mut buf = String::new();
            let mut stdin = BufReader::new(tokio::io::stdin());
            stdin.read_line(&mut buf).await.context("read stdin")?;

            // Best-effort: record a cookie count so the user can see we captured a session.
            if let Ok(res) = page
                .inner()
                .execute(network::GetCookiesParams::default())
                .await
            {
                tracing::info!(cookie_count = res.result.cookies.len(), "session captured");
            } else {
                tracing::info!("session captured");
            }

            auth_scope.clear_auth_origin();
            if let Some(net) = network {
                net.set_current_interaction_on(&page.tab(), None);
            }
            let _ = cdp_helpers::settle(&page, Duration::from_secs(5)).await;
            let _ = page.inner().clone().close().await;
        }
        AuthConfig::Cookie { cookie } => {
            let cookies = parse_cookie_header(cookie, &target.url)?;
            browser.set_cookies(cookies).await.context("set cookies")?;
            if let Some(contract) = auth_contract
                && let Some(probe) = contract.protected_probe.as_ref()
            {
                let cookie_hdr = cookie_header_from_raw(cookie)?;
                if let Ok(outcome) =
                    http_protected_probe(target, probe, Some(&cookie_hdr), &state.extra_headers)
                        .await
                {
                    if !probe.expected_statuses.contains(&outcome.status) {
                        return Err(anyhow::Error::new(format_http_probe_failure(
                            &outcome,
                            &probe.expected_statuses,
                        ))
                        .context("login_failed: auth contract validation failed"));
                    }
                    if contract.success_url_patterns.is_empty()
                        && contract.required_cookie_names.is_empty()
                    {
                        return Ok(state);
                    }
                    probe_verified_via_http = true;
                }
            }
        }
        AuthConfig::StorageState { path } => {
            let loaded = crate::session::storage_state::apply_storage_state(
                browser,
                std::path::Path::new(path),
            )
            .await?;
            state.storage_init_script = loaded.init_script.map(crate::session::SecretText::new);
            state.canary_url = loaded.landing_url;
            if loaded.login_pattern.is_some() {
                state.login_hint = loaded.login_pattern;
            }
        }
        AuthConfig::BearerToken { token } => {
            state
                .extra_headers
                .insert("Authorization".to_string(), format!("Bearer {token}"));
            if let Some(contract) = auth_contract
                && let Some(probe) = contract.protected_probe.as_ref()
            {
                if let Ok(outcome) =
                    http_protected_probe(target, probe, None, &state.extra_headers).await
                {
                    if !probe.expected_statuses.contains(&outcome.status) {
                        return Err(anyhow::Error::new(format_http_probe_failure(
                            &outcome,
                            &probe.expected_statuses,
                        ))
                        .context("login_failed: auth contract validation failed"));
                    }
                    if contract.success_url_patterns.is_empty()
                        && contract.required_cookie_names.is_empty()
                    {
                        return Ok(state);
                    }
                    probe_verified_via_http = true;
                }
            }
        }
        AuthConfig::OAuth { token, .. } => {
            state
                .extra_headers
                .insert("Authorization".to_string(), format!("Bearer {token}"));
        }
        AuthConfig::Supabase {
            project_url,
            anon_key,
            email,
            password,
        } => {
            let resp =
                crate::session::providers::supabase_sign_in(project_url, anon_key, email, password)
                    .await
                    .context("supabase sign-in")?;
            state.extra_headers.insert(
                "Authorization".to_string(),
                format!("Bearer {}", resp.access_token),
            );
            let session_json = crate::session::providers::supabase_session_json(&resp);
            let ssr_cookies = crate::session::providers::supabase_ssr_cookies(
                project_url,
                &target.url,
                &session_json,
            );
            if !ssr_cookies.is_empty() {
                browser
                    .set_cookies(ssr_cookies)
                    .await
                    .context("set @supabase/ssr auth cookies")?;
            }
            state.storage_init_script =
                crate::session::providers::supabase_local_storage_init_script(
                    project_url,
                    &target.url,
                    &session_json,
                )
                .map(crate::session::SecretText::new);
            state.refresh_token = resp.refresh_token;
            state.auth_provider = Some(crate::session::AuthProvider::Supabase {
                project_url: project_url.clone(),
                anon_key: anon_key.clone(),
            });
            state.target_url = Some(target.url.clone());
            if resp.expires_in > 0 {
                state.token_expires_at = Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(resp.expires_in),
                );
            }
        }
        AuthConfig::Firebase {
            api_key,
            email,
            password,
        } => {
            let resp = crate::session::providers::firebase_sign_in(api_key, email, password)
                .await
                .context("firebase sign-in")?;
            state.extra_headers.insert(
                "Authorization".to_string(),
                format!("Bearer {}", resp.access_token),
            );
            state.refresh_token = resp.refresh_token;
            state.auth_provider = Some(crate::session::AuthProvider::Firebase {
                api_key: api_key.clone(),
            });
            if resp.expires_in > 0 {
                state.token_expires_at = Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(resp.expires_in),
                );
            }
        }
        AuthConfig::GoogleOAuth {
            login_url,
            google_button_selector,
            google_email,
            google_password,
        } => {
            // 1. Resolve login URL (default to target.url if None).
            let url = match login_url.as_deref() {
                Some(path) => target.url.join(path).with_context(|| {
                    format!(
                        "build google oauth login url from base={} and login_url={path}",
                        target.url
                    )
                })?,
                None => target.url.clone(),
            };

            // 2. Create new browser page.
            let page = browser
                .new_page(CreateTargetParams::new("about:blank"))
                .await
                .context("create google oauth auth page")?;
            let page = PageClient::new(page);
            page.enable_domains().await?;
            cdp_helpers::install_instrumentation(&page).await?;
            if !state.extra_headers.is_empty() {
                page.set_extra_http_headers(
                    state
                        .extra_headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                )
                .await?;
            }

            let auth_scope = AuthWriteScope::default().google_identity();
            auth_scope.allow_url(url.as_str());
            auth_scope.allow_auth_origin(url.as_str());
            let auth_interaction = InteractionRef {
                view: "__auth__".to_string(),
                selector: "__google_oauth__".to_string(),
            };
            let _net_handle = match network {
                Some(net) => {
                    let page_id = format!("auth_google_oauth_{}", Uuid::new_v4());
                    let handle = Arc::clone(net)
                        .attach_auth(page.inner(), page_id, auth_scope.clone())
                        .await?;
                    net.set_current_interaction_on(&page.tab(), Some(auth_interaction.clone()));
                    Some(handle)
                }
                None => None,
            };

            // 3. Navigate to target login page.
            tracing::info!(url = %url, "navigating to login page for Google OAuth");
            page.goto_and_wait(url.as_str(), Duration::from_secs(30))
                .await?;
            let _ = cdp_helpers::settle(&page, Duration::from_secs(3)).await;

            // 4. Find Google sign-in button.
            tracing::info!("looking for Google sign-in button");
            let google_btn = if let Some(selector) = google_button_selector.as_deref() {
                find_element_retry(&page, selector, Duration::from_secs(15))
                    .await
                    .with_context(|| format!("find explicit Google button selector {selector}"))?
            } else {
                find_google_sign_in_button(&page, Duration::from_secs(15)).await?
            };

            // 5. Click the Google button and wait for redirect to accounts.google.com.
            tracing::info!("clicking Google sign-in button");
            google_btn.click().await?;
            wait_for_google_domain(&page, Duration::from_secs(15)).await?;
            let _ = cdp_helpers::settle(&page, Duration::from_secs(3)).await;

            // 6. Fill Google email.
            tracing::info!("filling Google email");
            tokio::time::sleep(Duration::from_secs(2)).await;
            let email_el =
                find_element_retry(&page, r#"input[type="email"]"#, Duration::from_secs(15))
                    .await
                    .context("find Google email input")?;
            email_el
                .click()
                .await?
                .call_js_fn("function() { this.value = ''; }", true)
                .await?;
            email_el.type_str(google_email).await?;

            let next_btn = find_google_next_button(&page, Duration::from_secs(10))
                .await
                .context("find Google Next button after email")?;
            next_btn.click().await?;
            let _ = cdp_helpers::settle(&page, Duration::from_secs(5)).await;
            tokio::time::sleep(Duration::from_secs(2)).await;

            // 7. Fill Google password.
            tracing::info!("filling Google password");
            let pass_el =
                find_element_retry(&page, r#"input[type="password"]"#, Duration::from_secs(15))
                    .await
                    .context("find Google password input")?;
            pass_el
                .click()
                .await?
                .call_js_fn("function() { this.value = ''; }", true)
                .await?;
            pass_el.type_str(google_password).await?;

            let next_btn2 = find_google_next_button(&page, Duration::from_secs(10))
                .await
                .context("find Google Next button after password")?;
            next_btn2.click().await?;
            let _ = cdp_helpers::settle(&page, Duration::from_secs(5)).await;

            // 8. Handle consent screen (if any).
            tracing::info!("checking for Google consent screen");
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok(Some(current_url)) = page.url().await {
                if current_url.contains("accounts.google.com") {
                    let consent_selectors = [
                        r#"button[id="submit_approve_access"]"#,
                        "#allow",
                        r#"[data-idom-class*="submit"]"#,
                    ];
                    for sel in &consent_selectors {
                        if let Ok(el) = find_element_retry(&page, sel, Duration::from_secs(3)).await
                        {
                            tracing::info!(selector = %sel, "clicking Google consent button");
                            let _ = el.click().await;
                            break;
                        }
                    }
                }
            }

            // 9. Wait for redirect back to target.
            let target_host = target.url.host_str().unwrap_or_default().to_string();
            wait_for_target_redirect(&page, &target_host, Duration::from_secs(30)).await?;
            let _ = cdp_helpers::settle(&page, Duration::from_secs(5)).await;
            auth_scope.clear_auth_origin();

            // 10. Verify not still on Google.
            if let Ok(Some(current_url)) = page.url().await {
                if current_url.contains("accounts.google.com") {
                    if let Some(net) = network {
                        net.set_current_interaction_on(&page.tab(), None);
                    }
                    let _ = page.inner().clone().close().await;
                    return Err(anyhow!(
                        "Google OAuth flow did not complete — still on accounts.google.com (url={})",
                        safe_auth_url(&current_url)
                    ));
                }
            }

            tracing::info!("Google OAuth authentication complete");

            // 11. Clean up.
            if let Some(net) = network {
                net.set_current_interaction_on(&page.tab(), None);
            }
            let _ = page.inner().clone().close().await;
        }
    }

    if let Some(contract) = auth_contract {
        if let Err(err) = verify_auth_contract_inner(
            browser,
            target,
            &state,
            contract,
            network,
            probe_verified_via_http,
        )
        .await
        {
            if matches!(auth, AuthConfig::Supabase { .. }) {
                let af = err
                    .chain()
                    .find_map(|e| e.downcast_ref::<AuthFailure>())
                    .cloned();
                let message = format!(
                    "login_failed: auth contract validation failed: {err:#}. {}",
                    crate::session::providers::SUPABASE_SSR_HINT
                );
                return Err(anyhow::Error::new(AuthFailure {
                    message,
                    landed: af.as_ref().and_then(|f| f.landed.clone()),
                    http_status: af.as_ref().and_then(|f| f.http_status),
                    page_alert: af.and_then(|f| f.page_alert),
                }));
            }
            return Err(err).context("login_failed: auth contract validation failed");
        }
    }

    Ok(state)
}

#[derive(Debug, Deserialize)]
struct ProbeStatusResult {
    status: u16,
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

impl ProbeStatusResult {
    fn is_opaque_redirect(&self) -> bool {
        self.response_type.as_deref() == Some("opaqueredirect")
            || (self.status == 0 && self.error.is_none())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HttpProbeOutcome {
    pub status: u16,
    pub location: Option<String>,
    pub method: &'static str,
    pub probe_url: String,
}

pub(crate) async fn http_protected_probe(
    target: &TargetConfig,
    probe: &AuthProtectedProbe,
    cookie_header: Option<&str>,
    extra_headers: &BTreeMap<String, String>,
) -> Result<HttpProbeOutcome> {
    http_protected_probe_with_timeout(
        target,
        probe,
        cookie_header,
        extra_headers,
        Duration::from_secs(30),
    )
    .await
}

pub(crate) async fn http_protected_probe_with_timeout(
    target: &TargetConfig,
    probe: &AuthProtectedProbe,
    cookie_header: Option<&str>,
    extra_headers: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<HttpProbeOutcome> {
    let probe_url = resolve_probe_url_for_page(target, None, &probe.path)
        .with_context(|| format!("resolve auth protected_probe path {:?}", probe.path))?;
    let (method_str, req_method) = match probe.method {
        AuthProbeMethod::Get => ("GET", reqwest::Method::GET),
        AuthProbeMethod::Head => ("HEAD", reqwest::Method::HEAD),
    };
    let attempt_timeout = timeout.max(Duration::from_millis(50));
    let client = reqwest::Client::builder()
        .timeout(attempt_timeout)
        .connect_timeout(attempt_timeout.min(Duration::from_secs(10)))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(target.ignore_https_errors)
        .no_proxy()
        .build()
        .context("build auth probe http client")?;
    let build_req = || {
        let mut req = client.request(req_method.clone(), probe_url.clone());
        if let Some(cookie) = cookie_header.filter(|c| !c.trim().is_empty())
            && crate::url_origin::equivalent_hosts(target.url.host_str(), probe_url.host_str())
        {
            req = req.header(reqwest::header::COOKIE, cookie);
        }
        for (k, v) in extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req
    };
    // Cold dev-server routes (e.g. Next.js SSR) can time out on the first
    // compile while compilation finishes in the background. Retry once on
    // timeout so the warm response succeeds cleanly.
    let resp = match build_req().send().await {
        Ok(resp) => resp,
        Err(err) if err.is_timeout() => {
            tracing::info!(
                url = %safe_auth_url(probe_url.as_str()),
                timeout_ms = attempt_timeout.as_millis() as u64,
                "auth protected_probe timed out; retrying once for cold route compile"
            );
            build_req().send().await.with_context(|| {
                format!(
                    "send {method_str} {} (after retry on timeout)",
                    safe_auth_url(probe_url.as_str())
                )
            })?
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!("send {method_str} {}", safe_auth_url(probe_url.as_str()))
            });
        }
    };
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(safe_redirect_location);
    Ok(HttpProbeOutcome {
        status,
        location,
        method: method_str,
        probe_url: safe_auth_url(probe_url.as_str()),
    })
}

fn safe_redirect_location(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(url) = Url::parse(trimmed) {
        return diagnostic_landed_url(url.as_str(), "");
    }
    // Relative redirect like `/auth?error=SessionExpired&token=secret`.
    if let Ok(base) = Url::parse("http://localhost/")
        && let Ok(joined) = base.join(trimmed)
    {
        let sanitized = diagnostic_landed_url(joined.as_str(), "");
        if let Ok(parsed) = Url::parse(&sanitized) {
            return match parsed.query() {
                Some(q) if !q.is_empty() => format!("{}?{q}", parsed.path()),
                _ => parsed.path().to_string(),
            };
        }
    }
    trimmed.split('?').next().unwrap_or(trimmed).to_string()
}

fn probe_display_target(probe_url: &str) -> String {
    Url::parse(probe_url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| probe_url.to_string())
}

pub(crate) fn format_http_probe_failure(
    outcome: &HttpProbeOutcome,
    expected: &[u16],
) -> AuthFailure {
    let target = probe_display_target(&outcome.probe_url);
    let message = if (300..400).contains(&outcome.status) {
        match outcome.location.as_deref() {
            Some(loc) => format!(
                "auth protected_probe failed: {} {target} returned HTTP {} -> {loc} (expected {expected:?})",
                outcome.method, outcome.status
            ),
            None => format!(
                "auth protected_probe failed: {} {target} returned HTTP {} redirect (expected {expected:?})",
                outcome.method, outcome.status
            ),
        }
    } else {
        format!(
            "auth protected_probe failed: {} {target} returned HTTP {} (expected {expected:?})",
            outcome.method, outcome.status
        )
    };
    AuthFailure {
        message,
        landed: outcome.location.clone(),
        http_status: Some(outcome.status),
        page_alert: None,
    }
}

fn format_browser_probe_failure(
    method: &str,
    probe_path: &str,
    result: &ProbeStatusResult,
    expected: &[u16],
    http_redirect: Option<&HttpProbeOutcome>,
) -> AuthFailure {
    if result.is_opaque_redirect() {
        if let Some(hr) = http_redirect
            && (300..400).contains(&hr.status)
        {
            let loc_suffix = hr
                .location
                .as_deref()
                .map(|loc| format!(" -> {loc}"))
                .unwrap_or_default();
            return AuthFailure {
                message: format!(
                    "auth protected_probe failed: {method} {probe_path} returned HTTP {}{loc_suffix} (redirected; fetch opaqueredirect, status=0; expected {expected:?})",
                    hr.status
                ),
                landed: hr.location.clone(),
                http_status: Some(hr.status),
                page_alert: None,
            };
        }
        return AuthFailure {
            message: format!(
                "auth protected_probe failed: {method} {probe_path} redirected (e.g. 302/307 to login; fetch opaqueredirect, status=0), expected {expected:?}"
            ),
            landed: None,
            http_status: None,
            page_alert: None,
        };
    }

    let err_suffix = result
        .error
        .as_deref()
        .map(|e| format!(" error={e}"))
        .unwrap_or_default();
    AuthFailure {
        message: format!(
            "auth protected_probe failed: {method} {probe_path} status={} expected={expected:?}{err_suffix}",
            result.status
        ),
        landed: None,
        http_status: (result.status > 0).then_some(result.status),
        page_alert: None,
    }
}

#[allow(dead_code)]
pub(crate) async fn verify_auth_contract(
    browser: &Browser,
    target: &TargetConfig,
    state: &SessionState,
    contract: &AuthSuccessContract,
    network: Option<&Arc<NetworkInterceptor>>,
) -> Result<()> {
    verify_auth_contract_inner(browser, target, state, contract, network, false).await
}

async fn verify_auth_contract_inner(
    browser: &Browser,
    target: &TargetConfig,
    state: &SessionState,
    contract: &AuthSuccessContract,
    network: Option<&Arc<NetworkInterceptor>>,
    skip_probe: bool,
) -> Result<()> {
    if contract.success_url_patterns.is_empty()
        && contract.required_cookie_names.is_empty()
        && (skip_probe || contract.protected_probe.is_none())
    {
        return Ok(());
    }

    let page = browser
        .new_page(CreateTargetParams::new("about:blank"))
        .await
        .context("create auth contract page")?;
    let page = PageClient::new(page);
    page.enable_domains().await?;
    cdp_helpers::install_instrumentation(&page).await?;
    apply_session_state(&page, state).await?;
    let _net_handle = match network {
        Some(net) => Some(
            Arc::clone(net)
                .attach_isolated(
                    page.inner(),
                    Some(format!("auth_contract_{}", Uuid::new_v4())),
                )
                .await?,
        ),
        None => None,
    };

    let check_result: Result<()> = async {
        goto_with_cold_compile_retry(&page, target.url.as_str())
            .await
            .context("navigate for auth contract check")?;
        let _ = cdp_helpers::settle(&page, Duration::from_secs(5)).await;

        let current_url = page
            .url()
            .await
            .context("read current url for auth contract")?
            .unwrap_or_else(|| target.url.to_string());
        if !contract.success_url_patterns.is_empty()
            && !matches_success_url_patterns(&current_url, &contract.success_url_patterns)
        {
            let landed = diagnostic_landed_url(&current_url, "");
            return Err(anyhow::Error::new(AuthFailure {
                message: format!(
                    "auth success_url_patterns not matched (current_url={landed}, patterns={:?})",
                    contract.success_url_patterns
                ),
                landed: Some(landed),
                http_status: None,
                page_alert: None,
            }));
        }

        let mut cached_cookies: Option<Vec<network::Cookie>> = None;
        if !contract.required_cookie_names.is_empty() {
            let cookies = page
                .inner()
                .execute(network::GetCookiesParams::default())
                .await
                .context("read cookies for auth contract")?;
            let names: std::collections::HashSet<String> = cookies
                .result
                .cookies
                .iter()
                .map(|c| c.name.clone())
                .collect();
            cached_cookies = Some(cookies.result.cookies);
            let missing: Vec<String> = contract
                .required_cookie_names
                .iter()
                .filter(|name| !names.contains(name.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                anyhow::bail!("auth required_cookie_names missing: {}", missing.join(", "));
            }
        }

        if !skip_probe && let Some(probe) = contract.protected_probe.as_ref() {
            let probe_result = protected_probe_status(&page, target, &current_url, probe).await?;
            if !probe.expected_statuses.contains(&probe_result.status) {
                let method = match probe.method {
                    AuthProbeMethod::Get => "GET",
                    AuthProbeMethod::Head => "HEAD",
                };
                // On opaque browser redirects (`fetch(..., { redirect: "manual" })`),
                // fire a quick non-redirecting reqwest probe with the browser's cookies
                // so we can report the exact `HTTP 307 -> /auth` when reachable.
                let http_redirect = if probe_result.is_opaque_redirect() {
                    let cookies = match cached_cookies {
                        Some(c) => Some(c),
                        None => page
                            .inner()
                            .execute(network::GetCookiesParams::default())
                            .await
                            .ok()
                            .map(|r| r.result.cookies),
                    };
                    let cookie_hdr = cookies.and_then(|list| {
                        let pairs: Vec<String> = list
                            .into_iter()
                            .filter(|c| cookie_matches_host(&c.domain, target.url.host_str()))
                            .map(|c| format!("{}={}", c.name, c.value))
                            .collect();
                        (!pairs.is_empty()).then(|| pairs.join("; "))
                    });
                    http_protected_probe_with_timeout(
                        target,
                        probe,
                        cookie_hdr.as_deref(),
                        &state.extra_headers,
                        Duration::from_secs(5),
                    )
                    .await
                    .ok()
                } else {
                    None
                };
                return Err(anyhow::Error::new(format_browser_probe_failure(
                    method,
                    &probe.path,
                    &probe_result,
                    &probe.expected_statuses,
                    http_redirect.as_ref(),
                )));
            }
        }

        Ok(())
    }
    .await;

    let _ = page.inner().clone().close().await;
    check_result
}

pub(crate) fn cookie_matches_host(cookie_domain: &str, host: Option<&str>) -> bool {
    let Some(host) = host.map(str::to_ascii_lowercase) else {
        return false;
    };
    let dom = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    if dom.is_empty() {
        return false;
    }
    host == dom
        || host.ends_with(&format!(".{dom}"))
        || crate::url_origin::equivalent_hosts(Some(&host), Some(&dom))
}

/// Run `probe` from `page` (already on the app's origin): `true` when it
/// answers with an expected status.
pub(crate) async fn run_protected_probe(
    page: &PageClient,
    target: &TargetConfig,
    probe: &crate::config::AuthProtectedProbe,
) -> Result<bool> {
    let current_url = page
        .url()
        .await
        .context("read current url for protected probe")?
        .unwrap_or_else(|| target.url.to_string());
    let result = protected_probe_status(page, target, &current_url, probe).await?;
    Ok(probe.expected_statuses.contains(&result.status))
}

async fn protected_probe_status(
    page: &PageClient,
    target: &TargetConfig,
    current_url: &str,
    probe: &crate::config::AuthProtectedProbe,
) -> Result<ProbeStatusResult> {
    let current_page_url = Url::parse(current_url).ok();
    let probe_url = resolve_probe_url_for_page(target, current_page_url.as_ref(), &probe.path)
        .with_context(|| format!("resolve auth protected_probe path {:?}", probe.path))?;
    let method = match probe.method {
        AuthProbeMethod::Get => "GET",
        AuthProbeMethod::Head => "HEAD",
    };
    let script = format!(
        r#"
(() => fetch({}, {{
  method: {},
  credentials: "include",
  redirect: "manual",
  cache: "no-store"
}})
  .then((resp) => ({{ status: resp.status, response_type: resp.type }}))
  .catch((err) => ({{ status: 0, error: String(err) }})))()
"#,
        serde_json::to_string(probe_url.as_str()).context("serialize probe url")?,
        serde_json::to_string(method).context("serialize probe method")?,
    );
    page.evaluate_json(&script)
        .await
        .context("run protected probe")
}

async fn apply_session_state(page: &PageClient, state: &SessionState) -> Result<()> {
    crate::session::SessionManager::apply_to_page(page, state).await
}

fn resolve_probe_url_for_page(
    target: &TargetConfig,
    current_page_url: Option<&Url>,
    raw: &str,
) -> Result<Url> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("probe path cannot be empty");
    }
    if let Ok(url) = Url::parse(trimmed) {
        return Ok(url);
    }

    let base = current_page_url
        .filter(|url| crate::url_origin::equivalent_hosts(target.url.host_str(), url.host_str()))
        .unwrap_or(&target.url);

    base.join(trimmed)
        .with_context(|| format!("join base={base} path={trimmed}"))
}

fn matches_success_url_patterns(url: &str, patterns: &[String]) -> bool {
    let url_l = url.to_ascii_lowercase();
    patterns.iter().any(|p| {
        let p = p.trim();
        !p.is_empty() && url_l.contains(&p.to_ascii_lowercase())
    })
}

fn accept_language_value(locale: &str) -> String {
    let locale = locale.trim();
    if locale.is_empty() {
        return "*".to_string();
    }

    // Prefer the full locale, then fall back to the base language if present.
    // Always include a low-priority wildcard.
    let mut parts = Vec::new();
    parts.push(locale.to_string());
    if let Some((lang, _)) = locale.split_once('-') {
        let lang = lang.trim();
        if !lang.is_empty() {
            parts.push(format!("{lang};q=0.9"));
        }
    }
    parts.push("*;q=0.1".to_string());
    parts.join(",")
}

/// Normalize any accepted cookie input (`Cookie:` header, `Set-Cookie:` lines,
/// or JSON export) into a `name=value; ...` `Cookie` header value.
pub(crate) fn cookie_header_from_raw(raw: &str) -> Result<String> {
    let pairs = extract_cookie_pairs(raw);
    if pairs.is_empty() {
        anyhow::bail!(
            "no parseable cookie key/value pairs found; expected Cookie header, Set-Cookie lines, or JSON cookies"
        );
    }
    Ok(pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; "))
}

fn parse_cookie_header(raw: &str, base_url: &Url) -> Result<Vec<CookieParam>> {
    let origin = origin_url(base_url)?;
    let pairs = extract_cookie_pairs(raw);
    if pairs.is_empty() {
        anyhow::bail!(
            "no parseable cookie key/value pairs found; expected Cookie header, Set-Cookie lines, or JSON cookies"
        );
    }

    let mut cookies = Vec::with_capacity(pairs.len());
    for (name, value) in pairs {
        let mut c = CookieParam::new(name, value);
        c.url = Some(origin.clone());
        cookies.push(c);
    }
    Ok(cookies)
}

fn extract_cookie_pairs(raw: &str) -> Vec<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut pairs = extract_cookie_pairs_from_json(trimmed);
    if !pairs.is_empty() {
        return dedupe_cookie_pairs(pairs);
    }

    for line in trimmed.lines() {
        let mut line = line.trim();
        if line.is_empty() {
            continue;
        }

        let explicit_set_cookie = starts_with_ignore_ascii_case(line, "set-cookie:");
        line = strip_prefix_ignore_ascii_case(line, "cookie:");
        line = strip_prefix_ignore_ascii_case(line, "set-cookie:");
        if line.is_empty() {
            continue;
        }

        if explicit_set_cookie || looks_like_set_cookie_line(line) {
            if let Some((name, value)) =
                parse_cookie_name_value(line.split(';').next().unwrap_or(""))
            {
                if !is_set_cookie_attribute_name(&name) {
                    pairs.push((name, value));
                }
            }
            continue;
        }

        for seg in line.split(';') {
            if let Some((name, value)) = parse_cookie_name_value(seg) {
                pairs.push((name, value));
            }
        }
    }

    dedupe_cookie_pairs(pairs)
}

fn extract_cookie_pairs_from_json(raw: &str) -> Vec<(String, String)> {
    let parsed: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    collect_cookie_pairs_from_json_value(&parsed, &mut out);
    out
}

fn collect_cookie_pairs_from_json_value(v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::Array(arr) => {
            for item in arr {
                collect_cookie_pairs_from_json_value(item, out);
            }
        }
        Value::Object(map) => {
            if let (Some(Value::String(name)), Some(Value::String(value))) =
                (map.get("name"), map.get("value"))
            {
                let name = name.trim();
                if !name.is_empty() {
                    out.push((name.to_string(), value.trim().to_string()));
                }
            }

            if let Some(cookies) = map.get("cookies") {
                collect_cookie_pairs_from_json_value(cookies, out);
            }
        }
        _ => {}
    }
}

fn parse_cookie_name_value(segment: &str) -> Option<(String, String)> {
    let seg = segment.trim();
    if seg.is_empty() {
        return None;
    }
    let (name, value) = seg.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.trim().to_string()))
}

fn is_set_cookie_attribute_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "domain"
            | "path"
            | "expires"
            | "max-age"
            | "samesite"
            | "secure"
            | "httponly"
            | "priority"
            | "partitioned"
            | "version"
            | "comment"
    )
}

fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .map(|head| head.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> &'a str {
    if starts_with_ignore_ascii_case(s, prefix) {
        s[prefix.len()..].trim()
    } else {
        s
    }
}

fn looks_like_set_cookie_line(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("httponly")
        || l.contains("samesite=")
        || l.contains("max-age=")
        || l.contains("expires=")
        || l.contains("path=")
        || l.contains("domain=")
}

fn dedupe_cookie_pairs(pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    // Last value wins for duplicate names.
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, value) in pairs {
        if let Some(slot) = out
            .iter_mut()
            .find(|(existing_name, _)| existing_name.eq_ignore_ascii_case(&name))
        {
            slot.1 = value;
        } else {
            out.push((name, value));
        }
    }
    out
}

fn origin_url(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("base url missing host: {url}"))?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push_str(&format!(":{port}"));
    }
    origin.push('/');
    Ok(origin)
}

/// Try common CSS selectors to find a Google sign-in button on the target app's login page.
async fn find_google_sign_in_button(page: &PageClient, timeout: Duration) -> Result<Element> {
    let selectors = [
        r#"[data-provider="google"]"#,
        "div.g_id_signin",
        "#g_id_onload",
        r#"button[aria-label*="Google" i]"#,
        r#"a[aria-label*="Google" i]"#,
        r#"button[data-social="google"]"#,
        r#"a[data-social="google"]"#,
        r#"a[href*="accounts.google.com/o/oauth2"]"#,
        r#"a[href*="accounts.google.com/signin/oauth"]"#,
    ];
    let start = Instant::now();
    let mut delay = Duration::from_millis(200);
    loop {
        for sel in &selectors {
            if let Ok(el) = page.inner().find_element(*sel).await {
                return Ok(el);
            }
        }
        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "timed out after {:?} looking for Google sign-in button; \
                 tried selectors {:?}. Provide an explicit `google_button_selector` in config.",
                timeout,
                selectors,
            ));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(1000));
    }
}

/// Poll `page.url()` until it contains "accounts.google.com".
async fn wait_for_google_domain(page: &PageClient, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    let mut delay = Duration::from_millis(200);
    loop {
        if let Ok(Some(url)) = page.url().await {
            if url.contains("accounts.google.com") {
                return Ok(());
            }
        }
        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "timed out after {:?} waiting for redirect to accounts.google.com",
                timeout,
            ));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(1000));
    }
}

/// Find Google's "Next" button on the accounts.google.com login flow.
async fn find_google_next_button(page: &PageClient, timeout: Duration) -> Result<Element> {
    let selectors = [
        "#identifierNext",
        "#passwordNext",
        r#"button[jsname="LgbsSe"]"#,
        "div#identifierNext",
        "div#passwordNext",
    ];
    let start = Instant::now();
    let mut delay = Duration::from_millis(300);
    loop {
        for sel in &selectors {
            if let Ok(el) = page.inner().find_element(*sel).await {
                return Ok(el);
            }
        }
        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "timed out after {:?} looking for Google Next button; tried selectors {:?}",
                timeout,
                selectors,
            ));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(1000));
    }
}

/// Poll `page.url()` until the host matches `target_host` or ends with `.{target_host}`.
async fn wait_for_target_redirect(
    page: &PageClient,
    target_host: &str,
    timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    let mut delay = Duration::from_millis(300);
    loop {
        if let Ok(Some(raw_url)) = page.url().await {
            if let Ok(parsed) = Url::parse(&raw_url) {
                if let Some(host) = parsed.host_str() {
                    if host == target_host || host.ends_with(&format!(".{target_host}")) {
                        return Ok(());
                    }
                }
            }
        }
        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "timed out after {:?} waiting for redirect back to {target_host}",
                timeout,
            ));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(1000));
    }
}

async fn find_element_retry(
    page: &PageClient,
    selector: &str,
    timeout: Duration,
) -> Result<Element> {
    let start = Instant::now();
    let mut delay = Duration::from_millis(150);
    loop {
        match page.inner().find_element(selector).await {
            Ok(el) => return Ok(el),
            Err(err) => {
                if start.elapsed() >= timeout {
                    return Err(err).with_context(|| {
                        format!(
                            "timed out after {:?} waiting for selector {}",
                            timeout, selector
                        )
                    });
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(1000));
            }
        }
    }
}

/// Wait for a selector to appear on the login page, or return redirect metadata
/// when we leave the login URL before the selector appears.
async fn wait_for_selector_or_redirect(
    page: &PageClient,
    selector: &str,
    login_url: &str,
    timeout: Duration,
) -> Result<SelectorWaitOutcome> {
    let start = Instant::now();
    let mut delay = Duration::from_millis(150);
    let mut last_err: Option<anyhow::Error> = None;

    loop {
        if start.elapsed() >= timeout {
            let current = page
                .url()
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "<unknown>".to_string());
            let ctx = format!(
                "login_failed: timed out after {:?} waiting for selector {} (current_url={})",
                timeout,
                selector,
                safe_auth_url(&current)
            );
            return match last_err.take() {
                Some(err) => Err(err).context(ctx),
                None => Err(anyhow!(ctx)),
            };
        }

        match page.inner().find_element(selector).await {
            Ok(el) => return Ok(SelectorWaitOutcome::Found(el)),
            Err(err) => {
                last_err = Some(anyhow!(err));
            }
        }

        if let Ok(Some(current)) = page.url().await {
            if current != "about:blank" && !same_login_route(&current, login_url) {
                return Ok(SelectorWaitOutcome::Redirected { url: current });
            }
        }

        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(1000));
    }
}

enum SelectorWaitOutcome {
    Found(Element),
    Redirected { url: String },
}

fn is_default_submit_selector(selector: &str) -> bool {
    let trimmed = selector.trim();
    trimmed.is_empty() || trimmed == crate::front::roles::DEFAULT_SUBMIT_SELECTOR
}

/// Passwordless dev-picker flow: `username` and `password` are both empty and
/// an explicit `--submit-selector` (e.g. `button[value="alice"]`) is set.
fn is_button_only_form_auth(username: &str, password: &str, submit_selector: &str) -> bool {
    username.trim().is_empty()
        && password.trim().is_empty()
        && !submit_selector.trim().is_empty()
        && !is_default_submit_selector(submit_selector)
}

/// Rank a visible button label for auto-detected React `<button type="button">`
/// login submission (lower is preferred; `None` means not a submit candidate).
fn submit_button_label_rank(label: &str, in_password_form: bool) -> Option<u8> {
    let norm: String = label
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if norm.is_empty() {
        return None;
    }
    const REJECT_CONTAINS: &[&str] = &[
        "show password",
        "hide password",
        "forgot",
        "reset password",
        "sign up",
        "signup",
        "register",
        "create account",
        "cancel",
        "back",
    ];
    if REJECT_CONTAINS.iter().any(|bad| norm.contains(bad)) {
        return None;
    }

    const PREFIXES: &[&str] = &[
        "sign in", "signin", "log in", "login", "continue", "submit", "next", "enter",
    ];
    let matched_prefix = PREFIXES.iter().find(|p| {
        if let Some(rest) = norm.strip_prefix(**p) {
            rest.is_empty() || !rest.as_bytes()[0].is_ascii_alphabetic()
        } else {
            false
        }
    })?;
    let exact = norm == *matched_prefix;
    const SSO_HINTS: &[&str] = &[
        "google",
        "github",
        "apple",
        "microsoft",
        "okta",
        "sso",
        "passkey",
        "magic link",
    ];
    let is_sso = SSO_HINTS.iter().any(|s| norm.contains(s));

    Some(match (in_password_form, exact, is_sso) {
        (true, true, false) => 0,
        (true, false, false) => 1,
        (false, true, false) => 2,
        (false, false, false) => 3,
        (true, _, true) => 4,
        (false, _, true) => 5,
    })
}

/// Collapse verbose/duplicated CDP error strings (like `-32000: Could not find
/// node with given id: Error -32000: ...`) into a concise, readable reason.
fn clean_cdp_error(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.contains("Could not find node with given id") {
        return "element not found or detached from DOM".to_string();
    }
    if trimmed.contains("Node is detached from document") {
        return "element detached from DOM".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in trimmed.split(": ") {
        let s = seg.trim();
        if s.is_empty() {
            continue;
        }
        let s_norm = s
            .strip_prefix("Error -32000: ")
            .or_else(|| s.strip_prefix("-32000: "))
            .unwrap_or(s);
        if !parts.iter().any(|prev| prev.eq_ignore_ascii_case(s_norm)) {
            parts.push(s_norm);
        }
    }
    let mut out = parts.join(": ");
    if out.chars().count() > 160 {
        out = out.chars().take(160).collect();
        out.push('…');
    }
    if out.is_empty() {
        "element interaction failed".to_string()
    } else {
        out
    }
}

async fn allow_enclosing_form_action(page: &PageClient, selector: &str, scope: &AuthWriteScope) {
    let Ok(sel_json) = serde_json::to_string(selector) else {
        return;
    };
    let action: Option<String> = page
        .evaluate_json(&format!(
            "(() => {{ const e = document.querySelector({sel_json}); const f = e && e.closest('form'); return f ? f.action : null; }})()"
        ))
        .await
        .unwrap_or(None);
    if let Some(action) = action {
        scope.allow_url(&action);
    }
}

async fn click_submit_element_with_retry(
    page: &PageClient,
    submit_el: Element,
    refind_selector: Option<&str>,
) -> Result<()> {
    match submit_el.click().await {
        Ok(_) => return Ok(()),
        Err(first_err) => {
            if let Some(sel) = refind_selector
                && let Ok(fresh) = page.inner().find_element(sel).await
                && fresh.click().await.is_ok()
            {
                return Ok(());
            }
            let reason = clean_cdp_error(&first_err.to_string());
            let sel_hint = refind_selector
                .filter(|s| {
                    !is_default_submit_selector(s) && !s.starts_with("[data-brokenapp-login-cand=")
                })
                .map(|s| format!(" matching {s:?}"))
                .unwrap_or_default();
            return Err(anyhow::Error::new(AuthFailure {
                message: format!(
                    "login_failed: failed to click submit button{sel_hint} ({reason}); specify or update --submit-selector \"<css>\""
                ),
                landed: page.url().await.ok().flatten().map(|u| safe_auth_url(&u)),
                http_status: None,
                page_alert: None,
            }));
        }
    }
}

#[derive(Debug, Deserialize)]
struct ReactButtonCandidate {
    idx: usize,
    label: String,
    in_form: bool,
    #[serde(default)]
    action: Option<String>,
}

struct ReactSubmitMatch {
    selector: String,
    action: Option<String>,
}

/// Locate a visible React `<button type="button">` / `[role="button"]` submit
/// control inside the password form (or nearest enclosing container around the
/// password input), ranked via [`submit_button_label_rank`].
async fn locate_react_submit_button(
    page: &PageClient,
    password_selector: &str,
) -> Option<ReactSubmitMatch> {
    let pass_sel_json = serde_json::to_string(password_selector).ok()?;
    let script = format!(
        r#"(() => {{
  for (const old of document.querySelectorAll('[data-brokenapp-login-cand]')) {{
    old.removeAttribute('data-brokenapp-login-cand');
  }}
  const passEl = document.querySelector({pass_sel_json}) || document.querySelector('input[type="password"]');
  const passForm = passEl ? passEl.closest('form') : null;
  const isVisible = (el) => {{
    if (!el || !el.getClientRects || !el.getClientRects().length) return false;
    const st = window.getComputedStyle ? window.getComputedStyle(el) : null;
    if (st && (st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0')) return false;
    if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
    return true;
  }};
  const btnQuery = 'button, [role="button"], input[type="button"]';
  const scopes = [];
  if (passForm) {{
    scopes.push({{ root: passForm, inForm: true }});
  }} else if (passEl) {{
    let cur = passEl.parentElement;
    for (let d = 0; d < 5 && cur && cur !== document.body && cur !== document.documentElement; d++) {{
      if (cur.querySelector(btnQuery)) {{
        scopes.push({{ root: cur, inForm: false }});
        break;
      }}
      cur = cur.parentElement;
    }}
  }}
  if (!scopes.length) {{
    scopes.push({{ root: document, inForm: false }});
  }}
  const out = [];
  let idx = 0;
  for (const sc of scopes) {{
    for (const el of sc.root.querySelectorAll(btnQuery)) {{
      if (!isVisible(el)) continue;
      const label = (el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '')
        .trim()
        .replace(/\s+/g, ' ');
      if (!label) continue;
      el.setAttribute('data-brokenapp-login-cand', String(idx));
      const form = el.closest('form') || passForm;
      out.push({{
        idx,
        label,
        in_form: sc.inForm,
        action: form ? form.action : null,
      }});
      idx++;
    }}
  }}
  return out;
}})()"#
    );
    let candidates: Vec<ReactButtonCandidate> = page.evaluate_json(&script).await.ok()?;
    let best = candidates
        .into_iter()
        .filter_map(|c| submit_button_label_rank(&c.label, c.in_form).map(|rank| (rank, c)))
        .min_by_key(|(rank, c)| (*rank, c.idx))
        .map(|(_, c)| c)?;
    Some(ReactSubmitMatch {
        selector: format!(r#"[data-brokenapp-login-cand="{}"]"#, best.idx),
        action: best.action,
    })
}

async fn submit_password_form(
    page: &PageClient,
    pass_el: &Element,
    password_selector: &str,
    submit_selector: &str,
    auth_scope: &AuthWriteScope,
) -> Result<()> {
    if !is_default_submit_selector(submit_selector) {
        let submit_el = find_element_retry(page, submit_selector, Duration::from_secs(20))
            .await
            .map_err(|err| {
                anyhow::Error::new(AuthFailure {
                    message: format!(
                        "login_failed: submit button not found for --submit-selector {submit_selector:?} ({}); verify --submit-selector \"<css>\"",
                        clean_cdp_error(&format!("{err:#}"))
                    ),
                    landed: None,
                    http_status: None,
                    page_alert: None,
                })
            })?;
        allow_enclosing_form_action(page, submit_selector, auth_scope).await;
        return click_submit_element_with_retry(page, submit_el, Some(submit_selector)).await;
    }

    // Auto-detect submit button:
    // 1) Standard submit controls inside the password form (DEFAULT_SUBMIT_SELECTOR).
    // 2) React `<button type="button">` / `[role="button"]` matching sign-in/login/continue/submit labels.
    // 3) Fallback: press `Enter` on the password input.
    let start = Instant::now();
    let detect_budget = Duration::from_secs(5);
    loop {
        if let Ok(submit_el) = page
            .inner()
            .find_element(crate::front::roles::DEFAULT_SUBMIT_SELECTOR)
            .await
        {
            allow_enclosing_form_action(
                page,
                crate::front::roles::DEFAULT_SUBMIT_SELECTOR,
                auth_scope,
            )
            .await;
            return click_submit_element_with_retry(
                page,
                submit_el,
                Some(crate::front::roles::DEFAULT_SUBMIT_SELECTOR),
            )
            .await;
        }

        if let Some(candidate) = locate_react_submit_button(page, password_selector).await {
            if let Some(action) = candidate.action.as_deref() {
                auth_scope.allow_url(action);
            }
            if let Ok(submit_el) = page.inner().find_element(&candidate.selector).await {
                return click_submit_element_with_retry(page, submit_el, Some(&candidate.selector))
                    .await;
            }
        }

        if start.elapsed() >= detect_budget {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Fallback: press Enter on the password input.
    tracing::debug!(
        "no submit button matched default or React heuristics; pressing Enter on password input"
    );
    allow_enclosing_form_action(page, password_selector, auth_scope).await;
    pass_el.press_key("Enter").await.map_err(|err| {
        anyhow::Error::new(AuthFailure {
            message: format!(
                "login_failed: no submit button found and pressing Enter on the password field failed ({}); pass --submit-selector \"<css>\"",
                clean_cdp_error(&err.to_string())
            ),
            landed: None,
            http_status: None,
            page_alert: None,
        })
    })?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct LandingDiagnostics {
    #[serde(default)]
    nav_status: u16,
    #[serde(default)]
    pass_visible: bool,
    #[serde(default)]
    submit_visible: bool,
    #[serde(default)]
    alert_text: Option<String>,
}

fn scrub_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() || !text.contains(secret) {
        text.to_string()
    } else {
        text.replace(secret, "***")
    }
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let mut out: String = trimmed.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

async fn validate_form_landing(
    page: &PageClient,
    password_selector: Option<&str>,
    button_only_submit_selector: Option<&str>,
    login_url: &str,
    password: &str,
    auth_monitor: Option<&AuthNetworkMonitor>,
) -> Result<()> {
    let pass_sel_json = match password_selector {
        Some(s) if !s.trim().is_empty() => serde_json::to_string(s)?,
        _ => "null".to_string(),
    };
    let submit_sel_json = match button_only_submit_selector {
        Some(s) if !s.trim().is_empty() => serde_json::to_string(s)?,
        _ => "null".to_string(),
    };
    let diag: LandingDiagnostics = page
        .evaluate_json(&format!(
            r#"(() => {{
  const n = performance.getEntriesByType('navigation')[0];
  const navStatus = (n && typeof n.responseStatus === 'number') ? n.responseStatus : 0;
  const passSel = {pass_sel_json};
  const passEl = passSel ? document.querySelector(passSel) : null;
  const passVisible = !!(passEl && passEl.getClientRects().length);
  const submitSel = {submit_sel_json};
  const submitEl = submitSel ? document.querySelector(submitSel) : null;
  const submitVisible = !!(submitEl && submitEl.getClientRects().length);
  const alerts = [];
  const seen = new Set();
  for (const el of document.querySelectorAll('[role="alert"], [aria-live="assertive"], .error, [data-error]')) {{
    if (!el || !el.getClientRects || !el.getClientRects().length) continue;
    const st = window.getComputedStyle ? window.getComputedStyle(el) : null;
    if (st && (st.visibility === 'hidden' || st.display === 'none' || st.opacity === '0')) continue;
    const text = (el.innerText || el.textContent || '').trim().replace(/\s+/g, ' ');
    if (text && !seen.has(text)) {{
      seen.add(text);
      alerts.push(text);
    }}
  }}
  return {{
    nav_status: navStatus,
    pass_visible: passVisible,
    submit_visible: submitVisible,
    alert_text: alerts.length ? alerts.join(' | ').slice(0, 200) : null
  }};
}})()"#
        ))
        .await
        .context("login_failed: could not verify the form landing page")?;

    let current_url = page
        .url()
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| login_url.to_string());

    let button_only_stuck = button_only_submit_selector.is_some()
        && same_login_route(&current_url, login_url)
        && diag.submit_visible;
    let failed = diag.nav_status >= 400 || diag.pass_visible || button_only_stuck;
    if !failed {
        return Ok(());
    }

    let landed = diagnostic_landed_url(&current_url, password);
    let page_alert = diag
        .alert_text
        .map(|t| truncate_chars(&scrub_secret(&t, password), 200))
        .filter(|t| !t.is_empty());
    let failed_req = auth_monitor.and_then(AuthNetworkMonitor::best_failure);
    let http_status = failed_req
        .as_ref()
        .map(|f| f.status)
        .or_else(|| (diag.nav_status >= 400).then_some(diag.nav_status));

    let reason = if diag.nav_status >= 400 {
        format!("sign-in reached an error page (HTTP {})", diag.nav_status)
    } else if diag.pass_visible {
        "sign-in still shows the password field".to_string()
    } else {
        "sign-in remained on the login page".to_string()
    };

    let mut details = vec![format!("landed: {landed}")];
    if let Some(alert) = page_alert.as_deref() {
        details.push(format!("alert: {alert:?}"));
    }
    if let Some(req) = failed_req.as_ref() {
        details.push(format!(
            "failed request: {} {} -> {}",
            req.method, req.target, req.status
        ));
    }

    let message = format!("login_failed: {reason} ({})", details.join("; "));
    Err(anyhow::Error::new(AuthFailure {
        message,
        landed: Some(landed),
        http_status,
        page_alert,
    }))
}

fn same_login_route(current: &str, login: &str) -> bool {
    let (Ok(current), Ok(login)) = (Url::parse(current), Url::parse(login)) else {
        return false;
    };
    let route = |url: &Url| {
        url.fragment()
            .filter(|f| f.starts_with('/') || f.starts_with("!/"))
            .map(|f| f.split('?').next().unwrap_or(f).to_string())
    };
    current.origin() == login.origin()
        && current.path().trim_end_matches('/') == login.path().trim_end_matches('/')
        && route(&current) == route(&login)
}

/// Auth redirects may carry credentials in query/fragment/userinfo. The
/// canary and diagnostics need only the destination route.
pub(crate) fn safe_auth_url(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<unknown>".to_string();
    };
    let route = url
        .fragment()
        .filter(|f| f.starts_with('/') || f.starts_with("!/"))
        .map(|f| f.split('?').next().unwrap_or(f).to_string());
    url.set_query(None);
    url.set_fragment(route.as_deref());
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

/// Like [`safe_auth_url`], but preserves safe error-indicator query parameters
/// (such as `?error=CredentialsSignin` or `?reason=expired`) for login failure
/// diagnostics while stripping credentials/tokens and scrubbing `secret`.
fn diagnostic_landed_url(raw: &str, secret: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<unknown>".to_string();
    };
    let route = url
        .fragment()
        .filter(|f| f.starts_with('/') || f.starts_with("!/"))
        .map(|f| f.split('?').next().unwrap_or(f).to_string());
    const SAFE_ERROR_KEYS: &[&str] = &[
        "error",
        "error_code",
        "error_description",
        "reason",
        "code",
        "status",
        "message",
    ];
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| SAFE_ERROR_KEYS.contains(&k.to_ascii_lowercase().as_str()))
        .map(|(k, v)| {
            let clean = truncate_chars(&scrub_secret(&v, secret), 80);
            (k.into_owned(), clean)
        })
        .collect();
    url.set_query(None);
    if !kept.is_empty() {
        let mut qp = url.query_pairs_mut();
        for (k, v) in kept {
            qp.append_pair(&k, &v);
        }
    }
    url.set_fragment(route.as_deref());
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

fn looks_like_authenticated_redirect(url: &str, login: &str) -> bool {
    if same_login_route(url, login) || crate::session::health::looks_like_login_page(url, None) {
        return false;
    }
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    !url.path().split('/').any(|segment| {
        [
            "error",
            "failed",
            "invalid",
            "denied",
            "unauthorized",
            "forbidden",
        ]
        .contains(&segment)
    })
}

#[cfg(test)]
mod tests {
    use super::{extract_cookie_pairs, parse_cookie_header, resolve_probe_url_for_page};
    use crate::config::TargetConfig;
    use std::path::PathBuf;
    use url::Url;

    fn target(url: &str) -> TargetConfig {
        TargetConfig {
            url: Url::parse(url).unwrap(),
            name: None,
            chrome_executable: None::<PathBuf>,
            headless: true,
            ignore_https_errors: false,
            remote_chrome_url: None,
            locale: None,
        }
    }

    #[test]
    fn login_redirects_compare_routes_not_query_substrings() {
        assert!(super::looks_like_authenticated_redirect(
            "https://app.test/dashboard",
            "https://app.test/"
        ));
        assert!(super::looks_like_authenticated_redirect(
            "https://app.test/dashboard?return=/login",
            "https://app.test/login"
        ));
        assert!(super::same_login_route(
            "https://app.test/login?next=/",
            "https://app.test/login"
        ));
        assert!(!super::same_login_route(
            "https://app.test/#/dashboard",
            "https://app.test/#/login"
        ));
        assert_eq!(
            super::safe_auth_url(
                "https://user:secret@app.test/dashboard?token=secret#access_token=secret"
            ),
            "https://app.test/dashboard"
        );
    }

    #[test]
    fn parses_cookie_header_pairs() {
        let pairs = extract_cookie_pairs("session=abc; token=xyz; theme=dark");
        assert_eq!(
            pairs,
            vec![
                ("session".to_string(), "abc".to_string()),
                ("token".to_string(), "xyz".to_string()),
                ("theme".to_string(), "dark".to_string()),
            ]
        );
    }

    #[test]
    fn parses_set_cookie_lines_and_ignores_attributes() {
        let raw = "Set-Cookie: session=abc; Path=/; HttpOnly\nSet-Cookie: token=xyz; Secure; SameSite=Lax";
        let pairs = extract_cookie_pairs(raw);
        assert_eq!(
            pairs,
            vec![
                ("session".to_string(), "abc".to_string()),
                ("token".to_string(), "xyz".to_string()),
            ]
        );
    }

    #[test]
    fn parses_json_cookie_export() {
        let raw = r#"[{"name":"session","value":"abc"},{"name":"token","value":"xyz"}]"#;
        let pairs = extract_cookie_pairs(raw);
        assert_eq!(
            pairs,
            vec![
                ("session".to_string(), "abc".to_string()),
                ("token".to_string(), "xyz".to_string()),
            ]
        );
    }

    #[test]
    fn parse_cookie_header_rejects_empty_payload() {
        let base = Url::parse("https://example.com/login").unwrap();
        let err = parse_cookie_header("Path=/; HttpOnly", &base).unwrap_err();
        assert!(
            err.to_string()
                .contains("no parseable cookie key/value pairs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn protected_probe_relative_path_uses_current_page_origin() {
        let target = target("http://127.0.0.1:4102");
        let current_page = Url::parse("http://localhost:4102/dashboard").unwrap();

        let got = resolve_probe_url_for_page(&target, Some(&current_page), "/api/me").unwrap();

        assert_eq!(got.as_str(), "http://localhost:4102/api/me");
    }

    #[test]
    fn protected_probe_absolute_url_stays_explicit() {
        let target = target("http://127.0.0.1:4102");
        let current_page = Url::parse("http://localhost:4102/dashboard").unwrap();

        let got =
            resolve_probe_url_for_page(&target, Some(&current_page), "https://api.example.com/me")
                .unwrap();

        assert_eq!(got.as_str(), "https://api.example.com/me");
    }

    #[test]
    fn react_submit_button_label_ranking_and_cdp_cleanup() {
        assert!(super::is_default_submit_selector(""));
        assert!(super::is_default_submit_selector(
            crate::front::roles::DEFAULT_SUBMIT_SELECTOR
        ));
        assert!(!super::is_default_submit_selector("button[type=button]"));

        // Exact & prefix matches inside password form beat out-of-form and SSO buttons.
        assert_eq!(super::submit_button_label_rank("Sign in", true), Some(0));
        assert_eq!(super::submit_button_label_rank("Log   in", true), Some(0));
        assert_eq!(super::submit_button_label_rank("Continue", true), Some(0));
        assert_eq!(
            super::submit_button_label_rank("Sign in to Portal", true),
            Some(1)
        );
        assert_eq!(
            super::submit_button_label_rank("Sign in with Google", true),
            Some(4)
        );
        assert!(
            super::submit_button_label_rank("Sign in", true)
                < super::submit_button_label_rank("Sign in with Google", true)
        );
        assert_eq!(super::submit_button_label_rank("Submit", false), Some(2));

        // Non-submit controls are rejected.
        assert_eq!(super::submit_button_label_rank("Show password", true), None);
        assert_eq!(
            super::submit_button_label_rank("Forgot password?", true),
            None
        );
        assert_eq!(super::submit_button_label_rank("Enterprise", true), None);
        assert_eq!(super::submit_button_label_rank("Cancel", true), None);

        // Duplicated raw CDP -32000 errors collapse cleanly.
        let cleaned = super::clean_cdp_error(
            "-32000: Could not find node with given id: Error -32000: Could not find node with given id",
        );
        assert!(!cleaned.contains("-32000"), "{cleaned}");
        assert!(cleaned.contains("not found or detached"), "{cleaned}");
    }

    #[test]
    fn button_only_form_auth_detection_requires_explicit_selector_and_empty_creds() {
        assert!(super::is_button_only_form_auth(
            "",
            "",
            r#"button[value="alice"]"#
        ));
        assert!(!super::is_button_only_form_auth(
            "",
            "",
            crate::front::roles::DEFAULT_SUBMIT_SELECTOR
        ));
        assert!(!super::is_button_only_form_auth("", "", ""));
        assert!(!super::is_button_only_form_auth(
            "alice@example.test",
            "",
            r#"button[value="alice"]"#
        ));
    }

    #[test]
    fn opaque_redirect_and_http_redirect_probe_diagnostics_are_actionable() {
        let opaque = super::ProbeStatusResult {
            status: 0,
            response_type: Some("opaqueredirect".to_string()),
            error: None,
        };
        assert!(opaque.is_opaque_redirect());

        let fallback =
            super::format_browser_probe_failure("GET", "/api/me", &opaque, &[200, 204], None);
        assert!(
            fallback
                .message
                .contains("redirected (e.g. 302/307 to login; fetch opaqueredirect, status=0"),
            "{}",
            fallback.message
        );
        assert_eq!(fallback.http_status, None);

        let http_307 = super::HttpProbeOutcome {
            status: 307,
            location: Some("/auth".to_string()),
            method: "GET",
            probe_url: "http://127.0.0.1:3000/api/me".to_string(),
        };
        let with_redirect = super::format_browser_probe_failure(
            "GET",
            "/api/me",
            &opaque,
            &[200, 204],
            Some(&http_307),
        );
        assert!(
            with_redirect.message.contains("HTTP 307 -> /auth"),
            "{}",
            with_redirect.message
        );
        assert_eq!(with_redirect.http_status, Some(307));
        assert_eq!(with_redirect.landed.as_deref(), Some("/auth"));

        let direct = super::format_http_probe_failure(&http_307, &[200, 204]);
        assert!(
            direct
                .message
                .contains("GET /api/me returned HTTP 307 -> /auth"),
            "{}",
            direct.message
        );
        assert_eq!(direct.http_status, Some(307));
        assert_eq!(direct.landed.as_deref(), Some("/auth"));
    }

    #[test]
    fn diagnostic_landed_url_keeps_error_query_and_strips_secrets() {
        assert_eq!(
            super::diagnostic_landed_url(
                "http://127.0.0.1:3000/auth?error=CredentialsSignin&token=secret-jwt",
                "my-pass"
            ),
            "http://127.0.0.1:3000/auth?error=CredentialsSignin"
        );
        let scrubbed = super::diagnostic_landed_url(
            "http://127.0.0.1:3000/auth?error=bad+my-pass&next=/admin",
            "my-pass",
        );
        assert!(!scrubbed.contains("my-pass"), "{scrubbed}");
        assert!(!scrubbed.contains("next="), "{scrubbed}");
        let parsed = Url::parse(&scrubbed).unwrap();
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(pairs, vec![("error".to_string(), "bad ***".to_string())]);
    }

    #[tokio::test]
    async fn http_protected_probe_retries_once_on_cold_timeout_and_succeeds() {
        use crate::config::{AuthProbeMethod, AuthProtectedProbe};
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let hits_srv = Arc::clone(&hits_srv);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    if path == "/always-slow" {
                        tokio::time::sleep(Duration::from_millis(600)).await;
                    } else {
                        let attempt = hits_srv.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            // First cold SSR compile outlasts the per-attempt timeout.
                            tokio::time::sleep(Duration::from_millis(600)).await;
                        }
                    }
                    let resp =
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        let tgt = target(&format!("http://127.0.0.1:{port}"));
        let probe = AuthProtectedProbe {
            path: "/api/me".to_string(),
            method: AuthProbeMethod::Get,
            expected_statuses: vec![200],
        };
        let outcome = super::http_protected_probe_with_timeout(
            &tgt,
            &probe,
            Some("sid=abc"),
            &BTreeMap::new(),
            Duration::from_millis(200),
        )
        .await
        .expect("second attempt after cold timeout should succeed");
        assert_eq!(outcome.status, 200);
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // If the retry also times out, fail cleanly instead of looping.
        let slow_probe = AuthProtectedProbe {
            path: "/always-slow".to_string(),
            method: AuthProbeMethod::Get,
            expected_statuses: vec![200],
        };
        let err = super::http_protected_probe_with_timeout(
            &tgt,
            &slow_probe,
            None,
            &BTreeMap::new(),
            Duration::from_millis(150),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("after retry on timeout"),
            "{err:#}"
        );
        handle.abort();
    }
}
