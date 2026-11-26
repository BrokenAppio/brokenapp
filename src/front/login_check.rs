//! Interactive credential verification uses the scanner's authenticator and
//! write guard (or fast non-redirecting HTTP `--check` verification for
//! `cookie`/`bearer`). `map` authenticates in its own scan process; there is no
//! separate browser preflight that could write before that guard is active.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use url::Url;

use super::roles::FormLogin;
use crate::browser::cdp_helpers;
use crate::browser::pool::{BrowserLaunchOptions, BrowserManager};
use crate::config::{AuthConfig, AuthSuccessContract, ScanConfig, TargetConfig, WriteGuardMode};
use crate::network::interceptor::NetworkInterceptor;
use crate::session::SessionManager;
use crate::session::auth::{self as session_auth, AuthFailure};

pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct LoginCheckOptions {
    pub base_url: Url,
    pub headless: bool,
    pub ignore_https_errors: bool,
    pub contract: Option<AuthSuccessContract>,
    /// Explicit project exceptions, identical to the role's map scan.
    pub write_guard_allow: Vec<String>,
    /// Per-attempt timeout for HTTP `--check` protected probes (defaults to 30s when zero).
    pub probe_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LoginCheck {
    pub ok: bool,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_alert: Option<String>,
}

pub async fn check_form_login(form: &FormLogin, opts: &LoginCheckOptions) -> Result<LoginCheck> {
    let auth = AuthConfig::Form {
        login_url: form.login_url.clone(),
        username_selector: form.username_selector.clone(),
        password_selector: form.password_selector.clone(),
        submit_selector: form.submit_selector.clone(),
        username: form.username.clone(),
        password: form.password.clone(),
    };
    check_auth_login(&auth, opts).await
}

/// Verify credentials for any non-interactive auth method (`form`, `cookie`,
/// `bearer`, `supabase`, `firebase`) using the same authenticator and write
/// guard that `map` uses — or fast direct HTTP `--check` verification for
/// `cookie`/`bearer` when a `protected_probe` is configured.
pub async fn check_auth_login(auth: &AuthConfig, opts: &LoginCheckOptions) -> Result<LoginCheck> {
    let target = TargetConfig {
        url: opts.base_url.clone(),
        name: None,
        chrome_executable: None,
        headless: opts.headless,
        ignore_https_errors: opts.ignore_https_errors,
        remote_chrome_url: None,
        locale: None,
    };

    // Fast HTTP preflight for cookie/bearer when `--check` (`protected_probe`)
    // is configured and no browser-only URL pattern is required.
    if let Some(contract) = opts.contract.as_ref()
        && let Some(probe) = contract.protected_probe.as_ref()
        && contract.success_url_patterns.is_empty()
        && matches!(
            auth,
            AuthConfig::Cookie { .. } | AuthConfig::BearerToken { .. }
        )
    {
        let resolved = match crate::session::secrets::resolve_auth_secrets(auth) {
            Ok(a) => a,
            Err(err) => {
                return Ok(LoginCheck {
                    ok: false,
                    detail: format!("{err:#}"),
                    landed: None,
                    http_status: None,
                    page_alert: None,
                });
            }
        };
        let mut extra_headers = BTreeMap::new();
        let cookie_header = match &resolved {
            AuthConfig::Cookie { cookie } => match session_auth::cookie_header_from_raw(cookie) {
                Ok(hdr) => {
                    if !contract.required_cookie_names.is_empty() {
                        let names: std::collections::HashSet<String> = hdr
                            .split(';')
                            .filter_map(|p| p.split_once('=').map(|(k, _)| k.trim().to_string()))
                            .collect();
                        let missing: Vec<String> = contract
                            .required_cookie_names
                            .iter()
                            .filter(|n| !names.contains(n.as_str()))
                            .cloned()
                            .collect();
                        if !missing.is_empty() {
                            return Ok(LoginCheck {
                                ok: false,
                                detail: format!(
                                    "auth required_cookie_names missing: {}",
                                    missing.join(", ")
                                ),
                                landed: None,
                                http_status: None,
                                page_alert: None,
                            });
                        }
                    }
                    Some(hdr)
                }
                Err(err) => {
                    return Ok(LoginCheck {
                        ok: false,
                        detail: format!("{err:#}"),
                        landed: None,
                        http_status: None,
                        page_alert: None,
                    });
                }
            },
            AuthConfig::BearerToken { token } => {
                if token.trim().is_empty() {
                    return Ok(LoginCheck {
                        ok: false,
                        detail: "bearer token is empty".to_string(),
                        landed: None,
                        http_status: None,
                        page_alert: None,
                    });
                }
                extra_headers.insert("Authorization".to_string(), format!("Bearer {token}"));
                None
            }
            _ => None,
        };

        let probe_timeout = if opts.probe_timeout.is_zero() {
            DEFAULT_PROBE_TIMEOUT
        } else {
            opts.probe_timeout
        };
        return Ok(
            match session_auth::http_protected_probe_with_timeout(
                &target,
                probe,
                cookie_header.as_deref(),
                &extra_headers,
                probe_timeout,
            )
            .await
            {
                Ok(outcome) if probe.expected_statuses.contains(&outcome.status) => LoginCheck {
                    ok: true,
                    detail: format!(
                        "{} {} returned HTTP {} (expected {:?})",
                        outcome.method, probe.path, outcome.status, probe.expected_statuses
                    ),
                    landed: None,
                    http_status: Some(outcome.status),
                    page_alert: None,
                },
                Ok(outcome) => {
                    let failure =
                        session_auth::format_http_probe_failure(&outcome, &probe.expected_statuses);
                    LoginCheck {
                        ok: false,
                        detail: failure.message,
                        landed: failure.landed,
                        http_status: failure.http_status,
                        page_alert: None,
                    }
                }
                Err(err) => LoginCheck {
                    ok: false,
                    detail: format!("protected probe {} failed: {err:#}", probe.path),
                    landed: None,
                    http_status: None,
                    page_alert: None,
                },
            },
        );
    }

    let browser = BrowserManager::launch(BrowserLaunchOptions {
        chrome_executable: BrowserManager::detect_chrome_executable(),
        headless: opts.headless,
        ignore_https_errors: opts.ignore_https_errors,
        remote_chrome_url: None,
        locale: None,
    })
    .await
    .context("launch Chrome for the login check")?;

    let auth_opt = Some(auth.clone());
    let mut cfg = ScanConfig::default();
    cfg.write_guard.mode = WriteGuardMode::Block;
    cfg.write_guard.allow.clone_from(&opts.write_guard_allow);
    let network = Arc::new(NetworkInterceptor::new(cfg, None, false));
    network.set_first_party_origin(&opts.base_url);

    let result = SessionManager::authenticate(
        browser.browser(),
        &target,
        &auth_opt,
        opts.contract.as_ref(),
        Some(&network),
    )
    .await;

    let check = match result {
        Ok(session_state) => {
            let has_contract = opts.contract.as_ref().is_some_and(|c| {
                !c.success_url_patterns.is_empty()
                    || !c.required_cookie_names.is_empty()
                    || c.protected_probe.is_some()
            });
            // For cookie/bearer without a `--check` probe, visit the app root
            // under write_guard = block to verify we don't bounce to a login gate.
            if !has_contract
                && matches!(
                    auth,
                    AuthConfig::Cookie { .. } | AuthConfig::BearerToken { .. }
                )
            {
                verify_root_landing(&browser, &target, &session_state, &network).await
            } else {
                LoginCheck {
                    ok: true,
                    detail: success_detail_for(auth, has_contract),
                    landed: session_state.canary_url,
                    http_status: None,
                    page_alert: None,
                }
            }
        }
        Err(err) => {
            let af = err
                .chain()
                .find_map(|e| e.downcast_ref::<AuthFailure>())
                .cloned();
            LoginCheck {
                ok: false,
                detail: format!("{err:#}"),
                landed: af.as_ref().and_then(|f| f.landed.clone()),
                http_status: af.as_ref().and_then(|f| f.http_status),
                page_alert: af.and_then(|f| f.page_alert),
            }
        }
    };

    let _ = browser.shutdown().await;
    Ok(check)
}

fn success_detail_for(auth: &AuthConfig, has_contract: bool) -> String {
    match auth {
        AuthConfig::Form { .. } => {
            "the scanner accepted the login and its configured authentication checks".to_string()
        }
        AuthConfig::Supabase { .. } if has_contract => {
            "Supabase sign-in succeeded and the configured --check probe passed".to_string()
        }
        AuthConfig::Supabase { .. } => {
            "Supabase sign-in succeeded (add --check /api/me to also verify app session cookies)"
                .to_string()
        }
        AuthConfig::Firebase { .. } if has_contract => {
            "Firebase sign-in succeeded and the configured --check probe passed".to_string()
        }
        AuthConfig::Firebase { .. } => {
            "Firebase sign-in succeeded (add --check /api/me to also verify app API auth)"
                .to_string()
        }
        AuthConfig::Cookie { .. } => {
            "cookie accepted and the configured authentication checks passed".to_string()
        }
        AuthConfig::BearerToken { .. } => {
            "bearer token accepted and the configured authentication checks passed".to_string()
        }
        _ => "authentication succeeded".to_string(),
    }
}

async fn verify_root_landing(
    browser: &BrowserManager,
    target: &TargetConfig,
    state: &crate::session::SessionState,
    network: &Arc<NetworkInterceptor>,
) -> LoginCheck {
    let page = match browser.new_page("about:blank").await {
        Ok(p) => p,
        Err(err) => {
            return LoginCheck {
                ok: false,
                detail: format!("open browser page to verify credentials: {err:#}"),
                landed: None,
                http_status: None,
                page_alert: None,
            };
        }
    };
    let res = async {
        page.enable_domains().await?;
        cdp_helpers::install_instrumentation(&page).await?;
        SessionManager::apply_to_page(&page, state).await?;
        let _guard = Arc::clone(network)
            .attach_isolated(
                page.inner(),
                Some(format!("login_check_{}", uuid::Uuid::new_v4())),
            )
            .await?;
        session_auth::goto_with_cold_compile_retry(&page, target.url.as_str()).await?;
        let _ = cdp_helpers::settle(&page, Duration::from_secs(5)).await;
        let current = page
            .url()
            .await?
            .unwrap_or_else(|| target.url.to_string());
        let nav_status: u16 = page
            .evaluate_json(
                "(() => { const n = performance.getEntriesByType('navigation')[0]; return (n && typeof n.responseStatus === 'number') ? n.responseStatus : 0; })()",
            )
            .await
            .unwrap_or(0);
        Ok::<_, anyhow::Error>((current, nav_status))
    }
    .await;
    let _ = page.inner().clone().close().await;

    match res {
        Ok((current, nav_status)) => {
            let safe_landed = session_auth::safe_auth_url(&current);
            if nav_status >= 400 {
                return LoginCheck {
                    ok: false,
                    detail: format!(
                        "visiting {} returned HTTP {nav_status} (landed: {safe_landed})",
                        target.url
                    ),
                    landed: Some(safe_landed),
                    http_status: Some(nav_status),
                    page_alert: None,
                };
            }
            if crate::session::health::landed_on_login_gate(target.url.as_str(), &current, None) {
                return LoginCheck {
                    ok: false,
                    detail: format!(
                        "visiting {} redirected to login ({safe_landed}); credentials appear invalid or expired (add --check /api/me for an explicit probe)",
                        target.url
                    ),
                    landed: Some(safe_landed),
                    http_status: None,
                    page_alert: None,
                };
            }
            LoginCheck {
                ok: true,
                detail: format!(
                    "credentials accepted on {} (no --check probe configured; add --check /api/me for stricter API verification)",
                    target.url
                ),
                landed: Some(safe_landed),
                http_status: (nav_status > 0).then_some(nav_status),
                page_alert: None,
            }
        }
        Err(err) => LoginCheck {
            ok: false,
            detail: format!("navigate to {} to verify credentials: {err:#}", target.url),
            landed: None,
            http_status: None,
            page_alert: None,
        },
    }
}
