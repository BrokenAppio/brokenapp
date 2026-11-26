pub mod auth;
pub mod cookies;
pub mod health;
pub mod persistence;
pub mod providers;
pub mod secrets;
pub mod storage_state;

use anyhow::Result;
use chromiumoxide::browser::Browser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::browser::PageClient;
use crate::config::{AuthConfig, AuthSuccessContract, TargetConfig};
use crate::network::interceptor::NetworkInterceptor;

/// Provider-specific credentials needed for token refresh.
#[derive(Debug, Clone)]
pub enum AuthProvider {
    Supabase {
        project_url: String,
        anon_key: String,
    },
    Firebase {
        api_key: String,
    },
}

/// A re-authentication event recorded during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReauthEvent {
    pub at: chrono::DateTime<chrono::Utc>,
    pub method: ReauthMethod,
    pub success: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReauthMethod {
    TokenRefresh,
    FullReauth,
}

#[derive(Debug, Clone, Default)]
pub struct SessionState {
    pub extra_headers: std::collections::BTreeMap<String, String>,
    pub refresh_token: Option<String>,
    pub auth_provider: Option<AuthProvider>,
    pub token_expires_at: Option<std::time::Instant>,
    /// History of re-authentication attempts during the scan.
    pub reauth_history: Vec<ReauthEvent>,
    /// Page script that restores a saved session's local/session storage
    /// (see [`storage_state`]); registered on every page before its first
    /// navigation by [`SessionManager::apply_to_page`].
    pub storage_init_script: Option<SecretText>,
    /// An authenticated page this session reached (where the login or the
    /// session capture landed). Navigating to it and landing on the login
    /// page means the session is gone: the scan's session canary.
    pub canary_url: Option<String>,
    /// Path (or URL substring) of the app's login page, when known.
    pub login_hint: Option<String>,
    /// Target origin URL used by provider session injection (e.g. Supabase token refresh).
    pub(crate) target_url: Option<url::Url>,
}

/// A secret string (credentials, tokens, saved storage) whose `Debug` output
/// is redacted.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret itself. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

pub struct SessionManager;

impl SessionManager {
    pub async fn authenticate(
        browser: &Browser,
        target: &TargetConfig,
        auth: &Option<AuthConfig>,
        auth_contract: Option<&AuthSuccessContract>,
        network: Option<&Arc<NetworkInterceptor>>,
    ) -> Result<SessionState> {
        auth::authenticate(browser, target, auth, auth_contract, network).await
    }

    /// Apply the session to a fresh page, before its first navigation:
    /// auth headers, and a saved session's local/session storage (cookies
    /// live in the browser's shared cookie jar already).
    pub async fn apply_to_page(page: &PageClient, state: &SessionState) -> Result<()> {
        if !state.extra_headers.is_empty() {
            page.set_extra_http_headers(
                state
                    .extra_headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            )
            .await?;
        }
        if let Some(script) = state.storage_init_script.as_ref() {
            let params =
                chromiumoxide::cdp::browser_protocol::page::AddScriptToEvaluateOnNewDocumentParams::builder()
                    .source(script.expose())
                    .build()
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            page.inner().execute(params).await.map_err(|e| {
                anyhow::anyhow!(
                    "Page.addScriptToEvaluateOnNewDocument (saved session storage): {e}"
                )
            })?;
        }
        Ok(())
    }

    /// Try to refresh the access token using a stored refresh token.
    /// Returns `Ok(true)` if refresh succeeded, `Ok(false)` if no refresh
    /// token is available, `Err` if the refresh attempt failed.
    pub async fn try_token_refresh(state: &mut SessionState) -> Result<bool> {
        let (refresh_token, provider) =
            match (state.refresh_token.as_deref(), state.auth_provider.as_ref()) {
                (Some(rt), Some(provider)) => (rt.to_string(), provider.clone()),
                _ => return Ok(false),
            };

        let resp = match &provider {
            AuthProvider::Supabase {
                project_url,
                anon_key,
            } => providers::supabase_refresh(project_url, anon_key, &refresh_token).await?,
            AuthProvider::Firebase { api_key } => {
                providers::firebase_refresh(api_key, &refresh_token).await?
            }
        };

        state.extra_headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", resp.access_token),
        );
        if let AuthProvider::Supabase { project_url, .. } = &provider
            && let Some(target_url) = state.target_url.as_ref()
        {
            let session_json = providers::supabase_session_json(&resp);
            state.storage_init_script = providers::supabase_local_storage_init_script(
                project_url,
                target_url,
                &session_json,
            )
            .map(SecretText::new);
        }
        state.refresh_token = resp.refresh_token.or(Some(refresh_token));
        state.token_expires_at = if resp.expires_in > 0 {
            Some(std::time::Instant::now() + std::time::Duration::from_secs(resp.expires_in))
        } else {
            None
        };

        tracing::info!(expires_in = resp.expires_in, "token refreshed successfully");
        Ok(true)
    }
}
