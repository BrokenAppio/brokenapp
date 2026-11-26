//! Auth providers: Supabase & Firebase REST API sign-in.

use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use chromiumoxide::cdp::browser_protocol::network::{CookieParam, CookieSameSite};
use serde::{Deserialize, Serialize};
use url::Url;

/// Helpful hint appended when a Supabase role's auth contract check still fails
/// against an app that uses custom `@supabase/ssr` cookie names.
pub const SUPABASE_SSR_HINT: &str = "Note: @supabase/ssr apps with custom cookie names should use --method form or --method session.";

/// Maximum encoded value length per `@supabase/ssr` cookie chunk.
const SUPABASE_SSR_MAX_CHUNK_SIZE: usize = 3180;

/// Successful sign-in response (unified across providers).
#[derive(Clone)]
pub struct SignInResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    /// Full session JSON returned by the provider (when available, e.g. Supabase GoTrue),
    /// used to populate browser `localStorage` and `@supabase/ssr` cookies.
    pub raw_session_json: Option<String>,
}

impl fmt::Debug for SignInResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignInResponse")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field(
                "raw_session_json",
                &self.raw_session_json.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

// ── Supabase ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SupabaseSignInRequest<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct SupabaseSignInResponse {
    access_token: String,
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Serialize)]
struct SupabaseRefreshRequest<'a> {
    refresh_token: &'a str,
}

fn parse_supabase_session_response(raw: &str) -> Result<SignInResponse> {
    let mut val: serde_json::Value =
        serde_json::from_str(raw).context("parse supabase response")?;
    let body: SupabaseSignInResponse =
        serde_json::from_value(val.clone()).context("parse supabase response")?;
    if let Some(obj) = val.as_object_mut() {
        obj.entry("token_type".to_string())
            .or_insert_with(|| serde_json::Value::String("bearer".to_string()));
        if !obj.contains_key("expires_at") && body.expires_in > 0 {
            let expires_at = chrono::Utc::now().timestamp() + body.expires_in as i64;
            obj.insert("expires_at".to_string(), serde_json::json!(expires_at));
        }
    }
    let raw_session_json = serde_json::to_string(&val).ok();
    Ok(SignInResponse {
        access_token: body.access_token,
        refresh_token: body.refresh_token,
        expires_in: body.expires_in,
        raw_session_json,
    })
}

/// Default `@supabase/supabase-js` and `@supabase/ssr` storage key / cookie name:
/// `sb-<first-host-label>-auth-token` (e.g. `https://abc.supabase.co` -> `sb-abc-auth-token`,
/// `http://127.0.0.1:54321` -> `sb-127-auth-token`, `http://localhost:54321` -> `sb-localhost-auth-token`).
pub fn supabase_storage_key(project_url: &str) -> Option<String> {
    let url = Url::parse(project_url.trim()).ok()?;
    let host = url.host_str()?;
    let prefix = host.split('.').next()?.trim();
    if prefix.is_empty() {
        return None;
    }
    Some(format!("sb-{prefix}-auth-token"))
}

/// Canonical Supabase `Session` JSON for `localStorage` and `@supabase/ssr` cookies.
pub fn supabase_session_json(resp: &SignInResponse) -> String {
    if let Some(raw) = resp
        .raw_session_json
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return raw.to_string();
    }
    let expires_at = chrono::Utc::now().timestamp() + resp.expires_in as i64;
    serde_json::json!({
        "access_token": resp.access_token,
        "refresh_token": resp.refresh_token.as_deref().unwrap_or(""),
        "token_type": "bearer",
        "expires_in": resp.expires_in,
        "expires_at": expires_at,
    })
    .to_string()
}

/// Build `@supabase/ssr` cookie(s) (`sb-<host-prefix>-auth-token`, chunked as `.0`, `.1`, ...
/// when the `base64-<url-safe-b64>` payload exceeds 3180 bytes) scoped to `target_url`'s origin.
pub fn supabase_ssr_cookies(
    project_url: &str,
    target_url: &Url,
    session_json: &str,
) -> Vec<CookieParam> {
    let Some(key) = supabase_storage_key(project_url) else {
        return Vec::new();
    };
    let Some(host) = target_url.host_str() else {
        return Vec::new();
    };
    let mut origin = format!("{}://{host}", target_url.scheme());
    if let Some(port) = target_url.port() {
        origin.push_str(&format!(":{port}"));
    }
    origin.push('/');

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session_json.as_bytes());
    let encoded = format!("base64-{b64}");
    let secure = target_url.scheme() == "https";

    let build_cookie = |name: String, value: String| {
        let mut c = CookieParam::new(name, value);
        c.url = Some(origin.clone());
        c.path = Some("/".to_string());
        c.same_site = Some(CookieSameSite::Lax);
        c.secure = Some(secure);
        // @supabase/ssr browser clients read document.cookie in addition to SSR middleware.
        c.http_only = Some(false);
        c
    };

    if encoded.len() <= SUPABASE_SSR_MAX_CHUNK_SIZE {
        return vec![build_cookie(key, encoded)];
    }

    encoded
        .as_bytes()
        .chunks(SUPABASE_SSR_MAX_CHUNK_SIZE)
        .enumerate()
        .map(|(idx, chunk)| {
            let value = std::str::from_utf8(chunk)
                .expect("base64-encoded cookie chunk is ASCII")
                .to_string();
            build_cookie(format!("{key}.{idx}"), value)
        })
        .collect()
}

/// Build an init script that seeds `window.localStorage['sb-<host-prefix>-auth-token']`
/// for SPA `@supabase/supabase-js` clients on `target_url`'s origin (only when absent).
pub fn supabase_local_storage_init_script(
    project_url: &str,
    target_url: &Url,
    session_json: &str,
) -> Option<String> {
    if !target_url.origin().is_tuple() {
        return None;
    }
    let key = supabase_storage_key(project_url)?;
    let origin = target_url.origin().ascii_serialization();
    let origin_js = serde_json::to_string(&origin).ok()?;
    let key_js = serde_json::to_string(&key).ok()?;
    let val_js = serde_json::to_string(session_json).ok()?;
    Some(format!(
        r#"(() => {{
  try {{
    if (window.top !== window) return;
    if (location.origin !== {origin_js}) return;
    if (window.localStorage.getItem({key_js}) === null) {{
      window.localStorage.setItem({key_js}, {val_js});
    }}
  }} catch (_) {{}}
}})();"#
    ))
}

pub async fn supabase_sign_in(
    project_url: &str,
    anon_key: &str,
    email: &str,
    password: &str,
) -> Result<SignInResponse> {
    let url = format!(
        "{}/auth/v1/token?grant_type=password",
        project_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    let resp = client
        .post(&url)
        .header("apikey", anon_key)
        .header("Content-Type", "application/json")
        .json(&SupabaseSignInRequest { email, password })
        .send()
        .await
        .context("supabase sign-in request")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("supabase sign-in failed ({status}): {body}");
    }

    let raw = resp.text().await.context("read supabase response")?;
    parse_supabase_session_response(&raw)
}

pub async fn supabase_refresh(
    project_url: &str,
    anon_key: &str,
    refresh_token: &str,
) -> Result<SignInResponse> {
    let url = format!(
        "{}/auth/v1/token?grant_type=refresh_token",
        project_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    let resp = client
        .post(&url)
        .header("apikey", anon_key)
        .header("Content-Type", "application/json")
        .json(&SupabaseRefreshRequest { refresh_token })
        .send()
        .await
        .context("supabase refresh request")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("supabase refresh failed ({status}): {body}");
    }

    let raw = resp.text().await.context("read supabase response")?;
    parse_supabase_session_response(&raw)
}

pub async fn supabase_logout(project_url: &str, anon_key: &str, access_token: &str) -> Result<()> {
    let url = format!("{}/auth/v1/logout", project_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    let resp = client
        .post(&url)
        .header("apikey", anon_key)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .context("supabase logout request")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("supabase logout failed ({status}): {body}");
    }

    Ok(())
}

// ── Firebase ─────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FirebaseSignInRequest<'a> {
    email: &'a str,
    password: &'a str,
    return_secure_token: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FirebaseSignInResponse {
    id_token: String,
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: String,
}

#[derive(Serialize)]
struct FirebaseRefreshRequest<'a> {
    grant_type: &'a str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct FirebaseRefreshResponse {
    id_token: String,
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: String,
}

pub async fn firebase_sign_in(
    api_key: &str,
    email: &str,
    password: &str,
) -> Result<SignInResponse> {
    let url = format!(
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    let resp = client
        .post(&url)
        .json(&FirebaseSignInRequest {
            email,
            password,
            return_secure_token: true,
        })
        .send()
        .await
        .context("firebase sign-in request")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("firebase sign-in failed ({status}): {body}");
    }

    let body: FirebaseSignInResponse = resp.json().await.context("parse firebase response")?;
    Ok(SignInResponse {
        access_token: body.id_token,
        refresh_token: body.refresh_token,
        expires_in: body.expires_in.parse().unwrap_or(3600),
        raw_session_json: None,
    })
}

pub async fn firebase_refresh(api_key: &str, refresh_token: &str) -> Result<SignInResponse> {
    let url = format!("https://securetoken.googleapis.com/v1/token?key={api_key}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;

    let resp = client
        .post(&url)
        .form(&FirebaseRefreshRequest {
            grant_type: "refresh_token",
            refresh_token,
        })
        .send()
        .await
        .context("firebase refresh request")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("firebase refresh failed ({status}): {body}");
    }

    let body: FirebaseRefreshResponse = resp.json().await.context("parse firebase response")?;
    Ok(SignInResponse {
        access_token: body.id_token,
        refresh_token: body.refresh_token,
        expires_in: body.expires_in.parse().unwrap_or(3600),
        raw_session_json: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supabase_storage_key_handles_cloud_and_local_dev_urls() {
        assert_eq!(
            supabase_storage_key("https://xyzproj.supabase.co").as_deref(),
            Some("sb-xyzproj-auth-token")
        );
        assert_eq!(
            supabase_storage_key("http://127.0.0.1:54321").as_deref(),
            Some("sb-127-auth-token")
        );
        assert_eq!(
            supabase_storage_key("http://localhost:54321").as_deref(),
            Some("sb-localhost-auth-token")
        );
        assert_eq!(supabase_storage_key("not-a-url"), None);
    }

    #[test]
    fn supabase_ssr_cookies_encode_single_and_chunked_sessions() {
        let target = Url::parse("http://127.0.0.1:3000/dashboard").unwrap();
        let small = r#"{"access_token":"tok","refresh_token":"ref","token_type":"bearer"}"#;
        let cookies = supabase_ssr_cookies("http://127.0.0.1:54321", &target, small);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "sb-127-auth-token");
        assert!(cookies[0].value.starts_with("base64-"));
        assert_eq!(cookies[0].url.as_deref(), Some("http://127.0.0.1:3000/"));
        assert_eq!(cookies[0].http_only, Some(false));
        assert_eq!(cookies[0].secure, Some(false));
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cookies[0].value.strip_prefix("base64-").unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), small);

        // Large payload (> 3180 bytes encoded) chunks as .0, .1, ...
        let large = serde_json::json!({
            "access_token": "a".repeat(3000),
            "refresh_token": "r".repeat(200),
            "token_type": "bearer"
        })
        .to_string();
        let https_target = Url::parse("https://app.example.test/").unwrap();
        let chunked = supabase_ssr_cookies("https://proj.supabase.co", &https_target, &large);
        assert!(
            chunked.len() >= 2,
            "expected chunked cookies: {}",
            chunked.len()
        );
        assert_eq!(chunked[0].name, "sb-proj-auth-token.0");
        assert_eq!(chunked[1].name, "sb-proj-auth-token.1");
        assert_eq!(chunked[0].secure, Some(true));
        let combined: String = chunked.iter().map(|c| c.value.as_str()).collect();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(combined.strip_prefix("base64-").unwrap())
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), large);
    }

    #[test]
    fn supabase_local_storage_init_script_targets_origin_and_key() {
        let target = Url::parse("http://127.0.0.1:3000/app").unwrap();
        let script = supabase_local_storage_init_script(
            "https://demo.supabase.co",
            &target,
            r#"{"access_token":"jwt"}"#,
        )
        .unwrap();
        assert!(script.contains("http://127.0.0.1:3000"));
        assert!(script.contains("sb-demo-auth-token"));
        assert!(script.contains("window.localStorage.setItem"));
    }

    #[test]
    fn sign_in_response_debug_redacts_tokens() {
        let resp = SignInResponse {
            access_token: "secret-access".into(),
            refresh_token: Some("secret-refresh".into()),
            expires_in: 3600,
            raw_session_json: Some("secret-raw".into()),
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("secret-access"));
        assert!(!dbg.contains("secret-refresh"));
        assert!(!dbg.contains("secret-raw"));
    }
}
