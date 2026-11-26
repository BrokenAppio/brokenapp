use anyhow::{Context, Result};

use crate::config::AuthConfig;

/// Resolve `env:` / `${VAR}` placeholders in auth configuration.
///
/// Supported forms:
/// - `env:MY_VAR`
/// - `${MY_VAR}`
pub fn resolve_auth_secrets(auth: &AuthConfig) -> Result<AuthConfig> {
    Ok(match auth {
        AuthConfig::Form {
            login_url,
            username_selector,
            password_selector,
            submit_selector,
            username,
            password,
        } => AuthConfig::Form {
            login_url: login_url.clone(),
            username_selector: username_selector.clone(),
            password_selector: password_selector.clone(),
            submit_selector: submit_selector.clone(),
            username: resolve_secret(username, "auth.form.username")?,
            password: resolve_secret(password, "auth.form.password")?,
        },
        AuthConfig::Manual { login_url } => AuthConfig::Manual {
            login_url: login_url.clone(),
        },
        AuthConfig::StorageState { path } => AuthConfig::StorageState {
            path: resolve_secret(path, "auth.storage_state.path")?,
        },
        AuthConfig::Cookie { cookie } => AuthConfig::Cookie {
            cookie: resolve_secret(cookie, "auth.cookie")?,
        },
        AuthConfig::BearerToken { token } => AuthConfig::BearerToken {
            token: resolve_secret(token, "auth.bearer.token")?,
        },
        AuthConfig::OAuth {
            token,
            refresh_url,
            refresh_token,
        } => AuthConfig::OAuth {
            token: resolve_secret(token, "auth.oauth.token")?,
            refresh_url: refresh_url.clone(),
            refresh_token: refresh_token
                .as_ref()
                .map(|v| resolve_secret(v, "auth.oauth.refresh_token"))
                .transpose()?,
        },
        AuthConfig::Supabase {
            project_url,
            anon_key,
            email,
            password,
        } => AuthConfig::Supabase {
            project_url: project_url.clone(),
            anon_key: resolve_secret(anon_key, "auth.supabase.anon_key")?,
            email: resolve_secret(email, "auth.supabase.email")?,
            password: resolve_secret(password, "auth.supabase.password")?,
        },
        AuthConfig::Firebase {
            api_key,
            email,
            password,
        } => AuthConfig::Firebase {
            api_key: resolve_secret(api_key, "auth.firebase.api_key")?,
            email: resolve_secret(email, "auth.firebase.email")?,
            password: resolve_secret(password, "auth.firebase.password")?,
        },
        AuthConfig::GoogleOAuth {
            login_url,
            google_button_selector,
            google_email,
            google_password,
        } => AuthConfig::GoogleOAuth {
            login_url: login_url.clone(),
            google_button_selector: google_button_selector.clone(),
            google_email: resolve_secret(google_email, "auth.google_oauth.google_email")?,
            google_password: resolve_secret(google_password, "auth.google_oauth.google_password")?,
        },
    })
}

fn resolve_secret(raw: &str, field: &str) -> Result<String> {
    let trimmed = raw.trim();
    let var = trimmed
        .strip_prefix("env:")
        .map(str::trim)
        .or_else(|| parse_braced_env(trimmed));

    let Some(var) = var else {
        return Ok(raw.to_string());
    };
    if var.is_empty() {
        anyhow::bail!("{} references an empty env var name", field);
    }

    let value = std::env::var(var)
        .with_context(|| format!("{} requires env var {var:?}, but it is not set", field))?;
    if value.trim().is_empty() {
        anyhow::bail!("{field} resolved from env var {var:?}, but it is empty");
    }
    Ok(value)
}

fn parse_braced_env(value: &str) -> Option<&str> {
    if value.starts_with("${") && value.ends_with('}') && value.len() > 3 {
        Some(&value[2..value.len() - 1])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_secret_passthrough_when_not_placeholder() {
        let out = resolve_secret("plain", "field").expect("resolve");
        assert_eq!(out, "plain");
    }

    #[test]
    fn parse_braced_env_extracts_var_name() {
        assert_eq!(
            parse_braced_env("${BROKENAPP_SECRET}"),
            Some("BROKENAPP_SECRET")
        );
        assert_eq!(parse_braced_env("BROKENAPP_SECRET"), None);
    }
}
