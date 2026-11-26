//! Local auth persistence for repeated scans.
//!
//! Stores effective auth material keyed by config path (+ auth path name when
//! present) so follow-up scans (including MCP-triggered scans/rescans) can
//! reuse successful credentials when the TOML contains placeholders.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::config::{AuthConfig, BrokenAppConfig};

const CACHE_FILE_NAME: &str = "auth-cache.json";
const CACHE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AuthCacheFile {
    #[serde(default = "default_cache_version")]
    version: u32,
    #[serde(default)]
    entries: BTreeMap<String, AuthCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthCacheEntry {
    target_origin: String,
    auth: AuthConfig,
    updated_at: String,
}

fn default_cache_version() -> u32 {
    CACHE_VERSION
}

fn auth_cache_path() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    find_project_root(&cwd)
        .join(".brokenapp")
        .join(CACHE_FILE_NAME)
}

fn find_project_root(start: &Path) -> PathBuf {
    let mut cur = start;
    loop {
        if cur.join(".brokenapp").is_dir() {
            return cur.to_path_buf();
        }
        if cur.join(".git").exists() {
            return cur.to_path_buf();
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        cur = parent;
    }
    start.to_path_buf()
}

fn cache_key(config_path: &Path) -> String {
    config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn cache_key_for_config(config_path: &Path, cfg: &BrokenAppConfig) -> String {
    let base = cache_key(config_path);
    if let Some(auth_path) = cfg.scan.auth_path.as_deref() {
        let auth_path = auth_path.trim();
        if !auth_path.is_empty() {
            return format!("{base}#auth:{auth_path}");
        }
    }
    base
}

fn load_cache(path: &Path) -> AuthCacheFile {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(error = %err, file = %path.display(), "failed to read auth cache");
            }
            return AuthCacheFile::default();
        }
    };
    match serde_json::from_str::<AuthCacheFile>(&raw) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, file = %path.display(), "failed to parse auth cache");
            AuthCacheFile::default()
        }
    }
}

fn write_cache(path: &Path, cache: &AuthCacheFile) {
    let Some(parent) = path.parent() else {
        return;
    };
    if let Err(err) = std::fs::create_dir_all(parent) {
        tracing::warn!(
            error = %err,
            dir = %parent.display(),
            "failed to create auth cache directory"
        );
        return;
    }

    let json = match serde_json::to_string_pretty(cache) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "failed to serialize auth cache");
            return;
        }
    };

    if let Err(err) = std::fs::write(path, json) {
        tracing::warn!(error = %err, file = %path.display(), "failed to write auth cache");
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn target_origin(cfg: &BrokenAppConfig) -> String {
    let url = &cfg.target.url;
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    }
}

fn string_needs_hydration(v: &str) -> bool {
    let t = v.trim();
    if t.is_empty() {
        return true;
    }
    if t.contains("<set-via") {
        return true;
    }
    if t.starts_with('<') && t.ends_with('>') {
        return true;
    }
    t.eq_ignore_ascii_case("changeme")
}

fn auth_needs_hydration(auth: &AuthConfig) -> bool {
    match auth {
        AuthConfig::Form {
            username, password, ..
        } => string_needs_hydration(username) || string_needs_hydration(password),
        AuthConfig::Cookie { cookie } => string_needs_hydration(cookie),
        AuthConfig::BearerToken { token } => string_needs_hydration(token),
        AuthConfig::OAuth { token, .. } => string_needs_hydration(token),
        AuthConfig::Supabase {
            anon_key,
            email,
            password,
            ..
        } => {
            string_needs_hydration(anon_key)
                || string_needs_hydration(email)
                || string_needs_hydration(password)
        }
        AuthConfig::Firebase {
            api_key,
            email,
            password,
        } => {
            string_needs_hydration(api_key)
                || string_needs_hydration(email)
                || string_needs_hydration(password)
        }
        AuthConfig::Manual { .. } => false,
        AuthConfig::StorageState { path } => string_needs_hydration(path),
        AuthConfig::GoogleOAuth {
            google_email,
            google_password,
            ..
        } => string_needs_hydration(google_email) || string_needs_hydration(google_password),
    }
}

fn auth_contains_secret(auth: &AuthConfig) -> bool {
    // A saved session's config only names the file (which stays where it is).
    !matches!(
        auth,
        AuthConfig::Manual { .. } | AuthConfig::StorageState { .. }
    )
}

fn allow_plaintext_auth_cache() -> bool {
    match std::env::var("BROKENAPP_ALLOW_PLAINTEXT_AUTH_CACHE") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "y" | "on")
        }
        Err(_) => false,
    }
}

/// If TOML auth looks like placeholders, try hydrating from local cache.
pub fn hydrate_auth_for_config(config_path: &Path, cfg: &mut BrokenAppConfig) -> bool {
    let needs = cfg.auth.as_ref().map(auth_needs_hydration).unwrap_or(true);
    if !needs {
        return false;
    }
    if !allow_plaintext_auth_cache() {
        tracing::debug!(
            "auth cache hydration skipped (set BROKENAPP_ALLOW_PLAINTEXT_AUTH_CACHE=1 to enable)"
        );
        return false;
    }

    let cache_path = auth_cache_path();
    let cache = load_cache(&cache_path);
    let scoped_key = cache_key_for_config(config_path, cfg);
    let legacy_key = cache_key(config_path);
    let entry = cache
        .entries
        .get(&scoped_key)
        .or_else(|| cache.entries.get(&legacy_key));
    let Some(entry) = entry else {
        return false;
    };
    if entry.target_origin != target_origin(cfg) {
        return false;
    }

    cfg.auth = Some(entry.auth.clone());
    true
}

/// Persist effective auth for this config path, skipping obvious placeholders.
pub fn remember_effective_auth(config_path: &Path, cfg: &BrokenAppConfig) {
    let Some(auth) = cfg.auth.clone() else {
        return;
    };
    if auth_needs_hydration(&auth) {
        return;
    }
    if auth_contains_secret(&auth) && !allow_plaintext_auth_cache() {
        tracing::debug!(
            "skipping auth cache write for secret-bearing auth (BROKENAPP_ALLOW_PLAINTEXT_AUTH_CACHE=1 to opt in)"
        );
        return;
    }

    let cache_path = auth_cache_path();
    let mut cache = load_cache(&cache_path);
    let key = cache_key_for_config(config_path, cfg);
    cache.entries.insert(
        key,
        AuthCacheEntry {
            target_origin: target_origin(cfg),
            auth,
            updated_at: Utc::now().to_rfc3339(),
        },
    );
    cache.version = CACHE_VERSION;
    write_cache(&cache_path, &cache);
}
