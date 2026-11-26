use brokenapp::BrokenAppConfig;
use brokenapp::config::AuthConfig;

#[test]
fn config_accepts_none_auth_type_as_no_auth() {
    let cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[auth]
type = "none"
"#,
    )
    .expect("parse none auth config");

    assert!(
        cfg.auth.is_none(),
        "auth type none should deserialize as no auth"
    );
}

#[test]
fn config_accepts_bearer_type_aliases() {
    let cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[auth]
type = "bearer"
token = "ABC123"
"#,
    )
    .expect("parse bearer config");

    match cfg.auth.expect("auth") {
        AuthConfig::BearerToken { token } => assert_eq!(token, "ABC123"),
        other => panic!("expected BearerToken, got {other:?}"),
    }

    let cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[auth]
type = "bearer_token"
token = "def456"
"#,
    )
    .expect("parse bearer_token config");

    assert!(matches!(cfg.auth, Some(AuthConfig::BearerToken { .. })));
}

#[test]
fn config_accepts_oauth_type_aliases() {
    let cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[auth]
type = "oauth"
token = "t0k"
"#,
    )
    .expect("parse oauth config");
    assert!(matches!(cfg.auth, Some(AuthConfig::OAuth { .. })));

    let cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[auth]
type = "o_auth"
token = "t0k"
"#,
    )
    .expect("parse o_auth config");
    assert!(matches!(cfg.auth, Some(AuthConfig::OAuth { .. })));
}

#[test]
fn config_accepts_supabase_field_aliases() {
    let cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[auth]
type = "supabase"
supabase_url = "https://xyz.supabase.co"
supabase_anon_key = "anon"
username = "user@example.com"
password = "pw"
"#,
    )
    .expect("parse supabase alias config");

    match cfg.auth.expect("auth") {
        AuthConfig::Supabase {
            project_url,
            anon_key,
            email,
            password,
        } => {
            assert_eq!(project_url, "https://xyz.supabase.co");
            assert_eq!(anon_key, "anon");
            assert_eq!(email, "user@example.com");
            assert_eq!(password, "pw");
        }
        other => panic!("expected Supabase, got {other:?}"),
    }
}

#[test]
fn config_accepts_firebase_field_aliases() {
    let cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[auth]
type = "firebase"
firebase_api_key = "k"
username = "user@example.com"
password = "pw"
"#,
    )
    .expect("parse firebase alias config");

    match cfg.auth.expect("auth") {
        AuthConfig::Firebase {
            api_key,
            email,
            password,
        } => {
            assert_eq!(api_key, "k");
            assert_eq!(email, "user@example.com");
            assert_eq!(password, "pw");
        }
        other => panic!("expected Firebase, got {other:?}"),
    }
}

#[test]
fn config_accepts_auth_profile_aliases() {
    let mut cfg: BrokenAppConfig = toml::from_str(
        r#"
[target]
url = "https://example.com"

[scan]
auth_profile = "staff"

[[auth_profiles]]
name = "staff"
type = "cookie"
cookie = "session=staff"
"#,
    )
    .expect("parse auth profile alias config");

    cfg.resolve_auth_path().expect("resolve auth profile");

    assert_eq!(cfg.scan.auth_path.as_deref(), Some("staff"));
    assert_eq!(cfg.auth_paths.len(), 1);
    match cfg.auth.expect("auth") {
        AuthConfig::Cookie { cookie } => assert_eq!(cookie, "session=staff"),
        other => panic!("expected Cookie auth, got {other:?}"),
    }
}
