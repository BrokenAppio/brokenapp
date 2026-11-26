use url::Url;

pub fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.port_or_known_default() == b.port_or_known_default()
        && equivalent_hosts(a.host_str(), b.host_str())
}

pub fn equivalent_hosts(a: Option<&str>, b: Option<&str>) -> bool {
    let Some(a) = a else {
        return b.is_none();
    };
    let Some(b) = b else {
        return false;
    };
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    is_localhost_alias(a) && is_localhost_alias(b)
}

pub fn is_localhost_alias(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "0.0.0.0" | "::1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_aliases_are_equivalent_hosts() {
        assert!(equivalent_hosts(Some("localhost"), Some("127.0.0.1")));
        assert!(equivalent_hosts(Some("localhost"), Some("0.0.0.0")));
        assert!(equivalent_hosts(Some("localhost"), Some("::1")));
    }

    #[test]
    fn non_local_hosts_are_strict() {
        assert!(equivalent_hosts(
            Some("APP.EXAMPLE.COM"),
            Some("app.example.com")
        ));
        assert!(!equivalent_hosts(
            Some("app.example.com"),
            Some("api.example.com")
        ));
        assert!(!equivalent_hosts(Some("localhost"), Some("example.com")));
    }
}
