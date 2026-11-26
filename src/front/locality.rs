//! Target URL safety and reachability for the front-door commands.
//!
//! `map` only scans local development servers unless a project explicitly
//! opts into remote targets (`scan.allow_remote`), and checks the URL is
//! answering before it launches a browser.

use std::error::Error as StdError;
use std::io::ErrorKind;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use url::{Host, Url};

/// Whether `host` is a local development host: `localhost`, a loopback IP
/// (`127.0.0.0/8`, `::1`), or a name ending in `.localhost` / `.test`.
pub fn is_local_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost") || name.ends_with(".test")
        }
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Whether the URL points at a local development host.
pub fn is_local_url(url: &Url) -> bool {
    url.host().is_some_and(|h| is_local_host(&h))
}

/// Parse a project URL and enforce the locality rule.
pub fn parse_target_url(raw: &str, allow_remote: bool) -> Result<Url> {
    let url = Url::parse(raw.trim()).with_context(|| format!("invalid project url {raw:?}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("project url must be http(s), got {raw:?}");
    }
    if url.host().is_none() {
        bail!("project url has no host: {raw:?}");
    }
    if !allow_remote && !is_local_url(&url) {
        bail!(
            "refusing to scan {url}: not a local development host (localhost, 127.0.0.1, ::1, *.localhost, *.test). \
             Set `allow_remote = true` under [scan] in .brokenapp/config.toml only for targets you own."
        );
    }
    Ok(url)
}

/// Result of one reachability probe.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Probe {
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub const PERMISSION_DENIED_MSG: &str = "connection blocked by OS/sandbox (permission denied)";

impl Probe {
    /// True when the probe could not even attempt TCP connect because the OS,
    /// firewall, or sandbox blocked it (`EPERM` / `EACCES`).
    pub fn is_permission_denied(&self) -> bool {
        self.error.as_deref() == Some(PERMISSION_DENIED_MSG)
    }
}

fn probe_client(url: &Url, timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        // A redirect already proves the server is up; never follow it to
        // another (possibly remote) host.
        .redirect(reqwest::redirect::Policy::none())
        // Local dev servers often use self-signed certificates; never relax
        // TLS checks for anything else.
        .danger_accept_invalid_certs(is_local_url(url))
        .no_proxy()
        .build()
        .context("build http client")
}

/// GET the URL once. Any HTTP response (even 404/500) counts as reachable:
/// the server is up, which is all the scan needs.
pub async fn probe(url: &Url, timeout: Duration) -> Probe {
    let client = match probe_client(url, timeout) {
        Ok(c) => c,
        Err(err) => {
            return Probe {
                reachable: false,
                status: None,
                error: Some(format!("{err:#}")),
            };
        }
    };
    match client.get(url.clone()).send().await {
        Ok(resp) => Probe {
            reachable: true,
            status: Some(resp.status().as_u16()),
            error: None,
        },
        Err(err) => Probe {
            reachable: false,
            status: None,
            error: Some(short_reqwest_error(&err)),
        },
    }
}

/// Whether something accepts TCP connections on the URL's host and port
/// (a dev server that is up but still compiling its first response).
pub async fn port_open(url: &Url) -> bool {
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(addrs) = tokio::net::lookup_host((host, port)).await else {
        return false;
    };
    for addr in addrs {
        let connect = tokio::net::TcpStream::connect(addr);
        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(2), connect).await {
            return true;
        }
    }
    false
}

/// Probe until the URL answers or `within` passes.
pub async fn wait_reachable(url: &Url, within: Duration) -> Probe {
    let deadline = std::time::Instant::now() + within;
    loop {
        let p = probe(url, Duration::from_secs(10)).await;
        if p.reachable || std::time::Instant::now() >= deadline {
            return p;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn find_io_error<'a>(err: &'a (dyn StdError + 'static)) -> Option<&'a std::io::Error> {
    let mut fallback = None;
    let mut cur: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if io.kind() != ErrorKind::Other {
                return Some(io);
            }
            fallback = Some(io);
        }
        cur = e.source();
    }
    fallback
}

fn root_cause<'a>(err: &'a (dyn StdError + 'static)) -> &'a (dyn StdError + 'static) {
    let mut cur = err;
    while let Some(next) = cur.source() {
        cur = next;
    }
    cur
}

pub(crate) fn classify_io_error(err: &std::io::Error) -> String {
    match err.kind() {
        ErrorKind::ConnectionRefused => "connection refused".to_string(),
        ErrorKind::PermissionDenied => PERMISSION_DENIED_MSG.to_string(),
        ErrorKind::TimedOut => "timed out".to_string(),
        ErrorKind::ConnectionReset => "connection reset".to_string(),
        ErrorKind::ConnectionAborted => "connection aborted".to_string(),
        ErrorKind::AddrNotAvailable => "address not available".to_string(),
        ErrorKind::UnexpectedEof => "connection closed unexpectedly".to_string(),
        _ => {
            let msg = err.to_string();
            if msg.is_empty() {
                format!("{:?}", err.kind())
            } else {
                msg
            }
        }
    }
}

fn classify_transport_error(
    err: &(dyn StdError + 'static),
    is_timeout: bool,
    is_connect: bool,
) -> String {
    if is_timeout {
        return "timed out".to_string();
    }
    if let Some(io) = find_io_error(err) {
        return classify_io_error(io);
    }
    let root = root_cause(err).to_string();
    if is_connect {
        let lower = root.to_ascii_lowercase();
        if lower.contains("permission denied") || lower.contains("operation not permitted") {
            return PERMISSION_DENIED_MSG.to_string();
        }
        if lower.contains("connection refused") {
            return "connection refused".to_string();
        }
        if lower.contains("timed out") || lower.contains("timeout") {
            return "timed out".to_string();
        }
    }
    if root.is_empty() {
        err.to_string()
    } else {
        root
    }
}

fn short_reqwest_error(err: &reqwest::Error) -> String {
    classify_transport_error(err, err.is_timeout(), err.is_connect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(raw: &str) -> bool {
        is_local_url(&Url::parse(raw).unwrap())
    }

    #[test]
    fn local_hosts_are_recognized() {
        assert!(local("http://localhost:3000/"));
        assert!(local("http://LOCALHOST:3000/"));
        assert!(local("http://127.0.0.1:5173/"));
        assert!(local("http://127.1.2.3/"));
        assert!(local("http://[::1]:8787/"));
        assert!(local("http://app.localhost:3000/"));
        assert!(local("https://shop.test/"));
        assert!(local("http://localhost./"));
    }

    #[test]
    fn remote_hosts_are_not_local() {
        assert!(!local("https://example.com/"));
        assert!(!local("http://10.0.0.5:3000/"));
        assert!(!local("http://192.168.1.10/"));
        assert!(!local("http://0.0.0.0:3000/"));
        assert!(!local("http://localhost.example.com/"));
        assert!(!local("http://mytest/"));
        assert!(!local("https://staging.app.dev/"));
    }

    #[test]
    fn parse_target_url_enforces_locality() {
        assert!(parse_target_url("http://localhost:3000", false).is_ok());
        let err = parse_target_url("https://example.com", false).unwrap_err();
        assert!(format!("{err:#}").contains("not a local development host"));
        assert!(parse_target_url("https://example.com", true).is_ok());
        assert!(parse_target_url("ftp://localhost/", true).is_err());
        assert!(parse_target_url("not a url", false).is_err());
    }

    #[tokio::test]
    async fn probe_reports_unreachable_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let p = probe(&url, Duration::from_secs(5)).await;
        assert!(!p.reachable);
        assert!(
            matches!(
                p.error.as_deref(),
                Some("connection refused") | Some("timed out") | Some(PERMISSION_DENIED_MSG)
            ),
            "unexpected unreachable probe error: {:?}",
            p.error
        );
        assert!(!port_open(&url).await);
    }

    #[tokio::test]
    async fn listening_but_silent_port_is_open_not_reachable() {
        // Accepts connections but never answers HTTP (a server still compiling).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let mut conns = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                conns.push(sock);
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        assert!(port_open(&url).await);
        let p = probe(&url, Duration::from_millis(500)).await;
        assert!(!p.reachable);
        hold.abort();
    }

    #[tokio::test]
    async fn redirects_count_as_reachable_and_are_not_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let p = probe(&url, Duration::from_secs(5)).await;
        assert!(p.reachable);
        assert_eq!(p.status, Some(302));
        server.abort();
    }

    #[derive(Debug)]
    struct WrappedErr {
        msg: &'static str,
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    }

    impl std::fmt::Display for WrappedErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.msg)
        }
    }

    impl StdError for WrappedErr {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.source
                .as_deref()
                .map(|e| e as &(dyn StdError + 'static))
        }
    }

    #[test]
    fn transport_errors_distinguish_refused_permission_timeout_and_other() {
        let refused = WrappedErr {
            msg: "client error (Connect)",
            source: Some(Box::new(std::io::Error::new(
                ErrorKind::ConnectionRefused,
                "Connection refused (os error 61)",
            ))),
        };
        assert_eq!(
            classify_transport_error(&refused, false, true),
            "connection refused"
        );

        let eperm = WrappedErr {
            msg: "client error (Connect)",
            source: Some(Box::new(std::io::Error::new(
                ErrorKind::PermissionDenied,
                "Operation not permitted (os error 1)",
            ))),
        };
        assert_eq!(
            classify_transport_error(&eperm, false, true),
            PERMISSION_DENIED_MSG
        );

        // Nested through multiple wrapper layers (like reqwest -> hyper -> ConnectError -> io::Error).
        let deep_eperm = WrappedErr {
            msg: "error sending request",
            source: Some(Box::new(WrappedErr {
                msg: "tcp connect error",
                source: Some(Box::new(std::io::Error::from_raw_os_error(1))),
            })),
        };
        if std::io::Error::from_raw_os_error(1).kind() == ErrorKind::PermissionDenied {
            assert_eq!(
                classify_transport_error(&deep_eperm, false, true),
                PERMISSION_DENIED_MSG
            );
        }

        let timed_out_io = std::io::Error::new(ErrorKind::TimedOut, "timed out");
        assert_eq!(
            classify_transport_error(&timed_out_io, false, true),
            "timed out"
        );
        assert_eq!(
            classify_transport_error(&refused, true, true),
            "timed out",
            "explicit reqwest timeout takes precedence"
        );

        let reset = std::io::Error::new(ErrorKind::ConnectionReset, "reset by peer");
        assert_eq!(
            classify_transport_error(&reset, false, true),
            "connection reset"
        );

        // Non-IO transport errors (e.g. DNS failure) report root cause instead of "connection refused".
        let dns = WrappedErr {
            msg: "client error (Connect)",
            source: Some(Box::new(WrappedErr {
                msg: "dns error: failed to lookup address information",
                source: None,
            })),
        };
        assert_eq!(
            classify_transport_error(&dns, false, true),
            "dns error: failed to lookup address information"
        );

        let probe = Probe {
            reachable: false,
            status: None,
            error: Some(PERMISSION_DENIED_MSG.to_string()),
        };
        assert!(probe.is_permission_denied());
    }
}
