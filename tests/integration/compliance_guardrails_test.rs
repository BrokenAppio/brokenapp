//! End-to-end headless Chromium tests for remote/program compliance guardrails:
//! 1. Scoped `extra_headers` (stamped only on in-scope / `allowed_hosts` requests,
//!    never leaked to out-of-scope third-party hosts).
//! 2. Custom `user_agent` applied via CDP emulation.
//! 3. Fail-closed `allowed_hosts` blocking out-of-scope XHR/Fetch and WebSocket
//!    connections while permitting passive CDN static assets to load.
//! 4. Hard-abort circuit breaker (`abort_on_rate_limits` -> `stop_reason = "rate_limited"`).

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::Value;

fn brokenapp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brokenapp")
}

fn chrome_available() -> bool {
    brokenapp::browser::BrowserManager::detect_chrome_executable().is_some()
}

#[derive(Debug, Clone)]
struct RecordedReq {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
}

type HandlerFn = dyn Fn(&str, &str, &BTreeMap<String, String>) -> (u16, &'static str, String)
    + Send
    + Sync
    + 'static;

struct MiniHttpServer {
    port: u16,
    requests: Arc<Mutex<Vec<RecordedReq>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MiniHttpServer {
    fn start(handler: Arc<HandlerFn>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener.set_nonblocking(true).expect("set nonblocking");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let reqs_ref = Arc::clone(&requests);

        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let reqs = Arc::clone(&reqs_ref);
                        let handler = Arc::clone(&handler);
                        thread::spawn(move || serve_once(stream, &reqs, &handler));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn snapshot(&self) -> Vec<RecordedReq> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for MiniHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve_once(
    mut stream: TcpStream,
    requests: &Arc<Mutex<Vec<RecordedReq>>>,
    handler: &Arc<HandlerFn>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            }
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    requests.lock().unwrap().push(RecordedReq {
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
    });

    let (status, content_type, body) = handler(&method, &path, &headers);
    let reason = match status {
        200 => "OK",
        429 => "Too Many Requests",
        404 => "Not Found",
        _ => "OK",
    };
    let extra = if status == 429 {
        "Retry-After: 1\r\n"
    } else {
        ""
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         {extra}\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

#[test]
fn compliance_headers_ua_and_allowed_hosts_enforced_in_chromium() {
    let _guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!(
            "skipping compliance_headers_ua_and_allowed_hosts_enforced_in_chromium: no Chrome"
        );
        return;
    }

    // Secondary server reached via hostname `localhost` (distinct from `127.0.0.1`
    // in `allowed_hosts`).
    let external = MiniHttpServer::start(Arc::new(|_method, path, _headers| {
        if path == "/cdn.js" {
            (
                200,
                "application/javascript",
                "window.__cdnLoaded = true;".to_string(),
            )
        } else {
            (200, "application/json", r#"{"leaked":true}"#.to_string())
        }
    }));
    let ext_port = external.port;

    let primary = MiniHttpServer::start(Arc::new(move |_method, path, _headers| {
        if path == "/api/profile" {
            (200, "application/json", r#"{"user":"alice"}"#.to_string())
        } else {
            let html = format!(
                r#"<!doctype html>
<html>
<head>
  <title>Compliance Test</title>
  <script src="http://localhost:{ext_port}/cdn.js"></script>
</head>
<body>
  <h1>Scope Guard Test</h1>
  <button id="check-btn" onclick="runChecks()">Run checks</button>
  <div id="status">ready</div>
  <script>
    async function runChecks() {{
      await fetch('/api/profile');
      try {{ await fetch('http://localhost:{ext_port}/api/leak'); }} catch (_) {{}}
      try {{ new WebSocket('ws://localhost:{ext_port}/ws'); }} catch (e) {{
        window.__wsBlocked = String(e && e.message || e);
      }}
      document.getElementById('status').textContent = 'done';
    }}
    window.addEventListener('load', () => {{ runChecks(); }});
  </script>
</body>
</html>"#
            );
            (200, "text/html; charset=utf-8", html)
        }
    }));

    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("scan-out");
    let cfg_path = tmp.path().join("scan.toml");
    let cfg = format!(
        r#"[target]
url = "http://127.0.0.1:{port}/"
name = "compliance-test"
headless = true

[scan]
max_views = 2
max_duration_minutes = 1
max_concurrent_tabs = 1
settle_timeout_ms = 500
allowed_hosts = ["127.0.0.1"]
user_agent = "BrokenAppComplianceTest/1.0"

[scan.extra_headers]
X-QA-Runner = "staging-ci-42"

[scan.write_guard]
mode = "block"

[output]
directory = "{out}"
include_network_log = true
include_screenshots = false
"#,
        port = primary.port,
        out = out_dir.display()
    );
    fs::write(&cfg_path, cfg).expect("write scan.toml");

    let status = Command::new(brokenapp_bin())
        .args(["scan", "--config", cfg_path.to_str().unwrap()])
        .status()
        .expect("run brokenapp scan");
    assert!(status.success(), "scan failed with status {status}");

    let primary_reqs = primary.snapshot();
    assert!(
        primary_reqs.iter().any(|r| r.path == "/"),
        "primary server never received document GET: {primary_reqs:?}"
    );
    assert!(
        primary_reqs.iter().any(|r| r.path == "/api/profile"),
        "primary server never received in-scope /api/profile: {primary_reqs:?}"
    );
    for req in primary_reqs
        .iter()
        .filter(|r| r.path == "/" || r.path == "/api/profile")
    {
        assert_eq!(req.method, "GET", "unexpected method on {req:?}");
        assert_eq!(
            req.headers.get("x-qa-runner").map(String::as_str),
            Some("staging-ci-42"),
            "missing scoped identifying header on in-scope request: {req:?}"
        );
        assert_eq!(
            req.headers.get("user-agent").map(String::as_str),
            Some("BrokenAppComplianceTest/1.0"),
            "missing custom user_agent on in-scope request: {req:?}"
        );
    }

    let external_reqs = external.snapshot();
    assert!(
        !external_reqs.iter().any(|r| r.path == "/api/leak"),
        "out-of-scope fetch to localhost leaked past allowed_hosts: {external_reqs:?}"
    );
    assert!(
        !external_reqs.iter().any(|r| r.path == "/ws"),
        "out-of-scope WebSocket to localhost leaked past allowed_hosts: {external_reqs:?}"
    );
    assert!(
        external_reqs
            .iter()
            .all(|r| !r.headers.contains_key("x-qa-runner")),
        "identifying extra_header leaked to out-of-scope host: {external_reqs:?}"
    );
}

#[test]
fn hard_abort_on_repeated_429_stops_with_rate_limited() {
    let _guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping hard_abort_on_repeated_429_stops_with_rate_limited: no Chrome");
        return;
    }

    let server = MiniHttpServer::start(Arc::new(|_method, path, _headers| {
        if path.starts_with("/api/throttled") {
            (
                429,
                "application/json",
                r#"{"error":"rate_limited"}"#.to_string(),
            )
        } else {
            let html = r#"<!doctype html>
<html>
<head><title>Rate Limit Test</title></head>
<body>
  <h1>Throttled App</h1>
  <a href="/page-2">Page 2</a>
  <a href="/page-3">Page 3</a>
  <script>
    Promise.all([
      fetch('/api/throttled/1'),
      fetch('/api/throttled/2'),
      fetch('/api/throttled/3'),
      fetch('/api/throttled/4'),
    ]).catch(() => {});
  </script>
</body>
</html>"#
                .to_string();
            (200, "text/html; charset=utf-8", html)
        }
    }));

    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("scan-429");
    let cfg_path = tmp.path().join("scan-429.toml");
    let cfg = format!(
        r#"[target]
url = "http://127.0.0.1:{port}/"
name = "rate-limit-test"
headless = true

[scan]
max_views = 10
max_duration_minutes = 1
max_concurrent_tabs = 1
settle_timeout_ms = 500
abort_on_rate_limits = 3

[scan.write_guard]
mode = "block"

[output]
directory = "{out}"
include_network_log = true
include_screenshots = false
"#,
        port = server.port,
        out = out_dir.display()
    );
    fs::write(&cfg_path, cfg).expect("write scan-429.toml");

    let status = Command::new(brokenapp_bin())
        .args(["scan", "--config", cfg_path.to_str().unwrap()])
        .status()
        .expect("run brokenapp scan");
    assert!(status.success(), "scan exited with {status}");

    let run_json = fs::read_to_string(out_dir.join("scan-run.json")).expect("read scan-run.json");
    let parsed: Value = serde_json::from_str(&run_json).expect("parse scan-run.json");
    assert_eq!(
        parsed["stop_reason"].as_str(),
        Some("rate_limited"),
        "expected rate_limited stop_reason, got {parsed}"
    );
}
