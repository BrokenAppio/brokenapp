//! Write guard: a default scan must never let a state-changing request reach
//! a backend. The fixture (`tests/fixtures/write-guard/index.html`) has one
//! control per write shape: same-origin POST via `fetch(Request)`, PATCH,
//! DELETE, a cross-origin JSON POST, a GraphQL mutation, `sendBeacon`, a
//! `confirm()`-gated POST, a native form POST, a native form POST aimed at a
//! new window, and a typing-triggered autosave. Two in-process servers (app origin + API origin) log every
//! request they receive.
//!
//! Documented exception: the cross-origin JSON POST triggers a CORS
//! preflight (`OPTIONS`) that Chrome sends before the actual request is
//! paused, so the API origin sees that `OPTIONS` (read-only by spec) and
//! nothing else.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
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

#[derive(Debug, Clone)]
struct Hit {
    server: &'static str,
    method: String,
    path: String,
}

type HitLog = Arc<Mutex<Vec<Hit>>>;

/// Fixture pages served by the app origin, keyed by request path.
type Pages = Arc<BTreeMap<&'static str, String>>;

#[derive(Clone, Copy)]
enum Role {
    App,
    Api,
}

struct LoggingServer {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LoggingServer {
    fn start(role: Role, pages: Pages, log: HitLog) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind logging server");
        listener
            .set_nonblocking(true)
            .expect("set logging server nonblocking");
        let addr = listener.local_addr().expect("server addr").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let pages = Arc::clone(&pages);
                        let log = Arc::clone(&log);
                        thread::spawn(move || handle_connection(stream, role, &pages, &log));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for LoggingServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one HTTP request (head plus `Content-Length` body).
fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body_read = buf.len() - head_end;
    while body_read < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body_read += n;
    }
    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();
    Some((method, path))
}

fn handle_connection(mut stream: TcpStream, role: Role, pages: &Pages, log: &HitLog) {
    let Some((method, raw_path)) = read_request(&mut stream) else {
        return;
    };
    let path = raw_path.split('?').next().unwrap_or("/").to_string();
    log.lock().unwrap_or_else(|p| p.into_inner()).push(Hit {
        server: match role {
            Role::App => "app",
            Role::Api => "api",
        },
        method: method.clone(),
        path: path.clone(),
    });

    match role {
        Role::Api => {
            let cors = "Access-Control-Allow-Origin: *\r\n\
                        Access-Control-Allow-Headers: *\r\n\
                        Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n";
            if method == "OPTIONS" {
                respond(&mut stream, "204 No Content", cors, "text/plain", b"");
            } else {
                respond(&mut stream, "200 OK", cors, "application/json", b"{}");
            }
        }
        Role::App => match (method.as_str(), path.as_str()) {
            ("GET", page) if pages.contains_key(page) => respond(
                &mut stream,
                "200 OK",
                "",
                "text/html; charset=utf-8",
                pages[page].as_bytes(),
            ),
            ("POST", "/login") => respond(
                &mut stream,
                "303 See Other",
                "Location: /index.html\r\nSet-Cookie: session=fixture; Path=/; HttpOnly\r\n",
                "text/plain",
                b"",
            ),
            ("GET", "/api/items") => respond(&mut stream, "200 OK", "", "application/json", b"[]"),
            ("GET" | "HEAD", _) => {
                respond(&mut stream, "404 Not Found", "", "text/plain", b"missing")
            }
            // Any other method reaching the app server is a leaked write;
            // answer like a real backend would so nothing masks it.
            _ => respond(&mut stream, "200 OK", "", "application/json", b"{}"),
        },
    }
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    extra_headers: &str,
    content_type: &str,
    body: &[u8],
) {
    let header = format!(
        "HTTP/1.1 {status}\r\n{extra_headers}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>Sign in</title></head>
  <body>
    <form method="post" action="/login">
      <input id="username" name="username" type="text" />
      <input id="password" name="password" type="password" />
      <button id="login-submit" type="submit">Sign in</button>
    </form>
  </body>
</html>
"#;

fn chrome_available() -> bool {
    brokenapp::browser::BrowserManager::detect_chrome_executable().is_some()
}

struct Fixture {
    log: HitLog,
    app: LoggingServer,
    api: LoggingServer,
}

fn start_fixture() -> Fixture {
    let log: HitLog = Arc::new(Mutex::new(Vec::new()));
    let api = LoggingServer::start(Role::Api, Arc::new(BTreeMap::new()), Arc::clone(&log));
    let api_origin = format!("http://{}", api.addr);
    let page = |name: &str| {
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/write-guard")
                .join(name),
        )
        .unwrap_or_else(|err| panic!("read write-guard fixture {name}: {err}"))
        .replace("__API_ORIGIN__", &api_origin)
    };
    let index = page("index.html");
    let pages: Pages = Arc::new(BTreeMap::from([
        ("/", index.clone()),
        ("/index.html", index),
        ("/more.html", page("more.html")),
        ("/login.html", LOGIN_HTML.to_string()),
    ]));
    let app = LoggingServer::start(Role::App, pages, Arc::clone(&log));
    Fixture { log, app, api }
}

fn scan_config(app_addr: &str, output_dir: &Path, auth: &str) -> String {
    format!(
        r#"[target]
url = "http://{app_addr}/"
name = "write-guard-fixture"
headless = true
{auth}
[scan]
max_depth = 1
max_views = 3
max_duration_minutes = 2
max_stagnation_minutes = 1
interaction_timeout_ms = 1500
settle_timeout_ms = 600
max_concurrent_tabs = 1

[scan.limits]
max_interactions_per_view = 40

[output]
directory = "{}"
include_screenshots = false
include_network_log = true
bug_report_format = ["json"]
"#,
        output_dir.display()
    )
}

fn run_scan(config_path: &Path) {
    let output = Command::new(brokenapp_bin())
        .args([
            "scan",
            "--json",
            "--config",
            config_path.to_str().expect("config path utf8"),
        ])
        .output()
        .expect("run brokenapp scan");
    assert!(
        output.status.success(),
        "scan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_network_rows(output_dir: &Path) -> Vec<Value> {
    fs::read_to_string(output_dir.join("network.jsonl"))
        .expect("read network.jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("network.jsonl row is JSON"))
        .collect()
}

fn is_read_only(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

fn str_at<'a>(v: &'a Value, pointer: &str) -> &'a str {
    v.pointer(pointer).and_then(Value::as_str).unwrap_or("")
}

#[test]
fn default_scan_blocks_every_write_and_logs_it() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping write guard e2e: Chrome/Chromium not detected");
        return;
    }

    let fixture = start_fixture();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let output_dir = tmp.path().join("scan-output");
    let config_path = tmp.path().join("brokenapp.toml");
    fs::write(
        &config_path,
        scan_config(&fixture.app.addr, &output_dir, ""),
    )
    .expect("write scan config");

    run_scan(&config_path);

    // 1) Nothing state-changing reached either server.
    let hits = fixture
        .log
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let leaked: Vec<&Hit> = hits.iter().filter(|h| !is_read_only(&h.method)).collect();
    assert!(
        leaked.is_empty(),
        "write guard leaked requests to the fixture servers: {leaked:#?}\nall hits: {hits:#?}"
    );
    // The only OPTIONS allowed is the CORS preflight of the cross-origin write.
    for hit in hits.iter().filter(|h| h.method == "OPTIONS") {
        assert_eq!(
            (hit.server, hit.path.as_str()),
            ("api", "/rest/v1/cart"),
            "unexpected OPTIONS request: {hit:?}"
        );
    }
    // Reads still work.
    assert!(
        hits.iter()
            .any(|h| h.server == "app" && h.method == "GET" && h.path == "/api/items"),
        "read-only GET /api/items should reach the server: {hits:#?}"
    );

    // 2) Every guarded write is a network.jsonl row with write_guard,
    //    triggered_by, and an action id.
    let rows = read_network_rows(&output_dir);
    let guarded: Vec<&Value> = rows
        .iter()
        .filter(|r| r.get("write_guard").and_then(Value::as_str) == Some("blocked"))
        .collect();
    let api_origin = format!("http://{}", fixture.api.addr);
    let expected = [
        (
            "POST",
            "/api/orders",
            "#buy",
            "POST /api/orders".to_string(),
        ),
        (
            "PATCH",
            "/api/items/42",
            "#rename",
            "PATCH /api/items/:id".to_string(),
        ),
        (
            "DELETE",
            "/api/items/42",
            "#clear-item",
            "DELETE /api/items/:id".to_string(),
        ),
        (
            "POST",
            "/rest/v1/cart",
            "#cart",
            format!("POST {api_origin}/rest/v1/cart"),
        ),
        (
            "POST",
            "/graphql",
            "#refund",
            "POST /graphql#MUTATION RefundOrder".to_string(),
        ),
        (
            "POST",
            "/api/beacon",
            "#upgrade",
            "POST /api/beacon".to_string(),
        ),
        (
            "POST",
            "/api/mark-read",
            "#mark-read",
            "POST /api/mark-read".to_string(),
        ),
        (
            "POST",
            "/api/subscribe",
            "#quick-join",
            "POST /api/subscribe".to_string(),
        ),
        (
            "POST",
            "/api/receipt",
            "#open-receipt",
            "POST /api/receipt".to_string(),
        ),
        (
            "POST",
            "/api/autosave",
            "#notes",
            "POST /api/autosave".to_string(),
        ),
    ];
    for (method, path, selector, endpoint_key) in &expected {
        let row = guarded.iter().find(|r| {
            str_at(r, "/request/method") == *method && str_at(r, "/request/url").ends_with(path)
        });
        let Some(row) = row else {
            panic!("no write_guard=blocked row for {method} {path}\nguarded rows: {guarded:#?}");
        };
        assert_eq!(str_at(row, "/triggered_by/selector"), *selector, "{row:#}");
        assert!(
            !str_at(row, "/trace/action_id").is_empty(),
            "guarded row should carry the action id: {row:#}"
        );
        assert_eq!(str_at(row, "/endpoint_key"), endpoint_key, "{row:#}");
        assert!(
            row.get("response").is_none() && row.get("failure").is_none(),
            "guarded rows carry no response/failure: {row:#}"
        );
    }

    // fetch(Request) keeps the Request's own headers alongside the probe's.
    let order = guarded
        .iter()
        .find(|r| str_at(r, "/request/url").ends_with("/api/orders"))
        .expect("orders row");
    let headers = order
        .pointer("/request/headers")
        .and_then(Value::as_object)
        .expect("orders headers");
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    assert_eq!(header("content-type"), "application/json", "{order:#}");
    assert_eq!(header("authorization"), "Bearer <redacted>", "{order:#}");
    assert!(header("traceparent").starts_with("00-"), "{order:#}");

    // 3) Guarded writes produce no network-failure findings, and controls
    //    whose only effect is a beacon / native form post are not dead.
    let bugs: Value = serde_json::from_str(
        &fs::read_to_string(output_dir.join("bugs.json")).expect("read bugs.json"),
    )
    .expect("parse bugs.json");
    let empty = Vec::new();
    for bug in bugs
        .pointer("/items")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
    {
        let kind = str_at(bug, "/category/kind");
        assert!(
            !matches!(
                kind,
                "network_request_failure" | "api_error" | "server_error"
            ),
            "guarded writes must not become findings: {bug:#}"
        );
        if kind == "dead_button" {
            let selector = str_at(bug, "/category/selector");
            assert!(
                !matches!(selector, "#upgrade" | "#quick-join"),
                "beacon/form-post controls must count as network activity: {bug:#}"
            );
        }
    }
}

#[test]
fn configured_form_login_passes_the_guard_and_nothing_else_does() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping write guard auth e2e: Chrome/Chromium not detected");
        return;
    }

    let fixture = start_fixture();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let output_dir = tmp.path().join("scan-output");
    let config_path = tmp.path().join("brokenapp.toml");
    let auth = r##"
[auth]
type = "form"
login_url = "/login.html"
username = "fixture-user"
password = "fixture-password"
username_selector = "#username"
password_selector = "#password"
submit_selector = "#login-submit"
"##;
    fs::write(
        &config_path,
        scan_config(&fixture.app.addr, &output_dir, auth),
    )
    .expect("write scan config");

    run_scan(&config_path);

    let hits = fixture
        .log
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let writes: Vec<&Hit> = hits.iter().filter(|h| !is_read_only(&h.method)).collect();
    assert_eq!(
        writes
            .iter()
            .map(|h| (h.server, h.method.as_str(), h.path.as_str()))
            .collect::<Vec<_>>(),
        vec![("app", "POST", "/login")],
        "only the configured login may write\nall hits: {hits:#?}"
    );

    let rows = read_network_rows(&output_dir);
    // The server log proves the one authorized login passed. Auth-page
    // traffic is deliberately omitted from artifacts because custom field
    // names and token-bearing responses cannot be safely redacted by schema.
    assert!(
        !rows.iter().any(|r| {
            str_at(r, "/request/method") == "POST" && str_at(r, "/request/url").ends_with("/login")
        }),
        "auth traffic must not be recorded in network.jsonl"
    );
    let recorded = serde_json::to_string(&rows).expect("serialize network rows");
    for secret in ["fixture-user", "fixture-password"] {
        assert!(
            !recorded.contains(secret),
            "auth secret entered network.jsonl"
        );
    }
    assert!(
        rows.iter().any(|r| {
            r.get("write_guard").and_then(Value::as_str) == Some("blocked")
                && str_at(r, "/request/url").ends_with("/api/orders")
        }),
        "writes after login must still be blocked"
    );
}
