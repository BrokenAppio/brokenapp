//! Crawler outcome coverage on a small SPA fixture (`tests/fixtures/ui-map-spa`):
//! hash routes plus a pushState route, a hamburger-revealed sidenav, shell
//! (header) controls, a dead button, a throwing handler, a modal, a fetching
//! button and repeated cards. Asserts the per-control `interactions.jsonl`
//! log, revealed-link harvesting, and that same-document restores do not stall.

use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

fn brokenapp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brokenapp")
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-spa")
}

/// Minimal SPA server: the app shell for `/`, `/index.html` and the pushState
/// route `/reports`, JSON for `GET /api/data`, and `GET /slow` that answers
/// only after a few seconds. Records every request line.
struct SpaServer {
    addr: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

/// Serves one request: `(stream, fixture root, method, path)`.
type Router = fn(&mut TcpStream, &Path, &str, &str);

impl SpaServer {
    fn start(root: PathBuf) -> Self {
        Self::start_with(root, spa_routes)
    }

    fn start_with(root: PathBuf, router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind SPA fixture server");
        listener
            .set_nonblocking(true)
            .expect("set fixture server nonblocking");
        let addr = listener.local_addr().expect("fixture addr").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stop_thread, requests_thread) = (Arc::clone(&stop), Arc::clone(&requests));
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let root = root.clone();
                        let requests = Arc::clone(&requests_thread);
                        thread::spawn(move || handle_connection(stream, &root, &requests, router));
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
            requests,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl Drop for SpaServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(&self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    root: &Path,
    requests: &Mutex<Vec<String>>,
    router: Router,
) {
    let _ = stream.set_nonblocking(false);
    let mut buf = [0_u8; 8192];
    let Ok(read) = stream.read(&mut buf) else {
        return;
    };
    if read == 0 {
        return;
    }
    let req = String::from_utf8_lossy(&buf[..read]);
    let line = req.lines().next().unwrap_or_default().to_string();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let raw_path = parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();
    requests
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(format!("{method} {path}"));
    router(&mut stream, root, &method, &path);
}

fn spa_routes(stream: &mut TcpStream, root: &Path, method: &str, path: &str) {
    match (method, path) {
        ("GET", "/" | "/index.html" | "/reports") => match fs::read(root.join("index.html")) {
            Ok(body) => respond(stream, "200 OK", "text/html; charset=utf-8", &body),
            Err(_) => respond(stream, "404 Not Found", "text/plain", b"missing"),
        },
        ("GET", "/api/data") => respond(
            stream,
            "200 OK",
            "application/json",
            br#"{"items":["alpha","beta"]}"#,
        ),
        ("GET", "/slow") => {
            thread::sleep(Duration::from_secs(6));
            respond(stream, "200 OK", "text/html", b"<p>slow</p>");
        }
        _ => respond(stream, "404 Not Found", "text/plain", b"missing"),
    }
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn chrome_available() -> bool {
    brokenapp::browser::BrowserManager::detect_chrome_executable().is_some()
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("interactions.jsonl row is JSON"))
        .collect()
}

fn str_field<'a>(row: &'a Value, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn rows_labelled<'a>(rows: &'a [Value], label: &str) -> Vec<&'a Value> {
    rows.iter()
        .filter(|r| str_field(r, "label") == label)
        .collect()
}

fn attempted<'a>(rows: &'a [Value], label: &str) -> &'a Value {
    rows_labelled(rows, label)
        .into_iter()
        .find(|r| str_field(r, "outcome") != "skipped")
        .unwrap_or_else(|| panic!("no attempted interaction for {label:?}:\n{rows:#?}"))
}

#[test]
fn ui_map_crawl_records_outcomes_for_spa_fixture() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping UI map crawl e2e: Chrome/Chromium not detected");
        return;
    }

    let server = SpaServer::start(fixture_root());
    let tmp = tempfile::tempdir().expect("create tempdir");
    let output_dir = tmp.path().join("scan");
    let config_path = tmp.path().join("brokenapp.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[target]
url = "{url}"
headless = true

[scan]
settle_timeout_ms = 500
interaction_timeout_ms = 3000
max_views = 20
max_depth = 5
max_duration_minutes = 3

[scan.limits]
max_interactions_per_view = 25

[scan.exploration]
strategy = "breadth_first"
fill_forms_with_test_data = true

[output]
directory = "{out}"
"#,
            url = server.url("/#/"),
            out = output_dir.display()
        ),
    )
    .expect("write config");

    let started = Instant::now();
    let output = Command::new(brokenapp_bin())
        .args([
            "scan",
            "--json",
            "--config",
            config_path.to_str().expect("config path utf8"),
        ])
        .output()
        .expect("run brokenapp scan on SPA fixture");
    let elapsed = started.elapsed();
    assert!(
        output.status.success(),
        "scan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // A same-document restore hang costs ~30 s per occurrence; the whole
    // fixture takes ~30 s locally.
    assert!(
        elapsed < Duration::from_secs(120),
        "scan took {elapsed:?}; restore or navigation stalled"
    );

    let rows = read_jsonl(&output_dir.join("interactions.jsonl"));
    assert!(!rows.is_empty(), "interactions.jsonl must not be empty");
    for row in &rows {
        assert_eq!(str_field(row, "schema"), "brokenapp.interaction.v1");
        assert!(!str_field(row, "view_id").is_empty());
        assert!(str_field(row, "page_url").starts_with("http://"));
        assert_eq!(
            row.get("action_id").and_then(Value::as_str).is_some(),
            str_field(row, "action") != "skip",
            "exercised controls carry an action_id, never-clicked ones do not: {row}"
        );
        if str_field(row, "outcome") == "skipped" {
            assert!(
                !str_field(row, "skipped_reason").is_empty(),
                "skipped rows carry a reason: {row}"
            );
        }
        let duration = row.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
        assert!(duration < 10_000, "no single interaction may stall: {row}");
    }

    // Dead button: clicked, nothing happened.
    let dead = attempted(&rows, "Do nothing");
    assert_eq!(str_field(dead, "outcome"), "no_effect", "{dead}");
    assert!(dead.get("console_errors").is_none(), "{dead}");

    // Handler that throws: an error outcome with the attributed exception.
    let boom = attempted(&rows, "Explode");
    assert_eq!(str_field(boom, "outcome"), "error", "{boom}");
    let console = boom
        .get("console_errors")
        .and_then(Value::as_array)
        .expect("console errors attributed to the throwing control");
    assert!(
        console.iter().any(|m| m
            .as_str()
            .unwrap_or_default()
            .contains("explode handler failed")),
        "{boom}"
    );
    assert!(str_field(boom, "error").contains("explode handler failed"));

    // Modal, fetch, toast and the hamburger-opened sidenav.
    assert_eq!(
        str_field(attempted(&rows, "Open details"), "dom_change"),
        "modal"
    );
    let load = attempted(&rows, "Load data");
    assert_eq!(str_field(load, "outcome"), "dom_change", "{load}");
    assert_eq!(
        load.get("network_activity"),
        Some(&Value::Bool(true)),
        "{load}"
    );
    let menu = attempted(&rows, "Open menu");
    assert_eq!(str_field(menu, "dom_change"), "menu", "{menu}");
    // Viewport is 1366 wide: the desktop-only Help button exists and works.
    assert_eq!(str_field(attempted(&rows, "Help"), "dom_change"), "modal");
    // Submit buttons are exercised while the write guard is on.
    let save = attempted(&rows, "Save settings");
    assert_eq!(str_field(save, "dom_change"), "toast", "{save}");

    // Mid-pass navigation, then the view is restored for the next control.
    let browse_idx = rows
        .iter()
        .position(|r| {
            str_field(r, "label") == "Browse products" && str_field(r, "outcome") != "skipped"
        })
        .expect("Browse products attempted");
    let browse = &rows[browse_idx];
    assert_eq!(str_field(browse, "outcome"), "navigated", "{browse}");
    assert!(
        str_field(browse, "after_url").ends_with("#/products"),
        "{browse}"
    );
    let next = rows[browse_idx + 1..]
        .iter()
        .find(|r| {
            str_field(r, "view_id") == str_field(browse, "view_id")
                && str_field(r, "outcome") != "skipped"
        })
        .expect("a control exercised after the navigation");
    assert_eq!(
        str_field(next, "page_url"),
        str_field(browse, "page_url"),
        "the view must be restored before the next control: {next}"
    );
    let browse_end = chrono::DateTime::parse_from_rfc3339(str_field(browse, "started_at"))
        .expect("started_at")
        + chrono::Duration::milliseconds(
            browse
                .get("duration_ms")
                .and_then(Value::as_i64)
                .unwrap_or(0),
        );
    let next_start =
        chrono::DateTime::parse_from_rfc3339(str_field(next, "started_at")).expect("started_at");
    assert!(
        (next_start - browse_end).num_milliseconds() < 5_000,
        "hash-route restore must not stall ({} ms)",
        (next_start - browse_end).num_milliseconds()
    );

    // Dangerous controls are never clicked.
    for label in ["Sign out", "Delete account"] {
        let labelled = rows_labelled(&rows, label);
        assert!(!labelled.is_empty(), "{label} recorded");
        assert!(
            labelled
                .iter()
                .all(|r| str_field(r, "skipped_reason") == "dangerous_label"),
            "{label}: {labelled:#?}"
        );
    }

    // Shell controls are exercised once, then recorded as exercised elsewhere.
    let menu_view = str_field(menu, "view_id");
    let elsewhere: Vec<_> = rows_labelled(&rows, "Open menu")
        .into_iter()
        .filter(|r| str_field(r, "skipped_reason") == "exercised_elsewhere")
        .collect();
    assert!(elsewhere.len() >= 3, "{elsewhere:#?}");
    assert!(
        elsewhere
            .iter()
            .all(|r| str_field(r, "exercised_on") == menu_view)
    );

    // Repeated cards: at most two of five identical buttons are exercised.
    let cards = rows_labelled(&rows, "Add to cart");
    assert_eq!(cards.len(), 5, "{cards:#?}");
    assert_eq!(
        cards
            .iter()
            .filter(|r| str_field(r, "outcome") != "skipped")
            .count(),
        2
    );
    assert_eq!(
        cards
            .iter()
            .filter(|r| str_field(r, "skipped_reason") == "repeated_control")
            .count(),
        3
    );

    // Links revealed by the hamburger were harvested and visited; routes that
    // share a layout (inbox/team) stay distinct views.
    let spec: Value =
        serde_json::from_str(&fs::read_to_string(output_dir.join("spec.json")).expect("spec"))
            .expect("spec json");
    let views = spec["views"].as_array().expect("views");
    let routes: BTreeSet<&str> = views.iter().filter_map(|v| v["route"].as_str()).collect();
    for route in [
        "/#/",
        "/#/products",
        "/#/inbox",
        "/#/team",
        "/reports",
        "/#/settings",
    ] {
        assert!(
            routes.contains(route),
            "route {route} not visited: {routes:?}"
        );
    }
    let fingerprint_of = |route: &str| {
        views
            .iter()
            .find(|v| v["route"] == route)
            .and_then(|v| v["dom_fingerprint"].as_str())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(
        fingerprint_of("/#/inbox"),
        fingerprint_of("/#/team"),
        "fixture invariant: inbox and team share one layout"
    );
    assert!(
        rows_labelled(&rows, "Inbox")
            .iter()
            .any(|r| str_field(r, "skipped_reason") == "navigation_via_href"),
        "revealed sidenav links are recorded as controls of the view"
    );
    let requests = server.requests();
    assert!(requests.iter().any(|r| r == "GET /reports"), "{requests:?}");

    // A price like "5000¤" is not an HTTP 500 error page.
    let products = views
        .iter()
        .find(|v| v["route"] == "/#/products")
        .expect("products view");
    assert!(
        !products.to_string().contains("\"error_page\""),
        "products view misclassified as an error page"
    );

    // Console findings are attributed to the control that raised them.
    let bugs: Value =
        serde_json::from_str(&fs::read_to_string(output_dir.join("bugs.json")).expect("bugs"))
            .expect("bugs json");
    let attributed = bugs["items"]
        .as_array()
        .expect("bug items")
        .iter()
        .any(|b| {
            b["title"] == "Unhandled exception"
                && b["location"]["element"] == "#explode-btn"
                && b["evidence"]["action_ids"][0] == boom["action_id"]
        });
    assert!(
        attributed,
        "exception finding attributed to #explode-btn: {bugs:#}"
    );
}

#[test]
fn goto_and_wait_restores_hash_routes_without_stalling() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping hash restore test: Chrome/Chromium not detected");
        return;
    }
    let server = SpaServer::start(fixture_root());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let browser =
            brokenapp::browser::BrowserManager::launch(brokenapp::browser::BrowserLaunchOptions {
                chrome_executable: brokenapp::browser::BrowserManager::detect_chrome_executable(),
                ..Default::default()
            })
            .await
            .expect("launch browser");
        let page = browser.new_page("about:blank").await.expect("new page");
        page.goto_and_wait(&server.url("/#/products"), Duration::from_secs(10))
            .await
            .expect("initial load");

        // Same-document (fragment-only) navigation: must not wait for the
        // ~30 s CDP timeout that Page.navigate hits here.
        let started = Instant::now();
        page.goto_and_wait(&server.url("/#/"), Duration::from_secs(10))
            .await
            .expect("hash restore");
        let hash_restore = started.elapsed();
        assert!(
            hash_restore < Duration::from_secs(2),
            "hash restore took {hash_restore:?}"
        );
        let mut hash = String::new();
        for _ in 0..20 {
            hash = page
                .evaluate_json::<String>("location.hash")
                .await
                .expect("read hash");
            if hash == "#/" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(hash, "#/");

        // Cross-document navigation is bounded by the timeout.
        let started = Instant::now();
        let slow = page
            .goto_and_wait(&server.url("/slow"), Duration::from_millis(1500))
            .await;
        let slow_elapsed = started.elapsed();
        assert!(
            slow.is_err(),
            "a navigation that cannot complete in time reports an error"
        );
        assert!(
            slow_elapsed < Duration::from_secs(4),
            "navigation took {slow_elapsed:?}"
        );

        let _ = browser.shutdown().await;
    });
}

fn precision_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-precision")
}

/// Routes for `tests/fixtures/ui-map-precision`: one HTML file per page,
/// `/towns/<slug>` instances of one template, a route chunk that is slow to
/// load (cold dev server), and writes that must never arrive.
fn precision_routes(stream: &mut TcpStream, root: &Path, method: &str, path: &str) {
    let file = |name: &str| fs::read(root.join(name));
    let html = |stream: &mut TcpStream, name: &str| match file(name) {
        Ok(body) => respond(stream, "200 OK", "text/html; charset=utf-8", &body),
        Err(_) => respond(stream, "404 Not Found", "text/plain", b"missing"),
    };
    if method != "GET" {
        respond(stream, "200 OK", "application/json", b"{}");
        return;
    }
    match path {
        "/" | "/index.html" => html(stream, "index.html"),
        "/lazy-frame" => html(stream, "lazy-frame.html"),
        "/frame.html" => html(stream, "frame.html"),
        "/lazy-route" => html(stream, "lazy-route.html"),
        "/deferred-lazy-route" => html(stream, "deferred-lazy-route.html"),
        "/wizard" => html(stream, "wizard.html"),
        "/towns" => html(stream, "towns.html"),
        "/contact" => html(stream, "contact.html"),
        "/chunks/receiving.js" => {
            thread::sleep(Duration::from_millis(2500));
            match file("chunks/receiving.js") {
                Ok(body) => respond(stream, "200 OK", "text/javascript", &body),
                Err(_) => respond(stream, "404 Not Found", "text/plain", b"missing"),
            }
        }
        p if p.starts_with("/towns/") => html(stream, "town.html"),
        _ => respond(stream, "404 Not Found", "text/plain", b"missing"),
    }
}

fn outcome_of<'a>(rows: &'a [Value], label: &str) -> &'a str {
    str_field(attempted(rows, label), "outcome")
}

fn has_side_effect(row: &Value, effect: &str) -> bool {
    row.get("side_effects")
        .and_then(Value::as_array)
        .is_some_and(|effects| effects.iter().any(|e| e.as_str() == Some(effect)))
}

/// Precision of what a click is credited with, page readiness, single-URL
/// state reset, template instance sampling and form filling.
#[test]
fn ui_map_crawl_attributes_effects_precisely() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping UI map precision e2e: Chrome/Chromium not detected");
        return;
    }

    let server = SpaServer::start_with(precision_root(), precision_routes);
    let tmp = tempfile::tempdir().expect("create tempdir");
    let output_dir = tmp.path().join("scan");
    let config_path = tmp.path().join("brokenapp.toml");
    let seeds = tmp.path().join("seeds.txt");
    fs::write(
        &seeds,
        "/\n/lazy-frame\n/lazy-route\n/wizard\n/towns\n/contact\n",
    )
    .expect("seeds");
    fs::write(
        &config_path,
        format!(
            r#"
[target]
url = "{url}"
headless = true

[scan]
settle_timeout_ms = 800
interaction_timeout_ms = 3000
max_views = 30
max_depth = 4
max_duration_minutes = 5
seed_routes_file = "{seeds}"
route_templates = ["/towns/:slug"]

[scan.limits]
max_interactions_per_view = 30

[scan.exploration]
strategy = "breadth_first"
fill_forms_with_test_data = true

[output]
directory = "{out}"
"#,
            url = server.url("/"),
            seeds = seeds.display(),
            out = output_dir.display()
        ),
    )
    .expect("write config");

    let started = Instant::now();
    let output = Command::new(brokenapp_bin())
        .args([
            "scan",
            "--json",
            "--config",
            config_path.to_str().expect("config path utf8"),
        ])
        .output()
        .expect("run brokenapp scan on precision fixture");
    assert!(
        output.status.success(),
        "scan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("precision fixture scan took {:?}", started.elapsed());
    if let Some(dir) = std::env::var_os("BROKENAPP_FORM_RECOVERY_ARTIFACT_DIR") {
        let case = PathBuf::from(dir).join("existing-precision");
        fs::create_dir_all(&case).unwrap();
        for name in [
            "spec.json",
            "interactions.jsonl",
            "network.jsonl",
            "scan-run.json",
        ] {
            if output_dir.join(name).exists() {
                fs::copy(output_dir.join(name), case.join(name)).unwrap();
            }
        }
        fs::write(case.join("stdout.json"), &output.stdout).unwrap();
        fs::write(case.join("stderr.log"), &output.stderr).unwrap();
        fs::copy(&config_path, case.join("brokenapp.toml")).unwrap();
    }

    let rows = read_jsonl(&output_dir.join("interactions.jsonl"));
    for row in &rows {
        assert_eq!(
            row.get("action_id").and_then(Value::as_str).is_some(),
            str_field(row, "action") != "skip",
            "{row}"
        );
    }

    // A button inside a closed <details> is clicked after opening it.
    assert_eq!(
        outcome_of(&rows, "Print location label CAGE-1"),
        "dom_change"
    );

    // Clicking the already-selected filter does nothing, and says why.
    let all = attempted(&rows, "All 3");
    assert_eq!(str_field(all, "outcome"), "no_effect", "{all}");
    assert_eq!(all.get("already_active"), Some(&Value::Bool(true)), "{all}");
    assert_eq!(outcome_of(&rows, "Open 1"), "dom_change");

    // window.print() and scrolling a container are effects, not dead clicks.
    let print = attempted(&rows, "Print");
    assert_eq!(str_field(print, "outcome"), "dom_change", "{print}");
    assert!(has_side_effect(print, "print"), "{print}");
    let jump = attempted(&rows, "Start the test");
    assert_eq!(str_field(jump, "outcome"), "dom_change", "{jump}");
    assert!(has_side_effect(jump, "scroll"), "{jump}");

    // Opening a file chooser is an effect too.
    let import = attempted(&rows, "Import CSV");
    assert_eq!(str_field(import, "outcome"), "dom_change", "{import}");
    assert!(has_side_effect(import, "file_chooser"), "{import}");

    // Sorting a list (same texts, new order) is an effect.
    assert_eq!(outcome_of(&rows, "Sort by name"), "dom_change");

    // Truly dead: confirmed on a fresh copy of the view, although a timer
    // keeps ticking next to it.
    let dead = attempted(&rows, "Do nothing at all");
    assert_eq!(str_field(dead, "outcome"), "no_effect", "{dead}");
    assert!(dead.get("already_active").is_none(), "{dead}");
    assert!(dead.get("side_effects").is_none(), "{dead}");
    assert_eq!(str_field(dead, "retest"), "confirmed_no_effect", "{dead}");
    // Re-writing attribute values that are already set is not an effect.
    assert_eq!(outcome_of(&rows, "Visit"), "no_effect");
    // Neither is a fixed bar reacting to the scroll that brought "Play
    // video" into view.
    assert_eq!(outcome_of(&rows, "Play video"), "no_effect");

    // Responsive resource selection during loading is not a click effect;
    // authored image and picture source changes still are.
    assert_eq!(outcome_of(&rows, "Wait for responsive image"), "no_effect");
    for label in [
        "Change image source",
        "Change image source set",
        "Change picture source",
    ] {
        assert_eq!(outcome_of(&rows, label), "dom_change", "{label}");
    }

    // Accessible names keep whitespace between blocks.
    assert_eq!(outcome_of(&rows, "WhatsApp Chat export"), "dom_change");

    // The row's own button is credited with its notice, not the row's
    // navigation, and the row's text cells are not controls.
    let row_print = attempted(&rows, "Print label");
    assert_eq!(str_field(row_print, "outcome"), "dom_change", "{row_print}");
    for cell in ["Available", "SHELF-A1"] {
        assert!(
            rows_labelled(&rows, cell).is_empty(),
            "{cell} is not a control"
        );
    }

    // A page with an off-screen lazy iframe loads and is exercised.
    assert_eq!(outcome_of(&rows, "Get directions"), "dom_change");
    // A lazy route chunk is waited for before discovery.
    assert_eq!(outcome_of(&rows, "Open & count"), "dom_change");

    // Single-URL wizard: the view is reset between siblings, gated controls
    // are enabled by filling their form, and later steps are reached.
    assert_eq!(outcome_of(&rows, "Show tip"), "dom_change");
    assert_eq!(outcome_of(&rows, "Continue"), "dom_change");
    assert_eq!(outcome_of(&rows, "Clear selection"), "dom_change");

    // Template instances: date cells are one repeated control (at most two
    // per view), the other controls are reached, and instances after the
    // third only exercise what no sibling did.
    let town_rows: Vec<&Value> = rows
        .iter()
        .filter(|r| str_field(r, "page_url").contains("/towns/"))
        .collect();
    let mut towns: BTreeSet<String> = BTreeSet::new();
    for r in &town_rows {
        let url = str_field(r, "page_url");
        if str_field(r, "outcome") != "skipped" && !url.contains('#') {
            towns.insert(url.to_string());
        }
    }
    let mut per_view: std::collections::BTreeMap<&str, usize> = Default::default();
    for r in &town_rows {
        if str_field(r, "label").contains("2026, open") && str_field(r, "outcome") != "skipped" {
            *per_view.entry(str_field(r, "view_id")).or_default() += 1;
        }
    }
    assert!(per_view.values().all(|n| *n <= 2), "{per_view:?}");
    for label in [
        "Next month",
        "More: Roll-off 10 yard",
        "Fewer: Roll-off 10 yard",
        "How long can I keep it?",
    ] {
        assert_eq!(outcome_of(&rows, label), "dom_change", "{label}");
    }
    assert!(
        towns.len() <= 3,
        "at most three town instances are exercised: {towns:?}"
    );
    assert!(
        town_rows
            .iter()
            .any(|r| str_field(r, "skipped_reason") == "exercised_elsewhere"),
        "later instances record controls exercised on siblings"
    );

    // Synthetic dates respect the field's min, so the form submits.
    assert_eq!(outcome_of(&rows, "Check these dates"), "dom_change");
    // A form the browser refuses to submit (a required file) shows a
    // validation message: an effect, not a dead button.
    let upload = attempted(&rows, "Upload file");
    assert_eq!(str_field(upload, "outcome"), "dom_change", "{upload}");
    assert!(has_side_effect(upload, "form_validation"), "{upload}");

    // The research form is filled, so its write is observed (and blocked).
    let research = attempted(&rows, "Research idea");
    let action_id = str_field(research, "action_id").to_string();
    let network: Vec<Value> = read_jsonl(&output_dir.join("network.jsonl"));
    let blocked = network.iter().find(|r| {
        r.get("write_guard").and_then(Value::as_str) == Some("blocked")
            && r.pointer("/request/url")
                .and_then(Value::as_str)
                .is_some_and(|u| u.ends_with("/api/research"))
    });
    let blocked = blocked.unwrap_or_else(|| panic!("POST /api/research was not attempted"));
    assert_eq!(
        blocked.pointer("/trace/action_id").and_then(Value::as_str),
        Some(action_id.as_str()),
        "{blocked:#}"
    );
    let requests = server.requests();
    assert!(
        requests.iter().all(|r| r.starts_with("GET ")),
        "no write reached the server: {requests:?}"
    );

    // A click that moves the page to another client-side route keeps its
    // own request; the new route's bootstrap request is not the click's.
    let spa_nav = attempted(&rows, "Go to research desk");
    let spa_action = str_field(spa_nav, "action_id").to_string();
    let request_row = |suffix: &str| {
        network
            .iter()
            .find(|r| {
                r.pointer("/request/url")
                    .and_then(Value::as_str)
                    .is_some_and(|u| u.ends_with(suffix))
            })
            .unwrap_or_else(|| panic!("no request for {suffix}"))
    };
    let own = request_row("/api/route-click");
    assert_eq!(
        own.pointer("/trace/action_id").and_then(Value::as_str),
        Some(spa_action.as_str()),
        "{own:#}"
    );
    let bootstrap = request_row("/api/route-bootstrap");
    assert!(
        bootstrap.get("triggered_by").is_none_or(Value::is_null),
        "{bootstrap:#}"
    );

    // Every seeded route was visited; nothing timed out.
    let spec: Value =
        serde_json::from_str(&fs::read_to_string(output_dir.join("spec.json")).expect("spec"))
            .expect("spec json");
    let routes: BTreeSet<&str> = spec["views"]
        .as_array()
        .expect("views")
        .iter()
        .filter_map(|v| v["route"].as_str())
        .collect();
    for route in ["/", "/lazy-frame", "/lazy-route", "/wizard", "/contact"] {
        assert!(
            routes.contains(route),
            "route {route} not visited: {routes:?}"
        );
    }
    let bugs = fs::read_to_string(output_dir.join("bugs.json")).expect("bugs");
    assert!(!bugs.contains("Navigation failed"), "{bugs}");
}

#[test]
fn goto_and_wait_tolerates_lazy_iframes_and_reloads() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping lazy iframe navigation test: Chrome/Chromium not detected");
        return;
    }
    let server = SpaServer::start_with(precision_root(), precision_routes);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let browser =
            brokenapp::browser::BrowserManager::launch(brokenapp::browser::BrowserLaunchOptions {
                chrome_executable: brokenapp::browser::BrowserManager::detect_chrome_executable(),
                ..Default::default()
            })
            .await
            .expect("launch browser");
        let page = browser.new_page("about:blank").await.expect("new page");
        page.enable_domains().await.expect("enable domains");
        // The off-screen loading=lazy iframe never fires `load`; the page
        // itself is ready almost at once.
        let started = Instant::now();
        page.goto_and_wait(&server.url("/lazy-frame"), Duration::from_secs(10))
            .await
            .expect("lazy iframe page loads");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        // Navigating away and back is not held up by the earlier page.
        let started = Instant::now();
        page.goto_and_wait(&server.url("/towns"), Duration::from_secs(10))
            .await
            .expect("next page");
        page.goto_and_wait(&server.url("/lazy-frame"), Duration::from_secs(10))
            .await
            .expect("back to the lazy iframe page");
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "took {:?}",
            started.elapsed()
        );
        // A reload gives a fresh document.
        page.evaluate_json::<bool>("(() => { window.__marker = 1; return true; })()")
            .await
            .expect("mark document");
        page.reload_and_wait(Duration::from_secs(10))
            .await
            .expect("reload");
        let marker = page
            .evaluate_json::<bool>("typeof window.__marker === 'undefined'")
            .await
            .expect("read marker");
        assert!(marker, "reload replaced the document");
        // Lazy route content is waited for.
        page.goto_and_wait(&server.url("/lazy-route"), Duration::from_secs(10))
            .await
            .expect("lazy route");
        let _ =
            brokenapp::browser::cdp_helpers::settle_page(&page, Duration::from_millis(800)).await;
        let rendered = page
            .evaluate_json::<bool>("!!document.getElementById('open-count')")
            .await
            .expect("probe");
        assert!(
            rendered,
            "settle_page waits for the lazily loaded route chunk"
        );
        let _ = browser.shutdown().await;
    });
}

#[test]
fn settle_page_waits_for_deferred_status_fallback_and_stays_bounded() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping deferred page readiness test: Chrome/Chromium not detected");
        return;
    }
    let server = SpaServer::start_with(precision_root(), precision_routes);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let browser =
            brokenapp::browser::BrowserManager::launch(brokenapp::browser::BrowserLaunchOptions {
                chrome_executable: brokenapp::browser::BrowserManager::detect_chrome_executable(),
                ..Default::default()
            })
            .await
            .expect("launch browser");
        let page = browser.new_page("about:blank").await.expect("new page");
        page.enable_domains().await.expect("enable domains");
        brokenapp::browser::cdp_helpers::install_instrumentation(&page)
            .await
            .expect("instrumentation");
        page.goto_and_wait(&server.url("/deferred-lazy-route"), Duration::from_secs(10))
            .await
            .expect("deferred lazy route");
        brokenapp::browser::cdp_helpers::settle_page(&page, Duration::from_millis(800))
            .await
            .expect("wait for workspace");
        // Run the same initial discovery as the crawler, before any action or
        // navigation-only harvest can lend late links to an incomplete view.
        let elements = brokenapp::dom::discover_interactive_elements(&page, &"initial".into())
            .await
            .expect("discover initial controls");
        let labels: BTreeSet<_> = elements.iter().filter_map(|e| e.label.as_deref()).collect();
        for label in [
            "Open & count",
            "All queue items",
            "Search queue",
            "Open queue item",
        ] {
            assert!(
                labels.contains(label),
                "missing initial {label}: {labels:?}"
            );
        }

        // Useful short content and ordinary live statuses must not be treated
        // as loading just because there are few controls or a status element.
        for html in [
            "<main><p role='status'>Ready</p><button>Continue</button></main>",
            "<main><p role='status'>All saved</p></main>",
            "<main><h1>Opening hours</h1></main>",
            "<main><p role='status'>Opening hours: 9–5</p></main>",
            "<main><p>Loading dock hours</p><a href='/contact'>Contact</a></main>",
        ] {
            let js = format!(
                "document.body.innerHTML = {}; true",
                serde_json::to_string(html).unwrap()
            );
            page.evaluate_json::<bool>(&js)
                .await
                .expect("ready fixture");
            let start = Instant::now();
            brokenapp::browser::cdp_helpers::settle_page(&page, Duration::from_millis(150))
                .await
                .expect("ready page settles");
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "ready page waited for content: {html}"
            );
        }

        // Bare Loading text exercises the real JS word boundary (not the
        // spinner/aria-busy branch) and a stuck fallback still reaches the cap.
        page.evaluate_json::<bool>(
            "document.body.innerHTML = '<main><p role=\"status\">Loading…</p></main>'; true",
        )
        .await
        .expect("stuck loading fixture");
        let start = Instant::now();
        brokenapp::browser::cdp_helpers::settle_page(&page, Duration::from_millis(150))
            .await
            .expect("stuck loading remains bounded");
        assert!(
            start.elapsed() >= Duration::from_secs(5),
            "bare loading text was accepted as ready"
        );
        assert!(
            start.elapsed() < Duration::from_secs(9),
            "content wait exceeded its bound"
        );
        let _ = browser.shutdown().await;
    });
}

fn parallel_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-parallel")
}

const PARALLEL_ROUTES: [&str; 7] = ["home", "alpha", "beta", "gamma", "delta", "epsilon", "zeta"];

/// Routes for `tests/fixtures/ui-map-parallel`: one page per route from a
/// template, tagged JSON endpoints (`/api/attr/<route>/<button>`, the load
/// one slow), a cross-origin twin (`/api/xattr/...`, reached through
/// `localhost`), and writes that must never arrive.
fn parallel_routes(stream: &mut TcpStream, root: &Path, method: &str, path: &str) {
    if method != "GET" {
        respond(stream, "200 OK", "application/json", b"{}");
        return;
    }
    let route = match path {
        "/" | "/index.html" => Some("home"),
        p => PARALLEL_ROUTES
            .iter()
            .copied()
            .find(|r| p.strip_prefix('/') == Some(*r)),
    };
    if let Some(route) = route {
        match fs::read_to_string(root.join("page.html")) {
            Ok(body) => respond(
                stream,
                "200 OK",
                "text/html; charset=utf-8",
                body.replace("__ROUTE__", route).as_bytes(),
            ),
            Err(_) => respond(stream, "404 Not Found", "text/plain", b"missing"),
        }
        return;
    }
    if path.starts_with("/api/attr/") && path.ends_with("/load") {
        // Slow enough that tabs are mid-action at the same time.
        thread::sleep(Duration::from_millis(400));
    }
    if path.starts_with("/api/") {
        let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.flush();
        return;
    }
    respond(stream, "404 Not Found", "text/plain", b"missing");
}

/// `(route, button)` of a tagged URL (`/api/attr/alpha/save?late=1`), a
/// label (`Save alpha`) or a message (`ATTR route=alpha button=save`).
fn tag_of_url(url: &str) -> Option<(String, String)> {
    let path = url.split('?').next()?;
    let rest = path
        .split_once("/api/attr/")
        .or_else(|| path.split_once("/api/xattr/"))?
        .1;
    let (route, button) = rest.split_once('/')?;
    Some((route.to_string(), button.to_string()))
}

fn tag_of_label(label: &str) -> Option<(String, String)> {
    let (button, route) = label.split_once(' ')?;
    PARALLEL_ROUTES
        .contains(&route)
        .then(|| (route.to_string(), button.to_ascii_lowercase()))
}

fn tag_of_message(message: &str) -> Option<(String, String)> {
    let rest = message.split_once("ATTR route=")?.1;
    let (route, rest) = rest.split_once(" button=")?;
    let button: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    Some((route.to_string(), button))
}

/// Fixture route of a `spec.json` view route (`/` is `home`).
fn fixture_route(route: &str) -> String {
    match route.trim_matches('/') {
        "" => "home".to_string(),
        r => r.to_string(),
    }
}

/// Several tabs exercise buttons on different routes at the same time; every
/// request, console error, exception and dialog must be credited to an action
/// of the tab (route) it happened on.
#[test]
fn parallel_tabs_never_misattribute_across_tabs() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping parallel attribution e2e: Chrome/Chromium not detected");
        return;
    }

    let server = SpaServer::start_with(parallel_root(), parallel_routes);
    let tmp = tempfile::tempdir().expect("create tempdir");
    let output_dir = tmp.path().join("scan");
    let config_path = tmp.path().join("brokenapp.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[target]
url = "{url}"
headless = true

[scan]
settle_timeout_ms = 500
interaction_timeout_ms = 3000
max_views = 20
max_depth = 3
max_duration_minutes = 3
max_concurrent_tabs = 3

[scan.exploration]
strategy = "breadth_first"

[output]
directory = "{out}"
"#,
            url = server.url("/"),
            out = output_dir.display()
        ),
    )
    .expect("write config");

    let output = Command::new(brokenapp_bin())
        .args([
            "scan",
            "--json",
            "--config",
            config_path.to_str().expect("config path utf8"),
        ])
        .env_remove("BROKENAPP_MAX_CONCURRENT_TABS")
        .output()
        .expect("run brokenapp scan on the parallel fixture");
    assert!(
        output.status.success(),
        "scan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The write guard holds on every tab.
    let writes: Vec<String> = server
        .requests()
        .into_iter()
        .filter(|r| !r.starts_with("GET "))
        .collect();
    assert!(writes.is_empty(), "writes reached the server: {writes:?}");

    let spec: Value =
        serde_json::from_str(&fs::read_to_string(output_dir.join("spec.json")).expect("spec"))
            .expect("spec json");
    let view_routes: std::collections::BTreeMap<String, String> = spec["views"]
        .as_array()
        .expect("views")
        .iter()
        .map(|v| {
            (
                str_field(v, "id").to_string(),
                fixture_route(str_field(v, "route")),
            )
        })
        .collect();
    let visited: BTreeSet<&str> = view_routes.values().map(String::as_str).collect();
    for route in PARALLEL_ROUTES {
        assert!(visited.contains(route), "{route} not visited: {visited:?}");
    }
    let view_ids: BTreeSet<&String> = view_routes.keys().collect();
    assert_eq!(view_ids.len(), view_routes.len(), "view ids are unique");

    // Every button of every route was exercised, by the tab on that route.
    let rows = read_jsonl(&output_dir.join("interactions.jsonl"));
    let mut by_action: std::collections::HashMap<String, (String, String)> = Default::default();
    let mut by_control: std::collections::HashMap<(String, String), (String, String)> =
        Default::default();
    let mut windows: Vec<(String, i64, i64)> = Vec::new();
    for route in PARALLEL_ROUTES {
        for button in ["Save", "Load", "Boom", "Ping"] {
            attempted(&rows, &format!("{button} {route}"));
        }
    }
    let mut checked_console = 0usize;
    for row in &rows {
        let Some(tag) = tag_of_label(str_field(row, "label")) else {
            continue;
        };
        let view = str_field(row, "view_id").to_string();
        assert_eq!(
            view_routes.get(&view),
            Some(&tag.0),
            "a {tag:?} control was recorded on another route's view: {row}"
        );
        by_control.insert((view, str_field(row, "selector").to_string()), tag.clone());
        if let Some(action_id) = row.get("action_id").and_then(Value::as_str) {
            by_action.insert(action_id.to_string(), tag.clone());
        }
        if str_field(row, "outcome") != "skipped" {
            let start = chrono::DateTime::parse_from_rfc3339(str_field(row, "started_at"))
                .expect("started_at")
                .timestamp_millis();
            let duration = row.get("duration_ms").and_then(Value::as_i64).unwrap_or(0);
            windows.push((tag.0.clone(), start, start + duration));
        }
        // Console errors and exceptions: only the action's own.
        for message in row
            .get("console_errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if let Some(source) = tag_of_message(message) {
                assert_eq!(
                    source, tag,
                    "console output credited to the wrong action: {row}"
                );
                checked_console += 1;
            }
        }
        if let Some(dialog) = row.get("native_dialog").and_then(Value::as_str) {
            assert_eq!(
                tag_of_message(dialog).as_ref(),
                Some(&tag),
                "dialog credited to the wrong action: {row}"
            );
        }
        if tag.1 == "ping" && str_field(row, "outcome") != "skipped" {
            assert!(
                str_field(row, "native_dialog").contains(&format!("route={}", tag.0)),
                "the ping alert is the ping action's: {row}"
            );
        }
    }
    assert!(
        checked_console >= PARALLEL_ROUTES.len() * 2,
        "console output was attributed ({checked_console} messages)"
    );

    // The tabs really overlapped: actions on different routes ran at once.
    let overlapping = windows
        .iter()
        .enumerate()
        .flat_map(|(i, a)| windows[i + 1..].iter().map(move |b| (a, b)))
        .filter(|(a, b)| a.0 != b.0 && a.1 < b.2 && b.1 < a.2)
        .count();
    assert!(
        overlapping > 0,
        "no actions on different routes overlapped; the crawl was not parallel"
    );

    // Requests: by action id and by trigger, only ever the same route; the
    // immediate same-origin ones exactly the button that fired them. Every
    // page (one visit, one tab) only ever logs its own route's requests.
    let network = read_jsonl(&output_dir.join("network.jsonl"));
    let mut attributed = 0usize;
    let mut page_routes: std::collections::HashMap<String, String> = Default::default();
    let mut same_page = |row: &Value, route: &str| {
        if let Some(page) = row.pointer("/trace/page_id").and_then(Value::as_str) {
            let first = page_routes
                .entry(page.to_string())
                .or_insert_with(|| route.to_string());
            assert_eq!(first, route, "one page logged two routes' requests: {row}");
        }
    };
    for row in &network {
        let url = row
            .pointer("/request/url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if url.contains("/api/boot/") {
            // Parallel tabs are never hidden background tabs.
            assert!(url.ends_with("?visibility=visible"), "{row}");
            let route = url
                .split('?')
                .next()
                .and_then(|path| path.rsplit('/').next())
                .unwrap_or_default();
            same_page(row, route);
            if let Some(trigger) = row.get("triggered_by").filter(|t| !t.is_null()) {
                assert_eq!(str_field(trigger, "selector"), "__page_load__", "{row}");
                // Rows are written as requests finish; the load marker is
                // renamed to the view id once the view is fingerprinted.
                let view = str_field(trigger, "view");
                if !view.starts_with("__load_") {
                    assert_eq!(
                        view_routes.get(view).map(String::as_str),
                        Some(route),
                        "page-load request credited to another route's view: {row}"
                    );
                }
            }
            continue;
        }
        let Some(source) = tag_of_url(url) else {
            continue;
        };
        same_page(row, &source.0);
        if let Some(action_id) = row.pointer("/trace/action_id").and_then(Value::as_str) {
            let action = by_action
                .get(action_id)
                .unwrap_or_else(|| panic!("unknown action id {action_id}: {row}"));
            assert_eq!(
                action.0, source.0,
                "request credited to another tab's action: {row}"
            );
            if !url.contains("late=1") && !url.contains("/api/xattr/") {
                assert_eq!(
                    action, &source,
                    "request credited to the wrong action: {row}"
                );
            }
            attributed += 1;
        }
        if let Some(trigger) = row.get("triggered_by").filter(|t| !t.is_null()) {
            let view = str_field(trigger, "view").to_string();
            assert_eq!(
                view_routes.get(&view),
                Some(&source.0),
                "request credited to another tab's view: {row}"
            );
            if let Some(control) =
                by_control.get(&(view.clone(), str_field(trigger, "selector").to_string()))
            {
                assert_eq!(control.0, source.0, "{row}");
                if !url.contains("late=1") && !url.contains("/api/xattr/") {
                    assert_eq!(
                        control, &source,
                        "request credited to the wrong control: {row}"
                    );
                }
            }
        }
    }
    assert!(
        attributed >= PARALLEL_ROUTES.len() * 3,
        "requests were attributed ({attributed})"
    );

    // Findings: console errors located on a view of their own route.
    let bugs: Value =
        serde_json::from_str(&fs::read_to_string(output_dir.join("bugs.json")).expect("bugs"))
            .expect("bugs json");
    for bug in bugs["items"].as_array().into_iter().flatten() {
        let text = bug.to_string();
        let Some(source) = tag_of_message(&text) else {
            continue;
        };
        if let Some(view) = bug.pointer("/location/view").and_then(Value::as_str) {
            assert_eq!(
                view_routes.get(view),
                Some(&source.0),
                "finding located on another tab's view: {bug}"
            );
        }
    }
}

fn query_state_routes(stream: &mut TcpStream, root: &Path, method: &str, path: &str) {
    match (method, path) {
        ("GET", "/" | "/account") => {
            respond(
                stream,
                "200 OK",
                "text/html",
                &fs::read(root.join("index.html")).unwrap(),
            );
        }
        _ => respond(stream, "404 Not Found", "text/plain", b"missing"),
    }
}

#[test]
fn observed_query_tabs_are_exercised_and_retained_in_inventory() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping query-state crawl: Chrome/Chromium not detected");
        return;
    }
    let server = SpaServer::start_with(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-query-state"),
        query_state_routes,
    );
    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("scan");
    let config = tmp.path().join("brokenapp.toml");
    let seeds = tmp.path().join("seed-routes.txt");
    fs::write(&seeds, "/#/account\n").unwrap();
    fs::write(
        &config,
        format!(
            r#"
[target]
url = "{url}"
headless = true
[scan]
settle_timeout_ms = 300
interaction_timeout_ms = 2000
max_views = 20
max_depth = 5
max_duration_minutes = 2
seed_routes_file = "{seeds}"
[scan.write_guard]
mode = "block"
[scan.limits]
max_interactions_per_view = 20
[scan.exploration]
strategy = "breadth_first"
fill_forms_with_test_data = true
[output]
directory = "{out}"
"#,
            url = server.url("/account"),
            out = output_dir.display(),
            seeds = seeds.display()
        ),
    )
    .unwrap();
    let output = Command::new(brokenapp_bin())
        .env("BROKENAPP_HOME", tmp.path().join("home"))
        .args(["scan", "--json", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let records = read_jsonl(&output_dir.join("interactions.jsonl"));
    for route in ["/account", "/#/account"] {
        for (tab, label) in [
            ("payout", "Payout recipient"),
            ("payments", "Payment reference"),
        ] {
            let expected = server.url(&format!("{route}?tab={tab}"));
            assert!(
                records.iter().any(|r| str_field(r, "page_url") == expected
                    && str_field(r, "label") == label
                    && str_field(r, "outcome") != "skipped"),
                "missing exercised {label} in {expected}"
            );
        }
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let inventory = runtime
        .block_on(brokenapp::inventory::build_from_scan_dir(
            &output_dir,
            &brokenapp::inventory::BuildOptions {
                project: "query-states".into(),
                target_url: server.url("/account"),
                write_guard: "block".into(),
                ..Default::default()
            },
        ))
        .unwrap();
    for route in ["/account", "/#/account"] {
        for (tab, label) in [
            ("payout", "Payout recipient"),
            ("payments", "Payment reference"),
        ] {
            let control = inventory
                .controls
                .iter()
                .find(|c| c.route == route && c.label == label)
                .unwrap_or_else(|| panic!("missing {route} {label} inventory control"));
            assert!(control.status.is_exercised(), "{control:?}");
            assert!(
                control.variants.contains(&format!("?tab={tab}")),
                "{control:?}"
            );
        }
    }
    assert!(
        server.requests().iter().all(|r| r.starts_with("GET ")),
        "fixture must stay read-only"
    );
}

fn load_overlay_routes(stream: &mut TcpStream, root: &Path, method: &str, path: &str) {
    match (method, path) {
        ("GET", "/orders/42" | "/orders" | "/redirect-cookie" | "/destination") => {
            let body = fs::read(root.join("index.html")).expect("overlay fixture");
            respond(stream, "200 OK", "text/html; charset=utf-8", &body);
        }
        _ => respond(stream, "404 Not Found", "text/plain", b"missing"),
    }
}

#[test]
fn initial_overlay_dismissal_preserves_route_owned_dialogs() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping load overlay test: Chrome/Chromium not detected");
        return;
    }
    let server = SpaServer::start_with(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-load-overlays"),
        load_overlay_routes,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let browser = brokenapp::browser::BrowserManager::launch(
            brokenapp::browser::BrowserLaunchOptions {
                chrome_executable: brokenapp::browser::BrowserManager::detect_chrome_executable(),
                ..Default::default()
            },
        )
        .await
        .expect("browser");
        let page = browser.new_page("about:blank").await.expect("page");
        page.goto_and_wait(&server.url("/orders/42"), Duration::from_secs(10))
            .await
            .expect("order route");
        assert_eq!(
            brokenapp::dom::interaction::dismiss_blocking_overlays(&page).await,
            2
        );
        // The nested cookie wrapper remains in the DOM briefly after its
        // dismiss handler. It must not also activate the Accept decision.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            brokenapp::dom::interaction::dismiss_blocking_overlays(&page).await,
            0
        );
        let actual: Value = page
            .evaluate_json("({ counts, path: location.pathname, order: !!document.querySelector('#order-reference') })")
            .await
            .expect("overlay result");
        assert_eq!(actual["path"], "/orders/42");
        assert_eq!(actual["order"], true);
        assert_eq!(actual["counts"], serde_json::json!({
            "cookie": 1, "accepted": 0, "welcome": 1, "order": 0, "escape": 0, "generic": 0, "hidden": 0
        }));
        let _ = page.inner().clone().close().await;
    });
}

#[test]
fn overlay_navigation_is_rediscovered_under_its_actual_route() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping overlay navigation test: Chrome/Chromium not detected");
        return;
    }
    let server = SpaServer::start_with(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-load-overlays"),
        load_overlay_routes,
    );
    let tmp = tempfile::tempdir().unwrap();
    let output_dir = tmp.path().join("scan");
    let config = tmp.path().join("brokenapp.toml");
    fs::write(
        &config,
        format!(
            r#"
[target]
url = "{}"
headless = true
[scan]
settle_timeout_ms = 300
max_views = 5
max_duration_minutes = 1
[scan.write_guard]
mode = "block"
[output]
directory = "{}"
"#,
            server.url("/redirect-cookie"),
            output_dir.display()
        ),
    )
    .unwrap();
    let output = Command::new(brokenapp_bin())
        .env("BROKENAPP_HOME", tmp.path().join("home"))
        .args(["scan", "--json", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = read_jsonl(&output_dir.join("interactions.jsonl"));
    assert!(
        records
            .iter()
            .any(|r| str_field(r, "page_url") == server.url("/destination")
                && str_field(r, "label") == "Destination details")
    );
    assert!(
        !records
            .iter()
            .any(|r| str_field(r, "page_url") == server.url("/redirect-cookie"))
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let inventory = runtime
        .block_on(brokenapp::inventory::build_from_scan_dir(
            &output_dir,
            &brokenapp::inventory::BuildOptions {
                project: "overlay-navigation".into(),
                target_url: server.url("/redirect-cookie"),
                write_guard: "block".into(),
                ..Default::default()
            },
        ))
        .unwrap();
    let control = inventory
        .controls
        .iter()
        .find(|c| c.label == "Destination details")
        .unwrap();
    assert_eq!(control.route, "/destination");
    assert!(
        !inventory
            .routes
            .iter()
            .any(|r| r.route == "/redirect-cookie" && r.visited)
    );
}

/// The first view primes a password field with exactly the same shell identity
/// used on both later pages. No submitting page can inherit that DOM value.
/// In two-tab mode a GET barrier proves both later pages were open together.
fn form_state_routes(stream: &mut TcpStream, root: &Path, method: &str, path: &str) {
    if method != "GET" {
        respond(stream, "200 OK", "application/json", b"{}");
        return;
    }
    if let Some(name @ ("a" | "b")) = path.strip_prefix("/ready/") {
        fs::write(root.join(format!("ready-{name}")), b"").expect("mark ready page");
        let start = Instant::now();
        while !(root.join("ready-a").exists() && root.join("ready-b").exists()) {
            if start.elapsed() > Duration::from_secs(10) {
                fs::write(root.join("barrier-failed"), b"").expect("mark failed barrier");
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        respond(stream, "200 OK", "application/json", b"{}");
        return;
    }
    let name = match path {
        "/" => "primer",
        "/a" => "a",
        "/b" => "b",
        _ => {
            respond(stream, "404 Not Found", "text/plain", b"missing");
            return;
        }
    };
    let email = if name == "primer" {
        ""
    } else {
        r#"<label for="email">Email</label><input id="email" name="email" type="email" required>"#
    };
    let submit = if name == "primer" {
        ""
    } else {
        r#"<button type="submit">Sign in</button>"#
    };
    let links = if name == "primer" {
        r#"<a href="/a">First form</a><a href="/b">Second form</a>"#
    } else {
        ""
    };
    let barrier = if name != "primer" && root.join("parallel").exists() {
        format!("fetch('/ready/{name}');")
    } else {
        String::new()
    };
    let html = format!(
        r#"<!doctype html><html><body>
<header><form>{email}
<label for="password">Password</label><input id="password" name="password" type="password" required>
{submit}</form></header>
<main><h1>Form state {name}</h1>{links}</main>
<script>
{barrier}
document.querySelector('form').addEventListener('submit', event => {{
  event.preventDefault();
  fetch('/api/sign-in', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: '{{}}'}}).catch(() => {{}});
}});
</script></body></html>"#
    );
    respond(
        stream,
        "200 OK",
        "text/html; charset=utf-8",
        html.as_bytes(),
    );
}

#[test]
fn page_local_form_fields_preserve_guarded_submits() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping form-state crawl: Chrome/Chromium not detected");
        return;
    }
    // One tab also gets a fresh DOM on the next view. Two tabs additionally
    // exercise independent pages concurrently. The opt-out must still hold.
    for (tabs, fill) in [(2, true), (1, true), (2, false)] {
        let tmp = tempfile::tempdir().expect("form-state tempdir");
        let root = tmp.path().join("fixture");
        fs::create_dir(&root).unwrap();
        if tabs == 2 {
            fs::write(root.join("parallel"), b"").unwrap();
        }
        let server = SpaServer::start_with(root.clone(), form_state_routes);
        let output_dir = tmp.path().join("scan");
        let config = tmp.path().join("brokenapp.toml");
        fs::write(
            &config,
            format!(
                r#"
[target]
url = "{url}"
headless = true
[scan]
settle_timeout_ms = 300
interaction_timeout_ms = 3000
max_views = 10
max_depth = 3
max_duration_minutes = 2
max_concurrent_tabs = {tabs}
[scan.write_guard]
mode = "block"
allow_auth = false
[scan.limits]
max_interactions_per_view = 10
[scan.exploration]
strategy = "breadth_first"
fill_forms_with_test_data = {fill}
[output]
directory = "{out}"
"#,
                url = server.url("/"),
                out = output_dir.display(),
            ),
        )
        .unwrap();
        let output = Command::new(brokenapp_bin())
            .args(["scan", "--json", "--config", config.to_str().unwrap()])
            .env_remove("BROKENAPP_MAX_CONCURRENT_TABS")
            .output()
            .expect("run form-state scan");
        assert!(
            output.status.success(),
            "tabs={tabs} fill={fill}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(dir) = std::env::var_os("BROKENAPP_FORM_STATE_ARTIFACT_DIR") {
            let case = PathBuf::from(dir).join(format!("tabs-{tabs}-fill-{fill}"));
            fs::create_dir_all(&case).unwrap();
            for name in [
                "spec.json",
                "interactions.jsonl",
                "network.jsonl",
                "scan-run.json",
            ] {
                if output_dir.join(name).exists() {
                    fs::copy(output_dir.join(name), case.join(name)).unwrap();
                }
            }
            fs::copy(&config, case.join("brokenapp.toml")).unwrap();
            fs::write(case.join("stdout.json"), &output.stdout).unwrap();
            fs::write(case.join("stderr.log"), &output.stderr).unwrap();
            fs::write(
                case.join("fixture-server-requests.json"),
                serde_json::to_vec_pretty(&server.requests()).unwrap(),
            )
            .unwrap();
        }
        let interactions = read_jsonl(&output_dir.join("interactions.jsonl"));
        let network = read_jsonl(&output_dir.join("network.jsonl"));
        let spec: Value =
            serde_json::from_str(&fs::read_to_string(output_dir.join("spec.json")).unwrap())
                .unwrap();
        let views: std::collections::BTreeMap<String, String> = spec["views"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| (str_field(v, "id").into(), str_field(v, "route").into()))
            .collect();
        for route in ["/", "/a", "/b"] {
            assert!(views.values().any(|r| r == route), "unvisited {route}");
        }
        if tabs == 2 {
            assert!(root.join("ready-a").exists() && root.join("ready-b").exists());
            assert!(
                !root.join("barrier-failed").exists(),
                "pages did not overlap"
            );
        }
        let writes: Vec<_> = network
            .iter()
            .filter(|r| r.pointer("/request/method").and_then(Value::as_str) == Some("POST"))
            .collect();
        assert!(
            server.requests().iter().all(|r| r.starts_with("GET ")),
            "backend write leaked"
        );
        if !fill {
            assert!(writes.is_empty(), "fill opt-out still submitted");
            assert!(
                !interactions
                    .iter()
                    .any(|r| str_field(r, "action") == "type")
            );
            assert!(
                interactions
                    .iter()
                    .any(|r| str_field(r, "skipped_reason") == "form_fill_disabled")
            );
            continue;
        }
        // The primer was actually typed before the two submitting pages; a
        // scan-wide input claim would suppress both pages' password actions.
        for route in ["/", "/a", "/b"] {
            assert!(
                interactions.iter().any(|r| {
                    str_field(r, "label") == "Password"
                        && str_field(r, "action") == "type"
                        && str_field(r, "outcome") != "skipped"
                        && views
                            .get(str_field(r, "view_id"))
                            .is_some_and(|v| v == route)
                }),
                "password not prepared on its own page: {route}"
            );
        }
        for route in ["/a", "/b"] {
            assert!(
                interactions.iter().any(|r| {
                    str_field(r, "label") == "Email"
                        && str_field(r, "action") == "type"
                        && str_field(r, "outcome") != "skipped"
                        && views
                            .get(str_field(r, "view_id"))
                            .is_some_and(|v| v == route)
                }),
                "email not prepared on its own page: {route}"
            );
        }
        let submits: Vec<_> = interactions
            .iter()
            .filter(|r| {
                str_field(r, "label") == "Sign in"
                    && matches!(str_field(r, "action"), "click" | "submit")
            })
            .collect();
        let submit_views: BTreeSet<_> = submits.iter().map(|r| str_field(r, "view_id")).collect();
        assert_eq!(submit_views.len(), 1, "shared submit dedup changed");
        assert!(!writes.is_empty(), "complete form produced no guarded POST");
        for write in writes {
            assert_eq!(str_field(write, "write_guard"), "blocked");
            assert!(
                write
                    .pointer("/request/url")
                    .and_then(Value::as_str)
                    .unwrap()
                    .ends_with("/api/sign-in")
            );
            let action = write
                .pointer("/trace/action_id")
                .and_then(Value::as_str)
                .expect("write action id");
            let submit = submits
                .iter()
                .find(|r| str_field(r, "action_id") == action)
                .expect("write belongs to submit action");
            assert_eq!(
                write.pointer("/triggered_by/view").and_then(Value::as_str),
                Some(str_field(submit, "view_id"))
            );
            assert_eq!(
                write
                    .pointer("/triggered_by/selector")
                    .and_then(Value::as_str),
                Some(str_field(submit, "selector"))
            );
            assert!(write.get("response").is_none() && write.get("failure").is_none());
        }
    }
}

fn preparation_attribution_routes(stream: &mut TcpStream, _root: &Path, method: &str, path: &str) {
    if method == "GET" && path.starts_with("/api/") {
        respond(stream, "200 OK", "application/json", b"{}");
    } else if method == "GET" && path == "/" {
        respond(
            stream,
            "200 OK",
            "text/html",
            b"<a href='/a'>A</a><a href='/b'>B</a>",
        );
    } else if method == "GET" && matches!(path, "/a" | "/b") {
        respond(stream, "200 OK", "text/html", br#"<!doctype html><html><body>
<form id="booking"><label>Day<input name="day" id="day" required></label>
<label>Add-on<input type="checkbox" name="addon_3" id="addon"></label>
<button type="submit" id="continue">Continue</button></form><p id="done"></p>
<script>
let afterAddon = false;
const api = '/api' + location.pathname;
const day = document.querySelector('#day');
day.addEventListener('change', () => {
  const phase = afterAddon ? 'prefill' : 'input';
  fetch(api + '/availability?phase=' + phase);
  const xhr = new XMLHttpRequest(); xhr.open('GET', api + '/quote?phase=' + phase); xhr.send();
  if (afterAddon) fetch(api + '/preparation-write', {method: 'POST', body: 'synthetic'}).catch(() => {});
});
document.querySelector('#addon').addEventListener('change', () => {
  afterAddon = true; day.value = '';
  fetch(api + '/quote?phase=addon');
});
document.querySelector('#booking').addEventListener('submit', event => {
  event.preventDefault();
  fetch(api + '/reserve', {method: 'POST', body: 'synthetic'}).catch(() => {});
  document.querySelector('#done').textContent = 'Reservation attempted';
});
</script></body></html>"#);
    } else {
        respond(stream, "404 Not Found", "text/plain", b"not found");
    }
}

#[test]
fn preparation_requests_do_not_rewire_adjacent_controls() {
    let _guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    assert!(
        chrome_available(),
        "preparation attribution proof requires Chrome"
    );
    for tabs in [1, 2] {
        let tmp = tempfile::tempdir().unwrap();
        let server = SpaServer::start_with(tmp.path().into(), preparation_attribution_routes);
        let output_dir = tmp.path().join("scan");
        let config = tmp.path().join("brokenapp.toml");
        fs::write(
            &config,
            format!(
                r#"
[target]
url = "{url}"
headless = true
[scan]
settle_timeout_ms = 300
interaction_timeout_ms = 3000
max_views = 5
max_depth = 1
max_duration_minutes = 2
max_concurrent_tabs = {tabs}
[scan.write_guard]
mode = "block"
allow_auth = false
[scan.limits]
max_interactions_per_view = 12
[scan.exploration]
fill_forms_with_test_data = true
[output]
directory = "{out}"
"#,
                url = server.url("/"),
                out = output_dir.display()
            ),
        )
        .unwrap();
        let output = Command::new(brokenapp_bin())
            .args(["scan", "--json", "--config", config.to_str().unwrap()])
            .env_remove("BROKENAPP_MAX_CONCURRENT_TABS")
            .output()
            .unwrap();
        if let Some(dir) = std::env::var_os("BROKENAPP_PREPARATION_ARTIFACT_DIR") {
            let dest = PathBuf::from(dir).join(format!("tabs-{tabs}"));
            fs::create_dir_all(&dest).unwrap();
            for name in [
                "spec.json",
                "interactions.jsonl",
                "network.jsonl",
                "scan-run.json",
            ] {
                if output_dir.join(name).exists() {
                    fs::copy(output_dir.join(name), dest.join(name)).unwrap();
                }
            }
            fs::write(dest.join("stdout.json"), &output.stdout).unwrap();
            fs::write(dest.join("stderr.log"), &output.stderr).unwrap();
            fs::write(
                dest.join("server-requests.json"),
                serde_json::to_vec_pretty(&server.requests()).unwrap(),
            )
            .unwrap();
        }
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let actions = read_jsonl(&output_dir.join("interactions.jsonl"));
        let network = read_jsonl(&output_dir.join("network.jsonl"));
        for route in ["/a", "/b"] {
            let own = |r: &&Value| {
                r.pointer("/request/url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| {
                        url::Url::parse(url).is_ok_and(|u| {
                            u.path()
                                .strip_prefix("/api")
                                .is_some_and(|p| p.starts_with(&format!("{route}/")))
                        })
                    })
            };
            let prefill: Vec<_> = network
                .iter()
                .filter(|r| {
                    r.pointer("/request/url")
                        .and_then(Value::as_str)
                        .unwrap()
                        .contains("phase=prefill")
                        || r.pointer("/request/url")
                            .and_then(Value::as_str)
                            .unwrap()
                            .ends_with("/preparation-write")
                })
                .filter(own)
                .collect();
            assert!(
                prefill.len() >= 3,
                "route {route}: no actual form preparation traffic"
            );
            assert!(
                prefill.iter().any(|r| r
                    .pointer("/request/url")
                    .and_then(Value::as_str)
                    .unwrap()
                    .ends_with("/preparation-write")
                    && str_field(r, "write_guard") == "blocked"),
                "preparation write not captured and blocked"
            );
            for row in prefill {
                assert!(
                    row.get("triggered_by").is_none_or(Value::is_null),
                    "preparation falsely credited to a control: {row}"
                );
                assert!(row.pointer("/trace/action_id").is_none_or(Value::is_null));
                if row
                    .pointer("/request/method")
                    .and_then(Value::as_str)
                    .unwrap()
                    == "POST"
                {
                    assert_eq!(str_field(row, "write_guard"), "blocked");
                }
            }
            let quote = network
                .iter()
                .filter(|r| {
                    r.pointer("/request/url")
                        .and_then(Value::as_str)
                        .unwrap()
                        .ends_with("phase=addon")
                })
                .filter(own)
                .next()
                .expect("actual addon quote");
            assert_eq!(
                quote
                    .pointer("/triggered_by/selector")
                    .and_then(Value::as_str),
                Some("#addon")
            );
            let quote_id = quote
                .pointer("/trace/action_id")
                .and_then(Value::as_str)
                .expect("addon action id");
            assert!(actions.iter().any(|r| str_field(r, "action_id") == quote_id
                && str_field(r, "selector") == "#addon"
                && quote.pointer("/triggered_by/view").and_then(Value::as_str)
                    == Some(str_field(r, "view_id"))));
            let submit = network
                .iter()
                .filter(|r| {
                    r.pointer("/request/url")
                        .and_then(Value::as_str)
                        .unwrap()
                        .ends_with("/reserve")
                })
                .filter(own)
                .next()
                .expect("actual submit");
            assert_eq!(str_field(submit, "write_guard"), "blocked");
            assert_eq!(
                submit
                    .pointer("/triggered_by/selector")
                    .and_then(Value::as_str),
                Some("#continue")
            );
            let id = submit
                .pointer("/trace/action_id")
                .and_then(Value::as_str)
                .expect("submit action id");
            assert!(actions.iter().any(
                |r| str_field(r, "action_id") == id && str_field(r, "selector") == "#continue"
            ));
        }
        assert!(
            !server.requests().iter().any(|r| r.starts_with("POST ")),
            "write guard allowed a backend write"
        );
        assert!(network.iter().all(|r| {
            r.pointer("/request/headers")
                .and_then(Value::as_object)
                .expect("captured request headers")
                .keys()
                .all(|k| !k.eq_ignore_ascii_case("x-brokenapp-preparation"))
        }));
    }
}

// Each reset runs after the local fields and before the submit. A real reload
// loses required values; the away page also exercises restore's early return.
fn form_recovery_routes(stream: &mut TcpStream, root: &Path, method: &str, path: &str) {
    if method != "GET" {
        respond(stream, "200 OK", "application/json", b"{}");
        return;
    }
    let mode = fs::read_to_string(root.join("mode")).unwrap();
    if path == "/" {
        let links = if mode == "retained" {
            "<h1>Forms</h1><a href='/a#/base'>First</a><a href='/b#/base'>Second</a>"
        } else {
            "<h1>Forms</h1><a href='/a'>First</a><a href='/b'>Second</a>"
        };
        respond(stream, "200 OK", "text/html", links.as_bytes());
        return;
    }
    if path == "/away" {
        respond(stream, "200 OK", "text/html", b"<h1>Away</h1>");
        return;
    }
    if !matches!(path, "/a" | "/b") {
        respond(stream, "404 Not Found", "text/plain", b"missing");
        return;
    }
    let reset = match mode.as_str() {
        "navigate" => "location.href='/away'",
        "retained" => "location.hash='/temporary'",
        _ => "",
    };
    let native = matches!(
        mode.as_str(),
        "native" | "retained" | "missing-option" | "disabled-option"
    );
    let extra = if mode == "unsupported" {
        r#"<div id="custom" role="checkbox" tabindex="0" aria-checked="false" onclick="this.setAttribute('aria-checked','true');document.querySelectorAll('button').forEach(b=>b.disabled=false)">Custom consent</div>"#
    } else if native {
        r#"<label for="choice">Choice</label><select id="choice" name="choice"><option value="">Pick</option><option value="a">A</option></select>
<label for="agree">Agree</label><input id="agree" name="agree" type="checkbox">
<label for="radio-a">Radio A</label><input id="radio-a" name="group" type="radio" value="a" checked>
<label for="radio-b">Radio B</label><input id="radio-b" name="group" type="radio" value="b">"#
    } else {
        ""
    };
    let disabled = if mode == "unsupported" {
        "disabled"
    } else {
        ""
    };
    let native_script = if native {
        format!(
            r#"
if (sessionStorage.getItem(location.pathname)) {{
  if ('{mode}' === 'missing-option') document.querySelector('#choice').options[1].remove();
  if ('{mode}' === 'disabled-option') document.querySelector('#choice').options[1].disabled=true;
}}
sessionStorage.setItem(location.pathname,'1');
window.nativeChanges=0;
['choice','agree','radio-a','radio-b'].forEach(id=>document.getElementById(id).addEventListener('change',()=>window.nativeChanges++));
"#
        )
    } else {
        String::new()
    };
    let native_submit = if native {
        r#"if(document.getElementById('choice').value !== 'a' || !document.getElementById('agree').checked || document.getElementById('radio-a').checked || !document.getElementById('radio-b').checked || window.nativeChanges!==3) return;"#.to_string()
    } else {
        String::new()
    };
    let missing = if mode == "missing" {
        "if(sessionStorage.getItem(location.pathname)){document.querySelector('#password').remove()}sessionStorage.setItem(location.pathname,'1');"
    } else {
        ""
    };
    let html = format!(
        r#"<!doctype html><html><body><main><h1>Form {path}</h1>
<form><label for="email">Email</label><input id="email" name="email" type="email" required>
<label for="password">Password</label><input id="password" name="password" type="password" required>
{extra}<button {disabled} type="button" onclick="{reset}">Reset state {path}</button>
<button {disabled} type="submit">Sign in {path}</button></form></main>
<script>{missing}{native_script}
document.querySelector('form').addEventListener('submit', e=>{{e.preventDefault();{native_submit}fetch('/api/sign-in',{{method:'POST',body:'{{}}'}}).catch(()=>{{}})}});
</script></body></html>"#
    );
    respond(stream, "200 OK", "text/html", html.as_bytes());
}

#[test]
fn restored_forms_recover_local_typing_before_guarded_submit() {
    let _guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping form recovery: Chrome unavailable");
        return;
    }
    for (mode, tabs, fill) in [
        ("reload", 1, true),
        ("reload", 2, true),
        ("navigate", 2, true),
        ("reload", 2, false),
        ("unsupported", 1, true),
        ("missing", 1, true),
        ("budget", 1, true),
        ("native", 1, true),
        ("retained", 1, true),
        ("missing-option", 1, true),
        ("disabled-option", 1, true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("fixture");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("mode"), mode).unwrap();
        let limit = if mode == "budget" { 4 } else { 15 };
        let server = SpaServer::start_with(root, form_recovery_routes);
        let output_dir = tmp.path().join("scan");
        let config = tmp.path().join("brokenapp.toml");
        fs::write(
            &config,
            format!(
                r#"
[target]
url = "{url}"
headless = true
[scan]
settle_timeout_ms = 200
interaction_timeout_ms = 3000
max_views = 6
max_depth = 3
max_duration_minutes = 2
max_concurrent_tabs = {tabs}
[scan.write_guard]
mode = "block"
allow_auth = false
[scan.limits]
max_interactions_per_view = {limit}
[scan.exploration]
fill_forms_with_test_data = {fill}
[output]
directory = "{out}"
"#,
                url = server.url("/"),
                out = output_dir.display()
            ),
        )
        .unwrap();
        let output = Command::new(brokenapp_bin())
            .args(["scan", "--json", "--config", config.to_str().unwrap()])
            .env_remove("BROKENAPP_MAX_CONCURRENT_TABS")
            .output()
            .unwrap();
        if let Some(dir) = std::env::var_os("BROKENAPP_FORM_RECOVERY_ARTIFACT_DIR") {
            let case = PathBuf::from(dir).join(format!("{mode}-tabs-{tabs}-fill-{fill}"));
            fs::create_dir_all(&case).unwrap();
            for name in [
                "spec.json",
                "interactions.jsonl",
                "network.jsonl",
                "scan-run.json",
            ] {
                if output_dir.join(name).exists() {
                    fs::copy(output_dir.join(name), case.join(name)).unwrap();
                }
            }
            fs::write(case.join("stdout.json"), &output.stdout).unwrap();
            fs::write(case.join("stderr.log"), &output.stderr).unwrap();
            fs::copy(&config, case.join("brokenapp.toml")).unwrap();
            fs::write(
                case.join("server-requests.json"),
                serde_json::to_vec_pretty(&server.requests()).unwrap(),
            )
            .unwrap();
        }
        assert!(
            output.status.success(),
            "{mode}/{tabs}/{fill}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rows = read_jsonl(&output_dir.join("interactions.jsonl"));
        let network = read_jsonl(&output_dir.join("network.jsonl"));
        let writes: Vec<_> = network
            .iter()
            .filter(|r| r.pointer("/request/method").and_then(Value::as_str) == Some("POST"))
            .collect();
        assert!(
            server.requests().iter().all(|r| r.starts_with("GET ")),
            "write reached backend"
        );
        if !fill {
            assert!(writes.is_empty());
            assert!(
                !rows
                    .iter()
                    .any(|r| matches!(str_field(r, "action"), "type" | "recover_type"))
            );
            continue;
        }
        if matches!(
            mode,
            "unsupported" | "missing" | "budget" | "missing-option" | "disabled-option"
        ) {
            let reason = match mode {
                "unsupported" => "form_state_recovery_unsupported",
                "budget" => "form_state_recovery_interaction_limit",
                _ => "form_state_recovery_target_changed",
            };
            assert!(writes.is_empty(), "unsafe recovery submitted");
            for path in ["/a", "/b"] {
                assert!(
                    rows.iter()
                        .any(|r| str_field(r, "label") == format!("Sign in {path}")
                            && str_field(r, "skipped_reason") == reason),
                    "{mode}: missing explicit submit gap on {path}"
                );
            }
            continue;
        }
        for path in ["/a", "/b"] {
            let submit = rows
                .iter()
                .find(|r| {
                    str_field(r, "label") == format!("Sign in {path}")
                        && matches!(str_field(r, "action"), "click" | "submit")
                })
                .expect("submit action");
            let view = str_field(submit, "view_id");
            let reset = rows
                .iter()
                .find(|r| {
                    str_field(r, "label") == format!("Reset state {path}")
                        && str_field(r, "action") == "click"
                })
                .expect("reset action");
            if mode == "reload" {
                assert_eq!(str_field(reset, "retest"), "confirmed_no_effect");
            }
            for label in ["Email", "Password"] {
                let original = rows
                    .iter()
                    .find(|r| {
                        str_field(r, "view_id") == view
                            && str_field(r, "label") == label
                            && str_field(r, "action") == "type"
                    })
                    .expect("local original typing");
                let recovery = rows
                    .iter()
                    .find(|r| {
                        str_field(r, "view_id") == view
                            && str_field(r, "label") == label
                            && str_field(r, "action") == "recover_type"
                    })
                    .expect("local recovery typing");
                assert_ne!(
                    str_field(original, "action_id"),
                    str_field(recovery, "action_id")
                );
                assert_ne!(
                    str_field(reset, "action_id"),
                    str_field(recovery, "action_id")
                );
                assert!(str_field(original, "started_at") <= str_field(recovery, "started_at"));
                assert!(str_field(recovery, "started_at") <= str_field(submit, "started_at"));
                assert!(recovery.get("retest").is_none());
            }
            if matches!(mode, "native" | "retained") {
                for label in ["Choice", "Agree", "Radio A", "Radio B"] {
                    let recovery = rows
                        .iter()
                        .find(|r| {
                            str_field(r, "view_id") == view
                                && str_field(r, "label") == label
                                && str_field(r, "action") == "recover_value"
                        })
                        .expect("native recovery record");
                    assert_ne!(
                        str_field(recovery, "action_id"),
                        str_field(reset, "action_id")
                    );
                    assert!(str_field(recovery, "started_at") <= str_field(submit, "started_at"));
                    assert!(recovery.get("retest").is_none());
                    if mode == "retained" {
                        assert_eq!(
                            str_field(recovery, "outcome"),
                            "no_effect",
                            "retained native value was changed"
                        );
                        assert!(
                            str_field(recovery, "page_url").ends_with(&format!("{path}#/base"))
                        );
                    }
                }
                if mode == "retained" {
                    assert!(str_field(submit, "page_url").ends_with(&format!("{path}#/base")));
                }
            }
            let write = writes
                .iter()
                .find(|r| {
                    r.pointer("/trace/action_id").and_then(Value::as_str)
                        == Some(str_field(submit, "action_id"))
                })
                .expect("submit action guarded POST");
            assert_eq!(str_field(write, "write_guard"), "blocked");
            assert_eq!(
                write.pointer("/triggered_by/view").and_then(Value::as_str),
                Some(view)
            );
            assert_eq!(
                write
                    .pointer("/triggered_by/selector")
                    .and_then(Value::as_str),
                Some(str_field(submit, "selector"))
            );
            assert!(write.get("response").is_none());
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let inv = runtime
            .block_on(brokenapp::inventory::build_from_scan_dir(
                &output_dir,
                &brokenapp::inventory::BuildOptions {
                    project: "form-recovery".into(),
                    target_url: server.url("/"),
                    write_guard: "block".into(),
                    ..Default::default()
                },
            ))
            .unwrap();
        if let Some(dir) = std::env::var_os("BROKENAPP_FORM_RECOVERY_ARTIFACT_DIR") {
            let case = PathBuf::from(dir).join(format!("{mode}-tabs-{tabs}-fill-{fill}"));
            fs::write(
                case.join("inventory.json"),
                serde_json::to_vec_pretty(&inv).unwrap(),
            )
            .unwrap();
        }
        let labels: &[&str] = if matches!(mode, "native" | "retained") {
            &["Email", "Password", "Choice", "Agree", "Radio A", "Radio B"]
        } else {
            &["Email", "Password"]
        };
        for path in ["/a", "/b"] {
            let route = if mode == "retained" {
                format!("{path}/#/base")
            } else {
                path.to_string()
            };
            for label in labels {
                assert_eq!(
                    inv.controls
                        .iter()
                        .filter(|c| c.label == *label
                            && (c.route == route
                                || (c.route == "*"
                                    && c.routes.iter().any(|covered| covered == &route))))
                        .count(),
                    1,
                    "recovery created a new control"
                );
            }
            let reset = inv
                .controls
                .iter()
                .find(|c| c.label == format!("Reset state {path}"))
                .unwrap();
            assert!(
                !serde_json::to_string(reset)
                    .unwrap()
                    .contains("POST /api/sign-in"),
                "recovery/submit credited to reset"
            );
        }
    }
}
