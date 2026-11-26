//! Front-door CLI regressions from the UI-map field tests:
//!
//! - `init` never writes secret values from `--dev-cmd` into config.toml: it
//!   moves them to `dev_env` `env:` references or refuses, without echoing
//!   the value;
//! - `map --json` always reports exit code, scan dir, inventory, counts by
//!   status, coverage, changes and warnings; it warms seeded routes first
//!   (reporting failures), never seeds error pages (`404.astro`) or sign-out
//!   pages, and passes dynamic route templates and crawl knobs to the scan;
//! - `map --changed` re-crawls only the page whose file changed, merges it
//!   into the latest map with the same change lines a full re-map reports,
//!   and skips the scan when nothing UI-related changed;
//! - roles: `roles add` keeps values out of config.toml (credentials.toml,
//!   mode 0600), `map` maps anonymous + every role into its own map, reports
//!   a wrong password as `login_failed` and skips that role, writes
//!   ROLE-ACCESS.md / role-access.tsv, and never prints or writes a value;
//!   read commands take `--role`;
//! - full mode emits no caps; an interrupted run continues with `map --resume`.

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
    time::Duration,
};

use serde_json::Value;

fn brokenapp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brokenapp")
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-front")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create fixture copy");
    for entry in fs::read_dir(from).expect("read fixture dir") {
        let entry = entry.expect("fixture entry");
        let dest = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), &dest).expect("copy fixture file");
        }
    }
}

const SECRET: &str = "postgres://app:hunter2-front@localhost:5432/app";

#[test]
fn init_moves_exported_secrets_and_refuses_unexported_ones() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    copy_tree(&fixture_root(), &repo);
    let home = tmp.path().join("home");
    let dev_cmd = format!(
        "DATABASE_URL={SECRET} NEXT_TELEMETRY_DISABLED=1 PORT=47391 npm run dev -- --port $PORT"
    );
    let init = |db_env: Option<&str>| {
        let mut cmd = Command::new(brokenapp_bin());
        cmd.args([
            "init",
            "--url",
            "http://127.0.0.1:47391",
            "--dev-cmd",
            &dev_cmd,
            "--agent",
            "none",
            "--json",
        ])
        .current_dir(&repo)
        .env("BROKENAPP_HOME", &home)
        .env("BROKENAPP_NO_BANNER", "1")
        .env_remove("DATABASE_URL")
        .env_remove("BROKENAPP_STATE_DIR");
        if let Some(v) = db_env {
            cmd.env("DATABASE_URL", v);
        }
        cmd.output().expect("run brokenapp init")
    };
    let config = repo.join(".brokenapp/config.toml");

    // Not exported: refuse, write nothing, never echo the value.
    let out = init(None);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "init must refuse: {stdout}{stderr}");
    assert!(stderr.contains("DATABASE_URL"), "{stderr}");
    assert!(stderr.contains("export DATABASE_URL=..."), "{stderr}");
    assert!(!stderr.contains("hunter2") && !stdout.contains("hunter2"));
    assert!(!config.exists(), "nothing written on refusal");
    assert!(!home.join("registry.json").exists());

    // Exported with a different value: refuse rather than guess.
    let out = init(Some("postgres://other@localhost/x"));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("different value"));
    assert!(!config.exists());

    // Exported with the same value: moved to an env: reference.
    let out = init(Some(SECRET));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_str(&stdout).expect("init --json report");
    assert_eq!(
        report["moved_to_dev_env"],
        serde_json::json!(["DATABASE_URL"])
    );
    assert_eq!(
        report["dev_cmd"],
        "NEXT_TELEMETRY_DISABLED=1 PORT=47391 npm run dev -- --port $PORT"
    );
    assert!(
        report["next"]
            .as_str()
            .is_some_and(|n| n.starts_with("brokenapp map ") && !n.contains("--quick")),
        "first map should be a full map: {report}"
    );
    let raw = fs::read_to_string(&config).expect("config written");
    assert!(!raw.contains("hunter2"), "{raw}");
    assert!(raw.contains("DATABASE_URL = \"env:DATABASE_URL\""), "{raw}");
    assert!(
        raw.contains(
            "dev_cmd = \"NEXT_TELEMETRY_DISABLED=1 PORT=47391 npm run dev -- --port $PORT\""
        ),
        "{raw}"
    );
    assert!(!stdout.contains("hunter2"));
}

/// Serves a four-page site and records `METHOD path user-agent` per request.
struct SiteServer {
    addr: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl SiteServer {
    fn start() -> Self {
        Self::start_with_nav_source(None)
    }

    fn start_with_nav_source(nav_source: Option<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind site server");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stop_t, requests_t) = (Arc::clone(&stop), Arc::clone(&requests));
        let handle = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = Arc::clone(&requests_t);
                        thread::spawn(move || serve(stream, &requests, nav_source));
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

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl Drop for SiteServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><title>{title}</title></head><body>\
         <nav><a href=\"/\">Home</a> <a href=\"/about\">About</a> \
         <a href=\"/towns/springfield\">Springfield</a></nav>\
         <main><h1>{title}</h1>{body}</main></body></html>"
    )
}

fn serve(mut stream: TcpStream, requests: &Mutex<Vec<String>>, nav_source: Option<&str>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let agent = head
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_default();
    if method.is_empty() {
        // A bare TCP connect (preconnect or reachability check), no request.
        return;
    }
    requests
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(format!("{method} {path} {agent}"));
    let route = path.split('?').next().unwrap_or("/");
    let (status, body) = match route {
        "/" => (
            "200 OK",
            page(
                "Home",
                "<button id=\"noop\" type=\"button\">Do nothing</button>\
                 <button id=\"toggle\" type=\"button\" \
                 onclick=\"document.getElementById('panel').hidden=false\">Show details</button>\
                 <div id=\"panel\" hidden>Details</div>",
            ),
        ),
        "/about" => ("200 OK", page("About", "<p>About us</p>")),
        "/towns/springfield" => ("200 OK", page("Springfield", "<p>Town</p>")),
        "/boom" => (
            "500 Internal Server Error",
            page("Error", "<p>Server error</p>"),
        ),
        _ => ("404 Not Found", page("Not found", "<p>Missing</p>")),
    };
    let body = if let Some(source) = nav_source {
        body.replace(
            "<a ",
            &format!("<a data-astro-source-file=\"{source}\" data-astro-source-loc=\"1:1\" "),
        )
    } else {
        body
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn chrome_available() -> bool {
    brokenapp::browser::BrowserManager::detect_chrome_executable().is_some()
}

#[test]
fn map_json_reports_contract_warmup_and_seed_hygiene() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping map --json e2e: Chrome/Chromium not detected");
        return;
    }
    let server = SiteServer::start();
    let tmp = tempfile::tempdir().expect("tempdir");
    let codebase = tmp.path().join("app");
    copy_tree(&fixture_root(), &codebase);
    let state = tmp.path().join("state/.brokenapp");
    fs::create_dir_all(&state).expect("state dir");
    fs::write(
        state.join("config.toml"),
        format!(
            r#"[project]
name = "front-fixture"
url = "{url}"
codebase = "{codebase}"

[scan]
max_minutes = 2
max_views = 10
extra_routes = ["/boom"]
settle_ms = 300
max_interactions_per_view = 10
"#,
            url = server.url(),
            codebase = codebase.display()
        ),
    )
    .expect("write project config");

    let output = Command::new(brokenapp_bin())
        .args(["map", "--json", "--state-dir"])
        .arg(&state)
        .env("BROKENAPP_HOME", tmp.path().join("home"))
        .env("BROKENAPP_NO_BANNER", "1")
        .env_remove("BROKENAPP_TELEMETRY_PATH")
        .output()
        .expect("run brokenapp map");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "map failed:\n{stdout}\n{stderr}");
    let report: Value = serde_json::from_str(&stdout).expect("map --json is one JSON object");

    // Contract fields.
    assert_eq!(report["exit_code"], 0, "{report:#}");
    assert_eq!(report["status"], "ok");
    let scan_dir = PathBuf::from(report["scan_dir"].as_str().expect("scan_dir"));
    assert!(scan_dir.join("interactions.jsonl").is_file(), "{report:#}");
    assert!(Path::new(report["inventory"].as_str().expect("inventory")).is_file());
    assert!(report["status_counts"].is_object());
    assert!(report["coverage"]["routes_visited"].as_u64().unwrap_or(0) >= 2);
    assert!(report["exercisable"]["exercisable"].as_u64().is_some());
    assert_eq!(report["changes"]["first_map"], true);
    let warnings: Vec<&str> = report["warnings"]
        .as_array()
        .expect("warnings[] always present")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    // Warm-up ran before the crawl and reported the failing seed.
    assert_eq!(
        report["warmup"]["failed"][0]["route"], "/boom",
        "{report:#}"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.starts_with("route warm-up") && w.contains("/boom (HTTP 500)")),
        "{warnings:?}"
    );
    let requests = server.requests();
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("GET /about ") && r.contains("brokenapp-map-warmup")),
        "{requests:#?}"
    );

    // Seed hygiene: no error page, no sign-out page; templates and knobs reach the scan.
    let run_dir = scan_dir.parent().expect("run dir");
    let seeds = fs::read_to_string(run_dir.join("seed-routes.txt")).expect("seed file");
    let seeds: Vec<&str> = seeds.lines().filter(|l| !l.starts_with('#')).collect();
    assert!(seeds.contains(&"/") && seeds.contains(&"/about") && seeds.contains(&"/boom"));
    assert!(
        !seeds
            .iter()
            .any(|s| s.contains("404") || s.contains("logout")),
        "{seeds:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("skipped seeds") && w.contains("/logout")),
        "{warnings:?}"
    );
    assert!(
        !requests.iter().any(|r| r.contains("/logout")),
        "sign-out page requested: {requests:#?}"
    );
    let scan_toml = fs::read_to_string(run_dir.join("scan.toml")).expect("scan.toml");
    assert!(
        scan_toml.contains("route_templates = [\"/towns/:slug\"]"),
        "{scan_toml}"
    );
    assert!(scan_toml.contains("settle_timeout_ms = 300"), "{scan_toml}");
    assert!(
        scan_toml.contains("max_interactions_per_view = 10"),
        "{scan_toml}"
    );
    assert_eq!(report["scan"]["route_templates"], 1);

    // The inventory never lists the 404 page as a route (it used to be `/:id`).
    let inventory: Value =
        serde_json::from_str(&fs::read_to_string(report["inventory"].as_str().unwrap()).unwrap())
            .expect("inventory json");
    let routes: Vec<&str> = inventory["routes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["route"].as_str())
        .collect();
    assert!(
        !routes.contains(&"/:id") && !routes.contains(&"/404"),
        "{routes:?}"
    );

    // Write guard and telemetry stay inside the run.
    assert!(
        requests
            .iter()
            .all(|r| r.starts_with("GET ") || r.starts_with("HEAD ")),
        "{requests:#?}"
    );
    assert!(
        !codebase.join(".brokenapp").exists(),
        "scan wrote into the codebase"
    );
    // Progress lines count routes and controls, not raw endpoints.
    for line in stderr
        .lines()
        .filter(|l| l.trim_start().starts_with("scanning:"))
    {
        assert!(
            line.contains("routes visited") && line.contains("controls exercised"),
            "{line}"
        );
    }
}

/// Serves `<root>/public/<path>/index.html`, re-read on every request.
struct StaticServer {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl StaticServer {
    fn start(root: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind static server");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let (stop_t, public) = (Arc::clone(&stop), root.join("public"));
        let handle = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let public = public.clone();
                        thread::spawn(move || serve_static(stream, &public));
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

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

impl Drop for StaticServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve_static(mut stream: TcpStream, public: &Path) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    if parts.next().is_none() {
        return;
    }
    let path = parts.next().unwrap_or("/");
    let route = path
        .split(['?', '#'])
        .next()
        .unwrap_or("/")
        .trim_matches('/');
    let file = if route.is_empty() {
        public.join("index.html")
    } else if route
        .split('/')
        .all(|s| !s.is_empty() && s != ".." && s != ".")
    {
        public.join(route).join("index.html")
    } else {
        public.join("missing")
    };
    let (status, body) = match fs::read_to_string(&file) {
        Ok(body) => ("200 OK", body),
        Err(_) => (
            "404 Not Found",
            "<!doctype html><title>Not found</title>".to_string(),
        ),
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// Backdate every file so the first map's start time is after them.
fn backdate(dir: &Path) {
    let past = std::time::SystemTime::now() - Duration::from_secs(3600);
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            backdate(&path);
        } else {
            fs::File::options()
                .write(true)
                .open(&path)
                .and_then(|f| f.set_modified(past))
                .expect("backdate fixture file");
        }
    }
}

fn run_map(state: &Path, home: &Path, extra: &[&str]) -> Value {
    let output = Command::new(brokenapp_bin())
        .args(["map", "--json", "--state-dir"])
        .arg(state)
        .args(extra)
        .env("BROKENAPP_HOME", home)
        .env("BROKENAPP_NO_BANNER", "1")
        .env_remove("BROKENAPP_TELEMETRY_PATH")
        .output()
        .expect("run brokenapp map");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "map {extra:?} failed:\n{stdout}\n{stderr}"
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("map --json: {e}\n{stdout}\n{stderr}"))
}

#[test]
fn map_exclusions_cover_linked_routes_and_remain_role_local() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping exclusion e2e: Chrome/Chromium not detected");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let codebase = tmp.path().join("app");
    copy_tree(&fixture_root(), &codebase);
    // The server renders shared navigation on every route. Give those links
    // their actual shared source instead of allowing the label "About" to
    // match the about page's heading and make an about edit app-wide.
    fs::create_dir_all(codebase.join("src/components")).unwrap();
    fs::write(
        codebase.join("src/components/Nav.astro"),
        "<nav><a href=\"/\">Home</a> <a href=\"/about\">About</a> <a href=\"/towns/springfield\">Springfield</a></nav>\n",
    )
    .unwrap();
    let server = SiteServer::start_with_nav_source(Some("src/components/Nav.astro"));
    backdate(&codebase);
    let state = tmp.path().join("state/.brokenapp");
    let home = tmp.path().join("home");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        state.join("config.toml"),
        format!(
            r#"[project]
name = "exclusion-fixture"
url = "{}"
codebase = "{}"
[scan]
tabs = 1
settle_ms = 200
max_minutes = 2
max_views = 10
exclude_routes = ["/towns", "/logout"]
[[roles]]
name = "viewer"
method = "cookie"
cookie = "env:EXCLUSION_FIXTURE_COOKIE"
exclude_routes = ["/about"]
"#,
            server.url(),
            codebase.display()
        ),
    )
    .unwrap();
    let run = |extra: &[&str]| {
        let output = brokenapp(
            &["map", "--json", "--state-dir", state.to_str().unwrap()],
            &home,
        )
        .args(extra)
        .env("EXCLUSION_FIXTURE_COOKIE", "fixture_viewer=synthetic")
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    let load = |report: &Value| -> brokenapp::inventory::Inventory {
        brokenapp::inventory::load(Path::new(report["inventory"].as_str().unwrap())).unwrap()
    };
    let assert_no_towns = |requests: &[String]| {
        assert!(
            !requests.iter().any(|r| r
                .split_whitespace()
                .nth(1)
                .is_some_and(|p| p.starts_with("/towns"))),
            "excluded target requested by crawl/warmup/link probe: {requests:#?}"
        );
    };
    // Source seeds and an ordinary visible href both point at /towns.
    let anon = run(&["--roles", "none"]);
    let inv = load(&anon);
    assert!(inv.routes.iter().any(|r| r.route == "/about" && r.visited));
    assert!(!inv.routes.iter().any(|r| r.route.starts_with("/towns")));
    assert_eq!(inv.coverage.routes_known, 2);
    assert_no_towns(&server.requests());
    let about = inv
        .controls
        .iter()
        .find(|c| c.route == "/" && c.label == "About")
        .unwrap();
    let source = about.source.as_ref().unwrap();
    assert_eq!(source.method, "annotation");
    assert_eq!(source.confidence, "exact");
    assert_eq!(
        source.render.as_ref().unwrap().file,
        "src/components/Nav.astro"
    );
    let town = inv
        .controls
        .iter()
        .find(|c| c.label == "Springfield")
        .unwrap();
    assert_eq!(town.status, brokenapp::inventory::ControlStatus::Skipped);
    assert_eq!(town.reason.as_deref(), Some("route_excluded"));

    // A harmless synthetic cookie exercises separate role configuration; this
    // fixture is public and makes no authenticated access claim.
    server.requests.lock().unwrap().clear();
    let role = run(&["--role", "viewer", "--full"]);
    let role_inv = load(&role);
    assert_eq!(role_inv.role.as_deref(), Some("viewer"));
    assert!(
        !role_inv
            .routes
            .iter()
            .any(|r| r.route == "/about" || r.route.starts_with("/towns"))
    );
    assert_eq!(role_inv.coverage.routes_known, 1);
    let requests = server.requests();
    assert_no_towns(&requests);
    assert!(
        !requests
            .iter()
            .any(|r| r.split_whitespace().nth(1) == Some("/about")),
        "role exclusion leaked: {requests:#?}"
    );

    // Incremental scope keeps the project exclusions and does not inherit the
    // viewer's /about exclusion when returning to anonymous.
    server.requests.lock().unwrap().clear();
    fs::write(
        codebase.join("src/pages/about.astro"),
        "<h1>About updated</h1>\n",
    )
    .unwrap();
    let incremental = run(&["--roles", "none", "--changed"]);
    assert_eq!(incremental["mode"], "incremental", "{incremental:#}");
    assert_eq!(
        incremental["recrawled_routes"],
        serde_json::json!(["/about"])
    );
    let updated = load(&incremental);
    assert!(
        updated
            .routes
            .iter()
            .any(|r| r.route == "/about" && r.visited)
    );
    assert!(!updated.routes.iter().any(|r| r.route.starts_with("/towns")));
    assert_no_towns(&server.requests());
}

fn change_lines(report: &Value) -> Vec<String> {
    report["changes"]["lines"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

#[test]
fn front_cli_map_changed_recrawls_only_the_edited_page() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping map --changed e2e: Chrome/Chromium not detected");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let codebase = tmp.path().join("site");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-incremental"),
        &codebase,
    );
    backdate(&codebase);
    let server = StaticServer::start(&codebase);
    let home = tmp.path().join("home");
    let state = tmp.path().join("state/.brokenapp");
    fs::create_dir_all(&state).expect("state dir");
    fs::write(
        state.join("config.toml"),
        format!(
            r#"[project]
name = "incremental-fixture"
url = "{url}"
codebase = "{codebase}"

[scan]
max_minutes = 2
max_views = 12
settle_ms = 300
tabs = 1
"#,
            url = server.url(),
            codebase = codebase.display()
        ),
    )
    .expect("write project config");

    // 1. Full map: four pages, header links are global controls.
    let first = run_map(&state, &home, &[]);
    assert_eq!(first["coverage"]["routes_visited"], 4, "{first:#}");
    assert_eq!(first["changes"]["first_map"], true);
    assert_eq!(first["tabs"], 1);
    let scan_toml = fs::read_to_string(
        Path::new(first["scan_dir"].as_str().unwrap())
            .parent()
            .unwrap()
            .join("scan.toml"),
    )
    .unwrap();
    assert!(scan_toml.contains("max_concurrent_tabs = 1"), "{scan_toml}");
    // A copy of the state to compare against a full re-map later.
    let full_state = tmp.path().join("state-full/.brokenapp");
    copy_tree(&state, &full_state);

    // 2. Nothing changed: no scan.
    let skipped = run_map(&state, &home, &["--changed"]);
    assert_eq!(skipped["mode"], "skipped", "{skipped:#}");
    assert!(skipped.get("scan_dir").is_none());

    // 3. Edit /about's button: new label, and it no longer does anything.
    let about = codebase.join("public/about/index.html");
    let html = fs::read_to_string(&about).unwrap().replace(
        "<button id=\"book\" type=\"button\" onclick=\"document.getElementById('book-panel').hidden=false\">Book a call</button>",
        "<button id=\"book\" type=\"button\">Book now</button>",
    );
    assert!(html.contains("Book now"));
    fs::write(&about, html).unwrap();

    let inc = run_map(&state, &home, &["--changed"]);
    assert_eq!(inc["mode"], "incremental", "{inc:#}");
    assert_eq!(
        inc["changed_files"],
        serde_json::json!(["public/about/index.html"])
    );
    assert_eq!(inc["affected_routes"][0]["route"], "/about", "{inc:#}");
    assert!(
        inc["affected_routes"][0]["reasons"]
            .as_array()
            .is_some_and(|r| r
                .iter()
                .any(|r| r == "route file changed: public/about/index.html")),
        "{inc:#}"
    );
    assert_eq!(inc["affected_routes"].as_array().map(Vec::len), Some(1));
    assert_eq!(inc["recrawled_routes"], serde_json::json!(["/about"]));
    assert!(inc["timings"]["analysis_ms"].is_u64() && inc["timings"]["total_ms"].is_u64());
    // The re-crawl was scoped to /about and seeded with it alone.
    let run_dir = Path::new(inc["scan_dir"].as_str().unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let seeds = fs::read_to_string(run_dir.join("seed-routes.txt")).unwrap();
    let seeds: Vec<&str> = seeds.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(seeds, vec!["/about"]);
    let scopes = fs::read_to_string(run_dir.join("scopes.toml")).unwrap();
    assert!(scopes.contains("routes = [\"/about\"]"), "{scopes}");
    // The merged map still covers the whole app.
    assert_eq!(inc["coverage"]["routes_visited"], 4, "{inc:#}");

    // Only /about changed, and the lines match a full re-map of the edit.
    let lines = change_lines(&inc);
    assert!(!lines.is_empty(), "{inc:#}");
    for line in &lines {
        assert!(line.contains("/about"), "change outside /about: {line}");
    }
    assert!(
        lines.iter().any(|l| l.contains("\"Book now\"")),
        "{lines:#?}"
    );
    let full = run_map(&full_state, &home, &[]);
    assert_eq!(lines, change_lines(&full), "incremental vs full re-map");

    // The changelog entry says it was incremental and lists only /about.
    let changelog = fs::read_to_string(state.join("map/CHANGELOG.md")).unwrap();
    let entry = changelog.split("\n## ").nth(1).expect("a changelog entry");
    assert!(
        entry
            .lines()
            .next()
            .unwrap_or_default()
            .contains("incremental: re-crawled 1 route (changed: public/about/index.html)"),
        "{entry}"
    );
    for line in entry.lines().filter(|l| l.starts_with("- ")) {
        assert!(line.contains("/about"), "{line}");
    }
    let latest: Value = serde_json::from_str(
        &fs::read_to_string(state.join("history/latest.inventory.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        latest["incremental"]["routes"],
        serde_json::json!(["/about"])
    );
    assert!(latest["route_scans"]["/contact"]["scanned_at"].is_string());

    // 4. A docs-only change maps to no route.
    fs::write(codebase.join("README.md"), "Docs only.\n").unwrap();
    let docs = run_map(&state, &home, &["--changed"]);
    assert_eq!(docs["mode"], "skipped", "{docs:#}");
    assert_eq!(
        docs["message"],
        "no UI routes affected by 1 changed file; the map is unchanged"
    );
    assert_eq!(docs["unmapped_files"][0]["file"], "README.md");
    assert_eq!(docs["unmapped_files"][0]["kind"], "docs");

    // 5. The docs change is still pending; a page edit maps, and the
    //    changelog heading names only the file that selected the route.
    let pricing = codebase.join("public/pricing/index.html");
    let html = fs::read_to_string(&pricing)
        .unwrap()
        .replace(">Compare plans<", ">Compare all plans<");
    fs::write(&pricing, html).unwrap();
    let next = run_map(&state, &home, &["--changed"]);
    assert_eq!(next["mode"], "incremental", "{next:#}");
    assert_eq!(
        next["changed_files"],
        serde_json::json!(["README.md", "public/pricing/index.html"])
    );
    assert_eq!(next["recrawled_routes"], serde_json::json!(["/pricing"]));
    let changelog = fs::read_to_string(state.join("map/CHANGELOG.md")).unwrap();
    let heading = changelog
        .split("\n## ")
        .nth(1)
        .and_then(|e| e.lines().next())
        .unwrap_or_default();
    assert!(
        heading.ends_with("incremental: re-crawled 1 route (changed: public/pricing/index.html)"),
        "{heading}"
    );
    for line in change_lines(&next) {
        assert!(line.contains("/pricing"), "{line}");
    }
    assert!(
        !codebase.join(".brokenapp").exists(),
        "scan wrote into the codebase"
    );
}

// ---------------------------------------------------------------------------
// Roles, full mode, resume (fixture: tests/fixtures/ui-map-roles-front/)
// ---------------------------------------------------------------------------

fn roles_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-roles-front")
}

/// The fixture's throwaway users (they exist only inside [`RolesServer`]).
struct FixtureUsers {
    user: (String, String),
    admin: (String, String),
    wrong_password: String,
}

fn fixture_users() -> FixtureUsers {
    let raw = fs::read_to_string(roles_fixture().join("users.json")).expect("users.json");
    let v: Value = serde_json::from_str(&raw).expect("users.json is JSON");
    let find = |role: &str| {
        let u = v["users"]
            .as_array()
            .and_then(|a| a.iter().find(|u| u["role"] == role))
            .unwrap_or_else(|| panic!("fixture user {role}"));
        (
            u["email"].as_str().unwrap().to_string(),
            u["password"].as_str().unwrap().to_string(),
        )
    };
    FixtureUsers {
        user: find("user"),
        admin: find("admin"),
        wrong_password: v["wrong_password"].as_str().unwrap().to_string(),
    }
}

/// A free port of the range reserved for these fixtures (47290-47299).
fn fixture_listener() -> TcpListener {
    (47290..=47299)
        .find_map(|p| TcpListener::bind(("127.0.0.1", p)).ok())
        .expect("a free port in 47290-47299")
}

/// Multi-role app: form login with sessions, user/admin-only pages, a 403
/// page, a sign-out page, and slow pages for the resume test.
struct RolesServer {
    addr: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct RolesState {
    sessions: std::collections::HashMap<String, &'static str>,
    next: u64,
}

impl RolesServer {
    fn start(slow_pages: usize) -> Self {
        let listener = fixture_listener();
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr").to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(RolesState::default()));
        let users = Arc::new(fixture_users());
        let (stop_t, requests_t) = (Arc::clone(&stop), Arc::clone(&requests));
        let handle = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (requests, state, users) = (
                            Arc::clone(&requests_t),
                            Arc::clone(&state),
                            Arc::clone(&users),
                        );
                        thread::spawn(move || {
                            serve_roles(stream, &requests, &state, &users, slow_pages)
                        });
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

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl Drop for RolesServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn roles_page(title: &str, role: Option<&str>, body: &str) -> String {
    let mut nav = String::from("<a href=\"/\">Home</a>");
    match role {
        None => nav.push_str(" <a href=\"/login\">Sign in</a>"),
        Some(r) => {
            nav.push_str(" <a href=\"/dashboard\">Dashboard</a> <a href=\"/reports\">Reports</a>");
            if r == "admin" {
                nav.push_str(" <a href=\"/admin\">Admin</a>");
            }
            nav.push_str(" <a href=\"/logout\">Log out</a>");
        }
    }
    format!(
        "<!doctype html><html><head><title>{title}</title></head><body>\
         <nav>{nav}</nav><main><h1>{title}</h1>{body}</main></body></html>"
    )
}

fn login_form(error: bool) -> String {
    format!(
        "{}<form method=\"post\" action=\"/login\">\
         <label>Email <input type=\"email\" name=\"email\" autocomplete=\"username\"></label>\
         <label>Password <input type=\"password\" name=\"password\"></label>\
         <button type=\"submit\">Sign in</button></form>",
        if error {
            "<p role=\"alert\">Invalid email or password</p>"
        } else {
            ""
        }
    )
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 2;
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn serve_roles(
    mut stream: TcpStream,
    requests: &Mutex<Vec<String>>,
    state: &Mutex<RolesState>,
    users: &FixtureUsers,
    slow_pages: usize,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65536 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let header = |name: &str| {
        head.lines().find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_string())
        })
    };
    let len: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + len {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[header_end..]).to_string();
    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();
    requests
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(format!("{method} {path}"));
    let sid = header("cookie").and_then(|c| {
        c.split(';')
            .filter_map(|kv| kv.trim().split_once('='))
            .find(|(k, _)| *k == "sid")
            .map(|(_, v)| v.to_string())
    });
    let role: Option<&'static str> = sid.as_ref().and_then(|s| {
        state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .sessions
            .get(s)
            .copied()
    });
    let route = path.split('?').next().unwrap_or("/").to_string();
    let redirect = |to: &str, cookie: Option<String>| {
        (
            "302 Found".to_string(),
            format!(
                "Location: {to}\r\n{}",
                cookie
                    .map(|c| format!("Set-Cookie: {c}\r\n"))
                    .unwrap_or_default()
            ),
            String::new(),
        )
    };
    let ok = |html: String| ("200 OK".to_string(), String::new(), html);
    let (status, extra, html) = match (method.as_str(), route.as_str()) {
        ("GET", "/") => ok(roles_page(
            "Home",
            role,
            "<p>Welcome</p><button id=\"more\" type=\"button\" \
             onclick=\"document.getElementById('more-info').hidden=false\">Show more</button>\
             <div id=\"more-info\" hidden>More</div>",
        )),
        ("GET", "/login") if role.is_some() => redirect("/dashboard", None),
        ("GET", "/login") => ok(roles_page("Sign in", None, &login_form(false))),
        ("GET", "/js-login") => ok(roles_page(
            "JavaScript sign in",
            None,
            &format!(
                "{}{}",
                login_form(false).replace("action=\"/login\"", "action=\"/js-login\""),
                r#"<script>
                document.querySelector('form').addEventListener('submit', async (event) => {
                    event.preventDefault();
                    try {
                        const response = await fetch('/api/custom-sign-in?flow=login', {
                            method: 'POST', body: new URLSearchParams(new FormData(event.target))
                        });
                        if (response.ok) location.assign('/js-dashboard');
                    } catch (_) {}
                });
                </script>"#,
            ),
        )),
        ("POST", "/login" | "/api/custom-sign-in") => {
            let form: std::collections::HashMap<String, String> = body
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (url_decode(k), url_decode(v)))
                .collect();
            let email = form.get("email").cloned().unwrap_or_default();
            let password = form.get("password").cloned().unwrap_or_default();
            let who = if (email.clone(), password.clone()) == users.admin {
                Some("admin")
            } else if (email, password) == users.user {
                Some("user")
            } else {
                None
            };
            match who {
                Some(r) => {
                    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                    st.next += 1;
                    let sid = format!("s{}-{r}", st.next);
                    st.sessions.insert(sid.clone(), r);
                    if route == "/api/custom-sign-in" {
                        (
                            "200 OK".to_string(),
                            format!("Set-Cookie: sid={sid}; Path=/; HttpOnly\r\n"),
                            "signed in".to_string(),
                        )
                    } else {
                        (
                            "303 See Other".to_string(),
                            format!(
                                "Location: /dashboard\r\nSet-Cookie: sid={sid}; Path=/; HttpOnly\r\n"
                            ),
                            String::new(),
                        )
                    }
                }
                None => ok(roles_page("Sign in", None, &login_form(true))),
            }
        }
        ("GET", "/js-dashboard") if role.is_none() => redirect("/js-login", None),
        ("GET", "/js-dashboard") => ok(roles_page(
            "JavaScript dashboard",
            role,
            r#"<script>
            Promise.allSettled([
                fetch('/api/custom-sign-in?flow=other', {method: 'POST', body: 'other'}),
                fetch('/api/custom-sign-in?flow=login', {method: 'DELETE'}),
                fetch('/api/autosave', {method: 'POST', body: 'save'}),
                fetch('/graphql', {method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({query: 'mutation { eraseAll }'})})
            ]).then(() => fetch('/guard-probes-finished'));
            </script>"#,
        )),
        ("GET", "/guard-probes-finished") => ok("probes finished".to_string()),
        ("GET", "/logout") => {
            if let Some(s) = &sid {
                state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .sessions
                    .remove(s);
            }
            redirect("/", Some("sid=; Path=/; Max-Age=0".to_string()))
        }
        ("GET", "/dashboard") if role.is_none() => redirect("/login?next=/dashboard", None),
        ("GET", "/dashboard") => {
            let mut body = String::from(
                "<h2>Team</h2><button id=\"refresh\" type=\"button\" \
                 onclick=\"document.getElementById('team').hidden=false\">Refresh</button>\
                 <div id=\"team\" hidden>3 members</div>",
            );
            if role == Some("admin") {
                body.push_str(
                    "<button id=\"delete-member\" type=\"button\" \
                     onclick=\"this.textContent='Deleting'\">Delete member</button>",
                );
            }
            ok(roles_page("Dashboard", role, &body))
        }
        ("GET", "/reports") if role.is_none() => (
            "404 Not Found".to_string(),
            String::new(),
            roles_page("Not found", None, "<p>Not found</p>"),
        ),
        ("GET", "/reports") => ok(roles_page(
            "Reports",
            role,
            "<button id=\"export\" type=\"button\" \
             onclick=\"document.getElementById('csv').hidden=false\">Export</button>\
             <div id=\"csv\" hidden>csv</div>",
        )),
        ("GET", "/admin") if role != Some("admin") => redirect("/login?next=/admin", None),
        ("GET", "/admin") => ok(roles_page(
            "Admin",
            role,
            "<a href=\"/admin/users\">Members</a>",
        )),
        ("GET", "/admin/users") if role.is_none() => redirect("/login?next=/admin/users", None),
        ("GET", "/admin/users") if role != Some("admin") => (
            "403 Forbidden".to_string(),
            String::new(),
            roles_page("Forbidden", role, "<p>Admins only</p>"),
        ),
        ("GET", "/admin/users") => ok(roles_page(
            "Members",
            role,
            "<button id=\"invite\" type=\"button\" \
             onclick=\"document.getElementById('invite-form').hidden=false\">Invite member</button>\
             <div id=\"invite-form\" hidden>Invite</div>",
        )),
        ("GET", r) if r.starts_with("/slow/") => {
            let n: usize = r.trim_start_matches("/slow/").parse().unwrap_or(0);
            thread::sleep(Duration::from_millis(700));
            let next = if n + 1 < slow_pages {
                format!("<a href=\"/slow/{}\">Next {}</a>", n + 1, n + 1)
            } else {
                String::new()
            };
            ok(roles_page(
                &format!("Slow {n}"),
                role,
                &format!(
                    "{next}<button id=\"b{n}\" type=\"button\" \
                     onclick=\"this.textContent='done'\">Load {n}</button>"
                ),
            ))
        }
        _ => (
            "404 Not Found".to_string(),
            String::new(),
            roles_page("Not found", role, "<p>Missing</p>"),
        ),
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        html.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(html.as_bytes());
    let _ = stream.flush();
}

fn brokenapp(args: &[&str], home: &Path) -> Command {
    let mut cmd = Command::new(brokenapp_bin());
    cmd.args(args)
        .env("BROKENAPP_HOME", home)
        .env("BROKENAPP_NO_BANNER", "1")
        .env_remove("BROKENAPP_TELEMETRY_PATH")
        .env_remove("BROKENAPP_STATE_DIR");
    cmd
}

fn roles_config(url: &str, codebase: &Path, extra_scan: &str) -> String {
    format!(
        r#"[project]
name = "roles-fixture"
url = "{url}"
codebase = "{codebase}"

[scan]
max_minutes = 3
max_views = 20
settle_ms = 300
max_interactions_per_view = 10
tabs = 2
extra_routes = ["/dashboard", "/reports", "/admin", "/admin/users"]
exclude_routes = ["/logout"]
{extra_scan}
[[roles]]
name = "user"
method = "form"
login_url = "/login"
username = "env:ROLES_FIXTURE_USER_EMAIL"
password = "env:ROLES_FIXTURE_USER_PASSWORD"

[[roles]]
name = "manager"
method = "form"
login_url = "/login"
username = "env:ROLES_FIXTURE_MANAGER_EMAIL"
password = "env:ROLES_FIXTURE_MANAGER_PASSWORD"
"#,
        codebase = codebase.display()
    )
}

fn tsv_row<'a>(tsv: &'a str, kind: &str, route: &str, control: &str) -> Vec<&'a str> {
    tsv.lines()
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .find(|cols| cols.len() > 3 && cols[0] == kind && cols[1] == route && cols[2] == control)
        .unwrap_or_else(|| panic!("no {kind} row for {route} {control:?} in\n{tsv}"))
}

/// Explicit login must honor the same configured endpoint exceptions as map,
/// without turning its whole authentication page into a write exemption.
#[test]
fn form_login_check_honors_configured_allow_patterns_without_relaxing_guard() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping login allow-pattern e2e: Chrome/Chromium not detected");
        return;
    }
    let server = RolesServer::start(0);
    let users = fixture_users();
    let tmp = tempfile::tempdir().expect("tempdir");
    let codebase = tmp.path().join("app");
    copy_tree(&roles_fixture().join("app"), &codebase);
    let state = codebase.join(".brokenapp");
    fs::create_dir_all(&state).unwrap();
    let home = tmp.path().join("home");
    let state_arg = state.display().to_string();
    let run = |extra_scan: &str| {
        fs::write(
            state.join("config.toml"),
            roles_config(&server.url(), &codebase, extra_scan)
                .replace("login_url = \"/login\"", "login_url = \"/js-login\""),
        )
        .unwrap();
        let out = brokenapp(
            &[
                "login",
                "--role",
                "user",
                "--no-start",
                "--json",
                "--state-dir",
                &state_arg,
            ],
            &home,
        )
        .env("ROLES_FIXTURE_USER_EMAIL", &users.user.0)
        .env("ROLES_FIXTURE_USER_PASSWORD", &users.user.1)
        .output()
        .expect("run login check");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        for value in [&users.user.0, &users.user.1] {
            assert!(!stdout.contains(value.as_str()) && !stderr.contains(value.as_str()));
        }
        let report: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|err| panic!("login JSON: {err}; {stdout}{stderr}"));
        (out.status.code(), report)
    };

    // The JavaScript endpoint is neither the login URL nor the form action.
    // Without the explicit exception, no write may reach the fixture.
    let (code, denied) = run("");
    assert_eq!(code, Some(1), "{denied:#}");
    assert_eq!(denied["check"]["ok"], false, "{denied:#}");
    assert!(server.requests().iter().all(|r| r.starts_with("GET ")));

    // Exact method/query matching must allow sign-in but reject the landing
    // page's wrong-query, wrong-method and autosave probes. Even an explicit
    // GraphQL URL allowance must not permit a mutation.
    let (code, allowed) =
        run("write_guard_allow = [\"POST /api/custom-sign-in?flow=login\", \"POST /graphql\"]");
    assert_eq!(code, Some(0), "{allowed:#}");
    assert_eq!(allowed["status"], "ok", "{allowed:#}");
    assert_eq!(allowed["check"]["ok"], true, "{allowed:#}");
    let requests = server.requests();
    assert!(
        requests.iter().any(|r| r == "GET /guard-probes-finished"),
        "landing-page safety probes must finish: {requests:?}"
    );
    let writes: Vec<&str> = requests
        .iter()
        .filter(|r| !r.starts_with("GET ") && !r.starts_with("HEAD "))
        .map(String::as_str)
        .collect();
    assert_eq!(writes, ["POST /api/custom-sign-in?flow=login"]);
}

#[test]
fn map_roles_maps_each_role_and_writes_role_access() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping roles e2e: Chrome/Chromium not detected");
        return;
    }
    let users = fixture_users();
    let server = RolesServer::start(0);
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let codebase = tmp.path().join("app");
    copy_tree(&roles_fixture().join("app"), &codebase);
    let state = tmp.path().join("state/.brokenapp");
    fs::create_dir_all(&state).expect("state dir");
    fs::write(state.join(".gitignore"), "scans/\nhistory/\n").expect("old-style gitignore");
    fs::write(
        state.join("config.toml"),
        roles_config(&server.url(), &codebase, ""),
    )
    .expect("config");
    let state_arg = state.display().to_string();
    let secrets = [
        users.user.1.as_str(),
        users.admin.1.as_str(),
        users.wrong_password.as_str(),
    ];
    let assert_no_secrets = |what: &str, text: &str| {
        for s in secrets {
            assert!(!text.contains(s), "{what} leaks a password:\n{text}");
        }
    };

    // A literal password in config.toml is refused (and not echoed).
    let literal = roles_config(&server.url(), &codebase, "").replace(
        "password = \"env:ROLES_FIXTURE_MANAGER_PASSWORD\"",
        &format!("password = \"{}\"", users.wrong_password),
    );
    fs::write(state.join("config.toml"), &literal).unwrap();
    let out = brokenapp(&["map", "--json", "--state-dir", &state_arg], &home)
        .output()
        .unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{all}");
    assert!(all.contains("literal value"), "{all}");
    assert_no_secrets("literal refusal", &all);
    fs::write(
        state.join("config.toml"),
        roles_config(&server.url(), &codebase, ""),
    )
    .unwrap();

    // `roles add` with values on stdin: credentials.toml (0600, gitignored),
    // env-free [[roles]] entry in config.toml.
    let mut add = brokenapp(
        &[
            "roles",
            "add",
            "admin",
            "--login-url",
            "/login",
            "--stdin",
            "--json",
            "--state-dir",
            &state_arg,
        ],
        &home,
    );
    add.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = add.spawn().expect("spawn roles add");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{}\n{}\n", users.admin.0, users.admin.1).as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_no_secrets("roles add", &stdout);
    let added: Value = serde_json::from_str(&stdout).expect("roles add --json");
    assert_eq!(added["stored"], serde_json::json!(["username", "password"]));
    let config = fs::read_to_string(state.join("config.toml")).unwrap();
    assert!(config.contains("name = \"admin\""), "{config}");
    assert!(!config.contains(&users.admin.0), "{config}");
    assert_no_secrets("config.toml", &config);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(state.join("credentials.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let gitignore = fs::read_to_string(state.join(".gitignore")).unwrap();
    assert!(
        gitignore.contains("/credentials.toml") && gitignore.contains("/session/"),
        "{gitignore}"
    );

    // `roles list --json`: sources, never values.
    let out = brokenapp(
        &["roles", "list", "--json", "--state-dir", &state_arg],
        &home,
    )
    .env("ROLES_FIXTURE_USER_EMAIL", &users.user.0)
    .env("ROLES_FIXTURE_USER_PASSWORD", &users.user.1)
    .output()
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "{stdout}");
    assert_no_secrets("roles list", &stdout);
    let list: Value = serde_json::from_str(&stdout).unwrap();
    let names: Vec<&str> = list["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["anonymous", "user", "manager", "admin"]);
    assert_eq!(list["roles"][3]["ready"], true);
    assert_eq!(list["roles"][3]["credentials"][1]["from"], "credentials");
    assert_eq!(list["roles"][2]["ready"], false, "manager env vars unset");

    // `roles add --force` without new values keeps the stored ones.
    let out = brokenapp(
        &[
            "roles",
            "add",
            "admin",
            "--login-url",
            "/login",
            "--force",
            "--no-prompt",
            "--json",
            "--state-dir",
            &state_arg,
        ],
        &home,
    )
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let readded: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        readded["missing"].as_array().is_none_or(Vec::is_empty),
        "{readded:#}"
    );
    let creds = fs::read_to_string(state.join("credentials.toml")).unwrap();
    assert!(creds.contains(&users.admin.1), "stored password kept");
    let config = fs::read_to_string(state.join("config.toml")).unwrap();
    assert_eq!(config.matches("name = \"admin\"").count(), 1, "{config}");

    // Map every role: manager's password is wrong.
    let out = brokenapp(&["map", "--json", "--state-dir", &state_arg], &home)
        .env("ROLES_FIXTURE_USER_EMAIL", &users.user.0)
        .env("ROLES_FIXTURE_USER_PASSWORD", &users.user.1)
        .env("ROLES_FIXTURE_MANAGER_EMAIL", &users.admin.0)
        .env("ROLES_FIXTURE_MANAGER_PASSWORD", &users.wrong_password)
        .output()
        .expect("run map");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_no_secrets("map stdout", &stdout);
    assert_no_secrets("map stderr", &stderr);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("map --json: {e}\n{stdout}\n{stderr}"));
    assert_eq!(
        out.status.code(),
        Some(3),
        "partial run:\n{report:#}\n{stderr}"
    );
    assert_eq!(report["status"], "partial");
    assert_eq!(report["role"], "anonymous");
    let role = |name: &str| {
        report["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["role"] == name)
            .unwrap_or_else(|| panic!("role {name} in {report:#}"))
            .clone()
    };
    for name in ["anonymous", "user", "admin"] {
        assert_eq!(
            role(name)["status"],
            "mapped",
            "{name}: {report:#}\n{stderr}"
        );
    }
    let manager = role("manager");
    assert_eq!(manager["status"], "login_failed", "{report:#}");
    assert!(
        manager["error"].as_str().unwrap().contains("login_failed"),
        "{manager:#}"
    );
    assert!(role("admin")["login_check"].is_null());
    assert_eq!(
        role("user")["credentials"][0]["env"],
        "ROLES_FIXTURE_USER_EMAIL"
    );
    assert!(
        report["warnings"].as_array().unwrap().iter().any(|w| w
            .as_str()
            .unwrap()
            .contains("role 'manager' not mapped (login_failed)")),
        "{report:#}"
    );

    // Per-role map files; the top level stays the anonymous map.
    let map = state.join("map");
    for f in [
        "UI-MAP.md",
        "ui-map.tsv",
        "endpoints.tsv",
        "DEAD-UI.md",
        "CHANGELOG.md",
    ] {
        assert!(map.join(f).is_file(), "{f}");
        for r in ["user", "admin"] {
            assert!(map.join("roles").join(r).join(f).is_file(), "{r}/{f}");
        }
    }
    assert!(
        !map.join("roles/manager").exists(),
        "failed role gets no map"
    );
    assert!(
        state
            .join("history/roles/admin/latest.inventory.json")
            .is_file()
    );
    let admin_map = fs::read_to_string(map.join("roles/admin/UI-MAP.md")).unwrap();
    assert!(
        admin_map.starts_with("# UI map: roles-fixture (role: admin)"),
        "{admin_map}"
    );
    let anon_map = fs::read_to_string(map.join("UI-MAP.md")).unwrap();
    assert!(
        anon_map.starts_with("# UI map: roles-fixture\n"),
        "{anon_map}"
    );
    let index = fs::read_to_string(map.join("README.md")).unwrap();
    assert!(
        index.contains("| admin | form | `roles/admin/` |"),
        "{index}"
    );
    assert!(
        index.contains("| manager | form | `roles/manager/` | no map yet |"),
        "{index}"
    );

    // The role access matrix.
    let tsv = fs::read_to_string(map.join("role-access.tsv")).unwrap();
    assert!(
        tsv.starts_with("kind\troute\tcontrol\tanonymous\tuser\tmanager\tadmin\treview\n"),
        "{tsv}"
    );
    // The signed-in user follows /admin -> /login -> /dashboard, while
    // anonymous stays on /login. Classify the final landing, not the first hop.
    assert_eq!(
        tsv_row(&tsv, "route", "/admin", "")[3..7],
        ["login", "redirected", "-", "visited"],
        "{tsv}"
    );
    assert_eq!(
        tsv_row(&tsv, "route", "/dashboard", "")[3..7],
        ["login", "visited", "-", "visited"]
    );
    let admin_users = tsv_row(&tsv, "route", "/admin/users", "");
    assert_eq!(admin_users[3], "login");
    assert_eq!(admin_users[4], "forbidden", "{tsv}");
    assert_eq!(admin_users[6], "visited");
    let delete = tsv_row(&tsv, "control", "/dashboard", "button \"Delete member\"");
    assert_eq!(delete[3..7], ["-", "absent", "-", "present"], "{tsv}");
    let admin_link = tsv_row(&tsv, "control", "*", "link \"Admin\"");
    assert_eq!(admin_link[6], "present");
    assert_eq!(admin_link[4], "absent");
    let md = fs::read_to_string(map.join("ROLE-ACCESS.md")).unwrap();
    assert!(
        md.contains("| manager | form | no map | 0/0 | login_failed (")
            && md.contains("sign-in still shows the password field"),
        "{md}"
    );
    assert_eq!(
        report["role_access"]
            .as_str()
            .map(|p| PathBuf::from(p).canonicalize().unwrap()),
        Some(map.join("ROLE-ACCESS.md").canonicalize().unwrap())
    );

    // Anonymous /reports is a deliberate 404, but the authenticated link works.
    let admin_inventory: brokenapp::inventory::Inventory = serde_json::from_str(
        &fs::read_to_string(state.join("history/roles/admin/latest.inventory.json")).unwrap(),
    )
    .unwrap();
    assert!(
        admin_inventory
            .controls
            .iter()
            .any(|c| c.label == "Reports")
    );
    assert!(
        !admin_inventory.controls.iter().any(
            |c| c.label == "Reports" && c.status == brokenapp::inventory::ControlStatus::Broken
        )
    );

    // The generated scan configs reference env vars, never values.
    let run_dir = PathBuf::from(report["run_dir"].as_str().unwrap());
    for (role, user_var) in [
        ("admin", "env:BROKENAPP_ROLE_ADMIN_USERNAME"),
        ("user", "env:ROLES_FIXTURE_USER_EMAIL"),
    ] {
        let toml = fs::read_to_string(run_dir.join("roles").join(role).join("scan.toml")).unwrap();
        assert!(
            toml.contains(&format!("username = \"{user_var}\"")),
            "{toml}"
        );
        assert!(toml.contains("type = \"form\""), "{toml}");
        assert!(!toml.contains(&users.admin.0) && !toml.contains(&users.user.0));
        assert_no_secrets("scan.toml", &toml);
    }
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"], "partial");
    assert_no_secrets("run.json", &manifest.to_string());
    // Nothing under the state dir holds a value except credentials.toml.
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&state, &mut files);
    for f in files.iter().filter(|f| !f.ends_with("credentials.toml")) {
        if let Ok(text) = fs::read_to_string(f) {
            assert_no_secrets(&f.display().to_string(), &text);
        }
    }

    // Safety: no sign-out, and the only writes are the logins.
    let requests = server.requests();
    assert!(
        !requests.iter().any(|r| r.contains("/logout")),
        "{requests:#?}"
    );
    assert!(
        requests
            .iter()
            .all(|r| r.starts_with("GET ") || r.starts_with("HEAD ") || r == "POST /login"),
        "{requests:#?}"
    );

    // Read commands per role.
    let read = |args: &[&str]| {
        let mut full = args.to_vec();
        full.extend(["--state-dir", &state_arg]);
        let out = brokenapp(&full, &home).output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )
    };
    let (code, out) = read(&[
        "ui",
        "--role",
        "admin",
        "--text",
        "Delete member",
        "--format",
        "tsv",
    ]);
    assert_eq!(code, Some(0));
    assert_eq!(out.lines().count(), 2, "{out}");
    let (_, out) = read(&[
        "ui",
        "--role",
        "user",
        "--text",
        "Delete member",
        "--format",
        "tsv",
    ]);
    assert_eq!(out.lines().count(), 1, "header only: {out}");
    let (_, out) = read(&[
        "ui", "--role", "all", "--text", "Refresh", "--format", "tsv",
    ]);
    assert!(out.starts_with("login_role\troute\t"), "{out}");
    let roles_with_refresh: BTreeSet<&str> = out
        .lines()
        .skip(1)
        .filter_map(|l| l.split('\t').next())
        .collect();
    assert_eq!(roles_with_refresh, ["admin", "user"].into_iter().collect());
    let (_, out) = read(&["ui", "--role", "button", "--route", "/", "--format", "tsv"]);
    assert!(
        out.lines()
            .skip(1)
            .all(|l| l.split('\t').nth(1) == Some("button")),
        "{out}"
    );
    let (code, out) = read(&["dead", "--role", "all"]);
    assert_eq!(code, Some(0));
    assert!(
        out.contains("== anonymous ==") && out.contains("== admin =="),
        "{out}"
    );
    let (code, _) = read(&["journey", "/admin/users", "--role", "admin"]);
    assert_eq!(code, Some(0));
    let (_, out) = read(&["changes", "--role", "user"]);
    assert!(out.starts_with("No earlier map"), "{out}");
    let (code, _) = read(&["ui", "--role", "nobody"]);
    assert_ne!(code, Some(0));

    // `--changed` is per role: nothing changed, nothing scanned.
    let out = brokenapp(
        &[
            "map",
            "--changed",
            "--role",
            "user",
            "--json",
            "--state-dir",
            &state_arg,
        ],
        &home,
    )
    .env("ROLES_FIXTURE_USER_EMAIL", &users.user.0)
    .env("ROLES_FIXTURE_USER_PASSWORD", &users.user.1)
    .output()
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let skipped: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(skipped["mode"], "skipped", "{skipped:#}");
    assert_eq!(skipped["roles"][0]["role"], "user");
    assert_eq!(skipped["roles"][0]["status"], "unchanged");

    // doctor: readiness per role, no values.
    let out = brokenapp(&["doctor", "--json", "--state-dir", &state_arg], &home)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_no_secrets("doctor", &stdout);
    let doctor: Value = serde_json::from_str(&stdout).unwrap();
    let check = |n: &str| {
        doctor["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .unwrap_or_else(|| panic!("{n} in {doctor:#}"))
            .clone()
    };
    assert_eq!(check("role:admin")["status"], "ok", "{doctor:#}");
    assert_eq!(check("role:user")["status"], "warn", "env vars unset here");

    // `login --role` for a session role reaches the capture step.
    let raw = fs::read_to_string(state.join("config.toml")).unwrap();
    fs::write(
        state.join("config.toml"),
        format!("{raw}\n[[roles]]\nname = \"coach\"\nmethod = \"session\"\n"),
    )
    .unwrap();
    let out = brokenapp(
        &[
            "login",
            "--role",
            "coach",
            "--json",
            "--timeout",
            "5",
            "--state-dir",
            &state_arg,
        ],
        &home,
    )
    .output()
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let login: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{e}: {stdout}{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(login["role"], "coach");
    assert!(
        login["status"] == "saved" || login["status"] == "error",
        "{login:#}"
    );
    let out = brokenapp(
        &[
            "login",
            "--role",
            "manager",
            "--json",
            "--state-dir",
            &state_arg,
        ],
        &home,
    )
    .env("ROLES_FIXTURE_MANAGER_EMAIL", &users.admin.0)
    .env("ROLES_FIXTURE_MANAGER_PASSWORD", &users.wrong_password)
    .output()
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert_no_secrets("login", &stdout);
    let login: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(login["exit_code"], 1);
    assert_eq!(login["status"], "error");
    assert!(login["error"].as_str().is_some_and(|e| !e.is_empty()));
    assert_eq!(login["check"]["ok"], false);
}

#[cfg(unix)]
#[test]
fn map_full_mode_interrupts_and_resumes() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !chrome_available() {
        eprintln!("skipping full-mode resume e2e: Chrome/Chromium not detected");
        return;
    }
    // A chain of slow pages (0.7 s each) keeps the crawl busy long enough
    // to interrupt it.
    let server = RolesServer::start(15);
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let codebase = tmp.path().join("app");
    copy_tree(&roles_fixture().join("app"), &codebase);
    let state = tmp.path().join("state/.brokenapp");
    fs::create_dir_all(&state).expect("state dir");
    fs::write(
        state.join("config.toml"),
        format!(
            r#"[project]
name = "full-fixture"
url = "{url}"
codebase = "{codebase}"

[scan]
settle_ms = 200
tabs = 1
progress_seconds = 5
extra_routes = ["/slow/0"]
exclude_routes = ["/logout"]
"#,
            url = server.url(),
            codebase = codebase.display()
        ),
    )
    .expect("config");
    let state_arg = state.display().to_string();

    // 1. Full mode: no caps reach the scanner.
    let child = brokenapp(
        &["map", "--full", "--json", "--state-dir", &state_arg],
        &home,
    )
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .expect("spawn map --full");
    let pid = child.id();
    // Interrupt as soon as interactions begin; do not wait for the periodic
    // checkpoint, since the signal itself must persist partial work.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let run_dir = loop {
        let found = fs::read_dir(state.join("scans"))
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .find(|d| {
                fs::read_to_string(d.join("scan/interactions.jsonl"))
                    .is_ok_and(|s| s.lines().count() >= 2)
            });
        if let Some(d) = found {
            break d;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the full crawl never got going"
        );
        thread::sleep(Duration::from_millis(200));
    };
    let scan_toml = fs::read_to_string(run_dir.join("scan.toml")).unwrap();
    for line in [
        "max_views = 0",
        "max_duration_minutes = 0",
        "stop_on_convergence = false",
        "max_interactions_per_view = 1000",
        "max_interaction_depth = 4",
        "view_budget_seconds = 300",
    ] {
        assert!(scan_toml.contains(line), "{line} missing:\n{scan_toml}");
    }

    // 2. Interrupt: engine receives a graceful signal and updates its checkpoint.
    let before_interrupt = fs::read_to_string(run_dir.join("scan/checkpoint.json")).ok();
    let status = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(130),
        "map --full should still be crawling the slow pages when interrupted:\n{stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("resume with: brokenapp map --resume"),
        "{stderr}"
    );
    let interrupted: Value = serde_json::from_str(&stdout).expect("interrupted --json");
    assert_eq!(interrupted["status"], "interrupted");
    assert_eq!(interrupted["resume"], "brokenapp map --resume");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"], "interrupted", "{manifest:#}");
    assert_eq!(manifest["roles"][0]["status"], "interrupted");
    assert_eq!(manifest["settings"]["scan_mode"], "full");
    assert!(run_dir.join("scan/checkpoint.json").is_file());
    assert_ne!(
        fs::read_to_string(run_dir.join("scan/checkpoint.json")).ok(),
        before_interrupt,
        "interrupt must let the engine refresh its checkpoint"
    );
    assert!(!state.join("history/latest.inventory.json").exists());

    // A changed target must not resume the old checkpoint under a new report.
    let original_config = fs::read_to_string(state.join("config.toml")).unwrap();
    fs::write(
        state.join("config.toml"),
        original_config.replace(&server.url(), "http://127.0.0.1:9/"),
    )
    .unwrap();
    let rejected = brokenapp(
        &["map", "--resume", "--json", "--state-dir", &state_arg],
        &home,
    )
    .output()
    .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stdout).contains("target URL or codebase differs"));
    fs::write(state.join("config.toml"), &original_config).unwrap();

    // 3. Resume: same run, same settings, the crawl continues from its checkpoint.
    let out = brokenapp(
        &["map", "--resume", "--json", "--state-dir", &state_arg],
        &home,
    )
    .output()
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        report["resumed"].as_str(),
        run_dir.file_name().and_then(|n| n.to_str()),
        "{report:#}"
    );
    assert_eq!(report["scan_mode"], "full");
    assert_eq!(
        (report["max_minutes"].as_u64(), report["max_views"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(report["scan"]["status"], "resumed", "{report:#}\n{stderr}");
    assert!(stderr.contains("resuming from the checkpoint"), "{stderr}");
    assert!(!stderr.contains("could not be resumed"), "{stderr}");
    assert!(state.join("history/latest.inventory.json").is_file());
    assert!(
        report["coverage"]["routes_visited"].as_u64().unwrap_or(0) >= 2,
        "{report:#}"
    );
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"], "completed", "{manifest:#}");
    assert_eq!(manifest["resumed_at"].as_array().map(Vec::len), Some(1));
    let progress: Value =
        serde_json::from_str(&fs::read_to_string(run_dir.join("map-progress.json")).unwrap())
            .unwrap();
    assert_eq!(progress["role"], "anonymous");
    assert_eq!(progress["estimated_remaining_seconds"], 0);

    // Nothing left to resume.
    let out = brokenapp(&["map", "--resume", "--state-dir", &state_arg], &home)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing to resume"));
    let requests = server.requests();
    assert!(
        requests
            .iter()
            .all(|r| r.starts_with("GET ") || r.starts_with("HEAD ")),
        "{requests:#?}"
    );
}
