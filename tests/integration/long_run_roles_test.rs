//! Long, multi-tab, authenticated crawls on the multi-role fixture
//! (`tests/fixtures/ui-map-roles`, served in-process here): form login per
//! role under parallel tabs, a session that expires mid-scan (one re-login,
//! the scan completes), saved browser sessions (captured without a human,
//! loaded into every tab, stopping with `session_expired` when they expire),
//! unlimited budgets that do not stop early, and interrupt + resume ending
//! with the coverage of an uninterrupted run.
//!
//! Credentials are throwaway fixture accounts (see the fixture README). They
//! reach the scan only through its environment and must never show up in
//! any scan output.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

const USER_EMAIL: &str = "user@roles.fixture.test";
const USER_PASSWORD: &str = "fixture-user-pass-1";
const ADMIN_EMAIL: &str = "admin@roles.fixture.test";
const ADMIN_PASSWORD: &str = "fixture-admin-pass-2";

/// Protected pages every signed-in role can open.
const MEMBER_ROUTES: [&str; 6] = [
    "/dashboard",
    "/reports",
    "/reports/weekly",
    "/reports/monthly",
    "/profile",
    "/settings",
];
/// Admin-only pages.
const ADMIN_ROUTES: [&str; 3] = ["/admin", "/admin/users", "/admin/audit"];
/// The public chain of docs pages (each links only to the next).
const DOCS: [&str; 10] = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet",
];

fn brokenapp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brokenapp")
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui-map-roles")
}

fn chrome_available() -> bool {
    brokenapp::browser::BrowserManager::detect_chrome_executable().is_some()
}

// ── Fixture server ──────────────────────────────────────────────────────────

#[derive(Default)]
struct AppState {
    /// Session id -> role.
    sessions: HashMap<String, String>,
    next_session: u64,
    /// Every request as `METHOD /path`.
    requests: Vec<String>,
    /// Successful sign-ins (`POST /login`).
    logins: usize,
    /// Authenticated page loads served.
    authed_pages: usize,
    /// Expire every session once, after this many authenticated page loads.
    expire_after: Option<usize>,
    expired: bool,
    /// Extra latency per page and API response (makes scans last).
    delay: Duration,
    /// Auth responses echo secret data and landing pages try autosave.
    hostile_auth: bool,
}

struct RolesApp {
    addr: String,
    state: Arc<Mutex<AppState>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

/// Bind a port of the fixture range (47280-47289).
fn bind_fixture_port() -> TcpListener {
    for port in 47280..=47289 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            return listener;
        }
    }
    panic!("no free fixture port in 47280-47289");
}

impl RolesApp {
    fn start() -> Self {
        let listener = bind_fixture_port();
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr").to_string();
        let state = Arc::new(Mutex::new(AppState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (state_t, stop_t) = (Arc::clone(&state), Arc::clone(&stop));
        let root = fixture_root();
        let handle = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&state_t);
                        let root = root.clone();
                        thread::spawn(move || serve(stream, &root, &state));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            state,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn with<R>(&self, f: impl FnOnce(&mut AppState) -> R) -> R {
        f(&mut self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Start a session for `role` directly (a saved session's cookie).
    fn create_session(&self, role: &str) -> String {
        self.with(|st| new_session(st, role))
    }

    fn requests(&self) -> Vec<String> {
        self.with(|st| st.requests.clone())
    }

    fn logins(&self) -> usize {
        self.with(|st| st.logins)
    }
}

impl Drop for RolesApp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(&self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn new_session(st: &mut AppState, role: &str) -> String {
    st.next_session += 1;
    let sid = format!(
        "s{:08x}{}",
        st.next_session * 2_654_435_761 % 4_294_967_291,
        role
    );
    st.sessions.insert(sid.clone(), role.to_string());
    sid
}

struct Request {
    method: String,
    path: String,
    query: String,
    cookie_sid: Option<String>,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    let mut content_length = 0usize;
    let mut cookie_sid = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "content-length" {
            content_length = value.trim().parse().unwrap_or(0);
        } else if name == "cookie" {
            for pair in value.split(';') {
                if let Some(("sid", v)) = pair.trim().split_once('=') {
                    cookie_sid = Some(v.to_string());
                }
            }
        }
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    Some(Request {
        method,
        path,
        query,
        cookie_sid,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn form_value(body: &str, key: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| {
            v.replace('+', " ")
                .replace("%40", "@")
                .replace("%2F", "/")
                .replace("%2f", "/")
        })
    })
}

fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, String)], body: &[u8]) {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn html(stream: &mut TcpStream, body: String) {
    respond(
        stream,
        "200 OK",
        &[("Content-Type", "text/html; charset=utf-8".to_string())],
        body.as_bytes(),
    );
}

fn redirect(stream: &mut TcpStream, location: &str, cookie: Option<String>) {
    let mut headers = vec![("Location", location.to_string())];
    if let Some(cookie) = cookie {
        headers.push(("Set-Cookie", cookie));
    }
    respond(stream, "302 Found", &headers, b"");
}

fn json(stream: &mut TcpStream, status: &str, body: &str) {
    respond(
        stream,
        status,
        &[("Content-Type", "application/json".to_string())],
        body.as_bytes(),
    );
}

fn serve(mut stream: TcpStream, root: &Path, state: &Mutex<AppState>) {
    let Some(req) = read_request(&mut stream) else {
        return;
    };
    let (role, delay) = {
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.requests.push(format!("{} {}", req.method, req.path));
        let role = req
            .cookie_sid
            .as_ref()
            .and_then(|sid| st.sessions.get(sid).cloned());
        (role, st.delay)
    };
    let path = req.path.as_str();
    if !delay.is_zero() && (path.starts_with("/api/") || role.is_some()) {
        thread::sleep(delay);
    }
    match (req.method.as_str(), path) {
        ("GET", "/") => html(
            &mut stream,
            "<!doctype html><html lang=\"en\"><head><title>Roles fixture</title></head><body><main><h1>Welcome</h1><a href=\"/login\">Sign in</a> <a href=\"/docs/alpha\">Docs</a></main></body></html>".to_string(),
        ),
        ("GET", "/login") => {
            let auto = req.query.contains("auto=");
            let accounts = if auto {
                format!(
                    r#"{{"user": ["{USER_EMAIL}", "{USER_PASSWORD}"], "admin": ["{ADMIN_EMAIL}", "{ADMIN_PASSWORD}"]}}"#
                )
            } else {
                "{}".to_string()
            };
            let message = if req.query.contains("reason=forbidden") {
                "That page needs another role."
            } else if req.query.contains("next=") {
                "Please sign in to continue."
            } else {
                ""
            };
            let page = fs::read_to_string(root.join("login.html")).expect("login.html");
            let mut page = page.replace("__AUTO_ACCOUNTS__", &accounts).replace("__MESSAGE__", message);
            if state.lock().unwrap_or_else(|p| p.into_inner()).hostile_auth {
                page = page.replace("name=\"email\"", "name=\"account\"").replace("name=\"password\"", "name=\"credential\"");
            }
            html(&mut stream, page);
        }
        ("POST", "/login") => {
            let email = form_value(&req.body, "email").or_else(|| form_value(&req.body, "account")).unwrap_or_default();
            let password = form_value(&req.body, "password").or_else(|| form_value(&req.body, "credential")).unwrap_or_default();
            let role = match (email.as_str(), password.as_str()) {
                (USER_EMAIL, USER_PASSWORD) => Some("user"),
                (ADMIN_EMAIL, ADMIN_PASSWORD) => Some("admin"),
                _ => None,
            };
            match role {
                Some(role) => {
                    let sid = {
                        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                        st.logins += 1;
                        new_session(&mut st, role)
                    };
                    let cookie = format!("sid={sid}; Path=/; HttpOnly; SameSite=Lax");
                    if state.lock().unwrap_or_else(|p| p.into_inner()).hostile_auth {
                        // Response content must not enter auth evidence, even
                        // when a custom field name defeats generic redaction.
                        respond(&mut stream, "200 OK", &[("Content-Type", "text/html".into()), ("Set-Cookie", cookie)],
                            format!("<script>const token='fixture-access-token-987';const account='{email}';const credential='{password}';location.replace('/dashboard');</script>").as_bytes());
                    } else {
                        redirect(&mut stream, "/dashboard", Some(cookie));
                    }
                }
                None => respond(
                    &mut stream,
                    "401 Unauthorized",
                    &[("Content-Type", "text/plain".to_string())],
                    b"wrong email or password",
                ),
            }
        }
        ("GET", "/logout") => {
            if let Some(sid) = req.cookie_sid.as_ref() {
                state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .sessions
                    .remove(sid);
            }
            redirect(
                &mut stream,
                "/login",
                Some("sid=; Path=/; Max-Age=0".to_string()),
            );
        }
        ("GET", p) if p.starts_with("/docs/") => {
            let name = p.trim_start_matches("/docs/");
            let Some(i) = DOCS.iter().position(|d| *d == name) else {
                respond(&mut stream, "404 Not Found", &[], b"missing");
                return;
            };
            let next = DOCS
                .get(i + 1)
                .map(|n| format!("<a href=\"/docs/{n}\">Next: {n}</a>"))
                .unwrap_or_default();
            html(
                &mut stream,
                format!(
                    "<!doctype html><html lang=\"en\"><head><title>Docs {name}</title></head><body><main><h1>Docs {name}</h1><button onclick=\"document.getElementById('n').hidden=!document.getElementById('n').hidden\">Toggle note {name}</button><p id=\"n\" hidden>note</p>{next}</main></body></html>"
                ),
            );
        }
        ("GET", p) if p.starts_with("/api/") => match (&role, p) {
            (None, _) => json(&mut stream, "401 Unauthorized", r#"{"error":"signed out"}"#),
            (Some(role), "/api/me") => {
                json(&mut stream, "200 OK", &format!(r#"{{"role":"{role}"}}"#))
            }
            (Some(_), "/api/stats") => json(&mut stream, "200 OK", r#"{"visits":42}"#),
            (Some(_), "/api/reports") => json(&mut stream, "200 OK", r#"{"rows":3}"#),
            _ => json(&mut stream, "404 Not Found", "{}"),
        },
        ("GET", p) if MEMBER_ROUTES.contains(&p) || ADMIN_ROUTES.contains(&p) => {
            let Some(role) = role else {
                redirect(&mut stream, &format!("/login?next={p}"), None);
                return;
            };
            if ADMIN_ROUTES.contains(&p) && role != "admin" {
                redirect(&mut stream, "/login?reason=forbidden", None);
                return;
            }
            let mut body = protected_page(root, p, &role);
            if state.lock().unwrap_or_else(|p| p.into_inner()).hostile_auth {
                body.push_str("<script>fetch('/api/autosave', {method:'POST',body:'autosave'}).catch(()=>{});</script>");
            }
            {
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                st.authed_pages += 1;
                if !st.expired && st.expire_after.is_some_and(|n| st.authed_pages >= n) {
                    // Every session ends (after this page is served).
                    st.expired = true;
                    st.sessions.clear();
                }
            }
            html(&mut stream, body);
        }
        _ if req.method != "GET" => json(&mut stream, "200 OK", "{}"),
        _ => respond(&mut stream, "404 Not Found", &[], b"missing"),
    }
}

fn protected_page(root: &Path, path: &str, role: &str) -> String {
    let mut nav = String::from(
        r#"<a href="/dashboard">Dashboard</a><a href="/reports">Reports</a><a href="/profile">Profile</a><a href="/settings">Settings</a>"#,
    );
    if role == "admin" {
        nav.push_str(r#"<a href="/admin">Admin</a>"#);
    }
    let (title, main) = match path {
        "/dashboard" => (
            "Dashboard",
            format!(
                r#"<button onclick="load('/api/stats','stats')">Refresh stats</button><p id="stats"></p>
<button onclick="togglePanel('details')">Toggle details</button><div id="details" class="panel">Details</div>{}"#,
                if role == "admin" {
                    r#"<button onclick="togglePanel('users-panel')">Manage users</button><div id="users-panel" class="panel">Users</div>"#
                } else {
                    ""
                }
            ),
        ),
        "/reports" => (
            "Reports",
            r#"<button onclick="load('/api/reports','report')">Run report</button><p id="report"></p>
<a href="/reports/weekly">Weekly report</a> <a href="/reports/monthly">Monthly report</a>"#
                .to_string(),
        ),
        "/reports/weekly" => (
            "Weekly report",
            r#"<button onclick="document.getElementById('csv').textContent='weekly.csv'">Download weekly CSV</button><p id="csv"></p>
<button onclick="togglePanel('cmp')">Compare weeks</button><div id="cmp" class="panel">Compare</div>"#
                .to_string(),
        ),
        "/reports/monthly" => (
            "Monthly report",
            r#"<button onclick="document.getElementById('csv').textContent='monthly.csv'">Download monthly CSV</button><p id="csv"></p>
<button onclick="togglePanel('cmp')">Compare months</button><div id="cmp" class="panel">Compare</div>"#
                .to_string(),
        ),
        "/profile" => (
            "Profile",
            r#"<button onclick="openDialog('edit')">Edit profile</button>
<div id="edit" role="dialog" aria-label="Edit profile" hidden><p>Edit</p><button onclick="closeDialog('edit')">Close</button></div>
<button onclick="save('/api/profile','saved')">Save profile</button><p id="saved"></p>"#
                .to_string(),
        ),
        "/settings" => (
            "Settings",
            r#"<button onclick="document.body.classList.toggle('dark')">Toggle theme</button>
<button onclick="togglePanel('adv')">Show advanced</button><div id="adv" class="panel">Advanced</div>"#
                .to_string(),
        ),
        "/admin" => (
            "Admin",
            r#"<button onclick="openDialog('create')">Create user</button>
<div id="create" role="dialog" aria-label="Create user" hidden><p>New user</p><button onclick="closeDialog('create')">Cancel</button></div>
<button onclick="save('/api/admin/reindex','reindex')">Rebuild index</button><p id="reindex"></p>
<a href="/admin/users">Users</a> <a href="/admin/audit">Audit log</a>"#
                .to_string(),
        ),
        "/admin/users" => (
            "Users",
            r#"<button onclick="togglePanel('admins')">Filter admins</button><div id="admins" class="panel">Admins</div>
<button onclick="save('/api/admin/promote','promoted')">Promote user</button><p id="promoted"></p>"#
                .to_string(),
        ),
        "/admin/audit" => (
            "Audit log",
            r#"<button onclick="togglePanel('log')">Show log</button><div id="log" class="panel">Log</div>"#
                .to_string(),
        ),
        _ => ("Page", String::new()),
    };
    fs::read_to_string(root.join("layout.html"))
        .expect("layout.html")
        .replace("__TITLE__", title)
        .replace("__ROLE__", role)
        .replace("__NAV__", &nav)
        .replace("__MAIN__", &main)
}

// ── Scan helpers ────────────────────────────────────────────────────────────

/// Config for one scan of the fixture. `auth` is the TOML of the auth part
/// (`[[auth_paths]]` blocks or an `[auth]` table), `scan` extra `[scan]` keys.
fn write_config(dir: &Path, base: &str, auth: &str, scan: &str) -> (PathBuf, PathBuf) {
    let out = dir.join("scan");
    let config = dir.join("brokenapp.toml");
    let seeds: Vec<String> = MEMBER_ROUTES
        .iter()
        .chain(ADMIN_ROUTES.iter())
        .map(|r| format!("{r:?}"))
        .collect();
    fs::write(
        &config,
        format!(
            r#"
[target]
url = "{base}/"
headless = true

{auth}

[scan]
max_depth = 6
max_concurrent_tabs = 3
settle_timeout_ms = 400
interaction_timeout_ms = 2500
seed_urls = [{seeds}]
{scan}

[scan.limits]
max_interactions_per_view = 8

[scan.pacing]
delay_between_interactions_ms = 50

[scan.exploration]
strategy = "breadth_first"

[output]
directory = "{out}"
checkpoint_interval_seconds = 2
"#,
            seeds = seeds.join(", "),
            out = out.display()
        ),
    )
    .expect("write config");
    (config, out)
}

const FORM_ROLES: &str = r##"
[[auth_paths]]
name = "user"
type = "form"
login_url = "/login"
username_selector = "#email"
password_selector = "#password"
submit_selector = "#submit"
username = "env:ROLES_FIXTURE_USER_EMAIL"
password = "env:ROLES_FIXTURE_USER_PASSWORD"

[[auth_paths]]
name = "admin"
type = "form"
login_url = "/login"
username_selector = "#email"
password_selector = "#password"
submit_selector = "#submit"
username = "env:ROLES_FIXTURE_ADMIN_EMAIL"
password = "env:ROLES_FIXTURE_ADMIN_PASSWORD"
"##;

fn scan_command(config: &Path, extra: &[&str]) -> Command {
    let mut cmd = Command::new(brokenapp_bin());
    cmd.args(["scan", "--json", "--store-import", "off", "--config"])
        .arg(config)
        .args(extra)
        .env_remove("BROKENAPP_MAX_CONCURRENT_TABS")
        .env("BROKENAPP_NO_BANNER", "1")
        .env(
            "BROKENAPP_TELEMETRY_PATH",
            config.with_file_name("telemetry.jsonl"),
        )
        // Credentials only ever travel through the environment.
        .env("ROLES_FIXTURE_USER_EMAIL", USER_EMAIL)
        .env("ROLES_FIXTURE_USER_PASSWORD", USER_PASSWORD)
        .env("ROLES_FIXTURE_ADMIN_EMAIL", ADMIN_EMAIL)
        .env("ROLES_FIXTURE_ADMIN_PASSWORD", ADMIN_PASSWORD);
    cmd
}

fn resume_command(scan_dir: &Path) -> Command {
    let mut cmd = Command::new(brokenapp_bin());
    cmd.args(["resume", "--json", "--store-import", "off"])
        .arg(scan_dir)
        .env_remove("BROKENAPP_MAX_CONCURRENT_TABS")
        .env("BROKENAPP_NO_BANNER", "1")
        .env("ROLES_FIXTURE_USER_EMAIL", USER_EMAIL)
        .env("ROLES_FIXTURE_USER_PASSWORD", USER_PASSWORD)
        .env("ROLES_FIXTURE_ADMIN_EMAIL", ADMIN_EMAIL)
        .env("ROLES_FIXTURE_ADMIN_PASSWORD", ADMIN_PASSWORD);
    cmd
}

/// Run to completion; the parsed `--json` summary.
fn run_json(mut cmd: Command, what: &str) -> (Output, Value) {
    let output = cmd
        .output()
        .unwrap_or_else(|err| panic!("run {what}: {err}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = stdout
        .find('{')
        .and_then(|start| serde_json::from_str::<Value>(&stdout[start..]).ok())
        .unwrap_or_else(|| {
            panic!(
                "{what}: no JSON summary (status {:?})\nstdout:\n{stdout}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    (output, json)
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Paths of the explored (top-level) views in `spec.json`.
fn visited_paths(scan_dir: &Path) -> BTreeSet<String> {
    let spec: Value =
        serde_json::from_str(&fs::read_to_string(scan_dir.join("spec.json")).expect("spec.json"))
            .expect("spec json");
    spec["views"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| !str_of(v, "id").contains(':') && str_of(v, "component_type") != "unchanged")
        .map(|v| {
            str_of(v, "route")
                .split('?')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// Interaction rows by page path.
fn rows_by_path(scan_dir: &Path) -> BTreeMap<String, Vec<Value>> {
    let mut out: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for row in read_jsonl(&scan_dir.join("interactions.jsonl")) {
        let path = url::Url::parse(str_of(&row, "page_url"))
            .map(|u| u.path().to_string())
            .unwrap_or_default();
        out.entry(path).or_default().push(row);
    }
    out
}

fn labels(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .map(|r| str_of(r, "label").to_string())
        .collect()
}

/// Requests that would change state on the server (only sign-ins may).
fn writes(app: &RolesApp) -> Vec<String> {
    app.requests()
        .into_iter()
        .filter(|r| !r.starts_with("GET ") && r != "POST /login")
        .collect()
}

/// No file of the scan (or the run directory) contains a password.
fn assert_no_secrets(dir: &Path) {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            for secret in [
                USER_EMAIL,
                ADMIN_EMAIL,
                USER_PASSWORD,
                ADMIN_PASSWORD,
                "fixture-access-token-987",
            ] {
                assert!(
                    !text.contains(secret),
                    "{} contains a password",
                    path.display()
                );
            }
        }
    }
}

fn run_report(scan_dir: &Path) -> Value {
    serde_json::from_str(
        &fs::read_to_string(scan_dir.join("scan-run.json")).expect("scan-run.json"),
    )
    .expect("scan-run json")
}

fn browser_lock() -> std::sync::MutexGuard<'static, ()> {
    super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write a saved session for `sid` (as `brokenapp login` would capture it).
fn write_saved_session(app: &RolesApp, path: &Path, role: &str, sid: &str) {
    let host = app.addr.split(':').next().unwrap_or("127.0.0.1");
    let state = serde_json::json!({
        "cookies": [{
            "name": "sid", "value": sid, "domain": host, "path": "/",
            "expires": -1, "httpOnly": true, "secure": false, "sameSite": "Lax"
        }],
        "origins": [{
            "origin": app.url(""),
            "localStorage": [{"name": "fixture_ui_token", "value": format!("ui-{role}")}],
            "sessionStorage": [{"name": "fixture_tab_token", "value": format!("tab-{role}")}]
        }],
        "brokenapp": {
            "version": 1,
            "capturedAt": "2026-10-22T10:00:00Z",
            "url": app.url("/login"),
            "landingUrl": app.url("/dashboard"),
            "loginPattern": "/login"
        }
    });
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    fs::rename(&tmp, path).unwrap();
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Each role logs in with its own credentials (from the environment) and
/// maps its own UI under three parallel tabs: the admin sees and exercises
/// admin-only routes and buttons; the user lands on the login page for them
/// and the session canary marks those routes gated for the role (no
/// re-login). `/logout` is never requested and nothing but sign-ins writes.
#[test]
fn form_login_per_role_maps_each_roles_ui_under_parallel_tabs() {
    let _guard = browser_lock();
    if !chrome_available() {
        eprintln!("skipping: Chrome/Chromium not detected");
        return;
    }
    for role in ["admin", "user"] {
        let app = RolesApp::start();
        let tmp = tempfile::tempdir().unwrap();
        let (config, scan_dir) = write_config(
            tmp.path(),
            &app.url(""),
            FORM_ROLES,
            "max_duration_minutes = 5\nmax_views = 0",
        );
        let (output, summary) = run_json(
            scan_command(&config, &["--auth-path", role]),
            &format!("{role} scan"),
        );
        assert_success(&output, role);
        assert_eq!(summary["status"], "ok", "{role}: {summary}");
        assert_eq!(app.logins(), 1, "{role}: one sign-in, no re-login");
        assert!(
            !app.requests().iter().any(|r| r.contains("/logout")),
            "{role}: /logout was requested"
        );
        assert!(
            writes(&app).is_empty(),
            "{role}: writes reached the server: {:?}",
            writes(&app)
        );

        let visited = visited_paths(&scan_dir);
        for route in MEMBER_ROUTES {
            assert!(
                visited.contains(route),
                "{role}: {route} not mapped: {visited:?}"
            );
        }
        let rows = rows_by_path(&scan_dir);
        let dashboard = labels(rows.get("/dashboard").map(Vec::as_slice).unwrap_or(&[]));
        let run = run_report(&scan_dir);
        assert_eq!(run["auth"]["type"], "form");
        assert_eq!(run["auth"]["role"], role);
        assert_eq!(run["tabs"], 3);
        assert_eq!(summary["run"]["status"], "ok");
        if role == "admin" {
            for route in ADMIN_ROUTES {
                assert!(
                    visited.contains(route),
                    "admin: {route} not mapped: {visited:?}"
                );
            }
            assert!(dashboard.contains("Manage users"), "{dashboard:?}");
            assert!(labels(&rows["/admin/users"]).contains("Promote user"));
            assert_eq!(run["session"]["reauths"].as_u64().unwrap_or(0), 0);
        } else {
            assert!(!dashboard.contains("Manage users"), "{dashboard:?}");
            for route in ADMIN_ROUTES {
                assert!(!visited.contains(route), "user mapped {route}");
            }
            assert!(
                run["session"]["role_gated"].as_u64().unwrap_or(0) >= 1,
                "admin routes are gated for the user role: {run}"
            );
            assert_eq!(run["session"]["reauths"].as_u64().unwrap_or(0), 0, "{run}");
            assert_eq!(run["session"]["expired"], false);
        }
        assert_no_secrets(tmp.path());
    }
}

/// The server ends every session mid-scan. Tabs that land on the login page
/// trigger one re-login (serialized: the others retry with the new session),
/// the views are retried, and the scan completes with every route mapped.
#[test]
fn session_expiry_mid_scan_relogs_in_once_and_completes() {
    let _guard = browser_lock();
    if !chrome_available() {
        eprintln!("skipping: Chrome/Chromium not detected");
        return;
    }
    let app = RolesApp::start();
    app.with(|st| st.expire_after = Some(4));
    let tmp = tempfile::tempdir().unwrap();
    let (config, scan_dir) = write_config(
        tmp.path(),
        &app.url(""),
        FORM_ROLES,
        "max_duration_minutes = 5\nmax_views = 0",
    );
    let (output, summary) = run_json(
        scan_command(&config, &["--auth-path", "admin"]),
        "expiring scan",
    );
    assert_success(&output, "expiring scan");
    assert!(
        app.with(|st| st.expired),
        "the fixture expired the sessions"
    );
    assert_eq!(summary["status"], "ok", "{summary}");
    assert_eq!(app.logins(), 2, "initial sign-in plus exactly one re-login");
    let run = run_report(&scan_dir);
    assert_eq!(run["session"]["reauths"], 1, "{run}");
    assert_eq!(run["session"]["failed_reauths"], 0, "{run}");
    assert_eq!(run["session"]["expired"], false, "{run}");
    let events = run["session"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "session_reauth" && e["success"] == true),
        "{run}"
    );

    let visited = visited_paths(&scan_dir);
    for route in MEMBER_ROUTES.iter().chain(ADMIN_ROUTES.iter()) {
        assert!(
            visited.contains(*route),
            "{route} not mapped after re-login: {visited:?}"
        );
    }
    // No view was mapped from the login page instead of its route, and every
    // mapped protected view saw the signed-in page.
    let rows = rows_by_path(&scan_dir);
    for route in MEMBER_ROUTES {
        let labels = labels(rows.get(route).map(Vec::as_slice).unwrap_or(&[]));
        assert!(
            labels.contains("Storage missing") || labels.contains("Storage ok"),
            "{route}: {labels:?}"
        );
    }
    assert!(!app.requests().iter().any(|r| r.contains("/logout")));
    assert!(writes(&app).is_empty(), "{:?}", writes(&app));
    assert_no_secrets(tmp.path());
}

/// A saved session captured without a human (the fixture's login page signs
/// in by itself) is written owner-only, then a scan loads its cookie and its
/// local and session storage into every one of three tabs: every protected
/// view shows `Storage ok`, and nobody logs in.
#[test]
fn captured_session_loads_into_every_tab() {
    let _guard = browser_lock();
    if !chrome_available() {
        eprintln!("skipping: Chrome/Chromium not detected");
        return;
    }
    let app = RolesApp::start();
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("session/admin.json");
    let opts = brokenapp::session::storage_state::CaptureOptions {
        url: app.url("/login?auto=admin"),
        out_path: session_path.clone(),
        chrome_executable: None,
        timeout_secs: 60,
        done_when_url_leaves: Some("/login".to_string()),
    };
    let captured = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(
            brokenapp::session::storage_state::capture_storage_state_with(
                &opts,
                &brokenapp::session::storage_state::CaptureControl {
                    headless: true,
                    ignore_stdin: true,
                },
            ),
        )
        .expect("capture");
    assert_eq!(app.logins(), 1, "the page signed in once");
    assert!(captured.cookies >= 1, "{captured:?}");
    assert_eq!(captured.origins, vec![app.url("")], "{captured:?}");
    assert!(!captured.captured_at.is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&session_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "saved sessions are owner-only");
    }
    let saved: Value = serde_json::from_str(&fs::read_to_string(&session_path).unwrap()).unwrap();
    assert_eq!(saved["brokenapp"]["landingUrl"], app.url("/dashboard"));
    assert_eq!(
        saved["origins"][0]["localStorage"][0]["name"],
        "fixture_ui_token"
    );
    assert_eq!(
        saved["origins"][0]["sessionStorage"][0]["name"],
        "fixture_tab_token"
    );
    let described =
        brokenapp::session::storage_state::describe_storage_state(&session_path).unwrap();
    assert_eq!(described, captured);

    let auth = format!(
        "[auth]\ntype = \"storage_state\"\npath = {:?}\n",
        session_path.display().to_string()
    );
    let (config, scan_dir) = write_config(
        tmp.path(),
        &app.url(""),
        &auth,
        "max_duration_minutes = 5\nmax_views = 0",
    );
    let (output, summary) = run_json(scan_command(&config, &[]), "saved-session scan");
    assert_success(&output, "saved-session scan");
    assert_eq!(summary["status"], "ok", "{summary}");
    assert_eq!(app.logins(), 1, "a saved session never logs in");
    let visited = visited_paths(&scan_dir);
    let rows = rows_by_path(&scan_dir);
    for route in MEMBER_ROUTES.iter().chain(ADMIN_ROUTES.iter()) {
        assert!(visited.contains(*route), "{route} not mapped: {visited:?}");
        let labels = labels(rows.get(*route).map(Vec::as_slice).unwrap_or(&[]));
        assert!(labels.contains("Storage ok"), "{route}: {labels:?}");
        assert!(!labels.contains("Storage missing"), "{route}: {labels:?}");
    }
    let run = run_report(&scan_dir);
    assert_eq!(run["auth"]["type"], "storage_state");
    assert_eq!(run["auth"]["renewable"], false);
    assert!(!app.requests().iter().any(|r| r.contains("/logout")));
    assert!(writes(&app).is_empty(), "{:?}", writes(&app));
    assert_no_secrets(tmp.path());
}

/// A saved session that expires mid-scan cannot be renewed: the scan stops
/// cleanly with status `session_expired` (no login attempts, URLs left in
/// the checkpoint). Once the session is captured again, `resume` finishes
/// the map.
#[test]
fn saved_session_expiry_stops_with_session_expired_then_resume_finishes() {
    let _guard = browser_lock();
    if !chrome_available() {
        eprintln!("skipping: Chrome/Chromium not detected");
        return;
    }
    let app = RolesApp::start();
    app.with(|st| st.expire_after = Some(3));
    let tmp = tempfile::tempdir().unwrap();
    let session_path = tmp.path().join("admin.json");
    let sid = app.create_session("admin");
    write_saved_session(&app, &session_path, "admin", &sid);
    let auth = format!(
        "[auth]\ntype = \"storage_state\"\npath = {:?}\n",
        session_path.display().to_string()
    );
    let (config, scan_dir) = write_config(
        tmp.path(),
        &app.url(""),
        &auth,
        "max_duration_minutes = 0\nmax_views = 0",
    );
    let started = Instant::now();
    let (output, summary) = run_json(scan_command(&config, &[]), "expiring saved session");
    assert_success(&output, "expiring saved session");
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "stopped promptly, no re-auth loop"
    );
    assert_eq!(summary["status"], "session_expired", "{summary}");
    assert_eq!(summary["run"]["stop_reason"], "session_expired");
    assert_eq!(
        app.logins(),
        0,
        "a saved session is never renewed by logging in"
    );
    let run = run_report(&scan_dir);
    assert_eq!(run["session"]["expired"], true, "{run}");
    assert_eq!(run["session"]["reauths"], 0);
    let checkpoint: Value =
        serde_json::from_str(&fs::read_to_string(scan_dir.join("checkpoint.json")).unwrap())
            .unwrap();
    let queued = checkpoint["queue"].as_array().map(Vec::len).unwrap_or(0);
    assert!(queued > 0, "unmapped routes stay queued for resume");
    let gaps: Value =
        serde_json::from_str(&fs::read_to_string(scan_dir.join("coverage-gaps.json")).unwrap())
            .unwrap();
    assert!(gaps.to_string().contains("session_expired"), "{gaps}");
    let before = visited_paths(&scan_dir);

    // The human signs in again (a new saved session); the scan resumes.
    let sid = app.create_session("admin");
    write_saved_session(&app, &session_path, "admin", &sid);
    let (output, summary) = run_json(resume_command(&scan_dir), "resume");
    assert_success(&output, "resume");
    assert_eq!(summary["status"], "ok", "{summary}");
    assert_eq!(summary["run"]["resumes"], 1);
    let after = visited_paths(&scan_dir);
    assert!(after.len() > before.len(), "{before:?} -> {after:?}");
    for route in MEMBER_ROUTES.iter().chain(ADMIN_ROUTES.iter()) {
        assert!(
            after.contains(*route),
            "{route} not mapped after resume: {after:?}"
        );
    }
    assert_eq!(app.logins(), 0);
    assert!(!app.requests().iter().any(|r| r.contains("/logout")));
    assert!(writes(&app).is_empty(), "{:?}", writes(&app));
}

/// With no time or view cap and convergence settings that would have ended
/// the crawl after two views, the crawl still maps the whole chain of pages:
/// convergence and stagnation wait while unvisited routes are queued.
#[test]
fn unlimited_budgets_map_everything_before_stopping() {
    let _guard = browser_lock();
    if !chrome_available() {
        eprintln!("skipping: Chrome/Chromium not detected");
        return;
    }
    let app = RolesApp::start();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("scan");
    let config = tmp.path().join("brokenapp.toml");
    fs::write(
        &config,
        format!(
            r#"
[target]
url = "{url}"
headless = true

[scan]
max_duration_minutes = 0
max_views = 0
max_depth = 20
max_concurrent_tabs = 2
settle_timeout_ms = 300
view_budget_seconds = 60
stop_on_convergence = true
convergence_window_views = 2
convergence_min_coverage_percent = 0.0
convergence_max_new_views = 5

[scan.pacing]
delay_between_interactions_ms = 0

[output]
directory = "{out}"
"#,
            url = app.url("/docs/alpha"),
            out = out.display()
        ),
    )
    .unwrap();
    let (output, summary) = run_json(scan_command(&config, &[]), "unlimited scan");
    assert_success(&output, "unlimited scan");
    assert_eq!(summary["status"], "ok", "{summary}");
    let visited = visited_paths(&out);
    for name in DOCS {
        assert!(
            visited.contains(&format!("/docs/{name}")),
            "/docs/{name} not mapped: {visited:?}"
        );
    }
    let run = &summary["run"];
    assert_eq!(run["budgets"]["max_duration_minutes"], 0);
    assert_eq!(run["budgets"]["max_views"], 0);
    assert_eq!(run["budgets"]["view_budget_seconds"], 60);
    assert!(
        matches!(
            run["stop_reason"].as_str(),
            Some("queue_exhausted" | "convergence_reached")
        ),
        "{run}"
    );
    assert!(run["peak_rss_bytes"].as_u64().unwrap_or(0) > 0, "{run}");
}

/// Coverage summary of a scan directory's inventory.
fn inventory_of(scan_dir: &Path, base: &str) -> brokenapp::inventory::Inventory {
    let opts = brokenapp::inventory::BuildOptions {
        project: "roles".into(),
        target_url: format!("{base}/"),
        write_guard: "block".into(),
        ..Default::default()
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(brokenapp::inventory::build_from_scan_dir(scan_dir, &opts))
        .expect("inventory")
}

fn visited_routes(inv: &brokenapp::inventory::Inventory) -> BTreeSet<String> {
    inv.routes
        .iter()
        .filter(|r| r.visited)
        .map(|r| r.route.clone())
        .collect()
}

/// A multi-tab, form-login scan stopped by SIGTERM mid-crawl checkpoints
/// (status `interrupted`, exit 143, in-flight views back in the queue);
/// `resume` logs in again and ends with the same inventory coverage as an
/// uninterrupted run.
#[cfg(unix)]
#[test]
fn interrupted_scan_resumes_to_the_coverage_of_an_uninterrupted_run() {
    let _guard = browser_lock();
    if !chrome_available() {
        eprintln!("skipping: Chrome/Chromium not detected");
        return;
    }
    let scan_settings = "max_duration_minutes = 0\nmax_views = 0";

    // Uninterrupted reference run.
    let reference = {
        let app = RolesApp::start();
        app.with(|st| st.delay = Duration::from_millis(250));
        let tmp = tempfile::tempdir().unwrap();
        let (config, scan_dir) = write_config(tmp.path(), &app.url(""), FORM_ROLES, scan_settings);
        let (output, summary) = run_json(
            scan_command(&config, &["--auth-path", "admin"]),
            "reference scan",
        );
        assert_success(&output, "reference scan");
        assert_eq!(summary["status"], "ok");
        let inv = inventory_of(&scan_dir, &app.url(""));
        (visited_routes(&inv), inv.coverage.clone())
    };

    let app = RolesApp::start();
    app.with(|st| st.delay = Duration::from_millis(250));
    let tmp = tempfile::tempdir().unwrap();
    let (config, scan_dir) = write_config(tmp.path(), &app.url(""), FORM_ROLES, scan_settings);
    let progress = tmp.path().join("progress.json");
    let mut child = scan_command(
        &config,
        &[
            "--auth-path",
            "admin",
            "--progress-file",
            progress.to_str().unwrap(),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn scan");
    // Interrupt once a few views are mapped (the crawl is mid-way).
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let views = fs::read_to_string(scan_dir.join("checkpoint.json"))
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|cp| cp["views"].as_array().map(Vec::len))
            .unwrap_or(0);
        if views >= 3 {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "the scan finished before it could be interrupted"
        );
        assert!(Instant::now() < deadline, "no progress");
        thread::sleep(Duration::from_millis(200));
    }
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(143), "SIGTERM exit code");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let summary: Value = serde_json::from_str(&stdout[stdout.find('{').expect("summary")..])
        .expect("interrupted summary");
    assert_eq!(summary["status"], "interrupted", "{summary}");
    assert_eq!(summary["run"]["stop_reason"], "interrupted");
    let checkpoint: Value =
        serde_json::from_str(&fs::read_to_string(scan_dir.join("checkpoint.json")).unwrap())
            .unwrap();
    assert!(
        !checkpoint["queue"].as_array().unwrap().is_empty(),
        "the rest of the crawl is queued"
    );
    let interrupted_views = checkpoint["views"].as_array().unwrap().len();
    assert!(checkpoint["crawl"]["crawl_seconds"].as_u64().unwrap_or(0) > 0);
    let logins_before = app.logins();

    let (output, resumed) = run_json(resume_command(&scan_dir), "resume");
    assert_success(&output, "resume");
    assert_eq!(resumed["status"], "ok", "{resumed}");
    assert_eq!(resumed["run"]["resumes"], 1);
    assert_eq!(app.logins(), logins_before + 1, "resume logs in again");
    let cp: Value =
        serde_json::from_str(&fs::read_to_string(scan_dir.join("checkpoint.json")).unwrap())
            .unwrap();
    assert!(cp["views"].as_array().unwrap().len() > interrupted_views);

    // Every interaction row belongs to a mapped view (rows of views cut off
    // by the interrupt were dropped and written again).
    let spec: Value =
        serde_json::from_str(&fs::read_to_string(scan_dir.join("spec.json")).unwrap()).unwrap();
    let view_ids: BTreeSet<String> = spec["views"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            str_of(v, "id")
                .split(':')
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    for row in read_jsonl(&scan_dir.join("interactions.jsonl")) {
        let base = str_of(&row, "view_id")
            .split(':')
            .next()
            .unwrap_or_default();
        assert!(view_ids.contains(base), "orphan interaction row: {row}");
    }

    let inv = inventory_of(&scan_dir, &app.url(""));
    let (ref_routes, ref_cov) = reference;
    assert_eq!(visited_routes(&inv), ref_routes, "same routes mapped");
    let cov = &inv.coverage;
    let within = |a: u32, b: u32| (a as f64 - b as f64).abs() <= (b as f64 * 0.15).max(2.0);
    assert!(
        within(cov.controls_total, ref_cov.controls_total),
        "controls {} vs {}",
        cov.controls_total,
        ref_cov.controls_total
    );
    assert!(
        within(cov.controls_exercised, ref_cov.controls_exercised),
        "exercised {} vs {}",
        cov.controls_exercised,
        ref_cov.controls_exercised
    );
    assert!(!app.requests().iter().any(|r| r.contains("/logout")));
    assert!(writes(&app).is_empty(), "{:?}", writes(&app));
    assert_no_secrets(tmp.path());
}

/// Login authorization must not exempt landing-page autosaves; custom form
/// secrets and token-bearing auth responses must never enter scan artifacts.
#[test]
fn auth_landing_writes_are_blocked_and_credentials_are_not_recorded() {
    let _guard = browser_lock();
    assert!(
        chrome_available(),
        "Chrome is required for auth guard regression"
    );
    let app = RolesApp::start();
    app.with(|st| st.hostile_auth = true);
    let tmp = tempfile::tempdir().unwrap();
    let (config, scan_dir) = write_config(
        tmp.path(),
        &app.url(""),
        FORM_ROLES,
        "max_duration_minutes = 5\nmax_views = 3",
    );
    let (output, summary) = run_json(
        scan_command(&config, &["--auth-path", "admin"]),
        "guarded auth",
    );
    assert_success(&output, "guarded auth");
    assert_eq!(summary["status"], "ok", "{summary}");
    assert_eq!(app.logins(), 1);
    assert!(
        writes(&app).is_empty(),
        "landing writes escaped the guard: {:?}",
        writes(&app)
    );
    assert!(read_jsonl(&scan_dir.join("network.jsonl")).iter().any(|row| row.to_string().contains("/api/autosave") && row["write_guard"] == "blocked"));
    assert_no_secrets(tmp.path());
    let mut wrong = scan_command(&config, &["--auth-path", "admin"]);
    wrong.env("ROLES_FIXTURE_ADMIN_PASSWORD", "invalid-fixture-password");
    let rejected = wrong.output().expect("wrong password scan");
    assert!(!rejected.status.success(), "wrong-password login must fail");
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("login_failed"));
    assert_no_secrets(tmp.path());
}
