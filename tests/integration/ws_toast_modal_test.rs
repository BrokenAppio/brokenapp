//! End-to-end headless Chromium tests for:
//! 1. WebSocket frame observation, write guarding, and RPC error detection.
//! 2. Runtime error-toast detection vs. benign inline form validation.
//! 3. Active blocking-modal discovery scoping and headless-UI hidden checkbox dedupe.

use std::{
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

use base64::Engine as _;
use ring::digest;
use serde_json::Value;

fn brokenapp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brokenapp")
}

fn chrome_available() -> bool {
    brokenapp::browser::BrowserManager::detect_chrome_executable().is_some()
}

struct WsTestServer {
    addr: String,
    received_frames: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl WsTestServer {
    fn start(index_html: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ws test server");
        listener.set_nonblocking(true).expect("set nonblocking");
        let addr = listener.local_addr().expect("local addr").to_string();
        let received_frames = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let frames_ref = Arc::clone(&received_frames);
        let html = Arc::new(index_html);

        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let html = Arc::clone(&html);
                        let frames = Arc::clone(&frames_ref);
                        let stop_conn = Arc::clone(&stop_flag);
                        thread::spawn(move || handle_client(stream, &html, &frames, &stop_conn));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            received_frames,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for WsTestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    html: &str,
    received_frames: &Arc<Mutex<Vec<String>>>,
    stop: &Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
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
    let first_line = head.lines().next().unwrap_or_default();
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let ws_key = head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("sec-websocket-key")
            .then(|| v.trim().to_string())
    });

    if let Some(key) = ws_key {
        let mut concat = key;
        concat.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, concat.as_bytes());
        let accept = base64::engine::general_purpose::STANDARD.encode(hash.as_ref());
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        if stream.write_all(resp.as_bytes()).is_err() {
            return;
        }
        let _ = stream.flush();
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        serve_ws_frames(&mut stream, received_frames, stop);
        return;
    }

    if path == "/" || path == "/index.html" {
        let body = html.as_bytes();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    } else {
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
    }
}

fn serve_ws_frames(
    stream: &mut TcpStream,
    received_frames: &Arc<Mutex<Vec<String>>>,
    stop: &Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        let mut hdr = [0_u8; 2];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        }
        let opcode = hdr[0] & 0x0f;
        if opcode == 0x8 {
            break;
        }
        let masked = (hdr[1] & 0x80) != 0;
        let mut len = (hdr[1] & 0x7f) as usize;
        if len == 126 {
            let mut ext = [0_u8; 2];
            if stream.read_exact(&mut ext).is_err() {
                break;
            }
            len = u16::from_be_bytes(ext) as usize;
        } else if len == 127 {
            let mut ext = [0_u8; 8];
            if stream.read_exact(&mut ext).is_err() {
                break;
            }
            len = u64::from_be_bytes(ext) as usize;
        }
        let mut mask = [0_u8; 4];
        if masked && stream.read_exact(&mut mask).is_err() {
            break;
        }
        let mut payload = vec![0_u8; len];
        if len > 0 && stream.read_exact(&mut payload).is_err() {
            break;
        }
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        if opcode == 0x1
            && let Ok(text) = String::from_utf8(payload)
        {
            received_frames
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(text.clone());

            if text.contains("server.getSecret") {
                let err_reply = r#"{"_tag":"Exit","requestId":"3","exit":{"_tag":"Failure","cause":{"_tag":"Fail","error":{"_tag":"EnvironmentAuthorizationError","message":"This connection lacks permission to read secret settings."}}}}"#;
                let _ = write_ws_text_frame(stream, err_reply);
            } else if text.contains("git.status") {
                let ok_reply = r#"{"_tag":"Exit","requestId":"1","exit":{"_tag":"Success","value":{"clean":true}}}"#;
                let _ = write_ws_text_frame(stream, ok_reply);
            }
        }
    }
}

fn write_ws_text_frame(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
    let bytes = text.as_bytes();
    let mut frame = Vec::with_capacity(bytes.len() + 10);
    frame.push(0x81);
    if bytes.len() < 126 {
        frame.push(bytes.len() as u8);
    } else if bytes.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(bytes);
    stream.write_all(&frame)?;
    stream.flush()
}

fn run_scan(target_url: &str, output_dir: &Path) {
    let config_path = output_dir.parent().unwrap().join("brokenapp.toml");
    fs::write(
        &config_path,
        format!(
            r#"[target]
url = "{target_url}"
name = "ws-toast-modal-fixture"
headless = true

[scan]
max_depth = 1
max_views = 2
max_duration_minutes = 2
max_stagnation_minutes = 1
interaction_timeout_ms = 2000
settle_timeout_ms = 500
max_concurrent_tabs = 1

[scan.limits]
max_interactions_per_view = 30

[output]
directory = "{}"
include_screenshots = false
include_network_log = true
bug_report_format = ["json"]
"#,
            output_dir.display()
        ),
    )
    .expect("write scan config");

    let output = Command::new(brokenapp_bin())
        .args([
            "scan",
            "--json",
            "--config",
            config_path.to_str().expect("utf8 path"),
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

fn read_jsonl(path: &Path) -> Vec<Value> {
    if !path.exists() {
        return Vec::new();
    }
    fs::read_to_string(path)
        .expect("read jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("valid json line"))
        .collect()
}

#[test]
fn ws_observation_guarding_and_error_toast_detection_e2e() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping ws/toast e2e: Chrome/Chromium not detected");
        return;
    }

    let html = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>WS & Error Toast Fixture</title>
  <style>
    body { font-family: system-ui; padding: 24px; }
    button { margin: 8px; padding: 10px 14px; }
    .toast-region { position: fixed; right: 16px; bottom: 16px; }
    .toast { background: #222; color: #fff; padding: 12px; border-radius: 6px; margin-top: 8px; }
    .field-error { color: red; }
  </style>
</head>
<body>
  <main>
    <h1>Workspace</h1>
    <button id="ws-read" type="button">Refresh diff</button>
    <button id="ws-write" type="button">Open in editor</button>
    <button id="ws-opaque" type="button">Run custom action</button>
    <button id="ws-error" type="button">Load secret config</button>
    <form id="profile-form" novalidate>
      <input id="display-name" name="display_name" type="text" required />
      <p id="name-err" class="field-error" hidden>Display name is required</p>
      <button id="form-validate" type="button">Check form</button>
    </form>
  </main>
  <div id="toasts" class="toast-region" data-slot="toast-viewport"></div>
  <script>
    const ws = new WebSocket("ws://" + location.host + "/ws");
    const ready = new Promise(resolve => { ws.addEventListener("open", resolve, { once: true }); });
    ws.addEventListener("message", (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg._tag === "Exit" && msg.exit && msg.exit._tag === "Failure") {
          const region = document.getElementById("toasts");
          const toast = document.createElement("div");
          // Mirrors Base UI Toast.Root (role="dialog" + data-type="error" inside toast-viewport).
          toast.className = "toast";
          toast.setAttribute("role", "dialog");
          toast.setAttribute("data-type", "error");
          toast.innerHTML =
            '<div data-slot="toast-title">Setting not saved</div>' +
            '<div data-slot="toast-description">This connection lacks permission to read secret settings.</div>' +
            '<button type="button" aria-label="Copy error">Copy error</button>' +
            '<button type="button" data-slot="toast-close" aria-label="Dismiss notification">Dismiss</button>';
          region.appendChild(toast);
        }
      } catch (_) {}
    });

    // Silent WS read: no DOM mutation, proves WS activity prevents false dead_button.
    document.getElementById("ws-read").addEventListener("click", async () => {
      await ready;
      ws.send(JSON.stringify({ _tag: "Request", id: "1", tag: "git.status" }));
    });

    // Mutating WS RPC: must be blocked by write guard and never reach the server.
    document.getElementById("ws-write").addEventListener("click", async () => {
      await ready;
      ws.send(JSON.stringify({ _tag: "Request", id: "2", tag: "shell.openInEditor", payload: { cwd: "/tmp" } }));
    });

    // Unrecognized non-read WS frame during a click: must fail closed and never reach the server.
    document.getElementById("ws-opaque").addEventListener("click", async () => {
      await ready;
      ws.send(JSON.stringify({ _tag: "Request", id: "4", tag: "workspace.frobnicate" }));
    });

    // WS read that triggers server RPC Failure + error toast.
    document.getElementById("ws-error").addEventListener("click", async () => {
      await ready;
      ws.send(JSON.stringify({ _tag: "Request", id: "3", tag: "server.getSecret" }));
    });

    // Expected inline form validation: must NOT trigger ui_error_toast.
    document.getElementById("form-validate").addEventListener("click", () => {
      document.getElementById("name-err").hidden = false;
    });
  </script>
</body>
</html>"#;

    let server = WsTestServer::start(html.to_string());
    let tmp = tempfile::tempdir().expect("tempdir");
    let output_dir = tmp.path().join("scan-output");

    run_scan(&server.url("/"), &output_dir);

    // 1) Server saw the read frames, NEVER saw the guarded mutation frame!
    let frames = server
        .received_frames
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert!(
        frames.iter().any(|f| f.contains("git.status")),
        "expected read WS frame git.status to reach server; frames={frames:#?}"
    );
    assert!(
        !frames.iter().any(|f| f.contains("shell.openInEditor")),
        "write guard leaked mutating WS frame shell.openInEditor to server! frames={frames:#?}"
    );
    assert!(
        !frames.iter().any(|f| f.contains("workspace.frobnicate")),
        "write guard leaked unrecognized WS frame during click to server! frames={frames:#?}"
    );

    // 2) network.jsonl contains both the observed WS read and the blocked WS write.
    let net_rows = read_jsonl(&output_dir.join("network.jsonl"));
    assert!(
        net_rows.iter().any(|r| {
            r.pointer("/request/method").and_then(Value::as_str) == Some("WS")
                && r.get("endpoint_key").and_then(Value::as_str)
                    == Some("WS /ws#shell.openInEditor")
                && r.get("write_guard").and_then(Value::as_str) == Some("blocked")
                && r.pointer("/triggered_by/selector").and_then(Value::as_str) == Some("#ws-write")
        }),
        "expected blocked WS write row in network.jsonl; rows={net_rows:#?}"
    );
    assert!(
        net_rows.iter().any(|r| {
            r.pointer("/request/method").and_then(Value::as_str) == Some("WS")
                && r.get("endpoint_key").and_then(Value::as_str) == Some("WS /ws#git.status")
                && r.get("write_guard").is_none()
        }),
        "expected observed WS read row in network.jsonl; rows={net_rows:#?}"
    );

    // 3) bugs.json has BOTH ui_error_toast and websocket_error for #ws-error,
    //    NO dead_button for #ws-read or #ws-write, and NO ui_error_toast for #form-validate.
    let bugs: Value = serde_json::from_str(
        &fs::read_to_string(output_dir.join("bugs.json")).expect("read bugs.json"),
    )
    .expect("parse bugs.json");
    let items = bugs
        .pointer("/items")
        .and_then(Value::as_array)
        .expect("bugs items");
    assert!(
        items.iter().any(|b| {
            b.pointer("/category/kind").and_then(Value::as_str) == Some("ui_error_toast")
                && b.pointer("/location/element").and_then(Value::as_str) == Some("#ws-error")
        }),
        "expected ui_error_toast bug for #ws-error; bugs={items:#?}"
    );
    assert!(
        items.iter().any(|b| {
            b.pointer("/category/kind").and_then(Value::as_str) == Some("websocket_error")
        }),
        "expected websocket_error bug; bugs={items:#?}"
    );
    assert!(
        !items.iter().any(|b| {
            b.pointer("/category/kind").and_then(Value::as_str) == Some("dead_button")
                && matches!(
                    b.pointer("/category/selector").and_then(Value::as_str),
                    Some("#ws-read" | "#ws-write")
                )
        }),
        "WS-driven controls must not be flagged as dead_button; bugs={items:#?}"
    );
    assert!(
        !items.iter().any(|b| {
            b.pointer("/category/kind").and_then(Value::as_str) == Some("ui_error_toast")
                && b.pointer("/location/element").and_then(Value::as_str) == Some("#form-validate")
        }),
        "inline form validation must not trigger ui_error_toast; bugs={items:#?}"
    );

    // 4) Inventory marks #ws-read and #ws-write Ok, and #ws-error Broken.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let inv = rt
        .block_on(brokenapp::inventory::build_from_scan_dir(
            &output_dir,
            &brokenapp::inventory::BuildOptions {
                project: "ws-fixture".into(),
                target_url: server.url("/"),
                write_guard: "block".into(),
                ..Default::default()
            },
        ))
        .expect("build inventory");

    let status_of = |label: &str| {
        inv.controls
            .iter()
            .find(|c| c.label == label)
            .unwrap_or_else(|| panic!("missing control {label:?} in {:#?}", inv.controls))
            .status
    };
    assert_eq!(
        status_of("Refresh diff"),
        brokenapp::inventory::ControlStatus::Ok
    );
    assert_eq!(
        status_of("Open in editor"),
        brokenapp::inventory::ControlStatus::Ok
    );
    assert_eq!(
        status_of("Load secret config"),
        brokenapp::inventory::ControlStatus::Broken
    );
}

#[test]
fn active_modal_scoping_and_hidden_switch_dedupe_e2e() {
    let _browser_guard = super::BROWSER_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !chrome_available() {
        eprintln!("skipping active-modal e2e: Chrome/Chromium not detected");
        return;
    }

    let html = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Settings Route Modal Fixture</title>
  <style>
    body { margin: 0; font-family: system-ui; }
    .backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.45); z-index: 40; }
    .modal { position: fixed; top: 80px; left: 50%; transform: translateX(-50%); width: 520px; background: #fff; padding: 24px; z-index: 50; border-radius: 10px; }
    .sr-only { position: absolute; width: 1px; height: 1px; opacity: 0; overflow: hidden; }
    button { margin: 6px; padding: 8px 12px; }
  </style>
</head>
<body>
  <main id="root" aria-hidden="true">
    <h1>Background Shell</h1>
    <button id="bg-1" type="button">Background One</button>
    <button id="bg-2" type="button">Background Two</button>
    <button id="bg-3" type="button">Background Three</button>
  </main>
  <div class="backdrop" data-slot="dialog-backdrop"></div>
  <div id="settings-modal" role="dialog" aria-modal="true" data-slot="dialog-popup" class="modal">
    <h2>General Settings</h2>
    <label for="hidden-switch-input">
      <button id="dark-switch" type="button" role="switch" aria-checked="false">Dark mode</button>
      <input id="hidden-switch-input" type="checkbox" class="sr-only" aria-hidden="true" tabindex="-1" />
    </label>
    <button id="modal-save" type="button">Save preference</button>
    <div id="modal-toast-slot"></div>
  </div>
  <script>
    document.getElementById("dark-switch").addEventListener("click", (e) => {
      const btn = e.currentTarget;
      const next = btn.getAttribute("aria-checked") !== "true";
      btn.setAttribute("aria-checked", String(next));
      document.getElementById("hidden-switch-input").checked = next;
    });
    document.getElementById("modal-save").addEventListener("click", () => {
      const slot = document.getElementById("modal-toast-slot");
      slot.innerHTML = '<div data-slot="toast" data-type="error" role="alert">Could not save preference. <button type="button">Copy error</button></div>';
    });
  </script>
</body>
</html>"#;

    let server = WsTestServer::start(html.to_string());
    let tmp = tempfile::tempdir().expect("tempdir");
    let output_dir = tmp.path().join("scan-output");

    run_scan(&server.url("/"), &output_dir);

    let interactions = read_jsonl(&output_dir.join("interactions.jsonl"));
    // Background buttons and hidden backing switch checkbox must NOT appear or cause obscured skips.
    for forbidden in ["#bg-1", "#bg-2", "#bg-3", "#hidden-switch-input"] {
        assert!(
            !interactions
                .iter()
                .any(|r| r.get("selector").and_then(Value::as_str) == Some(forbidden)),
            "control {forbidden} should be excluded by active-modal scoping / hidden-switch dedupe; interactions={interactions:#?}"
        );
    }
    assert!(
        !interactions
            .iter()
            .any(|r| r.get("skipped_reason").and_then(Value::as_str) == Some("obscured")),
        "expected zero obscured skips when modal scoping is active; interactions={interactions:#?}"
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let inv = rt
        .block_on(brokenapp::inventory::build_from_scan_dir(
            &output_dir,
            &brokenapp::inventory::BuildOptions {
                project: "modal-fixture".into(),
                target_url: server.url("/"),
                write_guard: "block".into(),
                ..Default::default()
            },
        ))
        .expect("build inventory");

    let dark = inv
        .controls
        .iter()
        .find(|c| c.label == "Dark mode")
        .expect("Dark mode switch discovered");
    assert_eq!(dark.status, brokenapp::inventory::ControlStatus::Ok);

    let save = inv
        .controls
        .iter()
        .find(|c| c.label == "Save preference")
        .expect("Save preference button discovered");
    assert_eq!(save.status, brokenapp::inventory::ControlStatus::Broken);
}
