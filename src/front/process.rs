//! Child processes owned by `brokenapp map`: the project's dev server and the
//! scan subprocess.
//!
//! Each runs in its own process group so the whole tree (npm → node → workers,
//! or scan → Chrome) can be stopped together. [`ManagedChild`] kills its group
//! on drop, so early returns, errors and cancelled futures never leave
//! processes behind; callers use [`ManagedChild::stop`] for a graceful
//! SIGTERM → SIGKILL shutdown on the normal path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use url::Url;

use super::locality;
use super::secrets;

/// A child process that leads its own process group.
pub struct ManagedChild {
    pub child: tokio::process::Child,
    pid: u32,
    stopped: bool,
}

/// How a process group was stopped.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StopReport {
    pub pid: u32,
    /// `already_exited`, `term`, or `kill`.
    pub signal: String,
    /// No process of the group is left.
    pub group_gone: bool,
}

impl ManagedChild {
    /// Spawn `command` as the leader of a new process group.
    pub fn spawn(mut command: tokio::process::Command, what: &str) -> Result<Self> {
        #[cfg(unix)]
        command.process_group(0);
        let child = command.spawn().with_context(|| format!("start {what}"))?;
        let pid = child
            .id()
            .with_context(|| format!("{what} exited immediately"))?;
        Ok(Self {
            child,
            pid,
            stopped: false,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Stop the whole group: SIGTERM, wait up to `grace`, then SIGKILL.
    pub async fn stop(&mut self, grace: Duration) -> StopReport {
        self.stopped = true;
        #[cfg(not(unix))]
        {
            // No process groups: stop the direct child only.
            let _ = self.child.start_kill();
            let _ = tokio::time::timeout(grace, self.child.wait()).await;
            return StopReport {
                pid: self.pid,
                signal: "kill".to_string(),
                group_gone: matches!(self.child.try_wait(), Ok(Some(_))),
            };
        }
        #[cfg(unix)]
        {
            if !group_alive(self.pid) {
                let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
                return StopReport {
                    pid: self.pid,
                    signal: "already_exited".to_string(),
                    group_gone: true,
                };
            }
            signal_group(self.pid, "TERM");
            let mut signal = "term";
            if !wait_group_gone(&mut self.child, self.pid, grace).await {
                signal = "kill";
                signal_group(self.pid, "KILL");
                let _ = self.child.start_kill();
                wait_group_gone(&mut self.child, self.pid, Duration::from_secs(3)).await;
            }
            let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
            StopReport {
                pid: self.pid,
                signal: signal.to_string(),
                group_gone: !group_alive(self.pid),
            }
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.stopped {
            signal_group(self.pid, "KILL");
            let _ = self.child.start_kill();
        }
    }
}

#[cfg(unix)]
async fn wait_group_gone(child: &mut tokio::process::Child, pid: u32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        // Reap the leader as soon as it exits so it does not linger as a zombie.
        let _ = child.try_wait();
        if !group_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Send `signal` (`TERM`, `KILL`, ...) to every process in group `pgid`.
#[cfg(unix)]
pub fn signal_group(pgid: u32, signal: &str) -> bool {
    std::process::Command::new("kill")
        .arg(format!("-{signal}"))
        .arg("--")
        .arg(format!("-{pgid}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(not(unix))]
pub fn signal_group(_pgid: u32, _signal: &str) -> bool {
    false
}

/// Whether any process of group `pgid` is still running.
#[cfg(unix)]
pub fn group_alive(pgid: u32) -> bool {
    signal_group(pgid, "0")
}

#[cfg(not(unix))]
pub fn group_alive(_pgid: u32) -> bool {
    false
}

/// Resolve `dev_env` values: `env:NAME` reads the variable from this
/// process's environment (missing ones are skipped with a warning); anything
/// else is used literally.
pub fn resolve_dev_env(env: &BTreeMap<String, String>) -> (Vec<(String, String)>, Vec<String>) {
    let mut vars = Vec::new();
    let mut warnings = Vec::new();
    for (key, value) in env {
        match value.strip_prefix("env:") {
            Some(name) => match std::env::var(name.trim()) {
                Ok(v) => vars.push((key.clone(), v)),
                Err(_) => warnings.push(format!(
                    "dev_env.{key} references env:{name}, which is not set; skipped"
                )),
            },
            None => vars.push((key.clone(), value.clone())),
        }
    }
    (vars, warnings)
}

/// The project's dev server, started by `map` because the URL was not
/// answering. Output goes to `log_path`.
pub struct DevServer {
    proc: ManagedChild,
    log_path: PathBuf,
}

impl DevServer {
    /// Run `cmd` with `sh -c` in `cwd`, in its own process group. The log
    /// starts with the command, assignment values redacted.
    pub fn spawn(cmd: &str, cwd: &Path, env: &[(String, String)], log_path: &Path) -> Result<Self> {
        Self::spawn_logged(cmd, cwd, env, log_path, false)
    }

    /// Like [`DevServer::spawn`]; `append` keeps the existing log (restarts).
    pub fn spawn_logged(
        cmd: &str,
        cwd: &Path,
        env: &[(String, String)],
        log_path: &Path,
        append: bool,
    ) -> Result<Self> {
        use std::io::Write as _;
        let shown = secrets::redact_command(cmd);
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(log_path)
            .with_context(|| format!("create {}", log_path.display()))?;
        writeln!(
            log,
            "# brokenapp map: {} `{shown}` in {}",
            if append { "restarted" } else { "started" },
            cwd.display()
        )
        .with_context(|| format!("write {}", log_path.display()))?;
        let log_err = log.try_clone().context("clone dev server log handle")?;
        #[cfg(unix)]
        let mut command = {
            let mut c = tokio::process::Command::new("/bin/sh");
            c.arg("-c").arg(cmd);
            c
        };
        #[cfg(not(unix))]
        let mut command = {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(cmd);
            c
        };
        command
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        // Dev servers like CRA open a browser tab unless told not to.
        if !env.iter().any(|(k, _)| k == "BROWSER") {
            command.env("BROWSER", "none");
        }
        for (k, v) in env {
            command.env(k, v);
        }
        let proc = ManagedChild::spawn(command, &format!("dev server `{shown}`"))?;
        Ok(Self {
            proc,
            log_path: log_path.to_path_buf(),
        })
    }

    pub fn pid(&self) -> u32 {
        self.proc.pid()
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Poll `url` until it answers or `timeout` passes. Fails early when the
    /// dev command exits with an error.
    pub async fn wait_ready(&mut self, url: &Url, timeout: Duration) -> Result<Duration> {
        let started = Instant::now();
        let mut exited_ok = false;
        loop {
            if !exited_ok {
                if let Some(status) = self.proc.child.try_wait().context("poll dev server")? {
                    if !status.success() {
                        bail!(
                            "dev server exited ({status}) before {url} answered. Last log lines ({}):\n{}",
                            self.log_path.display(),
                            log_tail(&self.log_path, 15)
                        );
                    }
                    // A wrapper that daemonizes and exits 0: keep waiting for the URL.
                    exited_ok = true;
                }
            }
            if locality::probe(url, Duration::from_secs(5)).await.reachable {
                return Ok(started.elapsed());
            }
            if started.elapsed() >= timeout {
                bail!(
                    "dev server did not answer at {url} within {}s (raise project.ready_timeout_secs). Last log lines ({}):\n{}",
                    timeout.as_secs(),
                    self.log_path.display(),
                    log_tail(&self.log_path, 15)
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn stop(&mut self) -> StopReport {
        self.proc.stop(Duration::from_secs(5)).await
    }

    /// No process of the server's group is left (it crashed or was killed).
    pub fn gone(&mut self) -> bool {
        let _ = self.proc.child.try_wait();
        #[cfg(unix)]
        {
            !group_alive(self.proc.pid())
        }
        #[cfg(not(unix))]
        {
            matches!(self.proc.child.try_wait(), Ok(Some(_)))
        }
    }
}

/// How `map` started the dev server, to start it again the same way.
#[derive(Clone)]
pub struct DevSpec {
    pub cmd: String,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub log: PathBuf,
}

/// The dev server across a (possibly hours-long) map run: started once,
/// restarted with the same command and environment when it dies, stopped at
/// the end. Shared by concurrent role scans.
pub struct DevSupervisor {
    url: Url,
    ready_timeout: Duration,
    server: tokio::sync::Mutex<Option<DevServer>>,
    spec: std::sync::Mutex<Option<DevSpec>>,
    last_check: std::sync::Mutex<Option<Instant>>,
    restarts: std::sync::atomic::AtomicU32,
    warned_down: std::sync::atomic::AtomicBool,
}

/// How often a running scan checks the dev server.
const DEV_CHECK_INTERVAL: Duration = Duration::from_secs(10);

impl DevSupervisor {
    pub fn new(url: Url, ready_timeout: Duration) -> Self {
        Self {
            url,
            ready_timeout,
            server: tokio::sync::Mutex::new(None),
            spec: std::sync::Mutex::new(None),
            last_check: std::sync::Mutex::new(None),
            restarts: std::sync::atomic::AtomicU32::new(0),
            warned_down: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Start the dev server; returns how long it took to answer.
    pub async fn start(&self, spec: DevSpec) -> Result<(Duration, u32)> {
        let mut server = DevServer::spawn(&spec.cmd, &spec.cwd, &spec.env, &spec.log)?;
        let pid = server.pid();
        let waited = match server.wait_ready(&self.url, self.ready_timeout).await {
            Ok(w) => w,
            Err(err) => {
                server.stop().await;
                return Err(err);
            }
        };
        *self.server.lock().await = Some(server);
        if let Ok(mut s) = self.spec.lock() {
            *s = Some(spec);
        }
        Ok((waited, pid))
    }

    pub async fn started(&self) -> bool {
        self.server.lock().await.is_some()
    }

    /// `(pid, log)` of the server `map` started.
    pub async fn info(&self) -> Option<(u32, PathBuf)> {
        self.server
            .lock()
            .await
            .as_ref()
            .map(|s| (s.pid(), s.log_path().to_path_buf()))
    }

    pub fn restarts(&self) -> u32 {
        self.restarts.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Called while a scan runs (at most every 10 s does anything): when the
    /// server `map` started has died and the URL no longer answers, start it
    /// again with the same command and environment. Returns a message to
    /// report (restart, failed restart, or a server `map` does not own going
    /// down), at most once per event.
    pub async fn watch(&self) -> Option<String> {
        {
            let mut last = self.last_check.lock().ok()?;
            if last.is_some_and(|t| t.elapsed() < DEV_CHECK_INTERVAL) {
                return None;
            }
            *last = Some(Instant::now());
        }
        let mut guard = self.server.lock().await;
        let Some(server) = guard.as_mut() else {
            // Not ours: report once when it stops answering.
            if !self.warned_down.load(std::sync::atomic::Ordering::Relaxed)
                && !locality::probe(&self.url, Duration::from_secs(5))
                    .await
                    .reachable
                && !locality::port_open(&self.url).await
            {
                self.warned_down
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return Some(format!(
                    "{} stopped answering during the scan and `map` did not start it, so it cannot restart it; pages visited while it is down are reported as navigation failures",
                    self.url
                ));
            }
            return None;
        };
        if !server.gone()
            || locality::probe(&self.url, Duration::from_secs(5))
                .await
                .reachable
        {
            return None;
        }
        let spec = self.spec.lock().ok()?.clone()?;
        let old = server.pid();
        let _ = server.stop().await;
        let n = self
            .restarts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let shown = secrets::redact_command(&spec.cmd);
        let mut fresh = match DevServer::spawn_logged(
            &spec.cmd, &spec.cwd, &spec.env, &spec.log, true,
        ) {
            Ok(s) => s,
            Err(err) => {
                *guard = None;
                return Some(format!(
                    "dev server (pid {old}) died during the scan and could not be restarted: {err:#}"
                ));
            }
        };
        match fresh.wait_ready(&self.url, self.ready_timeout).await {
            Ok(waited) => {
                let msg = format!(
                    "dev server (pid {old}) died during the scan; restarted `{shown}` (restart {n}, pid {}, ready after {:.1}s); the crawl retries pages that failed meanwhile",
                    fresh.pid(),
                    waited.as_secs_f64()
                );
                *guard = Some(fresh);
                Some(msg)
            }
            Err(err) => {
                fresh.stop().await;
                *guard = None;
                Some(format!(
                    "dev server (pid {old}) died during the scan; restart {n} did not answer: {err:#}"
                ))
            }
        }
    }

    /// Stop the server `map` started (if any).
    pub async fn stop(&self) -> Option<StopReport> {
        let mut guard = self.server.lock().await;
        let server = guard.as_mut()?;
        let report = server.stop().await;
        *guard = None;
        Some(report)
    }
}

/// Last `n` lines of a log file (best effort).
pub fn log_tail(path: &Path, n: usize) -> String {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(n);
    let tail = lines[start..].join("\n");
    if tail.trim().is_empty() {
        "(empty)".to_string()
    } else {
        tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_env_resolves_references() {
        let mut env = BTreeMap::new();
        env.insert("PORT".to_string(), "3100".to_string());
        env.insert("HOME_COPY".to_string(), "env:HOME".to_string());
        env.insert(
            "MISSING".to_string(),
            "env:BROKENAPP_TEST_SURELY_UNSET_VAR".to_string(),
        );
        let (vars, warnings) = resolve_dev_env(&env);
        assert!(vars.contains(&("PORT".to_string(), "3100".to_string())));
        assert!(vars.iter().any(|(k, _)| k == "HOME_COPY"));
        assert!(!vars.iter().any(|(k, _)| k == "MISSING"));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("BROKENAPP_TEST_SURELY_UNSET_VAR"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_kills_the_whole_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("dev.log");
        // A shell that starts a background grandchild, like npm -> node.
        let mut server =
            DevServer::spawn("sleep 30 & sleep 30; wait", dir.path(), &[], &log).unwrap();
        let pgid = server.pid();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(group_alive(pgid));
        let report = server.stop().await;
        assert!(report.group_gone, "{report:?}");
        assert!(!group_alive(pgid));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn drop_kills_the_group() {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c").arg("sleep 30 & sleep 30; wait");
        let child = ManagedChild::spawn(cmd, "test").unwrap();
        let pgid = child.pid();
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(child);
        let deadline = Instant::now() + Duration::from_secs(3);
        while group_alive(pgid) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!group_alive(pgid));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dev_log_header_redacts_inline_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("dev.log");
        let mut server =
            DevServer::spawn("API_TOKEN=hunter2 PORT=3100 true", dir.path(), &[], &log).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        server.stop().await;
        let raw = std::fs::read_to_string(&log).unwrap();
        assert!(raw.contains("API_TOKEN=*** PORT=3100 true"), "{raw}");
        assert!(!raw.contains("hunter2"), "{raw}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supervisor_restarts_a_dead_dev_server_with_the_same_command() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("dev.log");
        // A port of the range reserved for these fixtures.
        let Some(port) = (47290..=47299)
            .rev()
            .find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
        else {
            return;
        };
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        // A tiny HTTP server (python3), killed below to simulate a crash.
        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let cmd = format!("exec python3 -m http.server {port} --bind 127.0.0.1");
        let sup = DevSupervisor::new(url.clone(), Duration::from_secs(20));
        let (_, pid) = sup
            .start(DevSpec {
                cmd: cmd.clone(),
                cwd: dir.path().to_path_buf(),
                env: vec![("RESTART_MARK".into(), "1".into())],
                log: log.clone(),
            })
            .await
            .unwrap();
        assert!(sup.watch().await.is_none(), "healthy server: nothing to do");
        signal_group(pid, "KILL");
        let deadline = Instant::now() + Duration::from_secs(5);
        while group_alive(pid) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Next check is due immediately.
        *sup.last_check.lock().unwrap() = None;
        let msg = sup.watch().await.expect("restart reported");
        assert!(msg.contains("restarted"), "{msg}");
        assert_eq!(sup.restarts(), 1);
        assert!(
            locality::probe(&url, Duration::from_secs(5))
                .await
                .reachable
        );
        let raw = std::fs::read_to_string(&log).unwrap();
        assert!(
            raw.contains("started `") && raw.contains("restarted `"),
            "{raw}"
        );
        let report = sup.stop().await.unwrap();
        assert!(report.group_gone, "{report:?}");
        assert!(sup.stop().await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wait_ready_fails_fast_when_command_exits() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("dev.log");
        let mut server = DevServer::spawn("echo boom >&2; exit 3", dir.path(), &[], &log).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let err = server
            .wait_ready(&url, Duration::from_secs(20))
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("exited"), "{msg}");
        assert!(msg.contains("boom"), "{msg}");
        server.stop().await;
    }
}
