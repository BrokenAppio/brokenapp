use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn cmd_stdout(cmd: &mut Command) -> Option<String> {
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn git_path(args: &[&str]) -> Option<PathBuf> {
    let raw = cmd_stdout(Command::new("git").args(args))?;
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        Some(path)
    } else {
        env::current_dir().ok().map(|cwd| cwd.join(path))
    }
}

fn rerun_if_exists(path: impl AsRef<Path>) {
    let path = path.as_ref();
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    let pkg = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let sha = cmd_stdout(Command::new("git").args(["rev-parse", "--short", "HEAD"]));
    let dirty =
        cmd_stdout(Command::new("git").args(["status", "--porcelain", "--untracked-files=no"]))
            .map(|s| !s.is_empty())
            .unwrap_or(false);

    let build_version = match sha {
        Some(sha) => {
            if dirty {
                format!("{pkg}+{sha}.dirty")
            } else {
                format!("{pkg}+{sha}")
            }
        }
        None => pkg,
    };
    println!("cargo:rustc-env=BROKENAPP_BUILD_VERSION={build_version}");

    let build_timestamp = match env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(epoch) => {
            let st = UNIX_EPOCH + Duration::from_secs(epoch);
            let dt: chrono::DateTime<chrono::Utc> = st.into();
            dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }
        None => {
            let dt: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
            dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }
    };
    println!("cargo:rustc-env=BROKENAPP_BUILD_TIMESTAMP={build_timestamp}");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let git_dir = git_path(&["rev-parse", "--git-dir"]);
    let git_common_dir = git_path(&["rev-parse", "--git-common-dir"]);

    if let Some(dir) = &git_dir {
        rerun_if_exists(dir.join("HEAD"));
        rerun_if_exists(dir.join("index"));
    }
    if let Some(dir) = &git_common_dir {
        rerun_if_exists(dir.join("index"));
        rerun_if_exists(dir.join("packed-refs"));
    }
    if let Some(head_ref) = cmd_stdout(Command::new("git").args(["symbolic-ref", "-q", "HEAD"])) {
        if let Some(dir) = &git_common_dir {
            rerun_if_exists(dir.join(head_ref));
        }
    }
}
