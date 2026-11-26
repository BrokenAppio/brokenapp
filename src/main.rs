use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use brokenapp::front::{self, FrontCommand};

fn build_version_string() -> &'static str {
    concat!(
        env!("BROKENAPP_BUILD_VERSION"),
        " (built ",
        env!("BROKENAPP_BUILD_TIMESTAMP"),
        ")"
    )
}

#[derive(Debug, Parser)]
#[command(
    name = "brokenapp",
    version = build_version_string(),
    about = "A map of what your web app actually does — per login role, traced to source, with a write guard on by default.",
    after_help = "\
Quick start:
  brokenapp init --url http://127.0.0.1:3000 --dev-cmd \"npm run dev\"
  brokenapp map                        # standard baseline (10m / 80 views, write-guarded)
  brokenapp ui --route / --compact     # instant read (<0.2s, no browser)
  brokenapp map --changed              # incremental re-crawl after edits
  brokenapp changes --role all         # behavioral + role-access diff

Deep SPA / customer journeys (opt-in, not default):
  brokenapp map --full --depth 6       # uncapped whole-app SPA crawl
  brokenapp journey \"POST /api/orders\" # multi-step route + modal/wizard path

Environment:
  BROKENAPP_HOME               Global registry & settings dir (default: ~/.brokenapp)
  BROKENAPP_STATE_DIR          Override project state directory (default: .brokenapp)
  BROKENAPP_CHROME_EXECUTABLE  Path to Chrome/Chromium binary (overrides auto-detection)"
)]
struct Cli {
    /// Increase log verbosity (-v = info, -vv = debug, -vvv = trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(flatten)]
    Front(FrontCommand),

    /// Internal crawl worker invoked by `brokenapp map` for process isolation.
    #[command(name = "scan", hide = true)]
    InternalScan(InternalScanArgs),

    /// Internal checkpoint-resume worker invoked by `brokenapp map --resume`.
    #[command(name = "resume", hide = true)]
    InternalResume(InternalResumeArgs),
}

#[derive(Debug, Args)]
struct InternalScanArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    progress_file: Option<PathBuf>,
    #[arg(long)]
    auth_path: Option<String>,
    /// Accepted for backwards compatibility with older callers; ignored.
    #[arg(long = "store-import", hide = true)]
    _store_import: Option<String>,
}

#[derive(Debug, Args)]
struct InternalResumeArgs {
    checkpoint: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    progress_file: Option<PathBuf>,
    /// Accepted for backwards compatibility with older callers; ignored.
    #[arg(long = "store-import", hide = true)]
    _store_import: Option<String>,
}

fn init_logging(verbose: u8) {
    let default_level = match verbose {
        0 => "warn,chromiumoxide::handler=error,chromiumoxide::conn=error",
        1 => "info,chromiumoxide::handler=error,chromiumoxide::conn=error",
        2 => "debug,chromiumoxide::handler=error,chromiumoxide::conn=error",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

fn scan_json_summary(out: &brokenapp::ScanOutcome) -> serde_json::Value {
    let run_report: Option<serde_json::Value> = std::fs::read_to_string(
        out.output_dir
            .join(brokenapp::explorer::run_report::RUN_REPORT_FILE),
    )
    .ok()
    .and_then(|raw| serde_json::from_str(&raw).ok());
    let mut doc = serde_json::json!({
        "status": out.completion_status.as_str(),
        "target_url": out.target_url,
        "duration_seconds": out.scan_duration_seconds,
        "views": out.views.len(),
        "endpoints": out.endpoints.len(),
        "bugs": out.bugs.len(),
        "artifacts": {
            "output_dir": out.output_dir.display().to_string(),
        }
    });
    if let Some(run) = run_report {
        doc["run"] = run;
    }
    doc
}

fn exit_code_for_outcome(out: &brokenapp::ScanOutcome) -> i32 {
    if out.completion_status == "interrupted" {
        return brokenapp::explorer::interrupt::last_signal()
            .map(|kind| kind.exit_code())
            .unwrap_or(130);
    }
    0
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let wants_json = matches!(&cli.command, Command::Front(c) if c.wants_json());
    let result: Result<i32> = match cli.command {
        Command::Front(cmd) => front::run(cmd).await,
        Command::InternalScan(args) => run_internal_scan(args).await,
        Command::InternalResume(args) => run_internal_resume(args).await,
    };

    match result {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(err) => {
            let msg = format!("{err:#}");
            eprintln!("error: {msg}");
            if wants_json {
                let doc = serde_json::json!({
                    "exit_code": 1,
                    "status": "error",
                    "error": msg,
                });
                if let Ok(raw) = serde_json::to_string_pretty(&doc) {
                    println!("{raw}");
                }
            }
            std::process::exit(1);
        }
    }
}

async fn run_internal_scan(args: InternalScanArgs) -> Result<i32> {
    let mut cfg = brokenapp::BrokenAppConfig::from_toml_path(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;
    if let Some(auth_path) = args.auth_path {
        cfg.scan.auth_path = Some(auth_path);
        cfg.resolve_auth_path()?;
    }
    if args.progress_file.is_some() {
        cfg.output.progress_file = args.progress_file;
    }
    let opts = brokenapp::explorer::ScanRunOptions {
        handle_signals: true,
        progress_file: cfg.output.progress_file.clone(),
    };
    let out = brokenapp::explorer::run_scan_with_options(cfg, opts).await?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&scan_json_summary(&out))
                .context("serialize scan summary")?
        );
    }
    Ok(exit_code_for_outcome(&out))
}

async fn run_internal_resume(args: InternalResumeArgs) -> Result<i32> {
    let opts = brokenapp::explorer::ScanRunOptions {
        handle_signals: true,
        progress_file: args.progress_file,
    };
    let out = brokenapp::explorer::resume_scan_with_options(args.checkpoint, opts).await?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&scan_json_summary(&out))
                .context("serialize resume summary")?
        );
    }
    Ok(exit_code_for_outcome(&out))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn cli_help_documents_key_environment_variables() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("BROKENAPP_HOME"), "{help}");
        assert!(help.contains("BROKENAPP_STATE_DIR"), "{help}");
        assert!(help.contains("BROKENAPP_CHROME_EXECUTABLE"), "{help}");
    }
}
