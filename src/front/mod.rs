//! Front-door commands: the small, agent-friendly CLI surface.
//!
//! `init` sets a project up, `map` scans the running app (write-guarded) and
//! refreshes the greppable UI map + changelog (one per login role), and the
//! read commands (`ui`, `dead`, `journey`, `changes`, `projects`) answer
//! questions from the latest map without touching the app. `roles` and
//! `login` manage login roles; `doctor` checks the install.

use anyhow::Result;
use clap::Subcommand;

pub mod changed;
pub mod changes_gate;
pub mod detect;
pub mod doctor;
pub mod feedback;
pub mod impact;
pub mod init;
pub mod locality;
pub mod login_check;
pub mod map;
pub mod parity_cmd;
pub mod process;
pub mod project;
pub mod projects;
pub mod read;
pub mod role_access;
pub mod roles;
pub mod roles_cmd;
pub mod run_state;
pub mod scan_facts;
pub mod secrets;
pub mod warmup;

#[derive(Debug, Subcommand)]
pub enum FrontCommand {
    /// Setup: initialize a project (.brokenapp/config.toml, registry, agent instructions).
    Init(init::InitArgs),
    /// Crawl: scan the running app (write-guarded) and refresh the UI map + changelog in .brokenapp/map/.
    Map(map::MapArgs),
    /// Read (<0.2s, no browser): list UI controls and what they do (filter by route, text, status, endpoint).
    Ui(read::UiArgs),
    /// Read (<0.2s, no browser): list dead, broken, and not-exercised UI from the latest map.
    Dead(read::DeadArgs),
    /// Read (<0.2s, no browser): find multi-step route + modal/wizard paths to a route, endpoint, or label.
    Journey(read::JourneyArgs),
    /// Read (<0.2s, no browser): diff behavioral & role-access changes between maps (with optional CI `--fail-on` gate).
    Changes(read::ChangesArgs),
    /// Read (<0.2s, no browser): compare behavioral parity between two apps or map snapshots.
    Parity(parity_cmd::ParityArgs),
    /// Read (<0.2s, no browser): list registered projects and their last map.
    Projects(projects::ProjectsArgs),
    /// Setup: check Chrome, binary, project config, target reachability, and role readiness.
    Doctor(doctor::DoctorArgs),
    /// Setup: list, add, or remove login roles (admin, user, ...) that `map` maps besides anonymous.
    Roles(roles_cmd::RolesArgs),
    /// Setup: sign in as a role (save a browser session for session/manual, or verify a form login).
    Login(roles_cmd::LoginArgs),
    /// Opt-in: preview or queue sanitized feedback from you or your AI agent (zero background telemetry).
    Feedback(feedback::FeedbackArgs),
}

impl FrontCommand {
    /// Whether the command was asked for machine-readable JSON output.
    pub fn wants_json(&self) -> bool {
        match self {
            FrontCommand::Init(a) => a.json,
            FrontCommand::Map(a) => a.json,
            FrontCommand::Ui(a) => a.json || a.compact || a.format.eq_ignore_ascii_case("json"),
            FrontCommand::Dead(a) => a.json,
            FrontCommand::Journey(a) => a.json || a.format.eq_ignore_ascii_case("json"),
            FrontCommand::Changes(a) => a.json || a.format.eq_ignore_ascii_case("json"),
            FrontCommand::Parity(a) => a.wants_json(),
            FrontCommand::Projects(a) => a.json,
            FrontCommand::Doctor(a) => a.json,
            FrontCommand::Roles(a) => a.wants_json(),
            FrontCommand::Login(a) => a.json,
            FrontCommand::Feedback(a) => a.json,
        }
    }
}

/// Run a front-door command. Returns the process exit code.
pub async fn run(cmd: FrontCommand) -> Result<i32> {
    match cmd {
        FrontCommand::Init(a) => init::run(a).await,
        FrontCommand::Map(a) => map::run(a).await,
        FrontCommand::Ui(a) => read::run_ui(a).await,
        FrontCommand::Dead(a) => read::run_dead(a).await,
        FrontCommand::Journey(a) => read::run_journey(a).await,
        FrontCommand::Changes(a) => read::run_changes(a).await,
        FrontCommand::Parity(a) => parity_cmd::run(a).await,
        FrontCommand::Projects(a) => projects::run(a).await,
        FrontCommand::Doctor(a) => doctor::run(a).await,
        FrontCommand::Roles(a) => roles_cmd::run(a).await,
        FrontCommand::Login(a) => roles_cmd::run_login(a).await,
        FrontCommand::Feedback(a) => feedback::run(a).await,
    }
}
