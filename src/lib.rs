//! BrokenApp: write-guarded behavioral map and multi-role diff engine for web apps.
//!
//! The CLI binary entrypoint lives in `src/main.rs`.

pub mod browser;
pub mod bugs;
pub mod code_link;
pub mod config;
pub mod dom;
pub mod explorer;
pub mod finding_judgment;
pub mod front;
pub mod inventory;
pub mod network;
pub mod output;
pub mod route_discovery;
pub mod safety;
pub mod scope;
pub mod session;
pub mod types;
pub mod url_origin;

pub use crate::config::BrokenAppConfig;
pub use crate::explorer::{ScanOutcome, resume_scan, run_scan};
