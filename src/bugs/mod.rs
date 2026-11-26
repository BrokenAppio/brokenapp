pub mod accessibility;
pub mod broken_links;
pub mod console_errors;
pub mod custom_rules;
pub mod dead_buttons;
pub mod detector;
pub mod form_fuzz_replay;
pub mod form_validation;
pub mod passive_headers;
pub mod performance;
pub mod runtime_templates;
pub mod server_errors;
pub mod ui_errors;

pub use detector::BugDetector;
