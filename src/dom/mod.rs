pub mod classifier;
mod classify_js;
pub mod discovery;
pub mod effects;
pub mod fingerprint;
pub mod heuristics;
pub mod interaction;
pub mod interaction_signals;
pub mod selector;
pub mod snapshot;

pub use discovery::discover_elements_in_subtree;
pub use discovery::discover_interactive_elements;
pub use fingerprint::fingerprint_dom;
