use std::sync::Mutex;

/// Chrome-based integration tests share a browser/runtime; serialize them so
/// concurrent scans do not race on headless Chrome timing.
pub(crate) static BROWSER_TEST_LOCK: Mutex<()> = Mutex::new(());

mod compliance_guardrails_test;
mod config_auth_aliases_test;
mod front_cli_test;
mod long_run_roles_test;
mod runtime_fixture_contract_test;
mod ui_map_crawl_test;
mod ui_map_inventory_test;
mod v1_cli_contract_test;
mod write_guard_test;
mod ws_toast_modal_test;
