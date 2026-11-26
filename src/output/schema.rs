//! Schema helpers for serialized JSON artifacts.
//!
//! We keep schema URLs centralized so report structs can use `serde(default = ...)`
//! without duplicating strings everywhere.

pub fn tool_version() -> String {
    env!("BROKENAPP_BUILD_VERSION").to_string()
}

pub fn scan_checkpoint_v1() -> String {
    "https://brokenapp.dev/schemas/scan-checkpoint-v1.json".to_string()
}

pub fn bug_report_v1() -> String {
    "https://brokenapp.dev/schemas/bug-report-v1.json".to_string()
}

pub fn finding_quality_report_v1() -> String {
    "https://brokenapp.dev/schemas/finding-quality-report-v1.json".to_string()
}

pub fn security_report_v1() -> String {
    "https://brokenapp.dev/schemas/security-report-v1.json".to_string()
}

pub fn compliance_report_v1() -> String {
    "https://brokenapp.dev/schemas/compliance-report-v1.json".to_string()
}

pub fn compliance_report_v2() -> String {
    "https://brokenapp.dev/schemas/compliance-report-v2.json".to_string()
}

pub fn exposure_report_v1() -> String {
    "https://brokenapp.dev/schemas/exposure-report-v1.json".to_string()
}

pub fn idor_report_v1() -> String {
    "https://brokenapp.dev/schemas/idor-report-v1.json".to_string()
}

pub fn auth_matrix_report_v1() -> String {
    "https://brokenapp.dev/schemas/auth-matrix-report-v1.json".to_string()
}

pub fn logic_test_report_v1() -> String {
    "https://brokenapp.dev/schemas/logic-test-report-v1.json".to_string()
}

pub fn ui_consistency_report_v1() -> String {
    "https://brokenapp.dev/schemas/ui-consistency-report-v1.json".to_string()
}

pub fn layout_consistency_report_v1() -> String {
    "https://brokenapp.dev/schemas/layout-consistency-report-v1.json".to_string()
}

pub fn accessibility_report_v1() -> String {
    "https://brokenapp.dev/schemas/accessibility-report-v1.json".to_string()
}
