//! Form validation fuzzing — payload library and response classification.
//!
//! Provides a library of fuzzing payloads organized by category (XSS, SQL
//! injection, format bypass, boundary values) and functions to select
//! appropriate payloads based on form field type and classify responses.

use serde::{Deserialize, Serialize};

use crate::types::classifier::FormFieldType;

// ── Payload categories ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadCategory {
    Xss,
    SqlInjection,
    FormatBypass,
    BoundaryValue,
    CommandInjection,
}

/// A fuzzing payload with metadata.
#[derive(Debug, Clone)]
pub struct FuzzingPayload {
    pub category: PayloadCategory,
    pub value: &'static str,
    /// Human-readable description of what this payload tests.
    pub description: &'static str,
}

// ── Payload library ─────────────────────────────────────────────────

const XSS_PAYLOADS: &[FuzzingPayload] = &[
    FuzzingPayload {
        category: PayloadCategory::Xss,
        value: "<script>alert(1)</script>",
        description: "Basic script injection",
    },
    FuzzingPayload {
        category: PayloadCategory::Xss,
        value: "<img src=x onerror=alert(1)>",
        description: "Event handler injection via img",
    },
    FuzzingPayload {
        category: PayloadCategory::Xss,
        value: "javascript:alert(1)",
        description: "JavaScript protocol handler",
    },
    FuzzingPayload {
        category: PayloadCategory::Xss,
        value: "\"><svg onload=alert(1)>",
        description: "Attribute escape with SVG",
    },
    FuzzingPayload {
        category: PayloadCategory::Xss,
        value: "'-alert(1)-'",
        description: "Single-quote context escape",
    },
];

const SQL_INJECTION_PAYLOADS: &[FuzzingPayload] = &[
    FuzzingPayload {
        category: PayloadCategory::SqlInjection,
        value: "' OR '1'='1",
        description: "Classic SQL OR injection",
    },
    FuzzingPayload {
        category: PayloadCategory::SqlInjection,
        value: "1; DROP TABLE users--",
        description: "SQL statement termination with DROP",
    },
    FuzzingPayload {
        category: PayloadCategory::SqlInjection,
        value: "' UNION SELECT NULL,NULL--",
        description: "UNION-based injection probe",
    },
    FuzzingPayload {
        category: PayloadCategory::SqlInjection,
        value: "1' AND '1'='1",
        description: "Boolean-based blind injection",
    },
];

const FORMAT_BYPASS_PAYLOADS: &[FuzzingPayload] = &[
    FuzzingPayload {
        category: PayloadCategory::FormatBypass,
        value: "not-an-email",
        description: "Invalid email format",
    },
    FuzzingPayload {
        category: PayloadCategory::FormatBypass,
        value: "test@.com",
        description: "Email with missing domain",
    },
    FuzzingPayload {
        category: PayloadCategory::FormatBypass,
        value: "12345678901234567890",
        description: "Oversized numeric value",
    },
    FuzzingPayload {
        category: PayloadCategory::FormatBypass,
        value: "-1",
        description: "Negative value for unsigned fields",
    },
    FuzzingPayload {
        category: PayloadCategory::FormatBypass,
        value: "0.000001",
        description: "Very small decimal value",
    },
    FuzzingPayload {
        category: PayloadCategory::FormatBypass,
        value: "NaN",
        description: "NaN string for numeric fields",
    },
];

const BOUNDARY_VALUE_PAYLOADS: &[FuzzingPayload] = &[
    FuzzingPayload {
        category: PayloadCategory::BoundaryValue,
        value: "",
        description: "Empty string",
    },
    FuzzingPayload {
        category: PayloadCategory::BoundaryValue,
        value: " ",
        description: "Single space (whitespace only)",
    },
    FuzzingPayload {
        category: PayloadCategory::BoundaryValue,
        value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        description: "Long string (300+ chars) for buffer overflow",
    },
    FuzzingPayload {
        category: PayloadCategory::BoundaryValue,
        value: "\0",
        description: "Null byte",
    },
    FuzzingPayload {
        category: PayloadCategory::BoundaryValue,
        value: "\t\n\r",
        description: "Control characters",
    },
];

const COMMAND_INJECTION_PAYLOADS: &[FuzzingPayload] = &[
    FuzzingPayload {
        category: PayloadCategory::CommandInjection,
        value: "; ls -la",
        description: "Unix command injection via semicolon",
    },
    FuzzingPayload {
        category: PayloadCategory::CommandInjection,
        value: "| cat /etc/passwd",
        description: "Pipe-based command injection",
    },
    FuzzingPayload {
        category: PayloadCategory::CommandInjection,
        value: "$(whoami)",
        description: "Command substitution",
    },
];

// ── Payload selection ───────────────────────────────────────────────

/// Select appropriate fuzzing payloads for a given form field type.
///
/// Returns payloads ordered by likely relevance. The `max` parameter limits
/// the total number of payloads returned.
pub fn payloads_for_field_type(
    field_type: &FormFieldType,
    max: usize,
) -> Vec<&'static FuzzingPayload> {
    let categories = categories_for_field_type(field_type);
    let mut result = Vec::new();

    for cat in categories {
        let payloads = payloads_for_category(cat);
        for p in payloads {
            if result.len() >= max {
                return result;
            }
            result.push(p);
        }
    }

    result
}

/// Map a field type to the most relevant payload categories in priority order.
fn categories_for_field_type(field_type: &FormFieldType) -> Vec<PayloadCategory> {
    match field_type {
        FormFieldType::Text | FormFieldType::Textarea | FormFieldType::RichText => {
            vec![
                PayloadCategory::Xss,
                PayloadCategory::SqlInjection,
                PayloadCategory::CommandInjection,
                PayloadCategory::BoundaryValue,
            ]
        }
        FormFieldType::Email => {
            vec![
                PayloadCategory::FormatBypass,
                PayloadCategory::Xss,
                PayloadCategory::SqlInjection,
            ]
        }
        FormFieldType::Password => {
            vec![
                PayloadCategory::BoundaryValue,
                PayloadCategory::SqlInjection,
                PayloadCategory::Xss,
            ]
        }
        FormFieldType::Number => {
            vec![
                PayloadCategory::FormatBypass,
                PayloadCategory::BoundaryValue,
                PayloadCategory::SqlInjection,
            ]
        }
        FormFieldType::Url => {
            vec![
                PayloadCategory::Xss,
                PayloadCategory::FormatBypass,
                PayloadCategory::CommandInjection,
            ]
        }
        FormFieldType::Tel
        | FormFieldType::Date
        | FormFieldType::DateTime
        | FormFieldType::Time => {
            vec![
                PayloadCategory::FormatBypass,
                PayloadCategory::BoundaryValue,
            ]
        }
        FormFieldType::Hidden => {
            vec![
                PayloadCategory::SqlInjection,
                PayloadCategory::Xss,
                PayloadCategory::CommandInjection,
            ]
        }
        // Select/Radio/Checkbox: format bypass (out-of-bound values) + injection
        FormFieldType::Select { .. }
        | FormFieldType::MultiSelect { .. }
        | FormFieldType::Radio { .. }
        | FormFieldType::Checkbox
        | FormFieldType::Toggle => {
            vec![PayloadCategory::FormatBypass, PayloadCategory::SqlInjection]
        }
        FormFieldType::File | FormFieldType::Color | FormFieldType::Unknown { .. } => {
            vec![PayloadCategory::BoundaryValue]
        }
    }
}

fn payloads_for_category(category: PayloadCategory) -> &'static [FuzzingPayload] {
    match category {
        PayloadCategory::Xss => XSS_PAYLOADS,
        PayloadCategory::SqlInjection => SQL_INJECTION_PAYLOADS,
        PayloadCategory::FormatBypass => FORMAT_BYPASS_PAYLOADS,
        PayloadCategory::BoundaryValue => BOUNDARY_VALUE_PAYLOADS,
        PayloadCategory::CommandInjection => COMMAND_INJECTION_PAYLOADS,
    }
}

// ── Response classification ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationResult {
    /// The server properly rejected the malicious input (good).
    Rejected,
    /// The server accepted the malicious input (potential vulnerability).
    Accepted,
    /// The server returned a 5xx error (may indicate injection worked).
    ServerError,
    /// The payload was reflected back in the response (XSS/injection risk).
    Reflected,
}

/// Classify a form submission response.
///
/// Returns `Rejected` for 4xx responses (proper validation), `ServerError` for
/// 5xx (potential injection causing crashes), and checks for payload reflection
/// in 2xx responses.
pub fn classify_response(
    status: u16,
    response_body: Option<&str>,
    payload: &str,
) -> ValidationResult {
    // 4xx: server rejected the input — this is correct behavior.
    if (400..500).contains(&status) {
        return ValidationResult::Rejected;
    }

    // 5xx: server error — malicious input may have caused a crash.
    if status >= 500 {
        return ValidationResult::ServerError;
    }

    // 2xx: check if the payload is reflected in the response body.
    if (200..300).contains(&status) {
        if let Some(body) = response_body {
            if !payload.is_empty() && body.contains(payload) {
                return ValidationResult::Reflected;
            }
        }
        return ValidationResult::Accepted;
    }

    // Other statuses (3xx, etc.) — treat as accepted for safety.
    ValidationResult::Accepted
}

/// Determine the bug severity for a form validation issue.
pub fn severity_for_result(
    result: ValidationResult,
    category: PayloadCategory,
) -> crate::types::bugs::BugSeverity {
    use crate::types::bugs::BugSeverity;
    match (result, category) {
        (ValidationResult::Reflected, PayloadCategory::SqlInjection) => BugSeverity::Critical,
        (ValidationResult::Reflected, PayloadCategory::Xss) => BugSeverity::High,
        (ValidationResult::Reflected, PayloadCategory::CommandInjection) => BugSeverity::High,
        (ValidationResult::Reflected, _) => BugSeverity::Medium,
        (ValidationResult::ServerError, PayloadCategory::CommandInjection) => BugSeverity::Critical,
        (ValidationResult::ServerError, PayloadCategory::SqlInjection) => BugSeverity::High,
        (ValidationResult::ServerError, _) => BugSeverity::Medium,
        // "Accepted" is a weak signal for injection classes without reflection
        // or server errors. Many apps legitimately accept arbitrary strings for
        // free-text fields. Keep this low-noise by default.
        (ValidationResult::Accepted, PayloadCategory::FormatBypass) => BugSeverity::Low,
        (ValidationResult::Accepted, PayloadCategory::BoundaryValue) => BugSeverity::Low,
        (ValidationResult::Accepted, _) => BugSeverity::Info,
        (ValidationResult::Rejected, _) => BugSeverity::Info,
    }
}

// ── Total payload count ─────────────────────────────────────────────

pub fn total_payload_count() -> usize {
    XSS_PAYLOADS.len()
        + SQL_INJECTION_PAYLOADS.len()
        + FORMAT_BYPASS_PAYLOADS.len()
        + BOUNDARY_VALUE_PAYLOADS.len()
        + COMMAND_INJECTION_PAYLOADS.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::bugs::BugSeverity;

    // ── Payload library tests ───────────────────────────────────────

    #[test]
    fn payload_count_is_nonzero() {
        assert!(total_payload_count() > 0);
        assert!(XSS_PAYLOADS.len() >= 3);
        assert!(SQL_INJECTION_PAYLOADS.len() >= 3);
        assert!(FORMAT_BYPASS_PAYLOADS.len() >= 3);
        assert!(BOUNDARY_VALUE_PAYLOADS.len() >= 3);
        assert!(COMMAND_INJECTION_PAYLOADS.len() >= 2);
    }

    #[test]
    fn all_payloads_have_descriptions() {
        let all: Vec<&[FuzzingPayload]> = vec![
            XSS_PAYLOADS,
            SQL_INJECTION_PAYLOADS,
            FORMAT_BYPASS_PAYLOADS,
            BOUNDARY_VALUE_PAYLOADS,
            COMMAND_INJECTION_PAYLOADS,
        ];
        for group in all {
            for p in group {
                assert!(
                    !p.description.is_empty(),
                    "payload {:?} has empty description",
                    p.value
                );
            }
        }
    }

    #[test]
    fn xss_payloads_contain_script_or_event() {
        for p in XSS_PAYLOADS {
            assert_eq!(p.category, PayloadCategory::Xss);
            let lower = p.value.to_lowercase();
            assert!(
                lower.contains("script")
                    || lower.contains("alert")
                    || lower.contains("onerror")
                    || lower.contains("onload")
                    || lower.contains("javascript"),
                "XSS payload doesn't look like XSS: {}",
                p.value
            );
        }
    }

    #[test]
    fn sql_payloads_contain_sql_keywords() {
        for p in SQL_INJECTION_PAYLOADS {
            assert_eq!(p.category, PayloadCategory::SqlInjection);
            let upper = p.value.to_uppercase();
            assert!(
                upper.contains("OR")
                    || upper.contains("UNION")
                    || upper.contains("DROP")
                    || upper.contains("AND")
                    || upper.contains("SELECT"),
                "SQLi payload doesn't look like SQL: {}",
                p.value
            );
        }
    }

    // ── Field type → payload mapping ────────────────────────────────

    #[test]
    fn text_field_gets_xss_first() {
        let payloads = payloads_for_field_type(&FormFieldType::Text, 10);
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].category, PayloadCategory::Xss);
    }

    #[test]
    fn email_field_gets_format_bypass_first() {
        let payloads = payloads_for_field_type(&FormFieldType::Email, 10);
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].category, PayloadCategory::FormatBypass);
    }

    #[test]
    fn number_field_gets_format_bypass_first() {
        let payloads = payloads_for_field_type(&FormFieldType::Number, 10);
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].category, PayloadCategory::FormatBypass);
    }

    #[test]
    fn password_field_gets_boundary_first() {
        let payloads = payloads_for_field_type(&FormFieldType::Password, 10);
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].category, PayloadCategory::BoundaryValue);
    }

    #[test]
    fn hidden_field_gets_sqli_first() {
        let payloads = payloads_for_field_type(&FormFieldType::Hidden, 10);
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].category, PayloadCategory::SqlInjection);
    }

    #[test]
    fn url_field_gets_xss_first() {
        let payloads = payloads_for_field_type(&FormFieldType::Url, 10);
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].category, PayloadCategory::Xss);
    }

    #[test]
    fn max_limits_payload_count() {
        let payloads = payloads_for_field_type(&FormFieldType::Text, 3);
        assert_eq!(payloads.len(), 3);
    }

    #[test]
    fn select_field_gets_format_bypass() {
        let payloads = payloads_for_field_type(
            &FormFieldType::Select {
                options: vec!["a".into()],
            },
            5,
        );
        assert!(!payloads.is_empty());
        assert_eq!(payloads[0].category, PayloadCategory::FormatBypass);
    }

    #[test]
    fn textarea_gets_same_as_text() {
        let text_payloads = payloads_for_field_type(&FormFieldType::Text, 5);
        let textarea_payloads = payloads_for_field_type(&FormFieldType::Textarea, 5);
        assert_eq!(text_payloads.len(), textarea_payloads.len());
        for (a, b) in text_payloads.iter().zip(textarea_payloads.iter()) {
            assert_eq!(a.category, b.category);
            assert_eq!(a.value, b.value);
        }
    }

    // ── Response classification ─────────────────────────────────────

    #[test]
    fn classify_400_is_rejected() {
        assert_eq!(
            classify_response(400, Some("Bad Request"), "<script>alert(1)</script>"),
            ValidationResult::Rejected
        );
    }

    #[test]
    fn classify_422_is_rejected() {
        assert_eq!(
            classify_response(422, Some("Validation failed"), "test"),
            ValidationResult::Rejected
        );
    }

    #[test]
    fn classify_500_is_server_error() {
        assert_eq!(
            classify_response(500, Some("Internal Server Error"), "test"),
            ValidationResult::ServerError
        );
    }

    #[test]
    fn classify_200_with_reflected_payload_is_reflected() {
        let payload = "<script>alert(1)</script>";
        let body = format!("Welcome, {payload}!");
        assert_eq!(
            classify_response(200, Some(&body), payload),
            ValidationResult::Reflected
        );
    }

    #[test]
    fn classify_200_without_reflection_is_accepted() {
        assert_eq!(
            classify_response(200, Some("Success"), "<script>alert(1)</script>"),
            ValidationResult::Accepted
        );
    }

    #[test]
    fn classify_200_no_body_is_accepted() {
        assert_eq!(
            classify_response(200, None, "test"),
            ValidationResult::Accepted
        );
    }

    #[test]
    fn classify_empty_payload_is_accepted_not_reflected() {
        assert_eq!(
            classify_response(200, Some("any content"), ""),
            ValidationResult::Accepted
        );
    }

    #[test]
    fn classify_302_is_accepted() {
        assert_eq!(
            classify_response(302, None, "test"),
            ValidationResult::Accepted
        );
    }

    // ── Severity mapping ────────────────────────────────────────────

    #[test]
    fn reflected_xss_is_high() {
        assert_eq!(
            severity_for_result(ValidationResult::Reflected, PayloadCategory::Xss),
            BugSeverity::High
        );
    }

    #[test]
    fn reflected_sqli_is_critical() {
        assert_eq!(
            severity_for_result(ValidationResult::Reflected, PayloadCategory::SqlInjection),
            BugSeverity::Critical
        );
    }

    #[test]
    fn server_error_sqli_is_high() {
        assert_eq!(
            severity_for_result(ValidationResult::ServerError, PayloadCategory::SqlInjection),
            BugSeverity::High
        );
    }

    #[test]
    fn server_error_cmd_injection_is_critical() {
        assert_eq!(
            severity_for_result(
                ValidationResult::ServerError,
                PayloadCategory::CommandInjection
            ),
            BugSeverity::Critical
        );
    }

    #[test]
    fn accepted_xss_is_info() {
        assert_eq!(
            severity_for_result(ValidationResult::Accepted, PayloadCategory::Xss),
            BugSeverity::Info
        );
    }

    #[test]
    fn accepted_boundary_is_low() {
        assert_eq!(
            severity_for_result(ValidationResult::Accepted, PayloadCategory::BoundaryValue),
            BugSeverity::Low
        );
    }

    #[test]
    fn rejected_anything_is_info() {
        assert_eq!(
            severity_for_result(ValidationResult::Rejected, PayloadCategory::Xss),
            BugSeverity::Info
        );
        assert_eq!(
            severity_for_result(ValidationResult::Rejected, PayloadCategory::SqlInjection),
            BugSeverity::Info
        );
    }

    // ── Category mapping completeness ───────────────────────────────

    #[test]
    fn all_field_types_return_payloads() {
        let types = vec![
            FormFieldType::Text,
            FormFieldType::Email,
            FormFieldType::Password,
            FormFieldType::Number,
            FormFieldType::Tel,
            FormFieldType::Url,
            FormFieldType::Date,
            FormFieldType::DateTime,
            FormFieldType::Time,
            FormFieldType::Color,
            FormFieldType::File,
            FormFieldType::Hidden,
            FormFieldType::Textarea,
            FormFieldType::Select { options: vec![] },
            FormFieldType::MultiSelect { options: vec![] },
            FormFieldType::Checkbox,
            FormFieldType::Radio {
                group: None,
                options: vec![],
            },
            FormFieldType::Toggle,
            FormFieldType::RichText,
            FormFieldType::Unknown {
                raw_type: "range".into(),
            },
        ];
        for ft in &types {
            let payloads = payloads_for_field_type(ft, 100);
            assert!(!payloads.is_empty(), "field type {:?} has no payloads", ft);
        }
    }
}
