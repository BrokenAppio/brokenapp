//! Runtime template loader for Nuclei-style passive checks.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::bugs::custom_rules::{CustomRule, RuleMatcher};

#[derive(Debug, Deserialize)]
struct RuntimeTemplate {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    info: TemplateInfo,
    #[serde(default)]
    http: Vec<HttpBlock>,
}

#[derive(Debug, Default, Deserialize)]
struct TemplateInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    remediation: Option<String>,
    #[serde(default)]
    cwe: Option<String>,
    #[serde(default)]
    owasp: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct HttpBlock {
    #[serde(default)]
    path: TemplatePaths,
    #[serde(default)]
    matchers: Vec<TemplateMatcher>,
}

#[derive(Debug, Default)]
struct TemplatePaths(Vec<String>);

impl<'de> Deserialize<'de> for TemplatePaths {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum PathValue {
            One(String),
            Many(Vec<String>),
        }

        Ok(match Option::<PathValue>::deserialize(deserializer)? {
            Some(PathValue::One(path)) => Self(vec![path]),
            Some(PathValue::Many(paths)) => Self(paths),
            None => Self::default(),
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct TemplateMatcher {
    #[serde(rename = "type")]
    matcher_type: String,
    #[serde(default)]
    header: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    expected_value: Option<String>,
    #[serde(default)]
    part: Option<String>,
    #[serde(default)]
    words: Vec<String>,
}

/// Load supported Nuclei-style runtime templates from files or directories.
///
/// Supported matcher subset:
/// - `missing_header` with `header` or `name`
/// - `word` with `part: body` or an omitted part
pub fn load_runtime_templates(paths: &[PathBuf]) -> Result<Vec<CustomRule>> {
    let mut files = Vec::new();
    for path in paths {
        collect_template_files(path, &mut files)?;
    }
    files.sort();

    let mut rules = Vec::new();
    for file in files {
        let raw =
            std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
        let template: RuntimeTemplate = serde_yaml::from_str(&raw)
            .with_context(|| format!("parse runtime template {}", file.display()))?;
        rules.extend(template.into_rules(&file));
    }

    Ok(rules)
}

impl RuntimeTemplate {
    fn into_rules(self, source: &Path) -> Vec<CustomRule> {
        let base_name = self
            .info
            .name
            .clone()
            .or_else(|| self.id.clone())
            .unwrap_or_else(|| {
                source
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .unwrap_or("Runtime template")
                    .to_string()
            });
        let severity = self.info.severity.unwrap_or_else(|| "medium".to_string());

        let mut rules = Vec::new();
        for block in self.http {
            let paths = if block.path.0.is_empty() {
                vec![None]
            } else {
                block.path.0.into_iter().map(Some).collect()
            };

            for matcher in block.matchers {
                for path_pattern in &paths {
                    let Some(rule_matcher) = matcher.to_rule_matcher(path_pattern.clone()) else {
                        continue;
                    };
                    rules.push(CustomRule {
                        name: base_name.clone(),
                        category: Some("runtime_template".to_string()),
                        severity: severity.clone(),
                        description: self.info.description.clone(),
                        remediation: self.info.remediation.clone(),
                        cwe: self.info.cwe.clone(),
                        owasp: self.info.owasp.clone(),
                        matcher: rule_matcher,
                    });
                }
            }
        }

        rules
    }
}

impl TemplateMatcher {
    fn to_rule_matcher(&self, path_pattern: Option<String>) -> Option<RuleMatcher> {
        match self.matcher_type.as_str() {
            "missing_header" => {
                let header_name = self.header.clone().or_else(|| self.name.clone())?;
                Some(RuleMatcher::MissingHeader {
                    path_pattern,
                    header_name,
                    expected_value: self.expected_value.clone(),
                })
            }
            "word" => {
                let part = self.part.as_deref().unwrap_or("body");
                if !part.eq_ignore_ascii_case("body") {
                    return None;
                }
                let body_pattern = self
                    .words
                    .iter()
                    .filter(|word| !word.is_empty())
                    .map(|word| regex::escape(word))
                    .collect::<Vec<_>>()
                    .join("|");
                if body_pattern.is_empty() {
                    return None;
                }
                Some(RuleMatcher::ResponseBody {
                    path_pattern,
                    body_pattern,
                })
            }
            _ => None,
        }
    }
}

fn collect_template_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if is_yaml_file(path) {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        anyhow::bail!("runtime template path does not exist: {}", path.display());
    }

    let mut entries = std::fs::read_dir(path)
        .with_context(|| format!("read runtime template directory {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("read entries in {}", path.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        collect_template_files(&entry.path(), files)?;
    }

    Ok(())
}

fn is_yaml_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext, "yaml" | "yml"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::bugs::custom_rules::RuleMatcher;

    #[test]
    fn loads_nuclei_like_missing_header_template() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing-csp.yaml");
        std::fs::write(
            &path,
            r#"
id: missing-csp
info:
  name: Missing Content-Security-Policy
  severity: medium
  description: Adds CSP parity with ZAP/Nuclei passive checks.
  remediation: Add a Content-Security-Policy response header.
http:
  - path:
      - "*"
    matchers:
      - type: missing_header
        header: content-security-policy
"#,
        )
        .expect("write template");

        let rules = super::load_runtime_templates(&[path]).expect("load templates");

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Missing Content-Security-Policy");
        match &rules[0].matcher {
            RuleMatcher::MissingHeader {
                header_name,
                path_pattern,
                ..
            } => {
                assert_eq!(header_name, "content-security-policy");
                assert_eq!(path_pattern.as_deref(), Some("*"));
            }
            other => panic!("unexpected matcher: {other:?}"),
        }
    }

    #[test]
    fn loads_nuclei_like_body_word_template() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("debug-token.yaml");
        std::fs::write(
            &path,
            r#"
id: debug-token
info:
  name: Debug token exposed
  severity: high
http:
  - path:
      - "/debug*"
    matchers:
      - type: word
        part: body
        words:
          - "DEBUG_TOKEN="
"#,
        )
        .expect("write template");

        let rules = super::load_runtime_templates(&[path]).expect("load templates");

        assert_eq!(rules.len(), 1);
        match &rules[0].matcher {
            RuleMatcher::ResponseBody {
                path_pattern,
                body_pattern,
            } => {
                assert_eq!(path_pattern.as_deref(), Some("/debug*"));
                assert!(body_pattern.contains("DEBUG_TOKEN="));
            }
            other => panic!("unexpected matcher: {other:?}"),
        }
    }
}
