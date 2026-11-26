use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

pub(super) fn load_route_seed_file(path: &Path) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read route seed file {}", path.display()))?;
    let trimmed = raw.trim_start();
    let mut seeds = Vec::new();

    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let value: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse route seed JSON {}", path.display()))?;
        collect_json_route_seeds(&value, &mut seeds);
    } else {
        seeds.extend(raw.lines().filter_map(parse_seed_line));
    }

    let mut deduped = BTreeSet::new();
    for seed in seeds {
        let seed = seed.trim();
        if is_route_seed(seed) {
            deduped.insert(seed.to_string());
        }
    }

    Ok(deduped.into_iter().collect())
}

fn parse_seed_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    Some(line.to_string())
}

fn collect_json_route_seeds(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            if is_route_seed(s) {
                out.push(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_json_route_seeds(item, out);
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                if is_route_key(key) {
                    collect_json_route_seeds(value, out);
                } else if matches!(value, Value::Array(_) | Value::Object(_)) {
                    collect_json_route_seeds(value, out);
                }
            }
        }
        _ => {}
    }
}

fn is_route_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|ch| *ch != '_' && *ch != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "route"
            | "routes"
            | "path"
            | "paths"
            | "pathname"
            | "routepath"
            | "url"
            | "urls"
            | "href"
            | "page"
            | "pages"
            | "view"
            | "views"
            | "seedurl"
            | "seedurls"
            | "routeseed"
            | "routeseeds"
    )
}

fn is_route_seed(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    trimmed.starts_with('/') || trimmed.starts_with("http://") || trimmed.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::load_route_seed_file;

    #[test]
    fn loads_newline_route_seed_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.txt");
        std::fs::write(
            &path,
            "\n# curated app routes\n/staff/deals\n/staff/tasks\nhttps://app.example.com/admin\n",
        )
        .unwrap();

        let seeds = load_route_seed_file(&path).unwrap();

        assert_eq!(
            seeds,
            vec![
                "/staff/deals".to_string(),
                "/staff/tasks".to_string(),
                "https://app.example.com/admin".to_string(),
            ]
        );
    }

    #[test]
    fn loads_json_route_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.json");
        std::fs::write(
            &path,
            r#"{
              "routes": [
                "/dashboard",
                { "path": "/staff/deals" },
                { "routePath": "/staff/tasks" }
              ],
              "frontendNodes": [
                { "nodeType": "page", "url": "https://app.example.com/reports" }
              ],
              "metadata": { "name": "not-a-route" }
            }"#,
        )
        .unwrap();

        let seeds = load_route_seed_file(&path).unwrap();

        assert_eq!(
            seeds,
            vec![
                "/dashboard".to_string(),
                "/staff/deals".to_string(),
                "/staff/tasks".to_string(),
                "https://app.example.com/reports".to_string(),
            ]
        );
    }
}
