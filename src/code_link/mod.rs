//! Code-to-spec linking.
//!
//! MVP: best-effort static analysis that finds likely code locations for API
//! endpoints observed during a scan.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use chrono::Utc;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::network::path_parameterizer::path_to_template;

pub mod runtime_source;
pub mod static_source;

#[derive(Debug, Clone)]
pub struct LinkCodeOptions {
    pub max_results_per_endpoint: usize,
    pub max_file_bytes: u64,
    pub include_snippets: bool,
}

impl Default for LinkCodeOptions {
    fn default() -> Self {
        Self {
            max_results_per_endpoint: 8,
            max_file_bytes: 2_000_000,
            include_snippets: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub score: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSurfaceHint {
    pub method_hint: Option<String>,
    pub path_template: String,
    pub sample_path: String,
    pub confidence: String,
    pub locations: Vec<CodeLocation>,
}

#[derive(Debug, Clone)]
struct EndpointDescriptor {
    pointer: String,
    method: String,
    path: String,
}

#[derive(Debug, Clone)]
struct EndpointPattern {
    method: String,
    top_segment_hint: String,
    template_re: Regex,
    runtime_re: Regex,
    prefix: String,
    suffix: String,
}

#[derive(Debug, Default, Clone)]
struct SourceSurfaceHintAgg {
    sample_path: String,
    confidence_rank: u8,
    locations: Vec<CodeLocation>,
}

pub async fn link_code(
    spec_path: &Path,
    codebase_path: &Path,
    output: Option<&Path>,
    opts: LinkCodeOptions,
) -> Result<PathBuf> {
    let raw = tokio::fs::read_to_string(spec_path)
        .await
        .with_context(|| format!("read {}", spec_path.display()))?;
    let mut spec: Value = serde_json::from_str(&raw).context("parse spec json")?;

    let endpoints = extract_endpoints(&spec)?;

    let patterns = endpoints
        .iter()
        .map(|e| build_endpoint_pattern(&e.method, &e.path))
        .collect::<Result<Vec<_>>>()?;

    let mut findings: Vec<Vec<CodeLocation>> = vec![Vec::new(); patterns.len()];
    let observed_method_paths: BTreeSet<(String, String)> = endpoints
        .iter()
        .map(|e| {
            (
                e.method.trim().to_ascii_uppercase(),
                normalize_source_path_template(&e.path),
            )
        })
        .collect();
    let observed_paths: BTreeSet<String> = observed_method_paths
        .iter()
        .map(|(_, p)| p.clone())
        .collect();
    let mut source_surface_hints: BTreeMap<(Option<String>, String), SourceSurfaceHintAgg> =
        BTreeMap::new();

    let files = collect_files(codebase_path)?;
    let mut files_scanned = 0usize;
    let mut lines_scanned = 0usize;

    for file in files {
        let md = match std::fs::metadata(&file) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.len() > opts.max_file_bytes {
            continue;
        }

        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.iter().any(|b| *b == 0) {
            continue; // likely binary
        }

        let text = String::from_utf8_lossy(&bytes);
        files_scanned += 1;

        let rel_file = path_rel(codebase_path, &file);
        for (idx, locs) in extract_nest_route_locations(
            codebase_path,
            &file,
            &rel_file,
            &text,
            &endpoints,
            opts.include_snippets,
        ) {
            for loc in locs {
                push_unique_location(&mut findings[idx], loc, usize::MAX);
            }
        }
        for (idx, locs) in
            extract_express_route_locations(&rel_file, &text, &endpoints, opts.include_snippets)
        {
            for loc in locs {
                push_unique_location(&mut findings[idx], loc, usize::MAX);
            }
        }

        for (line_idx, line) in text.lines().enumerate() {
            let line_no = line_idx + 1;
            lines_scanned += 1;

            // Fast prefilter: most endpoint paths start with "/api" or "/graphql".
            // If this line doesn't mention either, avoid any regex work.
            if !line.contains("/api")
                && !line.contains("/graphql")
                && !line.to_ascii_lowercase().contains("graphql")
            {
                continue;
            }

            let method_hint = infer_source_method_hint(line);
            let confidence_rank = source_hint_confidence_rank(line, method_hint.as_deref());
            for raw_path in extract_source_paths(line) {
                let path_template = normalize_source_path_template(&raw_path);
                let key = (method_hint.clone(), path_template);
                let entry = source_surface_hints.entry(key).or_default();
                if entry.sample_path.is_empty() {
                    entry.sample_path = raw_path;
                }
                entry.confidence_rank = entry.confidence_rank.max(confidence_rank);
                if entry.locations.len() < opts.max_results_per_endpoint {
                    entry.locations.push(CodeLocation {
                        file: rel_file.clone(),
                        line: line_no,
                        kind: "source_hint".to_string(),
                        score: source_hint_score(line, method_hint.as_deref()),
                        snippet: if opts.include_snippets {
                            Some(trim_snippet(line))
                        } else {
                            None
                        },
                    });
                }
            }

            for (idx, pat) in patterns.iter().enumerate() {
                if !pat.top_segment_hint.is_empty() && !line.contains(&pat.top_segment_hint) {
                    continue;
                }

                if !pat.template_re.is_match(line)
                    && !pat.runtime_re.is_match(line)
                    && !prefix_suffix_match(line, &pat.prefix, &pat.suffix)
                {
                    continue;
                }

                let kind = if method_hint_present(line, &pat.method) {
                    "route_definition"
                } else {
                    "reference"
                };

                let score = score_hit(&file, kind, line, &pat.method);

                findings[idx].push(CodeLocation {
                    file: rel_file.clone(),
                    line: line_no,
                    kind: kind.to_string(),
                    score,
                    snippet: if opts.include_snippets {
                        Some(trim_snippet(line))
                    } else {
                        None
                    },
                });
            }
        }
    }

    // Sort and attach results.
    for (idx, e) in endpoints.iter().enumerate() {
        let mut locs = std::mem::take(&mut findings[idx]);
        locs.sort_by(|a, b| {
            code_location_rank(a)
                .cmp(&code_location_rank(b))
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });
        locs.truncate(opts.max_results_per_endpoint);

        if locs.is_empty() {
            continue;
        }
        let Some(node) = spec.pointer_mut(&e.pointer) else {
            continue;
        };
        if let Some(obj) = node.as_object_mut() {
            obj.insert(
                "code_locations".to_string(),
                serde_json::to_value(locs).unwrap_or(Value::Null),
            );
        }
    }

    let mut source_hints: Vec<SourceSurfaceHint> = source_surface_hints
        .into_iter()
        .map(|((method_hint, path_template), agg)| SourceSurfaceHint {
            method_hint,
            path_template,
            sample_path: agg.sample_path,
            confidence: confidence_label(agg.confidence_rank).to_string(),
            locations: agg.locations,
        })
        .collect();
    source_hints.sort_by(|a, b| a.path_template.cmp(&b.path_template));

    let mut unobserved_hints: Vec<SourceSurfaceHint> = source_hints
        .iter()
        .filter(|hint| {
            if let Some(ref method) = hint.method_hint {
                !observed_method_paths.contains(&(method.clone(), hint.path_template.clone()))
            } else {
                !observed_paths.contains(&hint.path_template)
            }
        })
        .cloned()
        .collect();
    unobserved_hints.sort_by(|a, b| a.path_template.cmp(&b.path_template));

    // Add a top-level summary for tooling/UX.
    if let Some(obj) = spec.as_object_mut() {
        obj.insert(
            "code_linking".to_string(),
            serde_json::json!({
                "generated_at": Utc::now().to_rfc3339(),
                "spec_path": spec_path.display().to_string(),
                "codebase_root": codebase_path.display().to_string(),
                "files_scanned": files_scanned,
                "lines_scanned": lines_scanned,
                "max_results_per_endpoint": opts.max_results_per_endpoint,
            }),
        );
        obj.insert(
            "source_surface_analysis".to_string(),
            serde_json::json!({
                "generated_at": Utc::now().to_rfc3339(),
                "codebase_root": codebase_path.display().to_string(),
                "hints_total": source_hints.len(),
                "hints_unobserved": unobserved_hints.len(),
                "hints_observed_overlap": source_hints.len().saturating_sub(unobserved_hints.len()),
                "limitations": "Best-effort static hints from source strings. This can include dead code, test fixtures, and false positives.",
                "unobserved_hints": unobserved_hints,
            }),
        );
    }

    let out_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| default_output_path(spec_path));
    let data = serde_json::to_vec_pretty(&spec).context("serialize linked spec")?;
    tokio::fs::write(&out_path, data)
        .await
        .with_context(|| format!("write {}", out_path.display()))?;

    Ok(out_path)
}

/// Source lines that mention an endpoint path (`fetch("/api/orders")`,
/// route definitions), best match first. A cheap static search for
/// endpoints a scan never observed; files over 2 MB, build output, and
/// dependency directories are skipped.
pub fn find_endpoint_references(
    codebase: &Path,
    method: Option<&str>,
    path: &str,
    limit: usize,
) -> Result<Vec<CodeLocation>> {
    let path = path.split(['?', '#']).next().unwrap_or(path).trim();
    let template = normalize_source_path_template(path);
    if template.trim_matches('/').is_empty() {
        return Ok(Vec::new());
    }
    let method = method.unwrap_or("GET");
    let pat = build_endpoint_pattern(method, &template)?;
    let opts = LinkCodeOptions::default();
    let mut hits = Vec::new();
    for file in collect_files(codebase)? {
        let Ok(md) = std::fs::metadata(&file) else {
            continue;
        };
        if md.len() > opts.max_file_bytes {
            continue;
        }
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        if bytes.contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        if !pat.top_segment_hint.is_empty() && !text.contains(&pat.top_segment_hint) {
            continue;
        }
        let rel = path_rel(codebase, &file);
        for (idx, line) in text.lines().enumerate() {
            if !pat.template_re.is_match(line)
                && !pat.runtime_re.is_match(line)
                && !prefix_suffix_match(line, &pat.prefix, &pat.suffix)
            {
                continue;
            }
            let kind = if method_hint_present(line, &pat.method) {
                "route_definition"
            } else {
                "reference"
            };
            hits.push(CodeLocation {
                file: rel.clone(),
                line: idx + 1,
                kind: kind.to_string(),
                score: score_hit(&file, kind, line, &pat.method),
                snippet: Some(trim_snippet(line)),
            });
        }
    }
    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    hits.truncate(limit);
    Ok(hits)
}

fn default_output_path(spec_path: &Path) -> PathBuf {
    let s = spec_path.to_string_lossy().to_string();
    if s.ends_with(".json") {
        return PathBuf::from(format!("{}.linked.json", s.trim_end_matches(".json")));
    }
    spec_path.with_extension("linked.json")
}

fn extract_endpoints(spec: &Value) -> Result<Vec<EndpointDescriptor>> {
    let schema = spec.get("$schema").and_then(|v| v.as_str()).unwrap_or("");

    if schema.contains("normalized-spec") {
        extract_endpoints_normalized(spec)
    } else {
        extract_endpoints_raw(spec)
    }
}

fn extract_endpoints_raw(spec: &Value) -> Result<Vec<EndpointDescriptor>> {
    let Some(arr) = spec
        .pointer("/api_surface/endpoints")
        .and_then(|v| v.as_array())
    else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for (idx, ep) in arr.iter().enumerate() {
        let Some(method) = ep.pointer("/key/method").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(path) = ep.pointer("/key/path_template").and_then(|v| v.as_str()) else {
            continue;
        };

        out.push(EndpointDescriptor {
            pointer: format!("/api_surface/endpoints/{idx}"),
            method: method.to_string(),
            path: path.to_string(),
        });
    }
    Ok(out)
}

fn extract_endpoints_normalized(spec: &Value) -> Result<Vec<EndpointDescriptor>> {
    let Some(resources) = spec
        .pointer("/api_surface/resources")
        .and_then(|v| v.as_array())
    else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for (ri, r) in resources.iter().enumerate() {
        let Some(endpoints) = r.get("endpoints").and_then(|v| v.as_array()) else {
            continue;
        };
        for (ei, ep) in endpoints.iter().enumerate() {
            let Some(method) = ep.get("method").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(path) = ep.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            out.push(EndpointDescriptor {
                pointer: format!("/api_surface/resources/{ri}/endpoints/{ei}"),
                method: method.to_string(),
                path: path.to_string(),
            });
        }
    }
    Ok(out)
}

/// Count runtime-observed endpoints in a linked normalized spec that bound to at
/// least one source location. `link_code` attaches a non-empty `code_locations`
/// array only when a file/line match was found, so this is the honest signal for
/// "did we establish the runtime->source edge" — distinct from "did the linker
/// run". Convention-routed / SSR apps (no literal route strings, no captured API
/// traffic) link zero endpoints even though linking ran successfully.
pub fn count_linked_endpoints(spec: &Value) -> usize {
    let Some(resources) = spec
        .pointer("/api_surface/resources")
        .and_then(|v| v.as_array())
    else {
        return 0;
    };
    resources
        .iter()
        .filter_map(|r| r.get("endpoints").and_then(|v| v.as_array()))
        .flatten()
        .filter(|ep| {
            ep.get("code_locations")
                .and_then(|v| v.as_array())
                .is_some_and(|locs| !locs.is_empty())
        })
        .count()
}

/// Count every runtime-observed endpoint in a normalized spec, regardless of
/// whether it bound to source. This is the denominator for the honest
/// "`linked` of `total` endpoints mapped to source" signal: a low ratio flags a
/// convention-routed/SSR app whose moat (endpoint->source file:line) is dark.
pub fn count_total_endpoints(spec: &Value) -> usize {
    let Some(resources) = spec
        .pointer("/api_surface/resources")
        .and_then(|v| v.as_array())
    else {
        return 0;
    };
    resources
        .iter()
        .filter_map(|r| r.get("endpoints").and_then(|v| v.as_array()))
        .map(|eps| eps.len())
        .sum()
}

fn build_endpoint_pattern(method: &str, path: &str) -> Result<EndpointPattern> {
    let method = method.trim().to_ascii_uppercase();
    let path = path.trim().to_string();

    let top_segment_hint = top_segment_hint(&path);

    let template_pat = build_path_regex_pattern(&path, PathRegexMode::Template);
    let runtime_pat = build_path_regex_pattern(&path, PathRegexMode::Runtime);
    let template_re = RegexBuilder::new(&template_pat)
        .case_insensitive(true)
        .build()
        .with_context(|| format!("compile template regex for {method} {path}"))?;
    let runtime_re = RegexBuilder::new(&runtime_pat)
        .case_insensitive(true)
        .build()
        .with_context(|| format!("compile runtime regex for {method} {path}"))?;

    let (prefix, suffix) = prefix_suffix(&path);

    Ok(EndpointPattern {
        method,
        top_segment_hint,
        template_re,
        runtime_re,
        prefix,
        suffix,
    })
}

fn top_segment_hint(path: &str) -> String {
    let seg = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if seg.is_empty() {
        String::new()
    } else {
        format!("/{seg}")
    }
}

#[derive(Debug, Clone, Copy)]
enum PathRegexMode {
    Template,
    Runtime,
}

fn build_path_regex_pattern(path_template: &str, mode: PathRegexMode) -> String {
    // Convert /api/deals/:id/close into a regex that matches a range of route
    // template syntaxes in code (Express/Rails/FastAPI/Next/etc).
    let segs = path_template
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>();

    let placeholder = match mode {
        PathRegexMode::Template => {
            // :id, {id}, [id], ${id}, <uuid:id>, <id>, etc.
            r"(?:\:[A-Za-z0-9_]+(?:\([^)]*\))?|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\]|\$\{[^}]+\}|<[^>]+>)"
        }
        PathRegexMode::Runtime => {
            // Likely runtime value (uuid/int/string) embedded in a literal.
            r#"[^"'\/\s]+"#
        }
    };

    let mut out = String::new();
    out.push('/');

    for (i, seg) in segs.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        if seg.starts_with(':') {
            out.push_str(placeholder);
        } else {
            out.push_str(&regex::escape(seg));
        }
    }

    out
}

fn prefix_suffix(path_template: &str) -> (String, String) {
    let segs = path_template
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let param_idxs: Vec<usize> = segs
        .iter()
        .enumerate()
        .filter(|(_, s)| s.starts_with(':'))
        .map(|(i, _)| i)
        .collect();
    if param_idxs.is_empty() {
        return (path_template.to_string(), String::new());
    }

    let first = *param_idxs.first().unwrap();
    let last = *param_idxs.last().unwrap();

    let prefix = if first == 0 {
        "/".to_string()
    } else {
        format!("/{}/", segs[..first].join("/"))
    };
    let suffix = if last + 1 >= segs.len() {
        String::new()
    } else {
        format!("/{}", segs[last + 1..].join("/"))
    };
    (prefix, suffix)
}

fn prefix_suffix_match(line: &str, prefix: &str, suffix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let Some(pidx) = line.find(prefix) else {
        return false;
    };
    if suffix.is_empty() {
        return true;
    }
    line[pidx + prefix.len()..].contains(suffix)
}

fn method_hint_present(line: &str, method: &str) -> bool {
    let m = method.to_ascii_lowercase();
    let l = line.to_ascii_lowercase();
    // Basic JS/Ruby patterns.
    if l.contains(&format!(".{m}("))
        || l.contains(&format!(" {m} "))
        || l.contains(&format!("{m}("))
        || l.contains(&format!(" {m}("))
    {
        return true;
    }
    // Some frameworks use Route::post / Method::POST, etc.
    if l.contains(&format!("::{m}")) || l.contains(&method.to_ascii_uppercase()) {
        return true;
    }
    false
}

fn score_hit(file: &Path, kind: &str, line: &str, method: &str) -> i64 {
    let mut score = 1i64;
    if kind == "route_definition" {
        score += 10;
    }

    let file_s = file.to_string_lossy().to_ascii_lowercase();
    let file_bonus = [
        "routes",
        "router",
        "controllers",
        "controller",
        "handlers",
        "handler",
        "endpoints",
        "api",
    ];
    if file_bonus.iter().any(|w| file_s.contains(w)) {
        score += 5;
    }

    let l = line.to_ascii_lowercase();
    if l.contains("requireauth") || l.contains("auth") {
        score += 2;
    }
    if l.contains(&method.to_ascii_lowercase()) {
        score += 1;
    }

    score
}

fn trim_snippet(line: &str) -> String {
    let s = line.trim().replace('\t', " ");
    let mut s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX: usize = 240;
    if s.len() > MAX {
        s.truncate(MAX);
    }
    s
}

fn infer_source_method_hint(line: &str) -> Option<String> {
    let l = line.to_ascii_lowercase();
    for (needle, method) in [
        (".get(", "GET"),
        (".post(", "POST"),
        (".put(", "PUT"),
        (".patch(", "PATCH"),
        (".delete(", "DELETE"),
    ] {
        if l.contains(needle) {
            return Some(method.to_string());
        }
    }

    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        let m = method.to_ascii_lowercase();
        if l.contains(&format!("method: '{m}'"))
            || l.contains(&format!("method:\"{m}\""))
            || l.contains(&format!("method: \"{m}\""))
            || l.contains(&format!("method: `{m}`"))
            || l.contains(&format!("method: {m}"))
            || l.contains(&format!("method = '{m}'"))
            || l.contains(&format!("method = \"{m}\""))
        {
            return Some(method.to_string());
        }
    }

    None
}

fn source_hint_confidence_rank(line: &str, method_hint: Option<&str>) -> u8 {
    let l = line.to_ascii_lowercase();
    if method_hint.is_some()
        && (l.contains("router.")
            || l.contains("app.")
            || l.contains("fetch(")
            || l.contains("axios.")
            || l.contains("http.")
            || l.contains("request("))
    {
        return 3; // high
    }
    if method_hint.is_some() {
        return 2; // medium
    }
    1 // low
}

fn confidence_label(rank: u8) -> &'static str {
    match rank {
        3 => "high",
        2 => "medium",
        _ => "low",
    }
}

fn source_hint_score(line: &str, method_hint: Option<&str>) -> i64 {
    let mut score = 1i64;
    score += i64::from(source_hint_confidence_rank(line, method_hint));
    if line.to_ascii_lowercase().contains("auth") {
        score += 1;
    }
    score
}

fn extract_express_route_locations(
    rel_file: &str,
    text: &str,
    endpoints: &[EndpointDescriptor],
    include_snippets: bool,
) -> Vec<(usize, Vec<CodeLocation>)> {
    if !looks_like_express_file(text) {
        return Vec::new();
    }

    static ROUTE_RE: OnceLock<Regex> = OnceLock::new();
    static MOUNT_RE: OnceLock<Regex> = OnceLock::new();
    let route_re = ROUTE_RE.get_or_init(|| {
        Regex::new(
            r#"(?P<object>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['"`](?P<path>/[^'"`]*)['"`]"#,
        )
        .expect("valid express route regex")
    });
    let mount_re = MOUNT_RE.get_or_init(|| {
        Regex::new(
            r#"(?P<object>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*use\s*\(\s*['"`](?P<prefix>/[^'"`]*)['"`]\s*,\s*(?P<router>[A-Za-z_$][A-Za-z0-9_$]*)"#,
        )
        .expect("valid express mount regex")
    });

    let lines = text.lines().collect::<Vec<_>>();
    let mut mounts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut router_objects: BTreeSet<String> = BTreeSet::new();
    for line in &lines {
        for object in express_router_objects(line) {
            router_objects.insert(object);
        }
        for cap in mount_re.captures_iter(line) {
            let Some(router) = cap.name("router").map(|m| m.as_str().to_string()) else {
                continue;
            };
            let Some(prefix) = cap.name("prefix").map(|m| m.as_str().to_string()) else {
                continue;
            };
            mounts.entry(router).or_default().push(prefix);
        }
    }

    let mut out: BTreeMap<usize, Vec<CodeLocation>> = BTreeMap::new();
    for (line_idx, line) in lines.iter().enumerate() {
        let line_no = line_idx + 1;
        for cap in route_re.captures_iter(line) {
            let object = cap.name("object").map(|m| m.as_str()).unwrap_or("");
            let method = cap
                .name("method")
                .map(|m| m.as_str().to_ascii_uppercase())
                .unwrap_or_default();
            let route_path = cap.name("path").map(|m| m.as_str()).unwrap_or("/");
            if !is_probable_express_route_object(object, &mounts, &router_objects) {
                continue;
            }
            let mut source_paths = vec![normalize_source_path_template(route_path)];
            if let Some(prefixes) = mounts.get(object) {
                for prefix in prefixes {
                    source_paths.push(join_route_paths(prefix, route_path));
                }
            }
            source_paths.sort();
            source_paths.dedup();

            for (idx, endpoint) in endpoints.iter().enumerate() {
                if !endpoint.method.eq_ignore_ascii_case(&method) {
                    continue;
                }
                if !source_paths
                    .iter()
                    .any(|source_path| source_route_matches_endpoint(source_path, &endpoint.path))
                {
                    continue;
                }
                out.entry(idx).or_default().push(CodeLocation {
                    file: rel_file.to_string(),
                    line: line_no,
                    kind: "express_route_definition".to_string(),
                    score: 58,
                    snippet: if include_snippets {
                        Some(trim_snippet(line))
                    } else {
                        None
                    },
                });
            }
        }

        if is_express_root_static_or_header_middleware(line) {
            for (idx, endpoint) in endpoints.iter().enumerate() {
                if endpoint.method.eq_ignore_ascii_case("GET")
                    && normalize_source_path_template(&endpoint.path) == "/"
                {
                    out.entry(idx).or_default().push(CodeLocation {
                        file: rel_file.to_string(),
                        line: line_no,
                        kind: "express_static_or_header_middleware".to_string(),
                        score: 42,
                        snippet: if include_snippets {
                            Some(trim_snippet(line))
                        } else {
                            None
                        },
                    });
                }
            }
        }
    }

    out.into_iter().collect()
}

fn express_router_objects(line: &str) -> Vec<String> {
    static ROUTER_RE: OnceLock<Regex> = OnceLock::new();
    let router_re = ROUTER_RE.get_or_init(|| {
        Regex::new(
            r#"(?:const|let|var)\s+(?P<object>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*express\s*\.\s*Router\s*\("#,
        )
        .expect("valid express router object regex")
    });
    router_re
        .captures_iter(line)
        .filter_map(|cap| cap.name("object").map(|m| m.as_str().to_string()))
        .collect()
}

fn is_probable_express_route_object(
    object: &str,
    mounts: &BTreeMap<String, Vec<String>>,
    router_objects: &BTreeSet<String>,
) -> bool {
    let lower = object.to_ascii_lowercase();
    lower == "app"
        || lower == "router"
        || lower.ends_with("router")
        || mounts.contains_key(object)
        || router_objects.contains(object)
}

fn looks_like_express_file(text: &str) -> bool {
    let lc = text.to_ascii_lowercase();
    lc.contains("express()")
        || lc.contains("express.router")
        || lc.contains("from 'express'")
        || lc.contains("from \"express\"")
        || lc.contains(" from 'express'")
        || lc.contains(" from \"express\"")
        || lc.contains("require('express')")
        || lc.contains("require(\"express\")")
}

fn is_express_root_static_or_header_middleware(line: &str) -> bool {
    let lc = line.to_ascii_lowercase();
    lc.contains("express.static")
        || lc.contains("helmet(")
        || (lc.contains("setheader(")
            && (lc.contains("content-security-policy")
                || lc.contains("x-frame-options")
                || lc.contains("x-content-type-options")
                || lc.contains("referrer-policy")
                || lc.contains("permissions-policy")))
}

fn extract_nest_route_locations(
    codebase_root: &Path,
    file: &Path,
    rel_file: &str,
    text: &str,
    endpoints: &[EndpointDescriptor],
    include_snippets: bool,
) -> Vec<(usize, Vec<CodeLocation>)> {
    if !text.contains("@Controller") || !contains_nest_http_decorator(text) {
        return Vec::new();
    }

    let imports = parse_named_imports(file, text);
    let injections = parse_constructor_injections(text);
    let lines = text.lines().collect::<Vec<_>>();
    let controller_prefix = parse_controller_prefix(text).unwrap_or_default();
    let mut out = Vec::new();

    for (line_idx, line) in lines.iter().enumerate() {
        let Some((method, route_path)) = parse_nest_http_decorator(line) else {
            continue;
        };
        let source_path = join_route_paths(&controller_prefix, &route_path);
        let matching = endpoints
            .iter()
            .enumerate()
            .filter(|(_, endpoint)| {
                endpoint.method.eq_ignore_ascii_case(&method)
                    && source_route_matches_endpoint(&source_path, &endpoint.path)
            })
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }

        let mut locs = vec![CodeLocation {
            file: rel_file.to_string(),
            line: line_idx + 1,
            kind: "route_definition".to_string(),
            score: 60,
            snippet: if include_snippets {
                Some(trim_snippet(line))
            } else {
                None
            },
        }];

        let body = method_body_after_decorator(&lines, line_idx);
        let mut seen = BTreeSet::new();
        seen.insert(format!("{}:{}", rel_file, line_idx + 1));
        locs.extend(collect_dependency_locations(
            codebase_root,
            &imports,
            &injections,
            &body,
            0,
            include_snippets,
            &mut seen,
        ));

        locs.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.file.cmp(&b.file)));
        for idx in matching {
            out.push((idx, locs.clone()));
        }
    }

    out
}

fn contains_nest_http_decorator(text: &str) -> bool {
    ["@Get", "@Post", "@Put", "@Patch", "@Delete"]
        .iter()
        .any(|needle| text.contains(needle))
}

fn parse_controller_prefix(text: &str) -> Option<String> {
    static CONTROLLER_RE: OnceLock<Regex> = OnceLock::new();
    let re = CONTROLLER_RE.get_or_init(|| {
        Regex::new(r#"@Controller\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)"#)
            .expect("valid controller regex")
    });
    re.captures(text)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

fn parse_nest_http_decorator(line: &str) -> Option<(String, String)> {
    static ROUTE_RE: OnceLock<Regex> = OnceLock::new();
    let re = ROUTE_RE.get_or_init(|| {
        Regex::new(r#"@(Get|Post|Put|Patch|Delete)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)"#)
            .expect("valid Nest route regex")
    });
    let cap = re.captures(line)?;
    let method = cap.get(1)?.as_str().to_ascii_uppercase();
    let path = cap.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
    Some((method, path))
}

fn join_route_paths(prefix: &str, path: &str) -> String {
    let mut parts = Vec::new();
    let p = prefix.trim().trim_matches('/');
    if !p.is_empty() {
        parts.push(p);
    }
    let path = path.trim().trim_matches('/');
    if !path.is_empty() {
        parts.push(path);
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn source_route_matches_endpoint(source_path: &str, endpoint_path: &str) -> bool {
    let source = normalize_source_path_template(source_path);
    let endpoint = normalize_source_path_template(endpoint_path);
    if source == endpoint {
        return true;
    }
    let source_with_api = if source == "/" {
        "/api".to_string()
    } else {
        format!("/api{source}")
    };
    if source_with_api == endpoint {
        return true;
    }
    endpoint
        .strip_prefix("/api/")
        .map(|stripped| format!("/{stripped}") == source)
        .unwrap_or(false)
}

fn parse_named_imports(current_file: &Path, text: &str) -> BTreeMap<String, PathBuf> {
    static IMPORT_RE: OnceLock<Regex> = OnceLock::new();
    let re = IMPORT_RE.get_or_init(|| {
        Regex::new(r#"import\s*\{\s*([^}]+)\s*\}\s*from\s*['"]([^'"]+)['"]"#)
            .expect("valid import regex")
    });
    let mut out = BTreeMap::new();
    for cap in re.captures_iter(text) {
        let Some(names) = cap.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(spec) = cap.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(path) = resolve_relative_ts_import(current_file, spec) else {
            continue;
        };
        for raw_name in names.split(',') {
            let name = raw_name
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() {
                out.insert(name.to_string(), path.clone());
            }
        }
    }
    out
}

fn resolve_relative_ts_import(current_file: &Path, spec: &str) -> Option<PathBuf> {
    if !spec.starts_with('.') {
        return None;
    }
    let base = current_file.parent()?.join(spec);
    let mut candidates = vec![base.clone()];
    for ext in ["ts", "tsx", "js", "jsx"] {
        candidates.push(PathBuf::from(format!("{}.{}", base.display(), ext)));
    }
    candidates.extend([
        base.join("index.ts"),
        base.join("index.tsx"),
        base.join("index.js"),
    ]);
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn parse_constructor_injections(text: &str) -> BTreeMap<String, String> {
    static CTOR_RE: OnceLock<Regex> = OnceLock::new();
    static PARAM_RE: OnceLock<Regex> = OnceLock::new();
    let ctor_re = CTOR_RE.get_or_init(|| {
        RegexBuilder::new(r#"constructor\s*\((.*?)\)"#)
            .dot_matches_new_line(true)
            .build()
            .expect("valid constructor regex")
    });
    let param_re = PARAM_RE.get_or_init(|| {
        Regex::new(
            r#"(?:(?:private|protected|public)\s+)?(?:readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .expect("valid constructor param regex")
    });
    let mut out = BTreeMap::new();
    for ctor in ctor_re.captures_iter(text) {
        let Some(params) = ctor.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for cap in param_re.captures_iter(params) {
            if let (Some(prop), Some(ty)) = (cap.get(1), cap.get(2)) {
                out.insert(prop.as_str().to_string(), ty.as_str().to_string());
            }
        }
    }
    out
}

fn method_body_after_decorator(lines: &[&str], decorator_idx: usize) -> String {
    for idx in decorator_idx + 1..lines.len().min(decorator_idx + 24) {
        let trimmed = lines[idx].trim_start();
        if trimmed.starts_with('@') {
            continue;
        }
        if trimmed.contains('(') {
            return block_from_line(lines, idx);
        }
        if trimmed.starts_with('}') {
            break;
        }
    }
    String::new()
}

fn block_from_line(lines: &[&str], start_idx: usize) -> String {
    let mut out = String::new();
    let mut brace_depth = 0i64;
    let mut saw_open = false;
    for line in lines.iter().skip(start_idx).take(120) {
        out.push_str(line);
        out.push('\n');
        for ch in line.chars() {
            match ch {
                '{' => {
                    brace_depth += 1;
                    saw_open = true;
                }
                '}' => brace_depth -= 1,
                _ => {}
            }
        }
        if saw_open && brace_depth <= 0 {
            break;
        }
    }
    out
}

fn collect_dependency_locations(
    codebase_root: &Path,
    imports: &BTreeMap<String, PathBuf>,
    injections: &BTreeMap<String, String>,
    body: &str,
    depth: usize,
    include_snippets: bool,
    seen: &mut BTreeSet<String>,
) -> Vec<CodeLocation> {
    if depth >= 2 {
        return Vec::new();
    }
    static THIS_CALL_RE: OnceLock<Regex> = OnceLock::new();
    let call_re = THIS_CALL_RE.get_or_init(|| {
        Regex::new(r#"this\.([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("valid this-call regex")
    });
    let mut out = Vec::new();
    for cap in call_re.captures_iter(body) {
        let Some(prop) = cap.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(method) = cap.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(type_name) = injections.get(prop) else {
            continue;
        };
        let Some(dep_path) = imports.get(type_name) else {
            continue;
        };
        let Ok(dep_text) = std::fs::read_to_string(dep_path) else {
            continue;
        };
        let rel_file = path_rel(codebase_root, dep_path);
        let dep_lines = dep_text.lines().collect::<Vec<_>>();
        let line_idx = find_method_line(&dep_lines, method)
            .or_else(|| find_class_line(&dep_lines, type_name))
            .unwrap_or(0);
        let key = format!("{}:{}", rel_file, line_idx + 1);
        if !seen.insert(key) {
            continue;
        }
        let kind = dependency_kind(type_name, dep_path);
        let score = match kind {
            "service" => 45,
            "repository" => 40,
            _ => 35,
        };
        out.push(CodeLocation {
            file: rel_file,
            line: line_idx + 1,
            kind: kind.to_string(),
            score,
            snippet: if include_snippets {
                dep_lines.get(line_idx).map(|line| trim_snippet(line))
            } else {
                None
            },
        });

        let dep_imports = parse_named_imports(dep_path, &dep_text);
        let dep_injections = parse_constructor_injections(&dep_text);
        let dep_body = block_from_line(&dep_lines, line_idx);
        out.extend(collect_dependency_locations(
            codebase_root,
            &dep_imports,
            &dep_injections,
            &dep_body,
            depth + 1,
            include_snippets,
            seen,
        ));
    }
    out
}

fn find_method_line(lines: &[&str], method: &str) -> Option<usize> {
    let needle = format!("{method}(");
    lines
        .iter()
        .position(|line| line.contains(&needle) && !line.trim_start().starts_with("this."))
}

fn find_class_line(lines: &[&str], class_name: &str) -> Option<usize> {
    let needle = format!("class {class_name}");
    lines.iter().position(|line| line.contains(&needle))
}

fn dependency_kind(type_name: &str, path: &Path) -> &'static str {
    let lower_name = type_name.to_ascii_lowercase();
    let lower_path = path.to_string_lossy().to_ascii_lowercase();
    if lower_name.contains("repository")
        || lower_name.ends_with("repo")
        || lower_path.contains("repositories")
        || lower_path.contains(".repository.")
    {
        "repository"
    } else if lower_name.contains("service") || lower_path.contains(".service.") {
        "service"
    } else {
        "source_dependency"
    }
}

fn push_unique_location(locs: &mut Vec<CodeLocation>, loc: CodeLocation, max_len: usize) {
    if locs
        .iter()
        .any(|existing| existing.file == loc.file && existing.line == loc.line)
    {
        return;
    }
    if locs.len() < max_len {
        locs.push(loc);
    }
}

fn code_location_rank(loc: &CodeLocation) -> i64 {
    let file = loc.file.replace('\\', "/").to_ascii_lowercase();
    let kind = loc.kind.to_ascii_lowercase();
    let weak_file = file.split('/').any(|segment| {
        matches!(
            segment,
            "tests"
                | "test"
                | "__tests__"
                | "fixtures"
                | "fixture"
                | "docs"
                | "doc"
                | "documentation"
                | "generated"
        )
    }) || file.ends_with(".test.ts")
        || file.ends_with(".test.tsx")
        || file.ends_with(".test.js")
        || file.ends_with(".spec.ts")
        || file.ends_with(".spec.tsx")
        || file.ends_with(".spec.js")
        || file.ends_with(".json")
        || file.ends_with(".yaml")
        || file.ends_with(".yml");
    if weak_file {
        return 30;
    }
    if kind.ends_with("route_definition")
        || file.contains("controller")
        || file.contains("route.")
        || file.contains("/routes/")
        || file.contains("/routers/")
        || file.contains("/handlers/")
    {
        return 0;
    }
    if file.contains("service") || file.contains("repository") || file.contains("/repositories/") {
        return 5;
    }
    10
}

fn extract_source_paths(line: &str) -> Vec<String> {
    static SOURCE_PATH_RE: OnceLock<Regex> = OnceLock::new();
    let re = SOURCE_PATH_RE.get_or_init(|| {
        Regex::new(r#"['"`](/(?:api|graphql)[^'"`\s]*)['"`]"#).expect("valid source path regex")
    });

    let mut out = Vec::new();
    for cap in re.captures_iter(line) {
        let Some(raw) = cap.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn normalize_source_path_template(raw: &str) -> String {
    static INTERP_RE: OnceLock<Regex> = OnceLock::new();
    static BRACKET_RE: OnceLock<Regex> = OnceLock::new();
    static CURLY_RE: OnceLock<Regex> = OnceLock::new();

    let mut path = raw.trim().to_string();
    if let Some((base, _)) = path.split_once('#') {
        path = base.to_string();
    }
    if let Some((base, _)) = path.split_once('?') {
        path = base.to_string();
    }
    if path.is_empty() {
        return "/".to_string();
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }

    let interp_re =
        INTERP_RE.get_or_init(|| Regex::new(r#"\$\{[^}]+\}"#).expect("valid interpolation regex"));
    let bracket_re =
        BRACKET_RE.get_or_init(|| Regex::new(r#"\[[^\]/]+\]"#).expect("valid bracket regex"));
    let curly_re =
        CURLY_RE.get_or_init(|| Regex::new(r#"\{[^\}/]+\}"#).expect("valid curly regex"));

    let normalized = interp_re.replace_all(&path, ":id").to_string();
    let normalized = bracket_re.replace_all(&normalized, ":id").to_string();
    let normalized = curly_re.replace_all(&normalized, ":id").to_string();
    path_to_template(&normalized)
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                if should_skip_file(&path) {
                    continue;
                }
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn should_skip_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "dist"
            | "dist-build"
            | "build"
            | "out"
            | "logs"
            | ".next"
            | "coverage"
            | ".turbo"
            | ".cache"
            | ".claude"
            | ".worktrees"
            | ".codex"
            | ".idea"
            | ".vscode"
            | ".brokenapp"
    )
}

fn should_skip_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if name.starts_with('.') {
        return true;
    }
    let lower_name = name.to_ascii_lowercase();
    if matches!(
        lower_name.as_str(),
        "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock"
    ) || lower_name.ends_with(".min.js")
        || lower_name.ends_with(".min.mjs")
        || lower_name.ends_with(".min.cjs")
        || lower_name.ends_with(".min.css")
    {
        return true;
    }
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "mp4"
            | "mov"
            | "avi"
            | "mp3"
            | "wav"
            | "zip"
            | "gz"
            | "tgz"
            | "bz2"
            | "7z"
            | "pdf"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
            | "bin"
            | "wasm"
            | "tsbuildinfo"
            | "map"
    )
}

fn path_rel(root: &Path, path: &Path) -> String {
    let root_norm = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let path_norm = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    path_norm
        .strip_prefix(&root_norm)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn infer_source_method_hint_detects_common_patterns() {
        assert_eq!(
            infer_source_method_hint("router.post('/api/users', handler)"),
            Some("POST".to_string())
        );
        assert_eq!(
            infer_source_method_hint("fetch('/api/users', { method: 'DELETE' })"),
            Some("DELETE".to_string())
        );
        assert_eq!(
            infer_source_method_hint("axios.get('/api/users')"),
            Some("GET".to_string())
        );
        assert_eq!(infer_source_method_hint("const x = '/api/users'"), None);
    }

    #[test]
    fn count_linked_endpoints_counts_only_endpoints_with_source_locations() {
        // One resource, two endpoints: one bound to a source line, one not.
        let spec = serde_json::json!({
            "api_surface": { "resources": [{ "endpoints": [
                { "method": "GET", "path": "/api/orders", "code_locations": [
                    { "file": "server.js", "line": 39, "kind": "route_definition", "score": 58 }
                ]},
                { "method": "GET", "path": "/users" }
            ]}]}
        });
        assert_eq!(count_linked_endpoints(&spec), 1);

        // Convention-routed/SSR app: endpoints observed at runtime, zero linked.
        let unlinked = serde_json::json!({
            "api_surface": { "resources": [{ "endpoints": [
                { "method": "GET", "path": "/users" },
                { "method": "GET", "path": "/pets" }
            ]}]}
        });
        assert_eq!(count_linked_endpoints(&unlinked), 0);

        // An endpoint with an empty code_locations array does not count as linked.
        let empty = serde_json::json!({
            "api_surface": { "resources": [{ "endpoints": [
                { "method": "GET", "path": "/users", "code_locations": [] }
            ]}]}
        });
        assert_eq!(count_linked_endpoints(&empty), 0);
    }

    #[test]
    fn count_total_endpoints_counts_every_observed_endpoint() {
        // Two resources spanning three endpoints; linkage state is irrelevant to
        // the total. This is the denominator for the "X of Y endpoints linked"
        // honesty signal.
        let spec = serde_json::json!({
            "api_surface": { "resources": [
                { "endpoints": [
                    { "method": "GET", "path": "/api/orders", "code_locations": [
                        { "file": "server.js", "line": 39 }
                    ]},
                    { "method": "POST", "path": "/api/orders" }
                ]},
                { "endpoints": [
                    { "method": "GET", "path": "/users" }
                ]}
            ]}
        });
        assert_eq!(count_total_endpoints(&spec), 3);

        // A spec with no api_surface (e.g. SSR-only) has zero observed endpoints.
        let none = serde_json::json!({ "views": [] });
        assert_eq!(count_total_endpoints(&none), 0);
    }

    #[test]
    fn extract_source_paths_finds_api_and_graphql_literals() {
        let line = "fetch('/api/users/${id}'); const q = '/graphql';";
        let paths = extract_source_paths(line);
        assert_eq!(paths, vec!["/api/users/${id}", "/graphql"]);
    }

    #[test]
    fn normalize_source_path_template_handles_interpolation_and_params() {
        assert_eq!(
            normalize_source_path_template("/api/users/${id}/orders/[orderId]?x=1"),
            "/api/users/:id/orders/:id"
        );
        assert_eq!(
            normalize_source_path_template("/api/tenants/{tenantId}/members/42"),
            "/api/tenants/:id/members/:id"
        );
    }

    #[tokio::test]
    async fn link_code_outputs_source_surface_unobserved_hints() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spec_path = tmp.path().join("spec.json");
        let codebase_path = tmp.path().join("app");
        std::fs::create_dir_all(&codebase_path).expect("create codebase dir");

        let spec = serde_json::json!({
            "api_surface": {
                "endpoints": [
                    {
                        "key": {
                            "method": "GET",
                            "path_template": "/api/users"
                        }
                    }
                ]
            }
        });
        std::fs::write(
            &spec_path,
            serde_json::to_vec_pretty(&spec).expect("serialize spec"),
        )
        .expect("write spec");

        let routes = r#"
            app.get('/api/users', usersHandler);
            app.get('/api/admin/users', adminUsersHandler);
        "#;
        std::fs::write(codebase_path.join("routes.js"), routes).expect("write routes");

        let out_path = tmp.path().join("linked.json");
        let linked_path = link_code(
            &spec_path,
            &codebase_path,
            Some(out_path.as_path()),
            LinkCodeOptions::default(),
        )
        .await
        .expect("run link_code");
        assert_eq!(linked_path, out_path);

        let raw = tokio::fs::read_to_string(&linked_path)
            .await
            .expect("read linked output");
        let linked: Value = serde_json::from_str(&raw).expect("parse linked output");

        assert_eq!(
            linked
                .pointer("/source_surface_analysis/hints_total")
                .and_then(|v| v.as_u64()),
            Some(2)
        );
        assert_eq!(
            linked
                .pointer("/source_surface_analysis/hints_unobserved")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            linked
                .pointer("/source_surface_analysis/hints_observed_overlap")
                .and_then(|v| v.as_u64()),
            Some(1)
        );

        let unobserved = linked
            .pointer("/source_surface_analysis/unobserved_hints")
            .and_then(|v| v.as_array())
            .expect("unobserved_hints array");
        assert_eq!(unobserved.len(), 1);
        assert_eq!(
            unobserved[0].get("path_template").and_then(|v| v.as_str()),
            Some("/api/admin/users")
        );
        assert_eq!(
            unobserved[0].get("method_hint").and_then(|v| v.as_str()),
            Some("GET")
        );
    }

    #[tokio::test]
    async fn link_code_maps_plain_express_routes_and_mounted_routers() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spec_path = tmp.path().join("spec.json");
        let codebase_path = tmp.path().join("checkd");
        std::fs::create_dir_all(&codebase_path).expect("create codebase dir");

        let spec = serde_json::json!({
            "api_surface": {
                "endpoints": [
                    {"key": {"method": "GET", "path_template": "/"}},
                    {"key": {"method": "GET", "path_template": "/api/session"}},
                    {"key": {"method": "POST", "path_template": "/api/auth/login"}},
                    {"key": {"method": "GET", "path_template": "/api/messages"}},
                    {"key": {"method": "POST", "path_template": "/api/webhooks/telnyx/sms"}},
                    {"key": {"method": "GET", "path_template": "/api/cloudflare/status"}}
                ]
            }
        });
        std::fs::write(
            &spec_path,
            serde_json::to_vec_pretty(&spec).expect("serialize spec"),
        )
        .expect("write spec");

        std::fs::write(
            codebase_path.join("server-index.js"),
            r#"
const express = require('express');
const app = express();
const api = express.Router();
app.use((req, res, next) => { res.setHeader('X-Frame-Options', 'DENY'); next(); });
app.use(express.static('public'));
api.get('/session', sessionHandler);
api.get('/messages', messagesHandler);
api.get('/cloudflare/status', cloudflareStatus);
app.use('/api', api);
app.post('/api/auth/login', loginHandler);
app.post('/api/webhooks/telnyx/sms', telnyxSmsWebhook);
"#,
        )
        .expect("write express app");

        let out_path = tmp.path().join("linked.json");
        let linked_path = link_code(
            &spec_path,
            &codebase_path,
            Some(out_path.as_path()),
            LinkCodeOptions::default(),
        )
        .await
        .expect("run link_code");

        let raw = tokio::fs::read_to_string(&linked_path)
            .await
            .expect("read linked output");
        let linked: Value = serde_json::from_str(&raw).expect("parse linked output");
        for idx in 0..6 {
            let locations = linked
                .pointer(&format!("/api_surface/endpoints/{idx}/code_locations"))
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("missing code locations for endpoint {idx}"));
            assert!(
                locations.iter().any(|loc| {
                    loc.get("file")
                        .and_then(|v| v.as_str())
                        .is_some_and(|file| file.ends_with("server-index.js"))
                }),
                "endpoint {idx} should map to server-index.js, got {locations:?}"
            );
            if idx == 2 {
                assert!(
                    locations.iter().any(|loc| {
                        loc.get("kind").and_then(|v| v.as_str()) == Some("express_route_definition")
                    }),
                    "auth login should map to the Express handler, got {locations:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn link_code_still_outputs_source_surface_hints_when_spec_has_no_endpoints() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spec_path = tmp.path().join("spec.json");
        let codebase_path = tmp.path().join("app");
        std::fs::create_dir_all(&codebase_path).expect("create codebase dir");

        let spec = serde_json::json!({
            "api_surface": {
                "endpoints": []
            }
        });
        std::fs::write(
            &spec_path,
            serde_json::to_vec_pretty(&spec).expect("serialize spec"),
        )
        .expect("write spec");

        let routes = "router.get('/api/admin/users', adminUsersHandler);";
        std::fs::write(codebase_path.join("routes.js"), routes).expect("write routes");

        let out_path = tmp.path().join("linked.json");
        let linked_path = link_code(
            &spec_path,
            &codebase_path,
            Some(out_path.as_path()),
            LinkCodeOptions::default(),
        )
        .await
        .expect("run link_code");
        assert_eq!(linked_path, out_path);

        let raw = tokio::fs::read_to_string(&linked_path)
            .await
            .expect("read linked output");
        let linked: Value = serde_json::from_str(&raw).expect("parse linked output");

        assert_eq!(
            linked
                .pointer("/source_surface_analysis/hints_total")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            linked
                .pointer("/source_surface_analysis/hints_unobserved")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        let unobserved = linked
            .pointer("/source_surface_analysis/unobserved_hints")
            .and_then(|v| v.as_array())
            .expect("unobserved_hints array");
        assert_eq!(unobserved.len(), 1);
        assert_eq!(
            unobserved[0].get("path_template").and_then(|v| v.as_str()),
            Some("/api/admin/users")
        );
    }

    #[tokio::test]
    async fn link_code_ignores_hidden_worktree_dirs_for_source_surface_hints() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spec_path = tmp.path().join("spec.json");
        let codebase_path = tmp.path().join("app");
        std::fs::create_dir_all(&codebase_path).expect("create codebase dir");
        std::fs::create_dir_all(codebase_path.join(".claude/worktrees/stale"))
            .expect("create claude worktree");
        std::fs::create_dir_all(codebase_path.join(".worktrees/codex/stale"))
            .expect("create codex worktree");
        std::fs::create_dir_all(codebase_path.join("backend/logs")).expect("create logs dir");
        std::fs::create_dir_all(codebase_path.join("backend/dist-build"))
            .expect("create build dir");

        let spec = serde_json::json!({
            "api_surface": {
                "endpoints": []
            }
        });
        std::fs::write(
            &spec_path,
            serde_json::to_vec_pretty(&spec).expect("serialize spec"),
        )
        .expect("write spec");

        std::fs::write(
            codebase_path.join("routes.js"),
            "router.get('/api/live', liveHandler);",
        )
        .expect("write live routes");
        std::fs::write(
            codebase_path.join(".claude/worktrees/stale/routes.js"),
            "router.get('/api/stale-claude', staleHandler);",
        )
        .expect("write claude stale routes");
        std::fs::write(
            codebase_path.join(".worktrees/codex/stale/routes.js"),
            "router.get('/api/stale-codex', staleHandler);",
        )
        .expect("write worktree stale routes");
        std::fs::write(
            codebase_path.join("backend/logs/combined.log"),
            "GET /api/stale-from-log 500",
        )
        .expect("write stale log route");
        std::fs::write(
            codebase_path.join("backend/dist-build/routes.js"),
            "router.get('/api/stale-from-build', staleHandler);",
        )
        .expect("write stale build route");

        let out_path = tmp.path().join("linked.json");
        let linked_path = link_code(
            &spec_path,
            &codebase_path,
            Some(out_path.as_path()),
            LinkCodeOptions::default(),
        )
        .await
        .expect("run link_code");

        let raw = tokio::fs::read_to_string(&linked_path)
            .await
            .expect("read linked output");
        let linked: Value = serde_json::from_str(&raw).expect("parse linked output");

        assert_eq!(
            linked
                .pointer("/source_surface_analysis/hints_total")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        let unobserved = linked
            .pointer("/source_surface_analysis/unobserved_hints")
            .and_then(|v| v.as_array())
            .expect("unobserved_hints array");
        assert_eq!(unobserved.len(), 1);
        assert_eq!(
            unobserved[0].get("path_template").and_then(|v| v.as_str()),
            Some("/api/live")
        );
    }

    #[tokio::test]
    async fn link_code_maps_nest_decorator_routes_to_controller_service_and_repository() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let spec_path = tmp.path().join("spec.json");
        let codebase_path = tmp.path().join("app");
        std::fs::create_dir_all(codebase_path.join("backend/src/modules/orgs"))
            .expect("create module dir");
        std::fs::create_dir_all(codebase_path.join("backend/src/repositories"))
            .expect("create repo dir");
        std::fs::create_dir_all(codebase_path.join("docs/api")).expect("create docs dir");

        let spec = serde_json::json!({
            "api_surface": {
                "endpoints": [
                    {
                        "key": {
                            "method": "GET",
                            "path_template": "/api/portal/branding"
                        }
                    }
                ]
            }
        });
        std::fs::write(
            &spec_path,
            serde_json::to_vec_pretty(&spec).expect("serialize spec"),
        )
        .expect("write spec");

        std::fs::write(
            codebase_path.join("backend/src/modules/orgs/portal-branding.controller.ts"),
            r#"
import { Controller, Get, UseGuards } from '@nestjs/common';
import { BrandingService } from './branding.service';

@Controller()
export class PortalBrandingController {
  constructor(private readonly branding: BrandingService) {}

  @UseGuards(AuthGuard)
  @Get('portal/branding')
  async getClientPortalBranding() {
    return this.branding.getBranding('org_123');
  }
}
"#,
        )
        .expect("write controller");
        std::fs::write(
            codebase_path.join("backend/src/modules/orgs/branding.service.ts"),
            r#"
import { Injectable } from '@nestjs/common';
import { OrgsRepository } from '../../repositories/orgs.repository';

@Injectable()
export class BrandingService {
  constructor(private readonly orgsRepo: OrgsRepository) {}

  async getBranding(orgId: string) {
    const row = await this.orgsRepo.loadOrgBranding(orgId);
    return this.orgsRepo.signBrandingLogoViewUrl(row.logo_storage_path);
  }
}
"#,
        )
        .expect("write service");
        std::fs::write(
            codebase_path.join("backend/src/repositories/orgs.repository.ts"),
            r#"
export class OrgsRepository {
  async loadOrgBranding(orgId: string) {
    return { logo_storage_path: orgId };
  }

  async signBrandingLogoViewUrl(path: string) {
    return `signed:${path}`;
  }
}
"#,
        )
        .expect("write repository");
        std::fs::write(
            codebase_path.join("docs/api/openapi.json"),
            r#"{ "path": "/api/portal/branding" }"#,
        )
        .expect("write docs");

        let out_path = tmp.path().join("linked.json");
        let linked_path = link_code(
            &spec_path,
            &codebase_path,
            Some(out_path.as_path()),
            LinkCodeOptions::default(),
        )
        .await
        .expect("run link_code");

        let raw = tokio::fs::read_to_string(&linked_path)
            .await
            .expect("read linked output");
        let linked: Value = serde_json::from_str(&raw).expect("parse linked output");
        let locations = linked
            .pointer("/api_surface/endpoints/0/code_locations")
            .and_then(|v| v.as_array())
            .expect("code_locations array");
        let files = locations
            .iter()
            .filter_map(|loc| loc.get("file").and_then(|v| v.as_str()))
            .collect::<Vec<_>>();

        assert!(
            files
                .first()
                .is_some_and(|file| file.ends_with("portal-branding.controller.ts")),
            "controller should outrank docs, got {files:?}"
        );
        assert!(
            files
                .iter()
                .any(|file| file.ends_with("branding.service.ts")),
            "expected service hop in {files:?}"
        );
        assert!(
            files
                .iter()
                .any(|file| file.ends_with("orgs.repository.ts")),
            "expected repository hop in {files:?}"
        );
    }

    #[test]
    fn find_endpoint_references_skips_tsbuildinfo_build_artifacts_and_lockfiles() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("lib/api")).unwrap();
        std::fs::create_dir_all(root.join(".next/server")).unwrap();
        std::fs::create_dir_all(root.join("dist")).unwrap();
        std::fs::create_dir_all(root.join("build")).unwrap();
        std::fs::create_dir_all(root.join("coverage")).unwrap();
        std::fs::create_dir_all(root.join(".turbo")).unwrap();

        let call = "export const enrich = () => fetch('/api/enrichment/run', { method: 'POST' });";
        std::fs::write(root.join("lib/api/enrichment.ts"), call).unwrap();
        for noise in [
            "tsconfig.tsbuildinfo",
            "bundle.min.js",
            "app.js.map",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            ".next/server/route.js",
            "dist/enrichment.js",
            "build/enrichment.js",
            "coverage/enrichment.js",
            ".turbo/enrichment.json",
        ] {
            std::fs::write(root.join(noise), call).unwrap();
        }

        let hits = find_endpoint_references(root, Some("POST"), "/api/enrichment/run", 8).unwrap();
        let files: Vec<&str> = hits.iter().map(|h| h.file.as_str()).collect();
        assert_eq!(files, vec!["lib/api/enrichment.ts"], "got {hits:?}");
    }
}
