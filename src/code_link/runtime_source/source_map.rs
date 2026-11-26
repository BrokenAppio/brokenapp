//! Minimal Source Map v3 decoder used to map dev-server stack frames back to
//! original sources.
//!
//! Supports regular maps and index maps (`sections`, as emitted by Turbopack),
//! `sourceRoot`, and `ignoreList` / `x_google_ignoreList`. Mappings are decoded
//! lazily per (sub)map, so a large index map only pays for the sections that
//! are actually looked up.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// An original position for a generated location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalPosition {
    /// Source path as written in the map, with `sourceRoot` applied.
    pub source: String,
    /// 1-based line.
    pub line: u32,
    /// 1-based column.
    pub col: u32,
    /// The source is on the map's ignore list (library / framework code).
    pub ignored: bool,
}

#[derive(Debug)]
pub struct SourceMap {
    kind: MapKind,
}

#[derive(Debug)]
enum MapKind {
    Regular(RegularMap),
    Index(Vec<Section>),
}

#[derive(Debug)]
struct Section {
    /// 0-based generated line offset.
    line: u32,
    /// 0-based generated column offset (applies to the first line only).
    col: u32,
    map: SourceMap,
}

#[derive(Debug)]
struct RegularMap {
    sources: Vec<String>,
    ignored: BTreeSet<u32>,
    mappings: String,
    decoded: OnceLock<Vec<Vec<Segment>>>,
}

/// One decoded mapping segment. `src == NO_SOURCE` marks a generated-only
/// segment (one VLQ field), which terminates the previous mapping.
#[derive(Debug, Clone, Copy)]
struct Segment {
    gen_col: u32,
    src: u32,
    src_line: u32,
    src_col: u32,
}

const NO_SOURCE: u32 = u32::MAX;
/// Guard against pathological nesting in index maps.
const MAX_SECTION_DEPTH: usize = 4;

impl SourceMap {
    pub fn from_json(raw: &str) -> Result<Self> {
        let raw = raw.trim_start_matches('\u{feff}');
        // Some servers prefix maps with an XSSI guard line.
        let raw = raw.strip_prefix(")]}'").unwrap_or(raw);
        let value: Value = serde_json::from_str(raw).context("parse source map JSON")?;
        Self::from_value(&value)
    }

    pub fn from_value(value: &Value) -> Result<Self> {
        Self::from_value_depth(value, 0)
    }

    fn from_value_depth(value: &Value, depth: usize) -> Result<Self> {
        let Some(obj) = value.as_object() else {
            bail!("source map is not a JSON object");
        };
        if let Some(sections) = obj.get("sections").and_then(Value::as_array) {
            if depth >= MAX_SECTION_DEPTH {
                bail!("source map sections nested too deeply");
            }
            let mut out = Vec::with_capacity(sections.len());
            for section in sections {
                let offset = section.get("offset");
                let line = offset
                    .and_then(|o| o.get("line"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let col = offset
                    .and_then(|o| o.get("column"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                // Sections that reference an external `url` are not supported;
                // skip them rather than failing the whole map.
                let Some(map) = section.get("map") else {
                    continue;
                };
                let Ok(map) = Self::from_value_depth(map, depth + 1) else {
                    continue;
                };
                out.push(Section {
                    line: u32::try_from(line).unwrap_or(u32::MAX),
                    col: u32::try_from(col).unwrap_or(u32::MAX),
                    map,
                });
            }
            out.sort_by_key(|s| (s.line, s.col));
            return Ok(Self {
                kind: MapKind::Index(out),
            });
        }

        let mappings = obj
            .get("mappings")
            .and_then(Value::as_str)
            .context("source map has no mappings")?
            .to_string();
        let source_root = obj.get("sourceRoot").and_then(Value::as_str).unwrap_or("");
        let sources = obj
            .get("sources")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|s| join_source_root(source_root, s.as_str().unwrap_or("")))
                    .collect()
            })
            .unwrap_or_default();
        let ignored = obj
            .get("ignoreList")
            .or_else(|| obj.get("x_google_ignoreList"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_u64)
                    .filter_map(|v| u32::try_from(v).ok())
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            kind: MapKind::Regular(RegularMap {
                sources,
                ignored,
                mappings,
                decoded: OnceLock::new(),
            }),
        })
    }

    /// Look up a generated position. `line` and `col` are 1-based, as in V8
    /// stack traces. Returns `None` when the position is unmapped.
    pub fn lookup(&self, line: u32, col: u32) -> Option<OriginalPosition> {
        if line == 0 {
            return None;
        }
        self.lookup0(line - 1, col.saturating_sub(1))
    }

    fn lookup0(&self, line0: u32, col0: u32) -> Option<OriginalPosition> {
        match &self.kind {
            MapKind::Regular(map) => map.lookup0(line0, col0),
            MapKind::Index(sections) => {
                // Last section whose offset is <= the position.
                let idx = sections.partition_point(|s| (s.line, s.col) <= (line0, col0));
                let section = sections.get(idx.checked_sub(1)?)?;
                let rel_line = line0 - section.line;
                let rel_col = if rel_line == 0 {
                    col0 - section.col
                } else {
                    col0
                };
                section.map.lookup0(rel_line, rel_col)
            }
        }
    }
}

impl RegularMap {
    fn lookup0(&self, line0: u32, col0: u32) -> Option<OriginalPosition> {
        let lines = self.decoded.get_or_init(|| decode_mappings(&self.mappings));
        let segments = lines.get(line0 as usize)?;
        // Greatest segment with gen_col <= col0, on the same generated line
        // (same semantics as `source-map`'s GREATEST_LOWER_BOUND bias).
        let idx = segments.partition_point(|s| s.gen_col <= col0);
        let seg = segments.get(idx.checked_sub(1)?)?;
        if seg.src == NO_SOURCE {
            return None;
        }
        let source = self.sources.get(seg.src as usize)?;
        if source.is_empty() {
            return None;
        }
        Some(OriginalPosition {
            source: source.clone(),
            line: seg.src_line + 1,
            col: seg.src_col + 1,
            ignored: self.ignored.contains(&seg.src),
        })
    }
}

fn join_source_root(root: &str, source: &str) -> String {
    if root.is_empty() || source.contains("://") || source.starts_with('/') {
        return source.to_string();
    }
    if root.ends_with('/') {
        format!("{root}{source}")
    } else {
        format!("{root}/{source}")
    }
}

fn base64_value(b: u8) -> Option<i64> {
    Some(match b {
        b'A'..=b'Z' => (b - b'A') as i64,
        b'a'..=b'z' => (b - b'a') as i64 + 26,
        b'0'..=b'9' => (b - b'0') as i64 + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

/// Decode one segment's VLQ fields. Returns `None` on malformed input.
fn decode_vlq_fields(segment: &[u8], out: &mut Vec<i64>) -> Option<()> {
    out.clear();
    let mut value: i64 = 0;
    let mut shift: u32 = 0;
    for &b in segment {
        let digit = base64_value(b)?;
        let cont = digit & 32 != 0;
        value |= (digit & 31) << shift;
        if cont {
            shift += 5;
            if shift > 60 {
                return None;
            }
            continue;
        }
        let negative = value & 1 == 1;
        let magnitude = value >> 1;
        out.push(if negative { -magnitude } else { magnitude });
        value = 0;
        shift = 0;
    }
    if shift != 0 {
        return None;
    }
    Some(())
}

fn decode_mappings(mappings: &str) -> Vec<Vec<Segment>> {
    let mut lines = Vec::new();
    let mut src: i64 = 0;
    let mut src_line: i64 = 0;
    let mut src_col: i64 = 0;
    let mut fields = Vec::with_capacity(5);

    for line in mappings.split(';') {
        let mut gen_col: i64 = 0;
        let mut segments = Vec::new();
        for raw in line.split(',') {
            if raw.is_empty() {
                continue;
            }
            if decode_vlq_fields(raw.as_bytes(), &mut fields).is_none() || fields.is_empty() {
                continue;
            }
            gen_col += fields[0];
            if fields.len() >= 4 {
                src += fields[1];
                src_line += fields[2];
                src_col += fields[3];
            }
            if gen_col < 0 {
                continue;
            }
            let mapped = fields.len() >= 4 && src >= 0 && src_line >= 0 && src_col >= 0;
            segments.push(Segment {
                gen_col: clamp_u32(gen_col),
                src: if mapped { clamp_u32(src) } else { NO_SOURCE },
                src_line: if mapped { clamp_u32(src_line) } else { 0 },
                src_col: if mapped { clamp_u32(src_col) } else { 0 },
            });
        }
        segments.sort_by_key(|s| s.gen_col);
        lines.push(segments);
    }
    lines
}

fn clamp_u32(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX - 1)
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Encode one VLQ value (test fixture helper).
    pub fn vlq(mut value: i64, out: &mut String) {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut v: u64 = if value < 0 {
            value = -value;
            ((value as u64) << 1) | 1
        } else {
            (value as u64) << 1
        };
        loop {
            let mut digit = (v & 31) as usize;
            v >>= 5;
            if v > 0 {
                digit |= 32;
            }
            out.push(ALPHABET[digit] as char);
            if v == 0 {
                break;
            }
        }
    }

    /// Build a `mappings` string from absolute segments per generated line:
    /// `(gen_col, src, src_line0, src_col0)`.
    pub fn encode(lines: &[Vec<(i64, i64, i64, i64)>]) -> String {
        let (mut src, mut sl, mut sc) = (0i64, 0i64, 0i64);
        let mut out = String::new();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                out.push(';');
            }
            let mut gc = 0i64;
            for (j, &(g, s, l, c)) in line.iter().enumerate() {
                if j > 0 {
                    out.push(',');
                }
                vlq(g - gc, &mut out);
                vlq(s - src, &mut out);
                vlq(l - sl, &mut out);
                vlq(c - sc, &mut out);
                gc = g;
                src = s;
                sl = l;
                sc = c;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::encode;
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_known_vlq_sequences() {
        let mut out = Vec::new();
        decode_vlq_fields(b"AAgBC", &mut out).unwrap();
        assert_eq!(out, vec![0, 0, 16, 1]);
        decode_vlq_fields(b"D", &mut out).unwrap();
        assert_eq!(out, vec![-1]);
        decode_vlq_fields(b"2Hw+B", &mut out).unwrap();
        assert_eq!(out, vec![123, 1000]);
        assert!(
            decode_vlq_fields(b"g", &mut out).is_none(),
            "dangling continuation"
        );
        assert!(decode_vlq_fields(b"A!", &mut out).is_none(), "invalid char");
    }

    #[test]
    fn regular_map_lookup_uses_greatest_lower_bound_on_same_line() {
        // Generated line 1: col 0 -> a.tsx 1:1, col 10 -> a.tsx 3:5
        // Generated line 2: col 4 -> b.tsx 10:1
        let mappings = encode(&[vec![(0, 0, 0, 0), (10, 0, 2, 4)], vec![(4, 1, 9, 0)]]);
        let map = SourceMap::from_value(&json!({
            "version": 3,
            "sources": ["a.tsx", "b.tsx"],
            "sourceRoot": "src/",
            "mappings": mappings,
        }))
        .unwrap();

        let p = map.lookup(1, 1).unwrap();
        assert_eq!((p.source.as_str(), p.line, p.col), ("src/a.tsx", 1, 1));
        let p = map.lookup(1, 15).unwrap();
        assert_eq!((p.source.as_str(), p.line, p.col), ("src/a.tsx", 3, 5));
        let p = map.lookup(2, 30).unwrap();
        assert_eq!((p.source.as_str(), p.line, p.col), ("src/b.tsx", 10, 1));
        // Column before the first segment of line 2 is unmapped.
        assert!(map.lookup(2, 2).is_none());
        // Out of range lines.
        assert!(map.lookup(3, 1).is_none());
        assert!(map.lookup(0, 1).is_none());
    }

    #[test]
    fn generated_only_segment_ends_mapping() {
        // Line 1: col 0 -> a.tsx 1:1, col 8 unmapped (1-field segment).
        let mut mappings = encode(&[vec![(0, 0, 0, 0)]]);
        mappings.push(',');
        super::test_support::vlq(8, &mut mappings);
        let map = SourceMap::from_value(&json!({
            "version": 3, "sources": ["a.tsx"], "mappings": mappings,
        }))
        .unwrap();
        assert!(map.lookup(1, 5).is_some());
        assert!(map.lookup(1, 9).is_none());
    }

    #[test]
    fn index_map_offsets_and_ignore_list() {
        let app = encode(&[vec![(0, 0, 4, 2)], vec![(2, 0, 5, 6)]]);
        let lib = encode(&[vec![(0, 0, 100, 0)]]);
        let map = SourceMap::from_json(
            &json!({
                "version": 3,
                "sections": [
                    {"offset": {"line": 3, "column": 0}, "map": {
                        "version": 3,
                        "sources": ["file:///repo/components/button.tsx"],
                        "mappings": app,
                    }},
                    {"offset": {"line": 10, "column": 4}, "map": {
                        "version": 3,
                        "sources": ["file:///repo/node_modules/react/index.js"],
                        "mappings": lib,
                        "ignoreList": [0],
                    }},
                    {"offset": {"line": 20, "column": 0}, "url": "external.map"}
                ]
            })
            .to_string(),
        )
        .unwrap();

        // Generated line 4 (0-based 3) is the first line of section 1.
        let p = map.lookup(4, 1).unwrap();
        assert_eq!(p.source, "file:///repo/components/button.tsx");
        assert_eq!((p.line, p.col, p.ignored), (5, 3, false));
        let p = map.lookup(5, 3).unwrap();
        assert_eq!((p.line, p.col), (6, 7));
        // Before the first section.
        assert!(map.lookup(1, 1).is_none());
        // Section 2 starts at column 4 of generated line 11.
        let p = map.lookup(11, 5).unwrap();
        assert!(p.ignored);
        assert_eq!(p.line, 101);
        // Before section 2's column offset: resolved in section 1, whose
        // relative line 7 is unmapped.
        assert!(map.lookup(11, 2).is_none());
    }

    #[test]
    fn rejects_non_maps() {
        assert!(SourceMap::from_json("<!doctype html><html></html>").is_err());
        assert!(SourceMap::from_json("{\"version\":3}").is_err());
        assert!(
            SourceMap::from_json(")]}'\n{\"version\":3,\"sources\":[],\"mappings\":\"\"}").is_ok()
        );
    }
}
