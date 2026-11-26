//! Tolerant JS/TS/JSX scanning helpers for route discovery.
//!
//! This is not a parser for the language. It blanks comments (keeping byte
//! offsets and newlines), matches brackets while skipping string literals, and
//! parses the literal subset route configs are written in: strings, arrays,
//! objects, calls, and spreads. Anything else becomes [`Value::Raw`] text.
//! Quoted strings end at a newline so an apostrophe in JSX text cannot swallow
//! more than one line.

use std::sync::LazyLock;

use regex::Regex;

/// Source text with comments replaced by spaces, plus a line index.
pub(crate) struct JsSource {
    pub text: String,
    line_starts: Vec<usize>,
}

impl JsSource {
    pub fn new(raw: &str) -> Self {
        let text = strip_comments(raw);
        let mut line_starts = vec![0];
        line_starts.extend(
            text.bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i + 1),
        );
        Self { text, line_starts }
    }

    /// 1-based line number of a byte offset.
    pub fn line(&self, offset: usize) -> u32 {
        let idx = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        u32::try_from(idx + 1).unwrap_or(u32::MAX)
    }

    pub fn bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }
}

fn strip_comments(raw: &str) -> String {
    let src = raw.as_bytes();
    let mut out = src.to_vec();
    let mut i = 0;
    while i < src.len() {
        match src[i] {
            b'\'' | b'"' | b'`' => i = skip_string(src, i),
            b'/' if src.get(i + 1) == Some(&b'/') => {
                while i < src.len() && src[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if src.get(i + 1) == Some(&b'*') => {
                let start = i;
                i += 2;
                while i < src.len() && !(src[i] == b'*' && src.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                let end = (i + 2).min(src.len());
                for b in &mut out[start..end] {
                    if *b != b'\n' {
                        *b = b' ';
                    }
                }
                i = end;
            }
            b'/' if regex_can_start(src, i) => i = skip_regex(src, i),
            _ => i += 1,
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// A `/` starts a regex literal when it follows an operator or opener.
fn regex_can_start(src: &[u8], i: usize) -> bool {
    let prev = src[..i].iter().rev().find(|b| !b.is_ascii_whitespace());
    match prev {
        None => true,
        Some(b) => b"(,=:[!&|?{};".contains(b),
    }
}

fn skip_regex(src: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    let mut in_class = false;
    while i < src.len() {
        match src[i] {
            b'\n' => return i,
            b'\\' => i += 1,
            b'[' => in_class = true,
            b']' => in_class = false,
            b'/' if !in_class => return i + 1,
            _ => {}
        }
        i += 1;
    }
    i
}

/// Index just past the string literal starting at `start` (a quote byte).
pub(crate) fn skip_string(src: &[u8], start: usize) -> usize {
    let quote = src[start];
    let mut i = start + 1;
    while i < src.len() {
        match src[i] {
            b'\\' => i += 2,
            b'\n' if quote != b'`' => return i,
            b if b == quote => return i + 1,
            _ => i += 1,
        }
    }
    src.len()
}

/// Value of the string literal at `start`, if it is a plain literal
/// (template literals with `${}` interpolation return `None`).
pub(crate) fn string_at(src: &[u8], start: usize) -> Option<(String, usize)> {
    let quote = *src.get(start)?;
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }
    let end = skip_string(src, start);
    if end < start + 2 || src.get(end - 1) != Some(&quote) {
        return None;
    }
    let body = std::str::from_utf8(&src[start + 1..end - 1]).ok()?;
    if quote == b'`' && body.contains("${") {
        return None;
    }
    Some((unescape(body), end))
}

fn unescape(body: &str) -> String {
    if !body.contains('\\') {
        return body.to_string();
    }
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Index of the bracket matching the opener at `open`, skipping strings.
pub(crate) fn find_matching(src: &[u8], open: usize) -> Option<usize> {
    let (o, c) = match src.get(open)? {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        b'<' => (b'<', b'>'),
        _ => return None,
    };
    let mut depth = 0usize;
    let mut i = open;
    while i < src.len() {
        let b = src[i];
        if matches!(b, b'\'' | b'"' | b'`') && o != b'<' {
            i = skip_string(src, i);
            continue;
        }
        if b == o {
            depth += 1;
        } else if b == c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// End (exclusive) of the expression starting at `start`: the first `,`,
/// `;`, or unmatched closer at depth zero.
pub(crate) fn skip_expression(src: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < src.len() {
        match src[i] {
            b'\'' | b'"' | b'`' => {
                i = skip_string(src, i);
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            b',' | b';' if depth == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    src.len()
}

pub(crate) fn skip_ws(src: &[u8], mut i: usize) -> usize {
    while i < src.len() && src[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

pub(crate) fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Reads a dotted identifier (`a.b.c`) at `i`.
fn read_path_ident(src: &[u8], mut i: usize) -> (String, usize) {
    let start = i;
    while i < src.len() && (is_ident_byte(src[i]) || (src[i] == b'.' && i > start)) {
        if src[i] == b'.' && !src.get(i + 1).copied().is_some_and(is_ident_byte) {
            break;
        }
        i += 1;
    }
    (String::from_utf8_lossy(&src[start..i]).into_owned(), i)
}

/// A literal-ish JS value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Str(String),
    Arr(Vec<Node>),
    Obj(Vec<Prop>),
    Call {
        callee: String,
        args: Vec<Node>,
    },
    Spread(Box<Node>),
    /// Anything else: identifiers, arrows, JSX, expressions (trimmed text).
    Raw(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Node {
    pub offset: usize,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Prop {
    pub key: String,
    pub offset: usize,
    pub value: Node,
}

impl Node {
    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Plain identifier text for `Raw` values like `routes` or `ADMIN_ROUTES`.
    pub fn as_ident(&self) -> Option<&str> {
        match &self.value {
            Value::Raw(s) if is_plain_ident(s) => Some(s),
            _ => None,
        }
    }

    pub fn raw_text(&self) -> Option<&str> {
        match &self.value {
            Value::Raw(s) => Some(s),
            _ => None,
        }
    }

    pub fn prop(&self, key: &str) -> Option<&Node> {
        match &self.value {
            Value::Obj(props) => props.iter().find(|p| p.key == key).map(|p| &p.value),
            _ => None,
        }
    }
}

pub(crate) fn is_plain_ident(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(is_ident_byte)
        && !s.as_bytes()[0].is_ascii_digit()
        && !matches!(s, "true" | "false" | "null" | "undefined")
}

const MAX_DEPTH: usize = 48;

/// Parses the value starting at `start` (whitespace allowed).
pub(crate) fn parse_value(src: &[u8], start: usize) -> Node {
    parse_value_at(src, start, 0).0
}

fn parse_value_at(src: &[u8], start: usize, depth: usize) -> (Node, usize) {
    let i = skip_ws(src, start);
    let raw = |end: usize| {
        let end = end.max(i);
        Node {
            offset: i,
            value: Value::Raw(String::from_utf8_lossy(&src[i..end]).trim().to_string()),
        }
    };
    if i >= src.len() || depth > MAX_DEPTH {
        return (raw(i), i);
    }
    match src[i] {
        b'[' => parse_array(src, i, depth),
        b'{' => parse_object(src, i, depth),
        b'\'' | b'"' | b'`' => {
            let end = skip_expression(src, i);
            if let Some((s, str_end)) = string_at(src, i)
                && ends_value(src, str_end, end)
            {
                return (
                    Node {
                        offset: i,
                        value: Value::Str(s),
                    },
                    str_end,
                );
            }
            (raw(end), end)
        }
        b'.' if src[i..].starts_with(b"...") => {
            let (inner, end) = parse_value_at(src, i + 3, depth + 1);
            (
                Node {
                    offset: i,
                    value: Value::Spread(Box::new(inner)),
                },
                end,
            )
        }
        b if is_ident_byte(b) && !b.is_ascii_digit() => {
            let (name, after) = read_path_ident(src, i);
            if name == "await" {
                return parse_value_at(src, after, depth + 1);
            }
            let mut j = skip_ws(src, after);
            if src.get(j) == Some(&b'<')
                && let Some(close) = find_matching(src, j)
            {
                // Generic call: `foo<T>(...)`.
                let next = skip_ws(src, close + 1);
                if src.get(next) == Some(&b'(') {
                    j = next;
                }
            }
            if src.get(j) == Some(&b'(')
                && let Some(close) = find_matching(src, j)
            {
                let end = skip_expression(src, i);
                if ends_value(src, close + 1, end) {
                    let args = parse_list(src, j + 1, close, depth);
                    return (
                        Node {
                            offset: i,
                            value: Value::Call { callee: name, args },
                        },
                        close + 1,
                    );
                }
                return (raw(end), end);
            }
            let end = skip_expression(src, i);
            (raw(end), end)
        }
        _ => {
            let end = skip_expression(src, i);
            (raw(end), end)
        }
    }
}

/// True when only whitespace or a type assertion (`satisfies T`, `as T`)
/// sits between `from` and the expression end.
fn ends_value(src: &[u8], from: usize, end: usize) -> bool {
    let next = skip_ws(src, from);
    if next >= end {
        return true;
    }
    let rest = &src[next..end];
    (rest.starts_with(b"satisfies") || rest.starts_with(b"as"))
        && rest
            .get(if rest.starts_with(b"as") { 2 } else { 9 })
            .is_some_and(u8::is_ascii_whitespace)
}

/// Arguments of the call whose `(` is at `open`, plus the `)` index.
pub(crate) fn parse_call_args(src: &[u8], open: usize) -> Option<(Vec<Node>, usize)> {
    let close = find_matching(src, open)?;
    Some((parse_list(src, open + 1, close, 0), close))
}

/// Parses comma-separated values in `src[start..end]`.
fn parse_list(src: &[u8], start: usize, end: usize, depth: usize) -> Vec<Node> {
    let mut items = Vec::new();
    let mut i = start;
    while i < end {
        i = skip_ws(src, i);
        if i >= end {
            break;
        }
        if src[i] == b',' {
            i += 1;
            continue;
        }
        let (node, next) = parse_value_at(&src[..end], i, depth + 1);
        items.push(node);
        let after = skip_ws(src, next);
        i = if after < end && src[after] == b',' {
            after + 1
        } else if after >= end {
            end
        } else {
            // Resync on unexpected tokens (`satisfies X`, `as const`, JSX text).
            let resync = skip_expression(&src[..end], after);
            if resync <= i { i + 1 } else { resync }
        };
    }
    items
}

fn parse_array(src: &[u8], open: usize, depth: usize) -> (Node, usize) {
    let close = find_matching(src, open).unwrap_or(src.len());
    let items = parse_list(src, open + 1, close, depth);
    (
        Node {
            offset: open,
            value: Value::Arr(items),
        },
        (close + 1).min(src.len()),
    )
}

fn parse_object(src: &[u8], open: usize, depth: usize) -> (Node, usize) {
    let close = find_matching(src, open).unwrap_or(src.len());
    let mut props = Vec::new();
    let mut i = open + 1;
    while i < close {
        i = skip_ws(src, i);
        if i >= close {
            break;
        }
        if src[i] == b',' {
            i += 1;
            continue;
        }
        let key_start = i;
        let key = if src[i..].starts_with(b"...") {
            let (node, next) = parse_value_at(&src[..close], i, depth + 1);
            props.push(Prop {
                key: "...".to_string(),
                offset: key_start,
                value: node,
            });
            i = next;
            continue;
        } else if matches!(src[i], b'\'' | b'"' | b'`') {
            match string_at(src, i) {
                Some((k, end)) => {
                    i = end;
                    k
                }
                None => {
                    i = skip_expression(&src[..close], i);
                    continue;
                }
            }
        } else if src[i] == b'[' {
            i = find_matching(src, i).map_or(close, |c| c + 1);
            "[computed]".to_string()
        } else if is_ident_byte(src[i]) {
            let s = i;
            while i < close && is_ident_byte(src[i]) {
                i += 1;
            }
            String::from_utf8_lossy(&src[s..i]).into_owned()
        } else {
            let next = skip_expression(&src[..close], i);
            i = if next <= i { i + 1 } else { next };
            continue;
        };
        let j = skip_ws(src, i);
        match src.get(j) {
            Some(b':') if j < close => {
                let (node, next) = parse_value_at(&src[..close], j + 1, depth + 1);
                props.push(Prop {
                    key,
                    offset: key_start,
                    value: node,
                });
                i = next;
            }
            Some(b',') | Some(b'}') if j <= close => {
                // Shorthand property: `{ routes }`.
                props.push(Prop {
                    key: key.clone(),
                    offset: key_start,
                    value: Node {
                        offset: key_start,
                        value: Value::Raw(key),
                    },
                });
                i = j;
            }
            _ => {
                // Method shorthand or something we do not model.
                let next = skip_expression(&src[..close], j);
                i = if next <= j { j + 1 } else { next };
                continue;
            }
        }
        let after = skip_ws(src, i);
        if after < close && src[after] != b',' {
            let next = skip_expression(&src[..close], after);
            i = if next <= after { after + 1 } else { next };
        } else {
            i = after;
        }
    }
    (
        Node {
            offset: open,
            value: Value::Obj(props),
        },
        (close + 1).min(src.len()),
    )
}

/// Byte offset of the value assigned by the first
/// `const|let|var NAME (: Type)? =` declaration.
pub(crate) fn find_const_value(text: &str, name: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    for (at, _) in text.match_indices(name) {
        let end = at + name.len();
        if at > 0 && is_ident_byte(bytes[at - 1])
            || bytes.get(end).copied().is_some_and(is_ident_byte)
        {
            continue;
        }
        let before = text[..at].trim_end();
        let keyword_ok = ["const", "let", "var"].iter().any(|kw| {
            before.ends_with(kw)
                && !before[..before.len() - kw.len()]
                    .bytes()
                    .last()
                    .is_some_and(is_ident_byte)
        });
        if !keyword_ok || before.len() == text[..at].len() {
            continue;
        }
        let mut i = skip_ws(bytes, end);
        if bytes.get(i) == Some(&b':') {
            // Type annotation: skip to the `=` that is not `=>` / `==`.
            let mut depth = 0usize;
            i += 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'<' | b'(' | b'[' | b'{' => depth += 1,
                    b'>' | b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                    b'=' if depth == 0 && !matches!(bytes.get(i + 1), Some(b'>') | Some(b'=')) => {
                        break;
                    }
                    b';' | b'\n' if depth == 0 => break,
                    _ => {}
                }
                i += 1;
            }
        }
        if bytes.get(i) == Some(&b'=') && !matches!(bytes.get(i + 1), Some(b'>') | Some(b'=')) {
            return Some(skip_ws(bytes, i + 1));
        }
    }
    None
}

/// String value of `const NAME = "..."` in the same file.
pub(crate) fn resolve_const_string(text: &str, name: &str) -> Option<String> {
    let start = find_const_value(text, name)?;
    string_at(text.as_bytes(), start).map(|(s, _)| s)
}

static IMPORT_DEFAULT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bimport\s+(?:type\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]"#)
        .expect("valid regex")
});
static IMPORT_NAMED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bimport\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]"#)
        .expect("valid regex")
});
static REQUIRE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .expect("valid regex")
});
static REQUIRE_DESTRUCT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#)
        .expect("valid regex")
});

/// One imported binding: local name -> (module specifier, exported name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Import {
    pub local: String,
    pub spec: String,
    /// `default` for default imports and `require()`.
    pub imported: String,
}

pub(crate) fn parse_imports(text: &str) -> Vec<Import> {
    let mut out = Vec::new();
    let named = |list: &str, spec: &str, out: &mut Vec<Import>| {
        for part in list.split(',') {
            let part = part.trim().trim_start_matches("type ").trim();
            if part.is_empty() {
                continue;
            }
            let (imported, local) = match part.split_once(" as ").or_else(|| part.split_once(':')) {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (part, part),
            };
            if is_plain_ident(local) {
                out.push(Import {
                    local: local.to_string(),
                    spec: spec.to_string(),
                    imported: imported.to_string(),
                });
            }
        }
    };
    for cap in IMPORT_DEFAULT_RE.captures_iter(text) {
        let spec = &cap[3];
        out.push(Import {
            local: cap[1].to_string(),
            spec: spec.to_string(),
            imported: "default".to_string(),
        });
        if let Some(list) = cap.get(2) {
            named(list.as_str(), spec, &mut out);
        }
    }
    for cap in IMPORT_NAMED_RE.captures_iter(text) {
        named(&cap[1], &cap[2], &mut out);
    }
    for cap in REQUIRE_RE.captures_iter(text) {
        out.push(Import {
            local: cap[1].to_string(),
            spec: cap[2].to_string(),
            imported: "default".to_string(),
        });
    }
    for cap in REQUIRE_DESTRUCT_RE.captures_iter(text) {
        named(&cap[1], &cap[2], &mut out);
    }
    out
}

/// At most `max` bytes of `s`, cut back to a character boundary.
pub(crate) fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// True when the text looks like it contains JSX markup.
pub(crate) fn has_jsx(text: &str) -> bool {
    text.contains("</") || text.contains("/>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_comments_but_keeps_strings_and_offsets() {
        let raw = "const a = '// not a comment'; // gone\n/* block\n x */ const b = /\\/\\//g;";
        let src = JsSource::new(raw);
        assert_eq!(src.text.len(), raw.len());
        assert!(src.text.contains("'// not a comment'"));
        assert!(!src.text.contains("gone"));
        assert!(!src.text.contains("block"));
        assert!(src.text.contains("/\\/\\//g"));
        assert_eq!(src.line(raw.find("const b").unwrap()), 3);
    }

    #[test]
    fn apostrophe_in_jsx_text_is_contained_to_its_line() {
        let raw = "<p>Don't stop</p>\n<Route path=\"/a\" />";
        let src = JsSource::new(raw);
        let bytes = src.bytes();
        let open = raw.find("Route").unwrap() - 1;
        assert_eq!(
            skip_string(bytes, raw.find('\'').unwrap()),
            raw.find('\n').unwrap()
        );
        assert!(src.text[open..].starts_with("<Route"));
    }

    #[test]
    fn parses_route_like_literals() {
        let text = r#"[
            { path: "/", element: <Root />, children: [
                { index: true, element: <Home /> },
                { path: 'about', lazy: () => import("./about") },
            ]},
            ...prefix("admin", [route("users", "routes/users.tsx")]),
            routes,
        ] satisfies RouteConfig"#;
        let node = parse_value(text.as_bytes(), 0);
        let Value::Arr(items) = &node.value else {
            panic!("expected array, got {node:?}");
        };
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].prop("path").and_then(Node::as_str), Some("/"));
        let Some(Value::Arr(children)) = items[0].prop("children").map(|n| &n.value) else {
            panic!("children");
        };
        assert_eq!(children.len(), 2);
        assert_eq!(
            children[0].prop("index").and_then(Node::raw_text),
            Some("true")
        );
        assert_eq!(
            children[1].prop("path").and_then(Node::as_str),
            Some("about")
        );
        let Value::Spread(inner) = &items[1].value else {
            panic!("spread");
        };
        let Value::Call { callee, args } = &inner.value else {
            panic!("call");
        };
        assert_eq!(callee, "prefix");
        assert_eq!(args.len(), 2);
        assert_eq!(items[2].as_ident(), Some("routes"));
    }

    #[test]
    fn clip_respects_char_boundaries() {
        assert_eq!(clip("héllo", 2), "h");
        assert_eq!(clip("héllo", 3), "hé");
        assert_eq!(clip("abc", 10), "abc");
    }

    #[test]
    fn parses_imports() {
        let text = r#"import admin from './routes/admin/index';
import { api, other as renamed } from "./api";
const legacy = require('./legacy');
const { users } = require("./users");"#;
        let imports = parse_imports(text);
        assert!(imports.contains(&Import {
            local: "admin".into(),
            spec: "./routes/admin/index".into(),
            imported: "default".into()
        }));
        assert!(
            imports
                .iter()
                .any(|i| i.local == "renamed" && i.imported == "other")
        );
        assert!(
            imports
                .iter()
                .any(|i| i.local == "legacy" && i.imported == "default")
        );
        assert!(
            imports
                .iter()
                .any(|i| i.local == "users" && i.imported == "users")
        );
    }

    #[test]
    fn resolves_const_strings() {
        let text = "const DEV_PATH: string = \"/dev/bench\";\nlet MY_DEV_PATH = '/x';\n";
        assert_eq!(
            resolve_const_string(text, "DEV_PATH").as_deref(),
            Some("/dev/bench")
        );
        assert_eq!(
            resolve_const_string(text, "MY_DEV_PATH").as_deref(),
            Some("/x")
        );
        assert_eq!(resolve_const_string(text, "OTHER"), None);
        let typed = "export const routes: Array<{ path: string }> = [];\nconst ok = routes;";
        assert_eq!(find_const_value(typed, "routes"), typed.find('['));
        assert_eq!(find_const_value("useRoutes(routes)", "routes"), None);
    }
}
