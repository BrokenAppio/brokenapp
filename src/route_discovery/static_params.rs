//! Concrete values for dynamic routes from literal `generateStaticParams`
//! (Next app router) and `getStaticPaths` (Next pages router, Astro) bodies.
//!
//! Handles three shapes, single-parameter routes only:
//! - `{ slug: "a" }` object literals in the body;
//! - `["a", "b"].map((x) => ({ slug: x }))` string arrays;
//! - `items.map((i) => ({ slug: i.slug }))` where `items` is a literal array
//!   declared in the same file or imported from a relative/aliased module.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::Ctx;
use super::js::{self, JsSource};

const MAX_EXAMPLES: usize = 50;

static TOP_LEVEL_DECL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\n(?:export\b|function\b|async\s+function\b|const\b|let\b|class\b)")
        .expect("valid regex")
});
static STRING_ARRAY_MAP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\[((?:\s*(?:"[^"\n]*"|'[^'\n]*')\s*,?)+)\]\s*\.map\s*\("#).expect("valid regex")
});
static STRING_LIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"\n]*)"|'([^'\n]*)'"#).expect("valid regex"));
static COLLECTION_MAP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\.\s*map\s*\(").expect("valid regex"));

/// Concrete router-relative paths for `route_path` (which must contain one
/// `:param` segment), or empty when the values are not literal.
pub(crate) fn examples(
    ctx: &Ctx,
    file: &Path,
    src: &JsSource,
    route_path: &str,
    fn_names: &[&str],
) -> Vec<String> {
    let params: Vec<&str> = route_path
        .split('/')
        .filter(|s| s.starts_with(':'))
        .collect();
    let [param_seg] = params.as_slice() else {
        return Vec::new();
    };
    let param = param_seg.trim_start_matches(':');
    if param.ends_with(['*', '+', '?']) {
        return Vec::new();
    }
    let Some(body) = function_body(&src.text, fn_names) else {
        return Vec::new();
    };
    let values = literal_values(ctx, file, src, body, param);
    values
        .into_iter()
        .filter(|v| !v.is_empty() && !v.contains(['/', ' ', '?', '#']))
        .take(MAX_EXAMPLES)
        .map(|v| {
            route_path
                .split('/')
                .map(|s| if s == *param_seg { v.as_str() } else { s })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}

/// Text from the named function to the next top-level declaration.
fn function_body<'a>(text: &'a str, fn_names: &[&str]) -> Option<&'a str> {
    let start = fn_names
        .iter()
        .filter(|name| text.contains(*name))
        .find_map(|name| {
            let re = Regex::new(&format!(
                r"(?:function\s+{0}\s*\(|(?:const|let)\s+{0}\b[^=]*=)",
                regex::escape(name)
            ))
            .ok()?;
            re.find(text).map(|m| m.end())
        })?;
    let rest = &text[start..];
    let end = TOP_LEVEL_DECL_RE
        .find(rest)
        .map_or(rest.len(), |m| m.start());
    Some(js::clip(&rest[..end], 8_000))
}

fn literal_values(ctx: &Ctx, file: &Path, src: &JsSource, body: &str, param: &str) -> Vec<String> {
    let key_re = Regex::new(&format!(
        r#"\b{}\s*:\s*(?:"([^"\n]*)"|'([^'\n]*)'|`([^`$\n]*)`)"#,
        regex::escape(param)
    ));
    let mut values: Vec<String> = Vec::new();
    if let Ok(re) = &key_re {
        values.extend(re.captures_iter(body).filter_map(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .or_else(|| c.get(3))
                .map(|m| m.as_str().to_string())
        }));
    }
    if values.is_empty()
        && let Some(cap) = STRING_ARRAY_MAP_RE.captures(body)
    {
        values.extend(string_literals(&cap[1]));
    }
    if values.is_empty() {
        values.extend(collection_field_values(ctx, file, src, body, param));
    }
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|v| seen.insert(v.clone()));
    values
}

fn string_literals(text: &str) -> Vec<String> {
    STRING_LIT_RE
        .captures_iter(text)
        .filter_map(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .collect()
}

/// `{ slug: item.slug }` + `items.map(` -> every `slug: "..."` inside the
/// literal `items` array.
fn collection_field_values(
    ctx: &Ctx,
    file: &Path,
    src: &JsSource,
    body: &str,
    param: &str,
) -> Vec<String> {
    let field_re = match Regex::new(&format!(
        r"\b{}\s*:\s*[A-Za-z_$][\w$]*\s*\.\s*([A-Za-z_$][\w$]*)",
        regex::escape(param)
    )) {
        Ok(re) => re,
        Err(_) => return Vec::new(),
    };
    let field = match field_re.captures(body) {
        Some(c) => c[1].to_string(),
        None => return Vec::new(),
    };
    let Some(collection) = COLLECTION_MAP_RE
        .captures(body)
        .map(|c| c[1].to_string())
        .filter(|name| name != "Object")
    else {
        return Vec::new();
    };

    let (target_src, name) = if js::find_const_value(&src.text, &collection).is_some() {
        (None, collection.clone())
    } else {
        let Some(import) = js::parse_imports(&src.text)
            .into_iter()
            .find(|i| i.local == collection)
        else {
            return Vec::new();
        };
        let Some(target) = ctx.resolve_import(file, &import.spec) else {
            return Vec::new();
        };
        (ctx.source(&target), import.imported)
    };
    let text = target_src
        .as_ref()
        .map_or(src.text.as_str(), |s| s.text.as_str());
    let Some(start) = js::find_const_value(text, &name) else {
        return Vec::new();
    };
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'[') {
        return Vec::new();
    }
    let Some(end) = js::find_matching(bytes, start) else {
        return Vec::new();
    };
    let lit_re = match Regex::new(&format!(
        r#"\b{}\s*:\s*(?:"([^"\n]*)"|'([^'\n]*)')"#,
        regex::escape(&field)
    )) {
        Ok(re) => re,
        Err(_) => return Vec::new(),
    };
    lit_re
        .captures_iter(&text[start..end])
        .filter_map(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .collect()
}
