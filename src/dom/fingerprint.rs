use anyhow::{Context, Result};

use crate::browser::PageClient;
use crate::types::graph::DomFingerprint;

pub async fn fingerprint_dom(page: &PageClient) -> Result<DomFingerprint> {
    let script = r#"
(() => {
  function skeleton(el, depth) {
    if (!el || depth > 10) return '';
    const tag = (el.tagName || '').toLowerCase();
    if (!tag) return '';
    // Skip dynamic/repeated containers.
    if (el.children && el.children.length > 10 && ['ul', 'ol', 'tbody', 'div'].includes(tag)) {
      return `<${tag} data-repeat="${el.children.length}"></${tag}>`;
    }
    const attr = (name) => (el.getAttribute ? (el.getAttribute(name) || '') : '');
    const role = attr('role');
    const type = attr('type');
    // Resource/action attributes are included so the fingerprint changes when a
    // broken image (src), broken/changed link (href), or changed form target
    // (action) is introduced — these are common runtime regressions that a pure
    // tag/role/type shape hash would otherwise miss, letting the --fast
    // early-exit pass a regressed page as "unchanged".
    const src = attr('src');
    const href = attr('href');
    const action = attr('action');
    const key = `<${tag}` +
      `${role ? ' role=' + role : ''}` +
      `${type ? ' type=' + type : ''}` +
      `${src ? ' src=' + src : ''}` +
      `${href ? ' href=' + href : ''}` +
      `${action ? ' action=' + action : ''}>`;
    const kids = (el.children ? Array.from(el.children) : [])
      .slice(0, 20)
      .map(c => skeleton(c, depth + 1))
      .join('');
    return key + kids + `</${tag}>`;
  }
  return skeleton(document.body, 0);
})()
"#;

    let skeleton: String = page
        .evaluate_json(script)
        .await
        .context("evaluate DOM skeleton")?;

    let hash = blake3::hash(skeleton.as_bytes()).to_hex().to_string();
    Ok(DomFingerprint(hash))
}
