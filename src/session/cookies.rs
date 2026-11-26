use anyhow::{Context, Result};
use chromiumoxide::cdp::browser_protocol::network;
use url::Url;

/// Capture a `Cookie:` header value for the current site from a live browser session.
///
/// This is used for network-replay features that need to send HTTP requests
/// authenticated as the same user/session as the scan.
///
/// Important: the returned string contains sensitive values. Do not log it.
pub async fn capture_cookie_header(
    browser: &crate::browser::BrowserManager,
    base_url: &Url,
) -> Result<String> {
    let host = base_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("base url missing host"))?
        .to_ascii_lowercase();

    let page = browser.new_page("about:blank").await?;
    page.enable_domains().await?;
    let res = page
        .inner()
        .execute(network::GetCookiesParams::default())
        .await
        .context("Network.getCookies")?;
    let _ = page.inner().clone().close().await;

    let mut parts = Vec::new();
    for c in res.result.cookies {
        // Only include cookies for the current site.
        let dom = c.domain.trim_start_matches('.').to_ascii_lowercase();
        if dom.is_empty() {
            continue;
        }
        // Cookie domain may be a parent domain (e.g. "example.com" for
        // "app.example.com").
        if dom != host && !host.ends_with(&format!(".{dom}")) {
            continue;
        }
        parts.push(format!("{}={}", c.name, c.value));
    }

    Ok(parts.join("; "))
}
