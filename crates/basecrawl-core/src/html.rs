//! Headless-Chromium page rendering: the post-render DOM that feeds the `html` and `markdown`
//! formats.
//!
//! Unlike `rawHtml` (the unmodified served source, produced straight from the HTTP fetch), the
//! rendered DOM is obtained by driving headless Chromium: the page is fetched, its scripts run, the
//! smart network-idle wait (or an explicit `wait_for` selector) lets JS-injected content settle,
//! and the resulting DOM is serialized. This is what makes `html`/`markdown` reflect JS-injected
//! content on a JS-rendered page while `rawHtml` continues to reflect the source. A single render is
//! shared by both `html` and `markdown`, so producing both never launches more than one browser.

use std::time::Duration;

use basecrawl_render::{render, RenderConfig, DEFAULT_NETWORK_IDLE_QUIET_MS};
use url::Url;

use crate::error::Error;

/// Render `url` with headless Chromium and return its cleaned, post-render DOM serialization.
///
/// `wait_for`, when supplied, blocks capture until an element matching that CSS selector exists;
/// otherwise the render smart-waits for network idle. The render is bounded by `timeout`. A render
/// failure (no browser available, navigation/eval failure, an exceeded timeout, empty DOM) is
/// surfaced as a structured [`Error`] so the scrape fails loudly rather than emitting misleading
/// output.
pub fn render_page(
    url: &Url,
    user_agent: &str,
    timeout: Duration,
    wait_for: Option<&str>,
) -> Result<String, Error> {
    let config = RenderConfig {
        timeout,
        user_agent: user_agent.to_string(),
        wait_for: wait_for.map(str::to_string),
        network_idle: true,
        quiet_period: Duration::from_millis(DEFAULT_NETWORK_IDLE_QUIET_MS),
    };
    let rendered = render(url, &config).map_err(|e| Error::Render(e.to_string()))?;
    Ok(rendered.html)
}
