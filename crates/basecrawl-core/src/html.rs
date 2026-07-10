//! Headless-Chromium page rendering: the post-render DOM that feeds the `html` and `markdown`
//! formats.
//!
//! Unlike `rawHtml` (the unmodified served source, produced straight from the HTTP fetch), the
//! rendered DOM is obtained by driving headless Chromium: the page is fetched, its scripts run, the
//! smart network-idle wait (or an explicit `wait_for` selector) lets JS-injected content settle,
//! and the resulting DOM is serialized. This is what makes `html`/`markdown` reflect JS-injected
//! content on a JS-rendered page while `rawHtml` continues to reflect the source. A single render is
//! shared by both `html` and `markdown`, so producing both never launches more than one browser.

use basecrawl_render::{render_until, RenderConfig, RenderError};
use std::time::Instant;
use url::Url;

use crate::error::Error;

/// Post-render DOM plus bounded browser-resource accounting.
pub type RenderedPage = basecrawl_render::Rendered;

/// Render `url` with headless Chromium and return its cleaned, post-render DOM serialization.
///
/// `wait_for`, when supplied, blocks capture until an element matching that CSS selector exists;
/// otherwise the render smart-waits for network idle while following (and bounding) any client-side
/// redirect (meta-refresh / `window.location`). The render also collects infinite-scroll content,
/// dismisses cookie/consent overlays, executes the supplied `actions` in order, and inlines
/// iframe/shadow-DOM content before serializing. Client-side redirects share the HTTP redirect hop
/// cap ([`MAX_REDIRECTS`]) and a loop is surfaced as [`Error::TooManyRedirects`]. The render is
/// bounded by `timeout`; any other failure is surfaced as a structured [`Error`] so the scrape
/// fails loudly rather than emitting misleading output.
pub fn render_page(url: &Url, config: RenderConfig) -> Result<RenderedPage, Error> {
    let deadline = Instant::now() + config.timeout;
    render_page_until(url, config, deadline)
}

/// Render while consuming the scrape-owned absolute deadline.
pub fn render_page_until(
    url: &Url,
    config: RenderConfig,
    deadline: Instant,
) -> Result<RenderedPage, Error> {
    match render_until(url, &config, deadline) {
        Ok(rendered) => Ok(rendered),
        Err(error) if error.is_deadline_exhausted() => Err(Error::Timeout(
            "scrape deadline exceeded during browser setup or render".to_string(),
        )),
        Err(RenderError::TooManyRedirects { max }) => Err(Error::TooManyRedirects {
            max,
            url: url.to_string(),
        }),
        Err(RenderError::PacingDeadlineExceeded) => Err(Error::Timeout(
            "scrape deadline exceeded while waiting for crawl delay".to_string(),
        )),
        Err(RenderError::ResourceBudgetExceeded) => Err(Error::ResourceBudgetExceeded),
        Err(RenderError::DocumentPolicyDenied(detail)) => {
            Err(Error::from_document_policy_denial(detail))
        }
        Err(e) => Err(Error::Render(e.to_string())),
    }
}
