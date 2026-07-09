//! `basecrawl` crawler core.
//!
//! At milestone M1 this crate owns the CLI/SDK entrypoint and the assembly of the canonical,
//! non-attestation [`ScrapeProof`] envelope: input validation (URL scheme + output format),
//! a foundational fetch, and construction of the top-level proof shape. Deeper capabilities
//! (TLS 1.3 capture, format producers, canonicalization, egress/geo, attestation) are layered
//! on by subsequent features.

pub mod canonical;
pub mod error;
pub mod fetch;
pub mod format;
pub mod html;
pub mod links;
pub mod markdown;
pub mod metadata;
pub mod screenshot;
pub mod url_validation;

use basecrawl_proof::{
    Attestation, Egress, Request, Response, ResultBlock, SdkSignature, Tls, SCRAPE_PROOF_VERSION,
};
use fetch::{FetchConfig, DEFAULT_TIMEOUT_SECS, DEFAULT_USER_AGENT};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

pub use basecrawl_proof::ScrapeProof;
pub use error::Error;
pub use format::Format;

/// The default HTTP method for a scrape.
pub const DEFAULT_METHOD: &str = "GET";

/// Options controlling a single scrape.
#[derive(Debug, Clone)]
pub struct ScrapeOptions {
    /// Requested formats (canonical order). Empty means "use the documented default set".
    pub formats: Vec<Format>,
    /// Validator-issued task id, echoed verbatim into the proof.
    pub task_id: Option<String>,
    /// Validator-issued anti-replay nonce, echoed verbatim into the proof.
    pub nonce: Option<String>,
    /// Whole-request timeout in seconds.
    pub timeout_secs: u64,
    /// Extra request headers to send, as parsed `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Screenshot viewport as `(width, height)` in CSS pixels (device-scale-factor 1).
    pub viewport: (u32, u32),
    /// When true, `screenshot` captures the full scrollable page rather than just the viewport.
    pub screenshot_full_page: bool,
    /// When true (default), the `html`/`markdown` formats are produced from the headless-Chromium
    /// post-render DOM (JS executed). When false (`--no-js`), they are produced from the raw served
    /// source, so no browser is launched and JS-injected content is not present.
    pub render_enabled: bool,
    /// Optional CSS selector that render must wait for before capturing (`--wait-for`).
    pub wait_for: Option<String>,
    /// Whole-render timeout in seconds bounding the JS render step independently of the fetch
    /// timeout, so a pathological (never-idle) page is aborted rather than hanging.
    pub render_timeout_secs: u64,
}

impl Default for ScrapeOptions {
    fn default() -> Self {
        Self {
            formats: format::default_set(),
            task_id: None,
            nonce: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            headers: Vec::new(),
            viewport: (
                basecrawl_render::DEFAULT_VIEWPORT_WIDTH,
                basecrawl_render::DEFAULT_VIEWPORT_HEIGHT,
            ),
            screenshot_full_page: false,
            render_enabled: true,
            wait_for: None,
            render_timeout_secs: basecrawl_render::DEFAULT_RENDER_TIMEOUT_SECS,
        }
    }
}

/// Validate `raw_url`, fetch it, and assemble the canonical [`ScrapeProof`].
///
/// URL/scheme validation happens before any network access, so a non-HTTP scheme or malformed
/// URL is refused without a fetch and without emitting a proof.
pub fn scrape(raw_url: &str, options: &ScrapeOptions) -> Result<ScrapeProof, Error> {
    let url = url_validation::validate_url(raw_url)?;

    let config = FetchConfig {
        timeout: Duration::from_secs(options.timeout_secs),
        headers: options.headers.clone(),
        user_agent: DEFAULT_USER_AGENT.to_string(),
    };
    let fetched = fetch::fetch(&url, &config)?;

    let formats = if options.formats.is_empty() {
        format::default_set()
    } else {
        format::normalize(options.formats.clone())
    };

    // The decoded served source, shared by the rawHtml passthrough and the links/metadata
    // producers. The resolution base is the terminal (post-redirect) URL so relative links/images
    // resolve correctly; a document `<base href>` overrides it inside each producer.
    let body_str = String::from_utf8_lossy(&fetched.body);
    let page_base = Url::parse(&fetched.final_url).unwrap_or_else(|_| url.clone());

    // The post-render DOM feeds `html` and `markdown` so JS-injected content is captured. It is
    // rendered at most once (shared by both formats) and only when rendering is enabled, the served
    // body is a non-empty HTML document, and a render-dependent format was requested — so a
    // `--no-js` run, a `rawHtml`/`links`-only run, and an empty/non-HTML response never launch a
    // browser. When rendering is skipped, `html`/`markdown` fall back to the raw served source.
    let needs_render = formats
        .iter()
        .any(|f| matches!(f, Format::Markdown | Format::Html));
    let is_html = fetched.content_type.as_deref().is_none_or(|ct| {
        let ct = ct.to_ascii_lowercase();
        ct.contains("html") || ct.contains("xml")
    });
    let rendered_html: Option<String> =
        if options.render_enabled && needs_render && is_html && !body_str.trim().is_empty() {
            Some(html::render_page(
                &url,
                &config.user_agent,
                Duration::from_secs(options.render_timeout_secs),
                options.wait_for.as_deref(),
            )?)
        } else {
            None
        };

    // `rawHtml` is always the served source (no render); `html`/`markdown` use the rendered DOM when
    // available and otherwise the served source.
    let mut formats_produced: BTreeMap<String, Value> = BTreeMap::new();
    for f in &formats {
        let value = match f {
            Format::RawHtml => Value::String(body_str.clone().into_owned()),
            Format::Markdown => {
                let source = rendered_html.as_deref().unwrap_or(&body_str);
                Value::String(markdown::to_markdown(source, &page_base))
            }
            Format::Html => {
                let source = rendered_html
                    .clone()
                    .unwrap_or_else(|| body_str.clone().into_owned());
                Value::String(source)
            }
            Format::Links => serde_json::to_value(links::extract(&body_str, &page_base))
                .expect("links surface is always serializable"),
            Format::Metadata => metadata::extract(
                &body_str,
                &metadata::PageMeta {
                    source_url: url.as_str(),
                    status_code: Some(fetched.status_code),
                    content_type: fetched.content_type.as_deref(),
                },
            ),
            Format::Screenshot => {
                let shot = screenshot::capture(
                    &url,
                    &config.user_agent,
                    config.timeout,
                    options.viewport,
                    options.screenshot_full_page,
                )?;
                Value::String(shot.base64)
            }
            _ => Value::Null,
        };
        formats_produced.insert(f.as_str().to_string(), value);
    }

    // `result_hash` covers only the deterministic result surface; `screenshot` (and `json`) are
    // excluded so a viewport tweak that changes only pixels never shifts the byte-quorum digest.
    let result_hash = canonical::result_hash(&formats_produced);

    Ok(ScrapeProof {
        version: SCRAPE_PROOF_VERSION,
        task_id: options.task_id.clone(),
        nonce: options.nonce.clone(),
        request: Request {
            method: DEFAULT_METHOD.to_string(),
            url: url.as_str().to_string(),
            headers_hash: None,
            body_hash: None,
            formats: formats.iter().map(|f| f.as_str().to_string()).collect(),
        },
        tls: Tls::default(),
        response: Response {
            status_code: Some(fetched.status_code),
            headers_hash: Some(fetched.headers_hash),
            body_hash: Some(fetched.body_hash),
            content_length: Some(fetched.content_length),
            final_url: Some(fetched.final_url),
            redirect_chain: fetched.redirects,
        },
        result: ResultBlock {
            formats_produced,
            result_hash: Some(result_hash),
            completeness_manifest: Value::Object(serde_json::Map::new()),
        },
        egress: Egress::default(),
        attestation: Attestation::default(),
        sdk_signature: SdkSignature::default(),
    })
}
