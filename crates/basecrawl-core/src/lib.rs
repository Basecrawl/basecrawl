//! `basecrawl` crawler core.
//!
//! At milestone M1 this crate owns the CLI/SDK entrypoint and the assembly of the canonical,
//! non-attestation [`ScrapeProof`] envelope: input validation (URL scheme + output format),
//! a foundational fetch, and construction of the top-level proof shape. Deeper capabilities
//! (TLS 1.3 capture, format producers, canonicalization, egress/geo, attestation) are layered
//! on by subsequent features.

pub mod error;
pub mod fetch;
pub mod format;
pub mod html;
pub mod links;
pub mod markdown;
pub mod metadata;
pub mod url_validation;

use basecrawl_proof::{
    Attestation, Egress, Request, Response, ResultBlock, ScrapeProof, SdkSignature, Tls,
    SCRAPE_PROOF_VERSION,
};
use fetch::{FetchConfig, DEFAULT_TIMEOUT_SECS, DEFAULT_USER_AGENT};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

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
}

impl Default for ScrapeOptions {
    fn default() -> Self {
        Self {
            formats: format::default_set(),
            task_id: None,
            nonce: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            headers: Vec::new(),
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

    // The decoded served source, shared by the rawHtml passthrough and the markdown/links
    // producers. The resolution base is the terminal (post-redirect) URL so relative links/images
    // resolve correctly; a document `<base href>` overrides it inside each producer.
    let body_str = String::from_utf8_lossy(&fetched.body);
    let page_base = Url::parse(&fetched.final_url).unwrap_or_else(|_| url.clone());

    // `rawHtml` is the served source (no render); `html` is the cleaned, post-render DOM. Rendering
    // is triggered only when `html` is requested, so a rawHtml-only scrape never launches a browser.
    let mut formats_produced: BTreeMap<String, Value> = BTreeMap::new();
    for f in &formats {
        let value = match f {
            Format::RawHtml => Value::String(body_str.clone().into_owned()),
            Format::Markdown => Value::String(markdown::to_markdown(&body_str, &page_base)),
            Format::Html => {
                Value::String(html::render_html(&url, &config.user_agent, config.timeout)?)
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
            _ => Value::Null,
        };
        formats_produced.insert(f.as_str().to_string(), value);
    }

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
            result_hash: None,
            completeness_manifest: Value::Object(serde_json::Map::new()),
        },
        egress: Egress::default(),
        attestation: Attestation::default(),
        sdk_signature: SdkSignature::default(),
    })
}
