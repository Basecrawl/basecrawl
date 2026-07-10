//! `basecrawl` crawler core.
//!
//! At milestone M1 this crate owns the CLI/SDK entrypoint and the assembly of the canonical,
//! non-attestation [`ScrapeProof`] envelope: input validation (URL scheme + output format),
//! a foundational fetch, and construction of the top-level proof shape. Deeper capabilities
//! (TLS 1.3 capture, format producers, canonicalization, egress/geo, attestation) are layered
//! on by subsequent features.

pub mod canonical;
pub mod charset;
pub mod content;
pub mod document;
pub mod egress;
pub mod error;
pub mod fetch;
pub mod format;
pub mod html;
pub mod links;
pub mod markdown;
pub mod metadata;
pub mod pagination;
pub mod robots;
pub mod screenshot;
pub mod url_validation;

use basecrawl_proof::{
    Attestation, Request, Response, ResultBlock, SdkSignature, SCRAPE_PROOF_VERSION,
};
use content::ContentKind;
use fetch::{FetchConfig, DEFAULT_MAX_BODY_BYTES, DEFAULT_TIMEOUT_SECS, DEFAULT_USER_AGENT};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};
use url::Url;

pub use basecrawl_proof::ScrapeProof;
pub use basecrawl_render::{Action, ScrollDirection};
pub use error::Error;
pub use format::Format;
pub use robots::RobotsPolicy;

/// The default HTTP method for a scrape.
pub const DEFAULT_METHOD: &str = "GET";

/// Default cap on the number of pages crawled when pagination following is enabled.
pub const DEFAULT_MAX_PAGES: usize = 5;

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
    /// Bypass TLS certificate verification. Disabled by default and intended only for an explicit
    /// diagnostic fetch of an invalid-certificate origin.
    pub insecure: bool,
    /// Maximum decoded response-body bytes retained in memory. Responses beyond this cap are
    /// truncated and signaled in the ScrapeProof response block.
    pub max_body_bytes: usize,
    /// Minimum spacing between physical requests to the same origin, including robots, redirects,
    /// sitemap discovery, pagination, and browser subresources.
    pub crawl_delay_ms: u64,
    /// Maximum browser subresources accepted while producing the rendered DOM.
    pub max_render_subresources: usize,
    /// Maximum sum of declared browser subresource response bytes accepted during one render.
    pub max_render_bytes: u64,
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
    /// Scripted navigation actions executed in order in the browser after the page settles and
    /// before capture (click / scroll / wait / wait-for-selector).
    pub actions: Vec<Action>,
    /// When true, follow "next page" links across a paginated listing, aggregating markdown and
    /// recording the crawled URL set.
    pub follow_pagination: bool,
    /// The maximum number of pages crawled (including the first) when `follow_pagination` is set.
    pub max_pages: usize,
    /// Handling for an origin's robots policy. The default is enforce: covered denied paths are
    /// never fetched, while allowed/unmatched paths proceed with an observable metadata decision.
    pub robots_policy: RobotsPolicy,
}

impl Default for ScrapeOptions {
    fn default() -> Self {
        Self {
            formats: format::default_set(),
            task_id: None,
            nonce: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            headers: Vec::new(),
            insecure: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            crawl_delay_ms: 0,
            max_render_subresources: basecrawl_render::DEFAULT_MAX_RENDER_SUBRESOURCES,
            max_render_bytes: basecrawl_render::DEFAULT_MAX_RENDER_BYTES,
            viewport: (
                basecrawl_render::DEFAULT_VIEWPORT_WIDTH,
                basecrawl_render::DEFAULT_VIEWPORT_HEIGHT,
            ),
            screenshot_full_page: false,
            render_enabled: true,
            wait_for: None,
            render_timeout_secs: basecrawl_render::DEFAULT_RENDER_TIMEOUT_SECS,
            actions: Vec::new(),
            follow_pagination: false,
            max_pages: DEFAULT_MAX_PAGES,
            robots_policy: RobotsPolicy::Enforce,
        }
    }
}

/// Validate `raw_url`, fetch it, and assemble the canonical [`ScrapeProof`].
///
/// URL/scheme validation happens before any network access, so a non-HTTP scheme or malformed
/// URL is refused without a fetch and without emitting a proof.
pub fn scrape(raw_url: &str, options: &ScrapeOptions) -> Result<ScrapeProof, Error> {
    let url = url_validation::validate_url(raw_url)?;
    let deadline = Instant::now() + Duration::from_secs(options.timeout_secs);

    let formats = if options.formats.is_empty() {
        format::default_set()
    } else {
        format::normalize(options.formats.clone())
    };

    // JSON structured extraction depends on an optional LLM-backed capability that is not part of
    // this deterministic M1 image. Refuse it before robots/fetch/render work so callers never
    // receive a successful proof that misleadingly contains `json: null`.
    if formats.contains(&Format::Json) {
        return Err(Error::StructuredExtractionUnsupported);
    }

    // Build this once before robots/DNS/rendering. It is the single validated ordered effective
    // header list shared by request hashing, direct HTTP/HTTPS, and Chromium.
    let effective_headers = fetch::effective_headers(&options.headers, DEFAULT_USER_AGENT)?;
    let config = FetchConfig {
        timeout: Duration::from_secs(options.timeout_secs),
        headers: effective_headers,
        credential_origin: Some(url.clone()),
        user_agent: DEFAULT_USER_AGENT.to_string(),
        insecure: options.insecure,
        max_body_bytes: options.max_body_bytes,
        crawl_delay: Duration::from_millis(options.crawl_delay_ms),
        ..FetchConfig::default()
    };
    let robots_decision = robots::consult(&url, &config, options.robots_policy, deadline)?;
    if robots_decision.denies_fetch() {
        return Err(Error::RobotsDenied(robots_decision.to_value()));
    }
    let fetched = fetch::fetch_until(&url, &config, deadline)?;

    // The request-side hashes cover the one validated ordered effective header list. The empty GET
    // body remains explicitly hashed.
    let headers_hash = canonical::headers_hash(&config.headers);
    let body_hash = canonical::body_hash(&[]);
    let request_hash =
        canonical::request_hash(DEFAULT_METHOD, url.as_str(), &headers_hash, &body_hash);
    let format_names: Vec<String> = formats
        .iter()
        .map(|format| format.as_str().to_string())
        .collect();

    // The decoded served source, shared by the rawHtml passthrough and the links/metadata
    // producers. The resolution base is the terminal (post-redirect) URL so relative links/images
    // resolve correctly; a document `<base href>` overrides it inside each producer.
    let content_kind = content::classify(fetched.content_type.as_deref());
    let document_text = match content_kind {
        ContentKind::Document(kind)
            if formats
                .iter()
                .any(|format| matches!(format, Format::Markdown | Format::Html)) =>
        {
            Some(document::extract(&fetched.body, kind).map_err(Error::DocumentExtraction)?)
        }
        _ => None,
    };
    let mut body_str = if matches!(content_kind, ContentKind::Document(_)) {
        String::new()
    } else {
        charset::decode_body(
            &fetched.body,
            fetched.content_type.as_deref(),
            content_kind == ContentKind::Html,
        )
    };
    redact_sensitive_request_echoes(&mut body_str, &options.headers);
    let page_base = Url::parse(&fetched.final_url).unwrap_or_else(|_| url.clone());
    let sitemap_urls = if formats.contains(&Format::Links) {
        robots::discover_sitemap_urls(&url, &config, &robots_decision.sitemap_urls, deadline)?
    } else {
        Vec::new()
    };

    // The post-render DOM feeds `html` and `markdown` so JS-injected content is captured. It is
    // rendered at most once (shared by both formats) and only when rendering is enabled, the served
    // body is a non-empty HTML document, and a render-dependent format was requested — so a
    // `--no-js` run, a `rawHtml`/`links`-only run, and an empty/non-HTML response never launch a
    // browser. When rendering is skipped, `html`/`markdown` fall back to the raw served source.
    let needs_render = formats
        .iter()
        .any(|f| matches!(f, Format::Markdown | Format::Html));
    let mut render_resource_usage = basecrawl_render::RenderResourceUsage::default();
    let rendered_html: Option<String> = if options.render_enabled
        && needs_render
        && content_kind == ContentKind::Html
        && !body_str.trim().is_empty()
    {
        config.wait_for_origin_until(&page_base, deadline)?;
        let mut rendered = html::render_page_until(
            &page_base,
            basecrawl_render::RenderConfig {
                timeout: Duration::from_secs(options.render_timeout_secs),
                user_agent: config.user_agent.clone(),
                request_headers: config.headers.clone(),
                credential_origin: Some(url.clone()),
                crawl_delay: config.crawl_delay,
                max_subresources: options.max_render_subresources,
                max_resource_bytes: options.max_render_bytes,
                wait_for: options.wait_for.clone(),
                actions: options.actions.clone(),
                max_redirects: fetch::MAX_REDIRECTS,
                ..basecrawl_render::RenderConfig::default()
            },
            deadline,
        )?;
        redact_sensitive_request_echoes(&mut rendered.html, &options.headers);
        render_resource_usage = rendered.resource_usage;
        Some(rendered.html)
    } else {
        None
    };

    // `rawHtml` is always the served source (no render); `html`/`markdown` use the rendered DOM when
    // available and otherwise the served source.
    let mut formats_produced: BTreeMap<String, Value> = BTreeMap::new();
    for f in &formats {
        let value = match f {
            Format::RawHtml => text_surface(&body_str, content_kind),
            Format::Markdown => {
                if content_kind == ContentKind::Html {
                    let source = rendered_html.as_deref().unwrap_or(&body_str);
                    Value::String(markdown::to_markdown(source, &page_base))
                } else if matches!(content_kind, ContentKind::Document(_)) {
                    Value::String(document_text.clone().unwrap_or_default())
                } else {
                    text_surface(&body_str, content_kind)
                }
            }
            Format::Html => {
                if content_kind == ContentKind::Html {
                    let source = rendered_html.clone().unwrap_or_else(|| body_str.clone());
                    Value::String(source)
                } else if matches!(content_kind, ContentKind::Document(_)) {
                    Value::String(document_text.clone().unwrap_or_default())
                } else {
                    text_surface(&body_str, content_kind)
                }
            }
            Format::Links => links_surface(&body_str, &page_base, content_kind, &sitemap_urls),
            Format::Metadata => {
                let mut value = metadata::extract_for_content(
                    &body_str,
                    &metadata::PageMeta {
                        source_url: url.as_str(),
                        status_code: Some(fetched.status_code),
                        content_type: fetched.content_type.as_deref(),
                    },
                    content_kind == ContentKind::Html,
                );
                if let Value::Object(metadata) = &mut value {
                    metadata.insert("robotsPolicy".to_string(), robots_decision.to_value());
                }
                value
            }
            Format::Screenshot => {
                config.wait_for_origin_until(&page_base, deadline)?;
                let shot = screenshot::capture_until(
                    &page_base,
                    basecrawl_render::ScreenshotConfig {
                        timeout: config.timeout,
                        user_agent: config.user_agent.clone(),
                        request_headers: config.headers.clone(),
                        credential_origin: Some(url.clone()),
                        crawl_delay: config.crawl_delay,
                        max_subresources: options.max_render_subresources,
                        max_resource_bytes: options.max_render_bytes,
                        width: options.viewport.0,
                        height: options.viewport.1,
                        full_page: options.screenshot_full_page,
                    },
                    deadline,
                )?;
                render_resource_usage.subresource_count = render_resource_usage
                    .subresource_count
                    .saturating_add(shot.resource_usage.subresource_count);
                render_resource_usage.resource_bytes = render_resource_usage
                    .resource_bytes
                    .saturating_add(shot.resource_usage.resource_bytes);
                render_resource_usage.cap_exceeded |= shot.resource_usage.cap_exceeded
                    || render_resource_usage.subresource_count
                        > options.max_render_subresources as u64
                    || render_resource_usage.resource_bytes > options.max_render_bytes;
                Value::String(shot.base64)
            }
            _ => Value::Null,
        };
        formats_produced.insert(f.as_str().to_string(), value);
    }

    // Pagination following: walk "next page" links, aggregating markdown and recording the crawled
    // URL set. Gated behind the option, so a single-page scrape is unchanged. Subsequent pages are
    // best-effort — a failed page ends the crawl rather than failing the whole scrape.
    let mut crawled_urls: Vec<String> = Vec::new();
    if options.follow_pagination {
        crawled_urls.push(url.as_str().to_string());
        let max_pages = options.max_pages.max(1);
        let mut current_html = rendered_html.clone().unwrap_or_else(|| body_str.clone());
        let mut current_base = page_base.clone();
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(url.as_str().to_string());

        let mut aggregated_markdown: Option<String> = if formats.contains(&Format::Markdown) {
            formats_produced
                .get(Format::Markdown.as_str())
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };

        while crawled_urls.len() < max_pages {
            let Some(next) = pagination::find_next(&current_html, &current_base) else {
                break;
            };
            let key = next.as_str().to_string();
            if !visited.insert(key.clone()) {
                break;
            }
            let (page_markdown, page_html, page_base_next) =
                crawl_page(&next, options, &config, deadline)?;
            if let Some(agg) = aggregated_markdown.as_mut() {
                agg.push_str("\n\n");
                agg.push_str(&page_markdown);
            }
            crawled_urls.push(key);
            current_html = page_html;
            current_base = page_base_next;
        }

        if let Some(agg) = aggregated_markdown {
            formats_produced.insert(Format::Markdown.as_str().to_string(), Value::String(agg));
        }
    }

    if Instant::now() >= deadline {
        return Err(Error::Timeout("scrape deadline exceeded".to_string()));
    }

    // `result_hash` covers only the deterministic result surface; `screenshot` (and `json`) are
    // excluded so a viewport tweak that changes only pixels never shifts the byte-quorum digest.
    let result_hash = canonical::result_hash(&formats_produced);
    let completeness_manifest = canonical::completeness_manifest(&format_names, &formats_produced);
    let manifest_sha256 =
        canonical::manifest_sha256(url.as_str(), options.nonce.as_deref(), &result_hash);
    let egress = egress::build(fetched.egress_ip, fetched.fetched_at, &request_hash)?;

    Ok(ScrapeProof {
        version: SCRAPE_PROOF_VERSION,
        task_id: options.task_id.clone(),
        nonce: options.nonce.clone(),
        request: Request {
            method: DEFAULT_METHOD.to_string(),
            url: url.as_str().to_string(),
            headers_hash: Some(headers_hash),
            body_hash: Some(body_hash),
            request_hash: Some(request_hash),
            formats: format_names,
        },
        tls: fetched.tls,
        response: Response {
            status_code: Some(fetched.status_code),
            headers_hash: Some(fetched.headers_hash),
            body_hash: Some(fetched.body_hash),
            content_length: Some(fetched.content_length),
            content_type: fetched.content_type,
            body_truncated: fetched.body_truncated,
            body_max_bytes: Some(options.max_body_bytes as u64),
            final_url: Some(fetched.final_url),
            redirect_chain: fetched.redirects,
            render_subresource_count: render_resource_usage.subresource_count,
            render_subresource_max_count: options.max_render_subresources as u64,
            render_resource_bytes: render_resource_usage.resource_bytes,
            render_max_bytes: options.max_render_bytes,
            render_resource_cap_exceeded: render_resource_usage.cap_exceeded,
        },
        result: ResultBlock {
            formats_produced,
            result_hash: Some(result_hash),
            completeness_manifest,
            manifest_sha256: Some(manifest_sha256),
            crawled_urls,
        },
        egress,
        attestation: Attestation::default(),
        sdk_signature: SdkSignature::default(),
    })
}

/// Fetch and extract a single pagination page: returns its markdown, the HTML used to locate the
/// next link (rendered DOM when rendering applies, else the served source), and the resolution base.
/// Subsequent pages are not subject to the page-1 scripted actions.
fn crawl_page(
    url: &Url,
    options: &ScrapeOptions,
    config: &FetchConfig,
    deadline: Instant,
) -> Result<(String, String, Url), Error> {
    let fetched = fetch::fetch_until(url, config, deadline)?;
    let is_html = content::classify(fetched.content_type.as_deref()) == ContentKind::Html;
    let mut body_str =
        charset::decode_body(&fetched.body, fetched.content_type.as_deref(), is_html);
    redact_sensitive_request_echoes(&mut body_str, &options.headers);
    let page_base = Url::parse(&fetched.final_url).unwrap_or_else(|_| url.clone());
    let source = if options.render_enabled && is_html && !body_str.trim().is_empty() {
        config.wait_for_origin_until(&page_base, deadline)?;
        let mut rendered = html::render_page_until(
            &page_base,
            basecrawl_render::RenderConfig {
                timeout: Duration::from_secs(options.render_timeout_secs),
                user_agent: config.user_agent.clone(),
                request_headers: config.headers.clone(),
                credential_origin: Some(url.clone()),
                crawl_delay: config.crawl_delay,
                max_subresources: options.max_render_subresources,
                max_resource_bytes: options.max_render_bytes,
                wait_for: options.wait_for.clone(),
                max_redirects: fetch::MAX_REDIRECTS,
                ..basecrawl_render::RenderConfig::default()
            },
            deadline,
        )?;
        redact_sensitive_request_echoes(&mut rendered.html, &options.headers);
        rendered.html
    } else {
        body_str
    };
    let markdown = markdown::to_markdown(&source, &page_base);
    Ok((markdown, source, page_base))
}

fn text_surface(body: &str, content_kind: ContentKind) -> Value {
    match content_kind {
        ContentKind::Binary | ContentKind::Document(_) => Value::String(String::new()),
        ContentKind::Html | ContentKind::Text => Value::String(body.to_owned()),
    }
}

fn links_surface(
    body: &str,
    page_base: &Url,
    content_kind: ContentKind,
    sitemap_urls: &[String],
) -> Value {
    if content_kind == ContentKind::Html {
        let mut links = links::extract(body, page_base);
        links.sitemap = sitemap_urls.to_vec();
        serde_json::to_value(links).expect("links surface is always serializable")
    } else {
        let links = links::Links {
            sitemap: sitemap_urls.to_vec(),
            ..links::Links::default()
        };
        serde_json::to_value(links).expect("links surface is always serializable")
    }
}

/// Remove request-header values when an origin reflects them into a surfaced result.
///
/// A valid origin can echo arbitrary custom headers, not just `Authorization` or `Cookie`, in
/// JSON/debug output. The proof commits to the original response via `response.body_hash`, but
/// plaintext result formats must not re-emit request-header material. Matching values rather than
/// names handles arbitrary echo-body layouts without changing unrelated response content.
fn redact_sensitive_request_echoes(body: &mut String, headers: &[(String, String)]) {
    for (name, value) in headers {
        if !value.is_empty() {
            *body = body.replace(value, "<redacted>");
        }
        if is_sensitive_request_header(name) {
            for secret in sensitive_header_components(name, value) {
                *body = body.replace(secret, "<redacted>");
            }
        }
    }
}

fn is_sensitive_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("set-cookie")
}

/// Return credentials embedded within an authentication or cookie header.
///
/// Full-value replacement catches normal reflective endpoints. These smaller components close the
/// gap for endpoints that reflect only a bearer credential or only the value side of a cookie.
fn sensitive_header_components<'a>(name: &str, value: &'a str) -> Vec<&'a str> {
    if name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
    {
        return value.split_whitespace().skip(1).collect();
    }

    value
        .split(';')
        .filter_map(|cookie| {
            cookie
                .trim()
                .split_once('=')
                .map(|(_, secret)| secret.trim())
        })
        .filter(|secret| !secret.is_empty())
        .collect()
}
