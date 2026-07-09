//! `basecrawl` CLI: scrape a URL and emit exactly one canonical ScrapeProof JSON object.
//!
//! On success the ScrapeProof is written to stdout (nothing else). On failure a structured
//! `{"error": {...}}` object is written to stderr and the process exits non-zero, so a failed
//! run never emits a partial ScrapeProof on stdout.

use base64::Engine;
use basecrawl_core::error::Error;
use basecrawl_core::fetch::{parse_header, DEFAULT_MAX_BODY_BYTES, DEFAULT_TIMEOUT_SECS};
use basecrawl_core::{
    format, scrape, screenshot, Action, Format, ScrapeOptions, DEFAULT_MAX_PAGES,
};
use clap::Parser;
use std::path::PathBuf;

/// basecrawl: verifiable web crawler that emits a canonical ScrapeProof.
#[derive(Parser, Debug)]
#[command(name = "basecrawl", version, about, long_about = None)]
struct Cli {
    /// URL to scrape (http/https only).
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Comma-separated output formats: markdown, html, rawHtml, links, metadata, screenshot, json
    /// [default: markdown,metadata].
    #[arg(long, value_delimiter = ',', value_name = "FORMATS")]
    formats: Option<Vec<String>>,

    /// Validator-issued task identifier, echoed verbatim into the ScrapeProof.
    #[arg(long, value_name = "TASK_ID")]
    task_id: Option<String>,

    /// Validator-issued anti-replay nonce, echoed verbatim into the ScrapeProof.
    #[arg(long, value_name = "NONCE")]
    nonce: Option<String>,

    /// Custom request header 'Name: Value', repeatable, sent to the origin.
    #[arg(long = "header", value_name = "HEADER")]
    headers: Vec<String>,

    /// Whole-request timeout in seconds; a slower endpoint aborts near this bound.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS, value_name = "SECONDS")]
    timeout: u64,

    /// Maximum decoded response-body bytes retained in memory [default: 10485760]. Bodies beyond
    /// this cap are truncated and reported as response.body_truncated=true in the ScrapeProof.
    #[arg(long, default_value_t = DEFAULT_MAX_BODY_BYTES, value_name = "BYTES")]
    max_body_bytes: usize,

    /// Explicitly bypass TLS certificate validation. This is disabled by default and is intended
    /// only for diagnostic capture of an invalid-certificate endpoint.
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Disable JS rendering: produce html/markdown from the raw served source (no headless browser),
    /// so JS-injected content is not present.
    #[arg(long = "no-js", default_value_t = false)]
    no_js: bool,

    /// Block capture until an element matching this CSS selector exists (headless render only).
    #[arg(long = "wait-for", value_name = "SELECTOR")]
    wait_for: Option<String>,

    /// Whole-render timeout in seconds bounding the JS render step; a never-idle page aborts near
    /// this bound instead of hanging [default: the --timeout value].
    #[arg(long = "render-timeout", value_name = "SECONDS")]
    render_timeout: Option<u64>,

    /// Ordered scripted actions as a JSON array executed in the browser before capture, e.g.
    /// '[{"type":"click","selector":"#more"},{"type":"wait","milliseconds":500}]'.
    #[arg(long = "actions", value_name = "JSON")]
    actions: Option<String>,

    /// Follow "next page" links across a paginated listing, aggregating content and recording the
    /// crawled URL set (result.crawled_urls).
    #[arg(long = "follow-pagination", default_value_t = false)]
    follow_pagination: bool,

    /// Maximum number of pages to crawl (including the first) when --follow-pagination is set.
    #[arg(long = "max-pages", default_value_t = DEFAULT_MAX_PAGES, value_name = "N")]
    max_pages: usize,

    /// Screenshot viewport WIDTHxHEIGHT in CSS pixels (device-scale-factor 1).
    #[arg(long, default_value = "1280x800", value_name = "WxH")]
    viewport: String,

    /// Capture the full scrollable page (beyond the fold) for the screenshot format.
    #[arg(long = "screenshot-full-page", default_value_t = false)]
    screenshot_full_page: bool,

    /// Also write the decoded screenshot PNG to this file (implies the screenshot format).
    #[arg(long = "screenshot-out", value_name = "PATH")]
    screenshot_out: Option<PathBuf>,

    /// Output format for the emitted proof (only "json" is supported).
    #[arg(long, default_value = "json", value_name = "OUTPUT")]
    output: String,
}

fn run(cli: Cli) -> Result<String, Error> {
    if cli.output != "json" {
        return Err(Error::UnsupportedOutput(cli.output));
    }

    let raw_url = cli.url.ok_or(Error::MissingUrl)?;

    // Validate formats before any fetch so an unknown format never triggers a network request.
    let mut formats = match &cli.formats {
        Some(tokens) if !tokens.is_empty() => format::parse_list(tokens)?,
        _ => format::default_set(),
    };

    // Writing the screenshot to a file requires producing it, so opt the format in when the user
    // asked for a file but not the format explicitly.
    if cli.screenshot_out.is_some() && !formats.contains(&Format::Screenshot) {
        formats.push(Format::Screenshot);
        formats = format::normalize(formats);
    }

    // Parse the viewport before any fetch so a malformed spec never triggers a network request.
    let viewport = screenshot::parse_viewport(&cli.viewport)?;

    // Parse custom headers before any fetch so a malformed header never triggers a network request.
    let headers = cli
        .headers
        .iter()
        .map(|spec| parse_header(spec))
        .collect::<Result<Vec<_>, _>>()?;

    // Parse scripted actions before any fetch so a malformed spec never triggers a network request.
    let actions = match &cli.actions {
        Some(json) => serde_json::from_str::<Vec<Action>>(json)
            .map_err(|e| Error::InvalidActions(e.to_string()))?,
        None => Vec::new(),
    };

    let options = ScrapeOptions {
        formats,
        task_id: cli.task_id,
        nonce: cli.nonce,
        timeout_secs: cli.timeout,
        headers,
        insecure: cli.insecure,
        max_body_bytes: cli.max_body_bytes,
        viewport,
        screenshot_full_page: cli.screenshot_full_page,
        render_enabled: !cli.no_js,
        wait_for: cli.wait_for,
        // Bound the render by its own flag when given, else reuse the request timeout so a single
        // --timeout still bounds a pathological render.
        render_timeout_secs: cli.render_timeout.unwrap_or(cli.timeout),
        actions,
        follow_pagination: cli.follow_pagination,
        max_pages: cli.max_pages,
    };

    let proof = scrape(&raw_url, &options)?;

    if let Some(path) = &cli.screenshot_out {
        write_screenshot(&proof, path)?;
    }

    Ok(proof.to_canonical_json())
}

/// Decode the base64 screenshot from the proof and write the raw PNG bytes to `path`.
fn write_screenshot(
    proof: &basecrawl_core::ScrapeProof,
    path: &std::path::Path,
) -> Result<(), Error> {
    let b64 = proof
        .result
        .formats_produced
        .get("screenshot")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Io("no screenshot was produced to write".to_string()))?;
    let bytes = base64::prelude::BASE64_STANDARD
        .decode(b64)
        .map_err(|e| Error::Io(format!("invalid screenshot base64: {e}")))?;
    std::fs::write(path, bytes).map_err(|e| Error::Io(e.to_string()))
}

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("{}", err.to_json_string());
            std::process::exit(err.exit_code());
        }
    }
}
