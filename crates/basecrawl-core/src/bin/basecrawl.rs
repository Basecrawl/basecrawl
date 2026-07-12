//! `basecrawl` CLI: scrape a URL and emit exactly one canonical ScrapeProof JSON object.
//!
//! On success the ScrapeProof is written to stdout (nothing else). On failure a structured
//! `{"error": {...}}` object is written to stderr and the process exits non-zero, so a failed
//! run never emits a partial ScrapeProof on stdout.

use base64::Engine;
use basecrawl_core::error::Error;
use basecrawl_core::fetch::{parse_header, DEFAULT_MAX_BODY_BYTES, DEFAULT_TIMEOUT_SECS};
use basecrawl_core::{
    format, scrape, screenshot, Action, Format, RobotsPolicy, ScrapeOptions, DEFAULT_MAX_PAGES,
};
use clap::Parser;
use serde_json::json;
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

    /// JSON Schema describing the requested structured extraction. The current deterministic
    /// image accepts this request syntax but explicitly reports JSON extraction as unavailable.
    #[arg(
        long = "json-schema",
        visible_alias = "schema",
        value_name = "JSON_SCHEMA"
    )]
    json_schema: Option<String>,

    /// Natural-language instruction for the requested structured extraction. The current
    /// deterministic image accepts this request syntax but explicitly reports JSON extraction as
    /// unavailable.
    #[arg(long = "json-prompt", visible_alias = "prompt", value_name = "PROMPT")]
    json_prompt: Option<String>,

    /// Validator-issued task identifier, echoed verbatim into the ScrapeProof.
    #[arg(long, value_name = "TASK_ID")]
    task_id: Option<String>,

    /// Validator-issued anti-replay nonce, echoed verbatim into the ScrapeProof.
    #[arg(long, value_name = "NONCE")]
    nonce: Option<String>,

    /// Custom request header 'Name: Value', repeatable, sent to the origin.
    #[arg(long = "header", value_name = "HEADER")]
    headers: Vec<String>,

    /// Session cookie `NAME=VALUE`, repeatable. Cookies are sent in the clear at M1.
    #[arg(long = "cookie", value_name = "NAME=VALUE")]
    cookies: Vec<String>,

    /// Value for the HTTP Authorization header, e.g. `Bearer TOKEN`. Sent in the clear at M1.
    #[arg(long = "auth-header", value_name = "VALUE")]
    auth_header: Option<String>,

    /// HTTP Basic credentials `USERNAME:PASSWORD`. Sent in the clear at M1.
    #[arg(long = "basic-auth", value_name = "USERNAME:PASSWORD")]
    basic_auth: Option<String>,

    /// Whole-request timeout in seconds; a slower endpoint aborts near this bound.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS, value_name = "SECONDS")]
    timeout: u64,

    /// Maximum decoded response-body bytes retained in memory [default: 10485760]. Bodies beyond
    /// this cap are truncated and reported as response.body_truncated=true in the ScrapeProof.
    #[arg(long, default_value_t = DEFAULT_MAX_BODY_BYTES, value_name = "BYTES")]
    max_body_bytes: usize,

    /// Minimum millisecond delay between requests to the same scheme/host/port origin, including
    /// redirects, robots, sitemap, pagination, and browser subresources.
    #[arg(long, default_value_t = 0, value_name = "MILLISECONDS")]
    crawl_delay_ms: u64,

    /// Maximum browser requests accepted across HTML, screenshots, and pagination [default: 128].
    /// Exhaustion fails with a structured resource_budget_exceeded error and no partial proof.
    #[arg(long, default_value_t = 128, value_name = "N")]
    max_render_subresources: usize,

    /// Maximum cumulative observed browser-response bytes across HTML, screenshots, and pagination
    /// [default: 20971520]. Exhaustion fails with a structured resource_budget_exceeded error.
    #[arg(long, default_value_t = 20 * 1024 * 1024, value_name = "BYTES")]
    max_render_bytes: u64,

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

    /// robots.txt policy: enforce blocks denied paths, observe records without blocking, and ignore
    /// skips policy consultation entirely.
    #[arg(long, default_value_t = RobotsPolicy::Enforce, value_name = "POLICY")]
    robots: RobotsPolicy,

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

    /// Emit a redacted completion summary to stderr. The summary contains only hashes and response
    /// metadata, never request headers, cookies, or request/response bodies.
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Request a signed Intel TDX quote and enclave signature from /var/run/dstack.sock and
    /// populate M2 attestation fields. Outside a CVM this fails closed with no fabricated proof.
    #[arg(long, default_value_t = false)]
    attest: bool,

    /// Explicitly request the M2 Ed25519 proof signature. Attestation also enables it, and the
    /// public key is committed into report_data.
    #[arg(long, default_value_t = false)]
    sign_proof: bool,

    /// Optional per-miner/per-task fingerprint seed. When set, non-security fingerprint dimensions
    /// (JA3/JA4 cipher order, header order, UA, viewport, timezone, locale, canvas/WebGL) are a
    /// pure function of this seed. When omitted, the seed is derived from task_id/nonce. The
    /// normalized seed always appears in egress.fingerprint_seed and report_data.
    #[arg(long = "fingerprint-seed", value_name = "SEED")]
    fingerprint_seed: Option<String>,
}

fn run(cli: Cli) -> Result<String, Error> {
    if cli.output != "json" {
        return Err(Error::UnsupportedOutput(cli.output));
    }

    let raw_url = cli.url.ok_or(Error::MissingUrl)?;
    let _json_extraction_request = (cli.json_schema, cli.json_prompt);

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
    let mut headers = cli
        .headers
        .iter()
        .map(|spec| parse_header(spec))
        .collect::<Result<Vec<_>, _>>()?;
    if !cli.cookies.is_empty() {
        if cli
            .cookies
            .iter()
            .any(|cookie| !cookie.contains('=') || cookie.starts_with('='))
        {
            return Err(Error::InvalidHeader("Cookie".to_string()));
        }
        set_header(&mut headers, "Cookie", cli.cookies.join("; "));
    }
    if let Some(auth_header) = cli.auth_header {
        if auth_header.trim().is_empty() {
            return Err(Error::InvalidHeader("Authorization".to_string()));
        }
        set_header(&mut headers, "Authorization", auth_header);
    }
    if let Some(basic_auth) = cli.basic_auth {
        let (username, password) = basic_auth
            .split_once(':')
            .ok_or_else(|| Error::InvalidHeader("basic-auth".to_string()))?;
        if username.is_empty() {
            return Err(Error::InvalidHeader("basic-auth".to_string()));
        }
        let value = format!(
            "Basic {}",
            base64::prelude::BASE64_STANDARD.encode(format!("{username}:{password}"))
        );
        set_header(&mut headers, "Authorization", value);
    }

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
        crawl_delay_ms: cli.crawl_delay_ms,
        max_render_subresources: cli.max_render_subresources,
        max_render_bytes: cli.max_render_bytes,
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
        robots_policy: cli.robots,
        attest: cli.attest || cli.sign_proof,
        sign_proof: cli.sign_proof,
        fingerprint_seed: cli.fingerprint_seed,
    };

    let proof = scrape(&raw_url, &options)?;

    if let Some(path) = &cli.screenshot_out {
        write_screenshot(&proof, path)?;
    }

    if cli.verbose {
        log_verbose_summary(&proof);
    }

    Ok(proof.to_canonical_json())
}

/// Add a caller convenience credential header without allowing duplicate sensitive header names.
///
/// A later explicit credential flag wins over a same-named generic `--header`, matching normal CLI
/// override behavior while keeping each request's header surface unambiguous.
fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value));
}

/// Write a completion event without exposing request or response plaintext.
///
/// Labels are reduced to host-safe digests / hashes only (VAL-CONF-018/019/020):
/// no URL path/query, no header/cookie/token/body values, no result content.
fn log_verbose_summary(proof: &basecrawl_core::ScrapeProof) {
    use basecrawl_seal::HostSafeLabels;

    let labels = HostSafeLabels::scrape_completed(
        proof.task_id.as_deref(),
        proof.response.status_code,
        proof.request.headers_hash.as_deref(),
        proof.request.body_hash.as_deref(),
    );
    let summary = json!({
        "event": labels.event,
        "task_id": labels.task_id,
        "request": {
            "method": proof.request.method,
            "headers_hash": proof.request.headers_hash,
            "body_hash": proof.request.body_hash,
        },
        "response": {
            "status_code": proof.response.status_code,
            "headers_hash": proof.response.headers_hash,
            "body_hash": proof.response.body_hash,
            "content_length": proof.response.content_length,
        },
    });
    // Defensive: never let residual marker text ship if a future field creep reintroduces it.
    let rendered = summary.to_string();
    eprintln!("{rendered}");
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
    // Install before any scrape work so panic payloads never dump path/query / secrets
    // onto host-visible stderr / crash logs (VAL-CONF-031).
    basecrawl_seal::install_host_safe_panic_hook();

    let cli = Cli::parse();
    let task_id = cli.task_id.clone();
    match run(cli) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            // Host-visible stderr is a single redacted structured envelope (VAL-CONF-018..031).
            // Exactly one JSON object keeps consumers / tests that `from_slice` stderr stable.
            eprintln!("{}", err.to_host_safe_json_string(task_id.as_deref()));
            std::process::exit(err.exit_code());
        }
    }
}
