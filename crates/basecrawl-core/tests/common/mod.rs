//! Shared test support for the `basecrawl-core` integration tests.
//!
//! HTTP-semantics integration tests target an httpbin-compatible origin. Prefer a hermetic
//! local container via `BASECRAWL_HTTPBIN_BASE` / `HTTPBIN_BASE` (CI sets this). When unset,
//! [`httpbin_base`] probes public mirrors, keeping the TLS 1.3-capable `nghttp2.org/httpbin`
//! deployment first because normal HTTPS scrapes require TLS 1.3 authenticity evidence.
#![allow(dead_code)]

use base64::Engine;
use basecrawl_core::ScrapeProof;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;
use x509_parser::prelude::parse_x509_certificate;

/// Capability-verified TLS 1.3 reference-httpbin mirror (no trailing slash).
///
/// Remote HTTPS candidates used when no hermetic env override is set. Plain HTTP loopback
/// (CI/local `BASECRAWL_HTTPBIN_BASE`) is preferred for hermetic HTTP-semantics tests; public
/// mirrors remain as a developer convenience.
pub const HTTPBIN_TLS13_MIRROR: &str = "https://nghttp2.org/httpbin";

/// Public httpbin-compatible bases in preference order (no trailing slash).
///
/// `nghttp2.org/httpbin` is TLS 1.3-capable and preferred for unattended public runs.
/// `httpbin.org` / `httpbingo.org` are also probed; HTTPS selection still requires `/get`
/// reachability plus TLS 1.3 for the host so TLS-gating scrapes do not fail later.
pub const HTTPBIN_CANDIDATES: &[&str] = &[
    HTTPBIN_TLS13_MIRROR,
    "https://httpbin.org",
    "https://httpbingo.org",
];

/// Environment variables consulted by [`httpbin_base`] (first non-empty wins).
const HTTPBIN_ENV_KEYS: &[&str] = &["BASECRAWL_HTTPBIN_BASE", "HTTPBIN_BASE"];

/// Return a configured or reachable httpbin-compatible base URL, memoized for the lifetime of
/// the test binary.
///
/// Order:
/// 1. `BASECRAWL_HTTPBIN_BASE` / `HTTPBIN_BASE` (trimmed, no trailing slash). Intended for a
///    hermetic local container on loopback plain HTTP; accepted without a TLS probe.
/// 2. Public candidates in [`HTTPBIN_CANDIDATES`], capability-probed.
///
/// Panics only when no env override is set and no candidate mirror is reachable.
pub fn httpbin_base() -> &'static str {
    static BASE: OnceLock<&'static str> = OnceLock::new();
    BASE.get_or_init(|| {
        if let Some(configured) = httpbin_env_override() {
            // Hermetic CI and local overrides must not depend on public egress or TLS 1.3.
            return leak_string(configured);
        }
        let mut tried = Vec::new();
        for base in HTTPBIN_CANDIDATES {
            tried.push(*base);
            if probe_ok(base) {
                return *base;
            }
        }
        panic!("no httpbin-compatible host reachable (tried {tried:?}; set BASECRAWL_HTTPBIN_BASE for a hermetic local instance)");
    })
}

/// Non-empty value of the first configured httpbin base env var, stripped of a trailing slash.
pub fn httpbin_env_override() -> Option<String> {
    for key in HTTPBIN_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim().trim_end_matches('/').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

fn leak_string(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

/// Probe `{base}/get` with curl.
///
/// Plain HTTP (including hermetic loopback containers) only requires HTTP 200.
/// HTTPS also requires an independent TLS 1.3 OpenSSL handshake so public selection does not
/// hand HTTP-semantics tests a TLS 1.2-only host that later fails authenticity capture.
fn probe_ok(base: &str) -> bool {
    let http_ok = Command::new("curl")
        .args([
            "-s",
            "-S",
            "-m",
            "8",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("{base}/get"),
        ])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .is_some_and(|status| status.trim() == "200");
    if !http_ok {
        return false;
    }

    let Ok(url) = url::Url::parse(base) else {
        return false;
    };
    // Loopback or explicit plain HTTP needs no TLS. CI's hermetic container uses `http://127.0.0.1`.
    if url.scheme() == "http" {
        return true;
    }
    if url.scheme() != "https" {
        return false;
    }

    let Some(host) = url.host_str() else {
        return false;
    };
    let port = url.port_or_known_default().unwrap_or(443);
    Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{host}:{port}"),
            "-servername",
            host,
            "-tls1_3",
            "-brief",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Maximum attempts made by an explicitly best-effort open-web smoke check.
pub const REMOTE_SMOKE_MAX_ATTEMPTS: usize = 3;

/// A transient availability failure independently identified from the crawler's structured
/// outcome. Only these failures may exhaust retries and turn a real-origin smoke into a skip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransientOriginFailure {
    Dns,
    Connect,
    Timeout,
    Upstream5xx(u16),
}

impl std::fmt::Display for TransientOriginFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dns => formatter.write_str("DNS resolution failed"),
            Self::Connect => formatter.write_str("origin connection failed"),
            Self::Timeout => formatter.write_str("origin request timed out"),
            Self::Upstream5xx(status) => {
                write!(formatter, "origin returned upstream HTTP {status}")
            }
        }
    }
}

/// A local crawler/proof contract failure. These failures are never silently converted into a
/// remote-origin skip because rerunning cannot make a malformed or incomplete proof trustworthy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FatalSmokeFailure {
    category: &'static str,
    detail: String,
}

impl FatalSmokeFailure {
    fn new(category: &'static str, detail: impl Into<String>) -> Self {
        Self {
            category,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for FatalSmokeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.category, self.detail)
    }
}

/// The classification of one crawler process invocation.
#[derive(Clone, Debug, PartialEq)]
pub enum RemoteSmokeAttempt<T> {
    Success(T),
    Retryable(TransientOriginFailure),
    Fatal(FatalSmokeFailure),
}

/// The final outcome of a bounded real-origin smoke check.
#[derive(Clone, Debug, PartialEq)]
pub enum RemoteSmokeOutcome<T> {
    Success(T),
    Skipped(TransientOriginFailure),
    Fatal(FatalSmokeFailure),
}

/// Retry a typed open-web outcome with a small, bounded exponential backoff.
///
/// Exact parser and navigation assertions belong to [`fixture_url`]. A fatal process, proof,
/// schema, serialization, TLS, or certificate failure exits immediately; only independently
/// classified transient origin failures can eventually become [`RemoteSmokeOutcome::Skipped`].
pub fn retry_open_web<T>(
    mut attempt: impl FnMut() -> RemoteSmokeAttempt<T>,
) -> RemoteSmokeOutcome<T> {
    for index in 0..REMOTE_SMOKE_MAX_ATTEMPTS {
        match attempt() {
            RemoteSmokeAttempt::Success(value) => return RemoteSmokeOutcome::Success(value),
            RemoteSmokeAttempt::Fatal(failure) => return RemoteSmokeOutcome::Fatal(failure),
            RemoteSmokeAttempt::Retryable(transient) => {
                if index + 1 == REMOTE_SMOKE_MAX_ATTEMPTS {
                    return RemoteSmokeOutcome::Skipped(transient);
                }
            }
        }
        if index + 1 < REMOTE_SMOKE_MAX_ATTEMPTS {
            let backoff = Duration::from_millis(250 * (1_u64 << index));
            thread::sleep(backoff);
        }
    }
    unreachable!("the bounded retry loop always returns an outcome")
}

/// Classify the output from a real-origin crawler process.
///
/// A successful process must emit exactly one schema-valid, deserializable [`ScrapeProof`] with
/// complete TLS evidence for `expected_host`. A non-success process is retryable only when its
/// complete structured error envelope independently identifies DNS, connection, or timeout
/// unavailability. HTTP 5xx is classified from a complete success proof's response status.
pub fn classify_open_web_output(
    output: &Output,
    expected_host: &str,
) -> RemoteSmokeAttempt<ScrapeProof> {
    classify_open_web_process(
        output.status.success(),
        &output.stdout,
        &output.stderr,
        expected_host,
    )
}

/// Classify raw process streams. Kept separate from [`classify_open_web_output`] so unit tests can
/// prove that malformed JSON/proofs and fatal crawler errors never enter the skip path.
pub fn classify_open_web_process(
    succeeded: bool,
    stdout: &[u8],
    stderr: &[u8],
    expected_host: &str,
) -> RemoteSmokeAttempt<ScrapeProof> {
    if succeeded {
        if !stderr.is_empty() {
            return RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
                "unexpected_success_stderr",
                String::from_utf8_lossy(stderr),
            ));
        }
        return classify_successful_open_web_proof(stdout, expected_host);
    }

    if !stdout.is_empty() {
        return RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
            "unexpected_failure_stdout",
            String::from_utf8_lossy(stdout),
        ));
    }

    let envelope = match parse_error_envelope(stderr) {
        Ok(envelope) => envelope,
        Err(error) => return RemoteSmokeAttempt::Fatal(error),
    };
    let kind = envelope["error"]["kind"]
        .as_str()
        .expect("parse_error_envelope validates error.kind");
    let message = envelope["error"]["message"]
        .as_str()
        .expect("parse_error_envelope validates error.message");

    match kind {
        "timeout" => RemoteSmokeAttempt::Retryable(TransientOriginFailure::Timeout),
        "transport_error" => classify_transport_failure(message).map_or_else(
            || {
                RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
                    "unclassified_transport_error",
                    message,
                ))
            },
            RemoteSmokeAttempt::Retryable,
        ),
        _ => RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
            "crawler_error",
            format!("{kind}: {message}"),
        )),
    }
}

fn classify_successful_open_web_proof(
    stdout: &[u8],
    expected_host: &str,
) -> RemoteSmokeAttempt<ScrapeProof> {
    let proof_value = match serde_json::from_slice::<Value>(stdout) {
        Ok(value) => value,
        Err(error) => {
            return RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
                "malformed_proof_json",
                error.to_string(),
            ));
        }
    };
    if let Err(error) = validate_scrapeproof_schema(&proof_value) {
        return RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new("proof_schema", error));
    }
    let proof = match serde_json::from_value::<ScrapeProof>(proof_value) {
        Ok(proof) => proof,
        Err(error) => {
            return RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
                "proof_deserialization",
                error.to_string(),
            ));
        }
    };

    match proof.response.status_code {
        Some(status @ 500..=599) => {
            RemoteSmokeAttempt::Retryable(TransientOriginFailure::Upstream5xx(status))
        }
        Some(200..=299) => match validate_open_web_tls(&proof, expected_host) {
            Ok(()) => RemoteSmokeAttempt::Success(proof),
            Err(error) => RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new("tls_evidence", error)),
        },
        Some(status) => RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
            "unexpected_http_status",
            status.to_string(),
        )),
        None => RemoteSmokeAttempt::Fatal(FatalSmokeFailure::new(
            "missing_response_status",
            "successful crawler output omitted response.status_code",
        )),
    }
}

fn parse_error_envelope(stderr: &[u8]) -> Result<Value, FatalSmokeFailure> {
    let envelope: Value = serde_json::from_slice(stderr).map_err(|error| {
        FatalSmokeFailure::new(
            "malformed_error_envelope",
            format!("{error}: {}", String::from_utf8_lossy(stderr)),
        )
    })?;
    let top = envelope.as_object().ok_or_else(|| {
        FatalSmokeFailure::new(
            "malformed_error_envelope",
            "error output must be a JSON object",
        )
    })?;
    if top.len() != 1 || !top.contains_key("error") {
        return Err(FatalSmokeFailure::new(
            "malformed_error_envelope",
            "error output must contain exactly one top-level error object",
        ));
    }
    let error = top["error"].as_object().ok_or_else(|| {
        FatalSmokeFailure::new("malformed_error_envelope", "error must be a JSON object")
    })?;
    if error.get("kind").and_then(Value::as_str).is_none()
        || error.get("message").and_then(Value::as_str).is_none()
    {
        return Err(FatalSmokeFailure::new(
            "malformed_error_envelope",
            "error.kind and error.message must be strings",
        ));
    }
    Ok(envelope)
}

fn classify_transport_failure(message: &str) -> Option<TransientOriginFailure> {
    let message = message.to_ascii_lowercase();
    if [
        "dns error",
        "failed to lookup",
        "name or service not known",
        "no such host",
        "temporary failure in name resolution",
    ]
    .iter()
    .any(|marker| message.contains(marker))
    {
        Some(TransientOriginFailure::Dns)
    } else if [
        "connection refused",
        "connection reset",
        "connection aborted",
        "connect error",
        "failed to connect",
    ]
    .iter()
    .any(|marker| message.contains(marker))
    {
        Some(TransientOriginFailure::Connect)
    } else {
        None
    }
}

fn validate_scrapeproof_schema(proof: &Value) -> Result<(), String> {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../basecrawl-proof/schema/scrapeproof.schema.json"
    ))
    .map_err(|error| format!("published schema is invalid JSON: {error}"))?;
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .map_err(|error| format!("published schema does not compile: {error}"))?;
    validator.validate(proof).map_err(|errors| {
        errors
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    })
}

fn validate_open_web_tls(proof: &ScrapeProof, expected_host: &str) -> Result<(), String> {
    let tls = &proof.tls;
    if tls.certificate_validation != basecrawl_proof::CertificateValidation::Validated {
        return Err(format!(
            "certificate_validation must be validated, got {:?}",
            tls.certificate_validation
        ));
    }
    if tls.negotiated_version.as_deref() != Some("1.3") {
        return Err(format!(
            "negotiated_version must be TLS 1.3, got {:?}",
            tls.negotiated_version
        ));
    }
    if tls.sni.as_deref() != Some(expected_host) {
        return Err(format!("SNI must be {expected_host}, got {:?}", tls.sni));
    }
    if tls.server_cert_chain_der.is_empty() {
        return Err("server_cert_chain_der must contain at least one certificate".to_string());
    }
    for (index, entry) in tls.server_cert_chain_der.iter().enumerate() {
        let der = base64::prelude::BASE64_STANDARD
            .decode(entry)
            .map_err(|error| format!("certificate #{index} is not valid base64 DER: {error}"))?;
        if der.is_empty() {
            return Err(format!("certificate #{index} is empty"));
        }
        let (remainder, _) = parse_x509_certificate(&der)
            .map_err(|error| format!("certificate #{index} is not valid DER: {error}"))?;
        if !remainder.is_empty() {
            return Err(format!("certificate #{index} has trailing non-DER bytes"));
        }
    }
    let server_ephemeral_pubkey = tls
        .server_ephemeral_pubkey
        .as_deref()
        .ok_or_else(|| "server_ephemeral_pubkey is missing".to_string())?;
    if base64::prelude::BASE64_STANDARD
        .decode(server_ephemeral_pubkey)
        .map_err(|error| format!("server_ephemeral_pubkey is not valid base64: {error}"))?
        .is_empty()
    {
        return Err("server_ephemeral_pubkey is empty".to_string());
    }
    let transcript = tls
        .handshake_transcript_hash
        .as_deref()
        .ok_or_else(|| "handshake_transcript_hash is missing".to_string())?;
    if !matches!(transcript.len(), 64 | 96)
        || !transcript.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
    {
        return Err(format!(
            "handshake_transcript_hash must be lowercase 64/96-hex, got {transcript}"
        ));
    }
    Ok(())
}

/// Return the deterministic test-origin base URL, backed by one loopback server per test binary.
pub fn fixture_base() -> &'static str {
    static BASE: OnceLock<String> = OnceLock::new();
    BASE.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture server");
        let address = listener
            .local_addr()
            .expect("read loopback fixture server address");
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_fixture_connection(stream));
            }
        });
        format!("http://{address}")
    })
}

/// Build an absolute URL for one deterministic fixture path.
pub fn fixture_url(path: &str) -> String {
    assert!(path.starts_with('/'), "fixture paths must start with '/'");
    format!("{}{}", fixture_base(), path)
}

fn fixture_page(body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Fixture Quotes</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
</head><body>{body}</body></html>"
    )
}

fn quotes_page() -> String {
    fixture_page(
        "<main><section class=\"quote\">Fixture quote for resilient parser coverage</section>\
<a href=\"/tags/fixtures/resilient/\">fixture tag</a></main>",
    )
}

fn book_product_page() -> String {
    fixture_page(
        "<header>Books to Scrape</header><article>\
<h1>A Fixture Light</h1><p>Fixture product description</p>\
<h2>Fixture Product Description</h2>\
<table><tr><th>UPC</th><td>fixture-upc</td></tr></table>\
<img alt=\"A Fixture Light\" src=\"/media/fixture-light.jpg\"></article>",
    )
}

fn books_page() -> String {
    fixture_page(
        "<main><a href=\"/books/catalogue/fixture-light/index.html\">Fixture light</a>\
<a href=\"/books/catalogue/fixture-second/index.html\">Fixture second</a>\
<a href=\"/books/category/fixtures/index.html\">Fixture category</a>\
<a rel=\"next\" href=\"/books/page-2.html\">next</a></main>",
    )
}

fn books_page_two() -> String {
    fixture_page(
        "<main><h1>Fixture page 2</h1>\
<a href=\"/books/catalogue/fixture-third/index.html\">Fixture third</a></main>",
    )
}

fn scroll_page() -> String {
    fixture_page(
        "<main style=\"min-height: 1800px\"><div class=\"quote\">“fixture quote 1”</div>\
<script>\
window.addEventListener('scroll', function () {\
  for (let i = 2; i <= 12; i += 1) {\
    const quote = document.createElement('div');\
    quote.className = 'quote'; quote.textContent = '“fixture quote ' + i + '”';\
    document.querySelector('main').appendChild(quote);\
  }\
}, { once: true });\
</script></main>",
    )
}

fn js_page() -> String {
    fixture_page(
        "<main id=\"quotes\"></main><script>\
var data = ['Fixture JS quote render marker'];\
data.forEach(function (text) {\
  var quote = document.createElement('div');\
  quote.className = 'quote'; quote.textContent = text;\
  document.getElementById('quotes').appendChild(quote);\
});\
</script>",
    )
}

fn tall_page() -> String {
    fixture_page("<main><div style=\"height: 1800px\">Fixture tall screenshot content</div></main>")
}

/// Minimal example.com-shaped page for metadata-only assertions.
///
/// Intentionally omits `<meta charset>` so VAL-CRAWL-053 can assert charset stays absent when the
/// response is bare `text/html` (no Content-Type charset parameter either).
fn example_like_page() -> String {
    "<!doctype html><html lang=\"en\"><head>\
<title>Example Domain</title>\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
</head><body><div><h1>Example Domain</h1>\
<p>This domain is for use in documentation examples without needing permission.</p>\
<p><a href=\"https://www.iana.org/domains/example\">More information...</a></p>\
</div></body></html>"
        .to_string()
}

fn fixture_response(path: &str) -> (&'static str, &'static str, String) {
    match path {
        "/quotes/" => ("200 OK", "text/html; charset=utf-8", quotes_page()),
        "/books/" => ("200 OK", "text/html; charset=utf-8", books_page()),
        "/books/page-2.html" => ("200 OK", "text/html; charset=utf-8", books_page_two()),
        "/books/catalogue/fixture-light/index.html" => {
            ("200 OK", "text/html; charset=utf-8", book_product_page())
        }
        "/scroll/" => ("200 OK", "text/html; charset=utf-8", scroll_page()),
        "/js/" => ("200 OK", "text/html; charset=utf-8", js_page()),
        "/tall/" => ("200 OK", "text/html; charset=utf-8", tall_page()),
        // VAL-CRAWL-053/054: example.com-shaped metadata (bare text/html, viewport, no charset).
        "/example/" => ("200 OK", "text/html", example_like_page()),
        // VAL-CRAWL-034: empty success response with no body (No Content).
        "/status/204" => ("204 No Content", "text/plain; charset=utf-8", String::new()),
        "/missing" => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "fixture missing".to_string(),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "fixture not found".to_string(),
        ),
    }
}

fn handle_fixture_connection(stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }

    let mut line = String::new();
    while reader
        .read_line(&mut line)
        .map(|count| count > 0)
        .unwrap_or(false)
    {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let (status, content_type, body) = fixture_response(path);
    let mut stream = reader.into_inner();
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}
