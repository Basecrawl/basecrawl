//! HTTP(S) fetch feeding the ScrapeProof `response` block.
//! HTTP(S) fetch feeding the ScrapeProof `response` and `tls` blocks.
//!
//! This path owns core fetch semantics: accurate status capture (2xx/4xx/5xx are recorded, not
//! masked), transparent `gzip`/`deflate`/`brotli` content decoding, an enforced request timeout,
//! custom request headers, a browser-plausible User-Agent, and structured transport failures.
//! HTTPS is terminated directly by rustls so the generated ScrapeProof binds the server's TLS
//! handshake metadata from the same connection that carried the response.
use crate::error::Error;
use base64::Engine;
use basecrawl_proof::{RedirectHop, Tls};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConnection, Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use url::Url;
use x509_parser::prelude::parse_x509_certificate;
/// A browser-plausible User-Agent so origins are not served a bare library fingerprint.
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

/// Default request timeout (seconds) when the caller does not specify one.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Maximum number of HTTP redirects followed before aborting with [`Error::TooManyRedirects`].
///
/// This is the documented hop cap that bounds redirect loops: a chain longer than this (including a
/// cyclic redirect) is refused rather than followed indefinitely. It is comfortably above the depth
/// of any legitimate redirect chain while still terminating pathological loops quickly.
pub const MAX_REDIRECTS: usize = 20;

/// Default upper bound for decoded response bodies, 10 MiB.
///
/// The fetcher stores at most this many decoded body bytes and marks the resulting proof as
/// truncated when additional data exists. This bounds memory use for unexpectedly large origin
/// responses while allowing callers to opt into a smaller or larger per-request cap.
pub const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Fixed allowance for an HTTP response status line and headers while applying the body cap to the
/// in-process HTTPS parser. Headers are also bounded so a malicious origin cannot move the memory
/// pressure from the body into an unbounded header block.
const MAX_HTTP_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

type Headers = Vec<(String, Vec<u8>)>;

/// Configuration for a single fetch.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Whole-request timeout. A slow endpoint aborts near this bound rather than blocking.
    pub timeout: Duration,
    /// Validated effective request headers, including the controlled default User-Agent.
    ///
    /// The exact vector order is the defined wire order for caller-controlled field lines.
    pub headers: Vec<(String, String)>,
    /// Origin that supplied [`Self::headers`]. Caller-controlled fields are emitted only when a
    /// request target has the same normalized scheme, host, and effective port. `None` means the
    /// URL passed to [`fetch`] is the initiating origin, preserving safe behavior for direct
    /// `FetchConfig` users while still scoping every redirect hop.
    pub credential_origin: Option<Url>,
    /// User-Agent presented to the origin.
    pub user_agent: String,
    /// Permit invalid TLS certificates only when the caller explicitly opts in. The secure
    /// default always uses the Mozilla root store and hostname validation.
    pub insecure: bool,
    /// Maximum decoded response-body bytes retained in memory.
    pub max_body_bytes: usize,
    /// Minimum interval between physical requests to the same scheme/host/port origin. The shared
    /// limiter applies across redirects, robots, sitemaps, and pagination fetches that reuse this
    /// config.
    pub crawl_delay: Duration,
    pub(crate) origin_limiter: Arc<OriginLimiter>,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            headers: vec![("user-agent".to_string(), DEFAULT_USER_AGENT.to_string())],
            credential_origin: None,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            insecure: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            crawl_delay: Duration::ZERO,
            origin_limiter: Arc::new(OriginLimiter::default()),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct OriginLimiter {
    last_request_at: Mutex<HashMap<Origin, Instant>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl OriginLimiter {
    fn wait_for_turn(&self, url: &Url, delay: Duration, deadline: Instant) -> Result<(), Error> {
        if delay.is_zero() {
            return Ok(());
        }
        let Some(host) = url.host_str() else {
            return Ok(());
        };
        let Some(port) = url.port_or_known_default() else {
            return Ok(());
        };
        let origin = Origin {
            scheme: url.scheme().to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
        };
        let mut requests = self
            .last_request_at
            .lock()
            .expect("origin limiter mutex must not be poisoned");
        if let Some(previous) = requests.get(&origin) {
            let elapsed = previous.elapsed();
            if elapsed < delay {
                let wait = delay - elapsed;
                if wait >= remaining(deadline)? {
                    return Err(deadline_elapsed());
                }
                thread::sleep(wait);
            }
        }
        requests.insert(origin, Instant::now());
        Ok(())
    }
}

impl FetchConfig {
    /// Apply this fetcher's shared per-origin limiter before a browser navigation reuses the same
    /// origin. Keeping this method on the config lets the core maintain one schedule across its
    /// direct Rust fetches and the subsequent Chromium render.
    pub(crate) fn wait_for_origin_until(&self, url: &Url, deadline: Instant) -> Result<(), Error> {
        self.origin_limiter
            .wait_for_turn(url, self.crawl_delay, deadline)
    }

    /// Return caller-controlled headers only for the initiating origin.
    ///
    /// The controlled User-Agent is emitted separately by the HTTP serializer, so cross-origin
    /// requests retain a browser-plausible identifier without transmitting any caller input.
    fn caller_headers_for<'a>(
        &'a self,
        target: &Url,
        credential_origin: &Url,
    ) -> &'a [(String, String)] {
        if same_origin(target, credential_origin) {
            &self.headers
        } else {
            &[]
        }
    }
}

/// Compare normalized URL origins using scheme, case-insensitive host, and effective port.
///
/// This intentionally treats every scheme transition, host transition, port transition, and HTTPS
/// downgrade as cross-origin. Paths, queries, and fragments do not determine whether a caller
/// credential may be transmitted.
pub(crate) fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme().eq_ignore_ascii_case(right.scheme())
        && left
            .host_str()
            .zip(right.host_str())
            .is_some_and(|(left_host, right_host)| left_host.eq_ignore_ascii_case(right_host))
        && left.port_or_known_default() == right.port_or_known_default()
}

/// Outcome of a single HTTP fetch. `body` is the *decoded* response body (any transfer/content
/// encoding already removed), so `content_length == body.len()`.
pub struct Fetched {
    pub status_code: u16,
    pub headers_hash: String,
    pub body_hash: String,
    pub content_length: u64,
    pub body: Vec<u8>,
    /// The terminal response `Content-Type` header value, if any. The charset parameter it carries
    /// is the authoritative source for the metadata charset field.
    pub content_type: Option<String>,
    /// Whether the body exceeded the configured maximum and was retained only up to that cap.
    pub body_truncated: bool,
    /// Terminal URL the response was served from after following any redirects.
    pub final_url: String,
    /// Redirect hops followed to reach the terminal response, in order.
    pub redirects: Vec<RedirectHop>,
    /// In-process TLS 1.3 evidence for the final HTTPS request (or the last HTTPS redirect hop).
    pub tls: Tls,
    /// Source address selected for the final outbound request.
    pub egress_ip: IpAddr,
    /// UTC wall-clock time recorded as soon as the final response is fetched, before rendering or
    /// other result processing can delay proof assembly.
    pub fetched_at: OffsetDateTime,
}

/// Parse and validate a single `Name: Value` header specification.
///
/// The name is the text before the first colon; the value is everything after it (trimmed of one
/// leading space, HTTP-style). An empty name or a missing colon is an [`Error::InvalidHeader`].
pub fn parse_header(spec: &str) -> Result<(String, String), Error> {
    let (name, value) = spec
        .split_once(':')
        .ok_or_else(|| Error::InvalidHeader("<redacted>".to_string()))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::InvalidHeader("<redacted>".to_string()));
    }
    let value = value.strip_prefix(' ').unwrap_or(value).trim_end();
    validate_header_pair(name, value)?;
    Ok((name.to_string(), value.to_string()))
}

/// Build the one validated header representation used for hashing and every transport.
///
/// Header names are case-insensitive in HTTP, so accepting two spellings of one name would make
/// duplicate-field ordering transport-sensitive. Basecrawl therefore rejects those ambiguous
/// inputs before robots, DNS, or any socket work. Effective names are lowercased before emission,
/// so case-only input changes do not produce different field bytes. The controlled User-Agent is
/// always first in the effective list and cannot be caller-overridden, which prevents HTTP and
/// HTTPS from emitting different User-Agent multiplicities.
pub fn effective_headers(
    headers: &[(String, String)],
    user_agent: &str,
) -> Result<Vec<(String, String)>, Error> {
    validate_header_pair("User-Agent", user_agent)?;

    let mut seen = HashSet::new();
    let mut effective = Vec::with_capacity(headers.len() + 1);
    effective.push(("user-agent".to_string(), user_agent.to_string()));
    seen.insert("user-agent".to_string());

    for (name, value) in headers {
        validate_header_pair(name, value)?;
        let normalized = name.to_ascii_lowercase();
        if is_transport_managed_header(&normalized) {
            return Err(Error::InvalidHeader(name.to_string()));
        }
        if !seen.insert(normalized.clone()) {
            return Err(Error::InvalidHeader(name.to_string()));
        }
        effective.push((normalized, value.clone()));
    }
    Ok(effective)
}

/// Direct HTTP/HTTPS write these field lines themselves, and Chromium owns the matching protocol
/// fields. Allowing callers to add another occurrence would make their wire semantics diverge.
fn is_transport_managed_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "user-agent"
            | "connection"
            | "accept-encoding"
            | "content-length"
            | "transfer-encoding"
            | "trailer"
            | "te"
            | "upgrade"
    )
}

/// Reject field names that cannot be emitted as an HTTP/1.1 field line and values that would
/// smuggle a second line. This validation is shared by the CLI and every FFI caller.
fn validate_header_pair(name: &str, value: &str) -> Result<(), Error> {
    let valid_name = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    let valid_value = value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f));
    if valid_name && valid_value {
        Ok(())
    } else {
        Err(Error::InvalidHeader(name.to_string()))
    }
}

/// Perform a blocking HTTP GET against a validated URL, following redirects to the final resource.
///
/// Redirects are followed in-process (reqwest's own redirect policy is disabled) so that each hop
/// is captured as a [`RedirectHop`] and the chain can be bounded. A relative or cross-scheme
/// `Location` is resolved against the URL that returned it, and the chain is capped at
/// [`MAX_REDIRECTS`]: a longer chain (including a cyclic loop) aborts with
/// [`Error::TooManyRedirects`] rather than following forever. The per-hop request timeout is
/// enforced on every hop, so a redirect chain cannot hang past it.
///
/// Transport failures (DNS resolution, connect, timeout, body-read) are returned as structured
/// [`Error`]s and never as a fabricated HTTP status. Any HTTP status the terminal resource returns
/// (including 4xx/5xx) is captured faithfully.
pub fn fetch(url: &Url, config: &FetchConfig) -> Result<Fetched, Error> {
    fetch_until(url, config, Instant::now() + config.timeout)
}

/// Perform a fetch while consuming the caller's absolute scrape deadline.
///
/// Every redirect hop and its DNS, connection, TLS, request-write, and body-read work receives
/// only the time still available from this deadline.
pub fn fetch_until(url: &Url, config: &FetchConfig, deadline: Instant) -> Result<Fetched, Error> {
    fetch_with_document_policy_until(url, config, deadline, |_| Ok(()))
}

/// Perform a document fetch while consulting `check_document` before every transmitted request.
///
/// The callback runs for the initial URL and each resolved redirect target, before origin pacing,
/// DNS resolution, or any connection attempt. Internal policy resources such as `robots.txt` and
/// sitemaps use [`fetch_until`] instead, so robots consultation does not recurse into itself.
pub fn fetch_document_until<F>(
    url: &Url,
    config: &FetchConfig,
    deadline: Instant,
    check_document: F,
) -> Result<Fetched, Error>
where
    F: FnMut(&Url) -> Result<(), Error>,
{
    fetch_with_document_policy_until(url, config, deadline, check_document)
}

fn fetch_with_document_policy_until<F>(
    url: &Url,
    config: &FetchConfig,
    deadline: Instant,
    mut check_document: F,
) -> Result<Fetched, Error>
where
    F: FnMut(&Url) -> Result<(), Error>,
{
    let mut current = url.clone();
    let credential_origin = config.credential_origin.as_ref().unwrap_or(url);
    let mut redirects: Vec<RedirectHop> = Vec::new();
    let mut tls = Tls::default();
    let mut egress_ip = None;

    loop {
        // This must precede every transport operation. In particular, a redirect target cannot
        // reach DNS or the origin before its document policy disposition is known.
        check_document(&current)?;
        // Record the request immediately before opening the connection. This is deliberately in
        // the redirect loop, rather than around `fetch`, so every physical same-origin request is
        // spaced, including redirect hops and callers such as robots/sitemap/pagination.
        config.wait_for_origin_until(&current, deadline)?;
        let response = match current.scheme() {
            "http" => fetch_http(&current, config, credential_origin, deadline)?,
            "https" => fetch_https(&current, config, credential_origin, deadline)?,
            scheme => return Err(Error::UnsupportedScheme(scheme.to_string())),
        };

        if let Some(captured) = response.tls {
            tls = captured;
        }
        if let Some(captured) = response.egress_ip {
            egress_ip = Some(captured);
        }

        if (300..400).contains(&response.status_code) {
            if let Some(location) = response.location {
                if redirects.len() >= MAX_REDIRECTS {
                    return Err(Error::TooManyRedirects {
                        max: MAX_REDIRECTS,
                        url: url.to_string(),
                    });
                }
                let target = current.join(&location).map_err(|_| {
                    Error::Redirect(format!(
                        "could not resolve redirect Location '{location}' against {current}"
                    ))
                })?;
                redirects.push(RedirectHop {
                    status_code: response.status_code,
                    url: current.to_string(),
                    location: target.to_string(),
                });
                current = target;
                continue;
            }
        }

        return Ok(Fetched {
            status_code: response.status_code,
            headers_hash: response.headers_hash,
            body_hash: sha256_hex(&response.body),
            content_length: response.body.len() as u64,
            body: response.body,
            content_type: response.content_type,
            body_truncated: response.body_truncated,
            final_url: current.to_string(),
            redirects,
            tls,
            egress_ip: egress_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            fetched_at: OffsetDateTime::now_utc(),
        });
    }
}

/// The normalized response from a single non-following HTTP(S) request.
struct SingleResponse {
    status_code: u16,
    headers_hash: String,
    content_type: Option<String>,
    location: Option<String>,
    body: Vec<u8>,
    body_truncated: bool,
    tls: Option<Tls>,
    egress_ip: Option<IpAddr>,
}

/// Perform plaintext HTTP with the same raw HTTP/1.1 request serializer used by HTTPS.
///
/// `reqwest::HeaderMap` coalesces duplicate names and does not promise field-line ordering. The
/// effective representation was validated before this point, so serializing it directly keeps the
/// request hash, HTTP bytes, and HTTPS bytes aligned.
fn fetch_http(
    url: &Url,
    config: &FetchConfig,
    credential_origin: &Url,
    deadline: Instant,
) -> Result<SingleResponse, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::InvalidUrl(url.to_string()))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let address = resolve_address(host, port, deadline)?;
    let stream = TcpStream::connect_timeout(&address, remaining(deadline)?).map_err(classify_io)?;
    let egress_ip = stream.local_addr().map_err(classify_io)?.ip();
    let mut stream = DeadlineStream::new(stream, deadline);

    let request = build_http_request(url, host, port, config, credential_origin)?;
    stream.write_all(&request).map_err(classify_io)?;
    stream.flush().map_err(classify_io)?;
    let raw_limit = config
        .max_body_bytes
        .saturating_add(MAX_HTTP_RESPONSE_HEADER_BYTES);
    let (raw_response, raw_truncated) = read_capped(&mut stream, raw_limit, deadline)?;
    let (status_code, headers, body) = parse_http_response(&raw_response)?;
    let content_type = header_value(&headers, "content-type");
    let location = header_value(&headers, "location");
    let (body, decoded_truncated) =
        decode_http_body(&headers, body, config.max_body_bytes, deadline)?;

    Ok(SingleResponse {
        status_code,
        headers_hash: hash_header_lines(&headers),
        content_type,
        location,
        body,
        body_truncated: raw_truncated || decoded_truncated,
        tls: None,
        egress_ip: Some(egress_ip),
    })
}

/// Perform an HTTPS request over a fresh rustls connection. No subprocess is involved: the
/// connection that carries HTTP also exposes the authenticated chain and wire handshake material
/// stored in [`Tls`]. TLS 1.3 is preferred and capture-complete.
fn fetch_https(
    url: &Url,
    config: &FetchConfig,
    credential_origin: &Url,
    deadline: Instant,
) -> Result<SingleResponse, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::InvalidUrl(url.to_string()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| Error::InvalidUrl(format!("invalid HTTPS host '{host}'")))?;
    let address = resolve_address(host, port, deadline)?;
    let tcp = TcpStream::connect_timeout(&address, remaining(deadline)?).map_err(classify_io)?;
    let egress_ip = tcp.local_addr().map_err(classify_io)?.ip();

    let capture = Arc::new(TlsCaptureState::default());
    let client_config = tls_config(capture.clone(), config.insecure)?;
    let mut connection =
        ClientConnection::new(Arc::new(client_config), server_name).map_err(|error| {
            Error::TlsCapture(format!("could not create rustls connection: {error}"))
        })?;

    // Drive the handshake explicitly so the recorder has an exact, bounded wire view that ends at
    // the client Finished. This is intentionally before any HTTP application data is written.
    let wire = Arc::new(Mutex::new(HandshakeWire::default()));
    let mut recorder = RecordingStream::new(tcp, wire.clone(), deadline);
    while connection.is_handshaking() {
        connection.complete_io(&mut recorder).map_err(classify_io)?;
    }
    let handshake_wire = wire
        .lock()
        .expect("handshake wire mutex must not be poisoned")
        .clone();
    let tls = capture_tls_metadata(&connection, host, &capture, &handshake_wire)?;

    let request = build_http_request(url, host, port, config, credential_origin)?;
    let mut stream = rustls::StreamOwned::new(connection, recorder);
    stream.write_all(&request).map_err(classify_io)?;
    stream.flush().map_err(classify_io)?;
    let raw_limit = config
        .max_body_bytes
        .saturating_add(MAX_HTTP_RESPONSE_HEADER_BYTES);
    let (raw_response, raw_truncated) = read_capped(&mut stream, raw_limit, deadline)?;
    let (status_code, headers, body) = parse_http_response(&raw_response)?;
    let content_type = header_value(&headers, "content-type");
    let location = header_value(&headers, "location");
    let (body, decoded_truncated) =
        decode_http_body(&headers, body, config.max_body_bytes, deadline)?;
    Ok(SingleResponse {
        status_code,
        headers_hash: hash_header_lines(&headers),
        content_type,
        location,
        body,
        body_truncated: raw_truncated || decoded_truncated,
        tls: Some(tls),
        egress_ip: Some(egress_ip),
    })
}

fn resolve_address(
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<std::net::SocketAddr, Error> {
    let host = host.to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(classify_io)
            .and_then(|mut addresses| {
                addresses.next().ok_or_else(|| {
                    Error::Transport(format!("DNS resolution returned no addresses for {host}"))
                })
            });
        let _ = sender.send(result);
    });
    receiver
        .recv_timeout(remaining(deadline)?)
        .map_err(|_| deadline_elapsed())?
}

/// Build a rustls configuration with Mozilla roots. TLS 1.3 is preferred and fully captured, while
/// TLS 1.2 remains enabled only so invalid-certificate test origins can reach the certificate
/// verifier and be rejected with the correct security error instead of a version-negotiation error.
/// Resumption is disabled to guarantee each scrape has a complete certificate-bearing handshake.
fn tls_config(capture: Arc<TlsCaptureState>, insecure: bool) -> Result<ClientConfig, Error> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let verifier: Arc<dyn ServerCertVerifier> = if insecure {
        Arc::new(InsecureVerifier)
    } else {
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| {
                Error::TlsCapture(format!("could not configure trust roots: {error}"))
            })?
    };
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(CapturingVerifier {
        inner: verifier,
        capture,
    });
    let mut config = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_root_certificates(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
    .with_no_client_auth();
    config.dangerous().set_certificate_verifier(verifier);
    config.resumption = Resumption::disabled();
    // This fetcher implements HTTP/1.1 itself. Do not offer h2, which a raw HTTP/1 parser cannot
    // decode, and do not offer ALPN values that would permit a different application protocol.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn build_http_request(
    url: &Url,
    host: &str,
    port: u16,
    config: &FetchConfig,
    credential_origin: &Url,
) -> Result<Vec<u8>, Error> {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let target = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let host_header = if url.port().is_none() {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host_header}\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\n",
    );
    let mut emitted_user_agent = false;
    for (name, value) in config.caller_headers_for(url, credential_origin) {
        validate_header_pair(name, value)?;
        if name.eq_ignore_ascii_case("user-agent") {
            emitted_user_agent = true;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if !emitted_user_agent {
        validate_header_pair("user-agent", &config.user_agent)?;
        request.push_str("user-agent: ");
        request.push_str(&config.user_agent);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    Ok(request.into_bytes())
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Headers, Vec<u8>), Error> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    let header_length = match response
        .parse(raw)
        .map_err(|error| Error::Fetch(format!("invalid HTTP response: {error}")))?
    {
        httparse::Status::Complete(length) => length,
        httparse::Status::Partial => {
            return Err(Error::Fetch(
                "incomplete HTTP response headers from TLS connection".to_string(),
            ));
        }
    };
    if header_length > MAX_HTTP_RESPONSE_HEADER_BYTES {
        return Err(Error::Fetch(format!(
            "HTTP response headers exceeded the maximum of {MAX_HTTP_RESPONSE_HEADER_BYTES} bytes"
        )));
    }
    let status_code = response
        .code
        .ok_or_else(|| Error::Fetch("HTTP response did not include a status code".to_string()))?;
    let headers = response
        .headers
        .iter()
        .map(|header| (header.name.to_ascii_lowercase(), header.value.to_vec()))
        .collect();
    Ok((status_code, headers, raw[header_length..].to_vec()))
}

fn decode_http_body(
    headers: &Headers,
    mut body: Vec<u8>,
    max_body_bytes: usize,
    deadline: Instant,
) -> Result<(Vec<u8>, bool), Error> {
    let mut truncated = false;
    if header_contains_token(headers, "transfer-encoding", "chunked") {
        let (decoded, chunk_truncated) = decode_chunked(&body, max_body_bytes, deadline)?;
        body = decoded;
        truncated |= chunk_truncated;
    }
    let encodings = header_value(headers, "content-encoding")
        .unwrap_or_default()
        .split(',')
        .map(|encoding| encoding.trim().to_ascii_lowercase())
        .filter(|encoding| !encoding.is_empty() && encoding != "identity")
        .collect::<Vec<_>>();
    for encoding in encodings.iter().rev() {
        let (decoded, decoding_truncated) = match encoding.as_str() {
            "gzip" => read_capped(GzDecoder::new(Cursor::new(body)), max_body_bytes, deadline)?,
            "deflate" => {
                // HTTP's historical `deflate` token is ambiguous in practice: some origins send
                // raw DEFLATE while others send a zlib wrapper. Accept both forms, as reqwest did
                // on this path before the in-process rustls terminator replaced HTTPS transport.
                let compressed = body;
                match read_capped(
                    DeflateDecoder::new(Cursor::new(&compressed)),
                    max_body_bytes,
                    deadline,
                ) {
                    Ok(decoded) => decoded,
                    Err(_) => read_capped(
                        ZlibDecoder::new(Cursor::new(&compressed)),
                        max_body_bytes,
                        deadline,
                    )
                    .map_err(|error| {
                        Error::Fetch(format!("could not decode deflate body: {error}"))
                    })?,
                }
            }
            "br" => read_capped(
                brotli::Decompressor::new(Cursor::new(body), 4096),
                max_body_bytes,
                deadline,
            )?,
            unsupported => {
                return Err(Error::Fetch(format!(
                    "unsupported Content-Encoding '{unsupported}'"
                )));
            }
        };
        body = decoded;
        truncated |= decoding_truncated;
    }
    let (body, body_truncated) = cap_bytes(body, max_body_bytes);
    Ok((body, truncated || body_truncated))
}

fn decode_chunked(
    mut encoded: &[u8],
    max_body_bytes: usize,
    deadline: Instant,
) -> Result<(Vec<u8>, bool), Error> {
    let mut decoded = Vec::new();
    loop {
        remaining(deadline)?;
        let Some(line_end) = encoded.windows(2).position(|bytes| bytes == b"\r\n") else {
            return Err(Error::Fetch(
                "malformed chunked response: missing chunk length terminator".to_string(),
            ));
        };
        let size_text = std::str::from_utf8(&encoded[..line_end])
            .map_err(|_| Error::Fetch("malformed chunked response length".to_string()))?;
        let size_text = size_text.split(';').next().unwrap_or(size_text).trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| Error::Fetch("malformed chunked response length".to_string()))?;
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            return Ok((decoded, false));
        }
        if encoded.len() < size + 2 || &encoded[size..size + 2] != b"\r\n" {
            return Err(Error::Fetch(
                "malformed chunked response: truncated chunk".to_string(),
            ));
        }
        let remaining = max_body_bytes.saturating_sub(decoded.len());
        if size > remaining {
            decoded.extend_from_slice(&encoded[..remaining]);
            return Ok((decoded, true));
        }
        decoded.extend_from_slice(&encoded[..size]);
        encoded = &encoded[size + 2..];
    }
}

/// Read no more than `max_body_bytes` and probe one additional byte to distinguish an exactly
/// sized body from a truncated one. This is the single memory boundary used by all transport and
/// decoder paths.
fn read_capped<R: Read>(
    mut reader: R,
    max_body_bytes: usize,
    deadline: Instant,
) -> Result<(Vec<u8>, bool), Error> {
    let mut body = Vec::with_capacity(max_body_bytes.min(64 * 1024));
    let mut chunk = [0_u8; 8192];
    while body.len() < max_body_bytes {
        remaining(deadline)?;
        let requested = (max_body_bytes - body.len()).min(chunk.len());
        let read = reader.read(&mut chunk[..requested]).map_err(classify_io)?;
        if read == 0 {
            return Ok((body, false));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let mut probe = [0_u8; 1];
    remaining(deadline)?;
    let body_truncated = reader.read(&mut probe).map_err(classify_io)? != 0;
    Ok((body, body_truncated))
}

fn cap_bytes(mut body: Vec<u8>, max_body_bytes: usize) -> (Vec<u8>, bool) {
    if body.len() > max_body_bytes {
        body.truncate(max_body_bytes);
        (body, true)
    } else {
        (body, false)
    }
}

fn header_value(headers: &Headers, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())
        .map(str::to_string)
}

fn header_contains_token(headers: &Headers, name: &str, token: &str) -> bool {
    header_value(headers, name).is_some_and(|value| {
        value
            .split(',')
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(token))
    })
}

fn hash_header_lines(headers: &Headers) -> String {
    let mut lines = headers
        .iter()
        .map(|(name, value)| format!("{name}: {}", String::from_utf8_lossy(value)))
        .collect::<Vec<_>>();
    lines.sort();
    sha256_hex(lines.join("\n").as_bytes())
}

/// Side-channel state populated by the verifier while rustls validates the peer. It only stores
/// the raw stapled OCSP response when the server actually sends one; absent evidence stays absent.
#[derive(Debug, Default)]
struct TlsCaptureState {
    ocsp: Mutex<Option<Vec<u8>>>,
}

#[derive(Debug)]
struct CapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    capture: Arc<TlsCaptureState>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !ocsp_response.is_empty() {
            *self
                .capture
                .ocsp
                .lock()
                .expect("OCSP capture mutex must not be poisoned") = Some(ocsp_response.to_vec());
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Deliberately permissive verifier, reachable only from the explicit `--insecure` option. It
/// exists solely to make a failed default certificate-validation test diagnosable and reproducible.
#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Records encrypted TLS records during the handshake only. Capturing at this layer binds the
/// digest to the actual client/server exchange without exposing application plaintext.
#[derive(Debug, Default, Clone)]
struct HandshakeWire {
    outbound: Vec<u8>,
    inbound: Vec<u8>,
}

#[derive(Debug)]
struct RecordingStream {
    inner: TcpStream,
    wire: Arc<Mutex<HandshakeWire>>,
    deadline: Instant,
}

impl RecordingStream {
    fn new(inner: TcpStream, wire: Arc<Mutex<HandshakeWire>>, deadline: Instant) -> Self {
        Self {
            inner,
            wire,
            deadline,
        }
    }
}

impl Read for RecordingStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        set_socket_read_timeout(&self.inner, self.deadline)?;
        let read = self.inner.read(buffer)?;
        if read != 0 {
            self.wire
                .lock()
                .expect("handshake wire mutex must not be poisoned")
                .inbound
                .extend_from_slice(&buffer[..read]);
        }
        Ok(read)
    }
}

impl Write for RecordingStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        set_socket_write_timeout(&self.inner, self.deadline)?;
        let written = self.inner.write(buffer)?;
        if written != 0 {
            self.wire
                .lock()
                .expect("handshake wire mutex must not be poisoned")
                .outbound
                .extend_from_slice(&buffer[..written]);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        set_socket_write_timeout(&self.inner, self.deadline)?;
        self.inner.flush()
    }
}

/// A TCP stream that derives each socket I/O timeout from the absolute scrape deadline.
///
/// Refreshing this before every read/write prevents a peer that drips bytes from obtaining a new
/// full request timeout for each socket operation.
struct DeadlineStream {
    inner: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn new(inner: TcpStream, deadline: Instant) -> Self {
        Self { inner, deadline }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        set_socket_read_timeout(&self.inner, self.deadline)?;
        self.inner.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        set_socket_write_timeout(&self.inner, self.deadline)?;
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        set_socket_write_timeout(&self.inner, self.deadline)?;
        self.inner.flush()
    }
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(deadline_elapsed)
}

fn deadline_elapsed() -> Error {
    Error::Timeout("scrape deadline exceeded".to_string())
}

fn socket_remaining(deadline: Instant) -> io::Result<Duration> {
    remaining(deadline).map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error.to_string()))
}

fn set_socket_read_timeout(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    stream.set_read_timeout(Some(socket_remaining(deadline)?))
}

fn set_socket_write_timeout(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    stream.set_write_timeout(Some(socket_remaining(deadline)?))
}

fn capture_tls_metadata(
    connection: &ClientConnection,
    host: &str,
    capture: &TlsCaptureState,
    handshake_wire: &HandshakeWire,
) -> Result<Tls, Error> {
    let version = match connection.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2".to_string(),
        Some(version) => {
            return Err(Error::TlsCapture(format!(
                "TLS terminator negotiated an unsupported version {version:?}"
            )));
        }
        None => {
            return Err(Error::TlsCapture(
                "TLS version was not negotiated".to_string(),
            ))
        }
    };
    let certificates = connection.peer_certificates().ok_or_else(|| {
        Error::TlsCapture("server did not provide a certificate chain".to_string())
    })?;
    if certificates.is_empty() {
        return Err(Error::TlsCapture(
            "server provided an empty certificate chain".to_string(),
        ));
    }
    let certs = certificates
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect::<Vec<_>>();
    let server_ephemeral_pubkey = if version == "1.3" {
        Some(
            parse_server_key_share(&handshake_wire.inbound).ok_or_else(|| {
                Error::TlsCapture(
                    "TLS 1.3 ServerHello did not include an ECDHE key share".to_string(),
                )
            })?,
        )
    } else {
        None
    };
    let transcript = handshake_wire_hash(handshake_wire);
    let ct_scts = embedded_scts(&certs[0]);
    let ocsp = capture
        .ocsp
        .lock()
        .expect("OCSP capture mutex must not be poisoned")
        .as_deref()
        .filter(|response| !response.is_empty())
        .map(|response| base64::prelude::BASE64_STANDARD.encode(response));

    Ok(Tls {
        negotiated_version: Some(version),
        sni: Some(host.to_string()),
        server_cert_chain_der: certs
            .iter()
            .map(|certificate| base64::prelude::BASE64_STANDARD.encode(certificate))
            .collect(),
        cert_chain_hash: Some(cert_chain_hash(&certs)),
        server_ephemeral_pubkey: server_ephemeral_pubkey
            .as_deref()
            .map(|key_share| base64::prelude::BASE64_STANDARD.encode(key_share)),
        ct_scts,
        ocsp,
        handshake_transcript_hash: Some(transcript),
    })
}

/// SHA-256 over the complete, direction-delimited handshake wire exchange. It includes exact TLS
/// record headers and encrypted TLS 1.3 handshake records, and is captured before HTTP bytes flow.
/// Fresh ClientHello randomness and ECDHE shares therefore make it non-static across sessions.
fn handshake_wire_hash(wire: &HandshakeWire) -> String {
    let mut hasher = Sha256::new();
    for (direction, bytes) in [(b'C', &wire.outbound), (b'S', &wire.inbound)] {
        hasher.update([direction]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hex_lower(&hasher.finalize())
}

/// Locate the final TLS 1.3 ServerHello and return its key-share bytes. ServerHello remains
/// plaintext in TLS 1.3, so this is extracted from the observed inbound records rather than a
/// rustls-private handshake structure.
fn parse_server_key_share(records: &[u8]) -> Option<Vec<u8>> {
    let mut handshake = Vec::new();
    let mut offset = 0;
    while offset + 5 <= records.len() {
        let content_type = records[offset];
        let length = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
        let end = offset.checked_add(5 + length)?;
        if end > records.len() {
            return None;
        }
        if content_type == 22 {
            handshake.extend_from_slice(&records[offset + 5..end]);
        }
        offset = end;
    }

    let mut offset = 0;
    let mut key_share = None;
    while offset + 4 <= handshake.len() {
        let message_type = handshake[offset];
        let length = ((handshake[offset + 1] as usize) << 16)
            | ((handshake[offset + 2] as usize) << 8)
            | handshake[offset + 3] as usize;
        let end = offset.checked_add(4 + length)?;
        if end > handshake.len() {
            return None;
        }
        if message_type == 2 {
            key_share = parse_server_hello_key_share(&handshake[offset + 4..end])
                .map(|key_share| key_share.to_vec())
                .or(key_share);
        }
        offset = end;
    }
    key_share
}

fn parse_server_hello_key_share(server_hello: &[u8]) -> Option<&[u8]> {
    // legacy_version(2), random(32), legacy_session_id_echo<0..32>, cipher_suite(2),
    // legacy_compression_method(1), extensions<8..2^16-1>.
    let session_id_length = *server_hello.get(34)? as usize;
    let extensions_start = 35usize.checked_add(session_id_length)?.checked_add(3)?;
    let extensions_length = u16::from_be_bytes([
        *server_hello.get(extensions_start)?,
        *server_hello.get(extensions_start + 1)?,
    ]) as usize;
    let mut offset = extensions_start + 2;
    let extensions_end = offset.checked_add(extensions_length)?;
    if extensions_end > server_hello.len() {
        return None;
    }
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([server_hello[offset], server_hello[offset + 1]]);
        let length =
            u16::from_be_bytes([server_hello[offset + 2], server_hello[offset + 3]]) as usize;
        offset += 4;
        let end = offset.checked_add(length)?;
        if end > extensions_end {
            return None;
        }
        if extension_type == 0x0033 && length >= 4 {
            let key_length =
                u16::from_be_bytes([server_hello[offset + 2], server_hello[offset + 3]]) as usize;
            if key_length != 0 && key_length + 4 == length {
                return server_hello.get(offset + 4..end);
            }
        }
        offset = end;
    }
    None
}

/// Capture only SCTs genuinely embedded in the leaf's RFC 6962 extension. The wire schema uses a
/// base64 array of original SCT byte entries, never synthetic metadata.
fn embedded_scts(leaf_der: &[u8]) -> Vec<String> {
    let Ok((_, certificate)) = parse_x509_certificate(leaf_der) else {
        return Vec::new();
    };
    certificate
        .extensions()
        .iter()
        // The current x509-parser release retains the SCT extension's ASN.1 OCTET STRING, so
        // identify the RFC 6962 OID directly, unwrap it, and parse the SCT list bytes ourselves.
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.11129.2.4.2")
        .map(|extension| parse_sct_extension(extension.value))
        .unwrap_or_default()
}

fn parse_sct_extension(value: &[u8]) -> Vec<String> {
    der_octet_string_contents(value)
        .map(parse_sct_list)
        .unwrap_or_else(|| parse_sct_list(value))
}

fn der_octet_string_contents(value: &[u8]) -> Option<&[u8]> {
    if value.first().copied()? != 0x04 {
        return None;
    }
    let first_length = *value.get(1)?;
    let (length, offset) = if first_length & 0x80 == 0 {
        (first_length as usize, 2)
    } else {
        let length_bytes = (first_length & 0x7f) as usize;
        if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
            return None;
        }
        let bytes = value.get(2..2 + length_bytes)?;
        let length = bytes
            .iter()
            .fold(0usize, |length, byte| (length << 8) | *byte as usize);
        (length, 2 + length_bytes)
    };
    value
        .get(offset..offset.checked_add(length)?)
        .filter(|contents| offset + contents.len() == value.len())
}

fn parse_sct_list(value: &[u8]) -> Vec<String> {
    if value.len() < 2 {
        return Vec::new();
    }
    let expected = u16::from_be_bytes([value[0], value[1]]) as usize;
    if expected != value.len() - 2 {
        return Vec::new();
    }
    let mut scts = Vec::new();
    let mut offset = 2;
    while offset + 2 <= value.len() {
        let length = u16::from_be_bytes([value[offset], value[offset + 1]]) as usize;
        offset += 2;
        let end = match offset.checked_add(length) {
            Some(end) if end <= value.len() => end,
            _ => return Vec::new(),
        };
        if length == 0 {
            return Vec::new();
        }
        scts.push(base64::prelude::BASE64_STANDARD.encode(&value[offset..end]));
        offset = end;
    }
    if offset == value.len() {
        scts
    } else {
        Vec::new()
    }
}

fn cert_chain_hash(certificates: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for certificate in certificates {
        hasher.update(certificate);
    }
    hex_lower(&hasher.finalize())
}

fn classify_io(error: io::Error) -> Error {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("certificate") || lower.contains("cert ") {
        Error::CertificateValidation(message)
    } else if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        Error::Timeout(message)
    } else {
        Error::Transport(message)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_lowercase_and_64_wide() {
        let h = sha256_hex(b"");
        assert_eq!(h.len(), 64);
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn parse_header_splits_name_and_value() {
        assert_eq!(
            parse_header("X-Probe: 1").unwrap(),
            ("X-Probe".to_string(), "1".to_string())
        );
    }

    #[test]
    fn parse_header_trims_only_one_leading_space() {
        // A value that intentionally starts with two spaces keeps the second one.
        assert_eq!(
            parse_header("X-Pad:  v").unwrap(),
            ("X-Pad".to_string(), " v".to_string())
        );
    }

    #[test]
    fn parse_header_allows_colons_in_value() {
        assert_eq!(
            parse_header("X-Time: 12:30:00").unwrap(),
            ("X-Time".to_string(), "12:30:00".to_string())
        );
    }

    #[test]
    fn parse_header_rejects_missing_colon() {
        assert!(matches!(
            parse_header("no-colon-here"),
            Err(Error::InvalidHeader(_))
        ));
    }

    #[test]
    fn parse_header_rejects_empty_name() {
        assert!(matches!(parse_header(": v"), Err(Error::InvalidHeader(_))));
    }

    #[test]
    fn default_user_agent_is_browser_like() {
        assert!(DEFAULT_USER_AGENT.contains("Mozilla/5.0"));
        assert!(!DEFAULT_USER_AGENT.to_lowercase().contains("reqwest"));
    }

    #[test]
    fn same_origin_requires_scheme_host_and_effective_port_match() {
        let origin = Url::parse("https://Example.test/path").unwrap();
        assert!(same_origin(
            &origin,
            &Url::parse("https://example.test:443/other").unwrap()
        ));
        assert!(!same_origin(
            &origin,
            &Url::parse("http://example.test/other").unwrap()
        ));
        assert!(!same_origin(
            &origin,
            &Url::parse("https://other.test/other").unwrap()
        ));
        assert!(!same_origin(
            &origin,
            &Url::parse("https://example.test:8443/other").unwrap()
        ));
    }

    #[test]
    fn extracts_server_key_share_from_tls13_server_hello() {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hello.extend_from_slice(&[0; 32]); // random
        hello.push(0); // legacy_session_id_echo length
        hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello.push(0); // legacy_compression_method
        hello.extend_from_slice(&[0, 10]); // extension vector length
        hello.extend_from_slice(&[0, 0x33, 0, 6, 0, 0x1d, 0, 2, 0xaa, 0xbb]);

        let mut handshake = vec![2, 0, 0, hello.len() as u8];
        handshake.extend_from_slice(&hello);
        let mut record = vec![22, 3, 3, 0, handshake.len() as u8];
        record.extend_from_slice(&handshake);

        assert_eq!(parse_server_key_share(&record), Some(vec![0xaa, 0xbb]));
    }

    #[test]
    fn handshake_wire_hash_is_direction_delimited_and_session_sensitive() {
        let first = HandshakeWire {
            outbound: b"client-one".to_vec(),
            inbound: b"server".to_vec(),
        };
        let same = first.clone();
        let second = HandshakeWire {
            outbound: b"client-two".to_vec(),
            inbound: b"server".to_vec(),
        };
        assert_eq!(handshake_wire_hash(&first), handshake_wire_hash(&same));
        assert_ne!(handshake_wire_hash(&first), handshake_wire_hash(&second));
        assert_eq!(handshake_wire_hash(&first).len(), 64);
    }

    #[test]
    fn sct_parser_preserves_only_well_formed_embedded_entries() {
        assert_eq!(parse_sct_list(&[0, 5, 0, 3, 1, 2, 3]), vec!["AQID"]);
        assert!(parse_sct_list(&[0, 6, 0, 3, 1, 2, 3]).is_empty());
        assert!(parse_sct_list(&[0, 2, 0, 1]).is_empty());
        assert_eq!(
            parse_sct_extension(&[4, 7, 0, 5, 0, 3, 1, 2, 3]),
            vec!["AQID"]
        );
    }
}
