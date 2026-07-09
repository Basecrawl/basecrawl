//! HTTP(S) fetch feeding the ScrapeProof `response` block.
//!
//! This path owns the core fetch semantics: accurate status capture (2xx/4xx/5xx are recorded, not
//! masked), transparent `gzip`/`deflate`/`brotli` content decoding (so `content_length` reflects the
//! decoded body), an enforced request timeout, custom request headers, a browser-plausible
//! User-Agent, and transport-level failures (DNS/connect/timeout) surfaced as structured errors
//! distinct from any HTTP status. The in-process TLS 1.3 termination that populates the `tls` block
//! replaces this transport in the TLS-capture feature.

use crate::error::Error;
use basecrawl_proof::RedirectHop;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

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

/// Configuration for a single fetch.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Whole-request timeout. A slow endpoint aborts near this bound rather than blocking.
    pub timeout: Duration,
    /// Extra request headers to send, as already-parsed `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// User-Agent presented to the origin.
    pub user_agent: String,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            headers: Vec::new(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }
}

/// Outcome of a single HTTP fetch. `body` is the *decoded* response body (any transfer/content
/// encoding already removed), so `content_length == body.len()`.
pub struct Fetched {
    pub status_code: u16,
    pub headers_hash: String,
    pub body_hash: String,
    pub content_length: u64,
    pub body: Vec<u8>,
    /// Terminal URL the response was served from after following any redirects.
    pub final_url: String,
    /// Redirect hops followed to reach the terminal response, in order.
    pub redirects: Vec<RedirectHop>,
}

/// Parse a single `Name: Value` header specification.
///
/// The name is the text before the first colon; the value is everything after it (trimmed of one
/// leading space, HTTP-style). An empty name or a missing colon is an [`Error::InvalidHeader`].
pub fn parse_header(spec: &str) -> Result<(String, String), Error> {
    let (name, value) = spec
        .split_once(':')
        .ok_or_else(|| Error::InvalidHeader(spec.to_string()))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::InvalidHeader(spec.to_string()));
    }
    let value = value.strip_prefix(' ').unwrap_or(value).trim_end();
    Ok((name.to_string(), value.to_string()))
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
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in &config.headers {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::InvalidHeader(format!("{name}: {value}")))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|_| Error::InvalidHeader(format!("{name}: {value}")))?;
        headers.insert(header_name, header_value);
    }

    let client = reqwest::blocking::Client::builder()
        .user_agent(&config.user_agent)
        .timeout(config.timeout)
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Fetch(error_chain(&e)))?;

    let mut current = url.clone();
    let mut redirects: Vec<RedirectHop> = Vec::new();

    loop {
        let response = client.get(current.clone()).send().map_err(classify)?;
        let status = response.status();

        if status.is_redirection() {
            if let Some(location) = response.headers().get(reqwest::header::LOCATION) {
                if redirects.len() >= MAX_REDIRECTS {
                    return Err(Error::TooManyRedirects {
                        max: MAX_REDIRECTS,
                        url: url.to_string(),
                    });
                }
                let location = location.to_str().map_err(|_| {
                    Error::Redirect(format!(
                        "redirect from {current} has a non-textual Location header"
                    ))
                })?;
                let target = current.join(location).map_err(|_| {
                    Error::Redirect(format!(
                        "could not resolve redirect Location '{location}' against {current}"
                    ))
                })?;
                redirects.push(RedirectHop {
                    status_code: status.as_u16(),
                    url: current.to_string(),
                    location: target.to_string(),
                });
                current = target;
                continue;
            }
        }

        let status_code = status.as_u16();
        let headers_hash = hash_headers(response.headers());
        // reqwest transparently decodes gzip/deflate/brotli, so these bytes are the decoded body.
        let body = response.bytes().map_err(classify)?;
        let body_hash = sha256_hex(&body);
        let content_length = body.len() as u64;

        return Ok(Fetched {
            status_code,
            headers_hash,
            body_hash,
            content_length,
            body: body.to_vec(),
            final_url: current.to_string(),
            redirects,
        });
    }
}

/// Classify a `reqwest` transport failure into a structured [`Error`]. Timeouts are reported
/// distinctly; every other send/read failure (DNS, connect, reset) is a transport error, never an
/// HTTP status.
fn classify(err: reqwest::Error) -> Error {
    if err.is_timeout() {
        Error::Timeout(error_chain(&err))
    } else {
        Error::Transport(error_chain(&err))
    }
}

/// Flatten an error and its source chain into a single message so the root cause (e.g. the DNS
/// lookup failure behind a connect error) is preserved for the caller.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut source = err.source();
    while let Some(inner) = source {
        let text = inner.to_string();
        if !msg.contains(&text) {
            msg.push_str(": ");
            msg.push_str(&text);
        }
        source = inner.source();
    }
    msg
}

fn hash_headers(headers: &reqwest::header::HeaderMap) -> String {
    let mut lines: Vec<String> = headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}: {}",
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes())
            )
        })
        .collect();
    lines.sort();
    sha256_hex(lines.join("\n").as_bytes())
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
}
