//! Structured error type for the crawler core and CLI.
//!
//! Every error carries a stable machine-readable `kind` and serializes to a structured JSON
//! object (`{"error": {...}}`) so that failures are testable and never emit a partial ScrapeProof.
//!
//! Host-visible serialization (stderr, FFI last-error) redacts target URL path/query, request
//! headers/cookies/tokens/body, and result content per VAL-CONF-018/019/020/031. Callers that need
//! a host-safe log/metric line use [`Error::to_host_safe_json`] / [`Error::host_safe_labels`].

use basecrawl_seal::{
    redact_json_value, task_id_ref, url_path_query_ref, url_ref, HostSafeLabels, REDACTED_TOKEN,
};
use serde_json::{json, Value};
use thiserror::Error;

/// Keys in structured robots / policy payloads whose values are URL-shaped and must be
/// host-safe-digested before they leave the enclave as error JSON.
const URL_SHAPED_JSON_KEYS: &[&str] = &[
    "targetUrl",
    "robotsUrl",
    "url",
    "final_url",
    "finalUrl",
    "path",
    "location",
];

/// A recoverable failure while validating input or performing a scrape.
#[derive(Debug, Error)]
pub enum Error {
    #[error("no URL provided")]
    MissingUrl,

    /// The raw input is retained for enclave-local diagnostics only; host-visible
    /// serialization never echoes it (VAL-CONF-018 / 031).
    #[error("invalid URL")]
    InvalidUrl(String),

    #[error("unsupported URL scheme '{0}' (only http and https are allowed)")]
    UnsupportedScheme(String),

    #[error("unknown format '{invalid}' (supported: {supported})")]
    UnknownFormat { invalid: String, supported: String },

    #[error("unsupported output format '{0}' (only 'json' is supported)")]
    UnsupportedOutput(String),

    #[error("structured extraction for the 'json' format is unavailable in this build")]
    StructuredExtractionUnsupported,

    #[error("invalid request header '{0}' (expected 'Name: Value')")]
    InvalidHeader(String),

    #[error("invalid viewport '{0}' (expected WIDTHxHEIGHT, e.g. 1280x800)")]
    InvalidViewport(String),

    #[error("invalid actions specification: {0}")]
    InvalidActions(String),

    #[error("invalid proxy configuration: {0}")]
    InvalidProxy(String),

    /// Required commercial proxy class cannot be dialed (missing upstream / refused dial).
    /// Fail closed: never emit a success proof claiming residential/mobile for direct egress.
    #[error("required proxy class '{required}' unavailable: {detail}")]
    ProxyClassUnavailable { required: String, detail: String },

    #[error("robots policy denied the requested path")]
    RobotsDenied(Value),

    #[error("request timed out: {0}")]
    Timeout(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("certificate validation failed: {0}")]
    CertificateValidation(String),

    #[error("TLS capture failed: {0}")]
    TlsCapture(String),

    #[error(
        "negotiated TLS version {negotiated_version} cannot produce an authenticity-capable proof; TLS 1.3 is required"
    )]
    TlsVersionUnsupported { negotiated_version: String },

    /// `url` is retained only for engave-local correlation; host-visible streams never
    /// include the raw path/query (VAL-CONF-018 / 031).
    #[error("too many redirects: exceeded the maximum of {max} hop(s)")]
    TooManyRedirects { max: usize, url: String },

    #[error("invalid redirect: {0}")]
    Redirect(String),

    #[error("fetch failed: {0}")]
    Fetch(String),

    #[error("html render failed: {0}")]
    Render(String),

    /// Sealed browser DoH/SOCKS DNS isolation could not be established (VAL-CONF-013 fail-closed).
    #[error("sealed browser DNS isolation failed: {0}")]
    DnsIsolation(String),

    #[error("the scrape-owned browser request or byte budget was exhausted")]
    ResourceBudgetExceeded,

    #[error("document extraction failed: {0}")]
    DocumentExtraction(String),

    #[error("could not produce egress metadata: {0}")]
    EgressMetadata(String),

    #[error("TDX attestation failed: {0}")]
    Attestation(String),

    #[error("enclave signature failed: {0}")]
    EnclaveSignature(String),

    #[error("failed to write output file: {0}")]
    Io(String),
}

impl Error {
    /// Stable machine-readable discriminant.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::MissingUrl => "missing_url",
            Error::InvalidUrl(_) => "invalid_url",
            Error::UnsupportedScheme(_) => "unsupported_scheme",
            Error::UnknownFormat { .. } => "invalid_format",
            Error::UnsupportedOutput(_) => "unsupported_output",
            Error::StructuredExtractionUnsupported => "structured_extraction_unsupported",
            Error::InvalidHeader(_) => "invalid_header",
            Error::InvalidViewport(_) => "invalid_viewport",
            Error::InvalidActions(_) => "invalid_actions",
            Error::InvalidProxy(_) => "invalid_proxy",
            Error::ProxyClassUnavailable { .. } => "proxy_class_unavailable",
            Error::RobotsDenied(_) => "robots_denied",
            Error::Timeout(_) => "timeout",
            Error::Transport(_) => "transport_error",
            Error::CertificateValidation(_) => "certificate_validation",
            Error::TlsCapture(_) => "tls_capture_error",
            Error::TlsVersionUnsupported { .. } => "tls_version_unsupported",
            Error::TooManyRedirects { .. } => "too_many_redirects",
            Error::Redirect(_) => "redirect_error",
            Error::Fetch(_) => "fetch_error",
            Error::Render(_) => "render_error",
            Error::DnsIsolation(_) => "dns_isolation",
            Error::ResourceBudgetExceeded => "resource_budget_exceeded",
            Error::DocumentExtraction(_) => "document_extraction",
            Error::EgressMetadata(_) => "egress_metadata_error",
            Error::Attestation(_) => "attestation_error",
            Error::EnclaveSignature(_) => "enclave_signature_error",
            Error::Io(_) => "io_error",
        }
    }

    /// Non-zero process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        1
    }

    /// Restore a robots denial recorded by the renderer's dependency-neutral document policy hook.
    ///
    /// The render crate intentionally does not depend on core policy types, so it carries a
    /// serialized decision detail. Invalid detail remains a normal render failure rather than
    /// fabricating a policy error.
    pub fn from_document_policy_denial(detail: String) -> Self {
        serde_json::from_str::<Value>(&detail)
            .map(Self::RobotsDenied)
            .unwrap_or(Self::Render(detail))
    }

    /// Host-visible structured `{"error": {...}}` payload.
    ///
    /// Never embeds target URL path/query, header/cookie/token/body values, or result plaintext.
    /// Equivalent to the historical `to_json` surface used by CLI stderr and FFI last-error.
    pub fn to_json(&self) -> Value {
        self.to_host_safe_json(None)
    }

    /// Host-visible structured error, optionally correlating to a redacted task id.
    pub fn to_host_safe_json(&self, task_id: Option<&str>) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("kind".into(), Value::String(self.kind().into()));
        obj.insert(
            "message".into(),
            Value::String(self.host_safe_message().into_owned()),
        );
        obj.insert("task_id".into(), Value::String(task_id_ref(task_id)));
        match self {
            Error::UnknownFormat { invalid, .. } => {
                obj.insert("invalid_format".into(), Value::String(invalid.clone()));
            }
            Error::UnsupportedScheme(scheme) => {
                obj.insert("scheme".into(), Value::String(scheme.clone()));
            }
            Error::TlsVersionUnsupported { negotiated_version } => {
                obj.insert(
                    "negotiated_version".into(),
                    Value::String(negotiated_version.clone()),
                );
            }
            Error::StructuredExtractionUnsupported => {
                obj.insert("format".into(), Value::String("json".into()));
                obj.insert(
                    "capability".into(),
                    Value::String("structured_extraction".into()),
                );
                obj.insert("reason".into(), Value::String("not_built".into()));
            }
            Error::TooManyRedirects { max, url } => {
                obj.insert("max_redirects".into(), Value::Number((*max).into()));
                // Host-safe path+query digest only — never the raw URL.
                obj.insert("url_ref".into(), Value::String(url_path_query_ref(url)));
            }
            Error::InvalidUrl(raw) => {
                // Correlate without echoing path/query. Host digests empty path for garbage input.
                obj.insert("url_ref".into(), Value::String(url_path_query_ref(raw)));
            }
            Error::RobotsDenied(robots) => {
                let mut scrubbed = robots.clone();
                redact_json_value(&mut scrubbed, &[], URL_SHAPED_JSON_KEYS);
                obj.insert("robots".into(), scrubbed);
            }
            Error::ProxyClassUnavailable { required, .. } => {
                obj.insert(
                    "required_proxy_class".into(),
                    Value::String(required.clone()),
                );
            }
            _ => {}
        }
        json!({ "error": Value::Object(obj) })
    }

    /// Compact JSON string of [`Error::to_json`].
    pub fn to_json_string(&self) -> String {
        self.to_json().to_string()
    }

    /// Compact host-safe JSON that optionally binds a task id reference.
    pub fn to_host_safe_json_string(&self, task_id: Option<&str>) -> String {
        self.to_host_safe_json(task_id).to_string()
    }

    /// Metric / log labels free of path/query / header / body / result content.
    pub fn host_safe_labels(&self, task_id: Option<&str>) -> HostSafeLabels {
        HostSafeLabels::scrape_failed(task_id, self.kind())
    }

    /// Human-readable message safe for host-visible channels.
    ///
    /// Differs from `Display` only where Display historically embedded a raw URL or token;
    /// for every other variant the Display text is already host-safe.
    pub fn host_safe_message(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Error::InvalidUrl(_) => std::borrow::Cow::Borrowed("invalid URL"),
            Error::TooManyRedirects { max, .. } => std::borrow::Cow::Owned(format!(
                "too many redirects: exceeded the maximum of {max} hop(s)"
            )),
            Error::InvalidHeader(name) => {
                // Header *names* are structural and host-safe; construction sites already
                // substitute REDACTED_TOKEN for any residual value material.
                let safe_name = if name.contains(':') || name.contains('=') {
                    REDACTED_TOKEN
                } else {
                    name.as_str()
                };
                std::borrow::Cow::Owned(format!(
                    "invalid request header '{safe_name}' (expected 'Name: Value')"
                ))
            }
            Error::Redirect(detail) => {
                // Redirect construction may still carry residual location text in older call sites;
                // scrub anything URL-shaped defensively.
                std::borrow::Cow::Owned(strip_url_shaped(detail))
            }
            // Preserve thiserror Display prefixes (e.g. "request timed out:", "html render
            // failed:") so host-visible messages stay stable under redaction. Strip any
            // residual URL-shaped text from the full Display string, not only the bare detail.
            Error::Transport(_)
            | Error::Fetch(_)
            | Error::Render(_)
            | Error::DnsIsolation(_)
            | Error::Timeout(_)
            | Error::CertificateValidation(_)
            | Error::TlsCapture(_)
            | Error::DocumentExtraction(_)
            | Error::EgressMetadata(_)
            | Error::Attestation(_)
            | Error::EnclaveSignature(_)
            | Error::Io(_)
            | Error::InvalidActions(_)
            | Error::InvalidViewport(_) => {
                std::borrow::Cow::Owned(strip_url_shaped(&self.to_string()))
            }
            other => std::borrow::Cow::Owned(other.to_string()),
        }
    }
}

/// Defensive scrub for free-form error details that might still embed a URL/path/query.
fn strip_url_shaped(detail: &str) -> String {
    // Fast path: no scheme and no query-looking fragment.
    if !(detail.contains("://") || (detail.contains('?') && detail.contains('='))) {
        // Also collapse bare absolute-path quotes that look like "/secret/...".
        if !detail.contains("/secret") && !detail.contains('\'') {
            return detail.to_owned();
        }
    }
    // Replace every URL-looking token with a host-safe ref inline.
    let mut out = String::with_capacity(detail.len());
    let mut rest = detail;
    while let Some(idx) = rest.find("://") {
        // Walk back to scheme start.
        let prefix = &rest[..idx];
        let scheme_start = prefix
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-'))
            .map(|i| i + 1)
            .unwrap_or(0);
        out.push_str(&rest[..scheme_start]);
        let url_region = &rest[scheme_start..];
        let url_end = url_region
            .find(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == '>')
            .unwrap_or(url_region.len());
        let (url, after) = url_region.split_at(url_end);
        out.push_str(&url_ref(url));
        rest = after;
    }
    // Residual path-looking quoted forms: '/foo?bar=baz'
    let rest = scrub_quoted_paths(rest);
    out.push_str(&rest);
    out
}

fn scrub_quoted_paths(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' || c == '"' {
            let quote = c;
            let mut token = String::new();
            while let Some(&n) = chars.peek() {
                if n == quote {
                    chars.next();
                    break;
                }
                token.push(n);
                chars.next();
            }
            if token.starts_with('/') || token.contains('?') {
                out.push(quote);
                out.push_str(&url_path_query_ref(&format!(
                    "https://placeholder.invalid{token}"
                )));
                out.push(quote);
            } else {
                out.push(quote);
                out.push_str(&token);
                out.push(quote);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn invalid_url_host_json_never_echoes_path_query() {
        let err = Error::InvalidUrl("https://target.example/secret/path?token=leak-me".into());
        let rendered = err.to_json_string();
        assert!(!rendered.contains("/secret/path"));
        assert!(!rendered.contains("token=leak-me"));
        assert!(!rendered.contains("leak-me"));
        assert_eq!(
            err.to_json()["error"]["kind"],
            Value::String("invalid_url".into())
        );
        assert!(rendered.contains("task:none"));
    }

    #[test]
    fn too_many_redirects_redacts_url() {
        let err = Error::TooManyRedirects {
            max: 20,
            url: "https://target.example/loop?session=abc".into(),
        };
        let rendered = err.to_json_string();
        assert!(!rendered.contains("/loop"));
        assert!(!rendered.contains("session=abc"));
        assert_eq!(err.to_json()["error"]["max_redirects"], 20);
        assert!(rendered.contains("url_ref"));
        assert!(rendered.contains("too many redirects"));
    }

    #[test]
    fn robots_denied_scrubs_target_url_and_path() {
        let err = Error::RobotsDenied(json!({
            "policy": "enforce",
            "disposition": "denied",
            "targetUrl": "https://example.com/blocked/private?robots-denied=1",
            "matched_rule": { "directive": "disallow", "path": "/blocked" },
        }));
        let rendered = err.to_json_string();
        assert!(!rendered.contains("/blocked"));
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("robots-denied=1"));
        assert!(rendered.contains("denied"));
        assert!(rendered.contains("enforce"));
    }

    #[test]
    fn host_safe_labels_free_of_url_and_task_plaintext() {
        let err = Error::Timeout("scrape deadline exceeded".into());
        let labels = err.host_safe_labels(Some("task-marker-xyz"));
        assert!(labels.is_free_of(&["task-marker-xyz", "/secret", "Bearer"]));
        assert_eq!(labels.kind.as_deref(), Some("timeout"));
    }
}
