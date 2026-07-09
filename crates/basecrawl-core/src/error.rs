//! Structured error type for the crawler core and CLI.
//!
//! Every error carries a stable machine-readable `kind` and serializes to a structured JSON
//! object (`{"error": {...}}`) so that failures are testable and never emit a partial ScrapeProof.

use serde_json::{json, Value};
use thiserror::Error;

/// A recoverable failure while validating input or performing a scrape.
#[derive(Debug, Error)]
pub enum Error {
    #[error("no URL provided")]
    MissingUrl,

    #[error("invalid URL: '{0}'")]
    InvalidUrl(String),

    #[error("unsupported URL scheme '{0}' (only http and https are allowed)")]
    UnsupportedScheme(String),

    #[error("unknown format '{invalid}' (supported: {supported})")]
    UnknownFormat { invalid: String, supported: String },

    #[error("unsupported output format '{0}' (only 'json' is supported)")]
    UnsupportedOutput(String),

    #[error("invalid request header '{0}' (expected 'Name: Value')")]
    InvalidHeader(String),

    #[error("invalid viewport '{0}' (expected WIDTHxHEIGHT, e.g. 1280x800)")]
    InvalidViewport(String),

    #[error("invalid actions specification: {0}")]
    InvalidActions(String),

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

    #[error("too many redirects: exceeded the maximum of {max} hop(s) while fetching '{url}'")]
    TooManyRedirects { max: usize, url: String },

    #[error("invalid redirect: {0}")]
    Redirect(String),

    #[error("fetch failed: {0}")]
    Fetch(String),

    #[error("html render failed: {0}")]
    Render(String),

    #[error("document extraction failed: {0}")]
    DocumentExtraction(String),

    #[error("could not produce egress metadata: {0}")]
    EgressMetadata(String),

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
            Error::InvalidHeader(_) => "invalid_header",
            Error::InvalidViewport(_) => "invalid_viewport",
            Error::InvalidActions(_) => "invalid_actions",
            Error::RobotsDenied(_) => "robots_denied",
            Error::Timeout(_) => "timeout",
            Error::Transport(_) => "transport_error",
            Error::CertificateValidation(_) => "certificate_validation",
            Error::TlsCapture(_) => "tls_capture_error",
            Error::TooManyRedirects { .. } => "too_many_redirects",
            Error::Redirect(_) => "redirect_error",
            Error::Fetch(_) => "fetch_error",
            Error::Render(_) => "render_error",
            Error::DocumentExtraction(_) => "document_extraction",
            Error::EgressMetadata(_) => "egress_metadata_error",
            Error::Io(_) => "io_error",
        }
    }

    /// Non-zero process exit code for this error.
    pub fn exit_code(&self) -> i32 {
        1
    }

    /// Structured `{"error": {...}}` representation for stderr.
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("kind".into(), Value::String(self.kind().into()));
        obj.insert("message".into(), Value::String(self.to_string()));
        match self {
            Error::UnknownFormat { invalid, .. } => {
                obj.insert("invalid_format".into(), Value::String(invalid.clone()));
            }
            Error::UnsupportedScheme(scheme) => {
                obj.insert("scheme".into(), Value::String(scheme.clone()));
            }
            Error::TooManyRedirects { max, .. } => {
                obj.insert("max_redirects".into(), Value::Number((*max).into()));
            }
            Error::RobotsDenied(robots) => {
                obj.insert("robots".into(), robots.clone());
            }
            _ => {}
        }
        json!({ "error": Value::Object(obj) })
    }

    /// Compact JSON string of [`Error::to_json`].
    pub fn to_json_string(&self) -> String {
        self.to_json().to_string()
    }
}
