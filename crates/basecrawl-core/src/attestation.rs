//! dstack guest-agent quote requests.
//!
//! The guest agent owns the TDX signing key.  This module only marshals a report-data request
//! over the mounted Unix socket and validates the signed response shape.  It never constructs a
//! quote locally, and it fails closed when the socket or any required response field is missing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// The dstack socket mounted by the Phala CVM image.
pub const DEFAULT_DSTACK_SOCKET: &str = "/var/run/dstack.sock";

/// A TDX quote is at least a v4 header, TD10 report, and signature-length field.  Real quotes
/// include certification data and are substantially larger, but this lower bound rejects
/// hand-assembled/truncated values before they can be emitted as an attestation.
pub const MIN_QUOTE_HEX_LEN: usize = (48 + 520 + 64) * 2;
const QUOTE_HEADER_BYTES: usize = 48;
const TD_REPORT_DATA_OFFSET: usize = 520;
const TD_REPORT_DATA_BYTES: usize = 64;
const QUOTE_VERSION: u16 = 4;
const TDX_TEE_TYPE: u32 = 0x81;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum QuoteRequestError {
    #[error("dstack report_data must contain at least one hexadecimal byte")]
    EmptyReportData,

    #[error("dstack report_data is not valid hexadecimal")]
    InvalidReportData,

    #[error("dstack guest-agent socket {path} is unavailable: {source}")]
    SocketUnavailable {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("dstack guest-agent request failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("dstack guest-agent returned HTTP status {status}")]
    HttpStatus { status: u16 },

    #[error("dstack guest-agent returned malformed JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("dstack guest-agent response is missing a non-empty {0}")]
    MissingField(&'static str),

    #[error("dstack quote is not hexadecimal")]
    InvalidQuote,

    #[error("dstack quote is truncated: got {actual} hex characters, need at least {minimum}")]
    QuoteTooShort { actual: usize, minimum: usize },

    #[error("dstack quote is not an Intel TDX v4 quote")]
    InvalidQuoteHeader,

    #[error("dstack quote report_data does not match the guest-agent response")]
    QuoteReportDataMismatch,

    #[error("dstack guest-agent report_data mismatch: submitted {submitted}, returned {returned}")]
    ReportDataMismatch { submitted: String, returned: String },
}

/// The complete response returned by `POST /GetQuote`.
///
/// `event_log` and `vm_config` are retained as JSON values because dstack versions may evolve
/// their nested representation.  They remain part of the wire response and are not discarded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuoteResponse {
    pub quote: String,
    pub event_log: Value,
    pub report_data: String,
    pub vm_config: Value,
}

/// The signed measurements carried by a v4 TDX TD10 report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuoteMeasurement {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

impl QuoteResponse {
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).expect("QuoteResponse is always serializable")
    }
}

/// Decode the TD10 measurement registers from a validated quote.
pub fn quote_measurement(quote_hex: &str) -> Result<QuoteMeasurement, QuoteRequestError> {
    let quote = decode_hex(quote_hex).ok_or(QuoteRequestError::InvalidQuote)?;
    if quote.len() < QUOTE_HEADER_BYTES + 520 {
        return Err(QuoteRequestError::QuoteTooShort {
            actual: quote_hex.len(),
            minimum: MIN_QUOTE_HEX_LEN,
        });
    }
    Ok(QuoteMeasurement {
        mrtd: encode_hex(&quote[48 + 136..48 + 184]),
        rtmr0: encode_hex(&quote[48 + 328..48 + 376]),
        rtmr1: encode_hex(&quote[48 + 376..48 + 424]),
        rtmr2: encode_hex(&quote[48 + 424..48 + 472]),
        rtmr3: encode_hex(&quote[48 + 472..48 + 520]),
    })
}

/// Recover the full 64-byte report data embedded in a TDX v4 TD10 quote.
///
/// Callers use this value, rather than trusting a free-floating JSON field, when checking that a
/// quote carries the expected ScrapeProof binding.
pub fn quote_report_data(quote_hex: &str) -> Result<String, QuoteRequestError> {
    let quote = decode_hex(quote_hex).ok_or(QuoteRequestError::InvalidQuote)?;
    if quote.len() < QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET + TD_REPORT_DATA_BYTES {
        return Err(QuoteRequestError::QuoteTooShort {
            actual: quote_hex.len(),
            minimum: MIN_QUOTE_HEX_LEN,
        });
    }
    if u16::from_le_bytes([quote[0], quote[1]]) != QUOTE_VERSION
        || u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]) != TDX_TEE_TYPE
    {
        return Err(QuoteRequestError::InvalidQuoteHeader);
    }
    Ok(encode_hex(
        &quote[QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET
            ..QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET + TD_REPORT_DATA_BYTES],
    ))
}

/// Request a quote from the production dstack socket.
pub fn get_quote(report_data: &str) -> Result<QuoteResponse, QuoteRequestError> {
    get_quote_at(Path::new(DEFAULT_DSTACK_SOCKET), report_data)
}

/// Request a quote from an explicit socket path.
///
/// The path override is useful for deterministic unit tests.  Production callers should use
/// [`get_quote`], which is fixed to the CVM guest-agent mount.
pub fn get_quote_at(
    socket_path: &Path,
    report_data: &str,
) -> Result<QuoteResponse, QuoteRequestError> {
    let normalized_report_data = normalize_report_data(report_data)?;
    let body = serde_json::json!({ "report_data": normalized_report_data }).to_string();
    let mut stream = UnixStream::connect(socket_path).map_err(|source| {
        QuoteRequestError::SocketUnavailable {
            path: socket_path.to_path_buf(),
            source,
        }
    })?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    let request = format!(
        "POST /GetQuote HTTP/1.1\r\nHost: dstack\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let (status, response_body) = parse_http_response(&response)?;
    if status != 200 {
        return Err(QuoteRequestError::HttpStatus { status });
    }
    let value: QuoteResponse = serde_json::from_slice(response_body)?;
    validate_quote_response(value, &normalized_report_data)
}

fn normalize_report_data(input: &str) -> Result<String, QuoteRequestError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(QuoteRequestError::EmptyReportData);
    }
    if !input.len().is_multiple_of(2) || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(QuoteRequestError::InvalidReportData);
    }
    let input_bytes = decode_hex(input).ok_or(QuoteRequestError::InvalidReportData)?;
    let normalized = if input_bytes.len() > TD_REPORT_DATA_BYTES {
        use sha2::{Digest, Sha256};
        Sha256::digest(input_bytes).to_vec()
    } else {
        let mut padded = vec![0_u8; TD_REPORT_DATA_BYTES];
        padded[..input_bytes.len()].copy_from_slice(&input_bytes);
        padded
    };
    Ok(encode_hex(&normalized))
}

fn validate_quote_response(
    mut response: QuoteResponse,
    expected_report_data: &str,
) -> Result<QuoteResponse, QuoteRequestError> {
    if response.quote.is_empty() {
        return Err(QuoteRequestError::MissingField("quote"));
    }
    if response.event_log.is_null() || is_empty_json(&response.event_log) {
        return Err(QuoteRequestError::MissingField("event_log"));
    }
    if response.vm_config.is_null() || is_empty_json(&response.vm_config) {
        return Err(QuoteRequestError::MissingField("vm_config"));
    }
    let quote = decode_hex(&response.quote).ok_or(QuoteRequestError::InvalidQuote)?;
    let quote_hex_len = response.quote.len();
    if quote_hex_len < MIN_QUOTE_HEX_LEN {
        return Err(QuoteRequestError::QuoteTooShort {
            actual: quote_hex_len,
            minimum: MIN_QUOTE_HEX_LEN,
        });
    }
    if quote.len() < QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET + TD_REPORT_DATA_BYTES
        || u16::from_le_bytes([quote[0], quote[1]]) != QUOTE_VERSION
        || u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]) != TDX_TEE_TYPE
    {
        return Err(QuoteRequestError::InvalidQuoteHeader);
    }
    let embedded_report_data = quote_report_data(&response.quote)?;
    response.quote = encode_hex(&quote);
    response.report_data = response.report_data.to_ascii_lowercase();
    if response.report_data != expected_report_data {
        return Err(QuoteRequestError::ReportDataMismatch {
            submitted: expected_report_data.to_string(),
            returned: response.report_data,
        });
    }
    if embedded_report_data != expected_report_data {
        return Err(QuoteRequestError::QuoteReportDataMismatch);
    }
    Ok(response)
}

fn is_empty_json(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.is_empty(),
        Value::Object(values) => values.is_empty(),
        Value::String(value) => value.is_empty(),
        _ => false,
    }
}

fn parse_http_response(response: &[u8]) -> Result<(u16, &[u8]), QuoteRequestError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| QuoteRequestError::Io(std::io::Error::other("missing HTTP headers")))?;
    let headers = &response[..header_end];
    let body = &response[header_end + 4..];
    let status_line_end = headers
        .iter()
        .position(|byte| *byte == b'\r')
        .ok_or_else(|| QuoteRequestError::Io(std::io::Error::other("missing HTTP status")))?;
    let status_line = std::str::from_utf8(&headers[..status_line_end])
        .map_err(|_| QuoteRequestError::Io(std::io::Error::other("invalid HTTP status")))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| QuoteRequestError::Io(std::io::Error::other("invalid HTTP status")))?;
    Ok((status, body))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
