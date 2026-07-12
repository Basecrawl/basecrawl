//! Enclave-attested RTT echo endpoint + validator/enclave RTT cross-check.
//!
//! Validator landmark servers probe the enclave's echo endpoint with a fresh
//! nonce. The response is an Ed25519 signature over a domain-tagged payload
//! (`RTT_ECHO_DOMAIN_TAG || nonce`) produced by the enclave-held key that is
//! also committed in ScrapeProof `report_data` / `sdk_signature.enclave_pubkey`.
//!
//! A co-located puppet that merely echoes the nonce (or signs with any key
//! other than the attested one) is rejected and never lowers the measured
//! distance (VAL-GEO-030). The enclave also records its own landmark RTTs into
//! `ScrapeProof.egress.landmark_rtts` so the validator can cross-check them
//! against independent measurements (VAL-GEO-009).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

/// Domain-separation tag for RTT-echo signatures. Distinct from the ScrapeProof
/// attestation tag and every other basecrawl report_data construction.
pub const RTT_ECHO_DOMAIN_TAG: &[u8] = b"basecrawl/rtt-echo/v1\0";

/// Build the exact byte sequence signed for an RTT probe nonce.
pub fn echo_signing_payload(nonce: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(RTT_ECHO_DOMAIN_TAG.len() + nonce.len());
    payload.extend_from_slice(RTT_ECHO_DOMAIN_TAG);
    payload.extend_from_slice(nonce.as_bytes());
    payload
}

/// JSON body returned by the attested RTT echo endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EchoResponse {
    /// Fresh nonce echoed verbatim.
    pub nonce: String,
    /// Lowercase hex Ed25519 signature over [`echo_signing_payload`].
    #[serde(default)]
    pub signature: String,
    /// Lowercase hex 32-byte public key that produced `signature`.
    /// Must equal the enclave key committed in report_data for acceptance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclave_pubkey: Option<String>,
}

/// Failure modes when validating an echo against the attested enclave key.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EchoValidationFailure {
    #[error("RTT echo nonce mismatch")]
    NonceMismatch,
    #[error("RTT echo is missing a signature")]
    MissingSignature,
    #[error("RTT echo is missing an enclave public key")]
    MissingPubkey,
    #[error("RTT echo public key is not the attested enclave key")]
    PubkeyMismatch,
    #[error("RTT echo signature is invalid for the attested enclave key")]
    InvalidSignature,
    #[error("RTT echo public key encoding is invalid")]
    MalformedPubkey,
    #[error("RTT echo signature encoding is invalid")]
    MalformedSignature,
    #[error("RTT echo itself is empty")]
    EmptyResponse,
}

/// Something that can produce an enclave-authenticated RTT echo signature.
pub trait EchoSigner: Send + Sync {
    fn public_key_hex(&self) -> String;
    fn sign_echo_payload(&self, payload: &[u8]) -> Result<String, EchoSignError>;
}

/// Dev / in-process enclave key (Ed25519). Production wire uses
/// [`GuestAgentEchoSigner`] which delegates to the dstack `/Sign` endpoint.
#[derive(Clone)]
pub struct LocalEchoSigner {
    key: SigningKey,
}

impl LocalEchoSigner {
    pub fn from_seed(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
        }
    }

    pub fn from_bytes(secret: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&secret),
        }
    }
}

impl EchoSigner for LocalEchoSigner {
    fn public_key_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    fn sign_echo_payload(&self, payload: &[u8]) -> Result<String, EchoSignError> {
        if payload.is_empty() {
            return Err(EchoSignError::EmptyPayload);
        }
        let sig = self.key.sign(payload);
        Ok(hex_encode(&sig.to_bytes()))
    }
}

/// Alias used by VAL-GEO-030 tests for a co-located unattested responder.
pub type PuppetEchoSigner = LocalEchoSigner;

/// Sign via the mounted dstack guest agent so the key matches the
/// report_data-committed enclave_pubkey in a real CVM.
pub struct GuestAgentEchoSigner {
    socket_path: std::path::PathBuf,
    cached_pubkey: std::sync::Mutex<Option<String>>,
}

impl GuestAgentEchoSigner {
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            cached_pubkey: std::sync::Mutex::new(None),
        }
    }

    pub fn default_socket() -> Self {
        Self::new(crate::attestation::DEFAULT_DSTACK_SOCKET)
    }
}

impl EchoSigner for GuestAgentEchoSigner {
    fn public_key_hex(&self) -> String {
        if let Ok(guard) = self.cached_pubkey.lock() {
            if let Some(pk) = guard.as_ref() {
                return pk.clone();
            }
        }
        // Discover the key by signing a fixed domain-tagged probe (same pattern as scrape).
        match crate::attestation::sign_at(&self.socket_path, b"basecrawl/enclave-signing-key/v1") {
            Ok(resp) => {
                if let Ok(mut guard) = self.cached_pubkey.lock() {
                    *guard = Some(resp.public_key.clone());
                }
                resp.public_key
            }
            Err(_) => String::new(),
        }
    }

    fn sign_echo_payload(&self, payload: &[u8]) -> Result<String, EchoSignError> {
        let resp = crate::attestation::sign_at(&self.socket_path, payload)
            .map_err(|e| EchoSignError::GuestAgent(e.to_string()))?;
        if let Ok(mut guard) = self.cached_pubkey.lock() {
            *guard = Some(resp.public_key.clone());
        }
        Ok(resp.signature)
    }
}

#[derive(Debug, Error)]
pub enum EchoSignError {
    #[error("RTT echo payload is empty")]
    EmptyPayload,
    #[error("guest-agent signing failed: {0}")]
    GuestAgent(String),
}

/// Sign a probe nonce with an [`EchoSigner`], producing a complete [`EchoResponse`].
pub fn sign_echo_with(
    signer: &(impl EchoSigner + ?Sized),
    nonce: &str,
) -> Result<EchoResponse, EchoSignError> {
    if nonce.is_empty() {
        return Err(EchoSignError::EmptyPayload);
    }
    let payload = echo_signing_payload(nonce);
    let signature = signer.sign_echo_payload(&payload)?;
    Ok(EchoResponse {
        nonce: nonce.to_string(),
        signature,
        enclave_pubkey: Some(signer.public_key_hex()),
    })
}

/// Convenience for the HTTP handler layer.
pub fn handle_echo_request(
    signer: &(impl EchoSigner + ?Sized),
    nonce: &str,
) -> Result<EchoResponse, EchoSignError> {
    sign_echo_with(signer, nonce)
}

/// Verify that `response` is an attestation-bound echo of `expected_nonce`
/// under the enclave pubkey committed in report_data.
pub fn verify_echo_response(
    response: &EchoResponse,
    attested_enclave_pubkey_hex: &str,
    expected_nonce: &str,
) -> Result<(), EchoValidationFailure> {
    if expected_nonce.is_empty() || response.nonce.is_empty() {
        return Err(EchoValidationFailure::EmptyResponse);
    }
    if response.nonce != expected_nonce {
        return Err(EchoValidationFailure::NonceMismatch);
    }
    if response.signature.is_empty() {
        return Err(EchoValidationFailure::MissingSignature);
    }
    let Some(response_pk) = response.enclave_pubkey.as_deref() else {
        return Err(EchoValidationFailure::MissingPubkey);
    };
    if !hex_eq_ignore_case(response_pk, attested_enclave_pubkey_hex) {
        return Err(EchoValidationFailure::PubkeyMismatch);
    }
    let public_key =
        decode_hex_32(attested_enclave_pubkey_hex).ok_or(EchoValidationFailure::MalformedPubkey)?;
    let signature =
        decode_hex_64(&response.signature).ok_or(EchoValidationFailure::MalformedSignature)?;
    let verifying = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| EchoValidationFailure::MalformedPubkey)?;
    let sig = Signature::from_bytes(&signature);
    let payload = echo_signing_payload(expected_nonce);
    verifying
        .verify(&payload, &sig)
        .map_err(|_| EchoValidationFailure::InvalidSignature)?;
    Ok(())
}

/// Bind a validator-measured RTT to a verified echo. Failures return the
/// validation error so a puppet / stale / unsigned echo cannot lower distance.
pub fn accept_echo_for_rtt(
    response: &EchoResponse,
    attested_enclave_pubkey_hex: &str,
    expected_nonce: &str,
    measured_rtt_ms: f64,
) -> Result<f64, EchoValidationFailure> {
    verify_echo_response(response, attested_enclave_pubkey_hex, expected_nonce)?;
    Ok(if measured_rtt_ms < 0.0 {
        0.0
    } else {
        measured_rtt_ms
    })
}

// ---------------------------------------------------------------------------
// HTTP echo server (dev / in-CVM)
// ---------------------------------------------------------------------------

/// Live loopback (or bind) HTTP server that answers `GET /echo?nonce=...` with
/// a signed JSON [`EchoResponse`].
pub struct EchoServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl EchoServer {
    pub fn base_url(&self) -> String {
        format!("http://{}/echo", self.addr)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Wake the accept loop with a self-connect.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

/// Start a signed RTT-echo endpoint bound to `127.0.0.1:0`.
pub fn start_echo_server(signer: impl EchoSigner + 'static) -> Result<EchoServer, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(false)?;
    let addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let join = thread::spawn(move || {
        let signer = Arc::new(signer);
        while !flag.load(Ordering::SeqCst) {
            // Short accept timeout so Drop can exit cleanly.
            let _ = listener.set_nonblocking(true);
            match listener.accept() {
                Ok((stream, _)) => {
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }
                    let signer = Arc::clone(&signer);
                    // Handle one request; ignore write/read errors.
                    let _ = handle_http_connection(stream, signer.as_ref());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    Ok(EchoServer {
        addr,
        shutdown,
        join: Some(join),
    })
}

fn handle_http_connection(mut stream: TcpStream, signer: &dyn EchoSigner) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");
    let (path_only, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };
    if path_only.trim_end_matches('/') != "/echo" {
        write_http(
            &mut stream,
            404,
            "application/json",
            br#"{"error":"not_found"}"#,
        )?;
        return Ok(());
    }
    let nonce = query
        .split('&')
        .find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let k = parts.next()?;
            let v = parts.next().unwrap_or("");
            if k == "nonce" {
                Some(percent_decode(v))
            } else {
                None
            }
        })
        .unwrap_or_default();
    if nonce.is_empty() {
        write_http(
            &mut stream,
            400,
            "application/json",
            br#"{"error":"missing_nonce"}"#,
        )?;
        return Ok(());
    }
    match sign_echo_with(signer, &nonce) {
        Ok(response) => {
            let body = serde_json::to_vec(&response)
                .unwrap_or_else(|_| br#"{"error":"serialize"}"#.to_vec());
            write_http(&mut stream, 200, "application/json", &body)?;
        }
        Err(_) => {
            write_http(
                &mut stream,
                500,
                "application/json",
                br#"{"error":"sign_failed"}"#,
            )?;
        }
    }
    Ok(())
}

fn write_http(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn percent_decode(input: &str) -> String {
    // Minimal decode for token_urlsafe / hex nonces (percent-encoded '=/+' rare).
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) =
                (from_hex_nibble(bytes[i + 1]), from_hex_nibble(bytes[i + 2]))
            {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Enclave → landmark probing (self-reported RTTs)
// ---------------------------------------------------------------------------

/// One landmark target the enclave measurements against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandmarkProbeTarget {
    pub landmark_id: String,
    pub echo_url: String,
}

/// One enclave-recorded landmark RTT measurement.
#[derive(Debug, Clone, PartialEq)]
pub struct LandmarkMeasurement {
    pub landmark_id: String,
    pub rtt_ms: f64,
}

#[derive(Debug, Error)]
pub enum LandmarkProbeError {
    #[error("landmark probe failed for {landmark}: {detail}")]
    Transport { landmark: String, detail: String },
}

/// Measure RTTs from the enclave to each landmark target (client-side wall clock).
///
/// Each probe issues a fresh 256-bit nonce so the landmark (or the enclave's own
/// echo fixture) must return that nonce before the measurement is recorded. The
/// resulting RTTs are what populates `ScrapeProof.egress.landmark_rtts`.
pub fn probe_landmarks(
    targets: &[LandmarkProbeTarget],
    timeout: Duration,
) -> Result<Vec<LandmarkMeasurement>, LandmarkProbeError> {
    let mut out = Vec::with_capacity(targets.len());
    for target in targets {
        let nonce = fresh_probe_nonce();
        let (echoed, rtt_ms) =
            http_echo_round_trip(&target.echo_url, &nonce, timeout).map_err(|detail| {
                LandmarkProbeError::Transport {
                    landmark: target.landmark_id.clone(),
                    detail,
                }
            })?;
        // Require verbatim nonce. For enclave self-report we accept signed OR
        // plain echo of the nonce (validator-side landmarks typically plain-respond;
        // the enclave is measuring TO them, not proving itself).
        if echoed.as_deref() != Some(nonce.as_str()) {
            return Err(LandmarkProbeError::Transport {
                landmark: target.landmark_id.clone(),
                detail: format!("landmark did not echo probe nonce (got {:?})", echoed),
            });
        }
        out.push(LandmarkMeasurement {
            landmark_id: target.landmark_id.clone(),
            rtt_ms,
        });
    }
    Ok(out)
}

fn fresh_probe_nonce() -> String {
    // 32 crypto-random bytes as base64url without padding (matches relay probe shape).
    let mut bytes = [0u8; 32];
    getrandom_fill(&mut bytes);
    base64url_nopad(&bytes)
}

fn getrandom_fill(buf: &mut [u8]) {
    // Prefer OS-provided randomness (getrandom via std); fall back is deterministic
    // only for unreachable paths in sandboxed unit tests without /dev/urandom.
    use std::fs::File;
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    // Time-derived last resort so tests still produce distinct nonces.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((nanos >> ((i % 16) * 8)) as u8).wrapping_add(i as u8);
    }
}

fn base64url_nopad(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    if i < bytes.len() {
        let rem = bytes.len() - i;
        let b0 = bytes[i] as u32;
        let b1 = if rem > 1 { bytes[i + 1] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if rem == 2 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
    }
    out
}

fn http_echo_round_trip(
    echo_url: &str,
    nonce: &str,
    timeout: Duration,
) -> Result<(Option<String>, f64), String> {
    let parsed = Url::parse(echo_url).map_err(|e| e.to_string())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "echo URL missing host".to_string())?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "echo URL missing port".to_string())?;
    let mut url = parsed.clone();
    {
        let mut qp = url.query_pairs_mut();
        // Preserve existing query, force the probe nonce.
        // Full rebuild is fine.
        qp.clear();
        for (k, v) in parsed.query_pairs() {
            if k != "nonce" {
                qp.append_pair(&k, &v);
            }
        }
        qp.append_pair("nonce", nonce);
    }
    let path = if let Some(q) = url.query() {
        format!("{}?{}", url.path(), q)
    } else {
        url.path().to_string()
    };

    let start = Instant::now();
    let mut stream = TcpStream::connect((host.as_str(), port)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
    let text = String::from_utf8_lossy(&raw);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    let echoed = extract_echoed_nonce(body);
    Ok((echoed, rtt_ms))
}

fn extract_echoed_nonce(body: &str) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(obj) = value.as_object() {
            if let Some(n) = obj.get("nonce").and_then(|v| v.as_str()) {
                return Some(n.to_string());
            }
        }
        if let Some(s) = value.as_str() {
            return Some(s.to_string());
        }
    }
    Some(body.to_string())
}

// ---------------------------------------------------------------------------
// VAL-GEO-009 consistency cross-check
// ---------------------------------------------------------------------------

/// Tolerances for comparing enclave self-reported RTTs vs validator measurements.
#[derive(Debug, Clone, Copy)]
pub struct RttConsistencyConfig {
    /// Absolute slack (ms) allowed between the two observations.
    pub absolute_tolerance_ms: f64,
    /// Relative slack: `self_rtt` may be at most `validator * (1 + relative)`
    /// when checking the *upper* band, and no more than
    /// `max(absolute, validator * relative)` *faster* than the validator
    /// floor (faster-than-physics rejection).
    pub relative_tolerance: f64,
}

impl Default for RttConsistencyConfig {
    fn default() -> Self {
        Self {
            absolute_tolerance_ms: 50.0,
            relative_tolerance: 0.5,
        }
    }
}

/// Validator-side outcome of comparing self-reported landmark RTTs.
#[derive(Debug, Clone, PartialEq)]
pub enum CrossCheckVerdict {
    Consistent {
        checked: usize,
    },
    /// Self-report claims a substantially lower RTT than the independently
    /// measured floor — treated as a faster-than-physics forgery.
    RejectedFasterThanPhysics {
        landmark: String,
        self_rtt_ms: f64,
        validator_rtt_ms: f64,
    },
    /// Self-report is present for a landmark the validator never measured
    /// (or vice-versa when required). Flagged rather than trusted.
    MissingLandmark {
        landmark: String,
    },
    /// Empty comparison — nothing to check.
    NoData,
}

/// Cross-check enclave self-reported RTTs against independent validator measurements.
///
/// A self-report that is *faster* than the validator floor by more than the
/// configured tolerance is [`CrossCheckVerdict::RejectedFasterThanPhysics`]
/// and must never be trusted for geo placement (VAL-GEO-009). Self-reports that
/// are merely slower are tolerated: an attacker can only add delay.
pub fn cross_check_landmark_rtts(
    self_reported: &BTreeMap<String, f64>,
    validator_measured: &BTreeMap<String, f64>,
    config: &RttConsistencyConfig,
) -> CrossCheckVerdict {
    if self_reported.is_empty() && validator_measured.is_empty() {
        return CrossCheckVerdict::NoData;
    }
    let mut checked = 0usize;
    for (landmark, &self_rtt) in self_reported {
        let Some(&validator_rtt) = validator_measured.get(landmark) else {
            return CrossCheckVerdict::MissingLandmark {
                landmark: landmark.clone(),
            };
        };
        let floor = validator_rtt;
        // Allowed under-run of the floor (self can be a little faster due to
        // jitter / measurement noise, but not substantially).
        let max_under = config
            .absolute_tolerance_ms
            .max(floor * config.relative_tolerance);
        if self_rtt + max_under < floor {
            return CrossCheckVerdict::RejectedFasterThanPhysics {
                landmark: landmark.clone(),
                self_rtt_ms: self_rtt,
                validator_rtt_ms: validator_rtt,
            };
        }
        checked += 1;
    }
    if checked == 0 {
        return CrossCheckVerdict::NoData;
    }
    CrossCheckVerdict::Consistent { checked }
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(from_nibble(b >> 4));
        out.push(from_nibble(b & 0x0f));
    }
    out
}

fn from_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '0',
    }
}

fn from_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex(hex)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_hex_64(hex: &str) -> Option<[u8; 64]> {
    let bytes = decode_hex(hex)?;
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex_nibble(bytes[i])?;
        let lo = from_hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn local_signer_round_trip() {
        let signer = LocalEchoSigner::from_seed(1);
        let resp = sign_echo_with(&signer, "n").unwrap();
        verify_echo_response(&resp, &signer.public_key_hex(), "n").unwrap();
    }

    #[test]
    fn faster_than_physics_rejects() {
        let self_r = BTreeMap::from([("paris".into(), 1.0)]);
        let val = BTreeMap::from([("paris".into(), 100.0)]);
        let v = cross_check_landmark_rtts(
            &self_r,
            &val,
            &RttConsistencyConfig {
                absolute_tolerance_ms: 5.0,
                relative_tolerance: 0.1,
            },
        );
        assert!(matches!(
            v,
            CrossCheckVerdict::RejectedFasterThanPhysics { .. }
        ));
    }
}
