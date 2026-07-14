//! Canonical `ScrapeProof` wire types shared by the `basecrawl` engine (producer) and the
//! `relay` verifier (consumer).
//!
//! The struct field order defines the canonical JSON key order (serde serializes fields in
//! declaration order); map-valued fields use [`BTreeMap`] so their keys are also emitted in a
//! stable order. This is the single wire format for every SDK binding.
//!
//! Scope of this module at milestone M1: the non-attestation envelope. The `attestation` and
//! `sdk_signature` blocks are present as explicit-null placeholders that later milestones
//! populate with a real hardware quote and enclave signature.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Canonical schema version of the emitted [`ScrapeProof`].
pub const SCRAPE_PROOF_VERSION: u32 = 1;

/// The canonical, non-attestation ScrapeProof envelope emitted for a single scrape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrapeProof {
    /// Canonical schema version (always [`SCRAPE_PROOF_VERSION`]).
    pub version: u32,
    /// Validator-issued task id, echoed verbatim. Omitted when not supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Validator-issued anti-replay nonce, echoed verbatim. Omitted when not supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub request: Request,
    pub tls: Tls,
    pub response: Response,
    pub result: ResultBlock,
    pub egress: Egress,
    pub attestation: Attestation,
    pub sdk_signature: SdkSignature,
}

/// The request that was issued, including the requested output formats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers_hash: Option<String>,
    pub body_hash: Option<String>,
    /// SHA-256 over the canonical method, URL, request-headers digest, and body digest. This is
    /// the request-side binding later committed into attestation report data.
    pub request_hash: Option<String>,
    /// Requested formats in canonical (order-normalized) order.
    pub formats: Vec<String>,
}

/// Whether the certificate chain was verified before this TLS evidence was recorded.
///
/// Only [`CertificateValidation::Validated`] TLS 1.3 evidence is suitable for a normal
/// authenticity-capable proof. The explicit insecure diagnostic mode is intentionally carried on
/// the wire so it cannot be mistaken for a normally validated proof.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateValidation {
    /// No TLS session occurred, for example for a plain HTTP scrape.
    #[default]
    NotApplicable,
    /// The default WebPKI verifier accepted the peer certificate for the requested server name.
    Validated,
    /// The caller explicitly bypassed certificate verification for diagnostic purposes.
    InsecureDiagnostic,
}

/// In-process TLS termination capture. Populated by the TLS 1.3 capture layer; at M1 the fields
/// default to null/empty.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tls {
    pub certificate_validation: CertificateValidation,
    pub negotiated_version: Option<String>,
    pub sni: Option<String>,
    pub server_cert_chain_der: Vec<String>,
    pub cert_chain_hash: Option<String>,
    pub server_ephemeral_pubkey: Option<String>,
    pub ct_scts: Vec<String>,
    pub ocsp: Option<String>,
    pub handshake_transcript_hash: Option<String>,
}

/// The observed HTTP response envelope.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub status_code: Option<u16>,
    pub headers_hash: Option<String>,
    pub body_hash: Option<String>,
    pub content_length: Option<u64>,
    /// Terminal response `Content-Type` header. Format classification is derived from this value,
    /// never from the requested URL path or filename extension.
    pub content_type: Option<String>,
    /// True when the response body exceeded the configured max-body cap and only the initial
    /// `body_max_bytes` decoded bytes were retained.
    pub body_truncated: bool,
    /// Decoded response-body cap applied by the crawler for this proof.
    pub body_max_bytes: Option<u64>,
    /// Terminal URL the response was served from after following any redirect chain. Equals the
    /// requested URL when no redirect occurred.
    pub final_url: Option<String>,
    /// Ordered redirect hops followed to reach the terminal response, in the order they were
    /// followed. Empty when the request was served without a redirect.
    pub redirect_chain: Vec<RedirectHop>,
    /// Browser requests accepted while producing rendered outputs, including top-level documents.
    pub render_subresource_count: u64,
    /// Configured ceiling for accepted browser requests across the scrape.
    pub render_subresource_max_count: u64,
    /// Sum of actually observed browser-response bytes across the scrape.
    pub render_resource_bytes: u64,
    /// Configured aggregate browser-response byte ceiling.
    pub render_max_bytes: u64,
    /// True when a browser request or response exhausted an aggregate resource cap. Exhaustion
    /// fails the scrape before this response block can be emitted.
    pub render_resource_cap_exceeded: bool,
}

/// One hop in a followed HTTP redirect chain.
///
/// `url` is the resource that returned the redirect, `status_code` is the redirect status it
/// returned (a 3xx), and `location` is the absolute target that its `Location` header resolved to
/// (relative and cross-scheme `Location`s are resolved against `url` before being recorded).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedirectHop {
    pub status_code: u16,
    pub url: String,
    pub location: String,
}

/// The produced result surface: one entry per requested format plus the deterministic
/// canonicalization fields consumed by the completeness verifier.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResultBlock {
    /// Keyed by format name; value is the produced output (null until a format producer fills it).
    pub formats_produced: BTreeMap<String, Value>,
    pub result_hash: Option<String>,
    /// Structured, deterministic L4 evidence for every requested output format.
    pub completeness_manifest: CompletenessManifest,
    /// Reconciliation digest over `(request.url, nonce, result_hash)`.
    pub manifest_sha256: Option<String>,
    /// The ordered set of page URLs crawled when pagination following is enabled (page 1 first).
    /// Omitted when pagination was not followed, so a single-page scrape is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crawled_urls: Vec<String>,
}

/// Structured L4 completeness evidence for a scrape result.
///
/// The fixed fields make presence, byte size, and structural richness available to downstream
/// completeness grading without inspecting possibly large format values. `formats` is a
/// [`BTreeMap`] so its emitted key order is canonical and stable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletenessManifest {
    /// Schema version for forward-compatible L4 grading.
    pub version: u32,
    /// Number of formats requested for this scrape.
    pub requested_format_count: u64,
    /// Number of requested formats that were actually populated (not JSON null).
    pub present_format_count: u64,
    /// Per-format presence, canonical serialized byte size, and top-level structural field count.
    pub formats: BTreeMap<String, FormatCompleteness>,
}

impl Default for CompletenessManifest {
    fn default() -> Self {
        Self {
            version: 1,
            requested_format_count: 0,
            present_format_count: 0,
            formats: BTreeMap::new(),
        }
    }
}

/// Completeness evidence for one requested result format.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FormatCompleteness {
    pub requested: bool,
    pub present: bool,
    pub byte_size: u64,
    pub key_field_count: u64,
}

/// Finite egress proxy class vocabulary (VAL-PROXY-026..028).
///
/// Truthful emission only: the producer must set this from the **actual dial path**, never
/// from an arbitrary operator wish string that contradicts a direct/unproxied success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyClass {
    /// Origin dialed without an upstream commercial/mock proxy.
    Direct,
    Datacenter,
    Residential,
    Mobile,
}

impl ProxyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyClass::Direct => "direct",
            ProxyClass::Datacenter => "datacenter",
            ProxyClass::Residential => "residential",
            ProxyClass::Mobile => "mobile",
        }
    }

    /// Parse a documented class token. Rejects unknown strings so a forged class cannot slip
    /// through silently.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "direct" | "none" => Some(ProxyClass::Direct),
            "datacenter" | "dc" => Some(ProxyClass::Datacenter),
            "residential" | "res" => Some(ProxyClass::Residential),
            "mobile" => Some(ProxyClass::Mobile),
            _ => None,
        }
    }

    /// Classes that require a successful upstream proxy dial (cannot be claimed for direct egress).
    pub fn requires_upstream(self) -> bool {
        !matches!(self, ProxyClass::Direct)
    }
}

impl std::fmt::Display for ProxyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which public client identity path produced the scrape (VAL-STEALTH-001/002/010).
///
/// Hard / residential classes must emit [`FetchPath::Chromium`]. Soft targets may keep
/// [`FetchPath::Direct`] (rustls). Never invent a path that was not actually used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchPath {
    /// Soft rustls / direct HTTP(S) client without headless Chromium.
    Direct,
    /// Hard / residential / JS path that drives real headless Chromium.
    Chromium,
}

impl FetchPath {
    pub fn as_str(self) -> &'static str {
        match self {
            FetchPath::Direct => "direct",
            FetchPath::Chromium => "chromium",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "direct" | "soft" | "rustls" => Some(FetchPath::Direct),
            "chromium" | "browser" | "hard" | "chrome" => Some(FetchPath::Chromium),
            _ => None,
        }
    }
}

impl std::fmt::Display for FetchPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Network egress metadata (egress IP, geo landmark RTTs, timestamp, fingerprint seed).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Egress {
    pub egress_ip: Option<String>,
    pub landmark_rtts: BTreeMap<String, f64>,
    pub timestamp: Option<String>,
    pub fingerprint_seed: Option<String>,
    /// Actual egress proxy class of the dial path when known
    /// (`direct|datacenter|residential|mobile`). Omitted only when genuinely unknown; never set
    /// to a higher commercial class than what was dialed (VAL-PROXY-026..028).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_class: Option<ProxyClass>,
    /// Truthful client path used for the scrape. Hard/residential requests must report
    /// `chromium` rather than a soft-only identity (VAL-STEALTH-001/010).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_path: Option<FetchPath>,
    /// Soft-path TLS chrome-impersonate audit (VAL-UTLS-*). Present only when the soft rustls
    /// path applied a chrome-like ClientHello profile. Digests are labeled soft/synthetic/
    /// impersonate and must never be read as native Chromium wire/packet capture.
    /// Soft impersonate never implies `fetch_path=chromium` or residential class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_tls_impersonate: Option<SoftTlsImpersonateEgress>,
}

/// Soft-path chrome-impersonate audit fields, exclusive to rustls/direct `fetch_path`
/// (VAL-UTLS-003/006). Hard Chromium success does not carry these fields as a substitute for
/// real browser wire identity (VAL-UTLS-010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftTlsImpersonateEgress {
    /// Applied soft profile token (`chrome`).
    pub profile: String,
    /// Always a soft/synthetic/impersonate label (never native Chromium wire capture claim).
    pub ja_label: String,
    /// Soft synthetic JA3-family digest under the chrome-oriented domain.
    pub soft_ja3: String,
    /// Soft synthetic JA4-family digest under the chrome-oriented domain.
    pub soft_ja4: String,
}

/// Signed measurement registers carried by an Intel TDX TD10 report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TdxMeasurement {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

/// Hardware attestation block. At M1 every field is an explicit-null placeholder: no quote,
/// measurement, or report_data is produced before TEE integration (milestone M2).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    pub tee_type: Option<String>,
    pub quote: Option<String>,
    pub measurement: Option<TdxMeasurement>,
    pub report_data: Option<String>,
}

/// Enclave-held signature over the proof. At M1 both fields are explicit-null placeholders.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SdkSignature {
    pub enclave_pubkey: Option<String>,
    pub sig: Option<String>,
}

impl ScrapeProof {
    /// Serialize to the canonical compact JSON wire form (stable key order, no extra whitespace).
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).expect("ScrapeProof is always serializable")
    }

    /// Serialize the canonical proof surface that the enclave signs.
    ///
    /// A signature cannot include its own bytes in the signed message. The signature slot is
    /// therefore serialized as an explicit JSON `null`, while the enclave public key remains
    /// present and is separately committed to the hardware report data. Validators reconstruct
    /// these exact bytes before verifying `sdk_signature.sig`.
    pub fn to_canonical_signing_json(&self) -> String {
        let mut unsigned = self.clone();
        unsigned.sdk_signature.sig = None;
        unsigned.to_canonical_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScrapeProof {
        ScrapeProof {
            version: SCRAPE_PROOF_VERSION,
            task_id: None,
            nonce: None,
            request: Request {
                method: "GET".into(),
                url: "https://example.com/".into(),
                headers_hash: None,
                body_hash: None,
                request_hash: None,
                formats: vec!["markdown".into(), "metadata".into()],
            },
            tls: Tls::default(),
            response: Response::default(),
            result: ResultBlock {
                formats_produced: BTreeMap::new(),
                result_hash: None,
                completeness_manifest: CompletenessManifest::default(),
                manifest_sha256: None,
                crawled_urls: Vec::new(),
            },
            egress: Egress::default(),
            attestation: Attestation::default(),
            sdk_signature: SdkSignature::default(),
        }
    }

    #[test]
    fn version_serializes_as_integer_one() {
        let v: Value = serde_json::from_str(&sample().to_canonical_json()).unwrap();
        assert_eq!(v["version"], serde_json::json!(1));
        assert!(v["version"].is_u64());
    }

    #[test]
    fn task_id_and_nonce_omitted_when_absent() {
        let v: Value = serde_json::from_str(&sample().to_canonical_json()).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("task_id"));
        assert!(!obj.contains_key("nonce"));
    }

    #[test]
    fn task_id_and_nonce_present_when_supplied() {
        let mut p = sample();
        p.task_id = Some("T123".into());
        p.nonce = Some("N456".into());
        let v: Value = serde_json::from_str(&p.to_canonical_json()).unwrap();
        assert_eq!(v["task_id"], "T123");
        assert_eq!(v["nonce"], "N456");
    }

    #[test]
    fn attestation_and_signature_are_explicit_null_placeholders() {
        let v: Value = serde_json::from_str(&sample().to_canonical_json()).unwrap();
        assert!(v["attestation"].is_object());
        assert!(v["attestation"]["quote"].is_null());
        assert!(v["attestation"]["measurement"].is_null());
        assert!(v["attestation"]["report_data"].is_null());
        assert!(v["sdk_signature"]["sig"].is_null());
    }

    #[test]
    fn populated_tdx_attestation_roundtrips_losslessly() {
        let mut proof = sample();
        proof.attestation = Attestation {
            tee_type: Some("tdx".into()),
            quote: Some("04aabbcc".into()),
            measurement: Some(TdxMeasurement {
                mrtd: "11".repeat(48),
                rtmr0: "22".repeat(48),
                rtmr1: "33".repeat(48),
                rtmr2: "44".repeat(48),
                rtmr3: "55".repeat(48),
            }),
            report_data: Some("66".repeat(64)),
        };

        let serialized = proof.to_canonical_json();
        let roundtripped: ScrapeProof = serde_json::from_str(&serialized).unwrap();

        assert_eq!(roundtripped, proof);
        let value: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(value["attestation"]["tee_type"], "tdx");
        assert_eq!(value["attestation"]["measurement"]["mrtd"], "11".repeat(48));
        assert_eq!(
            value["attestation"]["measurement"]["rtmr3"],
            "55".repeat(48)
        );
    }

    #[test]
    fn crawled_urls_omitted_when_empty_and_present_when_set() {
        let v: Value = serde_json::from_str(&sample().to_canonical_json()).unwrap();
        assert!(
            !v["result"]
                .as_object()
                .unwrap()
                .contains_key("crawled_urls"),
            "crawled_urls must be omitted for a single-page scrape"
        );

        let mut p = sample();
        p.result.crawled_urls = vec!["https://a/".into(), "https://a/page-2".into()];
        let v: Value = serde_json::from_str(&p.to_canonical_json()).unwrap();
        assert_eq!(v["result"]["crawled_urls"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn top_level_blocks_are_objects() {
        let v: Value = serde_json::from_str(&sample().to_canonical_json()).unwrap();
        for key in ["request", "tls", "response", "result", "egress"] {
            assert!(v[key].is_object(), "{key} must serialize to a JSON object");
        }
    }

    #[test]
    fn canonical_json_is_stable_across_runs() {
        assert_eq!(sample().to_canonical_json(), sample().to_canonical_json());
    }

    #[test]
    fn signing_json_excludes_only_signature_bytes() {
        let mut proof = sample();
        proof.sdk_signature.enclave_pubkey = Some("11".repeat(32));
        proof.sdk_signature.sig = Some("22".repeat(64));
        let value: Value = serde_json::from_str(&proof.to_canonical_signing_json()).unwrap();
        assert_eq!(value["sdk_signature"]["enclave_pubkey"], "11".repeat(32));
        assert!(value["sdk_signature"]["sig"].is_null());
    }

    #[test]
    fn canonical_json_includes_structured_completeness_and_digest_slots() {
        let serialized = sample().to_canonical_json();
        let value: Value = serde_json::from_str(&serialized).unwrap();

        assert!(value["request"]["request_hash"].is_null());
        assert_eq!(value["result"]["completeness_manifest"]["version"], 1);
        assert_eq!(
            value["result"]["completeness_manifest"]["requested_format_count"],
            0
        );
        assert!(
            value["result"]["completeness_manifest"]["formats"].is_object(),
            "manifest formats must use a stable keyed object"
        );
        assert!(value["result"]["manifest_sha256"].is_null());

        for key in [
            "\"formats_produced\"",
            "\"result_hash\"",
            "\"completeness_manifest\"",
            "\"manifest_sha256\"",
        ] {
            assert!(
                serialized.contains(key),
                "canonical JSON must expose key {key}: {serialized}"
            );
        }
    }

    #[test]
    fn roundtrips_through_serde() {
        let p = sample();
        let json = p.to_canonical_json();
        let back: ScrapeProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn response_exposes_final_url_and_empty_redirect_chain_by_default() {
        let v: Value = serde_json::from_str(&sample().to_canonical_json()).unwrap();
        assert!(v["response"]["final_url"].is_null());
        assert!(
            v["response"]["redirect_chain"].is_array(),
            "redirect_chain must serialize as an array"
        );
        assert_eq!(v["response"]["redirect_chain"].as_array().unwrap().len(), 0);
        assert_eq!(v["response"]["render_subresource_count"], 0);
        assert_eq!(v["response"]["render_resource_cap_exceeded"], false);
    }

    #[test]
    fn redirect_hops_serialize_with_status_url_and_location() {
        let mut p = sample();
        p.response.final_url = Some("https://example.com/final".into());
        p.response.redirect_chain = vec![RedirectHop {
            status_code: 302,
            url: "https://example.com/start".into(),
            location: "https://example.com/final".into(),
        }];
        let v: Value = serde_json::from_str(&p.to_canonical_json()).unwrap();
        let hop = &v["response"]["redirect_chain"][0];
        assert_eq!(hop["status_code"], 302);
        assert_eq!(hop["url"], "https://example.com/start");
        assert_eq!(hop["location"], "https://example.com/final");
        assert_eq!(v["response"]["final_url"], "https://example.com/final");
    }
}
