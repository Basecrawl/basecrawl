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

/// In-process TLS termination capture. Populated by the TLS 1.3 capture layer; at M1 the fields
/// default to null/empty.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tls {
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
    /// Terminal URL the response was served from after following any redirect chain. Equals the
    /// requested URL when no redirect occurred.
    pub final_url: Option<String>,
    /// Ordered redirect hops followed to reach the terminal response, in the order they were
    /// followed. Empty when the request was served without a redirect.
    pub redirect_chain: Vec<RedirectHop>,
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

/// Network egress metadata (egress IP, geo landmark RTTs, timestamp, fingerprint seed).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Egress {
    pub egress_ip: Option<String>,
    pub landmark_rtts: BTreeMap<String, f64>,
    pub timestamp: Option<String>,
    pub fingerprint_seed: Option<String>,
}

/// Hardware attestation block. At M1 every field is an explicit-null placeholder: no quote,
/// measurement, or report_data is produced before TEE integration (milestone M2).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    pub tee_type: Option<String>,
    pub quote: Option<String>,
    pub measurement: Option<Value>,
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
