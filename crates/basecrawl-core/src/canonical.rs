//! Canonical result-surface hashing.
//!
//! `result_hash` is the byte-quorum digest two honest miners must agree on for a canary. Per
//! architecture §5.4 it covers only the **deterministic** result surface
//! (`markdown`/`html`/`rawHtml`/`links`/`metadata`) and deliberately **excludes** `screenshot`
//! and `json`/`extract`, which are non-deterministic (pixel rendering) or LLM-optional and would
//! otherwise destabilize the quorum. It also owns the deterministic request, completeness, and
//! reconciliation digests that bind the M1 ScrapeProof surface without including volatile egress
//! values.

use basecrawl_proof::{CompletenessManifest, FormatCompleteness, ScrapeProof};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use thiserror::Error;

/// Result formats that contribute to the deterministic quorum surface, in canonical order.
/// `screenshot` and `json` are intentionally absent (see module docs).
pub const DETERMINISTIC_FORMATS: &[&str] = &["markdown", "html", "rawHtml", "links", "metadata"];

/// Schema version emitted in [`CompletenessManifest`].
pub const COMPLETENESS_MANIFEST_VERSION: u32 = 1;

/// Domain separation for the ScrapeProof hardware-attestation binding.
pub const ATTESTATION_DOMAIN_TAG: &[u8] = b"basecrawl/scrape-proof-report-data/v1\0";

/// A required section 5.4 component was absent from a proof selected for attestation.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("ScrapeProof cannot be attested without {field}")]
pub struct ReportDataError {
    pub field: &'static str,
}

/// Assemble the full-width SHA-512 report-data binding for a proof.
///
/// Components are concatenated byte-for-byte in the architecture-defined order. The pinned domain
/// tag ends in NUL, separating this protocol from other report-data constructions. M2 appends the
/// enclave public key as the final component, which makes a signature key substitution detectable
/// from the hardware-signed report data.
pub fn attestation_report_data(proof: &ScrapeProof) -> Result<String, ReportDataError> {
    let response_hash = response_hash(
        required(
            proof.response.headers_hash.as_deref(),
            "response.headers_hash",
        )?,
        required(proof.response.body_hash.as_deref(), "response.body_hash")?,
    );
    let components = [
        required(proof.task_id.as_deref(), "task_id")?,
        required(proof.nonce.as_deref(), "nonce")?,
        required(
            proof.request.request_hash.as_deref(),
            "request.request_hash",
        )?,
        required(proof.tls.cert_chain_hash.as_deref(), "tls.cert_chain_hash")?,
        required(
            proof.tls.handshake_transcript_hash.as_deref(),
            "tls.handshake_transcript_hash",
        )?,
        response_hash.as_str(),
        required(proof.result.result_hash.as_deref(), "result.result_hash")?,
        required(proof.egress.egress_ip.as_deref(), "egress.egress_ip")?,
        required(proof.egress.timestamp.as_deref(), "egress.timestamp")?,
        required(
            proof.egress.fingerprint_seed.as_deref(),
            "egress.fingerprint_seed",
        )?,
        required(
            proof.sdk_signature.enclave_pubkey.as_deref(),
            "sdk_signature.enclave_pubkey",
        )?,
    ];
    let mut hasher = Sha512::new();
    hasher.update(ATTESTATION_DOMAIN_TAG);
    for component in components {
        hasher.update(component.as_bytes());
    }
    Ok(hex(&hasher.finalize()))
}

fn required<'a>(value: Option<&'a str>, field: &'static str) -> Result<&'a str, ReportDataError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or(ReportDataError { field })
}

/// Serialize a JSON value into its compact canonical representation.
///
/// Every map that reaches the proof is backed by a `BTreeMap` (and this workspace does not enable
/// serde_json's `preserve_order` feature), so object keys are emitted lexicographically and the
/// resulting bytes are stable across repeated scrapes.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("format value is serializable")
}

/// Compute the canonical `result_hash` over the deterministic formats present in
/// `formats_produced`. Each contributing format is folded in as
/// `name || 0x00 || canonical_json(value) || 0x00`, in canonical order, so the digest is stable
/// across runs and independent of any excluded (e.g. `screenshot`) format's bytes.
pub fn result_hash(formats_produced: &BTreeMap<String, Value>) -> String {
    let mut hasher = Sha256::new();
    for name in DETERMINISTIC_FORMATS {
        if let Some(value) = formats_produced.get(*name) {
            hasher.update(name.as_bytes());
            hasher.update([0u8]);
            let canon = canonical_json(value);
            hasher.update(canon.as_bytes());
            hasher.update([0u8]);
        }
    }
    hex(&hasher.finalize())
}

/// Hash the canonical request header surface.
///
/// Header names are HTTP case-insensitive, so names are lowercased for the digest. Occurrences and
/// the caller-defined effective-field sequence are retained exactly: the effective list has
/// already been validated by [`crate::fetch::effective_headers`] and is emitted in this same order
/// by the direct transports and Chromium interception path.
pub fn headers_hash(headers: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    for (name, value) in headers {
        hasher.update(name.to_ascii_lowercase().as_bytes());
        hasher.update([0u8]);
        hasher.update(value.as_bytes());
        hasher.update([0u8]);
    }
    hex(&hasher.finalize())
}

/// Hash raw request-body bytes. A GET request has an empty body but still commits its SHA-256
/// digest so the later report-data binding never relies on a nullable body field.
pub fn body_hash(body: &[u8]) -> String {
    hex(&Sha256::digest(body))
}

/// Compute the canonical response digest defined by architecture §5.4:
/// `SHA256(response.headers_hash || response.body_hash)`.
pub fn response_hash(headers_hash: &str, body_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(headers_hash.as_bytes());
    hasher.update(body_hash.as_bytes());
    hex(&hasher.finalize())
}

/// Compute the deterministic request-side digest defined by architecture §5.4:
/// `SHA256(method || 0x00 || url || 0x00 || headers_hash || 0x00 || body_hash)`.
pub fn request_hash(method: &str, url: &str, headers_hash: &str, body_hash: &str) -> String {
    let mut hasher = Sha256::new();
    for component in [method, url, headers_hash, body_hash] {
        hasher.update(component.as_bytes());
        hasher.update([0u8]);
    }
    hex(&hasher.finalize())
}

/// Build structured, deterministic completeness evidence for every requested format.
///
/// `formats_produced` always carries an entry for each requested format. A JSON null represents
/// an unproduced value, so it is explicitly recorded as `present: false`, size `0`, and no
/// structural fields instead of being silently indistinguishable from a requested empty result.
pub fn completeness_manifest(
    requested_formats: &[String],
    formats_produced: &BTreeMap<String, Value>,
) -> CompletenessManifest {
    let mut formats = BTreeMap::new();
    let mut present_format_count = 0u64;

    for format in requested_formats {
        let value = formats_produced.get(format);
        let present = value.is_some_and(|value| !value.is_null());
        if present {
            present_format_count += 1;
        }
        let byte_size = value
            .filter(|value| !value.is_null())
            .map(|value| canonical_json(value).len() as u64)
            .unwrap_or(0);
        let key_field_count = value
            .filter(|value| !value.is_null())
            .map(structural_field_count)
            .unwrap_or(0);

        formats.insert(
            format.clone(),
            FormatCompleteness {
                requested: true,
                present,
                byte_size,
                key_field_count,
            },
        );
    }

    CompletenessManifest {
        version: COMPLETENESS_MANIFEST_VERSION,
        requested_format_count: requested_formats.len() as u64,
        present_format_count,
        formats,
    }
}

/// Count top-level key fields for structured values. Strings have no named fields, whereas arrays
/// report their item count so a format can distinguish an empty list from an item-bearing result.
fn structural_field_count(value: &Value) -> u64 {
    match value {
        Value::Object(map) => map.len() as u64,
        Value::Array(values) => values.len() as u64,
        _ => 0,
    }
}

/// Derive the worker-plane reconciliation key from exactly `(url, nonce, result_hash)`.
///
/// The separator-delimited preimage gives each component an unambiguous boundary and deliberately
/// excludes egress timestamp, IP address, TLS transcript, and every other volatile per-fetch field.
pub fn manifest_sha256(url: &str, nonce: Option<&str>, result_hash: &str) -> String {
    let mut hasher = Sha256::new();
    for component in [url, nonce.unwrap_or_default(), result_hash] {
        hasher.update(component.as_bytes());
        hasher.update([0u8]);
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use basecrawl_proof::{
        Attestation, Egress, Request, Response, ResultBlock, SdkSignature, Tls,
        SCRAPE_PROOF_VERSION,
    };
    use serde_json::json;

    fn base_surface() -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("markdown".to_string(), json!("# Title\n\nbody"));
        m.insert(
            "metadata".to_string(),
            json!({"title": "Title", "statusCode": 200}),
        );
        m
    }

    fn attestation_proof() -> ScrapeProof {
        ScrapeProof {
            version: SCRAPE_PROOF_VERSION,
            task_id: Some("task-123".to_string()),
            nonce: Some("validator-nonce-a".to_string()),
            request: Request {
                method: "GET".to_string(),
                url: "https://example.com/".to_string(),
                headers_hash: Some("11".repeat(32)),
                body_hash: Some("22".repeat(32)),
                request_hash: Some("33".repeat(32)),
                formats: vec!["markdown".to_string()],
            },
            tls: Tls {
                cert_chain_hash: Some("44".repeat(32)),
                handshake_transcript_hash: Some("55".repeat(32)),
                ..Tls::default()
            },
            response: Response {
                headers_hash: Some("66".repeat(32)),
                body_hash: Some("67".repeat(32)),
                ..Response::default()
            },
            result: ResultBlock {
                result_hash: Some("77".repeat(32)),
                ..ResultBlock::default()
            },
            egress: Egress {
                egress_ip: Some("203.0.113.5".to_string()),
                timestamp: Some("2026-07-12T12:34:56Z".to_string()),
                fingerprint_seed: Some("88".repeat(32)),
                ..Egress::default()
            },
            attestation: Attestation::default(),
            sdk_signature: SdkSignature {
                enclave_pubkey: Some("99".repeat(32)),
                sig: None,
            },
        }
    }

    fn independent_response_hash(headers_hash: &str, body_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(headers_hash.as_bytes());
        hasher.update(body_hash.as_bytes());
        hex(&hasher.finalize())
    }

    fn independent_report_data(proof: &ScrapeProof, domain_tag: &[u8]) -> String {
        let response_hash = independent_response_hash(
            proof.response.headers_hash.as_deref().unwrap(),
            proof.response.body_hash.as_deref().unwrap(),
        );
        let components = [
            proof.task_id.as_deref().unwrap(),
            proof.nonce.as_deref().unwrap(),
            proof.request.request_hash.as_deref().unwrap(),
            proof.tls.cert_chain_hash.as_deref().unwrap(),
            proof.tls.handshake_transcript_hash.as_deref().unwrap(),
            response_hash.as_str(),
            proof.result.result_hash.as_deref().unwrap(),
            proof.egress.egress_ip.as_deref().unwrap(),
            proof.egress.timestamp.as_deref().unwrap(),
            proof.egress.fingerprint_seed.as_deref().unwrap(),
            proof.sdk_signature.enclave_pubkey.as_deref().unwrap(),
        ];
        let mut hasher = Sha512::new();
        hasher.update(domain_tag);
        for component in components {
            hasher.update(component.as_bytes());
        }
        hex(&hasher.finalize())
    }

    #[test]
    fn report_data_matches_exact_section_5_4_preimage_with_enclave_key() {
        let proof = attestation_proof();
        let expected = independent_report_data(&proof, ATTESTATION_DOMAIN_TAG);
        assert_eq!(
            expected,
            "a4cab8203edc5783d578e0f44e62c372cdeb879789db1048d9ee20a7cc1f3101\
             e8c29b0c71afa2942eb95da7384757b975bf2850317bc2cde861a0e946d06e5b"
        );
        assert_eq!(attestation_report_data(&proof).unwrap(), expected);
    }

    #[test]
    fn report_data_is_full_width_sha512_without_zero_padding() {
        let report_data = attestation_report_data(&attestation_proof()).unwrap();
        assert_eq!(report_data.len(), 128);
        assert!(report_data.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(&report_data[64..], "0".repeat(64));
    }

    #[test]
    fn report_data_requires_the_pinned_domain_tag() {
        let proof = attestation_proof();
        let report_data = attestation_report_data(&proof).unwrap();
        assert_ne!(report_data, independent_report_data(&proof, b""));
        assert_ne!(
            report_data,
            independent_report_data(&proof, b"basecrawl/other-protocol/v1\0")
        );
    }

    #[test]
    fn every_section_5_4_component_is_load_bearing() {
        let proof = attestation_proof();
        let report_data = attestation_report_data(&proof).unwrap();
        let mut mutations: Vec<(&str, ScrapeProof)> = Vec::new();

        let mut changed = proof.clone();
        changed.task_id = Some("task-changed".to_string());
        mutations.push(("task_id", changed));
        let mut changed = proof.clone();
        changed.nonce = Some("nonce-changed".to_string());
        mutations.push(("nonce", changed));
        let mut changed = proof.clone();
        changed.request.request_hash = Some("03".repeat(32));
        mutations.push(("request_hash", changed));
        let mut changed = proof.clone();
        changed.tls.cert_chain_hash = Some("04".repeat(32));
        mutations.push(("cert_chain_hash", changed));
        let mut changed = proof.clone();
        changed.tls.handshake_transcript_hash = Some("05".repeat(32));
        mutations.push(("transcript_hash", changed));
        let mut changed = proof.clone();
        changed.response.body_hash = Some("06".repeat(32));
        mutations.push(("response_body_hash", changed));
        let mut changed = proof.clone();
        changed.response.headers_hash = Some("09".repeat(32));
        mutations.push(("response_headers_hash", changed));
        let mut changed = proof.clone();
        changed.result.result_hash = Some("07".repeat(32));
        mutations.push(("result_hash", changed));
        let mut changed = proof.clone();
        changed.egress.egress_ip = Some("198.51.100.9".to_string());
        mutations.push(("egress_ip", changed));
        let mut changed = proof.clone();
        changed.egress.timestamp = Some("2026-07-12T12:34:57Z".to_string());
        mutations.push(("timestamp", changed));
        let mut changed = proof.clone();
        changed.egress.fingerprint_seed = Some("08".repeat(32));
        mutations.push(("fingerprint_seed", changed));
        let mut changed = proof.clone();
        changed.sdk_signature.enclave_pubkey = Some("aa".repeat(32));
        mutations.push(("enclave_pubkey", changed));

        assert_eq!(mutations.len(), 12);
        for (field, changed) in mutations {
            assert_ne!(
                attestation_report_data(&changed).unwrap(),
                report_data,
                "mutating {field} must change report_data"
            );
        }
    }

    #[test]
    fn header_only_response_mutation_breaks_quote_binding_recomputation() {
        let quote_bound_proof = attestation_proof();
        let quote_report_data = attestation_report_data(&quote_bound_proof).unwrap();
        let mut mutated_proof = quote_bound_proof.clone();
        mutated_proof.response.headers_hash = Some("ab".repeat(32));

        assert_eq!(
            quote_report_data,
            independent_report_data(&quote_bound_proof, ATTESTATION_DOMAIN_TAG)
        );
        assert_ne!(
            quote_report_data,
            independent_report_data(&mutated_proof, ATTESTATION_DOMAIN_TAG)
        );
        assert_ne!(
            quote_report_data,
            attestation_report_data(&mutated_proof).unwrap(),
            "a proof with mutated response headers must not recompute the quote-bound report_data"
        );
    }

    #[test]
    fn report_data_component_order_is_canonical() {
        let proof = attestation_proof();
        let correct = attestation_report_data(&proof).unwrap();
        let response_hash = independent_response_hash(
            proof.response.headers_hash.as_deref().unwrap(),
            proof.response.body_hash.as_deref().unwrap(),
        );
        let swapped_response_hash = independent_response_hash(
            proof.response.body_hash.as_deref().unwrap(),
            proof.response.headers_hash.as_deref().unwrap(),
        );
        assert_ne!(response_hash, swapped_response_hash);

        let mut hasher = Sha512::new();
        hasher.update(ATTESTATION_DOMAIN_TAG);
        for component in [
            proof.task_id.as_deref().unwrap(),
            proof.nonce.as_deref().unwrap(),
            proof.request.request_hash.as_deref().unwrap(),
            proof.tls.cert_chain_hash.as_deref().unwrap(),
            proof.tls.handshake_transcript_hash.as_deref().unwrap(),
            proof.result.result_hash.as_deref().unwrap(),
            response_hash.as_str(),
            proof.egress.egress_ip.as_deref().unwrap(),
            proof.egress.timestamp.as_deref().unwrap(),
            proof.egress.fingerprint_seed.as_deref().unwrap(),
            proof.sdk_signature.enclave_pubkey.as_deref().unwrap(),
        ] {
            hasher.update(component.as_bytes());
        }
        assert_ne!(correct, hex(&hasher.finalize()));
    }

    #[test]
    fn fresh_nonce_changes_report_data_and_stale_nonce_does_not_match() {
        let stale = attestation_proof();
        let stale_report_data = attestation_report_data(&stale).unwrap();
        let mut current = stale.clone();
        current.nonce = Some("validator-nonce-b".to_string());
        let current_report_data = attestation_report_data(&current).unwrap();

        assert_ne!(stale_report_data, current_report_data);
        assert_eq!(
            stale_report_data,
            independent_report_data(&stale, ATTESTATION_DOMAIN_TAG)
        );
        assert_eq!(
            current_report_data,
            independent_report_data(&current, ATTESTATION_DOMAIN_TAG)
        );
        assert_ne!(
            stale_report_data,
            independent_report_data(&current, ATTESTATION_DOMAIN_TAG),
            "a replayed quote remains bound to its stale nonce"
        );
    }

    #[test]
    fn attestation_refuses_missing_or_empty_components() {
        let mut missing = attestation_proof();
        missing.nonce = None;
        assert_eq!(
            attestation_report_data(&missing).unwrap_err(),
            ReportDataError { field: "nonce" }
        );

        let mut empty = attestation_proof();
        empty.tls.handshake_transcript_hash = Some(String::new());
        assert_eq!(
            attestation_report_data(&empty).unwrap_err(),
            ReportDataError {
                field: "tls.handshake_transcript_hash"
            }
        );

        let mut missing_response_headers = attestation_proof();
        missing_response_headers.response.headers_hash = None;
        assert_eq!(
            attestation_report_data(&missing_response_headers).unwrap_err(),
            ReportDataError {
                field: "response.headers_hash"
            }
        );

        let mut missing_response_body = attestation_proof();
        missing_response_body.response.body_hash = None;
        assert_eq!(
            attestation_report_data(&missing_response_body).unwrap_err(),
            ReportDataError {
                field: "response.body_hash"
            }
        );

        let mut missing_key = attestation_proof();
        missing_key.sdk_signature.enclave_pubkey = None;
        assert_eq!(
            attestation_report_data(&missing_key).unwrap_err(),
            ReportDataError {
                field: "sdk_signature.enclave_pubkey"
            }
        );
    }

    #[test]
    fn hash_is_64_char_lowercase_hex() {
        let h = result_hash(&base_surface());
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn hash_is_deterministic_for_identical_surface() {
        assert_eq!(result_hash(&base_surface()), result_hash(&base_surface()));
    }

    #[test]
    fn hash_changes_when_deterministic_content_changes() {
        let mut other = base_surface();
        other.insert("markdown".to_string(), json!("# Different"));
        assert_ne!(result_hash(&base_surface()), result_hash(&other));
    }

    #[test]
    fn screenshot_bytes_do_not_affect_hash() {
        let baseline = result_hash(&base_surface());
        let mut with_shot = base_surface();
        with_shot.insert("screenshot".to_string(), json!("AAAAbase64-one"));
        let mut with_other_shot = base_surface();
        with_other_shot.insert("screenshot".to_string(), json!("ZZZZbase64-two-different"));
        assert_eq!(baseline, result_hash(&with_shot));
        assert_eq!(baseline, result_hash(&with_other_shot));
    }

    #[test]
    fn json_extract_presence_and_contents_are_excluded() {
        let baseline = result_hash(&base_surface());
        let mut with_first_json = base_surface();
        with_first_json.insert(
            "json".to_string(),
            json!({"title": "First extraction", "items": [{"name": "one"}]}),
        );
        let mut with_second_json = base_surface();
        with_second_json.insert(
            "json".to_string(),
            json!({"title": "Different extraction", "items": [{"name": "two"}, {"name": "three"}]}),
        );
        let mut with_null_json = base_surface();
        with_null_json.insert("json".to_string(), Value::Null);

        assert_eq!(baseline, result_hash(&with_first_json));
        assert_eq!(baseline, result_hash(&with_second_json));
        assert_eq!(baseline, result_hash(&with_null_json));
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let left = json!({"z": 1, "a": {"second": 2, "first": 1}});
        let right = json!({"a": {"first": 1, "second": 2}, "z": 1});
        assert_eq!(canonical_json(&left), canonical_json(&right));
        assert_eq!(
            canonical_json(&left),
            r#"{"a":{"first":1,"second":2},"z":1}"#
        );
    }

    #[test]
    fn request_digest_binds_every_input() {
        let headers = headers_hash(&[
            ("User-Agent".to_string(), "basecrawl/1".to_string()),
            ("X-Z".to_string(), "z".to_string()),
            ("X-A".to_string(), "a".to_string()),
        ]);
        let body = body_hash(b"body");
        let baseline = request_hash("GET", "https://example.com/", &headers, &body);
        assert_eq!(
            baseline,
            request_hash("GET", "https://example.com/", &headers, &body)
        );
        assert_ne!(
            baseline,
            request_hash("POST", "https://example.com/", &headers, &body)
        );
        assert_ne!(
            baseline,
            request_hash("GET", "https://example.test/", &headers, &body)
        );
        assert_ne!(
            baseline,
            request_hash("GET", "https://example.com/", "other", &body)
        );
        assert_ne!(
            baseline,
            request_hash("GET", "https://example.com/", &headers, "other")
        );
    }

    #[test]
    fn header_digest_normalizes_name_case_but_binds_sequence_and_multiplicity() {
        let first = headers_hash(&[
            ("User-Agent".to_string(), "basecrawl/1".to_string()),
            ("X-Alpha".to_string(), "a".to_string()),
            ("x-beta".to_string(), "b".to_string()),
        ]);
        let case_variant = headers_hash(&[
            ("user-agent".to_string(), "basecrawl/1".to_string()),
            ("x-alpha".to_string(), "a".to_string()),
            ("X-BETA".to_string(), "b".to_string()),
        ]);
        let reordered = headers_hash(&[
            ("User-Agent".to_string(), "basecrawl/1".to_string()),
            ("x-beta".to_string(), "b".to_string()),
            ("X-Alpha".to_string(), "a".to_string()),
        ]);
        let repeated = headers_hash(&[
            ("User-Agent".to_string(), "basecrawl/1".to_string()),
            ("X-Alpha".to_string(), "a".to_string()),
            ("X-Alpha".to_string(), "a".to_string()),
            ("x-beta".to_string(), "b".to_string()),
        ]);
        assert_eq!(first, case_variant);
        assert_ne!(first, reordered);
        assert_ne!(first, repeated);
    }

    #[test]
    fn completeness_manifest_records_presence_size_and_structure() {
        let mut produced = BTreeMap::new();
        produced.insert("markdown".to_string(), json!("# title"));
        produced.insert(
            "links".to_string(),
            json!({"links": ["https://example.com/"]}),
        );
        produced.insert("json".to_string(), Value::Null);
        let requested = vec![
            "markdown".to_string(),
            "links".to_string(),
            "json".to_string(),
        ];

        let manifest = completeness_manifest(&requested, &produced);
        assert_eq!(manifest.version, COMPLETENESS_MANIFEST_VERSION);
        assert_eq!(manifest.requested_format_count, 3);
        assert_eq!(manifest.present_format_count, 2);
        assert_eq!(
            manifest.formats["markdown"],
            FormatCompleteness {
                requested: true,
                present: true,
                byte_size: 9,
                key_field_count: 0,
            }
        );
        assert_eq!(manifest.formats["links"].key_field_count, 1);
        assert_eq!(manifest.formats["json"].byte_size, 0);
        assert!(!manifest.formats["json"].present);
    }

    #[test]
    fn reconciliation_digest_binds_url_nonce_and_result_hash() {
        let baseline = manifest_sha256("https://example.com/", Some("nonce-a"), "result-a");
        assert_eq!(
            baseline,
            manifest_sha256("https://example.com/", Some("nonce-a"), "result-a")
        );
        assert_ne!(
            baseline,
            manifest_sha256("https://example.test/", Some("nonce-a"), "result-a")
        );
        assert_ne!(
            baseline,
            manifest_sha256("https://example.com/", Some("nonce-b"), "result-a")
        );
        assert_ne!(
            baseline,
            manifest_sha256("https://example.com/", Some("nonce-a"), "result-b")
        );
    }
}
