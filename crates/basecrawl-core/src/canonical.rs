//! Canonical result-surface hashing.
//!
//! `result_hash` is the byte-quorum digest two honest miners must agree on for a canary. Per
//! architecture §5.4 it covers only the **deterministic** result surface
//! (`markdown`/`html`/`rawHtml`/`links`/`metadata`) and deliberately **excludes** `screenshot`
//! and `json`/`extract`, which are non-deterministic (pixel rendering) or LLM-optional and would
//! otherwise destabilize the quorum. It also owns the deterministic request, completeness, and
//! reconciliation digests that bind the M1 ScrapeProof surface without including volatile egress
//! values.

use basecrawl_proof::{CompletenessManifest, FormatCompleteness};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Result formats that contribute to the deterministic quorum surface, in canonical order.
/// `screenshot` and `json` are intentionally absent (see module docs).
pub const DETERMINISTIC_FORMATS: &[&str] = &["markdown", "html", "rawHtml", "links", "metadata"];

/// Schema version emitted in [`CompletenessManifest`].
pub const COMPLETENESS_MANIFEST_VERSION: u32 = 1;

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
