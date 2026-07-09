//! Canonical result-surface hashing.
//!
//! `result_hash` is the byte-quorum digest two honest miners must agree on for a canary. Per
//! architecture §5.4 it covers only the **deterministic** result surface
//! (`markdown`/`html`/`rawHtml`/`links`/`metadata`) and deliberately **excludes** `screenshot`
//! and `json`/`extract`, which are non-deterministic (pixel rendering) or LLM-optional and would
//! otherwise destabilize the quorum. This module owns that exclusion; later canonicalization work
//! layers the completeness manifest and request-side digests on top.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Result formats that contribute to the deterministic quorum surface, in canonical order.
/// `screenshot` and `json` are intentionally absent (see module docs).
pub const DETERMINISTIC_FORMATS: &[&str] = &["markdown", "html", "rawHtml", "links", "metadata"];

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
            // serde_json::Map is BTreeMap-backed in this workspace (no preserve_order), so object
            // keys serialize in a stable, sorted order.
            let canon = serde_json::to_string(value).expect("format value is serializable");
            hasher.update(canon.as_bytes());
            hasher.update([0u8]);
        }
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
    fn json_extract_is_excluded_too() {
        let baseline = result_hash(&base_surface());
        let mut with_json = base_surface();
        with_json.insert("json".to_string(), json!({"extracted": "anything"}));
        assert_eq!(baseline, result_hash(&with_json));
    }
}
