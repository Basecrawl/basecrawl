//! Security invariants of the seeded fingerprint generator
//! (architecture §6.5 / risk BOT-08 / VAL-ANTIBOT-038..040).
//!
//! Seed diversity only legalizes **non-security** client dimensions (JA3/JA4
//! cipher/group offer order, header order, UA, viewport, timezone, locale,
//! canvas/WebGL noise). Security-critical TLS parameters are **constants of the
//! measured image** and never leave the values encoded here, for any seed:
//!
//! * certificate validation is never weakened by a seed
//! * authenticity-capable scrapes always require negotiated TLS 1.3
//! * in-enclave cert-chain + handshake-transcript capture remains enabled
//!   (L2 binding intact under diversified fingerprints)

use serde::{Deserialize, Serialize};

use crate::FingerprintProfile;

/// How the client authenticates the peer certificate for a scrape.
///
/// This is intentionally not seed-selected. The only values the measured image
/// supports are the secure WebPKI path or an explicit, caller-opted diagnostic
/// bypass that is both host-visible on the wire (`InsecureDiagnostic`) and
/// outside the seed path (VAL-ANTIBOT-038).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateValidationPolicy {
    /// Default: Mozilla root store + hostname verification (never seed-weakened).
    WebPkiValidated,
}

/// Fixed protocol versions the measured image may offer / accept for a normal,
/// authenticity-capable scrape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferedTlsVersions {
    /// TLS 1.3 is preferred; TLS 1.2 remains only so the verifier can refuse a
    /// legacy peer as a certificate-validation failure before the protocol
    /// version is rejected as unsuitable for authenticity evidence.
    Tls13PreferredTls12DiagnosticOnly,
}

/// The complete set of security-critical TLS parameters that stay fixed across
/// every seed (VAL-ANTIBOT-038).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityCriticalTlsParams {
    /// Certificate validation policy. Never seed-parameterized.
    pub certificate_validation: CertificateValidationPolicy,
    /// `true` only when a seed could weaken certificate verification. Always
    /// `false` for this image.
    pub seed_may_weaken_cert_validation: bool,
    /// Protocol versions the stacked terminator may offer.
    pub offered_versions: OfferedTlsVersions,
    /// Negotiated version required for an authenticity-capable ScrapeProof.
    pub required_negotiated_version: &'static str,
    /// Cipher suites may be re-ordered by the seed (non-security JA3/JA4
    /// diversity) but never leave the closed TLS 1.3-only allowlist.
    pub cipher_suites_are_tls13_only: bool,
    /// Supported groups may be reordered; the closed, modern set is fixed.
    pub groups_are_modern_only: bool,
    /// In-enclave cert-chain DER + SHA-256 `cert_chain_hash` capture is always
    /// performed for TLS 1.3 scrapes, independent of the seed (BOT-08).
    pub cert_chain_capture_enabled: bool,
    /// Handshake transcript hash capture is always performed for TLS 1.3
    /// scrapes, independent of the seed (BOT-08).
    pub transcript_capture_enabled: bool,
    /// Report-data always binds `cert_chain_hash` + `handshake_transcript_hash`
    /// and the fingerprint seed itself (L2 + auditability of diversity).
    pub l2_binding_includes_cert_and_transcript: bool,
}

/// Return the fixed security-critical TLS parameters of the measured image.
///
/// Calling this function for any seed yields the **same** structure — seeds
/// never influence these fields.
pub fn security_critical_tls_params() -> SecurityCriticalTlsParams {
    SecurityCriticalTlsParams {
        certificate_validation: CertificateValidationPolicy::WebPkiValidated,
        seed_may_weaken_cert_validation: false,
        offered_versions: OfferedTlsVersions::Tls13PreferredTls12DiagnosticOnly,
        required_negotiated_version: REQUIRED_NEGOTIATED_TLS_VERSION,
        cipher_suites_are_tls13_only: true,
        groups_are_modern_only: true,
        cert_chain_capture_enabled: true,
        transcript_capture_enabled: true,
        l2_binding_includes_cert_and_transcript: true,
    }
}

/// Negotiated TLS version required for every authenticity-capable ScrapeProof.
pub const REQUIRED_NEGOTIATED_TLS_VERSION: &str = "1.3";

/// Closed set of TLS 1.3 cipher suite IANA values the seed may legalize (must
/// match `crate::TLS13_CIPHER_SUITES`). Seeds may only re-order this set — they
/// may never introduce a weaker cipher.
pub const SECURITY_TLS13_CIPHER_SUITE_IANA: &[u16] = &[0x1301, 0x1302, 0x1303];

/// Modern named groups the seed may re-order for JA3/JA4 diversity. Seeds may
/// never introduce legacy or anonymous groups.
pub const SECURITY_TLS_GROUP_ALLOWLIST: &[&str] = &["X25519", "secp256r1", "secp384r1"];

/// Assert that a generated fingerprint profile preserves every security
/// invariant of the measured image (VAL-ANTIBOT-038, BOT-08).
///
/// Returns `Ok(())` when the profile only varies non-security dimensions and
/// never weakens certificate validation, protocol versions, cipher classes, or
/// group classes. Used both by the pure generator unit tests and by the
/// integration path that re-checks the seed-selected ClientHello material
/// before a scrape is dispatched.
pub fn assert_security_invariants(profile: &FingerprintProfile) -> Result<(), String> {
    let fixed = security_critical_tls_params();
    if fixed.seed_may_weaken_cert_validation {
        return Err("measured image must never allow seeds to weaken cert validation".into());
    }
    if fixed.required_negotiated_version != REQUIRED_NEGOTIATED_TLS_VERSION {
        return Err(format!(
            "required negotiated TLS version must be {REQUIRED_NEGOTIATED_TLS_VERSION}"
        ));
    }
    if !fixed.cert_chain_capture_enabled || !fixed.transcript_capture_enabled {
        return Err("in-enclave cert/transcript capture must stay enabled under every seed".into());
    }
    if !fixed.l2_binding_includes_cert_and_transcript {
        return Err(
            "L2 report_data binding must include cert + transcript under every seed".into(),
        );
    }

    // Cipher suites: closed TLS 1.3 set, permutation only.
    if profile.tls13_cipher_order.len() != SECURITY_TLS13_CIPHER_SUITE_IANA.len() {
        return Err(format!(
            "seed emitted {} cipher suites; expected exactly {}",
            profile.tls13_cipher_order.len(),
            SECURITY_TLS13_CIPHER_SUITE_IANA.len()
        ));
    }
    for suite in &profile.tls13_cipher_order {
        if !SECURITY_TLS13_CIPHER_SUITE_IANA.contains(suite) {
            return Err(format!(
                "seed emitted non-TLS-1.3 / non-allowlisted cipher suite 0x{suite:04x}"
            ));
        }
    }
    {
        let mut sorted = profile.tls13_cipher_order.clone();
        sorted.sort_unstable();
        let mut expected = SECURITY_TLS13_CIPHER_SUITE_IANA.to_vec();
        expected.sort_unstable();
        if sorted != expected {
            return Err(
                "seed must re-order the closed TLS 1.3 cipher set, not drop or duplicate".into(),
            );
        }
    }

    // Groups: modern-only allowlist, permutation only.
    if profile.tls_group_order.len() != SECURITY_TLS_GROUP_ALLOWLIST.len() {
        return Err(format!(
            "seed emitted {} groups; expected exactly {}",
            profile.tls_group_order.len(),
            SECURITY_TLS_GROUP_ALLOWLIST.len()
        ));
    }
    for group in &profile.tls_group_order {
        if !SECURITY_TLS_GROUP_ALLOWLIST.contains(&group.as_str()) {
            return Err(format!("seed emitted non-allowlisted TLS group {group:?}"));
        }
    }
    {
        let mut sorted = profile.tls_group_order.clone();
        sorted.sort();
        let mut expected: Vec<String> = SECURITY_TLS_GROUP_ALLOWLIST
            .iter()
            .map(|g| (*g).to_string())
            .collect();
        expected.sort();
        if sorted != expected {
            return Err(
                "seed must re-order the closed modern group set, not drop or duplicate".into(),
            );
        }
    }

    // Named suites that accompany the IANA ids must stay TLS1.3-prefixed.
    for name in &profile.tls13_cipher_names {
        if !name.starts_with("TLS13_") {
            return Err(format!("seed emitted non-TLS-1.3 cipher name {name:?}"));
        }
    }

    Ok(())
}

/// Snapshot of the security-critical surface for a given seed. Useful for the
/// multi-seed dump required by VAL-ANTIBOT-038 evidence: every seed produces the
/// same security tuple, while non-security fingerprint dimensions still vary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeedSecuritySnapshot {
    pub seed: String,
    pub security: SecurityCriticalTlsParams,
    /// Non-security dimensions (may vary across seeds).
    pub ja3: String,
    pub ja4: String,
    pub user_agent: String,
    pub tls13_cipher_order: Vec<u16>,
    pub tls_group_order: Vec<String>,
}

/// Build a security snapshot for `seed`. The `security` half is independent of
/// the seed; the non-security half is generated from it.
pub fn security_snapshot_for_seed(seed_input: &str) -> SeedSecuritySnapshot {
    let profile = crate::generate(seed_input);
    SeedSecuritySnapshot {
        seed: profile.seed.clone(),
        security: security_critical_tls_params(),
        ja3: profile.ja3,
        ja4: profile.ja4,
        user_agent: profile.user_agent,
        tls13_cipher_order: profile.tls13_cipher_order,
        tls_group_order: profile.tls_group_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate;
    use std::collections::HashSet;

    #[test]
    fn val_antibot_038_security_params_fixed_across_many_seeds() {
        let baseline = security_critical_tls_params();
        assert_eq!(
            baseline.certificate_validation,
            CertificateValidationPolicy::WebPkiValidated
        );
        assert!(!baseline.seed_may_weaken_cert_validation);
        assert_eq!(baseline.required_negotiated_version, "1.3");
        assert!(baseline.cert_chain_capture_enabled);
        assert!(baseline.transcript_capture_enabled);
        assert!(baseline.l2_binding_includes_cert_and_transcript);

        let mut security_tuples = HashSet::new();
        let mut non_security_diverged = false;
        let first = security_snapshot_for_seed("security-baseline-0");
        for i in 0..48u32 {
            let snap = security_snapshot_for_seed(&format!("security-seed-{i}"));
            assert_eq!(
                snap.security, baseline,
                "seed {} altered security-critical TLS params",
                snap.seed
            );
            assert_security_invariants(&generate(&format!("security-seed-{i}")))
                .expect("seed must preserve security invariants");
            let security_key = serde_json::to_string(&snap.security).expect("serializable");
            security_tuples.insert(security_key);
            if snap.ja3 != first.ja3
                || snap.ja4 != first.ja4
                || snap.tls13_cipher_order != first.tls13_cipher_order
                || snap.user_agent != first.user_agent
            {
                non_security_diverged = true;
            }
        }
        assert_eq!(
            security_tuples.len(),
            1,
            "security-critical TLS params must be identical for every seed"
        );
        assert!(
            non_security_diverged,
            "non-security fingerprint dimensions must still vary across seeds"
        );
    }

    #[test]
    fn val_antibot_038_seed_never_emits_legacy_or_weak_ciphers() {
        for i in 0..64u32 {
            let profile = generate(&format!("cipher-harden-{i}"));
            assert_security_invariants(&profile).unwrap();
            for suite in &profile.tls13_cipher_order {
                // TLS_AES_*_GCM and CHACHA20 only; no RC4/3DES/CBC/SSL residue.
                assert!(
                    matches!(suite, 0x1301..=0x1303),
                    "suite 0x{suite:04x} is not a modern TLS 1.3 AEAD suite"
                );
            }
        }
    }
}
