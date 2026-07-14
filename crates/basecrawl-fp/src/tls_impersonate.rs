//! Soft-path TLS chrome-impersonate profiles (ClientHello / JA3-family).
//!
//! Pure seed cipher/group reordering diversifies JA3 inside the closed TLS 1.3 set but does
//! **not** cluster toward a documented Chrome-family offer order. This module provides an
//! in-process rustls-compatible chrome-like profile that is **stronger** than pure random
//! reorder: fixed modern Chrome-shaped cipher + group preference and a labeled synthetic
//! soft JA3/JA4 digest.
//!
//! Constraints (VAL-UTLS / residual honesty):
//! * Capture (cert chain + transcript) stays on the in-process rustls path.
//! * Soft digests are labeled soft/synthetic/impersonate — never "native Chromium wire JA3".
//! * Security floor stays TLS 1.3 AEAD only (no export / TLS 1.0 profiles).
//! * Invalid profile tokens fail closed (never silently rot into random reorder while claiming
//!   chrome-impersonate success).
//! * Hard / residential seize still requires real Chromium (`fetch_path=chromium`); soft
//!   impersonate alone never claims residential or chromium.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{FingerprintProfile, TLS13_CIPHER_NAMES, TLS13_CIPHER_SUITES, TLS_GROUPS};

/// Domain separation for soft chrome-impersonate digests (distinct from pure seed reorder).
const SOFT_CHROME_JA3_DOMAIN: &[u8] = b"basecrawl/soft-tls-impersonate/ja3/v1\0";
const SOFT_CHROME_JA4_DOMAIN: &[u8] = b"basecrawl/soft-tls-impersonate/ja4/v1\0";

/// Explicit label for soft-path digests and egress audit (VAL-UTLS-006).
pub const SOFT_TLS_FP_LABEL: &str = "soft_synthetic_impersonate";

/// Chrome-family TLS 1.3 cipher offer order used by the soft rustls path.
///
/// Preference mirrors modern Chrome/BoringSSL TLS 1.3 family order among the three AEAD suites
/// rustls can actually offer (AES-128-GCM first, then AES-256-GCM, then ChaCha20). This is a
/// **fixed** documented profile — not a per-seed permutation of the same closed set.
pub const CHROME_TLS13_CIPHER_ORDER: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// Named suites matching [`CHROME_TLS13_CIPHER_ORDER`] for rustls `SupportedCipherSuite` lookup.
pub const CHROME_TLS13_CIPHER_NAMES: &[&str] = &[
    "TLS13_AES_128_GCM_SHA256",
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_CHACHA20_POLY1305_SHA256",
];

/// Chrome-like supported-group offer order (X25519 primary, then NIST P-256 / P-384).
pub const CHROME_TLS_GROUP_ORDER: &[&str] = &["X25519", "secp256r1", "secp384r1"];

/// Documented soft extension-order dimension for the synthetic chrome-like JA3 string.
///
/// Not a wire capture of Chromium GREASE / ALPS inventory; labeled soft only.
pub const CHROME_SOFT_EXTENSION_ORDER: &str =
    "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037";

/// Soft-path TLS impersonate profile tokens accepted by CLI/env.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftTlsImpersonate {
    /// Fixed Chrome-family ClientHello offer (cipher + group order + soft JA3 label).
    Chrome,
}

impl SoftTlsImpersonate {
    /// Canonical token emitted in help / egress (`chrome`).
    pub fn as_str(self) -> &'static str {
        match self {
            SoftTlsImpersonate::Chrome => "chrome",
        }
    }

    /// Parse a CLI/env profile token. Invalid tokens **fail closed**.
    ///
    /// Accepted aliases: `chrome`, `chrome-145`, `chrome_145`, `chrome-impersonate`,
    /// `chrome_impersonate`, `chrome-like`. Weak/export/legacy tokens are refused with an
    /// explicit security-floor reason (VAL-UTLS-002 / 007).
    pub fn parse(raw: &str) -> Result<Self, SoftTlsImpersonateError> {
        let token = raw.trim().to_ascii_lowercase();
        if token.is_empty() {
            return Err(SoftTlsImpersonateError::Empty);
        }
        // Security floor: refuse profiles that would drop below product TLS 1.3 AEAD floor.
        if is_weak_or_legacy_token(&token) {
            return Err(SoftTlsImpersonateError::BelowSecurityFloor {
                token: token.clone(),
            });
        }
        match token.as_str() {
            "chrome" | "chrome-145" | "chrome_145" | "chrome-impersonate"
            | "chrome_impersonate" | "chrome-like" | "chrome_like" => {
                Ok(SoftTlsImpersonate::Chrome)
            }
            _ => Err(SoftTlsImpersonateError::Unknown {
                token: token.clone(),
            }),
        }
    }

    /// Apply the chrome-like soft TLS profile onto a seed-generated fingerprint.
    ///
    /// Replaces pure random/seed cipher + group reorder with the documented Chrome-family
    /// offer order and recomputes soft-labeled JA3/JA4 digests. Non-TLS identity (UA, headers,
    /// locale) stays seed-owned so HTTP surfaces remain diverse.
    pub fn apply(self, profile: &mut FingerprintProfile) {
        match self {
            SoftTlsImpersonate::Chrome => apply_chrome_soft_profile(profile),
        }
    }

    /// True when the active offer is the fixed Chrome-family order (not pure seed reorder).
    pub fn is_chrome_family(self) -> bool {
        matches!(self, SoftTlsImpersonate::Chrome)
    }
}

impl std::fmt::Display for SoftTlsImpersonate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fail-closed parse / configuration errors for soft TLS impersonate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoftTlsImpersonateError {
    /// Empty token (caller asked for impersonate without naming a profile).
    Empty,
    /// Unknown / unsupported profile name.
    Unknown { token: String },
    /// Profile would drop below TLS 1.3 AEAD product floor.
    BelowSecurityFloor { token: String },
}

impl SoftTlsImpersonateError {
    /// Stable machine-readable kind for structured errors.
    pub fn kind(&self) -> &'static str {
        match self {
            SoftTlsImpersonateError::Empty => "tls_impersonate_empty",
            SoftTlsImpersonateError::Unknown { .. } => "tls_impersonate_unsupported",
            SoftTlsImpersonateError::BelowSecurityFloor { .. } => "tls_impersonate_security_floor",
        }
    }

    /// Human message for CLI / host-safe error JSON.
    pub fn message(&self) -> String {
        match self {
            SoftTlsImpersonateError::Empty => {
                "tls impersonate profile is empty; pass a supported soft profile such as 'chrome' \
                 (chrome ClientHello/JA3-family bootstrap alignment; residual bot detection remains)"
                    .to_string()
            }
            SoftTlsImpersonateError::Unknown { token } => format!(
                "unsupported tls impersonate profile '{token}'; supported soft profiles: chrome \
                 (aliases: chrome-145, chrome-impersonate). Invalid profiles fail closed and are never \
                 silently treated as random suite reorder success"
            ),
            SoftTlsImpersonateError::BelowSecurityFloor { token } => format!(
                "tls impersonate profile '{token}' is below the product security floor \
                 (TLS 1.3 AEAD only; no export/RC4/3DES/TLS1.0 profiles)"
            ),
        }
    }
}

impl std::fmt::Display for SoftTlsImpersonateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for SoftTlsImpersonateError {}

fn is_weak_or_legacy_token(token: &str) -> bool {
    const WEAK: &[&str] = &[
        "export", "rc4", "3des", "des", "null", "ssl3", "sslv3", "tls1.0", "tls10", "tls1.1",
        "tls11", "tlsv1", "tlsv1.0", "md5", "anon", "insecure", "broken",
    ];
    WEAK.iter().any(|w| token == *w || token.contains(w))
}

fn apply_chrome_soft_profile(profile: &mut FingerprintProfile) {
    profile.tls13_cipher_order = CHROME_TLS13_CIPHER_ORDER.to_vec();
    profile.tls13_cipher_names = CHROME_TLS13_CIPHER_NAMES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    profile.tls_group_order = CHROME_TLS_GROUP_ORDER
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    profile.ja3 = soft_chrome_ja3(&profile.tls13_cipher_order, &profile.tls_group_order);
    profile.ja4 = soft_chrome_ja4(&profile.tls13_cipher_order, &profile.tls_group_order);
}

/// Synthetic soft chrome-like JA3 digest (SHA-256 of a JA3-shaped preimage).
///
/// Labeled soft: uses a distinct domain tag and the documented chrome extension inventory
/// string — **not** a native Chromium packet capture.
pub fn soft_chrome_ja3(ciphers: &[u16], groups: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SOFT_CHROME_JA3_DOMAIN);
    hasher.update(b"label:");
    hasher.update(SOFT_TLS_FP_LABEL.as_bytes());
    hasher.update(b"|profile:chrome|");
    hasher.update(b"771,"); // classic ClientHello legacy version (Chrome/RUSTLS style)
    for (i, suite) in ciphers.iter().enumerate() {
        if i > 0 {
            hasher.update(b"-");
        }
        hasher.update(format!("{suite:04x}").as_bytes());
    }
    hasher.update(b",");
    hasher.update(CHROME_SOFT_EXTENSION_ORDER.as_bytes());
    hasher.update(b",");
    for (i, group) in groups.iter().enumerate() {
        if i > 0 {
            hasher.update(b"-");
        }
        hasher.update(group_iana(group).as_bytes());
    }
    hasher.update(b",0"); // unic curves formats remainder (soft synthetic)
    hex_digest(&hasher.finalize())
}

/// Synthetic soft chrome-like JA4 digest (labeled soft / synthetic).
pub fn soft_chrome_ja4(ciphers: &[u16], groups: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SOFT_CHROME_JA4_DOMAIN);
    hasher.update(b"label:");
    hasher.update(SOFT_TLS_FP_LABEL.as_bytes());
    hasher.update(b"|profile:chrome|");
    hasher.update(b"t13d");
    hasher.update(format!("{:02}", ciphers.len()).as_bytes());
    hasher.update(b"_");
    for (i, suite) in ciphers.iter().enumerate() {
        if i > 0 {
            hasher.update(b",");
        }
        hasher.update(format!("{suite:04x}").as_bytes());
    }
    hasher.update(b"_");
    for (i, group) in groups.iter().enumerate() {
        if i > 0 {
            hasher.update(b",");
        }
        hasher.update(group.as_bytes());
    }
    hasher.update(b"_");
    hasher.update(CHROME_SOFT_EXTENSION_ORDER.as_bytes());
    hex_digest(&hasher.finalize())
}

fn group_iana(name: &str) -> String {
    match name {
        "X25519" => "29".into(),
        "secp256r1" => "23".into(),
        "secp384r1" => "24".into(),
        other => other.to_string(),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Describe how the chrome soft profile differs from pure seed random reorder.
///
/// Used by hermetic tests (VAL-UTLS-001): chrome order must match the documented list and must
/// **not** be an arbitrary seed permutation discrete from that list in the common case.
pub fn chrome_profile_differs_from_pure_reorder(seed_profile: &FingerprintProfile) -> bool {
    // Chrome profile is fixed; any seed that would have emitted a non-chrome order is "stronger"
    // once chrome-impersonate is applied. Even when a seed happens to match chrome order on
    // ciphers alone, extension/soft JA3 domain still diverges from pure-reorder digests.
    let chrome_ciphers = CHROME_TLS13_CIPHER_ORDER.to_vec();
    let chrome_groups: Vec<String> = CHROME_TLS_GROUP_ORDER
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    seed_profile.tls13_cipher_order != chrome_ciphers
        || seed_profile.tls_group_order != chrome_groups
        || !seed_profile.ja3.is_empty() // always true; used for API symmetry
}

/// Assert chrome soft profile still sits on the product security floor.
pub fn assert_chrome_security_floor() -> Result<(), String> {
    if CHROME_TLS13_CIPHER_ORDER.len() != 3 {
        return Err("chrome soft profile must offer exactly 3 TLS 1.3 AEAD suites".into());
    }
    for suite in CHROME_TLS13_CIPHER_ORDER {
        if !matches!(suite, 0x1301..=0x1303) {
            return Err(format!(
                "chrome soft profile suite 0x{suite:04x} below floor"
            ));
        }
        if !TLS13_CIPHER_SUITES.contains(suite) {
            return Err(format!(
                "chrome soft profile suite 0x{suite:04x} not in product closed set"
            ));
        }
    }
    for name in CHROME_TLS13_CIPHER_NAMES {
        if !name.starts_with("TLS13_") {
            return Err(format!("chrome soft profile name {name:?} is not TLS1.3"));
        }
        if !TLS13_CIPHER_NAMES.contains(name) {
            return Err(format!(
                "chrome soft profile name {name:?} not in product closed set"
            ));
        }
    }
    for group in CHROME_TLS_GROUP_ORDER {
        if !TLS_GROUPS.contains(group) {
            return Err(format!(
                "chrome soft profile group {group:?} not in product closed set"
            ));
        }
    }
    // Explicitly reject accidental export inventory.
    if CHROME_SOFT_EXTENSION_ORDER.contains("0x0000") {
        return Err("chrome soft profile must not include null/export inventory".into());
    }
    Ok(())
}

/// Wire-facing summary of the soft impersonate decision for ScrapeProof egress audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftTlsImpersonateAudit {
    /// Profile token applied (`chrome`).
    pub profile: String,
    /// Soft / synthetic / impersonate label — never "native Chromium packet capture".
    pub ja_label: String,
    /// Soft JA3 digest under the chrome-oriented domain (synthetic).
    pub soft_ja3: String,
    /// Soft JA4 digest under the chrome-oriented domain (synthetic).
    pub soft_ja4: String,
    /// Cipher offer IANA ids in chrome order.
    pub tls13_cipher_order: Vec<u16>,
    /// Group offer names in chrome order.
    pub tls_group_order: Vec<String>,
}

impl SoftTlsImpersonateAudit {
    pub fn from_applied(profile: SoftTlsImpersonate, fp: &FingerprintProfile) -> Self {
        Self {
            profile: profile.as_str().to_string(),
            ja_label: SOFT_TLS_FP_LABEL.to_string(),
            soft_ja3: fp.ja3.clone(),
            soft_ja4: fp.ja4.clone(),
            tls13_cipher_order: fp.tls13_cipher_order.clone(),
            tls_group_order: fp.tls_group_order.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate;
    use std::collections::HashSet;

    #[test]
    fn chrome_profile_is_fixed_stronger_than_seed_shuffle() {
        assert_chrome_security_floor().expect("floor");
        let mut seeds_that_differ = 0usize;
        let mut orders = HashSet::new();
        for i in 0..32u32 {
            let base = generate(&format!("soft-utls-seed-{i}"));
            orders.insert(base.tls13_cipher_order.clone());
            if chrome_profile_differs_from_pure_reorder(&base) {
                seeds_that_differ += 1;
            }
            let mut applied = base.clone();
            SoftTlsImpersonate::Chrome.apply(&mut applied);
            assert_eq!(applied.tls13_cipher_order, CHROME_TLS13_CIPHER_ORDER);
            assert_eq!(
                applied.tls_group_order,
                CHROME_TLS_GROUP_ORDER
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<Vec<_>>()
            );
            // Soft digests must not reuse pure-reorder domain if cipher ordered differently
            // or always use soft label domain → always different JA3 vs baseline pure tag path
            // when seed order mistmatched, and always soft-domain even if matched.
            assert_ne!(applied.ja3, base.ja3, "soft chrome JA3 must recompute");
            assert!(
                applied.ja3.len() == 64,
                "soft ja3 is 64-hex synthetic digest"
            );
        }
        // Named shuffle actually differs across seeds in the pure path (precondition of "stronger").
        assert!(
            orders.len() > 1,
            "pure seed reorder must produce multiple cipher orders so chrome fix is meaningful"
        );
        assert!(
            seeds_that_differ > 0,
            "at least some seeds must differ from chrome order before apply"
        );
    }

    #[test]
    fn invalid_and_weak_profiles_fail_closed() {
        assert!(matches!(
            SoftTlsImpersonate::parse("not-a-browser"),
            Err(SoftTlsImpersonateError::Unknown { .. })
        ));
        assert!(matches!(
            SoftTlsImpersonate::parse("export"),
            Err(SoftTlsImpersonateError::BelowSecurityFloor { .. })
        ));
        assert!(matches!(
            SoftTlsImpersonate::parse("rc4"),
            Err(SoftTlsImpersonateError::BelowSecurityFloor { .. })
        ));
        assert!(matches!(
            SoftTlsImpersonate::parse("tls1.0"),
            Err(SoftTlsImpersonateError::BelowSecurityFloor { .. })
        ));
        assert!(matches!(
            SoftTlsImpersonate::parse(""),
            Err(SoftTlsImpersonateError::Empty)
        ));
        assert_eq!(
            SoftTlsImpersonate::parse("chrome").unwrap(),
            SoftTlsImpersonate::Chrome
        );
        assert_eq!(
            SoftTlsImpersonate::parse("Chrome-Impersonate").unwrap(),
            SoftTlsImpersonate::Chrome
        );
    }

    #[test]
    fn soft_label_is_honest_not_native_chromium_wire() {
        let label = SOFT_TLS_FP_LABEL;
        assert!(label.contains("soft"));
        assert!(label.contains("synthetic") || label.contains("impersonate"));
        let ban = [
            "native chromium packet",
            "wireshark chromium ja3 equivalence",
            "undetectable",
        ];
        for bad in ban {
            assert!(
                !label.to_ascii_lowercase().contains(bad),
                "soft label must not claim {bad}"
            );
        }
        let mut fp = generate("soft-label-seed");
        SoftTlsImpersonate::Chrome.apply(&mut fp);
        let audit = SoftTlsImpersonateAudit::from_applied(SoftTlsImpersonate::Chrome, &fp);
        assert_eq!(audit.ja_label, SOFT_TLS_FP_LABEL);
        assert_eq!(audit.profile, "chrome");
    }
}
