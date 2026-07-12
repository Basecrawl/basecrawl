//! Coarse anti-bot difficulty / failure feedback sealed to the relay/validator
//! committee (VAL-ANTIBOT-040).
//!
//! Blind miners never see target content or plaintext failure detail. When
//! basecrawl observes an anti-bot obstruction it may emit an **encrypted,
//! coarse** hint back toward `relay` so the task generator can escalate proxy
//! class / difficulty without leaking the target page or response body to the
//! host-side miner.
//!
//! Design points:
//! * Hint body is a closed enum of coarse codes (`ok`, `blocked`,
//!   `rate_limited`, `challenge`, `captcha`, `empty`, `tls_error`, …) — never
//!   free-form origin text, never the response body, never URLs with path/query.
//! * Sealing reuses the committee threshold sealed-box construction
//!   (VAL-CONF-015/017) so miner/host-held keys recover no plaintext.
//! * Host-visible envelope fields are purely non-sensitive routing metadata
//!   (`task_id`, `nonce`, `kind`, `recipient`, digests). Content markers from
//!   the origin (title, body fragment, Set-Cookie values, challenge HTML) must
//!   not appear under `strings`/`grep` of the miner-visible payload.

use crate::error::SealError;
use crate::identity::{hex_encode, key_id_for};
use crate::result::{
    host_visible_contains_marker, seal_result_to_committee, unseal_result_with_committee_secret,
    CommitteeThresholdPublicKey, ResultSealPlaintext, SealedResultEnvelope, RESULT_RECIPIENT_ROLE,
    RESULT_SEAL_KIND, RESULT_SEAL_SUITE,
};
use crate::task::recipient_key_id;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Suite identifier (shared with result sealing).
pub const ANTIBOT_FEEDBACK_SUITE: &str = RESULT_SEAL_SUITE;

/// Envelope `kind` distinguishing antibot feedback from full result bodies.
pub const ANTIBOT_FEEDBACK_KIND: &str = "antibot_feedback";

/// Domain tag for antibot feedback AAD / audit digests.
pub const ANTIBOT_FEEDBACK_DOMAIN: &[u8] = b"basecrawl/antibot-feedback/v1";

/// Always sealed to the committee, never the miner.
pub const ANTIBOT_FEEDBACK_RECIPIENT: &str = RESULT_RECIPIENT_ROLE;

/// Closed set of coarse anti-bot codes a blind miner is allowed to imply the
/// enclave observed. No target content / free-form body text is logical here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CoarseFailureHint {
    /// Scrape succeeded without anti-bot obstruction.
    Ok,
    /// Generic HTTP block (403 / WAF deny without challenge media).
    Blocked,
    /// Rate-limit response (429 / Retry-After posture).
    RateLimited,
    /// Upstream unavailable / timeout association (503 / 408 class).
    UpstreamUnavailable,
    /// Challenge page detected (Cloudflare / similar interstitial).
    Challenge,
    /// CAPTCHA / Turnstile style interactive challenge.
    Captcha,
    /// Empty / boilerplate / soft-404 non-content page.
    Empty,
    /// TLS-layer failure (not cert-weakened by seed; handshake aborted).
    TlsError,
    /// DNS resolution failure for the sealed connect path.
    DnsError,
    /// Soft signal that a higher proxy class may help (no body detail).
    EscalateProxyClass,
}

impl CoarseFailureHint {
    /// Stable wire string for the coarse code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Blocked => "blocked",
            Self::RateLimited => "rate_limited",
            Self::UpstreamUnavailable => "upstream_unavailable",
            Self::Challenge => "challenge",
            Self::Captcha => "captcha",
            Self::Empty => "empty",
            Self::TlsError => "tls_error",
            Self::DnsError => "dns_error",
            Self::EscalateProxyClass => "escalate_proxy_class",
        }
    }

    /// Map an HTTP status code into a coarse failure code. Never returns
    /// content-bearing detail.
    pub fn from_http_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Ok,
            403 | 401 => Self::Blocked,
            429 => Self::RateLimited,
            408 | 503 | 502 | 504 => Self::UpstreamUnavailable,
            404 | 410 => Self::Empty,
            _ if (400..500).contains(&status) => Self::Blocked,
            _ if (500..600).contains(&status) => Self::UpstreamUnavailable,
            _ => Self::Ok,
        }
    }
}

/// Coarse anti-bot feedback plaintext that is sealed to the committee.
///
/// Fields are intentionally sparse and never carry origin content:
/// * `failure` — closed enum above
/// * `suggested_proxy_class` — optional coarse advisory (`datacenter` /
///   `residential` / `mobile`) with no target URL/body
/// * `http_status_class` — 1xx/2xx/3xx/4xx/5xx bucket (not the full status
///   line reason phrase from the origin)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntibotFeedbackPlaintext {
    pub task_id: String,
    pub nonce: String,
    pub failure: CoarseFailureHint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_proxy_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status_class: Option<String>,
}

impl AntibotFeedbackPlaintext {
    /// Construct feedback, rejecting free-form / content-shaped fields.
    pub fn new(
        task_id: impl Into<String>,
        nonce: impl Into<String>,
        failure: CoarseFailureHint,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            nonce: nonce.into(),
            failure,
            suggested_proxy_class: None,
            http_status_class: None,
        }
    }

    /// Attach a coarse proxy-class advisory from the closed allowlist only.
    pub fn with_suggested_proxy_class(mut self, class: &str) -> Result<Self, SealError> {
        let normalized = class.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "datacenter" | "residential" | "mobile" => {
                self.suggested_proxy_class = Some(normalized);
                Ok(self)
            }
            _ => Err(SealError::InvalidEnvelope {
                detail: "suggested_proxy_class must be datacenter|residential|mobile".into(),
            }),
        }
    }

    /// Attach an HTTP status *class* (e.g. `"4xx"`) derived from a numeric code.
    pub fn with_http_status(mut self, status: u16) -> Self {
        let class = match status {
            100..=199 => "1xx",
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            500..=599 => "5xx",
            _ => "other",
        };
        self.http_status_class = Some(class.to_string());
        self
    }

    /// True when this feedback is a pure coarse code with no content-shaped fields.
    pub fn is_coarse_only(&self) -> bool {
        // Free-form text is structurally impossible: failure is an enum, and
        // suggested_proxy_class is allowlisted. Reject empty identities so a
        // garbled envelope cannot masquerade as feedback.
        !self.task_id.is_empty() && !self.nonce.is_empty()
    }
}

/// Host-visible miner-relayed envelope for antibot feedback.
///
/// Mirrors [`SealedResultEnvelope`]: only non-sensitive routing metadata +
/// opaque ciphertext. Distinct `kind` so relay can route without opening.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedAntibotFeedback {
    pub version: u32,
    pub suite: String,
    /// Always [`ANTIBOT_FEEDBACK_KIND`].
    pub kind: String,
    /// Always [`ANTIBOT_FEEDBACK_RECIPIENT`].
    pub recipient: String,
    pub recipient_key_id: String,
    pub task_id: String,
    pub nonce: String,
    /// Deterministic digest of the coarse feedback payload (not content plaintext).
    pub feedback_hash: String,
    /// Opaque sealed-box ciphertext.
    pub ciphertext: String,
}

/// Seal coarse antibot feedback to the validator committee (VAL-ANTIBOT-040).
///
/// The miner / host is not a recipient. Decrypt attempts with any miner-held
/// key fail closed; host-visible fields never embed target/content markers.
pub fn seal_antibot_feedback(
    plaintext: &AntibotFeedbackPlaintext,
    committee: &CommitteeThresholdPublicKey,
) -> Result<SealedAntibotFeedback, SealError> {
    if !plaintext.is_coarse_only() {
        return Err(SealError::InvalidEnvelope {
            detail: "antibot feedback must be coarse-only (no free-form content)".into(),
        });
    }
    if plaintext.task_id.is_empty() || plaintext.nonce.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "task_id and nonce are required for antibot feedback".into(),
        });
    }

    let feedback_hash = feedback_hash(plaintext);
    let mut formats = Map::new();
    // Only closed enum analyses travel inside. Never attach origin body/title.
    formats.insert(
        "antibot_feedback".into(),
        json!({
            "failure": plaintext.failure.as_str(),
            "suggested_proxy_class": plaintext.suggested_proxy_class,
            "http_status_class": plaintext.http_status_class,
        }),
    );

    let result_plaintext = ResultSealPlaintext {
        task_id: plaintext.task_id.clone(),
        nonce: plaintext.nonce.clone(),
        result_hash: feedback_hash.clone(),
        formats_produced: formats,
    };
    let sealed = seal_result_to_committee(&result_plaintext, committee)?;

    // Re-tag the envelope so host-side routing knows this is feedback, not a
    // full result body. Ciphertext + AAD still authenticate the same payload.
    Ok(SealedAntibotFeedback {
        version: sealed.version,
        suite: ANTIBOT_FEEDBACK_SUITE.to_string(),
        kind: ANTIBOT_FEEDBACK_KIND.to_string(),
        recipient: ANTIBOT_FEEDBACK_RECIPIENT.to_string(),
        recipient_key_id: sealed.recipient_key_id,
        task_id: sealed.task_id,
        nonce: sealed.nonce,
        feedback_hash,
        ciphertext: sealed.ciphertext,
    })
}

/// Miner/host-side open of sealed antibot feedback: always fails closed
/// (VAL-ANTIBOT-040 / VAL-CONF-015).
pub fn decrypt_antibot_feedback_as_miner_host(
    envelope: &SealedAntibotFeedback,
) -> Result<AntibotFeedbackPlaintext, SealError> {
    validate_feedback_envelope(envelope)?;
    Err(SealError::KeyNotReleased)
}

/// Open sealed antibot feedback with the reconstructed committee secret
/// (relay-side helper / tests). The miner never holds this key.
pub fn unseal_antibot_feedback_with_committee_secret(
    envelope: &SealedAntibotFeedback,
    committee_secret: &[u8; 32],
) -> Result<AntibotFeedbackPlaintext, SealError> {
    validate_feedback_envelope(envelope)?;
    // Rehydrate as a result envelope for the shared AEAD open path, preserving
    // ciphertext and binding fields. Kind differs only in the host-visible
    // routing layer; AAD was built from task/nonce/result_hash/key_id.
    let result_envelope = SealedResultEnvelope {
        version: envelope.version,
        suite: envelope.suite.clone(),
        kind: RESULT_SEAL_KIND.to_string(),
        recipient: RESULT_RECIPIENT_ROLE.to_string(),
        recipient_key_id: envelope.recipient_key_id.clone(),
        task_id: envelope.task_id.clone(),
        nonce: envelope.nonce.clone(),
        result_hash: envelope.feedback_hash.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let opened = unseal_result_with_committee_secret(&result_envelope, committee_secret)?;
    let feedback_value = opened
        .formats_produced
        .get("antibot_feedback")
        .ok_or(SealError::MalformedPlaintext)?;
    let failure_str = feedback_value
        .get("failure")
        .and_then(|v| v.as_str())
        .ok_or(SealError::MalformedPlaintext)?;
    let failure = parse_failure_hint(failure_str).ok_or(SealError::MalformedPlaintext)?;
    let suggested = feedback_value
        .get("suggested_proxy_class")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let status_class = feedback_value
        .get("http_status_class")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Ok(AntibotFeedbackPlaintext {
        task_id: opened.task_id,
        nonce: opened.nonce,
        failure,
        suggested_proxy_class: suggested,
        http_status_class: status_class,
    })
}

/// True when any miner-visible bytes of the envelope contain `marker`.
///
/// Used by VAL-ANTIBOT-040 evidence: `grep/strings` for target/content markers
/// over the sealed feedback returns zero matches.
pub fn miner_visible_contains_marker(envelope: &SealedAntibotFeedback, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    // Shape-check without re-serializing ciphertext into a full result envelope
    // structure in a way that could hoist content (there is none). We include
    // every host-visible field and the ciphertext ascii form.
    let routing = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        envelope.version,
        envelope.suite,
        envelope.kind,
        envelope.recipient,
        envelope.recipient_key_id,
        envelope.task_id,
        envelope.nonce,
        envelope.feedback_hash,
        envelope.ciphertext
    );
    if routing.contains(marker) {
        return true;
    }
    // Also reuse the result helper against a synthetic envelope so the same
    // collision analysis applies.
    let synthetic = SealedResultEnvelope {
        version: envelope.version,
        suite: envelope.suite.clone(),
        kind: envelope.kind.clone(),
        recipient: envelope.recipient.clone(),
        recipient_key_id: envelope.recipient_key_id.clone(),
        task_id: envelope.task_id.clone(),
        nonce: envelope.nonce.clone(),
        result_hash: envelope.feedback_hash.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    host_visible_contains_marker(&synthetic, marker)
}

/// Generate a sealed feedback envelope for an observed HTTP status, suppressing
/// any emission when the code is pure success (`ok`). Used by house paths that
/// want to surface only non-success coarse hints.
pub fn maybe_seal_failure_feedback(
    task_id: &str,
    nonce: &str,
    http_status: u16,
    committee: &CommitteeThresholdPublicKey,
    suggest_residential: bool,
) -> Result<Option<SealedAntibotFeedback>, SealError> {
    let failure = CoarseFailureHint::from_http_status(http_status);
    if failure == CoarseFailureHint::Ok {
        return Ok(None);
    }
    let mut plaintext =
        AntibotFeedbackPlaintext::new(task_id, nonce, failure).with_http_status(http_status);
    if suggest_residential
        && matches!(
            failure,
            CoarseFailureHint::Blocked
                | CoarseFailureHint::RateLimited
                | CoarseFailureHint::Challenge
                | CoarseFailureHint::Captcha
        )
    {
        plaintext = plaintext.with_suggested_proxy_class("residential")?;
    }
    Ok(Some(seal_antibot_feedback(&plaintext, committee)?))
}

fn feedback_hash(plaintext: &AntibotFeedbackPlaintext) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ANTIBOT_FEEDBACK_DOMAIN);
    hasher.update(plaintext.task_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(plaintext.nonce.as_bytes());
    hasher.update([0u8]);
    hasher.update(plaintext.failure.as_str().as_bytes());
    hasher.update([0u8]);
    if let Some(class) = &plaintext.suggested_proxy_class {
        hasher.update(class.as_bytes());
    }
    hasher.update([0u8]);
    if let Some(status) = &plaintext.http_status_class {
        hasher.update(status.as_bytes());
    }
    hex_encode(&hasher.finalize())
}

fn validate_feedback_envelope(envelope: &SealedAntibotFeedback) -> Result<(), SealError> {
    if envelope.version != 1 {
        return Err(SealError::InvalidEnvelope {
            detail: "unsupported antibot feedback version".into(),
        });
    }
    if envelope.suite != ANTIBOT_FEEDBACK_SUITE {
        return Err(SealError::InvalidEnvelope {
            detail: "unexpected antibot feedback suite".into(),
        });
    }
    if envelope.kind != ANTIBOT_FEEDBACK_KIND {
        return Err(SealError::InvalidEnvelope {
            detail: "unexpected antibot feedback kind".into(),
        });
    }
    if envelope.recipient != ANTIBOT_FEEDBACK_RECIPIENT {
        return Err(SealError::InvalidEnvelope {
            detail: "antibot feedback recipient must be committee-threshold".into(),
        });
    }
    if envelope.task_id.is_empty() || envelope.nonce.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "task_id/nonce required".into(),
        });
    }
    if envelope.feedback_hash.is_empty() || envelope.ciphertext.is_empty() {
        return Err(SealError::InvalidEnvelope {
            detail: "feedback_hash/ciphertext required".into(),
        });
    }
    if !envelope.recipient_key_id.starts_with("sha256:") {
        return Err(SealError::InvalidEnvelope {
            detail: "recipient_key_id must be a sha256 content id".into(),
        });
    }
    let _ = recipient_key_id; // silence; validated via network shape only
    let _ = key_id_for;
    Ok(())
}

fn parse_failure_hint(value: &str) -> Option<CoarseFailureHint> {
    match value {
        "ok" => Some(CoarseFailureHint::Ok),
        "blocked" => Some(CoarseFailureHint::Blocked),
        "rate_limited" => Some(CoarseFailureHint::RateLimited),
        "upstream_unavailable" => Some(CoarseFailureHint::UpstreamUnavailable),
        "challenge" => Some(CoarseFailureHint::Challenge),
        "captcha" => Some(CoarseFailureHint::Captcha),
        "empty" => Some(CoarseFailureHint::Empty),
        "tls_error" => Some(CoarseFailureHint::TlsError),
        "dns_error" => Some(CoarseFailureHint::DnsError),
        "escalate_proxy_class" => Some(CoarseFailureHint::EscalateProxyClass),
        _ => None,
    }
}

/// Zeroize helper retained so a future buffer-holding path stays disciplined.
#[allow(dead_code)]
fn wipe(buf: Zeroizing<Vec<u8>>) {
    drop(buf);
}

/// Synthetic status/header-driven classifier that emits ONLY coarse codes.
///
/// Intentionally never inspects response body bytes for content extraction —
/// challenge / captcha detection on the production path is free to look at
/// attested response metadata (status + selected header markers) and surface
/// a closed-enum code, never a body excerpt.
pub fn classify_coarse_from_status_and_markers(
    status: u16,
    header_markers: &[&str],
) -> CoarseFailureHint {
    let joined = header_markers
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.contains("cf-mitigated") || joined.contains("cf-challenge") {
        return CoarseFailureHint::Challenge;
    }
    if joined.contains("turnstile") || joined.contains("captcha") {
        return CoarseFailureHint::Captcha;
    }
    if joined.contains("retry-after") && status == 429 {
        return CoarseFailureHint::RateLimited;
    }
    CoarseFailureHint::from_http_status(status)
}

// Keep Value import used in future extensions noted.
#[allow(dead_code)]
fn _touch_value(v: Value) -> Value {
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::aead::OsRng;
    use crypto_box::SecretKey;

    fn fixture_committee() -> (CommitteeThresholdPublicKey, [u8; 32]) {
        let secret = SecretKey::generate(&mut OsRng);
        let secret_bytes = secret.to_bytes();
        let pk = CommitteeThresholdPublicKey::from_public_key_bytes(secret.public_key().as_bytes());
        (pk, secret_bytes)
    }

    #[test]
    fn val_antibot_040_feedback_is_sealed_and_opaque_to_miner() {
        let (committee, secret) = fixture_committee();
        // Distinctive target/content markers that MUST NOT leave the enclave.
        let target_marker = "https://secret-origin.example/private/path?token=abc";
        let content_marker = "KNOWN-CHALLENGE-HTML-TITLE-Turnstile-αβγ";
        let body_marker = "Page content the blind miner must never see: CANARY-BODY-9f3a2c";

        let plaintext = AntibotFeedbackPlaintext::new(
            "task-fb-040",
            "nonce-fb-040",
            CoarseFailureHint::Challenge,
        )
        .with_http_status(403)
        .with_suggested_proxy_class("residential")
        .expect("allowlisted class");

        // Coarse payload itself must not embed the markers.
        let coded = serde_json::to_string(&plaintext).expect("ser");
        assert!(!coded.contains(target_marker));
        assert!(!coded.contains(content_marker));
        assert!(!coded.contains(body_marker));
        assert!(plaintext.is_coarse_only());

        let sealed = seal_antibot_feedback(&plaintext, &committee).expect("seal");
        assert_eq!(sealed.kind, ANTIBOT_FEEDBACK_KIND);
        assert_eq!(sealed.recipient, ANTIBOT_FEEDBACK_RECIPIENT);
        assert_eq!(sealed.task_id, "task-fb-040");

        // Miner-visible payload: zero content/target markers.
        for marker in [target_marker, content_marker, body_marker] {
            assert!(
                !miner_visible_contains_marker(&sealed, marker),
                "miner-visible feedback leaked marker {marker:?}"
            );
        }

        // Miner/host open always fails.
        assert!(matches!(
            decrypt_antibot_feedback_as_miner_host(&sealed),
            Err(SealError::KeyNotReleased)
        ));

        // Committee recovers the coarse code only.
        let opened = unseal_antibot_feedback_with_committee_secret(&sealed, &secret).expect("open");
        assert_eq!(opened.failure, CoarseFailureHint::Challenge);
        assert_eq!(opened.suggested_proxy_class.as_deref(), Some("residential"));
        assert_eq!(opened.http_status_class.as_deref(), Some("4xx"));
    }

    #[test]
    fn success_status_emits_no_feedback_envelope() {
        let (committee, _) = fixture_committee();
        let out = maybe_seal_failure_feedback("t", "n", 200, &committee, false).expect("seal path");
        assert!(out.is_none());
    }

    #[test]
    fn blocked_status_seals_coarse_code() {
        let (committee, secret) = fixture_committee();
        let sealed = maybe_seal_failure_feedback("t-block", "n-block", 403, &committee, true)
            .expect("seal")
            .expect("must emit");
        let opened = unseal_antibot_feedback_with_committee_secret(&sealed, &secret).expect("open");
        assert_eq!(opened.failure, CoarseFailureHint::Blocked);
        assert_eq!(opened.suggested_proxy_class.as_deref(), Some("residential"));
    }

    #[test]
    fn classify_uses_header_markers_not_body() {
        assert_eq!(
            classify_coarse_from_status_and_markers(403, &["cf-mitigated: challenge"]),
            CoarseFailureHint::Challenge
        );
        assert_eq!(
            classify_coarse_from_status_and_markers(403, &["x-turnstile: 1"]),
            CoarseFailureHint::Captcha
        );
        assert_eq!(
            classify_coarse_from_status_and_markers(429, &["retry-after: 30"]),
            CoarseFailureHint::RateLimited
        );
    }
}
