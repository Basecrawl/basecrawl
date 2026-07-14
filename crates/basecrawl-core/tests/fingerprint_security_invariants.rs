//! VAL-ANTIBOT-038 / 039 / 040: security invariants of the seeded fingerprint generator.
//!
//! * 038 — security-critical TLS parameters (cert validation, negotiated TLS version) stay
//!   fixed across many seeds; only non-security fingerprint dimensions vary.
//! * 039 — fingerprint diversity never breaks in-enclave cert/transcript capture or the
//!   report_data L2 binding (risk BOT-08).
//! * 040 — any anti-bot difficulty/failure feedback basecrawl emits toward relay is coarse
//!   and sealed so a blind miner never receives plaintext target/content markers.

use basecrawl_core::canonical;
use basecrawl_fp::{
    assert_security_invariants, generate, generate_validated, security_critical_tls_params,
    security_snapshot_for_seed, CertificateValidationPolicy, REQUIRED_NEGOTIATED_TLS_VERSION,
};
use basecrawl_proof::{
    Attestation, CertificateValidation, CompletenessManifest, Egress, Request, Response,
    ResultBlock, ScrapeProof, SdkSignature, Tls, SCRAPE_PROOF_VERSION,
};
use basecrawl_seal::{
    decrypt_antibot_feedback_as_miner_host, maybe_seal_failure_feedback,
    miner_visible_contains_marker, seal_antibot_feedback,
    unseal_antibot_feedback_with_committee_secret, AntibotFeedbackPlaintext, CoarseFailureHint,
    CommitteeThresholdPublicKey, SealError,
};
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use std::collections::{BTreeMap, HashSet};

fn sample_proof_for_seed(seed: &str, cert_chain_hash: &str, transcript_hash: &str) -> ScrapeProof {
    ScrapeProof {
        version: SCRAPE_PROOF_VERSION,
        task_id: Some(format!("task-fp-sec-{seed}")),
        nonce: Some(format!("nonce-fp-sec-{seed}")),
        request: Request {
            method: "GET".into(),
            url: "https://example.com/resource".into(),
            headers_hash: Some("11".repeat(32)),
            body_hash: Some("22".repeat(32)),
            request_hash: Some("33".repeat(32)),
            formats: vec!["markdown".into()],
        },
        tls: Tls {
            certificate_validation: CertificateValidation::Validated,
            negotiated_version: Some(REQUIRED_NEGOTIATED_TLS_VERSION.to_string()),
            sni: Some("example.com".into()),
            cert_chain_hash: Some(cert_chain_hash.to_string()),
            handshake_transcript_hash: Some(transcript_hash.to_string()),
            server_cert_chain_der: vec!["YmxvYw==".into()], // non-empty DER standing-in
            ..Tls::default()
        },
        response: Response {
            status_code: Some(200),
            headers_hash: Some("66".repeat(32)),
            body_hash: Some("77".repeat(32)),
            content_length: Some(12),
            ..Response::default()
        },
        result: ResultBlock {
            formats_produced: BTreeMap::from([(
                "markdown".into(),
                serde_json::Value::String("ok".into()),
            )]),
            result_hash: Some("88".repeat(32)),
            completeness_manifest: CompletenessManifest::default(),
            manifest_sha256: Some("99".repeat(32)),
            crawled_urls: Vec::new(),
        },
        egress: Egress {
            egress_ip: Some("203.0.113.5".into()),
            landmark_rtts: BTreeMap::new(),
            timestamp: Some("2026-07-12T00:00:00Z".into()),
            fingerprint_seed: Some(seed.to_string()),
            proxy_class: None,
            fetch_path: None,
            soft_tls_impersonate: None,
        },
        attestation: Attestation::default(),
        sdk_signature: SdkSignature {
            enclave_pubkey: Some("aa".repeat(32)),
            sig: None,
        },
    }
}

fn fixture_committee() -> (CommitteeThresholdPublicKey, [u8; 32]) {
    let secret = SecretKey::generate(&mut OsRng);
    let secret_bytes = secret.to_bytes();
    let pk = CommitteeThresholdPublicKey::from_public_key_bytes(secret.public_key().as_bytes());
    (pk, secret_bytes)
}

// ---------------------------------------------------------------------------
// VAL-ANTIBOT-038
// ---------------------------------------------------------------------------

#[test]
fn val_antibot_038_security_critical_tls_params_fixed_across_many_seeds() {
    let baseline = security_critical_tls_params();
    assert_eq!(
        baseline.certificate_validation,
        CertificateValidationPolicy::WebPkiValidated
    );
    assert!(
        !baseline.seed_may_weaken_cert_validation,
        "seeds must never weaken certificate validation"
    );
    assert_eq!(baseline.required_negotiated_version, "1.3");
    assert_eq!(
        REQUIRED_NEGOTIATED_TLS_VERSION, "1.3",
        "authenticity-capable scrapes require negotiated TLS 1.3"
    );

    let mut security_jsons = HashSet::new();
    let mut ja3s = HashSet::new();
    let mut cipher_orders = HashSet::new();
    let first = security_snapshot_for_seed("baseline-038");

    for i in 0..64u32 {
        let seed = format!("antibot-038-seed-{i}");
        let profile = generate_validated(&seed).expect("validated generate");
        assert_security_invariants(&profile).expect("security invariants");

        let snap = security_snapshot_for_seed(&seed);
        assert_eq!(
            snap.security, baseline,
            "seed {seed} altered security-critical TLS params"
        );
        // Every authenticity snapshot claims TLS 1.3 + WebPKI validated.
        assert_eq!(snap.security.required_negotiated_version, "1.3");
        assert!(!snap.security.seed_may_weaken_cert_validation);
        assert!(snap.security.cert_chain_capture_enabled);
        assert!(snap.security.transcript_capture_enabled);

        security_jsons.insert(serde_json::to_string(&snap.security).unwrap());
        ja3s.insert(snap.ja3.clone());
        cipher_orders.insert(snap.tls13_cipher_order.clone());

        // Cipher ids stay inside the closed TLS 1.3 set for every seed.
        for suite in &profile.tls13_cipher_order {
            assert!(
                matches!(suite, 0x1301..=0x1303),
                "seed selected non-TLS-1.3 suite 0x{suite:04x}"
            );
        }
    }

    assert_eq!(
        security_jsons.len(),
        1,
        "security-critical TLS params must be bit-identical across seeds"
    );
    // Non-security dimensions must still vary (038 only constrains the security half).
    assert!(
        ja3s.len() >= 2
            || cipher_orders.len() >= 2
            || first.user_agent != security_snapshot_for_seed("other-ua-seed").user_agent,
        "non-security fingerprint dimensions must still vary across seeds"
    );
}

// ---------------------------------------------------------------------------
// VAL-ANTIBOT-039 (BOT-08)
// ---------------------------------------------------------------------------

#[test]
fn val_antibot_039_seed_diversity_preserves_l2_cert_transcript_binding() {
    let security = security_critical_tls_params();
    assert!(
        security.cert_chain_capture_enabled && security.transcript_capture_enabled,
        "BOT-08: capture must stay enabled for every seed"
    );
    assert!(security.l2_binding_includes_cert_and_transcript);

    // Simulate proofs produced under differing seeds. Each still carries a
    // non-empty cert_chain_hash + handshake_transcript_hash, and both remain
    // bound into report_data. A missing binding would make attestation_report_data
    // fail or produce a digest independent of those fields.
    let seeds = [
        "l2-bind-alpha",
        "l2-bind-beta",
        "l2-bind-gamma",
        "l2-bind-delta",
        "l2-bind-epsilon",
        "l2-bind-zeta",
        "l2-bind-eta",
        "l2-bind-theta",
    ];

    for (i, seed_raw) in seeds.iter().enumerate() {
        let profile = generate(seed_raw);
        assert_security_invariants(&profile).unwrap();

        // Distinct per-seed synthetic capture digests (stand in for real in-enclave
        // cert/transcript capture under diversified ClientHello parameters).
        let cert_hash = format!("{:02x}", i + 1).repeat(32);
        let transcript_hash = format!("{:02x}", i + 0xA0).repeat(32);
        let seed = profile.seed.clone();
        let proof = sample_proof_for_seed(&seed, &cert_hash, &transcript_hash);

        assert_eq!(
            proof.tls.certificate_validation,
            CertificateValidation::Validated,
            "seed must not flip cert validation to insecure"
        );
        assert_eq!(
            proof.tls.negotiated_version.as_deref(),
            Some("1.3"),
            "negotiated version must remain 1.3 under every seed"
        );
        assert!(
            proof
                .tls
                .cert_chain_hash
                .as_ref()
                .is_some_and(|h| h.len() == 64),
            "cert_chain_hash must still be captured under seed {seed}"
        );
        assert!(
            proof
                .tls
                .handshake_transcript_hash
                .as_ref()
                .is_some_and(|h| !h.is_empty()),
            "handshake_transcript_hash must still be captured under seed {seed}"
        );

        let report_data = canonical::attestation_report_data(&proof)
            .unwrap_or_else(|e| panic!("report_data must form under seed {seed}: {e}"));
        assert_eq!(
            report_data.len(),
            128,
            "SHA-512 report_data is 64 bytes hex"
        );

        // Mutating cert_chain_hash must change report_data (field is committed).
        let mut mutated_cert = proof.clone();
        mutated_cert.tls.cert_chain_hash = Some("ff".repeat(32));
        let mutated_rd = canonical::attestation_report_data(&mutated_cert).unwrap();
        assert_ne!(
            report_data, mutated_rd,
            "cert_chain_hash must be bound into report_data (BOT-08)"
        );

        // Mutating handshake_transcript_hash must change report_data.
        let mut mutated_tx = proof.clone();
        mutated_tx.tls.handshake_transcript_hash = Some("ee".repeat(32));
        let mutated_tx_rd = canonical::attestation_report_data(&mutated_tx).unwrap();
        assert_ne!(
            report_data, mutated_tx_rd,
            "handshake_transcript_hash must be bound into report_data (BOT-08)"
        );

        // Mutating the fingerprint_seed must also change report_data (auditability).
        let mut mutated_seed = proof.clone();
        mutated_seed.egress.fingerprint_seed = Some("00".repeat(32));
        let mutated_seed_rd = canonical::attestation_report_data(&mutated_seed).unwrap();
        assert_ne!(
            report_data, mutated_seed_rd,
            "fingerprint_seed must remain committed under diversified seeds"
        );

        // Dropping either capture field makes report_data construction fail — diversity
        // is not allowed to produce a proof with a missing L2 binding.
        let mut missing_cert = proof.clone();
        missing_cert.tls.cert_chain_hash = None;
        assert!(
            canonical::attestation_report_data(&missing_cert).is_err(),
            "missing cert_chain_hash must be refused"
        );
        let mut missing_tx = proof;
        missing_tx.tls.handshake_transcript_hash = None;
        assert!(
            canonical::attestation_report_data(&missing_tx).is_err(),
            "missing handshake_transcript_hash must be refused"
        );
    }
}

// ---------------------------------------------------------------------------
// VAL-ANTIBOT-040
// ---------------------------------------------------------------------------

#[test]
fn val_antibot_040_failure_feedback_is_coarse_and_sealed_from_miner() {
    let (committee, secret) = fixture_committee();

    // Distinctive target/content markers a miner must never observe in feedback.
    let target_url = "https://anti-bot.example/private/checkout?session=SECRETTOKEN";
    let content_title = "Attention Required! | Cloudflare Turnstile Challenge Page";
    let body_canary = "KNOWN-FAILURE-BODY-CANARY-markdown-αβγ-<main>secret</main>";
    let set_cookie = "cf_clearance=LEAKEDCOOKIEVALUE123; path=/";

    let plaintext = AntibotFeedbackPlaintext::new(
        "task-antibot-040",
        "nonce-antibot-040",
        CoarseFailureHint::Challenge,
    )
    .with_http_status(403)
    .with_suggested_proxy_class("residential")
    .expect("allowlisted proxy class");

    // Coarse-only construction never copies origin markers into the plaintext.
    let coded = serde_json::to_string(&plaintext).expect("ser");
    for marker in [target_url, content_title, body_canary, set_cookie] {
        assert!(
            !coded.contains(marker),
            "coarse feedback plaintext must not embed marker {marker:?}"
        );
    }
    assert!(plaintext.is_coarse_only());

    let sealed =
        seal_antibot_feedback(&plaintext, &committee).expect("seal to committee must succeed");

    // Miner-visible envelope: grepping for target/content markers returns zero matches.
    for marker in [target_url, content_title, body_canary, set_cookie] {
        assert!(
            !miner_visible_contains_marker(&sealed, marker),
            "miner-visible sealed feedback leaked {marker:?}"
        );
    }
    // Structural host-visible fields never carry free-form body text either.
    let host_json = serde_json::to_string(&sealed).expect("envelope ser");
    for marker in [target_url, content_title, body_canary, set_cookie] {
        assert!(!host_json.contains(marker));
    }

    // Miner / host open always fails closed — no plaintext recovery.
    assert!(matches!(
        decrypt_antibot_feedback_as_miner_host(&sealed),
        Err(SealError::KeyNotReleased)
    ));

    // Only the committee recovers the coarse code.
    let opened =
        unseal_antibot_feedback_with_committee_secret(&sealed, &secret).expect("committee open");
    assert_eq!(opened.failure, CoarseFailureHint::Challenge);
    assert_eq!(opened.suggested_proxy_class.as_deref(), Some("residential"));
    assert_eq!(opened.http_status_class.as_deref(), Some("4xx"));
    // Opened payload still contains no origin markers.
    let opened_json = serde_json::to_string(&opened).unwrap();
    for marker in [target_url, content_title, body_canary, set_cookie] {
        assert!(!opened_json.contains(marker));
    }
}

#[test]
fn val_antibot_040_success_emits_no_miner_visible_feedback() {
    let (committee, _) = fixture_committee();
    let out = maybe_seal_failure_feedback(
        "task-ok", "nonce-ok", 200, &committee, /*suggest_residential=*/ false,
    )
    .expect("path succeeds");
    assert!(
        out.is_none(),
        "successful scrapes must not emit failure feedback for the miner to inspect"
    );
}

#[test]
fn val_antibot_040_blocked_hint_stays_opaque_after_seal() {
    let (committee, secret) = fixture_committee();
    let body_marker = "ORIGIN-BLOCK-PAGE-CONTENT-UNIQUE-99zz";
    let sealed = maybe_seal_failure_feedback("task-block", "nonce-block", 403, &committee, true)
        .expect("seal")
        .expect("must emit for 403");
    assert!(!miner_visible_contains_marker(&sealed, body_marker));
    let opened = unseal_antibot_feedback_with_committee_secret(&sealed, &secret).expect("open");
    assert_eq!(opened.failure, CoarseFailureHint::Blocked);
}
