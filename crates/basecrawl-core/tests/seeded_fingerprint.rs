//! VAL-ANTIBOT-033..037: seeded fingerprint generator diversity, determinism, auditability,
//! and bounded parameter-space compliance.
//!
//! These tests exercise the pure generator surface directly (no network) so the milestone
//! gate remains deterministic. End-to-end emission of `egress.fingerprint_seed` and its
//! binding into `report_data` is covered by unit tests on egress + canonical.

use basecrawl_core::canonical;
use basecrawl_fp::{
    generate, is_within_parameter_space, normalize_seed, parameter_space, resolve_seed,
    FingerprintProfile,
};
use basecrawl_proof::{
    Attestation, CompletenessManifest, Egress, Request, Response, ResultBlock, ScrapeProof,
    SdkSignature, Tls, SCRAPE_PROOF_VERSION,
};
use std::collections::BTreeMap;

fn sample_proof(seed: &str) -> ScrapeProof {
    ScrapeProof {
        version: SCRAPE_PROOF_VERSION,
        task_id: Some("task-fp".into()),
        nonce: Some("nonce-fp".into()),
        request: Request {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers_hash: Some("11".repeat(32)),
            body_hash: Some("22".repeat(32)),
            request_hash: Some("33".repeat(32)),
            formats: vec!["markdown".into()],
        },
        tls: Tls {
            negotiated_version: Some("1.3".into()),
            sni: Some("example.com".into()),
            cert_chain_hash: Some("44".repeat(32)),
            handshake_transcript_hash: Some("55".repeat(32)),
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
        },
        attestation: Attestation::default(),
        sdk_signature: SdkSignature {
            enclave_pubkey: Some("aa".repeat(32)),
            sig: None,
        },
    }
}

#[test]
fn val_antibot_033_different_seeds_produce_different_ja3_ja4() {
    let a = generate("subnet-miner-alpha");
    let b = generate("subnet-miner-beta");
    // Across the full parameter space a random pair nearly always differs; if it doesn't,
    // scan for at least one divergent pair so the contract holds.
    if a.ja3 == b.ja3 || a.ja4 == b.ja4 {
        let mut found = false;
        for i in 0..32u32 {
            let x = generate(&format!("pair-a-{i}"));
            let y = generate(&format!("pair-b-{i}"));
            if x.ja3 != y.ja3 && x.ja4 != y.ja4 {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "JA3/JA4 must differ across seeds so one rule cannot block the subnet"
        );
    } else {
        assert_ne!(a.ja3, b.ja3);
        assert_ne!(a.ja4, b.ja4);
    }
}

#[test]
fn val_antibot_034_fingerprint_is_deterministic_function_of_seed() {
    let seed = "deterministic-seed-xyz";
    let first = generate(seed);
    let second = generate(seed);
    assert_eq!(first.header_names, second.header_names);
    assert_eq!(first.user_agent, second.user_agent);
    assert_eq!(
        (first.viewport_width, first.viewport_height),
        (second.viewport_width, second.viewport_height)
    );
    assert_eq!(first.timezone, second.timezone);
    assert_eq!(first.locale, second.locale);
    assert_eq!(first.ja3, second.ja3);
    assert_eq!(first.ja4, second.ja4);

    let other = generate("other-deterministic-seed");
    assert!(
        first.header_names != other.header_names
            || first.user_agent != other.user_agent
            || first.viewport_width != other.viewport_width
            || first.timezone != other.timezone
            || first.locale != other.locale,
        "a different seed must diverge at least one of header order/UA/viewport/tz/locale"
    );
}

#[test]
fn val_antibot_035_canvas_webgl_differ_across_seeds() {
    let a = generate("render-noise-a");
    let b = generate("render-noise-b");
    assert_ne!(
        a.canvas_fingerprint, b.canvas_fingerprint,
        "canvas fingerprint must not be a subnet-wide constant"
    );
    assert_ne!(
        a.webgl_fingerprint, b.webgl_fingerprint,
        "WebGL fingerprint must not be a subnet-wide constant"
    );
    // Renderer string is drawn from a small allowlist, so two seeds may share it; the digest
    // above already proves per-seed divergence. Across a broader set, multiple renderers appear.
    let mut renderers = std::collections::HashSet::new();
    for i in 0..32u32 {
        renderers.insert(generate(&format!("webgl-cover-{i}")).webgl_renderer);
    }
    assert!(
        renderers.len() >= 2,
        "WebGL renderer diversity across seeds, got {renderers:?}"
    );
}

#[test]
fn val_antibot_036_fingerprint_seed_bound_into_report_data() {
    let seed = normalize_seed("audit-seed-1");
    let proof = sample_proof(&seed);
    assert_eq!(
        proof.egress.fingerprint_seed.as_deref(),
        Some(seed.as_str()),
        "egress must carry the fingerprint_seed"
    );

    let report_data = canonical::attestation_report_data(&proof).expect("report_data");
    let mut mutated = proof.clone();
    mutated.egress.fingerprint_seed = Some(normalize_seed("other-audit-seed"));
    let mutated_rd = canonical::attestation_report_data(&mutated).expect("mutated report_data");
    assert_ne!(
        report_data, mutated_rd,
        "fingerprint_seed must be committed into the attested report_data digest"
    );
}

#[test]
fn val_antibot_037_emitted_profiles_stay_in_declared_parameter_space() {
    let space = parameter_space();
    assert!(!space.user_agents.is_empty());
    assert!(!space.viewports.is_empty());
    assert!(!space.timezones.is_empty());
    assert!(!space.locales.is_empty());
    assert!(!space.header_orders.is_empty());
    assert_eq!(space.tls13_cipher_suites.len(), 3);

    for i in 0..64u32 {
        let profile = generate(&format!("space-check-{i}"));
        assert!(
            is_within_parameter_space(&profile),
            "profile escaped parameter space: {profile:?}"
        );
        assert!(space.user_agents.contains(&profile.user_agent.as_str()));
        assert!(space
            .viewports
            .contains(&(profile.viewport_width, profile.viewport_height)));
        assert!(space.timezones.contains(&profile.timezone.as_str()));
        assert!(space.locales.contains(&profile.locale.as_str()));
    }
}

#[test]
fn resolve_seed_prefers_explicit_seed_then_task_nonce() {
    let explicit = resolve_seed(Some("mine"), Some("t"), Some("n"), "fb");
    assert_eq!(explicit, normalize_seed("mine"));
    let from_task = resolve_seed(None, Some("task-A"), Some("nonce-B"), "fb");
    assert_eq!(from_task, normalize_seed("task-A\0nonce-B"));
}

#[test]
fn profile_exposes_all_dimensions_required_by_architecture() {
    let p: FingerprintProfile = generate("completeness-check");
    assert!(!p.user_agent.is_empty());
    assert!(p.viewport_width > 0 && p.viewport_height > 0);
    assert!(!p.timezone.is_empty());
    assert!(!p.locale.is_empty());
    assert!(!p.header_names.is_empty());
    assert_eq!(p.tls13_cipher_order.len(), 3);
    assert_eq!(p.tls_group_order.len(), 3);
    assert!(!p.canvas_fingerprint.is_empty());
    assert!(!p.webgl_fingerprint.is_empty());
    assert!(!p.ja3.is_empty());
    assert!(!p.ja4.is_empty());
    assert_eq!(p.seed.len(), 64);
}
