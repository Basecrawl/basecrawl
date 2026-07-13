//! Enclave-attested RTT echo + landmark RTT binding (VAL-GEO-009, VAL-GEO-030).
//!
//! VAL-GEO-030: a nonce'd RTT probe echo is signed by the in-enclave key committed
//! in report_data; a co-located puppet that merely echoes the nonce (unsigned /
//! wrong key) is rejected and never lowers the measured distance.
//!
//! VAL-GEO-009: the enclave records ITS measured landmark RTTs into
//! `ScrapeProof.egress.landmark_rtts` (carried on the signed proof surface whose
//! enclave key is bound into report_data); self-reports that contradict the
//! independently validator-measured floor (faster-than-physics) are rejected.

use basecrawl_core::attestation;
use basecrawl_core::canonical;
use basecrawl_core::rtt_echo::{
    accept_echo_for_rtt, cross_check_landmark_rtts, echo_signing_payload, handle_echo_request,
    sign_echo_with, start_echo_server, verify_echo_response, CrossCheckVerdict, EchoResponse,
    EchoSigner, EchoValidationFailure, LandmarkMeasurement, LandmarkProbeTarget, LocalEchoSigner,
    PuppetEchoSigner, RttConsistencyConfig, RTT_ECHO_DOMAIN_TAG,
};
use basecrawl_core::{scrape, Format, ScrapeOptions};
use basecrawl_proof::{
    Attestation, CertificateValidation, CompletenessManifest, Egress, Request, Response,
    ResultBlock, SdkSignature, Tls, SCRAPE_PROOF_VERSION,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn local_signer(seed: u8) -> LocalEchoSigner {
    LocalEchoSigner::from_seed(seed)
}

fn attestation_proof_with_pubkey(pubkey_hex: &str) -> basecrawl_proof::ScrapeProof {
    basecrawl_proof::ScrapeProof {
        version: SCRAPE_PROOF_VERSION,
        task_id: Some("task-geo-1".into()),
        nonce: Some("validator-nonce-a".into()),
        request: Request {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers_hash: Some("11".repeat(32)),
            body_hash: Some("22".repeat(32)),
            request_hash: Some("33".repeat(32)),
            formats: vec!["markdown".into()],
        },
        tls: Tls {
            certificate_validation: CertificateValidation::Validated,
            negotiated_version: Some("1.3".into()),
            sni: Some("example.com".into()),
            server_cert_chain_der: vec![],
            cert_chain_hash: Some("44".repeat(32)),
            server_ephemeral_pubkey: None,
            ct_scts: vec![],
            ocsp: None,
            handshake_transcript_hash: Some("55".repeat(32)),
        },
        response: Response {
            status_code: Some(200),
            headers_hash: Some("66".repeat(32)),
            body_hash: Some("77".repeat(32)),
            content_length: Some(1),
            content_type: Some("text/html".into()),
            body_truncated: false,
            body_max_bytes: Some(1024),
            final_url: Some("https://example.com/".into()),
            redirect_chain: vec![],
            render_subresource_count: 0,
            render_subresource_max_count: 128,
            render_resource_bytes: 0,
            render_max_bytes: 20 * 1024 * 1024,
            render_resource_cap_exceeded: false,
        },
        result: ResultBlock {
            formats_produced: BTreeMap::from([("markdown".into(), json!("hi"))]),
            result_hash: Some("88".repeat(32)),
            completeness_manifest: CompletenessManifest::default(),
            manifest_sha256: Some("aa".repeat(32)),
            crawled_urls: vec![],
        },
        egress: Egress {
            egress_ip: Some("203.0.113.5".into()),
            landmark_rtts: BTreeMap::from([("paris".into(), 11.2), ("nyc".into(), 78.4)]),
            timestamp: Some("2026-07-12T12:34:56Z".into()),
            fingerprint_seed: Some("bb".repeat(32)),
            proxy_class: None,
        },
        attestation: Attestation::default(),
        sdk_signature: SdkSignature {
            enclave_pubkey: Some(pubkey_hex.to_string()),
            sig: None,
        },
    }
}

// ---------------------------------------------------------------------------
// VAL-GEO-030 — signed echo, puppet rejection
// ---------------------------------------------------------------------------

#[test]
fn val_geo_030_echo_payload_is_domain_separated() {
    let nonce = "fresh-probe-nonce-abc";
    let payload = echo_signing_payload(nonce);
    assert!(payload.starts_with(RTT_ECHO_DOMAIN_TAG));
    assert!(payload.ends_with(nonce.as_bytes()));
    // Domain tag is distinct from the scrape-proof attestation tag.
    assert_ne!(
        RTT_ECHO_DOMAIN_TAG,
        b"basecrawl/scrape-proof-report-data/v1\0"
    );
    // Two different nonces produce different payloads.
    assert_ne!(
        echo_signing_payload("n1"),
        echo_signing_payload("n2"),
        "nonce must bind into the signing payload"
    );
}

#[test]
fn val_geo_030_attested_key_echo_is_accepted() {
    let signer = local_signer(7);
    let pubkey = signer.public_key_hex();
    let nonce = "probe-nonce-accept-me";

    let response = sign_echo_with(&signer, nonce).expect("honest enclave can sign");
    assert_eq!(response.nonce, nonce);
    assert_eq!(response.enclave_pubkey.as_deref(), Some(pubkey.as_str()));
    assert!(!response.signature.is_empty());

    verify_echo_response(&response, &pubkey, nonce).expect("attested-key echo must verify");

    // Accept path for RTT counting: only verified echoes contribute measured RTT.
    let measured = accept_echo_for_rtt(&response, &pubkey, nonce, 12.5).expect("accepted");
    assert_eq!(measured, 12.5);
}

#[test]
fn val_geo_030_unsigned_puppet_echo_is_rejected() {
    let signer = local_signer(7);
    let pubkey = signer.public_key_hex();
    let nonce = "probe-nonce-reject";

    // Puppet that only echoes the nonce (no signature) — the cheap co-located responder attack.
    let puppet = EchoResponse {
        nonce: nonce.into(),
        signature: String::new(),
        enclave_pubkey: None,
    };
    let err = verify_echo_response(&puppet, &pubkey, nonce).expect_err("puppet must fail");
    assert!(
        matches!(
            err,
            EchoValidationFailure::MissingSignature
                | EchoValidationFailure::InvalidSignature
                | EchoValidationFailure::PubkeyMismatch
        ),
        "unexpected puppets failure: {err:?}"
    );
    assert!(
        accept_echo_for_rtt(&puppet, &pubkey, nonce, 1.0).is_err(),
        "unsigned puppet RTT must not be counted"
    );
}

#[test]
fn val_geo_030_wrong_key_puppet_cannot_lower_distance() {
    let honest = local_signer(7);
    let honest_pubkey = honest.public_key_hex();
    let nonce = "probe-nonce-far-enclave";

    // Co-located puppet with a different (unattested) key answers with a near-zero RTT.
    let puppet = PuppetEchoSigner::from_seed(99);
    let puppet_resp = sign_echo_with(&puppet, nonce).expect("puppet can still sign bytes");
    assert_ne!(
        puppet_resp.enclave_pubkey.as_deref(),
        Some(honest_pubkey.as_str()),
        "puppet pubkey must not equal the attested enclave key"
    );

    let err = verify_echo_response(&puppet_resp, &honest_pubkey, nonce)
        .expect_err("wrong-key echo must fail");
    assert!(matches!(
        err,
        EchoValidationFailure::PubkeyMismatch | EchoValidationFailure::InvalidSignature
    ));
    // An attack that would manufacture a near-zone RTT of 0.5 ms is rejected; distance floor intact.
    assert!(accept_echo_for_rtt(&puppet_resp, &honest_pubkey, nonce, 0.5).is_err());
}

#[test]
fn val_geo_030_stale_nonce_echo_is_rejected() {
    let signer = local_signer(7);
    let pubkey = signer.public_key_hex();
    let response = sign_echo_with(&signer, "old-nonce").expect("sign");
    let err = verify_echo_response(&response, &pubkey, "new-fresh-nonce")
        .expect_err("stale nonce must fail");
    assert!(matches!(err, EchoValidationFailure::NonceMismatch));
    assert!(accept_echo_for_rtt(&response, &pubkey, "new-fresh-nonce", 3.0).is_err());
}

#[test]
fn val_geo_030_echo_binding_matches_report_data_committed_key() {
    let signer = local_signer(11);
    let pubkey = signer.public_key_hex();
    let proof = attestation_proof_with_pubkey(&pubkey);

    // report_data commits the same enclave_pubkey the echo verifies against.
    let report_data = canonical::attestation_report_data(&proof).expect("report_data");
    assert_eq!(report_data.len(), 128);

    let bound_key = proof
        .sdk_signature
        .enclave_pubkey
        .as_deref()
        .expect("enclave_pubkey committed in proof");
    assert_eq!(bound_key, pubkey);

    let nonce = "bound-to-report-data-key";
    let response = sign_echo_with(&signer, nonce).expect("sign");
    verify_echo_response(&response, bound_key, nonce)
        .expect("echo signed by report_data-committed key must verify");

    // Swapping the report_data-committed key would change report_data (M2 invariant).
    let mut swapped = proof.clone();
    swapped.sdk_signature.enclave_pubkey = Some(local_signer(22).public_key_hex());
    assert_ne!(
        canonical::attestation_report_data(&swapped).unwrap(),
        report_data,
        "enclave_pubkey is bound into report_data so a substituted key is detectable"
    );
}

#[test]
fn val_geo_030_http_echo_server_signs_and_rejects_puppets() {
    // Full HTTP surface the relay landmark probe talks to: GET /echo?nonce=... → signed JSON.
    let signer = local_signer(13);
    let pubkey = signer.public_key_hex();
    let server = start_echo_server(signer).expect("start echo server");
    let base = server.base_url();

    // Honest probe path: fetch + verify.
    let nonce = "live-probe-1";
    let url = format!("{base}?nonce={nonce}");
    let body = http_get_body(&url);
    let response: EchoResponse = serde_json::from_str(&body).expect("JSON echo");
    assert_eq!(response.nonce, nonce);
    verify_echo_response(&response, &pubkey, nonce).expect("HTTP signed echo interval verifies");

    // Plaintext-only puppet at a different endpoint must not count as the attested echo.
    let puppet_body = json!({ "nonce": nonce }).to_string();
    let puppet: EchoResponse = serde_json::from_str(&puppet_body).expect("parse unsigned");
    assert!(verify_echo_response(&puppet, &pubkey, nonce).is_err());

    // handle_echo_request helper — unit path without the HTTP layer.
    let built = handle_echo_request(&LocalEchoSigner::from_seed(13), nonce).expect("handle");
    assert_eq!(built.nonce, nonce);
    assert!(!built.signature.is_empty());

    drop(server); // stop listener
}

// ---------------------------------------------------------------------------
// VAL-GEO-009 — landmark_rtts recording + consistency cross-check
// ---------------------------------------------------------------------------

#[test]
fn val_geo_009_egress_records_landmark_rtts() {
    let measurements = [
        LandmarkMeasurement {
            landmark_id: "paris".into(),
            rtt_ms: 11.2,
        },
        LandmarkMeasurement {
            landmark_id: "nyc".into(),
            rtt_ms: 78.4,
        },
    ];
    let rtts = basecrawl_core::egress::landmark_rtts_from_measurements(&measurements);
    assert_eq!(rtts.get("paris"), Some(&11.2));
    assert_eq!(rtts.get("nyc"), Some(&78.4));
    // Stable BTreeMap key order (canonical JSON).
    let keys: Vec<_> = rtts.keys().cloned().collect();
    assert_eq!(keys, vec!["nyc".to_string(), "paris".to_string()]);
}

#[test]
fn val_geo_009_build_egress_includes_landmark_rtts() {
    use std::net::{IpAddr, Ipv4Addr};
    use time::OffsetDateTime;

    let mut map = BTreeMap::new();
    map.insert("paris".into(), 12.0);
    map.insert("amsterdam".into(), 15.5);

    let egress = basecrawl_core::egress::build_with_landmark_rtts(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        &"cc".repeat(32),
        map.clone(),
        basecrawl_proof::ProxyClass::Direct,
    )
    .expect("egress");
    assert_eq!(egress.landmark_rtts, map);
    assert_eq!(egress.egress_ip.as_deref(), Some("203.0.113.5"));
}

#[test]
fn val_geo_009_consistent_self_reported_and_validator_rtts_pass() {
    // Self-report and validator measure within tolerance.
    let self_reported = BTreeMap::from([("paris".into(), 11.0), ("amsterdam".into(), 14.0)]);
    let validator = BTreeMap::from([("paris".into(), 12.0), ("amsterdam".into(), 15.5)]);
    let cfg = RttConsistencyConfig {
        absolute_tolerance_ms: 5.0,
        relative_tolerance: 0.5,
    };
    let verdict = cross_check_landmark_rtts(&self_reported, &validator, &cfg);
    assert!(
        matches!(verdict, CrossCheckVerdict::Consistent { .. }),
        "expected Consistent, got {verdict:?}"
    );
}

#[test]
fn val_geo_009_faster_than_physics_self_report_is_rejected() {
    // Validator measured 80ms floor (far). Enclave self-reports 1ms (manufactured near-zone).
    // That contradicts the independent floor → rejected / flagged, never trusted.
    let self_reported = BTreeMap::from([("paris".into(), 1.0)]);
    let validator = BTreeMap::from([("paris".into(), 80.0)]);
    let cfg = RttConsistencyConfig {
        absolute_tolerance_ms: 5.0,
        relative_tolerance: 0.25,
    };
    let verdict = cross_check_landmark_rtts(&self_reported, &validator, &cfg);
    match verdict {
        CrossCheckVerdict::RejectedFasterThanPhysics {
            landmark,
            self_rtt_ms,
            validator_rtt_ms,
        } => {
            assert_eq!(landmark, "paris");
            assert!(self_rtt_ms < validator_rtt_ms);
        }
        other => panic!("expected RejectedFasterThanPhysics, got {other:?}"),
    }
}

#[test]
fn val_geo_009_landmark_rtts_ride_on_signed_scrapeproof_surface() {
    // landmark_rtts sits on the signed ScrapeProof whose enclave_pubkey is bound into report_data.
    // A mutate of landmark_rtts after signing must not accept a pre-signing signature.
    let signer_seed = 17u8;
    let signing_key = SigningKey::from_bytes(&[signer_seed; 32]);
    let pubkey = signing_key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let mut proof = attestation_proof_with_pubkey(&pubkey);
    proof.egress.landmark_rtts = BTreeMap::from([("paris".into(), 11.2), ("nyc".into(), 78.4)]);

    let message = proof.to_canonical_signing_json();
    let sig = signing_key.sign(message.as_bytes());
    let sig_hex = sig
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    proof.sdk_signature.sig = Some(sig_hex.clone());

    // Honest signature verifies over the proof that carries landmark_rtts.
    attestation::verify_signature(
        &pubkey,
        &sig_hex,
        proof.to_canonical_signing_json().as_bytes(),
    )
    .expect("honest signature over landmark_rtts-bearing proof");

    // Splice forged near-zone RTT: signature over original no longer matches.
    let mut forged = proof.clone();
    forged.egress.landmark_rtts.insert("paris".into(), 0.1);
    assert_ne!(forged.to_canonical_signing_json(), message);
    assert!(
        attestation::verify_signature(
            &pubkey,
            &sig_hex,
            forged.to_canonical_signing_json().as_bytes(),
        )
        .is_err(),
        "forged landmark_rtts must invalidate the enclave signature"
    );

    // report_data still commits the enclave key (the binding root for both echo and proof).
    let rd = canonical::attestation_report_data(&proof).expect("rd");
    assert!(!rd.is_empty());
}

#[test]
fn val_geo_009_record_landmark_rtts_into_live_scrape_egress() {
    // End-to-end (loopback): measure RTTs against local echo fixtures, place them
    // into the ScrapeProof egress of a real scrape.
    let landmark_a = start_echo_server(LocalEchoSigner::from_seed(31)).expect("lm a");
    let landmark_b = start_echo_server(LocalEchoSigner::from_seed(32)).expect("lm b");

    let (target, _join) = serve_static_html("<html><body>ok</body></html>");

    let targets = vec![
        LandmarkProbeTarget {
            landmark_id: "paris".into(),
            echo_url: landmark_a.base_url(),
        },
        LandmarkProbeTarget {
            landmark_id: "amsterdam".into(),
            echo_url: landmark_b.base_url(),
        },
    ];

    let measurements = basecrawl_core::rtt_echo::probe_landmarks(&targets, Duration::from_secs(2))
        .expect("probe landmarks from enclave");
    assert_eq!(measurements.len(), 2);
    for m in &measurements {
        assert!(m.rtt_ms >= 0.0);
        assert!(
            m.rtt_ms < 5_000.0,
            "loopback RTT must be small: {}",
            m.rtt_ms
        );
    }

    let landmark_rtts = basecrawl_core::egress::landmark_rtts_from_measurements(&measurements);

    let options = ScrapeOptions {
        formats: vec![Format::Html],
        render_enabled: false,
        task_id: Some("geo-task".into()),
        nonce: Some("geo-nonce".into()),
        landmark_rtts: Some(landmark_rtts.clone()),
        robots_policy: basecrawl_core::RobotsPolicy::Ignore,
        timeout_secs: 15,
        ..ScrapeOptions::default()
    };

    let proof = scrape(&target, &options).expect("scrape succeeds");
    assert_eq!(proof.egress.landmark_rtts, landmark_rtts);
    assert!(proof.egress.landmark_rtts.contains_key("paris"));
    assert!(proof.egress.landmark_rtts.contains_key("amsterdam"));

    // Cross-check: self-report is consistent with a re-probe that measures similar RTTs.
    let re_measure =
        basecrawl_core::rtt_echo::probe_landmarks(&targets, Duration::from_secs(2)).unwrap();
    let validator_map = basecrawl_core::egress::landmark_rtts_from_measurements(&re_measure);
    let verdict = cross_check_landmark_rtts(
        &proof.egress.landmark_rtts,
        &validator_map,
        &RttConsistencyConfig::default(),
    );
    assert!(
        matches!(verdict, CrossCheckVerdict::Consistent { .. }),
        "loopback re-probe must agree within tolerance: {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn http_get_body(url: &str) -> String {
    // Minimal client so the test doesn't depend on reqwest internals for plain HTTP.
    let parsed = url::Url::parse(url).expect("url");
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap_or(80);
    let path = if parsed.query().is_some() {
        format!("{}?{}", parsed.path(), parsed.query().unwrap())
    } else {
        parsed.path().to_string()
    };
    let mut stream = TcpStream::connect((host, port)).expect("connect echo");
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    text.split("\r\n\r\n")
        .nth(1)
        .expect("HTTP body")
        .to_string()
}

fn serve_static_html(html: &'static str) -> (String, thread::JoinHandle<()>) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/");
    let join = thread::spawn(move || {
        // Serve a few requests (direct + any robot probes if not ignored).
        for _ in 0..8 {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let body = html.as_bytes();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(body);
            }
        }
    });
    // Let the acceptor start.
    thread::sleep(Duration::from_millis(20));
    (url, join)
}
