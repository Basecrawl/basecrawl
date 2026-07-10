//! Strict, bounded open-web smoke checks for the public M1 demonstration targets.
//!
//! All exact parser, renderer, and navigation assertions live in deterministic loopback tests.
//! A public origin may be skipped only after bounded retries of an independently-classified
//! transient availability failure. Crawler, proof, TLS, schema, and serialization failures are
//! fatal because they indicate a broken local contract rather than a remote outage.

mod common;

use serde_json::Value;
use std::cell::Cell;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn run(url: &str) -> Output {
    Command::new(BIN)
        .args([
            url,
            "--formats",
            "rawHtml",
            "--no-js",
            "--robots",
            "ignore",
            "--timeout",
            "8",
        ])
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn assert_open_web_response(name: &str, proof: &Value) {
    assert_eq!(
        proof["version"], 1,
        "{name} returned an invalid proof version"
    );
    assert!(
        proof["response"]["status_code"]
            .as_u64()
            .is_some_and(|status| (200..300).contains(&status)),
        "{name} did not expose a successful HTTP response status"
    );
    assert!(
        proof["response"]["content_length"]
            .as_u64()
            .is_some_and(|length| length > 0),
        "{name} returned an empty smoke response"
    );
}

fn smoke_public_origin(name: &str, host: &str) {
    smoke_public_url(name, &format!("https://{host}/"), host);
}

fn smoke_public_url(name: &str, url: &str, expected_host: &str) {
    match common::retry_open_web(|| common::classify_open_web_output(&run(url), expected_host)) {
        common::RemoteSmokeOutcome::Success(proof) => {
            let proof = serde_json::to_value(proof).expect("ScrapeProof must serialize");
            assert_open_web_response(name, &proof);
        }
        common::RemoteSmokeOutcome::Skipped(transient) => {
            eprintln!(
                "{name} open-web smoke skipped after {} bounded transient-origin failure attempt(s): \
                 {transient}; deterministic loopback coverage remains authoritative",
                common::REMOTE_SMOKE_MAX_ATTEMPTS
            );
        }
        common::RemoteSmokeOutcome::Fatal(failure) => {
            panic!("{name} open-web smoke failed without a skip: {failure}");
        }
    }
}

#[test]
fn retry_helper_is_bounded_and_stops_after_success() {
    let attempts = Cell::new(0);
    let outcome = common::retry_open_web(|| {
        let next = attempts.get() + 1;
        attempts.set(next);
        if next == 2 {
            common::RemoteSmokeAttempt::Success("recovered")
        } else {
            common::RemoteSmokeAttempt::Retryable(common::TransientOriginFailure::Timeout)
        }
    });

    assert!(matches!(
        outcome,
        common::RemoteSmokeOutcome::Success("recovered")
    ));
    assert_eq!(attempts.get(), 2);
}

#[test]
fn typed_retry_helper_skips_only_exhausted_transient_origin_failures() {
    let attempts = Cell::new(0);
    let outcome = common::retry_open_web(|| {
        attempts.set(attempts.get() + 1);
        common::RemoteSmokeAttempt::<()>::Retryable(common::TransientOriginFailure::Upstream5xx(
            503,
        ))
    });

    assert!(matches!(
        outcome,
        common::RemoteSmokeOutcome::Skipped(common::TransientOriginFailure::Upstream5xx(503))
    ));
    assert_eq!(attempts.get(), common::REMOTE_SMOKE_MAX_ATTEMPTS);
}

#[test]
fn crawler_proof_tls_and_schema_failures_cannot_become_skips() {
    let cases = [
        (
            "crawler exit",
            false,
            b"".as_slice(),
            br#"{"error":{"kind":"fetch_error","message":"unexpected crawler failure"}}"#.as_slice(),
        ),
        ("malformed JSON", true, b"{".as_slice(), b"".as_slice()),
        (
            "malformed proof",
            true,
            br#"{"version":1}"#.as_slice(),
            b"".as_slice(),
        ),
        (
            "schema failure",
            true,
            br#"{"version":1,"request":{"method":"GET","url":"https://books.toscrape.com/","headers_hash":null,"body_hash":null,"request_hash":null,"formats":["rawHtml"]},"tls":{"negotiated_version":"1.3","sni":"books.toscrape.com","server_cert_chain_der":[],"cert_chain_hash":null,"server_ephemeral_pubkey":null,"ct_scts":[],"ocsp":null,"handshake_transcript_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"response":{"status_code":200,"headers_hash":null,"body_hash":null,"content_length":1,"content_type":"text/html","body_truncated":false,"body_max_bytes":10485760,"final_url":"https://books.toscrape.com/","redirect_chain":[],"render_subresource_count":0,"render_subresource_max_count":128,"render_resource_bytes":0,"render_max_bytes":20971520,"render_resource_cap_exceeded":false},"result":{"formats_produced":{"rawHtml":"x"},"result_hash":null,"completeness_manifest":{"version":1,"requested_format_count":1,"present_format_count":1,"formats":{"rawHtml":{"requested":true,"present":true,"byte_size":1,"key_field_count":0}}},"manifest_sha256":null},"egress":{"egress_ip":"127.0.0.1","landmark_rtts":{},"timestamp":"2026-01-01T00:00:00Z","fingerprint_seed":"seed"},"attestation":{"tee_type":null,"quote":null,"measurement":null,"report_data":null},"sdk_signature":{"enclave_pubkey":null,"sig":null},"unexpected":true}"#
                .as_slice(),
            b"".as_slice(),
        ),
        (
            "TLS evidence failure",
            true,
            br#"{"version":1,"request":{"method":"GET","url":"https://books.toscrape.com/","headers_hash":null,"body_hash":null,"request_hash":null,"formats":["rawHtml"]},"tls":{"negotiated_version":"1.1","sni":"books.toscrape.com","server_cert_chain_der":[],"cert_chain_hash":null,"server_ephemeral_pubkey":null,"ct_scts":[],"ocsp":null,"handshake_transcript_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"response":{"status_code":200,"headers_hash":null,"body_hash":null,"content_length":1,"content_type":"text/html","body_truncated":false,"body_max_bytes":10485760,"final_url":"https://books.toscrape.com/","redirect_chain":[],"render_subresource_count":0,"render_subresource_max_count":128,"render_resource_bytes":0,"render_max_bytes":20971520,"render_resource_cap_exceeded":false},"result":{"formats_produced":{"rawHtml":"x"},"result_hash":null,"completeness_manifest":{"version":1,"requested_format_count":1,"present_format_count":1,"formats":{"rawHtml":{"requested":true,"present":true,"byte_size":1,"key_field_count":0}}},"manifest_sha256":null},"egress":{"egress_ip":"127.0.0.1","landmark_rtts":{},"timestamp":"2026-01-01T00:00:00Z","fingerprint_seed":"seed"},"attestation":{"tee_type":null,"quote":null,"measurement":null,"report_data":null},"sdk_signature":{"enclave_pubkey":null,"sig":null}}"#
                .as_slice(),
            b"".as_slice(),
        ),
        (
            "certificate failure",
            false,
            b"".as_slice(),
            br#"{"error":{"kind":"certificate_validation","message":"certificate validation failed"}}"#
                .as_slice(),
        ),
        (
            "TLS capture failure",
            false,
            b"".as_slice(),
            br#"{"error":{"kind":"tls_capture_error","message":"missing CertificateVerify transcript"}}"#
                .as_slice(),
        ),
        (
            "unclassified transport failure",
            false,
            b"".as_slice(),
            br#"{"error":{"kind":"transport_error","message":"unexpected malformed response"}}"#
                .as_slice(),
        ),
    ];

    for (name, succeeded, stdout, stderr) in cases {
        let attempts = Cell::new(0);
        let outcome = common::retry_open_web(|| {
            attempts.set(attempts.get() + 1);
            common::classify_open_web_process(succeeded, stdout, stderr, "books.toscrape.com")
        });
        assert!(
            matches!(outcome, common::RemoteSmokeOutcome::Fatal(_)),
            "{name} must be fatal, never a skipped transient outage"
        );
        assert_eq!(
            attempts.get(),
            1,
            "{name} must fail immediately without a retry"
        );
    }
}

#[test]
fn books_open_web_smoke_is_strict_and_bounded() {
    smoke_public_origin("books", "books.toscrape.com");
}

#[test]
fn httpbin_open_web_smoke_is_strict_and_bounded() {
    for base in common::HTTPBIN_CANDIDATES {
        let host = url::Url::parse(base)
            .expect("httpbin candidate must be a URL")
            .host_str()
            .expect("httpbin candidate must have a host")
            .to_string();
        let url = format!("{base}/get");
        match common::retry_open_web(|| common::classify_open_web_output(&run(&url), &host)) {
            common::RemoteSmokeOutcome::Success(proof) => {
                let proof = serde_json::to_value(proof).expect("ScrapeProof must serialize");
                assert_open_web_response("httpbin", &proof);
                return;
            }
            common::RemoteSmokeOutcome::Skipped(transient) => {
                eprintln!(
                    "httpbin-compatible origin {base} skipped after {} bounded transient-origin \
                     failure attempt(s): {transient}; trying the next candidate",
                    common::REMOTE_SMOKE_MAX_ATTEMPTS
                );
            }
            common::RemoteSmokeOutcome::Fatal(failure) => {
                panic!("httpbin-compatible origin {base} failed without a skip: {failure}");
            }
        }
    }
    panic!(
        "no httpbin-compatible origin was available after bounded transient retries: {:?}",
        common::HTTPBIN_CANDIDATES
    );
}
