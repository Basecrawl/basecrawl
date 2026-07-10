//! Best-effort open-web smoke checks for the public M1 demonstration targets.
//!
//! All exact parser, renderer, and navigation assertions live in deterministic loopback tests.
//! These probes deliberately make only qualitative assertions and tolerate a bounded public-site
//! outage after retrying, so the authoritative default-parallel suite does not depend on public
//! origin availability.

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

fn assert_qualitative_open_web_result(name: &str, host: &str, proof: &Value) {
    assert_eq!(
        proof["version"], 1,
        "{name} returned an invalid proof version"
    );
    assert_eq!(
        proof["tls"]["sni"], host,
        "{name} SNI did not match its host"
    );
    assert!(
        proof["tls"]["handshake_transcript_hash"]
            .as_str()
            .is_some_and(|digest| matches!(digest.len(), 64 | 96)),
        "{name} did not expose a live TLS transcript digest"
    );
    assert!(
        proof["response"]["status_code"]
            .as_u64()
            .is_some_and(|status| (200..600).contains(&status)),
        "{name} did not expose an HTTP response status"
    );
    assert!(
        proof["response"]["content_length"]
            .as_u64()
            .is_some_and(|length| length > 0),
        "{name} returned an empty smoke response"
    );
}

fn smoke_public_origin(name: &str, host: &str) {
    let url = format!("https://{host}/");
    let result = common::retry_open_web(|| {
        let output = run(&url);
        output
            .status
            .success()
            .then(|| serde_json::from_slice::<Value>(&output.stdout).ok())
            .flatten()
    });

    if let Some(proof) = result {
        assert_qualitative_open_web_result(name, host, &proof);
    } else {
        eprintln!(
            "{name} open-web smoke unavailable after {} bounded attempts; \
             deterministic loopback coverage remains authoritative",
            common::REMOTE_SMOKE_MAX_ATTEMPTS
        );
    }
}

#[test]
fn retry_helper_is_bounded_and_stops_after_success() {
    let attempts = Cell::new(0);
    let outcome = common::retry_open_web(|| {
        let next = attempts.get() + 1;
        attempts.set(next);
        (next == 2).then_some("recovered")
    });

    assert_eq!(outcome, Some("recovered"));
    assert_eq!(attempts.get(), 2);
}

#[test]
fn books_open_web_smoke_is_qualitative_and_bounded() {
    smoke_public_origin("books", "books.toscrape.com");
}
