//! End-to-end canonicalization and deterministic quorum assertions (VAL-CRAWL-085..092).

use serde_json::Value;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const EXAMPLE: &str = "https://example.com/";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape(args: &[&str]) -> (String, Value) {
    let output = run(args);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let value = serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("stdout must be one strict JSON object: {error}\n{json}"));
    (json, value)
}

fn hash(value: &Value, path: &str) -> String {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("expected a hash-shaped string at {path}, got {value}");
        })
        .to_string()
}

fn assert_sha256(value: &str, name: &str) {
    assert_eq!(value.len(), 64, "{name} must be a SHA-256 digest");
    assert!(
        value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()),
        "{name} must be lowercase hexadecimal: {value}"
    );
}

// VAL-CRAWL-085, VAL-CRAWL-086, VAL-CRAWL-088, VAL-CRAWL-090, VAL-CRAWL-091, VAL-CRAWL-092.
#[test]
fn static_scrapes_have_a_stable_canonical_result_surface() {
    let args = [
        EXAMPLE,
        "--formats",
        "markdown,links,metadata",
        "--no-js",
        "--task-id",
        "canonical-task",
        "--nonce",
        "canonical-nonce",
    ];
    let (first_json, first) = scrape(&args);
    let (second_json, second) = scrape(&args);

    assert_eq!(
        hash(&first, "/result/result_hash"),
        hash(&second, "/result/result_hash"),
        "static content must have a deterministic result hash"
    );
    assert_eq!(
        first["result"]["formats_produced"]["markdown"],
        second["result"]["formats_produced"]["markdown"],
        "markdown must be byte-stable across repeated static scrapes"
    );
    assert_eq!(
        first["result"]["formats_produced"]["links"], second["result"]["formats_produced"]["links"],
        "links must retain a stable deterministic order"
    );

    let manifest = first["result"]["completeness_manifest"]
        .as_object()
        .expect("completeness_manifest must be an object");
    assert!(
        !manifest.is_empty(),
        "completeness_manifest must be populated for L4 completeness grading"
    );
    for format in ["markdown", "links", "metadata"] {
        let entry = &manifest["formats"][format];
        assert_eq!(entry["requested"], true, "{format} must be requested");
        assert_eq!(entry["present"], true, "{format} must be present");
        assert!(
            entry["byte_size"].as_u64().is_some_and(|size| size > 0),
            "{format} must report its produced byte size: {entry}"
        );
    }
    assert!(
        manifest["formats"]["links"]["key_field_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "links must report structural key fields: {}",
        manifest["formats"]["links"]
    );

    // The emitted canonical JSON key sequence must be stable. Dynamic values such as the TLS
    // transcript may differ between runs, but their enclosing key order cannot.
    for key in [
        "\"version\"",
        "\"task_id\"",
        "\"nonce\"",
        "\"request\"",
        "\"tls\"",
        "\"response\"",
        "\"result\"",
        "\"egress\"",
        "\"attestation\"",
        "\"sdk_signature\"",
    ] {
        let first_position = first_json
            .find(key)
            .expect("canonical top-level key exists");
        let second_position = second_json
            .find(key)
            .expect("canonical top-level key exists");
        assert_eq!(
            first_position, second_position,
            "key {key} must have the same serialization position across runs"
        );
    }
}

// VAL-CRAWL-087.
#[test]
fn request_hash_is_deterministic_and_binds_request_inputs() {
    let args = [
        EXAMPLE,
        "--formats",
        "markdown",
        "--no-js",
        "--nonce",
        "request-nonce",
    ];
    let (_, first) = scrape(&args);
    let (_, second) = scrape(&args);
    let (_, changed_header) = scrape(&[
        EXAMPLE,
        "--formats",
        "markdown",
        "--no-js",
        "--nonce",
        "request-nonce",
        "--header",
        "X-Canonical-Probe: changed",
    ]);

    let baseline = hash(&first, "/request/request_hash");
    assert_sha256(&baseline, "request_hash");
    assert_eq!(
        baseline,
        hash(&second, "/request/request_hash"),
        "identical request inputs must have the same request hash"
    );
    assert_ne!(
        baseline,
        hash(&changed_header, "/request/request_hash"),
        "a header change must change request_hash"
    );
    assert_ne!(
        first["request"]["headers_hash"], changed_header["request"]["headers_hash"],
        "request headers hash must bind the canonical request headers"
    );
    assert_sha256(
        first["request"]["body_hash"]
            .as_str()
            .expect("the empty GET body must still be hashed"),
        "body_hash",
    );
}

// VAL-CRAWL-089.
#[test]
fn reconciliation_digest_binds_url_nonce_and_result_hash() {
    let args = [
        EXAMPLE,
        "--formats",
        "markdown,metadata",
        "--no-js",
        "--nonce",
        "reconciliation-nonce-a",
    ];
    let (_, first) = scrape(&args);
    let (_, second) = scrape(&args);
    let (_, changed_nonce) = scrape(&[
        EXAMPLE,
        "--formats",
        "markdown,metadata",
        "--no-js",
        "--nonce",
        "reconciliation-nonce-b",
    ]);

    let baseline = hash(&first, "/result/manifest_sha256");
    assert_sha256(&baseline, "manifest_sha256");
    assert_eq!(
        baseline,
        hash(&second, "/result/manifest_sha256"),
        "same url, nonce, and result content must reconcile identically"
    );
    assert_ne!(
        baseline,
        hash(&changed_nonce, "/result/manifest_sha256"),
        "a nonce change must change the reconciliation digest"
    );
    assert_eq!(
        hash(&first, "/result/result_hash"),
        hash(&changed_nonce, "/result/result_hash"),
        "the nonce must not bleed into the content-only result hash"
    );
}
