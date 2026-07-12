//! End-to-end CLI assertions for the M1 ScrapeProof envelope (VAL-CRAWL-001..012).
//!
//! Tests that fetch use `https://example.com`, a stable open-web target, per the mission's
//! "real open-web targets" testing directive.

use serde_json::Value;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const TARGET: &str = "https://example.com";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

/// Run a scrape and parse stdout as exactly one strict JSON object.
fn scrape_json(args: &[&str]) -> Value {
    let out = run(args);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    // Strict parse of the entire stdout proves a single JSON value with no extra noise.
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout is not a single strict-JSON object: {e}\nstdout was:\n{stdout}")
    })
}

// VAL-CRAWL-001
#[test]
fn version_flag_prints_semver_and_exits_zero() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    // A semver-shaped token like 0.1.0 must appear.
    let has_semver = text.split_whitespace().any(|tok| {
        let parts: Vec<&str> = tok.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
    });
    assert!(has_semver, "no semver-shaped version in: {text}");
}

// VAL-CRAWL-001
#[test]
fn help_lists_url_formats_and_output_flag() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("URL"),
        "help should list the URL arg:\n{text}"
    );
    assert!(
        text.contains("--formats"),
        "help should list --formats:\n{text}"
    );
    assert!(
        text.contains("--output"),
        "help should list --output:\n{text}"
    );
}

// VAL-CRAWL-002
#[test]
fn basic_fetch_emits_single_valid_json() {
    let out = run(&[TARGET, "--output", "json"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("single strict JSON object");
    assert!(parsed.is_object());
}

// VAL-CRAWL-003
#[test]
fn scrapeproof_top_level_shape_is_complete() {
    let v = scrape_json(&[TARGET, "--output", "json"]);
    assert!(v["version"].is_u64(), "version must be an integer");
    for key in ["request", "tls", "response", "result", "egress"] {
        assert!(v[key].is_object(), "{key} must be an object");
    }
}

// VAL-CRAWL-004
#[test]
fn version_equals_integer_one() {
    let v = scrape_json(&[TARGET]);
    assert_eq!(v["version"], serde_json::json!(1));
}

// VAL-CRAWL-005
#[test]
fn request_url_and_method_reflect_invocation() {
    let v = scrape_json(&[TARGET]);
    assert_eq!(v["request"]["method"], "GET");
    let url = v["request"]["url"].as_str().unwrap();
    assert!(
        url == "https://example.com/" || url == "https://example.com",
        "request.url should reflect the requested origin/path, got {url}"
    );
}

// VAL-CRAWL-006
#[test]
fn formats_echoed_and_produced_exactly() {
    let v = scrape_json(&[TARGET, "--formats", "links,markdown,metadata"]);
    let formats: Vec<&str> = v["request"]["formats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    // Order-normalized canonical order: markdown, links, metadata.
    assert_eq!(formats, vec!["markdown", "links", "metadata"]);

    let produced = v["result"]["formats_produced"].as_object().unwrap();
    let mut keys: Vec<&String> = produced.keys().collect();
    keys.sort();
    assert_eq!(keys, vec!["links", "markdown", "metadata"]);
}

// VAL-CRAWL-007
#[test]
fn default_format_set_is_deterministic() {
    let a = scrape_json(&[TARGET]);
    let b = scrape_json(&[TARGET]);
    assert_eq!(
        a["request"]["formats"],
        serde_json::json!(["markdown", "metadata"])
    );
    assert_eq!(a["request"]["formats"], b["request"]["formats"]);
    // The default is documented in --help.
    let help = String::from_utf8_lossy(&run(&["--help"]).stdout).to_string();
    assert!(
        help.contains("markdown,metadata"),
        "default not documented in help:\n{help}"
    );
}

// VAL-CRAWL-008
#[test]
fn unknown_format_rejected_with_structured_error() {
    let out = run(&[TARGET, "--formats", "bogusfmt"]);
    assert!(!out.status.success(), "unknown format must exit non-zero");
    assert!(out.stdout.is_empty(), "no partial ScrapeProof on stdout");
    let err: Value = serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
    assert_eq!(err["error"]["kind"], "invalid_format");
    assert_eq!(err["error"]["invalid_format"], "bogusfmt");
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("bogusfmt"));
}

// VAL-CRAWL-009
#[test]
fn invalid_url_rejected() {
    let out = run(&["not a url"]);
    assert!(!out.status.success(), "invalid URL must exit non-zero");
    assert!(out.stdout.is_empty(), "no ScrapeProof on stdout");
    let err: Value = serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
    assert_eq!(err["error"]["kind"], "invalid_url");
}

// VAL-CRAWL-010
#[test]
fn non_http_schemes_refused() {
    for bad in [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/x",
    ] {
        let out = run(&[bad]);
        assert!(!out.status.success(), "{bad} must be refused");
        assert!(out.stdout.is_empty(), "{bad} must emit nothing on stdout");
        let err: Value =
            serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
        assert_eq!(err["error"]["kind"], "unsupported_scheme", "for {bad}");
        // Must not leak any file contents (e.g. a root: line from /etc/passwd).
        assert!(!String::from_utf8_lossy(&out.stdout).contains("root:"));
    }
}

// VAL-CRAWL-011
#[test]
fn task_id_and_nonce_echoed_verbatim() {
    let v = scrape_json(&[TARGET, "--task-id", "T123", "--nonce", "N456"]);
    assert_eq!(v["task_id"], "T123");
    assert_eq!(v["nonce"], "N456");
}

// VAL-CRAWL-011
#[test]
fn task_id_and_nonce_omitted_when_absent() {
    let v = scrape_json(&[TARGET]);
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("task_id"),
        "task_id must be omitted when absent"
    );
    assert!(
        !obj.contains_key("nonce"),
        "nonce must be omitted when absent"
    );
}

// VAL-CRAWL-012
#[test]
fn attestation_and_signature_absent_or_null_at_m1() {
    let v = scrape_json(&[TARGET]);
    assert!(
        v["attestation"]["quote"].is_null(),
        "quote must be null at M1"
    );
    assert!(
        v["attestation"]["measurement"].is_null(),
        "measurement must be null at M1"
    );
    assert!(
        v["attestation"]["report_data"].is_null(),
        "report_data must be null at M1"
    );
    assert!(
        v["sdk_signature"]["sig"].is_null(),
        "sdk_signature.sig must be null at M1"
    );
}

// VAL-TEE-026
#[test]
fn unavailable_dstack_socket_fails_closed_without_emitting_a_scrapeproof() {
    let out = run(&[
        TARGET,
        "--formats",
        "rawHtml",
        "--no-js",
        "--attest",
        "--task-id",
        "TEE-SOCKET-FAIL",
        "--nonce",
        "NONCE-SOCKET-FAIL",
    ]);

    assert!(!out.status.success(), "missing socket must exit non-zero");
    assert!(
        out.stdout.is_empty(),
        "no ScrapeProof or placeholder attestation may be emitted"
    );
    let err: Value = serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
    assert_eq!(err["error"]["kind"], "attestation_error");
    assert!(err["error"]["message"].as_str().unwrap().contains("socket"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("attestation"));
}
