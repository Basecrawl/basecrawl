//! Non-HTML response assertions (VAL-CRAWL-093..098).
//!
//! These exercise the CLI against the contract's real httpbin targets. `httpbin_base()` chooses a
//! behavior-compatible deployment when httpbin.org itself is unavailable, while preserving the
//! endpoint and Content-Type semantics under test.

mod common;

use common::httpbin_base;
use serde_json::Value;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape_json(args: &[&str]) -> Value {
    let out = run(args);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout is not a single strict-JSON ScrapeProof: {e}\nstdout:\n{stdout}")
    })
}

fn content_type(value: &Value) -> &str {
    value["result"]["formats_produced"]["metadata"]["contentType"]
        .as_str()
        .expect("metadata.contentType must record the response Content-Type")
}

// VAL-CRAWL-093: JSON is preserved as text, never parsed or HTML-wrapped.
#[test]
fn json_response_is_faithful_and_records_content_type() {
    let url = format!("{}/json", httpbin_base());
    let proof = scrape_json(&[&url, "--formats", "markdown,rawHtml,metadata"]);
    let raw = proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .expect("JSON rawHtml must be text");
    let markdown = proof["result"]["formats_produced"]["markdown"]
        .as_str()
        .expect("JSON markdown must be text");

    let _: Value = serde_json::from_str(raw).expect("rawHtml must contain the original JSON");
    assert_eq!(markdown, raw, "JSON must not pass through an HTML parser");
    assert!(
        content_type(&proof).starts_with("application/json"),
        "unexpected content type: {}",
        content_type(&proof)
    );
    assert!(
        proof["response"]["content_type"]
            .as_str()
            .is_some_and(|value| value.starts_with("application/json")),
        "response block must retain the Content-Type"
    );
}

// VAL-CRAWL-094: text/plain preserves every text byte rather than normalizing HTML-like whitespace.
#[test]
fn plain_text_response_is_intact_and_records_content_type() {
    let url = format!("{}/robots.txt", httpbin_base());
    let proof = scrape_json(&[&url, "--formats", "markdown,rawHtml,metadata"]);
    let raw = proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .expect("plain text rawHtml must be text");
    let markdown = proof["result"]["formats_produced"]["markdown"]
        .as_str()
        .expect("plain text markdown must be text");

    assert_eq!(markdown, raw, "plain text must not be HTML-normalized");
    assert!(!raw.is_empty(), "robots.txt must have text content");
    assert!(
        content_type(&proof).starts_with("text/plain"),
        "unexpected content type: {}",
        content_type(&proof)
    );
}

// VAL-CRAWL-095: a binary image produces an empty text surface rather than lossy binary markdown.
#[test]
fn image_response_has_no_garbage_markdown() {
    let url = format!("{}/image/png", httpbin_base());
    let proof = scrape_json(&[&url, "--formats", "markdown,metadata"]);

    assert_eq!(
        proof["result"]["formats_produced"]["markdown"], "",
        "binary content must not be converted into markdown"
    );
    assert!(
        content_type(&proof).starts_with("image/png"),
        "unexpected content type: {}",
        content_type(&proof)
    );
    assert_eq!(proof["response"]["status_code"], 200);
}

// VAL-CRAWL-096: no-content responses remain well-formed and have empty result surfaces.
#[test]
fn no_content_response_is_well_formed_and_empty() {
    let url = format!("{}/status/204", httpbin_base());
    let proof = scrape_json(&[&url, "--formats", "markdown,rawHtml,metadata"]);

    assert_eq!(proof["response"]["status_code"], 204);
    assert_eq!(proof["response"]["content_length"], 0);
    assert_eq!(proof["result"]["formats_produced"]["markdown"], "");
    assert_eq!(proof["result"]["formats_produced"]["rawHtml"], "");
    assert!(proof["result"]["formats_produced"]["metadata"].is_object());
}

// VAL-CRAWL-097: the authoritative response Content-Type wins over a misleading URL suffix.
#[test]
fn content_type_overrides_url_extension_for_classification() {
    let url = format!("{}/anything/misleading.html", httpbin_base());
    let proof = scrape_json(&[&url, "--formats", "markdown,rawHtml,metadata"]);
    let raw = proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .expect("JSON response body must remain text");
    let markdown = proof["result"]["formats_produced"]["markdown"]
        .as_str()
        .expect("JSON response body must remain text");

    let _: Value = serde_json::from_str(raw).expect("the misleading .html endpoint serves JSON");
    assert_eq!(
        markdown, raw,
        "a response served as JSON must not be classified by its .html URL suffix"
    );
    assert!(
        content_type(&proof).starts_with("application/json"),
        "the response Content-Type, not URL extension, must drive classification"
    );
}

// VAL-CRAWL-098: cap memory at a caller-visible bound and declare the truncation in the proof.
#[test]
fn oversized_response_is_capped_and_signaled() {
    let url = format!("{}/bytes/8192", httpbin_base());
    let proof = scrape_json(&[&url, "--formats", "metadata", "--max-body-bytes", "1024"]);

    assert_eq!(proof["response"]["body_truncated"], true);
    assert_eq!(proof["response"]["body_max_bytes"], 1024);
    assert_eq!(proof["response"]["content_length"], 1024);
}

#[test]
fn cli_help_documents_the_default_body_cap_and_truncation_signal() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).expect("help is UTF-8");
    assert!(
        help.contains("--max-body-bytes"),
        "body cap missing from help"
    );
    assert!(
        help.contains("body_truncated"),
        "help must identify the proof truncation signal"
    );
}
