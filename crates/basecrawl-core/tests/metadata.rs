//! Integration tests for the `metadata` format against deterministic loopback fixtures.
//!
//! These exercise the full `scrape()` wiring (fetch + charset-from-header + metadata extraction),
//! not the extractor in isolation, so they confirm the end-to-end metadata surface a validator
//! sees via the CLI/SDK. OpenGraph/Twitter, robots, and duplicate-key behavior are covered by the
//! crafted-HTML unit tests in `src/metadata.rs` (the named public targets carry none of those).

mod common;

use basecrawl_core::{scrape, Format, ScrapeOptions};

fn scrape_metadata(url: &str) -> serde_json::Value {
    let options = ScrapeOptions {
        formats: vec![Format::Metadata],
        ..ScrapeOptions::default()
    };
    let proof = scrape(url, &options).expect("scrape should succeed");
    proof
        .result
        .formats_produced
        .get("metadata")
        .cloned()
        .expect("metadata format should be produced")
}

#[test]
fn fixture_metadata_reports_title_language_charset_source_and_status() {
    let url = common::fixture_url("/quotes/");
    let meta = scrape_metadata(&url);
    assert_eq!(meta["title"], "Fixture Quotes");
    assert_eq!(meta["language"], "en");
    assert_eq!(meta["charset"], "utf-8");
    assert_eq!(meta["statusCode"], serde_json::json!(200));
    assert!(
        meta["sourceURL"]
            .as_str()
            .unwrap()
            .contains(common::fixture_base()),
        "sourceURL should be the requested URL: {}",
        meta["sourceURL"]
    );
}

#[test]
fn example_metadata_reports_viewport_language_and_title() {
    // Hermetic loopback stand-in for example.com (VAL-CRAWL-053/054): bare `text/html` with no
    // charset declaration, plus viewport / lang / title. Public example.com DNS is flaky on GHA.
    let url = common::fixture_url("/example/");
    let meta = scrape_metadata(&url);
    assert_eq!(meta["title"], "Example Domain");
    assert_eq!(meta["language"], "en");
    // example.com-shaped page declares a viewport meta tag (VAL-CRAWL-054).
    assert_eq!(meta["viewport"], "width=device-width, initial-scale=1");
    // Bare `text/html` with no `<meta charset>` must leave charset absent, not fabricated
    // (VAL-CRAWL-053).
    assert!(
        meta.get("charset").is_none(),
        "charset must be absent when undeclared: {}",
        meta["charset"]
    );
}
