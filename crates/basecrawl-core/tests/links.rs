//! End-to-end `links`-format assertions (VAL-CRAWL-042, VAL-CRAWL-048) exercised through the
//! shipped CLI against deterministic loopback catalogue fixtures.
//!
//! The extraction rules (base-href resolution, canonical/hreflang capture, de-duplication, and the
//! per-policy handling of non-navigational schemes) are unit-tested in `src/links.rs`; these tests
//! confirm the same behavior end-to-end on a fixed, link-rich catalogue page.

mod common;

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
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not a single strict-JSON object: {e}\n{stdout}"))
}

fn link_list(v: &Value) -> Vec<String> {
    v["result"]["formats_produced"]["links"]["links"]
        .as_array()
        .expect("links.links is an array")
        .iter()
        .map(|l| l.as_str().expect("each link is a string").to_string())
        .collect()
}

// VAL-CRAWL-042: links extracts anchors as absolute product/category URLs resolved against base.
#[test]
fn books_home_links_are_absolute_product_and_category_urls() {
    let books = common::fixture_url("/books/");
    let v = scrape_json(&[&books, "--formats", "links"]);
    let links = link_list(&v);
    assert!(
        !links.is_empty(),
        "link-rich catalogue page yielded no links"
    );
    assert!(
        links.iter().all(|l| l.starts_with(common::fixture_base())),
        "every extracted link must be an absolute fixture URL: {links:?}"
    );
    assert!(
        links
            .iter()
            .any(|l| l.contains("/books/category/fixtures/")),
        "expected category URLs resolved against base:\n{links:?}"
    );
    assert!(
        links.iter().any(|l| l.contains("/books/catalogue/")
            && l.ends_with("index.html")
            && !l.contains("category")),
        "expected product URLs resolved against base:\n{links:?}"
    );
    // No relative fragments should survive into the links list.
    assert!(
        !links
            .iter()
            .any(|l| l.starts_with("catalogue") || l.starts_with("/")),
        "found an unresolved relative link:\n{links:?}"
    );
}

// VAL-CRAWL-048: the deterministic catalogue has an exact de-duplicated link count.
#[test]
fn books_home_link_count_is_deterministic() {
    let books = common::fixture_url("/books/");
    let v = scrape_json(&[&books, "--formats", "links"]);
    let count = link_list(&v).len();

    assert_eq!(count, 4, "fixture link count must remain exact");
}
