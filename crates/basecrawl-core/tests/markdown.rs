//! End-to-end markdown-format assertions (VAL-CRAWL-027..035) exercised through the shipped CLI
//! against deterministic loopback fixtures.
//!
//! The converter's structural rules (GFM tables, fenced code, nested-list depth, heading levels,
//! absolute links/images, boilerplate stripping, empty-but-valid output) are unit-tested in
//! `src/markdown.rs`; these tests confirm the same behavior end-to-end on fixed fixture pages.

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

fn markdown_of(v: &Value) -> &str {
    v["result"]["formats_produced"]["markdown"]
        .as_str()
        .expect("markdown format present as a string")
}

// VAL-CRAWL-027
#[test]
fn quote_page_markdown_is_nonempty_with_visible_quote_text() {
    let quotes = common::fixture_url("/quotes/");
    let v = scrape_json(&[&quotes, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(!md.trim().is_empty(), "markdown was empty for a rich page");
    assert!(
        md.contains("Fixture quote for resilient parser coverage"),
        "visible quote text missing from markdown:\n{md}"
    );
}

// VAL-CRAWL-032 (inline links absolute, on a deterministic fixture)
#[test]
fn quote_page_links_are_absolute() {
    let quotes = common::fixture_url("/quotes/");
    let v = scrape_json(&[&quotes, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains(&format!("]({}/tags/fixtures/", common::fixture_base())),
        "expected absolute link targets resolved against the page base:\n{md}"
    );
    // No markdown link should point at a bare relative path like `](/tag/...)`.
    assert!(
        !md.contains("](/"),
        "found an unresolved relative markdown link:\n{md}"
    );
}

// VAL-CRAWL-033
#[test]
fn product_page_markdown_centers_on_main_content() {
    let book = common::fixture_url("/books/catalogue/fixture-light/index.html");
    let v = scrape_json(&[&book, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("A Fixture Light"),
        "product title missing:\n{md}"
    );
    assert!(
        md.contains("Fixture product description"),
        "product description missing:\n{md}"
    );
    // The repeated site header/chrome must be stripped (it lives outside <article>).
    assert!(
        !md.contains("Books to Scrape"),
        "site chrome (header) leaked into main-content markdown:\n{md}"
    );
}

// VAL-CRAWL-028 (GFM table on a deterministic fixture)
#[test]
fn product_page_renders_gfm_table() {
    let book = common::fixture_url("/books/catalogue/fixture-light/index.html");
    let v = scrape_json(&[&book, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("| --- |"),
        "expected a GFM header-separator row:\n{md}"
    );
    assert!(
        md.contains("| UPC |"),
        "expected the product-information table rows as pipe-delimited cells:\n{md}"
    );
}

// VAL-CRAWL-031 (heading hierarchy on a deterministic fixture)
#[test]
fn product_page_preserves_heading_hierarchy() {
    let book = common::fixture_url("/books/catalogue/fixture-light/index.html");
    let v = scrape_json(&[&book, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains("# A Fixture Light"),
        "h1 title not mapped to a level-1 heading:\n{md}"
    );
    assert!(
        md.contains("## Fixture Product Description"),
        "h2 not mapped to a level-2 heading:\n{md}"
    );
}

// VAL-CRAWL-035
#[test]
fn product_page_image_is_markdown_with_absolute_src() {
    let book = common::fixture_url("/books/catalogue/fixture-light/index.html");
    let v = scrape_json(&[&book, "--formats", "markdown"]);
    let md = markdown_of(&v);
    assert!(
        md.contains(&format!(
            "![A Fixture Light]({}/media/fixture-light.jpg)",
            common::fixture_base()
        )),
        "image not rendered as markdown with a resolved absolute src:\n{md}"
    );
}

// VAL-CRAWL-034
#[test]
fn empty_204_page_yields_empty_but_valid_markdown() {
    let base = common::httpbin_base();
    let url = format!("{base}/status/204");
    let v = scrape_json(&[&url, "--formats", "markdown"]);
    assert_eq!(
        v["response"]["status_code"], 204,
        "expected a 204 status to be captured faithfully"
    );
    let md = markdown_of(&v);
    assert_eq!(
        md, "",
        "a 204/empty body must yield empty-but-valid markdown"
    );
    assert_eq!(
        v["version"],
        serde_json::json!(1),
        "proof still well-formed"
    );
}
