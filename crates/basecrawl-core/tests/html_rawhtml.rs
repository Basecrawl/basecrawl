//! End-to-end `html` / `rawHtml` format assertions (VAL-CRAWL-036..041) exercised through the
//! shipped CLI against the real open-web targets named in the validation contract.
//!
//! `rawHtml` is the unmodified served source (no browser render); `html` is a cleaned, post-render
//! DOM serialization produced by driving headless Chromium. `curl` is used as the independent
//! ground-truth comparator for `rawHtml`.

mod common;

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const EXAMPLE: &str = "https://example.com/";
const QUOTES_JS: &str = "https://quotes.toscrape.com/js/";
const FIXTURE_QUOTE_ONE: &str = "fixture quote one";
const FIXTURE_QUOTE_TWO: &str = "fixture quote two";

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

fn produced<'a>(v: &'a Value, format: &str) -> &'a str {
    v["result"]["formats_produced"][format]
        .as_str()
        .unwrap_or_else(|| panic!("format '{format}' missing/non-string:\n{v}"))
}

fn curl(url: &str) -> String {
    let out = Command::new("curl")
        .args(["-s", "-m", "20", url])
        .output()
        .expect("failed to spawn curl");
    assert!(out.status.success(), "curl failed for {url}");
    String::from_utf8(out.stdout).expect("curl output is utf-8")
}

// ----------------------------------------------------------------------------------------------
// Deterministic local JS fixture
// ----------------------------------------------------------------------------------------------

/// A stable served source whose script creates exactly two quote nodes. The page includes
/// script/style/noscript elements and relative URLs so the complete `html`/`rawHtml` contract can
/// be asserted without comparing separate, mutable public-origin responses.
fn js_fixture_page() -> String {
    format!(
        r##"<!doctype html><html><head><meta charset="utf-8"><title>JS fixture</title>
<style>.quote {{ color: green; }}</style></head><body>
<a href="/fixture-login">Log in</a><img src="/static/fixture-image.png">
<noscript>fixture no-script content</noscript>
<script>
var data = ['{FIXTURE_QUOTE_ONE}', '{FIXTURE_QUOTE_TWO}'];
data.forEach(function(text) {{
  var quote = document.createElement('div');
  quote.className = 'quote';
  quote.textContent = text;
  document.body.appendChild(quote);
}});
</script></body></html>"##
    )
}

fn write_response(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle_fixture_connection(stream: TcpStream) {
    let writer = stream.try_clone().expect("clone fixture stream");
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }

    let mut line = String::new();
    while reader
        .read_line(&mut line)
        .map(|count| count > 0)
        .unwrap_or(false)
    {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    if request_line
        .split_whitespace()
        .nth(1)
        .is_some_and(|path| path == "/js-fixture")
    {
        write_response(
            writer,
            "200 OK",
            "text/html; charset=utf-8",
            js_fixture_page().as_bytes(),
        );
    } else {
        write_response(
            writer,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found",
        );
    }
}

/// Start one fixture server on an ephemeral loopback port for all tests in this integration binary.
fn fixture_url() -> &'static str {
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
        let address = listener.local_addr().expect("read fixture server address");
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_fixture_connection(stream));
            }
        });
        format!("http://{address}/js-fixture")
    })
}

// VAL-CRAWL-036: rawHtml is the unmodified served HTML (byte-equivalent to curl, modulo charset).
#[test]
fn rawhtml_is_unmodified_served_source() {
    let v = scrape_json(&[EXAMPLE, "--formats", "rawHtml"]);
    let raw = produced(&v, "rawHtml");
    let reference = curl(EXAMPLE);

    // Same served bytes (allowing only trailing-whitespace normalization).
    assert_eq!(
        raw.trim_end(),
        reference.trim_end(),
        "rawHtml diverged from the curl-served source"
    );
    // Same doctype + title, and no browser-injected markup.
    assert!(
        raw.to_ascii_lowercase().contains("<!doctype html>"),
        "served doctype missing from rawHtml:\n{raw}"
    );
    assert!(
        raw.contains("<title>Example Domain</title>"),
        "served <title> missing from rawHtml:\n{raw}"
    );
}

// VAL-CRAWL-037: html is a valid, cleaned/rendered DOM serialization that may differ from rawHtml.
#[test]
fn html_is_cleaned_serialized_dom() {
    let v = scrape_json(&[EXAMPLE, "--formats", "html,rawHtml"]);
    let html = produced(&v, "html");
    let raw = produced(&v, "rawHtml");

    // Valid serialized DOM: an <html> root wrapping the page content.
    assert!(
        html.to_ascii_lowercase().contains("<html")
            && html.to_ascii_lowercase().contains("</html>"),
        "html is not a serialized <html> document:\n{html}"
    );
    assert!(
        html.contains("<title>Example Domain</title>"),
        "html lost the document title:\n{html}"
    );
    assert!(
        html.contains("Example Domain"),
        "html lost the visible content:\n{html}"
    );
    // Cleaning normalizes/serializes the DOM, so it is not a byte copy of the raw source.
    assert_ne!(
        html.trim(),
        raw.trim(),
        "html must be a serialized DOM, not a byte copy of rawHtml"
    );
}

// VAL-CRAWL-038 smoke check: the public JS page still renders through Chromium and retains source.
#[test]
fn remote_js_page_smoke_renders_html_and_retains_source() {
    let v = scrape_json(&[QUOTES_JS, "--formats", "html,rawHtml"]);
    let html = produced(&v, "html");
    let raw = produced(&v, "rawHtml");

    // This is deliberately a smoke check: public content can vary between the core fetch and
    // Chromium's independent render request, so exact rendered/source comparisons belong below.
    assert!(
        html.contains("class=\"quote\""),
        "post-render html contains no quote nodes:\n{}",
        &html[..html.len().min(2000)]
    );
    assert!(
        raw.contains("var data ="),
        "rawHtml did not retain the served JavaScript source"
    );
}

// VAL-CRAWL-038: a deterministic fixture proves `html` is rendered and `rawHtml` is served source.
#[test]
fn local_js_fixture_has_exact_rendered_and_source_surfaces() {
    let v = scrape_json(&[fixture_url(), "--formats", "html,rawHtml"]);
    let html = produced(&v, "html");
    let raw = produced(&v, "rawHtml");

    assert_eq!(
        raw.matches("class=\"quote\"").count(),
        0,
        "rawHtml must remain the unrendered fixture source"
    );
    assert_eq!(
        html.matches("class=\"quote\"").count(),
        2,
        "html must contain both script-injected fixture quote nodes"
    );
    assert!(html.contains(FIXTURE_QUOTE_ONE));
    assert!(html.contains(FIXTURE_QUOTE_TWO));
    assert!(raw.contains("var data ="));
    assert!(raw.contains(FIXTURE_QUOTE_ONE));
    assert!(
        !html.contains("var data ="),
        "cleaned rendered html must not retain source scripts"
    );
}

// VAL-CRAWL-039: requesting only rawHtml returns raw bytes without a browser render, even for a JS page.
#[test]
fn rawhtml_alone_does_not_render() {
    let v = scrape_json(&[fixture_url(), "--formats", "rawHtml"]);

    // Only rawHtml is produced (no html key => no render was performed for this request).
    let produced_keys = v["result"]["formats_produced"]
        .as_object()
        .expect("formats_produced is an object");
    assert_eq!(
        produced_keys.keys().collect::<Vec<_>>(),
        vec!["rawHtml"],
        "requesting only rawHtml must not produce other (rendered) formats"
    );

    // The raw bytes are the source: no rendered quote nodes were injected.
    let raw = produced(&v, "rawHtml");
    assert_eq!(
        raw.matches("class=\"quote\"").count(),
        0,
        "rawHtml-only request injected rendered DOM into rawHtml"
    );
    assert!(
        raw.contains("var data ="),
        "rawHtml-only request did not return the served JS source"
    );
}

// VAL-CRAWL-040: absolute-URL rewriting in html is consistent (here: relative URLs are preserved).
#[test]
fn html_url_rewriting_is_consistent() {
    let v = scrape_json(&[fixture_url(), "--formats", "html"]);
    let html = produced(&v, "html");

    // Policy is "do not rewrite": every relative URL authored in the source stays relative in html.
    assert!(
        html.contains("href=\"/fixture-login\""),
        "a relative link was rewritten (or dropped) in html:\n{}",
        &html[..html.len().min(2000)]
    );
    assert!(
        html.contains("/static/fixture-image.png"),
        "a relative asset URL was rewritten (or dropped) in html"
    );
    // Consistency: no relative link/asset was absolutized to the origin.
    assert!(
        !html.contains(&format!(
            "{}/fixture-login",
            fixture_url().trim_end_matches("/js-fixture")
        )),
        "html rewrote some but not all relative URLs (inconsistent rewriting)"
    );
    assert!(
        !html.contains(&format!(
            "{}/static/fixture-image.png",
            fixture_url().trim_end_matches("/js-fixture")
        )),
        "html rewrote some but not all relative asset URLs (inconsistent rewriting)"
    );
}

// VAL-CRAWL-041: script/style handling in html is deterministic across repeated runs of the same URL.
#[test]
fn html_script_style_handling_is_deterministic() {
    let first = produced(&scrape_json(&[fixture_url(), "--formats", "html"]), "html").to_string();
    let second = produced(&scrape_json(&[fixture_url(), "--formats", "html"]), "html").to_string();

    // The script/style disposition (count of retained script/style tags) is identical across runs.
    assert_eq!(
        first.matches("<script").count(),
        second.matches("<script").count(),
        "<script> handling in html differed across runs"
    );
    assert_eq!(
        first.matches("<style").count(),
        second.matches("<style").count(),
        "<style> handling in html differed across runs"
    );
    // The rendered content is also stable across runs (same number of quote nodes).
    assert_eq!(
        first.matches("class=\"quote\"").count(),
        second.matches("class=\"quote\"").count(),
        "rendered quote-node count in html was nondeterministic across runs"
    );
    assert_eq!(
        first.matches("class=\"quote\"").count(),
        2,
        "fixture html must retain its exact script-injected quote-node count"
    );
}
