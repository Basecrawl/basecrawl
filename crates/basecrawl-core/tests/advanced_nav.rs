//! Advanced navigation assertions (VAL-CRAWL-064, 065, 066, 067, 068, 069, 072, 073) exercised
//! end-to-end through the shipped CLI.
//!
//! `064` (infinite scroll) runs against the real `quotes.toscrape.com/scroll` target and `065`
//! (pagination) against `books.toscrape.com`, both named in the validation contract. `066` (SPA
//! route), `067` (iframe), `068` (shadow DOM), `069` (consent wall), `072` (scripted actions), and
//! `073` (meta-refresh / JS redirect + loop bound) run against a deterministic local HTTP server so
//! the behaviour under test is reproducible.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const QUOTES_SCROLL: &str = "https://quotes.toscrape.com/scroll";
const BOOKS_HOME: &str = "https://books.toscrape.com/";
const QUOTES_JS: &str = "https://quotes.toscrape.com/js/";
/// A quote that only exists once JavaScript has rendered the `/js/` page.
const JS_QUOTE_TEXT: &str = "The world as we have created it is a process of our thinking";

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
        "expected exit 0, got {:?}\nargs: {args:?}\nstderr: {}",
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

// ----------------------------------------------------------------------------------------------
// Deterministic local test server
// ----------------------------------------------------------------------------------------------

fn page(body: &str) -> String {
    format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>t</title></head><body>{body}</body></html>")
}

/// SPA whose visible content depends on the location hash route (client-side routing).
fn spa_page() -> String {
    page(
        "<div id=\"app\">SHELL_PLACEHOLDER</div>\
<script>\
function render(){var el=document.getElementById('app');\
el.textContent=(location.hash==='#/widget')?'SPA_ROUTE_CONTENT_31337':'HOME_VIEW';}\
window.addEventListener('hashchange',render);render();\
</script>",
    )
}

/// A page embedding a same-origin iframe (via srcdoc) whose inner text must be surfaced.
fn iframe_page() -> String {
    page("<h1>OUTER</h1><iframe srcdoc=\"&lt;p&gt;IFRAME_INNER_54321&lt;/p&gt;\"></iframe>")
}

/// A page rendering text inside an open shadow root.
fn shadow_page() -> String {
    page(
        "<h1>OUTER</h1><div id=\"host\"></div>\
<script>\
var r=document.getElementById('host').attachShadow({mode:'open'});\
r.innerHTML='<p>SHADOW_TEXT_98765</p>';\
</script>",
    )
}

/// A page whose real content is only revealed after a cookie-consent overlay is accepted.
fn consent_page() -> String {
    page(
        "<div id=\"consent\" style=\"position:fixed;inset:0;z-index:9999;background:#fff\">\
This site uses cookies. <button id=\"accept-cookies\">Accept all</button></div>\
<main id=\"content\">PENDING_CONSENT</main>\
<script>\
document.getElementById('accept-cookies').addEventListener('click',function(){\
document.getElementById('consent').remove();\
document.getElementById('content').textContent='UNDERLYING_REAL_CONTENT_24680';});\
</script>",
    )
}

/// A page with a "load more" button that injects content asynchronously after being clicked.
fn loadmore_page() -> String {
    page(
        "<button id=\"load-more\">Load more</button><div id=\"target\">INITIAL_ONLY</div>\
<script>\
document.getElementById('load-more').addEventListener('click',function(){\
setTimeout(function(){document.getElementById('target').textContent='POSTACTION_LOADED_44444';},300);});\
</script>",
    )
}

fn write_response(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn html_response(stream: TcpStream, body: &str) {
    write_response(
        stream,
        "200 OK",
        "text/html; charset=utf-8",
        body.as_bytes(),
    );
}

fn handle_connection(stream: TcpStream) {
    let peer = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut line = String::new();
    while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let path = path.split('#').next().unwrap_or("/");

    if path.starts_with("/spa") {
        html_response(peer, &spa_page());
    } else if path.starts_with("/iframe") {
        html_response(peer, &iframe_page());
    } else if path.starts_with("/shadow") {
        html_response(peer, &shadow_page());
    } else if path.starts_with("/consent") {
        html_response(peer, &consent_page());
    } else if path.starts_with("/loadmore") {
        html_response(peer, &loadmore_page());
    } else if path.starts_with("/meta-start") {
        html_response(
            peer,
            &page("<meta http-equiv=\"refresh\" content=\"0; url=/meta-dest\"><p>META_START_SKELETON</p>"),
        );
    } else if path.starts_with("/meta-dest") {
        html_response(peer, &page("<h1>META_DEST_CONTENT_777</h1>"));
    } else if path.starts_with("/js-redirect") {
        html_response(
            peer,
            &page("<p>JS_START</p><script>window.location='/js-dest';</script>"),
        );
    } else if path.starts_with("/js-dest") {
        html_response(peer, &page("<h1>JS_DEST_CONTENT_888</h1>"));
    } else if path.starts_with("/loop-a") {
        html_response(
            peer,
            &page("<meta http-equiv=\"refresh\" content=\"0; url=/loop-b\"><p>LOOP_A</p>"),
        );
    } else if path.starts_with("/loop-b") {
        html_response(
            peer,
            &page("<meta http-equiv=\"refresh\" content=\"0; url=/loop-a\"><p>LOOP_B</p>"),
        );
    } else {
        write_response(peer, "404 Not Found", "text/plain; charset=utf-8", b"nf");
    }
}

fn server_base() -> &'static str {
    static BASE: OnceLock<String> = OnceLock::new();
    BASE.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_connection(stream));
            }
        });
        format!("http://127.0.0.1:{port}")
    })
}

// ----------------------------------------------------------------------------------------------
// Assertions
// ----------------------------------------------------------------------------------------------

// VAL-CRAWL-064: infinite-scroll / lazy-load content is collected beyond the first viewport batch.
#[test]
fn infinite_scroll_collects_beyond_first_batch() {
    let v = scrape_json(&[
        QUOTES_SCROLL,
        "--formats",
        "markdown",
        "--render-timeout",
        "60",
    ]);
    let md = produced(&v, "markdown");
    // Each quote's text is wrapped in a curly opening quote; the first batch is ~10 quotes.
    let quote_count = md.matches('\u{201c}').count();
    assert!(
        quote_count > 11,
        "expected more than the first ~10 quotes after scrolling, found {quote_count}:\n{}",
        &md[..md.len().min(600)]
    );
}

// VAL-CRAWL-065: pagination is followed when requested; the crawled set spans multiple pages.
#[test]
fn pagination_follows_next_across_pages() {
    let v = scrape_json(&[
        BOOKS_HOME,
        "--formats",
        "markdown",
        "--follow-pagination",
        "--max-pages",
        "3",
    ]);
    let crawled = v["result"]["crawled_urls"]
        .as_array()
        .expect("result.crawled_urls should be an array when pagination is followed");
    assert!(
        crawled.len() >= 2,
        "crawled URL set should span multiple pages, got {crawled:?}"
    );
    assert!(
        crawled
            .iter()
            .any(|u| u.as_str().unwrap_or("").contains("page-2")),
        "crawled set should include the second page, got {crawled:?}"
    );

    // Without the option, no multi-page crawl set is emitted.
    let single = scrape_json(&[BOOKS_HOME, "--formats", "markdown"]);
    assert!(
        single["result"]
            .get("crawled_urls")
            .map(|v| v.is_null() || v.as_array().map(|a| a.is_empty()).unwrap_or(false))
            .unwrap_or(true),
        "crawled_urls must be absent/empty without --follow-pagination"
    );
}

// VAL-CRAWL-066: a client-rendered (hash-routed SPA) view is captured, not a blank shell.
#[test]
fn spa_client_route_content_is_captured() {
    let url = format!("{}/spa#/widget", server_base());
    let v = scrape_json(&[&url, "--formats", "markdown,html"]);
    assert!(
        produced(&v, "markdown").contains("SPA_ROUTE_CONTENT_31337"),
        "SPA routed view content was not captured (blank shell?):\n{}",
        produced(&v, "markdown")
    );
    assert!(
        !produced(&v, "html").contains("SHELL_PLACEHOLDER"),
        "captured the pre-render shell instead of the routed view"
    );

    // The real client-rendered target also yields its routed content.
    let real = scrape_json(&[QUOTES_JS, "--formats", "markdown"]);
    assert!(
        produced(&real, "markdown").contains(JS_QUOTE_TEXT),
        "client-rendered quotes.toscrape.com/js/ content was not captured"
    );
}

// VAL-CRAWL-067: iframe inner text content is surfaced in output.
#[test]
fn iframe_inner_content_is_captured() {
    let url = format!("{}/iframe", server_base());
    let v = scrape_json(&[&url, "--formats", "markdown,html"]);
    assert!(
        produced(&v, "html").contains("IFRAME_INNER_54321"),
        "iframe inner content missing from html:\n{}",
        produced(&v, "html")
    );
    assert!(
        produced(&v, "markdown").contains("IFRAME_INNER_54321"),
        "iframe inner content missing from markdown"
    );
}

// VAL-CRAWL-068: shadow-root text content is surfaced in output.
#[test]
fn shadow_dom_content_is_captured() {
    let url = format!("{}/shadow", server_base());
    let v = scrape_json(&[&url, "--formats", "markdown,html"]);
    assert!(
        produced(&v, "html").contains("SHADOW_TEXT_98765"),
        "shadow-DOM content missing from html:\n{}",
        produced(&v, "html")
    );
    assert!(
        produced(&v, "markdown").contains("SHADOW_TEXT_98765"),
        "shadow-DOM content missing from markdown"
    );
}

// VAL-CRAWL-069: a cookie-consent overlay is dismissed and the underlying content captured.
#[test]
fn consent_wall_is_dismissed_before_capture() {
    let url = format!("{}/consent", server_base());
    let v = scrape_json(&[&url, "--formats", "markdown"]);
    let md = produced(&v, "markdown");
    assert!(
        md.contains("UNDERLYING_REAL_CONTENT_24680"),
        "consent wall was not dismissed; underlying content missing:\n{md}"
    );
    assert!(
        !md.contains("PENDING_CONSENT"),
        "underlying content still shows the pre-consent placeholder"
    );
}

// VAL-CRAWL-072: a scripted action sequence executes in order and yields the post-action DOM.
#[test]
fn scripted_actions_execute_in_order() {
    let url = format!("{}/loadmore", server_base());
    let actions =
        r##"[{"type":"click","selector":"#load-more"},{"type":"wait","milliseconds":800}]"##;
    let v = scrape_json(&[&url, "--formats", "html", "--actions", actions]);
    assert!(
        produced(&v, "html").contains("POSTACTION_LOADED_44444"),
        "scripted actions did not yield the post-action content:\n{}",
        produced(&v, "html")
    );

    // Without the actions, the async content is never triggered.
    let untouched = scrape_json(&[&url, "--formats", "html"]);
    assert!(
        !produced(&untouched, "html").contains("POSTACTION_LOADED_44444"),
        "post-action content appeared without running the actions"
    );
}

// VAL-CRAWL-073: meta-refresh and JS redirects resolve to the destination content.
#[test]
fn meta_refresh_redirect_is_followed() {
    let url = format!("{}/meta-start", server_base());
    let v = scrape_json(&[&url, "--formats", "html,markdown"]);
    assert!(
        produced(&v, "html").contains("META_DEST_CONTENT_777"),
        "meta-refresh redirect was not followed to the destination:\n{}",
        produced(&v, "html")
    );
}

#[test]
fn js_location_redirect_is_followed() {
    let url = format!("{}/js-redirect", server_base());
    let v = scrape_json(&[&url, "--formats", "html"]);
    assert!(
        produced(&v, "html").contains("JS_DEST_CONTENT_888"),
        "window.location redirect was not followed to the destination:\n{}",
        produced(&v, "html")
    );
}

// VAL-CRAWL-073: a client-side redirect loop is bounded by the hop cap, not an unbounded hang.
#[test]
fn client_redirect_loop_is_bounded() {
    let url = format!("{}/loop-a", server_base());
    let start = Instant::now();
    let out = run(&[&url, "--formats", "html", "--render-timeout", "30"]);
    let elapsed = start.elapsed();

    assert!(
        !out.status.success(),
        "a client-side redirect loop must not succeed"
    );
    assert!(
        out.stdout.is_empty(),
        "no partial ScrapeProof on a bounded redirect loop"
    );
    let err: Value = serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
    assert_eq!(
        err["error"]["kind"],
        "too_many_redirects",
        "redirect loop should abort with the shared hop-cap error, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(25),
        "redirect loop must be bounded by the hop cap, not hang (took {elapsed:?})"
    );
}

#[test]
fn wait_for_selector_still_tracks_and_bounds_client_redirects() {
    let url = format!("{}/loop-a", server_base());
    let start = Instant::now();
    let out = run(&[
        &url,
        "--formats",
        "html",
        "--wait-for",
        ".never-present",
        "--render-timeout",
        "30",
    ]);
    let elapsed = start.elapsed();

    assert!(
        !out.status.success(),
        "a redirect loop must fail even while waiting for a selector"
    );
    assert!(
        out.stdout.is_empty(),
        "no partial ScrapeProof on a selector wait interrupted by a redirect loop"
    );
    let err: Value = serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
    assert_eq!(
        err["error"]["kind"],
        "too_many_redirects",
        "--wait-for must not turn a redirect loop into a selector timeout: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        elapsed < Duration::from_secs(25),
        "the redirect hop cap must win before the selector timeout ({elapsed:?})"
    );
}
