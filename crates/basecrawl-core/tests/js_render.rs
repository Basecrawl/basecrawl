//! Headless-Chromium JS rendering core assertions (VAL-CRAWL-061, 062, 063, 070, 071) exercised
//! end-to-end through the shipped CLI.
//!
//! All exact behavior runs against deterministic loopback fixtures. `061` and `070` use a fixed
//! JavaScript-injected quote page; `062` (deferred-XHR smart wait), `063` (explicit `--wait-for`
//! selector), and `071` (never-idle render timeout) use a dedicated local HTTP server.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
/// A quote that only exists once JavaScript has rendered the page.
const JS_QUOTE_TEXT: &str = "Fixture JS quote render marker";

/// Distinctive markers embedded by the local server so we can prove late content was captured.
const DEFERRED_MARKER: &str = "DEFERREDCONTENT12345";
const WAITFOR_MARKER: &str = "LATEWAIT67890";

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

// ----------------------------------------------------------------------------------------------
// Deterministic local test server
// ----------------------------------------------------------------------------------------------

/// A page whose visible content is replaced only after a deferred XHR whose response the server
/// intentionally delays; capturing before network-idle yields the skeleton.
fn deferred_page() -> String {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Deferred</title></head>\
<body><h1 id=\"content\">SKELETON_PLACEHOLDER</h1>\
<script>\
fetch('/deferred-data').then(function(r){return r.text();}).then(function(t){\
document.getElementById('content').textContent=t;});\
</script></body></html>"
        .to_string()
}

/// A page that injects a `.late` element (with its content) only after a timer, with no network
/// activity, so only an explicit `--wait-for` selector can reliably capture it.
fn waitfor_page() -> String {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>WaitFor</title></head>\
<body><div id=\"root\">ROOT_START</div>\
<script>\
setTimeout(function(){var d=document.createElement('div');d.className='late';\
d.textContent='LATEWAIT67890';document.body.appendChild(d);},1500);\
</script></body></html>"
        .to_string()
}

/// A page whose network never goes idle (a request fires every 100ms forever).
fn never_idle_page() -> String {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>NeverIdle</title></head>\
<body><div>NEVER_IDLE_BODY</div>\
<script>\
setInterval(function(){fetch('/ping?t='+Date.now()).catch(function(){});},100);\
</script></body></html>"
        .to_string()
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

fn handle_connection(stream: TcpStream) {
    let peer = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    // Drain the remaining request headers so the client isn't reset mid-write.
    let mut line = String::new();
    while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    if path.starts_with("/deferred-data") {
        thread::sleep(Duration::from_millis(800));
        write_response(
            peer,
            "200 OK",
            "text/plain; charset=utf-8",
            DEFERRED_MARKER.as_bytes(),
        );
    } else if path.starts_with("/deferred") {
        write_response(
            peer,
            "200 OK",
            "text/html; charset=utf-8",
            deferred_page().as_bytes(),
        );
    } else if path.starts_with("/waitfor") {
        write_response(
            peer,
            "200 OK",
            "text/html; charset=utf-8",
            waitfor_page().as_bytes(),
        );
    } else if path.starts_with("/neveridle") {
        write_response(
            peer,
            "200 OK",
            "text/html; charset=utf-8",
            never_idle_page().as_bytes(),
        );
    } else if path.starts_with("/ping") {
        write_response(peer, "200 OK", "text/plain; charset=utf-8", b"pong");
    } else {
        write_response(
            peer,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found",
        );
    }
}

/// Start (once) the shared local test server and return its base URL, e.g. `http://127.0.0.1:PORT`.
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

// VAL-CRAWL-061: JS-injected content is rendered into markdown and html.
#[test]
fn js_injected_content_is_rendered_into_markdown_and_html() {
    let js_url = common::fixture_url("/js/");
    let v = scrape_json(&[&js_url, "--formats", "markdown,html"]);
    let md = produced(&v, "markdown");
    let html = produced(&v, "html");
    assert!(
        md.contains(JS_QUOTE_TEXT),
        "markdown is missing the JS-injected quote text (render not applied):\n{}",
        &md[..md.len().min(1500)]
    );
    assert!(
        html.contains(JS_QUOTE_TEXT),
        "html is missing the JS-injected quote text (render not applied)"
    );
    assert!(
        html.matches("class=\"quote\"").count() == 1,
        "post-render html is missing the JS-injected quote nodes"
    );
}

// VAL-CRAWL-062: content arriving via a deferred XHR is captured via the smart network-idle wait.
#[test]
fn deferred_xhr_content_is_captured_via_network_idle() {
    let url = format!("{}/deferred", server_base());
    let v = scrape_json(&[&url, "--formats", "markdown,html"]);
    let md = produced(&v, "markdown");
    let html = produced(&v, "html");
    assert!(
        md.contains(DEFERRED_MARKER),
        "markdown captured the pre-XHR skeleton instead of the late XHR content:\n{md}"
    );
    assert!(
        html.contains(DEFERRED_MARKER),
        "html captured the pre-XHR skeleton instead of the late XHR content"
    );
    assert!(
        !md.contains("SKELETON_PLACEHOLDER"),
        "markdown still shows the pre-XHR skeleton placeholder:\n{md}"
    );
}

// VAL-CRAWL-063: an explicit --wait-for selector blocks capture until the selector (and its
// content) exist; without it the same page is captured early.
#[test]
fn wait_for_selector_blocks_capture_until_present() {
    let url = format!("{}/waitfor", server_base());

    // With --wait-for the timer-injected element (and its text) is present.
    let with_wait = scrape_json(&[&url, "--formats", "html", "--wait-for", ".late"]);
    let html = produced(&with_wait, "html");
    assert!(
        html.contains(WAITFOR_MARKER) && html.contains("class=\"late\""),
        "--wait-for did not block capture until the selected content appeared:\n{}",
        &html[..html.len().min(1500)]
    );

    // Without --wait-for (network-idle only, no network activity) the timer content is not yet
    // present, proving the selector is what forced the wait.
    let without_wait = scrape_json(&[&url, "--formats", "html"]);
    let early = produced(&without_wait, "html");
    assert!(
        !early.contains(WAITFOR_MARKER),
        "expected early capture without --wait-for, but the timer content was present"
    );
}

// VAL-CRAWL-070: --no-js returns the raw served DOM only (no JS-injected quotes), while the
// default (JS-enabled) run does render them.
#[test]
fn no_js_mode_returns_source_without_rendering() {
    let js_url = common::fixture_url("/js/");
    let rendered = scrape_json(&[&js_url, "--formats", "markdown,html"]);
    assert!(
        produced(&rendered, "markdown").contains(JS_QUOTE_TEXT),
        "sanity: default run should render the JS quotes"
    );

    let raw = scrape_json(&[&js_url, "--formats", "markdown,html,rawHtml", "--no-js"]);
    let md = produced(&raw, "markdown");
    let html = produced(&raw, "html");
    assert!(
        !md.contains(JS_QUOTE_TEXT),
        "--no-js markdown unexpectedly contained JS-injected quote text (render was applied):\n{md}"
    );
    assert_eq!(
        html.matches("class=\"quote\"").count(),
        0,
        "--no-js html unexpectedly contained rendered JS-injected quote nodes"
    );
    // The served source is still returned (rawHtml is the source, which carries the JS data array).
    let raw_html = produced(&raw, "rawHtml");
    assert!(
        raw_html.contains("var data ="),
        "--no-js should still return the raw served source"
    );
}

// VAL-CRAWL-071: a never-idle page is aborted at the configured render timeout with a clear error,
// not an unbounded hang.
#[test]
fn never_idle_page_aborts_at_render_timeout() {
    let url = format!("{}/neveridle", server_base());
    let start = Instant::now();
    let out = run(&[&url, "--formats", "html", "--render-timeout", "4"]);
    let elapsed = start.elapsed();

    assert!(
        !out.status.success(),
        "a never-idle page must not exit 0 (it should abort at the render timeout)"
    );
    assert!(
        out.stdout.is_empty(),
        "no partial ScrapeProof on a render timeout"
    );
    let err: Value = serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
    assert_eq!(err["error"]["kind"], "render_error");
    let msg = err["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.to_lowercase().contains("tim"),
        "render timeout error must clearly mention the timeout, got: {msg}"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "render must abort near the configured timeout, not hang (took {elapsed:?})"
    );
}
