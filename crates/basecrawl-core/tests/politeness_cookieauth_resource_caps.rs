//! Operational-safety assertions for crawl politeness, M1 cleartext credentials, and bounded
//! aggregate browser resources (VAL-CRAWL-129..131).
//!
//! Every test uses a deterministic local origin so timing, credentials, and subresource volume are
//! observable without depending on a third-party endpoint.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

mod common;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const AUTH_HEADER_MARKER: &str = "AUTH_HEADER_GATE_OPEN_84321";
const BASIC_AUTH_MARKER: &str = "BASIC_AUTH_GATE_OPEN_84321";
const COOKIE_MARKER: &str = "COOKIE_GATE_OPEN_84321";
const ANONYMOUS_MARKER: &str = "ANONYMOUS_GATE_CLOSED_84321";
const ASSET_BYTES: usize = 768;

type RequestHeaders = Vec<(String, String)>;
type ParsedRequest = (TcpStream, String, RequestHeaders);

#[derive(Debug, Default)]
struct ServerState {
    polite_request_times: Mutex<Vec<Instant>>,
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape_json(args: &[&str]) -> Value {
    let output = run(args);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nargs: {args:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not one strict ScrapeProof JSON object: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn write_response(mut stream: TcpStream, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Connection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .expect("write response header");
    stream.write_all(body).expect("write response body");
    stream.flush().expect("flush response");
}

fn request(stream: TcpStream) -> Option<ParsedRequest> {
    let peer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let path = request_line.split_whitespace().nth(1)?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Some((peer, path, headers))
}

fn header<'a>(headers: &'a RequestHeaders, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn page(body: &str) -> Vec<u8> {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Safety</title></head>\
<body>{body}</body></html>"
    )
    .into_bytes()
}

fn handle_connection(stream: TcpStream, state: Arc<ServerState>) {
    let Some((peer, path, headers)) = request(stream) else {
        return;
    };

    if path == "/polite/page-1" {
        state
            .polite_request_times
            .lock()
            .expect("timestamps lock")
            .push(Instant::now());
        write_response(
            peer,
            "text/html; charset=utf-8",
            &page("<main>PAGE_ONE</main><a rel=\"next\" href=\"/polite/page-2\">next</a>"),
        );
    } else if path == "/polite/page-2" {
        state
            .polite_request_times
            .lock()
            .expect("timestamps lock")
            .push(Instant::now());
        write_response(
            peer,
            "text/html; charset=utf-8",
            &page("<main>PAGE_TWO</main>"),
        );
    } else if path == "/gated/cookie" {
        let authenticated =
            header(&headers, "cookie").is_some_and(|value| value.contains("session=opened"));
        let marker = if authenticated {
            COOKIE_MARKER
        } else {
            ANONYMOUS_MARKER
        };
        write_response(peer, "text/html; charset=utf-8", &page(marker));
    } else if path == "/gated/header" {
        let authenticated = header(&headers, "authorization") == Some("Bearer bearer-token");
        let marker = if authenticated {
            AUTH_HEADER_MARKER
        } else {
            ANONYMOUS_MARKER
        };
        write_response(peer, "text/html; charset=utf-8", &page(marker));
    } else if path == "/gated/basic" {
        let authenticated = header(&headers, "authorization") == Some("Basic dXNlcjpwYXNz");
        let marker = if authenticated {
            BASIC_AUTH_MARKER
        } else {
            ANONYMOUS_MARKER
        };
        write_response(peer, "text/html; charset=utf-8", &page(marker));
    } else if path == "/assets" {
        let assets = (0..8)
            .map(|index| format!("<img src=\"/asset/{index}.png\">"))
            .collect::<String>();
        write_response(
            peer,
            "text/html; charset=utf-8",
            &page(&format!("<main>RESOURCE_CAP_PAGE</main>{assets}")),
        );
    } else if path.starts_with("/asset/") {
        write_response(peer, "image/png", &vec![0_u8; ASSET_BYTES]);
    } else {
        write_response(peer, "text/plain; charset=utf-8", b"not found");
    }
}

fn server() -> (&'static str, Arc<ServerState>) {
    static SERVER: OnceLock<(String, Arc<ServerState>)> = OnceLock::new();
    let (base, state) = SERVER.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test origin");
        let port = listener.local_addr().expect("test origin address").port();
        let state = Arc::new(ServerState::default());
        let accept_state = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let connection_state = Arc::clone(&accept_state);
                thread::spawn(move || handle_connection(stream, connection_state));
            }
        });
        (format!("http://127.0.0.1:{port}"), state)
    });
    (base.as_str(), Arc::clone(state))
}

fn raw_html(proof: &Value) -> &str {
    proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .expect("rawHtml format should be a string")
}

// VAL-CRAWL-129: same-origin pagination requests observe the configured crawl delay.
#[test]
fn same_origin_pagination_observes_configured_crawl_delay() {
    let (base, state) = server();
    state
        .polite_request_times
        .lock()
        .expect("timestamps lock")
        .clear();

    let target = format!("{base}/polite/page-1");
    let proof = scrape_json(&[
        &target,
        "--formats",
        "markdown",
        "--no-js",
        "--robots",
        "ignore",
        "--follow-pagination",
        "--max-pages",
        "2",
        "--crawl-delay-ms",
        "200",
    ]);
    assert_eq!(proof["result"]["crawled_urls"].as_array().unwrap().len(), 2);

    let timestamps = state
        .polite_request_times
        .lock()
        .expect("timestamps lock")
        .clone();
    assert_eq!(
        timestamps.len(),
        2,
        "expected exactly two paginated origin requests, got {timestamps:?}"
    );
    let interval = timestamps[1].duration_since(timestamps[0]);
    assert!(
        interval >= Duration::from_millis(180),
        "same-origin requests were not spaced by the configured 200ms delay: {interval:?}"
    );
}

// VAL-CRAWL-130: explicit session cookies reach both the direct fetch and rendered browser view.
#[test]
fn session_cookie_retrieves_authenticated_rendered_view() {
    let (base, _) = server();
    let target = format!("{base}/gated/cookie");

    let anonymous = scrape_json(&[&target, "--formats", "html", "--robots", "ignore"]);
    assert!(anonymous["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap()
        .contains(ANONYMOUS_MARKER));
    assert!(!anonymous["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap()
        .contains(COOKIE_MARKER));

    let authenticated = scrape_json(&[
        &target,
        "--formats",
        "html",
        "--robots",
        "ignore",
        "--cookie",
        "session=opened",
    ]);
    assert!(authenticated["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap()
        .contains(COOKIE_MARKER));
}

// VAL-CRAWL-130: caller-supplied auth headers and basic credentials select their gated views.
#[test]
fn auth_header_and_basic_auth_retrieve_authenticated_views() {
    let (base, _) = server();

    let header_url = format!("{base}/gated/header");
    let anonymous_header =
        scrape_json(&[&header_url, "--formats", "rawHtml", "--robots", "ignore"]);
    assert!(raw_html(&anonymous_header).contains(ANONYMOUS_MARKER));
    let authenticated_header = scrape_json(&[
        &header_url,
        "--formats",
        "rawHtml",
        "--robots",
        "ignore",
        "--auth-header",
        "Bearer bearer-token",
    ]);
    assert!(raw_html(&authenticated_header).contains(AUTH_HEADER_MARKER));

    let basic_url = format!("{base}/gated/basic");
    let anonymous_basic = scrape_json(&[&basic_url, "--formats", "rawHtml", "--robots", "ignore"]);
    assert!(raw_html(&anonymous_basic).contains(ANONYMOUS_MARKER));
    let authenticated_basic = scrape_json(&[
        &basic_url,
        "--formats",
        "rawHtml",
        "--robots",
        "ignore",
        "--basic-auth",
        "user:pass",
    ]);
    assert!(raw_html(&authenticated_basic).contains(BASIC_AUTH_MARKER));
}

// VAL-CRAWL-130: the basic-auth convenience flag also succeeds against the contract's real
// httpbin-compatible target, with the shared resilient base selection used by the whole suite.
#[test]
fn basic_auth_retrieves_real_httpbin_authenticated_view() {
    let target = format!("{}/basic-auth/basecrawl/safety", common::httpbin_base());
    let anonymous = scrape_json(&[&target, "--formats", "rawHtml", "--robots", "ignore"]);
    assert_eq!(
        anonymous["response"]["status_code"], 401,
        "anonymous basic-auth request must remain gated"
    );

    let authenticated = scrape_json(&[
        &target,
        "--formats",
        "rawHtml",
        "--robots",
        "ignore",
        "--basic-auth",
        "basecrawl:safety",
    ]);
    let authenticated_body: Value = serde_json::from_str(raw_html(&authenticated))
        .expect("httpbin authenticated response JSON");
    assert_eq!(
        authenticated_body["authenticated"],
        Value::Bool(true),
        "basic credentials did not retrieve httpbin's authenticated view: {}",
        raw_html(&authenticated)
    );
}

// VAL-CRAWL-131: count and cumulative-byte caps fail the scrape before emitting a partial proof.
#[test]
fn aggregate_render_resource_caps_are_enforced_and_exposed() {
    let (base, _) = server();
    let target = format!("{base}/assets");
    let output = run(&[
        &target,
        "--formats",
        "html",
        "--robots",
        "ignore",
        "--max-render-subresources",
        "2",
        "--max-render-bytes",
        "1024",
    ]);
    assert!(
        !output.status.success(),
        "aggregate cap exhaustion must fail the scrape"
    );
    assert!(
        output.stdout.is_empty(),
        "resource exhaustion must not emit a partial ScrapeProof"
    );
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("resource exhaustion must be structured");
    assert!(
        error["error"]["kind"] == "resource_budget_exceeded",
        "aggregate cap error must be explicit: {error}"
    );
}
