//! Request-header canonicalization and transport parity regressions.
//!
//! The loopback origin records field lines in the order received. This makes header multiplicity
//! and sequencing observable without relying on a server framework that could normalize them.

use basecrawl_core::canonical;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

type HeaderLines = Vec<(String, String)>;

#[derive(Debug, Default)]
struct ServerState {
    requests: Mutex<Vec<HeaderLines>>,
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
        "expected success, got {:?}\nargs: {args:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must be one strict ScrapeProof JSON")
}

fn read_headers(stream: TcpStream) -> Option<(TcpStream, HeaderLines)> {
    let peer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((
            name.trim().to_ascii_lowercase(),
            value
                .trim_end_matches(['\r', '\n'])
                .trim_start()
                .to_string(),
        ));
    }
    Some((peer, headers))
}

fn respond(mut stream: TcpStream) {
    const BODY: &[u8] = b"<!doctype html><html><body>header fixture</body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response");
    stream.write_all(BODY).expect("write body");
    stream.flush().expect("flush response");
}

fn server() -> (String, Arc<ServerState>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let state = Arc::new(ServerState::default());
    let accepting_state = Arc::clone(&state);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let state = Arc::clone(&accepting_state);
            thread::spawn(move || {
                let Some((peer, headers)) = read_headers(stream) else {
                    return;
                };
                state
                    .requests
                    .lock()
                    .expect("fixture request lock")
                    .push(headers);
                respond(peer);
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), state)
}

fn custom_headers(headers: &HeaderLines) -> HeaderLines {
    headers
        .iter()
        .filter(|(name, _)| name == "x-first" || name == "x-second")
        .cloned()
        .collect()
}

#[test]
fn canonical_header_hash_binds_occurrences_and_sequence() {
    let single = canonical::headers_hash(&[("X-First".into(), "one".into())]);
    let duplicate = canonical::headers_hash(&[
        ("X-First".into(), "one".into()),
        ("X-First".into(), "one".into()),
    ]);
    let ordered = canonical::headers_hash(&[
        ("X-First".into(), "one".into()),
        ("X-Second".into(), "two".into()),
    ]);
    let reordered = canonical::headers_hash(&[
        ("X-Second".into(), "two".into()),
        ("X-First".into(), "one".into()),
    ]);

    assert_ne!(
        single, duplicate,
        "a repeated emitted field line is load-bearing"
    );
    assert_ne!(
        ordered, reordered,
        "the defined caller header sequence is load-bearing"
    );
}

#[test]
fn cli_hash_and_wire_order_track_ordered_headers() {
    let (base, state) = server();
    state.requests.lock().expect("fixture request lock").clear();
    let target = format!("{base}/ordered");

    let first = scrape_json(&[
        &target,
        "--formats",
        "rawHtml",
        "--no-js",
        "--robots",
        "ignore",
        "--header",
        "X-First: one",
        "--header",
        "X-Second: two",
    ]);
    let second = scrape_json(&[
        &target,
        "--formats",
        "rawHtml",
        "--no-js",
        "--robots",
        "ignore",
        "--header",
        "X-Second: two",
        "--header",
        "X-First: one",
    ]);

    let requests = state.requests.lock().expect("fixture request lock").clone();
    assert_eq!(
        requests.len(),
        2,
        "each CLI scrape must reach the fixture once"
    );
    assert_eq!(
        custom_headers(&requests[0]),
        vec![
            ("x-first".into(), "one".into()),
            ("x-second".into(), "two".into()),
        ],
        "HTTP must preserve the defined custom-header sequence"
    );
    assert_eq!(
        custom_headers(&requests[1]),
        vec![
            ("x-second".into(), "two".into()),
            ("x-first".into(), "one".into()),
        ],
        "HTTP must preserve a reordered custom-header sequence"
    );
    assert_ne!(
        first["request"]["headers_hash"],
        second["request"]["headers_hash"]
    );
    assert_ne!(
        first["request"]["request_hash"],
        second["request"]["request_hash"]
    );
}

#[test]
fn http_https_and_chromium_share_the_validated_effective_headers() {
    let (base, state) = server();
    let http_target = format!("{base}/rendered");
    let headers = ["--header", "X-First: one", "--header", "X-Second: two"];

    let http = scrape_json(&[
        &http_target,
        "--formats",
        "rawHtml",
        "--no-js",
        "--robots",
        "ignore",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
    ]);
    let https = scrape_json(&[
        "https://example.com/",
        "--formats",
        "rawHtml",
        "--no-js",
        "--robots",
        "ignore",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
    ]);
    assert_eq!(
        http["request"]["headers_hash"], https["request"]["headers_hash"],
        "HTTP and HTTPS must hash the identical validated effective-header list"
    );

    state.requests.lock().expect("fixture request lock").clear();
    let rendered = scrape_json(&[
        &http_target,
        "--formats",
        "html",
        "--robots",
        "ignore",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
    ]);
    let requests = state.requests.lock().expect("fixture request lock").clone();
    assert!(
        requests.len() >= 2,
        "an HTML scrape must perform a direct fetch and Chromium navigation"
    );
    let expected = vec![
        ("x-first".into(), "one".into()),
        ("x-second".into(), "two".into()),
    ];
    for request in requests {
        assert_eq!(
            custom_headers(&request),
            expected,
            "every Chromium document/subresource request must retain the effective headers"
        );
    }
    assert_eq!(
        rendered["request"]["headers_hash"], http["request"]["headers_hash"],
        "Chromium must consume the same effective-header representation as direct transports"
    );

    state.requests.lock().expect("fixture request lock").clear();
    let screenshot = scrape_json(&[
        &http_target,
        "--formats",
        "screenshot",
        "--robots",
        "ignore",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
    ]);
    for request in state.requests.lock().expect("fixture request lock").iter() {
        assert_eq!(
            custom_headers(request),
            expected,
            "the Chromium screenshot path must retain the effective headers"
        );
    }
    assert_eq!(
        screenshot["request"]["headers_hash"], http["request"]["headers_hash"],
        "screenshot capture must share the direct request header representation"
    );
}

#[test]
fn cli_rejects_duplicate_and_case_variant_header_names_before_fetch() {
    let (base, state) = server();
    let target = format!("{base}/must-not-fetch");

    for headers in [
        ["X-Duplicate: one", "X-Duplicate: two"],
        ["X-Case-Variant: one", "x-case-variant: two"],
    ] {
        state.requests.lock().expect("fixture request lock").clear();
        let output = run(&[
            &target,
            "--formats",
            "rawHtml",
            "--no-js",
            "--robots",
            "ignore",
            "--header",
            headers[0],
            "--header",
            headers[1],
        ]);
        assert!(
            !output.status.success(),
            "ambiguous headers must be rejected"
        );
        assert!(output.stdout.is_empty(), "no partial proof is allowed");
        let error: Value =
            serde_json::from_slice(&output.stderr).expect("structured error JSON on stderr");
        assert_eq!(error["error"]["kind"], "invalid_header");
        thread::sleep(Duration::from_millis(50));
        assert!(
            state
                .requests
                .lock()
                .expect("fixture request lock")
                .is_empty(),
            "header validation must happen before any network access"
        );
    }
}
