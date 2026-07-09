//! Egress and confidentiality-boundary assertions (VAL-CRAWL-117..121).

use basecrawl_core::{scrape, Action, Format, ScrapeOptions};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::process::{Command, Output};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const EXAMPLE: &str = "https://example.com/";

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
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .expect("stdout must be one strict ScrapeProof JSON object")
}

// VAL-CRAWL-117..120.
#[test]
fn scrape_emits_complete_non_attestation_egress_metadata() {
    let proof = scrape_json(&[EXAMPLE, "--no-js"]);
    let egress = proof["egress"]
        .as_object()
        .expect("egress must be an object");

    let timestamp = egress["timestamp"]
        .as_str()
        .expect("egress.timestamp must be present");
    let parsed =
        OffsetDateTime::parse(timestamp, &Rfc3339).expect("timestamp must be RFC 3339 / ISO-8601");
    assert!(
        parsed.offset().is_utc(),
        "timestamp must use a UTC offset, got {timestamp}"
    );
    assert!(
        (OffsetDateTime::now_utc() - parsed).abs() < time::Duration::seconds(10),
        "timestamp must be within a few seconds of fetch time, got {timestamp}"
    );

    let ip = egress["egress_ip"]
        .as_str()
        .expect("egress.egress_ip must be present");
    IpAddr::from_str(ip).unwrap_or_else(|error| {
        panic!("egress.egress_ip must be syntactically valid, got {ip}: {error}");
    });

    assert!(
        egress["fingerprint_seed"]
            .as_str()
            .is_some_and(|seed| !seed.is_empty()),
        "egress.fingerprint_seed must be present and non-empty"
    );
    assert!(
        egress["landmark_rtts"].is_object(),
        "egress.landmark_rtts must always be an object"
    );
}

// VAL-CRAWL-117: fetch time must not be shifted by later rendering work.
#[test]
fn egress_timestamp_tracks_the_network_fetch_not_later_render_steps() {
    const HTML: &str = "<!doctype html><html><body>timestamp test</body></html>";
    const RENDER_WAIT_MS: u64 = 1_500;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut first_fetch_completed = None;
        for request_number in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set request read timeout");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).expect("read request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{HTML}",
                HTML.len()
            )
            .expect("write response");
            if request_number == 0 {
                first_fetch_completed = Some(OffsetDateTime::now_utc());
            }
        }
        first_fetch_completed.expect("first fetch time")
    });

    let proof = scrape(
        &url,
        &ScrapeOptions {
            formats: vec![Format::Html],
            actions: vec![Action::Wait {
                milliseconds: RENDER_WAIT_MS,
            }],
            timeout_secs: 10,
            render_timeout_secs: 10,
            ..ScrapeOptions::default()
        },
    )
    .expect("scrape must succeed");
    let first_fetch_completed = server.join().expect("test server must complete");
    let timestamp = proof.egress.timestamp.expect("egress timestamp");
    let recorded = OffsetDateTime::parse(&timestamp, &Rfc3339).expect("RFC 3339 timestamp");

    assert!(
        (recorded - first_fetch_completed).abs() < time::Duration::seconds(1),
        "timestamp must record the completed network fetch, not the later {RENDER_WAIT_MS}ms render action; got {recorded}, fetch completed {first_fetch_completed}"
    );
}

// VAL-CRAWL-122.
#[test]
fn emitted_proof_validates_against_the_published_schema() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../basecrawl-proof/schema/scrapeproof.schema.json"
    ))
    .expect("published schema must be valid JSON");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .expect("published schema must compile under its declared draft");

    let proof = scrape_json(&[EXAMPLE, "--no-js"]);
    if let Err(errors) = validator.validate(&proof) {
        let errors = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("emitted ScrapeProof must validate: {errors:#?}");
    }

    let mut invalid_proof = proof.clone();
    invalid_proof["egress"]["timestamp"] = Value::Null;
    assert!(
        !validator.is_valid(&invalid_proof),
        "schema must reject an egress block without an RFC 3339 timestamp"
    );

    invalid_proof["egress"]["timestamp"] = Value::String("not-a-timestamp".to_string());
    assert!(
        !validator.is_valid(&invalid_proof),
        "schema must validate the RFC 3339 timestamp format"
    );
    invalid_proof["egress"]["timestamp"] = proof["egress"]["timestamp"].clone();
    invalid_proof["egress"]["egress_ip"] = Value::String("not-an-ip-address".to_string());
    assert!(
        !validator.is_valid(&invalid_proof),
        "schema must validate the egress IP address format"
    );
}

// VAL-CRAWL-121.
#[test]
fn verbose_output_redacts_auth_headers_cookies_and_response_bodies() {
    const AUTH_SECRET: &str = "auth-header-secret-marker";
    const COOKIE_SECRET: &str = "cookie-secret-marker";
    const CUSTOM_HEADER_VALUE: &str = "custom-header-secret-marker";
    const RESPONSE_SECRET: &str = "response-body-secret-marker";

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    listener
        .set_nonblocking(true)
        .expect("configure nonblocking test server");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0u8; 4096];
                    let received = stream.read(&mut request).expect("read request");
                    let request = String::from_utf8_lossy(&request[..received]);
                    let request_lower = request.to_ascii_lowercase();
                    assert!(
                        request_lower.contains("authorization: bearer auth-header-secret-marker"),
                        "custom authorization header must still reach the origin"
                    );
                    assert!(
                        request_lower.contains("cookie: session=cookie-secret-marker"),
                        "custom cookie header must still reach the origin"
                    );
                    assert!(
                        request_lower.contains("x-redaction-probe: custom-header-secret-marker"),
                        "custom headers must still reach the origin"
                    );
                    let response_body = format!(
                        "{AUTH_SECRET}|{COOKIE_SECRET}|{CUSTOM_HEADER_VALUE}|{RESPONSE_SECRET}"
                    );
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                        response_body.len()
                    )
                    .expect("write response");
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept request: {error}"),
            }
        }
        false
    });

    let output = run(&[
        &url,
        "--formats",
        "rawHtml",
        "--no-js",
        "--verbose",
        "--header",
        "Authorization: Bearer auth-header-secret-marker",
        "--header",
        "Cookie: session=cookie-secret-marker",
        "--header",
        "X-Redaction-Probe: custom-header-secret-marker",
    ]);
    let accepted = server.join().expect("test server must complete");

    assert!(
        output.status.success(),
        "verbose scrape must succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(accepted, "verbose scrape must reach the origin");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    for secret in [AUTH_SECRET, COOKIE_SECRET, CUSTOM_HEADER_VALUE] {
        assert!(
            !stdout.contains(secret) && !stderr.contains(secret),
            "proof and verbose logs must redact request secret marker {secret}"
        );
    }
    assert!(
        stdout.contains(RESPONSE_SECRET),
        "the requested result format must preserve an ordinary response body"
    );
    assert!(
        !stderr.contains(RESPONSE_SECRET),
        "verbose logs must never print response bodies"
    );

    let proof: Value = serde_json::from_str(stdout.trim()).expect("stdout must remain strict JSON");
    let headers_hash = proof["request"]["headers_hash"]
        .as_str()
        .expect("request headers must be represented by a hash");
    assert_eq!(headers_hash.len(), 64);
    assert!(stderr.contains("scrape_completed"));
    assert!(stderr.contains(headers_hash));
}
