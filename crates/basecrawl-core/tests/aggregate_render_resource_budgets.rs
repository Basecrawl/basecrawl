//! Regression coverage for the scrape-owned aggregate browser-resource budget.
//!
//! The fixtures deliberately omit or lie about `Content-Length` and make separate browser
//! launches for HTML, screenshots, and pagination. A successful partial proof would mean a
//! browser stage received a fresh independent budget rather than consuming the scrape budget.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const BODY_CAP: usize = 256;
const RESOURCE_CAP: usize = 512;
const OVERSIZED_BODY: usize = BODY_CAP + 512;
const OVERSIZED_RESOURCE: usize = RESOURCE_CAP + 512;

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn write_response(mut stream: TcpStream, headers: &[(&str, String)], body: &[u8]) {
    let mut response = String::from("HTTP/1.1 200 OK\r\nConnection: close\r\n");
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write headers");
    stream.write_all(body).expect("write body");
    stream.flush().expect("flush response");
}

fn write_chunked_response(mut stream: TcpStream, content_type: &str, body: &[u8]) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\
Connection: close\r\n\r\n"
    );
    write_chunked_body(&mut stream, response.as_bytes(), body);
}

fn write_chunked_response_with_lie(mut stream: TcpStream, content_type: &str, body: &[u8]) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: 1\r\n\
Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    write_chunked_body(&mut stream, response.as_bytes(), body);
}

fn write_chunked_body(stream: &mut TcpStream, headers: &[u8], body: &[u8]) {
    stream.write_all(headers).expect("write headers");
    for chunk in body.chunks(97) {
        write!(stream, "{:X}\r\n", chunk.len()).expect("write chunk size");
        stream.write_all(chunk).expect("write chunk");
        stream.write_all(b"\r\n").expect("write chunk terminator");
        stream.flush().expect("flush chunk");
        thread::sleep(Duration::from_millis(2));
    }
    stream
        .write_all(b"0\r\n\r\n")
        .expect("write terminal chunk");
    stream.flush().expect("flush response");
}

fn request(stream: TcpStream) -> Option<(TcpStream, String)> {
    let peer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    Some((peer, request_line.split_whitespace().nth(1)?.to_string()))
}

fn page(body: &str) -> Vec<u8> {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Budget</title></head>\
<body>{body}</body></html>"
    )
    .into_bytes()
}

fn handle_connection(stream: TcpStream) {
    let Some((mut peer, path)) = request(stream) else {
        return;
    };

    match path.as_str() {
        "/unknown-length-asset" => write_response(
            peer,
            &[("Content-Type", "text/html; charset=utf-8".to_string())],
            &page("<main>UNKNOWN_LENGTH</main><img src=\"/chunked-resource\">"),
        ),
        "/chunked-resource" => {
            write_chunked_response(peer, "image/png", &vec![b'x'; OVERSIZED_RESOURCE])
        }
        "/lying-length-asset" => write_response(
            peer,
            &[("Content-Type", "text/html; charset=utf-8".to_string())],
            &page("<main>LYING_LENGTH</main><img src=\"/lying-resource\">"),
        ),
        "/lying-resource" => {
            write_chunked_response_with_lie(peer, "image/png", &vec![b'x'; OVERSIZED_RESOURCE])
        }
        "/large-document" => write_chunked_response(
            peer,
            "text/html; charset=utf-8",
            &page(&format!("<main>{}</main>", "D".repeat(OVERSIZED_BODY))),
        ),
        "/large-document-redirect" => {
            let response = "HTTP/1.1 302 Found\r\nLocation: /large-document\r\n\
Connection: close\r\nContent-Length: 0\r\n\r\n";
            peer.write_all(response.as_bytes()).expect("write redirect");
            peer.flush().expect("flush redirect");
        }
        "/large-document-client-nav" => write_response(
            peer,
            &[("Content-Type", "text/html; charset=utf-8".to_string())],
            &page(
                "<main>CLIENT_NAV_START</main><script>\
setTimeout(function(){location='/large-document';},100)</script>",
            ),
        ),
        "/pagination/one" => write_response(
            peer,
            &[
                ("Content-Type", "text/html; charset=utf-8".to_string()),
                ("Content-Length", "200".to_string()),
            ],
            &page(
                "<main>PAGINATION_ONE</main><img src=\"/small-resource\"><a rel=\"next\" \
href=\"/pagination/two\">next</a>",
            ),
        ),
        "/pagination/two" => write_response(
            peer,
            &[
                ("Content-Type", "text/html; charset=utf-8".to_string()),
                ("Content-Length", "200".to_string()),
            ],
            &page("<main>PAGINATION_TWO</main><img src=\"/small-resource\">"),
        ),
        "/small-resource" => write_response(
            peer,
            &[
                ("Content-Type", "image/png".to_string()),
                ("Content-Length", "384".to_string()),
            ],
            &vec![b'x'; 384],
        ),
        "/plain" => write_response(
            peer,
            &[("Content-Type", "text/html; charset=utf-8".to_string())],
            &page("<main>PLAIN_RENDER_PAGE</main>"),
        ),
        _ => write_response(
            peer,
            &[("Content-Type", "text/plain; charset=utf-8".to_string())],
            b"not found",
        ),
    }
}

fn server_base() -> &'static str {
    static BASE: OnceLock<String> = OnceLock::new();
    BASE.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local resource-budget server");
        let port = listener.local_addr().expect("server address").port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_connection(stream));
            }
        });
        format!("http://127.0.0.1:{port}")
    })
}

fn assert_resource_budget_error(output: Output, started: Instant) {
    assert!(
        !output.status.success(),
        "resource exhaustion must fail immediately instead of emitting a partial proof\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.stdout.is_empty(),
        "a resource-budget error must never emit a partial ScrapeProof"
    );
    let error: Value = serde_json::from_slice(&output.stderr).unwrap_or_else(|parse_error| {
        panic!(
            "stderr must be a structured error ({parse_error}), status: {:?}, stdout: {}, stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    assert_eq!(
        error["error"]["kind"], "resource_budget_exceeded",
        "expected structured resource-budget exhaustion: {error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "resource exhaustion must abort without waiting for the 15-second scrape deadline"
    );
}

fn run_and_assert_resource_budget_error(args: &[&str]) {
    let started = Instant::now();
    assert_resource_budget_error(run(args), started);
}

fn render_args_with_budget<'a>(
    target: &'a str,
    formats: &'a str,
    max_requests: &'a str,
    max_bytes: &'a str,
) -> Vec<&'a str> {
    vec![
        target,
        "--formats",
        formats,
        "--robots",
        "ignore",
        "--timeout",
        "15",
        "--max-body-bytes",
        "256",
        "--max-render-subresources",
        max_requests,
        "--max-render-bytes",
        max_bytes,
    ]
}

fn render_args<'a>(target: &'a str, formats: &'a str) -> Vec<&'a str> {
    render_args_with_budget(target, formats, "8", "512")
}

#[test]
fn chunked_subresources_consume_observed_bytes_not_zero() {
    let target = format!("{}/unknown-length-asset", server_base());
    let args = render_args(&target, "html");
    run_and_assert_resource_budget_error(&args);
}

#[test]
fn lying_content_length_cannot_bypass_observed_byte_cap() {
    let target = format!("{}/lying-length-asset", server_base());
    let args = render_args(&target, "html");
    run_and_assert_resource_budget_error(&args);
}

#[test]
fn browser_document_recaptures_are_bounded_by_the_direct_body_cap() {
    for path in [
        "/large-document",
        "/large-document-redirect",
        "/large-document-client-nav",
    ] {
        let target = format!("{}{path}", server_base());
        let args = render_args(&target, "html");
        run_and_assert_resource_budget_error(&args);
    }
}

#[test]
fn html_and_screenshot_share_one_scrape_owned_request_budget() {
    let target = format!("{}/plain", server_base());
    let args = render_args_with_budget(&target, "html,screenshot", "1", "4096");
    run_and_assert_resource_budget_error(&args);
}

#[test]
fn pagination_uses_the_remaining_scrape_owned_request_budget() {
    let target = format!("{}/pagination/one", server_base());
    let mut args = render_args_with_budget(&target, "markdown", "1", "4096");
    args.extend(["--follow-pagination", "--max-pages", "2"]);
    run_and_assert_resource_budget_error(&args);
}
