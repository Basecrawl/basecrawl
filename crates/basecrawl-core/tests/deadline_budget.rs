//! Regression coverage for the scrape-owned absolute deadline.
//!
//! Each fixture deliberately takes less than the configured timeout for an individual request, but
//! takes longer when all scrape stages are added together. A successful proof after that budget is
//! exhausted would prove that a hop/page reset the timeout.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const HOP_DELAY: Duration = Duration::from_millis(350);
const SLOW_RENDER_DELAY: Duration = Duration::from_millis(650);

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn write_response(mut stream: TcpStream, status: &str, headers: &[(&str, String)], body: &str) {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
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
    if let Some(remaining) = path.strip_prefix("/slow-redirect/") {
        let remaining: usize = remaining.parse().unwrap_or_default();
        thread::sleep(HOP_DELAY);
        if remaining == 0 {
            write_response(peer, "200 OK", &[], "<main>TERMINAL</main>");
        } else {
            write_response(
                peer,
                "302 Found",
                &[("Location", format!("/slow-redirect/{}", remaining - 1))],
                "",
            );
        }
    } else if path == "/pages/one" {
        write_response(
            peer,
            "200 OK",
            &[],
            "<main>PAGE_ONE</main><a rel=\"next\" href=\"/pages/two\">next</a>",
        );
    } else if path == "/pages/two" {
        thread::sleep(Duration::from_millis(1_300));
        write_response(peer, "200 OK", &[], "<main>PAGE_TWO</main>");
    } else if path == "/slow-render" {
        thread::sleep(SLOW_RENDER_DELAY);
        write_response(peer, "200 OK", &[], "<main>SLOW_RENDER_PAGE</main>");
    } else {
        write_response(peer, "404 Not Found", &[], "not found");
    }
}

fn server_base() -> &'static str {
    static BASE: OnceLock<String> = OnceLock::new();
    BASE.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local address").port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_connection(stream));
            }
        });
        format!("http://127.0.0.1:{port}")
    })
}

fn assert_timeout_without_proof(out: &Output) {
    assert!(
        !out.status.success(),
        "deadline exhaustion must fail the scrape"
    );
    assert!(
        out.stdout.is_empty(),
        "a deadline error must not emit a partial ScrapeProof"
    );
    let error: Value =
        serde_json::from_slice(&out.stderr).expect("stderr must be a structured error");
    assert_eq!(
        error["error"]["kind"], "timeout",
        "unexpected error: {error}"
    );
}

#[test]
fn direct_redirect_hops_share_one_absolute_deadline() {
    let url = format!("{}/slow-redirect/4", server_base());
    let start = Instant::now();
    let out = run(&[
        &url,
        "--formats",
        "rawHtml",
        "--no-js",
        "--robots",
        "ignore",
        "--timeout",
        "1",
    ]);

    assert_timeout_without_proof(&out);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "redirect hops must not receive a fresh one-second timeout each"
    );
}

#[test]
fn pagination_deadline_failure_is_not_silently_returned_as_partial_success() {
    let url = format!("{}/pages/one", server_base());
    let out = run(&[
        &url,
        "--formats",
        "markdown",
        "--no-js",
        "--robots",
        "ignore",
        "--follow-pagination",
        "--timeout",
        "1",
    ]);

    assert_timeout_without_proof(&out);
}

#[test]
fn explicit_render_timeout_is_not_reset_after_the_direct_fetch() {
    let url = format!("{}/slow-render", server_base());
    let start = Instant::now();
    let out = run(&[
        &url,
        "--formats",
        "html",
        "--robots",
        "ignore",
        "--timeout",
        "30",
        "--render-timeout",
        "1",
    ]);

    assert!(
        !out.status.success(),
        "the render timeout must cap the browser stage after the direct fetch"
    );
    assert!(
        out.stdout.is_empty(),
        "a render-timeout error must not emit a partial ScrapeProof"
    );
    let error: Value =
        serde_json::from_slice(&out.stderr).expect("stderr must be a structured error");
    assert_eq!(error["error"]["kind"], "render_error");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("timed out")),
        "render timeout must be explicit: {error}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "the explicit render deadline must not reset to the 30-second scrape timeout"
    );
}

#[test]
fn screenshot_reuses_the_scrape_deadline_after_the_direct_fetch() {
    let url = format!("{}/slow-render", server_base());
    let start = Instant::now();
    let out = run(&[
        &url,
        "--formats",
        "screenshot",
        "--robots",
        "ignore",
        "--timeout",
        "1",
    ]);

    assert!(
        !out.status.success(),
        "a screenshot must consume the deadline remaining after the direct fetch"
    );
    assert!(
        out.stdout.is_empty(),
        "a screenshot timeout must not emit a partial ScrapeProof"
    );
    let error: Value =
        serde_json::from_slice(&out.stderr).expect("stderr must be a structured error");
    assert_eq!(error["error"]["kind"], "render_error");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "screenshot navigation must not receive a fresh one-second timeout"
    );
}
