//! Regression coverage for the scrape-owned absolute deadline.
//!
//! Each fixture deliberately takes less than the configured timeout for an individual request, but
//! takes longer when all scrape stages are added together. A successful proof after that budget is
//! exhausted would prove that a hop/page reset the timeout.

use base64::Engine;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const HOP_DELAY: Duration = Duration::from_millis(350);
const SLOW_RENDER_DELAY: Duration = Duration::from_millis(650);
const SETUP_DELAY: Duration = Duration::from_millis(250);
const UPGRADE_TRICKLE_INTERVAL: Duration = Duration::from_millis(80);

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn run_with_chrome(args: &[&str], chrome: &str) -> Output {
    Command::new(BIN)
        .args(args)
        .env("CHROME", chrome)
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
    let error = structured_error(out, "stderr must be a structured error");
    assert_eq!(
        error["error"]["kind"], "timeout",
        "unexpected error: {error}"
    );
}

fn structured_error(out: &Output, context: &str) -> Value {
    serde_json::from_slice(&out.stderr).unwrap_or_else(|error| {
        panic!(
            "{context}: {error}; stderr was: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// A minimal CDP WebSocket peer which deliberately delays each browser-setup response. The direct
/// fetch completes in 650ms, leaving less than the 1s scrape deadline for the CDP setup sequence.
/// A fresh timeout at every setup step incorrectly lets this peer consume roughly one second more.
struct DelayedCdpServer {
    chrome_script: String,
    pid_file: PathBuf,
}

impl DelayedCdpServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed CDP server");
        let port = listener.local_addr().expect("read delayed CDP port").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept CDP WebSocket");
            serve_delayed_cdp(stream);
        });

        let script = std::env::temp_dir().join(format!(
            "basecrawl-delayed-cdp-chrome-{}-{port}.sh",
            std::process::id()
        ));
        let pid_file = script.with_extension("pid");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > {pid_file}\nprintf 'DevTools listening on ws://127.0.0.1:{port}/devtools/browser/delayed\\n' >&2\nexec sleep 60\n",
                pid_file = pid_file.display(),
            ),
        )
        .expect("write fake Chrome launcher");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                .expect("mark fake Chrome launcher executable");
        }

        Self {
            chrome_script: script.to_string_lossy().into_owned(),
            pid_file,
        }
    }

    fn assert_browser_terminated(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(pid) = fs::read_to_string(&self.pid_file) {
                let process = PathBuf::from(format!("/proc/{}", pid.trim()));
                if !process.exists() {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "browser setup deadline must not leave its Chrome process running"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for DelayedCdpServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.chrome_script);
        let _ = fs::remove_file(&self.pid_file);
    }
}

/// A CDP endpoint that sends a syntactically valid HTTP 101 status line but never completes the
/// WebSocket upgrade. Each byte arrives well within a resettable socket timeout, so only the
/// caller-owned absolute deadline can end the setup promptly.
struct TricklingUpgradeCdpServer {
    chrome_script: String,
    pid_file: PathBuf,
    stop: Arc<AtomicBool>,
    peer: Option<thread::JoinHandle<()>>,
}

impl TricklingUpgradeCdpServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind trickling CDP server");
        listener
            .set_nonblocking(true)
            .expect("make trickling CDP listener nonblocking");
        let port = listener
            .local_addr()
            .expect("read trickling CDP port")
            .port();
        let stop = Arc::new(AtomicBool::new(false));
        let peer_stop = Arc::clone(&stop);
        let peer = thread::spawn(move || {
            while !peer_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve_trickling_upgrade(stream, &peer_stop);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept trickling CDP WebSocket: {error}"),
                }
            }
        });

        let script = std::env::temp_dir().join(format!(
            "basecrawl-trickling-cdp-chrome-{}-{port}.sh",
            std::process::id()
        ));
        let pid_file = script.with_extension("pid");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > {pid_file}\nprintf 'DevTools listening on ws://127.0.0.1:{port}/devtools/browser/trickling\\n' >&2\nexec sleep 60\n",
                pid_file = pid_file.display(),
            ),
        )
        .expect("write trickling fake Chrome launcher");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                .expect("mark trickling fake Chrome launcher executable");
        }

        Self {
            chrome_script: script.to_string_lossy().into_owned(),
            pid_file,
            stop,
            peer: Some(peer),
        }
    }

    fn assert_cleaned_up(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(pid) = fs::read_to_string(&self.pid_file) {
                let process = PathBuf::from(format!("/proc/{}", pid.trim()));
                if !process.exists() {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "an interrupted WebSocket upgrade must not leave its Chrome process running"
            );
            thread::sleep(Duration::from_millis(20));
        }

        self.stop.store(true, Ordering::SeqCst);
        self.peer
            .take()
            .expect("trickling peer is joined once")
            .join()
            .expect("trickling peer thread must not panic");
    }
}

impl Drop for TricklingUpgradeCdpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(peer) = self.peer.take() {
            peer.join()
                .expect("trickling peer thread must not panic during cleanup");
        }
        let _ = fs::remove_file(&self.chrome_script);
        let _ = fs::remove_file(&self.pid_file);
    }
}

fn serve_delayed_cdp(mut stream: TcpStream) {
    complete_websocket_handshake(&mut stream);

    while let Some(message) = read_websocket_text(&mut stream) {
        let request: Value = serde_json::from_str(&message).expect("decode CDP request");
        let id = request["id"].as_u64().expect("CDP request id");
        let method = request["method"].as_str().expect("CDP method");

        match method {
            "Target.setDiscoverTargets" => {
                delay_setup();
                send_cdp_result(&mut stream, id, serde_json::json!({}));
            }
            "Target.createTarget" => {
                delay_setup();
                send_cdp_result(&mut stream, id, serde_json::json!({"targetId":"target-1"}));
                send_websocket_text(
                    &mut stream,
                    &serde_json::json!({
                        "method":"Target.targetCreated",
                        "params":{"targetInfo":{
                            "targetId":"target-1",
                            "type":"page",
                            "title":"",
                            "url":"about:blank",
                            "attached":false,
                            "canAccessOpener":false
                        }}
                    })
                    .to_string(),
                );
            }
            "Target.attachToTarget" => {
                delay_setup();
                send_cdp_result(
                    &mut stream,
                    id,
                    serde_json::json!({"sessionId":"session-1"}),
                );
            }
            "Target.sendMessageToTarget" => {
                send_cdp_result(&mut stream, id, serde_json::json!({}));
                let nested: Value = serde_json::from_str(
                    request["params"]["message"].as_str().expect("nested CDP"),
                )
                .expect("decode nested CDP request");
                let nested_id = nested["id"].as_u64().expect("nested CDP request id");
                delay_setup();
                send_websocket_text(
                    &mut stream,
                    &serde_json::json!({
                        "method":"Target.receivedMessageFromTarget",
                        "params":{
                            "sessionId":"session-1",
                            "message":serde_json::json!({"id":nested_id,"result":{}}).to_string()
                        }
                    })
                    .to_string(),
                );
            }
            "Browser.close" => {
                send_cdp_result(&mut stream, id, serde_json::json!({}));
                break;
            }
            unexpected => panic!("unexpected CDP method from setup fixture: {unexpected}"),
        }
    }
}

fn serve_trickling_upgrade(mut stream: TcpStream, stop: &AtomicBool) {
    stream
        .set_write_timeout(Some(Duration::from_millis(100)))
        .expect("bound trickling peer writes");

    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        request.push(byte[0]);
    }

    for byte in b"HTTP/1.1 101 Switching Protocols\r\n" {
        if stop.load(Ordering::SeqCst)
            || stream.write_all(std::slice::from_ref(byte)).is_err()
            || stream.flush().is_err()
        {
            return;
        }
        thread::sleep(UPGRADE_TRICKLE_INTERVAL);
    }
}

fn delay_setup() {
    thread::sleep(SETUP_DELAY);
}

fn complete_websocket_handshake(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("read WebSocket upgrade request");
        request.push(byte[0]);
    }
    let request = String::from_utf8(request).expect("upgrade request is UTF-8");
    let key = request
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .expect("WebSocket key");
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = base64::prelude::BASE64_STANDARD.encode(hasher.finalize());
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    .expect("write WebSocket upgrade response");
    stream.flush().expect("flush WebSocket upgrade response");
}

fn read_websocket_text(stream: &mut TcpStream) -> Option<String> {
    let mut header = [0_u8; 2];
    if stream.read_exact(&mut header).is_err() {
        return None;
    }
    if header[0] & 0x0f == 0x8 {
        return None;
    }
    assert_eq!(header[0] & 0x0f, 0x1, "expected text WebSocket frame");
    let masked = header[1] & 0x80 != 0;
    assert!(masked, "CDP client frames must be masked");
    let length = read_websocket_length(stream, header[1] & 0x7f);
    let mut mask = [0_u8; 4];
    stream.read_exact(&mut mask).expect("read WebSocket mask");
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .expect("read WebSocket payload");
    for (index, value) in payload.iter_mut().enumerate() {
        *value ^= mask[index % mask.len()];
    }
    Some(String::from_utf8(payload).expect("CDP text payload is UTF-8"))
}

fn read_websocket_length(stream: &mut TcpStream, initial: u8) -> usize {
    match initial {
        value @ 0..=125 => usize::from(value),
        126 => {
            let mut bytes = [0_u8; 2];
            stream
                .read_exact(&mut bytes)
                .expect("read 16-bit frame length");
            usize::from(u16::from_be_bytes(bytes))
        }
        127 => {
            let mut bytes = [0_u8; 8];
            stream
                .read_exact(&mut bytes)
                .expect("read 64-bit frame length");
            usize::try_from(u64::from_be_bytes(bytes)).expect("frame length fits usize")
        }
        _ => unreachable!("WebSocket frame lengths use seven bits"),
    }
}

fn send_cdp_result(stream: &mut TcpStream, id: u64, result: Value) {
    send_websocket_text(
        stream,
        &serde_json::json!({"id":id,"result":result}).to_string(),
    );
}

fn send_websocket_text(stream: &mut TcpStream, payload: &str) {
    let bytes = payload.as_bytes();
    let mut header = vec![0x81];
    match bytes.len() {
        length @ 0..=125 => header.push(length as u8),
        length @ 126..=65_535 => {
            header.push(126);
            header.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            header.push(127);
            header.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    stream.write_all(&header).expect("write WebSocket header");
    stream
        .write_all(bytes)
        .expect("write WebSocket text payload");
    stream.flush().expect("flush WebSocket text payload");
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
    let error = structured_error(&out, "stderr must be a structured error");
    assert_eq!(error["error"]["kind"], "timeout");
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
    let error = structured_error(&out, "stderr must be a structured error");
    assert_eq!(error["error"]["kind"], "timeout");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "screenshot navigation must not receive a fresh one-second timeout"
    );
}

#[test]
fn render_browser_setup_consumes_the_remaining_scrape_deadline() {
    let delayed_cdp = DelayedCdpServer::new();
    let url = format!("{}/slow-render", server_base());
    let start = Instant::now();
    let out = run_with_chrome(
        &[
            &url,
            "--formats",
            "html",
            "--robots",
            "ignore",
            "--timeout",
            "1",
        ],
        &delayed_cdp.chrome_script,
    );

    assert_timeout_without_proof(&out);
    assert!(
        start.elapsed() < Duration::from_millis(1_400),
        "delayed browser setup must not receive a fresh timeout per CDP step (took {:?})",
        start.elapsed()
    );
    delayed_cdp.assert_browser_terminated();
}

#[test]
fn screenshot_browser_setup_consumes_the_remaining_scrape_deadline() {
    let delayed_cdp = DelayedCdpServer::new();
    let url = format!("{}/slow-render", server_base());
    let start = Instant::now();
    let out = run_with_chrome(
        &[
            &url,
            "--formats",
            "screenshot",
            "--robots",
            "ignore",
            "--timeout",
            "1",
        ],
        &delayed_cdp.chrome_script,
    );

    assert_timeout_without_proof(&out);
    assert!(
        start.elapsed() < Duration::from_millis(1_400),
        "delayed screenshot setup must not receive a fresh timeout per CDP step (took {:?})",
        start.elapsed()
    );
    delayed_cdp.assert_browser_terminated();
}

#[test]
fn incomplete_trickling_websocket_upgrade_obeys_the_absolute_scrape_deadline() {
    let mut trickling_cdp = TricklingUpgradeCdpServer::new();
    let url = format!("{}/slow-render", server_base());
    let start = Instant::now();
    let out = run_with_chrome(
        &[
            &url,
            "--formats",
            "html",
            "--robots",
            "ignore",
            "--timeout",
            "1",
        ],
        &trickling_cdp.chrome_script,
    );

    assert_timeout_without_proof(&out);
    trickling_cdp.assert_cleaned_up();
    assert!(
        start.elapsed() < Duration::from_millis(1_400),
        "a trickling incomplete upgrade must not reset the one-second scrape deadline (took {:?})",
        start.elapsed()
    );
}
