//! End-to-end charset and international-text regression tests (VAL-CRAWL-099..102).
//!
//! The fixture server intentionally sends legacy-encoded bytes. Each test requests the source-only
//! path so the crawler's own fetch-decoding path, rather than Chromium's decoder, is exercised.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape(path: &str) -> Value {
    let url = format!("{}/{}", server_base(), path);
    let output = run(&[&url, "--formats", "markdown,rawHtml,metadata", "--no-js"]);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("crawler stdout must be UTF-8");
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("stdout is not a strict JSON object: {error}\n{stdout}"))
}

fn produced<'a>(proof: &'a Value, format: &str) -> &'a str {
    proof["result"]["formats_produced"][format]
        .as_str()
        .unwrap_or_else(|| panic!("format '{format}' missing/non-string:\n{proof}"))
}

fn write_response(mut stream: TcpStream, content_type: &str, body: &[u8]) {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn fixture(path: &str) -> (&'static str, Vec<u8>) {
    match path {
        "/latin1" => (
            "text/html; charset=ISO-8859-1",
            b"<!doctype html><html><head><title>Latin</title></head><body><main>caf\xe9 cr\xe8me</main></body></html>"
                .to_vec(),
        ),
        "/shift-jis-meta" => {
            let mut body = b"<!doctype html><html><head><meta charset=\"Shift_JIS\"><title>Japanese</title></head><body><main>"
                .to_vec();
            // "日本語の内容" in Shift_JIS, not UTF-8.
            body.extend([0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea, 0x82, 0xcc, 0x93, 0xe0, 0x97, 0x65]);
            body.extend(b"</main></body></html>");
            ("text/html", body)
        }
        "/header-wins" => (
            "text/html; charset=ISO-8859-1",
            b"<!doctype html><html><head><meta charset=\"Shift_JIS\"><title>Header wins</title></head><body><main>caf\xe9</main></body></html>"
                .to_vec(),
        ),
        "/cjk-utf8" => (
            "text/html; charset=utf-8",
            "<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\"><title>CJK</title></head><body><main>漢字かなカナ</main></body></html>"
                .as_bytes()
                .to_vec(),
        ),
        "/rtl-utf8" => (
            "text/html; charset=utf-8",
            "<!doctype html><html lang=\"ar\" dir=\"rtl\"><head><meta charset=\"utf-8\"><title>RTL</title></head><body><main>مرحبا بالعالم שלום עולם</main></body></html>"
                .as_bytes()
                .to_vec(),
        ),
        _ => ("text/plain; charset=utf-8", b"not found".to_vec()),
    }
}

fn handle_connection(stream: TcpStream) {
    let peer = stream.try_clone().expect("clone stream");
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

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let (content_type, body) = fixture(path);
    write_response(peer, content_type, &body);
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

// VAL-CRAWL-099: header-declared ISO-8859-1 is transcoded to valid UTF-8.
#[test]
fn latin1_header_is_transcoded_to_utf8_markdown() {
    let proof = scrape("latin1");
    let markdown = produced(&proof, "markdown");
    let raw_html = produced(&proof, "rawHtml");

    for surface in [markdown, raw_html] {
        assert!(
            surface.contains("café crème"),
            "legacy text was corrupted: {surface}"
        );
        assert!(
            !surface.contains('\u{fffd}'),
            "legacy text contains replacement characters: {surface}"
        );
    }
    assert_eq!(
        proof["result"]["formats_produced"]["metadata"]["charset"],
        "iso-8859-1"
    );
}

// VAL-CRAWL-099/100: a meta-declared Shift_JIS source is decoded before Markdown conversion.
#[test]
fn shift_jis_meta_charset_drives_utf8_markdown() {
    let proof = scrape("shift-jis-meta");
    let markdown = produced(&proof, "markdown");
    let raw_html = produced(&proof, "rawHtml");

    for surface in [markdown, raw_html] {
        assert!(
            surface.contains("日本語の内容"),
            "Shift_JIS text was corrupted: {surface}"
        );
        assert!(
            !surface.contains('\u{fffd}'),
            "Shift_JIS text contains replacement characters: {surface}"
        );
    }
    assert_eq!(
        proof["result"]["formats_produced"]["metadata"]["charset"],
        "shift_jis"
    );
}

// VAL-CRAWL-100: the HTTP declaration takes precedence over a conflicting HTML meta declaration.
#[test]
fn header_charset_overrides_conflicting_meta_charset() {
    let proof = scrape("header-wins");
    let markdown = produced(&proof, "markdown");

    assert!(
        markdown.contains("café"),
        "HTTP charset did not govern decoding: {markdown}"
    );
    assert!(
        !markdown.contains('\u{fffd}'),
        "HTTP-declared text contains replacement characters: {markdown}"
    );
    assert_eq!(
        proof["result"]["formats_produced"]["metadata"]["charset"],
        "iso-8859-1"
    );
}

// VAL-CRAWL-101: multibyte CJK source text round-trips unchanged.
#[test]
fn cjk_utf8_text_round_trips_without_replacement_characters() {
    let proof = scrape("cjk-utf8");
    let markdown = produced(&proof, "markdown");

    assert!(
        markdown.contains("漢字かなカナ"),
        "CJK text was corrupted: {markdown}"
    );
    assert!(
        !markdown.contains('\u{fffd}'),
        "CJK text contains replacement characters: {markdown}"
    );
}

// VAL-CRAWL-102: bidi direction metadata must not alter the Arabic or Hebrew character sequence.
#[test]
fn rtl_arabic_and_hebrew_text_is_preserved() {
    let proof = scrape("rtl-utf8");
    let markdown = produced(&proof, "markdown");

    assert!(
        markdown.contains("مرحبا بالعالم"),
        "Arabic text was corrupted: {markdown}"
    );
    assert!(
        markdown.contains("שלום עולם"),
        "Hebrew text was corrupted: {markdown}"
    );
    assert!(
        !markdown.contains('\u{fffd}'),
        "RTL text contains replacement characters: {markdown}"
    );
}
