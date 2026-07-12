use basecrawl_core::attestation::{get_quote_at, quote_report_data, QuoteRequestError};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;

const REPORT_DATA: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
     202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

fn quote_fixture(report_data: &str) -> String {
    let mut quote = vec![0_u8; 48 + 584 + 4];
    quote[0..2].copy_from_slice(&4_u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x81_u32.to_le_bytes());
    let report_data_bytes: Vec<u8> = report_data
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap() as u8;
            let low = (pair[1] as char).to_digit(16).unwrap() as u8;
            (high << 4) | low
        })
        .collect();
    quote[48 + 520..48 + 584].copy_from_slice(&report_data_bytes);
    quote
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn socket_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basecrawl-attestation-{label}-{}.sock",
        std::process::id()
    ))
}

fn serve_once(path: &PathBuf, body: String) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    })
}

#[test]
fn get_quote_posts_a_full_report_data_value_and_validates_the_response() {
    let path = socket_path("valid");
    let body = serde_json::json!({
        "quote": quote_fixture(REPORT_DATA),
        "event_log": [{"event": "fixture"}],
        "report_data": REPORT_DATA,
        "vm_config": {"cpu": 1}
    })
    .to_string();
    let server = serve_once(&path, body);

    let response = get_quote_at(&path, REPORT_DATA).unwrap();

    server.join().unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(response.report_data, REPORT_DATA);
    assert_eq!(quote_report_data(&response.quote).unwrap(), REPORT_DATA);
    assert!(response.quote.len() >= 1264);
    assert!(!response.event_log.is_null());
    assert!(!response.vm_config.is_null());
}

#[test]
fn get_quote_rejects_a_report_data_mismatch() {
    let path = socket_path("mismatch");
    let body = serde_json::json!({
        "quote": quote_fixture(REPORT_DATA),
        "event_log": [{"event": "fixture"}],
        "report_data": "ff".repeat(64),
        "vm_config": {"cpu": 1}
    })
    .to_string();
    let server = serve_once(&path, body);

    let error = get_quote_at(&path, REPORT_DATA).unwrap_err();

    server.join().unwrap();
    fs::remove_file(&path).unwrap();
    assert!(matches!(
        error,
        QuoteRequestError::ReportDataMismatch { .. }
    ));
}

#[test]
fn get_quote_rejects_a_quote_embedded_report_data_mismatch() {
    let path = socket_path("quote-mismatch");
    let body = serde_json::json!({
        "quote": quote_fixture(&"ff".repeat(64)),
        "event_log": [{"event": "fixture"}],
        "report_data": REPORT_DATA,
        "vm_config": {"cpu": 1}
    })
    .to_string();
    let server = serve_once(&path, body);

    let error = get_quote_at(&path, REPORT_DATA).unwrap_err();

    server.join().unwrap();
    fs::remove_file(&path).unwrap();
    assert!(matches!(error, QuoteRequestError::QuoteReportDataMismatch));
}

#[test]
fn get_quote_rejects_an_unreachable_socket() {
    let path = socket_path("missing");
    let error = basecrawl_core::attestation::get_quote_at(&path, REPORT_DATA).unwrap_err();
    assert!(matches!(
        error,
        basecrawl_core::attestation::QuoteRequestError::SocketUnavailable { .. }
    ));
}
