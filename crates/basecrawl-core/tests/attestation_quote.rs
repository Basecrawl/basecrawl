use basecrawl_core::attestation::{
    get_quote_at, quote_measurement, quote_report_data, QuoteRequestError,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;

const REPORT_DATA: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
     202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

fn decode_quote_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap() as u8;
            let low = (pair[1] as char).to_digit(16).unwrap() as u8;
            (high << 4) | low
        })
        .collect()
}

fn quote_fixture(report_data: &str) -> String {
    let mut quote = vec![0_u8; 48 + 584];
    quote[0..2].copy_from_slice(&4_u16.to_le_bytes());
    quote[4..8].copy_from_slice(&0x81_u32.to_le_bytes());
    for (offset, value) in [
        (136, 0x11),
        (328, 0x22),
        (376, 0x33),
        (424, 0x44),
        (472, 0x55),
    ] {
        quote[48 + offset..48 + offset + 48].fill(value);
    }
    let report_data_bytes = decode_quote_hex(report_data);
    quote[48 + 520..48 + 584].copy_from_slice(&report_data_bytes);
    let mut qe_certification = vec![0_u8; 384 + 64];
    qe_certification.extend_from_slice(&32_u16.to_le_bytes());
    qe_certification.extend(0_u8..32);
    qe_certification.extend_from_slice(&5_u16.to_le_bytes());
    qe_certification.extend_from_slice(&1_u32.to_le_bytes());
    qe_certification.push(0x42);
    let mut signature_data = vec![0x11; 64];
    signature_data.extend(vec![0x22; 64]);
    signature_data.extend_from_slice(&6_u16.to_le_bytes());
    signature_data.extend_from_slice(&(qe_certification.len() as u32).to_le_bytes());
    signature_data.extend(qe_certification);
    quote.extend_from_slice(&(signature_data.len() as u32).to_le_bytes());
    quote.extend(signature_data);
    quote
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn quote_measurement_extracts_all_tdx_registers() {
    let measurement = quote_measurement(&quote_fixture(REPORT_DATA)).unwrap();

    assert_eq!(measurement.mrtd, "11".repeat(48));
    assert_eq!(measurement.rtmr0, "22".repeat(48));
    assert_eq!(measurement.rtmr1, "33".repeat(48));
    assert_eq!(measurement.rtmr2, "44".repeat(48));
    assert_eq!(measurement.rtmr3, "55".repeat(48));
}

fn socket_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "basecrawl-attestation-{label}-{}.sock",
        std::process::id()
    ))
}

fn serve_once(path: &PathBuf, body: String) -> thread::JoinHandle<Vec<u8>> {
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
        request
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
fn get_quote_sha256_reduces_overlong_report_data_instead_of_truncating_it() {
    let path = socket_path("sha256-overlong");
    let input = "ab".repeat(65);
    let digest = Sha256::digest([0xab; 65]);
    let expected = format!(
        "{}{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "00".repeat(32)
    );
    let body = serde_json::json!({
        "quote": quote_fixture(&expected),
        "event_log": [{"event": "fixture"}],
        "report_data": expected,
        "vm_config": {"cpu": 1}
    })
    .to_string();
    let server = serve_once(&path, body);

    let response = get_quote_at(&path, &input).unwrap();

    let request = String::from_utf8(server.join().unwrap()).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(request.contains(&format!(r#""report_data":"{expected}""#)));
    assert_eq!(response.report_data, expected);
    assert_eq!(quote_report_data(&response.quote).unwrap(), expected);
    assert_ne!(response.report_data, "ab".repeat(64));
}

#[test]
fn get_quote_left_aligns_and_zero_pads_short_report_data() {
    let path = socket_path("short");
    let input = "ab".repeat(32);
    let expected = format!("{input}{}", "00".repeat(32));
    let body = serde_json::json!({
        "quote": quote_fixture(&expected),
        "event_log": [{"event": "fixture"}],
        "report_data": expected,
        "vm_config": {"cpu": 1}
    })
    .to_string();
    let server = serve_once(&path, body);

    let response = get_quote_at(&path, &input).unwrap();

    let request = String::from_utf8(server.join().unwrap()).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(request.contains(&format!(r#""report_data":"{expected}""#)));
    assert_eq!(response.report_data, expected);
    assert_eq!(quote_report_data(&response.quote).unwrap(), expected);
}

#[test]
fn get_quote_rejects_malformed_report_data_before_opening_the_socket() {
    let path = socket_path("malformed");
    for input in ["0", "gg", "01xz"] {
        let error = get_quote_at(&path, input).unwrap_err();
        assert!(
            matches!(error, QuoteRequestError::InvalidReportData),
            "unexpected error for {input:?}: {error}"
        );
    }
    assert!(!path.exists());
}

#[test]
fn get_quote_preserves_json_encoded_event_log_and_vm_config_strings() {
    let path = socket_path("raw-json-strings");
    let event_log = r#"[{"event":"fixture"}]"#;
    let vm_config = r#"{"cpu":1}"#;
    let body = serde_json::json!({
        "quote": quote_fixture(REPORT_DATA),
        "event_log": event_log,
        "report_data": REPORT_DATA,
        "vm_config": vm_config
    })
    .to_string();
    let server = serve_once(&path, body);

    let response = get_quote_at(&path, REPORT_DATA).unwrap();

    server.join().unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(
        response.event_log,
        serde_json::Value::String(event_log.into())
    );
    assert_eq!(
        response.vm_config,
        serde_json::Value::String(vm_config.into())
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&response.to_canonical_json()).unwrap()
            ["event_log"],
        event_log
    );
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

#[test]
fn quote_accessors_reject_truncated_signature_and_certification_data() {
    let complete = quote_fixture(REPORT_DATA);
    for truncated in [
        &complete[..(48 + 584) * 2],
        &complete[..(48 + 584 + 4 + 64) * 2],
        &complete[..complete.len() - 2],
    ] {
        assert!(matches!(
            quote_report_data(truncated),
            Err(QuoteRequestError::QuoteTooShort { .. })
                | Err(QuoteRequestError::MalformedQuote(_))
        ));
        assert!(matches!(
            quote_measurement(truncated),
            Err(QuoteRequestError::QuoteTooShort { .. })
                | Err(QuoteRequestError::MalformedQuote(_))
        ));
    }
}

#[test]
fn get_quote_rejects_a_structurally_truncated_attestation() {
    let path = socket_path("truncated");
    let quote = quote_fixture(REPORT_DATA);
    let body = serde_json::json!({
        "quote": &quote[..quote.len() - 2],
        "event_log": [{"event": "fixture"}],
        "report_data": REPORT_DATA,
        "vm_config": {"cpu": 1}
    })
    .to_string();
    let server = serve_once(&path, body);

    let error = get_quote_at(&path, REPORT_DATA).unwrap_err();

    server.join().unwrap();
    fs::remove_file(&path).unwrap();
    assert!(matches!(error, QuoteRequestError::MalformedQuote(_)));
}

#[test]
fn quote_accessors_reject_nonzero_bytes_after_declared_quote() {
    let mut quote = quote_fixture(REPORT_DATA);
    quote.push_str("01");

    assert!(matches!(
        quote_report_data(&quote),
        Err(QuoteRequestError::MalformedQuote(_))
    ));
}

#[test]
fn retained_production_quote_passes_strict_structure_validation() {
    let evidence_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../image/tier2-attestation-evidence.json");
    let evidence: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(evidence_path).unwrap()).unwrap();
    let attestation = &evidence["scrapeproof_attestation"];
    let quote = attestation["quote"].as_str().unwrap();
    let quote_bytes = decode_quote_hex(quote);
    let signature_data_length =
        u32::from_le_bytes(quote_bytes[632..636].try_into().unwrap()) as usize;
    let declared_end = 636 + signature_data_length;

    assert_eq!(
        quote_report_data(quote).unwrap(),
        attestation["report_data"].as_str().unwrap()
    );
    assert_eq!(
        quote_measurement(quote).unwrap().mrtd,
        attestation["measurement"]["mrtd"].as_str().unwrap()
    );
    assert!(declared_end < quote_bytes.len());
    assert!(quote_bytes[declared_end..].iter().all(|byte| *byte == 0));
}
