//! Document extraction assertions (VAL-CRAWL-125 and VAL-CRAWL-126).
//!
//! The fixture server serves a valid text PDF plus minimal DOCX and ODT ZIP packages. The CLI must
//! expose their text through markdown, retain the authoritative content type, and never emit the
//! original binary package through a textual output surface.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::thread;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const PDF_SENTINEL: &str = "Basecrawl PDF document sentinel";
const DOCX_SENTINEL: &str = "Basecrawl DOCX document sentinel";
const ODT_SENTINEL: &str = "Basecrawl ODT document sentinel";
const DOCX_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const ODT_CONTENT_TYPE: &str = "application/vnd.oasis.opendocument.text";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape(path: &str) -> Value {
    let url = format!("{}/{path}", server_base());
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

fn extracted_markdown(proof: &Value) -> &str {
    proof["result"]["formats_produced"]["markdown"]
        .as_str()
        .unwrap_or_else(|| panic!("markdown is absent or not text:\n{proof}"))
}

fn assert_document_content_type(proof: &Value, expected: &str) {
    assert_eq!(
        proof["response"]["content_type"], expected,
        "response block must preserve the authoritative content type"
    );
    assert_eq!(
        proof["result"]["formats_produced"]["metadata"]["contentType"], expected,
        "metadata must preserve the authoritative content type"
    );
}

// VAL-CRAWL-125: a PDF yields extracted markdown, records its content type, and never dumps raw
// bytes through rawHtml.
#[test]
fn pdf_text_is_extracted_without_a_binary_dump() {
    let proof = scrape("document.pdf");

    assert!(
        extracted_markdown(&proof).contains(PDF_SENTINEL),
        "PDF text was not extracted:\n{proof}"
    );
    assert_eq!(
        proof["result"]["formats_produced"]["rawHtml"], "",
        "rawHtml must never expose PDF bytes"
    );
    assert_document_content_type(&proof, "application/pdf");
}

// VAL-CRAWL-126: DOCX and the comparable ODT office format both expose their document text.
#[test]
fn office_document_text_is_extracted_without_a_binary_dump() {
    for (path, sentinel, content_type) in [
        ("document.docx", DOCX_SENTINEL, DOCX_CONTENT_TYPE),
        ("document.odt", ODT_SENTINEL, ODT_CONTENT_TYPE),
    ] {
        let proof = scrape(path);
        assert!(
            extracted_markdown(&proof).contains(sentinel),
            "{path} text was not extracted:\n{proof}"
        );
        assert_eq!(
            proof["result"]["formats_produced"]["rawHtml"], "",
            "rawHtml must never expose {path} ZIP bytes"
        );
        assert_document_content_type(&proof, content_type);
    }
}

#[test]
fn malformed_office_document_fails_with_a_structured_extraction_error() {
    let url = format!("{}/malformed.docx", server_base());
    let output = run(&[&url, "--formats", "markdown,metadata", "--no-js"]);

    assert!(
        !output.status.success(),
        "malformed document must not be accepted as an empty successful scrape"
    );
    assert!(
        output.stdout.is_empty(),
        "failed extraction must not emit a partial ScrapeProof"
    );
    let error: Value = serde_json::from_slice(&output.stderr)
        .unwrap_or_else(|parse_error| panic!("stderr must be structured JSON: {parse_error}"));
    assert_eq!(error["error"]["kind"], "document_extraction");
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
        "/robots.txt" => ("text/plain", Vec::new()),
        "/document.pdf" => ("application/pdf", minimal_pdf(PDF_SENTINEL)),
        "/document.docx" => (DOCX_CONTENT_TYPE, docx()),
        "/document.odt" => (ODT_CONTENT_TYPE, odt()),
        "/malformed.docx" => (DOCX_CONTENT_TYPE, b"this is not a ZIP document".to_vec()),
        _ => ("text/plain", b"not found".to_vec()),
    }
}

fn minimal_pdf(text: &str) -> Vec<u8> {
    let stream = format!("BT\n/F1 18 Tf\n72 720 Td\n({text}) Tj\nET\n");
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_string(),
        format!("<< /Length {} >>\nstream\n{stream}endstream", stream.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];

    let mut pdf = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", index + 1).as_bytes());
    }
    let xref_offset = pdf.len();
    pdf.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n").as_bytes(),
    );
    pdf
}

fn docx() -> Vec<u8> {
    zip_stored(&[
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>"#,
        ),
        (
            "word/document.xml",
            &format!(
                r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{DOCX_SENTINEL}</w:t></w:r></w:p></w:body></w:document>"#
            ),
        ),
    ])
}

fn odt() -> Vec<u8> {
    zip_stored(&[
        ("mimetype", "application/vnd.oasis.opendocument.text"),
        (
            "content.xml",
            &format!(
                r#"<?xml version="1.0" encoding="UTF-8"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text><text:p>{ODT_SENTINEL}</text:p></office:text></office:body></office:document-content>"#
            ),
        ),
    ])
}

fn zip_stored(entries: &[(&str, &str)]) -> Vec<u8> {
    struct DirectoryEntry {
        name: String,
        crc: u32,
        size: u32,
        offset: u32,
    }

    let mut archive = Vec::new();
    let mut directory = Vec::with_capacity(entries.len());
    for (name, contents) in entries {
        let name_bytes = name.as_bytes();
        let data = contents.as_bytes();
        let entry = DirectoryEntry {
            name: (*name).to_string(),
            crc: crc32(data),
            size: u32::try_from(data.len()).expect("small fixture"),
            offset: u32::try_from(archive.len()).expect("small fixture"),
        };
        push_u32(&mut archive, 0x0403_4B50);
        push_u16(&mut archive, 20);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u32(&mut archive, entry.crc);
        push_u32(&mut archive, entry.size);
        push_u32(&mut archive, entry.size);
        push_u16(
            &mut archive,
            u16::try_from(name_bytes.len()).expect("small fixture"),
        );
        push_u16(&mut archive, 0);
        archive.extend_from_slice(name_bytes);
        archive.extend_from_slice(data);
        directory.push(entry);
    }

    let directory_offset = u32::try_from(archive.len()).expect("small fixture");
    for entry in &directory {
        let name_bytes = entry.name.as_bytes();
        push_u32(&mut archive, 0x0201_4B50);
        push_u16(&mut archive, 20);
        push_u16(&mut archive, 20);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u32(&mut archive, entry.crc);
        push_u32(&mut archive, entry.size);
        push_u32(&mut archive, entry.size);
        push_u16(
            &mut archive,
            u16::try_from(name_bytes.len()).expect("small fixture"),
        );
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u32(&mut archive, 0);
        push_u32(&mut archive, entry.offset);
        archive.extend_from_slice(name_bytes);
    }
    let directory_size = u32::try_from(archive.len()).expect("small fixture") - directory_offset;
    push_u32(&mut archive, 0x0605_4B50);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    let entry_count = u16::try_from(directory.len()).expect("small fixture");
    push_u16(&mut archive, entry_count);
    push_u16(&mut archive, entry_count);
    push_u32(&mut archive, directory_size);
    push_u32(&mut archive, directory_offset);
    push_u16(&mut archive, 0);
    archive
}

fn push_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
