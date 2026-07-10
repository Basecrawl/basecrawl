//! In-process TLS 1.3 capture assertions (VAL-CRAWL-074..084).
//!
//! These use real HTTPS origins and compare the captured leaf against a separate
//! `openssl s_client -tls1_3` handshake. The HTTP body is requested as `rawHtml`
//! with JS rendering disabled so the test exercises only the transport path.

mod common;

use base64::Engine;
use common::httpbin_base;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape_json(url: &str) -> serde_json::Value {
    let out = run(&[url, "--formats", "rawHtml", "--no-js", "--robots", "ignore"]);
    assert!(
        out.status.success(),
        "expected a successful scrape of {url}, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|error| panic!("basecrawl stdout was not valid JSON: {error}"))
}

fn assert_lower_hex_64(value: &str, name: &str) {
    assert_eq!(value.len(), 64, "{name} must be a SHA-256-width digest");
    assert!(
        value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{name} must be lowercase hex, got {value}"
    );
}

fn assert_lower_hex_transcript(value: &str, name: &str) {
    assert!(
        matches!(value.len(), 64 | 96),
        "{name} must use the negotiated SHA-256 or SHA-384 width, got {}",
        value.len()
    );
    assert!(
        value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{name} must be lowercase hex, got {value}"
    );
}

fn decoded_chain(proof: &serde_json::Value) -> Vec<Vec<u8>> {
    let chain = proof["tls"]["server_cert_chain_der"]
        .as_array()
        .expect("tls.server_cert_chain_der must be an array");
    assert!(
        chain.len() >= 2,
        "CA-issued test origins must expose leaf and intermediate DER certificates"
    );
    chain
        .iter()
        .map(|value| {
            let base64 = value
                .as_str()
                .expect("each certificate must be a base64 string");
            base64::prelude::BASE64_STANDARD
                .decode(base64)
                .expect("each certificate must be valid base64 DER")
        })
        .collect()
}

fn cert_chain_hash(chain: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for cert in chain {
        hasher.update(cert);
    }
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from_digit((byte >> 4) as u32, 16).unwrap(),
                char::from_digit((byte & 0x0f) as u32, 16).unwrap(),
            ]
        })
        .collect()
}

/// Fetch the leaf from an independent TLS 1.3 OpenSSL session, converting its
/// first PEM certificate into DER for an exact byte-level comparison.
fn openssl_leaf_der(host: &str) -> Vec<u8> {
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{host}:443"),
            "-servername",
            host,
            "-tls1_3",
            "-showcerts",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("openssl s_client must be available");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let begin = combined
        .find("-----BEGIN CERTIFICATE-----")
        .expect("openssl must emit a certificate");
    let end_marker = "-----END CERTIFICATE-----";
    let end = combined[begin..]
        .find(end_marker)
        .map(|index| begin + index + end_marker.len())
        .expect("openssl certificate must have an end marker");
    let pem = &combined[begin..end];

    let mut child = Command::new("openssl")
        .args(["x509", "-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("openssl x509 must be available");
    child
        .stdin
        .take()
        .expect("openssl x509 stdin must be piped")
        .write_all(pem.as_bytes())
        .expect("must write PEM to openssl x509");
    let output = child
        .wait_with_output()
        .expect("must read openssl x509 output");
    assert!(
        output.status.success(),
        "openssl x509 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

// VAL-CRAWL-074 through VAL-CRAWL-082.
#[test]
fn captures_tls13_chain_ground_truth_and_session_metadata() {
    let proof = scrape_json("https://example.com");
    let tls = &proof["tls"];

    assert_eq!(tls["negotiated_version"], "1.3");
    assert_eq!(tls["sni"], "example.com");

    let chain = decoded_chain(&proof);
    assert_eq!(
        chain[0],
        openssl_leaf_der("example.com"),
        "the captured leaf DER must equal the independent openssl TLS 1.3 ground truth"
    );

    let chain_hash = tls["cert_chain_hash"]
        .as_str()
        .expect("cert chain hash must be present");
    assert_lower_hex_64(chain_hash, "tls.cert_chain_hash");
    assert_eq!(
        chain_hash,
        cert_chain_hash(&chain),
        "cert_chain_hash must be SHA256 over concatenated handshake-order DER certificates"
    );

    let transcript = tls["handshake_transcript_hash"]
        .as_str()
        .expect("a TLS 1.3 fetch must have a transcript hash");
    assert_lower_hex_transcript(transcript, "tls.handshake_transcript_hash");

    let ephemeral = tls["server_ephemeral_pubkey"]
        .as_str()
        .expect("a TLS 1.3 ECDHE handshake must expose the server public key");
    assert!(
        !base64::prelude::BASE64_STANDARD
            .decode(ephemeral)
            .expect("server_ephemeral_pubkey must be base64")
            .is_empty(),
        "server_ephemeral_pubkey must not be empty"
    );

    let scts = tls["ct_scts"]
        .as_array()
        .expect("ct_scts must be an array, even when no SCT is supplied");
    assert!(
        !scts.is_empty(),
        "example.com's embedded SCTs must be captured when the leaf provides them"
    );
    for sct in scts {
        let sct = sct.as_str().expect("SCTs must be base64 strings");
        assert!(
            !base64::prelude::BASE64_STANDARD
                .decode(sct)
                .expect("SCT must be valid base64")
                .is_empty(),
            "captured SCTs must not be empty"
        );
    }
    if !tls["ocsp"].is_null() {
        assert!(
            !base64::prelude::BASE64_STANDARD
                .decode(tls["ocsp"].as_str().expect("OCSP must be a string"))
                .expect("OCSP must be valid base64")
                .is_empty(),
            "captured OCSP must not be empty"
        );
    }
}

// VAL-CRAWL-078 and VAL-CRAWL-080.
#[test]
fn tls_chain_hash_is_stable_and_transcript_varies_per_session() {
    let first = scrape_json("https://example.com");
    let second = scrape_json("https://example.com");

    assert_eq!(
        first["tls"]["cert_chain_hash"], second["tls"]["cert_chain_hash"],
        "certificate chain hash must be stable while the origin certificate is unchanged"
    );
    assert_ne!(
        first["tls"]["handshake_transcript_hash"], second["tls"]["handshake_transcript_hash"],
        "fresh TLS sessions must produce distinct handshake transcript hashes"
    );
}

// VAL-CRAWL-083.
#[test]
fn captures_tls_metadata_for_named_open_web_targets() {
    let httpbin = httpbin_base();
    for (name, url) in [
        ("books", "https://books.toscrape.com"),
        ("quotes", "https://quotes.toscrape.com"),
        ("httpbin", httpbin),
    ] {
        let proof = scrape_json(url);
        let tls = &proof["tls"];
        assert!(
            tls["negotiated_version"]
                .as_str()
                .is_some_and(|version| matches!(version, "1.2" | "1.3")),
            "{name} must report a supported TLS version"
        );
        assert!(
            tls["sni"].as_str().is_some_and(|sni| !sni.is_empty()),
            "{name} must expose its SNI"
        );
        assert!(
            !tls["server_cert_chain_der"]
                .as_array()
                .expect("certificate chain must be an array")
                .is_empty(),
            "{name} must expose a server certificate chain"
        );
        assert_lower_hex_transcript(
            tls["handshake_transcript_hash"]
                .as_str()
                .expect("transcript hash must be present"),
            "tls.handshake_transcript_hash",
        );
    }
}

// VAL-CRAWL-084.
#[test]
fn invalid_certificates_fail_closed_unless_explicitly_insecure() {
    for url in [
        "https://expired.badssl.com",
        "https://self-signed.badssl.com",
    ] {
        let rejected = run(&[url, "--formats", "rawHtml", "--no-js"]);
        assert!(
            !rejected.status.success(),
            "{url} must be rejected by default"
        );
        assert!(
            rejected.stdout.is_empty(),
            "{url} must not emit a partial proof when certificate validation fails"
        );
        let error: serde_json::Value =
            serde_json::from_slice(&rejected.stderr).expect("certificate failure must be JSON");
        assert_eq!(error["error"]["kind"], "certificate_validation");
        assert!(
            error["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("certificate validation")),
            "certificate failure must be clear: {error}"
        );

        let insecure = run(&[url, "--formats", "rawHtml", "--no-js", "--insecure"]);
        assert!(
            insecure.status.success(),
            "{url} must be capturable only with the explicit insecure flag: {}",
            String::from_utf8_lossy(&insecure.stderr)
        );
        let proof: serde_json::Value =
            serde_json::from_slice(&insecure.stdout).expect("insecure fetch must emit a proof");
        assert!(
            proof["tls"]["negotiated_version"]
                .as_str()
                .is_some_and(|version| version == "1.2" || version == "1.3"),
            "the explicit insecure capture must still report its negotiated TLS version"
        );
    }
}
