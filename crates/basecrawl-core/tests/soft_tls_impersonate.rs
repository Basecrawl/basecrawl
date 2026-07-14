//! Soft-path TLS chrome-impersonate (ClientHello / JA3-family) — VAL-UTLS-001..010.
//!
//! Hermetic loopback fixtures only (mission ports 21000–21099 for proxy). Soft path stays
//! rustls; hard/residential identity still requires Chromium.

use basecrawl_fp::{
    generate, SoftTlsImpersonate, SoftTlsImpersonateError, CHROME_TLS13_CIPHER_ORDER,
    CHROME_TLS_GROUP_ORDER, SOFT_TLS_FP_LABEL,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn run_cli(args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    for key in [
        "BASECRAWL_LIVE_PROXY",
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env_remove(key);
    }
    for (k, v) in env {
        match v {
            Some(val) => {
                cmd.env(k, val);
            }
            None => {
                cmd.env_remove(k);
            }
        }
    }
    cmd.output().expect("spawn basecrawl")
}

fn body_html(marker: &str) -> Vec<u8> {
    format!("<!doctype html><html><body>{marker}</body></html>").into_bytes()
}

/// Plain HTTP origin for soft --no-js scrapes (no TLS needed for class/path honesty).
fn origin_http(marker: &str) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_t = Arc::clone(&hits);
    let body = body_html(marker);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(&body);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}/soft-utls"), hits)
}

fn bind_mission_port() -> TcpListener {
    for port in 21000u16..=21099 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            listener
                .set_nonblocking(true)
                .expect("set nonblocking mock listener");
            return listener;
        }
    }
    panic!("no free mock proxy port in 21000-21099");
}

#[derive(Default, Debug, Clone)]
struct ConnectRecord {
    auth_present: bool,
    #[allow(dead_code)]
    target: String,
}

fn mock_connect_gateway(hits: Arc<AtomicUsize>) -> (String, Arc<Mutex<Vec<ConnectRecord>>>) {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("gw addr");
    let records = Arc::new(Mutex::new(Vec::new()));
    let records_t = Arc::clone(&records);
    let hits_t = Arc::clone(&hits);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
                    // Read CONNECT request headers.
                    let mut buf = Vec::with_capacity(1024);
                    let mut tmp = [0u8; 1];
                    let inner = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < inner {
                        match client.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(_) => {
                                buf.push(tmp[0]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                if buf.len() > 16 * 1024 {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let req = String::from_utf8_lossy(&buf);
                    let first = req.lines().next().unwrap_or("");
                    let mut parts = first.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let target = parts.next().unwrap_or("").to_string();
                    if method != "CONNECT" {
                        let _ = client.write_all(
                            b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n",
                        );
                        continue;
                    }
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    let auth_present = req.to_ascii_lowercase().contains("proxy-authorization");
                    if let Ok(mut guard) = records_t.lock() {
                        guard.push(ConnectRecord {
                            auth_present,
                            target: target.clone(),
                        });
                    }
                    let (host, port) = match target.rsplit_once(':') {
                        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(0)),
                        None => (target.clone(), 0),
                    };
                    match TcpStream::connect((host.as_str(), port)) {
                        Ok(target_stream) => {
                            let _ =
                                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                            let _ = client.set_nonblocking(false);
                            let _ = target_stream.set_nonblocking(false);
                            // Bidirectional copy for the short HTTP fixture exchange.
                            let Ok(mut a_clone) = client.try_clone() else {
                                continue;
                            };
                            let Ok(mut b_clone) = target_stream.try_clone() else {
                                continue;
                            };
                            let t1 = thread::spawn(move || {
                                let _ = std::io::copy(&mut a_clone, &mut b_clone);
                            });
                            let mut b = target_stream;
                            let _ = std::io::copy(&mut b, &mut client);
                            let _ = t1.join();
                        }
                        Err(_) => {
                            let _ = client.write_all(
                                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
                            );
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}"), records)
}

fn parse_proof_stdout(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected scrapeproof json on stdout: {e}; status={:?}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn parse_err_stderr(out: &Output) -> Value {
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Find first JSON object in stderr.
    if let Some(idx) = stderr.find('{') {
        if let Ok(v) = serde_json::from_str::<Value>(&stderr[idx..]) {
            return v;
        }
    }
    panic!(
        "expected structured error JSON on stderr; status={:?}; stderr={stderr}",
        out.status
    );
}

// ---------------------------------------------------------------------------
// VAL-UTLS-001: stronger than pure random reorder
// ---------------------------------------------------------------------------

#[test]
fn val_utls_001_chrome_impersonate_stronger_than_pure_reorder() {
    // Pure seed reorder produces diverse cipher orders.
    let mut pure_orders = std::collections::HashSet::new();
    let mut pure_ja3 = std::collections::HashSet::new();
    for i in 0..24u32 {
        let p = generate(&format!("val-utls-001-seed-{i}"));
        pure_orders.insert(p.tls13_cipher_order.clone());
        pure_ja3.insert(p.ja3.clone());
    }
    assert!(
        pure_orders.len() > 1,
        "baseline pure reorder must diversify ciphers"
    );

    // Chrome soft profile is a fixed documented Chrome-family order.
    let mut chrome_ja3 = String::new();
    for i in 0..8u32 {
        let mut p = generate(&format!("val-utls-001-seed-{i}"));
        SoftTlsImpersonate::Chrome.apply(&mut p);
        assert_eq!(
            p.tls13_cipher_order.as_slice(),
            CHROME_TLS13_CIPHER_ORDER,
            "chrome-impersonate must pin Chrome-family cipher order"
        );
        assert_eq!(
            p.tls_group_order,
            CHROME_TLS_GROUP_ORDER
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
        );
        if chrome_ja3.is_empty() {
            chrome_ja3 = p.ja3.clone();
        } else {
            assert_eq!(chrome_ja3, p.ja3, "chrome soft JA3 is profile-stable");
        }
    }

    // Soft digest must not equal pure-reorder digests under the same seeds (domain + extension).
    for i in 0..8u32 {
        let base = generate(&format!("val-utls-001-seed-{i}"));
        let mut chrome = base.clone();
        SoftTlsImpersonate::Chrome.apply(&mut chrome);
        assert_ne!(
            base.ja3, chrome.ja3,
            "soft chrome JA3 must recompute under soft domain/extension order"
        );
    }

    // At least some pure seed orders differ from the chrome fixed order — that's the "stronger
    // than pure random reorder alone" gap VAL-UTLS-001 cares about.
    let chrome_order = CHROME_TLS13_CIPHER_ORDER.to_vec();
    assert!(
        pure_orders.iter().any(|o| o != &chrome_order),
        "pure reorder must sometimes leave chrome order so the profile effect is observable"
    );
}

// ---------------------------------------------------------------------------
// VAL-UTLS-002 / 007: invalid / weak profiles fail closed
// ---------------------------------------------------------------------------

#[test]
fn val_utls_002_invalid_profile_fail_closed() {
    let (url, _) = origin_http("invalid-profile");
    let out = run_cli(
        &[
            &url,
            "--no-js",
            "--formats",
            "rawHtml",
            "--tls-impersonate",
            "not-a-browser",
        ],
        &[],
    );
    assert!(
        !out.status.success(),
        "invalid profile must non-zero exit; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = parse_err_stderr(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    assert_eq!(
        kind, "tls_impersonate_unsupported",
        "structured kind; err={err}"
    );
    let msg = err["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase();
    assert!(
        msg.contains("unsupported") || msg.contains("not-a-browser"),
        "message should name the failure; msg={msg}"
    );
    // Must never succeed with chrome-impersonate labeling while invalid.
    assert!(
        out.stdout.is_empty() || {
            let s = String::from_utf8_lossy(&out.stdout);
            !s.contains("soft_tls_impersonate")
        }
    );
}

#[test]
fn val_utls_007_weak_profile_below_security_floor() {
    for weak in ["export", "rc4", "tls1.0", "3des"] {
        assert!(
            matches!(
                SoftTlsImpersonate::parse(weak),
                Err(SoftTlsImpersonateError::BelowSecurityFloor { .. })
            ),
            "weak token {weak} must fail floor"
        );
        let (url, _) = origin_http("weak-profile");
        let out = run_cli(
            &[
                &url,
                "--no-js",
                "--formats",
                "rawHtml",
                "--tls-impersonate",
                weak,
            ],
            &[],
        );
        assert!(
            !out.status.success(),
            "weak profile {weak} must fail closed"
        );
        let err = parse_err_stderr(&out);
        assert_eq!(
            err["error"]["kind"].as_str().unwrap_or(""),
            "tls_impersonate_unsupported"
        );
    }
    // Product chrome profile stays on TLS 1.3 AEAD floor.
    basecrawl_fp::assert_chrome_security_floor().expect("chrome floor");
}

// ---------------------------------------------------------------------------
// VAL-UTLS-003/004/006: soft honesty (fetch_path / proxy_class / soft label)
// ---------------------------------------------------------------------------

#[test]
fn val_utls_003_004_006_soft_path_honest_audit_fields() {
    let (url, hits) = origin_http("soft-honest");
    let out = run_cli(
        &[
            &url,
            "--no-js",
            "--formats",
            "rawHtml,metadata",
            "--tls-impersonate",
            "chrome",
            "--fingerprint-seed",
            "val-utls-soft-honest",
        ],
        &[],
    );
    assert!(
        out.status.success(),
        "soft open path must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(hits.load(Ordering::SeqCst) >= 1);
    let proof = parse_proof_stdout(&out);
    let egress = &proof["egress"];
    assert_eq!(
        egress["fetch_path"].as_str(),
        Some("direct"),
        "soft must never emit chromium (VAL-UTLS-003); egress={egress}"
    );
    assert_ne!(egress["fetch_path"].as_str(), Some("chromium"));
    let class = egress["proxy_class"].as_str().unwrap_or("");
    assert!(
        class == "direct" || class.is_empty(),
        "no residential without dial (VAL-UTLS-004); class={class}"
    );
    assert_ne!(class, "residential");
    assert_ne!(class, "mobile");

    let soft = &egress["soft_tls_impersonate"];
    assert!(soft.is_object(), "soft audit present; egress={egress}");
    assert_eq!(soft["profile"].as_str(), Some("chrome"));
    let label = soft["ja_label"].as_str().unwrap_or("");
    assert_eq!(label, SOFT_TLS_FP_LABEL);
    assert!(label.contains("soft"));
    assert!(
        label.contains("synthetic") || label.contains("impersonate"),
        "label must declare soft/synthetic/impersonate"
    );
    // Forbidden: alleging native Chromium wire.
    let combined = format!("{soft}");
    let lower = combined.to_ascii_lowercase();
    for ban in [
        "native chromium packet",
        "wireshark",
        "undetectable",
        "anonymous",
    ] {
        assert!(
            !lower.contains(ban),
            "soft audit must not claim {ban}; soft={soft}"
        );
    }
    assert!(
        soft["soft_ja3"]
            .as_str()
            .map(|s| s.len() == 64)
            .unwrap_or(false),
        "soft_ja3 64-hex"
    );
    assert!(
        soft["soft_ja4"]
            .as_str()
            .map(|s| s.len() == 64)
            .unwrap_or(false),
        "soft_ja4 64-hex"
    );
}

// ---------------------------------------------------------------------------
// VAL-UTLS-005: soft impersonate + universal proxy (mock CONNECT)
// ---------------------------------------------------------------------------

#[test]
fn val_utls_005_soft_impersonate_with_universal_proxy() {
    let (origin, origin_hits) = origin_http("proxy-soft");
    // Origin must be reachable as host:port for CONNECT target.
    let origin_url = url::Url::parse(&origin).expect("origin url");
    let host = origin_url.host_str().unwrap();
    let port = origin_url.port().unwrap();
    let connect_target_page = format!("http://{host}:{port}/soft-utls");

    let connect_hits = Arc::new(AtomicUsize::new(0));
    let (proxy_url, records) = mock_connect_gateway(Arc::clone(&connect_hits));
    // Use user:pass to exercise redaction path (credentials must not appear in proof).
    let proxy_with_creds = proxy_url.replacen("http://", "http://u:p@", 1);

    let out = run_cli(
        &[
            &connect_target_page,
            "--no-js",
            "--formats",
            "rawHtml",
            "--proxy",
            &proxy_with_creds,
            "--proxy-class",
            "datacenter",
            "--tls-impersonate",
            "chrome",
        ],
        &[],
    );
    assert!(
        out.status.success(),
        "proxied soft impersonate must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        connect_hits.load(Ordering::SeqCst) >= 1,
        "mock CONNECT must see a hop; records={:?}",
        records.lock().ok()
    );
    assert!(
        origin_hits.load(Ordering::SeqCst) >= 1,
        "origin must receive tunneled request"
    );
    let recs = records.lock().expect("records");
    assert!(
        !recs.is_empty() && recs.iter().any(|r| r.auth_present),
        "CONNECT hop with auth should be recorded; recs={recs:?}"
    );
    let proof = parse_proof_stdout(&out);
    let egress = &proof["egress"];
    assert_eq!(egress["fetch_path"].as_str(), Some("direct"));
    assert_eq!(egress["proxy_class"].as_str(), Some("datacenter"));
    assert_eq!(
        egress["soft_tls_impersonate"]["profile"].as_str(),
        Some("chrome")
    );
    let proof_s = proof.to_string();
    assert!(
        !proof_s.contains("u:p@") && !proof_s.contains(":p@"),
        "proxy password must never appear in proof"
    );
}

// ---------------------------------------------------------------------------
// VAL-UTLS-008: help text honesty
// ---------------------------------------------------------------------------

#[test]
fn val_utls_008_help_honest_not_undetectable() {
    let out = run_cli(&["--help"], &[]);
    assert!(out.status.success());
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        help.contains("--tls-impersonate") || help.contains("tls-impersonate"),
        "help must advertise soft TLS toggle"
    );
    let lower = help.to_ascii_lowercase();
    // Absolute stealth marketing is forbidden. Explicit denials ("never anonymity",
    // "residual bot detection") are honest residual language and allowed.
    // Claim forms that assert, rather than deny, absolute stealth are banned.
    for claim in [
        "is undetectable",
        "fully undetectable",
        "makes you anonymous",
        "anonymity guarantee",
        "100% success",
        "trustless scrape",
    ] {
        assert!(
            !lower.contains(claim),
            "help must never advertise forbidden claim '{claim}'"
        );
    }
    // Positive honesty cues on the soft TLS toggle.
    assert!(
        lower.contains("bootstrap")
            || lower.contains("success-rate")
            || lower.contains("clienthello")
            || lower.contains("ja3")
            || lower.contains("residual"),
        "help should describe honest residual alignment"
    );
    // Must still reject absolute anonymity marketing (denial form is fine).
    if lower.contains("anonymity") {
        assert!(
            lower.contains("never anonymity")
                || lower.contains("not anonymity")
                || lower.contains("not an anonymous"),
            "if anonymity is mentioned it must be denial residual language"
        );
    }
}

// ---------------------------------------------------------------------------
// VAL-UTLS-009: soft open-web still works (http fixture)
// ---------------------------------------------------------------------------

#[test]
fn val_utls_009_soft_path_still_works() {
    let (url, hits) = origin_http("soft-still-works");
    let out = run_cli(
        &[
            &url,
            "--no-js",
            "--formats",
            "rawHtml",
            "--tls-impersonate",
            "chrome",
        ],
        &[],
    );
    assert!(out.status.success());
    assert!(hits.load(Ordering::SeqCst) >= 1);
    let proof = parse_proof_stdout(&out);
    assert_eq!(proof["response"]["status_code"], 200);
    assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("direct"));
    // Soft path was not removed / forced to chromium.
    assert_ne!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));
}

// ---------------------------------------------------------------------------
// VAL-UTLS-010: soft-then-hard escalation does not keep soft TLS as hard proof
// ---------------------------------------------------------------------------

#[test]
fn val_utls_010_hard_path_does_not_sell_soft_tls_as_chromium() {
    // Policy unit: hard-required without Chromium fails; chrome soft impersonate string does not
    // change require_chromium_hard_path or truthful_fetch_path.
    use basecrawl_core::stealth::{
        requires_chromium_hard_path, truthful_fetch_path, HardPathDecision,
    };
    use basecrawl_proof::{FetchPath, ProxyClass};

    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Residential),
        difficulty: None,
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));
    assert_eq!(truthful_fetch_path(false), FetchPath::Direct);
    assert_eq!(truthful_fetch_path(true), FetchPath::Chromium);

    // Soft scrape with chrome-impersonate remains direct even if operators wish residential
    // without a dialable residential upstream — fail closed on class, not soft-as-hard success.
    let (url, _) = origin_http("no-forge-residential");
    let out = run_cli(
        &[
            &url,
            "--no-js",
            "--formats",
            "rawHtml",
            "--tls-impersonate",
            "chrome",
            "--proxy-class",
            "residential",
        ],
        &[],
    );
    // Residential required without upstream and --no-js should fail hard path policy
    // (not succeed with soft-only fetch_path claiming residential chromium).
    assert!(
        !out.status.success(),
        "residential+no-js must fail closed, not soft-as-hard success; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = parse_err_stderr(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    assert!(
        kind == "hard_path_policy"
            || kind == "proxy_class_unavailable"
            || kind.contains("hard")
            || kind.contains("proxy"),
        "expected hard/class fail closed; kind={kind} err={err}"
    );
    // No success proof with soft fetch sold as residential chromium.
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.trim().is_empty() {
        if let Ok(proof) = serde_json::from_str::<Value>(stdout.trim()) {
            let fp = proof["egress"]["fetch_path"].as_str();
            let class = proof["egress"]["proxy_class"].as_str();
            assert!(
                !(fp == Some("direct") && class == Some("residential")),
                "must never claim residential with soft-only path"
            );
            assert_ne!(
                fp,
                Some("chromium"),
                "soft-only must not claim chromium when hard failed"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CLI document surface: soft chrome aliases
// ---------------------------------------------------------------------------

#[test]
fn chrome_aliases_accepted() {
    for token in ["chrome", "chrome-145", "chrome-impersonate", "chrome_like"] {
        assert_eq!(
            SoftTlsImpersonate::parse(token).unwrap(),
            SoftTlsImpersonate::Chrome
        );
    }
}
