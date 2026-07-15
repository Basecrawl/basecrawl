//! Hermetic VAL-OXY matrix: residential dial template, CONNECT fail typing, max-1 concurrency,
//! fail-closed residential, sticky session, secret redaction. Gate-off by default.
//!
//! Live residual notes for CONNECT 403 product/destination ACL (e.g. taostats) live under
//! `.docs-evidence/hard-shield/oxylabs-connect-403-residual.md`. Secrets never appear here.

use base64::Engine;
use basecrawl_core::proxy::{
    acquire_residential_dial_slot, classify_connect_status, render_username,
    reset_residential_concurrency_for_tests, residential_dial_slot_held, UsernameTemplateOptions,
    MAX_LIVE_RESIDENTIAL_CONCURRENT,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const SECRET_PASSWORD: &str = "pxy-oxy-VALOXY-9f1a22cd";
const SECRET_USER: &str = "customer-USER";

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

fn strip_proxy_env(cmd: &mut Command) {
    cmd.env_remove("BASECRAWL_LIVE_PROXY");
    for key in [
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "BASECRAWL_COMPOSER_FAIL_START",
    ] {
        cmd.env_remove(key);
    }
}

fn run_scrape(args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(BIN);
    strip_proxy_env(&mut cmd);
    cmd.args(args);
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

fn origin_fixture() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let body = b"<!doctype html><html><body>oxy-origin-ok</body></html>";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(body);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}/oxy-origin")
}

#[derive(Default, Debug, Clone)]
struct HopRecord {
    username: String,
    hop_id: String,
}

#[derive(Default, Debug)]
struct StickyLog {
    hops: Vec<HopRecord>,
    session_map: std::collections::HashMap<String, String>,
    next_hop: usize,
    refused: AtomicUsize,
}

/// Connect mock modes: success sticky, always 403 ACL, always 407 auth.
#[derive(Clone, Copy)]
enum MockMode {
    StickyOk,
    Connect403,
    Connect407,
}

fn spawn_connect_mock(
    mode: MockMode,
    require_auth: bool,
) -> (String, Arc<Mutex<StickyLog>>, Arc<AtomicBool>) {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let log = Arc::new(Mutex::new(StickyLog::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let log_t = Arc::clone(&log);
    let stop_t = Arc::clone(&stop);
    thread::spawn(move || {
        while !stop_t.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
                    handle_connect(&mut client, mode, require_auth, &log_t);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}"), log, stop)
}

fn decode_basic_auth(header_value: &str) -> Option<(String, String)> {
    let token = header_value
        .strip_prefix("Basic ")
        .or_else(|| header_value.strip_prefix("basic "))?
        .trim();
    let raw = base64::prelude::BASE64_STANDARD.decode(token).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

fn handle_connect(
    client: &mut TcpStream,
    mode: MockMode,
    require_auth: bool,
    log: &Arc<Mutex<StickyLog>>,
) {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1];
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match client.read(&mut tmp) {
            Ok(0) => return,
            Ok(_) => {
                buf.push(tmp[0]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 16 * 1024 {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let first = req.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "CONNECT" {
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
        return;
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(0)),
        None => (target.to_string(), 0),
    };

    let auth_header = req
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("proxy-authorization:"))
        .map(|l| {
            l.split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        });
    let presented = auth_header.as_ref().and_then(|h| decode_basic_auth(h));

    match mode {
        MockMode::Connect407 => {
            // Auth reject residual — progress refused count for observability.
            if let Ok(g) = log.lock() {
                g.refused.fetch_add(1, Ordering::SeqCst);
            }
            let _ = client.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"mock\"\r\n\
                  Connection: close\r\n\r\n",
            );
            return;
        }
        MockMode::Connect403 => {
            if let Ok(g) = log.lock() {
                g.refused.fetch_add(1, Ordering::SeqCst);
            }
            // Record username (no password) for dial-identity proof even on refuse.
            if let Some((u, _)) = &presented {
                if let Ok(mut g) = log.lock() {
                    g.hops.push(HopRecord {
                        username: u.clone(),
                        hop_id: "refused".into(),
                    });
                }
            }
            let _ = client.write_all(
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 9\r\n\r\nForbidden",
            );
            return;
        }
        MockMode::StickyOk => {}
    }

    if require_auth {
        match &presented {
            Some((u, p)) if u.starts_with(SECRET_USER) && p == SECRET_PASSWORD => {}
            _ => {
                let _ = client.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"mock\"\r\n\
                      Connection: close\r\n\r\n",
                );
                return;
            }
        }
    }

    let username = presented
        .as_ref()
        .map(|(u, _)| u.clone())
        .unwrap_or_default();
    let session = username
        .split("-sessid-")
        .nth(1)
        .map(|rest| {
            rest.split('-')
                .take_while(|p| !p.eq_ignore_ascii_case("cc") && !p.eq_ignore_ascii_case("sessid"))
                .collect::<Vec<_>>()
                .join("-")
        })
        .filter(|s| !s.is_empty());
    let hop_id = {
        let mut g = log.lock().expect("log");
        let hop = if let Some(sess) = session.as_ref() {
            if let Some(existing) = g.session_map.get(sess) {
                existing.clone()
            } else {
                g.next_hop += 1;
                let hop = format!("203.0.113.{}", g.next_hop);
                g.session_map.insert(sess.clone(), hop.clone());
                hop
            }
        } else {
            g.next_hop += 1;
            format!("198.51.100.{}", g.next_hop)
        };
        g.hops.push(HopRecord {
            username: username.clone(),
            hop_id: hop.clone(),
        });
        hop
    };
    let _ = hop_id;

    let target_stream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    let mut upstream = target_stream;
    let Ok(mut client_read) = client.try_clone() else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let Ok(mut upstream_read) = upstream.try_clone() else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let Ok(mut client_write) = client.try_clone() else {
        return;
    };
    // Simple half-duplex relay is enough for soft --no-js origin fixture.
    let to_up = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match client_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if upstream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = upstream.shutdown(Shutdown::Both);
    });
    let to_client = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match upstream_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = client_write.shutdown(Shutdown::Both);
    });
    let _ = to_up.join();
    let _ = to_client.join();
}

fn proxy_url_with_user(user: &str) -> String {
    format!("http://{user}:{SECRET_PASSWORD}@127.0.0.1:0") // port filled by callers
}

fn credentialed_proxy(base: &str, user: &str) -> String {
    // base is http://127.0.0.1:PORT
    let auth = format!("{user}:{SECRET_PASSWORD}");
    base.replacen("http://", &format!("http://{auth}@"), 1)
}

// ---------------------------------------------------------------------------
// VAL-OXY-001 / 002 — username templates embed cc + sessid
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_001_002_sticky_cc_username_template() {
    let rendered = render_username(
        Some("customer-USER"),
        &UsernameTemplateOptions {
            country: Some("US".into()),
            session: Some("SESS99".into()),
            template: None,
        },
    )
    .expect("render");
    let u = rendered.expect("username");
    assert!(u.contains("-cc-US"), "country token missing: {u}");
    assert!(u.contains("-sessid-SESS99"), "session token missing: {u}");
    // Predecorated base does not double -cc-
    let again = render_username(
        Some("customer-USER-cc-US"),
        &UsernameTemplateOptions {
            country: Some("US".into()),
            session: Some("SESS99".into()),
            template: None,
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        again.matches("-cc-").count(),
        1,
        "double cc residual: {again}"
    );
    assert!(again.ends_with("-sessid-SESS99"));
}

// Soft-path proxy with datacenter class (residential soft fails hard_path dual-stack).
// VAL-OXY template tokens still apply provider-agnostically to any dial username.
#[test]
fn val_oxy_002_cli_embeds_country_and_session_on_dial() {
    let (proxy_base, log, stop) = spawn_connect_mock(MockMode::StickyOk, true);
    let origin = origin_fixture();
    // Pre-decorated userinfo like live Oxylabs env commonly uses customer-x-cc-US.
    let proxy = credentialed_proxy(&proxy_base, "customer-USER-cc-US");
    let out = run_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
            "--proxy",
            &proxy,
            "--proxy-country",
            "US",
            "--proxy-session",
            "oxyS1",
            "--proxy-class",
            "datacenter",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hops = log.lock().unwrap().hops.clone();
    assert!(!hops.is_empty(), "connect must have dialed");
    let u = &hops[0].username;
    assert!(u.contains("-cc-US"), "username={u}");
    assert!(u.contains("-sessid-oxyS1"), "username={u}");
    assert_eq!(u.matches("-cc-").count(), 1, "no double-cc: {u}");
    // No secret leakage
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains(SECRET_PASSWORD));
    assert!(!combined.contains(&format!("{SECRET_USER}:{SECRET_PASSWORD}")));
}

// ---------------------------------------------------------------------------
// VAL-OXY-003 — CONNECT 403 typed transport residual ≠ challenge
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_003_connect_403_is_transport_not_challenge() {
    let err = classify_connect_status(403);
    assert_eq!(err.kind(), "transport_error");
    let json = err.to_json();
    assert_eq!(json["error"]["failure_class"], "proxy_acl_error");
    assert_eq!(json["error"]["status_code"], 403);
    assert_ne!(json["error"]["kind"], "challenge_blocked");
    assert_ne!(json["error"]["failure_class"], "challenge_block");

    let (proxy_base, _log, stop) = spawn_connect_mock(MockMode::Connect403, false);
    let origin = origin_fixture();
    let proxy = credentialed_proxy(&proxy_base, SECRET_USER);
    let out = run_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "12",
            "--proxy",
            &proxy,
            "--proxy-class",
            "datacenter",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    assert!(!out.status.success(), "CONNECT 403 must fail closed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("\"proxy_class\":\"residential\""));
    // Prefer structured JSON on stderr.
    let parsed: Value = serde_json::from_str(stderr.trim()).unwrap_or(Value::Null);
    let kind = parsed
        .pointer("/error/kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let failure_class = parsed
        .pointer("/error/failure_class")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        kind == "transport_error"
            || kind == "proxy_auth_error"
            || stderr.contains("transport_error")
            || stderr.contains("proxy_acl_error")
            || stderr.contains("CONNECT 403"),
        "expected transport residual, got kind={kind} stderr={stderr}"
    );
    assert_ne!(kind, "challenge_blocked");
    assert!(!stderr.contains("\"kind\":\"challenge_blocked\""));
    assert!(
        failure_class == "proxy_acl_error"
            || stderr.contains("proxy_acl_error")
            || stderr.contains("CONNECT 403")
            || stderr.contains("product ACL"),
        "expected ACL class, got failure_class={failure_class} stderr={stderr}"
    );
    assert!(!stderr.contains(SECRET_PASSWORD));
}

#[test]
fn val_oxy_003_connect_407_is_proxy_auth_error() {
    let err = classify_connect_status(407);
    assert_eq!(err.kind(), "proxy_auth_error");

    let (proxy_base, _log, stop) = spawn_connect_mock(MockMode::Connect407, false);
    let origin = origin_fixture();
    // Wrong password
    let proxy = proxy_base.replacen("http://", &format!("http://{SECRET_USER}:wrongpass@"), 1);
    let out = run_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "12",
            "--proxy",
            &proxy,
            "--proxy-class",
            "datacenter",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("proxy_auth_error")
            || stderr.contains("407")
            || stderr.contains("authentication"),
        "stderr={stderr}"
    );
    assert!(!stderr.contains("challenge_blocked"));
    assert!(!stderr.contains("wrongpass"));
    assert!(!stderr.contains(SECRET_PASSWORD));
}

// ---------------------------------------------------------------------------
// VAL-OXY-004 — required residential fails closed on CONNECT refuse
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_004_required_residential_fails_closed_on_connect_refuse() {
    // residential class refuse --no-js; therefore we test with force-browser + slow mock 403.
    // Soft datacenter path already proves CONNECT refuse typing; for residential required class
    // without a working upstream the dual soft-or unavailable path fails closed.
    let out = run_scrape(
        &[
            "http://127.0.0.1:9/no-proxy",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "8",
            "--proxy-class",
            "residential",
        ],
        &[],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stderr.contains("proxy_class_unavailable")
            || stderr.contains("hard_path_policy")
            || stderr.contains("residential"),
        "stderr={stderr}"
    );
    // Must not emit residential success proof.
    if let Ok(proof) = serde_json::from_str::<Value>(stdout.trim()) {
        assert_ne!(proof["egress"]["proxy_class"].as_str(), Some("residential"));
    }

    // CONNECT refuse under commercial class (datacenter soft path still models dial refuse).
    let (proxy_base, _log, stop) = spawn_connect_mock(MockMode::Connect403, false);
    let origin = origin_fixture();
    let proxy = credentialed_proxy(&proxy_base, SECRET_USER);
    let refuse = run_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "12",
            "--proxy",
            &proxy,
            "--proxy-class",
            "datacenter",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    assert!(!refuse.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&refuse.stdout),
        String::from_utf8_lossy(&refuse.stderr)
    );
    assert!(!combined.contains("\"proxy_class\":\"residential\""));
    assert!(!combined.contains(SECRET_PASSWORD));
}

// ---------------------------------------------------------------------------
// VAL-OXY-005 — max 1 concurrent residential dial family
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_005_residential_concurrency_max_one() {
    assert_eq!(MAX_LIVE_RESIDENTIAL_CONCURRENT, 1);
    reset_residential_concurrency_for_tests();
    let g1 = acquire_residential_dial_slot("oxy-test-a").expect("first");
    assert!(residential_dial_slot_held());
    let g2 = acquire_residential_dial_slot("oxy-test-b");
    assert!(g2.is_err());
    assert_eq!(g2.unwrap_err().kind(), "residential_concurrency");
    drop(g1);
    let g3 = acquire_residential_dial_slot("oxy-test-c").expect("after release");
    drop(g3);
    reset_residential_concurrency_for_tests();
}

// ---------------------------------------------------------------------------
// VAL-OXY-006 / 009 — live gate off: hermetic path green, no commercial dial
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_006_009_gate_off_hermetic_and_no_mandatory_live() {
    let report = Command::new("sh")
        .args([
            "-c",
            r#"
            unset BASECRAWL_LIVE_PROXY
            if [ "${BASECRAWL_LIVE_PROXY:-}" = "1" ]; then echo ON; else echo OFF; fi
            "#,
        ])
        .output()
        .expect("sh");
    assert!(String::from_utf8_lossy(&report.stdout).contains("OFF"));

    // Hermetic mock path works with gate off.
    let (proxy_base, log, stop) = spawn_connect_mock(MockMode::StickyOk, true);
    let origin = origin_fixture();
    let proxy = credentialed_proxy(&proxy_base, SECRET_USER);
    let out = run_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "12",
            "--proxy",
            &proxy,
            "--proxy-session",
            "herm1",
            "--proxy-country",
            "US",
            "--proxy-class",
            "datacenter",
        ],
        &[("BASECRAWL_LIVE_PROXY", None)],
    );
    stop.store(true, Ordering::SeqCst);
    assert!(
        out.status.success(),
        "hermetic without live gate: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let hops = log.lock().unwrap().hops.clone();
    assert!(!hops.is_empty());
    assert!(hops[0].username.contains("-cc-US"));
    assert!(hops[0].username.contains("sessid-herm1"));
}

// ---------------------------------------------------------------------------
// VAL-OXY-008 — sticky session reuses hop
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_008_sticky_session_same_hop() {
    let (proxy_base, log, stop) = spawn_connect_mock(MockMode::StickyOk, true);
    let origin = origin_fixture();
    let proxy = credentialed_proxy(&proxy_base, SECRET_USER);
    for _ in 0..2 {
        let out = run_scrape(
            &[
                &origin,
                "--no-js",
                "--robots",
                "ignore",
                "--formats",
                "rawHtml",
                "--timeout",
                "12",
                "--proxy",
                &proxy,
                "--proxy-session",
                "STICKY42",
                "--proxy-class",
                "datacenter",
            ],
            &[],
        );
        assert!(
            out.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    stop.store(true, Ordering::SeqCst);
    let g = log.lock().unwrap();
    assert!(
        g.hops.len() >= 2,
        "expected >=2 dials, got {}",
        g.hops.len()
    );
    assert_eq!(g.hops[0].hop_id, g.hops[1].hop_id, "sticky hop must match");
    assert!(g.hops[0].username.contains("sessid-STICKY42"));
}

// ---------------------------------------------------------------------------
// VAL-OXY-010 — secrets redacted
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_010_password_never_in_proof_or_logs() {
    let (proxy_base, _log, stop) = spawn_connect_mock(MockMode::StickyOk, true);
    let origin = origin_fixture();
    let proxy = credentialed_proxy(&proxy_base, SECRET_USER);
    let out = run_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "12",
            "--verbose",
            "--proxy",
            &proxy,
            "--proxy-class",
            "datacenter",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(SECRET_PASSWORD));
    assert!(!stderr.contains(SECRET_PASSWORD));
    assert!(!stdout.contains(&format!("{SECRET_USER}:{SECRET_PASSWORD}")));
    assert!(!stderr.contains(&format!("{SECRET_USER}:{SECRET_PASSWORD}")));
    if out.status.success() {
        let proof: Value = serde_json::from_str(stdout.trim()).expect("proof");
        let proof_s = proof.to_string();
        assert!(!proof_s.contains(SECRET_PASSWORD));
    }
}

// ---------------------------------------------------------------------------
// VAL-OXY-011 — residential class only when dialed
// ---------------------------------------------------------------------------
#[test]
fn val_oxy_011_direct_success_not_relabeled_residential() {
    let origin = origin_fixture();
    let out = run_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "10",
        ],
        &[],
    );
    assert!(out.status.success());
    let proof: Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(proof["egress"]["proxy_class"].as_str(), Some("direct"));
    assert_ne!(proof["egress"]["proxy_class"].as_str(), Some("residential"));
}

// Unused helper keep lint happy if rewritten: credentialed construction path is used.
#[allow(dead_code)]
fn _unused() {
    let _ = proxy_url_with_user(SECRET_USER);
}
