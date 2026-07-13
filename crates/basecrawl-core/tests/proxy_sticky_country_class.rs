//! Sticky session, country username templates, and truthful `egress.proxy_class`
//! (VAL-PROXY-010/011/013/014/020–028, hermetic mock only).
//!
//! VAL-PROXY-012 / 015+ Chromium composer multipage stickiness is owned by the M12
//! composer leaf; this matrix covers the shared soft-path dialer + proof emission
//! that the composer reuses.

use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;
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
const SECRET_PASSWORD: &str = "pxy-sticky-VALPROXY-7e2c91ab";
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

fn run_proxy_scrape(args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
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

fn origin_fixture() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_t = Arc::clone(&hits);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let body = b"<!doctype html><html><body>sticky-origin-ok</body></html>";
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
    (format!("http://{addr}/sticky-origin"), hits)
}

#[derive(Default, Debug, Clone)]
struct HopRecord {
    username: String,
    country: Option<String>,
    session: Option<String>,
    hop_id: String,
}

#[derive(Default, Debug)]
struct StickyLog {
    hops: Vec<HopRecord>,
    /// session → hop_id mapping used by the mock
    session_map: HashMap<String, String>,
    next_hop: usize,
}

fn parse_country_session(username: &str) -> (Option<String>, Option<String>) {
    let country = username.split("-cc-").nth(1).and_then(|rest| {
        let end = rest.find("-sessid-").unwrap_or(rest.len());
        let token = rest[..end].trim_matches('-');
        let token = token.split('-').next().unwrap_or(token);
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    });
    let session = username
        .split("-sessid-")
        .nth(1)
        .map(|rest| {
            // take remainder up to next known delimiter or end
            rest.split('-')
                .take_while(|p| !p.eq_ignore_ascii_case("cc") && !p.eq_ignore_ascii_case("sessid"))
                .collect::<Vec<_>>()
                .join("-")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty());
    (country, session)
}

fn spawn_sticky_http_connect_mock(
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
                    handle_sticky_connect(&mut client, require_auth, &log_t);
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

fn handle_sticky_connect(client: &mut TcpStream, require_auth: bool, log: &Arc<Mutex<StickyLog>>) {
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
    let (country, session) = parse_country_session(&username);
    let hop_id = {
        let mut g = log.lock().expect("log");
        let hop = if let Some(sess) = session.as_ref() {
            if let Some(existing) = g.session_map.get(sess) {
                existing.clone()
            } else {
                g.next_hop += 1;
                // Distinct sticky hop ids per session: 203.0.113.N TEST-NET-3 labels.
                let hop = format!("203.0.113.{}", g.next_hop);
                g.session_map.insert(sess.clone(), hop.clone());
                hop
            }
        } else {
            // Non-sticky open pool: rotate hop every call.
            g.next_hop += 1;
            format!("198.51.100.{}", g.next_hop)
        };
        g.hops.push(HopRecord {
            username: username.clone(),
            country: country.clone(),
            session: session.clone(),
            hop_id: hop.clone(),
        });
        hop
    };

    let target_stream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    // Expose stickiness via a hop-aware response header on the CONNECT success line trailers
    // (most clients ignore extra headers after 200); primarily the mock log is authoritative.
    let _ = write!(
        client,
        "HTTP/1.1 200 Connection Established\r\nX-Mock-Exit-Hop: {hop_id}\r\n\r\n"
    );
    let _ = client.set_nonblocking(false);
    let _ = target_stream.set_nonblocking(false);
    relay(client, target_stream);
}

fn decode_basic_auth(header: &str) -> Option<(String, String)> {
    let mut parts = header.split_whitespace();
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let token = parts.next()?;
    let raw = base64::prelude::BASE64_STANDARD.decode(token).ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (u, p) = text.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

fn relay(a: &mut TcpStream, mut b: TcpStream) {
    let Ok(mut a_clone) = a.try_clone() else {
        return;
    };
    let Ok(mut b_clone) = b.try_clone() else {
        return;
    };
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut a_clone, &mut b_clone);
        let _ = b_clone.shutdown(Shutdown::Both);
    });
    let _ = std::io::copy(&mut b, a);
    let _ = a.shutdown(Shutdown::Both);
    let _ = t1.join();
}

fn assert_scrape_ok(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr={stderr}\nstdout={stdout}",
        out.status.code()
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout not ScrapeProof JSON: {e}\nstdout={stdout}"))
}

fn assert_no_secret(text: &str) {
    assert!(
        !text.contains(SECRET_PASSWORD),
        "host-visible stream leaked proxy password"
    );
    assert!(
        !text.contains(&format!("{SECRET_USER}:{SECRET_PASSWORD}")),
        "host-visible stream leaked credential pair"
    );
}

fn proxy_url_with_creds(base: &str) -> String {
    let bare = base.strip_prefix("http://").unwrap();
    format!("http://{SECRET_USER}:{SECRET_PASSWORD}@{bare}")
}

// ---------------------------------------------------------------------------
// VAL-PROXY-010 — same sticky session → same hop
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_010_same_session_reuses_hop() {
    let (origin, _) = origin_fixture();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    let args = |origin: &str, proxy: &str| -> Vec<String> {
        vec![
            origin.to_string(),
            "--proxy".into(),
            proxy.to_string(),
            "--proxy-session".into(),
            "S1".into(),
            "--proxy-country".into(),
            "US".into(),
            "--proxy-class".into(),
            "residential".into(),
            "--no-js".into(),
            "--robots".into(),
            "ignore".into(),
            "--formats".into(),
            "rawHtml".into(),
            "--timeout".into(),
            "15".into(),
        ]
    };

    let out1 = run_proxy_scrape(
        &args(&origin, &proxy)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &[],
    );
    let proof1 = assert_scrape_ok(&out1);

    let out2 = run_proxy_scrape(
        &args(&origin, &proxy)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        &[],
    );
    let proof2 = assert_scrape_ok(&out2);
    stop.store(true, Ordering::SeqCst);

    let g = log.lock().expect("log");
    assert!(
        g.hops.len() >= 2,
        "mock must record two sticky hops, log={g:?}"
    );
    let hop_a = &g.hops[0].hop_id;
    let hop_b = &g.hops[1].hop_id;
    assert_eq!(
        hop_a, hop_b,
        "same sticky session id must reuse hop, log={g:?}"
    );
    assert_eq!(g.hops[0].session.as_deref(), Some("S1"));
    assert_eq!(g.hops[1].session.as_deref(), Some("S1"));
    assert_eq!(
        proof1["egress"]["proxy_class"].as_str(),
        Some("residential")
    );
    assert_eq!(
        proof2["egress"]["proxy_class"].as_str(),
        Some("residential")
    );
    assert_no_secret(&proof1.to_string());
    assert_no_secret(&proof2.to_string());
    assert_no_secret(&String::from_utf8_lossy(&out1.stderr));
}

// ---------------------------------------------------------------------------
// VAL-PROXY-011 — distinct sessions may get distinct hops
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_011_distinct_sessions_get_distinct_hops() {
    let (origin, _) = origin_fixture();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    for sess in ["S1", "S2"] {
        let out = run_proxy_scrape(
            &[
                &origin,
                "--proxy",
                &proxy,
                "--proxy-session",
                sess,
                "--proxy-country",
                "US",
                "--no-js",
                "--robots",
                "ignore",
                "--formats",
                "rawHtml",
                "--timeout",
                "15",
            ],
            &[],
        );
        assert_scrape_ok(&out);
    }
    stop.store(true, Ordering::SeqCst);
    let g = log.lock().expect("log");
    assert!(g.hops.len() >= 2, "need two session dials, log={g:?}");
    let s1 = g
        .hops
        .iter()
        .find(|h| h.session.as_deref() == Some("S1"))
        .expect("S1 hop");
    let s2 = g
        .hops
        .iter()
        .find(|h| h.session.as_deref() == Some("S2"))
        .expect("S2 hop");
    assert_ne!(
        s1.hop_id, s2.hop_id,
        "distinct sticky sessions must map independently, log={g:?}"
    );
    assert!(
        s1.username.contains("sessid-S1"),
        "username must embed sessid token, got {}",
        s1.username
    );
    assert!(
        s2.username.contains("sessid-S2"),
        "username must embed sessid token, got {}",
        s2.username
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-013 / 014 — country token in username template
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_013_014_country_token_in_username_and_mock_country() {
    let (origin, _) = origin_fixture();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-session",
            "geo1",
            "--proxy-country",
            "US",
            "--proxy-username-template",
            "{user}-cc-{cc}-sessid-{sessid}",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    assert_scrape_ok(&out);
    stop.store(true, Ordering::SeqCst);
    let g = log.lock().expect("log");
    assert!(!g.hops.is_empty());
    let hop = &g.hops[0];
    assert!(
        hop.username.contains("-cc-US"),
        "country token must appear in dialed username, got {}",
        hop.username
    );
    assert_eq!(
        hop.country.as_deref(),
        Some("US"),
        "mock must map hop to requested country, log={g:?}"
    );
    // Template used base username already containing customer-USER → customer-customer-USER is OK
    // (base username is the full secret-user token). Ensure not Oxylabs-host hardcoding.
    assert!(
        hop.username.contains("sessid-geo1"),
        "session token must appear, got {}",
        hop.username
    );
}

// ---------------------------------------------------------------------------
// VAL-PROXY-020 / 021 — required class without viable dial fails closed
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_020_021_required_residential_without_upstream_fails_closed() {
    let (origin, origin_hits) = origin_fixture();
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy-class",
            "residential",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "5",
        ],
        &[],
    );
    assert!(
        !out.status.success(),
        "required residential without proxy must fail closed; got exit {:?}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        origin_hits.load(Ordering::SeqCst),
        0,
        "must not silently dial origin direct under required residential"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let err: Value = serde_json::from_str(stderr.trim()).expect("structured stderr JSON");
    assert_eq!(
        err["error"]["kind"].as_str(),
        Some("proxy_class_unavailable")
    );
    assert!(out.stdout.is_empty(), "no forged success proof on stdout");
}

#[test]
fn val_proxy_021_required_class_dead_upstream_fails_closed() {
    let (origin, origin_hits) = origin_fixture();
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let dead = format!("http://{SECRET_USER}:{SECRET_PASSWORD}@{addr}");
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &dead,
            "--proxy-class",
            "mobile",
            "--proxy-session",
            "m1",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "5",
        ],
        &[],
    );
    assert!(!out.status.success(), "dead mobile path must fail closed");
    assert_eq!(origin_hits.load(Ordering::SeqCst), 0);
    assert!(out.stdout.is_empty());
}

// ---------------------------------------------------------------------------
// VAL-PROXY-023/024/025 — credentials / secret-bearing username redaction
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_023_024_025_credentials_and_secret_username_redacted() {
    let (origin, _) = origin_fixture();
    let (proxy_base, _log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-session",
            "redact1",
            "--proxy-country",
            "US",
            "--proxy-class",
            "residential",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
            "--verbose",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    let proof = assert_scrape_ok(&out);
    let proof_s = proof.to_string();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_no_secret(&proof_s);
    assert_no_secret(&stderr);
    assert_no_secret(&stdout);
    // Secret-bearing full residential username shape must not land in proof/logs.
    let secret_username = format!("{SECRET_USER}-cc-US-sessid-redact1");
    assert!(
        !proof_s.contains(&secret_username),
        "ScrapeProof must not echo full secret-bearing username"
    );
    assert!(
        !stderr.contains(&secret_username),
        "stderr must not echo full secret-bearing username"
    );
    assert!(!proof_s.contains(SECRET_PASSWORD));
}

// ---------------------------------------------------------------------------
// VAL-PROXY-026 / 027 / 028 — truthful egress.proxy_class
// ---------------------------------------------------------------------------
#[test]
fn val_proxy_026_proxied_scrape_emits_truthful_class() {
    let (origin, _) = origin_fixture();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    let out_res = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--proxy-class",
            "residential",
            "--proxy-session",
            "cls1",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    let proof = assert_scrape_ok(&out_res);
    assert_eq!(proof["egress"]["proxy_class"].as_str(), Some("residential"));
    assert!(!log.lock().expect("log").hops.is_empty());

    // Default configured upstream (no --proxy-class) is truthful datacenter.
    let out_dc = run_proxy_scrape(
        &[
            &origin,
            "--proxy",
            &proxy,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    stop.store(true, Ordering::SeqCst);
    let proof_dc = assert_scrape_ok(&out_dc);
    assert_eq!(
        proof_dc["egress"]["proxy_class"].as_str(),
        Some("datacenter"),
        "configured open proxy defaults to datacenter class"
    );
}

#[test]
fn val_proxy_027_direct_scrape_is_direct_not_residential() {
    let (origin, hits) = origin_fixture();
    let out = run_proxy_scrape(
        &[
            &origin,
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "15",
        ],
        &[],
    );
    let proof = assert_scrape_ok(&out);
    assert!(hits.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        proof["egress"]["proxy_class"].as_str(),
        Some("direct"),
        "direct path must emit proxy_class=direct"
    );
    assert_ne!(proof["egress"]["proxy_class"].as_str(), Some("residential"));
    assert_ne!(proof["egress"]["proxy_class"].as_str(), Some("mobile"));
}

#[test]
fn val_proxy_028_cannot_claim_residential_without_matching_dial() {
    let (origin, hits) = origin_fixture();
    // Wish for residential without any upstream → fail closed, no forged proof.
    let out = run_proxy_scrape(
        &[
            &origin,
            "--proxy-class",
            "residential",
            "--no-js",
            "--robots",
            "ignore",
            "--formats",
            "rawHtml",
            "--timeout",
            "5",
        ],
        &[],
    );
    assert!(!out.status.success());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert!(out.stdout.is_empty());
}
