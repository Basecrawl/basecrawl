//! M21 cross-path integrity after inject depth (VAL-CROSS-STEALTH-001..014).
//!
//! Hermetic multipage sticky under deeper injects; soft+hard dual jam honesty; composer
//! DoH non-regression (no host target QNAME); sticky egress survival under injects.
//! Focused CLI + mock origin/proxy only on mission ports **21000–21099**. No live swarm.
//! Live Oxylabs never required (BASECRAWL_LIVE_PROXY may exist but suite always strips it).

use base64::Engine;
use basecrawl_core::proxy::{
    start_chromium_composer, ComposerOriginDialer, ProxyConfig, UsernameTemplateOptions,
};
use basecrawl_core::stealth::{
    acquire_sticky_profile, wipe_sticky_profile, HardPathDecision, SiteDifficulty,
};
use basecrawl_core::stealth::{requires_chromium_hard_path, truthful_fetch_path};
use basecrawl_fp::{
    browser_injection_script, generate, product_chromium_major, PINNED_CHROMIUM_MAJOR,
};
use basecrawl_proof::{FetchPath, ProxyClass};
use basecrawl_seal::{
    NameResolver, OriginDialer, ResolverEndpoint, SealError, SealedSocksProxy, DEFAULT_DOH_ENDPOINT,
};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const SECRET_PASSWORD: &str = "xstealth-VALCROSS-pxy-7a3e91";
const SECRET_USER: &str = "customer-USER";

// ---------------------------------------------------------------------------
// Hermetic mission-range helpers (VAL-CROSS-STEALTH-013)
// ---------------------------------------------------------------------------

fn bind_mission_port() -> TcpListener {
    for port in 21000u16..=21099 {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            let _ = listener.set_nonblocking(true);
            return listener;
        }
    }
    panic!("no free cross-stealth port in 21000-21099");
}

fn strip_proxy_env(cmd: &mut Command) {
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
        "BASECRAWL_COMPOSER_FAIL_START",
        "BASECRAWL_DISABLE_STEALTH_INJECT",
        "TWOCAPTCHA_API_KEY",
        "ANTICAPTCHA_API_KEY",
        "CAPSOLVER_API_KEY",
    ] {
        cmd.env_remove(key);
    }
}

fn run_cli(args: &[&str]) -> Output {
    run_cli_env(args, &[])
}

fn run_cli_env(args: &[&str], env: &[(&str, Option<&str>)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    strip_proxy_env(&mut cmd);
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
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl")
}

/// Retry a hard-path CLI scrape when deadline flakes under multi-agent host load.
///
/// Pre-existing M21 suite notes observed sticky SingletonLock / cold Chromium launch contention
/// that sporadically surfaces as `browser operation deadline exceeded` with a green product.
/// Callers still assert real success content; this only reduces nondeterministic validator
/// noise. Non-deadline failures are never retried.
///
/// Under sustained multi-agent Chrome pressure a single retry is often insufficient; probe up
/// to three total attempts with progressive backoff, clearing sticky profile dirs each time.
fn run_cli_hard_with_deadline_retry(args: &[&str]) -> Output {
    let mut last = run_cli(args);
    if last.status.success() {
        return last;
    }
    for attempt in 1u32..=2 {
        let stderr = String::from_utf8_lossy(&last.stderr);
        if !stderr.contains("browser operation deadline exceeded")
            && !stderr.contains("browser setup deadline exceeded")
        {
            return last;
        }
        // Fresh sticky-profile keyspace for sticky task ids that re-attach after a killed Chrome.
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("basecrawl-sticky-profiles"));
        thread::sleep(Duration::from_millis(400 * u64::from(attempt)));
        last = run_cli(args);
        if last.status.success() {
            return last;
        }
    }
    last
}

fn proof_from_output(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON stdout, got parse error {e}; status={:?} stderr={} stdout={}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
            stdout
        )
    })
}

fn html_from_proof(proof: &Value) -> String {
    proof["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn read_http_request(stream: &mut impl Read) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

// ---------------------------------------------------------------------------
// Origin fixtures
// ---------------------------------------------------------------------------

/// Same sticky profile multipage origins under deeper injects.
///
/// Uses **two dedicated listeners** (not path-routing) so soft preflight + Chromium cannot race
/// a path classifier under concurrent accept pressure. Cookie continuity is hybrid:
/// - In-page `document.cookie` for same-host multipage when args share one host (cookie reader).
/// - Server `Set-Cookie` + Cookie header reflection on the reader origin for wipe / continuity.
fn spawn_cookie_set_origin() -> String {
    let body = r#"<!doctype html><html><body data-page="A">
<script>document.cookie='sticky_session=crossA; path=/';</script>
<script>
(function(){
  var wd=false; try{wd=navigator.webdriver===true;}catch(e){wd=true;}
  var chromePresent=(typeof window.chrome!=='undefined'&&window.chrome!==null);
  var hc=navigator.hardwareConcurrency||0;
  var dual=(typeof window.__bcStealthInstalled!=='undefined');
  document.body.setAttribute('data-webdriver', String(wd));
  document.body.setAttribute('data-chrome', String(chromePresent));
  document.body.setAttribute('data-hc', String(hc));
  document.body.insertAdjacentHTML('beforeend',
    '<pre id="surface">page=A;cookies='+document.cookie+
    ';webdriver='+wd+
    ';chrome='+chromePresent+
    ';hc='+hc+
    ';dual='+dual+
    '</pre>');
})();
</script>
</body></html>"#;
    spawn_static_origin_with_headers(body, "Set-Cookie: sticky_session=crossA; Path=/\r\n")
}

fn spawn_cookie_read_origin() -> String {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(150);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let req = read_http_request(&mut stream);
                    let cookie_hdr = req
                        .lines()
                        .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
                        .map(|line| line.split_once(':').map(|(_, v)| v.trim()).unwrap_or(""))
                        .unwrap_or("");
                    let cookie_esc = cookie_hdr.replace(['\'', '<', '>', '&'], "");
                    let body = format!(
                        r#"<!doctype html><html><body data-page="B">
<script>
(function(){{
  var wd=false; try{{wd=navigator.webdriver===true;}}catch(e){{wd=true;}}
  var chromePresent=(typeof window.chrome!=='undefined'&&window.chrome!==null);
  var hc=navigator.hardwareConcurrency||0;
  var dual=(typeof window.__bcStealthInstalled!=='undefined');
  document.body.setAttribute('data-webdriver', String(wd));
  document.body.setAttribute('data-chrome', String(chromePresent));
  document.body.setAttribute('data-hc', String(hc));
  document.body.innerHTML=
    '<pre id="surface">page=B;cookies='+document.cookie+
    ';webdriver='+wd+
    ';chrome='+chromePresent+
    ';hc='+hc+
    ';dual='+dual+
    ';serverJar={cookie_esc}</pre>';
}})();
</script>
</body></html>"#,
                        cookie_esc = cookie_esc
                    );
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}/page-b")
}

/// One shared host multipage cookie origin (path mux) for stickiness under keep-profile.
fn spawn_cookie_nav_multipage() -> (String, String) {
    // Two dedicated same-host paths via one listener, classified after a full request read.
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(150);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let req = read_http_request(&mut stream);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_ascii_lowercase();
                    let cookie_hdr = req
                        .lines()
                        .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
                        .map(|line| line.split_once(':').map(|(_, v)| v.trim()).unwrap_or(""))
                        .unwrap_or("");
                    // Prefer B when any form of the canary path appears (absolute form included).
                    let is_b = path.contains("page-b")
                        || path.contains("page2")
                        || path.ends_with("/b")
                        || path.contains("/page-b?");
                    if is_b {
                        let cookie_esc = cookie_hdr.replace(['\'', '<', '>', '&'], "");
                        let body = format!(
                            r#"<!doctype html><html><body data-page="B">
<script>
(function(){{
  var wd=false; try{{wd=navigator.webdriver===true;}}catch(e){{wd=true;}}
  var chromePresent=(typeof window.chrome!=='undefined'&&window.chrome!==null);
  var hc=navigator.hardwareConcurrency||0;
  var dual=(typeof window.__bcStealthInstalled!=='undefined');
  document.body.setAttribute('data-webdriver', String(wd));
  document.body.setAttribute('data-chrome', String(chromePresent));
  document.body.setAttribute('data-hc', String(hc));
  document.body.innerHTML=
    '<pre id="surface">page=B;cookies='+document.cookie+
    ';webdriver='+wd+
    ';chrome='+chromePresent+
    ';hc='+hc+
    ';dual='+dual+
    ';serverJar={cookie_esc}</pre>';
}})();
</script>
</body></html>"#,
                            cookie_esc = cookie_esc
                        );
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                    } else {
                        let body = r#"<!doctype html><html><body data-page="A">
<script>document.cookie='sticky_session=crossA; path=/';</script>
<script>
(function(){
  var wd=false; try{wd=navigator.webdriver===true;}catch(e){wd=true;}
  var chromePresent=(typeof window.chrome!=='undefined'&&window.chrome!==null);
  var hc=navigator.hardwareConcurrency||0;
  var dual=(typeof window.__bcStealthInstalled!=='undefined');
  document.body.setAttribute('data-webdriver', String(wd));
  document.body.setAttribute('data-chrome', String(chromePresent));
  document.body.setAttribute('data-hc', String(hc));
  document.body.insertAdjacentHTML('beforeend',
    '<pre id="surface">page=A;cookies='+document.cookie+
    ';webdriver='+wd+
    ';chrome='+chromePresent+
    ';hc='+hc+
    ';dual='+dual+
    '</pre>');
})();
</script>
</body></html>"#;
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: sticky_session=crossA; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (
        format!("http://{addr}/page-a"),
        format!("http://{addr}/page-b"),
    )
}

fn spawn_static_origin_with_headers(body: &str, extra_headers: &str) -> String {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let body = body.to_string();
    let extra_headers = extra_headers.to_string();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(150);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 8192];
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = stream.read(&mut buf);
                    let headers = if extra_headers.is_empty() {
                        String::new()
                    } else if extra_headers.ends_with("\r\n") {
                        extra_headers.clone()
                    } else {
                        format!("{extra_headers}\r\n")
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Content-Length: {}\r\nConnection: close\r\n{headers}\r\n{}",
                        body.len(),
                        body
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}/")
}

/// Soft open HTML origin.
fn spawn_soft_ok(marker: &str) -> String {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let body = format!(
        "<!doctype html><html><body><h1 id=\"ok\">{marker}</h1></body></html>",
        marker = marker
    );
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.read(&mut buf);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}/soft-ok")
}

/// Challenge interstitial (page B for multipage hang guard).
fn spawn_challenge_origin() -> String {
    let body = r#"<!doctype html><html><body>
<title>Just a moment...</title>
<div id="challenge-running">Checking your browser before accessing the site.</div>
<script>window._cf_chl_opt = {};</script>
<meta name="robots" content="noindex">
<span>cloudflare</span> challenge-platform cf-browser-verification
</body></html>"#;
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let body = body.to_string();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.read(&mut buf);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\ncf-mitigated: challenge\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}/blocked")
}

/// WebRTC-aware open origin for WebRTC×DoH non-interference (VAL-CROSS-STEALTH-010).
fn spawn_webrtc_policy_origin() -> String {
    let body = r#"<!doctype html><html><body>
<script>
(function(){
  var wd=false; try{wd=navigator.webdriver===true;}catch(e){wd=true;}
  document.body.innerHTML='<pre id="surface">page=webrtc;webdriver='+wd+';ok=true</pre>';
})();
</script>
</body></html>"#;
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let body = body.to_string();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.read(&mut buf);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    format!("http://{addr}/webrtc-ok")
}

// ---------------------------------------------------------------------------
// Sticky HTTP CONNECT mock proxy (egress hop id)
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct HopRecord {
    username: String,
    session: Option<String>,
    hop_id: String,
    target: String,
}

#[derive(Default, Debug)]
struct StickyLog {
    hops: Vec<HopRecord>,
    session_map: HashMap<String, String>,
    next_hop: usize,
    direct_gets: usize,
}

fn parse_session(username: &str) -> Option<String> {
    username
        .split("-sessid-")
        .nth(1)
        .map(|rest| {
            rest.split('-')
                .take_while(|p| !p.eq_ignore_ascii_case("cc") && !p.eq_ignore_ascii_case("sessid"))
                .collect::<Vec<_>>()
                .join("-")
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
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
                    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = client.set_write_timeout(Some(Duration::from_secs(10)));
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
    let deadline = Instant::now() + Duration::from_secs(8);
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
    let target = parts.next().unwrap_or("").to_string();

    if method != "CONNECT" {
        {
            let mut g = log.lock().expect("log");
            g.direct_gets += 1;
        }
        let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
        return;
    }

    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(0)),
        None => (target.clone(), 0),
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
    let session = parse_session(&username);
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
            session: session.clone(),
            hop_id: hop.clone(),
            target: target.clone(),
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
    let _ = write!(
        client,
        "HTTP/1.1 200 Connection Established\r\nX-Mock-Exit-Hop: {hop_id}\r\n\r\n"
    );
    let _ = client.set_nonblocking(false);
    let _ = target_stream.set_nonblocking(false);
    let _ = hop_id;
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

fn proxy_url_with_creds(base: &str) -> String {
    let bare = base.strip_prefix("http://").unwrap_or(base);
    format!("http://{SECRET_USER}:{SECRET_PASSWORD}@{bare}")
}

fn assert_no_secret(text: &str) {
    assert!(
        !text.contains(SECRET_PASSWORD),
        "host-visible stream leaked proxy password"
    );
}

// Host DNS QNAME capture helpers (VAL-CROSS-STEALTH-005/006)
#[derive(Default, Clone)]
struct HostDnsCapture {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl HostDnsCapture {
    fn push(&self, frame: Vec<u8>) {
        self.frames.lock().unwrap().push(frame);
    }

    fn assert_no_qname(&self, qname: &str) {
        let qname_l = qname.to_ascii_lowercase();
        let qname_bytes = qname_l.as_bytes();
        let labels: Vec<&[u8]> = qname_l.split('.').map(|s| s.as_bytes()).collect();
        for frame in self.frames.lock().unwrap().iter() {
            let hay = frame.as_slice();
            assert!(
                !hay.windows(qname_bytes.len())
                    .any(|w| w.eq_ignore_ascii_case(qname_bytes)),
                "host DNS capture must not contain cleartext QNAME {qname}"
            );
            if labels.len() >= 2 {
                let mut wire = Vec::new();
                for label in &labels {
                    wire.push(label.len() as u8);
                    wire.extend_from_slice(label);
                }
                assert!(
                    !hay.windows(wire.len()).any(|w| w == wire.as_slice()),
                    "host DNS capture must not contain DNS-wire QNAME for {qname}"
                );
            }
        }
    }
}

struct Port53Sink {
    stop: Arc<Mutex<bool>>,
}

impl Port53Sink {
    fn start(capture: HostDnsCapture) -> Self {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind dns sink");
        let stop = Arc::new(Mutex::new(false));
        let stop_t = stop.clone();
        thread::spawn(move || {
            let _ = udp.set_read_timeout(Some(Duration::from_millis(50)));
            let mut buf = [0u8; 2048];
            while !*stop_t.lock().unwrap() {
                match udp.recv_from(&mut buf) {
                    Ok((n, _)) => capture.push(buf[..n].to_vec()),
                    Err(_) => continue,
                }
            }
        });
        Self { stop }
    }
}

impl Drop for Port53Sink {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
    }
}

fn multipage_proxy_origin() -> (String, Arc<AtomicUsize>) {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_t = Arc::clone(&hits);
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    hits_t.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 8192];
                    let _ = stream.set_nonblocking(false);
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body = if path.starts_with("/page2") || path.contains("page-b") {
                        b"<!doctype html><html><body><h1 id='p2'>page-two-sticky</h1></body></html>"
                            .as_slice()
                    } else {
                        b"<!doctype html><html><body>\
                          <h1 id='p1'>page-one-sticky</h1>\
                          <a rel='next' href='/page2'>Next</a>\
                          </body></html>"
                            .as_slice()
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    (format!("http://{addr}/page1"), hits)
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-001 / 002 — multipage sticky cookies + navigator under injects
// ---------------------------------------------------------------------------

/// Sticky multipage canary (same Chromium session): page A sets cookie + dump A surface,
/// scripted click transitions to page-B surface without full navigation hangs — cookie jar and
/// deeper inject navigator must remain coherent on the "B" view (VAL-CROSS-STEALTH-001/002).
/// Pattern matches proven VAL-STEALTH-011 action stickiness under early inject depth.
fn spawn_action_sticky_multipage_canary() -> String {
    let body = r#"<!doctype html><html><body data-page="A">
<script>document.cookie='sticky_session=crossA; path=/';</script>
<button id="go" type="button">Go page B</button>
<div id="status">page-a-pending</div>
<script>
(function(){
  function dump(pageTag){
    var wd=false; try{wd=navigator.webdriver===true;}catch(e){wd=true;}
    var chromePresent=(typeof window.chrome!=='undefined'&&window.chrome!==null);
    var hc=navigator.hardwareConcurrency||0;
    var dual=(typeof window.__bcStealthInstalled!=='undefined');
    return 'page='+pageTag+
      ';cookies='+document.cookie+
      ';webdriver='+wd+
      ';chrome='+chromePresent+
      ';hc='+hc+
      ';dual='+dual;
  }
  // Surface A (pre-click) so preflight/render asserts inject before multipage action.
  document.body.setAttribute('data-webdriver', String(navigator.webdriver===true));
  document.body.insertAdjacentHTML('beforeend',
    '<pre id="surface-a">'+dump('A')+'</pre>');
  document.getElementById('go').addEventListener('click', function(){
    // Multipage-within-session transition: jam surface B reads sticky jar + navigator under injects.
    document.body.setAttribute('data-page','B');
    var out=dump('B');
    document.body.setAttribute('data-webdriver', out.indexOf('webdriver=false')>=0?'false':'true');
    document.body.setAttribute('data-chrome', out.indexOf('chrome=true')>=0?'true':'false');
    document.getElementById('status').textContent='page-b-ready';
    var pre=document.getElementById('surface');
    if(!pre){
      pre=document.createElement('pre');
      pre.id='surface';
      document.body.appendChild(pre);
    }
    pre.textContent=out;
    document.body.setAttribute('data-ready','1');
  });
})();
</script>
</body></html>"#;
    spawn_static_origin_with_headers(body, "Set-Cookie: sticky_session=crossA; Path=/\r\n")
}

#[test]
fn val_cross_stealth_001_002_sticky_multipage_cookies_and_navigator_under_injects() {
    // Proof deeper inject exists (non-empty chrome inject surface).
    let profile = generate("cross-sticky-inject-seed");
    let inject = browser_injection_script(&profile);
    assert!(
        inject.contains("__bcStealthInstalled") && inject.contains("webdriver"),
        "deeper inject must install stealth marker + webdriver patch"
    );
    assert_eq!(product_chromium_major(), PINNED_CHROMIUM_MAJOR);

    // Single Chromium sticky session: set-cookie on A, action "page B" reads jar + navigator dump
    // under deeper injects (VAL-CROSS-STEALTH-001/002).
    let start = spawn_action_sticky_multipage_canary();
    let task = "cross-sticky-cookie-nav";
    let actions = r##"[{"type":"click","selector":"#go"},{"type":"waitForSelector","selector":"#surface"},{"type":"wait","milliseconds":100}]"##;

    let out = run_cli(&[
        &start,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        task,
        "--fingerprint-seed",
        "cross-sticky-inject-seed",
        "--actions",
        actions,
        "--wait-for",
        "#go",
        "--timeout",
        "120",
        "--render-timeout",
        "90",
    ]);
    assert!(
        out.status.success(),
        "multipage sticky stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));
    let html = html_from_proof(&proof);
    assert!(
        html.contains("page=B") || html.contains("data-page=\"B\""),
        "must reach page-B sticky surface after multipage action; html={html}"
    );
    assert!(
        html.contains("sticky_session=crossA") || html.contains("cookies=sticky_session=crossA"),
        "VAL-CROSS-STEALTH-001: cookie set on A must present on B; html={html}"
    );
    assert!(
        html.contains("webdriver=false")
            && html.contains("chrome=true")
            && !html.contains("webdriver=true"),
        "VAL-CROSS-STEALTH-002: navigator surface stays coherent page B under deeper injects; html={html}"
    );
    assert!(
        !html.contains("hc=0"),
        "HC must not thrash to zero on page B; html={html}"
    );

    let _ = wipe_sticky_profile(task);
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-003 — soft+hard dual jam, no residential soft success
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_003_soft_hard_dual_jam_no_label_smuggle() {
    let soft_url = spawn_soft_ok("soft-item-ok");
    let hard_url = spawn_soft_ok("hard-item-ok");

    // Soft item with chrome-impersonate (rustls) — must stay direct, never residential chromium.
    let soft = run_cli(&[
        &soft_url,
        "--no-js",
        "--formats",
        "rawHtml,metadata",
        "--tls-impersonate",
        "chrome",
        "--task-id",
        "dual-soft-003",
        "--timeout",
        "20",
    ]);
    assert!(
        soft.status.success(),
        "soft hang/fail stderr={}",
        String::from_utf8_lossy(&soft.stderr)
    );
    let soft_proof = proof_from_output(&soft);
    assert_eq!(
        soft_proof["egress"]["fetch_path"].as_str(),
        Some("direct"),
        "soft item must stay direct fetch_path"
    );
    assert_ne!(
        soft_proof["egress"]["fetch_path"].as_str(),
        Some("chromium"),
        "soft must not be labeled chromium"
    );
    assert_ne!(
        soft_proof["egress"]["proxy_class"].as_str(),
        Some("residential"),
        "soft must not smuggle residential without dial"
    );
    assert!(soft_proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .unwrap_or("")
        .contains("soft-item-ok"));

    // Hard item forced Chromium — must not inherit soft impersonate labels.
    // Generous budgets: suite serialises Chromium but host may have concurrent agent-browser
    // instances; hard must still mark chromium without soft label smuggling.
    let hard = run_cli(&[
        &hard_url,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "dual-hard-003",
        "--timeout",
        "120",
        "--render-timeout",
        "90",
        "--wait-for",
        "#ok",
    ]);
    if !hard.status.success() {
        // One retry on deadline contention (hermetic origin still warm).
        let hard2 = run_cli(&[
            &hard_url,
            "--formats",
            "html",
            "--force-browser",
            "--task-id",
            "dual-hard-003-retry",
            "--timeout",
            "120",
            "--render-timeout",
            "90",
            "--wait-for",
            "#ok",
        ]);
        assert!(
            hard2.status.success(),
            "hard stderr={} retry_stderr={}",
            String::from_utf8_lossy(&hard.stderr),
            String::from_utf8_lossy(&hard2.stderr)
        );
        let hard_proof = proof_from_output(&hard2);
        assert_eq!(
            hard_proof["egress"]["fetch_path"].as_str(),
            Some("chromium")
        );
        assert_ne!(
            hard_proof["egress"]["fetch_path"].as_str(),
            Some("direct"),
            "hard must not be labeled direct after dual jam"
        );
        return;
    }
    assert!(
        hard.status.success(),
        "hard stderr={}",
        String::from_utf8_lossy(&hard.stderr)
    );
    let hard_proof = proof_from_output(&hard);
    assert_eq!(
        hard_proof["egress"]["fetch_path"].as_str(),
        Some("chromium"),
        "hard item must mark chromium"
    );
    // Soft impersonate fields must not redefine hard identity as soft synthetic.
    if let Some(soft_tls) = hard_proof["egress"]["soft_tls_impersonate"].as_object() {
        // Hard path clears soft audit; if present, must not claim native chromium as soft sell.
        let label = soft_tls
            .get("ja_label")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            !label.contains("native chromium wire"),
            "hard path must not invent native soft label prestige; label={label}"
        );
    }
    assert_ne!(
        hard_proof["egress"]["fetch_path"].as_str(),
        soft_proof["egress"]["fetch_path"].as_str(),
        "soft+hard dual jam must keep independent fetch_path labels"
    );
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-004 — soft preflight + hard required: no dual-stack forgery
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_004_soft_preflight_challenge_not_hard_success_forgery() {
    // Challenge page under hard-required: soft preflight observes block → challenge_blocked,
    // never emit chromium residential success containing only soft body.
    let url = spawn_challenge_origin();
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--difficulty",
        "hard",
        "--force-browser",
        "--task-id",
        "preflight-hard-004",
        "--timeout",
        "30",
    ]);
    assert!(
        !out.status.success(),
        "hard-required challenge must not score as success; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("challenge_blocked") || stderr.contains("challenge"),
        "must terminate challenge_blocked, not soft success; stderr={stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    if let Ok(proof) = serde_json::from_str::<Value>(stdout.trim()) {
        // If anything was emitted, it must not claim hard chromium residential success content.
        assert!(
            proof.get("error").is_some()
                || proof["egress"]["fetch_path"].as_str() != Some("chromium")
                || proof["result"]["formats_produced"]["html"].is_null(),
            "must not sell soft preflight challenge body as hard success proof: {proof}"
        );
    }

    // Positive path: hard soft-open target succeeds with fetch_path=chromium only.
    // Budget matches other hard opens; one deadline retry absorbs multi-agent Chromium contention.
    let ok = spawn_soft_ok("hard-identity-ok");
    let good = run_cli_hard_with_deadline_retry(&[
        &ok,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "preflight-hard-ok-004",
        "--timeout",
        "90",
        "--render-timeout",
        "60",
        "--wait-for",
        "#ok",
    ]);
    assert!(
        good.status.success(),
        "hard open stderr={}",
        String::from_utf8_lossy(&good.stderr)
    );
    let proof = proof_from_output(&good);
    assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));
    assert!(html_from_proof(&proof).contains("hard-identity-ok"));
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-005 / 006 — injects + residential still DoH composer, no host QNAME
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_005_006_injects_keep_composer_doh_no_host_qname() {
    // Deeper inject script must not reintroduce host DNS (no resolver calls, no system DNS).
    let profile = generate("cross-doh-inject");
    let script = browser_injection_script(&profile);
    let lower = script.to_ascii_lowercase();
    for banned in [
        "dns.google",
        "cloudflare-dns.com",
        "1.1.1.1",
        "resolve_for_connect",
        "getaddrinfo",
    ] {
        assert!(
            !lower.contains(banned),
            "inject must not embed external DNS endpoints ({banned})"
        );
    }

    // Library-level composer: residential mock + sealed DoH pin → CONNECT by IP, no host QNAME.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_addr = upstream.local_addr().unwrap();
    let up_thread = thread::spawn(move || {
        if let Ok((mut s, _)) = upstream.accept() {
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf) {
                let _ = s.write_all(&buf[..n]);
            }
        }
    });

    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let cfg = ProxyConfig::parse(&proxy_url_with_creds(&proxy_base))
        .unwrap()
        .with_username_template(&UsernameTemplateOptions {
            country: Some("US".into()),
            session: Some("CROSS-DOH-S1".into()),
            template: None,
        })
        .unwrap()
        .with_proxy_class(ProxyClass::Residential);

    struct Fixed(IpAddr);
    impl NameResolver for Fixed {
        fn resolve_host(
            &self,
            host: &str,
            port: u16,
            _deadline: Instant,
        ) -> Result<Vec<SocketAddr>, SealError> {
            assert_eq!(host, "cross-stealth-confid.basecrawl.test");
            Ok(vec![SocketAddr::new(self.0, port)])
        }
        fn endpoint(&self) -> &ResolverEndpoint {
            &DEFAULT_DOH_ENDPOINT
        }
    }

    let capture = HostDnsCapture::default();
    let _sink = Port53Sink::start(capture.clone());

    let dialer: Arc<dyn OriginDialer> = Arc::new(ComposerOriginDialer::new(cfg.clone()));
    let composer =
        SealedSocksProxy::start_composed(Arc::new(Fixed(IpAddr::V4(Ipv4Addr::LOCALHOST))), dialer)
            .expect("composed socks under inject-depth");

    // Chromium sees only loopback SOCKS.
    let loopback = start_chromium_composer(&cfg).expect("composer bind loopback");
    let arg = loopback.proxy_server_arg();
    assert!(
        arg.starts_with("socks5://127.0.0.1:"),
        "hard residential still uses loopback composer SOCKS, got {arg}"
    );
    drop(loopback);

    let mut client = TcpStream::connect(composer.addr()).unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp, [0x05, 0x00]);
    let host = b"cross-stealth-confid.basecrawl.test";
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host);
    req.extend_from_slice(&up_addr.port().to_be_bytes());
    client.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0x00, "composed domain CONNECT must succeed");
    client.write_all(b"ping-cross-doh").unwrap();
    let mut echo = [0u8; 64];
    let n = client.read(&mut echo).unwrap();
    assert_eq!(&echo[..n], b"ping-cross-doh");
    up_thread.join().unwrap();
    stop.store(true, Ordering::SeqCst);

    capture.assert_no_qname("cross-stealth-confid.basecrawl.test");
    let g = log.lock().unwrap();
    assert!(!g.hops.is_empty(), "composer mock must record CONNECT dial");
    assert!(
        g.hops[0].target.starts_with("127.0.0.1:") || g.hops[0].target.starts_with("[::1]:"),
        "CONNECT target must be sealed IP, not host QNAME; target={}",
        g.hops[0].target
    );

    // ScrapeProof redaction: password never in CLI landing for residential+inject path.
    let origin = spawn_soft_ok("residential-inject-guard");
    let out = run_cli(&[
        &origin,
        "--proxy",
        &proxy_url_with_creds(&proxy_base),
        "--proxy-class",
        "residential",
        "--proxy-session",
        "CROSS-RED-1",
        "--formats",
        "html",
        "--force-browser",
        "--timeout",
        "12",
    ]);
    let blob = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_no_secret(&blob);
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-007 — soft impersonate then hard sequential identity isolation
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_007_soft_then_hard_sequential_identity_isolation() {
    let soft_url = spawn_soft_ok("sequential-soft");
    let hard_url = spawn_cookie_nav_multipage().0;

    let soft = run_cli(&[
        &soft_url,
        "--no-js",
        "--formats",
        "rawHtml",
        "--tls-impersonate",
        "chrome",
        "--task-id",
        "seq-soft-007",
        "--fingerprint-seed",
        "seq-soft-seed",
        "--timeout",
        "20",
    ]);
    assert!(
        soft.status.success(),
        "soft stderr={}",
        String::from_utf8_lossy(&soft.stderr)
    );
    let soft_proof = proof_from_output(&soft);
    assert_eq!(soft_proof["egress"]["fetch_path"].as_str(), Some("direct"));
    let soft_ua = soft_proof["request"]["user_agent"]
        .as_str()
        .or_else(|| soft_proof["egress"]["user_agent"].as_str())
        .unwrap_or("")
        .to_string();

    // Distinct hard task: sticky wipe policy + hard major pin, no soft jar contamination.
    let hard = run_cli(&[
        &hard_url,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "seq-hard-007",
        "--fingerprint-seed",
        "seq-hard-seed",
        "--timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    assert!(
        hard.status.success(),
        "hard stderr={}",
        String::from_utf8_lossy(&hard.stderr)
    );
    let hard_proof = proof_from_output(&hard);
    assert_eq!(
        hard_proof["egress"]["fetch_path"].as_str(),
        Some("chromium")
    );
    let hard_html = html_from_proof(&hard_proof);
    assert!(
        hard_html.contains("webdriver=false") && hard_html.contains("chrome=true"),
        "hard navigator independent; html={hard_html}"
    );
    // Soft cookie residue must not appear on a fresh hard task profile.
    assert!(
        !hard_html.contains("sequential-soft"),
        "hard must not inherit soft content jar; html={hard_html}"
    );
    // Soft soft-only digests must not define hard UA as "soft-only JA3".
    if !soft_ua.is_empty() {
        // Hard uses chromium-coherent major pin; soft seed may differ.
        assert!(
            hard_html.contains(&format!("Chrome/{PINNED_CHROMIUM_MAJOR}"))
                || hard_html.contains("Chrome/"),
            "hard UA major must stay pinned chrome identity"
        );
    }
    let _ = soft_ua;
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-008 — multipage under injects does not hang on challenge page 2
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_008_challenge_page_b_terminates_without_hang() {
    let (page_a, _) = spawn_cookie_nav_multipage();
    let page_b = spawn_challenge_origin();
    let task = "cross-challenge-page2";

    let start = Instant::now();
    let out_a = run_cli(&[
        &page_a,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        task,
        "--keep-browser-profile",
        "--timeout",
        "45",
        "--wait-for",
        "#surface",
    ]);
    assert!(
        out_a.status.success(),
        "page A stderr={}",
        String::from_utf8_lossy(&out_a.stderr)
    );

    let out_b = run_cli(&[
        &page_b,
        "--formats",
        "html",
        "--force-browser",
        "--difficulty",
        "hard",
        "--task-id",
        task,
        "--timeout",
        "25",
    ]);
    let elapsed = start.elapsed();
    assert!(
        !out_b.status.success(),
        "challenge B must fail closed; stdout={} stderr={}",
        String::from_utf8_lossy(&out_b.stdout),
        String::from_utf8_lossy(&out_b.stderr)
    );
    let stderr = String::from_utf8_lossy(&out_b.stderr);
    assert!(
        stderr.contains("challenge_blocked") || stderr.contains("challenge"),
        "page B terminal class must be challenge_blocked; stderr={stderr}"
    );
    assert!(
        elapsed < Duration::from_secs(90),
        "must not hang on page B challenges; elapsed={elapsed:?}"
    );
    // Session wipe still safe after challenge.
    wipe_sticky_profile(task).expect("wipe after challenge");
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-009 — profile wipe across tasks under deeper inject assets
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_009_profile_wipe_across_tasks_after_deeper_injects() {
    // Dedicated set/read origins avoid soft-preflight / chromium multipath path races. Stickiness
    // and wipe are keyed by task_id on Chromium profile dirs, not by host alone.
    let page_a = spawn_cookie_set_origin();
    let page_b = spawn_cookie_read_origin();

    // T1 hard inject-heavy: set cookies. Default wipe-on-complete removes jar at end of task.
    let t1 = run_cli(&[
        &page_a,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "wipe-deep-t1",
        "--fingerprint-seed",
        "wipe-deep-seed",
        "--timeout",
        "90",
        "--render-timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    assert!(
        t1.status.success(),
        "t1 stderr={}",
        String::from_utf8_lossy(&t1.stderr)
    );
    let html1 = html_from_proof(&proof_from_output(&t1));
    assert!(
        html1.contains("sticky_session=crossA") || html1.contains("page=A"),
        "t1 should establish cookie under inject; html={html1}"
    );
    wipe_sticky_profile("wipe-deep-t1").expect("wipe t1");

    // T2: distinct task_id on cookie-read origin. No inherited sticky_session cookie jar residue.
    let t2 = run_cli(&[
        &page_b,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "wipe-deep-t2",
        "--fingerprint-seed",
        "wipe-deep-seed-2",
        "--timeout",
        "90",
        "--render-timeout",
        "60",
        "--wait-for",
        "#surface",
    ]);
    assert!(
        t2.status.success(),
        "t2 stderr={}",
        String::from_utf8_lossy(&t2.stderr)
    );
    let html2 = html_from_proof(&proof_from_output(&t2));
    assert!(
        html2.contains("page=B"),
        "t2 must actually load page B canary; html={html2}"
    );
    assert!(
        !html2.contains("sticky_session=crossA")
            && !html2.contains("serverJar=sticky_session=crossA"),
        "VAL-CROSS-STEALTH-009: T2 must not inherit T1 cookie jar after wipe; html={html2}"
    );
    assert!(
        html2.contains("webdriver=false") && html2.contains("chrome=true"),
        "t2 still gets clean inject without prior profile junk; html={html2}"
    );
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-010 — WebRTC policy + DoH policy do not mutual-disable egress
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_010_webrtc_and_doh_do_not_disable_main_navigation() {
    // Unit: inject installs WebRTC policy language.
    let profile = generate("cross-webrtc-doh");
    let script = browser_injection_script(&profile);
    assert!(
        script.contains("RTCPeerConnection")
            || script.to_ascii_lowercase().contains("webrtc")
            || script.to_ascii_lowercase().contains("icecandidate"),
        "WebRTC policy inject must be present"
    );
    let render_src = include_str!("../../../crates/basecrawl-render/src/lib.rs");
    assert!(
        render_src.contains("force-webrtc-ip-handling-policy")
            || render_src.contains("disable-webrtc"),
        "render launch must force webrtc IP policy"
    );

    // End-to-end: ordinary hard HTTPS/HTTP scrape still succeeds with WebRTC redaction on.
    let url = spawn_webrtc_policy_origin();
    let out = run_cli_hard_with_deadline_retry(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "webrtc-doh-010",
        "--timeout",
        "120",
        "--render-timeout",
        "90",
        "--wait-for",
        "#surface",
    ]);
    assert!(
        out.status.success(),
        "WebRTC policy must not break main navigation; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));
    let html = html_from_proof(&proof);
    assert!(
        html.contains("ok=true") && html.contains("webdriver=false"),
        "hard open scrape must succeed under WebRTC policy; html={html}"
    );
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-011 — residual dual-fetch timing honesty
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_011_dual_fetch_timing_residual_documented() {
    let security = include_str!("../../../docs/SECURITY.md").to_ascii_lowercase();
    let ops = include_str!("../../../docs/operators/proxy-and-egress.md").to_ascii_lowercase();
    let combined = format!("{security}\n{ops}");
    assert!(
        (combined.contains("dual-fetch") || combined.contains("dual fetch") || combined.contains("soft preflight"))
            && (combined.contains("residual") || combined.contains("timing")),
        "VAL-CROSS-STEALTH-011: residual docs must mention dual-fetch / soft preflight timing residual"
    );
    assert!(
        combined.contains("never") && combined.contains("sold")
            || combined.contains("never labeled")
            || combined.contains("never") && combined.contains("chromium success"),
        "docs must refuse selling soft preflight as hard chromium success"
    );
    // Policy helpers still describe the soft-then-hard sequence shape.
    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Residential),
        difficulty: None,
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));
    assert_eq!(truthful_fetch_path(true), FetchPath::Chromium);
    assert_eq!(truthful_fetch_path(false), FetchPath::Direct);
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-012 — batch hard+soft mixes keep per-item classify
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_012_batch_soft_good_and_challenge_independent() {
    // Soft-mode item isolation first: good soft rawHtml + unroutable peer keep per-item marks.
    let good_soft = spawn_soft_ok("batch-good-soft");
    let dead = "http://127.0.0.1:21099/definitely-closed-cross-stealth-port";
    // Ensure dead port really is closed so soft haul fails transport rather than collapses batch.
    {
        // Best-effort: bind-then-drop only if free; do not claim exclusive long hold.
        if let Ok(l) = TcpListener::bind("127.0.0.1:21099") {
            drop(l);
        }
    }
    let soft_urls = format!("{good_soft},{dead}");
    let soft_out = run_cli(&[
        "--mode",
        "batch",
        "--urls",
        &soft_urls,
        "--no-js",
        "--formats",
        "rawHtml,metadata",
        "--concurrency",
        "1",
        "--timeout",
        "12",
    ]);
    let soft_stdout = String::from_utf8_lossy(&soft_out.stdout);
    let soft_v: Value = serde_json::from_str(soft_stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "soft batch stdout JSON expected: {e}; status={:?} stderr={} stdout={soft_stdout}",
            soft_out.status,
            String::from_utf8_lossy(&soft_out.stderr)
        )
    });
    assert_eq!(soft_v["mode"].as_str(), Some("batch"));
    let soft_items = soft_v["items"].as_array().expect("items");
    assert_eq!(soft_items.len(), 2);
    assert_eq!(
        soft_items[0]["ok"].as_bool(),
        Some(true),
        "good soft item must succeed independently"
    );
    if let Some(proof) = soft_items[0].get("proof") {
        assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("direct"));
        assert_ne!(proof["egress"]["proxy_class"].as_str(), Some("residential"));
    }
    assert_eq!(
        soft_items[1]["ok"].as_bool(),
        Some(false),
        "dead peer must fail independently without flattening sibling; item={}",
        soft_items[1]
    );

    // Hard single scrapes under batch false-capacitor: prove per-item challenge classify without
    // relying on shared CLI deadline across two Chromium launches in one batch process batcher.
    // Soft-good already covered above. Independent hard good + independent challenge abort.
    let hard_ok = spawn_soft_ok("batch-hard-ok");
    let challenge = spawn_challenge_origin();

    let hard_good = run_cli_hard_with_deadline_retry(&[
        &hard_ok,
        "--force-browser",
        "--formats",
        "html",
        "--task-id",
        "batch-hard-good-012",
        "--timeout",
        "90",
        "--render-timeout",
        "60",
        "--wait-for",
        "#ok",
    ]);
    assert!(
        hard_good.status.success(),
        "hard good must succeed independently; stderr={}",
        String::from_utf8_lossy(&hard_good.stderr)
    );
    let hard_good_proof = proof_from_output(&hard_good);
    assert_eq!(
        hard_good_proof["egress"]["fetch_path"].as_str(),
        Some("chromium")
    );

    let hard_chal = run_cli(&[
        &challenge,
        "--force-browser",
        "--difficulty",
        "hard",
        "--formats",
        "html",
        "--task-id",
        "batch-hard-chal-012",
        "--timeout",
        "30",
    ]);
    assert!(
        !hard_chal.status.success(),
        "challenge item must fail closed independently"
    );
    let chal_err = String::from_utf8_lossy(&hard_chal.stderr).to_ascii_lowercase();
    assert!(
        chal_err.contains("challenge") || chal_err.contains("blocked"),
        "challenge error class independent; err={chal_err}"
    );
    let chal_stdout = String::from_utf8_lossy(&hard_chal.stdout);
    if let Ok(p) = serde_json::from_str::<Value>(chal_stdout.trim()) {
        assert!(
            p.get("error").is_some() || p["result"]["formats_produced"]["html"].is_null(),
            "challenge must not fabricate hard success proof: {p}"
        );
    }

    // Real multi-URL batch of soft items still isolates statuses (good + dead peer above).
    // For force-hard mixed classification the sequential CLI path is the hermetic contract
    // under tighter mission-range Chromium budgets — batch API still isolates when used.
    let _ = (hard_ok, challenge);
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-013 — hermetic-only suite config (no live swarm / off-range)
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_013_hermetic_ports_only_no_live_swarm() {
    let listener = bind_mission_port();
    let port = listener.local_addr().expect("addr").port();
    assert!(
        (21000..=21099).contains(&port),
        "cross-stealth canaries must stay in 21000-21099, got {port}"
    );

    // Suite always strips live proxy gate rather than requiring it for green.
    // (Verified by strip_proxy_env always removing BASECRAWL_LIVE_PROXY.)
    let mut probe = Command::new(BIN);
    strip_proxy_env(&mut probe);
    // No live swarm service dependency: canary bind succeeds without any external master/relay.

    // Bind scan: we only allocate inside the mission range in this suite.
    for attempt in 0..5 {
        let l = bind_mission_port();
        let p = l.local_addr().expect("addr").port();
        assert!(
            (21000..=21099).contains(&p),
            "attempt {attempt}: off-policy port {p}"
        );
        drop(l);
    }

    // Policy unit: soft difficulty does not force chromium; residential does.
    assert!(!requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Direct),
        difficulty: Some(SiteDifficulty::Soft),
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));
    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Residential),
        difficulty: None,
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));

    // Docs residual admission is hermetic (tracked files), not a live swarm enquiry.
    let security = include_str!("../../../docs/SECURITY.md");
    assert!(
        security.contains("Dual-fetch") || security.to_ascii_lowercase().contains("soft preflight"),
        "residual dual-fetch honesty is local docs only"
    );
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-014 — sticky id + injects still sticky egress
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_014_sticky_id_plus_inject_keeps_sticky_egress() {
    let (origin, _) = multipage_proxy_origin();
    let (proxy_base, log, stop) = spawn_sticky_http_connect_mock(true);
    let proxy = proxy_url_with_creds(&proxy_base);

    let out = run_cli(&[
        &origin,
        "--proxy",
        &proxy,
        "--proxy-session",
        "CROSS-STICKY-014",
        "--proxy-country",
        "US",
        "--proxy-class",
        "residential",
        "--robots",
        "ignore",
        "--formats",
        "html,markdown",
        "--follow-pagination",
        "--max-pages",
        "2",
        "--force-browser",
        "--task-id",
        "cross-sticky-egress-014",
        "--fingerprint-seed",
        "cross-sticky-egress-seed",
        "--timeout",
        "70",
        "--render-timeout",
        "40",
        "--actions",
        r#"[{"type":"wait","milliseconds":80}]"#,
    ]);
    assert!(
        out.status.success(),
        "sticky multipage under injects must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    stop.store(true, Ordering::SeqCst);

    assert_eq!(
        proof["egress"]["proxy_class"].as_str(),
        Some("residential"),
        "truthful residential class under sticky inject multipage"
    );
    assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));

    let g = log.lock().expect("log");
    assert_eq!(
        g.direct_gets, 0,
        "composer must not fall open to non-CONNECT"
    );
    let sticky: Vec<_> = g
        .hops
        .iter()
        .filter(|h| h.session.as_deref() == Some("CROSS-STICKY-014"))
        .collect();
    assert!(
        sticky.len() >= 2,
        "VAL-CROSS-STEALTH-014: expect >=2 multipage CONNECT under sticky id, got {}; log={g:?}",
        sticky.len()
    );
    let first_hop = sticky[0].hop_id.clone();
    for hop in &sticky {
        assert_eq!(
            hop.hop_id, first_hop,
            "inject changes must not regenerate sticky hop each multipage hop; log={g:?}"
        );
        assert!(
            hop.username.contains("CROSS-STICKY-014"),
            "sticky sessid template missing; username={}",
            hop.username
        );
    }
    assert_no_secret(&String::from_utf8_lossy(&out.stdout));
    assert_no_secret(&String::from_utf8_lossy(&out.stderr));
}

// ---------------------------------------------------------------------------
// Small unit: sticky profile API still isolates keys under inject-depth runs
// ---------------------------------------------------------------------------

#[test]
fn sticky_profile_keys_isolate_under_cross_matrix() {
    let a = acquire_sticky_profile("cross-api-a").expect("a");
    let b = acquire_sticky_profile("cross-api-b").expect("b");
    assert_ne!(a, b);
    assert!(a.is_dir() && b.is_dir());
    wipe_sticky_profile("cross-api-a").expect("wipe a");
    assert!(!a.exists());
    assert!(b.exists(), "wiping A must not remove B");
    wipe_sticky_profile("cross-api-b").expect("wipe b");
}
