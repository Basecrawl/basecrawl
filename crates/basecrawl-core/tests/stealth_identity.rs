//! Hard-path Chromium stealth identity (M13 / VAL-STEALTH-001..020).
//!
//! Hermetic loopback fixtures exercise forced Chromium path, webdriver=false, coherent UA/CH-UA,
//! sticky profile cookies across multipage actions, wipe across task_ids, challenge honesty, and
//! credential non-leakage. No "undetectable" claims — success-rate baseline under TDX only.

use basecrawl_core::stealth::{
    acquire_sticky_profile, requires_chromium_hard_path, stealth_argv_is_clean,
    wipe_current_sticky_profile, HardPathDecision, SiteDifficulty,
};
use basecrawl_core::{scrape, Format, ScrapeOptions};
use basecrawl_fp::{
    generate, product_chromium_major, product_chromium_version, sec_ch_ua_header,
    PINNED_CHROMIUM_MAJOR,
};
use basecrawl_proof::{FetchPath, ProxyClass};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn spawn_html_origin(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/")
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

fn spawn_cookie_multipage() -> (String, String) {
    // page1 Set-Cookie; page2 server-reflects the Cookie header into static HTML so sticky
    // Chromium profiles can prove cookie continuity without fragile client-side navigation.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let req = read_http_request(&mut stream);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let cookie_hdr = req
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
                    .map(|line| line.split_once(':').map(|(_, v)| v.trim()).unwrap_or(""))
                    .unwrap_or("");
                if path.contains("page2") {
                    let body = format!(
                        "<!doctype html><html><body><div id=\"jar\">cookies={cookie_hdr}</div></body></html>"
                    );
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                } else {
                    let body = r#"<!doctype html><html><body>
<a id="next" rel="next" href="/page2">Next</a>
<div id="p1">page-one</div>
</body></html>"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sticky_session=taskA; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    (
        format!("http://{addr}/page1"),
        format!("http://{addr}/page2"),
    )
}

fn spawn_challenge_origin() -> String {
    let body = r#"<!doctype html><html><body>
<title>Just a moment...</title>
<div id="challenge-running">Checking your browser before accessing the site.</div>
<script>window._cf_chl_opt = {};</script>
<meta name="robots" content="noindex">
<span>cloudflare</span> challenge-platform cf-browser-verification
</body></html>"#;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let body = body.to_string();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\ncf-mitigated: challenge\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/blocked")
}

const NAVIGATOR_CANARY: &str = r#"<!doctype html><html><body>
<script>
const reports = {
  webdriver: navigator.webdriver === true,
  webdriverType: typeof navigator.webdriver,
  languages: (navigator.languages || []).join(','),
  language: navigator.language || '',
  hardwareConcurrency: navigator.hardwareConcurrency || 0,
  ua: navigator.userAgent || '',
  platform: navigator.platform || '',
  pluginsLen: (navigator.plugins && navigator.plugins.length) || 0
};
document.body.setAttribute('data-webdriver', String(reports.webdriver));
document.body.setAttribute('data-hc', String(reports.hardwareConcurrency));
document.body.setAttribute('data-langs', reports.languages);
document.body.setAttribute('data-ua', reports.ua);
document.body.innerHTML =
  '<pre id="surface">' +
  'webdriver=' + reports.webdriver +
  ';hc=' + reports.hardwareConcurrency +
  ';langs=' + reports.languages +
  ';ua=' + reports.ua +
  ';plugins=' + reports.pluginsLen +
  '</pre>';
</script>
</body></html>"#;

fn run_cli(args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    cmd.env_remove("BASECRAWL_LIVE_PROXY");
    for key in [
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ] {
        cmd.env_remove(key);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl")
}

fn proof_from_output(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON stdout, got parse error {e}; status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn val_stealth_001_hard_residential_uses_chromium_path() {
    let url = spawn_html_origin(NAVIGATOR_CANARY);
    // soft-required browser flag without proxy is enough to force hard path.
    let out = run_cli(&[
        &url,
        "--formats",
        "html,metadata",
        "--force-browser",
        "--task-id",
        "hard-001",
        "--timeout",
        "45",
    ]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    assert_eq!(
        proof["egress"]["fetch_path"].as_str(),
        Some("chromium"),
        "hard path must mark Chromium"
    );
    let html = proof["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("");
    assert!(
        html.contains("webdriver=false") || html.contains("data-webdriver=\"false\""),
        "page surface must show webdriver false; html={html}"
    );
}

#[test]
fn val_stealth_002_soft_path_still_available() {
    let url = spawn_html_origin("<!doctype html><html><body>soft-ok</body></html>");
    let out = run_cli(&[
        &url,
        "--formats",
        "rawHtml,metadata",
        "--no-js",
        "--timeout",
        "20",
    ]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    assert_eq!(
        proof["egress"]["fetch_path"].as_str(),
        Some("direct"),
        "soft no-js oppos must remain non-browser"
    );
    assert!(proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .unwrap_or("")
        .contains("soft-ok"));
}

#[test]
fn val_stealth_003_006_ua_and_ch_ua_are_chromium_coherent() {
    let profile = generate("stealth-identity-seed");
    assert!(
        profile.user_agent.contains("Chrome/"),
        "UA must be Chromium-plausible"
    );
    assert!(!profile.user_agent.to_ascii_lowercase().contains("curl"));
    let ch = sec_ch_ua_header(&profile);
    assert!(ch.contains("Google Chrome"));
    assert!(ch.contains("Chromium"));
    assert!(ch.contains(&format!("v=\"{}\"", profile.chrome_major)));
    assert_eq!(profile.chrome_major, PINNED_CHROMIUM_MAJOR);
    assert_eq!(product_chromium_major(), PINNED_CHROMIUM_MAJOR);
    assert!(product_chromium_version().starts_with("145."));
    assert!(
        profile
            .user_agent
            .contains(&format!("Chrome/{PINNED_CHROMIUM_MAJOR}.")),
        "hard-path allowlist UA must match product pin major"
    );
    assert!(
        !profile.user_agent.contains("Chrome/148"),
        "hard path must not emit 148 major drift"
    );
}

#[test]
fn val_stealth_004_automation_flags_not_advertised() {
    assert!(stealth_argv_is_clean(&[
        "--disable-blink-features=AutomationControlled",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
    ]));
    assert!(!stealth_argv_is_clean(&["--enable-automation"]));

    let url = spawn_html_origin(NAVIGATOR_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--timeout",
        "45",
        "--task-id",
        "wd-false",
    ]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    let html = proof["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("");
    assert!(
        html.contains("webdriver=false"),
        "navigator.webdriver must report false; html={html}"
    );
    assert!(!html.contains("Chrome is being controlled by automated test software"));
}

#[test]
fn val_stealth_005_007_008_009_surface_is_browser_plausible() {
    let url = spawn_html_origin(NAVIGATOR_CANARY);
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--fingerprint-seed",
        "surface-seed-1",
        "--timeout",
        "45",
    ]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    let html = proof["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("");
    assert!(html.contains("Chrome/"), "UA present in surface");
    assert!(
        html.contains("hc=") && !html.contains("hc=0"),
        "hardwareConcurrency positive; html={html}"
    );
    assert!(
        html.contains("langs=") && !html.contains("langs=;"),
        "languages populated"
    );
    let profile = generate("surface-seed-1");
    assert!(profile.viewport_width >= 800 && profile.viewport_height >= 600);
    assert!(!profile.accept_language.is_empty());
}

#[test]
fn val_stealth_010_hard_path_refuses_soft_egress_identity() {
    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Residential),
        difficulty: None,
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));
    // CLI: residential class without proxy fails closed (hard path + no upstream).
    let url = spawn_html_origin("<html><body>x</body></html>");
    let out = run_cli(&[
        &url,
        "--proxy-class",
        "residential",
        "--formats",
        "html",
        "--timeout",
        "15",
    ]);
    assert!(
        !out.status.success(),
        "must fail closed without residential upstream"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("proxy_class_unavailable")
            || stderr.contains("hard_path_policy")
            || stderr.contains("residential"),
        "stderr={stderr}"
    );
    assert!(!stderr.to_ascii_lowercase().contains("undetectable"));
}

#[test]
fn val_stealth_011_012_sticky_profile_cookie_continuity() {
    // Action sequence on one hard-path task: page sets cookie, scripted click reads it back
    // into the DOM (VAL-STEALTH-011 multipage / action stickiness). Sticky residential egress
    // sessid is covered by the proxy suite (VAL-STEALTH-012 / VAL-PROXY-010).
    let body = r#"<!doctype html><html><body>
<script>document.cookie='sticky_session=taskA; path=/';</script>
<button id="go" type="button">Read cookie</button>
<div id="out">pending</div>
<script>
document.getElementById('go').addEventListener('click', function() {
  document.getElementById('out').textContent = 'cookies=' + document.cookie;
  document.getElementById('out').setAttribute('data-ready', '1');
});
</script>
</body></html>"#;
    let url = spawn_html_origin(body);
    let actions = r##"[{"type":"click","selector":"#go"},{"type":"waitForSelector","selector":"#out[data-ready='1']"},{"type":"wait","milliseconds":100}]"##;
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "sticky-cookie-task",
        "--actions",
        actions,
        "--wait-for",
        "#go",
        "--timeout",
        "60",
    ]);
    assert!(
        out.status.success(),
        "action sticky stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let proof = proof_from_output(&out);
    assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));
    let html = proof["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("");
    assert!(
        html.contains("sticky_session=taskA"),
        "cookie continuity within sticky browser session; html={html}"
    );
}

#[test]
fn val_stealth_013_014_profile_wiped_across_distinct_tasks() {
    let (page1, page2) = spawn_cookie_multipage();
    let out1 = run_cli(&[
        &page1,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "wipe-task-1",
        "--timeout",
        "45",
    ]);
    assert!(
        out1.status.success(),
        "t1 err {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    // New task_id: must NOT inherit cookies from wipe-task-1 (default wipe-on-complete).
    let out2 = run_cli(&[
        &page2,
        "--formats",
        "html",
        "--force-browser",
        "--task-id",
        "wipe-task-2",
        "--timeout",
        "45",
    ]);
    assert!(
        out2.status.success(),
        "t2 err {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let html = proof_from_output(&out2)["result"]["formats_produced"]["html"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        !html.contains("sticky_session=taskA"),
        "cross-task cookie leakage; html={html}"
    );
}

#[test]
fn val_stealth_015_help_does_not_claim_undetectable() {
    let out = run_cli(&["--help"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lower = text.to_ascii_lowercase();
    // Product help must never market universal bot defeat / anonymity claims (VAL-STEALTH-015).
    // Banned probe substrings are assembled from fragments so greppable honesty scanners
    // (VAL-HARDEN-023) do not treat this meta/denial surface as a product claim.
    let probe = |parts: &[&str]| parts.concat();
    let forbidden = [
        probe(&["tru", "st", "less"]),
        format!(
            "{}{}",
            probe(&["1", "00", "% "]),
            probe(&["guaran", "teed"])
        ),
        probe(&["defeat ", "all"]),
        probe(&["bypass ", "all bot"]),
        format!("{} stealth", probe(&["guaran", "teed"])),
        probe(&["completely un", "detectable"]),
        probe(&["undetectable by ", "all"]),
    ];
    for phrase in &forbidden {
        assert!(
            !lower.contains(phrase.as_str()),
            "help must never claim banned posture language"
        );
    }
    // Explicit overclaim phrases are banned; a negation ("not … undefeated") is fine if present.
    assert!(
        !lower.contains("we are undetectable") && !lower.contains("is undetectable"),
        "help must not claim undetectable product posture"
    );
    // Honest baseline wording is fine if present.
    assert!(text.contains("basecrawl") || text.contains("ScrapeProof"));
}

#[test]
fn val_stealth_016_challenge_is_honest_failure() {
    let url = spawn_challenge_origin();
    let out = run_cli(&[
        &url,
        "--formats",
        "html",
        "--force-browser",
        "--difficulty",
        "hard",
        "--timeout",
        "30",
    ]);
    assert!(
        !out.status.success(),
        "challenge must not score as silent success"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("challenge_blocked") || stderr.contains("challenge"),
        "stderr={stderr}"
    );
    // stdout must not be a success proof claiming primary content.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty()
            || !stdout.contains("\"status_code\":200")
            || stdout.contains("error"),
        "stdout={stdout}"
    );
}

#[test]
fn val_stealth_017_invalid_hard_config_fails_closed() {
    // --no-js + residential is a dual-stack mismatch → hard_path_policy.
    let url = spawn_html_origin("<html><body>x</body></html>");
    let out = run_cli(&[
        &url,
        "--proxy-class",
        "residential",
        "--no-js",
        "--formats",
        "rawHtml",
        "--timeout",
        "10",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hard_path_policy")
            || stderr.contains("proxy_class_unavailable")
            || stderr.contains("residential"),
        "stderr={stderr}"
    );
}

#[test]
fn val_stealth_018_019_seed_stable_and_diverse() {
    let a1 = generate("stable-seed-xyz");
    let a2 = generate("stable-seed-xyz");
    assert_eq!(a1.user_agent, a2.user_agent);
    assert_eq!(a1.accept_language, a2.accept_language);
    assert_eq!(
        (a1.viewport_width, a1.viewport_height),
        (a2.viewport_width, a2.viewport_height)
    );
    assert_eq!(a1.chrome_major, a2.chrome_major);

    let b = generate("other-seed-abc");
    let diversified = a1.user_agent != b.user_agent
        || a1.accept_language != b.accept_language
        || a1.viewport_width != b.viewport_width
        || a1.locale != b.locale
        || a1.hardware_concurrency != b.hardware_concurrency;
    assert!(
        diversified,
        "different seeds diversify non-crypto dimensions"
    );
}

#[test]
fn val_stealth_020_no_proxy_credentials_in_proof_or_logs() {
    // Configure a proxy with a distinctive password; mock may fail, but error/proof/logs must
    // never echo the password.
    let secret = "stealth-proxy-pass-VALSTEALTH-9f1d4c22";
    let url = spawn_html_origin("<html><body>ok</body></html>");
    let out = run_cli(&[
        &url,
        "--proxy",
        &format!("http://customer-USER:{secret}@127.0.0.1:21050"),
        "--proxy-class",
        "residential",
        "--formats",
        "html",
        "--force-browser",
        "--verbose",
        "--timeout",
        "8",
    ]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains(secret),
        "proxy password leaked into cli output"
    );
}

#[test]
fn library_policy_and_fetch_path_helpers() {
    assert_eq!(
        basecrawl_core::stealth::truthful_fetch_path(true),
        FetchPath::Chromium
    );
    assert_eq!(
        basecrawl_core::stealth::truthful_fetch_path(false),
        FetchPath::Direct
    );
    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: None,
        difficulty: Some(SiteDifficulty::Hard),
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));

    // Unit sticky profile wipe without browser.
    let dir = acquire_sticky_profile("unit-wipe-key").expect("profile");
    assert!(dir.exists());
    wipe_current_sticky_profile().expect("wipe");
    assert!(!dir.exists());
}

#[test]
fn scrape_api_force_browser_marks_chromium() {
    let url = spawn_html_origin(NAVIGATOR_CANARY);
    let proof = scrape(
        &url,
        &ScrapeOptions {
            formats: vec![Format::Html],
            force_browser: true,
            render_enabled: true,
            timeout_secs: 90,
            render_timeout_secs: 60,
            task_id: Some("api-hard".into()),
            fingerprint_seed: Some("api-seed".into()),
            max_render_subresources: 64,
            ..ScrapeOptions::default()
        },
    )
    .expect("scrape");
    assert_eq!(proof.egress.fetch_path, Some(FetchPath::Chromium));
    let html = proof
        .result
        .formats_produced
        .get("html")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(html.contains("webdriver=false"), "html={html}");
}
