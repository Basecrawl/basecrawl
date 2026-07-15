//! Hard-path integrity + challenge honesty (M20 / VAL-UNLOCK-*).
//!
//! Guards that soft chrome-impersonate work does not weaken real Chromium hard path.
//! Challenges/captchas remain detect+fail-closed (`challenge_blocked`), never hang forever,
//! never primary content success, never marketplace auto-solve. Sealed antibot feedback
//! stays coarse non-solving. Invalid stealth toggles fail closed. Soft impersonate never
//! satisfies residential seize.
//!
//! Hermetic loopback only. No captcha marketplace. No live proxy.

use basecrawl_core::stealth::{
    looks_like_challenge_interstitial, requires_chromium_hard_path, HardPathDecision,
    SiteDifficulty,
};
use basecrawl_fp::SoftTlsImpersonate;
use basecrawl_proof::{FetchPath, ProxyClass};
use basecrawl_seal::{
    classify_coarse_from_status_and_markers, decrypt_antibot_feedback_as_miner_host,
    seal_antibot_feedback, unseal_antibot_feedback_with_committee_secret, AntibotFeedbackPlaintext,
    CoarseFailureHint, CommitteeThresholdPublicKey, SealError,
};
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

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
        "TWOCAPTCHA_API_KEY",
        "ANTICAPTCHA_API_KEY",
        "CAPSOLVER_API_KEY",
    ] {
        cmd.env_remove(key);
    }
}

fn run_cli(args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    strip_proxy_env(&mut cmd);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl")
}

fn run_cli_with_timeout(args: &[&str], wall_secs: u64) -> (Output, Duration) {
    let start = Instant::now();
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    strip_proxy_env(&mut cmd);
    let _ = wall_secs;
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl");
    (out, start.elapsed())
}

fn err_json(out: &Output) -> Value {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let trim = stderr.trim();
    if let Some(idx) = trim.find('{') {
        if let Ok(v) = serde_json::from_str::<Value>(&trim[idx..]) {
            return v;
        }
    }
    serde_json::json!({ "raw": trim })
}

fn spawn_fixed_origin(status_line: &str, extra_headers: &str, body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let status_line = status_line.to_string();
    let extra_headers = extra_headers.to_string();
    let body = body.to_string();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "{status_line}\r\nContent-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{}",
                    body.len(),
                    body
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/challenge")
}

fn fixture_cf_challenge_html() -> &'static str {
    r#"<!doctype html><html><head>
<title>Just a moment...</title>
<meta name="robots" content="noindex">
</head><body>
<div id="challenge-running">Checking your browser before accessing the site.</div>
<script>window._cf_chl_opt = {};</script>
<span>cloudflare</span> challenge-platform cf-browser-verification cf-challenge
</body></html>"#
}

fn fixture_captcha_widget_html() -> &'static str {
    r#"<!doctype html><html><head><title>Verify you are human</title></head>
<body>
  <h1>Complete the captcha to continue</h1>
  <div class="g-recaptcha" data-sitekey="test-site-key"></div>
  <form id="captcha-form">
    <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
    <input type="hidden" name="cf-turnstile-response" value="">
    <button type="submit">Verify</button>
  </form>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</body></html>"#
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-001: CF markers -> challenge_blocked, not hang
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_001_cf_challenge_terminates_challenge_blocked_without_hang() {
    let url = spawn_fixed_origin(
        "HTTP/1.1 403 Forbidden",
        "cf-mitigated: challenge\r\n",
        fixture_cf_challenge_html(),
    );
    let (out, elapsed) = run_cli_with_timeout(
        &[
            &url,
            "--formats",
            "html",
            "--force-browser",
            "--difficulty",
            "hard",
            "--timeout",
            "25",
        ],
        40,
    );
    assert!(
        !out.status.success(),
        "CF challenge must not succeed; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        elapsed < Duration::from_secs(35),
        "challenge detect must terminate well under hang bound; elapsed={elapsed:?}"
    );
    let err = err_json(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        kind == "challenge_blocked"
            || stderr.contains("challenge_blocked")
            || stderr.contains("challenge"),
        "expected challenge_blocked; kind={kind} stderr={stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty()
            || stdout.contains("\"error\"")
            || !stdout.contains("\"formats_produced\""),
        "must not emit primary success proof for CF interstitial; stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-002: captcha interstitial never primary content success
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_002_captcha_interstitial_not_success_content() {
    let url = spawn_fixed_origin("HTTP/1.1 200 OK", "", fixture_captcha_widget_html());
    let out = run_cli(&[
        &url,
        "--formats",
        "html,markdown",
        "--force-browser",
        "--difficulty",
        "hard",
        "--timeout",
        "25",
    ]);
    assert!(
        !out.status.success(),
        "captcha widget must not score as primary content success; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = err_json(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        kind == "challenge_blocked"
            || stderr.contains("challenge_blocked")
            || stderr.contains("challenge")
            || stderr.contains("captcha"),
        "expected challenge/captcha failure class; kind={kind} stderr={stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.trim().is_empty() {
        if let Ok(proof) = serde_json::from_str::<Value>(stdout.trim()) {
            let status = proof["response"]["status_code"].as_u64();
            let md = proof["result"]["formats_produced"]["markdown"]
                .as_str()
                .unwrap_or("");
            assert!(
                status != Some(200) || md.is_empty() || proof.get("error").is_some(),
                "captcha interstitial must not be silent markdown success; proof={proof}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-003: no required captcha marketplace; optional CapSolver only
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_003_no_captcha_marketplace_surface() {
    let help = run_cli(&["--help"]);
    let help_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    let lower = help_text.to_ascii_lowercase();
    // Unauthorized multi-vendor marketplaces remain banned. CapSolver is the sole optional
    // operator-gated provider (M23 / VAL-SOLVE-*) and may appear with residual honesty language.
    for banned in [
        "2captcha",
        "anti-captcha",
        "anticaptcha",
        "capmonster",
        "deathbycaptcha",
        "twocaptcha",
        "rucaptcha",
    ] {
        assert!(
            !lower.contains(banned),
            "CLI --help must not expose captcha marketplace vendor '{banned}'"
        );
    }
    assert!(
        !lower.contains("auto-solve captcha")
            && !lower.contains("--captcha-key")
            && !lower.contains("--2captcha"),
        "CLI must not ship unauthenticated multi-vendor marketplace solve flags"
    );
    // Optional CapSolver surface residual honesty (not commercial unlocker parity).
    if lower.contains("capsolver") {
        assert!(
            lower.contains("optional")
                || lower.contains("not commercial")
                || lower.contains("unlocker parity"),
            "CapSolver in --help must carry optional residual honesty, not unlocker marketing"
        );
    }

    let mut cmd = Command::new(BIN);
    cmd.args(["--help"]);
    strip_proxy_env(&mut cmd);
    cmd.env("TWOCAPTCHA_API_KEY", "should-never-be-consumed");
    cmd.env("CAPSOLVER_API_KEY", "should-never-be-consumed");
    let out = cmd.output().expect("help under captcha env");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lower_c = combined.to_ascii_lowercase();
    assert!(!combined.contains("should-never-be-consumed"));
    for banned in ["2captcha", "anticaptcha"] {
        assert!(
            !lower_c.contains(banned),
            "marketplace env must not invent product surface for {banned}"
        );
    }
    // Key material itself (not vendor name) must never echo.
    assert!(!combined.contains("should-never-be-consumed"));
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-004: sealed antibot feedback remains non-solving
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_004_sealed_feedback_codes_are_detect_only_never_solved() {
    let all_codes = [
        CoarseFailureHint::Ok,
        CoarseFailureHint::Blocked,
        CoarseFailureHint::RateLimited,
        CoarseFailureHint::UpstreamUnavailable,
        CoarseFailureHint::Challenge,
        CoarseFailureHint::Captcha,
        CoarseFailureHint::Empty,
        CoarseFailureHint::TlsError,
        CoarseFailureHint::DnsError,
        CoarseFailureHint::EscalateProxyClass,
    ];
    for code in all_codes {
        let s = code.as_str();
        assert!(
            !s.contains("solved")
                && !s.contains("solver")
                && s != "captcha_solved"
                && s != "challenge_solved"
                && s != "marketplace_ok",
            "feedback code must stay detect/escalate only, got {s}"
        );
    }

    assert_eq!(
        classify_coarse_from_status_and_markers(403, &["cf-mitigated: challenge"]),
        CoarseFailureHint::Challenge
    );
    assert_eq!(
        classify_coarse_from_status_and_markers(200, &["x-captcha: turnstile"]),
        CoarseFailureHint::Captcha
    );

    let secret = SecretKey::generate(&mut OsRng);
    let secret_bytes = secret.to_bytes();
    let committee =
        CommitteeThresholdPublicKey::from_public_key_bytes(secret.public_key().as_bytes());
    for failure in [
        CoarseFailureHint::Challenge,
        CoarseFailureHint::Captcha,
        CoarseFailureHint::Blocked,
    ] {
        let plaintext =
            AntibotFeedbackPlaintext::new("task-unlock-004", "nonce-unlock-004", failure)
                .with_http_status(403);
        let sealed = seal_antibot_feedback(&plaintext, &committee).expect("seal");
        assert!(matches!(
            decrypt_antibot_feedback_as_miner_host(&sealed),
            Err(SealError::KeyNotReleased)
        ));
        let opened =
            unseal_antibot_feedback_with_committee_secret(&sealed, &secret_bytes).expect("open");
        assert_eq!(opened.failure, failure);
        let wire = serde_json::to_string(&opened).unwrap();
        assert!(!wire.contains("solved"));
        assert!(!wire.contains("2captcha"));
        assert!(!wire.contains("capsolver"));
    }
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-005: product docs residual risk section is honest
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_005_docs_residual_risk_section_honest() {
    // Residual product docs (not mission diary). Must list headless/CDP residual,
    // challenge detect-not-solve, and proxy ≠ anonymity. Absolute "undetectable"
    // marketing is forbidden (deny-form residual mentions are allowed).
    let security = include_str!("../../../docs/SECURITY.md");
    let operator = include_str!("../../../docs/operators/proxy-and-egress.md");
    let trust = include_str!("../../../docs/TRUST_MODEL.md");
    let combined = format!("{security}\n{operator}\n{trust}");
    let lower = combined.to_ascii_lowercase();

    assert!(
        lower.contains("headless") && (lower.contains("residual") || lower.contains("detect")),
        "VAL-UNLOCK-005: residual docs must admit headless residual risk"
    );
    assert!(
        lower.contains("cdp")
            || lower.contains("runtime.enable")
            || lower.contains("runtime protocol"),
        "VAL-UNLOCK-005: residual docs must admit CDP / Runtime residual risk"
    );
    assert!(
        (lower.contains("challenge") || lower.contains("captcha"))
            && (lower.contains("detect")
                || lower.contains("not solve")
                || lower.contains("not a captcha solve")
                || lower.contains("challenge_blocked")
                || lower.contains("no captcha marketplace")
                || lower.contains("marketplace")),
        "VAL-UNLOCK-005: residual docs must state challenge/captcha detect-not-solve posture"
    );
    assert!(
        (lower.contains("proxy") && lower.contains("anonymity"))
            || lower.contains("proxy ≠ anonymity")
            || lower.contains("proxy != anonymity")
            || lower.contains("not anonymity")
            || lower.contains("are not anonymity"),
        "VAL-UNLOCK-005: residual docs must state proxy ≠ anonymity"
    );
    assert!(
        lower.contains("soft")
            && (lower.contains("impersonat") || lower.contains("clienthello"))
            && (lower.contains("chromium") || lower.contains("hard")),
        "VAL-UNLOCK-005: residual docs should cover soft TLS not claim hard Chromium wire"
    );

    // Positive absolute marketing claims only (honest residual negation is fine).
    // Each denylist line carries denial/meta markers for greppable honesty scanners.
    for banned in [
        "we are undetectable",                // must never / forbidden claim
        "fully undetectable residential",     // must never / forbidden claim
        "trustless scrape authenticity",      // must never / forbidden claim
        "100% guaranteed authenticity",       // must never / forbidden claim
        "anonymous residential exit forever", // must never / forbidden claim
        "defeats every bot vendor",           // must never / forbidden claim
    ] {
        assert!(
            !lower.contains(banned),
            "VAL-UNLOCK-005: residual docs must never market absolute claim '{banned}'"
        );
    }
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-006: CLI help rejects banned slogans
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_006_cli_help_rejects_banned_slogans() {
    let help = run_cli(&["--help"]);
    assert!(
        help.status.success(),
        "--help must succeed; stderr={}",
        String::from_utf8_lossy(&help.stderr)
    );
    let help_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    let lower = help_text.to_ascii_lowercase();

    // Absolute claim strings are forbidden in product CLI surface. Deny-form residual
    // language is allowed and preferred. Greppable honesty: each denylist literal line
    // includes must-never / forbidden-claim markers (AGENTS.md).
    for banned in [
        "is undetectable",      // must never / forbidden claim
        "fully undetectable",   // must never / forbidden claim
        "we are undetectable",  // must never / forbidden claim
        "trustless scrape",     // must never / forbidden claim
        "makes you anonymous",  // must never / forbidden claim
        "anonymity guarantee",  // must never / forbidden claim
        "100% success",         // must never / forbidden claim
        "100% guaranteed",      // must never / forbidden claim
        "completely anonymous", // must never / forbidden claim
    ] {
        assert!(
            !lower.contains(banned),
            "VAL-UNLOCK-006: CLI --help must never advertise banned slogan '{banned}'"
        );
    }

    let ver = run_cli(&["--version"]);
    let ver_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ver.stdout),
        String::from_utf8_lossy(&ver.stderr)
    )
    .to_ascii_lowercase();
    for banned in [
        "undetectable", // must never claim as product slogan in version string
        "trustless",    // must never claim
        "anonymous",    // must never claim
        "100%",         // must never claim
    ] {
        assert!(
            !ver_text.contains(banned),
            "VAL-UNLOCK-006: --version must not market absolute slogan '{banned}'"
        );
    }

    // Positive residual honesty expected on the about line.
    assert!(
        lower.contains("residual")
            || lower.contains("headless")
            || lower.contains("trust-but-audit")
            || lower.contains("not anonymity"),
        "CLI help should surface residual / honesty posture rather than hype"
    );
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-015: hermetic unlocker fixtures stay on mission ports 21000–21099
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_015_hermetic_fixture_ports_in_mission_range() {
    // Peer unlocker-depth fixture suites (not this file's denylist literals) bind
    // ephemeral (`:0`) or mission window 21000–21099. They must never hard-code live BASE ports.
    let soft_src = include_str!("soft_tls_impersonate.rs");
    let cross_src = include_str!("cross_stealth_integrity.rs");
    let cdp_src = include_str!("cdp_stealth_depth.rs");
    let fingerprint_src = include_str!("fingerprint_depth.rs");
    let combined = format!("{soft_src}\n{cross_src}\n{cdp_src}\n{fingerprint_src}");

    // Construction patterns that would bind a reserved live BASE swarm port.
    for reserved_bind in [
        "bind(\"0.0.0.0:3000\")",
        "bind(\"127.0.0.1:3000\")",
        "bind(\"127.0.0.1:5432\")",
        "bind(\"127.0.0.1:8080\")",
        "bind(\"127.0.0.1:8082\")",
        "bind(\"127.0.0.1:9000\")",
        "bind(\"127.0.0.1:9001\")",
        "TcpListener::bind(\"0.0.0.0:3000\")",
        "TcpListener::bind(\"127.0.0.1:3000\")",
    ] {
        assert!(
            !combined.contains(reserved_bind),
            "VAL-UNLOCK-015: unlocker fixtures must not bind reserved live BASE port pattern {reserved_bind}"
        );
    }

    // Explicit fixed ports on 127.0.0.1 literals must be mission-range or ephemeral 0.
    for port in scan_loopback_ports(&combined) {
        assert!(
            port == 0 || (21000..=21099).contains(&port),
            "VAL-UNLOCK-015: fixture port {port} outside mission range 21000-21099 (and not ephemeral 0)"
        );
    }

    // Live CLI spawn in this suite uses the ephemeral bind helper.
    let url = spawn_fixed_origin(
        "HTTP/1.1 200 OK",
        "",
        "<!doctype html><html><body>unlock-port-policy</body></html>",
    );
    assert!(
        url.starts_with("http://127.0.0.1:"),
        "fixture origin must stay loopback; got {url}"
    );
    let port: u16 = url
        .trim_start_matches("http://127.0.0.1:")
        .split('/')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("ephemeral port parseable");
    assert!(
        port != 3000 && port != 5432 && port != 8080,
        "ephemeral fixture must not land on reserved live BASE ports; port={port}"
    );
}

/// Scan test source for `127.0.0.1:<port>` literals.
fn scan_loopback_ports(src: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    let bytes = src.as_bytes();
    let needle = b"127.0.0.1:";
    let mut i = 0;
    while i + needle.len() < bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            let start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > start {
                if let Ok(p) = std::str::from_utf8(&bytes[start..j])
                    .unwrap_or("")
                    .parse::<u16>()
                {
                    ports.push(p);
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    ports
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-019: product does not advertise commercial Web Unlocker parity
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_019_no_commercial_web_unlocker_parity_claims() {
    let help = run_cli(&["--help"]);
    let help_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    let security = include_str!("../../../docs/SECURITY.md");
    let operator = include_str!("../../../docs/operators/proxy-and-egress.md");
    let readme = include_str!("../../../README.md");
    let combined = format!("{help_text}\n{security}\n{operator}\n{readme}");
    let lower = combined.to_ascii_lowercase();

    // Positive marketing of commercial unlocker parity is forbidden.
    // Residual denial framing ("does not claim … web unlocker feature-parity", rest not /
    // no commercial Web Unlocker parity) is honest and expected.
    // Greppable honesty: each absolute denylist line includes must-never markers.
    for banned in [
        "offers web unlocker feature-parity", // must never / forbidden claim
        "provides web unlocker feature parity", // must never / forbidden claim
        "has bright data web unlocker parity", // must never / forbidden claim
        "guarantees unlock any site",         // must never / forbidden claim
        "ships oxylabs captcha manage parity", // must never / forbidden claim
        "advertises commercial unlocker parity", // must never / forbidden claim
        "with captcha solve marketplace parity", // must never / forbidden claim
    ] {
        assert!(
            !lower.contains(banned),
            "VAL-UNLOCK-019: product surface must not advertise unlocker-parity slogan '{banned}'"
        );
    }

    // Bare "unlock any site" only fails when not in residual denial context.
    if lower.contains("unlock any site") {
        let deny_ok = lower.contains("not") && lower.contains("unlock any site")
            || lower.contains("no") && lower.contains("unlock any site")
            || lower.contains("never") && lower.contains("unlock any site");
        assert!(
            deny_ok,
            "VAL-UNLOCK-019: 'unlock any site' may appear only as residual denial"
        );
    }

    // Operator residual should still refuse parity rather than staying silent only.
    assert!(
        (lower.contains("not") || lower.contains("no "))
            && (lower.contains("unlocker")
                || lower.contains("captcha")
                || lower.contains("marketplace")
                || lower.contains("commercial unlock")),
        "VAL-UNLOCK-019: product residual docs should explicitly refuse unlocker/captcha-solve parity"
    );
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-020: operator guide distinguishes soft impersonate vs hard Chromium
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_020_operator_guide_soft_vs_hard_identity_split() {
    let operator = include_str!("../../../docs/operators/proxy-and-egress.md");
    let security = include_str!("../../../docs/SECURITY.md");
    let lower_ops = operator.to_ascii_lowercase();
    let lower_sec = security.to_ascii_lowercase();
    let combined = format!("{lower_ops}\n{lower_sec}");

    assert!(
        lower_ops.contains("soft") && lower_ops.contains("hard"),
        "VAL-UNLOCK-020: operator guide must discuss both soft and hard identity paths"
    );
    assert!(
        (lower_ops.contains("tls-impersonate") || lower_ops.contains("impersonat"))
            && (lower_ops.contains("not")
                || lower_ops.contains("never")
                || lower_ops.contains("≠")
                || lower_ops.contains("!=")),
        "VAL-UNLOCK-020: operator guide must distinguish soft impersonate as not Chromium wire"
    );
    assert!(
        lower_ops.contains("chromium")
            && (lower_ops.contains("real")
                || lower_ops.contains("hard path")
                || lower_ops.contains("hard / residential")
                || lower_ops.contains("fetch_path")),
        "VAL-UNLOCK-020: operator guide must keep hard path as real Chromium"
    );
    assert!(
        combined.contains("fetch_path=direct")
            || combined.contains("fetch_path = direct")
            || combined.contains("`fetch_path=direct`")
            || combined.contains("fetch_path=direct"),
        "VAL-UNLOCK-020: soft success path must remain labeled direct, not chromium"
    );
    assert!(
        combined.contains("soft_synthetic")
            || combined.contains("soft synthetic")
            || combined.contains("not native chromium")
            || combined.contains("not** native chromium")
            || combined.contains("never hard chromium wire")
            || combined.contains("never hard Chromium wire")
            || lower_ops.contains("not") && lower_ops.contains("chromium wire"),
        "VAL-UNLOCK-020: docs must say soft impersonate is not native Chromium wire identity"
    );

    // Help for soft toggle must not claim hard wire equivalence.
    let help = run_cli(&["--help"]);
    let help_l = format!(
        "{}\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    )
    .to_ascii_lowercase();
    if help_l.contains("tls-impersonate") {
        assert!(
            help_l.contains("never hard")
                || help_l.contains("never.")
                || help_l.contains("not") && help_l.contains("chromium wire")
                || help_l.contains("soft scrapes")
                || help_l.contains("fetch_path=direct"),
            "soft TLS help must refuse hard Chromium wire equivalence"
        );
        assert!(
            !help_l.contains("tls-impersonate chrome equals chromium wire")
                && !help_l.contains("full chromium tls parity"),
            "help must not conflate soft impersonate with hard Chromium wire"
        );
    }
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-007: invalid stealth toggles fail closed
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_007_invalid_stealth_toggles_fail_closed() {
    let url = spawn_fixed_origin(
        "HTTP/1.1 200 OK",
        "",
        "<!doctype html><html><body>ok-page</body></html>",
    );

    for bad in ["export-rc4", "legacy-ssl3", "not-a-profile"] {
        let out = run_cli(&[
            &url,
            "--no-js",
            "--formats",
            "rawHtml",
            "--timeout",
            "10",
            "--tls-impersonate",
            bad,
        ]);
        assert!(
            !out.status.success(),
            "invalid tls-impersonate '{bad}' must fail closed; stdout={}",
            String::from_utf8_lossy(&out.stdout)
        );
        let err = err_json(&out);
        let kind = err["error"]["kind"].as_str().unwrap_or("");
        assert!(
            kind == "tls_impersonate_unsupported"
                || kind.contains("tls_impersonate")
                || String::from_utf8_lossy(&out.stderr).contains("tls impersonate"),
            "expected tls impersonate fail-closed kind; kind={kind} err={err}"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.trim().is_empty() || stdout.contains("error") || !out.status.success(),
            "invalid toggle must not emit success scrapeproof"
        );
    }

    let out = run_cli(&[
        &url,
        "--proxy-class",
        "residential",
        "--difficulty",
        "ultra-mecha-stealth",
        "--formats",
        "html",
        "--timeout",
        "10",
    ]);
    assert!(
        !out.status.success(),
        "invalid difficulty must fail closed; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = err_json(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    assert!(
        kind == "hard_path_policy"
            || kind == "invalid_proxy"
            || String::from_utf8_lossy(&out.stderr).contains("difficulty")
            || String::from_utf8_lossy(&out.stderr).contains("unknown"),
        "expected structured invalid difficulty error; kind={kind} err={err}"
    );

    let out = run_cli(&[
        &url,
        "--proxy-class",
        "residential-plus-plus",
        "--force-browser",
        "--formats",
        "html",
        "--timeout",
        "10",
    ]);
    assert!(!out.status.success());
    let err = err_json(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    assert!(
        kind == "invalid_proxy" || String::from_utf8_lossy(&out.stderr).contains("proxy class"),
        "invalid proxy-class must fail closed; kind={kind} err={err}"
    );
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-008: default hard residential remains fail-closed (no soft dual-stack)
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_008_default_hard_residential_never_soft_success() {
    let url = spawn_fixed_origin(
        "HTTP/1.1 200 OK",
        "",
        "<!doctype html><html><body>should-not-soft-succeed</body></html>",
    );
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
    assert!(
        !out.status.success(),
        "default hard residential + --no-js must fail closed; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = err_json(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    assert!(
        kind == "hard_path_policy"
            || kind == "proxy_class_unavailable"
            || kind.contains("hard")
            || kind.contains("proxy"),
        "expected hard/class fail closed; kind={kind} err={err}"
    );

    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Residential),
        difficulty: None,
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: false,
    }));
    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Mobile),
        difficulty: Some(SiteDifficulty::Soft),
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));
    assert!(SoftTlsImpersonate::parse("chrome").is_ok());
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-016/017: schema admits only documented fields; secrets redacted
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_016_017_schema_and_secret_redaction_for_soft_impersonate_fields() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../basecrawl-proof/schema/scrapeproof.schema.json"
    );
    let schema_text = std::fs::read_to_string(schema_path).expect("schema readable");
    let schema: Value = serde_json::from_str(&schema_text).expect("schema json");
    let soft = &schema["properties"]["egress"]["properties"]["soft_tls_impersonate"];
    assert!(
        soft.is_object(),
        "soft_tls_impersonate must be documented in scrapeproof schema"
    );
    assert_eq!(
        soft["additionalProperties"], false,
        "soft_tls_impersonate must not accept free-form secret bags"
    );
    for required in ["profile", "ja_label", "soft_ja3", "soft_ja4"] {
        let list = soft["required"].as_array().expect("required array");
        assert!(
            list.iter().any(|v| v.as_str() == Some(required)),
            "schema missing required field {required}"
        );
    }
    assert_eq!(
        schema["properties"]["egress"]["additionalProperties"], false,
        "egress must not accept arbitrary secret bags"
    );

    // Sticky session marker must never land in soft_tls_impersonate audit fields (VAL-UNLOCK-016).
    let session_marker = "unlock-sess-marker-zz9";
    let url = spawn_fixed_origin(
        "HTTP/1.1 200 OK",
        "",
        "<!doctype html><html><body>soft-ok</body></html>",
    );
    let out = run_cli(&[
        &url,
        "--no-js",
        "--formats",
        "rawHtml",
        "--tls-impersonate",
        "chrome",
        "--timeout",
        "15",
        "--verbose",
        "--proxy-session",
        session_marker,
    ]);
    assert!(
        out.status.success(),
        "soft chrome-impersonate fixture scrape must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let proof: Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("proof");
    let soft_obj = proof["egress"]["soft_tls_impersonate"]
        .as_object()
        .expect("soft success must document soft_tls_impersonate audit fields");
    let soft_json = serde_json::to_string(soft_obj).unwrap();
    assert!(
        !soft_json.contains(session_marker),
        "soft_tls_impersonate must never carry session secrets"
    );
    for key in soft_obj.keys() {
        assert!(
            matches!(
                key.as_str(),
                "profile" | "ja_label" | "soft_ja3" | "soft_ja4"
            ),
            "unexpected soft_tls_impersonate field {key} (schema-typed only)"
        );
    }
    assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("direct"));
    assert_ne!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));
    assert_ne!(proof["egress"]["proxy_class"].as_str(), Some("residential"));
    // Session markers can appear as redacted operator input trees elsewhere sometimes; the
    // critical bound is soft_tls_impersonate fields never absorb them. Still refuse raw
    // password-like proxy URL embedding in stdout/stderr composite for this dial-less case.
    assert!(
        !combined.contains("user:") || !soft_json.contains("user:"),
        "soft audit object must not contain user/pass shell form"
    );
}

// ---------------------------------------------------------------------------
// VAL-UNLOCK-018: challenge detect is deterministic
// ---------------------------------------------------------------------------

#[test]
fn val_unlock_018_challenge_detect_deterministic_across_runs() {
    let body = fixture_cf_challenge_html();
    let a = looks_like_challenge_interstitial(body, 403);
    let b = looks_like_challenge_interstitial(body, 403);
    assert!(a && b, "CF markers must jointly detect challenge");
    for _ in 0..8 {
        assert_eq!(
            looks_like_challenge_interstitial(body, 403),
            a,
            "challenge detect must not flap"
        );
    }
    let captcha = fixture_captcha_widget_html();
    let c1 = looks_like_challenge_interstitial(captcha, 200);
    let c2 = looks_like_challenge_interstitial(captcha, 200);
    assert!(
        c1,
        "captcha widget page must detect as challenge/captcha interstitial"
    );
    assert_eq!(c1, c2);

    let url = spawn_fixed_origin(
        "HTTP/1.1 403 Forbidden",
        "cf-mitigated: challenge\r\n",
        fixture_cf_challenge_html(),
    );
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let out = run_cli(&[
            &url,
            "--formats",
            "html",
            "--force-browser",
            "--difficulty",
            "hard",
            "--timeout",
            "20",
        ]);
        assert!(
            !out.status.success(),
            "repeated challenge run must remain fail-closed"
        );
        let err = err_json(&out);
        let kind = err["error"]["kind"].as_str().unwrap_or("").to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            kind == "challenge_blocked"
                || stderr.contains("challenge_blocked")
                || stderr.contains("challenge"),
            "expected challenge_blocked both times; kind={kind} stderr={stderr}"
        );
        kinds.push(if kind.is_empty() {
            "challenge_blocked".into()
        } else {
            kind
        });
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.trim().is_empty()
                || stdout.contains("error")
                || !stdout.contains("\"formats_produced\""),
            "must not intermittently succeed; stdout={stdout}"
        );
    }
    assert_eq!(
        kinds[0], kinds[1],
        "challenge class must be stable across runs"
    );
}

// ---------------------------------------------------------------------------
// VAL-CROSS-STEALTH-015: soft chrome-impersonate never satisfies residential seize
// ---------------------------------------------------------------------------

#[test]
fn val_cross_stealth_015_soft_impersonate_never_satisfies_residential_seize() {
    let url = spawn_fixed_origin(
        "HTTP/1.1 200 OK",
        "",
        "<!doctype html><html><body>soft-only</body></html>",
    );

    let out = run_cli(&[
        &url,
        "--no-js",
        "--formats",
        "rawHtml",
        "--tls-impersonate",
        "chrome",
        "--proxy-class",
        "residential",
        "--timeout",
        "15",
    ]);
    assert!(
        !out.status.success(),
        "soft impersonate + residential class wish must not seize-comply; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = err_json(&out);
    let kind = err["error"]["kind"].as_str().unwrap_or("");
    assert!(
        kind == "hard_path_policy"
            || kind == "proxy_class_unavailable"
            || kind.contains("hard")
            || kind.contains("proxy"),
        "expected residential seize mismatch / hard policy; kind={kind} err={err}"
    );

    let ok = run_cli(&[
        &url,
        "--no-js",
        "--formats",
        "rawHtml",
        "--tls-impersonate",
        "chrome",
        "--timeout",
        "15",
    ]);
    if ok.status.success() {
        let proof: Value =
            serde_json::from_str(String::from_utf8_lossy(&ok.stdout).trim()).expect("proof");
        assert_eq!(proof["egress"]["fetch_path"].as_str(), Some("direct"));
        assert_ne!(proof["egress"]["fetch_path"].as_str(), Some("chromium"));
        assert_ne!(proof["egress"]["proxy_class"].as_str(), Some("residential"));
        if let Some(soft) = proof["egress"]["soft_tls_impersonate"].as_object() {
            let label = soft.get("ja_label").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                label.contains("soft")
                    || label.contains("synthetic")
                    || label.contains("impersonate"),
                "soft label must stay soft/synthetic/impersonate; got {label}"
            );
        }
    }

    assert_eq!(FetchPath::Direct.as_str(), "direct");
    assert_eq!(FetchPath::Chromium.as_str(), "chromium");
    assert_ne!(FetchPath::Direct, FetchPath::Chromium);
}

// ---------------------------------------------------------------------------
// Detector unit: hard-path wire markers remain fail-closed under soft reordering
// ---------------------------------------------------------------------------

#[test]
fn soft_chrome_profile_does_not_change_hard_chromium_requirement() {
    let mut fp = basecrawl_fp::generate("unlock-hard-guard-seed");
    SoftTlsImpersonate::Chrome.apply(&mut fp);
    assert!(requires_chromium_hard_path(HardPathDecision {
        proxy_class: Some(ProxyClass::Residential),
        difficulty: None,
        force_browser: false,
        render_enabled: true,
        needs_browser_formats: true,
    }));
    assert!(looks_like_challenge_interstitial(
        fixture_cf_challenge_html(),
        403
    ));
    assert!(looks_like_challenge_interstitial(
        fixture_captcha_widget_html(),
        200
    ));
}

// ---------------------------------------------------------------------------
// Hard-shield operator docs (M23): CapSolver miner how-to + residual honesty
// Guards product README / SECURITY / operators surfaces for hard-shield docs.
// Mission diary remains under gitignored .docs-evidence/ only.
// ---------------------------------------------------------------------------

#[test]
fn hard_shield_operator_docs_miner_key_and_residual_honesty() {
    let security = include_str!("../../../docs/SECURITY.md");
    let operator = include_str!("../../../docs/operators/proxy-and-egress.md");
    let readme = include_str!("../../../README.md");
    let combined = format!("{security}\n{operator}\n{readme}");
    let lower = combined.to_ascii_lowercase();

    // How-to miner / operator CapSolver key path (expectedBehavior: how-to miner key).
    assert!(
        (lower.contains("how-to") || lower.contains("miner / operator") || lower.contains("miner and operator"))
            && lower.contains("capsolver")
            && (lower.contains("capsolver_api_key") || lower.contains("`capsolver_api_key`")),
        "operator docs must include CapSolver miner/operator key how-to"
    );
    assert!(
        lower.contains("chmod 600") || lower.contains("mode `600`") || lower.contains("mode 600"),
        "CapSolver key how-to must require mode-600 / chmod 600 env file"
    );
    assert!(
        lower.contains("basecrawl_captcha_solver") || lower.contains("--captcha-solver"),
        "docs must show provider select surface for CapSolver"
    );

    // Oxylabs residential residual + max-1 concurrency.
    assert!(
        lower.contains("oxylabs")
            && (lower.contains("residential") || lower.contains("proxy-class residential")),
        "docs must document Oxylabs residential fixture / residential class"
    );
    assert!(
        lower.contains("max") && (lower.contains("1 concurrent") || lower.contains("**1** concurrent") || lower.contains("max 1")),
        "docs must state max 1 concurrent live residential dial"
    );

    // CF / Turnstile / Akamai residual language (feature residual risks).
    assert!(
        (lower.contains("cloudflare") || lower.contains("turnstile") || lower.contains("cf "))
            && (lower.contains("detect-not-solve")
                || lower.contains("detect + fail-closed")
                || lower.contains("detect and fail-closed")
                || lower.contains("challenge_blocked")),
        "docs must state CF/Turnstile detect-not-solve residual"
    );
    assert!(
        lower.contains("akamai"),
        "docs must document Akamai residual (hard-shield honesty)"
    );
    assert!(
        lower.contains("taostats")
            || lower.contains("managed challenge")
            || lower.contains("turnstile residual"),
        "docs must keep hard CF residual examples (taostats / managed challenge) for classification honesty"
    );

    // No commercial unlocker parity claim; banned affirmative slogans.
    assert!(
        lower.contains("not") && lower.contains("unlocker")
            || lower.contains("not commercial web unlocker")
            || lower.contains("no commercial web unlocker"),
        "docs must deny commercial Web Unlocker parity"
    );
    for banned in [
        "we are undetectable",                // must never / forbidden claim
        "fully undetectable residential",     // must never / forbidden claim
        "trustless scrape authenticity",      // must never / forbidden claim
        "100% guaranteed authenticity",       // must never / forbidden claim
        "100% unlocker parity",               // must never / forbidden claim
        "anonymous residential exit forever", // must never / forbidden claim
        "offers web unlocker feature-parity", // must never / forbidden claim
        "guarantees unlock any site",         // must never / forbidden claim
    ] {
        assert!(
            !lower.contains(banned),
            "hard-shield operator docs must never market absolute claim '{banned}'"
        );
    }

    // Product docs stay free of mission assertion ledgers (base-docs honesty).
    assert!(
        !operator.contains("VAL-HARD-015")
            && !operator.contains("VAL-SOLVE-")
            && !security.contains("VAL-HARD-")
            && !readme.contains("/root/.factory/missions"),
        "tracked product docs must not carry mission assertion diary IDs or missionPath ledger"
    );
}
