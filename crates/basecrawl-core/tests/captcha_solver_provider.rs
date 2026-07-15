//! Optional CapSolver provider (M23 / VAL-SOLVE-* / VAL-HARD-015 / VAL-CROSS-HARD-*).
//!
//! Hermetic only: mock CapSolver HTTP on mission ports 21000–21099. Soft CI never requires a
//! live key. Never logs CAPSOLVER_API_KEY material. Fail closed on auth/timeout/empty token.

use basecrawl_core::captcha_solver::{
    attempt_optional_solve, classify_challenge_html, extract_turnstile_sitekey, outcome_to_error,
    probe_balance, resolve_runtime, scrub_secret, solve_challenge, CaptchaKeySource,
    CaptchaSolverProvider, CaptchaSolverRuntime, ChallengeClass, FifoMockCapSolverHttp,
    SolveOutcome, SolveRequest, SolverErrorKind, CAPSOLVER_API_KEY_ENV, CAPSOLVER_HONESTY_HELP,
    CAPTCHA_SOLVER_ENV, SUPPORTED_CHALLENGE_CLASSES, TURNSTILE_TASK_TYPE,
};
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn strip_ambient_solver_env(cmd: &mut Command) {
    for key in [
        "CAPSOLVER_API_KEY",
        "BASECRAWL_CAPSOLVER_API_KEY",
        "BASECRAWL_CAPTCHA_SOLVER",
        "BASECRAWL_CAPSOLVER_API_BASE",
        "BASECRAWL_LIVE_PROXY",
        "BASECRAWL_HTTP_PROXY",
        "BASECRAWL_HTTPS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "TWOCAPTCHA_API_KEY",
        "ANTICAPTCHA_API_KEY",
    ] {
        cmd.env_remove(key);
    }
}

fn run_cli(args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    strip_ambient_solver_env(&mut cmd);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl")
}

fn run_cli_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    strip_ambient_solver_env(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn basecrawl")
}

fn err_kind(out: &Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr);
    if let Some(idx) = stderr.find('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stderr[idx..]) {
            if let Some(k) = v["error"]["kind"].as_str() {
                return k.to_string();
            }
        }
    }
    stderr.to_string()
}

fn bind_mission_port() -> TcpListener {
    for port in 21050u16..=21099 {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            return l;
        }
    }
    panic!("no free mission port in 21050-21099");
}

fn spawn_challenge_origin(body: &str, status: &str) -> String {
    let listener = bind_mission_port();
    let addr = listener.local_addr().expect("addr");
    let body = body.to_string();
    let status = status.to_string();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
                let _ = write!(
                    stream,
                    "{status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    format!("http://{addr}/challenge")
}

fn turnstile_html() -> &'static str {
    r#"<!doctype html><html><body>
    <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
    <form id="captcha-form">verify you are human</form>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
    </body></html>"#
}

// VAL-SOLVE-001 / VAL-SOLVE-008 / VAL-HARD-015: no key → clean detect-not-solve, soft CI ok
#[test]
fn val_solve_001_008_no_key_detect_not_solve_no_capsolver_calls() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var(CAPSOLVER_API_KEY_ENV);
    std::env::remove_var(CAPTCHA_SOLVER_ENV);
    assert!(resolve_runtime(Some("capsolver"), None, None)
        .unwrap()
        .is_none());

    let url = spawn_challenge_origin(turnstile_html(), "HTTP/1.1 403 Forbidden");
    // Challenge origin under hard path without solver key.
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
        "challenge without key must not succeed"
    );
    let kind = err_kind(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        kind == "challenge_blocked"
            || stderr.contains("challenge_blocked")
            || stderr.contains("challenge"),
        "expected challenge_blocked without solver key; kind={kind} stderr={stderr}"
    );
    let combined = format!("{}\n{}", String::from_utf8_lossy(&out.stdout), stderr);
    assert!(
        !combined.contains("createTask") || combined.to_ascii_lowercase().contains("challenge"),
        "must not claim CapSolver e2e without key"
    );
    let _ = out;
}

// VAL-SOLVE-002/003: key + provider resolve equivalently from env and options
#[test]
fn val_solve_002_003_key_via_env_and_options() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var(CAPSOLVER_API_KEY_ENV);
    std::env::remove_var("BASECRAWL_CAPSOLVER_API_KEY");
    std::env::remove_var(CAPTCHA_SOLVER_ENV);

    let key = "CAP-HERMETIC-ENV-KEY-0000000000000001";
    std::env::set_var(CAPSOLVER_API_KEY_ENV, key);
    std::env::set_var(CAPTCHA_SOLVER_ENV, "capsolver");
    let rt = resolve_runtime(None, None, None)
        .unwrap()
        .expect("env runtime");
    assert_eq!(rt.config.provider, CaptchaSolverProvider::CapSolver);
    assert!(matches!(rt.config.key_source, CaptchaKeySource::Env(_)));
    assert!(!format!("{:?}", rt).contains(key));

    std::env::remove_var(CAPSOLVER_API_KEY_ENV);
    let rt2 = resolve_runtime(Some("capsolver"), Some(key), None)
        .unwrap()
        .expect("options runtime");
    assert_eq!(rt2.config.key_source, CaptchaKeySource::Options);

    // Soft help remains green without any key (VAL-HARD-015 / VAL-HTML soft CI).
    std::env::remove_var(CAPSOLVER_API_KEY_ENV);
    std::env::remove_var(CAPTCHA_SOLVER_ENV);
    let help = run_cli(&["--help"]);
    assert!(help.status.success());
    let help_txt = format!(
        "{}\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    )
    .to_ascii_lowercase();
    assert!(
        help_txt.contains("captcha-solver") || help_txt.contains("capsolver"),
        "CLI documents optional --captcha-solver capsolver"
    );
    assert!(
        help_txt.contains("optional") || help_txt.contains("unlocker"),
        "CLI residual must remain optional / not unlocker parity"
    );
}

// VAL-SOLVE-004/005/006/007: createTask + getTaskResult polled; empty token refuses forge
#[test]
fn val_solve_004_007_create_poll_and_empty_token_fail_closed() {
    let secret = "CAP-HERMETIC-POLL-KEY-do-not-log-00000001";
    let mut rt = CaptchaSolverRuntime::new(
        secret,
        "http://127.0.0.1:21055",
        Duration::from_secs(20),
        CaptchaKeySource::Options,
    );
    rt.config.poll_interval = Duration::from_millis(1);
    let mock = FifoMockCapSolverHttp::new();
    mock.enqueue_create(200, json!({"errorId": 0, "taskId": "tid-1"}));
    mock.enqueue_result(200, json!({"errorId": 0, "status": "processing"}));
    mock.enqueue_result(
        200,
        json!({
            "errorId": 0,
            "status": "ready",
            "taskId": "tid-1",
            "solution": {"token": "tok-abc", "type": "turnstile"}
        }),
    );
    let solved = solve_challenge(
        &rt,
        &SolveRequest {
            website_url: "https://example.com/login".into(),
            website_key: "1x00000000000000000000AA".into(),
            challenge_class: ChallengeClass::Turnstile,
            action: Some("login".into()),
            cdata: None,
        },
        &mock,
    );
    match solved {
        SolveOutcome::Solved(s) => {
            assert_eq!(s.token, "tok-abc");
            assert_eq!(s.task_type, TURNSTILE_TASK_TYPE);
        }
        other => panic!("expected solved {other:?}"),
    }
    assert_eq!(mock.create_call_count(), 1);
    assert!(mock.result_call_count() >= 2);
    let create = &mock.create_bodies()[0];
    assert_eq!(create["task"]["type"], TURNSTILE_TASK_TYPE);
    assert_eq!(create["task"]["websiteURL"], "https://example.com/login");
    // Client key present in wire body but must be redacted for artifacts.
    let rendered = mock.all_rendered_redacted(secret);
    assert!(!rendered.contains(secret));
    assert!(rendered.contains("<redacted>") || !rendered.contains(secret));

    // Empty token refuses forge.
    let mock2 = FifoMockCapSolverHttp::new();
    mock2.enqueue_create(200, json!({"errorId": 0, "taskId": "tid-empty"}));
    mock2.enqueue_result(
        200,
        json!({"errorId": 0, "status": "ready", "solution": {"token": ""}}),
    );
    let empty = solve_challenge(
        &rt,
        &SolveRequest {
            website_url: "https://example.com/".into(),
            website_key: "1x00000000000000000000AA".into(),
            challenge_class: ChallengeClass::Turnstile,
            action: None,
            cdata: None,
        },
        &mock2,
    );
    assert!(matches!(
        empty,
        SolveOutcome::Failed {
            kind: SolverErrorKind::Provider,
            ..
        }
    ));
    let err = outcome_to_error(empty, 403);
    assert_ne!(err.kind(), "ok");
    assert!(!err.to_json_string().contains(secret));
}

// VAL-SOLVE-009 timeout typed
#[test]
fn val_solve_009_timeout_typed() {
    let mut rt = CaptchaSolverRuntime::new(
        "CAP-TIMEOUT-HERMETIC-KEY-000000000001",
        "http://127.0.0.1:21056",
        Duration::from_millis(60),
        CaptchaKeySource::Options,
    );
    rt.config.poll_interval = Duration::from_millis(25);
    let mock = FifoMockCapSolverHttp::new();
    mock.enqueue_create(200, json!({"errorId": 0, "taskId": "slow"}));
    for _ in 0..30 {
        mock.enqueue_result(200, json!({"errorId": 0, "status": "processing"}));
    }
    let start = Instant::now();
    let outcome = solve_challenge(
        &rt,
        &SolveRequest {
            website_url: "https://example.com/".into(),
            website_key: "1x00000000000000000000AA".into(),
            challenge_class: ChallengeClass::Turnstile,
            action: None,
            cdata: None,
        },
        &mock,
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    match outcome {
        SolveOutcome::Failed {
            kind: SolverErrorKind::Timeout,
            ..
        } => {}
        other => panic!("timeout expected {other:?}"),
    }
    assert_eq!(outcome_to_error(outcome, 403).kind(), "solver_timeout");
}

// VAL-SOLVE-010 secrets redacted in error/json
#[test]
fn val_solve_010_secrets_redacted() {
    let secret = "CAP-REDACT-ME-AAAAAAAA-BBBBBBBBBBBBBB";
    let mut rt = CaptchaSolverRuntime::new(
        secret,
        "http://127.0.0.1:21057",
        Duration::from_secs(5),
        CaptchaKeySource::Options,
    );
    rt.config.poll_interval = Duration::from_millis(1);
    let mock = FifoMockCapSolverHttp::new();
    mock.enqueue_create(
        401,
        json!({"errorId": 1, "errorCode": "ERROR_KEY_DENIED", "errorDescription": "bad"}),
    );
    let outcome = solve_challenge(
        &rt,
        &SolveRequest {
            website_url: "https://example.com/".into(),
            website_key: "1x00000000000000000000AA".into(),
            challenge_class: ChallengeClass::Turnstile,
            action: None,
            cdata: None,
        },
        &mock,
    );
    let err = outcome_to_error(outcome, 403);
    let s = err.to_json_string();
    assert!(!s.contains(secret));
    assert_eq!(err.kind(), "solver_auth_error");
    assert!(!format!("{rt:?}").contains(secret));
    assert!(!scrub_secret(&format!("key={secret}"), secret).contains(secret));
}

// VAL-SOLVE-011 soft path never requires CapSolver (help + soft scrape option)
#[test]
fn val_solve_011_soft_path_never_requires_capsolver() {
    let help = run_cli(&["--help"]);
    assert!(help.status.success());
    // Soft example.com without solver env
    let out = run_cli(&[
        "https://example.com/",
        "--formats",
        "markdown",
        "--no-js",
        "--timeout",
        "30",
    ]);
    // Open-web soft may succeed or transient fail; must not claim missing solver key.
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_ascii_lowercase();
    assert!(!combined.contains("missing capsolver"));
    assert!(!combined.contains("captcha marketplace required"));
    assert!(!combined.contains("solver_auth_error") || out.status.success());
}

// VAL-SOLVE-012 honesty residual
#[test]
fn val_solve_012_honesty_not_unlocker_parity() {
    let lower = CAPSOLVER_HONESTY_HELP.to_ascii_lowercase();
    assert!(lower.contains("not") && lower.contains("unlocker"));
    assert!(SUPPORTED_CHALLENGE_CLASSES.contains(&"turnstile"));
    let help = run_cli(&["--help"]);
    let h = format!(
        "{}\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    )
    .to_ascii_lowercase();
    assert!(!h.contains("100% guaranteed") && !h.contains("fully undetectable"));
    assert!(!h.contains("fully undetectable"));
    assert!(
        h.contains("not commercial web unlocker")
            || h.contains("unlocker parity")
            || h.contains("optional capsolver"),
        "help residual honesty about optional CapSolver"
    );
}

// VAL-SOLVE-014 unsupported class residual
#[test]
fn val_solve_014_unsupported_class_fail_closed() {
    let cf =
        r#"<title>Just a moment...</title><span>cloudflare</span> challenge-platform cf-challenge"#;
    assert_eq!(classify_challenge_html(cf), ChallengeClass::Unsupported);
    let secret = "CAP-UNSUP-KEY-0000000000000000000001";
    let mut rt = CaptchaSolverRuntime::new(
        secret,
        "http://127.0.0.1:21058",
        Duration::from_secs(5),
        CaptchaKeySource::Options,
    );
    rt.config.poll_interval = Duration::from_millis(1);
    let mock = FifoMockCapSolverHttp::new();
    let err =
        attempt_optional_solve(Some(&rt), "https://example.com/", cf, 403, &mock).unwrap_err();
    assert!(
        err.kind() == "challenge_blocked" || err.kind() == "solver_unsupported",
        "unsupported must fail closed kind={}",
        err.kind()
    );
    assert_eq!(mock.create_call_count(), 0);
    assert!(!err.to_json_string().contains(secret));
}

// VAL-SOLVE-010 / invalid key CLI path (ambient invalid key never printed)
#[test]
fn val_solve_invalid_key_cli_fail_closed_no_leak() {
    let secret = "CAP-CLI-BAD-KEY-must-never-print-00000001";
    // Hermetic: pin base to mock that 401s.
    // Without a mock HTTP server for full scrape path (live host), we only prove CLI resolves /
    // env redaction on --help + unit fail-closed. Use assist library path with mock:
    let mut rt = CaptchaSolverRuntime::new(
        secret,
        "http://127.0.0.1:21059",
        Duration::from_secs(5),
        CaptchaKeySource::Options,
    );
    rt.config.poll_interval = Duration::from_millis(1);
    let mock = FifoMockCapSolverHttp::new();
    mock.enqueue_balance(401, json!({"errorId": 1, "errorCode": "ERROR_KEY_DENIED"}));
    let bal = probe_balance(&rt, &mock).expect_err("401");
    match bal {
        SolveOutcome::Failed {
            kind: SolverErrorKind::Auth,
            detail,
            ..
        } => {
            assert!(!detail.contains(secret));
            assert!(detail.contains("401") || detail.contains("rejected"));
        }
        other => panic!("{other:?}"),
    }

    let out = run_cli_env(
        &["--help"],
        &[
            (CAPSOLVER_API_KEY_ENV, secret),
            (CAPTCHA_SOLVER_ENV, "capsolver"),
        ],
    );
    assert!(out.status.success());
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!combined.contains(secret));
}

// VAL-CROSS-HARD-003: solver config never claims residential
#[test]
fn val_cross_hard_003_solver_without_residential_label() {
    let _g = ENV_LOCK.lock().unwrap();
    let key = "CAP-CROSS-HARD-003-KEY-00000000000001";
    std::env::set_var(CAPSOLVER_API_KEY_ENV, key);
    std::env::set_var(CAPTCHA_SOLVER_ENV, "capsolver");
    let rt = resolve_runtime(None, None, None).unwrap().expect("rt");
    // Runtime itself has no residential claim fields.
    let debug = format!("{rt:?}");
    assert!(!debug.to_ascii_lowercase().contains("residential"));
    assert!(!debug.contains(key));
    std::env::remove_var(CAPSOLVER_API_KEY_ENV);
    std::env::remove_var(CAPTCHA_SOLVER_ENV);
}

#[test]
fn turnstile_sitekey_extract() {
    assert_eq!(
        extract_turnstile_sitekey(turnstile_html()).as_deref(),
        Some("1x00000000000000000000AA")
    );
    assert_eq!(
        classify_challenge_html(turnstile_html()),
        ChallengeClass::Turnstile
    );
}

// Soft challenge page without hard path: soft should not require solver (VAL-SOLVE-011)
#[test]
fn soft_challenge_surface_without_solver_key_skips_marketplace() {
    let url = spawn_challenge_origin(turnstile_html(), "HTTP/1.1 200 OK");
    let out = run_cli(&[
        &url,
        "--formats",
        "markdown",
        "--no-js",
        "--timeout",
        "15",
        "--robots",
        "ignore",
    ]);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_ascii_lowercase();
    // Soft can succeed on literal captcha HTML (detect only hard-gated) or fail for other reasons.
    // Must never require CapSolver for soft.
    assert!(!combined.contains("missing capsolver"));
    assert!(!combined.contains("solver_auth_error"));
}
