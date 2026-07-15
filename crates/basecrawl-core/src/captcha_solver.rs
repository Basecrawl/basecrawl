//! Optional CapSolver captcha provider (M23 / VAL-SOLVE-*).
//!
//! CapSolver is **operator-optional** and never required for soft CI. Default product posture remains
//! detect-not-solve (`challenge_blocked`) when no key is configured. With a key and solver selection
//! (`capsolver`), this module may issue `createTask` / poll `getTaskResult` for supported challenge
//! classes (Turnstile). Failures are typed and fail closed — never forge unlocked content, never log
//! the API key, never claim commercial Web Unlocker parity.
//!
//! Supported task types today:
//! - Turnstile → `AntiTurnstileTaskProxyLess`
//!
//! Unsupported classes (even with a key) yield [`SolverErrorKind::Unsupported`] without inventing
//! success. Token *application* into a live browser challenge flow is owned by the hard-path solve
//! feature; this module owns create/poll, config gating, redaction, and fail-closed outcomes.

use crate::error::Error;
use serde_json::{json, Value};
use std::env;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Official CapSolver HTTPS API host (createTask / getTaskResult / getBalance).
pub const CAPSOLVER_API_BASE: &str = "https://api.capsolver.com";

/// Env that holds the CapSolver client key (gitignored `.env`, mode 600 for miners/operators).
pub const CAPSOLVER_API_KEY_ENV: &str = "CAPSOLVER_API_KEY";

/// Optional alias so miners can namespace keys under BASECRAWL_* without baking secrets in binary.
pub const BASECRAWL_CAPSOLVER_API_KEY_ENV: &str = "BASECRAWL_CAPSOLVER_API_KEY";

/// Selects the captcha solver provider (`capsolver` only in this build).
pub const CAPTCHA_SOLVER_ENV: &str = "BASECRAWL_CAPTCHA_SOLVER";

/// Optional override of the CapSolver HTTPS base (hermetic tests / operator pins).
pub const CAPSOLVER_API_BASE_ENV: &str = "BASECRAWL_CAPSOLVER_API_BASE";

/// Default whole-solve budget for createTask + getTaskResult polling.
pub const DEFAULT_SOLVE_TIMEOUT_SECS: u64 = 90;

/// Default delay between getTaskResult polls.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

/// CapSolver Turnstile task type (proxy-less).
pub const TURNSTILE_TASK_TYPE: &str = "AntiTurnstileTaskProxyLess";

/// Honesty residual for CLI/docs (VAL-SOLVE-012). Optional CapSolver is **not** commercial Web
/// Unlocker parity, not "100%", and not "undetectable".
pub const CAPSOLVER_HONESTY_HELP: &str = "Optional CapSolver (`--captcha-solver capsolver` + \
CAPSOLVER_API_KEY / miner key) may attempt createTask/getTaskResult for supported Turnstile/CF \
classes. Without a key the product stays detect-not-solve (`challenge_blocked`). CapSolver does \
not equal commercial Web Unlocker parity, 100% unlock, or undetectable browsing. Failures invent \
no content_success.";

/// Documented supported challenge classes for residual honesty (VAL-SOLVE-014).
pub const SUPPORTED_CHALLENGE_CLASSES: &[&str] = &["turnstile", "cloudflare_turnstile"];

/// Named provider selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaSolverProvider {
    CapSolver,
}

impl CaptchaSolverProvider {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "capsolver" => Some(Self::CapSolver),
            "" | "none" | "off" | "disabled" => None,
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapSolver => "capsolver",
        }
    }
}

/// Challenge class the product can map to a CapSolver task type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeClass {
    /// Cloudflare Turnstile (and Turnstile-backed CF widgets with a sitekey).
    Turnstile,
    /// Detected but not implemented as a CapSolver task yet.
    Unsupported,
}

impl ChallengeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Turnstile => "turnstile",
            Self::Unsupported => "unsupported",
        }
    }
}

/// How the key was supplied (name only; value never retained after read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaKeySource {
    Env(String),
    Options,
}

impl CaptchaKeySource {
    pub fn as_str(&self) -> &str {
        match self {
            CaptchaKeySource::Env(name) => name.as_str(),
            CaptchaKeySource::Options => "scrape_options.captcha_api_key",
        }
    }
}

/// Redacted, non-secret snapshot of optional CapSolver configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaSolverConfig {
    pub provider: CaptchaSolverProvider,
    pub key_source: CaptchaKeySource,
    pub api_base: String,
    pub solve_timeout: Duration,
    pub poll_interval: Duration,
}

/// Full runtime handle that retains the API key **only inside the process** (never logged).
#[derive(Clone)]
pub struct CaptchaSolverRuntime {
    pub config: CaptchaSolverConfig,
    /// CapSolver `clientKey`. Never Display / Debug as full material.
    api_key: String,
}

impl std::fmt::Debug for CaptchaSolverRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaSolverRuntime")
            .field("config", &self.config)
            .field("api_key", &redact_secret_preview(&self.api_key))
            .finish()
    }
}

impl CaptchaSolverRuntime {
    /// Build a runtime for hermetic tests or in-process SDK callers (key never logged).
    pub fn new(
        api_key: impl Into<String>,
        api_base: impl Into<String>,
        solve_timeout: Duration,
        key_source: CaptchaKeySource,
    ) -> Self {
        Self {
            config: CaptchaSolverConfig {
                provider: CaptchaSolverProvider::CapSolver,
                key_source,
                api_base: api_base.into().trim_end_matches('/').to_string(),
                solve_timeout,
                poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
            },
            api_key: api_key.into(),
        }
    }

    /// Returns a redacted preview of the key for tests only (never full material).
    pub fn redacted_key_preview(&self) -> String {
        redact_secret_preview(&self.api_key)
    }

    pub fn api_key_len(&self) -> usize {
        self.api_key.len()
    }

    /// Access the raw key only for issuer code paths (never log this return).
    pub(crate) fn client_key(&self) -> &str {
        &self.api_key
    }
}

/// Solve request for a detected challenge.
#[derive(Debug, Clone)]
pub struct SolveRequest {
    pub website_url: String,
    pub website_key: String,
    pub challenge_class: ChallengeClass,
    pub action: Option<String>,
    pub cdata: Option<String>,
}

/// Successful solver token (CapSolver solution).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolveSolution {
    pub token: String,
    pub task_id: String,
    pub task_type: String,
    pub user_agent: Option<String>,
}

/// Typed solver failure kinds (VAL-SOLVE-007/009/014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverErrorKind {
    /// API key rejected (HTTP 401 / CapSolver ERROR_KEY_DENIED / invalid key).
    Auth,
    /// Poll budget exceeded without ready status.
    Timeout,
    /// Challenge class not mapped / not implemented.
    Unsupported,
    /// CapSolver returned a typed error or empty solution.
    Provider,
    /// Transport / HTTP / JSON failures talking to CapSolver.
    Transport,
}

impl SolverErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SolverErrorKind::Auth => "solver_auth_error",
            SolverErrorKind::Timeout => "solver_timeout",
            SolverErrorKind::Unsupported => "solver_unsupported",
            SolverErrorKind::Provider => "solver_error",
            SolverErrorKind::Transport => "solver_transport_error",
        }
    }
}

/// Result of a createTask + getTaskResult attempt.
#[derive(Debug, Clone)]
pub enum SolveOutcome {
    Solved(SolveSolution),
    Failed {
        kind: SolverErrorKind,
        detail: String,
        task_id: Option<String>,
    },
}

/// Injectable HTTP transport for hermetic tests (no live CapSolver required).
pub trait CapSolverHttp: Send + Sync {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, Value), String>;
}

/// Default blocking reqwest transport for production / operator use.
#[derive(Debug, Default)]
pub struct ReqwestCapSolverHttp {
    timeout: Duration,
}

impl ReqwestCapSolverHttp {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl CapSolverHttp for ReqwestCapSolverHttp {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, Value), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| format!("client build failed: {e}"))?;
        let payload = serde_json::to_vec(body).map_err(|e| format!("serialize: {e}"))?;
        let response = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .map_err(|e| format!("capsolver transport: {e}"))?;
        let status = response.status().as_u16();
        let text = response
            .text()
            .map_err(|e| format!("capsolver read body: {e}"))?;
        // Never assume body is free of operator mistakes that echoed the key; scrub defensively
        // after parse. Parse first so typed error fields stay usable.
        let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| {
            json!({
                "errorId": 1,
                "errorCode": "INVALID_JSON",
                "errorDescription": "non-json response from capsolver host",
            })
        });
        Ok((status, value))
    }
}

/// Resolve provider selection from CLI/env (name only; no key required).
pub fn resolve_provider_name(
    cli_solver: Option<&str>,
    ambient_env: bool,
) -> Option<CaptchaSolverProvider> {
    if let Some(raw) = cli_solver {
        return CaptchaSolverProvider::parse(raw);
    }
    if !ambient_env {
        return None;
    }
    env::var(CAPTCHA_SOLVER_ENV)
        .ok()
        .as_deref()
        .and_then(CaptchaSolverProvider::parse)
}

/// Read CapSolver API key from documented env names. Value returned only to caller that stores it
/// in [`CaptchaSolverRuntime`]; never log.
pub fn read_api_key_from_env() -> Option<(String, CaptchaKeySource)> {
    for name in [CAPSOLVER_API_KEY_ENV, BASECRAWL_CAPSOLVER_API_KEY_ENV] {
        if let Ok(v) = env::var(name) {
            let trimmed = v.trim().to_string();
            if !trimmed.is_empty() {
                return Some((trimmed, CaptchaKeySource::Env(name.to_string())));
            }
        }
    }
    None
}

/// Build an optional CapSolver runtime.
///
/// Inactive (returns `None`) when:
/// - no non-empty API key (env or options), or
/// - provider is not CapSolver
///
/// Soft CI / soft scrapes stay clean: no network, no crash.
pub fn resolve_runtime(
    cli_solver: Option<&str>,
    options_key: Option<&str>,
    solve_timeout_secs: Option<u64>,
) -> Result<Option<CaptchaSolverRuntime>, Error> {
    let key_material = match options_key
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| (s.to_string(), CaptchaKeySource::Options))
        .or_else(read_api_key_from_env)
    {
        Some(pair) => pair,
        None => return Ok(None),
    };

    // Activate only when the operator selected CapSolver (CLI / BASECRAWL_CAPTCHA_SOLVER) or
    // supplied an explicit options key with captcha_solver CLI/name, or CAPSOLVER_API_KEY is set
    // (VAL-SOLVE-002: CAPSOLVER_API_KEY alone may activate because the env name is vendor-specific).
    let provider = match resolve_provider_name(cli_solver, true) {
        Some(p) => p,
        None => {
            // Explicit options key without --captcha-solver still needs a provider pick via env; if
            // miner set only options.captcha_api_key, require BASECRAWL_CAPTCHA_SOLVER or treat as
            // CapSolver (documented miner conf surface about CapSolver key).
            if matches!(key_material.1, CaptchaKeySource::Options)
                || matches!(
                    &key_material.1,
                    CaptchaKeySource::Env(n)
                        if n == CAPSOLVER_API_KEY_ENV || n == BASECRAWL_CAPSOLVER_API_KEY_ENV
                )
            {
                CaptchaSolverProvider::CapSolver
            } else {
                return Ok(None);
            }
        }
    };

    if provider != CaptchaSolverProvider::CapSolver {
        return Ok(None);
    }

    // Reject obviously invalid tokens for the CLI surface (empty already filtered). White-space /
    // control chars fail closed rather than shipping garbage clientKey.
    if key_material
        .0
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Error::Solver {
            kind: SolverErrorKind::Auth.as_str().to_string(),
            detail: "captcha solver API key contains invalid whitespace/control characters"
                .to_string(),
            status_code: None,
        });
    }

    let api_base = env::var(CAPSOLVER_API_BASE_ENV)
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| CAPSOLVER_API_BASE.to_string());

    let timeout = Duration::from_secs(solve_timeout_secs.unwrap_or(DEFAULT_SOLVE_TIMEOUT_SECS));
    Ok(Some(CaptchaSolverRuntime {
        config: CaptchaSolverConfig {
            provider,
            key_source: key_material.1,
            api_base,
            solve_timeout: timeout,
            poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
        },
        api_key: key_material.0,
    }))
}

/// True when CapSolver would be attempted if a supported challenge is seen.
pub fn solver_is_configured(runtime: &Option<CaptchaSolverRuntime>) -> bool {
    runtime.is_some()
}

/// Classify an HTML challenge page into a solvable class (or unsupported).
pub fn classify_challenge_html(html: &str) -> ChallengeClass {
    let lower = html.to_ascii_lowercase();
    let sitekey = extract_turnstile_sitekey(html).is_some();
    let turnstile_ish = lower.contains("turnstile")
        || lower.contains("cf-turnstile")
        || (lower.contains("data-sitekey")
            && (lower.contains("challenges.cloudflare.com") || lower.contains("cf-turnstile")));
    if turnstile_ish || (sitekey && lower.contains("captcha")) {
        if extract_turnstile_sitekey(html).is_some() {
            return ChallengeClass::Turnstile;
        }
        // Widget shell without sitekey still not free to forge as unsupported-success.
        return ChallengeClass::Unsupported;
    }
    // CF managed interstitials without a Turnstile sitekey are residual-only in this leaf.
    if lower.contains("challenge-platform")
        || lower.contains("cf-browser-verification")
        || (lower.contains("just a moment") && lower.contains("cloudflare"))
        || lower.contains("checking your browser")
    {
        return ChallengeClass::Unsupported;
    }
    if lower.contains("g-recaptcha") || lower.contains("h-captcha") || lower.contains("hcaptcha") {
        return ChallengeClass::Unsupported;
    }
    ChallengeClass::Unsupported
}

/// Extract a Turnstile / captcha site key from common HTML attributes.
pub fn extract_turnstile_sitekey(html: &str) -> Option<String> {
    // Prefer cf-turnstile / data-sitekey attributes.
    for needle in [
        "data-sitekey=\"",
        "data-sitekey='",
        "sitekey=\"",
        "sitekey='",
    ] {
        if let Some(idx) = html.to_ascii_lowercase().find(needle) {
            // Use original-case slice via same index on original (ASCII prefixes).
            let start = idx + needle.len();
            let rest = &html[start..];
            let end = rest.find(['"', '\'', ' ', '>', '&']).unwrap_or(rest.len());
            let key = rest[..end].trim();
            if !key.is_empty() && key.len() >= 8 {
                return Some(key.to_string());
            }
        }
    }
    None
}

/// Create a CapSolver task and poll until token, error, or timeout.
pub fn solve_challenge(
    runtime: &CaptchaSolverRuntime,
    request: &SolveRequest,
    http: &dyn CapSolverHttp,
) -> SolveOutcome {
    if request.challenge_class != ChallengeClass::Turnstile {
        return SolveOutcome::Failed {
            kind: SolverErrorKind::Unsupported,
            detail: format!(
                "challenge class '{}' is not implemented for CapSolver in this build \
                 (supported: {})",
                request.challenge_class.as_str(),
                SUPPORTED_CHALLENGE_CLASSES.join(", ")
            ),
            task_id: None,
        };
    }
    if request.website_key.trim().is_empty() {
        return SolveOutcome::Failed {
            kind: SolverErrorKind::Unsupported,
            detail: "turnstile sitekey missing; refuse forge".into(),
            task_id: None,
        };
    }

    let deadline = Instant::now() + runtime.config.solve_timeout;
    match create_task(runtime, request, http) {
        Ok(CreateTaskResult::Ready(solution)) => SolveOutcome::Solved(solution),
        Ok(CreateTaskResult::Pending { task_id }) => {
            poll_task_result(runtime, &task_id, deadline, http)
        }
        Err(outcome) => outcome,
    }
}

enum CreateTaskResult {
    Pending { task_id: String },
    Ready(SolveSolution),
}

fn create_task(
    runtime: &CaptchaSolverRuntime,
    request: &SolveRequest,
    http: &dyn CapSolverHttp,
) -> Result<CreateTaskResult, SolveOutcome> {
    let mut task = json!({
        "type": TURNSTILE_TASK_TYPE,
        "websiteURL": request.website_url,
        "websiteKey": request.website_key,
    });
    if request.action.is_some() || request.cdata.is_some() {
        let mut metadata = serde_json::Map::new();
        if let Some(a) = request.action.as_ref() {
            metadata.insert("action".into(), Value::String(a.clone()));
        }
        if let Some(c) = request.cdata.as_ref() {
            metadata.insert("cdata".into(), Value::String(c.clone()));
        }
        task["metadata"] = Value::Object(metadata);
    }
    let body = json!({
        "clientKey": runtime.client_key(),
        "task": task,
    });
    let url = format!("{}/createTask", runtime.config.api_base);
    let (status, value) = http
        .post_json(&url, &body)
        .map_err(|e| SolveOutcome::Failed {
            kind: SolverErrorKind::Transport,
            detail: scrub_secret(&e, runtime.client_key()),
            task_id: None,
        })?;

    if status == 401 || status == 403 {
        return Err(SolveOutcome::Failed {
            kind: SolverErrorKind::Auth,
            detail: format!("capsolver createTask HTTP {status} (invalid or unauthorized key)"),
            task_id: None,
        });
    }

    let error_id = value.get("errorId").and_then(|v| v.as_i64()).unwrap_or(0);
    if error_id != 0 || status >= 400 {
        let code = value
            .get("errorCode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let desc = value
            .get("errorDescription")
            .and_then(|v| v.as_str())
            .unwrap_or("capsolver createTask failed");
        let kind = classify_provider_error(code, desc, status);
        return Err(SolveOutcome::Failed {
            kind,
            detail: scrub_secret(
                &format!("createTask failed code={code} desc={desc} http={status}"),
                runtime.client_key(),
            ),
            task_id: value
                .get("taskId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }

    // Synchronous ready path (rare for Turnstile; still respect if present).
    if value.get("status").and_then(|v| v.as_str()) == Some("ready") {
        if let Some(solution) = extract_solution(&value, "") {
            return Ok(CreateTaskResult::Ready(solution));
        }
    }

    let task_id = value
        .get("taskId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SolveOutcome::Failed {
            kind: SolverErrorKind::Provider,
            detail: "createTask returned no taskId".into(),
            task_id: None,
        })?;
    Ok(CreateTaskResult::Pending {
        task_id: task_id.to_string(),
    })
}

fn poll_task_result(
    runtime: &CaptchaSolverRuntime,
    task_id: &str,
    deadline: Instant,
    http: &dyn CapSolverHttp,
) -> SolveOutcome {
    let url = format!("{}/getTaskResult", runtime.config.api_base);
    let body = json!({
        "clientKey": runtime.client_key(),
        "taskId": task_id,
    });
    let mut polls = 0u32;
    loop {
        if Instant::now() >= deadline {
            return SolveOutcome::Failed {
                kind: SolverErrorKind::Timeout,
                detail: format!(
                    "solver_timeout after {polls} poll(s) (budget {}s)",
                    runtime.config.solve_timeout.as_secs()
                ),
                task_id: Some(task_id.to_string()),
            };
        }
        // First poll can be immediate; subsequent respect poll_interval without sleeping past
        // deadline in unittests that inject a Clock — wall sleep elsewhere uses std.
        if polls > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let sleep_for = runtime.config.poll_interval.min(remaining);
            if !sleep_for.is_zero() {
                std::thread::sleep(sleep_for);
            }
        }
        polls += 1;
        let (status, value) = match http.post_json(&url, &body) {
            Ok(pair) => pair,
            Err(e) => {
                return SolveOutcome::Failed {
                    kind: SolverErrorKind::Transport,
                    detail: scrub_secret(&e, runtime.client_key()),
                    task_id: Some(task_id.to_string()),
                };
            }
        };
        if status == 401 || status == 403 {
            return SolveOutcome::Failed {
                kind: SolverErrorKind::Auth,
                detail: format!(
                    "capsolver getTaskResult HTTP {status} (invalid or unauthorized key)"
                ),
                task_id: Some(task_id.to_string()),
            };
        }
        let error_id = value.get("errorId").and_then(|v| v.as_i64()).unwrap_or(0);
        if error_id != 0 || status >= 400 {
            let code = value
                .get("errorCode")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let desc = value
                .get("errorDescription")
                .and_then(|v| v.as_str())
                .unwrap_or("getTaskResult failed");
            return SolveOutcome::Failed {
                kind: classify_provider_error(code, desc, status),
                detail: scrub_secret(
                    &format!("getTaskResult failed code={code} desc={desc} http={status}"),
                    runtime.client_key(),
                ),
                task_id: Some(task_id.to_string()),
            };
        }
        let status_s = value.get("status").and_then(|v| v.as_str()).unwrap_or("");
        match status_s {
            "ready" => {
                return match extract_solution(&value, task_id) {
                    Some(sol) if !sol.token.is_empty() => SolveOutcome::Solved(sol),
                    Some(_) => SolveOutcome::Failed {
                        kind: SolverErrorKind::Provider,
                        detail: "empty solution token; refuse forge".into(),
                        task_id: Some(task_id.to_string()),
                    },
                    None => SolveOutcome::Failed {
                        kind: SolverErrorKind::Provider,
                        detail: "ready status without solution token; refuse forge".into(),
                        task_id: Some(task_id.to_string()),
                    },
                };
            }
            "failed" | "error" => {
                return SolveOutcome::Failed {
                    kind: SolverErrorKind::Provider,
                    detail: "capsolver status=failed".into(),
                    task_id: Some(task_id.to_string()),
                };
            }
            // idle | processing | empty → continue polling
            _ => continue,
        }
    }
}

fn extract_solution(value: &Value, fallback_task_id: &str) -> Option<SolveSolution> {
    let solution = value.get("solution")?;
    let token = solution
        .get("token")
        .or_else(|| solution.get("gRecaptchaResponse"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();
    let task_id = value
        .get("taskId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_task_id)
        .to_string();
    let user_agent = solution
        .get("userAgent")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Some(SolveSolution {
        token,
        task_id,
        task_type: TURNSTILE_TASK_TYPE.to_string(),
        user_agent,
    })
}

fn classify_provider_error(code: &str, desc: &str, http_status: u16) -> SolverErrorKind {
    let c = code.to_ascii_uppercase();
    let d = desc.to_ascii_lowercase();
    if http_status == 401
        || http_status == 403
        || c.contains("KEY")
        || c.contains("AUTH")
        || d.contains("invalid key")
        || d.contains("api key")
        || d.contains("unauthorized")
        || d.contains("client key")
    {
        return SolverErrorKind::Auth;
    }
    SolverErrorKind::Provider
}

/// Optional readiness probe against `getBalance`. Fail closed on 401 / invalid key — never used
/// to forge unlock. Returns (http_status, redacted summary).
pub fn probe_balance(
    runtime: &CaptchaSolverRuntime,
    http: &dyn CapSolverHttp,
) -> Result<(u16, String), SolveOutcome> {
    let url = format!("{}/getBalance", runtime.config.api_base);
    let body = json!({ "clientKey": runtime.client_key() });
    let (status, value) = http
        .post_json(&url, &body)
        .map_err(|e| SolveOutcome::Failed {
            kind: SolverErrorKind::Transport,
            detail: scrub_secret(&e, runtime.client_key()),
            task_id: None,
        })?;
    if status == 401 || status == 403 {
        return Err(SolveOutcome::Failed {
            kind: SolverErrorKind::Auth,
            detail: format!(
                "capsolver getBalance HTTP {status}: key rejected (check CAP-… account/key format; \
                 remain fail-closed; never forge unlock)"
            ),
            task_id: None,
        });
    }
    let error_id = value.get("errorId").and_then(|v| v.as_i64()).unwrap_or(0);
    if error_id != 0 {
        let code = value
            .get("errorCode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let desc = value
            .get("errorDescription")
            .and_then(|v| v.as_str())
            .unwrap_or("getBalance failed");
        return Err(SolveOutcome::Failed {
            kind: classify_provider_error(code, desc, status),
            detail: scrub_secret(
                &format!("getBalance failed code={code} desc={desc}"),
                runtime.client_key(),
            ),
            task_id: None,
        });
    }
    // Never emit bucketized secrets; balance figure alone is ok for operator readiness.
    let balance = value
        .get("balance")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".into());
    Ok((status, format!("balance_ok={balance}")))
}

/// Convert a failed solve into a core Error — never content_success.
pub fn outcome_to_error(outcome: SolveOutcome, challenge_status: u16) -> Error {
    match outcome {
        SolveOutcome::Solved(_) => Error::Solver {
            kind: "solver_apply_pending".into(),
            detail: "solver returned a token but application into content is required before \
                     content_success (refuse forge from token alone)"
                .into(),
            status_code: Some(challenge_status),
        },
        SolveOutcome::Failed {
            kind,
            detail,
            task_id: _,
        } => match kind {
            SolverErrorKind::Timeout => Error::Solver {
                kind: kind.as_str().into(),
                detail,
                status_code: Some(challenge_status),
            },
            SolverErrorKind::Auth => Error::Solver {
                kind: kind.as_str().into(),
                detail,
                status_code: Some(challenge_status),
            },
            SolverErrorKind::Unsupported => Error::ChallengeBlocked {
                status_code: challenge_status,
                detail: format!("solver_unsupported: {detail}"),
            },
            SolverErrorKind::Provider | SolverErrorKind::Transport => Error::Solver {
                kind: kind.as_str().into(),
                detail,
                status_code: Some(challenge_status),
            },
        },
    }
}

/// Attempt a solve when CapSolver is configured; otherwise return challenge_blocked residual.
///
/// **Never** returns Ok(token) as a signal to emit forged content_success: callers that receive
/// `Ok(Some(solution))` must still apply the token before any content_success claim. This helper
/// is used by the hard-path solve wiring; provider unit tests exercise it via mocks.
pub fn attempt_optional_solve(
    runtime: Option<&CaptchaSolverRuntime>,
    website_url: &str,
    html: &str,
    challenge_status: u16,
    http: &dyn CapSolverHttp,
) -> Result<Option<SolveSolution>, Error> {
    let Some(rt) = runtime else {
        return Err(Error::ChallengeBlocked {
            status_code: challenge_status,
            detail: "hard path observed a bot-challenge / block response (detect-not-solve; \
                     CapSolver inactive without key)"
                .into(),
        });
    };

    let class = classify_challenge_html(html);
    if class == ChallengeClass::Unsupported {
        return Err(Error::ChallengeBlocked {
            status_code: challenge_status,
            detail: format!(
                "challenge class unsupported by CapSolver mapping (supported: {}); \
                 refuse content_success",
                SUPPORTED_CHALLENGE_CLASSES.join(", ")
            ),
        });
    }
    let sitekey = extract_turnstile_sitekey(html).ok_or_else(|| Error::ChallengeBlocked {
        status_code: challenge_status,
        detail: "turnstile sitekey not found; refuse forge".into(),
    })?;
    let request = SolveRequest {
        website_url: website_url.to_string(),
        website_key: sitekey,
        challenge_class: class,
        action: None,
        cdata: None,
    };
    match solve_challenge(rt, &request, http) {
        SolveOutcome::Solved(sol) => Ok(Some(sol)),
        other => Err(outcome_to_error(other, challenge_status)),
    }
}

/// Redact full secrets from a free-form string (replace with `<redacted>`).
pub fn scrub_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, basecrawl_seal::REDACTED_TOKEN)
}

/// Short host-safe preview: first 4 chars + ellipsis on length (never full key).
pub fn redact_secret_preview(secret: &str) -> String {
    if secret.is_empty() {
        return basecrawl_seal::REDACTED_TOKEN.to_string();
    }
    if secret.len() <= 8 {
        return basecrawl_seal::REDACTED_TOKEN.to_string();
    }
    format!("{}…<redacted>", &secret[..4.min(secret.len())])
}

/// Ensure a payload / text surface never contains the runtime key (tests/callers).
pub fn assert_no_secret_leak(surface: &str, secret: &str) -> bool {
    secret.is_empty() || !surface.contains(secret)
}

// ---------------------------------------------------------------------------
// Hermetic mock HTTP (tests / local injection)
// ---------------------------------------------------------------------------

/// Scripted CapSolver mock for hermetic tests. Records redactable create/poll bodies.
#[derive(Default)]
pub struct MockCapSolverHttp {
    inner: Mutex<MockCapSolverState>,
}

#[derive(Default)]
struct MockCapSolverState {
    create_responses: Vec<Result<(u16, Value), String>>,
    result_responses: Vec<Result<(u16, Value), String>>,
    balance_responses: Vec<Result<(u16, Value), String>>,
    pub create_bodies: Vec<Value>,
    pub result_bodies: Vec<Value>,
    pub balance_bodies: Vec<Value>,
    /// Artificial delay per result poll (for timeout tests).
    poll_delay: Duration,
}

impl MockCapSolverHttp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_create(&self, status: u16, body: Value) {
        self.inner
            .lock()
            .expect("mock lock")
            .create_responses
            .push(Ok((status, body)));
    }

    pub fn push_result(&self, status: u16, body: Value) {
        self.inner
            .lock()
            .expect("mock lock")
            .result_responses
            .push(Ok((status, body)));
    }

    pub fn push_balance(&self, status: u16, body: Value) {
        self.inner
            .lock()
            .expect("mock lock")
            .balance_responses
            .push(Ok((status, body)));
    }

    pub fn set_poll_delay(&self, delay: Duration) {
        self.inner.lock().expect("mock lock").poll_delay = delay;
    }

    pub fn create_bodies_redacted(&self, secret: &str) -> Vec<Value> {
        self.inner
            .lock()
            .expect("mock lock")
            .create_bodies
            .iter()
            .map(|v| redact_json_secrets(v, secret))
            .collect()
    }

    pub fn create_call_count(&self) -> usize {
        self.inner.lock().expect("mock lock").create_bodies.len()
    }

    pub fn result_call_count(&self) -> usize {
        self.inner.lock().expect("mock lock").result_bodies.len()
    }
}

impl CapSolverHttp for MockCapSolverHttp {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, Value), String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "mock lock poisoned".to_string())?;
        if url.contains("createTask") {
            guard.create_bodies.push(body.clone());
            return guard
                .create_responses
                .pop()
                .unwrap_or_else(|| Err("mock: no createTask response scripted".into()));
        }
        if url.contains("getTaskResult") {
            if !guard.poll_delay.is_zero() {
                std::thread::sleep(guard.poll_delay);
            }
            guard.result_bodies.push(body.clone());
            return guard
                .result_responses
                .pop()
                .unwrap_or_else(|| Err("mock: no getTaskResult response scripted".into()));
        }
        if url.contains("getBalance") {
            guard.balance_bodies.push(body.clone());
            return guard
                .balance_responses
                .pop()
                .unwrap_or_else(|| Err("mock: no getBalance response scripted".into()));
        }
        Err(format!("mock: unexpected url {url}"))
    }
}

/// FIFO mock preferred for predicted sequences.
#[derive(Default)]
pub struct FifoMockCapSolverHttp {
    inner: Mutex<FifoState>,
}

#[derive(Default)]
struct FifoState {
    create: std::collections::VecDeque<Result<(u16, Value), String>>,
    result: std::collections::VecDeque<Result<(u16, Value), String>>,
    balance: std::collections::VecDeque<Result<(u16, Value), String>>,
    create_bodies: Vec<Value>,
    result_bodies: Vec<Value>,
    balance_bodies: Vec<Value>,
    poll_delay: Duration,
}

impl FifoMockCapSolverHttp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_create(&self, status: u16, body: Value) {
        self.inner
            .lock()
            .expect("lock")
            .create
            .push_back(Ok((status, body)));
    }

    pub fn enqueue_result(&self, status: u16, body: Value) {
        self.inner
            .lock()
            .expect("lock")
            .result
            .push_back(Ok((status, body)));
    }

    pub fn enqueue_balance(&self, status: u16, body: Value) {
        self.inner
            .lock()
            .expect("lock")
            .balance
            .push_back(Ok((status, body)));
    }

    pub fn set_poll_delay(&self, delay: Duration) {
        self.inner.lock().expect("lock").poll_delay = delay;
    }

    pub fn create_bodies(&self) -> Vec<Value> {
        self.inner.lock().expect("lock").create_bodies.clone()
    }

    pub fn result_bodies(&self) -> Vec<Value> {
        self.inner.lock().expect("lock").result_bodies.clone()
    }

    pub fn create_call_count(&self) -> usize {
        self.inner.lock().expect("lock").create_bodies.len()
    }

    pub fn result_call_count(&self) -> usize {
        self.inner.lock().expect("lock").result_bodies.len()
    }

    pub fn all_rendered_redacted(&self, secret: &str) -> String {
        let g = self.inner.lock().expect("lock");
        let mut out = String::new();
        for b in g
            .create_bodies
            .iter()
            .chain(g.result_bodies.iter())
            .chain(g.balance_bodies.iter())
        {
            out.push_str(&scrub_secret(&b.to_string(), secret));
            out.push('\n');
        }
        out
    }
}

impl CapSolverHttp for FifoMockCapSolverHttp {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, Value), String> {
        let mut g = self.inner.lock().map_err(|_| "lock poisoned".to_string())?;
        if url.contains("createTask") {
            g.create_bodies.push(body.clone());
            return g
                .create
                .pop_front()
                .unwrap_or_else(|| Err("mock fifo: no createTask".into()));
        }
        if url.contains("getTaskResult") {
            if !g.poll_delay.is_zero() {
                std::thread::sleep(g.poll_delay);
            }
            g.result_bodies.push(body.clone());
            return g
                .result
                .pop_front()
                .unwrap_or_else(|| Err("mock fifo: no getTaskResult".into()));
        }
        if url.contains("getBalance") {
            g.balance_bodies.push(body.clone());
            return g
                .balance
                .pop_front()
                .unwrap_or_else(|| Err("mock fifo: no getBalance".into()));
        }
        Err(format!("mock fifo unexpected url={url}"))
    }
}

fn redact_json_secrets(value: &Value, secret: &str) -> Value {
    match value {
        Value::String(s) => {
            if !secret.is_empty() && s.contains(secret) {
                Value::String(scrub_secret(s, secret))
            } else if s == secret {
                Value::String(basecrawl_seal::REDACTED_TOKEN.to_string())
            } else {
                Value::String(s.clone())
            }
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_json_secrets(v, secret))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if k == "clientKey" || k.eq_ignore_ascii_case("api_key") {
                    out.insert(
                        k.clone(),
                        Value::String(basecrawl_seal::REDACTED_TOKEN.to_string()),
                    );
                } else {
                    out.insert(k.clone(), redact_json_secrets(v, secret));
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_solver_env() {
        env::remove_var(CAPSOLVER_API_KEY_ENV);
        env::remove_var(BASECRAWL_CAPSOLVER_API_KEY_ENV);
        env::remove_var(CAPTCHA_SOLVER_ENV);
        env::remove_var(CAPSOLVER_API_BASE_ENV);
    }

    #[test]
    fn inactive_without_key_no_network() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_solver_env();
        let rt = resolve_runtime(Some("capsolver"), None, None).unwrap();
        assert!(rt.is_none());
        let mock = FifoMockCapSolverHttp::new();
        // attempt without runtime → challenge_blocked; mock stays at zero calls
        let err = attempt_optional_solve(
            None,
            "https://example.com/",
            r#"<div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>"#,
            403,
            &mock,
        )
        .unwrap_err();
        assert_eq!(err.kind(), "challenge_blocked");
        assert_eq!(mock.create_call_count(), 0);
    }

    #[test]
    fn key_from_env_activates_capsolver() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_solver_env();
        env::set_var(CAPSOLVER_API_KEY_ENV, "CAP-TESTKEY000000000000000000000001");
        env::set_var(CAPTCHA_SOLVER_ENV, "capsolver");
        let rt = resolve_runtime(None, None, None).unwrap().expect("runtime");
        assert_eq!(rt.config.provider, CaptchaSolverProvider::CapSolver);
        assert!(matches!(rt.config.key_source, CaptchaKeySource::Env(_)));
        assert!(!format!("{rt:?}").contains("CAP-TESTKEY000000000000000000000001"));
        clear_solver_env();
    }

    #[test]
    fn options_key_activates_equivalently() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_solver_env();
        let rt = resolve_runtime(
            Some("capsolver"),
            Some("CAP-OPTIONSKEY00000000000000000002"),
            Some(30),
        )
        .unwrap()
        .expect("runtime");
        assert_eq!(rt.config.key_source, CaptchaKeySource::Options);
        assert_eq!(rt.config.solve_timeout, Duration::from_secs(30));
    }

    #[test]
    fn create_and_poll_turnstile_success_mocked() {
        let secret = "CAP-MOCKKEY-should-never-appear-in-artifacts-abcdef";
        let mut rt = CaptchaSolverRuntime::new(
            secret,
            "http://127.0.0.1:21041",
            Duration::from_secs(30),
            CaptchaKeySource::Options,
        );
        rt.config.poll_interval = Duration::from_millis(1);
        let mock = FifoMockCapSolverHttp::new();
        mock.enqueue_create(200, json!({"errorId": 0, "taskId": "task-turnstile-1"}));
        mock.enqueue_result(
            200,
            json!({"errorId": 0, "status": "processing", "taskId": "task-turnstile-1"}),
        );
        mock.enqueue_result(
            200,
            json!({
                "errorId": 0,
                "status": "ready",
                "taskId": "task-turnstile-1",
                "solution": {
                    "token": "turnstile-token-xyz",
                    "type": "turnstile",
                    "userAgent": "Mozilla/5.0"
                }
            }),
        );
        let outcome = solve_challenge(
            &rt,
            &SolveRequest {
                website_url: "https://protected.example/".into(),
                website_key: "1x00000000000000000000AA".into(),
                challenge_class: ChallengeClass::Turnstile,
                action: None,
                cdata: None,
            },
            &mock,
        );
        match outcome {
            SolveOutcome::Solved(sol) => {
                assert_eq!(sol.token, "turnstile-token-xyz");
                assert_eq!(sol.task_id, "task-turnstile-1");
            }
            other => panic!("expected solved, got {other:?}"),
        }
        assert_eq!(mock.create_call_count(), 1);
        assert!(mock.result_call_count() >= 2);
        let redacted = mock.all_rendered_redacted(secret);
        assert!(
            !redacted.contains(secret),
            "create/poll payloads must redact key"
        );
        let creates = mock.create_bodies();
        assert_eq!(
            creates[0]["task"]["type"], TURNSTILE_TASK_TYPE,
            "must request AntiTurnstileTaskProxyLess"
        );
        assert_eq!(creates[0]["task"]["websiteKey"], "1x00000000000000000000AA");
    }

    #[test]
    fn invalid_key_auth_fail_closed() {
        let secret = "CAP-BADKEY-xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let mut rt = CaptchaSolverRuntime::new(
            secret,
            "http://127.0.0.1:21042",
            Duration::from_secs(10),
            CaptchaKeySource::Options,
        );
        rt.config.poll_interval = Duration::from_millis(1);
        let mock = FifoMockCapSolverHttp::new();
        mock.enqueue_create(
            401,
            json!({
                "errorId": 1,
                "errorCode": "ERROR_KEY_DENIED",
                "errorDescription": "invalid key"
            }),
        );
        let outcome = solve_challenge(
            &rt,
            &SolveRequest {
                website_url: "https://protected.example/".into(),
                website_key: "1x00000000000000000000AA".into(),
                challenge_class: ChallengeClass::Turnstile,
                action: None,
                cdata: None,
            },
            &mock,
        );
        match &outcome {
            SolveOutcome::Failed {
                kind: SolverErrorKind::Auth,
                detail,
                ..
            } => {
                assert!(!detail.contains(secret));
            }
            other => panic!("expected auth fail, got {other:?}"),
        }
        // Must not claim success.
        let err = outcome_to_error(outcome, 403);
        assert_eq!(err.kind(), "solver_auth_error");
        let rendered = err.to_json_string();
        assert!(!rendered.contains(secret));
    }

    #[test]
    fn empty_token_refuses_forge() {
        let mut rt = CaptchaSolverRuntime::new(
            "CAP-EMPTYTOKEN-TESTKEY00000000000001",
            "http://127.0.0.1:21043",
            Duration::from_secs(5),
            CaptchaKeySource::Options,
        );
        rt.config.poll_interval = Duration::from_millis(1);
        let mock = FifoMockCapSolverHttp::new();
        mock.enqueue_create(200, json!({"errorId": 0, "taskId": "t-empty"}));
        mock.enqueue_result(
            200,
            json!({
                "errorId": 0,
                "status": "ready",
                "solution": { "token": "" }
            }),
        );
        let outcome = solve_challenge(
            &rt,
            &SolveRequest {
                website_url: "https://x.example/".into(),
                website_key: "1x00000000000000000000AA".into(),
                challenge_class: ChallengeClass::Turnstile,
                action: None,
                cdata: None,
            },
            &mock,
        );
        assert!(matches!(
            outcome,
            SolveOutcome::Failed {
                kind: SolverErrorKind::Provider,
                ..
            }
        ));
    }

    #[test]
    fn timeout_typed_non_hanging() {
        let mut rt = CaptchaSolverRuntime::new(
            "CAP-TIMEOUT-TESTKEY0000000000000001",
            "http://127.0.0.1:21044",
            Duration::from_millis(80),
            CaptchaKeySource::Options,
        );
        rt.config.poll_interval = Duration::from_millis(30);
        let mock = FifoMockCapSolverHttp::new();
        mock.enqueue_create(200, json!({"errorId": 0, "taskId": "t-slow"}));
        // Always processing until budget ends.
        for _ in 0..20 {
            mock.enqueue_result(
                200,
                json!({"errorId": 0, "status": "processing", "taskId": "t-slow"}),
            );
        }
        let start = Instant::now();
        let outcome = solve_challenge(
            &rt,
            &SolveRequest {
                website_url: "https://x.example/".into(),
                website_key: "1x00000000000000000000AA".into(),
                challenge_class: ChallengeClass::Turnstile,
                action: None,
                cdata: None,
            },
            &mock,
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "timeout path must not hang; elapsed={elapsed:?}"
        );
        match outcome {
            SolveOutcome::Failed {
                kind: SolverErrorKind::Timeout,
                ..
            } => {}
            other => panic!("expected timeout, got {other:?}"),
        }
        let err = outcome_to_error(outcome, 403);
        assert_eq!(err.kind(), "solver_timeout");
    }

    #[test]
    fn unsupported_class_fail_closed() {
        let mut rt = CaptchaSolverRuntime::new(
            "CAP-UNSUP-TESTKEY000000000000000001",
            "http://127.0.0.1:21045",
            Duration::from_secs(5),
            CaptchaKeySource::Options,
        );
        rt.config.poll_interval = Duration::from_millis(1);
        let mock = FifoMockCapSolverHttp::new();
        let outcome = solve_challenge(
            &rt,
            &SolveRequest {
                website_url: "https://x.example/".into(),
                website_key: "unused".into(),
                challenge_class: ChallengeClass::Unsupported,
                action: None,
                cdata: None,
            },
            &mock,
        );
        assert!(matches!(
            outcome,
            SolveOutcome::Failed {
                kind: SolverErrorKind::Unsupported,
                ..
            }
        ));
        assert_eq!(mock.create_call_count(), 0);
    }

    #[test]
    fn balance_401_fail_closed_diagnose() {
        let secret = "CAP-BAL401-TESTKEY00000000000000001";
        let mut rt = CaptchaSolverRuntime::new(
            secret,
            "http://127.0.0.1:21046",
            Duration::from_secs(5),
            CaptchaKeySource::Options,
        );
        rt.config.poll_interval = Duration::from_millis(1);
        let mock = FifoMockCapSolverHttp::new();
        mock.enqueue_balance(401, json!({"errorId": 1, "errorCode": "ERROR_KEY_DENIED"}));
        let err = probe_balance(&rt, &mock).expect_err("401");
        match err {
            SolveOutcome::Failed {
                kind: SolverErrorKind::Auth,
                detail,
                ..
            } => {
                assert!(detail.contains("401") || detail.contains("rejected"));
                assert!(!detail.contains(secret));
            }
            other => panic!("expected auth, got {other:?}"),
        }
    }

    #[test]
    fn classify_turnstile_html() {
        let html = r#"<div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>"#;
        assert_eq!(classify_challenge_html(html), ChallengeClass::Turnstile);
        assert_eq!(
            extract_turnstile_sitekey(html).as_deref(),
            Some("1x00000000000000000000AA")
        );
        let cf = r#"<title>Just a moment...</title><span>cloudflare</span> challenge-platform"#;
        assert_eq!(classify_challenge_html(cf), ChallengeClass::Unsupported);
    }

    #[test]
    fn honesty_help_refuses_unlocker_parity() {
        let lower = CAPSOLVER_HONESTY_HELP.to_ascii_lowercase();
        assert!(lower.contains("not") && lower.contains("unlocker"));
        assert!(!lower.contains("100% guaranteed"));
        assert!(!lower.contains("undetectable browsing success"));
        // Residual must admit not commercial unlocker parity.
        assert!(
            lower.contains("does not equal commercial web unlocker parity")
                || (lower.contains("not") && lower.contains("commercial web unlocker parity"))
        );
    }
}
