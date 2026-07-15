//! Hard-path Chromium identity policy (M13 / VAL-STEALTH-*).
//!
//! When a scrape is classed **hard** (residential/mobile proxy class, explicit difficulty, or
//! forced browser path), the product must dial through real Chromium with a coherent stealth
//! baseline — never a soft-only rustls identity masquerading as residential ok.
//!
//! Sticky browser profiles keep cookies/storage for multipage work **inside one task_id**, and
//! are wiped when the task ends or a different task_id starts (VAL-STEALTH-011..014).
//!
//! Honesty: this is a measured success-rate baseline under TDX. It is **not** anonymity and
//! never claims "undetectable" or universal bot defeat.

use basecrawl_proof::{FetchPath, ProxyClass};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

/// Optional difficulty token used by tasks / CLI (`soft|hard|challenge`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteDifficulty {
    Soft,
    Hard,
}

impl SiteDifficulty {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "soft" | "easy" | "direct" => Some(Self::Soft),
            "hard" | "challenge" | "residential" => Some(Self::Hard),
            _ => None,
        }
    }
}

/// Inputs that decide whether the hard Chromium path is required.
#[derive(Debug, Clone, Copy)]
pub struct HardPathDecision {
    pub proxy_class: Option<ProxyClass>,
    pub difficulty: Option<SiteDifficulty>,
    pub force_browser: bool,
    pub render_enabled: bool,
    pub needs_browser_formats: bool,
}

/// True when the scrape **must** go through Chromium (VAL-STEALTH-001).
///
/// Residential/mobile classes and hard difficulty always force browser; soft targets remain free.
pub fn requires_chromium_hard_path(decision: HardPathDecision) -> bool {
    if decision.force_browser {
        return true;
    }
    if let Some(class) = decision.proxy_class {
        if matches!(class, ProxyClass::Residential | ProxyClass::Mobile) {
            return true;
        }
    }
    if matches!(decision.difficulty, Some(SiteDifficulty::Hard)) {
        return true;
    }
    false
}

/// Whether this scrape will actually launch Chromium (formats/JS or forced hard path).
pub fn will_launch_chromium(
    decision: HardPathDecision,
    hard_required: bool,
) -> Result<bool, StealthPolicyError> {
    if hard_required {
        if !decision.render_enabled {
            return Err(StealthPolicyError::HardPathDisabled {
                reason: "hard/residential path requires Chromium rendering; refuse --no-js \
                         dual-stack fallback (VAL-STEALTH-001/017)"
                    .to_string(),
            });
        }
        return Ok(true);
    }
    Ok(decision.render_enabled && decision.needs_browser_formats)
}

/// Truthful fetch path label for egress (VAL-STEALTH-010).
pub fn truthful_fetch_path(chromium_used: bool) -> FetchPath {
    if chromium_used {
        FetchPath::Chromium
    } else {
        FetchPath::Direct
    }
}

/// Fail-closed policy errors for hard-path identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StealthPolicyError {
    #[error("hard path policy refused dual-stack identity: {reason}")]
    HardPathDisabled { reason: String },
    #[error("sticky browser profile failed: {0}")]
    Profile(String),
}

/// Process-wide sticky profile registry keyed by task_id.
///
/// Same key is reused for multipage cookie continuity (VAL-STEALTH-011). Distinct keys never
/// share directories; wiping one task does not touch another concurrent scrape's jar
/// (VAL-STEALTH-013/014). CLI scrapes typically hold one key at a time and wipe on completion.
static STICKY_PROFILES: LazyLock<Mutex<HashMap<String, PathBuf>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Last task key acquired in this process (CLI sequential wipe helper).
static LAST_STICKY_KEY: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// Allocate (or re-use) a sticky Chromium profile directory for `task_key`.
///
/// Same key returns the same directory so multipage/actions inherit cookies. First acquisition of
/// a key always starts from an empty directory.
pub fn acquire_sticky_profile(task_key: &str) -> Result<PathBuf, StealthPolicyError> {
    let key = normalize_task_key(task_key);
    let mut guard = STICKY_PROFILES
        .lock()
        .map_err(|_| StealthPolicyError::Profile("sticky profile mutex poisoned".into()))?;
    if let Some(existing) = guard.get(&key) {
        if existing.is_dir() {
            let mut last = LAST_STICKY_KEY
                .lock()
                .map_err(|_| StealthPolicyError::Profile("sticky key mutex poisoned".into()))?;
            *last = Some(key);
            return Ok(existing.clone());
        }
        guard.remove(&key);
    }
    let base = sticky_profile_root();
    fs::create_dir_all(&base).map_err(|error| {
        StealthPolicyError::Profile(format!("create sticky profile root failed: {error}"))
    })?;
    let dir = base.join(&key);
    // Re-attach a persisted profile left by `--keep-browser-profile` (same task_id, new process)
    // so multipage/session stickiness survives sequential CLI invocations without wiping cookies.
    if dir.is_dir() {
        guard.insert(key.clone(), dir.clone());
        let mut last = LAST_STICKY_KEY
            .lock()
            .map_err(|_| StealthPolicyError::Profile("sticky key mutex poisoned".into()))?;
        *last = Some(key);
        return Ok(dir);
    }
    fs::create_dir_all(&dir).map_err(|error| {
        StealthPolicyError::Profile(format!("create sticky profile dir failed: {error}"))
    })?;
    guard.insert(key.clone(), dir.clone());
    let mut last = LAST_STICKY_KEY
        .lock()
        .map_err(|_| StealthPolicyError::Profile("sticky key mutex poisoned".into()))?;
    *last = Some(key);
    Ok(dir)
}

/// Wipe the sticky profile for `task_key` if it is currently held.
///
/// Safe to call after a scrape completes. Does not require the operator to kill residual Chromium
/// (VAL-STEALTH-014): launch uses Drop to stop the browser, and this removes the on-disk jar.
pub fn wipe_sticky_profile(task_key: &str) -> Result<(), StealthPolicyError> {
    let key = normalize_task_key(task_key);
    let mut guard = STICKY_PROFILES
        .lock()
        .map_err(|_| StealthPolicyError::Profile("sticky profile mutex poisoned".into()))?;
    if key == "__all__" {
        for (_k, dir) in guard.drain() {
            let _ = fs::remove_dir_all(dir);
        }
        let mut last = LAST_STICKY_KEY
            .lock()
            .map_err(|_| StealthPolicyError::Profile("sticky key mutex poisoned".into()))?;
        *last = None;
        return Ok(());
    }
    if let Some(dir) = guard.remove(&key) {
        let _ = fs::remove_dir_all(dir);
    }
    let mut last = LAST_STICKY_KEY
        .lock()
        .map_err(|_| StealthPolicyError::Profile("sticky key mutex poisoned".into()))?;
    if last.as_deref() == Some(key.as_str()) {
        *last = None;
    }
    Ok(())
}

/// Wipe the sticky profile of the last acquired task key (end-of-scrape hygiene).
///
/// Prefer explicit [`wipe_sticky_profile`] when the task id is known. This helper covers the
/// common single-scrape CLI path without erasing concurrent in-process scrapes for other keys.
pub fn wipe_current_sticky_profile() -> Result<(), StealthPolicyError> {
    let key = {
        let last = LAST_STICKY_KEY
            .lock()
            .map_err(|_| StealthPolicyError::Profile("sticky key mutex poisoned".into()))?;
        last.clone()
    };
    match key {
        Some(k) => wipe_sticky_profile(&k),
        None => Ok(()),
    }
}

fn sticky_profile_root() -> PathBuf {
    std::env::var_os("BASECRAWL_BROWSER_PROFILE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("basecrawl-sticky-profiles"))
}

fn normalize_task_key(task_key: &str) -> String {
    let trimmed = task_key.trim();
    if trimmed.is_empty() {
        return "anonymous".to_string();
    }
    // Filesystem-safe: keep alnum + a few separators; hash overflow for exotic task ids.
    let safe: String = trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.len() > 96 {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(trimmed.as_bytes());
        format!(
            "t-{:x}",
            u128::from_be_bytes({
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&digest[..16]);
                buf
            })
        )
    } else {
        safe
    }
}

/// Best-effort probe for automation flags in a launch argv set used by tests (VAL-STEALTH-004).
pub fn stealth_argv_is_clean(args: &[&str]) -> bool {
    !args.contains(&"--enable-automation")
        && args
            .iter()
            .any(|arg| arg.contains("disable-blink-features=AutomationControlled"))
}

/// Detect classic challenge / captcha interstitials so hard-path blocks are never scored as
/// silent primary-content success (VAL-STEALTH-016, VAL-UNLOCK-001/002/018).
///
/// Pure, deterministic pure-function of `(html, status_code)`: same inputs always yield the same
/// decision. Detect only — never invent a solve path, marketplace call, or success upgrade.
pub fn looks_like_challenge_interstitial(html: &str, status_code: u16) -> bool {
    let lower = html.to_ascii_lowercase();
    if matches!(status_code, 401 | 403 | 429 | 503) {
        // Only treat wrap statuses as challenge-ish when body also looks defensive; bare 403s may be real.
        return lower.contains("captcha")
            || lower.contains("cf-mitigated")
            || lower.contains("just a moment")
            || lower.contains("attention required")
            || lower.contains("access denied")
            || lower.contains("bot detection")
            || lower.contains("challenge-platform")
            || lower.contains("cf-browser-verification")
            || lower.contains("cf-challenge")
            || lower.contains("turnstile");
    }
    // 2xx / other: require multi-signal interstitial markers so ordinary content is not false-positive.
    // Captcha widget pages (Turnstile / reCAPTCHA shells) are never primary userdata success
    // (VAL-UNLOCK-002). Default remains detect-not-solve; optional CapSolver is a gated provider
    // module and still refuses forged content_success without applied tokens (VAL-SOLVE-*).
    let cf_challenge = (lower.contains("just a moment") && lower.contains("cloudflare"))
        || lower.contains("cf-browser-verification")
        || lower.contains("cf-challenge")
        || lower.contains("challenge-platform")
        || (lower.contains("checking your browser") && lower.contains("cloudflare"));
    let turnstile_or_recaptcha = (lower.contains("turnstile")
        && (lower.contains("challenge")
            || lower.contains("cf-turnstile")
            || lower.contains("data-sitekey")))
        || lower.contains("g-recaptcha")
        || lower.contains("h-captcha")
        || lower.contains("hcaptcha")
        || (lower.contains("captcha")
            && (lower.contains("data-sitekey")
                || lower.contains("verify you are human")
                || lower.contains("complete the captcha")
                || lower.contains("captcha-form")
                || lower.contains("recaptcha")));
    cf_challenge
        || turnstile_or_recaptcha
        || lower.contains("hdn-captcha")
        || lower.contains("permanent redirect to a captcha")
}

/// Prove a path is gone / empty for tests.
pub fn profile_dir_exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use basecrawl_proof::ProxyClass;

    #[test]
    fn residential_requires_chromium() {
        assert!(requires_chromium_hard_path(HardPathDecision {
            proxy_class: Some(ProxyClass::Residential),
            difficulty: None,
            force_browser: false,
            render_enabled: true,
            needs_browser_formats: false,
        }));
    }

    #[test]
    fn soft_direct_does_not_require_chromium() {
        assert!(!requires_chromium_hard_path(HardPathDecision {
            proxy_class: Some(ProxyClass::Direct),
            difficulty: Some(SiteDifficulty::Soft),
            force_browser: false,
            render_enabled: true,
            needs_browser_formats: false,
        }));
    }

    #[test]
    fn hard_without_js_fails_closed() {
        let err = will_launch_chromium(
            HardPathDecision {
                proxy_class: Some(ProxyClass::Residential),
                difficulty: None,
                force_browser: false,
                render_enabled: false,
                needs_browser_formats: true,
            },
            true,
        )
        .expect_err("must refuse dual-stack");
        assert!(matches!(err, StealthPolicyError::HardPathDisabled { .. }));
    }

    #[test]
    fn sticky_profile_isolates_tasks() {
        let a = acquire_sticky_profile("task-A-stealth").expect("profile a");
        fs::write(a.join("cookie.db"), b"session-a").expect("write");
        let b = acquire_sticky_profile("task-B-stealth").expect("profile b");
        assert_ne!(a, b);
        // Concurrent keys coexist; wiping B leaves A intact until A is wiped.
        assert!(
            a.exists(),
            "other concurrent task profile remains until wiped"
        );
        assert!(b.exists());
        wipe_sticky_profile("task-B-stealth").expect("wipe b");
        assert!(!b.exists());
        assert!(a.exists());
        wipe_sticky_profile("task-A-stealth").expect("wipe a");
        assert!(!a.exists());
    }

    #[test]
    fn same_task_reuses_profile_dir() {
        let a1 = acquire_sticky_profile("sticky-same").expect("a1");
        fs::write(a1.join("jar"), b"1").expect("write");
        let a2 = acquire_sticky_profile("sticky-same").expect("a2");
        assert_eq!(a1, a2);
        assert_eq!(fs::read(a2.join("jar")).unwrap(), b"1");
        wipe_sticky_profile("sticky-same").ok();
    }

    #[test]
    fn sequential_cli_style_wipe_current_does_not_need_manual_kill() {
        let dir = acquire_sticky_profile("cli-seq").expect("profile");
        assert!(dir.exists());
        wipe_current_sticky_profile().expect("wipe last");
        assert!(!dir.exists());
    }

    #[test]
    fn stealth_argv_drops_enable_automation() {
        assert!(stealth_argv_is_clean(&[
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
        ]));
        assert!(!stealth_argv_is_clean(&[
            "--enable-automation",
            "--disable-blink-features=AutomationControlled",
        ]));
    }

    #[test]
    fn challenge_detect_is_deterministic_for_cf_and_captcha() {
        let cf = r#"<title>Just a moment...</title><span>cloudflare</span> challenge-platform cf-challenge"#;
        let captcha = r#"<div class="g-recaptcha" data-sitekey="x"></div><form id="captcha-form">verify you are human</form>"#;
        assert!(looks_like_challenge_interstitial(cf, 403));
        assert!(looks_like_challenge_interstitial(cf, 403));
        assert!(looks_like_challenge_interstitial(captcha, 200));
        assert_eq!(
            looks_like_challenge_interstitial(captcha, 200),
            looks_like_challenge_interstitial(captcha, 200)
        );
        // Ordinary content is not a captcha interstitial.
        assert!(!looks_like_challenge_interstitial(
            "<html><body><h1>Hello bookstore</h1><p>price $10</p></body></html>",
            200
        ));
    }
}
