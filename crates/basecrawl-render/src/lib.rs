//! Headless-Chromium (CDP) rendering for `basecrawl`.
//!
//! This crate drives a headless Chromium instance over the Chrome DevTools Protocol to obtain the
//! **post-render** DOM of a page: the browser fetches the document, executes its scripts, and the
//! resulting DOM is serialized back to HTML. This is what lets the `html` format reflect
//! JS-injected content (that a plain HTTP fetch of the source never contains).
//!
//! Rendering is deliberately kept separate from the HTTP fetch path so that formats which only need
//! the served source (e.g. `rawHtml`) never pay for, or depend on, a browser launch.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine;
use headless_chrome::protocol::cdp::{Emulation, Page};
use headless_chrome::{Browser, LaunchOptions, Tab};
use url::Url;

/// Default render timeout (seconds) when the caller does not specify one.
pub const DEFAULT_RENDER_TIMEOUT_SECS: u64 = 30;

/// Default network-idle quiet window: capture once no fetch/XHR has been in flight for this long.
pub const DEFAULT_NETWORK_IDLE_QUIET_MS: u64 = 500;

/// Candidate Chromium executables searched (in order) when `CHROME` is unset.
const CHROME_CANDIDATES: &[&str] = &[
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
];

/// A failure while rendering a page with headless Chromium.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("chrome executable not found (set the CHROME env var to a Chromium binary)")]
    ChromeNotFound,
    #[error("failed to launch headless browser: {0}")]
    Launch(String),
    #[error("failed to render page: {0}")]
    Render(String),
    #[error("render timed out after {0:?}: the page never reached network idle")]
    Timeout(Duration),
    #[error("timed out waiting for selector {selector:?}: {detail}")]
    WaitFor { selector: String, detail: String },
    #[error("browser returned no serialized DOM")]
    NoContent,
}

/// Configuration for a single render.
#[derive(Debug, Clone)]
pub struct RenderConfig {
    /// Whole-render timeout (navigation + smart-wait + evaluation). A page that never settles is
    /// aborted at this bound with [`RenderError::Timeout`] rather than hanging indefinitely.
    pub timeout: Duration,
    /// User-Agent presented to the origin (kept in parity with the HTTP fetch path).
    pub user_agent: String,
    /// When set, capture is blocked until an element matching this CSS selector exists (bounded by
    /// `timeout`). When present it takes precedence over the network-idle wait.
    pub wait_for: Option<String>,
    /// When true (and no `wait_for` selector is set), capture is deferred until the page's network
    /// has been idle (no in-flight fetch/XHR) for `quiet_period`, so JS-injected content that
    /// arrives via a deferred request is present at capture time.
    pub network_idle: bool,
    /// The quiet window that defines "network idle" for the smart wait.
    pub quiet_period: Duration,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS),
            user_agent: String::new(),
            wait_for: None,
            network_idle: true,
            quiet_period: Duration::from_millis(DEFAULT_NETWORK_IDLE_QUIET_MS),
        }
    }
}

/// The product of a render: the serialized post-render DOM.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The cleaned, post-render DOM serialization (see [`render`] for the cleaning policy).
    pub html: String,
}

/// Resolve a Chromium executable: prefer `$CHROME`, then the well-known system locations.
fn resolve_chrome() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CHROME") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    CHROME_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Launch a headless Chromium with the shared flag set used by every rendering path.
///
/// The flags beyond headless (`--force-color-profile=srgb`, `--font-render-hinting=none`,
/// `--hide-scrollbars`) pin color management and text rasterization so that repeated renders of the
/// same static page produce byte-identical pixels (screenshot determinism), while
/// `--disable-dev-shm-usage`/`--disable-gpu` keep Chromium stable in a container. Sandbox is
/// disabled because the crawler runs as root. The returned browser is killed when dropped.
fn launch_browser(timeout: Duration, window_size: (u32, u32)) -> Result<Browser, RenderError> {
    let chrome = resolve_chrome().ok_or(RenderError::ChromeNotFound)?;

    let args: Vec<&OsStr> = vec![
        OsStr::new("--disable-dev-shm-usage"),
        OsStr::new("--disable-gpu"),
        OsStr::new("--hide-scrollbars"),
        OsStr::new("--force-color-profile=srgb"),
        OsStr::new("--font-render-hinting=none"),
    ];
    let options = LaunchOptions::default_builder()
        .path(Some(chrome))
        .headless(true)
        .sandbox(false)
        .window_size(Some(window_size))
        .args(args)
        .idle_browser_timeout(timeout)
        .build()
        .map_err(|e| RenderError::Launch(e.to_string()))?;

    Browser::new(options).map_err(|e| RenderError::Launch(e.to_string()))
}

/// In-page cleaning + serialization script.
///
/// Executed *after* the page has loaded and its scripts have run, so any JS-injected content is
/// already in the DOM. It then removes `<script>`/`<style>`/`<noscript>` nodes (making `html` a
/// cleaned serialization that is deterministically script/style-free and clearly distinct from the
/// raw served source) and returns `document.documentElement.outerHTML`. It never rewrites element
/// URL attributes, so relative asset/link URLs are preserved exactly as authored (consistent,
/// no-rewrite policy).
const CLEAN_AND_SERIALIZE: &str = "(function(){\
var nodes=document.querySelectorAll('script,style,noscript');\
for(var i=0;i<nodes.length;i++){var n=nodes[i];if(n.parentNode){n.parentNode.removeChild(n);}}\
return document.documentElement.outerHTML;\
})()";

/// Installed (via `Page.addScriptToEvaluateOnNewDocument`) before any page script runs, so that
/// every `fetch`/`XMLHttpRequest` the page issues (including deferred requests fired long after
/// load) is counted. It maintains an in-flight counter and a last-activity timestamp that the
/// network-idle probe reads. Wrapping the network APIs before the document's own scripts execute is
/// what makes the smart wait observe requests started via the page's captured references.
const NETWORK_TRACKER_JS: &str = "(function(){\
try{\
if(window.__bcTrackerInstalled){return;}\
window.__bcTrackerInstalled=true;\
window.__bcInflight=0;\
window.__bcLastActivity=Date.now();\
var mark=function(){window.__bcLastActivity=Date.now();};\
var inc=function(){window.__bcInflight++;mark();};\
var dec=function(){window.__bcInflight=Math.max(0,window.__bcInflight-1);mark();};\
if(typeof window.fetch==='function'){\
var of=window.fetch;\
window.fetch=function(){inc();var p;try{p=of.apply(this,arguments);}catch(e){dec();throw e;}\
return Promise.resolve(p).then(function(r){dec();return r;},function(e){dec();throw e;});};\
}\
if(window.XMLHttpRequest&&XMLHttpRequest.prototype){\
var os=XMLHttpRequest.prototype.send;\
XMLHttpRequest.prototype.send=function(){try{inc();this.addEventListener('loadend',dec);}catch(e){}\
return os.apply(this,arguments);};\
}\
}catch(e){}\
})()";

/// Returns a JSON string describing the page's readiness and network activity for the idle probe.
/// A missing tracker (e.g. a page that never ran the injected script) reports a large quiet window
/// so the wait falls back to `readyState`-only, rather than blocking forever.
const IDLE_PROBE_JS: &str = "(function(){\
var la=(typeof window.__bcLastActivity==='number')?window.__bcLastActivity:0;\
var inflight=(typeof window.__bcInflight==='number')?window.__bcInflight:0;\
return JSON.stringify({ready:document.readyState,inflight:inflight,quietMs:Date.now()-la});\
})()";

/// The page's readiness + network-activity snapshot read from [`IDLE_PROBE_JS`].
struct IdleSnapshot {
    ready: String,
    inflight: i64,
    quiet_ms: i64,
}

/// Read a single network-idle snapshot from the tab, or `None` if the probe could not be evaluated.
fn probe_idle(tab: &Tab) -> Option<IdleSnapshot> {
    let evaluated = tab.evaluate(IDLE_PROBE_JS, false).ok()?;
    let raw = match evaluated.value {
        Some(serde_json::Value::String(s)) => s,
        _ => return None,
    };
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    Some(IdleSnapshot {
        ready: parsed.get("ready")?.as_str()?.to_string(),
        inflight: parsed.get("inflight").and_then(serde_json::Value::as_i64)?,
        quiet_ms: parsed.get("quietMs").and_then(serde_json::Value::as_i64)?,
    })
}

/// Block until the page has finished loading and its network has been idle for `quiet_period`,
/// bounded by `deadline`. Returns [`RenderError::Timeout`] (carrying `timeout`) if the page never
/// settles in time (e.g. a page that fires requests forever).
fn wait_for_network_idle(
    tab: &Tab,
    quiet_period: Duration,
    deadline: Instant,
    timeout: Duration,
) -> Result<(), RenderError> {
    let poll = Duration::from_millis(100);
    let quiet_ms = quiet_period.as_millis() as i64;
    loop {
        if Instant::now() >= deadline {
            return Err(RenderError::Timeout(timeout));
        }
        if let Some(snap) = probe_idle(tab) {
            if snap.ready == "complete" && snap.inflight <= 0 && snap.quiet_ms >= quiet_ms {
                return Ok(());
            }
        }
        std::thread::sleep(poll);
    }
}

/// Render `url` with headless Chromium and return its cleaned, post-render DOM serialization.
///
/// The browser is launched headless, navigated to `url`, and allowed to finish loading (so
/// JS-injected content is present) before the DOM is serialized. Capture timing is controlled by
/// [`RenderConfig`]: an explicit `wait_for` selector blocks until that element exists; otherwise the
/// smart network-idle wait defers capture until deferred fetch/XHR content has settled. The whole
/// render is bounded by `config.timeout` — a page that never settles is aborted with
/// [`RenderError::Timeout`] rather than hanging. The spawned browser is terminated when this
/// function returns (its `Browser` handle is dropped), so no browser process is leaked.
pub fn render(url: &Url, config: &RenderConfig) -> Result<Rendered, RenderError> {
    let deadline = Instant::now() + config.timeout;
    let browser = launch_browser(config.timeout, (1280, 800))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    tab.set_default_timeout(config.timeout);
    if !config.user_agent.is_empty() {
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }

    // Install the network in-flight tracker before any page script runs so the smart wait can see
    // fetch/XHR the page issues, including deferred requests.
    tab.call_method(Page::AddScriptToEvaluateOnNewDocument {
        source: NETWORK_TRACKER_JS.to_string(),
        world_name: None,
        include_command_line_api: None,
        run_immediately: Some(true),
    })
    .map_err(|e| RenderError::Render(e.to_string()))?;

    tab.navigate_to(url.as_str())
        .map_err(|e| RenderError::Render(e.to_string()))?;
    tab.wait_until_navigated().map_err(|e| {
        if Instant::now() >= deadline {
            RenderError::Timeout(config.timeout)
        } else {
            RenderError::Render(e.to_string())
        }
    })?;

    match &config.wait_for {
        // An explicit selector is the authoritative capture signal (it also handles content injected
        // by a timer with no network activity, which a network-idle wait would miss).
        Some(selector) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RenderError::Timeout(config.timeout));
            }
            tab.wait_for_element_with_custom_timeout(selector, remaining)
                .map_err(|e| RenderError::WaitFor {
                    selector: selector.clone(),
                    detail: e.to_string(),
                })?;
        }
        None => {
            if config.network_idle {
                wait_for_network_idle(&tab, config.quiet_period, deadline, config.timeout)?;
            }
        }
    }

    let evaluated = tab
        .evaluate(CLEAN_AND_SERIALIZE, false)
        .map_err(|e| RenderError::Render(e.to_string()))?;

    match evaluated.value {
        Some(serde_json::Value::String(html)) if !html.is_empty() => Ok(Rendered { html }),
        _ => Err(RenderError::NoContent),
    }
}

/// Default screenshot viewport width (CSS px) when the caller does not specify one.
pub const DEFAULT_VIEWPORT_WIDTH: u32 = 1280;
/// Default screenshot viewport height (CSS px) when the caller does not specify one.
pub const DEFAULT_VIEWPORT_HEIGHT: u32 = 800;

/// Configuration for a single deterministic screenshot capture.
#[derive(Debug, Clone)]
pub struct ScreenshotConfig {
    /// Whole-capture timeout (navigation + rasterization).
    pub timeout: Duration,
    /// User-Agent presented to the origin (kept in parity with the HTTP fetch path).
    pub user_agent: String,
    /// Layout viewport width in CSS pixels. Captured at device-scale-factor 1, so the produced
    /// image width equals this value exactly.
    pub width: u32,
    /// Layout viewport height in CSS pixels.
    pub height: u32,
    /// When true, capture the entire scrollable page (beyond the fold) rather than just the
    /// viewport rectangle.
    pub full_page: bool,
}

impl Default for ScreenshotConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS),
            user_agent: String::new(),
            width: DEFAULT_VIEWPORT_WIDTH,
            height: DEFAULT_VIEWPORT_HEIGHT,
            full_page: false,
        }
    }
}

/// The product of a capture: the PNG both decoded and in its base64 wire form.
#[derive(Debug, Clone)]
pub struct Screenshot {
    /// Decoded PNG bytes.
    pub png: Vec<u8>,
    /// Standard base64 encoding of [`Screenshot::png`] (the form embedded in the ScrapeProof).
    pub base64: String,
}

/// The full scrollable content height (CSS px) of the currently-loaded document.
fn content_height(tab: &Tab) -> Result<u32, RenderError> {
    let js = "Math.max(\
document.documentElement.scrollHeight,\
document.documentElement.offsetHeight,\
document.body?document.body.scrollHeight:0,\
document.body?document.body.offsetHeight:0)";
    let evaluated = tab
        .evaluate(js, false)
        .map_err(|e| RenderError::Render(e.to_string()))?;
    evaluated
        .value
        .and_then(|v| v.as_f64())
        .filter(|h| *h >= 1.0)
        .map(|h| h.ceil() as u32)
        .ok_or(RenderError::NoContent)
}

/// Capture a deterministic PNG screenshot of `url` with headless Chromium.
///
/// The layout viewport is pinned via `Emulation.setDeviceMetricsOverride` at device-scale-factor 1,
/// so the produced image width matches [`ScreenshotConfig::width`] exactly (no DPR scaling). For a
/// viewport capture the clip is the viewport rectangle; for a full-page capture the clip spans the
/// entire scrollable content height with `captureBeyondViewport` enabled, yielding an image taller
/// than the viewport. Rendering the same static page twice produces byte-identical PNGs (fixed
/// color profile + font hinting, no embedded timestamps). The spawned browser is killed on return.
pub fn screenshot(url: &Url, config: &ScreenshotConfig) -> Result<Screenshot, RenderError> {
    let browser = launch_browser(config.timeout, (config.width, config.height))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    tab.set_default_timeout(config.timeout);
    if !config.user_agent.is_empty() {
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }

    tab.call_method(Emulation::SetDeviceMetricsOverride {
        width: config.width,
        height: config.height,
        device_scale_factor: 1.0,
        mobile: false,
        scale: None,
        screen_width: None,
        screen_height: None,
        position_x: None,
        position_y: None,
        dont_set_visible_size: None,
        screen_orientation: None,
        viewport: None,
        display_feature: None,
        device_posture: None,
    })
    .map_err(|e| RenderError::Render(e.to_string()))?;

    tab.navigate_to(url.as_str())
        .map_err(|e| RenderError::Render(e.to_string()))?;
    tab.wait_until_navigated()
        .map_err(|e| RenderError::Render(e.to_string()))?;

    let clip_height = if config.full_page {
        content_height(&tab)?.max(config.height)
    } else {
        config.height
    };
    let clip = Page::Viewport {
        x: 0.0,
        y: 0.0,
        width: f64::from(config.width),
        height: f64::from(clip_height),
        scale: 1.0,
    };

    let data = tab
        .call_method(Page::CaptureScreenshot {
            format: Some(Page::CaptureScreenshotFormatOption::Png),
            quality: None,
            clip: Some(clip),
            from_surface: Some(true),
            capture_beyond_viewport: Some(config.full_page),
            optimize_for_speed: None,
        })
        .map_err(|e| RenderError::Render(e.to_string()))?
        .data;

    let png = base64::prelude::BASE64_STANDARD
        .decode(&data)
        .map_err(|e| RenderError::Render(format!("invalid base64 screenshot: {e}")))?;
    if png.is_empty() {
        return Err(RenderError::NoContent);
    }
    Ok(Screenshot { png, base64: data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_script_targets_script_style_noscript() {
        assert!(CLEAN_AND_SERIALIZE.contains("script,style,noscript"));
        assert!(CLEAN_AND_SERIALIZE.contains("outerHTML"));
    }

    #[test]
    fn default_config_uses_default_timeout() {
        let cfg = RenderConfig::default();
        assert_eq!(
            cfg.timeout,
            Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS)
        );
    }

    #[test]
    fn default_config_enables_network_idle_wait() {
        let cfg = RenderConfig::default();
        assert!(cfg.network_idle, "network-idle smart wait is on by default");
        assert!(cfg.wait_for.is_none(), "no selector wait by default");
        assert_eq!(
            cfg.quiet_period,
            Duration::from_millis(DEFAULT_NETWORK_IDLE_QUIET_MS)
        );
    }

    #[test]
    fn network_tracker_wraps_fetch_and_xhr() {
        // The tracker must wrap both dynamic-request APIs and record activity for the idle probe.
        assert!(NETWORK_TRACKER_JS.contains("window.fetch"));
        assert!(NETWORK_TRACKER_JS.contains("XMLHttpRequest.prototype.send"));
        assert!(NETWORK_TRACKER_JS.contains("__bcInflight"));
        assert!(NETWORK_TRACKER_JS.contains("__bcLastActivity"));
    }

    #[test]
    fn idle_probe_reports_ready_inflight_and_quiet() {
        assert!(IDLE_PROBE_JS.contains("readyState"));
        assert!(IDLE_PROBE_JS.contains("inflight"));
        assert!(IDLE_PROBE_JS.contains("quietMs"));
    }

    #[test]
    fn default_screenshot_config_is_1280x800_viewport_capture() {
        let cfg = ScreenshotConfig::default();
        assert_eq!(cfg.width, 1280);
        assert_eq!(cfg.height, 800);
        assert!(!cfg.full_page);
        assert_eq!(
            cfg.timeout,
            Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS)
        );
    }

    #[test]
    fn resolve_chrome_prefers_env_override() {
        // A non-existent override falls through to the system candidates rather than being returned.
        std::env::set_var("CHROME", "/definitely/not/a/real/chrome/binary");
        let resolved = resolve_chrome();
        std::env::remove_var("CHROME");
        if let Some(path) = resolved {
            assert_ne!(path, PathBuf::from("/definitely/not/a/real/chrome/binary"));
        }
    }
}
