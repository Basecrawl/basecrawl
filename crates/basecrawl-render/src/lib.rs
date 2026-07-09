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
use std::time::Duration;

use base64::Engine;
use headless_chrome::protocol::cdp::{Emulation, Page};
use headless_chrome::{Browser, LaunchOptions, Tab};
use url::Url;

/// Default render timeout (seconds) when the caller does not specify one.
pub const DEFAULT_RENDER_TIMEOUT_SECS: u64 = 30;

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
    #[error("browser returned no serialized DOM")]
    NoContent,
}

/// Configuration for a single render.
#[derive(Debug, Clone)]
pub struct RenderConfig {
    /// Whole-render timeout (navigation + evaluation). A page that never settles aborts near this.
    pub timeout: Duration,
    /// User-Agent presented to the origin (kept in parity with the HTTP fetch path).
    pub user_agent: String,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS),
            user_agent: String::new(),
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

/// Render `url` with headless Chromium and return its cleaned, post-render DOM serialization.
///
/// The browser is launched with `--no-sandbox --disable-dev-shm-usage --disable-gpu` (headless),
/// navigated to `url`, and allowed to finish loading (so JS-injected content is present) before the
/// DOM is serialized. The spawned browser is terminated when this function returns (its `Browser`
/// handle is dropped), so no browser process is leaked.
pub fn render(url: &Url, config: &RenderConfig) -> Result<Rendered, RenderError> {
    let browser = launch_browser(config.timeout, (1280, 800))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    tab.set_default_timeout(config.timeout);
    if !config.user_agent.is_empty() {
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }

    tab.navigate_to(url.as_str())
        .map_err(|e| RenderError::Render(e.to_string()))?;
    tab.wait_until_navigated()
        .map_err(|e| RenderError::Render(e.to_string()))?;

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
