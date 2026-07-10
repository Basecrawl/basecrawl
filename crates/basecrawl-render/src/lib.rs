//! Headless-Chromium (CDP) rendering for `basecrawl`.
//!
//! This crate drives a headless Chromium instance over the Chrome DevTools Protocol to obtain the
//! **post-render** DOM of a page: the browser fetches the document, executes its scripts, and the
//! resulting DOM is serialized back to HTML. This is what lets the `html` format reflect
//! JS-injected content (that a plain HTTP fetch of the source never contains).
//!
//! Rendering is deliberately kept separate from the HTTP fetch path so that formats which only need
//! the served source (e.g. `rawHtml`) never pay for, or depend on, a browser launch.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use headless_chrome::browser::tab::RequestPausedDecision;
use headless_chrome::protocol::cdp::{
    Emulation, Fetch,
    Network::{ErrorReason, ResourceType},
    Page,
};
use headless_chrome::{Browser, LaunchOptions, Tab};
use serde::Deserialize;
use url::Url;

/// Default render timeout (seconds) when the caller does not specify one.
pub const DEFAULT_RENDER_TIMEOUT_SECS: u64 = 30;

/// Default network-idle quiet window: capture once no fetch/XHR has been in flight for this long.
pub const DEFAULT_NETWORK_IDLE_QUIET_MS: u64 = 500;

/// Default cap on client-side redirect hops (meta-refresh / `window.location`). Kept equal to the
/// HTTP redirect cap so a client redirect loop is bounded by the same limit as an HTTP one.
pub const DEFAULT_MAX_REDIRECTS: usize = 20;

/// Default maximum number of auto-scroll steps used to collect infinite-scroll / lazy-loaded
/// content before giving up (each step is also bounded by the render deadline).
pub const DEFAULT_MAX_SCROLLS: usize = 15;

/// Default cap on the number of browser subresources accepted during one rendered DOM capture.
///
/// The top-level document is excluded because basecrawl's direct fetch already applies its
/// `max_body_bytes` cap before Chromium is launched. Every image, stylesheet, script, font, XHR,
/// and similar browser subresource is counted.
pub const DEFAULT_MAX_RENDER_SUBRESOURCES: usize = 128;

/// Default cap on cumulative accepted subresource bytes during one rendered DOM capture.
///
/// CDP intercepts each response before its body is consumed, so a declared `Content-Length` that
/// would carry the aggregate beyond this cap is blocked. Resources without a declared length are
/// still bounded by the independent subresource count cap.
pub const DEFAULT_MAX_RENDER_BYTES: u64 = 20 * 1024 * 1024;

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
    #[error("exceeded the maximum of {max} client-side redirect hop(s)")]
    TooManyRedirects { max: usize },
    #[error("browser returned no serialized DOM")]
    NoContent,
}

/// Direction of a scripted [`Action::Scroll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScrollDirection {
    /// Scroll one viewport down (the default).
    #[default]
    Down,
    /// Scroll one viewport up.
    Up,
}

/// A single scripted navigation action, executed in the order supplied after the page has settled.
///
/// The wire form is a tagged JSON object (`{"type": "...", ...}`) so a caller can pass an ordered
/// action list on the command line, e.g.
/// `[{"type":"click","selector":"#more"},{"type":"wait","milliseconds":500}]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Action {
    /// Click the first element matching a CSS selector.
    Click { selector: String },
    /// Scroll the viewport one screen in a direction.
    Scroll {
        #[serde(default)]
        direction: ScrollDirection,
    },
    /// Pause for a fixed number of milliseconds (bounded by the render deadline).
    Wait {
        #[serde(default)]
        milliseconds: u64,
    },
    /// Block until an element matching a CSS selector exists (bounded by the render deadline).
    WaitForSelector { selector: String },
}

/// Configuration for a single render.
#[derive(Debug, Clone)]
pub struct RenderConfig {
    /// Whole-render timeout (navigation + smart-wait + evaluation). A page that never settles is
    /// aborted at this bound with [`RenderError::Timeout`] rather than hanging indefinitely.
    pub timeout: Duration,
    /// User-Agent presented to the origin (kept in parity with the HTTP fetch path).
    pub user_agent: String,
    /// Validated effective request headers, including the controlled User-Agent, sent in order to
    /// same-origin rendered document and subresource requests.
    pub request_headers: Vec<(String, String)>,
    /// Origin that supplied `request_headers`. The browser removes every caller-controlled field
    /// before a request to another scheme, host, or effective port. `None` scopes headers to the
    /// URL passed to `render`/`screenshot`, which is safe for standalone callers.
    pub credential_origin: Option<Url>,
    /// Minimum interval between browser requests to one scheme/host/port origin.
    pub crawl_delay: Duration,
    /// Maximum non-document requests accepted during this render.
    pub max_subresources: usize,
    /// Maximum sum of accepted declared subresource response bytes during this render.
    pub max_resource_bytes: u64,
    /// When set, capture is blocked until an element matching this CSS selector exists (bounded by
    /// `timeout`). When present it takes precedence over the network-idle wait.
    pub wait_for: Option<String>,
    /// When true (and no `wait_for` selector is set), capture is deferred until the page's network
    /// has been idle (no in-flight fetch/XHR) for `quiet_period`, so JS-injected content that
    /// arrives via a deferred request is present at capture time.
    pub network_idle: bool,
    /// The quiet window that defines "network idle" for the smart wait.
    pub quiet_period: Duration,
    /// Scripted actions executed in order after the page settles and before capture.
    pub actions: Vec<Action>,
    /// When true, client-side redirects (meta-refresh / `window.location`) are followed and bounded
    /// by `max_redirects`; a loop exceeding the cap is aborted with [`RenderError::TooManyRedirects`].
    pub follow_client_redirects: bool,
    /// The client-side redirect hop cap (mirrors the HTTP redirect cap).
    pub max_redirects: usize,
    /// When true, the page is auto-scrolled to collect infinite-scroll / lazy-loaded content.
    pub auto_scroll: bool,
    /// The maximum number of auto-scroll steps attempted before giving up.
    pub max_scrolls: usize,
    /// When true, a detected cookie/consent overlay is dismissed before capture.
    pub dismiss_consent: bool,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_RENDER_TIMEOUT_SECS),
            user_agent: String::new(),
            request_headers: Vec::new(),
            credential_origin: None,
            crawl_delay: Duration::ZERO,
            max_subresources: DEFAULT_MAX_RENDER_SUBRESOURCES,
            max_resource_bytes: DEFAULT_MAX_RENDER_BYTES,
            wait_for: None,
            network_idle: true,
            quiet_period: Duration::from_millis(DEFAULT_NETWORK_IDLE_QUIET_MS),
            actions: Vec::new(),
            follow_client_redirects: true,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            auto_scroll: true,
            max_scrolls: DEFAULT_MAX_SCROLLS,
            dismiss_consent: true,
        }
    }
}

/// The product of a render: the serialized post-render DOM.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The cleaned, post-render DOM serialization (see [`render`] for the cleaning policy).
    pub html: String,
    /// Observable aggregate resource accounting for this browser render.
    pub resource_usage: RenderResourceUsage,
}

/// Browser subresource accounting and cap outcome surfaced by the core proof response block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderResourceUsage {
    /// Number of non-document browser requests accepted by the cap guard.
    pub subresource_count: u64,
    /// Sum of declared `Content-Length` values for accepted browser subresource responses.
    pub resource_bytes: u64,
    /// Whether a request or response was blocked due to either configured aggregate cap.
    pub cap_exceeded: bool,
}

#[derive(Debug, Default)]
struct RenderResourceState {
    usage: RenderResourceUsage,
    last_request_at: HashMap<RenderOrigin, Instant>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RenderOrigin {
    scheme: String,
    host: String,
    port: u16,
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

/// Configure per-origin pacing and aggregate subresource caps before page navigation starts.
///
/// Fetch interception pauses every non-document request before it is sent, allowing the count cap
/// and per-origin delay to prevent a request from reaching the origin. Response-stage interception
/// happens after headers but before the body is consumed, so a declared content length that would
/// exceed the cumulative cap is cancelled before it is downloaded.
fn configure_resource_guard(
    tab: &Tab,
    config: &RenderConfig,
    state: Arc<Mutex<RenderResourceState>>,
    credential_origin: &Url,
    deadline: Instant,
) -> Result<(), RenderError> {
    let patterns = [
        Fetch::RequestPattern {
            url_pattern: None,
            resource_Type: None,
            request_stage: Some(Fetch::RequestStage::Request),
        },
        Fetch::RequestPattern {
            url_pattern: None,
            resource_Type: None,
            request_stage: Some(Fetch::RequestStage::Response),
        },
    ];
    tab.enable_fetch(Some(&patterns), None)
        .map_err(|error| RenderError::Render(error.to_string()))?;

    let crawl_delay = config.crawl_delay;
    let max_subresources = config.max_subresources as u64;
    let max_resource_bytes = config.max_resource_bytes;
    let request_headers = config.request_headers.clone();
    let credential_origin = credential_origin.clone();
    let timeout = config.timeout;
    tab.enable_request_interception(Arc::new(
        move |_transport, _session_id, paused: Fetch::events::RequestPausedEvent| {
            let is_document = paused.params.resource_Type == ResourceType::Document;
            if paused.params.response_status_code.is_some() {
                if is_document {
                    return RequestPausedDecision::Continue(None);
                }
                let declared_bytes = paused
                    .params
                    .response_headers
                    .as_deref()
                    .and_then(declared_content_length)
                    .unwrap_or(0);
                let mut guard = state
                    .lock()
                    .expect("render resource guard mutex must not be poisoned");
                if guard.usage.resource_bytes.saturating_add(declared_bytes) > max_resource_bytes {
                    guard.usage.cap_exceeded = true;
                    return RequestPausedDecision::Fail(Fetch::FailRequest {
                        request_id: paused.params.request_id,
                        error_reason: ErrorReason::BlockedByClient,
                    });
                }
                guard.usage.resource_bytes += declared_bytes;
                return RequestPausedDecision::Continue(None);
            }

            let origin = origin_for_url(&paused.params.request.url);
            let mut guard = state
                .lock()
                .expect("render resource guard mutex must not be poisoned");
            if let Some(origin) = origin {
                if !crawl_delay.is_zero() {
                    if let Some(previous) = guard.last_request_at.get(&origin) {
                        let elapsed = previous.elapsed();
                        if elapsed < crawl_delay {
                            let wait = crawl_delay - elapsed;
                            let Ok(remaining) = remaining(deadline, timeout) else {
                                return RequestPausedDecision::Fail(Fetch::FailRequest {
                                    request_id: paused.params.request_id,
                                    error_reason: ErrorReason::TimedOut,
                                });
                            };
                            if wait >= remaining {
                                return RequestPausedDecision::Fail(Fetch::FailRequest {
                                    request_id: paused.params.request_id,
                                    error_reason: ErrorReason::TimedOut,
                                });
                            }
                            std::thread::sleep(wait);
                        }
                    }
                }
                guard.last_request_at.insert(origin, Instant::now());
            }
            if is_document {
                return continue_with_effective_headers(
                    paused,
                    &request_headers,
                    &credential_origin,
                );
            }
            if guard.usage.subresource_count >= max_subresources {
                guard.usage.cap_exceeded = true;
                return RequestPausedDecision::Fail(Fetch::FailRequest {
                    request_id: paused.params.request_id,
                    error_reason: ErrorReason::BlockedByClient,
                });
            }
            guard.usage.subresource_count += 1;
            continue_with_effective_headers(paused, &request_headers, &credential_origin)
        },
    ))
    .map_err(|error| RenderError::Render(error.to_string()))
}

/// Resume a paused request with caller headers restricted to their initiating origin.
///
/// CDP's `Network.setExtraHTTPHeaders` takes an object, so it discards duplicate keys and has no
/// field-order contract. `Fetch.continueRequest` accepts a header-entry list instead. Browser-owned
/// fields remain present. Any case-insensitive collision with a caller-controlled field is removed
/// first, then re-added only when the paused request has the initiating scheme, host, and port.
/// This guards cross-origin HTTP redirects, client navigations, iframes, and subresources even when
/// Chromium has copied headers from a prior same-origin request into the paused request.
fn continue_with_effective_headers(
    paused: Fetch::events::RequestPausedEvent,
    effective_headers: &[(String, String)],
    credential_origin: &Url,
) -> RequestPausedDecision {
    let is_same_origin = same_origin_url(&paused.params.request.url, credential_origin);
    let mut headers = paused
        .params
        .request
        .headers
        .0
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .map(|headers| {
            headers
                .iter()
                .map(|(name, value)| Fetch::HeaderEntry {
                    name: name.clone(),
                    value: value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    headers.retain(|header| {
        !effective_headers.iter().any(|(name, _)| {
            header.name.eq_ignore_ascii_case(name)
                && (is_same_origin || !name.eq_ignore_ascii_case("user-agent"))
        })
    });
    if is_same_origin {
        headers.extend(
            effective_headers
                .iter()
                .map(|(name, value)| Fetch::HeaderEntry {
                    name: name.clone(),
                    value: value.clone(),
                }),
        );
    }

    RequestPausedDecision::Continue(Some(Fetch::ContinueRequest {
        request_id: paused.params.request_id,
        url: None,
        method: None,
        post_data: None,
        headers: Some(headers),
        intercept_response: None,
    }))
}

fn origin_for_url(raw_url: &str) -> Option<RenderOrigin> {
    let url = Url::parse(raw_url).ok()?;
    Some(RenderOrigin {
        scheme: url.scheme().to_ascii_lowercase(),
        host: url.host_str()?.to_ascii_lowercase(),
        port: url.port_or_known_default()?,
    })
}

/// Compare a browser request URL with the caller credential origin. Origin equality includes the
/// scheme and effective port, so an HTTP→HTTPS transition and an HTTPS→HTTP downgrade are both
/// cross-origin even when the hostname is unchanged.
fn same_origin_url(raw_url: &str, credential_origin: &Url) -> bool {
    origin_for_url(raw_url).is_some_and(|request_origin| {
        origin_for_url(credential_origin.as_str()).is_some_and(|origin| request_origin == origin)
    })
}

fn declared_content_length(headers: &[Fetch::HeaderEntry]) -> Option<u64> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .and_then(|header| header.value.trim().parse().ok())
}

/// Launch a headless Chromium with the shared flag set used by every rendering path.
///
/// The flags beyond headless (`--force-color-profile=srgb`, `--font-render-hinting=none`,
/// `--hide-scrollbars`) pin color management and text rasterization so that repeated renders of the
/// same static page produce byte-identical pixels (screenshot determinism), while
/// `--disable-dev-shm-usage`/`--disable-gpu` keep Chromium stable in a container. Sandbox is
/// disabled because the crawler runs as root. The returned browser is killed when dropped.
fn launch_browser(
    deadline: Instant,
    timeout: Duration,
    window_size: (u32, u32),
) -> Result<Browser, RenderError> {
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
        .idle_browser_timeout(remaining(deadline, timeout)?)
        .build()
        .map_err(|error| RenderError::Launch(error.to_string()))?;

    Browser::new(options).map_err(|error| RenderError::Launch(error.to_string()))
}

/// In-page finalize script: inline embedded content, clean, and serialize (a single CDP round-trip).
///
/// Executed *after* the page has loaded and its scripts have run (so any JS-injected content is
/// already in the DOM). It first inlines open shadow roots and same-origin iframe documents into the
/// light DOM so their text is surfaced, then removes `<script>`/`<style>`/`<noscript>` nodes (making
/// `html` a cleaned serialization that is deterministically script/style-free and clearly distinct
/// from the raw served source), and returns `document.documentElement.outerHTML`. It never rewrites
/// element URL attributes, so relative asset/link URLs are preserved exactly as authored (consistent,
/// no-rewrite policy). Cross-origin iframes (whose document JS cannot read) and closed shadow roots
/// are skipped.
const CLEAN_AND_SERIALIZE: &str = "(function(){\
try{\
function inlineShadow(root){\
var els=root.querySelectorAll('*');\
for(var i=0;i<els.length;i++){\
var el=els[i];\
if(el.shadowRoot){\
inlineShadow(el.shadowRoot);\
var h=document.createElement('div');\
h.setAttribute('data-basecrawl-shadow','');\
h.innerHTML=el.shadowRoot.innerHTML;\
el.appendChild(h);\
}\
}\
}\
inlineShadow(document);\
var frames=document.querySelectorAll('iframe');\
for(var j=0;j<frames.length;j++){\
var f=frames[j];\
try{\
var doc=f.contentDocument;\
if(doc){\
var b=doc.body||doc.documentElement;\
var h2=document.createElement('div');\
h2.setAttribute('data-basecrawl-iframe','');\
h2.innerHTML=b?b.innerHTML:'';\
if(f.parentNode){f.parentNode.insertBefore(h2,f.nextSibling);}\
}\
}catch(e){}\
}\
}catch(e){}\
var nodes=document.querySelectorAll('script,style,noscript');\
for(var k=0;k<nodes.length;k++){var n=nodes[k];if(n.parentNode){n.parentNode.removeChild(n);}}\
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

/// Best-effort cookie/consent dismissal. Clicks the first accept-like control that is inside a
/// consent-looking container (id/class hints) or a fixed/sticky high-z-index overlay, and returns
/// whether a control was clicked. Conservative on purpose so ordinary page buttons are not clicked.
const CONSENT_DISMISS_JS: &str = "(function(){\
try{\
var ACCEPT=/^(accept all|accept all cookies|accept cookies|accept|i accept|agree|i agree|allow all|allow cookies|allow|got it|ok|okay|understood|i understand|continue)$/;\
function norm(s){return (s||'').replace(/\\s+/g,' ').trim().toLowerCase();}\
function consenty(el){\
for(var n=el;n;n=n.parentElement){\
var id=((n.id||'')+' '+((n.className&&n.className.toString)?n.className.toString():''));\
if(/cookie|consent|gdpr|privacy|cmp|banner/i.test(id))return true;\
try{var cs=getComputedStyle(n);if((cs.position==='fixed'||cs.position==='sticky')&&(parseInt(cs.zIndex||'0',10)>=100))return true;}catch(e){}\
}\
return false;\
}\
var cands=document.querySelectorAll('button,a,[role=\"button\"],input[type=\"button\"],input[type=\"submit\"]');\
for(var i=0;i<cands.length;i++){\
var el=cands[i];\
var t=norm(el.innerText||el.textContent||el.value);\
if(t&&ACCEPT.test(t)&&consenty(el)){el.click();return true;}\
}\
return false;\
}catch(e){return false;}\
})()";

/// Build the in-page auto-scroll script (a single async CDP round-trip).
///
/// It scrolls to the bottom repeatedly to trigger infinite-scroll / lazy-load. After each scroll it
/// waits a short window; if the content did not grow and nothing is loading (the in-flight counter is
/// zero) it stops promptly — so a page with no lazy content pays only that short window. If a scroll
/// triggered a load it waits (bounded) for the content to grow before scrolling again. The whole loop
/// is bounded by `max_scrolls` and `budget_ms` (the remaining render budget).
fn build_auto_scroll_js(max_scrolls: usize, budget_ms: u64) -> String {
    format!(
        "(async function(){{\
var MAX={max_scrolls},SETTLE=250,GROWTH=1800,BUDGET={budget_ms},START=Date.now();\
function h(){{return Math.max(document.body?document.body.scrollHeight:0,document.documentElement?document.documentElement.scrollHeight:0);}}\
function inflight(){{return (typeof window.__bcInflight==='number')?window.__bcInflight:0;}}\
function sleep(ms){{return new Promise(function(r){{setTimeout(r,ms);}});}}\
var vh=window.innerHeight||(document.documentElement?document.documentElement.clientHeight:0)||0;\
var last=h();\
if(last<=vh+1)return true;\
for(var i=0;i<MAX;i++){{\
if(Date.now()-START>BUDGET)break;\
window.scrollTo(0,h());\
await sleep(SETTLE);\
if(h()<=last+1&&inflight()<=0)break;\
var t=Date.now();\
while(Date.now()-t<GROWTH){{if(h()>last+1)break;await sleep(100);}}\
if(h()<=last+1)break;\
last=h();\
}}\
return true;\
}})()"
    )
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
    render_until(url, config, Instant::now() + config.timeout)
}

/// Render `url` while consuming the caller-owned absolute scrape deadline.
pub fn render_until(
    url: &Url,
    config: &RenderConfig,
    deadline: Instant,
) -> Result<Rendered, RenderError> {
    let deadline = effective_deadline(deadline, config.timeout);
    let browser = launch_browser(deadline, config.timeout, (1280, 800))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    set_tab_deadline(&tab, deadline, config.timeout)?;
    if !config.user_agent.is_empty() {
        set_tab_deadline(&tab, deadline, config.timeout)?;
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }
    let resource_state = Arc::new(Mutex::new(RenderResourceState::default()));
    set_tab_deadline(&tab, deadline, config.timeout)?;
    configure_resource_guard(
        &tab,
        config,
        Arc::clone(&resource_state),
        config.credential_origin.as_ref().unwrap_or(url),
        deadline,
    )?;

    // Install the network in-flight tracker before any page script runs so the smart wait can see
    // fetch/XHR the page issues, including deferred requests.
    set_tab_deadline(&tab, deadline, config.timeout)?;
    tab.call_method(Page::AddScriptToEvaluateOnNewDocument {
        source: NETWORK_TRACKER_JS.to_string(),
        world_name: None,
        include_command_line_api: None,
        run_immediately: Some(true),
    })
    .map_err(|e| RenderError::Render(e.to_string()))?;

    set_tab_deadline(&tab, deadline, config.timeout)?;
    tab.navigate_to(url.as_str())
        .map_err(|e| RenderError::Render(e.to_string()))?;
    // `navigate_to` returns without waiting for the load to finish. We deliberately do NOT call
    // `wait_until_navigated` here: it performs its own internal network-idle wait (doubling the
    // settle delay) and, on a client-side redirect loop (a page that never stops navigating), would
    // block for the whole render timeout before the hop cap could apply. Instead the settle loop
    // below polls the top-frame URL and readiness directly (bounded by the deadline), which both
    // waits for the committed page and detects/bounds client-side redirects.

    match &config.wait_for {
        // An explicit selector is the authoritative capture signal (it also handles content injected
        // by a timer with no network activity, which a network-idle wait would miss).
        Some(selector) => {
            wait_for_selector_and_follow_redirects(&tab, selector, config, deadline)?;
        }
        None => {
            // Wait for network idle while following (and bounding) any client-side redirect.
            settle_and_follow_redirects(&tab, config, deadline)?;
        }
    }
    // Dismiss a cookie/consent overlay (best-effort) so the underlying page, not the banner, is the
    // captured content; let anything the dismissal reveals settle briefly.
    if config.dismiss_consent && dismiss_consent(&tab, deadline, config.timeout)? {
        settle_quiet(&tab, config.quiet_period, deadline);
    }

    // Collect infinite-scroll / lazy-loaded content by scrolling until the page stops growing.
    if config.auto_scroll {
        auto_scroll(&tab, config, deadline)?;
    }

    // Execute the supplied scripted actions in order (click / scroll / wait / wait-for-selector).
    for action in &config.actions {
        run_action(&tab, action, config, deadline)?;
    }

    // Inline iframe/shadow content, strip scripts/styles, and serialize (one CDP round-trip).
    set_tab_deadline(&tab, deadline, config.timeout)?;
    let evaluated = tab
        .evaluate(CLEAN_AND_SERIALIZE, false)
        .map_err(|e| RenderError::Render(e.to_string()))?;

    match evaluated.value {
        Some(serde_json::Value::String(html)) if !html.is_empty() => {
            let resource_usage = resource_state
                .lock()
                .expect("render resource guard mutex must not be poisoned")
                .usage
                .clone();
            Ok(Rendered {
                html,
                resource_usage,
            })
        }
        _ => Err(RenderError::NoContent),
    }
}

fn effective_deadline(scrape_deadline: Instant, timeout: Duration) -> Instant {
    scrape_deadline.min(Instant::now() + timeout)
}

fn remaining(deadline: Instant, timeout: Duration) -> Result<Duration, RenderError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(RenderError::Timeout(timeout))
}

fn set_tab_deadline(tab: &Tab, deadline: Instant, timeout: Duration) -> Result<(), RenderError> {
    tab.set_default_timeout(remaining(deadline, timeout)?);
    Ok(())
}

/// The current top-frame URL with any fragment removed. Fragment-only changes are SPA hash routing,
/// not a navigation redirect, so they must not count against the client-redirect hop cap.
fn current_url_no_fragment(tab: &Tab) -> String {
    let url = tab.get_url();
    match url.split_once('#') {
        Some((base, _)) => base.to_string(),
        None => url,
    }
}

/// Whether `url` is a committed http(s) document (as opposed to `about:blank` / `chrome:` before the
/// navigation commits).
fn is_committed_http(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Wait until the committed page has loaded and its network has been idle for `quiet_period`, while
/// following any client-side redirect (meta-refresh / `window.location`) the top frame performs.
///
/// The loop first waits for the top frame to commit to an http(s) document (ignoring the pre-commit
/// `about:blank`), so it never settles on a blank shell. Thereafter a change of the top-frame URL
/// (ignoring the fragment) is a client-side redirect: each hop is counted and, when
/// `follow_client_redirects` is set, bounded by `max_redirects` — a loop exceeding the cap aborts
/// with [`RenderError::TooManyRedirects`] rather than hanging until the deadline. The whole wait is
/// also bounded by `deadline` ([`RenderError::Timeout`]).
fn settle_and_follow_redirects(
    tab: &Tab,
    config: &RenderConfig,
    deadline: Instant,
) -> Result<(), RenderError> {
    let poll = Duration::from_millis(100);
    let quiet_ms = config.quiet_period.as_millis() as i64;
    let mut current = String::new();
    let mut committed = false;
    let mut url_stable_since = Instant::now();
    let mut hops = 0usize;

    loop {
        set_tab_deadline(tab, deadline, config.timeout)?;

        let live = current_url_no_fragment(tab);
        if !is_committed_http(&live) {
            // The navigation has not committed to a real page yet (still about:blank).
            thread::sleep(poll.min(remaining(deadline, config.timeout)?));
            continue;
        }

        if !committed {
            // First commit: this is the initial navigation landing, not a client redirect.
            committed = true;
            current = live;
            url_stable_since = Instant::now();
        } else if live != current {
            if config.follow_client_redirects {
                hops += 1;
                if hops > config.max_redirects {
                    return Err(RenderError::TooManyRedirects {
                        max: config.max_redirects,
                    });
                }
            }
            current = live;
            url_stable_since = Instant::now();
            thread::sleep(poll.min(remaining(deadline, config.timeout)?));
            continue;
        }

        if !config.network_idle {
            // The URL is stable and network-idle waiting is disabled: nothing more to wait for.
            return Ok(());
        }

        set_tab_deadline(tab, deadline, config.timeout)?;
        if let Some(snap) = probe_idle(tab) {
            let url_quiet_ms = url_stable_since.elapsed().as_millis() as i64;
            if snap.ready == "complete"
                && snap.inflight <= 0
                && snap.quiet_ms >= quiet_ms
                && url_quiet_ms >= quiet_ms
            {
                return Ok(());
            }
        }
        thread::sleep(poll.min(remaining(deadline, config.timeout)?));
    }
}

/// Poll selector presence and the committed top-frame URL in one deadline-bounded loop.
///
/// `Tab::wait_for_element_with_custom_timeout` cannot observe document URL changes while it
/// blocks, allowing a client redirect loop to masquerade as a selector timeout. This loop makes
/// selector waits use the same client redirect accounting as the network-idle path.
fn wait_for_selector_and_follow_redirects(
    tab: &Tab,
    selector: &str,
    config: &RenderConfig,
    deadline: Instant,
) -> Result<(), RenderError> {
    let poll = Duration::from_millis(50);
    let selector_probe = format!(
        "document.querySelector({}) !== null",
        js_string_literal(selector)
    );
    let mut current = String::new();
    let mut committed = false;
    let mut hops = 0usize;

    loop {
        set_tab_deadline(tab, deadline, config.timeout)?;
        let live = current_url_no_fragment(tab);
        if is_committed_http(&live) {
            if !committed {
                committed = true;
                current = live;
            } else if live != current {
                if config.follow_client_redirects {
                    hops += 1;
                    if hops > config.max_redirects {
                        return Err(RenderError::TooManyRedirects {
                            max: config.max_redirects,
                        });
                    }
                }
                current = live;
            }
        }

        set_tab_deadline(tab, deadline, config.timeout)?;
        let present = tab
            .evaluate(&selector_probe, false)
            .map_err(|e| RenderError::WaitFor {
                selector: selector.to_string(),
                detail: e.to_string(),
            })?
            .value
            .as_ref()
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if present {
            return Ok(());
        }
        thread::sleep(poll.min(remaining(deadline, config.timeout)?));
    }
}

/// Best-effort short settle used after a consent dismissal: return once the network is idle, or
/// after a brief grace window, whichever comes first (never longer than the render deadline).
fn settle_quiet(tab: &Tab, quiet: Duration, deadline: Instant) {
    let poll = Duration::from_millis(50);
    let quiet_ms = quiet.as_millis() as i64;
    let step_deadline = (Instant::now() + Duration::from_secs(2)).min(deadline);
    loop {
        if Instant::now() >= step_deadline {
            return;
        }
        if let Some(snap) = probe_idle(tab) {
            if snap.ready == "complete" && snap.inflight <= 0 && snap.quiet_ms >= quiet_ms {
                return;
            }
        }
        thread::sleep(poll.min(step_deadline.saturating_duration_since(Instant::now())));
    }
}

/// Attempt to dismiss a cookie/consent overlay by clicking its accept control. Returns whether a
/// control was clicked. The match is deliberately conservative (an accept-like label *inside* a
/// consent-looking container or a fixed/sticky high-z-index overlay) so ordinary page buttons are
/// left untouched.
fn dismiss_consent(tab: &Tab, deadline: Instant, timeout: Duration) -> Result<bool, RenderError> {
    set_tab_deadline(tab, deadline, timeout)?;
    Ok(matches!(
        tab.evaluate(CONSENT_DISMISS_JS, false)
            .ok()
            .and_then(|r| r.value),
        Some(serde_json::Value::Bool(true))
    ))
}

/// Collect infinite-scroll / lazy-loaded content by running the in-page auto-scroll loop as a single
/// awaited CDP call, bounded by `max_scrolls` and the remaining render budget. Best-effort: any
/// failure or deadline simply captures whatever has loaded so far.
fn auto_scroll(tab: &Tab, config: &RenderConfig, deadline: Instant) -> Result<(), RenderError> {
    let remaining_budget = remaining(deadline, config.timeout)?;
    let budget_ms = remaining_budget.as_millis().min(u128::from(u64::MAX)) as u64;
    let js = build_auto_scroll_js(config.max_scrolls, budget_ms);
    set_tab_deadline(tab, deadline, config.timeout)?;
    let _ = tab.evaluate(&js, true);
    remaining(deadline, config.timeout)?;
    Ok(())
}

/// Encode a string as a JSON string literal (also a valid JS string literal) so a selector can be
/// embedded in an evaluated expression without breaking out of the quoting.
fn js_string_literal(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Execute a single scripted [`Action`], bounded by the render `deadline`.
fn run_action(
    tab: &Tab,
    action: &Action,
    config: &RenderConfig,
    deadline: Instant,
) -> Result<(), RenderError> {
    match action {
        Action::Click { selector } => {
            let js = format!(
                "(function(){{var e=document.querySelector({});if(e){{e.click();return true;}}return false;}})()",
                js_string_literal(selector)
            );
            set_tab_deadline(tab, deadline, config.timeout)?;
            let _ = tab.evaluate(&js, false);
        }
        Action::Scroll { direction } => {
            let js = match direction {
                ScrollDirection::Down => "window.scrollBy(0, window.innerHeight)",
                ScrollDirection::Up => "window.scrollBy(0, -window.innerHeight)",
            };
            set_tab_deadline(tab, deadline, config.timeout)?;
            let _ = tab.evaluate(js, false);
        }
        Action::Wait { milliseconds } => {
            let remaining_budget = remaining(deadline, config.timeout)?;
            std::thread::sleep(Duration::from_millis(*milliseconds).min(remaining_budget));
            remaining(deadline, config.timeout)?;
        }
        Action::WaitForSelector { selector } => {
            wait_for_selector_and_follow_redirects(tab, selector, config, deadline)?;
        }
    }
    Ok(())
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
    /// Validated effective request headers, including the controlled User-Agent, sent in order
    /// during same-origin capture requests.
    pub request_headers: Vec<(String, String)>,
    /// Origin that supplied `request_headers`; caller fields are stripped before every
    /// cross-origin document or subresource request.
    pub credential_origin: Option<Url>,
    /// Minimum interval between browser requests to one origin during capture.
    pub crawl_delay: Duration,
    /// Maximum non-document requests accepted during capture.
    pub max_subresources: usize,
    /// Maximum sum of accepted declared subresource response bytes during capture.
    pub max_resource_bytes: u64,
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
            request_headers: Vec::new(),
            credential_origin: None,
            crawl_delay: Duration::ZERO,
            max_subresources: DEFAULT_MAX_RENDER_SUBRESOURCES,
            max_resource_bytes: DEFAULT_MAX_RENDER_BYTES,
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
    /// Aggregate browser-resource accounting for this capture.
    pub resource_usage: RenderResourceUsage,
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
    screenshot_until(url, config, Instant::now() + config.timeout)
}

/// Capture a screenshot while consuming the caller-owned absolute scrape deadline.
pub fn screenshot_until(
    url: &Url,
    config: &ScreenshotConfig,
    deadline: Instant,
) -> Result<Screenshot, RenderError> {
    let deadline = effective_deadline(deadline, config.timeout);
    let browser = launch_browser(deadline, config.timeout, (config.width, config.height))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    set_tab_deadline(&tab, deadline, config.timeout)?;
    if !config.user_agent.is_empty() {
        set_tab_deadline(&tab, deadline, config.timeout)?;
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }
    let resource_state = Arc::new(Mutex::new(RenderResourceState::default()));
    let resource_config = RenderConfig {
        request_headers: config.request_headers.clone(),
        credential_origin: config.credential_origin.clone(),
        crawl_delay: config.crawl_delay,
        max_subresources: config.max_subresources,
        max_resource_bytes: config.max_resource_bytes,
        ..RenderConfig::default()
    };
    set_tab_deadline(&tab, deadline, config.timeout)?;
    configure_resource_guard(
        &tab,
        &resource_config,
        Arc::clone(&resource_state),
        resource_config.credential_origin.as_ref().unwrap_or(url),
        deadline,
    )?;

    set_tab_deadline(&tab, deadline, config.timeout)?;
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

    set_tab_deadline(&tab, deadline, config.timeout)?;
    tab.navigate_to(url.as_str())
        .map_err(|e| RenderError::Render(e.to_string()))?;
    let navigation_config = RenderConfig {
        timeout: config.timeout,
        request_headers: config.request_headers.clone(),
        credential_origin: config.credential_origin.clone(),
        crawl_delay: config.crawl_delay,
        max_subresources: config.max_subresources,
        max_resource_bytes: config.max_resource_bytes,
        ..RenderConfig::default()
    };
    settle_and_follow_redirects(&tab, &navigation_config, deadline)?;

    let clip_height = if config.full_page {
        set_tab_deadline(&tab, deadline, config.timeout)?;
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

    set_tab_deadline(&tab, deadline, config.timeout)?;
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
    remaining(deadline, config.timeout)?;
    let resource_usage = resource_state
        .lock()
        .expect("render resource guard mutex must not be poisoned")
        .usage
        .clone();
    Ok(Screenshot {
        png,
        base64: data,
        resource_usage,
    })
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

    #[test]
    fn default_config_enables_advanced_navigation() {
        let cfg = RenderConfig::default();
        assert!(cfg.follow_client_redirects);
        assert!(cfg.auto_scroll);
        assert!(cfg.dismiss_consent);
        assert!(cfg.actions.is_empty());
        assert_eq!(cfg.max_redirects, DEFAULT_MAX_REDIRECTS);
        assert_eq!(cfg.max_scrolls, DEFAULT_MAX_SCROLLS);
    }

    #[test]
    fn browser_credential_scope_requires_scheme_host_and_effective_port_match() {
        let origin = Url::parse("https://Example.test/path").unwrap();
        assert!(same_origin_url("https://example.test:443/other", &origin));
        assert!(!same_origin_url("http://example.test/other", &origin));
        assert!(!same_origin_url("https://other.test/other", &origin));
        assert!(!same_origin_url("https://example.test:8443/other", &origin));
    }

    #[test]
    fn actions_deserialize_from_tagged_json() {
        let json = r##"[
            {"type":"click","selector":"#more"},
            {"type":"scroll"},
            {"type":"scroll","direction":"up"},
            {"type":"wait","milliseconds":250},
            {"type":"waitForSelector","selector":".loaded"}
        ]"##;
        let actions: Vec<Action> = serde_json::from_str(json).unwrap();
        assert_eq!(
            actions,
            vec![
                Action::Click {
                    selector: "#more".to_string()
                },
                Action::Scroll {
                    direction: ScrollDirection::Down
                },
                Action::Scroll {
                    direction: ScrollDirection::Up
                },
                Action::Wait { milliseconds: 250 },
                Action::WaitForSelector {
                    selector: ".loaded".to_string()
                },
            ]
        );
    }

    #[test]
    fn scroll_direction_defaults_to_down() {
        assert_eq!(ScrollDirection::default(), ScrollDirection::Down);
    }

    #[test]
    fn consent_js_matches_accept_controls_conservatively() {
        assert!(CONSENT_DISMISS_JS.contains("cookie|consent|gdpr|privacy|cmp|banner"));
        assert!(CONSENT_DISMISS_JS.contains("accept"));
        assert!(CONSENT_DISMISS_JS.contains("fixed"));
    }

    #[test]
    fn finalize_js_inlines_shadow_and_iframes_and_cleans() {
        assert!(CLEAN_AND_SERIALIZE.contains("shadowRoot"));
        assert!(CLEAN_AND_SERIALIZE.contains("contentDocument"));
        assert!(CLEAN_AND_SERIALIZE.contains("iframe"));
        assert!(CLEAN_AND_SERIALIZE.contains("script,style,noscript"));
        assert!(CLEAN_AND_SERIALIZE.contains("outerHTML"));
    }

    #[test]
    fn auto_scroll_js_embeds_bounds() {
        let js = build_auto_scroll_js(7, 5000);
        assert!(js.contains("MAX=7"));
        assert!(js.contains("BUDGET=5000"));
        assert!(js.contains("__bcInflight"));
        assert!(js.contains("scrollTo"));
    }

    #[test]
    fn js_string_literal_escapes_quotes() {
        assert_eq!(js_string_literal("#a\"b"), "\"#a\\\"b\"");
    }
}
