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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use headless_chrome::browser::tab::RequestPausedDecision;
use headless_chrome::protocol::cdp::{
    types::Event,
    Emulation, Fetch, Network,
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

/// Default cap on the number of browser requests accepted during one scrape.
///
/// Document navigations, redirects, images, stylesheets, scripts, fonts, XHR, and every other
/// browser resource consume this one counter. The core shares a single budget across HTML renders,
/// screenshots, and pagination rather than granting every Chromium launch a fresh cap.
pub const DEFAULT_MAX_RENDER_SUBRESOURCES: usize = 128;

/// Default cap on cumulative accepted browser-response bytes during one scrape.
///
/// CDP response bodies are streamed through the interceptor and charged by actual observed bytes.
/// `Content-Length` can reject an obviously too-large response early, but never contributes to the
/// accounting total by itself.
pub const DEFAULT_MAX_RENDER_BYTES: u64 = 20 * 1024 * 1024;

/// A caller-supplied check run before Chromium transmits a top-level document request.
///
/// The renderer keeps this callback neutral so it does not depend on core policy code. The core
/// uses it for robots decisions, while standalone render consumers may leave it unset.
pub type DocumentRequestPolicy = Arc<dyn Fn(&Url) -> Result<(), String> + Send + Sync>;

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
    #[error("the scrape deadline expired while waiting for the per-origin crawl delay")]
    PacingDeadlineExceeded,
    #[error("timed out waiting for selector {selector:?}: {detail}")]
    WaitFor { selector: String, detail: String },
    #[error("exceeded the maximum of {max} client-side redirect hop(s)")]
    TooManyRedirects { max: usize },
    #[error("the scrape-owned browser request or byte budget was exhausted")]
    ResourceBudgetExceeded,
    #[error("top-level document policy denied navigation: {0}")]
    DocumentPolicyDenied(String),
    #[error("browser returned no serialized DOM")]
    NoContent,
}

impl RenderError {
    /// Whether this failure arose because the caller-owned absolute deadline was exhausted.
    ///
    /// The vendored CDP driver surfaces setup deadline expiry as an `anyhow` error, so preserve
    /// that structured condition through driver error wrappers.
    pub fn is_deadline_exhausted(&self) -> bool {
        self.to_string().contains("browser setup deadline exceeded")
    }
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
#[derive(Clone)]
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
    /// Maximum browser requests accepted by the shared scrape budget.
    pub max_subresources: usize,
    /// Maximum observed browser-response bytes accepted by the shared scrape budget.
    pub max_resource_bytes: u64,
    /// Maximum observed bytes for each top-level browser document. The core sets this to the
    /// direct-fetch body cap, preventing Chromium from re-downloading an unbounded document after
    /// the direct body was capped.
    pub max_document_bytes: u64,
    /// Optional scrape-owned budget shared by all browser launches. A standalone render without
    /// this value creates one from `max_subresources` and `max_resource_bytes`.
    pub resource_budget: Option<RenderResourceBudget>,
    /// Shared scheduler used by direct fetches and every browser launch in a scrape. Browser
    /// continuations record their timestamp only after the `Fetch.continueRequest` CDP command has
    /// completed, rather than when an interception callback first observes the request.
    pub origin_pacer: Option<OriginPacer>,
    /// Optional policy consulted before every top-level document request. This deliberately does
    /// not run for iframe documents or other subresources.
    pub document_request_policy: Option<DocumentRequestPolicy>,
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
            max_document_bytes: u64::MAX,
            resource_budget: None,
            origin_pacer: None,
            document_request_policy: None,
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

/// Browser request accounting surfaced by the core proof response block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderResourceUsage {
    /// Number of browser requests accepted by the cap guard, including documents.
    pub subresource_count: u64,
    /// Sum of actually observed browser-response bytes.
    pub resource_bytes: u64,
    /// Whether a request or response exhausted either configured aggregate cap.
    pub cap_exceeded: bool,
}

#[derive(Debug, Default)]
struct RenderResourceState {
    usage: RenderResourceUsage,
}

#[derive(Debug)]
struct BrowserResponseMeter {
    observed_bytes: u64,
    max_document_bytes: u64,
    is_document: bool,
}

/// One mutable request/byte budget owned by a scrape.
///
/// Clones share the same counters. The core gives this object to every HTML render, screenshot,
/// and paginated browser navigation so none can reset the configured caps.
#[derive(Debug, Clone)]
pub struct RenderResourceBudget {
    max_requests: u64,
    max_bytes: u64,
    state: Arc<Mutex<RenderResourceState>>,
}

impl RenderResourceBudget {
    /// Create a shared budget with explicit request and observed-byte ceilings.
    pub fn new(max_requests: usize, max_bytes: u64) -> Self {
        Self {
            max_requests: max_requests as u64,
            max_bytes,
            state: Arc::new(Mutex::new(RenderResourceState::default())),
        }
    }

    /// Return a snapshot suitable for the ScrapeProof response block.
    pub fn usage(&self) -> RenderResourceUsage {
        self.state
            .lock()
            .expect("render resource budget mutex must not be poisoned")
            .usage
            .clone()
    }

    fn ensure_available(&self) -> Result<(), RenderError> {
        if self
            .state
            .lock()
            .expect("render resource budget mutex must not be poisoned")
            .usage
            .cap_exceeded
        {
            Err(RenderError::ResourceBudgetExceeded)
        } else {
            Ok(())
        }
    }

    fn remaining_bytes(&self) -> Result<u64, RenderError> {
        let state = self
            .state
            .lock()
            .expect("render resource budget mutex must not be poisoned");
        if state.usage.cap_exceeded {
            return Err(RenderError::ResourceBudgetExceeded);
        }
        Ok(self.max_bytes.saturating_sub(state.usage.resource_bytes))
    }

    fn charge_bytes(&self, bytes: u64) -> Result<(), RenderError> {
        let mut state = self
            .state
            .lock()
            .expect("render resource budget mutex must not be poisoned");
        let Some(total) = state.usage.resource_bytes.checked_add(bytes) else {
            state.usage.cap_exceeded = true;
            return Err(RenderError::ResourceBudgetExceeded);
        };
        if state.usage.cap_exceeded || total > self.max_bytes {
            state.usage.cap_exceeded = true;
            return Err(RenderError::ResourceBudgetExceeded);
        }
        state.usage.resource_bytes = total;
        Ok(())
    }

    fn exhaust(&self) {
        self.state
            .lock()
            .expect("render resource budget mutex must not be poisoned")
            .usage
            .cap_exceeded = true;
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RenderOrigin {
    scheme: String,
    host: String,
    port: u16,
}

/// One monotonic per-origin transmission schedule shared by direct and browser request paths.
///
/// A browser continuation holds the schedule lock until its `Fetch.continueRequest` CDP command
/// finishes. The next request therefore begins its delay after Chromium has accepted the prior
/// continuation, avoiding the interception-callback-to-wire gap that can otherwise undershoot a
/// crawl-delay floor at the origin.
#[derive(Debug, Clone, Default)]
pub struct OriginPacer {
    last_transmission_at: Arc<Mutex<HashMap<RenderOrigin, Instant>>>,
}

/// The caller's absolute scrape deadline expired before an origin could next be contacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacingDeadlineExceeded;

impl OriginPacer {
    /// Run `transmit` only after the configured origin interval has elapsed.
    ///
    /// The schedule timestamp is committed after `transmit` returns, including a transport error,
    /// because an errored continuation or direct attempt may still have reached the origin.
    pub fn transmit<T>(
        &self,
        raw_url: &str,
        delay: Duration,
        deadline: Instant,
        transmit: impl FnOnce() -> T,
    ) -> Result<T, PacingDeadlineExceeded> {
        if delay.is_zero() {
            return Ok(transmit());
        }
        let Some(origin) = origin_for_url(raw_url) else {
            return Ok(transmit());
        };
        let mut transmissions = self
            .last_transmission_at
            .lock()
            .expect("origin pacer mutex must not be poisoned");
        if let Some(previous) = transmissions.get(&origin) {
            let elapsed = previous.elapsed();
            if elapsed < delay {
                let wait = delay - elapsed;
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|duration| !duration.is_zero())
                    .ok_or(PacingDeadlineExceeded)?;
                if wait >= remaining {
                    return Err(PacingDeadlineExceeded);
                }
                thread::sleep(wait);
            }
        }
        let result = transmit();
        transmissions.insert(origin, Instant::now());
        Ok(result)
    }
}

#[derive(Debug, Default)]
struct NavigationState {
    first_document_request_seen: bool,
    client_navigation_hops: usize,
    too_many_redirects: bool,
}

/// CDP-bound top-frame navigation accounting.
///
/// The initial browser document request establishes the rendered document. Every later top-frame
/// document request is a navigation hop, counted exactly where Chromium pauses it, including
/// same-URL reloads and meta/JavaScript redirects that URL sampling can miss. Fragment-only SPA
/// transitions do not issue a document request and are intentionally excluded.
#[derive(Debug, Clone)]
struct NavigationTracker {
    follow_client_redirects: bool,
    max_redirects: usize,
    state: Arc<Mutex<NavigationState>>,
}

impl NavigationTracker {
    fn new(follow_client_redirects: bool, max_redirects: usize) -> Self {
        Self {
            follow_client_redirects,
            max_redirects,
            state: Arc::new(Mutex::new(NavigationState::default())),
        }
    }

    fn record_top_document_request(&self) -> Result<(), RenderError> {
        let mut state = self
            .state
            .lock()
            .expect("navigation tracker mutex must not be poisoned");
        if !state.first_document_request_seen {
            state.first_document_request_seen = true;
            return Ok(());
        }
        if self.follow_client_redirects {
            state.client_navigation_hops += 1;
            if state.client_navigation_hops > self.max_redirects {
                state.too_many_redirects = true;
                return Err(RenderError::TooManyRedirects {
                    max: self.max_redirects,
                });
            }
        }
        Ok(())
    }

    fn ensure_within_limit(&self) -> Result<(), RenderError> {
        if self
            .state
            .lock()
            .expect("navigation tracker mutex must not be poisoned")
            .too_many_redirects
        {
            Err(RenderError::TooManyRedirects {
                max: self.max_redirects,
            })
        } else {
            Ok(())
        }
    }
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

#[derive(Clone)]
struct ResourceGuard {
    budget: RenderResourceBudget,
    credential_origin: Url,
    top_frame_id: Page::FrameId,
    document_policy_denial: Arc<Mutex<Option<String>>>,
    navigation_tracker: NavigationTracker,
    pacing_deadline_exceeded: Arc<AtomicBool>,
    deadline: Instant,
}

/// Configure per-origin pacing and one scrape-owned browser resource budget.
///
/// Request interception prevents requests above the count cap before transmission and rejects an
/// obviously excessive declared length as an early hint. `Network.dataReceived` then charges every
/// actually received byte, including chunked and invalid-length responses. An exhausted budget
/// closes the tab promptly, and the render path turns that into a structured failure.
fn configure_resource_guard(
    tab: &Arc<Tab>,
    config: &RenderConfig,
    guard: ResourceGuard,
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
    tab.call_method(Network::Enable {
        max_total_buffer_size: None,
        max_resource_buffer_size: None,
        max_post_data_size: None,
        report_direct_socket_traffic: None,
        enable_durable_messages: None,
    })
    .map_err(|error| RenderError::Render(error.to_string()))?;

    let crawl_delay = config.crawl_delay;
    let max_document_bytes = config.max_document_bytes;
    let request_headers = config.request_headers.clone();
    let ResourceGuard {
        budget,
        credential_origin,
        top_frame_id,
        document_policy_denial,
        navigation_tracker,
        pacing_deadline_exceeded,
        deadline,
    } = guard;
    let document_request_policy = config.document_request_policy.clone();
    let origin_pacer = config.origin_pacer.clone().unwrap_or_default();
    let response_meters = Arc::new(Mutex::new(HashMap::<String, BrowserResponseMeter>::new()));
    let response_meters_for_requests = Arc::clone(&response_meters);
    let budget_for_requests = budget.clone();
    tab.enable_request_interception(Arc::new(
        move |_transport, _session_id, paused: Fetch::events::RequestPausedEvent| {
            let is_document = paused.params.resource_Type == ResourceType::Document;
            if paused.params.response_status_code.is_some() {
                let declared_bytes = paused
                    .params
                    .response_headers
                    .as_deref()
                    .and_then(declared_content_length)
                    .unwrap_or_default();
                let document_limit = if is_document {
                    max_document_bytes
                } else {
                    u64::MAX
                };
                let early_limit = budget_for_requests
                    .remaining_bytes()
                    .ok()
                    .map(|remaining| remaining.min(document_limit));
                if early_limit.is_none_or(|limit| declared_bytes > limit) {
                    budget_for_requests.exhaust();
                    return RequestPausedDecision::Fail(Fetch::FailRequest {
                        request_id: paused.params.request_id,
                        error_reason: ErrorReason::BlockedByClient,
                    });
                }
                if let Some(network_id) = paused.params.network_id {
                    response_meters_for_requests
                        .lock()
                        .expect("browser response meter mutex must not be poisoned")
                        .insert(
                            network_id.to_string(),
                            BrowserResponseMeter {
                                observed_bytes: 0,
                                max_document_bytes,
                                is_document,
                            },
                        );
                }
                return RequestPausedDecision::Continue(None);
            }

            let is_top_document = is_document && paused.params.frame_id == top_frame_id;
            if is_top_document {
                if let Some(policy) = &document_request_policy {
                    match Url::parse(&paused.params.request.url)
                        .map_err(|error| error.to_string())
                        .and_then(|target| policy(&target))
                    {
                        Ok(()) => {}
                        Err(error) => {
                            *document_policy_denial
                                .lock()
                                .expect("document policy mutex must not be poisoned") = Some(error);
                            return RequestPausedDecision::Fail(Fetch::FailRequest {
                                request_id: paused.params.request_id,
                                error_reason: ErrorReason::BlockedByClient,
                            });
                        }
                    }
                }
                if navigation_tracker.record_top_document_request().is_err() {
                    return RequestPausedDecision::Fail(Fetch::FailRequest {
                        request_id: paused.params.request_id,
                        error_reason: ErrorReason::BlockedByClient,
                    });
                }
            }

            let mut state = budget_for_requests
                .state
                .lock()
                .expect("render resource guard mutex must not be poisoned");
            if state.usage.cap_exceeded
                || state.usage.subresource_count >= budget_for_requests.max_requests
            {
                state.usage.cap_exceeded = true;
                return RequestPausedDecision::Fail(Fetch::FailRequest {
                    request_id: paused.params.request_id,
                    error_reason: ErrorReason::BlockedByClient,
                });
            }
            state.usage.subresource_count += 1;
            drop(state);
            let request_url = paused.params.request.url.clone();
            let continue_request =
                effective_continue_request(paused.clone(), &request_headers, &credential_origin);
            let pacing_deadline_exceeded = Arc::clone(&pacing_deadline_exceeded);
            let navigation_tracker = navigation_tracker.clone();
            let origin_pacer = origin_pacer.clone();
            RequestPausedDecision::Deferred(Arc::new(move |transport, session_id, event| {
                let request_id = event.params.request_id.clone();
                let outcome = origin_pacer.transmit(&request_url, crawl_delay, deadline, || {
                    transport.call_method_on_target(session_id.clone(), continue_request.clone())
                });
                match outcome {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => {}
                    Err(PacingDeadlineExceeded) => {
                        pacing_deadline_exceeded.store(true, Ordering::SeqCst);
                        let _ = transport.call_method_on_target(
                            session_id.clone(),
                            Fetch::FailRequest {
                                request_id: request_id.clone(),
                                error_reason: ErrorReason::TimedOut,
                            },
                        );
                    }
                }
                if navigation_tracker.ensure_within_limit().is_err() {
                    let _ = transport.call_method_on_target(
                        session_id,
                        Fetch::FailRequest {
                            request_id,
                            error_reason: ErrorReason::BlockedByClient,
                        },
                    );
                }
            }))
        },
    ))
    .map_err(|error| RenderError::Render(error.to_string()))?;

    let response_meters_for_bytes = Arc::clone(&response_meters);
    let budget_for_bytes = budget.clone();
    let tab_for_abort = Arc::clone(tab);
    tab.add_event_listener(Arc::new(move |event: &Event| {
        let Event::NetworkDataReceived(event) = event else {
            return;
        };
        // CDP's encoded length is the received transfer size. Some Chromium response paths report
        // it as zero on an individual chunk, so fall back to the observed payload length rather
        // than letting a chunked or malformed-length response escape accounting.
        let encoded_bytes = u64::from(event.params.encoded_data_length);
        let bytes = if encoded_bytes == 0 {
            u64::from(event.params.data_length)
        } else {
            encoded_bytes
        };
        if bytes == 0 {
            return;
        }
        let exceeded = {
            let mut meters = response_meters_for_bytes
                .lock()
                .expect("browser response meter mutex must not be poisoned");
            let Some(meter) = meters.get_mut(&event.params.request_id.to_string()) else {
                return;
            };
            match meter.observed_bytes.checked_add(bytes) {
                None => true,
                Some(total) if meter.is_document && total > meter.max_document_bytes => true,
                Some(_) if budget_for_bytes.charge_bytes(bytes).is_err() => true,
                Some(total) => {
                    meter.observed_bytes = total;
                    false
                }
            }
        };
        if exceeded {
            budget_for_bytes.exhaust();
            let tab = Arc::clone(&tab_for_abort);
            thread::spawn(move || {
                let _ = tab.close_target();
            });
        }
    }))
    .map_err(|error| RenderError::Render(error.to_string()))?;
    Ok(())
}

/// Resume a paused request with caller headers restricted to their initiating origin.
///
/// CDP's `Network.setExtraHTTPHeaders` takes an object, so it discards duplicate keys and has no
/// field-order contract. `Fetch.continueRequest` accepts a header-entry list instead. Browser-owned
/// fields remain present. Any case-insensitive collision with a caller-controlled field is removed
/// first, then re-added only when the paused request has the initiating scheme, host, and port.
/// This guards cross-origin HTTP redirects, client navigations, iframes, and subresources even when
/// Chromium has copied headers from a prior same-origin request into the paused request.
fn effective_continue_request(
    paused: Fetch::events::RequestPausedEvent,
    effective_headers: &[(String, String)],
    credential_origin: &Url,
) -> Fetch::ContinueRequest {
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

    Fetch::ContinueRequest {
        request_id: paused.params.request_id,
        url: None,
        method: None,
        post_data: None,
        headers: Some(headers),
        intercept_response: None,
    }
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

    Browser::new_with_deadline(options, deadline)
        .map_err(|error| RenderError::Launch(error.to_string()))
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
    let resource_budget = config.resource_budget.clone().unwrap_or_else(|| {
        RenderResourceBudget::new(config.max_subresources, config.max_resource_bytes)
    });
    resource_budget.ensure_available()?;
    let browser = launch_browser(deadline, config.timeout, (1280, 800))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    let document_policy_denial = Arc::new(Mutex::new(None));
    let navigation_tracker =
        NavigationTracker::new(config.follow_client_redirects, config.max_redirects);
    let pacing_deadline_exceeded = Arc::new(AtomicBool::new(false));
    set_tab_deadline(&tab, deadline, config.timeout)?;
    if !config.user_agent.is_empty() {
        set_tab_deadline(&tab, deadline, config.timeout)?;
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }
    set_tab_deadline(&tab, deadline, config.timeout)?;
    let top_frame_id = top_frame_id(&tab)?;
    configure_resource_guard(
        &tab,
        config,
        ResourceGuard {
            budget: resource_budget.clone(),
            credential_origin: config.credential_origin.as_ref().unwrap_or(url).clone(),
            top_frame_id,
            document_policy_denial: Arc::clone(&document_policy_denial),
            navigation_tracker: navigation_tracker.clone(),
            pacing_deadline_exceeded: Arc::clone(&pacing_deadline_exceeded),
            deadline,
        },
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

    browser.complete_setup();
    set_tab_deadline(&tab, deadline, config.timeout)?;
    tab.navigate_to(url.as_str()).map_err(|error| {
        render_failure_with_policy(error.to_string(), &resource_budget, &document_policy_denial)
    })?;
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
            wait_for_selector_and_follow_redirects(
                &tab,
                selector,
                config,
                &resource_budget,
                &navigation_tracker,
                &pacing_deadline_exceeded,
                deadline,
            )
            .map_err(|error| {
                render_or_policy_error(
                    error,
                    &resource_budget,
                    &document_policy_denial,
                    &navigation_tracker,
                    &pacing_deadline_exceeded,
                )
            })?;
        }
        None => {
            // Wait for network idle while following (and bounding) any client-side redirect.
            settle_and_follow_redirects(
                &tab,
                config,
                &resource_budget,
                &navigation_tracker,
                &pacing_deadline_exceeded,
                deadline,
            )
            .map_err(|error| {
                render_or_policy_error(
                    error,
                    &resource_budget,
                    &document_policy_denial,
                    &navigation_tracker,
                    &pacing_deadline_exceeded,
                )
            })?;
        }
    }
    ensure_document_policy_allowed(&document_policy_denial)?;
    resource_budget.ensure_available()?;
    // Dismiss a cookie/consent overlay (best-effort) so the underlying page, not the banner, is the
    // captured content; let anything the dismissal reveals settle briefly.
    if config.dismiss_consent && dismiss_consent(&tab, deadline, config.timeout)? {
        settle_quiet(&tab, config.quiet_period, &resource_budget, deadline);
    }
    resource_budget.ensure_available()?;

    // Collect infinite-scroll / lazy-loaded content by scrolling until the page stops growing.
    if config.auto_scroll {
        auto_scroll(&tab, config, deadline)?;
    }
    resource_budget.ensure_available()?;

    // Execute the supplied scripted actions in order (click / scroll / wait / wait-for-selector).
    for action in &config.actions {
        run_action(
            &tab,
            action,
            config,
            &resource_budget,
            &navigation_tracker,
            &pacing_deadline_exceeded,
            deadline,
        )?;
        resource_budget.ensure_available()?;
    }
    ensure_document_policy_allowed(&document_policy_denial)?;
    if pacing_deadline_exceeded.load(Ordering::SeqCst) {
        return Err(RenderError::PacingDeadlineExceeded);
    }
    navigation_tracker.ensure_within_limit()?;

    // Inline iframe/shadow content, strip scripts/styles, and serialize (one CDP round-trip).
    set_tab_deadline(&tab, deadline, config.timeout)?;
    let evaluated = tab
        .evaluate(CLEAN_AND_SERIALIZE, false)
        .map_err(|e| RenderError::Render(e.to_string()))?;

    match evaluated.value {
        Some(serde_json::Value::String(html)) if !html.is_empty() => {
            resource_budget.ensure_available()?;
            Ok(Rendered {
                html,
                resource_usage: resource_budget.usage(),
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

/// Wait until a top-frame document request has committed and the page's network has been idle for
/// `quiet_period`. Client redirects are counted by the top-frame `Fetch.requestPaused` boundary,
/// not by polling a URL, so same-URL reloads count while fragment-only SPA transitions do not.
fn settle_and_follow_redirects(
    tab: &Tab,
    config: &RenderConfig,
    resource_budget: &RenderResourceBudget,
    navigation_tracker: &NavigationTracker,
    pacing_deadline_exceeded: &AtomicBool,
    deadline: Instant,
) -> Result<(), RenderError> {
    let poll = Duration::from_millis(100);
    let quiet_ms = config.quiet_period.as_millis() as i64;

    loop {
        if pacing_deadline_exceeded.load(Ordering::SeqCst) {
            return Err(RenderError::PacingDeadlineExceeded);
        }
        navigation_tracker.ensure_within_limit()?;
        resource_budget.ensure_available()?;
        set_tab_deadline(tab, deadline, config.timeout)?;

        if !config.network_idle {
            return Ok(());
        }

        set_tab_deadline(tab, deadline, config.timeout)?;
        if let Some(snap) = probe_idle(tab) {
            if snap.ready == "complete" && snap.inflight <= 0 && snap.quiet_ms >= quiet_ms {
                return Ok(());
            }
        }
        thread::sleep(poll.min(remaining(deadline, config.timeout)?));
    }
}

/// Poll selector presence while the interception boundary tracks every top-frame navigation.
fn wait_for_selector_and_follow_redirects(
    tab: &Tab,
    selector: &str,
    config: &RenderConfig,
    resource_budget: &RenderResourceBudget,
    navigation_tracker: &NavigationTracker,
    pacing_deadline_exceeded: &AtomicBool,
    deadline: Instant,
) -> Result<(), RenderError> {
    let poll = Duration::from_millis(50);
    let selector_probe = format!(
        "document.querySelector({}) !== null",
        js_string_literal(selector)
    );

    loop {
        if pacing_deadline_exceeded.load(Ordering::SeqCst) {
            return Err(RenderError::PacingDeadlineExceeded);
        }
        navigation_tracker.ensure_within_limit()?;
        resource_budget.ensure_available()?;
        set_tab_deadline(tab, deadline, config.timeout)?;

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
fn settle_quiet(
    tab: &Tab,
    quiet: Duration,
    resource_budget: &RenderResourceBudget,
    deadline: Instant,
) {
    let poll = Duration::from_millis(50);
    let quiet_ms = quiet.as_millis() as i64;
    let step_deadline = (Instant::now() + Duration::from_secs(2)).min(deadline);
    loop {
        if resource_budget.ensure_available().is_err() {
            return;
        }
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
    resource_budget: &RenderResourceBudget,
    navigation_tracker: &NavigationTracker,
    pacing_deadline_exceeded: &AtomicBool,
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
            wait_for_selector_and_follow_redirects(
                tab,
                selector,
                config,
                resource_budget,
                navigation_tracker,
                pacing_deadline_exceeded,
                deadline,
            )?;
        }
    }
    Ok(())
}

/// Default screenshot viewport width (CSS px) when the caller does not specify one.
pub const DEFAULT_VIEWPORT_WIDTH: u32 = 1280;
/// Default screenshot viewport height (CSS px) when the caller does not specify one.
pub const DEFAULT_VIEWPORT_HEIGHT: u32 = 800;

/// Configuration for a single deterministic screenshot capture.
#[derive(Clone)]
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
    /// Maximum browser requests accepted by the shared scrape budget.
    pub max_subresources: usize,
    /// Maximum observed browser-response bytes accepted by the shared scrape budget.
    pub max_resource_bytes: u64,
    /// Maximum observed bytes for an individual top-level browser document.
    pub max_document_bytes: u64,
    /// Optional scrape-owned budget shared with HTML renders and pagination.
    pub resource_budget: Option<RenderResourceBudget>,
    /// Optional shared direct/browser per-origin transmission scheduler.
    pub origin_pacer: Option<OriginPacer>,
    /// Optional policy consulted before every top-level document request during capture.
    pub document_request_policy: Option<DocumentRequestPolicy>,
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
            max_document_bytes: u64::MAX,
            resource_budget: None,
            origin_pacer: None,
            document_request_policy: None,
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
    let resource_budget = config.resource_budget.clone().unwrap_or_else(|| {
        RenderResourceBudget::new(config.max_subresources, config.max_resource_bytes)
    });
    resource_budget.ensure_available()?;
    let browser = launch_browser(deadline, config.timeout, (config.width, config.height))?;
    let tab = browser
        .new_tab()
        .map_err(|e| RenderError::Launch(e.to_string()))?;
    let document_policy_denial = Arc::new(Mutex::new(None));
    set_tab_deadline(&tab, deadline, config.timeout)?;
    if !config.user_agent.is_empty() {
        set_tab_deadline(&tab, deadline, config.timeout)?;
        tab.set_user_agent(&config.user_agent, None, None)
            .map_err(|e| RenderError::Render(e.to_string()))?;
    }
    let resource_config = RenderConfig {
        request_headers: config.request_headers.clone(),
        credential_origin: config.credential_origin.clone(),
        crawl_delay: config.crawl_delay,
        max_subresources: config.max_subresources,
        max_resource_bytes: config.max_resource_bytes,
        max_document_bytes: config.max_document_bytes,
        resource_budget: Some(resource_budget.clone()),
        origin_pacer: config.origin_pacer.clone(),
        document_request_policy: config.document_request_policy.clone(),
        ..RenderConfig::default()
    };
    set_tab_deadline(&tab, deadline, config.timeout)?;
    let top_frame_id = top_frame_id(&tab)?;
    let navigation_tracker = NavigationTracker::new(
        resource_config.follow_client_redirects,
        resource_config.max_redirects,
    );
    let pacing_deadline_exceeded = Arc::new(AtomicBool::new(false));
    configure_resource_guard(
        &tab,
        &resource_config,
        ResourceGuard {
            budget: resource_budget.clone(),
            credential_origin: resource_config
                .credential_origin
                .as_ref()
                .unwrap_or(url)
                .clone(),
            top_frame_id,
            document_policy_denial: Arc::clone(&document_policy_denial),
            navigation_tracker: navigation_tracker.clone(),
            pacing_deadline_exceeded: Arc::clone(&pacing_deadline_exceeded),
            deadline,
        },
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

    browser.complete_setup();
    set_tab_deadline(&tab, deadline, config.timeout)?;
    tab.navigate_to(url.as_str()).map_err(|error| {
        render_failure_with_policy(error.to_string(), &resource_budget, &document_policy_denial)
    })?;
    let navigation_config = RenderConfig {
        timeout: config.timeout,
        request_headers: config.request_headers.clone(),
        credential_origin: config.credential_origin.clone(),
        crawl_delay: config.crawl_delay,
        max_subresources: config.max_subresources,
        max_resource_bytes: config.max_resource_bytes,
        max_document_bytes: config.max_document_bytes,
        resource_budget: Some(resource_budget.clone()),
        origin_pacer: config.origin_pacer.clone(),
        document_request_policy: config.document_request_policy.clone(),
        ..RenderConfig::default()
    };
    settle_and_follow_redirects(
        &tab,
        &navigation_config,
        &resource_budget,
        &navigation_tracker,
        &pacing_deadline_exceeded,
        deadline,
    )
    .map_err(|error| {
        render_or_policy_error(
            error,
            &resource_budget,
            &document_policy_denial,
            &navigation_tracker,
            &pacing_deadline_exceeded,
        )
    })?;
    ensure_document_policy_allowed(&document_policy_denial)?;
    resource_budget.ensure_available()?;

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
    resource_budget.ensure_available()?;
    Ok(Screenshot {
        png,
        base64: data,
        resource_usage: resource_budget.usage(),
    })
}

/// Preserve a specific control-flow error, but prefer a budget exhaustion recorded by the
/// interceptor over Chromium's generic `ERR_BLOCKED_BY_CLIENT` navigation failure.
fn render_or_budget_error(error: RenderError, budget: &RenderResourceBudget) -> RenderError {
    if budget.usage().cap_exceeded {
        RenderError::ResourceBudgetExceeded
    } else {
        error
    }
}

fn top_frame_id(tab: &Tab) -> Result<Page::FrameId, RenderError> {
    tab.call_method(Page::GetFrameTree(None))
        .map(|tree| tree.frame_tree.frame.id)
        .map_err(|error| RenderError::Render(error.to_string()))
}

fn document_policy_error(
    document_policy_denial: &Arc<Mutex<Option<String>>>,
) -> Option<RenderError> {
    document_policy_denial
        .lock()
        .expect("document policy mutex must not be poisoned")
        .clone()
        .map(RenderError::DocumentPolicyDenied)
}

fn ensure_document_policy_allowed(
    document_policy_denial: &Arc<Mutex<Option<String>>>,
) -> Result<(), RenderError> {
    document_policy_error(document_policy_denial).map_or(Ok(()), Err)
}

/// Prefer a document-policy denial over Chromium's generic blocked-client error, then preserve
/// the existing budget-specific error mapping.
fn render_or_policy_error(
    error: RenderError,
    budget: &RenderResourceBudget,
    document_policy_denial: &Arc<Mutex<Option<String>>>,
    navigation_tracker: &NavigationTracker,
    pacing_deadline_exceeded: &AtomicBool,
) -> RenderError {
    if pacing_deadline_exceeded.load(Ordering::SeqCst) {
        return RenderError::PacingDeadlineExceeded;
    }
    if let Err(error) = navigation_tracker.ensure_within_limit() {
        return error;
    }
    document_policy_error(document_policy_denial)
        .unwrap_or_else(|| render_or_budget_error(error, budget))
}

fn render_failure_with_policy(
    message: String,
    budget: &RenderResourceBudget,
    document_policy_denial: &Arc<Mutex<Option<String>>>,
) -> RenderError {
    document_policy_error(document_policy_denial)
        .unwrap_or_else(|| render_or_budget_error(RenderError::Render(message), budget))
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
