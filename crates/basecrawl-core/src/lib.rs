//! `basecrawl` crawler core.
//!
//! At milestone M1 this crate owns the CLI/SDK entrypoint and the assembly of the canonical,
//! non-attestation [`ScrapeProof`] envelope: input validation (URL scheme + output format),
//! a foundational fetch, and construction of the top-level proof shape. Deeper capabilities
//! (TLS 1.3 capture, format producers, canonicalization, egress/geo, attestation) are layered
//! on by subsequent features.

pub mod attestation;
pub mod batch;
pub mod canonical;
pub mod charset;
pub mod content;
pub mod crawl;
pub mod document;
pub mod egress;
pub mod error;
pub mod extract;
pub mod fetch;
pub mod format;
pub mod html;
pub mod links;
pub mod map_lite;
pub mod markdown;
pub mod metadata;
pub mod pagination;
pub mod product_request;
pub mod proxy;
pub mod robots;
pub mod rtt_echo;
pub mod screenshot;
pub mod stealth;
pub mod url_validation;

use basecrawl_proof::{
    Attestation, Request, Response, ResultBlock, SdkSignature, SCRAPE_PROOF_VERSION,
};
use content::ContentKind;
use fetch::{FetchConfig, DEFAULT_MAX_BODY_BYTES, DEFAULT_TIMEOUT_SECS};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

pub use basecrawl_proof::ScrapeProof;
pub use basecrawl_render::{Action, ScrollDirection};
pub use error::Error;
pub use error::ExtractRefuseReason;
pub use extract::{
    gate_structured_extraction, provider_key_is_configured, validate_schema_text,
    ExtractProviderConfig, EXTRACT_API_KEY_ENVS, EXTRACT_HONESTY_HELP,
};
// Host-safe panic / label helpers for bindings and CLI (VAL-CONF-018..031).
pub use basecrawl_seal::{
    host_safe_panic_message, install_host_safe_panic_hook, task_id_ref, HostSafeLabels,
};
pub use format::Format;
pub use robots::RobotsPolicy;

/// The default HTTP method for a scrape.
pub const DEFAULT_METHOD: &str = product_request::DEFAULT_METHOD;

/// Default cap on the number of pages crawled when pagination following is enabled.
pub const DEFAULT_MAX_PAGES: usize = 5;

/// Options controlling a single scrape.
#[derive(Debug, Clone)]
pub struct ScrapeOptions {
    /// Requested formats (canonical order). Empty means "use the documented default set".
    pub formats: Vec<Format>,
    /// Validator-issued task id, echoed verbatim into the proof.
    pub task_id: Option<String>,
    /// Validator-issued anti-replay nonce, echoed verbatim into the proof.
    pub nonce: Option<String>,
    /// Whole-request timeout in seconds.
    pub timeout_secs: u64,
    /// Extra request headers to send, as parsed `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// HTTP method for the origin request (`GET` default, `POST` supported on soft path).
    /// Recorded honestly into ScrapeProof `request.method` (VAL-CRAWLPROD-001/005).
    pub method: String,
    /// Request body bytes for POST. Empty for GET. Hashed into `request.body_hash`.
    pub body: Vec<u8>,
    /// Bypass TLS certificate verification. Disabled by default and intended only for an explicit
    /// diagnostic fetch of an invalid-certificate origin.
    pub insecure: bool,
    /// Maximum decoded response-body bytes retained in memory. Responses beyond this cap are
    /// truncated and signaled in the ScrapeProof response block.
    pub max_body_bytes: usize,
    /// Minimum spacing between physical requests to the same origin, including robots, redirects,
    /// sitemap discovery, pagination, and browser subresources.
    pub crawl_delay_ms: u64,
    /// Maximum browser requests accepted while producing all rendered outputs.
    pub max_render_subresources: usize,
    /// Maximum observed browser-response bytes shared by all rendered outputs.
    pub max_render_bytes: u64,
    /// Screenshot viewport as `(width, height)` in CSS pixels (device-scale-factor 1).
    pub viewport: (u32, u32),
    /// When true, `screenshot` captures the full scrollable page rather than just the viewport.
    pub screenshot_full_page: bool,
    /// When true (default), the `html`/`markdown` formats are produced from the headless-Chromium
    /// post-render DOM (JS executed). When false (`--no-js`), they are produced from the raw served
    /// source, so no browser is launched and JS-injected content is not present.
    pub render_enabled: bool,
    /// Optional CSS selector that render must wait for before capturing (`--wait-for`).
    pub wait_for: Option<String>,
    /// Whole-render timeout in seconds bounding the JS render step independently of the fetch
    /// timeout, so a pathological (never-idle) page is aborted rather than hanging.
    pub render_timeout_secs: u64,
    /// Scripted navigation actions executed in order in the browser after the page settles and
    /// before capture (click / scroll / wait / wait-for-selector).
    pub actions: Vec<Action>,
    /// When true, follow "next page" links across a paginated listing, aggregating markdown and
    /// recording the crawled URL set.
    pub follow_pagination: bool,
    /// The maximum number of pages crawled (including the first) when `follow_pagination` is set.
    pub max_pages: usize,
    /// Handling for an origin's robots policy. The default is enforce: covered denied paths are
    /// never fetched, while allowed/unmatched paths proceed with an observable metadata decision.
    pub robots_policy: RobotsPolicy,
    /// Request a genuine quote from the mounted dstack guest agent after assembling the proof.
    pub attest: bool,
    /// Request an enclave-held Ed25519 signature over the canonical proof. This requires
    /// attestation and never accepts host-supplied key material.
    pub sign_proof: bool,
    /// Optional explicit fingerprint seed (per-miner/per-task). When unset, the seed is derived
    /// from `task_id`/`nonce`, falling back to a stable material from the request surface. The
    /// normalized seed always appears in `egress.fingerprint_seed` and is bound into `report_data`.
    pub fingerprint_seed: Option<String>,
    /// Enclave-recorded landmark RTTs (ms) to write into `egress.landmark_rtts` (VAL-GEO-009).
    /// When `None`, the emission uses an empty object (pre-geo / unmeasured). Callers that have
    /// measured landmarks (via [`rtt_echo::probe_landmarks`]) pass the resulting map so the
    /// validator can cross-check against independently measured floors.
    pub landmark_rtts: Option<std::collections::BTreeMap<String, f64>>,
    /// Explicit egress proxy URL (`http(s)://` CONNECT or `socks5://`, optional user:pass).
    /// When set, this overrides ambient `BASECRAWL_*` / `HTTPS_PROXY` / `ALL_PROXY` env vars.
    /// When unset, [`proxy::resolve_proxy`] consults that env stack. Credentials never appear in
    /// ScrapeProof or host-visible logs (VAL-PROXY-023/024).
    pub proxy: Option<String>,
    /// Sticky session id embedded into the dial-time username via the provider-agnostic template
    /// (`…-sessid-{session}` or `{sessid}` placeholder) — VAL-PROXY-010/011.
    pub proxy_session: Option<String>,
    /// Country code token embedded into the dial-time username (`…-cc-{country}` / `{cc}`) —
    /// VAL-PROXY-013/014. Provider-agnostic; not an Oxylabs-only flag.
    pub proxy_country: Option<String>,
    /// Optional full username template with `{user}`, `{country}`/`{cc}`, `{session}`/`{sessid}`.
    pub proxy_username_template: Option<String>,
    /// Required/declared proxy class for this scrape (`direct|datacenter|residential|mobile`).
    /// Commercial class without a viable upstream fails closed (VAL-PROXY-020/021/028).
    /// Emitted `egress.proxy_class` is always the truthful dial class, never a forged wish.
    pub proxy_class: Option<basecrawl_proof::ProxyClass>,
    /// Optional site difficulty (`soft|hard`). Hard forces the Chromium identity path
    /// (VAL-STEALTH-001) even without a residential proxy class.
    pub difficulty: Option<stealth::SiteDifficulty>,
    /// Explicitly force the hard Chromium path (sticky stealth identity), even for soft targets.
    pub force_browser: bool,
    /// Install the hard-path CDP `Page.addScriptToEvaluateOnNewDocument` stealth inject.
    ///
    /// Default true. When hard / residential identity is required, disabling this fails closed
    /// rather than emitting raw automation surface as silent stealth success (VAL-CDP-008).
    /// Soft-path scrapes that do not force Chromium may leave this false without consequence.
    pub stealth_inject: bool,
    /// When true (default), wipe the sticky Chromium profile when the scrape ends so the next
    /// distinct task_id starts clean without operator process surgery (VAL-STEALTH-014).
    pub wipe_profile_on_complete: bool,
    /// Optional JSON Schema text for structured `json` extraction (`--json-schema` / `--schema`).
    /// Validated when `formats` includes `json`; missing provider/extractor fails closed with a
    /// structured error and never invents fields (VAL-CRAWLPROD-024..027).
    pub json_schema: Option<String>,
    /// Optional natural-language extract prompt (`--json-prompt` / `--prompt`). Gated with schema;
    /// does not alone enable forged success.
    pub json_prompt: Option<String>,
    /// Soft-path TLS chrome-impersonate profile (`chrome`). None = pure seed suite reorder only.
    /// Invalid tokens fail closed (VAL-UTLS-002/007). Soft path never upgrades to chromium
    /// fetch_path or residential class (VAL-UTLS-003/004). Applied only on rustls soft fetch;
    /// hard Chromium path ignores the soft TLS offer as residential seize evidence (VAL-UTLS-010).
    pub tls_impersonate: Option<String>,
}

impl Default for ScrapeOptions {
    fn default() -> Self {
        Self {
            formats: format::default_set(),
            task_id: None,
            nonce: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            headers: Vec::new(),
            method: DEFAULT_METHOD.to_string(),
            body: Vec::new(),
            insecure: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            crawl_delay_ms: 0,
            max_render_subresources: basecrawl_render::DEFAULT_MAX_RENDER_SUBRESOURCES,
            max_render_bytes: basecrawl_render::DEFAULT_MAX_RENDER_BYTES,
            viewport: (
                basecrawl_render::DEFAULT_VIEWPORT_WIDTH,
                basecrawl_render::DEFAULT_VIEWPORT_HEIGHT,
            ),
            screenshot_full_page: false,
            render_enabled: true,
            wait_for: None,
            render_timeout_secs: basecrawl_render::DEFAULT_RENDER_TIMEOUT_SECS,
            actions: Vec::new(),
            follow_pagination: false,
            max_pages: DEFAULT_MAX_PAGES,
            robots_policy: RobotsPolicy::Enforce,
            attest: false,
            sign_proof: false,
            fingerprint_seed: None,
            landmark_rtts: None,
            proxy: None,
            proxy_session: None,
            proxy_country: None,
            proxy_username_template: None,
            proxy_class: None,
            difficulty: None,
            force_browser: false,
            stealth_inject: true,
            wipe_profile_on_complete: true,
            json_schema: None,
            json_prompt: None,
            tls_impersonate: None,
        }
    }
}

/// Validate `raw_url`, fetch it, and assemble the canonical [`ScrapeProof`].
///
/// URL/scheme validation happens before any network access, so a non-HTTP scheme or malformed
/// URL is refused without a fetch and without emitting a proof.
pub fn scrape(raw_url: &str, options: &ScrapeOptions) -> Result<ScrapeProof, Error> {
    let url = url_validation::validate_url(raw_url)?;
    let deadline = Instant::now() + Duration::from_secs(options.timeout_secs);

    let formats = if options.formats.is_empty() {
        format::default_set()
    } else {
        format::normalize(options.formats.clone())
    };

    // Method + body validation before network work (VAL-CRAWLPROD-001..006).
    let method = product_request::normalize_method(Some(options.method.as_str()))?;
    product_request::validate_method_body(&method, &options.body)?;

    // JSON structured extraction is gated and honest: validate schema when present, then refuse
    // without a configured provider/extractor. Never emit success with empty/fake `json` fields
    // (VAL-CRAWLPROD-024..027, VAL-CRAWL-127). Whole-request refusal when `json` is requested so
    // other formats are not silently half-produced (VAL-CRAWLPROD-029: clean unit reject).
    if formats.contains(&Format::Json) {
        extract::gate_structured_extraction(
            options.json_schema.as_deref(),
            options.json_prompt.as_deref(),
        )?;
        // Live path never returns Ok above in this build; keep the belt based on that invariant.
        return Err(Error::StructuredExtractionUnsupported {
            reason: ExtractRefuseReason::ExtractorNotAvailable,
        });
    }

    // Resolve the per-miner/per-task fingerprint seed first so every outgoing client dimension
    // (TLS cipher order → JA3/JA4, header order, UA, viewport, timezone, locale, canvas/WebGL)
    // is a pure function of that seed. The seed is later logged in egress and bound into
    // report_data (VAL-ANTIBOT-033..037).
    //
    // Fallback material MUST NOT depend on the target URL/scheme. Unattended CLI scrapes without
    // an explicit seed / task_id / nonce must still emit one stable default profile so HTTP and
    // HTTPS hash the same validated effective-header list (request header canonicalization).
    // Mission scrapes always supply task_id+nonce (or fingerprint_seed) and bypass this fallback.
    let fingerprint_seed = basecrawl_fp::resolve_seed(
        options.fingerprint_seed.as_deref(),
        options.task_id.as_deref(),
        options.nonce.as_deref(),
        basecrawl_fp::UNATTENDED_DEFAULT_SEED,
    );
    // Fail closed if a seed ever selects a weak security surface (VAL-ANTIBOT-038 / BOT-08).
    // Non-security dimensions (JA3/JA4, headers, UA, viewport, tz, locale, canvas) still vary.
    let mut fingerprint =
        basecrawl_fp::generate_validated(&fingerprint_seed).map_err(|detail| {
            Error::TlsCapture(format!(
                "fingerprint seed violated security-critical TLS invariants: {detail}"
            ))
        })?;

    // Soft chrome-impersonate ClientHello (VAL-UTLS-001..008): stronger than pure random suite
    // reorder. Invalid / weak profiles fail closed before any dial. Capture stays in-process.
    let soft_tls_impersonate = match options.tls_impersonate.as_deref() {
        None => None,
        Some(raw) => {
            let profile = basecrawl_fp::SoftTlsImpersonate::parse(raw)
                .map_err(|err| Error::TlsImpersonate(err.message()))?;
            basecrawl_fp::assert_chrome_security_floor().map_err(|detail| {
                Error::TlsImpersonate(format!(
                    "soft chrome profile below security floor: {detail}"
                ))
            })?;
            // Under --attest, soft impersonate still requires complete cert/transcript capture
            // on the rustls path. Capature remains enabled by product security invariants;
            // refuse any future mode that would skip capture while claiming attest success.
            if options.attest {
                let floor = basecrawl_fp::security_critical_tls_params();
                if !floor.cert_chain_capture_enabled || !floor.transcript_capture_enabled {
                    return Err(Error::TlsImpersonate(
                        "tls impersonate under --attest requires in-enclave cert/transcript capture"
                            .into(),
                    ));
                }
            }
            profile.apply(&mut fingerprint);
            // Re-check invariants after chrome-order swap (still TLS 1.3 closed set).
            basecrawl_fp::assert_security_invariants(&fingerprint).map_err(|detail| {
                Error::TlsImpersonate(format!(
                    "chrome soft profile violated security-critical TLS invariants: {detail}"
                ))
            })?;
            Some(profile)
        }
    };

    // Seed chooses viewport when the caller left the measured-image default; an explicit
    // non-default viewport from the CLI/SDK wins.
    let default_viewport = (
        basecrawl_render::DEFAULT_VIEWPORT_WIDTH,
        basecrawl_render::DEFAULT_VIEWPORT_HEIGHT,
    );
    let viewport = if options.viewport == default_viewport {
        (fingerprint.viewport_width, fingerprint.viewport_height)
    } else {
        options.viewport
    };

    // Reject ambiguous / transport-managed caller headers *before* any network work so the CLI
    // and regression tests still get InvalidHeader for duplicate or case-variant field names,
    // matching pre-seed request-header canonicalization (multi-value names stay unhashable).
    fetch::validate_caller_headers(&options.headers)?;

    // Seed-owned header order + UA (plus caller credentials) is the single validated ordered
    // effective header list shared by request hashing, direct HTTP/HTTPS, and Chromium.
    let effective_headers =
        basecrawl_fp::effective_fingerprint_headers(&fingerprint, &options.headers);
    // Validate entropy so a bad header never reaches the wire.
    for (name, value) in &effective_headers {
        fetch::validate_header_pair(name, value)?;
    }
    // Resolve the soft-path egress proxy before any origin dial. Explicit CLI/config wins over
    // ambient BASECRAWL_HTTP(S)_PROXY / HTTPS_PROXY / ALL_PROXY (VAL-PROXY-005/006). Failures of
    // a configured upstream are hard errors (no silent direct fallback; VAL-PROXY-020). Sticky
    // session + country are applied via provider-agnostic username templates (VAL-PROXY-010..014).
    let proxy_plan = proxy::ProxyPlan {
        explicit_url: options.proxy.clone(),
        username: proxy::UsernameTemplateOptions {
            country: options.proxy_country.clone(),
            session: options.proxy_session.clone(),
            template: options.proxy_username_template.clone(),
        },
        required_class: options.proxy_class,
        configured_class: options.proxy_class.filter(|c| c.requires_upstream()),
    };
    let proxy = proxy::resolve_proxy_plan(&proxy_plan, &url)?;
    let dialed_proxy_class = proxy::truthful_proxy_class(proxy.as_ref(), options.proxy_class)?;
    // Hard / residential identity policy (VAL-STEALTH-001/002/010/017):
    // residential|mobile or hard difficulty force the Chromium path; soft targets may stay rustls.
    let needs_browser_formats = formats
        .iter()
        .any(|f| matches!(f, Format::Screenshot | Format::Markdown | Format::Html))
        || options.follow_pagination;
    let hard_decision = stealth::HardPathDecision {
        proxy_class: options.proxy_class.or(Some(dialed_proxy_class)),
        difficulty: options.difficulty,
        force_browser: options.force_browser,
        render_enabled: options.render_enabled,
        needs_browser_formats,
    };
    let hard_required = stealth::requires_chromium_hard_path(hard_decision);
    // Hard Chromium path does not submit POST bodies in this build. Refuse before browser policy /
    // launch work so callers never see a silent empty-body success (VAL-CRAWLPROD-007). Soft POST
    // continues on rustls without browser identity so body transmission stays honest.
    if method.eq_ignore_ascii_case("POST") && hard_required {
        return Err(Error::PostNotSupportedOnHardPath);
    }
    // VAL-CDP-008: hard / residential identity requires the early document stealth inject. Disabling
    // it (CLI flag or env) fails closed — never claim hard-path success with raw automation surface.
    let stealth_inject_enabled = options.stealth_inject
        && !std::env::var("BASECRAWL_DISABLE_STEALTH_INJECT")
            .map(|v| {
                let t = v.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
    if hard_required && !stealth_inject_enabled {
        return Err(Error::HardPath(
            "stealth inject is required on the hard Chromium path; refuse silent success without Page.addScriptToEvaluateOnNewDocument install (VAL-CDP-008)"
                .into(),
        ));
    }
    let will_use_browser = if method.eq_ignore_ascii_case("POST") {
        // Soft POST body framing is only implemented on the rustls path.
        false
    } else {
        stealth::will_launch_chromium(hard_decision, hard_required).map_err(
            |error| match error {
                stealth::StealthPolicyError::HardPathDisabled { reason } => Error::HardPath(reason),
                stealth::StealthPolicyError::Profile(detail) => Error::HardPath(detail),
            },
        )?
    };
    // Sticky profile for multipage cookie continuity on one task; wiped across task_ids
    // (VAL-STEALTH-011..014). Soft-only scrapes skip an empty profile.
    let sticky_profile_dir = if will_use_browser {
        let key = options
            .task_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(options.proxy_session.as_deref())
            .unwrap_or("anonymous");
        Some(
            stealth::acquire_sticky_profile(key)
                .map_err(|error| Error::HardPath(error.to_string()))?,
        )
    } else {
        None
    };
    // Chromium hard path shares the soft-path dialer via a DoH-preserving composer
    // (VAL-PROXY-012/015..019). Only start when the scrape will launch headless Chromium so soft
    // --no-js paths stay cheap. Bind/start failures under a required commercial class fail closed
    // before any Chromium target is created (VAL-PROXY-022).
    let chromium_composer = if will_use_browser {
        match proxy.as_ref() {
            Some(cfg) => Some(proxy::start_chromium_composer(cfg)?),
            None => None,
        }
    } else {
        None
    };
    let config = FetchConfig {
        timeout: Duration::from_secs(options.timeout_secs),
        headers: effective_headers,
        credential_origin: Some(url.clone()),
        user_agent: fingerprint.user_agent.clone(),
        insecure: options.insecure,
        max_body_bytes: options.max_body_bytes,
        crawl_delay: Duration::from_millis(options.crawl_delay_ms),
        tls13_cipher_names: fingerprint.tls13_cipher_names.clone(),
        tls_group_order: fingerprint.tls_group_order.clone(),
        proxy,
        method: method.clone(),
        body: options.body.clone(),
        ..FetchConfig::default()
    };
    let document_policy =
        robots::DocumentPolicy::new(config.clone(), options.robots_policy, deadline);
    let fetched = fetch::fetch_document_until(&url, &config, deadline, |target| {
        document_policy.check(target)
    })?;
    let robots_decision = document_policy.initial_decision();

    // The request-side hashes cover the one validated ordered effective header list plus the actual
    // request body bytes (empty for GET, transmitted body for POST) — VAL-CRAWLPROD-004.
    let headers_hash = canonical::headers_hash(&config.headers);
    let body_hash = canonical::body_hash(&options.body);
    let request_hash = canonical::request_hash(&method, url.as_str(), &headers_hash, &body_hash);
    let format_names: Vec<String> = formats
        .iter()
        .map(|format| format.as_str().to_string())
        .collect();

    // The decoded served source, shared by the rawHtml passthrough and the links/metadata
    // producers. The resolution base is the terminal (post-redirect) URL so relative links/images
    // resolve correctly; a document `<base href>` overrides it inside each producer.
    let content_kind = content::classify(fetched.content_type.as_deref());
    // Classification and semantic validation are independent of requested output formats. This
    // invokes bounded extraction once for every recognized document so malformed or empty
    // documents cannot succeed through metadata-, links-, or rawHtml-only requests. The extracted
    // text remains emitted only by the markdown and HTML branches below.
    let document_text = match content_kind {
        ContentKind::Document(kind) => {
            Some(document::extract(&fetched.body, kind).map_err(Error::DocumentExtraction)?)
        }
        _ => None,
    };
    let mut body_str = if matches!(content_kind, ContentKind::Document(_)) {
        String::new()
    } else {
        charset::decode_body(
            &fetched.body,
            fetched.content_type.as_deref(),
            content_kind == ContentKind::Html,
        )
    };
    redact_sensitive_request_echoes(&mut body_str, &options.headers);
    let page_base = Url::parse(&fetched.final_url).unwrap_or_else(|_| url.clone());
    let sitemap_urls = if formats.contains(&Format::Links) {
        robots::discover_sitemap_urls(&url, &config, &robots_decision.sitemap_urls, deadline)?
    } else {
        Vec::new()
    };

    // The post-render DOM feeds `html` and `markdown` so JS-injected content is captured. It is
    // rendered at most once (shared by both formats) and only when rendering is enabled, the served
    // body is a non-empty HTML document, and a render-dependent format was requested — so a
    // `--no-js` run, a `rawHtml`/`links`-only run, and an empty/non-HTML response never launch a
    // browser. When rendering is skipped, `html`/`markdown` fall back to the raw served source.
    let needs_render = formats
        .iter()
        .any(|f| matches!(f, Format::Markdown | Format::Html));
    // Every browser launch for this scrape receives this same budget. It includes top-level
    // documents, redirects, subresources, HTML, screenshots, and paginated pages, so no stage can
    // reset a cap that an earlier stage already consumed.
    let render_resource_budget = basecrawl_render::RenderResourceBudget::new(
        options.max_render_subresources,
        options.max_render_bytes,
    );
    // Hard path always drives Chromium for HTML identity (VAL-STEALTH-001/003). Soft path keeps
    // the previous "render only when html/markdown requested" rule.
    let should_render_html = content_kind == ContentKind::Html
        && !body_str.trim().is_empty()
        && (hard_required || (options.render_enabled && needs_render));
    // Refuse hard-path silent success when the origin already returned a classic challenge page
    // before Chromium rolls (VAL-STEALTH-016). Still fail closed if the rendered DOM is a block page.
    if hard_required && stealth::looks_like_challenge_interstitial(&body_str, fetched.status_code) {
        if options.wipe_profile_on_complete {
            if let Some(key) = options.task_id.as_deref().filter(|s| !s.is_empty()) {
                let _ = stealth::wipe_sticky_profile(key);
            } else {
                let _ = stealth::wipe_current_sticky_profile();
            }
        }
        return Err(Error::ChallengeBlocked {
            status_code: fetched.status_code,
            detail: "hard path observed a bot-challenge / block response (VAL-STEALTH-016)".into(),
        });
    }
    let mut chromium_used = false;
    let rendered_html: Option<String> = if should_render_html {
        let mut rendered = html::render_page_until(
            &page_base,
            basecrawl_render::RenderConfig {
                timeout: Duration::from_secs(options.render_timeout_secs),
                user_agent: config.user_agent.clone(),
                request_headers: config.headers.clone(),
                credential_origin: config.credential_origin.clone(),
                crawl_delay: config.crawl_delay,
                max_subresources: options.max_render_subresources,
                max_resource_bytes: options.max_render_bytes,
                max_document_bytes: options.max_body_bytes as u64,
                resource_budget: Some(render_resource_budget.clone()),
                origin_pacer: Some(config.origin_pacer.clone()),
                document_request_policy: Some(render_document_policy(document_policy.clone())),
                wait_for: options.wait_for.clone(),
                actions: options.actions.clone(),
                max_redirects: fetch::MAX_REDIRECTS,
                accept_language: Some(fingerprint.accept_language.clone()),
                platform: Some(fingerprint.platform.clone()),
                timezone: Some(fingerprint.timezone.clone()),
                locale: Some(fingerprint.locale.clone()),
                fingerprint_script: if stealth_inject_enabled {
                    Some(basecrawl_fp::browser_injection_script(&fingerprint))
                } else {
                    None
                },
                window_size: Some((fingerprint.viewport_width, fingerprint.viewport_height)),
                sealed_socks: chromium_composer.clone(),
                user_data_dir: sticky_profile_dir.clone(),
                stealth: true,
                // VAL-CDP-001/008: hard path requires early inject; soft optional path may skip.
                require_stealth_inject: hard_required,
                chrome_full_version: Some(fingerprint.chrome_full_version.clone()),
                chrome_major: Some(fingerprint.chrome_major),
                ..basecrawl_render::RenderConfig::default()
            },
            deadline,
        )?;
        redact_sensitive_request_echoes(&mut rendered.html, &options.headers);
        // Hard path: refuse to silently score a challenge interstitial as primary success.
        if hard_required
            && stealth::looks_like_challenge_interstitial(&rendered.html, fetched.status_code)
        {
            if options.wipe_profile_on_complete {
                if let Some(key) = options.task_id.as_deref().filter(|s| !s.is_empty()) {
                    let _ = stealth::wipe_sticky_profile(key);
                } else {
                    let _ = stealth::wipe_current_sticky_profile();
                }
            }
            return Err(Error::ChallengeBlocked {
                status_code: fetched.status_code,
                detail: "hard path observed a bot-challenge / block interstitial rather than the primary document (VAL-STEALTH-016)".into(),
            });
        }
        chromium_used = true;
        Some(rendered.html)
    } else {
        // Soft-path non-render HTML may still be challenge-like; only hard tasks gate on it.
        if hard_required
            && stealth::looks_like_challenge_interstitial(&body_str, fetched.status_code)
        {
            if options.wipe_profile_on_complete {
                if let Some(key) = options.task_id.as_deref().filter(|s| !s.is_empty()) {
                    let _ = stealth::wipe_sticky_profile(key);
                } else {
                    let _ = stealth::wipe_current_sticky_profile();
                }
            }
            return Err(Error::ChallengeBlocked {
                status_code: fetched.status_code,
                detail: "hard path observed a bot-challenge / block response (VAL-STEALTH-016)"
                    .into(),
            });
        }
        None
    };

    // `rawHtml` is always the served source (no render); `html`/`markdown` use the rendered DOM when
    // available and otherwise the served source.
    let mut formats_produced: BTreeMap<String, Value> = BTreeMap::new();
    for f in &formats {
        let value = match f {
            Format::RawHtml => text_surface(&body_str, content_kind),
            Format::Markdown => {
                if content_kind == ContentKind::Html {
                    let source = rendered_html.as_deref().unwrap_or(&body_str);
                    Value::String(markdown::to_markdown(source, &page_base))
                } else if matches!(content_kind, ContentKind::Document(_)) {
                    Value::String(document_text.clone().unwrap_or_default())
                } else {
                    text_surface(&body_str, content_kind)
                }
            }
            Format::Html => {
                if content_kind == ContentKind::Html {
                    let source = rendered_html.clone().unwrap_or_else(|| body_str.clone());
                    Value::String(source)
                } else if matches!(content_kind, ContentKind::Document(_)) {
                    Value::String(document_text.clone().unwrap_or_default())
                } else {
                    text_surface(&body_str, content_kind)
                }
            }
            Format::Links => links_surface(&body_str, &page_base, content_kind, &sitemap_urls),
            Format::Metadata => {
                let mut value = metadata::extract_for_content(
                    &body_str,
                    &metadata::PageMeta {
                        source_url: url.as_str(),
                        status_code: Some(fetched.status_code),
                        content_type: fetched.content_type.as_deref(),
                    },
                    content_kind == ContentKind::Html,
                );
                if let Value::Object(metadata) = &mut value {
                    metadata.insert("robotsPolicy".to_string(), robots_decision.to_value());
                }
                value
            }
            Format::Screenshot => {
                let shot = screenshot::capture_until(
                    &page_base,
                    basecrawl_render::ScreenshotConfig {
                        timeout: config.timeout,
                        user_agent: config.user_agent.clone(),
                        request_headers: config.headers.clone(),
                        credential_origin: config.credential_origin.clone(),
                        crawl_delay: config.crawl_delay,
                        max_subresources: options.max_render_subresources,
                        max_resource_bytes: options.max_render_bytes,
                        max_document_bytes: options.max_body_bytes as u64,
                        resource_budget: Some(render_resource_budget.clone()),
                        origin_pacer: Some(config.origin_pacer.clone()),
                        document_request_policy: Some(render_document_policy(
                            document_policy.clone(),
                        )),
                        width: viewport.0,
                        height: viewport.1,
                        full_page: options.screenshot_full_page,
                        accept_language: Some(fingerprint.accept_language.clone()),
                        platform: Some(fingerprint.platform.clone()),
                        timezone: Some(fingerprint.timezone.clone()),
                        locale: Some(fingerprint.locale.clone()),
                        fingerprint_script: if stealth_inject_enabled {
                            Some(basecrawl_fp::browser_injection_script(&fingerprint))
                        } else {
                            None
                        },
                        sealed_socks: chromium_composer.clone(),
                        user_data_dir: sticky_profile_dir.clone(),
                        stealth: true,
                        require_stealth_inject: hard_required,
                        chrome_full_version: Some(fingerprint.chrome_full_version.clone()),
                        chrome_major: Some(fingerprint.chrome_major),
                    },
                    deadline,
                )?;
                chromium_used = true;
                Value::String(shot.base64)
            }
            _ => Value::Null,
        };
        formats_produced.insert(f.as_str().to_string(), value);
    }

    // Pagination following: walk "next page" links, aggregating markdown and recording the crawled
    // URL set. Gated behind the option, so a single-page scrape is unchanged. Subsequent pages are
    // best-effort — a failed page ends the crawl rather than failing the whole scrape.
    let mut crawled_urls: Vec<String> = Vec::new();
    if options.follow_pagination {
        crawled_urls.push(url.as_str().to_string());
        let max_pages = options.max_pages.max(1);
        let mut current_html = rendered_html.clone().unwrap_or_else(|| body_str.clone());
        let mut current_base = page_base.clone();
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(url.as_str().to_string());

        let mut aggregated_markdown: Option<String> = if formats.contains(&Format::Markdown) {
            formats_produced
                .get(Format::Markdown.as_str())
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };

        while crawled_urls.len() < max_pages {
            let Some(next) = pagination::find_next(&current_html, &current_base) else {
                break;
            };
            let key = next.as_str().to_string();
            if !visited.insert(key.clone()) {
                break;
            }
            let (page_markdown, page_html, page_base_next) = crawl_page(
                &next,
                options,
                &config,
                &document_policy,
                render_resource_budget.clone(),
                &fingerprint,
                chromium_composer.clone(),
                sticky_profile_dir.clone(),
                deadline,
            )?;
            if let Some(agg) = aggregated_markdown.as_mut() {
                agg.push_str("\n\n");
                agg.push_str(&page_markdown);
            }
            crawled_urls.push(key);
            current_html = page_html;
            current_base = page_base_next;
        }

        if let Some(agg) = aggregated_markdown {
            formats_produced.insert(Format::Markdown.as_str().to_string(), Value::String(agg));
        }
    }

    // Screenshot capture and pagination can each drive new direct or browser document
    // navigations. Materialize the shared policy recorder only after every format that can append
    // a document hop has completed, so metadata and the deterministic result hash see the complete
    // traversal in its recorded order.
    materialize_robots_policy_hops(&mut formats_produced, &document_policy);

    if Instant::now() >= deadline {
        return Err(Error::Timeout("scrape deadline exceeded".to_string()));
    }
    let render_resource_usage = render_resource_budget.usage();

    // `result_hash` covers only the deterministic result surface; `screenshot` (and `json`) are
    // excluded so a viewport tweak that changes only pixels never shifts the byte-quorum digest.
    let result_hash = canonical::result_hash(&formats_produced);
    let completeness_manifest = canonical::completeness_manifest(&format_names, &formats_produced);
    let manifest_sha256 =
        canonical::manifest_sha256(url.as_str(), options.nonce.as_deref(), &result_hash);
    // Truthful path marker: hard/residential HTML targets must not claim soft-only identity
    // (VAL-STEALTH-010). Non-HTML soft fixtures still report the actual wire path used.
    let fetch_path = stealth::truthful_fetch_path(
        chromium_used || (hard_required && will_use_browser && content_kind == ContentKind::Html),
    );
    if hard_required
        && content_kind == ContentKind::Html
        && fetch_path != basecrawl_proof::FetchPath::Chromium
    {
        if options.wipe_profile_on_complete {
            if let Some(key) = options.task_id.as_deref().filter(|s| !s.is_empty()) {
                let _ = stealth::wipe_sticky_profile(key);
            } else {
                let _ = stealth::wipe_current_sticky_profile();
            }
        }
        return Err(Error::HardPath(
            "hard/residential request completed without a Chromium identity (dual-stack mismatch)"
                .into(),
        ));
    }
    // Soft audit only when soft rustls was the wire path *and* chrome-impersonate was applied.
    // Hard Chromium proof must not sell soft TLS as residential identity (VAL-UTLS-003/006/010).
    let soft_impersonate_egress = match (soft_tls_impersonate, fetch_path) {
        (Some(profile), basecrawl_proof::FetchPath::Direct) => {
            let audit = basecrawl_fp::SoftTlsImpersonateAudit::from_applied(profile, &fingerprint);
            Some(basecrawl_proof::SoftTlsImpersonateEgress {
                profile: audit.profile,
                ja_label: audit.ja_label,
                soft_ja3: audit.soft_ja3,
                soft_ja4: audit.soft_ja4,
            })
        }
        _ => None,
    };
    let landmark_map = options.landmark_rtts.clone().unwrap_or_default();
    let egress = egress::build_with_soft_tls_impersonate(
        fetched.egress_ip,
        fetched.fetched_at,
        &fingerprint.seed,
        landmark_map,
        dialed_proxy_class,
        fetch_path,
        soft_impersonate_egress,
    )?;

    let mut proof = ScrapeProof {
        version: SCRAPE_PROOF_VERSION,
        task_id: options.task_id.clone(),
        nonce: options.nonce.clone(),
        request: Request {
            method: method.clone(),
            url: url.as_str().to_string(),
            headers_hash: Some(headers_hash),
            body_hash: Some(body_hash),
            request_hash: Some(request_hash),
            formats: format_names,
        },
        tls: fetched.tls,
        response: Response {
            status_code: Some(fetched.status_code),
            headers_hash: Some(fetched.headers_hash),
            body_hash: Some(fetched.body_hash),
            content_length: Some(fetched.content_length),
            content_type: fetched.content_type,
            body_truncated: fetched.body_truncated,
            body_max_bytes: Some(options.max_body_bytes as u64),
            final_url: Some(fetched.final_url),
            redirect_chain: fetched.redirects,
            render_subresource_count: render_resource_usage.subresource_count,
            render_subresource_max_count: options.max_render_subresources as u64,
            render_resource_bytes: render_resource_usage.resource_bytes,
            render_max_bytes: options.max_render_bytes,
            render_resource_cap_exceeded: render_resource_usage.cap_exceeded,
        },
        result: ResultBlock {
            formats_produced,
            result_hash: Some(result_hash),
            completeness_manifest,
            manifest_sha256: Some(manifest_sha256),
            crawled_urls,
        },
        egress,
        attestation: Attestation::default(),
        sdk_signature: SdkSignature::default(),
    };
    if options.sign_proof && !options.attest {
        return Err(Error::EnclaveSignature(
            "signed proofs require attestation".to_string(),
        ));
    }
    if options.wipe_profile_on_complete {
        // Task ends → wipe sticky jar so the next task_id starts clean (VAL-STEALTH-013/014).
        // Browser process itself is already Drop-killed by the render crate.
        if let Some(key) = options
            .task_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(options.proxy_session.as_deref())
        {
            let _ = stealth::wipe_sticky_profile(key);
        } else {
            let _ = stealth::wipe_current_sticky_profile();
        }
    }

    if options.attest {
        // Every M2 quote carries the enclave key commitment and signature. The explicit option
        // remains useful to SDK callers as an intent marker, but cannot disable this invariant.
        let sign_proof = options.sign_proof || options.attest;
        if sign_proof {
            // `/Sign` returns the public half of the guest-agent-derived key without exposing
            // private material. Discover that public key first so it can be included in the
            // report-data preimage before requesting the quote.
            let key_probe = attestation::sign_at(
                std::path::Path::new(attestation::DEFAULT_DSTACK_SOCKET),
                b"basecrawl/enclave-signing-key/v1",
            )
            .map_err(|error| {
                Error::Attestation(format!("guest-agent signing request failed: {error}"))
            })?;
            proof.sdk_signature.enclave_pubkey = Some(key_probe.public_key.clone());
        }
        let report_data = canonical::attestation_report_data(&proof)
            .map_err(|error| Error::Attestation(format!("report_data assembly failed: {error}")))?;
        let quote = attestation::get_quote(&report_data).map_err(|error| {
            Error::Attestation(format!("guest-agent quote request failed: {error}"))
        })?;
        let measurement = attestation::quote_measurement(&quote.quote).map_err(|error| {
            Error::Attestation(format!("guest-agent quote is malformed: {error}"))
        })?;
        proof.attestation = Attestation {
            tee_type: Some("tdx".to_string()),
            quote: Some(quote.quote),
            measurement: Some(measurement),
            report_data: Some(quote.report_data),
        };
        let signing_json = proof.to_canonical_signing_json();
        let sign = attestation::sign_at(
            std::path::Path::new(attestation::DEFAULT_DSTACK_SOCKET),
            signing_json.as_bytes(),
        )
        .map_err(|error| {
            Error::Attestation(format!("guest-agent signing request failed: {error}"))
        })?;
        let public_key = proof
            .sdk_signature
            .enclave_pubkey
            .as_deref()
            .ok_or_else(|| Error::EnclaveSignature("missing enclave public key".into()))?;
        if sign.public_key != public_key {
            return Err(Error::EnclaveSignature(
                "guest-agent signing key changed during proof assembly".to_string(),
            ));
        }
        proof.sdk_signature.sig = Some(sign.signature);
        let signature = proof
            .sdk_signature
            .sig
            .as_deref()
            .ok_or_else(|| Error::EnclaveSignature("missing enclave signature".into()))?;
        attestation::verify_signature(
            public_key,
            signature,
            proof.to_canonical_signing_json().as_bytes(),
        )
        .map_err(|error| Error::EnclaveSignature(error.to_string()))?;
    }
    Ok(proof)
}

fn materialize_robots_policy_hops(
    formats_produced: &mut BTreeMap<String, Value>,
    document_policy: &robots::DocumentPolicy,
) {
    if let Some(Value::Object(metadata)) = formats_produced.get_mut(Format::Metadata.as_str()) {
        metadata.insert("robotsPolicyHops".to_string(), document_policy.hops_value());
    }
}

/// Fetch and extract a single pagination page: returns its markdown, the HTML used to locate the
/// next link (rendered DOM when rendering applies, else the scraped source), and the resolution base.
/// Subsequent pages are not subject to the page-1 scripted actions.
///
/// When the scrape has a commercial/mock upstream, `chromium_composer` is the same sticky dialer
/// handle used by the first-page/browser actions so multipage stays on one exit hop (VAL-PROXY-012).
/// `sticky_profile_dir` is the same Chromium user-data dir so cookies/session persist across
/// multipage hops on one task (VAL-STEALTH-011).
#[allow(clippy::too_many_arguments)] // scrape-owned composer + sticky profile must share page-1
fn crawl_page(
    url: &Url,
    options: &ScrapeOptions,
    config: &FetchConfig,
    document_policy: &robots::DocumentPolicy,
    render_resource_budget: basecrawl_render::RenderResourceBudget,
    fingerprint: &basecrawl_fp::FingerprintProfile,
    chromium_composer: Option<std::sync::Arc<basecrawl_seal::SealedSocksProxy>>,
    sticky_profile_dir: Option<std::path::PathBuf>,
    deadline: Instant,
) -> Result<(String, String, Url), Error> {
    let fetched = fetch::fetch_document_until(url, config, deadline, |target| {
        document_policy.check(target)
    })?;
    let is_html = content::classify(fetched.content_type.as_deref()) == ContentKind::Html;
    let mut body_str =
        charset::decode_body(&fetched.body, fetched.content_type.as_deref(), is_html);
    redact_sensitive_request_echoes(&mut body_str, &options.headers);
    let page_base = Url::parse(&fetched.final_url).unwrap_or_else(|_| url.clone());
    // Multipage hops share the hard-path inject policy of the parent scrape (VAL-CDP-004).
    let hard_required = stealth::requires_chromium_hard_path(stealth::HardPathDecision {
        proxy_class: options.proxy_class,
        difficulty: options.difficulty,
        force_browser: options.force_browser,
        render_enabled: options.render_enabled,
        needs_browser_formats: true,
    });
    let stealth_inject_enabled = options.stealth_inject
        && !std::env::var("BASECRAWL_DISABLE_STEALTH_INJECT")
            .map(|v| {
                let t = v.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
    if hard_required && !stealth_inject_enabled {
        return Err(Error::HardPath(
            "stealth inject is required on the hard Chromium path; refuse silent success without Page.addScriptToEvaluateOnNewDocument install (VAL-CDP-008)"
                .into(),
        ));
    }
    let source = if options.render_enabled && is_html && !body_str.trim().is_empty() {
        let mut rendered = html::render_page_until(
            &page_base,
            basecrawl_render::RenderConfig {
                timeout: Duration::from_secs(options.render_timeout_secs),
                user_agent: config.user_agent.clone(),
                request_headers: config.headers.clone(),
                credential_origin: config.credential_origin.clone(),
                crawl_delay: config.crawl_delay,
                max_subresources: options.max_render_subresources,
                max_resource_bytes: options.max_render_bytes,
                max_document_bytes: options.max_body_bytes as u64,
                resource_budget: Some(render_resource_budget),
                origin_pacer: Some(config.origin_pacer.clone()),
                document_request_policy: Some(render_document_policy(document_policy.clone())),
                wait_for: options.wait_for.clone(),
                max_redirects: fetch::MAX_REDIRECTS,
                accept_language: Some(fingerprint.accept_language.clone()),
                platform: Some(fingerprint.platform.clone()),
                timezone: Some(fingerprint.timezone.clone()),
                locale: Some(fingerprint.locale.clone()),
                fingerprint_script: if stealth_inject_enabled {
                    Some(basecrawl_fp::browser_injection_script(fingerprint))
                } else {
                    None
                },
                window_size: Some((fingerprint.viewport_width, fingerprint.viewport_height)),
                sealed_socks: chromium_composer,
                user_data_dir: sticky_profile_dir,
                stealth: true,
                require_stealth_inject: hard_required,
                chrome_full_version: Some(fingerprint.chrome_full_version.clone()),
                chrome_major: Some(fingerprint.chrome_major),
                ..basecrawl_render::RenderConfig::default()
            },
            deadline,
        )?;
        redact_sensitive_request_echoes(&mut rendered.html, &options.headers);
        rendered.html
    } else {
        body_str
    };
    let markdown = markdown::to_markdown(&source, &page_base);
    Ok((markdown, source, page_base))
}

/// Adapt the core's typed robots policy to the renderer's dependency-neutral document hook.
fn render_document_policy(
    document_policy: robots::DocumentPolicy,
) -> basecrawl_render::DocumentRequestPolicy {
    Arc::new(move |target| {
        document_policy.check(target).map_err(|error| match error {
            Error::RobotsDenied(detail) => detail.to_string(),
            error => error.to_string(),
        })
    })
}

fn text_surface(body: &str, content_kind: ContentKind) -> Value {
    match content_kind {
        ContentKind::Binary | ContentKind::Document(_) => Value::String(String::new()),
        ContentKind::Html | ContentKind::Text => Value::String(body.to_owned()),
    }
}

fn links_surface(
    body: &str,
    page_base: &Url,
    content_kind: ContentKind,
    sitemap_urls: &[String],
) -> Value {
    if content_kind == ContentKind::Html {
        let mut links = links::extract(body, page_base);
        links.sitemap = sitemap_urls.to_vec();
        serde_json::to_value(links).expect("links surface is always serializable")
    } else {
        let links = links::Links {
            sitemap: sitemap_urls.to_vec(),
            ..links::Links::default()
        };
        serde_json::to_value(links).expect("links surface is always serializable")
    }
}

/// Remove request-header values when an origin reflects them into a surfaced result.
///
/// A valid origin can echo arbitrary custom headers, not just `Authorization` or `Cookie`, in
/// JSON/debug output. The proof commits to the original response via `response.body_hash`, but
/// plaintext result formats must not re-emit request-header material. Matching values rather than
/// names handles arbitrary echo-body layouts without changing unrelated response content.
fn redact_sensitive_request_echoes(body: &mut String, headers: &[(String, String)]) {
    for (name, value) in headers {
        if !value.is_empty() {
            *body = body.replace(value, "<redacted>");
        }
        if is_sensitive_request_header(name) {
            for secret in sensitive_header_components(name, value) {
                *body = body.replace(secret, "<redacted>");
            }
        }
    }
}

fn is_sensitive_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("set-cookie")
}

/// Return credentials embedded within an authentication or cookie header.
///
/// Full-value replacement catches normal reflective endpoints. These smaller components close the
/// gap for endpoints that reflect only a bearer credential or only the value side of a cookie.
fn sensitive_header_components<'a>(name: &str, value: &'a str) -> Vec<&'a str> {
    if name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
    {
        return value.split_whitespace().skip(1).collect();
    }

    value
        .split(';')
        .filter_map(|cookie| {
            cookie
                .trim()
                .split_once('=')
                .map(|(_, secret)| secret.trim())
        })
        .filter(|secret| !secret.is_empty())
        .collect()
}
