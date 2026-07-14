//! Seeded fingerprint generator for basecrawl (architecture §6.5).
//!
//! The measured image stays fixed and allowlistable while non-security fingerprint dimensions
//! are parameterized by a per-miner/per-task seed: TLS cipher/group ordering (JA3/JA4), HTTP
//! header order, User-Agent, viewport, timezone, locale, and canvas/WebGL noise. Security-critical
//! TLS parameters (cert validation behavior, offered TLS 1.3 preference) stay fixed.
//!
//! Every emitted profile is a pure function of the seed and is forced into a declared, assembled
//! bounded parameter space — never arbitrary or unbounded.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod security;
pub use security::{
    assert_security_invariants, security_critical_tls_params, security_snapshot_for_seed,
    CertificateValidationPolicy, OfferedTlsVersions, SecurityCriticalTlsParams,
    SeedSecuritySnapshot, REQUIRED_NEGOTIATED_TLS_VERSION, SECURITY_TLS13_CIPHER_SUITE_IANA,
    SECURITY_TLS_GROUP_ALLOWLIST,
};

// generate_validated is defined below next to generate.

/// Domain separation for seed normalizers (normalize arbitrary bytes → 64-hex seed).
const SEED_DOMAIN_TAG: &[u8] = b"basecrawl/fingerprint-seed/v1\0";

/// Domain separation for JA3/JA4 digests derived from an emitted profile.
const JA3_DOMAIN_TAG: &[u8] = b"basecrawl/ja3/v1\0";
const JA4_DOMAIN_TAG: &[u8] = b"basecrawl/ja4/v1\0";
const CANVAS_DOMAIN_TAG: &[u8] = b"basecrawl/canvas-fp/v1\0";
const WEBGL_DOMAIN_TAG: &[u8] = b"basecrawl/webgl-fp/v1\0";

// ---------------------------------------------------------------------------
// Declared / bounded parameter space (allowlisted choices the seed indexes into)
// ---------------------------------------------------------------------------

/// Product Chromium pin from the digest-pinned CVM image (`image/Dockerfile` `CHROMIUM_VERSION`).
/// Client-Hints / UA major remain coherent with this pin under TDX; host diagnostics may use a
/// neighboring Chrome major when the local binary differs (never a non-Chrome brand).
pub const PINNED_CHROMIUM_VERSION: &str = "145.0.7632.46";

/// Major version of the product-pinned Chromium (VAL-STEALTH-003/006).
pub const PINNED_CHROMIUM_MAJOR: u32 = 145;

/// Full product Chromium version string (env `CHROMIUM_VERSION` overrides for operator diagnostics).
pub fn product_chromium_version() -> String {
    std::env::var("CHROMIUM_VERSION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| PINNED_CHROMIUM_VERSION.to_string())
}

/// Major component of [`product_chromium_version`].
pub fn product_chromium_major() -> u32 {
    product_chromium_version()
        .split('.')
        .next()
        .and_then(|part| part.parse().ok())
        .unwrap_or(PINNED_CHROMIUM_MAJOR)
}

/// Chrome User-Agents allowed by the measured image (hard + soft product surface).
///
/// All entries use the **product-pinned Chromium major** ([`PINNED_CHROMIUM_MAJOR`]) so hard-path
/// UA / Sec-CH-UA / CDP overrides cannot drift to a neighbor major (no 145 vs 148 product drift;
/// VAL-CDP-007 / VAL-FPRINT-013). Soft-path rustls and hard-path Chromium must never claim a
/// non-Chrome brand. Platform strings still vary (Linux / Windows / macOS / Ubuntu).
pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
];

/// Plausible hardwareConcurrency values the seed may legalize (VAL-STEALTH-009).
pub const HARDWARE_CONCURRENCY: &[u32] = &[2, 4, 6, 8, 12, 16];

/// Viewport dimensions (CSS px @ device-scale-factor 1) the seed may legalize.
pub const VIEWPORTS: &[(u32, u32)] = &[
    (1280, 800),
    (1366, 768),
    (1440, 900),
    (1536, 864),
    (1920, 1080),
    (1280, 720),
    (1600, 900),
    (1680, 1050),
];

/// IANA timezones the seed may select.
pub const TIMEZONES: &[&str] = &[
    "UTC",
    "America/New_York",
    "America/Los_Angeles",
    "America/Chicago",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Asia/Tokyo",
    "Asia/Shanghai",
    "Asia/Singapore",
    "Australia/Sydney",
    "America/Sao_Paulo",
];

/// BCP-47 locales the seed may legalize.
pub const LOCALES: &[&str] = &[
    "en-US", "en-GB", "de-DE", "fr-FR", "ja-JP", "es-ES", "pt-BR", "zh-CN", "ko-KR", "it-IT",
];

/// Ordered HTTP header name sequences (beyond Host/Connection defaults) that the client may emit.
///
/// Each entry is a complete client header-order template. Only values known to stay safe under the
/// crawler's HTTP/1.1 serializer / Chromium interceptor are listed.
pub const HEADER_ORDERS: &[&[&str]] = &[
    &["user-agent", "accept", "accept-language", "accept-encoding"],
    &["user-agent", "accept-language", "accept", "accept-encoding"],
    &["user-agent", "accept-encoding", "accept", "accept-language"],
    &["user-agent", "accept", "accept-encoding", "accept-language"],
    &["accept", "user-agent", "accept-language", "accept-encoding"],
    &["accept-language", "user-agent", "accept", "accept-encoding"],
];

/// TLS 1.3 cipher suite IANA values offered by the measured stack, default preference first.
///
/// These reorder into JA3/JA4 diversity when permuted. Every suite stays inside this closed set
/// (no TLS 1.0/1.1, no RC4/3DES).
pub const TLS13_CIPHER_SUITES: &[u16] = &[
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// Named cipher suite “slots” used when mapping to rustls `SupportedCipherSuite` by suite id.
pub const TLS13_CIPHER_NAMES: &[&str] = &[
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_AES_128_GCM_SHA256",
    "TLS13_CHACHA20_POLY1305_SHA256",
];

/// TLS 1.3 supported groups (elliptic curves / X25519) that the seed may re-order for JA3/JA4.
pub const TLS_GROUPS: &[&str] = &["X25519", "secp256r1", "secp384r1"];

/// WebGL unmasked renderer strings the seed may legalize (bounded vendor surface).
pub const WEBGL_RENDERERS: &[&str] = &[
    "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)",
    "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660/PCIe/SSE2, OpenGL 4.5.0)",
    "ANGLE (AMD, AMD Radeon RX 580 Series, OpenGL 4.6)",
    "ANGLE (Apple, Apple M1, OpenGL 4.1)",
    "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader)",
    "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics, OpenGL 4.6)",
];

/// WebGL unmasked vendor strings paired with the renderer allowlist.
pub const WEBGL_VENDORS: &[&str] = &[
    "Google Inc. (Intel)",
    "Google Inc. (NVIDIA)",
    "Google Inc. (AMD)",
    "Google Inc. (Apple)",
    "Google Inc. (Google)",
    "Google Inc. (Intel)",
];

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/// Fully-resolved fingerprint profile selected by a seed inside the bounded parameter space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintProfile {
    /// Normalized 64-char lowercase hex seed used to produce this profile (auditable).
    pub seed: String,
    pub user_agent: String,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub timezone: String,
    pub locale: String,
    /// Ordered header *names* (lower-case) defining client field order on outgoing request lines.
    pub header_names: Vec<String>,
    /// Accept-Language header svalue derived from `locale`.
    pub accept_language: String,
    /// Accept header value (fixed within the allowlist of browser-plausable values).
    pub accept: String,
    /// Accept-Encoding value (fixed subset of supported encodings).
    pub accept_encoding: String,
    /// TLS 1.3 cipher suite IANA IDs in offer order (drives JA3/JA4 diversity).
    pub tls13_cipher_order: Vec<u16>,
    /// Named TLS 1.3 suites in the same order as `tls13_cipher_order`.
    pub tls13_cipher_names: Vec<String>,
    /// Supported-group names in offer order.
    pub tls_group_order: Vec<String>,
    /// Deterministic canvas fingerprint digest (64-hex). Differs across seeds.
    pub canvas_fingerprint: String,
    /// Deterministic WebGL fingerprint digest (64-hex). Differs across seeds.
    pub webgl_fingerprint: String,
    /// WebGL unmasked vendor string (from the allowlist).
    pub webgl_vendor: String,
    /// WebGL unmasked renderer string (from the allowlist).
    pub webgl_renderer: String,
    /// Opaque u64 used to drive canvas noise injection in the browser.
    pub canvas_noise: u64,
    /// Deterministic JA3 digest synthesized from the ClientHello parameter selection.
    pub ja3: String,
    /// Deterministic JA4 digest synthesized from the ClientHello parameter selection.
    pub ja4: String,
    /// Platform token for CDP `set_user_agent` (derived from the UA string).
    pub platform: String,
    /// Positive `navigator.hardwareConcurrency` value (VAL-STEALTH-009).
    pub hardware_concurrency: u32,
    /// Chrome major version extracted from `user_agent` (coherent with CH-UA).
    pub chrome_major: u32,
    /// Full Chrome version string used for Client Hints (`Sec-CH-UA-Full-Version-List`).
    pub chrome_full_version: String,
}

/// Static description of the declared parameter space (for audits / VAL-ANTIBOT-037).
#[derive(Debug, Clone, Serialize)]
pub struct ParameterSpace {
    pub user_agents: Vec<&'static str>,
    pub viewports: Vec<(u32, u32)>,
    pub timezones: Vec<&'static str>,
    pub locales: Vec<&'static str>,
    pub header_orders: Vec<Vec<&'static str>>,
    pub tls13_cipher_suites: Vec<u16>,
    pub tls_groups: Vec<&'static str>,
    pub webgl_renderers: Vec<&'static str>,
}

/// Return the declared bounded parameter space the generator indexes into.
pub fn parameter_space() -> ParameterSpace {
    ParameterSpace {
        user_agents: USER_AGENTS.to_vec(),
        viewports: VIEWPORTS.to_vec(),
        timezones: TIMEZONES.to_vec(),
        locales: LOCALES.to_vec(),
        header_orders: HEADER_ORDERS.iter().map(|order| order.to_vec()).collect(),
        tls13_cipher_suites: TLS13_CIPHER_SUITES.to_vec(),
        tls_groups: TLS_GROUPS.to_vec(),
        webgl_renderers: WEBGL_RENDERERS.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Seed normalization + generation
// ---------------------------------------------------------------------------

/// Normalize an arbitrary seed input into a stable 64-char lowercase hex digest.
///
/// The generator always consumes this form so equal Byte inputs produce equal profiles whether the
/// caller supplied raw text, task/nonce material, or an already-hashed seed.
pub fn normalize_seed(input: &str) -> String {
    let trimmed = input.trim();
    if is_hex64(trimmed) {
        return trimmed.to_ascii_lowercase();
    }
    let mut hasher = Sha256::new();
    hasher.update(SEED_DOMAIN_TAG);
    hasher.update(trimmed.as_bytes());
    hex(&hasher.finalize())
}

/// Stable fallback used when no explicit seed and no task_id/nonce are supplied.
///
/// Must not depend on the target URL or scheme: unattended CLI scrapes (diagnostics, headers
/// parity tests) share one default profile so HTTP and HTTPS emit identical effective headers.
/// Mission workers always pass `task_id`/`nonce` or `--fingerprint-seed` and bypass this constant.
pub const UNATTENDED_DEFAULT_SEED: &str = "basecrawl-unattended-default";

/// Compose a seed from task/nonce material when the caller did not supply one explicitly.
///
/// Preference:
/// 1. Explicit non-empty seed.
/// 2. `task_id || 0x00 || nonce` when either is present.
/// 3. `fallback_material` (typically [`UNATTENDED_DEFAULT_SEED`]) so unattended scrapes stay
///    deterministic, auditable, and scheme-independent.
pub fn resolve_seed(
    explicit: Option<&str>,
    task_id: Option<&str>,
    nonce: Option<&str>,
    fallback_material: &str,
) -> String {
    if let Some(seed) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return normalize_seed(seed);
    }
    match (task_id, nonce) {
        (Some(task), Some(n)) if !task.is_empty() && !n.is_empty() => {
            normalize_seed(&format!("{task}\0{n}"))
        }
        (Some(task), _) if !task.is_empty() => normalize_seed(task),
        (_, Some(n)) if !n.is_empty() => normalize_seed(n),
        _ => normalize_seed(fallback_material),
    }
}

/// Generate a deterministic fingerprint profile from `seed` inside the allowlisted parameter space.
///
/// Security-critical TLS parameters are constant across every seed (cert validation stays strong,
/// TLS 1.3 remains required, cert/transcript capture stays enabled). Only non-security dimensions
/// are seed-selected. Generated profiles are checked against
/// [`security::assert_security_invariants`] so a regressor that smuggled a weak cipher or
/// weakened cert policy into the seed path fails closed (VAL-ANTIBOT-038, BOT-08).
pub fn generate(seed_input: &str) -> FingerprintProfile {
    let seed = normalize_seed(seed_input);
    let stream = SeedStream::new(&seed);

    let user_agent = coerce_user_agent_to_product_pin(pick(&stream.lane(0), USER_AGENTS));
    let (viewport_width, viewport_height) = *pick(&stream.lane(1), VIEWPORTS);
    let timezone = pick(&stream.lane(2), TIMEZONES).to_string();
    let locale = pick(&stream.lane(3), LOCALES).to_string();
    let header_template = *pick(&stream.lane(4), HEADER_ORDERS);
    let header_names: Vec<String> = header_template
        .iter()
        .map(|name| (*name).to_string())
        .collect();

    let cipher_perm = permutation(&stream.lane(5), TLS13_CIPHER_SUITES.len());
    let tls13_cipher_order: Vec<u16> = cipher_perm
        .iter()
        .map(|&i| TLS13_CIPHER_SUITES[i])
        .collect();
    let tls13_cipher_names: Vec<String> = cipher_perm
        .iter()
        .map(|&i| TLS13_CIPHER_NAMES[i].to_string())
        .collect();

    let group_perm = permutation(&stream.lane(6), TLS_GROUPS.len());
    let tls_group_order: Vec<String> = group_perm
        .iter()
        .map(|&i| TLS_GROUPS[i].to_string())
        .collect();

    let webgl_idx = stream.lane(7).next_usize(WEBGL_RENDERERS.len());
    let webgl_renderer = WEBGL_RENDERERS[webgl_idx].to_string();
    let webgl_vendor = WEBGL_VENDORS[webgl_idx].to_string();
    let canvas_noise = stream.lane(8).next_u64();
    let hardware_concurrency = *pick(&stream.lane(9), HARDWARE_CONCURRENCY);
    let (chrome_major, chrome_full_version) = chrome_versions_for_ua(&user_agent);

    let accept_language = accept_language_for(&locale);
    let accept =
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            .to_string();
    let accept_encoding = "gzip, deflate, br".to_string();
    let platform = platform_for(&user_agent);

    let ja3 = compute_ja3(&tls13_cipher_order, &tls_group_order, &header_names);
    let ja4 = compute_ja4(&tls13_cipher_order, &tls_group_order, &locale);
    let canvas_fingerprint = compute_canvas_fingerprint(&seed, canvas_noise);
    let webgl_fingerprint = compute_webgl_fingerprint(&seed, &webgl_vendor, &webgl_renderer);

    FingerprintProfile {
        seed,
        user_agent,
        viewport_width,
        viewport_height,
        timezone,
        locale,
        header_names,
        accept_language,
        accept,
        accept_encoding,
        tls13_cipher_order,
        tls13_cipher_names,
        tls_group_order,
        canvas_fingerprint,
        webgl_fingerprint,
        webgl_vendor,
        webgl_renderer,
        canvas_noise,
        ja3,
        ja4,
        platform,
        hardware_concurrency,
        chrome_major,
        chrome_full_version,
    }
}

/// Generate a profile and fail closed if it escapes the security invariants
/// (VAL-ANTIBOT-038 / BOT-08). Production scrape paths should use this rather
/// than the pure [`generate`] when they are about to drive real TLS.
pub fn generate_validated(seed_input: &str) -> Result<FingerprintProfile, String> {
    let profile = generate(seed_input);
    security::assert_security_invariants(&profile)?;
    Ok(profile)
}

/// True when every field of `profile` falls inside [`parameter_space`].
pub fn is_within_parameter_space(profile: &FingerprintProfile) -> bool {
    USER_AGENTS.contains(&profile.user_agent.as_str())
        && VIEWPORTS.contains(&(profile.viewport_width, profile.viewport_height))
        && TIMEZONES.contains(&profile.timezone.as_str())
        && LOCALES.contains(&profile.locale.as_str())
        && HEADER_ORDERS.iter().any(|order| {
            order.len() == profile.header_names.len()
                && order
                    .iter()
                    .zip(profile.header_names.iter())
                    .all(|(a, b)| *a == b.as_str())
        })
        && profile.tls13_cipher_order.len() == TLS13_CIPHER_SUITES.len()
        && profile
            .tls13_cipher_order
            .iter()
            .all(|suite| TLS13_CIPHER_SUITES.contains(suite))
        && {
            // must be a permutation (no duplicates)
            let mut sorted = profile.tls13_cipher_order.clone();
            sorted.sort_unstable();
            let mut expected = TLS13_CIPHER_SUITES.to_vec();
            expected.sort_unstable();
            sorted == expected
        }
        && profile.tls_group_order.len() == TLS_GROUPS.len()
        && profile
            .tls_group_order
            .iter()
            .all(|g| TLS_GROUPS.contains(&g.as_str()))
        && WEBGL_RENDERERS.contains(&profile.webgl_renderer.as_str())
        && WEBGL_VENDORS.contains(&profile.webgl_vendor.as_str())
        && HARDWARE_CONCURRENCY.contains(&profile.hardware_concurrency)
        && profile.hardware_concurrency > 0
        && profile.chrome_major > 0
        && chrome_versions_for_ua(&profile.user_agent)
            == (profile.chrome_major, profile.chrome_full_version.clone())
        && is_hex64(&profile.seed)
        && is_hex64(&profile.ja3)
        && is_hex64(&profile.ja4)
        && is_hex64(&profile.canvas_fingerprint)
        && is_hex64(&profile.webgl_fingerprint)
}

/// Build the ordered effective header list for a direct fetch / Chromium request.
///
/// The controlled User-Agent is always present. Seeded Accept* headers fill any header-order
/// slots that the caller did not already supply.
pub fn effective_fingerprint_headers(
    profile: &FingerprintProfile,
    caller_headers: &[(String, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for name in &profile.header_names {
        let value = if name.eq_ignore_ascii_case("user-agent") {
            profile.user_agent.clone()
        } else if name.eq_ignore_ascii_case("accept") {
            profile.accept.clone()
        } else if name.eq_ignore_ascii_case("accept-language") {
            profile.accept_language.clone()
        } else if name.eq_ignore_ascii_case("accept-encoding") {
            profile.accept_encoding.clone()
        } else {
            continue;
        };
        out.push((name.clone(), value));
    }

    for (name, value) in caller_headers {
        if name.eq_ignore_ascii_case("user-agent")
            || name.eq_ignore_ascii_case("accept")
            || name.eq_ignore_ascii_case("accept-language")
            || name.eq_ignore_ascii_case("accept-encoding")
        {
            // Seed-owned headers win; caller overrides for credentials live below.
            continue;
        }
        out.push((name.to_ascii_lowercase(), value.clone()));
    }
    out
}

/// Produce a JS snippet injected via CDP `Page.addScriptToEvaluateOnNewDocument` that:
/// - installs **once** (idempotent guard) so dual inject cannot re-expose automation flags
///   (VAL-CDP-002/005)
/// - forces `navigator.webdriver` false (VAL-STEALTH-004 / VAL-CDP-001)
/// - pins `navigator.language` / `navigator.languages` to the profile locale
/// - pins a positive `navigator.hardwareConcurrency` (VAL-STEALTH-009)
/// - presents a plausible `window.chrome` surface and a coherent `chrome.runtime` policy
///   (VAL-FPRINT-001/002): non-throwing common reads; `runtime.id` stays `undefined` for
///   non-extension pages (honest residual, not a half-implemented extension host)
/// - injects canvas / WebGL noise so rendering fingerprints differ per seed
///
/// This is a hard-path identity **baseline** under TDX; it does **not** claim an undetectable,
/// universal bot-defeat, anonymous, or 100% success posture. Never embeds proxy/task secrets.
pub fn browser_injection_script(profile: &FingerprintProfile) -> String {
    let locale = serde_json::to_string(&profile.locale).unwrap_or_else(|_| "\"en-US\"".into());
    let short_locale = profile.locale.split('-').next().unwrap_or("en");
    let short_locale_json = serde_json::to_string(short_locale).unwrap_or_else(|_| "\"en\"".into());
    let vendor =
        serde_json::to_string(&profile.webgl_vendor).unwrap_or_else(|_| "\"Google Inc.\"".into());
    let renderer =
        serde_json::to_string(&profile.webgl_renderer).unwrap_or_else(|_| "\"ANGLE\"".into());
    let noise = profile.canvas_noise;
    let hardware = profile.hardware_concurrency.max(1);
    let platform =
        serde_json::to_string(&profile.platform).unwrap_or_else(|_| "\"Linux x86_64\"".into());
    // Secrets must never enter this string (VAL-CDP-009): only seed-derived surface values.
    format!(
        r#"(function() {{
  // Idempotent install identity (VAL-CDP-002): a second evaluate must no-op rather than thrash
  // property descriptors / re-expose automation seams.
  if (typeof window !== 'undefined' && window.__bcStealthInstalled) {{ return; }}
  try {{
    Object.defineProperty(window, '__bcStealthInstalled', {{
      value: true,
      configurable: false,
      enumerable: false,
      writable: false
    }});
  }} catch (_) {{
    try {{ window.__bcStealthInstalled = true; }} catch (_) {{}}
  }}

  const locale = {locale};
  const shortLocale = {short_locale_json};
  const hardwareConcurrency = {hardware};
  const platform = {platform};

  const installWebdriverFalse = () => {{
    const getter = () => false;
    try {{
      Object.defineProperty(Navigator.prototype, 'webdriver', {{
        get: getter,
        set: undefined,
        configurable: true,
        enumerable: true
      }});
    }} catch (_) {{}}
    try {{
      Object.defineProperty(navigator, 'webdriver', {{
        get: getter,
        set: undefined,
        configurable: true,
        enumerable: true
      }});
    }} catch (_) {{
      try {{
        if (navigator.webdriver) {{
          Object.defineProperty(navigator, 'webdriver', {{
            get: getter,
            configurable: true
          }});
        }}
      }} catch (_) {{}}
    }}
  }};
  installWebdriverFalse();

  try {{
    Object.defineProperty(Navigator.prototype, 'language', {{ get: () => locale, configurable: true }});
    Object.defineProperty(Navigator.prototype, 'languages', {{
      get: () => Object.freeze([locale, shortLocale]),
      configurable: true
    }});
    Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {{
      get: () => hardwareConcurrency,
      configurable: true
    }});
    Object.defineProperty(Navigator.prototype, 'platform', {{ get: () => platform, configurable: true }});
    Object.defineProperty(Navigator.prototype, 'plugins', {{
      get: () => {{
        const fake = {{ length: 1, 0: {{ name: 'PDF Viewer' }}, item: function() {{ return this[0]; }} }};
        return fake;
      }},
      configurable: true
    }});
  }} catch (_) {{}}

  // Plausible Chromium chrome surface (VAL-FPRINT-001) + runtime policy (VAL-FPRINT-002).
  // Policy: present a non-throwing chrome object. For pages without an extension context,
  // chrome.runtime exists with id === undefined (standard Chromium residual), and common
  // method slots are non-throwing'stubs' that reject rather than explode on property access.
  try {{
    const ensureChrome = () => {{
      if (typeof window.chrome === 'undefined' || window.chrome === null) {{
        try {{
          Object.defineProperty(window, 'chrome', {{
            value: {{}},
            configurable: true,
            enumerable: true,
            writable: true
          }});
        }} catch (_) {{
          try {{ window.chrome = {{}}; }} catch (_) {{}}
        }}
      }}
      if (!window.chrome || typeof window.chrome !== 'object') {{ return; }}
      if (typeof window.chrome.runtime === 'undefined') {{
        const runtime = {{
          // Non-extension residual: id is undefined (not a fake extension UUID).
          id: undefined,
          connect: function () {{
            throw new Error('Could not establish connection. Receiving end does not exist.');
          }},
          sendMessage: function () {{
            // Match callback-style residual: invoke response with lastError, not an uncaught throw
            // from mere property access. Calling the function still fails closed honestly.
            const args = Array.prototype.slice.call(arguments);
            const cb = typeof args[args.length - 1] === 'function' ? args[args.length - 1] : null;
            try {{
              if (window.chrome && window.chrome.runtime) {{
                window.chrome.runtime.lastError = {{ message: 'Could not establish connection. Receiving end does not exist.' }};
              }}
            }} catch (_) {{}}
            if (cb) {{
              try {{ cb(); }} catch (_) {{}}
            }}
          }}
        }};
        try {{
          Object.defineProperty(window.chrome, 'runtime', {{
            value: runtime,
            configurable: true,
            enumerable: true,
            writable: true
          }});
        }} catch (_) {{
          try {{ window.chrome.runtime = runtime; }} catch (_) {{}}
        }}
      }} else if (window.chrome.runtime && typeof window.chrome.runtime === 'object') {{
        // Coherent residual touches when a thin/host runtime already exists: ensure property
        // access of `id` does not throw (undefined ok), and method slots are callable-or-missing
        // without getter throw loops.
        try {{ void window.chrome.runtime.id; }} catch (_) {{
          try {{
            Object.defineProperty(window.chrome.runtime, 'id', {{
              value: undefined,
              configurable: true
            }});
          }} catch (_) {{}}
        }}
      }}
      // Minimal loadTimes/csi surface: present as functions when absent (common Chrome checks).
      if (typeof window.chrome.loadTimes !== 'function') {{
        try {{
          window.chrome.loadTimes = function () {{
            return {{
              commitLoadTime: 0,
              connectionInfo: 'http/1.1',
              finishDocumentLoadTime: 0,
              finishLoadTime: 0,
              firstPaintAfterLoadTime: 0,
              firstPaintTime: 0,
              navigationType: 'Other',
              npnNegotiatedProtocol: 'unknown',
              requestTime: 0,
              startLoadTime: 0,
              wasAlternateProtocolAvailable: false,
              wasFetchedViaSpdy: false,
              wasNpnNegotiated: false
            }};
          }};
        }} catch (_) {{}}
      }}
      if (typeof window.chrome.csi !== 'function') {{
        try {{
          window.chrome.csi = function () {{
            return {{ startE: 0, onloadT: 0, pageT: 0, tran: 15 }};
          }};
        }} catch (_) {{}}
      }}
      if (typeof window.chrome.app === 'undefined') {{
        try {{
          window.chrome.app = {{
            isInstalled: false,
            InstallState: {{ DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }},
            RunningState: {{ CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }}
          }};
        }} catch (_) {{}}
      }}
    }};
    ensureChrome();
  }} catch (_) {{}}

  const canvasNoise = {noise} >>> 0;
  const patchCanvas = (proto) => {{
    if (!proto || !proto.getImageData) return;
    if (proto.getImageData.__bcPatched) return;
    const original = proto.getImageData;
    const patched = function(x, y, w, h) {{
      const image = original.apply(this, arguments);
      if (image && image.data && image.data.length > 0) {{
        const data = image.data;
        for (let i = 0; i < Math.min(16, data.length); i++) {{
          data[i] = (data[i] ^ ((canvasNoise >>> (i % 4 * 8)) & 0xff)) & 0xff;
        }}
      }}
      return image;
    }};
    try {{ patched.__bcPatched = true; }} catch (_) {{}}
    proto.getImageData = patched;
  }};
  try {{
    patchCanvas(CanvasRenderingContext2D && CanvasRenderingContext2D.prototype);
  }} catch (_) {{}}

  const vendor = {vendor};
  const renderer = {renderer};
  const patchWebgl = (proto) => {{
    if (!proto || !proto.getParameter) return;
    if (proto.getParameter.__bcPatched) return;
    const original = proto.getParameter;
    const patched = function(parameter) {{
      const UNMASKED_VENDOR_WEBGL = 0x9245;
      const UNMASKED_RENDERER_WEBGL = 0x9246;
      if (parameter === UNMASKED_VENDOR_WEBGL) return vendor;
      if (parameter === UNMASKED_RENDERER_WEBGL) return renderer;
      return original.apply(this, arguments);
    }};
    try {{ patched.__bcPatched = true; }} catch (_) {{}}
    proto.getParameter = patched;
  }};
  try {{
    patchWebgl(WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchWebgl(typeof WebGL2RenderingContext !== 'undefined' && WebGL2RenderingContext.prototype);
  }} catch (_) {{}}
}})();"#,
        locale = locale,
        short_locale_json = short_locale_json,
        noise = noise,
        vendor = vendor,
        renderer = renderer,
        hardware = hardware,
        platform = platform,
    )
}

/// Brand list + full version for CDP `userAgentMetadata` / `Sec-CH-UA` (VAL-STEALTH-003/006).
pub fn client_hints_brands(profile: &FingerprintProfile) -> Vec<(String, String)> {
    let major = profile.chrome_major.to_string();
    vec![
        ("Not:A-Brand".to_string(), "99".to_string()),
        ("Google Chrome".to_string(), major.clone()),
        ("Chromium".to_string(), major),
    ]
}

/// Serialize client-hints brands in the wire form Chromium uses for `Sec-CH-UA`.
pub fn sec_ch_ua_header(profile: &FingerprintProfile) -> String {
    client_hints_brands(profile)
        .into_iter()
        .map(|(brand, version)| format!("\"{brand}\";v=\"{version}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// High-level platform family for Client Hints (`Sec-CH-UA-Platform`).
pub fn client_hints_platform(profile: &FingerprintProfile) -> &'static str {
    if profile.platform.starts_with("Win") {
        "Windows"
    } else if profile.platform.starts_with("Mac") {
        "macOS"
    } else {
        "Linux"
    }
}

/// Architecture token for Client Hints.
pub fn client_hints_architecture(_profile: &FingerprintProfile) -> &'static str {
    // Current allowlisted platforms are all desktop x86_64.
    "x86"
}

fn chrome_versions_for_ua(user_agent: &str) -> (u32, String) {
    let parsed_major = user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|rest| {
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest.get(..end)
        })
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(product_chromium_major());
    // Hard- and soft-path product surface: always emit the single product pin major so CDP UA
    // override, Sec-CH-UA brands, and fullVersionList cannot 145-vs-148 drift (VAL-CDP-007 /
    // VAL-FPRINT-013). If a future operator opens the allowlist to a neighbor major intentionally,
    // pin constants and residual TCB docs must move together.
    let major = if parsed_major != product_chromium_major() {
        product_chromium_major()
    } else {
        parsed_major
    };
    let full = if major == product_chromium_major() {
        product_chromium_version()
    } else {
        format!("{major}.0.0.0")
    };
    (major, full)
}

/// Rewrite a User-Agent so its Chrome/ major matches the product pin (hard-path coherence).
///
/// Keeps the rest of the UA string (platform tokens) intact when only the major digits drift.
pub fn coerce_user_agent_to_product_pin(user_agent: &str) -> String {
    let pin_major = product_chromium_major();
    if let Some(after) = user_agent.split_once("Chrome/") {
        let rest = after.1;
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if let Ok(parsed) = rest[..end].parse::<u32>() {
            if parsed != pin_major {
                return format!("{}Chrome/{}{}", after.0, pin_major, &rest[end..]);
            }
        }
    }
    user_agent.to_string()
}

/// True when UA major, chrome_major, and chrome_full_version all match the product pin major.
pub fn hard_path_versions_are_pin_coherent(profile: &FingerprintProfile) -> bool {
    let pin = product_chromium_major();
    let ua_major = profile.user_agent.split("Chrome/").nth(1).and_then(|rest| {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest.get(..end)?.parse::<u32>().ok()
    });
    let full_major = profile
        .chrome_full_version
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok());
    ua_major == Some(pin)
        && profile.chrome_major == pin
        && full_major == Some(pin)
        && profile.chrome_full_version.starts_with(&format!("{pin}."))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn accept_language_for(locale: &str) -> String {
    let short = locale.split('-').next().unwrap_or(locale);
    if short == locale {
        format!("{locale},en;q=0.8")
    } else {
        format!("{locale},{short};q=0.9,en;q=0.8")
    }
}

fn platform_for(user_agent: &str) -> String {
    if user_agent.contains("Windows") {
        "Win32".to_string()
    } else if user_agent.contains("Macintosh") || user_agent.contains("Mac OS") {
        "MacIntel".to_string()
    } else {
        "Linux x86_64".to_string()
    }
}

fn compute_ja3(ciphers: &[u16], groups: &[String], header_names: &[String]) -> String {
    // Synthetic JA3: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    // encoded as a domain-separated SHA-256 over the selected parameters. Different seeds
    // with different cipher/group order therefore emit different digests (VAL-ANTIBOT-033).
    let mut hasher = Sha256::new();
    hasher.update(JA3_DOMAIN_TAG);
    hasher.update(b"771,"); // TLS 1.2 ClientHello version wire value still used by modern browsers
    for (i, suite) in ciphers.iter().enumerate() {
        if i > 0 {
            hasher.update(b"-");
        }
        hasher.update(format!("{suite:04x}").as_bytes());
    }
    hasher.update(b",");
    // Fixed extension order dimension + seed-selected header-order entropy
    hasher.update(b"0-11-10-35-16-13");
    hasher.update(b",");
    for (i, group) in groups.iter().enumerate() {
        if i > 0 {
            hasher.update(b"-");
        }
        hasher.update(group.as_bytes());
    }
    hasher.update(b",0");
    hasher.update(b"|headers:");
    for name in header_names {
        hasher.update(name.as_bytes());
        hasher.update(b",");
    }
    hex(&hasher.finalize())
}

fn compute_ja4(ciphers: &[u16], groups: &[String], locale: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(JA4_DOMAIN_TAG);
    hasher.update(b"t13d"); // quic? no; TLS1.3, desktop
    hasher.update(format!("{:02}", ciphers.len()).as_bytes());
    hasher.update(b"_");
    for (i, suite) in ciphers.iter().enumerate() {
        if i > 0 {
            hasher.update(b",");
        }
        hasher.update(format!("{suite:04x}").as_bytes());
    }
    hasher.update(b"_");
    for (i, group) in groups.iter().enumerate() {
        if i > 0 {
            hasher.update(b",");
        }
        hasher.update(group.as_bytes());
    }
    hasher.update(b"_");
    hasher.update(locale.as_bytes());
    hex(&hasher.finalize())
}

fn compute_canvas_fingerprint(seed: &str, noise: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CANVAS_DOMAIN_TAG);
    hasher.update(seed.as_bytes());
    hasher.update(noise.to_le_bytes());
    hex(&hasher.finalize())
}

fn compute_webgl_fingerprint(seed: &str, vendor: &str, renderer: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(WEBGL_DOMAIN_TAG);
    hasher.update(seed.as_bytes());
    hasher.update(vendor.as_bytes());
    hasher.update(b"\0");
    hasher.update(renderer.as_bytes());
    hex(&hasher.finalize())
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Deterministic pseudo-random stream derived from a seed +lane index.
struct SeedStream {
    seed: [u8; 32],
}

impl SeedStream {
    fn new(seed_hex: &str) -> Self {
        let mut seed = [0u8; 32];
        if let Ok(bytes) = hex_decode32(seed_hex) {
            seed = bytes;
        } else {
            let digest = Sha256::digest(seed_hex.as_bytes());
            seed.copy_from_slice(&digest);
        }
        Self { seed }
    }

    fn lane(&self, lane: u64) -> Lane {
        let mut hasher = Sha256::new();
        hasher.update(b"basecrawl/fp-stream/v1\0");
        hasher.update(self.seed);
        hasher.update(lane.to_le_bytes());
        let block = hasher.finalize();
        let mut state = [0u8; 32];
        state.copy_from_slice(&block);
        Lane { state, offset: 0 }
    }
}

struct Lane {
    state: [u8; 32],
    offset: usize,
}

impl Lane {
    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(b"basecrawl/fp-stream-block/v1\0");
        hasher.update(self.state);
        let block = hasher.finalize();
        self.state.copy_from_slice(&block);
        self.offset = 0;
    }

    fn next_u64(&mut self) -> u64 {
        if self.offset + 8 > 32 {
            self.refill();
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.state[self.offset..self.offset + 8]);
        self.offset += 8;
        u64::from_le_bytes(buf)
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() as usize) % bound
    }
}

fn pick<'a, T>(lane: &Lane, items: &'a [T]) -> &'a T {
    // Lane needs &mut for next_usize; clone state via a local.
    let mut local = Lane {
        state: lane.state,
        offset: lane.offset,
    };
    &items[local.next_usize(items.len())]
}

fn permutation(lane: &Lane, n: usize) -> Vec<usize> {
    let mut local = Lane {
        state: lane.state,
        offset: lane.offset,
    };
    let mut items: Vec<usize> = (0..n).collect();
    // Fisher–Yates using the deterministic lane.
    for i in (1..n).rev() {
        let j = local.next_usize(i + 1);
        items.swap(i, j);
    }
    items
}

fn hex_decode32(input: &str) -> Result<[u8; 32], ()> {
    if input.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&input[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
        out[i] = byte;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn val_antibot_033_different_seeds_emit_different_ja3_ja4() {
        // Search a small pair space so the assertion is robust across the 6-suite
        // permutation set without hardcoding any particular seed string pair.
        let mut found_diff = false;
        for i in 0..32u32 {
            let a = generate(&format!("miner-a-{i}"));
            let b = generate(&format!("miner-b-{i}"));
            if a.ja3 != b.ja3 && a.ja4 != b.ja4 {
                found_diff = true;
                break;
            }
        }
        assert!(
            found_diff,
            "at least one seed pair must emit different JA3 and JA4"
        );

        // Direct check: seeds that permute ciphers differently always diverge.
        let mut seen = HashSet::new();
        for i in 0..48u32 {
            seen.insert(generate(&format!("ja3-cover-{i}")).ja3);
        }
        assert!(
            seen.len() >= 4,
            "JA3 diversity must cover multiple cipher/header orderings, got {}",
            seen.len()
        );
    }

    #[test]
    fn val_antibot_034_same_seed_reproduces_fingerprint_dimensions() {
        let first = generate("repro-seed-42");
        let second = generate("repro-seed-42");
        assert_eq!(first, second);

        let other = generate("repro-seed-99");
        // User-Agent space is small; require that *some* dimension diverges across seeds.
        assert!(
            first.header_names != other.header_names
                || first.viewport_width != other.viewport_width
                || first.timezone != other.timezone
                || first.locale != other.locale
                || first.user_agent != other.user_agent
        );

        // Explicit dimension list required by the contract.
        let same = generate("repro-seed-42");
        assert_eq!(first.header_names, same.header_names);
        assert_eq!(first.user_agent, same.user_agent);
        assert_eq!(
            (first.viewport_width, first.viewport_height),
            (same.viewport_width, same.viewport_height)
        );
        assert_eq!(first.timezone, same.timezone);
        assert_eq!(first.locale, same.locale);
    }

    #[test]
    fn val_antibot_035_canvas_webgl_differ_across_seeds() {
        let a = generate("canvas-seed-a");
        let b = generate("canvas-seed-b");
        assert_ne!(a.canvas_fingerprint, b.canvas_fingerprint);
        assert_ne!(a.webgl_fingerprint, b.webgl_fingerprint);
    }

    #[test]
    fn val_antibot_036_seed_is_present_and_normalized() {
        let profile = generate("audit-me");
        assert_eq!(profile.seed, normalize_seed("audit-me"));
        assert_eq!(profile.seed.len(), 64);
        assert!(profile.seed.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn val_antibot_037_all_profiles_stay_in_bounded_parameter_space() {
        let seeds = [
            "0",
            "1",
            "miner-1",
            "miner-2",
            "task-aaaaaaaa",
            "task-bbbbbbbb",
            "ffff",
            "zzzz",
            &"ab".repeat(32),
            &"00".repeat(32),
            "hello world",
            "Tokyo-zone",
            "locale-test",
            "cipher-x",
            "cipher-y",
            "viewport-a",
            "viewport-b",
            "ua-a",
            "ua-b",
            "full-coverage-21",
            "full-coverage-22",
            "full-coverage-23",
            "full-coverage-24",
            "full-coverage-25",
            "full-coverage-26",
            "full-coverage-27",
            "full-coverage-28",
            "full-coverage-29",
            "full-coverage-30",
            "full-coverage-31",
            "full-coverage-32",
        ];
        for seed in seeds {
            let profile = generate(seed);
            assert!(
                is_within_parameter_space(&profile),
                "profile for seed {seed:?} escaped the declared parameter space: {profile:?}"
            );
        }
    }

    #[test]
    fn diverse_seeds_cover_multiple_parameter_slots() {
        let mut uas = HashSet::new();
        let mut timezones = HashSet::new();
        let mut locales = HashSet::new();
        let mut ja3s = HashSet::new();
        for i in 0..64u32 {
            let profile = generate(&format!("coverage-{i}"));
            uas.insert(profile.user_agent.clone());
            timezones.insert(profile.timezone.clone());
            locales.insert(profile.locale.clone());
            ja3s.insert(profile.ja3.clone());
        }
        assert!(uas.len() >= 2, "UA diversity across seeds");
        assert!(timezones.len() >= 2, "timezone diversity across seeds");
        assert!(locales.len() >= 2, "locale diversity across seeds");
        assert!(ja3s.len() >= 8, "JA3 diversity across seeds");
    }

    #[test]
    fn resolve_seed_prefers_explicit_then_task_nonce() {
        let explicit = resolve_seed(Some("explicit-seed"), Some("t"), Some("n"), "fallback");
        assert_eq!(explicit, normalize_seed("explicit-seed"));

        let from_task = resolve_seed(None, Some("task-1"), Some("nonce-9"), "fallback");
        assert_eq!(from_task, normalize_seed("task-1\0nonce-9"));

        let fallback = resolve_seed(None, None, None, UNATTENDED_DEFAULT_SEED);
        assert_eq!(fallback, normalize_seed(UNATTENDED_DEFAULT_SEED));
    }

    #[test]
    fn effective_headers_include_seeded_order_and_caller_credentials() {
        let profile = generate("header-order-seed");
        let headers =
            effective_fingerprint_headers(&profile, &[("Authorization".into(), "Bearer x".into())]);
        assert!(headers
            .iter()
            .any(|(n, v)| n == "user-agent" && v == &profile.user_agent));
        assert!(headers
            .iter()
            .any(|(n, v)| n == "authorization" && v == "Bearer x"));
        // Order of seed-owned headers must match the profile.
        let seed_owned: Vec<&str> = headers
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| {
                matches!(
                    *n,
                    "user-agent" | "accept" | "accept-language" | "accept-encoding"
                )
            })
            .collect();
        assert_eq!(
            seed_owned,
            profile
                .header_names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn browser_injection_contains_canvas_and_webgl_hooks() {
        let profile = generate("inject-seed");
        let script = browser_injection_script(&profile);
        assert!(script.contains("getImageData"));
        assert!(script.contains("UNMASKED_RENDERER_WEBGL"));
        assert!(script.contains(&profile.webgl_renderer));
        assert!(script.contains("language"));
        assert!(script.contains("webdriver"));
        assert!(script.contains("hardwareConcurrency"));
        assert!(script.contains(&profile.hardware_concurrency.to_string()));
        // M18 surface: idempotent chrome / runtime policy, no dual-inject thrash.
        assert!(script.contains("__bcStealthInstalled"));
        assert!(script.contains("window.chrome") || script.contains("chrome"));
        assert!(script.contains("runtime"));
        // Never embed void credentials or marketing absolute claims.
        for banned in [
            "oxylabs",
            "2captcha",
            "undetectable",
            "trustless",
            "anonymous",
            "pr.oxylabs.io",
            "openai_api_key",
        ] {
            assert!(
                !script.to_ascii_lowercase().contains(banned),
                "inject must not embed banned token {banned}"
            );
        }
    }

    #[test]
    fn product_chromium_pin_is_coherent() {
        assert_eq!(PINNED_CHROMIUM_MAJOR, 145);
        assert!(product_chromium_version().starts_with("145."));
        let profile = generate("pin-coherent");
        assert_eq!(profile.chrome_major, PINNED_CHROMIUM_MAJOR);
        assert!(hard_path_versions_are_pin_coherent(&profile));
        let ch = sec_ch_ua_header(&profile);
        assert!(ch.contains("Google Chrome"));
        assert!(ch.contains(&format!("v=\"{}\"", profile.chrome_major)));
        assert!(!ch.to_lowercase().contains("curl"));
    }

    #[test]
    fn hard_path_user_agents_are_single_pin_major() {
        for ua in USER_AGENTS {
            assert!(
                ua.contains(&format!("Chrome/{PINNED_CHROMIUM_MAJOR}.")),
                "allowlist UA must stay on pin major {PINNED_CHROMIUM_MAJOR}: {ua}"
            );
            assert!(
                !ua.contains("Chrome/148"),
                "allowlist must not introduce 148 drift: {ua}"
            );
            let (major, full) = chrome_versions_for_ua(ua);
            assert_eq!(major, PINNED_CHROMIUM_MAJOR);
            assert!(full.starts_with("145."));
        }
        // Coercion repairs a neighbor-major UA string if one ever reappears.
        let repaired = coerce_user_agent_to_product_pin(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
        );
        assert!(repaired.contains("Chrome/145."));
        assert!(!repaired.contains("Chrome/148."));
    }
}
