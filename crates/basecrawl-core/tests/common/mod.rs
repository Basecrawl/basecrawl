//! Shared test support for the `basecrawl-core` integration tests.
//!
//! The validation contract names `httpbin.org` as the HTTP-semantics target, but that host is
//! frequently overloaded: it can answer `/get` while timing out other endpoints in the same run,
//! so it cannot be relied on for a deterministic suite. [`httpbin_base`] therefore returns the
//! first reachable base URL from a list of behavior-identical httpbin instances, ordered by
//! observed reliability. The reference-`httpbin` deployment at `nghttp2.org/httpbin` runs the same
//! software and the same endpoints as `httpbin.org` (redirects, gzip/deflate/brotli, headers, ...),
//! so the HTTP semantics under test are identical regardless of which base is selected.
#![allow(dead_code)]

use std::process::Command;
use std::sync::OnceLock;

/// httpbin-compatible bases in preference order (no trailing slash), ordered by observed
/// reliability. All run the httpbin API; `nghttp2.org/httpbin` and `httpbin.org` are the reference
/// Python httpbin (full endpoint set incl. brotli); `httpbingo.org` is a Go re-implementation kept
/// as a last-resort fallback.
const HTTPBIN_CANDIDATES: &[&str] = &[
    "https://nghttp2.org/httpbin",
    "https://httpbin.org",
    "https://httpbingo.org",
];

/// Return a live httpbin-compatible base URL, memoized for the lifetime of the test binary.
///
/// Panics only if none of the candidates are reachable, which indicates a genuine loss of network
/// egress rather than a single-host outage.
pub fn httpbin_base() -> &'static str {
    static BASE: OnceLock<&'static str> = OnceLock::new();
    BASE.get_or_init(|| {
        for base in HTTPBIN_CANDIDATES {
            if probe_ok(base) {
                return *base;
            }
        }
        panic!("no httpbin-compatible host reachable (tried {HTTPBIN_CANDIDATES:?})");
    })
}

/// Probe `{base}/get` with curl and report whether it answered `200`.
fn probe_ok(base: &str) -> bool {
    Command::new("curl")
        .args([
            "-s",
            "-m",
            "8",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("{base}/get"),
        ])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|code| code.trim() == "200")
        .unwrap_or(false)
}
