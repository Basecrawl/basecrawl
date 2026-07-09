//! Redirect-handling assertions (VAL-CRAWL-018..021).
//!
//! These exercise loop-safe HTTP redirect following: chains are followed to the final resource, the
//! per-hop redirect chain is captured, redirect loops are bounded by the documented hop cap with a
//! clear error, and relative `Location`s resolve against the correct base. Tests run against the
//! httpbin-compatible target selected by [`common::httpbin_base`] (the contract names `httpbin.org`;
//! a behavior-identical mirror is used only when it is unavailable).

mod common;

use common::httpbin_base;
use serde_json::Value;
use std::process::{Command, Output};
use std::time::Instant;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

/// Run a scrape and parse stdout as exactly one strict JSON object.
fn scrape_json(args: &[&str]) -> Value {
    let out = run(args);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout is not a single strict-JSON object: {e}\nstdout was:\n{stdout}")
    })
}

// VAL-CRAWL-018: redirect chains are followed to the final resource.
#[test]
fn redirect_chain_followed_to_final_resource() {
    let base = httpbin_base();
    let url = format!("{base}/redirect/3");
    let v = scrape_json(&[&url]);
    assert_eq!(
        v["response"]["status_code"], 200,
        "the terminal /get resource must report a 200 status"
    );
    let final_url = v["response"]["final_url"]
        .as_str()
        .expect("response.final_url must report the terminal location");
    assert_eq!(
        final_url,
        format!("{base}/get"),
        "final url must be the terminal /get target, not an intermediate 302"
    );
    // The request URL is preserved as-requested (the requested URL, not the redirect target).
    assert_eq!(v["request"]["url"], url);
}

// VAL-CRAWL-019: the redirect hop chain is captured.
#[test]
fn redirect_chain_metadata_is_captured() {
    let base = httpbin_base();
    let url = format!("{base}/redirect/3");
    let v = scrape_json(&[&url]);
    let chain = v["response"]["redirect_chain"]
        .as_array()
        .expect("response.redirect_chain must be an array");
    assert_eq!(
        chain.len(),
        3,
        "three intermediate redirects expected for /redirect/3, got: {chain:?}"
    );
    for hop in chain {
        let code = hop["status_code"]
            .as_u64()
            .expect("each hop must carry a numeric status_code");
        assert!(
            (300..400).contains(&code),
            "each hop must reflect a 3xx redirect status, got {code}"
        );
        assert!(
            hop["url"].as_str().is_some_and(|u| !u.is_empty()),
            "each hop must record the URL that returned the redirect"
        );
        assert!(
            hop["location"].as_str().is_some_and(|u| !u.is_empty()),
            "each hop must record the resolved Location target"
        );
    }
    // The first hop originates at the originally-requested URL.
    assert_eq!(chain[0]["url"], url);
    // Consecutive hops chain: each hop's resolved location is the next hop's origin URL.
    assert_eq!(chain[0]["location"], chain[1]["url"]);
    assert_eq!(chain[1]["location"], chain[2]["url"]);
    // The last hop resolves to the terminal /get target.
    assert_eq!(chain[2]["location"], format!("{base}/get"));
}

// VAL-CRAWL-020: redirect loops are detected and bounded (no hang).
#[test]
fn redirect_loop_is_bounded_with_clear_error() {
    let base = httpbin_base();
    let url = format!("{base}/redirect/50");
    let start = Instant::now();
    let out = run(&[&url, "--timeout", "20"]);
    let elapsed = start.elapsed();

    assert!(
        !out.status.success(),
        "a 50-hop chain must exceed the hop cap and exit non-zero"
    );
    assert!(
        out.stdout.is_empty(),
        "no partial ScrapeProof on a too-many-redirects failure"
    );
    let err: Value = serde_json::from_slice(&out.stderr).expect("structured JSON error on stderr");
    assert_eq!(
        err["error"]["kind"], "too_many_redirects",
        "a bounded redirect loop must report the too_many_redirects error kind"
    );
    let msg = err["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.to_lowercase().contains("too many redirects"),
        "the error must clearly say 'too many redirects', got: {msg}"
    );
    assert!(
        elapsed.as_secs() < 45,
        "must terminate promptly via the hop cap rather than hang, took {elapsed:?}"
    );
}

// VAL-CRAWL-021: cross-scheme / relative redirects resolve correctly.
#[test]
fn relative_redirect_resolves_against_correct_base() {
    let base = httpbin_base();
    let url = format!("{base}/relative-redirect/2");
    let v = scrape_json(&[&url]);
    assert_eq!(
        v["response"]["status_code"], 200,
        "a relative redirect chain must terminate at a 200"
    );
    let final_url = v["response"]["final_url"]
        .as_str()
        .expect("response.final_url must report the terminal location");
    assert_eq!(
        final_url,
        format!("{base}/get"),
        "a relative Location must resolve to the absolute /get on the same base"
    );
    let chain = v["response"]["redirect_chain"]
        .as_array()
        .expect("response.redirect_chain must be an array");
    assert_eq!(chain.len(), 2, "relative-redirect/2 has two hops");
    for hop in chain {
        let loc = hop["location"]
            .as_str()
            .expect("each hop location must be present");
        assert!(
            loc.starts_with(base),
            "each relative Location must resolve to an absolute URL on the requested base, got {loc}"
        );
    }
}
