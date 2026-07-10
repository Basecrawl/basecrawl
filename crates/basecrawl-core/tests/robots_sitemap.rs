//! End-to-end robots.txt and sitemap discovery assertions (VAL-CRAWL-123/124).
//!
//! A local origin gives every test deterministic ownership of the robots policy and sitemap
//! documents. The CLI is exercised directly so the tests cover both the configured enforcement
//! policy and the observable ScrapeProof surfaces.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");

struct FixtureServer {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn successful_scrape(args: &[&str]) -> Value {
    let output = run(args);
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .expect("crawler stdout must contain exactly one ScrapeProof JSON object")
}

fn write_response(mut stream: TcpStream, status: &str, content_type: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Connection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write fixture response");
    stream.flush().expect("flush fixture response");
}

fn write_redirect(mut stream: TcpStream, location: &str) {
    write!(
        stream,
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
Connection: close\r\n\r\n"
    )
    .expect("write fixture redirect");
    stream.flush().expect("flush fixture redirect");
}

fn handle_connection(stream: TcpStream, base: &str, requests: &Arc<Mutex<Vec<String>>>) {
    let peer = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut line = String::new();
    while reader
        .read_line(&mut line)
        .map(|count| count > 0)
        .unwrap_or(false)
    {
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    requests
        .lock()
        .expect("fixture request log mutex")
        .push(target.clone());
    let path = target.split('?').next().unwrap_or("/");

    match path {
        "/robots.txt" => write_response(
            peer,
            "200 OK",
            "text/plain; charset=utf-8",
            &format!(
                "User-agent: *\nDisallow: /blocked\nAllow: /blocked/open\nSitemap: {base}/robots-sitemap.xml\n"
            ),
        ),
        "/robots-sitemap.xml" => write_response(
            peer,
            "200 OK",
            "application/xml",
            &format!(
                "<?xml version=\"1.0\"?><sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><sitemap><loc>{base}/nested-sitemap.xml</loc></sitemap></sitemapindex>"
            ),
        ),
        "/nested-sitemap.xml" => write_response(
            peer,
            "200 OK",
            "application/xml",
            &format!(
                "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>{base}/from-robots-a</loc></url><url><loc>{base}/from-robots-b</loc></url></urlset>"
            ),
        ),
        "/sitemap.xml" => write_response(
            peer,
            "200 OK",
            "application/xml",
            &format!(
                "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>{base}/fallback-a</loc></url><url><loc>{base}/fallback-b</loc></url></urlset>"
            ),
        ),
        "/blocked/open" | "/allowed" | "/sitemap-page" | "/blocked/private" => write_response(
            peer,
            "200 OK",
            "text/html; charset=utf-8",
            &format!("<!doctype html><html><body><main>fixture {path}</main></body></html>"),
        ),
        "/redirect-to-blocked" => {
            let target = if target.contains("observe=1") {
                "/blocked/private?redirect-observe-target=1"
            } else {
                "/blocked/private?redirect-target=1"
            };
            write_redirect(peer, target);
        }
        "/browser-server-redirect" => {
            let request_count = requests
                .lock()
                .expect("fixture request log mutex")
                .iter()
                .filter(|request| request.as_str() == target)
                .count();
            if request_count == 1 {
                write_response(
                    peer,
                    "200 OK",
                    "text/html; charset=utf-8",
                    "<!doctype html><html><body><main>BROWSER_SERVER_START</main></body></html>",
                );
            } else {
                write_redirect(peer, "/blocked/private?browser-server-target=1");
            }
        }
        "/browser-client-navigate" => {
            let target = if target.contains("observe=1") {
                "/blocked/private?browser-client-observe-target=1"
            } else {
                "/blocked/private?browser-client-target=1"
            };
            write_response(
                peer,
                "200 OK",
                "text/html; charset=utf-8",
                &format!(
                    "<!doctype html><html><body><main>BROWSER_CLIENT_START</main>\
                     <script>location.replace('{target}')</script></body></html>"
                ),
            );
        }
        "/iframe-document" => write_response(
            peer,
            "200 OK",
            "text/html; charset=utf-8",
            "<!doctype html><html><body><main>IFRAME_PARENT</main>\
             <iframe src='/blocked/private?iframe-document-target=1'></iframe></body></html>",
        ),
        _ => write_response(peer, "404 Not Found", "text/plain; charset=utf-8", "not found"),
    }
}

fn fixture_server() -> &'static FixtureServer {
    static SERVER: OnceLock<FixtureServer> = OnceLock::new();
    SERVER.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
        let base = format!("http://{}", listener.local_addr().expect("local address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_base = base.clone();
        let server_requests = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let base = server_base.clone();
                let requests = Arc::clone(&server_requests);
                thread::spawn(move || handle_connection(stream, &base, &requests));
            }
        });
        FixtureServer { base, requests }
    })
}

// VAL-CRAWL-123: an allowed robots rule is recorded and the requested page proceeds normally.
#[test]
fn allowed_path_records_an_honored_robots_disposition() {
    let server = fixture_server();
    let url = format!("{}/blocked/open", server.base);
    let proof = successful_scrape(&[&url, "--formats", "metadata", "--no-js"]);
    let robots = &proof["result"]["formats_produced"]["metadata"]["robotsPolicy"];

    assert_eq!(proof["response"]["status_code"], 200);
    assert_eq!(robots["policy"], "enforce");
    assert_eq!(robots["disposition"], "allowed");
    assert_eq!(robots["fetched"], true);
    assert_eq!(robots["matched_rule"]["directive"], "allow");
    assert_eq!(robots["matched_rule"]["path"], "/blocked/open");
    assert!(
        server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/robots.txt"),
        "the crawler must consult /robots.txt before crawling the page"
    );
}

// VAL-CRAWL-123: the default enforcement policy blocks a covered denied path before its page fetch.
#[test]
fn denied_path_is_blocked_with_an_observable_policy_error() {
    let server = fixture_server();
    let url = format!("{}/blocked/private?robots-denied=1", server.base);
    let output = run(&[&url, "--formats", "metadata", "--no-js"]);

    assert!(
        !output.status.success(),
        "a robots-denied path must not succeed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "no partial ScrapeProof is emitted"
    );
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("stderr must expose structured policy JSON");
    assert_eq!(error["error"]["kind"], "robots_denied");
    assert_eq!(error["error"]["robots"]["policy"], "enforce");
    assert_eq!(error["error"]["robots"]["disposition"], "denied");
    assert_eq!(error["error"]["robots"]["matched_rule"]["path"], "/blocked");
    assert!(
        !server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/blocked/private?robots-denied=1"),
        "the denied resource itself must never be fetched"
    );
}

// VAL-CRAWL-123: observe mode retains a correct denied disposition but deliberately permits fetch.
#[test]
fn observe_policy_surfaces_denial_while_permitting_the_page() {
    let server = fixture_server();
    let url = format!("{}/blocked/private?robots-observe=1", server.base);
    let proof = successful_scrape(&[
        &url,
        "--formats",
        "metadata",
        "--robots",
        "observe",
        "--no-js",
    ]);
    let robots = &proof["result"]["formats_produced"]["metadata"]["robotsPolicy"];

    assert_eq!(proof["response"]["status_code"], 200);
    assert_eq!(robots["policy"], "observe");
    assert_eq!(robots["disposition"], "denied");
    assert_eq!(robots["matched_rule"]["directive"], "disallow");
    assert_eq!(robots["matched_rule"]["path"], "/blocked");
}

// An allowed entry point must not bypass the policy by redirecting to a denied target. The target
// must be denied before its request is transmitted, rather than after a response is received.
#[test]
fn enforce_blocks_a_denied_direct_redirect_target_before_fetch() {
    let server = fixture_server();
    let url = format!("{}/redirect-to-blocked", server.base);
    let output = run(&[&url, "--formats", "metadata", "--no-js"]);

    assert!(
        !output.status.success(),
        "a redirect to a denied robots path must fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("stderr must expose structured policy JSON");
    assert_eq!(error["error"]["kind"], "robots_denied");
    assert_eq!(error["error"]["robots"]["disposition"], "denied");
    assert_eq!(
        error["error"]["robots"]["targetUrl"],
        format!("{}/blocked/private?redirect-target=1", server.base)
    );
    assert!(
        !server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/blocked/private?redirect-target=1"),
        "a denied redirect target must never be requested"
    );
}

// Observe mode leaves the redirect traversable, but exposes every document-hop policy decision in
// order so callers can see that the terminal path was denied.
#[test]
fn observe_records_each_direct_redirect_hop_without_blocking() {
    let server = fixture_server();
    let url = format!("{}/redirect-to-blocked?observe=1", server.base);
    let proof = successful_scrape(&[
        &url,
        "--formats",
        "metadata",
        "--robots",
        "observe",
        "--no-js",
    ]);
    let hops = proof["result"]["formats_produced"]["metadata"]["robotsPolicyHops"]
        .as_array()
        .expect("robots policy records every document hop");

    assert_eq!(proof["response"]["status_code"], 200);
    assert_eq!(
        hops.len(),
        2,
        "entry and redirect target must both be checked"
    );
    assert_eq!(hops[0]["targetUrl"], url);
    assert_eq!(hops[0]["disposition"], "unmatched");
    assert_eq!(
        hops[1]["targetUrl"],
        format!("{}/blocked/private?redirect-observe-target=1", server.base)
    );
    assert_eq!(hops[1]["disposition"], "denied");
    assert!(
        server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/blocked/private?redirect-observe-target=1"),
        "observe mode must allow the denied redirect target"
    );
}

// The browser receives its own top-level navigation policy checks. Its HTTP redirect target is
// denied before Chromium transmits it and is mapped back to the core robots error surface.
#[test]
fn enforce_blocks_a_denied_browser_redirect_target_before_fetch() {
    let server = fixture_server();
    let url = format!("{}/browser-server-redirect", server.base);
    let output = run(&[&url, "--formats", "html"]);

    assert!(
        !output.status.success(),
        "a browser redirect to a denied robots path must fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("stderr must expose structured policy JSON");
    assert_eq!(error["error"]["kind"], "robots_denied");
    assert_eq!(error["error"]["robots"]["disposition"], "denied");
    assert_eq!(
        error["error"]["robots"]["targetUrl"],
        format!("{}/blocked/private?browser-server-target=1", server.base)
    );
    assert!(
        !server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/blocked/private?browser-server-target=1"),
        "a denied browser redirect target must never be requested"
    );
}

// JavaScript navigation is also a top-level document hop, not an exception to enforcement.
#[test]
fn enforce_blocks_a_denied_browser_client_navigation_before_fetch() {
    let server = fixture_server();
    let url = format!("{}/browser-client-navigate", server.base);
    let output = run(&[&url, "--formats", "html"]);

    assert!(
        !output.status.success(),
        "a client navigation to a denied robots path must fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let error: Value =
        serde_json::from_slice(&output.stderr).expect("stderr must expose structured policy JSON");
    assert_eq!(error["error"]["kind"], "robots_denied");
    assert_eq!(error["error"]["robots"]["disposition"], "denied");
    assert_eq!(
        error["error"]["robots"]["targetUrl"],
        format!("{}/blocked/private?browser-client-target=1", server.base)
    );
    assert!(
        !server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/blocked/private?browser-client-target=1"),
        "a denied client navigation target must never be requested"
    );
}

// Client-side top-frame navigation follows the same policy. In observe mode the navigation remains
// allowed, and its denied disposition is emitted alongside the initial document hops.
#[test]
fn observe_records_a_denied_browser_client_navigation_without_blocking() {
    let server = fixture_server();
    let url = format!("{}/browser-client-navigate?observe=1", server.base);
    let proof = successful_scrape(&[&url, "--formats", "html,metadata", "--robots", "observe"]);
    let hops = proof["result"]["formats_produced"]["metadata"]["robotsPolicyHops"]
        .as_array()
        .expect("browser top-level navigation decisions must be recorded");
    let target = format!(
        "{}/blocked/private?browser-client-observe-target=1",
        server.base
    );

    assert!(
        proof["result"]["formats_produced"]["html"]
            .as_str()
            .expect("rendered HTML")
            .contains("fixture /blocked/private"),
        "observe mode must allow the client-side navigation"
    );
    assert!(
        hops.iter().any(|hop| {
            hop["targetUrl"].as_str() == Some(target.as_str())
                && hop["disposition"].as_str() == Some("denied")
        }),
        "the client navigation target must be recorded as denied: {hops:?}"
    );
}

// An iframe document is not a top-level document hop. It remains outside this policy so document
// navigation enforcement never becomes accidental subresource enforcement.
#[test]
fn enforce_does_not_apply_document_hop_policy_to_iframe_documents() {
    let server = fixture_server();
    let url = format!("{}/iframe-document", server.base);
    let proof = successful_scrape(&[&url, "--formats", "html"]);

    assert!(
        proof["result"]["formats_produced"]["html"]
            .as_str()
            .expect("rendered HTML")
            .contains("fixture /blocked/private"),
        "an iframe document must stay outside top-frame robots enforcement"
    );
    assert!(
        server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/blocked/private?iframe-document-target=1"),
        "the iframe must be fetched separately from top-frame document policy"
    );
}

// VAL-CRAWL-124: default /sitemap.xml and robots-referenced sitemap indexes become URL seed sets.
#[test]
fn discovers_default_and_robots_referenced_sitemaps_on_the_links_surface() {
    let server = fixture_server();
    let url = format!("{}/sitemap-page", server.base);
    let proof = successful_scrape(&[&url, "--formats", "links", "--no-js"]);
    let sitemap = proof["result"]["formats_produced"]["links"]["sitemap"]
        .as_array()
        .expect("links.sitemap must be a URL array")
        .iter()
        .map(|value| value.as_str().expect("sitemap URL is a string"))
        .collect::<Vec<_>>();

    for expected in [
        format!("{}/fallback-a", server.base),
        format!("{}/fallback-b", server.base),
        format!("{}/from-robots-a", server.base),
        format!("{}/from-robots-b", server.base),
    ] {
        assert!(
            sitemap.contains(&expected.as_str()),
            "sitemap URL '{expected}' was not surfaced: {sitemap:?}"
        );
    }
    assert!(
        server
            .requests
            .lock()
            .expect("fixture request log mutex")
            .iter()
            .any(|path| path == "/nested-sitemap.xml"),
        "the robots-referenced sitemap index must be followed and parsed"
    );
}
