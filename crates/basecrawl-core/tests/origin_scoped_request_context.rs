//! Origin-scoped caller credential regressions.
//!
//! The two loopback origins deliberately use different ports. The primary listener additionally
//! accepts a `127.0.0.2` alias so a redirect can change only the host while retaining its port.
//! This makes every origin component observable without using external services or real secrets.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const AUTH: &str = "Bearer caller-origin-token";
const PROXY_AUTH: &str = "Basic cHJveHktb3JpZ2lu";
const COOKIE: &str = "session=caller-origin-cookie";
const CUSTOM_SECRET: &str = "caller-origin-custom-secret";
const SAME_ORIGIN_AUTHENTICATED: &str = "SAME_ORIGIN_AUTHENTICATED";
const SAME_ORIGIN_ANONYMOUS: &str = "SAME_ORIGIN_ANONYMOUS";
const CROSS_ORIGIN_AUTHENTICATED: &str = "CROSS_ORIGIN_AUTHENTICATED";
const CROSS_ORIGIN_ANONYMOUS: &str = "CROSS_ORIGIN_ANONYMOUS";

type Headers = Vec<(String, String)>;

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
    headers: Headers,
}

#[derive(Debug, Default)]
struct OriginState {
    requests: Mutex<Vec<RecordedRequest>>,
}

struct Fixture {
    primary: String,
    primary_host_alias: String,
    secondary: String,
    primary_state: Arc<OriginState>,
    secondary_state: Arc<OriginState>,
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape_with_credentials(target: &str, formats: &str, no_js: bool) -> Value {
    let mut args = vec![
        target,
        "--formats",
        formats,
        "--robots",
        "ignore",
        "--header",
        "Authorization: Bearer caller-origin-token",
        "--header",
        "Proxy-Authorization: Basic cHJveHktb3JpZ2lu",
        "--header",
        "Cookie: session=caller-origin-cookie",
        "--header",
        "X-Policy-Secret: caller-origin-custom-secret",
    ];
    if no_js {
        args.push("--no-js");
    }
    let output = run(&args);
    assert!(
        output.status.success(),
        "credential-scoped scrape must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must contain one ScrapeProof JSON object")
}

/// Chromium rejects `Proxy-Authorization` on a direct origin request before CDP interception, so
/// browser coverage exercises the remaining caller-secret classes while direct coverage below also
/// proves that proxy credentials are stripped on a cross-origin redirect.
fn scrape_browser_with_credentials(target: &str, formats: &str) -> Value {
    scrape_browser_with_options(target, formats, false)
}

fn scrape_paginated_browser_with_credentials(target: &str, formats: &str) -> Value {
    scrape_browser_with_options(target, formats, true)
}

fn scrape_browser_with_options(target: &str, formats: &str, follow_pagination: bool) -> Value {
    let mut args = vec![
        target,
        "--formats",
        formats,
        "--robots",
        "ignore",
        "--header",
        "Authorization: Bearer caller-origin-token",
        "--header",
        "Cookie: session=caller-origin-cookie",
        "--header",
        "X-Policy-Secret: caller-origin-custom-secret",
    ];
    if follow_pagination {
        args.extend(["--follow-pagination", "--max-pages", "2"]);
    }
    let output = run(&args);
    assert!(
        output.status.success(),
        "credential-scoped browser scrape must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must contain one ScrapeProof JSON object")
}

fn request(stream: TcpStream) -> Option<(TcpStream, String, Headers)> {
    let peer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let path = request_line.split_whitespace().nth(1)?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((
            name.trim().to_ascii_lowercase(),
            value.trim_matches([' ', '\r', '\n']).to_string(),
        ));
    }
    Some((peer, path, headers))
}

fn header_is(headers: &Headers, name: &str, expected: &str) -> bool {
    headers
        .iter()
        .any(|(key, value)| key == name && value == expected)
}

fn has_all_caller_credentials(headers: &Headers) -> bool {
    header_is(headers, "authorization", AUTH)
        && header_is(headers, "proxy-authorization", PROXY_AUTH)
        && header_is(headers, "cookie", COOKIE)
        && header_is(headers, "x-policy-secret", CUSTOM_SECRET)
}

fn has_browser_caller_credentials(headers: &Headers) -> bool {
    header_is(headers, "authorization", AUTH)
        && header_is(headers, "cookie", COOKIE)
        && header_is(headers, "x-policy-secret", CUSTOM_SECRET)
}

fn has_any_caller_credential(headers: &Headers) -> bool {
    header_is(headers, "authorization", AUTH)
        || header_is(headers, "proxy-authorization", PROXY_AUTH)
        || header_is(headers, "cookie", COOKIE)
        || header_is(headers, "x-policy-secret", CUSTOM_SECRET)
}

fn write_response(mut stream: TcpStream, status: &str, extra_headers: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
Content-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write fixture response");
    stream.flush().expect("flush fixture response");
}

fn html(body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>origin scope</title></head>\
<body><main>{body}</main></body></html>"
    )
}

fn record(state: &Arc<OriginState>, path: &str, headers: &Headers) {
    state
        .requests
        .lock()
        .expect("request-state lock")
        .push(RecordedRequest {
            path: path.to_string(),
            headers: headers.clone(),
        });
}

fn serve_primary(
    stream: TcpStream,
    state: Arc<OriginState>,
    secondary: String,
    host_alias: String,
) {
    let Some((peer, path, headers)) = request(stream) else {
        return;
    };
    record(&state, &path, &headers);
    match path.as_str() {
        "/redirect-to-secondary" => write_response(
            peer,
            "302 Found",
            &format!("Location: {secondary}/terminal\r\n"),
            "",
        ),
        "/redirect-to-host-alias" => write_response(
            peer,
            "302 Found",
            &format!("Location: {host_alias}/host-terminal\r\n"),
            "",
        ),
        "/same-origin-auth" => {
            let marker = if has_browser_caller_credentials(&headers) {
                SAME_ORIGIN_AUTHENTICATED
            } else {
                SAME_ORIGIN_ANONYMOUS
            };
            write_response(peer, "200 OK", "", &html(marker));
        }
        "/pagination-cross-start" => {
            let page = html(&format!(
                "{SAME_ORIGIN_AUTHENTICATED}<a rel=\"next\" href=\"{secondary}/pagination-cross-next\">Next</a>"
            ));
            write_response(peer, "200 OK", "", &page);
        }
        "/pagination-same-start" => {
            let page = html(
                &format!(
                    "{SAME_ORIGIN_AUTHENTICATED}<a rel=\"next\" href=\"/pagination-same-next\">Next</a>"
                ),
            );
            write_response(peer, "200 OK", "", &page);
        }
        "/pagination-same-next" => {
            let marker = if has_browser_caller_credentials(&headers) {
                SAME_ORIGIN_AUTHENTICATED
            } else {
                SAME_ORIGIN_ANONYMOUS
            };
            let page = html(&format!(
                "{marker}<script src=\"/pagination-same-subresource\"></script>"
            ));
            write_response(peer, "200 OK", "", &page);
        }
        "/pagination-same-subresource" => {
            write_response(
                peer,
                "200 OK",
                "",
                "window.paginationSameSubresourceLoaded = true;",
            );
        }
        "/cross-subresources" => {
            let page = format!(
                "<!doctype html><html><body><main>{SAME_ORIGIN_AUTHENTICATED}</main>\
<img src=\"{secondary}/image\"><script src=\"{secondary}/script.js\"></script>\
<iframe src=\"{secondary}/frame\"></iframe>\
<script>fetch('{secondary}/xhr').catch(function(){{}});</script></body></html>"
            );
            write_response(peer, "200 OK", "", &page);
        }
        "/client-navigate-secondary" => {
            let page = format!(
                "<!doctype html><html><body>{SAME_ORIGIN_AUTHENTICATED}\
<script>location.replace('{secondary}/terminal')</script></body></html>"
            );
            write_response(peer, "200 OK", "", &page);
        }
        "/host-terminal" => {
            let marker = if has_any_caller_credential(&headers) {
                CROSS_ORIGIN_AUTHENTICATED
            } else {
                CROSS_ORIGIN_ANONYMOUS
            };
            write_response(peer, "200 OK", "", &html(marker));
        }
        _ => write_response(peer, "404 Not Found", "", &html("not found")),
    }
}

fn serve_secondary(stream: TcpStream, state: Arc<OriginState>) {
    let Some((peer, path, headers)) = request(stream) else {
        return;
    };
    record(&state, &path, &headers);
    match path.as_str() {
        "/terminal" => {
            let marker = if has_any_caller_credential(&headers) {
                CROSS_ORIGIN_AUTHENTICATED
            } else {
                CROSS_ORIGIN_ANONYMOUS
            };
            write_response(peer, "200 OK", "", &html(marker));
        }
        "/pagination-cross-next" => {
            let marker = if has_any_caller_credential(&headers) {
                CROSS_ORIGIN_AUTHENTICATED
            } else {
                CROSS_ORIGIN_ANONYMOUS
            };
            let page = html(&format!(
                "{marker}<script src=\"/pagination-cross-subresource\"></script>"
            ));
            write_response(peer, "200 OK", "", &page);
        }
        "/pagination-cross-subresource" => {
            write_response(
                peer,
                "200 OK",
                "",
                "window.paginationCrossSubresourceLoaded = true;",
            );
        }
        "/image" => write_response(peer, "200 OK", "", "image bytes"),
        "/script.js" => write_response(peer, "200 OK", "", "window.crossScriptLoaded = true;"),
        "/frame" => write_response(peer, "200 OK", "", &html("CROSS_FRAME")),
        "/xhr" => write_response(peer, "200 OK", "", "xhr"),
        _ => write_response(peer, "404 Not Found", "", "not found"),
    }
}

fn fixture() -> Fixture {
    let secondary_listener = TcpListener::bind("127.0.0.1:0").expect("bind secondary listener");
    let secondary_port = secondary_listener
        .local_addr()
        .expect("secondary listener address")
        .port();
    let secondary = format!("http://127.0.0.1:{secondary_port}");
    let secondary_state = Arc::new(OriginState::default());
    let secondary_accept_state = Arc::clone(&secondary_state);
    thread::spawn(move || {
        for stream in secondary_listener.incoming().flatten() {
            let state = Arc::clone(&secondary_accept_state);
            thread::spawn(move || serve_secondary(stream, state));
        }
    });

    // Bind every IPv4 loopback alias. This lets a redirect from 127.0.0.1 to 127.0.0.2 retain
    // the port while changing only the hostname component of the caller credential origin.
    let primary_listener = TcpListener::bind("0.0.0.0:0").expect("bind primary listener");
    let primary_port = primary_listener
        .local_addr()
        .expect("primary listener address")
        .port();
    let primary = format!("http://127.0.0.1:{primary_port}");
    let primary_host_alias = format!("http://127.0.0.2:{primary_port}");
    let primary_state = Arc::new(OriginState::default());
    let primary_accept_state = Arc::clone(&primary_state);
    let primary_secondary = secondary.clone();
    let primary_alias = primary_host_alias.clone();
    thread::spawn(move || {
        for stream in primary_listener.incoming().flatten() {
            let state = Arc::clone(&primary_accept_state);
            let secondary = primary_secondary.clone();
            let host_alias = primary_alias.clone();
            thread::spawn(move || serve_primary(stream, state, secondary, host_alias));
        }
    });

    Fixture {
        primary,
        primary_host_alias,
        secondary,
        primary_state,
        secondary_state,
    }
}

fn requests_at(state: &Arc<OriginState>, path: &str) -> Vec<RecordedRequest> {
    state
        .requests
        .lock()
        .expect("request-state lock")
        .iter()
        .filter(|request| request.path == path)
        .cloned()
        .collect()
}

fn assert_requests_have_credentials(requests: &[RecordedRequest], context: &str) {
    assert!(
        !requests.is_empty(),
        "{context} should receive at least one request"
    );
    assert!(
        requests
            .iter()
            .all(|request| has_all_caller_credentials(&request.headers)),
        "{context} must retain the initiating-origin caller credentials"
    );
}

fn assert_requests_have_browser_credentials(requests: &[RecordedRequest], context: &str) {
    assert!(
        !requests.is_empty(),
        "{context} should receive at least one request"
    );
    assert!(
        requests.iter().all(|request| {
            header_is(&request.headers, "authorization", AUTH)
                && header_is(&request.headers, "cookie", COOKIE)
                && header_is(&request.headers, "x-policy-secret", CUSTOM_SECRET)
        }),
        "{context} must retain same-origin browser caller credentials"
    );
}

fn assert_requests_lack_credentials(requests: &[RecordedRequest], context: &str) {
    assert!(
        !requests.is_empty(),
        "{context} should receive at least one request"
    );
    assert!(
        requests
            .iter()
            .all(|request| !has_any_caller_credential(&request.headers)),
        "{context} must never receive caller credentials"
    );
}

#[test]
fn cross_origin_redirects_strip_caller_credentials_by_port_and_host() {
    let fixture = fixture();
    let by_port = format!("{}/redirect-to-secondary", fixture.primary);
    let proof = scrape_with_credentials(&by_port, "rawHtml", true);
    assert_eq!(
        proof["response"]["final_url"],
        format!("{}/terminal", fixture.secondary)
    );
    assert!(proof["result"]["formats_produced"]["rawHtml"]
        .as_str()
        .expect("raw HTML")
        .contains(CROSS_ORIGIN_ANONYMOUS));
    assert_requests_have_credentials(
        &requests_at(&fixture.primary_state, "/redirect-to-secondary"),
        "the initiating origin",
    );
    assert_requests_lack_credentials(
        &requests_at(&fixture.secondary_state, "/terminal"),
        "the cross-port redirect target",
    );

    let by_host = format!("{}/redirect-to-host-alias", fixture.primary);
    let proof = scrape_with_credentials(&by_host, "rawHtml", true);
    assert_eq!(
        proof["response"]["final_url"],
        format!("{}/host-terminal", fixture.primary_host_alias)
    );
    assert_requests_lack_credentials(
        &requests_at(&fixture.primary_state, "/host-terminal"),
        "the same-port, cross-host redirect target",
    );
}

#[test]
fn same_origin_authenticated_direct_rendered_and_screenshot_outputs_remain_authenticated() {
    let fixture = fixture();
    let target = format!("{}/same-origin-auth", fixture.primary);
    let proof = scrape_browser_with_credentials(&target, "rawHtml,html,markdown,screenshot");

    for format in ["rawHtml", "html", "markdown"] {
        assert!(
            proof["result"]["formats_produced"][format]
                .as_str()
                .expect("text result format")
                .contains(SAME_ORIGIN_AUTHENTICATED),
            "same-origin {format} output must retain the authenticated resource"
        );
    }
    assert!(
        proof["result"]["formats_produced"]["screenshot"]
            .as_str()
            .is_some_and(|png| !png.is_empty()),
        "same-origin screenshot must be produced"
    );
    assert_requests_have_browser_credentials(
        &requests_at(&fixture.primary_state, "/same-origin-auth"),
        "same-origin direct, rendered, and screenshot requests",
    );
}

#[test]
fn browser_subresources_and_client_document_navigation_never_receive_caller_credentials() {
    let fixture = fixture();
    let subresources = format!("{}/cross-subresources", fixture.primary);
    let proof = scrape_browser_with_credentials(&subresources, "html");
    assert!(proof["result"]["formats_produced"]["html"]
        .as_str()
        .expect("rendered HTML")
        .contains(SAME_ORIGIN_AUTHENTICATED));

    // Rendering completes only after the tracked XHR settles, but give the frame loader a brief
    // scheduling window before sampling the listener state.
    thread::sleep(Duration::from_millis(100));
    for path in ["/image", "/script.js", "/frame", "/xhr"] {
        assert_requests_lack_credentials(
            &requests_at(&fixture.secondary_state, path),
            "a cross-origin browser subresource",
        );
    }

    let client_navigation = format!("{}/client-navigate-secondary", fixture.primary);
    let proof = scrape_browser_with_credentials(&client_navigation, "html");
    assert!(proof["result"]["formats_produced"]["html"]
        .as_str()
        .expect("client navigation rendered HTML")
        .contains(CROSS_ORIGIN_ANONYMOUS));
    assert_requests_lack_credentials(
        &requests_at(&fixture.secondary_state, "/terminal"),
        "a cross-origin browser document navigation",
    );
}

#[test]
fn rendered_formats_start_at_the_direct_terminal_resource_and_remain_anonymous_cross_origin() {
    let fixture = fixture();
    let target = format!("{}/redirect-to-secondary", fixture.primary);
    let proof = scrape_browser_with_credentials(&target, "rawHtml,html,markdown,screenshot");
    let terminal = format!("{}/terminal", fixture.secondary);
    assert_eq!(proof["response"]["final_url"], terminal);
    for format in ["rawHtml", "html", "markdown"] {
        let value = proof["result"]["formats_produced"][format]
            .as_str()
            .expect("terminal text format");
        assert!(
            value.contains(CROSS_ORIGIN_ANONYMOUS),
            "{format} must represent the anonymous direct terminal resource"
        );
        assert!(
            !value.contains(CROSS_ORIGIN_AUTHENTICATED),
            "{format} must not silently represent a credentialed cross-origin resource"
        );
    }
    assert!(
        proof["result"]["formats_produced"]["screenshot"]
            .as_str()
            .is_some_and(|png| !png.is_empty()),
        "terminal screenshot must be produced"
    );
    assert_eq!(
        requests_at(&fixture.primary_state, "/redirect-to-secondary").len(),
        1,
        "browser outputs must begin at the direct terminal URL, not re-navigate the initial URL"
    );
    assert_eq!(
        requests_at(&fixture.secondary_state, "/terminal").len(),
        3,
        "the direct response plus shared HTML/markdown render and screenshot must all load the terminal resource"
    );
    assert_requests_lack_credentials(
        &requests_at(&fixture.secondary_state, "/terminal"),
        "the terminal direct, rendered, and screenshot origin",
    );
}

#[test]
fn paginated_rendering_preserves_the_initiating_credential_origin() {
    let fixture = fixture();
    let cross_origin_start = format!("{}/pagination-cross-start", fixture.primary);
    let proof = scrape_paginated_browser_with_credentials(&cross_origin_start, "markdown,html");

    let markdown = proof["result"]["formats_produced"]["markdown"]
        .as_str()
        .expect("paginated markdown");
    assert!(
        markdown.contains(CROSS_ORIGIN_ANONYMOUS),
        "cross-origin paginated output must represent the anonymous next page"
    );
    assert!(
        !markdown.contains(CROSS_ORIGIN_AUTHENTICATED),
        "cross-origin paginated output must not render a credentialed next page"
    );
    assert_eq!(
        proof["result"]["crawled_urls"],
        serde_json::json!([
            cross_origin_start,
            format!("{}/pagination-cross-next", fixture.secondary),
        ]),
        "pagination must retain the discovered cross-origin next URL"
    );
    assert_requests_lack_credentials(
        &requests_at(&fixture.secondary_state, "/pagination-cross-next"),
        "the cross-origin paginated document",
    );
    assert_requests_lack_credentials(
        &requests_at(&fixture.secondary_state, "/pagination-cross-subresource"),
        "a cross-origin paginated subresource",
    );

    let same_origin_start = format!("{}/pagination-same-start", fixture.primary);
    let proof = scrape_paginated_browser_with_credentials(&same_origin_start, "markdown,html");
    let markdown = proof["result"]["formats_produced"]["markdown"]
        .as_str()
        .expect("same-origin paginated markdown");
    assert!(
        markdown.contains(SAME_ORIGIN_AUTHENTICATED),
        "same-origin paginated output must retain authenticated content"
    );
    assert_eq!(
        proof["result"]["crawled_urls"],
        serde_json::json!([
            same_origin_start,
            format!("{}/pagination-same-next", fixture.primary),
        ]),
        "pagination must retain the discovered same-origin next URL"
    );
    assert_requests_have_browser_credentials(
        &requests_at(&fixture.primary_state, "/pagination-same-next"),
        "the same-origin paginated document",
    );
    assert_requests_have_browser_credentials(
        &requests_at(&fixture.primary_state, "/pagination-same-subresource"),
        "a same-origin paginated subresource",
    );
}
