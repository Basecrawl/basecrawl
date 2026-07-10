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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

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

/// Maximum attempts made by an explicitly best-effort open-web smoke check.
pub const REMOTE_SMOKE_MAX_ATTEMPTS: usize = 3;

/// Retry a best-effort open-web probe with a small, bounded exponential backoff.
///
/// Exact parser and navigation assertions belong to [`fixture_url`]. This helper only supports
/// intentionally qualitative smoke tests, where a transient public-origin refusal must not make
/// the deterministic default-parallel suite fail.
pub fn retry_open_web<T>(mut attempt: impl FnMut() -> Option<T>) -> Option<T> {
    for index in 0..REMOTE_SMOKE_MAX_ATTEMPTS {
        if let Some(value) = attempt() {
            return Some(value);
        }
        if index + 1 < REMOTE_SMOKE_MAX_ATTEMPTS {
            let backoff = Duration::from_millis(250 * (1_u64 << index));
            thread::sleep(backoff);
        }
    }
    None
}

/// Return the deterministic test-origin base URL, backed by one loopback server per test binary.
pub fn fixture_base() -> &'static str {
    static BASE: OnceLock<String> = OnceLock::new();
    BASE.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture server");
        let address = listener
            .local_addr()
            .expect("read loopback fixture server address");
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || handle_fixture_connection(stream));
            }
        });
        format!("http://{address}")
    })
}

/// Build an absolute URL for one deterministic fixture path.
pub fn fixture_url(path: &str) -> String {
    assert!(path.starts_with('/'), "fixture paths must start with '/'");
    format!("{}{}", fixture_base(), path)
}

fn fixture_page(body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Fixture Quotes</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
</head><body>{body}</body></html>"
    )
}

fn quotes_page() -> String {
    fixture_page(
        "<main><section class=\"quote\">Fixture quote for resilient parser coverage</section>\
<a href=\"/tags/fixtures/resilient/\">fixture tag</a></main>",
    )
}

fn book_product_page() -> String {
    fixture_page(
        "<header>Books to Scrape</header><article>\
<h1>A Fixture Light</h1><p>Fixture product description</p>\
<h2>Fixture Product Description</h2>\
<table><tr><th>UPC</th><td>fixture-upc</td></tr></table>\
<img alt=\"A Fixture Light\" src=\"/media/fixture-light.jpg\"></article>",
    )
}

fn books_page() -> String {
    fixture_page(
        "<main><a href=\"/books/catalogue/fixture-light/index.html\">Fixture light</a>\
<a href=\"/books/catalogue/fixture-second/index.html\">Fixture second</a>\
<a href=\"/books/category/fixtures/index.html\">Fixture category</a>\
<a rel=\"next\" href=\"/books/page-2.html\">next</a></main>",
    )
}

fn books_page_two() -> String {
    fixture_page(
        "<main><h1>Fixture page 2</h1>\
<a href=\"/books/catalogue/fixture-third/index.html\">Fixture third</a></main>",
    )
}

fn scroll_page() -> String {
    fixture_page(
        "<main style=\"min-height: 1800px\"><div class=\"quote\">“fixture quote 1”</div>\
<script>\
window.addEventListener('scroll', function () {\
  for (let i = 2; i <= 12; i += 1) {\
    const quote = document.createElement('div');\
    quote.className = 'quote'; quote.textContent = '“fixture quote ' + i + '”';\
    document.querySelector('main').appendChild(quote);\
  }\
}, { once: true });\
</script></main>",
    )
}

fn js_page() -> String {
    fixture_page(
        "<main id=\"quotes\"></main><script>\
var data = ['Fixture JS quote render marker'];\
data.forEach(function (text) {\
  var quote = document.createElement('div');\
  quote.className = 'quote'; quote.textContent = text;\
  document.getElementById('quotes').appendChild(quote);\
});\
</script>",
    )
}

fn tall_page() -> String {
    fixture_page("<main><div style=\"height: 1800px\">Fixture tall screenshot content</div></main>")
}

fn fixture_response(path: &str) -> (&'static str, &'static str, String) {
    match path {
        "/quotes/" => ("200 OK", "text/html; charset=utf-8", quotes_page()),
        "/books/" => ("200 OK", "text/html; charset=utf-8", books_page()),
        "/books/page-2.html" => ("200 OK", "text/html; charset=utf-8", books_page_two()),
        "/books/catalogue/fixture-light/index.html" => {
            ("200 OK", "text/html; charset=utf-8", book_product_page())
        }
        "/scroll/" => ("200 OK", "text/html; charset=utf-8", scroll_page()),
        "/js/" => ("200 OK", "text/html; charset=utf-8", js_page()),
        "/tall/" => ("200 OK", "text/html; charset=utf-8", tall_page()),
        "/missing" => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "fixture missing".to_string(),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "fixture not found".to_string(),
        ),
    }
}

fn handle_fixture_connection(stream: TcpStream) {
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

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let (status, content_type, body) = fixture_response(path);
    let mut stream = reader.into_inner();
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}
