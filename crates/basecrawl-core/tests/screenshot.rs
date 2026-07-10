//! End-to-end deterministic `screenshot` format assertions (VAL-CRAWL-056..060) exercised through
//! the shipped CLI against a stable open-web target and a deterministic loopback tall-page fixture.
//!
//! The screenshot is surfaced as a base64 PNG in `result.formats_produced.screenshot`; these tests
//! decode it with a real PNG decoder to assert validity and dimensions. The screenshot must be
//! byte-deterministic across identical runs and must stay outside the deterministic `result_hash`
//! quorum surface.

mod common;

use base64::Engine;
use serde_json::Value;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_basecrawl");
const EXAMPLE: &str = "https://example.com/";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn basecrawl binary")
}

fn scrape_json(args: &[&str]) -> Value {
    let out = run(args);
    assert!(
        out.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not a single strict-JSON object: {e}\n{stdout}"))
}

/// The base64 screenshot string from a proof.
fn screenshot_b64(v: &Value) -> String {
    v["result"]["formats_produced"]["screenshot"]
        .as_str()
        .unwrap_or_else(|| panic!("screenshot missing/non-string:\n{v}"))
        .to_string()
}

/// Decode a base64 PNG and return `(width, height)` using a real PNG decoder (validates the
/// signature, IHDR, and IDAT stream).
fn png_dimensions(b64: &str) -> (u32, u32) {
    let bytes = base64::prelude::BASE64_STANDARD
        .decode(b64)
        .expect("screenshot is valid base64");
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "not a PNG signature");
    let decoder = png::Decoder::new(std::io::Cursor::new(&bytes));
    let mut reader = decoder.read_info().expect("PNG header decodes");
    let (width, height) = {
        let info = reader.info();
        (info.width, info.height)
    };
    let mut buf = vec![0u8; reader.output_buffer_size()];
    reader.next_frame(&mut buf).expect("PNG image data decodes");
    (width, height)
}

// VAL-CRAWL-056: `--formats screenshot` yields a base64 PNG that decodes to a valid image with
// non-zero dimensions.
#[test]
fn screenshot_is_decodable_png_with_nonzero_dimensions() {
    let v = scrape_json(&[EXAMPLE, "--formats", "screenshot"]);
    let (w, h) = png_dimensions(&screenshot_b64(&v));
    assert!(w > 0 && h > 0, "expected non-zero dimensions, got {w}x{h}");
}

// VAL-CRAWL-057: two screenshots of example.com at the same viewport are byte-identical (no
// embedded timestamps / nondeterministic rendering).
#[test]
fn screenshot_is_deterministic_across_identical_runs() {
    let a = screenshot_b64(&scrape_json(&[
        EXAMPLE,
        "--formats",
        "screenshot",
        "--viewport",
        "1280x800",
    ]));
    let b = screenshot_b64(&scrape_json(&[
        EXAMPLE,
        "--formats",
        "screenshot",
        "--viewport",
        "1280x800",
    ]));
    assert_eq!(
        a, b,
        "identical runs must produce byte-identical screenshots"
    );
}

// VAL-CRAWL-058: `--viewport 1280x800` yields an image whose width matches 1280 (DPR fixed at 1).
#[test]
fn requested_viewport_width_is_honored() {
    let v = scrape_json(&[EXAMPLE, "--formats", "screenshot", "--viewport", "1280x800"]);
    let (w, _h) = png_dimensions(&screenshot_b64(&v));
    assert_eq!(
        w, 1280,
        "image width must match the requested viewport width"
    );
}

// VAL-CRAWL-059: `--screenshot-full-page` on a tall page yields an image taller than the viewport.
#[test]
fn full_page_capture_exceeds_viewport_height() {
    let viewport_height = 800;
    let tall = common::fixture_url("/tall/");
    let v = scrape_json(&[
        &tall,
        "--formats",
        "screenshot",
        "--viewport",
        "1280x800",
        "--screenshot-full-page",
    ]);
    let (_w, h) = png_dimensions(&screenshot_b64(&v));
    assert!(
        h > viewport_height,
        "full-page image height {h} must exceed the viewport height {viewport_height}"
    );
}

// VAL-CRAWL-060: changing only the screenshot (a viewport tweak) does NOT change result_hash,
// confirming the screenshot is outside the deterministic quorum surface.
#[test]
fn result_hash_is_unaffected_by_screenshot_viewport() {
    let big = scrape_json(&[
        EXAMPLE,
        "--formats",
        "markdown,screenshot",
        "--viewport",
        "1280x800",
    ]);
    let small = scrape_json(&[
        EXAMPLE,
        "--formats",
        "markdown,screenshot",
        "--viewport",
        "800x600",
    ]);

    // The viewport tweak must actually change the screenshot bytes...
    assert_ne!(
        screenshot_b64(&big),
        screenshot_b64(&small),
        "viewport tweak should change the screenshot pixels"
    );

    // ...while leaving the deterministic result_hash identical.
    let h_big = big["result"]["result_hash"]
        .as_str()
        .expect("result_hash present");
    let h_small = small["result"]["result_hash"]
        .as_str()
        .expect("result_hash present");
    assert_eq!(
        h_big, h_small,
        "result_hash must exclude screenshot bytes (deterministic quorum surface)"
    );
}
