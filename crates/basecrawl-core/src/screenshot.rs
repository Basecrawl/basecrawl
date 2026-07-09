//! `screenshot` format production: a deterministic PNG captured with headless Chromium.
//!
//! The bytes are produced by [`basecrawl_render::screenshot`] and surfaced as a base64 PNG string
//! in `result.formats_produced.screenshot`. The screenshot is deliberately outside the
//! deterministic `result_hash` surface (see [`crate::canonical`]).

use std::time::Duration;

use basecrawl_render::{screenshot, Screenshot, ScreenshotConfig};
use url::Url;

use crate::error::Error;

/// Capture a screenshot of `url` at the requested viewport, returning the decoded PNG plus its
/// base64 wire form. A capture failure is surfaced as a structured [`Error`] so the scrape fails
/// loudly rather than emitting a misleading screenshot value.
pub fn capture(
    url: &Url,
    user_agent: &str,
    timeout: Duration,
    viewport: (u32, u32),
    full_page: bool,
) -> Result<Screenshot, Error> {
    let config = ScreenshotConfig {
        timeout,
        user_agent: user_agent.to_string(),
        width: viewport.0,
        height: viewport.1,
        full_page,
    };
    screenshot(url, &config).map_err(|e| Error::Render(e.to_string()))
}

/// Parse a `WIDTHxHEIGHT` viewport spec (e.g. `1280x800`) into `(width, height)`.
///
/// Both dimensions must be positive integers. The separator is a case-insensitive `x`. A malformed
/// or zero-valued spec yields [`Error::InvalidViewport`] and is validated before any fetch.
pub fn parse_viewport(spec: &str) -> Result<(u32, u32), Error> {
    let err = || Error::InvalidViewport(spec.to_string());
    let lower = spec.trim().to_ascii_lowercase();
    let (w, h) = lower.split_once('x').ok_or_else(err)?;
    let width: u32 = w.trim().parse().map_err(|_| err())?;
    let height: u32 = h.trim().parse().map_err(|_| err())?;
    if width == 0 || height == 0 {
        return Err(err());
    }
    Ok((width, height))
}

#[cfg(test)]
mod tests {
    use super::parse_viewport;
    use crate::error::Error;

    #[test]
    fn parses_standard_spec() {
        assert_eq!(parse_viewport("1280x800").unwrap(), (1280, 800));
    }

    #[test]
    fn accepts_uppercase_separator() {
        assert_eq!(parse_viewport("640X480").unwrap(), (640, 480));
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(matches!(
            parse_viewport("1280"),
            Err(Error::InvalidViewport(_))
        ));
    }

    #[test]
    fn rejects_zero_dimension() {
        assert!(matches!(
            parse_viewport("0x800"),
            Err(Error::InvalidViewport(_))
        ));
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(matches!(
            parse_viewport("wide x tall"),
            Err(Error::InvalidViewport(_))
        ));
    }
}
