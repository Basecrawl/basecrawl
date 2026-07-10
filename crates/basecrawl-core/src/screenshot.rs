//! `screenshot` format production: a deterministic PNG captured with headless Chromium.
//!
//! The bytes are produced by [`basecrawl_render::screenshot`] and surfaced as a base64 PNG string
//! in `result.formats_produced.screenshot`. The screenshot is deliberately outside the
//! deterministic `result_hash` surface (see [`crate::canonical`]).

use basecrawl_render::{screenshot_until, RenderError, Screenshot, ScreenshotConfig};
use std::time::Instant;
use url::Url;

use crate::error::Error;

/// Capture a screenshot of `url` at the requested viewport, returning the decoded PNG plus its
/// base64 wire form. A capture failure is surfaced as a structured [`Error`] so the scrape fails
/// loudly rather than emitting a misleading screenshot value.
pub fn capture(url: &Url, config: ScreenshotConfig) -> Result<Screenshot, Error> {
    let deadline = Instant::now() + config.timeout;
    capture_until(url, config, deadline)
}

/// Capture while consuming the scrape-owned absolute deadline.
pub fn capture_until(
    url: &Url,
    config: ScreenshotConfig,
    deadline: Instant,
) -> Result<Screenshot, Error> {
    screenshot_until(url, &config, deadline).map_err(|error| match error {
        error if error.is_deadline_exhausted() => Error::Timeout(
            "scrape deadline exceeded during browser setup or screenshot".to_string(),
        ),
        RenderError::PacingDeadlineExceeded => {
            Error::Timeout("scrape deadline exceeded while waiting for crawl delay".to_string())
        }
        RenderError::ResourceBudgetExceeded => Error::ResourceBudgetExceeded,
        RenderError::DocumentPolicyDenied(detail) => Error::from_document_policy_denial(detail),
        error => Error::Render(error.to_string()),
    })
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
