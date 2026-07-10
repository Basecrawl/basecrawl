//! Shared binding adapter and C ABI for the canonical `basecrawl` ScrapeProof.
//!
//! Language SDKs pass their options as JSON into this crate. This is deliberately the only
//! language-specific translation layer: URL validation, option defaults, crawling, and canonical
//! JSON serialization remain authoritative in `basecrawl-core`.

use basecrawl_core::{format, scrape, Action, RobotsPolicy, ScrapeOptions};
use serde::Deserialize;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::str::FromStr;

const VERSION: &[u8] = b"0.1.0\0";

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Language-neutral options accepted by every binding.
///
/// Both camelCase and Python's snake_case spellings are accepted where they differ. Omitting a
/// member preserves the corresponding core default.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BindingOptions {
    formats: Option<Vec<String>>,
    #[serde(alias = "task_id")]
    task_id: Option<String>,
    nonce: Option<String>,
    #[serde(alias = "timeout_secs")]
    timeout_secs: Option<u64>,
    headers: Option<Vec<(String, String)>>,
    insecure: Option<bool>,
    #[serde(alias = "max_body_bytes")]
    max_body_bytes: Option<usize>,
    #[serde(alias = "crawl_delay_ms")]
    crawl_delay_ms: Option<u64>,
    #[serde(alias = "max_render_subresources")]
    max_render_subresources: Option<usize>,
    #[serde(alias = "max_render_bytes")]
    max_render_bytes: Option<u64>,
    viewport: Option<[u32; 2]>,
    #[serde(alias = "screenshot_full_page")]
    screenshot_full_page: Option<bool>,
    #[serde(alias = "render_enabled")]
    render_enabled: Option<bool>,
    #[serde(alias = "wait_for")]
    wait_for: Option<String>,
    #[serde(alias = "render_timeout_secs")]
    render_timeout_secs: Option<u64>,
    actions: Option<Vec<Action>>,
    #[serde(alias = "follow_pagination")]
    follow_pagination: Option<bool>,
    #[serde(alias = "max_pages")]
    max_pages: Option<usize>,
    #[serde(alias = "robots_policy")]
    robots_policy: Option<String>,
}

/// Error returned to bindings as the same structured JSON shape as core errors.
#[derive(Debug)]
pub struct BindingError {
    json: String,
}

impl BindingError {
    fn invalid_options(message: impl Into<String>) -> Self {
        Self {
            json: json!({
                "error": {
                    "kind": "invalid_options",
                    "message": message.into(),
                }
            })
            .to_string(),
        }
    }

    /// Structured error JSON intended for language-native exceptions or C error retrieval.
    pub fn to_json_string(&self) -> &str {
        &self.json
    }
}

impl From<basecrawl_core::Error> for BindingError {
    fn from(error: basecrawl_core::Error) -> Self {
        Self {
            json: error.to_json_string(),
        }
    }
}

/// Scrape `url` using options encoded as a JSON object and return the core's untouched canonical
/// JSON wire payload.
pub fn scrape_json(url: &str, options_json: Option<&str>) -> Result<String, BindingError> {
    let options = parse_options(options_json)?;
    let proof = scrape(url, &options).map_err(BindingError::from)?;
    Ok(proof.to_canonical_json())
}

fn parse_options(options_json: Option<&str>) -> Result<ScrapeOptions, BindingError> {
    let binding_options = match options_json {
        None | Some("") => BindingOptions::default(),
        Some(raw) => {
            let value: Value = serde_json::from_str(raw).map_err(|error| {
                BindingError::invalid_options(format!("options must be a JSON object: {error}"))
            })?;
            if value.is_null() {
                BindingOptions::default()
            } else {
                serde_json::from_value(value).map_err(|error| {
                    BindingError::invalid_options(format!("invalid scrape options: {error}"))
                })?
            }
        }
    };

    let mut options = ScrapeOptions::default();
    if let Some(formats) = binding_options.formats {
        options.formats = format::parse_list(&formats).map_err(BindingError::from)?;
    }
    if let Some(task_id) = binding_options.task_id {
        options.task_id = Some(task_id);
    }
    if let Some(nonce) = binding_options.nonce {
        options.nonce = Some(nonce);
    }
    if let Some(timeout_secs) = binding_options.timeout_secs {
        options.timeout_secs = timeout_secs;
    }
    if let Some(headers) = binding_options.headers {
        options.headers = headers;
    }
    if let Some(insecure) = binding_options.insecure {
        options.insecure = insecure;
    }
    if let Some(max_body_bytes) = binding_options.max_body_bytes {
        options.max_body_bytes = max_body_bytes;
    }
    if let Some(crawl_delay_ms) = binding_options.crawl_delay_ms {
        options.crawl_delay_ms = crawl_delay_ms;
    }
    if let Some(max_render_subresources) = binding_options.max_render_subresources {
        options.max_render_subresources = max_render_subresources;
    }
    if let Some(max_render_bytes) = binding_options.max_render_bytes {
        options.max_render_bytes = max_render_bytes;
    }
    if let Some(viewport) = binding_options.viewport {
        options.viewport = (viewport[0], viewport[1]);
    }
    if let Some(screenshot_full_page) = binding_options.screenshot_full_page {
        options.screenshot_full_page = screenshot_full_page;
    }
    if let Some(render_enabled) = binding_options.render_enabled {
        options.render_enabled = render_enabled;
    }
    if let Some(wait_for) = binding_options.wait_for {
        options.wait_for = Some(wait_for);
    }
    if let Some(render_timeout_secs) = binding_options.render_timeout_secs {
        options.render_timeout_secs = render_timeout_secs;
    }
    if let Some(actions) = binding_options.actions {
        options.actions = actions;
    }
    if let Some(follow_pagination) = binding_options.follow_pagination {
        options.follow_pagination = follow_pagination;
    }
    if let Some(max_pages) = binding_options.max_pages {
        options.max_pages = max_pages;
    }
    if let Some(robots_policy) = binding_options.robots_policy {
        options.robots_policy = RobotsPolicy::from_str(&robots_policy).map_err(|error| {
            BindingError::invalid_options(format!("invalid robots_policy: {error}"))
        })?;
    }

    Ok(options)
}

/// Return the SDK version shared by the CLI and every binding.
#[no_mangle]
pub extern "C" fn basecrawl_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// Scrape through the C ABI.
///
/// `url` and `options_json` must be valid UTF-8 NUL-terminated strings. Pass `NULL` for
/// `options_json` to use core defaults. On success the returned canonical JSON string must be
/// released with [`basecrawl_free_string`]. On failure this returns `NULL`; retrieve a structured
/// JSON error with [`basecrawl_last_error_json`].
///
/// # Safety
///
/// When non-null, `url` and `options_json` must each point to a readable, NUL-terminated C string
/// for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn basecrawl_scrape_json(
    url: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let url = c_string_arg(url, "url")?;
        let options = if options_json.is_null() {
            None
        } else {
            Some(c_string_arg(options_json, "options_json")?)
        };
        scrape_json(&url, options.as_deref())
    }));

    match result {
        Ok(Ok(json)) => {
            clear_last_error();
            CString::new(json)
                .expect("canonical ScrapeProof JSON never contains NUL")
                .into_raw()
        }
        Ok(Err(error)) => {
            set_last_error(error.to_json_string());
            ptr::null_mut()
        }
        Err(_) => {
            set_last_error(
                &json!({
                    "error": {
                        "kind": "internal_error",
                        "message": "basecrawl binding panicked",
                    }
                })
                .to_string(),
            );
            ptr::null_mut()
        }
    }
}

/// Return a thread-local structured error string after a failed C ABI call.
///
/// The returned pointer remains valid until the next `basecrawl_scrape_json` call on the same
/// thread and must not be freed by callers.
#[no_mangle]
pub extern "C" fn basecrawl_last_error_json() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(ptr::null(), |error| error.as_ptr())
    })
}

/// Free a successful result returned by [`basecrawl_scrape_json`].
///
/// # Safety
///
/// `value` must either be null or be a pointer returned by `basecrawl_scrape_json` that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn basecrawl_free_string(value: *mut c_char) {
    if !value.is_null() {
        unsafe {
            drop(CString::from_raw(value));
        }
    }
}

unsafe fn c_string_arg(value: *const c_char, name: &str) -> Result<String, BindingError> {
    if value.is_null() {
        return Err(BindingError::invalid_options(format!(
            "{name} must not be NULL"
        )));
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| BindingError::invalid_options(format!("{name} must be valid UTF-8")))
}

fn set_last_error(error: &str) {
    let error = CString::new(error).expect("structured error JSON never contains NUL");
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(error));
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default_to_core_defaults() {
        let options = parse_options(None).unwrap();
        assert_eq!(
            options
                .formats
                .iter()
                .map(|format| format.as_str())
                .collect::<Vec<_>>(),
            ["markdown", "metadata"]
        );
    }

    #[test]
    fn options_accept_python_and_javascript_spellings() {
        let python = parse_options(Some(r#"{"render_enabled":false,"task_id":"task"}"#)).unwrap();
        let javascript = parse_options(Some(r#"{"renderEnabled":false,"taskId":"task"}"#)).unwrap();

        assert!(!python.render_enabled);
        assert!(!javascript.render_enabled);
        assert_eq!(python.task_id, javascript.task_id);
    }

    #[test]
    fn unknown_format_returns_core_structured_error() {
        let error = parse_options(Some(r#"{"formats":["bogus"]}"#)).unwrap_err();
        let error: Value = serde_json::from_str(error.to_json_string()).unwrap();
        assert_eq!(error["error"]["kind"], "invalid_format");
    }

    #[test]
    fn ffi_rejects_duplicate_case_insensitive_header_names_before_transport() {
        for options in [
            r#"{"headers":[["X-Repeat","one"],["X-Repeat","two"]]}"#,
            r#"{"headers":[["X-Case","one"],["x-case","two"]]}"#,
        ] {
            let error = scrape_json("http://127.0.0.1:1/", Some(options))
                .expect_err("ambiguous binding headers must fail before connecting");
            let error: Value = serde_json::from_str(error.to_json_string()).unwrap();
            assert_eq!(error["error"]["kind"], "invalid_header");
        }
    }
}
