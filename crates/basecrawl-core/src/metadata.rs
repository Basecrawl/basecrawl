//! Firecrawl-parity metadata extraction for the `metadata` format.
//!
//! The emitted metadata is a flat JSON object combining page-level fields the crawler derives
//! (`title` from `<title>`, `language` from `<html lang>`, the detected source `charset`, the
//! requested `sourceURL`, and the HTTP `statusCode`) with every `<meta name=...>` / `<meta
//! property=...>` tag surfaced under its own key. OpenGraph (`og:*`, carried on `property`) and
//! Twitter card (`twitter:*`, carried on `name`) tags therefore appear with their original keys
//! preserved. `<meta name="description">`, `<meta name="viewport">`, and `<meta name="robots">`
//! are surfaced the same way.
//!
//! Duplicate-key policy (list-on-duplicate): a meta name/property that appears once serializes as a
//! scalar string; a name/property that appears more than once serializes as a JSON array holding
//! every value in document order. This is deterministic and lossless.
//!
//! Key order is stable: the object is a `serde_json::Map` (BTreeMap-backed in this workspace, i.e.
//! `preserve_order` is not enabled), so keys serialize alphabetically and identically across runs.

use scraper::{Html, Selector};
use serde_json::{Map, Value};

/// Page-level context the crawler supplies for the derived metadata fields that are not present in
/// the HTML itself: the requested URL (`sourceURL`), the terminal HTTP status (`statusCode`), and
/// the response `Content-Type` header (the authoritative charset source, if it declares one).
#[derive(Debug, Clone, Copy)]
pub struct PageMeta<'a> {
    /// The source/requested URL, surfaced as Firecrawl-parity `sourceURL`.
    pub source_url: &'a str,
    /// The terminal HTTP status code, surfaced as Firecrawl-parity `statusCode`.
    pub status_code: Option<u16>,
    /// The response `Content-Type` header value, if any; its `charset` parameter (when present)
    /// takes precedence over an in-document `<meta charset>` declaration.
    pub content_type: Option<&'a str>,
}

/// Extract the `metadata` surface from an HTML document plus the crawler-supplied [`PageMeta`].
pub fn extract(html: &str, page: &PageMeta) -> Value {
    let document = Html::parse_document(html);
    let mut map: Map<String, Value> = Map::new();

    // Every `<meta name=...>` / `<meta property=...>` tag, keyed by its raw name/property so
    // `og:*`/`twitter:*` (and description/viewport/robots/keywords/...) are preserved verbatim.
    // Repeated keys accumulate into an ordered list (list-on-duplicate).
    if let Ok(selector) = Selector::parse("meta") {
        for el in document.select(&selector) {
            let element = el.value();
            let Some(key) = element.attr("name").or_else(|| element.attr("property")) else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let Some(content) = element.attr("content") else {
                continue;
            };
            insert_meta(&mut map, key, content);
        }
    }

    // Derived, page-level fields overlay any same-named meta tag: the `<title>` element is
    // authoritative for `title`, `<html lang>`/http-equiv for `language`, and header/meta for
    // `charset`. `sourceURL`/`statusCode` come from the crawler, not the document.
    if let Some(title) = first_text(&document, "title") {
        map.insert("title".to_string(), Value::String(title));
    }
    if let Some(language) = language(&document) {
        map.insert("language".to_string(), Value::String(language));
    }
    if let Some(charset) = charset(&document, page.content_type) {
        map.insert("charset".to_string(), Value::String(charset));
    }
    map.insert(
        "sourceURL".to_string(),
        Value::String(page.source_url.to_string()),
    );
    if let Some(status) = page.status_code {
        map.insert("statusCode".to_string(), Value::Number(status.into()));
    }

    Value::Object(map)
}

/// Record a meta value under `key`, accumulating repeats into an ordered list. The first
/// occurrence is stored as a scalar string; a second turns it into a two-element array; each
/// subsequent occurrence is appended, preserving document order.
fn insert_meta(map: &mut Map<String, Value>, key: &str, content: &str) {
    match map.get_mut(key) {
        None => {
            map.insert(key.to_string(), Value::String(content.to_string()));
        }
        Some(Value::Array(items)) => items.push(Value::String(content.to_string())),
        Some(existing) => {
            let previous = existing.take();
            *existing = Value::Array(vec![previous, Value::String(content.to_string())]);
        }
    }
}

/// The trimmed, whitespace-collapsed text content of the first element matching `selector`, or
/// `None` when it is absent or empty.
fn first_text(document: &Html, selector: &str) -> Option<String> {
    let selector = Selector::parse(selector).ok()?;
    let element = document.select(&selector).next()?;
    let text: String = element.text().collect::<String>();
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

/// The declared page language: `<html lang>` first, then a `content-language` http-equiv meta,
/// falling back to a `<meta name="language">` if present. Returns `None` when none is declared.
fn language(document: &Html) -> Option<String> {
    if let Ok(selector) = Selector::parse("html[lang]") {
        if let Some(lang) = document
            .select(&selector)
            .next()
            .and_then(|el| el.value().attr("lang"))
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            return Some(lang.to_string());
        }
    }
    if let Some(lang) = meta_http_equiv(document, "content-language") {
        let lang = lang.trim();
        if !lang.is_empty() {
            return Some(lang.to_string());
        }
    }
    meta_named(document, "language")
}

/// The detected source charset, normalized to lowercase: the HTTP `Content-Type` header charset
/// takes precedence (per the encoding-sniffing order), then `<meta charset>`, then a
/// `Content-Type` http-equiv meta. Returns `None` when nothing declares a charset.
fn charset(document: &Html, content_type: Option<&str>) -> Option<String> {
    if let Some(charset) = content_type.and_then(charset_from_content_type) {
        return Some(charset);
    }
    if let Ok(selector) = Selector::parse("meta[charset]") {
        if let Some(charset) = document
            .select(&selector)
            .next()
            .and_then(|el| el.value().attr("charset"))
            .map(str::trim)
            .filter(|c| !c.is_empty())
        {
            return Some(charset.to_ascii_lowercase());
        }
    }
    meta_http_equiv(document, "content-type").and_then(|ct| charset_from_content_type(&ct))
}

/// The `content` of the first `<meta http-equiv="{equiv}">` (case-insensitive on the equiv name).
fn meta_http_equiv(document: &Html, equiv: &str) -> Option<String> {
    let selector = Selector::parse("meta[http-equiv][content]").ok()?;
    document
        .select(&selector)
        .find(|el| {
            el.value()
                .attr("http-equiv")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case(equiv))
        })
        .and_then(|el| el.value().attr("content"))
        .map(str::to_string)
}

/// The `content` of the first `<meta name="{name}">` (case-insensitive on the name).
fn meta_named(document: &Html, name: &str) -> Option<String> {
    let selector = Selector::parse("meta[name][content]").ok()?;
    document
        .select(&selector)
        .find(|el| {
            el.value()
                .attr("name")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case(name))
        })
        .and_then(|el| el.value().attr("content"))
        .map(str::to_string)
}

/// Parse the `charset` parameter out of a `Content-Type` header value (e.g.
/// `text/html; charset=utf-8` → `utf-8`), normalized to lowercase. Returns `None` when the header
/// declares no charset.
pub fn charset_from_content_type(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("charset") {
            let value = value.trim().trim_matches('"').trim();
            if !value.is_empty() {
                return Some(value.to_ascii_lowercase());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> PageMeta<'static> {
        PageMeta {
            source_url: "https://example.com/",
            status_code: Some(200),
            content_type: None,
        }
    }

    fn extract_html(html: &str) -> Value {
        extract(html, &ctx())
    }

    #[test]
    fn extracts_title() {
        let v = extract_html("<html><head><title>Quotes to Scrape</title></head></html>");
        assert_eq!(v["title"], "Quotes to Scrape");
    }

    #[test]
    fn extracts_description() {
        let v = extract_html("<meta name=\"description\" content=\"A quote site\">");
        assert_eq!(v["description"], "A quote site");
    }

    #[test]
    fn title_present_without_description_is_ok() {
        let v = extract_html("<title>Only Title</title>");
        assert_eq!(v["title"], "Only Title");
        assert!(v.get("description").is_none());
    }

    #[test]
    fn captures_og_and_twitter_keys_preserved() {
        let html = "<head>\
            <meta property=\"og:title\" content=\"OG Title\">\
            <meta property=\"og:image\" content=\"https://example.com/i.png\">\
            <meta name=\"twitter:card\" content=\"summary\">\
            <meta name=\"twitter:title\" content=\"TW Title\">\
            </head>";
        let v = extract_html(html);
        assert_eq!(v["og:title"], "OG Title");
        assert_eq!(v["og:image"], "https://example.com/i.png");
        assert_eq!(v["twitter:card"], "summary");
        assert_eq!(v["twitter:title"], "TW Title");
    }

    #[test]
    fn includes_source_url_and_status_code() {
        let v = extract_html("<title>t</title>");
        assert_eq!(v["sourceURL"], "https://example.com/");
        assert_eq!(v["statusCode"], serde_json::json!(200));
        assert!(v["statusCode"].is_number());
    }

    #[test]
    fn reports_language_from_html_lang() {
        let v = extract_html("<html lang=\"en\"><head><title>t</title></head></html>");
        assert_eq!(v["language"], "en");
    }

    #[test]
    fn language_absent_when_not_declared() {
        let v = extract_html("<html><head><title>t</title></head></html>");
        assert!(v.get("language").is_none());
    }

    #[test]
    fn reports_charset_from_header() {
        let page = PageMeta {
            source_url: "https://example.com/",
            status_code: Some(200),
            content_type: Some("text/html; charset=iso-8859-1"),
        };
        let v = extract("<title>t</title>", &page);
        assert_eq!(v["charset"], "iso-8859-1");
    }

    #[test]
    fn reports_charset_from_meta_when_no_header() {
        let v = extract_html("<head><meta charset=\"UTF-8\"><title>t</title></head>");
        assert_eq!(v["charset"], "utf-8");
    }

    #[test]
    fn header_charset_overrides_meta() {
        let page = PageMeta {
            source_url: "https://example.com/",
            status_code: Some(200),
            content_type: Some("text/html; charset=utf-8"),
        };
        let v = extract("<head><meta charset=\"iso-8859-1\"></head>", &page);
        assert_eq!(v["charset"], "utf-8");
    }

    #[test]
    fn reports_charset_from_http_equiv() {
        let v = extract_html(
            "<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=Shift_JIS\"></head>",
        );
        assert_eq!(v["charset"], "shift_jis");
    }

    #[test]
    fn charset_absent_when_not_declared() {
        let v = extract_html("<head><title>t</title></head>");
        assert!(v.get("charset").is_none());
    }

    #[test]
    fn captures_viewport_and_robots() {
        let html = "<head>\
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
            <meta name=\"robots\" content=\"noindex, nofollow\">\
            </head>";
        let v = extract_html(html);
        assert_eq!(v["viewport"], "width=device-width, initial-scale=1");
        assert_eq!(v["robots"], "noindex, nofollow");
    }

    #[test]
    fn single_meta_is_scalar_not_list() {
        let v = extract_html("<meta name=\"keywords\" content=\"a,b\">");
        assert_eq!(v["keywords"], "a,b");
        assert!(v["keywords"].is_string());
    }

    #[test]
    fn duplicate_meta_names_become_ordered_list() {
        let html = "<head>\
            <meta name=\"keywords\" content=\"first\">\
            <meta name=\"keywords\" content=\"second\">\
            <meta name=\"keywords\" content=\"third\">\
            </head>";
        let v = extract_html(html);
        assert_eq!(
            v["keywords"],
            serde_json::json!(["first", "second", "third"])
        );
    }

    #[test]
    fn meta_without_name_or_property_is_ignored() {
        // quotes.toscrape.com carries <meta itemprop="keywords" content="..."> with no name or
        // property attribute; such tags must not pollute the metadata object.
        let v = extract_html("<meta itemprop=\"keywords\" content=\"change,thinking\">");
        assert!(v.get("keywords").is_none());
    }

    #[test]
    fn charset_from_content_type_parses_param() {
        assert_eq!(
            charset_from_content_type("text/html; charset=utf-8"),
            Some("utf-8".to_string())
        );
    }

    #[test]
    fn charset_from_content_type_is_case_insensitive_and_lowercased() {
        assert_eq!(
            charset_from_content_type("text/html; Charset=UTF-8"),
            Some("utf-8".to_string())
        );
    }

    #[test]
    fn charset_from_content_type_none_when_absent() {
        assert_eq!(charset_from_content_type("application/json"), None);
    }

    #[test]
    fn empty_document_still_yields_source_and_status() {
        let v = extract_html("");
        assert!(v.is_object());
        assert_eq!(v["sourceURL"], "https://example.com/");
        assert_eq!(v["statusCode"], serde_json::json!(200));
    }

    #[test]
    fn deterministic_across_runs() {
        let html = "<html lang=\"en\"><head>\
            <meta charset=\"utf-8\">\
            <meta name=\"description\" content=\"d\">\
            <meta property=\"og:title\" content=\"o\">\
            <meta name=\"keywords\" content=\"a\">\
            <meta name=\"keywords\" content=\"b\">\
            <title>t</title></head></html>";
        let first = serde_json::to_string(&extract_html(html)).unwrap();
        let again = serde_json::to_string(&extract_html(html)).unwrap();
        assert_eq!(first, again);
    }
}
