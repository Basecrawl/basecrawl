//! Response `Content-Type` classification for output-format decisions.
//!
//! The response header is authoritative. URL paths and filename extensions are deliberately never
//! consulted, because an endpoint such as `/payload.html` can legitimately serve JSON and an
//! extension-less endpoint can serve HTML.

/// The representation safe to produce from a fetched response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// An HTML document that may be rendered or parsed for derived formats.
    Html,
    /// Text that is surfaced byte-for-byte as UTF-8 text, without HTML parsing.
    Text,
    /// Non-text data that must not be rendered, parsed, or lossy-converted to text.
    Binary,
}

/// Classify a response from its `Content-Type` header.
///
/// A missing header retains the crawler's historical HTML-compatible behavior. When a header is
/// present, its media type alone controls classification, independent of the URL path.
pub fn classify(content_type: Option<&str>) -> ContentKind {
    let Some(content_type) = content_type else {
        return ContentKind::Html;
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    if matches!(media_type.as_str(), "text/html" | "application/xhtml+xml") {
        return ContentKind::Html;
    }

    if media_type.starts_with("text/")
        || media_type == "application/json"
        || media_type.ends_with("+json")
        || media_type == "application/xml"
        || media_type.ends_with("+xml")
        || matches!(
            media_type.as_str(),
            "application/javascript"
                | "application/ecmascript"
                | "application/sql"
                | "application/graphql"
        )
    {
        ContentKind::Text
    } else {
        ContentKind::Binary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_content_type_overrides_filename_extension() {
        assert_eq!(
            classify(Some("application/json; charset=utf-8")),
            ContentKind::Text
        );
        assert_eq!(classify(Some("text/html")), ContentKind::Html);
    }

    #[test]
    fn images_are_binary() {
        assert_eq!(classify(Some("image/png")), ContentKind::Binary);
    }

    #[test]
    fn missing_type_remains_html_compatible() {
        assert_eq!(classify(None), ContentKind::Html);
    }
}
