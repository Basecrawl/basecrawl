//! Declared-charset detection and transcoding for textual response bodies.
//!
//! HTTP `Content-Type` takes precedence over an HTML `<meta charset>` declaration. The selected
//! source encoding is decoded through `encoding_rs`, so every text surface passed to the HTML,
//! markdown, links, and metadata producers is valid UTF-8.

use encoding_rs::{Encoding, UTF_8};

use crate::metadata;

const META_SCAN_LIMIT: usize = 8 * 1024;

/// Decode a textual response body to valid UTF-8.
///
/// A supported charset declared in the HTTP `Content-Type` header is authoritative. For HTML
/// without a header declaration, an ASCII-compatible `<meta charset>` or
/// `<meta http-equiv="content-type">` declaration is used. UTF-8 is the fallback when a source
/// does not declare a supported encoding.
pub fn decode_body(body: &[u8], content_type: Option<&str>, is_html: bool) -> String {
    let declared = content_type
        .and_then(metadata::charset_from_content_type)
        .or_else(|| is_html.then(|| charset_from_meta_bytes(body)).flatten());
    let encoding = declared
        .as_deref()
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .unwrap_or(UTF_8);
    let (decoded, _, _) = encoding.decode(body);
    decoded.into_owned()
}

/// Find an HTML charset declaration without attempting to decode the whole body first.
///
/// Charset declarations in HTML are ASCII-compatible. Replacing non-ASCII bytes with spaces
/// prevents legacy content from changing the parser's view of an otherwise ASCII declaration.
fn charset_from_meta_bytes(body: &[u8]) -> Option<String> {
    let head: String = body
        .iter()
        .take(META_SCAN_LIMIT)
        .map(|byte| match byte {
            0..=127 => byte.to_ascii_lowercase() as char,
            _ => ' ',
        })
        .collect();

    let mut offset = 0;
    while let Some(start) = head[offset..].find("<meta") {
        let start = offset + start;
        let name_end = start + "<meta".len();
        let Some(next) = head.as_bytes().get(name_end) else {
            break;
        };
        if !next.is_ascii_whitespace() && *next != b'/' && *next != b'>' {
            offset = name_end;
            continue;
        }
        let Some(close) = head[name_end..].find('>') else {
            break;
        };
        let close = name_end + close;
        let attributes = attributes(&head[name_end..close]);
        if let Some(charset) = attributes
            .iter()
            .find(|(name, _)| name == "charset")
            .map(|(_, value)| value)
            .filter(|value| !value.is_empty())
        {
            return Some(charset.to_string());
        }
        let is_content_type = attributes.iter().any(|(name, value)| {
            name == "http-equiv" && value.eq_ignore_ascii_case("content-type")
        });
        if is_content_type {
            if let Some(content) = attributes
                .iter()
                .find(|(name, _)| name == "content")
                .map(|(_, value)| value)
            {
                if let Some(charset) = metadata::charset_from_content_type(content) {
                    return Some(charset);
                }
            }
        }
        offset = close + 1;
    }
    None
}

/// Parse the simple ASCII attributes used by HTML charset declarations.
fn attributes(tag: &str) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let bytes = tag.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b'/') {
            index += 1;
        }
        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && !matches!(bytes[index], b'=' | b'/' | b'>')
        {
            index += 1;
        }
        if name_start == index {
            index += 1;
            continue;
        }
        let name = tag[name_start..index].to_string();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            attributes.push((name, String::new()));
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let value = match bytes.get(index) {
            Some(b'"') | Some(b'\'') => {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                let value = tag[value_start..index].to_string();
                if index < bytes.len() {
                    index += 1;
                }
                value
            }
            _ => {
                let value_start = index;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && !matches!(bytes[index], b'/' | b'>')
                {
                    index += 1;
                }
                tag[value_start..index].to_string()
            }
        };
        attributes.push((name, value));
    }
    attributes
}

#[cfg(test)]
mod tests {
    use super::decode_body;

    #[test]
    fn decodes_header_declared_latin1() {
        let decoded = decode_body(b"caf\xe9", Some("text/plain; charset=ISO-8859-1"), false);
        assert_eq!(decoded, "café");
    }

    #[test]
    fn decodes_meta_declared_shift_jis() {
        let mut body = b"<meta charset=Shift_JIS>".to_vec();
        body.extend([0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea]);
        assert_eq!(
            decode_body(&body, Some("text/html"), true),
            "<meta charset=Shift_JIS>日本語"
        );
    }

    #[test]
    fn header_charset_takes_precedence_over_meta() {
        let body = b"<meta charset=Shift_JIS>caf\xe9";
        assert_eq!(
            decode_body(body, Some("text/html; charset=iso-8859-1"), true),
            "<meta charset=Shift_JIS>café"
        );
    }

    #[test]
    fn recognizes_http_equiv_meta_charset() {
        let mut body =
            b"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=Shift_JIS\">".to_vec();
        body.extend([0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea]);
        assert!(
            decode_body(&body, Some("text/html"), true).contains("日本語"),
            "http-equiv charset declaration should govern decoding"
        );
    }
}
