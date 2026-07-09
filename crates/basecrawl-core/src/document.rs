//! Text extraction for PDF and office-document response bodies.
//!
//! Document parsing is strictly content-type driven and happens in-process. The original binary is
//! never converted with lossy UTF-8 or exposed through `rawHtml`; only extracted text is allowed
//! onto markdown and HTML text surfaces.

use crate::content::DocumentKind;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::io::{Cursor, Read};
use zip::ZipArchive;

/// A conservative limit per XML member read from an office package.
const MAX_OFFICE_PART_BYTES: u64 = 4 * 1024 * 1024;
/// A single office package may contribute this much extracted text.
const MAX_OFFICE_TEXT_BYTES: usize = 4 * 1024 * 1024;
/// Archive metadata must not make document inspection unbounded.
const MAX_OFFICE_ARCHIVE_ENTRIES: usize = 10_000;
/// Bound the amount of decompression and XML parsing attempted for one package.
const MAX_OFFICE_TEXT_PARTS: usize = 256;

/// Extract display text from a supported document body.
///
/// Errors deliberately contain parser context rather than source bytes, so callers can return a
/// structured failure without leaking or dumping malformed binary data.
pub fn extract(body: &[u8], kind: DocumentKind) -> Result<String, String> {
    match kind {
        DocumentKind::Pdf => pdf_extract::extract_text_from_mem(body)
            .map(|text| normalize_text(&text))
            .map_err(|error| format!("could not extract PDF text: {error}")),
        DocumentKind::Office => extract_office(body),
    }
}

fn extract_office(body: &[u8]) -> Result<String, String> {
    let mut archive = ZipArchive::new(Cursor::new(body))
        .map_err(|error| format!("could not open office package: {error}"))?;
    if archive.len() > MAX_OFFICE_ARCHIVE_ENTRIES {
        return Err(format!(
            "office package has more than {MAX_OFFICE_ARCHIVE_ENTRIES} entries"
        ));
    }
    let mut extracted = String::new();
    let mut parts_found = 0usize;

    for index in 0..archive.len() {
        let name = {
            let file = archive
                .by_index(index)
                .map_err(|error| format!("could not inspect office package: {error}"))?;
            file.name().to_owned()
        };
        if !is_text_part(&name) {
            continue;
        }
        if parts_found == MAX_OFFICE_TEXT_PARTS {
            return Err(format!(
                "office package has more than {MAX_OFFICE_TEXT_PARTS} text parts"
            ));
        }
        parts_found += 1;
        let mut file = archive
            .by_index(index)
            .map_err(|error| format!("could not open office XML part: {error}"))?;
        let bytes = read_capped_part(&mut file)?;
        let source = std::str::from_utf8(&bytes)
            .map_err(|error| format!("office XML part was not UTF-8: {error}"))?;
        append_text(&mut extracted, &xml_text(source)?);
        if extracted.len() > MAX_OFFICE_TEXT_BYTES {
            return Err(format!(
                "office document extracted text exceeds {MAX_OFFICE_TEXT_BYTES}-byte limit"
            ));
        }
    }

    if parts_found == 0 {
        return Err("office package contains no recognized text XML parts".to_string());
    }

    Ok(normalize_text(&extracted))
}

fn is_text_part(name: &str) -> bool {
    matches!(
        name,
        "word/document.xml" | "content.xml" | "xl/sharedStrings.xml"
    ) || (name.starts_with("word/")
        && matches!(
            name.rsplit('/').next(),
            Some(part)
                if part.starts_with("header")
                    || part.starts_with("footer")
                    || matches!(part, "footnotes.xml" | "endnotes.xml" | "comments.xml")
        ))
        || (name.starts_with("ppt/slides/") && name.ends_with(".xml"))
        || (name.starts_with("xl/worksheets/") && name.ends_with(".xml"))
}

fn read_capped_part<R: Read>(part: &mut R) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    part.take(MAX_OFFICE_PART_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read office XML part: {error}"))?;
    if bytes.len() as u64 > MAX_OFFICE_PART_BYTES {
        return Err(format!(
            "office XML part exceeds {MAX_OFFICE_PART_BYTES}-byte limit"
        ));
    }
    Ok(bytes)
}

fn xml_text(source: &str) -> Result<String, String> {
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(false);
    let mut text = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Text(value)) => {
                let value = value
                    .decode()
                    .map_err(|error| format!("could not decode office XML text: {error}"))?;
                append_text(&mut text, &value);
            }
            Ok(Event::CData(value)) => {
                let value = value
                    .decode()
                    .map_err(|error| format!("could not decode office XML text: {error}"))?;
                append_text(&mut text, &value);
            }
            Ok(Event::Empty(element)) if is_break(element.name().as_ref()) => text.push('\n'),
            Ok(Event::End(element)) if is_paragraph(element.name().as_ref()) => text.push('\n'),
            Ok(Event::Eof) => break,
            Err(error) => return Err(format!("could not parse office XML: {error}")),
            _ => {}
        }
    }

    Ok(text)
}

fn is_break(name: &[u8]) -> bool {
    matches!(local_name(name), b"br" | b"line-break")
}

fn is_paragraph(name: &[u8]) -> bool {
    matches!(local_name(name), b"p" | b"h" | b"row")
}

fn local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

fn append_text(target: &mut String, text: &str) {
    if target.is_empty() || target.ends_with(char::is_whitespace) || text.is_empty() {
        target.push_str(text);
    } else {
        target.push(' ');
        target.push_str(text);
    }
}

fn normalize_text(text: &str) -> String {
    text.lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_document_whitespace_by_paragraph() {
        assert_eq!(
            normalize_text("  one \t two \n\n three  "),
            "one two\nthree"
        );
    }

    #[test]
    fn recognizes_ooxml_and_odf_text_parts() {
        for part in [
            "word/document.xml",
            "word/header1.xml",
            "word/comments.xml",
            "ppt/slides/slide1.xml",
            "xl/sharedStrings.xml",
            "xl/worksheets/sheet1.xml",
            "content.xml",
        ] {
            assert!(is_text_part(part), "expected text part: {part}");
        }
        assert!(!is_text_part("word/styles.xml"));
        assert!(!is_text_part("xl/workbook.xml"));
    }
}
