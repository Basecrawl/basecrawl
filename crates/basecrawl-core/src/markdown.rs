//! HTML → Firecrawl-parity Markdown conversion.
//!
//! This module turns fetched HTML into main-content Markdown. It centers on the page's primary
//! content (preferring `<main>`/`<article>`/`[role=main]`, else `<body>`) and drops repeated site
//! chrome (`<nav>`/`<header>`/`<footer>`/`<aside>`) plus non-content nodes (`<script>`/`<style>`),
//! so the output is the article, not the navigation boilerplate. It emits GitHub-flavored Markdown:
//! `#`..`######` headings, pipe-delimited tables with a header separator, fenced code blocks that
//! preserve whitespace, depth-indented nested lists, `[text](url)` links and `![alt](src)` images
//! with URLs resolved to absolute against the page base. An empty or content-free document yields
//! an empty (but valid) string rather than crashing.

use ego_tree::NodeRef;
use scraper::node::{Element, Node};
use scraper::{Html, Selector};
use url::Url;

/// Convert an HTML document into main-content Markdown.
///
/// Links and image sources are resolved to absolute URLs against `page_url` (or a document
/// `<base href>` when one is present). An empty or content-free document yields an empty string.
pub fn to_markdown(html: &str, page_url: &Url) -> String {
    let document = Html::parse_document(html);
    let base = base_href(&document)
        .and_then(|href| page_url.join(&href).ok())
        .unwrap_or_else(|| page_url.clone());
    let (root, preserve_semantic_headers) = main_content_root(&document);
    let converter = Converter {
        base,
        preserve_semantic_headers,
    };

    let mut blocks: Vec<String> = Vec::new();
    converter.render_blocks(root, &mut blocks);
    let joined = blocks.join("\n\n");
    normalize(&joined)
}

/// Extract a document `<base href>` value, if the document declares one.
fn base_href(document: &Html) -> Option<String> {
    let selector = Selector::parse("base[href]").ok()?;
    document
        .select(&selector)
        .next()
        .and_then(|el| el.value().attr("href"))
        .map(str::to_string)
}

/// Choose the node whose subtree holds the primary content: the first `<main>`, `<article>`, or
/// `[role=main]`, else `<body>`, else the document root. Headers inside an explicitly selected
/// content root are semantic content, while headers in a body fallback are page-level chrome.
fn main_content_root(document: &Html) -> (NodeRef<'_, Node>, bool) {
    for candidate in ["main", "article", "[role=\"main\"]", "[role=main]"] {
        if let Ok(selector) = Selector::parse(candidate) {
            if let Some(el) = document.select(&selector).next() {
                return (*el, true);
            }
        }
    }
    if let Ok(body) = Selector::parse("body") {
        if let Some(el) = document.select(&body).next() {
            return (*el, false);
        }
    }
    (document.tree.root(), false)
}

struct Converter {
    base: Url,
    preserve_semantic_headers: bool,
}

/// Block-level HTML elements that break the surrounding inline flow.
fn is_block(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "details"
            | "dialog"
            | "dd"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hgroup"
            | "hr"
            | "li"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "ul"
    )
}

/// Elements whose subtrees carry no visible content and are dropped entirely.
fn is_skipped(name: &str) -> bool {
    matches!(
        name,
        "script" | "style" | "noscript" | "template" | "svg" | "head" | "title"
    )
}

/// Site-chrome elements stripped so the Markdown centers on main content, not navigation.
fn is_boilerplate(name: &str) -> bool {
    matches!(name, "nav" | "header" | "footer" | "aside")
}

impl Converter {
    /// Render the block-level content of `parent`'s children, appending one entry to `blocks` per
    /// produced block. Consecutive inline content (text + inline elements) is coalesced into a
    /// single paragraph block.
    fn render_blocks(&self, parent: NodeRef<'_, Node>, blocks: &mut Vec<String>) {
        let mut inline = String::new();
        for child in parent.children() {
            match child.value() {
                Node::Element(el) => {
                    let name = el.name();
                    if is_skipped(name) || self.is_boilerplate(name) {
                        continue;
                    }
                    if is_block(name) {
                        flush_inline(&mut inline, blocks);
                        self.render_block_element(child, el, blocks);
                    } else {
                        inline.push_str(&self.inline_node(child));
                    }
                }
                Node::Text(text) => inline.push_str(&collapse_ws(&text.text)),
                _ => {}
            }
        }
        flush_inline(&mut inline, blocks);
    }

    /// Render a single block-level element into zero or more blocks.
    fn render_block_element(
        &self,
        node: NodeRef<'_, Node>,
        el: &Element,
        blocks: &mut Vec<String>,
    ) {
        match el.name() {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let level = el.name()[1..].parse::<usize>().unwrap_or(1);
                let text = self.inline_children(node);
                let text = text.trim();
                if !text.is_empty() {
                    blocks.push(format!("{} {}", "#".repeat(level), text));
                }
            }
            "ul" | "ol" => {
                let mut lines = Vec::new();
                self.render_list(node, el.name() == "ol", 0, &mut lines);
                if !lines.is_empty() {
                    blocks.push(lines.join("\n"));
                }
            }
            "table" => {
                if let Some(table) = self.render_table(node) {
                    blocks.push(table);
                }
            }
            "pre" => {
                blocks.push(self.render_pre(node));
            }
            "blockquote" => {
                let quoted = self.render_blockquote(node);
                if !quoted.trim().is_empty() {
                    blocks.push(quoted);
                }
            }
            "hr" => blocks.push("---".to_string()),
            "p" => {
                let text = self.inline_children(node);
                let text = text.trim();
                if !text.is_empty() {
                    blocks.push(text.to_string());
                }
            }
            // figure/figcaption/dl/details and generic containers: recurse for nested blocks.
            _ => self.render_blocks(node, blocks),
        }
    }

    /// Render an `<ol>`/`<ul>` (and its nested lists) into indented Markdown list lines.
    fn render_list(
        &self,
        list: NodeRef<'_, Node>,
        ordered: bool,
        depth: usize,
        lines: &mut Vec<String>,
    ) {
        let indent = "  ".repeat(depth);
        let mut index = 1usize;
        for item in list.children() {
            let Node::Element(el) = item.value() else {
                continue;
            };
            if el.name() != "li" {
                continue;
            }
            let marker = if ordered {
                format!("{index}.")
            } else {
                "-".to_string()
            };
            let mut inline = String::new();
            let mut nested: Vec<(NodeRef<'_, Node>, bool)> = Vec::new();
            for child in item.children() {
                match child.value() {
                    Node::Element(child_el) if matches!(child_el.name(), "ul" | "ol") => {
                        nested.push((child, child_el.name() == "ol"));
                    }
                    Node::Element(child_el)
                        if is_skipped(child_el.name()) || self.is_boilerplate(child_el.name()) => {}
                    _ => inline.push_str(&self.inline_node(child)),
                }
            }
            lines.push(format!("{indent}{marker} {}", inline.trim()));
            for (nested_list, nested_ordered) in nested {
                self.render_list(nested_list, nested_ordered, depth + 1, lines);
            }
            index += 1;
        }
    }

    /// Render a `<table>` as a GitHub-flavored Markdown table with a header separator row.
    fn render_table(&self, table: NodeRef<'_, Node>) -> Option<String> {
        let mut rows: Vec<(bool, Vec<String>)> = Vec::new();
        self.collect_rows(table, false, &mut rows);
        if rows.is_empty() {
            return None;
        }
        let cols = rows.iter().map(|(_, cells)| cells.len()).max().unwrap_or(0);
        if cols == 0 {
            return None;
        }

        let (header, body) = if rows[0].0 {
            (rows[0].1.clone(), &rows[1..])
        } else {
            (vec![String::new(); cols], &rows[..])
        };

        let mut lines = Vec::with_capacity(body.len() + 2);
        lines.push(render_row(&header, cols));
        lines.push(format!("| {} |", vec!["---"; cols].join(" | ")));
        for (_, cells) in body {
            lines.push(render_row(cells, cols));
        }
        Some(lines.join("\n"))
    }

    /// Walk a table subtree collecting `<tr>` rows. A row is flagged as a header row when it lives
    /// inside `<thead>` or when every one of its cells is a `<th>`.
    fn collect_rows(
        &self,
        node: NodeRef<'_, Node>,
        in_thead: bool,
        rows: &mut Vec<(bool, Vec<String>)>,
    ) {
        for child in node.children() {
            let Node::Element(el) = child.value() else {
                continue;
            };
            match el.name() {
                "thead" => self.collect_rows(child, true, rows),
                "tbody" | "tfoot" => self.collect_rows(child, false, rows),
                "tr" => {
                    let mut cells = Vec::new();
                    let mut all_th = true;
                    let mut saw_cell = false;
                    for cell in child.children() {
                        let Node::Element(cell_el) = cell.value() else {
                            continue;
                        };
                        if !matches!(cell_el.name(), "th" | "td") {
                            continue;
                        }
                        saw_cell = true;
                        if cell_el.name() != "th" {
                            all_th = false;
                        }
                        cells.push(cell_text(&self.inline_children(cell)));
                    }
                    if saw_cell {
                        rows.push((in_thead || all_th, cells));
                    }
                }
                _ => self.collect_rows(child, in_thead, rows),
            }
        }
    }

    /// Render a `<pre>` as a fenced code block, preserving its inner text verbatim. A structural
    /// newline is added only when needed to put the closing fence on its own line.
    fn render_pre(&self, node: NodeRef<'_, Node>) -> String {
        let lang = code_language(node).unwrap_or_default();
        let mut raw = String::new();
        collect_raw_text(node, &mut raw);
        let fence = code_fence(&raw);
        let closing_prefix = if raw.ends_with('\n') { "" } else { "\n" };
        format!("{fence}{lang}\n{raw}{closing_prefix}{fence}")
    }

    /// Render a `<blockquote>` by prefixing each line of its inner blocks with `> `.
    fn render_blockquote(&self, node: NodeRef<'_, Node>) -> String {
        let mut inner_blocks = Vec::new();
        self.render_blocks(node, &mut inner_blocks);
        let inner = inner_blocks.join("\n\n");
        inner
            .lines()
            .map(|line| {
                if line.is_empty() {
                    ">".to_string()
                } else {
                    format!("> {line}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Render a single node as inline Markdown text.
    fn inline_node(&self, node: NodeRef<'_, Node>) -> String {
        match node.value() {
            Node::Text(text) => collapse_ws(&text.text),
            Node::Element(el) => {
                let name = el.name();
                if is_skipped(name) {
                    return String::new();
                }
                match name {
                    "a" => {
                        let text = self.inline_children(node);
                        match el.attr("href").and_then(|href| self.resolve(href)) {
                            Some(url) if !text.trim().is_empty() => {
                                emphasis_wrap(&text, &format!("[{}]({url})", text.trim()))
                            }
                            _ => text,
                        }
                    }
                    "img" => self.render_img(el),
                    "br" => "  \n".to_string(),
                    "strong" | "b" => wrap_emphasis(&self.inline_children(node), "**"),
                    "em" | "i" => wrap_emphasis(&self.inline_children(node), "*"),
                    "code" => {
                        let mut raw = String::new();
                        collect_raw_text(node, &mut raw);
                        if raw.is_empty() {
                            String::new()
                        } else {
                            format!("`{raw}`")
                        }
                    }
                    "wbr" => String::new(),
                    _ => self.inline_children(node),
                }
            }
            _ => String::new(),
        }
    }

    /// Concatenate the inline rendering of every child of `node`.
    fn inline_children(&self, node: NodeRef<'_, Node>) -> String {
        let mut out = String::new();
        for child in node.children() {
            out.push_str(&self.inline_node(child));
        }
        out
    }

    /// Render an `<img>` as `![alt](absolute-src)`, or the empty string when it has no usable src.
    fn render_img(&self, el: &Element) -> String {
        let src = el
            .attr("src")
            .or_else(|| el.attr("data-src"))
            .filter(|s| !s.trim().is_empty());
        let Some(src) = src else {
            return String::new();
        };
        let resolved = self.resolve(src).unwrap_or_else(|| src.to_string());
        let alt = el.attr("alt").unwrap_or("");
        format!("![{alt}]({resolved})")
    }

    /// Resolve an href/src against the page base, yielding an absolute URL. Empty targets resolve
    /// to `None`.
    fn resolve(&self, target: &str) -> Option<String> {
        let target = target.trim();
        if target.is_empty() {
            return None;
        }
        self.base.join(target).ok().map(String::from)
    }

    /// Headers selected as descendants of main/article/role=main carry article semantics rather
    /// than page chrome. Other boilerplate categories remain stripped at every depth.
    fn is_boilerplate(&self, name: &str) -> bool {
        is_boilerplate(name) && !(self.preserve_semantic_headers && name == "header")
    }
}

/// Collect the verbatim text of a subtree without collapsing whitespace (for code blocks).
fn collect_raw_text(node: NodeRef<'_, Node>, out: &mut String) {
    for child in node.children() {
        match child.value() {
            Node::Text(text) => out.push_str(&text.text),
            Node::Element(el) if !is_skipped(el.name()) => collect_raw_text(child, out),
            _ => {}
        }
    }
}

/// Choose a backtick fence that cannot be closed by a backtick run inside the code content.
fn code_fence(raw: &str) -> String {
    let mut longest_run = 0;
    let mut current_run = 0;
    for ch in raw.chars() {
        if ch == '`' {
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    "`".repeat((longest_run + 1).max(3))
}

/// Detect a fenced-code language hint from a `<code class="language-xxx">` (or `lang-xxx`).
fn code_language(pre: NodeRef<'_, Node>) -> Option<String> {
    for child in pre.children() {
        if let Node::Element(el) = child.value() {
            if el.name() == "code" {
                if let Some(class) = el.attr("class") {
                    for token in class.split_whitespace() {
                        if let Some(lang) = token
                            .strip_prefix("language-")
                            .or_else(|| token.strip_prefix("lang-"))
                        {
                            if !lang.is_empty() {
                                return Some(lang.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Prepare a single table cell: single-line, with pipes escaped.
fn cell_text(text: &str) -> String {
    text.trim().replace('\n', " ").replace('|', "\\|")
}

/// Render one table row padded to `cols` columns.
fn render_row(cells: &[String], cols: usize) -> String {
    let mut padded: Vec<String> = cells.to_vec();
    while padded.len() < cols {
        padded.push(String::new());
    }
    padded.truncate(cols);
    format!("| {} |", padded.join(" | "))
}

/// Wrap `inner` in an emphasis `marker`, preserving any leading/trailing whitespace outside the
/// markers (so `<b> x </b>` does not glue onto neighboring words).
fn wrap_emphasis(inner: &str, marker: &str) -> String {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return inner.to_string();
    }
    let lead = if inner.starts_with(char::is_whitespace) {
        " "
    } else {
        ""
    };
    let trail = if inner.ends_with(char::is_whitespace) {
        " "
    } else {
        ""
    };
    format!("{lead}{marker}{trimmed}{marker}{trail}")
}

/// Preserve leading/trailing whitespace of `original` around a `replacement` inline token.
fn emphasis_wrap(original: &str, replacement: &str) -> String {
    let lead = if original.starts_with(char::is_whitespace) {
        " "
    } else {
        ""
    };
    let trail = if original.ends_with(char::is_whitespace) {
        " "
    } else {
        ""
    };
    format!("{lead}{replacement}{trail}")
}

/// Collapse every run of ASCII/Unicode whitespace to a single space (HTML inline whitespace rules),
/// preserving a single leading/trailing space when the source had one.
fn collapse_ws(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

/// Flush the accumulated inline buffer as a paragraph block (if non-empty) and clear it.
fn flush_inline(inline: &mut String, blocks: &mut Vec<String>) {
    let trimmed = inline.trim();
    if !trimmed.is_empty() {
        blocks.push(trimmed.to_string());
    }
    inline.clear();
}

/// Normalize prose while treating fenced code as a verbatim region. Prose line endings are trimmed
/// and excess blank lines are collapsed, but code content preserves trailing spaces, tabs, blank
/// final lines, and internal newlines exactly.
fn normalize(markdown: &str) -> String {
    let mut out = String::with_capacity(markdown.len());
    let mut fence_len = None;
    let mut blank_lines = 0;
    for line in markdown.split('\n') {
        if let Some(opening_len) = fence_len {
            out.push_str(line);
            out.push('\n');
            if is_closing_fence(line, opening_len) {
                fence_len = None;
            }
            blank_lines = 0;
            continue;
        }

        if let Some(opening_len) = opening_fence_len(line) {
            out.push_str(line);
            out.push('\n');
            fence_len = Some(opening_len);
            blank_lines = 0;
            continue;
        }

        let line = line.trim_end();
        if line.is_empty() {
            blank_lines += 1;
            if blank_lines > 1 {
                continue;
            }
        } else {
            blank_lines = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim().to_string()
}

/// Return the leading backtick-fence length for an opening fence line.
fn opening_fence_len(line: &str) -> Option<usize> {
    let len = line.bytes().take_while(|byte| *byte == b'`').count();
    (len >= 3).then_some(len)
}

/// A closing fence is the matching-or-longer delimiter followed only by whitespace.
fn is_closing_fence(line: &str, opening_len: usize) -> bool {
    let len = line.bytes().take_while(|byte| *byte == b'`').count();
    len >= opening_len && line[len..].trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md(html: &str) -> String {
        to_markdown(
            html,
            &Url::parse("https://example.com/dir/page.html").unwrap(),
        )
    }

    #[test]
    fn headings_map_h1_to_h4() {
        let out = md("<h1>One</h1><h2>Two</h2><h3>Three</h3><h4>Four</h4>");
        assert!(out.contains("# One"));
        assert!(out.contains("## Two"));
        assert!(out.contains("### Three"));
        assert!(out.contains("#### Four"));
        // Ensure exact level mapping (no over/under counting hashes).
        for line in out.lines() {
            if line.ends_with("One") {
                assert_eq!(line, "# One");
            }
            if line.ends_with("Four") {
                assert_eq!(line, "#### Four");
            }
        }
    }

    #[test]
    fn table_renders_as_gfm_with_header_separator() {
        let html = "<table><thead><tr><th>Name</th><th>Age</th></tr></thead>\
            <tbody><tr><td>Alice</td><td>30</td></tr></tbody></table>";
        let out = md(html);
        assert!(out.contains("| Name | Age |"), "header row:\n{out}");
        assert!(out.contains("| --- | --- |"), "separator row:\n{out}");
        assert!(out.contains("| Alice | 30 |"), "data row:\n{out}");
    }

    #[test]
    fn header_less_table_still_gets_a_separator() {
        let html = "<table><tr><th>UPC</th><td>abc123</td></tr>\
            <tr><th>Price</th><td>51.77</td></tr></table>";
        let out = md(html);
        // key/value rows are not a heading row, so a separator is synthesized.
        assert!(out.contains("| --- | --- |"), "separator missing:\n{out}");
        assert!(out.contains("| UPC | abc123 |"), "row missing:\n{out}");
    }

    #[test]
    fn code_block_is_fenced_and_preserves_whitespace() {
        let html = "<pre><code>fn main() {\n    println!(\"hi\");\n}</code></pre>";
        let out = md(html);
        assert!(out.starts_with("```"), "not fenced:\n{out}");
        assert!(out.contains("    println!(\"hi\");"), "indent lost:\n{out}");
        assert!(out.trim_end().ends_with("```"), "no closing fence:\n{out}");
    }

    #[test]
    fn nested_lists_preserve_depth() {
        let html = "<ul><li>top<ul><li>child<ul><li>grand</li></ul></li></ul></li></ul>";
        let out = md(html);
        assert!(out.contains("- top"), "top level:\n{out}");
        assert!(out.contains("  - child"), "second level indent:\n{out}");
        assert!(out.contains("    - grand"), "third level indent:\n{out}");
    }

    #[test]
    fn ordered_list_numbers_items() {
        let out = md("<ol><li>first</li><li>second</li></ol>");
        assert!(out.contains("1. first"), "{out}");
        assert!(out.contains("2. second"), "{out}");
    }

    #[test]
    fn inline_links_are_absolute() {
        let out = md("<p>see <a href=\"../other.html\">other</a></p>");
        assert!(
            out.contains("[other](https://example.com/other.html)"),
            "relative link not resolved:\n{out}"
        );
    }

    #[test]
    fn root_relative_link_resolves_against_host() {
        let out = md("<p><a href=\"/tag/x/\">x</a></p>");
        assert!(out.contains("[x](https://example.com/tag/x/)"), "{out}");
    }

    #[test]
    fn images_render_with_resolved_src() {
        let out = md("<img src=\"../img/cover.jpg\" alt=\"Cover\">");
        assert!(
            out.contains("![Cover](https://example.com/img/cover.jpg)"),
            "image not resolved:\n{out}"
        );
    }

    #[test]
    fn image_without_alt_uses_empty_alt() {
        let out = md("<img src=\"/a.png\">");
        assert!(out.contains("![](https://example.com/a.png)"), "{out}");
    }

    #[test]
    fn empty_document_yields_empty_markdown() {
        assert_eq!(md(""), "");
        assert_eq!(md("<html><head></head><body></body></html>"), "");
        assert_eq!(to_markdown("", &Url::parse("https://x.test/").unwrap()), "");
    }

    #[test]
    fn boilerplate_is_stripped_in_favor_of_main() {
        let html = "<body><nav><a href=\"/\">Home</a> Navigation menu</nav>\
            <header>Site header</header>\
            <main><h1>Article Title</h1><p>The real content.</p></main>\
            <footer>Copyright footer</footer></body>";
        let out = md(html);
        assert!(out.contains("# Article Title"), "{out}");
        assert!(out.contains("The real content."), "{out}");
        assert!(!out.contains("Navigation menu"), "nav leaked:\n{out}");
        assert!(!out.contains("Site header"), "header leaked:\n{out}");
        assert!(!out.contains("Copyright footer"), "footer leaked:\n{out}");
    }

    #[test]
    fn semantic_headers_inside_selected_main_survive_page_chrome_stripping() {
        // VAL-CRAWL-027/031/033: outer page chrome must disappear, but a `<header>` that
        // belongs to the selected content root carries semantic article headings.
        let html = "<body>\
            <header>Global site header</header>\
            <nav>Global navigation</nav>\
            <main>\
              <header><h1>Article title</h1><h2>Overview</h2><h3>Details</h3></header>\
              <p>Article body.</p>\
            </main>\
            <footer>Global footer</footer>\
        </body>";
        let out = md(html);

        assert!(
            out.contains("# Article title"),
            "article h1 dropped:\n{out}"
        );
        assert!(out.contains("## Overview"), "article h2 dropped:\n{out}");
        assert!(out.contains("### Details"), "article h3 dropped:\n{out}");
        assert!(
            out.contains("Article body."),
            "article body dropped:\n{out}"
        );
        assert!(!out.contains("Global site header"), "chrome leaked:\n{out}");
        assert!(!out.contains("Global navigation"), "chrome leaked:\n{out}");
        assert!(!out.contains("Global footer"), "chrome leaked:\n{out}");
    }

    #[test]
    fn fenced_code_remains_verbatim_through_normalization() {
        // VAL-CRAWL-029/090: trailing spaces, tabs, blank final lines, and internal newlines
        // are data inside a fenced block and must not be touched by markdown normalization.
        let code = "let value = 1;  \t\n\n\tuse(value);  \n\n";
        let html = format!(
            "<main><pre><code class=\"language-rust\">{code}</code></pre><p>After</p></main>"
        );
        let out = md(&html);
        let expected = format!("```rust\n{code}```\n\nAfter");

        assert_eq!(out, expected);
        assert_eq!(out, md(&html), "markdown must remain deterministic");
    }

    #[test]
    fn scripts_and_styles_are_dropped() {
        let html = "<body><p>Visible</p><script>var secret=1;</script>\
            <style>.x{color:red}</style></body>";
        let out = md(html);
        assert!(out.contains("Visible"));
        assert!(!out.contains("secret"), "script leaked:\n{out}");
        assert!(!out.contains("color:red"), "style leaked:\n{out}");
    }

    #[test]
    fn base_href_is_honored_for_link_resolution() {
        let html = "<head><base href=\"https://cdn.test/base/\"></head>\
            <body><p><a href=\"rel.html\">rel</a></p></body>";
        let out = md(html);
        assert!(
            out.contains("[rel](https://cdn.test/base/rel.html)"),
            "{out}"
        );
    }

    #[test]
    fn paragraph_inline_run_is_coalesced() {
        let out = md("<div>Some text <a href=\"/l\">link</a> more text</div>");
        assert!(
            out.contains("Some text [link](https://example.com/l) more text"),
            "inline run split:\n{out}"
        );
        // The whole thing is a single block (one line).
        assert_eq!(out.lines().count(), 1, "expected one paragraph:\n{out}");
    }

    #[test]
    fn markdown_is_deterministic() {
        let html = "<main><h1>T</h1><p>a</p><ul><li>x</li><li>y</li></ul></main>";
        assert_eq!(md(html), md(html));
    }
}
