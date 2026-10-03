//! Bionic reading + raw-markdown view transforms (M3c).
//!
//! Ported from the standalone bionic reader at `~/projects/bionic-reader-cli`
//! (`src/transform/bold.rs` + `src/transform/acronym.rs`) with no new
//! dependencies: the CLI's pulldown-cmark parse is replaced by a line-aware
//! scanner covering the garden's markdown — fenced code blocks and inline
//! backtick spans are never transformed.
//!
//! Ported behaviour (must match the CLI):
//! - leading-portion bold fraction default `0.4`;
//!   `bold_len = floor(word_chars * ratio)` clamped to `[1, len]`;
//! - a "word" is a run of alphanumeric chars plus `'` and `-`;
//! - an acronym is an all-ASCII-uppercase word of length ≥ 2 that is not in
//!   the CLI's `FALSE_POSITIVES` list → styled purple, not bolded;
//! - fenced code blocks and inline code are left untouched.
//!
//! Known deltas vs the CLI (documented by the M3c design lock): indented code
//! blocks and HTML blocks are not specially skipped, and tables render as
//! source lines (the CLI renders them as HTML tables). The RSVP overlay is not
//! ported.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Default leading-portion bold fraction — the CLI's `bold_ratio` default.
pub const DEFAULT_BOLD_RATIO: f32 = 0.4;

/// The CLI's `FALSE_POSITIVES`: uppercase tokens that look like acronyms but
/// are common words.
const FALSE_POSITIVES: &[&str] = &[
    "I", "A", "OK", "AM", "PM", "US", "IT", "TV", "ID", "OR", "AN",
];

fn bold_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

fn acronym_style() -> Style {
    // The CLI's `.bionic-acronym { color: #B19CD9 }` (light purple).
    Style::default().fg(Color::LightMagenta)
}

fn code_style() -> Style {
    Style::default().fg(Color::Yellow)
}

fn heading_style(level: usize) -> Style {
    let color = match level {
        1 => Color::LightCyan,
        2 => Color::LightGreen,
        3 => Color::LightYellow,
        _ => Color::LightMagenta,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

/// Number of leading characters to bold in a word of `word_chars` chars.
/// Mirrors the CLI's `calculate_bold_length`.
pub fn bold_len(word_chars: usize, ratio: f32) -> usize {
    if word_chars == 0 {
        return 0;
    }
    let bold = (word_chars as f32 * ratio).floor() as usize;
    bold.max(1).min(word_chars)
}

/// Split `word` into its bold leading portion and the rest. Mirrors the CLI's
/// `boldify`, char-safe for Unicode.
pub fn split_word(word: &str, ratio: f32) -> (String, String) {
    let chars: Vec<char> = word.chars().collect();
    let n = bold_len(chars.len(), ratio);
    let bold: String = chars[..n].iter().collect();
    let rest: String = chars[n..].iter().collect();
    (bold, rest)
}

/// Whether `word` is an acronym by the CLI's rule.
pub fn is_acronym(word: &str) -> bool {
    if word.chars().count() < 2 {
        return false;
    }
    if FALSE_POSITIVES.contains(&word) {
        return false;
    }
    word.chars().all(|c| c.is_ascii_uppercase())
}

/// A word character by the CLI's rule: alphanumeric plus `'` and `-`.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '\'' || c == '-'
}

fn flush_word(spans: &mut Vec<Span<'static>>, word: &mut String, ratio: f32) {
    if word.is_empty() {
        return;
    }
    if is_acronym(word) {
        spans.push(Span::styled(std::mem::take(word), acronym_style()));
        return;
    }
    let (bold, rest) = split_word(word, ratio);
    if !bold.is_empty() {
        spans.push(Span::styled(bold, bold_style()));
    }
    if !rest.is_empty() {
        spans.push(Span::raw(rest));
    }
    word.clear();
}

/// Append the bionic spans for one non-code text segment. Whitespace and
/// punctuation are preserved verbatim (the CLI's contract).
fn push_bionic_text(spans: &mut Vec<Span<'static>>, text: &str, ratio: f32) {
    let mut word = String::new();
    let mut sep = String::new();
    for c in text.chars() {
        if is_word_char(c) {
            if !sep.is_empty() {
                spans.push(Span::raw(std::mem::take(&mut sep)));
            }
            word.push(c);
        } else {
            flush_word(spans, &mut word, ratio);
            sep.push(c);
        }
    }
    if !sep.is_empty() {
        spans.push(Span::raw(sep));
    }
    flush_word(spans, &mut word, ratio);
}

/// Backtick-aware inline styling for the raw view: backtick spans are left
/// verbatim but tinted; everything else is plain. A dangling/unmatched
/// backtick treats the rest of the line as code (scanner simplification).
fn inline_code_spans(text: &str) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut seg = String::new();
    let mut in_code = false;
    for c in text.chars() {
        if c == '`' {
            if in_code {
                seg.push('`');
                spans.push(Span::styled(std::mem::take(&mut seg), code_style()));
            } else {
                if !seg.is_empty() {
                    spans.push(Span::raw(std::mem::take(&mut seg)));
                }
                seg.push('`');
            }
            in_code = !in_code;
        } else {
            seg.push(c);
        }
    }
    if !seg.is_empty() {
        if in_code {
            spans.push(Span::styled(seg, code_style()));
        } else {
            spans.push(Span::raw(seg));
        }
    }
    spans
}

fn inline_code_line(line: &str) -> Line<'static> {
    let spans = inline_code_spans(line);
    if spans.is_empty() {
        Line::default()
    } else {
        Line::from(spans)
    }
}

/// Whether a raw markdown line opens/closes a fenced code block (up to three
/// leading spaces; ` ``` ` or `~~~`).
pub fn fence_marker(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("```") || t.starts_with("~~~")
}

/// Style one bionic-view line. When `in_fence` (or the line is a fence
/// marker) the line is fenced code and is returned untouched; inline backtick
/// spans are likewise untouched.
fn bionic_line(line: &str, ratio: f32, in_fence: bool) -> Line<'static> {
    if in_fence {
        return Line::from(Span::styled(line.to_string(), code_style()));
    }
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut seg = String::new();
    let mut in_code = false;
    for c in line.chars() {
        if c == '`' {
            if in_code {
                seg.push('`');
                spans.push(Span::styled(std::mem::take(&mut seg), code_style()));
            } else {
                if !seg.is_empty() {
                    push_bionic_text(&mut spans, &seg, ratio);
                    seg.clear();
                }
                seg.push('`');
            }
            in_code = !in_code;
        } else {
            seg.push(c);
        }
    }
    if !seg.is_empty() {
        if in_code {
            spans.push(Span::styled(seg, code_style()));
        } else {
            push_bionic_text(&mut spans, &seg, ratio);
        }
    }
    Line::from(spans)
}

/// Bionic-render a pre-split line buffer (no join/copy of the file).
pub fn render_bionic_lines(lines: &[String], ratio: f32) -> Vec<Line<'static>> {
    let mut out = Vec::with_capacity(lines.len());
    let mut in_fence = false;
    for line in lines {
        if fence_marker(line) {
            out.push(Line::from(Span::styled(line.clone(), code_style())));
            in_fence = !in_fence;
        } else {
            out.push(bionic_line(line, ratio, in_fence));
        }
    }
    out
}

/// Bionic-render a whole document. O(n) single pass; call once per open/toggle
/// and cache — never per frame.
pub fn render_bionic(text: &str, ratio: f32) -> Vec<Line<'static>> {
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    render_bionic_lines(&lines, ratio)
}

fn bullet_prefix(trimmed: &str) -> Option<usize> {
    let mut cs = trimmed.chars();
    match (cs.next(), cs.next()) {
        (Some(c), Some(' ')) if matches!(c, '-' | '*' | '+') => Some(c.len_utf8() + 1),
        _ => None,
    }
}

fn ordered_prefix(trimmed: &str) -> Option<usize> {
    let digits = trimmed.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0 && trimmed[digits..].starts_with(". ") {
        Some(digits + 2)
    } else {
        None
    }
}

/// Style one raw-source line for the editor's raw view plus the fence state
/// after the line (so a caller can cache incrementally). O(line); a fence
/// marker flips the state.
pub fn markdown_line(line: &str, in_fence: bool) -> (Line<'static>, bool) {
    if fence_marker(line) {
        return (
            Line::from(Span::styled(line.to_string(), code_style())),
            !in_fence,
        );
    }
    if in_fence {
        return (
            Line::from(Span::styled(line.to_string(), code_style())),
            in_fence,
        );
    }
    let trimmed = line.trim_start();
    let hashes = trimmed.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&hashes) && trimmed[hashes..].starts_with(' ') {
        return (
            Line::from(Span::styled(line.to_string(), heading_style(hashes))),
            in_fence,
        );
    }
    if matches!(trimmed, "---" | "***" | "___") {
        return (
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::DarkGray),
            )),
            in_fence,
        );
    }
    if trimmed.starts_with('>') {
        return (
            Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Green),
            )),
            in_fence,
        );
    }
    if let Some(n) = bullet_prefix(trimmed).or_else(|| ordered_prefix(trimmed)) {
        let lead = line.len() - trimmed.len();
        let mut spans: Vec<Span<'static>> = Vec::new();
        if lead > 0 {
            spans.push(Span::raw(line[..lead].to_string()));
        }
        spans.push(Span::styled(
            trimmed[..n].to_string(),
            Style::default().fg(Color::Cyan),
        ));
        spans.extend(inline_code_spans(&trimmed[n..]));
        return (Line::from(spans), in_fence);
    }
    (inline_code_line(line), in_fence)
}

/// Raw-source-render a pre-split line buffer (the editor's cache builder).
pub fn render_markdown_lines(lines: &[String]) -> Vec<Line<'static>> {
    let mut out = Vec::with_capacity(lines.len());
    let mut state = false;
    for line in lines {
        let (styled, after) = markdown_line(line, state);
        out.push(styled);
        state = after;
    }
    out
}

/// Raw-source-render a whole document (tests / one-shot use).
pub fn render_markdown(text: &str) -> Vec<Line<'static>> {
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    render_markdown_lines(&lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn is_bold(span: &Span<'_>) -> bool {
        span.style.add_modifier.contains(Modifier::BOLD)
    }

    #[test]
    fn bold_len_matches_cli() {
        assert_eq!(bold_len(0, 0.4), 0);
        assert_eq!(bold_len(1, 0.4), 1);
        assert_eq!(bold_len(2, 0.4), 1);
        assert_eq!(bold_len(3, 0.4), 1);
        assert_eq!(bold_len(5, 0.4), 2);
        assert_eq!(bold_len(7, 0.4), 2);
        assert_eq!(bold_len(10, 0.4), 4);
        assert_eq!(bold_len(10, 0.5), 5);
        assert_eq!(bold_len(10, 0.3), 3);
    }

    #[test]
    fn split_word_matches_cli_boldify() {
        assert_eq!(split_word("Hello", 0.4), ("He".into(), "llo".into()));
        assert_eq!(split_word("a", 0.4), ("a".into(), "".into()));
        assert_eq!(split_word("to", 0.4), ("t".into(), "o".into()));
        assert_eq!(
            split_word("programming", 0.4),
            ("prog".into(), "ramming".into())
        );
        // Unicode is char-counted, not byte-counted (CLI test).
        assert_eq!(split_word("héllo", 0.4), ("hé".into(), "llo".into()));
        assert_eq!(split_word("日本語", 0.4), ("日".into(), "本語".into()));
    }

    #[test]
    fn acronym_rule_and_false_positives() {
        assert!(is_acronym("API"));
        assert!(is_acronym("NASA"));
        assert!(!is_acronym("Api"));
        assert!(!is_acronym("I"));
        for fp in ["OK", "AM", "PM", "US", "IT", "TV", "ID", "OR", "AN", "A"] {
            assert!(!is_acronym(fp), "{fp} must stay a false positive");
        }
    }

    #[test]
    fn bionic_bolds_leading_portion_and_preserves_text() {
        let lines = render_bionic("Hello world", 0.4);
        assert_eq!(lines.len(), 1);
        let l = &lines[0];
        // "He" bold, "llo" plain, " " plain, "wo" bold, "rld" plain.
        assert!(is_bold(&l.spans[0]));
        assert_eq!(l.spans[0].content.as_ref(), "He");
        assert_eq!(line_text(l), "Hello world");
        assert!(
            l.spans
                .iter()
                .any(|s| s.content.as_ref() == "wo" && is_bold(s))
        );
    }

    #[test]
    fn acronyms_are_purple_and_not_bolded() {
        let lines = render_bionic("The API is great", 0.4);
        let l = &lines[0];
        let api = l
            .spans
            .iter()
            .find(|s| s.content.as_ref() == "API")
            .expect("API span");
        assert_eq!(api.style.fg, Some(Color::LightMagenta));
        assert!(!is_bold(api));
        assert_eq!(line_text(l), "The API is great");
    }

    #[test]
    fn fenced_code_is_untouched() {
        let doc = "before\n```\nHello world API\n```\nafter";
        let lines = render_bionic(doc, 0.4);
        assert_eq!(lines.len(), 5);
        // The code content line is one plain code-styled span, never bolded.
        let code = &lines[2];
        assert_eq!(code.spans.len(), 1);
        assert_eq!(code.spans[0].content.as_ref(), "Hello world API");
        assert!(!is_bold(&code.spans[0]));
        assert_eq!(code.spans[0].style.fg, Some(Color::Yellow));
    }

    #[test]
    fn inline_code_is_untouched() {
        let lines = render_bionic("Use `hello world` now", 0.4);
        let l = &lines[0];
        let code = l
            .spans
            .iter()
            .find(|s| s.content.as_ref() == "`hello world`")
            .expect("inline code span");
        assert!(!is_bold(code));
        assert_eq!(line_text(l), "Use `hello world` now");
    }

    #[test]
    fn contractions_and_punctuation_split_like_the_cli() {
        let l = render_bionic("don't stop, really!", 0.4);
        let text = line_text(&l[0]);
        assert_eq!(text, "don't stop, really!");
        // "don't" is 5 chars -> bold "do".
        assert_eq!(l[0].spans[0].content.as_ref(), "do");
        assert!(is_bold(&l[0].spans[0]));
    }

    #[test]
    fn empty_and_blank_lines_survive() {
        let lines = render_bionic("", 0.4);
        assert_eq!(lines.len(), 1);
        assert_eq!(line_text(&lines[0]), "");
        let lines = render_bionic("a\n\nb", 0.4);
        assert_eq!(lines.len(), 3);
        assert_eq!(line_text(&lines[1]), "");
    }

    #[test]
    fn markdown_line_styles_headings_and_tracks_fences() {
        let (h, state) = markdown_line("# Title", false);
        assert!(!state);
        assert!(is_bold(&h.spans[0]));
        assert_eq!(line_text(&h), "# Title");

        let (fence, state) = markdown_line("```rust", false);
        assert!(state);
        assert_eq!(fence.spans[0].style.fg, Some(Color::Yellow));

        let (inside, state) = markdown_line("let x = 1;", true);
        assert!(state);
        assert_eq!(inside.spans[0].style.fg, Some(Color::Yellow));

        let (close, state) = markdown_line("```", true);
        assert!(!state);
        assert_eq!(close.spans[0].style.fg, Some(Color::Yellow));
    }

    #[test]
    fn markdown_line_styles_bullets_and_quotes() {
        let (b, _) = markdown_line("- item", false);
        assert_eq!(b.spans[0].content.as_ref(), "- ");
        assert_eq!(b.spans[0].style.fg, Some(Color::Cyan));
        assert_eq!(line_text(&b), "- item");

        let (q, _) = markdown_line("> quoted", false);
        assert_eq!(q.spans[0].style.fg, Some(Color::Green));

        let (o, _) = markdown_line("12. ordered", false);
        assert_eq!(o.spans[0].content.as_ref(), "12. ");
    }

    #[test]
    fn large_document_transform_is_linear_and_survives() {
        // ≥1 MB synthesized doc: prose + acronyms + fenced code.
        let para = "The quick brown fox jumps over the lazy dog API HTTP NASA. \
                    Bionic reading bolds the leading portion of every word.\n";
        let fence = "```rust\nlet api_key = \"not a secret\";\n```\n";
        let mut doc = String::with_capacity(1_200_000);
        while doc.len() < 1_100_000 {
            doc.push_str(para);
            doc.push_str(fence);
        }
        let expected_lines = doc.split('\n').count();
        let start = std::time::Instant::now();
        let lines = render_bionic(&doc, DEFAULT_BOLD_RATIO);
        let elapsed = start.elapsed();
        assert_eq!(lines.len(), expected_lines);
        // Generous bound: a quadratic transform on ~1 MB would blow far past
        // this in a debug build; O(n) stays well under it.
        assert!(
            elapsed.as_secs() < 10,
            "1 MB transform took {elapsed:?} — expected near-linear"
        );
    }

    #[test]
    fn markdown_render_of_large_document_is_stable() {
        let doc = "# head\n\nbody text\n\n```\ncode\n```\n".repeat(8_000);
        let lines = render_markdown(&doc);
        assert_eq!(lines.len(), doc.split('\n').count());
    }
}
