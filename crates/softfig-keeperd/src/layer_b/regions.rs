//! M2c — inline `<vault id="...">…</vault>` tag parser registry +
//! region-keyed Layer B helpers.
//!
//! Per the lock in `meta/spec-vault.md` "M2c implementation slice":
//!
//! * Universal XML-like tag shape, per-format embedding rules. The
//!   parser only looks for `<vault id="…">` open tags and `</vault>`
//!   close tags as literal bytes — it never synthesizes the wrapper.
//! * Closed-enum [`RegionParser`]. v1 ships [`Markdown`](RegionParser::Markdown)
//!   (line-aware byte scan, skips fenced code blocks *and* inline
//!   backtick code spans so prose that documents `<vault …>` tags isn't
//!   parsed as a real region),
//!   [`Toml`](RegionParser::Toml) (raw-byte scan that masks `#` comments
//!   — the TOML analog of the markdown code-span exemption — so
//!   documented tags aren't parsed, while still finding tags embedded in
//!   string values), and [`PlainText`](RegionParser::PlainText) (UTF-8
//!   sniff + raw byte scan). YAML / JSON / source-code parsers land as
//!   additive enum variants later.
//! * Per-region subkey via [`VaultSession::derive_layer_b_region_subkey`]
//!   (path-and-id-keyed HKDF, distinct info string from the whole-file
//!   Layer B subkey).
//! * Read view: body bytes are replaced with the literal
//!   [`ENCRYPTED_PLACEHOLDER`] (`[encrypted]`); tag and id text round-
//!   trip verbatim.
//! * Write view: bodies equal to the literal `[encrypted]` re-embed the
//!   prior-tip ciphertext byte-identically; other bodies get fresh
//!   per-region encryption + base64 inline embedding. The literal
//!   `[encrypted]` is therefore a reserved placeholder.
//! * Strict base64 (STANDARD, padding required, no whitespace) on read
//!   to preserve the convergent-nonce dedup invariant.
//! * Fail-closed on malformed tags: read returns the
//!   `[malformed vault tag in <path>]\n` placeholder for the whole file;
//!   write rejects the commit (EIO at the FUSE boundary).

use std::ops::Range;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use softfig_vault::VaultSession;
use thiserror::Error;

/// Max id length per the M2c id-charset lock.
pub const REGION_ID_MAX: usize = 64;

/// Constant-length read-view placeholder for the body of a Ciphertext
/// region. Reserved on write (a literal `[encrypted]` plaintext body is
/// only valid when the prior commit had matching ciphertext to
/// re-embed).
pub const ENCRYPTED_PLACEHOLDER: &[u8] = b"[encrypted]";

/// One parsed `<vault id="…">…</vault>` region. Byte offsets index into
/// the original (raw) content the parser was called with.
#[derive(Debug, Clone)]
pub struct RegionSpan {
    pub id: String,
    /// Byte range of the body (between `>` of the open tag and `<` of
    /// the close tag). Substitutions on read / write happen against
    /// this range.
    pub body_byte_range: Range<usize>,
    pub kind: RegionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Body decodes as canonical base64 AND `layer_b_decrypt` under the
    /// per-region subkey for `(path, id)` succeeds.
    Ciphertext,
    /// Anything else (raw text, base64 of something else, invalid
    /// base64, or the literal `[encrypted]` placeholder). On write the
    /// placeholder special-cases through prior-tip re-embedding;
    /// everything else is freshly encrypted.
    Plaintext,
}

/// Closed enum — extension dispatch lives in [`parser_for`]. YAML / JSON
/// / source-code variants land in future slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionParser {
    Markdown,
    Toml,
    PlainText,
}

#[derive(Debug, Error)]
pub enum RegionParseError {
    #[error("vault id {0:?} repeated within file")]
    DuplicateId(String),
    #[error("vault region {0:?} nests inside another region")]
    Nested(String),
    #[error("vault region {0:?} missing closing </vault> tag")]
    MissingClosingTag(String),
    #[error("vault id {0:?} contains invalid characters or exceeds {REGION_ID_MAX} bytes")]
    InvalidId(String),
    #[error("vault open tag missing or empty id")]
    EmptyId,
    /// Write-path only — a body equal to the literal `[encrypted]`
    /// referred to an id with no prior commit. Folded into
    /// `MalformedVaultTag` at the IPC boundary per the M2c open-question
    /// 4 lean (keeps the IPC error enum lean).
    #[error("vault placeholder for unknown id {0:?} (no prior ciphertext to re-embed)")]
    PlaceholderForUnknownId(String),
}

/// Extension dispatch. Falls through to PlainText for anything we don't
/// recognize (binary files pass through unchanged because the parser
/// UTF-8-sniffs the first bytes and emits no spans on non-UTF-8 input).
pub fn parser_for(path: &str) -> RegionParser {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some("md") => RegionParser::Markdown,
        Some("toml") => RegionParser::Toml,
        _ => RegionParser::PlainText,
    }
}

/// Parse `content` for inline `<vault>` regions under the dispatch of
/// `parser`. The `session` + `path` are used to disambiguate
/// Plaintext vs Ciphertext by trial-decrypting each body's base64 under
/// the per-region subkey for `(path, id)`.
///
/// Returns an empty span list when:
/// * `content` is not UTF-8 (binary file — silently pass-through),
/// * the parser found no `<vault ` open tags at all.
pub fn parse(
    parser: RegionParser,
    content: &[u8],
    session: &VaultSession,
    path: &str,
) -> Result<Vec<RegionSpan>, RegionParseError> {
    if std::str::from_utf8(content).is_err() {
        return Ok(Vec::new());
    }
    let allow = match parser {
        RegionParser::Markdown => compute_markdown_mask(content),
        RegionParser::Toml => compute_toml_mask(content),
        RegionParser::PlainText => vec![true; content.len()],
    };
    scan_regions(content, &allow, session, path)
}

/// `[malformed vault tag in <path>]\n` placeholder used on the read path
/// when [`parse`] returns an error.
pub fn malformed_placeholder(path: &str) -> Vec<u8> {
    format!("[malformed vault tag in {path}]\n").into_bytes()
}

/// Pure helper: apply byte-range substitutions to `content`. Ranges may
/// be supplied in any order; the helper sorts by start descending so
/// earlier replacements don't shift later byte indices. Substituted
/// bytes do not have to match the original range's length.
pub fn with_substitutions(content: Vec<u8>, subs: &[(Range<usize>, Vec<u8>)]) -> Vec<u8> {
    let mut ordered: Vec<(Range<usize>, &[u8])> =
        subs.iter().map(|(r, v)| (r.clone(), v.as_slice())).collect();
    ordered.sort_by_key(|(r, _)| std::cmp::Reverse(r.start));
    let mut out = content;
    for (range, repl) in ordered {
        out.splice(range, repl.iter().copied());
    }
    out
}

/// Build a Vec<u8> for the read view: tag bytes + body replaced with
/// [`ENCRYPTED_PLACEHOLDER`] for every Ciphertext span; Plaintext
/// spans pass through unchanged (they'll be encrypted on the next
/// write).
pub fn render_read_view(content: Vec<u8>, spans: &[RegionSpan]) -> Vec<u8> {
    let subs: Vec<(Range<usize>, Vec<u8>)> = spans
        .iter()
        .filter(|s| s.kind == RegionKind::Ciphertext)
        .map(|s| (s.body_byte_range.clone(), ENCRYPTED_PLACEHOLDER.to_vec()))
        .collect();
    with_substitutions(content, &subs)
}

/// Build the post-substitution bytes for the write path. The output is
/// the file's content with every region body finalized as base64-
/// ciphertext — ready to feed into Layer A encryption as a single blob.
///
/// * Ciphertext span → pass through (the body already decrypts cleanly,
///   so it round-trips a daemon-side re-emit).
/// * Plaintext span whose body equals [`ENCRYPTED_PLACEHOLDER`] →
///   re-embed the prior commit's ciphertext for the same `id`. If the
///   prior commit had no matching `id`, returns
///   [`RegionParseError::PlaceholderForUnknownId`].
/// * Plaintext span otherwise → fresh per-region encrypt + base64
///   inline embed.
pub fn apply_write_path(
    content: &[u8],
    spans: &[RegionSpan],
    path: &str,
    session: &VaultSession,
    prior_content: Option<&[u8]>,
    prior_spans: &[RegionSpan],
) -> Result<Vec<u8>, RegionParseError> {
    let mut subs: Vec<(Range<usize>, Vec<u8>)> = Vec::with_capacity(spans.len());
    for span in spans {
        match span.kind {
            RegionKind::Ciphertext => {
                // Pass-through; nothing to substitute.
            }
            RegionKind::Plaintext => {
                let body = &content[span.body_byte_range.clone()];
                if body == ENCRYPTED_PLACEHOLDER {
                    let prior = prior_content
                        .and_then(|pc| {
                            prior_spans
                                .iter()
                                .find(|s| s.id == span.id)
                                .map(|s| pc[s.body_byte_range.clone()].to_vec())
                        })
                        .ok_or_else(|| {
                            RegionParseError::PlaceholderForUnknownId(span.id.clone())
                        })?;
                    subs.push((span.body_byte_range.clone(), prior));
                } else {
                    let ct = session
                        .encrypt_layer_b_region(path, &span.id, body)
                        .map_err(|_| {
                            RegionParseError::InvalidId(format!(
                                "encrypt failed for id {:?}",
                                span.id
                            ))
                        })?;
                    let b64 = B64.encode(ct).into_bytes();
                    subs.push((span.body_byte_range.clone(), b64));
                }
            }
        }
    }
    Ok(with_substitutions(content.to_vec(), &subs))
}

// --- internal byte scanner ----------------------------------------------

fn scan_regions(
    content: &[u8],
    allow: &[bool],
    session: &VaultSession,
    path: &str,
) -> Result<Vec<RegionSpan>, RegionParseError> {
    let mut spans: Vec<RegionSpan> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cursor = 0usize;
    while let Some(open) = next_open_tag(content, cursor) {
        // Open-tag position must be in an allowed (non-fenced /
        // in-string for TOML) byte position. If not, skip past it.
        if !is_allowed(allow, open.open_start) {
            cursor = open.open_start + 1;
            continue;
        }
        validate_id(&open.id)?;
        if !seen_ids.insert(open.id.clone()) {
            return Err(RegionParseError::DuplicateId(open.id.clone()));
        }
        let close = next_close_tag(content, open.body_start);
        let Some(close) = close else {
            return Err(RegionParseError::MissingClosingTag(open.id.clone()));
        };
        if !is_allowed(allow, close.start) {
            return Err(RegionParseError::MissingClosingTag(open.id.clone()));
        }
        // No nested open tag inside this region's body.
        if let Some(inner) = next_open_tag(content, open.body_start) {
            if inner.open_start < close.start {
                return Err(RegionParseError::Nested(inner.id));
            }
        }
        let body_range = open.body_start..close.start;
        let kind = classify_body(&content[body_range.clone()], session, path, &open.id);
        spans.push(RegionSpan {
            id: open.id,
            body_byte_range: body_range,
            kind,
        });
        cursor = close.end;
    }
    Ok(spans)
}

#[derive(Debug)]
struct OpenTag {
    open_start: usize,
    body_start: usize,
    id: String,
}

#[derive(Debug)]
struct CloseTag {
    start: usize,
    end: usize,
}

fn next_open_tag(content: &[u8], from: usize) -> Option<OpenTag> {
    let needle = b"<vault ";
    let mut i = from;
    while i + needle.len() <= content.len() {
        if &content[i..i + needle.len()] == needle {
            let attr_start = i + needle.len();
            // v1 accepts only `id="…"` immediately after `<vault `.
            // Whitespace tolerance / attribute reorder is a future polish.
            if content.get(attr_start..attr_start + 4) == Some(b"id=\"") {
                let id_start = attr_start + 4;
                if let Some(end_quote_rel) =
                    content[id_start..].iter().position(|&b| b == b'"')
                {
                    let id_bytes = &content[id_start..id_start + end_quote_rel];
                    let after_quote = id_start + end_quote_rel + 1;
                    if content.get(after_quote) == Some(&b'>') {
                        if let Ok(id) = std::str::from_utf8(id_bytes) {
                            return Some(OpenTag {
                                open_start: i,
                                body_start: after_quote + 1,
                                id: id.to_string(),
                            });
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn next_close_tag(content: &[u8], from: usize) -> Option<CloseTag> {
    let needle = b"</vault>";
    let mut i = from;
    while i + needle.len() <= content.len() {
        if &content[i..i + needle.len()] == needle {
            return Some(CloseTag {
                start: i,
                end: i + needle.len(),
            });
        }
        i += 1;
    }
    None
}

fn validate_id(id: &str) -> Result<(), RegionParseError> {
    if id.is_empty() {
        return Err(RegionParseError::EmptyId);
    }
    if id.len() > REGION_ID_MAX {
        return Err(RegionParseError::InvalidId(id.to_string()));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(RegionParseError::InvalidId(id.to_string()));
    }
    Ok(())
}

fn classify_body(body: &[u8], session: &VaultSession, path: &str, id: &str) -> RegionKind {
    // Strict base64: STANDARD alphabet, padding required, no whitespace.
    // The decode call already rejects whitespace; we additionally check
    // that the body is not the literal placeholder so a freshly-typed
    // `[encrypted]` doesn't accidentally trial-decrypt.
    if body == ENCRYPTED_PLACEHOLDER {
        return RegionKind::Plaintext;
    }
    let Ok(bytes) = B64.decode(body) else {
        return RegionKind::Plaintext;
    };
    match session.decrypt_layer_b_region(path, id, &bytes) {
        Ok(_) => RegionKind::Ciphertext,
        Err(_) => RegionKind::Plaintext,
    }
}

fn is_allowed(allow: &[bool], byte_offset: usize) -> bool {
    allow.get(byte_offset).copied().unwrap_or(false)
}

// --- per-format byte masks ----------------------------------------------

pub(crate) fn compute_markdown_mask(content: &[u8]) -> Vec<bool> {
    let mut out = vec![false; content.len()];
    let mut in_fence = false;
    let mut line_start = 0usize;
    while line_start <= content.len() {
        let rel = content[line_start..].iter().position(|&b| b == b'\n');
        let (line_end, has_newline) = match rel {
            Some(p) => (line_start + p, true),
            None => (content.len(), false),
        };
        let line = &content[line_start..line_end];
        let trimmed = strip_leading_spaces(line);
        let toggles = trimmed.starts_with(b"```");
        // The fence line itself is part of the code block (not
        // available for vault tags).
        let line_in_fence = in_fence || toggles;
        if line_in_fence {
            // Whole line is fenced code — nothing here is a real tag.
            // (`out` is pre-zeroed, so the bytes stay disallowed.)
        } else {
            // Outside any fenced block: also disallow inline backtick
            // code spans, so documentation that mentions `<vault …>` in
            // backticks isn't parsed as a real region. Inline spans are
            // line-scoped (a v1 simplification mirroring the fenced-only
            // line-aware design): a backtick run opens a span, a run of
            // the same length closes it, and any leftover open span is
            // dropped at the newline.
            let mut inline_run: Option<usize> = None;
            let mut j = line_start;
            while j < line_end {
                if content[j] == b'`' {
                    let run_start = j;
                    while j < line_end && content[j] == b'`' {
                        j += 1;
                    }
                    // Backtick delimiters are never tag bytes; leave them
                    // disallowed and toggle the span state.
                    let run_len = j - run_start;
                    match inline_run {
                        None => inline_run = Some(run_len),
                        Some(open) if open == run_len => inline_run = None,
                        Some(_) => { /* mismatched run stays inside the span */ }
                    }
                } else {
                    out[j] = inline_run.is_none();
                    j += 1;
                }
            }
        }
        if has_newline {
            out[line_end] = !line_in_fence;
        }
        if toggles {
            in_fence = !in_fence;
        }
        if !has_newline {
            break;
        }
        line_start = line_end + 1;
    }
    out
}

/// State of the line-and-string-aware TOML scan used by
/// [`compute_toml_mask`]. Only [`Comment`](TomlScan::Comment) bytes are
/// disallowed; the string states exist solely so a `#` *inside* a string
/// isn't mistaken for a comment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TomlScan {
    Normal,
    Comment,
    Basic,     // "…"
    Literal,   // '…'
    MlBasic,   // """…"""
    MlLiteral, // '''…'''
}

fn compute_toml_mask(content: &[u8]) -> Vec<bool> {
    // Non-UTF-8 → no regions (binary pass-through, matching `parse`).
    if std::str::from_utf8(content).is_err() {
        return vec![false; content.len()];
    }
    // v1 model: allow the raw-bytes scan over the whole document (so
    // `<vault>` tags inside literal/basic string values are still
    // detected without per-string span translation) EXCEPT inside `#`
    // comments. A `#` outside any string starts a comment to end of
    // line; those bytes are masked so prose that documents a
    // `<vault …>` tag in a comment isn't parsed as a real region — the
    // TOML analog of the markdown inline-code / fenced-block exemption.
    // This runs even on syntactically invalid TOML per the
    // open-question-3 lean: a half-edited file shouldn't lose redaction
    // (so the mask is hand-rolled rather than gated on a toml parse).
    //
    // Known v1 limitation (additive fix in a later slice): `<vault>`
    // tags inside basic strings with `\"` escapes are NOT found (the
    // literal `<vault id="…">` byte sequence is not present in the file
    // in that case).
    let mut out = vec![true; content.len()];
    let mut state = TomlScan::Normal;
    let mut i = 0usize;
    while i < content.len() {
        let b = content[i];
        match state {
            TomlScan::Normal => match b {
                b'#' => {
                    out[i] = false;
                    state = TomlScan::Comment;
                    i += 1;
                }
                b'"' if content[i + 1..].starts_with(b"\"\"") => {
                    state = TomlScan::MlBasic;
                    i += 3;
                }
                b'"' => {
                    state = TomlScan::Basic;
                    i += 1;
                }
                b'\'' if content[i + 1..].starts_with(b"''") => {
                    state = TomlScan::MlLiteral;
                    i += 3;
                }
                b'\'' => {
                    state = TomlScan::Literal;
                    i += 1;
                }
                _ => i += 1,
            },
            TomlScan::Comment => {
                if b == b'\n' {
                    // The newline ends the comment and is not part of it.
                    state = TomlScan::Normal;
                } else {
                    out[i] = false;
                }
                i += 1;
            }
            TomlScan::Basic => match b {
                b'\\' => i += 2, // escape: skip the escaped byte
                b'"' => {
                    state = TomlScan::Normal;
                    i += 1;
                }
                // A single-line string can't span a newline; recover so a
                // stray quote doesn't swallow the rest of the file.
                b'\n' => {
                    state = TomlScan::Normal;
                    i += 1;
                }
                _ => i += 1,
            },
            TomlScan::Literal => match b {
                b'\'' | b'\n' => {
                    state = TomlScan::Normal;
                    i += 1;
                }
                _ => i += 1,
            },
            TomlScan::MlBasic => {
                if b == b'\\' {
                    i += 2; // escape (incl. line-ending backslash)
                } else if b == b'"' && content[i..].starts_with(b"\"\"\"") {
                    state = TomlScan::Normal;
                    i += 3;
                } else {
                    i += 1;
                }
            }
            TomlScan::MlLiteral => {
                if b == b'\'' && content[i..].starts_with(b"'''") {
                    state = TomlScan::Normal;
                    i += 3;
                } else {
                    i += 1;
                }
            }
        }
    }
    out
}

fn strip_leading_spaces(line: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < line.len() && line[i] == b' ' {
        i += 1;
    }
    &line[i..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_vault::{params::VaultParams, Vault};

    const PASS: &str = "test-pass";

    fn fast_params() -> VaultParams {
        let mut p = VaultParams::default();
        p.argon2.m_cost = 8;
        p.argon2.t_cost = 1;
        p.argon2.p_cost = 1;
        p
    }

    fn fresh_session() -> softfig_vault::VaultSession {
        let tmp = tempfile::tempdir().unwrap();
        let (_v, session, _r) =
            Vault::init_with_params(tmp.path(), PASS.as_bytes(), fast_params()).unwrap();
        // Leak the tempdir so the session's vault stays valid for the
        // test (the session itself owns no file handles after unlock,
        // but a future refactor could).
        std::mem::forget(tmp);
        session
    }

    #[test]
    fn parser_for_dispatch() {
        assert_eq!(parser_for("readme.md"), RegionParser::Markdown);
        assert_eq!(parser_for("a/b/secrets.toml"), RegionParser::Toml);
        assert_eq!(parser_for("script.sh"), RegionParser::PlainText);
        assert_eq!(parser_for("no-extension"), RegionParser::PlainText);
    }

    #[test]
    fn plain_text_finds_single_region() {
        let session = fresh_session();
        let body = b"hello <vault id=\"foo\">SECRET</vault> world";
        let spans = parse(RegionParser::PlainText, body, &session, "x.txt").unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].id, "foo");
        assert_eq!(&body[spans[0].body_byte_range.clone()], b"SECRET");
        assert_eq!(spans[0].kind, RegionKind::Plaintext);
    }

    #[test]
    fn markdown_skips_fenced_code_block() {
        let session = fresh_session();
        let body = b"prose\n\n```\n<vault id=\"foo\">SECRET</vault>\n```\n\n<vault id=\"bar\">OPEN</vault>\n";
        let spans = parse(RegionParser::Markdown, body, &session, "x.md").unwrap();
        assert_eq!(spans.len(), 1, "fenced tag should be skipped; got {spans:?}");
        assert_eq!(spans[0].id, "bar");
    }

    #[test]
    fn markdown_skips_inline_code_span() {
        let session = fresh_session();
        // A tag inside an inline backtick span is documentation, not a
        // region; a bare tag on the same line still parses.
        let body = b"docs: `<vault id=\"foo\">SECRET</vault>` then <vault id=\"bar\">OPEN</vault>\n";
        let spans = parse(RegionParser::Markdown, body, &session, "x.md").unwrap();
        assert_eq!(spans.len(), 1, "inline-code tag should be skipped; got {spans:?}");
        assert_eq!(spans[0].id, "bar");
    }

    #[test]
    fn inline_code_documentation_does_not_brick_file() {
        // Regression: the default-garden CLAUDE.md documents the vault
        // syntax inline as `<vault id="…">…</vault>` (ellipsis id). Before
        // inline-code masking this poisoned `validate_id` and failed the
        // whole file closed to `[malformed vault tag in …]`.
        let session = fresh_session();
        let body =
            "5. **No secrets in plaintext.** … inline `<vault id=\"…\">…</vault>` tags).\n"
                .as_bytes();
        let spans = parse(RegionParser::Markdown, body, &session, "CLAUDE.md")
            .expect("inline-code vault docs must not error");
        assert!(spans.is_empty(), "documentation mention must yield no regions; got {spans:?}");
    }

    #[test]
    fn toml_accepts_literal_multiline_body() {
        let session = fresh_session();
        let body = b"api_key = '''<vault id=\"foo\">SECRET</vault>'''\n";
        let spans = parse(RegionParser::Toml, body, &session, "x.toml").unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].id, "foo");
    }

    #[test]
    fn toml_skips_comment_tag() {
        let session = fresh_session();
        // A `<vault>` tag inside a `#` comment is documentation, not a
        // region; a real region in a string value still parses.
        let body = b"# docs: <vault id=\"doc\">x</vault>\napi = '''<vault id=\"real\">SECRET</vault>'''\n";
        let spans = parse(RegionParser::Toml, body, &session, "x.toml").unwrap();
        assert_eq!(spans.len(), 1, "comment tag should be skipped; got {spans:?}");
        assert_eq!(spans[0].id, "real");
    }

    #[test]
    fn toml_hash_inside_string_is_not_a_comment() {
        let session = fresh_session();
        // The `#` lives inside a literal string, so it does NOT start a
        // comment — the region embedded after it must still be found.
        let body = b"note = 'see # <vault id=\"x\">SECRET</vault> here'\n";
        let spans = parse(RegionParser::Toml, body, &session, "x.toml").unwrap();
        assert_eq!(spans.len(), 1, "in-string `#` must not mask the region; got {spans:?}");
        assert_eq!(spans[0].id, "x");
    }

    #[test]
    fn toml_comment_documentation_does_not_brick_file() {
        // Regression mirroring the markdown case: a comment documenting
        // the vault syntax with an ellipsis id must not fail the file
        // closed to `[malformed vault tag in …]`.
        let session = fresh_session();
        let body =
            "# wrap a value as `<vault id=\"…\">…</vault>` (region-level seal)\nkey = \"plain\"\n"
                .as_bytes();
        let spans = parse(RegionParser::Toml, body, &session, "secrets.toml")
            .expect("commented vault docs must not error");
        assert!(spans.is_empty(), "comment mention must yield no regions; got {spans:?}");
    }

    #[test]
    fn duplicate_id_rejected() {
        let session = fresh_session();
        let body = b"<vault id=\"a\">x</vault>\n<vault id=\"a\">y</vault>\n";
        let err = parse(RegionParser::PlainText, body, &session, "x.txt").unwrap_err();
        assert!(matches!(err, RegionParseError::DuplicateId(s) if s == "a"));
    }

    #[test]
    fn missing_close_rejected() {
        let session = fresh_session();
        let body = b"<vault id=\"a\">x";
        let err = parse(RegionParser::PlainText, body, &session, "x.txt").unwrap_err();
        assert!(matches!(err, RegionParseError::MissingClosingTag(s) if s == "a"));
    }

    #[test]
    fn nested_tags_rejected() {
        let session = fresh_session();
        let body = b"<vault id=\"outer\"><vault id=\"inner\">x</vault></vault>";
        let err = parse(RegionParser::PlainText, body, &session, "x.txt").unwrap_err();
        assert!(matches!(err, RegionParseError::Nested(s) if s == "inner"));
    }

    #[test]
    fn invalid_id_rejected() {
        let session = fresh_session();
        let body = b"<vault id=\"bad id\">x</vault>";
        let err = parse(RegionParser::PlainText, body, &session, "x.txt").unwrap_err();
        assert!(matches!(err, RegionParseError::InvalidId(_)));
    }

    #[test]
    fn empty_id_rejected() {
        let session = fresh_session();
        let body = b"<vault id=\"\">x</vault>";
        let err = parse(RegionParser::PlainText, body, &session, "x.txt").unwrap_err();
        assert!(matches!(err, RegionParseError::EmptyId));
    }

    #[test]
    fn non_utf8_passes_through() {
        let session = fresh_session();
        let body: &[u8] = &[0xFF, 0xFE, 0xFD];
        let spans = parse(RegionParser::PlainText, body, &session, "x.bin").unwrap();
        assert!(spans.is_empty());
    }

    #[test]
    fn classify_ciphertext_round_trip() {
        let session = fresh_session();
        // Encrypt under the region subkey, then base64-embed; the
        // parser should recognize this as Ciphertext.
        let ct = session
            .encrypt_layer_b_region("notes/x.md", "k", b"secret-value")
            .unwrap();
        let b64 = B64.encode(&ct);
        let body = format!("hello <vault id=\"k\">{b64}</vault> world");
        let spans =
            parse(RegionParser::Markdown, body.as_bytes(), &session, "notes/x.md").unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].kind, RegionKind::Ciphertext);
    }

    #[test]
    fn with_substitutions_handles_descending_order() {
        let content = b"AAAA__BBBB__CCCC".to_vec();
        let subs = vec![
            (4..6, b"xx".to_vec()),
            (10..12, b"yy".to_vec()),
        ];
        let out = with_substitutions(content, &subs);
        assert_eq!(out, b"AAAAxxBBBByyCCCC");
    }

    #[test]
    fn render_read_view_replaces_ciphertext_bodies_only() {
        let session = fresh_session();
        let ct = session.encrypt_layer_b_region("x.md", "k", b"hi").unwrap();
        let b64 = B64.encode(&ct);
        let body = format!("a <vault id=\"k\">{b64}</vault> b <vault id=\"j\">raw</vault>");
        let spans = parse(RegionParser::PlainText, body.as_bytes(), &session, "x.md").unwrap();
        let view = render_read_view(body.into_bytes(), &spans);
        let s = String::from_utf8(view).unwrap();
        assert!(s.contains("<vault id=\"k\">[encrypted]</vault>"), "{s}");
        assert!(s.contains("<vault id=\"j\">raw</vault>"), "{s}");
    }

    #[test]
    fn apply_write_path_re_embeds_placeholder_from_prior() {
        let session = fresh_session();
        let ct = session.encrypt_layer_b_region("x.md", "k", b"secret").unwrap();
        let b64 = B64.encode(&ct);
        let prior_text = format!("<vault id=\"k\">{b64}</vault>");
        let new_text = b"<vault id=\"k\">[encrypted]</vault>";

        let prior_spans =
            parse(RegionParser::PlainText, prior_text.as_bytes(), &session, "x.md").unwrap();
        let new_spans =
            parse(RegionParser::PlainText, new_text, &session, "x.md").unwrap();

        let out = apply_write_path(
            new_text,
            &new_spans,
            "x.md",
            &session,
            Some(prior_text.as_bytes()),
            &prior_spans,
        )
        .unwrap();
        assert_eq!(out, prior_text.as_bytes());
    }

    #[test]
    fn apply_write_path_encrypts_fresh_plaintext() {
        let session = fresh_session();
        let new_text = b"<vault id=\"k\">SECRET</vault>";
        let new_spans =
            parse(RegionParser::PlainText, new_text, &session, "x.md").unwrap();
        let out = apply_write_path(new_text, &new_spans, "x.md", &session, None, &[]).unwrap();
        // The body should now be base64 of a layer_b blob.
        let s = std::str::from_utf8(&out).unwrap();
        let body_start = s.find("\">").unwrap() + 2;
        let body_end = s.find("</vault>").unwrap();
        let body = &s[body_start..body_end];
        let ct = B64.decode(body).unwrap();
        let pt = session.decrypt_layer_b_region("x.md", "k", &ct).unwrap();
        assert_eq!(pt, b"SECRET");
    }

    #[test]
    fn apply_write_path_rejects_unknown_id_placeholder() {
        let session = fresh_session();
        let new_text = b"<vault id=\"k\">[encrypted]</vault>";
        let new_spans =
            parse(RegionParser::PlainText, new_text, &session, "x.md").unwrap();
        let err = apply_write_path(new_text, &new_spans, "x.md", &session, None, &[])
            .unwrap_err();
        assert!(matches!(
            err,
            RegionParseError::PlaceholderForUnknownId(ref s) if s == "k"
        ));
    }
}
