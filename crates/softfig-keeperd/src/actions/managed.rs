//! Pure managed-region machinery — daemon-owned blocks inside otherwise
//! hand-authored markdown, delimited by HTML-comment markers the daemon
//! regenerates in place. Slice 4 (index tables) and slice 5 (backlinks) of
//! the small-files redesign both build on this.
//!
//! A region is addressed by a `tag` (e.g. `index notes`, `backlinks`):
//!
//! ```text
//! <!-- softfig:index notes -->
//!
//! ...daemon-generated body...
//!
//! <!-- /softfig:index notes -->
//! ```
//!
//! Marker lines are HTML comments (invisible when rendered) matched by their
//! trimmed text. Everything outside the region is byte-preserved across an
//! `upsert`/`remove` — the same `split('\n')` / `join("\n")` round-trip
//! invariant `sections.rs` relies on. The region body is wrapped in one
//! blank line on each side so the markdown inside still renders.

/// Open marker line text for `tag`, e.g. `<!-- softfig:index notes -->`.
pub fn open_marker(tag: &str) -> String {
    format!("<!-- softfig:{tag} -->")
}

/// Close marker line text for `tag`, e.g. `<!-- /softfig:index notes -->`.
pub fn close_marker(tag: &str) -> String {
    format!("<!-- /softfig:{tag} -->")
}

/// Locate the `(open_line, close_line)` indices of the region tagged `tag`
/// in `lines` (0-based, the marker lines themselves). `None` unless a
/// well-formed open line is followed by a matching close line.
fn locate(lines: &[&str], tag: &str) -> Option<(usize, usize)> {
    let open = open_marker(tag);
    let close = close_marker(tag);
    let open_idx = lines.iter().position(|l| l.trim() == open)?;
    let close_idx = lines[open_idx + 1..]
        .iter()
        .position(|l| l.trim() == close)
        .map(|rel| open_idx + 1 + rel)?;
    Some((open_idx, close_idx))
}

/// Whether `content` already hosts a region tagged `tag`.
pub fn has_region(content: &str, tag: &str) -> bool {
    locate(&content.split('\n').collect::<Vec<_>>(), tag).is_some()
}

/// Insert or replace the region `tag` so its inner body is exactly `body`
/// (which must not contain the marker lines and carries no surrounding
/// newlines). Present → swap the inner lines, keeping the markers in place.
/// Absent → append `\n\n<open>\n\n<body>\n\n<close>\n` at end-of-doc.
pub fn upsert(content: &str, tag: &str, body: &str) -> String {
    let lines: Vec<&str> = content.split('\n').collect();
    let body_lines = body.split('\n').map(str::to_string);
    if let Some((open_idx, close_idx)) = locate(&lines, tag) {
        let mut out: Vec<String> = lines[..=open_idx].iter().map(|s| s.to_string()).collect();
        out.push(String::new());
        out.extend(body_lines);
        out.push(String::new());
        out.extend(lines[close_idx..].iter().map(|s| s.to_string()));
        out.join("\n")
    } else {
        let core = content.trim_end_matches('\n');
        let mut s = String::new();
        if !core.is_empty() {
            s.push_str(core);
            s.push_str("\n\n");
        }
        s.push_str(&open_marker(tag));
        s.push_str("\n\n");
        s.push_str(body);
        s.push_str("\n\n");
        s.push_str(&close_marker(tag));
        s.push('\n');
        s
    }
}

/// Drop the region `tag` (markers included) if present, collapsing one
/// adjacent blank separator so removal leaves no double gap. No-op when the
/// region is absent.
pub fn remove(content: &str, tag: &str) -> String {
    let lines: Vec<&str> = content.split('\n').collect();
    let Some((open_idx, close_idx)) = locate(&lines, tag) else {
        return content.to_string();
    };
    let mut start = open_idx;
    let mut end = close_idx + 1; // exclusive
    // Swallow one blank separator — prefer the one before the region, else
    // the one after — so the surrounding text keeps its single blank gap.
    if start > 0 && lines[start - 1].trim().is_empty() {
        start -= 1;
    } else if end < lines.len() && lines[end].trim().is_empty() {
        end += 1;
    }
    let mut out: Vec<String> = lines[..start].iter().map(|s| s.to_string()).collect();
    out.extend(lines[end..].iter().map(|s| s.to_string()));
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = "index notes";
    const TABLE: &str = "| # | Note |\n|---|------|\n| 001 | [x](notes/001-x.md) |";

    #[test]
    fn markers_are_html_comments() {
        assert_eq!(open_marker(TAG), "<!-- softfig:index notes -->");
        assert_eq!(close_marker(TAG), "<!-- /softfig:index notes -->");
    }

    #[test]
    fn upsert_appends_when_absent() {
        let doc = "# services/waydroid/\n\nrouting prose\n";
        let out = upsert(doc, TAG, TABLE);
        assert_eq!(
            out,
            "# services/waydroid/\n\nrouting prose\n\n\
             <!-- softfig:index notes -->\n\n\
             | # | Note |\n|---|------|\n| 001 | [x](notes/001-x.md) |\n\n\
             <!-- /softfig:index notes -->\n"
        );
        assert!(out.contains(&open_marker(TAG)) && out.contains(&close_marker(TAG)));
    }

    #[test]
    fn upsert_into_empty_doc_omits_leading_blank() {
        let out = upsert("", TAG, "BODY");
        assert_eq!(
            out,
            "<!-- softfig:index notes -->\n\nBODY\n\n<!-- /softfig:index notes -->\n"
        );
    }

    #[test]
    fn upsert_replaces_inner_body_only() {
        let doc = "# Doc\n\nlead\n\n\
                   <!-- softfig:index notes -->\n\nOLD\n\n<!-- /softfig:index notes -->\n\n\
                   ## Tail\n\ntail body\n";
        let out = upsert(doc, TAG, "NEW1\nNEW2");
        assert_eq!(
            out,
            "# Doc\n\nlead\n\n\
             <!-- softfig:index notes -->\n\nNEW1\nNEW2\n\n<!-- /softfig:index notes -->\n\n\
             ## Tail\n\ntail body\n"
        );
    }

    #[test]
    fn remove_drops_region_and_one_blank() {
        let doc = "# Doc\n\nbody\n\n\
                   <!-- softfig:index notes -->\n\nT\n\n<!-- /softfig:index notes -->\n";
        assert_eq!(remove(doc, TAG), "# Doc\n\nbody\n");
    }

    #[test]
    fn remove_is_noop_when_absent() {
        let doc = "# Doc\n\nno region\n";
        assert_eq!(remove(doc, TAG), doc);
    }

    #[test]
    fn upsert_then_remove_round_trips() {
        let doc = "# Doc\n\nbody\n";
        let with = upsert(doc, TAG, TABLE);
        assert_eq!(remove(&with, TAG), doc);
    }

    #[test]
    fn distinct_tags_coexist() {
        let doc = "# Doc\n\nbody\n";
        let a = upsert(doc, "index notes", "A");
        let b = upsert(&a, "index troubleshooting", "B");
        assert!(b.contains(&open_marker("index notes")));
        assert!(b.contains(&open_marker("index troubleshooting")));
        // Replacing one leaves the other untouched.
        let c = upsert(&b, "index notes", "A2");
        assert!(c.contains("A2"));
        assert!(c.contains("\nB\n"));
    }
}
