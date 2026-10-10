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
//! trimmed text, and only **outside fenced code blocks** — a spec doc that
//! shows the marker syntax in a ```` ``` ```` example is documenting a region,
//! not hosting one, so its example is never rewritten, preserved, or guarded
//! as daemon state. Everything outside the region is byte-preserved across an
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

/// One well-formed region: its tag and the line indices of its two marker
/// lines (0-based, inclusive).
pub struct Span {
    pub tag: String,
    pub open: usize,
    pub close: usize,
}

/// `true` for every line inside a fenced code block, fence lines included.
fn fence_mask(lines: &[&str]) -> Vec<bool> {
    let mut in_fence = false;
    lines
        .iter()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("```") || t.starts_with("~~~") {
                in_fence = !in_fence;
                true
            } else {
                in_fence
            }
        })
        .collect()
}

/// Every well-formed region in `lines`, in document order: an open marker
/// outside a fence, closed by the first matching close marker outside a
/// fence. An unterminated open marker isn't a region and is skipped; scanning
/// resumes after each region's close, so regions never nest. The one scanner
/// every other function here builds on, so they agree on what a region is.
pub fn spans_of(lines: &[&str]) -> Vec<Span> {
    let fenced = fence_mask(lines);
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(tag) = (!fenced[i]).then(|| open_tag(lines[i])).flatten() else {
            i += 1;
            continue;
        };
        let close = close_marker(&tag);
        let Some(j) = (i + 1..lines.len()).find(|&j| !fenced[j] && lines[j].trim() == close) else {
            i += 1;
            continue;
        };
        out.push(Span { tag, open: i, close: j });
        i = j + 1;
    }
    out
}

/// Locate the `(open_line, close_line)` indices of the region tagged `tag`
/// in `lines` (0-based, the marker lines themselves). `None` unless a
/// well-formed open line is followed by a matching close line.
fn locate(lines: &[&str], tag: &str) -> Option<(usize, usize)> {
    spans_of(lines)
        .into_iter()
        .find(|s| s.tag == tag)
        .map(|s| (s.open, s.close))
}

/// Whether `content` already hosts a region tagged `tag`.
pub fn has_region(content: &str, tag: &str) -> bool {
    locate(&content.split('\n').collect::<Vec<_>>(), tag).is_some()
}

/// Extract the inner body of region `tag` — the lines between the markers,
/// with the one blank pad line on each side stripped — as a `\n`-joined
/// string. `None` if the region is absent. The inverse of `upsert`'s body
/// argument, so a daemon-owned region can be parsed back into structured
/// state (e.g. the growlight queue table).
pub fn region_body(content: &str, tag: &str) -> Option<String> {
    let lines: Vec<&str> = content.split('\n').collect();
    let (open_idx, close_idx) = locate(&lines, tag)?;
    let mut body = &lines[open_idx + 1..close_idx];
    while body.first().is_some_and(|l| l.trim().is_empty()) {
        body = &body[1..];
    }
    while body.last().is_some_and(|l| l.trim().is_empty()) {
        body = &body[..body.len() - 1];
    }
    Some(body.join("\n"))
}

/// If `line` is a managed-region OPEN marker (`<!-- softfig:<tag> -->` — not
/// the `/` close form, not prose that merely mentions the syntax), its tag
/// text. `None` for a blank tag.
fn open_tag(line: &str) -> Option<String> {
    let t = line.trim();
    let tag = t.strip_prefix("<!-- softfig:")?.strip_suffix("-->")?;
    let tag = tag.trim();
    (!tag.is_empty()).then(|| tag.to_string())
}

/// The tag of the first well-formed managed region whose marker span
/// `[open, close + 1)` overlaps the caller's half-open `[start, end)` line
/// range — the cheap guard behind `remove_section`'s managed-region refusal
/// (deleting through an index table would silently drop daemon-owned
/// content). `None` when no region overlaps; an unterminated open marker
/// isn't a region and is skipped, like [`locate`].
pub fn overlapping_region(content: &str, start: usize, end: usize) -> Option<String> {
    let lines: Vec<&str> = content.split('\n').collect();
    spans_of(&lines)
        .into_iter()
        .find(|s| start < s.close + 1 && end > s.open)
        .map(|s| s.tag)
}

/// Enumerate every well-formed managed region as `(tag, body)` in document
/// order — the body with its one blank pad line on each side stripped (the
/// same trim as [`region_body`]). The `unlink` reference refusal scans
/// `index *` region bodies for a listing of the target path. An unterminated
/// open marker isn't a region and is skipped, like [`locate`].
pub fn regions(content: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = content.split('\n').collect();
    spans_of(&lines)
        .into_iter()
        .map(|s| {
            let mut body = &lines[s.open + 1..s.close];
            while body.first().is_some_and(|l| l.trim().is_empty()) {
                body = &body[1..];
            }
            while body.last().is_some_and(|l| l.trim().is_empty()) {
                body = &body[..body.len() - 1];
            }
            (s.tag, body.join("\n"))
        })
        .collect()
}

/// The tags whose region differs between `before` and `after` — a body that
/// changed, or a region present on one side only — in first-seen order. Empty
/// iff both carry the same regions with the same bodies in the same order.
///
/// The managed-region invariant behind every non-break-glass write verb
/// (`patch_file`, the section verbs, `batch`'s sub-ops): an edit may move text
/// around a region, never change one — its content belongs to the daemon
/// machinery that derives it (index, backlinks) or owns it (the growlight
/// queue tables). `replace_file` uses it the other way round, to report which
/// regions the daemon re-derived under a verbatim write.
pub fn changed_regions(before: &str, after: &str) -> Vec<String> {
    let (b, a) = (regions(before), regions(after));
    if b == a {
        return Vec::new();
    }
    let bodies = |rs: &[(String, String)], tag: &str| -> Vec<String> {
        rs.iter()
            .filter(|(t, _)| t == tag)
            .map(|(_, body)| body.clone())
            .collect()
    };
    let mut out: Vec<String> = Vec::new();
    for (tag, _) in b.iter().chain(a.iter()) {
        if !out.contains(tag) && bodies(&b, tag) != bodies(&a, tag) {
            out.push(tag.clone());
        }
    }
    if out.is_empty() {
        // Same bodies per tag, different order: every region moved.
        for (tag, _) in &b {
            if !out.contains(tag) {
                out.push(tag.clone());
            }
        }
    }
    out
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
    fn region_body_round_trips_upsert() {
        let doc = upsert("# Doc\n\nlead\n", TAG, TABLE);
        assert_eq!(region_body(&doc, TAG).as_deref(), Some(TABLE));
        assert_eq!(region_body("# Doc\n\nno region\n", TAG), None);
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

    #[test]
    fn open_tag_matches_open_markers_only() {
        assert_eq!(open_tag("<!-- softfig:index notes -->").as_deref(), Some("index notes"));
        assert_eq!(open_tag("  <!-- softfig:queue -->  ").as_deref(), Some("queue"));
        assert_eq!(open_tag("<!-- /softfig:index notes -->"), None);
        assert_eq!(open_tag("<!-- softfig: -->"), None);
        assert_eq!(open_tag("prose <!-- softfig:index notes --> inline"), None);
    }

    #[test]
    fn overlapping_region_detects_full_and_partial_overlaps() {
        // lines: 0 "# T", 1 "", 2 "body", 3 "", 4 open, 5 "", 6 "| # |",
        //        7 "", 8 close, 9 ""
        let doc = "# T\n\nbody\n\n<!-- softfig:index notes -->\n\n| # |\n\n<!-- /softfig:index notes -->\n";
        // Full containment of the region.
        assert_eq!(overlapping_region(doc, 3, 9).as_deref(), Some("index notes"));
        // Top-edge partial overlap.
        assert_eq!(overlapping_region(doc, 2, 5).as_deref(), Some("index notes"));
        // Bottom-edge partial overlap (deletes the close marker line).
        assert_eq!(overlapping_region(doc, 8, 10).as_deref(), Some("index notes"));
        // Clear of the region.
        assert_eq!(overlapping_region(doc, 0, 3), None);
        // Adjacent-but-disjoint ranges don't count.
        assert_eq!(overlapping_region(doc, 0, 4), None);
    }

    #[test]
    fn overlapping_region_ignores_unterminated_markers() {
        let doc = "# T\n\n<!-- softfig:index notes -->\n\nno close\n";
        assert_eq!(overlapping_region(doc, 0, 6), None);
    }

    /// A spec doc that *shows* the marker syntax in a fenced example hosts no
    /// region: it is neither enumerated, guarded, nor rewritten by `upsert`.
    #[test]
    fn markers_inside_fences_are_examples_not_regions() {
        let doc = "# Spec\n\n```text\n<!-- softfig:index notes -->\n\nEXAMPLE\n\n\
                   <!-- /softfig:index notes -->\n```\n\nprose\n";
        assert!(regions(doc).is_empty());
        assert_eq!(overlapping_region(doc, 0, 12), None);
        assert!(!has_region(doc, TAG));
        // upsert appends a real region instead of rewriting the example.
        let out = upsert(doc, TAG, "REAL");
        assert!(out.contains("EXAMPLE"), "{out}");
        assert_eq!(regions(&out), vec![(TAG.to_string(), "REAL".to_string())]);
    }

    #[test]
    fn changed_regions_names_edited_added_and_dropped_tags() {
        let base = upsert(&upsert("# D\n\nx\n", TAG, "A"), "queue", "Q");
        assert!(changed_regions(&base, &base).is_empty());
        // Prose around a region may move freely.
        let moved_prose = base.replace("x\n", "y\n");
        assert!(changed_regions(&base, &moved_prose).is_empty());
        // A body change names that tag only.
        let edited = upsert(&base, "queue", "Q2");
        assert_eq!(changed_regions(&base, &edited), vec!["queue".to_string()]);
        // Dropping or introducing a region names it.
        let dropped = remove(&base, TAG);
        assert_eq!(changed_regions(&base, &dropped), vec![TAG.to_string()]);
        assert_eq!(changed_regions(&dropped, &base), vec![TAG.to_string()]);
    }

    #[test]
    fn regions_enumerates_bodies_in_order() {
        let doc = "# D\n\n<!-- softfig:index notes -->\n\nA\n\n<!-- /softfig:index notes -->\n\n\
                   prose\n\n<!-- softfig:queue -->\n\n| r |\n\n<!-- /softfig:queue -->\n\
                   <!-- softfig:index notes -->\n\nunterminated\n";
        assert_eq!(
            regions(doc),
            vec![
                ("index notes".to_string(), "A".to_string()),
                ("queue".to_string(), "| r |".to_string()),
            ]
        );
        assert!(regions("# D\n\nno regions\n").is_empty());
    }
}
