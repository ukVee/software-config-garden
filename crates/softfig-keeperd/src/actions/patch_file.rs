//! mcp-surgical-writes slice 002 — `patch_file`, the keystone surgical
//! mutation verb (spec: `meta/spec-mcp-writes/spec-patch-file.md`).
//!
//! Replace one exact occurrence of `old` with `new` in a garden file — the
//! opencode-Edit-tool model, keeperd-mediated. The middle band between the
//! coarse whole-file `replace_file` and the heading-addressed section verbs:
//! a caller emits only the irreducible old→new pair, never the surrounding
//! content.
//!
//! ## Find semantics
//!
//! Exact match only, no whitespace normalization — the caller holds ground
//! truth from its native read. `old` must occur **exactly once** within the
//! search window (the whole file, or the optional `anchor`'s line range):
//! zero → `TextNotFound`, several → `TextAmbiguous` (machine-distinct kinds —
//! an agent's retry strategy differs). `new` may be empty, the sanctioned
//! "delete this text" path (heading deletion is `remove_section`'s job; file
//! deletion is `unlink`'s).
//!
//! ## Guards (shared with the section verbs)
//!
//! Same write posture as `sections.rs`: `WorkTree` (mount-safe), vault
//! refusal via [`load_unprotected`](super::sections::load_unprotected) (a
//! plaintext rewrite must never clobber ciphertext), whole-file CAS via the
//! shared [`cas_check_whole_file`](crate::handlers::cas_check_whole_file)
//! (`patch` can span any byte range, so section-level CAS doesn't apply),
//! self-write suppression inside [`WorkTree::write`], backlink refresh
//! (a patch can add/remove `[[…]]` refs), exactly one `commit_now` with the
//! `text_patched` intent, and thrash registration with the editor identity
//! (whole-file target — `heading` is `None`, distinct from section targets).

use softfig_ipc::verbs::{PatchFileArgs, PatchFileReply};
use softfig_ipc::ErrorKind;
use softfig_vcs::Intent;

use super::sections::{edit, load_unprotected, note_edit_for_thrash, resolve};
use super::{commit_now, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{cas_check_whole_file, require_unlocked, HandlerResult};

pub fn patch_file(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: PatchFileArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("patch_file args: {e}")))?;
    if args.old.is_empty() {
        return Err((ErrorKind::BadArgs, "old must be non-empty".into()));
    }
    if args.anchor.as_deref().is_some_and(str::is_empty) {
        return Err((
            ErrorKind::BadArgs,
            "anchor must be non-empty when provided (omit it to search the whole file)".into(),
        ));
    }
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    let new_content = {
        let wt = WorkTree::new(daemon, &inner);
        let content = load_unprotected(&wt, &inner, &rel)?;
        cas_check_whole_file(&wt, &rel, &args.expected_version)?;
        core::patch(&content, &args.old, &args.new, args.anchor.as_deref())
            .map_err(|e| patch_err(&rel, &args.old, args.anchor.as_deref(), e))?
    };

    {
        let wt = WorkTree::new(daemon, &inner);
        wt.write(&rel, new_content.as_bytes())?;
        // A patch can add/remove `[[…]]` refs like any section edit, so keep
        // the backlink graph consistent before committing (best-effort).
        super::backlinks::refresh_all(&wt, &inner);
    }

    let version = edit::content_version(&new_content);
    let mut payload = serde_json::json!({ "path": rel });
    if let Some(summary) = preview(&args.new) {
        payload["summary"] = serde_json::json!(summary);
    }
    let intent = Intent::new("text_patched", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    let reply = serde_json::to_value(PatchFileReply {
        path: rel.clone(),
        hash: hash.to_string(),
        version,
    })
    .unwrap();
    note_edit_for_thrash(daemon, inner, &rel, None, args.editor.as_deref());
    Ok(reply)
}

/// Map a pure patch-core error onto the wire `(ErrorKind, message)` pair —
/// `pub(crate)` so the batch verb (slice 005) reuses the identical mapping for
/// its `patch_file` sub-ops instead of duplicating it.
pub(crate) fn patch_err(
    rel: &str,
    old: &str,
    anchor: Option<&str>,
    e: core::PatchError,
) -> (ErrorKind, String) {
    use core::PatchError::*;
    let snippet = |s: &str| -> String { s.chars().take(60).collect() };
    let old = snippet(old);
    match e {
        TextNotFound => (
            ErrorKind::TextNotFound,
            format!("{rel}: old text {old:?} not found in the search window"),
        ),
        TextAmbiguous => (
            ErrorKind::TextAmbiguous,
            format!(
                "{rel}: old text {old:?} occurs more than once in the search \
                 window — add an `anchor` to narrow it"
            ),
        ),
        AnchorNotFound => (
            ErrorKind::TextNotFound,
            format!("{rel}: anchor text {:?} not found in the file", snippet(anchor.unwrap_or(""))),
        ),
        AnchorAmbiguous => (
            ErrorKind::TextAmbiguous,
            format!(
                "{rel}: anchor text {:?} occurs more than once in the file",
                snippet(anchor.unwrap_or(""))
            ),
        ),
    }
}

/// The `text_patched` payload's `summary`: a ≤80-char first-line preview of
/// `new` (history readability), or `None` when `new` is blank — a deletion,
/// where the path alone says what happened.
fn preview(new: &str) -> Option<String> {
    let first = new.split('\n').next().unwrap_or("").trim();
    if first.is_empty() {
        return None;
    }
    let mut chars = first.chars();
    let mut out: String = chars.by_ref().take(79).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    Some(out)
}

// ---- pure patch core ----------------------------------------------------
//
// Split out so the find/replace semantics are exhaustively unit-testable
// without a daemon. Byte-exact: only the matched `old` range is rewritten,
// everything else round-trips verbatim.

pub mod core {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PatchError {
        /// `old` occurred zero times within the search window.
        TextNotFound,
        /// `old` occurred more than once within the search window.
        TextAmbiguous,
        /// The anchor string occurred zero times in the file.
        AnchorNotFound,
        /// The anchor string occurred more than once in the file.
        AnchorAmbiguous,
    }

    /// Replace the single occurrence of `old` with `new` inside the search
    /// window (the whole file, or `anchor`'s line range when given).
    ///
    /// `anchor` must occur exactly once in the file; its line range — the
    /// full line(s) it spans, terminators included — becomes the window
    /// `old` is searched in. `old` must occur exactly once (non-overlapping
    /// matches) within that window. `old` non-empty and `anchor` (when
    /// present) non-empty are enforced by the caller.
    pub fn patch(
        content: &str,
        old: &str,
        new: &str,
        anchor: Option<&str>,
    ) -> Result<String, PatchError> {
        let (window_start, window_end) = match anchor {
            None => (0, content.len()),
            Some(a) => {
                let start = content.find(a).ok_or(PatchError::AnchorNotFound)?;
                if content[start + a.len()..].contains(a) {
                    return Err(PatchError::AnchorAmbiguous);
                }
                let line_start = content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let line_end = match content[start + a.len()..].find('\n') {
                    Some(i) => start + a.len() + i + 1,
                    None => content.len(),
                };
                (line_start, line_end)
            }
        };

        let window = &content[window_start..window_end];
        let mut matches = window.match_indices(old);
        let Some((mstart, _)) = matches.next() else {
            return Err(PatchError::TextNotFound);
        };
        if matches.next().is_some() {
            return Err(PatchError::TextAmbiguous);
        }

        let abs_start = window_start + mstart;
        let abs_end = abs_start + old.len();
        let mut out = String::with_capacity(content.len() - old.len() + new.len());
        out.push_str(&content[..abs_start]);
        out.push_str(new);
        out.push_str(&content[abs_end..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::core::PatchError::*;
    use super::core::*;

    #[test]
    fn replaces_a_unique_single_line_occurrence() {
        let doc = "# T\n\nold line\n\nkeep me\n";
        assert_eq!(patch(doc, "old line", "new line", None).unwrap(),
                   "# T\n\nnew line\n\nkeep me\n");
    }

    #[test]
    fn replaces_a_unique_multi_line_occurrence() {
        let doc = "start\nfoo\nbar\nend\n";
        assert_eq!(
            patch(doc, "foo\nbar", "replaced", None).unwrap(),
            "start\nreplaced\nend\n"
        );
    }

    #[test]
    fn zero_and_multiple_occurrences() {
        let doc = "a b a b\n";
        assert_eq!(patch(doc, "zzz", "x", None), Err(TextNotFound));
        assert_eq!(patch(doc, "a", "x", None), Err(TextAmbiguous));
    }

    #[test]
    fn empty_new_deletes_the_matched_text() {
        let doc = "keep\nDELETE ME\nkeep\n";
        assert_eq!(patch(doc, "DELETE ME\n", "", None).unwrap(), "keep\nkeep\n");
    }

    #[test]
    fn untouched_regions_are_byte_identical() {
        let doc = "prefix with unicode ✓\nold\nsuffix\n";
        let out = patch(doc, "old", "new", None).unwrap();
        assert!(out.starts_with("prefix with unicode ✓\nnew\n"));
        assert!(out.ends_with("suffix\n"));
    }

    #[test]
    fn anchor_narrows_the_window_to_its_line_range() {
        // The anchor's line range is the window: a same-line unique marker
        // disambiguates the needle.
        let doc = "port = 8080 # staging\nport = 8080 # prod\n";
        assert_eq!(patch(doc, "port = 8080", "x", None), Err(TextAmbiguous));
        let out = patch(doc, "port = 8080", "port = 9090", Some("# prod")).unwrap();
        assert_eq!(out, "port = 8080 # staging\nport = 9090 # prod\n");

        // A multi-line anchor can span the target line to cover it.
        let doc2 = "## B\n\nvalue: one\n\n## C\n\nvalue: one\n";
        let out2 = patch(doc2, "value: one", "value: two", Some("## B\n\nvalue: one")).unwrap();
        assert_eq!(out2, "## B\n\nvalue: two\n\n## C\n\nvalue: one\n");
    }

    #[test]
    fn anchor_must_be_unique_in_the_file() {
        let doc = "tag\nbody\ntag\n";
        assert_eq!(patch(doc, "body", "x", Some("tag")), Err(AnchorAmbiguous));
        assert_eq!(patch(doc, "body", "x", Some("absent")), Err(AnchorNotFound));
    }

    #[test]
    fn a_multiline_anchor_windows_its_full_line_range() {
        let doc = "start\nanchor\ncontinued\noutside\nanchor\n";
        // anchor spans lines 2-3 (0-based 1-2); `outside` is not in the window.
        assert_eq!(
            patch(doc, "anchor\ncontinued", "A\nC", Some("anchor\ncontinued")).unwrap(),
            "start\nA\nC\noutside\nanchor\n"
        );
    }

    #[test]
    fn old_must_lie_entirely_inside_the_window() {
        // old straddles the anchor's window boundary (next line) → not found.
        let doc = "anchor line\nspill\n";
        assert_eq!(
            patch(doc, "anchor line\nspill", "x", Some("anchor line")),
            Err(TextNotFound)
        );
    }

    #[test]
    fn overlapping_needles_count_non_overlapping_matches() {
        // "aa" in "aaa" is one (non-overlapping) match → replaceable.
        assert_eq!(patch("aaa", "aa", "b", None).unwrap(), "ba");
    }

    #[test]
    fn multibyte_content_and_needles() {
        let doc = "ü line\nünïcode ✓ here\nend\n";
        let out = patch(doc, "ünïcode ✓", "replaced", None).unwrap();
        assert_eq!(out, "ü line\nreplaced here\nend\n");
    }

    #[test]
    fn preview_takes_the_first_line_truncated_to_80_chars() {
        use super::preview;
        assert_eq!(preview("one line\nsecond"), Some("one line".into()));
        assert_eq!(preview(""), None);
        assert_eq!(preview("\nsecond"), None);
        let long = "x".repeat(100);
        let p = preview(&long).unwrap();
        assert_eq!(p.chars().count(), 80);
        assert!(p.ends_with('…'));
        let exact = "y".repeat(79);
        assert_eq!(preview(&exact).unwrap(), exact, "79 chars: no ellipsis");
    }
}
