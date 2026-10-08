//! Slice 5 of the small-files redesign — the `[[…]]` reference graph +
//! auto-maintained backlinks.
//!
//! A doc references another with a wiki-style token:
//!
//! * `[[NNN-slug]]` — a **sibling note**, resolved within the referencing
//!   doc's own accretive folder (`notes/` or `troubleshooting/`).
//! * `[[path/to/doc]]` — a **garden-relative path** (the `.md` suffix is
//!   optional), e.g. `[[journal/decisions/decision-no-git]]`.
//!
//! For every doc that is referenced, the daemon maintains a `softfig:backlinks`
//! managed region (reusing [`super::managed`]) listing the docs that link to
//! it. Because note titles/filenames are immutable, the only structural
//! mutation is **archive**, which rewrites inbound references to point at the
//! archived location so links never dangle.
//!
//! Triggers: the note lifecycle (`add_note` / `revise_note` / `archive`) and
//! section edits — every way a doc body's `[[…]]` set can change. The whole
//! graph is recomputed from a fresh walk each time (the garden is small);
//! only the target regions whose content actually changes are rewritten.
//! Refs authored through the other create-doc verbs (`log_decision`, …) are
//! eventually-consistent — picked up on the next lifecycle op, since the walk
//! scans every markdown source.
//!
//! Maintenance is **best-effort and secondary**, like the slice-4 index: a
//! vault-protected, unreadable, or non-UTF-8 doc is silently skipped, never
//! blocking the primary write. Tokens are parsed outside fenced/inline code
//! (reusing the markdown code-mask), so docs that merely *document* the
//! `[[…]]` syntax don't forge edges.

use std::collections::{BTreeMap, BTreeSet};

use crate::actions::{managed, WorkTree};
use crate::daemon::DaemonInner;

/// Managed-region tag for the backlinks block.
const BACKLINKS_TAG: &str = "backlinks";

// ---- daemon orchestration ---------------------------------------------

/// Recompute the whole backlink graph from a fresh walk and rewrite every
/// target region whose content changed. Folded into the caller's in-flight
/// commit. Best-effort: never errors. Every read/write goes through the
/// [`WorkTree`] — in FUSE mode this whole-garden walk runs against the
/// in-memory (tip ∪ overlay) state, not by recursively self-reading the mount
/// under `daemon.inner` (the 2026-06-21 deadlock's worst self-read).
pub fn refresh_all(wt: &WorkTree, inner: &DaemonInner) {
    let files = collect_md(wt);
    let exists = |rel: &str| wt.exists(rel) && !wt.is_dir(rel);

    // One read per readable, non-vault markdown file: collect its refs and
    // note whether it already hosts a backlinks region.
    let mut contents: BTreeMap<String, String> = BTreeMap::new();
    let mut current_hosts: BTreeSet<String> = BTreeSet::new();
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for rel in &files {
        let Some(content) = super::sections::read_if_unprotected(wt, inner, rel) else {
            continue;
        };
        if managed::has_region(&content, BACKLINKS_TAG) {
            current_hosts.insert(rel.clone());
        }
        for token in refs::parse_refs(&content) {
            if let Some(target) = refs::resolve_ref(rel, &token, &exists) {
                if !is_excluded(&target) {
                    graph.entry(target).or_default().insert(rel.clone());
                }
            }
        }
        contents.insert(rel.clone(), content);
    }

    // Targets to (re)write = referenced docs ∪ docs that currently host a
    // region (so a no-longer-referenced doc has its stale region dropped).
    let mut targets: BTreeSet<String> = graph.keys().cloned().collect();
    targets.extend(current_hosts);

    for target in targets {
        // Skip targets we couldn't read safely (vault-protected/unreadable);
        // they were never inserted into `contents`.
        let Some(content) = contents.get(&target) else {
            continue;
        };
        let new = match graph.get(&target) {
            Some(sources) => managed::upsert(content, BACKLINKS_TAG, &refs::render(sources)),
            None => managed::remove(content, BACKLINKS_TAG),
        };
        if &new != content {
            let _ = wt.write(&target, new.as_bytes());
        }
    }
}

/// Rewrite every inbound `[[…]]` reference that resolved to `src_rel` so it
/// points at `dst_rel` (the archived location), keeping links from dangling.
/// Call before [`refresh_all`] on archive. Best-effort.
pub fn rewrite_refs_to_archived(
    wt: &WorkTree,
    inner: &DaemonInner,
    src_rel: &str,
    dst_rel: &str,
) {
    for rel in collect_md(wt) {
        let Some(content) = super::sections::read_if_unprotected(wt, inner, &rel) else {
            continue;
        };
        if let Some(new) = refs::rewrite_to(&content, &rel, src_rel, dst_rel) {
            let _ = wt.write(&rel, new.as_bytes());
        }
    }
}

/// The sources that reference `rel` right now via a resolvable `[[…]]`
/// token — the `unlink` reference refusal's backlink arm. The target itself
/// is skipped as a source (a self-reference dies with the file). Sorted.
/// Whole-garden walk, best-effort like the maintenance itself: a
/// vault-protected or unreadable source is skipped, never blocking the
/// primary op.
pub fn inbound_refs(wt: &WorkTree, inner: &DaemonInner, rel: &str) -> Vec<String> {
    let exists = |r: &str| wt.exists(r) && !wt.is_dir(r);
    let mut out = Vec::new();
    for source in collect_md(wt) {
        if source == rel {
            continue;
        }
        let Some(content) = super::sections::read_if_unprotected(wt, inner, &source) else {
            continue;
        };
        if refs::parse_refs(&content)
            .iter()
            .any(|t| refs::resolve_ref(&source, t, &exists).as_deref() == Some(rel))
        {
            out.push(source);
        }
    }
    out.sort();
    out
}

/// Collect garden-relative paths of every `.md` file, skipping the
/// `journal/archive` graveyard and any dot-prefixed entry (`.softfig`,
/// `.git`, `.seq`, …). Symlinked dirs are not followed.
pub(crate) fn collect_md(wt: &WorkTree) -> Vec<String> {
    let mut out = Vec::new();
    walk(wt, "", &mut out);
    out
}

fn walk(wt: &WorkTree, dir_rel: &str, out: &mut Vec<String>) {
    for entry in wt.read_dir(dir_rel) {
        if entry.name.starts_with('.') {
            continue; // .softfig, .git, .seq, dotfiles
        }
        let rel = if dir_rel.is_empty() {
            entry.name.clone()
        } else {
            format!("{dir_rel}/{}", entry.name)
        };
        if entry.is_dir {
            if rel == "journal/archive"
                || rel == "growlight/baton-log"
                || rel == "growlight/chat"
            {
                // graveyard + the growlight audit log + the coordination bus:
                // never source nor target. The baton-log/chat are append-only,
                // high-churn coordination, so their `[[…]]` mentions must not
                // forge edges onto live item docs (chat is injected, not graphed).
                continue;
            }
            walk(wt, &rel, out);
        } else if entry.name.ends_with(".md") {
            out.push(rel);
        }
    }
}

/// Whether `rel` is excluded from being a backlink target (the archive
/// graveyard + the growlight baton-log + the coordination chat bus). Mirrors
/// the source-walk skip so an archived doc — or an audit-only baton entry, or a
/// chat message — never grows a region.
fn is_excluded(rel: &str) -> bool {
    rel == "journal/archive"
        || rel.starts_with("journal/archive/")
        || rel == "growlight/baton-log"
        || rel.starts_with("growlight/baton-log/")
        || rel == "growlight/chat"
        || rel.starts_with("growlight/chat/")
}

// ---- pure reference core ----------------------------------------------
//
// Split out so the tokenizer / resolver / rewriter / renderer are
// exhaustively unit-testable without a daemon or filesystem.

pub mod refs {
    use std::collections::BTreeSet;
    use std::path::Path;

    use crate::actions::conventions;
    use crate::layer_b::regions::compute_markdown_mask;

    /// Extract `[[token]]` reference tokens (inner text, trimmed) from
    /// markdown, skipping fenced code blocks and inline backtick spans so a
    /// documented `[[NNN-slug]]` mention isn't parsed as a real edge.
    pub fn parse_refs(content: &str) -> Vec<String> {
        let bytes = content.as_bytes();
        let mask = compute_markdown_mask(bytes);
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if bytes[i] == b'[' && bytes[i + 1] == b'[' && mask[i] && mask[i + 1] {
                if let Some(close) = find_close(bytes, &mask, i + 2) {
                    if let Ok(inner) = std::str::from_utf8(&bytes[i + 2..close]) {
                        let token = inner.trim();
                        if valid_token(token) {
                            out.push(token.to_string());
                        }
                    }
                    i = close + 2;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// Find the byte index of the first `]` of a `]]` close on the same line
    /// as the open, both bytes outside code. `None` if the line ends first.
    fn find_close(bytes: &[u8], mask: &[bool], from: usize) -> Option<usize> {
        let mut j = from;
        while j + 1 < bytes.len() {
            if bytes[j] == b'\n' {
                return None;
            }
            if bytes[j] == b']' && bytes[j + 1] == b']' && mask[j] && mask[j + 1] {
                return Some(j);
            }
            j += 1;
        }
        None
    }

    /// A well-formed link token: non-empty, bounded, and free of the
    /// structural characters that would make it ambiguous.
    fn valid_token(token: &str) -> bool {
        !token.is_empty()
            && token.len() <= 256
            && !token.contains(['[', ']', '|', '\n', '\r', '\t'])
    }

    /// The garden-relative `.md` path a `[[token]]` in `source_rel` *names*,
    /// without checking existence. `None` for an unresolvable shape (a bare
    /// `NNN-slug` outside an accretive folder, or a `..`-traversing path).
    fn candidate(source_rel: &str, token: &str) -> Option<String> {
        if token.split('/').any(|c| c == ".." || c == ".") {
            return None;
        }
        if token.contains('/') {
            Some(with_md_suffix(token))
        } else {
            let parent = Path::new(source_rel).parent()?.to_str()?;
            if !conventions::is_accretive_dir(parent) {
                return None;
            }
            Some(format!("{parent}/{}", with_md_suffix(token)))
        }
    }

    fn with_md_suffix(token: &str) -> String {
        if token.ends_with(".md") {
            token.to_string()
        } else {
            format!("{token}.md")
        }
    }

    /// Resolve a `[[token]]` in `source_rel` to an existing garden-relative
    /// target (`.md`), or `None` if it can't resolve to a real file.
    pub fn resolve_ref(
        source_rel: &str,
        token: &str,
        exists: &dyn Fn(&str) -> bool,
    ) -> Option<String> {
        let cand = candidate(source_rel, token)?;
        exists(&cand).then_some(cand)
    }

    /// Render the backlinks region body (no surrounding newlines —
    /// `managed::upsert` owns the blank padding): an italic label over a
    /// sorted bullet list of garden-relative source paths.
    pub fn render(sources: &BTreeSet<String>) -> String {
        let mut s = String::from("_Backlinks:_\n");
        for src in sources {
            s.push_str(&format!("\n- `{src}`"));
        }
        s
    }

    /// Rewrite every `[[token]]` in `content` that *names* `old_target`
    /// (from `source_rel`) to `[[new_target]]`, preserving everything else.
    /// `None` when nothing matched. UTF-8 safe — only ASCII `[`/`]`/`\n`
    /// delimit the spans copied verbatim around each rewrite.
    pub fn rewrite_to(
        content: &str,
        source_rel: &str,
        old_target: &str,
        new_target: &str,
    ) -> Option<String> {
        let bytes = content.as_bytes();
        let mask = compute_markdown_mask(bytes);
        let mut out = String::with_capacity(content.len() + new_target.len());
        let mut last = 0usize; // copied up to here (a char boundary)
        let mut i = 0usize;
        let mut changed = false;
        while i + 1 < bytes.len() {
            if bytes[i] == b'[' && bytes[i + 1] == b'[' && mask[i] && mask[i + 1] {
                if let Some(close) = find_close(bytes, &mask, i + 2) {
                    if let Ok(inner) = std::str::from_utf8(&bytes[i + 2..close]) {
                        let token = inner.trim();
                        if valid_token(token)
                            && candidate(source_rel, token).as_deref() == Some(old_target)
                        {
                            out.push_str(&content[last..i]);
                            out.push_str("[[");
                            out.push_str(new_target);
                            out.push_str("]]");
                            last = close + 2;
                            changed = true;
                        }
                    }
                    i = close + 2;
                    continue;
                }
            }
            i += 1;
        }
        if !changed {
            return None;
        }
        out.push_str(&content[last..]);
        Some(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_finds_tokens_skips_code() {
            let doc = "see [[002-gpu]] and [[journal/decisions/decision-x]].\n\n\
                       ```\n[[001-in-fence]]\n```\n\n\
                       inline `[[001-in-span]]` not a ref.\n";
            assert_eq!(
                parse_refs(doc),
                vec!["002-gpu", "journal/decisions/decision-x"]
            );
        }

        #[test]
        fn parse_rejects_malformed_tokens() {
            assert!(parse_refs("[[ ]] and [[a|b]] and [[unclosed\n]]").is_empty());
        }

        #[test]
        fn resolve_bare_token_within_accretive_folder() {
            let exists = |rel: &str| rel == "services/waydroid/notes/002-gpu.md";
            assert_eq!(
                resolve_ref("services/waydroid/notes/001-a.md", "002-gpu", &exists).as_deref(),
                Some("services/waydroid/notes/002-gpu.md")
            );
            // Bare token from a non-accretive doc can't resolve.
            assert_eq!(
                resolve_ref("services/waydroid/CLAUDE.md", "002-gpu", &exists),
                None
            );
        }

        #[test]
        fn resolve_path_token_appends_md_and_checks_existence() {
            let exists = |rel: &str| rel == "journal/decisions/decision-x.md";
            assert_eq!(
                resolve_ref("notes/001-a.md", "journal/decisions/decision-x", &exists).as_deref(),
                Some("journal/decisions/decision-x.md")
            );
            // Same, with an explicit .md suffix.
            assert_eq!(
                resolve_ref("notes/001-a.md", "journal/decisions/decision-x.md", &exists).as_deref(),
                Some("journal/decisions/decision-x.md")
            );
            // Dangling path resolves to nothing.
            assert_eq!(resolve_ref("notes/001-a.md", "nope/gone", &exists), None);
        }

        #[test]
        fn resolve_rejects_traversal() {
            let exists = |_: &str| true;
            assert_eq!(resolve_ref("notes/001-a.md", "../../etc/passwd", &exists), None);
        }

        #[test]
        fn render_is_sorted_bulleted_paths() {
            let mut s = BTreeSet::new();
            s.insert("services/x/notes/002-b.md".to_string());
            s.insert("journal/decisions/decision-a.md".to_string());
            assert_eq!(
                render(&s),
                "_Backlinks:_\n\n- `journal/decisions/decision-a.md`\n- `services/x/notes/002-b.md`"
            );
        }

        #[test]
        fn rewrite_repoints_matching_refs_only() {
            // A bare sibling ref and a full garden-relative path ref both name
            // the same target; an unrelated sibling and a same-named note in a
            // *different* folder (`[[notes/002-gpu.md]]` → garden-root notes/)
            // do not.
            let doc = "[[002-gpu]] [[003-keep]] [[services/x/notes/002-gpu.md]] [[notes/002-gpu.md]]\n";
            let out = rewrite_to(
                doc,
                "services/x/notes/001-a.md",
                "services/x/notes/002-gpu.md",
                "journal/archive/gpu/002-gpu.md",
            )
            .unwrap();
            assert_eq!(
                out,
                "[[journal/archive/gpu/002-gpu.md]] [[003-keep]] \
                 [[journal/archive/gpu/002-gpu.md]] [[notes/002-gpu.md]]\n"
            );
        }

        #[test]
        fn rewrite_returns_none_when_no_match() {
            let doc = "nothing [[003-other]] here\n";
            assert_eq!(
                rewrite_to(doc, "notes/001-a.md", "notes/002-gpu.md", "journal/archive/x.md"),
                None
            );
        }

        #[test]
        fn rewrite_is_utf8_safe() {
            // A multibyte char before the ref must survive the byte-indexed
            // copy untouched.
            let doc = "café [[002-gpu]] end\n";
            let out = rewrite_to(
                doc,
                "notes/001-a.md",
                "notes/002-gpu.md",
                "journal/archive/g.md",
            )
            .unwrap();
            assert_eq!(out, "café [[journal/archive/g.md]] end\n");
        }
    }
}
