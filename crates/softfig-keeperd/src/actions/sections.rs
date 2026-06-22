//! Slice 2 of the small-files redesign — universal section editing +
//! `set_reviewed`.
//!
//! These verbs let Claude mutate any markdown doc (a numbered note, a
//! monolithic `CLAUDE.md`, a decision) by **heading address** so the only
//! tokens it emits are the irreducible new content — never the rest of the
//! file. The daemon keeps the heading line; the caller re-emits only the
//! body (`edit_section`), a single new row (`append_to_section`), a fresh
//! section (`add_section`), or nothing at all (`set_reviewed`). See
//! `meta/spec-small-files.md`.
//!
//! ## Heading addressing
//!
//! A section is addressed by its heading **text**, matched case-sensitively
//! and level-agnostically: `"Cross-refs"`, `"## Cross-refs"`, and
//! `"### Cross-refs"` all resolve to a heading whose text is `Cross-refs`,
//! whatever its `#` level. The match must be unique for `edit`/`append`
//! (ambiguous → `BadArgs`). For `add_section` the level comes from any
//! leading `#`s in the argument (`## Foo` → level 2), defaulting to `##`.
//! A section spans its heading line through the line before the next
//! heading of the same-or-higher level (subsections are part of it).
//!
//! ## Vault refusal
//!
//! `reads.rs` projects sealed content (`[sealed:…]`, `[encrypted]`), so a
//! plaintext rewrite of a vault file would clobber ciphertext. All four
//! verbs therefore refuse a target that is whole-file-sealed or that
//! contains an inline `<vault id=…>` region (`VaultProtected`), or whose
//! tags are malformed (`MalformedVaultTag`). Headings themselves are never
//! redacted, so a heading address always matches the daemon's truth.

use std::path::Path;

use softfig_vcs::Intent;
use softfig_ipc::verbs::{
    AddSectionArgs, AppendToSectionArgs, DocEditReply, EditSectionArgs, SetReviewedArgs,
};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, WorkTree};
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{
    path_to_repo_rel_string, require_unlocked, validate_repo_path, HandlerResult,
};

// ---- handlers ----------------------------------------------------------

pub fn add_section(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddSectionArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_section args: {e}")))?;
    if args.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
    }
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    let new = {
        let wt = WorkTree::new(daemon, &inner);
        let content = load_unprotected(&wt, &inner, &rel)?;
        edit::add_section(&content, &args.heading, &args.body)
            .map_err(|e| section_err(&rel, &args.heading, e))?
    };
    write_and_commit(daemon, &mut inner, &rel, new, "section_added", &args.heading)
}

pub fn edit_section(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: EditSectionArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("edit_section args: {e}")))?;
    if args.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
    }
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    let new = {
        let wt = WorkTree::new(daemon, &inner);
        let content = load_unprotected(&wt, &inner, &rel)?;
        edit::edit_section(&content, &args.heading, &args.body)
            .map_err(|e| section_err(&rel, &args.heading, e))?
    };
    write_and_commit(daemon, &mut inner, &rel, new, "section_edited", &args.heading)
}

pub fn append_to_section(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AppendToSectionArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("append_to_section args: {e}")))?;
    if args.text.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "text must be non-empty".into()));
    }
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    let new = {
        let wt = WorkTree::new(daemon, &inner);
        let content = load_unprotected(&wt, &inner, &rel)?;
        edit::append_to_section(&content, &args.heading, &args.text)
            .map_err(|e| section_err(&rel, &args.heading, e))?
    };
    write_and_commit(daemon, &mut inner, &rel, new, "section_appended", &args.heading)
}

pub fn set_reviewed(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: SetReviewedArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("set_reviewed args: {e}")))?;
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    {
        let wt = WorkTree::new(daemon, &inner);
        let content = load_unprotected(&wt, &inner, &rel)?;
        let new = edit::set_reviewed(&content, &conventions::today_hyphen()).ok_or((
            ErrorKind::NotFound,
            format!("{rel}: no 'Last reviewed:' line to stamp"),
        ))?;
        wt.write(&rel, new.as_bytes())?;
    }

    let payload = serde_json::json!({ "path": rel });
    let intent = Intent::new("reviewed_stamped", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;
    Ok(serde_json::to_value(DocEditReply { path: rel, hash: hash.to_string() }).unwrap())
}

// ---- handler helpers ---------------------------------------------------

fn resolve(garden_root: &Path, path: &str) -> Result<String, (ErrorKind, String)> {
    let abs = validate_repo_path(garden_root, path).map_err(|m| (ErrorKind::BadArgs, m))?;
    path_to_repo_rel_string(garden_root, &abs)
        .ok_or((ErrorKind::BadArgs, "path outside garden root".into()))
}

/// Read `rel`'s working-tree bytes as plaintext **iff** a plaintext rewrite
/// is safe — the file isn't whole-file-sealed and carries no inline
/// `<vault>` region (malformed tags count as unsafe). Returns `None` for a
/// protected, unreadable, or non-UTF-8 file. The read-once primitive behind
/// best-effort managed-region maintenance (slice 4 index + slice 5
/// backlinks), which must never clobber ciphertext or guess.
pub(crate) fn read_if_unprotected(wt: &WorkTree, inner: &DaemonInner, rel: &str) -> Option<String> {
    if inner.layer_b.snapshot().is_sealed(rel) {
        return None;
    }
    let bytes = wt.read(rel)?;
    let session = inner.session.as_ref()?;
    let parser = crate::layer_b::regions::parser_for(rel);
    match crate::layer_b::regions::parse(parser, &bytes, session, rel) {
        Ok(spans) if spans.is_empty() => {}
        _ => return None, // inline region present, or malformed → don't touch
    }
    String::from_utf8(bytes).ok()
}

/// Read the working-tree bytes of `rel` as plaintext, refusing any vault
/// target so a section rewrite can never clobber ciphertext (see module
/// docs). Returns the UTF-8 content on success. Reads through the
/// [`WorkTree`], so a FUSE-mode daemon never `std::fs`-reads the mount.
fn load_unprotected(
    wt: &WorkTree,
    inner: &DaemonInner,
    rel: &str,
) -> Result<String, (ErrorKind, String)> {
    if inner.layer_b.snapshot().is_sealed(rel) {
        return Err((
            ErrorKind::VaultProtected,
            format!("{rel}: whole-file sealed — edit via the vault path"),
        ));
    }
    let bytes = wt
        .read(rel)
        .ok_or((ErrorKind::NotFound, format!("{rel}: not found")))?;
    // Reuse the inline-region parser (it masks fenced/inline-code mentions,
    // so docs that merely *document* the `<vault>` syntax aren't refused).
    let session: &softfig_vault::VaultSession = inner.session.as_ref().expect("unlocked");
    let parser = crate::layer_b::regions::parser_for(rel);
    match crate::layer_b::regions::parse(parser, &bytes, session, rel) {
        Ok(spans) if spans.is_empty() => {}
        Ok(_) => {
            return Err((
                ErrorKind::VaultProtected,
                format!("{rel}: contains an inline <vault> region — edit via the vault path"),
            ))
        }
        Err(e) => return Err((ErrorKind::MalformedVaultTag, format!("{rel}: {e}"))),
    }
    String::from_utf8(bytes).map_err(|_| (ErrorKind::BadArgs, format!("{rel}: not UTF-8 text")))
}

/// Common tail for the three section verbs: write the rebuilt content + refresh
/// backlinks through a scoped [`WorkTree`] (mount-safe in FUSE mode), then
/// commit `intent` with a `{path, heading}` payload and reply `{path, hash}`.
/// The worktree is dropped before the `&mut inner` commit so its shared borrow
/// of `inner` doesn't collide with `commit_now`.
fn write_and_commit(
    daemon: &Daemon,
    inner: &mut std::sync::MutexGuard<'_, DaemonInner>,
    rel: &str,
    new_content: String,
    intent_name: &str,
    heading_arg: &str,
) -> HandlerResult {
    {
        let wt = WorkTree::new(daemon, inner);
        wt.write(rel, new_content.as_bytes())?;
        // Slice 5: a section edit can add/remove `[[…]]` refs in any doc, so
        // recompute the backlink graph before committing (best-effort).
        super::backlinks::refresh_all(&wt, inner);
    }
    let (_level, heading_text) = edit::parse_heading_arg(heading_arg);
    let payload = serde_json::json!({ "path": rel, "heading": heading_text });
    let intent = Intent::new(intent_name, payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut **inner;
    let hash = commit_now(inner, intent)?;
    Ok(serde_json::to_value(DocEditReply {
        path: rel.to_string(),
        hash: hash.to_string(),
    })
    .unwrap())
}

fn section_err(rel: &str, heading: &str, e: edit::SectionError) -> (ErrorKind, String) {
    use edit::SectionError::*;
    match e {
        NotFound => (
            ErrorKind::NotFound,
            format!("{rel}: no section heading {heading:?}"),
        ),
        Ambiguous => (
            ErrorKind::BadArgs,
            format!("{rel}: heading {heading:?} matches more than one section"),
        ),
        AlreadyExists => (
            ErrorKind::PathAlreadyExists,
            format!("{rel}: section {heading:?} already exists"),
        ),
        EmptyHeading => (ErrorKind::BadArgs, "heading must be non-empty".into()),
    }
}

// ---- pure markdown section core ----------------------------------------
//
// Split out so it's exhaustively unit-testable without a daemon. Every
// transform is total over the `split('\n')` / `join("\n")` representation,
// which round-trips the original bytes exactly (a trailing newline shows up
// as a final empty element).

pub mod edit {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SectionError {
        /// No heading matched the address.
        NotFound,
        /// More than one heading matched (edit/append require a unique one).
        Ambiguous,
        /// `add_section` heading text is already present.
        AlreadyExists,
        /// The heading argument had no text after the `#`s.
        EmptyHeading,
    }

    struct Heading {
        line: usize,
        level: usize,
        text: String,
    }

    /// Parse a caller heading argument into an optional explicit level (the
    /// count of leading `#`, capped at 6) and the trimmed heading text.
    pub fn parse_heading_arg(arg: &str) -> (Option<usize>, String) {
        let trimmed = arg.trim();
        let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
        let text = trimmed[hashes..].trim().to_string();
        let level = (hashes > 0).then(|| hashes.min(6));
        (level, text)
    }

    fn is_fence(line: &str) -> bool {
        let t = line.trim_start();
        t.starts_with("```") || t.starts_with("~~~")
    }

    /// Parse a single line as an ATX heading (1–6 leading `#` then a space
    /// or end-of-line). `#!/bin/sh`, `#hashtag` are not headings.
    fn parse_heading_line(line: &str) -> Option<(usize, String)> {
        let t = line.trim_start();
        let hashes = t.bytes().take_while(|&b| b == b'#').count();
        if hashes == 0 || hashes > 6 {
            return None;
        }
        let rest = &t[hashes..];
        if rest.is_empty() {
            return Some((hashes, String::new()));
        }
        if !rest.starts_with(' ') {
            return None;
        }
        Some((hashes, rest.trim().to_string()))
    }

    /// All ATX headings outside fenced code blocks, in document order.
    fn headings(lines: &[&str]) -> Vec<Heading> {
        let mut out = Vec::new();
        let mut in_fence = false;
        for (i, line) in lines.iter().enumerate() {
            if is_fence(line) {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }
            if let Some((level, text)) = parse_heading_line(line) {
                out.push(Heading { line: i, level, text });
            }
        }
        out
    }

    fn find_unique<'a>(hs: &'a [Heading], want: &str) -> Result<&'a Heading, SectionError> {
        let mut it = hs.iter().filter(|h| h.text == want);
        match (it.next(), it.next()) {
            (None, _) => Err(SectionError::NotFound),
            (Some(h), None) => Ok(h),
            (Some(_), Some(_)) => Err(SectionError::Ambiguous),
        }
    }

    /// The `[start, end)` line range of `target`'s body: the lines after the
    /// heading, up to (but not including) the next heading of the
    /// same-or-higher level, or end-of-doc.
    fn body_range(line_count: usize, hs: &[Heading], target: &Heading) -> (usize, usize) {
        let start = target.line + 1;
        let end = hs
            .iter()
            .find(|h| h.line > target.line && h.level <= target.level)
            .map(|h| h.line)
            .unwrap_or(line_count);
        (start, end)
    }

    /// A section body block: one blank line, the trimmed body, one trailing
    /// blank line (the separator before the next heading / file end).
    fn body_block(body: &str) -> Vec<String> {
        let trimmed = body.trim_start_matches('\n').trim_end();
        let mut v = vec![String::new()];
        v.extend(trimmed.split('\n').map(str::to_string));
        v.push(String::new());
        v
    }

    pub fn edit_section(content: &str, heading_arg: &str, body: &str) -> Result<String, SectionError> {
        let (_level, want) = parse_heading_arg(heading_arg);
        if want.is_empty() {
            return Err(SectionError::EmptyHeading);
        }
        let lines: Vec<&str> = content.split('\n').collect();
        let hs = headings(&lines);
        let target = find_unique(&hs, &want)?;
        let (bstart, bend) = body_range(lines.len(), &hs, target);

        let mut out: Vec<String> = lines[..bstart].iter().map(|s| s.to_string()).collect();
        out.extend(body_block(body));
        out.extend(lines[bend..].iter().map(|s| s.to_string()));
        Ok(out.join("\n"))
    }

    pub fn append_to_section(
        content: &str,
        heading_arg: &str,
        text: &str,
    ) -> Result<String, SectionError> {
        let (_level, want) = parse_heading_arg(heading_arg);
        if want.is_empty() {
            return Err(SectionError::EmptyHeading);
        }
        let lines: Vec<&str> = content.split('\n').collect();
        let hs = headings(&lines);
        let target = find_unique(&hs, &want)?;
        let (bstart, bend) = body_range(lines.len(), &hs, target);

        let text = text.trim_matches('\n');
        let text_lines = || text.split('\n').map(str::to_string);
        let last_nonblank = (bstart..bend).rev().find(|&i| !lines[i].trim().is_empty());

        let out: Vec<String> = match last_nonblank {
            // Insert right after the last content line, before any trailing
            // blanks / the next heading — the "add a row" behaviour.
            Some(idx) => {
                let mut v: Vec<String> = lines[..=idx].iter().map(|s| s.to_string()).collect();
                v.extend(text_lines());
                v.extend(lines[idx + 1..].iter().map(|s| s.to_string()));
                v
            }
            // Empty section: same as setting its body.
            None => {
                let mut v: Vec<String> = lines[..bstart].iter().map(|s| s.to_string()).collect();
                v.extend(body_block(text));
                v.extend(lines[bend..].iter().map(|s| s.to_string()));
                v
            }
        };
        Ok(out.join("\n"))
    }

    pub fn add_section(content: &str, heading_arg: &str, body: &str) -> Result<String, SectionError> {
        let (level_opt, want) = parse_heading_arg(heading_arg);
        if want.is_empty() {
            return Err(SectionError::EmptyHeading);
        }
        let lines: Vec<&str> = content.split('\n').collect();
        if headings(&lines).iter().any(|h| h.text == want) {
            return Err(SectionError::AlreadyExists);
        }
        let level = level_opt.unwrap_or(2);
        let heading_line = format!("{} {}", "#".repeat(level), want);
        let body = body.trim_start_matches('\n').trim_end();
        let core = content.trim_end_matches('\n');

        let mut s = String::new();
        if !core.is_empty() {
            s.push_str(core);
            s.push_str("\n\n");
        }
        s.push_str(&heading_line);
        s.push_str("\n\n");
        s.push_str(body);
        s.push('\n');
        Ok(s)
    }

    /// Rewrite the first `Last reviewed:` line (optionally `> `-quoted /
    /// indented) to `today`, preserving its prefix. `None` if absent.
    pub fn set_reviewed(content: &str, today: &str) -> Option<String> {
        let mut lines: Vec<String> = content.split('\n').map(str::to_string).collect();
        for line in lines.iter_mut() {
            if let Some(idx) = reviewed_prefix_len(line) {
                *line = format!("{}Last reviewed: {}", &line[..idx], today);
                return Some(lines.join("\n"));
            }
        }
        None
    }

    /// If `line` is a `Last reviewed:` line, the byte index just before
    /// `Last reviewed:` (so the caller keeps the `> `/indent prefix). The
    /// prefix must be only blanks / markdown quote markers, so prose that
    /// merely mentions "Last reviewed:" isn't matched.
    fn reviewed_prefix_len(line: &str) -> Option<usize> {
        let idx = line.find("Last reviewed:")?;
        line[..idx]
            .chars()
            .all(|c| c == ' ' || c == '\t' || c == '>')
            .then_some(idx)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_heading_arg_levels() {
            assert_eq!(parse_heading_arg("Cross-refs"), (None, "Cross-refs".into()));
            assert_eq!(parse_heading_arg("## Decisions"), (Some(2), "Decisions".into()));
            assert_eq!(parse_heading_arg("###  Spaced  "), (Some(3), "Spaced".into()));
            assert_eq!(parse_heading_arg("#######over"), (Some(6), "over".into()));
            assert_eq!(parse_heading_arg("##"), (Some(2), "".into()));
        }

        #[test]
        fn heading_line_parsing() {
            assert_eq!(parse_heading_line("## Foo"), Some((2, "Foo".into())));
            assert_eq!(parse_heading_line("   ### Bar "), Some((3, "Bar".into())));
            assert_eq!(parse_heading_line("#!/bin/sh"), None);
            assert_eq!(parse_heading_line("#hashtag"), None);
            assert_eq!(parse_heading_line("plain text"), None);
            assert_eq!(parse_heading_line("####### too many"), None);
        }

        #[test]
        fn edit_replaces_inner_section_body() {
            let doc = "# Title\n\n## A\n\nold a body\n\n## B\n\nb body\n";
            let out = edit_section(doc, "A", "new a body").unwrap();
            assert_eq!(
                out,
                "# Title\n\n## A\n\nnew a body\n\n## B\n\nb body\n"
            );
        }

        #[test]
        fn edit_replaces_last_section_body() {
            let doc = "# Title\n\n## A\n\nold a body\n\n## B\n\nb body\n";
            let out = edit_section(doc, "## B", "fresh").unwrap();
            assert_eq!(out, "# Title\n\n## A\n\nold a body\n\n## B\n\nfresh\n");
        }

        #[test]
        fn edit_section_spans_subsections() {
            // Editing a level-2 section replaces its level-3 subsection too.
            let doc = "## A\n\nintro\n\n### sub\n\ndetail\n\n## B\n\nb\n";
            let out = edit_section(doc, "A", "replaced").unwrap();
            assert_eq!(out, "## A\n\nreplaced\n\n## B\n\nb\n");
        }

        #[test]
        fn edit_missing_and_ambiguous() {
            let doc = "## A\n\nx\n\n## A\n\ny\n";
            assert_eq!(edit_section(doc, "Nope", "z"), Err(SectionError::NotFound));
            assert_eq!(edit_section(doc, "A", "z"), Err(SectionError::Ambiguous));
            assert_eq!(edit_section(doc, "##", "z"), Err(SectionError::EmptyHeading));
        }

        #[test]
        fn append_adds_row_before_trailing_blank() {
            let doc = "# refs\n\n## Cross-refs\n\n- foo\n- bar\n";
            let out = append_to_section(doc, "Cross-refs", "- baz").unwrap();
            assert_eq!(out, "# refs\n\n## Cross-refs\n\n- foo\n- bar\n- baz\n");
        }

        #[test]
        fn append_inserts_before_next_heading() {
            let doc = "## A\n\n- x\n\n## B\n\ny\n";
            let out = append_to_section(doc, "A", "- z").unwrap();
            assert_eq!(out, "## A\n\n- x\n- z\n\n## B\n\ny\n");
        }

        #[test]
        fn append_into_empty_section() {
            let doc = "## A\n\n## B\n\ny\n";
            let out = append_to_section(doc, "A", "first").unwrap();
            assert_eq!(out, "## A\n\nfirst\n\n## B\n\ny\n");
        }

        #[test]
        fn add_appends_section_at_end() {
            let doc = "# refs\n\n## Cross-refs\n\n- foo\n";
            let out = add_section(doc, "Notes", "first note").unwrap();
            assert_eq!(out, "# refs\n\n## Cross-refs\n\n- foo\n\n## Notes\n\nfirst note\n");
        }

        #[test]
        fn add_honours_explicit_level_and_rejects_dup() {
            let doc = "# T\n\n## A\n\nx\n";
            let out = add_section(doc, "### Deep", "body").unwrap();
            assert_eq!(out, "# T\n\n## A\n\nx\n\n### Deep\n\nbody\n");
            assert_eq!(add_section(doc, "A", "y"), Err(SectionError::AlreadyExists));
            // level-agnostic dup detection: `### A` collides with `## A`.
            assert_eq!(add_section(doc, "### A", "y"), Err(SectionError::AlreadyExists));
        }

        #[test]
        fn add_into_empty_doc() {
            assert_eq!(add_section("", "Start", "go").unwrap(), "## Start\n\ngo\n");
        }

        #[test]
        fn headings_inside_fence_are_ignored() {
            // The `# inside fence` line is shell, not a heading: editing the
            // real section must keep it verbatim.
            let doc = "## A\n\n```sh\n# inside fence\n```\n\ntail\n";
            let out = edit_section(doc, "A", "new").unwrap();
            assert_eq!(out, "## A\n\nnew\n");
            // And it isn't addressable / doesn't collide on add.
            assert!(add_section(doc, "inside fence", "x").is_ok());
        }

        #[test]
        fn set_reviewed_rewrites_quoted_and_bare() {
            let quoted = "# N\n\n> Last reviewed: 2026-01-01\n\nbody\n";
            assert_eq!(
                set_reviewed(quoted, "2026-06-11").unwrap(),
                "# N\n\n> Last reviewed: 2026-06-11\n\nbody\n"
            );
            let bare = "Last reviewed: 2020-09-09\nstuff\n";
            assert_eq!(
                set_reviewed(bare, "2026-06-11").unwrap(),
                "Last reviewed: 2026-06-11\nstuff\n"
            );
        }

        #[test]
        fn set_reviewed_absent_and_prose_mention() {
            assert!(set_reviewed("# N\n\nno stamp\n", "2026-06-11").is_none());
            // A prose mention is not a stamp line.
            assert!(set_reviewed("see Last reviewed: note\n", "2026-06-11").is_none());
        }

        /// Every transform must round-trip the `split`/`join` invariant: an
        /// edit only touches the addressed region.
        #[test]
        fn untouched_regions_are_byte_identical() {
            let doc = "# T\n\nlead para\n\n## Keep\n\nkeep me\n\n## Edit\n\nold\n";
            let out = edit_section(doc, "Edit", "new").unwrap();
            assert!(out.contains("# T\n\nlead para\n\n## Keep\n\nkeep me\n\n"));
            assert!(out.ends_with("## Edit\n\nnew\n"));
        }
    }
}
