//! Slice 2 of the small-files redesign — universal section editing +
//! `set_reviewed`.
//!
//! These verbs let Claude mutate any markdown doc (a numbered note, a
//! monolithic `CLAUDE.md`, a decision) by **heading address** so the only
//! tokens it emits are the irreducible new content — never the rest of the
//! file. The daemon keeps the heading line; the caller re-emits only the
//! body (`edit_section`), a single new row (`append_to_section`), a fresh
//! section (`add_section`), or nothing at all (`set_reviewed`) — or names a
//! section to delete outright (`remove_section`, mcp-surgical-writes slice
//! 003). See `meta/spec-small-files.md` and
//! `meta/spec-mcp-writes/spec-remove-section.md`.
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
//! heading of the same-or-higher level (subsections are part of it) — the
//! span `remove_section` deletes and section versions hash. `edit_section`
//! replaces less when it can: a body with **no headings of its own** replaces
//! only the section's own text, up to its first subsection, so editing a
//! `# Title`'s intro can no longer wipe every `##` below it; a body that
//! carries headings replaces the whole span (a deliberate restructure).
//!
//! ## Managed regions are daemon-owned
//!
//! No section verb changes a `<!-- softfig:… -->` region. `edit_section`
//! keeps the regions inside the text it replaces (re-appended after the new
//! body unless the caller re-emitted them verbatim), `append_to_section`
//! inserts above a trailing region, and any edit that would change, split, or
//! introduce a region is refused — so a region at the end of a doc's last
//! section survives an edit of that section. A trailing `---` separator is
//! kept the same way: it belongs to the boundary, not to the body.
//!
//! ## Vault refusal
//!
//! `reads.rs` projects sealed content (`[sealed:…]`, `[encrypted]`), so a
//! plaintext rewrite of a vault file would clobber ciphertext. All five
//! verbs therefore refuse a target that is whole-file-sealed or that
//! contains an inline `<vault id=…>` region (`VaultProtected`), or whose
//! tags are malformed (`MalformedVaultTag`). Headings themselves are never
//! redacted, so a heading address always matches the daemon's truth.

use std::path::Path;

use softfig_vcs::Intent;
use softfig_ipc::verbs::{
    AddSectionArgs, AppendToSectionArgs, DocEditReply, EditSectionArgs, RemoveSectionArgs,
    SetReviewedArgs,
};
use softfig_ipc::ErrorKind;

use super::growlight::chat;
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
    let heading = args.heading.clone();
    let version_of = move |c: &str| edit::section_version(c, &heading).unwrap_or_default();
    write_and_commit(daemon, &mut inner, &rel, new, "section_added", &args.heading, &version_of)
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
        cas_check_section(&content, &args.heading, &args.expected_version)?;
        edit::edit_section(&content, &args.heading, &args.body)
            .map_err(|e| section_err(&rel, &args.heading, e))?
    };
    let heading = args.heading.clone();
    let version_of = move |c: &str| edit::section_version(c, &heading).unwrap_or_default();
    let reply = write_and_commit(
        daemon,
        &mut inner,
        &rel,
        new,
        "section_edited",
        &args.heading,
        &version_of,
    )?;
    note_section_edit_for_thrash(daemon, &mut inner, &rel, &args.heading, args.editor.as_deref());
    Ok(reply)
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
        cas_check_section(&content, &args.heading, &args.expected_version)?;
        edit::append_to_section(&content, &args.heading, &args.text)
            .map_err(|e| section_err(&rel, &args.heading, e))?
    };
    let heading = args.heading.clone();
    let version_of = move |c: &str| edit::section_version(c, &heading).unwrap_or_default();
    let reply = write_and_commit(
        daemon,
        &mut inner,
        &rel,
        new,
        "section_appended",
        &args.heading,
        &version_of,
    )?;
    note_section_edit_for_thrash(daemon, &mut inner, &rel, &args.heading, args.editor.as_deref());
    Ok(reply)
}

pub fn remove_section(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: RemoveSectionArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("remove_section args: {e}")))?;
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    let new = {
        let wt = WorkTree::new(daemon, &inner);
        let content = load_unprotected(&wt, &inner, &rel)?;
        cas_check_section(&content, &args.heading, &args.expected_version)?;
        // Guard: never delete through a daemon-managed region — an index
        // table's content belongs to its machinery, not to the agent.
        let (rstart, rend) = edit::section_range(&content, &args.heading)
            .map_err(|e| section_err(&rel, &args.heading, e))?;
        if let Some(tag) = super::managed::overlapping_region(&content, rstart, rend) {
            return Err((
                ErrorKind::BadArgs,
                format!(
                    "{rel}: section {:?} overlaps the daemon-managed <!-- softfig:{tag} --> \
                     region — regenerate that region through its owning machinery, not by hand",
                    args.heading
                ),
            ));
        }
        edit::remove_section(&content, &args.heading)
            .map_err(|e| section_err(&rel, &args.heading, e))?
    };
    // The section no longer exists, so the reply carries the new whole-file
    // version — there is no post-delete section version to chain.
    let reply = write_and_commit(
        daemon,
        &mut inner,
        &rel,
        new,
        "section_removed",
        &args.heading,
        &edit::content_version,
    )?;
    note_section_edit_for_thrash(daemon, &mut inner, &rel, &args.heading, args.editor.as_deref());
    Ok(reply)
}

pub fn set_reviewed(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: SetReviewedArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("set_reviewed args: {e}")))?;
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let rel = resolve(&garden_root, &args.path)?;

    let (version, rederived) = {
        let wt = WorkTree::new(daemon, &inner);
        let content = load_unprotected(&wt, &inner, &rel)?;
        let new = edit::set_reviewed(&content, &conventions::today_hyphen()).ok_or((
            ErrorKind::NotFound,
            format!("{rel}: no 'Last reviewed:' line to stamp"),
        ))?;
        wt.write(&rel, new.as_bytes())?;
        // Task 060: the stamp this verb moves *is* the index's `Reviewed`
        // cell, so re-derive the owning table into the same commit — else the
        // index starts lying the moment a note is re-reviewed.
        super::index::refresh_index_for(&wt, &inner, &rel);
        // set_reviewed isn't section-addressed, so its CAS handle is the
        // whole-file version (informational here — date bumps rarely contend),
        // hashed over what is on disk after the upkeep (review 031 D1).
        let on_disk = on_disk_after_upkeep(&wt, &rel, &new);
        (edit::content_version(&on_disk), super::managed::changed_regions(&new, &on_disk))
    };

    let payload = serde_json::json!({ "path": rel });
    let intent = Intent::new("reviewed_stamped", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;
    Ok(serde_json::to_value(DocEditReply {
        path: rel,
        hash: hash.to_string(),
        version,
        rederived,
    })
    .unwrap())
}

/// Optimistic-concurrency guard for the section verbs: when the caller supplied
/// an `expected_version`, the addressed section must still carry it, else
/// `Conflict` (stale — the caller re-reads + reapplies). A `None` current
/// version (heading absent / ambiguous) is passed through so the edit transform
/// surfaces the precise `NotFound` / `Ambiguous` error instead. No lock is held
/// at any point — a crashed caller strands nothing. `pub(crate)` so the batch
/// verb (slice 005) can run the same guard against its simulated working state.
pub(crate) fn cas_check_section(
    content: &str,
    heading: &str,
    expected: &Option<String>,
) -> Result<(), (ErrorKind, String)> {
    if let (Some(want), Some(cur)) = (expected, edit::section_version(content, heading)) {
        if &cur != want {
            return Err((
                ErrorKind::Conflict,
                format!(
                    "stale: section {heading:?} changed since version {want} — re-read and retry"
                ),
            ));
        }
    }
    Ok(())
}

// ---- handler helpers ---------------------------------------------------

/// Validate `path` against the garden root and return its repo-relative form —
/// the shared resolve for every doc-edit verb (`patch_file` included).
pub(crate) fn resolve(garden_root: &Path, path: &str) -> Result<String, (ErrorKind, String)> {
    let abs = validate_repo_path(garden_root, path).map_err(|m| (ErrorKind::BadArgs, m))?;
    let rel = path_to_repo_rel_string(garden_root, &abs)
        .ok_or((ErrorKind::BadArgs, "path outside garden root".into()))?;
    // The daemon state dir is not garden content and is VCS-ignored — a
    // doc-edit verb must never land on it (mcp-surgical-writes slice 004
    // tightened this here, one guard for the whole family; `unlink`'s
    // history-recoverability argument wouldn't hold for ignored state).
    if rel == ".softfig" || rel.starts_with(".softfig/") {
        return Err((
            ErrorKind::BadArgs,
            format!("{rel}: the daemon state dir (.softfig/) is not garden content"),
        ));
    }
    Ok(rel)
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

/// The read for a verb that swaps a doc's body **wholesale** (`revise_note`):
/// a whole-file-sealed doc is fine — the caller supplies the complete new
/// body, and the commit re-seals it by glob — but a doc carrying inline
/// `<vault>` regions is refused like [`load_unprotected`] does, because the
/// caller only ever saw those regions as `[encrypted]` and the swap can only
/// destroy them.
pub(crate) fn load_for_body_swap(
    wt: &WorkTree,
    inner: &DaemonInner,
    rel: &str,
) -> Result<String, (ErrorKind, String)> {
    if inner.layer_b.snapshot().is_sealed(rel) {
        return wt
            .read_to_string(rel)
            .ok_or((ErrorKind::NotFound, format!("{rel}: not found")));
    }
    load_unprotected(wt, inner, rel)
}

/// Read the working-tree bytes of `rel` as plaintext, refusing any vault
/// target so a plaintext rewrite can never clobber ciphertext (see module
/// docs). Returns the UTF-8 content on success. Reads through the
/// [`WorkTree`], so a FUSE-mode daemon never `std::fs`-reads the mount.
/// Shared with the surgical write verbs (`patch_file`, `remove_section`).
pub(crate) fn load_unprotected(
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

/// The bytes of `rel` as they stand after a verb's write **and** the daemon's
/// region upkeep (index re-derivation, backlinks) — what a reply's CAS
/// `version` must hash. Hashing the verb's own content instead named bytes
/// that were never on disk whenever the upkeep rewrote the same file, so the
/// next chained `expected_version` call hit a spurious `Conflict` (review 031
/// D1). Falls back to `written` only if the read-back fails, which a write
/// that just succeeded through the same worktree does not do.
pub(crate) fn on_disk_after_upkeep(wt: &WorkTree, rel: &str, written: &str) -> String {
    wt.read_to_string(rel).unwrap_or_else(|| written.to_string())
}

/// Common tail for the section verbs (add/edit/append/remove): write the
/// rebuilt content + refresh index and backlinks through a scoped
/// [`WorkTree`] (mount-safe in FUSE mode), then commit `intent` with a
/// `{path, heading}` payload and reply `{path, hash, version, rederived}` —
/// `version` is `version_of` over the on-disk bytes after the upkeep. The
/// worktree is dropped before the `&mut inner` commit so its shared borrow
/// of `inner` doesn't collide with `commit_now`.
fn write_and_commit(
    daemon: &Daemon,
    inner: &mut std::sync::MutexGuard<'_, DaemonInner>,
    rel: &str,
    new_content: String,
    intent_name: &str,
    heading_arg: &str,
    version_of: &dyn Fn(&str) -> String,
) -> HandlerResult {
    let (version, rederived) = {
        let wt = WorkTree::new(daemon, inner);
        wt.write(rel, new_content.as_bytes())?;
        // Task 060: a section edit can move a note's `Last reviewed:` header
        // (or land inside a host doc that carries index tables), so re-derive
        // the owning table into the same commit.
        super::index::refresh_index_for(&wt, inner, rel);
        // Slice 5: a section edit can add/remove `[[…]]` refs in any doc, so
        // recompute the backlink graph before committing (best-effort).
        super::backlinks::refresh_all(&wt, inner);
        let on_disk = on_disk_after_upkeep(&wt, rel, &new_content);
        (version_of(&on_disk), super::managed::changed_regions(&new_content, &on_disk))
    };
    let (_level, heading_text) = edit::parse_heading_arg(heading_arg);
    let payload = serde_json::json!({ "path": rel, "heading": heading_text });
    let intent = Intent::new(intent_name, payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut **inner;
    let hash = commit_now(inner, intent)?;
    Ok(serde_json::to_value(DocEditReply {
        path: rel.to_string(),
        hash: hash.to_string(),
        version,
        rederived,
    })
    .unwrap())
}

/// After a doc edit commits, feed `(target, editor)` into the daemon's
/// ping-pong detector (spec §4d). On a trip — an A↔B alternation on the same
/// `(path, heading)` within the window — post one `coord-request` nudge to the
/// coordination bus ("settle `<target>`") from the system sender `growlightd`
/// to `@all`, commit it (`chat_message_posted`), and flag the target for a
/// lease. The lease GRANT + @human escalation are the next §4d rungs and land
/// with the scheduler milestone (phase 4); here we only nudge + flag, leaving a
/// clean hook (`inner.thrash` carries the lease flag).
///
/// Best-effort + side-channel: the underlying edit already committed and its
/// reply is returned regardless, so a failed nudge never fails the edit. The
/// caller still holds `inner`, so the nudge commit is serialized after the edit
/// on the same lock. `editor` defaults to `"anon"` when absent — a lone editor
/// can't alternate with itself, so the single-agent loop never trips.
/// `heading` is `None` for whole-file targets (`patch_file`); section edits
/// pass their heading text so `(path, heading)` and `(path, None)` are
/// distinct contention targets.
pub(crate) fn note_edit_for_thrash(
    daemon: &Daemon,
    inner: &mut DaemonInner,
    rel: &str,
    heading: Option<&str>,
    editor: Option<&str>,
) {
    let editor = editor.unwrap_or("anon");
    let now = conventions::now_unix_secs();
    let Some(trip) = inner.thrash.record(rel, heading, editor, now) else {
        return;
    };

    let (a, b) = (
        trip.editors.first().map(String::as_str).unwrap_or("?"),
        trip.editors.get(1).map(String::as_str).unwrap_or("?"),
    );
    let draft = chat::Draft {
        from: "growlightd".to_string(),
        to: chat::Recipient::All,
        kind: chat::MessageKind::CoordRequest,
        body: format!(
            "settle `{}` — `{a}` and `{b}` are editing it back and forth",
            trip.target_label(),
        ),
    };
    let ts = conventions::now_rfc3339();
    let msg = {
        let wt = WorkTree::new(daemon, inner);
        match chat::append(&wt, &draft, &ts) {
            Ok(m) => m,
            Err(_) => return, // best-effort: the edit already landed
        }
    };
    let payload = serde_json::json!({
        "number": msg.number, "from": msg.from, "to": msg.to.to_wire(), "kind": msg.kind.as_wire(),
    });
    if let Ok(intent) = Intent::new("chat_message_posted", payload) {
        let _ = commit_now(inner, intent);
    }
}

/// Section-verb wrapper over [`note_edit_for_thrash`]: parse the caller's
/// heading argument into its address text and register `(rel, heading)`.
fn note_section_edit_for_thrash(
    daemon: &Daemon,
    inner: &mut DaemonInner,
    rel: &str,
    heading_arg: &str,
    editor: Option<&str>,
) {
    let (_level, heading_text) = edit::parse_heading_arg(heading_arg);
    note_edit_for_thrash(daemon, inner, rel, Some(&heading_text), editor);
}

/// Map a pure section-core error onto the wire `(ErrorKind, message)` pair —
/// `pub(crate)` so the batch verb (slice 005) reuses the identical mapping for
/// its sub-ops instead of duplicating it.
pub(crate) fn section_err(rel: &str, heading: &str, e: edit::SectionError) -> (ErrorKind, String) {
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
        LastSection => (
            ErrorKind::BadArgs,
            format!(
                "{rel}: deleting section {heading:?} would leave the file without \
                 any heading — unlink the file instead if it should be empty"
            ),
        ),
        ManagedRegion => (
            ErrorKind::BadArgs,
            format!(
                "{rel}: editing section {heading:?} would change, split, or introduce a \
                 daemon-managed <!-- softfig:… --> region — leave regions out of the body \
                 (the daemon keeps them in place) and change their source instead"
            ),
        ),
    }
}

// ---- pure markdown section core ----------------------------------------
//
// Split out so it's exhaustively unit-testable without a daemon. Every
// transform is total over the `split('\n')` / `join("\n")` representation,
// which round-trips the original bytes exactly (a trailing newline shows up
// as a final empty element).

pub mod edit {
    use softfig_store::Hash;

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
        /// Deleting the addressed section would leave the file with no
        /// headings at all (a parent whose span swallows every subsection
        /// counts) — an agent that truly wants an empty file unlinks it.
        LastSection,
        /// The edit would change, split, drop, or introduce a daemon-managed
        /// `<!-- softfig:… -->` region.
        ManagedRegion,
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

    /// The end of `target`'s **own** text: the line of its first subsection,
    /// or `span_end` when it has none. `[body_start, own_end)` is what a
    /// heading-free `edit_section` body replaces.
    fn own_body_end(hs: &[Heading], target: &Heading, span_end: usize) -> usize {
        hs.iter()
            .find(|h| h.line > target.line)
            .map(|h| h.line.min(span_end))
            .unwrap_or(span_end)
    }

    /// A markdown thematic break — three or more `-`, `*`, or `_` (spaces
    /// allowed between) and nothing else.
    fn is_thematic_break(line: &str) -> bool {
        let t: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        t.len() >= 3
            && (t.chars().all(|c| c == '-') || t.chars().all(|c| c == '*') || t.chars().all(|c| c == '_'))
    }

    /// The index of the last non-blank line in `lines[start..end]` that is a
    /// separator (a thematic break preceded by a blank line, so not a setext
    /// heading's underline) — `None` when the range ends in anything else.
    fn trailing_rule(lines: &[&str], start: usize, end: usize) -> Option<usize> {
        let last = (start..end).rev().find(|&i| !lines[i].trim().is_empty())?;
        let preceded_by_blank = last == 0 || lines[last - 1].trim().is_empty();
        (is_thematic_break(lines[last]) && preceded_by_blank).then_some(last)
    }

    /// `body` without a first line that repeats the addressed heading. The
    /// daemon stamps the heading itself, so a body that opens with it again
    /// (`## Status` passed as both heading and body's first line) would
    /// produce a duplicate heading — and an ambiguous address for every later
    /// edit of it.
    fn strip_repeated_heading<'a>(body: &'a str, want: &str) -> &'a str {
        let trimmed = body.trim_start_matches(['\n', '\r']);
        let first_end = trimmed.find('\n').unwrap_or(trimmed.len());
        match parse_heading_line(&trimmed[..first_end]) {
            Some((_, text)) if text == want => &trimmed[first_end..],
            _ => body,
        }
    }

    /// The managed-region invariant every non-break-glass edit honours: the
    /// result carries exactly the regions `before` did, bodies unchanged.
    fn keep_regions(before: &str, after: String) -> Result<String, SectionError> {
        if crate::actions::managed::changed_regions(before, &after).is_empty() {
            Ok(after)
        } else {
            Err(SectionError::ManagedRegion)
        }
    }

    pub fn edit_section(content: &str, heading_arg: &str, body: &str) -> Result<String, SectionError> {
        let (_level, want) = parse_heading_arg(heading_arg);
        if want.is_empty() {
            return Err(SectionError::EmptyHeading);
        }
        let lines: Vec<&str> = content.split('\n').collect();
        let hs = headings(&lines);
        let target = find_unique(&hs, &want)?;
        let body = strip_repeated_heading(body, &want);
        let body_lines: Vec<&str> = body.split('\n').collect();

        // A heading-free body replaces the section's own text only; a body
        // with headings is a restructure and replaces the whole span.
        let (bstart, span_end) = body_range(lines.len(), &hs, target);
        let bend = if headings(&body_lines).is_empty() {
            own_body_end(&hs, target, span_end)
        } else {
            span_end
        };

        // Regions inside the replaced window are kept: re-appended after the
        // new body unless the caller re-emitted them (then `keep_regions`
        // checks the copy is verbatim). One straddling the window edge can't
        // be kept whole — refused.
        let spans = crate::actions::managed::spans_of(&lines);
        if spans
            .iter()
            .any(|s| (s.open < bstart && s.close >= bstart) || (s.open < bend && s.close >= bend))
        {
            return Err(SectionError::ManagedRegion);
        }
        let mut text = body.trim_start_matches('\n').trim_end().to_string();
        for s in spans.iter().filter(|s| s.open >= bstart && s.close < bend) {
            if !crate::actions::managed::has_region(body, &s.tag) {
                if !text.is_empty() {
                    text.push_str("\n\n");
                }
                text.push_str(&lines[s.open..=s.close].join("\n"));
            }
        }
        // A separator closing the replaced text survives a body that doesn't
        // bring its own.
        let body_has_rule = trailing_rule(&body_lines, 0, body_lines.len()).is_some();
        if let Some(rule) = trailing_rule(&lines, bstart, bend).filter(|_| !body_has_rule) {
            text.push_str("\n\n");
            text.push_str(lines[rule].trim());
        }

        let mut out: Vec<String> = lines[..bstart].iter().map(|s| s.to_string()).collect();
        out.extend(body_block(&text));
        out.extend(lines[bend..].iter().map(|s| s.to_string()));
        keep_regions(content, out.join("\n"))
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
        // Append after the section's last *content* line: a managed region
        // and a closing `---` separator are boundaries, so new text lands
        // above them rather than after a daemon table or past the rule.
        let spans = crate::actions::managed::spans_of(&lines);
        let in_region = |i: usize| spans.iter().any(|s| i >= s.open && i <= s.close);
        let rule = trailing_rule(&lines, bstart, bend);
        let last_content = (bstart..bend)
            .rev()
            .find(|&i| !lines[i].trim().is_empty() && !in_region(i) && Some(i) != rule);
        let has_boundary = rule.is_some() || spans.iter().any(|s| s.open >= bstart && s.open < bend);

        let out: Vec<String> = match last_content {
            // Insert right after the last content line, before any trailing
            // blanks / region / separator / the next heading — the "add a
            // row" behaviour.
            Some(idx) => {
                let mut v: Vec<String> = lines[..=idx].iter().map(|s| s.to_string()).collect();
                v.extend(text_lines());
                v.extend(lines[idx + 1..].iter().map(|s| s.to_string()));
                v
            }
            // No prose, but a region or separator: open the body above it.
            None if has_boundary => {
                let mut v: Vec<String> = lines[..bstart].iter().map(|s| s.to_string()).collect();
                v.push(String::new());
                v.extend(text_lines());
                v.extend(lines[bstart..].iter().map(|s| s.to_string()));
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
        keep_regions(content, out.join("\n"))
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
        let body = strip_repeated_heading(body, &want)
            .trim_start_matches('\n')
            .trim_end();
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
        keep_regions(content, s)
    }

    /// The `[start, end)` line range the uniquely-addressed section occupies —
    /// its heading line through the line before the next same-or-higher
    /// heading (subsections included), i.e. exactly the span
    /// [`remove_section`] deletes. Exposed so the handler can run the
    /// managed-region overlap guard against the precise deletion window
    /// before transforming.
    pub fn section_range(content: &str, heading_arg: &str) -> Result<(usize, usize), SectionError> {
        let (_level, want) = parse_heading_arg(heading_arg);
        if want.is_empty() {
            return Err(SectionError::EmptyHeading);
        }
        let lines: Vec<&str> = content.split('\n').collect();
        let hs = headings(&lines);
        let target = find_unique(&hs, &want)?;
        let (_, end) = body_range(lines.len(), &hs, target);
        Ok((target.line, end))
    }

    /// Delete the uniquely-addressed section — its heading line and body,
    /// through the line before the next same-or-higher heading (subsections
    /// included). Refused (`LastSection`) when the deletion range holds
    /// every heading: deleting a parent swallows its subsections, so the
    /// guard counts them, and a heading-less file is almost always a
    /// mistake. When the deleted section runs to end-of-doc, the blank
    /// separator that preceded it collapses and the final newline is kept.
    pub fn remove_section(content: &str, heading_arg: &str) -> Result<String, SectionError> {
        let (start, end) = section_range(content, heading_arg)?;
        let lines: Vec<&str> = content.split('\n').collect();
        let hs = headings(&lines);
        let doomed = hs.iter().filter(|h| h.line >= start && h.line < end).count();
        if doomed == hs.len() {
            return Err(SectionError::LastSection);
        }
        let mut start = start;
        let mut end = end;
        if end >= lines.len() {
            // End-of-doc deletion: swallow the blank separator that preceded
            // the section (no stray trailing blanks), but keep the trailing
            // newline's split artifact (the final empty line) out of the
            // range so the file stays newline-terminated.
            if start > 0 && lines[start - 1].trim().is_empty() {
                start -= 1;
            }
            if lines.last() == Some(&"") {
                end -= 1;
            }
        }
        let mut out: Vec<String> = lines[..start].iter().map(|s| s.to_string()).collect();
        out.extend(lines[end..].iter().map(|s| s.to_string()));
        Ok(out.join("\n"))
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

    // ---- Phase 3 (garden CAS): content versions ------------------------

    /// A content version: the BLAKE3 hex of `s`. Stable + collision-resistant —
    /// the optimistic-concurrency handle a caller reads and submits back as
    /// `expected_version`. Whole-file when `s` is the file; section-scoped when
    /// `s` is a section slice (see [`section_version`]).
    pub fn content_version(s: &str) -> String {
        Hash::of(s.as_bytes()).to_hex()
    }

    /// The exact line slice a section occupies: its heading line through the
    /// line before the next same-or-higher heading (subsections included) — the
    /// same span [`edit_section`] replaces, so hashing it yields a version that
    /// changes iff that section changes.
    fn section_slice(lines: &[&str], hs: &[Heading], target: &Heading) -> String {
        let (_bstart, bend) = body_range(lines.len(), hs, target);
        lines[target.line..bend].join("\n")
    }

    /// The content version of the uniquely-addressed section. `None` when the
    /// heading is absent, ambiguous, or empty (the same addressing
    /// [`edit_section`] enforces) — so a CAS check on a bad address degrades to
    /// letting the edit itself surface the precise error.
    pub fn section_version(content: &str, heading_arg: &str) -> Option<String> {
        let (_level, want) = parse_heading_arg(heading_arg);
        if want.is_empty() {
            return None;
        }
        let lines: Vec<&str> = content.split('\n').collect();
        let hs = headings(&lines);
        let target = find_unique(&hs, &want).ok()?;
        Some(content_version(&section_slice(&lines, &hs, target)))
    }

    /// `(heading_text, version)` for every ATX heading, in document order — the
    /// `read_file` sections list. Each version covers that heading through its
    /// body end, so editing one section changes only its own entry (a parent
    /// section's version also covers its subsections, which is the conservative
    /// truth: editing a subsection does change the parent's span).
    pub fn section_versions(content: &str) -> Vec<(String, String)> {
        let lines: Vec<&str> = content.split('\n').collect();
        let hs = headings(&lines);
        hs.iter()
            .map(|h| (h.text.clone(), content_version(&section_slice(&lines, &hs, h))))
            .collect()
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
        fn heading_free_body_replaces_only_the_own_text() {
            // A body with no headings rewrites the section's own text and
            // keeps its subsections.
            let doc = "## A\n\nintro\n\n### sub\n\ndetail\n\n## B\n\nb\n";
            let out = edit_section(doc, "A", "replaced").unwrap();
            assert_eq!(out, "## A\n\nreplaced\n\n### sub\n\ndetail\n\n## B\n\nb\n");
        }

        /// The 2026-08-01 incident: editing an H1 to change its intro wiped
        /// every `##` below it. A heading-free body now touches the intro only.
        #[test]
        fn editing_the_h1_intro_keeps_every_section() {
            let doc = "# Title\n\nold intro\n\n## Symptom\n\ns\n\n## Fix\n\nf\n";
            let out = edit_section(doc, "Title", "new intro").unwrap();
            assert_eq!(out, "# Title\n\nnew intro\n\n## Symptom\n\ns\n\n## Fix\n\nf\n");
        }

        #[test]
        fn body_with_headings_restructures_the_whole_span() {
            let doc = "## A\n\nintro\n\n### sub\n\ndetail\n\n## B\n\nb\n";
            let out = edit_section(doc, "A", "lead\n\n### renamed\n\nnew detail").unwrap();
            assert_eq!(out, "## A\n\nlead\n\n### renamed\n\nnew detail\n\n## B\n\nb\n");
        }

        /// The 2026-07-09 incident: editing a doc's last section ate the
        /// `softfig:index` region that trailed it. The region is kept.
        #[test]
        fn edit_keeps_a_trailing_managed_region() {
            let doc = "# M\n\n## Finish criteria\n\nold\n\n\
                       <!-- softfig:index slices -->\n\n| 001 | x |\n\n<!-- /softfig:index slices -->\n";
            let out = edit_section(doc, "Finish criteria", "new criteria").unwrap();
            assert_eq!(
                out,
                "# M\n\n## Finish criteria\n\nnew criteria\n\n\
                 <!-- softfig:index slices -->\n\n| 001 | x |\n\n<!-- /softfig:index slices -->\n"
            );
        }

        #[test]
        fn edit_accepts_a_verbatim_region_and_refuses_a_changed_one() {
            let region = "<!-- softfig:index notes -->\n\n| 001 | x |\n\n<!-- /softfig:index notes -->";
            let doc = format!("## A\n\nold\n\n{region}\n\n## B\n\nb\n");
            // Re-emitted verbatim (moved above the prose): accepted, not doubled.
            let out = edit_section(&doc, "A", &format!("{region}\n\nnew")).unwrap();
            assert_eq!(out.matches("<!-- softfig:index notes -->").count(), 1, "{out}");
            assert!(out.contains("new"));
            // A hand-edited cell is refused, not silently reverted later.
            let tampered = region.replace("| 001 | x |", "| 001 | y |");
            assert_eq!(
                edit_section(&doc, "A", &format!("new\n\n{tampered}")),
                Err(SectionError::ManagedRegion)
            );
            // So is introducing a region by hand.
            assert_eq!(
                edit_section(&doc, "B", "<!-- softfig:queue -->\n\n| q |\n\n<!-- /softfig:queue -->"),
                Err(SectionError::ManagedRegion)
            );
        }

        /// The root `CLAUDE.md` separates sections with `---`; an edit that
        /// doesn't re-emit it keeps it.
        #[test]
        fn edit_keeps_a_trailing_separator() {
            let doc = "## A\n\nold\n\n---\n\n## B\n\nb\n";
            let out = edit_section(doc, "A", "new").unwrap();
            assert_eq!(out, "## A\n\nnew\n\n---\n\n## B\n\nb\n");
            // A body that brings its own separator doesn't get a second one.
            let out = edit_section(doc, "A", "new\n\n---").unwrap();
            assert_eq!(out.matches("---").count(), 1, "{out}");
            // A setext underline is not a separator.
            let setext = "## A\n\nTitle\n---\n\n## B\n";
            assert!(!edit_section(setext, "A", "x").unwrap().contains("---"));
        }

        #[test]
        fn a_body_that_repeats_the_heading_does_not_duplicate_it() {
            let doc = "# T\n\n## Status\n\nold\n";
            let out = edit_section(doc, "Status", "## Status\n\nnew").unwrap();
            assert_eq!(out, "# T\n\n## Status\n\nnew\n");
            let out = add_section("# T\n", "## Notes", "## Notes\n\nfirst").unwrap();
            assert_eq!(out, "# T\n\n## Notes\n\nfirst\n");
            assert_eq!(out.matches("## Notes").count(), 1);
        }

        #[test]
        fn append_lands_above_a_trailing_region_and_separator() {
            let doc = "## Refs\n\n- a\n\n<!-- softfig:backlinks -->\n\n_x_\n\n<!-- /softfig:backlinks -->\n";
            let out = append_to_section(doc, "Refs", "- b").unwrap();
            assert!(out.starts_with("## Refs\n\n- a\n- b\n\n<!-- softfig:backlinks -->"), "{out}");
            let doc = "## A\n\n- a\n\n---\n\n## B\n";
            let out = append_to_section(doc, "A", "- b").unwrap();
            assert_eq!(out, "## A\n\n- a\n- b\n\n---\n\n## B\n");
            // A section holding only a region opens its body above it.
            let doc = "## Idx\n\n<!-- softfig:index notes -->\n\nT\n\n<!-- /softfig:index notes -->\n";
            let out = append_to_section(doc, "Idx", "lead").unwrap();
            assert!(out.starts_with("## Idx\n\nlead\n\n<!-- softfig:index notes -->"), "{out}");
        }

        #[test]
        fn add_section_refuses_to_introduce_a_region() {
            assert_eq!(
                add_section("# T\n", "X", "<!-- softfig:queue -->\n\nq\n\n<!-- /softfig:queue -->"),
                Err(SectionError::ManagedRegion)
            );
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
        fn remove_deletes_heading_body_and_subsections() {
            let doc = "# T\n\n## A\n\nintro\n\n### sub\n\ndetail\n\n## B\n\nb\n";
            let out = remove_section(doc, "A").unwrap();
            assert_eq!(out, "# T\n\n## B\n\nb\n");
        }

        #[test]
        fn remove_last_section_collapses_blank_and_keeps_newline() {
            let doc = "# T\n\n## A\n\nbody\n";
            let out = remove_section(doc, "A").unwrap();
            assert_eq!(out, "# T\n");
            // With a preceding section that itself ends in content.
            let doc = "## A\n\nbody\n\n## B\n\nx\n";
            let out = remove_section(doc, "B").unwrap();
            assert_eq!(out, "## A\n\nbody\n");
        }

        #[test]
        fn remove_first_heading_leaves_following_untouched() {
            let doc = "## A\n\nbody\n\n## B\n\nx\n";
            let out = remove_section(doc, "A").unwrap();
            assert_eq!(out, "## B\n\nx\n");
        }

        #[test]
        fn remove_refuses_the_last_remaining_heading() {
            assert_eq!(
                remove_section("# T\n\nonly section\n", "T"),
                Err(SectionError::LastSection)
            );
            // A parent whose span swallows every subsection is the same
            // refusal — the file would be heading-less either way.
            assert_eq!(
                remove_section("# T\n\n### sub\n\ndetail\n", "T"),
                Err(SectionError::LastSection)
            );
        }

        #[test]
        fn remove_errors_match_the_addressing_rules() {
            let doc = "## A\n\nx\n\n## A\n\ny\n";
            assert_eq!(remove_section(doc, "Nope"), Err(SectionError::NotFound));
            assert_eq!(remove_section(doc, "A"), Err(SectionError::Ambiguous));
            assert_eq!(remove_section(doc, "##"), Err(SectionError::EmptyHeading));
        }

        #[test]
        fn remove_preserves_untouched_regions_byte_identical() {
            let doc = "# T\n\nlead para\n\n## Keep\n\nkeep me\n\n## Gone\n\nold\n";
            let out = remove_section(doc, "Gone").unwrap();
            assert!(out.contains("# T\n\nlead para\n\n## Keep\n\nkeep me\n"));
            assert!(out.ends_with("## Keep\n\nkeep me\n"));
        }

        #[test]
        fn section_range_is_the_deletion_window() {
            let doc = "# T\n\n## A\n\nintro\n\n### sub\n\ndetail\n\n## B\n\nb\n";
            assert_eq!(section_range(doc, "A"), Ok((2, 10)));
            assert_eq!(section_range(doc, "Nope"), Err(SectionError::NotFound));
            assert_eq!(section_range(doc, "##"), Err(SectionError::EmptyHeading));
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

        // ---- Phase 3 CAS: content versions --------------------------------

        #[test]
        fn content_version_is_stable_and_distinguishes() {
            assert_eq!(content_version("abc"), content_version("abc"));
            assert_ne!(content_version("abc"), content_version("abd"));
        }

        #[test]
        fn section_version_changes_only_when_that_section_changes() {
            let doc = "# T\n\n## A\n\nalpha\n\n## B\n\nbeta\n";
            let va = section_version(doc, "A").unwrap();
            let vb = section_version(doc, "B").unwrap();
            assert_ne!(va, vb, "distinct sections hash distinctly");

            // Editing A moves A's version but leaves B's untouched — the CAS
            // basis for "different sections of one file never collide".
            let after = edit_section(doc, "A", "ALPHA!").unwrap();
            assert_ne!(section_version(&after, "A").unwrap(), va);
            assert_eq!(section_version(&after, "B").unwrap(), vb);
        }

        #[test]
        fn section_version_none_for_absent_or_ambiguous() {
            let doc = "## A\n\nx\n\n## A\n\ny\n";
            assert!(section_version(doc, "Nope").is_none());
            assert!(section_version(doc, "A").is_none()); // ambiguous
            assert!(section_version(doc, "##").is_none()); // empty heading
        }

        #[test]
        fn section_versions_lists_every_heading_in_order() {
            let doc = "# Title\n\n## A\n\na\n\n## B\n\nb\n";
            let vs = section_versions(doc);
            let headings: Vec<&str> = vs.iter().map(|(h, _)| h.as_str()).collect();
            assert_eq!(headings, vec!["Title", "A", "B"]);
            // Each entry matches the per-heading section_version.
            for (h, v) in &vs {
                assert_eq!(section_version(doc, h).as_deref(), Some(v.as_str()));
            }
        }
    }
}
