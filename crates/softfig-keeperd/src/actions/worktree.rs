//! Mount-safe working-tree access for the M3a garden-write actions.
//!
//! In FUSE mode `garden_root` is the mount this daemon serves, so any
//! `std::fs` read/write/stat/readdir against it **while holding
//! `daemon.inner`** is a self-read/-write of the mount — the 2026-06-21
//! commit-path deadlock (an in-flight FUSE op colliding with the daemon's own
//! blocking I/O wedges the whole garden until SIGKILL). 3a removed the commit
//! self-walk; this is the other half: every per-action working-tree touch goes
//! through here.
//!
//! [`WorkTree::Fuse`] routes reads and writes through the FUSE driver's
//! in-memory (tip ∪ overlay) state with no kernel round-trip; staged writes are
//! captured by the next [`commit_now`](super::commit_now) snapshot.
//! [`WorkTree::Disk`] is the byte-for-byte `std::fs` passthrough for non-FUSE
//! (M1c-compat / direct-CLI) daemons — it also keeps the self-write
//! suppression (`mark_self_write`) the inotify watcher relies on; the FUSE
//! backend needs none (a staged overlay write fires no kernel event).
//!
//! Paths are repo-relative strings (`""` = garden root), the same shape
//! [`conventions`](super::conventions) and the FUSE handlers use. Every entry
//! point canonicalises its path first ([`canonical_rel`]), so the guards below
//! never see an alias of a path they cover — `growlight/./backlog/…` and
//! `growlight//backlog/…` name the backlog exactly as `growlight/backlog/…`
//! does (review 042 G74-3).

use std::path::{Path, PathBuf};

use softfig_fuse::MountHandle;
use softfig_ipc::ErrorKind;

use crate::daemon::{Daemon, DaemonInner};

type ActionResult = Result<(), (ErrorKind, String)>;

/// Whose bytes a write carries, for the member guard's managed-region rule
/// (review 042 G74-1): the caller's own ([`WorkTree::write`]), which may not
/// change a daemon-managed region, or the daemon's re-derivation of one
/// ([`WorkTree::write_derived`]), which only ever changes a region.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bytes {
    Caller,
    Derived,
}

/// One entry from [`WorkTree::read_dir`].
pub struct DirEntry {
    /// Final path component (file or directory name).
    pub name: String,
    pub is_dir: bool,
}

/// Filesystem access for an M3a action, backed by the FUSE overlay in FUSE
/// mode and by `std::fs` otherwise. See the module docs.
pub enum WorkTree<'a> {
    Disk {
        daemon: &'a Daemon,
        garden_root: &'a Path,
    },
    Fuse {
        mount: &'a MountHandle,
    },
}

impl<'a> WorkTree<'a> {
    /// Pick the backend from the daemon state: the FUSE mount when one is live,
    /// else the on-disk garden root. Borrows `inner` (the mount / garden root)
    /// and `daemon` (the suppression map) immutably, so it coexists with the
    /// `&DaemonInner` the action's other helpers take and must be dropped
    /// before the trailing `&mut inner` commit.
    pub fn new(daemon: &'a Daemon, inner: &'a DaemonInner) -> WorkTree<'a> {
        match inner.fuse.as_ref() {
            Some(mount) => WorkTree::Fuse { mount },
            None => WorkTree::Disk {
                daemon,
                garden_root: &inner.config.garden_root,
            },
        }
    }

    /// `rel` joined onto the garden root, or `None` when `rel` is not a plain
    /// garden-relative path (see [`is_garden_rel`]). Every `Disk` touch goes
    /// through here, so no caller-supplied string — a verb arg, or a folder
    /// name read out of a managed-region tag — can reach outside the garden.
    fn abs(garden_root: &Path, rel: &str) -> Option<PathBuf> {
        is_garden_rel(rel).then(|| garden_root.join(rel))
    }

    /// The write-side form of [`canonical_rel`]: `rel` rebuilt from its normal
    /// components, or the refusal for a non-garden-relative `rel` (both
    /// backends: the FUSE overlay is keyed by the string, so a `..` there would
    /// stage a tree entry no path can name).
    fn canonical_or_refuse(rel: &str) -> Result<String, (ErrorKind, String)> {
        canonical_rel(rel).ok_or_else(|| {
            (
                ErrorKind::BadArgs,
                format!("{rel:?}: not a garden-relative path (no `..`, root, or prefix components)"),
            )
        })
    }

    /// Every check [`write`](Self::write) applies before it touches anything —
    /// the path shape and the key-before-content refusal — without writing.
    /// Multi-file verbs (`batch`, the reindex sweep) run this over every target
    /// before the first write, so a refusal can't land half their writes.
    pub fn check_write(&self, rel: &str) -> ActionResult {
        let rel = &Self::canonical_or_refuse(rel)?;
        self.refuse_unkeyed_shared(rel)
    }

    /// [`check_write`](Self::check_write) plus the content check
    /// [`write`](Self::write) makes for these exact bytes: the member guards —
    /// no hand edit of a daemon-managed region ([`member_region_refusal`]),
    /// §6.7's reserved `> Model:` / `> Grants:` / `> Worktree:` lines
    /// ([`member_reserved_refusal`]) and the `> Fleet:` hold
    /// ([`member_fleet_refusal`]). A verb that stages more than one file runs
    /// this over each before its first write, like `check_write`.
    pub fn check_write_bytes(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        let rel = &Self::canonical_or_refuse(rel)?;
        self.check_write(rel)?;
        self.guard_member_write(rel, Some(bytes), Bytes::Caller)
    }

    /// The member guards for replacing `rel` with `new` (`None` = removing it).
    /// Anywhere in the garden, the caller's bytes may not change a
    /// daemon-managed region ([`member_region_refusal`]; `bytes` says whether
    /// they are the caller's). Under `growlight/backlog/`, the three reserved
    /// metadata lines (`> Model:`, `> Grants:`, `> Worktree:`) are
    /// member-immutable and the `> Fleet:` line is member-tighten-only (see
    /// [`member_reserved_refusal`] / [`member_fleet_refusal`]). A no-op unless
    /// this request runs for a fleet member ([`crate::caller`]).
    fn guard_member_write(&self, rel: &str, new: Option<&[u8]>, bytes: Bytes) -> ActionResult {
        let Some(member) = crate::caller::member() else {
            return Ok(());
        };
        let old = self.read(rel);
        let text = |b: Option<&[u8]>| b.map(|b| String::from_utf8_lossy(b).into_owned());
        let (old, new) = (text(old.as_deref()), text(new));
        if bytes == Bytes::Caller
            && let Some(why) = member_region_refusal(&member, rel, old.as_deref(), new.as_deref())
        {
            return Err((ErrorKind::BadArgs, why));
        }
        if !is_backlog_rel(rel) {
            return Ok(());
        }
        if let Some(why) = member_vault_refusal(&member, rel, old.as_deref(), new.as_deref()) {
            return Err((ErrorKind::BadArgs, why));
        }
        if let Some(why) = member_reserved_refusal(&member, rel, old.as_deref(), new.as_deref()) {
            return Err((ErrorKind::BadArgs, why));
        }
        if let Some(why) = member_fleet_refusal(&member, rel, old.as_deref(), new.as_deref()) {
            return Err((ErrorKind::BadArgs, why));
        }
        if old.is_none() && new.is_some() && is_item_doc_path(rel) {
            return Err((ErrorKind::BadArgs, member_item_doc_refusal(&member, rel, "write creates")));
        }
        Ok(())
    }

    /// The same guard for removing `rel`, which may be a whole directory:
    /// refused for a member when it removes a reserved `> Model:` / `> Grants:`
    /// / `> Worktree:` line or loosens a held `> Fleet:` line under
    /// `growlight/backlog/` — a doc there carrying one, a directory holding such
    /// a doc, or an ancestor of the backlog itself.
    fn guard_member_removal(&self, rel: &str) -> ActionResult {
        let Some(member) = crate::caller::member() else {
            return Ok(());
        };
        let scope = if spans_backlog(rel) {
            super::growlight::paths::backlog_dir()
        } else if is_backlog_rel(rel) {
            rel.to_string()
        } else {
            return Ok(());
        };
        if let Some((doc, text)) = self.first_reserved_doc(&scope) {
            return Err(reserved_refusal(&member, &doc, Some(&text), None));
        }
        if let Some((doc, text)) = self.first_fleet_doc(&scope) {
            return Err(fleet_refusal(&member, &doc, Some(&text), None));
        }
        if let Some((doc, text)) = self.first_doc_with(&scope, |t| !super::managed::regions(t).is_empty()) {
            let why = member_region_refusal(&member, &doc, Some(&text), None)
                .expect("a doc carrying a managed region");
            return Err((ErrorKind::BadArgs, why));
        }
        Ok(())
    }

    /// The guard for a rename: moving `from` removes its lines from where they
    /// were, moving it into the backlog adds them at `to` (whatever `from`
    /// is), and replacing an existing `to` removes the destination's. A reserved
    /// `> Model:` / `> Grants:` / `> Worktree:` line is refused in both
    /// directions; `> Fleet:` only in the loosening one (a member may move a
    /// held doc *into* the backlog — that tightens).
    fn guard_member_rename(&self, from: &str, to: &str) -> ActionResult {
        let Some(member) = crate::caller::member() else {
            return Ok(());
        };
        self.guard_member_removal(from)?;
        if (is_backlog_rel(to) || spans_backlog(to))
            && let Some((doc, text)) = self.first_reserved_doc(from) {
                let landing = match doc.strip_prefix(from) {
                    Some(rest) => format!("{to}{rest}"),
                    None => to.to_string(),
                };
                return Err(reserved_refusal(&member, &landing, None, Some(&text)));
            }
        if let Some(landing) = self.landings(from, to).into_iter().find(|l| is_item_doc_path(l)) {
            return Err((ErrorKind::BadArgs, member_item_doc_refusal(&member, &landing, "rename lands on")));
        }
        self.guard_member_removal(to)
    }

    /// Where each file at or under `from` lands when `from` is renamed to
    /// `to`: `to` itself for a file, `to/<rest>` for each file in a directory.
    fn landings(&self, from: &str, to: &str) -> Vec<String> {
        if !self.is_dir(from) {
            return vec![to.to_string()];
        }
        let mut out = Vec::new();
        let mut stack = vec![from.to_string()];
        while let Some(dir) = stack.pop() {
            for entry in self.read_dir(&dir) {
                let child = format!("{dir}/{}", entry.name);
                if entry.is_dir {
                    stack.push(child);
                } else {
                    out.push(format!("{to}{}", &child[from.len()..]));
                }
            }
        }
        out
    }

    /// The first file at or under `rel` (a file or a directory) whose text
    /// satisfies `pred`, with its text.
    fn first_doc_with(
        &self,
        rel: &str,
        pred: impl Fn(&str) -> bool + Copy,
    ) -> Option<(String, String)> {
        if self.is_dir(rel) {
            return self.read_dir(rel).into_iter().find_map(|entry| {
                self.first_doc_with(&format!("{rel}/{}", entry.name), pred)
            });
        }
        let text = String::from_utf8_lossy(&self.read(rel)?).into_owned();
        pred(&text).then(|| (rel.to_string(), text))
    }

    /// The first file at or under `rel` carrying a reserved `> Model:` /
    /// `> Grants:` / `> Worktree:` line, with its text.
    fn first_reserved_doc(&self, rel: &str) -> Option<(String, String)> {
        use softfig_ipc::queue_v2::{reserved_field, SUB_DOC_RESERVED};
        self.first_doc_with(rel, |t| reserved_field(t, &SUB_DOC_RESERVED).is_some())
    }

    /// The first file at or under `rel` carrying a held `> Fleet:` line, with
    /// its text.
    fn first_fleet_doc(&self, rel: &str) -> Option<(String, String)> {
        self.first_doc_with(rel, softfig_ipc::fleet::held)
    }

    /// Working-tree bytes for repo-relative `rel`, or `None` if absent /
    /// unreadable / a directory.
    pub fn read(&self, rel: &str) -> Option<Vec<u8>> {
        let rel = &canonical_rel(rel)?;
        match self {
            WorkTree::Disk { garden_root, .. } => std::fs::read(Self::abs(garden_root, rel)?).ok(),
            WorkTree::Fuse { mount } => mount.read_workfile(rel).ok().flatten(),
        }
    }

    /// Working-tree bytes as UTF-8, or `None` if absent / unreadable / not text.
    pub fn read_to_string(&self, rel: &str) -> Option<String> {
        self.read(rel).and_then(|b| String::from_utf8(b).ok())
    }

    /// Whether `rel` resolves to a live file or directory.
    pub fn exists(&self, rel: &str) -> bool {
        let Some(rel) = &canonical_rel(rel) else {
            return false;
        };
        match self {
            WorkTree::Disk { garden_root, .. } => {
                Self::abs(garden_root, rel).is_some_and(|p| p.exists())
            }
            WorkTree::Fuse { mount } => mount.path_exists(rel),
        }
    }

    /// Whether `rel` is a directory.
    pub fn is_dir(&self, rel: &str) -> bool {
        let Some(rel) = &canonical_rel(rel) else {
            return false;
        };
        match self {
            WorkTree::Disk { garden_root, .. } => {
                Self::abs(garden_root, rel).is_some_and(|p| p.is_dir())
            }
            WorkTree::Fuse { mount } => mount.path_is_dir(rel),
        }
    }

    /// One-level children of directory `rel` (`""` = garden root). Empty when
    /// the directory is absent. Order is unspecified — callers sort.
    pub fn read_dir(&self, rel: &str) -> Vec<DirEntry> {
        let Some(rel) = &canonical_rel(rel) else {
            return Vec::new();
        };
        match self {
            WorkTree::Disk { garden_root, .. } => {
                let mut out = Vec::new();
                let Some(abs) = Self::abs(garden_root, rel) else {
                    return out;
                };
                if let Ok(rd) = std::fs::read_dir(abs) {
                    for e in rd.flatten() {
                        let Ok(name) = e.file_name().into_string() else {
                            continue;
                        };
                        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                        out.push(DirEntry { name, is_dir });
                    }
                }
                out
            }
            WorkTree::Fuse { mount } => mount
                .read_dir_entries(rel)
                .into_iter()
                .map(|(name, is_dir)| DirEntry { name, is_dir })
                .collect(),
        }
    }

    /// M5f slice 001 (key-before-content): refuse an action-verb write landing
    /// under an enabled shared mount whose key ceremony has not run yet. The
    /// commit path's `encrypt_for_ref` backstop would refuse to seal it anyway,
    /// but only after staging — leaving the overlay holding content whose
    /// chain can't advance, and failing the verb *after* its device-chain
    /// commit. Refusing here surfaces the clear error to the caller with
    /// nothing staged. Disk mode has no shared chains (`add` refuses in direct
    /// mode), so only the FUSE arm can trip.
    fn refuse_unkeyed_shared(&self, rel: &str) -> ActionResult {
        if let WorkTree::Fuse { mount } = self
            && let Some(share) = mount.unkeyed_shared_owner(rel) {
                return Err((
                    ErrorKind::SharedChainUnkeyed,
                    format!(
                        "{rel} is inside shared subtree {share:?}, which has no established \
                         key yet (key-before-content): content is accepted only after the \
                         share's key ceremony — run/accept the ceremony first"
                    ),
                ));
            }
        Ok(())
    }

    /// Create-or-overwrite repo-relative `rel`. Disk: create parent dirs +
    /// register the path for self-write suppression so the watcher drops the
    /// event, then write. FUSE: stage into the overlay (no kernel event).
    ///
    /// For a fleet member's request, a write under `growlight/backlog/` that
    /// adds, removes or changes a reserved `> Model:` / `> Grants:` /
    /// `> Worktree:` line (or loosens a `> Fleet:` hold) is refused here
    /// (§6.7) — see [`check_write_bytes`](Self::check_write_bytes).
    pub fn write(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        let rel = &Self::canonical_or_refuse(rel)?;
        self.check_write_bytes(rel, bytes)?;
        self.stage(rel, bytes)
    }

    /// [`write`](Self::write) without §6.7's member reserved-line guard, for
    /// the docs keeperd builds itself from a verb's typed fields — the v2 queue
    /// writer ([`super::growlight::v2::apply`]), whose generated `001-plan`
    /// slice carries keeperd's own `> Model:` line, not the caller's. The verb
    /// holds a member's text fields to §6.7 before it gets here.
    pub fn write_structured(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        let rel = &Self::canonical_or_refuse(rel)?;
        self.check_write(rel)?;
        self.stage(rel, bytes)
    }

    /// [`write`](Self::write) for the daemon's own re-derivation of a managed
    /// region — an index `Reviewed` cell, a backlinks list, a growlight queue
    /// table its verb moved, the reports index. The bytes are the doc as it
    /// stood with only that region rewritten, so the member guard's
    /// managed-region refusal (review 042 G74-1) does not apply; every other
    /// check `write` makes still does. A member's own bytes go through
    /// [`write`](Self::write), never here.
    pub fn write_derived(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        let rel = &Self::canonical_or_refuse(rel)?;
        self.check_write(rel)?;
        self.guard_member_write(rel, Some(bytes), Bytes::Derived)?;
        self.stage(rel, bytes)
    }

    /// The backend half of a write, every check already made.
    fn stage(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        match self {
            WorkTree::Disk { daemon, garden_root } => {
                let abs = garden_root.join(rel);
                daemon.mark_self_write(abs.clone());
                super::write_file(&abs, bytes)
            }
            WorkTree::Fuse { mount } => {
                mount.stage_write(rel, bytes.to_vec());
                Ok(())
            }
        }
    }

    /// Rename `from` → `to` (file or directory). Disk: `std::fs::rename` with
    /// both sides suppressed and the destination parent created. FUSE: re-key
    /// the overlay (descendants included). The destination gets the
    /// key-before-content refusal (m5f slice 001); the source side stays
    /// unguarded — moving *out* of an unkeyed share adds no blob to it.
    pub fn rename(&self, from: &str, to: &str) -> ActionResult {
        let (from, to) = (&Self::canonical_or_refuse(from)?, &Self::canonical_or_refuse(to)?);
        self.check_write(to)?;
        self.guard_member_rename(from, to)?;
        match self {
            WorkTree::Disk { daemon, garden_root } => {
                let from_abs = garden_root.join(from);
                let to_abs = garden_root.join(to);
                daemon.mark_self_write(from_abs.clone());
                daemon.mark_self_write(to_abs.clone());
                if let Some(parent) = to_abs.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| (ErrorKind::Io, e.to_string()))?;
                }
                std::fs::rename(&from_abs, &to_abs)
                    .map_err(|e| (ErrorKind::Io, format!("rename: {e}")))
            }
            WorkTree::Fuse { mount } => mount
                .stage_rename(from, to)
                .map_err(|e| (ErrorKind::Io, format!("stage rename: {e}"))),
        }
    }

    /// Recursively remove repo-relative `rel` (a file or a whole directory).
    /// Disk: `std::fs` remove with self-write suppression; an already-absent
    /// path is a no-op. FUSE: stage a recursive removal marker into the overlay
    /// (captured by the next [`commit_now`](super::commit_now)). The m5f slice
    /// 004 `migrate-into-share` device-side carve-out — run only AFTER the
    /// content is durably re-committed into the shared chain — is the only
    /// caller today; a removal carries no key-before-content concern (it strips
    /// a blob, never adds one), so no `refuse_unkeyed_shared` guard is needed.
    pub fn remove(&self, rel: &str) -> ActionResult {
        let rel = &Self::canonical_or_refuse(rel)?;
        self.guard_member_removal(rel)?;
        match self {
            WorkTree::Disk { daemon, garden_root } => {
                let abs = garden_root.join(rel);
                daemon.mark_self_write(abs.clone());
                if abs.is_dir() {
                    std::fs::remove_dir_all(&abs)
                        .map_err(|e| (ErrorKind::Io, format!("remove_dir_all {rel}: {e}")))
                } else {
                    match std::fs::remove_file(&abs) {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(e) => Err((ErrorKind::Io, format!("remove_file {rel}: {e}"))),
                    }
                }
            }
            WorkTree::Fuse { mount } => {
                mount.stage_remove(rel);
                Ok(())
            }
        }
    }
}

/// Whether repo-relative `rel` lies under `growlight/backlog/` — the tree
/// §6.7's reserved-line and `> Fleet:` guards cover.
fn is_backlog_rel(rel: &str) -> bool {
    let backlog = super::growlight::paths::backlog_dir();
    rel.strip_prefix(backlog.as_str())
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The inline `<vault …>…</vault>` regions in `text`, as `(open tag, body)`
/// pairs in order. A plain scan, deliberately wider than the vault's own
/// markdown-masked parser (a tag inside a code span counts here too), because
/// the member guard that reads it fails closed.
fn vault_regions(text: &str) -> Vec<(&str, &str)> {
    const CLOSE: &str = "</vault>";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("<vault") {
        let tag = &rest[i..];
        let Some(open_end) = tag.find('>') else {
            out.push((tag, ""));
            break;
        };
        let body = &tag[open_end + 1..];
        match body.find(CLOSE) {
            Some(j) => {
                out.push((&tag[..=open_end], &body[..j]));
                rest = &body[j + CLOSE.len()..];
            }
            None => {
                out.push((&tag[..=open_end], body));
                break;
            }
        }
    }
    out
}

/// The member vault-region guard, pure: `Some(refusal)` when replacing `old`
/// with `new` at `rel` adds, removes or changes an inline `<vault>` region.
/// Re-sending a region's `[encrypted]` placeholder unchanged — what a member
/// reads back — leaves it alone.
///
/// Review 042 G74-4: the reserved-line and `> Fleet:` guards compare the
/// plaintext a member writes, so wrapping `> Fleet: no` as
/// `<vault id="h">\n> Fleet: no\n</vault>` passed them — held before, held
/// after — while growlightd's redacted read then saw `[encrypted]` and no
/// hold. Under `growlight/backlog/` a member may not seal anything; the
/// readers also fail closed on a sealed region
/// ([`softfig_ipc::item_meta::unreadable_metadata`]). The refusal text leads
/// with the wire code, `member_not_allowed`.
pub(crate) fn member_vault_refusal(
    member: &str,
    rel: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Option<String> {
    let before = old.map(vault_regions).unwrap_or_default();
    let after = new.map(vault_regions).unwrap_or_default();
    let unchanged = before.len() == after.len()
        && before
            .iter()
            .zip(&after)
            .all(|((old_tag, old_body), (new_tag, new_body))| {
                old_tag == new_tag && (old_body == new_body || *new_body == "[encrypted]")
            });
    (!unchanged).then(|| {
        format!(
            "member_not_allowed: this write adds, removes or changes an inline `<vault>` region in \
             {rel}, and fleet member {member} may not seal or unseal anything under \
             growlight/backlog/ — a sealed region reads as `[encrypted]` to growlightd, so it \
             could hide a `> Fleet:` / `> Model:` / `> Worktree:` line. Write the text in the \
             clear; secrets do not belong in backlog docs. (spec-growlight-queue §6.7)"
        )
    })
}

/// Whether canonical `rel` is an item-doc path — a doc a growlight reader looks
/// an item or slice up by: a task doc (`…/tasks/*.md`), a `CLAUDE.md` (the
/// backlog doc, a milestone's, a sub-milestone's) or a slice doc
/// (`…/slices/*.md`), under `growlight/backlog/`.
fn is_item_doc_path(rel: &str) -> bool {
    if !is_backlog_rel(rel) {
        return false;
    }
    let mut parts = rel.rsplit('/');
    let name = parts.next().unwrap_or_default();
    let parent = parts.next().unwrap_or_default();
    name == "CLAUDE.md" || (name.ends_with(".md") && matches!(parent, "tasks" | "slices"))
}

/// Review 042 G74-2: a member may not create an item doc, nor rename a file
/// onto one. The readers find an item's doc by its number, so a second
/// `066-0.md` beside `066-loop-self-extend.md` could shadow it — dropping its
/// `> Fleet: no` hold, or naming another model or worktree. (The readers also
/// fail closed on two docs for one number; this keeps a member from making the
/// second.) Members are already refused `add_backlog_item` / `add_slice`. The
/// refusal text leads with the wire code, `member_not_allowed`.
fn member_item_doc_refusal(member: &str, rel: &str, what: &str) -> String {
    format!(
        "member_not_allowed: this {what} the item doc {rel}, and fleet member {member} may not \
         create one — a task doc, a backlog / milestone / sub-milestone CLAUDE.md or a slice doc. \
         Readers look an item up by its number, so a new doc beside the real one would shadow \
         it. The human seeds items and slices (add_backlog_item / add_slice); under queue v2 a \
         member adds a slice with slice_insert. (spec-growlight-queue §6.7)"
    )
}

/// Whether `rel` is the garden root or an ancestor of `growlight/backlog/`:
/// moving or removing it moves or removes the whole backlog.
fn spans_backlog(rel: &str) -> bool {
    rel.is_empty() || super::growlight::paths::backlog_dir().starts_with(&format!("{rel}/"))
}

/// [`member_reserved_refusal`] as the worktree's error, for a change the caller
/// already knows touches a reserved `> Model:` / `> Grants:` / `> Worktree:`
/// line.
fn reserved_refusal(
    member: &str,
    rel: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> (ErrorKind, String) {
    let why = member_reserved_refusal(member, rel, old, new)
        .expect("the caller found a reserved `> key:` line this change touches");
    (ErrorKind::BadArgs, why)
}

/// §6.7's member reserved-line guard, pure: `Some(refusal)` when replacing
/// `old` with `new` at `rel` (`None` = absent / removed) adds, removes or
/// changes a `> <key>:` line for any key in
/// [`softfig_ipc::queue_v2::SUB_DOC_RESERVED`] — the `> Model:`, `> Grants:`
/// and `> Worktree:` lines §6.7 reserves to humans. Two reads of the one
/// scanner ([`softfig_ipc::item_meta`]) are compared: every raw line (fenced or
/// not — an edit to a fenced example is refused too), and the value a resolver
/// reads ([`softfig_ipc::item_meta::field`] — so a fence opened or closed
/// around a real declaration, which moves no raw line, is refused as well;
/// review 042 G74-6). The refusal text leads with the wire code,
/// `field_not_allowed`.
pub(crate) fn member_reserved_refusal(
    member: &str,
    rel: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Option<String> {
    use softfig_ipc::item_meta::{display_key, field, reserved_lines};
    use softfig_ipc::queue_v2::SUB_DOC_RESERVED;
    for key in SUB_DOC_RESERVED {
        let before = old.map(|t| reserved_lines(t, &[key])).unwrap_or_default();
        let after = new.map(|t| reserved_lines(t, &[key])).unwrap_or_default();
        let resolved_same = old.and_then(|t| field(t, key)) == new.and_then(|t| field(t, key));
        let what = match (before.is_empty(), after.is_empty()) {
            _ if before == after && resolved_same => continue,
            _ if before == after => format!(
                "changes which `> {}:` line its resolver reads (a fence opened or closed around \
                 one)",
                display_key(key)
            ),
            (true, _) => format!("adds a `> {}:` line", display_key(key)),
            (false, true) => format!("removes its `> {}:` line", display_key(key)),
            (false, false) => format!("changes its `> {}:` line", display_key(key)),
        };
        let key = display_key(key);
        return Some(format!(
            "field_not_allowed: this write {what} in {rel}, and fleet member {member} may not \
             add, remove or change a `> {key}:` line under growlight/backlog/ \
             (spec-growlight-queue §6.7). Leave the line as it is; if it is wrong, file_report \
             it or post_message @human. A slice body handed to slice_insert / slice_update may \
             still declare `> Model:`, a subset of what the entry allows."
        ));
    }
    None
}

/// The member managed-region guard, pure: `Some(refusal)` when replacing `old`
/// with `new` at `rel` (`None` = absent / removed) changes a daemon-managed
/// `<!-- softfig:… -->` region — edits its body, adds one (a new doc carrying
/// a marker counts), or drops one ([`super::managed::changed_regions`]).
///
/// Review 042 G74-1: the region verbs (`patch_file`, the section verbs,
/// `batch`) already refuse a region change for every caller, but
/// `replace_file` is break-glass and does not, and growlightd schedules from
/// the queue tables it would rewrite — another item's status, the row order,
/// a `## Queues` repo cell (tomorrow's `$REPO` grant). A region is the
/// daemon's: derived (an index, backlinks) or owned (a queue table only the
/// growlight verbs move). The human keeps break-glass; a member does not. The
/// refusal text leads with the wire code, `member_not_allowed`.
pub(crate) fn member_region_refusal(
    member: &str,
    rel: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Option<String> {
    let changed = super::managed::changed_regions(old.unwrap_or(""), new.unwrap_or(""));
    if changed.is_empty() {
        return None;
    }
    Some(format!(
        "member_not_allowed: this write changes the daemon-managed `{}` region in {rel}, and \
         fleet member {member} may not edit one by hand — an index or backlinks table is \
         derived, and a growlight queue table moves only through the growlight verbs. Edit \
         the prose around it; if the region itself is wrong, file_report it or post_message \
         @human. (spec-growlight-queue §6.7)",
        changed.join("`, `")
    ))
}

/// [`member_fleet_refusal`] as the worktree's error, for a change the caller
/// already knows loosens or removes a held `> Fleet:` line.
fn fleet_refusal(member: &str, rel: &str, old: Option<&str>, new: Option<&str>) -> (ErrorKind, String) {
    let why = member_fleet_refusal(member, rel, old, new)
        .expect("the caller found a held `> Fleet:` line this change loosens");
    (ErrorKind::BadArgs, why)
}

/// The member `> Fleet:` guard, pure: `Some(refusal)` when replacing `old`
/// with `new` at `rel` (`None` = absent / removed) loosens or removes a
/// `> Fleet:` hold ([`softfig_ipc::fleet_marker`]): the doc goes from held (a
/// non-`yes` value) to claimable (`yes`, or no line). Adding a line or
/// tightening one — claimable → held — is allowed, because it fails closed.
/// The refusal text leads with the wire code, `field_not_allowed`.
pub(crate) fn member_fleet_refusal(
    member: &str,
    rel: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Option<String> {
    let before = old.and_then(softfig_ipc::fleet_marker);
    let after = new.and_then(softfig_ipc::fleet_marker);
    if before.is_some() && after.is_none() {
        Some(format!(
            "field_not_allowed: this write loosens or removes the `> Fleet:` hold in {rel}, and \
             fleet member {member} may only add or tighten one (growlight/backlog/CLAUDE.md \
             'Marking an item human-only'). Only the human removes it to free the item."
        ))
    } else {
        None
    }
}

/// Whether `rel` is a plain garden-relative path: `""` (the garden root) or
/// only normal components (`.` allowed). `..`, an absolute path, or a Windows
/// prefix is refused. Verb args are validated upstream by
/// `validate_repo_path`, but not every `rel` a verb touches comes from an arg —
/// task 060's index upkeep reads folder names out of `<!-- softfig:index … -->`
/// tags in file *content* — so the worktree enforces the shape itself (review
/// 031 D2: a `../../x/notes` tag read and wrote outside the garden in Disk
/// mode).
pub fn is_garden_rel(rel: &str) -> bool {
    canonical_rel(rel).is_some()
}

/// `rel` rebuilt from its normal components, `/`-joined — the one spelling of
/// a garden path every guard compares against. A `.` component, a doubled or
/// trailing `/` all drop out (`growlight/./backlog//x/` → `growlight/backlog/x`;
/// `""` and `.` are the garden root, `""`). `None` when `rel` is not plain
/// garden-relative: a `..`, an absolute path, a Windows prefix, or a component
/// that is not UTF-8.
///
/// Review 042 G74-3: without it a member's `growlight/./backlog/…` passed
/// `validate_repo_path` (an interior `.` is no `..`), skipped the backlog
/// guards (a raw prefix test), and landed on the real doc — `Path` equality,
/// the disk join and the FUSE overlay's component-keyed paths all read the
/// alias as the same file.
pub fn canonical_rel(rel: &str) -> Option<String> {
    use std::path::Component;
    let mut parts: Vec<&str> = Vec::new();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.join("/"))
}

/// The minimal working-tree surface a `.seq`-numbered doc store needs: read a
/// file, list a directory, test existence, stage a write. Implemented by
/// [`WorkTree`] for live daemons and by an in-memory fake in unit tests, so the
/// numbered-store machinery ([`super::numbering`] + the growlight chat store)
/// can be exercised with no daemon/mount behind it. The four methods mirror the
/// inherent [`WorkTree`] methods of the same name; generic store code binds to
/// the trait, concrete daemon code keeps calling the inherent methods.
pub trait Tree {
    fn read_to_string(&self, rel: &str) -> Option<String>;
    fn read_dir(&self, rel: &str) -> Vec<DirEntry>;
    fn exists(&self, rel: &str) -> bool;
    fn write(&self, rel: &str, bytes: &[u8]) -> ActionResult;
    /// Every refusal `write(rel, bytes)` would make, without writing — so a
    /// store can refuse a doc before it stages the `.seq` bump ahead of it.
    /// Default: nothing to refuse (the in-memory test fake).
    fn check_write_bytes(&self, _rel: &str, _bytes: &[u8]) -> ActionResult {
        Ok(())
    }
}

impl Tree for WorkTree<'_> {
    fn read_to_string(&self, rel: &str) -> Option<String> {
        WorkTree::read_to_string(self, rel)
    }
    fn read_dir(&self, rel: &str) -> Vec<DirEntry> {
        WorkTree::read_dir(self, rel)
    }
    fn exists(&self, rel: &str) -> bool {
        WorkTree::exists(self, rel)
    }
    fn write(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        WorkTree::write(self, rel, bytes)
    }
    fn check_write_bytes(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        WorkTree::check_write_bytes(self, rel, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "# slice\n\n> Model: flash\n\nbody\n";
    const FLEET_HELD: &str = "# slice\n\n> Fleet: no\n\nbody\n";

    #[test]
    fn the_guard_covers_growlight_backlog_only() {
        assert!(is_backlog_rel("growlight/backlog"));
        assert!(is_backlog_rel("growlight/backlog/milestones/m/slices/001-a.md"));
        assert!(!is_backlog_rel("growlight/backlog-old/x.md"));
        assert!(!is_backlog_rel("growlight/reports/001-x.md"));
        assert!(!is_backlog_rel("projects/p/CLAUDE.md"));
    }

    #[test]
    fn adding_removing_or_changing_a_reserved_line_is_refused() {
        let rel = "growlight/backlog/milestones/m/slices/001-a.md";
        let cases = [
            ("Model", "# slice\n\n> Model: flash\n\nbody\n", "# slice\n\n> Model: claude\n\nbody\n"),
            ("Grants", "# slice\n\n> Grants: ~/x\n\nbody\n", "# slice\n\n> Grants: ~/y\n\nbody\n"),
            ("Worktree", "# slice\n\n> Worktree: /tmp/x\n\nbody\n", "# slice\n\n> Worktree: /tmp/y\n\nbody\n"),
        ];
        for (key, doc, changed) in cases {
            let add = member_reserved_refusal("c", rel, Some("# slice\n\nbody\n"), Some(doc)).unwrap();
            assert!(add.starts_with("field_not_allowed: this write adds"), "{add}");
            assert!(add.contains(&format!("`> {key}:`")), "{add}");
            let new_file = member_reserved_refusal("c", rel, None, Some(doc)).unwrap();
            assert!(new_file.contains("adds"), "{new_file}");
            let change = member_reserved_refusal("c", rel, Some(doc), Some(changed)).unwrap();
            assert!(change.contains("changes"), "{change}");
            let remove = member_reserved_refusal("c", rel, Some(doc), Some("# slice\n")).unwrap();
            assert!(remove.contains("removes"), "{remove}");
            assert!(member_reserved_refusal("c", rel, Some(doc), None).unwrap().contains("removes"));
        }
    }

    use super::super::growlight::unlocked;
    use crate::caller;

    const SLICE: &str = "growlight/backlog/milestones/m/slices/001-a.md";

    /// The guard where every action writes: a member's write under the backlog
    /// that adds, changes or removes a reserved `> Model:` / `> Grants:` /
    /// `> Worktree:` line is refused before it lands; one that leaves them
    /// alone, one outside the backlog, a human's, and keeperd's own structured
    /// write all pass. The `> Model:` flow is exercised here; the grants and
    /// worktree keys get their own matrix in the next test.
    #[test]
    fn a_members_backlog_write_may_not_touch_a_reserved_line() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        wt.write(SLICE, b"# a\n\nbody\n").unwrap();
        {
            let _member = caller::enter(Some("c".into()));
            let err = wt.write(SLICE, DOC.as_bytes()).unwrap_err();
            assert_eq!(err.0, ErrorKind::BadArgs);
            assert!(err.1.starts_with("field_not_allowed:"), "{err:?}");
            assert_eq!(wt.read_to_string(SLICE).as_deref(), Some("# a\n\nbody\n"), "nothing written");
            wt.write(SLICE, b"# a\n\nmore body\n").expect("no model line touched");
            wt.write("projects/p/notes/001-x.md", DOC.as_bytes()).expect("outside the backlog");
        }
        wt.write(SLICE, DOC.as_bytes()).expect("a human may set a model");
        {
            let _member = caller::enter(Some("c".into()));
            assert!(wt.write(SLICE, DOC.replace("flash", "claude").as_bytes()).is_err(), "change");
            assert!(wt.write(SLICE, b"# a\n").is_err(), "remove");
            assert!(wt.check_write_bytes(SLICE, b"# a\n").is_err(), "the pre-check agrees");
            assert!(wt.remove(SLICE).is_err(), "deleting the doc removes its line");
            assert!(wt.rename(SLICE, "archive/001-a.md").is_err(), "so does moving it out");
            assert!(wt.remove("growlight/backlog/milestones/m").is_err(), "a directory holding one");
            assert!(wt.remove("growlight").is_err(), "an ancestor of the backlog");
            assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(DOC), "all refused untouched");
            wt.write("projects/p/notes/002-y.md", DOC.as_bytes()).expect("outside the backlog");
            let moved_in = wt
                .rename("projects/p/notes/002-y.md", "growlight/backlog/milestones/m/slices/002-y.md")
                .unwrap_err();
            assert!(moved_in.1.contains("adds a `> Model:` line"), "moving one in adds it: {moved_in:?}");
            wt.rename("projects/p/notes/001-x.md", "projects/p/notes/003-x.md")
                .expect("a rename outside the backlog is not the guard's");
            wt.write_structured(SLICE, b"# a\n").expect("keeperd's own structured write");
        }
    }

    /// The same worktree-level guard refuses a member's add, change and remove
    /// of a `> Grants:` or `> Worktree:` line (report 020), across write,
    /// `check_write_bytes`, `unlink` (remove) and rename-out. A human may set
    /// and change either.
    #[test]
    fn a_members_backlog_write_may_not_touch_a_grants_or_worktree_line() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let cases = [
            ("# slice\n\n> Grants: ~/x\n\nbody\n", "# slice\n\n> Grants: ~/y\n\nbody\n"),
            ("# slice\n\n> Worktree: /tmp/x\n\nbody\n", "# slice\n\n> Worktree: /tmp/y\n\nbody\n"),
        ];
        for (doc, changed) in cases {
            wt.write(SLICE, b"# a\n\nbody\n").expect("reset");
            {
                let _member = caller::enter(Some("c".into()));
                let err = wt.write(SLICE, doc.as_bytes()).unwrap_err();
                assert_eq!(err.0, ErrorKind::BadArgs);
                assert!(err.1.starts_with("field_not_allowed:"), "{err:?}");
                assert_eq!(wt.read_to_string(SLICE).as_deref(), Some("# a\n\nbody\n"), "add refused");
                wt.write(SLICE, b"# a\n\nmore\n").expect("a write touching no reserved line");
            }
            wt.write(SLICE, doc.as_bytes()).expect("a human may set the line");
            {
                let _member = caller::enter(Some("c".into()));
                assert!(wt.write(SLICE, changed.as_bytes()).is_err(), "change refused");
                assert!(wt.write(SLICE, b"# a\n").is_err(), "remove refused");
                assert!(wt.check_write_bytes(SLICE, b"# a\n").is_err(), "pre-check agrees");
                assert!(wt.remove(SLICE).is_err(), "unlink removes the line");
                assert!(wt.rename(SLICE, "archive/001-a.md").is_err(), "rename-out removes it");
                assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(doc), "untouched");
            }
        }
    }

    /// A refused doc refuses before the `.seq` bump stages: no number burned.
    #[test]
    fn a_refused_numbered_doc_burns_no_seq_number() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let dir = "growlight/backlog/milestones/m/slices";
        let _member = caller::enter(Some("c".into()));
        let err = super::super::numbering::write_numbered(&wt, dir, 1, SLICE, DOC).unwrap_err();
        assert!(err.1.starts_with("field_not_allowed:"), "{err:?}");
        let seq = format!("{dir}/{}", super::super::conventions::SEQ_FILE);
        assert!(!wt.exists(&seq) && !wt.exists(SLICE), "nothing staged");
    }

    /// `batch` validates every op before the first write: a member's op that
    /// adds a `> Model:` line fails the batch with the ops before it unstaged.
    #[test]
    fn a_members_batch_with_a_model_line_stages_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let note = "projects/p/notes/001-x.md";
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            wt.write(note, b"# x\n\nold\n").unwrap();
            wt.write(SLICE, b"# a\n\nbody\n").unwrap();
        }
        let patch = |path: &str, old: &str, new: &str| {
            serde_json::json!({ "op": "patch_file", "args": { "path": path, "old": old, "new": new } })
        };
        let args = serde_json::json!({ "ops": [
            patch(note, "old", "new"),
            patch(SLICE, "body", "> Model: flash\n\nbody"),
        ] });
        let err = {
            let _member = caller::enter(Some("c".into()));
            super::super::batch(&daemon, args.clone()).unwrap_err()
        };
        assert!(err.1.contains("op[1]") && err.1.contains("field_not_allowed:"), "{err:?}");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        assert_eq!(wt.read_to_string(note).as_deref(), Some("# x\n\nold\n"), "op 0 unstaged");
        drop(inner);
        super::super::batch(&daemon, args).expect("a human's batch lands");
    }

    #[test]
    fn a_write_that_leaves_the_reserved_lines_alone_passes() {
        let rel = "growlight/backlog/milestones/m/CLAUDE.md";
        assert_eq!(member_reserved_refusal("c", rel, Some(DOC), Some(&format!("{DOC}more\n"))), None);
        assert_eq!(member_reserved_refusal("c", rel, None, Some("# new doc, no reserved line\n")), None);
        assert_eq!(member_reserved_refusal("c", rel, Some("prose\n"), None), None);
        // Prose and inline-code mentions are not metadata lines: no refusal.
        assert_eq!(member_reserved_refusal("c", rel, Some("Grants: ~/x in prose\n"), Some("ok\n")), None);
        assert_eq!(member_reserved_refusal("c", rel, Some("`> Worktree: /tmp/x`\n"), None), None);
    }

    /// A reserved line inside a fenced code block still matches: the guard
    /// compares every raw line, fenced or not, as well as the resolved value,
    /// so a member can neither edit a fenced line nor toggle a fence to change
    /// what the resolver reads. (Over-guarding a fenced example is a benign
    /// false positive, not a hole.)
    #[test]
    fn a_fenced_reserved_line_still_matches() {
        let rel = "growlight/backlog/milestones/m/slices/001-a.md";
        let fenced = "```\n> Model: flash\n```\n";
        assert!(
            member_reserved_refusal("c", rel, Some("# t\n"), Some(fenced)).is_some(),
            "adding a fenced model line is still refused",
        );
        assert!(
            member_reserved_refusal("c", rel, Some(fenced), Some("# t\n")).is_some(),
            "removing a fenced model line is still refused",
        );
    }

    /// Review 042 G74-4: a member may not wrap a backlog doc's metadata in an
    /// inline `<vault>` region (or otherwise add, drop or change one), while
    /// re-sending an existing region's `[encrypted]` placeholder untouched —
    /// what a member reads back — still lets it edit around the region.
    #[test]
    fn a_member_may_not_seal_a_backlog_line_in_a_vault_region() {
        let wrapped = "# slice\n\n<vault id=\"h\">\n> Fleet: no\n</vault>\n\nbody\n";
        let rel = "growlight/backlog/milestones/m/slices/001-a.md";
        let why = member_vault_refusal("c", rel, Some(FLEET_HELD), Some(wrapped)).unwrap();
        assert!(why.starts_with("member_not_allowed:"), "{why}");
        let sealed = "# s\n<vault id=\"k\">c2VjcmV0</vault>\nbody\n";
        let edited = "# s\n<vault id=\"k\">[encrypted]</vault>\nmore body\n";
        assert_eq!(member_vault_refusal("c", rel, Some(sealed), Some(edited)), None, "edit around it");
        assert!(member_vault_refusal("c", rel, Some(sealed), Some("# s\nbody\n")).is_some(), "dropping it");
        assert!(
            member_vault_refusal("c", rel, Some(sealed), Some(&sealed.replace("c2VjcmV0", "new"))).is_some(),
            "re-sealing new text"
        );

        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        wt.write(SLICE, FLEET_HELD.as_bytes()).unwrap();
        let _member = caller::enter(Some("c".into()));
        assert!(wt.write(SLICE, wrapped.as_bytes()).is_err(), "the wrap is refused");
        assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(FLEET_HELD), "nothing written");
        wt.write("projects/p/notes/001-x.md", wrapped.as_bytes()).expect("outside the backlog");
    }

    /// Review 042 G74-2: a member may not create an item doc — a task doc, a
    /// `CLAUDE.md` under the backlog, a slice doc — nor rename a file or a
    /// directory onto one. Editing an existing one (no reserved line touched)
    /// and creating any other backlog file stay allowed.
    #[test]
    fn a_member_may_not_create_or_rename_onto_an_item_doc() {
        assert!(is_item_doc_path("growlight/backlog/tasks/066-0.md"));
        assert!(is_item_doc_path("growlight/backlog/milestones/m/CLAUDE.md"));
        assert!(is_item_doc_path("growlight/backlog/milestones/m/subs/s/CLAUDE.md"));
        assert!(is_item_doc_path("growlight/backlog/milestones/m/slices/002-x.md"));
        assert!(!is_item_doc_path("growlight/backlog/milestones/m/notes/001-x.md"));
        assert!(!is_item_doc_path("projects/p/tasks/001-x.md"), "outside the backlog");

        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let task = "growlight/backlog/tasks/066-loop-self-extend.md";
        let wt = WorkTree::new(&daemon, &inner);
        wt.write(task, FLEET_HELD.as_bytes()).unwrap();
        wt.write("projects/p/drafts/tasks/066-0.md", b"# shadow\n").unwrap();
        let _member = caller::enter(Some("c".into()));
        for shadow in [
            "growlight/backlog/tasks/066-0.md",
            "growlight/backlog/milestones/n/CLAUDE.md",
            "growlight/backlog/milestones/m/slices/001-shadow.md",
        ] {
            let err = wt.write(shadow, b"# x\n").unwrap_err();
            assert!(err.1.starts_with("member_not_allowed:") && err.1.contains("write creates"), "{err:?}");
            assert!(!wt.exists(shadow), "{shadow}: nothing written");
        }
        assert!(
            wt.rename("projects/p/drafts/tasks/066-0.md", "growlight/backlog/tasks/066-0.md").is_err(),
            "a file renamed onto an item-doc path"
        );
        assert!(
            wt.rename("projects/p/drafts", "growlight/backlog/milestones/m/drafts").is_err(),
            "a directory whose files land on item-doc paths"
        );
        wt.write(task, format!("{FLEET_HELD}more\n").as_bytes()).expect("editing the real doc");
        wt.write("growlight/backlog/milestones/m/notes/001-x.md", b"# n\n")
            .expect("a backlog file that is not an item doc");
    }

    /// Review 042 G74-1: a member's own bytes may not change a daemon-managed
    /// region anywhere — edit its body, add one, or drop one — while the
    /// daemon's re-derivation (`write_derived`) still lands under the member's
    /// scope, and the prose around a region stays the member's to edit.
    #[test]
    fn a_members_write_may_not_change_a_managed_region() {
        let host = "growlight/backlog/CLAUDE.md";
        let table = |status: &str| {
            format!(
                "# backlog\n\nprose\n\n<!-- softfig:queue -->\n\n| # | id | type | title | status |\n\
                 |---|----|------|-------|--------|\n| 1 | 066 | task | T | {status} |\n\n\
                 <!-- /softfig:queue -->\n"
            )
        };
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        wt.write(host, table("queued").as_bytes()).unwrap();
        let _member = caller::enter(Some("c".into()));
        let err = wt.write(host, table("done").as_bytes()).unwrap_err();
        assert!(err.1.starts_with("member_not_allowed:") && err.1.contains("`queue` region"), "{err:?}");
        assert!(wt.write(host, b"# backlog\n\nthe table is gone\n").is_err(), "dropping it");
        assert!(wt.check_write_bytes(host, table("done").as_bytes()).is_err(), "the pre-check agrees");
        assert!(
            wt.write("projects/p/notes/001-x.md", table("queued").as_bytes()).is_err(),
            "a new doc carrying a region marker, outside the backlog too"
        );
        assert!(wt.remove(host).is_err(), "deleting the queue doc");
        assert_eq!(wt.read_to_string(host), Some(table("queued")), "all refused untouched");
        wt.write(host, table("queued").replace("prose", "edited prose").as_bytes())
            .expect("the prose around the region is the member's");
        wt.write_derived(host, table("done").replace("prose", "edited prose").as_bytes())
            .expect("the daemon's re-derivation of the region");
    }

    /// Review 042 G74-3: every spelling of a garden path canonicalises to one,
    /// and a member's write, removal or rename through an alias of a guarded
    /// backlog doc is refused exactly as through its canonical path.
    #[test]
    fn a_path_alias_of_the_backlog_is_still_guarded() {
        assert_eq!(
            canonical_rel("growlight/./backlog//tasks/001-x.md/").as_deref(),
            Some("growlight/backlog/tasks/001-x.md")
        );
        assert_eq!(canonical_rel("./growlight").as_deref(), Some("growlight"));
        assert_eq!(canonical_rel(".").as_deref(), Some(""));
        assert_eq!(canonical_rel("growlight/../etc"), None);
        assert_eq!(canonical_rel("/etc/passwd"), None);

        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        wt.write(SLICE, FLEET_HELD.as_bytes()).unwrap();
        let _member = caller::enter(Some("c".into()));
        for alias in [
            "growlight/./backlog/milestones/m/slices/001-a.md",
            "growlight//backlog/milestones/m/slices/001-a.md",
            "./growlight/backlog/milestones/m/slices/001-a.md",
        ] {
            assert!(wt.write(alias, b"# a\n").is_err(), "write {alias}");
            assert!(wt.remove(alias).is_err(), "remove {alias}");
            assert!(wt.rename(alias, "archive/001-a.md").is_err(), "rename {alias}");
        }
        assert!(wt.remove("growlight/./backlog").is_err(), "an aliased backlog dir");
        assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(FLEET_HELD), "all refused untouched");
    }

    /// Review 042 G74-6: a fence line inserted above a `> Worktree:` declaration
    /// moves no raw line, but the repo resolver stops reading it — refused, in
    /// both directions, through the pure guard and a real worktree write.
    #[test]
    fn a_fence_that_hides_or_reveals_a_reserved_line_is_refused() {
        let rel = "growlight/backlog/tasks/001-x.md";
        let declared = "# t\n\n> Worktree: /tmp/x\n";
        let hidden = "# t\n\n```\n> Worktree: /tmp/x\n";
        let why = member_reserved_refusal("c", rel, Some(declared), Some(hidden)).unwrap();
        assert!(why.contains("changes which `> Worktree:` line"), "{why}");
        assert!(member_reserved_refusal("c", rel, Some(hidden), Some(declared)).is_some(), "un-hiding");

        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        wt.write(rel, declared.as_bytes()).unwrap();
        let _member = caller::enter(Some("c".into()));
        assert!(wt.write(rel, hidden.as_bytes()).is_err(), "the fence trick is refused");
        assert_eq!(wt.read_to_string(rel).as_deref(), Some(declared), "nothing written");
    }

    /// The `> Fleet:` guard is tighten-only in the pure sense: a member's write
    /// may add a line or tighten one (claimable → held), but never remove or
    /// loosen one (held → claimable), matching the resolver's "first line wins"
    /// and "fenced code doesn't count" reads.
    #[test]
    fn the_fleet_guard_is_tighten_only() {
        let rel = "growlight/backlog/milestones/m/CLAUDE.md";
        // Tighten: claimable → held is allowed (fails closed).
        assert_eq!(member_fleet_refusal("c", rel, Some("# t\n"), Some("> Fleet: no\n")), None);
        assert_eq!(member_fleet_refusal("c", rel, Some("> Fleet: yes\n"), Some("> Fleet: no\n")), None);
        // Loosen / remove: held → claimable is refused.
        assert!(member_fleet_refusal("c", rel, Some("> Fleet: no\n"), Some("> Fleet: yes\n")).is_some());
        assert!(member_fleet_refusal("c", rel, Some("> Fleet: no\n"), Some("# t\n")).is_some());
        assert!(member_fleet_refusal("c", rel, Some("> Fleet: no\n"), None).is_some());
        // Inserting a `yes` before the first `no` line flips the resolved marker.
        assert!(
            member_fleet_refusal(
                "c",
                rel,
                Some("> Fleet: no\n> Fleet: yes\n"),
                Some("> Fleet: yes\n> Fleet: no\n"),
            )
            .is_some()
        );
        // A held value changed to another non-`yes` value stays held: allowed.
        assert_eq!(member_fleet_refusal("c", rel, Some("> Fleet: no\n"), Some("> Fleet: nope\n")), None);
        // A non-holding line is not protected.
        assert_eq!(member_fleet_refusal("c", rel, Some("# t\n"), Some("> Fleet: yes\n")), None);
        assert_eq!(member_fleet_refusal("c", rel, Some("> Fleet: yes\n"), Some("# t\n")), None);
        // A fenced example is not a marker, so removing it is allowed …
        assert_eq!(
            member_fleet_refusal("c", rel, Some("```\n> Fleet: no\n```\n"), Some("# t\n")),
            None,
        );
        // … but a real line after the fence is held, so removing it is refused.
        assert!(
            member_fleet_refusal(
                "c",
                rel,
                Some("```\n> Fleet: no\n```\n> Fleet: no\n"),
                Some("```\n> Fleet: no\n```\n"),
            )
            .is_some()
        );
    }

    /// The worktree-level `> Fleet:` guard: a member may add/tighten a line but
    /// never loosen/remove it, across write, `check_write_bytes`, `unlink`
    /// (remove), `archive` (rename out), directory/ancestor removal, and a
    /// rename *into* the backlog (which is a tighten, so allowed). A human may
    /// remove the line.
    #[test]
    fn a_members_backlog_write_may_not_loosen_or_remove_a_fleet_line() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        wt.write(SLICE, b"# a\n\nbody\n").unwrap();
        {
            let _member = caller::enter(Some("c".into()));
            // Add a hold: allowed (fails closed).
            wt.write(SLICE, FLEET_HELD.as_bytes()).expect("adding a hold");
            assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(FLEET_HELD));
            // Loosen: refused.
            let loosened = FLEET_HELD.replace("> Fleet: no", "> Fleet: yes");
            let err = wt.write(SLICE, loosened.as_bytes()).unwrap_err();
            assert_eq!(err.0, ErrorKind::BadArgs);
            assert!(err.1.contains("loosens or removes") && err.1.contains("member c"), "{err:?}");
            assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(FLEET_HELD), "nothing written");
            // Remove: refused (and the pre-check agrees).
            assert!(wt.write(SLICE, b"# slice\n\nbody\n").is_err(), "remove the line");
            assert!(wt.check_write_bytes(SLICE, b"# slice\n\nbody\n").is_err(), "pre-check");
            // unlink / archive / directory / ancestor removal all refused.
            assert!(wt.remove(SLICE).is_err(), "unlink removes the hold");
            assert!(wt.rename(SLICE, "archive/001-a.md").is_err(), "archive moves it out");
            assert!(wt.remove("growlight/backlog/milestones/m").is_err(), "a dir holding one");
            assert!(wt.remove("growlight").is_err(), "an ancestor of the backlog");
            assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(FLEET_HELD), "all refused untouched");
            // Moving a held doc INTO the backlog tightens: allowed — onto any
            // path but an item doc's (G74-2: a new slice doc could shadow one).
            wt.write("projects/p/notes/020-z.md", FLEET_HELD.as_bytes()).expect("seed outside");
            let shadow = wt
                .rename("projects/p/notes/020-z.md", "growlight/backlog/milestones/m/slices/020-z.md")
                .unwrap_err();
            assert!(shadow.1.contains("rename lands on the item doc"), "{shadow:?}");
            wt.rename("projects/p/notes/020-z.md", "growlight/backlog/milestones/m/notes/020-z.md")
                .expect("moving a held doc in is a tighten");
            // Outside the backlog is not the guard's.
            wt.write("projects/p/notes/021-x.md", FLEET_HELD.as_bytes()).expect("outside add");
            wt.write("projects/p/notes/021-x.md", b"# a\n").expect("outside loosen is fine");
        }
        // A human may remove the line (this frees the item).
        wt.write(SLICE, b"# slice\n\nbody\n").expect("the human removes it");
    }

    /// `batch` validates every op before the first write: a member's op that
    /// loosens a `> Fleet:` line fails the batch with the ops before it unstaged.
    #[test]
    fn a_members_batch_that_loosens_a_fleet_line_stages_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let note = "projects/p/notes/001-x.md";
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            wt.write(note, b"# x\n\nold\n").unwrap();
            wt.write(SLICE, FLEET_HELD.as_bytes()).unwrap();
        }
        let patch = |path: &str, old: &str, new: &str| {
            serde_json::json!({ "op": "patch_file", "args": { "path": path, "old": old, "new": new } })
        };
        let args = serde_json::json!({ "ops": [
            patch(note, "old", "new"),
            patch(SLICE, "> Fleet: no", "> Fleet: yes"),
        ] });
        let err = {
            let _member = caller::enter(Some("c".into()));
            super::super::batch(&daemon, args.clone()).unwrap_err()
        };
        assert!(err.1.contains("op[1]") && err.1.contains("loosens or removes"), "{err:?}");
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        assert_eq!(wt.read_to_string(note).as_deref(), Some("# x\n\nold\n"), "op 0 unstaged");
        assert_eq!(wt.read_to_string(SLICE).as_deref(), Some(FLEET_HELD), "op 1 unstaged");
        drop(inner);
        super::super::batch(&daemon, args).expect("a human's batch lands");
    }
}
