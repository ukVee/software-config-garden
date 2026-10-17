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
//! [`conventions`](super::conventions) and the FUSE handlers use.

use std::path::{Path, PathBuf};

use softfig_fuse::MountHandle;
use softfig_ipc::ErrorKind;

use crate::daemon::{Daemon, DaemonInner};

type ActionResult = Result<(), (ErrorKind, String)>;

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

    /// The write-side refusal for a non-garden-relative `rel` (both backends:
    /// the FUSE overlay is keyed by the string, so a `..` there would stage a
    /// tree entry no path can name).
    fn require_garden_rel(rel: &str) -> ActionResult {
        if is_garden_rel(rel) {
            Ok(())
        } else {
            Err((
                ErrorKind::BadArgs,
                format!("{rel:?}: not a garden-relative path (no `..`, root, or prefix components)"),
            ))
        }
    }

    /// Every check [`write`](Self::write) applies before it touches anything —
    /// the path shape and the key-before-content refusal — without writing.
    /// Multi-file verbs (`batch`, the reindex sweep) run this over every target
    /// before the first write, so a refusal can't land half their writes.
    pub fn check_write(&self, rel: &str) -> ActionResult {
        Self::require_garden_rel(rel)?;
        self.refuse_unkeyed_shared(rel)
    }

    /// [`check_write`](Self::check_write) plus the content check
    /// [`write`](Self::write) makes for these exact bytes: §6.7's guard on a
    /// member's `> Model:` lines ([`member_model_refusal`]). A verb that stages
    /// more than one file runs this over each before its first write, like
    /// `check_write`.
    pub fn check_write_bytes(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        self.check_write(rel)?;
        self.guard_member_models(rel, Some(bytes))
    }

    /// §6.7's `> Model:` guard for replacing `rel` with `new` (`None` = removing
    /// it): a no-op unless this request runs for a fleet member
    /// ([`crate::caller`]) and `rel` lies under `growlight/backlog/`.
    fn guard_member_models(&self, rel: &str, new: Option<&[u8]>) -> ActionResult {
        let Some(member) = crate::caller::member() else {
            return Ok(());
        };
        if !is_backlog_rel(rel) {
            return Ok(());
        }
        let old = self.read(rel);
        let text = |b: Option<&[u8]>| b.map(|b| String::from_utf8_lossy(b).into_owned());
        let (old, new) = (text(old.as_deref()), text(new));
        match member_model_refusal(&member, rel, old.as_deref(), new.as_deref()) {
            Some(why) => Err((ErrorKind::BadArgs, why)),
            None => Ok(()),
        }
    }

    /// The same guard for removing `rel`, which may be a whole directory:
    /// refused for a member when it removes a `> Model:` line under
    /// `growlight/backlog/` — a doc there carrying one, a directory holding
    /// such a doc, or an ancestor of the backlog itself.
    fn guard_member_model_removal(&self, rel: &str) -> ActionResult {
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
        match self.first_model_doc(&scope) {
            Some((doc, text)) => Err(refusal(&member, &doc, Some(&text), None)),
            None => Ok(()),
        }
    }

    /// The guard for a rename: moving `from` removes its lines from where they
    /// were, moving it into the backlog adds them at `to` (whatever `from`
    /// is), and replacing an existing `to` removes the destination's.
    fn guard_member_rename(&self, from: &str, to: &str) -> ActionResult {
        let Some(member) = crate::caller::member() else {
            return Ok(());
        };
        self.guard_member_model_removal(from)?;
        if (is_backlog_rel(to) || spans_backlog(to))
            && let Some((doc, text)) = self.first_model_doc(from) {
                let landing = match doc.strip_prefix(from) {
                    Some(rest) => format!("{to}{rest}"),
                    None => to.to_string(),
                };
                return Err(refusal(&member, &landing, None, Some(&text)));
            }
        self.guard_member_model_removal(to)
    }

    /// The first file at or under `rel` (a file or a directory) carrying a
    /// `> Model:` line, with its text.
    fn first_model_doc(&self, rel: &str) -> Option<(String, String)> {
        if self.is_dir(rel) {
            return self
                .read_dir(rel)
                .into_iter()
                .find_map(|entry| self.first_model_doc(&format!("{rel}/{}", entry.name)));
        }
        let text = String::from_utf8_lossy(&self.read(rel)?).into_owned();
        (!softfig_ipc::queue_v2::model_lines(&text).is_empty()).then(|| (rel.to_string(), text))
    }

    /// Working-tree bytes for repo-relative `rel`, or `None` if absent /
    /// unreadable / a directory.
    pub fn read(&self, rel: &str) -> Option<Vec<u8>> {
        match self {
            WorkTree::Disk { garden_root, .. } => std::fs::read(Self::abs(garden_root, rel)?).ok(),
            WorkTree::Fuse { mount } => {
                is_garden_rel(rel).then(|| mount.read_workfile(rel).ok().flatten())?
            }
        }
    }

    /// Working-tree bytes as UTF-8, or `None` if absent / unreadable / not text.
    pub fn read_to_string(&self, rel: &str) -> Option<String> {
        self.read(rel).and_then(|b| String::from_utf8(b).ok())
    }

    /// Whether `rel` resolves to a live file or directory.
    pub fn exists(&self, rel: &str) -> bool {
        match self {
            WorkTree::Disk { garden_root, .. } => {
                Self::abs(garden_root, rel).is_some_and(|p| p.exists())
            }
            WorkTree::Fuse { mount } => is_garden_rel(rel) && mount.path_exists(rel),
        }
    }

    /// Whether `rel` is a directory.
    pub fn is_dir(&self, rel: &str) -> bool {
        match self {
            WorkTree::Disk { garden_root, .. } => {
                Self::abs(garden_root, rel).is_some_and(|p| p.is_dir())
            }
            WorkTree::Fuse { mount } => is_garden_rel(rel) && mount.path_is_dir(rel),
        }
    }

    /// One-level children of directory `rel` (`""` = garden root). Empty when
    /// the directory is absent. Order is unspecified — callers sort.
    pub fn read_dir(&self, rel: &str) -> Vec<DirEntry> {
        if !is_garden_rel(rel) {
            return Vec::new();
        }
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
    /// adds, removes or changes a `> Model:` line is refused here (§6.7) —
    /// see [`check_write_bytes`](Self::check_write_bytes).
    pub fn write(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        self.check_write_bytes(rel, bytes)?;
        self.stage(rel, bytes)
    }

    /// [`write`](Self::write) without §6.7's member `> Model:` guard, for the
    /// docs keeperd builds itself from a verb's typed fields — the v2 queue
    /// writer ([`super::growlight::v2::apply`]), whose generated `001-plan`
    /// slice carries keeperd's own `> Model:` line, not the caller's. The verb
    /// holds a member's text fields to §6.7 before it gets here.
    pub fn write_structured(&self, rel: &str, bytes: &[u8]) -> ActionResult {
        self.check_write(rel)?;
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
        Self::require_garden_rel(from)?;
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
        Self::require_garden_rel(rel)?;
        self.guard_member_model_removal(rel)?;
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
/// §6.7's `> Model:` guard covers.
fn is_backlog_rel(rel: &str) -> bool {
    let backlog = super::growlight::paths::backlog_dir();
    rel.strip_prefix(backlog.as_str())
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether `rel` is the garden root or an ancestor of `growlight/backlog/`:
/// moving or removing it moves or removes the whole backlog.
fn spans_backlog(rel: &str) -> bool {
    rel.is_empty() || super::growlight::paths::backlog_dir().starts_with(&format!("{rel}/"))
}

/// [`member_model_refusal`] as the worktree's error, for a change the caller
/// already knows touches a `> Model:` line.
fn refusal(member: &str, rel: &str, old: Option<&str>, new: Option<&str>) -> (ErrorKind, String) {
    let why = member_model_refusal(member, rel, old, new)
        .expect("the caller found a `> Model:` line this change touches");
    (ErrorKind::BadArgs, why)
}

/// §6.7's member `> Model:` guard, pure: `Some(refusal)` when replacing
/// `old` with `new` at `rel` (`None` = absent / removed) adds, removes or
/// changes a `> Model:` line ([`softfig_ipc::queue_v2::model_lines`]). The
/// refusal text leads with the wire code, `field_not_allowed`.
pub(crate) fn member_model_refusal(
    member: &str,
    rel: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Option<String> {
    use softfig_ipc::queue_v2::model_lines;
    let before = old.map(model_lines).unwrap_or_default();
    let after = new.map(model_lines).unwrap_or_default();
    if before == after {
        return None;
    }
    let what = match (before.is_empty(), after.is_empty()) {
        (true, _) => "adds a `> Model:` line",
        (false, true) => "removes its `> Model:` line",
        (false, false) => "changes its `> Model:` line",
    };
    Some(format!(
        "field_not_allowed: this write {what} in {rel}, and fleet member {member} may not set a \
         unit's model under growlight/backlog/ (spec-growlight-queue §6.7). A slice body passed to \
         slice_insert, or a member verb's new slice, may declare a subset of what it inherits."
    ))
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
    use std::path::Component;
    Path::new(rel)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
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

    #[test]
    fn the_guard_covers_growlight_backlog_only() {
        assert!(is_backlog_rel("growlight/backlog"));
        assert!(is_backlog_rel("growlight/backlog/milestones/m/slices/001-a.md"));
        assert!(!is_backlog_rel("growlight/backlog-old/x.md"));
        assert!(!is_backlog_rel("growlight/reports/001-x.md"));
        assert!(!is_backlog_rel("projects/p/CLAUDE.md"));
    }

    #[test]
    fn adding_removing_or_changing_a_model_line_is_refused() {
        let rel = "growlight/backlog/milestones/m/slices/001-a.md";
        let add = member_model_refusal("c", rel, Some("# slice\n\nbody\n"), Some(DOC)).unwrap();
        assert!(add.starts_with("field_not_allowed: this write adds"), "{add}");
        let new_file = member_model_refusal("c", rel, None, Some(DOC)).unwrap();
        assert!(new_file.contains("adds"), "{new_file}");
        let change =
            member_model_refusal("c", rel, Some(DOC), Some(&DOC.replace("flash", "claude"))).unwrap();
        assert!(change.contains("changes"), "{change}");
        let remove = member_model_refusal("c", rel, Some(DOC), Some("# slice\n")).unwrap();
        assert!(remove.contains("removes"), "{remove}");
        assert!(member_model_refusal("c", rel, Some(DOC), None).unwrap().contains("removes"));
    }

    use super::super::growlight::unlocked;
    use crate::caller;

    const SLICE: &str = "growlight/backlog/milestones/m/slices/001-a.md";

    /// The guard where every action writes: a member's write under the backlog
    /// that adds, changes or removes a `> Model:` line is refused before it
    /// lands; one that leaves them alone, one outside the backlog, a human's,
    /// and keeperd's own structured write all pass.
    #[test]
    fn a_members_backlog_write_may_not_touch_a_model_line() {
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
    fn a_write_that_leaves_the_model_lines_alone_passes() {
        let rel = "growlight/backlog/milestones/m/CLAUDE.md";
        assert_eq!(member_model_refusal("c", rel, Some(DOC), Some(&format!("{DOC}more\n"))), None);
        assert_eq!(member_model_refusal("c", rel, None, Some("# new doc, no model\n")), None);
        assert_eq!(member_model_refusal("c", rel, Some("prose\n"), None), None);
    }
}
