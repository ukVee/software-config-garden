//! Filesystem watcher. Source-agnostic accumulator + inotify driver.
//!
//! [`DirtySetAccumulator`] owns the dirty-set buffer, the VCS-ignore
//! filter (`softfig_vcs::ignore` — `.softfig`, `.claude`, …), the daemon's
//! self-event suppression-map check, and the flush
//! hook (→ classifier → `commit_workdir`). Sources push [`DirtyEvent`]s
//! into it. The inotify driver here is one such source; M2a's FUSE
//! driver will be the next.
//!
//! Semantics preserved bit-for-bit from M1c: 200 ms debounce (provided
//! by the source — `notify-debouncer-full` for inotify), 500 ms suppress
//! TTL (in [`Daemon`]), the same `EventKind` → dirty-set translation,
//! and the same `manual_edit`-with-no-files drop.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecursiveMode, Watcher};
use notify_debouncer_full::{new_debouncer, DebounceEventResult};
use softfig_vcs::{ignore, Intent};

use crate::classify::{self, DirtySet};
use crate::daemon::{Daemon, DaemonInner, SUPPRESS_WINDOW_MS};
use crate::state::State;

/// Time the source waits between bursts before flushing the accumulator.
/// Sources are responsible for honoring this; the inotify driver gets it
/// for free from `notify-debouncer-full`.
pub const DEBOUNCE_MS: u64 = 200;
const STATE_POLL_MS: u64 = 100;

// ─── DirtyEvent ───────────────────────────────────────────────────────────

/// One semantic change reported by a source. Repo-relative paths.
/// Sources translate their native event shape into these variants.
#[derive(Debug, Clone)]
pub enum DirtyEvent {
    Created(String),
    Modified(String),
    Removed(String),
    Renamed { from: String, to: String },
}

// ─── DirtySetAccumulator ─────────────────────────────────────────────────

#[derive(Default, Debug)]
struct Buffer {
    created: HashSet<String>,
    modified: HashSet<String>,
    removed: HashSet<String>,
    renamed_to_archive: Vec<(String, String)>,
}

impl Buffer {
    fn into_dirty_set(self) -> DirtySet {
        let created = self.created;
        let mut modified = self.modified;
        let removed = self.removed;
        // Created+modified collapses to created.
        for r in &created {
            modified.remove(r);
        }
        let mut created_v: Vec<String> = created.into_iter().collect();
        let mut modified_v: Vec<String> = modified.into_iter().collect();
        let mut removed_v: Vec<String> = removed.into_iter().collect();
        created_v.sort();
        modified_v.sort();
        removed_v.sort();

        DirtySet {
            created: created_v,
            modified: modified_v,
            removed: removed_v,
            renamed_to_archive: self.renamed_to_archive,
        }
    }
}

/// Source-agnostic accumulator. Sources push [`DirtyEvent`]s; on each
/// `flush()` the buffered events are coalesced, classified, and (if the
/// classification is non-empty) committed via `commit_workdir`.
///
/// Filters applied at push time:
/// - `.softfig/` paths (daemon-internal state).
/// - Paths the daemon has marked as self-writes (per the 500 ms
///   suppress map keyed off the user-visible garden root).
///
/// Holds bare `Arc`s into the daemon (instead of a full [`Daemon`]
/// clone) so [`Daemon::new`] can construct the accumulator before the
/// daemon itself is fully assembled — no chicken-and-egg.
#[derive(Debug)]
pub struct DirtySetAccumulator {
    inner: Arc<Mutex<DaemonInner>>,
    suppress: Arc<Mutex<HashMap<PathBuf, Instant>>>,
    /// User-visible garden root. In M1c this equals the watched root;
    /// in M2a it is the FUSE mount path (the suppress map keys off
    /// joins against this path either way).
    garden_root: PathBuf,
    buffer: Mutex<Buffer>,
}

impl DirtySetAccumulator {
    pub fn new(
        inner: Arc<Mutex<DaemonInner>>,
        suppress: Arc<Mutex<HashMap<PathBuf, Instant>>>,
        garden_root: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            suppress,
            garden_root,
            buffer: Mutex::new(Buffer::default()),
        })
    }

    pub fn garden_root(&self) -> &Path {
        &self.garden_root
    }

    /// Filter + record one event. Returns whether anything was buffered
    /// (false = filtered for `.softfig/` or suppress map; for renames,
    /// only false when both sides are filtered).
    pub fn push(&self, ev: DirtyEvent) -> bool {
        let mut buf = self.buffer.lock().unwrap();
        match ev {
            DirtyEvent::Created(p) => {
                if !self.accept(&p) {
                    return false;
                }
                buf.created.insert(p);
                true
            }
            DirtyEvent::Modified(p) => {
                if !self.accept(&p) {
                    return false;
                }
                buf.modified.insert(p);
                true
            }
            DirtyEvent::Removed(p) => {
                if !self.accept(&p) {
                    return false;
                }
                buf.removed.insert(p);
                true
            }
            DirtyEvent::Renamed { from, to } => {
                let f_ok = self.accept(&from);
                let t_ok = self.accept(&to);
                match (f_ok, t_ok) {
                    (false, false) => false,
                    (true, true) => {
                        if to.starts_with("journal/archive/") {
                            buf.renamed_to_archive.push((from, to));
                        } else {
                            buf.removed.insert(from);
                            buf.created.insert(to);
                        }
                        true
                    }
                    // Partial survival mirrors M1c's "defensive: treat as
                    // plain modifications" branch — only the surviving
                    // side becomes a modified entry.
                    (true, false) => {
                        buf.modified.insert(from);
                        true
                    }
                    (false, true) => {
                        buf.modified.insert(to);
                        true
                    }
                }
            }
        }
    }

    /// Take the buffered events, run them through `classify`, and
    /// `commit_workdir` if the classification is non-empty. No-op on an
    /// empty buffer or on an empty `manual_edit`.
    ///
    /// M2c: between classify and commit, the accumulator scans every
    /// `manual_edit` candidate path for newly-introduced `<vault>` ids
    /// (via [`crate::layer_b::promote_manual_edit_for_new_ids`]). When
    /// any new id is present, the intent is replaced with a batched
    /// `vault_seal`. Then the prior-tip plaintext snapshot is
    /// installed on the layer_b hook so the commit's region encoder
    /// can re-embed `[encrypted]` placeholders byte-identically.
    pub fn flush(&self) {
        let dirty = {
            let mut buf = self.buffer.lock().unwrap();
            std::mem::take(&mut *buf).into_dirty_set()
        };
        if dirty.is_empty() {
            return;
        }
        let classified = classify::classify(&dirty);
        if classified.intent == "manual_edit"
            && classified
                .payload
                .get("files")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty())
        {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.state != State::Unlocked {
            return;
        }
        let garden_root = inner.config.garden_root.clone();
        let inner = &mut *inner;
        let session = match inner.session.as_ref() {
            Some(s) => s.clone(),
            None => return,
        };
        let hook = inner.layer_b.clone();
        // In FUSE mode commit from the in-memory (tip ∪ overlay) snapshot, not
        // by walking `garden_root` (= the mount this daemon serves) — the
        // 2026-06-21 commit-path deadlock. Captured before borrowing `repo`
        // (disjoint `DaemonInner` field) and before the commit clears the
        // overlay. Manual editor writes already live in the overlay (kernel →
        // FUSE write handler), so the flush just snapshots them.
        let fuse_snapshot = match inner.fuse.as_ref() {
            Some(mount) => match mount.workdir_snapshot() {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("keeperd: watcher: workdir snapshot failed: {e}");
                    return;
                }
            },
            None => None,
        };
        let repo = match inner.repo.as_mut() {
            Some(r) => r,
            None => return,
        };

        // Prior-tip snapshot is needed twice: once to decide whether a
        // `manual_edit` should be promoted to `vault_seal`, and once
        // to back the region encoder's placeholder preservation. Build
        // it once and reuse.
        let prior_snap = match crate::layer_b::build_prior_tip_snapshot(repo, &session) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("keeperd: watcher: prior-tip snapshot failed: {e}");
                return;
            }
        };

        let promoted = if classified.intent == "manual_edit" {
            let touched_paths: Vec<String> = dirty.all_paths();
            crate::layer_b::promote_manual_edit_for_new_ids(
                &touched_paths,
                &garden_root,
                &session,
                &prior_snap,
            )
        } else {
            None
        };

        let intent = if let Some(p) = promoted {
            p
        } else {
            match Intent::new(&classified.intent, classified.payload) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("keeperd: watcher: invalid auto-classified intent: {e}");
                    return;
                }
            }
        };

        hook.install_prior_tip(prior_snap);
        let result = match fuse_snapshot {
            Some(snapshot) => repo.commit_snapshot(&session, snapshot, intent),
            None => repo.commit_workdir(&session, intent),
        };
        hook.clear_prior_tip();
        if let Err(e) = result {
            eprintln!("keeperd: watcher: commit failed: {e}");
        }
    }

    /// True if the path should be buffered: not VCS-ignored and not currently
    /// in the daemon's self-write suppression map.
    ///
    /// The ignore test here is the **pure built-in predicate**
    /// (`softfig_vcs::ignore::is_ignored` — `.softfig`, `.claude`) and reads
    /// nothing from disk. It must not read disk: in FUSE mode `self.garden_root`
    /// IS the mount this code runs against, and the fuser worker thread calls
    /// the dirty-set sink synchronously, so an `Ignore::load` of
    /// `<root>/.softfigignore` would issue a read whose kernel LOOKUP only the
    /// same blocked worker can service — the self-walk-under-mount reentrant
    /// deadlock (audit slice 003; the `.softfigignore` feature reintroduced it
    /// and it is reverted here).
    ///
    /// The push-time filter is only an optimization. The user-overridable
    /// `.softfigignore` set is still enforced authoritatively at commit time
    /// from in-memory state — `workdir_snapshot`/`inmem_ignore` (FUSE) and
    /// `walk()` (direct) build the full `Ignore` and re-apply it — so a
    /// user-ignored path is never committed; it just isn't dropped quite this
    /// early. Restoring early user-entry filtering without a mount read (a
    /// cached in-memory `Ignore`, refreshed only when `.softfigignore` itself
    /// changes) is deferred to task 005.
    fn accept(&self, rel: &str) -> bool {
        let p = Path::new(rel);
        if ignore::is_ignored(p) {
            return false;
        }
        if self.is_self_write(&self.garden_root.join(rel)) {
            return false;
        }
        true
    }

    fn is_self_write(&self, path: &Path) -> bool {
        // Lazy prune.
        let now = Instant::now();
        let mut map = self.suppress.lock().unwrap();
        map.retain(|_, until| *until > now);
        let _ = SUPPRESS_WINDOW_MS; // referenced for docs/exports.
        map.contains_key(path)
    }
}

// ─── DirtySetSource trait ────────────────────────────────────────────────

/// A driver that feeds events into a [`DirtySetAccumulator`]. The
/// inotify driver in this module is the M1d implementation; M2a's FUSE
/// driver will be the next.
///
/// Sources whose lifecycle does not fit "spawn a thread that loops"
/// (e.g., FUSE, where handlers are called by the kernel) are free to
/// hold an `Arc<DirtySetAccumulator>` directly without implementing
/// this trait — the trait is the convenient shape for thread-driven
/// sources, not a hard contract.
pub trait DirtySetSource: Send + 'static {
    /// Drive events from this source. Called on a dedicated thread and
    /// must return when the daemon transitions to [`State::Stopping`].
    fn run(self, accumulator: Arc<DirtySetAccumulator>, daemon: Daemon);
}

// ─── InotifyDriver ───────────────────────────────────────────────────────

/// `notify-debouncer-full`-backed source. Recursive watch on the
/// configured `garden_root`; each debounced batch becomes a series of
/// `accumulator.push(...)` calls plus one `accumulator.flush()`.
#[derive(Debug)]
pub struct InotifyDriver {
    /// Repo root in non-canonical form. Used so per-event repo-relative
    /// paths round-trip through the daemon's suppress map (which keys
    /// off `garden_root.join(rel)`).
    garden_root: PathBuf,
    /// Canonicalized once so notify's absolute event paths strip cleanly.
    watch_root: PathBuf,
}

impl InotifyDriver {
    pub fn new(garden_root: PathBuf) -> Self {
        let watch_root = garden_root
            .canonicalize()
            .unwrap_or_else(|_| garden_root.clone());
        Self {
            garden_root,
            watch_root,
        }
    }

    fn process_batch(
        &self,
        accumulator: &DirtySetAccumulator,
        events: Vec<notify_debouncer_full::DebouncedEvent>,
    ) {
        for de in events {
            let kind = de.event.kind;
            // Translate notify's absolute paths into repo-relative
            // strings; drop anything outside the watch root. The
            // accumulator does the `.softfig/` + suppress-map filtering.
            let rels: Vec<String> = de
                .event
                .paths
                .iter()
                .filter_map(|abs| repo_relative(abs, &self.garden_root, &self.watch_root))
                .collect();
            if rels.is_empty() {
                continue;
            }

            match kind {
                EventKind::Create(_) => {
                    for r in rels {
                        accumulator.push(DirtyEvent::Created(r));
                    }
                }
                EventKind::Remove(_) => {
                    for r in rels {
                        accumulator.push(DirtyEvent::Removed(r));
                    }
                }
                EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                    if rels.len() == 2 {
                        accumulator.push(DirtyEvent::Renamed {
                            from: rels[0].clone(),
                            to: rels[1].clone(),
                        });
                    } else {
                        // Defensive: notify reported a Both-mode rename
                        // with !=2 paths. Treat as modifications.
                        for r in rels {
                            accumulator.push(DirtyEvent::Modified(r));
                        }
                    }
                }
                EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
                    for r in rels {
                        accumulator.push(DirtyEvent::Removed(r));
                    }
                }
                EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
                    for r in rels {
                        accumulator.push(DirtyEvent::Created(r));
                    }
                }
                EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Any) => {
                    for r in rels {
                        accumulator.push(DirtyEvent::Modified(r));
                    }
                }
                // Skip metadata-only changes (atime, permissions) and
                // other kinds.
                _ => {}
            }
        }
        accumulator.flush();
    }
}

impl DirtySetSource for InotifyDriver {
    fn run(self, accumulator: Arc<DirtySetAccumulator>, daemon: Daemon) {
        // Wait for unlock (or shutdown) before installing inotify watches.
        loop {
            match daemon.state() {
                State::Unlocked => break,
                State::Stopping => return,
                State::Locked => std::thread::sleep(Duration::from_millis(STATE_POLL_MS)),
            }
        }

        let (tx, rx) = mpsc::channel::<DebounceEventResult>();
        let mut debouncer = match new_debouncer(
            Duration::from_millis(DEBOUNCE_MS),
            None,
            move |res: DebounceEventResult| {
                let _ = tx.send(res);
            },
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("keeperd: watcher: failed to create debouncer: {e}");
                return;
            }
        };

        if let Err(e) = debouncer
            .watcher()
            .watch(&self.watch_root, RecursiveMode::Recursive)
        {
            eprintln!(
                "keeperd: watcher: failed to watch {}: {e}",
                self.watch_root.display()
            );
            return;
        }

        loop {
            if daemon.state() == State::Stopping {
                break;
            }
            match rx.recv_timeout(Duration::from_millis(STATE_POLL_MS)) {
                Ok(Ok(events)) => {
                    self.process_batch(&accumulator, events);
                }
                Ok(Err(errs)) => {
                    for e in errs {
                        eprintln!("keeperd: watcher: notify error: {e}");
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        debouncer.stop();
    }
}

// ─── module entry ────────────────────────────────────────────────────────

/// Spawn the inotify-backed source feeding the daemon's shared
/// accumulator. M1c-compat: watches `garden_root`. Public API preserved
/// from M1c so the existing `server::start` path is untouched.
pub fn spawn(daemon: Daemon) -> std::thread::JoinHandle<()> {
    let garden_root = daemon.inner.lock().unwrap().config.garden_root.clone();
    spawn_with_target(daemon, garden_root)
}

/// M2a-flavored spawn: caller picks the watch target (e.g., the
/// state root rather than the garden mount). The accumulator is the
/// daemon's shared one — FUSE pushes into it too, so a single
/// classifier pipeline serves both sources per the M1d picks.
pub fn spawn_with_target(daemon: Daemon, watch_target: PathBuf) -> std::thread::JoinHandle<()> {
    let accumulator = daemon.accumulator.clone();
    let source = InotifyDriver::new(watch_target);
    std::thread::Builder::new()
        .name("keeperd-watcher".into())
        .spawn(move || source.run(accumulator, daemon))
        .expect("spawn watcher")
}

// ─── helpers ─────────────────────────────────────────────────────────────

/// Strip the canonical watch root and return a repo-relative path string,
/// or `None` if the absolute path is outside the root.
fn repo_relative(abs: &Path, garden_root: &Path, watch_root: &Path) -> Option<String> {
    let rel = abs
        .strip_prefix(watch_root)
        .or_else(|_| abs.strip_prefix(garden_root))
        .ok()?;
    if rel.as_os_str().is_empty() {
        return None;
    }
    if rel
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
    {
        return None;
    }
    Some(rel.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeeperConfig;
    use softfig_vcs::ignore::Ignore;

    /// Build a bare accumulator whose `garden_root` is `root`. Only `accept`
    /// is exercised, which touches `garden_root` + the (empty) suppress map —
    /// never `inner` — so a default `DaemonInner` is enough.
    fn accumulator_rooted_at(root: &Path) -> Arc<DirtySetAccumulator> {
        let inner = Arc::new(Mutex::new(DaemonInner::new(KeeperConfig::new(root))));
        let suppress = Arc::new(Mutex::new(HashMap::new()));
        DirtySetAccumulator::new(inner, suppress, root.to_path_buf())
    }

    #[test]
    fn accept_uses_the_builtin_predicate_without_reading_softfigignore() {
        // Audit slice 003: in FUSE mode `garden_root` IS the mount the fuser
        // worker serves, so `accept` must never `std::fs`-read `.softfigignore`
        // back through it (a reentrant kernel LOOKUP the same blocked worker
        // would have to service — the self-walk-under-mount deadlock). Proof
        // that no read happens: point `garden_root` at a real dir that *does*
        // contain a `.softfigignore` listing `scratch`, then assert a
        // `scratch/...` path is still ACCEPTED at push time. If `accept` read
        // the file the path would be filtered; that it is not proves the disk
        // file is not consulted here (commit-time `inmem_ignore` still excludes
        // it from the snapshot).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".softfigignore"), "scratch\n").unwrap();
        let acc = accumulator_rooted_at(dir.path());

        // Built-in, un-ignorable names are filtered with no disk read.
        assert!(!acc.accept(".softfig/objects/aa/bb"));
        assert!(!acc.accept(".claude/settings.local.json"));
        // The on-disk `.softfigignore` is NOT consulted on the hot path: a
        // user-listed name is accepted here (and dropped later, at commit).
        assert!(acc.accept("scratch/notes.md"));
        // Ordinary garden content is accepted.
        assert!(acc.accept("journal/decisions/decision-x.md"));
    }

    #[test]
    fn accept_does_not_depend_on_garden_root_existing_on_disk() {
        // The classification is purely in-memory, so it works even when
        // `garden_root` does not exist on disk at all — there is no path under
        // which `accept` issues a filesystem read of the (FUSE) mount.
        let acc = accumulator_rooted_at(Path::new("/nonexistent/softfig-garden-xyz"));
        assert!(!acc.accept(".softfig"));
        assert!(!acc.accept(".claude/settings.local.json"));
        assert!(acc.accept("a.md"));
        assert!(acc.accept("scratch/notes.md"));
    }

    #[test]
    fn ignored_paths_are_filtered() {
        // The accumulator's `accept` delegates to the shared VCS-ignore
        // predicate; both `.softfig` (daemon state) and `.claude` (agent
        // scratch) are filtered out, real garden content is kept. The
        // built-in set is the `.softfigignore`-absent case.
        let ig = Ignore::builtin();
        assert!(ig.is_ignored(Path::new(".softfig/objects/aa/bb")));
        assert!(ig.is_ignored(Path::new(".softfig")));
        assert!(ig.is_ignored(Path::new(".claude/settings.local.json")));
        assert!(ig.is_ignored(Path::new(".claude")));
        assert!(!ig.is_ignored(Path::new("journal/decisions/decision-x.md")));
        assert!(!ig.is_ignored(Path::new("a.md")));
    }

    #[test]
    fn repo_relative_strips_root() {
        let root = Path::new("/tmp/garden-x");
        let abs = Path::new("/tmp/garden-x/journal/decisions/decision-foo.md");
        let rel = repo_relative(abs, root, root).unwrap();
        assert_eq!(rel, "journal/decisions/decision-foo.md");
    }

    #[test]
    fn repo_relative_rejects_outside() {
        let root = Path::new("/tmp/garden-x");
        let abs = Path::new("/etc/passwd");
        assert!(repo_relative(abs, root, root).is_none());
    }
}
