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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecursiveMode, Watcher};
use notify_debouncer_full::{new_debouncer, DebounceEventResult};
use softfig_vcs::ignore::{Ignore, IGNORE_FILE};
use softfig_vcs::Intent;

use crate::classify::{self, DirtySet};
use crate::daemon::{Daemon, DaemonInner, SUPPRESS_WINDOW_MS};
use crate::state::State;

/// Time the source waits between bursts before flushing the accumulator.
/// Sources are responsible for honoring this; the inotify driver gets it
/// for free from `notify-debouncer-full`.
pub const DEBOUNCE_MS: u64 = 200;
const STATE_POLL_MS: u64 = 100;

/// Requeue-retry backoff (slice 010). A failed chain commit re-arms a flush
/// this far out, **doubling each consecutive failure** up to `RETRY_MAX_MS`, so
/// a transient blip (db busy, disk hiccup) retries in ~0.5 s but a
/// persistently-failing chain settles to one attempt per `RETRY_MAX_MS` instead
/// of hot-looping a commit every debounce tick. The flush drivers poll
/// [`DirtySetAccumulator::retry_due`] on their idle tick, so the retry fires
/// with **no new filesystem event** — closing the idle-garden loss window where
/// a requeued write would otherwise sit RAM-only until an unrelated save.
const RETRY_BASE_MS: u64 = 500;
const RETRY_MAX_MS: u64 = 30_000;
/// Cap on the backoff shift so `RETRY_BASE_MS << shift` can never overflow;
/// `500 << 6 = 32_000` already exceeds `RETRY_MAX_MS`, so 6 is the effective
/// ceiling regardless.
const RETRY_MAX_SHIFT: u32 = 6;

/// The capped exponential backoff for the `n`-th consecutive requeue
/// (0-based: the first failure waits `RETRY_BASE_MS`). Pure so the schedule is
/// unit-testable without a clock.
fn backoff_delay(consecutive: u32) -> Duration {
    let shift = consecutive.min(RETRY_MAX_SHIFT);
    Duration::from_millis((RETRY_BASE_MS << shift).min(RETRY_MAX_MS))
}

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

/// Requeue-retry schedule (slice 010). Armed by [`DirtySetAccumulator::requeue`]
/// after a failed commit, polled by the flush drivers via
/// [`DirtySetAccumulator::retry_due`], cleared when a flush fully succeeds.
#[derive(Default, Debug)]
struct RetrySchedule {
    /// When the next requeue-driven retry flush is due. `None` = no pending
    /// retry.
    due_at: Option<Instant>,
    /// Consecutive requeue count; drives the capped [`backoff_delay`]. Reset to
    /// 0 the moment a flush lands cleanly.
    consecutive: u32,
}

/// Source-agnostic accumulator. Sources push [`DirtyEvent`]s; on each
/// `flush()` the buffered events are coalesced, classified, and (if the
/// classification is non-empty) committed via `commit_workdir`.
///
/// Filters applied at push time:
/// - VCS-ignored paths — the built-in set (`.softfig`, `.claude`) ∪ the
///   user's `.softfigignore` entries, via the cached in-memory [`Ignore`]
///   below (never a mount read; see [`Self::accept`]).
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
    /// Cached exclusion set (built-in defaults ∪ the user `.softfigignore`)
    /// consulted by [`Self::accept`] on the fuser worker thread. Rebuilt from
    /// the daemon's *in-memory* state by [`Self::refresh_ignore`] whenever
    /// `.softfigignore` changes — **never** a `std::fs`-read of the mount
    /// (audit slice-003 reentrant deadlock). A leaf lock: only ever held alone.
    cached_ignore: RwLock<Ignore>,
    /// Set when `.softfigignore` is observed to change (and once at startup so
    /// a pre-existing file is honored from the first event). The next
    /// [`Self::push`] rebuilds `cached_ignore` before filtering, then clears it.
    ignore_dirty: AtomicBool,
    /// Requeue-retry deadline + backoff counter (slice 010). A leaf lock: taken
    /// alone, never nested under `buffer` or `inner`.
    retry: Mutex<RetrySchedule>,
    /// Test-only: forces the next N chain commits in [`Self::flush`] to fail
    /// (without touching the repo) so a regression can drive the requeue-retry
    /// path with no real disk/db fault. Absent from release builds.
    #[cfg(test)]
    injected_commit_failures: std::sync::atomic::AtomicUsize,
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
            // Built-ins until the first refresh; `ignore_dirty` starts true so
            // the first push rebuilds from state (honoring a pre-existing
            // `.softfigignore`) before any path is filtered.
            cached_ignore: RwLock::new(Ignore::builtin()),
            ignore_dirty: AtomicBool::new(true),
            retry: Mutex::new(RetrySchedule::default()),
            #[cfg(test)]
            injected_commit_failures: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn garden_root(&self) -> &Path {
        &self.garden_root
    }

    /// Filter + record one event. Returns whether anything was buffered
    /// (false = filtered for `.softfig/` or suppress map; for renames,
    /// only false when both sides are filtered).
    pub fn push(&self, ev: DirtyEvent) -> bool {
        // Rebuild the cached ignore set if a prior push saw `.softfigignore`
        // change (or on first use) — from the daemon's in-memory state, never a
        // read of the mount. Done before taking the buffer lock so the refresh
        // (which briefly takes `inner`) never nests under `buffer`.
        self.ensure_ignore_fresh();
        // Flag a rebuild if THIS event touches `.softfigignore`: the edit is
        // already in the FUSE overlay (the write handler updates it before
        // firing the sink), so the next push's `ensure_ignore_fresh` reflects it
        // ("takes effect on the next save").
        if event_touches_ignore_file(&ev) {
            self.ignore_dirty.store(true, Ordering::Release);
        }
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
            // A retry tick may have fired after a normal flush already drained
            // the buffer — nothing pending, so stand the retry schedule down.
            self.clear_retry();
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
            // Buffer drained to an empty manual_edit (dropped) — a clean, if
            // no-op, resolution; clear any pending retry.
            self.clear_retry();
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.state != State::Unlocked {
            return;
        }
        let garden_root = inner.config.garden_root.clone();
        // M5d slice 016 (NONCE-2): captured before the `repo` borrow below so the
        // shared-chain commit path can re-derive keyed-ness from committed state.
        let state_dir = inner.config.state_dir().to_path_buf();
        let inner = &mut *inner;
        let session = match inner.session.as_ref() {
            Some(s) => s.clone(),
            None => return,
        };
        let hook = inner.layer_b.clone();
        // In-memory working-tree snapshot(s) drive id-promotion + the commit —
        // never reading `garden_root` back through the filesystem. In FUSE mode
        // `garden_root` is the mount this daemon serves, so walking or
        // `fs::read`-ing it here (under `inner`, on the flush path) is the
        // 2026-06-21 mount-read deadlock, and the kernel would hand back the
        // reader-redacted view, not plaintext; the FUSE driver reconstructs the
        // tip∪overlay plaintext from its own state instead (editor writes
        // already live in the overlay). In direct mode `garden_root` is a real
        // dir, so a plain `walk` is safe. Captured before borrowing `repo`.
        //
        // M5c slice 002 — the FUSE mount is a **union** over its chains, so the
        // commit routes per owning chain: the touched paths pick which chains
        // this flush advances (a shared-only write must not move the device
        // ref), the device chain keeps the Layer-B promotion path, and each
        // shared chain (m5c: a plaintext local chain) gets a plain commit to its
        // own ref. `device_only` ⇒ every path routes to the device chain, so a
        // single device commit fires exactly as before.
        let touched_paths: Vec<String> = dirty.all_paths();
        // Kept for the partial-failure path: a failed chain's touched paths are
        // re-queued (the FUSE overlay retains their bytes — slice 006 — so the
        // next flush retries the commit instead of the write being dropped).
        let mut chain_router: Option<softfig_vcs::ChainRegistry> = None;
        let (device_snapshot, shared_snapshots): (
            Option<softfig_vcs::WalkSnapshot>,
            Vec<(String, softfig_vcs::WalkSnapshot)>,
        ) = match inner.fuse.as_ref() {
            Some(mount) => {
                let registry = mount.registry();
                let mut affected: Vec<String> = Vec::new();
                for p in &touched_paths {
                    let r = registry.owning_chain(std::path::Path::new(p)).ref_name.clone();
                    if !affected.contains(&r) {
                        affected.push(r);
                    }
                }
                chain_router = Some(registry);
                let snaps = match mount.chain_snapshots() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("keeperd: watcher: chain snapshots failed: {e}");
                        self.requeue(requeue_events(&dirty, |_| true));
                        return;
                    }
                };
                let mut device = None;
                let mut shared = Vec::new();
                for (ref_name, snap) in snaps {
                    if !affected.contains(&ref_name) {
                        continue;
                    }
                    if ref_name == softfig_vcs::TIP_REF {
                        device = Some(snap);
                    } else {
                        shared.push((ref_name, snap));
                    }
                }
                (device, shared)
            }
            None => match softfig_vcs::walk(&garden_root) {
                Ok(s) => (Some(s), Vec::new()),
                Err(e) => {
                    eprintln!("keeperd: watcher: workdir walk failed: {e}");
                    self.requeue(requeue_events(&dirty, |_| true));
                    return;
                }
            },
        };
        // M5e part 3b-ii: gate each shared chain's ref advance on holding its
        // write turn. A quiesced chain (a peer holds the turn) is skipped in the
        // commit loop and re-queued (via `failed_refs`) so the capped-backoff
        // retry lands it on a later flush once we're granted the turn — the FUSE
        // overlay retains the staged bytes, so nothing is dropped. No-op /
        // self-acquire when net is down, so a solo device never blocks.
        let mut deferred_refs: Vec<String> = Vec::new();
        for (ref_name, _) in &shared_snapshots {
            if !crate::net::gate_shared_chain_commit(inner, ref_name) {
                deferred_refs.push(ref_name.clone());
            }
        }
        let repo = match inner.repo.as_mut() {
            Some(r) => r,
            None => return,
        };
        let mut committed = false;
        let mut failed_refs: Vec<String> = Vec::new();

        // Device chain — the Layer-B-aware commit path (prior-tip snapshot for
        // manual_edit → vault_seal promotion + region placeholder preservation).
        // Skipped when this flush touched no device-owned path.
        if let Some(snapshot) = device_snapshot {
            let prior_snap = match crate::layer_b::build_prior_tip_snapshot(repo, &session) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("keeperd: watcher: prior-tip snapshot failed: {e}");
                    self.requeue(requeue_events(&dirty, |_| true));
                    return;
                }
            };
            let promoted = if classified.intent == "manual_edit" {
                crate::layer_b::promote_manual_edit_for_new_ids(
                    &touched_paths,
                    &snapshot,
                    &session,
                    &prior_snap,
                )
            } else {
                None
            };
            let intent = if let Some(p) = promoted {
                p
            } else {
                match Intent::new(&classified.intent, classified.payload.clone()) {
                    Ok(i) => i,
                    Err(e) => {
                        eprintln!("keeperd: watcher: invalid auto-classified intent: {e}");
                        self.requeue(requeue_events(&dirty, |_| true));
                        return;
                    }
                }
            };
            hook.install_prior_tip(prior_snap);
            let result = repo.commit_snapshot(&session, snapshot, intent);
            hook.clear_prior_tip();
            match result {
                Ok(_) => committed = true,
                Err(e) => {
                    eprintln!("keeperd: watcher: commit failed: {e}");
                    failed_refs.push(softfig_vcs::TIP_REF.to_string());
                }
            }
        }

        // Shared chains — a per-ref commit that routes each blob through
        // `encrypt_for_ref` (a keyed chain seals under `S`; the device-chain
        // Layer-B manual_edit→seal promotion does not apply here). Each advances
        // only its own ref.
        //
        // M5d slice 016 (NONCE-2): before committing, re-prime the `S` router
        // from committed membership so keyed-ness is read from the source of
        // truth at the moment we seal, not from a cache that a just-completed
        // ceremony might not have refreshed yet. Only `set_shared_chain_keys`
        // (not the full `refresh_mount_registry`) — the FUSE mount's owning-chain
        // routing this flush already resolved must stay put. Cheap: one committed
        // `shared-subtrees.toml` decode; skipped entirely when no shared ref moved.
        if !shared_snapshots.is_empty() {
            let fresh = crate::handlers::load_chain_registry(repo, &session, &state_dir);
            hook.set_shared_chain_keys(&fresh);
        }
        for (ref_name, snap) in shared_snapshots {
            // M5e part 3b-ii: quiesced on its write turn (a peer holds it). The
            // overlay retains `snap`'s bytes; route it through the partial-failure
            // requeue so the capped-backoff retry lands it once we're granted.
            if deferred_refs.contains(&ref_name) {
                eprintln!(
                    "keeperd: watcher: shared-chain commit to {ref_name} deferred on write turn"
                );
                failed_refs.push(ref_name);
                continue;
            }
            let intent = match Intent::new(&classified.intent, classified.payload.clone()) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("keeperd: watcher: invalid auto-classified intent: {e}");
                    failed_refs.push(ref_name);
                    continue;
                }
            };
            #[cfg(test)]
            let inject_fail = self.take_injected_failure();
            #[cfg(not(test))]
            let inject_fail = false;
            if inject_fail {
                eprintln!(
                    "keeperd: watcher: [test] injected commit failure for {ref_name}"
                );
                failed_refs.push(ref_name);
                continue;
            }
            match repo.commit_snapshot_to(&ref_name, &session, snap, intent) {
                Ok(_) => committed = true,
                Err(e) => {
                    eprintln!("keeperd: watcher: shared-chain commit to {ref_name} failed: {e}");
                    failed_refs.push(ref_name);
                }
            }
        }

        // Partial failure (slice 006, review finding 3): a failed chain's
        // writes are still in the FUSE overlay (the sibling's rotation absorbs
        // only its own chain's entries), so re-queue that chain's touched
        // paths — the next flush rebuilds the snapshot from the overlay and
        // retries the commit. Nothing is dropped.
        if !failed_refs.is_empty() {
            let events = match &chain_router {
                Some(router) => requeue_events(&dirty, |p| {
                    failed_refs.contains(&router.owning_chain(std::path::Path::new(p)).ref_name)
                }),
                None => requeue_events(&dirty, |_| true),
            };
            self.requeue(events);
        } else {
            // Every affected chain committed — stand down any retry armed by a
            // prior failed flush (this may itself be that retry landing).
            self.clear_retry();
        }

        // Slice 1 (M5b-hardening): an auto-commit advanced a tip — wake the
        // replica push loop so backups fire event-driven, not on the ~20s
        // reconcile poll. No-op when net is down / nothing granted.
        if committed {
            if let Some(net) = inner.net.as_ref() {
                net.signal_commit();
            }
        }
    }

    /// Re-file `events` into the dirty buffer after a failed commit **and** arm
    /// a retry deadline so the next flush actually fires.
    ///
    /// Two responsibilities, both load-bearing (slice 010):
    /// - **Re-file, kind-preserved.** The events go back into the buffer under
    ///   their original kind (a removal stays a removal), so a retried flush
    ///   doesn't re-file a delete as a `modified` and mint a `manual_edit`
    ///   intent naming a file the commit removes (record 018 NIT). The write
    ///   bytes themselves are safe meanwhile — a FUSE overlay retains everything
    ///   a rotation didn't absorb (slice 006), and a direct-mode working tree is
    ///   the disk itself; this only reconstructs the dirty *set* that `flush`
    ///   consumed with its `mem::take`.
    /// - **Re-arm the trigger.** `flush`'s `mem::take` also cleared the flush
    ///   trigger, and neither driver re-arms on its own (FUSE fires off a
    ///   one-shot `last_nudge`, inotify's timeout arm never flushes), so a
    ///   requeued write on an idle garden would sit RAM-only until an unrelated
    ///   save. [`Self::arm_retry`] sets a capped-backoff deadline that both
    ///   drivers poll via [`Self::retry_due`], so the retry fires with no new
    ///   filesystem event.
    fn requeue(&self, events: impl IntoIterator<Item = DirtyEvent>) {
        let mut n = 0usize;
        {
            let mut buf = self.buffer.lock().unwrap();
            for ev in events {
                match ev {
                    DirtyEvent::Created(p) => {
                        buf.created.insert(p);
                    }
                    DirtyEvent::Modified(p) => {
                        buf.modified.insert(p);
                    }
                    DirtyEvent::Removed(p) => {
                        buf.removed.insert(p);
                    }
                    DirtyEvent::Renamed { from, to } => {
                        if to.starts_with("journal/archive/") {
                            buf.renamed_to_archive.push((from, to));
                        } else {
                            buf.removed.insert(from);
                            buf.created.insert(to);
                        }
                    }
                }
                n += 1;
            }
        }
        if n > 0 {
            eprintln!("keeperd: watcher: re-queued {n} change(s) for retry");
            self.arm_retry();
        }
    }

    /// Arm (or re-arm) the requeue-retry deadline with a capped exponential
    /// [`backoff_delay`] off the consecutive-failure count. Called only from
    /// [`Self::requeue`] (i.e. only when something was re-filed).
    fn arm_retry(&self) {
        let mut sched = self.retry.lock().unwrap();
        sched.due_at = Some(Instant::now() + backoff_delay(sched.consecutive));
        sched.consecutive = sched.consecutive.saturating_add(1);
    }

    /// Stand the retry schedule down after a fully-successful flush (nothing
    /// re-queued): drops the deadline and resets the backoff so the next
    /// transient failure retries promptly.
    fn clear_retry(&self) {
        let mut sched = self.retry.lock().unwrap();
        sched.due_at = None;
        sched.consecutive = 0;
    }

    /// True **once** when an armed requeue-retry deadline has elapsed: consuming
    /// the deadline so exactly one flush is driven per backoff interval (that
    /// flush re-arms via [`Self::requeue`] if it fails again, or clears it on
    /// success). The flush drivers ([`crate::fuse_sink::AccumulatorSink`]'s loop
    /// and the inotify run loop) call this on their idle tick and `flush()` when
    /// it returns true — the sole mechanism that re-fires a requeue with no new
    /// filesystem event.
    pub(crate) fn retry_due(&self) -> bool {
        let mut sched = self.retry.lock().unwrap();
        match sched.due_at {
            Some(t) if Instant::now() >= t => {
                sched.due_at = None;
                true
            }
            _ => false,
        }
    }

    /// Test-only: claim one injected commit failure (see
    /// [`Self::injected_commit_failures`]).
    #[cfg(test)]
    fn take_injected_failure(&self) -> bool {
        use std::sync::atomic::Ordering;
        let mut cur = self.injected_commit_failures.load(Ordering::Acquire);
        loop {
            if cur == 0 {
                return false;
            }
            match self.injected_commit_failures.compare_exchange(
                cur,
                cur - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Test-only: force the next `n` chain commits in [`Self::flush`] to fail.
    #[cfg(test)]
    pub(crate) fn inject_commit_failures(&self, n: usize) {
        self.injected_commit_failures
            .store(n, std::sync::atomic::Ordering::Release);
    }

    /// Test-only: pull an armed retry deadline into the past so [`Self::retry_due`]
    /// fires immediately — exercises the driver-poll path without sleeping out
    /// the real backoff.
    #[cfg(test)]
    pub(crate) fn expire_retry_deadline(&self) {
        let mut sched = self.retry.lock().unwrap();
        if sched.due_at.is_some() {
            sched.due_at = Some(Instant::now());
        }
    }

    /// True if the path should be buffered: not VCS-ignored and not currently
    /// in the daemon's self-write suppression map.
    ///
    /// The ignore test consults the cached [`Ignore`] — the built-in defaults
    /// (`.softfig`, `.claude`) ∪ the user's `.softfigignore` — and reads
    /// **nothing from disk**. It must not read disk: in FUSE mode
    /// `self.garden_root` IS the mount this code runs against, and the fuser
    /// worker thread calls the dirty-set sink synchronously, so an
    /// `Ignore::load` of `<root>/.softfigignore` would issue a read whose kernel
    /// LOOKUP only the same blocked worker can service — the
    /// self-walk-under-mount reentrant deadlock (audit slice 003).
    ///
    /// Audit slice 002 restores the early *user*-ignore filtering that slice 003
    /// had to drop: [`Self::refresh_ignore`] rebuilds `cached_ignore` from the
    /// daemon's in-memory state (the FUSE overlay∪tip via
    /// [`MountHandle::inmem_ignore`], or a direct-mode real-dir load) whenever
    /// `.softfigignore` changes — never a mount read. So a user-ignored path
    /// never enters the dirty set, and no `manual_edit` commit is minted whose
    /// payload names a file its own diff excludes (the no-op-commit churn).
    /// Commit-time enforcement from in-memory state remains the backstop.
    fn accept(&self, rel: &str) -> bool {
        let p = Path::new(rel);
        if self.cached_ignore.read().unwrap().is_ignored(p) {
            return false;
        }
        if self.is_self_write(&self.garden_root.join(rel)) {
            return false;
        }
        true
    }

    /// Rebuild [`Self::cached_ignore`] if a prior push flagged a
    /// `.softfigignore` change (or on first use). Claims the flag with a `swap`
    /// so a change racing the rebuild re-flags rather than being lost: the next
    /// call rebuilds again.
    fn ensure_ignore_fresh(&self) {
        if self.ignore_dirty.swap(false, Ordering::AcqRel) {
            self.refresh_ignore();
        }
    }

    /// Rebuild the cached exclusion set from the daemon's **in-memory** view:
    /// the FUSE overlay∪tip snapshot ([`MountHandle::inmem_ignore`]), or — in
    /// direct mode, where `garden_root` is a real dir and not a mount — a plain
    /// [`Ignore::load`] (the same source the flush path's `walk` reads). NEVER a
    /// read of the FUSE mount: in FUSE mode this runs on the fuser worker thread
    /// (via `push` ← the sink), so a `std::fs`-read of `<mount>/.softfigignore`
    /// would deadlock on the same worker (audit slice 003). Lock order
    /// `inner → fuse.SharedState.inner` matches `flush`; no buffer lock is held.
    fn refresh_ignore(&self) {
        let rebuilt = {
            let inner = self.inner.lock().unwrap();
            match inner.fuse.as_ref() {
                Some(mount) => match mount.inmem_ignore() {
                    Ok(ig) => ig,
                    Err(e) => {
                        // Keep the prior cache; commit-time enforcement still
                        // excludes the path. Don't re-flag (a persistent decrypt
                        // error must not hot-loop the `inner` lock every push).
                        eprintln!("keeperd: watcher: in-memory ignore refresh failed: {e}");
                        return;
                    }
                },
                None => Ignore::load(&inner.config.garden_root),
            }
        };
        *self.cached_ignore.write().unwrap() = rebuilt;
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
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Slice 010: no new events, but a prior failed commit may
                    // have re-armed a retry deadline — the inotify timeout arm
                    // never flushed on its own, so an idle-garden requeue would
                    // sit RAM-only. Poll + drive it here, matching the FUSE
                    // driver's per-tick retry poll.
                    if accumulator.retry_due() {
                        accumulator.flush();
                    }
                    continue;
                }
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

/// Reconstruct the [`DirtyEvent`]s to re-queue from a classified [`DirtySet`],
/// keeping each path's original kind (so a removal isn't re-filed as a
/// modification — record 018 NIT) and selecting only paths `retain` accepts (the
/// partial-failure case re-queues just the failed chains' paths; a whole-flush
/// failure passes `|_| true`).
fn requeue_events(dirty: &DirtySet, mut retain: impl FnMut(&str) -> bool) -> Vec<DirtyEvent> {
    let mut out = Vec::new();
    for p in &dirty.created {
        if retain(p) {
            out.push(DirtyEvent::Created(p.clone()));
        }
    }
    for p in &dirty.modified {
        if retain(p) {
            out.push(DirtyEvent::Modified(p.clone()));
        }
    }
    for p in &dirty.removed {
        if retain(p) {
            out.push(DirtyEvent::Removed(p.clone()));
        }
    }
    for (from, to) in &dirty.renamed_to_archive {
        // The archive move is carried by its destination; re-queue when either
        // side belongs to a selected chain.
        if retain(to) || retain(from) {
            out.push(DirtyEvent::Renamed {
                from: from.clone(),
                to: to.clone(),
            });
        }
    }
    out
}

/// True if a dirty event touches the garden's `.softfigignore` (either side of
/// a rename). Used to flag a rebuild of the cached ignore set.
fn event_touches_ignore_file(ev: &DirtyEvent) -> bool {
    let is_ignore_file = |p: &str| p == IGNORE_FILE;
    match ev {
        DirtyEvent::Created(p) | DirtyEvent::Modified(p) | DirtyEvent::Removed(p) => {
            is_ignore_file(p)
        }
        DirtyEvent::Renamed { from, to } => is_ignore_file(from) || is_ignore_file(to),
    }
}

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

    /// Build a bare accumulator whose `garden_root` is `root`. A default
    /// `DaemonInner` (`fuse: None`, state `Locked`) is enough: `accept` touches
    /// only `cached_ignore` + the (empty) suppress map, and a `push`-driven
    /// `refresh_ignore` takes the direct-mode `Ignore::load(garden_root)` branch
    /// (no FUSE mount to reconstruct from).
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
    fn a_user_ignored_path_is_dropped_once_the_cache_is_loaded() {
        // Audit slice 002, criterion (a): with `.softfigignore` listing
        // `scratch`, a `scratch/...` write is filtered *before* it enters the
        // dirty set — closing the no-op-commit churn at the accept gate. (Direct
        // mode exercises the refresh wiring: `fuse: None` → `Ignore::load` of the
        // real dir. In FUSE mode the same set comes from the in-memory
        // overlay∪tip via `MountHandle::inmem_ignore`; that is the on-device
        // "doesn't hang" smoke, not runnable headlessly.)
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".softfigignore"), "scratch\n").unwrap();
        let acc = accumulator_rooted_at(dir.path());

        // A bare `accept` (no push) still sees only the built-ins — the
        // slice-003 posture that the hot path itself never reads disk.
        assert!(acc.accept("scratch/x.md"));

        // The first push refreshes the cache from state (ignore_dirty starts
        // true), so the user-ignored path is NOT buffered.
        assert!(!acc.push(DirtyEvent::Modified("scratch/x.md".to_string())));
        // Built-ins are never lost when user entries are layered on.
        assert!(!acc.accept(".softfig/objects/aa/bb"));
        assert!(!acc.accept(".claude/settings.local.json"));
        // A non-ignored sibling is still tracked (criterion c).
        assert!(acc.push(DirtyEvent::Modified("journal/decisions/d.md".to_string())));
    }

    #[test]
    fn editing_softfigignore_takes_effect_on_the_next_push() {
        // Audit slice 002, criterion (b): adding an entry to `.softfigignore`
        // filters the newly-ignored path on the next save. The refresh is driven
        // off the `.softfigignore` change itself, and the accept hot path never
        // reads disk (proven by the slice-003 reentrancy tests above).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".softfigignore"), "# nothing yet\n").unwrap();
        let acc = accumulator_rooted_at(dir.path());

        // `scratch` is tracked while it isn't listed.
        assert!(acc.push(DirtyEvent::Modified("scratch/x.md".to_string())));

        // User adds `scratch` and saves `.softfigignore`.
        std::fs::write(dir.path().join(".softfigignore"), "scratch\n").unwrap();
        // The save of `.softfigignore` is itself tracked and flags a rebuild.
        assert!(acc.push(DirtyEvent::Modified(".softfigignore".to_string())));

        // The next save of `scratch/x` is now filtered.
        assert!(!acc.push(DirtyEvent::Modified("scratch/x.md".to_string())));
    }

    #[test]
    fn event_touches_ignore_file_flags_only_the_ignore_file() {
        assert!(event_touches_ignore_file(&DirtyEvent::Modified(
            ".softfigignore".to_string()
        )));
        assert!(event_touches_ignore_file(&DirtyEvent::Removed(
            ".softfigignore".to_string()
        )));
        // A rename into or out of `.softfigignore` counts on either side.
        assert!(event_touches_ignore_file(&DirtyEvent::Renamed {
            from: "journal/archive/old-ignore".to_string(),
            to: ".softfigignore".to_string(),
        }));
        // Nested or similarly-named paths do not.
        assert!(!event_touches_ignore_file(&DirtyEvent::Modified(
            "docs/.softfigignore".to_string()
        )));
        assert!(!event_touches_ignore_file(&DirtyEvent::Modified(
            "a.md".to_string()
        )));
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

    // ─── slice 010 — requeue re-arms the flush trigger ──────────────────────

    #[test]
    fn backoff_delay_doubles_then_caps() {
        assert_eq!(backoff_delay(0), Duration::from_millis(500));
        assert_eq!(backoff_delay(1), Duration::from_millis(1_000));
        assert_eq!(backoff_delay(2), Duration::from_millis(2_000));
        assert_eq!(backoff_delay(3), Duration::from_millis(4_000));
        assert_eq!(backoff_delay(4), Duration::from_millis(8_000));
        assert_eq!(backoff_delay(5), Duration::from_millis(16_000));
        // 500 << 6 = 32_000 → clamped to RETRY_MAX_MS, and it stays there.
        assert_eq!(backoff_delay(6), Duration::from_millis(30_000));
        assert_eq!(backoff_delay(7), Duration::from_millis(30_000));
        assert_eq!(backoff_delay(1_000), Duration::from_millis(30_000));
    }

    #[test]
    fn requeue_events_preserves_kind_and_filters_by_chain() {
        let dirty = DirtySet {
            created: vec!["proj/new.md".into()],
            modified: vec!["proj/edit.md".into(), "other/keep.md".into()],
            removed: vec!["proj/gone.md".into()],
            renamed_to_archive: vec![(
                "proj/old.md".into(),
                "journal/archive/x/proj-old.md".into(),
            )],
        };
        let events = requeue_events(&dirty, |p| p.starts_with("proj/"));
        // A removal survives AS a removal — not silently re-filed `modified`
        // (record 018 NIT: else a retried flush mints a manual_edit naming a
        // file the commit deletes).
        assert!(events
            .iter()
            .any(|e| matches!(e, DirtyEvent::Removed(p) if p == "proj/gone.md")));
        assert!(events
            .iter()
            .any(|e| matches!(e, DirtyEvent::Created(p) if p == "proj/new.md")));
        assert!(events
            .iter()
            .any(|e| matches!(e, DirtyEvent::Modified(p) if p == "proj/edit.md")));
        // The unselected chain's path is filtered out.
        assert!(!events
            .iter()
            .any(|e| matches!(e, DirtyEvent::Modified(p) if p == "other/keep.md")));
        // A rename is re-queued when its `from` side is selected even though the
        // archive destination is not.
        assert!(events
            .iter()
            .any(|e| matches!(e, DirtyEvent::Renamed { from, .. } if from == "proj/old.md")));
    }

    #[test]
    fn retry_schedule_arms_expires_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let acc = accumulator_rooted_at(dir.path());
        // Nothing armed → not due, and probing an unarmed schedule is a no-op.
        assert!(!acc.retry_due());
        // Arming via requeue leaves a pending (not-yet-elapsed) deadline.
        acc.requeue([DirtyEvent::Modified("a.md".into())]);
        assert!(!acc.retry_due(), "the 500ms deadline hasn't elapsed");
        // Simulated time passing → due exactly once (the poll consumes it).
        acc.expire_retry_deadline();
        assert!(acc.retry_due());
        assert!(!acc.retry_due(), "the deadline is consumed on the first true");
        // clear_retry stands a fresh arming down (and resets the backoff).
        acc.requeue([DirtyEvent::Modified("a.md".into())]);
        acc.clear_retry();
        acc.expire_retry_deadline(); // no-op: due_at is None
        assert!(!acc.retry_due());
    }

    struct NullSink;
    impl softfig_fuse::DirtyEventSink for NullSink {
        fn created(&self, _: &str) {}
        fn modified(&self, _: &str) {}
        fn removed(&self, _: &str) {}
        fn renamed(&self, _: &str, _: &str) {}
        fn nudge(&self) {}
    }

    const SHARED_REF: &str = "chain/proj";

    /// A full Unlocked FUSE-mode accumulator over a tempdir garden with a shared
    /// chain mounted at `proj/` (minus the kernel mount, via the slice-007
    /// `attach_unmounted` seam) — lets a regression drive the real `flush`
    /// per-chain commit routing headlessly.
    fn fuse_accumulator(garden: &Path) -> (Arc<Mutex<DaemonInner>>, Arc<DirtySetAccumulator>) {
        use softfig_fuse::FuseMount;
        use softfig_vault::{params::VaultParams, Vault};
        use softfig_vcs::{Chain, ChainRegistry, Repo, WalkSnapshot};

        let mut p = VaultParams::default();
        p.argon2.m_cost = 8;
        p.argon2.t_cost = 1;
        p.argon2.p_cost = 1;
        let (_v, session, _rec) = Vault::init_with_params(garden, b"pw-test-12345", p).unwrap();
        let session = Arc::new(session);
        let (mut repo, _genesis) = Repo::init(garden, &session).unwrap();
        repo.commit_snapshot_to(
            SHARED_REF,
            &session,
            WalkSnapshot::empty(),
            softfig_vcs::Intent::init("genesis"),
        )
        .unwrap();
        let registry = ChainRegistry::new(
            Chain::device(),
            vec![Chain::shared("proj", SHARED_REF, "proj", true)],
        );
        let handle =
            FuseMount::attach_unmounted(garden, garden, session.clone(), Arc::new(NullSink), None, registry)
                .unwrap();
        FuseMount::install_tip_callback(&mut repo, &handle);

        let mut di = DaemonInner::new(KeeperConfig::new(garden));
        di.state = crate::state::State::Unlocked;
        di.session = Some(session);
        di.repo = Some(repo);
        di.fuse = Some(handle);
        let inner = Arc::new(Mutex::new(di));
        let acc = DirtySetAccumulator::new(
            inner.clone(),
            Arc::new(Mutex::new(HashMap::new())),
            garden.to_path_buf(),
        );
        (inner, acc)
    }

    fn shared_tip(inner: &Arc<Mutex<DaemonInner>>) -> Option<softfig_store::Hash> {
        inner
            .lock()
            .unwrap()
            .repo
            .as_ref()
            .unwrap()
            .tip_of(SHARED_REF)
            .unwrap()
    }

    #[test]
    fn a_failed_commit_retries_with_no_new_event_and_lands_when_it_clears() {
        let garden = tempfile::tempdir().unwrap();
        let (inner, acc) = fuse_accumulator(garden.path());

        // A FUSE write: bytes into the overlay, the dirty event into the sink.
        {
            let g = inner.lock().unwrap();
            g.fuse
                .as_ref()
                .unwrap()
                .stage_write("proj/note.md", b"hello".to_vec());
        }
        assert!(acc.push(DirtyEvent::Created("proj/note.md".into())));
        let before = shared_tip(&inner);

        // First flush: the shared-chain commit is injected to fail once.
        acc.inject_commit_failures(1);
        acc.flush();

        // The ref did NOT advance — but the bytes are safe in the overlay and a
        // retry is armed (pending, not yet due: the backoff hasn't elapsed).
        assert_eq!(shared_tip(&inner), before, "the failed commit left the ref put");
        assert!(!acc.retry_due(), "the retry deadline is pending, not immediate");

        // Idle garden: NO new filesystem event. The driver tick expires the
        // backoff and drives the retry flush — the load-bearing pin.
        acc.expire_retry_deadline();
        assert!(acc.retry_due());
        acc.flush();

        // The write reached its chain, and the schedule stood down.
        assert_ne!(
            shared_tip(&inner),
            before,
            "the retry landed the commit once the failure cleared"
        );
        acc.expire_retry_deadline();
        assert!(!acc.retry_due(), "a clean flush cleared the retry schedule");
        let g = inner.lock().unwrap();
        let mount = g.fuse.as_ref().unwrap();
        assert!(
            mount.pending_chain_refs().is_empty(),
            "the overlay write was absorbed by the landed commit"
        );
        assert_eq!(mount.read_workfile("proj/note.md").unwrap().unwrap(), b"hello");
    }
}
