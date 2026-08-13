//! M3a — typed, daemon-mediated garden write actions.
//!
//! Each verb takes high-level args (`log_decision({slug, body})`) and the
//! daemon — not the calling Claude session — stamps the garden-convention
//! path, header, intent, and payload from one source of truth
//! ([`conventions`]). All five actions share the same skeleton:
//!
//! 1. parse + validate args (charset, date, snapshot-prefix rules),
//! 2. resolve the garden-relative path(s) from [`conventions`],
//! 3. reject-on-exists for create-style actions,
//! 4. register each path in the daemon's self-event suppression map,
//! 5. write the bytes (or `rename`, for `archive`),
//! 6. exactly one `commit_workdir` under a [`PriorTipGuard`], with the
//!    explicit intent (already present in `KNOWN_INTENTS`).
//!
//! Module shape resolves the decision file's first open question in favor
//! of per-action files + a shared `conventions` module. The server
//! dispatches straight here (no pass-through layer in `handlers.rs`); the
//! `HandlerResult` type alias is reused so the wire-error contract is
//! identical to every other verb.

pub mod conventions;

mod add_code_review;
mod add_note;
mod add_project;
mod archive;
mod backlinks;
mod growlight;
mod index;
mod log_decision;
mod log_incident;
mod managed;
mod migrate_config;
mod numbering;
mod patch_file;
mod refresh_snapshot;
pub(crate) mod sections;
mod shared_pull;
mod split;
mod sync_conflict;
mod thrash;
mod unlink;
mod worktree;

pub use add_code_review::add_code_review;
pub use add_note::{add_note, revise_note};
pub use add_project::add_project;
pub use archive::archive;
pub use growlight::{
    add_backlog_item, add_queue, add_slice, growlight_init, growlight_set_resources, log_baton,
    post_message, read_inbox, release_lease, reorder_backlog_item, request_lease, set_item_status,
    tail_bus, HolderStore,
};
// Crate-internal helpers behind the `growlight_queue` read verb (020 slice 002):
// the queue-grammar parser + the backlog-doc path. `pub(crate)`, so they can't
// ride the `pub use` above.
pub(crate) use growlight::{default_queue_rows, growlight_backlog_claude};
pub use log_decision::log_decision;
pub use log_incident::log_incident;
pub use migrate_config::migrate_config;
pub use patch_file::patch_file;
pub use refresh_snapshot::refresh_snapshot;
pub use sections::{add_section, append_to_section, edit_section, set_reviewed};
pub(crate) use shared_pull::{apply_shared_pull, SharedPullInput, SharedPullOutcome};
pub use split::migrate_split;
pub(crate) use sync_conflict::{resolve_sync_conflict, ConflictResolution, ConflictSides};
pub use thrash::ThrashDetector;
pub use unlink::unlink;
pub(crate) use worktree::{Tree, WorkTree};

use std::path::Path;

use softfig_vcs::Intent;
use softfig_ipc::ErrorKind;
use softfig_store::Hash;

use crate::daemon::DaemonInner;
use crate::layer_b::PriorTipGuard;
use crate::server::err_to_response;

/// Create the parent dir (if needed) and write `bytes` to `abs`.
pub(crate) fn write_file(abs: &Path, bytes: &[u8]) -> Result<(), (ErrorKind, String)> {
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| (ErrorKind::Io, e.to_string()))?;
    }
    std::fs::write(abs, bytes).map_err(|e| (ErrorKind::Io, e.to_string()))
}

/// Run one action commit, mirroring the M2c-aware commit at every other
/// daemon write site. The caller must hold the inner lock, have already
/// written every file into the working tree, and have registered each path
/// in the suppression map.
///
/// In FUSE mode the daemon serves `garden_root` itself, so the legacy
/// `commit_workdir` (which walks `garden_root`) would recursively self-read
/// the mount while we hold `inner` — the 2026-06-21 commit-path deadlock.
/// We commit from the FUSE driver's in-memory (tip ∪ overlay) snapshot
/// instead. The snapshots are captured **before** the commits because each
/// commit's `tip_changed` rotates the view and absorbs its chain's overlay
/// entries. [`MountHandle`](softfig_fuse::MountHandle)'s snapshot methods
/// lock the *FUSE* `SharedState` mutex (a different lock from `daemon.inner`)
/// and never re-enter the kernel, so they are safe under `inner`. Non-FUSE /
/// M1c-compat callers keep walking the working tree via `commit_workdir`.
///
/// M5c slice 006 — the commit **routes per owning chain**, like the watcher
/// flush: every chain with a staged overlay write/removal
/// ([`MountHandle::pending_chain_refs`](softfig_fuse::MountHandle::pending_chain_refs))
/// gets its carve-out committed to its own ref, so an action-verb write under
/// an enabled shared mount lands in that chain instead of vanishing through
/// the device carve-out + rotation (interim-review finding 1). The device
/// chain keeps the Layer-B [`PriorTipGuard`] path; shared chains (plaintext
/// in m5c) take a plain `commit_snapshot_to`, matching the watcher. Only
/// pending chains are committed — no no-op commit is minted on a ref whose
/// content didn't change. Returns the device commit hash when the device
/// chain advanced (the common case, and always in `device_only`), else the
/// last shared chain's.
pub(crate) fn commit_now(
    inner: &mut DaemonInner,
    intent: Intent,
) -> Result<Hash, (ErrorKind, String)> {
    // Reborrow `inner.fuse` on its own (disjoint from `repo`/`session`/`hook`
    // below) and finish the snapshots into owned values before touching the
    // repo, so no two `DaemonInner` fields are borrowed at once.
    let fuse_snapshots = match inner.fuse.as_ref() {
        Some(mount) => {
            // Pending refs BEFORE the snapshot capture: a write racing in
            // between lands at a later overlay generation than the snapshot
            // stamps, so the rotation retains it either way.
            let pending = mount.pending_chain_refs();
            let snaps = mount
                .chain_snapshots()
                .map_err(|e| (ErrorKind::Io, format!("workdir snapshot: {e}")))?;
            let mut device = None;
            let mut shared = Vec::new();
            for (ref_name, snap) in snaps {
                if ref_name == softfig_vcs::TIP_REF {
                    // Always eligible: an action with nothing staged (or in a
                    // device_only registry) keeps today's contract of minting
                    // its intent on the device chain.
                    device = Some(snap);
                } else if pending.contains(&ref_name) {
                    shared.push((ref_name, snap));
                }
            }
            let device_pending =
                pending.is_empty() || pending.iter().any(|r| r == softfig_vcs::TIP_REF);
            Some((device.filter(|_| device_pending || shared.is_empty()), shared))
        }
        None => None,
    };
    // M5e part 3b-ii: gate each shared chain's ref advance on holding its write
    // turn. A quiesced (peer holds the turn) chain is skipped below — its staged
    // write stays in the FUSE overlay and lands on a later boundary once we are
    // granted the turn. No-op / self-acquire when net is down (a solo device
    // never blocks), so every non-mesh commit path is byte-unchanged.
    let mut deferred_shared: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some((_, shared)) = &fuse_snapshots {
        for (ref_name, _) in shared {
            if !crate::net::gate_shared_chain_commit(inner, ref_name) {
                deferred_shared.insert(ref_name.clone());
            }
        }
    }
    let hook = inner.layer_b.clone();
    let hash = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_mut().expect("unlocked");
        match fuse_snapshots {
            Some((device_snapshot, shared_snapshots)) => {
                let mut last = None;
                if let Some(snapshot) = device_snapshot {
                    let _guard =
                        PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
                    last = Some(
                        repo.commit_snapshot(session, snapshot, intent.clone())
                            .map_err(|e| err_to_response(e.into()))?,
                    );
                }
                let device_hash = last;
                for (ref_name, snap) in shared_snapshots {
                    // Quiesced on its write turn (a peer holds it) — leave the
                    // snapshot staged in the overlay for a later boundary.
                    if deferred_shared.contains(&ref_name) {
                        continue;
                    }
                    last = Some(
                        repo.commit_snapshot_to(&ref_name, session, snap, intent.clone())
                            .map_err(|e| err_to_response(e.into()))?,
                    );
                }
                match device_hash.or(last) {
                    Some(h) => h,
                    // Every advancing chain was deferred on its write turn: nothing
                    // committed this call — return the device tip unchanged (the
                    // staged writes land on a later boundary once granted).
                    None => repo
                        .tip()
                        .map_err(|e| err_to_response(e.into()))?
                        .expect("device chain always has a genesis tip"),
                }
            }
            None => {
                let _guard =
                    PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
                repo.commit_workdir(session, intent)
                    .map_err(|e| err_to_response(e.into()))?
            }
        }
    };
    // Slice 1 (M5b-hardening): a tip-advancing commit landed — wake the replica
    // push loop so it pushes to online granted hosts now, instead of on the next
    // ~20s reconcile tick. No-op when net is down or nothing is granted.
    if let Some(net) = inner.net.as_ref() {
        net.signal_commit();
    }
    Ok(hash)
}

/// Commit a pre-built `snapshot` to an arbitrary chain `ref_name` under a fresh
/// [`PriorTipGuard`] — the M5c slice 003 path for creating a shared chain's
/// genesis ref (an empty snapshot on a not-yet-existing ref, so the union mount
/// can compose it). Mirrors [`commit_now`] but targets `ref_name` with a
/// caller-supplied snapshot instead of the device chain's FUSE workdir snapshot,
/// so it never self-reads the mount. The caller holds the inner lock and has
/// verified the vault is unlocked.
pub(crate) fn commit_snapshot_to_now(
    inner: &mut DaemonInner,
    ref_name: &str,
    snapshot: softfig_vcs::WalkSnapshot,
    intent: Intent,
) -> Result<Hash, (ErrorKind, String)> {
    let hook = inner.layer_b.clone();
    let hash = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_mut().expect("unlocked");
        let _guard = PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
        repo.commit_snapshot_to(ref_name, session, snapshot, intent)
            .map_err(|e| err_to_response(e.into()))?
    };
    // A genesis on a shared ref never advances the device tip, so the device-only
    // replica push loop no-ops; wake it anyway for parity with `commit_now`.
    if let Some(net) = inner.net.as_ref() {
        net.signal_commit();
    }
    Ok(hash)
}

#[cfg(test)]
mod commit_now_tests {
    //! M5c slice 006 (d): an action-verb write staged under an enabled shared
    //! mount must commit to the owning chain's ref — not vanish through the
    //! device carve-out + rotation (interim-review finding 1). Headless via
    //! `FuseMount::attach_unmounted`: the full overlay/registry/commit state
    //! machine with no kernel mount behind it.

    use std::sync::Arc;

    use softfig_fuse::{DirtyEventSink, FuseMount};
    use softfig_vault::{params::VaultParams, Vault, VaultSession};
    use softfig_vcs::{Chain, ChainRegistry, Repo, WalkSnapshot, TIP_REF};

    use super::commit_now;
    use crate::config::KeeperConfig;
    use crate::daemon::DaemonInner;
    use crate::state::State;

    const PASS: &[u8] = b"pw-test-12345";
    const SHARED_REF: &str = "chain/proj";

    struct NullSink;
    impl DirtyEventSink for NullSink {
        fn created(&self, _: &str) {}
        fn modified(&self, _: &str) {}
        fn removed(&self, _: &str) {}
        fn renamed(&self, _: &str, _: &str) {}
        fn nudge(&self) {}
    }

    /// An Unlocked FUSE-mode `DaemonInner` over a tempdir garden with a shared
    /// chain mounted at `proj/`, minus only the kernel mount.
    fn fuse_inner(garden: &std::path::Path) -> (DaemonInner, Arc<VaultSession>) {
        let mut p = VaultParams::default();
        p.argon2.m_cost = 8;
        p.argon2.t_cost = 1;
        p.argon2.p_cost = 1;
        let (_v, session, _recovery) = Vault::init_with_params(garden, PASS, p).unwrap();
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
        let handle = FuseMount::attach_unmounted(
            garden,
            garden,
            session.clone(),
            Arc::new(NullSink),
            None,
            registry,
        )
        .unwrap();
        FuseMount::install_tip_callback(&mut repo, &handle);

        let mut inner = DaemonInner::new(KeeperConfig::new(garden));
        inner.state = State::Unlocked;
        inner.session = Some(session.clone());
        inner.repo = Some(repo);
        inner.fuse = Some(handle);
        (inner, session)
    }

    #[test]
    fn a_shared_only_action_write_commits_to_the_owning_chain_not_the_device() {
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = fuse_inner(garden.path());
        inner
            .fuse
            .as_ref()
            .unwrap()
            .stage_write("proj/note.md", b"hello".to_vec());
        let repo = inner.repo.as_ref().unwrap();
        let dev_before = repo.tip_of(TIP_REF).unwrap();
        let shared_before = repo.tip_of(SHARED_REF).unwrap();

        commit_now(&mut inner, softfig_vcs::Intent::init("action")).unwrap();

        let repo = inner.repo.as_ref().unwrap();
        assert_eq!(
            repo.tip_of(TIP_REF).unwrap(),
            dev_before,
            "a shared-only write must not advance (or churn) the device ref"
        );
        assert_ne!(
            repo.tip_of(SHARED_REF).unwrap(),
            shared_before,
            "the owning chain's ref advanced"
        );
        let mount = inner.fuse.as_ref().unwrap();
        assert!(mount.pending_chain_refs().is_empty(), "staged write absorbed");
        assert_eq!(
            mount.read_workfile("proj/note.md").unwrap().unwrap(),
            b"hello",
            "the write serves from the shared chain's committed tip"
        );
    }

    #[test]
    fn a_mixed_action_write_advances_both_chains_and_returns_the_device_hash() {
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = fuse_inner(garden.path());
        let mount = inner.fuse.as_ref().unwrap();
        mount.stage_write("note.md", b"device".to_vec());
        mount.stage_write("proj/x.md", b"shared".to_vec());
        let shared_before = inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap();

        let hash = commit_now(&mut inner, softfig_vcs::Intent::init("action")).unwrap();

        let repo = inner.repo.as_ref().unwrap();
        assert_eq!(
            repo.tip_of(TIP_REF).unwrap(),
            Some(hash),
            "the returned hash is the device commit"
        );
        assert_ne!(repo.tip_of(SHARED_REF).unwrap(), shared_before);
        let mount = inner.fuse.as_ref().unwrap();
        assert!(mount.pending_chain_refs().is_empty());
        assert_eq!(mount.read_workfile("note.md").unwrap().unwrap(), b"device");
        assert_eq!(mount.read_workfile("proj/x.md").unwrap().unwrap(), b"shared");
    }
}
