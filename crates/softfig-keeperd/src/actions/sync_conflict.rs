//! M5e slice 003 — resolve an offline / partitioned concurrent edit to a shared
//! file that the write-turn lease couldn't prevent, **without losing work**.
//!
//! The write-turn lease (slice 001) stops conflicts *while members are online
//! and coordinated*; two members that edit the same shared file offline (or past
//! a lease expiry) still diverge. Slice 002's apply core detects that divergence
//! and returns [`SharedPullOutcome::Conflict`](super::SharedPullOutcome); this
//! module resolves it: **last-writer-wins by signed edit timestamp** keeps the
//! newer content live, the loser's bytes are preserved in a
//! `<path>.conflict-<loser_device>-<loser_ts>.md` **sidecar**, and one
//! `sync_conflict` commit records the resolution.
//!
//! **Convergence is by construction.** LWW is a *total* order over
//! `(timestamp, device_name)` (newer timestamp wins; equal timestamps break by
//! the deterministic device-name ordering), so both members — seeing the same
//! two `(timestamp, device)` pairs — pick the same winner, reconstruct the
//! **byte-identical** winner-tree-plus-sidecar independently, and land on the
//! same content. The resulting tip then propagates through the ordinary M5b
//! push-on-commit sweep (a third member catches up as a normal fast-forward);
//! the sidecar itself is never re-pushed. See
//! [[decision-m5e-sync-conflict-intent]].
//!
//! **v1 scope.** Single-file conflict (the payload carries a singular `path`).
//! A blob that is Layer-B *sealed under `S`* inside a shared subtree is not
//! auto-resolved — [`materialize_tree`] would need the garden-relative path salt
//! the chain-relative tree walk does not carry, so its decrypt fails and the
//! resolution is refused (fails safe — the conflict is left unresolved, never
//! mis-sealed or dropped). Multi-file conflicts and sidecar GC stay deferred
//! (decision note "Open questions").

use std::path::Path;

use serde_json::json;

use softfig_ipc::ErrorKind;
use softfig_store::{Hash, TreeEntryKind};
use softfig_vault::VaultSession;
use softfig_vcs::{Intent, Repo, WalkSnapshot};

use crate::actions::conventions::sanitize_name_component;
use crate::daemon::{DaemonInner, KeeperError};
use crate::handlers::resolve_path_in_tree;
use crate::server::err_to_response;

/// The two diverged sides of one shared-file conflict, plus the metadata the
/// `sync_conflict` commit records. Captured by the caller before the daemon lock
/// is dropped (the net receive path, [`crate::net`]); every field is already in
/// scope there.
#[derive(Debug, Clone)]
pub(crate) struct ConflictSides {
    /// The shared chain's ref (`chain/<id>`).
    pub chain_ref: String,
    /// The payload `subtree` label. An m5f-slice-002 sender puts the share's
    /// stable id here and sends `files` chain-relative (they resolve verbatim);
    /// a legacy sender puts its own mount path, which
    /// [`read_file_from_tree`]'s fallback strips from the mount-prefixed paths
    /// such a sender ships.
    pub subtree: String,
    /// The conflicting file (payload `files[0]`; v1 is single-file). Addresses
    /// the loser's bytes and names the sidecar.
    pub path: String,
    /// The base **tree** both edits diverged from — recorded in the payload.
    pub base_hash: Hash,
    /// The incoming (peer) edit's tree, already content-addressed into this store
    /// by the transfer.
    pub incoming_tree: Hash,
    /// The incoming edit's originating author device name (payload
    /// `writer_device`; propagated verbatim across relays).
    pub incoming_device: String,
    /// The incoming edit's signed unix-secs timestamp (the LWW key; frame field
    /// 9, propagated verbatim on re-push).
    pub incoming_ts: i64,
    /// Our local chain tip's tree. Slice 002 guarantees a conflict implies a born
    /// local tip, so this is always a real tree.
    pub local_tree: Hash,
    /// Our local tip commit's author device name (read from `CommitRow`).
    pub local_device: String,
    /// Our local tip commit's signed timestamp.
    pub local_ts: i64,
}

/// The outcome of resolving one conflict.
#[derive(Debug)]
pub(crate) enum ConflictResolution {
    /// Committed the `sync_conflict` resolution; the chain fast-forwarded to
    /// `hash`. `kept_device` is the winner; `loser_sidecar` is the tree path the
    /// loser's bytes were preserved at.
    Resolved {
        hash: Hash,
        kept_device: String,
        loser_sidecar: String,
    },
    /// The loser's bytes could not be located in the loser's tree (or its blob
    /// could not be decrypted — e.g. a sealed-under-`S` file, see the module
    /// note). **Refused rather than resolved** — a dropped edit is the exact
    /// failure the sidecar exists to prevent, so the conflict is left unresolved
    /// (the caller logs it) rather than committing a resolution that loses work.
    LoserUnresolvable { path: String },
}

/// Resolve one shared-file conflict: LWW by `(timestamp, device_name)`, preserve
/// the loser in a sidecar within the winner's tree, and land one `sync_conflict`
/// commit on the chain (parent = local tip, linear). The caller holds the inner
/// lock and has verified the vault is unlocked.
pub(crate) fn resolve_sync_conflict(
    inner: &mut DaemonInner,
    sides: ConflictSides,
) -> Result<ConflictResolution, (ErrorKind, String)> {
    let session = inner
        .session
        .clone()
        .ok_or((ErrorKind::VaultLocked, "vault locked".to_string()))?;

    // LWW total order: newer timestamp wins; equal timestamps break by the
    // deterministic device-name ordering (both are device *names*, matching the
    // sidecar filename component). `>` over the tuple is that total order, so
    // both members compute the SAME winner.
    let incoming_wins = (sides.incoming_ts, sides.incoming_device.as_str())
        > (sides.local_ts, sides.local_device.as_str());
    let (winner_tree, loser_tree, loser_device, loser_ts, kept_device) = if incoming_wins {
        (
            sides.incoming_tree,
            sides.local_tree,
            sides.local_device.clone(),
            sides.local_ts,
            sides.incoming_device.clone(),
        )
    } else {
        (
            sides.local_tree,
            sides.incoming_tree,
            sides.incoming_device.clone(),
            sides.incoming_ts,
            sides.local_device.clone(),
        )
    };

    // Read the loser's bytes + materialize the winner tree (immutable repo).
    let (snapshot, sidecar_path) = {
        let repo = inner
            .repo
            .as_ref()
            .ok_or((ErrorKind::VaultLocked, "vault locked".to_string()))?;

        let Some((tree_path, loser_bytes)) =
            read_file_from_tree(repo, &session, &sides.path, &sides.subtree, loser_tree)?
        else {
            return Ok(ConflictResolution::LoserUnresolvable { path: sides.path });
        };

        // `loser_device` is the LOSING side's device *name*; when the local edit
        // wins it is the peer's self-reported `writer_device`, propagated verbatim
        // off the push payload (see `net.rs` provenance). Sanitize it to a single
        // safe path component before it reaches this in-tree write path, so a `/`
        // or `..` in a hostile peer name cannot relocate the sidecar or silently
        // overwrite a tracked file (`insert_file` splits on `/`, honors `..`, and
        // has no exists-check). The sanitizer is pure + deterministic, so both
        // nodes still derive the identical sidecar path (LWW convergence survives).
        // `tree_path` needs no guard: it is the path of a real blob that
        // `read_file_from_tree` resolved out of the loser's committed tree (only
        // real entry names — never `..`/absolute), and `loser_ts` is an `i64`.
        //
        // Spec-faithful literal suffix — appended even when `<path>` already ends
        // in `.md`. A sibling of the resolved tree path, so it lands in the same
        // directory as the file it preserves.
        let safe_device = sanitize_name_component(&loser_device);
        let sidecar_path = format!("{tree_path}.conflict-{safe_device}-{loser_ts}.md");

        let mut snapshot = materialize_tree(repo, &session, winner_tree)?;
        snapshot
            .insert_file(Path::new(&sidecar_path), 0o100644, loser_bytes)
            .map_err(|e| err_to_response(e.into()))?;
        (snapshot, sidecar_path)
    };

    // One `sync_conflict` commit on the chain (parent = local tip, linear).
    let payload = json!({
        "chain_id": sides.chain_ref,
        "path": sides.path,
        "kept_device": kept_device,
        "loser_sidecar": sidecar_path,
        "base_hash": sides.base_hash.to_hex(),
    });
    let intent = Intent::new("sync_conflict", payload).map_err(|e| err_to_response(e.into()))?;

    let repo = inner
        .repo
        .as_mut()
        .ok_or((ErrorKind::VaultLocked, "vault locked".to_string()))?;
    let hash = repo
        .commit_snapshot_to(&sides.chain_ref, &session, snapshot, intent)
        .map_err(|e| err_to_response(e.into()))?;

    Ok(ConflictResolution::Resolved {
        hash,
        kept_device,
        loser_sidecar: sidecar_path,
    })
}

/// A located loser file: the tree path that actually matched + its plaintext.
type LoserFile = (String, Vec<u8>);

/// Read a file's plaintext from `tree` at `path`, returning the tree path that
/// actually resolved alongside the bytes. The push payload carries the path in
/// the write-path's convention; a shared chain's tree stores paths
/// chain-relative (mount stripped), so try `path` verbatim first, then with the
/// `subtree` mount prefix stripped. `None` if neither resolves (the caller
/// treats that as unresolvable).
fn read_file_from_tree(
    repo: &Repo,
    session: &VaultSession,
    path: &str,
    subtree: &str,
    tree: Hash,
) -> Result<Option<LoserFile>, (ErrorKind, String)> {
    let stripped = subtree
        .is_empty()
        .then(|| path.to_string())
        .or_else(|| path.strip_prefix(&format!("{subtree}/")).map(str::to_string));
    let candidates: Vec<String> = match stripped {
        Some(s) if s != path => vec![path.to_string(), s],
        _ => vec![path.to_string()],
    };
    for candidate in candidates {
        if let Some(blob) = resolve_path_in_tree(repo, &tree, &candidate)? {
            let cipher = repo
                .objects()
                .get(&blob)
                .map_err(|e| err_to_response(KeeperError::Store(e)))?;
            let plaintext = session
                .decrypt_tracked_blob(&candidate, &cipher)
                .map_err(|e| (ErrorKind::AuthFailed, format!("decrypt {candidate}: {e}")))?;
            return Ok(Some((candidate, plaintext)));
        }
    }
    Ok(None)
}

/// Materialize an entire tree into a [`WalkSnapshot`] of plaintext files
/// (chain-relative paths, per-file modes preserved). Recommitting the snapshot
/// through `commit_snapshot_to` re-derives the same tree by content —
/// master-keyed / shared-key convergent encryption means every unchanged file
/// round-trips to a byte-identical blob — so the winner's live content is
/// preserved exactly while the sidecar is grafted in.
fn materialize_tree(
    repo: &Repo,
    session: &VaultSession,
    root_tree: Hash,
) -> Result<WalkSnapshot, (ErrorKind, String)> {
    let mut snapshot = WalkSnapshot::empty();
    materialize_into(repo, session, &root_tree, "", &mut snapshot)?;
    Ok(snapshot)
}

fn materialize_into(
    repo: &Repo,
    session: &VaultSession,
    tree: &Hash,
    prefix: &str,
    snapshot: &mut WalkSnapshot,
) -> Result<(), (ErrorKind, String)> {
    let entries = repo
        .db()
        .get_tree(tree)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;
    for entry in entries {
        let path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        match entry.kind {
            TreeEntryKind::Tree => {
                materialize_into(repo, session, &entry.target, &path, snapshot)?;
            }
            TreeEntryKind::Blob => {
                let cipher = repo
                    .objects()
                    .get(&entry.target)
                    .map_err(|e| err_to_response(KeeperError::Store(e)))?;
                let plaintext = session
                    .decrypt_tracked_blob(&path, &cipher)
                    .map_err(|e| (ErrorKind::AuthFailed, format!("decrypt {path}: {e}")))?;
                snapshot
                    .insert_file(Path::new(&path), entry.mode, plaintext)
                    .map_err(|e| err_to_response(e.into()))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Headless (NO net) over a real Vault + Repo with a genesis'd shared chain,
    //! mirroring the slice-002 `apply_shared_pull` harness. The chain is unkeyed
    //! here (no ceremony), so blobs seal under Layer A / `M` — the resolution
    //! logic (LWW, sidecar naming, tree surgery, commit) is key-agnostic, so this
    //! exercises it exactly as the keyed path would.

    use std::path::Path;
    use std::sync::Arc;

    use softfig_store::Hash;
    use softfig_vault::{params::VaultParams, Vault, VaultSession};
    use softfig_vcs::{Intent, Repo, WalkSnapshot};

    use super::{resolve_sync_conflict, ConflictResolution, ConflictSides};
    use crate::actions::conventions::sanitize_name_component;
    use crate::config::KeeperConfig;
    use crate::daemon::DaemonInner;
    use crate::handlers::resolve_path_in_tree;
    use crate::state::State;

    const PASS: &[u8] = b"pw-test-12345";
    const SHARED_REF: &str = "chain/proj";
    const PATH: &str = "proj/a.md";

    fn unlocked_inner(garden: &Path) -> (DaemonInner, Arc<VaultSession>) {
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
            Intent::init("genesis"),
        )
        .unwrap();
        let mut inner = DaemonInner::new(KeeperConfig::new(garden));
        inner.state = State::Unlocked;
        inner.session = Some(session.clone());
        inner.repo = Some(repo);
        (inner, session)
    }

    /// Commit `content` at `PATH` onto `ref_name`, returning the new tip tree.
    fn commit_file(inner: &mut DaemonInner, ref_name: &str, content: &[u8]) -> Hash {
        let session = inner.session.clone().unwrap();
        let repo = inner.repo.as_mut().unwrap();
        let mut snap = WalkSnapshot::empty();
        snap.insert_file(Path::new(PATH), 0o100644, content.to_vec())
            .unwrap();
        let commit = repo
            .commit_snapshot_to(ref_name, &session, snap, Intent::init("genesis"))
            .unwrap();
        repo.db().get_commit(&commit).unwrap().root_tree
    }

    /// Commit a set of `(path, content)` files onto `ref_name`, returning the
    /// new tip tree — the multi-file analogue of [`commit_file`], used to plant
    /// a second tracked file a hostile sidecar path might try to overwrite.
    fn commit_files(inner: &mut DaemonInner, ref_name: &str, files: &[(&str, &[u8])]) -> Hash {
        let session = inner.session.clone().unwrap();
        let repo = inner.repo.as_mut().unwrap();
        let mut snap = WalkSnapshot::empty();
        for (path, content) in files {
            snap.insert_file(Path::new(path), 0o100644, content.to_vec())
                .unwrap();
        }
        let commit = repo
            .commit_snapshot_to(ref_name, &session, snap, Intent::init("genesis"))
            .unwrap();
        repo.db().get_commit(&commit).unwrap().root_tree
    }

    fn tree_of(inner: &DaemonInner, ref_name: &str) -> Option<Hash> {
        let repo = inner.repo.as_ref().unwrap();
        repo.tip_of(ref_name)
            .unwrap()
            .map(|tip| repo.db().get_commit(&tip).unwrap().root_tree)
    }

    /// Read a file's plaintext from the tip tree of `ref_name`, or `None`.
    fn read_tip_file(inner: &DaemonInner, ref_name: &str, path: &str) -> Option<Vec<u8>> {
        let repo = inner.repo.as_ref().unwrap();
        let session = inner.session.as_ref().unwrap();
        let tip = repo.tip_of(ref_name).unwrap()?;
        let root = repo.db().get_commit(&tip).unwrap().root_tree;
        let blob = resolve_path_in_tree(repo, &root, path).unwrap()?;
        let cipher = repo.objects().get(&blob).unwrap();
        Some(session.decrypt_tracked_blob(path, &cipher).unwrap())
    }

    fn sides(
        inner: &DaemonInner,
        incoming_tree: Hash,
        incoming_device: &str,
        incoming_ts: i64,
        local_tree: Hash,
        local_device: &str,
        local_ts: i64,
    ) -> ConflictSides {
        ConflictSides {
            chain_ref: SHARED_REF.to_string(),
            subtree: "proj".to_string(),
            path: PATH.to_string(),
            base_hash: tree_of(inner, SHARED_REF).unwrap(),
            incoming_tree,
            incoming_device: incoming_device.to_string(),
            incoming_ts,
            local_tree,
            local_device: local_device.to_string(),
            local_ts,
        }
    }

    #[test]
    fn incoming_newer_wins_local_preserved_in_sidecar() {
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());

        // Local tip holds our (older) edit; the incoming peer edit is newer.
        let local_tree = commit_file(&mut inner, SHARED_REF, b"local content");
        let incoming_tree = commit_file(&mut inner, "chain/peer-src", b"incoming content");
        let tip_before = inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap();

        let s = sides(&inner, incoming_tree, "peerbox", 200, local_tree, "thisbox", 100);
        let out = resolve_sync_conflict(&mut inner, s).unwrap();
        let (kept, sidecar) = match out {
            ConflictResolution::Resolved { kept_device, loser_sidecar, .. } => (kept_device, loser_sidecar),
            other => panic!("expected Resolved, got {other:?}"),
        };
        assert_eq!(kept, "peerbox", "the newer (incoming) writer wins");
        assert_eq!(sidecar, "proj/a.md.conflict-thisbox-100.md");

        // Winner content is live; the loser's bytes are recoverable from the
        // correctly-named sidecar — the whole point of the slice.
        assert_eq!(
            read_tip_file(&inner, SHARED_REF, PATH).as_deref(),
            Some(&b"incoming content"[..]),
            "the newer content is live"
        );
        assert_eq!(
            read_tip_file(&inner, SHARED_REF, &sidecar).as_deref(),
            Some(&b"local content"[..]),
            "the loser's bytes are recoverable from the sidecar"
        );

        // Exactly ONE sync_conflict commit, parented on the pre-resolve tip.
        let repo = inner.repo.as_ref().unwrap();
        let tip = repo.tip_of(SHARED_REF).unwrap().unwrap();
        let row = repo.db().get_commit(&tip).unwrap();
        assert_eq!(row.intent, "sync_conflict");
        assert_eq!(row.parent, tip_before, "linear on the local tip");
        let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
        assert_eq!(payload["kept_device"], "peerbox");
        assert_eq!(payload["path"], PATH);
        assert_eq!(payload["loser_sidecar"], sidecar);
    }

    #[test]
    fn local_newer_wins_incoming_preserved_in_sidecar() {
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());

        let local_tree = commit_file(&mut inner, SHARED_REF, b"local content");
        let incoming_tree = commit_file(&mut inner, "chain/peer-src", b"incoming content");

        // Local timestamp newer → local wins; the incoming (older) loses.
        let s = sides(&inner, incoming_tree, "peerbox", 100, local_tree, "thisbox", 200);
        let out = resolve_sync_conflict(&mut inner, s).unwrap();
        let (kept, sidecar) = match out {
            ConflictResolution::Resolved { kept_device, loser_sidecar, .. } => (kept_device, loser_sidecar),
            other => panic!("expected Resolved, got {other:?}"),
        };
        assert_eq!(kept, "thisbox", "the newer (local) writer wins");
        assert_eq!(sidecar, "proj/a.md.conflict-peerbox-100.md");
        assert_eq!(
            read_tip_file(&inner, SHARED_REF, PATH).as_deref(),
            Some(&b"local content"[..]),
        );
        assert_eq!(
            read_tip_file(&inner, SHARED_REF, &sidecar).as_deref(),
            Some(&b"incoming content"[..]),
            "the incoming loser's bytes are recoverable",
        );
    }

    #[test]
    fn equal_timestamp_breaks_by_device_name_deterministically() {
        // Equal ts → the lexicographically larger device NAME wins, regardless of
        // which side it is on. Both members compute the identical winner.
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());
        let local_tree = commit_file(&mut inner, SHARED_REF, b"local content");
        let incoming_tree = commit_file(&mut inner, "chain/peer-src", b"incoming content");

        // "zzz" (local) > "aaa" (incoming) → local wins on the tiebreak.
        let s = sides(&inner, incoming_tree, "aaa", 150, local_tree, "zzz", 150);
        match resolve_sync_conflict(&mut inner, s).unwrap() {
            ConflictResolution::Resolved { kept_device, .. } => {
                assert_eq!(kept_device, "zzz", "equal ts → larger device name wins");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }

        // Mirror: put the larger name on the INCOMING side → incoming wins. Same
        // rule, opposite side, proving the tiebreak is side-independent.
        let garden2 = tempfile::tempdir().unwrap();
        let (mut inner2, _s2) = unlocked_inner(garden2.path());
        let local2 = commit_file(&mut inner2, SHARED_REF, b"local content");
        let incoming2 = commit_file(&mut inner2, "chain/peer-src", b"incoming content");
        let s2 = sides(&inner2, incoming2, "zzz", 150, local2, "aaa", 150);
        match resolve_sync_conflict(&mut inner2, s2).unwrap() {
            ConflictResolution::Resolved { kept_device, .. } => {
                assert_eq!(kept_device, "zzz", "the larger name wins from either side");
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn unresolvable_loser_refuses_rather_than_dropping_work() {
        // If the loser's path is absent from the loser tree, refuse — never
        // commit a resolution that silently drops the loser's bytes.
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());
        let local_tree = commit_file(&mut inner, SHARED_REF, b"local content");
        let incoming_tree = commit_file(&mut inner, "chain/peer-src", b"incoming content");
        let tip_before = inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap();

        // Incoming wins, so the loser is LOCAL, but we name a path that isn't in
        // the tree.
        let mut s = sides(&inner, incoming_tree, "peerbox", 200, local_tree, "thisbox", 100);
        s.path = "proj/missing.md".to_string();
        match resolve_sync_conflict(&mut inner, s).unwrap() {
            ConflictResolution::LoserUnresolvable { path } => {
                assert_eq!(path, "proj/missing.md");
            }
            other => panic!("expected LoserUnresolvable, got {other:?}"),
        }
        assert_eq!(
            inner.repo.as_ref().unwrap().tip_of(SHARED_REF).unwrap(),
            tip_before,
            "a refused resolution must NOT advance the chain",
        );
    }

    #[test]
    fn hostile_loser_device_name_is_sanitized_and_convergent() {
        // Slice 006: the LOSING side's device name reaches the in-tree sidecar
        // path. When the local edit wins, `loser_device` is the peer's verbatim
        // self-reported `writer_device` — a `/` or `..` in it must not relocate
        // the sidecar, and the sanitized path must be identical on both nodes
        // (LWW convergence must survive the guard).
        for hostile in ["a/b", "../escape", "x/../../y"] {
            let mut sidecars = Vec::new();
            for _ in 0..2 {
                // Two independent nodes, identical inputs → identical sidecar.
                let garden = tempfile::tempdir().unwrap();
                let (mut inner, _s) = unlocked_inner(garden.path());
                let local_tree = commit_file(&mut inner, SHARED_REF, b"winner");
                let incoming_tree = commit_file(&mut inner, "chain/peer-src", b"loser bytes");
                // local ts newer → local wins → loser = incoming (hostile name).
                let s = sides(&inner, incoming_tree, hostile, 100, local_tree, "thisbox", 200);
                let sidecar = match resolve_sync_conflict(&mut inner, s).unwrap() {
                    ConflictResolution::Resolved { loser_sidecar, .. } => loser_sidecar,
                    other => panic!("expected Resolved, got {other:?}"),
                };
                // One safe component appended under `proj/a.md`: uses the
                // sanitized device name, injects no separator, climbs nowhere.
                assert_eq!(
                    sidecar,
                    format!("proj/a.md.conflict-{}-100.md", sanitize_name_component(hostile)),
                    "sidecar uses the sanitized device component ({hostile})",
                );
                assert_eq!(
                    sidecar.matches('/').count(),
                    "proj/a.md".matches('/').count(),
                    "no separator injected by the device name ({hostile})",
                );
                assert!(
                    !sidecar.split('/').any(|c| c == ".."),
                    "no parent-traversal component ({hostile})",
                );
                // Loser bytes land at the sanitized sidecar; winner stays live.
                assert_eq!(
                    read_tip_file(&inner, SHARED_REF, &sidecar).as_deref(),
                    Some(&b"loser bytes"[..]),
                    "loser recoverable at the sanitized sidecar ({hostile})",
                );
                assert_eq!(
                    read_tip_file(&inner, SHARED_REF, PATH).as_deref(),
                    Some(&b"winner"[..]),
                    "winner content live ({hostile})",
                );
                sidecars.push(sidecar);
            }
            assert_eq!(sidecars[0], sidecars[1], "convergent sidecar path for {hostile}");
        }
    }

    #[test]
    fn hostile_loser_device_cannot_overwrite_a_tracked_file() {
        // Pre-fix, a `loser_device` of `x/../secret` would have made the sidecar
        // path `proj/a.md.conflict-x/../secret-100.md` → `insert_file` splits on
        // `/`, honors `..`, and (no exists-check) would clobber the tracked
        // `proj/secret-100.md` in the winner tree. Post-sanitization the device
        // name is one component, so the tracked file is untouched.
        let garden = tempfile::tempdir().unwrap();
        let (mut inner, _session) = unlocked_inner(garden.path());

        // Winner (local) tree carries the conflicting file AND a bystander file.
        let local_tree = commit_files(
            &mut inner,
            SHARED_REF,
            &[("proj/a.md", b"winner"), ("proj/secret-100.md", b"do not overwrite")],
        );
        let incoming_tree = commit_file(&mut inner, "chain/peer-src", b"loser bytes");

        // local ts newer → local wins → loser = incoming with the hostile name.
        let s = sides(&inner, incoming_tree, "x/../secret", 100, local_tree, "thisbox", 200);
        let sidecar = match resolve_sync_conflict(&mut inner, s).unwrap() {
            ConflictResolution::Resolved { kept_device, loser_sidecar, .. } => {
                assert_eq!(kept_device, "thisbox");
                loser_sidecar
            }
            other => panic!("expected Resolved, got {other:?}"),
        };

        // The bystander file keeps its content — NOT the loser's bytes.
        assert_eq!(
            read_tip_file(&inner, SHARED_REF, "proj/secret-100.md").as_deref(),
            Some(&b"do not overwrite"[..]),
            "a hostile device name must not overwrite a tracked file",
        );
        // The sidecar lands at the sanitized sibling path with the loser bytes.
        assert_eq!(sidecar, "proj/a.md.conflict-x_._secret-100.md");
        assert_eq!(
            read_tip_file(&inner, SHARED_REF, &sidecar).as_deref(),
            Some(&b"loser bytes"[..]),
        );
    }
}
