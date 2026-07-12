//! M5c slice 006 — the overlay absorption invariant: no rotation may drop
//! unabsorbed writes.
//!
//! Root cause under test: `rotate_tip` used to end in an unconditional
//! `overlay.clear()`, correct only while every rotation followed a commit
//! that had absorbed the whole overlay. Multi-ref broke that — a device
//! commit's rotation absorbs only the device carve-out, and a registry
//! hot-swap (`set_registry`) commits nothing at all. These tests drive the
//! production state machine headlessly via `FuseMount::attach_unmounted`
//! (everything but the kernel session — no `/dev/fuse` needed) and pin:
//!
//! * (a) a staged shared-path write survives a device-only commit's rotation;
//! * (b) it survives `set_registry` (enable/disable/add/remove hot-swaps);
//! * (c) an unabsorbed write is *recoverable* — the next snapshot of its
//!   chain still carries it, and committing that chain absorbs it;
//! * a write racing in after the snapshot capture survives the rotation
//!   (the generation cutoff, not just chain ownership).

use std::path::Path;
use std::sync::Arc;

use softfig_fuse::{DirtyEventSink, FuseMount, MountHandle};
use softfig_vault::{params::VaultParams, Vault, VaultSession};
use softfig_vcs::{Chain, ChainRegistry, Intent, Repo, WalkSnapshot, TIP_REF};

const PASS: &[u8] = b"correct horse battery staple";
const SHARED_REF: &str = "chain/proj";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

/// The FUSE driver's sink is irrelevant here — staged writes go through
/// `MountHandle::stage_write`, which deliberately fires no dirty event.
struct NullSink;
impl DirtyEventSink for NullSink {
    fn created(&self, _: &str) {}
    fn modified(&self, _: &str) {}
    fn removed(&self, _: &str) {}
    fn renamed(&self, _: &str, _: &str) {}
    fn nudge(&self) {}
}

/// A garden with a device chain (genesis) + an empty shared chain mounted at
/// `proj/`, served by an unmounted `MountHandle` wired to the repo's
/// tip-changed callback — the exact production rotation path.
struct Fixture {
    repo: Repo,
    session: Arc<VaultSession>,
    handle: MountHandle,
    _garden: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let garden = tempfile::tempdir().unwrap();
    let (_v, session, _recovery) =
        Vault::init_with_params(garden.path(), PASS, fast_params()).expect("vault init");
    let session = Arc::new(session);
    let (mut repo, _genesis) = Repo::init(garden.path(), &session).expect("repo init");
    // Shared-chain genesis: an empty snapshot on its own ref (the slice-003
    // add shape), so the union can compose it.
    repo.commit_snapshot_to(SHARED_REF, &session, WalkSnapshot::empty(), Intent::init("genesis"))
        .expect("shared genesis");

    let registry = ChainRegistry::new(
        Chain::device(),
        vec![Chain::shared("proj", SHARED_REF, "proj", true)],
    );
    let handle = FuseMount::attach_unmounted(
        garden.path(),
        garden.path(),
        session.clone(),
        Arc::new(NullSink),
        None,
        registry,
    )
    .expect("attach");
    FuseMount::install_tip_callback(&mut repo, &handle);
    Fixture {
        repo,
        session,
        handle,
        _garden: garden,
    }
}

fn read(handle: &MountHandle, rel: &str) -> Option<Vec<u8>> {
    handle.read_workfile(rel).unwrap()
}

/// (a) + (c): a staged shared write survives the device commit's rotation and
/// is absorbed only when its own chain commits — never lost, never misrouted.
#[test]
fn shared_write_survives_device_rotation_and_is_absorbed_by_its_own_chain() {
    let mut fx = fixture();
    fx.handle.stage_write("note.md", b"device body".to_vec());
    fx.handle.stage_write("proj/x.md", b"shared body".to_vec());

    let mut pending = fx.handle.pending_chain_refs();
    pending.sort();
    assert_eq!(pending, vec![SHARED_REF.to_string(), TIP_REF.to_string()]);

    // Device-only commit (the watcher/commit_now device leg): its rotation
    // must absorb note.md and ONLY note.md.
    let snap = fx.handle.workdir_snapshot().unwrap();
    assert!(snap.file_content(Path::new("note.md")).is_some());
    assert!(
        snap.file_content(Path::new("proj/x.md")).is_none(),
        "device carve-out must exclude the shared subtree"
    );
    let dev_tip = fx
        .repo
        .commit_snapshot(&fx.session, snap, Intent::init("device commit"))
        .unwrap();

    assert_eq!(read(&fx.handle, "note.md").unwrap(), b"device body");
    assert_eq!(
        read(&fx.handle, "proj/x.md").unwrap(),
        b"shared body",
        "unabsorbed shared write must survive the device rotation"
    );
    assert_eq!(fx.handle.pending_chain_refs(), vec![SHARED_REF.to_string()]);

    // (c) recoverable: a fresh snapshot of the shared chain still carries the
    // write (mount-relative), and committing it absorbs it.
    let shared_snap = fx
        .handle
        .chain_snapshots()
        .unwrap()
        .into_iter()
        .find(|(r, _)| r == SHARED_REF)
        .map(|(_, s)| s)
        .expect("shared chain snapshot");
    assert!(shared_snap.file_content(Path::new("x.md")).is_some());
    fx.repo
        .commit_snapshot_to(SHARED_REF, &fx.session, shared_snap, Intent::init("shared commit"))
        .unwrap();

    assert!(fx.handle.pending_chain_refs().is_empty(), "overlay fully absorbed");
    assert_eq!(
        read(&fx.handle, "proj/x.md").unwrap(),
        b"shared body",
        "the write now serves from the shared chain's tip"
    );
    // The device ref never moved for the shared commit.
    assert_eq!(fx.repo.tip_of(TIP_REF).unwrap(), Some(dev_tip));
}

/// (b): a registry hot-swap commits nothing, so it must clear nothing — the
/// pending overlay survives enable/disable/add/remove recompositions.
#[test]
fn set_registry_preserves_the_pending_overlay() {
    let fx = fixture();
    fx.handle.stage_write("dev.md", b"dev".to_vec());
    fx.handle.stage_write("proj/y.md", b"shared".to_vec());
    let dev_tip = fx.repo.tip_of(TIP_REF).unwrap();
    let shared_tip = fx.repo.tip_of(SHARED_REF).unwrap();

    // Disable the share (ownership of proj/ falls back to the device chain),
    // then re-enable — the local-toggle round trip.
    for enabled in [false, true] {
        fx.handle.set_registry(ChainRegistry::new(
            Chain::device(),
            vec![Chain::shared("proj", SHARED_REF, "proj", enabled)],
        ));
        assert_eq!(read(&fx.handle, "dev.md").unwrap(), b"dev");
        assert_eq!(
            read(&fx.handle, "proj/y.md").unwrap(),
            b"shared",
            "registry hot-swap (enabled={enabled}) must not drop staged writes"
        );
    }
    // No commit happened anywhere.
    assert_eq!(fx.repo.tip_of(TIP_REF).unwrap(), dev_tip);
    assert_eq!(fx.repo.tip_of(SHARED_REF).unwrap(), shared_tip);
}

/// The cutoff is the snapshot *generation*, not mere chain ownership: a
/// device-owned write staged after the snapshot capture was not in the
/// commit and must survive its rotation.
#[test]
fn write_racing_in_after_the_snapshot_survives_the_rotation() {
    let mut fx = fixture();
    fx.handle.stage_write("a.md", b"captured".to_vec());
    let snap = fx.handle.workdir_snapshot().unwrap(); // stamps the cutoff
    fx.handle.stage_write("b.md", b"raced in".to_vec()); // after capture

    fx.repo
        .commit_snapshot(&fx.session, snap, Intent::init("device commit"))
        .unwrap();

    assert_eq!(read(&fx.handle, "a.md").unwrap(), b"captured");
    assert_eq!(
        read(&fx.handle, "b.md").unwrap(),
        b"raced in",
        "a post-snapshot write is unabsorbed and must survive"
    );
    assert_eq!(
        fx.handle.pending_chain_refs(),
        vec![TIP_REF.to_string()],
        "the racer stays pending for the next flush"
    );
}
