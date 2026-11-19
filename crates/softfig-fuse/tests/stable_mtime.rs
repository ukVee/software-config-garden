//! Report 185: the mount's timestamps move only when content does.
//!
//! Root cause: every `getattr` stamped atime/mtime/ctime with
//! `SystemTime::now()`, so each file looked freshly modified on every `stat`.
//! No mtime-keyed cache could work against the mount; growlightd's v2 source
//! re-read its whole backlog every second because of it (its module doc said
//! so), and that pegged keeperd's FUSE thread at ~42 % of the core.
//!
//! These drive the production rotation path headlessly (the repo's
//! `tip_changed` callback into an unmounted `MountHandle`) and pin:
//!
//! * an untouched path keeps its mtime across looks and across rotations;
//! * a staged write moves the mtime, and the commit that absorbs the write
//!   keeps that stamp (an editor that saved does not see a second change);
//! * a change below a directory moves the directory's mtime, not a sibling's;
//! * the base for untouched paths is the tip commit's time, so a fresh mount
//!   (a daemon restart) reports the same mtimes as the last one.

use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, UNIX_EPOCH};

use softfig_fuse::{DirtyEventSink, FuseMount, MountHandle};
use softfig_vault::{params::VaultParams, Vault, VaultSession};
use softfig_vcs::{Chain, ChainRegistry, Intent, Repo};

const PASS: &[u8] = b"correct horse battery staple";

struct NullSink;
impl DirtyEventSink for NullSink {
    fn created(&self, _: &str) {}
    fn modified(&self, _: &str) {}
    fn removed(&self, _: &str) {}
    fn renamed(&self, _: &str, _: &str) {}
    fn nudge(&self) {}
}

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

struct Fixture {
    repo: Repo,
    session: Arc<VaultSession>,
    handle: MountHandle,
    garden: tempfile::TempDir,
}

impl Fixture {
    /// Commit whatever the overlay holds, through the production rotation.
    fn commit(&mut self) {
        let snap = self.handle.workdir_snapshot().unwrap();
        self.repo
            .commit_snapshot(&self.session, snap, Intent::init("commit"))
            .unwrap();
    }

    /// A second, fresh mount of the same garden — what a daemon restart serves.
    fn remount(&self) -> MountHandle {
        attach(&self.garden, &self.session)
    }
}

fn attach(garden: &tempfile::TempDir, session: &Arc<VaultSession>) -> MountHandle {
    FuseMount::attach_unmounted(
        garden.path(),
        garden.path(),
        session.clone(),
        Arc::new(NullSink),
        None,
        ChainRegistry::new(Chain::device(), vec![]),
    )
    .expect("attach")
}

fn fixture() -> Fixture {
    let garden = tempfile::tempdir().unwrap();
    let (_v, session, _recovery) =
        Vault::init_with_params(garden.path(), PASS, fast_params()).expect("vault init");
    let session = Arc::new(session);
    let (mut repo, _genesis) = Repo::init(garden.path(), &session).expect("repo init");
    let handle = attach(&garden, &session);
    FuseMount::install_tip_callback(&mut repo, &handle);
    Fixture {
        repo,
        session,
        handle,
        garden,
    }
}

/// Long enough that two `SystemTime::now()` reads on either side differ.
fn tick() {
    sleep(Duration::from_millis(5));
}

#[test]
fn an_untouched_file_keeps_its_mtime_across_looks_and_rotations() {
    let mut fx = fixture();
    fx.handle.stage_write("a.md", b"a".to_vec());
    fx.handle.stage_write("b.md", b"b".to_vec());
    fx.commit();

    let a = fx.handle.modified_at("a.md").expect("a.md resolves");
    let b = fx.handle.modified_at("b.md").expect("b.md resolves");
    tick();
    assert_eq!(fx.handle.modified_at("a.md"), Some(a), "a second look is the same time");

    fx.handle.stage_write("b.md", b"b2".to_vec());
    fx.commit();
    assert_eq!(fx.handle.modified_at("a.md"), Some(a), "another file's commit leaves a.md alone");
    assert!(fx.handle.modified_at("b.md").unwrap() > b, "b.md changed, so its mtime moved");
}

#[test]
fn a_write_stamps_the_file_and_the_commit_keeps_that_stamp() {
    let mut fx = fixture();
    fx.handle.stage_write("note.md", b"v1".to_vec());
    fx.commit();
    let committed = fx.handle.modified_at("note.md").unwrap();

    tick();
    fx.handle.stage_write("note.md", b"v2".to_vec());
    let written = fx.handle.modified_at("note.md").unwrap();
    assert!(written > committed, "the staged write moves the mtime");

    tick();
    fx.commit();
    assert_eq!(
        fx.handle.modified_at("note.md"),
        Some(written),
        "absorbing the write is not a second change"
    );
}

#[test]
fn a_change_below_a_directory_moves_its_mtime_and_not_a_siblings() {
    let mut fx = fixture();
    fx.handle.stage_write("d/x.md", b"x".to_vec());
    fx.handle.stage_write("e/z.md", b"z".to_vec());
    fx.commit();
    let d = fx.handle.modified_at("d").unwrap();
    let e = fx.handle.modified_at("e").unwrap();

    tick();
    fx.handle.stage_write("d/y.md", b"y".to_vec());
    fx.commit();
    assert!(fx.handle.modified_at("d").unwrap() > d, "a new child moves the directory");
    assert_eq!(fx.handle.modified_at("e"), Some(e), "the sibling directory is untouched");
    assert_eq!(fx.handle.modified_at("gone"), None, "an absent path has no mtime");
}

#[test]
fn a_fresh_mount_reports_the_tip_commit_time_for_untouched_paths() {
    let mut fx = fixture();
    fx.handle.stage_write("a.md", b"a".to_vec());
    fx.commit();
    let tip = fx.repo.tip().unwrap().expect("a tip");
    let committed_at = fx.repo.db().get_commit(&tip).unwrap().timestamp;
    let expected = UNIX_EPOCH + Duration::from_secs(committed_at as u64);

    let first = fx.remount();
    assert_eq!(first.modified_at("a.md"), Some(expected));
    tick();
    let second = fx.remount();
    assert_eq!(
        second.modified_at("a.md"),
        Some(expected),
        "a restart alone does not make the garden look modified"
    );
}
