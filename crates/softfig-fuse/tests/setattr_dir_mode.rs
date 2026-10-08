//! Regression: a `chmod` on a directory must not replace it with a file.
//!
//! Root cause (fixed 2026-09-09): `setattr` staged *every* mode change through
//! `overlay.insert_file`, with no check on the entry's kind. A directory's
//! bytes read back empty, so `chmod` on one inserted a zero-byte **File**
//! overlay entry at the directory's path — the directory became a file and
//! every child was orphaned.
//!
//! It is reachable from the most ordinary copy there is: `cp -r`, `cp -a`,
//! `rsync -a` and `tar -xp` all chmod each directory after filling it. It cost
//! eight directories of content while importing a garden's first files onto a
//! second device. `setattr` already carried a mount-root guard for the same
//! hazard at a shared graft point (m5e slice 007); this pins the general case.

use std::path::Path;
use std::sync::Arc;

use softfig_fuse::{DirtyEventSink, FuseMount, MountHandle};
use softfig_vault::{params::VaultParams, Vault, VaultSession};
use softfig_vcs::{Chain, ChainRegistry, Repo};

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
    handle: MountHandle,
    _session: Arc<VaultSession>,
    _garden: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let garden = tempfile::tempdir().unwrap();
    let (_v, session, _recovery) =
        Vault::init_with_params(garden.path(), PASS, fast_params()).expect("vault init");
    let session = Arc::new(session);
    let (mut repo, _genesis) = Repo::init(garden.path(), &session).expect("repo init");
    let registry = ChainRegistry::new(Chain::device(), vec![]);
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
        handle,
        _session: session,
        _garden: garden,
    }
}

/// The `cp -r` shape: fill a directory, then chmod the directory. The children
/// must still be there, and the directory must still be a directory.
#[test]
fn chmod_on_a_directory_keeps_the_directory_and_its_children() {
    let fx = fixture();
    fx.handle.stage_write("services/sshd/CLAUDE.md", b"posture".to_vec());
    fx.handle.stage_write("services/sshd/notes/001-port.md", b"42218".to_vec());
    assert!(fx.handle.path_is_dir("services/sshd"));

    // What `cp -r` does after copying a directory's contents.
    let staged = fx.handle.stage_mode("services/sshd", 0o755);

    assert!(!staged, "a directory's mode is not versioned — nothing to stage");
    assert!(
        fx.handle.path_is_dir("services/sshd"),
        "chmod turned the directory into a file"
    );
    assert_eq!(
        fx.handle.read_workfile("services/sshd/CLAUDE.md").unwrap(),
        Some(b"posture".to_vec()),
        "child orphaned by a chmod on its parent"
    );
    assert_eq!(
        fx.handle.read_workfile("services/sshd/notes/001-port.md").unwrap(),
        Some(b"42218".to_vec()),
        "grandchild orphaned by a chmod on its grandparent"
    );

    // The whole subtree must still reach a commit intact.
    let snap = fx.handle.workdir_snapshot().unwrap();
    assert!(snap.file_content(Path::new("services/sshd/CLAUDE.md")).is_some());
    assert!(snap.file_content(Path::new("services/sshd/notes/001-port.md")).is_some());
}

/// The counterpart: a chmod on a *file* is the case `setattr` was written for
/// and must still stage, preserving the file's bytes.
#[test]
fn chmod_on_a_file_still_stages_and_keeps_its_content() {
    let fx = fixture();
    fx.handle.stage_write("snapshots/refresh.sh", b"#!/bin/sh\n".to_vec());

    let staged = fx.handle.stage_mode("snapshots/refresh.sh", 0o100755);

    assert!(staged, "a file's mode change must still be staged");
    assert_eq!(
        fx.handle.read_workfile("snapshots/refresh.sh").unwrap(),
        Some(b"#!/bin/sh\n".to_vec()),
        "chmod must not disturb the file's bytes"
    );
}
