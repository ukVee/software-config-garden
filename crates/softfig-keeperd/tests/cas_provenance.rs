//! Phase 3 (`growlight-garden-cas`) slice 001 integration: optimistic
//! concurrency (CAS) on the section / whole-file edit verbs + the
//! `file_provenance` read.
//!
//! Proves the spec §5 contract end-to-end against a live daemon: two writers
//! to DIFFERENT sections of one file both succeed; two to the SAME section
//! conflict, and the loser re-reads + reapplies. `replace_file` carries the
//! same whole-file guard. `file_provenance` reconstructs who/when/what from
//! committed commit data alone.
//!
//! All gardens are M1c-compat (no `state_root` → no FUSE), so the suite runs
//! without `/dev/fuse`; files reach the tip via the same `replace_file` /
//! section verbs production uses. The "no mount I/O under `daemon.inner`"
//! invariant is upheld by construction (CAS reads ride the `WorkTree`,
//! provenance reads ride the committed object DB); a live-FUSE concurrent
//! fleet is the deferred on-device smoke (milestone `## Deferred verification`).

use std::path::{Path, PathBuf};

use softfig_vcs::Repo;
use softfig_ipc::verbs::{op, DocEditReply, FileProvenanceReply, ReadFileReply, ReplaceFileReply};
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::Vault;

mod common;
use common::{err_kind, fast_params, ok_data, send, wait_for_socket};

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn init_garden(garden: &Path) {
    let (_vault, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
}

struct Fixture {
    socket: PathBuf,
    handle: Option<DaemonHandle>,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn start() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let garden = tmp.path().to_path_buf();
        init_garden(&garden);
        let socket = garden.join("sock");
        let config = KeeperConfig::new(&garden)
            .without_watcher()
            .without_net()
            .with_socket(&socket);
        let handle = Daemon::new(config).start().unwrap();
        wait_for_socket(&socket);
        let resp = send(
            &socket,
            &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
        );
        assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");
        Fixture {
            socket,
            handle: Some(handle),
            _tmp: tmp,
        }
    }

    fn call(&self, op_name: &str, args: serde_json::Value) -> Response {
        send(&self.socket, &Request::new(op_name, args))
    }

    fn write_file(&self, path: &str, content: &str) {
        let resp = self.call(
            op::REPLACE_FILE,
            serde_json::json!({ "path": path, "content": content }),
        );
        assert!(matches!(resp, Response::Ok { .. }), "write {path}: {resp:?}");
    }

    fn read(&self, path: &str) -> ReadFileReply {
        serde_json::from_value(ok_data(self.call(op::READ_FILE, serde_json::json!({ "path": path }))))
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
            let _ = handle.join();
        }
    }
}

/// The current version of `heading` from a `read_file` reply's section list.
fn section_version(r: &ReadFileReply, heading: &str) -> String {
    r.sections
        .iter()
        .find(|s| s.heading == heading)
        .unwrap_or_else(|| panic!("no section {heading:?} in {:?}", r.sections))
        .version
        .clone()
}

fn edit_section(fx: &Fixture, path: &str, heading: &str, body: &str, expected: Option<&str>) -> Response {
    let mut args = serde_json::json!({ "path": path, "heading": heading, "body": body });
    if let Some(v) = expected {
        args["expected_version"] = serde_json::json!(v);
    }
    fx.call(op::EDIT_SECTION, args)
}

// ---- CAS: concurrent different sections never collide -----------------

#[test]
fn cas_different_sections_of_one_file_both_succeed() {
    let fx = Fixture::start();
    fx.write_file("doc.md", "# Doc\n\n## Alpha\n\nold a\n\n## Beta\n\nold b\n");

    let r = fx.read("doc.md");
    let va = section_version(&r, "Alpha");
    let vb = section_version(&r, "Beta");
    assert_ne!(va, vb);

    // Writer 1 guards on Alpha's version → applies.
    let reply: DocEditReply =
        serde_json::from_value(ok_data(edit_section(&fx, "doc.md", "Alpha", "new a", Some(&va))))
            .unwrap();
    assert_ne!(reply.version, va, "edit hands back a fresh section version");

    // Writer 2 guards on Beta's version — still valid because only Alpha moved.
    // This is the whole point of per-section CAS: same file, different section,
    // no conflict.
    let resp = edit_section(&fx, "doc.md", "Beta", "new b", Some(&vb));
    assert!(matches!(resp, Response::Ok { .. }), "beta edit: {resp:?}");

    let after = fx.read("doc.md");
    assert!(after.content.contains("new a"));
    assert!(after.content.contains("new b"));
}

// ---- CAS: same-section conflict, then re-read + reapply ----------------

#[test]
fn cas_same_section_rejects_stale_then_succeeds_after_reread() {
    let fx = Fixture::start();
    fx.write_file("doc.md", "## A\n\nv1\n");

    let v0 = section_version(&fx.read("doc.md"), "A");

    // Writer 1 commits, advancing A past v0.
    let reply1: DocEditReply =
        serde_json::from_value(ok_data(edit_section(&fx, "doc.md", "A", "w1 wins", Some(&v0))))
            .unwrap();
    let v1 = reply1.version;
    assert_ne!(v1, v0);

    // Writer 2 still holds the stale v0 → stale-reject (no lost update).
    let resp = edit_section(&fx, "doc.md", "A", "w2 clobber", Some(&v0));
    assert_eq!(err_kind(resp), ErrorKind::Conflict);
    // ...and the stale write did NOT land.
    assert!(fx.read("doc.md").content.contains("w1 wins"));

    // Writer 2 re-reads, gets the fresh version, and re-applies successfully.
    let v_fresh = section_version(&fx.read("doc.md"), "A");
    assert_eq!(v_fresh, v1, "re-read yields writer 1's version");
    let resp = edit_section(&fx, "doc.md", "A", "w2 after reread", Some(&v_fresh));
    assert!(matches!(resp, Response::Ok { .. }), "retry: {resp:?}");
    assert!(fx.read("doc.md").content.contains("w2 after reread"));
}

#[test]
fn edit_without_expected_version_is_unconditional() {
    // Omitting the guard keeps the legacy last-writer-wins behaviour.
    let fx = Fixture::start();
    fx.write_file("doc.md", "## A\n\nv1\n");
    let resp = edit_section(&fx, "doc.md", "A", "blind write", None);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    assert!(fx.read("doc.md").content.contains("blind write"));
}

// ---- CAS: whole-file replace_file --------------------------------------

#[test]
fn replace_file_whole_file_cas() {
    let fx = Fixture::start();
    fx.write_file("rf.md", "hello\n");
    let v0 = fx.read("rf.md").version;
    assert!(!v0.is_empty());

    // Correct version → applies, returns the new version.
    let reply: ReplaceFileReply = serde_json::from_value(ok_data(fx.call(
        op::REPLACE_FILE,
        serde_json::json!({ "path": "rf.md", "content": "hello v2\n", "expected_version": v0 }),
    )))
    .unwrap();
    assert_ne!(reply.version, v0);

    // Re-using the stale v0 → conflict (the file moved under it).
    let resp = fx.call(
        op::REPLACE_FILE,
        serde_json::json!({ "path": "rf.md", "content": "hello v3\n", "expected_version": v0 }),
    );
    assert_eq!(err_kind(resp), ErrorKind::Conflict);
    assert!(fx.read("rf.md").content.contains("hello v2"));
}

// ---- file_provenance ---------------------------------------------------

#[test]
fn provenance_reports_recent_edits_most_recent_first() {
    let fx = Fixture::start();
    fx.write_file("p.md", "# P\n\n## S\n\nbody\n"); // memory_edit
    let resp = edit_section(&fx, "p.md", "S", "edited body", None); // section_edited
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

    let reply: FileProvenanceReply = serde_json::from_value(ok_data(
        fx.call(op::FILE_PROVENANCE, serde_json::json!({ "path": "p.md" })),
    ))
    .unwrap();

    assert_eq!(reply.path, "p.md");
    assert!(reply.edits.len() >= 2, "edits: {:?}", reply.edits);
    // Most-recent-first: the last edit was the section edit.
    assert_eq!(reply.edits[0].intent, "section_edited");
    // The file's creation is in there too.
    assert!(reply.edits.iter().any(|e| e.intent == "memory_edit"));
    // Who/when are populated, and timestamps are non-increasing (tip → genesis).
    assert!(!reply.edits[0].author_device.is_empty());
    for w in reply.edits.windows(2) {
        assert!(w[0].timestamp >= w[1].timestamp, "not ordered: {:?}", reply.edits);
    }
}

#[test]
fn provenance_of_unwritten_path_is_empty() {
    let fx = Fixture::start();
    fx.write_file("present.md", "x");
    let reply: FileProvenanceReply = serde_json::from_value(ok_data(
        fx.call(op::FILE_PROVENANCE, serde_json::json!({ "path": "never.md" })),
    ))
    .unwrap();
    assert!(reply.edits.is_empty(), "edits: {:?}", reply.edits);
}

#[test]
fn provenance_limit_caps_results() {
    let fx = Fixture::start();
    fx.write_file("p.md", "## A\n\nstart\n");
    for i in 0..4 {
        let resp = edit_section(&fx, "p.md", "A", &format!("rev {i}"), None);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    }
    let reply: FileProvenanceReply = serde_json::from_value(ok_data(fx.call(
        op::FILE_PROVENANCE,
        serde_json::json!({ "path": "p.md", "limit": 2 }),
    )))
    .unwrap();
    assert_eq!(reply.edits.len(), 2);
}

#[test]
fn provenance_refuses_when_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path().to_path_buf();
    init_garden(&garden);
    let socket = garden.join("sock");
    let config = KeeperConfig::new(&garden)
        .without_watcher()
        .without_net()
        .with_socket(&socket);
    let handle = Daemon::new(config).start().unwrap();
    wait_for_socket(&socket);
    // No unlock.
    let resp = send(
        &socket,
        &Request::new(op::FILE_PROVENANCE, serde_json::json!({ "path": "anything.md" })),
    );
    assert_eq!(err_kind(resp), ErrorKind::VaultLocked);
    handle.shutdown();
    let _ = handle.join();
}
