//! mcp-surgical-writes integration: the surgical write-surface verbs
//! (`read_versions`, `patch_file`, `remove_section`, `unlink`, `batch`) —
//! slice 001 first: the CAS-seeding read verb.
//!
//! Same harness posture as `m3b_reads.rs`: M1c-compat gardens (no FUSE), files
//! reach the committed tip via `replace_file` (the same `BlobEncryptor` hook
//! real writes use), so sealing + redaction behave exactly as in production.
//!
//! `read_versions` is a projection of `read_file`'s Phase 3 CAS — the tests
//! assert the two verbs agree on the same file, and that the new verb returns
//! version tokens ONLY (no content, no commit, no intent).

use std::path::PathBuf;

use softfig_ipc::verbs::{op, ReadFileReply, ReadVersionsReply};
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::Vault;
use softfig_vcs::Repo;

mod common;
use common::{err_kind, fast_params, ok_data, send, wait_for_socket};

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn init_garden(garden: &std::path::Path) {
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
    fn start(unlock: bool) -> Self {
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
        if unlock {
            let resp = send(
                &socket,
                &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
            );
            assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");
        }
        Fixture {
            socket,
            handle: Some(handle),
            _tmp: tmp,
        }
    }

    fn call(&self, op_name: &str, args: serde_json::Value) -> Response {
        send(&self.socket, &Request::new(op_name, args))
    }

    /// Commit one file into the tip via `replace_file` (goes through the same
    /// BlobEncryptor hook as real writes).
    fn write_file(&self, path: &str, content: &str) {
        let resp = self.call(
            op::REPLACE_FILE,
            serde_json::json!({ "path": path, "content": content }),
        );
        assert!(matches!(resp, Response::Ok { .. }), "write {path}: {resp:?}");
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

fn versions(fx: &Fixture, path: &str) -> ReadVersionsReply {
    serde_json::from_value(ok_data(fx.call(
        op::READ_VERSIONS,
        serde_json::json!({ "path": path }),
    )))
    .unwrap()
}

fn read(fx: &Fixture, path: &str) -> ReadFileReply {
    serde_json::from_value(ok_data(fx.call(op::READ_FILE, serde_json::json!({ "path": path }))))
        .unwrap()
}

// ---- read_versions (slice 001) ----------------------------------------

#[test]
fn read_versions_agrees_with_read_file_phase_3() {
    let fx = Fixture::start(true);
    fx.write_file(
        "meta/conventions.md",
        "# conventions\n\nrule one\n\n## Naming\n\nlowercase\n\n## Cross-refs\n\nsee meta\n",
    );

    let v = versions(&fx, "meta/conventions.md");
    let r = read(&fx, "meta/conventions.md");

    // The CAS projection is read_file's Phase 3 — same versions, same order.
    assert_eq!(v.path, "meta/conventions.md");
    assert!(!v.sealed);
    assert_eq!(v.version, r.version, "whole-file version must agree");
    assert_eq!(v.sections, r.sections, "per-section versions must agree");
    // Sections are addressable ATX headings in document order.
    let headings: Vec<&str> = v.sections.iter().map(|s| s.heading.as_str()).collect();
    assert_eq!(headings, vec!["conventions", "Naming", "Cross-refs"]);
    assert!(v
        .sections
        .iter()
        .all(|s| !s.version.is_empty()), "every section carries a version");
}

/// `read_versions` returns tokens only — no content field on the wire, ever
/// (the whole point of a coordination primitive is that content stays native).
#[test]
fn read_versions_reply_carries_no_content() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "body text\n");
    let resp = fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "doc.md" }));
    let data = ok_data(resp);
    assert!(data.get("content").is_none(), "no content on the wire: {data:?}");
    assert!(data.get("version").and_then(|v| v.as_str()).is_some());
}

#[test]
fn read_versions_sealed_file_flags_and_hashes_the_placeholder() {
    let fx = Fixture::start(true);
    // Seal first, then write the secret so it commits Layer B directly.
    let resp = fx.call(op::VAULT_SEAL, serde_json::json!({ "pattern": "secrets/**" }));
    assert!(matches!(resp, Response::Ok { .. }), "seal: {resp:?}");
    fx.write_file("secrets/key.txt", "TOPSECRET-do-not-leak");

    let v = versions(&fx, "secrets/key.txt");
    assert!(v.sealed, "expected sealed flag");
    assert!(
        v.sections.is_empty(),
        "a sealed placeholder has no addressable sections: {:?}",
        v.sections
    );
    // The version is that of the redacted `[sealed:…]` placeholder — the same
    // content a (refused) write verb would hash, never the plaintext's.
    let r = read(&fx, "secrets/key.txt");
    assert_eq!(v.version, r.version, "placeholder version must agree with read_file");
    // Proof the version isn't the secret's: hash the projected content.
    let projected = "[sealed:secrets/key.txt]\n";
    let hash = softfig_store::Hash::of(projected.as_bytes()).to_hex();
    assert_eq!(v.version, hash, "version must be the placeholder's hash");
}

#[test]
fn read_versions_rejects_traversal() {
    let fx = Fixture::start(true);
    assert_eq!(
        err_kind(fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "../etc/passwd" }))),
        ErrorKind::BadArgs
    );
}

#[test]
fn read_versions_missing_is_not_found() {
    let fx = Fixture::start(true);
    fx.write_file("present.md", "x");
    assert_eq!(
        err_kind(fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "absent.md" }))),
        ErrorKind::NotFound
    );
}

#[test]
fn read_versions_refuses_when_locked() {
    let fx = Fixture::start(false); // do NOT unlock
    assert_eq!(
        err_kind(fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "anything.md" }))),
        ErrorKind::VaultLocked
    );
}
