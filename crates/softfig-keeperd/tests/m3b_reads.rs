//! M3b integration: the read-only browse verbs `list_tree` and
//! `read_file`, including the daemon-side redaction that keeps sealed
//! content out of the reply (the whole point of routing browse through the
//! daemon instead of the filesystem).
//!
//! All gardens are M1c-compat (no `state_root` → no FUSE), so the suite
//! runs without `/dev/fuse`. Files reach the committed tip via
//! `replace_file` (which commits through the same `BlobEncryptor`
//! hook the watcher/FUSE writes use), so sealing + inline-region
//! encryption happen exactly as in production.

use std::path::{Path, PathBuf};

use softfig_vcs::Repo;
use softfig_ipc::verbs::{op, ListTreeReply, ReadFileReply};
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
    fn start(unlock: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let garden = tmp.path().to_path_buf();
        init_garden(&garden);
        let socket = garden.join("sock");
        let config = KeeperConfig::new(&garden)
            .without_watcher()
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

    /// Commit one file into the tip via `replace_file` (goes through
    /// the same BlobEncryptor hook as real writes).
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

fn list(fx: &Fixture, path: Option<&str>) -> Vec<softfig_ipc::TreeEntry> {
    let args = match path {
        Some(p) => serde_json::json!({ "path": p }),
        None => serde_json::json!({}),
    };
    let reply: ListTreeReply = serde_json::from_value(ok_data(fx.call(op::LIST_TREE, args))).unwrap();
    reply.entries
}

fn read(fx: &Fixture, path: &str) -> ReadFileReply {
    serde_json::from_value(ok_data(fx.call(op::READ_FILE, serde_json::json!({ "path": path })))).unwrap()
}

// ---- list_tree --------------------------------------------------------

#[test]
fn list_tree_root_and_subdir_with_is_dir() {
    let fx = Fixture::start(true);
    fx.write_file("top.md", "hi");
    fx.write_file("journal/decisions/decision-x.md", "body");

    let root = list(&fx, None);
    // dirs first (journal), then files (top.md), each alphabetical.
    assert_eq!(root.len(), 2);
    assert_eq!(root[0].name, "journal");
    assert!(root[0].is_dir);
    assert_eq!(root[0].path, "journal");
    assert_eq!(root[1].name, "top.md");
    assert!(!root[1].is_dir);

    let journal = list(&fx, Some("journal"));
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].name, "decisions");
    assert!(journal[0].is_dir);
    assert_eq!(journal[0].path, "journal/decisions");

    let decisions = list(&fx, Some("journal/decisions"));
    assert_eq!(decisions[0].name, "decision-x.md");
    assert!(!decisions[0].is_dir);
}

#[test]
fn list_tree_empty_garden() {
    let fx = Fixture::start(true);
    assert!(list(&fx, None).is_empty());
}

#[test]
fn list_tree_missing_dir_is_not_found() {
    let fx = Fixture::start(true);
    assert_eq!(
        err_kind(fx.call(op::LIST_TREE, serde_json::json!({ "path": "nope/gone" }))),
        ErrorKind::NotFound
    );
}

// ---- read_file --------------------------------------------------------

#[test]
fn read_file_plaintext() {
    let fx = Fixture::start(true);
    fx.write_file("meta/conventions.md", "# conventions\n\nrule one\n");
    let r = read(&fx, "meta/conventions.md");
    assert_eq!(r.path, "meta/conventions.md");
    assert!(!r.sealed);
    assert!(r.content.contains("rule one"));
    assert!(r.region_ids.is_empty(), "no regions: {:?}", r.region_ids);
}

#[test]
fn read_file_whole_file_sealed_projects_placeholder() {
    let fx = Fixture::start(true);
    // Seal first, then write the secret so it commits Layer B directly.
    let resp = fx.call(op::VAULT_SEAL, serde_json::json!({ "pattern": "secrets/**" }));
    assert!(matches!(resp, Response::Ok { .. }), "seal: {resp:?}");
    fx.write_file("secrets/key.txt", "TOPSECRET-do-not-leak");

    let r = read(&fx, "secrets/key.txt");
    assert!(r.sealed, "expected sealed flag");
    assert_eq!(r.content, "[sealed:secrets/key.txt]\n");
    assert!(
        !r.content.contains("TOPSECRET"),
        "sealed plaintext leaked: {r:?}"
    );
    // A whole-file seal is not an inline-region file — no per-region ids.
    assert!(r.region_ids.is_empty(), "region_ids: {:?}", r.region_ids);
}

#[test]
fn read_file_inline_region_projects_encrypted() {
    let fx = Fixture::start(true);
    fx.write_file(
        "notes/secret.md",
        "before\n<vault id=\"tok\">s3cr3t-value</vault>\nafter\n",
    );

    let r = read(&fx, "notes/secret.md");
    assert!(!r.sealed);
    assert!(r.content.contains("[encrypted]"), "content: {:?}", r.content);
    assert!(r.content.contains("tok"), "id should be preserved: {:?}", r.content);
    assert!(
        !r.content.contains("s3cr3t-value"),
        "region plaintext leaked: {:?}",
        r.content
    );
    assert!(r.content.contains("before") && r.content.contains("after"));
    // 020 slice 003: the daemon computes the sealed region id with its
    // authoritative grammar and carries it on the reply — the TUI reads this
    // instead of re-parsing the projected `[encrypted]` prose.
    assert_eq!(r.region_ids, vec!["tok".to_string()], "reply: {r:?}");
}

/// 020 slice 003 regression (finding #6): an inline-code `<vault>` mention is
/// documentation, not a region — the daemon's markdown grammar masks it, so the
/// reply must carry ZERO region_ids (and never redact the prose to `[encrypted]`).
/// The old client `parse_vault_region_ids` matched such prose and conjured a
/// phantom region whose picker entry failed at the daemon.
#[test]
fn read_file_inline_code_mention_has_no_region_ids() {
    let fx = Fixture::start(true);
    fx.write_file(
        "meta/vault-howto.md",
        "Wrap a secret inline as `<vault id=\"example\">…</vault>` to seal it.\n",
    );

    let r = read(&fx, "meta/vault-howto.md");
    assert!(!r.sealed);
    assert!(
        r.region_ids.is_empty(),
        "inline-code mention must yield no regions: {:?}",
        r.region_ids
    );
    // The prose round-trips verbatim — it was never treated as a real region.
    assert!(
        r.content.contains("<vault id=\"example\">"),
        "documentation mention should survive unredacted: {:?}",
        r.content
    );
    assert!(!r.content.contains("[encrypted]"), "content: {:?}", r.content);
}

#[test]
fn read_file_rejects_traversal() {
    let fx = Fixture::start(true);
    assert_eq!(
        err_kind(fx.call(op::READ_FILE, serde_json::json!({ "path": "../etc/passwd" }))),
        ErrorKind::BadArgs
    );
}

#[test]
fn read_file_missing_is_not_found() {
    let fx = Fixture::start(true);
    fx.write_file("present.md", "x");
    assert_eq!(
        err_kind(fx.call(op::READ_FILE, serde_json::json!({ "path": "absent.md" }))),
        ErrorKind::NotFound
    );
}

// ---- locked-state refusal --------------------------------------------

#[test]
fn reads_refuse_when_locked() {
    let fx = Fixture::start(false); // do NOT unlock
    assert_eq!(
        err_kind(fx.call(op::LIST_TREE, serde_json::json!({}))),
        ErrorKind::VaultLocked
    );
    assert_eq!(
        err_kind(fx.call(op::READ_FILE, serde_json::json!({ "path": "anything.md" }))),
        ErrorKind::VaultLocked
    );
}
