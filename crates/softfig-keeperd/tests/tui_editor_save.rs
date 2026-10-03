//! tui-file-editor slice 004: the TUI save path, end to end.
//!
//! The TUI's save is ONE `patch_file` call composing shipped verbs (no new
//! daemon verb):
//!
//! ```text
//! patch_file { path, old: <exact read_file content>, new: <edited buffer>,
//!              expected_version: <read_file.version> }
//! ```
//!
//! These tests drive exactly that composition through the daemon and assert
//! the contract the editor's async bridge relies on: one commit with the
//! `text_patched` intent and a fresh version token on success; a stale
//! `expected_version` → `Conflict` with nothing written; sealed / inline-
//! `<vault>` targets refused (`VaultProtected`); traversal → `BadArgs`.
//!
//! Same harness posture as `mcp_write_surface.rs`: an M1c-compat garden (no
//! FUSE); files reach the committed tip via `replace_file` (the same
//! `BlobEncryptor` hook real writes use), so sealing + region redaction behave
//! exactly as in production.

use std::path::PathBuf;

use softfig_ipc::verbs::{LogReply, PatchFileReply, ReadFileReply, op};
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

    /// Commit one file into the tip via `replace_file` (the break-glass verb;
    /// the daemon's BlobEncryptor hook treats its bytes like any real write).
    fn write_file(&self, path: &str, content: &str) {
        let resp = self.call(
            op::REPLACE_FILE,
            serde_json::json!({ "path": path, "content": content }),
        );
        assert!(
            matches!(resp, Response::Ok { .. }),
            "write {path}: {resp:?}"
        );
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

fn read(fx: &Fixture, path: &str) -> ReadFileReply {
    serde_json::from_value(ok_data(
        fx.call(op::READ_FILE, serde_json::json!({ "path": path })),
    ))
    .unwrap()
}

/// One TUI save: the exact `patch_file` composition the editor bridge sends
/// (see `crates/softfig-tui/src/app.rs` `editor_save`).
fn tui_save(fx: &Fixture, base: &ReadFileReply, new: &str) -> Response {
    fx.call(
        op::PATCH_FILE,
        serde_json::json!({
            "path": base.path,
            "old": base.content,
            "new": new,
            "expected_version": base.version,
        }),
    )
}

/// The tip commit's hash — for "nothing was written" / "exactly one commit"
/// assertions.
fn tip_hash(fx: &Fixture) -> String {
    let log: LogReply =
        serde_json::from_value(ok_data(fx.call(op::LOG, serde_json::json!({ "limit": 1 }))))
            .unwrap();
    log.commits[0].hash.clone()
}

#[test]
fn tui_save_edits_a_file_and_commits_exactly_once_text_patched() {
    let fx = Fixture::start(true);
    fx.write_file("notes/doc.md", "# T\n\nbody line\n\nkeep\n");
    let before = tip_hash(&fx);

    // The TUI read the file (open) and now sends the edited whole buffer.
    let base = read(&fx, "notes/doc.md");
    let edited = base.content.replace("body line", "edited body");
    assert_ne!(edited, base.content, "the fixture edit must change bytes");
    let reply: PatchFileReply =
        serde_json::from_value(ok_data(tui_save(&fx, &base, &edited))).unwrap();
    assert_eq!(reply.path, "notes/doc.md");
    assert!(!reply.hash.is_empty());

    // The edited bytes are the daemon's new truth; the reply's version is the
    // editor's next `expected_version`.
    let after = read(&fx, "notes/doc.md");
    assert_eq!(after.content, edited);
    assert_eq!(reply.version, after.version);

    // Exactly one commit, and it carries the `text_patched` intent.
    let log: LogReply =
        serde_json::from_value(ok_data(fx.call(op::LOG, serde_json::json!({ "limit": 2 }))))
            .unwrap();
    assert_eq!(log.commits[0].intent, "text_patched");
    assert_eq!(log.commits[1].hash, before, "one save = one commit");
}

#[test]
fn tui_save_stale_version_conflicts_and_leaves_bytes_untouched() {
    let fx = Fixture::start(true);
    fx.write_file("notes/doc.md", "v0\n");
    // The TUI reads v0 — this is the buffer's base + CAS token.
    let base = read(&fx, "notes/doc.md");

    // Someone else (another device / an MCP agent) moves the file first.
    fx.write_file("notes/doc.md", "v1\n");
    let before = tip_hash(&fx);

    let resp = tui_save(&fx, &base, "v2 (tui)\n");
    assert_eq!(err_kind(resp), ErrorKind::Conflict);

    // The conflict wrote nothing: same bytes, same tip.
    assert_eq!(read(&fx, "notes/doc.md").content, "v1\n");
    assert_eq!(tip_hash(&fx), before, "a conflict must not commit");
}

#[test]
fn tui_save_refuses_a_whole_file_sealed_target() {
    let fx = Fixture::start(true);
    let resp = fx.call(
        op::VAULT_SEAL,
        serde_json::json!({ "pattern": "secrets/**" }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "seal: {resp:?}");
    fx.write_file("secrets/key.txt", "TOPSECRET");

    let base = read(&fx, "secrets/key.txt");
    assert!(base.sealed, "fixture target is sealed");
    assert_eq!(
        err_kind(tui_save(&fx, &base, "overwritten\n")),
        ErrorKind::VaultProtected,
        "the daemon's load_unprotected gate refuses the sealed target"
    );
}

#[test]
fn tui_save_refuses_an_inline_vault_region_file() {
    let fx = Fixture::start(true);
    fx.write_file(
        "notes/region.md",
        "intro\n\n<vault id=\"api\">SECRET</vault>\n\noutro\n",
    );

    // `read_file` projects the region as `[encrypted]` and hands back its id —
    // the same projection the TUI's client-side gate refuses.
    let base = read(&fx, "notes/region.md");
    assert_eq!(base.region_ids, vec!["api".to_string()]);
    assert!(base.content.contains("[encrypted]"), "redacted projection");

    assert_eq!(
        err_kind(tui_save(&fx, &base, "edited\n")),
        ErrorKind::VaultProtected,
        "the daemon refuses a plaintext rewrite of a region-bearing file"
    );
    assert_eq!(read(&fx, "notes/region.md").content, base.content);
}

#[test]
fn tui_save_rejects_path_traversal() {
    let fx = Fixture::start(true);
    fx.write_file("notes/doc.md", "x\n");
    let base = read(&fx, "notes/doc.md");

    let resp = fx.call(
        op::PATCH_FILE,
        serde_json::json!({
            "path": "../outside.md",
            "old": base.content,
            "new": "y\n",
            "expected_version": base.version,
        }),
    );
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
}
