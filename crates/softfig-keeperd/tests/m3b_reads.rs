//! M3b integration: the read-only browse verbs `list_tree` and
//! `read_file`, including the daemon-side redaction that keeps sealed
//! content out of the reply (the whole point of routing browse through the
//! daemon instead of the filesystem).
//!
//! All gardens are M1c-compat (no `state_root` → no FUSE), so the suite
//! runs without `/dev/fuse`. Files reach the committed tip via
//! `propose_doc_update` (which commits through the same `BlobEncryptor`
//! hook the watcher/FUSE writes use), so sealing + inline-region
//! encryption happen exactly as in production.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use softfig_vcs::Repo;
use softfig_ipc::verbs::{op, ListTreeReply, ReadFileReply};
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::{params::VaultParams, Vault};

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_garden(garden: &Path) {
    let (_vault, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            if let Ok(stream) = UnixStream::connect(path) {
                drop(stream);
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("socket {} did not appear", path.display());
}

fn send(socket: &Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    let mut bytes = serde_json::to_vec(req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
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

    /// Commit one file into the tip via `propose_doc_update` (goes through
    /// the same BlobEncryptor hook as real writes).
    fn write_file(&self, path: &str, content: &str) {
        let resp = self.call(
            op::PROPOSE_DOC_UPDATE,
            serde_json::json!({
                "summary": "test fixture",
                "project": "test",
                "files": [{ "path": path, "content": content }],
            }),
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

fn ok_data(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected Ok, got {kind:?}: {error}"),
    }
}

fn err_kind(resp: Response) -> ErrorKind {
    match resp {
        Response::Err { kind, .. } => kind,
        Response::Ok { data, .. } => panic!("expected Err, got Ok: {data}"),
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
