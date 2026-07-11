//! M5c slice 003 integration: the shared-subtree lifecycle verbs end to end.
//!
//! Two control axes, proven headless (M1c-compat garden ⇒ no FUSE, so the suite
//! runs without `/dev/fuse`):
//!
//! * `add`/`remove` = ring membership — validate (machine dir + overlap
//!   rejected), append to `config/shared-subtrees.toml`, create the chain's
//!   genesis ref, commit `shared_subtrees_changed`;
//! * `enable`/`disable` = a per-device local toggle — flips ONLY the never-
//!   committed sidecar, provably ceremony-free (no commit, membership byte-
//!   unchanged across a disable→enable cycle).
//!
//! The live enable/disable *remount* recompose is FUSE-only and is deferred to
//! the on-device smoke (see the slice's `## Deferred verification`); here we
//! prove the committed-state + registry-derivation half.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use softfig_ipc::verbs::{
    op, SharedSubtreeAddArgs, SharedSubtreeAddReply, SharedSubtreeListReply,
    SharedSubtreeRemoveArgs, SharedSubtreeRemoveReply, SharedSubtreeToggleArgs,
    SharedSubtreeToggleReply,
};
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_store::Hash;
use softfig_vault::{params::VaultParams, Vault};
use softfig_vcs::Repo;

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
    let (_vault, session, _recovery) = Vault::init_with_params(garden, PASS, fast_params()).unwrap();
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
    garden: PathBuf,
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
            garden,
            handle: Some(handle),
            _tmp: tmp,
        }
    }

    fn call(&self, op_name: &str, args: serde_json::Value) -> Response {
        send(&self.socket, &Request::new(op_name, args))
    }

    /// Device-chain tip commit hash (fresh repo handle; WAL coexists with the
    /// daemon's connection).
    fn tip(&self) -> Hash {
        Repo::open(&self.garden).unwrap().tip().unwrap().unwrap()
    }

    /// Whether a chain ref has a commit (i.e. was created).
    fn ref_exists(&self, ref_name: &str) -> bool {
        Repo::open(&self.garden)
            .unwrap()
            .tip_of(ref_name)
            .unwrap()
            .is_some()
    }

    fn config_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.garden.join("config/shared-subtrees.toml")).ok()
    }

    fn list(&self) -> SharedSubtreeListReply {
        serde_json::from_value(ok_data(self.call(op::SHARED_SUBTREE_LIST, serde_json::Value::Null)))
            .unwrap()
    }

    fn add(&self, mount_path: &str, id: Option<&str>) -> Response {
        self.call(
            op::SHARED_SUBTREE_ADD,
            serde_json::to_value(SharedSubtreeAddArgs {
                mount_path: mount_path.into(),
                id: id.map(str::to_string),
            })
            .unwrap(),
        )
    }

    fn toggle(&self, op_name: &str, id: &str) -> SharedSubtreeToggleReply {
        serde_json::from_value(ok_data(self.call(
            op_name,
            serde_json::to_value(SharedSubtreeToggleArgs { id: id.into() }).unwrap(),
        )))
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

// ---- add: validation ------------------------------------------------------

#[test]
fn add_rejects_machine_dirs() {
    let fx = Fixture::start();
    for p in ["hardware", "services/waydroid", "os/boot", "storage/luks", "snapshots/pacman"] {
        assert_eq!(err_kind(fx.add(p, None)), ErrorKind::BadArgs, "{p} should reject");
    }
    // Nothing was committed for a rejected add.
    assert!(fx.list().subtrees.is_empty());
}

#[test]
fn add_rejects_overlapping_and_bad_paths() {
    let fx = Fixture::start();
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));
    // Nested under an existing share, and the existing share nested under a new
    // one — both overlap directions rejected (v1 shares must be disjoint).
    assert_eq!(err_kind(fx.add("projects/journals/2026", None)), ErrorKind::BadArgs);
    assert_eq!(err_kind(fx.add("projects", None)), ErrorKind::BadArgs);
    // Not garden-relative.
    assert_eq!(err_kind(fx.add("/abs/path", None)), ErrorKind::BadArgs);
    assert_eq!(err_kind(fx.add("projects/../hardware", None)), ErrorKind::BadArgs);
    // A disjoint sibling is accepted.
    assert!(matches!(fx.add("notes/wiki", None), Response::Ok { .. }));
    // A duplicate id is rejected.
    assert_eq!(err_kind(fx.add("elsewhere/journals", Some("journals"))), ErrorKind::BadArgs);
}

// ---- add: creates the ref + list shows it ---------------------------------

#[test]
fn add_creates_chain_ref_and_list_shows_it() {
    let fx = Fixture::start();
    let reply: SharedSubtreeAddReply =
        serde_json::from_value(ok_data(fx.add("projects/journals", None))).unwrap();
    assert_eq!(reply.id, "journals");
    assert_eq!(reply.mount_path, "projects/journals");
    assert_eq!(reply.ref_name, "chain/journals");

    // The chain's genesis ref exists (so the union mount can compose it).
    assert!(fx.ref_exists("chain/journals"), "genesis ref should exist");

    // The membership was committed under the schema-change intent.
    let repo = Repo::open(&fx.garden).unwrap();
    let row = repo.db().get_commit(&fx.tip()).unwrap();
    assert_eq!(row.intent, "shared_subtrees_changed");

    // list surfaces the member, enabled by default, no key yet (m5d).
    let list = fx.list();
    assert_eq!(list.subtrees.len(), 1);
    let s = &list.subtrees[0];
    assert_eq!(s.id, "journals");
    assert_eq!(s.mount_path, "projects/journals");
    assert_eq!(s.ref_name, "chain/journals");
    assert!(s.enabled);
    assert_eq!(s.key_id, None);
}

#[test]
fn add_honors_an_explicit_id() {
    let fx = Fixture::start();
    let reply: SharedSubtreeAddReply =
        serde_json::from_value(ok_data(fx.add("projects/journals", Some("my-journal")))).unwrap();
    assert_eq!(reply.id, "my-journal");
    assert_eq!(reply.ref_name, "chain/my-journal");
    assert!(fx.ref_exists("chain/my-journal"));
}

// ---- absent config ⇒ device_only ------------------------------------------

#[test]
fn absent_config_lists_empty() {
    let fx = Fixture::start();
    assert!(fx.list().subtrees.is_empty());
}

// ---- disable / enable: the ceremony-free local toggle ---------------------

#[test]
fn disable_enable_flips_state_and_leaves_membership_byte_unchanged() {
    let fx = Fixture::start();
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));

    // Capture the committed state right after add: the device tip and the
    // membership file bytes. A ceremony-free toggle must not perturb either.
    let tip_after_add = fx.tip();
    let config_after_add = fx.config_bytes().expect("membership file exists after add");

    // Disable → transparent on this device.
    let r = fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert!(!r.enabled);
    assert!(r.changed);
    assert!(!fx.list().subtrees[0].enabled, "list reflects the disable");

    // No commit fired (tip unchanged) and the membership file is byte-identical.
    assert_eq!(fx.tip(), tip_after_add, "disable must not commit");
    assert_eq!(fx.config_bytes().unwrap(), config_after_add, "membership byte-unchanged");

    // Idempotent: a second disable is a no-op.
    let r = fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert!(!r.changed);

    // Re-enable restores the full view, still with no commit + no membership edit.
    let r = fx.toggle(op::SHARED_SUBTREE_ENABLE, "journals");
    assert!(r.enabled);
    assert!(r.changed);
    assert!(fx.list().subtrees[0].enabled, "list reflects the enable");
    assert_eq!(fx.tip(), tip_after_add, "enable must not commit");
    assert_eq!(fx.config_bytes().unwrap(), config_after_add, "membership byte-unchanged");
}

#[test]
fn toggle_rejects_an_unknown_id() {
    let fx = Fixture::start();
    assert_eq!(
        err_kind(fx.call(
            op::SHARED_SUBTREE_DISABLE,
            serde_json::to_value(SharedSubtreeToggleArgs { id: "nope".into() }).unwrap(),
        )),
        ErrorKind::NotFound
    );
}

// ---- remove: un-share -----------------------------------------------------

#[test]
fn remove_unshares_and_is_idempotent() {
    let fx = Fixture::start();
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));

    let reply: SharedSubtreeRemoveReply = serde_json::from_value(ok_data(fx.call(
        op::SHARED_SUBTREE_REMOVE,
        serde_json::to_value(SharedSubtreeRemoveArgs { id: "journals".into() }).unwrap(),
    )))
    .unwrap();
    assert!(reply.removed);
    assert!(fx.list().subtrees.is_empty(), "removed share is gone from list");

    // The un-share committed under the schema-change intent.
    let repo = Repo::open(&fx.garden).unwrap();
    let row = repo.db().get_commit(&fx.tip()).unwrap();
    assert_eq!(row.intent, "shared_subtrees_changed");

    // A second remove is an idempotent no-op.
    let reply: SharedSubtreeRemoveReply = serde_json::from_value(ok_data(fx.call(
        op::SHARED_SUBTREE_REMOVE,
        serde_json::to_value(SharedSubtreeRemoveArgs { id: "journals".into() }).unwrap(),
    )))
    .unwrap();
    assert!(!reply.removed);
}

// ---- replica isolation: lifecycle never touches the device-chain grants ----

/// M5c slice 004 (user requirement #2): the shared-subtree lifecycle and the
/// M5b device-chain replica grants (`replica.toml` `push_to`) are **independent
/// config surfaces**. add/remove (ring membership) and enable/disable (local
/// toggle) must leave the grant ledger byte-unchanged — a shared subtree can
/// never redirect, add to, or drop a device-chain backup target. Trivially true
/// today (no lifecycle handler touches the `GrantLedger`), pinned so a future
/// edit can't silently regress it.
#[test]
fn lifecycle_ops_never_touch_the_replica_grant_ledger() {
    use softfig_keeperd::replica::{replica_ledger_path, GrantLedger};

    let fx = Fixture::start();

    // Seed a non-empty owner-side push_to ledger (the device-chain backup hosts).
    // For an M1c-compat garden the store dir is the garden root, so this lands at
    // `<garden>/.softfig/replica.toml`.
    let mut ledger = GrantLedger::default();
    assert!(ledger.grant(&"ab".repeat(32)));
    assert!(ledger.grant(&"cd".repeat(32)));
    ledger.save(&fx.garden).unwrap();
    let ledger_path = replica_ledger_path(&fx.garden);
    let before = std::fs::read(&ledger_path).expect("seeded replica.toml exists");

    let assert_unchanged = |after_what: &str| {
        assert_eq!(
            std::fs::read(&ledger_path).unwrap(),
            before,
            "{after_what} must leave replica.toml push_to byte-unchanged"
        );
    };

    // add = ring membership + a `shared_subtrees_changed` commit.
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));
    assert_unchanged("add");

    // disable / enable = a local sidecar toggle (ceremony-free).
    fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert_unchanged("disable");
    fx.toggle(op::SHARED_SUBTREE_ENABLE, "journals");
    assert_unchanged("enable");

    // remove = ring membership + a `shared_subtrees_changed` commit.
    let reply: SharedSubtreeRemoveReply = serde_json::from_value(ok_data(fx.call(
        op::SHARED_SUBTREE_REMOVE,
        serde_json::to_value(SharedSubtreeRemoveArgs { id: "journals".into() }).unwrap(),
    )))
    .unwrap();
    assert!(reply.removed);
    assert_unchanged("remove");

    // And the ledger still round-trips to the exact seeded grants — the two
    // surfaces never crossed.
    let reloaded = GrantLedger::load(&fx.garden).unwrap();
    assert_eq!(reloaded.push_to, vec!["ab".repeat(32), "cd".repeat(32)]);
}
