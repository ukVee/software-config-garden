//! M2b end-to-end coverage: Layer B subkey derivation, daemon-side
//! pre-commit Layer B encryption, sealed-paths.toml auto-migration on
//! glob add, `softfig reveal` → 0600 temp file + audit commit, idle
//! window re-prompt semantics.
//!
//! The tests use the M1c-compat daemon mode (no FUSE) so they work in
//! environments without `/dev/fuse` — Layer B encryption happens
//! daemon-side, not in the FUSE driver, so the relevant invariants are
//! verifiable without a mount.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use softfig_vcs::Repo;
use softfig_ipc::{
    self,
    verbs::{
        op, LogReply, UnlockArgs, VaultListSealedReply, VaultRevealArgs, VaultRevealReply,
        VaultSealArgs, VaultSealReply, VaultUnsealArgs, VaultUnsealReply,
    },
    ErrorKind, Request, Response,
};
use softfig_keeperd::{layer_b, Daemon, KeeperConfig};
use softfig_vault::{is_layer_b, params::VaultParams, Vault};

const PASS: &str = "correct horse battery staple";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn write_file(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

fn rpc(socket: &Path, op: &str, args: serde_json::Value) -> Response {
    let mut s = softfig_ipc::connect(socket).expect("connect");
    let req = Request::new(op, args);
    softfig_ipc::call(&mut s, &req).expect("call")
}

fn unwrap_ok(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => {
            panic!("expected ok, got {:?}: {}", kind, error)
        }
    }
}

fn unique_socket(tmp: &Path) -> PathBuf {
    tmp.join("keeperd.sock")
}

fn wait_for_socket(socket: &Path) {
    for _ in 0..50 {
        if socket.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("socket {} never appeared", socket.display());
}

fn bootstrap(garden: &Path) {
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);
}

fn unlock(socket: &Path) {
    let _ = unwrap_ok(rpc(
        socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));
}

// ---- Test 1: write-through-mount round-trip lands Layer B ciphertext ----

#[test]
fn layer_b_seal_writes_layer_b_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    write_file(garden, "secrets/foo.toml", "api_key = \"hunter2\"\n");
    write_file(garden, "public.md", "open content\n");
    bootstrap(garden);

    let socket = unique_socket(garden);
    let cfg = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(cfg);
    let handle = daemon.start().expect("start");
    wait_for_socket(&socket);
    unlock(&socket);

    // Seal `secrets/**` — the daemon writes sealed-paths.toml, commits a
    // schema_change, and auto-migrates the matching tracked files.
    let seal_args = serde_json::to_value(VaultSealArgs {
        pattern: "secrets/**".into(),
    })
    .unwrap();
    let seal_reply: VaultSealReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::VAULT_SEAL, seal_args))).unwrap();
    assert!(seal_reply.seal_commit.is_some(), "auto-migration commit");
    assert!(
        seal_reply.newly_sealed.contains(&"secrets/foo.toml".to_string()),
        "newly sealed should include secrets/foo.toml; got {:?}",
        seal_reply.newly_sealed
    );

    // Verify the committed blob for `secrets/foo.toml` is Layer-B-encrypted.
    //
    // Look up the tip via `softfig log`, then resolve the tree on-disk.
    let log: LogReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::LOG, json!({"limit": 0}))))
            .unwrap();
    // Genesis (init) + schema_change + vault_seal = 3 commits, newest first.
    assert!(log.commits.len() >= 3, "expected ≥3 commits, got {:?}", log.commits.iter().map(|c| &c.intent).collect::<Vec<_>>());
    assert_eq!(log.commits[0].intent, "vault_seal");
    assert_eq!(log.commits[1].intent, "schema_change");

    // Read the secrets/foo.toml blob directly out of the object store
    // and check the marker byte.
    let store_paths = softfig_store::StorePaths::for_garden(garden);
    let db = softfig_store::Db::open(&store_paths).unwrap();
    let tip = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
    let row = db.get_commit(&tip).unwrap();

    let blob_hash = resolve_path(&db, &row.root_tree, &["secrets", "foo.toml"])
        .expect("secrets/foo.toml present in tip tree");
    let objects = softfig_store::ObjectStore::new(store_paths.clone());
    let cipher = objects.get(&blob_hash).unwrap();
    assert!(
        is_layer_b(&cipher),
        "secrets/foo.toml should be Layer B (marker 0xFF); first byte = 0x{:02x}",
        cipher.first().copied().unwrap_or(0)
    );

    // Also verify `public.md` is NOT Layer B.
    let public_hash = resolve_path(&db, &row.root_tree, &["public.md"])
        .expect("public.md present in tip");
    let public_cipher = objects.get(&public_hash).unwrap();
    assert!(
        !is_layer_b(&public_cipher),
        "public.md should remain Layer A"
    );

    handle.shutdown();
    handle.join().unwrap();
}

fn resolve_path(
    db: &softfig_store::Db,
    root: &softfig_store::Hash,
    components: &[&str],
) -> Option<softfig_store::Hash> {
    let mut current = *root;
    for (i, name) in components.iter().enumerate() {
        let entries = db.get_tree(&current).ok()?;
        let entry = entries.into_iter().find(|e| &e.name == name)?;
        let is_last = i + 1 == components.len();
        match entry.kind {
            softfig_store::TreeEntryKind::Blob if is_last => return Some(entry.target),
            softfig_store::TreeEntryKind::Tree if !is_last => current = entry.target,
            _ => return None,
        }
    }
    None
}

// ---- Test 2: auto-migration on glob add ----------------------------------

#[test]
fn auto_migrate_on_glob_add() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    // Two pre-existing plaintext files that will newly match `secrets/**`.
    write_file(garden, "secrets/foo.toml", "v=1\n");
    write_file(garden, "secrets/dir/bar.toml", "v=2\n");
    write_file(garden, "readme.md", "plain\n");
    bootstrap(garden);

    let socket = unique_socket(garden);
    let cfg = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(cfg);
    let handle = daemon.start().expect("start");
    wait_for_socket(&socket);
    unlock(&socket);

    // Confirm no globs are loaded yet.
    let list: VaultListSealedReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_LIST_SEALED,
        json!(null),
    )))
    .unwrap();
    assert!(list.globs.is_empty());
    assert!(list.matching_files.is_empty());

    // Seal — should auto-migrate two files.
    let reply: VaultSealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_SEAL,
        serde_json::to_value(VaultSealArgs {
            pattern: "secrets/**".into(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert_eq!(reply.newly_sealed.len(), 2);
    assert!(reply.seal_commit.is_some());

    // list-sealed now reports both files.
    let list: VaultListSealedReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_LIST_SEALED,
        json!(null),
    )))
    .unwrap();
    assert_eq!(list.globs, vec!["secrets/**".to_string()]);
    assert_eq!(list.matching_files.len(), 2);

    // sealed-paths.toml exists on disk and is itself Layer A.
    let sp_path = garden
        .join(".softfig/vault/sealed-paths.toml");
    assert!(sp_path.exists(), "sealed-paths.toml present");
    let raw = fs::read_to_string(&sp_path).unwrap();
    assert!(raw.contains("secrets/**"));

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 3: reveal flow writes a 0600 temp file + commits vault_reveal --

#[test]
fn reveal_writes_temp_file_and_audits() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let runtime = tmp.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    // Constrain XDG_RUNTIME_DIR to a tempdir so test output is contained.
    // SAFETY: tests run single-threaded by default for this binary.
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    }

    write_file(garden, "secrets/foo.toml", "PLAINTEXT_TOKEN_42\n");
    bootstrap(garden);

    let socket = unique_socket(garden);
    let cfg = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(cfg);
    let handle = daemon.start().expect("start");
    wait_for_socket(&socket);
    unlock(&socket);

    // Seal first.
    let _ = unwrap_ok(rpc(
        &socket,
        op::VAULT_SEAL,
        serde_json::to_value(VaultSealArgs {
            pattern: "secrets/**".into(),
        })
        .unwrap(),
    ));

    // First reveal attempt with no master password → MasterPasswordRequired.
    let no_pw_resp = rpc(
        &socket,
        op::VAULT_REVEAL,
        serde_json::to_value(VaultRevealArgs {
            path: "secrets/foo.toml".into(),
            master_password: None,
            probe_only: false,
            id: None,
        })
        .unwrap(),
    );
    let kind = match &no_pw_resp {
        Response::Err { kind, .. } => *kind,
        _ => panic!("expected MasterPasswordRequired, got {:?}", no_pw_resp),
    };
    assert_eq!(kind, ErrorKind::MasterPasswordRequired);

    // Now supply the password.
    let reveal: VaultRevealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_REVEAL,
        serde_json::to_value(VaultRevealArgs {
            path: "secrets/foo.toml".into(),
            master_password: Some(PASS.into()),
            probe_only: false,
            id: None,
        })
        .unwrap(),
    )))
    .unwrap();

    // Temp file: 0600 perms, contains plaintext.
    let tp = PathBuf::from(&reveal.temp_path);
    assert!(tp.exists(), "{} missing", tp.display());
    let meta = fs::metadata(&tp).unwrap();
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());
    assert_eq!(mode & 0o777, 0o600, "0o{:o}", mode & 0o777);
    let pt = fs::read_to_string(&tp).unwrap();
    assert!(pt.contains("PLAINTEXT_TOKEN_42"));

    // Top of the log is `vault_reveal`.
    let log: LogReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::LOG, json!({"limit": 0}))))
            .unwrap();
    assert_eq!(log.commits[0].intent, "vault_reveal");

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 4: reveal idle window — first prompt, then skip, then prompt ---

#[test]
fn reveal_idle_window_semantics() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let runtime = tmp.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    }

    write_file(garden, "secrets/foo.toml", "alpha\n");
    bootstrap(garden);

    let socket = unique_socket(garden);
    // Large window so the second reveal is "within idle".
    let cfg = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher()
        .with_reveal_idle_seconds(60);
    let daemon = Daemon::new(cfg);
    let handle = daemon.start().expect("start");
    wait_for_socket(&socket);
    unlock(&socket);

    let _ = unwrap_ok(rpc(
        &socket,
        op::VAULT_SEAL,
        serde_json::to_value(VaultSealArgs {
            pattern: "secrets/**".into(),
        })
        .unwrap(),
    ));

    // First reveal needs a password (no prior reveal recorded).
    let _: VaultRevealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_REVEAL,
        serde_json::to_value(VaultRevealArgs {
            path: "secrets/foo.toml".into(),
            master_password: Some(PASS.into()),
            probe_only: false,
            id: None,
        })
        .unwrap(),
    )))
    .unwrap();

    // Second reveal without password — should succeed because we're
    // within the idle window.
    let r2: VaultRevealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_REVEAL,
        serde_json::to_value(VaultRevealArgs {
            path: "secrets/foo.toml".into(),
            master_password: None,
            probe_only: false,
            id: None,
        })
        .unwrap(),
    )))
    .unwrap();
    let tp = PathBuf::from(&r2.temp_path);
    assert!(tp.exists());

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 5: unseal removes the glob; old blobs stay Layer-B-encrypted ----

#[test]
fn unseal_removes_glob_but_keeps_blobs_sealed() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    write_file(garden, "secrets/foo.toml", "shh\n");
    bootstrap(garden);

    let socket = unique_socket(garden);
    let cfg = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(cfg);
    let handle = daemon.start().expect("start");
    wait_for_socket(&socket);
    unlock(&socket);

    // Seal then unseal.
    let _: VaultSealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_SEAL,
        serde_json::to_value(VaultSealArgs {
            pattern: "secrets/**".into(),
        })
        .unwrap(),
    )))
    .unwrap();
    let unseal: VaultUnsealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_UNSEAL,
        serde_json::to_value(VaultUnsealArgs {
            pattern: "secrets/**".into(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert!(unseal.removed);

    // The underlying blob on disk should still be Layer-B-encrypted —
    // unseal does NOT bulk-decrypt (intentional, per the M2b lock).
    let store_paths = softfig_store::StorePaths::for_garden(garden);
    let db = softfig_store::Db::open(&store_paths).unwrap();
    let tip = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
    let row = db.get_commit(&tip).unwrap();
    let blob_hash = resolve_path(&db, &row.root_tree, &["secrets", "foo.toml"])
        .expect("path in tip tree");
    let objects = softfig_store::ObjectStore::new(store_paths);
    let cipher = objects.get(&blob_hash).unwrap();
    assert!(
        is_layer_b(&cipher),
        "previously-sealed blob should remain Layer B after unseal"
    );

    // The matcher itself is empty after unseal.
    let list: VaultListSealedReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_LIST_SEALED,
        json!(null),
    )))
    .unwrap();
    assert!(list.globs.is_empty());
    assert!(list.matching_files.is_empty());

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 6: layer_b module hook implements both BlobEncryptor + SealedQuery -

#[test]
fn layer_b_hook_routes_sealed_paths() {
    use softfig_vcs::BlobEncryptor;
    use softfig_fuse::SealedQuery;
    use softfig_keeperd::layer_b::{LayerBHook, SealedPaths};
    use softfig_vault::is_layer_b;

    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();

    let hook = LayerBHook::new(
        SealedPaths::compile(&["secrets/**".to_string()]).unwrap(),
    );

    // Sealed path routes through Layer B (0xFF marker).
    let ct_sealed = hook
        .encrypt("secrets/foo.toml", b"hi", &session)
        .unwrap();
    assert!(is_layer_b(&ct_sealed));
    assert!(SealedQuery::is_sealed(&hook, "secrets/foo.toml"));

    // Non-sealed path stays Layer A.
    let ct_plain = hook.encrypt("readme.md", b"hi", &session).unwrap();
    assert!(!is_layer_b(&ct_plain));
    assert!(!SealedQuery::is_sealed(&hook, "readme.md"));

    let _ = layer_b::SEALED_PATHS_REL;
}
