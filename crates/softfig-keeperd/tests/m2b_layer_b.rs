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
use softfig_vault::{is_layer_b, Vault};

mod common;
use common::{fast_params, wait_for_socket};

const PASS: &str = "correct horse battery staple";

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
        .without_watcher()
        .without_net();
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
        .without_watcher()
        .without_net();
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
        .without_watcher()
        .without_net();
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
        .without_net()
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
        .without_watcher()
        .without_net();
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

// ---- Test 7: FUSE-mode seal/reveal/unseal commit from the in-memory snapshot
// (task 010 — no mount walk under `inner`) + byte-exact Layer B parity --------

/// Skip body when FUSE isn't actually usable in this env (CI sandbox). The
/// dependency is runtime-resolved (kernel + setuid helper), not build-time.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && (Path::new("/usr/bin/fusermount3").exists()
            || Path::new("/usr/bin/fusermount").exists())
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Task 010 regression: with a **real FUSE mount**, vault seal/reveal/unseal must
/// build their commits from the in-memory snapshot — never `WalkDir`/`std::fs`-
/// walking the mount this daemon serves under `inner` (the 2026-06-21 commit-path
/// deadlock), and never committing the reader-facing `[sealed:…]` placeholder.
///
/// `workdir_snapshot` decrypts a whole-file-sealed (Layer B) tip blob under its
/// path subkey, and the committer re-seals it convergently, so the on-tip blob is
/// **byte-identical** to a direct `encrypt_layer_b` of the plaintext — i.e. exact
/// parity with the disk-walk (`commit_workdir`) path the M1c-compat tests above
/// pin. The auto-migration `seal_commit` and reveal's audit commit both
/// re-snapshot a tree whose `secrets/foo.toml` is ALREADY Layer B — the precise
/// case that errored (`decrypt_blob` on a 0xFF blob) before task 010.
///
/// Gated on a usable `/dev/fuse`; skips cleanly in a sandbox.
#[test]
fn fuse_seal_reveal_unseal_commit_from_snapshot() {
    if !fuse_available() {
        eprintln!("fuse unavailable; skipping");
        return;
    }

    const SECRET: &str = "PLAINTEXT_TOKEN_010\n";
    const PUBLIC: &str = "open content\n";

    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path().join("garden");
    let state = tmp.path().join("state");
    let runtime = tmp.path().join("runtime");
    fs::create_dir_all(&garden).unwrap();
    fs::create_dir_all(&runtime).unwrap();
    // Constrain reveal's temp output to a tempdir.
    // SAFETY: this test binary runs single-threaded per test by default.
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    }

    // Two plaintext files committed at genesis (Layer A); one will be sealed.
    write_file(&garden, "secrets/foo.toml", SECRET);
    write_file(&garden, "public.md", PUBLIC);
    let (_v, session, _r) =
        Vault::init_with_params(&garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(&garden, &session).unwrap();
    // Keep `session` (same keys as the daemon) for the byte-exact parity check —
    // pure crypto, no I/O, so using it alongside the running daemon is safe.

    // Migrated layout: `.softfig` in a sibling state root so the mount can't
    // shadow it; socket outside the garden for the same reason.
    fs::create_dir_all(&state).unwrap();
    copy_dir(&garden.join(".softfig"), &state.join(".softfig")).unwrap();
    let socket = tmp.path().join("keeperd.sock");
    let cfg = KeeperConfig::new(&garden)
        .with_state_root(&state)
        .with_socket(&socket)
        .without_watcher()
        .without_net();
    let handle = match Daemon::new(cfg).start() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("daemon start failed: {e}; skipping");
            return;
        }
    };
    wait_for_socket(&socket);
    let unlock_resp = rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    );
    if let Response::Err { kind, error, .. } = &unlock_resp {
        eprintln!("unlock failed (likely fuse-mount issue: {kind:?} {error}); skipping");
        handle.shutdown();
        let _ = handle.join();
        return;
    }
    let _ = unwrap_ok(unlock_resp);
    std::thread::sleep(Duration::from_millis(150)); // let the mount settle

    // --- Seal `secrets/**`. The enumerate runs off the in-memory snapshot, and
    //     the auto-migration seal_commit re-snapshots a tree whose foo.toml is
    //     already Layer B.
    let seal: VaultSealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_SEAL,
        serde_json::to_value(VaultSealArgs {
            pattern: "secrets/**".into(),
        })
        .unwrap(),
    )))
    .unwrap();
    assert!(
        seal.newly_sealed.contains(&"secrets/foo.toml".to_string()),
        "in-memory enumerate must find secrets/foo.toml; got {:?}",
        seal.newly_sealed
    );
    assert!(seal.seal_commit.is_some(), "auto-migration seal commit");

    // --- Read both files back THROUGH the kernel mount: secrets is the sealed
    //     placeholder, public is untouched plaintext (no placeholder committed).
    let mount_secret = fs::read_to_string(garden.join("secrets/foo.toml")).unwrap();
    assert_eq!(mount_secret, "[sealed:secrets/foo.toml]\n");
    assert_eq!(fs::read_to_string(garden.join("public.md")).unwrap(), PUBLIC);

    // --- The committed blob is Layer B and BYTE-IDENTICAL to a direct
    //     encrypt_layer_b of the plaintext (convergent) → parity with the
    //     disk-walk path; public.md stays Layer A.
    let store_paths = softfig_store::StorePaths::with_state_root(&garden, &state);
    let db = softfig_store::Db::open(&store_paths).unwrap();
    let objects = softfig_store::ObjectStore::new(store_paths.clone());
    let tip = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
    let row = db.get_commit(&tip).unwrap();
    let secret_hash = resolve_path(&db, &row.root_tree, &["secrets", "foo.toml"])
        .expect("secrets/foo.toml in tip");
    let secret_blob = objects.get(&secret_hash).unwrap();
    assert!(is_layer_b(&secret_blob), "secrets/foo.toml must be Layer B");
    let expected = session
        .encrypt_layer_b("secrets/foo.toml", SECRET.as_bytes())
        .unwrap();
    assert_eq!(
        secret_blob, expected,
        "snapshot-built sealed blob must equal a direct encrypt_layer_b (parity)"
    );
    let public_hash =
        resolve_path(&db, &row.root_tree, &["public.md"]).expect("public.md in tip");
    assert!(
        !is_layer_b(&objects.get(&public_hash).unwrap()),
        "public.md must stay Layer A"
    );

    // --- Reveal round-trips the ORIGINAL plaintext (its audit commit also
    //     re-snapshots the Layer B tip blob), proving full integrity.
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
    assert_eq!(
        fs::read_to_string(&reveal.temp_path).unwrap(),
        SECRET,
        "reveal must return the original plaintext"
    );

    // --- Unseal keeps the blob Layer B (no bulk-decrypt) and empties the matcher.
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
    let tip2 = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
    let row2 = db.get_commit(&tip2).unwrap();
    let secret_hash2 = resolve_path(&db, &row2.root_tree, &["secrets", "foo.toml"])
        .expect("secrets/foo.toml in tip after unseal");
    assert!(
        is_layer_b(&objects.get(&secret_hash2).unwrap()),
        "previously-sealed blob stays Layer B after unseal"
    );

    handle.shutdown();
    handle.join().unwrap();
}
