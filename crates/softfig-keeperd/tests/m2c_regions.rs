//! M2c end-to-end coverage: per-region subkey derivation, region-aware
//! write path (placeholder preservation), classifier promotion to
//! `vault_seal` on new-id introduction, `softfig reveal --id` flow,
//! malformed-tag fail-closed, and M2b commit serialization stability.
//!
//! All tests use M1c-compat daemon mode (no FUSE) so they run in
//! environments without `/dev/fuse`. Region encryption + redaction
//! happen daemon-side (in `LayerBHook`), not in the FUSE driver, so
//! the relevant invariants are verifiable without a mount.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use serde_json::json;
use softfig_vcs::{BlobEncryptor, Repo};
use softfig_fuse::SealedQuery;
use softfig_ipc::{
    self,
    verbs::{
        op, CommitArgs, LogReply, UnlockArgs, VaultRevealArgs, VaultRevealReply,
        VaultSealArgs,
    },
    Request, Response,
};
use softfig_keeperd::layer_b::{LayerBHook, SealedPaths};
use softfig_keeperd::{Daemon, KeeperConfig};
use softfig_vault::Vault;

mod common;
use common::{fast_params, wait_for_socket};

const PASS: &str = "correct horse battery staple";
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn write_file(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

fn write_file_bytes(root: &Path, rel: &str, body: &[u8]) {
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

// ---- Test 1: region write round trip lands base64 ciphertext --------------

#[test]
fn region_write_round_trip_blob_and_redact_view() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    write_file(
        garden,
        "notes/secret.md",
        "intro\n\n<vault id=\"foo\">SECRET</vault>\n\noutro\n",
    );
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

    // Drive a manual commit through the IPC `commit` verb. The
    // daemon's blob encryptor (LayerBHook) parses the region, encrypts
    // it under the per-region subkey, and inline-embeds the base64
    // ciphertext in place of the raw plaintext.
    let _ = unwrap_ok(rpc(
        &socket,
        op::COMMIT,
        serde_json::to_value(CommitArgs {
            intent: "manual_edit".into(),
            payload: json!({
                "files": ["notes/secret.md"],
                "summary": null,
            }),
        })
        .unwrap(),
    ));

    // Verify the on-disk blob, after Layer A decrypt, has the
    // <vault id="foo">{base64}</vault> form, and the base64 decrypts
    // back to SECRET under the per-region subkey.
    let store_paths = softfig_store::StorePaths::for_garden(garden);
    let db = softfig_store::Db::open(&store_paths).unwrap();
    let tip = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
    let row = db.get_commit(&tip).unwrap();
    let blob_hash = resolve_path(&db, &row.root_tree, &["notes", "secret.md"])
        .expect("notes/secret.md present in tip tree");
    let objects = softfig_store::ObjectStore::new(store_paths.clone());
    let cipher = objects.get(&blob_hash).unwrap();

    // Decrypt under Layer A via a fresh session.
    let session = Vault::at(garden).unlock(PASS.as_bytes()).unwrap();
    let plain = session.decrypt_blob(&cipher).unwrap();
    let plain_str = std::str::from_utf8(&plain).unwrap();
    let regex = regex_match(plain_str);
    assert!(
        regex.is_some(),
        "expected <vault id=\"foo\">{{base64}}</vault> in committed plaintext; got {plain_str:?}"
    );
    let b64 = regex.unwrap();
    let raw = B64.decode(b64).expect("base64 decodes");
    let pt = session.decrypt_layer_b_region("notes/secret.md", "foo", &raw).unwrap();
    assert_eq!(pt, b"SECRET");

    // And the read-view (LayerBHook::redact_regions on the decrypted
    // Layer A bytes) projects `[encrypted]` as the body.
    let hook = LayerBHook::new(SealedPaths::empty());
    hook.set_session(Some(Arc::new(session)));
    let view = hook.redact_regions("notes/secret.md", plain.clone());
    let view_str = std::str::from_utf8(&view).unwrap();
    assert!(
        view_str.contains("<vault id=\"foo\">[encrypted]</vault>"),
        "expected redacted view; got {view_str:?}"
    );

    handle.shutdown();
    handle.join().unwrap();
}

// Match `<vault id="foo">…</vault>` in a string, returning the body.
fn regex_match(s: &str) -> Option<&str> {
    let open = "<vault id=\"foo\">";
    let close = "</vault>";
    let start = s.find(open)? + open.len();
    let end_offset = s[start..].find(close)?;
    Some(&s[start..start + end_offset])
}

// ---- Test 2: two regions; placeholder preservation across edits ----------

#[test]
fn placeholder_preservation_two_regions() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    write_file(
        garden,
        "notes/multi.md",
        "intro\n\n<vault id=\"a\">SECRET_A</vault>\n\n\
         middle\n\n<vault id=\"b\">SECRET_B</vault>\n\nouter\n",
    );
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

    // First commit: both regions become base64 ciphertext.
    let _ = unwrap_ok(rpc(
        &socket,
        op::COMMIT,
        serde_json::to_value(CommitArgs {
            intent: "manual_edit".into(),
            payload: json!({
                "files": ["notes/multi.md"],
                "summary": null,
            }),
        })
        .unwrap(),
    ));

    // Capture the committed blob's bytes (post-Layer-A-decrypt).
    let store_paths = softfig_store::StorePaths::for_garden(garden);
    let db = softfig_store::Db::open(&store_paths).unwrap();
    let session = Vault::at(garden).unlock(PASS.as_bytes()).unwrap();
    let objects = softfig_store::ObjectStore::new(store_paths.clone());

    let read_committed_bytes = || -> Vec<u8> {
        let tip = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
        let row = db.get_commit(&tip).unwrap();
        let h =
            resolve_path(&db, &row.root_tree, &["notes", "multi.md"]).expect("path present");
        let cipher = objects.get(&h).unwrap();
        session.decrypt_blob(&cipher).unwrap()
    };
    let after_first = read_committed_bytes();

    // Now write the file *as the read view would render it* — with
    // `[encrypted]` placeholders — but change the surrounding prose.
    // The write-path region encoder must re-embed each placeholder
    // with its prior ciphertext byte-identically.
    let edited = "DIFFERENT intro\n\n<vault id=\"a\">[encrypted]</vault>\n\n\
                  edited middle\n\n<vault id=\"b\">[encrypted]</vault>\n\nedited outer\n";
    write_file(garden, "notes/multi.md", edited);

    let _ = unwrap_ok(rpc(
        &socket,
        op::COMMIT,
        serde_json::to_value(CommitArgs {
            intent: "manual_edit".into(),
            payload: json!({
                "files": ["notes/multi.md"],
                "summary": null,
            }),
        })
        .unwrap(),
    ));

    let after_second = read_committed_bytes();
    let s = std::str::from_utf8(&after_second).unwrap();
    // Extract the two region bodies from `after_second`.
    let a_body = body_for_id(s, "a").expect("region a present");
    let b_body = body_for_id(s, "b").expect("region b present");
    // Extract the prior committed bytes' bodies.
    let prior_s = std::str::from_utf8(&after_first).unwrap();
    let prior_a = body_for_id(prior_s, "a").expect("prior region a");
    let prior_b = body_for_id(prior_s, "b").expect("prior region b");
    assert_eq!(
        a_body, prior_a,
        "region 'a' ciphertext should be byte-identical across edits"
    );
    assert_eq!(
        b_body, prior_b,
        "region 'b' ciphertext should be byte-identical across edits"
    );
    // And the surrounding prose did change.
    assert!(s.contains("DIFFERENT intro"));
    assert!(s.contains("edited middle"));

    handle.shutdown();
    handle.join().unwrap();
}

fn body_for_id<'a>(s: &'a str, id: &str) -> Option<&'a str> {
    let open = format!("<vault id=\"{id}\">");
    let start = s.find(&open)? + open.len();
    let end_offset = s[start..].find("</vault>")?;
    Some(&s[start..start + end_offset])
}

// ---- Test 3: classifier promotes manual_edit → vault_seal on new id ------

#[test]
fn classifier_promotes_to_vault_seal_on_new_id() {
    use softfig_keeperd::watcher::DirtyEvent;

    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    write_file(garden, "notes/x.md", "no tags yet\n");
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

    // Introduce a vault tag with a brand-new id on disk, then drive
    // the accumulator manually.
    write_file(
        garden,
        "notes/x.md",
        "edited\n\n<vault id=\"alpha\">FRESH</vault>\n",
    );
    let acc = handle.daemon.accumulator.clone();
    acc.push(DirtyEvent::Modified("notes/x.md".into()));
    acc.flush();

    let log: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(log.commits[0].intent, "vault_seal", "log = {:?}", log.commits);

    // Now edit the SAME id's plaintext — the next commit should stay
    // `manual_edit` (existing-region edits are normal content churn,
    // not a re-seal event).
    write_file(
        garden,
        "notes/x.md",
        "edited again\n\n<vault id=\"alpha\">CHANGED</vault>\n",
    );
    acc.push(DirtyEvent::Modified("notes/x.md".into()));
    acc.flush();

    let log: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(
        log.commits[0].intent, "manual_edit",
        "second commit should NOT re-fire vault_seal; log = {:?}",
        log.commits
    );

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 4: `softfig reveal --id foo` writes a 0600 temp file ----------

#[test]
fn region_reveal_writes_temp_file() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let runtime = tmp.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    // SAFETY: test single-threaded for this binary.
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    }

    write_file(
        garden,
        "notes/secret.md",
        "intro\n\n<vault id=\"foo\">PLAINTEXT_REGION_42</vault>\n",
    );
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

    // Commit so the region becomes ciphertext on disk.
    let _ = unwrap_ok(rpc(
        &socket,
        op::COMMIT,
        serde_json::to_value(CommitArgs {
            intent: "manual_edit".into(),
            payload: json!({
                "files": ["notes/secret.md"],
                "summary": null,
            }),
        })
        .unwrap(),
    ));

    let reveal: VaultRevealReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::VAULT_REVEAL,
        serde_json::to_value(VaultRevealArgs {
            path: "notes/secret.md".into(),
            master_password: Some(PASS.into()),
            probe_only: false,
            id: Some("foo".into()),
        })
        .unwrap(),
    )))
    .unwrap();
    let tp = PathBuf::from(&reveal.temp_path);
    assert!(tp.exists(), "{} missing", tp.display());
    let meta = fs::metadata(&tp).unwrap();
    let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());
    assert_eq!(mode & 0o777, 0o600, "0o{:o}", mode & 0o777);
    let pt = fs::read_to_string(&tp).unwrap();
    assert_eq!(pt, "PLAINTEXT_REGION_42");
    // Temp file name follows the M2c pattern.
    let fname = tp.file_name().unwrap().to_str().unwrap();
    assert!(fname.starts_with("softfig-reveal-foo-"), "name = {fname}");

    // The audit commit carries `id`.
    let log: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(log.commits[0].intent, "vault_reveal");

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 5: malformed tag fails closed on write -------------------------

#[test]
fn malformed_tag_fails_closed_on_write() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    // Missing close tag.
    write_file_bytes(garden, "notes/bad.md", b"intro\n<vault id=\"x\">DANGLING");
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

    let resp = rpc(
        &socket,
        op::COMMIT,
        serde_json::to_value(CommitArgs {
            intent: "manual_edit".into(),
            payload: json!({
                "files": ["notes/bad.md"],
                "summary": null,
            }),
        })
        .unwrap(),
    );
    match resp {
        Response::Err { error, .. } => {
            assert!(
                error.contains("malformed vault tag")
                    || error.contains("missing closing"),
                "expected fail-closed; got {error:?}"
            );
        }
        Response::Ok { .. } => panic!("expected commit to fail on malformed tag"),
    }

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 6: M2b commits stay bit-identical for whole-file reveal --------

#[test]
fn m2b_compat_serialization_for_whole_file_reveal() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let runtime = tmp.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    }

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

    // Seal first so reveal has a Layer-B blob to decrypt.
    let _ = unwrap_ok(rpc(
        &socket,
        op::VAULT_SEAL,
        serde_json::to_value(VaultSealArgs {
            pattern: "secrets/**".into(),
        })
        .unwrap(),
    ));

    // Whole-file reveal — id is None.
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

    // Fetch the freshest vault_reveal commit's payload JSON. The
    // canonical serialization must NOT include an `"id"` field — that
    // pins M2b commit bit-identity.
    let store_paths = softfig_store::StorePaths::for_garden(garden);
    let db = softfig_store::Db::open(&store_paths).unwrap();
    let tip = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
    let row = db.get_commit(&tip).unwrap();
    assert_eq!(row.intent, "vault_reveal");
    let parsed: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
    assert!(
        parsed.get("id").is_none(),
        "M2b whole-file vault_reveal should not serialize an `id` field; got {parsed:?}"
    );

    handle.shutdown();
    handle.join().unwrap();
}

// ---- Test 7: probing `<vault>` parsing on TOML literal multi-line --------

#[test]
fn region_round_trip_toml_literal_multiline() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    write_file(
        garden,
        "config.toml",
        "api_key = '''<vault id=\"k\">TOKEN42</vault>'''\n",
    );
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

    let _ = unwrap_ok(rpc(
        &socket,
        op::COMMIT,
        serde_json::to_value(CommitArgs {
            intent: "manual_edit".into(),
            payload: json!({
                "files": ["config.toml"],
                "summary": null,
            }),
        })
        .unwrap(),
    ));

    // The committed blob's plaintext should embed ciphertext, not the
    // literal `TOKEN42`.
    let store_paths = softfig_store::StorePaths::for_garden(garden);
    let db = softfig_store::Db::open(&store_paths).unwrap();
    let tip = db.try_get_ref(softfig_vcs::TIP_REF).unwrap().unwrap();
    let row = db.get_commit(&tip).unwrap();
    let blob_hash = resolve_path(&db, &row.root_tree, &["config.toml"])
        .expect("config.toml present");
    let objects = softfig_store::ObjectStore::new(store_paths.clone());
    let cipher = objects.get(&blob_hash).unwrap();
    let session = Vault::at(garden).unlock(PASS.as_bytes()).unwrap();
    let plain = session.decrypt_blob(&cipher).unwrap();
    let plain_str = std::str::from_utf8(&plain).unwrap();
    assert!(
        !plain_str.contains("TOKEN42"),
        "raw plaintext leaked into TOML region: {plain_str}"
    );
    assert!(
        plain_str.contains("<vault id=\"k\">"),
        "expected vault tag preserved: {plain_str}"
    );

    handle.shutdown();
    handle.join().unwrap();
}

// Sanity: the BlobEncryptor + SealedQuery extension via M2c on a hook
// without any sealed paths still routes inline regions through
// per-region encryption (no whole-file path needed).
#[test]
fn hook_routes_inline_regions_without_seal() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();

    let hook = LayerBHook::new(SealedPaths::empty());
    let session_arc = Arc::new(session);
    hook.set_session(Some(session_arc.clone()));

    let body = b"prelude\n<vault id=\"k\">SECRET</vault>\nepilogue";
    let ct = hook.encrypt("notes/x.md", body, &session_arc).unwrap();
    let plain = session_arc.decrypt_blob(&ct).unwrap();
    let s = std::str::from_utf8(&plain).unwrap();
    assert!(s.contains("<vault id=\"k\">"));
    assert!(!s.contains("SECRET"), "raw secret leaked: {s}");

    let view = hook.redact_regions("notes/x.md", plain);
    let v = std::str::from_utf8(&view).unwrap();
    assert!(v.contains("<vault id=\"k\">[encrypted]</vault>"));

    // Unrelated path with no tags → straight Layer A passthrough.
    let pass = hook.encrypt("notes/y.md", b"just text", &session_arc).unwrap();
    assert_eq!(session_arc.decrypt_blob(&pass).unwrap(), b"just text");
}
