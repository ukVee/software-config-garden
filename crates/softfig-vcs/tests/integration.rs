//! End-to-end coverage of the M1b VCS slice: vault unlock → init → commit
//! → log → show → fsck. Uses tempdirs so the host filesystem stays clean.
//!
//! All tests run with the Vault's minimum-cost Argon2 parameters so the
//! suite stays under a second.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use softfig_vcs::{
    fsck, log_collect, verify_commit, walk, CanonicalCommit, FsckReport, Intent, Repo, TreeNode,
    WalkSnapshot,
};
use softfig_store::{Db, Hash, ObjectStore, StorePaths, TreeEntryKind};
use softfig_vault::{params::VaultParams, Vault, VaultSession};

const PASS: &[u8] = b"correct horse battery staple";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_vault_at(garden: &Path) -> VaultSession {
    let (_v, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).expect("vault init");
    session
}

fn write_files(root: &Path, files: &[(&str, &str)]) {
    for (rel, body) in files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }
}

#[test]
fn init_requires_a_vault() {
    let tmp = tempfile::tempdir().unwrap();
    // No vault yet — we can't construct a session, so we just check the
    // `RepoMissing` / `VaultMissing` error paths via Repo::open.
    let err = Repo::open(tmp.path()).expect_err("must fail without a repo");
    let msg = err.to_string();
    assert!(msg.contains("not initialized"), "msg = {msg}");
}

#[test]
fn init_writes_genesis_and_tip() {
    let tmp = tempfile::tempdir().unwrap();
    write_files(
        tmp.path(),
        &[("README.md", "hello"), ("dir/notes.md", "stuff")],
    );
    let session = init_vault_at(tmp.path());

    let (repo, genesis) = Repo::init(tmp.path(), &session).expect("repo init");
    assert_eq!(repo.tip().unwrap(), Some(genesis));
    let row = repo.db().get_commit(&genesis).unwrap();
    assert!(row.parent.is_none(), "genesis has no parent");
    assert_eq!(row.intent, "init");
}

#[test]
fn init_refuses_when_already_initialized() {
    let tmp = tempfile::tempdir().unwrap();
    write_files(tmp.path(), &[("a.md", "x")]);
    let session = init_vault_at(tmp.path());
    let _ = Repo::init(tmp.path(), &session).unwrap();
    let err = Repo::init(tmp.path(), &session).expect_err("must reject second init");
    assert!(err.to_string().contains("already initialized"));
}

#[test]
fn commit_then_log_yields_two_commits() {
    let tmp = tempfile::tempdir().unwrap();
    write_files(tmp.path(), &[("a.md", "first")]);
    let session = init_vault_at(tmp.path());

    let (mut repo, genesis) = Repo::init(tmp.path(), &session).unwrap();

    fs::write(tmp.path().join("a.md"), "second").unwrap();
    let intent = Intent::new(
        "memory_edit",
        serde_json::json!({ "summary": "edited a.md", "files": ["a.md"] }),
    )
    .unwrap();
    let second = repo.commit_workdir(&session, intent).unwrap();
    assert_ne!(genesis, second);
    assert_eq!(repo.tip().unwrap(), Some(second));

    let log = log_collect(repo.db(), second).unwrap();
    assert_eq!(log.len(), 2, "tip + parent");
    assert_eq!(log[0].hash, second);
    assert_eq!(log[1].hash, genesis);
    assert_eq!(log[1].parent, None);
    assert_eq!(log[0].parent, Some(genesis));
}

#[test]
fn commit_signature_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    write_files(tmp.path(), &[("a.md", "x")]);
    let session = init_vault_at(tmp.path());
    let (_repo, genesis) = Repo::init(tmp.path(), &session).unwrap();

    let repo = Repo::open(tmp.path()).unwrap();
    let row = repo.db().get_commit(&genesis).unwrap();

    let payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
    let canon = CanonicalCommit {
        parent: row.parent,
        root_tree: row.root_tree,
        author_device: &row.author_device,
        author_pubkey: row.author_pubkey,
        timestamp: row.timestamp,
        intent: &row.intent,
        payload: &payload,
        master_key_id: row.master_key_id,
    };
    verify_commit(&canon, row.hash, &row.signature).expect("signature must verify");
}

#[test]
fn jcs_canonicalization_is_deterministic() {
    let payload_a = serde_json::json!({ "z": 1, "a": [3, 2, 1], "m": { "y": 2, "x": 1 } });
    let payload_b = serde_json::json!({ "a": [3, 2, 1], "m": { "x": 1, "y": 2 }, "z": 1 });
    let bytes_a = serde_jcs::to_vec(&payload_a).unwrap();
    let bytes_b = serde_jcs::to_vec(&payload_b).unwrap();
    assert_eq!(bytes_a, bytes_b, "key order must not affect canonical bytes");

    let canon = CanonicalCommit {
        parent: None,
        root_tree: Hash::of(b"x"),
        author_device: "host",
        author_pubkey: [7u8; 32],
        timestamp: 1_700_000_000,
        intent: "init",
        payload: &payload_a,
        master_key_id: 1,
    };
    let h1 = canon.hash().unwrap();
    let h2 = canon.hash().unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn fsck_clean_repo_reports_ok() {
    let tmp = tempfile::tempdir().unwrap();
    write_files(
        tmp.path(),
        &[("a.md", "alpha"), ("dir/b.md", "beta"), ("dir/sub/c.md", "gamma")],
    );
    let session = init_vault_at(tmp.path());
    let (_repo, _genesis) = Repo::init(tmp.path(), &session).unwrap();

    let repo = Repo::open(tmp.path()).unwrap();
    let report: FsckReport = fsck(repo.db(), repo.objects()).unwrap();
    assert!(
        report.ok(),
        "fsck should be clean, problems: {:?}",
        report.problems
    );
    assert!(report.commits_checked >= 1);
    assert!(report.trees_checked >= 1);
    assert!(report.objects_checked >= 3);
    assert!(report.orphan_objects.is_empty());
}

#[test]
fn fsck_detects_corrupted_object() {
    let tmp = tempfile::tempdir().unwrap();
    write_files(tmp.path(), &[("a.md", "needle in haystack")]);
    let session = init_vault_at(tmp.path());
    let (_repo, _genesis) = Repo::init(tmp.path(), &session).unwrap();

    // Find any object file under .softfig/objects/<aa>/<rest> and mutate
    // a single byte.
    let objects = tmp.path().join(".softfig/objects");
    let mut victim = None;
    for fanout in fs::read_dir(&objects).unwrap() {
        let fanout = fanout.unwrap();
        if fanout.file_type().unwrap().is_dir() {
            if let Some(inner) = fs::read_dir(fanout.path()).unwrap().next() {
                victim = Some(inner.unwrap().path());
            }
        }
        if victim.is_some() {
            break;
        }
    }
    let victim = victim.expect("at least one object on disk");
    let mut bytes = fs::read(&victim).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&victim, &bytes).unwrap();

    let repo = Repo::open(tmp.path()).unwrap();
    let report = fsck(repo.db(), repo.objects()).unwrap();
    assert!(!report.ok(), "fsck must catch the corruption");
    assert!(
        report.problems.iter().any(|p| p.contains("hash to")),
        "expected an object-hash mismatch, got: {:?}",
        report.problems
    );
}

#[test]
fn empty_dir_with_keep_is_tracked() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("kept")).unwrap();
    fs::write(tmp.path().join("kept/.keep"), "").unwrap();
    fs::create_dir_all(tmp.path().join("dropped")).unwrap();
    let session = init_vault_at(tmp.path());
    let (_repo, genesis) = Repo::init(tmp.path(), &session).unwrap();

    let repo = Repo::open(tmp.path()).unwrap();
    let row = repo.db().get_commit(&genesis).unwrap();
    let entries = repo.db().get_tree(&row.root_tree).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"kept"), "kept/ should appear: {names:?}");
    assert!(!names.contains(&"dropped"), "dropped/ should be pruned: {names:?}");
}

#[test]
fn init_skips_softfig_dir() {
    // Make sure `walk` doesn't try to commit `.softfig/`'s own files.
    let tmp = tempfile::tempdir().unwrap();
    write_files(tmp.path(), &[("README.md", "x")]);
    let session = init_vault_at(tmp.path());
    let (_repo, genesis) = Repo::init(tmp.path(), &session).unwrap();

    let repo = Repo::open(tmp.path()).unwrap();
    let row = repo.db().get_commit(&genesis).unwrap();
    let entries = repo.db().get_tree(&row.root_tree).unwrap();
    for e in &entries {
        assert_ne!(e.name, ".softfig", "must not track our own state dir");
    }
}

#[test]
fn init_skips_claude_dir() {
    // `.claude/` is Claude Code's per-session scratch (task 002): it must
    // never enter a snapshot/commit, the same way `.softfig/` is skipped.
    let tmp = tempfile::tempdir().unwrap();
    write_files(
        tmp.path(),
        &[
            ("README.md", "x"),
            (".claude/settings.local.json", "{\"permissions\":[]}"),
        ],
    );
    let session = init_vault_at(tmp.path());
    let (_repo, genesis) = Repo::init(tmp.path(), &session).unwrap();

    let repo = Repo::open(tmp.path()).unwrap();
    let row = repo.db().get_commit(&genesis).unwrap();
    let entries = repo.db().get_tree(&row.root_tree).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"README.md"), "real content tracked: {names:?}");
    assert!(
        !names.contains(&".claude"),
        "must not track agent scratch: {names:?}"
    );
}

#[test]
fn convergent_blob_dedup_in_object_store() {
    let tmp = tempfile::tempdir().unwrap();
    write_files(
        tmp.path(),
        &[("twin-1/a.md", "duplicate body"), ("twin-2/a.md", "duplicate body")],
    );
    let session = init_vault_at(tmp.path());
    let (_repo, _genesis) = Repo::init(tmp.path(), &session).unwrap();

    // Two files with identical content → exactly one object on disk
    // (master-keyed convergent encryption + content-addressed store).
    let mut count = 0;
    for fanout in fs::read_dir(tmp.path().join(".softfig/objects")).unwrap() {
        let fanout = fanout.unwrap();
        if !fanout.file_type().unwrap().is_dir() {
            continue;
        }
        for _ in fs::read_dir(fanout.path()).unwrap() {
            count += 1;
        }
    }
    assert_eq!(count, 1, "expected dedup, found {count} objects");
}

#[test]
fn store_layer_hash_helpers_round_trip() {
    let h = Hash::of(b"hello");
    let hex = h.to_hex();
    let parsed = Hash::from_hex(&hex).unwrap();
    assert_eq!(parsed, h);
    assert_eq!(parsed.as_bytes().len(), 32);
}

#[test]
fn store_db_open_rejects_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StorePaths::for_garden(tmp.path());
    let err = Db::open(&paths).expect_err("missing DB must error");
    assert!(format!("{err}").contains("not initialized"));
}

#[test]
fn objects_store_get_after_put_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StorePaths::for_garden(tmp.path());
    fs::create_dir_all(paths.softfig_dir()).unwrap();
    let store = ObjectStore::new(paths);
    store.ensure_root().unwrap();

    let blob = b"plaintext-doesnt-matter-here";
    let hash = store.put(blob).unwrap();
    let back = store.get(&hash).unwrap();
    assert_eq!(back, blob);

    // Idempotent put.
    let again = store.put(blob).unwrap();
    assert_eq!(again, hash);

    // Filing tree entry kind round-trips.
    assert_eq!(TreeEntryKind::Blob.as_str(), "blob");
    assert_eq!(TreeEntryKind::parse("tree"), Some(TreeEntryKind::Tree));
}

#[test]
fn commit_snapshot_commits_the_given_tree_not_the_filesystem() {
    // The FUSE daemon commits from its in-memory (tip ∪ overlay) tree, never
    // by walking the mount it serves. Prove `commit_snapshot` honors the
    // supplied snapshot and ignores the on-disk working tree: build a snapshot
    // holding a file that does NOT exist on disk and assert it lands in the
    // commit, while a plain `walk` of the dir would miss it.
    let tmp = tempfile::tempdir().unwrap();
    write_files(tmp.path(), &[("a.md", "on-disk")]);
    let session = init_vault_at(tmp.path());
    let (mut repo, genesis) = Repo::init(tmp.path(), &session).unwrap();

    // Hand-built in-memory tree — `b.md` is never written to disk.
    let mut root = BTreeMap::new();
    root.insert(
        "a.md".to_string(),
        TreeNode::File { mode: 0o644, content: b"in-memory".to_vec() },
    );
    root.insert(
        "b.md".to_string(),
        TreeNode::File { mode: 0o644, content: b"overlay-only".to_vec() },
    );
    let snapshot = WalkSnapshot { root: TreeNode::Dir(root) };

    let intent = Intent::new(
        "memory_edit",
        serde_json::json!({ "summary": "from in-memory tree", "files": ["a.md", "b.md"] }),
    )
    .unwrap();
    let hash = repo.commit_snapshot(&session, snapshot, intent).unwrap();
    assert_ne!(hash, genesis);
    assert_eq!(repo.tip().unwrap(), Some(hash));

    // The committed tree carries the snapshot's files, including the one that
    // exists only in memory.
    let row = repo.db().get_commit(&hash).unwrap();
    let names: Vec<String> = repo
        .db()
        .get_tree(&row.root_tree)
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert!(names.contains(&"a.md".to_string()), "names = {names:?}");
    assert!(
        names.contains(&"b.md".to_string()),
        "b.md came from the snapshot, not disk: {names:?}"
    );

    // A filesystem walk would NOT see `b.md` — confirming the commit used the
    // provided snapshot rather than the working tree.
    let walked = walk(tmp.path()).unwrap();
    match &walked.root {
        TreeNode::Dir(children) => {
            assert!(!children.contains_key("b.md"), "b.md must not exist on disk")
        }
        TreeNode::File { .. } => panic!("walk root is always a Dir"),
    }
}
