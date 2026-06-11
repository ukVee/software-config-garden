//! End-to-end coverage for M1c: spin up a daemon in a tempdir on a
//! tempfile socket, drive unlock → commit → log → fsck → replace_file →
//! shutdown. Uses minimum-cost Argon2 so the suite stays under a
//! second per the project's test-perf convention.

use std::fs;
use std::path::Path;
use std::time::Duration;

use serde_json::json;
use softfig_vcs::Repo;
use softfig_ipc::{
    self,
    verbs::{
        op, CommitArgs, CommitReply, FsckReply, LogReply,
        ReplaceFileArgs, ReplaceFileReply, StatusReply, UnlockArgs,
    },
    ErrorKind, Request, Response,
};
use softfig_keeperd::{Daemon, KeeperConfig};
use softfig_vault::{params::VaultParams, Vault};

const PASS: &str = "correct horse battery staple";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

/// Send one request, return the response.
fn rpc(socket: &Path, op: &str, args: serde_json::Value) -> Response {
    let mut s = softfig_ipc::connect(socket).expect("connect");
    let req = Request::new(op, args);
    softfig_ipc::call(&mut s, &req).expect("call")
}

fn unwrap_ok(resp: Response) -> serde_json::Value {
    match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => panic!("expected ok, got {:?}: {}", kind, error),
    }
}

fn unique_socket(tmp: &Path) -> std::path::PathBuf {
    tmp.join("keeperd.sock")
}

#[test]
fn full_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    write(garden, "a.md", "hello\n");
    write(garden, "dir/b.md", "world\n");

    // Bootstrap vault + repo OUT-OF-PROCESS would normally happen via the
    // CLI; here we drive them directly to avoid argon2-cost test slowness.
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = unique_socket(tmp.path());
    let config = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(config);
    let handle = daemon.start().expect("start");

    // Wait for the socket to become ready (accept-thread takes a beat).
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "socket never appeared");

    // status before unlock
    let s: StatusReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::STATUS,
        json!({}),
    )))
    .unwrap();
    assert_eq!(s.state, "locked");
    assert!(s.tip.is_none(), "tip visible while locked? {:?}", s.tip);

    // commit while locked → vault_locked
    let args = serde_json::to_value(CommitArgs {
        intent: "memory_edit".into(),
        payload: json!({"summary": "tiny edit", "files": ["a.md"]}),
    })
    .unwrap();
    let r = rpc(&socket, op::COMMIT, args.clone());
    match r {
        Response::Err { kind, .. } => assert_eq!(kind, ErrorKind::VaultLocked),
        _ => panic!("expected vault_locked"),
    }

    // unlock
    let r = rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    );
    let _ = unwrap_ok(r);

    // status after unlock now sees the tip
    let s: StatusReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::STATUS,
        json!({}),
    )))
    .unwrap();
    assert_eq!(s.state, "unlocked");
    assert!(s.tip.is_some(), "tip should be set after init");

    // edit the working tree, then commit through the daemon
    write(garden, "a.md", "hello edited\n");
    let reply: CommitReply = serde_json::from_value(unwrap_ok(rpc(
        &socket, op::COMMIT, args,
    )))
    .unwrap();
    let new_tip = reply.hash;

    // log returns 2 commits
    let r: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(r.commits.len(), 2);
    assert_eq!(r.commits[0].hash, new_tip);
    assert_eq!(r.commits[1].intent, "init");

    // fsck is happy
    let f: FsckReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::FSCK,
        json!({}),
    )))
    .unwrap();
    assert!(f.problems.is_empty(), "fsck reported problems: {:?}", f.problems);
    assert_eq!(f.commits_checked, 2);

    // replace_file writes the file and creates a memory_edit commit
    let req = ReplaceFileArgs {
        path: "notes/added.md".into(),
        content: "new note from claude\n".into(),
    };
    let reply: ReplaceFileReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::REPLACE_FILE,
        serde_json::to_value(req).unwrap(),
    )))
    .unwrap();
    assert_eq!(reply.path, "notes/added.md");
    let written = garden.join("notes/added.md");
    assert!(written.exists());
    assert_eq!(fs::read_to_string(&written).unwrap(), "new note from claude\n");

    // log now has 3 commits
    let r: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(r.commits.len(), 3);
    assert_eq!(r.commits[0].hash, reply.hash);
    assert_eq!(r.commits[0].intent, "memory_edit");

    // shutdown
    let _ = unwrap_ok(rpc(&socket, op::SHUTDOWN, json!({})));
    handle.join().expect("daemon clean exit");
}

#[test]
fn rejects_traversal_in_replace_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = unique_socket(tmp.path());
    let daemon = Daemon::new(
        KeeperConfig::new(garden)
            .with_socket(&socket)
            .without_watcher(),
    );
    let handle = daemon.start().unwrap();
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let _ = rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    );

    for bad in ["../escape.md", "/etc/passwd", "a/../../b.md"] {
        let req = ReplaceFileArgs {
            path: bad.into(),
            content: "x".into(),
        };
        let r = rpc(
            &socket,
            op::REPLACE_FILE,
            serde_json::to_value(req).unwrap(),
        );
        match r {
            Response::Err { kind, .. } => assert_eq!(kind, ErrorKind::BadArgs, "for {bad}"),
            Response::Ok { .. } => panic!("path {bad:?} should have been rejected"),
        }
    }

    handle.shutdown();
    handle.join().unwrap();
}

/// M1d acceptance: pushing synthetic `DirtyEvent`s into a
/// `DirtySetAccumulator` (no inotify, no debouncer, no real fs watching)
/// produces the same classify+commit outcome the inotify path produces.
/// This is the proof the pipeline is source-agnostic — M2a's FUSE driver
/// plugs into this same accumulator via the `AccumulatorSink` adapter.
#[test]
fn accumulator_classifies_synthetic_events() {
    use softfig_keeperd::watcher::DirtyEvent;

    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();

    fs::create_dir_all(garden.join("journal/decisions")).unwrap();

    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = unique_socket(tmp.path());
    // Watcher disabled — we drive the accumulator manually.
    let config = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(config);
    let handle = daemon.start().expect("start");

    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists());

    let _ = unwrap_ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));

    // commit_workdir reads the working tree on flush, so the file has to
    // exist on disk before we tell the accumulator about it.
    write(
        garden,
        "journal/decisions/decision-foo.md",
        "# decision: foo\n\nbody.\n",
    );

    let acc = handle.daemon.accumulator.clone();
    acc.push(DirtyEvent::Created(
        "journal/decisions/decision-foo.md".into(),
    ));
    acc.flush();

    // No polling — flush is synchronous, so the commit is already in
    // the log when this returns.
    let r: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(r.commits.len(), 2, "expected init + decision commits");
    assert_eq!(r.commits[0].intent, "decision_logged");
    assert_eq!(r.commits[0].summary, "foo");

    handle.shutdown();
    handle.join().unwrap();
}

/// Watcher follow-up: dropping a `decision-<slug>.md` file under
/// `journal/decisions/` should produce a `decision_logged` commit
/// without the test calling `commit` itself.
#[test]
fn watcher_classifies_new_decision_file() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();

    // Pre-create the parent dir so the only `Create` event in the dirty
    // batch is the decision file itself (the classifier requires a
    // homogeneous dirty set with a single created path).
    fs::create_dir_all(garden.join("journal/decisions")).unwrap();

    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = unique_socket(tmp.path());
    let config = KeeperConfig::new(garden).with_socket(&socket); // watcher enabled
    let daemon = Daemon::new(config);
    let handle = daemon.start().expect("start");

    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists());

    let _ = unwrap_ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));

    // Give the watcher thread a moment to set up its inotify watches
    // after seeing the Unlocked transition.
    std::thread::sleep(Duration::from_millis(300));

    write(
        garden,
        "journal/decisions/decision-foo.md",
        "# decision: foo\n\nbody.\n",
    );

    // Debounce is 200ms; commit + log round-trip takes a beat. Poll up
    // to ~3s for the second commit to land.
    let mut got_decision = false;
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(50));
        let r: LogReply = serde_json::from_value(unwrap_ok(rpc(
            &socket,
            op::LOG,
            json!({"limit": 0}),
        )))
        .unwrap();
        if r.commits.len() >= 2 {
            assert_eq!(r.commits[0].intent, "decision_logged");
            assert_eq!(r.commits[0].summary, "foo");
            got_decision = true;
            break;
        }
    }
    assert!(got_decision, "watcher never produced the decision commit");

    handle.shutdown();
    handle.join().unwrap();
}

