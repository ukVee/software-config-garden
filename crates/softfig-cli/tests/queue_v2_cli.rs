//! queue-v2-state slice 009: the §6.9 CLI forms, exercised as the **binary**
//! sends them — the built `softfig` executable spawned over argv against a real
//! keeperd on a temp garden + temp socket (no FUSE, no watcher). This is the
//! "installed binary" check of the slice: real process, real arg parsing, real
//! wire traffic, temp garden only (spec §11 — the live garden never sees a v2
//! file from this suite).
//!
//! The in-crate `cmd_growlight` tests cover the arg mappings and the
//! handler-level round trip; this suite covers the process seam on top.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde_json::json;
use softfig_ipc::{
    Request, Response, connect,
    queue_v2::{QueueToml, QUEUE_ARCHIVE_FILE, QUEUE_FILE},
    verbs::{ReadFileReply, op},
};
use softfig_keeperd::{Daemon, KeeperConfig};
use softfig_vault::{Vault, params::VaultParams};
use softfig_vcs::Repo;

const PASS: &str = "pw-test-12345";

fn tmp(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("softfig-cli-{tag}-{}-{nanos}", std::process::id()))
}

/// Boot keeperd on a fresh temp garden + unlock it over the socket.
fn boot(socket: &Path, garden: &Path) -> softfig_keeperd::DaemonHandle {
    fs::create_dir_all(garden).unwrap();

    // Minimum-cost Argon2 so the fixture stays fast (the keeperd suite's
    // convention).
    let mut params = VaultParams::default();
    params.argon2.m_cost = 8;
    params.argon2.t_cost = 1;
    params.argon2.p_cost = 1;
    let (_v, session, _r) = Vault::init_with_params(garden, PASS.as_bytes(), params).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let config = KeeperConfig::new(garden)
        .with_socket(socket)
        .without_watcher()
        .without_net()
        .without_fuse();
    let handle = Daemon::new(config).start().expect("keeperd boots");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(std::time::Instant::now() < deadline, "socket never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut stream = connect(socket).expect("connect");
    let req = Request::new(op::UNLOCK, json!({ "passphrase": PASS }));
    let resp = softfig_ipc::call(&mut stream, &req).expect("unlock call");
    assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");
    handle
}

/// One `softfig growlight {queue|slice} …` invocation; returns the completed
/// process output. The `--socket` flag sits at the `queue`/`slice` level, so
/// it precedes the subcommand word (clap parses parent args before the
/// subcommand here). Call sites spell the group word at the head of `args`
/// for readability; it is dropped when it matches `group`.
fn cli(socket: &Path, group: &str, args: &[&str]) -> Output {
    let sock = socket.to_str().expect("utf8 socket path");
    let mut argv: Vec<&str> = vec!["growlight", group, "--socket", sock];
    let rest = if args.first() == Some(&group) {
        &args[1..]
    } else {
        args
    };
    argv.extend_from_slice(rest);
    Command::new(env!("CARGO_BIN_EXE_softfig"))
        .args(&argv)
        .output()
        .expect("softfig runs")
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "expected success, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn refused(out: &Output) -> String {
    assert!(
        !out.status.success(),
        "expected refusal, got exit 0\nstdout: {}",
        String::from_utf8_lossy(&out.stdout),
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn read(socket: &Path, path: &str) -> String {
    let mut stream = connect(socket).expect("connect");
    let req = Request::new(op::READ_FILE, json!({ "path": path }));
    match softfig_ipc::call(&mut stream, &req).expect("read") {
        Response::Ok { data, .. } => {
            let reply: ReadFileReply = serde_json::from_value(data).unwrap();
            reply.content
        }
        other => panic!("read {path}: {other:?}"),
    }
}

fn queue(socket: &Path) -> QueueToml {
    QueueToml::parse(&read(socket, QUEUE_FILE)).expect("queue.toml parses")
}

#[test]
fn the_six_nine_forms_round_trip_through_the_binary() {
    let dir = tmp("queue-v2-cli-e2e");
    let garden = dir.join("garden");
    let socket = dir.join("keeperd.sock");
    let handle = boot(&socket, &garden);

    // Fresh garden: `queue show` says there is nothing v2 yet (exit 0 — §3.4).
    let out = ok(&cli(&socket, "queue", &["queue", "show"]));
    assert!(out.contains("no growlight/backlog/queue.toml"), "{out}");

    // project add → the projects table; the duplicate is refused, code first.
    let out = ok(&cli(&socket, "queue", &["queue", "project", "add", "softfig", "~/p"]));
    assert!(out.contains("softfig"), "{out}");
    let err = refused(&cli(&socket, "queue", &["queue", "project", "add", "softfig", "~/p"]));
    assert!(err.contains("exists"), "{err}");
    assert_eq!(queue(&socket).projects.len(), 1);

    // add milestone — the view carries the row + its branch seed.
    let out = ok(&cli(
        &socket,
        "queue",
        &[
            "queue", "add", "milestone", "m1", "--project", "softfig", "--title", "M1",
            "--mission", "do the thing", "--criteria", "done when done",
        ],
    ));
    assert!(out.contains("feat/m1"), "{out}");

    // @file values read from disk (§6.9).
    let mission = dir.join("mission.md");
    fs::write(&mission, "mission from a file\n").unwrap();
    let out = ok(&cli(
        &socket,
        "queue",
        &[
            "queue", "add", "task", "t1", "--project", "softfig", "--title", "T1",
            "--mission", &format!("@{}", mission.display()), "--criteria", "c",
        ],
    ));
    assert!(out.contains("T1"), "{out}");
    // The task's id is its NNN, assigned by keeperd (finding 4) — the slug
    // never appears in the queue view.
    let task_id = queue(&socket)
        .entries
        .iter()
        .find(|e| e.kind == softfig_ipc::queue_v2::EntryKind::Task)
        .expect("task row")
        .id
        .clone();

    // dry-run on a mutating form writes nothing and says so.
    let out = ok(&cli(
        &socket,
        "queue",
        &[
            "queue", "add", "milestone", "ghost", "--project", "softfig", "--title", "G",
            "--mission", "m", "--criteria", "c", "--dry-run",
        ],
    ));
    assert!(out.contains("dry run — nothing written"), "{out}");
    assert!(
        queue(&socket).entries.iter().all(|e| e.id != "ghost"),
        "dry run wrote nothing"
    );

    // lane → urgent; the two-lane show renders it in the urgent section.
    ok(&cli(&socket, "queue", &["queue", "lane", "m1", "urgent"]));
    assert_eq!(
        queue(&socket).entries.iter().find(|e| e.id == "m1").unwrap().lane,
        softfig_ipc::queue_v2::Lane::Urgent
    );
    let out = ok(&cli(&socket, "queue", &["queue", "show"]));
    let urgent = out.find("### Urgent").expect("urgent lane");
    let normal = out.find("### Normal").expect("normal lane");
    assert!(urgent < normal, "urgent lane renders first");
    assert!(out.contains("| m1 | milestone | M1 |"), "{out}");

    // after links (replaces the list) and a within-lane move.
    ok(&cli(&socket, "queue", &["queue", "after", "m1", &task_id]));
    assert_eq!(
        queue(&socket).entries.iter().find(|e| e.id == "m1").unwrap().after,
        vec![task_id.clone()]
    );
    ok(&cli(&socket, "queue", &["queue", "move", "m1", "back"]));

    // slice insert + move + status inside m1's slices.toml.
    let out = ok(&cli(
        &socket,
        "slice",
        &[
            "slice", "insert", "m1", "002", "--title", "s2", "--body", "do it",
        ],
    ));
    assert!(out.contains("002"), "{out}");
    let s = softfig_ipc::queue_v2::SlicesToml::parse(&read(
        &socket,
        &softfig_ipc::queue_v2::slices_file("m1"),
    ))
    .expect("slices.toml parses");
    assert_eq!(s.items.len(), 2);
    ok(&cli(&socket, "slice", &["slice", "move", "m1", "002", "front"]));
    let s = softfig_ipc::queue_v2::SlicesToml::parse(&read(
        &socket,
        &softfig_ipc::queue_v2::slices_file("m1"),
    ))
    .expect("slices.toml parses");
    assert_eq!(s.items[0].id, "002", "front move reorders");
    ok(&cli(&socket, "slice", &["slice", "status", "m1", "002", "done"]));
    let s = softfig_ipc::queue_v2::SlicesToml::parse(&read(
        &socket,
        &softfig_ipc::queue_v2::slices_file("m1"),
    ))
    .expect("slices.toml parses");
    assert_eq!(s.items[0].status, softfig_ipc::queue_v2::SliceStatus::Done);

    // status done archives; drop archives with a reason; the archive file
    // reflects both.
    ok(&cli(&socket, "queue", &["queue", "status", &task_id, "done"]));
    ok(&cli(&socket, "queue", &["queue", "drop", "m1", "--reason", "superseded"]));
    assert!(queue(&socket).entries.is_empty(), "both entries left the list");
    let arch = softfig_ipc::queue_v2::QueueArchiveToml::parse(&read(
        &socket,
        QUEUE_ARCHIVE_FILE,
    ))
    .expect("queue-archive.toml parses");
    let t1 = arch.entries.iter().find(|e| e.row.id == task_id).expect("task archived");
    assert_eq!(t1.final_status, softfig_ipc::queue_v2::FinalStatus::Done);
    let m1 = arch.entries.iter().find(|e| e.row.id == "m1").expect("m1 archived");
    assert_eq!(m1.final_status, softfig_ipc::queue_v2::FinalStatus::Dropped);
    assert_eq!(m1.reason.as_deref(), Some("superseded"));

    // A bad slug surfaces the wire refusal code on stderr, unadorned.
    let err = refused(&cli(
        &socket,
        "queue",
        &[
            "queue", "add", "milestone", "Bad_Name!", "--project", "softfig", "--title", "B",
            "--mission", "m", "--criteria", "c",
        ],
    ));
    assert!(err.contains("bad_name"), "{err}");

    // The restack form: project only, lands in the urgent lane with no branch.
    ok(&cli(&socket, "queue", &["queue", "add", "restack", "--project", "softfig"]));
    let q = queue(&socket);
    let restack = q.entries.iter().find(|e| e.kind == softfig_ipc::queue_v2::EntryKind::Restack).expect("restack row");
    assert_eq!(restack.lane, softfig_ipc::queue_v2::Lane::Urgent);
    assert!(restack.branch.is_empty());

    // The CLI grammar itself refuses the daemon-owned words (clap exit 2).
    let err = refused(&cli(&socket, "queue", &["queue", "status", "001", "active"]));
    assert!(err.contains("error") || err.contains("invalid"), "{err}");

    handle.shutdown();
    handle.join().unwrap();
    fs::remove_dir_all(&dir).ok();
}
