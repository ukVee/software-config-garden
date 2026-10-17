//! Integration: `queue pick` end to end over a real Unix socket and a real
//! (temp) v2 garden. The verb is READ-ONLY: it assembles the v2 list, applies
//! the loop's published overlay, runs `pick_v2` and reports the assignment plus
//! every skip reason. Nothing is written; no keeperd and no live agent are
//! involved.

use std::path::{Path, PathBuf};

use softfig_growlightd::fleet::FleetConfig;
use softfig_growlightd::{Daemon, GrowlightdConfig};
use softfig_ipc::growlightd::{op, QueuePickArgs, QueuePickReply};
use softfig_ipc::queue_v2::{
    slices_file, Entry, EntryKind, EntryStatus, Lane, Project, QueueToml, SliceItem, SliceKind,
    SliceStatus, SlicesToml, QUEUE_FILE,
};
use softfig_ipc::{connect, ErrorKind, Request};

/// Boot growlightd with a scripted roster (a disarmed fleet: the pick is
/// read-only and the roster is all it needs).
fn boot(socket: PathBuf, garden: PathBuf, fleet_toml: &str) -> softfig_growlightd::DaemonHandle {
    let daemon = Daemon::new(GrowlightdConfig::new(socket, garden));
    daemon.set_fleet_config(
        FleetConfig::from_growlight_toml(fleet_toml).expect("valid fleet config"),
    );
    daemon.start().expect("daemon boots")
}

fn call_ok<T: serde::de::DeserializeOwned>(
    socket: &Path,
    op: &str,
    args: serde_json::Value,
) -> T {
    let mut stream = connect(socket).expect("client connects");
    let resp = softfig_ipc::call(&mut stream, &Request::new(op, args)).expect("verb round-trip");
    let value = resp.into_result().expect("verb ok");
    serde_json::from_value(value).expect("reply decodes")
}

fn call_err(socket: &Path, op: &str, args: serde_json::Value) -> ErrorKind {
    let mut stream = connect(socket).expect("client connects");
    let resp = softfig_ipc::call(&mut stream, &Request::new(op, args)).expect("verb round-trip");
    match resp.into_result() {
        Err((kind, _)) => kind,
        Ok(_) => panic!("expected an error reply"),
    }
}

fn project(name: &str, repo: &str) -> Project {
    Project {
        name: name.into(),
        repo: repo.into(),
        main: "main".into(),
    }
}

fn entry(id: &str, project: &str, status: EntryStatus) -> Entry {
    Entry {
        id: id.into(),
        kind: EntryKind::Milestone,
        title: format!("{id} title"),
        project: project.into(),
        lane: Lane::Normal,
        status,
        after: vec![],
        added: "2026-10-17T01:00:00Z".into(),
        branch: format!("feat/{id}"),
        parent: String::new(),
        base: String::new(),
        claimed: String::new(),
        follow_ups: 0,
        pending_status: None,
    }
}

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).expect("create parent dirs");
    std::fs::write(path, content).expect("write fixture");
}

/// A garden with two projects, a workable milestone `m` (one queued slice), a
/// blocked entry, and a queued task on the other project.
fn v2_garden(root: &Path) {
    // File order matters: `pick_v2` scans in list order and stops at the first
    // workable entry, so the blocked row is placed FIRST — otherwise it would
    // never be examined, and the report would have no skip to show.
    let mut task = entry("t", "other", EntryStatus::Queued);
    task.kind = EntryKind::Task;
    let queue = QueueToml::new(
        vec![project("default", "~/projects/default"), project("other", "~/projects/other")],
        vec![
            entry("blocked", "other", EntryStatus::Blocked),
            entry("m", "default", EntryStatus::Queued),
            task,
        ],
    )
    .to_toml()
    .expect("serialize queue");
    write(root, QUEUE_FILE, &queue);

    // `m`'s tree: one queued slice. No doc for it, so the unit declares no
    // model — every backend runs it (§6.4).
    let slices = SlicesToml::new(
        "m".into(),
        vec![SliceItem {
            kind: SliceKind::Slice,
            id: "001".into(),
            status: SliceStatus::Queued,
            follow_ups: Some(0),
        }],
    )
    .to_toml()
    .expect("serialize slices");
    write(root, &slices_file("m"), &slices);
}

const ROSTER: &str = r#"
fleet_enabled = false

[[fleet]]
agent = "c"
pin = "default"

[[fleet]]
agent = "d"
pin = "other"
"#;

#[test]
fn an_unpinned_pick_reports_the_assignment_and_the_blocked_skip() {
    let dir = tempfile::tempdir().unwrap();
    let garden = dir.path().join("garden");
    std::fs::create_dir_all(&garden).unwrap();
    v2_garden(&garden);
    let socket = dir.path().join("growlightd.sock");
    let _handle = boot(socket.clone(), garden, ROSTER);

    let reply: QueuePickReply =
        call_ok(&socket, op::QUEUE_PICK, serde_json::json!({}));

    assert!(reply.list, "a v2 garden reports its list");
    assert_eq!(reply.member, None, "no --member is an unnamed member");
    assert_eq!(reply.backend, "claude", "the default backend");
    assert_eq!(reply.pin, None, "an unnamed member is unpinned");

    let picked = reply.picked.expect("m is workable");
    assert_eq!(picked.entry, "m");
    assert_eq!(picked.unit, "slice 001 of m");
    assert_eq!(picked.declared, None, "no doc declares a model");

    let blocked = reply
        .skips
        .iter()
        .find(|s| s.entry == "blocked")
        .expect("the blocked entry is reported, not silently dropped");
    assert_eq!(blocked.reason, "not_eligible");
    assert!(!blocked.detail.is_empty(), "every skip carries its explanation");
}

#[test]
fn a_pinned_member_gets_its_own_project_and_another_gets_theirs() {
    let dir = tempfile::tempdir().unwrap();
    let garden = dir.path().join("garden");
    std::fs::create_dir_all(&garden).unwrap();
    v2_garden(&garden);
    let socket = dir.path().join("growlightd.sock");
    let _handle = boot(socket.clone(), garden, ROSTER);

    // c is pinned to `default` — m.
    let c: QueuePickReply = call_ok(
        &socket,
        op::QUEUE_PICK,
        serde_json::json!({ "member": "c" }),
    );
    assert_eq!(c.member.as_deref(), Some("c"));
    assert_eq!(c.pin.as_deref(), Some("default"));
    assert_eq!(c.picked.expect("c has work").entry, "m");

    // d is pinned to `other` — the queued task there, not m.
    let d: QueuePickReply = call_ok(
        &socket,
        op::QUEUE_PICK,
        serde_json::json!({ "member": "d" }),
    );
    assert_eq!(d.pin.as_deref(), Some("other"));
    assert_eq!(d.picked.expect("d has work").entry, "t");

    // An unknown id is a bad argument, never a guessed pick.
    assert_eq!(
        call_err(&socket, op::QUEUE_PICK, serde_json::json!({ "member": "zz" })),
        ErrorKind::BadArgs,
    );
}

#[test]
fn a_garden_without_a_v2_file_answers_nothing_to_show() {
    let dir = tempfile::tempdir().unwrap();
    let garden = dir.path().join("garden");
    std::fs::create_dir_all(&garden).unwrap();
    let socket = dir.path().join("growlightd.sock");
    let _handle = boot(socket.clone(), garden, ROSTER);

    let reply: QueuePickReply = call_ok(
        &socket,
        op::QUEUE_PICK,
        serde_json::to_value(QueuePickArgs::default()).unwrap(),
    );
    assert!(!reply.list, "no queue.toml is the fresh-garden state §3.4");
    assert!(reply.picked.is_none() && reply.skips.is_empty());
    assert_eq!(reply.backend, "claude");
}
