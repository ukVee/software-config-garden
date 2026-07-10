//! Phase 3 (`growlight-garden-cas`) slice 002 integration: the ping-pong
//! contention detector wired into the section-edit commit path (spec §4d).
//!
//! Proves end-to-end against a live daemon that an A↔B alternation on the SAME
//! section over the real edit verbs lands exactly ONE `coord-request` nudge on
//! the coordination bus (from the system sender `growlightd`, to `@all`), and
//! that a non-alternating sequence (one editor, the single-agent case) lands
//! none. The detector's history + cooldown are exercised through the daemon's
//! `inner.thrash` instance, fed one `(target, editor)` per committed edit.
//!
//! M1c-compat garden (no `state_root` → no FUSE), so it runs without
//! `/dev/fuse`; the "no mount I/O under `inner`" invariant is upheld by
//! construction (the nudge rides the same `WorkTree`/in-memory commit pipeline
//! as `post_message`). A live concurrent fleet is the deferred on-device smoke.

use std::path::{Path, PathBuf};

use softfig_vcs::Repo;
use softfig_ipc::verbs::{op, ChatMessage, TailBusReply};
use softfig_ipc::{Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::Vault;

mod common;
use common::{fast_params, ok_data, send, wait_for_socket};

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn init_garden(garden: &Path) {
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
            handle: Some(handle),
            _tmp: tmp,
        }
    }

    fn call(&self, op_name: &str, args: serde_json::Value) -> Response {
        send(&self.socket, &Request::new(op_name, args))
    }

    fn write_file(&self, path: &str, content: &str) {
        let resp = self.call(
            op::REPLACE_FILE,
            serde_json::json!({ "path": path, "content": content }),
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

fn edit_section(fx: &Fixture, path: &str, heading: &str, body: &str, editor: &str) {
    let resp = fx.call(
        op::EDIT_SECTION,
        serde_json::json!({ "path": path, "heading": heading, "body": body, "editor": editor }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "edit {heading}: {resp:?}");
}

fn append_to_section(fx: &Fixture, path: &str, heading: &str, text: &str, editor: &str) {
    let resp = fx.call(
        op::APPEND_TO_SECTION,
        serde_json::json!({ "path": path, "heading": heading, "text": text, "editor": editor }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "append {heading}: {resp:?}");
}

/// Every bus message posted by the system sender `growlightd` (i.e. a thrash
/// nudge), in total order.
fn growlightd_nudges(fx: &Fixture) -> Vec<ChatMessage> {
    let reply: TailBusReply =
        serde_json::from_value(ok_data(fx.call(op::TAIL_BUS, serde_json::json!({ "since": 0 }))))
            .unwrap();
    reply
        .messages
        .into_iter()
        .filter(|m| m.from == "growlightd")
        .collect()
}

// ---- the A↔B ping-pong trips one nudge per window ----------------------

#[test]
fn ping_pong_over_edit_section_nudges_the_bus_once() {
    let fx = Fixture::start();
    fx.write_file("doc.md", "# Doc\n\n## Layout\n\nv0\n");

    // A→B→A→B on the SAME section: the 4th edit completes the alternation.
    edit_section(&fx, "doc.md", "Layout", "by a #1", "agent-a");
    edit_section(&fx, "doc.md", "Layout", "by b #1", "agent-b");
    edit_section(&fx, "doc.md", "Layout", "by a #2", "agent-a");
    edit_section(&fx, "doc.md", "Layout", "by b #2", "agent-b");

    let nudges = growlightd_nudges(&fx);
    assert_eq!(nudges.len(), 1, "exactly one nudge per window: {nudges:?}");
    let n = &nudges[0];
    assert_eq!(n.kind, "coord-request");
    assert_eq!(n.to, "@all");
    assert!(n.body.contains("doc.md §Layout"), "names the target: {}", n.body);
    assert!(n.body.contains("agent-a") && n.body.contains("agent-b"), "names both: {}", n.body);

    // Continuing the ping-pong inside the cooldown stays at one nudge.
    edit_section(&fx, "doc.md", "Layout", "by a #3", "agent-a");
    edit_section(&fx, "doc.md", "Layout", "by b #3", "agent-b");
    assert_eq!(growlightd_nudges(&fx).len(), 1, "cooldown suppresses repeats");
}

// ---- a single editor (the single-agent loop) never trips ---------------

#[test]
fn non_alternating_edits_do_not_nudge() {
    let fx = Fixture::start();
    fx.write_file("doc.md", "## Layout\n\nv0\n");

    // One editor editing repeatedly cannot alternate with itself.
    for i in 0..6 {
        edit_section(&fx, "doc.md", "Layout", &format!("solo {i}"), "agent-a");
    }
    assert!(growlightd_nudges(&fx).is_empty(), "single editor never thrashes");
}

// ---- the append verb feeds the same detector ---------------------------

#[test]
fn ping_pong_over_append_to_section_also_nudges() {
    let fx = Fixture::start();
    fx.write_file("doc.md", "## Log\n\n- start\n");

    append_to_section(&fx, "doc.md", "Log", "- a1", "agent-a");
    append_to_section(&fx, "doc.md", "Log", "- b1", "agent-b");
    append_to_section(&fx, "doc.md", "Log", "- a2", "agent-a");
    append_to_section(&fx, "doc.md", "Log", "- b2", "agent-b");

    let nudges = growlightd_nudges(&fx);
    assert_eq!(nudges.len(), 1, "append-driven ping-pong nudges too: {nudges:?}");
    assert!(nudges[0].body.contains("doc.md §Log"));
}

// ---- edits to DIFFERENT sections of one file never trip ----------------

#[test]
fn alternating_across_different_sections_does_not_nudge() {
    let fx = Fixture::start();
    fx.write_file("doc.md", "## Alpha\n\na0\n\n## Beta\n\nb0\n");

    // a and b alternate, but on DIFFERENT targets — neither section sees a
    // 2-party ping-pong (the detector keys on path + heading).
    edit_section(&fx, "doc.md", "Alpha", "x1", "agent-a");
    edit_section(&fx, "doc.md", "Beta", "y1", "agent-b");
    edit_section(&fx, "doc.md", "Alpha", "x2", "agent-a");
    edit_section(&fx, "doc.md", "Beta", "y2", "agent-b");
    edit_section(&fx, "doc.md", "Alpha", "x3", "agent-a");
    edit_section(&fx, "doc.md", "Beta", "y3", "agent-b");

    assert!(
        growlightd_nudges(&fx).is_empty(),
        "different sections are not contention"
    );
}
