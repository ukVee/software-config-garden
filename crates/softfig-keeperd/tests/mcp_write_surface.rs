//! mcp-surgical-writes integration: the surgical write-surface verbs
//! (`read_versions`, `patch_file`, `remove_section`, `unlink`, `batch`) —
//! slice 001 (`read_versions`, the CAS-seeding read), slice 002
//! (`patch_file`, the keystone surgical string replacement), and slice 003
//! (`remove_section`, the heading-addressed section deletion).
//!
//! Same harness posture as `m3b_reads.rs`: M1c-compat gardens (no FUSE), files
//! reach the committed tip via `replace_file` (the same `BlobEncryptor` hook
//! real writes use), so sealing + redaction behave exactly as in production.
//!
//! `read_versions` is a projection of `read_file`'s Phase 3 CAS — the tests
//! assert the two verbs agree on the same file, and that the new verb returns
//! version tokens ONLY (no content, no commit, no intent).

use std::path::PathBuf;

use softfig_ipc::verbs::{op, ChatMessage, DocEditReply, LogReply, PatchFileReply, ReadFileReply, ReadVersionsReply, ShowReply, TailBusReply, UnlinkReply};
use softfig_ipc::{ErrorKind, Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::Vault;
use softfig_vcs::Repo;

mod common;
use common::{err_kind, fast_params, ok_data, send, wait_for_socket};

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn init_garden(garden: &std::path::Path) {
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
    fn start(unlock: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let garden = tmp.path().to_path_buf();
        init_garden(&garden);
        let socket = garden.join("sock");
        let config = KeeperConfig::new(&garden)
            .without_watcher()
            .without_net()
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

    /// Commit one file into the tip via `replace_file` (goes through the same
    /// BlobEncryptor hook as real writes).
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

fn versions(fx: &Fixture, path: &str) -> ReadVersionsReply {
    serde_json::from_value(ok_data(fx.call(
        op::READ_VERSIONS,
        serde_json::json!({ "path": path }),
    )))
    .unwrap()
}

fn read(fx: &Fixture, path: &str) -> ReadFileReply {
    serde_json::from_value(ok_data(fx.call(op::READ_FILE, serde_json::json!({ "path": path }))))
        .unwrap()
}

// ---- read_versions (slice 001) ----------------------------------------

#[test]
fn read_versions_agrees_with_read_file_phase_3() {
    let fx = Fixture::start(true);
    fx.write_file(
        "meta/conventions.md",
        "# conventions\n\nrule one\n\n## Naming\n\nlowercase\n\n## Cross-refs\n\nsee meta\n",
    );

    let v = versions(&fx, "meta/conventions.md");
    let r = read(&fx, "meta/conventions.md");

    // The CAS projection is read_file's Phase 3 — same versions, same order.
    assert_eq!(v.path, "meta/conventions.md");
    assert!(!v.sealed);
    assert_eq!(v.version, r.version, "whole-file version must agree");
    assert_eq!(v.sections, r.sections, "per-section versions must agree");
    // Sections are addressable ATX headings in document order.
    let headings: Vec<&str> = v.sections.iter().map(|s| s.heading.as_str()).collect();
    assert_eq!(headings, vec!["conventions", "Naming", "Cross-refs"]);
    assert!(v
        .sections
        .iter()
        .all(|s| !s.version.is_empty()), "every section carries a version");
}

/// `read_versions` returns tokens only — no content field on the wire, ever
/// (the whole point of a coordination primitive is that content stays native).
#[test]
fn read_versions_reply_carries_no_content() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "body text\n");
    let resp = fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "doc.md" }));
    let data = ok_data(resp);
    assert!(data.get("content").is_none(), "no content on the wire: {data:?}");
    assert!(data.get("version").and_then(|v| v.as_str()).is_some());
}

#[test]
fn read_versions_sealed_file_flags_and_hashes_the_placeholder() {
    let fx = Fixture::start(true);
    // Seal first, then write the secret so it commits Layer B directly.
    let resp = fx.call(op::VAULT_SEAL, serde_json::json!({ "pattern": "secrets/**" }));
    assert!(matches!(resp, Response::Ok { .. }), "seal: {resp:?}");
    fx.write_file("secrets/key.txt", "TOPSECRET-do-not-leak");

    let v = versions(&fx, "secrets/key.txt");
    assert!(v.sealed, "expected sealed flag");
    assert!(
        v.sections.is_empty(),
        "a sealed placeholder has no addressable sections: {:?}",
        v.sections
    );
    // The version is that of the redacted `[sealed:…]` placeholder — the same
    // content a (refused) write verb would hash, never the plaintext's.
    let r = read(&fx, "secrets/key.txt");
    assert_eq!(v.version, r.version, "placeholder version must agree with read_file");
    // Proof the version isn't the secret's: hash the projected content.
    let projected = "[sealed:secrets/key.txt]\n";
    let hash = softfig_store::Hash::of(projected.as_bytes()).to_hex();
    assert_eq!(v.version, hash, "version must be the placeholder's hash");
}

#[test]
fn read_versions_rejects_traversal() {
    let fx = Fixture::start(true);
    assert_eq!(
        err_kind(fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "../etc/passwd" }))),
        ErrorKind::BadArgs
    );
}

#[test]
fn read_versions_missing_is_not_found() {
    let fx = Fixture::start(true);
    fx.write_file("present.md", "x");
    assert_eq!(
        err_kind(fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "absent.md" }))),
        ErrorKind::NotFound
    );
}

#[test]
fn read_versions_refuses_when_locked() {
    let fx = Fixture::start(false); // do NOT unlock
    assert_eq!(
        err_kind(fx.call(op::READ_VERSIONS, serde_json::json!({ "path": "anything.md" }))),
        ErrorKind::VaultLocked
    );
}

// ---- patch_file (slice 002) --------------------------------------------

fn patch(
    fx: &Fixture,
    path: &str,
    old: &str,
    new: &str,
    extra: serde_json::Value,
) -> Response {
    let mut args = serde_json::json!({ "path": path, "old": old, "new": new });
    if let serde_json::Value::Object(map) = &extra {
        for (k, v) in map {
            args[k] = v.clone();
        }
    }
    fx.call(op::PATCH_FILE, args)
}

#[test]
fn patch_replaces_a_unique_occurrence_and_replies_the_new_version() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "# T\n\nold line\n\nkeep\n");

    let reply: PatchFileReply = serde_json::from_value(ok_data(patch(
        &fx,
        "doc.md",
        "old line",
        "new line",
        serde_json::json!({}),
    )))
    .unwrap();
    assert_eq!(reply.path, "doc.md");
    assert!(!reply.hash.is_empty());

    let r = read(&fx, "doc.md");
    assert_eq!(r.content, "# T\n\nnew line\n\nkeep\n");
    // The reply's version is the post-patch whole-file version — feed it back
    // as the next `expected_version`.
    assert_eq!(reply.version, versions(&fx, "doc.md").version);
    assert_eq!(reply.version, r.version);
}

#[test]
fn patch_replaces_a_multi_line_occurrence() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "start\nfoo\nbar\nend\n");

    assert!(matches!(
        patch(&fx, "doc.md", "foo\nbar", "replaced", serde_json::json!({})),
        Response::Ok { .. }
    ));
    assert_eq!(read(&fx, "doc.md").content, "start\nreplaced\nend\n");
}

#[test]
fn patch_ambiguous_and_not_found_are_machine_distinct() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "dup dup\n");

    let resp = patch(&fx, "doc.md", "dup", "x", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::TextAmbiguous);

    let resp = patch(&fx, "doc.md", "absent", "x", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::TextNotFound);
}

#[test]
fn patch_anchor_narrows_the_search_window() {
    let fx = Fixture::start(true);
    fx.write_file(
        "doc.md",
        "## A\n\nvalue: one\n\n## B\n\nvalue: one\n\n## C\n\nvalue: one\n",
    );

    // Without the anchor: three occurrences → ambiguous.
    let resp = patch(&fx, "doc.md", "value: one", "value: two", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::TextAmbiguous);

    // The anchor's LINE RANGE is the window (spec-literal): a same-line unique
    // marker disambiguates the needle, and a multi-line anchor can span the
    // target line to cover it.
    fx.write_file("doc2.md", "port = 8080 # staging\nport = 8080 # prod\n");
    let resp = patch(
        &fx,
        "doc2.md",
        "port = 8080",
        "port = 9090",
        serde_json::json!({ "anchor": "# prod" }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "anchored patch: {resp:?}");
    assert_eq!(
        read(&fx, "doc2.md").content,
        "port = 8080 # staging\nport = 9090 # prod\n"
    );

    // A multi-line anchor spanning the target line narrows to its own range.
    let resp = patch(
        &fx,
        "doc.md",
        "value: one",
        "value: two",
        serde_json::json!({ "anchor": "## B\n\nvalue: one" }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "spanning anchor: {resp:?}");
    assert_eq!(
        read(&fx, "doc.md").content,
        "## A\n\nvalue: one\n\n## B\n\nvalue: two\n\n## C\n\nvalue: one\n"
    );

    // A missing / ambiguous anchor surfaces the same machine kinds.
    let resp = patch(
        &fx,
        "doc.md",
        "value: one",
        "x",
        serde_json::json!({ "anchor": "absent" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::TextNotFound);
    let resp = patch(
        &fx,
        "doc.md",
        "value: one",
        "x",
        serde_json::json!({ "anchor": "value" }),
    );
    assert_eq!(err_kind(resp), ErrorKind::TextAmbiguous);
}

#[test]
fn patch_empty_new_deletes_the_matched_text() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "keep\nDELETE ME\nkeep\n");

    assert!(matches!(
        patch(&fx, "doc.md", "DELETE ME\n", "", serde_json::json!({})),
        Response::Ok { .. }
    ));
    assert_eq!(read(&fx, "doc.md").content, "keep\nkeep\n");
}

#[test]
fn patch_cas_guard_conflicts_on_stale_version() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "v0\n");

    let v0 = versions(&fx, "doc.md").version;
    // Stale guard: the pinned version no longer matches the current file.
    fx.write_file("doc.md", "v1\n");
    let resp = patch(
        &fx,
        "doc.md",
        "v1",
        "v2",
        serde_json::json!({ "expected_version": v0 }),
    );
    assert_eq!(err_kind(resp), ErrorKind::Conflict);

    // Current guard: applies cleanly and hands back the new version.
    let v1 = versions(&fx, "doc.md").version;
    let reply: PatchFileReply = serde_json::from_value(ok_data(patch(
        &fx,
        "doc.md",
        "v1",
        "v2",
        serde_json::json!({ "expected_version": v1 }),
    )))
    .unwrap();
    assert_eq!(read(&fx, "doc.md").content, "v2\n");
    assert_eq!(reply.version, versions(&fx, "doc.md").version);
}

#[test]
fn patch_refuses_vault_sealed_targets() {
    let fx = Fixture::start(true);
    let resp = fx.call(op::VAULT_SEAL, serde_json::json!({ "pattern": "secrets/**" }));
    assert!(matches!(resp, Response::Ok { .. }), "seal: {resp:?}");
    fx.write_file("secrets/key.txt", "TOPSECRET");

    let resp = patch(&fx, "secrets/key.txt", "TOPSECRET", "x", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::VaultProtected);
}

#[test]
fn patch_rejects_bad_args() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "x\n");
    // `old` must be non-empty; a provided `anchor` must be non-empty too.
    assert_eq!(
        err_kind(patch(&fx, "doc.md", "", "y", serde_json::json!({}))),
        ErrorKind::BadArgs
    );
    assert_eq!(
        err_kind(patch(&fx, "doc.md", "x", "y", serde_json::json!({ "anchor": "" }))),
        ErrorKind::BadArgs
    );
    assert_eq!(
        err_kind(patch(&fx, "../outside.md", "x", "y", serde_json::json!({}))),
        ErrorKind::BadArgs
    );
}

#[test]
fn patch_refuses_when_locked() {
    let fx = Fixture::start(false); // do NOT unlock
    assert_eq!(
        err_kind(patch(&fx, "doc.md", "x", "y", serde_json::json!({}))),
        ErrorKind::VaultLocked
    );
}

/// The patch path feeds the §4d ping-pong detector like the section verbs: an
/// A↔B alternation on the same whole-file target lands one `coord-request`
/// nudge naming the path (no heading), committed to the bus.
#[test]
fn patch_ping_pong_nudges_the_bus_once() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "v0\n");

    for (i, editor) in ["agent-a", "agent-b", "agent-a", "agent-b"].iter().enumerate() {
        let old = format!("v{i}");
        let new = format!("v{}", i + 1);
        let resp = patch(
            &fx,
            "doc.md",
            &old,
            &new,
            serde_json::json!({ "editor": editor }),
        );
        assert!(matches!(resp, Response::Ok { .. }), "patch {i} by {editor}: {resp:?}");
    }

    let reply: TailBusReply = serde_json::from_value(ok_data(fx.call(
        op::TAIL_BUS,
        serde_json::json!({ "since": 0 }),
    )))
    .unwrap();
    let nudges: Vec<ChatMessage> = reply
        .messages
        .into_iter()
        .filter(|m| m.from == "growlightd")
        .collect();
    assert_eq!(nudges.len(), 1, "exactly one nudge: {nudges:?}");
    assert_eq!(nudges[0].kind, "coord-request");
    assert!(nudges[0].body.contains("doc.md"), "names the target: {}", nudges[0].body);
    assert!(
        !nudges[0].body.contains('§'),
        "a whole-file patch has no heading address: {}",
        nudges[0].body
    );

    // A single editor (the single-agent loop) never trips.
    let fx2 = Fixture::start(true);
    fx2.write_file("doc.md", "s0\n");
    for i in 0..6 {
        let resp = patch(
            &fx2,
            "doc.md",
            &format!("s{i}"),
            &format!("s{}", i + 1),
            serde_json::json!({ "editor": "agent-a" }),
        );
        assert!(matches!(resp, Response::Ok { .. }), "solo patch {i}: {resp:?}");
    }
    let reply: TailBusReply = serde_json::from_value(ok_data(fx2.call(
        op::TAIL_BUS,
        serde_json::json!({ "since": 0 }),
    )))
    .unwrap();
    assert!(
        !reply.messages.iter().any(|m| m.from == "growlightd"),
        "single editor never thrashes: {:?}",
        reply.messages
    );
}

// ---- remove_section (slice 003) -----------------------------------------

fn remove(fx: &Fixture, path: &str, heading: &str, extra: serde_json::Value) -> Response {
    let mut args = serde_json::json!({ "path": path, "heading": heading });
    if let serde_json::Value::Object(map) = &extra {
        for (k, v) in map {
            args[k] = v.clone();
        }
    }
    fx.call(op::REMOVE_SECTION, args)
}

#[test]
fn remove_section_deletes_heading_body_and_subsections() {
    let fx = Fixture::start(true);
    fx.write_file(
        "doc.md",
        "# T\n\n## A\n\nintro\n\n### sub\n\ndetail\n\n## B\n\nb\n",
    );

    let reply: DocEditReply = serde_json::from_value(ok_data(remove(
        &fx,
        "doc.md",
        "A",
        serde_json::json!({}),
    )))
    .unwrap();
    assert_eq!(reply.path, "doc.md");
    assert!(!reply.hash.is_empty());
    assert_eq!(read(&fx, "doc.md").content, "# T\n\n## B\n\nb\n");
    // The reply's version is the new WHOLE-FILE version — the section no
    // longer exists, so there is no post-delete section version to chain.
    assert_eq!(reply.version, versions(&fx, "doc.md").version);
}

#[test]
fn remove_section_addressing_errors() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "## A\n\nx\n\n## A\n\ny\n");

    // Ambiguous → BadArgs (same mapping as edit_section).
    assert_eq!(
        err_kind(remove(&fx, "doc.md", "A", serde_json::json!({}))),
        ErrorKind::BadArgs
    );
    // Absent → NotFound.
    assert_eq!(
        err_kind(remove(&fx, "doc.md", "Nope", serde_json::json!({}))),
        ErrorKind::NotFound
    );
    assert_eq!(
        err_kind(remove(&fx, "doc.md", "##", serde_json::json!({}))),
        ErrorKind::BadArgs
    );
    assert_eq!(read(&fx, "doc.md").content, "## A\n\nx\n\n## A\n\ny\n");
}

#[test]
fn remove_section_cas_guard_is_section_level() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "# T\n\n## A\n\nalpha\n\n## B\n\nbeta\n");
    let va = versions(&fx, "doc.md")
        .sections
        .iter()
        .find(|s| s.heading == "A")
        .unwrap()
        .version
        .clone();

    // Editing the OTHER section leaves A's section version untouched — a
    // section-level guard must not conflict where a whole-file one would.
    let edit_b = fx.call(
        op::EDIT_SECTION,
        serde_json::json!({ "path": "doc.md", "heading": "B", "body": "BETA!" }),
    );
    assert!(matches!(edit_b, Response::Ok { .. }), "edit B: {edit_b:?}");

    // Current guard: deletes cleanly.
    let resp = remove(
        &fx,
        "doc.md",
        "A",
        serde_json::json!({ "expected_version": va }),
    );
    assert!(matches!(resp, Response::Ok { .. }), "remove A: {resp:?}");
    assert_eq!(read(&fx, "doc.md").content, "# T\n\n## B\n\nBETA!\n");

    // Stale guard: the section changed since the caller read it → Conflict.
    fx.write_file("doc2.md", "# T\n\n## C\n\nc0\n\n## D\n\nd\n");
    let vc0 = versions(&fx, "doc2.md")
        .sections
        .iter()
        .find(|s| s.heading == "C")
        .unwrap()
        .version
        .clone();
    let edit_c = fx.call(
        op::EDIT_SECTION,
        serde_json::json!({ "path": "doc2.md", "heading": "C", "body": "c1" }),
    );
    assert!(matches!(edit_c, Response::Ok { .. }), "edit C: {edit_c:?}");
    let resp = remove(
        &fx,
        "doc2.md",
        "C",
        serde_json::json!({ "expected_version": vc0 }),
    );
    assert_eq!(err_kind(resp), ErrorKind::Conflict);
}

#[test]
fn remove_section_refuses_the_last_remaining_heading() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "# T\n\nonly section\n");
    let resp = remove(&fx, "doc.md", "T", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
    assert_eq!(read(&fx, "doc.md").content, "# T\n\nonly section\n");

    // A parent whose span swallows every subsection is the same refusal.
    fx.write_file("doc2.md", "# T\n\n### sub\n\ndetail\n");
    let resp = remove(&fx, "doc2.md", "T", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
    assert_eq!(read(&fx, "doc2.md").content, "# T\n\n### sub\n\ndetail\n");
}

#[test]
fn remove_section_refuses_over_managed_regions() {
    let fx = Fixture::start(true);
    // Deleting the only heading (whose span holds the region) is refused and
    // the managed region survives byte-intact.
    fx.write_file(
        "folder/CLAUDE.md",
        "# folder\n\nrouting prose\n\n<!-- softfig:index notes -->\n\n| # | Note |\n|---|------|\n\n<!-- /softfig:index notes -->\n",
    );
    let resp = remove(&fx, "folder/CLAUDE.md", "folder", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
    assert!(
        read(&fx, "folder/CLAUDE.md").content.contains("<!-- softfig:index notes -->"),
        "region must survive a refused removal"
    );

    // A section clear of the region (the region sits inside a SIBLING's
    // span) deletes cleanly and leaves the region alone.
    fx.write_file(
        "two.md",
        "# T\n\n## A\n\n<!-- softfig:index notes -->\n\n| # |\n\n<!-- /softfig:index notes -->\n\n## B\n\nx\n",
    );
    let resp = remove(&fx, "two.md", "B", serde_json::json!({}));
    assert!(matches!(resp, Response::Ok { .. }), "clear section: {resp:?}");
    let content = read(&fx, "two.md").content;
    assert!(content.contains("<!-- softfig:index notes -->"), "region intact: {content}");
    assert!(content.contains("## A"), "sibling intact: {content}");
    assert!(!content.contains("## B"), "B gone: {content}");
}

#[test]
fn remove_section_refuses_vault_targets() {
    let fx = Fixture::start(true);
    let resp = fx.call(op::VAULT_SEAL, serde_json::json!({ "pattern": "secrets/**" }));
    assert!(matches!(resp, Response::Ok { .. }), "seal: {resp:?}");
    fx.write_file("secrets/doc.md", "# S\n\nsecret body\n");

    let resp = remove(&fx, "secrets/doc.md", "S", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::VaultProtected);
}

#[test]
fn remove_section_rejects_bad_args_and_locked() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "# T\n\n## A\n\nx\n");
    assert_eq!(
        err_kind(remove(&fx, "../outside.md", "A", serde_json::json!({}))),
        ErrorKind::BadArgs
    );

    let fx = Fixture::start(false); // do NOT unlock
    assert_eq!(
        err_kind(remove(&fx, "doc.md", "A", serde_json::json!({}))),
        ErrorKind::VaultLocked
    );
}

/// The remove path feeds the §4d ping-pong detector like the section verbs:
/// an A↔B alternation on the same `(path, heading)` target lands one
/// `coord-request` nudge naming the section, committed to the bus.
#[test]
fn remove_section_ping_pong_nudges_the_bus_once() {
    let fx = Fixture::start(true);

    for (i, editor) in ["agent-a", "agent-b", "agent-a", "agent-b"].iter().enumerate() {
        fx.write_file("doc.md", &format!("# T\n\n## G\n\nbody v{i}\n"));
        let resp = remove(
            &fx,
            "doc.md",
            "G",
            serde_json::json!({ "editor": editor }),
        );
        assert!(matches!(resp, Response::Ok { .. }), "remove {i} by {editor}: {resp:?}");
    }

    let reply: TailBusReply = serde_json::from_value(ok_data(fx.call(
        op::TAIL_BUS,
        serde_json::json!({ "since": 0 }),
    )))
    .unwrap();
    let nudges: Vec<ChatMessage> = reply
        .messages
        .into_iter()
        .filter(|m| m.from == "growlightd")
        .collect();
    assert_eq!(nudges.len(), 1, "exactly one nudge: {nudges:?}");
    assert_eq!(nudges[0].kind, "coord-request");
    assert!(
        nudges[0].body.contains("doc.md") && nudges[0].body.contains("G"),
        "names the section target: {}",
        nudges[0].body
    );
}

// ---- unlink (slice 004) ------------------------------------------------

fn unlink(fx: &Fixture, path: &str, extra: serde_json::Value) -> Response {
    let mut args = serde_json::json!({ "path": path });
    if let serde_json::Value::Object(map) = &extra {
        for (k, v) in map {
            args[k] = v.clone();
        }
    }
    fx.call(op::UNLINK, args)
}

#[test]
fn unlink_deletes_a_leaf_and_commits_file_unlinked() {
    let fx = Fixture::start(true);
    fx.write_file("junk.md", "triage leftover\n");

    let reply: UnlinkReply = serde_json::from_value(ok_data(unlink(
        &fx,
        "junk.md",
        serde_json::json!({}),
    )))
    .unwrap();
    assert_eq!(reply.path, "junk.md");
    assert!(!reply.hash.is_empty());
    assert_eq!(
        err_kind(fx.call(op::READ_FILE, serde_json::json!({ "path": "junk.md" }))),
        ErrorKind::NotFound
    );

    // The tip commit carries the `file_unlinked` intent.
    let log: LogReply = serde_json::from_value(ok_data(fx.call(
        op::LOG,
        serde_json::json!({ "limit": 1 }),
    )))
    .unwrap();
    assert_eq!(log.commits[0].intent, "file_unlinked");
}

#[test]
fn unlink_refuses_when_listed_in_a_managed_index() {
    let fx = Fixture::start(true);
    fx.write_file(
        "folder/CLAUDE.md",
        "# folder\n\n<!-- softfig:index notes -->\n\n| # | Note | Reviewed |\n\
         |---|------|----------|\n| 001 | [A note](notes/001-a.md) | 2026-08-13 |\n\n\
         <!-- /softfig:index notes -->\n",
    );
    fx.write_file("folder/notes/001-a.md", "# A note\n\nbody\n");

    let resp = unlink(&fx, "folder/notes/001-a.md", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::ReferencedElsewhere);
    assert_eq!(read(&fx, "folder/notes/001-a.md").content, "# A note\n\nbody\n");

    // A file NOT listed in the index is a plain leaf → deletable.
    fx.write_file("folder/notes/002-b.md", "# B\n");
    let resp = unlink(&fx, "folder/notes/002-b.md", serde_json::json!({}));
    assert!(matches!(resp, Response::Ok { .. }), "unlisted leaf: {resp:?}");
}

#[test]
fn unlink_refuses_when_inbound_backlinks_exist() {
    let fx = Fixture::start(true);
    fx.write_file("notes/002-target.md", "# Target\n");
    fx.write_file("notes/001-source.md", "# Source\n\nsee [[002-target]]\n");

    let resp = unlink(&fx, "notes/002-target.md", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::ReferencedElsewhere);
    assert_eq!(read(&fx, "notes/002-target.md").content, "# Target\n");

    // The backlink source itself is a leaf (nothing links TO it) → deletable.
    let resp = unlink(&fx, "notes/001-source.md", serde_json::json!({}));
    assert!(matches!(resp, Response::Ok { .. }), "source leaf: {resp:?}");
}

/// Deleting a file drops it from every backlinks region that named it as a
/// source — no dangling rows after an unlink.
#[test]
fn unlink_drops_the_deleted_file_from_backlinks_regions() {
    let fx = Fixture::start(true);
    fx.write_file("notes/002-target.md", "# T\n\ntarget body\n");
    // Make 001 reference 002, then force the graph to materialize 002's
    // backlinks region via a patch (which refreshes the graph).
    fx.write_file("notes/001-source.md", "# S\n\nref [[002-target]]\n");
    let resp = patch(
        &fx,
        "notes/001-source.md",
        "ref [[002-target]]",
        "ref [[002-target]] kept",
        serde_json::json!({}),
    );
    assert!(matches!(resp, Response::Ok { .. }), "patch: {resp:?}");
    assert!(
        read(&fx, "notes/002-target.md").content.contains("001-source"),
        "region materialized"
    );

    // 002 does NOT reference 001, so 001 is an unreferenced leaf → deletable;
    // the graph refresh must drop 001 from 002's region.
    let resp = unlink(&fx, "notes/001-source.md", serde_json::json!({}));
    assert!(matches!(resp, Response::Ok { .. }), "unlink: {resp:?}");
    let t = read(&fx, "notes/002-target.md").content;
    assert!(!t.contains("001-source"), "dangling backlink row: {t}");
}

#[test]
fn unlink_cas_guard_conflicts_on_stale_version() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "v0\n");
    let v0 = versions(&fx, "doc.md").version;

    // Stale guard: the pinned version no longer matches the current file.
    fx.write_file("doc.md", "v1\n");
    let resp = unlink(&fx, "doc.md", serde_json::json!({ "expected_version": v0 }));
    assert_eq!(err_kind(resp), ErrorKind::Conflict);
    assert_eq!(read(&fx, "doc.md").content, "v1\n");

    // Current guard: deletes cleanly.
    let v1 = versions(&fx, "doc.md").version;
    let resp = unlink(&fx, "doc.md", serde_json::json!({ "expected_version": v1 }));
    assert!(matches!(resp, Response::Ok { .. }), "unlink: {resp:?}");
    assert_eq!(
        err_kind(fx.call(op::READ_FILE, serde_json::json!({ "path": "doc.md" }))),
        ErrorKind::NotFound
    );
}

#[test]
fn unlink_refuses_directories() {
    let fx = Fixture::start(true);
    fx.write_file("sub/keep.md", "x\n");
    let resp = unlink(&fx, "sub", serde_json::json!({}));
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
    assert_eq!(read(&fx, "sub/keep.md").content, "x\n");
}

#[test]
fn unlink_deletes_a_sealed_file_with_a_sealed_payload_flag() {
    let fx = Fixture::start(true);
    // Seal first, then write the secret so it commits Layer B directly.
    let resp = fx.call(op::VAULT_SEAL, serde_json::json!({ "pattern": "secrets/**" }));
    assert!(matches!(resp, Response::Ok { .. }), "seal: {resp:?}");
    fx.write_file("secrets/key.txt", "TOPSECRET-do-not-leak");

    // No vault refusal: a sealed blob is deletable (history keeps the bytes),
    // and the commit payload marks that the deleted content was vault-tagged.
    let reply: UnlinkReply = serde_json::from_value(ok_data(unlink(
        &fx,
        "secrets/key.txt",
        serde_json::json!({}),
    )))
    .unwrap();
    let show: ShowReply = serde_json::from_value(ok_data(fx.call(
        op::SHOW,
        serde_json::json!({ "hash": reply.hash }),
    )))
    .unwrap();
    assert_eq!(show.commit.intent, "file_unlinked");
    let payload: serde_json::Value = serde_json::from_str(&show.commit.payload).unwrap();
    assert_eq!(payload["path"], "secrets/key.txt");
    assert_eq!(payload["sealed"], serde_json::json!(true));
}

#[test]
fn unlink_rejects_bad_args_and_locked() {
    let fx = Fixture::start(true);
    fx.write_file("doc.md", "x\n");
    assert_eq!(
        err_kind(unlink(&fx, "../outside.md", serde_json::json!({}))),
        ErrorKind::BadArgs
    );
    // Daemon state is not garden content (and not VCS-recoverable).
    assert_eq!(
        err_kind(unlink(&fx, ".softfig/keeper.toml", serde_json::json!({}))),
        ErrorKind::BadArgs
    );
    assert_eq!(
        err_kind(unlink(&fx, "absent.md", serde_json::json!({}))),
        ErrorKind::NotFound
    );
    assert_eq!(read(&fx, "doc.md").content, "x\n");

    let fx = Fixture::start(false); // do NOT unlock
    assert_eq!(
        err_kind(unlink(&fx, "doc.md", serde_json::json!({}))),
        ErrorKind::VaultLocked
    );
}
