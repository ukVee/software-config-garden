//! M5c slice 003 + 007 integration: the shared-subtree lifecycle verbs end to
//! end, headless. The standard fixture runs the daemon with the slice-007
//! `fuse_attach_unmounted` seam — the full FUSE state machine (overlay
//! staging, union view, commit routing, registry hot-swap) with no kernel
//! mount, so the suite exercises the production paths without `/dev/fuse`
//! (`add` refuses in true direct mode; see `add_refuses_in_direct_mode`).
//!
//! Two control axes:
//!
//! * `add`/`remove` = ring membership — validate (machine/reserved dir +
//!   overlap + populated path rejected), create the chain's genesis ref, then
//!   append to `config/shared-subtrees.toml` + commit
//!   `shared_subtrees_changed`;
//! * `enable`/`disable` = a per-device local toggle — flips ONLY the never-
//!   committed sidecar, provably ceremony-free (no commit, membership byte-
//!   unchanged across a disable→enable cycle).
//!
//! The live kernel-mount smoke stays deferred to the on-device step (see the
//! slice docs' `## Deferred verification`).

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
    /// The standard fixture: FUSE state machine attached with no kernel mount
    /// (the slice-007 `fuse_attach_unmounted` seam), so the suite exercises
    /// the production union-mount paths — overlay staging, commit routing,
    /// registry hot-swap — headlessly. `add` requires a live mount (direct
    /// mode would fold shared content into the device chain), so this is also
    /// what makes the lifecycle verbs reachable at all.
    fn start() -> Self {
        Self::start_with(true)
    }

    /// A true direct-mode (M1c-compat, no FUSE) daemon — only for proving the
    /// direct-mode `add` refusal.
    fn start_disk() -> Self {
        Self::start_with(false)
    }

    fn start_with(attach_fuse: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let garden = tmp.path().to_path_buf();
        init_garden(&garden);
        let socket = garden.join("sock");
        let mut config = KeeperConfig::new(&garden)
            .without_watcher()
            .with_socket(&socket);
        if attach_fuse {
            config = config.with_unmounted_fuse_attach();
        }
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

    /// Committed text of `config/shared-subtrees.toml` through the daemon's
    /// read path (the attach-seam fixture has no on-disk working tree to
    /// read). `None` when absent.
    fn config_text(&self) -> Option<String> {
        match self.call(
            op::READ_FILE,
            serde_json::json!({ "path": "config/shared-subtrees.toml" }),
        ) {
            Response::Ok { data, .. } => Some(data["content"].as_str().unwrap().to_string()),
            Response::Err { .. } => None,
        }
    }

    /// Break-glass write: commit `content` at garden-relative `path` (seeds
    /// device-chain content / corrupts the membership file for the guards).
    fn write_committed(&self, path: &str, content: &str) {
        let resp = self.call(
            op::REPLACE_FILE,
            serde_json::json!({ "path": path, "content": content }),
        );
        assert!(matches!(resp, Response::Ok { .. }), "replace_file {path}: {resp:?}");
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

    /// Stage a create-or-overwrite directly into the daemon's FUSE overlay — no
    /// commit, no kernel round-trip. The headless stand-in for a write through
    /// the live mount that hasn't yet hit the ~200ms flush-debounce commit, so
    /// the add-guard's composed-view (tip ∪ overlay) probe can be exercised in
    /// the `fuse_attach_unmounted` fixture (m5c residual finding 1).
    fn stage_overlay_write(&self, rel: &str, content: &[u8]) {
        let daemon = &self.handle.as_ref().unwrap().daemon;
        let inner = daemon.inner.lock().unwrap();
        let mount = inner.fuse.as_ref().expect("fuse attached");
        mount.stage_write(rel, content.to_vec());
    }

    /// Whether the composed (tip ∪ overlay) mount view has a live entry at `rel`.
    fn mount_path_exists(&self, rel: &str) -> bool {
        let daemon = &self.handle.as_ref().unwrap().daemon;
        let inner = daemon.inner.lock().unwrap();
        inner.fuse.as_ref().expect("fuse attached").path_exists(rel)
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
    let config_after_add = fx.config_text().expect("membership file exists after add");

    // Disable → transparent on this device.
    let r = fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert!(!r.enabled);
    assert!(r.changed);
    assert!(!fx.list().subtrees[0].enabled, "list reflects the disable");

    // No commit fired (tip unchanged) and the membership file is byte-identical.
    assert_eq!(fx.tip(), tip_after_add, "disable must not commit");
    assert_eq!(fx.config_text().unwrap(), config_after_add, "membership byte-unchanged");

    // Idempotent: a second disable is a no-op.
    let r = fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert!(!r.changed);

    // Re-enable restores the full view, still with no commit + no membership edit.
    let r = fx.toggle(op::SHARED_SUBTREE_ENABLE, "journals");
    assert!(r.enabled);
    assert!(r.changed);
    assert!(fx.list().subtrees[0].enabled, "list reflects the enable");
    assert_eq!(fx.tip(), tip_after_add, "enable must not commit");
    assert_eq!(fx.config_text().unwrap(), config_after_add, "membership byte-unchanged");
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

// ---- slice 007: add-time guards + lifecycle robustness ---------------------

/// Finding 14: in true direct (no-FUSE / M1c-compat) mode nothing splits —
/// shared-marked content would fold into the device chain and reach its
/// backup replicas — so `add` refuses outright. Un-sharing stays available.
#[test]
fn add_refuses_in_direct_mode() {
    let fx = Fixture::start_disk();
    match fx.add("projects/journals", None) {
        Response::Err { kind, error, .. } => {
            assert_eq!(kind, ErrorKind::BadArgs);
            assert!(error.contains("union mount"), "unexpected message: {error}");
        }
        Response::Ok { data, .. } => panic!("direct-mode add must refuse, got {data}"),
    }
    // Nothing was created for the refused add.
    assert!(!fx.ref_exists("chain/journals"));
    assert!(fx.list().subtrees.is_empty());
    // remove (un-sharing) is not mode-gated: idempotent no-op, not a refusal.
    let reply: SharedSubtreeRemoveReply = serde_json::from_value(ok_data(fx.call(
        op::SHARED_SUBTREE_REMOVE,
        serde_json::to_value(SharedSubtreeRemoveArgs { id: "journals".into() }).unwrap(),
    )))
    .unwrap();
    assert!(!reply.removed);
}

/// Finding 8: beyond the machine dirs, `add` rejects the reserved top-level
/// names the daemon trusts or writes (`config`, `growlight`, `journal`,
/// `inbox`) and the infrastructure names at any depth (`.softfig`, `.claude`,
/// `.softfigignore`).
#[test]
fn add_rejects_reserved_and_infra_names() {
    let fx = Fixture::start();
    for p in [
        "config",
        "config/deploy",
        "growlight/backlog",
        "journal",
        "inbox",
        ".softfig",
        ".softfigignore",
        "projects/app/.claude",
    ] {
        assert_eq!(err_kind(fx.add(p, None)), ErrorKind::BadArgs, "{p} should reject");
    }
    assert!(fx.list().subtrees.is_empty());
    // A nested dir merely named like a reserved top-level is ordinary content.
    assert!(matches!(fx.add("projects/app/config", None), Response::Ok { .. }));
}

/// Finding 4: a mount path that already has committed device-chain content
/// would vanish behind the graft (empty genesis shadows it; the next device
/// commit's carve-out drops it) — `add` refuses instead.
#[test]
fn add_refuses_a_mount_path_with_committed_device_content() {
    let fx = Fixture::start();
    fx.write_committed("projects/journals/2026.md", "# journal\n");

    assert_eq!(
        err_kind(fx.add("projects/journals", None)),
        ErrorKind::PathAlreadyExists
    );
    // Nothing was created for the refused add...
    assert!(!fx.ref_exists("chain/journals"));
    assert!(fx.list().subtrees.is_empty());
    // ...the committed device content is untouched...
    let resp = fx.call(
        op::READ_FILE,
        serde_json::json!({ "path": "projects/journals/2026.md" }),
    );
    assert_eq!(ok_data(resp)["content"].as_str().unwrap(), "# journal\n");
    // ...and an empty sibling path is still shareable.
    assert!(matches!(fx.add("projects/empty-share", None), Response::Ok { .. }));
}

/// m5c-residual slice 011 (018 finding 10): a committed device FILE at an
/// *ancestor* of the mount path can't be descended through, so the emptiness
/// probe reads the leaf as absent (Blob mid-path -> Ok(false)) and would mint a
/// dead, untraversable share. `add` refuses the blob-ancestor path outright.
#[test]
fn add_refuses_a_blob_ancestor_mount_path() {
    let fx = Fixture::start();
    // A device FILE at projects/notes.md; nothing can be shared *under* it.
    fx.write_committed("projects/notes.md", "# notes\n");

    let resp = fx.add("projects/notes.md/shared", None);
    assert_eq!(err_kind(resp), ErrorKind::BadArgs);
    // Nothing was created for the refused add — no dead share, no orphan ref.
    assert!(!fx.ref_exists("chain/shared"));
    assert!(fx.list().subtrees.is_empty());
    // The device file is untouched...
    let read = fx.call(
        op::READ_FILE,
        serde_json::json!({ "path": "projects/notes.md" }),
    );
    assert_eq!(ok_data(read)["content"].as_str().unwrap(), "# notes\n");
    // ...and an empty sibling path is still shareable.
    assert!(matches!(fx.add("projects/ok-share", None), Response::Ok { .. }));
}

/// Finding 5: a present-but-unreadable membership file must hard-error the
/// mutations — the old `.unwrap_or_default()` turned one corrupt read into a
/// committed allow-list wipe. The compose path (list) parses leniently, so a
/// newer-schema file still routes what this version understands.
#[test]
fn mutations_hard_error_on_unreadable_membership_instead_of_wiping() {
    let fx = Fixture::start();
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));

    // Corrupt the committed membership file outright.
    fx.write_committed("config/shared-subtrees.toml", "not [ valid toml");
    assert_eq!(err_kind(fx.add("notes/wiki", None)), ErrorKind::Internal);
    assert_eq!(
        err_kind(fx.call(
            op::SHARED_SUBTREE_REMOVE,
            serde_json::to_value(SharedSubtreeRemoveArgs { id: "journals".into() }).unwrap(),
        )),
        ErrorKind::Internal
    );
    // The corrupt bytes were never rewritten by the refused mutations.
    assert_eq!(fx.config_text().unwrap(), "not [ valid toml");

    // A newer-schema file (additive unknown fields): mutations still refuse —
    // a strict rewrite would silently drop the fields this daemon doesn't
    // understand — but the lenient compose path still lists the member.
    fx.write_committed(
        "config/shared-subtrees.toml",
        "schema_rev = 2\n\n[[subtree]]\nid = \"journals\"\nmount_path = \"projects/journals\"\n\
         ref_name = \"chain/journals\"\nwrite_turn = \"device-b\"\n",
    );
    assert_eq!(err_kind(fx.add("notes/wiki", None)), ErrorKind::Internal);
    let list = fx.list();
    assert_eq!(list.subtrees.len(), 1, "lenient compose still sees the member");
    assert_eq!(list.subtrees[0].id, "journals");
}

/// Finding 9 (+ the finding-10 ref-reuse semantics): disable → remove → re-add
/// must not be born disabled — remove purges the local-toggle sidecar entry.
/// The chain ref survives the remove (gc reclaims it later) and the re-add
/// reuses it as-is.
#[test]
fn readd_after_disable_and_remove_is_born_enabled() {
    let fx = Fixture::start();
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));
    let r = fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert!(!r.enabled);

    let reply: SharedSubtreeRemoveReply = serde_json::from_value(ok_data(fx.call(
        op::SHARED_SUBTREE_REMOVE,
        serde_json::to_value(SharedSubtreeRemoveArgs { id: "journals".into() }).unwrap(),
    )))
    .unwrap();
    assert!(reply.removed);
    assert!(fx.ref_exists("chain/journals"), "remove keeps the chain ref");

    // Re-add the same id: reuses the surviving chain, born enabled.
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));
    let list = fx.list();
    assert_eq!(list.subtrees.len(), 1);
    assert!(list.subtrees[0].enabled, "re-added share must be born enabled");
}

// ---- slice 009: composed-view add/enable guards (m5c residuals) -------------

/// Slice 009 finding 1: the add-guard probes the *composed* (device tip ∪ FUSE
/// overlay) view, not just the committed tip. A write staged through the live
/// mount that hasn't yet hit the ~200ms flush-debounce commit is real content
/// the empty-genesis graft would still swallow — the tip-only walk (pre-009)
/// passed it, so `add` won the race against the flush timer and the content
/// vanished. The composed-view probe now catches it and refuses.
#[test]
fn add_refuses_a_mount_path_with_overlay_staged_content() {
    let fx = Fixture::start();
    // Content lives only in the overlay — no commit yet (flush pending). The
    // committed tip is empty at this path, so the old tip-only guard would have
    // missed it; the tip ∪ overlay probe catches it.
    fx.stage_overlay_write("projects/journals/2026.md", b"# staged, uncommitted\n");
    assert!(
        fx.mount_path_exists("projects/journals"),
        "the staged child makes the mount dir live in the union view"
    );

    assert_eq!(
        err_kind(fx.add("projects/journals", None)),
        ErrorKind::PathAlreadyExists
    );
    // Nothing was created for the refused add, and the staged content is intact.
    assert!(!fx.ref_exists("chain/journals"));
    assert!(fx.list().subtrees.is_empty());
    assert!(
        fx.mount_path_exists("projects/journals"),
        "the refusal left the staged overlay content untouched"
    );
    // An empty sibling is still shareable.
    assert!(matches!(fx.add("projects/empty-share", None), Response::Ok { .. }));
}

/// Slice 009 finding 2a: `enable` gets the same composed-view populated-path
/// guard as `add`. While a share is disabled the chain is transparent, so a
/// write at/under the mount path routes to the device chain; re-enabling would
/// graft the empty shared chain over it (`retain(!starts_with(prefix))`) and the
/// committed device content would vanish — the exact shape the add-guard
/// prevents, reached through the sibling verb. Enable refuses when the path is
/// populated; disable (nothing to shadow) stays unguarded.
#[test]
fn enable_refuses_when_the_mount_path_holds_content_written_while_disabled() {
    let fx = Fixture::start();
    assert!(matches!(fx.add("projects/journals", None), Response::Ok { .. }));
    let membership_after_add = fx.config_text().expect("membership exists after add");

    // Disable → transparent; the mount path now routes to the device chain.
    let r = fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert!(!r.enabled);

    // A write lands at the mount path while disabled (device-chain content
    // stand-in — the composed-view probe sees the overlay just as it would the
    // committed device tip).
    fx.stage_overlay_write("projects/journals/note.md", b"# written while disabled\n");
    assert!(fx.mount_path_exists("projects/journals"));

    // Re-enabling would shadow it → refused, same kind as add.
    assert_eq!(
        err_kind(fx.call(
            op::SHARED_SUBTREE_ENABLE,
            serde_json::to_value(SharedSubtreeToggleArgs { id: "journals".into() }).unwrap(),
        )),
        ErrorKind::PathAlreadyExists
    );
    // The refused enable left the share disabled, the committed membership
    // byte-unchanged, and the at-risk content live.
    assert!(!fx.list().subtrees[0].enabled, "refused enable stays disabled");
    assert_eq!(fx.config_text().unwrap(), membership_after_add, "membership byte-unchanged");
    assert!(fx.mount_path_exists("projects/journals"), "content survived the refusal");

    // Disable is never guarded — an already-disabled populated share re-disables
    // as a plain no-op (nothing to shadow).
    let r = fx.toggle(op::SHARED_SUBTREE_DISABLE, "journals");
    assert!(!r.changed, "a populated path does not block a disable");
}
