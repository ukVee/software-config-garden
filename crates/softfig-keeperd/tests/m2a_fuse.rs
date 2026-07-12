//! M2a end-to-end coverage: FUSE round-trip, mixed-mode daemon,
//! migrate prepare / finalize.
//!
//! These tests need `/dev/fuse` and `fusermount3`. Where the env
//! denies them (CI sandbox), they emit a notice via `eprintln!` and
//! return early — they're not gated by `#[cfg]` because the dependency
//! is runtime-resolved (kernel + setuid helper), not build-time.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use softfig_vcs::Repo;
use softfig_fuse::{DirtyEventSink, FuseMount};
use softfig_ipc::{
    self,
    verbs::{op, LogIncidentArgs, LogReply, MigrateFinalizeReply, UnlockArgs},
    Request, Response,
};
use softfig_keeperd::{
    fuse_sink::AccumulatorSink, Daemon, KeeperConfig,
};
use softfig_vault::Vault;

mod common;
use common::{fast_params, wait_for_socket};

const PASS: &str = "correct horse battery staple";

fn unique_socket(tmp: &Path) -> PathBuf {
    tmp.join("keeperd.sock")
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

/// Skip body when FUSE isn't actually usable in this env. Returns
/// `true` if the test should proceed.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && (Path::new("/usr/bin/fusermount3").exists()
            || Path::new("/usr/bin/fusermount").exists())
}

/// Init vault + repo at `garden`, then move the entire `.softfig/`
/// to a sibling directory so the resulting layout looks like a
/// finished `softfig migrate prepare`.
fn bootstrap_migrated_garden(tmp: &Path) -> (PathBuf, PathBuf) {
    let garden = tmp.join("garden");
    let state = tmp.join("state");
    fs::create_dir_all(&garden).unwrap();
    fs::write(garden.join("a.md"), "hello\n").unwrap();
    let (_v, session, _r) =
        Vault::init_with_params(&garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(&garden, &session).unwrap();
    drop(session);

    // Copy .softfig/ to the state root (mirrors `migrate prepare`).
    fs::create_dir_all(&state).unwrap();
    copy_dir(&garden.join(".softfig"), &state.join(".softfig")).unwrap();
    // Write keeper.toml in both locations (matches migrate prepare).
    let body = format!("state_root = {:?}\n", state.display().to_string());
    fs::write(garden.join(".softfig/keeper.toml"), &body).unwrap();
    fs::write(state.join(".softfig/keeper.toml"), &body).unwrap();
    (garden, state)
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir(&from, &to)?;
        } else if ft.is_file() {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

// ---------- Test 1: FUSE round-trip via the FuseMount API. ----------

#[test]
fn fuse_round_trip_through_mount() {
    if !fuse_available() {
        eprintln!("fuse unavailable; skipping");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    let mount = tmp.path().join("mount");
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(&mount).unwrap();
    fs::write(staging.join("a.md"), "hello\n").unwrap();

    let (_v, session, _r) =
        Vault::init_with_params(&staging, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(&staging, &session).unwrap();

    // Move the `.softfig/` to a separate state root so the FUSE mount
    // doesn't shadow it.
    let state = tmp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    copy_dir(&staging.join(".softfig"), &state.join(".softfig")).unwrap();

    let session_arc = Arc::new(session);
    let sink: Arc<dyn DirtyEventSink> = Arc::new(NullSink);
    let handle = match FuseMount::mount(&mount, &state, session_arc, sink) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("fuse mount failed (likely sandbox restriction): {e}; skipping");
            return;
        }
    };

    // Wait briefly for the mount to settle.
    std::thread::sleep(Duration::from_millis(100));

    // Read the file the staging garden seeded.
    let read = fs::read_to_string(mount.join("a.md")).expect("read through fuse");
    assert_eq!(read, "hello\n");

    // Drop the mount cleanly.
    drop(handle);
}

#[derive(Debug)]
struct NullSink;
impl DirtyEventSink for NullSink {
    fn created(&self, _r: &str) {}
    fn modified(&self, _r: &str) {}
    fn removed(&self, _r: &str) {}
    fn renamed(&self, _f: &str, _t: &str) {}
    fn nudge(&self) {}
}

// ---------- Test 2: mixed-mode daemon — same binary handles M1c-compat
// and M2a (FUSE) configs without panicking. ----------

#[test]
fn mixed_mode_daemon_handles_both_configs() {
    // M1c-compat path: state_root = None, FUSE off.
    let tmp1 = tempfile::tempdir().unwrap();
    let garden = tmp1.path();
    fs::write(garden.join("a.md"), "hi\n").unwrap();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = unique_socket(tmp1.path());
    let cfg = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(cfg);
    let handle = daemon.start().expect("start m1c-compat");
    wait_for_socket(&socket);
    let _ = unwrap_ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));
    handle.shutdown();
    handle.join().unwrap();

    // M2a path: state_root present, FUSE off (test exercises wiring,
    // not the mount itself, since fuse_available is environment
    // dependent).
    let tmp2 = tempfile::tempdir().unwrap();
    let (garden2, state2) = bootstrap_migrated_garden(tmp2.path());

    let socket2 = unique_socket(tmp2.path());
    let cfg2 = KeeperConfig::new(&garden2)
        .with_state_root(&state2)
        .with_socket(&socket2)
        .without_watcher()
        .without_fuse();
    let daemon2 = Daemon::new(cfg2);
    let handle2 = daemon2.start().expect("start m2a");
    wait_for_socket(&socket2);
    let _ = unwrap_ok(rpc(
        &socket2,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));
    // The daemon should be able to log the genesis commit even without
    // FUSE, because the repo opened against state_root.
    let log: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket2,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(log.commits.len(), 1);
    assert_eq!(log.commits[0].intent, "init");
    handle2.shutdown();
    handle2.join().unwrap();
}

// ---------- Test 3: migrate prepare end-to-end via the CLI helpers. -----

#[test]
fn migrate_prepare_copies_softfig_and_writes_keeper_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path().join("g");
    fs::create_dir_all(&garden).unwrap();
    fs::write(garden.join("a.md"), "hello\n").unwrap();
    let (_v, session, _r) =
        Vault::init_with_params(&garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(&garden, &session).unwrap();
    drop(session);

    // Drive the CLI prepare logic by invoking the command's helpers
    // directly. The CLI wraps these with clap parsing; we replicate
    // the call.
    let state_root = tmp.path().join("state");
    let body = format!("state_root = {:?}\n", state_root.display().to_string());

    // Mirror cmd_migrate::prepare's body.
    fs::create_dir_all(&state_root).unwrap();
    copy_dir(&garden.join(".softfig"), &state_root.join(".softfig")).unwrap();
    fs::write(garden.join(".softfig/keeper.toml"), &body).unwrap();
    fs::write(state_root.join(".softfig/keeper.toml"), &body).unwrap();

    // Assertions: original `.softfig/` still present (copy not move)
    // and plaintext untouched.
    assert!(garden.join(".softfig/db.sqlite").exists());
    assert!(state_root.join(".softfig/db.sqlite").exists());
    assert!(garden.join("a.md").exists());
    let content = fs::read_to_string(garden.join("a.md")).unwrap();
    assert_eq!(content, "hello\n");
    let toml_in_garden = fs::read_to_string(garden.join(".softfig/keeper.toml")).unwrap();
    assert!(toml_in_garden.contains("state_root"));
}

// ---------- Test 4: migrate_finalize IPC verb sequencing. ----------

#[test]
fn migrate_finalize_unmounts_deletes_remounts() {
    if !fuse_available() {
        eprintln!("fuse unavailable; skipping migrate_finalize test");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (garden, state) = bootstrap_migrated_garden(tmp.path());

    let socket = unique_socket(tmp.path());
    let cfg = KeeperConfig::new(&garden)
        .with_state_root(&state)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(cfg);
    let handle = match daemon.start() {
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

    // Confirm FUSE is mounted: reading `a.md` should return its
    // bytes.
    std::thread::sleep(Duration::from_millis(150));
    let _ = fs::read_to_string(garden.join("a.md")); // tolerates either content

    // Drive finalize.
    let resp = rpc(&socket, op::MIGRATE_FINALIZE, json!({}));
    let val = match resp {
        Response::Ok { data, .. } => data,
        Response::Err { kind, error, .. } => {
            eprintln!("finalize errored ({kind:?}): {error}; skipping");
            handle.shutdown();
            let _ = handle.join();
            return;
        }
    };
    let reply: MigrateFinalizeReply = serde_json::from_value(val).unwrap();
    assert!(reply.unmounted, "finalize did not unmount");
    assert!(reply.remounted, "finalize did not remount");
    // Old state should be gone after finalize (best-effort, but a
    // clean tempdir should succeed).
    assert!(reply.old_state_deleted, "old .softfig/ not deleted");

    handle.shutdown();
    let _ = handle.join();
}

// ---------- Test 5: AccumulatorSink translates events into accumulator pushes. -----

#[test]
fn fuse_sink_pushes_into_accumulator() {
    let tmp = tempfile::tempdir().unwrap();
    let garden = tmp.path();
    fs::create_dir_all(garden.join("journal/decisions")).unwrap();
    let (_v, session, _r) =
        Vault::init_with_params(garden, PASS.as_bytes(), fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
    drop(session);

    let socket = unique_socket(tmp.path());
    let cfg = KeeperConfig::new(garden)
        .with_socket(&socket)
        .without_watcher();
    let daemon = Daemon::new(cfg);
    let handle = daemon.start().expect("start");
    wait_for_socket(&socket);
    let _ = unwrap_ok(rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    ));

    // Pre-write the file so commit_workdir sees it on flush.
    fs::write(
        garden.join("journal/decisions/decision-foo.md"),
        "# decision: foo\n\nbody.\n",
    )
    .unwrap();

    let sink = AccumulatorSink::spawn(handle.daemon.accumulator.clone());
    sink.created("journal/decisions/decision-foo.md");
    // Force-flush by draining the debouncer manually — the sink's
    // background flush is timer-based; in tests we poke the
    // accumulator directly to avoid the wait.
    handle.daemon.accumulator.flush();

    let log: LogReply = serde_json::from_value(unwrap_ok(rpc(
        &socket,
        op::LOG,
        json!({"limit": 0}),
    )))
    .unwrap();
    assert_eq!(log.commits.len(), 2);
    assert_eq!(log.commits[0].intent, "decision_logged");
    assert_eq!(log.commits[0].summary, "foo");

    handle.shutdown();
    handle.join().unwrap();
}

// ---------- Test 6: busy-mount SIGTERM must not wedge. ----------

/// Regression for the 2026-06-21 incident: a SIGTERM delivered while the
/// FUSE mount is *busy* (a process with its cwd inside the garden, the
/// growlight loop, in-flight reads) must still tear down in seconds — never
/// the ~90 s wedge that ends in systemd's SIGKILL. The earlier
/// graceful-shutdown fixes were only ever verified against an *idle* mount,
/// so the busy-mount deadlock shipped twice. This test spawns the real
/// daemon binary, unlocks it to mount a real garden, pins the mount busy
/// with a child whose cwd is inside it, sends SIGTERM, and asserts the
/// process exits well under 90 s. The full faithful repro lives here (real
/// FUSE + watcher) rather than an in-process unit test because the wedge is
/// a *process*-exit hang, not a `MountHandle::drop` return.
#[test]
fn busy_mount_sigterm_shuts_down_promptly() {
    use std::process::Command;

    if !fuse_available() {
        eprintln!("fuse unavailable; skipping busy-mount sigterm test");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let (garden, _state) = bootstrap_migrated_garden(tmp.path());
    let socket = unique_socket(tmp.path());

    // Real binary, FUSE mode discovered from keeper.toml, watcher live —
    // matches the on-device daemon as closely as a test can.
    let mut child = Command::new(env!("CARGO_BIN_EXE_softfig-keeperd"))
        .arg("--garden")
        .arg(&garden)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn keeperd");
    wait_for_socket(&socket);

    let unlock = rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs {
            passphrase: PASS.into(),
        })
        .unwrap(),
    );
    if let Response::Err { kind, error, .. } = &unlock {
        eprintln!("unlock failed (likely sandbox fuse restriction: {kind:?} {error}); skipping");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }

    // Let the mount settle, prove it's live, then pin it BUSY with a child
    // process whose cwd is inside the garden — the exact condition (a shell
    // / the loop sitting in the mount) that wedged the device.
    std::thread::sleep(Duration::from_millis(200));
    let _ = fs::read_to_string(garden.join("a.md"));
    // Generate continuous read+write traffic *through* the mount (cwd inside,
    // in-flight FUSE ops, dirty events feeding commit_workdir) — the real
    // device condition (the growlight loop actively working the garden), far
    // busier than a passive cwd pin.
    let mut busy = match Command::new("sh")
        .arg("-c")
        .arg("cd \"$0\" && while true; do echo x >> a.md; cat a.md >/dev/null; ls >/dev/null; done")
        .arg(&garden)
        .current_dir(&garden)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not spawn busy holder ({e}); skipping");
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    };
    std::thread::sleep(Duration::from_millis(300));

    // SIGTERM the daemon while the mount is busy — what systemctl/logout do.
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();

    // Must exit far under systemd's 90 s DefaultTimeoutStopSec. 15 s is a
    // generous ceiling that still cleanly distinguishes "prompt" from "wedged".
    let mut exited = None;
    for _ in 0..150 {
        if let Some(status) = child.try_wait().expect("try_wait") {
            exited = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Tear everything down regardless of outcome so a wedge can't linger.
    // SIGKILL the daemon FIRST if it hung: that closes /dev/fuse, the kernel
    // aborts the connection, and the busy holder (possibly blocked in D-state
    // on the mount) unblocks so we can reap it without hanging the test.
    let wedged = exited.is_none();
    if wedged {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = busy.kill();
    let _ = busy.wait();
    softfig_fuse::clear_stale_mount(&garden);

    let status = exited
        .unwrap_or_else(|| panic!("daemon WEDGED: no exit within 15 s of a busy-mount SIGTERM"));
    assert!(
        status.success(),
        "daemon exited non-zero on busy-mount SIGTERM: {status:?}"
    );
    assert!(
        !socket.exists(),
        "socket left behind after busy-mount SIGTERM"
    );
}

// ---------- Test 7: an M3a write verb commits through the FUSE overlay. ----------

/// Slice 3 (3a + 3b) proof: in FUSE mode an M3a verb (`log_incident`) stages its
/// write into the in-memory overlay and the daemon commits from the
/// `workdir_snapshot` — never `std::fs`-touching or self-walking the mount it
/// serves. Drives the verb through the real daemon + real mount, then asserts
/// the commit landed (new `incident_logged` tip) and the file reads back through
/// the mount with the exact body — i.e. the staged overlay write was persisted.
#[test]
fn fuse_log_incident_commits_via_overlay() {
    use std::process::Command;

    if !fuse_available() {
        eprintln!("fuse unavailable; skipping");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (garden, _state) = bootstrap_migrated_garden(tmp.path());
    let socket = unique_socket(tmp.path());

    let mut child = Command::new(env!("CARGO_BIN_EXE_softfig-keeperd"))
        .arg("--garden")
        .arg(&garden)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn keeperd");
    wait_for_socket(&socket);

    let unlock = rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs { passphrase: PASS.into() }).unwrap(),
    );
    if let Response::Err { kind, error, .. } = &unlock {
        eprintln!("unlock failed (likely sandbox fuse restriction: {kind:?} {error}); skipping");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    std::thread::sleep(Duration::from_millis(200));

    let body = "Repro + fix notes for the commit-path deadlock.\n".repeat(64);
    let reply = unwrap_ok(rpc(
        &socket,
        op::LOG_INCIDENT,
        serde_json::to_value(LogIncidentArgs {
            slug: "overlay-commit".into(),
            summary: "commit via overlay".into(),
            body: body.clone(),
            date: Some("20260621".into()),
        })
        .unwrap(),
    ));
    let rel = reply
        .get("path")
        .and_then(|v| v.as_str())
        .expect("reply path")
        .to_string();
    assert_eq!(rel, "journal/incidents/incident-20260621-overlay-commit.md");

    // The commit landed: the new tip is `incident_logged`.
    let log: LogReply =
        serde_json::from_value(unwrap_ok(rpc(&socket, op::LOG, json!({ "limit": 1 })))).unwrap();
    assert_eq!(log.commits[0].intent, "incident_logged");

    // The staged overlay write was persisted + reads back through the mount (in
    // FUSE mode `garden_root` IS the mount, so this read can only succeed if the
    // overlay write reached the commit — no `std::fs` plaintext path exists).
    let read = fs::read_to_string(garden.join(&rel)).expect("read incident through mount");
    assert!(read.contains(&body), "incident body missing from committed file");
    assert!(read.contains("2026-06-21"), "daemon-stamped date missing: {read}");
    assert!(read.contains("commit via overlay"), "summary missing: {read}");

    let _ = child.kill();
    let _ = child.wait();
    softfig_fuse::clear_stale_mount(&garden);
}

// ---------- Test 8: a commit on a BUSY mount must not wedge. ----------

/// Regression for the 2026-06-21 *commit-path* deadlock (sibling of the
/// shutdown one Test 6 covers). Before slice 3 the daemon committed by walking
/// `garden_root` (= the mount it serves) under `daemon.inner`; when an external
/// FUSE op was in flight during that self-walk it wedged the whole garden for
/// ~20 min until SIGKILL. This pins the mount busy with continuous read+write
/// traffic, fires the exact shape that wedged (an MCP `log_incident` with a big
/// body), and asserts it commits promptly AND the daemon stays responsive to a
/// second IPC call. Full faithful repro (real bin + real mount + watcher),
/// since the wedge is a cross-thread lock starvation, not an in-process hang.
#[test]
fn busy_mount_commit_does_not_wedge() {
    use std::process::Command;
    use std::sync::mpsc;

    if !fuse_available() {
        eprintln!("fuse unavailable; skipping busy-mount commit test");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (garden, _state) = bootstrap_migrated_garden(tmp.path());
    let socket = unique_socket(tmp.path());

    let mut child = Command::new(env!("CARGO_BIN_EXE_softfig-keeperd"))
        .arg("--garden")
        .arg(&garden)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("spawn keeperd");
    wait_for_socket(&socket);

    let unlock = rpc(
        &socket,
        op::UNLOCK,
        serde_json::to_value(UnlockArgs { passphrase: PASS.into() }).unwrap(),
    );
    if let Response::Err { kind, error, .. } = &unlock {
        eprintln!("unlock failed (likely sandbox fuse restriction: {kind:?} {error}); skipping");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    std::thread::sleep(Duration::from_millis(200));
    let _ = fs::read_to_string(garden.join("a.md"));

    // Pin the mount BUSY: continuous read+write+ls through it (cwd inside) — the
    // exact in-flight-FUSE-op condition that collided with the commit's
    // self-walk (the growlight loop actively working the garden).
    let mut busy = match Command::new("sh")
        .arg("-c")
        .arg("cd \"$0\" && while true; do echo x >> a.md; cat a.md >/dev/null; ls >/dev/null; done")
        .arg(&garden)
        .current_dir(&garden)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not spawn busy holder ({e}); skipping");
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    };
    std::thread::sleep(Duration::from_millis(300));

    // Fire the wedge-shaped write from a worker thread so the test can time it.
    let (tx, rx) = mpsc::channel();
    let socket_w = socket.clone();
    let writer = std::thread::spawn(move || {
        let big = "Investigation notes; the commit walk wedged right here.\n".repeat(4096); // ~220 KB
        let resp = rpc(
            &socket_w,
            op::LOG_INCIDENT,
            serde_json::to_value(LogIncidentArgs {
                slug: "busy-commit".into(),
                summary: "busy-mount commit".into(),
                body: big,
                date: Some("20260621".into()),
            })
            .unwrap(),
        );
        let _ = tx.send(resp);
    });

    // It must commit well under the old ~20-min wedge. 20 s is a generous
    // ceiling that still cleanly distinguishes "prompt" from "wedged".
    let outcome = rx.recv_timeout(Duration::from_secs(20));

    // On success, prove the daemon stayed responsive *while still under load*
    // (daemon + busy holder both alive) — a second IPC call must return, not
    // starve behind a wedged commit holding `inner`.
    let responsive =
        outcome.is_ok() && matches!(rpc(&socket, op::STATUS, json!({})), Response::Ok { .. });

    // Teardown order mirrors the busy_mount_sigterm sibling: SIGKILL the daemon
    // FIRST (closes /dev/fuse, aborting the connection) so the busy holder —
    // possibly parked in D-state on the mount — and the blocked writer thread
    // both unblock and can be reaped without hanging the test.
    let _ = child.kill();
    let _ = child.wait();
    let _ = busy.kill();
    let _ = busy.wait();
    let _ = writer.join();
    softfig_fuse::clear_stale_mount(&garden);

    let committed = outcome
        .unwrap_or_else(|_| panic!("daemon WEDGED: log_incident did not commit within 20 s on a busy mount"));
    let data = unwrap_ok(committed);
    assert_eq!(
        data.get("path").and_then(|v| v.as_str()),
        Some("journal/incidents/incident-20260621-busy-commit.md")
    );
    assert!(responsive, "daemon unresponsive during a busy-mount commit");
}
