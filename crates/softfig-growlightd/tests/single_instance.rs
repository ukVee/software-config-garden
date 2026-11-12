//! One growlightd per socket (review 061 F3), proven against the real binary:
//! a second instance started by hand must exit non-zero before it unlinks the
//! live socket or reaches the boot reconcile, and a start after the holder is
//! gone must succeed.
//!
//! The reconcile probe is a fake keeperd socket per instance: an armed boot
//! reconcile always dials keeperd (the backlog read), so a connection there
//! means the reconcile ran. The holder's own probe must see one, or the
//! "never reconciles" assertion on the second instance would prove nothing.

use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(60);

/// A listener standing in for keeperd that only counts who dials it.
struct FakeKeeperd {
    path: PathBuf,
    dials: Arc<AtomicUsize>,
}

impl FakeKeeperd {
    fn start(path: PathBuf) -> FakeKeeperd {
        let listener = UnixListener::bind(&path).unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = dials.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        drop(s);
                    }
                    Err(_) => break,
                }
            }
        });
        FakeKeeperd { path, dials }
    }

    fn dials(&self) -> usize {
        self.dials.load(Ordering::SeqCst)
    }
}

struct Rig {
    dir: tempfile::TempDir,
}

impl Rig {
    /// A garden whose config arms an (empty) v2 fleet, so the boot reconcile runs.
    fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let garden = dir.path().join("garden");
        std::fs::create_dir_all(garden.join("config")).unwrap();
        std::fs::create_dir_all(garden.join("growlight")).unwrap();
        std::fs::write(
            garden.join("config/growlight.toml"),
            "fleet_enabled = true\nqueue = \"v2\"\n",
        )
        .unwrap();
        std::fs::write(garden.join("growlight/protocol-fleet-v2.md"), "protocol\n").unwrap();
        for sub in ["home", "run", "state", "config"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        Rig { dir }
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("run/growlightd.sock")
    }

    /// Spawn the real binary with every XDG root inside the rig, so nothing
    /// reaches the user's runtime, state or config dirs.
    fn spawn(&self, keeperd: &Path) -> Daemon {
        let p = self.dir.path();
        Daemon(Command::new(env!("CARGO_BIN_EXE_softfig-growlightd"))
            .arg("--socket")
            .arg(self.socket())
            .arg("--keeperd-socket")
            .arg(keeperd)
            .arg("--garden-root")
            .arg(p.join("garden"))
            .env("HOME", p.join("home"))
            .env("XDG_RUNTIME_DIR", p.join("run"))
            .env("XDG_STATE_HOME", p.join("state"))
            .env("XDG_CONFIG_HOME", p.join("config"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap())
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < DEADLINE, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Kills the daemon it owns when the test ends, so a failed assertion never
/// leaves a growlightd running.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        kill(&mut self.0);
    }
}

#[test]
fn a_second_instance_exits_without_touching_the_socket_or_reconciling_and_a_later_start_succeeds() {
    let rig = Rig::new();
    let run = rig.dir.path().join("run");

    // The holder: up when its socket exists and its boot reconcile has dialled.
    let holder_keeperd = FakeKeeperd::start(run.join("holder-keeperd.sock"));
    let mut holder = rig.spawn(&holder_keeperd.path);
    wait_until("the holder's socket", || rig.socket().exists());
    wait_until("the holder's boot reconcile to dial keeperd", || holder_keeperd.dials() > 0);
    let inode = std::fs::metadata(rig.socket()).unwrap().ino();

    // The intruder.
    let intruder_keeperd = FakeKeeperd::start(run.join("intruder-keeperd.sock"));
    let mut intruder = rig.spawn(&intruder_keeperd.path);
    wait_until("the second instance to exit", || {
        intruder.0.try_wait().unwrap().is_some()
    });
    let status = intruder.0.wait().unwrap();
    assert!(!status.success(), "a second instance must exit non-zero, got {status}");

    let mut stderr = String::new();
    std::io::Read::read_to_string(intruder.0.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    assert!(
        stderr.contains(&rig.socket().display().to_string()),
        "the error names the socket: {stderr}"
    );
    assert!(
        stderr.contains(&holder.0.id().to_string()),
        "the error names the holder's pid {}: {stderr}",
        holder.0.id()
    );

    assert_eq!(
        std::fs::metadata(rig.socket()).unwrap().ino(),
        inode,
        "the live socket was unlinked and re-bound"
    );
    assert_eq!(
        intruder_keeperd.dials(),
        0,
        "the second instance reached the boot reconcile"
    );
    assert!(holder.0.try_wait().unwrap().is_none(), "the holder is still running");

    // The holder dies without cleaning up (SIGKILL): the kernel frees the lock,
    // so the next start needs no stale-pidfile handling.
    kill(&mut holder.0);
    let heir_keeperd = FakeKeeperd::start(run.join("heir-keeperd.sock"));
    let mut heir = rig.spawn(&heir_keeperd.path);
    wait_until("the next instance's boot reconcile to dial keeperd", || {
        heir_keeperd.dials() > 0
    });
    assert!(heir.0.try_wait().unwrap().is_none(), "the next instance is serving");
}
