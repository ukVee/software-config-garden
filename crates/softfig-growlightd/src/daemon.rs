//! `Daemon` is the long-lived owner of growlightd's state — the bound socket,
//! the policy, and (in later phases) the agent fleet registry. Mirrors the
//! keeperd `Daemon`/`DaemonHandle` split: the accept loop hands `Arc`-shared
//! clones to each connection handler.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use thiserror::Error;

use crate::config::GrowlightdConfig;
use crate::control::Control;
use crate::hub::EventHub;
use crate::state::State;

#[derive(Debug, Error)]
pub enum GrowlightdError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, GrowlightdError>;

#[derive(Debug)]
pub struct DaemonInner {
    pub state: State,
    pub config: GrowlightdConfig,
    /// Fleet/agent control intent the control verbs set and the drive loop reads
    /// at safe handoff boundaries (spec §8 / §13 Control). Phase 1 holds no live
    /// agent — see [`crate::control`].
    pub control: Control,
    // Phase 6 (concurrency milestone) adds the agent registry here: the live
    // `claude -p` child handles + per-agent status, registered via
    // `control.attach_child`. Hard-stop teardown of those children rides the
    // same kill-safety discipline as keeperd's FUSE/commit path (spec §8) — a
    // clean per-agent SIGKILL is safe because each agent's keeperd writes
    // already commit from an in-memory snapshot, never mid-walk.
}

impl DaemonInner {
    pub fn new(config: GrowlightdConfig) -> Self {
        Self {
            state: State::Running,
            config,
            control: Control::default(),
        }
    }
}

/// Thread-safe handle the accept loop and (future) supervisor both share.
#[derive(Debug, Clone)]
pub struct Daemon {
    pub inner: Arc<Mutex<DaemonInner>>,
    /// The event hub backing `subscribe`. Lives *outside* `inner` so a producer
    /// never has to take the daemon lock to publish — and so `publish` can't
    /// contend with anything holding `inner` (the hub has its own brief lock).
    pub hub: EventHub,
}

impl Daemon {
    pub fn new(config: GrowlightdConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DaemonInner::new(config))),
            hub: EventHub::new(),
        }
    }

    /// Bind the socket and run the accept loop. Returns a handle that stays
    /// live until [`DaemonHandle::shutdown`] is called.
    pub fn start(self) -> Result<DaemonHandle> {
        crate::server::start(self)
    }

    pub fn state(&self) -> State {
        self.inner.lock().unwrap().state
    }

    pub fn socket_path(&self) -> PathBuf {
        self.inner.lock().unwrap().config.socket_path.clone()
    }

    /// Graceful teardown shared by every shutdown trigger — the IPC `shutdown`
    /// op, a caught SIGTERM/SIGINT, and [`DaemonHandle`]'s `Drop`. Marks the
    /// daemon `Stopping`; the accept loop notices on its next poll and exits.
    ///
    /// Phase 6 hooks fleet teardown in here: take the child handles out under
    /// the lock, release it, then SIGKILL them outside the lock (never hold the
    /// mutex across a blocking child wait — the lock-ordering lesson from
    /// keeperd's `request_shutdown`). The hard-kill is safe per spec §8 because
    /// each agent's garden writes commit from an in-memory snapshot. Idempotent.
    pub fn request_shutdown(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.state = State::Stopping;
    }

    /// Hard-kill one agent (`force_stop` `hard_kill` / the urgent
    /// interrupt-and-reroll, spec §8) under the kill-safety discipline.
    ///
    /// The ordering is the load-bearing contract (keeperd incident 20260622): the
    /// child handle is taken OUT of the control map **under** the daemon lock,
    /// the lock is released, and only THEN is the (potentially blocking) kill run
    /// — never while holding the mutex. The same lesson behind keeperd's
    /// `force_release_mount` and commit-from-memory. The kill is safe per spec §8
    /// because each agent's garden writes commit from an in-memory snapshot, so a
    /// SIGKILL can never corrupt the garden mid-commit.
    ///
    /// Returns `true` if a live child was present and killed. Phase 1 has no real
    /// children, so this is `false` in production — but the safety *structure* is
    /// in place and proven against a fake child in this crate's tests.
    pub fn hard_kill_agent(&self, agent: &str) -> bool {
        // Take the handle out UNDER the lock; the guard is a temporary that drops
        // at the end of this statement, so the lock is released before `kill`.
        let child = self.inner.lock().unwrap().control.take_child(agent);
        // OUTSIDE the lock: run the (possibly blocking) kill.
        match child {
            Some(child) => {
                child.kill();
                true
            }
            None => false,
        }
    }

    /// Drive-loop boundary accessor: read **and clear** an agent's pending stop
    /// intent at a handoff. Honoured exactly once (spec §8 boundary semantics).
    pub fn take_pending_stop(
        &self,
        agent: &str,
    ) -> Option<softfig_ipc::growlightd::StopLevel> {
        self.inner.lock().unwrap().control.take_pending_stop(agent)
    }

    /// Drive-loop boundary accessor: drain an agent's inject lane, delivering its
    /// queued messages at the agent's next baton (spec §8 boundary-async).
    pub fn drain_inject_lane(&self, agent: &str) -> Vec<String> {
        self.inner.lock().unwrap().control.drain_inject_lane(agent)
    }

    /// Whether the fleet admission gate is engaged (`pause`/`resume`).
    pub fn is_paused(&self) -> bool {
        self.inner.lock().unwrap().control.paused
    }
}

/// Handle to a running daemon. Owns the accept-thread join handle and the bound
/// socket path so it can clean up on drop.
#[derive(Debug)]
pub struct DaemonHandle {
    pub daemon: Daemon,
    pub thread: Option<JoinHandle<Result<()>>>,
    pub socket_path: PathBuf,
}

impl DaemonHandle {
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Request orderly shutdown: the accept loop notices `Stopping` on its next
    /// poll iteration and exits.
    pub fn shutdown(&self) {
        self.daemon.request_shutdown();
    }

    /// Block until the accept loop exits. Returns its result.
    pub fn join(mut self) -> Result<()> {
        if let Some(t) = self.thread.take() {
            t.join()
                .map_err(|_| GrowlightdError::Other("accept thread panicked".into()))?
        } else {
            Ok(())
        }
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        // Best-effort cleanup if the caller forgot to shutdown.
        self.shutdown();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::AgentChild;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Weak;

    fn test_daemon() -> Daemon {
        Daemon::new(GrowlightdConfig::new("/run/g.sock".into(), "/garden".into()))
    }

    /// A fake agent child that, when killed, checks whether the daemon lock was
    /// free at the moment of the kill — the safety contract `hard_kill_agent`
    /// must uphold (take the handle under the lock, kill OUTSIDE it).
    #[derive(Debug)]
    struct SpyChild {
        inner: Weak<Mutex<DaemonInner>>,
        killed: Arc<AtomicBool>,
        killed_lock_free: Arc<AtomicBool>,
    }

    impl AgentChild for SpyChild {
        fn kill(&self) {
            // `try_lock` succeeds only if no one holds the daemon lock. A
            // non-reentrant std `Mutex` returns `WouldBlock` if THIS thread still
            // held it — which is exactly the violation we want to catch.
            let lock_free = self
                .inner
                .upgrade()
                .map(|m| m.try_lock().is_ok())
                .unwrap_or(true);
            self.killed_lock_free.store(lock_free, Ordering::SeqCst);
            self.killed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn hard_kill_takes_the_child_under_the_lock_and_kills_outside_it() {
        let daemon = test_daemon();
        let killed = Arc::new(AtomicBool::new(false));
        let killed_lock_free = Arc::new(AtomicBool::new(false));

        // Plant a spy child for "a1" (the phase-6 fleet would register a real one).
        daemon.inner.lock().unwrap().control.attach_child(
            "a1",
            Box::new(SpyChild {
                inner: Arc::downgrade(&daemon.inner),
                killed: Arc::clone(&killed),
                killed_lock_free: Arc::clone(&killed_lock_free),
            }),
        );

        assert!(daemon.hard_kill_agent("a1"), "a live child was present + killed");
        assert!(killed.load(Ordering::SeqCst), "the child was actually killed");
        assert!(
            killed_lock_free.load(Ordering::SeqCst),
            "the kill ran OUTSIDE the daemon lock (kill-safety contract)",
        );

        // The handle is gone now — a second hard-kill finds nothing.
        assert!(!daemon.hard_kill_agent("a1"), "child only killed once");
    }

    #[test]
    fn hard_kill_on_an_agent_with_no_child_is_a_safe_no_op() {
        let daemon = test_daemon();
        assert!(!daemon.hard_kill_agent("nobody"), "nothing to kill, no panic");
    }

    #[test]
    fn boundary_accessors_reach_the_control_state() {
        use softfig_ipc::growlightd::StopLevel;
        let daemon = test_daemon();
        assert!(!daemon.is_paused());

        daemon.inner.lock().unwrap().control.pause();
        assert!(daemon.is_paused());

        daemon
            .inner
            .lock()
            .unwrap()
            .control
            .request_stop("a1", StopLevel::AfterIteration);
        assert_eq!(daemon.take_pending_stop("a1"), Some(StopLevel::AfterIteration));
        assert_eq!(daemon.take_pending_stop("a1"), None, "honoured once");

        daemon
            .inner
            .lock()
            .unwrap()
            .control
            .queue_inject("a1", "ping".into());
        assert_eq!(daemon.drain_inject_lane("a1"), vec!["ping".to_string()]);
        assert!(daemon.drain_inject_lane("a1").is_empty());
    }
}
