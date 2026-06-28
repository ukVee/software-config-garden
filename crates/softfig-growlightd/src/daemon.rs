//! `Daemon` is the long-lived owner of growlightd's state — the bound socket,
//! the policy, and (in later phases) the agent fleet registry. Mirrors the
//! keeperd `Daemon`/`DaemonHandle` split: the accept loop hands `Arc`-shared
//! clones to each connection handler.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use thiserror::Error;

use softfig_ipc::growlightd::{Event, LeaseReply, RestartReply};

use crate::config::{GrowlightdConfig, Policy};
use crate::control::Control;
use crate::hub::EventHub;
use crate::leases::{LeaseDecision, LeaseTable, ReleaseOutcome, ThrashClear};
use crate::resume::{ItemResumer, ResumeOutcome};
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
    /// Supervisor-arbitrated leases over dangerous shared actions (spec §4c):
    /// the `request_lease`/`release_lease`/`request_restart` verbs grant/queue
    /// over this table. Pure decision logic lives in [`crate::leases`]; the
    /// daemon methods wire it thin (see [`Daemon::request_lease`]).
    pub leases: LeaseTable,
    /// The fleet config loaded at boot from `config/growlight.toml` (gate +
    /// roster). Stored regardless of the gate so `status` can report the
    /// configured fleet even when it is disarmed (no drive loop assembled).
    /// Defaults to [`FleetConfig::disabled`](crate::fleet::FleetConfig::disabled)
    /// until `main` sets it via [`Daemon::set_fleet_config`].
    pub fleet: crate::fleet::FleetConfig,
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
            leases: LeaseTable::new(),
            fleet: crate::fleet::FleetConfig::disabled(),
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
    /// The §4d rung-2 thrash hook, invoked when a lease is granted over a
    /// contended target. Lives *outside* `inner` (like `hub`) so it is called
    /// without the daemon lock held — the production impl reaches keeperd over
    /// the bus bridge and may block, so holding the mutex across it would
    /// reintroduce the keeperd deadlock class (incident 20260622). `None` until
    /// that bridge is wired (phase 6); a test installs a spy.
    pub thrash_clear: Option<Arc<dyn ThrashClear>>,
    /// The item-resume hook (`resume_item` verb, fleet-member-model slice 004):
    /// reads keeperd's backlog, guards on the current status, and flips a blocked
    /// item back to `queued`. Lives *outside* `inner` (like `thrash_clear`) so it
    /// is called WITHOUT the daemon lock — it reaches keeperd over the socket and
    /// may block, so holding the mutex across it would reintroduce the keeperd
    /// deadlock class (incident 20260622). `None` until `main` installs the live
    /// [`crate::resume::KeeperdItemResumer`]; a test installs a spy.
    pub resumer: Option<Arc<dyn ItemResumer>>,
}

impl Daemon {
    pub fn new(config: GrowlightdConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DaemonInner::new(config))),
            hub: EventHub::new(),
            thrash_clear: None,
            resumer: None,
        }
    }

    /// Install the §4d thrash-clear hook (builder-style). Phase 6 binds this to
    /// keeperd's `ThrashDetector::clear_flag` over the bus bridge; tests pass a
    /// spy to prove a granted lease over a flagged target clears that flag.
    pub fn with_thrash_clear(mut self, hook: Arc<dyn ThrashClear>) -> Self {
        self.thrash_clear = Some(hook);
        self
    }

    /// Install the item-resume hook (builder-style). `main` binds the live
    /// [`crate::resume::KeeperdItemResumer`] over the keeperd socket; a test
    /// installs a spy to drive the `resume_item` verb without a live keeperd.
    pub fn with_item_resumer(mut self, hook: Arc<dyn ItemResumer>) -> Self {
        self.resumer = Some(hook);
        self
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

    /// The garden root growlightd serves — derived from the keeperd `status`
    /// handshake at boot (never a literal). The fleet assembler reads it to anchor
    /// each agent's pre-approval (the `Edit`/`Write` garden-deny rules + the
    /// `protocol.md` the SessionStart hook injects). Brief-lock clone.
    pub fn garden_root(&self) -> PathBuf {
        self.inner.lock().unwrap().config.garden_root.clone()
    }

    /// Record the fleet config loaded at boot so `status` can report the gate +
    /// roster (config-in-garden slice 3). Set once in `main` after
    /// [`load_fleet_config`](crate::fleet::load_fleet_config), before the drive
    /// loop is spawned. Brief-lock store.
    pub fn set_fleet_config(&self, fleet: crate::fleet::FleetConfig) {
        self.inner.lock().unwrap().fleet = fleet;
    }

    /// The current runtime per-device [`Policy`] — the single source of truth the
    /// `set_policy` verb mutates, `status` echoes, and the drive loop refreshes
    /// its admission governor from each tick. Brief-lock read (`Policy` is `Copy`).
    pub fn policy(&self) -> Policy {
        self.inner.lock().unwrap().config.policy
    }

    /// Replace the runtime per-device [`Policy`] (the `set_policy` verb). The
    /// caller validates the value first ([`Policy::from_summary`]); this stores it
    /// under the daemon lock so `status` and the drive loop's next admission
    /// boundary both observe it (no restart).
    pub fn set_policy(&self, policy: Policy) {
        self.inner.lock().unwrap().config.policy = policy;
    }

    /// The per-device short-window TPM/RPM limits (spec §7 admission's second
    /// window). Static per-device config, read once by the fleet assembler to
    /// build the live [`crate::drive_loop::LiveRate`] source — not a `set_policy`
    /// /`status` wire knob in this slice. Brief-lock read (`RateLimits` is `Copy`).
    pub fn rate_limits(&self) -> crate::config::RateLimits {
        self.inner.lock().unwrap().config.rate_limits
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

    /// `request_lease` (spec §4c): arbitrate a lease over the shared resource
    /// `key` for `agent`. Free → granted; held by another → queued (FIFO); held
    /// by `agent` → idempotently granted. On a grant, any thrash flag keeper
    /// raised on the target is cleared (the §4d ladder rung 2) — OUTSIDE the
    /// daemon lock, since the hook may reach keeperd. Emits a `LeaseChanged`
    /// event either way.
    pub fn request_lease(&self, agent: &str, key: &str) -> LeaseReply {
        // Decide under the lock; release it before any side effect (the hook may
        // block on keeperd; the kill-safety lock-ordering lesson, §8).
        let decision = self.inner.lock().unwrap().leases.request(key, agent);
        match decision {
            LeaseDecision::Granted => {
                // §4d rung 2: a granted lease resolves the contention → clear the
                // thrash flag. Done lock-free; no-op until the bridge is wired.
                if let Some(hook) = &self.thrash_clear {
                    hook.clear_flag(key);
                }
                self.hub.publish(Event::LeaseChanged {
                    lease: key.to_string(),
                    holder: Some(agent.to_string()),
                    state: "granted".to_string(),
                });
                LeaseReply {
                    key: key.to_string(),
                    state: "granted".to_string(),
                    holder: Some(agent.to_string()),
                    position: None,
                    reason: None,
                }
            }
            LeaseDecision::Queued { position } => {
                let holder = self.inner.lock().unwrap().leases.holder(key).map(str::to_string);
                self.hub.publish(Event::LeaseChanged {
                    lease: key.to_string(),
                    holder: holder.clone(),
                    state: "waiting".to_string(),
                });
                LeaseReply {
                    key: key.to_string(),
                    state: "waiting".to_string(),
                    holder,
                    position: Some(position),
                    reason: None,
                }
            }
        }
    }

    /// `release_lease` (spec §4c): release the lease `key` held by `agent`,
    /// promoting the head waiter (if any) to holder. A release by a non-holder
    /// is refused (`state == "denied"`). Emits a `LeaseChanged` on a real
    /// release.
    pub fn release_lease(&self, agent: &str, key: &str) -> LeaseReply {
        let outcome = self.inner.lock().unwrap().leases.release(key, agent);
        match outcome {
            ReleaseOutcome::Released { next_holder } => {
                self.hub.publish(Event::LeaseChanged {
                    lease: key.to_string(),
                    holder: next_holder.clone(),
                    state: "released".to_string(),
                });
                LeaseReply {
                    key: key.to_string(),
                    state: "released".to_string(),
                    holder: next_holder,
                    position: None,
                    reason: None,
                }
            }
            ReleaseOutcome::NotHolder => LeaseReply {
                key: key.to_string(),
                state: "denied".to_string(),
                holder: self.inner.lock().unwrap().leases.holder(key).map(str::to_string),
                position: None,
                reason: Some("only the lease holder may release it".to_string()),
            },
        }
    }

    /// `request_restart` (spec §4c/§8): `requester` asks growlightd to restart
    /// `target`. Self-restart is denied (use `force_stop`). Otherwise the
    /// restart is arbitrated through a lease over the target: granted → the
    /// DAEMON performs the kill via [`Daemon::hard_kill_agent`] (the kill-safety
    /// path — child taken under the lock, SIGKILL outside it); already in flight
    /// → queued. Agents never kill each other — only the supervisor does.
    pub fn request_restart(&self, requester: &str, target: &str) -> RestartReply {
        if requester == target {
            return RestartReply {
                target: target.to_string(),
                state: "denied".to_string(),
                performed: false,
                reason: Some("an agent cannot restart itself — use force_stop".to_string()),
            };
        }
        let key = restart_key(target);
        let decision = self.inner.lock().unwrap().leases.request(&key, requester);
        match decision {
            LeaseDecision::Granted => {
                // DAEMON-executed restart, OUTSIDE the lock (hard_kill_agent
                // enforces the take-under-lock / kill-outside ordering itself).
                let performed = self.hard_kill_agent(target);
                self.hub.publish(Event::LeaseChanged {
                    lease: key,
                    holder: Some(requester.to_string()),
                    state: "granted".to_string(),
                });
                RestartReply {
                    target: target.to_string(),
                    state: "restarted".to_string(),
                    performed,
                    reason: None,
                }
            }
            LeaseDecision::Queued { .. } => RestartReply {
                target: target.to_string(),
                state: "queued".to_string(),
                performed: false,
                reason: Some("a restart of this agent is already in flight".to_string()),
            },
        }
    }

    /// `resume_item` (fleet-member-model slice 004): un-block a human-parked
    /// backlog item (`blocked → queued`) so the scheduler re-picks it — the
    /// inverse of the drive loop's item-park. Delegates to the installed
    /// [`ItemResumer`] hook (the live [`crate::resume::KeeperdItemResumer`] reads
    /// keeperd's backlog, guards on the current status, and writes `queued`),
    /// called WITHOUT the daemon lock since it reaches keeperd and may block.
    /// Returns the typed [`ResumeOutcome`]; the server maps it to the wire reply /
    /// a guard error. With no hook installed (no keeperd binding) the un-park is
    /// unavailable, reported as [`ResumeOutcome::Unreachable`].
    pub fn resume_item(&self, item: &str, queue: Option<&str>) -> ResumeOutcome {
        match &self.resumer {
            Some(hook) => hook.resume_item(item, queue),
            None => ResumeOutcome::Unreachable {
                reason: "item-resume is not wired (growlightd has no keeperd binding)".to_string(),
            },
        }
    }
}

/// The lease key a restart is arbitrated under — namespaced so it never collides
/// with a garden-target lease key. Held by the requester from grant until the
/// restart settles (released via `release_lease`, or the agent's phase-6
/// re-registration), so a concurrent second `request_restart` of the same target
/// queues rather than double-killing.
fn restart_key(target: &str) -> String {
    format!("restart:{target}")
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

    /// A fake child that just records that it was killed — enough to prove the
    /// restart was DAEMON-executed (the lock-safety is covered by `SpyChild`).
    #[derive(Debug)]
    struct RecordingChild {
        killed: Arc<AtomicBool>,
    }
    impl AgentChild for RecordingChild {
        fn kill(&self) {
            self.killed.store(true, Ordering::SeqCst);
        }
    }

    /// A spy thrash hook recording the keys it was asked to clear.
    #[derive(Debug, Default)]
    struct SpyThrashClear {
        cleared: Mutex<Vec<String>>,
    }
    impl ThrashClear for SpyThrashClear {
        fn clear_flag(&self, key: &str) -> bool {
            self.cleared.lock().unwrap().push(key.to_string());
            true
        }
    }

    #[test]
    fn request_restart_is_performed_by_the_daemon_not_the_caller() {
        let daemon = test_daemon();
        let killed = Arc::new(AtomicBool::new(false));
        // The fleet (phase 6) would register the target's real child; here a fake.
        daemon.inner.lock().unwrap().control.attach_child(
            "b",
            Box::new(RecordingChild {
                killed: Arc::clone(&killed),
            }),
        );

        let reply = daemon.request_restart("a", "b");
        assert_eq!(reply.state, "restarted");
        assert!(reply.performed, "a live child was present and killed");
        assert!(killed.load(Ordering::SeqCst), "the DAEMON killed the target");
        // The restart is in flight (lease held by the requester), so a second
        // request for the same target queues rather than double-killing.
        let again = daemon.request_restart("c", "b");
        assert_eq!(again.state, "queued");
        assert!(!again.performed);
    }

    #[test]
    fn request_restart_of_self_is_denied() {
        let daemon = test_daemon();
        let reply = daemon.request_restart("a", "a");
        assert_eq!(reply.state, "denied");
        assert!(!reply.performed);
        assert!(reply.reason.unwrap().contains("itself"));
    }

    #[test]
    fn restart_with_no_live_child_still_arbitrates_but_kills_nothing() {
        let daemon = test_daemon();
        // No child registered for "b" (production today): the lease is granted and
        // the restart is "performed" as a no-op kill — the arbitration still ran.
        let reply = daemon.request_restart("a", "b");
        assert_eq!(reply.state, "restarted");
        assert!(!reply.performed, "nothing live to kill");
    }

    #[test]
    fn a_granted_lease_clears_the_thrash_flag_a_queued_one_does_not() {
        let spy = Arc::new(SpyThrashClear::default());
        let daemon = test_daemon().with_thrash_clear(Arc::clone(&spy) as Arc<dyn ThrashClear>);
        let key = "dock.rs §Layout";

        // Grant → the §4d rung-2 hook fires for this target.
        let granted = daemon.request_lease("a", key);
        assert_eq!(granted.state, "granted");
        assert_eq!(granted.holder.as_deref(), Some("a"));
        assert_eq!(*spy.cleared.lock().unwrap(), vec![key.to_string()]);

        // A second agent is queued, NOT granted — so the flag hook does not fire
        // again (only the agent that won the lease resolves the contention).
        let queued = daemon.request_lease("b", key);
        assert_eq!(queued.state, "waiting");
        assert_eq!(queued.position, Some(1));
        assert_eq!(queued.holder.as_deref(), Some("a"), "the holder is reported");
        assert_eq!(
            spy.cleared.lock().unwrap().len(),
            1,
            "a queued request clears nothing new",
        );
    }

    #[test]
    fn release_through_the_daemon_promotes_the_waiter_then_frees_the_key() {
        let daemon = test_daemon();
        let key = "shared.rs";
        assert_eq!(daemon.request_lease("a", key).state, "granted");
        assert_eq!(daemon.request_lease("b", key).state, "waiting");

        // a releases → b is promoted to holder.
        let rel = daemon.release_lease("a", key);
        assert_eq!(rel.state, "released");
        assert_eq!(rel.holder.as_deref(), Some("b"));

        // A non-holder release is denied and changes nothing.
        let denied = daemon.release_lease("a", key);
        assert_eq!(denied.state, "denied");
        assert_eq!(denied.holder.as_deref(), Some("b"), "b still holds it");

        // b releases the last claim → the key is free again.
        let freed = daemon.release_lease("b", key);
        assert_eq!(freed.state, "released");
        assert_eq!(freed.holder, None);
        assert!(!daemon.inner.lock().unwrap().leases.is_held(key));
    }
}
