//! Control intent — the fleet/agent state the control verbs (`pause`,
//! `resume`, `stop_after_slice`, `force_stop`, `inject_message`) set and the
//! drive loop reads at safe handoff boundaries (spec §8 / §13 Control). This
//! models the *boundary* control state:
//!
//! - `paused` is a fleet-wide admission-gate placeholder — flipped now, read by
//!   the scheduler later.
//! - `pending_stop` is a boundary intent (only `AfterSlice`/`AfterIteration` —
//!   never `HardKill`, which acts immediately). The drive loop calls
//!   [`Control::take_pending_stop`] at a handoff to honour it once.
//! - the inject lane is boundary-async: [`Control::queue_inject`] appends,
//!   [`Control::drain_inject_lane`] delivers at the next baton. There is no
//!   native mid-session injection (spec §8), so a queued message is invisible
//!   until the boundary drain — exactly the timing the tests assert.
//!
//! The one control action that acts *immediately* is the hard kill — but the
//! live children it targets are NOT held here. A running fleet's kill handles
//! live in the daemon's [`crate::daemon::Daemon::kill_handles`] registry, which
//! the live backend ([`crate::claude_backend::ClaudeBackend`]) populates on
//! every spawn (mirroring `live_scopes`) and the per-agent reader thread drains
//! on exit — so `force_stop --hard-kill` / `request_restart` reach the agents
//! the supervisor is actually running. (An earlier design parked a per-agent
//! child handle in `Control`, but only tests ever filled it, so for every real
//! agent the kill was a silent no-op — the audit-005 finding. The handle moved
//! to the daemon registry the fleet truly uses.)
//!
//! This module still owns the kill *abstractions* that registry stores: the
//! [`AgentChild`] handle trait and the [`LiveKill`] registry entry. The kill's
//! safety contract lives in [`crate::daemon::Daemon::hard_kill_agent`]: the
//! handle comes OUT under the registry lock, then [`AgentChild::kill`] runs
//! OUTSIDE the lock — the keeperd `force_release_mount` / commit-from-memory
//! discipline (incident 20260622).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use softfig_ipc::growlightd::StopLevel;

/// A live agent's forcibly-killable process handle.
///
/// Implemented over a real `claude -p` child by
/// [`crate::claude_backend::ClaudeChild`] (a scope-cgroup SIGKILL + controller
/// reap). The live backend stores one in the daemon's
/// [`crate::daemon::Daemon::kill_handles`] registry on every spawn, so the
/// hard-kill path reaches the agent the supervisor is actually running.
///
/// `kill` MUST be invoked with no registry lock held — it may block (a real
/// SIGKILL waits on the child to reap), and holding the mutex across that is the
/// exact deadlock keeperd hit on the FUSE/commit path (incident 20260622). It
/// takes `&self` and is idempotent / best-effort, so an already-exited child (or
/// a second kill) is a harmless no-op.
pub trait AgentChild: Send + fmt::Debug {
    /// Forcibly terminate the child. Called OUTSIDE the registry lock.
    fn kill(&self);
}

/// One live agent's entry in the daemon's hard-kill registry
/// ([`crate::daemon::Daemon::kill_handles`]): its forcibly-killable
/// [`AgentChild`] handle plus the unique per-spawn `scope_token` that guards
/// stale removal.
///
/// The registry is keyed by agent id, and a re-roll **overwrites** the entry
/// (latest spawn wins — a hard kill always targets the agent's *current* child).
/// The exiting child's reader thread removes its own entry only while the stored
/// `scope_token` still matches its generation, so a re-roll's newer handle is
/// never clobbered by an older generation's late exit — the same guard
/// `live_scopes` already uses (the token IS the `.scope` unit in production).
#[derive(Debug)]
pub struct LiveKill {
    /// The unique per-spawn token (the `.scope` unit name in production) that
    /// guards stale removal: the reader removes its entry only if this still
    /// matches, so a re-roll's newer handle survives an older one's late exit.
    pub scope_token: String,
    /// The forcibly-killable handle. Taken OUT of the registry under its lock by
    /// [`crate::daemon::Daemon::hard_kill_agent`], then `kill`ed OUTSIDE the lock.
    pub child: Box<dyn AgentChild>,
}

impl LiveKill {
    /// A registry entry pairing `child` with the `scope_token` that guards its
    /// stale removal.
    pub fn new(scope_token: impl Into<String>, child: Box<dyn AgentChild>) -> Self {
        Self {
            scope_token: scope_token.into(),
            child,
        }
    }
}

/// Per-agent control intent. Phase 1: no live agent stands behind a key — these
/// are the knobs the future drive loop reads at a handoff boundary.
#[derive(Debug, Default)]
pub struct AgentControl {
    /// Pending graceful-stop boundary, read once at the next handoff.
    ///
    /// Invariant: only ever `Some(AfterSlice)` / `Some(AfterIteration)` —
    /// `HardKill` is not a boundary intent (it acts immediately and is never
    /// stored). `None` = keep running.
    pending_stop: Option<StopLevel>,
    /// Boundary-async inject lane (FIFO): messages delivered at the agent's
    /// next baton, never mid-iteration (spec §8).
    inject_lane: VecDeque<String>,
}

/// growlightd's control state: the fleet admission gate plus per-agent intent.
/// Owned by `DaemonInner` (behind the daemon mutex).
#[derive(Debug, Default)]
pub struct Control {
    /// Fleet-wide admission gate (spec §7/§8). When `true`, the future
    /// scheduler admits no new/rolling agents. Phase 1: recorded + surfaced in
    /// `status`, with no fleet yet to gate.
    pub paused: bool,
    /// Per-agent intent, keyed by agent (work-stream) id. `BTreeMap` for stable
    /// ordering in any future `status`/roster rendering.
    agents: BTreeMap<String, AgentControl>,
}

impl Control {
    /// Engage the admission gate (`pause`). Idempotent; returns the new state.
    pub fn pause(&mut self) -> bool {
        self.paused = true;
        self.paused
    }

    /// Clear the admission gate (`resume`). Idempotent; returns the new state.
    pub fn resume(&mut self) -> bool {
        self.paused = false;
        self.paused
    }

    /// Record a graceful-stop boundary intent for `agent` (`stop_after_slice` /
    /// `force_stop` with a boundary level). The drive loop honours it once via
    /// [`Control::take_pending_stop`] at the next handoff.
    ///
    /// Panics in debug builds if handed `HardKill` — that is acted on
    /// immediately by the daemon's hard-kill path, never recorded here.
    pub fn request_stop(&mut self, agent: &str, level: StopLevel) {
        debug_assert!(
            !level.is_immediate(),
            "HardKill acts immediately and is never stored as a boundary intent",
        );
        self.agents.entry(agent.to_string()).or_default().pending_stop = Some(level);
    }

    /// Queue a message onto `agent`'s boundary-async inject lane. Returns the
    /// lane depth after the append (the `queued` count the verb replies with).
    pub fn queue_inject(&mut self, agent: &str, message: String) -> usize {
        let lane = &mut self.agents.entry(agent.to_string()).or_default().inject_lane;
        lane.push_back(message);
        lane.len()
    }

    // --- Drive-loop boundary accessors. These are what a handoff boundary
    // calls; they read-and-clear, so an intent is honoured exactly once. ---

    /// Read **and clear** `agent`'s pending stop intent. Returns `None` if there
    /// was none (or it was already honoured). The drive loop calls this at a
    /// handoff boundary, NOT mid-iteration.
    pub fn take_pending_stop(&mut self, agent: &str) -> Option<StopLevel> {
        self.agents
            .get_mut(agent)
            .and_then(|a| a.pending_stop.take())
    }

    /// Drain `agent`'s inject lane in FIFO order, delivering the queued messages
    /// at the agent's next baton (spec §8 boundary-async). Returns the messages
    /// and leaves the lane empty; a second drain returns nothing.
    pub fn drain_inject_lane(&mut self, agent: &str) -> Vec<String> {
        match self.agents.get_mut(agent) {
            Some(a) => a.inject_lane.drain(..).collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_and_resume_toggle_the_gate() {
        let mut c = Control::default();
        assert!(!c.paused);
        assert!(c.pause());
        assert!(c.paused);
        assert!(c.pause(), "pause is idempotent");
        assert!(!c.resume());
        assert!(!c.paused);
        assert!(!c.resume(), "resume is idempotent");
    }

    #[test]
    fn a_stop_intent_is_honoured_exactly_once_at_the_boundary() {
        let mut c = Control::default();
        assert_eq!(c.take_pending_stop("a1"), None, "nothing pending initially");

        c.request_stop("a1", StopLevel::AfterSlice);
        // Boundary read returns it once...
        assert_eq!(c.take_pending_stop("a1"), Some(StopLevel::AfterSlice));
        // ...and a second boundary read sees it already honoured.
        assert_eq!(c.take_pending_stop("a1"), None);
    }

    #[test]
    fn a_later_stop_request_overrides_an_unread_one() {
        let mut c = Control::default();
        c.request_stop("a1", StopLevel::AfterSlice);
        c.request_stop("a1", StopLevel::AfterIteration);
        assert_eq!(c.take_pending_stop("a1"), Some(StopLevel::AfterIteration));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "HardKill acts immediately")]
    fn storing_hard_kill_as_a_boundary_intent_is_a_bug() {
        Control::default().request_stop("a1", StopLevel::HardKill);
    }

    #[test]
    fn the_inject_lane_is_fifo_and_drains_at_the_boundary() {
        let mut c = Control::default();
        assert_eq!(c.queue_inject("a1", "first".into()), 1);
        assert_eq!(c.queue_inject("a1", "second".into()), 2, "lane depth grows");

        // Boundary-async: the only way to see queued messages is the boundary
        // drain — they are NOT delivered mid-iteration.
        assert_eq!(c.drain_inject_lane("a1"), vec!["first", "second"]);
        // Delivered once: a second drain at the next boundary is empty.
        assert!(c.drain_inject_lane("a1").is_empty());
    }

    #[test]
    fn unknown_agents_drain_and_take_to_nothing() {
        let mut c = Control::default();
        assert!(c.drain_inject_lane("ghost").is_empty());
        assert_eq!(c.take_pending_stop("ghost"), None);
    }

    #[test]
    fn live_kill_pairs_a_child_with_its_stale_removal_token() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        #[derive(Debug)]
        struct Noop {
            killed: Arc<AtomicBool>,
        }
        impl AgentChild for Noop {
            fn kill(&self) {
                self.killed.store(true, Ordering::SeqCst);
            }
        }

        let killed = Arc::new(AtomicBool::new(false));
        let entry = LiveKill::new(
            "growlight-agent-a1-3.scope",
            Box::new(Noop {
                killed: Arc::clone(&killed),
            }),
        );
        assert_eq!(entry.scope_token, "growlight-agent-a1-3.scope");
        // The handle the daemon's hard-kill path takes out + kills.
        entry.child.kill();
        assert!(killed.load(Ordering::SeqCst));
    }
}
