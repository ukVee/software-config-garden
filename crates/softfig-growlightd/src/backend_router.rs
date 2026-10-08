//! Per-member backend routing (opencode-fleet-backend slice 005).
//!
//! Until this slice the fleet had exactly one backend: [`assemble_fleet`] built a
//! single `Arc<ClaudeBackend>` and cloned it into all five seams, so "which member
//! runs on what" was not a question anyone could ask. With a second backend built
//! (slice 004) it becomes the central one, and the answer has to reach five places
//! that were written assuming there is only one.
//!
//! ## Why a router rather than per-member plumbing
//!
//! The alternative was to thread a backend through [`Supervisor`] and
//! [`DriveLoop`] per member. That spreads the plurality across the whole control
//! plane — every seam grows an agent-keyed map, and `DriveLoop::new`'s contract
//! (one backend, cloned into the seams it fills) breaks for everyone. Routing
//! instead keeps the plurality in ONE type: the control plane still holds a single
//! backend-shaped thing, and the dispatch happens where the agent id is already in
//! hand. Every seam the loop consumes is agent-keyed already
//! (`spawn(spec)`/`health(agent)`/`stderr_tail(agent)`/`budget(agent)`), so the id
//! needed to route is always present — the one exception is the rate meter, which
//! is fleet-wide by definition and therefore sums (see [`BackendRouter::distinct`]).
//!
//! ## The two invariants
//!
//! 1. **One member, one backend, every seam.** Health, stderr, budget and spawn all
//!    dispatch through the same [`BackendRouter::backend_for`], so a member cannot
//!    be spawned on one backend and observed on another.
//! 2. **Sum each backend once.** Several claude members share ONE `ClaudeBackend`
//!    (its per-agent cells already separate them), so the fleet-wide rate window
//!    must fold over the DISTINCT backends — folding over members would count a
//!    shared backend's whole fleet window once per member it serves.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::Arc;

use crate::admission::BudgetUsage;
use crate::agent_harness::sum_rate_windows;
use crate::claude_backend::ClaudeBackend;
use crate::control::AgentChild;
use crate::drive_loop::{AgentHealthSource, AgentStderrSource, BudgetSampleSource, RateMeter};
use crate::opencode_backend::{AgentSpend, OpencodeBackend};
use crate::preapproval::AgentPaths;
use crate::supervisor::{AgentBackend, AgentHealth, AgentSpec, SpawnError};

/// One member's live backend. The runtime counterpart of the configured
/// [`MemberBackend`](crate::fleet::MemberBackend): that one says what the operator
/// asked for, this one is the constructed object serving it.
///
/// Cheap to clone (an `Arc` bump) — the router holds one per member plus one per
/// distinct backend, and cloning is how a shared claude backend reaches several
/// members without being rebuilt.
#[derive(Debug, Clone)]
pub enum BackendHandle {
    /// The `claude -p` backend. Normally ONE instance shared by every claude
    /// member (its per-agent cells keep them apart), exactly as before slice 005.
    Claude(Arc<ClaudeBackend>),
    /// An `opencode run` backend. One instance PER MEMBER, because the model and
    /// variant a member runs on live in that backend's
    /// [`OpencodeLaunch`](crate::opencode_backend::OpencodeLaunch) — two members on
    /// different models are two backends, not one backend consulted twice.
    Opencode(Arc<OpencodeBackend>),
}

impl BackendHandle {
    /// Whether `self` and `other` are the SAME constructed backend (pointer
    /// identity, not equality of configuration). This is what makes
    /// [`BackendRouter::distinct`] a set: two members sharing one claude backend
    /// must fold its fleet-wide rate window once, and two opencode members on the
    /// same model string are still two backends with two sets of cells.
    fn is_same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Claude(a), Self::Claude(b)) => Arc::ptr_eq(a, b),
            (Self::Opencode(a), Self::Opencode(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    /// Spawn `spec`'s agent on this backend.
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        match self {
            Self::Claude(b) => b.spawn(spec),
            Self::Opencode(b) => b.spawn(spec),
        }
    }

    /// `agent`'s health on this backend, or `None` if it never spawned it.
    fn health(&self, agent: &str) -> Option<AgentHealth> {
        match self {
            Self::Claude(b) => b.health(agent),
            Self::Opencode(b) => b.health(agent),
        }
    }

    /// `agent`'s stderr tail on this backend (empty if it never spawned it).
    fn stderr_tail(&self, agent: &str) -> Vec<String> {
        match self {
            Self::Claude(b) => b.stderr_tail(agent),
            Self::Opencode(b) => b.stderr_tail(agent),
        }
    }

    /// `agent`'s latest reading of the **Anthropic** account pool. Structurally
    /// `None` for opencode — a metered DeepSeek run has no 5h/7d subscription
    /// window and synthesising one would corrupt the gate governing the claude
    /// members (the milestone's locked decision, [`OpencodeBackend::budget`]).
    fn budget(&self, agent: &str) -> Option<BudgetUsage> {
        match self {
            Self::Claude(b) => b.budget(agent),
            Self::Opencode(b) => b.budget(agent),
        }
    }

    /// The instant admission may re-probe `agent`'s rate-limit window; `None` for
    /// opencode, which emits no `rate_limit_event` at all.
    fn rate_limit_reopen(&self, agent: &str) -> Option<i64> {
        match self {
            Self::Claude(b) => b.rate_limit_reopen(agent),
            Self::Opencode(b) => b.rate_limit_reopen(agent),
        }
    }

    /// `agent`'s accumulated metered spend on this backend, or [`None`] when this
    /// backend is not metered.
    ///
    /// The exact mirror of [`budget`](Self::budget), which is structurally `None`
    /// for opencode: the two providers are accounted differently, and each seam
    /// answers `None` for the provider the seam does not describe. A claude member
    /// draws on the Anthropic *subscription* pool — its cost is the shared 5h/7d
    /// reserve that `budget` reports, so there is no per-member dollar figure to
    /// return and inventing a `0` would read as "metered, spent nothing" rather
    /// than the truth, "not metered". An opencode member is the converse: metered
    /// per step, contributing nothing to that reserve.
    fn spend(&self, agent: &str) -> Option<AgentSpend> {
        match self {
            Self::Claude(_) => None,
            Self::Opencode(b) => Some(b.spend(agent)),
        }
    }

    /// This backend's fleet-wide rolling-minute window at `now`.
    fn rate_used(&self, now: i64) -> (u32, u32) {
        match self {
            Self::Claude(b) => b.rate_used(now),
            Self::Opencode(b) => b.rate_used(now),
        }
    }

    /// The argv `agent` would be exec'd with on this backend (after the
    /// `systemd-run … --` separator). The routing assertion: a member's backend is
    /// only *really* the one the operator asked for if this is that backend's
    /// command line.
    fn command_argv(&self, agent: &str, paths: &AgentPaths) -> Vec<OsString> {
        match self {
            Self::Claude(b) => b.command_argv(agent, paths),
            Self::Opencode(b) => b.command_argv(agent, paths),
        }
    }
}

/// The fleet's agent-id → backend routing table: one backend-shaped thing the
/// control plane holds, dispatching each agent-keyed call to that member's own
/// backend.
///
/// Fail-closed on an unknown agent: a spawn is an `Err` (never a silent spawn on
/// the wrong backend), and every read seam answers "nothing observed" rather than
/// another member's reading. That case means the roster and the router disagree,
/// which assembly makes impossible — both are built from the same
/// `fleet.members` — so it is a structural guard, not an expected path.
#[derive(Debug, Default)]
pub struct BackendRouter {
    /// agent id → the backend serving it.
    by_agent: BTreeMap<String, BackendHandle>,
    /// Every DISTINCT backend, each exactly once (invariant 2 in the module docs).
    distinct: Vec<BackendHandle>,
}

impl BackendRouter {
    /// An empty router — no members, no backends. [`insert`](Self::insert) fills it
    /// in roster order.
    pub fn new() -> Self {
        Self::default()
    }

    /// Route `agent` to `backend`. Re-inserting the same id replaces its route (the
    /// config layer rejects duplicate ids, so assembly never does).
    pub fn insert(&mut self, agent: impl Into<String>, backend: BackendHandle) {
        if !self.distinct.iter().any(|b| b.is_same(&backend)) {
            self.distinct.push(backend.clone());
        }
        self.by_agent.insert(agent.into(), backend);
    }

    /// The backend serving `agent`, or `None` if it is not in the roster.
    pub fn backend_for(&self, agent: &str) -> Option<&BackendHandle> {
        self.by_agent.get(agent)
    }

    /// Every distinct backend, each appearing once regardless of how many members
    /// it serves — what the fleet-wide rate window folds over.
    pub fn distinct(&self) -> &[BackendHandle] {
        &self.distinct
    }

    /// The argv `agent` would be exec'd with, or `None` if it is not in the roster.
    /// The observation the assembly tests assert routing through — it names a
    /// backend without spawning one.
    pub fn command_argv(&self, agent: &str, paths: &AgentPaths) -> Option<Vec<OsString>> {
        self.backend_for(agent).map(|b| b.command_argv(agent, paths))
    }

    /// `agent`'s accumulated metered spend, or [`None`] when its backend is not
    /// metered (claude) *or* it is not in the roster at all.
    ///
    /// Both of those are `None` on purpose and the surface treats them alike: an
    /// unrouted agent is the same fail-closed posture every other read seam here
    /// takes (never another member's reading), and "no metered spend" is precisely
    /// what the status surface needs in order to show a reserve-pool member as a
    /// reserve-pool member instead of a $0.00 metered one. Nothing downstream
    /// needs to tell the two apart — a row is only built for a roster member, so
    /// the unrouted case cannot reach a render.
    pub fn spend(&self, agent: &str) -> Option<AgentSpend> {
        self.backend_for(agent).and_then(|b| b.spend(agent))
    }
}

impl RateMeter for BackendRouter {
    fn rate_used(&self, now: i64) -> (u32, u32) {
        // Over `distinct`, NOT `by_agent`: each backend's window is already
        // fleet-wide across ITS members, so folding per member would count a shared
        // claude backend's whole window once per member it serves. Reuses the
        // harness's saturating fold so a mixed roster saturates exactly as a
        // single-backend one does.
        sum_rate_windows(self.distinct.iter().map(|b| {
            let (t, r) = b.rate_used(now);
            (u64::from(t), u64::from(r))
        }))
    }
}

impl AgentBackend for Arc<BackendRouter> {
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        match self.backend_for(&spec.agent) {
            Some(backend) => backend.spawn(spec),
            // Fail-closed: never fall back to "some" backend — the wrong one would
            // burn the wrong pool, which is the exact failure the config layer's
            // unknown-backend refusal exists to prevent.
            None => Err(SpawnError(format!(
                "no backend is configured for agent {} — the fleet roster and the \
                 backend router disagree",
                spec.agent
            ))),
        }
    }
}

impl AgentHealthSource for Arc<BackendRouter> {
    fn health(&self, agent: &str) -> Option<AgentHealth> {
        self.backend_for(agent).and_then(|b| b.health(agent))
    }
}

impl AgentStderrSource for Arc<BackendRouter> {
    fn stderr_tail(&self, agent: &str) -> Vec<String> {
        self.backend_for(agent)
            .map(|b| b.stderr_tail(agent))
            .unwrap_or_default()
    }
}

impl BudgetSampleSource for Arc<BackendRouter> {
    fn budget(&self, agent: &str) -> Option<BudgetUsage> {
        self.backend_for(agent).and_then(|b| b.budget(agent))
    }

    fn rate_limit_reopen(&self, agent: &str) -> Option<i64> {
        self.backend_for(agent)
            .and_then(|b| b.rate_limit_reopen(agent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The routing tests over a REAL mixed roster live in [`crate::fleet`], where the
    /// backends are built from an actual `config/growlight.toml`. What is provable
    /// here without constructing backends is the fail-closed edge: an agent the
    /// router does not know.
    #[test]
    fn an_unrouted_agent_fails_closed_on_every_seam() {
        let router = Arc::new(BackendRouter::new());
        let spec = AgentSpec::new("ghost", "/cfg/agents/ghost/loop.json", "/cfg/agents/ghost/mcp.json");

        // A spawn is refused rather than sent to "some" backend: the wrong one would
        // burn the wrong pool, the exact failure the config layer's unknown-backend
        // refusal exists to prevent. The message names the agent so the operator can
        // find it.
        let err = router.spawn(&spec).expect_err("an unrouted agent must not spawn");
        assert!(err.0.contains("ghost"), "the error names the agent: {}", err.0);

        // And every read seam answers "nothing observed" — never another member's
        // reading, which would misreport a live agent's health or fold a stranger's
        // budget into the admission aggregate.
        assert_eq!(AgentHealthSource::health(&router, "ghost"), None);
        assert!(AgentStderrSource::stderr_tail(&router, "ghost").is_empty());
        assert_eq!(BudgetSampleSource::budget(&router, "ghost"), None);
        assert_eq!(BudgetSampleSource::rate_limit_reopen(&router, "ghost"), None);
        // Spend included: a stranger must not read as a $0.00 metered member
        // either — `None` here means "no metered accounting", which is what keeps
        // the status surface from drawing a dollar figure it cannot justify.
        assert_eq!(router.spend("ghost"), None);
        assert_eq!(
            router.command_argv("ghost", &crate::preapproval::agent_paths(Path::new("/cfg/agents"), "ghost")),
            None,
        );
    }

    #[test]
    fn an_empty_fleet_reads_zero_rate() {
        // No backends ⇒ nothing burned ⇒ admission admits freely, the same reading a
        // fresh single-backend fleet gives (`sum_rate_windows` over an empty
        // iterator). A router that could not answer would wedge the rate gate.
        assert_eq!(BackendRouter::new().rate_used(1_700_000_000), (0, 0));
    }
}
