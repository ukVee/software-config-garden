//! The GUI view-model — pure data the (deferred) iced `view()` renders, mutated
//! only by the reducer ([`crate::update`]). No iced types appear here: the panels
//! of spec §11 (fleet status, the per-agent thoughts feed, the groupchat, the
//! lease/roster, the budget gauges, the policy knobs) are each a plain field, so
//! the whole model is provable without a window.

use std::collections::VecDeque;

use softfig_ipc::growlightd::{
    AgentDeltaKind, AgentSummary, BuildCapsSummary, FleetStatusReply, PolicySummary,
    SetResourcesReply,
};

/// Cap on the per-agent thoughts feed so a long-lived GUI never grows unbounded;
/// the oldest line is dropped past this.
pub const MAX_THOUGHTS: usize = 500;
/// Cap on the groupchat history (same rationale).
pub const MAX_CHAT: usize = 500;

/// Liveness of the `subscribe` stream behind the GUI, driven by the reconnecting
/// client's [`softfig_growlightd_client::ClientEvent`]s.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnState {
    /// Before the first successful connect.
    #[default]
    Connecting,
    /// A live stream is attached.
    Connected,
    /// The stream dropped and the client is retrying (1-based attempt count).
    Reconnecting { attempt: u32 },
    /// The reconnect budget was exhausted — the stream is gone for good until
    /// the GUI restarts it.
    Lost,
}

/// One per-agent line in the fleet roster panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    /// Stable agent (work-stream) id.
    pub id: String,
    /// Coarse lifecycle label (from `status` or inferred from deltas).
    pub status: String,
    /// Latest per-agent context-window %, when one has been observed.
    pub ctx_pct: Option<u8>,
}

/// One fragment in the per-agent **thoughts** feed (a stream-json delta, §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThoughtLine {
    /// The agent the delta came from.
    pub agent: String,
    /// Whether it's assistant prose, a tool call, or a thinking block.
    pub kind: AgentDeltaKind,
    /// The fragment text.
    pub text: String,
}

/// The sender form a human post shows as **on the bus** — the `@` sigil stripped
/// from [`crate::command::HUMAN_SENDER`] (`@human`). The echoed
/// [`softfig_ipc::growlightd::Event::BusMessage`] carries this form, so the
/// optimistic chat line uses it to match the echo.
pub const HUMAN_FROM: &str = "human";

/// Strip a leading bus sigil (`@all` → `all`, `@human` → `human`); agent slugs
/// pass through unchanged. The `post_message` args keep the sigil form (keeperd
/// expects it); the echoed `BusMessage` and the optimistic chat line use this
/// stripped form (spec §11).
pub fn strip_sigil(addr: &str) -> &str {
    addr.strip_prefix('@').unwrap_or(addr)
}

/// One line in the **groupchat** panel (a coordination-bus message). An alert is
/// just `kind == "alert"` (spec §9), so the chat *is* the alert history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLine {
    /// Sender — an agent id or "human".
    pub from: String,
    /// Recipient — an agent id, "all", or "human".
    pub to: String,
    /// Message class ("note", "question", "alert", …).
    pub kind: String,
    /// The message body.
    pub body: String,
    /// `true` while this is an optimistic human post awaiting its bus echo (spec
    /// §11 input box). Cleared when the echoed `BusMessage` reconciles it; an
    /// incoming or reconciled line is always `false`.
    pub pending: bool,
}

impl ChatLine {
    /// A confirmed line — an incoming bus message, or a reconciled human post.
    pub fn confirmed(
        from: impl Into<String>,
        to: impl Into<String>,
        kind: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
            body: body.into(),
            pending: false,
        }
    }

    /// An optimistic, not-yet-echoed human post (rendered with a pending marker).
    pub fn pending(
        from: impl Into<String>,
        to: impl Into<String>,
        kind: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
            body: body.into(),
            pending: true,
        }
    }

    /// Whether this line is an alert (spec §9 — rendered with emphasis).
    pub fn is_alert(&self) -> bool {
        self.kind == "alert"
    }

    /// Whether this line is the same logical message as `(from, to, kind, body)`
    /// — used to reconcile an optimistic post against its echo, ignoring
    /// [`ChatLine::pending`].
    pub fn same_message(&self, from: &str, to: &str, kind: &str, body: &str) -> bool {
        self.from == from && self.to == to && self.kind == kind && self.body == body
    }
}

/// Latest fleet-wide (account-pool) budget reading — the shared 5h/7d reserves
/// and any fleet-wide context figure (spec §7). Per-agent context lives on the
/// agent's [`AgentRow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Budgets {
    /// Fleet-wide context %, if a fleet-scoped reading carried one.
    pub ctx_pct: Option<u8>,
    /// 5h rolling-reserve %.
    pub session_5h_pct: Option<u8>,
    /// 7d rolling-reserve %.
    pub session_7d_pct: Option<u8>,
}

/// The now-vs-next-spawn outcome of a `set_resources` adjustment (peer-isolation
/// slice 003): which scope properties were applied LIVE to running scopes, which
/// caps wait for the NEXT spawn, and the running agent scopes the live
/// `set-property` targeted. The non-cap fields of a wire
/// [`SetResourcesReply`](softfig_ipc::growlightd::SetResourcesReply), kept so the
/// resources panel can render "what just happened" without re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourcesOutcome {
    /// Scope properties pushed to running scopes immediately (a subset of
    /// `MemoryHigh` / `CPUWeight`).
    pub applied_live: Vec<String>,
    /// Caps that take effect only at the next spawn (`CARGO_BUILD_JOBS`).
    pub next_spawn: Vec<String>,
    /// The running agent scope units the live `set-property` was attempted on.
    pub scopes_targeted: Vec<String>,
}

/// One row in the lease/roster "who holds what" panel (spec §4c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    /// The lease key (the shared resource/action).
    pub lease: String,
    /// The current holder, or `None` if free/released.
    pub holder: Option<String>,
    /// Coarse lease state ("granted"/"released"/"waiting"/…).
    pub state: String,
}

/// The whole GUI view-model. Pure data; [`crate::update`] is the only mutator.
#[derive(Debug, Clone, Default)]
pub struct App {
    /// Stream liveness.
    pub conn: ConnState,
    /// growlightd's own state ("running"/"stopping"), from the last `status`.
    pub state_label: String,
    /// The garden root growlightd derived (never a literal path — spec §12).
    pub garden_root: String,
    /// The active per-device policy (the tweak-knobs panel edits this later).
    pub policy: Option<PolicySummary>,
    /// The active GENTLE per-agent build-resource caps (the throttle), from the
    /// last `status` and refreshed by a `set_resources` reply. `None` until the
    /// first `status` lands; the resources panel edits these.
    pub build_caps: Option<BuildCapsSummary>,
    /// The latest `set_resources` now-vs-next-spawn outcome — the resources
    /// panel's feedback line. `None` until a `set_resources` reply lands.
    pub last_resources_outcome: Option<ResourcesOutcome>,
    /// Whether the fleet admission gate is engaged.
    pub paused: bool,
    /// The fleet roster.
    pub agents: Vec<AgentRow>,
    /// The per-agent thoughts feed (most recent last), capped at [`MAX_THOUGHTS`].
    pub thoughts: VecDeque<ThoughtLine>,
    /// The groupchat history (most recent last), capped at [`MAX_CHAT`].
    pub chat: VecDeque<ChatLine>,
    /// Active leases.
    pub leases: Vec<LeaseRow>,
    /// Latest fleet-wide budgets.
    pub budgets: Budgets,
}

impl App {
    /// Fold a fleet `status` reply (the one-shot Observe verb) into the model:
    /// overwrite the daemon-scoped fields and *merge* the roster (a `status`
    /// agent line refreshes an existing row's status but preserves any per-agent
    /// ctx already learned from the stream).
    pub fn apply_status(&mut self, r: FleetStatusReply) {
        self.state_label = r.state;
        self.garden_root = r.garden_root;
        self.policy = Some(r.policy);
        self.build_caps = Some(r.build_caps);
        self.paused = r.paused;
        for AgentSummary { id, status } in r.agents {
            match self.agents.iter_mut().find(|row| row.id == id) {
                Some(row) => row.status = status,
                None => self.agents.push(AgentRow {
                    id,
                    status,
                    ctx_pct: None,
                }),
            }
        }
    }

    /// Fold a `set_resources` reply: refresh the active build-resource caps and
    /// record the now-vs-next-spawn outcome for the resources panel's feedback
    /// line. The live `subscribe` stream carries no caps event, so this reply is
    /// how the panel reflects an adjustment until the next `status` refresh.
    pub fn apply_resources(&mut self, reply: SetResourcesReply) {
        self.build_caps = Some(reply.build_caps);
        self.last_resources_outcome = Some(ResourcesOutcome {
            applied_live: reply.applied_live,
            next_spawn: reply.next_spawn,
            scopes_targeted: reply.scopes_targeted,
        });
    }

    /// Ensure an agent has a roster row (a delta from an agent the roster hasn't
    /// seen yet registers it as "running").
    pub fn touch_agent(&mut self, id: &str) {
        if !self.agents.iter().any(|r| r.id == id) {
            self.agents.push(AgentRow {
                id: id.to_string(),
                status: "running".to_string(),
                ctx_pct: None,
            });
        }
    }

    /// Record a per-agent context-window reading, registering the agent if new.
    pub fn set_agent_ctx(&mut self, id: &str, ctx: u8) {
        match self.agents.iter_mut().find(|r| r.id == id) {
            Some(row) => row.ctx_pct = Some(ctx),
            None => self.agents.push(AgentRow {
                id: id.to_string(),
                status: "running".to_string(),
                ctx_pct: Some(ctx),
            }),
        }
    }

    /// Upsert a lease row keyed by lease name.
    pub fn upsert_lease(&mut self, lease: String, holder: Option<String>, state: String) {
        match self.leases.iter_mut().find(|l| l.lease == lease) {
            Some(l) => {
                l.holder = holder;
                l.state = state;
            }
            None => self.leases.push(LeaseRow {
                lease,
                holder,
                state,
            }),
        }
    }

    /// Append to the thoughts feed, dropping the oldest line past the cap.
    pub fn push_thought(&mut self, t: ThoughtLine) {
        if self.thoughts.len() >= MAX_THOUGHTS {
            self.thoughts.pop_front();
        }
        self.thoughts.push_back(t);
    }

    /// Append to the groupchat, dropping the oldest line past the cap.
    pub fn push_chat(&mut self, c: ChatLine) {
        if self.chat.len() >= MAX_CHAT {
            self.chat.pop_front();
        }
        self.chat.push_back(c);
    }

    /// Push an optimistic human post: a `pending` [`ChatLine`] in the echo
    /// address form ([`strip_sigil`], [`HUMAN_FROM`]) so the eventual
    /// `BusMessage` echo can reconcile it (spec §11). The matching
    /// `post_message` wire request is built+sent separately
    /// ([`crate::command::Command::PostHuman`]).
    pub fn push_human_post(&mut self, to: &str, kind: &str, body: &str) {
        self.push_chat(ChatLine::pending(HUMAN_FROM, strip_sigil(to), kind, body));
    }

    /// Fold an incoming bus message. If it echoes the oldest matching optimistic
    /// human post (same from/to/kind/body), reconcile that line — clear
    /// `pending` — instead of appending a duplicate; otherwise append it as a
    /// confirmed line. Only a `from == "human"` message can reconcile, so an
    /// agent posting an identical body never clears the human's pending line.
    pub fn reconcile_or_push_chat(&mut self, from: String, to: String, kind: String, body: String) {
        if from == HUMAN_FROM {
            if let Some(line) = self
                .chat
                .iter_mut()
                .find(|l| l.pending && l.same_message(&from, &to, &kind, &body))
            {
                line.pending = false;
                return;
            }
        }
        self.push_chat(ChatLine::confirmed(from, to, kind, body));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_status_sets_daemon_fields_and_merges_roster_preserving_ctx() {
        let mut app = App::default();
        // A delta first taught us agent "a"'s ctx.
        app.set_agent_ctx("a", 30);

        let reply = FleetStatusReply {
            state: "running".into(),
            garden_root: "/g".into(),
            protocol_version: 1,
            policy: PolicySummary {
                max_concurrent_agents: 2,
                ctx_roll_pct: 50,
                ctx_handoff_pct: 60,
                session_5h_halt_pct: 85,
                session_7d_halt_pct: 90,
            },
            build_caps: BuildCapsSummary {
                cargo_build_jobs: Some(2),
                memory_high: Some("3G".into()),
                cpu_weight: None,
            },
            paused: true,
            fleet_enabled: false,
            roster: Vec::new(),
            agents: vec![
                AgentSummary {
                    id: "a".into(),
                    status: "running".into(),
                },
                AgentSummary {
                    id: "b".into(),
                    status: "idle".into(),
                },
            ],
        };
        app.apply_status(reply);

        assert_eq!(app.state_label, "running");
        assert_eq!(app.garden_root, "/g");
        assert!(app.paused);
        assert_eq!(app.policy.unwrap().max_concurrent_agents, 2);
        // The build-resource caps land in the model for the resources panel.
        let caps = app.build_caps.clone().unwrap();
        assert_eq!(caps.cargo_build_jobs, Some(2));
        assert_eq!(caps.memory_high.as_deref(), Some("3G"));
        // "a" kept its ctx; "b" was added.
        let a = app.agents.iter().find(|r| r.id == "a").unwrap();
        assert_eq!(a.ctx_pct, Some(30), "status merge preserves learned ctx");
        assert_eq!(a.status, "running");
        assert!(app.agents.iter().any(|r| r.id == "b"));
    }

    #[test]
    fn apply_resources_refreshes_caps_and_records_the_outcome() {
        let mut app = App::default();
        app.apply_resources(SetResourcesReply {
            build_caps: BuildCapsSummary {
                cargo_build_jobs: Some(1),
                memory_high: Some("2G".into()),
                cpu_weight: Some(50),
            },
            applied_live: vec!["MemoryHigh".into(), "CPUWeight".into()],
            next_spawn: vec!["CARGO_BUILD_JOBS".into()],
            scopes_targeted: vec!["growlight-agent-loop-1.scope".into()],
            scopes_applied: 1,
        });

        let caps = app.build_caps.clone().unwrap();
        assert_eq!(caps.memory_high.as_deref(), Some("2G"));
        assert_eq!(caps.cpu_weight, Some(50));
        let outcome = app.last_resources_outcome.clone().unwrap();
        assert_eq!(outcome.applied_live, vec!["MemoryHigh", "CPUWeight"]);
        assert_eq!(outcome.next_spawn, vec!["CARGO_BUILD_JOBS"]);
        assert_eq!(outcome.scopes_targeted, vec!["growlight-agent-loop-1.scope"]);
    }

    #[test]
    fn thoughts_and_chat_are_capped_oldest_first() {
        let mut app = App::default();
        for i in 0..(MAX_THOUGHTS + 5) {
            app.push_thought(ThoughtLine {
                agent: "a".into(),
                kind: AgentDeltaKind::Assistant,
                text: format!("{i}"),
            });
        }
        assert_eq!(app.thoughts.len(), MAX_THOUGHTS);
        // The oldest 5 were dropped; the front is now line "5".
        assert_eq!(app.thoughts.front().unwrap().text, "5");
        assert_eq!(
            app.thoughts.back().unwrap().text,
            format!("{}", MAX_THOUGHTS + 4)
        );
    }

    #[test]
    fn strip_sigil_maps_bus_addrs_to_the_echo_form() {
        assert_eq!(strip_sigil("@all"), "all");
        assert_eq!(strip_sigil("@human"), "human");
        assert_eq!(strip_sigil("loop-1"), "loop-1");
    }

    #[test]
    fn human_post_is_pending_and_uses_the_echo_address_form() {
        let mut app = App::default();
        app.push_human_post("@all", "info", "hi");
        let line = app.chat.back().unwrap();
        assert!(line.pending, "optimistic line is pending");
        assert_eq!(line.from, "human", "sigil-stripped sender");
        assert_eq!(line.to, "all", "sigil-stripped recipient");
    }

    #[test]
    fn upsert_lease_replaces_in_place() {
        let mut app = App::default();
        app.upsert_lease("k".into(), Some("a".into()), "granted".into());
        app.upsert_lease("k".into(), None, "released".into());
        assert_eq!(app.leases.len(), 1, "same key updates in place");
        assert_eq!(app.leases[0].holder, None);
        assert_eq!(app.leases[0].state, "released");
    }
}
