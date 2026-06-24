//! The GUI view-model — pure data the (deferred) iced `view()` renders, mutated
//! only by the reducer ([`crate::update`]). No iced types appear here: the panels
//! of spec §11 (fleet status, the per-agent thoughts feed, the groupchat, the
//! lease/roster, the budget gauges, the policy knobs) are each a plain field, so
//! the whole model is provable without a window.

use std::collections::VecDeque;

use softfig_ipc::growlightd::{AgentDeltaKind, AgentSummary, FleetStatusReply, PolicySummary};

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
}

impl ChatLine {
    /// Whether this line is an alert (spec §9 — rendered with emphasis).
    pub fn is_alert(&self) -> bool {
        self.kind == "alert"
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
            paused: true,
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
        // "a" kept its ctx; "b" was added.
        let a = app.agents.iter().find(|r| r.id == "a").unwrap();
        assert_eq!(a.ctx_pct, Some(30), "status merge preserves learned ctx");
        assert_eq!(a.status, "running");
        assert!(app.agents.iter().any(|r| r.id == "b"));
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
    fn upsert_lease_replaces_in_place() {
        let mut app = App::default();
        app.upsert_lease("k".into(), Some("a".into()), "granted".into());
        app.upsert_lease("k".into(), None, "released".into());
        assert_eq!(app.leases.len(), 1, "same key updates in place");
        assert_eq!(app.leases[0].holder, None);
        assert_eq!(app.leases[0].state, "released");
    }
}
