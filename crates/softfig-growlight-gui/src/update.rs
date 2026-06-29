//! The Elm-style message + reducer. `update(&mut App, Message)` is a pure fold —
//! the tested heart of the GUI (spec §11). `Message` wraps the shared
//! [`ClientEvent`] 1:1 (the bridge from the IPC client is trivial; the value is
//! the reducer + the decoder/reconnect that produced the events).

use softfig_growlightd_client::ClientEvent;
use softfig_ipc::growlightd::{Event, FleetStatusReply, SetResourcesReply};

use crate::state::{App, ConnState, ThoughtLine};

/// A message the GUI runtime folds into the state. `Debug + Clone` is all an
/// iced `Message` needs (a `FleetStatusReply` carries no `Eq`).
#[derive(Debug, Clone)]
pub enum Message {
    /// The fleet `status` one-shot landed (initial load or a manual refresh).
    StatusLoaded(FleetStatusReply),
    /// A `set_resources` reply landed (the resources panel adjusted the build
    /// caps): refresh the active caps and the now-vs-next-spawn outcome line. The
    /// live `subscribe` stream carries no caps event, so this reply is how the
    /// panel reflects the change (the *write* mirror of [`Message::StatusLoaded`]).
    ResourcesApplied(SetResourcesReply),
    /// A frame from the reconnecting subscribe driver.
    Stream(ClientEvent),
    /// The human submitted the input box (spec §11). Pushes an optimistic
    /// `pending` chat line; the matching `post_message` wire request is built +
    /// sent by the live binding via [`crate::command::Command::PostHuman`], and
    /// the bus echo later reconciles the line. `to`/`kind` are wire-token forms
    /// (`@all`/`@human`/slug; a bus kind token).
    HumanPosted { to: String, kind: String, body: String },
}

impl From<ClientEvent> for Message {
    fn from(e: ClientEvent) -> Self {
        Message::Stream(e)
    }
}

/// Fold one message into the app state. Pure — no IO, no iced — so the whole GUI
/// logic is unit-tested without a window.
pub fn update(app: &mut App, msg: Message) {
    match msg {
        Message::StatusLoaded(reply) => app.apply_status(reply),
        Message::ResourcesApplied(reply) => app.apply_resources(reply),
        Message::Stream(ev) => apply_client_event(app, ev),
        Message::HumanPosted { to, kind, body } => app.push_human_post(&to, &kind, &body),
    }
}

/// Fold a streamed client event: lifecycle events move [`ConnState`]; a decoded
/// [`Event`] updates the matching panel.
fn apply_client_event(app: &mut App, ev: ClientEvent) {
    match ev {
        ClientEvent::Connected => app.conn = ConnState::Connected,
        // A drop is always immediately followed by `Reconnecting`/`GaveUp`, which
        // carry the real next state — so this needs no transition of its own.
        ClientEvent::Disconnected => {}
        ClientEvent::Reconnecting { attempt, .. } => {
            app.conn = ConnState::Reconnecting { attempt }
        }
        ClientEvent::GaveUp => app.conn = ConnState::Lost,
        // A frame this build can't decode is tolerated (the shared decoder already
        // logged it); it never corrupts the model.
        ClientEvent::Undecodable(_) => {}
        ClientEvent::Event(e) => apply_event(app, e),
    }
}

/// Route one decoded [`Event`] to the panel it updates.
fn apply_event(app: &mut App, e: Event) {
    match e {
        Event::AgentDelta { agent, kind, text } => {
            app.touch_agent(&agent);
            app.push_thought(ThoughtLine { agent, kind, text });
        }
        Event::BudgetChanged {
            agent,
            ctx_pct,
            session_5h_pct,
            session_7d_pct,
        } => match agent {
            // Per-agent reading → the agent's roster row (context only).
            Some(id) => {
                if let Some(c) = ctx_pct {
                    app.set_agent_ctx(&id, c);
                }
            }
            // Fleet-wide (account pool) reading → the budget panel. Only fields
            // the update actually carried overwrite the last reading.
            None => {
                if ctx_pct.is_some() {
                    app.budgets.ctx_pct = ctx_pct;
                }
                if session_5h_pct.is_some() {
                    app.budgets.session_5h_pct = session_5h_pct;
                }
                if session_7d_pct.is_some() {
                    app.budgets.session_7d_pct = session_7d_pct;
                }
            }
        },
        Event::LeaseChanged {
            lease,
            holder,
            state,
        } => app.upsert_lease(lease, holder, state),
        // An incoming bus message either reconciles the human's optimistic post
        // (no duplicate) or appends as a confirmed line (spec §11 optimistic UI).
        Event::BusMessage {
            from,
            to,
            kind,
            body,
        } => app.reconcile_or_push_chat(from, to, kind, body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::growlightd::AgentDeltaKind;

    fn fold(app: &mut App, ev: ClientEvent) {
        update(app, Message::from(ev));
    }

    #[test]
    fn connection_lifecycle_transitions() {
        let mut app = App::default();
        assert_eq!(app.conn, ConnState::Connecting);
        fold(&mut app, ClientEvent::Connected);
        assert_eq!(app.conn, ConnState::Connected);
        fold(&mut app, ClientEvent::Disconnected); // no-op on its own
        assert_eq!(app.conn, ConnState::Connected);
        fold(
            &mut app,
            ClientEvent::Reconnecting {
                attempt: 2,
                backoff: std::time::Duration::from_millis(1),
            },
        );
        assert_eq!(app.conn, ConnState::Reconnecting { attempt: 2 });
        fold(&mut app, ClientEvent::Connected);
        assert_eq!(app.conn, ConnState::Connected);
        fold(&mut app, ClientEvent::GaveUp);
        assert_eq!(app.conn, ConnState::Lost);
    }

    #[test]
    fn agent_delta_registers_the_agent_and_appends_a_thought() {
        let mut app = App::default();
        fold(
            &mut app,
            ClientEvent::Event(Event::agent_delta(
                "loop-1",
                AgentDeltaKind::Thinking,
                "hmm",
            )),
        );
        assert_eq!(app.agents.len(), 1);
        assert_eq!(app.agents[0].id, "loop-1");
        assert_eq!(app.thoughts.len(), 1);
        assert_eq!(app.thoughts.back().unwrap().text, "hmm");
        assert_eq!(app.thoughts.back().unwrap().kind, AgentDeltaKind::Thinking);
    }

    #[test]
    fn budget_changed_routes_per_agent_vs_fleet_wide() {
        let mut app = App::default();
        // Per-agent ctx → the agent row.
        fold(
            &mut app,
            ClientEvent::Event(Event::BudgetChanged {
                agent: Some("loop-1".into()),
                ctx_pct: Some(42),
                session_5h_pct: None,
                session_7d_pct: None,
            }),
        );
        assert_eq!(
            app.agents.iter().find(|a| a.id == "loop-1").unwrap().ctx_pct,
            Some(42)
        );
        assert_eq!(app.budgets.session_5h_pct, None);

        // Fleet-wide reserves → the budget panel (agent == None).
        fold(
            &mut app,
            ClientEvent::Event(Event::BudgetChanged {
                agent: None,
                ctx_pct: None,
                session_5h_pct: Some(12),
                session_7d_pct: Some(7),
            }),
        );
        assert_eq!(app.budgets.session_5h_pct, Some(12));
        assert_eq!(app.budgets.session_7d_pct, Some(7));
        // A later partial fleet update overwrites only what it carries.
        fold(
            &mut app,
            ClientEvent::Event(Event::BudgetChanged {
                agent: None,
                ctx_pct: None,
                session_5h_pct: Some(20),
                session_7d_pct: None,
            }),
        );
        assert_eq!(app.budgets.session_5h_pct, Some(20));
        assert_eq!(app.budgets.session_7d_pct, Some(7), "7d retained");
    }

    #[test]
    fn bus_message_appends_to_chat_and_flags_alerts() {
        let mut app = App::default();
        fold(
            &mut app,
            ClientEvent::Event(Event::bus_message("loop-1", "all", "note", "starting 001")),
        );
        fold(
            &mut app,
            ClientEvent::Event(Event::bus_message("loop-2", "human", "alert", "blocked")),
        );
        assert_eq!(app.chat.len(), 2);
        assert!(!app.chat.front().unwrap().is_alert());
        assert!(app.chat.back().unwrap().is_alert());
        assert_eq!(app.chat.back().unwrap().to, "human");
    }

    #[test]
    fn human_post_then_echo_reconciles_to_exactly_one_line() {
        let mut app = App::default();
        // Optimistic post addressed to @all.
        update(
            &mut app,
            Message::HumanPosted {
                to: "@all".into(),
                kind: "info".into(),
                body: "deploy starting".into(),
            },
        );
        assert_eq!(app.chat.len(), 1);
        assert!(app.chat.back().unwrap().pending, "optimistic line is pending");
        assert_eq!(app.chat.back().unwrap().from, "human");
        assert_eq!(app.chat.back().unwrap().to, "all", "echo address form");

        // The bus echoes it back (from human, @-stripped addrs).
        fold(
            &mut app,
            ClientEvent::Event(Event::bus_message("human", "all", "info", "deploy starting")),
        );
        assert_eq!(app.chat.len(), 1, "echo reconciles, does not duplicate");
        assert!(!app.chat.back().unwrap().pending, "reconciled line is confirmed");
    }

    #[test]
    fn an_agent_message_never_reconciles_a_pending_human_post() {
        let mut app = App::default();
        update(
            &mut app,
            Message::HumanPosted {
                to: "@all".into(),
                kind: "info".into(),
                body: "hi".into(),
            },
        );
        // An agent posts an identical body — must NOT clear the human's pending
        // line (only a from:human echo reconciles).
        fold(
            &mut app,
            ClientEvent::Event(Event::bus_message("loop-1", "all", "info", "hi")),
        );
        assert_eq!(app.chat.len(), 2);
        assert!(app.chat.front().unwrap().pending, "human line still pending");
        assert!(!app.chat.back().unwrap().pending);
    }

    #[test]
    fn resources_applied_folds_the_caps_and_outcome_into_the_model() {
        use softfig_ipc::growlightd::BuildCapsSummary;
        let mut app = App::default();
        update(
            &mut app,
            Message::ResourcesApplied(SetResourcesReply {
                build_caps: BuildCapsSummary {
                    cargo_build_jobs: Some(2),
                    memory_high: Some("3G".into()),
                    cpu_weight: Some(50),
                },
                applied_live: vec!["MemoryHigh".into()],
                next_spawn: vec!["CARGO_BUILD_JOBS".into()],
                scopes_targeted: vec!["growlight-agent-loop-1.scope".into()],
            }),
        );
        assert_eq!(
            app.build_caps.as_ref().unwrap().memory_high.as_deref(),
            Some("3G")
        );
        let outcome = app.last_resources_outcome.unwrap();
        assert_eq!(outcome.applied_live, vec!["MemoryHigh"]);
        assert_eq!(outcome.next_spawn, vec!["CARGO_BUILD_JOBS"]);
    }

    #[test]
    fn lease_changed_updates_the_roster_panel() {
        let mut app = App::default();
        fold(
            &mut app,
            ClientEvent::Event(Event::LeaseChanged {
                lease: "dock.rs §Layout".into(),
                holder: Some("loop-1".into()),
                state: "granted".into(),
            }),
        );
        assert_eq!(app.leases.len(), 1);
        assert_eq!(app.leases[0].holder.as_deref(), Some("loop-1"));
        fold(
            &mut app,
            ClientEvent::Event(Event::LeaseChanged {
                lease: "dock.rs §Layout".into(),
                holder: None,
                state: "released".into(),
            }),
        );
        assert_eq!(app.leases.len(), 1, "same lease updates in place");
        assert_eq!(app.leases[0].state, "released");
    }

    #[test]
    fn an_undecodable_frame_does_not_touch_the_model() {
        let mut app = App::default();
        fold(&mut app, ClientEvent::Undecodable("bad json".into()));
        assert!(app.agents.is_empty());
        assert!(app.thoughts.is_empty());
        assert!(app.chat.is_empty());
        assert_eq!(app.conn, ConnState::Connecting);
    }
}
