//! Integration: the whole slice-001 path composed — the reconnecting subscribe
//! client decodes a scripted (disconnect-and-resume) stream, [`drive_messages`]
//! bridges each frame to a [`Message`], and the reducer folds them into the
//! [`App`] view-model. No iced, no live socket, no real time — exactly the body
//! the deferred iced `Subscription` will run, proven here.

use std::collections::VecDeque;
use std::io::{self, Cursor};
use std::time::Duration;

use softfig_growlight_gui::{
    drive_messages, update, App, ConnState, Connector, Message, ReconnectPolicy, Sleeper,
};
use softfig_ipc::growlightd::{AgentDeltaKind, Event};

/// A scripted connector: each entry is one connection's worth of lines (then EOF)
/// or a connect failure. Mirrors the client crate's own test seam.
struct ScriptedConnector {
    scripts: VecDeque<io::Result<Vec<String>>>,
}

impl Connector for ScriptedConnector {
    type Source = Cursor<Vec<u8>>;
    fn connect(&mut self) -> io::Result<Self::Source> {
        match self.scripts.pop_front() {
            Some(Ok(lines)) => Ok(Cursor::new(lines.concat().into_bytes())),
            Some(Err(e)) => Err(e),
            None => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
        }
    }
}

struct NoSleep;
impl Sleeper for NoSleep {
    fn sleep(&mut self, _dur: Duration) {}
}

fn line(e: &Event) -> String {
    let mut s = serde_json::to_string(e).unwrap();
    s.push('\n');
    s
}

#[test]
fn a_dropped_then_reconnected_stream_folds_into_the_view_model() {
    // Session 1: a thinking delta + a fleet-wide 5h budget, then the daemon
    // drops. Session 2 (after a reconnect): a bus message. Then it's gone.
    let s1 = vec![
        line(&Event::agent_delta("loop-1", AgentDeltaKind::Thinking, "planning")),
        line(&Event::BudgetChanged {
            agent: None,
            ctx_pct: None,
            session_5h_pct: Some(40),
            session_7d_pct: None,
        }),
    ];
    let s2 = vec![line(&Event::bus_message("loop-1", "all", "note", "slice 001 underway"))];

    let mut connector = ScriptedConnector {
        scripts: VecDeque::from(vec![
            Ok(s1),
            Ok(s2),
            Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
        ]),
    };
    let policy = ReconnectPolicy {
        max_consecutive: Some(1),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(1),
    };

    let mut app = App::default();
    let mut sleeper = NoSleep;
    drive_messages(
        &mut connector,
        policy,
        &mut sleeper,
        &|| false,
        &mut |msg: Message| update(&mut app, msg),
    );

    // Both sessions' events landed across the reconnect.
    assert_eq!(app.thoughts.len(), 1, "session-1 thought folded");
    assert_eq!(app.thoughts.back().unwrap().text, "planning");
    assert_eq!(app.budgets.session_5h_pct, Some(40), "session-1 budget folded");
    assert_eq!(app.chat.len(), 1, "session-2 chat folded after the reconnect");
    assert_eq!(app.chat.back().unwrap().body, "slice 001 underway");
    assert!(app.agents.iter().any(|a| a.id == "loop-1"));

    // The driver exhausted its budget on the final failed dial → Lost.
    assert_eq!(app.conn, ConnState::Lost);
}
