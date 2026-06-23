//! The coordination-bus bridge (phase 2, slice 003): growlightd tails keeperd's
//! chat store and republishes each new message onto the `subscribe` event hub as
//! an [`Event::BusMessage`], so a subscribed client renders the groupchat live.
//!
//! The two daemons are deliberately separate processes (spec §2): **keeperd owns
//! the bus store + the commits, growlightd owns the `subscribe` stream**. keeperd
//! knows nothing of growlightd, and growlightd is a keeperd *client* — so the
//! bridge is strictly one-way, **growlightd pulling from keeperd**, never keeperd
//! pushing into growlightd (which would invert the layering). The pull is the
//! read-only `tail_bus` verb: every message above a high-water mark, the whole
//! channel (`@all`/`@human`/direct alike — the human is a bus member). A
//! background tailer thread polls it and fans the new messages onto the hub.
//!
//! The hub drops to slow/absent subscribers (best-effort live telemetry, see
//! [`crate::hub`]), so the bridge never blocks on a consumer. The [`BusSource`]
//! seam keeps the whole fan-onto-`subscribe` path testable with a scripted fake —
//! no live keeperd, no real socket.

use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use softfig_ipc::growlightd::Event;
use softfig_ipc::verbs::{op, ChatMessage, TailBusArgs, TailBusReply};
use softfig_ipc::{connect, Request};

use crate::daemon::Daemon;
use crate::hub::EventHub;
use crate::state::State;

/// How often the bus tailer polls keeperd for new messages. The bus is async
/// turn-boundary (agents post at handoff, not mid-iteration — spec §4a/§8), so
/// sub-second latency is ample; this is not a hot path.
pub const BUS_POLL_MS: u64 = 250;

/// A failure pulling messages from the [`BusSource`]. Non-fatal to the tailer:
/// it is logged and the poll retried on the next tick, so a transient keeperd
/// hiccup (a restart, a momentary unavailability) never kills the bridge.
#[derive(Debug)]
pub struct BusError(pub String);

impl std::fmt::Display for BusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The seam the bus bridge pulls new messages through. Production reads keeperd's
/// read-only `tail_bus` verb ([`KeeperdBusSource`]); tests supply a scripted
/// fake, so the fan-onto-`subscribe` path is exercised without a live keeperd.
pub trait BusSource: Send + std::fmt::Debug {
    /// Bus messages numbered strictly above `since`, ascending — the whole
    /// channel, not a per-agent lane.
    fn messages_since(&self, since: u32) -> Result<Vec<ChatMessage>, BusError>;
}

/// Production [`BusSource`]: calls keeperd's read-only `tail_bus` over its
/// socket. growlightd is already a keeperd client (the `status` handshake); this
/// is the same JSON-Lines client idiom pointed at `tail_bus`.
#[derive(Debug, Clone)]
pub struct KeeperdBusSource {
    keeperd_socket: PathBuf,
}

impl KeeperdBusSource {
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self { keeperd_socket }
    }
}

impl BusSource for KeeperdBusSource {
    fn messages_since(&self, since: u32) -> Result<Vec<ChatMessage>, BusError> {
        let mut stream =
            connect(&self.keeperd_socket).map_err(|e| BusError(format!("connect keeperd: {e}")))?;
        let args = serde_json::to_value(TailBusArgs { since })
            .map_err(|e| BusError(format!("encode tail_bus args: {e}")))?;
        let req = Request::new(op::TAIL_BUS, args);
        let resp =
            softfig_ipc::call(&mut stream, &req).map_err(|e| BusError(format!("tail_bus call: {e}")))?;
        let value = resp
            .into_result()
            .map_err(|(kind, message)| BusError(format!("keeperd {kind:?}: {message}")))?;
        let reply: TailBusReply = serde_json::from_value(value)
            .map_err(|e| BusError(format!("decode tail_bus reply: {e}")))?;
        Ok(reply.messages)
    }
}

/// Pulls new bus messages and fans them onto the hub as [`Event::BusMessage`],
/// tracking a high-water `since` so each message publishes exactly once. [`poll`]
/// is the unit the tailer thread loops; it's pure of any timing, so the whole
/// bridge is unit-tested against a fake source + a real hub subscription.
///
/// [`poll`]: BusBridge::poll
#[derive(Debug)]
pub struct BusBridge {
    hub: EventHub,
    source: Box<dyn BusSource>,
    since: u32,
}

impl BusBridge {
    /// Start fresh: watermark at 0, so the first poll republishes the current
    /// backlog (harmless — the hub drops it if no one is subscribed yet, and a
    /// client connecting right at boot gets the recent history).
    pub fn new(hub: EventHub, source: Box<dyn BusSource>) -> Self {
        Self { hub, source, since: 0 }
    }

    /// Fetch messages past the watermark, publish each onto the hub, and advance
    /// the watermark past the last one delivered. On a source error the watermark
    /// is left PUT and the error returned — never advance past messages we failed
    /// to read, so the next tick retries them. Returns how many were published.
    pub fn poll(&mut self) -> Result<usize, BusError> {
        let messages = self.source.messages_since(self.since)?;
        let mut published = 0;
        for m in messages {
            self.hub.publish(bus_event(&m));
            self.since = self.since.max(m.number);
            published += 1;
        }
        Ok(published)
    }
}

/// Project a wire [`ChatMessage`] onto a `subscribe` [`Event::BusMessage`]: the
/// chat kind token passes straight through as the class (lossless — the variant's
/// `kind` is a free class string), and the `@` sigil is stripped from the bus
/// addresses to match the event's documented address form.
fn bus_event(m: &ChatMessage) -> Event {
    Event::bus_message(strip_at(&m.from), strip_at(&m.to), m.kind.clone(), m.body.clone())
}

/// Strip a leading `@` from a bus address: `@all` → `all`, `@human` → `human`,
/// an agent slug unchanged (slugs never start with `@`).
fn strip_at(addr: &str) -> &str {
    addr.strip_prefix('@').unwrap_or(addr)
}

/// Spawn the background bus tailer: loop [`BusBridge::poll`] every `interval`,
/// publishing new bus messages onto the daemon hub, until the daemon enters
/// `Stopping`. A poll error is logged and retried next tick (a transient keeperd
/// blip never kills the bridge or the daemon). Returns the join handle so the
/// caller (production: `main`; tests) can join it on shutdown.
pub fn spawn_bus_tailer(
    daemon: Daemon,
    source: Box<dyn BusSource>,
    interval: Duration,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("growlightd-bus-tailer".into())
        .spawn(move || {
            let mut bridge = BusBridge::new(daemon.hub.clone(), source);
            while daemon.state() != State::Stopping {
                if let Err(e) = bridge.poll() {
                    eprintln!("growlightd: bus tail error: {e}");
                }
                thread::sleep(interval);
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A scripted [`BusSource`]: returns the messages numbered above `since` from
    /// a fixed list, so the bridge runs without a live keeperd.
    #[derive(Debug)]
    struct FakeSource {
        msgs: Vec<ChatMessage>,
    }

    impl BusSource for FakeSource {
        fn messages_since(&self, since: u32) -> Result<Vec<ChatMessage>, BusError> {
            Ok(self.msgs.iter().filter(|m| m.number > since).cloned().collect())
        }
    }

    /// A source that always fails — to prove a poll error leaves the watermark put.
    #[derive(Debug)]
    struct ErrSource;
    impl BusSource for ErrSource {
        fn messages_since(&self, _since: u32) -> Result<Vec<ChatMessage>, BusError> {
            Err(BusError("keeperd down".into()))
        }
    }

    fn msg(number: u32, from: &str, to: &str, kind: &str, body: &str) -> ChatMessage {
        ChatMessage {
            number,
            from: from.into(),
            to: to.into(),
            kind: kind.into(),
            body: body.into(),
            ts: "ts".into(),
        }
    }

    #[test]
    fn bus_event_strips_sigils_and_passes_kind_through() {
        let e = bus_event(&msg(1, "@human", "@all", "coord-request", "rebase pls"));
        assert_eq!(
            e,
            Event::BusMessage {
                from: "human".into(),
                to: "all".into(),
                kind: "coord-request".into(),
                body: "rebase pls".into(),
            }
        );
        // A direct agent→agent message keeps the slugs verbatim.
        let d = bus_event(&msg(2, "agent-a", "agent-b", "info", "hi"));
        assert_eq!(
            d,
            Event::BusMessage {
                from: "agent-a".into(),
                to: "agent-b".into(),
                kind: "info".into(),
                body: "hi".into(),
            }
        );
    }

    #[test]
    fn poll_publishes_new_messages_and_advances_the_watermark() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let source = FakeSource {
            msgs: vec![
                msg(1, "agent-a", "@all", "info", "one"),
                msg(2, "agent-b", "@all", "alert", "two"),
            ],
        };
        let mut bridge = BusBridge::new(hub, Box::new(source));

        assert_eq!(bridge.poll().unwrap(), 2, "both new messages published");
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::bus_message("agent-a", "all", "info", "one")
        );
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::bus_message("agent-b", "all", "alert", "two"),
            "the alert rides the same stream",
        );
        // Watermark advanced past #2 → a re-poll over the same source is empty.
        assert_eq!(bridge.poll().unwrap(), 0, "nothing new the second time");
        assert!(sub.try_recv().is_err());
    }

    #[test]
    fn a_source_error_leaves_the_watermark_put() {
        let hub = EventHub::new();
        let mut bridge = BusBridge::new(hub, Box::new(ErrSource));
        assert!(bridge.poll().is_err(), "the source error surfaces");
        assert_eq!(bridge.since, 0, "a failed poll never advances the watermark");
    }

    /// A source whose first `messages_since` returns one batch and whose second
    /// returns a later message — proving incremental polling fans only the new
    /// ones each tick (no duplicate publishes).
    #[derive(Debug)]
    struct GrowingSource {
        batches: Mutex<std::collections::VecDeque<Vec<ChatMessage>>>,
    }
    impl BusSource for GrowingSource {
        fn messages_since(&self, since: u32) -> Result<Vec<ChatMessage>, BusError> {
            let batch = self.batches.lock().unwrap().pop_front().unwrap_or_default();
            Ok(batch.into_iter().filter(|m| m.number > since).collect())
        }
    }

    #[test]
    fn incremental_polls_fan_only_the_newly_arrived_messages() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let mut q = std::collections::VecDeque::new();
        q.push_back(vec![msg(1, "a", "@all", "info", "first")]);
        q.push_back(vec![
            msg(1, "a", "@all", "info", "first"), // already seen — filtered by `since`
            msg(2, "a", "@all", "info", "second"),
        ]);
        let mut bridge = BusBridge::new(hub, Box::new(GrowingSource { batches: Mutex::new(q) }));

        assert_eq!(bridge.poll().unwrap(), 1);
        assert_eq!(bridge.poll().unwrap(), 1, "only #2 is new on the second tick");
        assert_eq!(sub.try_recv().unwrap(), Event::bus_message("a", "all", "info", "first"));
        assert_eq!(sub.try_recv().unwrap(), Event::bus_message("a", "all", "info", "second"));
        assert!(sub.try_recv().is_err(), "no duplicate of #1");
    }
}
