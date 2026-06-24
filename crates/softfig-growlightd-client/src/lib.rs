//! A thin, reconnecting client for growlightd's `subscribe` event stream.
//!
//! growlightd's one *streaming* verb (`subscribe`, spec §13 Observe) holds the
//! connection open and writes newline-framed [`Event`] JSON until the client
//! disconnects or the daemon stops (see `softfig-growlightd/tests/subscribe_stream.rs`).
//! Every frontend — the CLI `watch` path, the iced GUI (spec §11), the phone —
//! needs the *same* thing: dial the socket, send `subscribe`, decode each line as
//! an [`Event`], and **ride out a daemon restart** (the stream ends on stop; a
//! responsive frontend re-dials and resumes folding events) rather than dying on
//! the first EOF. This crate factors that out so it lives once.
//!
//! Pure-core discipline (the phase-3..6 precedent, [[spec-growlight-orchestrator]]
//! §12): the hard parts — frame decoding and the reconnect decision — are pure
//! value units with **injected** IO (a [`Connector`] seam) and an **injected**
//! sleep ([`Sleeper`]). The driver is therefore provable end to end against a
//! scripted in-memory stream with no live socket, no real time, and no window.
//! The only non-pure piece is [`UnixConnector`], the thin live binding.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use softfig_ipc::growlightd::{op, Event};
use softfig_ipc::Request;

// ---------------------------------------------------------------------------
// Frame decoding (pure). Tolerant by design: a frame this build can't decode is
// never fatal — it's surfaced as [`Frame::Undecodable`] and the stream rolls on
// (forward-compatible with `Event` variants a frontend predates, mirroring the
// CLI's old `watch_stream`).
// ---------------------------------------------------------------------------

/// One decoded line of the `subscribe` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A blank/whitespace-only line — skipped by producers and consumers alike.
    Blank,
    /// A successfully decoded event.
    Event(Event),
    /// A non-empty line that did not decode as an [`Event`]. Carries the decode
    /// error text so a frontend can log it. Never fatal.
    Undecodable(String),
}

/// Decode one newline-framed line into a [`Frame`]. Pure — the unit every
/// frontend shares so the tolerant framing rule lives in exactly one place.
pub fn decode_frame(line: &str) -> Frame {
    let trimmed = line.trim_end_matches(['\n', '\r']);
    if trimmed.trim().is_empty() {
        return Frame::Blank;
    }
    match serde_json::from_str::<Event>(trimmed) {
        Ok(event) => Frame::Event(event),
        Err(e) => Frame::Undecodable(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// What the driver emits. A frontend (the GUI reducer, the CLI renderer) maps
// these 1:1 onto its own message type — the bridge is trivial, the value is in
// the decoder + reconnect that produced the sequence.
// ---------------------------------------------------------------------------

/// An observation from the reconnecting subscribe driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A `subscribe` connection was established (initial dial or a reconnect).
    Connected,
    /// A decoded stream event.
    Event(Event),
    /// A non-empty frame that failed to decode (forward-compat); the error text.
    Undecodable(String),
    /// The active stream ended (daemon stopped / connection dropped). A
    /// reconnect attempt follows unless the policy is exhausted.
    Disconnected,
    /// About to re-dial after a drop/connect failure: the 1-based consecutive
    /// failure count and the backoff waited before this attempt.
    Reconnecting { attempt: u32, backoff: Duration },
    /// The reconnect policy is exhausted — the driver gives up and returns.
    GaveUp,
}

// ---------------------------------------------------------------------------
// Reconnect policy (pure). Consecutive-failure semantics: a *successful* connect
// resets the count, so a transient daemon `cycle` is ridden out, but a daemon
// that is genuinely gone exhausts the budget and the driver stops instead of
// spinning forever (the keeperd `RetryPolicy` lesson, applied to a long stream).
// ---------------------------------------------------------------------------

/// Backoff + give-up policy for the reconnect loop.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// Max consecutive failed attempts before giving up; `None` = retry forever
    /// (the GUI default — a long-lived frontend keeps trying until closed).
    pub max_consecutive: Option<u32>,
    /// Backoff before the 1st retry; doubles each consecutive failure, capped at
    /// `max_backoff`.
    pub initial_backoff: Duration,
    /// Ceiling on the per-retry backoff.
    pub max_backoff: Duration,
}

impl Default for ReconnectPolicy {
    /// The long-lived-frontend default: retry forever with a 200ms→5s backoff.
    fn default() -> Self {
        Self {
            max_consecutive: None,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl ReconnectPolicy {
    /// The backoff to wait before consecutive-failure number `attempt` (1-based),
    /// or `None` once the budget is exhausted (the driver then gives up).
    /// Exponential: `initial * 2^(attempt-1)`, capped at `max_backoff`.
    pub fn backoff_for(&self, attempt: u32) -> Option<Duration> {
        if let Some(max) = self.max_consecutive {
            if attempt > max {
                return None;
            }
        }
        let shift = attempt.saturating_sub(1).min(31);
        let scaled = self
            .initial_backoff
            .checked_mul(1u32 << shift)
            .unwrap_or(self.max_backoff);
        Some(scaled.min(self.max_backoff))
    }
}

// ---------------------------------------------------------------------------
// Seams. `Connector` produces a fresh `subscribe` line stream per dial (the live
// impl connects the socket + sends the request); `Sleeper` injects the backoff
// wait. Both are trivial to fake, so the driver is tested without IO or time.
// ---------------------------------------------------------------------------

/// A source of newline-framed lines from one `subscribe` connection. `None`
/// means EOF (the stream ended). Blanket-implemented for any [`BufRead`], so the
/// live `BufReader<UnixStream>` and an in-memory `Cursor` are both sources.
pub trait LineSource {
    /// The next line (including its trailing newline), or `None` at EOF.
    fn next_line(&mut self) -> io::Result<Option<String>>;
}

impl<R: BufRead> LineSource for R {
    fn next_line(&mut self) -> io::Result<Option<String>> {
        let mut line = String::new();
        let n = self.read_line(&mut line)?;
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(line))
        }
    }
}

/// Opens a fresh `subscribe` stream on demand. The driver calls this once per
/// (re)connect; each call must establish a new connection and start the stream.
pub trait Connector {
    /// The per-connection line source type.
    type Source: LineSource;
    /// Dial growlightd and begin a `subscribe` stream, or fail (the driver counts
    /// the failure and consults the [`ReconnectPolicy`]).
    fn connect(&mut self) -> io::Result<Self::Source>;
}

/// Injected backoff wait, so the reconnect loop is testable without real sleeps
/// (mirrors the `growlight_backend::Clock` seam).
pub trait Sleeper {
    /// Block for `dur` (a no-op in tests, which record the request instead).
    fn sleep(&mut self, dur: Duration);
}

/// The production sleeper: real thread sleeps.
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&mut self, dur: Duration) {
        std::thread::sleep(dur);
    }
}

// ---------------------------------------------------------------------------
// The driver. Connect → stream → decode → emit; on EOF/error, consult the policy
// and reconnect or give up. `stop` lets a frontend tear it down (Ctrl-C / window
// close) at any line boundary.
// ---------------------------------------------------------------------------

/// Drives a reconnecting `subscribe` stream, emitting [`ClientEvent`]s to `sink`.
///
/// Returns when `stop()` becomes true or the [`ReconnectPolicy`] is exhausted
/// (after emitting [`ClientEvent::GaveUp`]). A successful connect resets the
/// consecutive-failure count, so only *repeated* connect failures with no
/// intervening success exhaust the budget.
pub fn run_subscribe(
    connector: &mut impl Connector,
    policy: ReconnectPolicy,
    sleeper: &mut impl Sleeper,
    stop: &dyn Fn() -> bool,
    sink: &mut dyn FnMut(ClientEvent),
) {
    let mut failures: u32 = 0;
    loop {
        if stop() {
            return;
        }
        // A connect failure falls through to the failure-counting below; a
        // successful connect resets the budget and streams until it ends.
        if let Ok(mut source) = connector.connect() {
            failures = 0;
            sink(ClientEvent::Connected);
            if stream_until_end(&mut source, stop, sink) {
                // stop() interrupted mid-stream — leave without reconnecting.
                return;
            }
            // Natural EOF: the stream ended; fall through to reconnect.
            sink(ClientEvent::Disconnected);
        }

        failures += 1;
        match policy.backoff_for(failures) {
            Some(backoff) => {
                sink(ClientEvent::Reconnecting {
                    attempt: failures,
                    backoff,
                });
                sleeper.sleep(backoff);
            }
            None => {
                sink(ClientEvent::GaveUp);
                return;
            }
        }
    }
}

/// Pump one connection's lines into `sink` until EOF, an error, or `stop()`.
/// Returns `true` if `stop()` cut it short (the caller must not reconnect),
/// `false` on a natural end-of-stream (EOF or read error → reconnect).
fn stream_until_end(
    source: &mut impl LineSource,
    stop: &dyn Fn() -> bool,
    sink: &mut dyn FnMut(ClientEvent),
) -> bool {
    loop {
        if stop() {
            return true;
        }
        match source.next_line() {
            Ok(Some(line)) => match decode_frame(&line) {
                Frame::Blank => {}
                Frame::Event(e) => sink(ClientEvent::Event(e)),
                Frame::Undecodable(err) => sink(ClientEvent::Undecodable(err)),
            },
            Ok(None) => return false,  // EOF: stream ended cleanly.
            Err(_) => return false,    // read error: treat as a drop → reconnect.
        }
    }
}

// ---------------------------------------------------------------------------
// The live binding (the only non-pure piece): connect the Unix socket, send the
// `subscribe` request, hand back a buffered reader as the line source.
// ---------------------------------------------------------------------------

/// Connects growlightd's Unix socket and opens a `subscribe` stream. The live
/// [`Connector`] the CLI/GUI pass to [`run_subscribe`].
#[derive(Debug, Clone)]
pub struct UnixConnector {
    socket: PathBuf,
}

impl UnixConnector {
    /// A connector for the growlightd socket at `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// The socket path this connector dials.
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Connector for UnixConnector {
    type Source = BufReader<UnixStream>;

    fn connect(&mut self) -> io::Result<Self::Source> {
        let mut stream = UnixStream::connect(&self.socket)?;
        let mut framed = serde_json::to_vec(&Request::new(op::SUBSCRIBE, serde_json::Value::Null))
            .map_err(io::Error::other)?;
        framed.push(b'\n');
        stream.write_all(&framed)?;
        stream.flush()?;
        Ok(BufReader::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::growlightd::AgentDeltaKind;
    use std::collections::VecDeque;
    use std::io::Cursor;

    fn line(event: &Event) -> String {
        let mut s = serde_json::to_string(event).unwrap();
        s.push('\n');
        s
    }

    // --- decoder --------------------------------------------------------

    #[test]
    fn decode_frame_handles_event_blank_and_garbage() {
        let e = Event::agent_delta("loop-1", AgentDeltaKind::Assistant, "hi");
        assert_eq!(decode_frame(&line(&e)), Frame::Event(e));
        assert_eq!(decode_frame("   \n"), Frame::Blank);
        assert_eq!(decode_frame("\n"), Frame::Blank);
        match decode_frame("{not json}\n") {
            Frame::Undecodable(_) => {}
            other => panic!("expected Undecodable, got {other:?}"),
        }
    }

    #[test]
    fn decode_frame_accepts_a_bus_message_a_frontend_predates() {
        // The bus variant decodes even where no bus exists yet (forward-compat).
        let json = r#"{"type":"bus_message","from":"human","to":"all","kind":"note","body":"hi"}"#;
        match decode_frame(json) {
            Frame::Event(Event::BusMessage { from, body, .. }) => {
                assert_eq!(from, "human");
                assert_eq!(body, "hi");
            }
            other => panic!("expected a BusMessage event, got {other:?}"),
        }
    }

    // --- reconnect policy ----------------------------------------------

    #[test]
    fn backoff_grows_exponentially_capped_and_gives_up_past_the_budget() {
        let p = ReconnectPolicy {
            max_consecutive: Some(3),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(350),
        };
        assert_eq!(p.backoff_for(1), Some(Duration::from_millis(100)));
        assert_eq!(p.backoff_for(2), Some(Duration::from_millis(200)));
        // 400ms would be next, but the cap floors it at 350ms.
        assert_eq!(p.backoff_for(3), Some(Duration::from_millis(350)));
        // Past max_consecutive → give up.
        assert_eq!(p.backoff_for(4), None);
    }

    #[test]
    fn default_policy_retries_forever() {
        let p = ReconnectPolicy::default();
        assert!(p.backoff_for(1).is_some());
        assert!(p.backoff_for(1000).is_some(), "no give-up without a budget");
    }

    // --- driver: a scripted connector + a recording sleeper ------------

    /// A connector that hands out a scripted sequence of connections. Each entry
    /// is either `Ok(lines)` (a stream that yields those lines then EOFs) or
    /// `Err` (a connect failure). Once the script is exhausted, every further
    /// dial fails — modelling a daemon that went away and stayed away.
    struct ScriptedConnector {
        scripts: VecDeque<io::Result<Vec<String>>>,
    }

    impl ScriptedConnector {
        fn new(scripts: Vec<io::Result<Vec<String>>>) -> Self {
            Self {
                scripts: scripts.into(),
            }
        }
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

    #[derive(Default)]
    struct RecordingSleeper {
        waited: Vec<Duration>,
    }
    impl Sleeper for RecordingSleeper {
        fn sleep(&mut self, dur: Duration) {
            self.waited.push(dur);
        }
    }

    fn drive(scripts: Vec<io::Result<Vec<String>>>, policy: ReconnectPolicy) -> Vec<ClientEvent> {
        let mut connector = ScriptedConnector::new(scripts);
        let mut sleeper = RecordingSleeper::default();
        let mut out = Vec::new();
        run_subscribe(
            &mut connector,
            policy,
            &mut sleeper,
            &|| false,
            &mut |e| out.push(e),
        );
        out
    }

    #[test]
    fn reconnects_after_a_drop_and_resumes_folding_events() {
        let a = Event::agent_delta("loop-1", AgentDeltaKind::Assistant, "a");
        let b = Event::agent_delta("loop-1", AgentDeltaKind::Thinking, "b");
        let c = Event::agent_delta("loop-1", AgentDeltaKind::ToolCall, "c");
        let policy = ReconnectPolicy {
            max_consecutive: Some(1),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(10),
        };
        // session 1: [a,b] then EOF; reconnect; session 2: [c] then EOF;
        // reconnect; then the daemon is gone → connect fails → give up.
        let out = drive(
            vec![
                Ok(vec![line(&a), line(&b)]),
                Ok(vec![line(&c)]),
                Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
            ],
            policy,
        );
        assert_eq!(
            out,
            vec![
                ClientEvent::Connected,
                ClientEvent::Event(a),
                ClientEvent::Event(b),
                ClientEvent::Disconnected,
                ClientEvent::Reconnecting {
                    attempt: 1,
                    backoff: Duration::from_millis(10)
                },
                ClientEvent::Connected,
                ClientEvent::Event(c),
                ClientEvent::Disconnected,
                ClientEvent::Reconnecting {
                    attempt: 1,
                    backoff: Duration::from_millis(10)
                },
                // connect now fails: failures=1 reset? no — no success since, so
                // this is the 1st failure after the last success → attempt 1 was
                // already spent reconnecting INTO this dial; the dial failed, so
                // failures increments to 2, past max_consecutive=1 → give up.
                ClientEvent::GaveUp,
            ]
        );
    }

    #[test]
    fn a_successful_connect_resets_the_failure_budget() {
        let a = Event::agent_delta("x", AgentDeltaKind::Assistant, "a");
        let policy = ReconnectPolicy {
            max_consecutive: Some(2),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
        };
        // fail, fail (2 == budget, still retries), then SUCCEED (resets), then
        // fail, fail, fail → give up. Proves the reset.
        let out = drive(
            vec![
                Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                Ok(vec![line(&a)]),
                Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
            ],
            policy,
        );
        let connects = out.iter().filter(|e| **e == ClientEvent::Connected).count();
        assert_eq!(connects, 1, "exactly one successful session");
        assert_eq!(out.last(), Some(&ClientEvent::GaveUp));
        // The successful session's event was folded.
        assert!(out.contains(&ClientEvent::Event(a)));
    }

    #[test]
    fn stop_mid_stream_returns_without_reconnecting() {
        // stop() flips true immediately, so the driver returns before its first
        // dial — no Connected/GaveUp, a clean teardown.
        let mut connector = ScriptedConnector::new(vec![Ok(vec![])]);
        let mut sleeper = RecordingSleeper::default();
        let mut out = Vec::new();
        run_subscribe(
            &mut connector,
            ReconnectPolicy::default(),
            &mut sleeper,
            &|| true,
            &mut |e| out.push(e),
        );
        assert!(out.is_empty(), "stop before any dial emits nothing: {out:?}");
    }

    #[test]
    fn an_undecodable_frame_is_surfaced_not_fatal() {
        let good = Event::agent_delta("x", AgentDeltaKind::Assistant, "ok");
        let policy = ReconnectPolicy {
            max_consecutive: Some(0), // give up immediately after the first EOF
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
        };
        let out = drive(
            vec![Ok(vec![
                "{garbage}\n".to_string(),
                line(&good),
            ])],
            policy,
        );
        assert!(matches!(out.get(1), Some(ClientEvent::Undecodable(_))));
        assert_eq!(out.get(2), Some(&ClientEvent::Event(good)));
        assert_eq!(out.last(), Some(&ClientEvent::GaveUp));
    }
}
