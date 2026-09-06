//! Bounded waits for tests that own both ends of a loopback socket.
//!
//! A test that calls `TcpListener::accept()` bare has no way to fail. When the
//! initiator does not dial — a port collision, a peer that took a different
//! route, a bug in the code under test — `accept()` blocks forever, the `join()`
//! behind it blocks too, and because `cargo test` has no per-test deadline the
//! one wedged test takes its whole binary with it. The run then has to be killed
//! by hand, which destroys the evidence: no failure message, no backtrace, and no
//! record of which test was waiting for what (task `055`; the two keeperd net
//! tests that wedged the 317-test lib suite are the case that prompted this).
//!
//! So every test-owned socket gets a deadline, and every expiry names what it was
//! waiting for. A test that cannot connect must fail in seconds with a diagnosis,
//! not hang forever — that turns the next occurrence of the underlying race into
//! a readable red test instead of a silent stall.
//!
//! This module is **test support**, not part of this crate's supported surface.
//! It is `pub` rather than `#[cfg(test)]` because the sockets that need bounding
//! live in three places that cannot share a `#[cfg(test)]` module: this crate's
//! own integration tests, `softfig-keeperd`'s unit tests, and `softfig-keeperd`'s
//! integration tests. One definition beats a per-file copy of the same poll loop
//! and three different guesses at the deadline.

use std::fmt;
use std::io;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// How long a test waits for a peer that, when healthy, arrives in well under a
/// second. Deliberately far more generous than any observed healthy time (the two
/// tests this was written for complete in 0.6s and 1.9s) so it can only fire on a
/// genuine stall, never on this device being busy under a parallel build.
pub const TEST_NET_DEADLINE: Duration = Duration::from_secs(20);

/// How often the accept loop re-checks. Short enough that a healthy test pays no
/// visible cost, long enough not to spin a core while it waits.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Accept one connection on `listener` within [`TEST_NET_DEADLINE`], or panic
/// naming what never arrived. `what` completes the sentence "no inbound … within
/// 20s", so phrase it as the thing expected — `"ceremony"`, not `"error"`.
///
/// The returned stream is blocking and carries the deadline in both directions,
/// so a peer that connects and then goes quiet cannot wedge the test either — see
/// [`with_deadlines`].
///
/// # Panics
///
/// On expiry, or on an accept error other than would-block. Panicking is the
/// point: this is the failure the test previously had no way to express.
pub fn accept_within(listener: &TcpListener, what: &str) -> TcpStream {
    accept_within_deadline(listener, what, TEST_NET_DEADLINE)
}

/// [`accept_within`] with the budget spelled out, so this module's own tests can
/// prove the expiry path in milliseconds instead of waiting out the real 20s.
/// Private: every caller outside gets the one shared deadline, which is what
/// keeps it from becoming a magic number sprinkled per test.
fn accept_within_deadline(listener: &TcpListener, what: &str, budget: Duration) -> TcpStream {
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|e| panic!("could not make the {what} listener non-blocking: {e}"));
    let deadline = Instant::now() + budget;
    let accepted = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "no inbound {what} connection within {}s — nothing dialled {}, so there \
                     is no peer-side error to report",
                    budget.as_secs_f32(),
                    listener
                        .local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "the listening address".into()),
                );
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => panic!("accepting the {what} connection failed: {e}"),
        }
    };
    // Leave the listener as we found it, in case the test accepts on it again.
    let _ = listener.set_nonblocking(false);
    // Linux does not inherit O_NONBLOCK across accept, but do not depend on it:
    // a non-blocking stream handed back to code expecting a blocking one fails in
    // a far more confusing way than anything this module is preventing.
    accepted
        .set_nonblocking(false)
        .unwrap_or_else(|e| panic!("could not make the accepted {what} stream blocking: {e}"));
    with_deadline_of(accepted, what, budget)
}

/// Stamp [`TEST_NET_DEADLINE`] on both directions of a test-owned stream, so a
/// peer that connects and then stops talking fails the test instead of parking it
/// in `read()` forever. `what` names the stream for the panic message.
///
/// Returns the stream, so it can wrap a `TcpStream::connect` in place.
///
/// # Panics
///
/// If the timeouts cannot be set — a test whose socket silently kept no deadline
/// is precisely what this module exists to prevent, so it does not fail quietly.
pub fn with_deadlines(stream: TcpStream, what: &str) -> TcpStream {
    with_deadline_of(stream, what, TEST_NET_DEADLINE)
}

fn with_deadline_of(stream: TcpStream, what: &str, budget: Duration) -> TcpStream {
    stream
        .set_read_timeout(Some(budget))
        .unwrap_or_else(|e| panic!("could not set the {what} read deadline: {e}"));
    stream
        .set_write_timeout(Some(budget))
        .unwrap_or_else(|e| panic!("could not set the {what} write deadline: {e}"));
    stream
}

/// Dial `addr` within [`TEST_NET_DEADLINE`], with the same deadline on both
/// directions of the resulting stream. `what` names the peer for the panic.
///
/// A loopback `connect` normally fails fast rather than hanging, so the dial is
/// the deadline's least interesting end — the value here is that the initiator's
/// stream comes back already bounded, since a connected-then-silent peer is how a
/// suite wedges even when every accept was bounded.
///
/// Generic over the address form so call sites keep whatever they already hold —
/// a `&str`, a `String`, or the `SocketAddr` a listener handed back.
///
/// # Panics
///
/// If the address does not resolve, or the dial fails or times out.
pub fn connect_within<A: ToSocketAddrs + fmt::Debug>(addr: A, what: &str) -> TcpStream {
    let resolved = addr
        .to_socket_addrs()
        .unwrap_or_else(|e| panic!("the {what} address {addr:?} does not resolve: {e}"))
        .next()
        .unwrap_or_else(|| panic!("the {what} address {addr:?} resolved to nothing"));
    let stream = TcpStream::connect_timeout(&resolved, TEST_NET_DEADLINE).unwrap_or_else(|e| {
        panic!(
            "could not reach {what} at {resolved} within {}s: {e}",
            TEST_NET_DEADLINE.as_secs(),
        )
    });
    with_deadlines(stream, what)
}

/// A connected pair of loopback TCP streams, `(initiator, responder)`, both
/// carrying [`TEST_NET_DEADLINE`]. `what` names the pair for any panic.
///
/// The dial happens before the accept, so the connection is already in the
/// backlog and the accept would not normally block — but it is bounded anyway,
/// because "the connect landed somewhere else" is exactly the failure this module
/// refuses to let a test express as a hang.
pub fn loopback_pair(what: &str) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener
        .local_addr()
        .expect("loopback listener has a local addr")
        .to_string();
    let initiator = connect_within(&addr, what);
    let responder = accept_within(&listener, what);
    (initiator, responder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// The whole point of the module: an accept nobody dials **fails**, in
    /// bounded time, with a message naming what it was waiting for. Before this,
    /// the same situation was an unkillable park with no output at all.
    #[test]
    fn an_accept_nobody_dials_fails_with_a_message_naming_what_it_awaited() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let started = Instant::now();
        let panicked = std::panic::catch_unwind(|| {
            accept_within_deadline(&listener, "ceremony", Duration::from_millis(200))
        })
        .expect_err("an accept nobody dials must fail, not return a stream");
        let elapsed = started.elapsed();

        let msg = panicked
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panicked.downcast_ref::<&str>().copied())
            .expect("the panic carries a message");
        assert!(
            msg.contains("no inbound ceremony connection within"),
            "the failure must name what never arrived, got: {msg}",
        );
        assert!(
            msg.contains(&addr),
            "the failure must name the address nothing dialled, got: {msg}",
        );
        // Bounded: the deadline is what ends it, not the suite being killed.
        assert!(
            elapsed < Duration::from_secs(5),
            "the failure must arrive on its deadline, took {elapsed:?}",
        );
    }

    /// A healthy dial is accepted, and both ends come back deadlined — a stream
    /// with no read timeout is how a connected-then-silent peer wedges a suite
    /// even when the accept itself was bounded.
    #[test]
    fn a_dialled_connection_is_accepted_and_both_ends_carry_deadlines() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dialer = std::thread::spawn(move || connect_within(&addr, "the test listener"));

        let accepted = accept_within(&listener, "test");
        assert_eq!(accepted.read_timeout().unwrap(), Some(TEST_NET_DEADLINE));
        assert_eq!(accepted.write_timeout().unwrap(), Some(TEST_NET_DEADLINE));

        let dialled = dialer.join().expect("the dialler connected");
        assert_eq!(dialled.read_timeout().unwrap(), Some(TEST_NET_DEADLINE));
        assert_eq!(dialled.write_timeout().unwrap(), Some(TEST_NET_DEADLINE));
    }

    /// A peer that connects and then says nothing is a bounded error, not a park.
    #[test]
    fn a_connected_but_silent_peer_times_out_rather_than_parking() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Hold the connection open and say nothing.
        let quiet = std::thread::spawn(move || {
            let s = connect_within(&addr, "the test listener");
            std::thread::sleep(Duration::from_millis(500));
            drop(s);
        });

        let mut accepted = accept_within(&listener, "test");
        // Shorten just this read so the proof costs 200ms rather than the full
        // deadline; what is under test is that a deadline applies at all.
        accepted
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let err = accepted
            .read(&mut [0u8; 1])
            .expect_err("a silent peer must time out");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "expected a timeout, got {err:?}",
        );
        quiet.join().unwrap();
    }
}
