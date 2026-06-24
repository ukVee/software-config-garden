//! The live one-shot send (spec §8 control / §13 IPC): the thin binding that
//! takes a built [`WireRequest`] — the pure [`Command::to_request`](crate::Command::to_request)
//! output — and actually puts it on the wire. The keeperd-vs-growlightd routing
//! was already decided in [`command`](crate::command); this module only honors
//! [`WireRequest::daemon`] by dialing the matching socket and delegating the
//! whole connect→send→receive (with its reconnect/idempotency rules) to the
//! already-tested [`softfig_ipc::call_reconnecting`]. There is **no new client**.
//!
//! This is the *write* mirror of [`crate::drive_messages`] (the reconnecting
//! *read* binding over `subscribe`): both are the thin live edges of the
//! view-model, kept pure over an injected seam so the routing is provable
//! without a socket.
//!
//! Pure-core discipline ([[spec-growlight-orchestrator]] §12): the daemon→socket
//! selection ([`socket_for`]) and the request assembly are pure; the only IO is
//! behind the [`Transport`] seam. Production is [`ReconnectingTransport`] (one
//! line over `call_reconnecting`); tests inject a recording fake, so "this
//! command dialed that daemon with this op/args" is asserted with no daemon
//! running.

use std::path::{Path, PathBuf};

use softfig_ipc::{
    call_reconnecting, growlightd_runtime_socket_path, runtime_socket_path, ReconnectError,
    Request, Response, RetryPolicy,
};

use crate::command::{Daemon, WireRequest};

/// The socket a [`Daemon`] is dialed at. Pure over `$XDG_RUNTIME_DIR`
/// resolution: keeperd and growlightd are separate processes binding distinct
/// sockets beside each other under the same per-user runtime dir.
pub fn socket_for(daemon: Daemon) -> PathBuf {
    match daemon {
        Daemon::Keeperd => runtime_socket_path(),
        Daemon::Growlightd => growlightd_runtime_socket_path(),
    }
}

/// One round-trip against a daemon socket. The seam that keeps [`dispatch`]
/// provable without a live daemon: production is [`ReconnectingTransport`]
/// (delegating verbatim to [`softfig_ipc::call_reconnecting`]); a test injects a
/// fake that records the `(socket, request)` it was handed and returns a canned
/// [`Response`].
pub trait Transport {
    /// Send `req` to the daemon listening at `socket` and return its response (or
    /// the transport failure). Carries the same idempotency disposition as
    /// [`call_reconnecting`]: a pre-send failure is retried, a post-send drop is
    /// surfaced as [`ReconnectError::Ambiguous`] rather than blindly re-applied.
    fn send(&mut self, socket: &Path, req: &Request) -> Result<Response, ReconnectError>;
}

/// The live transport: the already-tested reconnecting client. **No new client**
/// — just [`call_reconnecting`] with the default [`RetryPolicy`], so a transient
/// daemon `cycle` is ridden out exactly as everywhere else (the MCP→keeperd hop,
/// the keeperd→growlightd lease hop, the growlightd→keeperd alert post).
#[derive(Debug, Default, Clone, Copy)]
pub struct ReconnectingTransport;

impl Transport for ReconnectingTransport {
    fn send(&mut self, socket: &Path, req: &Request) -> Result<Response, ReconnectError> {
        call_reconnecting(socket, req, RetryPolicy::default())
    }
}

/// Dispatch a built [`WireRequest`] to its daemon over `transport`: pick the
/// socket by [`WireRequest::daemon`], wrap the op + args in the `\n`-framed
/// [`Request`] envelope, and send. The routing decision (human post → keeperd,
/// control verbs → growlightd) was made by [`Command::to_request`](crate::Command::to_request);
/// this only carries it out. Returns the daemon's [`Response`] (an `Ok`/`Err`
/// round-trip — a daemon-side rejection is still a successful round-trip) or the
/// [`ReconnectError`] transport failure.
pub fn dispatch(
    transport: &mut impl Transport,
    req: &WireRequest,
) -> Result<Response, ReconnectError> {
    let socket = socket_for(req.daemon);
    let request = Request::new(req.op, req.args.clone());
    transport.send(&socket, &request)
}

/// Live one-shot send of a [`WireRequest`] over the production
/// [`ReconnectingTransport`] — the entry the (deferred) iced runtime calls when a
/// control gesture's [`WireRequest`] is ready. A thin alias for [`dispatch`] with
/// the live transport, so the frontend wires one call, not a client.
pub fn send(req: &WireRequest) -> Result<Response, ReconnectError> {
    dispatch(&mut ReconnectingTransport, req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Command;
    use softfig_ipc::growlightd::{PolicySummary, StopLevel};

    /// A recording fake [`Transport`]: captures every `(socket, request)` it is
    /// handed and answers with a canned `Ok` so [`dispatch`]'s routing can be
    /// asserted with no daemon running.
    #[derive(Default)]
    struct RecordingTransport {
        calls: Vec<(PathBuf, Request)>,
    }

    impl Transport for RecordingTransport {
        fn send(&mut self, socket: &Path, req: &Request) -> Result<Response, ReconnectError> {
            self.calls.push((socket.to_path_buf(), req.clone()));
            Ok(Response::ok(serde_json::json!({"acked": true})))
        }
    }

    fn dispatched(cmd: Command) -> (PathBuf, Request) {
        let mut t = RecordingTransport::default();
        let resp = dispatch(&mut t, &cmd.to_request().unwrap()).unwrap();
        assert!(matches!(resp, Response::Ok { .. }), "fake acks Ok");
        assert_eq!(t.calls.len(), 1, "exactly one round-trip per dispatch");
        t.calls.into_iter().next().unwrap()
    }

    #[test]
    fn socket_for_picks_the_distinct_per_daemon_sockets() {
        assert_eq!(socket_for(Daemon::Keeperd), runtime_socket_path());
        assert_eq!(socket_for(Daemon::Growlightd), growlightd_runtime_socket_path());
        assert_ne!(
            socket_for(Daemon::Keeperd),
            socket_for(Daemon::Growlightd),
            "keeperd and growlightd bind separate sockets"
        );
    }

    #[test]
    fn human_post_dispatches_to_keeperd_with_the_human_sender() {
        let (socket, req) = dispatched(Command::PostHuman {
            to: "@all".into(),
            kind: "info".into(),
            body: "hi".into(),
        });
        assert_eq!(socket, runtime_socket_path(), "human post → keeperd socket");
        assert_eq!(req.op, "post_message");
        assert_eq!(req.args["from"], "@human", "sender forced to the human");
        assert_eq!(req.args["to"], "@all");
        assert_eq!(req.args["body"], "hi");
    }

    #[test]
    fn pause_and_resume_dispatch_to_growlightd() {
        for (cmd, op) in [(Command::Pause, "pause"), (Command::Resume, "resume")] {
            let (socket, req) = dispatched(cmd);
            assert_eq!(
                socket,
                growlightd_runtime_socket_path(),
                "control verb → growlightd socket"
            );
            assert_eq!(req.op, op);
        }
    }

    #[test]
    fn force_stop_dispatches_to_growlightd_with_agent_and_level() {
        let (socket, req) = dispatched(Command::ForceStop {
            agent: "loop-1".into(),
            level: StopLevel::HardKill,
        });
        assert_eq!(socket, growlightd_runtime_socket_path());
        assert_eq!(req.op, "force_stop");
        assert_eq!(req.args["agent"], "loop-1");
        assert_eq!(req.args["level"], "hard_kill");
    }

    #[test]
    fn set_policy_dispatches_to_growlightd_with_the_knobs() {
        let policy = PolicySummary {
            max_concurrent_agents: 3,
            ctx_roll_pct: 50,
            ctx_handoff_pct: 60,
            session_5h_halt_pct: 85,
            session_7d_halt_pct: 90,
        };
        let (socket, req) = dispatched(Command::SetPolicy { policy });
        assert_eq!(socket, growlightd_runtime_socket_path());
        assert_eq!(req.op, "set_policy");
        assert_eq!(req.args["policy"]["max_concurrent_agents"], 3);
    }

    /// A daemon-side rejection is a *successful* round-trip — `dispatch` relays
    /// the `Response::Err` rather than turning it into a transport error.
    #[test]
    fn a_daemon_side_error_is_relayed_not_swallowed() {
        struct Rejecting;
        impl Transport for Rejecting {
            fn send(&mut self, _: &Path, _: &Request) -> Result<Response, ReconnectError> {
                Ok(Response::err(softfig_ipc::ErrorKind::BadArgs, "nope"))
            }
        }
        let req = Command::Pause.to_request().unwrap();
        match dispatch(&mut Rejecting, &req).unwrap() {
            Response::Err { kind, error, .. } => {
                assert_eq!(kind, softfig_ipc::ErrorKind::BadArgs);
                assert_eq!(error, "nope");
            }
            Response::Ok { .. } => panic!("expected the relayed daemon error"),
        }
    }
}
