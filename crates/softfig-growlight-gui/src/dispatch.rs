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

use softfig_ipc::growlightd::{op as gop, FleetStatusReply};
use softfig_ipc::{
    call_reconnecting, growlightd_runtime_socket_path, runtime_socket_path, ErrorKind,
    ReconnectError, Request, Response, RetryPolicy,
};

use crate::command::{Daemon, WireRequest};
use crate::update::Message;

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

/// The growlightd one-shot `status` request — the Observe verb (spec §13) the GUI
/// fires at boot to seed the fleet roster/policy *before* the live `subscribe`
/// stream takes over. Pure, like every other [`WireRequest`] builder.
pub fn status_request() -> WireRequest {
    WireRequest {
        daemon: Daemon::Growlightd,
        op: gop::STATUS,
        args: serde_json::Value::Null,
    }
}

/// Why a boot-time [`load_status`] failed: a transport drop, a daemon-side
/// rejection, or a reply that didn't decode. The boot path treats any of these as
/// "leave the model in its `Connecting` default and let the stream populate it".
#[derive(Debug)]
pub enum StatusError {
    /// The round-trip failed at the transport (growlightd absent / restarting).
    Transport(ReconnectError),
    /// growlightd answered with an error response.
    Daemon {
        /// The machine-readable error category.
        kind: ErrorKind,
        /// The human-readable error message.
        error: String,
    },
    /// The `Ok` reply did not decode as a [`FleetStatusReply`].
    Decode(serde_json::Error),
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusError::Transport(e) => write!(f, "growlightd status transport error: {e}"),
            StatusError::Daemon { kind, error } => {
                write!(f, "growlightd status error ({kind:?}): {error}")
            }
            StatusError::Decode(e) => write!(f, "decoding the fleet status reply: {e}"),
        }
    }
}

impl std::error::Error for StatusError {}

/// Fetch growlightd's fleet `status` over `transport` and fold it into a
/// [`Message::StatusLoaded`] — the *read* mirror of a control [`dispatch`], kept
/// pure over the same [`Transport`] seam so the boot load is provable with a fake
/// (no daemon running). The deferred iced runtime runs this once at startup (over
/// the live [`ReconnectingTransport`], off the UI thread) and feeds the resulting
/// `Message` to the reducer.
pub fn load_status(transport: &mut impl Transport) -> Result<Message, StatusError> {
    let resp = dispatch(transport, &status_request()).map_err(StatusError::Transport)?;
    match resp.into_result() {
        Ok(data) => Ok(Message::StatusLoaded(
            serde_json::from_value::<FleetStatusReply>(data).map_err(StatusError::Decode)?,
        )),
        Err((kind, error)) => Err(StatusError::Daemon { kind, error }),
    }
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

    #[test]
    fn status_request_targets_growlightd_status_with_null_args() {
        let r = status_request();
        assert_eq!(r.daemon, Daemon::Growlightd);
        assert_eq!(r.op, "status");
        assert_eq!(r.args, serde_json::Value::Null);
    }

    #[test]
    fn load_status_decodes_the_fleet_reply_into_a_status_loaded_message() {
        use softfig_ipc::growlightd::{AgentSummary, FleetStatusReply, PolicySummary};

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
            paused: false,
            agents: vec![AgentSummary {
                id: "loop-1".into(),
                status: "running".into(),
            }],
        };

        /// A transport that answers the one `status` round-trip with a canned
        /// reply, asserting it was dialed at growlightd's socket.
        struct Replying(serde_json::Value);
        impl Transport for Replying {
            fn send(&mut self, socket: &Path, req: &Request) -> Result<Response, ReconnectError> {
                assert_eq!(socket, growlightd_runtime_socket_path(), "status → growlightd");
                assert_eq!(req.op, "status");
                Ok(Response::ok(self.0.clone()))
            }
        }

        let mut t = Replying(serde_json::to_value(&reply).unwrap());
        match load_status(&mut t).unwrap() {
            Message::StatusLoaded(got) => {
                assert_eq!(got.state, "running");
                assert_eq!(got.policy.max_concurrent_agents, 2);
                assert_eq!(got.agents.len(), 1);
                assert_eq!(got.agents[0].id, "loop-1");
            }
            other => panic!("expected StatusLoaded, got {other:?}"),
        }
    }

    #[test]
    fn load_status_surfaces_a_daemon_error_rather_than_a_status() {
        struct Rejecting;
        impl Transport for Rejecting {
            fn send(&mut self, _: &Path, _: &Request) -> Result<Response, ReconnectError> {
                Ok(Response::err(ErrorKind::Io, "boom"))
            }
        }
        match load_status(&mut Rejecting) {
            Err(StatusError::Daemon { kind, error }) => {
                assert_eq!(kind, ErrorKind::Io);
                assert_eq!(error, "boom");
            }
            other => panic!("expected a Daemon StatusError, got {other:?}"),
        }
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
