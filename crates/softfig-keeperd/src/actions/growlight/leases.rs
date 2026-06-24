//! growlight Phase 4 (coordination, spec §4c/§14) — the agent-facing lease
//! verbs, routed keeperd→growlightd.
//!
//! Dangerous shared actions are supervisor-arbitrated: an agent *requests* a
//! lease, growlightd *grants / queues / denies* it, and agents never act on
//! each other directly. The pure arbitration core (`LeaseTable`) and the
//! request/reply IPC live in **growlightd**; the agent-facing surface is an MCP
//! verb that reaches **keeperd** (the one daemon Claude sessions talk to). So
//! keeperd is a thin proxy: it forwards `request_lease`/`release_lease` to
//! growlightd over growlightd's socket and relays the [`LeaseReply`].
//!
//! This is the FIRST keeperd→growlightd call. The bus bridge runs the other way
//! (growlightd pulls `tail_bus` *from* keeperd), so the hop is established here.
//! growlightd speaks the same `\n`-framed [`Request`]/[`Response`] envelope as
//! keeperd, so the live binding is just [`softfig_ipc::call_reconnecting`]
//! against growlightd's socket — the same reconnecting client the MCP uses to
//! reach keeperd, so a transient growlightd `cycle` is ridden out rather than
//! surfaced as a hard error. Leases are ephemeral in-memory state in
//! growlightd's `LeaseTable`: this path commits **nothing** to the garden.

use std::path::Path;

use softfig_ipc::growlightd::{self, ReleaseLeaseArgs, RequestLeaseArgs};
use softfig_ipc::{ErrorKind, Request, Response, RetryPolicy};

use crate::daemon::Daemon;
use crate::handlers::HandlerResult;

/// `request_lease` (spec §4c/§14): forward an agent's lease request to
/// growlightd and relay the [`LeaseReply`]. keeperd does not arbitrate — the
/// supervisor does. Malformed args fail locally as `BadArgs`; empty
/// `agent`/`key` are rejected by growlightd and surfaced verbatim.
pub fn request_lease(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: RequestLeaseArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("request_lease args: {e}")))?;
    let req = Request::new(
        growlightd::op::REQUEST_LEASE,
        serde_json::to_value(args).unwrap(),
    );
    forward_to_growlightd(&daemon.growlightd_socket(), &req)
}

/// `release_lease` (spec §4c/§14): forward a lease release to growlightd. A
/// release by a non-holder comes back `denied`; the promoted waiter (if any)
/// rides back in the reply's `holder`.
pub fn release_lease(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReleaseLeaseArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("release_lease args: {e}")))?;
    let req = Request::new(
        growlightd::op::RELEASE_LEASE,
        serde_json::to_value(args).unwrap(),
    );
    forward_to_growlightd(&daemon.growlightd_socket(), &req)
}

/// The keeperd→growlightd hop: send one one-shot request to growlightd at
/// `socket` and relay its reply. A growlightd-side error (`Response::Err`) is a
/// successful round-trip and is relayed verbatim (e.g. growlightd's empty-arg
/// `BadArgs`); a transport failure (growlightd down / unreachable / an
/// ambiguous post-send drop) surfaces as `Io` with a clear message rather than
/// being blindly retried into a possible double-apply.
pub(crate) fn forward_to_growlightd(socket: &Path, req: &Request) -> HandlerResult {
    match softfig_ipc::call_reconnecting(socket, req, RetryPolicy::default()) {
        Ok(Response::Ok { data, .. }) => Ok(data),
        Ok(Response::Err { kind, error, .. }) => Err((kind, error)),
        Err(e) => Err((
            ErrorKind::Io,
            format!("growlightd unreachable at {}: {e}", socket.display()),
        )),
    }
}
