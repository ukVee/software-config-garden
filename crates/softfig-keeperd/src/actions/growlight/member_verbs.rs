//! Queue v2 member verbs (spec-growlight-queue §6.1–§6.6), routed
//! keeperd→growlightd exactly like the leases ([`super::leases`]): softfig-mcp
//! reaches keeperd, the one daemon a session talks to, and keeperd relays to
//! growlightd, which owns the fleet's assignments and validates the call.
//!
//! keeperd only checks the envelope's shape — a [`MemberCall`] around the
//! verb's args, so a malformed call fails here as `BadArgs` without a hop —
//! and relays growlightd's [`MemberVerbReply`](softfig_ipc::growlightd::MemberVerbReply)
//! verbatim. The identity in `member` was set by softfig-mcp from its launch
//! env; keeperd neither fills nor trusts-and-rewrites it.

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;
use softfig_ipc::growlightd::{
    AddFollowUpSessionArgs, AddSubMilestoneArgs, BlockArgs, CompleteEntryArgs, CompleteSliceArgs,
    MemberCall,
};
use softfig_ipc::{op, ErrorKind, Request};

use super::leases::forward_to_growlightd;
use crate::daemon::Daemon;
use crate::handlers::HandlerResult;

/// Shape-check one member verb's envelope and forward it to growlightd under
/// the same op name.
fn forward<A: DeserializeOwned + Serialize>(
    daemon: &Daemon,
    verb: &'static str,
    args: serde_json::Value,
) -> HandlerResult {
    forward_at::<A>(&daemon.growlightd_socket(), verb, args)
}

/// [`forward`] against an explicit growlightd socket (the testable seam).
fn forward_at<A: DeserializeOwned + Serialize>(
    socket: &Path,
    verb: &'static str,
    args: serde_json::Value,
) -> HandlerResult {
    let call: MemberCall<A> = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("{verb} args: {e}")))?;
    let req = Request::new(verb, serde_json::to_value(call).unwrap());
    forward_to_growlightd(socket, &req)
}

/// `growlight_add_follow_up_session` (§6.1).
pub fn growlight_add_follow_up_session(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    forward::<AddFollowUpSessionArgs>(daemon, op::GROWLIGHT_ADD_FOLLOW_UP_SESSION, args)
}

/// `growlight_complete_slice` (§6.2).
pub fn growlight_complete_slice(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    forward::<CompleteSliceArgs>(daemon, op::GROWLIGHT_COMPLETE_SLICE, args)
}

/// `growlight_complete_entry` (§6.5).
pub fn growlight_complete_entry(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    forward::<CompleteEntryArgs>(daemon, op::GROWLIGHT_COMPLETE_ENTRY, args)
}

/// `growlight_block` (§6.6).
pub fn growlight_block(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    forward::<BlockArgs>(daemon, op::GROWLIGHT_BLOCK, args)
}

/// `growlight_add_sub_milestone` (§7).
pub fn growlight_add_sub_milestone(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    forward::<AddSubMilestoneArgs>(daemon, op::GROWLIGHT_ADD_SUB_MILESTONE, args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    use softfig_ipc::growlightd::{MemberVerbReply, RefusalCode};
    use softfig_ipc::Response;

    /// A malformed envelope (a model-supplied `member` inside `args`) fails here
    /// as `BadArgs` — no growlightd hop, so the socket is never touched.
    #[test]
    fn a_malformed_envelope_fails_locally() {
        let dir = tempfile::tempdir().unwrap();
        let err = forward_at::<CompleteSliceArgs>(
            &dir.path().join("absent.sock"),
            op::GROWLIGHT_COMPLETE_SLICE,
            serde_json::json!({ "args": { "summary": "s", "baton": "b", "member": "forged" } }),
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::BadArgs, "{err:?}");
    }

    /// A well-formed call reaches growlightd under the same op with the envelope
    /// intact (the identity beside the args), and growlightd's reply — here a
    /// refusal — is relayed verbatim.
    #[test]
    fn a_member_verb_is_forwarded_verbatim_and_its_reply_relayed() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("growlightd.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let reply = MemberVerbReply::refused(
            op::GROWLIGHT_BLOCK,
            RefusalCode::NotYourSession,
            "no live assignment",
        );
        let reply_value = serde_json::to_value(&reply).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let req: Request = serde_json::from_str(line.trim_end()).unwrap();
            let mut bytes = serde_json::to_vec(&Response::ok(reply_value)).unwrap();
            bytes.push(b'\n');
            stream.write_all(&bytes).unwrap();
            req
        });
        let args = serde_json::json!({
            "member": "oc",
            "args": { "kind": "stuck", "reason": "r", "baton": "b" },
        });
        let data = forward_at::<BlockArgs>(&socket, op::GROWLIGHT_BLOCK, args.clone()).unwrap();
        let req = server.join().unwrap();
        assert_eq!(req.op, op::GROWLIGHT_BLOCK);
        assert_eq!(req.args, args, "the envelope crosses unchanged");
        assert_eq!(serde_json::from_value::<MemberVerbReply>(data).unwrap(), reply);
    }
}
