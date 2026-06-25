//! The live [`PartClaimer`] (`growlight-live-fleet` slice 003): claim a picked
//! part by marking it `active` in keeperd's per-queue table — the WRITE that
//! closes the fallback double-assignment window across ticks.
//!
//! ## What this is
//!
//! The read mirror is [`crate::queue_source`] (`read_file` → parse → snapshot).
//! This is the matching write: growlightd, as keeperd's *client*, issues
//! `set_item_status(part, "active", queue)` over the same socket so the part the
//! scheduler just picked is marked claimed before its agent spawns. keeperd
//! enforces single-active **per queue** (scoped to the resolved region), so one
//! claimed `active` part per queue is exactly the scheduler's per-queue claim.
//!
//! The claim **gates** the spawn (it is issued between admission admitting and
//! the backend spawning — [`Supervisor::start_claiming`](crate::supervisor::Supervisor::start_claiming)),
//! so a claim that cannot be confirmed never leaves an agent running on an
//! unclaimed part.
//!
//! ## Fail-closed
//!
//! Only keeperd's `Response::Ok` counts as claimed. keeperd returns `Ok` for
//! **both** a fresh `active` write and the *idempotent already-`active` no-op*
//! (re-claiming a part this agent already holds), so the two are indistinguishable
//! here — which is the point: a re-claim is a no-op success. Everything else maps
//! to `Err`:
//!
//! - a `Response::Err` (keeperd refused — another part in the queue is already
//!   `active`, or the daemon is Locked) is a successful round-trip that did NOT
//!   claim;
//! - a transport failure — unreachable past the reconnect budget, or an ambiguous
//!   post-send drop — is unconfirmed.
//!
//! In all `Err` cases the drive loop must NOT spawn, so no agent is orphaned on an
//! unclaimed part. An ambiguous claim that actually landed is harmless: the next
//! tick's snapshot shows the part `active` and the pinned agent resumes it,
//! re-claiming idempotently.

use std::path::{Path, PathBuf};

use softfig_ipc::verbs::{op, SetItemStatusArgs};
use softfig_ipc::{call_reconnecting, ReconnectError, Request, Response, RetryPolicy};

use crate::drive_loop::PartClaimer;

/// The status a claim writes. keeperd enforces single-active scoped to the
/// queue's region, so this marks exactly one part `active` per queue.
const CLAIM_STATUS: &str = "active";

/// Classify a keeperd `set_item_status` response into a fail-closed claim result.
/// Pure (no I/O), so the idempotent-ok / refused / transport-fail mapping is
/// unit-proven without a live keeperd; [`KeeperdPartClaimer::claim`] feeds it the
/// live `call_reconnecting` result.
fn classify_claim(socket: &Path, result: Result<Response, ReconnectError>) -> Result<(), String> {
    match result {
        // Claimed — a fresh `active` write OR keeperd's idempotent no-op when the
        // part is already `active` (already ours). Indistinguishable, by design.
        Ok(Response::Ok { .. }) => Ok(()),
        // keeperd refused (another part active in this queue, or Locked): a
        // successful round-trip that did NOT claim — fail-closed.
        Ok(Response::Err { kind, error, .. }) => {
            Err(format!("keeperd refused claim ({kind:?}): {error}"))
        }
        // Never reached keeperd, or an ambiguous post-send drop: the claim is
        // unconfirmed — fail-closed (do not spawn). The next tick retries.
        Err(e) => Err(format!(
            "claim to keeperd at {} failed: {e}",
            socket.display()
        )),
    }
}

/// The live [`PartClaimer`]: claim each picked part by marking it `active` in
/// keeperd's per-queue table before the agent spawns. Wired into the live
/// assembly ([`crate::fleet::assemble_fleet`]) alongside the slice-002
/// [`KeeperdQueueSource`](crate::queue_source::KeeperdQueueSource); both ride the
/// same keeperd socket. The claim reuses
/// [`call_reconnecting`](softfig_ipc::call_reconnecting) so a transient keeperd
/// `cycle` is ridden out within the retry budget, mirroring the slice-002 read.
#[derive(Debug, Clone)]
pub struct KeeperdPartClaimer {
    /// keeperd's listen socket (the same path the bus tailer / queue source read).
    keeperd_socket: PathBuf,
}

impl KeeperdPartClaimer {
    /// Bind the claimer to keeperd's listen socket.
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self { keeperd_socket }
    }
}

impl PartClaimer for KeeperdPartClaimer {
    fn claim(&self, queue: &str, part: &str) -> Result<(), String> {
        let args = serde_json::to_value(SetItemStatusArgs {
            id: part.to_string(),
            status: CLAIM_STATUS.to_string(),
            queue: Some(queue.to_string()),
        })
        .map_err(|e| format!("encode set_item_status args: {e}"))?;
        let req = Request::new(op::SET_ITEM_STATUS, args);
        let result = call_reconnecting(&self.keeperd_socket, &req, RetryPolicy::default());
        classify_claim(&self.keeperd_socket, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::{ClientError, ErrorKind};

    fn socket() -> PathBuf {
        PathBuf::from("/run/keeperd.sock")
    }

    /// A keeperd `Ok` is a claim — and keeperd returns `Ok` for BOTH a fresh
    /// `active` write and the idempotent already-`active` no-op, so a re-claim of
    /// a part we already hold is also a (no-op) success.
    #[test]
    fn an_ok_response_is_a_claim_including_the_idempotent_re_claim() {
        let s = socket();
        // Fresh claim: keeperd commits and returns Ok with the new tip.
        assert_eq!(
            classify_claim(&s, Ok(Response::ok(serde_json::json!({ "id": "p1", "status": "active" })))),
            Ok(()),
        );
        // Idempotent re-claim: keeperd returns Ok with the *current* tip (no new
        // commit). Indistinguishable here — still a claim.
        assert_eq!(
            classify_claim(&s, Ok(Response::ok(serde_json::json!({ "id": "p1", "status": "active" })))),
            Ok(()),
        );
    }

    /// A keeperd refusal (per-queue single-active conflict, or Locked) is a
    /// successful round-trip that did NOT claim — fail-closed `Err`.
    #[test]
    fn a_refusal_response_is_a_fail_closed_error() {
        let s = socket();
        let r = classify_claim(
            &s,
            Ok(Response::err(ErrorKind::BadArgs, "item \"p2\" is already active")),
        );
        let e = r.unwrap_err();
        assert!(e.contains("refused claim"), "{e}");
        assert!(e.contains("already active"), "{e}");
    }

    /// A transport failure — unreachable, or an ambiguous post-send drop — is
    /// unconfirmed, so it maps to a fail-closed `Err` (the loop must not spawn).
    #[test]
    fn a_transport_failure_is_a_fail_closed_error() {
        let s = socket();
        // Ambiguous: the request was sent but the response read failed — the claim
        // MAY have landed, but it is unconfirmed, so fail-closed.
        let ambiguous = ReconnectError::Ambiguous {
            socket: s.clone(),
            source: ClientError::UnexpectedEof,
        };
        let e = classify_claim(&s, Err(ambiguous)).unwrap_err();
        assert!(e.contains("claim to keeperd"), "{e}");
        assert!(e.contains("/run/keeperd.sock"), "{e}");
    }
}
