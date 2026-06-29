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

use crate::drive_loop::{ItemParker, PartClaimer};

/// The status a claim writes. keeperd enforces single-active scoped to the
/// queue's region, so this marks exactly one part `active` per queue.
const CLAIM_STATUS: &str = "active";
/// The status an item-park writes — `BLOCKED_ON_HUMAN` / `STUCK` recorded on the
/// item so the scheduler pivots past it (pivot-on-block, spec §6).
const BLOCK_STATUS: &str = "blocked";

/// Classify a keeperd `set_item_status` response into a fail-closed write result.
/// Shared by the claim (`active`) and the item-park (`blocked`) writes — the two
/// are the same round-trip with a different status, so the success/refusal/
/// transport mapping is one function. `what` (`"claim"` / `"block"`) labels the
/// error text. Pure (no I/O), so the idempotent-ok / refused / transport-fail
/// mapping is unit-proven without a live keeperd; the callers feed it the live
/// `call_reconnecting` result.
fn classify_status_write(
    what: &str,
    socket: &Path,
    result: Result<Response, ReconnectError>,
) -> Result<(), String> {
    match result {
        // Written — a fresh status write OR keeperd's idempotent no-op when the
        // part is already in the target status (already ours). Indistinguishable.
        Ok(Response::Ok { .. }) => Ok(()),
        // keeperd refused (e.g. a per-queue single-active conflict, or Locked): a
        // successful round-trip that did NOT write — fail-closed.
        Ok(Response::Err { kind, error, .. }) => {
            Err(format!("keeperd refused {what} ({kind:?}): {error}"))
        }
        // Never reached keeperd, or an ambiguous post-send drop: unconfirmed —
        // fail-closed. The caller retries on a later tick.
        Err(e) => Err(format!(
            "{what} to keeperd at {} failed: {e}",
            socket.display()
        )),
    }
}

/// Build + send a `set_item_status(part, status, queue)` request to keeperd and
/// classify the reply. The single round-trip [`KeeperdPartClaimer`] (the `active`
/// claim), [`KeeperdItemParker`] (the `blocked` item-park), and
/// [`crate::resume::KeeperdItemResumer`] (the `queued` un-block) all issue —
/// reusing [`call_reconnecting`] so a transient keeperd `cycle` is ridden out
/// within the retry budget, exactly as the slice-002 read does.
pub(crate) fn write_item_status(
    socket: &Path,
    what: &str,
    queue: &str,
    part: &str,
    status: &str,
    holder: Option<&str>,
) -> Result<(), String> {
    let args = serde_json::to_value(SetItemStatusArgs {
        id: part.to_string(),
        status: status.to_string(),
        queue: Some(queue.to_string()),
        holder: holder.map(|h| h.to_string()),
    })
    .map_err(|e| format!("encode set_item_status args: {e}"))?;
    let req = Request::new(op::SET_ITEM_STATUS, args);
    let result = call_reconnecting(socket, &req, RetryPolicy::default());
    classify_status_write(what, socket, result)
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
    fn claim(&self, queue: &str, part: &str, holder: &str) -> Result<(), String> {
        write_item_status(&self.keeperd_socket, "claim", queue, part, CLAIM_STATUS, Some(holder))
    }
}

/// The live [`ItemParker`]: item-park a part by marking it `blocked` in keeperd's
/// per-queue table when its member exited on a human-block (`BLOCKED_ON_HUMAN` /
/// `STUCK`). The WRITE sibling of [`KeeperdPartClaimer`] — same socket, same
/// round-trip, status `blocked` instead of `active` — wired into the live
/// assembly ([`crate::fleet::assemble_fleet`]) alongside the claimer. Writing
/// `blocked` flips the part out of `active` (keeperd's single-active gate only
/// guards writes TO `active`, so an `active → blocked` flip is always accepted),
/// which is what makes the next snapshot park the queue and the freed member pivot.
#[derive(Debug, Clone)]
pub struct KeeperdItemParker {
    /// keeperd's listen socket (the same path the claimer / queue source use).
    keeperd_socket: PathBuf,
}

impl KeeperdItemParker {
    /// Bind the item-parker to keeperd's listen socket.
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self { keeperd_socket }
    }
}

impl ItemParker for KeeperdItemParker {
    fn park_item(&self, queue: &str, part: &str) -> Result<(), String> {
        // An item-park flips the part out of `active`; it carries no holder (the
        // CAS guards writes TO `active` only).
        write_item_status(&self.keeperd_socket, "block", queue, part, BLOCK_STATUS, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::{ClientError, ErrorKind};

    fn socket() -> PathBuf {
        PathBuf::from("/run/keeperd.sock")
    }

    /// A keeperd `Ok` is a write — and keeperd returns `Ok` for BOTH a fresh write
    /// and the idempotent already-in-status no-op, so a re-claim of a part we
    /// already hold is also a (no-op) success.
    #[test]
    fn an_ok_response_is_a_claim_including_the_idempotent_re_claim() {
        let s = socket();
        // Fresh claim: keeperd commits and returns Ok with the new tip.
        assert_eq!(
            classify_status_write("claim", &s, Ok(Response::ok(serde_json::json!({ "id": "p1", "status": "active" })))),
            Ok(()),
        );
        // Idempotent re-claim: keeperd returns Ok with the *current* tip (no new
        // commit). Indistinguishable here — still a claim.
        assert_eq!(
            classify_status_write("claim", &s, Ok(Response::ok(serde_json::json!({ "id": "p1", "status": "active" })))),
            Ok(()),
        );
    }

    /// A keeperd refusal (per-queue single-active conflict, or Locked) is a
    /// successful round-trip that did NOT claim — fail-closed `Err`.
    #[test]
    fn a_refusal_response_is_a_fail_closed_error() {
        let s = socket();
        let r = classify_status_write(
            "claim",
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
        let e = classify_status_write("claim", &s, Err(ambiguous)).unwrap_err();
        assert!(e.contains("claim to keeperd"), "{e}");
        assert!(e.contains("/run/keeperd.sock"), "{e}");
    }

    /// The item-park (`block`) write uses the SAME classification, labelled `block`:
    /// an `Ok` (fresh or idempotent re-block) is a success; a refusal/transport
    /// failure is fail-soft `Err` the drive loop tolerates (the member is already
    /// released). Pins the shared seam works for both writes.
    #[test]
    fn the_block_write_classifies_with_its_own_label() {
        let s = socket();
        // Idempotent re-block / fresh block both read as Ok.
        assert_eq!(
            classify_status_write("block", &s, Ok(Response::ok(serde_json::json!({ "id": "p1", "status": "blocked" })))),
            Ok(()),
        );
        // A refusal is labelled "block", not "claim".
        let e = classify_status_write(
            "block",
            &s,
            Ok(Response::err(ErrorKind::NotFound, "no backlog item with id \"p9\"")),
        )
        .unwrap_err();
        assert!(e.contains("refused block"), "{e}");
        // A transport failure carries the block label + socket path.
        let dropped = ReconnectError::Ambiguous {
            socket: s.clone(),
            source: ClientError::UnexpectedEof,
        };
        let te = classify_status_write("block", &s, Err(dropped)).unwrap_err();
        assert!(te.contains("block to keeperd"), "{te}");
    }
}
