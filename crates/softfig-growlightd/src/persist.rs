//! The build-cap persist seam (peer-isolation slice 003a-persist): after a live
//! `set_resources` adjusts the GENTLE per-agent caps in RAM + on running scopes,
//! write the new default into the in-garden `config/growlight.toml` `[build_caps]`
//! table — through keeperd — so it survives a daemon restart.
//!
//! ## Why a seam
//!
//! growlightd is keeperd's *client* (like the claim / item-park / item-resume
//! writes in [`crate::claim`] / [`crate::resume`]): it issues the
//! `growlight_set_resources` verb over keeperd's socket, and keeperd does the
//! surgical TOML edit + the `growlight_resources_set` commit (the MCP-mediated
//! commit the slice spec requires — never a raw mount write). The persist is a
//! trait so the `set_resources` handler's best-effort call is unit-proven over a
//! spy without a live keeperd, mirroring [`crate::resume::ItemResumer`].
//!
//! ## Best-effort, never blocking the live adjust
//!
//! The hook is owned by the daemon as `Option<Arc<dyn ResourcePersister>>` and
//! called **without the daemon lock** — it reaches keeperd over the socket and
//! may block, so holding the mutex across it would reintroduce the keeperd
//! deadlock class (incident 20260622). A persist `Err` (keeperd refused /
//! unreachable) is **logged and swallowed** by the caller: the running fleet has
//! already taken the new caps, so a failed on-disk write must not fail the verb.
//! `None` (no hook installed — a test, or a growlightd without a keeperd socket)
//! simply skips the persist.

use std::fmt;
use std::path::{Path, PathBuf};

use softfig_ipc::verbs::{op, GrowlightSetResourcesArgs};
use softfig_ipc::{call_reconnecting, ReconnectError, Request, Response, RetryPolicy};

use crate::config::BuildCaps;

/// The seam the `set_resources` handler persists the new caps default through.
/// Production installs [`KeeperdResourcePersister`]; a test installs a spy.
pub trait ResourcePersister: Send + Sync + fmt::Debug {
    /// Persist `caps` into `config/growlight.toml`'s `[build_caps]` via keeperd.
    /// `Ok(())` = committed (or an idempotent no-op); `Err(reason)` = keeperd
    /// refused / was unreachable. The caller logs the error and carries on — a
    /// persist failure must NEVER fail the live adjust.
    fn persist(&self, caps: &BuildCaps) -> Result<(), String>;
}

/// Production [`ResourcePersister`]: `growlight_set_resources` over keeperd's
/// socket, reusing [`call_reconnecting`] so a transient keeperd `cycle` is ridden
/// out within the retry budget (mirrors the claim / park / resume writes).
#[derive(Debug, Clone)]
pub struct KeeperdResourcePersister {
    /// keeperd's listen socket (the same path the claimer / queue source use).
    keeperd_socket: PathBuf,
}

impl KeeperdResourcePersister {
    /// Bind the persister to keeperd's listen socket.
    pub fn new(keeperd_socket: PathBuf) -> Self {
        Self { keeperd_socket }
    }
}

impl ResourcePersister for KeeperdResourcePersister {
    fn persist(&self, caps: &BuildCaps) -> Result<(), String> {
        // The full desired `[build_caps]` state: keeperd sets each `Some` key and
        // removes each `None`, so the persisted table mirrors the live caps.
        let args = GrowlightSetResourcesArgs {
            cargo_build_jobs: caps.cargo_build_jobs,
            memory_high: caps.memory_high.clone(),
            cpu_weight: caps.cpu_weight,
        };
        let args = serde_json::to_value(args)
            .map_err(|e| format!("encode growlight_set_resources args: {e}"))?;
        let req = Request::new(op::GROWLIGHT_SET_RESOURCES, args);
        let result = call_reconnecting(&self.keeperd_socket, &req, RetryPolicy::default());
        classify_persist(&self.keeperd_socket, result)
    }
}

/// Classify a keeperd `growlight_set_resources` response into a persist result.
/// Pure (no I/O) so the success / refusal / transport mapping is unit-proven
/// without a live keeperd. An `Ok` — a fresh commit OR keeperd's idempotent
/// no-op (caps unchanged) — is success; a refusal or transport failure is `Err`
/// the caller logs (the live adjust already landed).
fn classify_persist(socket: &Path, result: Result<Response, ReconnectError>) -> Result<(), String> {
    match result {
        Ok(Response::Ok { .. }) => Ok(()),
        Ok(Response::Err { kind, error, .. }) => {
            Err(format!("keeperd refused persist ({kind:?}): {error}"))
        }
        Err(e) => Err(format!(
            "persist to keeperd at {} failed: {e}",
            socket.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::{ClientError, ErrorKind};

    fn socket() -> PathBuf {
        PathBuf::from("/run/keeperd.sock")
    }

    /// A keeperd `Ok` is a persist — both a fresh `growlight_resources_set`
    /// commit and the idempotent no-op (caps unchanged) come back `Ok`, and both
    /// mean "persisted", so they're indistinguishable here.
    #[test]
    fn an_ok_response_is_a_persist_including_the_idempotent_no_op() {
        let s = socket();
        assert_eq!(
            classify_persist(
                &s,
                Ok(Response::ok(serde_json::json!({ "committed": true, "path": "config/growlight.toml" })))
            ),
            Ok(()),
        );
        assert_eq!(
            classify_persist(
                &s,
                Ok(Response::ok(serde_json::json!({ "committed": false, "path": "config/growlight.toml" })))
            ),
            Ok(()),
        );
    }

    /// A keeperd refusal (e.g. Locked, or the config absent) is a successful
    /// round-trip that did NOT persist — `Err` the caller logs, not a panic.
    #[test]
    fn a_refusal_response_is_a_logged_error() {
        let s = socket();
        let e = classify_persist(
            &s,
            Ok(Response::err(ErrorKind::NotFound, "config/growlight.toml: absent")),
        )
        .unwrap_err();
        assert!(e.contains("refused persist"), "{e}");
        assert!(e.contains("absent"), "{e}");
    }

    /// A transport failure — unreachable, or an ambiguous post-send drop — maps
    /// to `Err` carrying the socket path. The caller swallows it (the live adjust
    /// already succeeded).
    #[test]
    fn a_transport_failure_is_an_error_with_the_socket() {
        let s = socket();
        let dropped = ReconnectError::Ambiguous {
            socket: s.clone(),
            source: ClientError::UnexpectedEof,
        };
        let e = classify_persist(&s, Err(dropped)).unwrap_err();
        assert!(e.contains("persist to keeperd"), "{e}");
        assert!(e.contains("/run/keeperd.sock"), "{e}");
    }
}
