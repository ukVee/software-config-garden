//! Envelope types and the closed-enum error taxonomy.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wire request: protocol version, opcode name, free-form args object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub v: u8,
    pub op: String,
    #[serde(default = "Value::default")]
    pub args: Value,
}

impl Request {
    pub fn new(op: impl Into<String>, args: Value) -> Self {
        Self {
            v: crate::PROTOCOL_VERSION,
            op: op.into(),
            args,
        }
    }
}

/// Wire response: union of success-with-data and machine-readable error.
///
/// Serialized form is one of:
///
/// ```json
/// {"ok": true,  "data": <obj>}
/// {"ok": false, "error": "<message>", "kind": "<kind>"}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Ok {
        ok: OkTrue,
        data: Value,
    },
    Err {
        ok: OkFalse,
        error: String,
        kind: ErrorKind,
    },
}

impl Response {
    pub fn ok(data: Value) -> Self {
        Response::Ok {
            ok: OkTrue,
            data,
        }
    }

    pub fn err(kind: ErrorKind, error: impl Into<String>) -> Self {
        Response::Err {
            ok: OkFalse,
            error: error.into(),
            kind,
        }
    }

    pub fn into_result(self) -> Result<Value, (ErrorKind, String)> {
        match self {
            Response::Ok { data, .. } => Ok(data),
            Response::Err { kind, error, .. } => Err((kind, error)),
        }
    }
}

/// Machine-readable error categories. Free-form `error` field carries the
/// human message; clients branch on `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The vault is locked. Caller should run `softfig daemon unlock`.
    VaultLocked,
    /// Args failed schema / value validation.
    BadArgs,
    /// Filesystem or socket I/O error inside the daemon.
    Io,
    /// Sqlite returned `SQLITE_BUSY` despite WAL — caller may retry.
    SqliteBusy,
    /// A referenced object (commit, ref, file path) doesn't exist.
    NotFound,
    /// Passphrase or signature check failed.
    AuthFailed,
    /// `softfig reveal`: the caller did not include `master_password` and
    /// the daemon's reveal-idle window has expired (or is 0). The client
    /// should prompt for the master password and retry.
    MasterPasswordRequired,
    /// `softfig reveal` named a path that isn't in `sealed-paths.toml`'s
    /// match set, or has no committed blob to reveal.
    SealedPathNotFound,
    /// `softfig reveal` was asked for idle-status only — daemon reports
    /// "yes you need to re-prompt" via this kind without leaking
    /// plaintext.
    IdleStatusOnly,
    /// M2c: a `<vault id="...">…</vault>` region on read or write was
    /// malformed (missing close tag, nested tags, invalid id charset,
    /// or a placeholder body whose id has no prior commit). Fails
    /// closed — the write commit is rejected and on read the entire
    /// content surfaces a `[malformed vault tag in <path>]\n`
    /// placeholder.
    MalformedVaultTag,
    /// M2c: a single `<vault>` parse pass found two regions sharing the
    /// same `id`. Rejected on write so the on-read region disambiguator
    /// remains unique-keyed.
    DuplicateVaultId,
    /// M3a: a `log_decision` / `log_incident` slug failed the
    /// `[a-z0-9-]+` (length 1–64) charset rule.
    InvalidSlug,
    /// M3a: an `add_project` name failed the
    /// `[a-z0-9]([a-z0-9-]*[a-z0-9])?` (length 1–64) rule.
    InvalidProjectName,
    /// M3a: a create-style action (`log_decision`, `log_incident`,
    /// `add_project`, or `archive`'s destination) targeted a path that is
    /// already present in the tree. No accidental clobber.
    PathAlreadyExists,
    /// M3a: `archive` named a `src` that doesn't exist.
    SourceNotFound,
    /// M3a: `refresh_snapshot` was given a path outside `snapshots/` or
    /// whose parent directory doesn't exist.
    InvalidSnapshotPath,
    /// Slice 1 (small-files): `add_note` / `revise_note` was given a `dir`
    /// whose basename is not an accretive folder (`notes` or
    /// `troubleshooting`). Notes only live in those folders.
    NotAccretiveDir,
    /// M5a-4: `pair_begin` could not establish or authenticate the Noise
    /// channel to the peer — TCP-connect failed, the handshake failed, the
    /// peer's attestation did not verify, or the peer's identity did not match
    /// the requested fingerprint. Distinct from `NotFound` (peer endpoint not
    /// known) and `BadArgs` (malformed fingerprint).
    PairFailed,
    /// Slice 2 (small-files): a section / `set_reviewed` op targeted a file
    /// that is whole-file-sealed or contains an inline `<vault id=…>`
    /// region. Those go through the vault-aware path; the daemon refuses so
    /// a plaintext rewrite can never clobber ciphertext.
    VaultProtected,
    /// Growlight relock: `relock_mint` was called but `[growlight]
    /// allow_relock` is not set in `keeper.toml`. The opt-in is the human's to
    /// grant; the loop must fall back to `BLOCKED_ON_HUMAN`.
    RelockDisabled,
    /// Phase 3 (garden CAS): an edit verb carried an `expected_version` that no
    /// longer matches the target's current content version — a concurrent
    /// writer moved it first. Optimistic-concurrency stale-reject: the caller
    /// should re-read the current content (+ version) and re-apply. No lock is
    /// ever held, so a crashed agent strands nothing.
    Conflict,
    /// mcp-surgical-writes slice 002 (`patch_file`): the `old` text (or the
    /// `anchor`, when given) occurred zero times in the search window — the
    /// caller's ground truth is stale or misremembered; re-read and retry.
    TextNotFound,
    /// mcp-surgical-writes slice 002 (`patch_file`): the `old` text (or the
    /// `anchor`, when given) occurred more than once in the search window —
    /// add/narrow an `anchor` to disambiguate. Distinct from `TextNotFound`
    /// because an agent's retry strategy differs.
    TextAmbiguous,
    /// mcp-surgical-writes slice 004 (`unlink`): the file is referenced
    /// elsewhere — listed in a daemon-managed `<!-- softfig:index … -->`
    /// region or linked by inbound `[[…]]` backlinks — so it is not an
    /// unreferenced leaf. Use `archive` instead (it rewrites the
    /// references); `unlink` can only cut what nothing points at.
    ReferencedElsewhere,
    /// M5f slice 001 (key-before-content): a write verb targeted a path under
    /// an enabled shared subtree whose key ceremony has not run yet (`key_id`
    /// empty). Pre-ceremony content would seal under the per-device `M` —
    /// unreadable to every other member and never converted by establishment —
    /// so the daemon refuses until the share is keyed (run/accept the
    /// ceremony, or `migrate-into-share` for existing content).
    SharedChainUnkeyed,
    /// Unknown / unhandled internal error.
    Internal,
}

// Phantom singletons that serialize as JSON `true` / `false`. Keeps the
// untagged-enum discriminator unambiguous.

#[derive(Debug, Clone, Copy)]
pub struct OkTrue;

#[derive(Debug, Clone, Copy)]
pub struct OkFalse;

impl Serialize for OkTrue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}

impl Serialize for OkFalse {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for OkTrue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = bool::deserialize(d)?;
        if b {
            Ok(OkTrue)
        } else {
            Err(serde::de::Error::custom("expected ok = true"))
        }
    }
}

impl<'de> Deserialize<'de> for OkFalse {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = bool::deserialize(d)?;
        if !b {
            Ok(OkFalse)
        } else {
            Err(serde::de::Error::custom("expected ok = false"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_round_trip() {
        let r = Response::ok(serde_json::json!({"x": 1}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":true"));
        let back: Response = serde_json::from_str(&s).unwrap();
        match back {
            Response::Ok { data, .. } => assert_eq!(data["x"], 1),
            _ => panic!(),
        }
    }

    #[test]
    fn err_round_trip() {
        let r = Response::err(ErrorKind::VaultLocked, "locked");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"kind\":\"vault_locked\""));
        let back: Response = serde_json::from_str(&s).unwrap();
        match back {
            Response::Err { kind, error, .. } => {
                assert_eq!(kind, ErrorKind::VaultLocked);
                assert_eq!(error, "locked");
            }
            _ => panic!(),
        }
    }
}
