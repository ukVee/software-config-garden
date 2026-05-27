//! Op-name constants + typed args/replies for each verb.
//!
//! The wire `args` and `data` fields are `serde_json::Value`; these typed
//! shapes are convenience helpers on both ends. Mismatched shapes surface
//! as `ErrorKind::BadArgs` in the daemon.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod op {
    pub const STATUS: &str = "status";
    pub const UNLOCK: &str = "unlock";
    pub const COMMIT: &str = "commit";
    pub const LOG: &str = "log";
    pub const SHOW: &str = "show";
    pub const FSCK: &str = "fsck";
    pub const PROPOSE_DOC_UPDATE: &str = "propose_doc_update";
    pub const MIGRATE_FINALIZE: &str = "migrate_finalize";
    pub const SHUTDOWN: &str = "shutdown";
    /// M2b: write plaintext of a sealed file to `$XDG_RUNTIME_DIR` and
    /// commit an audit `vault_reveal` intent.
    pub const VAULT_REVEAL: &str = "vault_reveal";
    /// M2b: append a glob to `.softfig/vault/sealed-paths.toml`,
    /// commit a `schema_change`, kick off auto-migration.
    pub const VAULT_SEAL: &str = "vault_seal";
    /// M2b: remove a glob from `sealed-paths.toml` (does NOT bulk-decrypt
    /// already-sealed blobs).
    pub const VAULT_UNSEAL: &str = "vault_unseal";
    /// M2b: read-only listing of `sealed-paths.toml` globs + the tracked
    /// files that currently match.
    pub const VAULT_LIST_SEALED: &str = "vault_list_sealed";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    /// "locked" or "unlocked".
    pub state: String,
    /// Hex tip-commit hash, or null if no commits yet.
    pub tip: Option<String>,
    pub garden_root: String,
    pub protocol_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockArgs {
    pub passphrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockReply {
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitArgs {
    pub intent: String,
    /// JSON object payload. Must be an object per the closed-enum contract.
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitReply {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogArgs {
    /// 0 means no limit.
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogReply {
    pub commits: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub hash: String,
    pub timestamp: i64,
    pub intent: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShowArgs {
    /// Hex commit hash. None = tip.
    #[serde(default)]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShowReply {
    pub commit: ShowCommit,
    pub root_tree: Vec<ShowTreeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShowCommit {
    pub hash: String,
    pub parent: Option<String>,
    pub root_tree: String,
    pub author_device: String,
    pub author_pubkey_hex: String,
    pub timestamp: i64,
    pub intent: String,
    pub master_key_id: u32,
    pub signature_hex: String,
    /// Canonical JCS bytes of the payload as a JSON string.
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShowTreeEntry {
    pub name: String,
    /// "blob" or "tree".
    pub kind: String,
    pub mode: u32,
    pub target_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsckReply {
    pub commits_checked: u64,
    pub trees_checked: u64,
    pub objects_checked: u64,
    pub orphan_objects: Vec<String>,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeDocUpdateArgs {
    pub summary: String,
    pub files: Vec<DocFile>,
    /// Slug or name of the originating project; recorded in the commit
    /// payload for traceability.
    pub project: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocFile {
    /// Garden-relative path. Validated server-side: must lie inside the
    /// garden root and not traverse `..`.
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeDocUpdateReply {
    pub hash: String,
    pub files_written: usize,
}

/// Daemon-orchestrated phase 3 of `softfig migrate`. Empty args; the
/// daemon operates on its own configured garden.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MigrateFinalizeArgs {}

// ---- M2b: Layer B reveal + seal/unseal/list-sealed --------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRevealArgs {
    /// Repo-relative path inside the garden (e.g. `secrets/foo.toml`).
    pub path: String,
    /// Master password for re-auth. `None` is permitted only when the
    /// daemon's `[reveal] idle_seconds` window is still open. The daemon
    /// surfaces `MasterPasswordRequired` if the value is missing but
    /// re-prompt is needed.
    #[serde(default)]
    pub master_password: Option<String>,
    /// When `true`, the caller is probing for "do I need to prompt?"
    /// without actually requesting a reveal. The daemon replies with
    /// `IdleStatusOnly` (with `error` set to the idle status) instead of
    /// performing the reveal.
    #[serde(default)]
    pub probe_only: bool,
    /// M2c: when `Some(id)`, reveal only the inline `<vault id="id">`
    /// region's plaintext into the temp file. `None` preserves M2b
    /// behavior (whole-file reveal). Skip-serialized when `None` so
    /// existing M2b callers and recorded payloads stay bit-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRevealReply {
    /// Absolute path of the temp file holding the plaintext (mode 0600,
    /// tmpfs-backed in `$XDG_RUNTIME_DIR`).
    pub temp_path: String,
    /// Unix seconds at which the next reveal would require a fresh
    /// master-password prompt. Equals the operation's timestamp when
    /// `idle_seconds = 0` (i.e., always re-prompt).
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSealArgs {
    /// Glob pattern (`globset` syntax — `**`, `*`, `?`, `[…]`,
    /// `{a,b}`). Appended to `.softfig/vault/sealed-paths.toml`.
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSealReply {
    /// Hash of the `schema_change` commit recording the sealed-paths
    /// edit.
    pub schema_commit: String,
    /// Hash of the follow-up `vault_seal` commit that performed the
    /// auto-migration, or `None` if no tracked files newly matched the
    /// added glob.
    pub seal_commit: Option<String>,
    /// Tracked files that were just sealed (Layer-B-encrypted) by the
    /// auto-migration pass.
    pub newly_sealed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultUnsealArgs {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultUnsealReply {
    /// Hash of the `schema_change` commit recording the removal.
    pub schema_commit: String,
    /// Whether the pattern was actually present (false = no-op).
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultListSealedArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultListSealedReply {
    /// Current contents of `sealed-paths.toml`, in file order.
    pub globs: Vec<String>,
    /// Tracked files in the working tree that match at least one glob.
    pub matching_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateFinalizeReply {
    /// True if the FUSE mount was unmounted as part of the dance.
    pub unmounted: bool,
    /// Plaintext working-tree entries deleted from `garden_root/`.
    pub plaintext_deleted: usize,
    /// Per-path failures during the plaintext sweep. Best-effort
    /// semantics per the M2a open-question #2 lean: failures don't
    /// abort `finalize`.
    pub plaintext_skipped: Vec<String>,
    /// True if the old `garden_root/.softfig/` was removed.
    pub old_state_deleted: bool,
    pub old_state_skipped: Vec<String>,
    /// True if FUSE was remounted at the end. False means the user
    /// should `softfig daemon stop && softfig daemon start` to recover.
    pub remounted: bool,
}
