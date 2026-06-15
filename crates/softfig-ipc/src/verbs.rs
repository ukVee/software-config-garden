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
    /// Break-glass: overwrite a single garden file with verbatim bytes (no
    /// convention stamping) and commit `memory_edit`. The narrowed/renamed
    /// `propose_doc_update`; callers should prefer the structural verbs
    /// (`add_note`, `*_section`, `log_*`, …) that stamp conventions.
    pub const REPLACE_FILE: &str = "replace_file";
    pub const MIGRATE_FINALIZE: &str = "migrate_finalize";
    /// Slice 1 (small-files): one-time splitter. Walk the working tree for
    /// `notes.md` / `troubleshooting.md` monoliths, rewrite each into its
    /// sibling accretive folder of numbered notes, archive the monolith, and
    /// commit one `monolith_split` per file. Dry-run unless `apply`.
    pub const MIGRATE_SPLIT: &str = "migrate_split";
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
    /// M3a: write a `journal/decisions/decision-<slug>.md` stub with a
    /// daemon-stamped header, commit `decision_logged`.
    pub const LOG_DECISION: &str = "log_decision";
    /// M3a: write a `journal/incidents/incident-<date>-<slug>.md` stub,
    /// commit `incident_logged`.
    pub const LOG_INCIDENT: &str = "log_incident";
    /// Slice 1 (small-files): append a numbered note `NNN-slug.md` to an
    /// accretive folder (`notes/` or `troubleshooting/`). The daemon
    /// assigns `NNN` from the folder's `.seq` high-water mark and stamps
    /// the header + reviewed date; commit `note_added`.
    pub const ADD_NOTE: &str = "add_note";
    /// Slice 1 (small-files): replace the body of an existing numbered
    /// note in place, re-stamping the reviewed date. Title, slug, and
    /// number are immutable; commit `note_revised`.
    pub const REVISE_NOTE: &str = "revise_note";
    /// M3a: move a tracked path under `journal/archive/<name>/`, commit
    /// `archive_move`.
    pub const ARCHIVE: &str = "archive";
    /// M3a: stamp the four reserved-name stubs under `projects/<name>/`,
    /// commit `project_added`.
    pub const ADD_PROJECT: &str = "add_project";
    /// M3a: write caller-supplied content to a path under `snapshots/`,
    /// commit `snapshot_refresh`. The daemon never executes user code.
    pub const REFRESH_SNAPSHOT: &str = "refresh_snapshot";
    /// M3b: list the immediate children of a garden-relative directory in
    /// the committed tip tree. Read-only.
    pub const LIST_TREE: &str = "list_tree";
    /// M3b: read a garden-relative file's daemon-redacted content from the
    /// committed tip tree. Sealed files / inline regions are projected, not
    /// decrypted. Read-only.
    pub const READ_FILE: &str = "read_file";
    /// M5a-4: begin pairing as the initiator — TCP-connect to the target
    /// device, run the Noise `XX` handshake + attestation, and park the
    /// pending pairing awaiting SAS confirmation. Returns the SAS to compare.
    pub const PAIR_BEGIN: &str = "pair_begin";
    /// M5a-4: confirm a parked pairing (the SAS matched on the other device);
    /// persist the peer into the `peers.toml` network trust ring.
    pub const PAIR_CONFIRM: &str = "pair_confirm";
    /// M5a-4: list the network trust ring (`peers.toml`).
    pub const PAIR_LIST: &str = "pair_list";
    /// M5a-4: remove a peer from the ring (unpair) by device-id fingerprint.
    pub const PAIR_REMOVE: &str = "pair_remove";
    /// Pairing-UX Slice A: list nearby-but-unpaired devices the mDNS browse
    /// loop has discovered (the LAN pick-list). Read-only; surfaces the
    /// discovery cache so the CLI/TUI can pair by name without typing a
    /// fingerprint.
    pub const DISCOVER_LIST: &str = "discover_list";
    /// M5b: grant a ring member permission to host this device's chain backup —
    /// add it to the owner-side `push_to` allow-list. The owner then pushes its
    /// signed ciphertext chain to that host (which must also have opted in via
    /// `[replica] host = true`).
    pub const REPLICA_GRANT: &str = "replica_grant";
    /// M5b: revoke a replication grant (remove from `push_to`). Stops new
    /// pushes; cannot un-send ciphertext the host already holds.
    pub const REPLICA_REVOKE: &str = "replica_revoke";
    /// M5b: backup-health metadata — who this device pushes to, whether it is a
    /// host, and per-peer mirror stats for chains it hosts. Read-only; never a
    /// document browser (peer-doc reading is the deferred M5b-view slice).
    pub const REPLICA_STATUS: &str = "replica_status";
    /// Slice 2 (small-files): append a brand-new heading-addressed section
    /// to the end of any markdown doc. The heading must not already exist;
    /// commit `section_added`.
    pub const ADD_SECTION: &str = "add_section";
    /// Slice 2 (small-files): replace the body of an existing
    /// heading-addressed section, keeping the heading line. The heading must
    /// exist and be unique; commit `section_edited`.
    pub const EDIT_SECTION: &str = "edit_section";
    /// Slice 2 (small-files): append text to the end of an existing
    /// section's body (the "add a row/bullet" op); commit `section_appended`.
    pub const APPEND_TO_SECTION: &str = "append_to_section";
    /// Slice 2 (small-files): rewrite a doc's `Last reviewed:` line to today.
    /// Zero content tokens — just a path; commit `reviewed_stamped`.
    pub const SET_REVIEWED: &str = "set_reviewed";
    /// growlight Phase 1: append a numbered iteration entry to the
    /// `growlight/baton-log/` audit folder (item, slice, iteration, what
    /// shipped, budgets). Mirrors `add_note`; commit `baton_logged`.
    pub const LOG_BATON: &str = "log_baton";
    /// growlight Phase 1: seed a backlog item — a milestone
    /// (`growlight/backlog/milestones/<id>/`) or a standalone task
    /// (`growlight/backlog/tasks/NNN-<slug>.md`) — and enqueue it (status
    /// `queued`) in the managed queue table. Mirrors `add_project`; commit
    /// `backlog_item_added`.
    pub const ADD_BACKLOG_ITEM: &str = "add_backlog_item";
    /// growlight Phase 1: append a numbered slice under a milestone
    /// (`growlight/backlog/milestones/<id>/slices/NNN-<slug>.md`) and refresh
    /// the milestone's slices index. Commit `slice_added`.
    pub const ADD_SLICE: &str = "add_slice";
    /// growlight Phase 1: set a backlog item's status (`queued|active|done|
    /// blocked`) by flipping its cell in the authoritative queue table in
    /// `growlight/backlog/CLAUDE.md` (enforces at most one `active`). Commit
    /// `item_status_set`.
    pub const SET_ITEM_STATUS: &str = "set_item_status";
    /// growlight Phase 2: scaffold the `growlight/` pillar — write the routing
    /// docs + embedded `protocol.md`/`session-policy.md` + the backlog/baton-log
    /// skeleton, and wire the garden nav (root map + boundary row + meta docs).
    /// Idempotent retrofit; one `growlight_initialized` commit, or none if the
    /// pillar already exists. Mirrors `migrate split`.
    pub const GROWLIGHT_INIT: &str = "growlight_init";
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

/// `replace_file({path, content}) -> {path, hash}`. **Break-glass.** Writes
/// `content` to `path` verbatim — no convention stamping, you hand-write the
/// whole file (frontmatter and all). Discouraged in favor of the structural
/// verbs; commit `memory_edit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaceFileArgs {
    /// Garden-relative path. Validated server-side: must lie inside the
    /// garden root and not traverse `..`.
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaceFileReply {
    /// Garden-relative path the daemon wrote.
    pub path: String,
    pub hash: String,
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

// ---- M3a: typed garden-write action surface ---------------------------

/// `log_decision({slug, summary?, body}) -> {path, hash}`.
///
/// The daemon stamps the `# decision: <title>` header + `Date:` line and
/// writes the body below — the caller supplies only the slug, an optional
/// title (defaults to the slug), and the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogDecisionArgs {
    /// `[a-z0-9-]+`, length 1–64. Becomes `decision-<slug>.md`.
    pub slug: String,
    /// Title used in the `# decision: <summary>` header line. Defaults to
    /// the slug when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Markdown body written below the daemon-stamped header.
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogDecisionReply {
    /// Garden-relative path the daemon wrote.
    pub path: String,
    pub hash: String,
}

/// `log_incident({slug, summary, body, date?}) -> {path, hash}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogIncidentArgs {
    /// `[a-z0-9-]+`, length 1–64. Becomes the trailing `-<slug>` of the
    /// `incident-<date>-<slug>.md` filename.
    pub slug: String,
    /// One-line summary stamped into the `# <YYYY-MM-DD> — <summary>`
    /// header.
    pub summary: String,
    /// Markdown body written below the header.
    pub body: String,
    /// `YYYYMMDD` date for the filename. Defaults to today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogIncidentReply {
    pub path: String,
    pub hash: String,
}

// ---- Slice 1 (small-files): numbered notes -----------------------------

/// `add_note({dir, slug, title?, body}) -> {path, hash}`.
///
/// `dir` is the garden-relative path of an accretive folder (its basename
/// must be `notes` or `troubleshooting`). The daemon assigns the next
/// number from the folder's `.seq` high-water mark, writes
/// `dir/NNN-slug.md`, and stamps the `# <title>` header + `> Last
/// reviewed:` line — the caller supplies only the slug, an optional title
/// (defaults to the slug), and the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddNoteArgs {
    /// Garden-relative accretive folder, e.g. `services/waydroid/notes`.
    pub dir: String,
    /// `[a-z0-9-]+`, length 1–64. The terse filename address; immutable.
    pub slug: String,
    /// Human title used in the `# <title>` header. Defaults to the slug.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Markdown body written below the daemon-stamped header.
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddNoteReply {
    /// Garden-relative path the daemon wrote (`dir/NNN-slug.md`).
    pub path: String,
    pub hash: String,
}

/// `revise_note({dir, id, body}) -> {path, hash}`. Replace the body of
/// `dir/NNN-*.md` (the note numbered `id`), re-stamping the reviewed date.
/// The header (title), slug, and number are left untouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviseNoteArgs {
    pub dir: String,
    /// The note's creation-order number (the `NNN` in its filename).
    pub id: u32,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviseNoteReply {
    pub path: String,
    pub hash: String,
}

// ---- Slice 2 (small-files): universal section editing ------------------

/// `add_section({path, heading, body}) -> {path, hash}`. Append a brand-new
/// section to the end of `path`. `heading` is the section's heading text
/// (matched case-sensitively, level-agnostically); include leading `#`s to
/// choose the level (defaults to `##`). Errors: heading already present
/// (`PathAlreadyExists`), target whole-file-sealed or containing an inline
/// `<vault>` region (`VaultProtected`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddSectionArgs {
    /// Garden-relative path of the markdown doc.
    pub path: String,
    /// Heading text. Leading `#`s set the level (`## Foo` → level 2); bare
    /// text defaults to `##`.
    pub heading: String,
    /// Markdown body written below the daemon-stamped heading line.
    pub body: String,
}

/// `edit_section({path, heading, body}) -> {path, hash}`. Replace the body
/// of an existing section, keeping its heading line. `heading` matches by
/// text (level-agnostic); the match must be unique. Errors: no such heading
/// (`NotFound`), ambiguous heading (`BadArgs`), vault target
/// (`VaultProtected`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditSectionArgs {
    pub path: String,
    pub heading: String,
    pub body: String,
}

/// `append_to_section({path, heading, text}) -> {path, hash}`. Add `text`
/// after the last content line of an existing section (before the next
/// heading) — the "add a row/bullet" op. Same matching + error contract as
/// `edit_section`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendToSectionArgs {
    pub path: String,
    pub heading: String,
    /// The new content to append (one or more lines, e.g. a list row).
    pub text: String,
}

/// `set_reviewed({path}) -> {path, hash}`. Rewrite the doc's `Last
/// reviewed:` line (optionally `> `-quoted) to today's date. Errors: no
/// such line (`NotFound`), vault target (`VaultProtected`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetReviewedArgs {
    pub path: String,
}

/// Shared reply for the Slice 2 doc-editing verbs (`add_section`,
/// `edit_section`, `append_to_section`, `set_reviewed`): the daemon owns
/// every mechanical field, so the caller only learns where it landed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocEditReply {
    /// Garden-relative path the daemon rewrote.
    pub path: String,
    pub hash: String,
}

/// `archive({src, archive_name?}) -> {from, to, hash}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveArgs {
    /// Garden-relative path of the file or directory to archive.
    pub src: String,
    /// Single path component naming the archive bucket under
    /// `journal/archive/<archive_name>/`. Defaults to the basename of
    /// `src`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveReply {
    /// Source path (garden-relative) that was moved.
    pub from: String,
    /// Destination path (garden-relative) it now lives at.
    pub to: String,
    pub hash: String,
}

/// `add_project({name, repo_path?, summary?}) -> {path, hash, files}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddProjectArgs {
    /// `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, length 1–64. Becomes
    /// `projects/<name>/`.
    pub name: String,
    /// Absolute path of the real code repo, inlined into the `CLAUDE.md`
    /// stub when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_path: Option<String>,
    /// One-line description stamped into the stubs when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddProjectReply {
    /// The created `projects/<name>/` directory (garden-relative).
    pub path: String,
    pub hash: String,
    /// The four reserved-name stub files written, garden-relative.
    pub files: Vec<String>,
}

/// `refresh_snapshot({path, content}) -> {path, hash}`. Path must lie
/// under `snapshots/` and its parent dir must already exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSnapshotArgs {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSnapshotReply {
    pub path: String,
    pub hash: String,
}

// ---- M3b: read-only browse surface ------------------------------------

/// `list_tree({path?}) -> {entries}`. Lists the immediate children of a
/// garden-relative directory in the committed tip tree. `path` omitted (or
/// empty) means the garden root.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListTreeArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTreeReply {
    pub entries: Vec<TreeEntry>,
}

/// One child of a directory listing. `path` is the full garden-relative
/// path of the entry (e.g. `journal/decisions`), suitable for feeding back
/// into `list_tree`/`read_file`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
}

/// `read_file({path}) -> {path, content, sealed}`. Returns the file's
/// daemon-redacted content from the committed tip tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileArgs {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFileReply {
    pub path: String,
    /// Daemon-redacted UTF-8 content: whole-file-sealed paths surface as
    /// `[sealed:<path>]`, inline `<vault id="…">` regions as `[encrypted]`.
    /// Never raw ciphertext or sealed plaintext. Non-UTF-8 content is
    /// replaced by a short placeholder; very large files are truncated.
    pub content: String,
    /// True when the whole file is sealed (Layer B).
    pub sealed: bool,
}

// ---- M5a-4: network pairing (transport + trust ring) ------------------

/// `pair_begin({fingerprint, endpoint?}) -> {pairing_id, sas, fingerprint,
/// name}`. The daemon connects to the peer (LAN-direct TCP), runs the Noise
/// `XX` pairing handshake, verifies the peer's attestation, derives the SAS,
/// and parks the live session keyed by `pairing_id`. The caller shows the SAS
/// to the user, who confirms it matches the peer device, then calls
/// `pair_confirm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairBeginArgs {
    /// The target device's Ed25519 identity fingerprint (lowercase hex), full
    /// or a unique prefix. Used to resolve the endpoint from mDNS discovery and
    /// to verify the peer that answers is the intended one.
    pub fingerprint: String,
    /// Explicit `host:port` to dial, overriding mDNS discovery. Required while
    /// the peer is not yet discoverable (e.g. headless / no multicast).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairBeginReply {
    /// Opaque handle for the parked pairing; pass to `pair_confirm`.
    pub pairing_id: String,
    /// The SAS short code, grouped `"XXX XXX"`, to compare with the peer.
    pub sas: String,
    /// The peer's actual device-id fingerprint (lowercase hex), as
    /// authenticated by the handshake.
    pub fingerprint: String,
    /// The peer's advertised device name.
    pub name: String,
}

/// `pair_confirm({pairing_id}) -> {fingerprint, name}`. The user confirmed the
/// SAS matched; persist the parked peer into the ring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairConfirmArgs {
    pub pairing_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairConfirmReply {
    pub fingerprint: String,
    pub name: String,
}

/// `pair_list({}) -> {peers, pending}`. Read-only listing of the network trust
/// ring plus any pairings awaiting SAS confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PairListArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairListReply {
    pub peers: Vec<PairPeer>,
    /// Pairings whose handshake completed but whose SAS the user has not yet
    /// confirmed (initiator-side from `pair_begin`, or responder-side parked by
    /// the inbound listener). Confirm with `pair_confirm`.
    #[serde(default)]
    pub pending: Vec<PendingPairing>,
}

/// One parked pairing awaiting confirmation, as surfaced to `softfig peers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPairing {
    pub pairing_id: String,
    /// SAS short code, grouped `"XXX XXX"`, to compare with the peer.
    pub sas: String,
    pub fingerprint: String,
    pub name: String,
}

/// One ring member, as surfaced to `softfig peers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairPeer {
    /// Device-id fingerprint (lowercase hex of the Ed25519 identity).
    pub fingerprint: String,
    pub name: String,
    /// X25519 transport public key (lowercase hex).
    pub transport_pubkey: String,
    /// Reachable `host:port` endpoints discovered for this peer (may be empty).
    pub endpoints: Vec<String>,
    /// When pairing happened, Unix seconds.
    pub paired_at: i64,
}

/// `pair_remove({fingerprint}) -> {removed, fingerprint}`. Unpair by device-id
/// fingerprint (full or unique prefix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRemoveArgs {
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRemoveReply {
    pub removed: bool,
    /// The full fingerprint that was matched and removed.
    pub fingerprint: String,
}

// ---- Pairing-UX Slice A: LAN pick-list --------------------------------

/// `discover_list({}) -> {devices}`. Read-only snapshot of the daemon's mDNS
/// discovery cache, filtered to devices **not yet in the ring** (and not this
/// device). The pick-list that lets a user pair by name instead of typing a
/// fingerprint. Empty when networking is off or nothing has been discovered.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoverListArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverListReply {
    pub devices: Vec<DiscoveredDevice>,
}

/// One nearby, unpaired device seen over mDNS. `name`/`endpoint` are
/// convenience hints from the broadcast — pairing still authenticates via the
/// Noise handshake + SAS, so neither is security-load-bearing; they only
/// *address* the peer for `pair_begin`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredDevice {
    /// The peer's advertised friendly name (TXT `nm`), if it published one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The peer's device-id fingerprint (lowercase hex of its Ed25519
    /// identity) — what `pair_begin` resolves and authenticates against.
    pub fingerprint: String,
    /// A reachable `host:port` to dial, if discovery resolved one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Seconds since this device was last seen on the LAN (0 = just now).
    pub last_seen_secs: u64,
}

// ---- M5b: replication (zero-knowledge device-chain backup) ------------

/// `replica_grant({fingerprint}) -> {fingerprint, granted}`. Add a ring member
/// (by device-id fingerprint, full or unique prefix) to the owner's `push_to`
/// allow-list, authorizing it to host this device's chain backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaGrantArgs {
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaGrantReply {
    /// The full fingerprint that was matched and granted.
    pub fingerprint: String,
    /// False when it was already granted (idempotent no-op).
    pub granted: bool,
}

/// `replica_revoke({fingerprint}) -> {fingerprint, revoked}`. Remove a host from
/// `push_to`. Stops future pushes; the host keeps any ciphertext already sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaRevokeArgs {
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaRevokeReply {
    pub fingerprint: String,
    /// False when it was not in the allow-list (idempotent no-op).
    pub revoked: bool,
}

/// `replica_status({}) -> {host, push_to, hosted}`. Backup-health metadata only.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplicaStatusArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaStatusReply {
    /// Whether this device hosts backups (`[replica] host`).
    pub host: bool,
    /// Device-id fingerprints this device pushes its chain to (`push_to`).
    pub push_to: Vec<String>,
    /// Per-peer mirror stats for chains this device hosts (empty unless `host`).
    pub hosted: Vec<HostedChain>,
}

/// One peer chain this device mirrors, as surfaced to `softfig replica status`.
/// Metadata only — the mirror is opaque ciphertext this device cannot read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedChain {
    /// The owner's device-id fingerprint (lowercase hex of its Ed25519 identity).
    pub fingerprint: String,
    /// The owner's advertised name, if known from the ring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The mirror's current tip commit hash (hex), or null if nothing synced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip: Option<String>,
    /// Chain height (commit count) at the mirror's tip.
    pub height: u64,
    /// Number of ciphertext objects stored in the mirror.
    pub objects: u64,
    /// Total bytes of stored ciphertext objects.
    pub bytes: u64,
    /// Unix seconds of the last successful sync, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<i64>,
}

/// `migrate split [--apply]` — one-time monolith → numbered-notes splitter.
/// Dry-run (preview only, no writes) unless `apply` is set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MigrateSplitArgs {
    /// Commit the split. Without it the daemon only discovers + plans.
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateSplitReply {
    /// True when the splits were committed; false for a dry-run preview.
    pub applied: bool,
    /// One entry per monolith that was (or would be) split.
    pub splits: Vec<SplitOutcome>,
    /// Monoliths found but not split, with the reason (already-migrated
    /// folder, no `## ` sections, read error).
    pub skipped: Vec<SplitSkip>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitOutcome {
    /// Garden-relative monolith path (e.g. `projects/foo/notes.md`).
    pub from: String,
    /// Garden-relative accretive folder it split into (e.g.
    /// `projects/foo/notes`).
    pub folder: String,
    /// Number of numbered notes produced.
    pub notes: usize,
    /// Where the monolith was archived. `None` in a dry-run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_to: Option<String>,
    /// Hash of the `monolith_split` commit. `None` in a dry-run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitSkip {
    pub path: String,
    pub reason: String,
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

// ---- growlight Phase 1: the work-loop pillar verbs ---------------------

/// `log_baton({item, iteration, summary, ...}) -> {path, hash}`. Append a
/// numbered audit entry to `growlight/baton-log/`. The daemon assigns the
/// number from the folder's `.seq` high-water mark, derives the filename
/// slug (`<item>-iter-<iteration>` unless `slug` is given), and stamps the
/// iteration-metadata header above `summary`. Audit-only; never injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogBatonArgs {
    /// Backlog item id this iteration worked (milestone id or task `NNN`).
    pub item: String,
    /// Monotonic iteration counter carried by the baton.
    pub iteration: u32,
    /// What shipped this iteration + pointers (the entry body).
    pub summary: String,
    /// `milestone | task`; informational. Defaults to `milestone`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_type: Option<String>,
    /// Active slice id (milestones only); `None` for tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<String>,
    /// Loop status at handoff (`IN_PROGRESS`, `HALTED_RATE_LIMIT`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Last observed context-window used %.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctx_pct: Option<u32>,
    /// Last observed 5h-session rate used %.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_5h_pct: Option<u32>,
    /// Override the derived filename slug (`[a-z0-9-]+`, 1–64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogBatonReply {
    /// Garden-relative path the daemon wrote (`growlight/baton-log/NNN-slug.md`).
    pub path: String,
    pub hash: String,
}

/// `add_backlog_item({item_type, slug, title, mission, finish_criteria}) ->
/// {id, path, hash}`. Seed a milestone or task and enqueue it (`queued`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddBacklogItemArgs {
    /// `milestone | task`.
    pub item_type: String,
    /// `[a-z0-9-]+`, 1–64. For a milestone this is its id + dir name
    /// (`milestones/<slug>/`); for a task it's the filename slug under
    /// `tasks/` (the daemon assigns the task's numeric id).
    pub slug: String,
    /// Human title shown in the queue table + the item doc heading.
    pub title: String,
    /// Why this item exists (the item doc's `## Mission`).
    pub mission: String,
    /// Checkable completion criteria (the item doc's `## Finish criteria`).
    pub finish_criteria: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddBacklogItemReply {
    /// The item's queue id (milestone slug, or the task's `NNN`).
    pub id: String,
    /// Garden-relative path of the item's main doc.
    pub path: String,
    pub hash: String,
}

/// `add_slice({milestone, slug, title?, body}) -> {path, hash}`. Append a
/// numbered slice doc under an existing milestone and refresh its slices
/// index. The daemon assigns the slice number from `slices/.seq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddSliceArgs {
    /// The owning milestone's id (its `milestones/<id>/` dir name).
    pub milestone: String,
    /// `[a-z0-9-]+`, 1–64; the slice's terse filename address.
    pub slug: String,
    /// Slice heading title. Defaults to the slug.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The slice's plan/spec markdown body.
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddSliceReply {
    /// Garden-relative path the daemon wrote.
    pub path: String,
    pub hash: String,
}

/// `set_item_status({id, status}) -> {id, status, path, hash}`. Flip a
/// backlog item's status cell in the authoritative queue table. Setting
/// `active` is refused when a different item is already `active`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetItemStatusArgs {
    /// The item's queue id (milestone slug or task `NNN`).
    pub id: String,
    /// `queued | active | done | blocked`.
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetItemStatusReply {
    pub id: String,
    pub status: String,
    /// The queue doc the daemon rewrote (`growlight/backlog/CLAUDE.md`).
    pub path: String,
    pub hash: String,
}

/// `growlight_init({}) -> {created, skipped, nav_wired, committed, hash}`.
/// Scaffold the `growlight/` pillar (Phase 2). Idempotent: only writes what's
/// missing, so a re-run on an already-set-up garden creates nothing and makes
/// no commit.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrowlightInitArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowlightInitReply {
    /// Garden-relative pillar paths newly created this run.
    pub created: Vec<String>,
    /// Pillar paths already present, left untouched.
    pub skipped: Vec<String>,
    /// Existing nav docs the daemon edited (root `CLAUDE.md`, `meta/*`).
    pub nav_wired: Vec<String>,
    /// False on a fully-idempotent re-run (nothing changed, no commit).
    pub committed: bool,
    /// The resulting commit hash, or the current tip if nothing changed.
    pub hash: String,
}
