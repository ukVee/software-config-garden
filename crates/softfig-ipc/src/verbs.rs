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
    /// Config-in-garden: one-time migration that lifts the post-unlock policy
    /// (`[net]`/`[relay]`/`[replica]`/`[reveal]`) out of the local `.softfig/`
    /// pointer into the encrypted, versioned, backed-up `config/keeper.toml`
    /// inside the garden, committing `config_migrated`. Dry-run unless `apply`.
    pub const MIGRATE_CONFIG: &str = "migrate_config";
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
    /// Task 020 (code-review records): append a numbered code-review record
    /// `NNN-slug.md` to a `code-reviews/` accretive folder (primary home
    /// `projects/<project>/code-reviews/`). Same daemon-stamped machinery as
    /// `add_note` (`.seq` numbering, header + reviewed line, parent index +
    /// backlinks); commit `code_review_added`.
    pub const ADD_CODE_REVIEW: &str = "add_code_review";
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
    /// Phase 3 (garden CAS, §4d): provenance for a garden path — who/when last
    /// edited it + the recent edit history — derived from committed commit data
    /// (author_device, timestamp, intent) by walking the chain and diffing the
    /// path's blob across each commit. Read-only; never touches the mount.
    pub const FILE_PROVENANCE: &str = "file_provenance";
    /// 020 slice 002 (finding #5): serve the backlog queue as structured rows,
    /// parsed daemon-side by the authoritative queue-table parser that owns the
    /// `\|` cell escape — so a frontend renders rows directly instead of
    /// re-splitting the managed `<!-- softfig:queue -->` table (which mis-handles
    /// a piped title and loses the active item). Only the default queue is
    /// returned. Read-only; require Unlocked.
    pub const GROWLIGHT_QUEUE: &str = "growlight_queue";
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
    /// M5c slice 003: register a new shared subtree — validate the mount path,
    /// append the membership row to `config/shared-subtrees.toml`, create the
    /// chain's genesis ref so the union mount can compose it, and live-recompose.
    /// Commit `shared_subtrees_changed`. The collaborative key ceremony is the
    /// stubbed m5d hook (no real `S` is wired here).
    pub const SHARED_SUBTREE_ADD: &str = "shared_subtree_add";
    /// M5c slice 003: un-share a subtree — drop its membership row + commit
    /// `shared_subtrees_changed` + live-recompose. Leaves the chain ref/objects
    /// in place (gc reclaims them later).
    pub const SHARED_SUBTREE_REMOVE: &str = "shared_subtree_remove";
    /// M5c slice 003: re-enable a subtree on THIS device — clear its id from the
    /// never-committed `.softfig/shared-subtrees-local.toml` sidecar + live-
    /// recompose. No commit, no ceremony, no membership change.
    pub const SHARED_SUBTREE_ENABLE: &str = "shared_subtree_enable";
    /// M5c slice 003: disable a subtree on THIS device — add its id to the local
    /// sidecar + live-recompose (its subtree falls back to the device chain). No
    /// commit, no ceremony, no membership change — the headline "easy on/off".
    pub const SHARED_SUBTREE_DISABLE: &str = "shared_subtree_disable";
    /// M5c slice 003: list every shared-subtree member with its per-device
    /// enabled state. Read-only.
    pub const SHARED_SUBTREE_LIST: &str = "shared_subtree_list";
    /// M5f slice 003: accept a device-local pending share-offer at THIS device's
    /// chosen mount path (default = the sharer's advisory `recommended_path`).
    /// Runs the add-time placement guards locally against this garden, appends
    /// the membership row (key ceremony deferred to the reconcile sweep — until
    /// keyed the mount accepts no content, composing with slice 001), and
    /// consumes the offer. Commit `shared_subtrees_changed`.
    pub const SHARED_SUBTREE_ACCEPT: &str = "shared_subtree_accept";
    /// M5f slice 004: migrate existing DEVICE-chain content at a garden path into
    /// an already-**keyed** shared chain (the explicit, only M→S path — refused
    /// on an unkeyed chain). Re-encrypts each blob under the share's `S` and
    /// re-homes it under the share's mount as two ordered commits — the shared
    /// add first (durable), then the device-side carve-out — so an interrupted
    /// migrate leaves the content in both chains, never neither. Commits
    /// `migrate_into_share` (share) + `migrate_into_share_carve` (device).
    pub const MIGRATE_INTO_SHARE: &str = "migrate_into_share";
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
    /// growlight Phase 4: register a named work-stream queue with a bound repo
    /// path (the fleet scheduler's multi-queue model, spec orchestrator §6).
    /// Seeds the registry + an empty per-queue item table in
    /// `growlight/backlog/CLAUDE.md`. Commit `queue_added`.
    pub const ADD_QUEUE: &str = "add_queue";
    /// growlight Phase 1: append a numbered slice under a milestone
    /// (`growlight/backlog/milestones/<id>/slices/NNN-<slug>.md`) and refresh
    /// the milestone's slices index. Commit `slice_added`.
    pub const ADD_SLICE: &str = "add_slice";
    /// growlight Phase 1: set a backlog item's status (`queued|active|done|
    /// blocked`) by flipping its cell in the authoritative queue table in
    /// `growlight/backlog/CLAUDE.md` (enforces at most one `active`). Commit
    /// `item_status_set`.
    pub const SET_ITEM_STATUS: &str = "set_item_status";
    /// growlight: move a backlog item's row in the authoritative queue table in
    /// `growlight/backlog/CLAUDE.md` (`top|bottom|before|after`) WITHOUT touching
    /// its status. Reprioritizes the drain order; the `#` column re-renders to
    /// match. Idempotent (a no-op move makes no commit). Commit
    /// `backlog_item_reordered`.
    pub const REORDER_BACKLOG_ITEM: &str = "reorder_backlog_item";
    /// growlight Phase 2: scaffold the `growlight/` pillar — write the routing
    /// docs + embedded `protocol.md`/`session-policy.md` + the backlog/baton-log
    /// skeleton, and wire the garden nav (root map + boundary row + meta docs).
    /// Idempotent retrofit; one `growlight_initialized` commit, or none if the
    /// pillar already exists. Mirrors `migrate split`.
    pub const GROWLIGHT_INIT: &str = "growlight_init";
    /// growlight peer-isolation slice 003: persist the live GENTLE build-resource
    /// caps default into the in-garden `config/growlight.toml` `[build_caps]`
    /// table. A daemon-mediated, surgical `toml_edit` update (the table is
    /// created if absent; comments + the rest of the fleet config preserved);
    /// one `growlight_resources_set` commit, or none if the caps are unchanged.
    /// keeperd↔growlightd only (growlightd calls it best-effort after a live
    /// `set_resources`), never an agent-facing MCP verb.
    ///
    /// Naming (slice 008, all intentional — NOT a cross-wire): this keeperd op is
    /// `growlight_set_resources`, but its commit *intent* is spelled
    /// `growlight_resources_set` (verb-last); and it is distinct from growlightd's
    /// own client-facing `set_resources` verb ([`crate::growlightd::op::SET_RESOURCES`])
    /// — growlightd handles the live push, then calls THIS to persist.
    pub const GROWLIGHT_SET_RESOURCES: &str = "growlight_set_resources";
    /// growlight Phase 2: post a message to the coordination bus — append a
    /// numbered message under `growlight/chat/messages/` addressed to an agent
    /// slug, `@all`, or `@human`. The daemon numbers it + stamps the wall-clock
    /// `ts`. Mirrors `log_baton`; one `chat_message_posted` commit.
    pub const POST_MESSAGE: &str = "post_message";
    /// growlight Phase 2: read an agent's unread bus inbox — its lane messages
    /// numbered above its stored cursor, in order — and advance the cursor past
    /// them. One `inbox_read` commit when the cursor moves; none if empty.
    pub const READ_INBOX: &str = "read_inbox";
    /// growlight Phase 2 (bus bridge, slice 003): tail the coordination bus for
    /// the orchestrator daemon (growlightd). Returns every bus message numbered
    /// above `since`, in total order — the WHOLE channel (`@all`/`@human`/direct
    /// alike), not a per-agent lane — as a pure read: no cursor advance, no
    /// commit (mirrors `read_file`/`list_tree`). growlightd polls this and
    /// republishes each as a `subscribe` `Event::BusMessage`. keeperd↔growlightd
    /// only, never an agent-facing MCP verb.
    pub const TAIL_BUS: &str = "tail_bus";
    /// Growlight relock: mint a one-time token wrapping the live KEK so an
    /// unattended daemon restart can resume this session. Requires Unlocked +
    /// `[growlight] allow_relock = true`. `persist=true` (cycle and relock-arm)
    /// writes the token to a `0600` tmpfs file and returns the path; the redeem
    /// reads it server-side. `persist=false` returns the token hex in the reply
    /// for an in-RAM redeem. Commit-free; CLI-over-IPC, never MCP.
    pub const RELOCK_MINT: &str = "relock_mint";
    /// Growlight relock: redeem a minted token + its tmpfs blob to rebuild the
    /// session on a freshly-restarted (Locked) daemon. `cycle`/`relock` pass
    /// nothing and the daemon reads its own persisted token file; passing the
    /// token hex redeems an in-RAM token. Single-use: the blob is deleted on
    /// success.
    pub const RELOCK_REDEEM: &str = "relock_redeem";
    /// growlight Phase 4 (coordination, spec §4c/§14): agent-facing
    /// `request_lease` — ask the supervisor to arbitrate a lease over a shared
    /// resource/action (the lease `key`). keeperd does not decide; it forwards
    /// to growlightd (which owns the `LeaseTable`) and relays the `LeaseReply`.
    /// The FIRST keeperd→growlightd call (the bus bridge is the other
    /// direction). Commit-free — leases are ephemeral in-memory state.
    pub const REQUEST_LEASE: &str = "request_lease";
    /// growlight Phase 4 (coordination): agent-facing `release_lease` — release a
    /// held lease, promoting the head waiter. Forwarded keeperd→growlightd like
    /// [`REQUEST_LEASE`]; a release by a non-holder comes back `denied`.
    pub const RELEASE_LEASE: &str = "release_lease";
    /// M4 deploy (TUI Deploy tab): compute the deploy plan — a read-only diff of
    /// `config/deploy.toml` against the live filesystem. The daemon runs
    /// `softfig-deploy`'s `plan` against the unlocked garden mount so a frontend
    /// (the TUI) never touches the filesystem itself. Require Unlocked; no
    /// mutation, no commit. Mirrors `softfig deploy --dry-run`.
    pub const DEPLOY_PLAN: &str = "deploy_plan";
    /// M4 deploy (TUI Deploy tab): materialize the plan onto the filesystem
    /// (deploy-cache + targets) via `softfig-deploy`'s `apply`, returning the
    /// `Report`. `force` backs up a conflicting target to `<target>.softfig-bak`.
    /// Require Unlocked. A native-FS op, not a VCS event (M4a defers that) — so
    /// no commit. Mirrors `softfig deploy [--force]`.
    pub const DEPLOY_APPLY: &str = "deploy_apply";
    /// M5e slice 004 (TUI Coordination tab): read the daemon's live write-turn +
    /// device-state coordination snapshot — the turn holder per shared chain, the
    /// local device state, and each peer's announced state. Read-only, no args, no
    /// mutation, no commit; this state lives only in the running daemon (not in any
    /// committed file, so `list_tree`/`read_file` can't reach it) and is cleared on
    /// lock, so Require Unlocked. v1 exposes the turn HOLDER only (queue depth
    /// deferred). Device ids are hex; names are resolved frontend-side via the ring.
    pub const COORDINATION_STATUS: &str = "coordination_status";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReply {
    /// "locked" or "unlocked".
    pub state: String,
    /// Hex tip-commit hash, or null if no commits yet.
    pub tip: Option<String>,
    pub garden_root: String,
    pub protocol_version: u8,
    /// Growlight: true when an unexpired relock token is armed for this garden
    /// (a `cycle`/`relock-arm` is in flight). `#[serde(default)]` keeps older
    /// daemons/clients wire-compatible.
    #[serde(default)]
    pub relock_pending: bool,
    /// Unix seconds at which the armed relock token expires, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relock_expires_at: Option<i64>,
    /// Daemon-owned growlight gate: the fail-closed `fleet_enabled()` value the
    /// keeperd already owns, surfaced so a client never re-derives it from
    /// file-presence and disagrees. Refreshes on every status tick.
    /// `#[serde(default)]` keeps older daemons/clients wire-compatible
    /// (an absent field ⇒ `false`, i.e. no tab — the fail-closed default).
    #[serde(default)]
    pub growlight_enabled: bool,
    /// M5d slice 006: the most recent shared-key ceremony divergence message, if
    /// any — a completed ceremony that met a chain already keyed with a
    /// *different* key (the one-key-per-chain invariant violated; with
    /// S-encryption live this otherwise presents as silent chain corruption).
    /// `None` in the healthy case. Surfaced here so a divergence is visible, not
    /// stderr-only. `#[serde(default)]` keeps older daemons/clients compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_key_divergence: Option<String>,
}

// ---- growlight relock token -------------------------------------------

/// `relock_mint({persist}) -> RelockMintReply`. Mint a one-time token wrapping
/// the live KEK. Requires Unlocked + `[growlight] allow_relock`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelockMintArgs {
    /// `true` (cycle and relock-arm): persist the token to a `0600` tmpfs file
    /// and return its path; the redeem reads it server-side, and an aborted
    /// caller can still recover via `softfig daemon relock`. `false`: return the
    /// token hex in the reply for an in-RAM redeem (no on-disk copy, but an
    /// aborted caller loses the token — see incident 20260622).
    #[serde(default)]
    pub persist: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelockMintReply {
    /// Whether the token was persisted to disk (`persist=true`).
    pub persisted: bool,
    /// Unix seconds at which the token expires.
    pub expires_at: i64,
    /// Absolute tmpfs path of the wrapped-KEK blob (the redeem reads this).
    pub blob_path: String,
    /// The token, lowercase hex — present only when `persisted=false`. Lets a
    /// caller redeem from RAM with no on-disk copy; `cycle`/`relock-arm` instead
    /// persist (recoverable on abort) and leave this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Absolute tmpfs path of the persisted token — present only when
    /// `persisted=true` (relock-arm). The redeem reads it server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_path: Option<String>,
}

/// `relock_redeem({token?}) -> RelockRedeemReply`. Rebuild the session on a
/// Locked daemon. `token` present = cycle (hex held in CLI RAM); `token`
/// absent = relock (the daemon reads its own persisted token file).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelockRedeemArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelockRedeemReply {
    /// "unlocked" on success.
    pub state: String,
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
    /// Phase 3 CAS (optional): the whole-file content version the caller based
    /// this rewrite on. When set, the daemon applies only if the file still
    /// has that version (and still exists); else it returns `Conflict` so the
    /// caller re-reads. Omit for unconditional last-writer-wins (the legacy
    /// behaviour, also the create-if-absent path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaceFileReply {
    /// Garden-relative path the daemon wrote.
    pub path: String,
    pub hash: String,
    /// The whole-file content version after the write — feed it back as the
    /// next `expected_version` to chain CAS-guarded rewrites without re-reading.
    #[serde(default)]
    pub version: String,
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

// ---- task 020: code-review records --------------------------------------

/// `add_code_review({dir, slug, title?, body}) -> {path, hash}`.
///
/// The code-review sibling of `add_note`: `dir` is the garden-relative path
/// of an accretive folder whose basename must be `code-reviews` (primary
/// home `projects/<project>/code-reviews/`). The daemon assigns the next
/// number from the folder's `.seq` high-water mark, writes `dir/NNN-slug.md`,
/// and stamps the `# <title>` header + `> Last reviewed:` line. The body is
/// the caller's review markdown (see the review template in the garden's
/// code-review-records decision file); the daemon never parses it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddCodeReviewArgs {
    /// Garden-relative `code-reviews/` folder, e.g.
    /// `projects/software-config_garden/code-reviews`.
    pub dir: String,
    /// `[a-z0-9-]+`, length 1–64. The terse filename address; immutable.
    pub slug: String,
    /// Human title used in the `# <title>` header. Defaults to the slug.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Markdown review body written below the daemon-stamped header.
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddCodeReviewReply {
    /// Garden-relative path the daemon wrote (`dir/NNN-slug.md`).
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
    /// Phase 3 CAS (optional): the addressed section's content version the
    /// caller read. When set, the daemon applies only if that section is still
    /// unchanged; else it returns `Conflict`. Editing a *different* section of
    /// the same file never conflicts (versions are per-section). Omit for
    /// unconditional last-writer-wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
    /// Phase 3 thrash detection (optional): the per-agent editor identity, fed
    /// to the daemon's ping-pong detector (spec §4d). Absent → a generic
    /// `"anon"`, so a single-editor loop never self-trips; the concurrent fleet
    /// (phase 6) passes real per-agent slugs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,
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
    /// Phase 3 CAS (optional): the addressed section's content version the
    /// caller read; see [`EditSectionArgs::expected_version`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
    /// Phase 3 thrash detection (optional): the per-agent editor identity; see
    /// [`EditSectionArgs::editor`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,
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
    /// Phase 3 CAS: the content version of the affected target *after* the
    /// edit. For the section verbs it's the addressed section's new version
    /// (feed it back as the next `expected_version`); for `set_reviewed` it's
    /// the whole-file version. `#[serde(default)]` keeps older clients
    /// wire-compatible.
    #[serde(default)]
    pub version: String,
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

/// `read_file({path}) -> {path, content, sealed, version, sections, region_ids}`.
/// Returns the file's daemon-redacted content from the committed tip tree.
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
    /// Phase 3 CAS: whole-file content version of the (redacted) content —
    /// pass to `replace_file`'s `expected_version`. `#[serde(default)]` keeps
    /// older clients/daemons wire-compatible.
    #[serde(default)]
    pub version: String,
    /// Phase 3 CAS: per-section content versions for every addressable ATX
    /// heading, in document order. Pick the one for the heading you intend to
    /// edit and pass it as the section verb's `expected_version`. Empty for
    /// sealed / non-markdown / sectionless content.
    #[serde(default)]
    pub sections: Vec<SectionVersion>,
    /// M2c (020 slice 003): the ids of the file's inline `<vault id="…">`
    /// *sealed* regions — those projected as `[encrypted]` and revealable via
    /// `vault_reveal --id`. Computed daemon-side with the authoritative region
    /// grammar (`layer_b/regions.rs`), in document order; a frontend consumes
    /// these directly instead of re-parsing the projected content (which can't
    /// tell a real region from an inline-code `<vault>` mention). Empty for
    /// sealed / non-region / malformed content. `#[serde(default)]` keeps older
    /// clients/daemons wire-compatible.
    #[serde(default)]
    pub region_ids: Vec<String>,
}

/// One addressable section's CAS handle: its heading text + current content
/// version. Surfaced by `read_file` so a caller can guard a section edit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionVersion {
    /// The heading text (no leading `#`s), as `edit_section`/`append_to_section`
    /// address it.
    pub heading: String,
    /// The section's content version (heading line + body).
    pub version: String,
}

/// `growlight_queue() -> {rows}` (020 slice 002, finding #5). The default
/// backlog queue parsed daemon-side with the authoritative table parser that
/// owns the `\|` cell escape, so a frontend renders structured rows and never
/// re-splits the managed `<!-- softfig:queue -->` table itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowlightQueueReply {
    pub rows: Vec<GrowlightQueueRow>,
}

/// One backlog item's authoritative queue state, as served over the wire: its
/// id, title, and status. A title carrying a literal `|` round-trips intact
/// (the daemon un-escapes the `\|` cell escape); the frontend never
/// string-parses the table, so the active item is always found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrowlightQueueRow {
    pub id: String,
    pub title: String,
    pub status: String,
}

// ---- Phase 3 (garden CAS §4d): file provenance ------------------------

/// `file_provenance({path, limit?}) -> {path, edits}`. Who/when last edited a
/// garden path, plus its recent edit history — the §4d awareness query. Pure
/// read over committed commit data (no mount I/O): the daemon walks the commit
/// chain and reports each commit whose tree changed `path`'s blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProvenanceArgs {
    /// Garden-relative path to trace.
    pub path: String,
    /// Cap on how many recent edits to return (most-recent first). 0 / omitted
    /// uses the daemon default.
    #[serde(default)]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProvenanceReply {
    /// The traced garden-relative path.
    pub path: String,
    /// Edits that changed this path's content, most recent first. Empty when
    /// the path has never been committed. `edits[0]` is the last editor.
    pub edits: Vec<ProvenanceEntry>,
}

/// One commit that changed the traced path's blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceEntry {
    /// The commit hash (hex).
    pub hash: String,
    /// The committing device's id (the "who").
    pub author_device: String,
    /// Unix seconds of the commit (the "when").
    pub timestamp: i64,
    /// The commit intent (the "what kind", e.g. `section_edited`, `memory_edit`).
    pub intent: String,
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

// ---- M5e slice 004: coordination-status read ------------------------------

/// `coordination_status({}) -> {local_device_id, local_state, peers, turns}`.
/// A read-only snapshot of the daemon's live write-turn + device-state
/// coordination surface (the TUI Coordination tab renders it). Device ids are
/// lowercase hex; frontends resolve them to names via the peer ring.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoordinationStatusArgs {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoordinationStatusReply {
    /// This device's own id (hex of its Ed25519 identity pubkey).
    pub local_device_id: String,
    /// This device's coordination state: `offline` / `online-idle` / `online-active`.
    pub local_state: String,
    /// Each peer's most-recently-announced coordination state, sorted by device id.
    pub peers: Vec<PeerCoordRow>,
    /// The current write-turn holder per shared chain, sorted by chain ref name.
    pub turns: Vec<TurnCoordRow>,
}

/// One peer's announced coordination state (from `DaemonInner::peer_states`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCoordRow {
    /// The peer's device id (lowercase hex).
    pub device_id: String,
    /// The peer's announced state: `offline` / `online-idle` / `online-active`.
    pub state: String,
}

/// The write-turn holder for one shared chain (from `DaemonInner::write_turns`).
/// v1 exposes the holder only; the waiter queue depth is deferred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnCoordRow {
    /// The shared chain's ref name (its `write_turns` map key).
    pub chain: String,
    /// The current turn holder's device id (hex), or null when the turn is free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_device_id: Option<String>,
}

// ---- M5c slice 003: shared-subtree lifecycle -------------------------------

/// `shared_subtree_add({mount_path, id?}) -> {id, mount_path, ref_name}`. Register
/// a new shared subtree (ring membership); the daemon validates the mount path,
/// assigns an id (derived from `mount_path` when omitted), and creates the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeAddArgs {
    /// Garden-relative mount prefix to share, `/`-separated (e.g. `projects/journals`).
    pub mount_path: String,
    /// Stable id for the share; when absent the daemon derives one from
    /// `mount_path`'s last component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeAddReply {
    /// The id assigned to the new share.
    pub id: String,
    /// The garden-relative mount prefix that was registered.
    pub mount_path: String,
    /// The `refs`-table ref holding the new chain's tip (`chain/<id>`).
    pub ref_name: String,
}

/// `shared_subtree_remove({id}) -> {id, removed}`. Drop a share's membership row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeRemoveArgs {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeRemoveReply {
    pub id: String,
    /// False when no member had this id (idempotent no-op).
    pub removed: bool,
}

/// `shared_subtree_enable`/`disable({id}) -> {id, enabled, changed}`. Flip the
/// per-device local toggle only — never the committed membership or `key_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeToggleArgs {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeToggleReply {
    pub id: String,
    /// The resulting per-device state (`true` = enabled on this device).
    pub enabled: bool,
    /// False when the toggle was already in this state (idempotent no-op).
    pub changed: bool,
}

/// `shared_subtree_list({}) -> {subtrees}`. Every member + its per-device state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharedSubtreeListArgs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeListReply {
    pub subtrees: Vec<SharedSubtreeInfo>,
}

/// One shared-subtree member as surfaced to `softfig shared-subtree list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeInfo {
    pub id: String,
    pub mount_path: String,
    pub ref_name: String,
    /// Per-device enabled state (`!local.is_disabled(id)`).
    pub enabled: bool,
    /// The collaborative key id — a placeholder (`None`) until m5d.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// `shared_subtree_accept({id, mount_path?}) -> {id, mount_path, ref_name,
/// already_accepted}`. Accept a device-local pending share-offer at a placement
/// of this device's own choosing (default = the offer's advisory
/// `recommended_path`). Placement is per-device state and never crosses the wire
/// ([[decision-shared-subtree-recipient-placement]]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeAcceptArgs {
    /// The offered share's id (as fanned by the sharer).
    pub id: String,
    /// Where THIS device mounts the share; defaults to the offer's
    /// `recommended_path` when omitted. Validated locally, never sent to peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSubtreeAcceptReply {
    pub id: String,
    /// The garden-relative mount prefix this device chose.
    pub mount_path: String,
    /// The `refs`-table ref holding the adopted chain's tip (`chain/<id>`).
    pub ref_name: String,
    /// True when the id was already a member (idempotent no-op; the offer was
    /// consumed and the existing placement returned).
    pub already_accepted: bool,
}

/// `migrate_into_share({id, from}) -> {id, mount_path, from, files}`. Move the
/// device-chain content at garden path `from` into the already-keyed shared
/// chain `id`, re-encrypting each blob under the share's `S`. Refused on an
/// unkeyed chain (key-before-content) and when `from` overlaps any share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateIntoShareArgs {
    /// The target share's id (must already exist and be keyed).
    pub id: String,
    /// Garden-relative device path whose content moves into the share.
    pub from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateIntoShareReply {
    /// The share the content was migrated into.
    pub id: String,
    /// This device's mount path for the share (where the content now lives).
    pub mount_path: String,
    /// The device path the content was migrated out of.
    pub from: String,
    /// How many files were re-homed into the share.
    pub files: usize,
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

/// `migrate config [--apply]` — one-time lift of the post-unlock daemon policy
/// and the trust-ring membership out of the local `.softfig/` files into the
/// in-garden `config/{keeper,peers}.toml`. Dry-run (no writes) unless `apply` is
/// set. Both files migrate in one `config_migrated` commit.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MigrateConfigArgs {
    /// Write + commit the in-garden config files. Without it the daemon only
    /// reports what it would write.
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateConfigReply {
    /// Garden-relative paths written + committed this run (in a dry-run, the
    /// paths that *would* be written). Handles the partial state where one file
    /// is already migrated and the other isn't.
    pub migrated: Vec<String>,
    /// Garden-relative paths skipped because they already exist in the garden
    /// (an idempotent re-run, or a partial earlier migration).
    pub skipped: Vec<String>,
    /// True when at least one file was written + committed (false for a dry-run
    /// preview or an all-skipped / nothing-to-migrate no-op).
    pub applied: bool,
    /// Hash of the single `config_migrated` commit. `None` in a dry-run or no-op.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
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
    /// Which named work-stream queue to enqueue into. Omitted/`default` →
    /// the implicit default queue (back-compat). A named queue must already be
    /// registered via `add_queue`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddBacklogItemReply {
    /// The item's queue id (milestone slug, or the task's `NNN`).
    pub id: String,
    /// Garden-relative path of the item's main doc.
    pub path: String,
    pub hash: String,
}

/// `add_queue({name, repo}) -> {name, repo, path, hash}`. Register a named
/// work-stream queue with a bound repo path (the fleet scheduler's multi-queue
/// model). The implicit `default` queue is never registered here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddQueueArgs {
    /// `[a-z0-9-]+`, 1–64; the queue name. `default` is reserved (implicit).
    pub name: String,
    /// The repo path the queue's parts build against (advisory; non-empty).
    pub repo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddQueueReply {
    pub name: String,
    pub repo: String,
    /// The backlog doc the daemon rewrote (`growlight/backlog/CLAUDE.md`).
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

/// `set_item_status({id, status, holder?}) -> {id, status, path, hash}`. Flip a
/// backlog item's status cell in the authoritative queue table. Setting
/// `active` is refused when a different item in the same queue is already
/// `active`, and (the holder-identity CAS) when the part is already `active`
/// under a *different* `holder` — a fleet member never double-claims a part a
/// live peer holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetItemStatusArgs {
    /// The item's queue id (milestone slug or task `NNN`).
    pub id: String,
    /// `queued | active | done | blocked`.
    pub status: String,
    /// Which queue the item lives in. Omitted → the id is located across all
    /// queues (unique today); pass it to disambiguate a cross-queue collision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// The claiming agent's id, for the holder-identity compare-and-swap on an
    /// `active` claim (milestone #40). When set, keeperd records this agent as
    /// the part's holder and refuses a later `active` claim from a *different*
    /// agent; the same holder's re-claim stays idempotent. `None` (the CLI/MCP
    /// default) opts out of the CAS — back-compat, unchanged behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetItemStatusReply {
    pub id: String,
    pub status: String,
    /// The queue doc the daemon rewrote (`growlight/backlog/CLAUDE.md`).
    pub path: String,
    pub hash: String,
}

/// `reorder_backlog_item({id, position, ref_id?}) -> {id, index, path, hash}`.
/// Move an item's row in the queue table without changing its status. Order is
/// the round-tripped row order of the managed `queue` region, so the move just
/// relocates the row and the `#` column re-renders to match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorderBacklogItemArgs {
    /// The item's queue id (milestone slug or task `NNN`) to move.
    pub id: String,
    /// Where to move it: `top | bottom | before | after`.
    pub position: String,
    /// The reference item's id, required for `before`/`after` and rejected for
    /// `top`/`bottom`. Must differ from `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_id: Option<String>,
    /// Which queue the item lives in (reorder is per-queue). Omitted → the id
    /// is located across all queues; pass it to disambiguate a collision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorderBacklogItemReply {
    pub id: String,
    /// The item's 1-based row number (`#` column) after the move.
    pub index: usize,
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

/// `growlight_set_resources({cargo_build_jobs?, memory_high?, cpu_weight?}) ->
/// {committed, hash, path}`. Persist the live build-resource caps default into
/// `config/growlight.toml` `[build_caps]` (peer-isolation slice 003). Each field
/// is the FULL desired state of that key: `Some` writes it, `None` removes it
/// from the table. Surgical (`toml_edit`) — the comments + `fleet_enabled` /
/// `claude_bin` / `prompt` / `[[fleet]]` are preserved, and the table is created
/// if absent. There is deliberately **no** hard-cap field (throttle-not-kill).
///
/// **`None` semantics differ from the live [`crate::growlightd::SetResourcesArgs`]**
/// (slice 008, intentional): here `None` = *remove the key* (the persisted table
/// mirrors the desired caps exactly); in the live args `None` = *leave untouched*
/// (a partial merge). They never cross because growlightd always sends the FULL
/// merged caps (every field `Some`) to this verb — so in practice the remove branch
/// is unreachable, and even a removed key would be refilled on reload from
/// `BuildCaps`'s all-`Some` default (`FleetConfig`'s `#[serde(default)]`): a cap can
/// never actually become runtime-unset (by design — there is always a throttle).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrowlightSetResourcesArgs {
    /// `CARGO_BUILD_JOBS` to persist (the parallel-`rustc` ceiling). `None` ⇒ the
    /// key is removed from `[build_caps]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_build_jobs: Option<u32>,
    /// `MemoryHigh` SOFT throttle to persist (a systemd memory value, e.g. `"3G"`).
    /// `None` ⇒ removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_high: Option<String>,
    /// `CPUWeight` to persist (1..=10000). `None` ⇒ removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_weight: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowlightSetResourcesReply {
    /// False when the surgery produced byte-identical content (an idempotent
    /// re-persist of the current caps) — no commit was minted.
    pub committed: bool,
    /// The resulting commit hash, or the current tip if nothing changed.
    pub hash: String,
    /// The garden-relative config path written (`config/growlight.toml`).
    pub path: String,
}

// ---- growlight Phase 2: the coordination bus verbs ---------------------

/// `post_message({from, to, kind, body}) -> {number, path, hash}`. Append a
/// message to the coordination bus. `to` selects the recipient lane (an agent
/// slug, `@all` to fan into every agent's lane, or `@human`); `kind` is one of
/// the six bus tokens. The daemon assigns the number and stamps `ts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageArgs {
    /// Sender: an agent slug, or `@human` (the human is a first-class member).
    pub from: String,
    /// Addressee: an agent slug, `@all` (every agent's lane), or `@human`.
    pub to: String,
    /// Message kind: `info | coord-request | lease-request | question | alert |
    /// restart-request`. An unknown token is rejected.
    pub kind: String,
    /// The message text (non-empty).
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageReply {
    /// The message's monotonic number (its total-order position on the bus).
    pub number: u32,
    /// Garden-relative path the daemon wrote (`growlight/chat/messages/NNN-…`).
    pub path: String,
    pub hash: String,
}

/// `read_inbox({agent}) -> {messages}`. The agent's unread lane messages since
/// its cursor, in total order; delivering them advances the cursor past the
/// last one (one `inbox_read` commit, or none when the inbox is empty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadInboxArgs {
    /// The reading agent's slug.
    pub agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadInboxReply {
    /// Unread messages in total order (oldest first).
    pub messages: Vec<ChatMessage>,
}

/// One coordination-bus message as it crosses the wire. `to`/`kind` are the
/// wire-token forms (`@all`/`@human`/slug; `coord-request`; …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// The message's monotonic number (its total-order position).
    pub number: u32,
    /// Sender slug, or `@human`.
    pub from: String,
    /// Addressee wire form: an agent slug, `@all`, or `@human`.
    pub to: String,
    /// Kind wire token.
    pub kind: String,
    /// The message text.
    pub body: String,
    /// Daemon-stamped wall-clock timestamp (informational; order is by number).
    pub ts: String,
}

/// `tail_bus({since}) -> {messages}`. Every bus message numbered above `since`,
/// in total order — the whole channel, not a per-agent lane, and a pure read
/// (no cursor advance, no commit). The orchestrator daemon (growlightd) polls
/// this to fan the bus onto its `subscribe` stream (spec §13 Coordinate);
/// `since = 0` returns the full log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailBusArgs {
    /// Return messages with number strictly greater than this watermark.
    pub since: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailBusReply {
    /// Matching messages in total order (ascending number).
    pub messages: Vec<ChatMessage>,
}

// ---- M4 deploy (TUI Deploy tab) ---------------------------------------

/// `deploy_plan({}) -> DeployPlanReply`. Read-only — the daemon runs
/// `softfig-deploy`'s `plan` against the unlocked garden mount and returns a
/// metadata-only projection (no source bytes cross the boundary).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployPlanArgs {}

/// `deploy_apply({force}) -> DeployApplyReply`. Materialize the plan onto the
/// filesystem (deploy-cache + targets).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployApplyArgs {
    /// Back up a conflicting target to `<target>.softfig-bak` and overwrite it
    /// instead of refusing (mirrors `softfig deploy --force`).
    #[serde(default)]
    pub force: bool,
}

/// What `apply` would do with one dot — the wire projection of
/// `softfig_deploy::Action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployAction {
    /// Target absent → create the cache file + symlink.
    CreateSymlink,
    /// Target is ours but stale → refresh it.
    ReplaceManaged,
    /// `method = "copy"`, target absent → write the stamped copy.
    CopyStamped,
    /// Target already matches the desired state → nothing to do.
    SkipUnchanged,
    /// Target exists and is not ours → refused unless `force`.
    Conflict,
}

impl DeployAction {
    /// The compact verb rendered for this action. Must mirror
    /// `softfig_deploy::Action::verb` (the impl-side enum in the deploy crate;
    /// no crate dependency couples them, so the two stay in sync by hand).
    pub const fn verb(&self) -> &'static str {
        match self {
            DeployAction::CreateSymlink => "symlink",
            DeployAction::ReplaceManaged => "replace",
            DeployAction::CopyStamped => "copy",
            DeployAction::SkipUnchanged => "skip",
            DeployAction::Conflict => "CONFLICT",
        }
    }
}

/// One planned dot as surfaced to the Deploy tab. Metadata only — the source
/// bytes never cross IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPlanEntry {
    /// The dot's name (its `config/deploy.toml` key).
    pub name: String,
    pub action: DeployAction,
    /// Resolved absolute target path (for display).
    pub target: String,
    /// Human reason, set only when `action == Conflict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployPlanReply {
    /// Planned dots in stable (name) order.
    pub entries: Vec<DeployPlanEntry>,
    /// True when any entry is a `Conflict` — `apply` would refuse it without
    /// `force`.
    pub has_conflicts: bool,
}

/// The wire projection of `softfig_deploy::Report` — what `apply` actually did,
/// by category. Each vec holds dot names (conflicts carry their reason inline).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployApplyReply {
    pub created: Vec<String>,
    pub replaced: Vec<String>,
    pub copied: Vec<String>,
    pub skipped: Vec<String>,
    /// Conflicts that were refused (no `force`), with their reasons.
    pub conflicts: Vec<String>,
    /// Conflicts overridden with `force` (target backed up first).
    pub forced: Vec<String>,
    pub warnings: Vec<String>,
}
