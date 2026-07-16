//! Central TUI state + the key→IPC and reply→state glue.
//!
//! Pure-state helpers (the tree model, forms, palette parsing) live in
//! their own modules and carry the unit tests; this module wires them to
//! the worker-thread [`IpcClient`] and the key stream.

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use serde_json::{json, Value};
use softfig_ipc::{
    DeployAction, DeployApplyReply, DeployPlanEntry, DeployPlanReply, DiscoverListReply, DiscoveredDevice,
    HostedChain, LogReply, PairBeginReply, PairConfirmReply, PairListReply, PairPeer,
    PairRemoveReply, PendingPairing, ReadFileReply, ReplicaGrantReply, ReplicaRevokeReply,
    ReplicaStatusReply, SharedSubtreeAddReply, SharedSubtreeInfo, SharedSubtreeListReply,
    SharedSubtreeRemoveReply, SharedSubtreeToggleReply, ShowReply, StatusReply,
    VaultListSealedReply, VaultRevealReply,
};

use crate::clip;
use crate::command::{parse_command, Command};
use crate::forms::{ActionForm, ActionKind};
use crate::ipc::{IpcClient, Reply, Tag};
use crate::tree::TreeModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Browse,
    History,
    Vault,
    Peers,
    Backup,
    Deploy,
    /// M5d slice 004: shared-subtree membership + collaborative-key ceremony
    /// surface — which folders are shared, each share's per-device enable state,
    /// and its ceremony/`key_id` status. Thin over the `shared_subtree_*` verbs +
    /// `status.shared_key_divergence`; drives no crypto itself.
    Shares,
    /// Read-only growlight section (the autonomous work-loop at a glance). Only
    /// reachable when growlight is enabled on this garden (`growlight_enabled ==
    /// Some(true)`); the tab is absent otherwise.
    Growlight,
}

/// M5d slice 004: the collaborative-key ceremony state for one shared subtree,
/// derived purely from what the daemon exposes about it (`key_id`) — no raw key
/// material. The ceremony itself runs deferred in the daemon's net reconcile
/// sweep once ≥2 members are online; the TUI observes only its *outcome*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyState {
    /// `key_id` empty — the collaborative commit-reveal ceremony has not yet
    /// produced `S` (it fires once ≥2 members are online, restart-safe).
    Pending,
    /// `key_id` filled — `S` was collaboratively derived and this device
    /// verified + persisted the signed transcript. The id shown is the one-way
    /// `S-<hex>` handle, never `S` itself.
    Keyed,
}

/// Derive a share's [`CeremonyState`] from its daemon-surfaced `key_id`. A
/// filled `key_id` means the ceremony completed and the transcript verified
/// (slices 006–008 persist the key only after `verify()` passes); an empty one
/// means the ceremony is still pending. Pure — the unit-tested "progress state
/// machine from mock IPC events" the slice calls for.
pub fn ceremony_state(info: &SharedSubtreeInfo) -> CeremonyState {
    if info.key_id.is_some() {
        CeremonyState::Keyed
    } else {
        CeremonyState::Pending
    }
}

/// One row of the growlight backlog queue table, parsed from the managed
/// `<!-- softfig:queue -->` region of `growlight/backlog/CLAUDE.md`. Read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrowlightRow {
    pub num: String,
    pub id: String,
    pub kind: String,
    pub title: String,
    pub status: String,
}

/// One navigable row in the Peers view: a ring member, a pairing awaiting SAS
/// confirmation, or a nearby device discovered over mDNS (Slice A pick-list).
/// The three collections are flattened into a single selection list (peers,
/// then pending, then discovered) so `j`/`k` move over all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRow {
    /// Index into [`App::peers`].
    Peer(usize),
    /// Index into [`App::pending`].
    Pending(usize),
    /// Index into [`App::discovered`].
    Discovered(usize),
}

/// One navigable row in the Backup view (M5b `replica_status`). The tab splits
/// the owner's backup posture into two lists flattened into one selection: the
/// hosts that back *me* up (`push_to` grants) first, then the peer chains *I*
/// host as a backup for others (`hosted`). `j`/`k` move over both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupRow {
    /// Index into [`App::replica_push_to`] — a host I've granted to back me up.
    PushTo(usize),
    /// Index into [`App::hosted`] — a peer chain I mirror (opaque ciphertext).
    Hosted(usize),
}

/// Which field the `pair_begin` overlay is editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairField {
    Fingerprint,
    Endpoint,
}

#[derive(Debug)]
pub enum Overlay {
    None,
    Palette(String),
    Unlock { buf: String, error: Option<String> },
    /// Masked master-password prompt for `vault_reveal` against `path`. When
    /// `id` is `Some`, the reveal targets a single inline `<vault id="…">`
    /// region (M2c); `None` reveals the whole Layer-B-sealed file (M2b).
    Reveal {
        path: String,
        buf: String,
        error: Option<String>,
        id: Option<String>,
    },
    /// M2c: inline-region picker. The selected file carries one or more
    /// `<vault id="…">[encrypted]</vault>` regions (parsed from its `read_file`
    /// projection); pick one and `Enter` advances to the masked-password
    /// [`Overlay::Reveal`] carrying that region `id`.
    RevealRegion {
        path: String,
        ids: Vec<String>,
        selected: usize,
    },
    Form(ActionForm),
    /// Initiate a pairing: collect the peer fingerprint + optional endpoint,
    /// then run `pair_begin`. Stays open until the SAS comes back (then it is
    /// replaced by [`Overlay::PairConfirm`]) or the daemon errors.
    PairBegin {
        fingerprint: String,
        endpoint: String,
        focus: PairField,
        error: Option<String>,
    },
    /// Compare the SAS out of band, then `pair_confirm` (or abort). Reached
    /// from a `pair_begin` reply (initiator) or by selecting a parked pending
    /// pairing (responder).
    PairConfirm {
        pairing_id: String,
        sas: String,
        fingerprint: String,
        name: String,
        error: Option<String>,
    },
    /// Confirm removing a ring member (`pair_remove`).
    Unpair {
        fingerprint: String,
        name: String,
        error: Option<String>,
    },
    /// M5b: grant a paired ring member permission to back up this device's
    /// chain (`replica_grant`). A single fingerprint field, mirroring
    /// `PairBegin` — client-validated non-empty, daemon-authoritative on
    /// whether it names a paired member.
    ReplicaGrant {
        fingerprint: String,
        error: Option<String>,
    },
    /// M5b: confirm revoking a host's backup grant (`replica_revoke`). The host
    /// keeps any ciphertext already pushed; only future pushes stop.
    ReplicaRevoke {
        fingerprint: String,
        name: Option<String>,
        error: Option<String>,
    },
    /// M4: confirm a `--force` deploy apply — back up each conflicting target to
    /// `<target>.softfig-bak` and overwrite it. Gates the destructive path
    /// behind an explicit y/n (a plain `a` apply never forces).
    DeployForce {
        error: Option<String>,
    },
    /// M5d slice 004: register a new shared subtree — collect the garden-relative
    /// mount path to share, then run `shared_subtree_add`. The daemon derives the
    /// id, creates the chain, and (once ≥2 members are online) runs the ceremony.
    AddShare {
        mount_path: String,
        error: Option<String>,
    },
    /// M5d slice 004: confirm un-sharing a subtree (`shared_subtree_remove`) —
    /// drops its membership row; the local chain objects stay until gc.
    RemoveShare {
        id: String,
        mount_path: String,
        error: Option<String>,
    },
    Help,
}

/// The result of a successful reveal — the daemon's temp-file path + the
/// re-auth expiry. Never holds the plaintext itself.
#[derive(Debug, Clone)]
pub struct RevealInfo {
    pub path: String,
    pub temp_path: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct HistoryLine {
    pub hash: String,
    pub intent: String,
    pub summary: String,
}

#[derive(Debug)]
pub struct App {
    pub locked: bool,
    pub tip: Option<String>,
    pub garden_root: String,
    pub view: View,
    pub tree: TreeModel,
    pub preview: String,
    pub preview_title: String,
    /// Vertical scroll offset of the preview pane, in wrapped-line units.
    pub preview_scroll: u16,
    /// Visible content rows of the preview pane; written by the renderer so
    /// page/half-page key math and clamping have the live viewport height.
    pub preview_viewport: u16,
    /// Total wrapped line count of the current preview at the last render
    /// width; written by the renderer so scrolling clamps to the real bottom.
    pub preview_total: u16,
    pub history: Vec<HistoryLine>,
    pub history_selected: usize,
    pub vault_globs: Vec<String>,
    pub vault_files: Vec<String>,
    pub vault_selected: usize,
    pub vault_loaded: bool,
    pub reveal: Option<RevealInfo>,
    /// M2c: inline `<vault id="…">` region ids parsed from the currently-opened
    /// file's daemon projection, plus the path they belong to. Drives the
    /// per-region reveal picker; empty when the open file carries no regions.
    pub regions: Vec<String>,
    pub regions_path: Option<String>,
    pub peers: Vec<PairPeer>,
    pub pending: Vec<PendingPairing>,
    /// Nearby unpaired devices discovered over mDNS (`discover_list`).
    pub discovered: Vec<DiscoveredDevice>,
    /// Flattened selection model over `peers` ++ `pending` ++ `discovered`,
    /// rebuilt on each `pair_list` / `discover_list` reply.
    pub peer_rows: Vec<PeerRow>,
    pub peers_selected: usize,
    pub peers_loaded: bool,
    /// M5b Backup tab (`replica_status`): whether this device hosts backups.
    pub replica_host: bool,
    /// Device-id fingerprints this device pushes its chain to (the hosts that
    /// back *me* up — the `push_to` allow-list).
    pub replica_push_to: Vec<String>,
    /// Per-peer mirror stats for chains *I* host for others (empty unless
    /// `replica_host`). Opaque ciphertext metadata only.
    pub hosted: Vec<HostedChain>,
    /// Flattened selection model over `replica_push_to` ++ `hosted`, rebuilt on
    /// each `replica_status` reply.
    pub backup_rows: Vec<BackupRow>,
    pub backup_selected: usize,
    pub backup_loaded: bool,
    /// M4 Deploy tab (`deploy_plan`): the current plan's per-dot entries.
    pub deploy_entries: Vec<DeployPlanEntry>,
    /// True when some entry is a `Conflict` — apply refuses it without force.
    pub deploy_has_conflicts: bool,
    pub deploy_selected: usize,
    pub deploy_loaded: bool,
    /// M5d slice 004 Shares tab (`shared_subtree_list`): every shared subtree
    /// this device knows about, with its per-device enable state + `key_id`.
    pub shares: Vec<SharedSubtreeInfo>,
    pub shares_selected: usize,
    pub shares_loaded: bool,
    /// M5d slice 006: the daemon's most recent shared-key ceremony divergence
    /// message (`status.shared_key_divergence`), surfaced as a banner on the
    /// Shares tab. `None` in the healthy case.
    pub shared_key_divergence: Option<String>,
    /// growlight enablement (load-bearing gate): `None` until probed, `Some(true)`
    /// when `config/growlight.toml` exists, `Some(false)` otherwise. The Growlight
    /// tab is rendered/reachable **only** when `Some(true)` — no tab, no empty
    /// pane, no error when growlight isn't set up on this garden.
    pub growlight_enabled: Option<bool>,
    /// Whether the enablement probe has been sent (dedup: `status` refreshes tick
    /// repeatedly, so probe at most once per session).
    growlight_probed: bool,
    /// The backlog queue rows (drain order + statuses), parsed read-only from
    /// `growlight/backlog/CLAUDE.md`.
    pub growlight_queue: Vec<GrowlightRow>,
    pub growlight_selected: usize,
    /// The latest baton-log entry (title + body) — the loop's most recent handoff
    /// state, read from the highest-numbered `growlight/baton-log/NNN-*.md`.
    pub growlight_baton_title: Option<String>,
    pub growlight_baton: Option<String>,
    pub growlight_loaded: bool,
    pub overlay: Overlay,
    pub status: String,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        App {
            locked: true,
            tip: None,
            garden_root: String::new(),
            view: View::Browse,
            tree: TreeModel::new(),
            preview: String::new(),
            preview_title: "preview".into(),
            preview_scroll: 0,
            preview_viewport: 0,
            preview_total: 0,
            history: Vec::new(),
            history_selected: 0,
            vault_globs: Vec::new(),
            vault_files: Vec::new(),
            vault_selected: 0,
            vault_loaded: false,
            reveal: None,
            regions: Vec::new(),
            regions_path: None,
            peers: Vec::new(),
            pending: Vec::new(),
            discovered: Vec::new(),
            peer_rows: Vec::new(),
            peers_selected: 0,
            peers_loaded: false,
            replica_host: false,
            replica_push_to: Vec::new(),
            hosted: Vec::new(),
            backup_rows: Vec::new(),
            backup_selected: 0,
            backup_loaded: false,
            deploy_entries: Vec::new(),
            deploy_has_conflicts: false,
            deploy_selected: 0,
            deploy_loaded: false,
            shares: Vec::new(),
            shares_selected: 0,
            shares_loaded: false,
            shared_key_divergence: None,
            growlight_enabled: None,
            growlight_probed: false,
            growlight_queue: Vec::new(),
            growlight_selected: 0,
            growlight_baton_title: None,
            growlight_baton: None,
            growlight_loaded: false,
            overlay: Overlay::None,
            status: "starting…".into(),
            should_quit: false,
        }
    }

    /// First contact: ask the daemon for its state.
    pub fn bootstrap(&mut self, ipc: &mut IpcClient) {
        ipc.send("status", json!({}), Tag::Status);
    }

    // ---- request helpers ----

    fn load_dir(&self, ipc: &mut IpcClient, dir: &str) {
        ipc.send(
            "list_tree",
            json!({ "path": dir }),
            Tag::ListTree { dir: dir.to_string() },
        );
    }

    fn open_file(&self, ipc: &mut IpcClient, path: &str) {
        ipc.send(
            "read_file",
            json!({ "path": path }),
            Tag::ReadFile { path: path.to_string() },
        );
    }

    fn load_history(&self, ipc: &mut IpcClient) {
        ipc.send("log", json!({ "limit": 200 }), Tag::History);
    }

    fn load_vault(&self, ipc: &mut IpcClient) {
        ipc.send("vault_list_sealed", json!({}), Tag::VaultList);
    }

    fn load_peers(&self, ipc: &mut IpcClient) {
        ipc.send("pair_list", json!({}), Tag::PairList);
        ipc.send("discover_list", json!({}), Tag::DiscoverList);
    }

    fn load_backup(&self, ipc: &mut IpcClient) {
        ipc.send("replica_status", json!({}), Tag::ReplicaStatus);
    }

    /// M4: (re)compute the deploy plan (read-only). The reply repopulates the
    /// Deploy tab's entry list.
    fn load_deploy(&self, ipc: &mut IpcClient) {
        ipc.send("deploy_plan", json!({}), Tag::DeployPlan);
    }

    /// M5d slice 004: (re)load the Shares tab — every shared subtree with its
    /// per-device enable state + `key_id`. Read-only; the ceremony runs in the
    /// daemon's reconcile sweep, so a plain refresh reflects its progress.
    fn load_shares(&self, ipc: &mut IpcClient) {
        ipc.send("shared_subtree_list", json!({}), Tag::SharedSubtreeList);
    }

    /// growlight enablement probe. Lists `config/` (a daemon read verb) so the
    /// reply can decide whether growlight is set up on this garden — detected via
    /// the presence of `config/growlight.toml`, **without** assuming the
    /// `growlight/` pillar exists. Sent at most once per session (unlock-gated).
    fn probe_growlight(&mut self, ipc: &mut IpcClient) {
        if self.growlight_probed || self.locked {
            return;
        }
        self.growlight_probed = true;
        ipc.send("list_tree", json!({ "path": "config" }), Tag::GrowlightProbe);
    }

    /// growlight: (re)load the read-only section — the backlog queue table plus a
    /// listing of the baton-log (whose reply triggers the latest-entry read).
    fn load_growlight(&self, ipc: &mut IpcClient) {
        ipc.send(
            "read_file",
            json!({ "path": "growlight/backlog/CLAUDE.md" }),
            Tag::GrowlightQueue,
        );
        ipc.send(
            "list_tree",
            json!({ "path": "growlight/baton-log" }),
            Tag::GrowlightBatonList,
        );
    }

    /// Re-fetch every directory whose children are loaded, so the view
    /// reflects a write that just landed.
    fn refresh_view(&self, ipc: &mut IpcClient) {
        for dir in self.tree.loaded_dirs() {
            self.load_dir(ipc, &dir);
        }
        ipc.send("status", json!({}), Tag::Status);
        if self.view == View::History {
            self.load_history(ipc);
        }
        if self.vault_loaded {
            self.load_vault(ipc);
        }
        if self.peers_loaded {
            self.load_peers(ipc);
        }
        if self.backup_loaded {
            self.load_backup(ipc);
        }
        if self.deploy_loaded {
            self.load_deploy(ipc);
        }
        if self.shares_loaded {
            self.load_shares(ipc);
        }
        if self.growlight_loaded {
            self.load_growlight(ipc);
        }
    }

    /// Rebuild the flattened selection list (ring peers, then pending, then
    /// discovered-nearby) and clamp the selection into range. A discovered
    /// device already shown as a ring member or a pending pairing is skipped so
    /// it isn't listed twice.
    fn rebuild_peer_rows(&mut self) {
        let mut rows =
            Vec::with_capacity(self.peers.len() + self.pending.len() + self.discovered.len());
        for i in 0..self.peers.len() {
            rows.push(PeerRow::Peer(i));
        }
        for i in 0..self.pending.len() {
            rows.push(PeerRow::Pending(i));
        }
        for (i, d) in self.discovered.iter().enumerate() {
            let already_shown = self.peers.iter().any(|p| p.fingerprint == d.fingerprint)
                || self.pending.iter().any(|p| p.fingerprint == d.fingerprint);
            if !already_shown {
                rows.push(PeerRow::Discovered(i));
            }
        }
        self.peer_rows = rows;
        if self.peers_selected >= self.peer_rows.len() {
            self.peers_selected = self.peer_rows.len().saturating_sub(1);
        }
    }

    pub fn selected_peer_row(&self) -> Option<PeerRow> {
        self.peer_rows.get(self.peers_selected).copied()
    }

    /// Rebuild the Backup view's flattened selection list — hosts that back me
    /// up (`push_to`) first, then peer chains I host (`hosted`) — and clamp the
    /// selection into range.
    fn rebuild_backup_rows(&mut self) {
        let mut rows = Vec::with_capacity(self.replica_push_to.len() + self.hosted.len());
        for i in 0..self.replica_push_to.len() {
            rows.push(BackupRow::PushTo(i));
        }
        for i in 0..self.hosted.len() {
            rows.push(BackupRow::Hosted(i));
        }
        self.backup_rows = rows;
        if self.backup_selected >= self.backup_rows.len() {
            self.backup_selected = self.backup_rows.len().saturating_sub(1);
        }
    }

    pub fn selected_backup_row(&self) -> Option<BackupRow> {
        self.backup_rows.get(self.backup_selected).copied()
    }

    pub fn selected_deploy_entry(&self) -> Option<&DeployPlanEntry> {
        self.deploy_entries.get(self.deploy_selected)
    }

    /// The shared subtree under the Shares-tab cursor, if any.
    pub fn selected_share(&self) -> Option<&SharedSubtreeInfo> {
        self.shares.get(self.shares_selected)
    }

    /// The advertised name for a push_to host, if it's a loaded ring member.
    /// A display nicety — `push_to` carries only fingerprints.
    pub fn peer_name_for(&self, fingerprint: &str) -> Option<&str> {
        self.peers
            .iter()
            .find(|p| p.fingerprint == fingerprint)
            .map(|p| p.name.as_str())
    }

    /// The one `active` backlog item, if any (the loop runs ≤1 active at a time).
    pub fn growlight_active_item(&self) -> Option<&GrowlightRow> {
        self.growlight_queue.iter().find(|r| r.status == "active")
    }

    pub fn selected_growlight_row(&self) -> Option<&GrowlightRow> {
        self.growlight_queue.get(self.growlight_selected)
    }

    fn hint_growlight_readonly(&mut self) {
        self.status = "growlight is a read-only view (queue · active item · latest baton)".into();
    }

    // ---- reply handling ----

    pub fn apply_reply(&mut self, reply: Reply, ipc: &mut IpcClient) {
        match reply.tag {
            Tag::Status => match reply.result {
                Ok(v) => {
                    if let Ok(s) = serde_json::from_value::<StatusReply>(v) {
                        let was_locked = self.locked;
                        self.locked = s.state != "unlocked";
                        self.tip = s.tip;
                        self.garden_root = s.garden_root;
                        // M5d slice 006: a completed ceremony that met an
                        // already-differently-keyed chain — surfaced on the
                        // Shares tab, not stderr-only.
                        self.shared_key_divergence = s.shared_key_divergence;
                        if !self.locked && (was_locked || !self.tree.is_loaded("")) {
                            self.load_dir(ipc, "");
                        }
                        if !self.locked {
                            self.probe_growlight(ipc);
                        }
                        if self.locked {
                            self.status = "locked — press u to unlock".into();
                        } else if self.status == "starting…" {
                            self.status = "ready".into();
                        }
                    }
                }
                Err((_, m)) => self.status = format!("status failed: {m}"),
            },
            Tag::Unlock => match reply.result {
                Ok(_) => {
                    self.locked = false;
                    self.overlay = Overlay::None;
                    self.status = "unlocked".into();
                    self.load_dir(ipc, "");
                    self.probe_growlight(ipc);
                    ipc.send("status", json!({}), Tag::Status);
                }
                Err((_, m)) => {
                    if let Overlay::Unlock { error, .. } = &mut self.overlay {
                        *error = Some(m);
                    } else {
                        self.status = format!("unlock failed: {m}");
                    }
                }
            },
            Tag::ListTree { dir } => match reply.result {
                Ok(v) => {
                    if let Ok(r) =
                        serde_json::from_value::<softfig_ipc::ListTreeReply>(v)
                    {
                        self.tree.set_children(&dir, r.entries);
                        self.tree.clamp_selection();
                    }
                }
                Err((_, m)) => self.status = format!("list_tree {dir}: {m}"),
            },
            Tag::ReadFile { path } => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<ReadFileReply>(v) {
                        // M2c: surface the file's inline `<vault id=…>` regions so
                        // `x`/Enter offers the per-region reveal picker.
                        self.regions = parse_vault_region_ids(&r.content);
                        self.regions_path = Some(path.clone());
                        self.preview = r.content;
                        self.preview_title = if r.sealed {
                            format!("{path}  [sealed]")
                        } else {
                            path
                        };
                        self.preview_scroll = 0;
                    }
                }
                Err((_, m)) => self.status = format!("read_file {path}: {m}"),
            },
            Tag::History => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<LogReply>(v) {
                        self.history = r
                            .commits
                            .into_iter()
                            .map(|c| HistoryLine {
                                hash: c.hash,
                                intent: c.intent,
                                summary: c.summary,
                            })
                            .collect();
                        if self.history_selected >= self.history.len() {
                            self.history_selected = self.history.len().saturating_sub(1);
                        }
                    }
                }
                Err((_, m)) => self.status = format!("log: {m}"),
            },
            Tag::Show => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<ShowReply>(v) {
                        self.preview = format_commit(&r);
                        self.preview_title = format!("commit {}", short_hash(&r.commit.hash));
                        self.preview_scroll = 0;
                    }
                }
                Err((_, m)) => self.status = format!("show: {m}"),
            },
            Tag::Action { title } => match reply.result {
                Ok(v) => {
                    self.status = format!("{title}: {}", summarize_action(&v));
                    self.overlay = Overlay::None;
                    self.refresh_view(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("{title} failed ({kind:?}): {m}");
                    if let Overlay::Form(f) = &mut self.overlay {
                        f.error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::VaultList => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<VaultListSealedReply>(v) {
                        self.vault_globs = r.globs;
                        self.vault_files = r.matching_files;
                        self.vault_loaded = true;
                        if self.vault_selected >= self.vault_files.len() {
                            self.vault_selected = self.vault_files.len().saturating_sub(1);
                        }
                    }
                }
                Err((_, m)) => self.status = format!("vault list: {m}"),
            },
            Tag::Reveal { path } => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<VaultRevealReply>(v) {
                        self.status = format!(
                            "revealed {path} → {} · press c to copy",
                            r.temp_path
                        );
                        self.reveal = Some(RevealInfo {
                            path,
                            temp_path: r.temp_path,
                            expires_at: r.expires_at,
                        });
                        self.overlay = Overlay::None;
                    }
                }
                Err((kind, m)) => {
                    let msg = format!("reveal {path} failed ({kind:?}): {m}");
                    if let Overlay::Reveal { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::PairList => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<PairListReply>(v) {
                        self.peers = r.peers;
                        self.pending = r.pending;
                        self.peers_loaded = true;
                        self.rebuild_peer_rows();
                    }
                }
                Err((_, m)) => self.status = format!("pair list: {m}"),
            },
            // Discovery is best-effort surfacing; an error just leaves the
            // pick-list as-is (no status nag).
            Tag::DiscoverList => {
                if let Ok(v) = reply.result {
                    if let Ok(r) = serde_json::from_value::<DiscoverListReply>(v) {
                        self.discovered = r.devices;
                        self.rebuild_peer_rows();
                    }
                }
            }
            Tag::PairBegin => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<PairBeginReply>(v) {
                        self.status =
                            format!("compare SAS with {} — y confirm · n abort", r.name);
                        self.overlay = Overlay::PairConfirm {
                            pairing_id: r.pairing_id,
                            sas: r.sas,
                            fingerprint: r.fingerprint,
                            name: r.name,
                            error: None,
                        };
                    }
                }
                Err((kind, m)) => {
                    let msg = format!("pair failed ({kind:?}): {m}");
                    if let Overlay::PairBegin { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::PairConfirm => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<PairConfirmReply>(v) {
                        self.status = format!("paired with {} ({})", r.name, short_fp(&r.fingerprint));
                    } else {
                        self.status = "paired".into();
                    }
                    self.overlay = Overlay::None;
                    self.load_peers(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("confirm failed ({kind:?}): {m}");
                    if let Overlay::PairConfirm { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::PairRemove => match reply.result {
                Ok(v) => {
                    self.status = match serde_json::from_value::<PairRemoveReply>(v) {
                        Ok(r) if r.removed => format!("unpaired {}", short_fp(&r.fingerprint)),
                        Ok(r) => format!("no change ({} not in ring)", short_fp(&r.fingerprint)),
                        Err(_) => "unpaired".into(),
                    };
                    self.overlay = Overlay::None;
                    self.load_peers(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("unpair failed ({kind:?}): {m}");
                    if let Overlay::Unpair { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::ReplicaStatus => match reply.result {
                Ok(v) => match serde_json::from_value::<ReplicaStatusReply>(v) {
                    Ok(r) => {
                        self.replica_host = r.host;
                        self.replica_push_to = r.push_to;
                        self.hosted = r.hosted;
                        self.backup_loaded = true;
                        self.rebuild_backup_rows();
                    }
                    Err(e) => self.status = format!("replica status: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("replica status: {m}"),
            },
            Tag::ReplicaGrant => match reply.result {
                Ok(v) => {
                    self.status = match serde_json::from_value::<ReplicaGrantReply>(v) {
                        Ok(r) if r.granted => format!("granted backup to {}", short_fp(&r.fingerprint)),
                        Ok(r) => format!("already granted ({})", short_fp(&r.fingerprint)),
                        Err(_) => "granted".into(),
                    };
                    self.overlay = Overlay::None;
                    self.load_backup(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("grant failed ({kind:?}): {m}");
                    if let Overlay::ReplicaGrant { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::ReplicaRevoke => match reply.result {
                Ok(v) => {
                    self.status = match serde_json::from_value::<ReplicaRevokeReply>(v) {
                        Ok(r) if r.revoked => format!("revoked backup from {}", short_fp(&r.fingerprint)),
                        Ok(r) => format!("no change ({} not a host)", short_fp(&r.fingerprint)),
                        Err(_) => "revoked".into(),
                    };
                    self.overlay = Overlay::None;
                    self.load_backup(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("revoke failed ({kind:?}): {m}");
                    if let Overlay::ReplicaRevoke { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::DeployPlan => match reply.result {
                Ok(v) => match serde_json::from_value::<DeployPlanReply>(v) {
                    Ok(r) => {
                        self.deploy_entries = r.entries;
                        self.deploy_has_conflicts = r.has_conflicts;
                        self.deploy_loaded = true;
                        if self.deploy_selected >= self.deploy_entries.len() {
                            self.deploy_selected = self.deploy_entries.len().saturating_sub(1);
                        }
                    }
                    Err(e) => self.status = format!("deploy plan: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("deploy plan: {m}"),
            },
            Tag::DeployApply => match reply.result {
                Ok(v) => {
                    self.status = match serde_json::from_value::<DeployApplyReply>(v) {
                        Ok(r) => deploy_summary(&r),
                        Err(e) => format!("deploy: malformed reply: {e}"),
                    };
                    // Close the force-confirm overlay if it was open, then re-plan
                    // so the tab reflects the new on-disk state.
                    self.overlay = Overlay::None;
                    self.load_deploy(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("apply failed ({kind:?}): {m}");
                    if let Overlay::DeployForce { error } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::SharedSubtreeList => match reply.result {
                Ok(v) => match serde_json::from_value::<SharedSubtreeListReply>(v) {
                    Ok(r) => {
                        self.shares = r.subtrees;
                        self.shares_loaded = true;
                        if self.shares_selected >= self.shares.len() {
                            self.shares_selected = self.shares.len().saturating_sub(1);
                        }
                    }
                    Err(e) => self.status = format!("shares: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("shares: {m}"),
            },
            Tag::SharedSubtreeAdd => match reply.result {
                Ok(v) => {
                    self.status = match serde_json::from_value::<SharedSubtreeAddReply>(v) {
                        Ok(r) => format!("sharing {} (id {})", r.mount_path, r.id),
                        Err(_) => "share added".into(),
                    };
                    self.overlay = Overlay::None;
                    self.load_shares(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("share failed ({kind:?}): {m}");
                    if let Overlay::AddShare { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::SharedSubtreeRemove => match reply.result {
                Ok(v) => {
                    self.status = match serde_json::from_value::<SharedSubtreeRemoveReply>(v) {
                        Ok(r) if r.removed => format!("un-shared {}", r.id),
                        Ok(r) => format!("no change ({} not shared)", r.id),
                        Err(_) => "un-shared".into(),
                    };
                    self.overlay = Overlay::None;
                    self.load_shares(ipc);
                }
                Err((kind, m)) => {
                    let msg = format!("un-share failed ({kind:?}): {m}");
                    if let Overlay::RemoveShare { error, .. } = &mut self.overlay {
                        *error = Some(msg);
                    } else {
                        self.status = msg;
                    }
                }
            },
            Tag::SharedSubtreeToggle => match reply.result {
                Ok(v) => {
                    self.status = match serde_json::from_value::<SharedSubtreeToggleReply>(v) {
                        Ok(r) if !r.changed => format!(
                            "{} already {}",
                            r.id,
                            if r.enabled { "enabled" } else { "disabled" }
                        ),
                        Ok(r) => format!(
                            "{} {}",
                            r.id,
                            if r.enabled { "enabled" } else { "disabled" }
                        ),
                        Err(_) => "toggled".into(),
                    };
                    self.load_shares(ipc);
                }
                Err((_, m)) => self.status = format!("toggle failed: {m}"),
            },
            // growlight enablement probe: `config/growlight.toml` present ⇒ the
            // section is enabled. A missing `config/` (Err) ⇒ disabled — degrade
            // silently, never surface an error (the tab simply won't appear).
            Tag::GrowlightProbe => {
                let enabled = match reply.result {
                    Ok(v) => serde_json::from_value::<softfig_ipc::ListTreeReply>(v)
                        .map(|r| config_has_growlight(&r.entries))
                        .unwrap_or(false),
                    Err(_) => false,
                };
                self.growlight_enabled = Some(enabled);
            }
            Tag::GrowlightQueue => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<ReadFileReply>(v) {
                        self.growlight_queue = parse_growlight_queue(&r.content);
                        self.growlight_loaded = true;
                        if self.growlight_selected >= self.growlight_queue.len() {
                            self.growlight_selected =
                                self.growlight_queue.len().saturating_sub(1);
                        }
                    }
                }
                Err((_, m)) => self.status = format!("growlight queue: {m}"),
            },
            Tag::GrowlightBatonList => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<softfig_ipc::ListTreeReply>(v) {
                        if let Some(path) = latest_baton_path(&r.entries) {
                            ipc.send(
                                "read_file",
                                json!({ "path": path }),
                                Tag::GrowlightBaton { path },
                            );
                        }
                    }
                }
                Err((_, m)) => self.status = format!("growlight baton-log: {m}"),
            },
            Tag::GrowlightBaton { path } => match reply.result {
                Ok(v) => {
                    if let Ok(r) = serde_json::from_value::<ReadFileReply>(v) {
                        self.growlight_baton_title = Some(
                            path.rsplit('/').next().unwrap_or(&path).to_string(),
                        );
                        self.growlight_baton = Some(r.content);
                    }
                }
                Err((_, m)) => self.status = format!("growlight baton: {m}"),
            },
        }
    }

    // ---- key handling ----

    pub fn handle_key(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        match &mut self.overlay {
            Overlay::None => self.handle_key_main(key, ipc),
            Overlay::Palette(_) => self.handle_key_palette(key, ipc),
            Overlay::Unlock { .. } => self.handle_key_unlock(key, ipc),
            Overlay::Reveal { .. } => self.handle_key_reveal(key, ipc),
            Overlay::RevealRegion { .. } => self.handle_key_reveal_region(key, ipc),
            Overlay::Form(_) => self.handle_key_form(key, ipc),
            Overlay::PairBegin { .. } => self.handle_key_pair_begin(key, ipc),
            Overlay::PairConfirm { .. } => self.handle_key_pair_confirm(key, ipc),
            Overlay::Unpair { .. } => self.handle_key_unpair(key, ipc),
            Overlay::ReplicaGrant { .. } => self.handle_key_replica_grant(key, ipc),
            Overlay::ReplicaRevoke { .. } => self.handle_key_replica_revoke(key, ipc),
            Overlay::DeployForce { .. } => self.handle_key_deploy_force(key, ipc),
            Overlay::AddShare { .. } => self.handle_key_add_share(key, ipc),
            Overlay::RemoveShare { .. } => self.handle_key_remove_share(key, ipc),
            Overlay::Help => {
                self.overlay = Overlay::None;
            }
        }
    }

    fn handle_key_main(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        // Vim-style preview scrolling on the Ctrl chord, kept off the bare
        // h/j/k/l keys so list navigation is untouched. Half/full page sizes
        // come from the viewport the renderer recorded last frame.
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            let half = (self.preview_viewport / 2).max(1) as i32;
            let full = self.preview_viewport.max(1) as i32;
            match key.code {
                KeyCode::Char('e') => return self.scroll_preview(1),
                KeyCode::Char('y') => return self.scroll_preview(-1),
                KeyCode::Char('d') => return self.scroll_preview(half),
                KeyCode::Char('u') => return self.scroll_preview(-half),
                KeyCode::Char('f') => return self.scroll_preview(full),
                KeyCode::Char('b') => return self.scroll_preview(-full),
                _ => {}
            }
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.overlay = Overlay::Help,
            KeyCode::Char(':') => self.overlay = Overlay::Palette(String::new()),
            KeyCode::Char('u') if self.locked => {
                self.overlay = Overlay::Unlock {
                    buf: String::new(),
                    error: None,
                };
            }
            KeyCode::Char('1') => self.view = View::Browse,
            KeyCode::Char('2') => {
                self.view = View::History;
                if self.history.is_empty() && !self.locked {
                    self.load_history(ipc);
                }
            }
            KeyCode::Char('3') => {
                self.view = View::Vault;
                if !self.vault_loaded && !self.locked {
                    self.load_vault(ipc);
                }
            }
            KeyCode::Char('4') => {
                self.view = View::Peers;
                if !self.peers_loaded && !self.locked {
                    self.load_peers(ipc);
                }
            }
            KeyCode::Char('5') => {
                self.view = View::Backup;
                if !self.backup_loaded && !self.locked {
                    self.load_backup(ipc);
                }
            }
            KeyCode::Char('6') => {
                self.view = View::Deploy;
                if !self.deploy_loaded && !self.locked {
                    self.load_deploy(ipc);
                }
            }
            KeyCode::Char('7') => {
                self.view = View::Shares;
                if !self.shares_loaded && !self.locked {
                    self.load_shares(ipc);
                }
            }
            // Only reachable when growlight is enabled — the tab is absent
            // otherwise, so `8` is inert on a garden without growlight.
            KeyCode::Char('8') if self.growlight_enabled == Some(true) => {
                self.view = View::Growlight;
                if !self.growlight_loaded && !self.locked {
                    self.load_growlight(ipc);
                }
            }
            KeyCode::Char('r') if !self.locked => self.refresh_view(ipc),
            _ if self.locked => {}
            KeyCode::Char('p') if self.view == View::Peers => self.pair_selected(ipc),
            KeyCode::Char('D') if self.view == View::Peers => self.start_unpair(),
            KeyCode::Char('g') if self.view == View::Backup => self.open_grant(),
            KeyCode::Char('D') if self.view == View::Backup => self.start_revoke(),
            KeyCode::Char('a') if self.view == View::Deploy => self.apply_deploy(ipc, false),
            KeyCode::Char('F') if self.view == View::Deploy => self.start_force_apply(),
            KeyCode::Char('a') if self.view == View::Shares => self.open_add_share(),
            KeyCode::Char('D') if self.view == View::Shares => self.start_remove_share(),
            KeyCode::Char('e') if self.view == View::Shares => self.toggle_share(ipc),
            KeyCode::Char('x') => self.start_reveal(ipc),
            KeyCode::Char('c') => self.copy_reveal(),
            KeyCode::Up | KeyCode::Char('k') => self.nav_up(),
            KeyCode::Down | KeyCode::Char('j') => self.nav_down(ipc),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.activate(ipc),
            KeyCode::Left | KeyCode::Char('h') => self.collapse_selected(),
            KeyCode::PageDown => self.scroll_preview(self.preview_viewport.max(1) as i32),
            KeyCode::PageUp => self.scroll_preview(-(self.preview_viewport.max(1) as i32)),
            KeyCode::Char('g') => self.preview_to_top(),
            KeyCode::Char('G') => self.preview_to_bottom(),
            _ => {}
        }
    }

    /// Wheel events scroll the preview pane, three lines per notch.
    pub fn handle_mouse(&mut self, ev: MouseEvent, _ipc: &mut IpcClient) {
        match ev.kind {
            MouseEventKind::ScrollDown => self.scroll_preview(3),
            MouseEventKind::ScrollUp => self.scroll_preview(-3),
            _ => {}
        }
    }

    /// Largest valid scroll offset: enough to bring the last wrapped line to
    /// the bottom of the viewport, never past it.
    fn preview_max_scroll(&self) -> u16 {
        self.preview_total.saturating_sub(self.preview_viewport)
    }

    /// Move the preview offset by `delta` lines (negative = up), clamped to
    /// `[0, preview_max_scroll]`.
    fn scroll_preview(&mut self, delta: i32) {
        let max = self.preview_max_scroll() as i32;
        let next = (self.preview_scroll as i32 + delta).clamp(0, max);
        self.preview_scroll = next as u16;
    }

    fn preview_to_top(&mut self) {
        self.preview_scroll = 0;
    }

    fn preview_to_bottom(&mut self) {
        self.preview_scroll = self.preview_max_scroll();
    }

    fn nav_up(&mut self) {
        match self.view {
            View::Browse => self.tree.move_up(),
            View::History => {
                self.history_selected = self.history_selected.saturating_sub(1);
            }
            View::Vault => {
                self.vault_selected = self.vault_selected.saturating_sub(1);
            }
            View::Peers => {
                self.peers_selected = self.peers_selected.saturating_sub(1);
            }
            View::Backup => {
                self.backup_selected = self.backup_selected.saturating_sub(1);
            }
            View::Deploy => {
                self.deploy_selected = self.deploy_selected.saturating_sub(1);
            }
            View::Shares => {
                self.shares_selected = self.shares_selected.saturating_sub(1);
            }
            View::Growlight => {
                self.growlight_selected = self.growlight_selected.saturating_sub(1);
            }
        }
    }

    fn nav_down(&mut self, _ipc: &mut IpcClient) {
        match self.view {
            View::Browse => self.tree.move_down(),
            View::History => {
                if self.history_selected + 1 < self.history.len() {
                    self.history_selected += 1;
                }
            }
            View::Vault => {
                if self.vault_selected + 1 < self.vault_files.len() {
                    self.vault_selected += 1;
                }
            }
            View::Peers => {
                if self.peers_selected + 1 < self.peer_rows.len() {
                    self.peers_selected += 1;
                }
            }
            View::Backup => {
                if self.backup_selected + 1 < self.backup_rows.len() {
                    self.backup_selected += 1;
                }
            }
            View::Deploy => {
                if self.deploy_selected + 1 < self.deploy_entries.len() {
                    self.deploy_selected += 1;
                }
            }
            View::Shares => {
                if self.shares_selected + 1 < self.shares.len() {
                    self.shares_selected += 1;
                }
            }
            View::Growlight => {
                if self.growlight_selected + 1 < self.growlight_queue.len() {
                    self.growlight_selected += 1;
                }
            }
        }
    }

    fn activate(&mut self, ipc: &mut IpcClient) {
        match self.view {
            View::Browse => {
                let Some(row) = self.tree.selected_row() else {
                    return;
                };
                if row.is_dir {
                    if self.tree.is_expanded(&row.path) {
                        self.tree.collapse(&row.path);
                    } else {
                        self.tree.expand(&row.path);
                        if !self.tree.is_loaded(&row.path) {
                            self.load_dir(ipc, &row.path);
                        }
                    }
                    self.tree.clamp_selection();
                } else {
                    self.open_file(ipc, &row.path);
                }
            }
            View::History => {
                if let Some(h) = self.history.get(self.history_selected) {
                    ipc.send("show", json!({ "hash": h.hash }), Tag::Show);
                }
            }
            View::Vault => self.start_reveal(ipc),
            // Activating a parked pending pairing opens the SAS-confirm
            // overlay; a discovered device initiates pairing; a settled ring
            // member is a no-op (its details already show in the right pane).
            View::Peers => self.activate_selected_peer(ipc),
            // Backup rows are read-only detail; grant/revoke are explicit
            // actions (g / D / palette), never a stray Enter.
            View::Backup => self.hint_backup_actions(),
            // Deploy entries are read-only detail; apply is an explicit action
            // (a / F / palette), never a stray Enter.
            View::Deploy => self.hint_deploy_actions(),
            // Share rows are toggled/added/removed with explicit keys; Enter is
            // a hint, matching the Backup/Deploy read-only-detail pattern.
            View::Shares => self.hint_shares_actions(),
            // Growlight is a read-only glance — Enter is a no-op hint.
            View::Growlight => self.hint_growlight_readonly(),
        }
    }

    fn hint_shares_actions(&mut self) {
        self.status = match self.selected_share() {
            Some(s) if s.enabled => {
                format!("{} enabled · e disable · D un-share · a share a folder", s.id)
            }
            Some(s) => {
                format!("{} disabled · e enable · D un-share · a share a folder", s.id)
            }
            None => "a share a folder across your devices".into(),
        };
    }

    fn hint_backup_actions(&mut self) {
        self.status = match self.selected_backup_row() {
            Some(BackupRow::PushTo(_)) => "g grant a host · D revoke selected".into(),
            Some(BackupRow::Hosted(_)) => "this is a chain I host (read-only mirror)".into(),
            None => "g grant a paired device to back up this chain".into(),
        };
    }

    fn collapse_selected(&mut self) {
        if self.view != View::Browse {
            return;
        }
        if let Some(row) = self.tree.selected_row() {
            if row.is_dir && self.tree.is_expanded(&row.path) {
                self.tree.collapse(&row.path);
                self.tree.clamp_selection();
            }
        }
    }

    fn handle_key_palette(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::Palette(buf) = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let cmd = parse_command(buf);
                self.overlay = Overlay::None;
                self.run_command(cmd, ipc);
            }
            _ => {}
        }
    }

    fn run_command(&mut self, cmd: Command, ipc: &mut IpcClient) {
        match cmd {
            Command::Browse => self.view = View::Browse,
            Command::History => {
                self.view = View::History;
                if !self.locked {
                    self.load_history(ipc);
                }
            }
            Command::Vault => {
                self.view = View::Vault;
                if !self.locked {
                    self.load_vault(ipc);
                }
            }
            Command::Peers => {
                self.view = View::Peers;
                if !self.locked {
                    self.load_peers(ipc);
                }
            }
            Command::Reveal => self.start_reveal(ipc),
            Command::Pair => {
                self.view = View::Peers;
                self.open_pair_begin();
            }
            Command::Unpair => {
                self.view = View::Peers;
                self.start_unpair();
            }
            Command::Backup => {
                self.view = View::Backup;
                if !self.locked {
                    self.load_backup(ipc);
                }
            }
            Command::Grant => {
                self.view = View::Backup;
                self.open_grant();
            }
            Command::Revoke => {
                self.view = View::Backup;
                self.start_revoke();
            }
            Command::Deploy => {
                self.view = View::Deploy;
                if !self.locked {
                    self.load_deploy(ipc);
                }
            }
            Command::Apply => {
                self.view = View::Deploy;
                self.apply_deploy(ipc, false);
            }
            Command::Shares => {
                self.view = View::Shares;
                if !self.locked {
                    self.load_shares(ipc);
                }
            }
            Command::Share => {
                self.view = View::Shares;
                self.open_add_share();
            }
            Command::Unshare => {
                self.view = View::Shares;
                self.start_remove_share();
            }
            Command::Reload if !self.locked => self.refresh_view(ipc),
            Command::Reload => {}
            Command::Unlock => {
                if self.locked {
                    self.overlay = Overlay::Unlock {
                        buf: String::new(),
                        error: None,
                    };
                }
            }
            Command::Quit => self.should_quit = true,
            Command::Help => self.overlay = Overlay::Help,
            Command::Action(kind) => self.open_form(kind),
            Command::Unknown(s) => self.status = format!("unknown command: {s}"),
        }
    }

    fn open_form(&mut self, kind: ActionKind) {
        if self.locked {
            self.status = "locked — unlock before running actions".into();
            return;
        }
        self.overlay = Overlay::Form(ActionForm::for_kind(kind));
    }

    fn handle_key_unlock(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::Unlock { buf, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let pass = buf.clone();
                ipc.send("unlock", json!({ "passphrase": pass }), Tag::Unlock);
                self.status = "unlocking…".into();
            }
            _ => {}
        }
    }

    /// Open the masked reveal prompt for the currently-selected sealed file.
    fn start_reveal(&mut self, _ipc: &mut IpcClient) {
        if self.locked {
            self.status = "locked — unlock before revealing".into();
            return;
        }
        let target = match self.view {
            View::Vault => self.vault_files.get(self.vault_selected).cloned(),
            View::Browse => self
                .tree
                .selected_row()
                .filter(|r| !r.is_dir)
                .map(|r| r.path.clone()),
            View::History | View::Peers | View::Backup | View::Deploy | View::Shares
            | View::Growlight => None,
        };
        match target {
            // M2c: if the reveal target is the currently-open file and it
            // carries inline `<vault id=…>` regions, pick a region first;
            // otherwise fall through to the whole-file (M2b) reveal prompt.
            Some(path)
                if self.regions_path.as_deref() == Some(path.as_str())
                    && !self.regions.is_empty() =>
            {
                self.overlay = Overlay::RevealRegion {
                    path,
                    ids: self.regions.clone(),
                    selected: 0,
                };
            }
            Some(path) => {
                self.overlay = Overlay::Reveal {
                    path,
                    buf: String::new(),
                    error: None,
                    id: None,
                }
            }
            None => self.status = "select a sealed file to reveal".into(),
        }
    }

    /// Region picker keys (M2c): move over the `<vault id=…>` ids and `Enter`
    /// advances to the masked-password prompt for the chosen region.
    fn handle_key_reveal_region(&mut self, key: KeyEvent, _ipc: &mut IpcClient) {
        let Overlay::RevealRegion {
            path,
            ids,
            selected,
        } = &mut self.overlay
        else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Char('j') | KeyCode::Down if *selected + 1 < ids.len() => {
                *selected += 1;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                *selected = selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                let id = ids.get(*selected).cloned();
                let path = path.clone();
                if let Some(id) = id {
                    self.overlay = Overlay::Reveal {
                        path,
                        buf: String::new(),
                        error: None,
                        id: Some(id),
                    };
                }
            }
            _ => {}
        }
    }

    fn handle_key_reveal(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::Reveal { path, buf, id, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let path = path.clone();
                let pass = buf.clone();
                let id = id.clone();
                let args = vault_reveal_args(&path, &pass, id.as_deref());
                ipc.send("vault_reveal", args, Tag::Reveal { path: path.clone() });
                self.status = match &id {
                    Some(id) => format!("revealing {path} <{id}>…"),
                    None => format!("revealing {path}…"),
                };
            }
            _ => {}
        }
    }

    /// Copy the last reveal's plaintext into the Wayland clipboard. The
    /// bytes flow from the daemon's 0600 temp file straight into `wl-copy`'s
    /// stdin — they never enter this process's memory.
    fn copy_reveal(&mut self) {
        let Some(info) = self.reveal.clone() else {
            self.status = "nothing to copy — reveal a secret first".into();
            return;
        };
        if !clip::clipboard_available() {
            self.status =
                format!("no clipboard tool (wl-copy) — temp file at {}", info.temp_path);
            return;
        }
        self.status = match clip::copy_file_to_clipboard(Path::new(&info.temp_path)) {
            Ok(()) => format!("copied {} to clipboard", info.path),
            Err(e) => format!("copy failed: {e} — temp file at {}", info.temp_path),
        };
    }

    // ---- pairing (M5a) ----

    /// Open the "initiate pairing" overlay (the initiator side of `pair_begin`).
    fn open_pair_begin(&mut self) {
        if self.locked {
            self.status = "locked — unlock before pairing".into();
            return;
        }
        self.overlay = Overlay::PairBegin {
            fingerprint: String::new(),
            endpoint: String::new(),
            focus: PairField::Fingerprint,
            error: None,
        };
    }

    /// `p` on the Peers tab. On a discovered device it kicks off pairing with
    /// the cached fingerprint + endpoint (no typing); otherwise it opens the
    /// manual "initiate pairing" overlay (off-LAN / not-yet-discovered peers).
    fn pair_selected(&mut self, ipc: &mut IpcClient) {
        match self.selected_peer_row() {
            Some(PeerRow::Discovered(i)) => self.pair_discovered(i, ipc),
            _ => self.open_pair_begin(),
        }
    }

    /// Enter on the Peers tab: confirm a parked pending pairing, initiate a
    /// discovered device, or no-op on a settled ring member.
    fn activate_selected_peer(&mut self, ipc: &mut IpcClient) {
        match self.selected_peer_row() {
            Some(PeerRow::Pending(i)) => {
                if let Some(p) = self.pending.get(i) {
                    self.overlay = Overlay::PairConfirm {
                        pairing_id: p.pairing_id.clone(),
                        sas: p.sas.clone(),
                        fingerprint: p.fingerprint.clone(),
                        name: p.name.clone(),
                        error: None,
                    };
                }
            }
            Some(PeerRow::Discovered(i)) => self.pair_discovered(i, ipc),
            Some(PeerRow::Peer(_)) => {
                self.status = "already paired — D to unpair".into();
            }
            None => self.status = "nothing selected".into(),
        }
    }

    /// Initiate pairing with a discovered device: send `pair_begin` with its
    /// cached fingerprint + endpoint. The reply opens the SAS-confirm overlay,
    /// exactly as the manual path does — only the addressing is auto-filled.
    fn pair_discovered(&mut self, i: usize, ipc: &mut IpcClient) {
        if self.locked {
            self.status = "locked — unlock before pairing".into();
            return;
        }
        let Some(d) = self.discovered.get(i) else {
            self.status = "no discovered device selected".into();
            return;
        };
        let mut args = json!({ "fingerprint": d.fingerprint });
        if let Some(ep) = &d.endpoint {
            args["endpoint"] = json!(ep);
        }
        let who = d.name.clone().unwrap_or_else(|| short_fp(&d.fingerprint).to_string());
        self.status = format!("pairing with {who}… (running handshake)");
        ipc.send("pair_begin", args, Tag::PairBegin);
    }

    /// If a ring member is selected, open the unpair-confirm overlay.
    fn start_unpair(&mut self) {
        match self.selected_peer_row() {
            Some(PeerRow::Peer(i)) => {
                if let Some(p) = self.peers.get(i) {
                    self.overlay = Overlay::Unpair {
                        fingerprint: p.fingerprint.clone(),
                        name: p.name.clone(),
                        error: None,
                    };
                }
            }
            _ => self.status = "select a paired device to unpair".into(),
        }
    }

    fn handle_key_pair_begin(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::PairBegin {
            fingerprint,
            endpoint,
            focus,
            ..
        } = &mut self.overlay
        else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Tab | KeyCode::Down | KeyCode::BackTab | KeyCode::Up => {
                *focus = match focus {
                    PairField::Fingerprint => PairField::Endpoint,
                    PairField::Endpoint => PairField::Fingerprint,
                };
            }
            KeyCode::Backspace => {
                match focus {
                    PairField::Fingerprint => fingerprint.pop(),
                    PairField::Endpoint => endpoint.pop(),
                };
            }
            KeyCode::Char(c) => match focus {
                PairField::Fingerprint => fingerprint.push(c),
                PairField::Endpoint => endpoint.push(c),
            },
            KeyCode::Enter => self.submit_pair_begin(ipc),
            _ => {}
        }
    }

    fn submit_pair_begin(&mut self, ipc: &mut IpcClient) {
        let Overlay::PairBegin {
            fingerprint,
            endpoint,
            error,
            ..
        } = &mut self.overlay
        else {
            return;
        };
        let fp = fingerprint.trim().to_string();
        if fp.is_empty() {
            *error = Some("fingerprint must not be empty".into());
            return;
        }
        let mut args = json!({ "fingerprint": fp });
        let ep = endpoint.trim();
        if !ep.is_empty() {
            args["endpoint"] = json!(ep);
        }
        *error = None;
        self.status = "pairing… (running handshake)".into();
        ipc.send("pair_begin", args, Tag::PairBegin);
    }

    fn handle_key_pair_confirm(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::PairConfirm { pairing_id, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.overlay = Overlay::None;
                self.status = "pairing aborted (not confirmed)".into();
            }
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                let id = pairing_id.clone();
                self.status = "confirming…".into();
                ipc.send("pair_confirm", json!({ "pairing_id": id }), Tag::PairConfirm);
            }
            _ => {}
        }
    }

    fn handle_key_unpair(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::Unpair { fingerprint, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.overlay = Overlay::None;
                self.status = "unpair cancelled".into();
            }
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                let fp = fingerprint.clone();
                self.status = "unpairing…".into();
                ipc.send("pair_remove", json!({ "fingerprint": fp }), Tag::PairRemove);
            }
            _ => {}
        }
    }

    // ---- replica backup grants (M5b) ----

    /// Open the "grant a host" overlay (owner side of `replica_grant`).
    fn open_grant(&mut self) {
        if self.locked {
            self.status = "locked — unlock before granting backup".into();
            return;
        }
        self.overlay = Overlay::ReplicaGrant {
            fingerprint: String::new(),
            error: None,
        };
    }

    /// `D` / `:revoke` on the Backup tab: if a host (`push_to`) row is selected,
    /// open the revoke-confirm overlay. A hosted-chain row cannot be revoked
    /// (it's a mirror I keep, not a grant I made).
    fn start_revoke(&mut self) {
        if self.locked {
            self.status = "locked — unlock before revoking backup".into();
            return;
        }
        match self.selected_backup_row() {
            Some(BackupRow::PushTo(i)) => {
                if let Some(fp) = self.replica_push_to.get(i) {
                    let name = self.peer_name_for(fp).map(str::to_string);
                    self.overlay = Overlay::ReplicaRevoke {
                        fingerprint: fp.clone(),
                        name,
                        error: None,
                    };
                }
            }
            _ => self.status = "select a granted host to revoke".into(),
        }
    }

    fn handle_key_replica_grant(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::ReplicaGrant { fingerprint, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                fingerprint.pop();
            }
            KeyCode::Char(c) => fingerprint.push(c),
            KeyCode::Enter => self.submit_grant(ipc),
            _ => {}
        }
    }

    fn submit_grant(&mut self, ipc: &mut IpcClient) {
        let Overlay::ReplicaGrant { fingerprint, error } = &mut self.overlay else {
            return;
        };
        let fp = fingerprint.trim().to_string();
        if fp.is_empty() {
            *error = Some("fingerprint must not be empty".into());
            return;
        }
        *error = None;
        self.status = "granting backup…".into();
        ipc.send(
            "replica_grant",
            json!({ "fingerprint": fp }),
            Tag::ReplicaGrant,
        );
    }

    fn handle_key_replica_revoke(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::ReplicaRevoke { fingerprint, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.overlay = Overlay::None;
                self.status = "revoke cancelled".into();
            }
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                let fp = fingerprint.clone();
                self.status = "revoking backup…".into();
                ipc.send(
                    "replica_revoke",
                    json!({ "fingerprint": fp }),
                    Tag::ReplicaRevoke,
                );
            }
            _ => {}
        }
    }

    // ---- M4 Deploy tab ----

    /// `a` / `:apply` — apply the current deploy plan. `force = false` refuses
    /// conflicting targets (they come back in the report's `conflicts`); `force
    /// = true` (only reached via the confirm overlay) backs each up first.
    fn apply_deploy(&mut self, ipc: &mut IpcClient, force: bool) {
        if self.locked {
            self.status = "locked — unlock before deploying".into();
            return;
        }
        self.status = if force { "applying (force)…" } else { "applying…" }.into();
        ipc.send("deploy_apply", json!({ "force": force }), Tag::DeployApply);
    }

    /// `F` — open the confirm for a destructive `--force` apply. Kept behind a
    /// y/n prompt because force backs up + overwrites unmanaged targets.
    fn start_force_apply(&mut self) {
        if self.locked {
            self.status = "locked — unlock before deploying".into();
            return;
        }
        self.overlay = Overlay::DeployForce { error: None };
    }

    fn handle_key_deploy_force(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.overlay = Overlay::None;
                self.status = "force apply cancelled".into();
            }
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                self.apply_deploy(ipc, true);
            }
            _ => {}
        }
    }

    fn hint_deploy_actions(&mut self) {
        self.status = match self.selected_deploy_entry() {
            Some(e) if e.action == DeployAction::Conflict => {
                "conflict — a skips it · F force (backs up + overwrites)".into()
            }
            Some(_) => "a apply · F force · r refresh".into(),
            None => "no dots in config/deploy.toml".into(),
        };
    }

    // ---- M5d Shares tab (shared-subtree membership + ceremony) ----

    /// `a` / `:share` — open the "share a folder" overlay. The daemon derives the
    /// id from the mount path and runs the ceremony once ≥2 members are online.
    fn open_add_share(&mut self) {
        if self.locked {
            self.status = "locked — unlock before sharing".into();
            return;
        }
        self.overlay = Overlay::AddShare {
            mount_path: String::new(),
            error: None,
        };
    }

    fn handle_key_add_share(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::AddShare { mount_path, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Backspace => {
                mount_path.pop();
            }
            KeyCode::Char(c) => mount_path.push(c),
            KeyCode::Enter => self.submit_add_share(ipc),
            _ => {}
        }
    }

    fn submit_add_share(&mut self, ipc: &mut IpcClient) {
        let Overlay::AddShare { mount_path, error } = &mut self.overlay else {
            return;
        };
        let path = mount_path.trim().trim_matches('/').to_string();
        if path.is_empty() {
            *error = Some("mount path must not be empty".into());
            return;
        }
        *error = None;
        self.status = "sharing…".into();
        ipc.send(
            "shared_subtree_add",
            json!({ "mount_path": path }),
            Tag::SharedSubtreeAdd,
        );
    }

    /// `D` / `:unshare` — confirm un-sharing the selected subtree.
    fn start_remove_share(&mut self) {
        if self.locked {
            self.status = "locked — unlock before un-sharing".into();
            return;
        }
        match self.selected_share() {
            Some(s) => {
                self.overlay = Overlay::RemoveShare {
                    id: s.id.clone(),
                    mount_path: s.mount_path.clone(),
                    error: None,
                };
            }
            None => self.status = "select a shared folder to un-share".into(),
        }
    }

    fn handle_key_remove_share(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        let Overlay::RemoveShare { id, .. } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.overlay = Overlay::None;
                self.status = "un-share cancelled".into();
            }
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                let id = id.clone();
                self.status = "un-sharing…".into();
                ipc.send(
                    "shared_subtree_remove",
                    json!({ "id": id }),
                    Tag::SharedSubtreeRemove,
                );
            }
            _ => {}
        }
    }

    /// `e` — flip the selected share's per-device enable state. Enabled shares
    /// disable (fall back to the device chain); disabled shares re-enable. No
    /// membership or ceremony change — the headline "easy on/off".
    fn toggle_share(&mut self, ipc: &mut IpcClient) {
        if self.locked {
            self.status = "locked — unlock before toggling shares".into();
            return;
        }
        match self.selected_share() {
            Some(s) => {
                let op = if s.enabled {
                    "shared_subtree_disable"
                } else {
                    "shared_subtree_enable"
                };
                let id = s.id.clone();
                self.status = "toggling…".into();
                ipc.send(op, json!({ "id": id }), Tag::SharedSubtreeToggle);
            }
            None => self.status = "select a shared folder to toggle".into(),
        }
    }

    fn handle_key_form(&mut self, key: KeyEvent, ipc: &mut IpcClient) {
        // Ctrl-S submits regardless of focused field.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.submit_form(ipc);
            return;
        }
        let Overlay::Form(form) = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = Overlay::None,
            KeyCode::Tab | KeyCode::Down => form.focus_next(),
            KeyCode::BackTab | KeyCode::Up => form.focus_prev(),
            KeyCode::Enter => form.enter(),
            KeyCode::Backspace => form.backspace(),
            KeyCode::Char(c) => form.input_char(c),
            _ => {}
        }
    }

    fn submit_form(&mut self, ipc: &mut IpcClient) {
        let Overlay::Form(form) = &mut self.overlay else {
            return;
        };
        match form.to_request() {
            Ok((op, args)) => {
                let title = form.kind.title().to_string();
                form.error = None;
                self.status = format!("{title}…");
                ipc.send(op, args, Tag::Action { title });
            }
            Err(e) => form.error = Some(e),
        }
    }
}

fn short_hash(h: &str) -> String {
    h.chars().take(10).collect()
}

/// Build the `vault_reveal` IPC args. `id` is threaded in only when `Some`, so
/// a whole-file (M2b) reveal's payload stays byte-identical to the pre-M2c
/// caller (matching the `skip_serializing_if = "Option::is_none"` on the verb).
fn vault_reveal_args(path: &str, master_password: &str, id: Option<&str>) -> Value {
    let mut args = json!({ "path": path, "master_password": master_password });
    if let Some(id) = id {
        args["id"] = json!(id);
    }
    args
}

/// M2c: parse the inline `<vault id="…">` region ids out of a file's daemon
/// projection (a `read_file` reply). The daemon renders each encrypted region
/// as `<vault id="…">[encrypted]</vault>`; this pulls the ids in document order,
/// de-duplicated (a repeated id reveals the same region). Tolerates single- or
/// double-quoted ids and extra whitespace/attributes inside the opening tag.
pub fn parse_vault_region_ids(content: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = content;
    while let Some(pos) = rest.find("<vault") {
        rest = &rest[pos + "<vault".len()..];
        // Scope the `id=` search to this opening tag (up to its closing `>`).
        let Some(tag_end) = rest.find('>') else { break };
        if let Some(id) = extract_id_attr(&rest[..tag_end]) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        rest = &rest[tag_end + 1..];
    }
    ids
}

/// Pull the `id="…"` (or `id='…'`) attribute value out of a `<vault …>` opening
/// tag's inner text. Requires `id` to be a whole attribute name (not a suffix of
/// e.g. `valid`) so an unrelated attribute can't be mistaken for the region id.
fn extract_id_attr(tag: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut i = 0;
    while let Some(rel) = tag[i..].find("id") {
        let start = i + rel;
        let name_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let mut j = start + 2;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if name_ok && bytes.get(j) == Some(&b'=') {
            let mut k = j + 1;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            match bytes.get(k) {
                Some(&q) if q == b'"' || q == b'\'' => {
                    let after = &tag[k + 1..];
                    if let Some(end) = after.find(q as char) {
                        return Some(after[..end].to_string());
                    }
                }
                _ => {}
            }
        }
        i = start + 2;
    }
    None
}

/// growlight enablement signal: is `config/growlight.toml` present among the
/// `config/` listing? This is the lean gate — growlight is "enabled" on a garden
/// exactly when its fleet config exists, detected without assuming the
/// `growlight/` pillar dir exists.
pub fn config_has_growlight(entries: &[softfig_ipc::TreeEntry]) -> bool {
    entries
        .iter()
        .any(|e| !e.is_dir && e.name == "growlight.toml")
}

/// Parse the managed backlog queue table out of `growlight/backlog/CLAUDE.md`.
/// Only the default queue is read — the region between `<!-- softfig:queue -->`
/// and `<!-- /softfig:queue -->`; per-queue tables (`softfig:queue:<name>`) are
/// ignored. The markdown header + `|---|` separator rows are skipped.
pub fn parse_growlight_queue(md: &str) -> Vec<GrowlightRow> {
    let mut rows = Vec::new();
    let mut in_region = false;
    for line in md.lines() {
        let t = line.trim();
        if t == "<!-- softfig:queue -->" {
            in_region = true;
            continue;
        }
        if t == "<!-- /softfig:queue -->" {
            break;
        }
        if !in_region || !t.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = t.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 5 {
            continue;
        }
        // Skip the header row (`| # | id | … |`) and the `|---|` separator.
        if cells[0] == "#" || cells[0].chars().all(|c| c == '-' || c == ':') {
            continue;
        }
        rows.push(GrowlightRow {
            num: cells[0].to_string(),
            id: cells[1].to_string(),
            kind: cells[2].to_string(),
            title: cells[3].to_string(),
            status: cells[4].to_string(),
        });
    }
    rows
}

/// The highest-numbered `NNN-*.md` baton-log entry (the latest handoff) from a
/// `list_tree growlight/baton-log` reply. Non-numeric entries (e.g. `CLAUDE.md`)
/// and directories are ignored; returns the entry's repo-relative path.
pub fn latest_baton_path(entries: &[softfig_ipc::TreeEntry]) -> Option<String> {
    entries
        .iter()
        .filter(|e| !e.is_dir)
        .filter_map(|e| {
            let num: u64 = e.name.split('-').next()?.parse().ok()?;
            Some((num, e.path.clone()))
        })
        .max_by_key(|(num, _)| *num)
        .map(|(_, path)| path)
}

/// One-line summary of a deploy `Report` for the status bar. Names the counts
/// that happened and, when some target conflicted (no `--force`), flags that
/// `F` will force.
fn deploy_summary(r: &DeployApplyReply) -> String {
    let mut s = format!(
        "deployed: {} created, {} replaced, {} copied, {} skipped, {} forced",
        r.created.len(),
        r.replaced.len(),
        r.copied.len(),
        r.skipped.len(),
        r.forced.len(),
    );
    if !r.conflicts.is_empty() {
        s.push_str(&format!(" · {} conflicted (F to force)", r.conflicts.len()));
    }
    s
}

/// First 16 hex chars of a device-id / transport fingerprint for compact
/// display (mirrors the CLI's `short_fp`).
pub fn short_fp(fp: &str) -> &str {
    &fp[..16.min(fp.len())]
}

fn summarize_action(v: &Value) -> String {
    // Vault seal: report how many tracked files were newly Layer-B-sealed.
    if let Some(sealed) = v.get("newly_sealed").and_then(|x| x.as_array()) {
        return format!("sealed {} file(s)", sealed.len());
    }
    // Vault unseal: whether the pattern was actually present.
    if let Some(removed) = v.get("removed").and_then(|x| x.as_bool()) {
        return if removed {
            "removed".into()
        } else {
            "pattern not present".into()
        };
    }
    for key in ["path", "to", "hash"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            return format!("{key}={s}");
        }
    }
    "ok".into()
}

fn format_commit(r: &ShowReply) -> String {
    let c = &r.commit;
    let mut out = String::new();
    out.push_str(&format!("hash:    {}\n", c.hash));
    if let Some(p) = &c.parent {
        out.push_str(&format!("parent:  {p}\n"));
    }
    out.push_str(&format!("intent:  {}\n", c.intent));
    out.push_str(&format!("author:  {}\n", c.author_device));
    out.push_str(&format!("payload: {}\n\n", c.payload));
    out.push_str("root tree:\n");
    for e in &r.root_tree {
        out.push_str(&format!("  {:<4} {}\n", e.kind, e.name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_blocks_actions_and_nav() {
        let mut app = App::new();
        assert!(app.locked);
        app.open_form(ActionKind::LogDecision);
        // open_form refuses while locked → still no overlay
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn unlocked_opens_form() {
        let mut app = App::new();
        app.locked = false;
        app.open_form(ActionKind::Archive);
        assert!(matches!(app.overlay, Overlay::Form(_)));
    }

    #[test]
    fn summarize_prefers_path() {
        assert_eq!(
            summarize_action(&json!({"path":"journal/x.md","hash":"abc"})),
            "path=journal/x.md"
        );
        assert_eq!(summarize_action(&json!({"hash":"abc"})), "hash=abc");
        assert_eq!(summarize_action(&json!({})), "ok");
    }

    #[test]
    fn summarize_vault_replies() {
        assert_eq!(
            summarize_action(&json!({"newly_sealed":["a","b"],"schema_commit":"x"})),
            "sealed 2 file(s)"
        );
        assert_eq!(summarize_action(&json!({"removed":true})), "removed");
        assert_eq!(
            summarize_action(&json!({"removed":false})),
            "pattern not present"
        );
    }

    fn dummy_ipc() -> IpcClient {
        // The worker thread idles until a send; the VaultList / Reveal Ok
        // paths issue none, so a bogus socket path is never connected.
        IpcClient::spawn(std::path::PathBuf::from("/nonexistent/softfig.sock"))
    }

    #[test]
    fn vault_list_populates_view() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::VaultList,
                result: Ok(json!({
                    "globs": ["secrets/**"],
                    "matching_files": ["secrets/api-keys.toml", "secrets/coords.txt"],
                })),
            },
            &mut ipc,
        );
        assert!(app.vault_loaded);
        assert_eq!(app.vault_globs, vec!["secrets/**".to_string()]);
        assert_eq!(app.vault_files.len(), 2);
    }

    #[test]
    fn reveal_reply_records_path_not_plaintext() {
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::Reveal {
            path: "secrets/api-keys.toml".into(),
            buf: "pw".into(),
            error: None,
            id: None,
        };
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::Reveal {
                    path: "secrets/api-keys.toml".into(),
                },
                result: Ok(json!({
                    "temp_path": "/run/user/1000/softfig-reveal-abc.toml",
                    "expires_at": 1000,
                })),
            },
            &mut ipc,
        );
        let info = app.reveal.expect("reveal recorded");
        assert_eq!(info.temp_path, "/run/user/1000/softfig-reveal-abc.toml");
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("press c to copy"));
    }

    // ---- M2c: inline-region reveal (slice 003) ----

    #[test]
    fn parse_region_ids_from_projection() {
        // The daemon projects each encrypted region as `[encrypted]`; the ids
        // come out in document order, de-duplicated.
        let content = "\
host = \"db\"
password = <vault id=\"db-pw\">[encrypted]</vault>
token = <vault id='api-token'>[encrypted]</vault>
backup = <vault id=\"db-pw\">[encrypted]</vault>
";
        assert_eq!(
            parse_vault_region_ids(content),
            vec!["db-pw".to_string(), "api-token".to_string()],
        );
    }

    #[test]
    fn parse_region_ids_ignores_non_id_attrs_and_plain_text() {
        // A file with no `<vault>` tags → nothing; an unrelated attribute whose
        // name merely ends in "id" must not be mistaken for the region id.
        assert!(parse_vault_region_ids("just prose, no secrets").is_empty());
        assert_eq!(
            parse_vault_region_ids("<vault valid=\"no\" id=\"real\">[encrypted]</vault>"),
            vec!["real".to_string()],
        );
    }

    #[test]
    fn vault_reveal_args_include_id_only_when_present() {
        // Whole-file (M2b) reveal: no `id` key at all, byte-identical to the
        // pre-M2c payload.
        let whole = vault_reveal_args("secrets/db.toml", "pw", None);
        assert_eq!(whole["path"], json!("secrets/db.toml"));
        assert_eq!(whole["master_password"], json!("pw"));
        assert!(whole.get("id").is_none());
        // Per-region (M2c) reveal: the chosen id rides along.
        let region = vault_reveal_args("secrets/db.toml", "pw", Some("db-pw"));
        assert_eq!(region["id"], json!("db-pw"));
    }

    #[test]
    fn region_bearing_file_opens_the_picker_then_carries_the_id() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Browse;
        app.tree.set_children(
            "",
            vec![softfig_ipc::TreeEntry {
                name: "db.toml".into(),
                path: "config/db.toml".into(),
                is_dir: false,
            }],
        );
        let mut ipc = dummy_ipc();

        // Opening the file parses its inline regions off the read_file reply.
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::ReadFile {
                    path: "config/db.toml".into(),
                },
                result: Ok(json!({
                    "path": "config/db.toml",
                    "content": "pw = <vault id=\"db-pw\">[encrypted]</vault>\n\
                                tok = <vault id=\"api\">[encrypted]</vault>\n",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert_eq!(app.regions, vec!["db-pw".to_string(), "api".to_string()]);
        assert_eq!(app.regions_path.as_deref(), Some("config/db.toml"));

        // `x` on a region-bearing file opens the region picker, not the
        // whole-file password prompt.
        app.start_reveal(&mut ipc);
        match &app.overlay {
            Overlay::RevealRegion { path, ids, selected } => {
                assert_eq!(path, "config/db.toml");
                assert_eq!(ids, &vec!["db-pw".to_string(), "api".to_string()]);
                assert_eq!(*selected, 0);
            }
            other => panic!("expected region picker, got {other:?}"),
        }

        // Move to the second region and confirm — the masked-password prompt
        // now carries that region's id.
        app.handle_key(
            KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
            &mut ipc,
        );
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &mut ipc);
        match &app.overlay {
            Overlay::Reveal { path, id, .. } => {
                assert_eq!(path, "config/db.toml");
                assert_eq!(id.as_deref(), Some("api"));
            }
            other => panic!("expected reveal prompt with id, got {other:?}"),
        }
    }

    #[test]
    fn plain_file_reveal_skips_the_picker() {
        // A file with no inline regions falls through to the whole-file prompt.
        let mut app = App::new();
        app.locked = false;
        app.view = View::Browse;
        app.tree.set_children(
            "",
            vec![softfig_ipc::TreeEntry {
                name: "notes.md".into(),
                path: "notes.md".into(),
                is_dir: false,
            }],
        );
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::ReadFile {
                    path: "notes.md".into(),
                },
                result: Ok(json!({
                    "path": "notes.md",
                    "content": "no secrets here\n",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert!(app.regions.is_empty());
        app.start_reveal(&mut ipc);
        match &app.overlay {
            Overlay::Reveal { path, id, .. } => {
                assert_eq!(path, "notes.md");
                assert!(id.is_none());
            }
            other => panic!("expected whole-file reveal prompt, got {other:?}"),
        }
    }

    #[test]
    fn preview_scroll_clamps_and_pages() {
        let mut app = App::new();
        // Renderer-supplied geometry: 10 visible rows over 50 wrapped lines.
        app.preview_viewport = 10;
        app.preview_total = 50;
        assert_eq!(app.preview_scroll, 0);

        app.scroll_preview(5);
        assert_eq!(app.preview_scroll, 5);
        app.scroll_preview(-100); // clamp at the top
        assert_eq!(app.preview_scroll, 0);

        app.preview_to_bottom();
        assert_eq!(app.preview_scroll, 40, "max = total - viewport");
        app.scroll_preview(100); // never past the bottom
        assert_eq!(app.preview_scroll, 40);
        app.preview_to_top();
        assert_eq!(app.preview_scroll, 0);
    }

    #[test]
    fn short_preview_does_not_scroll() {
        let mut app = App::new();
        // Content shorter than the viewport → max scroll is zero.
        app.preview_viewport = 20;
        app.preview_total = 5;
        app.scroll_preview(10);
        assert_eq!(app.preview_scroll, 0);
        app.preview_to_bottom();
        assert_eq!(app.preview_scroll, 0);
    }

    #[test]
    fn preview_scroll_resets_on_new_file() {
        let mut app = App::new();
        app.locked = false;
        app.preview_viewport = 10;
        app.preview_total = 50;
        app.preview_scroll = 20;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::ReadFile {
                    path: "meta/CLAUDE.md".into(),
                },
                result: Ok(json!({
                    "path": "meta/CLAUDE.md",
                    "content": "fresh file",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert_eq!(app.preview, "fresh file");
        assert_eq!(app.preview_scroll, 0, "opening a new file jumps to the top");
    }

    #[test]
    fn mouse_wheel_scrolls_preview() {
        let mut app = App::new();
        app.preview_viewport = 5;
        app.preview_total = 100;
        let mut ipc = dummy_ipc();
        let wheel = |kind| MouseEvent {
            kind,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(wheel(MouseEventKind::ScrollDown), &mut ipc);
        assert_eq!(app.preview_scroll, 3);
        app.handle_mouse(wheel(MouseEventKind::ScrollDown), &mut ipc);
        assert_eq!(app.preview_scroll, 6);
        app.handle_mouse(wheel(MouseEventKind::ScrollUp), &mut ipc);
        assert_eq!(app.preview_scroll, 3);
    }

    fn peer(name: &str, fp: &str) -> PairPeer {
        PairPeer {
            fingerprint: fp.into(),
            name: name.into(),
            transport_pubkey: "aa".repeat(32),
            endpoints: vec!["192.168.1.5:9100".into()],
            paired_at: 1_700_000_000,
        }
    }

    fn pending(name: &str, fp: &str, sas: &str) -> PendingPairing {
        PendingPairing {
            pairing_id: format!("pid-{name}"),
            sas: sas.into(),
            fingerprint: fp.into(),
            name: name.into(),
        }
    }

    #[test]
    fn pair_list_flattens_and_clamps() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::PairList,
                result: Ok(serde_json::to_value(softfig_ipc::PairListReply {
                    peers: vec![peer("tablet", &"11".repeat(32))],
                    pending: vec![pending("laptop", &"22".repeat(32), "123 456")],
                })
                .unwrap()),
            },
            &mut ipc,
        );
        assert!(app.peers_loaded);
        assert_eq!(app.peers.len(), 1);
        assert_eq!(app.pending.len(), 1);
        // Peers first, then pending.
        assert_eq!(
            app.peer_rows,
            vec![PeerRow::Peer(0), PeerRow::Pending(0)]
        );
    }

    #[test]
    fn pair_begin_reply_opens_confirm() {
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::PairBegin {
            fingerprint: "22".repeat(32),
            endpoint: String::new(),
            focus: PairField::Fingerprint,
            error: None,
        };
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::PairBegin,
                result: Ok(serde_json::to_value(PairBeginReply {
                    pairing_id: "pid-1".into(),
                    sas: "123 456".into(),
                    fingerprint: "22".repeat(32),
                    name: "laptop".into(),
                })
                .unwrap()),
            },
            &mut ipc,
        );
        match &app.overlay {
            Overlay::PairConfirm { sas, name, pairing_id, .. } => {
                assert_eq!(sas, "123 456");
                assert_eq!(name, "laptop");
                assert_eq!(pairing_id, "pid-1");
            }
            other => panic!("expected PairConfirm, got {other:?}"),
        }
    }

    #[test]
    fn activate_pending_confirms_peer_does_not() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Peers;
        app.peers = vec![peer("tablet", &"11".repeat(32))];
        app.pending = vec![pending("laptop", &"22".repeat(32), "123 456")];
        app.rebuild_peer_rows();
        let mut ipc = dummy_ipc();

        // Row 0 is the settled peer → activating does not open a confirm.
        app.peers_selected = 0;
        app.activate(&mut ipc);
        assert!(matches!(app.overlay, Overlay::None));

        // Row 1 is the pending pairing → activating opens the SAS confirm.
        app.peers_selected = 1;
        app.activate(&mut ipc);
        match &app.overlay {
            Overlay::PairConfirm { name, sas, .. } => {
                assert_eq!(name, "laptop");
                assert_eq!(sas, "123 456");
            }
            other => panic!("expected PairConfirm, got {other:?}"),
        }
    }

    #[test]
    fn unpair_targets_ring_member_only() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Peers;
        app.peers = vec![peer("tablet", &"11".repeat(32))];
        app.pending = vec![pending("laptop", &"22".repeat(32), "123 456")];
        app.rebuild_peer_rows();

        app.peers_selected = 0; // a ring member
        app.start_unpair();
        match &app.overlay {
            Overlay::Unpair { name, fingerprint, .. } => {
                assert_eq!(name, "tablet");
                assert_eq!(fingerprint, &"11".repeat(32));
            }
            other => panic!("expected Unpair, got {other:?}"),
        }

        app.overlay = Overlay::None;
        app.peers_selected = 1; // the pending row → cannot unpair
        app.start_unpair();
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("paired device"));
    }

    #[test]
    fn pair_begin_requires_a_fingerprint() {
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::PairBegin {
            fingerprint: "   ".into(),
            endpoint: String::new(),
            focus: PairField::Fingerprint,
            error: None,
        };
        let mut ipc = dummy_ipc();
        app.submit_pair_begin(&mut ipc);
        match &app.overlay {
            Overlay::PairBegin { error, .. } => {
                assert!(error.as_deref().unwrap().contains("fingerprint"));
            }
            other => panic!("expected PairBegin still open, got {other:?}"),
        }
    }

    fn discovered(name: Option<&str>, fp: &str, endpoint: Option<&str>) -> DiscoveredDevice {
        DiscoveredDevice {
            name: name.map(str::to_string),
            fingerprint: fp.into(),
            endpoint: endpoint.map(str::to_string),
            last_seen_secs: 3,
        }
    }

    #[test]
    fn discover_list_appends_rows_and_skips_duplicates() {
        let mut app = App::new();
        app.peers = vec![peer("tablet", &"11".repeat(32))];
        app.pending = vec![pending("laptop", &"22".repeat(32), "123 456")];
        // One discovered device duplicates the ring member (skipped); one is new.
        app.discovered = vec![
            discovered(Some("tablet"), &"11".repeat(32), Some("10.0.0.2:9100")),
            discovered(Some("desktop"), &"33".repeat(32), Some("10.0.0.3:9100")),
        ];
        app.rebuild_peer_rows();
        assert_eq!(
            app.peer_rows,
            vec![
                PeerRow::Peer(0),
                PeerRow::Pending(0),
                PeerRow::Discovered(1), // index 0 was a dup of the ring member
            ]
        );
    }

    #[test]
    fn p_on_discovered_initiates_pairing() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Peers;
        app.discovered = vec![discovered(Some("desktop"), &"33".repeat(32), Some("10.0.0.3:9100"))];
        app.rebuild_peer_rows();
        app.peers_selected = 0; // the lone discovered row
        let mut ipc = dummy_ipc();

        app.pair_selected(&mut ipc);
        // No overlay yet (it opens on the pair_begin reply); status reflects the
        // in-flight handshake against the named device.
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("desktop"), "status was {:?}", app.status);
    }

    #[test]
    fn p_on_ring_member_opens_manual_overlay() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Peers;
        app.peers = vec![peer("tablet", &"11".repeat(32))];
        app.rebuild_peer_rows();
        app.peers_selected = 0; // a ring member, not discovered
        let mut ipc = dummy_ipc();

        app.pair_selected(&mut ipc);
        assert!(
            matches!(app.overlay, Overlay::PairBegin { .. }),
            "p on a non-discovered row opens the manual initiate overlay"
        );
    }

    #[test]
    fn start_reveal_needs_a_selected_file() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Vault;
        let mut ipc = dummy_ipc();
        // No sealed files loaded → no overlay, a hint instead.
        app.start_reveal(&mut ipc);
        assert!(matches!(app.overlay, Overlay::None));

        app.vault_files = vec!["secrets/api-keys.toml".into()];
        app.start_reveal(&mut ipc);
        match &app.overlay {
            Overlay::Reveal { path, .. } => assert_eq!(path, "secrets/api-keys.toml"),
            other => panic!("expected reveal overlay, got {other:?}"),
        }
    }

    // ---- M5b Backup tab ----

    fn hosted_chain(fp: &str, name: &str, height: u64) -> HostedChain {
        HostedChain {
            fingerprint: fp.into(),
            name: Some(name.into()),
            tip: Some("deadbeef".into()),
            height,
            objects: height * 3,
            bytes: height * 1024,
            last_sync: Some(1_700_000_000),
        }
    }

    #[test]
    fn replica_status_populates_and_flattens() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::ReplicaStatus,
                result: Ok(serde_json::to_value(softfig_ipc::ReplicaStatusReply {
                    host: true,
                    push_to: vec!["11".repeat(32)],
                    hosted: vec![hosted_chain(&"22".repeat(32), "tablet", 4)],
                })
                .unwrap()),
            },
            &mut ipc,
        );
        assert!(app.backup_loaded);
        assert!(app.replica_host);
        assert_eq!(app.replica_push_to.len(), 1);
        assert_eq!(app.hosted.len(), 1);
        // Hosts-that-back-me first, then chains-I-host.
        assert_eq!(
            app.backup_rows,
            vec![BackupRow::PushTo(0), BackupRow::Hosted(0)]
        );
    }

    #[test]
    fn grant_requires_a_fingerprint() {
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::ReplicaGrant {
            fingerprint: "   ".into(),
            error: None,
        };
        let mut ipc = dummy_ipc();
        app.submit_grant(&mut ipc);
        match &app.overlay {
            Overlay::ReplicaGrant { error, .. } => {
                assert!(error.as_deref().unwrap().contains("fingerprint"));
            }
            other => panic!("expected ReplicaGrant still open, got {other:?}"),
        }
    }

    #[test]
    fn revoke_targets_a_granted_host_only() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Backup;
        app.replica_push_to = vec!["11".repeat(32)];
        app.hosted = vec![hosted_chain(&"22".repeat(32), "tablet", 4)];
        app.rebuild_backup_rows();

        // Row 0 is a granted host → revoke opens the confirm on its fingerprint.
        app.backup_selected = 0;
        app.start_revoke();
        match &app.overlay {
            Overlay::ReplicaRevoke { fingerprint, .. } => {
                assert_eq!(fingerprint, &"11".repeat(32));
            }
            other => panic!("expected ReplicaRevoke, got {other:?}"),
        }

        // Row 1 is a chain I host → cannot be revoked (it's a mirror, not a grant).
        app.overlay = Overlay::None;
        app.backup_selected = 1;
        app.start_revoke();
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("granted host"));
    }

    #[test]
    fn revoke_is_blocked_when_locked() {
        // Stale rows from before a re-lock must not open the revoke confirm
        // (mirrors `open_grant`'s locked guard; the daemon would reject it too).
        let mut app = App::new();
        app.locked = true;
        app.view = View::Backup;
        app.replica_push_to = vec!["11".repeat(32)];
        app.rebuild_backup_rows();
        app.backup_selected = 0;
        app.start_revoke();
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("locked"));
    }

    #[test]
    fn grant_reply_closes_overlay_and_reloads() {
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::ReplicaGrant {
            fingerprint: "11".repeat(32),
            error: None,
        };
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::ReplicaGrant,
                result: Ok(serde_json::to_value(ReplicaGrantReply {
                    fingerprint: "11".repeat(32),
                    granted: true,
                })
                .unwrap()),
            },
            &mut ipc,
        );
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("granted"), "status was {:?}", app.status);
    }

    #[test]
    fn five_key_switches_to_backup() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.handle_key(
            KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_eq!(app.view, View::Backup);
    }

    // ---- M4 Deploy tab ----

    fn plan_entry(name: &str, action: DeployAction, reason: Option<&str>) -> DeployPlanEntry {
        DeployPlanEntry {
            name: name.into(),
            action,
            target: format!("/home/u/.{name}"),
            conflict_reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn deploy_plan_populates_then_clamps_on_shrink() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::DeployPlan,
                result: Ok(serde_json::to_value(DeployPlanReply {
                    entries: vec![
                        plan_entry("bashrc", DeployAction::CreateSymlink, None),
                        plan_entry("vimrc", DeployAction::Conflict, Some("existing file")),
                    ],
                    has_conflicts: true,
                })
                .unwrap()),
            },
            &mut ipc,
        );
        assert!(app.deploy_loaded);
        assert_eq!(app.deploy_entries.len(), 2);
        assert!(app.deploy_has_conflicts);

        // Select the last row, then a smaller plan arrives → selection clamps.
        app.deploy_selected = 1;
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::DeployPlan,
                result: Ok(serde_json::to_value(DeployPlanReply {
                    entries: vec![plan_entry("bashrc", DeployAction::SkipUnchanged, None)],
                    has_conflicts: false,
                })
                .unwrap()),
            },
            &mut ipc,
        );
        assert_eq!(app.deploy_entries.len(), 1);
        assert_eq!(app.deploy_selected, 0);
        assert!(!app.deploy_has_conflicts);
    }

    #[test]
    fn force_apply_confirm_opens_and_cancels() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Deploy;
        app.start_force_apply();
        assert!(matches!(app.overlay, Overlay::DeployForce { .. }));

        let mut ipc = dummy_ipc();
        app.handle_key(
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("cancel"));
    }

    #[test]
    fn force_apply_blocked_when_locked() {
        // A stale Deploy view after a re-lock must not open the force confirm.
        let mut app = App::new();
        app.locked = true;
        app.view = View::Deploy;
        app.start_force_apply();
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("locked"));
    }

    #[test]
    fn deploy_apply_reply_summarizes_and_closes_force() {
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::DeployForce { error: None };
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::DeployApply,
                result: Ok(serde_json::to_value(DeployApplyReply {
                    created: vec!["bashrc".into()],
                    replaced: vec![],
                    copied: vec![],
                    skipped: vec!["gitconfig".into()],
                    conflicts: vec![],
                    forced: vec!["vimrc".into()],
                    warnings: vec![],
                })
                .unwrap()),
            },
            &mut ipc,
        );
        assert!(matches!(app.overlay, Overlay::None));
        assert!(app.status.contains("1 created"), "status was {:?}", app.status);
        assert!(app.status.contains("1 forced"), "status was {:?}", app.status);
    }

    #[test]
    fn deploy_summary_flags_conflicts() {
        let r = DeployApplyReply {
            created: vec![],
            replaced: vec![],
            copied: vec![],
            skipped: vec![],
            conflicts: vec!["vimrc (existing file)".into()],
            forced: vec![],
            warnings: vec![],
        };
        let s = deploy_summary(&r);
        assert!(s.contains("1 conflicted"), "summary was {s:?}");
        assert!(s.contains("F to force"), "summary was {s:?}");
    }

    #[test]
    fn apply_blocked_when_locked() {
        let mut app = App::new();
        app.locked = true;
        let mut ipc = dummy_ipc();
        app.apply_deploy(&mut ipc, false);
        assert!(app.status.contains("locked"));
    }

    #[test]
    fn six_key_switches_to_deploy() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.handle_key(
            KeyEvent::new(KeyCode::Char('6'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_eq!(app.view, View::Deploy);
    }

    // ---- slice 004: read-only growlight section ----

    fn tree_entry(name: &str, path: &str, is_dir: bool) -> softfig_ipc::TreeEntry {
        softfig_ipc::TreeEntry {
            name: name.to_string(),
            path: path.to_string(),
            is_dir,
        }
    }

    const SAMPLE_QUEUE: &str = "\
# growlight/backlog/

## Queue

<!-- softfig:queue -->

| # | id | type | title | status |
|---|----|------|-------|--------|
| 1 | growlightd-crash-diagnostics | milestone | crash diag | done |
| 2 | tui-modernize | milestone | Modernize the TUI | active |
| 3 | 020 | task | code-review records | queued |

<!-- /softfig:queue -->

## Queue: smoke-a

<!-- softfig:queue:smoke-a -->

| # | id | type | title | status |
|---|----|------|-------|--------|
| 1 | 021 | task | smoke marker | done |

<!-- /softfig:queue:smoke-a -->
";

    #[test]
    fn parse_queue_skips_header_separator_and_other_queues() {
        let rows = parse_growlight_queue(SAMPLE_QUEUE);
        // Only the DEFAULT queue's three rows — the smoke-a queue is ignored,
        // and the header + `|---|` separator never appear.
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].id, "growlightd-crash-diagnostics");
        assert_eq!(rows[0].status, "done");
        assert_eq!(rows[1].id, "tui-modernize");
        assert_eq!(rows[1].kind, "milestone");
        assert_eq!(rows[1].title, "Modernize the TUI");
        assert_eq!(rows[1].status, "active");
        assert_eq!(rows[2].id, "020");
        assert!(rows.iter().all(|r| r.id != "021"), "leaked smoke-a queue");
    }

    #[test]
    fn config_growlight_signal() {
        // Present ⇒ enabled; a directory named the same, or absence ⇒ not.
        assert!(config_has_growlight(&[
            tree_entry("keeper.toml", "config/keeper.toml", false),
            tree_entry("growlight.toml", "config/growlight.toml", false),
        ]));
        assert!(!config_has_growlight(&[tree_entry(
            "keeper.toml",
            "config/keeper.toml",
            false
        )]));
        assert!(!config_has_growlight(&[tree_entry(
            "growlight.toml",
            "config/growlight.toml",
            true // a dir, not the file
        )]));
    }

    #[test]
    fn latest_baton_picks_highest_numbered_entry() {
        let entries = vec![
            tree_entry("CLAUDE.md", "growlight/baton-log/CLAUDE.md", false),
            tree_entry(
                "101-tui-modernize-001.md",
                "growlight/baton-log/101-tui-modernize-001.md",
                false,
            ),
            tree_entry(
                "103-tui-modernize-003.md",
                "growlight/baton-log/103-tui-modernize-003.md",
                false,
            ),
            tree_entry(
                "102-tui-modernize-002.md",
                "growlight/baton-log/102-tui-modernize-002.md",
                false,
            ),
        ];
        assert_eq!(
            latest_baton_path(&entries).as_deref(),
            Some("growlight/baton-log/103-tui-modernize-003.md")
        );
        // No numbered entries ⇒ nothing to show.
        assert_eq!(
            latest_baton_path(&[tree_entry("CLAUDE.md", "x/CLAUDE.md", false)]),
            None
        );
    }

    #[test]
    fn probe_reply_gates_enablement_present() {
        let mut app = App::new();
        assert_eq!(app.growlight_enabled, None); // unprobed
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightProbe,
                result: Ok(json!({
                    "entries": [
                        {"name": "keeper.toml", "path": "config/keeper.toml", "is_dir": false},
                        {"name": "growlight.toml", "path": "config/growlight.toml", "is_dir": false},
                    ]
                })),
            },
            &mut ipc,
        );
        assert_eq!(app.growlight_enabled, Some(true));
    }

    #[test]
    fn probe_reply_disables_when_absent_or_errored() {
        let mut ipc = dummy_ipc();

        // config/ present but no growlight.toml ⇒ disabled.
        let mut app = App::new();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightProbe,
                result: Ok(json!({
                    "entries": [
                        {"name": "keeper.toml", "path": "config/keeper.toml", "is_dir": false},
                    ]
                })),
            },
            &mut ipc,
        );
        assert_eq!(app.growlight_enabled, Some(false));

        // config/ missing entirely (Err) ⇒ disabled, silently (no error surfaced).
        let mut app2 = App::new();
        app2.apply_reply(
            Reply {
                id: 2,
                tag: Tag::GrowlightProbe,
                result: Err((softfig_ipc::ErrorKind::Internal, "no such path".into())),
            },
            &mut ipc,
        );
        assert_eq!(app2.growlight_enabled, Some(false));
    }

    #[test]
    fn growlight_tab_key_inert_until_enabled() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        // Not yet enabled: `8` must NOT switch views (tab absent).
        app.handle_key(
            KeyEvent::new(KeyCode::Char('8'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_ne!(app.view, View::Growlight);

        // Enabled: `8` switches to the growlight view (Shares took `7`).
        app.growlight_enabled = Some(true);
        app.handle_key(
            KeyEvent::new(KeyCode::Char('8'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_eq!(app.view, View::Growlight);
    }

    #[test]
    fn queue_reply_populates_and_finds_active_item() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightQueue,
                result: Ok(json!({
                    "path": "growlight/backlog/CLAUDE.md",
                    "content": SAMPLE_QUEUE,
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert!(app.growlight_loaded);
        assert_eq!(app.growlight_queue.len(), 3);
        assert_eq!(
            app.growlight_active_item().map(|r| r.id.as_str()),
            Some("tui-modernize")
        );
    }

    #[test]
    fn baton_reply_records_title_and_body() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightBaton {
                    path: "growlight/baton-log/103-tui-modernize-003.md".into(),
                },
                result: Ok(json!({
                    "path": "growlight/baton-log/103-tui-modernize-003.md",
                    "content": "# baton tui-modernize #3\n\nshipped slice 003",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert_eq!(
            app.growlight_baton_title.as_deref(),
            Some("103-tui-modernize-003.md")
        );
        assert!(app.growlight_baton.unwrap().contains("shipped slice 003"));
    }

    // ---- M5d slice 004: Shares tab ----

    fn share_info(
        id: &str,
        mount: &str,
        enabled: bool,
        key_id: Option<&str>,
    ) -> SharedSubtreeInfo {
        SharedSubtreeInfo {
            id: id.into(),
            mount_path: mount.into(),
            ref_name: format!("chain/{id}"),
            enabled,
            key_id: key_id.map(str::to_string),
        }
    }

    #[test]
    fn ceremony_state_tracks_key_id() {
        // The pure "progress state machine": an empty key_id is Pending, a
        // filled one (S derived + transcript verified) is Keyed.
        let pending = share_info("journals", "projects/journals", true, None);
        let keyed = share_info("journals", "projects/journals", true, Some("S-abc123"));
        assert_eq!(ceremony_state(&pending), CeremonyState::Pending);
        assert_eq!(ceremony_state(&keyed), CeremonyState::Keyed);
    }

    #[test]
    fn shared_subtree_list_populates_then_clamps_on_shrink() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::SharedSubtreeList,
                result: Ok(json!({ "subtrees": [
                    {"id":"a","mount_path":"projects/a","ref_name":"chain/a","enabled":true,"key_id":"S-a"},
                    {"id":"b","mount_path":"projects/b","ref_name":"chain/b","enabled":false}
                ]})),
            },
            &mut ipc,
        );
        assert!(app.shares_loaded);
        assert_eq!(app.shares.len(), 2);
        app.shares_selected = 1;
        // A later, shorter list clamps the selection back in-range.
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::SharedSubtreeList,
                result: Ok(json!({ "subtrees": [
                    {"id":"a","mount_path":"projects/a","ref_name":"chain/a","enabled":true,"key_id":"S-a"}
                ]})),
            },
            &mut ipc,
        );
        assert_eq!(app.shares.len(), 1);
        assert_eq!(app.shares_selected, 0);
    }

    #[test]
    fn add_share_validates_then_dispatches() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Shares;
        let mut ipc = dummy_ipc();
        app.open_add_share();
        // An empty path is rejected client-side — no dispatch, error set.
        app.submit_add_share(&mut ipc);
        match &app.overlay {
            Overlay::AddShare { error, .. } => assert!(error.is_some()),
            other => panic!("expected AddShare overlay, got {other:?}"),
        }
        // A real path submits (leading/trailing slashes trimmed away).
        if let Overlay::AddShare { mount_path, .. } = &mut app.overlay {
            *mount_path = "/projects/journals/".into();
        }
        app.submit_add_share(&mut ipc);
        assert!(app.status.contains("sharing"));
    }

    #[test]
    fn toggle_share_picks_enable_or_disable() {
        // The dispatch is proven by the status line it sets synchronously (the
        // worker socket is a dead stub, so no reply is drained).
        let mut app = App::new();
        app.locked = false;
        app.view = View::Shares;
        let mut ipc = dummy_ipc();
        app.shares = vec![share_info("a", "projects/a", true, Some("S-a"))];
        app.shares_selected = 0;
        app.toggle_share(&mut ipc);
        assert!(app.status.contains("toggling"));
        // No selection → a hint, never a dispatch.
        app.shares.clear();
        app.status = "ready".into();
        app.toggle_share(&mut ipc);
        assert!(app.status.contains("select a shared folder"));
    }

    #[test]
    fn remove_share_confirm_flow() {
        let mut app = App::new();
        app.locked = false;
        app.view = View::Shares;
        let mut ipc = dummy_ipc();
        app.shares = vec![share_info("journals", "projects/journals", true, None)];
        app.shares_selected = 0;
        app.start_remove_share();
        match &app.overlay {
            Overlay::RemoveShare { id, mount_path, .. } => {
                assert_eq!(id, "journals");
                assert_eq!(mount_path, "projects/journals");
            }
            other => panic!("expected RemoveShare overlay, got {other:?}"),
        }
        // `n` cancels without dispatching.
        app.handle_key(
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn status_reply_surfaces_shared_key_divergence() {
        let mut app = App::new();
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::Status,
                result: Ok(json!({
                    "state": "unlocked", "tip": null, "garden_root": "/g",
                    "protocol_version": 1,
                    "shared_key_divergence": "shared-key divergence for chain chain/x: differs"
                })),
            },
            &mut ipc,
        );
        assert!(app
            .shared_key_divergence
            .as_deref()
            .unwrap()
            .contains("divergence"));
    }
}
