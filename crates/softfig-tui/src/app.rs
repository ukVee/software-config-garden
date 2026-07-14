//! Central TUI state + the key→IPC and reply→state glue.
//!
//! Pure-state helpers (the tree model, forms, palette parsing) live in
//! their own modules and carry the unit tests; this module wires them to
//! the worker-thread [`IpcClient`] and the key stream.

use std::collections::HashSet;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use serde_json::{json, Value};
use softfig_ipc::growlightd::{BatonReply, FleetStatusReply};
use softfig_ipc::{
    DeployAction, DeployApplyReply, DeployPlanEntry, DeployPlanReply, DiscoverListReply, DiscoveredDevice,
    GrowlightQueueReply, HostedChain, LogReply, PairBeginReply, PairConfirmReply, PairListReply,
    PairPeer, PairRemoveReply, PendingPairing, ReadFileReply, ReplicaGrantReply, ReplicaRevokeReply,
    ReplicaStatusReply, ShowReply, StatusReply, VaultListSealedReply, VaultRevealReply,
};

use crate::clip;
use crate::command::{parse_command, Command};
use crate::forms::{ActionForm, ActionKind};
use crate::growlight_source::{GrowlightArtifact, GrowlightRead, GrowlightSource};
use crate::ipc::{IpcClient, Reply, Tag};
use crate::listpane::ListPane;
use crate::tree::{
    derive_slice_status, parse_slice_index, BacklogItem, BacklogKind, BacklogTree, LoopContextNode,
    SliceChild, TreeModel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Browse,
    History,
    Vault,
    Peers,
    Backup,
    Deploy,
    /// Read-only growlight section (the autonomous work-loop at a glance). Only
    /// reachable when growlight is enabled on this garden (`growlight_enabled ==
    /// Some(true)`); the tab is absent otherwise.
    Growlight,
}

/// Live growlightd fleet process-state for the Growlight header (slice 003).
///
/// This is the ONE permanent growlightd read: which agents are running, the
/// admission gate, the policy budgets — none of it is a file, so it never
/// migrates to the future runtime-FUSE mount and stays a dedicated `status`
/// poll on its own path (milestone `## Forward-compat`). It **soft-fails**: an
/// unreachable socket (growlightd down / fleet disarmed) or a version-skew
/// malformed reply degrades to [`FleetHeader::Unreachable`] — one dim header
/// line — while the garden-only tree and node bodies keep working. The page is
/// never gated on growlightd.
#[derive(Debug, Clone, Default)]
pub enum FleetHeader {
    /// Not polled yet (before the first `status` reply after entering the tab).
    #[default]
    Unknown,
    /// A decoded live growlightd `status` reply.
    Live(FleetStatusReply),
    /// The last poll couldn't reach growlightd — render one dim line, keep the
    /// garden-only page fully functional.
    Unreachable,
}

/// One row of the growlight backlog queue. Served as a structured row over the
/// wire by the daemon's authoritative queue-table parser (020 slice 002,
/// finding #5) — the TUI no longer re-parses the managed
/// `<!-- softfig:queue -->` table itself, so a piped `|` in a title round-trips
/// and the active item is always found. Read-only.
pub type GrowlightRow = softfig_ipc::GrowlightQueueRow;

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
    pub vault: ListPane<String>,
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
    pub peer_list: ListPane<PeerRow>,
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
    pub backup: ListPane<BackupRow>,
    /// M4 Deploy tab (`deploy_plan`): the current plan's per-dot entries.
    pub deploy: ListPane<DeployPlanEntry>,
    /// Set when a write lands while the Deploy tab is hidden. `deploy_plan` is a
    /// full daemon-side dot diff (re-read `deploy.toml`, `symlink_metadata`+read
    /// per dot, stat+read every target/cache) — expensive eMMC I/O nobody is
    /// looking at if refired for a hidden tab. Instead of eagerly re-fetching in
    /// `refresh_view`, the tab is marked stale and lazily re-fetches on entry
    /// (020 slice 006 — mirrors how History is view-gated).
    pub deploy_stale: bool,
    /// growlight enablement (load-bearing gate): `None` until the first status
    /// reply, then the daemon-owned `growlight_enabled` bit (its fail-closed
    /// `fleet_enabled()`), forced `Some(false)` while locked. The Growlight tab is
    /// rendered/reachable **only** when `Some(true)` — no tab, no empty pane, no
    /// error when growlight isn't set up/armed on this garden. Refreshed every
    /// status tick, so it can't go stale mid-session.
    pub growlight_enabled: Option<bool>,
    /// The backlog queue rows (drain order + statuses), served read-only as
    /// structured rows by the daemon's `growlight_queue` verb. Still the source
    /// for the right-pane detail (active item + latest baton); the left pane is
    /// now the navigable `growlight_tree` built from these rows.
    pub growlight: ListPane<GrowlightRow>,
    /// Left-pane backlog tree: milestone/task items (from `growlight`) expanding
    /// to their slices, plus the loop-context section. Rebuilt whenever the queue
    /// or the milestone set arrives.
    pub growlight_tree: BacklogTree,
    /// Ids that are milestones (expandable) — the authoritative dir listing of
    /// `growlight/backlog/milestones`, not an id-format heuristic. Empty until
    /// the `GrowlightMilestones` reply lands; rows classify as tasks until then.
    pub growlight_milestone_ids: Vec<String>,
    /// The logical-artifact → read resolver for the right-pane viewer (the seam
    /// the future runtime-FUSE-mount re-points). Carries the task dir listing so
    /// a task's bare `NNN` id resolves to its `NNN-slug.md` file.
    pub growlight_source: GrowlightSource,
    /// Markdown body of the selected tree node, shown scrollably in the right
    /// pane (reuses the shared `preview_scroll`/`preview_viewport`/`preview_total`
    /// so the same scroll keys drive it). `growlight_preview_path` is the node
    /// currently loaded/fetching — a stale in-flight reply (the user moved on) is
    /// dropped, and a re-select of the same node skips the re-read.
    pub growlight_preview: String,
    pub growlight_preview_title: String,
    pub growlight_preview_path: Option<String>,
    /// The latest baton-log entry (title + body) — the loop's most recent handoff
    /// state, read from the highest-numbered `growlight/baton-log/NNN-*.md`.
    pub growlight_baton_title: Option<String>,
    pub growlight_baton: Option<String>,
    /// Set when a write lands while the Growlight tab is hidden. `load_growlight`
    /// is four IPC round-trips (`growlight_queue` + `list_tree` of milestones,
    /// tasks, and the unboundedly-growing baton-log, then the latest-entry
    /// `read_file`) — too much to refire for a tab nobody is viewing. Marked
    /// stale here, lazily re-fetched on entry (020 slice 006, like `deploy_stale`).
    pub growlight_stale: bool,
    /// Live growlightd process-state for the fleet header, from the second
    /// (growlightd-only) IPC channel's `status` poll — repolled on a ~1.5s
    /// cadence WHILE the Growlight tab is active (see `App::should_poll_fleet` /
    /// `poll_fleet_status`), and soft-failing to `Unreachable` when growlightd is
    /// down/disarmed. Distinct from the garden reads: process-state is not a file
    /// and stays a dedicated growlightd read forever (`## Forward-compat`).
    pub fleet: FleetHeader,
    /// The LIVE runtime baton (slice 004), polled on the growlightd channel via the
    /// `baton` verb on the same cadence as `fleet` while the Growlight tab is
    /// active. `Some` when growlightd answered (even an empty baton — `text` empty);
    /// `None` when unreachable/disarmed/malformed (the soft-fail), which is when the
    /// header falls back to the garden baton-LOG headline. Feeds both the header
    /// baton-headline and the live-baton tree node. Out-of-garden today, so it is
    /// the one node NOT read through keeperd — retires on the runtime FUSE mount.
    pub growlight_runtime_baton: Option<BatonReply>,
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
            vault: ListPane::new(),
            reveal: None,
            regions: Vec::new(),
            regions_path: None,
            peers: Vec::new(),
            pending: Vec::new(),
            discovered: Vec::new(),
            peer_list: ListPane::new(),
            replica_host: false,
            replica_push_to: Vec::new(),
            hosted: Vec::new(),
            backup: ListPane::new(),
            deploy: ListPane::new(),
            deploy_stale: false,
            growlight_enabled: None,
            growlight: ListPane::new(),
            growlight_tree: BacklogTree::new(),
            growlight_milestone_ids: Vec::new(),
            growlight_source: GrowlightSource::new(),
            growlight_preview: String::new(),
            growlight_preview_title: String::new(),
            growlight_preview_path: None,
            growlight_baton_title: None,
            growlight_baton: None,
            growlight_stale: false,
            fleet: FleetHeader::Unknown,
            growlight_runtime_baton: None,
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

    /// growlight: (re)load the read-only section — the backlog queue table, the
    /// milestone set (for tree classification), the tasks listing (for the
    /// resolver's `NNN` → file map), plus a listing of the baton-log (whose reply
    /// triggers the latest-entry read).
    fn load_growlight(&self, ipc: &mut IpcClient) {
        ipc.send("growlight_queue", json!({}), Tag::GrowlightQueue);
        ipc.send(
            "list_tree",
            json!({ "path": "growlight/backlog/milestones" }),
            Tag::GrowlightMilestones,
        );
        ipc.send(
            "list_tree",
            json!({ "path": "growlight/backlog/tasks" }),
            Tag::GrowlightTasks,
        );
        ipc.send(
            "list_tree",
            json!({ "path": "growlight/baton-log" }),
            Tag::GrowlightBatonList,
        );
    }

    /// Whether the live fleet header should be polled this tick: only while the
    /// Growlight tab is the active, enabled view. Mirrors the view-gated load
    /// discipline (`refresh_view`) — the run loop must never hammer growlightd
    /// from another tab. Kept as a predicate so the gating is unit-testable
    /// without a live socket.
    pub fn should_poll_fleet(&self) -> bool {
        self.view == View::Growlight && self.growlight_enabled == Some(true)
    }

    /// Issue one one-shot growlightd `status` poll on the dedicated growlightd
    /// channel (NOT the keeperd `ipc`), tagged [`Tag::FleetStatus`]. The reply
    /// feeds `apply_reply`, whose `FleetStatus` arm decodes it into the live
    /// header or soft-fails an unreachable socket to the dim line.
    pub fn poll_fleet_status(&self, growlightd: &mut IpcClient) {
        growlightd.send("status", json!({}), Tag::FleetStatus);
    }

    /// Poll the LIVE runtime baton on the growlightd channel via the `baton` verb
    /// (slice 004), same gating + cadence as [`Self::poll_fleet_status`]. No
    /// `agent` → the fleet/legacy single-agent runtime baton. The reply feeds
    /// `apply_reply`'s [`Tag::GrowlightRuntimeBaton`] arm; any error soft-fails to
    /// `None` (header falls back to the garden baton-log), never a status splat.
    pub fn poll_runtime_baton(&self, growlightd: &mut IpcClient) {
        growlightd.send("baton", json!({}), Tag::GrowlightRuntimeBaton);
    }

    /// The right-pane view of the live runtime-baton node: a title and body sourced
    /// from the polled [`Self::growlight_runtime_baton`] (NOT a keeperd read). A
    /// present baton renders a compact parsed head above its post-frontmatter body;
    /// an empty or unavailable baton renders a calm placeholder — never an error.
    pub fn runtime_baton_view(&self) -> (String, String) {
        match &self.growlight_runtime_baton {
            Some(b) if !b.text.trim().is_empty() => {
                let head = runtime_baton_head(&b.text);
                let body = strip_frontmatter(&b.text);
                (
                    format!("live runtime baton — {}  (read-only)", b.path),
                    format!("{head}\n\n{body}"),
                )
            }
            Some(b) => (
                "live runtime baton  (read-only)".to_string(),
                format!("(the runtime baton is empty — {})", b.path),
            ),
            None => (
                "live runtime baton  (read-only)".to_string(),
                "(runtime baton unavailable — growlightd unreachable or the fleet is not initialized)"
                    .to_string(),
            ),
        }
    }

    /// Re-fetch every directory whose children are loaded, so the view
    /// reflects a write that just landed.
    fn refresh_view(&mut self, ipc: &mut IpcClient) {
        for dir in self.tree.loaded_dirs() {
            self.load_dir(ipc, &dir);
        }
        ipc.send("status", json!({}), Tag::Status);
        if self.view == View::History {
            self.load_history(ipc);
        }
        if self.vault.loaded {
            self.load_vault(ipc);
        }
        if self.peer_list.loaded {
            self.load_peers(ipc);
        }
        if self.backup.loaded {
            self.load_backup(ipc);
        }
        // Deploy + Growlight are the expensive loads (a full daemon-side dot
        // diff; a 4-round-trip read over the unbounded baton-log). Gate them on
        // the active view like History is: a write that lands while they're
        // hidden marks them stale to lazily re-fetch on entry, instead of
        // refiring eMMC I/O for a tab nobody is looking at (020 slice 006).
        if self.deploy.loaded {
            if self.view == View::Deploy {
                self.load_deploy(ipc);
            } else {
                self.deploy_stale = true;
            }
        }
        if self.growlight.loaded {
            if self.view == View::Growlight {
                self.load_growlight(ipc);
            } else {
                self.growlight_stale = true;
            }
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
        self.peer_list.items = rows;
        self.peer_list.clamp();
    }

    pub fn selected_peer_row(&self) -> Option<PeerRow> {
        self.peer_list.selected().copied()
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
        self.backup.items = rows;
        self.backup.clamp();
    }

    pub fn selected_backup_row(&self) -> Option<BackupRow> {
        self.backup.selected().copied()
    }

    pub fn selected_deploy_entry(&self) -> Option<&DeployPlanEntry> {
        self.deploy.selected()
    }

    /// True when some entry is a `Conflict` — apply refuses it without force.
    /// Derived from the plan entries rather than stored: the daemon sets
    /// `DeployPlanReply.has_conflicts = plan.has_conflicts()` and maps
    /// `Action::Conflict → DeployAction::Conflict` 1:1, so this is equivalent.
    pub fn deploy_has_conflicts(&self) -> bool {
        self.deploy
            .items
            .iter()
            .any(|e| e.action == DeployAction::Conflict)
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
        self.growlight.items.iter().find(|r| r.status == "active")
    }

    /// The queue row for the tree's selected node — the owning milestone/task
    /// (a slice maps to its parent milestone). Feeds the right-pane detail's
    /// selected line while the right pane is untouched (slice 001).
    pub fn selected_growlight_row(&self) -> Option<&GrowlightRow> {
        let sel = self.growlight_tree.selected_row()?;
        self.growlight.items.iter().find(|r| r.id == sel.item_id)
    }

    /// Rebuild the backlog tree from the current queue rows + the milestone set.
    /// Called whenever either the `growlight_queue` or `GrowlightMilestones`
    /// reply lands, so the tree converges once both are in (order-independent);
    /// `set_items` preserves expansion/slice state across rebuilds.
    fn rebuild_growlight_tree(&mut self) {
        let milestones: HashSet<&str> =
            self.growlight_milestone_ids.iter().map(String::as_str).collect();
        let items = self
            .growlight
            .items
            .iter()
            .map(|r| BacklogItem {
                id: r.id.clone(),
                title: r.title.clone(),
                status: r.status.clone(),
                is_milestone: milestones.contains(r.id.as_str()),
            })
            .collect();
        // The loop-context section + the live runtime-baton node are static; (re)seed
        // them on every rebuild so the tree stays self-consistent, then set the
        // backlog (which clamps last).
        self.growlight_tree.set_loop_context(loop_context_nodes());
        self.growlight_tree.set_runtime_baton(true);
        self.growlight_tree.set_items(items);
    }

    /// Resolve the selected tree node to its markdown artifact and fetch its body
    /// for the right pane. Idempotent — skips the read when the node's body is
    /// already loaded/fetching — so it is safe to call after every nav,
    /// expand/collapse, and data reply. Resets `preview_scroll` and fires a fresh
    /// `read_file` only when the selection lands on a *different* node. A task
    /// whose dir listing hasn't arrived yet resolves to nothing and retries once
    /// the `GrowlightTasks` reply seeds the resolver.
    fn refresh_growlight_selection(&mut self, ipc: &mut IpcClient) {
        let Some(row) = self.growlight_tree.selected_row() else {
            return;
        };
        let artifact = match row.kind {
            BacklogKind::Milestone => GrowlightArtifact::Milestone {
                id: row.item_id.clone(),
            },
            BacklogKind::Task => GrowlightArtifact::Task {
                id: row.item_id.clone(),
            },
            BacklogKind::Slice => match &row.path {
                Some(p) => GrowlightArtifact::Slice { path: p.clone() },
                None => return,
            },
            BacklogKind::LoopContext => match &row.path {
                Some(p) => GrowlightArtifact::LoopContext { path: p.clone() },
                None => return,
            },
            BacklogKind::RuntimeBaton => GrowlightArtifact::RuntimeBaton,
        };
        match self.growlight_source.resolve(&artifact) {
            // An in-garden node → a keeperd `read_file`, refined on reply.
            Some(GrowlightRead::Garden { path }) => {
                if self.growlight_preview_path.as_deref() == Some(path.as_str()) {
                    return; // already showing / fetching this node
                }
                // A slice node carries (milestone, num) so the reply can refine its
                // derived status to awaiting-smoke from the loaded body.
                let slice = match row.kind {
                    BacklogKind::Slice => {
                        row.slice_num.clone().map(|num| (row.item_id.clone(), num))
                    }
                    _ => None,
                };
                self.growlight_preview_path = Some(path.clone());
                self.growlight_preview_title = row.label.clone();
                self.preview_scroll = 0;
                ipc.send(
                    "read_file",
                    json!({ "path": path }),
                    Tag::GrowlightNodeFile { path, slice },
                );
            }
            // The out-of-garden runtime baton → NO keeperd read: the detail pane
            // renders it LIVE from the polled `growlight_runtime_baton` (fed by the
            // growlightd `baton` verb on the fleet cadence). Mark the preview slot
            // with a sentinel so a stale garden body doesn't linger and a re-select
            // is a no-op, and reset the shared scroll on (re)select.
            Some(GrowlightRead::Growlightd { .. }) => {
                if self.growlight_preview_path.as_deref() == Some(RUNTIME_BATON_SLOT) {
                    return;
                }
                self.growlight_preview_path = Some(RUNTIME_BATON_SLOT.to_string());
                self.growlight_preview_title = row.label.clone();
                self.growlight_preview.clear();
                self.preview_scroll = 0;
            }
            // e.g. a task whose dir listing hasn't landed — retry on the listing.
            None => {}
        }
    }

    fn hint_growlight_readonly(&mut self) {
        self.status = "growlight is a read-only browser (backlog · slices · loop context)".into();
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
                        // Daemon-owned growlight gate, refreshed every tick — the
                        // client never re-derives it (so it can't disagree). Force
                        // it off while locked: the section can't load, and the
                        // daemon fail-closes anyway when the mount is down.
                        self.growlight_enabled = Some(!self.locked && s.growlight_enabled);
                        // The gate can flip off mid-session (config edit, lock):
                        // the tab header disappears, so don't leave the view
                        // stranded on a section that is no longer reachable.
                        if self.growlight_enabled != Some(true) && self.view == View::Growlight {
                            self.view = View::Browse;
                        }
                        if !self.locked && (was_locked || !self.tree.is_loaded("")) {
                            self.load_dir(ipc, "");
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
                    // The status reply we request next carries the daemon-owned
                    // growlight_enabled bit — no separate probe needed.
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
                        // M2c: the daemon computes the file's sealed inline
                        // `<vault id=…>` region ids with its authoritative grammar
                        // (020 slice 003) — consume them directly so `x`/Enter
                        // offers the per-region reveal picker only for real regions,
                        // never a phantom from an inline-code `<vault>` mention.
                        self.regions = r.region_ids;
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
                        self.vault.set_items(r.matching_files);
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
                        self.peer_list.loaded = true;
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
                        self.backup.loaded = true;
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
                        self.deploy.set_items(r.entries);
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
                    // Close the force-confirm overlay only if it still owns the
                    // screen, matching the specific overlay the way the Err branch
                    // below does. A slow in-flight apply must not force-close a
                    // `:` palette or Unlock prompt the user opened meanwhile —
                    // that would drop the remaining keystrokes into normal mode
                    // (a stray `q` quits, an `a` re-fires apply). Then re-plan so
                    // the tab reflects the new on-disk state.
                    if matches!(self.overlay, Overlay::DeployForce { .. }) {
                        self.overlay = Overlay::None;
                    }
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
            Tag::GrowlightQueue => match reply.result {
                Ok(v) => match serde_json::from_value::<GrowlightQueueReply>(v) {
                    Ok(r) => {
                        self.growlight.set_items(r.rows);
                        self.rebuild_growlight_tree();
                        self.refresh_growlight_selection(ipc);
                    }
                    Err(e) => self.status = format!("growlight queue: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("growlight queue: {m}"),
            },
            Tag::GrowlightMilestones => match reply.result {
                Ok(v) => match serde_json::from_value::<softfig_ipc::ListTreeReply>(v) {
                    Ok(r) => {
                        self.growlight_milestone_ids = r
                            .entries
                            .iter()
                            .filter(|e| e.is_dir)
                            .map(|e| e.name.clone())
                            .collect();
                        self.rebuild_growlight_tree();
                        self.refresh_growlight_selection(ipc);
                    }
                    Err(e) => self.status = format!("growlight milestones: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("growlight milestones: {m}"),
            },
            Tag::GrowlightTasks => match reply.result {
                Ok(v) => match serde_json::from_value::<softfig_ipc::ListTreeReply>(v) {
                    Ok(r) => {
                        // Seed the resolver's bare-`NNN` → file map, then retry the
                        // selection read (a task selected before this landed had
                        // no resolvable path).
                        self.growlight_source.set_task_paths(&r.entries);
                        self.refresh_growlight_selection(ipc);
                    }
                    Err(e) => self.status = format!("growlight tasks: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("growlight tasks: {m}"),
            },
            Tag::GrowlightSliceIndex { milestone } => match reply.result {
                Ok(v) => match serde_json::from_value::<ReadFileReply>(v) {
                    Ok(r) => {
                        let dir = format!("growlight/backlog/milestones/{milestone}");
                        let children = parse_slice_index(&r.content)
                            .into_iter()
                            .map(|s| {
                                // `is_active` (the live baton's active slice) is
                                // wired by the growlightd `baton` verb in slice
                                // 004; `body` (for awaiting-smoke) is fed by the
                                // right-pane read on select (`refine_slice_status`).
                                // Until then a reviewed slice reads as done, an
                                // unreviewed one queued; `reviewed` is kept for the
                                // later re-derivation.
                                let status =
                                    derive_slice_status(false, s.reviewed.as_deref(), None);
                                SliceChild {
                                    path: format!("{dir}/{}", s.path),
                                    num: s.num,
                                    title: s.title,
                                    reviewed: s.reviewed,
                                    status,
                                }
                            })
                            .collect();
                        self.growlight_tree.set_slices(&milestone, children);
                        // Slices just appeared under the selection — read the one
                        // now selected (if selection shifted onto a slice).
                        self.refresh_growlight_selection(ipc);
                    }
                    Err(e) => {
                        self.status = format!("growlight milestone {milestone}: malformed reply: {e}")
                    }
                },
                Err((_, m)) => self.status = format!("growlight milestone {milestone}: {m}"),
            },
            Tag::GrowlightNodeFile { path, slice } => match reply.result {
                Ok(v) => match serde_json::from_value::<ReadFileReply>(v) {
                    Ok(r) => {
                        // Drop a stale reply: the user navigated to another node
                        // while this read was in flight.
                        if self.growlight_preview_path.as_deref() == Some(path.as_str()) {
                            if let Some((milestone, num)) = &slice {
                                self.growlight_tree
                                    .refine_slice_status(milestone, num, false, &r.content);
                            }
                            self.growlight_preview = r.content;
                        }
                    }
                    Err(e) => self.status = format!("growlight node {path}: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("growlight node {path}: {m}"),
            },
            Tag::GrowlightBatonList => match reply.result {
                Ok(v) => match serde_json::from_value::<softfig_ipc::ListTreeReply>(v) {
                    Ok(r) => {
                        if let Some(path) = latest_baton_path(&r.entries) {
                            ipc.send(
                                "read_file",
                                json!({ "path": path }),
                                Tag::GrowlightBaton { path },
                            );
                        }
                    }
                    Err(e) => self.status = format!("growlight baton-log: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("growlight baton-log: {m}"),
            },
            Tag::GrowlightBaton { path } => match reply.result {
                Ok(v) => match serde_json::from_value::<ReadFileReply>(v) {
                    Ok(r) => {
                        self.growlight_baton_title =
                            Some(path.rsplit('/').next().unwrap_or(&path).to_string());
                        self.growlight_baton = Some(r.content);
                    }
                    Err(e) => self.status = format!("growlight baton: malformed reply: {e}"),
                },
                Err((_, m)) => self.status = format!("growlight baton: {m}"),
            },
            Tag::FleetStatus => match reply.result {
                // Live process-state → the header. A version-skewed / malformed
                // reply degrades to the dim line rather than a splat.
                Ok(v) => {
                    self.fleet = match serde_json::from_value::<FleetStatusReply>(v) {
                        Ok(reply) => FleetHeader::Live(reply),
                        Err(_) => FleetHeader::Unreachable,
                    };
                }
                // Soft-fail (load-bearing): growlightd down / disarmed → the
                // connect errors on the worker. One dim header line — deliberately
                // NEVER `self.status` (no status splat) and never touching the
                // garden-sourced tree/preview, so the page keeps working.
                Err(_) => self.fleet = FleetHeader::Unreachable,
            },
            Tag::GrowlightRuntimeBaton => match reply.result {
                // Live runtime baton → the header baton-headline + the live-baton
                // node. Decode into `Some` (even an empty baton is a valid answer);
                // a malformed reply is treated like unreachable (`None`).
                Ok(v) => self.growlight_runtime_baton = serde_json::from_value::<BatonReply>(v).ok(),
                // Soft-fail (load-bearing), same discipline as `FleetStatus`:
                // growlightd down/disarmed → `None`, so the header falls back to the
                // garden baton-LOG headline. Never `self.status` (no splat), never
                // touches the garden-sourced tree/preview.
                Err(_) => self.growlight_runtime_baton = None,
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
                if !self.vault.loaded && !self.locked {
                    self.load_vault(ipc);
                }
            }
            KeyCode::Char('4') => {
                self.view = View::Peers;
                if !self.peer_list.loaded && !self.locked {
                    self.load_peers(ipc);
                }
            }
            KeyCode::Char('5') => {
                self.view = View::Backup;
                if !self.backup.loaded && !self.locked {
                    self.load_backup(ipc);
                }
            }
            KeyCode::Char('6') => {
                self.view = View::Deploy;
                // Re-fetch on first entry, or when a write marked the tab stale
                // while it was hidden (020 slice 006); consume the mark so we
                // don't re-fetch again until the next hidden write.
                if (!self.deploy.loaded || self.deploy_stale) && !self.locked {
                    self.deploy_stale = false;
                    self.load_deploy(ipc);
                }
            }
            // Only reachable when growlight is enabled — the tab is absent
            // otherwise, so `7` is inert on a garden without growlight.
            KeyCode::Char('7') if self.growlight_enabled == Some(true) => {
                self.view = View::Growlight;
                // The right-pane body reuses the shared `preview_scroll` (also
                // driven by Browse/History), so reset it on entry — the node
                // viewer always opens at the top, never at another view's offset.
                self.preview_scroll = 0;
                if (!self.growlight.loaded || self.growlight_stale) && !self.locked {
                    self.growlight_stale = false;
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
            KeyCode::Char('x') => self.start_reveal(ipc),
            KeyCode::Char('c') => self.copy_reveal(),
            KeyCode::Up | KeyCode::Char('k') => self.nav_up(ipc),
            KeyCode::Down | KeyCode::Char('j') => self.nav_down(ipc),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.activate(ipc),
            KeyCode::Left | KeyCode::Char('h') => self.collapse_selected(ipc),
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

    fn nav_up(&mut self, ipc: &mut IpcClient) {
        match self.view {
            View::Browse => self.tree.move_up(),
            View::History => {
                self.history_selected = self.history_selected.saturating_sub(1);
            }
            View::Vault => self.vault.up(),
            View::Peers => self.peer_list.up(),
            View::Backup => self.backup.up(),
            View::Deploy => self.deploy.up(),
            View::Growlight => {
                self.growlight_tree.move_up();
                self.refresh_growlight_selection(ipc);
            }
        }
    }

    fn nav_down(&mut self, ipc: &mut IpcClient) {
        match self.view {
            View::Browse => self.tree.move_down(),
            View::History => {
                if self.history_selected + 1 < self.history.len() {
                    self.history_selected += 1;
                }
            }
            View::Vault => self.vault.down(),
            View::Peers => self.peer_list.down(),
            View::Backup => self.backup.down(),
            View::Deploy => self.deploy.down(),
            View::Growlight => {
                self.growlight_tree.move_down();
                self.refresh_growlight_selection(ipc);
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
            // Growlight is read-only: Enter/l toggles a milestone's slices
            // (lazy-reading its CLAUDE.md on first expand); leaves just hint.
            View::Growlight => self.activate_growlight(ipc),
        }
    }

    /// Toggle the selected milestone's slice children (lazy-load its slice index
    /// on first expand); a task/slice/loop-context leaf is a read-only glance
    /// (its body already shows in the right pane on select).
    fn activate_growlight(&mut self, ipc: &mut IpcClient) {
        let Some(row) = self.growlight_tree.selected_row() else {
            return self.hint_growlight_readonly();
        };
        if !row.expandable {
            return self.hint_growlight_readonly();
        }
        if self.growlight_tree.is_expanded(&row.item_id) {
            self.growlight_tree.collapse(&row.item_id);
        } else {
            self.growlight_tree.expand(&row.item_id);
            if !self.growlight_tree.is_loaded(&row.item_id) {
                // Resolve the milestone doc's path through the same seam as the
                // body reads (its slice index lives in that CLAUDE.md).
                if let Some(GrowlightRead::Garden { path }) = self
                    .growlight_source
                    .resolve(&GrowlightArtifact::Milestone {
                        id: row.item_id.clone(),
                    })
                {
                    ipc.send(
                        "read_file",
                        json!({ "path": path }),
                        Tag::GrowlightSliceIndex {
                            milestone: row.item_id.clone(),
                        },
                    );
                }
            }
        }
        self.growlight_tree.clamp_selection();
        self.refresh_growlight_selection(ipc);
    }

    fn hint_backup_actions(&mut self) {
        self.status = match self.selected_backup_row() {
            Some(BackupRow::PushTo(_)) => "g grant a host · D revoke selected".into(),
            Some(BackupRow::Hosted(_)) => "this is a chain I host (read-only mirror)".into(),
            None => "g grant a paired device to back up this chain".into(),
        };
    }

    fn collapse_selected(&mut self, ipc: &mut IpcClient) {
        match self.view {
            View::Browse => {
                if let Some(row) = self.tree.selected_row() {
                    if row.is_dir && self.tree.is_expanded(&row.path) {
                        self.tree.collapse(&row.path);
                        self.tree.clamp_selection();
                    }
                }
            }
            View::Growlight => {
                if let Some(row) = self.growlight_tree.selected_row() {
                    if row.expandable && self.growlight_tree.is_expanded(&row.item_id) {
                        self.growlight_tree.collapse(&row.item_id);
                        self.growlight_tree.clamp_selection();
                    }
                }
                self.refresh_growlight_selection(ipc);
            }
            _ => {}
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
                // `:apply` is the deliberate "apply now" verb (mirrors the `a`
                // key), distinct from `:deploy` which only previews. Applying
                // straight from the palette without a preview step is
                // intentional and safe: this is a *non-force* apply, so the
                // daemon re-plans from the freshest on-disk state and refuses
                // every conflict (backing up nothing, overwriting no unmanaged
                // target), and the DeployApply Ok handler re-runs `load_deploy`
                // so the resulting plan is shown immediately after.
                self.view = View::Deploy;
                self.apply_deploy(ipc, false);
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
            View::Vault => self.vault.selected().cloned(),
            View::Browse => self
                .tree
                .selected_row()
                .filter(|r| !r.is_dir)
                .map(|r| r.path.clone()),
            View::History | View::Peers | View::Backup | View::Deploy | View::Growlight => None,
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

/// The loop-context docs surfaced as browsable tree nodes (plain garden reads):
/// the injected protocol templates, the session policy, and the pillar map. The
/// injected protocol is exactly these files read verbatim by the SessionStart
/// hook, so they resolve to ordinary keeperd reads. (The assembled
/// injected-context view — protocol + the member's live baton — waits on slice
/// 004's growlightd `baton` verb.)
/// Sentinel value for `growlight_preview_path` while the live runtime-baton node
/// is selected — a growlightd read, not a garden path, so it never collides with a
/// real repo-relative path and keeps re-selects idempotent.
const RUNTIME_BATON_SLOT: &str = "growlightd:runtime-baton";

fn loop_context_nodes() -> Vec<LoopContextNode> {
    [
        ("protocol.md", "growlight/protocol.md"),
        ("protocol-fleet.md", "growlight/protocol-fleet.md"),
        ("session-policy.md", "growlight/session-policy.md"),
        ("CLAUDE.md (pillar)", "growlight/CLAUDE.md"),
    ]
    .into_iter()
    .map(|(label, path)| LoopContextNode {
        label: label.into(),
        path: path.into(),
    })
    .collect()
}

/// The first meaningful line of a baton (its headline) for the fleet-header
/// strip: the first non-empty line after an optional leading `--- … ---` YAML
/// frontmatter block. `None` for an empty/blank baton.
pub fn baton_headline(body: &str) -> Option<&str> {
    let mut lines = body.lines().peekable();
    if lines.peek().map(|l| l.trim_end()) == Some("---") {
        lines.next();
        for l in lines.by_ref() {
            if l.trim_end() == "---" {
                break;
            }
        }
    }
    lines.map(str::trim).find(|l| !l.is_empty())
}

/// The body of a baton with any leading `--- … ---` YAML frontmatter block
/// stripped — the useful part (`# NEXT ACTION`, …) shown under the compact head in
/// the live-baton viewer. Returns the whole text when there is no (or an
/// unterminated) frontmatter block; an empty string for a frontmatter-only baton.
pub fn strip_frontmatter(text: &str) -> &str {
    let Some(after_open) = text.strip_prefix("---\n") else {
        return text; // no leading frontmatter fence
    };
    match after_open.split_once("\n---\n") {
        // Drop the blank line that conventionally follows the closing fence, so
        // the body starts at its first real line (matches `baton_headline`).
        Some((_frontmatter, body)) => body.trim_start_matches('\n'),
        // No `---` fence followed by a body: either frontmatter-only (fence at EOF)
        // or an unterminated block.
        None => match after_open.strip_suffix("\n---") {
            Some(_) => "",   // frontmatter only, no body
            None => text,    // unterminated fence — show the raw text
        },
    }
}

/// Parse the flat `key: value` pairs from a baton's leading `--- … ---` YAML
/// frontmatter block (the baton frontmatter is flat scalars — no nested YAML).
/// Empty when there is no frontmatter. Pure.
fn frontmatter_fields(text: &str) -> Vec<(String, String)> {
    let Some(after_open) = text.strip_prefix("---\n") else {
        return Vec::new();
    };
    // The block is everything up to the next `---` fence line (or EOF fence).
    let block = match after_open.split_once("\n---") {
        Some((fm, _)) => fm,
        None => return Vec::new(), // unterminated — treat as no frontmatter
    };
    block
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            let k = k.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// A compact one-line head for the live runtime baton, parsed from its YAML
/// frontmatter (`item` / `slice` / `iteration` / `status` + the ctx & 5h budget
/// %s) — what the loop is on right now, shown above the baton body and in the
/// fleet header. Missing fields are omitted; a baton with no frontmatter (or none
/// of these keys) yields an empty string, and the caller falls back to a headline.
pub fn runtime_baton_head(text: &str) -> String {
    let fm = frontmatter_fields(text);
    let get = |k: &str| {
        fm.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    };
    let mut parts: Vec<String> = Vec::new();
    if let Some(item) = get("item") {
        parts.push(format!("item {item}"));
    }
    if let Some(slice) = get("slice") {
        parts.push(format!("slice {slice}"));
    }
    if let Some(iter) = get("iteration") {
        parts.push(format!("iter {iter}"));
    }
    if let Some(status) = get("status") {
        parts.push(status.to_string());
    }
    if let Some(ctx) = get("ctx_pct") {
        parts.push(format!("ctx {ctx}%"));
    }
    if let Some(h5) = get("session_5h_pct") {
        parts.push(format!("5h {h5}%"));
    }
    parts.join(" · ")
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
        assert!(app.vault.loaded);
        assert_eq!(app.vault_globs, vec!["secrets/**".to_string()]);
        assert_eq!(app.vault.items.len(), 2);
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
    // Region-id parsing now lives in the daemon (authoritative grammar); the
    // client just consumes `ReadFileReply.region_ids`. The daemon-side
    // computation is covered by keeperd's `m3b_reads` integration test.

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

        // Opening the file takes its inline region ids straight off the
        // daemon-computed `region_ids` in the read_file reply.
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
                    "region_ids": ["db-pw", "api"],
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
        assert!(app.peer_list.loaded);
        assert_eq!(app.peers.len(), 1);
        assert_eq!(app.pending.len(), 1);
        // Peers first, then pending.
        assert_eq!(
            app.peer_list.items,
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
        app.peer_list.selected = 0;
        app.activate(&mut ipc);
        assert!(matches!(app.overlay, Overlay::None));

        // Row 1 is the pending pairing → activating opens the SAS confirm.
        app.peer_list.selected = 1;
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

        app.peer_list.selected = 0; // a ring member
        app.start_unpair();
        match &app.overlay {
            Overlay::Unpair { name, fingerprint, .. } => {
                assert_eq!(name, "tablet");
                assert_eq!(fingerprint, &"11".repeat(32));
            }
            other => panic!("expected Unpair, got {other:?}"),
        }

        app.overlay = Overlay::None;
        app.peer_list.selected = 1; // the pending row → cannot unpair
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
            app.peer_list.items,
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
        app.peer_list.selected = 0; // the lone discovered row
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
        app.peer_list.selected = 0; // a ring member, not discovered
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

        app.vault.items = vec!["secrets/api-keys.toml".into()];
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
        assert!(app.backup.loaded);
        assert!(app.replica_host);
        assert_eq!(app.replica_push_to.len(), 1);
        assert_eq!(app.hosted.len(), 1);
        // Hosts-that-back-me first, then chains-I-host.
        assert_eq!(
            app.backup.items,
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
        app.backup.selected = 0;
        app.start_revoke();
        match &app.overlay {
            Overlay::ReplicaRevoke { fingerprint, .. } => {
                assert_eq!(fingerprint, &"11".repeat(32));
            }
            other => panic!("expected ReplicaRevoke, got {other:?}"),
        }

        // Row 1 is a chain I host → cannot be revoked (it's a mirror, not a grant).
        app.overlay = Overlay::None;
        app.backup.selected = 1;
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
        app.backup.selected = 0;
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
        assert!(app.deploy.loaded);
        assert_eq!(app.deploy.items.len(), 2);
        assert!(app.deploy_has_conflicts());

        // Select the last row, then a smaller plan arrives → selection clamps.
        app.deploy.selected = 1;
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
        assert_eq!(app.deploy.items.len(), 1);
        assert_eq!(app.deploy.selected, 0);
        assert!(!app.deploy_has_conflicts());
    }

    // ---- 020 slice 006: refresh_view gates the expensive tab loads on view ----

    /// A write while viewing a non-Deploy/non-Growlight tab must NOT refire the
    /// expensive Deploy/Growlight loads (a full daemon-side dot diff; a
    /// 3-round-trip read over the unbounded baton-log). Instead it marks them
    /// stale so they lazily re-fetch when the user next opens them.
    #[test]
    fn refresh_view_marks_hidden_expensive_tabs_stale_then_entry_refetches() {
        let mut app = App::new();
        app.locked = false;
        app.growlight_enabled = Some(true);
        // Both expensive tabs were visited once (load-once flags set); the user
        // is now looking at Browse.
        app.deploy.loaded = true;
        app.growlight.loaded = true;
        app.view = View::Browse;
        let mut ipc = dummy_ipc();

        // A write lands — any tab's action reply funnels through refresh_view.
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::Action {
                    title: "log_decision".into(),
                },
                result: Ok(json!({ "path": "journal/x.md" })),
            },
            &mut ipc,
        );
        // Hidden → marked stale, not eagerly re-fetched.
        assert!(app.deploy_stale, "hidden Deploy tab marked stale");
        assert!(app.growlight_stale, "hidden Growlight tab marked stale");

        // Entering Deploy consumes the mark (a re-fetch is issued).
        app.handle_key(
            KeyEvent::new(KeyCode::Char('6'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_eq!(app.view, View::Deploy);
        assert!(!app.deploy_stale, "entering Deploy re-fetches + clears stale");
        // Growlight is still hidden → still stale.
        assert!(app.growlight_stale);

        // Entering Growlight consumes its mark too.
        app.handle_key(
            KeyEvent::new(KeyCode::Char('7'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_eq!(app.view, View::Growlight);
        assert!(
            !app.growlight_stale,
            "entering Growlight re-fetches + clears stale"
        );
    }

    /// A write while the expensive tab IS active re-fetches it in place and
    /// never marks it stale — staleness is only for hidden tabs.
    #[test]
    fn refresh_view_refetches_active_expensive_tab_without_marking_stale() {
        let mut app = App::new();
        app.locked = false;
        app.deploy.loaded = true;
        app.view = View::Deploy;
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::Action {
                    title: "deploy".into(),
                },
                result: Ok(json!({ "path": "x" })),
            },
            &mut ipc,
        );
        assert!(!app.deploy_stale, "active Deploy tab re-fetches, stays fresh");
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
    fn deploy_apply_reply_leaves_unrelated_overlay_open() {
        // Finding #7: a slow apply's Ok reply must not force-close a `:` palette
        // or Unlock prompt the user opened while it was in flight — only the
        // deploy-force overlay it owns. Otherwise the remaining keystrokes land
        // in normal mode (a stray `q` quits, an `a` re-fires apply).
        let ok_reply = || Reply {
            id: 1,
            tag: Tag::DeployApply,
            result: Ok(serde_json::to_value(DeployApplyReply {
                created: vec!["bashrc".into()],
                replaced: vec![],
                copied: vec![],
                skipped: vec![],
                conflicts: vec![],
                forced: vec![],
                warnings: vec![],
            })
            .unwrap()),
        };

        // Palette open meanwhile → stays open.
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::Palette("apply".into());
        let mut ipc = dummy_ipc();
        app.apply_reply(ok_reply(), &mut ipc);
        assert!(
            matches!(app.overlay, Overlay::Palette(_)),
            "palette was closed by an in-flight apply reply: {:?}",
            app.overlay
        );

        // Unlock passphrase prompt open meanwhile → stays open.
        let mut app = App::new();
        app.locked = false;
        app.overlay = Overlay::Unlock {
            buf: "hunter2".into(),
            error: None,
        };
        let mut ipc = dummy_ipc();
        app.apply_reply(ok_reply(), &mut ipc);
        assert!(
            matches!(app.overlay, Overlay::Unlock { .. }),
            "unlock prompt was closed by an in-flight apply reply: {:?}",
            app.overlay
        );
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

    // The daemon now owns the queue-table grammar (`\|` un-escape, default-queue
    // scoping); that parse is tested in `softfig-keeperd`'s `default_queue_rows`.
    // The TUI just consumes the structured rows over the wire — see
    // `queue_reply_populates_and_finds_active_item`.

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

    /// Build a `Tag::Status` reply carrying the daemon-owned growlight gate.
    fn status_reply(state: &str, growlight_enabled: bool) -> Reply {
        Reply {
            id: 1,
            tag: Tag::Status,
            result: Ok(serde_json::to_value(StatusReply {
                state: state.into(),
                tip: None,
                garden_root: "/g".into(),
                protocol_version: softfig_ipc::PROTOCOL_VERSION,
                relock_pending: false,
                relock_expires_at: None,
                growlight_enabled,
            })
            .unwrap()),
        }
    }

    #[test]
    fn status_reply_carries_growlight_gate() {
        let mut ipc = dummy_ipc();

        // Unlocked + daemon says enabled ⇒ the tab is gated on.
        let mut app = App::new();
        assert_eq!(app.growlight_enabled, None); // no status yet
        app.apply_reply(status_reply("unlocked", true), &mut ipc);
        assert_eq!(app.growlight_enabled, Some(true));

        // Unlocked + daemon says disabled (fresh garden: toml present, fleet off)
        // ⇒ gated off, silently (no tab, no load attempt, no error splat).
        let mut app2 = App::new();
        app2.apply_reply(status_reply("unlocked", false), &mut ipc);
        assert_eq!(app2.growlight_enabled, Some(false));
        assert!(!app2.growlight.loaded);
    }

    #[test]
    fn growlight_view_snaps_to_browse_when_the_gate_flips_off() {
        let mut ipc = dummy_ipc();
        let mut app = App::new();
        app.apply_reply(status_reply("unlocked", true), &mut ipc);
        app.view = View::Growlight;

        // The gate flips off mid-session: the tab header disappears, so the
        // active view must not stay stranded on the unreachable section.
        app.apply_reply(status_reply("unlocked", false), &mut ipc);
        assert_eq!(app.growlight_enabled, Some(false));
        assert_eq!(app.view, View::Browse);

        // Same snap when the flip comes from locking rather than the config.
        let mut app2 = App::new();
        app2.apply_reply(status_reply("unlocked", true), &mut ipc);
        app2.view = View::Growlight;
        app2.apply_reply(status_reply("locked", true), &mut ipc);
        assert_eq!(app2.view, View::Browse);

        // A gate-on tick never disturbs the current view.
        let mut app3 = App::new();
        app3.apply_reply(status_reply("unlocked", true), &mut ipc);
        app3.view = View::Growlight;
        app3.apply_reply(status_reply("unlocked", true), &mut ipc);
        assert_eq!(app3.view, View::Growlight);
    }

    #[test]
    fn status_reply_forces_growlight_off_when_locked() {
        let mut ipc = dummy_ipc();
        let mut app = App::new();
        // Even if the daemon reports enabled, a locked session shows no tab —
        // the section can't load while locked.
        app.apply_reply(status_reply("locked", true), &mut ipc);
        assert_eq!(app.growlight_enabled, Some(false));
        // Unlock refreshes it back on from the same daemon bit.
        app.apply_reply(status_reply("unlocked", true), &mut ipc);
        assert_eq!(app.growlight_enabled, Some(true));
    }

    #[test]
    fn growlight_tab_key_inert_until_enabled() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        // Not yet enabled: `7` must NOT switch views (tab absent).
        app.handle_key(
            KeyEvent::new(KeyCode::Char('7'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_ne!(app.view, View::Growlight);

        // Enabled: `7` switches to the growlight view.
        app.growlight_enabled = Some(true);
        app.handle_key(
            KeyEvent::new(KeyCode::Char('7'), KeyModifiers::NONE),
            &mut ipc,
        );
        assert_eq!(app.view, View::Growlight);
    }

    #[test]
    fn queue_reply_populates_and_finds_active_item() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        // Structured rows straight off the wire (`growlight_queue` reply). A
        // title carrying a literal `|` arrives intact — the daemon un-escaped
        // the `\|` cell escape, so the TUI never mis-splits it (finding #5).
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightQueue,
                result: Ok(json!({
                    "rows": [
                        { "id": "growlightd-crash-diagnostics", "title": "crash diag", "status": "done" },
                        { "id": "tui-modernize", "title": "Modernize | the TUI", "status": "active" },
                        { "id": "020", "title": "code-review records", "status": "queued" },
                    ],
                })),
            },
            &mut ipc,
        );
        assert!(app.growlight.loaded);
        assert_eq!(app.growlight.items.len(), 3);
        let active = app.growlight_active_item().expect("active item found");
        assert_eq!(active.id, "tui-modernize");
        // The piped title round-trips through the wire, not garbled.
        assert_eq!(active.title, "Modernize | the TUI");
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

    #[test]
    fn growlight_tree_classifies_expands_and_maps_selection() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();

        // The authoritative milestone set is the dir listing — a milestone
        // subdir + a stray non-dir entry the classifier must ignore.
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightMilestones,
                result: Ok(json!({
                    "entries": [
                        tree_entry("my-milestone", "growlight/backlog/milestones/my-milestone", true),
                        tree_entry("CLAUDE.md", "growlight/backlog/milestones/CLAUDE.md", false),
                    ],
                })),
            },
            &mut ipc,
        );
        // The queue: one milestone (in the set) + one task (not).
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::GrowlightQueue,
                result: Ok(json!({
                    "rows": [
                        { "id": "my-milestone", "title": "A milestone", "status": "deferred" },
                        { "id": "042", "title": "A task", "status": "queued" },
                    ],
                })),
            },
            &mut ipc,
        );

        let vis = app.growlight_tree.visible();
        // 2 backlog rows + the 4 static loop-context nodes + the live-baton node,
        // all seeded on rebuild.
        assert_eq!(vis.len(), 7);
        assert!(vis[0].expandable, "milestone row expands");
        assert!(!vis[1].expandable, "task row is a leaf");
        assert_eq!(vis[2].kind, BacklogKind::LoopContext, "loop-context follows the backlog");
        assert_eq!(
            vis[6].kind,
            BacklogKind::RuntimeBaton,
            "the live runtime-baton node closes the tree",
        );

        // Expand the milestone (Enter) — fires the lazy read_file (to the dead
        // dummy worker; no reply), marks it expanded.
        app.view = View::Growlight;
        app.growlight_tree.selected = 0;
        app.handle_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut ipc,
        );
        assert!(app.growlight_tree.is_expanded("my-milestone"));

        // Feed the milestone CLAUDE.md: one reviewed slice (→ done) + one blank
        // (→ queued).
        app.apply_reply(
            Reply {
                id: 3,
                tag: Tag::GrowlightSliceIndex {
                    milestone: "my-milestone".into(),
                },
                result: Ok(json!({
                    "path": "growlight/backlog/milestones/my-milestone/CLAUDE.md",
                    "content": "<!-- softfig:index slices -->\n\
                                | # | Note | Reviewed |\n\
                                |---|------|----------|\n\
                                | 001 | [first](slices/001-first.md) | 2026-07-14 |\n\
                                | 002 | [second](slices/002-second.md) |  |\n\
                                <!-- /softfig:index slices -->\n",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );

        let vis = app.growlight_tree.visible();
        // milestone + 2 slices + task + 4 loop-context + the live-baton node.
        assert_eq!(vis.len(), 9, "milestone + 2 slices + task + loop-context + baton");
        assert_eq!(vis[1].depth, 1);
        assert_eq!(vis[1].label, "001 first");
        assert_eq!(vis[1].status, "done", "reviewed slice → done");
        assert_eq!(vis[2].status, "queued", "blank-reviewed slice → queued");
        assert_eq!(
            vis[1].path.as_deref(),
            Some("growlight/backlog/milestones/my-milestone/slices/001-first.md")
        );

        // Selecting a slice maps the right-pane row back to its parent milestone.
        app.growlight_tree.selected = 1;
        assert_eq!(
            app.selected_growlight_row().map(|r| r.id.as_str()),
            Some("my-milestone")
        );
    }

    /// A small queue-only tree (one task + the loop-context section).
    fn seed_growlight_tree(app: &mut App, ipc: &mut IpcClient) {
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightQueue,
                result: Ok(json!({
                    "rows": [ { "id": "042", "title": "a task", "status": "queued" } ],
                })),
            },
            ipc,
        );
    }

    #[test]
    fn selecting_a_loop_context_node_targets_its_garden_path_and_resets_scroll() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        seed_growlight_tree(&mut app, &mut ipc);

        app.view = View::Growlight;
        app.preview_scroll = 25; // a leftover offset from another view
                                 // tree = [task, protocol.md, protocol-fleet.md, session-policy.md, pillar]
        app.growlight_tree.selected = 1; // first loop-context node
        app.refresh_growlight_selection(&mut ipc);
        assert_eq!(
            app.growlight_preview_path.as_deref(),
            Some("growlight/protocol.md")
        );
        assert_eq!(app.preview_scroll, 0, "a new node resets the shared scroll");
    }

    #[test]
    fn growlight_node_file_reply_populates_preview_and_drops_stale() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        seed_growlight_tree(&mut app, &mut ipc);
        app.view = View::Growlight;
        app.growlight_tree.selected = 1; // protocol.md loop-context node
        app.refresh_growlight_selection(&mut ipc);

        // The matching reply lands → the body shows in the right pane.
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::GrowlightNodeFile {
                    path: "growlight/protocol.md".into(),
                    slice: None,
                },
                result: Ok(json!({
                    "path": "growlight/protocol.md",
                    "content": "# operating protocol\nboot the baton",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert!(app.growlight_preview.contains("operating protocol"));

        // A reply for a node we already navigated away from is ignored.
        app.apply_reply(
            Reply {
                id: 3,
                tag: Tag::GrowlightNodeFile {
                    path: "growlight/protocol-fleet.md".into(),
                    slice: None,
                },
                result: Ok(json!({
                    "path": "growlight/protocol-fleet.md",
                    "content": "stale fleet body",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert!(
            !app.growlight_preview.contains("stale fleet body"),
            "a stale in-flight reply must not overwrite the current node"
        );
    }

    #[test]
    fn slice_node_read_lights_up_awaiting_smoke() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();

        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightMilestones,
                result: Ok(json!({
                    "entries": [
                        tree_entry("m", "growlight/backlog/milestones/m", true),
                    ],
                })),
            },
            &mut ipc,
        );
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::GrowlightQueue,
                result: Ok(json!({
                    "rows": [ { "id": "m", "title": "milestone m", "status": "deferred" } ],
                })),
            },
            &mut ipc,
        );
        app.growlight_tree.expand("m");
        app.apply_reply(
            Reply {
                id: 3,
                tag: Tag::GrowlightSliceIndex { milestone: "m".into() },
                result: Ok(json!({
                    "path": "growlight/backlog/milestones/m/CLAUDE.md",
                    "content": "<!-- softfig:index slices -->\n\
                                | # | Note | Reviewed |\n\
                                |---|------|----------|\n\
                                | 001 | [first](slices/001-first.md) | 2026-07-14 |\n\
                                <!-- /softfig:index slices -->\n",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        // A reviewed slice with no loaded body reads as done.
        assert_eq!(app.growlight_tree.visible()[1].status, "done");

        // Select the slice, then its body arrives carrying a Deferred
        // verification section → the derived status refines to awaiting-smoke.
        app.view = View::Growlight;
        app.growlight_tree.selected = 1;
        app.refresh_growlight_selection(&mut ipc);
        let slice_path = "growlight/backlog/milestones/m/slices/001-first.md";
        assert_eq!(app.growlight_preview_path.as_deref(), Some(slice_path));
        app.apply_reply(
            Reply {
                id: 4,
                tag: Tag::GrowlightNodeFile {
                    path: slice_path.into(),
                    slice: Some(("m".into(), "001".into())),
                },
                result: Ok(json!({
                    "path": slice_path,
                    "content": "## Finish criteria\n...\n## Deferred verification\nrun on-device",
                    "sealed": false,
                })),
            },
            &mut ipc,
        );
        assert_eq!(app.growlight_tree.visible()[1].status, "awaiting-smoke");
    }

    #[test]
    fn baton_headline_skips_frontmatter() {
        assert_eq!(
            baton_headline("---\nloop: x\nstatus: IN_PROGRESS\n---\n\n# NEXT ACTION\ngo"),
            Some("# NEXT ACTION")
        );
        assert_eq!(baton_headline("just a line\nmore"), Some("just a line"));
        assert_eq!(baton_headline("\n\n   \n"), None);
    }

    // ---- slice 003: live fleet header (growlightd status poll) ----

    /// A scripted growlightd `status` reply decodes into the live header.
    #[test]
    fn fleet_status_reply_decodes_into_live_header() {
        let mut app = App::new();
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::FleetStatus,
                result: Ok(json!({
                    "state": "running",
                    "garden_root": "/g",
                    "protocol_version": 1,
                    "policy": {
                        "max_concurrent_agents": 2,
                        "ctx_roll_pct": 50,
                        "ctx_handoff_pct": 60,
                        "session_5h_halt_pct": 85,
                        "session_7d_halt_pct": 90
                    },
                    "fleet_enabled": true,
                    "paused": false,
                    "agents": [{ "id": "a", "status": "running" }],
                    "roster": [{ "agent": "a" }]
                })),
            },
            &mut ipc,
        );
        match &app.fleet {
            FleetHeader::Live(s) => {
                assert!(s.fleet_enabled);
                assert!(!s.paused);
                assert_eq!(s.agents.len(), 1);
                assert_eq!(s.agents[0].id, "a");
                assert_eq!(s.policy.max_concurrent_agents, 2);
            }
            other => panic!("expected a live header, got {other:?}"),
        }
    }

    /// The header poll is view-gated: it fires ONLY while the Growlight tab is
    /// the active, enabled view — never from another tab, never before the
    /// enablement gate is known.
    #[test]
    fn fleet_poll_gated_to_active_enabled_growlight_view() {
        let mut app = App::new();
        // Default view is Browse, gate unknown → no poll.
        assert!(!app.should_poll_fleet());

        // Growlight view but gate not yet known → still no poll.
        app.view = View::Growlight;
        assert!(!app.should_poll_fleet());

        // Growlight view + enabled → poll.
        app.growlight_enabled = Some(true);
        assert!(app.should_poll_fleet());

        // Enabled but the user is on another tab → no poll (don't hammer growlightd).
        app.view = View::Browse;
        assert!(!app.should_poll_fleet());

        // Explicitly disabled while on the (now-stranded) view → no poll.
        app.view = View::Growlight;
        app.growlight_enabled = Some(false);
        assert!(!app.should_poll_fleet());
    }

    /// Soft-fail (load-bearing): an unreachable growlightd socket degrades the
    /// header to `Unreachable` WITHOUT a status splat or disturbing the
    /// garden-sourced tree/preview — the page keeps working.
    #[test]
    fn unreachable_growlightd_soft_fails_without_status_splat() {
        let mut app = App::new();
        // Seed some garden-sourced state + a prior live header.
        app.status = "ready".into();
        app.growlight_preview = "## Mission\nbody".into();
        app.fleet = FleetHeader::Unknown;

        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::FleetStatus,
                result: Err((softfig_ipc::ErrorKind::Io, "connect: no such file".into())),
            },
            &mut ipc,
        );

        assert!(matches!(app.fleet, FleetHeader::Unreachable));
        // No status splat: the footer status line is untouched.
        assert_eq!(app.status, "ready");
        // The garden-only body is untouched — the page still works.
        assert_eq!(app.growlight_preview, "## Mission\nbody");
    }

    /// A version-skewed / malformed `Ok` reply also degrades to the dim line
    /// rather than splatting an error.
    #[test]
    fn malformed_fleet_status_reply_degrades_to_unreachable() {
        let mut app = App::new();
        app.status = "ready".into();
        let mut ipc = dummy_ipc();
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::FleetStatus,
                // Missing the required `policy` object → decode fails.
                result: Ok(json!({ "state": "running", "garden_root": "/g", "protocol_version": 1 })),
            },
            &mut ipc,
        );
        assert!(matches!(app.fleet, FleetHeader::Unreachable));
        assert_eq!(app.status, "ready", "malformed reply must not splat the status line");
    }

    // ---- slice 004: live runtime baton (growlightd `baton` verb) ----

    const SAMPLE_BATON: &str = "---\n\
        loop: soft-fig_garden\n\
        status: IN_PROGRESS\n\
        item: growlight-tui-detail-pane\n\
        slice: 004\n\
        iteration: 1\n\
        ctx_pct: 16\n\
        session_5h_pct: 7\n\
        ---\n\n\
        # NEXT ACTION\n\
        do the thing";

    #[test]
    fn strip_frontmatter_returns_the_body_after_the_fence() {
        assert_eq!(strip_frontmatter(SAMPLE_BATON), "# NEXT ACTION\ndo the thing");
        // No frontmatter → the whole text passes through.
        assert_eq!(strip_frontmatter("# just a doc\nbody"), "# just a doc\nbody");
        // Frontmatter only, fence at EOF → empty body (no panic).
        assert_eq!(strip_frontmatter("---\nk: v\n---"), "");
        assert_eq!(strip_frontmatter("---\nk: v\n---\n"), "");
        // Unterminated fence → raw text (never lose content).
        assert_eq!(strip_frontmatter("---\nk: v\nmore"), "---\nk: v\nmore");
    }

    #[test]
    fn runtime_baton_head_parses_the_compact_fields_in_order() {
        assert_eq!(
            runtime_baton_head(SAMPLE_BATON),
            "item growlight-tui-detail-pane · slice 004 · iter 1 · IN_PROGRESS · ctx 16% · 5h 7%",
        );
        // A baton with no frontmatter yields an empty head (caller falls back).
        assert_eq!(runtime_baton_head("# NEXT ACTION\ngo"), "");
        // Only some fields present → only those, still in order.
        assert_eq!(
            runtime_baton_head("---\nstatus: STUCK\nitem: x\n---\nbody"),
            "item x · STUCK",
        );
    }

    #[test]
    fn runtime_baton_view_renders_present_empty_and_absent() {
        let mut app = App::new();
        // Absent (growlightd unreachable) → a calm placeholder, never an error.
        let (title, body) = app.runtime_baton_view();
        assert!(title.starts_with("live runtime baton"));
        assert!(body.contains("unavailable"), "absent baton reads as unavailable: {body}");

        // Present + non-empty → compact head above the frontmatter-stripped body.
        app.growlight_runtime_baton = Some(BatonReply {
            agent: None,
            path: "/x/baton.md".into(),
            text: SAMPLE_BATON.into(),
        });
        let (title, body) = app.runtime_baton_view();
        assert!(title.contains("/x/baton.md"), "the path is surfaced: {title}");
        assert!(body.starts_with("item growlight-tui-detail-pane · slice 004"));
        assert!(body.contains("# NEXT ACTION\ndo the thing"), "body follows the head");
        assert!(!body.contains("loop: soft-fig_garden"), "frontmatter is stripped from the body");

        // Present but empty (a real, seeded-but-blank baton) → its own placeholder.
        app.growlight_runtime_baton = Some(BatonReply {
            agent: None,
            path: "/x/baton.md".into(),
            text: "   \n".into(),
        });
        let (_title, body) = app.runtime_baton_view();
        assert!(body.contains("empty"), "an empty baton reads as empty: {body}");
    }

    #[test]
    fn runtime_baton_reply_decodes_into_some_and_soft_fails_to_none() {
        let mut app = App::new();
        app.status = "ready".into();
        app.growlight_preview = "## Mission\nbody".into();
        let mut ipc = dummy_ipc();

        // Ok → Some(reply).
        app.apply_reply(
            Reply {
                id: 1,
                tag: Tag::GrowlightRuntimeBaton,
                result: Ok(json!({ "path": "/x/baton.md", "text": SAMPLE_BATON })),
            },
            &mut ipc,
        );
        assert_eq!(
            app.growlight_runtime_baton.as_ref().map(|b| b.path.as_str()),
            Some("/x/baton.md"),
        );

        // Err → None (soft-fail), and NO status splat / no preview disturbance.
        app.apply_reply(
            Reply {
                id: 2,
                tag: Tag::GrowlightRuntimeBaton,
                result: Err((softfig_ipc::ErrorKind::Io, "connect: no such file".into())),
            },
            &mut ipc,
        );
        assert!(app.growlight_runtime_baton.is_none(), "unreachable → None");
        assert_eq!(app.status, "ready", "no status splat");
        assert_eq!(app.growlight_preview, "## Mission\nbody", "garden preview untouched");

        // A malformed Ok (missing `path`) also degrades to None, not a splat.
        app.growlight_runtime_baton = Some(BatonReply::default());
        app.apply_reply(
            Reply {
                id: 3,
                tag: Tag::GrowlightRuntimeBaton,
                result: Ok(json!({ "text": "no path field" })),
            },
            &mut ipc,
        );
        assert!(app.growlight_runtime_baton.is_none(), "malformed → None");
        assert_eq!(app.status, "ready");
    }

    #[test]
    fn selecting_the_runtime_baton_node_marks_the_slot_without_a_keeperd_read() {
        let mut app = App::new();
        app.locked = false;
        let mut ipc = dummy_ipc();
        seed_growlight_tree(&mut app, &mut ipc);
        app.view = View::Growlight;

        // The tree = [task, 4 loop-context, live-baton]; select the last (baton).
        let vis = app.growlight_tree.visible();
        let baton_idx = vis.len() - 1;
        assert_eq!(vis[baton_idx].kind, BacklogKind::RuntimeBaton);
        app.growlight_tree.selected = baton_idx;
        app.preview_scroll = 25; // a leftover offset
        app.growlight_preview = "stale garden body".into();

        app.refresh_growlight_selection(&mut ipc);
        // No keeperd `read_file` path — the sentinel marks the growlightd-sourced node.
        assert_eq!(app.growlight_preview_path.as_deref(), Some(RUNTIME_BATON_SLOT));
        assert_eq!(app.preview_scroll, 0, "selecting the baton node resets scroll");
        assert!(app.growlight_preview.is_empty(), "the stale garden body is cleared");

        // Re-selecting the same node is an idempotent no-op (scroll not re-reset).
        app.preview_scroll = 9;
        app.refresh_growlight_selection(&mut ipc);
        assert_eq!(app.preview_scroll, 9, "re-select does not reset scroll");
    }
}
