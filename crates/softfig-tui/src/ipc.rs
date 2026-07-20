//! Worker-thread IPC client.
//!
//! The sync `softfig-ipc` client runs on a dedicated thread so the UI loop
//! never blocks on a daemon round-trip. The UI sends `(id, op, args, tag)`
//! commands and drains replies non-blockingly each tick. The daemon serves
//! one request per connection, so the worker connects fresh per call.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use serde_json::Value;
use softfig_ipc::{call, connect, ErrorKind, Request};

pub type ReqId = u64;

/// What the reply is for, so the UI can route it to the right pane.
#[derive(Debug, Clone)]
pub enum Tag {
    Status,
    Unlock,
    ListTree { dir: String },
    ReadFile { path: String },
    History,
    Show,
    Action { title: String },
    VaultList,
    Reveal { path: String },
    /// M5a: list the network trust ring + pending pairings (`pair_list`).
    PairList,
    /// Pairing-UX Slice A: list nearby unpaired devices (`discover_list`).
    DiscoverList,
    /// M5a: initiate a pairing (`pair_begin`); reply carries the SAS to confirm.
    PairBegin,
    /// M5a: confirm a parked pairing's SAS (`pair_confirm`).
    PairConfirm,
    /// M5a: remove a peer from the ring (`pair_remove`).
    PairRemove,
    /// M5b: backup health for this device's chain (`replica_status`).
    ReplicaStatus,
    /// M5b: grant a paired host permission to back me up (`replica_grant`).
    ReplicaGrant,
    /// M5b: revoke a host's backup grant (`replica_revoke`).
    ReplicaRevoke,
    /// M4: the deploy plan (read-only diff) for the Deploy tab (`deploy_plan`).
    DeployPlan,
    /// M4: apply the deploy plan (`deploy_apply`); reply carries the `Report`.
    DeployApply,
    /// M5d slice 004: list every shared subtree (`shared_subtree_list`) for the
    /// Shares tab — membership + per-device enable state + `key_id`.
    SharedSubtreeList,
    /// M5d slice 004: register a new shared subtree (`shared_subtree_add`).
    SharedSubtreeAdd,
    /// M5d slice 004: un-share a subtree (`shared_subtree_remove`).
    SharedSubtreeRemove,
    /// M5d slice 004: flip a share's per-device enable state
    /// (`shared_subtree_enable`/`disable`).
    SharedSubtreeToggle,
    /// growlight: the backlog queue as daemon-parsed structured rows
    /// (`growlight_queue`) — no client re-parse of the managed table.
    GrowlightQueue,
    /// growlight: list `growlight/backlog/milestones` to classify which queue
    /// rows are milestones (expandable in the backlog tree) vs task leaves —
    /// the authoritative milestone set is the dir listing, not an id heuristic.
    GrowlightMilestones,
    /// growlight: list `growlight/backlog/tasks` so the `GrowlightSource`
    /// resolver can map a task's bare `NNN` queue id → its `NNN-slug.md` file.
    GrowlightTasks,
    /// growlight: read a milestone `CLAUDE.md` (`read_file`) to populate its
    /// slice-index children in the backlog tree (lazy, on first expand).
    GrowlightSliceIndex { milestone: String },
    /// growlight: read the selected tree node's markdown body for the right pane
    /// (`read_file`), resolved through `GrowlightSource`. `slice` carries the
    /// node's `(milestone_id, num)` when it is a slice, so the reply can refine
    /// that slice's derived status (awaiting-smoke) from the loaded body.
    GrowlightNodeFile {
        path: String,
        slice: Option<(String, String)>,
    },
    /// growlight: list the baton-log dir (`list_tree growlight/baton-log`) to
    /// find the highest-numbered entry (the latest handoff).
    GrowlightBatonList,
    /// growlight: read the latest baton-log entry (`read_file <path>`).
    GrowlightBaton { path: String },
    /// growlight: a one-shot growlightd `status` poll for the live fleet header
    /// (slice 003). Rides the SECOND, growlightd-only [`IpcClient`] channel, not
    /// the keeperd one — process-state is the one permanent growlightd read and
    /// never migrates to the garden mount. `Ok` carries a
    /// `softfig_ipc::growlightd::FleetStatusReply`; ANY `Err` (growlightd down /
    /// fleet disarmed / a version-skew malformed reply) soft-fails to the
    /// header's dim "unreachable" line — never a status splat, never blanking the
    /// garden-only tree/body.
    FleetStatus,
    /// growlight: the LIVE runtime baton, polled on the SECOND (growlightd-only)
    /// [`IpcClient`] channel via the `baton` verb (slice 004) — the loop's carried
    /// state, which lives OUTSIDE the garden today. `Ok` carries a
    /// `softfig_ipc::growlightd::BatonReply`; ANY `Err` (growlightd down / disarmed
    /// / a malformed reply) soft-fails to `None` — the header then falls back to the
    /// garden baton-LOG headline — never a status splat, never blanking the page.
    /// Transitional: retires when the runtime is a mounted garden chain, when the
    /// baton becomes a garden `read_file` like the other nodes (`## Forward-compat`).
    GrowlightRuntimeBaton,
    /// growlight: the coordination-bus history (slice 005), read via the keeperd
    /// `tail_bus` verb on the FIRST (keeperd `ipc`) channel — the bus is GARDEN
    /// state, like `GrowlightNodeFile`, NOT the growlightd channel (contrast
    /// `FleetStatus`/`GrowlightRuntimeBaton`). Eagerly loaded on tab entry (and on
    /// the stale-refresh path), not per-select. `Ok` carries a
    /// `softfig_ipc::TailBusReply` (messages ascending); the app parses it into
    /// newest-first rows. An `Err` surfaces on `self.status` like the other garden
    /// reads — the page keeps working with growlightd down (keeper-sourced).
    GrowlightBus,
    /// growlight: the PROTOCOL half of the injected-context node (slice 006) — a
    /// keeperd `read_file` of `growlight/protocol.md` (the SINGLE-AGENT template,
    /// through the resolver's garden arm), fired on select. `Ok` carries a
    /// `ReadFileReply`; the app stores its content in `growlight_injected_protocol`
    /// and the detail pane assembles it with the polled runtime baton at render
    /// time. An `Err` surfaces on `self.status` like the other garden reads (the
    /// baton half soft-fails on its own).
    GrowlightInjectedProtocol,
    /// m5e slice 004: the live coordination snapshot (`coordination_status`) —
    /// write-turn holders + S-member device states for the Coordination tab.
    CoordinationStatus,
    /// m5e slice 004: list every shared subtree (`shared_subtree_list`) so each
    /// mount root can be scanned for `.conflict-` sidecars.
    CoordinationShares,
    /// m5e slice 004: one shared subtree's mount-root listing (`list_tree`) —
    /// its `.conflict-` entries (slice 003 output) are the conflict sidecars.
    CoordinationSidecarList,
    /// m5e slice 004: read a selected conflict sidecar (`read_file`) for preview.
    CoordinationSidecar,
}

#[derive(Debug)]
struct Command {
    id: ReqId,
    op: String,
    args: Value,
    tag: Tag,
}

#[derive(Debug)]
pub struct Reply {
    pub id: ReqId,
    pub tag: Tag,
    pub result: Result<Value, (ErrorKind, String)>,
}

#[derive(Debug)]
pub struct IpcClient {
    tx: Sender<Command>,
    rx: Receiver<Reply>,
    next_id: ReqId,
}

impl IpcClient {
    pub fn spawn(socket: PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Command>();
        let (rep_tx, rep_rx) = std::sync::mpsc::channel::<Reply>();
        thread::Builder::new()
            .name("softfig-tui-ipc".into())
            .spawn(move || worker(socket, cmd_rx, rep_tx))
            .expect("spawn ipc worker");
        Self {
            tx: cmd_tx,
            rx: rep_rx,
            next_id: 1,
        }
    }

    pub fn send(&mut self, op: &str, args: Value, tag: Tag) -> ReqId {
        let id = self.next_id;
        self.next_id += 1;
        let _ = self.tx.send(Command {
            id,
            op: op.to_string(),
            args,
            tag,
        });
        id
    }

    /// Non-blocking drain of all replies that have arrived.
    pub fn drain(&self) -> Vec<Reply> {
        self.rx.try_iter().collect()
    }
}

fn worker(socket: PathBuf, cmd_rx: Receiver<Command>, rep_tx: Sender<Reply>) {
    for cmd in cmd_rx {
        let result = run_one(&socket, &cmd.op, &cmd.args);
        if rep_tx
            .send(Reply {
                id: cmd.id,
                tag: cmd.tag,
                result,
            })
            .is_err()
        {
            break; // UI gone
        }
    }
}

fn run_one(socket: &Path, op: &str, args: &Value) -> Result<Value, (ErrorKind, String)> {
    let mut stream = connect(socket).map_err(|e| (ErrorKind::Io, e.to_string()))?;
    let req = Request::new(op, args.clone());
    let resp = call(&mut stream, &req).map_err(|e| (ErrorKind::Io, e.to_string()))?;
    resp.into_result()
}
