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
    /// growlight: the backlog queue table (`read_file growlight/backlog/CLAUDE.md`).
    GrowlightQueue,
    /// growlight: list the baton-log dir (`list_tree growlight/baton-log`) to
    /// find the highest-numbered entry (the latest handoff).
    GrowlightBatonList,
    /// growlight: read the latest baton-log entry (`read_file <path>`).
    GrowlightBaton { path: String },
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
