//! `softfig shared-subtree add|remove|enable|disable|list` (M5c slice 003).
//!
//! The lifecycle surface for shared subtrees, two control axes deliberately
//! split ([[decision-softfig-shared-subtrees-impl]] pick 3):
//!
//! * `add` / `remove` edit the committed, ring-membership allow-list
//!   `config/shared-subtrees.toml` (add registers the path + creates the chain;
//!   the collaborative key ceremony is the stubbed m5d hook). `remove` un-shares.
//! * `enable` / `disable` flip a per-device **local** toggle only — no ceremony,
//!   no membership change, no effect on other members. The headline "easy on/off".
//!
//! All talk to the running daemon (which holds the unlocked vault + the garden);
//! there is no direct-mode fallback (same posture as `softfig replica`).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, MigrateIntoShareArgs, MigrateIntoShareReply, PendingShareOfferInfo,
        SharedSubtreeAcceptArgs, SharedSubtreeAcceptReply, SharedSubtreeAddArgs,
        SharedSubtreeAddReply, SharedSubtreeInfo, SharedSubtreeListReply, SharedSubtreeRemoveArgs,
        SharedSubtreeRemoveReply, SharedSubtreeToggleArgs, SharedSubtreeToggleReply,
    },
    Request,
};

#[derive(Subcommand, Debug)]
pub enum SharedSubtreeCmd {
    /// Register a new shared subtree (ring membership). Validates the mount path
    /// (machine dirs + overlaps rejected), creates the chain, and mounts it.
    Add(AddArgs),
    /// Un-share a subtree (drop its membership). Leaves the chain's objects for
    /// gc to reclaim later.
    Remove(IdArgs),
    /// Re-enable a subtree on THIS device (local toggle; no ceremony).
    Enable(IdArgs),
    /// Disable a subtree on THIS device (local toggle; no ceremony). Its subtree
    /// falls back to the device chain until re-enabled.
    Disable(IdArgs),
    /// List every shared-subtree member with its per-device enabled state.
    List(ListArgs),
    /// Accept a pending share-offer from a peer at a mount path of YOUR choosing
    /// (default = the sharer's recommended path). Validates the placement locally
    /// against your own garden; the key ceremony runs when the sharer is online.
    Accept(AcceptArgs),
    /// Migrate existing device content into a keyed share — the explicit M→S
    /// path. Moves the content at a garden path into an already-keyed shared
    /// subtree, re-encrypted under its key; refused on an unkeyed chain (run the
    /// key ceremony first). The way to "share a folder that already has content".
    MigrateIntoShare(MigrateArgs),
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Garden-relative mount prefix to share (e.g. `projects/journals`).
    pub mount_path: String,
    /// Stable id for the share; derived from the mount path's last component
    /// when omitted.
    #[arg(long)]
    pub id: Option<String>,
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct IdArgs {
    /// The share's id (as shown by `shared-subtree list`).
    pub id: String,
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct AcceptArgs {
    /// The offered share's id (as fanned by the sharer).
    pub id: String,
    /// Where to mount the share in YOUR garden. Defaults to the sharer's
    /// advisory recommended path when omitted.
    #[arg(long)]
    pub mount_path: Option<String>,
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// The target share's id (must already exist and be keyed).
    pub id: String,
    /// Garden-relative device path whose content moves into the share.
    pub from: String,
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub fn run(cmd: SharedSubtreeCmd) -> Result<()> {
    match cmd {
        SharedSubtreeCmd::Add(args) => add(args),
        SharedSubtreeCmd::Remove(args) => remove(args),
        SharedSubtreeCmd::Enable(args) => toggle(args, true),
        SharedSubtreeCmd::Disable(args) => toggle(args, false),
        SharedSubtreeCmd::List(args) => list(args),
        SharedSubtreeCmd::Accept(args) => accept(args),
        SharedSubtreeCmd::MigrateIntoShare(args) => migrate_into_share(args),
    }
}

fn add(args: AddArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let call = serde_json::to_value(SharedSubtreeAddArgs {
        mount_path: args.mount_path,
        id: args.id,
    })?;
    let reply: SharedSubtreeAddReply =
        serde_json::from_value(daemon_call(&socket, op::SHARED_SUBTREE_ADD, call)?)?;
    println!(
        "added shared subtree {} at {} (chain {})",
        reply.id, reply.mount_path, reply.ref_name
    );
    Ok(())
}

fn remove(args: IdArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let call = serde_json::to_value(SharedSubtreeRemoveArgs { id: args.id })?;
    let reply: SharedSubtreeRemoveReply =
        serde_json::from_value(daemon_call(&socket, op::SHARED_SUBTREE_REMOVE, call)?)?;
    if reply.removed {
        println!("removed shared subtree {}", reply.id);
    } else {
        println!("no change ({} was not a shared subtree)", reply.id);
    }
    Ok(())
}

fn toggle(args: IdArgs, enable: bool) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let op_name = if enable {
        op::SHARED_SUBTREE_ENABLE
    } else {
        op::SHARED_SUBTREE_DISABLE
    };
    let call = serde_json::to_value(SharedSubtreeToggleArgs { id: args.id })?;
    let reply: SharedSubtreeToggleReply = serde_json::from_value(daemon_call(&socket, op_name, call)?)?;
    let state = if reply.enabled { "enabled" } else { "disabled" };
    if reply.changed {
        println!("{state} shared subtree {} on this device", reply.id);
    } else {
        println!("no change ({} was already {state})", reply.id);
    }
    Ok(())
}

fn accept(args: AcceptArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let call = serde_json::to_value(SharedSubtreeAcceptArgs {
        id: args.id,
        mount_path: args.mount_path,
    })?;
    let reply: SharedSubtreeAcceptReply =
        serde_json::from_value(daemon_call(&socket, op::SHARED_SUBTREE_ACCEPT, call)?)?;
    if reply.already_accepted {
        println!(
            "shared subtree {} already accepted at {} (chain {})",
            reply.id, reply.mount_path, reply.ref_name
        );
    } else {
        println!(
            "accepted shared subtree {} at {} (chain {}); the key ceremony runs when the sharer \
             is next online — until then the mount holds no content",
            reply.id, reply.mount_path, reply.ref_name
        );
    }
    Ok(())
}

fn migrate_into_share(args: MigrateArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let call = serde_json::to_value(MigrateIntoShareArgs {
        id: args.id,
        from: args.from,
    })?;
    let reply: MigrateIntoShareReply =
        serde_json::from_value(daemon_call(&socket, op::MIGRATE_INTO_SHARE, call)?)?;
    println!(
        "migrated {} file(s) from {} into shared subtree {} at {}",
        reply.files, reply.from, reply.id, reply.mount_path
    );
    Ok(())
}

fn list(args: ListArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let reply: SharedSubtreeListReply = serde_json::from_value(daemon_call(
        &socket,
        op::SHARED_SUBTREE_LIST,
        serde_json::Value::Null,
    )?)?;

    if reply.subtrees.is_empty() && reply.offers.is_empty() {
        println!("no shared subtrees and no pending offers (sharing off)");
        return Ok(());
    }

    if reply.subtrees.is_empty() {
        println!("no shared subtrees mounted");
    } else {
        println!("shared subtrees ({}):", reply.subtrees.len());
        for s in &reply.subtrees {
            print_subtree(s);
        }
    }

    // M5f slice 006: pending offers from peers, held until this device accepts
    // them at a placement of its own choosing (accept is a separate verb).
    if !reply.offers.is_empty() {
        println!("pending share offers ({}):", reply.offers.len());
        for o in &reply.offers {
            print_offer(o);
        }
    }
    Ok(())
}

fn print_subtree(s: &SharedSubtreeInfo) {
    let state = if s.enabled { "enabled" } else { "disabled" };
    let key = s.key_id.as_deref().unwrap_or("(no key yet)");
    println!(
        "  {}  {}  {state}  chain {}  key {key}",
        s.id, s.mount_path, s.ref_name
    );
    // Placement is per-device; the sharer's recommendation is only a hint. Show
    // it solely when this device chose a different path (the divergent-placement
    // case the milestone makes first-class).
    if let Some(rec) = s.recommended_path.as_deref() {
        if rec != s.mount_path {
            println!("      (sharer recommended {rec})");
        }
    }
}

/// Render a pending share-offer row (M5f slice 006). Read-only surface — accept
/// is a separate verb, so each row spells out the accept command.
fn print_offer(o: &PendingShareOfferInfo) {
    // `offered_by` is a 64-hex-char fingerprint; a short prefix is enough to
    // tell peers apart on the surface without wrapping the line.
    let from = o.offered_by.get(..12).unwrap_or(&o.offered_by);
    match o.recommended_path.as_deref() {
        Some(rec) => println!(
            "  {}  from {from}…  recommends {rec}  chain {}",
            o.id, o.ref_name
        ),
        None => println!(
            "  {}  from {from}…  (no path hint — name one on accept)  chain {}",
            o.id, o.ref_name
        ),
    }
    println!("      accept: softfig shared-subtree accept {}", o.id);
}

/// Call the daemon, surfacing an absent daemon as an error (shared-subtree state
/// lives in the daemon; there is no direct-mode fallback).
fn daemon_call(socket: &Path, op: &str, args: serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = softfig_ipc::connect(socket).map_err(|e| {
        if e.is_daemon_absent() {
            anyhow!("daemon not running — start it and unlock the vault first")
        } else {
            anyhow!("{e}")
        }
    })?;
    let req = Request::new(op, args);
    let resp = softfig_ipc::call(&mut stream, &req)?;
    match resp.into_result() {
        Ok(v) => Ok(v),
        Err((kind, message)) => Err(anyhow!("{message}").context(format!("daemon error ({kind:?})"))),
    }
}
