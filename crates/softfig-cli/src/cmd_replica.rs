//! `softfig replica grant|revoke|status` (M5b).
//!
//! The owner-side controls for zero-knowledge device-chain replication. `grant`
//! / `revoke` edit this device's `push_to` allow-list (who may host its chain
//! backup); `status` shows backup-health metadata — who we push to, whether we
//! host, and per-peer mirror stats for chains we hold. All talk to the running
//! daemon (which holds the unlocked vault + the ring); there is no direct-mode
//! fallback. Becoming a *host* is a `keeper.toml [replica] host = true` flag,
//! not a subcommand here (same posture as `[relay]`).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, ReplicaGrantArgs, ReplicaGrantReply, ReplicaRevokeArgs, ReplicaRevokeReply,
        ReplicaStatusReply,
    },
    Request,
};

#[derive(Subcommand, Debug)]
pub enum ReplicaCmd {
    /// Grant a paired peer permission to host this device's chain backup
    /// (add it to `push_to`). The host must also opt in via `[replica] host`.
    Grant(GrantArgs),
    /// Revoke a replication grant (remove from `push_to`). Stops new pushes;
    /// cannot un-send ciphertext the host already holds.
    Revoke(GrantArgs),
    /// Show backup-health metadata: who we push to, whether we host, and
    /// per-peer mirror stats for chains we hold.
    Status(StatusArgs),
}

#[derive(Args, Debug)]
pub struct GrantArgs {
    /// The peer's device-id fingerprint (lowercase hex), full or a unique
    /// prefix. For `grant`, must name an already-paired ring member.
    pub fingerprint: String,
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub fn run(cmd: ReplicaCmd) -> Result<()> {
    match cmd {
        ReplicaCmd::Grant(args) => grant(args),
        ReplicaCmd::Revoke(args) => revoke(args),
        ReplicaCmd::Status(args) => status(args),
    }
}

fn grant(args: GrantArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let call = serde_json::to_value(ReplicaGrantArgs {
        fingerprint: args.fingerprint,
    })?;
    let reply: ReplicaGrantReply =
        serde_json::from_value(daemon_call(&socket, op::REPLICA_GRANT, call)?)?;
    if reply.granted {
        println!(
            "granted: {} may now host this device's chain backup",
            reply.fingerprint
        );
    } else {
        println!("no change ({} was already granted)", reply.fingerprint);
    }
    Ok(())
}

fn revoke(args: GrantArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let call = serde_json::to_value(ReplicaRevokeArgs {
        fingerprint: args.fingerprint,
    })?;
    let reply: ReplicaRevokeReply =
        serde_json::from_value(daemon_call(&socket, op::REPLICA_REVOKE, call)?)?;
    if reply.revoked {
        println!(
            "revoked: {} will receive no further pushes (it keeps what it already holds)",
            reply.fingerprint
        );
    } else {
        println!("no change ({} was not granted)", reply.fingerprint);
    }
    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let reply: ReplicaStatusReply = serde_json::from_value(daemon_call(
        &socket,
        op::REPLICA_STATUS,
        serde_json::Value::Null,
    )?)?;

    println!("backup host: {}", if reply.host { "yes" } else { "no" });

    if reply.push_to.is_empty() {
        println!("pushing chain to: (no granted hosts)");
    } else {
        println!("pushing chain to ({}):", reply.push_to.len());
        for fp in &reply.push_to {
            println!("  {}", short_fp(fp));
        }
    }

    if reply.host {
        if reply.hosted.is_empty() {
            println!("hosting backups for: (none yet)");
        } else {
            println!("hosting backups for ({}):", reply.hosted.len());
            for h in &reply.hosted {
                let name = h.name.as_deref().unwrap_or("(unknown)");
                let tip = h.tip.as_deref().map(short_fp).unwrap_or("(none)");
                println!(
                    "  {}  {name}  tip {tip}  height {}  {} objects / {}  last sync {}",
                    short_fp(&h.fingerprint),
                    h.height,
                    h.objects,
                    human_bytes(h.bytes),
                    h.last_sync
                        .map(format_unix)
                        .unwrap_or_else(|| "never".to_string()),
                );
            }
        }
    }
    Ok(())
}

/// First 16 hex chars of a fingerprint for compact display.
fn short_fp(fp: &str) -> &str {
    &fp[..16.min(fp.len())]
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn format_unix(secs: i64) -> String {
    // Avoid a chrono dep for a status line: show the raw epoch seconds.
    format!("@{secs}")
}

/// Call the daemon, surfacing an absent daemon as an error (replication state
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
        Err((kind, message)) => {
            Err(anyhow!("{message}").context(format!("daemon error ({kind:?})")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn short_fp_truncates() {
        assert_eq!(short_fp(&"a".repeat(64)), "aaaaaaaaaaaaaaaa");
        assert_eq!(short_fp("abcd"), "abcd");
    }
}
