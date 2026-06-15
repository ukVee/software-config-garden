//! `softfig pair <fingerprint>`, `softfig peers`, `softfig unpair <id>`
//! (M5a-4).
//!
//! Cross-device pairing over the network trust ring. All three talk to the
//! running daemon (which holds the unlocked vault + the live `softfig-net`
//! host); there is no direct-mode fallback — pairing needs the daemon's keys
//! and parked-session state, so an absent daemon is an error, not a bypass.
//!
//! `pair <fingerprint>` is dual-purpose, keyed on whether a pairing is already
//! parked awaiting confirmation:
//!
//! * if a **pending** pairing matches the fingerprint (the inbound listener
//!   parked it — the responder side), show its SAS and confirm it;
//! * otherwise **initiate** to the peer (the initiator side: dial, run the
//!   Noise `XX` handshake, show the SAS), then confirm.
//!
//! The user compares the SAS on both devices out of band before confirming; a
//! mismatch means a MITM and you answer `n` to abort.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use clap::Args;
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, DiscoverListReply, DiscoveredDevice, PairBeginArgs, PairBeginReply, PairConfirmArgs,
        PairConfirmReply, PairListReply, PairRemoveArgs, PairRemoveReply, PendingPairing,
    },
    Request,
};

#[derive(Args, Debug)]
pub struct PairArgs {
    /// The peer's device-id fingerprint (lowercase hex), full or a unique
    /// prefix. Omit it to pick a discovered device from a list by name (LAN
    /// pick-list).
    pub fingerprint: Option<String>,
    /// Explicit `host:port` to dial, overriding mDNS discovery. Required while
    /// the peer is not yet discoverable on the LAN.
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Skip the interactive SAS confirmation prompt (assume the codes match).
    /// Use only when you have already compared the SAS by another channel.
    #[arg(long)]
    pub yes: bool,
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct PeersArgs {
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct UnpairArgs {
    /// The ring peer's device-id fingerprint (full or unique prefix).
    pub fingerprint: String,
    /// Override the daemon socket path.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

pub fn pair(args: PairArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);

    // No fingerprint → LAN pick-list: surface discovered devices by name, let
    // the user choose, and thread its cached endpoint into the initiate path.
    let (fingerprint, endpoint) = match args.fingerprint {
        Some(fp) => (fp, args.endpoint),
        None => match pick_discovered(&socket)? {
            Some(device) => (device.fingerprint, device.endpoint),
            None => return Ok(()),
        },
    };

    pair_with(&socket, &fingerprint, endpoint, args.yes)
}

/// The shared pair flow for both a typed fingerprint and a picked device:
/// confirm a matching parked pending pairing if one exists (responder side),
/// otherwise initiate to the peer (initiator side). `endpoint` overrides mDNS
/// resolution when present.
fn pair_with(
    socket: &Path,
    fingerprint: &str,
    endpoint: Option<String>,
    assume_yes: bool,
) -> Result<()> {
    // Is there already a parked pairing matching this fingerprint (responder
    // side, parked by the inbound listener)? If so, confirm that one.
    let list: PairListReply =
        serde_json::from_value(daemon_call(socket, op::PAIR_LIST, serde_json::Value::Null)?)?;
    let query = fingerprint.trim().to_ascii_lowercase();
    if let Some(p) = list
        .pending
        .iter()
        .find(|p| p.fingerprint.starts_with(&query))
    {
        return confirm_flow(
            socket,
            &p.pairing_id,
            &p.sas,
            &p.fingerprint,
            &p.name,
            assume_yes,
        );
    }

    // Otherwise initiate.
    let begin_args = serde_json::to_value(PairBeginArgs {
        fingerprint: fingerprint.to_string(),
        endpoint,
    })?;
    let reply: PairBeginReply =
        serde_json::from_value(daemon_call(socket, op::PAIR_BEGIN, begin_args)?)?;
    confirm_flow(
        socket,
        &reply.pairing_id,
        &reply.sas,
        &reply.fingerprint,
        &reply.name,
        assume_yes,
    )
}

/// Show the LAN pick-list of discovered, unpaired devices and read the user's
/// choice. `Ok(None)` means nothing to pick or the user cancelled.
fn pick_discovered(socket: &Path) -> Result<Option<DiscoveredDevice>> {
    let reply: DiscoverListReply = serde_json::from_value(daemon_call(
        socket,
        op::DISCOVER_LIST,
        serde_json::Value::Null,
    )?)?;
    let mut devices = reply.devices;
    if devices.is_empty() {
        println!(
            "no devices discovered nearby — pass a fingerprint (`softfig pair <fp>`) \
             or --endpoint host:port"
        );
        return Ok(None);
    }

    println!("discovered nearby ({}):", devices.len());
    for (i, d) in devices.iter().enumerate() {
        println!("  {}) {}", i + 1, describe_device(d));
    }
    print!("pick a device [1-{}], or q to cancel: ", devices.len());
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;

    match parse_pick(&line, devices.len()) {
        Some(i) => Ok(Some(devices.swap_remove(i))),
        None => {
            println!("cancelled");
            Ok(None)
        }
    }
}

/// One pick-list row: name (or `(unnamed)`), short fingerprint, endpoint, age.
fn describe_device(d: &DiscoveredDevice) -> String {
    let name = d.name.as_deref().unwrap_or("(unnamed)");
    let endpoint = d.endpoint.as_deref().unwrap_or("(no endpoint)");
    format!(
        "{name}  {}  {endpoint}  (seen {}s ago)",
        short_fp(&d.fingerprint),
        d.last_seen_secs
    )
}

/// Parse a pick-list selection: a 1-based index within `1..=len` → a 0-based
/// index. Blank, `q`, out-of-range, or non-numeric all mean "no choice".
fn parse_pick(input: &str, len: usize) -> Option<usize> {
    let t = input.trim();
    let n: usize = t.parse().ok()?;
    if (1..=len).contains(&n) {
        Some(n - 1)
    } else {
        None
    }
}

/// Show the SAS, prompt (unless `--yes`), then confirm or abort.
fn confirm_flow(
    socket: &Path,
    pairing_id: &str,
    sas: &str,
    fingerprint: &str,
    name: &str,
    assume_yes: bool,
) -> Result<()> {
    println!("Peer:        {name}");
    println!("Fingerprint: {fingerprint}");
    println!("SAS:         {sas}");
    if !assume_yes && !prompt_yes("Confirm this code matches the other device? [y/N] ")? {
        println!("pairing aborted (not confirmed)");
        return Ok(());
    }

    let confirm_args = serde_json::to_value(PairConfirmArgs {
        pairing_id: pairing_id.to_string(),
    })?;
    let reply: PairConfirmReply =
        serde_json::from_value(daemon_call(socket, op::PAIR_CONFIRM, confirm_args)?)?;
    println!("paired with {} ({})", reply.name, reply.fingerprint);
    Ok(())
}

pub fn peers(args: PeersArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let reply: PairListReply = serde_json::from_value(daemon_call(
        &socket,
        op::PAIR_LIST,
        serde_json::Value::Null,
    )?)?;

    if reply.peers.is_empty() {
        println!("no paired devices");
    } else {
        println!("paired devices ({}):", reply.peers.len());
        for p in &reply.peers {
            let endpoints = if p.endpoints.is_empty() {
                "(no endpoints discovered)".to_string()
            } else {
                p.endpoints.join(", ")
            };
            println!("  {}  {}", short_fp(&p.fingerprint), p.name);
            println!("      transport {}", short_fp(&p.transport_pubkey));
            println!("      endpoints {endpoints}");
        }
    }

    if !reply.pending.is_empty() {
        println!("\npending pairings (awaiting SAS confirmation):");
        for p in &reply.pending {
            print_pending(p);
        }
        println!("\nconfirm one with `softfig pair <fingerprint>`");
    }
    Ok(())
}

fn print_pending(p: &PendingPairing) {
    println!("  {}  {}  SAS {}", short_fp(&p.fingerprint), p.name, p.sas);
}

pub fn unpair(args: UnpairArgs) -> Result<()> {
    let socket = args.socket.unwrap_or_else(runtime_socket_path);
    let remove_args = serde_json::to_value(PairRemoveArgs {
        fingerprint: args.fingerprint.clone(),
    })?;
    let reply: PairRemoveReply =
        serde_json::from_value(daemon_call(&socket, op::PAIR_REMOVE, remove_args)?)?;
    if reply.removed {
        println!("unpaired {}", reply.fingerprint);
    } else {
        println!("no change ({} was not in the ring)", reply.fingerprint);
    }
    Ok(())
}

/// First 16 hex chars of a fingerprint for compact display.
fn short_fp(fp: &str) -> &str {
    &fp[..16.min(fp.len())]
}

fn prompt_yes(msg: &str) -> Result<bool> {
    print!("{msg}");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let a = line.trim().to_ascii_lowercase();
    Ok(a == "y" || a == "yes")
}

/// Call the daemon, surfacing an absent daemon as an error (pairing has no
/// direct-mode fallback — it needs the daemon's keys + parked sessions).
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
    fn parse_pick_accepts_in_range_one_based() {
        assert_eq!(parse_pick("1", 3), Some(0));
        assert_eq!(parse_pick(" 3 \n", 3), Some(2));
    }

    #[test]
    fn parse_pick_rejects_out_of_range_and_noise() {
        assert_eq!(parse_pick("0", 3), None);
        assert_eq!(parse_pick("4", 3), None);
        assert_eq!(parse_pick("", 3), None);
        assert_eq!(parse_pick("q", 3), None);
        assert_eq!(parse_pick("two", 3), None);
        assert_eq!(parse_pick("1", 0), None);
    }

    #[test]
    fn describe_device_handles_missing_name_and_endpoint() {
        let d = DiscoveredDevice {
            name: None,
            fingerprint: "ab".repeat(32),
            endpoint: None,
            last_seen_secs: 7,
        };
        let s = describe_device(&d);
        assert!(s.contains("(unnamed)"));
        assert!(s.contains("(no endpoint)"));
        assert!(s.contains("seen 7s ago"));
    }
}
