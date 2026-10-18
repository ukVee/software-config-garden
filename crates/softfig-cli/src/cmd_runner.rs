//! `softfig runner …` — the remote-runner control surface (spec §9, slice 002).
//!
//! A runner is a paired peer running `softfig-runnerd` under its own
//! `softfig-runner` uid. The runner's own identity is a delegated certificate
//! the device identity signs; the CLI drives three things:
//!
//! * **runnerd's admin socket** (`/var/lib/softfig-runner/admin.sock` by
//!   default), gated by `SO_PEERCRED` to the owner uid — `enable`/`disable`/
//!   `status`/`grant`/`revoke`/`apply`/`purge`/`toolchain list`/`store-cert`.
//! * **keeperd** (unlocked) for the identity-key signing: `runner_sign_cert`
//!   (enable/renew), `runner_sign_revoke` (revoke-cert), `pair_list` (grant
//!   reads the peer's keys from the ring), and `read_file` (apply reads the
//!   garden's `config/runner.toml` `[serve]`).
//! * **the human** for root steps: `toolchain add` shells `rustup` as
//!   `softfig-runner`, so it is written out as a fenced command, never run
//!   here (the loop never runs sudo).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use softfig_ipc::{
    runtime_socket_path,
    verbs::{
        op, PairListReply, ReadFileArgs, ReadFileReply, RunnerSignCertArgs,
        RunnerSignCertReply, RunnerSignRevokeArgs, RunnerSignRevokeReply,
    },
    Request,
};
use softfig_runnerd::{
    admin::{AdminClient, ApplyArgs, GrantArgs, RevokeArgs, StoreCertArgs},
    cert::StoredCert,
    config::ServeConfig,
    state::DEFAULT_STATE_ROOT,
};

/// Default certificate lifetime: 90 days (spec §3.1).
const DEFAULT_LIFETIME_SECS: i64 = 90 * 24 * 60 * 60;

/// Default admin socket path (`<state-root>/admin.sock`).
fn default_admin_socket() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_ROOT).join("admin.sock")
}

#[derive(Subcommand, Debug)]
pub enum RunnerCmd {
    /// Enable the runner (generate keys if needed) and issue its certificate.
    Enable(RunnerArgs),
    /// Disable the runner.
    Disable(RunnerArgs),
    /// Show certificate expiry, accepted requesters, and the enforced `[serve]`.
    Status(RunnerArgs),
    /// Grant a ring peer permission to use this runner.
    Grant(GrantRevokeArgs),
    /// Revoke a ring peer and purge its mirrors.
    Revoke(GrantRevokeArgs),
    /// Re-issue the certificate (new serial + window) without touching keys.
    Renew(RunnerArgs),
    /// Sign and store a revocation for the current certificate serial.
    RevokeCert(RunnerArgs),
    /// Copy the garden's `config/runner.toml` `[serve]` into `serve.toml`.
    Apply(RunnerArgs),
    /// Clear the runner's mirrors and caches.
    Purge(RunnerArgs),
    /// Manage toolchains (`list`, `add` — `add` needs the human).
    Toolchain(ToolchainArgs),
}

#[derive(Args, Debug)]
pub struct RunnerArgs {
    /// The runnerd admin socket path.
    #[arg(long, default_value_os_t = default_admin_socket())]
    pub socket: PathBuf,
    /// The keeperd socket path.
    #[arg(long)]
    pub daemon_socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct GrantRevokeArgs {
    /// The peer's device-id fingerprint (full or unique prefix) or name.
    pub peer: String,
    #[arg(long, default_value_os_t = default_admin_socket())]
    pub socket: PathBuf,
    #[arg(long)]
    pub daemon_socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ToolchainArgs {
    #[command(subcommand)]
    pub cmd: ToolchainCmd,
    #[arg(long, default_value_os_t = default_admin_socket())]
    pub socket: PathBuf,
}

#[derive(Subcommand, Debug)]
pub enum ToolchainCmd {
    /// List the toolchains `[serve]` declares this runner can serve.
    List,
    /// Print the (root) command that installs a toolchain as `softfig-runner`.
    Add { spec: String },
}

pub fn run(cmd: RunnerCmd) -> Result<()> {
    match cmd {
        RunnerCmd::Enable(a) => enable(a),
        RunnerCmd::Disable(a) => disable(a),
        RunnerCmd::Status(a) => status(a),
        RunnerCmd::Grant(a) => grant(a),
        RunnerCmd::Revoke(a) => revoke(a),
        RunnerCmd::Renew(a) => renew(a),
        RunnerCmd::RevokeCert(a) => revoke_cert(a),
        RunnerCmd::Apply(a) => apply(a),
        RunnerCmd::Purge(a) => purge(a),
        RunnerCmd::Toolchain(a) => toolchain(a),
    }
}

fn client(socket: &Path) -> AdminClient {
    AdminClient::new(socket)
}

fn daemon_socket(args: &RunnerArgs) -> PathBuf {
    args.daemon_socket.clone().unwrap_or_else(runtime_socket_path)
}

fn daemon_socket_g(args: &GrantRevokeArgs) -> PathBuf {
    args.daemon_socket.clone().unwrap_or_else(runtime_socket_path)
}

/// Call keeperd, surfacing an absent daemon as a clear error (the signing and
/// ring reads need the unlocked vault).
fn daemon_call(socket: &Path, op: &str, args: Value) -> Result<Value> {
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

/// Drive a runnerd verb and return its `data`; a `!ok` response is an error.
fn runner_call(c: &AdminClient, verb: &str, args: Value) -> Result<Value> {
    let resp = c
        .request(verb, args)
        .context(format!("{verb}: runnerd admin socket at {}", c.socket().display()))?;
    if !resp.ok {
        return Err(anyhow!(
            "runnerd {verb} failed: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        ));
    }
    Ok(resp.data.unwrap_or(Value::Null))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sign a fresh certificate for the runner's two pubkeys via keeperd, then
/// store it on runnerd. Shared by `enable` and `renew` (keeperd mints a fresh
/// serial each call).
fn sign_and_store(c: &AdminClient, dsock: &Path, transport: &str, attest: &str) -> Result<()> {
    let issued = now_secs();
    let sign_args = serde_json::to_value(RunnerSignCertArgs {
        runner_transport_pubkey: transport.to_string(),
        runner_attest_pubkey: attest.to_string(),
        issued_at: issued,
        expires_at: issued + DEFAULT_LIFETIME_SECS,
    })?;
    let reply: RunnerSignCertReply =
        serde_json::from_value(daemon_call(dsock, op::RUNNER_SIGN_CERT, sign_args)?)?;

    let cert = StoredCert {
        device_id: reply.cert.device_id,
        runner_transport_pubkey: reply.cert.runner_transport_pubkey,
        runner_attest_pubkey: reply.cert.runner_attest_pubkey,
        serial: reply.cert.serial,
        issued_at: reply.cert.issued_at,
        expires_at: reply.cert.expires_at,
        signature: reply.signature,
    };
    runner_call(c, "store-cert", serde_json::to_value(StoreCertArgs { cert })?)?;
    Ok(())
}

fn enable(args: RunnerArgs) -> Result<()> {
    let c = client(&args.socket);
    let dsock = daemon_socket(&args);
    let enabled = runner_call(&c, "enable", Value::Null)?;
    let transport = enabled["transport_pubkey"].as_str().unwrap_or_default().to_string();
    let attest = enabled["attest_pubkey"].as_str().unwrap_or_default().to_string();
    if transport.len() != 64 || attest.len() != 64 {
        return Err(anyhow!("runnerd enable returned malformed pubkeys"));
    }
    sign_and_store(&c, &dsock, &transport, &attest)?;
    println!("runner enabled; certificate issued (transport {})", &transport[..16]);
    Ok(())
}

fn disable(args: RunnerArgs) -> Result<()> {
    let c = client(&args.socket);
    let _ = runner_call(&c, "disable", Value::Null)?;
    println!("runner disabled");
    Ok(())
}

fn renew(args: RunnerArgs) -> Result<()> {
    let c = client(&args.socket);
    let dsock = daemon_socket(&args);
    let st = runner_call(&c, "status", Value::Null)?;
    let transport = st["transport_pubkey"].as_str().ok_or_else(|| anyhow!("no runner keys"))?;
    let attest = st["attest_pubkey"].as_str().ok_or_else(|| anyhow!("no runner keys"))?;
    sign_and_store(&c, &dsock, transport, attest)?;
    println!("certificate renewed");
    Ok(())
}

fn revoke_cert(args: RunnerArgs) -> Result<()> {
    let c = client(&args.socket);
    let dsock = daemon_socket(&args);
    let st = runner_call(&c, "status", Value::Null)?;
    let serial = st["cert"]["serial"]
        .as_str()
        .ok_or_else(|| anyhow!("no certificate present — nothing to revoke"))?;
    let revoke_args = serde_json::to_value(RunnerSignRevokeArgs {
        serial: serial.to_string(),
    })?;
    let reply: RunnerSignRevokeReply =
        serde_json::from_value(daemon_call(&dsock, op::RUNNER_SIGN_REVOKE, revoke_args)?)?;
    runner_call(
        &c,
        "revoke-cert",
        serde_json::json!({
            "device_id": reply.device_id,
            "serial": serial,
            "signature": reply.signature,
        }),
    )?;
    println!("certificate {serial} revoked (record held locally)");
    Ok(())
}

/// Resolve `<peer>` (fingerprint prefix or name) against the ring, returning
/// the peer's identity + transport key + name.
fn resolve_peer(dsock: &Path, query: &str) -> Result<(String, String, String)> {
    let list: PairListReply =
        serde_json::from_value(daemon_call(dsock, op::PAIR_LIST, Value::Null)?)?;
    let q = query.trim().to_ascii_lowercase();
    let matches: Vec<_> = list
        .peers
        .iter()
        .filter(|p| p.fingerprint.starts_with(&q) || p.name.to_ascii_lowercase() == q)
        .collect();
    match matches.as_slice() {
        [p] => Ok((
            p.fingerprint.clone(),
            p.transport_pubkey.clone(),
            p.name.clone(),
        )),
        [] => Err(anyhow!("peer {query:?} not in the ring (try `softfig peers`)")),
        many => Err(anyhow!(
            "peer {query:?} is ambiguous: {}",
            many.iter()
                .map(|p| format!("{} ({})", p.name, short(&p.fingerprint)))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn grant(args: GrantRevokeArgs) -> Result<()> {
    let c = client(&args.socket);
    let dsock = daemon_socket_g(&args);
    let (device_id, transport_pubkey, name) = resolve_peer(&dsock, &args.peer)?;
    let data = runner_call(
        &c,
        "grant",
        serde_json::to_value(GrantArgs {
            device_id,
            transport_pubkey,
            name,
        })?,
    )?;
    let granted = data["granted"].as_bool().unwrap_or(false);
    if granted {
        println!("granted {} ({})", args.peer, short(&args.peer));
    } else {
        println!("{} was already granted (refreshed)", args.peer);
    }
    Ok(())
}

fn revoke(args: GrantRevokeArgs) -> Result<()> {
    let c = client(&args.socket);
    let dsock = daemon_socket_g(&args);
    let (device_id, _, _) = resolve_peer(&dsock, &args.peer)?;
    let data = runner_call(
        &c,
        "revoke",
        serde_json::to_value(RevokeArgs { device_id })?,
    )?;
    if data["revoked"].as_bool().unwrap_or(false) {
        println!("revoked {}", args.peer);
    } else {
        println!("{} was not granted", args.peer);
    }
    Ok(())
}

fn status(args: RunnerArgs) -> Result<()> {
    let c = client(&args.socket);
    let st = runner_call(&c, "status", Value::Null)?;

    println!("enabled: {}", st["enabled"].as_bool().unwrap_or(false));
    if let Some(tp) = st["transport_pubkey"].as_str() {
        println!("transport key: {}", short(tp));
    }
    if let Some(cert) = st["cert"].as_object() {
        let serial = cert.get("serial").and_then(|v| v.as_str()).unwrap_or("?");
        let expires = cert.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);
        let device = cert.get("device_id").and_then(|v| v.as_str()).unwrap_or("?");
        println!("certificate: serial {serial} expires {expires} (device {})", short(device));
    } else {
        println!("certificate: none");
    }
    if let Some(rev) = st["revocation"].as_object() {
        println!(
            "revoked: serial {}",
            rev.get("serial").and_then(|v| v.as_str()).unwrap_or("?")
        );
    }
    let accepted = st["accepted_requesters"].as_array().cloned().unwrap_or_default();
    if accepted.is_empty() {
        println!("accepted requesters: none");
    } else {
        println!("accepted requesters:");
        for id in accepted {
            if let Some(s) = id.as_str() {
                println!("  {s}");
            }
        }
    }
    // The enforced `[serve]` table (drift against the garden's `[serve]` is
    // surfaced by comparing `softfig runner status` with `config/runner.toml`).
    if let Ok(serve) = serde_json::from_value::<ServeConfig>(st["serve"].clone()) {
        println!(
            "serve: enabled={} max_jobs={} memory_max={} toolchains={:?} egress={:?}",
            serve.enabled, serve.max_jobs, serve.memory_max, serve.toolchains, serve.egress
        );
    }
    Ok(())
}

fn apply(args: RunnerArgs) -> Result<()> {
    let c = client(&args.socket);
    let dsock = daemon_socket(&args);

    // The garden's `config/runner.toml` `[serve]` is the reviewed source of
    // truth (spec §5.2); read it through keeperd so it works in FUSE and Disk
    // modes alike.
    let read: ReadFileReply = serde_json::from_value(daemon_call(
        &dsock,
        op::READ_FILE,
        serde_json::to_value(ReadFileArgs {
            path: "config/runner.toml".to_string(),
        })?,
    )?)?;
    if read.sealed {
        return Err(anyhow!("config/runner.toml is sealed; cannot read [serve]"));
    }
    let doc: toml::Value = toml::from_str(&read.content).context("config/runner.toml is not valid TOML")?;
    let serve_toml = doc
        .get("serve")
        .ok_or_else(|| anyhow!("config/runner.toml has no [serve] table"))?;
    let serve: ServeConfig = serve_toml
        .clone()
        .try_into()
        .context("config/runner.toml [serve] is malformed")?;

    runner_call(&c, "apply", serde_json::to_value(ApplyArgs { serve })?)?;
    println!("applied [serve] to runnerd's serve.toml");
    Ok(())
}

fn purge(args: RunnerArgs) -> Result<()> {
    let c = client(&args.socket);
    let data = runner_call(&c, "purge", Value::Null)?;
    println!("purged {} dir(s)", data["purged"].as_u64().unwrap_or(0));
    Ok(())
}

fn toolchain(args: ToolchainArgs) -> Result<()> {
    let c = client(&args.socket);
    match args.cmd {
        ToolchainCmd::List => {
            let data = runner_call(&c, "toolchain", serde_json::json!({ "action": "list" }))?;
            let tcs = data["toolchains"].as_array().cloned().unwrap_or_default();
            if tcs.is_empty() {
                println!("no toolchains configured in [serve]");
            } else {
                for t in tcs {
                    if let Some(s) = t.as_str() {
                        println!("{s}");
                    }
                }
            }
            Ok(())
        }
        ToolchainCmd::Add { spec } => {
            // Runs `rustup` as `softfig-runner`, which needs root — write it as
            // a fenced command for the human (the loop never runs sudo).
            println!("install a toolchain as the runner user (needs root):");
            println!();
            println!("    runuser -u softfig-runner -- rustup toolchain install {spec}");
            println!();
            println!("rollback (only if the install breaks a working toolchain):");
            println!("    runuser -u softfig-runner -- rustup toolchain uninstall {spec}");
            Ok(())
        }
    }
}

fn short(fp: &str) -> &str {
    &fp[..16.min(fp.len())]
}
