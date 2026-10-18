//! The real job executor (spec remote-runner §6 steps 3–6, slice 006 chunk 1):
//! fetch → run → collect, each inside its own `softfig-sandbox` profile, over
//! the materialized tree. Replaces slice 003's stub `JobResult`.
//!
//! The fetch step runs `cargo fetch --locked` against an extracted skeleton
//! (no repo-authored code) behind the allowlisting egress proxy; the run step
//! runs the offered command offline from the fetch-filled cargo home; the
//! collect step BLAKE3s the declared artifact globs inside the sandbox view so
//! a symlink can never leak a host file.
//!
//! **Chunk-1 scope.** The transient systemd unit, the resource caps, log
//! streaming, attach/cancel/TTL, and the *signed* attestation are chunk 2+.
//! Here the steps run unsandboxed-from-systemd (bwrap still confines them) and
//! the result carries the real exit code with an empty attestation.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use softfig_sandbox::{
    profile_collect, profile_fetch, profile_run, profile_run_egress, Bind, JobContext, Policy,
    ProxyConfig,
};
use softfig_source::extract_skeleton;

use crate::config::ServeConfig;
use crate::error::{Error, Result};
use crate::fetch::toolchain_missing;
use crate::proxy::EgressProxy;

/// In-sandbox mount points for the helper binaries (mirrors the install
/// convention the fetch harness uses; the proxy socket mounts at `EGRESS_SOCKET`).
const SHIM_MOUNT: &str = "/softfig-sandbox-init";
const FORWARDER_MOUNT: &str = "/softfig-sandbox-forward";
const COLLECT_MOUNT: &str = "/softfig-sandbox-collect";

/// The loopback TCP address the in-namespace forwarder listens on. A fresh net
/// namespace makes a fixed port safe (spec §7.2).
const FORWARDER_LISTEN: &str = "127.0.0.1:3128";

/// Paths to the sandbox helper binaries the executor bind-mounts into each
/// step's sandbox.
#[derive(Debug, Clone)]
pub struct SandboxBinaries {
    /// `softfig-sandbox-init` — the exec shim (Landlock + seccomp).
    pub init: PathBuf,
    /// `softfig-sandbox-forward` — the in-namespace TCP→unix CONNECT forwarder.
    pub forwarder: PathBuf,
    /// `softfig-sandbox-collect` — BLAKE3s the artifact globs inside the view.
    pub collect: PathBuf,
}

impl SandboxBinaries {
    /// Explicit paths (tests, which can't rely on the install layout).
    pub fn new(init: PathBuf, forwarder: PathBuf, collect: PathBuf) -> Self {
        Self { init, forwarder, collect }
    }

    /// Resolve the helper binaries from the directory containing the running
    /// runnerd binary (production install convention: they sit beside it).
    pub fn next_to_runnerd() -> Result<Self> {
        let dir = std::env::current_exe()
            .map_err(Error::Io)?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| Error::Protocol("current_exe has no parent dir".into()))?;
        Ok(Self {
            init: dir.join("softfig-sandbox-init"),
            forwarder: dir.join("softfig-sandbox-forward"),
            collect: dir.join("softfig-sandbox-collect"),
        })
    }
}

/// One hashed artifact from the collect step (spec §8 `artifacts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub size: u64,
    pub blake3: String,
}

/// The outcome of a job's run: the exit code plus the collected artifacts.
/// Chunk 2 signs this into the `JobAttestation`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunOutcome {
    pub exit_code: i32,
    pub artifacts: Vec<Artifact>,
}

/// Parse a human-readable size ("8G", "512M", "20G") into bytes (1024-based, as
/// systemd's bare `G`/`M`/`K`). A bare number is bytes. Reused by chunk 2 for
/// `memory_max`/`time_max` handling.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::malformed("size", "empty"));
    }
    let (num, mult) = if let Some(v) = s.strip_suffix('G') {
        (v, 1024u64.pow(3))
    } else if let Some(v) = s.strip_suffix('M') {
        (v, 1024u64.pow(2))
    } else if let Some(v) = s.strip_suffix('K') {
        (v, 1024)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| Error::malformed("size", s.to_string()))?;
    Ok(n * mult)
}

/// Parse a human-readable duration ("60m", "45m", "20m", "10s", "2h", "1d")
/// into whole seconds (spec §5.2's shorthand). systemd time spans reject a bare
/// `m` (ambiguous min vs month), so the spec's "60m" is our shorthand: `s`
/// seconds, `m` minutes, `h` hours, `d` days. A bare number is seconds. Reused
/// by the transient unit for `RuntimeMaxSec` (and, later, `[use] wait_timeout`).
pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::malformed("duration", "empty"));
    }
    let (num, mult) = if let Some(v) = s.strip_suffix('m') {
        (v, 60u64)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3600)
    } else if let Some(v) = s.strip_suffix('d') {
        (v, 86400)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| Error::malformed("duration", s.to_string()))?;
    Ok(n * mult)
}

/// Run a job's fetch → run → collect sequence over the materialized tree in
/// `ctx.src`. Returns a [`RunOutcome`] (the run step's real exit code plus the
/// collected artifacts), or [`Error::ToolchainMissing`] when the tree pins a
/// toolchain the runner lacks (the wire maps that to a `toolchain-missing`
/// [`JobReject`]).
pub fn execute(
    ctx: &JobContext,
    serve: &ServeConfig,
    offer: &softfig_net::proto::JobOffer,
    bins: &SandboxBinaries,
) -> Result<RunOutcome> {
    // 1. Extract the skeleton (manifests + lockfile + toolchain file) and check
    //    the toolchain *before* any sandbox runs (spec §7.2).
    let skel_dir = tempfile::tempdir()?;
    let skel = extract_skeleton(&ctx.src, skel_dir.path())
        .map_err(|e| Error::Protocol(format!("skeleton extraction failed: {e}")))?;
    if let Some(add_cmd) = toolchain_missing(skel.toolchain.as_deref(), serve) {
        return Err(Error::ToolchainMissing(add_cmd));
    }

    // A live egress proxy is needed when the fetch step has manifests to
    // resolve (cargo fetch) or the run step opts into network.
    let need_proxy = skel.manifests > 0 || offer.network == "egress";
    let proxy = if need_proxy { Some(JobProxy::start(&serve.egress)?) } else { None };

    // 2. Fetch, unless the tree has no manifests (nothing for cargo to resolve).
    if skel.manifests > 0 {
        let cfg = proxy.as_ref().expect("proxy started for the fetch step").config();
        let exit = fetch_step(ctx, skel_dir.path(), &cfg, bins)?;
        if exit != 0 {
            // A failed fetch is a failed job — a real result, not a runner-side
            // error (spec §9: only rejects trigger local fallback).
            return Ok(RunOutcome { exit_code: exit, artifacts: Vec::new() });
        }
    }

    // 3. Run the offered command (skip when the offer names none).
    let exit_code = run_step(ctx, offer, proxy.as_ref().map(JobProxy::config), bins)?;

    // 4. Collect the declared artifacts, BLAKE3-ed inside the sandbox view.
    let artifacts = if offer.artifacts.is_empty() {
        Vec::new()
    } else {
        collect_step(ctx, &offer.artifacts, bins)?
    };

    Ok(RunOutcome { exit_code, artifacts })
}

/// `cargo fetch --locked` against the skeleton, through the allowlisted proxy.
/// Returns the fetch command's exit code (the job fails on a non-zero one).
fn fetch_step(
    ctx: &JobContext,
    skel_dir: &Path,
    proxy: &ProxyConfig,
    bins: &SandboxBinaries,
) -> Result<i32> {
    let policy = profile_fetch(ctx, skel_dir.to_path_buf(), proxy.clone());
    let out = run_sandboxed(
        &policy,
        &["cargo".into(), "fetch".into(), "--locked".into()],
        bins,
        true,
        false,
    )?;
    Ok(exit_code(&out))
}

/// Run the offered command in the run profile (offline, or egress when the
/// offer opts in). The offer's `env` rides on top of the profile's environment.
fn run_step(
    ctx: &JobContext,
    offer: &softfig_net::proto::JobOffer,
    proxy: Option<ProxyConfig>,
    bins: &SandboxBinaries,
) -> Result<i32> {
    if offer.cmd.is_empty() {
        return Ok(0);
    }
    let mut policy = match (&offer.network, proxy) {
        (n, Some(cfg)) if n == "egress" => profile_run_egress(ctx, cfg),
        _ => profile_run(ctx),
    };
    for e in &offer.env {
        policy.env.insert(e.name.clone(), e.value.clone());
    }
    let out = run_sandboxed(&policy, &offer.cmd, bins, false, false)?;
    Ok(exit_code(&out))
}

/// BLAKE3 the declared artifact globs inside the collect sandbox.
fn collect_step(ctx: &JobContext, globs: &[String], bins: &SandboxBinaries) -> Result<Vec<Artifact>> {
    let policy = profile_collect(ctx);
    let mut cmd = vec![COLLECT_MOUNT.to_string()];
    cmd.extend(globs.iter().cloned());
    let out = run_sandboxed(&policy, &cmd, bins, false, true)?;
    if !out.status.success() {
        return Err(Error::Protocol(format!(
            "collect step failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    parse_artifacts(&out.stdout)
}

/// Parse the collect helper's `<blake3>\t<size>\t<relpath>` lines.
fn parse_artifacts(stdout: &[u8]) -> Result<Vec<Artifact>> {
    let text = String::from_utf8_lossy(stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, '\t');
        let (Some(blake3), Some(size), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        out.push(Artifact {
            path: path.to_string(),
            size: size.trim().parse().unwrap_or(0),
            blake3: blake3.trim().to_string(),
        });
    }
    Ok(out)
}

/// Render a policy into a bwrap argv and run the command inside the sandbox.
///
/// The helper binaries are added as read-only binds **on the policy** (not just
/// the bwrap argv), so the Landlock ruleset the shim derives from the *same*
/// bind list lets the command reach them. The collect helper is the command the
/// shim execs after Landlock is applied, so it must be Landlock-visible, not
/// merely mount-visible.
fn run_sandboxed(
    policy: &Policy,
    cmd: &[String],
    bins: &SandboxBinaries,
    with_forwarder: bool,
    with_collect: bool,
) -> std::io::Result<Output> {
    let mut policy = policy.clone();
    policy.ro_binds.push(Bind::ro(&bins.init, SHIM_MOUNT));
    if with_forwarder {
        policy.ro_binds.push(Bind::ro(&bins.forwarder, FORWARDER_MOUNT));
    }
    if with_collect {
        policy.ro_binds.push(Bind::ro(&bins.collect, COLLECT_MOUNT));
    }

    let argv = policy.render();
    let json = serde_json::to_string(&policy).map_err(std::io::Error::other)?;
    let mut c = Command::new("bwrap");
    c.args(&argv);
    c.arg(SHIM_MOUNT).arg("--policy").arg(&json).arg("--");
    c.args(cmd);
    c.output()
}

/// The exit code of a completed sandbox step: the process's code, or `-1` for a
/// signal-killed command (chunk 2 records the signal in the attestation).
fn exit_code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

/// A per-job allowlisted egress proxy on a Unix socket, served on a background
/// thread for the lifetime of the job's fetch/run steps. Stopped (cleanly) when
/// dropped: the stop flag wakes the non-blocking accept loop, which joins.
struct JobProxy {
    socket: PathBuf,
    _dir: tempfile::TempDir,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl JobProxy {
    fn start(allowlist: &[String]) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let socket = dir.path().join("egress.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).map_err(Error::Io)?;
        listener.set_nonblocking(true).map_err(Error::Io)?;

        let stop = Arc::new(AtomicBool::new(false));
        let allowlist = allowlist.to_vec();
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let allowlist = allowlist.clone();
                        std::thread::spawn(move || {
                            let _ = EgressProxy::serve_conn_with(stream, &allowlist);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if thread_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self { socket, _dir: dir, stop, handle: Some(handle) })
    }

    /// The [`ProxyConfig`] the fetch/egress profiles consume: the host socket
    /// path (bind-mounted at `EGRESS_SOCKET`) and the in-namespace forwarder.
    fn config(&self) -> ProxyConfig {
        ProxyConfig {
            socket: self.socket.clone(),
            forwarder: PathBuf::from(FORWARDER_MOUNT),
            listen: FORWARDER_LISTEN.into(),
        }
    }
}

impl Drop for JobProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_handles_suffixes_and_bare_bytes() {
        assert_eq!(parse_size("8G").unwrap(), 8 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("20G").unwrap(), 20 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("").is_err());
        assert!(parse_size("bogus").is_err());
    }

    #[test]
    fn parse_duration_handles_suffixes_and_bare_seconds() {
        assert_eq!(parse_duration("60m").unwrap(), 3600);
        assert_eq!(parse_duration("45m").unwrap(), 2700);
        assert_eq!(parse_duration("20m").unwrap(), 1200);
        assert_eq!(parse_duration("10s").unwrap(), 10);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("bogus").is_err());
    }

    #[test]
    fn parse_artifacts_reads_collect_lines() {
        let lines = b"abc123\t42\ttarget/release/softfig\ndef456\t7\ttarget/release/keeperd\n";
        let got = parse_artifacts(lines).unwrap();
        assert_eq!(
            got,
            vec![
                Artifact { path: "target/release/softfig".into(), size: 42, blake3: "abc123".into() },
                Artifact { path: "target/release/keeperd".into(), size: 7, blake3: "def456".into() },
            ]
        );
    }
}
