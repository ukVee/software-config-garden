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

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use softfig_sandbox::{
    profile_collect, profile_fetch, profile_run, profile_run_egress, Bind, JobContext, Policy,
    ProxyConfig,
};
use softfig_source::extract_skeleton;

use crate::attestation::ToolchainInfo;
use crate::config::ServeConfig;
use crate::error::{Error, Result};
use crate::fetch::toolchain_missing;
use crate::log::LogSink;
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

/// The outcome of a job's run: the exit code (or signal), the collected
/// artifacts, the runner's toolchain, and the resolved run-policy fingerprint.
/// Chunk 3 folds these into the signed `JobAttestation`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunOutcome {
    pub exit_code: i32,
    /// `Some(signal)` when the run step was signal-killed (exit code -1).
    pub signal: Option<i32>,
    pub artifacts: Vec<Artifact>,
    /// The toolchain the runner used (empty for a cap-killed job, whose payload
    /// never wrote a report).
    #[serde(default)]
    pub toolchain: ToolchainInfo,
    /// Hex BLAKE3 of the resolved run policy (`None` when the offer named no
    /// command, so no run step happened).
    pub sandbox_policy: Option<String>,
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
    log: Option<&LogSink>,
) -> Result<RunOutcome> {
    // 1. Extract the skeleton (manifests + lockfile + toolchain file) and check
    //    the toolchain *before* any sandbox runs (spec §7.2).
    let skel_dir = tempfile::tempdir()?;
    let skel = extract_skeleton(&ctx.src, skel_dir.path())
        .map_err(|e| Error::Protocol(format!("skeleton extraction failed: {e}")))?;
    if let Some(add_cmd) = toolchain_missing(skel.toolchain.as_deref(), serve) {
        return Err(Error::ToolchainMissing(add_cmd));
    }
    // The toolchain the run step will resolve (spec §8 `toolchain`).
    let toolchain = toolchain_info(&ctx.toolchain, skel.toolchain.as_deref());

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
            return Ok(RunOutcome {
                exit_code: exit,
                signal: None,
                artifacts: Vec::new(),
                toolchain,
                sandbox_policy: None,
            });
        }
    }

    // 3. Run the offered command (skip when the offer names none), streaming
    //    its stdout/stderr to `log` when present.
    let (exit_code, signal, sandbox_policy) =
        run_step(ctx, offer, proxy.as_ref().map(JobProxy::config), bins, log)?;

    // 4. Collect the declared artifacts, BLAKE3-ed inside the sandbox view.
    let artifacts = if offer.artifacts.is_empty() {
        Vec::new()
    } else {
        collect_step(ctx, &offer.artifacts, bins)?
    };

    Ok(RunOutcome { exit_code, signal, artifacts, toolchain, sandbox_policy })
}

/// `cargo fetch --locked` against the skeleton, through the allowlisted proxy.
/// Returns the fetch command's exit code (the job fails on a non-zero one).
fn fetch_step(
    ctx: &JobContext,
    skel_dir: &Path,
    proxy: &ProxyConfig,
    bins: &SandboxBinaries,
) -> Result<i32> {
    // The fetch step alone gets the etc that carries a `resolv.conf`, when the
    // runner built one (`etc::fetch_etc_for`).
    let fetch_etc = crate::etc::fetch_etc_for(&ctx.etc);
    let mut fetch_ctx = ctx.clone();
    if fetch_etc.is_dir() {
        fetch_ctx.etc = fetch_etc;
    }
    let policy = profile_fetch(&fetch_ctx, skel_dir.to_path_buf(), proxy.clone());
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
/// Returns the exit code, the signal (when signal-killed), and the hex BLAKE3
/// of the resolved run policy (`None` when the offer named no command).
fn run_step(
    ctx: &JobContext,
    offer: &softfig_net::proto::JobOffer,
    proxy: Option<ProxyConfig>,
    bins: &SandboxBinaries,
    log: Option<&LogSink>,
) -> Result<(i32, Option<i32>, Option<String>)> {
    if offer.cmd.is_empty() {
        return Ok((0, None, None));
    }
    // The egress run step must bind-mount the in-namespace forwarder, or the
    // proxy the profile points at never launches (report #060 — the chunk-1
    // copy hard-coded `false`).
    let with_forwarder = offer.network == "egress";
    let mut policy = match (&offer.network, proxy) {
        (n, Some(cfg)) if n == "egress" => profile_run_egress(ctx, cfg),
        _ => profile_run(ctx),
    };
    for e in &offer.env {
        policy.env.insert(e.name.clone(), e.value.clone());
    }

    // The resolved run policy, fingerprinted canonically (spec §8
    // `sandbox_policy`), using the same JCS canonicalizer the attestation
    // reuses — never a second canonicalization scheme.
    let sandbox_policy = hex::encode(*blake3::hash(&serde_jcs::to_vec(&policy)?).as_bytes());

    let (code, signal) = match log {
        Some(sink) => run_streaming(&policy, &offer.cmd, bins, with_forwarder, sink)?,
        None => {
            let out = run_sandboxed(&policy, &offer.cmd, bins, with_forwarder, false)?;
            (exit_code(&out), out.status.signal())
        }
    };
    Ok((code, signal, Some(sandbox_policy)))
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

/// Parse the collect helper's rows: one JSON [`Artifact`] per line. JSON, not
/// tab-separated fields, because the tree's author names the files and a `\n`
/// or `\t` in a name must not forge a row (pre-merge review m3). Our own
/// helper printed these, so a row that doesn't parse fails the step rather
/// than being dropped from the attestation.
fn parse_artifacts(stdout: &[u8]) -> Result<Vec<Artifact>> {
    stdout
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line).map_err(|e| {
                Error::Protocol(format!(
                    "collect step printed a malformed row ({e}): {:?}",
                    String::from_utf8_lossy(line)
                ))
            })
        })
        .collect()
}

/// Build the bwrap [`Command`] for a policy + command: render the argv, add the
/// helper binaries as read-only binds **on the policy** (not just the argv), so
/// the Landlock ruleset the shim derives from the *same* bind list lets the
/// command reach them. The command's own argv is appended by the caller.
fn sandbox_command(
    policy: &Policy,
    bins: &SandboxBinaries,
    with_forwarder: bool,
    with_collect: bool,
) -> std::io::Result<Command> {
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
    Ok(c)
}

/// Render a policy into a bwrap argv and run the command inside the sandbox,
/// buffering its output. Used by the fetch and collect steps (whose output is
/// machine-read or short); the run step streams instead (see [`run_streaming`]).
fn run_sandboxed(
    policy: &Policy,
    cmd: &[String],
    bins: &SandboxBinaries,
    with_forwarder: bool,
    with_collect: bool,
) -> std::io::Result<Output> {
    let mut c = sandbox_command(policy, bins, with_forwarder, with_collect)?;
    c.args(cmd);
    c.output()
}

/// Run a sandboxed command with piped stdio, streaming its stdout (stream 0)
/// and stderr (stream 1) to `log` as they arrive. Returns the exit code and, if
/// signal-killed, the signal number. This replaces `Command::output()` buffering
/// for the run step (spec §6 Logs).
fn run_streaming(
    policy: &Policy,
    cmd: &[String],
    bins: &SandboxBinaries,
    with_forwarder: bool,
    log: &LogSink,
) -> std::io::Result<(i32, Option<i32>)> {
    let mut c = sandbox_command(policy, bins, with_forwarder, false)?;
    c.args(cmd);
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn()?;

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let out_sink = log.clone();
    let err_sink = log.clone();
    let out_thread = std::thread::spawn(move || pump(stdout, 0, &out_sink));
    let err_thread = std::thread::spawn(move || pump(stderr, 1, &err_sink));

    let status = child.wait()?;
    let _ = out_thread.join();
    let _ = err_thread.join();
    Ok((status.code().unwrap_or(-1), status.signal()))
}

/// Read a byte stream to EOF, pushing each read into the log sink.
fn pump<R: Read>(mut reader: R, stream: u8, sink: &LogSink) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => sink.push(stream, &buf[..n]),
            Err(_) => break,
        }
    }
}

/// The exit code of a completed sandbox step: the process's code, or `-1` for a
/// signal-killed command (the attestation records the signal separately).
fn exit_code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

/// The runner's toolchain, as the run step will resolve it: `rustc -vV` under
/// the runner's rustup home, pinned to the tree's channel when one is declared.
/// On any failure (no rustc, a missing channel), returns an empty record — a
/// rust job could not have run anyway, and `toolchain_missing` already rejects
/// a declared channel the runner lacks before this point.
fn toolchain_info(toolchain_home: &Path, channel: Option<&str>) -> ToolchainInfo {
    let mut cmd = Command::new("rustc");
    cmd.arg("-vV").env("RUSTUP_HOME", toolchain_home);
    if let Some(c) = channel {
        cmd.env("RUSTUP_TOOLCHAIN", c);
    }
    match cmd.output() {
        Ok(out) if out.status.success() => parse_rustc_vv(&out.stdout),
        _ => ToolchainInfo::default(),
    }
}

/// Parse `rustc -vV` output into a [`ToolchainInfo`]: the `rustc` line (the
/// version, commit and date) and the `host:` line (the target triple), then
/// infer the libc from the triple.
fn parse_rustc_vv(stdout: &[u8]) -> ToolchainInfo {
    let text = String::from_utf8_lossy(stdout);
    let mut rustc = String::new();
    let mut host = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("rustc ") {
            rustc = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("host: ") {
            host = rest.trim().to_string();
        }
    }
    let libc = if host.contains("musl") {
        "musl".into()
    } else if host.contains("gnu") {
        "gnu".into()
    } else {
        String::new()
    };
    ToolchainInfo { rustc, host_triple: host, libc }
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
    fn parse_artifacts_reads_collect_rows() {
        let rows = br#"{"path":"target/release/softfig","size":42,"blake3":"abc123"}
{"path":"target/release/keeperd","size":7,"blake3":"def456"}
"#;
        let got = parse_artifacts(rows).unwrap();
        assert_eq!(
            got,
            vec![
                Artifact { path: "target/release/softfig".into(), size: 42, blake3: "abc123".into() },
                Artifact { path: "target/release/keeperd".into(), size: 7, blake3: "def456".into() },
            ]
        );
    }

    #[test]
    fn parse_artifacts_keeps_a_control_character_name_in_one_row() {
        // m3: under the old `<hash>\t<size>\t<path>` framing this one file
        // read as two artifacts, the second chosen by the tree's author.
        let name = format!("x\n{}\t1\tforged.bin", "0".repeat(64));
        let row = Artifact { path: name, size: 4, blake3: "ab".repeat(32) };
        let mut line = serde_json::to_vec(&row).unwrap();
        line.push(b'\n');
        assert_eq!(parse_artifacts(&line).unwrap(), vec![row]);
    }

    #[test]
    fn parse_artifacts_refuses_a_malformed_row() {
        let tabbed = format!("{}\t5\ta.txt\n", "ab".repeat(32));
        let err = parse_artifacts(tabbed.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("malformed row"), "{err}");
    }

    #[test]
    fn parse_rustc_vv_extracts_version_host_and_libc() {
        let vv = b"rustc 1.85.0 (4d91de4e4 2025-02-17)\nbinary: rustc\ncommit-hash: 4d91de4e4\ncommit-date: 2025-02-17\nhost: x86_64-unknown-linux-gnu\nrelease: 1.85.0\nLLVM version: 20.1.0\n";
        let t = parse_rustc_vv(vv);
        assert_eq!(t.rustc, "1.85.0 (4d91de4e4 2025-02-17)");
        assert_eq!(t.host_triple, "x86_64-unknown-linux-gnu");
        assert_eq!(t.libc, "gnu");
    }

    #[test]
    fn parse_rustc_vv_infers_musl() {
        let vv = b"rustc 1.85.0 (x)\nhost: x86_64-unknown-linux-musl\n";
        assert_eq!(parse_rustc_vv(vv).libc, "musl");
    }
}
