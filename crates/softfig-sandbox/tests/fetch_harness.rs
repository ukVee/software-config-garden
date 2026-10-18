//! The fetch-step harness (spec remote-runner §7.2, slice 005): run
//! `cargo fetch --locked` against an extracted skeleton inside the
//! `profile_fetch` sandbox, through the in-namespace forwarder to a CONNECT
//! proxy on a Unix socket. Proves the whole stack end to end:
//!
//! - cargo's HTTP(S) goes to the forwarder (loopback), which pumps to the proxy
//!   socket — no direct network from the sandbox;
//! - the registry cache is filled by the fetch step (rw there only);
//! - no repo-authored code runs: a `build.rs` that would write a marker, and a
//!   `.cargo/config.toml` that would name a credential provider, are both
//!   stripped by the skeleton and leave no trace.
//!
//! The CONNECT proxy here is a *test double* for `softfig-runnerd`'s
//! `EgressProxy` (which is unit-tested for its allowlist on both a TCP and a
//! Unix listener in that crate); it speaks the same CONNECT protocol so the
//! forwarder and the fetch path are exercised for real. Skips loudly when
//! bwrap, user namespaces, cargo or the network are unavailable.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;

use softfig_sandbox::{profile_fetch, profile_run, JobContext, ProxyConfig};
use softfig_source::extract_skeleton;

const SHIM: &str = env!("CARGO_BIN_EXE_softfig-sandbox-init");
const FORWARDER: &str = env!("CARGO_BIN_EXE_softfig-sandbox-forward");

/// The in-sandbox paths the shim and forwarder are bind-mounted to (mirrors the
/// runner's install convention; the proxy socket mounts at `EGRESS_SOCKET`).
const SHIM_MOUNT: &str = "/softfig-sandbox-init";
const FORWARDER_MOUNT: &str = "/softfig-sandbox-forward";

fn bwrap_ok() -> bool {
    Command::new("bwrap").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}
fn userns_ok() -> bool {
    Command::new("unshare").args(["-Ur", "true"]).status().map(|s| s.success()).unwrap_or(false)
}
fn cargo_ok() -> bool {
    Command::new("cargo").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}
fn network_ok() -> bool {
    TcpStream::connect(("index.crates.io", 443)).is_ok()
}

/// `true` when the preconditions are unmet, after printing a loud skip.
fn skip() -> bool {
    if !bwrap_ok() || !userns_ok() {
        eprintln!("SKIPPED: bwrap or user namespaces unavailable; cannot run the fetch harness");
        return true;
    }
    if !cargo_ok() {
        eprintln!("SKIPPED: cargo unavailable; cannot run the fetch harness");
        return true;
    }
    if !network_ok() {
        eprintln!("SKIPPED: no network to index.crates.io; cannot run the fetch harness");
        return true;
    }
    false
}

/// A fixture repo whose `build.rs` would write a `MARKER` if it ran, and whose
/// `.cargo/config.toml` names a credential provider. Both must be stripped by
/// the skeleton and must not execute during fetch.
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n\n[dependencies]\nlibc = \"0.2.191\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        "# This lockfile is replaced by a real `cargo fetch` below before the harness runs.\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn m() -> i32 { unsafe { libc::getpid() } }\n").unwrap();
    std::fs::write(
        root.join("build.rs"),
        "fn main() { std::fs::write(\"MARKER\", \"ran\").unwrap(); }\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join(".cargo")).unwrap();
    std::fs::write(
        root.join(".cargo/config.toml"),
        "[registry]\nglobal-credential-providers = [\"cargo:token-from-env\"]\n",
    )
    .unwrap();
    dir
}

/// Pin the fixture's real lockfile by running `cargo fetch` (host, unsandboxed)
/// against a throwaway cargo home, so the harness's `--locked` fetch has a
/// lockfile to honor.
fn pin_lockfile(fixture: &Path) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new("cargo")
        .env("CARGO_HOME", home.path())
        .arg("fetch")
        .current_dir(fixture)
        .output()
        .expect("failed to run cargo fetch to pin the lockfile");
    assert!(out.status.success(), "pin lockfile failed: {}", String::from_utf8_lossy(&out.stderr));
    home
}

/// A minimal CONNECT proxy on a Unix socket (test double for runnerd's
/// `EgressProxy`): parse CONNECT, dial the target, pump bidirectionally.
fn spawn_proxy(socket: &Path) {
    let listener = UnixListener::bind(socket).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || serve_proxy_conn(stream));
        }
    });
}

fn serve_proxy_conn(mut client: UnixStream) {
    // Read the CONNECT head.
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 64 * 1024 {
        if client.read_exact(&mut byte).is_err() {
            return;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let first = buf.split(|&b| b == b'\n').next().unwrap_or_default();
    let first = String::from_utf8_lossy(first);
    let mut parts = first.split_whitespace();
    if parts.next() != Some("CONNECT") {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    }
    let Some(target) = parts.next() else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    let Some((host, port)) = target.rsplit_once(':') else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    let Ok(port) = port.parse::<u16>() else {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
    };
    let Ok(upstream) = TcpStream::connect((host, port)) else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
    pump(client, upstream);
}

fn pump(mut a: UnixStream, mut b: TcpStream) {
    let mut a_read = match a.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut b_read = match b.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let a_to_b = thread::spawn(move || {
        let _ = std::io::copy(&mut a, &mut b_read);
        let _ = b_read.shutdown(Shutdown::Write);
    });
    let b_to_a = thread::spawn(move || {
        let _ = std::io::copy(&mut b, &mut a_read);
        let _ = a_read.shutdown(Shutdown::Write);
    });
    let _ = a_to_b.join();
    let _ = b_to_a.join();
}

/// Run `profile_fetch` for real: render the bwrap argv, bind the shim and
/// forwarder, and exec `cargo fetch --locked` inside.
fn run_fetch(ctx: &JobContext, skeleton: &Path, proxy: ProxyConfig) -> Output {
    let policy = profile_fetch(ctx, skeleton.to_path_buf(), proxy);
    let mut argv = policy.render();
    argv.push("--ro-bind".into());
    argv.push(SHIM.to_string());
    argv.push(SHIM_MOUNT.into());
    argv.push("--ro-bind".into());
    argv.push(FORWARDER.to_string());
    argv.push(FORWARDER_MOUNT.into());

    let json = serde_json::to_string(&policy).expect("policy serializes");
    let mut command = Command::new("bwrap");
    command.args(&argv);
    command.arg(SHIM_MOUNT).arg("--policy").arg(&json).arg("--");
    command.args(["cargo", "fetch", "--locked"]);
    command.output().expect("failed to spawn bwrap")
}

/// Run the offline run step: `cargo build --offline` in the full materialized
/// tree (`src` rw at `/src`), with the fetch-populated cargo home read-only.
fn run_build(ctx: &JobContext) -> Output {
    let policy = profile_run(ctx);
    let mut argv = policy.render();
    argv.push("--ro-bind".into());
    argv.push(SHIM.to_string());
    argv.push(SHIM_MOUNT.into());

    let json = serde_json::to_string(&policy).expect("policy serializes");
    let mut command = Command::new("bwrap");
    command.args(&argv);
    command.arg(SHIM_MOUNT).arg("--policy").arg(&json).arg("--");
    command.args(["cargo", "build", "--offline"]);
    command.output().expect("failed to spawn bwrap")
}

#[test]
fn run_builds_offline_from_the_fetch_cache() {
    if skip() {
        return;
    }

    let dir = fixture();
    let _pin_home = pin_lockfile(dir.path());

    let skeleton = tempfile::tempdir().unwrap();
    extract_skeleton(dir.path(), skeleton.path()).unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let target_cache = tempfile::tempdir().unwrap();

    let proxy_socket_dir = tempfile::tempdir().unwrap();
    let proxy_socket = proxy_socket_dir.path().join("egress.sock");
    spawn_proxy(&proxy_socket);

    let ctx = JobContext {
        src: dir.path().to_path_buf(),
        target_cache: target_cache.path().to_path_buf(),
        toolchain: PathBuf::from("/home/ukv/.rustup"),
        cargo_home: cargo_home.path().to_path_buf(),
        etc: PathBuf::from("/etc"),
        scratch_size: 64 * 1024 * 1024,
    };

    // 1. Fetch through the proxy, filling the fresh cargo home.
    let proxy = ProxyConfig {
        socket: proxy_socket,
        forwarder: PathBuf::from(FORWARDER_MOUNT),
        listen: "127.0.0.1:3128".into(),
    };
    let fetch = run_fetch(&ctx, skeleton.path(), proxy);
    assert!(
        fetch.status.success(),
        "fetch failed:\n{}",
        String::from_utf8_lossy(&fetch.stderr)
    );
    // The marker-writing build.rs must not have run during fetch.
    assert!(find(dir.path(), "MARKER").is_none(), "build.rs must not run during fetch");

    // 2. Build offline from that cache (the run profile binds cargo_home ro).
    let run = run_build(&ctx);
    assert!(
        run.status.success(),
        "offline run build failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    // This time build.rs *did* run, offline, in the run step.
    assert!(
        find(dir.path(), "MARKER").is_some(),
        "build.rs must run in the offline run step"
    );
}

#[test]
fn fetch_through_the_proxy_runs_no_repo_code() {
    if skip() {
        return;
    }

    let dir = fixture();
    let _pin_home = pin_lockfile(dir.path()); // keep the lockfile-pinning cargo home alive

    let skeleton = tempfile::tempdir().unwrap();
    let skel = extract_skeleton(dir.path(), skeleton.path()).unwrap();
    assert!(skel.manifests >= 1);
    assert_eq!(skel.lockfiles, 1, "the fixture's Cargo.lock must be extracted");

    // A fresh, empty cargo home the fetch step fills.
    let cargo_home = tempfile::tempdir().unwrap();

    let proxy_socket_dir = tempfile::tempdir().unwrap();
    let proxy_socket = proxy_socket_dir.path().join("egress.sock");
    spawn_proxy(&proxy_socket);

    let ctx = JobContext {
        src: PathBuf::from("/unused/src"),
        target_cache: PathBuf::from("/unused/target"),
        toolchain: PathBuf::from("/home/ukv/.rustup"),
        cargo_home: cargo_home.path().to_path_buf(),
        etc: PathBuf::from("/etc"),
        scratch_size: 64 * 1024 * 1024,
    };
    let proxy = ProxyConfig {
        socket: proxy_socket,
        forwarder: PathBuf::from(FORWARDER_MOUNT),
        listen: "127.0.0.1:3128".into(),
    };

    let out = run_fetch(&ctx, skeleton.path(), proxy);
    assert!(
        out.status.success(),
        "cargo fetch --locked failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The registry was populated (a `.crate` and its extracted source).
    assert!(
        find(cargo_home.path(), ".crate").is_some(),
        "expected a downloaded .crate in the cargo home"
    );
    assert!(
        find(cargo_home.path(), ".cargo-ok").is_some(),
        "expected extracted registry source (.cargo-ok) in the cargo home"
    );

    // No repo code ran: the marker-writing build.rs was stripped and never ran,
    // and the credential provider was never consulted (fetch succeeded anon).
    assert!(
        find(dir.path(), "MARKER").is_none() && find(skeleton.path(), "MARKER").is_none(),
        "the fixture's build.rs must not run during fetch"
    );
    assert!(
        !skeleton.path().join(".cargo/config.toml").exists(),
        ".cargo/config.toml must be stripped from the skeleton"
    );
}

/// Find a file under `root` whose name **ends with** `suffix` (e.g. a
/// `libc-0.2.191.crate` or the `.cargo-ok` extraction marker).
fn find(root: &Path, suffix: &str) -> Option<PathBuf> {
    for entry in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.file_name().to_str().is_some_and(|n| n.ends_with(suffix)) {
            return Some(entry.path().to_path_buf());
        }
    }
    None
}
