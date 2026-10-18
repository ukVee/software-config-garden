//! Direct executor test (slice 006 chunk 1): fetch → run → collect in real
//! sandboxes, returning a real [`RunOutcome`] with the run step's exit code and
//! the BLAKE3-ed artifacts. Complements the wire loopback test (which proves the
//! `serve_source` wiring); this one asserts the artifacts the collect step
//! hashes. Skips loudly when bwrap / user namespaces / cargo / network are
//! unavailable — the sandbox stack is a hard precondition, never a silent pass.

use std::path::PathBuf;
use std::process::Command;

use softfig_runnerd::executor::execute;
use softfig_runnerd::{SandboxBinaries, ServeConfig};
use softfig_sandbox::JobContext;

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
    std::net::TcpStream::connect(("index.crates.io", 443)).is_ok()
}

fn skip() -> bool {
    if !bwrap_ok() || !userns_ok() {
        eprintln!("SKIPPED: bwrap or user namespaces unavailable; cannot run the executor test");
        return true;
    }
    if !cargo_ok() {
        eprintln!("SKIPPED: cargo unavailable; cannot run the executor test");
        return true;
    }
    if !network_ok() {
        eprintln!("SKIPPED: no network to index.crates.io; cannot run the executor test");
        return true;
    }
    false
}

/// The sandbox helper binaries live beside this test's own target dir:
/// `<target>/<profile>/deps/<test-binary>` → `<target>/<profile>/<name>`.
fn sandbox_bins() -> SandboxBinaries {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    SandboxBinaries::new(
        profile_dir.join("softfig-sandbox-init"),
        profile_dir.join("softfig-sandbox-forward"),
        profile_dir.join("softfig-sandbox-collect"),
    )
}

#[test]
fn execute_runs_fetch_build_collect_and_returns_artifacts() {
    if skip() {
        return;
    }

    // A tiny cargo project with a real registry dependency, so the fetch step
    // actually downloads through the proxy and the run step builds offline.
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(
        fixture.path().join("Cargo.toml"),
        "[package]\nname = \"job\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nlibc = \"0.2.191\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(fixture.path().join("src")).unwrap();
    std::fs::write(fixture.path().join("src/lib.rs"), "pub fn m() -> i32 { 42 }\n").unwrap();
    // Pin the lockfile (host cargo fetch into a throwaway home) so the fetch
    // step's `--locked` has a lockfile to honor.
    let pin = tempfile::tempdir().unwrap();
    let out = Command::new("cargo")
        .env("CARGO_HOME", pin.path())
        .arg("fetch")
        .current_dir(fixture.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "pin lockfile failed: {}", String::from_utf8_lossy(&out.stderr));

    let cargo_home = tempfile::tempdir().unwrap();
    let target_cache = tempfile::tempdir().unwrap();
    let ctx = JobContext {
        src: fixture.path().to_path_buf(),
        target_cache: target_cache.path().to_path_buf(),
        toolchain: PathBuf::from("/home/ukv/.rustup"),
        cargo_home: cargo_home.path().to_path_buf(),
        etc: PathBuf::from("/etc"),
        scratch_size: 64 * 1024 * 1024,
    };
    let serve = ServeConfig {
        egress: vec![
            "index.crates.io".into(),
            "static.crates.io".into(),
            "crates.io".into(),
            "github.com".into(),
            "codeload.github.com".into(),
        ],
        ..ServeConfig::default()
    };
    let offer = softfig_net::proto::JobOffer {
        cmd: vec!["cargo".into(), "build".into(), "--offline".into()],
        network: "none".into(),
        cache: "shared".into(),
        artifacts: vec!["Cargo.lock".into()],
        ..Default::default()
    };

    let outcome = execute(&ctx, &serve, &offer, &sandbox_bins(), None).unwrap();
    assert_eq!(outcome.exit_code, 0, "the offline build must succeed");

    assert_eq!(outcome.artifacts.len(), 1, "one declared artifact: Cargo.lock");
    let a = &outcome.artifacts[0];
    assert_eq!(a.path, "Cargo.lock");
    assert_eq!(a.blake3.len(), 64, "a BLAKE3 hex digest is 64 chars");
    let expected_size = std::fs::metadata(fixture.path().join("Cargo.lock")).unwrap().len();
    assert_eq!(a.size, expected_size, "the hashed file must be the real Cargo.lock");
}
