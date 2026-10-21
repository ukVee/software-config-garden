//! M11: the sandbox sees the runner's minimal `/etc`, never the host's. A file
//! that exists only in the host etc must be invisible to the job, while the
//! stub `passwd` is present. Skips loudly when bwrap / user namespaces are
//! unavailable — the sandbox stack is a hard precondition, never a silent pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use softfig_runnerd::etc::build_minimal_etc;
use softfig_runnerd::executor::execute;
use softfig_runnerd::{SandboxBinaries, ServeConfig};
use softfig_sandbox::JobContext;

fn sandbox_available() -> bool {
    let bwrap =
        Command::new("bwrap").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    let userns =
        Command::new("unshare").args(["-Ur", "true"]).status().map(|s| s.success()).unwrap_or(false);
    bwrap && userns
}

fn sandbox_bins() -> SandboxBinaries {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    SandboxBinaries::new(
        profile_dir.join("softfig-sandbox-init"),
        profile_dir.join("softfig-sandbox-forward"),
        profile_dir.join("softfig-sandbox-collect"),
    )
}

fn run_in_sandbox(etc: &Path, script: &str) -> i32 {
    let work = tempfile::tempdir().unwrap();
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let ctx = JobContext {
        src: work.path().to_path_buf(),
        target_cache: dirs[0].path().to_path_buf(),
        toolchain: dirs[1].path().to_path_buf(),
        cargo_home: dirs[2].path().to_path_buf(),
        etc: etc.to_path_buf(),
        scratch_size: 16 * 1024 * 1024,
    };
    let offer = softfig_net::proto::JobOffer {
        cmd: vec!["sh".into(), "-c".into(), script.into()],
        network: "none".into(),
        cache: "fresh".into(),
        ..Default::default()
    };
    execute(&ctx, &ServeConfig::default(), &offer, &sandbox_bins(), None).unwrap().exit_code
}

#[test]
fn unlisted_host_etc_files_are_not_visible_in_the_sandbox() {
    if !sandbox_available() {
        eprintln!("SKIPPED: bwrap or user namespaces unavailable; cannot run the minimal-etc test");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let host_etc: PathBuf = tmp.path().join("host-etc");
    std::fs::create_dir_all(&host_etc).unwrap();
    std::fs::write(host_etc.join("host-secret"), "do not leak\n").unwrap();
    let etc = tmp.path().join("etc");
    build_minimal_etc(&etc, &host_etc, false).unwrap();

    let code = run_in_sandbox(&etc, "test -e /etc/passwd && test ! -e /etc/host-secret");
    assert_eq!(code, 0, "the stub passwd must be visible and the host-only file must not be");
}
