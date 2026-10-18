//! The transient-systemd-unit wrapper (slice 006 chunk 2): the `[serve]` caps →
//! `systemd-run` directives, the power-state check, and the `--run-job` payload
//! that runs the executor inside the unit.
//!
//! The real systemd tests skip **loudly** when `systemd-run --user` can't run a
//! unit (the spec's "never pass silently" rule) — the sandbox stack is a hard
//! precondition here, but systemd is the runner's own layer and must be present
//! for the unit path at all.

use std::path::{Path, PathBuf};
use std::process::Command;

use softfig_runnerd::{
    on_battery, run_unit, Caps, Manager, UnitResult,
};

/// `true` when a `systemd-run --user` unit can't run, after a loud skip.
fn systemd_skip() -> bool {
    let ok = Command::new("systemd-run")
        .args(["--user", "--wait", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIPPED: systemd-run --user cannot run a unit; cannot test the transient-unit path");
    }
    !ok
}

/// The built `softfig-runnerd` binary, beside this test's target dir.
fn runnerd_bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join("softfig-runnerd")
}

/// Copy the built runnerd binary to a non-`/tmp` location: the unit's
/// `PrivateTmp` hides `/tmp` (where the build target dir lives), so the payload
/// binary must be staged somewhere the unit can see — here, the caller's
/// `/dev/shm` scratch. `fs::copy` preserves the mode, but be explicit.
fn stage_runnerd(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let src = runnerd_bin();
    assert!(src.exists(), "build softfig-runnerd first: {}", src.display());
    let dst = dir.join("softfig-runnerd");
    std::fs::copy(&src, &dst).unwrap();
    let mut perms = std::fs::metadata(&dst).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&dst, perms).unwrap();
    dst
}

/// A scratch dir under `/dev/shm` (tmpfs), **not** `/tmp`: the unit's
/// `PrivateTmp` hides `/tmp` from its payload, so job scratch must live
/// elsewhere. Mirrors the production layout (`/var/lib/softfig-runner`).
fn shm_scratch(name: &str) -> PathBuf {
    let d = PathBuf::from("/dev/shm").join(format!("softfig-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_supply(dir: &Path, ty: &str, online: Option<&str>) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("type"), ty).unwrap();
    if let Some(o) = online {
        std::fs::write(dir.join("online"), o).unwrap();
    }
}

#[test]
fn on_battery_reads_sysfs_supplies() {
    let base = tempfile::tempdir().unwrap();

    // On AC: mains online.
    write_supply(&base.path().join("AC0"), "Mains", Some("1"));
    write_supply(&base.path().join("BAT0"), "Battery", None);
    assert!(!on_battery(base.path()).unwrap());

    // On battery: mains offline, battery present.
    std::fs::write(base.path().join("AC0/online"), "0").unwrap();
    assert!(on_battery(base.path()).unwrap());

    // A desktop (no mains, no battery) is not "on battery".
    let empty = tempfile::tempdir().unwrap();
    assert!(!on_battery(empty.path()).unwrap());
}

/// The caps are applied to the transient unit and verifiable via
/// `systemctl show` while the job runs (spec §7.1 layer 2 + the loopback
/// "verify the caps" done-when).
#[test]
fn run_unit_applies_caps_and_reports_exit() {
    if systemd_skip() {
        return;
    }
    let serve = softfig_runnerd::ServeConfig {
        cpu_weight: 25,
        nice: 10,
        io_class: "idle".into(),
        memory_max: "64M".into(),
        tasks_max: 2048,
        time_max: "30s".into(),
        ..Default::default()
    };
    let caps = Caps::resolve(&serve, false).unwrap();
    let unit = format!("softfig-test-caps-{}", std::process::id());
    let payload = vec!["sleep".to_string(), "3".to_string()];

    // run_unit blocks on --wait; drive it from a thread and poll systemctl show
    // while the unit is live.
    let (unit2, caps2) = (unit.clone(), caps.clone());
    let handle = std::thread::spawn(move || {
        run_unit(Manager::User, &unit2, &caps2, &payload, &[]).unwrap()
    });

    let mut saw = None;
    for _ in 0..60 {
        let out = Command::new("systemctl")
            .args([
                "--user", "show", &unit,
                "--property=MemoryMax",
                "--property=CPUWeight",
                "--property=TasksMax",
                "--property=NoNewPrivileges",
                "--property=ProtectSystem",
                "--property=ProtectHome",
                "--property=PrivateDevices",
                "--property=PrivateTmp",
                "--property=KillMode",
                "--property=MemorySwapMax",
            ])
            .output();
        if let Ok(o) = out {
            let t = String::from_utf8_lossy(&o.stdout).to_string();
            if t.contains("MemoryMax=67108864") {
                saw = Some(t);
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let (result, _code) = handle.join().unwrap();
    assert_eq!(result, UnitResult::Exited(0));

    let t = saw.expect("systemctl show should observe the unit's properties while it runs");
    assert!(t.contains("MemoryMax=67108864"), "MemoryMax: {t}");
    assert!(t.contains("CPUWeight=25"), "CPUWeight: {t}");
    assert!(t.contains("TasksMax=2048"), "TasksMax: {t}");
    assert!(t.contains("NoNewPrivileges=yes"), "NoNewPrivileges: {t}");
    assert!(t.contains("ProtectSystem=strict"), "ProtectSystem: {t}");
    assert!(t.contains("ProtectHome=yes"), "ProtectHome: {t}");
    assert!(t.contains("PrivateDevices=yes"), "PrivateDevices: {t}");
    assert!(t.contains("PrivateTmp=yes"), "PrivateTmp: {t}");
    assert!(t.contains("KillMode=control-group"), "KillMode: {t}");
    assert!(t.contains("MemorySwapMax=0"), "MemorySwapMax: {t}");
}

/// A runaway job is killed by the time cap (`RuntimeMaxSec`) and the reason is
/// reported as [`UnitResult::TimedOut`].
#[test]
fn runaway_job_is_killed_by_the_time_cap() {
    if systemd_skip() {
        return;
    }
    let serve = softfig_runnerd::ServeConfig {
        time_max: "2s".into(),
        ..Default::default()
    };
    let caps = Caps::resolve(&serve, false).unwrap();
    let unit = format!("softfig-test-time-{}", std::process::id());
    let payload = vec!["sleep".to_string(), "30".to_string()];
    let (result, _code) = run_unit(Manager::User, &unit, &caps, &payload, &[]).unwrap();
    assert_eq!(result, UnitResult::TimedOut, "a 30s job under a 2s time cap must be killed");
}

/// A runaway job is killed by the memory cap (`MemoryMax` + `MemorySwapMax=0`)
/// and the reason is reported as [`UnitResult::OomKilled`].
#[test]
fn runaway_job_is_killed_by_the_memory_cap() {
    if systemd_skip() {
        return;
    }
    if Command::new("python3").arg("--version").output().map(|o| !o.status.success()).unwrap_or(true) {
        eprintln!("SKIPPED: python3 unavailable; cannot run the memory-cap allocator");
        return;
    }
    let serve = softfig_runnerd::ServeConfig {
        memory_max: "64M".into(),
        ..Default::default()
    };
    let caps = Caps::resolve(&serve, false).unwrap();
    let unit = format!("softfig-test-mem-{}", std::process::id());
    // Allocate 200 MiB under a 64 MiB cap (no swap): the cgroup OOM-killer
    // must kill the job, never the laptop.
    let payload = vec![
        "sh".to_string(),
        "-c".to_string(),
        "python3 -c 'import time; a=bytearray(200*1024*1024); time.sleep(10)'".to_string(),
    ];
    let (result, _code) = run_unit(Manager::User, &unit, &caps, &payload, &[]).unwrap();
    assert_eq!(result, UnitResult::OomKilled, "a 200 MiB allocation under a 64 MiB cap must be oom-killed");
}

/// The `--run-job` payload runs the real executor inside the unit and writes a
/// report the runner reads back. A no-manifest tree with an empty command runs
/// the full fetch(skip) → run(skip) → collect(skip) sequence with no bwrap,
/// cargo or network, so this proves the unit + spec/report round-trip on its
/// own (the bwrap/cargo steps are proven by the Direct loopback test).
#[test]
fn payload_runs_executor_through_the_unit() {
    if systemd_skip() {
        return;
    }
    let scratch = shm_scratch("payload");
    let runnerd = stage_runnerd(&scratch);
    let src = scratch.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f.txt"), "hello\n").unwrap();
    let target = scratch.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let cargo_home = scratch.join("cargo");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let rustup = scratch.join("rustup");
    std::fs::create_dir_all(&rustup).unwrap();

    let ctx = softfig_sandbox::JobContext {
        src,
        target_cache: target,
        toolchain: rustup,
        cargo_home,
        etc: PathBuf::from("/etc"),
        scratch_size: 64 * 1024 * 1024,
    };
    let spec = softfig_runnerd::JobSpec {
        ctx,
        egress: vec![],
        toolchains: vec!["rust".into()],
        cmd: vec![],
        env: vec![],
        network: "none".into(),
        artifacts: vec![],
    };
    let spec_path = scratch.join("spec.json");
    let result_path = scratch.join("result.json");
    std::fs::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();

    let serve = softfig_runnerd::ServeConfig {
        memory_max: "64M".into(),
        time_max: "30s".into(),
        ..Default::default()
    };
    let caps = Caps::resolve(&serve, false).unwrap();
    let unit = format!("softfig-test-payload-{}", std::process::id());
    let payload = vec![
        runnerd.display().to_string(),
        "--run-job".to_string(),
        spec_path.display().to_string(),
        result_path.display().to_string(),
    ];
    let (result, _code) = run_unit(Manager::User, &unit, &caps, &payload, std::slice::from_ref(&scratch)).unwrap();
    assert_eq!(result, UnitResult::Exited(0), "the payload must exit 0 for an empty job");

    let report: softfig_runnerd::JobReport =
        serde_json::from_slice(&std::fs::read(&result_path).unwrap()).unwrap();
    assert!(report.error.is_none(), "unexpected payload error: {:?}", report.error);
    let outcome = report.outcome.expect("a clean run fills the outcome");
    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.artifacts.is_empty());

    let _ = std::fs::remove_dir_all(&scratch);
}
