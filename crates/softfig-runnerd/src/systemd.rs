//! The transient-systemd-unit job wrapper (spec remote-runner §6, §7.1 layer 2,
//! §5.2 power state): one `systemd-run` unit per job, its cgroup caps + unit
//! hardening derived from the `[serve]` table (lowered by `on_battery_caps`
//! when the runner is on battery), plus the `[serve] on_battery = "refuse"`
//! reject and the payload/report types the `--run-job` mode consumes.
//!
//! **Directive set.** The cgroup caps (`CPUWeight`, `Nice`, `IOSchedulingClass`,
//! `MemoryMax`, `MemorySwapMax=0`, `TasksMax`, `RuntimeMaxSec`,
//! `KillMode=control-group`) and the hardening (`NoNewPrivileges`,
//! `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateDevices`, `PrivateTmp`)
//! are spec §7.1's table, recorded as-is. The slice-001 laptop probe — which
//! settles the exact directive set bwrap needs under the *system* manager — is
//! still parked for the human, so the hardening set is applied verbatim and any
//! deviation the loopback test surfaces is recorded in slice 006's `## Outcome`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use softfig_sandbox::JobContext;

use crate::config::ServeConfig;
use crate::error::{Error, Result};
use crate::executor::{parse_duration, parse_size, RunOutcome};

/// The default sysfs power-supply root (spec §5.2 "check the power state
/// through sysfs").
pub const POWER_SUPPLY_PATH: &str = "/sys/class/power_supply";

/// Which systemd manager a transient unit runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    /// The system manager (`systemd-run --system`) — production, where runnerd
    /// is itself a system service under the `softfig-runner` uid. Requires
    /// root; the loop never runs `sudo`, so this path is the laptop's.
    System,
    /// The user manager (`systemd-run --user`) — the loopback/test path where a
    /// system manager isn't reachable.
    User,
    /// Run the job in-process with no transient unit (tests that don't need
    /// systemd; the spec's unit is the real path, this is a test seam only).
    Direct,
}

/// `true` when the host is running on battery: there is a battery and no online
/// mains supply. `false` on AC (mains online) or when there is no battery at
/// all (a desktop, or a session host with no power source). `base` is the
/// sysfs `power_supply` dir — injectable so tests can point it at a fixture.
pub fn on_battery(base: &Path) -> Result<bool> {
    let mut mains_online = false;
    let mut has_battery = false;
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        // No power_supply dir (e.g. a container) — treat as not on battery.
        Err(_) => return Ok(false),
    };
    for entry in entries {
        let dir = match entry {
            Ok(e) => e.path(),
            Err(_) => continue,
        };
        let ty = std::fs::read_to_string(dir.join("type")).unwrap_or_default();
        match ty.trim() {
            "Mains" if supply_online(&dir) => mains_online = true,
            "Battery" => has_battery = true,
            _ => {}
        }
    }
    Ok(has_battery && !mains_online)
}

fn supply_online(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("online"))
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Whether an offer is rejected for the power state: `on_battery = "refuse"`
/// and the runner is on battery (spec §6 step 1, reason `on-battery`).
pub fn battery_reject(serve: &ServeConfig, on_battery: bool) -> Option<softfig_net::JobRejectReason> {
    if serve.on_battery == "refuse" && on_battery {
        Some(softfig_net::JobRejectReason::OnBattery)
    } else {
        None
    }
}

/// The resolved caps + hardening for one job's transient unit. `[serve]` is the
/// ceiling; `on_battery_caps` lowers the cgroup caps when the runner is on
/// battery (spec §5.2). The hardening flags are fixed by spec §7.1 layer 2 and
/// always applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caps {
    pub cpu_weight: u32,
    pub nice: i32,
    pub io_class: String,
    /// `MemoryMax`, in bytes.
    pub memory_max: u64,
    pub tasks_max: u32,
    /// `RuntimeMaxSec`, in seconds.
    pub time_max_sec: u64,
}

impl Caps {
    /// Resolve the cgroup caps from `[serve]`, lowering them when on battery.
    pub fn resolve(serve: &ServeConfig, on_battery: bool) -> Result<Self> {
        let mut cpu_weight = serve.cpu_weight;
        let mut memory_max = serve.memory_max.as_str();
        let mut tasks_max = serve.tasks_max;
        let mut time_max = serve.time_max.as_str();
        if on_battery
            && let Some(bc) = &serve.on_battery_caps
        {
            cpu_weight = bc.cpu_weight;
            memory_max = bc.memory_max.as_str();
            tasks_max = bc.tasks_max;
            time_max = bc.time_max.as_str();
        }
        Ok(Caps {
            cpu_weight,
            nice: serve.nice,
            io_class: serve.io_class.clone(),
            memory_max: parse_size(memory_max)?,
            tasks_max,
            time_max_sec: parse_duration(time_max)?,
        })
    }

    /// The `--property=` list: the cgroup caps plus spec §7.1's hardening set.
    /// Every value is emitted as a `KEY=VALUE` string for `systemd-run
    /// --property=`.
    pub fn properties(&self) -> Vec<String> {
        vec![
            format!("CPUWeight={}", self.cpu_weight),
            format!("Nice={}", self.nice),
            format!("IOSchedulingClass={}", self.io_class),
            format!("MemoryMax={}", self.memory_max),
            "MemorySwapMax=0".to_string(),
            format!("TasksMax={}", self.tasks_max),
            format!("RuntimeMaxSec={}", self.time_max_sec),
            "KillMode=control-group".to_string(),
            "NoNewPrivileges=yes".to_string(),
            "ProtectSystem=strict".to_string(),
            "ProtectHome=yes".to_string(),
            "PrivateDevices=yes".to_string(),
            "PrivateTmp=yes".to_string(),
        ]
    }
}

/// The `JobResult.exit_code` sentinel for a job killed by the time cap
/// (`timeout(1)`'s conventional 124).
pub const TIMEOUT_EXIT: i32 = 124;
/// The `JobResult.exit_code` sentinel for a job killed by the memory cap
/// (128 + SIGKILL).
pub const OOM_EXIT: i32 = 137;

/// Which resource cap killed a job (spec §6 step 9's `caps_hit`; folded into
/// the attestation in chunk 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsHit {
    /// `RuntimeMaxSec` (the time cap).
    Time,
    /// `MemoryMax` (the memory cap).
    Memory,
}

impl CapsHit {
    /// The wire/log name.
    pub fn as_str(self) -> &'static str {
        match self {
            CapsHit::Time => "time",
            CapsHit::Memory => "memory",
        }
    }

    /// The `JobResult.exit_code` sentinel for this kill.
    pub fn exit_code(self) -> i32 {
        match self {
            CapsHit::Time => TIMEOUT_EXIT,
            CapsHit::Memory => OOM_EXIT,
        }
    }
}

/// What happened to a completed transient unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitResult {
    /// The payload ran to completion and exited with this code (the job's real
    /// exit code, passed through by `systemd-run --wait`).
    Exited(i32),
    /// Killed by the `RuntimeMaxSec` time cap.
    TimedOut,
    /// Killed by the `MemoryMax` memory cap.
    OomKilled,
    /// The unit failed for some other reason (payload missing, etc.).
    Failed,
}

/// Run a payload command inside a transient unit with `caps`, under `manager`.
///
/// `unit` is the transient unit name; `payload` is the full argv; `read_write`
/// lists host paths re-opened for writing under `ProtectSystem=strict` (the
/// runner's state root — job scratch, cargo home, target cache). Returns the
/// parsed [`UnitResult`] and `systemd-run`'s exit code.
///
/// The cap kills are distinguished from a payload's own exit code by parsing
/// `systemd-run --wait`'s human-readable result line: `result: timeout` and
/// `result: oom-kill` both exit `1`, so the text is the reliable signal.
pub fn run_unit(
    manager: Manager,
    unit: &str,
    caps: &Caps,
    payload: &[String],
    read_write: &[PathBuf],
) -> Result<(UnitResult, i32)> {
    assert!(!matches!(manager, Manager::Direct), "run_unit never takes Direct");

    let mut cmd = Command::new("systemd-run");
    match manager {
        Manager::System => {
            cmd.arg("--system");
        }
        Manager::User => {
            cmd.arg("--user");
        }
        Manager::Direct => unreachable!("asserted above"),
    }
    cmd.arg("--unit").arg(unit);
    cmd.arg("--wait");
    for p in caps.properties() {
        cmd.arg(format!("--property={p}"));
    }
    for rw in read_write {
        cmd.arg(format!("--property=ReadWritePaths={}", rw.display()));
    }
    cmd.args(payload);

    let out = cmd.output().map_err(Error::Io)?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let code = out.status.code().unwrap_or(-1);

    let result = if text.contains("result: timeout") {
        UnitResult::TimedOut
    } else if text.contains("result: oom-kill") {
        UnitResult::OomKilled
    } else if out.status.success() {
        UnitResult::Exited(code)
    } else if code > 0 && code != 1 {
        // A non-zero exit that isn't a cap kill: the payload's own exit code
        // (systemd-run passes it through). `1` is ambiguous (a payload exit 1
        // looks like a unit failure), so treat 1 as the payload's code too.
        UnitResult::Exited(code)
    } else {
        UnitResult::Failed
    };

    Ok((result, code))
}

// --- Payload/report types (the `--run-job` mode) -------------------------

/// The executor-relevant subset of a job, serialized for the transient unit's
/// payload process (`softfig-runnerd --run-job <spec> <result>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    pub ctx: JobContext,
    /// `[serve] egress` — the fetch proxy's allowlist.
    pub egress: Vec<String>,
    /// `[serve] toolchains` — for the toolchain check.
    pub toolchains: Vec<String>,
    /// The offered command.
    pub cmd: Vec<String>,
    /// The offered environment (name/value pairs).
    pub env: Vec<EnvSpec>,
    /// `"none" | "egress"`.
    pub network: String,
    /// The declared artifact globs.
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSpec {
    pub name: String,
    pub value: String,
}

/// The payload's report, written to the result file. Exactly one of `outcome`
/// / `error` is set: a clean run fills `outcome`, a runner-side failure (e.g.
/// `toolchain-missing`) fills `error` with the rendered message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobReport {
    #[serde(default)]
    pub outcome: Option<RunOutcome>,
    #[serde(default)]
    pub error: Option<String>,
}

impl JobReport {
    /// A clean run.
    pub fn ok(outcome: RunOutcome) -> Self {
        Self { outcome: Some(outcome), error: None }
    }

    /// A runner-side failure.
    pub fn err(message: impl Into<String>) -> Self {
        Self { outcome: None, error: Some(message.into()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BatteryCaps;

    fn serve(on_battery: &str, caps: Option<BatteryCaps>) -> ServeConfig {
        ServeConfig {
            on_battery: on_battery.into(),
            on_battery_caps: caps,
            ..ServeConfig::default()
        }
    }

    #[test]
    fn battery_reject_only_when_refusing_and_on_battery() {
        assert_eq!(battery_reject(&serve("allow", None), true), None);
        assert_eq!(battery_reject(&serve("refuse", None), false), None);
        assert_eq!(
            battery_reject(&serve("refuse", None), true),
            Some(softfig_net::JobRejectReason::OnBattery)
        );
    }

    #[test]
    fn caps_resolve_lowers_when_on_battery() {
        let s = ServeConfig {
            cpu_weight: 20,
            memory_max: "8G".into(),
            tasks_max: 4096,
            time_max: "60m".into(),
            on_battery_caps: Some(BatteryCaps {
                cpu_weight: 10,
                memory_max: "4G".into(),
                tasks_max: 2048,
                time_max: "20m".into(),
            }),
            ..ServeConfig::default()
        };
        let ac = Caps::resolve(&s, false).unwrap();
        assert_eq!(ac.cpu_weight, 20);
        assert_eq!(ac.memory_max, 8 * 1024 * 1024 * 1024);
        assert_eq!(ac.tasks_max, 4096);
        assert_eq!(ac.time_max_sec, 3600);

        let batt = Caps::resolve(&s, true).unwrap();
        assert_eq!(batt.cpu_weight, 10);
        assert_eq!(batt.memory_max, 4 * 1024 * 1024 * 1024);
        assert_eq!(batt.tasks_max, 2048);
        assert_eq!(batt.time_max_sec, 1200);
    }

    #[test]
    fn caps_properties_map_to_systemd_directives() {
        let s = ServeConfig {
            cpu_weight: 20,
            nice: 10,
            io_class: "idle".into(),
            memory_max: "8G".into(),
            tasks_max: 4096,
            time_max: "60m".into(),
            ..ServeConfig::default()
        };
        let caps = Caps::resolve(&s, false).unwrap();
        let props = caps.properties();
        assert!(props.contains(&"CPUWeight=20".to_string()));
        assert!(props.contains(&"Nice=10".to_string()));
        assert!(props.contains(&"IOSchedulingClass=idle".to_string()));
        assert!(props.contains(&"MemoryMax=8589934592".to_string()));
        assert!(props.contains(&"MemorySwapMax=0".to_string()));
        assert!(props.contains(&"TasksMax=4096".to_string()));
        assert!(props.contains(&"RuntimeMaxSec=3600".to_string()));
        assert!(props.contains(&"KillMode=control-group".to_string()));
        assert!(props.contains(&"NoNewPrivileges=yes".to_string()));
        assert!(props.contains(&"ProtectSystem=strict".to_string()));
        assert!(props.contains(&"ProtectHome=yes".to_string()));
        assert!(props.contains(&"PrivateDevices=yes".to_string()));
        assert!(props.contains(&"PrivateTmp=yes".to_string()));
    }
}
