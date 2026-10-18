//! runnerd's two enforced config files: `serve.toml` and `accept.toml`.
//!
//! runnerd cannot read the garden (it holds no vault), so the garden's
//! `config/runner.toml` `[serve]` table is copied into its enforced copy at
//! `serve.toml` by `softfig runner apply`. The allowlist of requesters lives at
//! `accept.toml`, written through the admin socket by `grant`/`revoke`.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// The `[serve]` table (spec §5.2). Size/duration fields are kept as their
/// source strings ("8G", "60m") here; slice 006 parses them into the transient
/// unit's resource caps. `deny_unknown_fields` makes a hand-edited field a hard
/// error rather than a silently-ignored typo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    /// Whether the runner accepts jobs at all. `softfig runner enable/disable`.
    pub enabled: bool,
    /// Maximum concurrent jobs.
    pub max_jobs: u32,
    /// cgroup `CPUWeight` — yield to the owner's interactive use.
    pub cpu_weight: u32,
    /// cgroup `Nice`.
    pub nice: i32,
    /// cgroup `IOSchedulingClass` ("idle", "best-effort", …).
    pub io_class: String,
    /// Hard `MemoryMax` ("8G"): a runaway job is killed, never the laptop.
    pub memory_max: String,
    /// cgroup `TasksMax`.
    pub tasks_max: u32,
    /// Per-job `RuntimeMaxSec` ("60m").
    pub time_max: String,
    /// Scratch space bound ("20G").
    pub scratch_max: String,
    /// LRU cache bound across repo keys ("60G").
    pub cache_max: String,
    /// "allow" | "refuse" — on battery, lower caps kick in.
    pub on_battery: String,
    /// Lower caps applied while on battery.
    #[serde(default)]
    pub on_battery_caps: Option<BatteryCaps>,
    /// Toolchains the runner can serve ("rust", …).
    pub toolchains: Vec<String>,
    /// Egress allowlist hostnames for the fetch step's proxy.
    pub egress: Vec<String>,
}

/// The lower caps applied when running on battery (`on_battery = "allow"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatteryCaps {
    pub cpu_weight: u32,
    pub memory_max: String,
    pub tasks_max: u32,
    pub time_max: String,
}

impl Default for ServeConfig {
    /// A fresh, disabled runner: `enabled = false` until the owner runs
    /// `softfig runner apply` (which pushes the garden's `[serve]` table) or
    /// `softfig runner enable`. The caps are the spec §5.2 defaults, inert
    /// while disabled. This exists so a freshly-installed state root has a
    /// valid (refusing) `serve.toml` before the first `apply`.
    fn default() -> Self {
        Self {
            enabled: false,
            max_jobs: 1,
            cpu_weight: 20,
            nice: 10,
            io_class: "idle".into(),
            memory_max: "8G".into(),
            tasks_max: 4096,
            time_max: "60m".into(),
            scratch_max: "20G".into(),
            cache_max: "60G".into(),
            on_battery: "allow".into(),
            on_battery_caps: None,
            toolchains: Vec::new(),
            egress: Vec::new(),
        }
    }
}

impl ServeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// One granted requester in `accept.toml`. `device_id` and `transport_pubkey`
/// are lowercase hex, read from the ring by `grant` and handed over the admin
/// socket; `name` is display-only, not trusted for anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedPeer {
    /// The requester's Ed25519 identity public key (lowercase hex).
    pub device_id: String,
    /// The requester's X25519 transport static (lowercase hex).
    pub transport_pubkey: String,
    /// Human-readable device name.
    pub name: String,
}

/// The runner's allowlist of requesters (spec §3.2, two-sided consent).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptConfig {
    #[serde(default)]
    pub peer: Vec<AcceptedPeer>,
}

impl AcceptConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Whether `device_id` (hex) is already granted.
    pub fn contains(&self, device_id: &str) -> bool {
        self.peer.iter().any(|p| p.device_id == device_id)
    }

    /// Add or refresh a granted peer. Returns `true` if it was newly added
    /// (false if it was already present and just refreshed).
    pub fn grant(&mut self, peer: AcceptedPeer) -> bool {
        if let Some(existing) = self.peer.iter_mut().find(|p| p.device_id == peer.device_id) {
            *existing = peer;
            false
        } else {
            self.peer.push(peer);
            true
        }
    }

    /// Remove a peer by `device_id` (hex). Returns `true` if it was present.
    pub fn revoke(&mut self, device_id: &str) -> bool {
        let before = self.peer.len();
        self.peer.retain(|p| p.device_id != device_id);
        self.peer.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_config_round_trips() {
        let cfg = ServeConfig {
            enabled: true,
            max_jobs: 1,
            cpu_weight: 20,
            nice: 10,
            io_class: "idle".into(),
            memory_max: "8G".into(),
            tasks_max: 4096,
            time_max: "60m".into(),
            scratch_max: "20G".into(),
            cache_max: "60G".into(),
            on_battery: "allow".into(),
            on_battery_caps: Some(BatteryCaps {
                cpu_weight: 10,
                memory_max: "4G".into(),
                tasks_max: 2048,
                time_max: "20m".into(),
            }),
            toolchains: vec!["rust".into()],
            egress: vec!["index.crates.io".into()],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serve.toml");
        cfg.save(&path).unwrap();
        assert_eq!(ServeConfig::load(&path).unwrap(), cfg);
    }

    #[test]
    fn serve_config_rejects_unknown_field() {
        let raw = r#"
enabled = true
max_jobs = 1
cpu_weight = 20
nice = 10
io_class = "idle"
memory_max = "8G"
tasks_max = 4096
time_max = "60m"
scratch_max = "20G"
cache_max = "60G"
on_battery = "allow"
toolchains = ["rust"]
egress = []
bogus_field = "nope"
"#;
        assert!(toml::from_str::<ServeConfig>(raw).is_err());
    }

    #[test]
    fn accept_grant_revoke() {
        let mut cfg = AcceptConfig::default();
        let peer = |id: &str| AcceptedPeer {
            device_id: id.into(),
            transport_pubkey: "ab".repeat(16),
            name: "tablet".into(),
        };

        assert!(cfg.grant(peer("aa")));
        assert!(!cfg.grant(peer("aa"))); // refresh, not a new add
        assert!(cfg.grant(peer("bb")));
        assert!(cfg.contains("aa"));
        assert!(cfg.contains("bb"));

        assert!(cfg.revoke("aa"));
        assert!(!cfg.revoke("aa")); // already gone
        assert!(!cfg.contains("aa"));
        assert!(cfg.contains("bb"));
    }

    #[test]
    fn accept_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AcceptConfig::load(&dir.path().join("accept.toml")).unwrap();
        assert!(cfg.peer.is_empty());
    }
}
