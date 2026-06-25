//! `keeper.toml` — per-garden config consumed by the daemon and the
//! `softfig migrate` CLI subcommands.
//!
//! Lives at `<garden_root>/.softfig/keeper.toml` (M1c-compat layout) so
//! the file can be discovered without first knowing the state-root
//! relocation. After a successful `softfig migrate prepare`, the same
//! file is written into the new state root so the daemon can read it
//! once the FUSE mount is up.
//!
//! Schema for v1 (open question #1 lean — top-level field):
//!
//! ```toml
//! state_root = "/home/.../<repo_id>/"
//! ```
//!
//! Absent file or absent `state_root` field both mean "M1c-compat
//! layout, no FUSE."

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const KEEPER_TOML: &str = "keeper.toml";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KeeperToml {
    /// Absolute path to the directory containing the on-disk `.softfig/`
    /// tree. When set, the daemon runs in M2a (FUSE) mode and mounts the
    /// garden root as a FUSE filesystem.
    #[serde(default)]
    pub state_root: Option<PathBuf>,
    /// M2b: `softfig reveal` re-prompt policy. Absent table defaults to
    /// `idle_seconds = 0` (always re-prompt).
    #[serde(default)]
    pub reveal: RevealToml,
    /// M5a-4: cross-device networking (the `softfig-net` host). Absent table
    /// defaults to `enabled = true`, listening on `0.0.0.0:9100`.
    #[serde(default)]
    pub net: NetToml,
    /// M5a-4: relay configuration. The hosting half (`enabled`/`listen`) makes
    /// this device an always-on blind relay; the client half
    /// (`endpoint`/`static_key`) tells a NAT'd device how to reach one. Absent
    /// table = no relay hosted, no relay client configured.
    #[serde(default)]
    pub relay: RelayToml,
    /// M5b: replication. The static host opt-in (`host = true`) makes this
    /// device store zero-knowledge ciphertext backups for ring members the
    /// owner has granted it. The owner-side per-peer grant list lives in a
    /// separate, runtime-mutable `replica.toml` (managed by `replica_grant` /
    /// `replica_revoke`), not here — same network-state-beside-the-vault posture
    /// as `peers.toml`. Absent table = not a backup host.
    #[serde(default)]
    pub replica: ReplicaToml,
    /// Growlight relock: the opt-in that lets the autonomous loop resume an
    /// already-unlocked vault across an unattended daemon restart. Off by
    /// default; the daemon refuses to mint a relock token unless
    /// `allow_relock = true`. Because `keeper.toml` is not a garden file and
    /// Vault ops are never MCP-exposed, the loop physically cannot enable its
    /// own relock — only the human can. Absent table = relock disabled.
    #[serde(default)]
    pub growlight: GrowlightToml,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RevealToml {
    /// Number of seconds after a successful reveal during which the
    /// next reveal may skip the master-password prompt. `0` = always
    /// re-prompt.
    #[serde(default)]
    pub idle_seconds: u64,
}

/// `[net]` — the device's own `softfig-net` host (inbound Noise listener +
/// mDNS advertisement).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetToml {
    /// Whether to host the networking instance on unlock. Default `true`.
    #[serde(default = "default_net_enabled")]
    pub enabled: bool,
    /// Inbound Noise listener bind address (`host:port`); also the port mDNS
    /// advertises. Default `0.0.0.0:9100`.
    #[serde(default = "default_net_listen")]
    pub listen: String,
    /// Human-readable device name advertised in the handshake / mDNS. Defaults
    /// to the system hostname when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// Pairing-UX Slice A: publish the device name in the mDNS TXT `nm` field
    /// so peers can pick it from a list by name. Default `true`; set `false`
    /// for a fingerprint-only broadcast (privacy fall-back). The name is a
    /// convenience hint only — pairing still authenticates via the SAS.
    #[serde(default = "default_advertise_name")]
    pub advertise_name: bool,
}

impl Default for NetToml {
    fn default() -> Self {
        Self {
            enabled: default_net_enabled(),
            listen: default_net_listen(),
            device_name: None,
            advertise_name: default_advertise_name(),
        }
    }
}

fn default_net_enabled() -> bool {
    true
}

fn default_advertise_name() -> bool {
    true
}

fn default_net_listen() -> String {
    "0.0.0.0:9100".to_string()
}

/// `[relay]` — relay hosting (`enabled`/`listen`) and relay-client reach
/// (`endpoint`/`static_key`). The two halves are independent: the always-on
/// server sets the hosting half; a NAT'd device sets the client half.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayToml {
    /// Host a blind relay on this device. Default `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Relay listener bind address (`host:port`). Required when `enabled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// `host:port` of a relay this device reaches as a client (off-LAN
    /// fallback). Consumed by the M5b reconnect path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The relay's X25519 transport public key (lowercase hex), learned at
    /// pairing — keys the outer control session to the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_key: Option<String>,
}

/// `[replica]` — M5b backup-host opt-in. Just the static host flag; the
/// owner-side `push_to` grant list is runtime state in `replica.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReplicaToml {
    /// Store ciphertext backups for granted ring members. Default `false`.
    /// Toggled in `keeper.toml` (a static opt-in, same posture as `[relay]`),
    /// not via a subcommand.
    #[serde(default)]
    pub host: bool,
}

/// `[growlight]` — the growlight policy table. keeperd owns exactly one key here,
/// `allow_relock` (a deliberate, security-relevant toggle the human sets by hand,
/// never the agent).
///
/// The `[growlight]` table is **shared with growlightd**, which reads its own live
/// fleet keys from the very same table (`fleet_enabled`, `claude_bin`, `prompt`,
/// `[[growlight.fleet]]` — see `softfig-growlightd`'s `fleet.rs`). So this struct
/// must NOT `deny_unknown_fields`: it has to parse-and-ignore the fleet keys,
/// exactly as growlightd's own parser already tolerates keeperd's `allow_relock`.
/// Without this, arming the fleet (`fleet_enabled = true`) crash-loops keeperd on
/// boot. Closed-world validation still applies at the top-level [`KeeperToml`], so
/// a stray *top-level* key — or a misspelled table — still fails the boot; only
/// the shared `[growlight]` table is open. A misspelled `allow_relock` is ignored
/// and fails safe (relock stays off).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrowlightToml {
    /// Permit the relock token (resume an already-unlocked vault across an
    /// unattended daemon restart). Default `false` — the daemon refuses
    /// `relock_mint` unless this is `true`.
    #[serde(default)]
    pub allow_relock: bool,
}

impl KeeperToml {
    /// Load `keeper.toml` from the location next to a `.softfig/`. Both
    /// "file absent" and "empty file" return [`KeeperToml::default()`]
    /// (i.e., M1c-compat). Other parse errors propagate.
    pub fn load(softfig_parent: &Path) -> std::io::Result<Self> {
        let path = softfig_parent.join(".softfig").join(KEEPER_TOML);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)?;
        toml::from_str(&raw).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }

    /// Write `keeper.toml` next to a `.softfig/`. Creates the parent dir
    /// if absent.
    pub fn store(&self, softfig_parent: &Path) -> std::io::Result<()> {
        let dir = softfig_parent.join(".softfig");
        fs::create_dir_all(&dir)?;
        let path = dir.join(KEEPER_TOML);
        let raw = toml::to_string_pretty(self).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        fs::write(path, raw)
    }
}

/// Directory inside the garden holding the in-garden config files
/// (`config/keeper.toml`, and — Slice 2 — `config/peers.toml`).
pub const CONFIG_DIR: &str = "config";

/// `config/keeper.toml` — the in-garden, encrypted, versioned, M5b-backed,
/// hand-editable daemon config. Holds exactly the settings consumed *after*
/// unlock (`[net]`/`[relay]`/`[replica]`/`[reveal]`). The bootstrap `state_root`
/// (read before unlock) and the security opt-in `[growlight] allow_relock`
/// (kept off the agent-writable garden surface) stay in the plaintext
/// `.softfig/keeper.toml` pointer instead. See
/// `journal/decisions/decision-softfig-config-in-garden.md`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GardenConfig {
    #[serde(default)]
    pub reveal: RevealToml,
    #[serde(default)]
    pub net: NetToml,
    #[serde(default)]
    pub relay: RelayToml,
    #[serde(default)]
    pub replica: ReplicaToml,
}

impl GardenConfig {
    /// Absolute path of the in-garden config for a garden root.
    pub fn path(garden_root: &Path) -> PathBuf {
        garden_root.join(CONFIG_DIR).join(KEEPER_TOML)
    }

    /// Load `<garden_root>/config/keeper.toml`. An absent file returns
    /// `Ok(None)` so the caller keeps the pointer's boot-time values — this is
    /// what makes a not-yet-migrated garden keep working unchanged. A present
    /// but unparseable file propagates as an error.
    pub fn load(garden_root: &Path) -> std::io::Result<Option<Self>> {
        let path = Self::path(garden_root);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path)?;
        let cfg = toml::from_str(&raw).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })?;
        Ok(Some(cfg))
    }

    /// Serialize to the TOML written into the garden (used by onboard's seed and
    /// the `migrate config` writer).
    pub fn to_toml(&self) -> std::io::Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// The post-unlock policy half of a pointer [`KeeperToml`]. `migrate config`
    /// uses this to lift any policy a legacy pointer still carries into the
    /// garden; for a born-minimal pointer it yields the defaults.
    pub fn from_keeper(k: &KeeperToml) -> Self {
        Self {
            reveal: k.reveal.clone(),
            net: k.net.clone(),
            relay: k.relay.clone(),
            replica: k.replica.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_returns_default() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KeeperToml::load(tmp.path()).unwrap();
        assert!(cfg.state_root.is_none());
    }

    #[test]
    fn round_trip_state_root() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KeeperToml {
            state_root: Some(PathBuf::from("/var/lib/softfig/abc")),
            ..Default::default()
        };
        cfg.store(tmp.path()).unwrap();
        let back = KeeperToml::load(tmp.path()).unwrap();
        assert_eq!(back.state_root, cfg.state_root);
        assert_eq!(back.reveal.idle_seconds, 0);
    }

    #[test]
    fn net_defaults_when_absent() {
        // A keeper.toml with only state_root → net enabled, default listen.
        let tmp = tempfile::tempdir().unwrap();
        let softfig = tmp.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join(KEEPER_TOML),
            "state_root = \"/var/lib/softfig/abc\"\n",
        )
        .unwrap();
        let cfg = KeeperToml::load(tmp.path()).unwrap();
        assert!(cfg.net.enabled);
        assert_eq!(cfg.net.listen, "0.0.0.0:9100");
        assert!(cfg.net.device_name.is_none());
        assert!(cfg.net.advertise_name, "advertise_name defaults on");
        assert!(!cfg.relay.enabled);
    }

    #[test]
    fn advertise_name_can_be_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let softfig = tmp.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join(KEEPER_TOML),
            "state_root = \"/s\"\n\n[net]\nadvertise_name = false\n",
        )
        .unwrap();
        let cfg = KeeperToml::load(tmp.path()).unwrap();
        assert!(!cfg.net.advertise_name);
        // Other [net] fields still take their defaults.
        assert!(cfg.net.enabled);
        assert_eq!(cfg.net.listen, "0.0.0.0:9100");
    }

    #[test]
    fn growlight_relock_defaults_off_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        // Absent table → relock disabled.
        let cfg = KeeperToml::default();
        assert!(!cfg.growlight.allow_relock);

        // Explicit opt-in round-trips through store/load.
        let softfig = tmp.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join(KEEPER_TOML),
            "state_root = \"/s\"\n\n[growlight]\nallow_relock = true\n",
        )
        .unwrap();
        let back = KeeperToml::load(tmp.path()).unwrap();
        assert!(back.growlight.allow_relock, "explicit opt-in parses");
    }

    #[test]
    fn growlight_tolerates_growlightd_fleet_keys_in_the_shared_table() {
        // The `[growlight]` table is shared with growlightd, which reads
        // `fleet_enabled`/`claude_bin`/`prompt`/`[[growlight.fleet]]` from it.
        // keeperd must parse-and-ignore those (not crash-boot) while still
        // honoring its own `allow_relock`. Regression for the post-merge
        // crash-loop where arming the fleet wedged keeperd on boot.
        let tmp = tempfile::tempdir().unwrap();
        let softfig = tmp.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join(KEEPER_TOML),
            "state_root = \"/s\"\n\n\
             [growlight]\n\
             allow_relock = true\n\
             fleet_enabled = true\n\
             claude_bin = \"/usr/bin/claude\"\n\
             prompt = \"go\"\n\
             [[growlight.fleet]]\n\
             agent = \"v\"\n",
        )
        .unwrap();
        let back = KeeperToml::load(tmp.path()).unwrap();
        // keeperd's own key still parses; growlightd's fleet keys are ignored,
        // not rejected.
        assert!(
            back.growlight.allow_relock,
            "allow_relock honored alongside the fleet keys"
        );
    }

    #[test]
    fn top_level_unknown_key_still_crash_boots() {
        // The shared-table relaxation is scoped to `[growlight]` only — the
        // top-level pointer stays closed-world so a typo'd key still fails loud.
        let tmp = tempfile::tempdir().unwrap();
        let softfig = tmp.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join(KEEPER_TOML),
            "state_root = \"/s\"\nbogus_top_level = true\n",
        )
        .unwrap();
        assert!(
            KeeperToml::load(tmp.path()).is_err(),
            "a stray top-level key must still fail the boot"
        );
    }

    #[test]
    fn parses_net_and_relay_blocks() {
        let tmp = tempfile::tempdir().unwrap();
        let softfig = tmp.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join(KEEPER_TOML),
            "state_root = \"/s\"\n\n\
             [net]\nenabled = true\nlisten = \"0.0.0.0:9300\"\ndevice_name = \"tablet\"\n\n\
             [relay]\nenabled = true\nlisten = \"0.0.0.0:9301\"\n\
             endpoint = \"relay.example:9301\"\nstatic_key = \"abcd\"\n",
        )
        .unwrap();
        let cfg = KeeperToml::load(tmp.path()).unwrap();
        assert_eq!(cfg.net.listen, "0.0.0.0:9300");
        assert_eq!(cfg.net.device_name.as_deref(), Some("tablet"));
        assert!(cfg.relay.enabled);
        assert_eq!(cfg.relay.listen.as_deref(), Some("0.0.0.0:9301"));
        assert_eq!(cfg.relay.endpoint.as_deref(), Some("relay.example:9301"));
        assert_eq!(cfg.relay.static_key.as_deref(), Some("abcd"));
    }

    // ── GardenConfig (config/keeper.toml) ──────────────────────────────────

    #[test]
    fn garden_config_absent_is_none() {
        // A garden with no config/keeper.toml → None, so the caller keeps the
        // pointer's boot values (the non-migrated path).
        let tmp = tempfile::tempdir().unwrap();
        assert!(GardenConfig::load(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn garden_config_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = GardenConfig {
            net: NetToml {
                listen: "0.0.0.0:9300".into(),
                device_name: Some("tablet".into()),
                advertise_name: false,
                ..NetToml::default()
            },
            relay: RelayToml {
                enabled: true,
                listen: Some("0.0.0.0:9301".into()),
                ..RelayToml::default()
            },
            replica: ReplicaToml { host: true },
            reveal: RevealToml { idle_seconds: 42 },
        };
        let path = GardenConfig::path(tmp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, cfg.to_toml().unwrap()).unwrap();

        let back = GardenConfig::load(tmp.path()).unwrap().unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn garden_config_from_minimal_pointer_is_defaults() {
        // A born-minimal pointer (just state_root) yields the default policy —
        // what `migrate config` seeds into our garden.
        let pointer = KeeperToml {
            state_root: Some(PathBuf::from("/s")),
            ..Default::default()
        };
        let gc = GardenConfig::from_keeper(&pointer);
        assert_eq!(gc, GardenConfig::default());
        // The serialized seed parses back to the same thing.
        let tmp = tempfile::tempdir().unwrap();
        let path = GardenConfig::path(tmp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, gc.to_toml().unwrap()).unwrap();
        assert_eq!(GardenConfig::load(tmp.path()).unwrap().unwrap(), gc);
    }

    #[test]
    fn garden_config_lifts_pointer_policy() {
        // A legacy pointer carrying policy → from_keeper lifts exactly the
        // post-unlock fields (net/relay/replica/reveal), nothing else.
        let pointer = KeeperToml {
            state_root: Some(PathBuf::from("/s")),
            reveal: RevealToml { idle_seconds: 7 },
            relay: RelayToml {
                enabled: true,
                ..RelayToml::default()
            },
            growlight: GrowlightToml { allow_relock: true },
            ..Default::default()
        };
        let gc = GardenConfig::from_keeper(&pointer);
        assert_eq!(gc.reveal.idle_seconds, 7);
        assert!(gc.relay.enabled);
        // growlight is deliberately NOT part of GardenConfig — it stays in the
        // pointer. (GardenConfig has no such field; this just documents intent.)
    }

    #[test]
    fn garden_config_rejects_unknown_field() {
        let tmp = tempfile::tempdir().unwrap();
        let path = GardenConfig::path(tmp.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        // `state_root` belongs in the pointer, not the garden config — a stray
        // one must be rejected, not silently ignored.
        fs::write(&path, "state_root = \"/x\"\n").unwrap();
        assert!(GardenConfig::load(tmp.path()).is_err());
    }
}
