//! Daemon configuration: garden root + (optional) relocated state root +
//! socket path.

use std::path::{Path, PathBuf};

use crate::keeper_toml::{GardenConfig, GrowlightToml, KeeperToml, NetToml, RelayToml, ReplicaToml};

#[derive(Debug, Clone)]
pub struct KeeperConfig {
    pub garden_root: PathBuf,
    /// When `Some(state_root)`, the daemon runs in M2a (FUSE) mode:
    /// `.softfig/` lives at `state_root/.softfig/` and the garden root
    /// is the FUSE mount path. When `None`, the daemon runs in
    /// M1c-compat mode: `.softfig/` lives at `garden_root/.softfig/`.
    pub state_root: Option<PathBuf>,
    pub socket_path: PathBuf,
    /// When true, the watcher thread is started after `unlock`. Tests
    /// disable this to keep the runtime predictable.
    pub enable_watcher: bool,
    /// When true (M2a mode only), the daemon mounts a FUSE filesystem
    /// over `garden_root` after the unlock transition. Tests disable
    /// this to exercise the daemon's M2a wiring without the real mount.
    pub enable_fuse: bool,
    /// M5a-4: when true (and `[net] enabled`), the daemon hosts the
    /// `softfig-net` instance (inbound listener + mDNS + optional relay)
    /// after `unlock`. Tests disable this so the pairing *verbs* can be
    /// exercised without binding real sockets / multicast.
    pub enable_net: bool,
    /// M2b: `softfig reveal` re-prompt policy.
    pub reveal: RevealConfig,
    /// M5a-4: cross-device networking config from `[net]`.
    pub net: NetConfig,
    /// M5a-4: relay config from `[relay]`.
    pub relay: RelayConfig,
    /// M5b: replication config from `[replica]` (the static host opt-in).
    pub replica: ReplicaConfig,
    /// M5b: root dir for per-peer ciphertext mirrors. `None` → the XDG default
    /// `~/.local/share/softfig/peers/`. Overridable so tests mirror into a
    /// tempdir instead of the real data home.
    pub replica_root: Option<PathBuf>,
    /// Growlight loop policy from `[growlight]` — currently the relock opt-in.
    pub growlight: GrowlightConfig,
    /// growlightd's listen socket, for the keeperd→growlightd hop the lease
    /// verbs forward over (spec §4c). `None` → the default
    /// [`softfig_ipc::growlightd_runtime_socket_path`]; overridable so tests
    /// point keeperd at a growlightd bound on a tempdir socket.
    pub growlightd_socket: Option<PathBuf>,
    /// config-in-garden: when true, keeperd manages the
    /// `softfig-growlightd.service` user unit — `systemctl --user start`s it on
    /// unlock when the in-garden `config/growlight.toml` `fleet_enabled` gate is
    /// on, and `stop`s it on a *terminal* lock (not a relock-cycle). Default
    /// **false** so no library/test path ever shells `systemctl`; the real
    /// `softfig-keeperd` binary opts in via [`with_growlight_supervision`] in
    /// `main`. (`with_growlight_supervision`: KeeperConfig::with_growlight_supervision)
    pub enable_growlight_supervision: bool,
}

/// Growlight: autonomous-loop policy (`[growlight]`).
#[derive(Debug, Clone, Default)]
pub struct GrowlightConfig {
    /// Permit minting relock tokens (unattended daemon restart). Default off.
    pub allow_relock: bool,
}

impl From<GrowlightToml> for GrowlightConfig {
    fn from(t: GrowlightToml) -> Self {
        Self {
            allow_relock: t.allow_relock,
        }
    }
}

/// M5b: replication config (`[replica]`).
#[derive(Debug, Clone, Default)]
pub struct ReplicaConfig {
    /// This device hosts ciphertext backups for granted ring members.
    pub host: bool,
}

impl From<ReplicaToml> for ReplicaConfig {
    fn from(t: ReplicaToml) -> Self {
        Self { host: t.host }
    }
}

/// M5a-4: the device's own `softfig-net` host config (`[net]`).
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Whether the user configured networking on (`[net] enabled`).
    pub enabled: bool,
    /// Inbound Noise listener bind address (`host:port`).
    pub listen: String,
    /// Device name override; `None` → system hostname.
    pub device_name: Option<String>,
    /// Pairing-UX Slice A: advertise the device name in the mDNS TXT `nm`
    /// field. `false` → fingerprint-only broadcast.
    pub advertise_name: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self::from(NetToml::default())
    }
}

impl From<NetToml> for NetConfig {
    fn from(t: NetToml) -> Self {
        Self {
            enabled: t.enabled,
            listen: t.listen,
            device_name: t.device_name,
            advertise_name: t.advertise_name,
        }
    }
}

/// M5a-4: relay config (`[relay]`) — hosting + client halves.
#[derive(Debug, Clone, Default)]
pub struct RelayConfig {
    /// Host a blind relay on this device.
    pub enabled: bool,
    /// Relay listener bind address (required when `enabled`).
    pub listen: Option<String>,
    /// `host:port` of a relay reached as a client (M5b reconnect fallback).
    pub endpoint: Option<String>,
    /// The relay's X25519 transport public key, lowercase hex.
    pub static_key: Option<String>,
}

impl From<RelayToml> for RelayConfig {
    fn from(t: RelayToml) -> Self {
        Self {
            enabled: t.enabled,
            listen: t.listen,
            endpoint: t.endpoint,
            static_key: t.static_key,
        }
    }
}

/// M2b: `softfig reveal` configuration. `idle_seconds = 0` (the default)
/// makes every reveal re-prompt the master password; a positive value
/// permits the daemon to skip re-prompt if the previous successful
/// reveal happened within that window.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevealConfig {
    pub idle_seconds: u64,
}

impl KeeperConfig {
    pub fn new(garden_root: impl AsRef<Path>) -> Self {
        Self {
            garden_root: garden_root.as_ref().to_path_buf(),
            state_root: None,
            socket_path: softfig_ipc::runtime_socket_path(),
            enable_watcher: true,
            enable_fuse: true,
            enable_net: true,
            reveal: RevealConfig::default(),
            net: NetConfig::default(),
            relay: RelayConfig::default(),
            replica: ReplicaConfig::default(),
            replica_root: None,
            growlight: GrowlightConfig::default(),
            growlightd_socket: None,
            enable_growlight_supervision: false,
        }
    }

    /// Build the config and resolve `state_root` from `keeper.toml`.
    ///
    /// Search order matches what `softfig migrate` writes:
    /// 1. `<garden_root>/.softfig/keeper.toml` (pre-finalize layout —
    ///    `.softfig/` still in the garden, `keeper.toml` here points at
    ///    the new state root).
    /// 2. (No fallback. If the user manually relocated `.softfig/`
    ///    without writing keeper.toml in the garden root, the daemon
    ///    can't find it. That's deliberate — the daemon refuses to
    ///    guess.)
    pub fn discover(garden_root: impl AsRef<Path>) -> std::io::Result<Self> {
        let garden_root = garden_root.as_ref().to_path_buf();
        let cfg = KeeperToml::load(&garden_root)?;
        Ok(Self {
            garden_root,
            state_root: cfg.state_root,
            socket_path: softfig_ipc::runtime_socket_path(),
            enable_watcher: true,
            enable_fuse: true,
            enable_net: true,
            reveal: RevealConfig {
                idle_seconds: cfg.reveal.idle_seconds,
            },
            net: cfg.net.into(),
            relay: cfg.relay.into(),
            replica: cfg.replica.into(),
            replica_root: None,
            growlight: cfg.growlight.into(),
            growlightd_socket: None,
            enable_growlight_supervision: false,
        })
    }

    /// Overlay the in-garden `config/keeper.toml` onto this config after unlock.
    /// Touches only the post-unlock policy fields (`reveal`/`net`/`relay`/
    /// `replica.host`); leaves the bootstrap/local fields (`state_root`,
    /// `socket_path`, `growlight.allow_relock`, `replica_root`, the `enable_*`
    /// runtime flags) untouched — those are sourced from the pointer / runtime,
    /// never from the garden. Called only when the file is present; an absent
    /// file keeps the boot-time pointer values.
    pub fn apply_garden_config(&mut self, gc: GardenConfig) {
        self.reveal.idle_seconds = gc.reveal.idle_seconds;
        self.net = gc.net.into();
        self.relay = gc.relay.into();
        self.replica.host = gc.replica.host;
    }

    pub fn with_reveal_idle_seconds(mut self, secs: u64) -> Self {
        self.reveal.idle_seconds = secs;
        self
    }

    pub fn with_socket(mut self, path: impl AsRef<Path>) -> Self {
        self.socket_path = path.as_ref().to_path_buf();
        self
    }

    /// Point the keeperd→growlightd lease hop at a specific growlightd socket
    /// (tests; production resolves the default).
    pub fn with_growlightd_socket(mut self, path: impl AsRef<Path>) -> Self {
        self.growlightd_socket = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn with_state_root(mut self, state_root: impl AsRef<Path>) -> Self {
        self.state_root = Some(state_root.as_ref().to_path_buf());
        self
    }

    pub fn without_watcher(mut self) -> Self {
        self.enable_watcher = false;
        self
    }

    /// Opt into managing the `softfig-growlightd.service` user unit (the real
    /// `softfig-keeperd` binary; off everywhere else). See
    /// [`enable_growlight_supervision`](Self::enable_growlight_supervision).
    pub fn with_growlight_supervision(mut self, on: bool) -> Self {
        self.enable_growlight_supervision = on;
        self
    }

    pub fn without_fuse(mut self) -> Self {
        self.enable_fuse = false;
        self
    }

    /// Disable the `softfig-net` host (inbound listener / mDNS / relay). The
    /// pairing verbs still work — they drive their own outbound sockets and the
    /// on-disk ring — so tests exercise pair/list/remove without real sockets.
    pub fn without_net(mut self) -> Self {
        self.enable_net = false;
        self
    }

    /// M5b: override the per-peer mirror root (default
    /// `~/.local/share/softfig/peers/`). Tests point this at a tempdir.
    pub fn with_replica_root(mut self, root: impl AsRef<Path>) -> Self {
        self.replica_root = Some(root.as_ref().to_path_buf());
        self
    }

    /// M5b: make this device a backup host (`[replica] host = true`).
    pub fn as_replica_host(mut self, host: bool) -> Self {
        self.replica.host = host;
        self
    }

    /// Growlight: permit relock-token minting (`[growlight] allow_relock`).
    pub fn allow_relock(mut self, allow: bool) -> Self {
        self.growlight.allow_relock = allow;
        self
    }

    /// M5b: the root dir holding per-peer ciphertext mirrors. The configured
    /// override, else `$XDG_DATA_HOME/softfig/peers` (falling back to
    /// `~/.local/share/softfig/peers`, then a relative `softfig/peers` if even
    /// `$HOME` is unset — the last only happens in a degenerate environment).
    pub fn replica_root(&self) -> PathBuf {
        if let Some(root) = &self.replica_root {
            return root.clone();
        }
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("softfig").join("peers")
    }

    /// Directory containing the on-disk `.softfig/`. Equals
    /// `garden_root` in M1c-compat mode, the relocated state root in
    /// M2a mode.
    pub fn state_dir(&self) -> &Path {
        self.state_root.as_deref().unwrap_or(&self.garden_root)
    }

    pub fn is_fuse_mode(&self) -> bool {
        self.state_root.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discover_without_keeper_toml_is_m1c_compat() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = KeeperConfig::discover(tmp.path()).unwrap();
        assert!(!cfg.is_fuse_mode(), "no keeper.toml → no FUSE");
        assert_eq!(cfg.state_dir(), tmp.path());
    }

    #[test]
    fn discover_born_in_fuse_keeper_toml_enters_fuse_mode() {
        // A born-in-FUSE garden (as `softfig onboard` writes it): the
        // garden root holds a keeper.toml pointing at a relocated state
        // root. `discover` must put the daemon in FUSE mode.
        let garden = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let softfig = garden.path().join(".softfig");
        fs::create_dir_all(&softfig).unwrap();
        fs::write(
            softfig.join("keeper.toml"),
            format!("state_root = {:?}\n", state.path()),
        )
        .unwrap();

        let cfg = KeeperConfig::discover(garden.path()).unwrap();
        assert!(cfg.is_fuse_mode(), "keeper.toml with state_root → FUSE");
        assert_eq!(cfg.state_dir(), state.path());
    }

    #[test]
    fn apply_garden_config_overlays_policy_only() {
        use crate::keeper_toml::{GardenConfig, NetToml, RelayToml, ReplicaToml, RevealToml};

        // A boot config with pointer-sourced bootstrap/local fields set.
        let mut cfg = KeeperConfig::new("/garden")
            .with_state_root("/state")
            .with_socket("/run/sock")
            .allow_relock(true)
            .with_replica_root("/peers");

        let gc = GardenConfig {
            reveal: RevealToml { idle_seconds: 30 },
            net: NetToml {
                listen: "0.0.0.0:9300".into(),
                advertise_name: false,
                ..NetToml::default()
            },
            relay: RelayToml {
                enabled: true,
                ..RelayToml::default()
            },
            replica: ReplicaToml { host: true },
        };
        cfg.apply_garden_config(gc);

        // Policy overridden from the garden.
        assert_eq!(cfg.reveal.idle_seconds, 30);
        assert_eq!(cfg.net.listen, "0.0.0.0:9300");
        assert!(!cfg.net.advertise_name);
        assert!(cfg.relay.enabled);
        assert!(cfg.replica.host);

        // Bootstrap/local fields untouched by the overlay.
        assert_eq!(cfg.state_root.as_deref(), Some(Path::new("/state")));
        assert_eq!(cfg.socket_path, Path::new("/run/sock"));
        assert!(cfg.growlight.allow_relock, "allow_relock stays from pointer");
        assert_eq!(cfg.replica_root.as_deref(), Some(Path::new("/peers")));
    }
}
