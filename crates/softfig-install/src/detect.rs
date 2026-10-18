//! OS/distro + supervisor detection — the install helper's first job
//! (`meta/spec-install.md` workstream B, release-pipeline slice 005).
//!
//! Detection is split into a **pure** half (parse an `/etc/os-release` blob,
//! decide the supervisor from observed facts) and an **impure** half
//! ([`Distro::detect`] / [`Supervisor::detect`], which read the live
//! filesystem / process environment). The pure half is what the unit tests
//! exercise with a fake `/etc/os-release`; the impure half is thin enough to
//! need no test.
//!
//! ## The supervisor seam
//!
//! The daemon's init-system seam today is systemd `--user` only
//! (`softfig-keeperd`'s `growlight_unit.rs` shells `systemctl --user`). This
//! module detects the *same* fact — "is a systemd user bus reachable?" — and
//! names it with one [`Supervisor`] enum, so when a launchd (macOS, later) or
//! foreground / no-supervisor fallback lands, both the daemon and the helper
//! slot into the same seam instead of each re-deciding in a script branch.
//! The no-supervisor fallback is **honest**: the helper reports it and tells
//! the user to run the daemon in the foreground, rather than pretending a
//! supervisor exists.

use std::path::Path;

/// The four near-term Linux distros the installer targets (round-2 decision 4),
/// plus explicit buckets for everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Distro {
    Arch,
    Debian,
    Ubuntu,
    Fedora,
    /// A recognized `/etc/os-release` that is not one of the four. Carries the
    /// `NAME` so the helper can still report honestly.
    Other(String),
    /// No `/etc/os-release` at all.
    Unknown,
}

/// The service supervisor available to run the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    /// A systemd **user** bus is reachable (`systemctl --user` works).
    SystemdUser,
    /// No supervisor: the daemon must be run in the foreground / started
    /// manually.
    None,
}

/// The fields of `/etc/os-release` the installer reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub id_like: Vec<String>,
    pub name: String,
}

/// Parse a `/etc/os-release` blob.
///
/// The format is `KEY=VALUE` lines: `ID=` and `NAME=` are single values,
/// `ID_LIKE=` is a space-separated list, and values may be double-quoted.
pub fn parse_os_release(text: &str) -> OsRelease {
    let mut id = String::new();
    let mut id_like = Vec::new();
    let mut name = String::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(value.trim());
        match key {
            "ID" => id = value.to_string(),
            "ID_LIKE" => id_like = value.split_whitespace().map(str::to_string).collect(),
            "NAME" => name = value.to_string(),
            _ => {}
        }
    }
    OsRelease { id, id_like, name }
}

/// Strip one layer of surrounding double quotes, if present.
fn unquote(v: &str) -> &str {
    v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(v)
}

/// Classify a parsed release into one of the four target distros.
pub fn distro_from(release: &OsRelease) -> Distro {
    match release.id.as_str() {
        "arch" => Distro::Arch,
        "debian" => Distro::Debian,
        "ubuntu" => Distro::Ubuntu,
        "fedora" => Distro::Fedora,
        "" => Distro::Unknown,
        _ => Distro::Other(release.name.clone()),
    }
}

impl Distro {
    /// Detect the distro from `root`. Production passes `/`; tests pass a fake
    /// root holding a fake `etc/os-release`.
    pub fn detect(root: &Path) -> Distro {
        match std::fs::read_to_string(root.join("etc/os-release")) {
            Ok(text) => distro_from(&parse_os_release(&text)),
            Err(_) => Distro::Unknown,
        }
    }

    /// One human-readable line for the detection report.
    pub fn report(&self) -> String {
        match self {
            Distro::Arch => "Arch Linux".to_string(),
            Distro::Debian => "Debian".to_string(),
            Distro::Ubuntu => "Ubuntu".to_string(),
            Distro::Fedora => "Fedora".to_string(),
            Distro::Other(name) => format!("other ({name})"),
            Distro::Unknown => "unknown (no /etc/os-release)".to_string(),
        }
    }

    /// The FUSE-prereq install command for this distro, for the helper's copy.
    /// `None` for an unrecognized distro: we say "install fuse3" honestly
    /// without pretending to know the package manager.
    pub fn fuse_package_command(&self) -> Option<&'static str> {
        match self {
            Distro::Arch => Some("sudo pacman -S fuse3"),
            Distro::Debian | Distro::Ubuntu => Some("sudo apt-get install -y fuse3"),
            Distro::Fedora => Some("sudo dnf install -y fuse3"),
            Distro::Other(_) | Distro::Unknown => None,
        }
    }
}

/// Decide the supervisor from observed facts (pure, so tests can fake it).
pub fn supervisor_from(systemctl_present: bool, user_bus_reachable: bool) -> Supervisor {
    if systemctl_present && user_bus_reachable {
        Supervisor::SystemdUser
    } else {
        Supervisor::None
    }
}

impl Supervisor {
    /// Detect the supervisor on the live system.
    pub fn detect() -> Supervisor {
        supervisor_from(
            which("systemctl"),
            // A systemd user bus is reachable iff its socket lives under the
            // user's runtime dir. This is the same "is systemd --user here?"
            // question `systemctl --user` answers, read without spawning.
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(|d| Path::new(&d).join("systemd/private").exists())
                .unwrap_or(false),
        )
    }

    /// One human-readable line for the detection report.
    pub fn describe(&self) -> &'static str {
        match self {
            Supervisor::SystemdUser => "systemd (user)",
            Supervisor::None => "none (foreground / manual start)",
        }
    }
}

/// Is `name` on `PATH`? Factored here so the supervisor check, the `claude`
/// MCP-registration check and the `fusermount3` check all read the same way.
pub fn which(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| dir.join(name).is_file())
    })
}

/// Is the installed set at `prefix` owned by the distro's package manager?
///
/// A package-owned prefix — an AUR `/usr/bin` install — must never be written
/// or removed by the helper: those files belong to the package manager. The
/// question is only answerable on Arch, where `pacman` can say so directly;
/// every other distro returns `false` (the helper cannot overwrite a package
/// manager it does not know).
pub fn package_owned(distro: &Distro, prefix: &Path) -> bool {
    match distro {
        Distro::Arch => package_owned_with("pacman", prefix),
        Distro::Debian | Distro::Ubuntu | Distro::Fedora | Distro::Other(_) | Distro::Unknown => {
            false
        }
    }
}

/// The shared refusal for a package-owned prefix: point at the package manager
/// for both update and removal, since the helper never writes over or removes
/// files the package manager owns. Install/upgrade/uninstall all gate on it.
pub fn package_owned_message(prefix: &Path) -> String {
    format!(
        "the install prefix {} is owned by the package manager (soft-fig is \
         installed from the AUR here). The helper will not write over or remove \
         package-managed files: update with `pacman -Syu soft-fig`, or remove with \
         `pacman -Rns soft-fig`.",
        prefix.display()
    )
}

/// The `pacman` half of [`package_owned`]: ask it whether it owns any
/// installed-set member at `prefix`. `pacman -Qo <path>` exits 0 when the
/// package database owns the file, 1 when it does not. The first member that
/// exists is the one asked about, so a partial install still answers correctly.
/// A missing pacman (or a prefix with no installed-set member) is "not owned" —
/// the helper only needs to refuse a real AUR install, and no pacman means no
/// package manager to conflict with.
fn package_owned_with(pacman: &str, prefix: &Path) -> bool {
    if !which(pacman) {
        return false;
    }
    for name in softfig_ipc::compat::INSTALLED_SET {
        let candidate = prefix.join(name);
        if candidate.is_file() {
            let status = std::process::Command::new(pacman)
                .args(["-Qo"])
                .arg(&candidate)
                .status();
            return matches!(status, Ok(s) if s.success());
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCH: &str = "ID=arch\nNAME=\"Arch Linux\"\nID_LIKE=\"archlinux\"\n";
    const UBUNTU: &str = "ID=ubuntu\nNAME=\"Ubuntu\"\nID_LIKE=debian\n";

    #[test]
    fn classifies_each_target_distro() {
        assert_eq!(distro_from(&parse_os_release(ARCH)), Distro::Arch);
        assert_eq!(distro_from(&parse_os_release(UBUNTU)), Distro::Ubuntu);
        assert_eq!(
            distro_from(&parse_os_release("ID=debian\nNAME=\"Debian GNU/Linux\"\n")),
            Distro::Debian
        );
        assert_eq!(
            distro_from(&parse_os_release("ID=fedora\nNAME=\"Fedora Linux\"\n")),
            Distro::Fedora
        );
    }

    #[test]
    fn an_unrecognized_id_carries_its_name() {
        let r = parse_os_release("ID=nixos\nNAME=\"NixOS\"\n");
        assert_eq!(distro_from(&r), Distro::Other("NixOS".to_string()));
    }

    #[test]
    fn id_like_is_split_on_whitespace() {
        assert_eq!(parse_os_release(UBUNTU).id_like, vec!["debian".to_string()]);
    }

    #[test]
    fn detect_reads_a_fake_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(root.path().join("etc/os-release"), ARCH).unwrap();
        assert_eq!(Distro::detect(root.path()), Distro::Arch);
    }

    #[test]
    fn a_missing_os_release_is_unknown() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(Distro::detect(root.path()), Distro::Unknown);
    }

    #[test]
    fn supervisor_needs_both_systemctl_and_a_user_bus() {
        assert_eq!(supervisor_from(true, true), Supervisor::SystemdUser);
        assert_eq!(supervisor_from(true, false), Supervisor::None);
        assert_eq!(supervisor_from(false, true), Supervisor::None);
        assert_eq!(supervisor_from(false, false), Supervisor::None);
    }

    #[test]
    fn fuse_command_is_per_distro() {
        assert_eq!(Distro::Arch.fuse_package_command(), Some("sudo pacman -S fuse3"));
        assert_eq!(Distro::Ubuntu.fuse_package_command(), Some("sudo apt-get install -y fuse3"));
        assert_eq!(Distro::Fedora.fuse_package_command(), Some("sudo dnf install -y fuse3"));
        assert_eq!(Distro::Unknown.fuse_package_command(), None);
    }

    // ---- M4: package-owned prefix detection ----

    /// A fake `pacman` script that exits with `exit_code` — the test stand-in
    /// for `pacman -Qo` (0 = owns the file, 1 = does not).
    fn write_fake_pacman(dir: &Path, exit_code: i32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("pacman");
        std::fs::write(&p, format!("#!/bin/sh\nexit {exit_code}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn write_member(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"fake").unwrap();
    }

    #[test]
    fn package_owned_reads_pacmans_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_member(&prefix, "softfig");

        // pacman exits 0 ⇒ the file is package-owned.
        let owned = write_fake_pacman(dir.path(), 0);
        assert!(package_owned_with(owned.to_string_lossy().as_ref(), &prefix));
        // pacman exits 1 ⇒ not owned.
        let not_owned = write_fake_pacman(dir.path(), 1);
        assert!(!package_owned_with(not_owned.to_string_lossy().as_ref(), &prefix));
    }

    #[test]
    fn package_owned_is_false_off_arch() {
        let dir = tempfile::tempdir().unwrap();
        // Non-Arch distros never consult pacman, regardless of what is there.
        assert!(!package_owned(&Distro::Debian, dir.path()));
        assert!(!package_owned(&Distro::Ubuntu, dir.path()));
        assert!(!package_owned(&Distro::Fedora, dir.path()));
        assert!(!package_owned(&Distro::Other("nixos".into()), dir.path()));
        assert!(!package_owned(&Distro::Unknown, dir.path()));
    }

    #[test]
    fn package_owned_is_false_when_pacman_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("bin");
        std::fs::create_dir_all(&prefix).unwrap();
        write_member(&prefix, "softfig");
        // A program name that is certainly not on PATH.
        assert!(!package_owned_with("softfig-no-such-pacman-anywhere", &prefix));
    }

    #[test]
    fn package_owned_is_false_with_no_installed_set_member() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("bin");
        std::fs::create_dir_all(&prefix).unwrap();
        // Nothing to own, even though pacman would claim it.
        let owned = write_fake_pacman(dir.path(), 0);
        assert!(!package_owned_with(owned.to_string_lossy().as_ref(), &prefix));
    }

    #[test]
    fn package_owned_asks_about_the_first_member_that_exists() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("bin");
        std::fs::create_dir_all(&prefix).unwrap();
        // `softfig` and `softfig-keeperd` are absent; `softfig-mcp` exists.
        write_member(&prefix, "softfig-mcp");
        let owned = write_fake_pacman(dir.path(), 0);
        assert!(package_owned_with(owned.to_string_lossy().as_ref(), &prefix));
    }
}
