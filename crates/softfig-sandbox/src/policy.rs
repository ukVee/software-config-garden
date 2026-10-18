//! The sandbox [`Policy`] model and its deterministic bwrap rendering.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// How a path is mounted into the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindMode {
    /// Read-only.
    Ro,
    /// Read-write.
    Rw,
}

/// One bind mount in the sandbox filesystem view.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bind {
    /// Host source path.
    pub src: PathBuf,
    /// In-sandbox destination path.
    pub dest: PathBuf,
    /// Read-only or read-write.
    pub mode: BindMode,
}

impl Bind {
    /// A read-only bind.
    pub fn ro(src: impl Into<PathBuf>, dest: impl Into<PathBuf>) -> Self {
        Self { src: src.into(), dest: dest.into(), mode: BindMode::Ro }
    }

    /// A read-write bind.
    pub fn rw(src: impl Into<PathBuf>, dest: impl Into<PathBuf>) -> Self {
        Self { src: src.into(), dest: dest.into(), mode: BindMode::Rw }
    }
}

/// A sized tmpfs mount (scratch, `/tmp`, `/home/job`, …).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TmpfsMount {
    /// In-sandbox mount point.
    pub path: PathBuf,
    /// Optional size limit, a bwrap `--size` string ("512M", "2G"); `None` = unbounded.
    pub size: Option<String>,
}

impl TmpfsMount {
    /// An unbounded tmpfs.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), size: None }
    }

    /// A size-capped tmpfs.
    pub fn sized(path: impl Into<PathBuf>, size: impl Into<String>) -> Self {
        Self { path: path.into(), size: Some(size.into()) }
    }
}

/// The network posture of the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Network {
    /// No network: `--unshare-all` gives a fresh netns with only loopback.
    #[default]
    None,
    /// Allowlisted egress through a proxy socket (spec §7.2, slice 005). The
    /// socket is handed to the in-namespace forwarder, not to bwrap, so it does
    /// not change the rendered argv.
    Proxy(PathBuf),
}

/// Syscalls to deny beyond the base profile. Consumed by the init shim's seccomp
/// filter, not by [`Policy::render`] — the bwrap argv stays a pure `Vec<String>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SeccompDeny {
    /// Lowercase syscall names ("ptrace", "bpf", "keyctl", …).
    pub syscalls: Vec<String>,
}

/// A fully-specified sandbox policy — one per runner step (or ad hoc run).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    /// Read-only binds.
    pub ro_binds: Vec<Bind>,
    /// Read-write binds.
    pub rw_binds: Vec<Bind>,
    /// Sized tmpfs mounts.
    pub tmpfs: Vec<TmpfsMount>,
    /// The environment: cleared, then this explicit set is applied (BTreeMap ⇒ sorted).
    pub env: BTreeMap<String, String>,
    /// Network posture.
    pub network: Network,
    /// Seccomp deny list (init-shim-only; see [`SeccompDeny`]).
    pub seccomp_deny: SeccompDeny,
    /// `--die-with-parent`: SIGKILL the command when bwrap (or its parent) dies.
    pub die_with_parent: bool,
    /// `--new-session`: a fresh terminal session (no TIOCSTI).
    pub new_session: bool,
    /// Mount a fresh procfs at `/proc` (pid namespace).
    pub proc: bool,
    /// Mount a fresh devtmpfs at `/dev` (null/zero/random/urandom).
    pub dev: bool,
}

impl Policy {
    /// Render the policy into a deterministic bwrap argv (bwrap 0.13).
    ///
    /// The flag order is fixed and every collection is emitted in a stable order
    /// (binds sorted by `(src, dest, mode)`, tmpfs by `path`, env by key), so the
    /// same policy always renders to the same argv — a property slice 001's unit
    /// tests pin.
    pub fn render(&self) -> Vec<String> {
        let mut argv: Vec<String> = Vec::new();

        // Namespaces: unshare every one bwrap supports. `--unshare-user` is
        // repeated explicitly because `--disable-userns` requires the literal
        // `--unshare-user` flag (verified against bwrap 0.13.1, which rejects
        // `--disable-userns` after a bare `--unshare-all`).
        argv.push("--unshare-all".into());
        argv.push("--unshare-user".into());
        argv.push("--disable-userns".into());

        if self.die_with_parent {
            argv.push("--die-with-parent".into());
        }
        if self.new_session {
            argv.push("--new-session".into());
        }

        // Drop every capability in the (new) user namespace.
        argv.push("--cap-drop".into());
        argv.push("ALL".into());

        // Fixed pseudo-filesystems first (deterministic, before binds).
        if self.proc {
            argv.push("--proc".into());
            argv.push("/proc".into());
        }
        if self.dev {
            argv.push("--dev".into());
            argv.push("/dev".into());
        }

        // Binds, sorted by (src, dest, mode) for determinism.
        let mut binds: Vec<&Bind> = self.ro_binds.iter().chain(self.rw_binds.iter()).collect();
        binds.sort_unstable();
        for b in binds {
            argv.push(match b.mode {
                BindMode::Ro => "--ro-bind",
                BindMode::Rw => "--bind",
            }
            .into());
            argv.push(b.src.to_string_lossy().into_owned());
            argv.push(b.dest.to_string_lossy().into_owned());
        }

        // tmpfs mounts, sorted by path; bwrap's `--size` scopes to the NEXT `--tmpfs`.
        let mut tmpfs: Vec<&TmpfsMount> = self.tmpfs.iter().collect();
        tmpfs.sort_unstable();
        for t in tmpfs {
            if let Some(size) = &t.size {
                argv.push("--size".into());
                argv.push(size.clone());
            }
            argv.push("--tmpfs".into());
            argv.push(t.path.to_string_lossy().into_owned());
        }

        // Environment: clear, then the explicit set (BTreeMap is already sorted).
        argv.push("--clearenv".into());
        for (k, v) in &self.env {
            argv.push("--setenv".into());
            argv.push(k.clone());
            argv.push(v.clone());
        }

        argv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_emits_the_fixed_namespace_and_cap_prefix() {
        let p = Policy { die_with_parent: true, new_session: true, ..Policy::default() };
        let argv = p.render();

        // The fixed prefix must appear in order.
        let expected = [
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
        ];
        assert!(argv.windows(expected.len()).any(|w| w == expected), "argv = {argv:?}");
    }

    #[test]
    fn render_is_deterministic_and_sorts_binds() {
        let mut p = Policy { die_with_parent: true, ..Policy::default() };
        // Insert out of order on purpose.
        p.rw_binds.push(Bind::rw("/zz", "/zz"));
        p.ro_binds.push(Bind::ro("/aa", "/aa"));

        let a = p.render();
        let b = p.render();
        assert_eq!(a, b, "the same policy must render identically");

        // Both binds appear, ro as `--ro-bind`, rw as `--bind`, in sorted src order.
        let aa = a.iter().position(|s| s == "--ro-bind").expect("ro-bind present");
        assert_eq!(a[aa + 1], "/aa");
        let zz = a.iter().position(|s| s == "--bind").expect("bind present");
        assert_eq!(a[zz + 1], "/zz");
        assert!(aa < zz, "binds must be emitted in sorted order");
    }

    #[test]
    fn render_emits_size_before_its_tmpfs() {
        let mut p = Policy { die_with_parent: true, ..Policy::default() };
        p.tmpfs.push(TmpfsMount::sized("/tmp", "2G"));

        let argv = p.render();
        let size = argv.iter().position(|s| s == "--size").expect("--size present");
        assert_eq!(argv[size + 1], "2G");
        assert_eq!(argv[size + 2], "--tmpfs");
        assert_eq!(argv[size + 3], "/tmp");
    }

    #[test]
    fn render_clears_then_sets_env() {
        let mut p = Policy::default();
        p.env.insert("HOME".into(), "/home/job".into());
        p.env.insert("LANG".into(), "C.UTF-8".into());

        let argv = p.render();
        let clear = argv.iter().position(|s| s == "--clearenv").expect("--clearenv present");
        // After --clearenv, the only flags are the setenv triples, in key order.
        let rest = &argv[clear + 1..];
        assert_eq!(
            rest,
            &["--setenv", "HOME", "/home/job", "--setenv", "LANG", "C.UTF-8"]
        );
    }
}
