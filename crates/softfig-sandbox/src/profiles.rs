//! The runner's named sandbox profiles — a function from a job context to a
//! [`Policy`].
//!
//! One profile per runner step, following spec §7.1's filesystem-view table and
//! §7.2's trusted fetch step. The host paths are finalized in slices 004–006
//! (source ingest, fetch, run); these functions are the shape of that contract
//! and are unit-tested for the properties that matter (no `/src` in fetch, no
//! network in run, …).

use std::path::PathBuf;

use crate::{Bind, Network, Policy, ProxyConfig, SeccompDeny, TmpfsMount, EGRESS_SOCKET};

/// The job context a profile derives from. All paths are *host* paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobContext {
    /// The materialized source tree (rw at `/src`).
    pub src: PathBuf,
    /// The per-(repo key, toolchain) target cache (rw at `/cache/target`).
    pub target_cache: PathBuf,
    /// The rustup toolchain root (ro at `/opt/toolchain`).
    pub toolchain: PathBuf,
    /// The cargo home whose `registry/` the fetch step fills.
    pub cargo_home: PathBuf,
    /// A minimal `/etc` (ld cache, ssl certs, a stub `passwd`).
    pub etc: PathBuf,
    /// Scratch tmpfs size in **bytes** (bwrap's `--size` is a byte count; the
    /// config layer converts human-readable sizes like "2G" into bytes).
    pub scratch_size: u64,
}

/// The seccomp deny list from spec §7.1 layer 5 (applied by the init shim, not
/// by bwrap).
fn seccomp_deny() -> SeccompDeny {
    SeccompDeny {
        syscalls: vec![
            "ptrace".into(),
            "keyctl".into(),
            "add_key".into(),
            "bpf".into(),
            "perf_event_open".into(),
            "userfaultfd".into(),
            "io_uring_setup".into(),
            "io_uring_enter".into(),
            "io_uring_register".into(),
            "mount".into(),
            "pivot_root".into(),
            "init_module".into(),
            "finit_module".into(),
            "delete_module".into(),
            "kexec_load".into(),
            "kexec_file_load".into(),
            "personality".into(),
        ],
    }
}

/// The common layers every runner profile shares.
fn base(ctx: &JobContext) -> Policy {
    let mut policy = Policy {
        network: Network::None,
        seccomp_deny: seccomp_deny(),
        die_with_parent: true,
        new_session: true,
        proc: true,
        dev: true,
        ..Policy::default()
    };

    // Read-only system view (spec §7.1): `/usr`, a minimal `/etc`, the toolchain.
    // On a merged-/usr system (Arch, the reference laptop) `/bin`, `/lib`,
    // `/lib64` and `/sbin` are symlinks into `/usr`, and a dynamically-linked
    // binary's ELF interpreter (`/lib64/ld-linux-*.so.2`) lives behind those
    // symlinks — they must be present in the namespace or exec fails with
    // ENOENT even though `/usr` is bound.
    policy.ro_binds.push(Bind::ro("/usr", "/usr"));
    policy.ro_binds.push(Bind::ro("/bin", "/bin"));
    policy.ro_binds.push(Bind::ro("/lib", "/lib"));
    policy.ro_binds.push(Bind::ro("/lib64", "/lib64"));
    policy.ro_binds.push(Bind::ro("/sbin", "/sbin"));
    policy.ro_binds.push(Bind::ro(&ctx.etc, "/etc"));
    policy.ro_binds.push(Bind::ro(&ctx.toolchain, "/opt/toolchain"));

    // Scratch tmpfs.
    policy.tmpfs.push(TmpfsMount::sized("/tmp", ctx.scratch_size));
    policy.tmpfs.push(TmpfsMount::sized("/home/job", ctx.scratch_size));

    // Cleared environment, then the explicit set (spec §7.1).
    policy.env.insert("PATH".into(), "/usr/bin:/usr/sbin".into());
    policy.env.insert("HOME".into(), "/home/job".into());
    policy.env.insert("LANG".into(), "C.UTF-8".into());
    // `rustup` proxies cargo/rustc on the reference laptop (Arch: /usr/bin/cargo
    // is a symlink to rustup), so it must find its home — the toolchain bind —
    // or it refuses to run. The channel is pinned per profile (a rust-toolchain
    // file in the tree or RUSTUP_TOOLCHAIN), not here.
    policy.env.insert("RUSTUP_HOME".into(), "/opt/toolchain".into());

    policy
}

/// Ingest: the runner's bare mirror is rw; git runs here, never in runnerd's
/// own context (spec §4.4). No `/src` yet.
pub fn profile_ingest(ctx: &JobContext, mirror: PathBuf) -> Policy {
    let mut p = base(ctx);
    p.rw_binds.push(Bind::rw(mirror, "/repo"));
    p
}

/// Materialize: the mirror is read-only and `/src` is written with
/// `read-tree` + `checkout-index` (spec §4.4).
pub fn profile_materialize(ctx: &JobContext, mirror: PathBuf) -> Policy {
    let mut p = base(ctx);
    p.ro_binds.push(Bind::ro(mirror, "/repo"));
    p.rw_binds.push(Bind::rw(&ctx.src, "/src"));
    p
}

/// Fetch: only the manifests + lockfile, against the allowlisted egress proxy.
/// No repo-authored code runs, so there is deliberately **no `/src`** (spec §7.2).
///
/// `skeleton` is the extracted dependency shape (manifests + lockfile + empty
/// stubs, no `build.rs`/`.cargo/config.toml`/source — see `softfig-source`),
/// bound read-only at `/skeleton` and set as the cwd.
pub fn profile_fetch(ctx: &JobContext, skeleton: PathBuf, proxy: ProxyConfig) -> Policy {
    let mut p = base(ctx);
    let listen = proxy.listen.clone();
    let socket = proxy.socket.clone();
    p.network = Network::Proxy(proxy);
    // The cargo-home registry is the only writable non-scratch path, and rw
    // **only** in this step (the slice-005 cargo-home probe: `cargo fetch` fills
    // registry/{cache,index,src} and writes the root `.global-cache`/`.package-cache`,
    // while `cargo build --offline` needs the whole home read-only).
    p.rw_binds.push(Bind::rw(&ctx.cargo_home, "/opt/cargo-home"));
    p.env.insert("CARGO_HOME".into(), "/opt/cargo-home".into());
    p.ro_binds.push(Bind::ro(skeleton, "/skeleton"));
    p.chdir = Some("/skeleton".into());

    // The proxy socket is bind-mounted rw: `connect()` to a Unix socket needs
    // write permission on the socket file (it is a socket, not a regular file,
    // so rw here does not let the job modify runnerd's proxy).
    p.rw_binds.push(Bind::rw(socket, EGRESS_SOCKET));

    // Point cargo's HTTP(S) at the in-namespace forwarder (lowercase + uppercase,
    // for cargo/libcurl and git). The CONNECT allowlist decision stays in runnerd.
    let url = format!("http://{listen}");
    for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
        p.env.insert(key.into(), url.clone());
    }
    p
}

/// Run: the full offline view — `/src` + caches, **no network** (spec §7.1).
pub fn profile_run(ctx: &JobContext) -> Policy {
    let mut p = base(ctx);
    p.ro_binds.push(Bind::ro(&ctx.cargo_home, "/opt/cargo-home"));
    p.rw_binds.push(Bind::rw(&ctx.src, "/src"));
    p.rw_binds.push(Bind::rw(&ctx.target_cache, "/cache/target"));
    p.chdir = Some("/src".into());

    p.env.insert("CARGO_HOME".into(), "/opt/cargo-home".into());
    p.env.insert("CARGO_TARGET_DIR".into(), "/cache/target".into());
    p.env.insert("CARGO_NET_OFFLINE".into(), "true".into());
    p
}

/// Run with `network = "egress"`: the offline [`profile_run`] view, but routed
/// through the same allowlisted proxy as fetch, and with `CARGO_NET_OFFLINE`
/// cleared so the run step may actually reach it (spec §7.2 "opting in to
/// network at run time"). Declared in the requester's config and recorded in
/// the attestation.
pub fn profile_run_egress(ctx: &JobContext, proxy: ProxyConfig) -> Policy {
    let mut p = profile_run(ctx);
    let listen = proxy.listen.clone();
    p.network = Network::Proxy(proxy);
    p.env.remove("CARGO_NET_OFFLINE");
    let url = format!("http://{listen}");
    for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
        p.env.insert(key.into(), url.clone());
    }
    p
}

/// Collect: the same view as run but read-only — the step only hashes declared
/// artifacts, it never writes.
pub fn profile_collect(ctx: &JobContext) -> Policy {
    let mut p = base(ctx);
    p.ro_binds.push(Bind::ro(&ctx.cargo_home, "/opt/cargo-home"));
    p.ro_binds.push(Bind::ro(&ctx.src, "/src"));
    p.ro_binds.push(Bind::ro(&ctx.target_cache, "/cache/target"));
    // The collect helper matches the declared artifact globs relative to its
    // working directory, so start it in the materialized tree root.
    p.chdir = Some("/src".into());
    p
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx() -> JobContext {
        JobContext {
            src: "/var/lib/softfig-runner/jobs/j1/src".into(),
            target_cache: "/var/lib/softfig-runner/cache/target".into(),
            toolchain: "/var/lib/softfig-runner/toolchains/rust".into(),
            cargo_home: "/var/lib/softfig-runner/cargo".into(),
            etc: "/var/lib/softfig-runner/etc".into(),
            scratch_size: 2 * 1024 * 1024 * 1024,
        }
    }

    #[test]
    fn run_profile_is_offline_and_binds_src_and_target() {
        let p = profile_run(&ctx());
        assert_eq!(p.network, Network::None);
        assert_eq!(p.env.get("CARGO_NET_OFFLINE").map(String::as_str), Some("true"));
        assert!(p.rw_binds.iter().any(|b| b.dest.as_path() == Path::new("/src")));
        assert!(p.rw_binds.iter().any(|b| b.dest.as_path() == Path::new("/cache/target")));
        assert!(p.ro_binds.iter().any(|b| b.dest.as_path() == Path::new("/opt/toolchain")));
    }

    fn proxy() -> ProxyConfig {
        ProxyConfig {
            socket: "/run/egress.sock".into(),
            forwarder: "/softfig-sandbox-forward".into(),
            listen: "127.0.0.1:3128".into(),
        }
    }

    #[test]
    fn fetch_profile_has_no_src_and_uses_the_proxy() {
        let p = profile_fetch(&ctx(), "/skeleton".into(), proxy());
        assert_eq!(p.network, Network::Proxy(proxy()));
        assert!(!p.rw_binds.iter().any(|b| b.dest.as_path() == Path::new("/src")));
        assert!(!p.ro_binds.iter().any(|b| b.dest.as_path() == Path::new("/src")));
        assert!(p.rw_binds.iter().any(|b| b.dest.as_path() == Path::new("/opt/cargo-home")));
        // The skeleton is the fetch step's only input: read-only and the cwd.
        assert!(p.ro_binds.iter().any(|b| b.dest.as_path() == Path::new("/skeleton")));
        assert_eq!(p.chdir.as_deref(), Some(Path::new("/skeleton")));
        assert_eq!(p.env.get("http_proxy").map(String::as_str), Some("http://127.0.0.1:3128"));
    }

    #[test]
    fn run_egress_clears_offline_and_uses_the_proxy() {
        let p = profile_run_egress(&ctx(), proxy());
        assert_eq!(p.network, Network::Proxy(proxy()));
        assert!(!p.env.contains_key("CARGO_NET_OFFLINE"));
        assert_eq!(p.env.get("http_proxy").map(String::as_str), Some("http://127.0.0.1:3128"));
        // Still the full run view.
        assert!(p.rw_binds.iter().any(|b| b.dest.as_path() == Path::new("/src")));
    }

    #[test]
    fn materialize_reads_the_mirror_and_writes_src() {
        let p = profile_materialize(&ctx(), "/var/lib/softfig-runner/repos/r.git".into());
        assert!(p.ro_binds.iter().any(|b| b.dest.as_path() == Path::new("/repo")));
        assert!(p.rw_binds.iter().any(|b| b.dest.as_path() == Path::new("/src")));
    }
}
