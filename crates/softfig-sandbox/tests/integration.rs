//! Integration tests for the sandbox stack (spec §7.1): real `bwrap` plus the
//! `softfig-sandbox-init` shim. These prove the *whole* stack — namespaces,
//! binds, Landlock and seccomp together — so they run `bwrap` for real and
//! skip loudly (a visible `SKIPPED: <reason>`) when `bwrap`, user namespaces or
//! a probe interpreter is unavailable, never passing silently.

use std::process::{Command, Output};

use softfig_sandbox::{Bind, Policy, SeccompDeny, TmpfsMount};

/// The init shim binary, resolved by cargo for integration tests.
const SHIM: &str = env!("CARGO_BIN_EXE_softfig-sandbox-init");

/// A minimal run-step view: `/usr` and `/etc` read-only, `/tmp` and `/home/job`
/// as sized tmpfs, plus fresh `/proc` and `/dev`. No `/home`, no `/src`.
fn policy() -> Policy {
    let mut p = Policy {
        die_with_parent: true,
        new_session: true,
        proc: true,
        dev: true,
        seccomp_deny: SeccompDeny {
            syscalls: vec![
                "ptrace".into(),
                "bpf".into(),
                "keyctl".into(),
                "mount".into(),
            ],
        },
        ..Policy::default()
    };
    p.ro_binds.push(Bind::ro("/usr", "/usr"));
    // The merged-/usr symlinks the ELF interpreter and libc sit behind.
    p.ro_binds.push(Bind::ro("/bin", "/bin"));
    p.ro_binds.push(Bind::ro("/lib", "/lib"));
    p.ro_binds.push(Bind::ro("/lib64", "/lib64"));
    p.ro_binds.push(Bind::ro("/sbin", "/sbin"));
    p.ro_binds.push(Bind::ro("/etc", "/etc"));
    p.tmpfs.push(TmpfsMount::sized("/tmp", 64 * 1024 * 1024));
    p
}

fn bwrap_ok() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn userns_ok() -> bool {
    Command::new("unshare")
        .args(["-Ur", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn python3_ok() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns `true` when the bwrap/userns preconditions are unmet, after printing
/// a loud skip line.
fn skip_bwrap() -> bool {
    if !bwrap_ok() || !userns_ok() {
        eprintln!("SKIPPED: bwrap or user namespaces unavailable; cannot run the integration sandbox test");
        return true;
    }
    false
}

/// Run the policy's bwrap argv plus the shim, with `cmd` as the job command.
///
/// The shim is a host binary at an absolute path, invisible inside the fresh
/// mount namespace, so it is bound to a fixed in-sandbox path first — mirroring
/// how the runner will install it at a known location.
fn run_with(argv_extra: &[&str], policy: &Policy, cmd: &[&str]) -> Output {
    let mut argv = policy.render();
    argv.push("--ro-bind".into());
    argv.push(SHIM.to_string());
    argv.push("/softfig-sandbox-init".into());
    argv.extend(argv_extra.iter().map(|s| s.to_string()));
    let json = serde_json::to_string(policy).expect("policy serializes");

    let mut command = Command::new("bwrap");
    command.args(&argv);
    command.arg("/softfig-sandbox-init").arg("--policy").arg(&json).arg("--");
    command.args(cmd);
    command.output().expect("failed to spawn bwrap")
}

fn run(policy: &Policy, cmd: &[&str]) -> Output {
    run_with(&[], policy, cmd)
}

/// The command must not be able to open an outbound TCP connection: bwrap
/// `--unshare-all` gives a fresh netns with only loopback.
#[test]
fn no_outbound_network() {
    if skip_bwrap() {
        return;
    }
    if !python3_ok() {
        eprintln!("SKIPPED: python3 unavailable; cannot run the network probe");
        return;
    }
    let p = policy();
    let out = run(
        &p,
        &[
            "python3",
            "-c",
            "import socket,sys; \
             s=socket.socket(); s.settimeout(2); \
             try:\n  s.connect(('1.1.1.1',443)); sys.exit(0)\n\
             except OSError: sys.exit(1)",
        ],
    );
    assert!(
        !out.status.success(),
        "connect() to 1.1.1.1:443 should fail, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `/home` is not in the mount table and not granted by Landlock, so it must
/// not be visible.
#[test]
fn home_is_not_visible() {
    if skip_bwrap() {
        return;
    }
    let p = policy();
    let out = run(&p, &["sh", "-c", "test -e /home && echo VISIBLE || echo HIDDEN"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("HIDDEN"),
        "expected /home to be invisible, stdout={stdout:?} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Writing outside a read-write path (a read-only bind) must fail.
#[test]
fn write_to_read_only_path_fails() {
    if skip_bwrap() {
        return;
    }
    let p = policy();
    let out = run(
        &p,
        &["sh", "-c", "echo x > /etc/.sandbox-write-test 2>/dev/null && echo WROTE || echo DENIED"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("DENIED"),
        "expected a write to /etc to be denied, stdout={stdout:?}"
    );
}

/// A writable tmpfs path must accept a write (the positive control).
#[test]
fn write_to_tmpfs_succeeds() {
    if skip_bwrap() {
        return;
    }
    let p = policy();
    let out = run(
        &p,
        &["sh", "-c", "echo x > /tmp/.sandbox-write-test && echo WROTE || echo DENIED"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WROTE"),
        "expected a write to /tmp to succeed, stdout={stdout:?} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Landlock blocks a path even when bwrap is (mis)configured to bind-mount it:
/// we append an over-broad `/home` bind to the bwrap argv, but the shim's
/// Landlock rules — derived from the same narrow policy, which has no `/home` —
/// must still deny access.
#[test]
fn landlock_blocks_a_path_bwrap_mounts() {
    if skip_bwrap() {
        return;
    }
    let p = policy();
    let out = run_with(
        &["--ro-bind", "/home", "/home"],
        &p,
        &["sh", "-c", "cat /home/ukv/.bashrc >/dev/null 2>&1 && echo VISIBLE || echo BLOCKED"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("BLOCKED"),
        "expected Landlock to block /home despite the bwrap bind, stdout={stdout:?}"
    );
}

/// The seccomp deny list must return EPERM for a denied syscall (`ptrace`).
#[test]
fn ptrace_is_denied() {
    if skip_bwrap() {
        return;
    }
    if !python3_ok() {
        eprintln!("SKIPPED: python3 unavailable; cannot run the ptrace probe");
        return;
    }
    let p = policy();
    let out = run(
        &p,
        &[
            "python3",
            "-c",
            "import ctypes; libc=ctypes.CDLL('libc.so.6', use_errno=True); \
             r=libc.ptrace(0,0,0,0); err=ctypes.get_errno(); \
             print('ptrace_ret', r, 'errno', err); \
             raise SystemExit(0 if (r == -1 and err == 1) else 1)",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected ptrace() to return EPERM, stdout={stdout:?} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
