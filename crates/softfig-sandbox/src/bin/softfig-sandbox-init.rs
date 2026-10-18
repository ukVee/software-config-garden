//! `softfig-sandbox-init` — the exec shim that runs *inside* bubblewrap.
//!
//! Invoked as the command bwrap execs after it has set up namespaces, binds and
//! the environment:
//!
//! ```text
//! bwrap <flags> softfig-sandbox-init --policy <json> -- <cmd> [args…]
//! ```
//!
//! It sets `no_new_privs` (via the Landlock and seccomp layers, both of which
//! require it), applies a Landlock ruleset derived from the *same* bind list
//! bwrap used (belt-and-braces against a bwrap misconfiguration), applies the
//! seccomp deny-list filter, then `exec`s the command. Landlock and seccomp
//! restrictions are inherited across the exec, so the job runs with the full
//! stack enforced.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{bail, Context, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use softfig_sandbox::{build_seccomp_filter, Policy};

/// The Landlock ABI this shim targets. `V5` covers every access right the
/// runner needs (through `IoctlDev`, added in ABI 5 / kernel 6.7) without
/// requiring the newer scoping rights, so it works on any Landlock kernel the
/// runner is likely to run.
const ABI: ABI = ABI::V5;

fn main() -> Result<()> {
    let mut args = std::env::args_os();
    let _prog = args.next();

    let (policy_json, cmd) = parse_args(args)?;
    let policy: Policy =
        serde_json::from_str(&policy_json).context("failed to parse --policy JSON")?;

    apply_landlock(&policy)?;

    let bpf = build_seccomp_filter(&policy.seccomp_deny.syscalls)
        .map_err(|e| anyhow::anyhow!("failed to build the seccomp filter: {e}"))?;
    seccompiler::apply_filter(&bpf).context("failed to apply the seccomp filter")?;

    let (program, cmd_args) = cmd.split_first().context("no command after `--`")?;
    // The `Err(io::Error)` from `exec()` is the only way out: on success the
    // process image is replaced and this never returns.
    Err(
        Command::new(program)
            .args(cmd_args)
            .exec()
            .into(),
    )
}

/// Parse `--policy <json> -- <cmd> [args…]` from the remaining argv.
fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<(String, Vec<OsString>)> {
    let mut policy_json: Option<String> = None;
    let mut cmd: Vec<OsString> = Vec::new();
    let mut in_cmd = false;

    while let Some(a) = args.next() {
        if in_cmd {
            cmd.push(a);
        } else if a == "--" {
            in_cmd = true;
        } else if a == "--policy" {
            policy_json = Some(
                args.next()
                    .context("--policy requires a JSON argument")?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("--policy argument is not valid UTF-8"))?,
            );
        } else {
            bail!("unexpected argument: {}", a.to_string_lossy());
        }
    }

    Ok((
        policy_json.context("missing required --policy <json>")?,
        cmd,
    ))
}

/// Apply the Landlock ruleset the policy implies (spec §7.1 layer 4).
fn apply_landlock(policy: &Policy) -> Result<()> {
    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI))
        .context("failed to declare handled Landlock access rights")?
        .create()
        .context("failed to create the Landlock ruleset")?;

    for rule in policy.fs_rules() {
        let access = if rule.writable {
            AccessFs::from_all(ABI)
        } else {
            AccessFs::from_read(ABI)
        };
        created = created
            .add_rule(PathBeneath::new(
                PathFd::new(&rule.path)
                    .with_context(|| format!("failed to open {}", rule.path.display()))?,
                access,
            ))
            .with_context(|| format!("failed to add Landlock rule for {}", rule.path.display()))?;
    }

    let status = created
        .restrict_self()
        .context("failed to enforce the Landlock ruleset")?;

    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock ruleset not enforced (kernel unsupported or disabled)");
    }

    Ok(())
}
