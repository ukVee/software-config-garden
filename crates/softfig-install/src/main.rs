//! `softfig-install` — the downloaded, prebuilt front door (round-2 decision
//! 5, `meta/spec-install.md` workstream B). Detects OS + supervisor, gates the
//! toolchain, builds the program from source, installs the reconciled binary
//! set atomically, offers the consented + reversible integration steps
//! (systemd unit, MCP registration), then hands off to `softfig onboard`.
//!
//! Idempotent: re-running on an installed device is a repair / no-op, not a
//! duplicate (the growlight `init` "idempotent retrofit" is the model).
//!
//! Posture, mirroring `scripts/onboard-device.sh`: the build, install, fuse3
//! and PATH checks are **automatic**; the unit install and MCP registration
//! are **prompted, reversible, user-consented** — never silent.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use softfig_install::detect::{package_owned, package_owned_message, which, Distro, Supervisor};
use softfig_install::gate::{self, Gate};
use softfig_install::prompt::{Answer, Consent, Fixed, Offer, Tty};
use softfig_install::source::{self, Source};
use softfig_install::stage::{stage_and_swap, StageOutcome};
use softfig_install::unit;
use softfig_ipc::compat::SetReport;

#[derive(Parser, Debug)]
#[command(name = "softfig-install", version, about = "soft-fig: the guided install front door")]
struct Cli {
    /// Build an existing source checkout at this path.
    #[arg(long)]
    source: Option<PathBuf>,
    /// Clone this repo URL instead of building an existing checkout.
    #[arg(long)]
    repo: Option<String>,
    /// The tag/ref to check out when cloning with `--repo`.
    #[arg(long)]
    r#ref: Option<String>,
    /// Install the binaries here (default: ~/.local/bin).
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// The garden path handed to `softfig onboard` (default: ~/soft-fig_garden).
    #[arg(long)]
    garden: Option<PathBuf>,
    /// Consent to every offered step (unit + MCP registration) without prompting.
    #[arg(long)]
    yes: bool,
    /// Decline every offered step without prompting.
    #[arg(long)]
    no: bool,
    /// Detect + gate + print the plan, then stop before building or touching anything.
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    let cli = Cli::parse();
    let mut consent: Box<dyn Consent> = if cli.yes {
        Box::new(Fixed(Answer::Yes))
    } else if cli.no {
        Box::new(Fixed(Answer::No))
    } else {
        Box::new(Tty)
    };

    if let Err(err) = run(cli, consent.as_mut()) {
        // A failed toolchain gate already printed its own actionable message
        // (the rustup command) inside `run`; everything else is a real error.
        eprintln!("softfig-install: {err:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli, consent: &mut dyn Consent) -> Result<()> {
    // 1. Detect and report.
    let distro = Distro::detect(Path::new("/"));
    let supervisor = Supervisor::detect();
    println!("soft-fig install");
    println!("  distro:     {}", distro.report());
    println!("  supervisor: {}", supervisor.describe());

    // 2. Resolve the prefix and refuse a package-owned one — the helper must
    //    never write over `/usr/bin` (an AUR install). Refused before the
    //    build, the swap, and any filesystem touch.
    let prefix = cli.prefix.clone().unwrap_or_else(default_bin_dir);
    if package_owned(&distro, &prefix) {
        anyhow::bail!("{}", package_owned_message(&prefix));
    }
    // Resolve the garden too — the unit render and the hand-off both name it.
    let garden = cli.garden.clone().unwrap_or_else(default_garden);

    // Dry run: print the plan and stop before any clone, build or
    //    filesystem touch (report 081 item 6). The gate needs the source on
    //    disk, so it runs here only for an existing --source checkout.
    if cli.dry_run {
        print_plan(&cli, &prefix, &garden);
        return Ok(());
    }

    // 3. Resolve a real source: an explicit --source checkout, an explicit
    //    --repo/--ref clone, or the baked repo + tag — never the current dir.
    //    Resolved *before* the gate: the gate reads the required rustc from the
    //    source's own manifest and probes rustc with `cwd = source` (M9).
    let source = resolve_source(&cli)?;

    // 4. Toolchain gate — refuse here, before anything is built or touched.
    let gate = Gate::probe(source.path())?;
    if !gate.is_ok() {
        println!("{}", gate::failure_message(&gate));
        anyhow::bail!("toolchain gate failed");
    }

    // 6. Build the program from source.
    build_program(source.path())?;

    // 7. Stage + atomically install the reconciled set (idempotent).
    install_set(source.path(), &prefix)?;

    // Record an explicit --source checkout at install, so a later
    // `softfig upgrade` / `softfig uninstall` can name the real source.
    if source.is_checkout() {
        source::record_source(&prefix, source.path())?;
    }

    // 8. Non-fatal environment checks (fuse3, PATH).
    check_fuse(&distro);
    check_path(&prefix);

    // 9. Consented, reversible integration steps.
    offer_unit(consent, source.path(), &supervisor, &prefix, &garden);
    offer_mcp(consent, &prefix);

    // 10. Hand off to `softfig onboard`.
    handoff(&prefix, &garden);
    Ok(())
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_bin_dir() -> PathBuf {
    home().join(".local/bin")
}

fn default_garden() -> PathBuf {
    home().join("soft-fig_garden")
}

/// Resolve a real source: an explicit `--source` checkout, an explicit
/// `--repo`/`--ref` clone, or the baked repo + tag — never the current dir.
/// The `--dry-run` plan: everything the install would do, nothing done.
fn print_plan(cli: &Cli, prefix: &Path, garden: &Path) {
    let described = source::describe(cli.source.as_deref(), cli.repo.as_deref(), cli.r#ref.as_deref(), None);
    println!("dry run — softfig-install would:");
    println!("  source        build {described}");
    match cli.source.as_deref().map(Gate::probe) {
        Some(Ok(gate)) if gate.is_ok() => println!("  toolchain     ok"),
        Some(Ok(gate)) => println!("  toolchain     FAILS — {}", gate::failure_message(&gate).lines().next().unwrap_or("")),
        Some(Err(e)) => println!("  toolchain     cannot check: {e}"),
        None => println!("  toolchain     checked after the clone"),
    }
    println!("  build         cargo build --release --locked");
    println!("  install       the installed set into {}", prefix.display());
    println!("  offer         the softfig-keeperd systemd user unit (--garden {})", garden.display());
    println!("  offer         the softfig-mcp registration with Claude Code");
    println!("  then          softfig onboard (garden at {})", garden.display());
    println!("nothing cloned, built or installed.");
}

fn resolve_source(cli: &Cli) -> Result<Source> {
    source::resolve(
        cli.source.as_deref(),
        cli.repo.as_deref(),
        cli.r#ref.as_deref(),
        None,
    )
}

/// `cargo build --release --locked` in the source root — the same build the
/// release workflow runs (`meta/spec-release.md` → "What CI must prove").
fn build_program(source: &Path) -> Result<()> {
    println!("building the program from source (cargo build --release --locked)…");
    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--locked")
        .current_dir(source)
        .status()
        .context("running cargo build")?;
    if !status.success() {
        anyhow::bail!("cargo build failed (exit {status})");
    }
    Ok(())
}

/// Stage the five freshly-built binaries into a same-filesystem temp dir and
/// atomically swap them into `prefix` (the shared [`stage_and_swap`] routine).
/// Idempotent: a prefix already carrying a consistent set at the
/// freshly-built version is a no-op.
fn install_set(source: &Path, prefix: &Path) -> Result<()> {
    match stage_and_swap(source, prefix, false)? {
        StageOutcome::Noop { version, .. } => {
            println!("already installed: {version} in {} — nothing to do", prefix.display());
        }
        StageOutcome::Swapped { .. } => {
            println!("installed: {}", SetReport::scan(prefix));
        }
    }
    Ok(())
}

/// Non-fatal fuse3 check — the daemon mounts its plaintext view over FUSE.
fn check_fuse(distro: &Distro) {
    let present = which("fusermount3") || Path::new("/dev/fuse").exists();
    if present {
        println!("fuse3 present.");
        return;
    }
    let hint = distro
        .fuse_package_command()
        .map(|c| format!(" — install it first ({c})"))
        .unwrap_or_default();
    println!("WARNING: fuse3 not found{hint} before starting the daemon.");
}

/// Non-fatal PATH check — `~/.local/bin` must be on PATH for `softfig` to work.
fn check_path(prefix: &Path) {
    let on_path = std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|d| d == prefix)
    });
    if !on_path {
        println!(
            "NOTE: {} is not on your PATH — add it to your shell profile.",
            prefix.display()
        );
    }
}

/// The consented, reversible systemd unit install.
fn offer_unit(
    consent: &mut dyn Consent,
    source: &Path,
    supervisor: &Supervisor,
    prefix: &Path,
    garden: &Path,
) {
    if *supervisor != Supervisor::SystemdUser {
        println!(
            "no systemd user bus — skipping the daemon unit offer \
             (start the daemon in the foreground instead)."
        );
        return;
    }
    let unit_src = source.join("packaging/systemd/softfig-keeperd.service");
    let template = match std::fs::read_to_string(&unit_src) {
        Ok(text) => text,
        Err(_) => {
            println!("unit file not found in source ({}) — skipping the unit offer.", unit_src.display());
            return;
        }
    };
    // Render the unit with the resolved prefix + garden — never the `%h`-based
    // template verbatim.
    let rendered = unit::render_unit(&template, prefix, garden);
    // The daemon binary the rendered unit will exec: verify it exists and is
    // executable BEFORE enabling, so a missing install is a clear skip, not a
    // silently broken enable.
    let Some(bin) = unit::exec_start(&rendered).map(PathBuf::from) else {
        println!("rendered unit has no ExecStart — skipping the unit offer.");
        return;
    };
    if !unit::is_executable(&bin) {
        println!(
            "{} is not an executable — skipping the unit offer (the daemon \
             binary must exist at the install prefix before it can be enabled).",
            bin.display()
        );
        return;
    }
    let offer = Offer {
        id: "systemd-unit",
        summary: "Install + enable the softfig-keeperd systemd user unit (auto-start the daemon at login)?".to_string(),
        undo: "systemctl --user disable --now softfig-keeperd.service && \
               rm ~/.config/systemd/user/softfig-keeperd.service"
            .to_string(),
    };
    if consent.ask(&offer) != Answer::Yes {
        println!("skipped unit install — start the daemon manually with: softfig daemon start");
        return;
    }
    let unit_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("systemd/user");
    if let Err(e) = install_unit(&rendered, &unit_dir) {
        println!("unit install failed: {e}");
        return;
    }
    // daemon-reload AFTER the write, BEFORE enable — systemd must load the
    // rendered unit we just wrote, not a stale cached copy. Both statuses are
    // checked: a failure is reported with the undo, never "unit enabled"
    // (report 081 item 1).
    let garden_exists = garden.is_dir();
    let enabled = systemctl(&["--user", "daemon-reload"])
        .and_then(|()| systemctl(&enable_args(garden_exists)));
    match enabled {
        Ok(()) if garden_exists => println!("unit enabled and started (reversible: {})", offer.undo),
        Ok(()) => println!(
            "unit enabled; it starts at your next login. Start it now, after \
             `softfig onboard` has created the garden: systemctl --user start \
             softfig-keeperd (reversible: {})",
            offer.undo
        ),
        Err(e) => println!("unit written but not enabled: {e}\n  undo: {}", offer.undo),
    }
}

/// `systemctl` arguments that enable the unit — with `--now` only when the
/// garden already exists. Started before `onboard` creates it, the daemon
/// boots against a path it cannot use (report 081 item 2; the AUR README's
/// install order).
fn enable_args(garden_exists: bool) -> Vec<&'static str> {
    let mut args = vec!["--user", "enable"];
    if garden_exists {
        args.push("--now");
    }
    args.push("softfig-keeperd.service");
    args
}

/// Run `systemctl <args>`, failing on a spawn error or a non-zero exit.
fn systemctl(args: &[&str]) -> std::result::Result<(), String> {
    match std::process::Command::new("systemctl").args(args).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("`systemctl {}` exited {status}", args.join(" "))),
        Err(e) => Err(format!("`systemctl {}` could not run: {e}", args.join(" "))),
    }
}

fn install_unit(rendered: &str, dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("softfig-keeperd.service"), rendered)?;
    Ok(())
}

/// The consented, reversible MCP registration (writes `~/.claude.json` via the
/// `claude` CLI — the same `claude mcp add --scope user` as onboard-device.sh).
fn offer_mcp(consent: &mut dyn Consent, prefix: &Path) {
    let bin = prefix.join("softfig-mcp");
    if !which("claude") {
        println!(
            "'claude' CLI not found — skipping MCP registration. \
             Register later with: claude mcp add --scope user softfig-mcp {}",
            bin.display()
        );
        return;
    }
    let offer = Offer {
        id: "mcp-registration",
        summary: "Register softfig-mcp with Claude Code (writes ~/.claude.json)?".to_string(),
        undo: "claude mcp remove --scope user softfig-mcp".to_string(),
    };
    if consent.ask(&offer) != Answer::Yes {
        println!(
            "skipped MCP registration — register later with: \
             claude mcp add --scope user softfig-mcp {}",
            bin.display()
        );
        return;
    }
    let status = std::process::Command::new("claude")
        .args(["mcp", "add", "--scope", "user", "softfig-mcp"])
        .arg(&bin)
        .status();
    match status {
        Ok(s) if s.success() => println!("registered softfig-mcp (reversible: {})", offer.undo),
        Ok(s) => println!("MCP registration exited {s}"),
        Err(e) => println!("MCP registration failed: {e}"),
    }
}

/// The hand-off: print the exact `softfig onboard` / unlock steps. (`softfig
/// onboard` is interactive — it needs a passphrase at a TTY — so the helper
/// prints it rather than exec-ing it and stealing the passphrase prompt.)
fn handoff(prefix: &Path, garden: &Path) {
    let softfig = prefix.join("softfig");
    println!();
    println!("Done. Next:");
    println!("  1. Scaffold the garden (interactive — needs a passphrase at a TTY):");
    println!("       {} onboard --garden-root {}", softfig.display(), garden.display());
    println!("  2. Unlock the session once per boot:");
    println!("       {} daemon unlock", softfig.display());
    println!("See docs/onboard-laptop.md for the full walkthrough.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Report 081 item 2: on a fresh box (no garden yet) the unit is enabled
    /// but not started; once the garden exists, `--now` starts it.
    #[test]
    fn the_unit_starts_now_only_when_the_garden_exists() {
        assert_eq!(enable_args(false), ["--user", "enable", "softfig-keeperd.service"]);
        assert_eq!(enable_args(true), ["--user", "enable", "--now", "softfig-keeperd.service"]);
    }

    /// Report 081 item 1: a failing `systemctl` is an error, not "enabled".
    #[test]
    fn a_failing_systemctl_is_an_error() {
        assert!(systemctl(&["--this-flag-does-not-exist"]).is_err());
    }
}
