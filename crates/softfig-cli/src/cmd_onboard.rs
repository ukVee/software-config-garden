//! `softfig onboard` — the first-run wizard. Scaffolds a fresh garden from
//! the embedded default-layout skeleton, inits the Vault, and writes a
//! born-in-FUSE genesis commit. This is a thin TTY frontend over the
//! frontend-agnostic `softfig-onboard` core (M-onboard pick #3); a future
//! MCP tool wraps the same `onboard()` entry point.
//!
//! Flow (pick #4): resolve garden_root / state_root / machine → optional
//! concept-dir customization → prompt passphrase twice → stamp + genesis →
//! print the recovery phrase ONCE + the next-step commands. With no TTY we
//! stop before the passphrase step, since onboarding can't proceed without
//! one.

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use softfig_onboard::{onboard, OnboardOptions, CONCEPT_DIRS};

#[derive(Args, Debug)]
pub struct OnboardArgs {
    /// Garden root (the eventual FUSE mount path). Defaults to
    /// `~/soft-fig_garden`.
    #[arg(long)]
    pub garden_root: Option<PathBuf>,
    /// On-disk encrypted state root. Defaults to
    /// `$XDG_DATA_HOME/softfig/<garden-dir-name>/` (or `~/.local/share/...`).
    #[arg(long)]
    pub state_root: Option<PathBuf>,
    /// Machine identity recorded in the routing `CLAUDE.md`. Defaults to
    /// the system hostname.
    #[arg(long)]
    pub machine: Option<String>,
    /// Interactively toggle which concept dirs the scaffold includes.
    /// Without this flag, the full default set is scaffolded.
    #[arg(long)]
    pub customize: bool,
    /// Accept all defaults non-interactively (skips concept-dir prompts).
    /// Still requires a TTY for the passphrase.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(args: OnboardArgs) -> Result<()> {
    let garden_root = match args.garden_root {
        Some(p) => p,
        None => default_garden_root()?,
    };
    let state_root = match args.state_root {
        Some(p) => p,
        None => default_state_root(&garden_root)?,
    };
    let machine = match args.machine {
        Some(m) => m,
        None => default_machine(),
    };
    let date = today_iso();

    // Refuse early if a garden's state is already present.
    if state_root.join(".softfig/db.sqlite").exists() {
        return Err(anyhow!(
            "a garden already exists at state root {} — refusing to clobber it",
            state_root.display()
        ));
    }

    println!("soft-fig onboarding");
    println!("  garden_root  {}", garden_root.display());
    println!("  state_root   {}", state_root.display());
    println!("  machine      {machine}");
    println!();

    let interactive = std::io::stdin().is_terminal() && !args.yes;

    // Concept-dir selection. Default = all; `--customize` (when interactive)
    // lets the user trim the toggleable set.
    let include = if args.customize && interactive {
        Some(prompt_concept_dirs()?)
    } else {
        if args.customize {
            println!("(--customize ignored: no interactive terminal; scaffolding the full default)");
        }
        None
    };

    let opts = OnboardOptions {
        garden_root: garden_root.clone(),
        state_root: state_root.clone(),
        machine,
        date,
        include,
    };

    // Without a TTY we can't safely prompt for a passphrase. Per pick #4,
    // stop here with a clear message rather than failing cryptically.
    if !std::io::stdin().is_terminal() {
        println!("No interactive terminal detected.");
        println!(
            "Onboarding needs a passphrase, which must be entered at a TTY. Re-run \
             `softfig onboard` in a terminal."
        );
        return Ok(());
    }

    let pass1 = prompt_passphrase("Choose a master passphrase: ")?;
    let pass2 = prompt_passphrase("Confirm passphrase: ")?;
    if pass1 != pass2 {
        return Err(anyhow!("passphrases do not match"));
    }

    println!();
    println!("Scaffolding skeleton + writing genesis commit…");
    let outcome = onboard(&opts, pass1.as_bytes())
        .context("onboarding failed")?;

    print_recovery(&outcome.recovery_phrase);

    println!();
    println!("Garden onboarded.");
    println!("  files in genesis : {}", outcome.file_count);
    println!("  genesis commit   : {}", outcome.genesis);
    println!("  garden_root      : {}", outcome.garden_root.display());
    println!("  state_root       : {}", outcome.state_root.display());
    println!();
    println!("Next steps:");
    println!(
        "  1. Start the daemon (mounts the garden via FUSE):\n     softfig daemon start --garden {}",
        outcome.garden_root.display()
    );
    println!("  2. Unlock the session (prompts for your passphrase):\n     softfig daemon unlock");
    println!(
        "  3. Browse your garden at {} and start filling the concept-dir stubs.",
        outcome.garden_root.display()
    );
    Ok(())
}

fn prompt_concept_dirs() -> Result<BTreeSet<String>> {
    println!("Concept dirs (answer y/n; default y for each):");
    let mut chosen = BTreeSet::new();
    for dir in CONCEPT_DIRS {
        let keep = prompt_yes_no(&format!("  include {dir}/?"), true)?;
        if keep {
            chosen.insert((*dir).to_string());
        }
    }
    Ok(chosen)
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    use std::io::Write;
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{prompt} {hint} ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("could not read answer from stdin")?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(match ans.as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    })
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("could not read passphrase from tty")
}

fn print_recovery(phrase: &str) {
    println!();
    println!("==============================================================");
    println!("RECOVERY PHRASE — store this somewhere safe and OFFLINE.");
    println!("It is the ONLY way to unlock this vault if you forget your");
    println!("passphrase. It is shown ONCE and never written to disk in");
    println!("plaintext. Anyone who learns it can unlock your vault.");
    println!("--------------------------------------------------------------");
    println!("    {phrase}");
    println!("==============================================================");
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("$HOME not set"))
}

fn default_garden_root() -> Result<PathBuf> {
    Ok(home_dir()?.join("soft-fig_garden"))
}

/// `$XDG_DATA_HOME/softfig/<garden-dir-name>/`, falling back to
/// `~/.local/share/softfig/<garden-dir-name>/`. Uses the garden directory
/// name (not the repo_id, which doesn't exist until after creation) — the
/// documented simplest pick for born-in-FUSE state placement.
fn default_state_root(garden_root: &std::path::Path) -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home_dir()?.join(".local/share"),
    };
    let name = garden_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("soft-fig_garden");
    Ok(base.join("softfig").join(name))
}

fn default_machine() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Today's UTC date as `YYYY-MM-DD`. Hand-rolled civil-from-days (Howard
/// Hinnant's algorithm) so onboarding needs no chrono/time dependency for a
/// single placeholder.
fn today_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_known_epochs() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18_993), (2022, 1, 1));
        // 2026-05-26
        assert_eq!(civil_from_days(20_599), (2026, 5, 26));
    }
}
