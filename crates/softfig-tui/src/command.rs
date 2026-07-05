//! Command-palette parsing (`:` line). Pure; unit-tested.

use crate::forms::ActionKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Browse,
    History,
    Vault,
    Peers,
    Reveal,
    /// Open the "initiate pairing" overlay (`pair_begin`).
    Pair,
    /// Unpair the selected ring member (`pair_remove`).
    Unpair,
    /// Switch to the Backup tab (M5b `replica_status`).
    Backup,
    /// Open the "grant a host" overlay (`replica_grant`).
    Grant,
    /// Revoke the selected host's backup grant (`replica_revoke`).
    Revoke,
    /// Switch to the Deploy tab (M4 `deploy_plan`).
    Deploy,
    /// Apply the current deploy plan (`deploy_apply`, no force).
    Apply,
    Reload,
    Unlock,
    Quit,
    Help,
    Action(ActionKind),
    Unknown(String),
}

pub fn parse_command(input: &str) -> Command {
    let t = input.trim();
    match t {
        "browse" | "b" => Command::Browse,
        "history" | "log" | "h" => Command::History,
        "vault" | "v" => Command::Vault,
        "peers" => Command::Peers,
        "reveal" | "x" => Command::Reveal,
        "pair" => Command::Pair,
        "unpair" => Command::Unpair,
        "backup" => Command::Backup,
        "grant" => Command::Grant,
        "revoke" => Command::Revoke,
        "deploy" => Command::Deploy,
        "apply" => Command::Apply,
        "reload" | "r" => Command::Reload,
        "unlock" => Command::Unlock,
        "quit" | "q" => Command::Quit,
        "help" | "?" => Command::Help,
        other => {
            for k in ActionKind::ALL {
                if k.command_name() == other {
                    return Command::Action(k);
                }
            }
            Command::Unknown(other.to_string())
        }
    }
}

/// Names offered in the palette hint line.
pub fn command_hints() -> String {
    let mut names = vec![
        "browse", "history", "vault", "peers", "reveal", "pair", "unpair", "backup", "grant",
        "revoke", "deploy", "apply", "reload", "unlock", "quit", "help",
    ];
    for k in ActionKind::ALL {
        names.push(k.command_name());
    }
    names.join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_and_aliases() {
        assert_eq!(parse_command("history"), Command::History);
        assert_eq!(parse_command(" h "), Command::History);
        assert_eq!(parse_command("q"), Command::Quit);
        assert_eq!(parse_command("browse"), Command::Browse);
    }

    #[test]
    fn action_commands() {
        assert_eq!(
            parse_command("log_decision"),
            Command::Action(ActionKind::LogDecision)
        );
        assert_eq!(
            parse_command("replace"),
            Command::Action(ActionKind::ReplaceFile)
        );
    }

    #[test]
    fn vault_commands() {
        assert_eq!(parse_command("vault"), Command::Vault);
        assert_eq!(parse_command("v"), Command::Vault);
        assert_eq!(parse_command("reveal"), Command::Reveal);
        assert_eq!(parse_command("x"), Command::Reveal);
        assert_eq!(parse_command("seal"), Command::Action(ActionKind::VaultSeal));
        assert_eq!(
            parse_command("unseal"),
            Command::Action(ActionKind::VaultUnseal)
        );
    }

    #[test]
    fn peer_commands() {
        assert_eq!(parse_command("peers"), Command::Peers);
        assert_eq!(parse_command("pair"), Command::Pair);
        assert_eq!(parse_command("unpair"), Command::Unpair);
        assert!(command_hints().contains("pair"));
        assert!(command_hints().contains("peers"));
    }

    #[test]
    fn deploy_commands() {
        assert_eq!(parse_command("deploy"), Command::Deploy);
        assert_eq!(parse_command("apply"), Command::Apply);
        assert!(command_hints().contains("deploy"));
        assert!(command_hints().contains("apply"));
    }

    #[test]
    fn unknown_passthrough() {
        assert_eq!(parse_command("frobnicate"), Command::Unknown("frobnicate".into()));
    }
}
