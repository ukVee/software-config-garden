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
    /// Switch to the Shares tab (M5d `shared_subtree_list`).
    Shares,
    /// Open the "share a folder" overlay (`shared_subtree_add`).
    Share,
    /// Un-share the selected subtree (`shared_subtree_remove`).
    Unshare,
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
        "shares" => Command::Shares,
        "share" => Command::Share,
        "unshare" => Command::Unshare,
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
    command_menu()
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>()
        .join("  ")
}

/// The palette's tappable rows: `(name, one-line description)` in a stable
/// order, so a touch user can pick a command instead of typing it. Parsing the
/// picked name goes through the same [`parse_command`] the typed path uses.
pub fn command_menu() -> Vec<(&'static str, &'static str)> {
    let mut rows: Vec<(&'static str, &'static str)> = vec![
        ("browse", "switch to Browse"),
        ("history", "switch to History"),
        ("vault", "switch to Vault"),
        ("peers", "switch to Peers"),
        ("backup", "switch to Backup"),
        ("deploy", "preview the deploy plan"),
        ("shares", "switch to Shares"),
        ("reveal", "reveal the selected sealed file"),
        ("pair", "pair a device"),
        ("unpair", "unpair the selected device"),
        ("grant", "grant a host backup access"),
        ("revoke", "revoke a host's backup grant"),
        ("apply", "apply the deploy plan"),
        ("share", "share a folder"),
        ("unshare", "un-share the selected folder"),
        ("reload", "refresh the current view"),
        ("unlock", "unlock the vault"),
        ("help", "show the key help"),
        ("quit", "quit"),
    ];
    for k in ActionKind::ALL {
        rows.push((k.command_name(), k.title()));
    }
    rows
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
    fn share_commands() {
        assert_eq!(parse_command("shares"), Command::Shares);
        assert_eq!(parse_command("share"), Command::Share);
        assert_eq!(parse_command("unshare"), Command::Unshare);
        assert!(command_hints().contains("shares"));
        assert!(command_hints().contains("unshare"));
    }

    #[test]
    fn unknown_passthrough() {
        assert_eq!(parse_command("frobnicate"), Command::Unknown("frobnicate".into()));
    }
}
