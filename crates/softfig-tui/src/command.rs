//! Command-palette parsing (`:` line). Pure; unit-tested.

use crate::forms::ActionKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Browse,
    History,
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
    let mut names = vec!["browse", "history", "reload", "unlock", "quit", "help"];
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
            parse_command("propose"),
            Command::Action(ActionKind::ProposeDocUpdate)
        );
    }

    #[test]
    fn unknown_passthrough() {
        assert_eq!(parse_command("frobnicate"), Command::Unknown("frobnicate".into()));
    }
}
