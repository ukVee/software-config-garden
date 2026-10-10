//! The opencode 2.x **permission floor**: the one ordered rule list both opencode
//! config generators emit — the interactive `softfig growlight start --opencode`
//! config (`softfig-cli`'s `growlight_backend::opencode_config`) and each headless
//! fleet member's config (`softfig-growlightd`'s `opencode_preapproval`).
//!
//! It lives here for the reason the baton parser does: those two crates share
//! `softfig-ipc` and nothing else (growlightd depends on no other softfig crate),
//! so the floor is built ONCE rather than re-expressed twice and left to drift.
//! The postures differ only where [`Posture`] says they do.
//!
//! ## How opencode 2.x evaluates these (probe-proven, `opencode-v2-repin` slice 001)
//!
//! - A rule is `{action, resource, effect}` and the **last match wins**. A
//!   resource pattern is anchored, `*` matches any run of characters *including*
//!   `/`, and `?` matches one; nothing else is special. So `**` is just `*` twice.
//! - The resolved list runs: opencode's built-ins (`* * allow`, `external_directory
//!   * ask`, the `.env` asks, allows for opencode's own dirs) → the global
//!   `~/.config/opencode` file (on this device it grants `~/projects/**`,
//!   `~/dotfiles/**`, … as `external_directory allow`) → **the config's top-level
//!   `permissions`** → the agent's own `permissions`.
//! - Top-level `permissions` apply to **every** agent the server loads, not just
//!   ours: the built-in `general` / `explore` subagents a `subagent` call spawns,
//!   and the `build` / `plan` primaries a TUI user can switch to. That is why the
//!   generators emit this list at the top level and not on their agent: a subagent
//!   runs on its *own* agent's rules, so a reset placed only on our agent would be
//!   one `subagent` call away from every global grant.
//! - An in-cwd path is matched as a **cwd-relative** resource (`inbox/x.md`); only
//!   a path outside cwd is absolute, and only that one is gated by
//!   `external_directory` (with the resource `<parent dir>/*`). The garden is the
//!   cwd on both launch paths.
//!
//! ## The order is the design
//!
//! 1. **Reset.** `external_directory * deny` (headless) / `ask` (interactive)
//!    lands after the global file, so no global grant survives it. It also drops
//!    the built-in allow on `~/.config/opencode/*`, a self-escalation path into
//!    the human's own opencode config, which is never granted back.
//! 2. **Reach, the loop's own state.** The runtime root (the baton is the loop's
//!    only carried state and every handoff rewrites it) and the claude-memory tree.
//! 3. **Reach, read-only: opencode's own output dirs** (`shell/*/*`,
//!    `tool-output/*` under its data dir), copied from the built-ins the reset
//!    removed, so a truncated tool result stays readable. Read-only because no
//!    `edit` rule below allows them. The data dir's root (which holds `auth.json`)
//!    and `/tmp/opencode` (shared scratch) are not re-granted.
//! 4. **Read.** `read *` is allowed, then opencode's own `.env` caution is
//!    restated, because the explicit `read *` would otherwise override it.
//! 5. **Tools.** `shell` and every `softfig-mcp` verb (an MCP call's action is
//!    `<server>_<tool>`, so `softfig-mcp*` matches).
//! 6. **Garden write guard.** `edit * deny`. An absolute garden glob would never
//!    match (in-cwd resources are relative), so the guard is the universal deny and
//!    everything writable is re-opened after it. Garden mutations go through
//!    softfig-mcp (the house rule); this is the config half of that rule.
//! 7. **Interactive only: `edit /* ask`.** Every absolute resource is outside the
//!    cwd, so this re-opens code-repo edits to the human's prompt without touching
//!    the garden, whose resources are relative.
//! 8. **Write floor.** `edit` on the runtime root and the memory tree.
//!
//! Folder grants (step 2 of `decision-opencode-v2-fleet-safety-order`) append
//! after rule 8, so they are always the narrowest and win. The shell is not a
//! boundary under any of this: `shell` runs with full host authority.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// A rule's effect. Serialized lowercase, as opencode spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Ask,
    Deny,
}

/// One opencode 2.x permission rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    pub action: String,
    pub resource: String,
    pub effect: Effect,
}

impl Rule {
    fn new(action: &str, resource: impl Into<String>, effect: Effect) -> Self {
        Self {
            action: action.to_string(),
            resource: resource.into(),
            effect,
        }
    }
}

/// Who answers a permission prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// A headless fleet member (`opencode run`). Nobody can answer a prompt
    /// (opencode auto-rejects it), so anything not granted is denied outright.
    Headless,
    /// The interactive loop (`softfig growlight start --opencode`). The human
    /// answers, so anything not granted is asked rather than denied.
    Interactive,
}

impl Posture {
    /// The effect for a resource the floor does not grant.
    fn ungranted(self) -> Effect {
        match self {
            Posture::Headless => Effect::Deny,
            Posture::Interactive => Effect::Ask,
        }
    }
}

/// The directories the floor grants. Every one must be absolute, UTF-8, free of
/// opencode's pattern metacharacters, and not `/`; see [`floor`].
#[derive(Debug, Clone, Copy)]
pub struct Floor<'a> {
    /// The growlight runtime grant root (`$XDG_CONFIG_HOME/softfig`).
    pub runtime_root: &'a Path,
    /// The claude-memory tree (`~/.claude/projects`).
    pub claude_projects: &'a Path,
    /// opencode's data dir (see [`opencode_data_dir`]).
    pub opencode_data: &'a Path,
}

/// A floor directory that cannot be turned into a safe rule. Generation fails
/// closed on it: the caller must not launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorError {
    /// Which [`Floor`] field.
    pub what: &'static str,
    pub path: PathBuf,
    pub reason: &'static str,
}

impl fmt::Display for FloorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "opencode permission floor: {} {} {}",
            self.what,
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for FloorError {}

/// The MCP action pattern granting every `softfig-mcp` verb.
pub const MCP_ACTION: &str = "softfig-mcp*";

/// Build the ordered floor for `posture` (see the module doc for why each rule is
/// where it is). **Fail-closed**: a floor directory that is relative, non-UTF-8,
/// carries a `*` / `?`, or is `/` is an error, never a rule. A relative root would
/// match in-cwd resources and open a garden write hole; a metacharacter would widen
/// the grant past the directory named.
pub fn floor(posture: Posture, dirs: &Floor<'_>) -> Result<Vec<Rule>, FloorError> {
    let runtime = tree(checked("runtime_root", dirs.runtime_root)?);
    let memory = tree(checked("claude_projects", dirs.claude_projects)?);
    let data = checked("opencode_data", dirs.opencode_data)?;
    let ungranted = posture.ungranted();

    use Effect::{Allow, Ask, Deny};
    let mut rules = vec![
        // 1. reset
        Rule::new("external_directory", "*", ungranted),
        // 2. reach: the loop's own state
        Rule::new("external_directory", runtime.as_str(), Allow),
        Rule::new("external_directory", memory.as_str(), Allow),
        // 3. reach, read-only: opencode's own output dirs (the built-in shapes)
        Rule::new("external_directory", format!("{data}/shell/*/*"), Allow),
        Rule::new("external_directory", format!("{data}/tool-output/*"), Allow),
        // 4. read, with opencode's own .env caution restated
        Rule::new("read", "*", Allow),
        Rule::new("read", "*.env", ungranted),
        Rule::new("read", "*.env.*", ungranted),
        Rule::new("read", "*.env.example", Allow),
        // 5. tools
        Rule::new("shell", "*", Allow),
        Rule::new(MCP_ACTION, "*", Allow),
        // 6. the garden write guard
        Rule::new("edit", "*", Deny),
    ];
    // 7. interactive: code-repo edits go to the human; garden resources are
    // relative, so `/*` never reaches them.
    if posture == Posture::Interactive {
        rules.push(Rule::new("edit", "/*", Ask));
    }
    // 8. the write floor
    rules.push(Rule::new("edit", runtime, Allow));
    rules.push(Rule::new("edit", memory, Allow));
    Ok(rules)
}

/// opencode's data dir, `$XDG_DATA_HOME/opencode` (fallback
/// `~/.local/share/opencode`), resolved the way opencode resolves it. Pure: the
/// caller passes the environment in.
pub fn opencode_data_dir(xdg_data_home: Option<&OsStr>, home: &Path) -> PathBuf {
    let base = match xdg_data_home {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home.join(".local/share"),
    };
    base.join("opencode")
}

/// `root` as a rule-safe string, or why not.
fn checked<'a>(what: &'static str, root: &'a Path) -> Result<&'a str, FloorError> {
    let err = |reason| FloorError {
        what,
        path: root.to_path_buf(),
        reason,
    };
    let s = root.to_str().ok_or_else(|| err("is not UTF-8"))?;
    if !root.is_absolute() {
        return Err(err("is not absolute"));
    }
    if s.contains(['*', '?']) {
        return Err(err("contains an opencode pattern metacharacter (* or ?)"));
    }
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        return Err(err("is the filesystem root"));
    }
    Ok(s)
}

/// The recursive pattern for a granted directory.
fn tree(root: &str) -> String {
    format!("{root}/**")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> Floor<'static> {
        Floor {
            runtime_root: Path::new("/home/u/.config/softfig"),
            claude_projects: Path::new("/home/u/.claude/projects"),
            opencode_data: Path::new("/home/u/.local/share/opencode"),
        }
    }

    fn table(rules: &[Rule]) -> Vec<(String, String, Effect)> {
        rules
            .iter()
            .map(|r| (r.action.clone(), r.resource.clone(), r.effect))
            .collect()
    }

    fn rule(action: &str, resource: &str, effect: Effect) -> (String, String, Effect) {
        (action.to_string(), resource.to_string(), effect)
    }

    #[test]
    fn the_headless_floor_is_exactly_this_ordered_list() {
        use Effect::{Allow, Deny};
        let got = table(&floor(Posture::Headless, &dirs()).unwrap());
        assert_eq!(
            got,
            vec![
                rule("external_directory", "*", Deny),
                rule("external_directory", "/home/u/.config/softfig/**", Allow),
                rule("external_directory", "/home/u/.claude/projects/**", Allow),
                rule("external_directory", "/home/u/.local/share/opencode/shell/*/*", Allow),
                rule("external_directory", "/home/u/.local/share/opencode/tool-output/*", Allow),
                rule("read", "*", Allow),
                rule("read", "*.env", Deny),
                rule("read", "*.env.*", Deny),
                rule("read", "*.env.example", Allow),
                rule("shell", "*", Allow),
                rule("softfig-mcp*", "*", Allow),
                rule("edit", "*", Deny),
                rule("edit", "/home/u/.config/softfig/**", Allow),
                rule("edit", "/home/u/.claude/projects/**", Allow),
            ],
        );
    }

    #[test]
    fn the_interactive_floor_asks_where_headless_denies_and_reopens_external_edits() {
        use Effect::{Allow, Ask, Deny};
        let got = table(&floor(Posture::Interactive, &dirs()).unwrap());
        assert_eq!(
            got,
            vec![
                rule("external_directory", "*", Ask),
                rule("external_directory", "/home/u/.config/softfig/**", Allow),
                rule("external_directory", "/home/u/.claude/projects/**", Allow),
                rule("external_directory", "/home/u/.local/share/opencode/shell/*/*", Allow),
                rule("external_directory", "/home/u/.local/share/opencode/tool-output/*", Allow),
                rule("read", "*", Allow),
                rule("read", "*.env", Ask),
                rule("read", "*.env.*", Ask),
                rule("read", "*.env.example", Allow),
                rule("shell", "*", Allow),
                rule("softfig-mcp*", "*", Allow),
                rule("edit", "*", Deny),
                rule("edit", "/*", Ask),
                rule("edit", "/home/u/.config/softfig/**", Allow),
                rule("edit", "/home/u/.claude/projects/**", Allow),
            ],
        );
    }

    #[test]
    fn the_two_postures_share_one_floor_and_differ_only_where_a_human_can_answer() {
        let h = floor(Posture::Headless, &dirs()).unwrap();
        let i = floor(Posture::Interactive, &dirs()).unwrap();
        // Drop the one interactive-only rule; what remains lines up rule for rule,
        // and every difference is headless `deny` against interactive `ask`.
        let i: Vec<_> = i.into_iter().filter(|r| !(r.action == "edit" && r.resource == "/*")).collect();
        assert_eq!(h.len(), i.len());
        for (h, i) in h.iter().zip(&i) {
            assert_eq!((&h.action, &h.resource), (&i.action, &i.resource));
            if h.effect != i.effect {
                assert_eq!((h.effect, i.effect), (Effect::Deny, Effect::Ask), "{h:?} vs {i:?}");
            }
        }
    }

    #[test]
    fn the_reset_comes_first_and_the_guard_precedes_every_edit_allow() {
        for posture in [Posture::Headless, Posture::Interactive] {
            let rules = floor(posture, &dirs()).unwrap();
            assert_eq!((rules[0].action.as_str(), rules[0].resource.as_str()), ("external_directory", "*"));
            let guard = rules
                .iter()
                .position(|r| r.action == "edit" && r.resource == "*" && r.effect == Effect::Deny)
                .expect("the garden write guard is emitted");
            for (n, r) in rules.iter().enumerate().filter(|(_, r)| r.action == "edit") {
                if r.effect != Effect::Deny {
                    assert!(n > guard, "{posture:?}: edit allow/ask before the guard: {r:?}");
                }
            }
            // The last edit rule is never a bare `* deny`, or opencode hides the
            // edit tool altogether (its tool filter checks exactly that).
            let last_edit = rules.iter().rev().find(|r| r.action == "edit").unwrap();
            assert_ne!(last_edit.resource, "*", "{posture:?}");
        }
    }

    #[test]
    fn opencodes_own_config_and_secrets_are_never_granted() {
        for posture in [Posture::Headless, Posture::Interactive] {
            for r in floor(posture, &dirs()).unwrap() {
                if r.effect == Effect::Deny {
                    continue;
                }
                assert!(!r.resource.contains("/.config/opencode"), "{posture:?}: {r:?}");
                assert_ne!(r.resource, "/home/u/.local/share/opencode/**", "auth.json lives there");
                assert!(!r.resource.starts_with("/tmp"), "{posture:?}: {r:?}");
                assert!(!r.resource.starts_with("/home/u/.claude/*"), "{posture:?}: {r:?}");
            }
        }
    }

    #[test]
    fn rules_serialize_as_opencodes_action_resource_effect_objects() {
        let v = serde_json::to_value(floor(Posture::Headless, &dirs()).unwrap()).unwrap();
        assert_eq!(
            v[0],
            serde_json::json!({"action": "external_directory", "resource": "*", "effect": "deny"}),
        );
    }

    #[test]
    fn a_trailing_slash_does_not_double_up() {
        let d = Floor {
            runtime_root: Path::new("/rt/"),
            ..dirs()
        };
        let rules = floor(Posture::Headless, &d).unwrap();
        assert!(rules.iter().any(|r| r.resource == "/rt/**"), "{rules:?}");
    }

    #[test]
    fn an_unsafe_floor_directory_fails_closed() {
        for (bad, why) in [
            ("growlight", "is not absolute"),
            ("", "is not absolute"),
            ("/home/*/x", "metacharacter"),
            ("/home/u?", "metacharacter"),
            ("/", "filesystem root"),
        ] {
            let d = Floor {
                runtime_root: Path::new(bad),
                ..dirs()
            };
            let err = floor(Posture::Headless, &d).unwrap_err();
            assert_eq!(err.what, "runtime_root");
            assert!(err.reason.contains(why), "{bad:?}: {err}");
        }
        let d = Floor {
            opencode_data: Path::new("rel/opencode"),
            ..dirs()
        };
        assert_eq!(floor(Posture::Interactive, &d).unwrap_err().what, "opencode_data");
    }

    #[test]
    fn opencode_data_dir_follows_xdg_then_home() {
        let home = Path::new("/home/u");
        assert_eq!(opencode_data_dir(None, home), Path::new("/home/u/.local/share/opencode"));
        assert_eq!(
            opencode_data_dir(Some(OsStr::new("")), home),
            Path::new("/home/u/.local/share/opencode"),
        );
        assert_eq!(
            opencode_data_dir(Some(OsStr::new("/xdg/data")), home),
            Path::new("/xdg/data/opencode"),
        );
    }
}
