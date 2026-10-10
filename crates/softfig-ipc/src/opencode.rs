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
//! 8. **Write floor.** `edit` on the runtime root, then the memory tree under
//!    the session's [`MemoryPolicy`]: `allow`, or `deny` when read-only. The deny
//!    is explicit rather than left to rule 6 so read-only also holds under the
//!    interactive posture, where rule 7 would otherwise put the write to the human.
//!
//! Folder grants (step 2 of `decision-opencode-v2-fleet-safety-order`) append
//! after rule 8, so they are always the narrowest and win. The shell is not a
//! boundary under any of this: `shell` runs with full host authority.
//!
//! ## Session context (`opencode-v2-repin` slice 005)
//!
//! opencode 2.x loads `AGENTS.md` only (no `CLAUDE.md` fallback, no
//! `instructions`), so a session would never see the garden map or the
//! claude-memory index Claude Code injects. [`context`] renders what each
//! generator appends to its agent's `system` prompt, all by `{file:}` reference
//! (house rule 1, never copied): the garden root `CLAUDE.md`, the garden's memory
//! rules (`growlight/memory-read.md`, plus `memory-write.md` only when the session
//! may write), and the memory index `MEMORY.md`.
//!
//! How opencode 2.0.24 expands `{file:…}` (probe-proven on a private server,
//! slice 005): at config load, by position, in one pass, over the **raw config
//! text**. The content is trimmed and lands verbatim (`$&`, `$'` and the like
//! included). A `{file:}` or `{env:}` literal *inside* an injected file is never
//! expanded. But a path naming a missing file fails the whole location (every API
//! call returns HTTP 500), so [`context`] injects only files that exist and are
//! readable when it runs, which is once per spawn. And because the path is read
//! out of the raw JSON text, [`file_ref`] refuses any path JSON would escape or
//! the `{file:[^}]+}` pattern would cut short.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
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

/// Whether a session may write the claude-memory tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPolicy {
    /// Read and write (the interactive loop).
    ReadWrite,
    /// Read only: the floor denies the write and [`context`] leaves out the write
    /// rules (fleet members, until memory writes are tracked and revertable).
    ReadOnly,
}

/// The directories the floor grants, and the memory policy it applies to one of
/// them. Every directory must be absolute, UTF-8, free of opencode's pattern
/// metacharacters, and not `/`; see [`floor`].
#[derive(Debug, Clone, Copy)]
pub struct Floor<'a> {
    /// The growlight runtime grant root (`$XDG_CONFIG_HOME/softfig`).
    pub runtime_root: &'a Path,
    /// The claude-memory tree (`~/.claude/projects`).
    pub claude_projects: &'a Path,
    /// opencode's data dir (see [`opencode_data_dir`]).
    pub opencode_data: &'a Path,
    /// Whether the memory tree is writable (rule 8).
    pub memory: MemoryPolicy,
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
    let memory_writes = match dirs.memory {
        MemoryPolicy::ReadWrite => Allow,
        MemoryPolicy::ReadOnly => Deny,
    };
    rules.push(Rule::new("edit", memory, memory_writes));
    Ok(rules)
}

/// The garden's memory rules, read half: injected into every session.
pub const MEMORY_READ_RULES: &str = "growlight/memory-read.md";
/// The garden's memory rules, write half: injected only under
/// [`MemoryPolicy::ReadWrite`].
pub const MEMORY_WRITE_RULES: &str = "growlight/memory-write.md";

/// The longest project slug Claude Code uses verbatim. A longer one is cut and
/// suffixed with a hash of the path, which [`claude_memory_dir`] does not
/// reproduce.
const CLAUDE_SLUG_MAX: usize = 200;

/// What [`context`] renders.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// The garden root: the session's cwd, and the path Claude Code derives the
    /// memory directory from.
    pub garden_root: &'a Path,
    /// The claude-memory tree (`~/.claude/projects`).
    pub claude_projects: &'a Path,
    /// Whether the session may write memory: decides whether the write rules are
    /// injected. Pass the same value the session's [`Floor`] carries.
    pub memory: MemoryPolicy,
}

/// A path that cannot be a safe `{file:}` reference. Generation fails closed on
/// it: the caller must not launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextError {
    /// Which file.
    pub what: &'static str,
    pub path: PathBuf,
    pub reason: &'static str,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "opencode session context: {} {} {}",
            self.what,
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for ContextError {}

/// `path` as an opencode `{file:…}` reference, or why it can't be one.
/// **Fail-closed**: opencode reads the path out of the raw config text, so a
/// character JSON escapes (`"`, `\`, a control character) would name a different
/// file, and a `{` or `}` would cut the reference short. Either way the location
/// fails to load or loads the wrong text. A relative path would resolve against
/// the config file's directory, not the garden.
pub fn file_ref(what: &'static str, path: &Path) -> Result<String, ContextError> {
    let err = |reason| ContextError {
        what,
        path: path.to_path_buf(),
        reason,
    };
    let s = path.to_str().ok_or_else(|| err("is not UTF-8"))?;
    if !path.is_absolute() {
        return Err(err("is not absolute"));
    }
    if s.chars().any(|c| matches!(c, '{' | '}' | '"' | '\\') || c.is_control()) {
        return Err(err("contains a character opencode's {file:} cannot carry"));
    }
    Ok(format!("{{file:{s}}}"))
}

/// The claude-memory directory Claude Code keeps for a session rooted at `cwd`:
/// `<claude_projects>/<slug>/memory`, where the slug is `cwd` with every
/// character outside `[A-Za-z0-9]` replaced by `-` (per UTF-16 unit, as Claude
/// Code's JavaScript does it). So `/home/u/soft-fig_garden` gives
/// `-home-u-soft-fig-garden`. `None` when `cwd` is not UTF-8, or its slug is long
/// enough that Claude Code would hash it.
pub fn claude_memory_dir(claude_projects: &Path, cwd: &Path) -> Option<PathBuf> {
    let s = cwd.to_str()?;
    let s = match s.trim_end_matches('/') {
        "" => "/",
        trimmed => trimmed,
    };
    let slug: String = s
        .encode_utf16()
        .map(|u| match char::from_u32(u32::from(u)) {
            Some(c) if c.is_ascii_alphanumeric() => c,
            _ => '-',
        })
        .collect();
    (slug.len() <= CLAUDE_SLUG_MAX).then(|| claude_projects.join(slug).join("memory"))
}

/// Render the session context each generator appends to its agent's `system`
/// prompt (see the module doc). Each file is referenced only if it exists and is
/// readable now, so a fresh install with no `MEMORY.md` (or a garden whose pillar
/// predates the memory rules) still generates. Returns an empty string when there
/// is nothing to inject.
///
/// Order: the garden map, then the memory section (when the memory directory can
/// be derived): the read rules, the write rules (read-write only), the directory,
/// and the index.
pub fn context(ctx: &Context<'_>) -> Result<String, ContextError> {
    let mut parts = Vec::new();

    let map = ctx.garden_root.join("CLAUDE.md");
    if readable(&map) {
        parts.push(format!(
            "Contents of `{}` (the garden map and house rules, loaded at session start):\n\n{}",
            map.display(),
            file_ref("garden map", &map)?,
        ));
    }

    if let Some(dir) = claude_memory_dir(ctx.claude_projects, ctx.garden_root) {
        let read_rules = ctx.garden_root.join(MEMORY_READ_RULES);
        if readable(&read_rules) {
            parts.push(file_ref("memory read rules", &read_rules)?);
        }
        let write_rules = ctx.garden_root.join(MEMORY_WRITE_RULES);
        if ctx.memory == MemoryPolicy::ReadWrite && readable(&write_rules) {
            parts.push(file_ref("memory write rules", &write_rules)?);
        }
        let index = dir.join("MEMORY.md");
        parts.push(if readable(&index) {
            format!(
                "Your memory directory is `{}`. Contents of its `MEMORY.md` (the memory \
                 index, loaded at session start):\n\n{}",
                dir.display(),
                file_ref("memory index", &index)?,
            )
        } else {
            format!(
                "Your memory directory is `{}`. It has no `MEMORY.md` yet: no memories \
                 have been saved for this garden.",
                dir.display(),
            )
        });
    }

    Ok(parts.join("\n\n"))
}

/// A regular file this process can open. opencode reads it moments later; one it
/// can't read would fail the whole location.
fn readable(path: &Path) -> bool {
    File::open(path)
        .and_then(|f| f.metadata())
        .is_ok_and(|m| m.is_file())
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
            memory: MemoryPolicy::ReadWrite,
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
    fn read_only_memory_flips_exactly_the_memory_write_rule_to_deny() {
        for posture in [Posture::Headless, Posture::Interactive] {
            let rw = floor(posture, &dirs()).unwrap();
            let ro = floor(
                posture,
                &Floor {
                    memory: MemoryPolicy::ReadOnly,
                    ..dirs()
                },
            )
            .unwrap();
            // Same list, same order; one effect differs. That is what keeps the
            // fleet's eventual flip to read-write a one-line change.
            assert_eq!(rw.len(), ro.len(), "{posture:?}");
            let diffs: Vec<_> = rw.iter().zip(&ro).filter(|(a, b)| a != b).collect();
            assert_eq!(diffs.len(), 1, "{posture:?}: {diffs:?}");
            let (a, b) = diffs[0];
            assert_eq!((a.action.as_str(), a.resource.as_str()), ("edit", "/home/u/.claude/projects/**"));
            assert_eq!((a.effect, b.effect), (Effect::Allow, Effect::Deny));
            // The memory write rule is the last one that matches a memory path, so
            // under read-only even the interactive `edit /* ask` can't reopen it,
            // while the reach (and `read *`) stay, so the index stays readable.
            let last = ro.last().unwrap();
            assert_eq!((last.resource.as_str(), last.effect), ("/home/u/.claude/projects/**", Effect::Deny));
            assert!(ro.iter().any(|r| r.action == "external_directory"
                && r.resource == "/home/u/.claude/projects/**"
                && r.effect == Effect::Allow));
        }
    }

    #[test]
    fn the_memory_dir_slug_matches_claude_codes() {
        let projects = Path::new("/home/u/.claude/projects");
        let dir = |cwd: &str| claude_memory_dir(projects, Path::new(cwd));
        // Both shapes observed in ~/.claude/projects on this device: `/` and `_`
        // (anything outside [A-Za-z0-9]) become `-`.
        assert_eq!(
            dir("/home/ukv/soft-fig_garden").unwrap(),
            Path::new("/home/u/.claude/projects/-home-ukv-soft-fig-garden/memory"),
        );
        assert_eq!(
            dir("/home/ukv/projects/software-config_garden").unwrap(),
            Path::new("/home/u/.claude/projects/-home-ukv-projects-software-config-garden/memory"),
        );
        assert_eq!(dir("/g/").unwrap(), dir("/g").unwrap(), "a trailing slash is not part of the cwd");
        assert_eq!(dir("/").unwrap(), Path::new("/home/u/.claude/projects/-/memory"));
        // Per UTF-16 unit, as JavaScript's replace sees the string: one `-` for a
        // BMP character, two for a surrogate pair.
        assert!(dir("/g/caf\u{e9}").unwrap().ends_with("-g-caf-/memory"));
        assert!(dir("/g/\u{1f331}").unwrap().ends_with("-g---/memory"));
        // Past 200 characters Claude Code hashes the slug; not reproduced.
        let long = format!("/{}", "a".repeat(199));
        assert!(dir(&long).is_some(), "exactly 200 is used verbatim");
        assert!(dir(&format!("{long}a")).is_none());
    }

    #[test]
    fn a_file_ref_refuses_what_opencodes_raw_text_scan_would_mangle() {
        assert_eq!(file_ref("x", Path::new("/g/CLAUDE.md")).unwrap(), "{file:/g/CLAUDE.md}");
        assert_eq!(file_ref("x", Path::new("/g/caf\u{e9} x.md")).unwrap(), "{file:/g/caf\u{e9} x.md}");
        for (bad, why) in [
            ("CLAUDE.md", "not absolute"),
            ("/g}/x.md", "cannot carry"),
            ("/g{/x.md", "cannot carry"),
            ("/g\"/x.md", "cannot carry"),
            ("/g\\/x.md", "cannot carry"),
            ("/g\n/x.md", "cannot carry"),
        ] {
            let err = file_ref("garden map", Path::new(bad)).unwrap_err();
            assert_eq!(err.what, "garden map");
            assert!(err.reason.contains(why), "{bad:?}: {err}");
        }
        use std::os::unix::ffi::OsStrExt;
        let non_utf8 = Path::new(OsStr::from_bytes(b"/g/\xff.md"));
        assert!(file_ref("x", non_utf8).unwrap_err().reason.contains("UTF-8"));
    }

    /// A temporary garden + claude-projects tree for [`context`].
    struct Tree {
        _tmp: tempfile::TempDir,
        garden: PathBuf,
        projects: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let garden = tmp.path().join("garden");
            let projects = tmp.path().join("claude/projects");
            std::fs::create_dir_all(garden.join("growlight")).unwrap();
            Self { _tmp: tmp, garden, projects }
        }
        fn memory_dir(&self) -> PathBuf {
            claude_memory_dir(&self.projects, &self.garden).unwrap()
        }
        fn put(&self, path: &Path) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x\n").unwrap();
        }
        fn full(&self) -> &Self {
            self.put(&self.garden.join("CLAUDE.md"));
            self.put(&self.garden.join(MEMORY_READ_RULES));
            self.put(&self.garden.join(MEMORY_WRITE_RULES));
            self.put(&self.memory_dir().join("MEMORY.md"));
            self
        }
        fn render(&self, memory: MemoryPolicy) -> String {
            context(&Context {
                garden_root: &self.garden,
                claude_projects: &self.projects,
                memory,
            })
            .unwrap()
        }
    }

    #[test]
    fn the_context_references_the_map_the_rules_and_the_index_in_order() {
        let t = Tree::new();
        t.full();
        let (g, m) = (t.garden.display(), t.memory_dir().display().to_string());
        assert_eq!(
            t.render(MemoryPolicy::ReadWrite),
            format!(
                "Contents of `{g}/CLAUDE.md` (the garden map and house rules, loaded at session start):\n\n\
                 {{file:{g}/CLAUDE.md}}\n\n\
                 {{file:{g}/growlight/memory-read.md}}\n\n\
                 {{file:{g}/growlight/memory-write.md}}\n\n\
                 Your memory directory is `{m}`. Contents of its `MEMORY.md` (the memory index, \
                 loaded at session start):\n\n\
                 {{file:{m}/MEMORY.md}}"
            ),
        );
    }

    #[test]
    fn a_read_only_session_gets_the_read_half_only() {
        let t = Tree::new();
        t.full();
        let ro = t.render(MemoryPolicy::ReadOnly);
        assert!(ro.contains(MEMORY_READ_RULES), "{ro}");
        assert!(!ro.contains(MEMORY_WRITE_RULES), "{ro}");
        assert!(ro.contains("/MEMORY.md}"), "a read-only session still sees the index: {ro}");
        // Nothing else moves.
        let rw = t.render(MemoryPolicy::ReadWrite);
        let write_ref = format!("\n\n{{file:{}}}", t.garden.join(MEMORY_WRITE_RULES).display());
        assert_eq!(rw.replacen(&write_ref, "", 1), ro);
    }

    #[test]
    fn only_files_that_exist_are_referenced_so_a_fresh_install_still_generates() {
        // Nothing but the dirs: no map, no rules, no index. opencode would 500 the
        // whole location on a `{file:}` naming a missing file.
        let t = Tree::new();
        let got = t.render(MemoryPolicy::ReadWrite);
        assert!(!got.contains("{file:"), "{got}");
        assert_eq!(
            got,
            format!(
                "Your memory directory is `{}`. It has no `MEMORY.md` yet: no memories have \
                 been saved for this garden.",
                t.memory_dir().display(),
            ),
        );
        // A directory where a file should be is not a file opencode can read.
        std::fs::create_dir_all(t.garden.join("CLAUDE.md")).unwrap();
        std::fs::create_dir_all(t.memory_dir().join("MEMORY.md")).unwrap();
        assert!(!t.render(MemoryPolicy::ReadWrite).contains("{file:"));
    }

    #[test]
    fn a_garden_path_opencode_cannot_reference_fails_closed() {
        let t = Tree::new();
        let garden = t.garden.with_file_name("gar}den");
        t.put(&garden.join("CLAUDE.md"));
        let err = context(&Context {
            garden_root: &garden,
            claude_projects: &t.projects,
            memory: MemoryPolicy::ReadWrite,
        })
        .unwrap_err();
        assert_eq!(err.what, "garden map");
        assert!(err.to_string().starts_with("opencode session context: garden map "), "{err}");
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
