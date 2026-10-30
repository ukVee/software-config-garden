//! The declarative slot layout (claude-login-switcher slice 006; this was
//! slice 002's per-member overlay map).
//!
//! A slot is a real `CLAUDE_CONFIG_DIR` in the profile store. For each
//! top-level name Claude Code keeps in a config dir, this map says how a slot
//! holds it:
//!
//! * [`PathClass::Shared`]: an absolute symlink `<slot>/<name>` →
//!   `~/.claude/<name>`, so configuration and memory are one tree across
//!   accounts. `projects/` is Shared, so auto-memory and transcripts never
//!   split per account (review 047 S12). `add`/`migrate` create a link only
//!   when the shared source exists: a dangling dir link would make Claude's
//!   `mkdir` fail.
//! * [`PathClass::PerSlot`]: mutable runtime state that Claude creates and
//!   owns inside each slot. softfig never pre-creates or touches it.
//! * [`PathClass::SlotOwned`]: an account-bound real file. softfig places it
//!   exactly once (`migrate` moves it in, `add` seeds `.claude.json`), and
//!   Claude owns it from then on. A credential is moved, never copied.
//! * [`PathClass::Ignored`]: names known to appear that no slot needs.
//!
//! `softfig claude-login doctor` diffs every name actually present in
//! `~/.claude/` and in each slot against this map at runtime. An
//! unclassified name is how a Claude Code upgrade that adds new state shows
//! up (review 047 S11).

/// How a slot holds one top-level config-dir name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathClass {
    /// Absolute symlink into the real `~/.claude/<name>`.
    Shared,
    /// Claude-created runtime state, private to each slot.
    PerSlot,
    /// Account-bound real file, placed once by softfig, then Claude-owned.
    SlotOwned,
    /// Known, but deliberately not part of a slot.
    Ignored,
}

/// One entry in the slot layout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudePath {
    /// Name directly under the config dir, with no trailing slash.
    pub name: &'static str,
    pub class: PathClass,
}

/// The layout, in a stable order for readable output.
pub(crate) fn slot_layout() -> &'static [ClaudePath] {
    use PathClass::*;
    &[
        // --- Shared (symlink → real ~/.claude/<name>) ----------------------
        ClaudePath { name: "settings.json", class: Shared },
        ClaudePath { name: "settings.local.json", class: Shared },
        ClaudePath { name: "keybindings.json", class: Shared },
        ClaudePath { name: "statusline-command.sh", class: Shared },
        ClaudePath { name: "CLAUDE.md", class: Shared },
        ClaudePath { name: "plugins", class: Shared },
        ClaudePath { name: "skills", class: Shared },
        ClaudePath { name: "agents", class: Shared },
        ClaudePath { name: "commands", class: Shared },
        ClaudePath { name: "projects", class: Shared },

        // --- Per-slot (Claude creates; softfig never touches) --------------
        ClaudePath { name: "history.jsonl", class: PerSlot },
        ClaudePath { name: "cache", class: PerSlot },
        ClaudePath { name: "sessions", class: PerSlot },
        ClaudePath { name: "tasks", class: PerSlot },
        ClaudePath { name: "todos", class: PerSlot },
        ClaudePath { name: "telemetry", class: PerSlot },
        ClaudePath { name: "jobs", class: PerSlot },
        ClaudePath { name: "paste-cache", class: PerSlot },
        ClaudePath { name: "file-history", class: PerSlot },
        ClaudePath { name: "session-env", class: PerSlot },
        ClaudePath { name: "shell-snapshots", class: PerSlot },
        ClaudePath { name: "state", class: PerSlot },
        ClaudePath { name: "plans", class: PerSlot },
        ClaudePath { name: "backups", class: PerSlot },
        ClaudePath { name: "stats-cache.json", class: PerSlot },
        ClaudePath { name: ".last-cleanup", class: PerSlot },
        ClaudePath { name: ".last-update-result.json", class: PerSlot },
        // The OAuth refresh lock (proper-lockfile). It lives beside the
        // credentials it guards, so every consumer of a slot shares it.
        ClaudePath { name: ".oauth_refresh.lock", class: PerSlot },
        // `daemon*` family: Claude Code's background-session daemon state.
        ClaudePath { name: "daemon", class: PerSlot },
        ClaudePath { name: "daemon.json", class: PerSlot },
        ClaudePath { name: "daemon.lock", class: PerSlot },
        ClaudePath { name: "daemon.log", class: PerSlot },
        ClaudePath { name: "daemon.status.json", class: PerSlot },

        // --- Slot-owned (placed once, then Claude's) -----------------------
        ClaudePath { name: ".credentials.json", class: SlotOwned },
        // Under the `home` slot this file sits at `~/.claude.json`, beside
        // `~/.claude/` rather than inside it.
        ClaudePath { name: ".claude.json", class: SlotOwned },

        // --- Ignored (known, not part of a slot) ---------------------------
        //
        // `chrome/`: legacy claude-in-chrome extension cache.
        // `downloads/`: destination for `/download`.
        ClaudePath { name: "chrome", class: Ignored },
        ClaudePath { name: "downloads", class: Ignored },
    ]
}

/// A top-level name's class, or `None` when the layout doesn't know it.
pub(crate) fn classify(name: &str) -> Option<PathClass> {
    slot_layout()
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.class)
}

/// The names a slot links into `~/.claude/`.
pub(crate) fn shared_names() -> impl Iterator<Item = &'static str> {
    slot_layout()
        .iter()
        .filter(|e| e.class == PathClass::Shared)
        .map(|e| e.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A duplicate would mean one entry silently shadows another.
    #[test]
    fn slot_layout_has_unique_names() {
        let mut seen: HashSet<&str> = HashSet::new();
        for e in slot_layout() {
            assert!(seen.insert(e.name), "duplicate slot-layout entry: {}", e.name);
        }
    }

    /// Every top-level name seen in this device's `~/.claude/` (2026-10-22,
    /// Claude Code 2.1.308) plus what a fresh config dir grows. A fixed
    /// fixture keeps the test reproducible; `doctor`'s runtime diff is what
    /// catches a name added after this list.
    const KNOWN_SHAPE: &[&str] = &[
        "backups", "cache", "chrome", "CLAUDE.md", "daemon", "daemon.lock",
        "daemon.log", "daemon.status.json", "downloads", "file-history",
        "history.jsonl", "jobs", "paste-cache", "plans", "plugins", "projects",
        "session-env", "sessions", "settings.json", "settings.local.json",
        "shell-snapshots", "skills", "state", "stats-cache.json",
        "statusline-command.sh", "tasks", ".credentials.json", ".last-cleanup",
        ".last-update-result.json", ".claude.json",
    ];

    #[test]
    fn every_known_name_is_classified() {
        let uncovered: Vec<&str> = KNOWN_SHAPE
            .iter()
            .copied()
            .filter(|n| classify(n).is_none())
            .collect();
        assert!(uncovered.is_empty(), "unclassified config-dir names: {uncovered:?}");
    }

    /// S12: one `projects/` tree, so auto-memory never splits per account.
    #[test]
    fn projects_is_shared() {
        assert_eq!(classify("projects"), Some(PathClass::Shared));
    }

    /// The two account-bound files are never links: a symlinked credential
    /// is refused by Claude's strict store and broken by rename-on-refresh.
    #[test]
    fn account_files_are_slot_owned() {
        assert_eq!(classify(".credentials.json"), Some(PathClass::SlotOwned));
        assert_eq!(classify(".claude.json"), Some(PathClass::SlotOwned));
        assert!(!shared_names().any(|n| n.starts_with(".c")));
    }
}
