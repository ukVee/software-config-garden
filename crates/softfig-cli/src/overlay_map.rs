//! The declarative overlay map (claude-login-switcher slice 002).
//!
//! For each top-level name under `~/.claude/`, we classify how the per-member
//! overlay HOME at `~/.config/softfig/growlight/agents/<id>/home/.claude/`
//! materializes it. Three classes do real work and one is an explicit opt-out:
//!
//! * [`PathClass::Shared`] — a symlink into the real `~/.claude/<name>`. Used
//!   for read-mostly content (settings, plugins, skills, statusline, backups).
//!   The symlink is absolute, because the overlay HOME is NOT `~/.claude/`.
//! * [`PathClass::PerMemberDir`] / [`PathClass::PerMemberFile`] — a real path
//!   inside the overlay, created empty on first refresh and preserved
//!   afterwards. Used for mutable per-member state (projects, history, cache,
//!   sessions, tasks, telemetry, daemon state).
//! * [`PathClass::PerSession`] — a symlink retargeted per-session by
//!   growlightd (slice 003+). In this slice the symlink initially points at
//!   the top-level active profile (`~/.claude/credentials.d/<slot>.json` or,
//!   if the top-level is a plain file, `~/.claude/.credentials.json`).
//! * [`PathClass::Ignored`] — known top-level names we deliberately do not
//!   materialize in the overlay (e.g. the Chrome extension's cache,
//!   `downloads/`). Letting them exist in the map keeps the inventory test
//!   total: a new Claude Code addition that we didn't opt out of trips the
//!   coverage check.
//!
//! `~/.claude/credentials.d/` is deliberately NOT in the map: it is implicitly
//! shared via the `.credentials.json` symlink target and is owned by slice
//! 001's profile store, not by the overlay.

/// How an entry under `~/.claude/` is materialized in the overlay HOME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathClass {
    /// Absolute symlink into the real `~/.claude/<name>`.
    Shared,
    /// A real directory inside the overlay, preserved across refreshes.
    PerMemberDir,
    /// A real empty file inside the overlay, preserved across refreshes.
    PerMemberFile,
    /// A symlink that growlightd retargets per-session. For this slice the
    /// initial target is the top-level active profile.
    PerSession,
    /// Known to exist in `~/.claude/` but intentionally not in the overlay.
    Ignored,
}

/// One entry in the overlay map.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudePath {
    /// Name directly under `~/.claude/`, with no trailing slash.
    pub name: &'static str,
    pub class: PathClass,
}

/// The map, in a stable order for readable `--dry-run` plans. Any top-level
/// name under `~/.claude/` must be covered here, as a real class or as
/// [`PathClass::Ignored`]; a new Claude Code addition that is not covered
/// trips the inventory test.
pub(crate) fn overlay_map() -> &'static [ClaudePath] {
    use PathClass::*;
    &[
        // --- Shared (symlink → real ~/.claude/<name>) ----------------------
        ClaudePath { name: "settings.json", class: Shared },
        ClaudePath { name: "settings.local.json", class: Shared },
        ClaudePath { name: "statusline-command.sh", class: Shared },
        ClaudePath { name: "plugins", class: Shared },
        ClaudePath { name: "skills", class: Shared },
        ClaudePath { name: "shell-snapshots", class: Shared },
        ClaudePath { name: "backups", class: Shared },
        ClaudePath { name: ".last-cleanup", class: Shared },
        ClaudePath { name: ".last-update-result.json", class: Shared },
        ClaudePath { name: "CLAUDE.md", class: Shared },

        // --- Per-member (mutable, preserved) -------------------------------
        ClaudePath { name: "projects", class: PerMemberDir },
        ClaudePath { name: "history.jsonl", class: PerMemberFile },
        ClaudePath { name: "cache", class: PerMemberDir },
        ClaudePath { name: "sessions", class: PerMemberDir },
        ClaudePath { name: "tasks", class: PerMemberDir },
        ClaudePath { name: "telemetry", class: PerMemberDir },
        ClaudePath { name: "jobs", class: PerMemberDir },
        ClaudePath { name: "paste-cache", class: PerMemberDir },
        ClaudePath { name: "file-history", class: PerMemberDir },
        ClaudePath { name: "session-env", class: PerMemberDir },
        ClaudePath { name: "state", class: PerMemberDir },
        ClaudePath { name: "plans", class: PerMemberDir },
        ClaudePath { name: "stats-cache.json", class: PerMemberFile },
        // `daemon*` family: Claude Code's daemon lifecycle state.
        ClaudePath { name: "daemon", class: PerMemberDir },
        ClaudePath { name: "daemon.lock", class: PerMemberFile },
        ClaudePath { name: "daemon.log", class: PerMemberFile },
        ClaudePath { name: "daemon.status.json", class: PerMemberFile },

        // --- Per-session (symlink retargeted per-session; slice 003+) ------
        ClaudePath { name: ".credentials.json", class: PerSession },

        // --- Ignored (known but intentionally not materialized) ------------
        //
        // `chrome/`: legacy claude-in-chrome extension cache; the overlay
        // doesn't need its own copy and we don't want to share one either.
        // `downloads/`: destination for `/download`; whichever member wrote
        // the file already has the content elsewhere.
        ClaudePath { name: "chrome", class: Ignored },
        ClaudePath { name: "downloads", class: Ignored },
    ]
}

/// Look up a top-level name's class, if the map covers it. The inventory
/// test uses this; refresh-members walks `overlay_map()` directly, so the
/// helper is test-only for now.
#[cfg(test)]
pub(crate) fn classify(name: &str) -> Option<PathClass> {
    overlay_map()
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The map must have unique names: a duplicate would mean one entry
    /// silently shadows another, which is exactly the kind of drift the
    /// inventory check is here to prevent.
    #[test]
    fn overlay_map_has_unique_names() {
        let m = overlay_map();
        let mut seen: HashSet<&str> = HashSet::new();
        for e in m {
            assert!(seen.insert(e.name), "duplicate overlay entry: {}", e.name);
        }
    }

    /// A known-shape fixture of every real-world top-level `~/.claude/` name
    /// as of 2026-10-21. Every one must resolve through the map; a Claude
    /// Code addition that isn't yet classified trips this assertion loudly.
    ///
    /// The real-device inventory smoke lives in the slice doc's
    /// `## Deferred verification` section — this unit test uses a FIXED
    /// fixture, not the live `~/.claude/`, so the test is reproducible on
    /// any host.
    const KNOWN_SHAPE: &[&str] = &[
        // --- real-world shared ---
        "settings.json",
        "settings.local.json",
        "statusline-command.sh",
        "plugins",
        "skills",
        "shell-snapshots",
        "backups",
        ".last-cleanup",
        ".last-update-result.json",
        "CLAUDE.md",
        // --- real-world per-member ---
        "projects",
        "history.jsonl",
        "cache",
        "sessions",
        "tasks",
        "telemetry",
        "jobs",
        "paste-cache",
        "file-history",
        "session-env",
        "state",
        "plans",
        "stats-cache.json",
        "daemon",
        "daemon.lock",
        "daemon.log",
        "daemon.status.json",
        // --- real-world per-session ---
        ".credentials.json",
        // --- real-world ignored ---
        "chrome",
        "downloads",
    ];

    #[test]
    fn every_known_name_is_classified() {
        let mut uncovered: Vec<&str> = Vec::new();
        for name in KNOWN_SHAPE {
            if classify(name).is_none() {
                uncovered.push(name);
            }
        }
        assert!(
            uncovered.is_empty(),
            "unclassified ~/.claude/ names: {uncovered:?}\n\
             add them to overlay_map::overlay_map() (as Shared / PerMemberDir / \
             PerMemberFile / PerSession / Ignored) and to KNOWN_SHAPE above."
        );
    }

    /// `credentials.d/` must NOT be in the overlay map — slice 001 owns it,
    /// and the overlay reaches it through `.credentials.json`'s target.
    #[test]
    fn credentials_d_is_not_in_the_map() {
        assert!(
            classify("credentials.d").is_none(),
            "credentials.d/ belongs to slice 001's profile store, not the overlay"
        );
    }
}
