//! VCS ignore rules — the single source of truth for "what the garden VCS
//! excludes from snapshots and commits."
//!
//! Some directories in the garden working tree are not garden knowledge and
//! must never enter a snapshot or trigger a commit:
//!
//! * `.softfig` — the VCS's own state (objects, sqlite db). M2a moves it out
//!   of the FUSE mount, but the skip stays as a guard for legacy in-tree
//!   gardens and as defense in depth.
//! * `.claude` — Claude Code's per-session scratch (the permission allowlist
//!   in `.claude/settings.local.json`, which grows every session). Agent
//!   scratch, not garden knowledge.
//!
//! These two are **built-in and un-ignorable** — listing them in
//! `.softfigignore` is redundant and removing them is impossible.
//!
//! On top of the built-ins, the user may exclude additional **top-level**
//! names via a `.softfigignore` file at the garden root (see [`IGNORE_FILE`]).
//! This is a strict, additive extension of the same predicate — there is no
//! way to *un*-ignore a built-in, and there is still exactly one place a rule
//! is evaluated ([`Ignore::is_ignored`]).
//!
//! Matching is by first path component (top-level directory name), mirroring
//! git's simplest anchored ignore entries. Every working-tree walk in the
//! codebase routes through [`Ignore::is_ignored`] so the committer's walker
//! (`walk.rs`), the daemon's dirty-set accumulator, and the Layer B scan all
//! agree on the same exclusion set — there is exactly one place to add a rule.
//!
//! `.softfigignore` is itself a normal tracked file (it is not in the ignore
//! set), so the ignore set is versioned with the garden and replicates to
//! backup hosts. Each consumer loads it *fresh* (the walker on every commit,
//! the watcher on every event), so an edit takes effect on the next commit /
//! filesystem event with no daemon restart — unlike `keeper.toml`, which is
//! read once at unlock. See `journal/decisions/decision-garden-vcs-ignore.md`.

use std::path::Path;

/// Top-level directory names excluded from the VCS unconditionally. See the
/// module note for why each is here. These are built-in and cannot be
/// un-ignored; user additions live in [`IGNORE_FILE`].
pub const IGNORED_TOP_LEVEL: &[&str] = &[".softfig", ".claude"];

/// The user-editable ignore file at the garden root. Each non-empty,
/// non-comment line names one additional top-level directory/file to exclude.
pub const IGNORE_FILE: &str = ".softfigignore";

/// True if a repo-relative path is excluded by the **built-in** defaults,
/// i.e. its first path component is one of [`IGNORED_TOP_LEVEL`]. This is the
/// one place the built-in rule lives; user overrides are layered on top in
/// [`Ignore::is_ignored`].
///
/// The path must be relative to the garden root; callers walking absolute
/// paths strip the root prefix first.
pub fn is_ignored(rel: &Path) -> bool {
    rel.components()
        .next()
        .map(|c| IGNORED_TOP_LEVEL.iter().any(|name| c.as_os_str() == *name))
        .unwrap_or(false)
}

/// The exclusion set for one garden: the built-in defaults plus any
/// user-listed top-level names from `<garden_root>/.softfigignore`. This is
/// the single predicate every working-tree walk consults.
///
/// Build it with [`Ignore::load`] (reads the file from a garden root) or
/// [`Ignore::builtin`] (defaults only, for contexts without a root in scope).
#[derive(Debug, Clone, Default)]
pub struct Ignore {
    /// Extra top-level names from `.softfigignore`. The built-ins
    /// ([`IGNORED_TOP_LEVEL`]) are always applied and are *not* stored here.
    user_top_level: Vec<String>,
}

impl Ignore {
    /// Built-in defaults only — `.softfigignore` is not consulted. Use where
    /// there is no garden root in scope (and in tests of the built-in set).
    pub fn builtin() -> Self {
        Self::default()
    }

    /// Load the exclusion set for the garden rooted at `garden_root`: the
    /// built-ins plus any top-level names listed in
    /// `<garden_root>/.softfigignore`. An absent, empty, or unreadable file
    /// yields the built-ins only — i.e. exactly the pre-`.softfigignore`
    /// behavior.
    pub fn load(garden_root: &Path) -> Self {
        match std::fs::read_to_string(garden_root.join(IGNORE_FILE)) {
            Ok(contents) => Self::from_contents(&contents),
            Err(_) => Self::default(),
        }
    }

    /// Build the exclusion set from already-in-hand `.softfigignore`
    /// contents, the built-ins plus the parsed user names. The in-memory
    /// twin of [`Ignore::load`] for callers that already hold the bytes —
    /// e.g. the FUSE driver reconstructing a commit snapshot, which must
    /// read the ignore file from its own tip/overlay state rather than
    /// `std::fs`-reading back through the mount it serves (the 2026-06-21
    /// commit-path deadlock). Empty/comment-only contents yield the
    /// built-ins only, exactly like an absent file.
    pub fn from_contents(contents: &str) -> Self {
        Self {
            user_top_level: parse(contents),
        }
    }

    /// True if a repo-relative path is excluded — its first component is a
    /// built-in default ([`is_ignored`]) or a user-listed name. User names
    /// are purely additive: a built-in can never be un-ignored.
    pub fn is_ignored(&self, rel: &Path) -> bool {
        if is_ignored(rel) {
            return true;
        }
        match rel.components().next() {
            Some(c) => self
                .user_top_level
                .iter()
                .any(|name| c.as_os_str() == name.as_str()),
            None => false,
        }
    }
}

/// Parse `.softfigignore` contents into a list of top-level names. Blank
/// lines and `#` comments are dropped; surrounding whitespace and a single
/// trailing `/` (a gitignore-style directory marker) are trimmed. v1 honors
/// **top-level names only** — a line is matched against the first path
/// component, so an interior `/` (a nested path) simply never matches.
fn parse(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.strip_suffix('/').unwrap_or(line).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softfig_dir_is_ignored() {
        assert!(is_ignored(Path::new(".softfig")));
        assert!(is_ignored(Path::new(".softfig/objects/aa/bb")));
    }

    #[test]
    fn claude_dir_is_ignored() {
        assert!(is_ignored(Path::new(".claude")));
        assert!(is_ignored(Path::new(".claude/settings.local.json")));
    }

    #[test]
    fn garden_content_is_not_ignored() {
        assert!(!is_ignored(Path::new("journal/decisions/decision-x.md")));
        assert!(!is_ignored(Path::new("a.md")));
        // Only the top-level component matters: a `.claude` name deeper in
        // the tree, or a similar-but-different name, stays tracked.
        assert!(!is_ignored(Path::new("projects/.claude-notes.md")));
        assert!(!is_ignored(Path::new("docs/.claude/x")));
    }

    #[test]
    fn empty_path_is_not_ignored() {
        assert!(!is_ignored(Path::new("")));
    }

    #[test]
    fn builtin_matches_the_free_predicate() {
        let ig = Ignore::builtin();
        assert!(ig.is_ignored(Path::new(".softfig")));
        assert!(ig.is_ignored(Path::new(".claude/settings.local.json")));
        assert!(!ig.is_ignored(Path::new("journal/decisions/decision-x.md")));
        assert!(!ig.is_ignored(Path::new("scratch/notes.md")));
    }

    #[test]
    fn softfigignore_extends_the_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(IGNORE_FILE),
            "# personal exclusions\nscratch\nbuild/\n\n",
        )
        .unwrap();
        let ig = Ignore::load(dir.path());

        // User-listed top-level names (and everything under them) are ignored.
        assert!(ig.is_ignored(Path::new("scratch")));
        assert!(ig.is_ignored(Path::new("scratch/notes.md")));
        assert!(ig.is_ignored(Path::new("build/out/x"))); // trailing-slash tolerated
        // Built-ins still apply.
        assert!(ig.is_ignored(Path::new(".softfig")));
        assert!(ig.is_ignored(Path::new(".claude")));
        // Unlisted content stays tracked.
        assert!(!ig.is_ignored(Path::new("journal/decisions/decision-x.md")));
        assert!(!ig.is_ignored(Path::new("scratchpad.md"))); // not the `scratch` dir
    }

    #[test]
    fn absent_or_empty_file_is_builtin_behavior() {
        // Absent file.
        let dir = tempfile::tempdir().unwrap();
        let ig = Ignore::load(dir.path());
        assert!(ig.is_ignored(Path::new(".softfig")));
        assert!(!ig.is_ignored(Path::new("scratch")));

        // Comment-and-whitespace-only file ⇒ no user names.
        std::fs::write(dir.path().join(IGNORE_FILE), "# nothing here\n   \n").unwrap();
        let ig = Ignore::load(dir.path());
        assert!(!ig.is_ignored(Path::new("scratch")));
        assert!(ig.is_ignored(Path::new(".claude")));
    }

    #[test]
    fn nested_path_lines_do_not_match_a_top_level_component() {
        // v1 honors top-level names only; an interior `/` never matches a
        // single path component, so the line is inert (documented behavior).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IGNORE_FILE), "projects/scratch\n").unwrap();
        let ig = Ignore::load(dir.path());
        assert!(!ig.is_ignored(Path::new("projects/scratch/x.md")));
        assert!(!ig.is_ignored(Path::new("projects")));
    }
}
