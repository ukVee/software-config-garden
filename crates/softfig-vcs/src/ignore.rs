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
//! Matching is by first path component (top-level directory name), mirroring
//! git's simplest anchored ignore entries. Every working-tree walk in the
//! codebase routes through [`is_ignored`] so the committer's walker
//! (`walk.rs`), the daemon's dirty-set accumulator, and the Layer B scan all
//! agree on the same exclusion set — there is exactly one place to add a rule.
//!
//! A user-editable `.softfigignore` override file (full gitignore globbing) is
//! a deliberate future addition; today the set is a built-in default. See
//! `journal/decisions/decision-garden-vcs-ignore.md`.

use std::path::Path;

/// Top-level directory names excluded from the VCS. See the module note for
/// why each is here. This is the one place to add an exclusion.
pub const IGNORED_TOP_LEVEL: &[&str] = &[".softfig", ".claude"];

/// True if a repo-relative path is excluded from the VCS, i.e. its first path
/// component is one of [`IGNORED_TOP_LEVEL`].
///
/// The path must be relative to the garden root; callers walking absolute
/// paths strip the root prefix first.
pub fn is_ignored(rel: &Path) -> bool {
    rel.components()
        .next()
        .map(|c| IGNORED_TOP_LEVEL.iter().any(|name| c.as_os_str() == *name))
        .unwrap_or(false)
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
}
