//! The item-doc metadata lines — `> Model:`, `> Fleet:`, `> Grants:`,
//! `> Worktree:` — and the ONE scanner every reader and guard goes through
//! (task 074, review 042 G74-6 / G74-11).
//!
//! A metadata line is a blockquote line `> <key>: <value>`: the key is the text
//! before the first `:`, compared case-insensitively, and the value is the rest,
//! trimmed. Two reads are built on that one line shape:
//!
//! - [`field`] — what a resolver reads: the FIRST line for a key, anywhere in
//!   the doc, skipping lines inside a ```` ``` ```` / `~~~` fenced block, so a
//!   doc that shows a marker as an example does not declare it. growlightd's
//!   claim hold ([`crate::fleet_marker`]), the repo lookup
//!   ([`crate::item_repo::worktree_field`]) and the model resolver
//!   ([`crate::model_choice::item_model_field`]) are each a filter over it.
//! - [`reserved_field`] / [`reserved_lines`] — what a guard reads: every line
//!   for a key, fenced or not. A member-write guard compares these raw lines
//!   AND the resolved [`field`] before and after a write, so neither an edit to
//!   a fenced line nor a fence opened or closed around a real one slips past.
//!
//! Before this module the readers carried three scanners with two fence rules
//! (`> Model:` read fenced lines, `> Fleet:` / `> Worktree:` skipped them), so a
//! guard comparing raw lines could pass a write that changed what a resolver
//! read: inserting a fence line above `> Worktree:` left every raw line intact
//! and the declaration gone.

/// The `> Model:` key (lowercase, as the scanner compares it).
pub const MODEL: &str = "model";
/// The `> Fleet:` key.
pub const FLEET: &str = "fleet";
/// The `> Grants:` key.
pub const GRANTS: &str = "grants";
/// The `> Worktree:` key.
pub const WORKTREE: &str = "worktree";

/// `line` as a metadata line: its key (trimmed, case as written) and value
/// (trimmed), or `None` when it is not a blockquote `key: value` line.
fn metadata_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim_start().strip_prefix('>')?;
    let (key, value) = rest.trim().split_once(':')?;
    Some((key.trim(), value.trim()))
}

/// Whether `line` opens or closes a fenced code block.
fn is_fence(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

/// The value of the first `> <key>:` line in `doc` outside fenced code,
/// trimmed — `Some("")` for a line with no value, `None` when there is no such
/// line. The first line wins even when its value is empty, so every key reads
/// the same way; each resolver decides what an empty or particular value means.
pub fn field<'a>(doc: &'a str, key: &str) -> Option<&'a str> {
    let mut fenced = false;
    for line in doc.lines() {
        if is_fence(line) {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        if let Some((k, value)) = metadata_line(line)
            && k.eq_ignore_ascii_case(key)
        {
            return Some(value);
        }
    }
    None
}

/// The first `> <key>:` metadata line in `text` whose key is one of `keys`, as
/// that key — fenced or not, value ignored (an empty `> Model:` counts). The
/// guard-side read: any line a resolver could ever read is a line this finds.
pub fn reserved_field(text: &str, keys: &[&'static str]) -> Option<&'static str> {
    text.lines().find_map(|line| {
        let (key, _) = metadata_line(line)?;
        keys.iter().copied().find(|k| key.eq_ignore_ascii_case(k))
    })
}

/// Every `> <key>:` metadata line in `text` whose key is one of `keys`, in
/// order and trimmed, fenced or not — each line [`reserved_field`] would
/// report. A guard compares these before and after a write.
pub fn reserved_lines<'a>(text: &'a str, keys: &[&'static str]) -> Vec<&'a str> {
    text.lines()
        .filter(|line| reserved_field(line, keys).is_some())
        .map(str::trim)
        .collect()
}

/// `model` → `Model`: a key as refusal text and docs spell it.
pub fn display_key(key: &str) -> String {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_is_the_first_blockquote_line_outside_a_fence() {
        let doc = "# t\n\n> Last reviewed: 2026-10-20\n> Worktree: /a\n> Worktree: /b\n";
        assert_eq!(field(doc, WORKTREE), Some("/a"), "the first line wins");
        assert_eq!(field("  >  WORKTREE :  /a  \n", WORKTREE), Some("/a"), "case and spacing");
        assert_eq!(field("```\n> Model: flash\n```\n", MODEL), None, "a fenced example");
        assert_eq!(field("~~~\n> Fleet: no\n~~~\n> Fleet: yes\n", FLEET), Some("yes"));
        assert_eq!(field("```\n> Fleet: no\n", FLEET), None, "an unterminated fence runs to the end");
        assert_eq!(field("Model: flash in prose\n`> Model: x`\n", MODEL), None, "prose and inline code");
        assert_eq!(field("> Model:\n> Model: flash\n", MODEL), Some(""), "an empty first line still wins");
    }

    #[test]
    fn the_guard_reads_see_fenced_lines_too() {
        let doc = "# t\n```\n> Model: flash\n```\n> Grants: ~/x\nprose Model: y\n";
        assert_eq!(reserved_field(doc, &[MODEL, GRANTS]), Some(MODEL));
        assert_eq!(reserved_lines(doc, &[MODEL]), vec!["> Model: flash"]);
        assert_eq!(reserved_lines(doc, &[GRANTS]), vec!["> Grants: ~/x"]);
        assert!(reserved_lines("# none\n", &[MODEL, GRANTS, WORKTREE]).is_empty());
    }

    /// The G74-6 shape: a fence line inserted above a declaration leaves every
    /// raw line in place while the resolved value disappears — which is why a
    /// guard must compare both.
    #[test]
    fn a_fence_hides_a_declaration_without_moving_any_raw_line() {
        let before = "# t\n> Worktree: /a\n";
        let after = "# t\n```\n> Worktree: /a\n";
        assert_eq!(reserved_lines(before, &[WORKTREE]), reserved_lines(after, &[WORKTREE]));
        assert_eq!(field(before, WORKTREE), Some("/a"));
        assert_eq!(field(after, WORKTREE), None);
    }

    #[test]
    fn display_key_capitalizes() {
        assert_eq!(display_key("worktree"), "Worktree");
        assert_eq!(display_key(""), "");
    }
}
