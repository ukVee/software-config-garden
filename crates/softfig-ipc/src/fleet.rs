//! The `> Fleet:` item-doc marker (task 068) — the one parser for the line,
//! shared by growlightd's claim-time reader and keeperd's member-write guard
//! (task 074 part 2) so neither crate writes a second one.

/// The claim hold an item doc declares: a `> Fleet: <value>` blockquote line
/// marks the item human-only unless the value is `yes`. Returns the declared
/// (non-`yes`) value when the item is held, `None` when it is claimable.
///
/// Read the way `> Model:` is ([`crate::model_choice::item_model_field`]): the
/// first blockquote line whose key is `fleet`, case-insensitive, anywhere in the
/// doc. Lines inside a fenced code block don't count, so a doc that shows the
/// marker as an example does not mark itself. Any value other than `yes` holds —
/// a typo fails closed. See `growlight/backlog/CLAUDE.md` "Marking an item
/// human-only".
pub fn fleet_marker(doc: &str) -> Option<&str> {
    let mut fenced = false;
    for line in doc.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix('>') else {
            continue;
        };
        let Some((key, value)) = rest.trim().split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("fleet") {
            let value = value.trim();
            return (!value.eq_ignore_ascii_case("yes")).then_some(value);
        }
    }
    None
}

/// Whether `doc` is held human-only: [`fleet_marker`] returned a non-`yes`
/// value. This is the boolean the member-write guard compares before and after
/// a write — a member may flip it `false` → `true` (add/tighten, fails closed)
/// but never `true` → `false` (remove/loosen, frees the item).
pub fn held(doc: &str) -> bool {
    fleet_marker(doc).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_any_value_but_yes() {
        let doc = "# hover-view-sticky\n\n> Last reviewed: 2026-10-17\n> Fleet: no\n\n## Mission\n";
        assert_eq!(fleet_marker(doc), Some("no"));
        assert_eq!(fleet_marker("> fleet: No"), Some("No"), "case-insensitive key");
        // A typo fails closed rather than quietly letting the fleet in.
        assert_eq!(fleet_marker("> Fleet: nope"), Some("nope"));
        assert_eq!(fleet_marker("> Fleet: yes"), None, "an explicit yes is claimable");
        assert!(held(doc));
        assert!(!held("> Fleet: yes\n"));
    }

    #[test]
    fn is_absent_without_a_blockquote_line() {
        assert_eq!(fleet_marker("# t\n\n> Model: claude\n\nFleet: no in prose\n"), None);
        assert_eq!(fleet_marker("Mark it with `> Fleet: no`.\n"), None, "inline code is prose");
        // A fenced example does not mark the doc that shows it.
        assert_eq!(fleet_marker("```\n> Fleet: no\n```\n"), None);
        assert_eq!(
            fleet_marker("```\n> Fleet: no\n```\n> Fleet: no\n"),
            Some("no"),
            "a real line after the fence still counts",
        );
    }

    #[test]
    fn the_first_line_wins() {
        // The resolver returns on the first `> Fleet:` line, so a `yes` before
        // a `no` is claimable (and a member inserting that `yes` would loosen —
        // the guard compares the resolved marker, so it sees the flip).
        assert_eq!(fleet_marker("> Fleet: yes\n> Fleet: no\n"), None);
        assert_eq!(fleet_marker("> Fleet: no\n> Fleet: yes\n"), Some("no"));
    }
}
