//! The `> Fleet:` item-doc marker (task 068) — the one parser for the line,
//! shared by growlightd's claim-time reader and keeperd's member-write guard
//! (task 074 part 2) so neither crate writes a second one.
//!
//! The pure value rules (`holds`, the `not_before` grammar and its civil-date
//! math) live in `softfig_protocol_keeperd::fleet` — keeperd validates the same
//! values and the wire surface reads them — and are re-exported here, so every
//! caller keeps the one implementation.

pub use softfig_protocol_keeperd::fleet::{days_from_civil, holds, parse_not_before};

/// The claim hold an item doc declares: a `> Fleet: <value>` blockquote line
/// marks the item human-only unless the value is `yes`. Returns the declared
/// (non-`yes`) value when the item is held, `None` when it is claimable.
///
/// Read through the shared scanner ([`crate::item_meta::field`]): the first
/// blockquote line whose key is `fleet`, case-insensitive, anywhere in the doc.
/// Lines inside a fenced code block don't count, so a doc that shows the marker
/// as an example does not mark itself. Any value other than `yes` holds — a typo
/// or an empty value fails closed. See `growlight/backlog/CLAUDE.md` "Marking an item
/// human-only".
pub fn fleet_marker(doc: &str) -> Option<&str> {
    crate::item_meta::field(doc, crate::item_meta::FLEET).filter(|v| holds(v))
}

/// Whether `doc` is held human-only: [`fleet_marker`] returned a non-`yes`
/// value. This is the boolean the member-write guard compares before and after
/// a write — a member may flip it `false` → `true` (add/tighten, fails closed)
/// but never `true` → `false` (remove/loosen, frees the item).
pub fn held(doc: &str) -> bool {
    fleet_marker(doc).is_some()
}

/// An item doc's start time: a `> Not before: <when>` blockquote line (the
/// interim scheduler, 2026-10-30) keeps the fleet from claiming the item before
/// `<when>`. `None` when the doc has no such line; otherwise the raw value and
/// its parse ([`parse_not_before`]) — the caller holds the item on an error, so a
/// typo never starts it early. Read through the same scanner as `> Fleet:`.
pub fn not_before(doc: &str) -> Option<(&str, Result<i64, String>)> {
    crate::item_meta::field(doc, crate::item_meta::NOT_BEFORE).map(|v| (v, parse_not_before(v)))
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

    #[test]
    fn not_before_reads_the_doc_line_like_the_fleet_marker() {
        let doc = "# t\n\n```\n> Not before: 2000-01-01 00:00Z\n```\n> Not before: 2026-10-31 02:00 -04:00\n";
        assert_eq!(not_before(doc), Some(("2026-10-31 02:00 -04:00", Ok(1_793_426_400))));
        assert_eq!(not_before("# t\n\n> Fleet: no\n"), None);
        let (raw, parsed) = not_before("> not before: soon\n").unwrap();
        assert_eq!(raw, "soon");
        assert!(parsed.is_err(), "a bad value is surfaced, so the caller can hold");
    }
}
