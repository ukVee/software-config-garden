//! The `> Fleet:` item-doc marker (task 068) — the one parser for the line,
//! shared by growlightd's claim-time reader and keeperd's member-write guard
//! (task 074 part 2) so neither crate writes a second one.

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
    crate::item_meta::field(doc, crate::item_meta::FLEET).filter(|v| !v.eq_ignore_ascii_case("yes"))
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

/// `YYYY-MM-DD HH:MM[:SS] <offset>` (or a `T` in place of the space) as UNIX
/// seconds, where `<offset>` is `Z` or `±HH:MM` and may follow the time with or
/// without a space. The offset is required: the crate has no tz database, and an
/// explicit offset can't be misread across a DST change. Out-of-range fields
/// (month 13, Feb 30, 24:00) are errors. `~/.local/bin/growlight-window`'s
/// `parse_not_before` must accept exactly this grammar.
pub fn parse_not_before(value: &str) -> Result<i64, String> {
    let bad = || format!("`{value}` is not `YYYY-MM-DD HH:MM ±HH:MM`");
    let s = value.trim();
    let num = |part: &str| -> Result<i64, String> {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        part.parse::<i64>().map_err(|_| bad())
    };
    let (date, rest) = (s.get(..10).ok_or_else(bad)?, s.get(10..).ok_or_else(bad)?);
    let rest = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('T')).ok_or_else(bad)?;
    let mut ymd = date.split('-');
    let (y, mo, d) = match (ymd.next(), ymd.next(), ymd.next(), ymd.next()) {
        (Some(y), Some(mo), Some(d), None) if y.len() == 4 && mo.len() == 2 && d.len() == 2 => {
            (num(y)?, num(mo)?, num(d)?)
        }
        _ => return Err(bad()),
    };
    // The time runs up to the offset: `Z`, `+`, or `-`, optionally after a space.
    let split = rest.find(['Z', '+', '-']).ok_or_else(bad)?;
    let (time, offset) = (rest[..split].trim_end(), &rest[split..]);
    let mut hms = time.split(':');
    let (h, mi, sec) = match (hms.next(), hms.next(), hms.next(), hms.next()) {
        (Some(h), Some(mi), None, None) if h.len() == 2 && mi.len() == 2 => (num(h)?, num(mi)?, 0),
        (Some(h), Some(mi), Some(sec), None) if h.len() == 2 && mi.len() == 2 && sec.len() == 2 => {
            (num(h)?, num(mi)?, num(sec)?)
        }
        _ => return Err(bad()),
    };
    let offset_secs = if offset == "Z" {
        0
    } else {
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        match offset[1..].split_once(':') {
            Some((oh, om)) if oh.len() == 2 && om.len() == 2 && num(oh)? <= 23 && num(om)? <= 59 => {
                sign * (num(oh)? * 3600 + num(om)? * 60)
            }
            _ => return Err(bad()),
        }
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo)
        || d < 1
        || d > month_days[(mo - 1) as usize]
        || h > 23
        || mi > 59
        || sec > 59
    {
        return Err(bad());
    }
    Ok(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset_secs)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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
    fn not_before_parses_with_a_required_offset() {
        // `date -d '2026-10-31 02:00 -04:00' +%s` = 1793426400.
        let at = 1_793_426_400;
        assert_eq!(parse_not_before("2026-10-31 02:00 -04:00"), Ok(at));
        assert_eq!(parse_not_before("2026-10-31T02:00-04:00"), Ok(at));
        assert_eq!(parse_not_before("2026-10-31 06:00Z"), Ok(at));
        assert_eq!(parse_not_before("2026-10-31 06:00:30 +00:00"), Ok(at + 30));
        assert_eq!(parse_not_before("1970-01-01 00:00Z"), Ok(0));
        assert_eq!(parse_not_before("2028-02-29 00:00Z"), Ok(1_835_395_200), "a leap day");
        for bad in [
            "2026-10-31 02:00",       // no offset
            "2026-13-01 00:00Z",      // month 13
            "2027-02-29 00:00Z",      // not a leap year
            "2026-10-31 24:00Z",      // hour 24
            "2026-10-31 2:00 -04:00", // one-digit hour
            "2026-10-31 02:00 -4:00", // one-digit offset
            "tomorrow",
            "",
        ] {
            assert!(parse_not_before(bad).is_err(), "{bad:?} must not parse");
        }
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
