//! The `> Fleet:` / `> Not before:` **value rules**, pure and IO-free: what a
//! marker value means, and the one `not_before` time grammar. The doc scan
//! that finds the markers stays in `softfig-ipc::fleet` (it reads an item doc
//! through `item_meta`); these rules live here because keeperd validates the
//! same values on its verbs and because `QueueShowEntry::doc_hold_warning` in
//! `softfig-protocol-growlightd` must read a doc line exactly as the v2 entry
//! does (spec-softfig-tui-frontend-split §3.1, milestone
//! `tui-split-protocol-merge` slice 003). `softfig-ipc::fleet` re-exports them.

/// Whether a `> Fleet:` line's value holds the item: anything but `yes`,
/// case-insensitive (an empty value or a typo fails closed). The one value
/// rule, so a surface comparing a doc's line with a v2 entry reads the line as
/// `softfig-ipc::fleet::fleet_marker` does.
pub fn holds(value: &str) -> bool {
    !value.eq_ignore_ascii_case("yes")
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
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
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
}
