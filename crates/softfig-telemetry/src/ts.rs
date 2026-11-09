//! ISO 8601 UTC timestamps from unix seconds, with no chrono dependency.
//!
//! `ts` is stored as `YYYY-MM-DDTHH:MM:SSZ` text, which sorts the same as the
//! instant it names, so the retention sweep compares strings. The civil-date
//! arithmetic is keeperd's (`actions/conventions.rs`), copied because keeperd
//! is not a dependency of this crate.

/// `secs` as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso8601_utc(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Parse claude's transcript `timestamp` (`YYYY-MM-DDTHH:MM:SS[.fff]Z`, UTC)
/// back to unix seconds, dropping the fraction. `None` for any other shape.
pub fn parse_iso8601_utc(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let time = time.split_once('.').map_or(time, |(whole, _)| whole);
    let num = |part: &str, len: usize| -> Option<i64> {
        (part.len() == len && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    let mut d = date.split('-');
    let (y, m, day) = (num(d.next()?, 4)?, num(d.next()?, 2)?, num(d.next()?, 2)?);
    let mut t = time.split(':');
    let (hh, mm, ss) = (num(t.next()?, 2)?, num(t.next()?, 2)?, num(t.next()?, 2)?);
    if d.next().is_some() || t.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some(days_from_civil(y, m as u32, day as u32) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// The inverse of [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 }.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 }); // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Convert a count of days since 1970-01-01 to (year, month [1-12],
/// day [1-31]) in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0,399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0,365]
    let mp = (5 * doy + 2) / 153; // [0,11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1,31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1,12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        // 2000-02-29 (a leap day in a /400 year) 12:34:56.
        assert_eq!(iso8601_utc(951_827_696), "2000-02-29T12:34:56Z");
        assert_eq!(iso8601_utc(1_793_462_624), "2026-10-31T16:03:44Z");
        assert_eq!(iso8601_utc(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn parse_round_trips_and_drops_the_fraction() {
        for secs in [0, 951_827_696, 1_793_462_624, -1] {
            assert_eq!(parse_iso8601_utc(&iso8601_utc(secs)), Some(secs));
        }
        assert_eq!(parse_iso8601_utc("2026-10-31T18:00:45.043Z"), Some(1_793_469_645));
        for bad in ["", "2026-10-31", "2026-10-31T18:00:45", "2026-13-01T00:00:00Z", "26-10-31T18:00:45Z"] {
            assert_eq!(parse_iso8601_utc(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn text_order_is_time_order() {
        let a = iso8601_utc(1_700_000_000);
        let b = iso8601_utc(1_700_000_001);
        let c = iso8601_utc(1_800_000_000);
        assert!(a < b && b < c);
    }
}
