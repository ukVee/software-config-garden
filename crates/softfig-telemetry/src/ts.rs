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
    fn text_order_is_time_order() {
        let a = iso8601_utc(1_700_000_000);
        let b = iso8601_utc(1_700_000_001);
        let c = iso8601_utc(1_800_000_000);
        assert!(a < b && b < c);
    }
}
