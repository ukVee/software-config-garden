//! Local time without a time crate (milestone `growlight-schedule`, spec
//! `meta/spec-growlight-schedule.md` §3.2) — a std-only TZif reader.
//!
//! ## What this is
//!
//! A [`Zone`] is a compiled tz database file (RFC 8536 TZif, v1 or v2+) or a
//! bare POSIX `TZ` string. growlightd's `[schedule]` windows are local
//! wall-clock intervals, so the scheduler needs the UTC offset at any instant
//! and, to keep edges exact across a DST jump, the next instant the offset
//! changes.
//!
//! - **TZif v2+** carries 64-bit transition times and a POSIX-TZ footer for
//!   instants past the last transition. Arch ships `zic -b slim` files, whose
//!   tables stop at the most recent rule change and leave every future
//!   transition to the footer, so the footer is not optional here.
//! - **The footer grammar** is POSIX `std offset [dst [offset] [,start[/time],end[/time]]]`
//!   with `Mm.w.d`, `Jn` and `n` dates and `<...>`-quoted names. A `dst` with
//!   no rule takes the US rule (`M3.2.0,M11.1.0`), as glibc does.
//! - **Leap-second records are skipped.** The `right/` zones count them; the
//!   default zones (what `/etc/localtime` points at) carry none.
//!
//! ## Source
//!
//! [`Zone::load`] reads `$TZ` if set (`:path`, a zone name under
//! `/usr/share/zoneinfo`, or a POSIX string; empty means UTC), else
//! `/etc/localtime`. An unreadable zone is an `Err`: with the schedule enabled
//! the caller closes it (fail-closed); it never guesses UTC.
//!
//! Civil-date math reuses [`crate::fleet::days_from_civil`].

use std::path::Path;

use crate::fleet::days_from_civil;

/// Where named zones live.
pub const ZONEINFO_DIR: &str = "/usr/share/zoneinfo";
/// The system's local zone when `$TZ` is unset.
pub const LOCALTIME_PATH: &str = "/etc/localtime";

const DAY: i64 = 86_400;

/// A wall-clock reading in a [`Zone`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    /// Year.
    pub y: i64,
    /// Month, 1..=12.
    pub mo: u8,
    /// Day of month, 1..=31.
    pub d: u8,
    /// Hour, 0..=23.
    pub h: u8,
    /// Minute, 0..=59.
    pub mi: u8,
    /// Second, 0..=59.
    pub s: u8,
    /// Day of week, ISO order: 0 = Monday .. 6 = Sunday.
    pub weekday: u8,
    /// UTC offset in effect, seconds east of UTC.
    pub offset: i32,
}

/// One local time type: an offset and whether it is daylight time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalType {
    offset: i32,
    dst: bool,
}

/// A time zone: a transition table, a POSIX rule for after it, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    name: String,
    /// Transition instants, ascending, Unix seconds.
    transitions: Vec<i64>,
    /// The local type each transition switches to (index into `types`).
    trans_types: Vec<u8>,
    /// Never empty. `types[0]` applies before the first transition (RFC 8536 §3.2).
    types: Vec<LocalType>,
    /// The footer rule for instants at or past the last transition.
    footer: Option<PosixTz>,
}

impl Zone {
    /// The system's local zone: `$TZ` if set, else `/etc/localtime`.
    pub fn load() -> Result<Zone, String> {
        let tz = std::env::var("TZ").ok();
        Self::load_with(tz.as_deref(), Path::new(ZONEINFO_DIR), Path::new(LOCALTIME_PATH))
    }

    /// [`load`](Self::load) with the environment and paths injected (tests).
    pub fn load_with(tz: Option<&str>, zoneinfo: &Path, localtime: &Path) -> Result<Zone, String> {
        let Some(tz) = tz else {
            let bytes = std::fs::read(localtime)
                .map_err(|e| format!("read {}: {e}", localtime.display()))?;
            let name = std::fs::read_link(localtime)
                .ok()
                .and_then(|t| {
                    let t = t.to_string_lossy().into_owned();
                    t.split_once("zoneinfo/").map(|(_, n)| n.to_string())
                })
                .unwrap_or_else(|| "localtime".to_string());
            return Self::from_tzif_bytes(&name, &bytes);
        };
        if tz.is_empty() {
            return Ok(Self::utc());
        }
        let (spec, explicit_file) = match tz.strip_prefix(':') {
            Some(rest) => (rest, true),
            None => (tz, false),
        };
        let path = if spec.starts_with('/') {
            Some(Path::new(spec).to_path_buf())
        } else if !spec.split('/').any(|c| c == ".." || c.is_empty()) {
            Some(zoneinfo.join(spec))
        } else {
            None
        };
        if let Some(path) = path.filter(|p| explicit_file || p.is_file()) {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            return Self::from_tzif_bytes(spec, &bytes);
        }
        if explicit_file {
            return Err(format!("TZ={tz:?}: not a readable zone file"));
        }
        Self::from_posix(tz)
    }

    /// UTC, offset zero forever.
    pub fn utc() -> Zone {
        Zone {
            name: "UTC".to_string(),
            transitions: Vec::new(),
            trans_types: Vec::new(),
            types: vec![LocalType { offset: 0, dst: false }],
            footer: None,
        }
    }

    /// A zone from a bare POSIX TZ string such as `EST5EDT,M3.2.0,M11.1.0`.
    pub fn from_posix(s: &str) -> Result<Zone, String> {
        let rule = PosixTz::parse(s)?;
        Ok(Zone {
            name: s.to_string(),
            transitions: Vec::new(),
            trans_types: Vec::new(),
            types: vec![LocalType { offset: rule.std_offset, dst: false }],
            footer: Some(rule),
        })
    }

    /// A zone from the bytes of a TZif file (RFC 8536, v1 or v2+).
    pub fn from_tzif_bytes(name: &str, bytes: &[u8]) -> Result<Zone, String> {
        let bad = |why: &str| format!("TZif {name:?}: {why}");
        let mut r = Reader { b: bytes, at: 0 };
        let v1 = Header::read(&mut r).map_err(|e| bad(&e))?;
        let (header, time_size) = if v1.version >= b'2' {
            r.skip(v1.block_len(4)).map_err(|e| bad(&e))?;
            (Header::read(&mut r).map_err(|e| bad(&e))?, 8)
        } else {
            (v1, 4)
        };
        let h = header;
        if h.typecnt == 0 {
            return Err(bad("no local time types"));
        }
        // The counts come off the wire: size the tables only once the data
        // block they describe is known to fit in what is left of the file.
        if h.block_len(time_size) > bytes.len() - r.at {
            return Err(bad("header counts exceed the file"));
        }
        let mut transitions = Vec::with_capacity(h.timecnt);
        for _ in 0..h.timecnt {
            let t = if time_size == 8 {
                r.i64().map_err(|e| bad(&e))?
            } else {
                i64::from(r.i32().map_err(|e| bad(&e))?)
            };
            if transitions.last().is_some_and(|&prev| t <= prev) {
                return Err(bad("transition times not ascending"));
            }
            transitions.push(t);
        }
        let trans_types = r.take(h.timecnt).map_err(|e| bad(&e))?.to_vec();
        if trans_types.iter().any(|&i| usize::from(i) >= h.typecnt) {
            return Err(bad("transition names a missing local time type"));
        }
        let mut types = Vec::with_capacity(h.typecnt);
        for _ in 0..h.typecnt {
            let offset = r.i32().map_err(|e| bad(&e))?;
            let dst = r.take(1).map_err(|e| bad(&e))?[0] != 0;
            r.skip(1).map_err(|e| bad(&e))?; // designation index
            types.push(LocalType { offset, dst });
        }
        r.skip(h.charcnt + h.leapcnt * (time_size + 4) + h.isstdcnt + h.isutcnt)
            .map_err(|e| bad(&e))?;
        let footer = if time_size == 8 {
            let rest = &bytes[r.at..];
            let text = rest
                .strip_prefix(b"\n")
                .and_then(|t| t.split(|&c| c == b'\n').next())
                .ok_or_else(|| bad("missing footer"))?;
            let text = std::str::from_utf8(text).map_err(|_| bad("footer is not UTF-8"))?;
            // An empty footer means "no rule": the last type holds forever.
            if text.is_empty() {
                None
            } else {
                Some(PosixTz::parse(text).map_err(|e| bad(&e))?)
            }
        } else {
            None
        };
        Ok(Zone { name: name.to_string(), transitions, trans_types, types, footer })
    }

    /// The zone's name (`America/New_York`, the POSIX string, `UTC`, ...).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The UTC offset in effect at `unix`, seconds east of UTC.
    pub fn offset_at(&self, unix: i64) -> i32 {
        match self.transitions.last() {
            Some(&last) if unix >= last => match &self.footer {
                Some(rule) => rule.offset_at(unix),
                None => self.type_after(self.transitions.len() - 1).offset,
            },
            _ => match self.transitions.partition_point(|&t| t <= unix) {
                0 => match (&self.footer, self.transitions.is_empty()) {
                    // A footer-only zone (bare POSIX string, or a TZif with an
                    // empty table): the rule covers all time.
                    (Some(rule), true) => rule.offset_at(unix),
                    _ => self.types[0].offset,
                },
                n => self.type_after(n - 1).offset,
            },
        }
    }

    /// The wall-clock reading at `unix`.
    pub fn local(&self, unix: i64) -> LocalTime {
        let offset = self.offset_at(unix);
        let secs = unix + i64::from(offset);
        let days = secs.div_euclid(DAY);
        let sod = secs.rem_euclid(DAY);
        let (y, mo, d) = civil_from_days(days);
        LocalTime {
            y,
            mo: mo as u8,
            d: d as u8,
            h: (sod / 3600) as u8,
            mi: (sod % 3600 / 60) as u8,
            s: (sod % 60) as u8,
            weekday: weekday_of_days(days),
            offset,
        }
    }

    /// The first instant after `unix` at which the offset changes, if any.
    pub fn next_change_after(&self, unix: i64) -> Option<i64> {
        let mut current = self.offset_at(unix);
        let from = self.transitions.partition_point(|&t| t <= unix);
        for i in from..self.transitions.len() {
            let next = self.type_after(i).offset;
            if next != current {
                return Some(self.transitions[i]);
            }
            current = next;
        }
        let rule = self.footer.as_ref()?;
        let after = self.transitions.last().map_or(unix, |&last| unix.max(last));
        rule.next_change_after(after)
    }

    /// The first instant at which the wall clock reads `local` or later, where
    /// `local` is local seconds since the epoch (a civil day number × 86 400
    /// plus seconds into the day).
    ///
    /// A reading the clock shows twice (a fall-back repeat) resolves to its
    /// **first** occurrence; one the clock skips (a spring-forward gap)
    /// resolves to the first instant after the gap (§3.3).
    pub fn resolve_local(&self, local: i64) -> i64 {
        let before = i64::from(self.offset_at(local - DAY));
        let after = i64::from(self.offset_at(local + DAY));
        let valid = [local - before, local - after]
            .into_iter()
            .filter(|&t| i64::from(self.offset_at(t)) == local - t)
            .min();
        match valid {
            Some(t) => t,
            None => {
                let lo = (local - before).min(local - after);
                self.next_change_after(lo).unwrap_or(local - before)
            }
        }
    }

    fn type_after(&self, transition: usize) -> LocalType {
        self.types[usize::from(self.trans_types[transition])]
    }
}

/// Day of week (0 = Monday .. 6 = Sunday) of a civil day number.
pub fn weekday_of_days(days: i64) -> u8 {
    // 1970-01-01 was a Thursday.
    (days + 3).rem_euclid(7) as u8
}

/// Civil date of a day number since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, the inverse of `days_from_civil`).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m as u32, d as u32)
}

/// Days since 1970-01-01 of a civil date.
pub fn days_of_civil(y: i64, mo: u32, d: u32) -> i64 {
    days_from_civil(y, i64::from(mo), i64::from(d))
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn month_days(y: i64, m: u32) -> u32 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// ---------------------------------------------------------------------------
// TZif byte reader

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len());
        let end = end.ok_or_else(|| "truncated".to_string())?;
        let out = &self.b[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.take(n).map(|_| ())
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
}

struct Header {
    version: u8,
    isutcnt: usize,
    isstdcnt: usize,
    leapcnt: usize,
    timecnt: usize,
    typecnt: usize,
    charcnt: usize,
}

impl Header {
    fn read(r: &mut Reader<'_>) -> Result<Header, String> {
        if r.take(4)? != b"TZif" {
            return Err("not a TZif file".to_string());
        }
        let version = r.take(1)?[0];
        r.skip(15)?;
        let mut n = || r.u32().map(|v| v as usize);
        Ok(Header {
            version,
            isutcnt: n()?,
            isstdcnt: n()?,
            leapcnt: n()?,
            timecnt: n()?,
            typecnt: n()?,
            charcnt: n()?,
        })
    }

    /// The data block's length for `time_size`-byte transition times.
    fn block_len(&self, time_size: usize) -> usize {
        self.timecnt * (time_size + 1)
            + self.typecnt * 6
            + self.charcnt
            + self.leapcnt * (time_size + 4)
            + self.isstdcnt
            + self.isutcnt
    }
}

// ---------------------------------------------------------------------------
// POSIX TZ rule

/// A POSIX `TZ` rule: a standard offset and, optionally, a yearly DST period.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PosixTz {
    /// Seconds east of UTC (POSIX spells the opposite sign).
    std_offset: i32,
    dst: Option<Dst>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Dst {
    offset: i32,
    /// When DST starts, in local standard time.
    start: Rule,
    /// When DST ends, in local daylight time.
    end: Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    date: RuleDate,
    /// Seconds after local midnight; may be negative or past 24 h (RFC 8536 §3.3.1).
    time: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleDate {
    /// `Jn`: day 1..=365, February 29 never counted.
    Julian1(u16),
    /// `n`: day 0..=365, February 29 counted in leap years.
    Julian0(u16),
    /// `Mm.w.d`: weekday `d` (0 = Sunday) of week `w` (5 = last) of month `m`.
    Mwd(u8, u8, u8),
}

impl RuleDate {
    /// The civil day number this date falls on in `year`.
    fn day_in(self, year: i64) -> i64 {
        let jan1 = days_of_civil(year, 1, 1);
        match self {
            RuleDate::Julian1(n) => {
                let n = i64::from(n);
                jan1 + n - 1 + i64::from(is_leap(year) && n >= 60)
            }
            RuleDate::Julian0(n) => jan1 + i64::from(n),
            RuleDate::Mwd(m, w, d) => {
                let m = u32::from(m);
                let first = days_of_civil(year, m, 1);
                // weekday_of_days is Monday-based; POSIX d is Sunday-based.
                let first_wd = (i64::from(weekday_of_days(first)) + 1) % 7;
                let mut day = 1 + (i64::from(d) - first_wd).rem_euclid(7) + 7 * (i64::from(w) - 1);
                while day > i64::from(month_days(year, m)) {
                    day -= 7;
                }
                first + day - 1
            }
        }
    }
}

impl PosixTz {
    fn parse(s: &str) -> Result<PosixTz, String> {
        let bad = |why: &str| format!("POSIX TZ {s:?}: {why}");
        let mut p = Cursor { s: s.as_bytes(), at: 0 };
        p.name().map_err(|e| bad(&e))?;
        let std_offset = -p.hms(24).map_err(|e| bad(&e))?;
        let dst = if p.done() {
            None
        } else {
            p.name().map_err(|e| bad(&e))?;
            let offset = if p.done() || p.peek() == Some(b',') {
                std_offset + 3600
            } else {
                -p.hms(24).map_err(|e| bad(&e))?
            };
            let (start, end) = if p.eat(b',') {
                let start = p.rule().map_err(|e| bad(&e))?;
                if !p.eat(b',') {
                    return Err(bad("a DST start rule needs an end rule"));
                }
                (start, p.rule().map_err(|e| bad(&e))?)
            } else {
                // No rule: the US rule, as glibc assumes.
                let us = |m, w| Rule { date: RuleDate::Mwd(m, w, 0), time: 7200 };
                (us(3, 2), us(11, 1))
            };
            Some(Dst { offset: offset as i32, start, end })
        };
        if !p.done() {
            return Err(bad("trailing characters"));
        }
        Ok(PosixTz { std_offset: std_offset as i32, dst })
    }

    /// Both of `year`'s transitions as `(instant, offset after)`, sorted.
    fn transitions_in(&self, year: i64) -> Option<[(i64, i32); 2]> {
        let dst = self.dst.as_ref()?;
        let at = |rule: Rule, offset_before: i32| {
            rule.date.day_in(year) * DAY + rule.time - i64::from(offset_before)
        };
        let mut both = [
            (at(dst.start, self.std_offset), dst.offset),
            (at(dst.end, dst.offset), self.std_offset),
        ];
        both.sort_unstable();
        Some(both)
    }

    fn year_of(&self, unix: i64) -> i64 {
        civil_from_days((unix + i64::from(self.std_offset)).div_euclid(DAY)).0
    }

    fn offset_at(&self, unix: i64) -> i32 {
        let year = self.year_of(unix);
        let mut last = None;
        for y in year - 1..=year + 1 {
            for (t, off) in self.transitions_in(y).into_iter().flatten() {
                if t <= unix && last.is_none_or(|(lt, _)| t >= lt) {
                    last = Some((t, off));
                }
            }
        }
        last.map_or(self.std_offset, |(_, off)| off)
    }

    fn next_change_after(&self, unix: i64) -> Option<i64> {
        let year = self.year_of(unix);
        (year - 1..=year + 2)
            .flat_map(|y| self.transitions_in(y).into_iter().flatten())
            .filter(|&(t, _)| t > unix)
            .map(|(t, _)| t)
            .min()
    }
}

struct Cursor<'a> {
    s: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn done(&self) -> bool {
        self.at >= self.s.len()
    }

    fn eat(&mut self, c: u8) -> bool {
        let hit = self.peek() == Some(c);
        self.at += usize::from(hit);
        hit
    }

    /// A zone abbreviation: `<...>` quoted, or three or more letters.
    fn name(&mut self) -> Result<(), String> {
        if self.eat(b'<') {
            while let Some(c) = self.peek() {
                self.at += 1;
                if c == b'>' {
                    return Ok(());
                }
            }
            return Err("unterminated <name>".to_string());
        }
        let start = self.at;
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            self.at += 1;
        }
        if self.at - start < 3 {
            return Err("a zone name needs three or more letters".to_string());
        }
        Ok(())
    }

    fn number(&mut self) -> Result<i64, String> {
        let start = self.at;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) && self.at - start < 3 {
            self.at += 1;
        }
        let digits = std::str::from_utf8(&self.s[start..self.at]).expect("ASCII digits");
        digits.parse().map_err(|_| "expected a number".to_string())
    }

    /// `[+-]hh[:mm[:ss]]` in seconds, POSIX sign; hours up to `max_h`.
    fn hms(&mut self, max_h: i64) -> Result<i64, String> {
        let sign = if self.eat(b'-') {
            -1
        } else {
            self.eat(b'+');
            1
        };
        let h = self.number()?;
        if h > max_h {
            return Err(format!("hour {h} out of range"));
        }
        let mut secs = h * 3600;
        for scale in [60, 1] {
            if !self.eat(b':') {
                break;
            }
            let v = self.number()?;
            if v > 59 {
                return Err(format!("{v} out of range"));
            }
            secs += v * scale;
        }
        Ok(sign * secs)
    }

    /// `Mm.w.d`, `Jn` or `n`, then an optional `/time`.
    fn rule(&mut self) -> Result<Rule, String> {
        let date = if self.eat(b'M') {
            let m = self.number()?;
            let w = if self.eat(b'.') { self.number()? } else { -1 };
            let d = if self.eat(b'.') { self.number()? } else { -1 };
            if !(1..=12).contains(&m) || !(1..=5).contains(&w) || !(0..=6).contains(&d) {
                return Err("bad Mm.w.d rule".to_string());
            }
            RuleDate::Mwd(m as u8, w as u8, d as u8)
        } else if self.eat(b'J') {
            let n = self.number()?;
            if !(1..=365).contains(&n) {
                return Err("bad Jn rule".to_string());
            }
            RuleDate::Julian1(n as u16)
        } else {
            let n = self.number()?;
            if !(0..=365).contains(&n) {
                return Err("bad n rule".to_string());
            }
            RuleDate::Julian0(n as u16)
        };
        // RFC 8536 §3.3.1 widens the rule time to -167..=167 hours.
        let time = if self.eat(b'/') { self.hms(167)? } else { 7200 };
        Ok(Rule { date, time })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i64, mo: u32, d: u32, h: i64, mi: i64) -> i64 {
        days_of_civil(y, mo, d) * DAY + h * 3600 + mi * 60
    }

    /// A TZif v2 file in the `zic -b slim` shape: a minimal v1 block, then a
    /// v2 table of `transitions` and a footer for everything after it.
    fn tzif_v2(transitions: &[(i64, u8)], types: &[(i32, bool)], footer: &str) -> Vec<u8> {
        fn header(out: &mut Vec<u8>, counts: [u32; 6]) {
            out.extend_from_slice(b"TZif2");
            out.extend_from_slice(&[0; 15]);
            for c in counts {
                out.extend_from_slice(&c.to_be_bytes());
            }
        }
        let mut out = Vec::new();
        header(&mut out, [0, 0, 0, 0, 1, 1]);
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]); // one UTC type + one NUL char
        let chars = b"LMT\0";
        let n = |v: usize| v as u32;
        header(&mut out, [0, 0, 0, n(transitions.len()), n(types.len()), n(chars.len())]);
        for &(t, _) in transitions {
            out.extend_from_slice(&t.to_be_bytes());
        }
        out.extend(transitions.iter().map(|&(_, i)| i));
        for &(off, dst) in types {
            out.extend_from_slice(&off.to_be_bytes());
            out.extend_from_slice(&[u8::from(dst), 0]);
        }
        out.extend_from_slice(chars);
        out.push(b'\n');
        out.extend_from_slice(footer.as_bytes());
        out.push(b'\n');
        out
    }

    /// America/New_York, slim: 2025's two transitions in the table, the
    /// footer for 2026 on.
    fn new_york() -> Zone {
        let bytes = tzif_v2(
            &[(utc(2025, 3, 9, 7, 0), 1), (utc(2025, 11, 2, 6, 0), 0)],
            &[(-18_000, false), (-14_400, true)],
            "EST5EDT,M3.2.0,M11.1.0",
        );
        Zone::from_tzif_bytes("America/New_York", &bytes).expect("fixture parses")
    }

    const EST: i32 = -18_000;
    const EDT: i32 = -14_400;

    #[test]
    fn civil_round_trips_and_weekdays() {
        for days in [-719_468, -1, 0, 1, 20_000, 20_757, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_of_civil(y, m, d), days);
        }
        assert_eq!(weekday_of_days(0), 3, "1970-01-01 was a Thursday");
        assert_eq!(weekday_of_days(days_of_civil(2026, 10, 30)), 4, "a Friday");
        assert_eq!(weekday_of_days(days_of_civil(2026, 11, 1)), 6, "a Sunday");
    }

    #[test]
    fn the_table_answers_inside_its_range() {
        let z = new_york();
        assert_eq!(z.name(), "America/New_York");
        assert_eq!(z.offset_at(utc(2024, 7, 1, 0, 0)), EST, "type 0 before the first transition");
        assert_eq!(z.offset_at(utc(2025, 3, 9, 6, 59)), EST);
        assert_eq!(z.offset_at(utc(2025, 3, 9, 7, 0)), EDT);
        assert_eq!(z.offset_at(utc(2025, 7, 1, 0, 0)), EDT);
        assert_eq!(z.next_change_after(utc(2025, 1, 1, 0, 0)), Some(utc(2025, 3, 9, 7, 0)));
        assert_eq!(z.next_change_after(utc(2025, 3, 9, 7, 0)), Some(utc(2025, 11, 2, 6, 0)));
    }

    #[test]
    fn the_footer_carries_2026_spring_forward_and_fall_back() {
        for z in [new_york(), Zone::from_posix("EST5EDT,M3.2.0,M11.1.0").unwrap()] {
            let spring = utc(2026, 3, 8, 7, 0); // 02:00 EST
            let fall = utc(2026, 11, 1, 6, 0); // 02:00 EDT
            assert_eq!(z.offset_at(spring - 1), EST, "{}", z.name());
            assert_eq!(z.offset_at(spring), EDT);
            assert_eq!(z.offset_at(fall - 1), EDT);
            assert_eq!(z.offset_at(fall), EST);
            assert_eq!(z.next_change_after(utc(2025, 12, 1, 0, 0)), Some(spring));
            assert_eq!(z.next_change_after(spring), Some(fall));
            assert_eq!(z.next_change_after(fall - 1), Some(fall));
            assert_eq!(z.next_change_after(fall), Some(utc(2027, 3, 14, 7, 0)));
        }
    }

    #[test]
    fn local_readings_and_weekdays() {
        let z = new_york();
        let t = utc(2026, 10, 31, 6, 18); // 02:18 EDT, Saturday
        let l = z.local(t);
        assert_eq!((l.y, l.mo, l.d, l.h, l.mi, l.s), (2026, 10, 31, 2, 18, 0));
        assert_eq!((l.weekday, l.offset), (5, EDT));
        // Across midnight UTC the local day lags: still Friday evening.
        let l = z.local(utc(2026, 10, 31, 1, 30));
        assert_eq!((l.d, l.h, l.mi, l.weekday), (30, 21, 30, 4));
    }

    #[test]
    fn resolve_local_takes_the_first_reading_at_or_after_the_wall_time() {
        let z = new_york();
        let local = |y, mo, d, h: i64, mi: i64| days_of_civil(y, mo, d) * DAY + h * 3600 + mi * 60;
        // A plain reading.
        assert_eq!(z.resolve_local(local(2026, 10, 28, 23, 0)), utc(2026, 10, 29, 3, 0));
        // Spring-forward gap 02:00..03:00: every reading in it resolves to 03:00 EDT.
        let jump = utc(2026, 3, 8, 7, 0);
        assert_eq!(z.resolve_local(local(2026, 3, 8, 2, 0)), jump);
        assert_eq!(z.resolve_local(local(2026, 3, 8, 2, 30)), jump);
        assert_eq!(z.resolve_local(local(2026, 3, 8, 3, 0)), jump);
        assert_eq!(z.resolve_local(local(2026, 3, 8, 1, 59)), jump - 60);
        // Fall-back repeat 01:00..02:00: the first (EDT) occurrence.
        assert_eq!(z.resolve_local(local(2026, 11, 1, 1, 30)), utc(2026, 11, 1, 5, 30));
        assert_eq!(z.resolve_local(local(2026, 11, 1, 2, 0)), utc(2026, 11, 1, 7, 0));
    }

    #[test]
    fn a_zone_with_no_dst_never_changes() {
        for z in [Zone::utc(), Zone::from_posix("UTC0").unwrap()] {
            assert_eq!(z.offset_at(utc(2026, 7, 1, 0, 0)), 0);
            assert_eq!(z.next_change_after(0), None);
            assert_eq!(z.resolve_local(1000), 1000);
        }
        let z = Zone::from_posix("<+0530>-5:30").unwrap();
        assert_eq!(z.offset_at(0), 19_800);
    }

    #[test]
    fn posix_rules_cover_julian_dates_southern_dst_and_defaults() {
        // Jn: J60 is March 1 even in a leap year; n counts Feb 29.
        assert_eq!(RuleDate::Julian1(60).day_in(2028), days_of_civil(2028, 3, 1));
        assert_eq!(RuleDate::Julian0(59).day_in(2028), days_of_civil(2028, 2, 29));
        // M10.5.0 = last Sunday of October.
        assert_eq!(RuleDate::Mwd(10, 5, 0).day_in(2026), days_of_civil(2026, 10, 25));
        // Southern hemisphere: DST spans the new year (Australia/Sydney).
        let syd = Zone::from_posix("AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap();
        assert_eq!(syd.offset_at(utc(2026, 1, 15, 0, 0)), 39_600);
        assert_eq!(syd.offset_at(utc(2026, 7, 15, 0, 0)), 36_000);
        assert_eq!(syd.next_change_after(utc(2026, 7, 15, 0, 0)), Some(utc(2026, 10, 3, 16, 0)));
        // A DST name with no rule takes the US rule and std + 1 h.
        let us = Zone::from_posix("EST5EDT").unwrap();
        assert_eq!(us.offset_at(utc(2026, 3, 8, 7, 0)), EDT);
        for bad in ["", "E5", "EST", "EST5EDT,M3.2.0", "EST5EDT,M13.1.0,M11.1.0", "EST5x", "<EST5"] {
            assert!(Zone::from_posix(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn malformed_tzif_is_refused() {
        let good = tzif_v2(&[(0, 0)], &[(0, false)], "UTC0");
        assert!(Zone::from_tzif_bytes("x", &good).is_ok());
        assert!(Zone::from_tzif_bytes("x", b"TZjf").is_err());
        assert!(Zone::from_tzif_bytes("x", &good[..good.len() - 10]).is_err());
        let bad_index = tzif_v2(&[(0, 3)], &[(0, false)], "UTC0");
        assert!(Zone::from_tzif_bytes("x", &bad_index).is_err());
        let descending = tzif_v2(&[(10, 0), (5, 0)], &[(0, false)], "UTC0");
        assert!(Zone::from_tzif_bytes("x", &descending).is_err());
    }

    #[test]
    fn a_header_whose_counts_outrun_the_file_is_an_error_not_an_allocation() {
        // A v1 header: magic, version 0, 15 reserved bytes, then the six
        // counts (isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt).
        let header = |counts: [u32; 6]| {
            let mut b = b"TZif\0".to_vec();
            b.extend([0u8; 15]);
            for c in counts {
                b.extend(c.to_be_bytes());
            }
            b
        };
        let all_zero = header([0; 6]);
        assert!(Zone::from_tzif_bytes("x", &all_zero).is_err(), "no local time types");
        let huge_times = header([0, 0, 0, u32::MAX, 1, 0]);
        assert!(Zone::from_tzif_bytes("x", &huge_times).is_err());
        let huge_types = header([0, 0, 0, 0, u32::MAX, 0]);
        assert!(Zone::from_tzif_bytes("x", &huge_types).is_err());
    }

    #[test]
    fn load_reads_tz_then_localtime_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("softfig-tz-{}", std::process::id()));
        let zoneinfo = dir.join("zoneinfo");
        std::fs::create_dir_all(zoneinfo.join("America")).unwrap();
        let bytes = tzif_v2(&[], &[(EST, false)], "EST5EDT,M3.2.0,M11.1.0");
        std::fs::write(zoneinfo.join("America/New_York"), &bytes).unwrap();
        let missing = dir.join("no-localtime");
        let ny = Zone::load_with(Some("America/New_York"), &zoneinfo, &missing).unwrap();
        assert_eq!(ny.name(), "America/New_York");
        assert_eq!(ny.offset_at(utc(2026, 7, 1, 0, 0)), EDT, "an empty table defers to the footer");
        let path = zoneinfo.join("America/New_York");
        let explicit = format!(":{}", path.display());
        assert!(Zone::load_with(Some(&explicit), &zoneinfo, &missing).is_ok());
        assert_eq!(Zone::load_with(Some("UTC0"), &zoneinfo, &missing).unwrap().offset_at(0), 0);
        assert_eq!(Zone::load_with(Some(""), &zoneinfo, &missing).unwrap().name(), "UTC");
        assert!(Zone::load_with(Some(":Nowhere/City"), &zoneinfo, &missing).is_err());
        assert!(Zone::load_with(Some("../etc"), &zoneinfo, &missing).is_err());
        assert!(Zone::load_with(None, &zoneinfo, &missing).is_err(), "no localtime: Err, never UTC");
        std::os::unix::fs::symlink(&path, dir.join("localtime")).unwrap();
        let local = Zone::load_with(None, &zoneinfo, &dir.join("localtime")).unwrap();
        assert_eq!(local.name(), "America/New_York");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Agreement with the system tz database, when this host has one.
    #[test]
    fn the_system_new_york_file_agrees() {
        let Ok(bytes) = std::fs::read(Path::new(ZONEINFO_DIR).join("America/New_York")) else {
            return;
        };
        let z = Zone::from_tzif_bytes("America/New_York", &bytes).unwrap();
        // 2006 still ran the pre-2007 rule: first Sunday of April.
        assert_eq!(z.offset_at(utc(2006, 4, 2, 6, 59)), EST);
        assert_eq!(z.offset_at(utc(2006, 4, 2, 7, 0)), EDT);
        assert_eq!(z.offset_at(utc(2026, 3, 8, 7, 0)), EDT);
        assert_eq!(z.offset_at(utc(2026, 11, 1, 6, 0)), EST);
        assert_eq!(z.next_change_after(utc(2026, 3, 8, 7, 0)), Some(utc(2026, 11, 1, 6, 0)));
        assert_eq!(z.next_change_after(utc(2060, 1, 1, 0, 0)), Some(utc(2060, 3, 14, 7, 0)));
    }
}
