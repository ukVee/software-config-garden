//! Growlight **schedules** (milestone `growlight-schedule`, spec
//! `meta/spec-growlight-schedule.md` §3) — growlightd owns the clock.
//!
//! ## What this is
//!
//! The `[schedule]` table of `config/growlight.toml` and the per-tick verdict
//! the drive loop gates admission on. `fleet_enabled` stays the master arm;
//! the schedule only narrows admission *inside* an armed fleet (§3.7).
//!
//! - **Config** ([`ScheduleDoc`] / [`WindowDoc`]): the interim table the
//!   `growlight-window` timer reads (`enabled`, `windows = ["HH:MM-HH:MM"]`,
//!   `close_grace_minutes`, `tasks`) parses unchanged, beside the v1
//!   `[[schedule.window]]` rows and the per-pool `reserve_weekly_pct` (§3.1).
//!   Unknown keys are refused, so a typo fails closed at the loader instead of
//!   silently widening a window.
//! - **Verdict** ([`ScheduleVerdict`]): pure, computed once per tick from the
//!   config, the local zone and the wall clock (§3.3). The drive loop applies
//!   it as one more per-member filter beside the rate-limit hold — in the
//!   step 2 re-roll `workable` closure and the step 3 member loop, legacy and
//!   v2 alike — so a schedule-held member gets no claim, no spawn, no re-roll,
//!   no backoff and no page (§3.4).
//!
//! ## Edges
//!
//! Closing is **finish-iteration** (owner ruling 2): nothing here ever stops a
//! running member. A member mid-iteration runs to its handoff; only the
//! re-roll or fresh start that would follow is held. Waking from suspend needs
//! no special case: the first tick after wake evaluates the real wall clock, so
//! a window that opened during sleep opens late and one missed entirely is
//! never seen (ruling 4).
//!
//! ## Status
//!
//! Slice 002: the raw table validates into a typed [`ScheduleConfig`]
//! (carried on [`crate::fleet::FleetConfig::schedule`]; errors fail closed at
//! the loader) and [`evaluate`] computes the verdict against a
//! [`softfig_ipc::tz::Zone`]. Nothing gates admission yet: slice 003 wires the
//! verdict in, slice 004 adds the reserve hold, slice 003 the `tasks` exception.

use std::collections::BTreeMap;

use serde::Deserialize;
use softfig_ipc::model_choice::Backend;
use softfig_ipc::tz::Zone;

use crate::fleet::FleetMemberConfig;

/// `close_grace_minutes` when the key is absent — the interim timer's default.
pub const DEFAULT_CLOSE_GRACE_MINUTES: u32 = 45;

/// The raw `[schedule]` table, exactly as TOML spells it (§3.1).
///
/// The interim keys keep their interim defaults, so today's table means what
/// it meant to `growlight-window`. A missing table is `None` on
/// [`crate::fleet::FleetConfig::schedule`]: no schedule gate at all.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleDoc {
    /// The schedule's own switch. `false` (the default) leaves an armed fleet
    /// running at any hour, as before this milestone.
    #[serde(default)]
    pub enabled: bool,
    /// Interim windows, `"HH:MM-HH:MM"` local time, every day, every member.
    /// May cross midnight; `start == end` means the whole day.
    #[serde(default)]
    pub windows: Vec<String>,
    /// Minutes past a window's close after which a still-running member is
    /// flagged `overrun` (§3.4). Information only: v1 never kills a member.
    #[serde(default = "default_close_grace_minutes")]
    pub close_grace_minutes: u32,
    /// Whether an item whose `> Not before:` has arrived is admissible outside
    /// every window (§3.5).
    #[serde(default = "default_tasks")]
    pub tasks: bool,
    /// Per subscription pool (claude-login slot, `"*"` for the rest): leave this
    /// percentage of the weekly window for the owner (§3.6, ruling 5).
    #[serde(default)]
    pub reserve_weekly_pct: BTreeMap<String, u8>,
    /// `[[schedule.window]]` rows — the v1 window form.
    #[serde(default)]
    pub window: Vec<WindowDoc>,
}

fn default_close_grace_minutes() -> u32 {
    DEFAULT_CLOSE_GRACE_MINUTES
}

fn default_tasks() -> bool {
    true
}

/// One `[[schedule.window]]` row (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowDoc {
    /// Day names (`mon`..`sun`), ranges (`mon-fri`) or `daily`. Absent means
    /// every day. A window crossing midnight belongs to the day it starts.
    #[serde(default)]
    pub days: Option<Vec<String>>,
    /// Local wall-clock start, `HH:MM`.
    pub start: String,
    /// Local wall-clock end, `HH:MM`; may cross midnight.
    pub end: String,
    /// Only members on these backends (`claude` / `opencode`). Absent: any.
    #[serde(default)]
    pub backends: Option<Vec<String>>,
    /// Only these member ids. Absent: any. Both filters must match.
    #[serde(default)]
    pub members: Option<Vec<String>>,
}

/// The validated `[schedule]` (§3.1) — what [`crate::fleet::FleetConfig`]
/// carries. Only [`ScheduleConfig::from_doc`] builds one, so a window with an
/// out-of-range time or a filter naming no member cannot exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleConfig {
    /// The schedule's own switch; `false` evaluates to [`ScheduleVerdict::ungated`].
    pub enabled: bool,
    /// Every window, interim strings first, then `[[schedule.window]]` rows.
    /// The open set is their union.
    pub windows: Vec<Window>,
    /// See [`ScheduleDoc::close_grace_minutes`].
    pub close_grace_minutes: u32,
    /// See [`ScheduleDoc::tasks`].
    pub tasks: bool,
    /// Per pool, `0..=100`. See [`ScheduleDoc::reserve_weekly_pct`].
    pub reserve_weekly_pct: BTreeMap<String, u8>,
}

/// One validated window: a local wall-clock interval on a set of days, with
/// optional backend and member filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// The status label, e.g. `daily 23:00-07:00` or `mon-fri 10:00-20:00 [opencode]`.
    pub label: String,
    /// The days a run may *start* on.
    pub days: DaySet,
    /// Minutes after local midnight.
    pub start_min: u16,
    /// Minutes after local midnight. `end <= start` crosses midnight;
    /// `end == start` is a whole day.
    pub end_min: u16,
    /// Only members on these backends. `None`: any.
    pub backends: Option<Vec<Backend>>,
    /// Only these member ids. `None`: any.
    pub members: Option<Vec<String>>,
}

impl Window {
    /// Does this window's filter admit `member`? Both filters must match (§3.1).
    pub fn matches(&self, member: &MemberRef<'_>) -> bool {
        self.backends.as_ref().is_none_or(|b| b.contains(&member.backend))
            && self.members.as_ref().is_none_or(|m| m.iter().any(|a| a == member.agent))
    }

    /// The run attributed to local civil day `day`, as `[open, close)` Unix
    /// seconds, or `None` when the day is not in [`days`](Self::days) or DST
    /// swallows the whole run.
    fn run_on(&self, zone: &Zone, day: i64) -> Option<(i64, i64)> {
        if !self.days.contains(softfig_ipc::tz::weekday_of_days(day)) {
            return None;
        }
        let end_day = day + i64::from(self.end_min <= self.start_min);
        let open = zone.resolve_local(day * DAY + i64::from(self.start_min) * 60);
        let close = zone.resolve_local(end_day * DAY + i64::from(self.end_min) * 60);
        (open < close).then_some((open, close))
    }
}

/// A set of weekdays, bit `i` = weekday `i` (0 = Monday .. 6 = Sunday).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaySet(pub u8);

impl DaySet {
    /// Every day of the week.
    pub const ALL: DaySet = DaySet(0x7f);

    /// Is `weekday` (0 = Monday) in the set?
    pub fn contains(self, weekday: u8) -> bool {
        weekday < 7 && self.0 & (1 << weekday) != 0
    }
}

/// A fleet member as the schedule sees it: an id and a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberRef<'a> {
    /// The member's agent id.
    pub agent: &'a str,
    /// The backend it runs on.
    pub backend: Backend,
}

impl<'a> MemberRef<'a> {
    /// The schedule's view of a configured member.
    pub fn of(member: &'a FleetMemberConfig) -> Self {
        Self { agent: &member.agent, backend: member.backend.ipc_backend() }
    }
}

const DAY_NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

impl ScheduleConfig {
    /// Validate the raw table against the configured `members` (§3.1). Any
    /// error is the loader's to turn into a disabled fleet (fail-closed).
    pub fn from_doc(doc: &ScheduleDoc, members: &[FleetMemberConfig]) -> Result<Self, String> {
        let bad = |why: String| format!("[schedule] {why}");
        if let Some((pool, pct)) = doc.reserve_weekly_pct.iter().find(|(_, p)| **p > 100) {
            return Err(bad(format!("reserve_weekly_pct.{pool} = {pct} is over 100")));
        }
        let mut windows = Vec::with_capacity(doc.windows.len() + doc.window.len());
        for span in &doc.windows {
            let (start, end) = span
                .split_once('-')
                .ok_or_else(|| bad(format!("windows entry {span:?} is not \"HH:MM-HH:MM\"")))?;
            let start_min = parse_hhmm(start).map_err(&bad)?;
            let end_min = parse_hhmm(end).map_err(&bad)?;
            windows.push(Window {
                label: format!("daily {}-{}", hhmm(start_min), hhmm(end_min)),
                days: DaySet::ALL,
                start_min,
                end_min,
                backends: None,
                members: None,
            });
        }
        for (i, w) in doc.window.iter().enumerate() {
            let bad = |why: String| bad(format!("window #{}: {why}", i + 1));
            let start_min = parse_hhmm(&w.start).map_err(&bad)?;
            let end_min = parse_hhmm(&w.end).map_err(&bad)?;
            let (days, days_label) = match &w.days {
                None => (DaySet::ALL, "daily".to_string()),
                Some(list) => {
                    let set = parse_days(list).map_err(&bad)?;
                    let label = if set == DaySet::ALL { "daily".to_string() } else { list.join(",") };
                    (set, label)
                }
            };
            let mut label = format!("{days_label} {}-{}", hhmm(start_min), hhmm(end_min));
            let backends = match &w.backends {
                None => None,
                Some(list) => {
                    let parsed = list
                        .iter()
                        .map(|b| match b.as_str() {
                            "claude" => Ok(Backend::Claude),
                            "opencode" => Ok(Backend::Opencode),
                            other => Err(bad(format!("backend {other:?} is not claude or opencode"))),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    if parsed.is_empty() {
                        return Err(bad("backends = [] admits no member; omit the key for any".into()));
                    }
                    label.push_str(&format!(" [{}]", list.join(",")));
                    Some(parsed)
                }
            };
            if let Some(list) = &w.members {
                if list.is_empty() {
                    return Err(bad("members = [] admits no member; omit the key for any".into()));
                }
                if let Some(unknown) = list.iter().find(|a| !members.iter().any(|m| &m.agent == *a)) {
                    return Err(bad(format!("members names {unknown:?}, which is no [[fleet]] agent")));
                }
                label.push_str(&format!(" [{}]", list.join(",")));
            }
            windows.push(Window {
                label,
                days,
                start_min,
                end_min,
                backends,
                members: w.members.clone(),
            });
        }
        Ok(Self {
            enabled: doc.enabled,
            windows,
            close_grace_minutes: doc.close_grace_minutes,
            tasks: doc.tasks,
            reserve_weekly_pct: doc.reserve_weekly_pct.clone(),
        })
    }
}

/// `HH:MM` (one- or two-digit hour, two-digit minute) → minutes after midnight.
fn parse_hhmm(s: &str) -> Result<u16, String> {
    let bad = || format!("{s:?} is not a time HH:MM (00:00..23:59)");
    let (h, m) = s.split_once(':').ok_or_else(bad)?;
    let digits = |p: &str, lens: std::ops::RangeInclusive<usize>| {
        lens.contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit())
    };
    if !digits(h, 1..=2) || !digits(m, 2..=2) {
        return Err(bad());
    }
    let (h, m): (u16, u16) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if h > 23 || m > 59 {
        return Err(bad());
    }
    Ok(h * 60 + m)
}

fn hhmm(min: u16) -> String {
    format!("{:02}:{:02}", min / 60, min % 60)
}

/// Day names (`mon`..`sun`), ranges (`mon-fri`, wrapping `fri-mon`) and `daily`.
fn parse_days(list: &[String]) -> Result<DaySet, String> {
    if list.is_empty() {
        return Err("days = [] never opens; omit the key for every day".to_string());
    }
    let day = |name: &str| {
        DAY_NAMES
            .iter()
            .position(|d| d.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("day {name:?} is not one of mon..sun or daily"))
    };
    let mut set = 0u8;
    for entry in list {
        if entry.eq_ignore_ascii_case("daily") {
            set |= DaySet::ALL.0;
        } else if let Some((a, b)) = entry.split_once('-') {
            let (a, b) = (day(a)?, day(b)?);
            let mut d = a;
            loop {
                set |= 1 << d;
                if d == b {
                    break;
                }
                d = (d + 1) % 7;
            }
        } else {
            set |= 1 << day(entry)?;
        }
    }
    Ok(DaySet(set))
}

/// Why the schedule holds a member this tick (surfaced in `growlight status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldReason {
    /// No window is open at all.
    OutsideWindow,
    /// A window is open, but its backend/member filter excludes this member
    /// (ruling 3).
    NotInWindow,
    /// Every slot in the member's pool is at or past its weekly reserve.
    Reserve,
    /// The schedule is enabled but local time can't be read: fail-closed.
    ZoneUnreadable,
}

impl HoldReason {
    /// The short status label.
    pub fn label(self) -> &'static str {
        match self {
            Self::OutsideWindow => "outside window",
            Self::NotInWindow => "backend not in window",
            Self::Reserve => "reserve",
            Self::ZoneUnreadable => "local time unreadable",
        }
    }
}

/// The per-tick schedule decision (§3.3). Pure data: computed from the config,
/// the zone and `now`, read by the drive loop's admission filters and by
/// `status`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScheduleVerdict {
    /// Is any window open for any member?
    pub open: bool,
    /// Labels of the windows open right now (e.g. `daily 23:00-07:00 [claude]`).
    pub open_windows: Vec<String>,
    /// The next open or close edge, Unix seconds, exact across a DST change.
    pub next_edge: Option<i64>,
    /// Members held this tick, with the reason. A member absent here is
    /// admitted by the schedule (the governor and holds still apply).
    pub held: BTreeMap<String, HoldReason>,
}

impl ScheduleVerdict {
    /// The verdict when no schedule gates: everything open, nobody held.
    pub fn ungated() -> Self {
        Self { open: true, ..Self::default() }
    }

    /// Does the schedule admit `agent` this tick?
    pub fn admits(&self, agent: &str) -> bool {
        !self.held.contains_key(agent)
    }
}

const DAY: i64 = 86_400;

/// How many days past today [`evaluate`] looks for the next edge. A week
/// covers every weekday, so any edge of a weekly schedule shows up.
const HORIZON_DAYS: i64 = 7;

impl ScheduleVerdict {
    /// The verdict when the schedule is enabled but no local zone is readable:
    /// closed, every member held (§3.2, fail-closed).
    pub fn zone_unreadable(members: &[MemberRef<'_>]) -> Self {
        Self {
            held: members
                .iter()
                .map(|m| (m.agent.to_string(), HoldReason::ZoneUnreadable))
                .collect(),
            ..Self::default()
        }
    }
}

/// The schedule's verdict at `now` (Unix seconds) for `members` (§3.3). Pure.
///
/// A window is open while `now` lies in one of its runs; a run belongs to the
/// day it starts and its ends resolve through [`Zone::resolve_local`], so a
/// start in a spring-forward gap opens at the first instant after the gap and
/// an end in a fall-back repeat closes at the first occurrence. `next_edge` is
/// the next instant any window opens or closes, within a week; back-to-back
/// runs of one window (a whole-day window on consecutive days) are one run,
/// so an always-open schedule has no edge.
pub fn evaluate(cfg: &ScheduleConfig, zone: &Zone, now: i64, members: &[MemberRef<'_>]) -> ScheduleVerdict {
    if !cfg.enabled {
        return ScheduleVerdict::ungated();
    }
    let today = (now + i64::from(zone.offset_at(now))).div_euclid(DAY);
    // Edges at or past the horizon are unknowable from the days scanned.
    let horizon = zone.resolve_local((today + HORIZON_DAYS + 1) * DAY);
    let mut open = Vec::new();
    let mut next_edge: Option<i64> = None;
    for w in &cfg.windows {
        let mut runs: Vec<(i64, i64)> = Vec::new();
        for day in today - 1..=today + HORIZON_DAYS {
            let Some((s, e)) = w.run_on(zone, day) else { continue };
            match runs.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => runs.push((s, e)),
            }
        }
        for (s, e) in runs {
            if s <= now && now < e {
                open.push(w);
            }
            for edge in [s, e] {
                if edge > now && edge < horizon && next_edge.is_none_or(|n| edge < n) {
                    next_edge = Some(edge);
                }
            }
        }
    }
    let held = members
        .iter()
        .filter_map(|m| {
            let reason = if open.is_empty() {
                HoldReason::OutsideWindow
            } else if open.iter().any(|w| w.matches(m)) {
                return None;
            } else {
                HoldReason::NotInWindow
            };
            Some((m.agent.to_string(), reason))
        })
        .collect();
    ScheduleVerdict {
        open: !open.is_empty(),
        open_windows: open.iter().map(|w| w.label.clone()).collect(),
        next_edge,
        held,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::tz::days_of_civil;

    #[test]
    fn an_ungated_verdict_admits_everyone() {
        let v = ScheduleVerdict::ungated();
        assert!(v.open && v.admits("a"));
        let mut held = ScheduleVerdict::ungated();
        held.held.insert("a".into(), HoldReason::OutsideWindow);
        assert!(!held.admits("a") && held.admits("b"));
    }

    fn parse(toml: &str) -> Result<crate::fleet::FleetConfig, String> {
        crate::fleet::FleetConfig::from_growlight_toml(toml)
    }

    /// Two members: `a` on claude, `b` on opencode.
    const ROSTER: &str = concat!(
        "[[fleet]]\nagent = \"a\"\n",
        "[[fleet]]\nagent = \"b\"\nbackend = \"opencode\"\nmodel = \"deepseek/deepseek-flash\"\n",
    );

    fn schedule(body: &str) -> ScheduleConfig {
        parse(&format!("{ROSTER}[schedule]\nenabled = true\n{body}"))
            .expect("valid schedule")
            .schedule
            .expect("a [schedule] table")
    }

    #[test]
    fn the_interim_schedule_table_parses_unchanged() {
        // The table the interim `growlight-window` timer reads, as deployed
        // 2026-10-30 (services/notes/002).
        let cfg = parse(concat!(
            "fleet_enabled = true\n",
            "[schedule]\n",
            "enabled = true\n",
            "windows = [\"00:00-00:00\"]\n",
            "close_grace_minutes = 45\n",
            "tasks = true\n",
        ))
        .expect("the interim table is valid");
        let s = cfg.schedule.expect("a [schedule] table parses to Some");
        assert!(s.enabled && s.tasks);
        assert_eq!(s.close_grace_minutes, 45);
        assert!(s.reserve_weekly_pct.is_empty());
        let w = &s.windows[..];
        assert_eq!(w.len(), 1, "one interim string is one all-day-set window");
        assert_eq!((w[0].start_min, w[0].end_min, w[0].days), (0, 0, DaySet::ALL));
        assert_eq!((w[0].backends.as_ref(), w[0].members.as_ref()), (None, None));
        assert_eq!(w[0].label, "daily 00:00-00:00");
    }

    #[test]
    fn interim_defaults_hold_and_an_absent_table_is_none() {
        assert_eq!(parse("fleet_enabled = true\n").unwrap().schedule, None);
        let s = parse("[schedule]\n").unwrap().schedule.unwrap();
        assert!(!s.enabled, "the schedule is off unless enabled");
        assert!(s.tasks && s.windows.is_empty());
        assert_eq!(s.close_grace_minutes, DEFAULT_CLOSE_GRACE_MINUTES);
    }

    #[test]
    fn v1_windows_and_reserves_parse_beside_the_interim_keys() {
        let s = schedule(concat!(
            "windows = [\"23:00-07:00\"]\n",
            "reserve_weekly_pct = { home = 25, \"*\" = 10 }\n",
            "[[schedule.window]]\n",
            "days = [\"mon-fri\"]\n",
            "start = \"10:00\"\n",
            "end = \"20:00\"\n",
            "backends = [\"opencode\"]\n",
            "[[schedule.window]]\n",
            "days = [\"sat\", \"sun\"]\n",
            "start = \"9:30\"\n",
            "end = \"9:30\"\n",
            "members = [\"a\"]\n",
        ));
        assert_eq!(s.reserve_weekly_pct.get("home"), Some(&25));
        assert_eq!(s.reserve_weekly_pct.get("*"), Some(&10));
        let labels: Vec<_> = s.windows.iter().map(|w| w.label.as_str()).collect();
        assert_eq!(
            labels,
            ["daily 23:00-07:00", "mon-fri 10:00-20:00 [opencode]", "sat,sun 09:30-09:30 [a]"]
        );
        let w = &s.windows[1];
        assert_eq!((w.start_min, w.end_min, w.days), (600, 1200, DaySet(0b001_1111)));
        assert_eq!(w.backends, Some(vec![Backend::Opencode]));
        assert_eq!(s.windows[2].days, DaySet(0b110_0000));
        assert_eq!(s.windows[2].members, Some(vec!["a".to_string()]));
    }

    #[test]
    fn an_unknown_schedule_key_fails_closed() {
        // A typo must never silently widen a window: the loader turns the Err
        // into a disabled fleet.
        assert!(parse("[schedule]\nenabeld = true\n").is_err());
        assert!(parse("[[schedule.window]]\nstart = \"1:00\"\nend = \"2:00\"\nday = []\n").is_err());
    }

    #[test]
    fn validation_refuses_what_could_widen_or_silently_never_open() {
        let refused = |body: &str| {
            let err = parse(&format!("{ROSTER}[schedule]\n{body}")).expect_err(body);
            assert!(err.starts_with("[schedule]"), "{err}");
        };
        for span in ["24:00-01:00", "07:60-08:00", "7:5-8:00", "0700-0800", "07:00", "a:00-b:00"] {
            refused(&format!("windows = [\"{span}\"]\n"));
        }
        let row = |extra: &str| format!("[[schedule.window]]\nstart = \"01:00\"\nend = \"02:00\"\n{extra}");
        refused(&row("days = [\"funday\"]\n"));
        refused(&row("days = [\"mon-xyz\"]\n"));
        refused(&row("days = []\n"));
        refused(&row("backends = [\"gemini\"]\n"));
        refused(&row("backends = []\n"));
        refused(&row("members = [\"zed\"]\n"));
        refused(&row("members = []\n"));
        refused("reserve_weekly_pct = { home = 101 }\n");
        // Wrapping ranges and `daily` are fine.
        let s = schedule(&row("days = [\"fri-mon\"]\n"));
        assert_eq!(s.windows[0].days, DaySet(0b111_0001));
        assert_eq!(schedule(&row("days = [\"daily\"]\n")).windows[0].label, "daily 01:00-02:00");
    }

    // ---- evaluation, in America/New_York ------------------------------------

    fn ny() -> Zone {
        Zone::from_posix("EST5EDT,M3.2.0,M11.1.0").unwrap()
    }

    /// Local wall time in New York with an explicit offset (hours).
    fn at(y: i64, mo: u32, d: u32, h: i64, mi: i64, utc_offset_h: i64) -> i64 {
        days_of_civil(y, mo, d) * DAY + (h - utc_offset_h) * 3600 + mi * 60
    }

    const EDT: i64 = -4;
    const EST: i64 = -5;

    fn members() -> [MemberRef<'static>; 2] {
        [
            MemberRef { agent: "a", backend: Backend::Claude },
            MemberRef { agent: "b", backend: Backend::Opencode },
        ]
    }

    fn eval(cfg: &ScheduleConfig, now: i64) -> ScheduleVerdict {
        evaluate(cfg, &ny(), now, &members())
    }

    #[test]
    fn a_disabled_schedule_gates_nothing_and_an_unreadable_zone_closes() {
        let mut cfg = schedule("windows = [\"01:00-02:00\"]\n");
        cfg.enabled = false;
        assert_eq!(eval(&cfg, at(2026, 10, 28, 12, 0, EDT)), ScheduleVerdict::ungated());
        let v = ScheduleVerdict::zone_unreadable(&members());
        assert!(!v.open && !v.admits("a") && !v.admits("b"));
        assert_eq!(v.held.get("a"), Some(&HoldReason::ZoneUnreadable));
    }

    #[test]
    fn a_window_crossing_midnight_belongs_to_its_start_day() {
        let cfg = schedule("[[schedule.window]]\ndays = [\"fri\"]\nstart = \"23:00\"\nend = \"07:00\"\n");
        // Fri 2026-10-30 23:00 runs into Saturday morning.
        let v = eval(&cfg, at(2026, 10, 31, 3, 0, EDT));
        assert!(v.open && v.admits("a") && v.admits("b"));
        assert_eq!(v.open_windows, ["fri 23:00-07:00"]);
        assert_eq!(v.next_edge, Some(at(2026, 10, 31, 7, 0, EDT)));
        // Saturday 23:30 is closed: only Friday is listed.
        let v = eval(&cfg, at(2026, 10, 31, 23, 30, EDT));
        assert!(!v.open);
        assert_eq!(v.held.get("a"), Some(&HoldReason::OutsideWindow));
        assert_eq!(v.held.get("b"), Some(&HoldReason::OutsideWindow));
        // Next Friday 23:00 EST (DST has ended by then).
        assert_eq!(v.next_edge, Some(at(2026, 11, 6, 23, 0, EST)));
    }

    #[test]
    fn an_all_day_window_is_always_open_with_no_edge() {
        let cfg = schedule("windows = [\"00:00-00:00\"]\n");
        for now in [
            at(2026, 10, 28, 12, 0, EDT),
            at(2026, 3, 8, 1, 59, EST),
            at(2026, 3, 8, 3, 0, EDT),
            at(2026, 11, 1, 1, 30, EST),
        ] {
            let v = eval(&cfg, now);
            assert!(v.open && v.held.is_empty(), "open at {now}");
            assert_eq!(v.next_edge, None, "an always-open schedule has no edge");
        }
    }

    #[test]
    fn the_days_filter_holds_off_days() {
        let cfg = schedule("[[schedule.window]]\ndays = [\"mon-fri\"]\nstart = \"10:00\"\nend = \"20:00\"\n");
        assert!(eval(&cfg, at(2026, 10, 30, 12, 0, EDT)).open, "Friday");
        let sat = eval(&cfg, at(2026, 10, 31, 12, 0, EDT));
        assert!(!sat.open, "Saturday");
        assert_eq!(sat.next_edge, Some(at(2026, 11, 2, 10, 0, EST)), "Monday 10:00");
    }

    #[test]
    fn next_edge_on_a_plain_day() {
        let cfg = schedule("windows = [\"23:00-07:00\"]\n");
        let v = eval(&cfg, at(2026, 10, 28, 12, 0, EDT));
        assert!(!v.open);
        assert_eq!(v.next_edge, Some(at(2026, 10, 28, 23, 0, EDT)));
        let v = eval(&cfg, at(2026, 10, 28, 23, 0, EDT));
        assert!(v.open, "a window is open at its start instant");
        assert_eq!(v.next_edge, Some(at(2026, 10, 29, 7, 0, EDT)));
        assert!(!eval(&cfg, at(2026, 10, 29, 7, 0, EDT)).open, "and closed at its end instant");
    }

    #[test]
    fn next_edge_across_the_2026_11_01_fall_back() {
        // Sat 23:00 EDT -> Sun 07:00 EST is nine real hours.
        let cfg = schedule("windows = [\"23:00-07:00\"]\n");
        let v = eval(&cfg, at(2026, 11, 1, 1, 30, EST));
        assert!(v.open);
        assert_eq!(v.next_edge, Some(at(2026, 11, 1, 7, 0, EST)));
        // An end inside the repeated hour closes at the first (EDT) 01:30.
        let cfg = schedule("windows = [\"00:00-01:30\"]\n");
        let v = eval(&cfg, at(2026, 11, 1, 0, 30, EDT));
        assert!(v.open);
        assert_eq!(v.next_edge, Some(at(2026, 11, 1, 1, 30, EDT)));
        assert!(!eval(&cfg, at(2026, 11, 1, 1, 0, EST)).open, "the second 01:00 is past the close");
    }

    #[test]
    fn next_edge_across_the_2026_03_08_spring_forward() {
        // 02:30 never happens that night: the window opens at 03:00 EDT.
        let cfg = schedule("windows = [\"02:30-05:00\"]\n");
        let v = eval(&cfg, at(2026, 3, 8, 1, 0, EST));
        assert!(!v.open);
        let jump = at(2026, 3, 8, 3, 0, EDT);
        assert_eq!(v.next_edge, Some(jump));
        assert!(!eval(&cfg, jump - 1).open);
        let v = eval(&cfg, jump);
        assert!(v.open);
        assert_eq!(v.next_edge, Some(at(2026, 3, 8, 5, 0, EDT)));
        // A run wholly inside the gap never opens.
        let cfg = schedule("windows = [\"02:00-02:30\"]\n");
        assert_eq!(eval(&cfg, at(2026, 3, 8, 1, 0, EST)).next_edge, Some(at(2026, 3, 9, 2, 0, EDT)));
    }

    #[test]
    fn two_windows_union_and_filters_pick_members() {
        let cfg = schedule(concat!(
            "[[schedule.window]]\nstart = \"10:00\"\nend = \"12:00\"\nbackends = [\"claude\"]\n",
            "[[schedule.window]]\nstart = \"11:00\"\nend = \"13:00\"\nmembers = [\"b\"]\n",
        ));
        let day = |h, mi| at(2026, 10, 28, h, mi, EDT);
        let v = eval(&cfg, day(10, 30));
        assert!(v.open && v.admits("a"));
        assert_eq!(v.held.get("b"), Some(&HoldReason::NotInWindow));
        assert_eq!(v.next_edge, Some(day(11, 0)));
        let v = eval(&cfg, day(11, 30));
        assert!(v.held.is_empty(), "the union admits both");
        assert_eq!(v.open_windows, ["daily 10:00-12:00 [claude]", "daily 11:00-13:00 [b]"]);
        let v = eval(&cfg, day(12, 30));
        assert_eq!(v.held.get("a"), Some(&HoldReason::NotInWindow));
        assert!(v.admits("b"));
        let v = eval(&cfg, day(14, 0));
        assert!(!v.open);
        assert_eq!(v.held.get("a"), Some(&HoldReason::OutsideWindow));
        assert_eq!(v.next_edge, Some(at(2026, 10, 29, 10, 0, EDT)));
        // Overlapping windows with no filters are one open set.
        let cfg = schedule("windows = [\"01:00-03:00\", \"02:00-04:00\"]\n");
        let v = eval(&cfg, at(2026, 10, 28, 3, 30, EDT));
        assert!(v.open && v.held.is_empty());
        assert_eq!(v.open_windows, ["daily 02:00-04:00"]);
    }
}
