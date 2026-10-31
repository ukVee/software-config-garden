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
//! [`softfig_ipc::tz::Zone`]. Slice 003: the drive loop evaluates it every
//! tick through a [`ZoneSource`] and gates admission on
//! [`ScheduleVerdict::admission`], including the `tasks` exception. Slice 004:
//! [`apply_reserve`] adds the weekly reserve per claude-login slot (§3.6) —
//! a member whose every pool slot is held gets [`HoldReason::Reserve`], and
//! the profile picker skips a held slot while its pool has a clear one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::Deserialize;
use softfig_ipc::model_choice::Backend;
use softfig_ipc::tz::{Zone, LOCALTIME_PATH, ZONEINFO_DIR};

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

impl ScheduleConfig {
    /// `slot`'s weekly reserve, `0..=100`: its own `reserve_weekly_pct` key,
    /// else the `"*"` default, else `0` (no reserve, §3.6).
    pub fn reserve_pct(&self, slot: &str) -> u8 {
        self.reserve_weekly_pct
            .get(slot)
            .or_else(|| self.reserve_weekly_pct.get(RESERVE_DEFAULT_KEY))
            .copied()
            .unwrap_or(0)
    }
}

/// The `reserve_weekly_pct` key that covers every slot not named on its own.
pub const RESERVE_DEFAULT_KEY: &str = "*";

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
    /// The weekly reserve of every slot in a member's admission pool, from
    /// [`apply_reserve`]. Empty until that pass runs.
    pub reserves: BTreeMap<String, SlotReserve>,
    /// The local zone's name, or `unreadable: <why>`. Empty while ungated.
    pub zone: String,
    /// [`next_edge`](Self::next_edge) as local time, `YYYY-MM-DD HH:MM ±HH:MM`.
    pub next_edge_local: Option<String>,
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

    /// How far the schedule admits `agent` this tick, given the config's
    /// `tasks` switch (§3.5). A member held only because no window is open to
    /// it — [`HoldReason::OutsideWindow`] or [`HoldReason::NotInWindow`] — may
    /// still take an item whose `> Not before:` has arrived when `tasks` is
    /// on: the item opens its own window, to any member. A reserve hold or an
    /// unreadable zone holds outright.
    pub fn admission(&self, agent: &str, tasks: bool) -> Admission {
        match self.held.get(agent) {
            None => Admission::Open,
            Some(HoldReason::OutsideWindow | HoldReason::NotInWindow) if tasks => {
                Admission::TimedOnly
            }
            Some(&reason) => Admission::Held(reason),
        }
    }
}

impl ScheduleVerdict {
    /// The slots at or past their weekly reserve: the profile picker skips
    /// these while another slot of the pool is clear (§3.6).
    pub fn reserve_held_slots(&self) -> BTreeSet<String> {
        self.reserves
            .iter()
            .filter(|(_, reserve)| reserve.state == ReserveState::Held)
            .map(|(slot, _)| slot.clone())
            .collect()
    }
}

/// A slot's vouchable 7d reading (§3.6): the used share the reserve compares,
/// and when that window resets, if the reading said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading7d {
    pub used_pct: u8,
    pub resets_at: Option<i64>,
}

/// One slot's weekly reserve this tick: its state, plus what `status` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotReserve {
    pub state: ReserveState,
    /// The share kept back ([`ScheduleConfig::reserve_pct`]).
    pub reserve_pct: u8,
    /// The reading, when one vouched. Never read for a slot keeping no reserve.
    pub reading: Option<Reading7d>,
}

/// One slot's weekly reserve state this tick (§3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveState {
    /// The vouchable 7d reading is at or past `100 − reserve`: no new spawn on
    /// this slot until the 7d window resets.
    Held,
    /// Below the threshold, or the slot keeps no reserve.
    Clear,
    /// No vouchable 7d reading (none at all, no `used_percentage`, or a
    /// `resets_at` that has passed). Never held: an unusable reading is not a
    /// low one (protocol §2b).
    Unknown,
}

impl ReserveState {
    /// The short status label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Clear => "clear",
            Self::Unknown => "unknown",
        }
    }
}

/// A slot's reserve state from its reserve `pct` and its vouchable 7d
/// percentage (`None` when no reading can vouch for one). Pure.
///
/// A reserve of `0` keeps nothing back, so it is [`ReserveState::Clear`]
/// whatever the reading says: a weekly-exhausted slot is the rate-limit
/// path's to hold, not the reserve's.
pub fn reserve_state(pct: u8, vouchable_7d: Option<u8>) -> ReserveState {
    if pct == 0 {
        return ReserveState::Clear;
    }
    match vouchable_7d {
        None => ReserveState::Unknown,
        Some(used) if u16::from(used) + u16::from(pct) >= 100 => ReserveState::Held,
        Some(_) => ReserveState::Clear,
    }
}

/// Add the weekly reserve to `verdict` (§3.6). Pure over its inputs.
///
/// `pools` is each member's admission pool, as the rate-limit hold reads it
/// (an opencode member's is empty, so it is never reserve-held). `vouchable_7d`
/// gives a slot's vouchable 7d reading, and is asked only for a slot that
/// keeps a reserve. Every pool slot lands in [`ScheduleVerdict::reserves`]. A
/// member whose every slot is [`ReserveState::Held`] is held with
/// [`HoldReason::Reserve`], which replaces a window hold (the reserve holds
/// outright, even from a timed item) but never an unreadable zone.
pub fn apply_reserve(
    verdict: &mut ScheduleVerdict,
    cfg: &ScheduleConfig,
    pools: &[(&str, Vec<String>)],
    mut vouchable_7d: impl FnMut(&str) -> Option<Reading7d>,
) {
    for (agent, pool) in pools {
        for slot in pool {
            if !verdict.reserves.contains_key(slot) {
                let reserve_pct = cfg.reserve_pct(slot);
                let reading = if reserve_pct == 0 { None } else { vouchable_7d(slot) };
                let state = reserve_state(reserve_pct, reading.map(|r| r.used_pct));
                verdict.reserves.insert(slot.clone(), SlotReserve { state, reserve_pct, reading });
            }
        }
        let all_held = !pool.is_empty()
            && pool.iter().all(|slot| verdict.reserves[slot].state == ReserveState::Held);
        if all_held && verdict.held.get(*agent) != Some(&HoldReason::ZoneUnreadable) {
            verdict.held.insert((*agent).to_string(), HoldReason::Reserve);
        }
    }
}

/// What the schedule lets one member do this tick ([`ScheduleVerdict::admission`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Admitted as if no schedule gated.
    Open,
    /// Admitted only to an item whose `> Not before:` has arrived (§3.5).
    TimedOnly,
    /// Not admitted: no claim, no spawn, no re-roll (§3.4).
    Held(HoldReason),
}

/// The seam the drive loop reads local time through (slice 003). The live
/// [`SystemZone`] reloads when the zone's source changes; a test injects a
/// fixed zone or a fixed failure.
pub trait ZoneSource: Send + fmt::Debug {
    /// The current local zone, or why it can't be read. Called once per tick,
    /// and only while a schedule is enabled.
    fn zone(&mut self) -> Result<&Zone, String>;
}

/// The system's local zone ([`Zone::load`]), reloaded when its source's
/// identity changes: `$TZ`, and the file it resolves to (`/etc/localtime`
/// when `$TZ` is unset) — the symlink target plus the file's inode, size and
/// mtime. One `stat` per tick; a zone that fails to load is retried only when
/// the identity changes, and its error is kept until then.
#[derive(Debug, Default)]
pub struct SystemZone {
    identity: Option<ZoneIdentity>,
    loaded: Option<Result<Zone, String>>,
}

/// What [`SystemZone`] compares to decide a reload.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZoneIdentity {
    tz: Option<String>,
    link: Option<PathBuf>,
    file: Option<(u64, u64, Option<SystemTime>)>,
}

impl ZoneIdentity {
    fn now() -> Self {
        let tz = std::env::var("TZ").ok();
        let path = match tz.as_deref() {
            None => Some(PathBuf::from(LOCALTIME_PATH)),
            Some(spec) => {
                let spec = spec.strip_prefix(':').unwrap_or(spec);
                if spec.is_empty() {
                    None
                } else if spec.starts_with('/') {
                    Some(PathBuf::from(spec))
                } else {
                    Some(PathBuf::from(ZONEINFO_DIR).join(spec))
                }
            }
        };
        let link = path.as_deref().and_then(|p| std::fs::read_link(p).ok());
        let file = path.as_deref().and_then(|p| std::fs::metadata(p).ok()).map(|m| {
            use std::os::unix::fs::MetadataExt;
            (m.ino(), m.len(), m.modified().ok())
        });
        Self { tz, link, file }
    }
}

impl SystemZone {
    /// A source that loads on first use.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ZoneSource for SystemZone {
    fn zone(&mut self) -> Result<&Zone, String> {
        let identity = ZoneIdentity::now();
        if self.loaded.is_none() || self.identity.as_ref() != Some(&identity) {
            self.loaded = Some(Zone::load());
            self.identity = Some(identity);
        }
        match self.loaded.as_ref() {
            Some(Ok(zone)) => Ok(zone),
            Some(Err(e)) => Err(e.clone()),
            None => Err("local zone not loaded".to_string()),
        }
    }
}

const DAY: i64 = 86_400;

/// How many days past today [`evaluate`] looks for the next edge. A week
/// covers every weekday, so any edge of a weekly schedule shows up.
const HORIZON_DAYS: i64 = 7;

impl ScheduleVerdict {
    /// The verdict when the schedule is enabled but no local zone is readable
    /// (`why`): closed, every member held (§3.2, fail-closed).
    pub fn zone_unreadable(members: &[MemberRef<'_>], why: &str) -> Self {
        Self {
            zone: format!("unreadable: {why}"),
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
        reserves: BTreeMap::new(),
        zone: zone.name().to_string(),
        next_edge_local: next_edge.map(|edge| local_label(zone, edge)),
    }
}

/// `unix` as local time in `zone`, `YYYY-MM-DD HH:MM ±HH:MM` — what `status`
/// shows for the next edge.
pub fn local_label(zone: &Zone, unix: i64) -> String {
    let t = zone.local(unix);
    let sign = if t.offset < 0 { '-' } else { '+' };
    let off = t.offset.unsigned_abs() / 60;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} {sign}{:02}:{:02}",
        t.y,
        t.mo,
        t.d,
        t.h,
        t.mi,
        off / 60,
        off % 60
    )
}

/// The `status` block for a verdict (§3.8). `overrun` names the members
/// still running more than `close_grace_minutes` past their window's close;
/// each shows as `overrun` in place of its window reason. `held_items` are
/// the items waiting on `> Not before:`.
pub fn summary(
    verdict: &ScheduleVerdict,
    overrun: &BTreeSet<String>,
    held_items: Vec<String>,
) -> softfig_ipc::growlightd::ScheduleSummary {
    use softfig_ipc::growlightd::{ReserveSummary, ScheduleHeld, ScheduleSummary};
    ScheduleSummary {
        open: verdict.open,
        current_windows: verdict.open_windows.clone(),
        next_edge: verdict.next_edge,
        next_edge_local: verdict.next_edge_local.clone(),
        zone: verdict.zone.clone(),
        held_members: verdict
            .held
            .iter()
            .map(|(agent, reason)| ScheduleHeld {
                agent: agent.clone(),
                reason: if overrun.contains(agent) { OVERRUN } else { reason.label() }.to_string(),
            })
            .collect(),
        held_items,
        reserve: verdict
            .reserves
            .iter()
            .map(|(slot, r)| ReserveSummary {
                slot: slot.clone(),
                reserve_pct: r.reserve_pct,
                used_7d_pct: r.reading.map(|x| x.used_pct),
                held: r.state == ReserveState::Held,
                resets_at: r.reading.and_then(|x| x.resets_at),
            })
            .collect(),
        projection: Vec::new(),
    }
}

/// The `status` reason for a member past its close grace (§3.4).
pub const OVERRUN: &str = "overrun";

/// Whether `reason` is a window closing on a member — the holds a running
/// member can overrun (§3.4). A reserve hold or an unreadable zone is not a
/// window's close.
pub fn is_window_hold(reason: HoldReason) -> bool {
    matches!(reason, HoldReason::OutsideWindow | HoldReason::NotInWindow)
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
    fn admission_lets_only_a_window_hold_through_to_timed_items() {
        let verdict = ScheduleVerdict {
            held: BTreeMap::from([
                ("out".to_string(), HoldReason::OutsideWindow),
                ("filtered".to_string(), HoldReason::NotInWindow),
                ("reserve".to_string(), HoldReason::Reserve),
                ("zone".to_string(), HoldReason::ZoneUnreadable),
            ]),
            ..ScheduleVerdict::default()
        };
        assert_eq!(verdict.admission("free", true), Admission::Open);
        assert_eq!(verdict.admission("out", true), Admission::TimedOnly);
        assert_eq!(verdict.admission("filtered", true), Admission::TimedOnly);
        assert_eq!(verdict.admission("out", false), Admission::Held(HoldReason::OutsideWindow));
        assert_eq!(verdict.admission("reserve", true), Admission::Held(HoldReason::Reserve));
        assert_eq!(verdict.admission("zone", true), Admission::Held(HoldReason::ZoneUnreadable));
    }

    #[test]
    fn a_reserve_holds_at_its_threshold_and_never_on_an_unvouchable_reading() {
        assert_eq!(reserve_state(25, Some(75)), ReserveState::Held, "at 100 - X");
        assert_eq!(reserve_state(25, Some(90)), ReserveState::Held);
        assert_eq!(reserve_state(25, Some(74)), ReserveState::Clear, "below it");
        assert_eq!(reserve_state(25, None), ReserveState::Unknown);
        assert_eq!(reserve_state(0, Some(100)), ReserveState::Clear, "no reserve kept");
        assert_eq!(reserve_state(100, Some(0)), ReserveState::Held, "a whole-week reserve");
    }

    #[test]
    fn a_slot_takes_its_own_reserve_else_the_star_default_else_none() {
        let cfg = schedule("reserve_weekly_pct = { home = 25, \"*\" = 10 }\n");
        assert_eq!(cfg.reserve_pct("home"), 25);
        assert_eq!(cfg.reserve_pct("slot1"), 10);
        assert_eq!(schedule("").reserve_pct("slot1"), 0);
    }

    #[test]
    fn a_member_is_reserve_held_only_when_every_pool_slot_is() {
        let cfg = schedule("reserve_weekly_pct = { slot1 = 20, slot2 = 20 }\n");
        let used = BTreeMap::from([("slot1", 85), ("slot2", 50), ("slot3", 99)]);
        let pools = vec![
            ("two", vec!["slot1".to_string(), "slot2".to_string()]),
            ("one", vec!["slot1".to_string()]),
            ("free", vec!["slot3".to_string()]),
            ("metered", Vec::new()),
        ];
        let mut verdict = ScheduleVerdict::ungated();
        apply_reserve(&mut verdict, &cfg, &pools, |slot| {
            used.get(slot).map(|&used_pct| Reading7d { used_pct, resets_at: None })
        });
        assert_eq!(verdict.held, BTreeMap::from([("one".to_string(), HoldReason::Reserve)]));
        assert_eq!(verdict.reserve_held_slots(), BTreeSet::from(["slot1".to_string()]));
        assert_eq!(verdict.reserves["slot2"].state, ReserveState::Clear);
        assert_eq!(verdict.reserves["slot3"].state, ReserveState::Clear, "slot3 keeps no reserve");
        assert_eq!(verdict.reserves["slot3"].reading, None, "and its reading is never asked");
        assert_eq!(verdict.admission("one", true), Admission::Held(HoldReason::Reserve));
    }

    #[test]
    fn a_reserve_hold_replaces_a_window_hold_but_not_an_unreadable_zone() {
        let cfg = schedule("reserve_weekly_pct = { \"*\" = 10 }\n");
        let pools = vec![("out", vec!["home".to_string()]), ("zone", vec!["home".to_string()])];
        let mut verdict = ScheduleVerdict {
            held: BTreeMap::from([
                ("out".to_string(), HoldReason::OutsideWindow),
                ("zone".to_string(), HoldReason::ZoneUnreadable),
            ]),
            ..ScheduleVerdict::default()
        };
        apply_reserve(&mut verdict, &cfg, &pools, |_| Some(Reading7d { used_pct: 95, resets_at: None }));
        assert_eq!(verdict.held["out"], HoldReason::Reserve);
        assert_eq!(verdict.held["zone"], HoldReason::ZoneUnreadable);
        let mut unknown = ScheduleVerdict::ungated();
        apply_reserve(&mut unknown, &cfg, &pools, |_| None);
        assert!(unknown.held.is_empty());
        assert_eq!(unknown.reserves["home"].state, ReserveState::Unknown);
    }

    #[test]
    fn the_system_zone_loads_once_and_keeps_its_answer_while_the_source_is_unchanged() {
        let mut zone = SystemZone::new();
        let first = zone.zone().map(|z| z.name().to_string());
        assert_eq!(zone.zone().map(|z| z.name().to_string()), first);
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
        let v = ScheduleVerdict::zone_unreadable(&members(), "no /etc/localtime");
        assert!(!v.open && !v.admits("a") && !v.admits("b"));
        assert_eq!(v.held.get("a"), Some(&HoldReason::ZoneUnreadable));
        assert_eq!(v.zone, "unreadable: no /etc/localtime");
    }

    #[test]
    fn the_status_block_names_the_zone_the_local_edge_reserves_and_overruns() {
        let cfg = schedule(concat!(
            "windows = [\"23:00-07:00\"]\n",
            "reserve_weekly_pct = { slot1 = 20 }\n",
        ));
        let mut v = eval(&cfg, at(2026, 10, 28, 12, 0, EDT));
        assert_eq!(v.next_edge_local.as_deref(), Some("2026-10-28 23:00 -04:00"));
        let pools = vec![("a", vec!["slot1".to_string()]), ("b", vec!["slot2".to_string()])];
        apply_reserve(&mut v, &cfg, &pools, |_| {
            Some(Reading7d { used_pct: 50, resets_at: Some(99) })
        });
        let s = summary(&v, &BTreeSet::from(["b".to_string()]), vec!["q/084".into()]);
        assert!(!s.open && s.current_windows.is_empty());
        assert_eq!(s.zone, v.zone);
        assert!(!s.zone.is_empty());
        let held: Vec<(&str, &str)> =
            s.held_members.iter().map(|h| (h.agent.as_str(), h.reason.as_str())).collect();
        assert_eq!(held, [("a", "outside window"), ("b", OVERRUN)]);
        assert_eq!(s.held_items, ["q/084"]);
        let slot1 = &s.reserve[0];
        assert_eq!((slot1.slot.as_str(), slot1.reserve_pct, slot1.used_7d_pct), ("slot1", 20, Some(50)));
        assert_eq!((slot1.held, slot1.resets_at), (false, Some(99)));
        // slot2 keeps no reserve, so its reading is never taken.
        assert_eq!((s.reserve[1].reserve_pct, s.reserve[1].used_7d_pct), (0, None));
        assert!(s.projection.is_empty(), "slice 008");
    }

    #[test]
    fn a_local_label_carries_the_offset_in_force() {
        let ny = ny();
        assert_eq!(local_label(&ny, at(2026, 11, 1, 1, 30, EDT)), "2026-11-01 01:30 -04:00");
        assert_eq!(local_label(&Zone::utc(), 0), "1970-01-01 00:00 +00:00");
        assert!(is_window_hold(HoldReason::NotInWindow) && !is_window_hold(HoldReason::Reserve));
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
    fn a_window_filter_is_backends_and_members() {
        let window = |backends: Option<&[Backend]>, ids: Option<&[&str]>| Window {
            label: String::new(),
            days: DaySet::ALL,
            start_min: 0,
            end_min: 0,
            backends: backends.map(<[Backend]>::to_vec),
            members: ids.map(|ids| ids.iter().map(|s| s.to_string()).collect()),
        };
        let [a, b] = members();
        let claude: &[Backend] = &[Backend::Claude];
        let both: &[Backend] = &[Backend::Claude, Backend::Opencode];
        // (backends, members) → (admits a [claude], admits b [opencode])
        let matrix = [
            (None, None, (true, true)),
            (Some(claude), None, (true, false)),
            (Some(both), None, (true, true)),
            (None, Some(&["b"][..]), (false, true)),
            (Some(claude), Some(&["a", "b"][..]), (true, false)),
            (Some(claude), Some(&["b"][..]), (false, false)),
            (Some(both), Some(&["b"][..]), (false, true)),
        ];
        for (backends, ids, want) in matrix {
            let w = window(backends, ids);
            assert_eq!((w.matches(&a), w.matches(&b)), want, "{backends:?} {ids:?}");
        }
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
