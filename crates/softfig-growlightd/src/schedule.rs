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
//! Slice 001 scaffold: the config parses into [`ScheduleDoc`] (carried on
//! [`crate::fleet::FleetConfig::schedule`]) and gates nothing yet. Slice 002
//! validates it into a typed config and evaluates windows against local time;
//! slice 003 wires the verdict into admission.

use std::collections::BTreeMap;

use serde::Deserialize;

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(s.windows, vec!["00:00-00:00".to_string()]);
        assert_eq!(s.close_grace_minutes, 45);
        assert!(s.window.is_empty() && s.reserve_weekly_pct.is_empty());
    }

    #[test]
    fn interim_defaults_hold_and_an_absent_table_is_none() {
        assert_eq!(parse("fleet_enabled = true\n").unwrap().schedule, None);
        let s = parse("[schedule]\n").unwrap().schedule.unwrap();
        assert!(!s.enabled, "the schedule is off unless enabled");
        assert!(s.tasks);
        assert_eq!(s.close_grace_minutes, DEFAULT_CLOSE_GRACE_MINUTES);
    }

    #[test]
    fn v1_windows_and_reserves_parse_beside_the_interim_keys() {
        let s = parse(concat!(
            "[schedule]\n",
            "enabled = true\n",
            "windows = [\"23:00-07:00\"]\n",
            "reserve_weekly_pct = { home = 25, \"*\" = 10 }\n",
            "[[schedule.window]]\n",
            "days = [\"mon-fri\"]\n",
            "start = \"10:00\"\n",
            "end = \"20:00\"\n",
            "backends = [\"opencode\"]\n",
        ))
        .unwrap()
        .schedule
        .unwrap();
        assert_eq!(s.reserve_weekly_pct.get("home"), Some(&25));
        assert_eq!(s.reserve_weekly_pct.get("*"), Some(&10));
        assert_eq!(s.window.len(), 1);
        let w = &s.window[0];
        assert_eq!((w.start.as_str(), w.end.as_str()), ("10:00", "20:00"));
        assert_eq!(w.backends.as_deref(), Some(&["opencode".to_string()][..]));
        assert_eq!(w.members, None);
    }

    #[test]
    fn an_unknown_schedule_key_fails_closed() {
        // A typo must never silently widen a window: the loader turns the Err
        // into a disabled fleet.
        assert!(parse("[schedule]\nenabeld = true\n").is_err());
        assert!(parse("[[schedule.window]]\nstart = \"1:00\"\nend = \"2:00\"\nday = []\n").is_err());
    }
}
