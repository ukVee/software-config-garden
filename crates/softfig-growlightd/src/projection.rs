//! The **budget projection** (milestone `growlight-schedule` slice 008, spec
//! `meta/spec-growlight-schedule.md` §3.11): when each claude-login slot's
//! 5h and 7d windows are projected to reach their cap, and the 7d window its
//! reserve threshold (§3.6), shown as a range and never a point.
//!
//! ## Samples
//!
//! A [`SampleRing`] per slot keeps the used percentages the drive loop
//! already reads each tick (the slot's `usage.by-profile/<slot>.json`, plus
//! the shared `usage.json` when it names the slot). It lives in memory only:
//! nothing here touches disk (eMMC), and a restarted daemon starts with
//! `unknown` until two fresh readings land.
//!
//! - A sample is a reading's own `ts`, not the tick's clock, so re-reading an
//!   unchanged file adds nothing. A reading no newer than the ring's newest is
//!   ignored.
//! - Only a reading that measured a percentage is kept: a headless capture
//!   (status + `resets_at`, no `used_percentage`) is not a sample.
//! - One ring holds one window. A new `resets_at`, or a percentage lower than
//!   the last, is a reset: the old window's samples are dropped.
//! - The ring is bounded twice. Samples closer together than the window's
//!   spacing replace the newest instead of adding one, so the newest is always
//!   the freshest reading, and the oldest fall off past a fixed count.
//!
//! ## Projection
//!
//! [`project`] anchors at the newest sample. For each of a few look-back
//! spans it takes the oldest sample inside the span and the burn between the
//! two; the fastest burn gives `cap_at_earliest`, the slowest `cap_at_latest`.
//! A span holding one sample gives no burn, so fewer than two vouchable
//! samples is `unknown`. A window whose `resets_at` has passed is unknown too
//! (`RateWindow::vouchable_pct_at`'s rule): those samples describe a window
//! that no longer exists. A cap time at or past `resets_at` is dropped, and
//! when even the fastest burn misses the reset the row says `resets_first`.
//!
//! Metered (opencode) pools have no rate window and get no row; their $/hour
//! projection waits for a configured spend cap.

use std::collections::{BTreeMap, VecDeque};

use softfig_ipc::growlightd::PoolProjection;
use softfig_ipc::usage::{RateWindow, UsageSnapshot};

/// One rate window a [`SampleRing`] tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    FiveHour,
    SevenDay,
}

impl WindowKind {
    /// The status label ([`PoolProjection::window`]).
    pub fn label(self) -> &'static str {
        match self {
            Self::FiveHour => "5h",
            Self::SevenDay => "7d",
        }
    }

    /// The least time between two kept samples, seconds.
    fn spacing(self) -> i64 {
        match self {
            Self::FiveHour => 60,
            Self::SevenDay => 600,
        }
    }

    /// The most samples kept: a whole window at [`spacing`](Self::spacing).
    fn cap(self) -> usize {
        match self {
            Self::FiveHour => 300,
            Self::SevenDay => 1008,
        }
    }

    /// The look-back spans the burn range is taken over, seconds.
    fn spans(self) -> [i64; 3] {
        match self {
            Self::FiveHour => [30 * 60, 2 * 3600, 5 * 3600],
            Self::SevenDay => [6 * 3600, 24 * 3600, 7 * 86_400],
        }
    }
}

/// One measured reading of one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// When the reading was taken, Unix seconds.
    pub ts: i64,
    pub pct: u8,
    pub resets_at: Option<i64>,
}

/// The samples of one window, oldest first, all from the current window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowRing {
    samples: VecDeque<Sample>,
}

impl WindowRing {
    /// Fold one sample in (the module docs' rules).
    pub fn push(&mut self, kind: WindowKind, sample: Sample) {
        if let Some(last) = self.samples.back() {
            if sample.ts <= last.ts {
                return;
            }
            if sample.resets_at != last.resets_at || sample.pct < last.pct {
                self.samples.clear();
            }
        }
        // Every sample but the newest is at least `spacing` from the one
        // before it; a newest still inside that is replaced.
        let len = self.samples.len();
        if len >= 2 && self.samples[len - 1].ts - self.samples[len - 2].ts < kind.spacing() {
            self.samples[len - 1] = sample;
            return;
        }
        self.samples.push_back(sample);
        if self.samples.len() > kind.cap() {
            self.samples.pop_front();
        }
    }

    pub fn samples(&self) -> impl Iterator<Item = &Sample> {
        self.samples.iter()
    }
}

/// One slot's samples, per window. In memory only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SampleRing {
    five_hour: WindowRing,
    seven_day: WindowRing,
}

impl SampleRing {
    /// Fold in one reading of the slot: each window that measured a
    /// percentage becomes a sample at the reading's `ts`.
    pub fn record(&mut self, reading: &UsageSnapshot) {
        let ts = reading.ts as i64;
        let windows = [
            (WindowKind::FiveHour, &reading.rate_limits.five_hour),
            (WindowKind::SevenDay, &reading.rate_limits.seven_day),
        ];
        for (kind, window) in windows {
            let RateWindow { used_percentage: Some(pct), resets_at, .. } = *window else {
                continue;
            };
            self.ring_mut(kind).push(kind, Sample { ts, pct, resets_at });
        }
    }

    pub fn ring(&self, kind: WindowKind) -> &WindowRing {
        match kind {
            WindowKind::FiveHour => &self.five_hour,
            WindowKind::SevenDay => &self.seven_day,
        }
    }

    fn ring_mut(&mut self, kind: WindowKind) -> &mut WindowRing {
        match kind {
            WindowKind::FiveHour => &mut self.five_hour,
            WindowKind::SevenDay => &mut self.seven_day,
        }
    }
}

/// `slot`'s projection rows at `now`: the 5h and 7d windows to 100%, then,
/// when the slot keeps a reserve, the 7d window to `100 − reserve_pct`. Pure.
pub fn project(slot: &str, ring: &SampleRing, reserve_pct: u8, now: i64) -> Vec<PoolProjection> {
    let mut rows = vec![
        project_window(slot, WindowKind::FiveHour.label(), ring.ring(WindowKind::FiveHour), WindowKind::FiveHour, 100, now),
        project_window(slot, WindowKind::SevenDay.label(), ring.ring(WindowKind::SevenDay), WindowKind::SevenDay, 100, now),
    ];
    if reserve_pct > 0 {
        let target = 100u8.saturating_sub(reserve_pct);
        rows.push(project_window(slot, "reserve", ring.ring(WindowKind::SevenDay), WindowKind::SevenDay, target, now));
    }
    rows
}

/// One row: when `ring`'s window reaches `target_pct`.
fn project_window(
    slot: &str,
    window: &str,
    ring: &WindowRing,
    kind: WindowKind,
    target_pct: u8,
    now: i64,
) -> PoolProjection {
    let mut row = PoolProjection {
        slot: slot.to_string(),
        window: window.to_string(),
        target_pct,
        cap_at_earliest: None,
        cap_at_latest: None,
        resets_at: None,
        resets_first: false,
    };
    let Some(newest) = ring.samples.back().copied() else {
        return row;
    };
    if newest.resets_at.is_some_and(|at| at <= now) {
        return row;
    }
    row.resets_at = newest.resets_at;
    // Per span: `None` with one sample in it (no burn to read), else the cap
    // time, `None` inside when the span burned nothing (never).
    let caps: Vec<Option<i64>> = kind
        .spans()
        .iter()
        .filter_map(|span| {
            let first = ring.samples.iter().find(|s| s.ts >= newest.ts - span)?;
            (first.ts < newest.ts).then(|| cap_at(first, &newest, target_pct))
        })
        .collect();
    if caps.is_empty() {
        return row;
    }
    let before_reset = |at: &i64| newest.resets_at.is_none_or(|reset| *at < reset);
    let earliest = caps.iter().flatten().min().copied();
    let latest = if caps.iter().any(Option::is_none) { None } else { caps.iter().flatten().max().copied() };
    row.cap_at_earliest = earliest.filter(before_reset);
    row.cap_at_latest = latest.filter(before_reset).filter(|_| row.cap_at_earliest.is_some());
    row.resets_first = row.cap_at_earliest.is_none();
    row
}

/// When the burn from `first` to `newest` carries `newest` to `target_pct`:
/// `newest.ts` when already there, `None` when it burned nothing. Integer
/// math, rounded up.
fn cap_at(first: &Sample, newest: &Sample, target_pct: u8) -> Option<i64> {
    let remaining = i64::from(target_pct) - i64::from(newest.pct);
    if remaining <= 0 {
        return Some(newest.ts);
    }
    let burned = i64::from(newest.pct) - i64::from(first.pct);
    if burned <= 0 {
        return None;
    }
    let elapsed = newest.ts - first.ts;
    Some(newest.ts + (remaining * elapsed + burned - 1) / burned)
}

/// Every pooled slot's [`SampleRing`], keyed by slot.
#[derive(Debug, Clone, Default)]
pub struct Projections {
    rings: BTreeMap<String, SampleRing>,
}

impl Projections {
    /// Fold this tick's readings into each slot's ring and project it.
    /// `slots` is every pooled slot with its reserve; a ring whose slot left
    /// every pool is dropped, so the map stays as small as the pools.
    pub fn tick<'a>(
        &mut self,
        slots: impl IntoIterator<Item = (&'a str, u8)>,
        mut readings: impl FnMut(&str) -> Vec<UsageSnapshot>,
        now: i64,
    ) -> Vec<PoolProjection> {
        let slots: Vec<(&str, u8)> = slots.into_iter().collect();
        self.rings.retain(|slot, _| slots.iter().any(|(s, _)| s == slot));
        let mut rows = Vec::new();
        for (slot, reserve_pct) in slots {
            let ring = self.rings.entry(slot.to_string()).or_default();
            for reading in readings(slot) {
                ring.record(&reading);
            }
            rows.extend(project(slot, ring, reserve_pct, now));
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::usage::RateLimits;

    const RESET: i64 = 1_000_000;

    fn week(ts: i64, pct: u8) -> UsageSnapshot {
        week_resetting(ts, pct, RESET)
    }

    fn week_resetting(ts: i64, pct: u8, resets_at: i64) -> UsageSnapshot {
        UsageSnapshot {
            rate_limits: RateLimits {
                five_hour: RateWindow::default(),
                seven_day: RateWindow { used_percentage: Some(pct), resets_at: Some(resets_at), status: None },
            },
            ts: ts as f64,
            ..UsageSnapshot::default()
        }
    }

    fn ring_of(readings: &[UsageSnapshot]) -> SampleRing {
        let mut ring = SampleRing::default();
        for r in readings {
            ring.record(r);
        }
        ring
    }

    fn row<'a>(rows: &'a [PoolProjection], window: &str) -> &'a PoolProjection {
        rows.iter().find(|r| r.window == window).unwrap()
    }

    const H: i64 = 3600;

    #[test]
    fn a_steady_burn_projects_one_time_from_every_span() {
        // 1% an hour, sampled hourly for a day: every span reads the same burn.
        let readings: Vec<_> = (0..=24).map(|h| week(h * H, 40 + h as u8)).collect();
        let rows = project("slot1", &ring_of(&readings), 20, 24 * H);
        let seven = row(&rows, "7d");
        // 64% at hour 24; 36 more hours to 100.
        assert_eq!((seven.cap_at_earliest, seven.cap_at_latest), (Some(60 * H), Some(60 * H)));
        assert_eq!((seven.target_pct, seven.resets_at, seven.resets_first), (100, Some(RESET), false));
        let reserve = row(&rows, "reserve");
        assert_eq!((reserve.target_pct, reserve.cap_at_earliest), (80, Some(40 * H)));
        // No 5h percentage was ever measured: unknown, not "resets first".
        let five = row(&rows, "5h");
        assert_eq!((five.cap_at_earliest, five.resets_at, five.resets_first), (None, None, false));
    }

    #[test]
    fn a_burst_widens_the_range() {
        // 1%/h for a day, then 6% in the last six hours (the short span's burn).
        let mut readings: Vec<_> = (0..=18).map(|h| week(h * H, 40 + h as u8)).collect();
        readings.extend((19..=24).map(|h| week(h * H, 58 + (h as u8 - 18) * 6)));
        let rows = project("slot1", &ring_of(&readings), 0, 24 * H);
        let seven = row(&rows, "7d");
        // 94% at hour 24. 6h span: 36%/6h → 1h. 24h span: 54%/24h → 2.67h.
        assert_eq!(seven.cap_at_earliest, Some(25 * H));
        assert_eq!(seven.cap_at_latest, Some(24 * H + (6 * 24 * H + 53) / 54));
        assert!(seven.cap_at_earliest < seven.cap_at_latest);
        // A slot keeping no reserve has no reserve row.
        assert!(rows.iter().all(|r| r.window != "reserve"));
    }

    #[test]
    fn a_reset_mid_series_starts_the_window_over() {
        let mut readings: Vec<_> = (0..=10).map(|h| week(h * H, 80 + h as u8)).collect();
        // The window resets at hour 11: a new `resets_at`, and a low percentage.
        readings.push(week_resetting(11 * H, 2, RESET + 7 * 86_400));
        let ring = ring_of(&readings);
        assert_eq!(ring.ring(WindowKind::SevenDay).samples().count(), 1);
        // One sample in the new window: unknown, whatever the old one burned.
        let seven = row(&project("slot1", &ring, 0, 11 * H), "7d").clone();
        assert_eq!((seven.cap_at_earliest, seven.resets_first), (None, false));
        assert_eq!(seven.resets_at, Some(RESET + 7 * 86_400));
        // A lower percentage under the same `resets_at` is a reset too.
        let mut ring = ring_of(&[week(0, 50), week(H, 51)]);
        ring.record(&week(2 * H, 3));
        assert_eq!(ring.ring(WindowKind::SevenDay).samples().count(), 1);
    }

    #[test]
    fn an_expired_reading_is_unknown() {
        let ring = ring_of(&[week(0, 10), week(H, 20)]);
        assert!(row(&project("slot1", &ring, 0, RESET - 1), "7d").cap_at_earliest.is_some());
        // Once `resets_at` passes, those samples describe a window that is gone.
        let seven = row(&project("slot1", &ring, 0, RESET), "7d").clone();
        assert_eq!((seven.cap_at_earliest, seven.resets_at, seven.resets_first), (None, None, false));
    }

    #[test]
    fn the_reset_comes_first_when_no_burn_reaches_the_cap() {
        // 1% in 6h with the reset two days off: no cap before the reset.
        let ring = ring_of(&[week(RESET - 50 * H, 10), week(RESET - 44 * H, 11)]);
        let seven = row(&project("slot1", &ring, 0, RESET - 44 * H), "7d").clone();
        assert_eq!((seven.cap_at_earliest, seven.cap_at_latest, seven.resets_first), (None, None, true));
        // No burn at all is "resets first" as well, never a cap.
        let flat = ring_of(&[week(0, 10), week(H, 10)]);
        assert!(row(&project("slot1", &flat, 0, H), "7d").resets_first);
    }

    #[test]
    fn the_slowest_burn_may_miss_the_reset_while_the_fastest_does_not() {
        // Flat for two days, then 30% in the last 6h: the 6h span caps in 2h,
        // the 7d span's average (16h) not before the reset 10h off.
        let now = RESET - 10 * H;
        let mut readings = vec![week(now - 48 * H, 60), week(now - 6 * H, 60)];
        readings.push(week(now, 90));
        let seven = row(&project("slot1", &ring_of(&readings), 0, now), "7d").clone();
        assert_eq!(seven.cap_at_earliest, Some(now + 2 * H));
        assert_eq!((seven.cap_at_latest, seven.resets_first), (None, false));
    }

    #[test]
    fn one_sample_or_none_is_unknown_and_a_window_at_its_target_caps_now() {
        assert!(row(&project("s", &SampleRing::default(), 0, 0), "7d").cap_at_earliest.is_none());
        let one = ring_of(&[week(0, 10)]);
        assert!(!row(&project("s", &one, 0, 0), "7d").resets_first);
        // 85% with a 20% reserve: the threshold is already behind it.
        let at = ring_of(&[week(0, 84), week(H, 85)]);
        assert_eq!(row(&project("s", &at, 20, H), "reserve").cap_at_earliest, Some(H));
    }

    #[test]
    fn the_ring_keeps_reading_time_and_stays_bounded() {
        let mut ring = WindowRing::default();
        let kind = WindowKind::FiveHour;
        let s = |ts, pct| Sample { ts, pct, resets_at: Some(RESET) };
        ring.push(kind, s(0, 1));
        ring.push(kind, s(0, 2)); // the same reading, re-read: ignored
        ring.push(kind, s(120, 2));
        ring.push(kind, s(150, 3));
        ring.push(kind, s(170, 4)); // 150 sat inside the spacing: replaced
        let kept: Vec<_> = ring.samples().map(|s| (s.ts, s.pct)).collect();
        assert_eq!(kept, [(0, 1), (120, 2), (170, 4)]);
        for i in 0..1000 {
            ring.push(kind, s(200 + i * 60, 3));
        }
        assert_eq!(ring.samples().count(), kind.cap());
    }

    #[test]
    fn a_headless_reading_adds_no_sample() {
        let mut headless = week(H, 0);
        headless.rate_limits.seven_day.used_percentage = None;
        let ring = ring_of(&[week(0, 10), headless]);
        assert_eq!(ring.ring(WindowKind::SevenDay).samples().count(), 1);
    }

    #[test]
    fn projections_follow_the_pools() {
        let mut p = Projections::default();
        let rows = p.tick([("slot1", 0), ("slot2", 10)], |_| vec![week(0, 5)], 0);
        assert_eq!(rows.len(), 5, "two windows each, plus slot2's reserve");
        p.tick([("slot2", 10)], |_| vec![week(H, 6)], H);
        assert_eq!(p.rings.keys().collect::<Vec<_>>(), ["slot2"]);
        let rows = p.tick([("slot2", 10)], |_| Vec::new(), H);
        assert_eq!(row(&rows, "7d").cap_at_earliest, Some(H + 94 * H));
    }
}
