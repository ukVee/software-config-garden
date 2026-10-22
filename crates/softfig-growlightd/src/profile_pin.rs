//! Per-member claude-login profile pins + the naive round-robin picker
//! (`claude-login-switcher` slice 003).
//!
//! A pin is the record that at *this* session boundary, growlightd routed
//! member `<id>`'s overlay credentials at profile slot `<name>`. One record
//! lives at
//!
//! ```text
//! $XDG_CONFIG_HOME/softfig/growlight/agents/<id>/profile.pin.json
//! ```
//!
//! and a parallel append-only JSON-Lines log at
//!
//! ```text
//! $XDG_CONFIG_HOME/softfig/growlight/agents/<id>/profile.pin.history.jsonl
//! ```
//!
//! captures every pick so the picker's "least recently used" is a decision
//! on observable past evidence, not on today's wall clock. Both are small
//! (~1 KB per pin), and the history is bounded by convention: the picker only
//! reads back enough to decide ordering (see [`pick_round_robin`]).
//!
//! Scope and non-scope:
//!
//! - The **picker** is pure: it takes a pool and a history slice and returns
//!   the slot to use. [`pick_round_robin`] is unit-proven here, so slice-003
//!   finish-check "round-robin via pin history, not timing-sensitive
//!   observation" is a plain assertion.
//! - The **writer** is atomic (`tempfile sibling + rename`) so a crash in
//!   spawn never leaves half a pin: either the previous generation's pin is
//!   intact or the new one is fully written (slice-003 finish-check 3).
//! - The **reader** is used both for the per-member credential retarget (in
//!   claude_backend's spawn seam) and for the status surfaces (growlightd
//!   `status` + `softfig claude-login status`).
//! - **Budget awareness** is slice 004: [`pick_with_budget`] wraps the pure
//!   round-robin picker with a per-slot headroom sort, returning
//!   [`PickResult::Chose`] / [`PickResult::Warn`] / [`PickResult::Stall`]
//!   depending on where the pool sits versus [`HEADROOM_WARN_PCT`] and
//!   [`HEADROOM_STALL_PCT`]. The round-robin stays the LRU tiebreak on an
//!   equal-headroom tier, so a healthy pool still rotates.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::profile_budget::Headroom;

/// One pick's record — written when a member starts a session on a claude
/// profile pool. Small by design (~a dozen bytes of overhead); the fields are
/// what the operator and the picker both ask of a historical pick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePin {
    /// The chosen slot name (shape-validated at parse via
    /// [`softfig_ipc::validate_slot_name`]).
    pub profile: String,
    /// Unix seconds at pick time. Monotonic within a boot; across boots it is
    /// the host clock, which is fine — the picker uses order, not deltas.
    pub picked_at: i64,
    /// A session identifier the fleet writer stamps in. The payload is
    /// opaque to this module; today it is the per-spawn scope base name
    /// (`growlight-agent-<id>-<gen>`), which is unique per generation.
    pub session_id: String,
    /// The slice / baton item this pick was made for, when known. `None` is
    /// legal: a crash-restart may not know its baton's active slice.
    pub slice: Option<String>,
}

impl ProfilePin {
    /// A convenience constructor that stamps `picked_at` to "now".
    pub fn now(profile: impl Into<String>, session_id: impl Into<String>, slice: Option<String>) -> Self {
        Self {
            profile: profile.into(),
            picked_at: now_unix(),
            session_id: session_id.into(),
            slice,
        }
    }
}

/// Where a member's pin files live, derived purely from the fleet's
/// `agents_dir` and the member id.
#[derive(Debug, Clone)]
pub struct PinPaths {
    /// `profile.pin.json` — the most-recent pin, atomically rewritten.
    pub pin: PathBuf,
    /// `profile.pin.history.jsonl` — append-only JSON-Lines, one row per pick.
    pub history: PathBuf,
}

/// Derive the pin paths for `member_id` under `agents_dir`. Pure, no I/O.
pub fn pin_paths(agents_dir: &Path, member_id: &str) -> PinPaths {
    let dir = agents_dir.join(member_id);
    PinPaths {
        pin: dir.join("profile.pin.json"),
        history: dir.join("profile.pin.history.jsonl"),
    }
}

/// Read a member's current pin, or `None` when none has been written yet
/// (fleet never ran this member on a pool, or the dir was wiped). A corrupt
/// pin reads as `None`: the next spawn re-pins, which is both correct and
/// safer than crashing the spawn seam over a malformed historical file.
pub fn read_pin(paths: &PinPaths) -> Option<ProfilePin> {
    let bytes = fs::read(&paths.pin).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Read a member's pin history, oldest first; empty when the member has
/// never been pinned. Lines that fail to parse are skipped (same tolerance
/// as [`read_pin`]); a corrupt tail would otherwise poison the picker on
/// every tick.
pub fn read_pin_history(paths: &PinPaths) -> Vec<ProfilePin> {
    let Ok(raw) = fs::read_to_string(&paths.history) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                None
            } else {
                serde_json::from_str::<ProfilePin>(line).ok()
            }
        })
        .collect()
}

/// Write a member's new pin **atomically** (tempfile-sibling + `rename`) so a
/// crash mid-spawn never leaves half a pin, and append it to the history —
/// also atomic for the single row (`O_APPEND` is per-write atomic on
/// Linux). The pin dir is created with 0700 if it does not already exist.
///
/// The write is deliberately a two-step append-then-swap: history grows
/// first, so if the atomic rename fails the picker still sees the fresh
/// pick on the next tick (worst case: the previous `profile.pin.json` is
/// stale by one pick, which the next session boundary corrects).
pub fn write_pin(paths: &PinPaths, pin: &ProfilePin) -> std::io::Result<()> {
    if let Some(parent) = paths.pin.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
        // Best-effort tighten; a 0755 default is a surprise for a profile
        // cache that may name slot ids, and this dir is per-user already.
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    // 1) Append the row to the history file first (small, append-safe).
    let mut history = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&paths.history)?;
    let mut line = serde_json::to_string(pin).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serialize pin: {e}"))
    })?;
    line.push('\n');
    history.write_all(line.as_bytes())?;
    history.sync_all().ok(); // best effort; the pin itself is the primary artefact.

    // 2) Atomic swap of the current-pin file (tempfile sibling + rename).
    let dir = paths
        .pin
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let tmp = dir.join(format!(".profile.pin.{}.tmp", std::process::id()));
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        let bytes = serde_json::to_vec_pretty(pin).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serialize pin: {e}"))
        })?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &paths.pin)?;
    Ok(())
}

/// Round-robin pick over `pool`, given a member's `history` (as returned by
/// [`read_pin_history`]). Returns the slot least recently used across the
/// pool; ties (a slot never picked, or two slots last-picked at the same
/// timestamp) resolve to **pool order** so the first pick with an empty
/// history is `pool[0]`.
///
/// Pure, no I/O: the caller supplies the history slice. `pool` must be
/// non-empty — a `profile_pool = []` is refused at parse (see
/// `fleet::validate_profile_pool_shape`), so a `None` return here would be
/// a dead branch; expressed with `Option` anyway so the caller can keep its
/// error path proof-sound.
pub fn pick_round_robin<'a>(pool: &'a [String], history: &[ProfilePin]) -> Option<&'a str> {
    if pool.is_empty() {
        return None;
    }
    // Walk the pool and look at each slot's most-recent historical pick.
    // "Never picked" is treated as "last picked at i64::MIN", so an
    // un-picked slot always wins ties. Pool order is the tie-break: we scan
    // the pool once, picking the leftmost minimum, so index 0 is implicitly
    // preferred over equally-stale index 2.
    let mut best: Option<(usize, i64)> = None;
    for (idx, slot) in pool.iter().enumerate() {
        let last = history
            .iter()
            .rev()
            .find(|p| &p.profile == slot)
            .map(|p| p.picked_at)
            .unwrap_or(i64::MIN);
        match best {
            None => best = Some((idx, last)),
            Some((_, prev)) if last < prev => best = Some((idx, last)),
            _ => {}
        }
    }
    best.map(|(idx, _)| pool[idx].as_str())
}

/// Headroom (%) below which the budget-aware picker still proceeds but emits a
/// warning (slice 004 pick rule: `warn` at `< 10%`).
pub const HEADROOM_WARN_PCT: u8 = 10;

/// Headroom (%) at or below which a slot is "effectively exhausted" and must
/// not be chosen; if the whole pool is at or below this floor, the picker
/// returns [`PickResult::Stall`] (slice 004 pick rule: stall at `< 2%` across
/// every pool slot). A slot sitting exactly on the floor is treated as
/// exhausted so a `rejected` reading maps there cleanly (headroom 0).
pub const HEADROOM_STALL_PCT: u8 = 2;

/// Result of a budget-aware pick ([`pick_with_budget`]). The caller — the
/// `ClaudeFlavor` spawn seam — maps `Chose` → unchanged spawn, `Warn` → the
/// same spawn with a journalled warning, `Stall` → a `SpawnError` that the
/// drive loop surfaces as a human-visible hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickResult {
    /// A healthy pick: `slot` has `>= HEADROOM_WARN_PCT` headroom. Spawn as
    /// usual (`headroom_pct` carried for status surfaces).
    Chose {
        /// The slot picked.
        slot: String,
        /// Current 5h headroom of the chosen slot (`0..=100`).
        headroom_pct: u8,
    },
    /// A low-headroom pick: `slot` is below [`HEADROOM_WARN_PCT`] but above
    /// the stall floor; the spawn proceeds and the caller journals a warning
    /// so the operator can see the fleet about to exhaust.
    Warn {
        /// The slot picked (the best available).
        slot: String,
        /// Current 5h headroom of the chosen slot (`0..=100`).
        headroom_pct: u8,
    },
    /// Every pool slot sits at or below [`HEADROOM_STALL_PCT`]: the member
    /// stalls until the earliest known `resets_at`, which the drive loop uses
    /// as the retry pin. `None` when no slot carried a boundary (the picker
    /// has nothing to pin, so admission falls back to its own age bound).
    Stall {
        /// Earliest 5h-window reset time across the stalled pool, unix
        /// seconds — or `None` when no slot carries one.
        until_at: Option<i64>,
    },
}

/// Budget-aware pick: prefer the slot with the highest headroom, breaking a
/// tie by [`pick_round_robin`] (LRU over the pin history). Pure over its
/// inputs — `pool`, `history`, and `headroom` (one entry per `pool` slot in
/// pool order, as [`crate::profile_budget::pool_headroom`] returns it).
///
/// Returns `None` when `pool` is empty; a `profile_pool = []` is refused at
/// parse (see `fleet::validate_profile_pool_shape`), so a production caller
/// never reaches that branch — expressed with `Option` anyway so the error
/// path stays proof-sound.
///
/// Policy:
///
/// 1. If every slot has `pct <= HEADROOM_STALL_PCT` ⇒ [`PickResult::Stall`]
///    pinned to the earliest known `resets_at`.
/// 2. Otherwise pick from the slots at the highest `pct` tier, breaking the
///    tie by LRU. A pool where both slots are at `100%` (unused or stale)
///    then still rotates round-robin, which matches slice 003's rule.
/// 3. If the winner's `pct` is below [`HEADROOM_WARN_PCT`] ⇒
///    [`PickResult::Warn`]; otherwise ⇒ [`PickResult::Chose`].
pub fn pick_with_budget(
    pool: &[String],
    history: &[ProfilePin],
    headroom: &[Headroom],
) -> Option<PickResult> {
    if pool.is_empty() {
        return None;
    }
    debug_assert_eq!(
        pool.len(),
        headroom.len(),
        "pick_with_budget: one Headroom per pool slot",
    );
    // Stall gate first — all effectively exhausted (`pct <=` the floor).
    if headroom
        .iter()
        .all(|h| h.pct <= HEADROOM_STALL_PCT)
    {
        let until_at = headroom.iter().filter_map(|h| h.resets_at).min();
        return Some(PickResult::Stall { until_at });
    }
    // Highest headroom among the slots that are not themselves stalled;
    // ignore stalled slots for the max so a single-rejected slot doesn't win
    // on its (lower) `resets_at` tie.
    let max_pct = headroom
        .iter()
        .filter(|h| h.pct > HEADROOM_STALL_PCT)
        .map(|h| h.pct)
        .max()
        .unwrap_or(100);
    // Narrow the pool + history to the top tier, then LRU over that subset.
    let tier: Vec<String> = pool
        .iter()
        .zip(headroom.iter())
        .filter(|(_, h)| h.pct == max_pct)
        .map(|(name, _)| name.clone())
        .collect();
    // `tier` is non-empty: `max_pct` came from a slot above the stall floor,
    // which exists because the stall gate above would have returned Stall.
    let chosen = pick_round_robin(&tier, history)
        .map(str::to_string)
        .unwrap_or_else(|| tier[0].clone());
    if max_pct < HEADROOM_WARN_PCT {
        Some(PickResult::Warn {
            slot: chosen,
            headroom_pct: max_pct,
        })
    } else {
        Some(PickResult::Chose {
            slot: chosen,
            headroom_pct: max_pct,
        })
    }
}

/// Unix seconds since epoch, saturating to `0` if the host clock predates it
/// (which would be a system misconfig the picker should not panic over).
/// `pub(crate)` so the spawn seam's budget-aware pick can use the same clock
/// here reads the pin history from.
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(profile: &str, picked_at: i64) -> ProfilePin {
        ProfilePin {
            profile: profile.into(),
            picked_at,
            session_id: format!("s-{picked_at}"),
            slice: None,
        }
    }

    #[test]
    fn empty_history_pool_zero_wins_first() {
        // First pick with no history ⇒ pool[0]: pool order breaks the tie
        // (every slot's "last pick" is -∞).
        let pool = vec!["slot1".to_string(), "slot2".into()];
        assert_eq!(pick_round_robin(&pool, &[]), Some("slot1"));
    }

    #[test]
    fn one_pick_switches_to_the_sibling() {
        // One history entry on slot1 ⇒ the next pick must be slot2.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot1", 100)];
        assert_eq!(pick_round_robin(&pool, &hist), Some("slot2"));
    }

    #[test]
    fn three_pool_entries_round_robin_in_order() {
        // Three sequential picks must step through [slot1, slot2, slot3] —
        // the "rotation" finish-check.
        let pool = vec!["slot1".to_string(), "slot2".into(), "slot3".into()];
        let mut hist: Vec<ProfilePin> = Vec::new();

        let first = pick_round_robin(&pool, &hist).unwrap();
        assert_eq!(first, "slot1");
        hist.push(pin(first, 100));

        let second = pick_round_robin(&pool, &hist).unwrap();
        assert_eq!(second, "slot2");
        hist.push(pin(second, 200));

        let third = pick_round_robin(&pool, &hist).unwrap();
        assert_eq!(third, "slot3");
        hist.push(pin(third, 300));

        // Fourth returns to slot1, closing the cycle.
        let fourth = pick_round_robin(&pool, &hist).unwrap();
        assert_eq!(fourth, "slot1");
    }

    #[test]
    fn stale_slot_wins_over_recent_one() {
        // Two slots, both picked, slot1 older ⇒ slot1 wins the LRU race.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot1", 10), pin("slot2", 500)];
        assert_eq!(pick_round_robin(&pool, &hist), Some("slot1"));
    }

    #[test]
    fn history_outside_the_pool_is_ignored() {
        // Pool shrunk since picks were recorded — the extra history entries
        // vanish from the decision: an orphaned "slot3" that is no longer in
        // the pool must not pin the next pick to its sibling forever.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot3", 999), pin("slot1", 10)];
        assert_eq!(
            pick_round_robin(&pool, &hist),
            Some("slot2"),
            "slot2 is older here (never picked), so it wins",
        );
    }

    #[test]
    fn write_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = pin_paths(dir.path(), "a");
        assert_eq!(read_pin(&paths), None);

        let p = ProfilePin {
            profile: "slot1".into(),
            picked_at: 123,
            session_id: "s1".into(),
            slice: Some("003".into()),
        };
        write_pin(&paths, &p).unwrap();
        assert_eq!(read_pin(&paths), Some(p.clone()));

        // The parent dir was created 0700.
        let md = std::fs::symlink_metadata(dir.path().join("a")).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o700);

        // History carries one row — the pick we just wrote.
        let hist = read_pin_history(&paths);
        assert_eq!(hist, vec![p]);
    }

    #[test]
    fn second_write_appends_history_and_swaps_current_pin() {
        // The pin flips to the latest, the history keeps both rows in order.
        let dir = tempfile::tempdir().unwrap();
        let paths = pin_paths(dir.path(), "a");
        write_pin(&paths, &pin("slot1", 100)).unwrap();
        write_pin(&paths, &pin("slot2", 200)).unwrap();

        let latest = read_pin(&paths).unwrap();
        assert_eq!(latest.profile, "slot2");

        let hist = read_pin_history(&paths);
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0].profile, "slot1");
        assert_eq!(hist[1].profile, "slot2");
    }

    #[test]
    fn two_consecutive_rotations_pick_alternating_slots() {
        // The slice's "two consecutive single-member slices" finish-check:
        // simulate it against the real reader/writer so the picker + the
        // storage agree, not timing-sensitive.
        let dir = tempfile::tempdir().unwrap();
        let paths = pin_paths(dir.path(), "a");
        let pool = vec!["slot1".to_string(), "slot2".into()];

        let hist = read_pin_history(&paths);
        let first = pick_round_robin(&pool, &hist).unwrap().to_string();
        write_pin(&paths, &pin(&first, 100)).unwrap();

        let hist = read_pin_history(&paths);
        let second = pick_round_robin(&pool, &hist).unwrap().to_string();
        write_pin(&paths, &pin(&second, 200)).unwrap();

        assert_eq!(first, "slot1");
        assert_eq!(second, "slot2");
    }

    // --- pick_with_budget (slice 004) ----------------------------------------

    fn hr(pct: u8, resets_at: Option<i64>) -> Headroom {
        Headroom { pct, resets_at }
    }

    #[test]
    fn pick_with_budget_healthy_pool_rotates_lru_at_full_headroom() {
        // Both slots at 100% (unused / stale / reset) ⇒ LRU wins the tie.
        // Mirrors slice 003's rotation rule when the budget signal is quiet.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let headroom = vec![hr(100, None), hr(100, None)];
        assert_eq!(
            pick_with_budget(&pool, &[], &headroom),
            Some(PickResult::Chose {
                slot: "slot1".into(),
                headroom_pct: 100,
            }),
        );
        // After one pick on slot1, the next lands on slot2.
        let hist = vec![pin("slot1", 10)];
        assert_eq!(
            pick_with_budget(&pool, &hist, &headroom),
            Some(PickResult::Chose {
                slot: "slot2".into(),
                headroom_pct: 100,
            }),
        );
    }

    #[test]
    fn pick_with_budget_higher_headroom_beats_lru() {
        // slot1 is older (LRU-preferred) but has 20% headroom; slot2 is
        // fresher but 100%. Highest-headroom wins — exactly the slice 004
        // policy "pick the profile with highest headroom".
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot2", 50), pin("slot1", 10)]; // slot1 oldest
        let headroom = vec![hr(20, Some(2_000)), hr(100, Some(9_000))];
        assert_eq!(
            pick_with_budget(&pool, &hist, &headroom),
            Some(PickResult::Chose {
                slot: "slot2".into(),
                headroom_pct: 100,
            }),
        );
    }

    #[test]
    fn pick_with_budget_warn_branch_below_ten_percent() {
        // Every slot below 10% ⇒ pick highest, still proceed, but it's a
        // Warn — slice spec: "If chosen headroom < 10%, emit `warn` to the
        // baton-log but still proceed."
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let headroom = vec![hr(5, Some(2_000)), hr(7, Some(9_000))];
        assert_eq!(
            pick_with_budget(&pool, &[], &headroom),
            Some(PickResult::Warn {
                slot: "slot2".into(),
                headroom_pct: 7,
            }),
        );
    }

    #[test]
    fn pick_with_budget_stall_branch_when_all_exhausted() {
        // Both slots at 0% headroom ⇒ Stall at the earliest reset_at
        // (slice spec: "schedule a retry at the earliest `resets_at`").
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let headroom = vec![hr(0, Some(2_000)), hr(0, Some(9_000))];
        assert_eq!(
            pick_with_budget(&pool, &[], &headroom),
            Some(PickResult::Stall {
                until_at: Some(2_000),
            }),
        );
    }

    #[test]
    fn pick_with_budget_stall_floor_is_inclusive() {
        // The stall floor is HEADROOM_STALL_PCT; a slot sitting exactly there
        // is treated as exhausted, so a pool at 2%/2% stalls.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let headroom = vec![
            hr(HEADROOM_STALL_PCT, Some(2_000)),
            hr(HEADROOM_STALL_PCT, Some(9_000)),
        ];
        assert!(matches!(
            pick_with_budget(&pool, &[], &headroom),
            Some(PickResult::Stall { .. }),
        ));
    }

    #[test]
    fn pick_with_budget_skips_an_exhausted_sibling() {
        // slot1 is rejected (0%), slot2 is healthy (100%) ⇒ pick slot2 even
        // though slot1 is LRU-preferred. The fallback path when one 5h
        // window exhausts and the other is still live.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot2", 50)]; // slot1 is LRU
        let headroom = vec![hr(0, Some(2_000)), hr(100, Some(9_000))];
        assert_eq!(
            pick_with_budget(&pool, &hist, &headroom),
            Some(PickResult::Chose {
                slot: "slot2".into(),
                headroom_pct: 100,
            }),
        );
    }

    #[test]
    fn pick_with_budget_stall_with_no_known_resets() {
        // Pool fully exhausted but no boundary known ⇒ Stall { None }.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let headroom = vec![hr(0, None), hr(0, None)];
        assert_eq!(
            pick_with_budget(&pool, &[], &headroom),
            Some(PickResult::Stall { until_at: None }),
        );
    }

    #[test]
    fn pick_with_budget_empty_pool_is_none() {
        assert_eq!(pick_with_budget(&[], &[], &[]), None);
    }

    #[test]
    fn corrupt_pin_file_reads_as_none() {
        // A corrupt pin never crashes the reader — the next spawn re-pins.
        let dir = tempfile::tempdir().unwrap();
        let paths = pin_paths(dir.path(), "a");
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::write(&paths.pin, b"not json").unwrap();
        assert_eq!(read_pin(&paths), None);
    }
}
