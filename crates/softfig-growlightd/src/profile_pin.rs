//! Per-member claude-login profile pins + the pool picker
//! (`claude-login-switcher` slices 003, 004, 007).
//!
//! A pin is the record that at *this* session boundary, growlightd started
//! member `<id>`'s session on profile slot `<name>` (its `CLAUDE_CONFIG_DIR`).
//! One record lives at
//!
//! ```text
//! $XDG_CONFIG_HOME/softfig/growlight/agents/<id>/profile.pin.json
//! ```
//!
//! and a parallel JSON-Lines log at
//!
//! ```text
//! $XDG_CONFIG_HOME/softfig/growlight/agents/<id>/profile.pin.history.jsonl
//! ```
//!
//! captures every pick so the picker's "least recently used" is a decision
//! on observable past evidence. The log keeps the last [`HISTORY_CAP`] picks
//! per member, oldest dropped, and its line order is the order of the picks.
//!
//! Scope and non-scope:
//!
//! - The **picker** is pure: it takes a pool, the fleet-wide recency
//!   ([`last_used`] over every pooled member's history), the slots live
//!   members are on, and per-slot headroom, and returns the slot to use.
//! - The **writer** is atomic (`tempfile sibling + rename`, both files) so a
//!   crash never leaves half a pin. growlightd calls it only after the
//!   session's `spawn()` succeeded, so a failed launch records nothing.
//! - The **readers** drop any row whose slot name does not shape-check, so a
//!   hand-edited or corrupt file can never name a path outside the store.
//!   They back the status surfaces (growlightd `status` + `softfig
//!   claude-login status`) and the picker.
//! - **Budget awareness** is slice 004: [`pick_with_budget`] sorts by per-slot
//!   headroom, returning [`PickResult::Chose`] / [`PickResult::Warn`] /
//!   [`PickResult::Stall`] depending on where the pool sits versus
//!   [`HEADROOM_WARN_PCT`] and [`HEADROOM_STALL_PCT`]. LRU stays the tiebreak
//!   on an equal-headroom tier, so a healthy pool still rotates.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use softfig_ipc::validate_slot_name;

use crate::profile_budget::Headroom;

/// The most picks a member's history keeps; the oldest row goes first.
pub const HISTORY_CAP: usize = 64;

/// One pick's record — written when a member starts a session on a claude
/// profile pool. Small by design (~a dozen bytes of overhead); the fields are
/// what the operator and the picker both ask of a historical pick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePin {
    /// The chosen slot name. The derived `Deserialize` accepts any string;
    /// [`read_pin`] and [`read_pin_history`] drop a row whose name fails
    /// [`softfig_ipc::validate_slot_name`].
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
    /// `profile.pin.history.jsonl` — JSON-Lines, one row per pick, oldest
    /// first, at most [`HISTORY_CAP`] rows.
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

/// Parse one pin, refusing a slot name that does not shape-check.
fn parse_pin(bytes: &[u8]) -> Option<ProfilePin> {
    let pin: ProfilePin = serde_json::from_slice(bytes).ok()?;
    validate_slot_name(&pin.profile).ok()?;
    Some(pin)
}

/// Read a member's current pin, or `None` when none has been written yet
/// (fleet never ran this member on a pool, or the dir was wiped). A corrupt
/// pin, or one naming an invalid slot, reads as `None`: the next spawn
/// re-pins, which is both correct and safer than trusting a malformed file.
pub fn read_pin(paths: &PinPaths) -> Option<ProfilePin> {
    parse_pin(&fs::read(&paths.pin).ok()?)
}

/// Read a member's pin history in line order (oldest first); empty when the
/// member has never been pinned. Lines that fail to parse or name an invalid
/// slot are skipped (same tolerance as [`read_pin`]); a corrupt tail would
/// otherwise poison the picker on every tick.
pub fn read_pin_history(paths: &PinPaths) -> Vec<ProfilePin> {
    let Ok(raw) = fs::read_to_string(&paths.history) else {
        return Vec::new();
    };
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| parse_pin(line.as_bytes()))
        .collect()
}

/// Write `bytes` to `path` atomically: a `0600` temp sibling, fsynced, then
/// renamed over it, then the parent dir is fsynced so the rename itself
/// survives a power cut (this device has thermal power cuts — review 047
/// nit). The temp is removed if any step fails.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("pin");
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        fs::File::open(dir).and_then(|d| d.sync_all())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Record a member's new pin: the history gains it as its last line (keeping
/// the newest [`HISTORY_CAP`] rows), then `profile.pin.json` is swapped to
/// it. Both files are rewritten atomically, so a crash leaves either the old
/// or the new version of each, never half a row. The pin dir is created with
/// 0700 if it does not already exist.
///
/// History goes first: if the pin swap then fails, the picker still sees the
/// fresh pick on the next tick (worst case: `profile.pin.json` is stale by one
/// pick, which the next session boundary corrects).
pub fn write_pin(paths: &PinPaths, pin: &ProfilePin) -> std::io::Result<()> {
    if let Some(parent) = paths.pin.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
        // Best-effort tighten; a 0755 default is a surprise for a profile
        // cache that may name slot ids, and this dir is per-user already.
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let serialize = |e: serde_json::Error| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serialize pin: {e}"))
    };

    let mut history = read_pin_history(paths);
    history.push(pin.clone());
    let keep_from = history.len().saturating_sub(HISTORY_CAP);
    let mut rows = String::new();
    for row in &history[keep_from..] {
        rows.push_str(&serde_json::to_string(row).map_err(serialize)?);
        rows.push('\n');
    }
    write_atomic(&paths.history, rows.as_bytes())?;
    write_atomic(&paths.pin, &serde_json::to_vec_pretty(pin).map_err(serialize)?)
}

/// When each slot was last picked by any member, from every pooled member's
/// history (review 047 S3: LRU is fleet-wide, not per member). The value is a
/// sort key, `(time, line)`: within one member's history a later line is
/// always more recent, whatever its `picked_at` says (the clock may have
/// stepped back, or two picks share a second), and `picked_at` only orders
/// picks of different members. A slot no one has picked is absent.
pub fn last_used(histories: &[Vec<ProfilePin>]) -> BTreeMap<String, (i64, usize)> {
    let mut last: BTreeMap<String, (i64, usize)> = BTreeMap::new();
    for history in histories {
        let mut floor = i64::MIN;
        for (line, pin) in history.iter().enumerate() {
            floor = floor.max(pin.picked_at);
            let key = (floor, line);
            let slot = last.entry(pin.profile.clone()).or_insert(key);
            *slot = (*slot).max(key);
        }
    }
    last
}

/// The least recently used slot of `pool` by `last_used`. A never-picked slot
/// beats any picked one; ties resolve to **pool order**, so the first pick
/// with no history is `pool[0]`.
///
/// Pure, no I/O. `pool` must be non-empty — a `profile_pool = []` is refused
/// at parse (see `fleet::validate_profile_pool_shape`), so a `None` return
/// here would be a dead branch; expressed with `Option` anyway so the caller
/// can keep its error path proof-sound.
pub fn pick_round_robin<'a>(
    pool: &'a [String],
    last_used: &BTreeMap<String, (i64, usize)>,
) -> Option<&'a str> {
    // `min_by_key` keeps the first of equal minimums, which is the pool-order
    // tie-break; `None` (never picked) sorts below every `Some`.
    pool.iter()
        .min_by_key(|slot| last_used.get(slot.as_str()))
        .map(String::as_str)
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
/// tie by [`pick_round_robin`] (fleet-wide LRU). Pure over its inputs —
/// `pool`, `last_used` (from [`last_used`]), `live` (the slots other members'
/// running sessions are on), and `headroom` (one entry per `pool` slot in
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
/// 2. Drop the stalled slots, then the `live` ones — unless that leaves
///    nothing, in which case a live slot is shared (review 047 S3: two
///    members on one two-slot pool run on two accounts while both have
///    headroom).
/// 3. Pick from the remaining slots at the highest `pct` tier, breaking the
///    tie by LRU. A pool where both slots are at `100%` (unused or stale)
///    then still rotates round-robin, which matches slice 003's rule.
/// 4. If the winner's `pct` is below [`HEADROOM_WARN_PCT`] ⇒
///    [`PickResult::Warn`]; otherwise ⇒ [`PickResult::Chose`].
pub fn pick_with_budget(
    pool: &[String],
    last_used: &BTreeMap<String, (i64, usize)>,
    live: &BTreeSet<String>,
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
    // The slots worth considering: not stalled (so a single-rejected slot
    // never wins on its `resets_at`), and not on a live member's session
    // unless every unstalled slot is.
    let open: Vec<(&String, &Headroom)> = pool
        .iter()
        .zip(headroom.iter())
        .filter(|(_, h)| h.pct > HEADROOM_STALL_PCT)
        .collect();
    let free: Vec<(&String, &Headroom)> = open
        .iter()
        .copied()
        .filter(|(name, _)| !live.contains(name.as_str()))
        .collect();
    let candidates = if free.is_empty() { open } else { free };
    // `candidates` is non-empty: the stall gate above returned unless some
    // slot sits above the floor.
    let max_pct = candidates.iter().map(|(_, h)| h.pct).max().unwrap_or(100);
    // Narrow to the top tier, then LRU over that subset.
    let tier: Vec<String> = candidates
        .iter()
        .filter(|(_, h)| h.pct == max_pct)
        .map(|(name, _)| (*name).clone())
        .collect();
    let chosen = pick_round_robin(&tier, last_used)
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

    /// One member's history as the picker's recency map.
    fn lu(history: &[ProfilePin]) -> BTreeMap<String, (i64, usize)> {
        last_used(&[history.to_vec()])
    }

    fn none_live() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn empty_history_pool_zero_wins_first() {
        // First pick with no history ⇒ pool[0]: pool order breaks the tie
        // (no slot has a "last pick").
        let pool = vec!["slot1".to_string(), "slot2".into()];
        assert_eq!(pick_round_robin(&pool, &lu(&[])), Some("slot1"));
    }

    #[test]
    fn one_pick_switches_to_the_sibling() {
        // One history entry on slot1 ⇒ the next pick must be slot2.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot1", 100)];
        assert_eq!(pick_round_robin(&pool, &lu(&hist)), Some("slot2"));
    }

    #[test]
    fn three_pool_entries_round_robin_in_order() {
        // Three sequential picks must step through [slot1, slot2, slot3] —
        // the "rotation" finish-check.
        let pool = vec!["slot1".to_string(), "slot2".into(), "slot3".into()];
        let mut hist: Vec<ProfilePin> = Vec::new();

        let first = pick_round_robin(&pool, &lu(&hist)).unwrap();
        assert_eq!(first, "slot1");
        hist.push(pin(first, 100));

        let second = pick_round_robin(&pool, &lu(&hist)).unwrap();
        assert_eq!(second, "slot2");
        hist.push(pin(second, 200));

        let third = pick_round_robin(&pool, &lu(&hist)).unwrap();
        assert_eq!(third, "slot3");
        hist.push(pin(third, 300));

        // Fourth returns to slot1, closing the cycle.
        let fourth = pick_round_robin(&pool, &lu(&hist)).unwrap();
        assert_eq!(fourth, "slot1");
    }

    #[test]
    fn stale_slot_wins_over_recent_one() {
        // Two slots, both picked, slot1 older ⇒ slot1 wins the LRU race.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot1", 10), pin("slot2", 500)];
        assert_eq!(pick_round_robin(&pool, &lu(&hist)), Some("slot1"));
    }

    #[test]
    fn line_order_beats_the_wall_clock_within_one_member() {
        // Review 047 nit: the clock stepped back between two picks, and two
        // picks share a second. Line order still says slot2 was used last.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        assert_eq!(
            pick_round_robin(&pool, &lu(&[pin("slot1", 500), pin("slot2", 100)])),
            Some("slot1"),
        );
        assert_eq!(
            pick_round_robin(&pool, &lu(&[pin("slot2", 100), pin("slot1", 100)])),
            Some("slot2"),
        );
    }

    #[test]
    fn recency_is_fleet_wide() {
        // Review 047 S3: `a` used slot1, `d` used slot2 later. A fresh pick by
        // either member goes to slot1, the fleet's least recently used, not
        // to whatever that member's own history lacks.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let a = vec![pin("slot1", 100)];
        let d = vec![pin("slot2", 200)];
        let fleet = last_used(&[a.clone(), d]);
        assert_eq!(pick_round_robin(&pool, &fleet), Some("slot1"));
        assert_eq!(pick_round_robin(&pool, &lu(&a)), Some("slot2"), "per-member view differs");
    }

    #[test]
    fn history_outside_the_pool_is_ignored() {
        // Pool shrunk since picks were recorded — the extra history entries
        // vanish from the decision: an orphaned "slot3" that is no longer in
        // the pool must not pin the next pick to its sibling forever.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let hist = vec![pin("slot3", 999), pin("slot1", 10)];
        assert_eq!(
            pick_round_robin(&pool, &lu(&hist)),
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

        // The parent dir was created 0700, and both files are 0600.
        let md = std::fs::symlink_metadata(dir.path().join("a")).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o700);
        for f in [&paths.pin, &paths.history] {
            let md = std::fs::symlink_metadata(f).unwrap();
            assert_eq!(md.permissions().mode() & 0o777, 0o600, "{}", f.display());
        }

        // History carries one row — the pick we just wrote — and no temp is left.
        let hist = read_pin_history(&paths);
        assert_eq!(hist, vec![p]);
        let names: Vec<_> = std::fs::read_dir(dir.path().join("a"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
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
    fn history_is_capped_and_drops_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let paths = pin_paths(dir.path(), "a");
        let total = HISTORY_CAP + 6;
        for i in 0..total {
            write_pin(&paths, &pin(if i % 2 == 0 { "slot1" } else { "slot2" }, i as i64)).unwrap();
        }
        let hist = read_pin_history(&paths);
        assert_eq!(hist.len(), HISTORY_CAP);
        assert_eq!(hist[0].picked_at, (total - HISTORY_CAP) as i64, "oldest rows dropped");
        assert_eq!(hist.last().unwrap().picked_at, (total - 1) as i64, "newest kept last");
        let raw = std::fs::read_to_string(&paths.history).unwrap();
        assert_eq!(raw.lines().count(), HISTORY_CAP, "the file itself is bounded");
    }

    #[test]
    fn rows_naming_an_invalid_slot_are_dropped_on_read() {
        // Review 047 nit: the derived Deserialize accepts any string, so the
        // readers re-validate. A traversal name never reaches the picker.
        let dir = tempfile::tempdir().unwrap();
        let paths = pin_paths(dir.path(), "a");
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        let good = serde_json::to_string(&pin("slot1", 1)).unwrap();
        let bad = serde_json::to_string(&pin("../../etc", 2)).unwrap();
        std::fs::write(&paths.history, format!("{bad}\n{good}\n")).unwrap();
        assert_eq!(read_pin_history(&paths), vec![pin("slot1", 1)]);
        std::fs::write(&paths.pin, &bad).unwrap();
        assert_eq!(read_pin(&paths), None);
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
        let first = pick_round_robin(&pool, &lu(&hist)).unwrap().to_string();
        write_pin(&paths, &pin(&first, 100)).unwrap();

        let hist = read_pin_history(&paths);
        let second = pick_round_robin(&pool, &lu(&hist)).unwrap().to_string();
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
            pick_with_budget(&pool, &lu(&[]), &none_live(), &headroom),
            Some(PickResult::Chose {
                slot: "slot1".into(),
                headroom_pct: 100,
            }),
        );
        // After one pick on slot1, the next lands on slot2.
        let hist = vec![pin("slot1", 10)];
        assert_eq!(
            pick_with_budget(&pool, &lu(&hist), &none_live(), &headroom),
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
        let hist = vec![pin("slot1", 10), pin("slot2", 50)]; // slot1 oldest
        let headroom = vec![hr(20, Some(2_000)), hr(100, Some(9_000))];
        assert_eq!(
            pick_with_budget(&pool, &lu(&hist), &none_live(), &headroom),
            Some(PickResult::Chose {
                slot: "slot2".into(),
                headroom_pct: 100,
            }),
        );
    }

    #[test]
    fn a_live_members_slot_is_demoted_while_another_has_headroom() {
        // Review 047 S3: `a` is running on slot1, which also has the most
        // headroom and is the LRU. `d` still lands on slot2.
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let live = BTreeSet::from(["slot1".to_string()]);
        let headroom = vec![hr(90, None), hr(40, None)];
        assert_eq!(
            pick_with_budget(&pool, &lu(&[pin("slot2", 50)]), &live, &headroom),
            Some(PickResult::Chose {
                slot: "slot2".into(),
                headroom_pct: 40,
            }),
        );
    }

    #[test]
    fn a_live_slot_is_shared_when_every_other_slot_is_exhausted() {
        let pool = vec!["slot1".to_string(), "slot2".into()];
        let live = BTreeSet::from(["slot1".to_string()]);
        let headroom = vec![hr(60, None), hr(0, Some(9_000))];
        assert_eq!(
            pick_with_budget(&pool, &lu(&[]), &live, &headroom),
            Some(PickResult::Chose {
                slot: "slot1".into(),
                headroom_pct: 60,
            }),
        );
        // Every slot live ⇒ fall back to the plain headroom + LRU order.
        let both = BTreeSet::from(["slot1".to_string(), "slot2".into()]);
        let even = vec![hr(100, None), hr(100, None)];
        assert_eq!(
            pick_with_budget(&pool, &lu(&[pin("slot1", 1)]), &both, &even),
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
            pick_with_budget(&pool, &lu(&[]), &none_live(), &headroom),
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
            pick_with_budget(&pool, &lu(&[]), &none_live(), &headroom),
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
            pick_with_budget(&pool, &lu(&[]), &none_live(), &headroom),
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
            pick_with_budget(&pool, &lu(&hist), &none_live(), &headroom),
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
            pick_with_budget(&pool, &lu(&[]), &none_live(), &headroom),
            Some(PickResult::Stall { until_at: None }),
        );
    }

    #[test]
    fn pick_with_budget_empty_pool_is_none() {
        assert_eq!(pick_with_budget(&[], &lu(&[]), &none_live(), &[]), None);
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
