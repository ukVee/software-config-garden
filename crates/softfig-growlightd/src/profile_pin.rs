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
//! - Budget awareness is slice 004, not here: the picker owns the
//!   round-robin policy; budget-aware fallback is a future layer.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

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

fn now_unix() -> i64 {
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
