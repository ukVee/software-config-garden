//! The growlight **budget file** `usage.json` — the on-disk shape of a reading of
//! the account-wide 5h/7d rate-limit pool, shared by everything that writes or
//! reads it.
//!
//! It lives in the churny runtime namespace (`$XDG_CONFIG_HOME/softfig/growlight/
//! usage.json`), never in the garden, and it has **three writers**:
//!
//! - the **interactive statusline** hook `softfig growlight start` generates — a
//!   `jq` filter that tees Claude Code's own status payload on every render
//!   (`softfig-cli`'s `cmd_growlight::statusline_script`);
//! - the single-agent **`--auto`** driver, which persists each iteration's parsed
//!   stream in this same shape; and
//! - **growlightd**, which captures a headless member's `rate_limit_event`s as they
//!   stream (task 048 — a headless `claude -p` has no statusline, so without this
//!   the file fossilizes at whenever the human last ran an interactive session,
//!   and every reader downstream acts on days-old rate data).
//!
//! and **three readers**: the `--auto` between-iteration governor, the loop
//! protocol's §2b boot check (the agent reads the file itself), and the human.
//! Both crates that touch it depend on `softfig-ipc`, so — exactly like
//! [`crate::baton`] — the shape lives here once rather than being re-declared per
//! writer, where the two copies would drift.
//!
//! ## What a reading may and may not claim
//!
//! Every field a writer cannot vouch for is `Option` and **omitted**, never
//! defaulted to a number. That is not tidiness: a missing `used_percentage`
//! written as `0` reads as "the pool is empty" and silently disables a governor
//! (`window_tripped` in the `--auto` driver deliberately never trips on a missing
//! percentage). Headless runs are the case that matters — the wire's
//! `rate_limit_event` carries a coarse per-window `status` and a `resets_at`, but
//! **no** percentage — so a headless capture writes the status and the boundary it
//! genuinely observed and leaves the percentage absent.
//!
//! [`RateWindow::resets_at`] is what makes a reading falsifiable: the windows are
//! anchored to account time, not rolling from the moment of the read, so a reading
//! younger than its own window can still describe a window that has already reset.
//! A reader judges a window with [`RateWindow::window_reset_by`], never by the
//! file's age alone.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One reading of the budget pool, in the shape the file holds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageSnapshot {
    /// The reading session's own context window, when the writer had one. Absent
    /// from a **fleet** capture: growlightd runs N members with N context windows
    /// and no single one is "the" context — each member reports its own in its
    /// baton head instead of inheriting a neighbour's here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<ContextWindow>,
    /// The account-wide 5h/7d reserve windows.
    #[serde(default)]
    pub rate_limits: RateLimits,
    /// When this reading was taken, unix seconds (the statusline tee's `ts`).
    pub ts: f64,
}

/// The writing session's context window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContextWindow {
    /// Derived: `round(100 * current_tokens / context_window_size)`, clamped to a
    /// saturating `0..=100` (0 when the window size is unknown). The clamp matters
    /// because `current_tokens` is cumulative — see its note — so the raw ratio can
    /// exceed 100 in a long session.
    #[serde(default)]
    pub used_percentage: u8,
    #[serde(default)]
    pub remaining_percentage: u8,
    #[serde(default)]
    pub context_window_size: u64,
    /// The token figure the percentage was derived from: `input + cache_read +
    /// cache_creation`. This is cumulative across the session (cache reads accrue
    /// per request), NOT the exact live prompt footprint, so it can run past
    /// `context_window_size` — hence the clamp on `used_percentage`.
    #[serde(default)]
    pub current_tokens: u64,
}

/// Both rolling reserve windows of the one shared account pool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RateLimits {
    #[serde(default)]
    pub five_hour: RateWindow,
    #[serde(default)]
    pub seven_day: RateWindow,
}

/// One rolling rate-limit window as one reading saw it. Every field is optional
/// because a writer may honestly know only some of them: a headless run learns the
/// `resets_at` boundary and a coarse `status` (`"allowed"` / `"warning"` /
/// `"rejected"`) from the wire's `rate_limit_event` but **not** a used-percentage,
/// while the interactive statusline knows the percentage. An unknown field is
/// omitted from the JSON rather than written as `0` — see the module docs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RateWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_percentage: Option<u8>,
    /// When this window next resets, unix seconds — the wire's `resetsAt`, carried
    /// on every status. The one field that lets a reader tell a live reading from a
    /// fossil independently of the file's age.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<i64>,
    /// The window's coarse status as the reading saw it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl RateWindow {
    /// Whether this window has **demonstrably reset** by `now` (unix seconds): its
    /// known boundary has passed, so whatever the reading said about the window is
    /// about a window that no longer exists. `false` when the boundary is unknown —
    /// that is a reading which cannot be falsified this way, not a fresh one, so a
    /// caller with an age bound should still apply it.
    pub fn window_reset_by(&self, now: i64) -> bool {
        self.resets_at.is_some_and(|at| at <= now)
    }

    /// The window's percentage **only if the reading can still vouch for it**: a
    /// percentage was actually observed AND the window it describes has not reset by
    /// `now`. `None` means "no honest number" — report the absence, never a `0` that
    /// reads as an empty pool (the fossil-echo this file's readers must not repeat).
    pub fn vouchable_pct_at(&self, now: i64) -> Option<u8> {
        self.used_percentage.filter(|_| !self.window_reset_by(now))
    }
}

impl UsageSnapshot {
    /// Read a snapshot from `path`. `Ok(None)` when the file does not exist yet (a
    /// loop that has never run leaves no reading — an absence, not an error); an
    /// unreadable or malformed file is an error the caller reports rather than
    /// silently treating as a fresh pool.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write this snapshot to `path` atomically (write a sibling temp, then
    /// rename), so a reader — a booting member reading its budget, the human —
    /// never observes a half-written file. Creates the parent directory if needed.
    pub fn write_atomic(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let body = serde_json::to_string_pretty(self)
            .map(|j| format!("{j}\n"))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)
    }
}
