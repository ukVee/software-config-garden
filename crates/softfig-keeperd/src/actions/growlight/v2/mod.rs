//! The queue **v2** file layer — keeperd's half of spec §3 (milestone
//! `queue-v2-state`, slice 003).
//!
//! The state model lives in `softfig-ipc` (slices 001–002); this module is
//! the only keeperd code that touches the v2 TOML files:
//!
//! - [`state`] — the file paths and the fail-closed loaders (read → parse →
//!   validate; an invalid file is a typed error, never an empty model);
//! - [`write`] — the only writer path: whole-file CAS checks + worktree
//!   writes + exactly one commit per verb;
//! - [`views`] — the §3.4 derived-view renderers (managed regions in the
//!   backlog and milestone docs), rendered only when their TOML exists.
//!
//! No verbs live here yet — they arrive in slices 004–006, live beside this
//! module in `actions::growlight`, and call these three. Until then nothing
//! creates a v2 file, so nothing v2-shaped appears in the live garden (§11)
//! and the legacy verbs keep running unchanged.
//!
//! Staging note: with the verbs still unwritten, every item here is reachable
//! only from the slice-003 tests, so `dead_code` would flag the lot. The
//! module-scoped allow below is the same staging pattern `paths.rs` uses for
//! its scaffolder-only helpers — drop it (and the re-export allows) when the
//! first verb lands in slice 004.

#[allow(dead_code)]
mod state;
#[allow(dead_code)]
mod views;
#[allow(dead_code)]
mod write;

#[allow(unused_imports)]
pub use state::{
    load_queue_state, load_slices, milestone_path, slices_file, LoadedFile, QueueState,
    V2FileError, MILESTONES_DIR, QUEUE_ARCHIVE_FILE, QUEUE_FILE,
};
#[allow(unused_imports)]
pub use views::{
    queue_view, queue_view_host, slices_view, slices_view_host, QUEUE_V2_TAG, SLICES_V2_TAG,
};
#[allow(unused_imports)]
pub use write::{apply, FileWrite, ViewWrite};
