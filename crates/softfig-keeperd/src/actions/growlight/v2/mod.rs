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
//! The §6.8 verbs live beside this module in
//! [`super::queue_verbs`](super::queue_verbs) (slice 004 onward) and call
//! these three. Nothing else creates a v2 file, so nothing v2-shaped appears
//! in the live garden before the first v2 verb runs (§11), and the legacy
//! verbs keep running unchanged.

mod ops;
mod state;
mod views;
// `pub(crate)` (instead of `mod`) so the slice-004 tests reuse the
// temp-garden harness in `write::tests::unlocked` — keeperd-internal either
// way.
pub(crate) mod write;

pub use ops::{
    queue_v2_add_sub, queue_v2_claim, queue_v2_deferred, queue_v2_follow_ups, queue_v2_session_log,
    queue_v2_set_status,
};
pub use state::{load_queue_state, load_slices, milestone_path, slices_file, QUEUE_FILE};
pub use views::{
    queue_view, queue_view_host, slices_view, slices_view_host, QUEUE_V2_TAG, SLICES_V2_TAG,
};
pub use write::{apply, ExtraWrites, FileWrite, ViewWrite};
