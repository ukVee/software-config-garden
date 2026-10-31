//! soft-fig token telemetry — **phase 1: Layer-1 capture + flush** (garden
//! `meta/spec-token-telemetry.md` §3.1, §4, §5, §10).
//!
//! One [`RequestRow`] per model API request made by a growlight session: a
//! growlightd-driven claude or opencode member, or a semi-auto `claude`. The
//! crate owns the row, the [`Recorder`] seam the capture points hand rows to,
//! and (from slice 002) the bounded ring + batched sqlite flush to
//! `$XDG_STATE_HOME/softfig/telemetry.db`.
//!
//! ## Where rows come from (spec §4)
//!
//! Not an HTTP client — growlightd shells `claude -p` and `opencode run`, and
//! semi-auto is an interactive `claude`. Capture reads what those already emit:
//!
//! - **claude members** — the stream-json `assistant` events, one row per
//!   closed `message.id` ([`SettledFrom::Stream`]).
//! - **opencode members** — one row per `step_finish`, plus one remainder row
//!   settled against opencode's `session_v2` at EOF ([`SettledFrom::Ledger`]),
//!   because 2.x never streams the final step.
//! - **semi-auto** — a `SessionEnd` hook ingests the transcript JSONL in one
//!   batch ([`SettledFrom::Transcript`]), idempotent on
//!   `(session_id, request_id)`.
//!
//! ## What a row never carries
//!
//! Message bodies. A row is ids + token counts + a derived cost, so a
//! vault-sealed slice produces an ordinary row (spec §11 "Sealed slices").
//!
//! ## Wear
//!
//! The tablet's eMMC is wear-sensitive: the ring soaks bursts and the flush is
//! coalesced (30 s or 1 000 pending, one transaction, no transaction at all
//! when idle). The constants live in [`schema`].

pub mod recorder;
pub mod row;
pub mod schema;

pub use recorder::{NullRecorder, Recorder};
pub use row::{Backend, RequestRow, SettledFrom, Speed, TokenCounts};
