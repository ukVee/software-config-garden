//! soft-fig token telemetry — **phase 1: Layer-1 capture + flush** (garden
//! `meta/spec-token-telemetry.md` §3.1, §4, §5, §10).
//!
//! One [`RequestRow`] per model API request made by a growlight session: a
//! growlightd-driven claude or opencode member, or a semi-auto `claude`. The
//! crate owns the row, the [`Recorder`] seam the capture points hand rows to,
//! the bounded [`RingRecorder`], and the [`Flusher`] that batches it into the
//! sqlite [`Store`] at [`default_db_path`] (`$XDG_STATE_HOME/softfig/telemetry.db`).
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
//! ## Pricing
//!
//! A capture point prices each row once with [`PriceTable::price_row`] (the
//! garden's `config/pricing.toml`, spec §6) before recording it, so
//! `cost_usd` is fixed at write time. An unknown model stores null, never 0.
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

pub mod claude;
pub mod flush;
pub mod pricing;
pub mod recorder;
pub mod ring;
pub mod row;
pub mod schema;
pub mod store;
pub mod transcript;
pub mod ts;

pub use claude::{AssistantRequest, ClaudeFold, ClosedRequest, request_for_assistant};
pub use flush::{Clock, FlushHandle, FlushPolicy, FlushStats, Flusher};
pub use pricing::{ModelPrice, PriceTable, PricingError};
pub use recorder::{NullRecorder, Recorder};
pub use ring::RingRecorder;
pub use row::{Backend, RequestRow, SettledFrom, Speed, TokenCounts};
pub use store::{Store, StoreError, SweepOutcome, default_db_path};
pub use transcript::{TranscriptKeys, ingest_transcript, renumber_turns};
