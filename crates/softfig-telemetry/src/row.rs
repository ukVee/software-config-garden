//! The Layer-1 per-request row (spec §3.1, with the phase-1 additions recorded
//! in §4: `member`, `profile`, `item_id`, `request_id`, `settled_from`).

/// Which agent CLI produced the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    Claude,
    Opencode,
}

impl Backend {
    /// The value stored in the `backend` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Claude => "claude",
            Backend::Opencode => "opencode",
        }
    }
}

/// claude's fast mode (spec §3.1 `speed`). opencode has no such switch, so its
/// rows store null.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Speed {
    Standard,
    Fast,
}

impl Speed {
    /// The value stored in the `speed` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Speed::Standard => "standard",
            Speed::Fast => "fast",
        }
    }
}

/// Where a row's token counts were read from. Kept on the row so a later
/// reader can tell a per-class streamed count from an unsplit ledger remainder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettledFrom {
    /// A live member's event stream (claude `assistant` / opencode `step_finish`).
    Stream,
    /// A semi-auto session's transcript, ingested at `SessionEnd`.
    Transcript,
    /// opencode's `session_v2` totals beyond what the stream carried — one
    /// remainder row per run, its tokens unsplit in `input_tokens`.
    Ledger,
}

impl SettledFrom {
    /// The value stored in the `settled_from` column.
    pub fn as_str(self) -> &'static str {
        match self {
            SettledFrom::Stream => "stream",
            SettledFrom::Transcript => "transcript",
            SettledFrom::Ledger => "ledger",
        }
    }
}

/// The five token classes a request is billed on (spec §6).
///
/// The classes are **disjoint**, so [`total`](Self::total) and the price sum
/// never count a token twice. The wires disagree on reasoning, and capture
/// normalises it:
///
/// - claude reports `usage.output_tokens_details.thinking_tokens` as a
///   breakdown *inside* `output_tokens`, so a claude row stores
///   `output = output_tokens − thinking_tokens`, `thinking = Some(thinking_tokens)`;
/// - opencode reports `tokens.reasoning` *beside* `tokens.output`, so it maps
///   straight across.
///
/// `thinking` is `None` where the wire gives no split at all (reasoning, if
/// any, is then inside `output`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenCounts {
    pub input: u64,
    /// Non-reasoning output — see the type docs.
    pub output: u64,
    pub cache_read: u64,
    pub cache_creation: u64,
    /// The part of `cache_creation` written at the 1-hour TTL (claude
    /// `usage.cache_creation.ephemeral_1h_input_tokens`), priced above the
    /// 5-minute tier. A breakdown *inside* `cache_creation`, not a sixth
    /// class, so [`total`](Self::total) never adds it; `0` where the wire has
    /// no TTL split.
    pub cache_creation_1h: u64,
    pub thinking: Option<u64>,
}

impl TokenCounts {
    /// Every class summed — the same total the rate meter sees for a turn.
    pub fn total(&self) -> u64 {
        self.input
            .saturating_add(self.output)
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_creation)
            .saturating_add(self.thinking.unwrap_or(0))
    }
}

/// One Messages-API (or provider-equivalent) response. Built by a capture
/// point, priced before it is recorded, and append-only once written.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestRow {
    /// Request completion time, unix seconds (stored as ISO 8601 UTC).
    pub ts: i64,
    pub backend: Backend,
    /// `anthropic` | `deepseek` | `local` | … — the pricing key's first half.
    pub provider: String,
    /// The exact model id the wire reported.
    pub model: String,
    /// The backend's own session id (claude `session_id`, opencode `sessionID`).
    pub session_id: String,
    /// The backend's id for this response (claude `message.id`, opencode
    /// `part.messageID`). With `session_id`, the row's idempotency key.
    pub request_id: String,
    /// The growlight member (agent id), or `semi-auto`.
    pub member: String,
    /// The claude login slot the session ran on; `None` for `home`, unpinned
    /// members, and opencode.
    pub profile: Option<String>,
    /// The backlog item (milestone id or task number); `None` before one is bound.
    pub item_id: Option<String>,
    pub slice_id: Option<String>,
    pub queue: Option<String>,
    /// 0-based request index within the session — Layer 2's join key.
    pub turn_index: u32,
    pub tokens: TokenCounts,
    /// `low` | `medium` | `high` | `xhigh` | `max`, as resolved at spawn.
    pub effort: Option<String>,
    pub speed: Option<Speed>,
    pub stop_reason: Option<String>,
    pub tool_use_count: u32,
    /// Neither stream carries a per-request duration, so this is `None` unless
    /// a capture point can measure it honestly.
    pub latency_ms: Option<u64>,
    /// Derived at write time from `config/pricing.toml` and stored, so a later
    /// price change never rewrites history (spec §3.1). `None` when the
    /// `(provider, model)` has no price row.
    pub cost_usd: Option<f64>,
    /// The vendor's own total for this request, kept beside `cost_usd` as a
    /// cross-check and never summed into it. opencode's `part.cost` (a step)
    /// or the ledger's difference (the remainder row); `None` for claude,
    /// whose wire carries no cost.
    pub vendor_cost_usd: Option<f64>,
    pub settled_from: SettledFrom,
}
