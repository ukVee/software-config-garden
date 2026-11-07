//! The store's constants: file location, schema DDL, and the ring / flush /
//! retention policy (spec §5). Pure data — [`crate::store`] applies it.

/// The db file under `$XDG_STATE_HOME/softfig/` (state dir, not config dir:
/// this is not agent runtime scratch).
pub const DB_FILE: &str = "telemetry.db";

/// `PRAGMA user_version`. Bumped by a migration, never by editing the v1 DDL
/// in place (the softfig-store `SCHEMA_V1` rule).
pub const SCHEMA_VERSION: u32 = 3;

/// The ring's capacity. Full → the oldest row is dropped and counted.
pub const RING_CAPACITY: usize = 10_000;

/// Flush when this many rows are pending...
pub const FLUSH_PENDING_ROWS: usize = 1_000;

/// ...or this often, whichever comes first. A tick with nothing pending opens
/// no transaction.
pub const FLUSH_INTERVAL_SECS: u64 = 30;

/// Raw rows older than this are rolled into `daily_rollup`, then deleted.
pub const RAW_RETENTION_DAYS: u32 = 90;

/// How often the retention sweep runs on the flush thread.
pub const RETENTION_SWEEP_SECS: u64 = 24 * 60 * 60;

/// The Layer-1 table, one row per request. The `(session_id, request_id)`
/// unique key makes every ingest `INSERT OR IGNORE`-idempotent.
pub const CREATE_REQUESTS: &str = "\
CREATE TABLE IF NOT EXISTS requests (
    id                          INTEGER PRIMARY KEY,
    ts                          TEXT    NOT NULL,
    backend                     TEXT    NOT NULL,
    provider                    TEXT    NOT NULL,
    model                       TEXT    NOT NULL,
    session_id                  TEXT    NOT NULL,
    request_id                  TEXT    NOT NULL,
    member                      TEXT    NOT NULL,
    profile                     TEXT,
    item_id                     TEXT,
    slice_id                    TEXT,
    queue                       TEXT,
    turn_index                  INTEGER NOT NULL,
    input_tokens                INTEGER NOT NULL,
    output_tokens               INTEGER NOT NULL,
    cache_read_input_tokens     INTEGER NOT NULL,
    cache_creation_input_tokens INTEGER NOT NULL,
    cache_creation_1h_input_tokens INTEGER NOT NULL,
    thinking_tokens             INTEGER,
    effort                      TEXT,
    speed                       TEXT,
    stop_reason                 TEXT,
    tool_use_count              INTEGER NOT NULL,
    latency_ms                  INTEGER,
    cost_usd                    REAL,
    settled_from                TEXT    NOT NULL,
    UNIQUE (session_id, request_id)
)";

/// The three indexes spec §5 names.
pub const CREATE_INDEXES: [&str; 3] = [
    "CREATE INDEX IF NOT EXISTS requests_session_ts ON requests (session_id, ts)",
    "CREATE INDEX IF NOT EXISTS requests_slice ON requests (slice_id)",
    "CREATE INDEX IF NOT EXISTS requests_model_backend_ts ON requests (model, backend, ts)",
];

// The flush threshold fits inside the ring: a pending batch can never be
// larger than what the ring holds, so a flush never races an overwrite.
const _: () = assert!(FLUSH_PENDING_ROWS < RING_CAPACITY);

/// Daily rollups, kept forever. `slice_id` is `''` rather than null for
/// unbound rows so the primary key (and the sweep's upsert) can match it.
pub const CREATE_DAILY_ROLLUP: &str = "\
CREATE TABLE IF NOT EXISTS daily_rollup (
    day                         TEXT    NOT NULL,
    model                       TEXT    NOT NULL,
    backend                     TEXT    NOT NULL,
    provider                    TEXT    NOT NULL,
    slice_id                    TEXT    NOT NULL,
    requests                    INTEGER NOT NULL,
    input_tokens                INTEGER NOT NULL,
    output_tokens               INTEGER NOT NULL,
    cache_read_input_tokens     INTEGER NOT NULL,
    cache_creation_input_tokens INTEGER NOT NULL,
    cache_creation_1h_input_tokens INTEGER NOT NULL,
    thinking_tokens             INTEGER NOT NULL,
    cost_usd                    REAL    NOT NULL,
    PRIMARY KEY (day, model, backend, provider, slice_id)
)";

/// Schema v3: how many of a rollup row's `requests` carried no price. A
/// rollup's `cost_usd` sums only the priced ones, so without this count an
/// unpriced model's aged rows would read as free. `cost_usd` is exact only
/// where `unpriced_requests = 0`; elsewhere it is a lower bound. A separate
/// `ALTER` rather than an edit to [`CREATE_DAILY_ROLLUP`], which is v1's DDL.
pub const ROLLUP_ADD_UNPRICED: &str = "\
ALTER TABLE daily_rollup ADD COLUMN unpriced_requests INTEGER NOT NULL DEFAULT 0";

/// How far each session has been rolled up. A raw row is gone once it is in
/// `daily_rollup`, so the `(session_id, request_id)` key no longer recognises
/// it: a resumed session's transcript re-offers history the sweep already
/// counted. The insert skips any row at or before its session's `through`, so
/// that history is never counted twice.
pub const CREATE_ROLLUP_WATERMARK: &str = "\
CREATE TABLE IF NOT EXISTS rollup_watermark (
    session_id TEXT PRIMARY KEY,
    through    TEXT NOT NULL
)";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every token class the pricing derivation reads has a column, in both
    /// tables, so a priced row and its rollup can't disagree about a class.
    #[test]
    fn every_token_class_is_stored_and_rolled_up() {
        for col in [
            "input_tokens",
            "output_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
            "cache_creation_1h_input_tokens",
            "thinking_tokens",
            "cost_usd",
        ] {
            assert!(CREATE_REQUESTS.contains(col), "requests lacks {col}");
            assert!(
                CREATE_DAILY_ROLLUP.contains(col),
                "daily_rollup lacks {col}"
            );
        }
    }
}
