//! The sqlite store: open + migrate, batched insert, retention sweep (spec §5).

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, params};

use crate::row::RequestRow;
use crate::schema::{
    CREATE_DAILY_ROLLUP, CREATE_INDEXES, CREATE_REQUESTS, DB_FILE, RAW_RETENTION_DAYS,
    SCHEMA_VERSION,
};
use crate::ts::iso8601_utc;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("telemetry db: {0}")]
    Io(#[from] std::io::Error),
    #[error("telemetry db: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The file was written by a newer build; this one won't guess at it.
    #[error("telemetry db schema v{found} is newer than this build's v{SCHEMA_VERSION}")]
    NewerSchema { found: u32 },
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// `$XDG_STATE_HOME/softfig/telemetry.db`, falling back to
/// `~/.local/state/softfig/telemetry.db`. `None` when the environment gives
/// neither a state dir nor a home.
pub fn default_db_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("softfig").join(DB_FILE))
}

/// One migration step per schema version: `MIGRATIONS[i]` takes a db from
/// `user_version` `i` to `i + 1`. Layer 2 appends a step; nothing edits one in
/// place.
const MIGRATIONS: &[fn(&Connection) -> rusqlite::Result<()>] = &[migrate_v0_to_v1];

const _: () = assert!(MIGRATIONS.len() == SCHEMA_VERSION as usize);

fn migrate_v0_to_v1(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_REQUESTS)?;
    for ddl in CREATE_INDEXES {
        conn.execute_batch(ddl)?;
    }
    conn.execute_batch(CREATE_DAILY_ROLLUP)
}

/// What one [`Store::sweep_retention`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Raw rows rolled into `daily_rollup` and then deleted.
    pub rolled: usize,
}

#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if absent) the db at `path` and bring it to
    /// [`SCHEMA_VERSION`]. WAL + `synchronous=NORMAL` keep a flush to one
    /// fsync-light append; the busy timeout makes a concurrent writer (a
    /// semi-auto `ingest-transcript` beside growlightd) queue instead of fail.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        migrate(&mut conn)?;
        Ok(Self { conn })
    }

    /// Insert `rows` in one transaction. `INSERT OR IGNORE` on the
    /// `(session_id, request_id)` key, so a re-ingest is a no-op; returns how
    /// many rows were new. An empty batch opens no transaction.
    pub fn insert_batch(&mut self, rows: &[RequestRow]) -> Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.transaction()?;
        let mut new = 0;
        {
            let mut stmt = tx.prepare_cached(INSERT_REQUEST)?;
            for r in rows {
                new += stmt.execute(params![
                    iso8601_utc(r.ts),
                    r.backend.as_str(),
                    r.provider,
                    r.model,
                    r.session_id,
                    r.request_id,
                    r.member,
                    r.profile,
                    r.item_id,
                    r.slice_id,
                    r.queue,
                    r.turn_index,
                    sql_u64(r.tokens.input),
                    sql_u64(r.tokens.output),
                    sql_u64(r.tokens.cache_read),
                    sql_u64(r.tokens.cache_creation),
                    sql_u64(r.tokens.cache_creation_1h),
                    r.tokens.thinking.map(sql_u64),
                    r.effort,
                    r.speed.map(|s| s.as_str()),
                    r.stop_reason,
                    r.tool_use_count,
                    r.latency_ms.map(sql_u64),
                    r.cost_usd,
                    r.settled_from.as_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(new)
    }

    /// Roll every raw row older than [`RAW_RETENTION_DAYS`] before `now` (unix
    /// seconds) into `daily_rollup`, then delete those rows — one transaction,
    /// so a crash can't count a row twice or lose it. Opens no transaction
    /// when nothing has aged out.
    ///
    /// A day straddling the cutoff rolls up in parts across sweeps; the upsert
    /// adds each part to the same rollup row.
    pub fn sweep_retention(&mut self, now: i64) -> Result<SweepOutcome> {
        let cutoff = iso8601_utc(now - i64::from(RAW_RETENTION_DAYS) * 86_400);
        let aged: bool = self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM requests WHERE ts < ?1)",
            [&cutoff],
            |r| r.get(0),
        )?;
        if !aged {
            return Ok(SweepOutcome::default());
        }
        let tx = self.conn.transaction()?;
        tx.execute(ROLL_UP_AGED, [&cutoff])?;
        let rolled = tx.execute("DELETE FROM requests WHERE ts < ?1", [&cutoff])?;
        tx.commit()?;
        Ok(SweepOutcome { rolled })
    }

    #[cfg(test)]
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let found: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema { found });
    }
    for (from, step) in MIGRATIONS.iter().enumerate().skip(found as usize) {
        let tx = conn.transaction()?;
        step(&tx)?;
        tx.pragma_update(None, "user_version", from as u32 + 1)?;
        tx.commit()?;
    }
    Ok(())
}

/// sqlite integers are i64; a count past that is not a real count, so clamp
/// rather than fail the batch.
fn sql_u64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

const INSERT_REQUEST: &str = "\
INSERT OR IGNORE INTO requests (
    ts, backend, provider, model, session_id, request_id, member, profile,
    item_id, slice_id, queue, turn_index, input_tokens, output_tokens,
    cache_read_input_tokens, cache_creation_input_tokens,
    cache_creation_1h_input_tokens, thinking_tokens, effort, speed, stop_reason,
    tool_use_count, latency_ms, cost_usd, settled_from
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
          ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)";

/// `ts` is `YYYY-MM-DDTHH:MM:SSZ`, so its first ten characters are the UTC day.
/// A null `slice_id` rolls up as `''` (the rollup key can't hold null), and an
/// unpriced row adds nothing to `cost_usd`.
const ROLL_UP_AGED: &str = "\
INSERT INTO daily_rollup (
    day, model, backend, provider, slice_id, requests, input_tokens,
    output_tokens, cache_read_input_tokens, cache_creation_input_tokens,
    cache_creation_1h_input_tokens, thinking_tokens, cost_usd
)
SELECT substr(ts, 1, 10), model, backend, provider, COALESCE(slice_id, ''),
       COUNT(*), SUM(input_tokens), SUM(output_tokens),
       SUM(cache_read_input_tokens), SUM(cache_creation_input_tokens),
       SUM(cache_creation_1h_input_tokens), COALESCE(SUM(thinking_tokens), 0), COALESCE(SUM(cost_usd), 0.0)
FROM requests
WHERE ts < ?1
GROUP BY 1, 2, 3, 4, 5
ON CONFLICT (day, model, backend, provider, slice_id) DO UPDATE SET
    requests                    = requests + excluded.requests,
    input_tokens                = input_tokens + excluded.input_tokens,
    output_tokens               = output_tokens + excluded.output_tokens,
    cache_read_input_tokens     = cache_read_input_tokens + excluded.cache_read_input_tokens,
    cache_creation_input_tokens = cache_creation_input_tokens + excluded.cache_creation_input_tokens,
    cache_creation_1h_input_tokens = cache_creation_1h_input_tokens + excluded.cache_creation_1h_input_tokens,
    thinking_tokens             = thinking_tokens + excluded.thinking_tokens,
    cost_usd                    = cost_usd + excluded.cost_usd";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::row::{Backend, SettledFrom, Speed, TokenCounts};

    pub(crate) fn row(session: &str, request: &str, ts: i64) -> RequestRow {
        RequestRow {
            ts,
            backend: Backend::Claude,
            provider: "anthropic".into(),
            model: "claude-opus-5-5".into(),
            session_id: session.into(),
            request_id: request.into(),
            member: "a".into(),
            profile: Some("slot1".into()),
            item_id: Some("token-telemetry-p1".into()),
            slice_id: Some("002".into()),
            queue: None,
            turn_index: 0,
            tokens: TokenCounts {
                input: 10,
                output: 20,
                cache_read: 300,
                cache_creation: 40,
                cache_creation_1h: 15,
                thinking: Some(5),
            },
            effort: Some("high".into()),
            speed: Some(Speed::Standard),
            stop_reason: Some("end_turn".into()),
            tool_use_count: 1,
            latency_ms: None,
            cost_usd: Some(0.5),
            settled_from: SettledFrom::Stream,
        }
    }

    fn count(store: &Store, table: &str) -> i64 {
        store
            .conn()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    const NOW: i64 = 1_793_462_624; // 2026-10-31T16:03:44Z
    const DAY: i64 = 86_400;

    #[test]
    fn open_creates_the_schema_and_reopens_without_migrating_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/softfig/telemetry.db");
        {
            let mut store = Store::open(&path).unwrap();
            assert_eq!(store.insert_batch(&[row("s", "r1", NOW)]).unwrap(), 1);
            let v: u32 = store
                .conn()
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert_eq!(v, SCHEMA_VERSION);
            let mode: String = store
                .conn()
                .pragma_query_value(None, "journal_mode", |r| r.get(0))
                .unwrap();
            assert_eq!(mode, "wal");
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(count(&store, "requests"), 1, "reopen kept the row");
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::NewerSchema { found }) if found == SCHEMA_VERSION + 1
        ));
    }

    #[test]
    fn insert_is_idempotent_on_session_and_request() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let batch = [
            row("s", "r1", NOW),
            row("s", "r2", NOW),
            row("t", "r1", NOW),
        ];
        assert_eq!(store.insert_batch(&batch).unwrap(), 3);
        assert_eq!(store.insert_batch(&batch).unwrap(), 0);
        assert_eq!(store.insert_batch(&[row("s", "r3", NOW)]).unwrap(), 1);
        assert_eq!(store.insert_batch(&[]).unwrap(), 0);
        assert_eq!(count(&store, "requests"), 4);
    }

    #[test]
    fn a_row_round_trips_its_columns() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let mut r = row("s", "r1", NOW);
        r.tokens.thinking = None;
        r.speed = None;
        r.backend = Backend::Opencode;
        r.settled_from = SettledFrom::Ledger;
        store.insert_batch(&[r]).unwrap();
        let got: (String, String, Option<i64>, Option<String>, String, i64) = store
            .conn()
            .query_row(
                "SELECT ts, backend, thinking_tokens, speed, settled_from, cache_read_input_tokens
                 FROM requests",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            got,
            (
                "2026-10-31T16:03:44Z".into(),
                "opencode".into(),
                None,
                None,
                "ledger".into(),
                300
            )
        );
    }

    #[test]
    fn sweep_rolls_up_aged_rows_by_day_and_slice_then_deletes_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let old = NOW - 100 * DAY; // 2026-07-23
        let mut unbound = row("s", "r3", old + 60);
        unbound.slice_id = None;
        unbound.cost_usd = None;
        unbound.tokens.thinking = None;
        store
            .insert_batch(&[
                row("s", "r1", old),
                row("s", "r2", old + 60),
                unbound,
                row("s", "r4", old + DAY), // the next day
                row("s", "fresh", NOW - 89 * DAY),
            ])
            .unwrap();

        assert_eq!(
            store.sweep_retention(NOW).unwrap(),
            SweepOutcome { rolled: 4 }
        );
        assert_eq!(count(&store, "requests"), 1, "only the fresh row is left");

        // day, slice_id, requests, then the five token classes, then cost.
        type Rollup = (String, String, i64, i64, i64, i64, i64, i64, f64);
        let rollup: Vec<Rollup> = store
            .conn()
            .prepare(
                "SELECT day, slice_id, requests, input_tokens, output_tokens,
                        cache_read_input_tokens, cache_creation_input_tokens,
                        thinking_tokens, cost_usd
                 FROM daily_rollup ORDER BY day, slice_id",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rollup,
            vec![
                ("2026-07-23".into(), "".into(), 1, 10, 20, 300, 40, 0, 0.0),
                (
                    "2026-07-23".into(),
                    "002".into(),
                    2,
                    20,
                    40,
                    600,
                    80,
                    10,
                    1.0
                ),
                (
                    "2026-07-24".into(),
                    "002".into(),
                    1,
                    10,
                    20,
                    300,
                    40,
                    5,
                    0.5
                ),
            ]
        );
        // The 1h breakdown rolls up beside its total: four rows of 15.
        let one_h: i64 = store
            .conn()
            .query_row(
                "SELECT SUM(cache_creation_1h_input_tokens) FROM daily_rollup",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(one_h, 60);

        // Nothing left to age: no transaction, no change.
        assert_eq!(store.sweep_retention(NOW).unwrap(), SweepOutcome::default());
    }

    #[test]
    fn a_day_swept_in_parts_adds_into_one_rollup_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let day_start = (NOW - 100 * DAY).div_euclid(DAY) * DAY;
        store
            .insert_batch(&[
                row("s", "morning", day_start + 3600),
                row("s", "evening", day_start + 20 * 3600),
            ])
            .unwrap();
        // Cutoff falls between the two rows.
        let first_now = day_start + 12 * 3600 + i64::from(RAW_RETENTION_DAYS) * DAY;
        assert_eq!(store.sweep_retention(first_now).unwrap().rolled, 1);
        assert_eq!(store.sweep_retention(first_now + DAY).unwrap().rolled, 1);
        let (requests, cost): (i64, f64) = store
            .conn()
            .query_row("SELECT requests, cost_usd FROM daily_rollup", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((requests, cost), (2, 1.0));
        assert_eq!(count(&store, "daily_rollup"), 1);
    }
}
