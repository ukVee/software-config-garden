//! The sqlite store: open + migrate, batched insert, retention sweep (spec §5).

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};

use crate::row::RequestRow;
use crate::schema::{
    CREATE_DAILY_ROLLUP, CREATE_INDEXES, CREATE_REQUESTS, CREATE_ROLLUP_WATERMARK,
    CREATE_TRANSCRIPT_MARKS, DB_FILE,
    RAW_RETENTION_DAYS, REQUESTS_ADD_VENDOR_COST, ROLLUP_ADD_UNPRICED, SCHEMA_VERSION,
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
const MIGRATIONS: &[fn(&Connection) -> rusqlite::Result<()>] = &[
    migrate_v0_to_v1,
    migrate_v1_to_v2,
    migrate_v2_to_v3,
    migrate_v3_to_v4,
    migrate_v4_to_v5,
];

const _: () = assert!(MIGRATIONS.len() == SCHEMA_VERSION as usize);

fn migrate_v0_to_v1(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_REQUESTS)?;
    for ddl in CREATE_INDEXES {
        conn.execute_batch(ddl)?;
    }
    conn.execute_batch(CREATE_DAILY_ROLLUP)
}

fn migrate_v1_to_v2(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_ROLLUP_WATERMARK)
}

fn migrate_v2_to_v3(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(ROLLUP_ADD_UNPRICED)
}

fn migrate_v3_to_v4(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(REQUESTS_ADD_VENDOR_COST)
}

fn migrate_v4_to_v5(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_TRANSCRIPT_MARKS)
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
        // Create the file 0600 ourselves: sqlite gives the `-wal` and `-shm`
        // files the main db's mode, so they are born 0600 too, whatever the
        // umask. An older, looser db is tightened below.
        create_private(path)?;
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        migrate(&mut conn)?;
        restrict_modes(path)?;
        Ok(Self { conn })
    }

    /// Insert `rows` in one transaction. `INSERT OR IGNORE` on the
    /// `(session_id, request_id)` key, so a re-ingest is a no-op. A row at or
    /// before its session's `rollup_watermark` is skipped too, so history the
    /// sweep already rolled up is not counted twice; returns how many rows were
    /// new. An empty batch opens no transaction.
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
                    r.vendor_cost_usd,
                    r.settled_from.as_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(new)
    }

    /// The bytes of the transcript at `path` already ingested, if any.
    pub fn transcript_mark(&self, path: &Path) -> Result<Option<u64>> {
        let bytes: Option<i64> = self
            .conn
            .query_row(
                "SELECT bytes FROM transcript_marks WHERE path = ?1",
                [path.to_string_lossy()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(bytes.map(|b| u64::try_from(b).unwrap_or(0)))
    }

    /// Record that the first `bytes` of the transcript at `path` are in.
    pub fn set_transcript_mark(&self, path: &Path, bytes: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO transcript_marks (path, bytes) VALUES (?1, ?2)
             ON CONFLICT(path) DO UPDATE SET bytes = excluded.bytes",
            params![path.to_string_lossy(), sql_u64(bytes)],
        )?;
        Ok(())
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
        tx.execute(ADVANCE_WATERMARKS, [&cutoff])?;
        let rolled = tx.execute("DELETE FROM requests WHERE ts < ?1", [&cutoff])?;
        tx.commit()?;
        Ok(SweepOutcome { rolled })
    }

    #[cfg(test)]
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }
}

/// Create `path` empty with mode 0600 if it is absent. An existing file is
/// left alone (sqlite opens an empty file as a new db).
fn create_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

/// Set the db and whichever `-wal` / `-shm` sidecars exist to 0600. A db a
/// build before this one made is 0644, and its sidecars follow it.
fn restrict_modes(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        match std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    Ok(())
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
    tool_use_count, latency_ms, cost_usd, vendor_cost_usd, settled_from
)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
       ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26
WHERE NOT EXISTS (
    SELECT 1 FROM rollup_watermark w WHERE w.session_id = ?5 AND ?1 <= w.through
)";

/// Run in the roll-up's transaction, before the delete: each session's
/// watermark moves to the newest of its rows being rolled up.
const ADVANCE_WATERMARKS: &str = "\
INSERT INTO rollup_watermark (session_id, through)
SELECT session_id, MAX(ts) FROM requests WHERE ts < ?1 GROUP BY session_id
ON CONFLICT (session_id) DO UPDATE SET through = MAX(through, excluded.through)";

/// `ts` is `YYYY-MM-DDTHH:MM:SSZ`, so its first ten characters are the UTC day.
/// A null `slice_id` rolls up as `''` (the rollup key can't hold null). An
/// unpriced row adds nothing to `cost_usd` but is counted in
/// `unpriced_requests`, so the rollup never reads an unknown cost as zero.
const ROLL_UP_AGED: &str = "\
INSERT INTO daily_rollup (
    day, model, backend, provider, slice_id, requests, input_tokens,
    output_tokens, cache_read_input_tokens, cache_creation_input_tokens,
    cache_creation_1h_input_tokens, thinking_tokens, cost_usd, unpriced_requests
)
SELECT substr(ts, 1, 10), model, backend, provider, COALESCE(slice_id, ''),
       COUNT(*), SUM(input_tokens), SUM(output_tokens),
       SUM(cache_read_input_tokens), SUM(cache_creation_input_tokens),
       SUM(cache_creation_1h_input_tokens), COALESCE(SUM(thinking_tokens), 0), COALESCE(SUM(cost_usd), 0.0),
       COALESCE(SUM(cost_usd IS NULL), 0)
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
    cost_usd                    = cost_usd + excluded.cost_usd,
    unpriced_requests           = unpriced_requests + excluded.unpriced_requests";

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
            vendor_cost_usd: None,
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
    fn the_db_and_its_sidecars_are_0600_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let sidecar = |s: &str| {
            let mut f = path.as_os_str().to_owned();
            f.push(s);
            PathBuf::from(f)
        };
        // A db an older build left world-readable is tightened on open.
        Connection::open(&path).unwrap().execute_batch("CREATE TABLE x (a)").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut store = Store::open(&path).unwrap();
        store.insert_batch(&[row("s", "r1", NOW)]).unwrap();
        // The sidecars exist while the connection is open.
        for s in ["", "-wal", "-shm"] {
            assert_eq!(mode(&sidecar(s)), 0o600, "{path:?}{s}");
        }
        drop(store);
        // A fresh db is created 0600 from the start.
        let fresh = dir.path().join("fresh.db");
        let store = Store::open(&fresh).unwrap();
        assert_eq!(mode(&fresh), 0o600);
        drop(store);
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
    fn history_already_rolled_up_is_not_counted_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let old = NOW - 100 * DAY;
        let history = [row("s", "r1", old), row("s", "r2", old + 60)];
        // A backfill of old history is kept, then rolled up by the sweep.
        assert_eq!(store.insert_batch(&history).unwrap(), 2);
        assert_eq!(store.sweep_retention(NOW).unwrap().rolled, 2);

        // A resumed session's transcript offers the same history again, beside
        // a request that is new.
        let resumed = [history[0].clone(), history[1].clone(), row("s", "r3", NOW)];
        assert_eq!(store.insert_batch(&resumed).unwrap(), 1, "only r3 is new");
        assert_eq!(store.sweep_retention(NOW).unwrap(), SweepOutcome::default());
        let requests: i64 = store
            .conn()
            .query_row("SELECT SUM(requests) FROM daily_rollup", [], |r| r.get(0))
            .unwrap();
        assert_eq!(requests, 2, "the rollup counted each request once");

        // Another session's history of the same age is its own.
        assert_eq!(store.insert_batch(&[row("t", "r1", old)]).unwrap(), 1);
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

    #[test]
    fn an_unpriced_row_stays_unpriced_in_the_rollup() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let day_start = (NOW - 100 * DAY).div_euclid(DAY) * DAY;
        let mut unpriced = row("s", "u1", day_start + 60);
        unpriced.model = "mystery".into();
        unpriced.cost_usd = None;
        let mut also = row("s", "u2", day_start + 120);
        also.model = "mystery".into();
        also.cost_usd = None;
        // A priced model on the same day, and a model with one of each.
        let mut mixed = row("s", "m2", day_start + 240);
        mixed.model = "mixed".into();
        let mut mixed_unpriced = row("s", "m1", day_start + 180);
        mixed_unpriced.model = "mixed".into();
        mixed_unpriced.cost_usd = None;
        store
            .insert_batch(&[
                unpriced,
                also,
                mixed,
                mixed_unpriced,
                row("s", "priced", day_start + 300),
            ])
            .unwrap();
        store.sweep_retention(NOW).unwrap();

        let by_model: Vec<(String, i64, f64, i64)> = store
            .conn()
            .prepare(
                "SELECT model, requests, cost_usd, unpriced_requests
                 FROM daily_rollup ORDER BY model",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            by_model,
            vec![
                ("claude-opus-5-5".into(), 1, 0.5, 0),
                ("mixed".into(), 2, 0.5, 1),
                // Every request unpriced: the count says so, and cost_usd is not a price.
                ("mystery".into(), 2, 0.0, 2),
            ]
        );
    }

    #[test]
    fn unpriced_counts_add_across_sweeps_of_one_day() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("t.db")).unwrap();
        let day_start = (NOW - 100 * DAY).div_euclid(DAY) * DAY;
        let mut a = row("s", "morning", day_start + 3600);
        a.cost_usd = None;
        let mut b = row("s", "evening", day_start + 20 * 3600);
        b.cost_usd = None;
        store.insert_batch(&[a, b]).unwrap();
        let first_now = day_start + 12 * 3600 + i64::from(RAW_RETENTION_DAYS) * DAY;
        store.sweep_retention(first_now).unwrap();
        store.sweep_retention(first_now + DAY).unwrap();
        let (requests, unpriced): (i64, i64) = store
            .conn()
            .query_row(
                "SELECT requests, unpriced_requests FROM daily_rollup",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((requests, unpriced), (2, 2));
    }

    #[test]
    fn a_v2_db_migrates_to_v3_keeping_its_rollup_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            // A db as the v2 build left it: steps 0 and 1, user_version 2.
            let conn = Connection::open(&path).unwrap();
            migrate_v0_to_v1(&conn).unwrap();
            migrate_v1_to_v2(&conn).unwrap();
            conn.pragma_update(None, "user_version", 2).unwrap();
            conn.execute(
                "INSERT INTO daily_rollup VALUES
                 ('2026-07-23', 'm', 'claude', 'anthropic', '', 3, 1, 1, 1, 1, 1, 0, 1.5)",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let v: u32 = store
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION, "v2 steps through v3 to the current schema");
        let (requests, cost, unpriced): (i64, f64, i64) = store
            .conn()
            .query_row(
                "SELECT requests, cost_usd, unpriced_requests FROM daily_rollup",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((requests, cost, unpriced), (3, 1.5, 0), "history kept, none marked unpriced");
        // The column is not re-added on the next open.
        drop(store);
        Store::open(&path).unwrap();
        assert!(Connection::open(&path).unwrap().execute_batch(ROLLUP_ADD_UNPRICED).is_err());
    }

    #[test]
    fn a_v3_db_migrates_to_v4_keeping_its_requests_with_a_null_vendor_cost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            // A db as the v3 build left it: steps 0 to 2, user_version 3, one raw row.
            let conn = Connection::open(&path).unwrap();
            migrate_v0_to_v1(&conn).unwrap();
            migrate_v1_to_v2(&conn).unwrap();
            migrate_v2_to_v3(&conn).unwrap();
            conn.pragma_update(None, "user_version", 3).unwrap();
            conn.execute(
                "INSERT INTO requests (
                     ts, backend, provider, model, session_id, request_id, member, turn_index,
                     input_tokens, output_tokens, cache_read_input_tokens,
                     cache_creation_input_tokens, cache_creation_1h_input_tokens,
                     tool_use_count, cost_usd, settled_from
                 ) VALUES ('2026-07-23T00:00:00Z', 'opencode', 'deepseek', 'm', 's', 'r', 'a', 0,
                           1, 1, 1, 0, 0, 0, 0.25, 'stream')",
                [],
            )
            .unwrap();
        }
        let mut store = Store::open(&path).unwrap();
        let (cost, vendor): (f64, Option<f64>) = store
            .conn()
            .query_row("SELECT cost_usd, vendor_cost_usd FROM requests", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((cost, vendor), (0.25, None), "history kept; no vendor figure to invent");
        // A new row stores its vendor figure beside the table's.
        let mut r = row("s2", "r1", NOW);
        r.vendor_cost_usd = Some(0.125);
        store.insert_batch(&[r]).unwrap();
        let vendor: Option<f64> = store
            .conn()
            .query_row(
                "SELECT vendor_cost_usd FROM requests WHERE session_id = 's2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(vendor, Some(0.125));
        // The column is not re-added on the next open.
        drop(store);
        Store::open(&path).unwrap();
        assert!(Connection::open(&path)
            .unwrap()
            .execute_batch(REQUESTS_ADD_VENDOR_COST)
            .is_err());
    }

    #[test]
    fn a_v4_db_migrates_to_v5_and_a_mark_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        {
            // A db as the v4 build left it: steps 0 to 3, user_version 4, one raw row.
            let conn = Connection::open(&path).unwrap();
            for step in &MIGRATIONS[..4] {
                step(&conn).unwrap();
            }
            conn.pragma_update(None, "user_version", 4).unwrap();
        }
        let mut store = Store::open(&path).unwrap();
        let v: u32 = store
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        store.insert_batch(&[row("s", "r1", NOW)]).unwrap();
        let t = Path::new("/x/sess.jsonl");
        assert_eq!(store.transcript_mark(t).unwrap(), None);
        store.set_transcript_mark(t, 120).unwrap();
        store.set_transcript_mark(t, 480).unwrap();
        assert_eq!(store.transcript_mark(t).unwrap(), Some(480), "a later mark replaces");
        assert_eq!(store.transcript_mark(Path::new("/x/other.jsonl")).unwrap(), None);
        assert_eq!(count(&store, "requests"), 1, "history kept");
    }
}
