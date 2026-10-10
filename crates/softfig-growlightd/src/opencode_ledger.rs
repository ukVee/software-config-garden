//! opencode's own session record: where an opencode member's authoritative
//! end-of-run spend comes from (opencode-v2-repin slice 004).
//!
//! ## Why the stream is not enough
//!
//! On opencode 2.x, `opencode run --format json` never emits the **final** step's
//! `step_finish`. Every captured run ends `step_start`, `text`, then EOF (slice 001,
//! L8), so summing the streamed `step_finish.cost` under-reports every run, and a
//! text-only run streams no cost at all. The true totals live in opencode's session
//! record. [`crate::opencode_backend`] meters the stream live and settles against
//! this record once the child's stdout closes.
//!
//! ## Why the database and not the API
//!
//! Two sources hold the record, and both couple to opencode internals: its sqlite
//! store (`<data dir>/opencode.db`, table `session_v2`) and its HTTP API
//! (`opencode api --standalone session.get`). This module reads the database:
//!
//! - The API path boots a whole second opencode server per member exit. That server
//!   loads the global config, its plugins and MCP servers, on a 4 GB tablet, and
//!   opencode startup has hung before (the `reference_opencode_permissions` memory).
//!   A read-only sqlite query does none of that.
//! - A member's subagents run in **child sessions** (`session_v2.parent_id`) whose
//!   cost is not rolled into the root. Here that is one recursive query; over the
//!   API it is a walk of `session.children` calls.
//! - `rusqlite` is already in the workspace (softfig-store), with the same features.
//!
//! The coupling is contained here. A schema drift, a missing file or a locked
//! database is an `Err`: the member keeps the streamed lower bound and the daemon
//! logs why. Nothing fails a member over its accounting.
//!
//! ## Finality
//!
//! opencode is event-sourced (`event`, `event_sequence`). The session row is a
//! projection: the final step's `cost`/`tokens_*` land when the step ends, and
//! `time_idle` + `idle_outcome` land when the execution ends, after it. The
//! client's stdout EOF can race that projection, so [`OpencodeDb`] polls briefly
//! until the root session reads idle. A read that never sees idle is still
//! returned, marked unsettled.
//!
//! Read-only, always: the connection opens `SQLITE_OPEN_READ_ONLY`, so growlightd
//! can never write, migrate or checkpoint the human's opencode store.

use std::fmt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension};

/// The database file inside opencode's data dir
/// (`softfig_ipc::opencode::opencode_data_dir`).
const DB_FILE: &str = "opencode.db";

/// How long one read waits on opencode's write lock. WAL readers don't block
/// writers, so this only matters during a checkpoint.
const BUSY_TIMEOUT: Duration = Duration::from_millis(500);

/// Gap between finality polls, and how many polls before giving up on `idle`.
/// 20 × 100 ms bounds the wait at about 2 s, which the reader thread spends
/// before it records the exit. In the captured runs `time_idle` landed 0–20 ms
/// after the last streamed line.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const POLL_ATTEMPTS: u32 = 20;

/// One member session's totals as opencode recorded them, summed over the root
/// session and every descendant (subagent) session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SessionTotals {
    /// USD across the session tree.
    pub cost_usd: f64,
    /// `input + output + reasoning + cache.read + cache.write` across the tree,
    /// the same sum the stream's per-step tokens use.
    pub tokens: u64,
    /// The root session had gone idle when read, so these totals include the final
    /// step. `false`: the poll deadline passed first, and the totals may still miss
    /// it.
    pub settled: bool,
}

/// Why a session's totals could not be read. Never fatal to a member: the caller
/// keeps the streamed lower bound.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The database could not be opened (missing file, permissions).
    #[error("could not open {}: {source}", .path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    /// The query failed: a locked database, or a schema that drifted from the
    /// `session_v2` shape this module pins.
    #[error("could not read session {session} from {}: {source}", .path.display())]
    Query {
        path: PathBuf,
        session: String,
        #[source]
        source: rusqlite::Error,
    },
    /// The database has no row for the session.
    #[error("no session {session} in {}", .path.display())]
    NoSession { path: PathBuf, session: String },
}

/// Where a member's end-of-run totals are read from. A seam so the backend's
/// tests settle against scripted totals and never touch a real opencode store.
pub trait SessionLedger: fmt::Debug + Send + Sync {
    /// The totals for `session_id` and its descendants.
    fn totals(&self, session_id: &str) -> Result<SessionTotals, LedgerError>;
}

/// The production [`SessionLedger`]: a read-only query of opencode's sqlite store.
#[derive(Debug, Clone)]
pub struct OpencodeDb {
    path: PathBuf,
    poll_interval: Duration,
    poll_attempts: u32,
}

impl OpencodeDb {
    /// The store inside opencode's data dir.
    pub fn in_data_dir(data_dir: &Path) -> Self {
        Self::at(data_dir.join(DB_FILE))
    }

    /// The store at `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            poll_interval: POLL_INTERVAL,
            poll_attempts: POLL_ATTEMPTS,
        }
    }

    /// Override the finality poll, so a test of an unsettled session is instant.
    #[cfg(test)]
    fn with_poll(mut self, interval: Duration, attempts: u32) -> Self {
        self.poll_interval = interval;
        self.poll_attempts = attempts;
        self
    }

    fn open(&self) -> Result<Connection, LedgerError> {
        let open_err = |source| LedgerError::Open {
            path: self.path.clone(),
            source,
        };
        // No SQLITE_OPEN_CREATE: a missing store is an error, never a new file.
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(open_err)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(open_err)?;
        Ok(conn)
    }

    /// One read: whether the root session is idle, and the tree's totals. `None`
    /// when the root row does not exist.
    fn read_once(
        &self,
        conn: &Connection,
        session_id: &str,
    ) -> Result<Option<(bool, f64, u64)>, LedgerError> {
        conn.query_row(
            "WITH RECURSIVE tree(id) AS (
                 SELECT id FROM session_v2 WHERE id = ?1
                 UNION
                 SELECT s.id FROM session_v2 s JOIN tree t ON s.parent_id = t.id
             )
             SELECT
                 (SELECT time_idle IS NOT NULL FROM session_v2 WHERE id = ?1),
                 TOTAL(cost),
                 TOTAL(tokens_input + tokens_output + tokens_reasoning
                       + tokens_cache_read + tokens_cache_write)
             FROM session_v2 WHERE id IN tree",
            [session_id],
            |row| {
                let idle: Option<bool> = row.get(0)?;
                let cost: f64 = row.get(1)?;
                let tokens: f64 = row.get(2)?;
                Ok(idle.map(|idle| (idle, cost, tokens.max(0.0) as u64)))
            },
        )
        .optional()
        .map(Option::flatten)
        .map_err(|source| LedgerError::Query {
            path: self.path.clone(),
            session: session_id.to_string(),
            source,
        })
    }
}

impl SessionLedger for OpencodeDb {
    fn totals(&self, session_id: &str) -> Result<SessionTotals, LedgerError> {
        let conn = self.open()?;
        let mut attempt = 0;
        loop {
            let Some((idle, cost_usd, tokens)) = self.read_once(&conn, session_id)? else {
                return Err(LedgerError::NoSession {
                    path: self.path.clone(),
                    session: session_id.to_string(),
                });
            };
            attempt += 1;
            if idle || attempt >= self.poll_attempts {
                return Ok(SessionTotals {
                    cost_usd,
                    tokens,
                    settled: idle,
                });
            }
            thread::sleep(self.poll_interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `session_v2` columns this module reads, as opencode 2.0.24 declares them
    /// (the rest of the table is irrelevant to the query).
    const SCHEMA: &str = "CREATE TABLE session_v2 (
        id text PRIMARY KEY,
        parent_id text,
        cost real DEFAULT 0 NOT NULL,
        tokens_input integer DEFAULT 0 NOT NULL,
        tokens_output integer DEFAULT 0 NOT NULL,
        tokens_reasoning integer DEFAULT 0 NOT NULL,
        tokens_cache_read integer DEFAULT 0 NOT NULL,
        tokens_cache_write integer DEFAULT 0 NOT NULL,
        time_idle integer
    );";

    /// A store holding the slice 001 text run's real row, `ses_edb4e6137…`.
    fn store(dir: &Path) -> (PathBuf, Connection) {
        let path = dir.join(DB_FILE);
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "wal").unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO session_v2 VALUES ('root', NULL, 0.000118278, 141, 2, 133, 5376, 0, 1791616986217)",
            [],
        )
        .unwrap();
        (path, conn)
    }

    #[test]
    fn an_idle_session_reads_settled_with_its_recorded_totals() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _writer) = store(tmp.path());

        let totals = OpencodeDb::at(&path).totals("root").unwrap();
        assert!(totals.settled);
        assert_eq!(totals.tokens, 141 + 2 + 133 + 5376);
        assert!((totals.cost_usd - 0.000118278).abs() < 1e-12);
    }

    #[test]
    fn subagent_sessions_are_summed_into_the_member_and_strangers_are_not() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, writer) = store(tmp.path());
        // A subagent, a grandchild under it, and an unrelated session (the human's
        // own, in the same shared store).
        writer
            .execute_batch(
                "INSERT INTO session_v2 VALUES ('child', 'root', 0.25, 10, 0, 0, 0, 0, 1);
                 INSERT INTO session_v2 VALUES ('grandchild', 'child', 0.5, 0, 20, 0, 0, 5, 1);
                 INSERT INTO session_v2 VALUES ('human', NULL, 99.0, 9999, 0, 0, 0, 0, 1);",
            )
            .unwrap();

        let totals = OpencodeDb::at(&path).totals("root").unwrap();
        assert!((totals.cost_usd - (0.000118278 + 0.25 + 0.5)).abs() < 1e-12);
        assert_eq!(totals.tokens, (141 + 2 + 133 + 5376) + 10 + (20 + 5));
    }

    #[test]
    fn a_session_still_running_is_returned_unsettled_after_the_poll() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, writer) = store(tmp.path());
        writer
            .execute("UPDATE session_v2 SET time_idle = NULL WHERE id = 'root'", [])
            .unwrap();

        let totals = OpencodeDb::at(&path)
            .with_poll(Duration::ZERO, 3)
            .totals("root")
            .unwrap();
        assert!(!totals.settled, "never went idle inside the poll");
        assert_eq!(totals.tokens, 141 + 2 + 133 + 5376, "still the best reading");
    }

    #[test]
    fn an_unknown_session_a_missing_store_and_a_drifted_schema_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, writer) = store(tmp.path());

        assert!(matches!(
            OpencodeDb::at(&path).totals("ses_nope"),
            Err(LedgerError::NoSession { .. })
        ));

        // A missing store is never created: the open is read-only.
        let missing = tmp.path().join("absent/opencode.db");
        assert!(matches!(
            OpencodeDb::at(&missing).totals("root"),
            Err(LedgerError::Open { .. })
        ));
        assert!(!missing.exists());

        // opencode renames a column it reads → a Query error, not a panic or a zero.
        writer
            .execute_batch("ALTER TABLE session_v2 RENAME COLUMN tokens_reasoning TO tokens_think;")
            .unwrap();
        assert!(matches!(
            OpencodeDb::at(&path).totals("root"),
            Err(LedgerError::Query { .. })
        ));
    }
}
