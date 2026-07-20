//! Sqlite-backed metadata: refs, commits, trees, tree entries.
//!
//! Schema lives in `SCHEMA_V1` and is applied at create time. Future
//! migrations will append to a `MIGRATIONS` table; v1 ships only the
//! genesis schema and bumps `PRAGMA user_version` to `1`.

use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{Result, StoreError};
use crate::hash::{Hash, HASH_LEN};
use crate::paths::StorePaths;

pub const SCHEMA_VERSION: u32 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE refs (
  name        TEXT PRIMARY KEY,
  commit_hash BLOB NOT NULL
);

CREATE TABLE commits (
  hash          BLOB PRIMARY KEY,
  parent        BLOB,
  root_tree     BLOB NOT NULL,
  author_device TEXT NOT NULL,
  author_pubkey BLOB NOT NULL,
  timestamp     INTEGER NOT NULL,
  intent        TEXT NOT NULL,
  payload       TEXT NOT NULL,
  master_key_id INTEGER NOT NULL,
  signature     BLOB NOT NULL,
  FOREIGN KEY (parent) REFERENCES commits(hash)
);
CREATE INDEX idx_commits_timestamp ON commits(timestamp);
CREATE INDEX idx_commits_intent    ON commits(intent);

CREATE TABLE trees (
  hash BLOB PRIMARY KEY
);

CREATE TABLE tree_entries (
  tree_hash   BLOB NOT NULL,
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  mode        INTEGER NOT NULL,
  target_hash BLOB NOT NULL,
  PRIMARY KEY (tree_hash, name),
  FOREIGN KEY (tree_hash) REFERENCES trees(hash)
);
CREATE INDEX idx_tree_entries_target ON tree_entries(target_hash);
"#;

/// Whether a tree entry points at a blob (file content) or another tree
/// (subdirectory). Stored as a string in sqlite for queryability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeEntryKind {
    Blob,
    Tree,
}

impl TreeEntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "blob" => Some(Self::Blob),
            "tree" => Some(Self::Tree),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TreeEntryRow {
    pub name: String,
    pub kind: TreeEntryKind,
    pub mode: u32,
    pub target: Hash,
}

#[derive(Debug, Clone)]
pub struct CommitRow {
    pub hash: Hash,
    pub parent: Option<Hash>,
    pub root_tree: Hash,
    pub author_device: String,
    pub author_pubkey: [u8; 32],
    pub timestamp: i64,
    pub intent: String,
    /// Canonical JCS bytes (utf-8) of the payload object.
    pub payload: String,
    pub master_key_id: u32,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct RefRow {
    pub name: String,
    pub commit_hash: Hash,
}

#[derive(Debug)]
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open an existing DB. Errors if the file isn't there or its
    /// `user_version` doesn't match this build.
    pub fn open(paths: &StorePaths) -> Result<Self> {
        let path = paths.db_path();
        if !path.exists() {
            return Err(StoreError::NotInitialized(paths.softfig_dir()));
        }
        let conn = Connection::open(&path)?;
        let v: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if v != SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema(v));
        }
        configure(&conn)?;
        Ok(Self { conn })
    }

    /// Create a fresh DB at `<paths>/db.sqlite`. Errors if the file
    /// already exists.
    pub fn create(paths: &StorePaths, repo_id: &str, created_at_unix: i64) -> Result<Self> {
        let path = paths.db_path();
        if path.exists() {
            return Err(StoreError::AlreadyInitialized(paths.softfig_dir()));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&path)?;
        configure(&conn)?;
        conn.execute_batch(SCHEMA_V1)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let mut db = Self { conn };
        db.meta_put("format_version", &SCHEMA_VERSION.to_string())?;
        db.meta_put("repo_id", repo_id)?;
        db.meta_put("created_at_unix", &created_at_unix.to_string())?;
        Ok(db)
    }

    pub fn path(&self) -> &Path {
        let p = self.conn.path().expect("DB opened from a real path");
        Path::new(p)
    }

    /// Run `f` inside a sqlite transaction, committing on Ok.
    pub fn with_tx<R>(&mut self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        let tx = self.conn.transaction()?;
        let r = f(&tx)?;
        tx.commit()?;
        Ok(r)
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        let v = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(v)
    }

    pub fn meta_put(&mut self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn try_get_ref(&self, name: &str) -> Result<Option<Hash>> {
        let v = self
            .conn
            .query_row(
                "SELECT commit_hash FROM refs WHERE name = ?1",
                params![name],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        match v {
            Some(bytes) => Ok(Some(hash_from_blob(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn get_ref(&self, name: &str) -> Result<Hash> {
        self.try_get_ref(name)?
            .ok_or_else(|| StoreError::RefNotSet(name.to_string()))
    }

    pub fn list_refs(&self) -> Result<Vec<RefRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, commit_hash FROM refs ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (name, blob) = row?;
            out.push(RefRow {
                name,
                commit_hash: hash_from_blob(&blob)?,
            });
        }
        Ok(out)
    }

    pub fn commit_exists(&self, hash: &Hash) -> Result<bool> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM commits WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    pub fn get_commit(&self, hash: &Hash) -> Result<CommitRow> {
        self.conn
            .query_row(
                "SELECT hash, parent, root_tree, author_device, author_pubkey,
                        timestamp, intent, payload, master_key_id, signature
                 FROM commits WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                row_to_commit,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StoreError::CommitNotFound(*hash),
                other => StoreError::Sqlite(other),
            })
    }

    pub fn list_commits(&self) -> Result<Vec<CommitRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, parent, root_tree, author_device, author_pubkey,
                    timestamp, intent, payload, master_key_id, signature
             FROM commits",
        )?;
        let rows = stmt.query_map([], row_to_commit)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn tree_exists(&self, hash: &Hash) -> Result<bool> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM trees WHERE hash = ?1",
                params![hash.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    pub fn get_tree(&self, hash: &Hash) -> Result<Vec<TreeEntryRow>> {
        if !self.tree_exists(hash)? {
            return Err(StoreError::TreeNotFound(*hash));
        }
        let mut stmt = self.conn.prepare(
            "SELECT name, kind, mode, target_hash
             FROM tree_entries WHERE tree_hash = ?1
             ORDER BY name",
        )?;
        let rows = stmt.query_map(params![hash.as_bytes().as_slice()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (name, kind_str, mode, target_blob) = row?;
            let kind = TreeEntryKind::parse(&kind_str).ok_or_else(|| {
                StoreError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("bad tree_entries.kind = {kind_str:?}"),
                    )),
                ))
            })?;
            entries.push(TreeEntryRow {
                name,
                kind,
                mode: mode as u32,
                target: hash_from_blob(&target_blob)?,
            });
        }
        Ok(entries)
    }

    pub fn list_tree_hashes(&self) -> Result<Vec<Hash>> {
        let mut stmt = self.conn.prepare("SELECT hash FROM trees")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(hash_from_blob(&r?)?);
        }
        Ok(out)
    }
}

// ---- helpers usable inside or outside a transaction ----

pub fn put_tree(
    conn: &Connection,
    hash: &Hash,
    entries: &[TreeEntryRow],
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO trees(hash) VALUES(?1)",
        params![hash.as_bytes().as_slice()],
    )?;
    let mut stmt = conn.prepare(
        "INSERT OR REPLACE INTO tree_entries(tree_hash, name, kind, mode, target_hash)
         VALUES(?1, ?2, ?3, ?4, ?5)",
    )?;
    for e in entries {
        stmt.execute(params![
            hash.as_bytes().as_slice(),
            e.name,
            e.kind.as_str(),
            e.mode as i64,
            e.target.as_bytes().as_slice(),
        ])?;
    }
    Ok(())
}

pub fn put_commit(conn: &Connection, c: &CommitRow) -> Result<()> {
    conn.execute(
        "INSERT INTO commits(hash, parent, root_tree, author_device, author_pubkey,
                             timestamp, intent, payload, master_key_id, signature)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            c.hash.as_bytes().as_slice(),
            c.parent.map(|h| h.as_bytes().to_vec()),
            c.root_tree.as_bytes().as_slice(),
            c.author_device,
            c.author_pubkey.as_slice(),
            c.timestamp,
            c.intent,
            c.payload,
            c.master_key_id as i64,
            c.signature.as_slice(),
        ],
    )?;
    Ok(())
}

pub fn set_ref(conn: &Connection, name: &str, hash: &Hash) -> Result<()> {
    conn.execute(
        "INSERT INTO refs(name, commit_hash) VALUES(?1, ?2)
         ON CONFLICT(name) DO UPDATE SET commit_hash = excluded.commit_hash",
        params![name, hash.as_bytes().as_slice()],
    )?;
    Ok(())
}

/// Compare-and-swap advance of `name` to `hash`: the write lands only if the
/// currently-stored tip equals `expected`. `expected == None` requires the ref
/// to not yet exist (the first commit on a chain). On a mismatch — a concurrent
/// writer created or advanced the ref since the caller read `expected` — nothing
/// is written and [`StoreError::RefCasMismatch`] is returned, so the enclosing
/// transaction rolls back the whole commit instead of clobbering the winner.
///
/// This is the write-path guard against a lost update when two writers race the
/// same ref (m5e slice 001). The single-writer device chain (`TIP_REF`) passes
/// its just-read tip as `expected`, so the CAS always succeeds and the advance
/// is identical to [`set_ref`]; it only ever fires under genuine contention on a
/// shared chain.
pub fn set_ref_cas(
    conn: &Connection,
    name: &str,
    expected: Option<&Hash>,
    hash: &Hash,
) -> Result<()> {
    let changed = match expected {
        // Advance an existing ref only while it still points at `prior`.
        Some(prior) => conn.execute(
            "UPDATE refs SET commit_hash = ?3 WHERE name = ?1 AND commit_hash = ?2",
            params![
                name,
                prior.as_bytes().as_slice(),
                hash.as_bytes().as_slice()
            ],
        )?,
        // First commit on this chain: insert only while the ref is absent.
        None => conn.execute(
            "INSERT INTO refs(name, commit_hash) SELECT ?1, ?2
             WHERE NOT EXISTS(SELECT 1 FROM refs WHERE name = ?1)",
            params![name, hash.as_bytes().as_slice()],
        )?,
    };
    if changed == 0 {
        // Report the tip we lost the race to (absent -> None) for diagnostics.
        let actual = conn
            .query_row(
                "SELECT commit_hash FROM refs WHERE name = ?1",
                params![name],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|b| hash_from_blob(&b))
            .transpose()?;
        return Err(StoreError::RefCasMismatch {
            name: name.to_string(),
            expected: expected.copied(),
            actual,
        });
    }
    Ok(())
}

// ---- internal ----

fn configure(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    // WAL already lets many readers run beside one writer, but two *writers* on
    // separate handles to the same file (e.g. the daemon's `Repo` and a
    // shared-chain `SharedChainSink` landing a pulled subtree) would otherwise
    // race straight to `SQLITE_BUSY`. A busy-timeout makes the loser wait for
    // the in-flight write transaction to commit instead of erroring — writes
    // still serialize (WAL guarantees that), they just queue rather than fail.
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(())
}

fn hash_from_blob(b: &[u8]) -> Result<Hash> {
    if b.len() != HASH_LEN {
        return Err(StoreError::BadHashHex(format!(
            "blob length {} != {HASH_LEN}",
            b.len()
        )));
    }
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(b);
    Ok(Hash::from_bytes(out))
}

fn row_to_commit(r: &rusqlite::Row<'_>) -> rusqlite::Result<CommitRow> {
    let hash_b: Vec<u8> = r.get(0)?;
    let parent_b: Option<Vec<u8>> = r.get(1)?;
    let root_tree_b: Vec<u8> = r.get(2)?;
    let author_device: String = r.get(3)?;
    let author_pubkey_b: Vec<u8> = r.get(4)?;
    let timestamp: i64 = r.get(5)?;
    let intent: String = r.get(6)?;
    let payload: String = r.get(7)?;
    let master_key_id: i64 = r.get(8)?;
    let signature_b: Vec<u8> = r.get(9)?;

    fn to_hash(label: &str, bytes: &[u8]) -> rusqlite::Result<Hash> {
        if bytes.len() != HASH_LEN {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{label}: expected {HASH_LEN} bytes, got {}", bytes.len()),
                )),
            ));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Hash::from_bytes(out))
    }

    let parent = match parent_b {
        Some(b) => Some(to_hash("parent", &b)?),
        None => None,
    };

    let mut author_pubkey = [0u8; 32];
    if author_pubkey_b.len() != 32 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "author_pubkey not 32 bytes",
            )),
        ));
    }
    author_pubkey.copy_from_slice(&author_pubkey_b);

    let mut signature = [0u8; 64];
    if signature_b.len() != 64 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "signature not 64 bytes",
            )),
        ));
    }
    signature.copy_from_slice(&signature_b);

    Ok(CommitRow {
        hash: to_hash("hash", &hash_b)?,
        parent,
        root_tree: to_hash("root_tree", &root_tree_b)?,
        author_device,
        author_pubkey,
        timestamp,
        intent,
        payload,
        master_key_id: master_key_id as u32,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REF: &str = "chain-x";

    fn scratch_db(dir: &Path) -> Db {
        let paths = StorePaths::for_garden(dir);
        Db::create(&paths, "test-repo", 0).expect("create scratch db")
    }

    fn h(seed: &[u8]) -> Hash {
        Hash::of(seed)
    }

    #[test]
    fn cas_creates_ref_only_while_absent() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = scratch_db(dir.path());
        let c1 = h(b"c1");

        // expected == None inserts the first tip.
        db.with_tx(|conn| set_ref_cas(conn, REF, None, &c1)).unwrap();
        assert_eq!(db.try_get_ref(REF).unwrap(), Some(c1));

        // A second create against a now-present ref is a lost race, not a clobber.
        let c2 = h(b"c2");
        let err = db
            .with_tx(|conn| set_ref_cas(conn, REF, None, &c2))
            .unwrap_err();
        match err {
            StoreError::RefCasMismatch { name, expected, actual } => {
                assert_eq!(name, REF);
                assert_eq!(expected, None);
                assert_eq!(actual, Some(c1));
            }
            other => panic!("expected RefCasMismatch, got {other:?}"),
        }
        // The winner's tip is untouched.
        assert_eq!(db.try_get_ref(REF).unwrap(), Some(c1));
    }

    #[test]
    fn cas_advances_only_when_tip_matches() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = scratch_db(dir.path());
        let (c1, c2, c3) = (h(b"c1"), h(b"c2"), h(b"c3"));

        db.with_tx(|conn| set_ref_cas(conn, REF, None, &c1)).unwrap();
        // Expected tip matches -> advance lands.
        db.with_tx(|conn| set_ref_cas(conn, REF, Some(&c1), &c2))
            .unwrap();
        assert_eq!(db.try_get_ref(REF).unwrap(), Some(c2));

        // A writer that still expects the old tip loses the race.
        let err = db
            .with_tx(|conn| set_ref_cas(conn, REF, Some(&c1), &c3))
            .unwrap_err();
        match err {
            StoreError::RefCasMismatch { expected, actual, .. } => {
                assert_eq!(expected, Some(c1));
                assert_eq!(actual, Some(c2));
            }
            other => panic!("expected RefCasMismatch, got {other:?}"),
        }
        assert_eq!(db.try_get_ref(REF).unwrap(), Some(c2));
    }

    #[test]
    fn cas_advance_against_absent_ref_is_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = scratch_db(dir.path());
        let c1 = h(b"c1");

        // Expecting a prior tip on a ref that never existed reports actual: None.
        let err = db
            .with_tx(|conn| set_ref_cas(conn, REF, Some(&c1), &h(b"c2")))
            .unwrap_err();
        match err {
            StoreError::RefCasMismatch { expected, actual, .. } => {
                assert_eq!(expected, Some(c1));
                assert_eq!(actual, None);
            }
            other => panic!("expected RefCasMismatch, got {other:?}"),
        }
        assert_eq!(db.try_get_ref(REF).unwrap(), None);
    }

    #[test]
    fn cas_matches_plain_set_ref_when_uncontended() {
        // The device-chain path: parent == stored tip every advance, so CAS is
        // byte-for-byte the same end state as a plain `set_ref` chain.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let mut cas = scratch_db(dir_a.path());
        let mut plain = scratch_db(dir_b.path());
        let (c1, c2) = (h(b"tip1"), h(b"tip2"));

        cas.with_tx(|conn| set_ref_cas(conn, REF, None, &c1)).unwrap();
        cas.with_tx(|conn| set_ref_cas(conn, REF, Some(&c1), &c2))
            .unwrap();
        plain.with_tx(|conn| set_ref(conn, REF, &c1)).unwrap();
        plain.with_tx(|conn| set_ref(conn, REF, &c2)).unwrap();

        assert_eq!(cas.try_get_ref(REF).unwrap(), plain.try_get_ref(REF).unwrap());
        assert_eq!(cas.try_get_ref(REF).unwrap(), Some(c2));
    }
}
