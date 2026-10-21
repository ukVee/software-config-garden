//! The runner's in-memory job table + the durable `jobs.ndjson` run log
//! (spec remote-runner §6 step 9).
//!
//! The table holds each live or recently-finished job for attach/cancel and is
//! swept after the TTL (default 24 h). The durable `jobs.ndjson` is the system
//! of record for every job the runner has ever executed: one JSON row per
//! terminal job, append-only, mode 0600.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::attestation::{ExitInfo, ToolchainInfo};
use crate::error::{Error, Result};
use crate::log::JobLogs;
use crate::state::StateRoot;

/// `job_id` is a random 128-bit value (spec §6 step 1).
pub const JOB_ID_LEN: usize = 16;

/// A job's name on this runner: the authenticated requester device id plus its
/// `job_id` (pre-merge review m2). The table, the scratch dir and attach/cancel
/// all go through it, so two requesters can't collide on an id and one can't
/// reach another's job. [`JobKey::new`] is the only constructor and refuses an
/// id that isn't exactly [`JOB_ID_LEN`] bytes, so no key can name `jobs/` or a
/// requester's whole subtree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobKey {
    device_id: [u8; 32],
    job_id: [u8; JOB_ID_LEN],
}

impl JobKey {
    pub fn new(device_id: [u8; 32], job_id: &[u8]) -> Result<Self> {
        let job_id = job_id.try_into().map_err(|_| {
            Error::Protocol(format!(
                "job_id is {} bytes; a job id is exactly {JOB_ID_LEN}",
                job_id.len()
            ))
        })?;
        Ok(Self { device_id, job_id })
    }

    pub fn device_id(&self) -> [u8; 32] {
        self.device_id
    }

    pub fn job_id(&self) -> &[u8] {
        &self.job_id
    }

    /// The job's scratch dir: `jobs/<devicehex>/<jobhex>`.
    pub fn scratch_dir(&self, root: &StateRoot) -> std::path::PathBuf {
        root.jobs_dir().join(hex::encode(self.device_id)).join(hex::encode(self.job_id))
    }
}

/// A live or recently-finished job. Held in the table for attach/cancel and
/// removed after the TTL.
pub struct Job {
    /// The submitting requester + its job id; attach/cancel find the job only
    /// under the same requester.
    pub key: JobKey,
    /// The transient unit name, once launched (unit mode only).
    pub unit: Mutex<Option<String>>,
    /// Set by `JobCancel`; checked by the run loop and the attestation.
    pub cancelled: AtomicBool,
    /// The shared log ring + hash + subscribers.
    pub logs: JobLogs,
    pub started_at: i64,
    pub finished_at: Mutex<Option<i64>>,
    /// The signed `JobResult`, stored on completion for attach.
    pub result: Mutex<Option<softfig_net::proto::JobResult>>,
}

impl Job {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// The shared job registry (spec §6 detach/attach/cancel), keyed by [`JobKey`].
pub struct JobTable {
    inner: Mutex<HashMap<JobKey, Arc<Job>>>,
}

impl JobTable {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub fn insert(&self, job: Arc<Job>) {
        self.inner.lock().unwrap().insert(job.key, job);
    }

    pub fn get(&self, key: &JobKey) -> Option<Arc<Job>> {
        self.inner.lock().unwrap().get(key).cloned()
    }

    pub fn remove(&self, key: &JobKey) -> Option<Arc<Job>> {
        self.inner.lock().unwrap().remove(key)
    }

    /// Remove every finished job whose `finished_at` is at least `ttl_secs`
    /// ago, returning their keys (the caller removes their scratch dirs).
    pub fn sweep(&self, ttl_secs: i64) -> Vec<JobKey> {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        let expired: Vec<JobKey> = inner
            .iter()
            .filter(|(_, job)| {
                job.finished_at
                    .lock()
                    .unwrap()
                    .map(|f| now - f >= ttl_secs)
                    .unwrap_or(false)
            })
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            inner.remove(key);
        }
        expired
    }
}

impl Default for JobTable {
    fn default() -> Self {
        Self::new()
    }
}

/// One durable `jobs.ndjson` row (spec §6 step 9). `exit` and `toolchain` reuse
/// the attestation's typed shapes; `source_id` is the tree root, `snapshot_commit`
/// the commit it was built from.
#[derive(Debug, Serialize)]
pub struct JobRecord {
    pub job_id: String,
    pub requester_device: String,
    pub repo_key: String,
    pub source_id: String,
    pub snapshot_commit: String,
    pub profile: String,
    pub cmd: Vec<String>,
    pub env_names: Vec<String>,
    pub toolchain: ToolchainInfo,
    pub caps_hit: Option<String>,
    pub cache_mode: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub exit: ExitInfo,
    pub log_blake3: String,
    pub attestation_hash: String,
    pub where_route: String,
}

/// Append one row to `log/jobs.ndjson` (owner `softfig-runner`, mode 0600).
pub fn append_ndjson(root: &StateRoot, record: &JobRecord) -> Result<()> {
    let dir = root.log_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("jobs.ndjson");
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    let mut line = serde_json::to_string(record)?;
    line.push('\n');
    f.write_all(line.as_bytes())?;
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(key: JobKey, finished_at: Option<i64>) -> Arc<Job> {
        Arc::new(Job {
            key,
            unit: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            logs: JobLogs::new(),
            started_at: 0,
            finished_at: Mutex::new(finished_at),
            result: Mutex::new(None),
        })
    }

    fn key(device: u8, job: u8) -> JobKey {
        JobKey::new([device; 32], &[job; JOB_ID_LEN]).unwrap()
    }

    #[test]
    fn sweep_removes_only_expired_finished_jobs() {
        let table = JobTable::new();
        table.insert(job(key(0, 1), Some(now_unix() - 1000)));
        table.insert(job(key(0, 2), None));

        let expired = table.sweep(60);
        assert_eq!(expired, vec![key(0, 1)], "only the finished job expired");
        assert!(table.get(&key(0, 1)).is_none());
        assert!(table.get(&key(0, 2)).is_some());
    }

    #[test]
    fn job_key_refuses_an_id_that_is_not_16_bytes() {
        // m2: an empty id made the scratch dir `jobs/` itself.
        for len in [0, 1, 15, 17, 32] {
            let err = JobKey::new([0xAA; 32], &vec![0u8; len]).unwrap_err().to_string();
            assert!(err.contains(&format!("job_id is {len} bytes")), "{err}");
        }
        assert!(JobKey::new([0xAA; 32], &[0u8; 16]).is_ok());
    }

    #[test]
    fn scratch_dir_is_always_two_levels_under_jobs() {
        // m2: cleanup and the TTL sweep remove this dir, so it must never be
        // `jobs/` or a requester's whole `jobs/<device>/` subtree.
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
        let k = key(0xAA, 0x01);
        assert_eq!(
            k.scratch_dir(&root),
            root.jobs_dir().join("aa".repeat(32)).join("01".repeat(16))
        );
    }

    #[test]
    fn job_table_keys_by_requester_and_job_id() {
        let table = JobTable::new();
        table.insert(job(key(0xAA, 1), None));
        table.insert(job(key(0xBB, 1), None)); // same job_id, another requester

        assert!(table.get(&key(0xAA, 1)).is_some());
        assert!(table.get(&key(0xBB, 1)).is_some());
        assert!(table.remove(&key(0xAA, 1)).is_some());
        assert!(table.get(&key(0xAA, 1)).is_none());
        assert!(table.get(&key(0xBB, 1)).is_some(), "removing one requester's job keeps the other's");
    }

    #[test]
    fn ndjson_appends_one_line_per_row() {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
        root.ensure_dirs().unwrap();
        let record = JobRecord {
            job_id: "ab".repeat(16),
            requester_device: "cd".repeat(32),
            repo_key: "ef".repeat(32),
            source_id: "11".repeat(20),
            snapshot_commit: "22".repeat(20),
            profile: "gate".into(),
            cmd: vec!["cargo".into(), "test".into()],
            env_names: vec!["A".into()],
            toolchain: ToolchainInfo::default(),
            caps_hit: None,
            cache_mode: "shared".into(),
            started_at: 1,
            finished_at: 2,
            exit: ExitInfo::code(0),
            log_blake3: "33".repeat(32),
            attestation_hash: "44".repeat(32),
            where_route: "lan".into(),
        };
        append_ndjson(&root, &record).unwrap();
        append_ndjson(&root, &record).unwrap();
        let text = std::fs::read_to_string(root.log_dir().join("jobs.ndjson")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["attestation_hash"], "44".repeat(32));
    }
}
