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
use crate::error::Result;
use crate::log::JobLogs;
use crate::state::StateRoot;

/// A live or recently-finished job. Held in the table for attach/cancel and
/// removed after the TTL.
pub struct Job {
    pub job_id: Vec<u8>,
    /// The submitting requester (attach/cancel are restricted to it).
    pub requester_device: [u8; 32],
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

/// The shared job registry (spec §6 detach/attach/cancel).
pub struct JobTable {
    inner: Mutex<HashMap<Vec<u8>, Arc<Job>>>,
}

impl JobTable {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub fn insert(&self, job: Arc<Job>) {
        self.inner.lock().unwrap().insert(job.job_id.clone(), job);
    }

    pub fn get(&self, job_id: &[u8]) -> Option<Arc<Job>> {
        self.inner.lock().unwrap().get(job_id).cloned()
    }

    pub fn remove(&self, job_id: &[u8]) -> Option<Arc<Job>> {
        self.inner.lock().unwrap().remove(job_id)
    }

    /// Remove every finished job whose `finished_at` is at least `ttl_secs`
    /// ago, returning their ids (the caller removes their scratch dirs).
    pub fn sweep(&self, ttl_secs: i64) -> Vec<Vec<u8>> {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        let expired: Vec<Vec<u8>> = inner
            .iter()
            .filter(|(_, job)| {
                job.finished_at
                    .lock()
                    .unwrap()
                    .map(|f| now - f >= ttl_secs)
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            inner.remove(id);
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

    #[test]
    fn sweep_removes_only_expired_finished_jobs() {
        let table = JobTable::new();
        let finished = Arc::new(Job {
            job_id: vec![1u8; 16],
            requester_device: [0u8; 32],
            unit: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            logs: JobLogs::new(),
            started_at: 0,
            finished_at: Mutex::new(Some(now_unix() - 1000)),
            result: Mutex::new(None),
        });
        let running = Arc::new(Job {
            job_id: vec![2u8; 16],
            requester_device: [0u8; 32],
            unit: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            logs: JobLogs::new(),
            started_at: now_unix(),
            finished_at: Mutex::new(None),
            result: Mutex::new(None),
        });
        table.insert(finished);
        table.insert(running);

        let expired = table.sweep(60);
        assert_eq!(expired, vec![vec![1u8; 16]], "only the finished job expired");
        assert!(table.get(&[1u8; 16]).is_none());
        assert!(table.get(&[2u8; 16]).is_some());
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
