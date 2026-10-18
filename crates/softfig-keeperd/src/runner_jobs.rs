//! keeperd's requester-side job table (spec remote-runner §6, §8).
//!
//! The requester keeps the last N jobs **in memory** to spare the tablet's
//! eMMC (the "prefer in-memory" constraint) — no disk by default. Each row
//! holds a bounded per-job log ring (default 4 MiB); `--log-file` on the CLI
//! writes a file only where the caller asks. The runner's own durable
//! `jobs.ndjson` (slice 006) remains the system of record for what the runner
//! has ever executed; this table is the requester's session-scoped view that
//! backs `softfig run ls|show|logs` and (later) `--detach`/`attach`/`cancel`.
//!
//! In-memory by design, like [`crate::daemon::DaemonInner::holders`]: a
//! `daemon cycle` resets it to empty.

use std::collections::VecDeque;

use softfig_ipc::verbs::{RunnerJobLsReply, RunnerJobLogReply, RunnerJobShowReply, RunnerJobSummary};

/// The default bound on the job table (last N jobs). A config knob can lift
/// this later; the spec only requires it be bounded.
pub const DEFAULT_MAX_JOBS: usize = 128;

/// The default bound on a single job's in-memory log ring (spec §6: ~4 MiB).
pub const LOG_RING_CAP: usize = 4 * 1024 * 1024;

/// The lifecycle-state label for a job still running (no terminal row yet).
pub const STATE_RUNNING: &str = "running";

/// A bounded byte ring for one job's log (stdout/stderr/system bytes in arrival
/// order). Drops the oldest bytes once `cap` is exceeded — never grows past it.
#[derive(Debug, Default, Clone)]
pub struct JobLogRing {
    bytes: Vec<u8>,
    cap: usize,
}

impl JobLogRing {
    pub fn new(cap: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(cap.min(1 << 20)),
            cap,
        }
    }

    /// Append bytes, evicting from the front once over `cap`.
    pub fn append(&mut self, chunk: &[u8]) {
        if self.bytes.len() + chunk.len() <= self.cap {
            self.bytes.extend_from_slice(chunk);
            return;
        }
        // Keep the tail: drop the oldest bytes so the new chunk fits.
        let keep = self.cap.saturating_sub(chunk.len().min(self.cap));
        if keep < self.bytes.len() {
            let start = self.bytes.len() - keep;
            self.bytes.drain(..start);
        }
        let tail = chunk.len().min(self.cap);
        self.bytes.extend_from_slice(&chunk[chunk.len() - tail..]);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// One job row in the requester-side table (spec §6 step 9's requester field
/// set, plus the `where` tag from §9). A row is inserted at start and completed
/// at finish; the log ring accumulates in between.
#[derive(Debug, Clone)]
pub struct RunnerJob {
    pub job_id: String,
    pub requester_device: String,
    pub repo_key: String,
    pub source_id: String,
    pub snapshot_commit: String,
    pub profile: String,
    pub cmd: Vec<String>,
    pub env_names: Vec<String>,
    pub toolchain: String,
    pub cache: String,
    pub where_: String,
    pub endpoint: String,
    pub runner_identity: String,
    pub cancelled: bool,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub exit: Option<i32>,
    pub attestation_hash: Option<String>,
    pub log: JobLogRing,
}

impl RunnerJob {
    /// The lifecycle state: `running` until a terminal row lands, then
    /// `done`/`failed` from the exit code.
    pub fn state(&self) -> &'static str {
        if self.cancelled {
            return "cancelled";
        }
        match self.exit {
            None => STATE_RUNNING,
            Some(0) => "done",
            Some(_) => "failed",
        }
    }

    pub fn to_summary(&self) -> RunnerJobSummary {
        RunnerJobSummary {
            job_id: self.job_id.clone(),
            started_at: self.started_at,
            finished_at: self.finished_at,
            exit: self.exit,
            where_: self.where_.clone(),
            profile: self.profile.clone(),
            cmd: self.cmd.clone(),
            state: self.state().to_string(),
        }
    }

    pub fn to_show(&self) -> RunnerJobShowReply {
        RunnerJobShowReply {
            job_id: self.job_id.clone(),
            requester_device: self.requester_device.clone(),
            repo_key: self.repo_key.clone(),
            source_id: self.source_id.clone(),
            snapshot_commit: self.snapshot_commit.clone(),
            profile: self.profile.clone(),
            cmd: self.cmd.clone(),
            env_names: self.env_names.clone(),
            toolchain: self.toolchain.clone(),
            cache: self.cache.clone(),
            started_at: self.started_at,
            finished_at: self.finished_at,
            exit: self.exit,
            attestation_hash: self.attestation_hash.clone(),
            where_: self.where_.clone(),
            state: self.state().to_string(),
            endpoint: self.endpoint.clone(),
            runner_identity: self.runner_identity.clone(),
            log_bytes: self.log.len(),
        }
    }

    pub fn to_log(&self) -> RunnerJobLogReply {
        use base64::Engine as _;
        RunnerJobLogReply {
            job_id: self.job_id.clone(),
            log_base64: base64::engine::general_purpose::STANDARD.encode(self.log.as_bytes()),
        }
    }
}

/// The bounded, in-memory job table (newest first).
#[derive(Debug, Default, Clone)]
pub struct RunnerJobTable {
    jobs: VecDeque<RunnerJob>,
    max_jobs: usize,
}

impl RunnerJobTable {
    pub fn new(max_jobs: usize) -> Self {
        Self {
            jobs: VecDeque::new(),
            max_jobs,
        }
    }

    /// Insert a row at the front, evicting the oldest beyond `max_jobs`.
    pub fn insert(&mut self, job: RunnerJob) {
        self.jobs.push_front(job);
        while self.jobs.len() > self.max_jobs {
            self.jobs.pop_back();
        }
    }

    /// Find a row by job id (exact or unique prefix).
    pub fn find(&self, job_id: &str) -> Option<&RunnerJob> {
        if job_id.len() >= 16 {
            return self.jobs.iter().find(|j| j.job_id == job_id);
        }
        self.jobs
            .iter()
            .find(|j| j.job_id.starts_with(job_id))
    }

    pub fn find_mut(&mut self, job_id: &str) -> Option<&mut RunnerJob> {
        if job_id.len() >= 16 {
            return self.jobs.iter_mut().find(|j| j.job_id == job_id);
        }
        self.jobs
            .iter_mut()
            .find(|j| j.job_id.starts_with(job_id))
    }

    pub fn ls(&self) -> RunnerJobLsReply {
        RunnerJobLsReply {
            jobs: self.jobs.iter().map(RunnerJob::to_summary).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str) -> RunnerJob {
        RunnerJob {
            job_id: id.to_string(),
            requester_device: "tablet".to_string(),
            repo_key: String::new(),
            source_id: String::new(),
            snapshot_commit: String::new(),
            profile: "gate".to_string(),
            cmd: vec!["cargo".to_string(), "test".to_string()],
            env_names: vec![],
            toolchain: "rust".to_string(),
            cache: "shared".to_string(),
            where_: "remote".to_string(),
            endpoint: String::new(),
            runner_identity: String::new(),
            cancelled: false,
            started_at: 1,
            finished_at: None,
            exit: None,
            attestation_hash: None,
            log: JobLogRing::new(LOG_RING_CAP),
        }
    }

    #[test]
    fn table_evicts_oldest_beyond_bound() {
        let mut t = RunnerJobTable::new(3);
        for id in ["a", "b", "c", "d"] {
            t.insert(job(id));
        }
        assert_eq!(t.len(), 3);
        let ids: Vec<String> = t.ls().jobs.iter().map(|j| j.job_id.clone()).collect();
        assert_eq!(ids, vec!["d", "c", "b"]);
        assert!(t.find("a").is_none());
        assert!(t.find("d").is_some());
    }

    #[test]
    fn find_matches_by_unique_prefix() {
        let mut t = RunnerJobTable::new(2);
        t.insert(job("0123456789abcdef"));
        t.insert(job("fedcba9876543210"));
        assert!(t.find("0123").is_some());
        assert!(t.find("0123456789abcdef").is_some());
        assert!(t.find("zzz").is_none());
    }

    #[test]
    fn log_ring_is_bounded() {
        let mut ring = JobLogRing::new(10);
        ring.append(b"hello"); // 5
        ring.append(b"world"); // 10 total
        assert_eq!(ring.as_bytes(), b"helloworld");
        ring.append(b"!"); // 11 -> drop 1 from front
        assert_eq!(ring.as_bytes(), b"elloworld!");
        ring.append(&[b'x'; 100]); // keep last 10 bytes only
        assert_eq!(ring.as_bytes(), &vec![b'x'; 10][..]);
    }

    #[test]
    fn state_reflects_exit_code() {
        let mut j = job("a");
        assert_eq!(j.state(), "running");
        j.exit = Some(0);
        j.finished_at = Some(2);
        assert_eq!(j.state(), "done");
        j.exit = Some(3);
        assert_eq!(j.state(), "failed");
    }

    #[test]
    fn state_reports_cancelled_over_any_exit() {
        let mut j = job("a");
        j.cancelled = true;
        assert_eq!(j.state(), "cancelled");
        // `cancelled` is terminal and wins over a (stale) exit code.
        j.exit = Some(0);
        assert_eq!(j.state(), "cancelled");
    }
}
