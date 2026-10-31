//! Bounded git probes for the drive loop (queue-v2-git V13).
//!
//! The §8 stack model ([`crate::git_stack`]) runs several read-only git calls
//! per decision: about k+1 in a first claim, about 2k in a restack scan, and a
//! scan over every project at boot. Each call had its own 10 s kill, but
//! nothing bounded the chain, it all ran on the drive loop's one thread, and a
//! failing claim repeated it every tick. This module is the bound:
//!
//! - **One probe per repo, on a worker thread.** [`ProbeCache::spawn`] runs the
//!   whole chain for a repo on its own thread under one overall deadline
//!   ([`PROBE_DEADLINE`]); [`Probe::wait`] is the only thing the loop does, and
//!   it returns by the deadline. Probes for different repos are spawned first
//!   and waited second, so a boot scan over every project costs one deadline,
//!   not one per project. The `child.kill(); child.wait()` a git in D-state can
//!   block on parks the worker, not the tick.
//! - **Cached per tick.** Every probe of a repo within a tick shares one
//!   [`GitMemo`], so the claim's scan, the handshake's scan and a second entry's
//!   first claim answer repeated commands from the first one's results, and a
//!   timeout fails the rest of the tick's probes at once.
//! - **Backed off across ticks.** A probe that misses its deadline is "unknown":
//!   the repo is then held, doubling per consecutive timeout like a failing
//!   claim ([`crate::drive_loop`]'s claim backoff), and probes of a held repo
//!   fail without spawning anything. A probe that completes clears the hold.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::drive_loop::v2_claim_backoff_secs;
use crate::git_stack::{Git, GitError, GitMemo};

/// The overall budget for one repo's probe chain.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(10);

/// How long past its deadline a probe is waited for, so a worker that reports
/// its own timeout is heard before the caller gives up on it.
const WAIT_SLACK: Duration = Duration::from_millis(500);

/// Per-repo probe state, shared by the drive loop and every claim closure it
/// builds (clones are handles to one state).
#[derive(Debug, Clone)]
pub struct ProbeCache {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    deadline: Duration,
    program: PathBuf,
    /// The current tick's time, set by [`ProbeCache::begin_tick`].
    now: AtomicI64,
    repos: Mutex<HashMap<PathBuf, Slot>>,
}

#[derive(Debug, Default)]
struct Slot {
    memo: Arc<GitMemo>,
    /// Consecutive probe timeouts, and the tick time before which the repo is
    /// held (probes fail without spawning).
    streak: u32,
    hold_until: i64,
}

impl Default for ProbeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeCache {
    pub fn new() -> Self {
        Self::with(PROBE_DEADLINE, "git")
    }

    /// A cache with its own deadline and git binary (tests point it at a slow
    /// fake with a short deadline).
    pub fn with(deadline: Duration, program: impl Into<PathBuf>) -> Self {
        Self {
            shared: Arc::new(Shared {
                deadline,
                program: program.into(),
                now: AtomicI64::new(0),
                repos: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn repos(&self) -> MutexGuard<'_, HashMap<PathBuf, Slot>> {
        self.shared.repos.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Start a tick: stamp its time and drop last tick's answers. Holds and
    /// timeout streaks carry over.
    pub fn begin_tick(&self, now: i64) {
        self.shared.now.store(now, Ordering::Relaxed);
        for slot in self.repos().values_mut() {
            slot.memo = Arc::new(GitMemo::default());
        }
    }

    /// Run `f` against `repo` on a worker thread under the overall deadline,
    /// sharing this tick's answers with every other probe of the repo.
    pub fn spawn<T, F>(&self, repo: &Path, f: F) -> Probe<T>
    where
        T: Send + 'static,
        F: FnOnce(&Git) -> Result<T, GitError> + Send + 'static,
    {
        self.start(repo, true, f)
    }

    /// Like [`Self::spawn`], but every command runs fresh: for a read that
    /// follows a change the loop is waiting on (a re-record after a restack).
    pub fn spawn_fresh<T, F>(&self, repo: &Path, f: F) -> Probe<T>
    where
        T: Send + 'static,
        F: FnOnce(&Git) -> Result<T, GitError> + Send + 'static,
    {
        self.start(repo, false, f)
    }

    fn start<T, F>(&self, repo: &Path, memoize: bool, f: F) -> Probe<T>
    where
        T: Send + 'static,
        F: FnOnce(&Git) -> Result<T, GitError> + Send + 'static,
    {
        let shared = &self.shared;
        let now = shared.now.load(Ordering::Relaxed);
        let secs = shared.deadline.as_secs_f64().ceil() as u64;
        let memo = {
            let mut repos = self.repos();
            let slot = repos.entry(repo.to_path_buf()).or_default();
            if slot.hold_until > now {
                return Probe {
                    state: State::Done(Some(Err(GitError::Timeout {
                        cmd: "probe (held after an earlier timeout)".into(),
                        repo: repo.to_path_buf(),
                        secs,
                    }))),
                    cache: self.clone(),
                    repo: repo.to_path_buf(),
                    memo: slot.memo.clone(),
                };
            }
            slot.memo.clone()
        };
        let started = Instant::now();
        let mut git = Git::new(repo)
            .with_program(shared.program.clone())
            .with_deadline(started + shared.deadline);
        if memoize {
            git = git.with_memo(memo.clone());
        }
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f(&git));
        });
        Probe {
            state: State::Running { rx, until: started + shared.deadline + WAIT_SLACK },
            cache: self.clone(),
            repo: repo.to_path_buf(),
            memo,
        }
    }

    /// The git processes spawned for `repo` this tick (tests).
    pub fn spawned(&self, repo: &Path) -> usize {
        self.repos().get(repo).map_or(0, |s| s.memo.spawned())
    }

    fn record(&self, repo: &Path, timed_out: bool) {
        let now = self.shared.now.load(Ordering::Relaxed);
        let mut repos = self.repos();
        let slot = repos.entry(repo.to_path_buf()).or_default();
        if timed_out {
            slot.streak = slot.streak.saturating_add(1);
            slot.hold_until = now + v2_claim_backoff_secs(slot.streak);
        } else {
            slot.streak = 0;
            slot.hold_until = 0;
        }
    }
}

enum State<T> {
    Running {
        rx: mpsc::Receiver<Result<T, GitError>>,
        until: Instant,
    },
    Done(Option<Result<T, GitError>>),
}

/// A running (or already refused) probe. [`Self::wait`] returns by the probe's
/// deadline, whatever the worker is doing.
pub struct Probe<T> {
    state: State<T>,
    cache: ProbeCache,
    repo: PathBuf,
    memo: Arc<GitMemo>,
}

impl<T> Probe<T> {
    /// The probe's result. A probe that outlives its deadline is a
    /// [`GitError::Timeout`]: the repo is marked hung for the rest of the tick
    /// and held across the next ticks, and the worker is left to finish alone.
    pub fn wait(mut self) -> Result<T, GitError> {
        let result = match &mut self.state {
            State::Done(result) => return result.take().expect("a probe is waited once"),
            State::Running { rx, until } => {
                let left = until.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(result) => result,
                    Err(RecvTimeoutError::Timeout) => {
                        let secs = self.cache.shared.deadline.as_secs_f64().ceil() as u64;
                        self.memo.mark_hung("probe", secs);
                        Err(GitError::Timeout {
                            cmd: "probe".into(),
                            repo: self.repo.clone(),
                            secs,
                        })
                    }
                    Err(RecvTimeoutError::Disconnected) => Err(GitError::Run {
                        cmd: "probe".into(),
                        repo: self.repo.clone(),
                        cause: "worker panicked".into(),
                    }),
                }
            }
        };
        match &result {
            Err(GitError::Timeout { .. }) => self.cache.record(&self.repo, true),
            // Completed, whatever it concluded: the repo answers.
            _ => self.cache.record(&self.repo, false),
        }
        result
    }
}

impl<T> std::fmt::Debug for Probe<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Probe").field("repo", &self.repo).finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// A fake `git` that logs each invocation, sleeps `delay`, then prints a
    /// hash. Returns `(script, log)`.
    pub(crate) fn fake_git(dir: &Path, delay: &str) -> (PathBuf, PathBuf) {
        let log = dir.join("calls.log");
        let script = dir.join("fake-git");
        fs::write(
            &script,
            format!("#!/bin/sh\necho \"$@\" >> '{}'\nsleep {delay}\necho deadbeef\n", log.display()),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        (script, log)
    }

    pub(crate) fn calls(log: &Path) -> usize {
        fs::read_to_string(log).map_or(0, |s| s.lines().count())
    }

    #[test]
    fn a_slow_git_misses_the_deadline_and_the_wait_returns() {
        let dir = tempfile::tempdir().unwrap();
        let (git, _) = fake_git(dir.path(), "30");
        let cache = ProbeCache::with(Duration::from_millis(300), git);
        let started = Instant::now();
        let err = cache
            .spawn(dir.path(), |g| g.rev_parse("main"))
            .wait()
            .unwrap_err();
        assert!(matches!(err, GitError::Timeout { .. }), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[test]
    fn a_chain_of_calls_shares_one_overall_deadline() {
        // Ten distinct 0.2 s calls: each is far inside the per-call kill, but the
        // chain is not inside the 0.5 s budget.
        let dir = tempfile::tempdir().unwrap();
        let (git, log) = fake_git(dir.path(), "0.2");
        let cache = ProbeCache::with(Duration::from_millis(500), git);
        let started = Instant::now();
        let result = cache
            .spawn(dir.path(), |g| {
                for i in 0..10 {
                    g.rev_parse(&format!("rev{i}"))?;
                }
                Ok(())
            })
            .wait();
        assert!(matches!(result, Err(GitError::Timeout { .. })), "{result:?}");
        assert!(started.elapsed() < Duration::from_millis(1800), "{:?}", started.elapsed());
        assert!(calls(&log) < 10, "the spent budget stops spawning: {}", calls(&log));
    }

    #[test]
    fn probes_of_one_repo_in_a_tick_run_each_command_once() {
        let dir = tempfile::tempdir().unwrap();
        let (git, log) = fake_git(dir.path(), "0");
        let cache = ProbeCache::with(Duration::from_secs(5), git);
        cache.begin_tick(100);
        for _ in 0..3 {
            let tip = cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().unwrap();
            assert_eq!(tip, "deadbeef");
        }
        assert_eq!(calls(&log), 1, "three probes, one git process");
        assert_eq!(cache.spawned(dir.path()), 1);
        // A new tick asks git again.
        cache.begin_tick(101);
        cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().unwrap();
        assert_eq!(calls(&log), 2);
    }

    #[test]
    fn a_fresh_probe_does_not_read_the_tick_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (git, log) = fake_git(dir.path(), "0");
        let cache = ProbeCache::with(Duration::from_secs(5), git);
        cache.begin_tick(100);
        cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().unwrap();
        cache.spawn_fresh(dir.path(), |g| g.rev_parse("main")).wait().unwrap();
        assert_eq!(calls(&log), 2);
    }

    #[test]
    fn a_timed_out_repo_is_held_with_backoff_then_probed_again() {
        let dir = tempfile::tempdir().unwrap();
        let (git, log) = fake_git(dir.path(), "30");
        let cache = ProbeCache::with(Duration::from_millis(200), git);
        cache.begin_tick(1000);
        assert!(cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().is_err());
        let after_first = calls(&log);
        assert_eq!(after_first, 1);

        // Same tick: the repo is known hung, nothing more is spawned or waited on.
        let started = Instant::now();
        assert!(cache.spawn(dir.path(), |g| g.rev_parse("other")).wait().is_err());
        assert!(started.elapsed() < Duration::from_millis(100));

        // Next ticks inside the backoff: held, no process.
        cache.begin_tick(1000 + v2_claim_backoff_secs(1) - 1);
        assert!(cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().is_err());
        assert_eq!(calls(&log), after_first, "a held repo is not probed");

        // Past the backoff it is probed again.
        cache.begin_tick(1000 + v2_claim_backoff_secs(1));
        assert!(cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().is_err());
        assert_eq!(calls(&log), after_first + 1);
    }

    #[test]
    fn a_completed_probe_clears_the_hold() {
        let dir = tempfile::tempdir().unwrap();
        let (git, _) = fake_git(dir.path(), "0");
        let cache = ProbeCache::with(Duration::from_secs(5), git);
        cache.begin_tick(10);
        cache.record(dir.path(), true);
        cache.begin_tick(10 + v2_claim_backoff_secs(1));
        cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().unwrap();
        assert_eq!(cache.repos().get(dir.path()).unwrap().streak, 0);
    }
}
