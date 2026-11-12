//! A git that never dies must not leak a probe worker per backoff window (F6).
//!
//! Its own test binary, with one test, so the process's thread count is this
//! test's alone. A real D-state can't be staged, so the fake gets the same
//! effect from the other thing a worker blocks on after the kill: its killed
//! shell leaves a subshell holding stdout open, and the worker sits in the
//! stdout reader's join until the gate file goes away.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use softfig_growlightd::git_probe::ProbeCache;

/// Past the longest claim backoff, so every tick is a fresh backoff window.
const WINDOW_SECS: i64 = 1_000;

fn threads() -> usize {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn calls(log: &Path) -> usize {
    fs::read_to_string(log).map_or(0, |s| s.lines().count())
}

#[test]
fn a_git_that_never_dies_leaves_a_bounded_set_of_threads() {
    let dir = tempfile::tempdir().unwrap();
    let gate = dir.path().join("gate");
    let log = dir.path().join("calls.log");
    let script = dir.path().join("fake-git");
    fs::write(&gate, "").unwrap();
    fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{log}'\nif [ -e '{gate}' ]; then\n  (while [ -e '{gate}' ]; do sleep 0.05; done) &\n  wait\nfi\necho deadbeef\n",
            log = log.display(),
            gate = gate.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let cache = ProbeCache::with(Duration::from_millis(100), &script);
    let before = threads();
    let mut now = 0;
    for _ in 0..12 {
        now += WINDOW_SECS;
        cache.begin_tick(now);
        assert!(cache.spawn(dir.path(), |g| g.rev_parse("main")).wait().is_err());
    }
    // Two parked workers, each with its stdout reader and its one git.
    assert_eq!(calls(&log), 2, "a repo with parked workers stops getting new gits");
    let grown = threads().saturating_sub(before);
    assert!(grown <= 4, "12 backoff windows grew the process by {grown} threads");

    // The repo recovers on its own once the stuck gits go away.
    fs::remove_file(&gate).unwrap();
    let give_up = Instant::now() + Duration::from_secs(20);
    let tip = loop {
        now += WINDOW_SECS;
        cache.begin_tick(now);
        match cache.spawn(dir.path(), |g| g.rev_parse("main")).wait() {
            Ok(tip) => break tip,
            Err(e) => assert!(Instant::now() < give_up, "the repo never recovered: {e}"),
        }
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(tip, "deadbeef");
    while threads() > before {
        assert!(Instant::now() < give_up, "{} threads, was {before}", threads());
        thread::sleep(Duration::from_millis(50));
    }
}
