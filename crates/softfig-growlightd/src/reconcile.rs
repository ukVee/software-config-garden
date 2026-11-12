//! The boot reconciler (crash-diagnostics slice 002): heal the queue on a
//! growlightd restart, BEFORE the drive loop's first claim tick.
//!
//! ## Why
//!
//! All in-memory orchestration state (supervisor slots, leases, live holders) is
//! gone on a restart, but the persisted queue keeps whatever `active` status the
//! dead member left. An unpinned fallback member's [`pick`](crate::scheduler::pick)
//! SKIPS `active` heads (the pinned agent is meant to resume its own claim), and
//! [`resume_item`](crate::resume) refuses `active` — so a dead `active` claim has
//! no running-time path out and deadlocks the whole queue behind it (single-active
//! per queue). The 2026-07-01 wifi crash loop left `m5b-hardening` in exactly this
//! state: `active`, unheld, blocking the default queue with the fleet idle.
//!
//! This is the counterpart to keeperd's holder-identity CAS: the CAS stops a *live*
//! double-claim; this clears a *dead* claim on restart.
//!
//! ## What it does, in order
//!
//! 1. **Kill stray scopes.** SIGKILL any leftover `growlight-agent-*.scope`
//!    transient units from a prior growlightd generation, so no zombie peer can
//!    still be writing to an item we are about to reset. Clean slate first.
//! 2. **Reap orphaned-active.** Read the queue snapshot and reset EVERY `active`
//!    item to `queued`. Post-restart there is no live holder for any `active` item
//!    by definition, so this is unconditional at boot — NOT a running-time reaper
//!    (no liveness check; there is no live state left to check against).
//!
//! 3. **Reap the v2 queue** (report 172). Under `queue = "v2"` the claim is a row of
//!    `queue.toml`, which step 2 never reads. Every `active` entry goes back to its
//!    `pending_status` if one is recorded, else to `queued`, through keeperd's
//!    `queue_v2_set_status` — the op applies the pending change itself, exactly as
//!    at a handshake. Same reasoning as step 2: post-restart nothing holds an
//!    `active` entry. A failed read of the v2 files skips the step.
//!
//! Ordering is the crux: [`reconcile_on_boot`] runs synchronously and returns
//! before `main` spawns the drive-loop thread, so the reset always completes before
//! the first [`pick`](crate::scheduler::pick) — the loop can never race it.
//!
//! ## Testable without systemctl or keeperd
//!
//! The scope side is a pure argv builder ([`scope_list_argv`]) + a pure parser over
//! scripted `systemctl` output ([`parse_scope_units`]) behind a [`ScopeKiller`]
//! seam; the reap side is a pure decision ([`orphaned_active`]) over a parsed
//! [`Snapshot`] behind the shared [`BacklogReader`] read + a [`StatusResetter`]
//! write seam. So the whole reconcile is unit-proven over fakes (mirroring
//! [`crate::resume`]), with the live impls shelling `systemctl` / reaching keeperd.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::claim::write_item_status;
use crate::agent_harness::scope_kill_argv;
use crate::fleet::QueueMode;
use crate::queue_source::{parse_snapshot, BacklogReader, KeeperdBacklogReader};
use crate::scheduler::{PartStatus, Snapshot};
use softfig_ipc::queue_v2::EntryStatus;
use softfig_ipc::verbs::{op, DaemonStatusArg, QueueV2SetStatusArgs, QueueV2SetStatusReply};
use softfig_ipc::{call_reconnecting, Request, RetryPolicy};

/// The status the reap writes: a dead `active` claim goes back to the ready pool.
const REAP_STATUS: &str = "queued";

// The bounds of a `growlight-agent-<id>-<gen>.scope` unit, used to both glob
// the list and filter the parse. Shared with the harness that names the scope
// and with keeperd, which reads a connection's member out of it.
use softfig_ipc::member::{SCOPE_PREFIX, SCOPE_SUFFIX};

/// The `systemctl list-units` glob that narrows the listing to our agent scopes.
const SCOPE_GLOB: &str = "growlight-agent-*.scope";

// ---------------------------------------------------------------------------
// Stray-scope side: pure argv + parser, behind the ScopeKiller seam.
// ---------------------------------------------------------------------------

/// The `systemctl` argv that lists this daemon's transient agent scopes so a boot
/// reconcile can find strays from a prior generation. `--user` (our scopes live in
/// the user manager), `--type=scope`, `--all` (a scope whose leader died but whose
/// build subtree lingers may not be `active`), `--no-legend` + `--plain` (no header,
/// no leading status dot) so each row's unit token is clean, and the glob narrows it
/// to our units. Pure so the shape is unit-asserted without a real `systemctl`.
fn scope_list_argv() -> Vec<String> {
    vec![
        "--user".to_string(),
        "list-units".to_string(),
        "--type=scope".to_string(),
        "--all".to_string(),
        "--no-legend".to_string(),
        "--plain".to_string(),
        SCOPE_GLOB.to_string(),
    ]
}

/// Extract the `growlight-agent-*.scope` unit names from `systemctl list-units`
/// output. Scans each line for the first whitespace token that is one of our scope
/// units, so a leading status dot (`●` on a failed unit) or the trailing
/// LOAD/ACTIVE/SUB/DESCRIPTION columns never trip it. Pure over scripted output —
/// the glob in [`scope_list_argv`] already narrows the listing; this is the
/// defensive parse that keeps only our units.
fn parse_scope_units(list_output: &str) -> Vec<String> {
    list_output
        .lines()
        .filter_map(|line| {
            line.split_whitespace()
                .find(|tok| tok.starts_with(SCOPE_PREFIX) && tok.ends_with(SCOPE_SUFFIX))
        })
        .map(|s| s.to_string())
        .collect()
}

/// The seam the boot reconcile enumerates + kills stray agent scopes through.
/// Production shells `systemctl` ([`SystemctlScopeKiller`]); a test scripts the unit
/// list and records the kills, so the enumerate → kill orchestration is proven
/// without a real user manager. All best-effort: a missing `systemctl`, an absent
/// `--user` manager, or an already-gone scope is a no-op, never a boot failure.
pub(crate) trait ScopeKiller: Send + Sync + fmt::Debug {
    /// The stray `growlight-agent-*.scope` unit names to kill (empty on any error —
    /// nothing to kill is the safe default).
    fn list_scopes(&self) -> Vec<String>;
    /// SIGKILL one scope unit's whole cgroup (best-effort).
    fn kill_scope(&self, unit: &str);
}

/// Production [`ScopeKiller`]: `systemctl --user list-units …` to enumerate, then
/// `systemctl --user kill --signal=SIGKILL <unit>` per stray (the same
/// [`scope_kill_argv`] the live [`crate::claude_backend`] kill uses).
#[derive(Debug, Clone, Default)]
struct SystemctlScopeKiller;

impl ScopeKiller for SystemctlScopeKiller {
    fn list_scopes(&self) -> Vec<String> {
        let out = Command::new("systemctl")
            .args(scope_list_argv())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        match out {
            // A clean listing → parse the unit tokens out of it.
            Ok(o) if o.status.success() => parse_scope_units(&String::from_utf8_lossy(&o.stdout)),
            // `systemctl` missing, no `--user` manager, or a non-zero exit: nothing
            // we can enumerate ⇒ nothing to kill (safe default, boot proceeds).
            _ => Vec::new(),
        }
    }

    fn kill_scope(&self, unit: &str) {
        // Kill the whole SCOPE cgroup (every pid, so a lingering `cargo`/`rustc`
        // subtree dies too), best-effort: an already-gone scope just errors.
        let _ = Command::new("systemctl")
            .args(scope_kill_argv(unit))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

// ---------------------------------------------------------------------------
// Reap side: pure decision + StatusResetter write seam (shared BacklogReader read).
// ---------------------------------------------------------------------------

/// Every `active` `(queue, id)` pair in `snap`, in snapshot order. Post-restart
/// there is no live holder for ANY of them, so each is reset to `queued` — this is
/// the unconditional-at-boot decision (no liveness filter). Pure over a parsed
/// [`Snapshot`], so it is provable against fixtures.
fn orphaned_active(snap: &Snapshot) -> Vec<(String, String)> {
    snap.queues
        .iter()
        .flat_map(|q| {
            q.parts
                .iter()
                .filter(|p| p.status == PartStatus::Active)
                .map(move |p| (q.name.clone(), p.id.clone()))
        })
        .collect()
}

/// The seam the reap writes `queued` through — the WRITE counterpart to the
/// [`BacklogReader`] read. Production wraps keeperd's `set_item_status` over the
/// socket ([`KeeperdStatusResetter`]); a test records the writes, so the whole
/// read → decide → write is proven without a live keeperd (mirroring
/// [`crate::resume`]).
pub(crate) trait StatusResetter: Send + Sync + fmt::Debug {
    /// Reset `(queue, item)` to `queued` in keeperd's queue table. `Ok(())` =
    /// committed (an idempotent re-write is also ok); `Err(reason)` = keeperd
    /// refused / was unreachable.
    fn reset_to_queued(&self, queue: &str, item: &str) -> Result<(), String>;
}

/// Production [`StatusResetter`]: `set_item_status(item, "queued", queue)` over
/// keeperd's socket, reusing [`write_item_status`] (the same fail-closed round-trip
/// the claim/park/resume writes use, reconnecting through a transient `cycle`).
#[derive(Debug, Clone)]
struct KeeperdStatusResetter {
    keeperd_socket: PathBuf,
}

impl StatusResetter for KeeperdStatusResetter {
    fn reset_to_queued(&self, queue: &str, item: &str) -> Result<(), String> {
        // No holder: a reset OUT of `active` is not a write TO `active`, so keeperd's
        // holder-identity CAS never guards it (and the dead holder is unknowable
        // anyway). keeperd flips any status to the target, so `active → queued` lands.
        write_item_status(&self.keeperd_socket, "reap", queue, item, REAP_STATUS, None, None)
    }
}

// ---------------------------------------------------------------------------
// v2 reap: the `queue.toml` counterpart of the legacy reap above.
// ---------------------------------------------------------------------------

/// The seam the v2 reap reads and writes through: the `active` entries of the v2
/// list, and the keeperd op that moves one off `active`. Production reads the
/// mount and calls `queue_v2_set_status`; a test scripts both.
pub(crate) trait V2Reaper: Send + Sync + fmt::Debug {
    /// The ids of every `active` entry in the v2 list; empty when there is no v2
    /// list yet. `Err` = the v2 files could not be read or did not validate.
    fn active_entries(&self) -> Result<Vec<String>, String>;
    /// Move one `active` entry to `queued`, or to its recorded `pending_status`
    /// (the op applies it). Returns the status that landed.
    fn requeue(&self, entry: &str) -> Result<String, String>;
}

/// Production [`V2Reaper`]: the same fail-closed read the drive loop schedules
/// from ([`crate::v2_source::assemble`]) and an entry-level
/// `queue_v2_set_status(entry, queued)` over keeperd's socket.
#[derive(Debug, Clone)]
struct KeeperdV2Reaper {
    garden_root: PathBuf,
    keeperd_socket: PathBuf,
}

impl V2Reaper for KeeperdV2Reaper {
    fn active_entries(&self) -> Result<Vec<String>, String> {
        match crate::v2_source::assemble(&self.garden_root) {
            Ok(Some(snapshot)) => Ok(snapshot
                .entries
                .into_iter()
                .filter(|e| e.status == EntryStatus::Active)
                .map(|e| e.id)
                .collect()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn requeue(&self, entry: &str) -> Result<String, String> {
        let args = serde_json::to_value(QueueV2SetStatusArgs {
            entry: entry.to_string(),
            unit: None,
            new: DaemonStatusArg::Queued,
        })
        .map_err(|e| format!("encode queue_v2_set_status args: {e}"))?;
        let req = Request::new(op::QUEUE_V2_SET_STATUS, args);
        match call_reconnecting(&self.keeperd_socket, &req, RetryPolicy::default()) {
            Ok(softfig_ipc::Response::Ok { data, .. }) => {
                serde_json::from_value::<QueueV2SetStatusReply>(data)
                    .map(|r| r.status)
                    .map_err(|e| format!("decode queue_v2_set_status reply: {e}"))
            }
            Ok(softfig_ipc::Response::Err { kind, error, .. }) => {
                Err(format!("keeperd refused ({kind:?}): {error}"))
            }
            Err(e) => Err(format!(
                "queue_v2_set_status to keeperd at {} failed: {e}",
                self.keeperd_socket.display()
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Orchestration.
// ---------------------------------------------------------------------------

/// A boot-reconcile summary for the startup log: which strays were killed, which
/// orphaned-active items were reset, any keeperd write that was refused, and a read
/// failure that skipped the reap. All non-fatal — recorded, never propagated.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Stray scope units SIGKILLed, in listing order.
    pub scopes_killed: Vec<String>,
    /// `(queue, item)` reset `active → queued`, in snapshot order.
    pub items_reset: Vec<(String, String)>,
    /// `(queue, item, reason)` for each reset keeperd refused — logged, non-fatal.
    pub reset_failures: Vec<(String, String, String)>,
    /// A backlog-read failure that skipped the reap entirely (keeperd down / Locked).
    pub read_error: Option<String>,
    /// `(entry, status)` for each v2 `active` entry moved off `active`; the status
    /// is what landed (`queued`, or the entry's recorded `pending_status`).
    pub v2_reset: Vec<(String, String)>,
    /// `(entry, reason)` for each v2 move keeperd refused — logged, non-fatal.
    pub v2_failures: Vec<(String, String)>,
    /// A failure to read the v2 files, which skipped the v2 reap.
    pub v2_read_error: Option<String>,
}

/// Run the two-step boot reconcile over injected seams (the tested core): kill stray
/// scopes FIRST, then reap orphaned-active — the ordering that guarantees no zombie
/// peer is still writing to an item we reset. Never errors: every failure is recorded
/// in the [`ReconcileReport`] and boot proceeds (a botched reconcile must not strand
/// the daemon).
fn reconcile(
    scopes: &dyn ScopeKiller,
    reader: &dyn BacklogReader,
    resetter: &dyn StatusResetter,
    v2: Option<&dyn V2Reaper>,
) -> ReconcileReport {
    let mut report = ReconcileReport::default();

    // 1. Clean slate: kill stray scopes from a prior generation.
    for unit in scopes.list_scopes() {
        scopes.kill_scope(&unit);
        report.scopes_killed.push(unit);
    }

    // 2. Reap orphaned-active. A read failure skips the reap (fail-closed: reset
    //    nothing rather than guess), leaving the deadlock for the next boot — no
    //    worse than not reconciling at all.
    match reader.read_backlog() {
        Ok(doc) => {
            let snap = parse_snapshot(&doc);
            for (queue, item) in orphaned_active(&snap) {
                match resetter.reset_to_queued(&queue, &item) {
                    Ok(()) => report.items_reset.push((queue, item)),
                    Err(reason) => report.reset_failures.push((queue, item, reason)),
                }
            }
        }
        Err(reason) => report.read_error = Some(reason),
    }

    // 3. Reap the v2 queue (report 172), only under `queue = "v2"`. Same
    //    fail-closed shape: a failed read resets nothing.
    if let Some(v2) = v2 {
        match v2.active_entries() {
            Ok(entries) => {
                for entry in entries {
                    match v2.requeue(&entry) {
                        Ok(status) => report.v2_reset.push((entry, status)),
                        Err(reason) => report.v2_failures.push((entry, reason)),
                    }
                }
            }
            Err(reason) => report.v2_read_error = Some(reason),
        }
    }

    report
}

/// Boot reconcile with the production seams: shell `systemctl` for the stray-scope
/// kill and reach `keeperd` over `keeperd_socket` for the orphaned-active reap. Runs
/// synchronously (so it completes before the caller spawns the drive loop) and logs a
/// one-line-per-effect summary. Best-effort — it never returns an error; a failure is
/// logged and boot continues.
pub fn reconcile_on_boot(keeperd_socket: &Path, garden_root: &Path, queue: QueueMode) {
    let scopes = SystemctlScopeKiller;
    let reader = KeeperdBacklogReader::new(keeperd_socket.to_path_buf());
    let resetter = KeeperdStatusResetter {
        keeperd_socket: keeperd_socket.to_path_buf(),
    };
    let v2_reaper = KeeperdV2Reaper {
        garden_root: garden_root.to_path_buf(),
        keeperd_socket: keeperd_socket.to_path_buf(),
    };
    let v2 = (queue == QueueMode::V2).then_some(&v2_reaper as &dyn V2Reaper);
    log_report(&reconcile(&scopes, &reader, &resetter, v2));
}

/// Emit the human-readable startup log for a [`ReconcileReport`] (nothing when the
/// reconcile was a clean no-op: no strays, no orphaned-active, no errors).
fn log_report(report: &ReconcileReport) {
    if !report.scopes_killed.is_empty() {
        eprintln!(
            "softfig-growlightd: boot reconcile killed {} stray scope(s): {}",
            report.scopes_killed.len(),
            report.scopes_killed.join(", "),
        );
    }
    for (queue, item) in &report.items_reset {
        eprintln!("softfig-growlightd: boot reconcile reset orphaned-active {item} ({queue}) -> queued");
    }
    for (queue, item, reason) in &report.reset_failures {
        eprintln!("softfig-growlightd: boot reconcile FAILED to reset {item} ({queue}): {reason}");
    }
    for (entry, status) in &report.v2_reset {
        eprintln!("softfig-growlightd: boot reconcile reset orphaned-active v2 entry {entry} -> {status}");
    }
    for (entry, reason) in &report.v2_failures {
        eprintln!("softfig-growlightd: boot reconcile FAILED to reset v2 entry {entry}: {reason}");
    }
    if let Some(err) = &report.v2_read_error {
        eprintln!(
            "softfig-growlightd: boot reconcile skipped the v2 reap (queue files unreadable): {err}"
        );
    }
    if let Some(err) = &report.read_error {
        eprintln!(
            "softfig-growlightd: boot reconcile skipped the orphaned-active reap (backlog read failed): {err}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::{PartView, QueueView};
    use std::sync::{Arc, Mutex};

    // ---- pure: scope argv + parser -----------------------------------------

    #[test]
    fn scope_list_argv_lists_only_our_user_scopes_without_a_legend() {
        let argv = scope_list_argv();
        assert_eq!(argv[0], "--user", "our scopes live in the user manager");
        assert!(argv.contains(&"list-units".to_string()));
        assert!(argv.contains(&"--type=scope".to_string()));
        assert!(
            argv.contains(&"--all".to_string()),
            "a dead-leader scope may not be `active` — --all still lists it",
        );
        // No legend/dot, so the parse sees clean unit tokens.
        assert!(argv.contains(&"--no-legend".to_string()));
        assert!(argv.contains(&"--plain".to_string()));
        assert_eq!(argv.last().unwrap(), SCOPE_GLOB, "the glob narrows to our units");
    }

    #[test]
    fn parse_scope_units_keeps_only_growlight_agent_scopes() {
        // Realistic `systemctl list-units --plain --no-legend` rows: UNIT then the
        // LOAD/ACTIVE/SUB/DESCRIPTION columns.
        let out = "\
growlight-agent-a-0.scope   loaded active running   growlight agent a
growlight-agent-b-3.scope   loaded active running   growlight agent b
some-other.scope            loaded active running   unrelated
";
        assert_eq!(
            parse_scope_units(out),
            vec![
                "growlight-agent-a-0.scope".to_string(),
                "growlight-agent-b-3.scope".to_string(),
            ],
            "only our agent scopes survive; the unrelated scope is dropped",
        );
    }

    #[test]
    fn parse_scope_units_survives_a_leading_status_dot_and_blank_lines() {
        // A failed unit gets a leading `●`; the parser scans for the unit token, so
        // the dot never masks it. Blank lines and junk are ignored.
        let out = "\n● growlight-agent-a-1.scope loaded failed failed agent a\n\nnot a unit line\n";
        assert_eq!(
            parse_scope_units(out),
            vec!["growlight-agent-a-1.scope".to_string()],
        );
    }

    #[test]
    fn parse_scope_units_of_empty_output_is_no_strays() {
        assert!(parse_scope_units("").is_empty());
        assert!(parse_scope_units("\n\n").is_empty());
    }

    // ---- pure: the orphaned-active decision --------------------------------

    fn snap(queues: Vec<(&str, Vec<(&str, &str)>)>) -> Snapshot {
        Snapshot::new(
            queues
                .into_iter()
                .map(|(name, parts)| {
                    QueueView::new(
                        name,
                        parts
                            .into_iter()
                            .map(|(id, status)| PartView::new(id, status))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn orphaned_active_selects_every_active_item_across_queues_in_order() {
        let s = snap(vec![
            ("default", vec![("m5b", "active"), ("t2", "queued"), ("t3", "blocked")]),
            ("smoke-a", vec![("s1", "done"), ("s2", "active")]),
        ]);
        assert_eq!(
            orphaned_active(&s),
            vec![
                ("default".to_string(), "m5b".to_string()),
                ("smoke-a".to_string(), "s2".to_string()),
            ],
            "only the `active` heads, in snapshot (queue then row) order",
        );
    }

    #[test]
    fn orphaned_active_of_a_queue_with_no_active_is_empty() {
        let s = snap(vec![("default", vec![("t1", "queued"), ("t2", "done"), ("t3", "blocked")])]);
        assert!(orphaned_active(&s).is_empty(), "nothing active ⇒ nothing to reap");
    }

    // ---- the full reconcile over faked seams -------------------------------

    /// A shared, ordered event log so a test can assert the kills all precede the
    /// resets (the ordering crux).
    #[derive(Debug, Default)]
    struct Recorder {
        events: Mutex<Vec<String>>,
    }
    impl Recorder {
        fn record(&self, ev: String) {
            self.events.lock().unwrap().push(ev);
        }
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    #[derive(Debug)]
    struct FakeScopeKiller {
        units: Vec<String>,
        rec: Arc<Recorder>,
    }
    impl ScopeKiller for FakeScopeKiller {
        fn list_scopes(&self) -> Vec<String> {
            self.units.clone()
        }
        fn kill_scope(&self, unit: &str) {
            self.rec.record(format!("kill:{unit}"));
        }
    }

    #[derive(Debug)]
    struct FakeReader {
        result: Result<String, String>,
    }
    impl BacklogReader for FakeReader {
        fn read_backlog(&self) -> Result<String, String> {
            self.result.clone()
        }
    }

    #[derive(Debug)]
    struct SpyResetter {
        rec: Arc<Recorder>,
        /// Items whose reset should fail, by id (keeperd refused).
        fail_ids: Vec<String>,
    }
    impl StatusResetter for SpyResetter {
        fn reset_to_queued(&self, queue: &str, item: &str) -> Result<(), String> {
            if self.fail_ids.iter().any(|id| id == item) {
                return Err(format!("keeperd refused reap of {item} (Locked)"));
            }
            self.rec.record(format!("reset:{queue}/{item}"));
            Ok(())
        }
    }

    /// Wrap a default-queue table in the managed-region markers keeperd renders, so
    /// the reconcile's `parse_snapshot` sees a realistic backlog doc.
    fn backlog_doc(rows: &[(&str, &str)]) -> String {
        let mut table =
            String::from("| # | id | type | title | status |\n|---|----|------|-------|--------|");
        for (i, (id, status)) in rows.iter().enumerate() {
            table.push_str(&format!("\n| {} | {id} | task | T | {status} |", i + 1));
        }
        format!("<!-- softfig:queue -->\n\n{table}\n\n<!-- /softfig:queue -->")
    }

    #[test]
    fn an_orphaned_active_item_with_no_live_holder_becomes_queued() {
        // The core acceptance shape: an `active` head, no live holder, resets to
        // `queued` (mirroring the on-device m5b-hardening case).
        let rec = Arc::new(Recorder::default());
        let scopes = FakeScopeKiller { units: vec![], rec: Arc::clone(&rec) };
        let reader = FakeReader {
            result: Ok(backlog_doc(&[("m5b", "active"), ("t2", "queued")])),
        };
        let resetter = SpyResetter { rec: Arc::clone(&rec), fail_ids: vec![] };

        let report = reconcile(&scopes, &reader, &resetter, None);
        assert_eq!(
            report.items_reset,
            vec![("default".to_string(), "m5b".to_string())],
            "only the orphaned `active` item is reset; the `queued` one is untouched",
        );
        assert!(report.reset_failures.is_empty());
        assert!(report.read_error.is_none());
        assert_eq!(rec.events(), vec!["reset:default/m5b".to_string()]);
    }

    #[test]
    fn strays_are_killed_before_any_item_is_reset() {
        // The ordering crux: every scope kill precedes every reap write, so no zombie
        // peer can still write to an item we then reset.
        let rec = Arc::new(Recorder::default());
        let scopes = FakeScopeKiller {
            units: vec![
                "growlight-agent-a-0.scope".to_string(),
                "growlight-agent-b-1.scope".to_string(),
            ],
            rec: Arc::clone(&rec),
        };
        let reader = FakeReader { result: Ok(backlog_doc(&[("m5b", "active")])) };
        let resetter = SpyResetter { rec: Arc::clone(&rec), fail_ids: vec![] };

        let report = reconcile(&scopes, &reader, &resetter, None);
        assert_eq!(
            report.scopes_killed,
            vec![
                "growlight-agent-a-0.scope".to_string(),
                "growlight-agent-b-1.scope".to_string(),
            ],
        );
        assert_eq!(
            rec.events(),
            vec![
                "kill:growlight-agent-a-0.scope".to_string(),
                "kill:growlight-agent-b-1.scope".to_string(),
                "reset:default/m5b".to_string(),
            ],
            "both kills come before the reset",
        );
    }

    #[test]
    fn a_backlog_read_failure_skips_the_reap_but_still_kills_strays() {
        let rec = Arc::new(Recorder::default());
        let scopes = FakeScopeKiller {
            units: vec!["growlight-agent-a-0.scope".to_string()],
            rec: Arc::clone(&rec),
        };
        let reader = FakeReader { result: Err("keeperd Locked".to_string()) };
        let resetter = SpyResetter { rec: Arc::clone(&rec), fail_ids: vec![] };

        let report = reconcile(&scopes, &reader, &resetter, None);
        assert_eq!(report.scopes_killed.len(), 1, "the stray is still killed");
        assert!(report.items_reset.is_empty(), "no reap on a read failure — fail-closed");
        assert_eq!(report.read_error.as_deref(), Some("keeperd Locked"));
        // Only the kill happened; nothing was reset.
        assert_eq!(rec.events(), vec!["kill:growlight-agent-a-0.scope".to_string()]);
    }

    #[test]
    fn a_refused_reset_is_recorded_as_a_failure_not_a_success() {
        let rec = Arc::new(Recorder::default());
        let scopes = FakeScopeKiller { units: vec![], rec: Arc::clone(&rec) };
        let reader = FakeReader {
            result: Ok(backlog_doc(&[("m5b", "active"), ("other", "active")])),
        };
        // keeperd refuses the m5b write but accepts `other`.
        let resetter = SpyResetter {
            rec: Arc::clone(&rec),
            fail_ids: vec!["m5b".to_string()],
        };

        let report = reconcile(&scopes, &reader, &resetter, None);
        assert_eq!(
            report.items_reset,
            vec![("default".to_string(), "other".to_string())],
            "the accepted reset lands",
        );
        assert_eq!(report.reset_failures.len(), 1);
        assert_eq!(report.reset_failures[0].0, "default");
        assert_eq!(report.reset_failures[0].1, "m5b");
        assert!(report.reset_failures[0].2.contains("refused reap"));
    }

    #[test]
    fn a_clean_queue_with_no_strays_reconciles_to_an_empty_report() {
        let rec = Arc::new(Recorder::default());
        let scopes = FakeScopeKiller { units: vec![], rec: Arc::clone(&rec) };
        let reader = FakeReader {
            result: Ok(backlog_doc(&[("t1", "queued"), ("t2", "done")])),
        };
        let resetter = SpyResetter { rec: Arc::clone(&rec), fail_ids: vec![] };

        let report = reconcile(&scopes, &reader, &resetter, None);
        assert_eq!(report, ReconcileReport::default(), "nothing to do ⇒ empty report");
        assert!(rec.events().is_empty());
    }

    // ---- the v2 reap (report 172) ------------------------------------------

    /// A scripted v2 list: the `active` ids it reports, and what `requeue` lands
    /// per entry (the recorded `pending_status` a real keeperd applies).
    #[derive(Debug)]
    struct FakeV2 {
        rec: Arc<Recorder>,
        active: Result<Vec<String>, String>,
        /// `entry -> landed status`; absent means `queued`.
        pending: Vec<(String, String)>,
        refuse: Vec<String>,
    }
    impl V2Reaper for FakeV2 {
        fn active_entries(&self) -> Result<Vec<String>, String> {
            self.active.clone()
        }
        fn requeue(&self, entry: &str) -> Result<String, String> {
            if self.refuse.iter().any(|e| e == entry) {
                return Err(format!("keeperd refused ({entry})"));
            }
            self.rec.record(format!("v2:{entry}"));
            Ok(self
                .pending
                .iter()
                .find(|(e, _)| e == entry)
                .map_or_else(|| "queued".to_string(), |(_, s)| s.clone()))
        }
    }

    fn v2_fixture(rec: &Arc<Recorder>, active: Result<Vec<&str>, &str>) -> FakeV2 {
        FakeV2 {
            rec: Arc::clone(rec),
            active: active
                .map(|v| v.into_iter().map(String::from).collect())
                .map_err(String::from),
            pending: vec![],
            refuse: vec![],
        }
    }

    fn quiet_legacy(rec: &Arc<Recorder>) -> (FakeScopeKiller, FakeReader, SpyResetter) {
        (
            FakeScopeKiller { units: vec![], rec: Arc::clone(rec) },
            FakeReader { result: Ok(backlog_doc(&[])) },
            SpyResetter { rec: Arc::clone(rec), fail_ids: vec![] },
        )
    }

    #[test]
    fn a_holder_less_active_v2_entry_goes_back_to_queued() {
        let rec = Arc::new(Recorder::default());
        let (scopes, reader, resetter) = quiet_legacy(&rec);
        let v2 = v2_fixture(&rec, Ok(vec!["109"]));

        let report = reconcile(&scopes, &reader, &resetter, Some(&v2));
        assert_eq!(report.v2_reset, vec![("109".to_string(), "queued".to_string())]);
        assert!(report.v2_failures.is_empty() && report.v2_read_error.is_none());
        assert_eq!(rec.events(), vec!["v2:109".to_string()]);
    }

    #[test]
    fn a_recorded_pending_status_is_the_one_that_lands() {
        // keeperd's op applies the pending change; the report carries what it landed.
        let rec = Arc::new(Recorder::default());
        let (scopes, reader, resetter) = quiet_legacy(&rec);
        let mut v2 = v2_fixture(&rec, Ok(vec!["109", "110"]));
        v2.pending = vec![("109".to_string(), "deferred".to_string())];

        let report = reconcile(&scopes, &reader, &resetter, Some(&v2));
        assert_eq!(
            report.v2_reset,
            vec![
                ("109".to_string(), "deferred".to_string()),
                ("110".to_string(), "queued".to_string()),
            ],
        );
    }

    #[test]
    fn the_v2_reap_runs_after_the_stray_scopes_are_killed() {
        let rec = Arc::new(Recorder::default());
        let scopes = FakeScopeKiller {
            units: vec!["growlight-agent-a-0.scope".to_string()],
            rec: Arc::clone(&rec),
        };
        let reader = FakeReader { result: Ok(backlog_doc(&[])) };
        let resetter = SpyResetter { rec: Arc::clone(&rec), fail_ids: vec![] };
        let v2 = v2_fixture(&rec, Ok(vec!["109"]));

        reconcile(&scopes, &reader, &resetter, Some(&v2));
        assert_eq!(
            rec.events(),
            vec!["kill:growlight-agent-a-0.scope".to_string(), "v2:109".to_string()],
        );
    }

    #[test]
    fn an_unreadable_v2_list_resets_nothing_and_says_why() {
        let rec = Arc::new(Recorder::default());
        let (scopes, reader, resetter) = quiet_legacy(&rec);
        let v2 = v2_fixture(&rec, Err("queue.toml: invalid TOML at line 3, column 1: x"));

        let report = reconcile(&scopes, &reader, &resetter, Some(&v2));
        assert!(report.v2_reset.is_empty(), "fail closed");
        assert_eq!(
            report.v2_read_error.as_deref(),
            Some("queue.toml: invalid TOML at line 3, column 1: x")
        );
        assert!(rec.events().is_empty());
    }

    #[test]
    fn a_refused_v2_move_is_a_failure_and_the_next_entry_is_still_tried() {
        let rec = Arc::new(Recorder::default());
        let (scopes, reader, resetter) = quiet_legacy(&rec);
        let mut v2 = v2_fixture(&rec, Ok(vec!["109", "110"]));
        v2.refuse = vec!["109".to_string()];

        let report = reconcile(&scopes, &reader, &resetter, Some(&v2));
        assert_eq!(report.v2_reset, vec![("110".to_string(), "queued".to_string())]);
        assert_eq!(report.v2_failures.len(), 1);
        assert_eq!(report.v2_failures[0].0, "109");
    }

    #[test]
    fn no_v2_reaper_leaves_the_v2_fields_empty() {
        // The legacy queue mode hands `reconcile` no reaper.
        let rec = Arc::new(Recorder::default());
        let (scopes, reader, resetter) = quiet_legacy(&rec);
        assert_eq!(reconcile(&scopes, &reader, &resetter, None), ReconcileReport::default());
    }

    /// The production reader over a real on-disk v2 list: only `active` rows,
    /// no list at all is nothing to reap, and a file that does not parse is an
    /// error rather than an empty list.
    #[test]
    fn the_production_v2_reaper_reads_active_entries_and_fails_closed() {
        use softfig_ipc::queue_v2::{Entry, EntryKind, Lane, Project, QueueToml};

        let root = std::env::temp_dir().join(format!("sf-reconcile-v2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let backlog = root.join("growlight/backlog");
        std::fs::create_dir_all(&backlog).unwrap();
        let reaper = KeeperdV2Reaper {
            garden_root: root.clone(),
            keeperd_socket: root.join("no-keeperd.sock"),
        };
        assert_eq!(reaper.active_entries(), Ok(vec![]), "no queue.toml: nothing to reap");

        let entry = |id: &str, status| Entry {
            id: id.into(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".into(),
            lane: Lane::Normal,
            status,
            after: vec![],
            added: "2026-10-11T15:04:00Z".into(),
            branch: format!("feat/{id}"),
            parent: String::new(),
            base: String::new(),
            claimed: String::new(),
            follow_ups: 0,
            pending_status: None,
            auto_restack: true,
            fleet: false,
            not_before: None,
        };
        let project = Project { name: "softfig".into(), repo: "~/p".into(), main: "main".into() };
        let queue = QueueToml::new(
            vec![project],
            vec![entry("a", EntryStatus::Active), entry("b", EntryStatus::Queued)],
        )
        .to_toml()
        .unwrap();
        std::fs::write(backlog.join("queue.toml"), queue).unwrap();
        assert_eq!(reaper.active_entries(), Ok(vec!["a".to_string()]));
        // A human-only (`fleet = false`) entry is reaped too: that is the 109 case.

        std::fs::write(backlog.join("queue.toml"), "not = [toml").unwrap();
        let err = reaper.active_entries().unwrap_err();
        assert!(err.contains("queue.toml"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
