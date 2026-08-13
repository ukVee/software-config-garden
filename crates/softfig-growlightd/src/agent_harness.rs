//! The backend-agnostic agent supervision harness — everything a headless agent
//! child needs that is NOT specific to which CLI is being shelled
//! (opencode-fleet-backend slice 001).
//!
//! This module is the extraction of [`crate::claude_backend`]'s load-bearing
//! middle: the transient-scope wrapper, the health/stderr/rate observation cells,
//! the live scope + kill registries, and the two detached reader threads. All of
//! it is *supervision machinery*, not wire format — a second backend
//! (spec-agents §10 phase 2) implements the small [`BackendFlavor`] seam instead
//! of copy-pasting ~1000 lines of the daemon's kill-safety code.
//!
//! ## The seam
//!
//! A backend supplies exactly three things ([`BackendFlavor`]):
//!
//! - [`command_argv`](BackendFlavor::command_argv) — what goes AFTER
//!   `systemd-run … --`. The wrapper half is the harness's.
//! - [`generate_preapproval`](BackendFlavor::generate_preapproval) — fail-closed,
//!   called BEFORE exec (§15: a headless agent **errors out** on an un-approved
//!   tool, so a member whose pre-approval can't be written must not be spawned).
//! - [`new_observer`](BackendFlavor::new_observer) — this spawn's per-line fold:
//!   publish deltas, and record whatever budget/rate signal its wire format
//!   carries.
//!
//! Everything else — the scope naming/generation, the gentle build caps, the
//! heartbeat, the bounded stderr ring, the rolling-minute token meter, the
//! exit-time registry cleanup guarded by scope token — is shared and lives here.
//!
//! ## Why this is the load-bearing code
//!
//! Two incidents are encoded in it and must not be duplicated per backend: the
//! **kill-outside-the-lock** contract (incident-20260622 — [`AgentChild`] stays a
//! pure kill handle, health is a separate `Arc`-shared observation) and the
//! **transient-scope isolation** (incident growlightd-resource-down-build,
//! 2026-06-28 — a building agent's whole `agent → cargo → rustc` tree lives in its
//! own cgroup, never `softfig-growlightd.service`'s).
//!
//! ## Time
//!
//! The pure policy ([`crate::supervisor::Supervisor`]) stays time-injected. Only
//! this live binding reads the wall clock — at spawn (the initial heartbeat) and
//! on every stream line. The line loop is itself pure over a `BufRead` + an
//! injected clock ([`pump`]), so it is unit-proven with a scripted fixture and a
//! fake clock — no real agent CLI is ever spawned in tests.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::config::BuildCaps;
use crate::control::{AgentChild, LiveKill};
use crate::preapproval::AgentPaths;
use crate::supervisor::{AgentBackend, AgentHealth, AgentSpec, SpawnError};

/// Sentinel in [`AgentHealthState::exit_code`] meaning "still running".
const NOT_EXITED: i64 = i64::MIN;
/// Exit code recorded when a child ended but its code was unreadable (killed by a
/// signal, or the status couldn't be collected). Non-zero so it classifies as a
/// crash, never a clean (code-0) roll.
const UNKNOWN_EXIT: i32 = -1;
/// How many trailing stderr lines each agent's crash-diagnostics ring buffer
/// retains (crash-diagnostics slice 001). Bounded so a chatty child can't grow the
/// in-memory buffer without limit; the oldest line drops once the ring is full.
const STDERR_RING_MAX_LINES: usize = 50;
/// Per-line cap (chars) on a retained stderr line, so one pathological line can't
/// bloat the ring. Char-truncated (never mid-codepoint).
const STDERR_LINE_MAX_CHARS: usize = 512;
/// How many trailing stderr lines the `AgentCrashed` alert carries (the tail
/// surfaced to the human) — a subset of what the ring retains.
const STDERR_ALERT_TAIL_LINES: usize = 10;

/// The rolling window admission's TPM/RPM gate meters over: tokens/requests in
/// the trailing minute (spec §7 "tokens/requests per minute"). One minute.
const RATE_WINDOW_SECS: i64 = 60;

/// Shared, lock-free observation of one live agent: the Unix-seconds heartbeat
/// (bumped on every stream line) and the exit code once the child ends. The
/// reader thread writes it; the drive loop reads it via [`Harness::health`] to
/// build the [`AgentHealth`] it feeds [`crate::supervisor::Supervisor::poll`].
///
/// ## Why a shared health cell, not a method on [`AgentChild`]
///
/// [`AgentChild`] stays the pure *kill* handle (its only job is the
/// incident-20260622 kill-outside-the-lock contract). Health is a *separate*
/// observation the reader thread writes into an `AgentHealthState` shared by
/// `Arc`; the harness keeps a registry of those cells and the drive loop reads
/// them by agent id. This keeps lifecycle (kill) and observability (health)
/// decoupled and leaves the existing `AgentChild` fakes untouched.
#[derive(Debug)]
pub struct AgentHealthState {
    last_active: AtomicI64,
    exit_code: AtomicI64,
}

impl AgentHealthState {
    /// A fresh state for a just-spawned child whose first heartbeat is its spawn
    /// time (so a child that never emits a line still hangs only after the window).
    pub(crate) fn new(spawned_at: i64) -> Self {
        Self {
            last_active: AtomicI64::new(spawned_at),
            exit_code: AtomicI64::new(NOT_EXITED),
        }
    }

    /// Record stream activity at `now` — a heartbeat. Stores the latest stamp.
    pub(crate) fn touch(&self, now: i64) {
        self.last_active.store(now, Ordering::SeqCst);
    }

    /// Record the child's terminal exit code once it has ended.
    pub(crate) fn record_exit(&self, code: i32) {
        self.exit_code.store(code as i64, Ordering::SeqCst);
    }

    pub(crate) fn last_active(&self) -> i64 {
        self.last_active.load(Ordering::SeqCst)
    }

    /// The current [`AgentHealth`]: `Exited` once the child has ended, else
    /// `Alive` stamped with the last heartbeat. The Supervisor compares the stamp
    /// to its own injected clock, so no `now` is needed to build the value.
    pub fn observe(&self) -> AgentHealth {
        match self.exit_code.load(Ordering::SeqCst) {
            NOT_EXITED => AgentHealth::Alive {
                last_active: self.last_active(),
            },
            code => AgentHealth::Exited { code: code as i32 },
        }
    }
}

/// One agent's timestamped token/request samples over the trailing
/// [`RATE_WINDOW_SECS`], the live source of admission's short-window TPM/RPM gate
/// (spec §7 second window). **Provider-neutral** — tokens per minute is tokens
/// per minute, whichever CLI reported them; only the *parse* that produces a
/// sample is wire-specific (the flavor's [`LineObserver`] owns that). The reader
/// thread appends one sample per completed turn, the drive loop reads the
/// **fleet-wide** sum via [`Harness::rate_used`]. Samples older than the window
/// are pruned on every append and read, so the cell is self-bounding and a
/// retired agent's burst ages out without an explicit forget.
#[derive(Debug, Default)]
pub struct AgentRateState {
    /// Append-ordered samples; pruned to the trailing window on touch.
    inner: Mutex<Vec<RateSample>>,
}

/// One observed turn: when it completed (`at`, unix secs) and the tokens it cost.
/// A request tick is implicit (one sample == one completed turn == one request).
#[derive(Debug, Clone, Copy)]
struct RateSample {
    at: i64,
    tokens: u64,
}

impl AgentRateState {
    /// Record one completed turn's token cost at `at` (the reader's clock). Prunes
    /// anything already outside the trailing window so the buffer can't grow
    /// unbounded between reads.
    pub(crate) fn record(&self, at: i64, tokens: u64) {
        let mut v = self.inner.lock().unwrap();
        v.push(RateSample { at, tokens });
        let cutoff = at - RATE_WINDOW_SECS;
        v.retain(|s| s.at > cutoff);
    }

    /// `(tokens, requests)` observed within the trailing `RATE_WINDOW_SECS` of
    /// `now`. Prunes expired samples as it reads (the drive loop reads every tick,
    /// so the buffer stays small). A retired agent's stale burst contributes 0
    /// once it ages past the window.
    pub(crate) fn window(&self, now: i64) -> (u64, u64) {
        let cutoff = now - RATE_WINDOW_SECS;
        let mut v = self.inner.lock().unwrap();
        v.retain(|s| s.at > cutoff);
        let tokens = v.iter().map(|s| s.tokens).sum();
        (tokens, v.len() as u64)
    }
}

/// Shared per-agent ring buffer of the child's most recent stderr lines
/// (crash-diagnostics slice 001). growlightd launches the peer with **piped**
/// stderr and a reader thread ([`drain_stderr`]) tails it into this bounded
/// [`VecDeque`] (oldest dropped past [`STDERR_RING_MAX_LINES`]), so a crash carries
/// a *reason* — not just a non-zero exit code, the gap that made the 2026-07-01
/// wifi crash loop only inferable. Sibling to [`AgentHealthState`]: one more
/// decoupled observation of a live agent, held in the harness's per-agent registry
/// and read via [`Harness::stderr_tail`] when the supervisor classifies a crash.
///
/// **Intentionally in-memory + ephemeral** (SSD-wear, Surface Go 3): the buffer is
/// lost on a growlightd restart; the crash *alert* carries the diagnostic forward,
/// never a persisted `stderr.log`.
#[derive(Debug, Default)]
pub struct AgentStderrState {
    inner: Mutex<VecDeque<String>>,
}

impl AgentStderrState {
    /// Append one drained stderr line, char-truncated to [`STDERR_LINE_MAX_CHARS`],
    /// dropping the oldest once the ring exceeds [`STDERR_RING_MAX_LINES`]. Called
    /// once per non-empty line by the reader thread.
    fn push_line(&self, line: &str) {
        let line = if line.chars().count() > STDERR_LINE_MAX_CHARS {
            let mut t: String = line.chars().take(STDERR_LINE_MAX_CHARS).collect();
            t.push('…');
            t
        } else {
            line.to_string()
        };
        let mut buf = self.inner.lock().unwrap();
        buf.push_back(line);
        while buf.len() > STDERR_RING_MAX_LINES {
            buf.pop_front();
        }
    }

    /// The last `n` retained lines (oldest→newest) — the crash-alert tail. At most
    /// [`STDERR_RING_MAX_LINES`] are retained; `n` caps what the alert carries.
    pub(crate) fn tail(&self, n: usize) -> Vec<String> {
        let buf = self.inner.lock().unwrap();
        let start = buf.len().saturating_sub(n);
        buf.iter().skip(start).cloned().collect()
    }
}

/// Drain an agent's piped stderr to EOF, appending each non-empty line into the
/// bounded [`AgentStderrState`] ring (crash-diagnostics slice 001). The SAME
/// deadlock-safe shape [`pump`] uses on stdout: a blocked `lines()` reader holds NO
/// lock, so an actively-drained pipe never fills — the deadlock the old
/// `Stdio::null()` comment warned of applies only to an *unread* pipe, not a
/// drained one. Trailing whitespace is trimmed (leading indentation kept, so a
/// stack trace stays readable); a blank line carries no diagnostic and is skipped.
/// Pure over its `reader` seam: a test drives it with a scripted fixture and
/// asserts the ring bound (oldest-dropped), no real spawn.
pub(crate) fn drain_stderr<R: BufRead>(reader: R, buf: &AgentStderrState) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        buf.push_line(line);
    }
}

/// One backend's per-spawn fold over its child's stdout lines — the ONLY
/// wire-format-aware step in the reader thread. The harness has already stamped
/// the line's arrival (`at`) and bumped the heartbeat; the observer turns the line
/// into whatever its format carries: content deltas published on the hub, a
/// budget/reserve reading, a token sample for the rolling-minute meter.
///
/// `&self` (not `&mut self`): an observer holds `Arc`-shared cells, so the reader
/// thread needs no exclusive borrow and a test can drive the same fold over a
/// borrowed fixture.
pub trait LineObserver: Send {
    /// Fold one non-empty, trimmed stdout line that arrived at `at` (unix secs).
    fn observe(&self, line: &str, at: i64);
}

/// What a specific agent CLI supplies to the shared [`Harness`] — the whole
/// backend seam (spec-agents §10 phase 2). Three methods: the command after the
/// scope wrapper's `--`, the fail-closed pre-approval, and the per-line fold.
///
/// `Debug + Send + Sync` because the harness holds it behind an `Arc` shared with
/// every spawn's reader thread.
pub trait BackendFlavor: std::fmt::Debug + Send + Sync {
    /// Generate THIS agent's pre-approval BEFORE exec, fail-closed (§15): a
    /// headless agent errors out on the first un-approved tool, so an agent whose
    /// pre-approval can't be written must NOT be spawned. The `Err` becomes the
    /// [`SpawnError`] the drive loop surfaces as an operator alert — the flavor
    /// owns the message so it can name its own generator.
    fn generate_preapproval(&self, agent: &str) -> Result<AgentPaths, SpawnError>;

    /// The command argv (program first) that goes AFTER `systemd-run … --`, given
    /// the paths this spawn's pre-approval just wrote. The scope wrapper half is
    /// the harness's ([`scope_wrapper_argv`]) — this is only the backend's own
    /// invocation.
    fn command_argv(&self, paths: &AgentPaths) -> Vec<OsString>;

    /// Build this spawn's [`LineObserver`], installing any per-agent cell the
    /// flavor keeps (e.g. claude's account-wide reserve cell). Called once per
    /// spawn BEFORE the reader thread starts. `rate` is the harness's meter for
    /// this spawn — the flavor feeds it from whatever its wire format reports as
    /// a completed turn's token cost.
    fn new_observer(&self, agent: &str, rate: Arc<AgentRateState>) -> Box<dyn LineObserver>;
}

/// Tail an agent's stdout to EOF, bumping `health`'s heartbeat on every non-empty
/// line and handing each to `observer` for the backend's wire-format fold. Pure
/// over its `reader` / `now` seams: a test drives it with a scripted fixture + fake
/// clock, no real spawn.
///
/// Any line from the child is a sign of life → heartbeat, even if it carries no
/// renderable delta. The arrival is stamped ONCE per line and shared with the
/// observer, so the heartbeat and whatever the observer meters agree on one clock
/// reading (and a test clock advances once per line).
pub(crate) fn pump<R: BufRead>(
    reader: R,
    health: &AgentHealthState,
    observer: &dyn LineObserver,
    now: &dyn Fn() -> i64,
) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let at = now();
        health.touch(at);
        observer.observe(line, at);
    }
}

/// Fold each agent's `(tokens, requests)` trailing-minute window into the
/// fleet-wide `(tpm_used, rpm_used)`, saturating into the `RateState`'s `u32`
/// fields so a hot fleet can never overflow-panic. Pure — the fleet-wide summing
/// the live [`crate::drive_loop::LiveRate`] gate depends on, proven directly.
pub(crate) fn sum_rate_windows(per_agent: impl Iterator<Item = (u64, u64)>) -> (u32, u32) {
    let (mut tokens, mut reqs) = (0u64, 0u64);
    for (t, r) in per_agent {
        tokens = tokens.saturating_add(t);
        reqs = reqs.saturating_add(r);
    }
    let sat = |v: u64| v.min(u32::MAX as u64) as u32;
    (sat(tokens), sat(reqs))
}

/// The transient-scope base unit name for `agent`: `growlight-agent-<id>`,
/// sanitized to the systemd unit-name charset (anything outside `[A-Za-z0-9_-]`
/// becomes `-`). Agent ids are lowercase slugs already, so this is normally a
/// no-op; the sanitize is a defensive belt so an exotic id can never produce an
/// invalid `--unit=` (which would fail the whole spawn).
pub(crate) fn scope_base_name(agent: &str) -> String {
    let safe: String = agent
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("growlight-agent-{safe}")
}

/// The transient-scope base unit name for THIS spawn of `agent`, with a unique
/// per-spawn `generation` suffix: `growlight-agent-<id>-<gen>` (peer-isolation
/// hardening slice 002, `scope-name-reuse-race-on-reroll`).
///
/// The bare per-agent name ([`scope_base_name`]) is a pure function of the id, so
/// a clean within-item handoff (`Supervisor::roll` ⇒ no-backoff re-spawn ≤1s
/// later) reused it while systemd's async GC of the just-exited `--collect` scope
/// might not have finished — `systemd-run --unit=<same>` then fails *"unit already
/// exists"*, recorded as a non-zero exit ⇒ a spurious `AgentCrashed` + a backoff.
/// A monotonic generation makes every spawn's unit name distinct, so the
/// name-reuse window is closed structurally rather than papered over with a retry.
pub(crate) fn scope_base_name_gen(agent: &str, generation: u64) -> String {
    format!("{}-{generation}", scope_base_name(agent))
}

/// Build the `systemd-run` cap flags (the scope options BEFORE the `--`) that
/// GENTLY throttle an agent's build subtree without ever aborting it
/// (peer-isolation slice 002; human direction 2026-06-28): a low
/// `CARGO_BUILD_JOBS` env (fewer parallel `rustc` → lower peak RAM), a SOFT
/// `--property=MemoryHigh` (the kernel throttles + reclaims past it, never
/// OOM-kills), and a deprioritizing `--property=CPUWeight`. Deliberately NEVER
/// `MemoryMax` (the hard OOM-kill cap) nor a tight `TasksMax` (a `fork` EAGAIN) —
/// either would crash the `cargo build`/`test` the agent is blocked on. Each cap
/// is emitted only when configured (`None` ⇒ omitted), so an all-`None`
/// [`BuildCaps`] yields the un-throttled un-capped argv. Pure: the flag shape is
/// unit-asserted without a real `systemd-run`.
pub(crate) fn build_cap_args(caps: &BuildCaps) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(jobs) = caps.cargo_build_jobs {
        args.push(format!("--setenv=CARGO_BUILD_JOBS={jobs}").into());
    }
    if let Some(high) = &caps.memory_high {
        args.push(format!("--property=MemoryHigh={high}").into());
    }
    if let Some(weight) = caps.cpu_weight {
        args.push(format!("--property=CPUWeight={weight}").into());
    }
    args
}

/// Build the **wrapper half** of an agent spawn's argv — everything up to and
/// including the `--` separator, after which the backend's own
/// [`command_argv`](BackendFlavor::command_argv) is appended. This is the piece
/// that puts the child's whole `agent → cargo → rustc` process tree in a cgroup
/// SEPARATE from `softfig-growlightd.service` (incident
/// growlightd-resource-down-build, 2026-06-28: a building agent in the shared
/// service cgroup peaked at 4.6 GB → EAGAIN → growlightd caught a SIGTERM and,
/// being crash-restart-only, stayed down).
///
/// `systemd-run --user --scope --collect --unit=growlight-agent-<id>-<gen> <caps> --`:
/// - `--scope` (not `--service`) runs the command synchronously as our child,
///   inheriting our stdin/stdout/stderr — so the stdout tail still reads the
///   agent's output directly (the wrapper must not eat it).
/// - `--collect` garbage-collects the scope on exit, leaving no residue.
/// - `--unit=` names it per-spawn (a unique generation suffix, slice 002) so a
///   kill / re-roll / on-device cgroup check can address exactly this spawn's
///   scope, and a no-backoff re-roll never collides with the GC of the prior one.
/// - `<caps>` are the slice-002 GENTLE build throttle ([`build_cap_args`]):
///   scope options (so they apply before the command runs) that only SLOW a
///   build, never kill it. They MUST precede the `--`.
///
/// Pure: a unit test asserts the wrapping shape without a real `systemd-run`
/// (the on-device `/proc/<pid>/cgroup` check is a deferred §7b run).
pub(crate) fn scope_wrapper_argv(scope_base: &str, caps: &BuildCaps) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        "systemd-run".into(),
        "--user".into(),
        "--scope".into(),
        "--collect".into(),
        format!("--unit={scope_base}").into(),
    ];
    argv.extend(build_cap_args(caps));
    argv.push("--".into());
    argv
}

/// The full argv (program first) for one spawn: the [`scope_wrapper_argv`] half,
/// then the backend's own `command` after the `--`. The ONE place the two halves
/// are joined — [`Harness::spawn`] shells exactly this, so a backend's argv can be
/// asserted byte-for-byte by composing the same two production pieces (there is no
/// second, test-only join that could drift from the real one).
pub(crate) fn spawn_argv(
    scope_base: &str,
    caps: &BuildCaps,
    command: Vec<OsString>,
) -> Vec<OsString> {
    let mut argv = scope_wrapper_argv(scope_base, caps);
    argv.extend(command);
    argv
}

/// Build the `systemctl` argv that SIGKILLs an agent's whole transient scope —
/// every pid in the cgroup, so a `cargo`/`rustc` build subtree dies with the
/// agent. We kill the SCOPE, not just the `systemd-run` controller process: the
/// controller alone would leave the build subtree orphaned inside the scope.
/// Pure so the kill shape is unit-proven without a real scope. Shared with the
/// boot reconciler ([`crate::reconcile`]), which SIGKILLs stray scopes left by a
/// prior growlightd generation with the exact same kill shape.
pub(crate) fn scope_kill_argv(unit: &str) -> Vec<String> {
    vec![
        "--user".to_string(),
        "kill".to_string(),
        "--signal=SIGKILL".to_string(),
        unit.to_string(),
    ]
}

/// Build the `systemctl --user set-property --runtime <unit> …` argv that pushes
/// the **LIVE-applicable** GENTLE caps onto a RUNNING agent scope (peer-isolation
/// slice 003). Only the two *scope properties* are emitted — a `MemoryHigh` SOFT
/// throttle and a deprioritizing `CPUWeight`; `CARGO_BUILD_JOBS` is an **env var**,
/// not a scope property, so it is DELIBERATELY never here (it takes effect at the
/// next spawn, not live). `--runtime` keeps the change transient (it dies with the
/// scope, never persisted to a drop-in).
///
/// Returns `None` when neither live property is set — there is nothing to push, so
/// the caller shells nothing (an empty `set-property` would be a pointless call).
/// Pure: the argv shape is unit-asserted without a real `systemctl`. Stays
/// throttle-not-kill by construction — there is no `MemoryMax` arg to emit.
pub(crate) fn set_property_argv(
    unit: &str,
    memory_high: Option<&str>,
    cpu_weight: Option<u32>,
) -> Option<Vec<String>> {
    let mut props = Vec::new();
    if let Some(high) = memory_high {
        props.push(format!("MemoryHigh={high}"));
    }
    if let Some(weight) = cpu_weight {
        props.push(format!("CPUWeight={weight}"));
    }
    if props.is_empty() {
        return None; // nothing live to apply
    }
    let mut argv = vec![
        "--user".to_string(),
        "set-property".to_string(),
        "--runtime".to_string(),
        unit.to_string(),
    ];
    argv.extend(props);
    Some(argv)
}

/// Best-effort: push the live `MemoryHigh`/`CPUWeight` of `caps` onto the running
/// scope `unit` via `systemctl --user set-property --runtime` (slice 003). Returns
/// `true` only if a `set-property` actually ran and succeeded.
///
/// **Invariant 5: a failed live push is LOGGED and swallowed, never failing the
/// verb** (hardening slice 003 — the code previously swallowed *without* logging,
/// then the reply misreported it as "no scopes"). A push the running scope REJECTS
/// (a bad value, a permission error, a transient `systemctl`) is logged with the
/// failing unit + systemd's stderr and returns `false` — the next-spawn caps (the
/// shared cell) already carry the change, so the agent picks up the new throttle
/// when it (re-)spawns. The reply distinguishes this "targeted but failed" outcome
/// from "no scopes targeted" via the M-of-N counts (slice 004). The `None` argv
/// (nothing live to push — only `CARGO_BUILD_JOBS` would change) is NOT a failure
/// and is not logged. Must be called OUTSIDE the daemon lock (it shells a
/// subprocess that may block — the kill-safety lock-ordering discipline).
pub(crate) fn apply_set_property(unit: &str, caps: &BuildCaps) -> bool {
    let Some(argv) = set_property_argv(unit, caps.memory_high.as_deref(), caps.cpu_weight) else {
        return false; // only CARGO_BUILD_JOBS changed → nothing live to push (not a failure)
    };
    match Command::new("systemctl")
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            // Invariant 5: log + swallow (the persist path at server.rs already logs;
            // this matches it). The next-spawn caps still took the change.
            eprintln!(
                "growlightd set_resources: live set-property on {unit} failed (exit {:?}): {}; \
                 next-spawn caps still updated",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim(),
            );
            false
        }
        Err(e) => {
            eprintln!(
                "growlightd set_resources: could not run systemctl set-property on {unit} ({e}); \
                 next-spawn caps still updated"
            );
            false
        }
    }
}

/// Wall-clock Unix seconds for the live heartbeat / spawn stamps. The pure policy
/// stays time-injected; only this live binding reads the clock.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The killable handle for a live agent child (the [`AgentChild`] contract),
/// whichever backend spawned it. The child runs inside a per-agent transient scope
/// (`scope_unit`), so `kill` SIGKILLs the whole SCOPE cgroup — not just the
/// `systemd-run` controller — best effort and OUTSIDE the daemon lock; that takes
/// down any `cargo`/`rustc` build subtree too. The processes dying closes stdout,
/// so the reader thread reaps and records the exit; the `--collect` scope is then
/// GC'd once empty.
#[derive(Debug)]
pub(crate) struct ScopedChild {
    child: Arc<Mutex<Child>>,
    scope_unit: String,
}

impl AgentChild for ScopedChild {
    fn kill(&self) {
        // Kill the SCOPE first: `systemctl --user kill` reaches every pid in the
        // agent's cgroup, so the build subtree dies with the agent (the controller
        // alone would orphan it). Best-effort — a never-started or already-gone
        // scope just errors, which is fine.
        let _ = Command::new("systemctl")
            .args(scope_kill_argv(&self.scope_unit))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // Then reap the `systemd-run` controller handle directly (already-exited
        // ⇒ Err, fine). We do NOT wait() — the reader thread reaps on stdout EOF.
        // Called outside the daemon lock (incident 20260622).
        let _ = self.child.lock().unwrap().kill();
    }
}

/// The backend-agnostic supervision harness: spawns a [`BackendFlavor`]'s child
/// inside its own transient systemd user scope, tracks the per-agent health /
/// stderr / rate cells the drive loop reads, and owns the live scope + kill
/// registries the daemon addresses.
///
/// A concrete backend (e.g. [`crate::claude_backend::ClaudeBackend`]) is a thin
/// wrapper: it holds a `Harness` plus whatever wire-specific state its flavor
/// needs, and forwards its `AgentBackend`/health/rate/stderr surface here.
#[derive(Debug)]
pub struct Harness {
    /// The backend-specific half of every spawn, shared by `Arc` with each
    /// spawn's reader thread.
    flavor: Arc<dyn BackendFlavor>,
    /// The GENTLE per-agent build-resource caps (peer-isolation slice 002) spliced
    /// into every spawn's transient scope: a low `CARGO_BUILD_JOBS` + a SOFT
    /// `MemoryHigh` + a deprioritizing `CPUWeight`. They THROTTLE a building agent,
    /// never kill it (no `MemoryMax` / tight `TasksMax`).
    ///
    /// **Live (slice 003):** held behind a shared `Arc<Mutex<…>>` the daemon also
    /// holds, so the `set_resources` verb adjusts the throttle the NEXT spawn uses
    /// without a restart — [`spawn`](Harness::spawn) reads the *current* caps off
    /// this cell each time, never a value baked in at construction.
    build_caps: Arc<Mutex<BuildCaps>>,
    /// Per-agent health cells, keyed by agent id; re-spawn (re-roll) replaces the
    /// agent's cell with a fresh one.
    agents: Mutex<BTreeMap<String, Arc<AgentHealthState>>>,
    /// Per-agent rolling-minute rate meters, keyed by agent id; the live
    /// [`crate::drive_loop::LiveRate`] source sums these fleet-wide via
    /// [`rate_used`](Harness::rate_used) to feed admission's TPM/RPM gate
    /// (spec §7 second window). Re-spawn replaces the cell.
    rates: Mutex<BTreeMap<String, Arc<AgentRateState>>>,
    /// Per-agent stderr ring buffers (crash-diagnostics slice 001), keyed by agent
    /// id; the reader thread drains the child's piped stderr into the agent's cell,
    /// and [`stderr_tail`](Harness::stderr_tail) reads the tail when the drive loop
    /// enriches an `AgentCrashed` alert. Re-spawn (re-roll) replaces the cell, so
    /// the tail is always the CURRENT generation's — the same lifecycle as
    /// `agents`/`rates`. In-memory + ephemeral by design (no `stderr.log`).
    stderrs: Mutex<BTreeMap<String, Arc<AgentStderrState>>>,
    /// Monotonic per-spawn generation (slice 002): each spawn bumps it so the
    /// transient-scope `--unit=` name (`growlight-agent-<id>-<gen>`) is unique,
    /// closing the re-roll-vs-GC name-reuse race structurally.
    scope_gen: AtomicU64,
    /// The live agent→running-scope-unit registry (slice 002), shared by `Arc`
    /// with the daemon so `set_resources` addresses the *actually-running* scope
    /// units (whose names now carry a generation), not a re-derived roster name.
    /// A spawn records `agent → growlight-agent-<id>-<gen>.scope`; the reader
    /// thread removes it on exit (guarded by unit, so a re-roll's newer entry is
    /// never clobbered). An entry is the live, current scope for that agent.
    live_scopes: Arc<Mutex<BTreeMap<String, String>>>,
    /// The live agent→kill-handle registry (audit slice 005), shared by `Arc`
    /// with the daemon so `force_stop --hard-kill` / `request_restart` reach the
    /// agent the supervisor is actually running. Each spawn records a
    /// [`LiveKill`] here (its [`ScopedChild`] handle + the `.scope` token);
    /// [`Daemon::hard_kill_agent`](crate::daemon::Daemon::hard_kill_agent) takes
    /// the handle out under this registry's lock and `kill`s it OUTSIDE the lock.
    /// The reader thread removes the entry on exit, guarded by the scope token so
    /// a re-roll's newer handle is never clobbered — the exact lifecycle of
    /// `live_scopes`, carrying the kill handle alongside the scope name.
    pub(crate) kill_handles: Arc<Mutex<BTreeMap<String, LiveKill>>>,
}

impl Harness {
    /// A harness supervising `flavor`'s children, capping each spawn's scope from
    /// the shared `build_caps` cell and recording it in the daemon-shared
    /// `live_scopes` / `kill_handles` registries.
    pub fn new(
        flavor: Arc<dyn BackendFlavor>,
        build_caps: Arc<Mutex<BuildCaps>>,
        live_scopes: Arc<Mutex<BTreeMap<String, String>>>,
        kill_handles: Arc<Mutex<BTreeMap<String, LiveKill>>>,
    ) -> Self {
        Self {
            flavor,
            build_caps,
            agents: Mutex::new(BTreeMap::new()),
            rates: Mutex::new(BTreeMap::new()),
            stderrs: Mutex::new(BTreeMap::new()),
            scope_gen: AtomicU64::new(0),
            live_scopes,
            kill_handles,
        }
    }

    /// `agent`'s current health (heartbeat-or-exit), or `None` if this harness
    /// never spawned it. The drive loop calls this each cycle to feed
    /// [`crate::supervisor::Supervisor::poll`].
    pub fn health(&self, agent: &str) -> Option<AgentHealth> {
        self.agents.lock().unwrap().get(agent).map(|s| s.observe())
    }

    /// The **fleet-wide** rolling-minute `(tpm_used, rpm_used)` at `now`: the sum
    /// across every agent's rate meter of the tokens/requests observed in the
    /// trailing minute. Feeds the live [`crate::drive_loop::LiveRate`] source's
    /// `used` fields, which the admission governor checks against the per-device
    /// limits (spec §7). Saturating into `u32` so a hot fleet can never overflow
    /// the `RateState` fields. A retired agent's cell lingers in the map but its
    /// samples have aged out of the window, so it contributes 0 — the rolling
    /// window is the forget.
    pub fn rate_used(&self, now: i64) -> (u32, u32) {
        sum_rate_windows(self.rates.lock().unwrap().values().map(|c| c.window(now)))
    }

    /// `agent`'s most recent stderr lines (up to [`STDERR_ALERT_TAIL_LINES`],
    /// oldest→newest), or an empty vec if it was never spawned or has emitted no
    /// stderr (crash-diagnostics slice 001). The drive loop reads this to enrich an
    /// `AgentCrashed` alert with the crash reason. Ephemeral: a growlightd restart
    /// loses the buffer — the alert, not a file, carries the diagnostic forward.
    pub fn stderr_tail(&self, agent: &str) -> Vec<String> {
        self.stderrs
            .lock()
            .unwrap()
            .get(agent)
            .map(|s| s.tail(STDERR_ALERT_TAIL_LINES))
            .unwrap_or_default()
    }

    /// Spawn `spec`'s agent: generate its pre-approval fail-closed, launch the
    /// flavor's command inside a fresh transient user scope, install this spawn's
    /// observation cells, register its scope + kill handle, and start the two
    /// detached reader threads (stdout → observer, stderr → ring).
    ///
    /// The [`AgentBackend`] contract — see that trait for the supervisor's side.
    pub fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        // §15 fail-closed pre-approval: generate THIS agent's config BEFORE exec.
        // A headless agent errors out on the first un-approved tool, so an agent
        // whose pre-approval can't be generated must NOT be spawned — the Err
        // becomes a SpawnError the drive loop surfaces as an operator alert (never
        // a spawned-but-doomed session). Regenerated every spawn, so a re-roll
        // re-lays the current pre-approval. The generated paths are the spec's
        // (derived identically at assembly); we shell the freshly-written ones.
        let paths = self.flavor.generate_preapproval(&spec.agent)?;
        // Launch wrapped in a per-agent transient systemd user scope so the
        // child's whole `agent → cargo → rustc` tree is in its OWN cgroup, not
        // `softfig-growlightd.service`'s (incident growlightd-resource-down-build).
        // `--scope` inherits our stdio, so the stdout pipe below still tails the
        // child's output directly. A missing/failed `systemd-run` fails the spawn
        // closed (no isolation ⇒ no spawn) — the safe direction.
        // Read the CURRENT caps off the shared cell (slice 003): a `set_resources`
        // since the last spawn is picked up here — the next-spawn half of the
        // now-vs-next-spawn surface. Cloned out so the brief lock is released
        // before the (blocking) spawn.
        let caps = self.build_caps.lock().unwrap().clone();
        // Unique per-spawn scope unit (slice 002): a monotonic generation suffix so a
        // no-backoff within-item re-roll never reuses a name systemd may not have
        // GC'd yet. The full `.scope` unit is stored on the child (kill addresses it)
        // and recorded in the shared live-scope registry (set_resources targets it).
        let generation = self.scope_gen.fetch_add(1, Ordering::Relaxed);
        let scope_base = scope_base_name_gen(&spec.agent, generation);
        let scope_unit = format!("{scope_base}.scope");
        let argv = spawn_argv(&scope_base, &caps, self.flavor.command_argv(&paths));
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // stderr is PIPED and drained into a bounded in-memory ring
            // (crash-diagnostics slice 001), so a crash carries its reason — not just
            // a non-zero exit (the gap that left the 2026-07-01 wifi crash loop only
            // inferable). The old deadlock worry (an *unread* pipe fills and blocks
            // the child) does not apply: the reader thread below drains it
            // continuously, the exact deadlock-safe shape the stdout `pump` uses.
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                SpawnError(format!(
                    "failed to launch agent {} in a transient scope (systemd-run): {e}",
                    spec.agent
                ))
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SpawnError("child stdout was not captured".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SpawnError("child stderr was not captured".into()))?;

        let state = Arc::new(AgentHealthState::new(unix_now()));
        self.agents
            .lock()
            .unwrap()
            .insert(spec.agent.clone(), Arc::clone(&state));

        let rate = Arc::new(AgentRateState::default());
        self.rates
            .lock()
            .unwrap()
            .insert(spec.agent.clone(), Arc::clone(&rate));

        // Fresh stderr ring for this spawn (crash-diagnostics slice 001),
        // overwriting any prior generation's — so `stderr_tail` always reads the
        // CURRENT child's reason. Drained by the dedicated reader thread below.
        let stderr_ring = Arc::new(AgentStderrState::default());
        self.stderrs
            .lock()
            .unwrap()
            .insert(spec.agent.clone(), Arc::clone(&stderr_ring));

        // This spawn's wire-format fold. Built BEFORE the reader thread starts, so
        // the flavor's own per-agent cell (e.g. claude's reserve) is installed and
        // readable the moment the agent is registered — the same replace-on-re-roll
        // lifecycle as the harness cells above.
        let observer = self.flavor.new_observer(&spec.agent, Arc::clone(&rate));

        // Record this spawn's running scope (slice 002), overwriting any prior
        // generation for the agent — `set_resources` pushes its live `set-property`
        // onto exactly the running units, and the reader thread below drops this
        // entry on exit (guarded by unit, so a re-roll's newer entry survives).
        self.live_scopes
            .lock()
            .unwrap()
            .insert(spec.agent.clone(), scope_unit.clone());

        // The child is shared with the reader thread for reaping. While the child
        // lives, the reader is blocked in `lines()` on stdout (it holds NO lock),
        // so `kill` can always take the lock to SIGKILL; the reader only locks the
        // child AFTER stdout EOF (the child is already exiting), so `wait` returns
        // promptly and there is no kill/reap deadlock.
        let child = Arc::new(Mutex::new(child));

        // Register this spawn's kill handle in the daemon-shared registry (audit
        // slice 005), so `force_stop --hard-kill` / `request_restart` reach this
        // running agent — the registry the live fleet actually populates. It
        // shares the SAME controller handle + scope as the handle returned to the
        // supervisor below (killing via either is idempotent/best-effort, since
        // `ScopedChild::kill` is a no-op on an already-gone scope/child). Keyed by
        // agent, so a re-roll OVERWRITES it: a hard-kill always targets the
        // agent's current child. The reader thread removes it on exit, guarded by
        // the scope token (like `live_scopes`).
        self.kill_handles.lock().unwrap().insert(
            spec.agent.clone(),
            LiveKill::new(
                scope_unit.clone(),
                Box::new(ScopedChild {
                    child: Arc::clone(&child),
                    scope_unit: scope_unit.clone(),
                }),
            ),
        );

        // Drain the child's stderr into its bounded in-memory ring (crash
        // diagnostics slice 001) — a second detached reader, the same deadlock-safe
        // shape as the stdout pump: a blocked `lines()` reader holds no lock, so the
        // actively-drained pipe never fills. The ring is dropped when the agent's
        // `stderrs` entry is replaced on its next re-roll; the crash tail is read
        // into the alert before then.
        thread::spawn(move || {
            drain_stderr(BufReader::new(stderr), &stderr_ring);
        });

        let agent = spec.agent.clone();
        let reader_state = Arc::clone(&state);
        let reader_child = Arc::clone(&child);
        let reader_live_scopes = Arc::clone(&self.live_scopes);
        let reader_kill_handles = Arc::clone(&self.kill_handles);
        let reader_scope_unit = scope_unit.clone();
        thread::spawn(move || {
            pump(
                BufReader::new(stdout),
                &reader_state,
                observer.as_ref(),
                &|| unix_now(),
            );
            // stdout closed → the child is ending; reap it for the exit code.
            let code = reader_child
                .lock()
                .unwrap()
                .wait()
                .ok()
                .and_then(|s| s.code())
                .unwrap_or(UNKNOWN_EXIT);
            reader_state.record_exit(code);
            // Drop this spawn's live-scope entry — but only if it is still THIS
            // generation's unit: a re-roll may already have recorded a newer one for
            // the same agent, which must survive (slice 002).
            let mut scopes = reader_live_scopes.lock().unwrap();
            if scopes.get(&agent).map(String::as_str) == Some(reader_scope_unit.as_str()) {
                scopes.remove(&agent);
            }
            drop(scopes);
            // Drop this spawn's kill handle too (audit slice 005), under the SAME
            // scope-token guard so a re-roll's newer handle survives this older
            // generation's late exit. A hard-kill may already have taken it out
            // (then this is a no-op); either way the entry never outlives the
            // process. Sequential lock, never nested with `live_scopes`.
            let mut handles = reader_kill_handles.lock().unwrap();
            if handles.get(&agent).map(|k| k.scope_token.as_str())
                == Some(reader_scope_unit.as_str())
            {
                handles.remove(&agent);
            }
        });

        Ok(Box::new(ScopedChild { child, scope_unit }))
    }
}

/// The harness IS the [`AgentBackend`] once a flavor is bound — a concrete backend
/// forwards its own `impl` here (see [`crate::claude_backend`]).
impl AgentBackend for Harness {
    fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
        Harness::spawn(self, spec)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn drain_stderr_rings_the_tail_and_drops_the_oldest() {
        // More lines than the ring holds: the oldest must fall off, the newest stay.
        let total = STDERR_RING_MAX_LINES + 5;
        let script: String = (0..total).map(|i| format!("line {i}\n")).collect();
        let ring = AgentStderrState::default();
        drain_stderr(Cursor::new(script), &ring);

        // Bounded: only the last STDERR_RING_MAX_LINES survive (oldest dropped).
        let all = ring.tail(usize::MAX);
        assert_eq!(all.len(), STDERR_RING_MAX_LINES, "ring is bounded");
        assert_eq!(all.first().unwrap(), &format!("line {}", total - STDERR_RING_MAX_LINES));
        assert_eq!(all.last().unwrap(), &format!("line {}", total - 1));

        // The alert tail is the last N, oldest→newest.
        let tail = ring.tail(3);
        assert_eq!(
            tail,
            vec![
                format!("line {}", total - 3),
                format!("line {}", total - 2),
                format!("line {}", total - 1),
            ],
        );
    }

    #[test]
    fn drain_stderr_skips_blank_lines_and_truncates_a_giant_line() {
        let mut script = String::from("real error: connection reset\n");
        script.push('\n'); // a blank line — no diagnostic, skipped
        script.push_str("   \n"); // whitespace-only — also skipped
        script.push_str(&"x".repeat(STDERR_LINE_MAX_CHARS + 50));
        script.push('\n');
        let ring = AgentStderrState::default();
        drain_stderr(Cursor::new(script), &ring);

        let tail = ring.tail(usize::MAX);
        assert_eq!(tail.len(), 2, "the two blank lines are dropped");
        assert_eq!(tail[0], "real error: connection reset");
        // The over-long line is char-truncated with an ellipsis, never panicking.
        assert_eq!(tail[1].chars().count(), STDERR_LINE_MAX_CHARS + 1);
        assert!(tail[1].ends_with('…'));
    }

    #[test]
    fn observe_reports_a_recorded_exit_over_the_heartbeat() {
        let state = AgentHealthState::new(42);
        assert_eq!(state.observe(), AgentHealth::Alive { last_active: 42 });
        // Once the reader thread reaps a non-zero exit, health flips to Exited
        // (the supervisor classifies that as a crash).
        state.record_exit(1);
        assert_eq!(state.observe(), AgentHealth::Exited { code: 1 });
    }

    #[test]
    fn agent_rate_meter_sums_within_the_minute_and_expires_old_samples() {
        let m = AgentRateState::default();
        // Two turns inside the same minute: tokens sum, two requests.
        m.record(100, 40_000);
        m.record(130, 60_000);
        assert_eq!(m.window(150), (100_000, 2), "both samples within the minute");
        // At now=180 the trailing minute is (120, 180]: the t=100 sample has aged
        // out, only the t=130 one remains.
        assert_eq!(m.window(180), (60_000, 1), "the t=100 sample expired");
        // Long past both → empty.
        assert_eq!(m.window(1000), (0, 0));
    }

    #[test]
    fn sum_rate_windows_folds_agents_fleet_wide_and_saturates() {
        // Two agents' trailing-minute windows sum into the fleet-wide reading.
        assert_eq!(
            sum_rate_windows([(30_000u64, 2u64), (50_000, 3)].into_iter()),
            (80_000, 5)
        );
        // No agents → a fresh fleet reads zero (admits freely).
        assert_eq!(sum_rate_windows(std::iter::empty()), (0, 0));
        // A pathological over-u32 fleet sum saturates instead of overflow-panicking.
        assert_eq!(
            sum_rate_windows([(u32::MAX as u64, 1), (u32::MAX as u64, 1)].into_iter()),
            (u32::MAX, 2)
        );
    }

    #[test]
    fn build_cap_args_emits_only_the_configured_gentle_caps() {
        // The default caps render as the three GENTLE flags, in order: a low
        // CARGO_BUILD_JOBS env + a SOFT MemoryHigh + a deprioritizing CPUWeight.
        assert_eq!(
            build_cap_args(&BuildCaps::default()),
            vec![
                OsString::from("--setenv=CARGO_BUILD_JOBS=2"),
                OsString::from("--property=MemoryHigh=3G"),
                OsString::from("--property=CPUWeight=50"),
            ]
        );
        // None of them is ever a HARD kill cap (the throttle-not-kill contract).
        assert!(
            !build_cap_args(&BuildCaps::default())
                .iter()
                .any(|a| a.to_string_lossy().contains("MemoryMax")
                    || a.to_string_lossy().contains("TasksMax")),
            "caps must THROTTLE, never KILL: no MemoryMax/TasksMax",
        );
        // An all-None BuildCaps emits NO flags → the un-throttled slice-001 argv.
        let none = BuildCaps {
            cargo_build_jobs: None,
            memory_high: None,
            cpu_weight: None,
        };
        assert!(build_cap_args(&none).is_empty());
        // A partial cap emits only what's set.
        let partial = BuildCaps {
            cargo_build_jobs: None,
            memory_high: Some("70%".to_string()),
            cpu_weight: None,
        };
        assert_eq!(
            build_cap_args(&partial),
            vec![OsString::from("--property=MemoryHigh=70%")]
        );
    }

    #[test]
    fn scope_base_name_is_per_agent_and_sanitized() {
        assert_eq!(scope_base_name("a"), "growlight-agent-a");
        // A slug carrying chars outside the systemd unit-name set is sanitized to
        // `-` so the `--unit=` can never be rejected (which would fail the spawn).
        assert_eq!(
            scope_base_name("two agents/x"),
            "growlight-agent-two-agents-x"
        );
    }

    #[test]
    fn scope_base_name_gen_is_unique_per_spawn_generation() {
        // slice 002: the per-spawn generation suffix makes the scope unit name
        // distinct on every spawn, so a no-backoff within-item re-roll never reuses
        // a name systemd may not have GC'd yet (the spurious-crash race).
        assert_eq!(scope_base_name_gen("a", 0), "growlight-agent-a-0");
        assert_eq!(scope_base_name_gen("a", 1), "growlight-agent-a-1");
        assert_ne!(
            scope_base_name_gen("a", 0),
            scope_base_name_gen("a", 1),
            "two generations of the same agent never collide",
        );
        // The agent portion is still sanitized (the defensive belt under the suffix).
        assert_eq!(scope_base_name_gen("two agents/x", 3), "growlight-agent-two-agents-x-3");
    }

    #[test]
    fn scope_kill_argv_sigkills_the_whole_scope_cgroup() {
        // Killing the SCOPE (not just the controller) reaches every pid in the
        // agent's cgroup, so a build subtree dies with the agent.
        assert_eq!(
            scope_kill_argv("growlight-agent-a1.scope"),
            vec![
                "--user".to_string(),
                "kill".to_string(),
                "--signal=SIGKILL".to_string(),
                "growlight-agent-a1.scope".to_string(),
            ]
        );
    }

    #[test]
    fn set_property_argv_emits_only_the_live_scope_properties() {
        let unit = "growlight-agent-a1.scope";

        // Both live properties → a `--runtime set-property` carrying MemoryHigh +
        // CPUWeight, in a stable order. CARGO_BUILD_JOBS is NEVER here (it is an env
        // var, applied at next spawn — the now-vs-next-spawn split).
        assert_eq!(
            set_property_argv(unit, Some("3G"), Some(50)),
            Some(vec![
                "--user".to_string(),
                "set-property".to_string(),
                "--runtime".to_string(),
                unit.to_string(),
                "MemoryHigh=3G".to_string(),
                "CPUWeight=50".to_string(),
            ]),
        );
        assert!(
            !set_property_argv(unit, Some("3G"), Some(50))
                .unwrap()
                .iter()
                .any(|a| a.contains("CARGO_BUILD_JOBS") || a.contains("MemoryMax")),
            "live set-property never carries the env var nor a hard MemoryMax cap",
        );

        // Only one property set → only that one is pushed.
        assert_eq!(
            set_property_argv(unit, None, Some(80)),
            Some(vec![
                "--user".to_string(),
                "set-property".to_string(),
                "--runtime".to_string(),
                unit.to_string(),
                "CPUWeight=80".to_string(),
            ]),
        );

        // Neither live property → None (nothing to push; the caller shells nothing).
        // This is the build-jobs-only change: a live `set-property` would be empty.
        assert_eq!(set_property_argv(unit, None, None), None);
    }

    #[test]
    fn scope_wrapper_argv_is_a_collected_user_scope_ending_in_the_separator() {
        // The harness's half of every spawn, whichever backend supplies the command:
        // a `--collect`ed transient USER scope named for this spawn's generation,
        // then the gentle caps (scope options, so BEFORE the `--`), then the `--`.
        let argv = scope_wrapper_argv(&scope_base_name_gen("a1", 7), &BuildCaps::default());
        let s: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            s,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "--collect",
                "--unit=growlight-agent-a1-7",
                "--setenv=CARGO_BUILD_JOBS=2",
                "--property=MemoryHigh=3G",
                "--property=CPUWeight=50",
                "--",
            ],
        );
    }

    #[test]
    fn spawn_argv_joins_the_wrapper_and_the_backends_command_at_the_separator() {
        // `spawn_argv` is the ONE join `Harness::spawn` shells, so a backend's full
        // argv can be asserted byte-for-byte (see the claude golden test). The
        // backend's command lands immediately after the `--`, untouched.
        let argv = spawn_argv(
            &scope_base_name_gen("a1", 7),
            &BuildCaps::default(),
            vec![OsString::from("some-agent"), OsString::from("--flag")],
        );
        let s: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        let sep = s.iter().position(|a| a == "--").expect("a `--` separator");
        assert_eq!(&s[sep + 1..], &["some-agent", "--flag"]);
        assert_eq!(
            &s[..sep],
            &scope_wrapper_argv(&scope_base_name_gen("a1", 7), &BuildCaps::default())
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()[..sep],
            "the wrapper half is unchanged by the join",
        );
    }
}
