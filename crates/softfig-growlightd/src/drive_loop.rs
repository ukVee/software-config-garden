//! The orchestration **drive loop** (drive-loop slice 002) — the thin coordinator
//! that turns the proven phase 3–6 pure cores into a running fleet
//! (spec-growlight-orchestrator §6 scheduler, §7 admission, §8 control, §15
//! operational must-haves).
//!
//! ## What this is (and isn't)
//!
//! [`DriveLoop::tick`] is the daemon's per-cycle coordinator. It instantiates
//! nothing new — it *binds* the existing cores: the pure scheduler
//! ([`crate::scheduler::pick`] / [`parked`]), the [`Supervisor`] (which itself
//! owns the [`crate::admission::AdmissionGovernor`] and the live
//! [`crate::supervisor::AgentBackend`]), and the daemon's control state
//! ([`Daemon::take_pending_stop`] / [`Daemon::drain_inject_lane`] /
//! [`Daemon::is_paused`]). Each tick, for the configured fleet:
//!
//! 1. **Honor control** at the per-agent boundary (spec §8): a pending boundary
//!    stop (`stop_after_slice` / `stop_after_iteration`) is read once and the
//!    agent retired when it next reaches its boundary; the boundary-async inject
//!    lane is drained (delivered at the agent's next baton, never mid-iteration);
//!    `pause` gates admission so a paused fleet starts and rolls nothing.
//! 2. **Observe + re-roll** (spec §15): each agent's [`AgentHealth`] feeds
//!    [`Supervisor::poll`]; a crash surfaces a [`NotifyEvent::AgentCrashed`] and
//!    schedules a capped-backoff re-roll, performed by [`Supervisor::tick`].
//! 3. **Schedule + admit + spawn** (spec §6/§7): the [`Snapshot`] picks each idle
//!    member's next workable part (pinned-with-fallback, pivot-on-block); an
//!    admitted [`Intent::Start`](crate::admission::Intent) spawns it via the live
//!    backend under the per-device cap, a queued/refused one is held.
//!
//! The hard logic already exists and is unit-proven in isolation; this loop is the
//! thin binding around it. The live data sources are **default-deferred seams**,
//! exactly like [`crate::leases::ThrashClear`] / [`crate::notify_dispatch::BusEmit`]:
//!
//! - [`QueueSource`] — the live impl pulls keeperd's per-queue managed regions;
//!   wiring that pull is `growlight-wire-loose-ends`.
//! - [`BudgetSampleSource`] — the live impl is the per-agent
//!   [`ClaudeBackend`] budget cell (slice 003); each tick the loop folds every
//!   agent's reading into its **owned** [`UsageAggregator`] and gates admission on
//!   the aggregate. [`RateSource`] feeds admission's second (rate) gate — live
//!   feed is `growlight-wire-loose-ends`, [`PermissiveRate`] until then.
//! - [`AgentHealthSource`] — implemented over [`crate::claude_backend::ClaudeBackend`]
//!   (slice 001), so the live loop reads real `stream-json` heartbeats.
//!
//! Keeping the sources behind seams keeps `tick` provable over fakes (scripted
//! queues / budget / health, the slice-001 fake backend) with **no real `claude`
//! spawn**, and lets the live assembly land in the slices that own each source.
//!
//! ## Time
//!
//! [`DriveLoop::tick`] takes `now` (injected Unix seconds), like every pure core;
//! only [`spawn_drive_loop`]'s live thread reads the wall clock.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::admission::{BudgetUsage, RateState};
use crate::claude_backend::ClaudeBackend;
use crate::config::RateLimits;
use crate::daemon::Daemon;
use crate::notifications::NotifyEvent;
use crate::notify_dispatch::NotifyDispatcher;
use crate::scheduler::{classify_queue, parked, pick, QueueState, Snapshot};
use crate::state::State;
use crate::supervisor::{
    AgentHealth, AgentSpec, PollOutcome, RerollOutcome, StartOutcome, Supervisor,
};
use crate::usage::{UsageAggregator, UsageSample};

/// How often the live drive loop ticks: schedule, observe health, honor control,
/// re-roll. Agents run for minutes per session, so a ~1s cadence is ample — this
/// is not a hot path (mirrors [`crate::bus::BUS_POLL_MS`]).
pub const DRIVE_POLL_MS: u64 = 1_000;

/// How long the device must stay offline before the sustained-outage alert pages the
/// human (network-failsafe slice 003). Below this, an offline stretch is a BLIP: the
/// pre-spawn gate holds spawns quietly and NOTHING pages — the whole point (the
/// 2026-07-01 crash loop paged every ~30min). Past it, exactly one
/// [`NotifyEvent::NetworkOffline`](crate::notifications::NotifyEvent::NetworkOffline)
/// fires, cleared by a `NetworkRecovered` on reconnect. A few minutes: long enough to
/// ride out a normal wifi hiccup, short enough that a real outage still reaches the
/// human.
pub const OFFLINE_ALERT_THRESHOLD_SECS: i64 = 180;

/// The seam the loop reads the current multi-queue [`Snapshot`] through. The
/// production impl pulls keeperd's per-queue managed regions (the `queue` /
/// `queue:<name>` item tables) — deferred to `growlight-wire-loose-ends`; a test
/// injects a fixed snapshot.
pub trait QueueSource: Send + Sync + fmt::Debug {
    /// The current view of every queue the fleet can draw from, in fallback order.
    fn snapshot(&self) -> Snapshot;
}

/// The seam the loop **claims** a picked part through before spawning its agent
/// — the WRITE counterpart to [`QueueSource`]'s read. Marking the part `active`
/// in keeperd's queue table is what closes the fallback double-assignment window
/// across ticks: once claimed, the next [`snapshot`](QueueSource::snapshot) shows
/// the part `active`, so every other agent's fallback [`pick`] flows past it. The
/// claim **gates** the spawn — it is issued between admission admitting and the
/// backend spawning ([`Supervisor::start_claiming`](crate::supervisor::Supervisor::start_claiming))
/// — so a claim that cannot be confirmed never leaves an agent running on an
/// unclaimed part. The production impl is a `set_item_status(... active)` write
/// over `call_reconnecting` ([`crate::claim::KeeperdPartClaimer`]); a test injects
/// a scripted claim result.
pub trait PartClaimer: Send + Sync + fmt::Debug {
    /// Claim `(queue, part)` for `holder` (the agent about to spawn) — mark it
    /// `active` in keeperd's queue table, stamped with the claimant's id so
    /// keeperd's holder-identity CAS refuses a later claim of the same part by a
    /// *different* agent (milestone #40, defense-in-depth behind the loop's own
    /// `assignments` dedup). `Ok(())` means the part is now ours (idempotent:
    /// re-claiming a part this agent already holds `active` is a no-op success).
    /// `Err(reason)` means the claim could NOT be confirmed (keeperd refused —
    /// another part is active OR the part is held by a different agent — was
    /// unreachable, or the write was ambiguous): the loop must NOT spawn on it.
    fn claim(&self, queue: &str, part: &str, holder: &str) -> Result<(), String>;
}

/// The seam the loop **item-parks** a part through when its member exits
/// `BLOCKED_ON_HUMAN` / `STUCK` — the WRITE that records the block on the ITEM
/// rather than by sticking the member on its slot. The sibling of
/// [`PartClaimer`]: a claim writes `active` *before* a spawn; this writes
/// `blocked` *after* a human-block exit. Marking the part `blocked` in keeperd's
/// queue table is what makes the next [`snapshot`](QueueSource::snapshot)'s
/// [`classify_queue`](crate::scheduler::classify_queue) park that queue, so the
/// just-released member's [`pick`] pivots past it to other workable work
/// (pivot-on-block, spec §6) and the blocked head surfaces to the §9 alert. Unlike
/// a claim it does NOT gate anything — the member has already exited and been
/// released — so it is **fail-soft**: a write that cannot be confirmed leaves the
/// part `active`, and the next tick retries the block when the freed member
/// re-resolves to (and re-blocks) that still-`active` part. The production impl is
/// a `set_item_status(... blocked)` write over `call_reconnecting`
/// ([`crate::claim::KeeperdItemParker`]); a test scripts the result.
pub trait ItemParker: Send + Sync + fmt::Debug {
    /// Mark `(queue, part)` `blocked` in keeperd's queue table. `Ok(())` means the
    /// block landed (idempotent: re-blocking an already-`blocked` part is a no-op
    /// success). `Err(reason)` means it could not be confirmed — fail-soft: the
    /// member is already released, the local snapshot is item-parked regardless (so
    /// this tick still pivots + alerts), and the next tick retries.
    fn park_item(&self, queue: &str, part: &str) -> Result<(), String>;
}

/// The seam the loop reads each agent's latest reading of the **shared** account
/// budget pool through, to fold into the loop's owned cross-agent
/// [`UsageAggregator`]. The aggregate then gates admission and fires the §9 usage
/// alert. Implemented over the live [`ClaudeBackend`]'s per-agent budget cell
/// (drive-loop slice 003); a test injects per-agent readings.
pub trait BudgetSampleSource: Send + Sync + fmt::Debug {
    /// `agent`'s latest reading of the shared pool, or `None` if it has not
    /// reported a parseable reserve yet (so the aggregator skips it this tick).
    fn budget(&self, agent: &str) -> Option<BudgetUsage>;
}

impl BudgetSampleSource for Arc<ClaudeBackend> {
    fn budget(&self, agent: &str) -> Option<BudgetUsage> {
        // Disambiguate from this trait method: call the inherent one on the
        // backed `ClaudeBackend`.
        self.as_ref().budget(agent)
    }
}

/// The seam the loop reads the per-minute **rate** (TPM/RPM) through, admission's
/// second gate alongside the budget aggregate. The loop is the clock authority —
/// it passes the tick's `now` so the source can sum its **rolling** trailing
/// minute (the meter samples and the read share one unix-seconds clock). The live
/// feed is [`LiveRate`] over the backend's per-agent meters (`growlight-live-fleet`
/// slice 006); [`PermissiveRate`] is the test/default seam that grants headroom.
pub trait RateSource: Send + Sync + fmt::Debug {
    /// The rolling-minute rate reading as of `now` (unix seconds).
    fn rate(&self, now: i64) -> RateState;
}

/// The default/test [`RateSource`]: generous per-minute headroom so the rate gate
/// never refuses. The production assembly wires [`LiveRate`] instead (slice 006);
/// this stays as the `DriveLoop` default seam and the fixture a test injects when
/// it wants the rate gate out of the way.
#[derive(Debug, Default, Clone, Copy)]
pub struct PermissiveRate;

impl RateSource for PermissiveRate {
    fn rate(&self, _now: i64) -> RateState {
        RateState {
            tpm_used: 0,
            rpm_used: 0,
            tpm_limit: u32::MAX,
            rpm_limit: u32::MAX,
            tpm_per_agent: 0,
            rpm_per_agent: 0,
        }
    }
}

/// The live [`RateSource`] (slice 006): admission's second window from real data.
/// Reads the **fleet-wide** rolling-minute `(tpm_used, rpm_used)` off the
/// [`ClaudeBackend`]'s per-agent meters (each fed from its agents' `result`-line
/// `usage` tokens + a request tick — see [`ClaudeBackend::rate_used`]) and pairs
/// it with the per-device [`RateLimits`]. This is what replaces [`PermissiveRate`]
/// in [`crate::fleet::assemble_fleet`], so the TPM/RPM burst gate actually gates
/// (spec §7 "two windows, not one"; §15). Holds an `Arc` clone of the same backend
/// the supervisor spawns through and the budget/health sources read — one backend,
/// one set of cells.
#[derive(Debug)]
pub struct LiveRate {
    backend: Arc<ClaudeBackend>,
    limits: RateLimits,
}

impl LiveRate {
    /// Build the live rate source over `backend`'s meters and the per-device
    /// `limits` (the account TPM/RPM ceilings + per-agent burst headroom).
    pub fn new(backend: Arc<ClaudeBackend>, limits: RateLimits) -> Self {
        Self { backend, limits }
    }
}

impl RateSource for LiveRate {
    fn rate(&self, now: i64) -> RateState {
        let (tpm_used, rpm_used) = self.backend.rate_used(now);
        RateState {
            tpm_used,
            rpm_used,
            tpm_limit: self.limits.tpm_limit,
            rpm_limit: self.limits.rpm_limit,
            tpm_per_agent: self.limits.tpm_per_agent,
            rpm_per_agent: self.limits.rpm_per_agent,
        }
    }
}

/// The seam the loop probes network reachability through BEFORE it spawns a
/// headless `claude -p` (network-failsafe slice 001). A peer launched with no
/// route to the API errors out instantly on its first request; the supervisor then
/// misreads that as a crash — punitive backoff + a false `AgentCrashed` page — so a
/// flaky link becomes a crash loop that makes no progress and pages the human (the
/// 2026-07-01 m5b-hardening incident). The gate turns "offline at spawn" into a
/// HOLD instead: no spawn, no backoff, no crash count, and the ~1s tick cadence
/// retries until the link returns.
///
/// It is an *optimisation* layered over slice 002's mid-session backstop, not a
/// lock — a drop that kills a peer mid-session is unpreventable here, and a probe
/// that cannot tell **fails open** (see [`online`](Connectivity::online)). The live
/// impl ([`RouteConnectivity`]) reads the kernel routing table (is a default route
/// present), never a network round-trip, so probing it every tick is cheap.
/// [`AssumeOnline`] is the default/test seam (always online → spawns proceed as
/// before); a test injects a fake to exercise the offline HOLD.
pub trait Connectivity: Send + Sync + fmt::Debug {
    /// `true` when the device has a route to spawn a peer over; `false` HOLDS this
    /// tick's spawns (steps 2 + 3). A probe that cannot determine the state returns
    /// `true` (**fail-open**): a false "online" costs at most one spawn that slice
    /// 002 reclassifies as a transient network exit (no penalty), whereas a false
    /// "offline" would wedge a healthy fleet — so the safe default is to let the
    /// spawn through and lean on the mid-session backstop.
    fn online(&self) -> bool;
}

/// The default/test [`Connectivity`] seam: always online, so a loop assembled
/// without a live probe spawns exactly as before (the pre-failsafe behaviour). The
/// production assembly wires [`RouteConnectivity`] instead; this stays the
/// `DriveLoop` default seam and the fixture a test injects for the online path.
/// Mirrors [`PermissiveRate`]'s deferred-default shape.
#[derive(Debug, Default, Clone, Copy)]
pub struct AssumeOnline;

impl Connectivity for AssumeOnline {
    fn online(&self) -> bool {
        true
    }
}

/// The live [`Connectivity`] probe (network-failsafe slice 001): "is there a
/// default route" read straight from the kernel routing table — `/proc/net/route`
/// (IPv4) plus `/proc/net/ipv6_route` (IPv6) — with NO network round-trip, so the
/// per-tick cost is a couple of small `/proc` reads. A default route present is the
/// signal the link is up enough to reach the API; when wifi drops, the route
/// disappears and the gate holds the spawn. It does not detect a route-up /
/// internet-down captive-portal case — that is slice 002's mid-session job; the
/// pre-spawn gate targets the common "wifi is simply off" case. Reads **fail open**
/// (a missing/unreadable `/proc` returns online) per the trait contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct RouteConnectivity;

impl Connectivity for RouteConnectivity {
    fn online(&self) -> bool {
        has_default_route()
    }
}

/// `true` if the kernel has a usable default route on any interface (IPv4 or IPv6).
/// **Fail-open**: if neither routing table can be read, assume online — never wedge
/// the fleet on a probe failure. The per-table parse is a pure function of the file
/// body ([`v4_has_default`] / [`v6_has_default`]), unit-tested over `/proc`
/// fixtures.
fn has_default_route() -> bool {
    let v4 = std::fs::read_to_string("/proc/net/route").ok();
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").ok();
    if v4.is_none() && v6.is_none() {
        return true; // cannot probe → fail open, do not hold the fleet
    }
    v4.as_deref().is_some_and(v4_has_default) || v6.as_deref().is_some_and(v6_has_default)
}

/// Parse an IPv4 `/proc/net/route` body: `true` if any row is an UP default route
/// (Destination `00000000` with the `RTF_UP` flag set). Columns are whitespace-
/// separated — `Iface Destination Gateway Flags …`; the header line has a non-hex
/// Destination and so is skipped by the `00000000` match. Pure over the body.
fn v4_has_default(body: &str) -> bool {
    body.lines().any(|line| {
        let mut cols = line.split_whitespace();
        let _iface = cols.next();
        let dest = cols.next(); // col 1: destination network, hex
        let _gateway = cols.next(); // col 2
        let flags = cols.next(); // col 3: RTF_* flags, hex
        dest == Some("00000000")
            && flags
                .and_then(|f| u32::from_str_radix(f, 16).ok())
                .is_some_and(|f| f & 0x1 != 0) // RTF_UP
    })
}

/// Parse an IPv6 `/proc/net/ipv6_route` body: `true` if any row is an UP default
/// route — destination `::/0` (all-zero 32-hex network with prefix-length `00`)
/// with the `RTF_UP` flag set (column 8, hex). Pure over the body.
fn v6_has_default(body: &str) -> bool {
    body.lines().any(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        cols.len() >= 9
            && cols[0] == "00000000000000000000000000000000"
            && cols[1] == "00"
            && u32::from_str_radix(cols[8], 16).is_ok_and(|f| f & 0x1 != 0) // RTF_UP
    })
}

/// The network-error needles a peer's stderr tail is matched against to recognise a
/// TRANSIENT API-connection death (network-failsafe slice 002). Case-insensitive
/// substring match, curated to connection-LAYER failures a headless `claude -p`
/// prints when the link drops (reset / refused / timeout / DNS / TLS / unreachable),
/// NOT application errors — a 4xx/5xx body or a Rust panic is a genuine failure, not
/// a blip, so it must NOT appear here (that would mask a real crash as a reconnect).
const NETWORK_ERROR_NEEDLES: &[&str] = &[
    "connection reset",
    "connection refused",
    "connection closed",
    "connection error",
    "connection timed out",
    "error sending request",
    "network is unreachable",
    "no route to host",
    "temporary failure in name resolution",
    "name or service not known",
    "dns error",
    "failed to lookup address",
    "tls handshake",
    "broken pipe",
    "socket hang up",
    "econnreset",
    "econnrefused",
    "etimedout",
    "enotfound",
    "eai_again",
    "fetch failed",
    "request timed out",
];

/// `true` if any line of a peer's stderr `tail` matches a [`NETWORK_ERROR_NEEDLES`]
/// signature (case-insensitive). Pure over the tail.
fn stderr_matches_network_signature(tail: &[String]) -> bool {
    tail.iter().any(|line| {
        let lower = line.to_ascii_lowercase();
        NETWORK_ERROR_NEEDLES
            .iter()
            .any(|needle| lower.contains(needle))
    })
}

/// The pure network-exit classifier (network-failsafe slice 002): does a non-zero
/// peer exit look like a TRANSIENT network death — reconnect off the baton with no
/// streak/backoff/alert — rather than a genuine crash? `true` when the device is
/// **offline at exit** (the link died and has not recovered) OR the stderr `tail`
/// carries a network-error signature (a blip that may already have recovered by the
/// time we poll — connectivity is racy across a flap, so the signature corroborates
/// it). A genuine crash is online AND shows no network signature → `false`, so the
/// historical crash path (backoff + `AgentCrashed`) is unchanged. The caller
/// restricts this to an actual `Exited` non-zero code — a hung child is never
/// reclassified. Pure `(tail, connectivity) → bool`, provable without a real network
/// or a real `claude`.
fn is_transient_network_exit(stderr_tail: &[String], online_at_exit: bool) -> bool {
    !online_at_exit || stderr_matches_network_signature(stderr_tail)
}

/// The default [`QueueSource`] until the live keeperd queue feed lands
/// (`growlight-live-fleet` slice 002): an **empty** [`Snapshot`], so the
/// scheduler picks nothing and a gated-on fleet stays idle. Fail-closed — a
/// fleet assembled before its live queue source schedules zero work rather than
/// guessing at parts. Mirrors [`PermissiveRate`]'s deferred-default shape; the
/// live assembly ([`crate::fleet::assemble_fleet`]) wires this in until slice 002
/// replaces it with the real per-queue managed-region pull.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeferredQueues;

impl QueueSource for DeferredQueues {
    fn snapshot(&self) -> Snapshot {
        Snapshot::default()
    }
}

/// The seam the loop reads per-agent [`AgentHealth`] through, to feed
/// [`Supervisor::poll`]. Implemented over the live [`ClaudeBackend`] (slice 001),
/// which tracks a heartbeat-or-exit cell per agent; a test scripts the health.
pub trait AgentHealthSource: Send + Sync + fmt::Debug {
    /// `agent`'s current health, or `None` if it was never spawned (so the loop
    /// skips a `poll` it has no observation for).
    fn health(&self, agent: &str) -> Option<AgentHealth>;
}

impl AgentHealthSource for Arc<ClaudeBackend> {
    fn health(&self, agent: &str) -> Option<AgentHealth> {
        // Disambiguate from this trait method: call the inherent one on the
        // backed `ClaudeBackend`.
        self.as_ref().health(agent)
    }
}

/// The seam the loop reads a crashed agent's **stderr tail** through, to enrich an
/// [`NotifyEvent::AgentCrashed`] with the crash *reason* (crash-diagnostics slice
/// 001). Implemented over the live [`ClaudeBackend`]'s bounded per-agent in-memory
/// ring buffer; a test scripts the tail. Read ONLY when [`Supervisor::poll`]
/// classifies a crash, so a healthy tick pays nothing. The tail is ephemeral (lost
/// on a growlightd restart) — the alert, not a file, carries it forward.
pub trait AgentStderrSource: Send + Sync + fmt::Debug {
    /// `agent`'s most recent stderr lines (oldest→newest), or empty if it was never
    /// spawned / emitted nothing.
    fn stderr_tail(&self, agent: &str) -> Vec<String>;
}

impl AgentStderrSource for Arc<ClaudeBackend> {
    fn stderr_tail(&self, agent: &str) -> Vec<String> {
        // Disambiguate from this trait method: call the inherent one.
        self.as_ref().stderr_tail(agent)
    }
}

/// The seam the loop reads an EXITED agent's terminal baton status through, to
/// feed [`Supervisor::poll`]'s retire-vs-park-vs-re-roll decision (the spin fix,
/// [[decision-growlight-fleet-loop-spin]]). Slice 002 implements it over the
/// per-member baton write-back (`agents/<id>/baton.md`); until then the live loop
/// wires [`DeferredBatonStatus`] (always `None` → the historical clean-exit
/// re-roll, so this slice ships with no behaviour change to a working member),
/// and a test scripts the status.
pub trait BatonStatusSource: Send + Sync + fmt::Debug {
    /// `agent`'s terminal baton `status:` field as of its last exit, or `None`
    /// when no baton was written/readable (the clean-exit re-roll fallback).
    fn status(&self, agent: &str) -> Option<String>;
}

/// The deferred (slice 001) baton-status source: no per-member baton write-back
/// exists yet, so every read is `None` and [`Supervisor::poll`] keeps the
/// historical clean-exit behaviour (re-roll). Slice 002 replaces it in the live
/// assembly with the real per-member reader. Mirrors [`DeferredQueues`].
#[derive(Debug)]
pub struct DeferredBatonStatus;

impl BatonStatusSource for DeferredBatonStatus {
    fn status(&self, _agent: &str) -> Option<String> {
        None
    }
}

/// The seam the loop **seeds** a fresh member's per-member baton through, so an
/// assigned agent boots WITH its baton (`agents/<id>/baton.md`) instead of the
/// `(no baton yet)` `inject.sh` fallback — the WRITE counterpart to
/// [`BatonStatusSource`]'s read. The loop calls it on a **fresh start only** (the
/// step-3 spawn of an un-registered member, where the claimed `(queue, part)` is
/// known), BEFORE the part claim and the backend spawn, so the file exists when
/// the child's SessionStart hook cats it. A **re-roll** never re-seeds — the
/// member's own write-back from the prior iteration is what carries forward (the
/// curated state across iterations). The live impl is
/// [`crate::baton_store::FsBatonStore`] over the runtime `agents/` namespace; a
/// test records or scripts the seed.
pub trait BatonSeeder: Send + Sync + fmt::Debug {
    /// Seed `agent`'s baton from the claimed `(queue, part)`. `Ok(())` means the
    /// baton is laid down (the agent will boot with it); `Err(reason)` aborts the
    /// spawn fail-closed (a member booting stateless is the bug this slice fixes) —
    /// the drive loop holds the start and retries next tick.
    fn seed(&self, agent: &str, queue: &str, part: &str) -> Result<(), String>;
}

/// The deferred [`BatonSeeder`] for the disabled/test seam: seeding is a no-op
/// success, so a loop assembled without the live store behaves as before (a member
/// boots `(no baton yet)`). The live assembly wires [`crate::baton_store::FsBatonStore`]
/// instead. Mirrors [`DeferredBatonStatus`].
#[derive(Debug)]
pub struct DeferredBatonSeeder;

impl BatonSeeder for DeferredBatonSeeder {
    fn seed(&self, _agent: &str, _queue: &str, _part: &str) -> Result<(), String> {
        Ok(())
    }
}

/// One configured fleet member: the agent's spawn [`AgentSpec`] plus the
/// work-stream it is **pinned** to (pinned-with-fallback, spec §6). An unpinned
/// member (`pin: None`) goes straight to fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetMember {
    /// The per-agent spawn spec (id + pre-approval file paths).
    pub spec: AgentSpec,
    /// The agent's pinned queue name, or `None` for an unpinned agent.
    pub pin: Option<String>,
}

impl FleetMember {
    /// A member pinned to `pin`'s work-stream.
    pub fn pinned(spec: AgentSpec, pin: impl Into<String>) -> Self {
        Self {
            spec,
            pin: Some(pin.into()),
        }
    }

    /// An unpinned member (fallback-only).
    pub fn unpinned(spec: AgentSpec) -> Self {
        Self { spec, pin: None }
    }
}

/// A scheduler assignment the loop acted on this tick: which agent it started on
/// which `(queue, part)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The agent that was started.
    pub agent: String,
    /// The queue the scheduler picked for it.
    pub queue: String,
    /// The part (item id) at that queue's head.
    pub part: String,
}

/// A start the admission governor did not admit this tick — queued (cap) or
/// refused (budget/rate). Carries the [`StartOutcome`] so the caller can log /
/// alert the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldStart {
    /// The agent whose start was held.
    pub agent: String,
    /// The non-admit outcome (`Queued` / `Refused` / `SpawnFailed`).
    pub outcome: StartOutcome,
}

/// A member whose FRESH start was skipped in step 3 BEFORE admission — no workable
/// part to pick, or the part it picked was already spoken for. Distinct from a
/// [`HeldStart`] (which reached admission and was refused/queued): a `HeldFresh`
/// never even attempted a claim. Recorded so the drive loop's journal voice can
/// name a held fleet member (task 042) — before this these two `continue`s were
/// SILENT, so a held fleet-of-one left no trace (the 2026-07-07 4h stall).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldFresh {
    /// The agent held out of a fresh start this tick.
    pub agent: String,
    /// Why (`no workable part` / `part already claimed`) — the `held (…)` reason.
    pub reason: &'static str,
}

/// A member EXIT this tick as the drive loop classified it: the terminal baton
/// status growlightd OBSERVED (from `agents/<id>/baton.md`, or the legacy-path
/// misroute fallback — see [`crate::baton_store`]) and the lifecycle disposition it
/// drove. Recorded on every classified exit so the health-pass is diagnosable from
/// the journal (task 042): a stale or misrouted baton — growlightd reading a status
/// the member never intended — is visible as a line, not a silent stall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDisposition {
    /// The exiting agent.
    pub agent: String,
    /// The baton status growlightd read on the exit (`None` = missing/unreadable).
    pub baton_status: Option<String>,
    /// The one-word disposition it drove (`rolling` / `completed` / `retired` / …).
    pub disposition: &'static str,
}

/// Everything one [`DriveLoop::tick`] did, for the caller (the live thread, or a
/// test) to inspect and — in slice 003 — route through the single notification
/// dispatcher.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Agents started this tick, with their scheduler assignment.
    pub started: Vec<Assignment>,
    /// Starts held by admission (cap queue / budget-rate refuse / spawn failure).
    pub held_starts: Vec<HeldStart>,
    /// Fresh starts SKIPPED in step 3 before admission — no workable part, or the
    /// part was already spoken for (task 042's diagnosability half). Narrated as a
    /// hold so a held fleet member names itself in the journal instead of stalling
    /// silently; edge-deduped by the [`TickLogger`] like any other hold.
    pub held_fresh: Vec<HeldFresh>,
    /// Re-roll outcomes from [`Supervisor::tick`] (rerolled / held / failed).
    pub rerolls: Vec<RerollOutcome>,
    /// Crash alerts surfaced by [`Supervisor::poll`] (slice 003 dispatches these).
    pub crashes: Vec<NotifyEvent>,
    /// Members whose non-zero exit this tick was classified a TRANSIENT network death
    /// (network-failsafe slice 002) and re-rolled off the baton instead of crashing:
    /// NO `AgentCrashed` alert, NO backoff, NO failure-streak bump. Recorded distinct
    /// from [`crashes`](TickReport::crashes) so the caller logs a soft reconnect apart
    /// from a real crash; the member stays registered and step 2 re-rolls it (paced by
    /// the connectivity gate while offline).
    pub reconnecting: Vec<String>,
    /// Agents retired this tick (a boundary stop was honored).
    pub retired: Vec<String>,
    /// Agents that finished/deferred their current part this tick on an
    /// `ITEM_COMPLETE` / `ITEM_DEFERRED` baton and **released their slot** (the
    /// item boundary). Unlike [`retired`](TickReport::retired) — a permanent stop
    /// or a drained-queue idle — a completed member is immediately re-pickable:
    /// step 3 this same tick re-claims + re-seeds it onto its next workable part
    /// (the orchestrator owns continuation, not the member). Recorded distinctly so
    /// the caller can log an item boundary apart from a retire.
    pub completed: Vec<String>,
    /// Members **released on a human-block** this tick (`BLOCKED_ON_HUMAN` / `STUCK`):
    /// each left the fleet (slot freed) and had its current part item-parked —
    /// marked `blocked` in keeperd — so the freed member pivots past it to other work
    /// (pivot-on-block) and the human is alerted via [`parked`](TickReport::parked).
    /// Carries the `(agent, queue, part)` so the caller can log which item was
    /// parked. Distinct from a crash (no kill, no backoff) and from a retire (the
    /// member is immediately re-pickable in step 3 onto a *different* part).
    pub blocked: Vec<Assignment>,
    /// Every classified member EXIT this tick with the baton status growlightd
    /// observed and the disposition it drove — the health-pass diagnostic (task
    /// 042). One journal line per exit (edge-deduped by the [`TickLogger`]), so a
    /// misread/misrouted baton is visible where a silent stall used to be.
    pub exit_dispositions: Vec<ExitDisposition>,
    /// Boundary-async messages drained from inject lanes, per agent.
    pub injected: Vec<(String, Vec<String>)>,
    /// Parked (blocked-head) queues, surfaced for the §9 alert hook every tick —
    /// even while paused, so the human still learns an item needs them.
    pub parked: Vec<(String, String)>,
    /// Whether admission was gated by `pause` this tick (no starts/rolls attempted).
    pub paused: bool,
    /// Whether the pre-spawn connectivity gate HELD this tick's spawns because the
    /// device is offline (network-failsafe slice 001): steps 2 (re-roll) + 3
    /// (fresh start) were skipped — no spawn, no backoff, no crash count — and the
    /// next tick re-probes. Distinct from `paused` (a human/policy stop): this is a
    /// "waiting for the link to return" hold. Slice 003 turns this signal into the
    /// visible member state + the sustained-offline alert; slice 001 only proves
    /// the spawn is held. Health/control (step 1) still ran — exits and boundary
    /// stops are observed regardless.
    pub waiting_for_connectivity: bool,
}

/// The fleet drive loop: binds the scheduler, the [`Supervisor`], and the daemon
/// control state into one per-tick coordinator. Owned by the daemon's drive-loop
/// thread (see [`spawn_drive_loop`]) — it carries `&mut self` mutable state (the
/// supervised fleet, the retire/stop bookkeeping), so it is NOT shared behind the
/// daemon mutex; it reads control through the daemon's lock-brief boundary
/// accessors.
#[derive(Debug)]
pub struct DriveLoop {
    /// The daemon handle — read-only here for control intent + lifecycle (the loop
    /// never mutates `DaemonInner` directly; it goes through the public boundary
    /// accessors, each of which takes the daemon lock only briefly).
    daemon: Daemon,
    /// The fleet supervisor (owns the live backend + admission governor).
    supervisor: Supervisor,
    /// Per-agent health probe (the live [`ClaudeBackend`] in production).
    health: Box<dyn AgentHealthSource>,
    /// Per-agent stderr-tail probe (crash-diagnostics slice 001): read only when a
    /// `poll` classifies a crash, to enrich the [`NotifyEvent::AgentCrashed`] alert
    /// with the reason. The live [`ClaudeBackend`]'s in-memory ring in production.
    stderr: Box<dyn AgentStderrSource>,
    /// Reads an exited agent's terminal baton status — the source for
    /// [`Supervisor::poll`]'s retire-vs-re-roll decision (the spin fix). Deferred
    /// in slice 001 ([`DeferredBatonStatus`], always `None`); slice 002 wires the
    /// real per-member reader ([`crate::baton_store::FsBatonStore`]).
    baton: Box<dyn BatonStatusSource>,
    /// Seeds a fresh member's per-member baton from its claimed `(queue, part)`
    /// (slice 002), so an assigned agent boots with its baton rather than
    /// `(no baton yet)`. Invoked on a fresh start only — a re-roll carries the
    /// member's own write-back forward (the same [`crate::baton_store::FsBatonStore`]
    /// the `baton` reader reads, in the live assembly).
    seeder: Box<dyn BatonSeeder>,
    /// Where the multi-queue snapshot comes from.
    queues: Box<dyn QueueSource>,
    /// How a picked part is claimed (`active`) before its agent spawns — the
    /// write that closes the fallback double-assignment window cross-tick.
    claimer: Box<dyn PartClaimer>,
    /// How a member's current part is item-parked (`blocked`) when it exits on a
    /// human-block (`BLOCKED_ON_HUMAN` / `STUCK`) — the write that records the
    /// block on the ITEM so the freed member pivots past it (the sibling of
    /// `claimer`).
    parker: Box<dyn ItemParker>,
    /// Per-agent shared-pool budget readings, folded into `aggregator` each tick.
    samples: Box<dyn BudgetSampleSource>,
    /// Per-minute rate readings — admission's second gate.
    rate: Box<dyn RateSource>,
    /// Pre-spawn network reachability probe (network-failsafe slice 001). Read once
    /// per tick (when not paused): offline → HOLD every spawn this tick — no re-roll,
    /// no fresh start, no backoff, no crash — rather than launch a headless `claude
    /// -p` into an instant crash. The live [`RouteConnectivity`] (a cheap kernel
    /// routing-table read) in production; [`AssumeOnline`] by default and in tests
    /// that don't exercise the gate.
    connectivity: Box<dyn Connectivity>,
    /// The cross-agent usage aggregate (owned): refreshed from `samples` each tick,
    /// it feeds admission (gate on real fleet burn) and the single §9 usage alert
    /// ([`UsageAggregator::fleet_alert`]).
    aggregator: UsageAggregator,
    /// The single notification dispatcher (owned): every tick's events — crashes,
    /// parked (blocked-head) items, the usage alert — route through it, so its
    /// per-event dedup/cooldown makes a sustained condition announce at most once
    /// per window (spec §9). Owned (not per-tick) precisely so that state persists
    /// across ticks.
    dispatcher: NotifyDispatcher,
    /// The configured fleet (specs + pins). Stable across ticks; lifecycle is
    /// tracked in `retiring`/`stopped`, not by mutating this.
    fleet: Vec<FleetMember>,
    /// Agents that were asked to stop and are awaiting their next boundary to
    /// retire (the boundary intent was consumed; this persists it until honored).
    retiring: BTreeSet<String>,
    /// Agents that have retired on a boundary stop — never re-started this run.
    stopped: BTreeSet<String>,
    /// Members whose last non-zero exit was classified a TRANSIENT network death and
    /// are awaiting a reconnect re-roll (network-failsafe slice 002). A down member is
    /// re-observed with the SAME stale exit each tick until it re-rolls, so this latch
    /// keeps the classifier from escalating that repeat into a false crash when
    /// connectivity flaps back before step 2 re-rolls it. Set on a `Reconnecting`
    /// poll, cleared when the member re-rolls (a `Rerolled` outcome) or on any other
    /// disposition — so a session that genuinely re-crashes after reconnecting is
    /// classified fresh.
    reconnecting: BTreeSet<String>,
    /// Each running member's current `(queue, part)` assignment, recorded on its
    /// fresh start (step 3) and carried across re-rolls (a re-roll stays on the same
    /// part). Read when a member exits on a human-block so the loop knows which item
    /// to park (`blocked`); cleared when the member leaves the fleet. The supervisor
    /// owns lifecycle (it knows the agent, not its part); the loop owns the
    /// assignment (it did the claim), so the part lookup lives here.
    assignments: std::collections::BTreeMap<String, (String, String)>,
    /// When the pre-spawn connectivity gate first held THIS outage (its first offline
    /// tick's `now`), or `None` while online/paused (network-failsafe slice 003).
    /// Drives the sustained-offline alert threshold — a blip clears it before
    /// [`OFFLINE_ALERT_THRESHOLD_SECS`] (no page); a sustained outage crosses it.
    offline_since: Option<i64>,
    /// Whether the sustained-offline page has already fired for the CURRENT outage, so
    /// it pages EXACTLY ONCE (not every tick past the threshold) and re-arms only after
    /// a reconnect (network-failsafe slice 003).
    offline_alerted: bool,
}

impl DriveLoop {
    /// Assemble a drive loop over its seams + fleet. The `health` and `samples`
    /// probes should observe the SAME backend the `supervisor` spawns through (in
    /// production all three are clones of one `Arc<ClaudeBackend>`). The owned
    /// [`UsageAggregator`] starts empty (a fresh fleet has burned nothing); the
    /// `dispatcher` arrives with its channels already registered (in production a
    /// [`crate::notify_dispatch::GuiNotifier`] over the daemon hub + a
    /// [`crate::notify_dispatch::LogNotifier`]). The `claimer` (`active` write) and
    /// `parker` (`blocked` write) are keeperd siblings — in production both ride the
    /// same socket ([`crate::claim`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        daemon: Daemon,
        supervisor: Supervisor,
        health: Box<dyn AgentHealthSource>,
        stderr: Box<dyn AgentStderrSource>,
        baton: Box<dyn BatonStatusSource>,
        seeder: Box<dyn BatonSeeder>,
        queues: Box<dyn QueueSource>,
        claimer: Box<dyn PartClaimer>,
        parker: Box<dyn ItemParker>,
        samples: Box<dyn BudgetSampleSource>,
        rate: Box<dyn RateSource>,
        connectivity: Box<dyn Connectivity>,
        dispatcher: NotifyDispatcher,
        fleet: Vec<FleetMember>,
    ) -> Self {
        Self {
            daemon,
            supervisor,
            health,
            stderr,
            baton,
            seeder,
            queues,
            claimer,
            parker,
            samples,
            rate,
            connectivity,
            aggregator: UsageAggregator::new(),
            dispatcher,
            fleet,
            retiring: BTreeSet::new(),
            stopped: BTreeSet::new(),
            reconnecting: BTreeSet::new(),
            assignments: std::collections::BTreeMap::new(),
            offline_since: None,
            offline_alerted: false,
        }
    }

    /// One orchestration cycle at `now` (injected Unix seconds): honor control,
    /// observe + re-roll, then schedule + admit + spawn. Returns a [`TickReport`]
    /// of everything it did.
    pub fn tick(&mut self, now: i64) -> TickReport {
        let mut report = TickReport::default();
        let paused = self.daemon.is_paused();
        report.paused = paused;

        // Connectivity gate (network-failsafe slice 001). Probe the link BEFORE any
        // spawn: a headless `claude -p` launched offline errors out on its first API
        // request and the supervisor misreads it as a crash (punitive backoff + a
        // false `AgentCrashed` page) — so a flaky link becomes a crash loop. Offline
        // → HOLD every spawn this tick: steps 2 (re-roll) + 3 (fresh start) below are
        // gated on `!offline`, so no spawn is issued, no backoff accrues, and no
        // crash is counted. Distinct from `paused` (a human/policy admission stop)
        // and from a crash re-roll; the ~1s tick cadence is the retry (the next tick
        // re-probes; spawns resume the moment the link returns). Only meaningful when
        // not paused (a paused fleet attempts nothing regardless), and the live probe
        // is a cheap local `/proc` read, so probing every tick is fine. Health +
        // control (step 1) still run offline — exits and boundary stops are still
        // observed; only the spawn is held. A mid-session drop (the link dies while a
        // peer runs, unpreventable here) is slice 002's non-punitive re-classify.
        let offline = !paused && !self.connectivity.online();
        report.waiting_for_connectivity = offline;

        // Refresh the admission policy from the runtime source of truth BEFORE any
        // admission decision this tick: the daemon's `config.policy` is what the
        // `set_policy` verb mutates, so re-reading it here makes a live policy
        // change (a new cap / budget rail) take effect at THIS boundary — no
        // restart (spec §11/§13 Control). Cheap: a brief daemon-lock read + a `Copy`
        // compare, rebuilding the governor only on an actual change.
        let policy = self.daemon.policy();
        if self.supervisor.policy() != policy {
            self.supervisor.set_policy(policy);
        }

        // Clone the configured fleet up front so the per-agent passes can borrow the
        // supervisor / aggregator / lifecycle sets mutably without aliasing
        // `self.fleet`.
        let fleet = self.fleet.clone();

        // 0. Refresh the cross-agent usage aggregate BEFORE the admission gate
        //    (spec §7): fold in each live agent's latest reading of the shared
        //    pool, and forget a stopped agent's stale reading so it can never pin
        //    the aggregate after it leaves the fleet (see [`crate::usage`]).
        for member in &fleet {
            let agent = &member.spec.agent;
            if self.stopped.contains(agent) {
                self.aggregator.forget(agent);
            } else if let Some(budget) = self.samples.budget(agent) {
                self.aggregator
                    .observe(UsageSample::new(agent.clone(), budget));
            }
        }
        let budget = self.aggregator.aggregate_or_fresh();
        let rate = self.rate.rate(now);

        // Parts item-parked this tick (a member exited on a human-block): collected
        // in the health pass and applied to the snapshot below (`mark_blocked`), the
        // intra-tick half of the item-park — so this tick's parked-head alert AND the
        // freed member's pivot both see the block. keeperd's committed `blocked`
        // write (the `parker` call in the health pass) is the cross-tick half.
        let mut to_block: Vec<(String, String)> = Vec::new();

        // 1. Per-agent control + health pass (boundary semantics, spec §8).
        for member in &fleet {
            let agent = &member.spec.agent;

            // a. Honor a pending boundary stop, exactly once. The agent does not
            //    stop until it reaches its boundary; we just record the intent.
            if self.daemon.take_pending_stop(agent).is_some() {
                self.retiring.insert(agent.clone());
            }

            // b. Drain the boundary-async inject lane (delivered at the agent's
            //    next baton — folding it into the next session is wire-loose-ends).
            let drained = self.daemon.drain_inject_lane(agent);
            if !drained.is_empty() {
                report.injected.push((agent.clone(), drained));
            }

            // c. Health-driven lifecycle. No observation (never spawned, or already
            //    retired) → nothing to poll. On an EXIT, read the agent's terminal
            //    baton status so `poll` can retire/park/re-roll on it (the spin
            //    fix) rather than re-roll on the exit code alone; a still-alive
            //    agent has no terminal status to read.
            if let Some(health) = self.health.health(agent) {
                let baton_status = match health {
                    AgentHealth::Exited { .. } => self.baton.status(agent),
                    AgentHealth::Alive { .. } => None,
                };
                // Network-exit classifier (slice 002): `poll_with_network` evaluates
                // it ONLY on a crash verdict (so a healthy tick reads no stderr). A
                // non-zero EXIT whose in-memory stderr tail carries a network-error
                // signature, OR that exited while the device is offline, is a
                // transient network death → reconnect, not crash; a hung child or a
                // non-network exit stays a genuine crash. `stderr` + `connectivity`
                // are disjoint fields from `&mut supervisor`, scoped to this block so
                // their borrows release before the `&mut self` match arms below.
                let outcome = {
                    let stderr = &self.stderr;
                    let connectivity = &self.connectivity;
                    let reconnecting = &self.reconnecting;
                    let network_exit = || {
                        matches!(health, AgentHealth::Exited { .. })
                            // Latch: a down member is re-observed with the SAME stale
                            // exit every tick until it re-rolls (spawn resets the cell
                            // to Alive). A member already deemed reconnecting must not
                            // be escalated into a false crash if connectivity flaps back
                            // before step 2 re-rolls it — it is the same pending network
                            // death, not a new crash. Cleared on re-roll (after step 2),
                            // so a session that genuinely re-crashes after reconnecting
                            // is classified fresh.
                            && (reconnecting.contains(agent)
                                || is_transient_network_exit(
                                    &stderr.stderr_tail(agent),
                                    connectivity.online(),
                                ))
                    };
                    self.supervisor.poll_with_network(
                        agent,
                        health,
                        baton_status.as_deref(),
                        now,
                        network_exit,
                    )
                };
                // Health-pass diagnostic (task 042): record what baton status this
                // EXIT was classified against and the disposition it drove, so a
                // stale/misrouted baton is visible in the journal (before this, a
                // misclassified exit stalled the fleet silently). Only real exits are
                // recorded — a still-registered `Healthy`/`Unknown` observation (e.g.
                // the cross-tick latched-`Exited` re-poll of an already-gone member)
                // is not an exit event, so it is skipped to keep the log clean.
                if matches!(health, AgentHealth::Exited { .. })
                    && !matches!(outcome, PollOutcome::Healthy | PollOutcome::Unknown)
                {
                    report.exit_dispositions.push(ExitDisposition {
                        agent: agent.clone(),
                        baton_status: baton_status.clone(),
                        disposition: exit_disposition_label(&outcome),
                    });
                }
                // Maintain the reconnect latch (slice 002): any non-reconnect
                // disposition clears it (the member re-rolled, exited clean, or
                // genuinely crashed — a fresh slate); the Reconnecting arm re-sets it
                // below. The classifier above already read the pre-clear value.
                if !matches!(outcome, PollOutcome::Reconnecting) {
                    self.reconnecting.remove(agent);
                }
                match outcome {
                    PollOutcome::Crashed { event, .. } => {
                        // Enrich the alert with the crashed agent's stderr tail
                        // (crash-diagnostics slice 001): the supervisor built the
                        // event without a reason (it has no backend); we read the
                        // in-memory ring off the backend here, before the event is
                        // dispatched, so the human sees *why* it crashed. Read once,
                        // only on a crash — a healthy tick never touches stderr.
                        let event = event.with_stderr_tail(self.stderr.stderr_tail(agent));
                        report.crashes.push(event);
                        // A retiring agent that crashes at its boundary stops here
                        // rather than re-rolling.
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        }
                    }
                    PollOutcome::Reconnecting => {
                        // Transient network exit (slice 002): the member lost its API
                        // connection mid-session and is re-rolled off its baton — NO
                        // `AgentCrashed` alert (nothing pushed to `report.crashes`), NO
                        // backoff, NO streak bump. Like `Rolling` but from a non-zero
                        // exit the classifier attributed to the network; the member
                        // stays down+registered so step 2 re-rolls it (held by the
                        // connectivity gate while the link is still down). A retiring
                        // agent stops here instead of reconnecting; its assignment is
                        // untouched (it re-rolls on the SAME part).
                        if self.retiring.remove(agent) {
                            self.reconnecting.remove(agent);
                            self.retire(agent, &mut report);
                        } else {
                            self.reconnecting.insert(agent.clone());
                            report.reconnecting.push(agent.clone());
                        }
                    }
                    PollOutcome::Rolling => {
                        // Clean boundary exit on a continue status (or no baton yet):
                        // a retiring agent stops here instead of re-rolling;
                        // otherwise `Supervisor::tick` rolls it below.
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        }
                    }
                    PollOutcome::Retired => {
                        // QUEUE_EMPTY: the member retired itself to idle and is
                        // already gone from the supervisor — the spin fix. If a
                        // human also asked it to stop, it stops for good; otherwise
                        // it stays eligible to RE-START when new queued work appears
                        // (not in `stopped`), and the daemon idles in between.
                        self.assignments.remove(agent);
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        } else {
                            self.aggregator.forget(agent);
                            report.retired.push(agent.clone());
                        }
                    }
                    PollOutcome::Completed => {
                        // ITEM_COMPLETE / ITEM_DEFERRED: the member finished or
                        // deferred its part and released its slot (already gone from
                        // the supervisor), like the QUEUE_EMPTY idle-retire EXCEPT
                        // the queue still has work — so step 3 below re-claims +
                        // re-seeds it onto its next workable part THIS tick (the
                        // orchestrator owns continuation; no member self-pull). A
                        // pending boundary stop instead retires it for good (it must
                        // not re-pick). Drop the finished assignment; step 3 records
                        // the next one if it re-picks.
                        self.assignments.remove(agent);
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        } else {
                            self.aggregator.forget(agent);
                            report.completed.push(agent.clone());
                        }
                    }
                    PollOutcome::Blocked { .. } => {
                        // STUCK / BLOCKED_ON_HUMAN: the member is RELEASED to idle
                        // (already gone from the supervisor, slot freed — like an
                        // item-boundary release), NOT sticky-parked on its slot. Its
                        // current part is ITEM-PARKED — marked `blocked` in keeperd
                        // (the write seam) and in this tick's snapshot (`mark_blocked`
                        // below) — so the freed member pivots past it to other work in
                        // step 3 (pivot-on-block) and the human is alerted on the ITEM
                        // via the parked-head set. A pending boundary stop instead
                        // retires it for good. Fail-soft: a `parker` error still
                        // releases + locally item-parks (this tick pivots + alerts);
                        // the part lingers `active` in keeperd and is re-blocked when
                        // the pinned member next cycles back to it. The slot is never
                        // stuck — that is the whole fix.
                        self.aggregator.forget(agent);
                        if let Some((queue, part)) = self.assignments.remove(agent) {
                            if let Err(_e) = self.parker.park_item(&queue, &part) {
                                // Fail-soft (see the arm comment): the member is
                                // already released and the local item-park below still
                                // pivots + alerts this tick; the keeperd write is
                                // re-attempted when the member next resolves to it.
                            }
                            to_block.push((queue.clone(), part.clone()));
                            report.blocked.push(Assignment {
                                agent: agent.clone(),
                                queue,
                                part,
                            });
                        }
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        }
                    }
                    PollOutcome::ParkedRateLimited => {
                        // HALTED_RATE_LIMIT: the member is down-but-registered, held
                        // by admission's rate gate and re-rolled by `Supervisor::tick`
                        // once its window resets; no alert. A boundary stop retires.
                        if self.retiring.remove(agent) {
                            self.retire(agent, &mut report);
                        }
                    }
                    PollOutcome::Healthy | PollOutcome::Unknown => {}
                }
            }
        }

        // Read this tick's queue snapshot ONCE, before the re-roll: BOTH the
        // re-roll's queue-gate (step 2) and the fresh-start claim (step 3) consult
        // it, so they share one consistent view. Step 3 mutates a working copy
        // (`mark_claimed`) as it claims; step 2 only reads it through `workable`.
        let mut snapshot = self.queues.snapshot();
        // Apply this tick's item-parks to the working snapshot BEFORE the parked-head
        // alert and the re-roll/start picks read it, so the block is seen this tick
        // regardless of snapshot freshness (the intra-tick half — `mark_claimed`'s
        // sibling): the parked head surfaces to the §9 alert, and the just-released
        // member's `pick` pivots past its own item-parked part to other work.
        for (queue, part) in &to_block {
            snapshot.mark_blocked(queue, part);
        }
        report.parked = parked(&snapshot);

        // 2. Re-roll due agents ([`Intent::Roll`]). `pause` is the admission gate
        //    (spec §8): a paused fleet attempts no rolls (and no starts, below).
        //    The re-roll is ALSO queue-gated — a member is re-rolled only if its
        //    OWN recorded assignment still stands (its part is its queue's
        //    head-active row: the mid-item carry-forward) or its
        //    pinned-with-fallback `pick` yields a workable part, so a clean
        //    exit is never respawned into a drained queue (belt-and-suspenders to
        //    slice 001's terminal-status retire).
        //    ALSO connectivity-gated (`!offline`): a re-roll re-spawns a `claude -p`,
        //    so an offline re-roll would instant-crash exactly like a fresh start —
        //    the 2026-07-01 crash-loop path. Held here means no re-spawn, no backoff,
        //    no crash; the member stays down (its `not_before` is absolute, so
        //    skipping `Supervisor::tick` strands nothing) and re-rolls once online.
        if !paused && !offline {
            // Map each configured member to its pin so the queue-gate can ask "is
            // there workable work for this agent?" via the same `pick` a fresh
            // start uses. A member not in the configured fleet (shouldn't happen)
            // is treated as having no work, so it is never blindly re-rolled.
            let pins: std::collections::BTreeMap<&str, Option<&str>> = fleet
                .iter()
                .map(|m| (m.spec.agent.as_str(), m.pin.as_deref()))
                .collect();
            let snap = &snapshot;
            let assignments = &self.assignments;
            let workable = |agent: &str| -> bool {
                // A down member's OWN in-progress part is workable — for itself.
                // Its claim marked the part `active`, and `pick`'s fallback
                // deliberately skips `active` heads (they are someone's work —
                // here, its own), so an unpinned member (or a pinned one whose
                // fallback pick landed in another queue) would otherwise read as
                // "no work" and be held `HeldNoWork` every tick, stranding the
                // item `active` with no agent forever (the 2026-07-06 stall,
                // task 033). The loop recorded the assignment at claim time;
                // the part still standing as its queue's head-active row is
                // exactly the "resume own part" right `pick` gives a pinned
                // member over its pinned queue.
                let resumes_own = assignments.get(agent).is_some_and(|(queue, part)| {
                    snap.queue(queue).is_some_and(|q| {
                        matches!(classify_queue(q), QueueState::Active(head) if head == *part)
                    })
                });
                resumes_own || pins.get(agent).is_some_and(|pin| pick(snap, *pin).is_some())
            };
            report.rerolls = self.supervisor.tick(budget, rate, now, &workable);
            // A member that re-rolled has consumed its pending-reconnect latch (slice
            // 002): the fresh session's next exit is a NEW event to classify anew, so a
            // genuine re-crash after a reconnect is never masked by a stale latch.
            for outcome in &report.rerolls {
                if let RerollOutcome::Rerolled { agent } = outcome {
                    self.reconnecting.remove(agent);
                }
            }
        }

        // 3. Schedule + claim + admit + spawn over the snapshot read above. Each
        //    successful claim stamps the part `active` in the LOCAL working copy
        //    (`mark_claimed`) so a later member's `pick` in the SAME tick flows
        //    past it — the intra-tick half of the double-assignment fix. keeperd's
        //    committed `active` write (the claim itself) is the cross-tick half:
        //    the next tick's snapshot shows the part claimed, so every other
        //    agent's fallback skips it.
        //    Connectivity-gated (`!offline`) like the re-roll: the pre-spawn HOLD —
        //    an offline fresh start is exactly the "spawn a headless `claude -p` with
        //    no route" instant-crash this milestone exists to prevent, so it is held
        //    (no claim, no spawn, no backoff) and retried next tick once online.
        if !paused && !offline {
            // Parts already SPOKEN FOR — excluded before a fresh start so the SAME
            // `(queue, part)` is never assigned twice. SEEDED from the LIVE
            // `assignments` (every part a registered member already holds, recorded on
            // its fresh start and carried across re-rolls), so the cross-tick
            // pinned-resume hole is closed (milestone `fleet-resume-double-claim`): a
            // member PINNED to a queue whose head a live peer claimed last tick would
            // otherwise re-resolve to that now-`active` head (`scheduler.rs:228` resume
            // path, which fallback's `active`-skip does NOT cover) and double-claim it,
            // since keeperd's claim of an already-`active` part is idempotent-`Ok`.
            // Each this-tick claim is then inserted as before — the same-tick
            // belt-and-suspenders for two members mis-pinned to one queue, where
            // marking the head `active` would otherwise read as a *resume*. A fresh
            // loop after a daemon restart has an empty `assignments`, so the rightful
            // resumer still claims (resume-after-restart preserved).
            let mut spoken_for: BTreeSet<(String, String)> =
                self.assignments.values().cloned().collect();
            for member in &fleet {
                let agent = &member.spec.agent;
                // A stopping/stopped agent is never (re-)started; a registered one
                // re-rolls via step 2, it is not re-`start`ed.
                if self.retiring.contains(agent)
                    || self.stopped.contains(agent)
                    || self.supervisor.is_registered(agent)
                {
                    continue;
                }
                let Some((queue, part)) = pick(&snapshot, member.pin.as_deref()) else {
                    // Nothing workable for this agent's pin right now. Before task 042
                    // this `continue` was SILENT, so a held fleet-of-one (e.g. a
                    // completed member whose next queued head has not yet surfaced)
                    // left no journal trace — the 2026-07-07 4h stall. Narrate it as a
                    // hold, edge-deduped like the re-roll `HeldNoWork`.
                    report.held_fresh.push(HeldFresh {
                        agent: agent.clone(),
                        reason: "no workable part",
                    });
                    continue;
                };
                // A part already spoken for — held by a live member (cross-tick) or
                // claimed earlier this tick — is taken; never double-assign it (the
                // resume-collision guard, now cross-tick as well as same-tick).
                if spoken_for.contains(&(queue.clone(), part.clone())) {
                    report.held_fresh.push(HeldFresh {
                        agent: agent.clone(),
                        reason: "part already claimed",
                    });
                    continue;
                }
                // Seed the per-member baton, then claim the part (mark it `active`
                // in keeperd), both BETWEEN admission and the spawn (slice 002 +
                // 001). Order is deliberate: the local seed write comes FIRST so a
                // seed failure aborts the start before the keeperd claim — a claim
                // that landed before a later seed failure would orphan an `active`
                // part. The seed is fresh-start only (this step-3 path); a re-roll
                // re-spawns through `Supervisor::tick` without re-seeding, carrying
                // the member's own write-back forward. Either step's `Err` aborts
                // fail-closed ([`StartOutcome::ClaimFailed`]): nothing spawned, no
                // agent left running on an unclaimed part, retried next tick. The
                // claimer/seeder borrows are disjoint fields from `supervisor`.
                let claimer = &self.claimer;
                let seeder = &self.seeder;
                let outcome = self.supervisor.start_claiming(
                    member.spec.clone(),
                    budget,
                    rate,
                    now,
                    || {
                        seeder.seed(agent, &queue, &part)?;
                        claimer.claim(&queue, &part, agent)
                    },
                );
                match outcome {
                    StartOutcome::Started => {
                        snapshot.mark_claimed(&queue, &part);
                        spoken_for.insert((queue.clone(), part.clone()));
                        // Record the assignment so a later human-block exit knows
                        // which item to park (the part lookup the supervisor can't
                        // do). A re-roll keeps the member on the same part, so this
                        // is overwritten only on its next fresh start.
                        self.assignments
                            .insert(agent.clone(), (queue.clone(), part.clone()));
                        report.started.push(Assignment {
                            agent: agent.clone(),
                            queue,
                            part,
                        });
                    }
                    // The claim landed (it precedes the spawn) even though the
                    // spawn failed — keep the part excluded this tick so no peer
                    // grabs the part keeperd now shows `active`; the agent retries
                    // next tick via a re-pick of its (now `active`) part.
                    outcome @ StartOutcome::SpawnFailed { .. } => {
                        snapshot.mark_claimed(&queue, &part);
                        spoken_for.insert((queue, part));
                        report.held_starts.push(HeldStart {
                            agent: agent.clone(),
                            outcome,
                        });
                    }
                    // Queued / Refused (no claim attempted) or ClaimFailed (claim
                    // refused, fail-closed): nothing claimed, nothing excluded.
                    outcome => report.held_starts.push(HeldStart {
                        agent: agent.clone(),
                        outcome,
                    }),
                }
            }
        }

        // 4. Route this tick's events through the single owned dispatcher (spec
        //    §9). The report is still RETURNED for the caller (and tests) to
        //    inspect — dispatch is the live side-effect on top of it.
        self.dispatch(&report, now);

        report
    }

    /// Route a completed tick's events through the single owned
    /// [`NotifyDispatcher`] (spec §9): every surfaced crash and every parked
    /// (blocked-head) item alerts, and the cross-agent usage aggregate reaching
    /// the single near-exhaustion rung ([`UsageAggregator::fleet_alert`]) fires
    /// the one usage alert. The dispatcher's per-event dedup/cooldown makes a
    /// sustained condition — a still-blocked head, a still-hot pool — announce at
    /// most once per window, even though `tick` surfaces it every cycle.
    fn dispatch(&mut self, report: &TickReport, now: i64) {
        for crash in &report.crashes {
            self.dispatcher.notify(crash, now);
        }
        // A start or re-roll whose backend spawn FAILED is an operator alert, not a
        // silent held-start: a fail-closed pre-approval generation failure (slice
        // 004) — or any launch failure — means an agent could not be (re-)spawned
        // and needs a human, exactly like a crash. Surfaced as `AgentCrashed` so it
        // rides the §9 alert path; the dispatcher's per-event cooldown dedups a
        // persistently-failing agent (one alert per window, not one per tick).
        for held in &report.held_starts {
            if let StartOutcome::SpawnFailed { .. } = held.outcome {
                // A spawn failure: the child never ran, so there is no stderr tail —
                // the bare `agent_crashed` shape (crash-diagnostics slice 001).
                self.dispatcher
                    .notify(&NotifyEvent::agent_crashed(held.agent.clone()), now);
            }
        }
        for reroll in &report.rerolls {
            if let RerollOutcome::SpawnFailed { agent, .. } = reroll {
                self.dispatcher
                    .notify(&NotifyEvent::agent_crashed(agent.clone()), now);
            }
        }
        for (_queue, part) in &report.parked {
            self.dispatcher
                .notify(&NotifyEvent::BlockedOnHuman { item: part.clone() }, now);
        }
        if self.aggregator.fleet_alert() {
            self.dispatcher.notify(&NotifyEvent::Usage, now);
        }
        // Sustained-offline alert policy (network-failsafe slice 003). A blip stays
        // QUIET — the pre-spawn gate holds spawns but NOTHING pages while offline is
        // shorter than the threshold (the whole point: the 2026-07-01 loop paged every
        // ~30min). A SUSTAINED outage pages the human EXACTLY ONCE past
        // `OFFLINE_ALERT_THRESHOLD_SECS`, and the state clears on reconnect — so a
        // later outage pages again and `growlight watch` shows the recovery. The event
        // stream (GUI hub + log + bus) is the surface: a distinct per-agent "waiting"
        // status field in `growlight status` waits on the deferred live per-agent
        // status surface (see the milestone's deferred verification).
        if report.waiting_for_connectivity {
            let since = *self.offline_since.get_or_insert(now);
            if !self.offline_alerted && now.saturating_sub(since) >= OFFLINE_ALERT_THRESHOLD_SECS {
                let secs = now.saturating_sub(since);
                self.dispatcher
                    .notify(&NotifyEvent::NetworkOffline { secs }, now);
                self.offline_alerted = true;
            }
        } else if self.offline_since.take().is_some() {
            // Reconnected (or paused): the outage is over (the `.take()` clears its
            // start). If we had paged, announce recovery so `watch`/the log show it
            // cleared and re-arm for a future outage; a blip that never paged clears
            // silently.
            if self.offline_alerted {
                self.dispatcher.notify(&NotifyEvent::NetworkRecovered, now);
                self.offline_alerted = false;
            }
        }
    }

    /// Retire `agent` from the supervisor on a boundary stop, killing any live
    /// child OUTSIDE any daemon lock (the [`crate::control::AgentChild`] contract).
    /// Records the retire and marks the agent permanently stopped for this run.
    fn retire(&mut self, agent: &str, report: &mut TickReport) {
        if let Some(child) = self.supervisor.retire(agent) {
            child.kill();
        }
        // Drop its budget reading so a departed agent can't pin the fleet aggregate,
        // and its assignment so a stale part is never item-parked later.
        self.aggregator.forget(agent);
        self.assignments.remove(agent);
        self.stopped.insert(agent.to_string());
        report.retired.push(agent.to_string());
    }
}

/// The one-word disposition label for an exit poll's [`PollOutcome`] — the
/// health-pass journal line (task 042). Exhaustive so a new outcome variant forces
/// a label choice rather than silently reading as an unclassified exit.
fn exit_disposition_label(outcome: &PollOutcome) -> &'static str {
    match outcome {
        PollOutcome::Crashed { .. } => "crashed",
        PollOutcome::Reconnecting => "reconnecting (transient network)",
        PollOutcome::Rolling => "rolling (continue status)",
        PollOutcome::Retired => "retired (queue drained)",
        PollOutcome::Completed => "completed (item boundary)",
        PollOutcome::Blocked { .. } => "blocked on human",
        PollOutcome::ParkedRateLimited => "held (rate-limited)",
        PollOutcome::Healthy => "healthy",
        PollOutcome::Unknown => "unknown",
    }
}

/// The drive loop's journal voice (task 033's diagnosability half): render one
/// terse line per fleet lifecycle event so a silent stall is debuggable from the
/// systemd journal — before this, growlightd logged nothing after "drive loop
/// running", so a fleet that stopped spawning left no trace of why. One-shot
/// events (a start, a re-roll, an exit disposition) log every occurrence; HELD
/// states recur every tick by design (the ~1s cadence is their retry), so they
/// log only on ENTRY — keyed `(agent, kind)`, re-armed when the hold clears — a
/// stalled fleet writes one line, not one per second. Crash-shaped events
/// (`AgentCrashed`, spawn failures) already reach the journal through the §9
/// dispatcher's stderr [`crate::notify_dispatch::LogNotifier`], so they are NOT
/// duplicated here. Pure over the report (returns the lines); the live thread
/// prints them, so the dedup is provable without capturing stderr.
#[derive(Debug, Default)]
struct TickLogger {
    /// The held `(agent, kind)` states seen last tick — a hold logs only when its
    /// key enters this set.
    held: BTreeSet<(String, &'static str)>,
    /// Agents whose EXIT was narrated last tick — an exit disposition (task 042)
    /// logs only on its ENTRY edge, so a member re-observed `Exited` every tick
    /// until it re-rolls/retires (e.g. a rate-limited hold) writes one line, not one
    /// per second. Re-armed once the agent is no longer in an exit state.
    exits: BTreeSet<String>,
    /// Agents whose transient-network-exit disposition was narrated last tick — the
    /// "hit a transient network exit" line logs only on its ENTRY edge (task 034),
    /// the reconnect twin of `exits`. A latched member is re-observed with the SAME
    /// stale exit every tick while the connectivity hold gates its re-roll, so it
    /// re-populates `reconnecting` per tick — a HELD state, not a fresh occurrence.
    /// Without this edge it re-narrated ~1/tick (642 lines across the 2026-07-06
    /// wifi-drop). Re-armed once the member leaves the latch (re-rolled / exited
    /// clean / genuinely crashed), so a genuinely NEW network exit narrates again.
    reconnecting: BTreeSet<String>,
    /// Whether the connectivity HOLD was on last tick (its enter/exit edges log).
    offline: bool,
}

impl TickLogger {
    /// The journal lines this tick's `report` earns, updating the edge state.
    fn lines(&mut self, r: &TickReport) -> Vec<String> {
        let mut out = Vec::new();
        for a in &r.started {
            out.push(format!("fleet: started {} on {}/{}", a.agent, a.queue, a.part));
        }
        let mut held_now: BTreeSet<(String, &'static str)> = BTreeSet::new();
        for roll in &r.rerolls {
            match roll {
                RerollOutcome::Rerolled { agent } => {
                    out.push(format!("fleet: re-rolled {agent} (fresh session, same part)"));
                }
                // Alerted through the dispatcher (`AgentCrashed`) — no duplicate.
                RerollOutcome::SpawnFailed { .. } => {}
                RerollOutcome::HeldForBackoff { agent, .. } => {
                    held_now.insert((agent.clone(), "crash backoff"));
                }
                RerollOutcome::HeldNoWork { agent } => {
                    held_now.insert((agent.clone(), "no workable part"));
                }
                RerollOutcome::HeldForAdmission { agent, .. } => {
                    held_now.insert((agent.clone(), "admission budget/rate"));
                }
            }
        }
        for held in &r.held_starts {
            let kind = match held.outcome {
                StartOutcome::Queued { .. } => "agent cap",
                StartOutcome::Refused { .. } => "admission budget/rate",
                StartOutcome::ClaimFailed { .. } => "part claim failed",
                // `Started` never lands in `held_starts`; a spawn failure is
                // alerted through the dispatcher — no duplicate.
                StartOutcome::Started | StartOutcome::SpawnFailed { .. } => continue,
            };
            held_now.insert((held.agent.clone(), kind));
        }
        // Step-3 fresh-start holds (task 042): a member with no workable part, or
        // whose part was already claimed, joins the same edge-deduped hold set — so a
        // held fleet-of-one narrates once on entry, mirroring the re-roll `HeldNoWork`.
        for hf in &r.held_fresh {
            held_now.insert((hf.agent.clone(), hf.reason));
        }
        for (agent, kind) in held_now.difference(&self.held) {
            out.push(format!("fleet: holding {agent} ({kind})"));
        }
        self.held = held_now;
        // Exit dispositions (task 042 health pass): what baton status each exit was
        // classified against and the disposition it drove — logged once on the entry
        // edge so a stale/misrouted baton is visible where a silent stall used to be.
        let mut exits_now: BTreeSet<String> = BTreeSet::new();
        for ed in &r.exit_dispositions {
            exits_now.insert(ed.agent.clone());
        }
        for ed in &r.exit_dispositions {
            if !self.exits.contains(&ed.agent) {
                out.push(format!(
                    "fleet: {} exited — baton {} -> {}",
                    ed.agent,
                    ed.baton_status.as_deref().unwrap_or("(none)"),
                    ed.disposition,
                ));
            }
        }
        self.exits = exits_now;
        for agent in &r.retired {
            out.push(format!("fleet: retired {agent} to idle"));
        }
        for agent in &r.completed {
            out.push(format!(
                "fleet: {agent} finished its part (item boundary; slot released)"
            ));
        }
        for a in &r.blocked {
            out.push(format!(
                "fleet: {} blocked on human — item-parked {}/{}",
                a.agent, a.queue, a.part
            ));
        }
        // Transient network exits (network-failsafe slice 002): a latched member
        // whose re-roll is gated by the connectivity hold is re-classified
        // `Reconnecting` every tick — a HELD state, not a fresh occurrence — so it
        // narrates once on its entry edge and dedups like the exit dispositions
        // above (task 034). A genuinely new network exit re-arms the edge and re-logs.
        let mut reconnecting_now: BTreeSet<String> = BTreeSet::new();
        for agent in &r.reconnecting {
            reconnecting_now.insert(agent.clone());
        }
        for agent in &r.reconnecting {
            if !self.reconnecting.contains(agent) {
                out.push(format!(
                    "fleet: {agent} hit a transient network exit (will re-roll)"
                ));
            }
        }
        self.reconnecting = reconnecting_now;
        if r.waiting_for_connectivity != self.offline {
            self.offline = r.waiting_for_connectivity;
            out.push(if self.offline {
                "fleet: offline — holding spawns until the link returns".to_string()
            } else {
                "fleet: connectivity hold cleared — spawns resume".to_string()
            });
        }
        out
    }
}

/// Spawn the daemon-owned drive-loop thread: tick the loop every `interval` until
/// the daemon enters [`State::Stopping`], mirroring [`crate::bus::spawn_bus_tailer`].
/// The live thread reads the wall clock for `now`; the pure [`DriveLoop::tick`]
/// stays time-injected so it is unit-proven against fakes. Each tick's report is
/// narrated to stderr (→ the systemd journal) through a [`TickLogger`], so member
/// spawns/exits/holds are diagnosable after the fact (task 033).
///
/// Construction of a *live* `DriveLoop` (a real [`ClaudeBackend`] behind both
/// [`AgentHealthSource`] and [`BudgetSampleSource`], the keeperd [`QueueSource`],
/// a [`RateSource`]) is assembled by the slices that own each source; this is the
/// thread shape that drives it.
pub fn spawn_drive_loop(
    daemon: Daemon,
    mut drive: DriveLoop,
    interval: Duration,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("growlightd-drive-loop".into())
        .spawn(move || {
            let mut logger = TickLogger::default();
            while daemon.state() != State::Stopping {
                let report = drive.tick(unix_now());
                for line in logger.lines(&report) {
                    eprintln!("softfig-growlightd: {line}");
                }
                thread::sleep(interval);
            }
        })
}

/// Wall-clock Unix seconds for the live thread's `now`. The pure policy stays
/// time-injected; only this live driver reads the clock (mirrors
/// [`crate::claude_backend`]'s local clock).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{AdmissionDecision, AdmissionGovernor, RefuseReason};
    use crate::config::{GrowlightdConfig, Policy};
    use crate::control::AgentChild;
    use crate::hub::EventHub;
    use crate::notifications::NotifyPolicy;
    use crate::notify_dispatch::{GuiNotifier, LogNotifier, LogSink};
    use crate::scheduler::{classify_queue, PartView, QueueState, QueueView};
    use crate::supervisor::{AgentBackend, Backoff, SpawnError};
    use softfig_ipc::growlightd::StopLevel;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A fake live child that records how many times it was killed.
    #[derive(Debug)]
    struct FakeChild {
        kills: Arc<AtomicUsize>,
    }
    impl AgentChild for FakeChild {
        fn kill(&self) {
            self.kills.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A fake fleet backend that is BOTH the spawn seam ([`AgentBackend`]) and the
    /// health probe ([`AgentHealthSource`]) — the production split is `ClaudeBackend`
    /// behind both. Records every spawn, scripts each agent's health, and shares a
    /// kill counter with the children it makes.
    #[derive(Debug, Default)]
    struct FakeFleet {
        spawns: Mutex<Vec<String>>,
        kills: Arc<AtomicUsize>,
        health: Mutex<BTreeMap<String, AgentHealth>>,
        /// Scripted stderr tail per agent (the live loop reads it off the backend's
        /// ring to enrich a crash alert — crash-diagnostics slice 001).
        stderr: Mutex<BTreeMap<String, Vec<String>>>,
        budgets: Mutex<BTreeMap<String, BudgetUsage>>,
        /// Scripted terminal baton status per agent (the per-member write-back the
        /// live loop reads on exit — slice 002's real reader is `FsBatonStore`).
        baton: Mutex<BTreeMap<String, String>>,
        /// Recorded per-member baton seeds `(agent, queue, part)` — the slice-002
        /// seed the loop writes on a FRESH start. A test asserts a fresh start
        /// seeds and a re-roll does not (carry-across-iterations).
        seeds: Mutex<Vec<(String, String, String)>>,
        /// When set, every `spawn` fails (models a fail-closed pre-approval
        /// generation failure, slice 004 — `ClaudeBackend::spawn` returns
        /// `SpawnError` before exec).
        fail_spawn: AtomicBool,
        /// When set, every `seed` fails (the fail-closed seed path — a member that
        /// can't be given its baton is not spawned).
        fail_seed: AtomicBool,
        /// When set, the [`Connectivity`] probe reports **offline** (the pre-spawn
        /// HOLD path, network-failsafe slice 001). Defaults to `false` = online, so a
        /// loop built by `make_*` spawns exactly as before unless a test toggles it.
        offline: AtomicBool,
    }
    impl FakeFleet {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn set_health(&self, agent: &str, h: AgentHealth) {
            self.health.lock().unwrap().insert(agent.to_string(), h);
        }
        /// Script `agent`'s stderr tail (what the loop reads to enrich a crash alert).
        fn set_stderr(&self, agent: &str, lines: &[&str]) {
            self.stderr.lock().unwrap().insert(
                agent.to_string(),
                lines.iter().map(|s| s.to_string()).collect(),
            );
        }
        /// Script `agent`'s terminal baton status (read by the loop on its exit).
        fn set_baton(&self, agent: &str, status: &str) {
            self.baton
                .lock()
                .unwrap()
                .insert(agent.to_string(), status.to_string());
        }
        /// Force every subsequent `spawn` to fail (the fail-closed path).
        fn set_fail_spawn(&self, fail: bool) {
            self.fail_spawn.store(fail, Ordering::SeqCst);
        }
        /// Force every subsequent `seed` to fail (the fail-closed seed path).
        fn set_fail_seed(&self, fail: bool) {
            self.fail_seed.store(fail, Ordering::SeqCst);
        }
        /// Toggle the connectivity probe offline (`true`) / online (`false`) — the
        /// pre-spawn HOLD gate (network-failsafe slice 001).
        fn set_offline(&self, offline: bool) {
            self.offline.store(offline, Ordering::SeqCst);
        }
        /// The recorded `(agent, queue, part)` seeds, in call order.
        fn seeds(&self) -> Vec<(String, String, String)> {
            self.seeds.lock().unwrap().clone()
        }
        /// Script `agent`'s latest reading of the shared pool (its budget cell).
        fn set_budget(&self, agent: &str, b: BudgetUsage) {
            self.budgets.lock().unwrap().insert(agent.to_string(), b);
        }
        fn spawns(&self) -> Vec<String> {
            self.spawns.lock().unwrap().clone()
        }
        fn spawn_count(&self) -> usize {
            self.spawns.lock().unwrap().len()
        }
        fn kill_count(&self) -> usize {
            self.kills.load(Ordering::SeqCst)
        }
    }
    impl AgentBackend for Arc<FakeFleet> {
        fn spawn(&self, spec: &AgentSpec) -> Result<Box<dyn AgentChild>, SpawnError> {
            self.spawns.lock().unwrap().push(spec.agent.clone());
            if self.fail_spawn.load(Ordering::SeqCst) {
                return Err(SpawnError(format!(
                    "pre-approval generation failed for agent {}",
                    spec.agent
                )));
            }
            Ok(Box::new(FakeChild {
                kills: Arc::clone(&self.kills),
            }))
        }
    }
    impl AgentHealthSource for Arc<FakeFleet> {
        fn health(&self, agent: &str) -> Option<AgentHealth> {
            self.health.lock().unwrap().get(agent).copied()
        }
    }
    impl AgentStderrSource for Arc<FakeFleet> {
        fn stderr_tail(&self, agent: &str) -> Vec<String> {
            self.stderr.lock().unwrap().get(agent).cloned().unwrap_or_default()
        }
    }
    impl BudgetSampleSource for Arc<FakeFleet> {
        fn budget(&self, agent: &str) -> Option<BudgetUsage> {
            self.budgets.lock().unwrap().get(agent).copied()
        }
    }
    impl BatonStatusSource for Arc<FakeFleet> {
        fn status(&self, agent: &str) -> Option<String> {
            self.baton.lock().unwrap().get(agent).cloned()
        }
    }
    impl BatonSeeder for Arc<FakeFleet> {
        fn seed(&self, agent: &str, queue: &str, part: &str) -> Result<(), String> {
            if self.fail_seed.load(Ordering::SeqCst) {
                return Err("seed refused".into());
            }
            self.seeds
                .lock()
                .unwrap()
                .push((agent.to_string(), queue.to_string(), part.to_string()));
            Ok(())
        }
    }
    impl Connectivity for Arc<FakeFleet> {
        fn online(&self) -> bool {
            !self.offline.load(Ordering::SeqCst)
        }
    }

    /// A recording [`LogSink`] — captures the audit lines the loop's owned
    /// dispatcher fanned out, so a test can assert "exactly one alert" without
    /// scraping stderr.
    #[derive(Debug, Default)]
    struct SpyLog {
        lines: Mutex<Vec<String>>,
    }
    impl SpyLog {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn lines(&self) -> Vec<String> {
            self.lines.lock().unwrap().clone()
        }
    }
    impl LogSink for Arc<SpyLog> {
        fn write_line(&self, line: &str) {
            self.lines.lock().unwrap().push(line.to_string());
        }
    }

    /// The dispatch side a test inspects after a tick: the GUI subscribe stream the
    /// loop's [`GuiNotifier`] fans alerts onto, and the audit-log spy. The fake
    /// backend publishes nothing to this hub, so every event on it is a dispatched
    /// alert.
    struct Probe {
        alerts: crate::hub::Subscription,
        log: Arc<SpyLog>,
    }
    impl Probe {
        /// Drain and count the alert bus-messages dispatched to the GUI hub.
        fn gui_alerts(&self) -> usize {
            let mut n = 0;
            while self.alerts.try_recv().is_ok() {
                n += 1;
            }
            n
        }
        fn log_lines(&self) -> Vec<String> {
            self.log.lines()
        }
    }

    /// A fixed (mutable) queue snapshot source.
    #[derive(Debug)]
    struct FixedQueues(Mutex<Snapshot>);
    impl FixedQueues {
        fn new(qs: Vec<QueueView>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(Snapshot::new(qs))))
        }
        /// Mark a part `blocked` in the shared snapshot — models keeperd's
        /// committed item-park write, so the NEXT `snapshot()` shows it blocked (the
        /// cross-tick half of pivot-on-block).
        fn mark_blocked(&self, queue: &str, part: &str) {
            self.0.lock().unwrap().mark_blocked(queue, part);
        }
        /// Mark a part `active` in the shared snapshot — models keeperd's
        /// committed claim write, so the NEXT `snapshot()` shows it claimed (the
        /// cross-tick half of the double-assignment fix).
        fn mark_active(&self, queue: &str, part: &str) {
            self.0.lock().unwrap().mark_claimed(queue, part);
        }
        /// Replace the whole snapshot — models the queue tables moving on between
        /// ticks (e.g. an agent marked its item `done` before reporting
        /// QUEUE_EMPTY, so the next tick sees a drained queue).
        fn set(&self, qs: Vec<QueueView>) {
            *self.0.lock().unwrap() = Snapshot::new(qs);
        }
    }
    impl QueueSource for Arc<FixedQueues> {
        fn snapshot(&self) -> Snapshot {
            self.0.lock().unwrap().clone()
        }
    }

    /// A fake [`PartClaimer`]: records every claim, can be scripted to fail (the
    /// fail-closed path), and on success marks the part `active` in the SAME
    /// `FixedQueues` the loop reads — so a claim shows up on the next tick's
    /// snapshot exactly as keeperd's committed write would (the cross-tick half).
    #[derive(Debug)]
    struct FakeClaimer {
        claims: Mutex<Vec<(String, String)>>,
        /// Per-claim holder id (the agent the loop stamped the claim with), in
        /// claim order — proves the member id is plumbed to keeperd's CAS.
        holders: Mutex<Vec<String>>,
        fail: AtomicBool,
        committed: Arc<FixedQueues>,
    }
    impl FakeClaimer {
        fn new(committed: Arc<FixedQueues>) -> Arc<Self> {
            Arc::new(Self {
                claims: Mutex::new(Vec::new()),
                holders: Mutex::new(Vec::new()),
                fail: AtomicBool::new(false),
                committed,
            })
        }
        fn set_fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }
        fn claims(&self) -> Vec<(String, String)> {
            self.claims.lock().unwrap().clone()
        }
        fn holders(&self) -> Vec<String> {
            self.holders.lock().unwrap().clone()
        }
    }
    impl PartClaimer for Arc<FakeClaimer> {
        fn claim(&self, queue: &str, part: &str, holder: &str) -> Result<(), String> {
            if self.fail.load(Ordering::SeqCst) {
                return Err("claim refused".into());
            }
            self.claims.lock().unwrap().push((queue.to_string(), part.to_string()));
            self.holders.lock().unwrap().push(holder.to_string());
            self.committed.mark_active(queue, part);
            Ok(())
        }
    }

    /// A fake [`ItemParker`]: records every item-park, can be scripted to fail (the
    /// fail-soft path), and on success marks the part `blocked` in the SAME
    /// `FixedQueues` the loop reads — so the block shows up on the next tick's
    /// snapshot exactly as keeperd's committed `blocked` write would (the cross-tick
    /// half), mirroring [`FakeClaimer`].
    #[derive(Debug)]
    struct FakeParker {
        parks: Mutex<Vec<(String, String)>>,
        fail: AtomicBool,
        committed: Arc<FixedQueues>,
    }
    impl FakeParker {
        fn new(committed: Arc<FixedQueues>) -> Arc<Self> {
            Arc::new(Self {
                parks: Mutex::new(Vec::new()),
                fail: AtomicBool::new(false),
                committed,
            })
        }
        fn set_fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }
        fn parks(&self) -> Vec<(String, String)> {
            self.parks.lock().unwrap().clone()
        }
    }
    impl ItemParker for Arc<FakeParker> {
        fn park_item(&self, queue: &str, part: &str) -> Result<(), String> {
            self.parks.lock().unwrap().push((queue.to_string(), part.to_string()));
            if self.fail.load(Ordering::SeqCst) {
                return Err("block refused".into());
            }
            self.committed.mark_blocked(queue, part);
            Ok(())
        }
    }

    fn hot_budget() -> BudgetUsage {
        BudgetUsage::new(90, 5) // over the 85 5h halt
    }
    fn spec(id: &str) -> AgentSpec {
        AgentSpec::new(id, format!("/cfg/{id}/loop.json"), format!("/cfg/{id}/mcp.json"))
    }
    fn member(id: &str, pin: &str) -> FleetMember {
        FleetMember::pinned(spec(id), pin)
    }
    fn q(name: &str, rows: &[(&str, &str)]) -> QueueView {
        QueueView::new(
            name,
            rows.iter().map(|(i, s)| PartView::new(*i, s)).collect(),
        )
    }
    /// A daemon whose runtime policy matches the supervisor's governor — exactly
    /// the production invariant (both derive from one `config.policy`). The drive
    /// loop refreshes its governor from the daemon each tick, so they must start
    /// consistent or the refresh would clobber a test's non-default policy.
    fn daemon(policy: Policy) -> Daemon {
        Daemon::new(
            GrowlightdConfig::new("/run/g.sock".into(), "/garden".into()).with_policy(policy),
        )
    }

    /// Assemble a loop with the given fleet + policy over fresh seam fakes,
    /// returning the loop plus the handles a test pokes (daemon control, the fake
    /// backend = health + budget source, and a [`Probe`] over the owned
    /// dispatcher's GUI hub + audit log). The supervisor uses a small,
    /// easy-to-assert backoff; the dispatcher's cooldown is huge so a sustained
    /// condition (a still-blocked head re-surfaced every tick) announces once.
    fn make(
        fleet: Vec<FleetMember>,
        snapshot: Vec<QueueView>,
        policy: Policy,
    ) -> (DriveLoop, Daemon, Arc<FakeFleet>, Probe) {
        let (drive, d, backend, _claimer, _queues, probe) = make_claiming(fleet, snapshot, policy);
        (drive, d, backend, probe)
    }

    /// Like [`make`], but also hands back the [`FakeClaimer`] so a test can inspect
    /// the recorded claims or script a claim failure. The claimer is wired to the
    /// SAME [`FixedQueues`] the loop reads, so a successful claim marks the part
    /// `active` in the shared snapshot (the cross-tick half) while the loop's own
    /// `mark_claimed` is the intra-tick half. A thin wrapper over [`make_full`] that
    /// drops the parker handle (most tests don't poke item-parking).
    fn make_claiming(
        fleet: Vec<FleetMember>,
        snapshot: Vec<QueueView>,
        policy: Policy,
    ) -> (DriveLoop, Daemon, Arc<FakeFleet>, Arc<FakeClaimer>, Arc<FixedQueues>, Probe) {
        let (drive, d, backend, claimer, _parker, queues, probe) =
            make_full(fleet, snapshot, policy);
        (drive, d, backend, claimer, queues, probe)
    }

    /// The full builder: like [`make_claiming`] but ALSO hands back the
    /// [`FakeParker`] so a slice-003 item-park test can inspect the recorded
    /// `blocked` writes or script a fail-soft failure. The parker is wired to the
    /// SAME [`FixedQueues`] the loop reads, so a successful item-park marks the part
    /// `blocked` in the shared snapshot (the cross-tick half) while the loop's own
    /// `mark_blocked` is the intra-tick half — mirroring the claimer.
    #[allow(clippy::type_complexity)]
    fn make_full(
        fleet: Vec<FleetMember>,
        snapshot: Vec<QueueView>,
        policy: Policy,
    ) -> (
        DriveLoop,
        Daemon,
        Arc<FakeFleet>,
        Arc<FakeClaimer>,
        Arc<FakeParker>,
        Arc<FixedQueues>,
        Probe,
    ) {
        let d = daemon(policy);
        let backend = FakeFleet::new();
        let queues = FixedQueues::new(snapshot);
        let claimer = FakeClaimer::new(Arc::clone(&queues));
        let parker = FakeParker::new(Arc::clone(&queues));
        let sup = Supervisor::with_backoff(
            Box::new(Arc::clone(&backend)),
            AdmissionGovernor::new(policy),
            Backoff {
                base_secs: 2,
                cap_secs: 8,
            },
            100,
        );
        let hub = EventHub::new();
        let alerts = hub.subscribe();
        let log = SpyLog::new();
        let mut dispatcher = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(1_000_000));
        dispatcher.register(Box::new(GuiNotifier::new(hub)));
        dispatcher.register(Box::new(LogNotifier::new(Arc::clone(&log))));
        let drive = DriveLoop::new(
            d.clone(),
            sup,
            Box::new(Arc::clone(&backend)), // health
            Box::new(Arc::clone(&backend)), // stderr tail — scripted via set_stderr
            Box::new(Arc::clone(&backend)), // baton status — scripted via set_baton
            Box::new(Arc::clone(&backend)), // seeder — records seeds, scriptable failure
            Box::new(Arc::clone(&queues)),
            Box::new(Arc::clone(&claimer)),
            Box::new(Arc::clone(&parker)),
            Box::new(Arc::clone(&backend)),
            Box::new(PermissiveRate),
            Box::new(Arc::clone(&backend)), // connectivity — scripted via set_offline (default online)
            dispatcher,
            fleet,
        );
        (drive, d, backend, claimer, parker, queues, Probe { alerts, log })
    }

    /// SLICE 001 — offline at a FRESH START: the pre-spawn connectivity gate HOLDS
    /// the start (no spawn, no claim, no crash, no alert) and flags
    /// `waiting_for_connectivity`; when the link returns the next tick spawns
    /// cleanly, with NO backoff (the spawn was never attempted, so no failure streak
    /// accrued) — the whole point of the failsafe.
    #[test]
    fn offline_holds_the_fresh_start_then_resumes_when_the_link_returns() {
        let (mut loop_, _d, backend, claimer, _queues, probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        backend.set_offline(true);
        let r = loop_.tick(0);
        assert!(r.waiting_for_connectivity, "the tick reports the offline HOLD");
        assert!(r.started.is_empty(), "no start issued while offline");
        assert!(backend.spawns().is_empty(), "no `claude -p` spawned while offline");
        assert!(claimer.claims().is_empty(), "no part claimed while offline");
        assert!(r.crashes.is_empty(), "an offline hold is NOT a crash");
        assert_eq!(probe.gui_alerts(), 0, "a blip pages nobody");

        // The link returns: the held start now proceeds, cleanly and exactly once.
        backend.set_offline(false);
        let r2 = loop_.tick(1);
        assert!(!r2.waiting_for_connectivity);
        assert_eq!(
            r2.started,
            vec![Assignment {
                agent: "a1".into(),
                queue: "qa".into(),
                part: "p1".into(),
            }],
            "the spawn proceeds the moment the link returns",
        );
        assert_eq!(backend.spawns(), vec!["a1"], "exactly one spawn, on reconnect");
        assert_eq!(
            claimer.claims(),
            vec![("qa".into(), "p1".into())],
            "the part is claimed only on the real start, never during the hold",
        );
    }

    /// SLICE 001 — offline holds the RE-ROLL too (the ACTUAL 2026-07-01 crash-loop
    /// path: a running member's session dies and would re-roll into an instant crash
    /// while the link is down). A member that exited clean and is due to re-roll is
    /// NOT re-spawned while offline — no re-roll, no backoff, no crash — and re-rolls
    /// on the same part once the link returns.
    #[test]
    fn offline_holds_a_reroll_then_resumes_when_the_link_returns() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        // tick 0: a1 starts on p1 (online).
        loop_.tick(0);
        assert_eq!(backend.spawns(), vec!["a1"], "a1 starts online");

        // a1 exits clean on a continue baton → a down re-roll candidate. Offline now
        // HOLDS the re-spawn (step 2): no re-roll, no crash — just the waiting flag.
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "IN_PROGRESS");
        backend.set_offline(true);
        let r1 = loop_.tick(1);
        assert!(r1.waiting_for_connectivity);
        assert!(r1.rerolls.is_empty(), "no re-roll attempted while offline");
        assert!(r1.crashes.is_empty(), "a held re-roll is NOT a crash");
        assert_eq!(backend.spawn_count(), 1, "no re-spawn while offline");

        // The link returns → it re-rolls on the same part, no backoff delay.
        backend.set_offline(false);
        let r2 = loop_.tick(2);
        assert!(!r2.waiting_for_connectivity);
        assert_eq!(
            r2.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "re-rolls the moment the link returns",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "re-rolled on reconnect");
    }

    /// SLICE 001 — the pure IPv4 routing-table parser [`v4_has_default`] over
    /// `/proc/net/route` fixtures: an UP default route reads online; a header-only,
    /// non-default-only, or down (no `RTF_UP`) table reads offline.
    #[test]
    fn v4_route_table_default_detection() {
        let with_default = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0";
        assert!(v4_has_default(with_default), "an UP default route is online");

        let header_only =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";
        assert!(!v4_has_default(header_only), "no routes → offline");

        let no_default = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0";
        assert!(!v4_has_default(no_default), "a non-default route only → offline");

        let down_default = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0100A8C0\t0002\t0\t0\t600\t00000000\t0\t0\t0";
        assert!(
            !v4_has_default(down_default),
            "a default route without RTF_UP → offline",
        );
    }

    /// SLICE 001 — the pure IPv6 routing-table parser [`v6_has_default`] over
    /// `/proc/net/ipv6_route` fixtures: an UP `::/0` route reads online; loopback +
    /// link-local only, or a `::/0` without `RTF_UP`, reads offline.
    #[test]
    fn v6_route_table_default_detection() {
        let with_default = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlan0";
        assert!(v6_has_default(with_default), "an UP ::/0 route is online");

        let loopback_and_ll = "\
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001 lo
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 wlan0";
        assert!(
            !v6_has_default(loopback_and_ll),
            "loopback + link-local only → offline",
        );

        let down_default = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000000 wlan0";
        assert!(
            !v6_has_default(down_default),
            "a ::/0 route without RTF_UP → offline",
        );
    }

    /// SLICE 002 — a mid-session network death (the peer's stderr tail carries a
    /// connection-error signature while online) is classified TRANSIENT: the member
    /// re-rolls off its baton with NO `AgentCrashed` alert, NO backoff, NO streak
    /// bump — the false-crash-loop fix. Online, so it re-rolls the same tick.
    #[test]
    fn a_mid_session_network_exit_reconnects_without_a_crash_alert() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        loop_.tick(0);
        assert_eq!(backend.spawns(), vec!["a1"], "a1 starts");

        // The link blips: a1 exits non-zero with an API connection-error tail while
        // still (just) online. Slice 002 reads that as a transient reconnect.
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        backend.set_stderr(
            "a1",
            &["API Error: Connection error (connection reset by peer)"],
        );
        let r = loop_.tick(1);
        assert_eq!(r.reconnecting, vec!["a1".to_string()], "a network exit reconnects");
        assert!(r.crashes.is_empty(), "NO AgentCrashed alert for a network blip");
        assert_eq!(probe.gui_alerts(), 0, "nobody is paged for a reconnect");
        // Re-rolled off the baton the SAME tick (online) — no backoff delay.
        assert_eq!(r.rerolls, vec![RerollOutcome::Rerolled { agent: "a1".into() }]);
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "reconnected off the baton");
    }

    /// SLICE 002 — an exit with NO network signature but OFFLINE at exit is still
    /// transient (the connectivity signal), and the reconnect LATCH keeps the SAME
    /// stale exit — re-polled after the link returns before step 2 re-rolls it — from
    /// escalating into a false crash. Slice 001's gate + slice 002's latch compose:
    /// no page, resume on reconnect.
    #[test]
    fn an_offline_exit_reconnects_and_the_latch_prevents_a_false_crash_on_return() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        loop_.tick(0);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // The link drops: a1 exits non-zero with NO stderr signature, offline. The
        // connectivity signal alone marks it transient; the slice-001 gate then holds
        // the re-roll while still offline.
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        backend.set_offline(true);
        let r1 = loop_.tick(1);
        assert_eq!(
            r1.reconnecting,
            vec!["a1".to_string()],
            "an offline exit is a reconnect, not a crash",
        );
        assert!(r1.crashes.is_empty(), "no crash alert");
        assert!(r1.waiting_for_connectivity, "the gate holds the re-roll while offline");
        assert_eq!(backend.spawn_count(), 1, "no re-spawn while offline");

        // The link returns. step 1 RE-POLLS the same stale exit — now online, with no
        // signature — which WITHOUT the latch would classify a false crash. The latch
        // keeps it a reconnect, and step 2 re-rolls it off the baton.
        backend.set_offline(false);
        let r2 = loop_.tick(2);
        assert!(r2.crashes.is_empty(), "the latch prevents a false crash on reconnect");
        assert_eq!(probe.gui_alerts(), 0, "still nobody paged");
        assert_eq!(r2.rerolls, vec![RerollOutcome::Rerolled { agent: "a1".into() }]);
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "resumed on reconnect");
    }

    /// SLICE 002 — the pure network-exit classifier over fixtures (network vs genuine
    /// crash), the provable core the drive loop feeds `poll_with_network`.
    #[test]
    fn network_exit_classifier_distinguishes_network_from_a_genuine_crash() {
        // Online + a connection-error signature → transient (a blip that recovered).
        assert!(is_transient_network_exit(
            &["API Error: Connection reset by peer".to_string()],
            true,
        ));
        // Online + a DNS signature → transient.
        assert!(is_transient_network_exit(
            &["error sending request: dns error: failed to lookup address".to_string()],
            true,
        ));
        // Offline at exit, no signature at all → transient (the connectivity signal).
        assert!(is_transient_network_exit(&[], false));
        // Online + a genuine crash (a panic, no network signature) → NOT transient.
        assert!(!is_transient_network_exit(
            &["thread 'main' panicked at src/main.rs:12:5: index out of bounds".to_string()],
            true,
        ));
        // Online + an application error (a 500, no connection-layer signature) → NOT
        // transient: a real failure must still crash, not silently reconnect-loop.
        assert!(!is_transient_network_exit(
            &["API Error: 500 Internal Server Error".to_string()],
            true,
        ));
        // The signature match is case-insensitive and specific to the connection layer.
        assert!(stderr_matches_network_signature(&["ECONNRESET".to_string()]));
        assert!(!stderr_matches_network_signature(&["clean shutdown".to_string()]));
    }

    /// SLICE 003 — a connectivity BLIP stays quiet: offline for less than the
    /// sustained-outage threshold pages NOBODY (the whole point — the 2026-07-01 loop
    /// paged every ~30min), even though the pre-spawn gate holds spawns; and its
    /// recovery clears silently since it never paged.
    #[test]
    fn a_connectivity_blip_pages_nobody() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        backend.set_offline(true);
        loop_.tick(0); // offline_since = 0
        loop_.tick(30);
        loop_.tick(60); // still well under the threshold
        backend.set_offline(false);
        loop_.tick(90); // reconnect before the threshold → silent clear
        assert_eq!(probe.gui_alerts(), 0, "a blip and its recovery page nobody");
        assert!(probe.log_lines().is_empty(), "and log nothing");
    }

    /// SLICE 003 — a SUSTAINED outage pages the human EXACTLY ONCE past the threshold
    /// (not every tick), and a `NetworkRecovered` clears it on reconnect — the quiet-
    /// on-blip / alert-once-on-outage policy the milestone requires.
    #[test]
    fn a_sustained_outage_pages_once_then_clears_on_reconnect() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        backend.set_offline(true);
        loop_.tick(0); // offline_since = 0
        loop_.tick(OFFLINE_ALERT_THRESHOLD_SECS - 1); // still under → quiet
        assert_eq!(probe.gui_alerts(), 0, "under the threshold stays quiet");

        // Cross the threshold and stay offline several ticks: exactly one page.
        loop_.tick(OFFLINE_ALERT_THRESHOLD_SECS);
        loop_.tick(OFFLINE_ALERT_THRESHOLD_SECS + 60);
        loop_.tick(OFFLINE_ALERT_THRESHOLD_SECS + 120);
        assert_eq!(probe.gui_alerts(), 1, "a sustained outage pages exactly once, not per tick");

        // Reconnect emits exactly one recovery event (the clear), so `watch` sees it.
        backend.set_offline(false);
        loop_.tick(OFFLINE_ALERT_THRESHOLD_SECS + 150);
        assert_eq!(probe.gui_alerts(), 1, "reconnect emits one recovery event");
    }

    /// The loop picks each member's pinned part, admits under the per-device cap,
    /// and queues the over-cap start.
    #[test]
    fn schedules_and_starts_under_the_cap_queuing_the_rest() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![member("a1", "qa"), member("a2", "qb"), member("a3", "qc")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("qb", &[("p2", "queued")]),
                q("qc", &[("p3", "queued")]),
            ],
            Policy::default(), // cap 2
        );

        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![
                Assignment {
                    agent: "a1".into(),
                    queue: "qa".into(),
                    part: "p1".into()
                },
                Assignment {
                    agent: "a2".into(),
                    queue: "qb".into(),
                    part: "p2".into()
                },
            ],
            "two members start, each on its pinned part",
        );
        assert_eq!(
            r.held_starts,
            vec![HeldStart {
                agent: "a3".into(),
                outcome: StartOutcome::Queued { active: 2, cap: 2 },
            }],
            "the third is queued behind the cap",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a2"], "only admitted starts spawn");

        // A second tick starts nothing new (the two are running; the third is still
        // capped) and re-rolls nothing (all healthy / no observation).
        let r2 = loop_.tick(1);
        assert!(r2.started.is_empty());
        assert_eq!(backend.spawn_count(), 2, "no duplicate spawn of running agents");
    }

    /// A live `set_policy` change to the runtime policy takes effect at the next
    /// admission boundary: the loop refreshes its governor from the daemon's policy
    /// each tick, so raising the cap admits a previously-capped start on the very
    /// next tick — and lowering it later holds new starts — with no restart.
    #[test]
    fn a_runtime_policy_change_takes_effect_at_the_next_tick() {
        let (mut loop_, d, backend, _probe) = make(
            vec![member("a1", "qa"), member("a2", "qb"), member("a3", "qc")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("qb", &[("p2", "queued")]),
                q("qc", &[("p3", "queued")]),
            ],
            Policy::default(), // cap 2
        );

        // Tick 0: cap 2 → a1, a2 start; a3 is queued behind the cap.
        let r0 = loop_.tick(0);
        assert_eq!(r0.started.len(), 2);
        assert_eq!(backend.spawns(), vec!["a1", "a2"]);

        // Raise the cap to 3 at runtime — exactly what the `set_policy` verb writes.
        d.set_policy(Policy {
            max_concurrent_agents: 3,
            ..Policy::default()
        });

        // The next tick reflects the new cap: a3 is now admitted (no restart).
        let r1 = loop_.tick(1);
        assert_eq!(
            r1.started,
            vec![Assignment {
                agent: "a3".into(),
                queue: "qc".into(),
                part: "p3".into()
            }],
            "raising the cap admits the previously-queued start at the next boundary",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a2", "a3"]);
        // The governor now reports the live cap (the refresh rebuilt it).
        assert_eq!(loop_.supervisor.policy().max_concurrent_agents, 3);
    }

    /// An exhausted shared budget refuses a start (not a slot wait): the fleet
    /// aggregate, fed from a1's hot reading of the shared pool, is over the rail.
    #[test]
    fn an_exhausted_budget_refuses_the_start() {
        let (mut loop_, _d, backend, _probe) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        backend.set_budget("a1", hot_budget());

        let r = loop_.tick(0);
        assert!(r.started.is_empty());
        assert_eq!(
            r.held_starts,
            vec![HeldStart {
                agent: "a1".into(),
                outcome: StartOutcome::Refused {
                    reason: RefuseReason::Budget5h
                },
            }],
        );
        assert_eq!(backend.spawn_count(), 0, "a refused start never spawns");
    }

    /// A blocked pinned head does not halt the agent — it pivots to another queue,
    /// and the blocked head is surfaced as parked for the §9 alert.
    #[test]
    fn pivots_off_a_blocked_pinned_queue_and_surfaces_the_park() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![member("a1", "mine")],
            vec![
                q("mine", &[("p1", "blocked"), ("p2", "queued")]),
                q("other", &[("o1", "queued")]),
            ],
            Policy::default(),
        );

        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![Assignment {
                agent: "a1".into(),
                queue: "other".into(),
                part: "o1".into()
            }],
            "a blocked pinned head pivots to the fallback queue",
        );
        assert_eq!(
            r.parked,
            vec![("mine".into(), "p1".into())],
            "the blocked head is surfaced for the human alert",
        );
        assert_eq!(backend.spawns(), vec!["a1"]);
    }

    /// A pending boundary stop is honored once: the agent retires at its next clean
    /// boundary instead of re-rolling, and is never re-started.
    #[test]
    fn honors_a_boundary_stop_then_never_re_starts_the_agent() {
        let (mut loop_, d, backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());

        // Tick 1 starts a1.
        assert_eq!(loop_.tick(0).started.len(), 1);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // The human asks a1 to stop after its slice; a1 then reaches a clean
        // boundary (exit 0).
        d.inner
            .lock()
            .unwrap()
            .control
            .request_stop("a1", StopLevel::AfterSlice);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });

        let r = loop_.tick(1);
        assert_eq!(r.retired, vec!["a1".to_string()], "the boundary stop retired a1");
        assert!(r.rerolls.is_empty(), "a retiring agent does not re-roll");
        assert_eq!(backend.spawn_count(), 1, "a1 was not re-spawned");

        // The stop is permanent for this run: even with workable queued work, a
        // later tick never re-starts a1.
        let r2 = loop_.tick(2);
        assert!(r2.started.is_empty() && r2.rerolls.is_empty());
        assert_eq!(backend.spawn_count(), 1, "a stopped agent is never re-started");
    }

    /// The inject lane is boundary-async: a queued message is invisible until the
    /// next tick drains it, and it is delivered exactly once.
    #[test]
    fn drains_the_inject_lane_at_the_boundary_once() {
        let (mut loop_, d, _backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        loop_.tick(0); // start a1

        // Queue two messages mid-run; nothing observes them yet.
        d.inner.lock().unwrap().control.queue_inject("a1", "ping".into());
        d.inner.lock().unwrap().control.queue_inject("a1", "pong".into());

        let r = loop_.tick(1);
        assert_eq!(
            r.injected,
            vec![("a1".to_string(), vec!["ping".to_string(), "pong".to_string()])],
            "the lane drains in FIFO order at the boundary",
        );

        // Delivered once — the next boundary drains nothing.
        let r2 = loop_.tick(2);
        assert!(r2.injected.is_empty(), "a second boundary drains nothing");
    }

    /// A crashed agent surfaces an `AgentCrashed` alert, is held through its
    /// backoff window, then re-rolls when the window opens.
    #[test]
    fn re_rolls_a_crashed_agent_after_its_backoff() {
        let (mut loop_, _d, backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());

        // Tick 1 starts a1.
        loop_.tick(0);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 errors out → crash classification. A GENUINE crash (a panic — no
        // network signature, and online), so network-failsafe slice 002 does NOT
        // reclassify it as a transient reconnect; its stderr ring holds the reason
        // (crash-diagnostics slice 001), so the surfaced alert must carry it.
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        backend.set_stderr("a1", &["thread 'main' panicked at src/main.rs:12:5: boom"]);
        let r = loop_.tick(0);
        assert_eq!(
            r.crashes,
            vec![NotifyEvent::agent_crashed("a1")
                .with_stderr_tail(vec!["thread 'main' panicked at src/main.rs:12:5: boom".to_string()])],
            "the crash surfaces an alert carrying the stderr tail (crash-diagnostics slice 001)",
        );
        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::HeldForBackoff {
                agent: "a1".into(),
                not_before: 2,
            }],
            "inside the backoff window it is held",
        );
        assert_eq!(backend.spawn_count(), 1, "no re-spawn yet");

        // The re-rolled session is healthy; at the backoff boundary it re-rolls.
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r2 = loop_.tick(2);
        assert!(r2.crashes.is_empty(), "the healthy poll raises no new crash");
        assert_eq!(
            r2.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "a1 was re-spawned");
    }

    /// THE SPIN FIX end-to-end ([[decision-growlight-fleet-loop-spin]]): a member
    /// that exits clean with a `QUEUE_EMPTY` baton is retired to idle and NOT
    /// re-rolled — no fresh `claude -p` against a drained queue — and the daemon
    /// stays resident, re-starting a member only when new queued work appears.
    #[test]
    fn a_queue_empty_baton_retires_to_idle_then_re_starts_on_new_work() {
        let (mut loop_, _d, backend, _claimer, queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        // Tick 0 starts a1 on p1 (claiming it `active`).
        loop_.tick(0);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 finished its item and reported QUEUE_EMPTY: the queue is drained
        // (p1 `done`) and the member exits clean with that terminal baton.
        queues.set(vec![q("qa", &[("p1", "done")])]);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "QUEUE_EMPTY");

        let r = loop_.tick(1);
        assert_eq!(r.retired, vec!["a1".to_string()], "the member retired to idle");
        assert!(
            r.rerolls.is_empty(),
            "a QUEUE_EMPTY member is NOT re-rolled — the inverse of the old spin",
        );
        assert!(r.started.is_empty(), "nothing to start on a drained queue");
        assert_eq!(backend.spawn_count(), 1, "NO fresh claude -p on the drained queue");

        // The daemon stays resident and idle — a tick on the still-drained queue
        // spawns nothing (zero agents running, no burn).
        let r2 = loop_.tick(2);
        assert!(r2.rerolls.is_empty() && r2.started.is_empty(), "idle: zero agents");
        assert_eq!(backend.spawn_count(), 1, "still no spin while idle");

        // New queued work appears → the loop re-starts a member.
        queues.set(vec![q("qa", &[("p2", "queued")])]);
        let r3 = loop_.tick(3);
        assert_eq!(r3.started.len(), 1, "new queued work re-starts a member");
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "a1 re-started on the new part");
    }

    /// SLICE 003 — the headline: a `STUCK` / `BLOCKED_ON_HUMAN` member is RELEASED
    /// to idle (not sticky-parked on its slot), its current part is **item-parked**
    /// (`blocked` in keeperd), the human is alerted on the ITEM, and the freed member
    /// **pivots** the same tick onto a different queue's work (pivot-on-block).
    #[test]
    fn a_stuck_member_is_released_item_parked_and_pivots() {
        let (mut loop_, _d, backend, _claimer, parker, queues, probe) = make_full(
            vec![member("a1", "qa")],
            vec![
                q("qa", &[("p1", "queued")]), // a1's pinned work
                q("qb", &[("o1", "queued")]), // the pivot target
            ],
            Policy::default(),
        );

        loop_.tick(0); // a1 starts on its pinned qa/p1 (claimed active)
        assert_eq!(backend.spawn_count(), 1);

        // a1 exits clean but wrote a STUCK baton → release + item-park p1 + pivot.
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "STUCK");

        let r = loop_.tick(1);

        // The part is item-parked — both in keeperd (the write seam) and surfaced.
        assert_eq!(
            parker.parks(),
            vec![("qa".into(), "p1".into())],
            "the member's current part is marked blocked in keeperd",
        );
        assert_eq!(
            r.blocked,
            vec![Assignment { agent: "a1".into(), queue: "qa".into(), part: "p1".into() }],
            "the release-on-block is reported with its item",
        );
        assert_eq!(
            r.parked,
            vec![("qa".into(), "p1".into())],
            "the item-parked head is surfaced for the §9 alert this tick",
        );
        assert_eq!(probe.gui_alerts(), 1, "the human is alerted on the item, once");
        assert!(r.crashes.is_empty(), "a human-block is not a crash");

        // The freed member pivots onto the other queue's work the same tick.
        assert_eq!(
            r.started,
            vec![Assignment { agent: "a1".into(), queue: "qb".into(), part: "o1".into() }],
            "the released member pivots past its blocked part to qb (pivot-on-block)",
        );
        assert!(r.rerolls.is_empty(), "a released member re-starts, it is not re-rolled");
        assert_eq!(backend.spawn_count(), 2, "the pivot is a fresh spawn");

        // keeperd now holds p1 `blocked` (committed by the parker) — so a later
        // snapshot keeps pivoting past it until a human clears it (slice 004).
        assert_eq!(
            classify_queue(queues.0.lock().unwrap().queue("qa").unwrap()),
            QueueState::Blocked("p1".into()),
        );
    }

    /// Fail-soft: if the keeperd item-park WRITE can't be confirmed, the member is
    /// STILL released and STILL pivots this tick (the local snapshot mark drives the
    /// pivot + alert); only the cross-tick `blocked` commit is missing, so keeperd's
    /// part lingers `active` until the pinned member cycles back and re-blocks it.
    /// The slot is never stuck — that is the whole fix.
    #[test]
    fn a_failed_item_park_still_releases_and_pivots() {
        let (mut loop_, _d, backend, _claimer, parker, queues, probe) = make_full(
            vec![member("a1", "qa")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("qb", &[("o1", "queued")]),
            ],
            Policy::default(),
        );

        loop_.tick(0); // a1 starts on qa/p1
        parker.set_fail(true); // keeperd refuses / is unreachable for the block write

        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "BLOCKED_ON_HUMAN");

        let r = loop_.tick(1);
        assert_eq!(parker.parks(), vec![("qa".into(), "p1".into())], "the write was attempted");
        assert_eq!(probe.gui_alerts(), 1, "the human is still alerted this tick");
        assert_eq!(
            r.started,
            vec![Assignment { agent: "a1".into(), queue: "qb".into(), part: "o1".into() }],
            "the member still pivots locally even though the block write failed",
        );
        // keeperd's qa/p1 was NOT committed blocked (the write failed) — it lingers
        // `active`, to be re-blocked when the member next resolves to it. No sticky slot.
        assert_eq!(
            classify_queue(queues.0.lock().unwrap().queue("qa").unwrap()),
            QueueState::Active("p1".into()),
            "the uncommitted block left the part active in keeperd (fail-soft)",
        );
    }

    /// `pause` is the admission gate: a paused fleet starts nothing and re-rolls
    /// nothing; resuming releases both. Parked queues are still surfaced.
    #[test]
    fn pause_gates_starts_and_re_rolls_resume_releases_them() {
        let (mut loop_, d, backend, _probe) = make(
            vec![member("a1", "qa")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("parked", &[("b1", "blocked")]),
            ],
            Policy::default(),
        );

        // Start a1, then crash it so a re-roll is pending.
        loop_.tick(0);
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        loop_.tick(0); // crash → held for backoff (not_before 2)
        assert_eq!(backend.spawn_count(), 1);

        // Pause; past the backoff window a re-roll would be due, but pause gates it.
        d.inner.lock().unwrap().control.pause();
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r = loop_.tick(2);
        assert!(r.paused, "the tick reports the paused gate");
        assert!(r.rerolls.is_empty(), "no re-roll while paused");
        assert!(r.started.is_empty(), "no new start while paused");
        assert_eq!(
            r.parked,
            vec![("parked".into(), "b1".into())],
            "parked queues are surfaced even while paused",
        );
        assert_eq!(backend.spawn_count(), 1, "paused: nothing spawned");

        // Resume → the held re-roll fires.
        d.inner.lock().unwrap().control.resume();
        let r2 = loop_.tick(3);
        assert!(!r2.paused);
        assert_eq!(
            r2.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "resume releases the re-roll",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"]);
    }

    /// Slice-003 (a): `pause` gates EVERY spawn path. A member that FINISHES on a
    /// clean boundary (which would otherwise re-roll immediately) spawns nothing for
    /// as long as the fleet is paused — across repeated ticks — then resuming
    /// releases exactly one respawn. This is the smoke's "pause didn't stop the
    /// spawns" regression, in its sharpest form (a clean finish, not a crash).
    #[test]
    fn paused_a_finished_member_never_respawns_until_resume() {
        let (mut loop_, d, backend, _claimer, _queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued"), ("p2", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a1 starts on p1
        assert_eq!(backend.spawn_count(), 1);

        // Pause, THEN a1 finishes a slice on a continue boundary (it would re-roll).
        d.inner.lock().unwrap().control.pause();
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "IN_PROGRESS");

        // Many ticks while paused → not a single respawn (every spawn path gated).
        for now in 1..=5 {
            let r = loop_.tick(now);
            assert!(r.paused, "tick {now} reports the paused gate");
            assert!(
                r.rerolls.is_empty() && r.started.is_empty(),
                "tick {now}: paused fleet (re-)spawns nothing",
            );
        }
        assert_eq!(backend.spawn_count(), 1, "paused: zero spawns across 5 ticks");

        // Resume → the held re-roll finally fires (exactly once).
        d.inner.lock().unwrap().control.resume();
        let r = loop_.tick(6);
        assert_eq!(r.rerolls, vec![RerollOutcome::Rerolled { agent: "a1".into() }]);
        assert_eq!(backend.spawn_count(), 2, "resume releases exactly one respawn");
    }

    /// Slice-003 (c): atomic `max_agents` at the loop level. With cap 1, while one
    /// member is down inside its crash backoff (it still OWNS its slot), a second
    /// member's fresh start stays QUEUED — concurrency never transiently exceeds the
    /// cap, even though no child is live at the instant the start is considered.
    /// (With the old live-child gate the start was admitted into the momentarily
    /// empty slot, then the backing-off member re-rolled → TWO concurrent vs cap 1.)
    #[test]
    fn concurrency_never_exceeds_the_cap_while_a_member_backs_off() {
        let policy = Policy {
            max_concurrent_agents: 1,
            ..Policy::default()
        };
        let (mut loop_, _d, backend, _claimer, _queues, _probe) = make_claiming(
            vec![member("a1", "qa"), member("a2", "qb")],
            vec![q("qa", &[("p1", "queued")]), q("qb", &[("p2", "queued")])],
            policy,
        );

        // Tick 0: only a1 starts (cap 1); a2 is held behind the cap.
        let r0 = loop_.tick(0);
        assert_eq!(r0.started.len(), 1, "one start under cap 1");
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 crashes → down, registered, inside its backoff window.
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        let r1 = loop_.tick(1);
        assert!(
            matches!(r1.rerolls.as_slice(), [RerollOutcome::HeldForBackoff { .. }]),
            "a1 is down, held inside its backoff: {:?}",
            r1.rerolls,
        );
        // a2 must STILL be queued — the down member's slot is reserved, not stolen.
        assert!(
            r1.started.is_empty(),
            "a fresh start cannot fill the slot a backing-off member still owns",
        );
        assert!(
            r1.held_starts
                .iter()
                .any(|h| h.agent == "a2" && matches!(h.outcome, StartOutcome::Queued { .. })),
            "a2 stays queued behind the committed cap: {:?}",
            r1.held_starts,
        );
        assert_eq!(backend.spawn_count(), 1, "never two concurrent against cap 1");
    }

    /// Slice-003 (2): the re-roll's queue-gate at the loop level. A member that
    /// exits on a CONTINUE status but whose queue has since DRAINED is held
    /// (`HeldNoWork`), not respawned into an empty queue — the belt-and-suspenders
    /// to slice 001's `QUEUE_EMPTY` retire. When queued work reappears it re-rolls.
    #[test]
    fn a_continue_exit_into_a_drained_queue_is_held_not_re_rolled() {
        let (mut loop_, _d, backend, _claimer, queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a1 starts on p1
        assert_eq!(backend.spawn_count(), 1);

        // a1 exits on a CONTINUE status, but its queue drained in the meantime
        // (the item finished `done`, nothing else queued).
        queues.set(vec![q("qa", &[("p1", "done")])]);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "IN_PROGRESS");

        let r = loop_.tick(1);
        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::HeldNoWork { agent: "a1".into() }],
            "a continue-status exit into a drained queue is held, not respawned",
        );
        assert_eq!(backend.spawn_count(), 1, "no fresh claude -p into an empty queue");

        // New queued work appears → it re-rolls.
        queues.set(vec![q("qa", &[("p2", "queued")])]);
        let r2 = loop_.tick(2);
        assert_eq!(r2.rerolls, vec![RerollOutcome::Rerolled { agent: "a1".into() }]);
        assert_eq!(backend.spawn_count(), 2, "work reappears → the member re-rolls");
    }

    /// Task-033 regression (the 2026-07-06 stall): a fleet-of-one UNPINNED member
    /// exits clean on a CONTINUE status (`IN_PROGRESS` — same part carries
    /// forward, the member exits for the orchestrator) while its own part is the
    /// queue's `active` head — its own claim. Fallback `pick` deliberately skips
    /// `active` heads (anti-starvation for OTHER agents), so without the
    /// own-assignment check the queue-gate reads "no work" and holds the member
    /// `HeldNoWork` every tick forever: the item stays `active`, `agents (none)`,
    /// the fleet is not self-sustaining. The member must re-roll onto its own
    /// in-progress part instead.
    #[test]
    fn an_unpinned_member_resumes_its_own_active_part_after_a_continue_exit() {
        let (mut loop_, _d, backend, _claimer, _queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a1"))],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a1 claims p1 (`active` in the shared snapshot) and starts
        assert_eq!(backend.spawn_count(), 1);

        // a1 exits clean mid-item; p1 is still `active` (its own claim), nothing
        // else queued anywhere.
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "IN_PROGRESS");

        let r = loop_.tick(1);
        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "the member re-rolls onto its own in-progress part, not HeldNoWork",
        );
        assert_eq!(backend.spawn_count(), 2, "the fleet keeps driving the item");

        // And it keeps sustaining across further iterations on the same part.
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        let r2 = loop_.tick(2);
        assert_eq!(
            r2.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "iteration after iteration, no manual nudge",
        );
        assert_eq!(backend.spawn_count(), 3);
    }

    /// The pinned flavour of the same hole: a member pinned to a DRAINED queue
    /// whose fallback pick landed it in ANOTHER queue — its pin yields nothing and
    /// fallback skips its own now-`active` part, so only the recorded assignment
    /// makes it workable again after a continue exit.
    #[test]
    fn a_pinned_member_resumes_its_own_fallback_part_after_a_continue_exit() {
        let (mut loop_, _d, backend, _claimer, _queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[]), q("qb", &[("p1", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // pin qa is empty → fallback claims qb/p1
        assert_eq!(backend.spawn_count(), 1);

        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "IN_PROGRESS");

        let r = loop_.tick(1);
        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "the fallback part it holds is its own workable work",
        );
        assert_eq!(backend.spawn_count(), 2);
    }

    /// Task-033 diagnosability: one-shot lifecycle events narrate every
    /// occurrence, while a HELD state (re-observed every ~1s tick by design) logs
    /// only on its ENTRY edge and re-arms after it clears — a stalled fleet writes
    /// one journal line, not one per second.
    #[test]
    fn tick_logger_narrates_one_shots_and_dedups_held_states() {
        let mut logger = TickLogger::default();

        let started = TickReport {
            started: vec![Assignment {
                agent: "a".into(),
                queue: "default".into(),
                part: "020".into(),
            }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&started),
            vec!["fleet: started a on default/020".to_string()],
        );

        // The stall shape: held (no workable part) tick after tick → one line.
        let held = TickReport {
            rerolls: vec![RerollOutcome::HeldNoWork { agent: "a".into() }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&held),
            vec!["fleet: holding a (no workable part)".to_string()],
            "the hold logs on entry",
        );
        assert!(
            logger.lines(&held).is_empty() && logger.lines(&held).is_empty(),
            "a persisting hold does not repeat",
        );

        // The hold clears (a re-roll fires) → narrated; a LATER hold re-logs.
        let rolled = TickReport {
            rerolls: vec![RerollOutcome::Rerolled { agent: "a".into() }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&rolled),
            vec!["fleet: re-rolled a (fresh session, same part)".to_string()],
        );
        assert_eq!(
            logger.lines(&held),
            vec!["fleet: holding a (no workable part)".to_string()],
            "the edge re-arms once the hold clears",
        );
    }

    /// Task-033 diagnosability: exit dispositions and the connectivity hold edge
    /// narrate; crash-shaped events (dispatcher-alerted) are not duplicated.
    #[test]
    fn tick_logger_narrates_exits_and_connectivity_edges() {
        let mut logger = TickLogger::default();

        let boundary = TickReport {
            completed: vec!["a".into()],
            retired: vec!["b".into()],
            blocked: vec![Assignment {
                agent: "c".into(),
                queue: "default".into(),
                part: "021".into(),
            }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&boundary),
            vec![
                "fleet: retired b to idle".to_string(),
                "fleet: a finished its part (item boundary; slot released)".to_string(),
                "fleet: c blocked on human — item-parked default/021".to_string(),
            ],
        );

        // Offline edge: enter once, silent while it persists, exit once.
        let offline = TickReport {
            waiting_for_connectivity: true,
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&offline),
            vec!["fleet: offline — holding spawns until the link returns".to_string()],
        );
        assert!(logger.lines(&offline).is_empty(), "no per-tick offline spam");
        assert_eq!(
            logger.lines(&TickReport::default()),
            vec!["fleet: connectivity hold cleared — spawns resume".to_string()],
        );

        // A re-roll spawn failure rides the §9 dispatcher alert — no line here.
        let failed = TickReport {
            rerolls: vec![RerollOutcome::SpawnFailed {
                agent: "a".into(),
                error: "boom".into(),
            }],
            ..TickReport::default()
        };
        assert!(logger.lines(&failed).is_empty());
    }

    /// TASK 042 diagnosability: a fresh-start HOLD (no workable part / part already
    /// claimed) narrates on its entry edge and dedups like any other hold, and each
    /// EXIT narrates its observed baton status + disposition once — so a held
    /// fleet-of-one and a stale/misrouted baton are both visible in the journal
    /// where a silent stall used to be.
    #[test]
    fn tick_logger_narrates_held_fresh_and_exit_dispositions() {
        let mut logger = TickLogger::default();

        // A completed exit that could not be re-placed this tick (the next head is
        // not visible yet): the exit disposition AND the fresh-start hold both narrate.
        let held_and_exited = TickReport {
            completed: vec!["a".into()],
            exit_dispositions: vec![ExitDisposition {
                agent: "a".into(),
                baton_status: Some("ITEM_COMPLETE".into()),
                disposition: "completed (item boundary)",
            }],
            held_fresh: vec![HeldFresh {
                agent: "a".into(),
                reason: "no workable part",
            }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&held_and_exited),
            vec![
                "fleet: holding a (no workable part)".to_string(),
                "fleet: a exited — baton ITEM_COMPLETE -> completed (item boundary)".to_string(),
                "fleet: a finished its part (item boundary; slot released)".to_string(),
            ],
        );

        // The hold persists (still no head) AND the member is re-observed exited
        // (latched) — neither repeats: one line per second is the stall bug this fixes.
        let still_held = TickReport {
            exit_dispositions: vec![ExitDisposition {
                agent: "a".into(),
                baton_status: Some("ITEM_COMPLETE".into()),
                disposition: "unknown",
            }],
            held_fresh: vec![HeldFresh {
                agent: "a".into(),
                reason: "no workable part",
            }],
            ..TickReport::default()
        };
        assert!(
            logger.lines(&still_held).is_empty(),
            "a persisting hold + a latched exit do not repeat",
        );

        // Both edges re-arm once the member starts (leaves the hold + exit states).
        let started = TickReport {
            started: vec![Assignment {
                agent: "a".into(),
                queue: "default".into(),
                part: "y".into(),
            }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&started),
            vec!["fleet: started a on default/y".to_string()],
        );
        // A NEW exit re-logs (the edge re-armed).
        let re_exit = TickReport {
            exit_dispositions: vec![ExitDisposition {
                agent: "a".into(),
                baton_status: None,
                disposition: "rolling (continue status)",
            }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&re_exit),
            vec!["fleet: a exited — baton (none) -> rolling (continue status)".to_string()],
        );
    }

    /// TASK 034: a LATCHED transient network exit — a member re-observed `Exited`
    /// every tick while the connectivity hold gates its re-roll re-populates
    /// `reconnecting` per tick — narrates once on its ENTRY edge, not once per tick
    /// (the 2026-07-06 wifi-drop logged this line 642 times in ~40 min). Once the
    /// member leaves the latch (re-rolls), the edge re-arms so a genuinely NEW
    /// network exit narrates again.
    #[test]
    fn tick_logger_edge_dedups_a_latched_network_exit() {
        let mut logger = TickLogger::default();

        // Entry edge: the transient network exit narrates once.
        let reconnect = TickReport {
            reconnecting: vec!["a".into()],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&reconnect),
            vec!["fleet: a hit a transient network exit (will re-roll)".to_string()],
        );

        // Latched: the offline gate holds the re-roll, so the member is re-classified
        // `Reconnecting` every tick — across many ticks the line must NOT repeat.
        for _ in 0..100 {
            assert!(
                logger.lines(&reconnect).is_empty(),
                "a latched network exit does not re-narrate while spawns are held",
            );
        }

        // The member re-rolls (leaves the latch): this tick carries no reconnecting
        // entry, so the edge re-arms. The re-roll narration itself is unchanged.
        let rerolled = TickReport {
            rerolls: vec![RerollOutcome::Rerolled { agent: "a".into() }],
            ..TickReport::default()
        };
        assert_eq!(
            logger.lines(&rerolled),
            vec!["fleet: re-rolled a (fresh session, same part)".to_string()],
        );

        // A genuinely NEW network exit re-logs (the edge re-armed).
        assert_eq!(
            logger.lines(&reconnect),
            vec!["fleet: a hit a transient network exit (will re-roll)".to_string()],
            "a genuinely new network exit narrates after the latch cleared",
        );
    }

    /// An immediate-stop (force_stop hard kill) retiring agent that is still alive
    /// at its boundary crash is killed via the returned child, outside any lock.
    #[test]
    fn a_hung_retiring_agent_is_killed_on_retire() {
        let (mut loop_, d, backend, _budget) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        loop_.tick(0); // start a1
        assert_eq!(backend.kill_count(), 0);

        // Ask a1 to stop, and have it hang (stale heartbeat) — poll classifies a
        // crash and kills the still-live child; the retire path also drops it.
        d.inner
            .lock()
            .unwrap()
            .control
            .request_stop("a1", StopLevel::AfterIteration);
        backend.set_health("a1", AgentHealth::Alive { last_active: 0 });
        let r = loop_.tick(1000); // 1000s gap >> 100s hang window → hung crash

        assert_eq!(r.retired, vec!["a1".to_string()]);
        assert!(
            r.crashes.contains(&NotifyEvent::agent_crashed("a1")),
            "the hung agent also surfaces a crash alert",
        );
        // The supervisor's poll kills the hung child once; retire finds it already
        // taken, so no double kill.
        assert_eq!(backend.kill_count(), 1, "the hung child was killed exactly once");
        // Permanently stopped: never re-started.
        let r2 = loop_.tick(1001);
        assert!(r2.started.is_empty());
        assert_eq!(backend.spawn_count(), 1);
    }

    /// An unpinned member falls back to the first ready queue.
    #[test]
    fn an_unpinned_member_takes_the_first_ready_queue() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![FleetMember::unpinned(spec("a1"))],
            vec![
                q("claimed", &[("c1", "active")]), // skipped (claimed)
                q("free", &[("f1", "queued")]),
            ],
            Policy::default(),
        );
        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![Assignment {
                agent: "a1".into(),
                queue: "free".into(),
                part: "f1".into()
            }],
        );
        assert_eq!(backend.spawns(), vec!["a1"]);
    }

    /// Belt-and-suspenders: a budget that goes hot AFTER the fleet is running holds
    /// a re-roll on admission (the cap never gates a roll, the budget rail does).
    #[test]
    fn a_re_roll_is_held_when_the_budget_goes_hot() {
        let (mut loop_, _d, backend, _probe) =
            make(vec![member("a1", "qa")], vec![q("qa", &[("p1", "queued")])], Policy::default());
        loop_.tick(0); // start a1
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        loop_.tick(0); // crash → backoff not_before 2

        backend.set_budget("a1", hot_budget());
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r = loop_.tick(2);
        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::HeldForAdmission {
                agent: "a1".into(),
                decision: AdmissionDecision::Refuse {
                    reason: RefuseReason::Budget5h
                },
            }],
        );
        assert_eq!(backend.spawn_count(), 1, "the held re-roll did not spawn");
    }

    /// Admission gates on the cross-agent aggregate (spec §7): one agent that saw
    /// the shared pool deeper than the others pushes the per-field MAX over the 5h
    /// rail, so EVERY start is refused on budget — not just that agent's.
    #[test]
    fn admission_gates_on_the_cross_agent_aggregate() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![member("a1", "qa"), member("a2", "qb"), member("a3", "qc")],
            vec![
                q("qa", &[("p1", "queued")]),
                q("qb", &[("p2", "queued")]),
                q("qc", &[("p3", "queued")]),
            ],
            Policy::default(),
        );
        // a1/a2 each read the pool under the 85 rail; a3 saw it at 88 (over).
        backend.set_budget("a1", BudgetUsage::new(50, 10));
        backend.set_budget("a2", BudgetUsage::new(70, 10));
        backend.set_budget("a3", BudgetUsage::new(88, 10));

        let r = loop_.tick(0);
        assert!(r.started.is_empty(), "the fleet aggregate (88) is over the rail");
        assert_eq!(r.held_starts.len(), 3, "every member's start is held");
        assert!(
            r.held_starts.iter().all(|h| matches!(
                h.outcome,
                StartOutcome::Refused {
                    reason: RefuseReason::Budget5h
                }
            )),
            "all refused on the shared 5h budget, not the cap",
        );
        assert_eq!(backend.spawn_count(), 0, "nothing spawns over the budget rail");
    }

    /// A retired agent's stale-hot reading is forgotten, so it stops pinning the
    /// admission aggregate for the remaining fleet (the loop's `forget` on retire,
    /// belt-and-suspenders with the per-tick refresh forgetting stopped agents).
    #[test]
    fn a_retired_hot_agent_no_longer_pins_the_admission_aggregate() {
        // cap 1: a1 runs first, a2 waits behind the cap.
        let policy = Policy {
            max_concurrent_agents: 1,
            ..Policy::default()
        };
        let (mut loop_, d, backend, _probe) = make(
            vec![member("a1", "qa"), member("a2", "qb")],
            vec![q("qa", &[("p1", "queued")]), q("qb", &[("p2", "queued")])],
            policy,
        );
        backend.set_budget("a1", BudgetUsage::new(20, 5)); // cool → a1 admitted
        backend.set_budget("a2", BudgetUsage::new(20, 5));

        // Tick 0: a1 starts (cap 1); a2 is queued behind the cap.
        assert_eq!(loop_.tick(0).started.len(), 1);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 now reads the shared pool HOT (over the rail) — while it is in the
        // fleet its reading pins the aggregate. Then a1 is asked to stop and
        // reaches a clean boundary → it retires, freeing the slot AND leaving the
        // aggregate.
        backend.set_budget("a1", hot_budget());
        d.inner
            .lock()
            .unwrap()
            .control
            .request_stop("a1", StopLevel::AfterSlice);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        assert_eq!(loop_.tick(1).retired, vec!["a1".to_string()]);

        // Next tick: a1's hot reading is gone, the aggregate is a2's cool 20, the
        // slot is free → a2 starts. (Had a1's 90 lingered, a2 would be refused.)
        let r = loop_.tick(2);
        assert_eq!(
            r.started,
            vec![Assignment {
                agent: "a2".into(),
                queue: "qb".into(),
                part: "p2".into()
            }],
            "the retired hot agent no longer gates the remaining fleet",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a2"]);
    }

    /// The cross-agent aggregate crossing the single 97% rung fires exactly ONE
    /// usage alert through the loop's owned dispatcher (one GUI hub message + one
    /// audit line); sub-97 readings fire nothing and a later still-hot reading
    /// does not re-announce it (the §9 dedup holds across ticks).
    #[test]
    fn the_aggregate_crossing_97_alerts_exactly_once_via_the_owned_dispatcher() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        // Below the rung: the usage alert never fires.
        backend.set_budget("a1", BudgetUsage::new(80, 5));
        loop_.tick(0);
        backend.set_budget("a1", BudgetUsage::new(96, 5));
        loop_.tick(1);
        assert_eq!(probe.gui_alerts(), 0, "sub-97 never alerts");
        assert!(probe.log_lines().is_empty(), "no audit line under the rung");

        // Crossing 97 fires once; a later still-over-97 reading re-reaches the rung
        // but the dedup suppresses a repeat.
        backend.set_budget("a1", BudgetUsage::new(98, 5));
        loop_.tick(2);
        backend.set_budget("a1", BudgetUsage::new(99, 5));
        loop_.tick(3);
        assert_eq!(probe.gui_alerts(), 1, "exactly one GUI alert across the crossing");
        assert_eq!(
            probe.log_lines(),
            vec!["growlightd alert: 5h budget at 97%".to_string()],
            "exactly one audit line",
        );
    }

    /// Each surfaced crash and each parked (blocked-head) item routes through the
    /// loop's owned dispatcher as its own alert, and a re-surfaced blocked head is
    /// deduped — proving `tick` both RETURNS the report AND dispatches it.
    #[test]
    fn crashes_and_parked_heads_route_through_the_owned_dispatcher() {
        let (mut loop_, _d, backend, probe) = make(
            vec![member("a1", "mine")],
            vec![
                q("mine", &[("p1", "blocked"), ("p2", "queued")]),
                q("other", &[("o1", "queued")]),
            ],
            Policy::default(),
        );

        // Tick 0: a1 pivots off the blocked head onto `other`; the blocked head
        // `p1` is surfaced as parked → dispatched as one BlockedOnHuman alert.
        let r0 = loop_.tick(0);
        assert_eq!(r0.parked, vec![("mine".into(), "p1".into())]);
        assert_eq!(backend.spawns(), vec!["a1"]);

        // a1 then crashes → an AgentCrashed alert is dispatched; the still-blocked
        // `p1` re-surfaces this tick but its alert is suppressed by the dedup.
        backend.set_health("a1", AgentHealth::Exited { code: 1 });
        let r1 = loop_.tick(1);
        assert_eq!(r1.crashes, vec![NotifyEvent::agent_crashed("a1")]);

        // Two distinct alerts fired across the two ticks (blocked p1 + crashed a1),
        // each exactly once.
        assert_eq!(probe.gui_alerts(), 2, "one blocked + one crash alert");
        let lines = probe.log_lines();
        assert_eq!(lines.len(), 2, "exactly two distinct audit lines");
        assert!(lines.iter().any(|l| l.contains("blocked on a human")));
        assert!(lines.iter().any(|l| l.contains("crashed")));
    }

    // ---- slice 003: part-claim closes the double-assignment window ----------

    /// Two idle unpinned members in one tick claim DIFFERENT parts — the
    /// intra-tick fallback double-assignment window is closed: the first claim
    /// stamps its part `active` in the working snapshot, so the second member's
    /// `pick` flows past it to the next free queue.
    #[test]
    fn two_unpinned_members_in_one_tick_claim_different_parts() {
        let (mut loop_, _d, backend, claimer, _queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a1")), FleetMember::unpinned(spec("a2"))],
            vec![q("qa", &[("p1", "queued")]), q("qb", &[("p2", "queued")])],
            Policy::default(),
        );
        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![
                Assignment { agent: "a1".into(), queue: "qa".into(), part: "p1".into() },
                Assignment { agent: "a2".into(), queue: "qb".into(), part: "p2".into() },
            ],
            "each unpinned member claims a distinct (queue, part) — never the same",
        );
        assert_eq!(
            claimer.claims(),
            vec![("qa".into(), "p1".into()), ("qb".into(), "p2".into())],
            "both parts were claimed in keeperd, in order, before spawning",
        );
        // Each claim is stamped with the claiming member's agent id, so keeperd's
        // holder-identity CAS (milestone #40) can refuse a different agent's claim
        // of the same part.
        assert_eq!(
            claimer.holders(),
            vec!["a1".to_string(), "a2".to_string()],
            "the claim carries the member's agent id as the holder",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a2"]);
    }

    /// With a single workable part, the first unpinned member claims it and the
    /// second finds nothing — never a double-assignment of the same part.
    #[test]
    fn a_lone_part_is_claimed_once_and_the_second_member_gets_none() {
        let (mut loop_, _d, backend, claimer, _queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a1")), FleetMember::unpinned(spec("a2"))],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![Assignment { agent: "a1".into(), queue: "qa".into(), part: "p1".into() }],
            "only one member starts on the lone part",
        );
        assert!(r.held_starts.is_empty(), "the second member simply found nothing workable");
        assert_eq!(claimer.claims(), vec![("qa".into(), "p1".into())], "claimed exactly once");
        assert_eq!(backend.spawns(), vec!["a1"], "no second spawn on the same part");
    }

    /// Cross-tick: a part claimed in one tick (keeperd shows it `active` on the
    /// next snapshot) is skipped by a later tick's pick. a1 claims qa/p1 under a
    /// cap-1 fleet; once the cap lifts, a2 flows PAST the now-`active` qa to the
    /// still-free qb rather than re-resolving to a1's claimed part.
    #[test]
    fn a_claimed_part_is_skipped_by_a_later_tick() {
        let policy = Policy {
            max_concurrent_agents: 1,
            ..Policy::default()
        };
        let (mut loop_, d, backend, claimer, _queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a1")), FleetMember::unpinned(spec("a2"))],
            vec![q("qa", &[("p1", "queued")]), q("qb", &[("p2", "queued")])],
            policy,
        );

        // Tick 0 (cap 1): a1 claims + starts on qa/p1; a2 is queued behind the cap
        // (admission queues it before any claim, so a2 claims nothing yet).
        let r0 = loop_.tick(0);
        assert_eq!(
            r0.started,
            vec![Assignment { agent: "a1".into(), queue: "qa".into(), part: "p1".into() }],
        );
        assert_eq!(backend.spawns(), vec!["a1"]);
        assert_eq!(claimer.claims(), vec![("qa".into(), "p1".into())], "only a1 claimed in tick 0");

        // Lift the cap; the committed snapshot now shows qa/p1 `active` (a1's
        // claim), so a2's fallback skips qa and takes the still-free qb.
        d.set_policy(Policy {
            max_concurrent_agents: 2,
            ..Policy::default()
        });
        let r1 = loop_.tick(1);
        assert_eq!(
            r1.started,
            vec![Assignment { agent: "a2".into(), queue: "qb".into(), part: "p2".into() }],
            "a2 flows past the cross-tick-claimed qa/p1 to the free qb",
        );
        assert_eq!(
            claimer.claims(),
            vec![("qa".into(), "p1".into()), ("qb".into(), "p2".into())],
            "a2 claimed qb/p2 — it never re-claimed a1's qa/p1",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a2"]);
    }

    /// Cross-tick PINNED resume — the §7b double-claim (milestone
    /// `fleet-resume-double-claim`). The gap `a_claimed_part_is_skipped_by_a_later_tick`
    /// MISSES: its peer is UNPINNED, and fallback skips an `active` head
    /// (`scheduler.rs:240`). Here a fallback member `a` claims `qb/p` at tick N and a
    /// member `b` PINNED to `qb` is excluded that tick by `spoken_for`. At tick
    /// N+1 `qb/p` is `active` (a's committed claim) and a PINNED `pick` RESUMES an
    /// `active` head (`scheduler.rs:228`) rather than skipping it — so without seeding
    /// the per-pass dedup set from the LIVE `assignments`, `b` re-resolves to the part
    /// `a` still holds and double-claims it (keeperd's active-claim is idempotent-`Ok`,
    /// `claim.rs:67`). The fleet must yield AT MOST ONE assignment/spawn/claim across
    /// both ticks. (Fails before the loop-layer fix; slice 002 adds keeperd's durable
    /// holder-CAS behind it.)
    #[test]
    fn a_pinned_member_does_not_resume_a_part_a_live_peer_holds() {
        // Fleet order: the fallback member `a` is scheduled before the pinned `b`, so
        // `a` claims qb/p at tick N and `b` is the one excluded by `spoken_for`.
        let (mut loop_, _d, backend, claimer, _queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a")), member("b", "qb")],
            vec![q("qb", &[("p", "queued")])],
            Policy::default(), // cap 2 — both eligible at tick N; b is held by the dedup, not the cap
        );

        // Tick N: `a` (fallback) claims + starts on qb/p; `b` (pinned qb) picks the
        // same head but it is already claimed THIS tick, so b is excluded and starts
        // nothing — the same-tick guard, already proven.
        let rn = loop_.tick(0);
        assert_eq!(
            rn.started,
            vec![Assignment { agent: "a".into(), queue: "qb".into(), part: "p".into() }],
            "tick N: only the fallback member claims the shared head",
        );
        assert_eq!(backend.spawns(), vec!["a"]);
        assert_eq!(claimer.claims(), vec![("qb".into(), "p".into())], "qb/p claimed once at tick N");

        // `a` keeps running — its claim left qb/p `active` on the committed snapshot.
        backend.set_health("a", AgentHealth::Alive { last_active: 0 });

        // Tick N+1: qb/p is now `active`. A PINNED `pick` RESUMES an active head, so
        // without the cross-tick dedup `b` re-resolves to qb/p and double-claims it.
        let rn1 = loop_.tick(1);
        assert!(
            rn1.started.is_empty(),
            "tick N+1: the pinned member must NOT resume the part its live peer holds, got {:?}",
            rn1.started,
        );
        assert_eq!(backend.spawn_count(), 1, "exactly one spawn across both ticks (no double-assign)");
        assert_eq!(
            claimer.claims(),
            vec![("qb".into(), "p".into())],
            "qb/p claimed exactly once across both ticks — b never re-claimed a's part",
        );
        assert!(!loop_.supervisor.is_registered("b"), "b never spawned, so it is not registered");
    }

    /// A claim failure is fail-closed: admission cleared but the part could not be
    /// claimed, so the agent is NOT spawned (never left running on an unclaimed
    /// part) and the start is held as `ClaimFailed`.
    #[test]
    fn a_failed_claim_is_fail_closed_and_never_spawns() {
        let (mut loop_, _d, backend, claimer, _queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a1"))],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        claimer.set_fail(true);
        let r = loop_.tick(0);
        assert!(r.started.is_empty(), "a start whose claim failed never reports as started");
        assert_eq!(r.held_starts.len(), 1);
        assert!(
            matches!(r.held_starts[0].outcome, StartOutcome::ClaimFailed { .. }),
            "the held start records a fail-closed claim, got {:?}",
            r.held_starts[0].outcome,
        );
        assert_eq!(backend.spawn_count(), 0, "a failed claim spawns nothing");
    }

    /// A backend spawn failure (slice 004: a fail-closed pre-approval generation
    /// failure surfaces as `SpawnError`) is fail-closed AND operator-visible — no
    /// agent is registered, the start is held as `SpawnFailed`, and the loop
    /// dispatches one `AgentCrashed` alert through its owned dispatcher (it was a
    /// silent held-start before slice 004).
    #[test]
    fn a_spawn_failure_is_fail_closed_and_alerts_the_operator() {
        let (mut loop_, _d, backend, probe) = make(
            vec![FleetMember::unpinned(spec("a1"))],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        backend.set_fail_spawn(true);
        let r = loop_.tick(0);

        assert!(r.started.is_empty(), "a spawn failure never reports as started");
        assert_eq!(backend.spawn_count(), 1, "the spawn was attempted (and failed)");
        assert!(
            matches!(
                r.held_starts.as_slice(),
                [HeldStart { outcome: StartOutcome::SpawnFailed { .. }, .. }]
            ),
            "the failed start is held SpawnFailed, got {:?}",
            r.held_starts,
        );
        assert!(!loop_.supervisor.is_registered("a1"), "no doomed agent registered");
        // Operator-visible: exactly one alert reached the GUI hub.
        assert_eq!(probe.gui_alerts(), 1, "a spawn failure alerts the operator once");
        assert!(
            probe.log_lines().iter().any(|l| l.contains("a1")),
            "the audit log records the failing agent: {:?}",
            probe.log_lines(),
        );
    }

    /// Two members mis-pinned to the SAME queue never double-assign its head: the
    /// first claims it; the second — whose `pick` would otherwise read the now
    /// `active` head as a *resume* — is excluded by the per-tick claimed set and
    /// gets nothing. (Marking the head `active` alone is not enough here; the
    /// per-tick claimed set is the belt-and-suspenders that closes the resume
    /// collision.)
    #[test]
    fn two_members_pinned_to_one_queue_never_double_assign_its_head() {
        let (mut loop_, _d, backend, claimer, _queues, _probe) = make_claiming(
            vec![member("a1", "qa"), member("a2", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        let r = loop_.tick(0);
        assert_eq!(
            r.started,
            vec![Assignment { agent: "a1".into(), queue: "qa".into(), part: "p1".into() }],
            "only the first member claims and starts on the shared head",
        );
        assert_eq!(claimer.claims(), vec![("qa".into(), "p1".into())], "the head is claimed exactly once");
        assert_eq!(backend.spawns(), vec!["a1"], "the mis-pinned peer does not also spawn on p1");
    }

    /// SLICE 002: a fresh start seeds the member's per-member baton from the claimed
    /// `(queue, part)` — so the agent boots WITH its baton, not `(no baton yet)`.
    #[test]
    fn a_fresh_start_seeds_the_per_member_baton_from_the_claimed_part() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        let r = loop_.tick(0);
        assert_eq!(r.started.len(), 1, "the member starts on its pinned part");
        assert_eq!(
            backend.seeds(),
            vec![("a1".to_string(), "qa".to_string(), "p1".to_string())],
            "the fresh start seeded the per-member baton, reflecting the claimed (queue, part)",
        );
    }

    /// SLICE 002: a re-roll does NOT re-seed — the member carries its own baton
    /// write-back across iterations (the curated-state contract). Only the fresh
    /// start seeds; the continue-status re-roll re-spawns through `Supervisor::tick`,
    /// which never reaches the step-3 seed.
    #[test]
    fn a_re_roll_carries_state_forward_without_re_seeding() {
        let (mut loop_, _d, backend, _probe) = make(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // fresh start → one seed
        assert_eq!(backend.seeds().len(), 1, "the fresh start seeded once");

        // a1 exits clean on a continue baton (IN_PROGRESS) → an immediate re-roll.
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "IN_PROGRESS");
        let r = loop_.tick(1);

        assert_eq!(
            r.rerolls,
            vec![RerollOutcome::Rerolled { agent: "a1".into() }],
            "a continue baton re-rolls the member",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "the member re-spawned");
        assert_eq!(
            backend.seeds().len(),
            1,
            "the re-roll did NOT re-seed — the member's own write-back carries forward",
        );
    }

    /// SLICE 002 fail-closed: if the per-member baton can't be seeded, the start is
    /// aborted before the keeperd claim (seed-before-claim ordering) — nothing
    /// spawned, nothing claimed (no orphaned `active` part), held as `ClaimFailed`,
    /// retried next tick. A member booting stateless is the bug this slice fixes.
    #[test]
    fn a_seed_failure_is_fail_closed_before_the_claim() {
        let (mut loop_, _d, backend, claimer, _queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );
        backend.set_fail_seed(true);

        let r = loop_.tick(0);
        assert!(r.started.is_empty(), "a start whose seed failed never reports as started");
        assert!(
            matches!(
                r.held_starts.as_slice(),
                [HeldStart { outcome: StartOutcome::ClaimFailed { .. }, .. }]
            ),
            "the held start records a fail-closed seed (as ClaimFailed), got {:?}",
            r.held_starts,
        );
        assert_eq!(backend.spawn_count(), 0, "a failed seed spawns nothing");
        assert!(
            claimer.claims().is_empty(),
            "the seed runs BEFORE the claim, so a seed failure never claims the part (no orphan)",
        );
    }

    /// SLICE 001+002 end-to-end: a fresh start seeds, the agent drains the queue and
    /// reports QUEUE_EMPTY, the loop reads that back and retires the member; when new
    /// work appears the re-start seeds AGAIN with the NEW part (a retired member is a
    /// fresh start, not a re-roll).
    #[test]
    fn a_re_start_after_retire_re_seeds_the_new_part() {
        let (mut loop_, _d, backend, _claimer, queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // start a1 on p1, seeding it
        assert_eq!(backend.seeds(), vec![("a1".into(), "qa".into(), "p1".into())]);

        // a1 drained the queue → QUEUE_EMPTY → retire to idle (not re-rolled).
        queues.set(vec![q("qa", &[("p1", "done")])]);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "QUEUE_EMPTY");
        assert_eq!(loop_.tick(1).retired, vec!["a1".to_string()], "the member retired");

        // New queued work → a fresh start, which re-seeds with the NEW part.
        queues.set(vec![q("qa", &[("p2", "queued")])]);
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r = loop_.tick(2);
        assert_eq!(r.started.len(), 1, "new work re-starts the member");
        assert_eq!(
            backend.seeds(),
            vec![
                ("a1".into(), "qa".into(), "p1".into()),
                ("a1".into(), "qa".into(), "p2".into()),
            ],
            "the re-start (a fresh start) re-seeded with the new part",
        );
    }

    /// SLICE 001 — the headline: a member that exits on an `ITEM_COMPLETE` baton
    /// RELEASES its slot and the orchestrator re-claims its NEXT part the SAME tick
    /// (re-pick + re-seed + re-claim through the fresh-start handshake), with no
    /// member self-pull. Contrast `a_re_start_after_retire_re_seeds_the_new_part`
    /// (QUEUE_EMPTY → drained → idle until new work appears): here the queue still
    /// has work, so continuation happens immediately, in one tick.
    #[test]
    fn an_item_complete_exit_re_claims_the_next_part_the_same_tick() {
        let (mut loop_, _d, backend, claimer, queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued"), ("p2", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a1 starts on p1 (claimed `active`, seeded)
        assert_eq!(backend.spawns(), vec!["a1"]);
        assert_eq!(backend.seeds(), vec![("a1".into(), "qa".into(), "p1".into())]);

        // a1 completed p1 (wrote `set_item_status p1 done`) and exited ITEM_COMPLETE.
        // The next snapshot shows p1 done, p2 still queued.
        queues.set(vec![q("qa", &[("p1", "done"), ("p2", "queued")])]);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "ITEM_COMPLETE");

        let r = loop_.tick(1);
        assert_eq!(r.completed, vec!["a1".to_string()], "the member released its slot");
        assert!(
            r.rerolls.is_empty(),
            "a completed member is NOT re-rolled — no same-part carry-forward",
        );
        assert_eq!(
            r.started,
            vec![Assignment {
                agent: "a1".into(),
                queue: "qa".into(),
                part: "p2".into()
            }],
            "the orchestrator re-claimed the member's NEXT part the same tick",
        );
        assert_eq!(backend.spawns(), vec!["a1", "a1"], "re-spawned on the new part");
        assert_eq!(
            backend.seeds(),
            vec![
                ("a1".into(), "qa".into(), "p1".into()),
                ("a1".into(), "qa".into(), "p2".into()),
            ],
            "the re-claim re-seeded with the NEW part (a fresh start, not a re-roll carry)",
        );
        assert_eq!(
            claimer.claims(),
            vec![("qa".into(), "p1".into()), ("qa".into(), "p2".into())],
            "p1 claimed at tick 0, p2 re-claimed through the same handshake at tick 1",
        );
    }

    /// SLICE 001 finish criterion: TWO members that exit `ITEM_COMPLETE` in ONE
    /// tick never claim the same next part — continuation flows through the same
    /// `spoken_for` + `mark_claimed` + claim handshake a fresh start uses, so
    /// the double-assignment window the old member-self-pull bypassed stays closed
    /// (intra-tick and cross-tick).
    #[test]
    fn two_members_completing_in_one_tick_never_claim_the_same_next_part() {
        // Two queues so both unpinned members start on distinct parts at tick 0
        // (two members drawing ONE queue is the resume-collision case — only one
        // would start; see `two_unpinned_members_in_one_tick_claim_different_parts`).
        let (mut loop_, _d, backend, claimer, queues, _probe) = make_claiming(
            vec![
                FleetMember::unpinned(spec("a1")),
                FleetMember::unpinned(spec("a2")),
            ],
            vec![q("qa", &[("p1", "queued")]), q("qb", &[("p2", "queued")])],
            Policy::default(), // cap 2
        );

        loop_.tick(0); // a1 → qa/p1, a2 → qb/p2 (distinct parts, proven elsewhere)
        assert_eq!(backend.spawn_count(), 2, "both members started on their own part");

        // Both finish in the same window; across BOTH queues only ONE next part
        // (qa/p3) remains workable (qb is drained).
        queues.set(vec![
            q("qa", &[("p1", "done"), ("p3", "queued")]),
            q("qb", &[("p2", "done")]),
        ]);
        for a in ["a1", "a2"] {
            backend.set_health(a, AgentHealth::Exited { code: 0 });
            backend.set_baton(a, "ITEM_COMPLETE");
        }

        let r = loop_.tick(1);
        assert_eq!(r.completed.len(), 2, "both members released their slots");
        assert_eq!(
            r.started.len(),
            1,
            "exactly ONE member re-claims the lone next part — no double-assign",
        );
        assert_eq!(r.started[0].part, "p3");
        assert_eq!(
            claimer.claims().iter().filter(|(_, p)| p == "p3").count(),
            1,
            "the next part was claimed exactly once across the whole run",
        );
        assert_eq!(backend.spawn_count(), 3, "one re-spawn on p3, not two");
    }

    /// SLICE 001: a member that completes its LAST part (`ITEM_COMPLETE` into a now-
    /// drained queue) releases to idle with its slot freed and is NOT re-claimed —
    /// step 3 finds no workable part. New work later re-starts it as a fresh start.
    #[test]
    fn an_item_complete_into_a_drained_queue_releases_and_idles() {
        let (mut loop_, _d, backend, _claimer, queues, _probe) = make_claiming(
            vec![member("a1", "qa")],
            vec![q("qa", &[("p1", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a1 on p1
        assert_eq!(backend.spawn_count(), 1);

        // a1 completed its only part → ITEM_COMPLETE into a now-drained queue.
        queues.set(vec![q("qa", &[("p1", "done")])]);
        backend.set_health("a1", AgentHealth::Exited { code: 0 });
        backend.set_baton("a1", "ITEM_COMPLETE");

        let r = loop_.tick(1);
        assert_eq!(r.completed, vec!["a1".to_string()], "released its slot");
        assert!(r.started.is_empty(), "no next part → idle, slot freed (not re-claimed)");
        assert!(r.rerolls.is_empty());
        assert_eq!(backend.spawn_count(), 1, "no respawn into a drained queue");

        // New queued work → a fresh re-start, which re-seeds the new part.
        queues.set(vec![q("qa", &[("p2", "queued")])]);
        backend.set_health("a1", AgentHealth::Alive { last_active: 2 });
        let r2 = loop_.tick(2);
        assert_eq!(r2.started.len(), 1, "new work re-starts the released member");
        assert_eq!(backend.spawns(), vec!["a1", "a1"]);
    }

    /// TASK 042 repro — the incident: a fleet-of-ONE **unpinned** (fallback)
    /// member completes item X (`ITEM_COMPLETE`, X→`done`) with item Y still
    /// `queued` behind it in the SAME (default) queue. It must re-claim Y + spawn.
    /// (The `an_item_complete_exit_re_claims_the_next_part_the_same_tick` sibling
    /// covers only a PINNED member, which resolves through `pick`'s step-1 own-queue
    /// path; an unpinned member resolves through the step-2 fallback scan — the exact
    /// path the 2026-07-07 fleet-of-one stall rode.)
    #[test]
    fn fleet_of_one_unpinned_completes_and_continues_to_next_queued_head() {
        let (mut loop_, _d, backend, claimer, queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a"))],
            vec![q("default", &[("x", "queued"), ("y", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a starts on x (claimed `active`, seeded)
        assert_eq!(backend.spawns(), vec!["a"], "the sole member starts on the head");

        // a completed x (`set_item_status x done`) and exited ITEM_COMPLETE; the
        // next snapshot shows x done, y still queued behind it.
        queues.set(vec![q("default", &[("x", "done"), ("y", "queued")])]);
        backend.set_health("a", AgentHealth::Exited { code: 0 });
        backend.set_baton("a", "ITEM_COMPLETE");

        let r = loop_.tick(1);
        assert_eq!(r.completed, vec!["a".to_string()], "the member released its slot");
        assert_eq!(
            r.started,
            vec![Assignment { agent: "a".into(), queue: "default".into(), part: "y".into() }],
            "the fleet-of-one auto-advances to the next queued head (no manual restart)",
        );
        assert_eq!(backend.spawns(), vec!["a", "a"], "re-spawned on the next item");
        assert_eq!(
            claimer.claims(),
            vec![("default".into(), "x".into()), ("default".into(), "y".into())],
            "x claimed tick 0, y re-claimed the same handshake tick 1",
        );
    }

    /// TASK 042 repro — the cross-tick latch: the exit is observed a tick BEFORE the
    /// member's own `done` write lands in the drive loop's committed-tip snapshot
    /// (`read_file` reads the tip; a set_item_status commit + the ~1s tick can race).
    /// At the exit tick the head still reads `active`, so the fallback `pick` skips it
    /// (single-active-per-queue anti-starvation) and holds; the very next tick, once
    /// the `done` write lands, it MUST re-claim the freed head. The health cell stays
    /// latched `Exited` across the gap (a real backend only clears it on re-spawn), so
    /// the second-tick poll sees the member already gone (`PollOutcome::Unknown`) and
    /// the re-start must come from step 3, not a re-poll.
    #[test]
    fn fleet_of_one_unpinned_recovers_when_the_done_write_lands_a_tick_late() {
        let (mut loop_, _d, backend, _claimer, queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a"))],
            vec![q("default", &[("x", "queued"), ("y", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a on x (x now `active` in the shared snapshot)
        assert_eq!(backend.spawns(), vec!["a"]);

        // Exit observed, but x's `done` write hasn't landed yet — the snapshot still
        // shows x `active`, y queued behind it.
        backend.set_health("a", AgentHealth::Exited { code: 0 });
        backend.set_baton("a", "ITEM_COMPLETE");
        let r1 = loop_.tick(1);
        assert_eq!(r1.completed, vec!["a".to_string()], "the member released its slot");
        assert!(
            r1.started.is_empty(),
            "the head still reads `active` (done not landed), so the fallback holds",
        );

        // The `done` write lands: x done, y queued. The latched-Exited member is gone
        // from the supervisor, so this re-start comes from step 3.
        queues.set(vec![q("default", &[("x", "done"), ("y", "queued")])]);
        let r2 = loop_.tick(2);
        assert_eq!(
            r2.started,
            vec![Assignment { agent: "a".into(), queue: "default".into(), part: "y".into() }],
            "once the freed head is visible the fleet-of-one auto-advances — no stall",
        );
        assert_eq!(backend.spawns(), vec!["a", "a"], "re-spawned on the next item");
    }

    /// TASK 042 finish-criterion 5 (the diagnosability half), end to end: when a
    /// fleet-of-one completes but its next head is not yet visible, the tick both
    /// RECORDS the fresh-start hold + the exit disposition AND narrates them — so the
    /// 2026-07-07 stall (a held fleet-of-one that logged nothing for 4h) is now
    /// diagnosable from the journal. Rides the same cross-tick-latch shape as
    /// `fleet_of_one_unpinned_recovers_when_the_done_write_lands_a_tick_late`.
    #[test]
    fn a_held_fleet_of_one_records_and_narrates_the_hold_and_exit_disposition() {
        let (mut loop_, _d, backend, _claimer, _queues, _probe) = make_claiming(
            vec![FleetMember::unpinned(spec("a"))],
            vec![q("default", &[("x", "queued"), ("y", "queued")])],
            Policy::default(),
        );

        loop_.tick(0); // a starts on x (x `active`)

        // a completed x and exited ITEM_COMPLETE, but its `done` write has not landed
        // — the head still reads `active`, so step 3's fallback pick finds no workable
        // part and holds. Before task 042 that hold was SILENT.
        backend.set_health("a", AgentHealth::Exited { code: 0 });
        backend.set_baton("a", "ITEM_COMPLETE");
        let r = loop_.tick(1);

        assert_eq!(
            r.exit_dispositions,
            vec![ExitDisposition {
                agent: "a".into(),
                baton_status: Some("ITEM_COMPLETE".into()),
                disposition: "completed (item boundary)",
            }],
            "the exit records the observed baton status + disposition (health pass)",
        );
        assert_eq!(
            r.held_fresh,
            vec![HeldFresh { agent: "a".into(), reason: "no workable part" }],
            "the fresh-start hold is recorded, not skipped silently",
        );

        // And it is NARRATED — a held fleet-of-one now names itself in the journal.
        let mut logger = TickLogger::default();
        let lines = logger.lines(&r);
        assert!(
            lines.contains(&"fleet: holding a (no workable part)".to_string()),
            "the held fleet-of-one is narrated: {lines:?}",
        );
        assert!(
            lines.contains(
                &"fleet: a exited — baton ITEM_COMPLETE -> completed (item boundary)".to_string()
            ),
            "the exit disposition is narrated with the observed baton status: {lines:?}",
        );
    }
}
