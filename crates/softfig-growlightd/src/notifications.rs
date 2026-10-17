//! The notification **policy engine** (phase 5, slice 001) — the pure
//! `event → rule → channel` core with per-event dedup/cooldown
//! (spec-growlight-orchestrator §9, alerts also §4a).
//!
//! ## What this is (and isn't)
//!
//! A **pure value model**: [`NotifyPolicy::decide`]`(event, now)` maps an
//! orchestrator event to the set of [`Channel`]s that should carry it, with an
//! **injected clock** (`now`, Unix seconds) so the once-per-window dedup is
//! unit-testable with no real clock and no sleeps — exactly the shape of
//! keeperd's [`ThrashDetector`](../../../softfig-keeperd/src/actions/thrash.rs)
//! and this crate's [`crate::scheduler::pick`] / [`crate::leases::LeaseTable`].
//! There is **no I/O, no bus posting, no socket** here.
//!
//! The actual delivery — a `Notifier` trait with a GUI-stream channel, an
//! audit-log channel, an inert phone stub, and emitting each fired alert as a
//! `kind: alert` message on the coordination bus (§4a) — is **slice 002**'s
//! seam. This slice answers only the policy question: *given this event right
//! now, which channels fire?* Keeping the policy pure keeps it provable against
//! the event table (the theory-code proof obligation) and keeps the slice
//! additive.
//!
//! ## The policy (spec §9)
//!
//! - **GUI and the audit log always fire** for every event — the groupchat is
//!   the alert history (§4a), the log is the durable record.
//! - **The phone additionally fires for the human-attention set** (§10): events
//!   that stall the fleet or need a human decision — the single near-exhaustion
//!   budget alert (97%, §7 refined 2026-06-23), a `BLOCKED_ON_HUMAN` park, a
//!   drained queue, a crashed agent. Routine progress (`slice-complete`) and
//!   self-healing coordination signals (`thrash-detected`, `lease-denied` — the
//!   fleet's §4d ladder handles these before the human) stay GUI/log only.
//! - **Per-event dedup/cooldown.** Each event has a stable identity key (its
//!   class plus subject); a repeat of the *same* identity inside the cooldown is
//!   suppressed (an empty channel set), so a sustained 97% does not re-fire every
//!   iteration. Past the cooldown the same identity fires again (a reminder).
//!   Distinct identities — the usage alert, a different blocked item, a different
//!   crashed agent — are independent and never suppress each other.
//!
//! ## Per-class cooldowns (task 071)
//!
//! One flat cooldown was wrong for [`BlockedOnHuman`](NotifyEvent::BlockedOnHuman):
//! a block lasts until the human acts — often hours or days — so the old 30-min
//! cadence re-paged every half hour for the SAME standing block (~70 pages in one
//! night on 2026-10-16/17), training the human to ignore the alert that matters.
//! The rule is now per-class:
//!
//! - **`BlockedOnHuman` reminders back off** — the first page for a newly blocked
//!   item stays immediate; each further reminder of the same standing block waits
//!   `30 min → 2 h → 8 h → daily` ([`BLOCKED_REMINDER_LADDER_SECS`]), so after the
//!   first hour the human hears at most one page per 2 h per item. A spin-guard
//!   park ([`SpinGuardParked`](NotifyEvent::SpinGuardParked), task 069) rides the
//!   same ladder under its own `stuck:` identity. A *change of reason is a new
//!   identity*: an item is parked once and stands until the human acts (a
//!   spin-guard park and a member-declared block cannot succeed one another
//!   without an un-block between them), and an un-blocked-then-re-blocked item
//!   pages again immediately — the drive loop reconciles the parked set each
//!   tick ([`reconcile_blocked`](NotifyPolicy::reconcile_blocked)): an identity
//!   that left the set is forgotten, so the re-block (whatever its new reason) is
//!   a fresh fire, not a swallowed reminder.
//! - **Every other class keeps the flat cadence** ([`DEFAULT_COOLDOWN_SECS`]):
//!   usage, crash, network — their conditions rise and clear on the loop's own
//!   timescale, so the old "one page per window, then a reminder" semantics is
//!   exactly right for them and is unchanged.
//!
//! The ladder keys off how many times the identity has fired, so the state is
//! per-identity and survives an arbitrary gap (a block seen again a week later is
//! still "the same standing block", not a fresh page).

use std::collections::HashMap;

/// Default per-event cooldown for every class EXCEPT the backoff ladder
/// ([`BlockedOnHuman`](NotifyEvent::BlockedOnHuman)): after an event fires, the
/// *same identity* is suppressed for at least this long. Generous (30 min)
/// because the loop's natural cadence is whole sessions — one ping per identity
/// per window, not per iteration. The test seam ([`NotifyPolicy::with_cooldown`])
/// overrides it.
const DEFAULT_COOLDOWN_SECS: i64 = 1800;

/// The `BlockedOnHuman` reminder ladder (task 071): the cooldown before the
/// *next* reminder of the same standing block, by how many times its identity
/// has fired — 30 min after the first page, then 2 h, then 8 h, then one per
/// day. The first page itself is always immediate (a fresh identity has no
/// stamp). After the first hour this bounds a standing block to at most one
/// page per 2 h.
const BLOCKED_REMINDER_LADDER_SECS: [i64; 4] = [1800, 7200, 28_800, 86_400];

/// A delivery channel. Modeled as a small enum now; the concrete transports
/// (the GUI subscribe stream, the audit log, the phone over Bluetooth) are
/// slice 002 / the held phone-peer milestone. `Ord` so a routed set has a
/// deterministic order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Channel {
    /// The iced GUI subscribe stream (§11) — always fires.
    Gui,
    /// The durable audit log — always fires.
    Log,
    /// The phone peer (§10) — fires only for the human-attention set.
    Phone,
}

/// An orchestrator event the policy engine routes (spec §9 event set). Variants
/// that name a subject (an item, a queue, an agent, a target) carry it so two
/// different subjects route and dedup independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyEvent {
    /// The shared 5h budget reached the single near-exhaustion rung
    /// ([`USAGE_ALERT_PCT`](crate::usage::USAGE_ALERT_PCT), §7 refined
    /// 2026-06-23). One dedup identity — the rising budget announces it once, to
    /// the phone (it is near the halt rail).
    Usage {
        /// The LIVE fleet-aggregate 5h reserve % at fire time — the drive loop
        /// reads it off [`UsageAggregator::aggregate_or_fresh`](crate::usage::UsageAggregator::aggregate_or_fresh),
        /// NOT the constant rung, so the log/alert shows the real number a
        /// stale-or-pinned value would betray (task 031). NOT part of the dedup
        /// identity — [`dedup_key`](Self::dedup_key) keys on the class alone, so a
        /// rising budget still announces exactly once per cooldown window.
        pct: u8,
    },
    /// An item parked `BLOCKED_ON_HUMAN` (§6 pivot-on-block) — needs a human
    /// answer before it can proceed.
    BlockedOnHuman {
        /// The parked backlog item's id.
        item: String,
    },
    /// The spin guard parked an item (task 069): its member ended session after
    /// session on the same NEXT ACTION with no repo movement to show for it. Not
    /// a human decision — the member never asked one — but it stalls the item
    /// all the same, so it pages on the same reminder ladder under its own
    /// identity.
    SpinGuardParked {
        /// The parked backlog item's id.
        item: String,
        /// How many sessions the streak ran before the guard tripped.
        sessions: u32,
        /// How many dirty paths the item's repo had at the last read; `None` when
        /// the item has no repo this machine can probe.
        dirty: Option<usize>,
    },
    /// A work-stream drained — the named queue (or the whole backlog) has no
    /// workable part left.
    QueueEmpty {
        /// The queue name (a sentinel like `"all"` for the whole backlog).
        queue: String,
    },
    /// A slice/part finished — routine progress.
    SliceComplete {
        /// The completed part's id.
        part: String,
    },
    /// A supervised agent exited abnormally (§8 kill-safety / supervision).
    AgentCrashed {
        /// The crashed agent's name.
        agent: String,
        /// The tail of the crashed agent's stderr (crash-diagnostics slice 001):
        /// the last few in-memory ring-buffer lines (oldest→newest), so the alert
        /// carries a *reason* (e.g. a lost-connection error) — not just a non-zero
        /// exit. Empty when the agent emitted no stderr, or the child never ran (a
        /// spawn failure). NOT part of the dedup identity — [`dedup_key`](Self::dedup_key)
        /// keys on the agent alone, so a re-crash with different stderr still dedups
        /// per cooldown window.
        stderr_tail: Vec<String>,
        /// The crashed agent's last **stdout** stream error, when its stream ended
        /// on one (task 070): the in-band API error a headless member prints on
        /// STDOUT — a permission failure, a provider error, anything the stderr
        /// ring is blind to (stderr carries only the `systemd-run` banner). Rendered
        /// FIRST in the summary, so the alert names the real reason; the banner
        /// lines are filtered out of `stderr_tail` by the drive loop, never carried.
        /// NOT part of the dedup identity.
        stdout_error: Option<String>,
    },
    /// The thrash detector tripped on a contended target (§4d rung 1).
    ThrashDetected {
        /// The contended target label (`"path §heading"` / `"path"`).
        target: String,
    },
    /// A lease request was denied — an action-layer refusal such as a
    /// self-restart (§4c).
    LeaseDenied {
        /// The lease key (the contended resource/action).
        key: String,
        /// The agent that was denied.
        agent: String,
    },
    /// The device has been offline past the sustained-outage threshold
    /// (network-failsafe slice 003): the pre-spawn connectivity gate is holding the
    /// fleet's spawns. A blip never reaches here (it clears before the threshold); a
    /// sustained outage pages the human ONCE (human-attention), the deliberate
    /// inverse of the 2026-07-01 crash-loop that paged every ~30min. `secs` (how
    /// long offline) rides the body but is NOT part of the dedup identity.
    NetworkOffline {
        /// Seconds the device had been offline when the alert fired.
        secs: i64,
    },
    /// The device's link returned after a [`NetworkOffline`](Self::NetworkOffline)
    /// alert (network-failsafe slice 003): the fleet's spawns resume. Info only (NOT
    /// human-attention) — it clears the outage on `growlight watch` / the log.
    NetworkRecovered,
    /// growlightd caught a stop signal (SIGTERM/SIGINT) while the fleet was armed
    /// (task 032). A graceful teardown exits 0, so systemd's `Restart=on-failure`
    /// will NOT revive it — the whole fleet stays parked until the next garden
    /// unlock (keeperd relaunches growlightd) or an explicit restart.
    /// Human-attention: the operator is *paged* on the committed bus, not merely
    /// left a `[fleet-park]` journal line to go grep, because a silent park left
    /// the fleet dead for hours on 2026-07-05/06
    /// (incident-20260706-growlightd-fleet-liveness-2bugs). Raised ONLY from the
    /// signal handler (the sole signal path), so an asked-for IPC `shutdown` stays
    /// quiet; it still fires on an *expected* keeperd terminal-lock stop, which
    /// growlightd cannot distinguish from a phantom one by pid — the loud-but-passive
    /// call in decision-growlightd-clean-stop-no-silent-fleet-park.
    FleetParked {
        /// How many fleet members were armed when the stop landed — the blast radius.
        members: usize,
    },
}

impl NotifyEvent {
    /// An [`AgentCrashed`](Self::AgentCrashed) with no stderr tail yet. The
    /// supervisor builds it this way (it has no backend to read stderr from); the
    /// drive loop enriches it via [`with_stderr_tail`](Self::with_stderr_tail) /
    /// [`with_stdout_error`](Self::with_stdout_error) before dispatch. Also the
    /// right shape for a *spawn* failure — the child never ran, so there is no
    /// stderr to carry.
    pub fn agent_crashed(agent: impl Into<String>) -> Self {
        Self::AgentCrashed {
            agent: agent.into(),
            stderr_tail: Vec::new(),
            stdout_error: None,
        }
    }

    /// Attach a crashed agent's stderr tail (crash-diagnostics slice 001), returning
    /// the enriched event. A no-op on any non-[`AgentCrashed`](Self::AgentCrashed)
    /// event, so the drive loop can call it uniformly on whatever `poll` returned.
    pub fn with_stderr_tail(mut self, tail: Vec<String>) -> Self {
        if let Self::AgentCrashed { stderr_tail, .. } = &mut self {
            *stderr_tail = tail;
        }
        self
    }

    /// Attach a crashed agent's last stdout stream error (task 070), returning the
    /// enriched event: the in-band API error a headless member printed on STDOUT —
    /// the reason stderr-only enrichment can't see (stderr carries only the
    /// `systemd-run` banner). A no-op on any non-[`AgentCrashed`](Self::AgentCrashed)
    /// event.
    pub fn with_stdout_error(mut self, error: Option<String>) -> Self {
        if let Self::AgentCrashed { stdout_error, .. } = &mut self {
            *stdout_error = error;
        }
        self
    }

    /// Whether this event belongs to the human-attention set — the events that
    /// additionally route to the phone (§9/§10). These stall the fleet or need a
    /// human decision; everything else is GUI/log only.
    pub fn is_human_attention(&self) -> bool {
        match self {
            Self::Usage { .. }
            | Self::BlockedOnHuman { .. }
            | Self::SpinGuardParked { .. }
            | Self::QueueEmpty { .. }
            | Self::AgentCrashed { .. }
            | Self::NetworkOffline { .. }
            | Self::FleetParked { .. } => true,
            Self::SliceComplete { .. }
            | Self::ThrashDetected { .. }
            | Self::LeaseDenied { .. }
            | Self::NetworkRecovered => false,
        }
    }

    /// The channels this event routes to, ignoring dedup: GUI and the log
    /// always, plus the phone for the human-attention set. Deterministic order
    /// (`Gui`, `Log`, then `Phone`). [`NotifyPolicy::decide`] returns this on a
    /// fresh fire and an empty set when the event is suppressed.
    pub fn channels(&self) -> Vec<Channel> {
        let mut chans = vec![Channel::Gui, Channel::Log];
        if self.is_human_attention() {
            chans.push(Channel::Phone);
        }
        chans
    }

    /// This event's stable dedup identity — its class plus subject. Two events
    /// with the same key are "the same event" for cooldown purposes; different
    /// keys never suppress each other.
    pub fn dedup_key(&self) -> String {
        match self {
            Self::Usage { .. } => "usage".to_string(),
            Self::BlockedOnHuman { item } => format!("blocked:{item}"),
            Self::SpinGuardParked { item, .. } => format!("stuck:{item}"),
            Self::QueueEmpty { queue } => format!("queue-empty:{queue}"),
            Self::SliceComplete { part } => format!("slice-complete:{part}"),
            Self::AgentCrashed { agent, .. } => format!("agent-crashed:{agent}"),
            Self::ThrashDetected { target } => format!("thrash:{target}"),
            Self::LeaseDenied { key, agent } => format!("lease-denied:{key}:{agent}"),
            // Class-only identities (no subject): one outage / one recovery / one
            // fleet-park at a time (the park's process is exiting anyway).
            Self::NetworkOffline { .. } => "network-offline".to_string(),
            Self::NetworkRecovered => "network-recovered".to_string(),
            Self::FleetParked { .. } => "fleet-parked".to_string(),
        }
    }

    /// A one-line human-facing summary — the body slice 002 renders into the
    /// `kind: alert` bus message, the log line, and the GUI toast. Pure
    /// formatting; lives on the event because the event owns its own meaning.
    pub fn summary(&self) -> String {
        match self {
            Self::Usage { pct } => format!("5h budget at {pct}%"),
            Self::BlockedOnHuman { item } => {
                format!("`{item}` is blocked on a human decision")
            }
            Self::SpinGuardParked {
                item,
                sessions,
                dirty,
            } => {
                let repo = match dirty {
                    None => "repo unknown".to_string(),
                    Some(0) => "repo clean".to_string(),
                    Some(1) => "repo dirty: 1 file".to_string(),
                    Some(k) => format!("repo dirty: {k} files"),
                };
                format!(
                    "`{item}` stuck (spin guard): {sessions} sessions ended with no new handoff — {repo}"
                )
            }
            Self::QueueEmpty { queue } => format!("queue `{queue}` is empty — no workable part"),
            Self::SliceComplete { part } => format!("slice `{part}` complete"),
            Self::AgentCrashed {
                agent,
                stderr_tail,
                stdout_error,
            } => {
                // The stdout stream error (task 070) leads — it is the in-band
                // reason the member died on; the stderr lines (banner-filtered by
                // the drive loop) follow. Neither present → the plain crash line.
                let mut lines: Vec<&str> = Vec::new();
                if let Some(err) = stdout_error {
                    lines.push(err.as_str());
                }
                lines.extend(stderr_tail.iter().map(String::as_str));
                if lines.is_empty() {
                    format!("agent `{agent}` crashed")
                } else {
                    // The reasons ride the one-line alert body so `growlight watch`
                    // and the log show the crash *why*; lines joined with a visible
                    // separator (the ring already bounds it).
                    format!("agent `{agent}` crashed: {}", lines.join(" ⏎ "))
                }
            }
            Self::ThrashDetected { target } => format!("thrash detected on {target}"),
            Self::LeaseDenied { key, agent } => {
                format!("lease `{key}` denied to `{agent}`")
            }
            Self::NetworkOffline { secs } => {
                format!("network offline for {secs}s — fleet spawns held")
            }
            Self::NetworkRecovered => "network recovered — fleet spawns resumed".to_string(),
            Self::FleetParked { members } => format!(
                "growlightd stopped while the fleet was armed — {members} member(s) parked; \
                 Restart=on-failure will NOT revive it, so restart softfig-growlightd or unlock \
                 the garden to re-arm"
            ),
        }
    }
}

/// One identity's fire history — when it last fired and how many times. The
/// [`BlockedOnHuman`](NotifyEvent::BlockedOnHuman) ladder keys its escalating
/// cooldown off `times` (task 071); every other class ignores the count and
/// keeps the flat cadence.
#[derive(Debug, Clone, Copy)]
struct FireStamp {
    /// Unix-seconds of the last (fresh) fire.
    at: i64,
    /// How many times this identity has fired in total.
    times: u32,
}

/// The notification policy engine: a pure router with per-class cooldown dedup.
/// Holds only the last-fired stamp per event identity; no clock, no I/O, no
/// socket. The daemon wires it thin (slice 002): on each orchestrator event it
/// calls [`decide`](Self::decide) with the current time and fans the returned
/// channels out to the `Notifier` impls.
#[derive(Debug)]
pub struct NotifyPolicy {
    cooldown_secs: i64,
    last_fired: HashMap<String, FireStamp>,
}

impl Default for NotifyPolicy {
    fn default() -> Self {
        Self::with_cooldown(DEFAULT_COOLDOWN_SECS)
    }
}

impl NotifyPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an explicit cooldown (the test seam — production uses
    /// [`new`](Self::new)). Sets the flat per-window cadence for every class
    /// except the [`BlockedOnHuman`](NotifyEvent::BlockedOnHuman) ladder, which
    /// is a policy constant.
    pub fn with_cooldown(cooldown_secs: i64) -> Self {
        Self {
            cooldown_secs,
            last_fired: HashMap::new(),
        }
    }

    /// The cooldown gating the NEXT reminder of this identity, given it has
    /// already fired `times` times: the `BlockedOnHuman` ladder (30 min → 2 h →
    /// 8 h → daily, task 071), or the flat per-window cadence for every other
    /// class.
    fn cooldown_for(&self, event: &NotifyEvent, times: u32) -> i64 {
        match event {
            NotifyEvent::BlockedOnHuman { .. } | NotifyEvent::SpinGuardParked { .. } => {
                BLOCKED_REMINDER_LADDER_SECS[(times.saturating_sub(1).min(3)) as usize]
            }
            _ => self.cooldown_secs,
        }
    }

    /// Decide which channels `event` fires to at `now` (Unix seconds). Returns
    /// the routed channel set on a fresh fire, or an **empty** set when the same
    /// event identity fired within its cooldown (suppressed). A fresh fire
    /// records `now` as the event's last-fired stamp and bumps its fire count —
    /// which is what the `BlockedOnHuman` reminder ladder steps on.
    pub fn decide(&mut self, event: &NotifyEvent, now: i64) -> Vec<Channel> {
        let key = event.dedup_key();
        if let Some(&FireStamp { at, times }) = self.last_fired.get(&key)
            && now - at < self.cooldown_for(event, times) {
                return Vec::new();
            }
        let times = self.last_fired.get(&key).map_or(1, |s| s.times.saturating_add(1));
        self.last_fired.insert(key, FireStamp { at: now, times });
        event.channels()
    }

    /// Forget every parked-item identity — `BlockedOnHuman` or `SpinGuardParked`
    /// — not in `currently_blocked` (tasks 071, 069). The drive loop calls this
    /// each tick with the parked (blocked-head) set: an item that left the set —
    /// un-blocked, done, re-queued — is forgotten, so a LATER re-block pages
    /// immediately as a fresh fire instead of being swallowed by a still-running
    /// backoff window. Identities still in the set are untouched (their ladder
    /// keeps stepping). Every other event class is never touched.
    pub fn reconcile_blocked(&mut self, currently_blocked: &[&str]) {
        let stale: Vec<String> = self
            .last_fired
            .keys()
            .filter(|key| {
                key.strip_prefix("blocked:")
                    .or_else(|| key.strip_prefix("stuck:"))
                    .is_some_and(|item| !currently_blocked.contains(&item))
            })
            .cloned()
            .collect();
        for key in stale {
            self.last_fired.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(item: &str) -> NotifyEvent {
        NotifyEvent::BlockedOnHuman {
            item: item.to_string(),
        }
    }

    fn stuck(item: &str, dirty: Option<usize>) -> NotifyEvent {
        NotifyEvent::SpinGuardParked {
            item: item.to_string(),
            sessions: 2,
            dirty,
        }
    }

    /// GUI and the log fire for *every* event class — the §9 always-on invariant.
    #[test]
    fn gui_and_log_always_fire_for_every_event() {
        let events = [
            NotifyEvent::Usage { pct: 97 },
            blocked("004"),
            NotifyEvent::QueueEmpty {
                queue: "all".to_string(),
            },
            NotifyEvent::SliceComplete {
                part: "001".to_string(),
            },
            NotifyEvent::agent_crashed("tab"),
            NotifyEvent::ThrashDetected {
                target: "dock.rs §Layout".to_string(),
            },
            NotifyEvent::LeaseDenied {
                key: "dock.rs".to_string(),
                agent: "tab".to_string(),
            },
        ];
        for e in &events {
            let chans = e.channels();
            assert!(chans.contains(&Channel::Gui), "{e:?} → GUI");
            assert!(chans.contains(&Channel::Log), "{e:?} → Log");
        }
    }

    /// SLICE 003 — the connectivity events route correctly: a sustained
    /// `NetworkOffline` is human-attention (pages Phone+GUI+Log), a `NetworkRecovered`
    /// is info only (GUI+Log, no page), and each carries a distinct class-only dedup
    /// identity so a repeat inside the cooldown dedups to one.
    #[test]
    fn connectivity_events_route_and_dedup_by_class() {
        assert!(NotifyEvent::NetworkOffline { secs: 300 }.is_human_attention());
        assert_eq!(
            NotifyEvent::NetworkOffline { secs: 300 }.channels(),
            vec![Channel::Gui, Channel::Log, Channel::Phone],
        );
        assert!(!NotifyEvent::NetworkRecovered.is_human_attention());
        assert_eq!(
            NotifyEvent::NetworkRecovered.channels(),
            vec![Channel::Gui, Channel::Log],
        );
        // `secs` is not part of the identity — two outages share one dedup key.
        assert_eq!(
            NotifyEvent::NetworkOffline { secs: 1 }.dedup_key(),
            "network-offline",
        );
        assert_eq!(
            NotifyEvent::NetworkOffline { secs: 999 }.dedup_key(),
            "network-offline",
        );
        assert_eq!(NotifyEvent::NetworkRecovered.dedup_key(), "network-recovered");

        // A repeat of the same identity inside the cooldown is suppressed.
        let mut policy = NotifyPolicy::with_cooldown(100);
        assert!(!policy
            .decide(&NotifyEvent::NetworkOffline { secs: 300 }, 0)
            .is_empty());
        assert!(
            policy
                .decide(&NotifyEvent::NetworkOffline { secs: 360 }, 50)
                .is_empty(),
            "the same identity within the cooldown is deduped",
        );
    }

    /// The human-attention set routes to Phone+GUI+Log; everything else is
    /// GUI/Log only (no phone).
    #[test]
    fn human_attention_set_routes_to_phone_others_do_not() {
        // Human-attention: budget near the rail, blocked, spin-parked, drained,
        // crashed.
        for e in [
            NotifyEvent::Usage { pct: 97 },
            blocked("004"),
            stuck("004", Some(3)),
            NotifyEvent::QueueEmpty {
                queue: "all".to_string(),
            },
            NotifyEvent::agent_crashed("tab"),
        ] {
            assert!(e.is_human_attention(), "{e:?} is human-attention");
            assert_eq!(
                e.channels(),
                vec![Channel::Gui, Channel::Log, Channel::Phone],
                "{e:?} → phone+gui+log"
            );
        }
        // Low-priority: routine progress, self-healing coordination.
        for e in [
            NotifyEvent::SliceComplete {
                part: "001".to_string(),
            },
            NotifyEvent::ThrashDetected {
                target: "dock.rs §Layout".to_string(),
            },
            NotifyEvent::LeaseDenied {
                key: "dock.rs".to_string(),
                agent: "tab".to_string(),
            },
        ] {
            assert!(!e.is_human_attention(), "{e:?} is not human-attention");
            assert_eq!(
                e.channels(),
                vec![Channel::Gui, Channel::Log],
                "{e:?} → gui+log only, no phone"
            );
        }
    }

    /// A fresh event fires its full channel set; the same identity inside the
    /// cooldown is suppressed (empty); past the cooldown it fires again.
    #[test]
    fn cooldown_suppresses_a_repeat_then_re_fires() {
        let mut p = NotifyPolicy::with_cooldown(100);
        // A low-priority event (gui/log only) isolates the cooldown mechanics from
        // the human-attention routing.
        let e = NotifyEvent::SliceComplete {
            part: "001".to_string(),
        };
        assert_eq!(p.decide(&e, 0), vec![Channel::Gui, Channel::Log], "first fire");
        // Inside the 100s window → suppressed.
        assert!(p.decide(&e, 50).is_empty(), "suppressed inside cooldown");
        assert!(p.decide(&e, 99).is_empty(), "still suppressed at the edge");
        // At exactly the cooldown boundary it re-fires (mirrors ThrashDetector's
        // `< cooldown` test).
        assert_eq!(p.decide(&e, 100), vec![Channel::Gui, Channel::Log], "re-fires");
    }

    /// Distinct event identities are independent — one firing never suppresses
    /// another, even back-to-back at the same instant.
    #[test]
    fn distinct_events_are_independent() {
        let mut p = NotifyPolicy::with_cooldown(1000);
        // Two different blocked items at the same instant both fire.
        assert!(!p.decide(&blocked("004"), 0).is_empty());
        assert!(!p.decide(&blocked("005"), 0).is_empty());
        // A second 004 is now suppressed, but 005 was unaffected by 004.
        assert!(p.decide(&blocked("004"), 1).is_empty());
        // A wholly different class at the same instant fires.
        assert!(!p
            .decide(
                &NotifyEvent::agent_crashed("tab"),
                1
            )
            .is_empty());
    }

    /// The single usage alert fires once — to the phone (it is near the halt
    /// rail) — then is suppressed within the cooldown (the §9 single-97% collapse).
    #[test]
    fn the_single_usage_alert_fires_once_then_is_suppressed() {
        let mut p = NotifyPolicy::with_cooldown(1000);
        // First fire routes everywhere, phone included (near-exhaustion).
        assert_eq!(
            p.decide(&NotifyEvent::Usage { pct: 97 }, 0),
            vec![Channel::Gui, Channel::Log, Channel::Phone]
        );
        // A repeat inside the cooldown is suppressed — no re-spam of a sustained 97%.
        assert!(p.decide(&NotifyEvent::Usage { pct: 97 }, 1).is_empty());
        assert!(p.decide(&NotifyEvent::Usage { pct: 97 }, 999).is_empty());
    }

    /// Dedup keys encode class + subject so the identity is stable and unique.
    #[test]
    fn dedup_keys_distinguish_class_and_subject() {
        assert_eq!(NotifyEvent::Usage { pct: 97 }.dedup_key(), "usage");
        assert_eq!(blocked("004").dedup_key(), "blocked:004");
        assert_ne!(blocked("004").dedup_key(), blocked("005").dedup_key());
        assert_eq!(
            NotifyEvent::LeaseDenied {
                key: "dock.rs".to_string(),
                agent: "tab".to_string(),
            }
            .dedup_key(),
            "lease-denied:dock.rs:tab"
        );
    }

    /// Every event renders a non-empty summary (the body slice 002 emits as the
    /// `kind: alert` bus message / log line).
    #[test]
    fn every_event_summary_is_non_empty() {
        for e in [
            NotifyEvent::Usage { pct: 97 },
            blocked("004"),
            NotifyEvent::QueueEmpty {
                queue: "all".to_string(),
            },
            NotifyEvent::SliceComplete {
                part: "001".to_string(),
            },
            NotifyEvent::agent_crashed("tab"),
            NotifyEvent::ThrashDetected {
                target: "dock.rs §Layout".to_string(),
            },
            NotifyEvent::LeaseDenied {
                key: "dock.rs".to_string(),
                agent: "tab".to_string(),
            },
        ] {
            assert!(!e.summary().is_empty(), "{e:?} has a summary");
        }
    }

    /// The crash alert carries the stderr tail (crash-diagnostics slice 001): a
    /// bare crash reads plainly, an enriched one renders the reason into the
    /// one-line body `watch`/the log show. Enrichment never changes the dedup
    /// identity, so a re-crash with new stderr still suppresses within a window.
    #[test]
    fn agent_crashed_summary_carries_the_stderr_tail_without_changing_dedup() {
        let bare = NotifyEvent::agent_crashed("a");
        assert_eq!(bare.summary(), "agent `a` crashed");

        let enriched = NotifyEvent::agent_crashed("a")
            .with_stderr_tail(vec!["API error: Connection reset".to_string()]);
        assert_eq!(
            enriched.summary(),
            "agent `a` crashed: API error: Connection reset"
        );

        // Same subject → same dedup key regardless of the tail.
        assert_eq!(bare.dedup_key(), enriched.dedup_key());

        // `with_stderr_tail` is a no-op on a non-crash event.
        assert_eq!(
            NotifyEvent::Usage { pct: 97 }.with_stderr_tail(vec!["x".to_string()]),
            NotifyEvent::Usage { pct: 97 }
        );
    }

    /// TASK 070 — the crash body leads with the member's last **stdout** stream
    /// error when there is one (the in-band reason stderr-only enrichment is blind
    /// to), the stderr lines follow, and neither present reads the plain crash
    /// line. Enrichment never changes the dedup identity.
    #[test]
    fn agent_crashed_summary_leads_with_the_stdout_error() {
        // A 429 death that slipped through as a genuine crash (the classifier
        // missed it) still names its real reason from the stream, not the banner.
        let with_stream = NotifyEvent::agent_crashed("a")
            .with_stdout_error(Some(
                "You've hit your session limit · resets 4:40pm".to_string(),
            ))
            .with_stderr_tail(vec!["stack line".to_string()]);
        assert_eq!(
            with_stream.summary(),
            "agent `a` crashed: You've hit your session limit · resets 4:40pm ⏎ stack line"
        );
        assert_eq!(
            with_stream.dedup_key(),
            NotifyEvent::agent_crashed("a").dedup_key(),
            "the stdout error is not part of the identity"
        );

        // No stdout error, no stderr → the plain line.
        assert_eq!(
            NotifyEvent::agent_crashed("a")
                .with_stdout_error(None)
                .with_stderr_tail(Vec::new())
                .summary(),
            "agent `a` crashed"
        );

        // `with_stdout_error` is a no-op on a non-crash event.
        assert_eq!(
            NotifyEvent::Usage { pct: 97 }
                .with_stdout_error(Some("x".to_string())),
            NotifyEvent::Usage { pct: 97 }
        );
    }

    /// TASK 032 — a stop-while-armed park is human-attention (pages Phone+GUI+Log),
    /// keyed class-only (`"fleet-parked"` — one park at a time, the process is
    /// exiting), and renders a recovery-bearing summary. The loud half of the
    /// clean-stop-resilience decision (the `[fleet-park]` journal line is the other).
    #[test]
    fn fleet_parked_pages_the_human_and_keys_class_only() {
        let e = NotifyEvent::FleetParked { members: 3 };
        assert!(
            e.is_human_attention(),
            "a stop-while-armed park pages the human"
        );
        assert_eq!(e.channels(), vec![Channel::Gui, Channel::Log, Channel::Phone]);
        // Class-only identity: the member count is not part of the key.
        assert_eq!(e.dedup_key(), "fleet-parked");
        assert_eq!(
            NotifyEvent::FleetParked { members: 1 }.dedup_key(),
            NotifyEvent::FleetParked { members: 9 }.dedup_key(),
        );
        // The summary names the blast radius + the recovery lever.
        let s = e.summary();
        assert!(s.contains("3 member"), "names the blast radius: {s}");
        assert!(
            s.contains("re-arm") || s.contains("unlock"),
            "names the recovery lever: {s}",
        );
    }

    // ---- task 071: the BlockedOnHuman reminder ladder -----------------------

    /// A newly blocked item pages ONCE, immediately; reminders for the SAME
    /// standing block then back off 30 min → 2 h → 8 h → daily — and past the
    /// first hour that is at most one page per 2 h (the upper bound the fix was
    /// asked to hold). All on the injected clock — no sleeps, no wall time.
    #[test]
    fn a_standing_block_backs_off_30m_2h_8h_then_daily() {
        let mut p = NotifyPolicy::new();
        let e = blocked("004");

        // First page: immediate.
        assert_eq!(p.decide(&e, 0), vec![Channel::Gui, Channel::Log, Channel::Phone]);
        // Inside the first (30-min) rung: suppressed — every tick, however often.
        assert!(p.decide(&e, 1).is_empty());
        assert!(p.decide(&e, 1_799).is_empty());

        // 30 min → the first reminder fires.
        assert_eq!(
            p.decide(&e, 1_800),
            vec![Channel::Gui, Channel::Log, Channel::Phone],
            "the first reminder waits 30 min",
        );
        // Then the NEXT rung is 2 h: a tick an hour later is still suppressed.
        assert!(p.decide(&e, 3_600).is_empty(), "still inside the 2h rung");

        // 2 h after the reminder → the second reminder fires.
        assert_eq!(
            p.decide(&e, 9_000), // 1800 + 7200
            vec![Channel::Gui, Channel::Log, Channel::Phone],
            "the second reminder waits 2 h",
        );
        // 8 h rung.
        assert!(p.decide(&e, 10_000).is_empty());
        assert_eq!(
            p.decide(&e, 37_800), // 9000 + 28800
            vec![Channel::Gui, Channel::Log, Channel::Phone],
            "the third reminder waits 8 h",
        );
        // Daily from here on: a tick 6 h later is suppressed, the next page
        // waits a full day.
        assert!(p.decide(&e, 40_000).is_empty());
        assert_eq!(
            p.decide(&e, 37_800 + 86_400),
            vec![Channel::Gui, Channel::Log, Channel::Phone],
            "past the 8h rung a standing block pages at most daily",
        );

        // The upper bound the fix was asked to hold: after the first hour of a
        // standing block, at most one page per 2 h. Drive a policy from t=0 (the
        // ladder steps on block age); between age 1h and 1h+2h the only page is
        // the 2h30m reminder (the 30m one landed before the first hour).
        let mut p2 = NotifyPolicy::new();
        for now in (0..3_600).step_by(60) {
            let _ = p2.decide(&e, now);
        }
        let mut pages_after_first_hour = 0;
        for now in (3_600..(3_600 + 7_200)).step_by(60) {
            if !p2.decide(&e, now).is_empty() {
                pages_after_first_hour += 1;
            }
        }
        assert_eq!(pages_after_first_hour, 1, "≤ 1 page per 2 h after the first hour");
    }

    /// A SECOND distinct blocked item still pages immediately — identities are
    /// independent, so one standing block's ladder never suppresses another.
    #[test]
    fn a_second_distinct_blocked_item_pages_immediately() {
        let mut p = NotifyPolicy::new();
        // 004 blocks and pages; 005 blocks a second later — fresh identity.
        assert!(!p.decide(&blocked("004"), 0).is_empty());
        assert_eq!(
            p.decide(&blocked("005"), 1),
            vec![Channel::Gui, Channel::Log, Channel::Phone],
            "a different blocked item is its own identity — immediate page",
        );
        // 004 is deep inside its first rung, 005's page left it untouched.
        assert!(p.decide(&blocked("004"), 2).is_empty());
    }

    /// Un-blocking and re-blocking an item pages again: the drive loop
    /// reconciles the parked set each tick, and an identity that left it is
    /// forgotten — so the re-block is a FRESH fire, not a reminder swallowed by
    /// the still-running ladder.
    #[test]
    fn unblocking_and_reblocking_pages_again() {
        let mut p = NotifyPolicy::new();
        assert!(!p.decide(&blocked("004"), 0).is_empty());

        // The block cleared (the item left the parked set): reconcile forgets it.
        p.reconcile_blocked(&["other"]);
        // Re-blocked minutes later — nowhere near any ladder rung — pages fresh.
        assert_eq!(
            p.decide(&blocked("004"), 60),
            vec![Channel::Gui, Channel::Log, Channel::Phone],
            "a re-block after an un-block pages immediately",
        );
        // And the ladder restarts from rung one.
        assert!(p.decide(&blocked("004"), 61).is_empty());
        assert_eq!(
            p.decide(&blocked("004"), 60 + 1_800),
            vec![Channel::Gui, Channel::Log, Channel::Phone],
        );

        // Reconcile leaves still-blocked identities (and every other class) alone.
        let mut p2 = NotifyPolicy::new();
        assert!(!p2.decide(&blocked("004"), 0).is_empty());
        assert!(!p2.decide(&NotifyEvent::agent_crashed("tab"), 1).is_empty());
        p2.reconcile_blocked(&["004"]);
        assert!(p2.decide(&blocked("004"), 10).is_empty(), "still blocked — the ladder stands");
        assert!(
            p2.decide(&NotifyEvent::agent_crashed("tab"), 2).is_empty(),
            "a crash identity is never touched by the blocked reconcile",
        );
    }

    /// Other event classes (usage, crash) keep their current cadence — the flat
    /// per-window cooldown, no ladder: a still-hot budget re-announces every
    /// cooldown window, exactly as before task 071.
    #[test]
    fn other_classes_keep_the_flat_cadence() {
        let mut p = NotifyPolicy::with_cooldown(1_000);
        let usage = NotifyEvent::Usage { pct: 97 };
        assert!(!p.decide(&usage, 0).is_empty());
        assert!(p.decide(&usage, 999).is_empty());
        assert!(!p.decide(&usage, 1_000).is_empty(), "the usage reminder fires each window");
        assert!(!p.decide(&usage, 2_000).is_empty(), "…and the NEXT window too — no ladder");

        let crash = NotifyEvent::agent_crashed("tab");
        assert!(!p.decide(&crash, 0).is_empty());
        assert!(p.decide(&crash, 500).is_empty());
        assert!(!p.decide(&crash, 1_000).is_empty());
        assert!(!p.decide(&crash, 2_000).is_empty(), "a re-crashing agent keeps its 1/window cadence");
    }

    // ---- task 069: a spin-guard park is not a human decision ---------------

    /// A spin park says what happened — the guard, the session count, how dirty
    /// the repo was — and never "blocked on a human decision". A member-declared
    /// block reads exactly as before.
    #[test]
    fn a_spin_park_reads_as_stuck_never_as_a_human_decision() {
        assert_eq!(
            stuck("069", Some(3)).summary(),
            "`069` stuck (spin guard): 2 sessions ended with no new handoff — repo dirty: 3 files",
        );
        assert_eq!(
            stuck("069", Some(1)).summary(),
            "`069` stuck (spin guard): 2 sessions ended with no new handoff — repo dirty: 1 file",
        );
        assert_eq!(
            stuck("069", Some(0)).summary(),
            "`069` stuck (spin guard): 2 sessions ended with no new handoff — repo clean",
        );
        assert_eq!(
            stuck("069", None).summary(),
            "`069` stuck (spin guard): 2 sessions ended with no new handoff — repo unknown",
        );
        for dirty in [None, Some(0), Some(4)] {
            assert!(!stuck("069", dirty).summary().contains("human decision"));
        }
        assert_eq!(blocked("069").summary(), "`069` is blocked on a human decision");
    }

    /// `blocked:` and `stuck:` are separate identities: one never suppresses the
    /// other, the spin park climbs the same reminder ladder, and the parked-set
    /// reconcile forgets both once the item leaves.
    #[test]
    fn blocked_and_stuck_identities_are_independent() {
        assert_eq!(stuck("069", Some(3)).dedup_key(), "stuck:069");
        assert_eq!(stuck("069", None).dedup_key(), "stuck:069", "the counts are not identity");
        assert_ne!(stuck("069", None).dedup_key(), blocked("069").dedup_key());

        let page = vec![Channel::Gui, Channel::Log, Channel::Phone];
        let mut p = NotifyPolicy::new();
        assert_eq!(p.decide(&blocked("069"), 0), page);
        assert_eq!(p.decide(&stuck("069", Some(3)), 0), page, "a blocked page doesn't swallow it");
        assert!(p.decide(&stuck("069", Some(4)), 1).is_empty(), "the same standing spin park");

        // The ladder, not the flat cadence: 30 min, then 2 h.
        assert_eq!(p.decide(&stuck("069", Some(3)), 1_800), page);
        assert!(p.decide(&stuck("069", Some(3)), 3_600).is_empty(), "inside the 2h rung");
        assert_eq!(p.decide(&stuck("069", Some(3)), 9_000), page);

        // Still parked: the reconcile leaves it. Gone: forgotten, so a re-park
        // pages at once.
        p.reconcile_blocked(&["069"]);
        assert!(p.decide(&stuck("069", Some(3)), 9_001).is_empty());
        p.reconcile_blocked(&[]);
        assert_eq!(p.decide(&stuck("069", Some(3)), 9_002), page);
        assert_eq!(p.decide(&blocked("069"), 9_002), page);
    }
}
