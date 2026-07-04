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

use std::collections::HashMap;

/// Default per-event cooldown: after an event fires, the *same identity* is
/// suppressed for at least this long. Generous (30 min) because the loop's
/// natural cadence is whole sessions — one ping per identity per window, not
/// per iteration. The test seam ([`NotifyPolicy::with_cooldown`]) overrides it.
const DEFAULT_COOLDOWN_SECS: i64 = 1800;

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
    Usage,
    /// An item parked `BLOCKED_ON_HUMAN` (§6 pivot-on-block) — needs a human
    /// answer before it can proceed.
    BlockedOnHuman {
        /// The parked backlog item's id.
        item: String,
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
}

impl NotifyEvent {
    /// An [`AgentCrashed`](Self::AgentCrashed) with no stderr tail yet. The
    /// supervisor builds it this way (it has no backend to read stderr from); the
    /// drive loop enriches it via [`with_stderr_tail`](Self::with_stderr_tail)
    /// before dispatch. Also the right shape for a *spawn* failure — the child never
    /// ran, so there is no stderr to carry.
    pub fn agent_crashed(agent: impl Into<String>) -> Self {
        Self::AgentCrashed {
            agent: agent.into(),
            stderr_tail: Vec::new(),
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

    /// Whether this event belongs to the human-attention set — the events that
    /// additionally route to the phone (§9/§10). These stall the fleet or need a
    /// human decision; everything else is GUI/log only.
    pub fn is_human_attention(&self) -> bool {
        match self {
            Self::Usage
            | Self::BlockedOnHuman { .. }
            | Self::QueueEmpty { .. }
            | Self::AgentCrashed { .. } => true,
            Self::SliceComplete { .. }
            | Self::ThrashDetected { .. }
            | Self::LeaseDenied { .. } => false,
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
            Self::Usage => "usage".to_string(),
            Self::BlockedOnHuman { item } => format!("blocked:{item}"),
            Self::QueueEmpty { queue } => format!("queue-empty:{queue}"),
            Self::SliceComplete { part } => format!("slice-complete:{part}"),
            Self::AgentCrashed { agent, .. } => format!("agent-crashed:{agent}"),
            Self::ThrashDetected { target } => format!("thrash:{target}"),
            Self::LeaseDenied { key, agent } => format!("lease-denied:{key}:{agent}"),
        }
    }

    /// A one-line human-facing summary — the body slice 002 renders into the
    /// `kind: alert` bus message, the log line, and the GUI toast. Pure
    /// formatting; lives on the event because the event owns its own meaning.
    pub fn summary(&self) -> String {
        match self {
            Self::Usage => format!("5h budget at {}%", crate::usage::USAGE_ALERT_PCT),
            Self::BlockedOnHuman { item } => {
                format!("`{item}` is blocked on a human decision")
            }
            Self::QueueEmpty { queue } => format!("queue `{queue}` is empty — no workable part"),
            Self::SliceComplete { part } => format!("slice `{part}` complete"),
            Self::AgentCrashed { agent, stderr_tail } => {
                if stderr_tail.is_empty() {
                    format!("agent `{agent}` crashed")
                } else {
                    // The tail rides the one-line alert body so `growlight watch`
                    // and the log show the crash *reason*; lines joined with a
                    // visible separator (the ring already bounds it).
                    format!("agent `{agent}` crashed: {}", stderr_tail.join(" ⏎ "))
                }
            }
            Self::ThrashDetected { target } => format!("thrash detected on {target}"),
            Self::LeaseDenied { key, agent } => {
                format!("lease `{key}` denied to `{agent}`")
            }
        }
    }
}

/// The notification policy engine: a pure router with per-event cooldown dedup.
/// Holds only the last-fired stamp per event identity; no clock, no I/O, no
/// socket. The daemon wires it thin (slice 002): on each orchestrator event it
/// calls [`decide`](Self::decide) with the current time and fans the returned
/// channels out to the `Notifier` impls.
#[derive(Debug)]
pub struct NotifyPolicy {
    cooldown_secs: i64,
    last_fired: HashMap<String, i64>,
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
    /// [`new`](Self::new)).
    pub fn with_cooldown(cooldown_secs: i64) -> Self {
        Self {
            cooldown_secs,
            last_fired: HashMap::new(),
        }
    }

    /// Decide which channels `event` fires to at `now` (Unix seconds). Returns
    /// the routed channel set on a fresh fire, or an **empty** set when the same
    /// event identity fired within the cooldown (suppressed). A fresh fire
    /// records `now` as the event's last-fired stamp.
    pub fn decide(&mut self, event: &NotifyEvent, now: i64) -> Vec<Channel> {
        let key = event.dedup_key();
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown_secs {
                return Vec::new();
            }
        }
        self.last_fired.insert(key, now);
        event.channels()
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

    /// GUI and the log fire for *every* event class — the §9 always-on invariant.
    #[test]
    fn gui_and_log_always_fire_for_every_event() {
        let events = [
            NotifyEvent::Usage,
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

    /// The human-attention set routes to Phone+GUI+Log; everything else is
    /// GUI/Log only (no phone).
    #[test]
    fn human_attention_set_routes_to_phone_others_do_not() {
        // Human-attention: budget near the rail, blocked, drained, crashed.
        for e in [
            NotifyEvent::Usage,
            blocked("004"),
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
            p.decide(&NotifyEvent::Usage, 0),
            vec![Channel::Gui, Channel::Log, Channel::Phone]
        );
        // A repeat inside the cooldown is suppressed — no re-spam of a sustained 97%.
        assert!(p.decide(&NotifyEvent::Usage, 1).is_empty());
        assert!(p.decide(&NotifyEvent::Usage, 999).is_empty());
    }

    /// Dedup keys encode class + subject so the identity is stable and unique.
    #[test]
    fn dedup_keys_distinguish_class_and_subject() {
        assert_eq!(NotifyEvent::Usage.dedup_key(), "usage");
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
            NotifyEvent::Usage,
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
            NotifyEvent::Usage.with_stderr_tail(vec!["x".to_string()]),
            NotifyEvent::Usage
        );
    }
}
