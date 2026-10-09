//! Owner-side replica push health (`replica-health.toml`) — task `058`.
//!
//! [`GrantLedger`](crate::replica::GrantLedger) says *who* this device may push
//! its chain to. This module records *how that is going*: per granted host, the
//! last successful push, the current reachability class, and when that class
//! began. It exists because the one failure mode that can persist forever — a
//! granted host with no route at all — used to be the only one that logged
//! nothing, so a backup could stop without ever failing.
//!
//! Two consumers, one file:
//!
//! * The reconcile pass ([`crate::net`]) calls [`PushHealth::record`] once per
//!   granted host per tick. `record` returns a [`Transition`] **only on the
//!   edge** — entering an unhealthy class, or recovering out of one — so a host
//!   that has been unreachable for a month costs one journal line, not one every
//!   [`REPLICA_RECONCILE_INTERVAL`](crate::net) (~20s). The persisted state *is*
//!   the latch, so a daemon restart doesn't re-announce what it already said.
//! * `replica_status` reads it so `softfig replica status` can judge staleness
//!   instead of printing a raw timestamp, and can tell "no route" (fix discovery
//!   or the endpoint) apart from "route exists, push failed" (fix transport or
//!   auth) — different diagnoses with different fixes.
//!
//! The file is regenerable metadata, not authority: absent, unreadable or
//! unparseable all degrade to "no prior state", which re-announces each host's
//! class on the next pass rather than losing the signal.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use softfig_ipc::human_age_secs;

/// Filename of the owner-side push-health record within `.softfig/`.
pub const REPLICA_HEALTH_FILE: &str = "replica-health.toml";

/// How long a chain may go without a successful push (or, for a mirror we host,
/// without an inbound sync) before the status surface calls it stale. One day:
/// the reconcile tick is ~20s, so a day of silence is far outside normal jitter,
/// while still letting a laptop sleep through a weekend without crying wolf.
pub const STALE_AFTER_SECS: i64 = 24 * 60 * 60;

/// Coalescing granularity for the on-disk `last_ok` stamp. A healthy host
/// round-trips every reconcile tick; re-writing the file every 20s to advance a
/// timestamp nobody reads at that resolution is pointless churn, so a success
/// only re-stamps once this much has elapsed.
pub const OK_STAMP_GRANULARITY_SECS: i64 = 60;

/// Minimum gap between journal lines for a host that stays in [`PushState::Error`]
/// with a *changing* failure message. The class edge always logs; this bounds the
/// detail-changed re-log so an error text that varies per attempt (a rotating
/// source port, a differing peer address) can't reopen the flood this task closed.
pub const ERROR_RELOG_MIN_SECS: i64 = 5 * 60;

/// How the last push attempt to a granted host ended. The two unreachable
/// classes are deliberately distinct from [`Self::Error`]: they mean "we never
/// dialed", and they are fixed by discovery/endpoint/pairing work, not by
/// looking at the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// A full round-trip succeeded — commits were served, or the host was
    /// already at our tip (equally proof of reachability).
    Ok,
    /// The host is a ring member but has no LAN endpoint and no relay fallback,
    /// so there was nothing to dial.
    NoRoute,
    /// The grant names a fingerprint that is not in the ring at all — a peer
    /// that was decommissioned, un-paired or never paired. Its grant can never
    /// be satisfied until it is re-paired or revoked.
    Unpaired,
    /// A route existed and the push failed; the string is the failure text.
    Error(String),
}

impl PushOutcome {
    fn state(&self) -> PushState {
        match self {
            Self::Ok => PushState::Ok,
            Self::NoRoute => PushState::NoRoute,
            Self::Unpaired => PushState::Unpaired,
            Self::Error(_) => PushState::Error,
        }
    }
}

/// The persisted reachability class of a granted host — [`PushOutcome`] without
/// the failure text, so it can live in a file and be compared across ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PushState {
    Ok,
    NoRoute,
    Unpaired,
    Error,
}

impl PushState {
    /// The wire/display token (also what `softfig replica status` prints).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoRoute => "no-route",
            Self::Unpaired => "unpaired",
            Self::Error => "error",
        }
    }

    /// Whether this class means backups to the host are currently stopped.
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl std::fmt::Display for PushState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Push health for one granted host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostHealth {
    /// The host's device-id fingerprint (lowercase hex), as it appears in the
    /// grant ledger.
    pub fingerprint: String,
    /// The host's current reachability class.
    pub state: PushState,
    /// Unix seconds at which `state` began — the edge we journalled.
    pub since: i64,
    /// Unix seconds of the most recent successful push round-trip, ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ok: Option<i64>,
    /// For [`PushState::Error`], the failure text of the last attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Unix seconds of the last journal line emitted for this host, so a
    /// changing error detail can be re-logged without flooding.
    #[serde(default)]
    pub logged_at: i64,
}

impl HostHealth {
    /// Seconds since the last successful push, or `None` if there has never
    /// been one.
    pub fn ok_age_secs(&self, now: i64) -> Option<u64> {
        self.last_ok.map(|t| now.saturating_sub(t).max(0) as u64)
    }

    /// Whether this host's backup is stale: never pushed at all, or not pushed
    /// within [`STALE_AFTER_SECS`].
    pub fn is_stale(&self, now: i64) -> bool {
        is_stale_at(self.last_ok, now)
    }
}

/// Staleness judgement shared by the push side and the hosted-mirror side: no
/// sync on record at all, or none within [`STALE_AFTER_SECS`].
pub fn is_stale_at(last_sync: Option<i64>, now: i64) -> bool {
    match last_sync {
        None => true,
        Some(t) => now.saturating_sub(t) > STALE_AFTER_SECS,
    }
}

/// An edge in a host's reachability class — the thing worth a journal line.
/// Produced only when the class changed (or an error's detail changed and the
/// re-log gap has elapsed), never on a steady-state tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub fingerprint: String,
    /// The class we left, or `None` on this host's first observation.
    pub from: Option<PushState>,
    /// The class we entered.
    pub to: PushState,
    /// For [`PushState::Error`], the failure text.
    pub detail: Option<String>,
    /// How long `from` had held, when known.
    pub held_secs: Option<i64>,
    /// Seconds since the last successful push at the moment of the edge.
    pub ok_age_secs: Option<u64>,
}

impl Transition {
    /// The journal line for this edge, without keeperd's `keeperd: net: ` prefix.
    /// Each unhealthy class names the fix that class actually needs — the whole
    /// point of keeping them apart.
    pub fn message(&self) -> String {
        let fp = &self.fingerprint;
        let ok = match self.ok_age_secs {
            Some(age) => format!("last successful push {} ago", human_age_secs(age)),
            None => "no successful push on record".to_string(),
        };
        match self.to {
            PushState::NoRoute => format!(
                "replica host {fp} UNREACHABLE: no LAN endpoint and no relay — \
                 pushes to it have stopped ({ok}). Fix discovery, seed its endpoint \
                 in .softfig/peers-endpoints.toml, or configure a relay"
            ),
            PushState::Unpaired => format!(
                "replica host {fp} UNREACHABLE: granted but not a ring member — \
                 pushes to it have stopped ({ok}). Re-pair the device, or \
                 `softfig replica revoke {fp}`"
            ),
            PushState::Error => format!(
                "replica push to {fp} FAILING: {} — a route exists, so this is \
                 transport/auth, not discovery ({ok})",
                self.detail.as_deref().unwrap_or("unknown error"),
            ),
            PushState::Ok => {
                let was = match (self.from, self.held_secs) {
                    (Some(prev), Some(held)) => {
                        format!(" (was {prev} for {})", human_age_secs(held.max(0) as u64))
                    }
                    (Some(prev), None) => format!(" (was {prev})"),
                    (None, _) => String::new(),
                };
                format!("replica host {fp} reachable again — pushes resumed{was}")
            }
        }
    }
}

/// Path to the push-health record: `<state_dir>/.softfig/replica-health.toml`.
pub fn replica_health_path(state_dir: &Path) -> PathBuf {
    state_dir.join(".softfig").join(REPLICA_HEALTH_FILE)
}

/// Per-host push health for every granted host, persisted beside the grant
/// ledger. See the module docs for why this is persisted rather than in-daemon
/// state: it is both the edge-logging latch and the status surface's source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PushHealth {
    #[serde(default)]
    pub hosts: Vec<HostHealth>,
    /// Set by any mutation that changed persisted content; `save` is a no-op
    /// otherwise, so a steady-state tick writes nothing.
    #[serde(skip)]
    dirty: bool,
}

impl PushHealth {
    /// Load the record. Absent, unreadable or unparseable all yield an empty
    /// record — the state is regenerable, and starting from "no prior state"
    /// re-announces each host's class rather than swallowing it.
    pub fn load(state_dir: &Path) -> Self {
        let path = replica_health_path(state_dir);
        let Ok(raw) = fs::read_to_string(&path) else {
            return Self::default();
        };
        toml::from_str(&raw).unwrap_or_default()
    }

    /// Atomically write the record (temp + rename), creating `.softfig/`.
    /// A no-op unless a mutation marked it dirty.
    pub fn save(&self, state_dir: &Path) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let dir = state_dir.join(".softfig");
        fs::create_dir_all(&dir)?;
        let path = dir.join(REPLICA_HEALTH_FILE);
        let raw = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, &path)
    }

    /// Whether a mutation since `load` changed persisted content.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn get(&self, fingerprint: &str) -> Option<&HostHealth> {
        self.hosts.iter().find(|h| h.fingerprint == fingerprint)
    }

    /// Record `outcome` for `fingerprint` at `now`, returning the [`Transition`]
    /// to journal — `None` on a steady-state tick. This is the rate limiter: the
    /// caller logs exactly what this returns.
    pub fn record(
        &mut self,
        fingerprint: &str,
        outcome: PushOutcome,
        now: i64,
    ) -> Option<Transition> {
        let to = outcome.state();
        let idx = self.hosts.iter().position(|h| h.fingerprint == fingerprint);
        let prev = idx.map(|i| (self.hosts[i].state, self.hosts[i].since));

        // Steady state in the same class: nothing to say, and usually nothing to
        // write either.
        if let (Some(i), Some((prev_state, _))) = (idx, prev) {
            if prev_state == to {
                return self.record_same_class(i, outcome, now);
            }
        }

        let ok_age_secs = idx.and_then(|i| self.hosts[i].ok_age_secs(now));
        let last_ok = match outcome {
            PushOutcome::Ok => Some(now),
            _ => idx.and_then(|i| self.hosts[i].last_ok),
        };
        let detail = match &outcome {
            PushOutcome::Error(e) => Some(e.clone()),
            _ => None,
        };
        // A host's first observation is only worth a line when it is unhealthy;
        // a healthy push already narrates itself ("pushed chain to ...").
        let announce = prev.is_some() || !to.is_healthy();
        let entry = HostHealth {
            fingerprint: fingerprint.to_string(),
            state: to,
            since: now,
            last_ok,
            detail: detail.clone(),
            logged_at: if announce { now } else { 0 },
        };
        match idx {
            Some(i) => self.hosts[i] = entry,
            None => self.hosts.push(entry),
        }
        self.dirty = true;
        if !announce {
            return None;
        }
        Some(Transition {
            fingerprint: fingerprint.to_string(),
            from: prev.map(|(s, _)| s),
            to,
            detail,
            held_secs: prev.map(|(_, since)| now.saturating_sub(since)),
            // For a recovery the age is measured before this success stamped
            // `last_ok`, so it reads as the length of the outage.
            ok_age_secs,
        })
    }

    /// The host is already in `outcome`'s class. Advance the coalesced success
    /// stamp, or re-log a changed error detail once the gap has elapsed.
    fn record_same_class(
        &mut self,
        i: usize,
        outcome: PushOutcome,
        now: i64,
    ) -> Option<Transition> {
        match outcome {
            PushOutcome::Ok => {
                let stale_stamp = self.hosts[i]
                    .last_ok
                    .is_none_or(|t| now.saturating_sub(t) >= OK_STAMP_GRANULARITY_SECS);
                if stale_stamp {
                    self.hosts[i].last_ok = Some(now);
                    self.dirty = true;
                }
                None
            }
            PushOutcome::Error(e) => {
                if self.hosts[i].detail.as_deref() == Some(e.as_str()) {
                    return None; // same failure, still failing — already said
                }
                self.hosts[i].detail = Some(e.clone());
                self.dirty = true;
                if now.saturating_sub(self.hosts[i].logged_at) < ERROR_RELOG_MIN_SECS {
                    return None;
                }
                self.hosts[i].logged_at = now;
                Some(Transition {
                    fingerprint: self.hosts[i].fingerprint.clone(),
                    from: Some(PushState::Error),
                    to: PushState::Error,
                    detail: Some(e),
                    held_secs: Some(now.saturating_sub(self.hosts[i].since)),
                    ok_age_secs: self.hosts[i].ok_age_secs(now),
                })
            }
            // `NoRoute` / `Unpaired` carry no per-tick detail, so holding the
            // class is literally no news.
            PushOutcome::NoRoute | PushOutcome::Unpaired => None,
        }
    }

    /// Drop hosts that are no longer granted, so a revoke doesn't leave a ghost
    /// row in `replica status`. Returns whether anything was removed.
    pub fn retain_granted(&mut self, granted: &[String]) -> bool {
        let before = self.hosts.len();
        self.hosts.retain(|h| granted.contains(&h.fingerprint));
        let removed = self.hosts.len() != before;
        self.dirty |= removed;
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "aa";
    const T0: i64 = 1_700_000_000;

    fn err(msg: &str) -> PushOutcome {
        PushOutcome::Error(msg.to_string())
    }

    #[test]
    fn unreachable_announces_once_not_per_tick() {
        let mut h = PushHealth::default();
        let first = h.record(FP, PushOutcome::NoRoute, T0);
        assert!(first.is_some(), "entering no-route must announce");
        assert_eq!(first.unwrap().to, PushState::NoRoute);
        // Twenty-second ticks for an hour: not one more line, not one more write.
        h.dirty = false;
        for tick in 1..=180 {
            assert_eq!(h.record(FP, PushOutcome::NoRoute, T0 + tick * 20), None);
        }
        assert!(!h.is_dirty(), "a held class must not re-write the file");
    }

    #[test]
    fn recovery_announces_and_clears() {
        let mut h = PushHealth::default();
        h.record(FP, PushOutcome::NoRoute, T0).unwrap();
        let back = h.record(FP, PushOutcome::Ok, T0 + 3600).expect("recovery announces");
        assert_eq!(back.to, PushState::Ok);
        assert_eq!(back.from, Some(PushState::NoRoute));
        assert_eq!(back.held_secs, Some(3600));
        assert_eq!(h.get(FP).unwrap().state, PushState::Ok);
        assert_eq!(h.get(FP).unwrap().last_ok, Some(T0 + 3600));
        // ...and steady-state success says nothing further.
        assert_eq!(h.record(FP, PushOutcome::Ok, T0 + 3620), None);
    }

    #[test]
    fn first_healthy_observation_is_quiet_but_recorded() {
        let mut h = PushHealth::default();
        assert_eq!(h.record(FP, PushOutcome::Ok, T0), None);
        assert_eq!(h.get(FP).unwrap().last_ok, Some(T0));
        assert!(h.is_dirty());
    }

    #[test]
    fn healthy_ticks_coalesce_the_stamp() {
        let mut h = PushHealth::default();
        h.record(FP, PushOutcome::Ok, T0);
        h.dirty = false;
        // Inside the granularity window: no write.
        assert_eq!(h.record(FP, PushOutcome::Ok, T0 + 20), None);
        assert!(!h.is_dirty());
        assert_eq!(h.get(FP).unwrap().last_ok, Some(T0));
        // Past it: the stamp advances, still silently.
        assert_eq!(h.record(FP, PushOutcome::Ok, T0 + OK_STAMP_GRANULARITY_SECS), None);
        assert!(h.is_dirty());
        assert_eq!(
            h.get(FP).unwrap().last_ok,
            Some(T0 + OK_STAMP_GRANULARITY_SECS)
        );
    }

    #[test]
    fn no_route_and_push_error_are_distinct_classes() {
        let mut h = PushHealth::default();
        let t = h.record(FP, PushOutcome::NoRoute, T0).unwrap();
        assert!(t.message().contains("no LAN endpoint"));
        assert!(t.message().contains("peers-endpoints.toml"));
        let t = h.record(FP, err("handshake rejected"), T0 + 60).unwrap();
        assert_eq!(t.from, Some(PushState::NoRoute));
        assert_eq!(t.to, PushState::Error);
        assert!(t.message().contains("handshake rejected"));
        assert!(t.message().contains("transport/auth"));
    }

    #[test]
    fn unpaired_grant_is_its_own_class() {
        let mut h = PushHealth::default();
        let t = h.record(FP, PushOutcome::Unpaired, T0).unwrap();
        assert_eq!(t.to, PushState::Unpaired);
        assert!(t.message().contains("not a ring member"));
        assert!(t.message().contains("replica revoke"));
        assert_eq!(h.record(FP, PushOutcome::Unpaired, T0 + 20), None);
    }

    #[test]
    fn repeated_identical_error_is_silent_and_changed_detail_is_gap_bounded() {
        let mut h = PushHealth::default();
        h.record(FP, err("connection refused"), T0).unwrap();
        assert_eq!(h.record(FP, err("connection refused"), T0 + 20), None);
        // A detail that changes every tick must not reopen the flood.
        assert_eq!(h.record(FP, err("refused :41001"), T0 + 40), None);
        assert_eq!(h.record(FP, err("refused :41002"), T0 + 60), None);
        // Past the re-log gap, one line carries the current text.
        let t = h
            .record(FP, err("refused :41003"), T0 + ERROR_RELOG_MIN_SECS)
            .expect("a changed detail re-logs once the gap elapses");
        assert!(t.message().contains(":41003"));
        assert_eq!(h.record(FP, err("refused :41004"), T0 + ERROR_RELOG_MIN_SECS + 20), None);
    }

    #[test]
    fn transition_reports_outage_length_not_zero() {
        let mut h = PushHealth::default();
        h.record(FP, PushOutcome::Ok, T0);
        h.record(FP, PushOutcome::NoRoute, T0 + 100).unwrap();
        let back = h.record(FP, PushOutcome::Ok, T0 + 100 + 7 * 86_400).unwrap();
        // The recovery line must age the *last success*, not the success it just
        // recorded, or a week-long outage reads as "0s ago".
        assert_eq!(back.ok_age_secs, Some(100 + 7 * 86_400));
        assert!(back.message().contains("reachable again"));
    }

    #[test]
    fn staleness_judges_against_the_threshold() {
        assert!(is_stale_at(None, T0), "never synced is stale");
        assert!(!is_stale_at(Some(T0), T0 + STALE_AFTER_SECS));
        assert!(is_stale_at(Some(T0), T0 + STALE_AFTER_SECS + 1));
    }

    #[test]
    fn roundtrips_through_the_file_so_a_restart_keeps_the_latch() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = PushHealth::default();
        h.record(FP, PushOutcome::NoRoute, T0).unwrap();
        h.save(dir.path()).unwrap();

        // A restarted daemon must not re-announce what the previous one said.
        let mut back = PushHealth::load(dir.path());
        assert_eq!(back.get(FP).unwrap().state, PushState::NoRoute);
        assert_eq!(back.record(FP, PushOutcome::NoRoute, T0 + 20), None);
        assert!(!back.is_dirty());
    }

    #[test]
    fn a_clean_tick_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        PushHealth::default().save(dir.path()).unwrap();
        assert!(
            !replica_health_path(dir.path()).exists(),
            "a no-op save must not create the file"
        );
    }

    #[test]
    fn unparseable_file_degrades_to_no_prior_state() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".softfig")).unwrap();
        fs::write(replica_health_path(dir.path()), "this is not toml {{{").unwrap();
        let mut h = PushHealth::load(dir.path());
        assert!(h.hosts.is_empty());
        // Losing the latch must re-announce, never swallow.
        assert!(h.record(FP, PushOutcome::NoRoute, T0).is_some());
    }

    #[test]
    fn revoking_a_grant_drops_its_row() {
        let mut h = PushHealth::default();
        h.record(FP, PushOutcome::NoRoute, T0);
        h.record("bb", PushOutcome::Ok, T0);
        assert!(h.retain_granted(&["bb".to_string()]));
        assert!(h.get(FP).is_none());
        assert!(h.get("bb").is_some());
        assert!(!h.retain_granted(&["bb".to_string()]));
    }
}
